import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS,
  StaticApprovedDagLaunchError,
  createStaticApprovedDagPlanApproval,
  executeStaticApprovedDag,
  inspectStaticApprovedDagSpec,
  normalizeStaticApprovedDagLaunchSpec,
  staticApprovedDagSpecSha256,
  type StaticApprovedDagLaunchSpec,
} from "../src/static-approved-dag-launcher.js";
import { main as staticApprovedDagCliMain } from "../src/cli/static-approved-dag.js";

const HEAD = "a".repeat(40);
const TREE = "b".repeat(40);
const ROOT = process.cwd();
const digest = (letter: string) => `sha256:${letter.repeat(64)}`;

function spec(): Record<string, unknown> {
  return {
    spec_version: "static-approved-dag-launch-v1", run_label: "launcher-test", expected_repository_branch: "main", expected_head: HEAD, expected_tree: TREE,
    goal: { objective: "Write exactly two outputs.", stop_condition: "Stop after verification.", execution_mode: "STATIC_APPROVED_DAG", scope: { readable_paths: ["node_modules"], editable_paths: ["out/a.txt", "out/b.txt"], frozen_paths: ["node_modules"] }, required_outputs: ["out/a.txt", "out/b.txt"], tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["out/a.txt"], required_outputs: ["out/a.txt"], dependencies: [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["out/b.txt"], required_outputs: ["out/b.txt"], dependencies: ["a"] },
    ] },
    verification_commands: [{ command_id: "tsx", executable: process.execPath, args: ["tsx/dist/cli.mjs", "--version"], cwd: "node_modules", timeout_ms: 60_000 }],
    static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
    expected_route: { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: false },
  };
}

const facts = async () => ({ repository_root: ROOT, branch: "main", head: HEAD, tree: TREE, clean: true, active_operations: [], index_lock: false });

function approvalInput(value: StaticApprovedDagLaunchSpec): any {
  value = structuredClone(value);
  const commands = value.verification_commands.map((command) => ({ command_id: command.command_id, argv: [command.executable, `${ROOT}/${command.cwd}/${command.args[0]!}`, ...command.args.slice(1)], cwd: command.cwd, timeout_ms: command.timeout_ms, network: "FORBIDDEN" }));
  const tasks = value.goal.tasks.map((task, index) => ({ task_id: task.task_id, objective: task.objective, assigned_role: value.expected_route.logical_role, write_owner: task.task_id, dependencies: task.dependencies, scope: { readable_paths: value.goal.scope.readable_paths, editable_paths: task.editable_paths, frozen_paths: value.goal.scope.frozen_paths }, required_inputs: value.goal.scope.readable_paths, required_outputs: task.required_outputs, verification_commands: task.verification_command_ids === undefined ? commands : commands.filter((command) => task.verification_command_ids!.includes(command.command_id)) }));
  const route = { logical_role: value.expected_route.logical_role, provider_id: value.expected_route.provider_id, model_id: value.expected_route.model_id, effort: value.expected_route.effort };
  const plan = { content_sha256: digest("c"), bindings: { scope: value.goal.scope, required_inputs: value.goal.scope.readable_paths, required_outputs: value.goal.required_outputs, limits: { static_time_budgets: value.static_time_budgets, max_wall_time_ms: value.static_time_budgets.workflow_wall_ms, max_attempts_per_leaf: value.static_max_attempts_per_leaf }, logical_routes: [route], verification_commands: commands } };
  return { mode: "STATIC_APPROVED_DAG", plan, tasks, executionAuthority: { plan, mode: "STATIC_APPROVED_DAG", repository: { branch: "main", head: HEAD, head_tree: TREE, worktree_root: ROOT }, route_map: { fallback: false, routes: [route] }, tasks, task_graph: { edges: [{ from: "a", to: "b" }] } } };
}

async function withTemporarySpec(action: (path: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "static-approved-dag-cli-")); const path = join(directory, "spec.json");
  try { await writeFile(path, JSON.stringify(spec()), "utf8"); await action(path); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

async function captureStdout<T>(action: () => Promise<T>): Promise<{ readonly result: T; readonly output: string }> {
  const stdout = process.stdout as unknown as { write(chunk: string | Uint8Array): boolean };
  const originalWrite = stdout.write; let output = "";
  // Only the CLI's own writes (always strings) are captured; node:test emits binary reporter chunks through the same patched stream.
  stdout.write = (chunk) => { if (typeof chunk === "string") output += chunk; return true; };
  try { return { result: await action(), output }; }
  finally { stdout.write = originalWrite; }
}

function cliReport(classification: "PASS" | "VALID_BLOCKED" | "INVALID"): any {
  return { classification, spec_sha256: digest("e"), run_label: "cli-test", reason: classification, workflow: null, telemetry: null };
}

test("launcher normalizes a valid spec, binds its canonical digest, and calls the controller once", async () => {
  const source = spec(); const approved = staticApprovedDagSpecSha256(source); let calls = 0;
  const report = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: approved, cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => {
    calls += 1; assert.equal(options?.authority?.verification_commands[0]?.timeout_ms, 60_000); assert.deepEqual(options?.authority?.static_time_budgets, { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }); assert.equal(options?.authority?.static_terra_effort, undefined);
    return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any;
  } });
  assert.equal(calls, 1); assert.equal(report.classification, "PASS"); assert.equal(report.telemetry, null);
});


test("XHigh launch specs bind a distinct digest, exact controller authority, and exact plan route", async () => {
  const high = spec();
  const xhigh = spec();
  (xhigh["expected_route"] as any).effort = "xhigh";
  const normalized = normalizeStaticApprovedDagLaunchSpec(xhigh);
  assert.equal(normalized.expected_route.effort, "xhigh");
  assert.notEqual(staticApprovedDagSpecSha256(high), staticApprovedDagSpecSha256(xhigh));

  const approve = createStaticApprovedDagPlanApproval(normalized);
  assert.equal(await approve(approvalInput(normalized)), digest("c"));
  for (const mutate of [
    (input: any) => { input.plan.bindings.logical_routes[0].effort = "high"; },
    (input: any) => { input.executionAuthority.route_map.routes[0].effort = "high"; },
  ]) {
    const candidate = approvalInput(normalized);
    mutate(candidate);
    assert.equal(await approve(candidate), null);
  }

  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: xhigh, approved_spec_sha256: staticApprovedDagSpecSha256(xhigh), cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => {
    calls += 1;
    assert.equal(options?.authority?.static_terra_effort, "xhigh");
    return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any;
  } });
  assert.equal(calls, 1);
  assert.equal(report.classification, "PASS");

  for (const [source, approved] of [[xhigh, staticApprovedDagSpecSha256(high)], [high, staticApprovedDagSpecSha256(xhigh)]] as const) {
    let substitutedCalls = 0;
    const substituted = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: approved, cwd: ROOT, repositoryFacts: facts, controller: async () => { substitutedCalls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
    assert.equal(substituted.classification, "INVALID");
    assert.equal(substitutedCalls, 0);
  }
});

test("canonical spec digest ignores object key order and wrong approval blocks before controller work", async () => {
  const first = spec(); const second = { expected_route: first["expected_route"], static_max_attempts_per_leaf: 1, static_time_budgets: first["static_time_budgets"], verification_commands: first["verification_commands"], goal: first["goal"], expected_tree: TREE, expected_head: HEAD, expected_repository_branch: "main", run_label: "launcher-test", spec_version: "static-approved-dag-launch-v1" };
  assert.equal(staticApprovedDagSpecSha256(first), staticApprovedDagSpecSha256(second));
  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: first, approved_spec_sha256: digest("0"), cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(calls, 0); assert.equal(report.classification, "INVALID");
});

test("launcher rejects an unknown field in nested scope authority", () => {
  const source = spec(); (source["goal"] as any).scope.unapproved_authority = true;
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source));
});

test("launcher rejects root-like cwd forms and accepts node_modules", () => {
  for (const cwd of [".", "", "/tmp", "../node_modules", "REPOSITORY_ROOT"]) {
    const source = spec(); (source["verification_commands"] as any[])[0]!.cwd = cwd;
    assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source));
  }
  assert.equal(normalizeStaticApprovedDagLaunchSpec(spec()).verification_commands[0]?.cwd, "node_modules");
});

test("verification timeout is bounded independently from worker deadline", () => {
  assert.equal(STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS, 60_000);
  assert.equal(normalizeStaticApprovedDagLaunchSpec(spec()).verification_commands[0]?.timeout_ms, 60_000);
  const overlong = spec(); (overlong["verification_commands"] as any[])[0]!.timeout_ms = 300_000;
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(overlong));
  const workerLong = spec(); (workerLong["static_time_budgets"] as any).worker_deadline_ms = 300_000;
  assert.equal(normalizeStaticApprovedDagLaunchSpec(workerLong).verification_commands[0]?.timeout_ms, 60_000);
});

test("time budgets are structured, ordered, and safe", () => {
  assert.deepEqual(normalizeStaticApprovedDagLaunchSpec(spec()).static_time_budgets, { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 });
  const reordered = spec(); reordered["static_time_budgets"] = { workflow_wall_ms: 1_800_000, worker_deadline_ms: 300_000, node_wall_ms: 600_000 };
  assert.equal(staticApprovedDagSpecSha256(spec()), staticApprovedDagSpecSha256(reordered));
  for (const budgets of [{ worker_deadline_ms: 2, node_wall_ms: 1, workflow_wall_ms: 3 }, { worker_deadline_ms: 1, node_wall_ms: 3, workflow_wall_ms: 2 }, { worker_deadline_ms: 1.5, node_wall_ms: 2, workflow_wall_ms: 3 }, { worker_deadline_ms: Number.MAX_SAFE_INTEGER + 1, node_wall_ms: Number.MAX_SAFE_INTEGER + 1, workflow_wall_ms: Number.MAX_SAFE_INTEGER + 1 }]) {
    const source = spec(); source["static_time_budgets"] = budgets; assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source));
  }
});

test("plan approval binds plan identity, tasks, scope, commands, budgets, and route", async () => {
  const normalized = normalizeStaticApprovedDagLaunchSpec(spec()); const approve = createStaticApprovedDagPlanApproval(normalized);
  assert.equal(await approve(approvalInput(normalized)), digest("c"));
  for (const mutate of [
    (input: any) => { input.executionAuthority.plan = { ...input.plan, content_sha256: digest("d") }; },
    (input: any) => { input.executionAuthority.tasks[0].task_id = "substituted"; },
    (input: any) => { input.plan.bindings.scope.editable_paths = ["out/other.txt"]; },
    (input: any) => { input.plan.bindings.verification_commands[0].cwd = "other"; },
    (input: any) => { input.plan.bindings.limits.static_time_budgets.worker_deadline_ms = 1; },
    (input: any) => { input.plan.bindings.logical_routes[0].model_id = "gpt-5.6-luna"; },
    (input: any) => { input.plan.bindings.logical_routes[0].effort = "xhigh"; },
  ]) { const candidate = approvalInput(normalized); mutate(candidate); assert.equal(await approve(candidate), null); }
});

test("repository preflight drift blocks before controller invocation", async () => {
  for (const change of ["branch", "head", "tree", "dirty"] as const) {
    let calls = 0; const report = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: async () => ({ ...(await facts()), ...(change === "branch" ? { branch: "other" } : change === "head" ? { head: "c".repeat(40) } : change === "tree" ? { tree: "d".repeat(40) } : { clean: false }) }), controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
    assert.equal(calls, 0, change); assert.equal(report.classification, "INVALID");
  }
});

test("result classification distinguishes PASS, admitted BLOCKED, and INVALID", async () => {
  const approved = staticApprovedDagSpecSha256(spec());
  for (const [result, expected] of [[{ outcome: "PASS", reason: "ok", finalState: { phase: "PASS" } }, "PASS"], [{ outcome: "BLOCKED", reason: "blocked", finalState: { phase: "BLOCKED" } }, "VALID_BLOCKED"], [{ outcome: "BLOCKED", reason: "not admitted", finalState: null }, "INVALID"]] as const) {
    const report = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: approved, cwd: ROOT, repositoryFacts: facts, controller: async () => result as any });
    assert.equal(report.classification, expected); assert.equal(report.telemetry, null);
  }
});

const passFinalState = {
  phase: "PASS",
  counters: { worker_invocations: { sol_closeout: 0, luna_executor: 0, terra_executor: 2 }, direct_attempts: 0, single_owner_mutation_cycles: 0, constrained_replans: 0, leaves_completed: 2 },
  tasks: [
    { task_id: "a", status: "PASS", attempts: 1, postflight_completed: true, verification_completed: true, retry_progress_admitted: false },
    { task_id: "b", status: "PASS", attempts: 1, postflight_completed: true, verification_completed: true, retry_progress_admitted: false },
  ],
  active_task_id: null,
  terminal_reason: null,
};
const blockedFinalState = {
  phase: "BLOCKED",
  counters: { worker_invocations: { sol_closeout: 0, luna_executor: 0, terra_executor: 2 }, direct_attempts: 0, single_owner_mutation_cycles: 0, constrained_replans: 0, leaves_completed: 1 },
  tasks: [
    { task_id: "a", status: "PASS", attempts: 1, postflight_completed: true, verification_completed: true, retry_progress_admitted: false },
    { task_id: "b", status: "RUNNING", attempts: 2, postflight_completed: false, verification_completed: false, retry_progress_admitted: true },
  ],
  active_task_id: "b",
  terminal_reason: "BLOCKED: leaf verification failed after admitted retry",
};

test("PASS report projects the authoritative final state summary", async () => {
  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: passFinalState, evidenceRoot: "/tmp/evidence/run-1" } as any; } });
  assert.equal(calls, 1);
  assert.equal(report.classification, "PASS");
  assert.deepEqual(report.workflow, { outcome: "PASS", final_phase: "PASS", terminal_reason: null, active_task_id: null, leaves_completed: 2, terra_worker_invocations: 2, coding_worker_invocations: null, tasks: passFinalState.tasks });
  assert.equal(report.evidence_root, "/tmp/evidence/run-1");
  assert.equal(report.hygiene_warning, null);
  assert.equal(report.telemetry, null);
});

test("VALID_BLOCKED report truthfully exposes the blocked final state", async () => {
  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "BLOCKED", reason: "BLOCKED: leaf verification failed after admitted retry", finalState: blockedFinalState, evidenceRoot: "/tmp/evidence/run-2", hygieneWarning: "worktree lock release could not be proved" } as any; } });
  assert.equal(calls, 1);
  assert.equal(report.classification, "VALID_BLOCKED");
  assert.deepEqual(report.workflow, { outcome: "BLOCKED", final_phase: "BLOCKED", terminal_reason: "BLOCKED: leaf verification failed after admitted retry", active_task_id: "b", leaves_completed: 1, terra_worker_invocations: 2, coding_worker_invocations: null, tasks: blockedFinalState.tasks });
  assert.equal(report.evidence_root, "/tmp/evidence/run-2");
  assert.equal(report.hygiene_warning, "worktree lock release could not be proved");
  assert.equal(report.telemetry, null);
});

test("INVALID report keeps the workflow summary null and fabricates no counters or tasks", async () => {
  let calls = 0;
  const rejected = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "BLOCKED", reason: "not admitted", finalState: null } as any; } });
  assert.equal(calls, 1);
  assert.equal(rejected.classification, "INVALID");
  assert.equal(rejected.workflow, null);
  assert.equal(rejected.evidence_root, null);
  assert.equal(rejected.hygiene_warning, null);
  assert.equal(rejected.telemetry, null);

  const drifted = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: async () => ({ ...(await facts()), clean: false }), controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: passFinalState } as any; } });
  assert.equal(calls, 1);
  assert.equal(drifted.classification, "INVALID");
  assert.equal(drifted.workflow, null);
  assert.equal(drifted.evidence_root, null);
  assert.equal(drifted.hygiene_warning, null);
});

test("evidence root and hygiene warning are projected only when the controller returned them", async () => {
  const without = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: facts, controller: async () => ({ outcome: "PASS", reason: "PASS", finalState: passFinalState }) as any });
  assert.equal(without.classification, "PASS");
  assert.equal(without.evidence_root, null);
  assert.equal(without.hygiene_warning, null);

  const bounded = await executeStaticApprovedDag({ spec: spec(), approved_spec_sha256: staticApprovedDagSpecSha256(spec()), cwd: ROOT, repositoryFacts: facts, controller: async () => ({ outcome: "BLOCKED", reason: "blocked", finalState: blockedFinalState, evidenceRoot: "/tmp/evidence/run-3", hygieneWarning: "x".repeat(5_000) }) as any });
  assert.equal(bounded.classification, "VALID_BLOCKED");
  assert.equal(bounded.evidence_root, "/tmp/evidence/run-3");
  assert.equal(bounded.hygiene_warning, "x".repeat(4_096));
});

test("state summary projection preserves spec digest, plan approval, route authority, and exactly-once invocation", async () => {
  const source = spec();
  assert.equal(staticApprovedDagSpecSha256(source), "sha256:160ad49e913ec431b2e757ee50ab4ba37051a1d0b2a0abd8a242ba65b763e262");
  const normalized = normalizeStaticApprovedDagLaunchSpec(source);
  const approve = createStaticApprovedDagPlanApproval(normalized);
  assert.equal(await approve(approvalInput(normalized)), digest("c"));
  const mutated = approvalInput(normalized);
  mutated.executionAuthority.route_map.routes[0].effort = "xhigh";
  assert.equal(await approve(mutated), null);

  let highCalls = 0; let xhighCalls = 0;
  const high = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: staticApprovedDagSpecSha256(source), cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => { highCalls += 1; assert.equal(options?.authority?.static_terra_effort, undefined); return { outcome: "PASS", reason: "PASS", finalState: passFinalState } as any; } });
  const xhigh = spec(); (xhigh["expected_route"] as any).effort = "xhigh";
  const xhighReport = await executeStaticApprovedDag({ spec: xhigh, approved_spec_sha256: staticApprovedDagSpecSha256(xhigh), cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => { xhighCalls += 1; assert.equal(options?.authority?.static_terra_effort, "xhigh"); return { outcome: "PASS", reason: "PASS", finalState: passFinalState } as any; } });
  assert.equal(highCalls, 1); assert.equal(xhighCalls, 1);
  assert.equal(high.classification, "PASS"); assert.equal(xhighReport.classification, "PASS");
});

test("static route rejects non-static modes, non-Terra routes, Max, and fallback", () => {
  for (const mode of ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"]) { const source = spec(); (source["goal"] as any).execution_mode = mode; assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source)); }
  for (const route of [{ logical_role: "LUNA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-luna", effort: "high", fallback: false }, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "max", fallback: false }, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: true }]) { const source = spec(); source["expected_route"] = route; assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source)); }
});

test("launcher has no manual verification path and npm entrypoint builds before the built CLI", async () => {
  const source = await readFile(new URL("../src/static-approved-dag-launcher.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /node:child_process|execFile\(|spawn\(/u);
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as { scripts: Record<string, string> };
  assert.match(packageJson.scripts["static-dag"]!, /^npm run build && node dist\/src\/cli\/static-approved-dag\.js$/u);
});

test("CLI rejects every --report request before canonical execution", async () => {
  for (const reportPath of [join(ROOT, "report.json"), "../outside/report.json", "/tmp/static-approved-dag-report.json"]) {
    let calls = 0;
    const captured = await captureStdout(() => staticApprovedDagCliMain(["missing-spec.json", "--approved-spec-sha256", digest("a"), "--report", reportPath], async () => { calls += 1; return cliReport("PASS"); }));
    assert.equal(captured.result, 2); assert.equal(calls, 0); assert.match(captured.output, /--report is not supported/u);
  }
});

test("CLI emits PASS, VALID_BLOCKED, and INVALID reports once on stdout", async () => {
  await withTemporarySpec(async (path) => {
    for (const [classification, exitCode] of [["PASS", 0], ["VALID_BLOCKED", 3], ["INVALID", 2]] as const) {
      let calls = 0;
      const captured = await captureStdout(() => staticApprovedDagCliMain([path, "--approved-spec-sha256", digest("a")], async () => { calls += 1; return cliReport(classification); }));
      assert.equal(captured.result, exitCode); assert.equal(calls, 1); assert.equal(JSON.parse(captured.output).classification, classification);
    }
  });
});

test("CLI stdout failure cannot repeat canonical execution", async () => {
  await withTemporarySpec(async (path) => {
    const stdout = process.stdout as unknown as { write(chunk: string | Uint8Array): boolean }; const originalWrite = stdout.write; let calls = 0;
    stdout.write = () => { throw new Error("stdout unavailable"); };
    try {
      await assert.rejects(staticApprovedDagCliMain([path, "--approved-spec-sha256", digest("a")], async () => { calls += 1; return cliReport("PASS"); }), /stdout unavailable/u);
      assert.equal(calls, 1);
    } finally { stdout.write = originalWrite; }
  });
});

function threeNodeSpec(): Record<string, unknown> {
  const source = spec();
  source["goal"] = { ...(source["goal"] as any), scope: { readable_paths: ["node_modules"], editable_paths: ["out/a.txt", "out/b.txt", "out/c.txt"], frozen_paths: ["node_modules"] }, required_outputs: ["out/a.txt", "out/b.txt", "out/c.txt"], tasks: [
    { task_id: "a", objective: "Write a.", editable_paths: ["out/a.txt"], required_outputs: ["out/a.txt"], dependencies: [] },
    { task_id: "b", objective: "Write b.", editable_paths: ["out/b.txt"], required_outputs: ["out/b.txt"], dependencies: ["a"], verification_command_ids: ["tsx"] },
    { task_id: "c", objective: "Write c.", editable_paths: ["out/c.txt"], required_outputs: ["out/c.txt"], dependencies: ["a", "b"] },
  ] };
  return source;
}

function reversedKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reversedKeys);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).reverse().map(([key, entry]) => [key, reversedKeys(entry)]));
  return value;
}

test("inspection projects the exact 3-node topology, verifier selection, route, and budgets", () => {
  const report = inspectStaticApprovedDagSpec(threeNodeSpec());
  assert.equal(report.classification, "INSPECTED");
  assert.equal(report.spec_version, "static-approved-dag-launch-v1");
  assert.equal(report.run_label, "launcher-test");
  assert.deepEqual(report.repository, { expected_branch: "main", expected_head: HEAD, expected_tree: TREE });
  assert.equal(report.graph!.node_count, 3);
  assert.equal(report.graph!.edge_count, 3);
  assert.deepEqual(report.graph!.nodes.map((node) => node.task_id), ["a", "b", "c"]);
  assert.deepEqual(report.graph!.nodes.map((node) => node.dependencies), [[], ["a"], ["a", "b"]]);
  assert.deepEqual(report.graph!.edges, [{ from: "a", to: "b" }, { from: "a", to: "c" }, { from: "b", to: "c" }]);
  assert.deepEqual(report.graph!.nodes[0]!.verification_command_ids, ["tsx"]);
  assert.deepEqual(report.graph!.nodes[1]!.verification_command_ids, ["tsx"]);
  assert.deepEqual(report.graph!.nodes[2]!.verification_command_ids, ["tsx"]);
  assert.deepEqual(report.route, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: false });
  assert.deepEqual(report.budgets, { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000, max_attempts_per_leaf: 1 });
  assert.deepEqual(report.verification_commands, [{ command_id: "tsx", cwd: "node_modules", timeout_ms: 60_000 }]);
});

test("inspection output is deterministic across equivalent JSON object key order", () => {
  const first = inspectStaticApprovedDagSpec(threeNodeSpec());
  const second = inspectStaticApprovedDagSpec(reversedKeys(threeNodeSpec()));
  assert.deepEqual(first, second);
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.equal(first.spec_sha256, second.spec_sha256);
});

test("inspection digest equals the canonical spec digest and is accepted unchanged by execution", async () => {
  const source = threeNodeSpec();
  const report = inspectStaticApprovedDagSpec(source);
  assert.equal(report.spec_sha256, staticApprovedDagSpecSha256(source));
  let calls = 0;
  const launch = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: report.spec_sha256!, cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(calls, 1);
  assert.equal(launch.classification, "PASS");
});

test("High and XHigh specs both inspect successfully with distinct efforts and digests", () => {
  const high = inspectStaticApprovedDagSpec(threeNodeSpec());
  const xhighSource = threeNodeSpec(); (xhighSource["expected_route"] as any).effort = "xhigh";
  const xhigh = inspectStaticApprovedDagSpec(xhighSource);
  assert.equal(high.classification, "INSPECTED"); assert.equal(xhigh.classification, "INSPECTED");
  assert.equal(high.route!.effort, "high"); assert.equal(xhigh.route!.effort, "xhigh");
  assert.notEqual(high.spec_sha256, xhigh.spec_sha256);
});

test("inspection keeps invalid specs INVALID without repair and exposes no projection", () => {
  for (const mutate of [
    (source: Record<string, unknown>) => { (source["goal"] as any).scope.unapproved_authority = true; },
    (source: Record<string, unknown>) => { source["expected_route"] = { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "max", fallback: false }; },
    (source: Record<string, unknown>) => { source["spec_version"] = "unknown-version"; },
  ]) {
    const source = threeNodeSpec(); mutate(source);
    const report = inspectStaticApprovedDagSpec(source);
    assert.equal(report.classification, "INVALID");
    assert.notEqual(report.reason, "");
    assert.equal(report.spec_sha256, null); assert.equal(report.graph, null); assert.equal(report.route, null);
  }
});

test("inspection is provider-free: the CLI inspect path never invokes the executor", async () => {
  await withTemporarySpec(async (path) => {
    for (const argv of [["inspect", path], ["inspect", "missing-spec.json"]]) {
      let calls = 0;
      const captured = await captureStdout(() => staticApprovedDagCliMain(argv, async () => { calls += 1; return cliReport("PASS"); }));
      assert.equal(calls, 0, argv.join(" "));
      assert.equal(JSON.parse(captured.output).classification, argv.length === 2 && argv[1] === path ? "INSPECTED" : "INVALID");
    }
  });
});

test("inspection ignores repository drift while execution still rejects the same spec before the controller", async () => {
  const drifted = threeNodeSpec(); drifted["expected_head"] = "c".repeat(40);
  const inspected = inspectStaticApprovedDagSpec(drifted);
  assert.equal(inspected.classification, "INSPECTED");
  assert.equal(inspected.repository!.expected_head, "c".repeat(40));
  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: drifted, approved_spec_sha256: staticApprovedDagSpecSha256(drifted), cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(calls, 0);
  assert.equal(report.classification, "INVALID");
});

test("inspection output stays privacy-bounded: no objective text, absolute executables, or verifier argv", () => {
  const text = JSON.stringify(inspectStaticApprovedDagSpec(threeNodeSpec()));
  assert.doesNotMatch(text, /Write a\.|objective|stop_condition/u);
  assert.ok(!text.includes(process.execPath));
  assert.ok(!text.includes("tsx/dist/cli.mjs"));
  assert.ok(!text.includes(ROOT));
  assert.ok(!text.includes('"args"'));
  assert.ok(!text.includes('"executable"'));
});

test("CLI inspect emits INSPECTED JSON with exit 0 and never executes; invalid inspect forms exit 2", async () => {
  await withTemporarySpec(async (path) => {
    let calls = 0;
    const valid = await captureStdout(() => staticApprovedDagCliMain(["inspect", path], async () => { calls += 1; return cliReport("PASS"); }));
    assert.equal(valid.result, 0); assert.equal(calls, 0);
    const parsed = JSON.parse(valid.output) as any;
    assert.equal(parsed.classification, "INSPECTED");
    assert.equal(parsed.spec_sha256, staticApprovedDagSpecSha256(spec()));
    assert.equal(parsed.graph.node_count, 2);
    assert.equal(parsed.graph.edge_count, 1);
    for (const argv of [["inspect"], ["inspect", path, "--approved-spec-sha256", digest("a")], ["inspect", path, "extra-arg"], ["inspect", path, "--report", "report.json"], ["inspect", "--unknown", path]]) {
      const captured = await captureStdout(() => staticApprovedDagCliMain(argv, async () => { calls += 1; return cliReport("PASS"); }));
      assert.equal(captured.result, 2, argv.join(" ")); assert.equal(calls, 0, argv.join(" "));
      assert.equal((JSON.parse(captured.output) as any).classification, "INVALID", argv.join(" "));
    }
  });
});

const EXECUTE_INVALID_KEYS = ["classification", "spec_sha256", "run_label", "reason", "workflow", "telemetry"].sort();
const INSPECT_INVALID_KEYS = ["classification", "spec_version", "spec_sha256", "run_label", "reason", "repository", "graph", "route", "budgets", "verification_commands"].sort();

test("execute-mode pre-execution failures keep the exact legacy execution INVALID shape", async () => {
  for (const argv of [["missing-spec.json"], [join(ROOT, "..", "outside-spec.json"), "--approved-spec-sha256", digest("a")]]) {
    let calls = 0;
    const captured = await captureStdout(() => staticApprovedDagCliMain(argv, async () => { calls += 1; return cliReport("PASS"); }));
    assert.equal(captured.result, 2); assert.equal(calls, 0);
    const parsed = JSON.parse(captured.output) as Record<string, unknown>;
    assert.deepEqual(Object.keys(parsed).sort(), EXECUTE_INVALID_KEYS, argv.join(" "));
    assert.equal(parsed["classification"], "INVALID"); assert.notEqual(parsed["reason"], "");
  }
});

test("inspect-mode pre-execution failures keep the inspection INVALID shape", async () => {
  for (const argv of [["inspect"], ["inspect", join(ROOT, "..", "missing-inspect-spec.json"), "--approved-spec-sha256", digest("a")], ["inspect", "missing-inspect-spec.json"]]) {
    let calls = 0;
    const captured = await captureStdout(() => staticApprovedDagCliMain(argv, async () => { calls += 1; return cliReport("PASS"); }));
    assert.equal(captured.result, 2); assert.equal(calls, 0);
    const parsed = JSON.parse(captured.output) as Record<string, unknown>;
    assert.deepEqual(Object.keys(parsed).sort(), INSPECT_INVALID_KEYS, argv.join(" "));
    assert.equal(parsed["classification"], "INVALID"); assert.notEqual(parsed["reason"], "");
  }
});

// ---------------------------------------------------------------------------
// Task 4: static-approved-dag-launch-v2 — capability-oriented CODING_EXECUTOR
// ---------------------------------------------------------------------------

// Portable V1 freeze pins: computed from the exact spec shapes below with a
// fixed executable, so the digest is machine-independent historical authority.
const V1_PIN_SPEC = {
  spec_version: "static-approved-dag-launch-v1", run_label: "launcher-test", expected_repository_branch: "main", expected_head: HEAD, expected_tree: TREE,
  goal: { objective: "Write exactly two outputs.", stop_condition: "Stop after verification.", execution_mode: "STATIC_APPROVED_DAG", scope: { readable_paths: ["node_modules"], editable_paths: ["out/a.txt", "out/b.txt"], frozen_paths: ["node_modules"] }, required_outputs: ["out/a.txt", "out/b.txt"], tasks: [
    { task_id: "a", objective: "Write a.", editable_paths: ["out/a.txt"], required_outputs: ["out/a.txt"], dependencies: [] },
    { task_id: "b", objective: "Write b.", editable_paths: ["out/b.txt"], required_outputs: ["out/b.txt"], dependencies: ["a"] },
  ] },
  verification_commands: [{ command_id: "tsx", executable: "/usr/bin/tsx", args: ["--version"], cwd: "node_modules", timeout_ms: 60_000 }],
  static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
  expected_route: { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: false },
};
const V1_FROZEN_HIGH_DIGEST = "sha256:c557d053d284175ae8bd683341679f456a58ec799593ab183888255aeb1c1ed8";
const V1_FROZEN_XHIGH_DIGEST = "sha256:792fa269f752717023643b977307ef11cb0904952c6fcfb48104c2a842b58fbc";

function v2Spec(expectedRoute: Record<string, unknown> = { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false }): Record<string, unknown> {
  const source = spec();
  source["spec_version"] = "static-approved-dag-launch-v2";
  source["expected_route"] = expectedRoute;
  source["verification_commands"] = (source["verification_commands"] as Array<Record<string, unknown>>).map((command) => ({ ...command, readable_paths: [{ path: "node_modules", kind: "PREFIX" }] }));
  return source;
}

test("V1 freeze: legacy Terra specs keep their exact historical digests and route semantics", () => {
  assert.equal(staticApprovedDagSpecSha256(V1_PIN_SPEC), V1_FROZEN_HIGH_DIGEST);
  const xhigh = structuredClone(V1_PIN_SPEC); (xhigh["expected_route"] as any).effort = "xhigh";
  assert.equal(staticApprovedDagSpecSha256(xhigh), V1_FROZEN_XHIGH_DIGEST);
  const normalized = normalizeStaticApprovedDagLaunchSpec(V1_PIN_SPEC);
  assert.equal(normalized.spec_version, "static-approved-dag-launch-v1");
  assert.deepEqual(normalized.expected_route, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: false });
});

test("V1 freeze rejects verifier-specific readable authority without changing legacy normalization", () => {
  const widened = structuredClone(V1_PIN_SPEC); (widened.verification_commands[0] as any).readable_paths = [{ path: "node_modules", kind: "PREFIX" }];
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(widened), (error: unknown) => error instanceof StaticApprovedDagLaunchError && error.code === "INVALID_SPEC");
  assert.equal(Object.hasOwn(normalizeStaticApprovedDagLaunchSpec(V1_PIN_SPEC).verification_commands[0]!, "readable_paths"), false);
});

test("V2 CODING_EXECUTOR spec normalizes and inspects with its exact bounded route", () => {
  const normalized = normalizeStaticApprovedDagLaunchSpec(v2Spec());
  assert.equal(normalized.spec_version, "static-approved-dag-launch-v2");
  assert.deepEqual(normalized.expected_route, { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false });
  const report = inspectStaticApprovedDagSpec(v2Spec());
  assert.equal(report.classification, "INSPECTED");
  assert.equal(report.spec_version, "static-approved-dag-launch-v2");
  assert.deepEqual(report.route, { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false });
  assert.equal(report.graph!.node_count, 2);
  assert.deepEqual(report.verification_commands, [{ command_id: "tsx", cwd: "node_modules", timeout_ms: 60_000, readable_paths: [{ path: "node_modules", kind: "PREFIX" }] }]);
});

test("V2 model identity is routing data: different provider/model produce different digests over an identical graph", () => {
  const first = inspectStaticApprovedDagSpec(v2Spec());
  const second = inspectStaticApprovedDagSpec(v2Spec({ logical_role: "CODING_EXECUTOR", provider_id: "provider-b", model_id: "model-b", effort: "high", fallback: false }));
  assert.equal(first.classification, "INSPECTED"); assert.equal(second.classification, "INSPECTED");
  assert.notEqual(first.spec_sha256, second.spec_sha256);
  assert.deepEqual(first.graph, second.graph);
  const widened = v2Spec(); ((widened["verification_commands"] as any[])[0].readable_paths as any[]).push({ path: "src", kind: "PREFIX" });
  assert.notEqual(inspectStaticApprovedDagSpec(widened).spec_sha256, first.spec_sha256);
  assert.deepEqual(first.budgets, second.budgets);
});

test("V2 binds effort to high only and rejects escalation, fallback, and every legacy role", () => {
  for (const route of [
    { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "xhigh", fallback: false },
    { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "max", fallback: false },
    { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: true },
    { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: false },
    { logical_role: "LUNA_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false },
    { logical_role: "SOL_OWNER", provider_id: "provider-a", model_id: "model-a", effort: "max", fallback: false },
    { logical_role: "SOL_PLANNER", provider_id: "provider-a", model_id: "model-a", effort: "max", fallback: false },
    { logical_role: "SOL_REPLAN", provider_id: "provider-a", model_id: "model-a", effort: "max", fallback: false },
    { logical_role: "SOL_CLOSEOUT", provider_id: "provider-a", model_id: "model-a", effort: "max", fallback: false },
    { logical_role: "BENCHMARK_VERIFIER", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false },
    { logical_role: "BENCHMARK_SELECTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false },
  ]) {
    const source = v2Spec(structuredClone(route));
    assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source), (error: unknown) => error instanceof StaticApprovedDagLaunchError && error.code === "STATIC_ROUTE_RESTRICTED", JSON.stringify(route));
  }
  // Malformed routing identity is a spec-shape failure, not a policy restriction.
  for (const route of [
    { logical_role: "CODING_EXECUTOR", provider_id: "", model_id: "model-a", effort: "high", fallback: false },
    { logical_role: "CODING_EXECUTOR", provider_id: "provider a", model_id: "model-a", effort: "high", fallback: false },
  ]) {
    const source = v2Spec(structuredClone(route));
    assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source), (error: unknown) => error instanceof StaticApprovedDagLaunchError && error.code === "INVALID_SPEC", JSON.stringify(route));
  }
  // V1 keeps rejecting capability routes just as V2 rejects legacy roles.
  const v1Coding = spec(); v1Coding["expected_route"] = { logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high", fallback: false };
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(v1Coding), (error: unknown) => error instanceof StaticApprovedDagLaunchError && error.code === "STATIC_ROUTE_RESTRICTED");
});

test("V2 inspection stays privacy-bounded while showing the exact routing identity", () => {
  const text = JSON.stringify(inspectStaticApprovedDagSpec(v2Spec()));
  assert.match(text, /CODING_EXECUTOR/u);
  assert.match(text, /provider-a/u); assert.match(text, /model-a/u);
  assert.ok(text.includes('"effort":"high"'));
  assert.doesNotMatch(text, /objective|stop_condition|argv|"args"|"executable"/u);
  assert.ok(!text.includes(process.execPath));
});

test("V2 inspect digest is accepted unchanged by execute; post-approval route mutation rejects before the controller", async () => {
  const source = v2Spec();
  const inspected = inspectStaticApprovedDagSpec(source);
  let calls = 0;
  const accepted = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: inspected.spec_sha256!, cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => {
    calls += 1;
    assert.deepEqual(options?.authority?.static_coding_route, { provider_id: "provider-a", model_id: "model-a", effort: "high" });
    assert.equal(options?.authority?.static_terra_effort, undefined);
    return { outcome: "PASS", reason: "PASS", finalState: passFinalState } as any;
  } });
  assert.equal(calls, 1);
  assert.equal(accepted.classification, "PASS");

  const mutated = structuredClone(source);
  (mutated["expected_route"] as any).model_id = "model-b";
  let substitutedCalls = 0;
  const rejected = await executeStaticApprovedDag({ spec: mutated, approved_spec_sha256: inspected.spec_sha256!, cwd: ROOT, repositoryFacts: facts, controller: async () => { substitutedCalls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(substitutedCalls, 0);
  assert.equal(rejected.classification, "INVALID");
  assert.match(rejected.reason, /--approved-spec-sha256 does not match the normalized launch spec/u);
});

test("V2 execution forwards the exact approved route as controller authority and reports coding_worker_invocations", async () => {
  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: v2Spec(), approved_spec_sha256: staticApprovedDagSpecSha256(v2Spec()), cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => {
    calls += 1;
    assert.deepEqual(options?.authority?.static_coding_route, { provider_id: "provider-a", model_id: "model-a", effort: "high" });
    assert.equal(options?.authority?.static_terra_effort, undefined);
    return { outcome: "PASS", reason: "PASS", finalState: passFinalState, evidenceRoot: "/tmp/evidence/run-v2" } as any;
  } });
  assert.equal(calls, 1);
  assert.equal(report.classification, "PASS");
  assert.equal(report.workflow!.coding_worker_invocations, 2);
  assert.equal(report.workflow!.terra_worker_invocations, null);
});

// ---------------------------------------------------------------------------
// Task 4 narrow repair: real Pi provider/model route identities (Ox Alpha)
// ---------------------------------------------------------------------------

const OX_ROUTE = { logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false };

test("V2 accepts the exact discovered Ox route identity in normalization and inspection", () => {
  const source = v2Spec(structuredClone(OX_ROUTE));
  const normalized = normalizeStaticApprovedDagLaunchSpec(source);
  assert.deepEqual(normalized.expected_route, OX_ROUTE);
  const report = inspectStaticApprovedDagSpec(source);
  assert.equal(report.classification, "INSPECTED");
  assert.equal(report.spec_version, "static-approved-dag-launch-v2");
  assert.equal(report.route!.provider_id, "openrouter");
  assert.equal(report.route!.model_id, "stealth/ox-alpha");
  assert.equal(report.route!.effort, "high");
  assert.equal(report.route!.fallback, false);
  assert.match(report.spec_sha256!, /^sha256:[0-9a-f]{64}$/u);
});

test("V2 digest binding: swapping stealth/ox-alpha for another/model invalidates the prior approval before the controller", async () => {
  const source = v2Spec(structuredClone(OX_ROUTE));
  const approved = inspectStaticApprovedDagSpec(source).spec_sha256!;
  let calls = 0;
  const accepted = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: approved, cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(calls, 1);
  assert.equal(accepted.classification, "PASS");

  const substituted = structuredClone(source);
  (substituted["expected_route"] as any).model_id = "another/model";
  assert.notEqual(staticApprovedDagSpecSha256(substituted), approved);
  let substitutedCalls = 0;
  const rejected = await executeStaticApprovedDag({ spec: substituted, approved_spec_sha256: approved, cwd: ROOT, repositoryFacts: facts, controller: async () => { substitutedCalls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(substitutedCalls, 0);
  assert.equal(rejected.classification, "INVALID");
  assert.match(rejected.reason, /--approved-spec-sha256 does not match the normalized launch spec/u);
});

test("V2 routing identity rejects whitespace, control characters, oversize values, and empty identifiers at every layer", () => {
  const overlong = `a${"x".repeat(128)}`;
  for (const bad of ["", " openrouter", "openrouter ", "stealth /ox-alpha", "stealth/\nox-alpha", "bad\tid", overlong]) {
    const source = v2Spec({ ...OX_ROUTE, provider_id: bad });
    assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source), (error: unknown) => error instanceof StaticApprovedDagLaunchError && error.code === "INVALID_SPEC", JSON.stringify(bad));
    const badModel = v2Spec({ ...OX_ROUTE, model_id: bad });
    assert.throws(() => normalizeStaticApprovedDagLaunchSpec(badModel), (error: unknown) => error instanceof StaticApprovedDagLaunchError && error.code === "INVALID_SPEC", JSON.stringify(bad));
    assert.equal(inspectStaticApprovedDagSpec(badModel).classification, "INVALID");
  }
});
