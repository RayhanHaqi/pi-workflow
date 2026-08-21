import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS,
  createStaticApprovedDagPlanApproval,
  executeStaticApprovedDag,
  normalizeStaticApprovedDagLaunchSpec,
  staticApprovedDagSpecSha256,
  type StaticApprovedDagLaunchSpec,
} from "../src/static-approved-dag-launcher.js";

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
  const tasks = value.goal.tasks.map((task, index) => ({ task_id: task.task_id, objective: task.objective, assigned_role: "TERRA_EXECUTOR", write_owner: task.task_id, dependencies: task.dependencies, scope: { readable_paths: value.goal.scope.readable_paths, editable_paths: task.editable_paths, frozen_paths: value.goal.scope.frozen_paths }, required_inputs: value.goal.scope.readable_paths, required_outputs: task.required_outputs, verification_commands: task.verification_command_ids === undefined ? commands : commands.filter((command) => task.verification_command_ids!.includes(command.command_id)) }));
  const route = { logical_role: value.expected_route.logical_role, provider_id: value.expected_route.provider_id, model_id: value.expected_route.model_id, effort: value.expected_route.effort };
  const plan = { content_sha256: digest("c"), bindings: { scope: value.goal.scope, required_inputs: value.goal.scope.readable_paths, required_outputs: value.goal.required_outputs, limits: { static_time_budgets: value.static_time_budgets, max_wall_time_ms: value.static_time_budgets.workflow_wall_ms, max_attempts_per_leaf: value.static_max_attempts_per_leaf }, logical_routes: [route], verification_commands: commands } };
  return { mode: "STATIC_APPROVED_DAG", plan, tasks, executionAuthority: { plan, mode: "STATIC_APPROVED_DAG", repository: { branch: "main", head: HEAD, head_tree: TREE, worktree_root: ROOT }, route_map: { fallback: false, routes: [route] }, tasks, task_graph: { edges: [{ from: "a", to: "b" }] } } };
}

test("launcher normalizes a valid spec, binds its canonical digest, and calls the controller once", async () => {
  const source = spec(); const approved = staticApprovedDagSpecSha256(source); let calls = 0;
  const report = await executeStaticApprovedDag({ spec: source, approved_spec_sha256: approved, cwd: ROOT, repositoryFacts: facts, controller: async (_goal, options) => {
    calls += 1; assert.equal(options?.authority?.verification_commands[0]?.timeout_ms, 60_000); assert.deepEqual(options?.authority?.static_time_budgets, { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 });
    return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any;
  } });
  assert.equal(calls, 1); assert.equal(report.classification, "PASS"); assert.equal(report.telemetry, null);
});

test("canonical spec digest ignores object key order and wrong approval blocks before controller work", async () => {
  const first = spec(); const second = { expected_route: first["expected_route"], static_max_attempts_per_leaf: 1, static_time_budgets: first["static_time_budgets"], verification_commands: first["verification_commands"], goal: first["goal"], expected_tree: TREE, expected_head: HEAD, expected_repository_branch: "main", run_label: "launcher-test", spec_version: "static-approved-dag-launch-v1" };
  assert.equal(staticApprovedDagSpecSha256(first), staticApprovedDagSpecSha256(second));
  let calls = 0;
  const report = await executeStaticApprovedDag({ spec: first, approved_spec_sha256: digest("0"), cwd: ROOT, repositoryFacts: facts, controller: async () => { calls += 1; return { outcome: "PASS", reason: "PASS", finalState: { phase: "PASS" } } as any; } });
  assert.equal(calls, 0); assert.equal(report.classification, "INVALID");
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

test("static route rejects non-static modes, non-Terra routes, XHigh/Max, and fallback", () => {
  for (const mode of ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"]) { const source = spec(); (source["goal"] as any).execution_mode = mode; assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source)); }
  for (const route of [{ logical_role: "LUNA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-luna", effort: "high", fallback: false }, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "xhigh", fallback: false }, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "max", fallback: false }, { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: true }]) { const source = spec(); source["expected_route"] = route; assert.throws(() => normalizeStaticApprovedDagLaunchSpec(source)); }
});

test("launcher has no manual verification path and npm entrypoint builds before the built CLI", async () => {
  const source = await readFile(new URL("../src/static-approved-dag-launcher.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /node:child_process|execFile\(|spawn\(/u);
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as { scripts: Record<string, string> };
  assert.match(packageJson.scripts["static-dag"]!, /^npm run build && node dist\/src\/cli\/static-approved-dag\.js$/u);
});
