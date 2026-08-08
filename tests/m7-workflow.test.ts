import { execFile as execFileCallback, spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import assert from "node:assert/strict";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import {
  compileGoalToTask,
  prepareWorkflow,
  runApprovedWorkflow,
  type WorkflowExecutionOptions,
  type WorkflowRunResult,
  WorkflowValidationError,
} from "../src/workflow.js";
import { inspectRunStorage, publishM6WorkerRecord } from "../src/persistence/store.js";
import { M6_RUNTIME_MODULES } from "../src/persistence/m6-authority.js";
import type { M6DirectReadOnlyWorkerInput, M6WorkerExecutionResult } from "../src/pi-adapter/worker.js";
import { identifyContractDocument } from "../src/schemas/index.js";
import workflowExtension from "../src/pi-extension/workflow.js";

const execFile = promisify(execFileCallback);

async function runProcess(command: string, args: readonly string[], cwd: string): Promise<{ readonly code: number; readonly stdout: string; readonly stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { cwd });
    const stdout: Buffer[] = []; const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code) => resolve({ code: code ?? 1, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") }));
    child.stdin.end();
  });
}

function goal(): Record<string, any> {
  return {
    objective: "Inspect one selected source and report its bounded state.",
    resources: [{ path: "README.md", max_bytes: 1024, data_class: "PUBLIC_SOURCE" }],
    non_goals: ["Do not edit files", "Do not use network"],
    deliverable: "One structured report.",
    acceptance_criteria: [{ criterion_id: "report", description: "The bounded report is completed.", evidence_kind: "DIGEST", owner_acceptance: false }],
    verification_commands: [],
    budget: { max_worker_invocations: 1, max_model_turns: 2, max_tool_calls: 2, max_wall_time_ms: 120000, max_read_bytes: 1024 },
    stop_condition: "Stop after one report.",
  };
}

function fakeWorker(outcome: "COMPLETED" | "BLOCKED" = "COMPLETED"): (input: unknown) => Promise<M6WorkerExecutionResult> {
  return async () => ({
    invocation: { fake: true },
    result: {
      outcome,
      usage: {
        provider_turns: 2,
        model_turns: 2,
        provider_requests: 2,
        tool_calls: 2,
        read_calls: 1,
        report_submissions: 1,
        input_tokens: null,
        output_tokens: null,
        cost_microusd: null,
        wall_time_ms: 10,
      },
    },
    replayed: false,
  } as unknown as M6WorkerExecutionResult);
}

function canonicalWorker(publish = true, outcome: "COMPLETED" | "BLOCKED" = "COMPLETED"): (input: unknown) => Promise<M6WorkerExecutionResult> {
  return async (unknownInput) => {
    const input = unknownInput as M6DirectReadOnlyWorkerInput;
    const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
    if (inspection.status !== "HEALTHY" || inspection.statePointer === null || inspection.workflowState === null || inspection.transitionCommit === null) throw new Error("test M6 fixture lacks committed admission");
    const task = input.runAuthority.task;
    const read = outcome === "COMPLETED"
      ? (await input.gateway.read_scoped({ stateTokenContentSha256: input.gateway.acceptedState.content_sha256 as Sha256Digest, path: task.scope.readable_paths[0]!, offset: 0, length: input.m4ToolPolicy.limits.maximum_read_bytes, mode: "TEXT" })).resultRecord
      : undefined;
    const m5Reservation = input.m5Decision.reservation;
    const projection = {
      protocol_id: "m6-direct-read-v0",
      run_id: input.runId,
      revision: inspection.revision,
      state_pointer_content_sha256: inspection.statePointer.content_sha256,
      current_state_content_sha256: inspection.workflowState.content_sha256,
      predecessor_state_content_sha256: inspection.transitionCommit.previous_workflow_state_content_sha256,
      transition_commit_content_sha256: inspection.transitionCommit.content_sha256,
      m5_decision_content_sha256: input.m5Decision.content_sha256,
      m5_policy_content_sha256: input.m5Policy.content_sha256,
      m5_reservation_decision_key: m5Reservation?.reservation_decision_key ?? null,
      operation_id: input.m5Decision.operation_id!,
      transition_event_content_sha256: inspection.transitionCommit.transition_event_content_sha256,
      predicted_next_state_content_sha256: input.m5Decision.predicted_next_state_content_sha256!,
      execution_mode: "DIRECT_LUNA_HIGH" as const,
      continuation_action: "CONTINUE_ADMITTED_OPERATION" as const,
      logical_role: "LUNA_EXECUTOR" as const,
      repository_identity_content_sha256: input.repository.content_sha256,
      worktree_key: input.repository.worktree_key,
      m3_state_token_content_sha256: input.m3StateToken.content_sha256,
      m4_tool_policy_content_sha256: input.m4ToolPolicy.content_sha256,
      m4_command_catalog_content_sha256: input.m4CommandCatalog.content_sha256,
      task_content_sha256: task.content_sha256,
      task_scope_identity: input.m3StateToken.task_scope_identity,
      route_map_sha256: input.runAuthority.routeMap.route_map_sha256,
      route_map_approval_sha256: input.runAuthority.routeMapApproval.route_map_approval_sha256,
      provider_id: input.runAuthority.routeMap.routes.find((route) => route.logical_role === "LUNA_EXECUTOR")!.provider_id,
      model_id: input.runAuthority.routeMap.routes.find((route) => route.logical_role === "LUNA_EXECUTOR")!.model_id,
      effort: "high" as const,
      runtime_boundary_policy: "OA-M6-02" as const,
      pi_modules: M6_RUNTIME_MODULES.map((expected) => ({ ...expected, resolved_url: import.meta.resolve(expected.specifier) })),
      approved_resources: [],
      system_prompt_sha256: sha256Bytes(Buffer.from(input.systemPrompt, "utf8")),
      user_prompt_sha256: sha256Bytes(Buffer.from(input.userPrompt, "utf8")),
      read_path: task.scope.readable_paths[0]!,
      read_offset: 0,
      read_length: input.m4ToolPolicy.limits.maximum_read_bytes,
      hard_limits: { provider_turns: 2, model_turns: 2, read_calls: 1, tool_calls: 2, report_submissions: 1, prompt_bytes: 32_768, read_bytes: input.m4ToolPolicy.limits.maximum_read_bytes, tool_result_bytes: 69_632, report_canonical_bytes: 4_096, wall_deadline_ms: 120_000 },
      attempt_number: 1,
    };
    const invocation = identifyContractDocument("pi_gacw_m6_worker_invocation_v0", {
      schema_id: "pi_gacw_m6_worker_invocation_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      ...projection, invocation_key: sha256Canonical(projection), admitted_at: new Date().toISOString(),
    }) as M6WorkerExecutionResult["invocation"];
    const completed = outcome === "COMPLETED";
    const readDigest = read?.content_sha256 as Sha256Digest | undefined;
    const result = identifyContractDocument("pi_gacw_m6_worker_result_v0", {
      schema_id: "pi_gacw_m6_worker_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      invocation_key: invocation.invocation_key, invocation_content_sha256: invocation.content_sha256, run_id: input.runId,
      outcome, provider_work_started: completed,
      first_failure_code: completed ? null : "AUTHORITY_REJECTED", first_failure_stage: completed ? null : "M1_M5_ADMISSION",
      worker_report: completed ? { status: "COMPLETED", summary: "Completed the bounded read-only task from authoritative M4 evidence.", evidence_content_sha256: [readDigest!] } : null,
      m4_result_content_sha256: completed ? readDigest! : null,
      usage: { provider_turns: completed ? 2 : 0, model_turns: completed ? 2 : 0, provider_requests: null, tool_calls: completed ? 2 : 0, read_calls: completed ? 1 : 0, report_submissions: completed ? 1 : 0, input_tokens: null, output_tokens: null, cost_microusd: null, wall_time_ms: completed ? 10 : 0 },
      settlement: { prompt_settled: true, agent_idle: true, pending_tool_calls: 0, subscriber_removed: false, queues_empty: false, reset_completed: false, timers_cleared: false, provider_collection_cleared: false, owned_provider_streams: 0, owned_child_processes: 0, owned_sockets: 0, owned_fifos: 0, cleanup_certain: false },
      cleanup_failure_code: null, completed_at: new Date().toISOString(),
    }) as M6WorkerExecutionResult["result"];
    if (publish) {
      await publishM6WorkerRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "M6_WORKER_INVOCATION", document: invocation });
      await publishM6WorkerRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "M6_WORKER_RESULT", document: result });
    }
    return { invocation, result, replayed: false };
  };
}

async function gitRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "m7-workflow-test-"));
  await execFile("git", ["-C", root, "init", "-q", "-b", "main"]);
  await execFile("git", ["-C", root, "config", "user.name", "M7 test"]);
  await execFile("git", ["-C", root, "config", "user.email", "m7@example.invalid"]);
  await writeFile(join(root, "README.md"), "M7 test source\n", "utf8");
  await execFile("git", ["-C", root, "add", "README.md"]);
  await execFile("git", ["-C", root, "commit", "-q", "-m", "initial"]);
  return root;
}

async function productionRun(
  input: Record<string, unknown>,
  worker: (input: unknown) => Promise<M6WorkerExecutionResult>,
  options: Omit<WorkflowExecutionOptions, "cwd" | "worker"> = {},
): Promise<WorkflowRunResult> {
  const root = await gitRepository();
  try {
    const prepared = prepareWorkflow(input);
    return await runApprovedWorkflow(prepared, prepared.task.content_sha256, { ...options, cwd: root, worker });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("M7 compilation is deterministic and binds every Goal execution field", () => {
  const input = goal();
  const first = compileGoalToTask(input);
  const second = compileGoalToTask(structuredClone(input));
  assert.deepEqual(first, second);
  assert.equal(first.task_id, "task-only");
  assert.equal(first.objective.includes("goal_sha256"), false);
  assert.equal(first.objective.includes("m7-ephemeral-goal-v1"), true);
  assert.equal(first.verification_commands.length, 0);
  assert.equal(first.acceptance_criteria[0]?.criterion_id, "report");
  assert.equal(first.acceptance_criteria[0]?.evidence_kind, "DIGEST");

  const variants: Array<(value: Record<string, any>) => void> = [
    (value) => { value["objective"] += " changed"; },
    (value) => { value["resources"][0].path = "package.json"; },
    (value) => { value["resources"][0].max_bytes = 2048; },
    (value) => { value["resources"][0].data_class = "PRIVATE_SOURCE"; },
    (value) => { value["non_goals"][0] = "A different non-goal"; },
    (value) => { value["deliverable"] += " changed"; },
    (value) => { value["acceptance_criteria"][0].description += " changed"; },
    (value) => { value["budget"]["max_wall_time_ms"] = 110000; },
    (value) => { value["budget"]["max_read_bytes"] = 512; },
    (value) => { value["stop_condition"] += " changed"; },
  ];
  for (const mutate of variants) {
    const variant = structuredClone(input) as Record<string, any>;
    mutate(variant);
    assert.notEqual(compileGoalToTask(variant).content_sha256, first.content_sha256);
  }
});

test("M7 deletes Goal executable authority and rejects unsupported acceptance before M5", () => {
  assert.throws(() => compileGoalToTask({ ...goal(), unknown: true }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), budget: { ...goal()["budget"], max_worker_invocations: 2 } }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), verification_commands: [{ command_id: "verify", argv: ["/usr/bin/true"], cwd: "REPOSITORY_ROOT", timeout_ms: 1, network: "FORBIDDEN" }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), verification_commands: [{ command_id: "verify", argv: ["/bin/sh", "-c", "true"], cwd: "REPOSITORY_ROOT", timeout_ms: 1, network: "FORBIDDEN" }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), acceptance_criteria: [{ ...goal()["acceptance_criteria"][0], evidence_kind: "FILE" }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), acceptance_criteria: [{ ...goal()["acceptance_criteria"][0], criterion_id: "arbitrary" }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), resources: [{ path: "../README.md", max_bytes: 1, data_class: "PUBLIC_SOURCE" }] }), WorkflowValidationError);
});

test("approval mismatch and tampering do not reach the shared execution hook", async () => {
  const prepared = prepareWorkflow(goal());
  let executions = 0;
  const executeApproved = async (): Promise<WorkflowRunResult> => {
    executions += 1;
    return { outcome: "PASS", reason: "test", task: prepared.task };
  };
  await assert.rejects(() => runApprovedWorkflow(prepared, "sha256:" + "0".repeat(64), { executeApproved }), WorkflowValidationError);
  assert.equal(executions, 0);
  const tampered = { ...prepared, goal: { ...prepared.goal, objective: "tampered" } } as typeof prepared;
  await assert.rejects(() => runApprovedWorkflow(tampered, prepared.task.content_sha256, { executeApproved }), WorkflowValidationError);
  assert.equal(executions, 0);
});

test("M5 authorization invokes exactly one worker and a completed worker reaches authoritative PASS", async () => {
  let calls = 0;
  const result = await productionRun(goal(), async (input) => { calls += 1; return canonicalWorker()(input); });
  assert.equal(calls, 1, JSON.stringify({ outcome: result.outcome, reason: result.reason, phase: result.finalState?.phase, decision: result.m5Decision }));
  assert.equal(result.outcome, "PASS", JSON.stringify({ reason: result.reason, phase: result.finalState?.phase, decision: result.m5Decision, m6: result.m6 }));
  assert.equal(result.finalState?.phase, "PASS");
  assert.equal(result.m5Decision?.outcome, "PASS");
});

test("M7 uses exact persisted M6 authority instead of a reconstructed worker return", async () => {
  const result = await productionRun(goal(), async (input) => {
    const persisted = await canonicalWorker()(input);
    const reconstructed = identifyContractDocument("pi_gacw_m6_worker_result_v0", {
      ...persisted.result,
      content_sha256: undefined,
      completed_at: new Date(Date.parse(persisted.result.completed_at) + 1).toISOString(),
    }) as M6WorkerExecutionResult["result"];
    return { ...persisted, result: reconstructed };
  });
  assert.equal(result.outcome, "BLOCKED");
  assert.equal(result.finalState?.phase, "BLOCKED");
  assert.match(result.reason, /M6 returned locator does not identify a persisted record/u);
});

test("M5 BLOCK and M6 BLOCKED both stop without retry", async () => {
  let blockedWorkerCalls = 0;
  const commandGoal = { ...goal(), verification_commands: [{ command_id: "verify", argv: ["/usr/bin/false"], cwd: "REPOSITORY_ROOT", timeout_ms: 1000, network: "FORBIDDEN" }] };
  assert.throws(() => prepareWorkflow(commandGoal), WorkflowValidationError);
  assert.equal(blockedWorkerCalls, 0);

  let m6Calls = 0;
  const m6Blocked = await productionRun(goal(), async (input) => { m6Calls += 1; return canonicalWorker(true, "BLOCKED")(input); });
  assert.equal(m6Blocked.outcome, "BLOCKED");
  assert.equal(m6Calls, 1);

  const thrown = await productionRun(goal(), async () => { m6Calls += 1; throw new Error("synthetic M6 failure"); });
  assert.equal(thrown.outcome, "BLOCKED");
  assert.equal(m6Calls, 2);
});

test("/workflow registers one human command and rejects without UI approval", async () => {
  let registered: { name: string; handler: (args: string, context: any) => Promise<void> } | undefined;
  workflowExtension({ registerCommand: (name, options) => { registered = { name, handler: options.handler }; } });
  assert.equal(registered?.name, "workflow");
  const root = await mkdtemp(join(tmpdir(), "m7-extension-test-"));
  try {
    await writeFile(join(root, "goal.json"), JSON.stringify(goal()), "utf8");
    const notifications: string[] = [];
    let confirmed = 0;
    const context = {
      cwd: root,
      hasUI: true,
      signal: undefined,
      ui: {
        setWidget: () => undefined,
        setStatus: () => undefined,
        notify: (message: string) => { notifications.push(message); },
        confirm: async () => { confirmed += 1; return false; },
      },
    };
    await registered!.handler("goal.json", context);
    assert.equal(confirmed, 1);
    assert.equal(notifications.some((message) => message.includes("BLOCKED (not started)")), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI has no approval bypass and rejects before workflow start", async () => {
  const root = await mkdtemp(join(tmpdir(), "m7-cli-test-"));
  try {
    const goalPath = join(root, "goal.json");
    await writeFile(goalPath, JSON.stringify(goal()), "utf8");
    const cli = join(process.cwd(), "dist/src/cli/pi-workflow.js");
    const rejected = await runProcess(process.execPath, [cli, goalPath], root);
    assert.equal(rejected.code, 2);
    assert.match(rejected.stdout, /APPROVAL_REQUIRED sha256:/u);
    assert.match(rejected.stdout, /BLOCKED \(not started\)/u);
    const bypass = await runProcess(process.execPath, [cli, goalPath, "--yes"], root);
    assert.equal(bypass.code, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
