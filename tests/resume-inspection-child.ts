import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { inspectRunStorage } from "../src/persistence/index.js";
import { configureM5PersistenceTestHooks } from "../src/persistence/m5-test-hooks.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";
import { runBoundedMutationWorkflowForTests, type BoundedMutationAuthority, type BoundedMutationGoal } from "../src/workflow-controller.js";

const execFileAsync = promisify(execFile);
const mode = process.argv[2];
if (process.send === undefined || !["READY", "READY_VERIFY", "READY_VERIFY_FAIL", "READY_VERIFY_RETRY", "READY_LIMIT_1", "DELTA", "DELTA_VERIFY", "M5", "WORKER", "AMBIGUOUS", "WINDOW_A", "WINDOW_B", "RESULT", "WINDOW_A_B", "WINDOW_B_B", "WORKER_B", "RESULT_B"].includes(mode ?? "")) {
  throw new Error("resume-inspection-child requires a fixture mode and IPC");
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "resume-inspection-crash-repo-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "resume@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "resume"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "check.mjs"), `process.exit(${mode === "READY_VERIFY_FAIL" || mode === "READY_VERIFY_RETRY" ? 1 : 0});\n`);
  await execFileAsync("git", ["add", "verify"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

async function main(): Promise<void> {
  const root = await repository(); const parent = await mkdtemp(join(tmpdir(), "resume-inspection-crash-retained-"));
  let announced = false;
  const announce = async (): Promise<void> => {
    if (announced) return;
    const entries = await readdir(parent); if (entries.length !== 1) throw new Error("retained workspace is unavailable");
    announced = true; process.send?.({ type: "PAUSED", root: join(parent, entries[0]!), repository: root });
  };
  // The factory runs once per bounded worker execution; the counter is therefore run-scoped, not call-local.
  let executions = 0;
  configureBoundedWorkerFauxRuntimeForTests(() => {
    const call = ++executions;
    return { async execute({ tools }) {
      const path = ["a.txt", "b.txt"][call - 1]!;
      if (mode === "WORKER" && call === 1) { await announce(); await new Promise<void>(() => {}); }
      // WORKER_B: leaf a completes normally (settled history); leaf b's invocation persists without a result.
      if (mode === "WORKER_B" && call === 2) { await announce(); await new Promise<void>(() => {}); }
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport(`wrote ${path}`);
      // Non-null cost keeps usage-evidence identity exercised on its historically drift-prone dimension.
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0, inputTokens: 10, outputTokens: 20, costMicrousd: 1234 };
    } };
  });
  configureM5PersistenceTestHooks({ checkpoint: async (checkpoint, detail) => {
    if (announced) return;
    const entries = await readdir(parent); if (entries.length !== 1) return;
    const stateRoot = join(parent, entries[0]!, "state"); const inspection = await inspectRunStorage({ stateRoot, runId: "pre-m8-bounded" }); const state = inspection.workflowState;
    let pause = false;
    if (checkpoint === "AFTER_STATE_POINTER_UPDATE") {
      const ready = (mode === "READY" || mode === "READY_VERIFY" || mode === "READY_VERIFY_FAIL" || mode === "READY_VERIFY_RETRY" || mode === "READY_LIMIT_1") && state?.phase === "READY" && state.tasks.every((task) => task.status === "PENDING");
      const delta = (mode === "DELTA" || mode === "DELTA_VERIFY") && state?.phase === "READY" && state.tasks.find((task) => task.task_id === "a")?.status === "PASS";
      const reservation = mode === "M5" && state?.phase === "LEAF_RUNNING";
      const ambiguous = mode === "AMBIGUOUS" && state?.phase === "LEAF_FAST_PREFLIGHT";
      pause = ready || delta || reservation || ambiguous;
    } else if (mode === "WINDOW_A" && checkpoint === "AFTER_DECISION_PUBLICATION" && state?.phase === "LEAF_FAST_PREFLIGHT") {
      // Exact WINDOW A seam: the AUTHORIZE_WORK decision is durably published but its M2 transition is not yet committed.
      const records = await readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" });
      pause = records.decisions.some((decision) => decision.intent === "AUTHORIZE_WORK" && decision.operation_id?.startsWith("static-leaf-") === true);
    } else if (mode === "WINDOW_B" && checkpoint === "AFTER_COMMITTED_STATE_BEFORE_RESPONSE" && state?.phase === "LEAF_RUNNING") {
      // Exact WINDOW B seam: START_LEAF_ATTEMPT committed and classified, response not yet returned to the caller.
      pause = true;
    } else if (mode === "RESULT" && checkpoint === "BEFORE_TRANSITION_EVIDENCE_PUBLICATION" && state?.phase === "LEAF_RUNNING") {
      // Result exists while the reducer remains LEAF_RUNNING: the exact refusal seam for existing worker evidence.
      const records = await readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" });
      pause = records.boundedWorkerInvocations.length === 1 && records.boundedWorkerResults.length === 1;
    } else if (mode === "WINDOW_A_B" && checkpoint === "AFTER_DECISION_PUBLICATION" && state?.phase === "LEAF_FAST_PREFLIGHT") {
      // Two-leaf WINDOW A: leaf a fully settled; leaf b's AUTHORIZE_WORK decision durable, transition uncommitted.
      const records = await readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" });
      pause = records.decisions.some((decision) => decision.intent === "AUTHORIZE_WORK" && decision.operation_id === "static-leaf-b-attempt-1");
    } else if (mode === "WINDOW_B_B" && checkpoint === "AFTER_COMMITTED_STATE_BEFORE_RESPONSE" && state?.phase === "LEAF_RUNNING") {
      // Two-leaf WINDOW B: leaf b's START_LEAF_ATTEMPT committed and classified, response lost.
      const records = await readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" });
      pause = records.decisions.some((decision) => decision.content_sha256 === detail && decision.operation_id === "static-leaf-b-attempt-1");
    } else if (mode === "RESULT_B" && checkpoint === "BEFORE_TRANSITION_EVIDENCE_PUBLICATION" && state?.phase === "LEAF_RUNNING") {
      // Leaf b's result exists while the reducer remains LEAF_RUNNING: current-operation refusal seam.
      const records = await readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" });
      pause = records.boundedWorkerInvocations.length === 2 && records.boundedWorkerResults.length === 2;
    }
    if (!pause) return;
    await announce(); await new Promise<void>(() => {});
  } });
  const goal: BoundedMutationGoal = {
    objective: "Write exactly two resume-fixture outputs.", stop_condition: "Stop after deterministic verification.", execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] }, required_outputs: ["a.txt", "b.txt"],
    tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [], verification_command_ids: mode === "READY_VERIFY" || mode === "READY_VERIFY_FAIL" || mode === "READY_VERIFY_RETRY" || mode === "DELTA_VERIFY" ? ["verify"] : [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["a"], verification_command_ids: mode === "READY_VERIFY" || mode === "READY_VERIFY_FAIL" || mode === "READY_VERIFY_RETRY" || mode === "DELTA_VERIFY" ? ["verify"] : [] },
    ],
  };
  const authority: BoundedMutationAuthority = { verification_commands: [{ command_id: "verify", executable: process.execPath, args: ["check.mjs"], cwd: "verify", timeout_ms: 10_000, readable_paths: [{ path: "verify", kind: "PREFIX" }] }], static_max_attempts_per_leaf: mode === "READY_VERIFY_RETRY" ? 2 : 1, static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, ...(mode === "READY_LIMIT_1" ? { hard_mutation_tool_limit: 1 as const } : {}) };
  await runBoundedMutationWorkflowForTests(goal, { cwd: root, authority, retainedArtifactRoot: parent, approveTasks: async ({ plan }) => plan!.content_sha256 as `sha256:${string}` });
  throw new Error("fixture reached terminal state before interruption");
}

main().catch((error: unknown) => { process.send?.({ type: "ERROR", error: error instanceof Error ? error.message : String(error) }); process.exitCode = 1; });
