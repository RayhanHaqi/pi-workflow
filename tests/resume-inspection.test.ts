import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { main as workflowCliMain } from "../src/cli/pi-workflow.js";
import { captureGitState } from "../src/repository/fingerprint.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { configureM5PersistenceTestHooks } from "../src/persistence/m5-test-hooks.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";
import { inspectDeterministicResumeEligibility, deriveStaticDagResumePoint } from "../src/resume-inspection.js";
import { runBoundedMutationWorkflowForTests, type BoundedMutationAuthority, type BoundedMutationGoal } from "../src/workflow-controller.js";
import type { ReducerPolicy, WorkflowState } from "../src/schemas/index.js";

const execFileAsync = promisify(execFile);

const digest = (letter: string) => `sha256:${letter.repeat(64)}`;

function staticState(tasks: readonly { readonly task_id: string; readonly status: "PENDING" | "PASS" }[]): WorkflowState {
  return {
    schema_id: "pi_gacw_state_v0", schema_version: "0.1.0", content_sha256: digest("a"), run_id: "resume-test",
    execution_mode: "STATIC_APPROVED_DAG", phase: "READY",
    identities: { objective_sha256: digest("b"), contract_sha256: digest("c"), baseline_approval_sha256: digest("d"), authority_lock_sha256: digest("e"), plan_approval_sha256: digest("f"), task_graph_sha256: digest("0"), scope_sha256: digest("1"), acceptance_sha256: digest("2"), budget_sha256: digest("3") },
    frozen_policy_content_sha256: digest("4"), counters: { worker_invocations: { total: 0, sol_owner: 0, sol_planner: 0, sol_replan: 0, sol_closeout: 0, luna_executor: 0, terra_executor: 0 }, direct_attempts: 0, single_owner_mutation_cycles: 0, constrained_replans: 0, leaves_completed: 0 },
    gates: { planner_completed: false, owner_acceptance_completed: false, closeout_completed: false, closeout_verification_completed: false },
    tasks: tasks.map((task) => ({ task_id: task.task_id, status: task.status, attempts: 0, postflight_completed: task.status === "PASS", verification_completed: task.status === "PASS", retry_progress_admitted: false })),
    active_task_id: null, baseline_approval_required: false, route_frozen: true, owner_acceptance_required: false, replan_in_progress: false, terminal_reason: null,
  } as WorkflowState;
}

function staticPolicy(): ReducerPolicy {
  return {
    schema_id: "pi_gacw_reducer_policy_v0", schema_version: "0.1.0", content_sha256: digest("4"), run_id: "resume-test", execution_mode: "STATIC_APPROVED_DAG", owner_acceptance_required: false,
    limits: { max_direct_attempts: 1, max_single_owner_mutation_cycles: 1, max_attempts_per_leaf: 1, max_replans: 0, max_leaves: 2, max_worker_invocations: 2 },
    tasks: [
      { task_id: "a", task_sha256: digest("5"), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["a.txt"] },
      { task_id: "b", task_sha256: digest("6"), topological_rank: 1, priority: 0, dependencies: ["a"], editable_paths: ["b.txt"] },
    ],
    frozen_bindings: { plan_approval_sha256: digest("f"), task_graph_sha256: digest("0"), scope_sha256: digest("1"), acceptance_sha256: digest("2"), budget_sha256: digest("3") },
  } as ReducerPolicy;
}

async function captureStdout<T>(action: () => Promise<T>): Promise<{ readonly result: T; readonly output: string }> {
  const stdout = process.stdout as unknown as { write(chunk: string | Uint8Array): boolean };
  const write = stdout.write; let output = "";
  stdout.write = (chunk) => { if (typeof chunk === "string") output += chunk; return true; };
  try { return { result: await action(), output }; } finally { stdout.write = write; }
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "resume-inspection-repo-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "resume@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "resume"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "check.mjs"), "process.exit(0);\n");
  await execFileAsync("git", ["add", "verify"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

async function inventory(root: string): Promise<readonly string[]> {
  const visit = async (directory: string, prefix = ""): Promise<string[]> => {
    const names = await readdir(directory, { withFileTypes: true }); const output: string[] = [];
    for (const entry of names.sort((left, right) => left.name.localeCompare(right.name))) {
      const path = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
      output.push(path); if (entry.isDirectory() && !entry.isSymbolicLink()) output.push(...await visit(join(directory, entry.name), path));
    }
    return output;
  };
  return visit(root);
}

type PausedStaticRun = { readonly root: string; readonly repository: string; readonly release: () => void; readonly workerEntered: Promise<void>; readonly releaseWorker: () => void; readonly finish: () => Promise<void> };

async function pauseStaticRun(when: (state: WorkflowState) => boolean, blockFirstWorker = false): Promise<PausedStaticRun> {
  const root = await repository(); const parent = await mkdtemp(join(tmpdir(), "resume-inspection-retained-"));
  let paused = false; let releasePause!: () => void; const pause = new Promise<void>((resolvePause) => { releasePause = resolvePause; });
  let releaseWorker!: () => void; const workerGate = new Promise<void>((resolveWorker) => { releaseWorker = resolveWorker; });
  let workerEnteredResolve!: () => void; const workerEntered = new Promise<void>((resolveWorkerEntered) => { workerEnteredResolve = resolveWorkerEntered; });
  let resolveReached!: (value: { readonly root: string }) => void; let rejectReached!: (reason: unknown) => void;
  const reached = new Promise<{ readonly root: string }>((resolveReachedValue, rejectReachedValue) => { resolveReached = resolveReachedValue; rejectReached = rejectReachedValue; });
  configureBoundedWorkerFauxRuntimeForTests(() => {
    let calls = 0;
    return { async execute({ tools }) {
      const path = ["a.txt", "b.txt"][calls++]!;
      if (blockFirstWorker && calls === 1) { workerEnteredResolve(); await workerGate; }
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport(`wrote ${path}`); return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    } };
  });
  configureM5PersistenceTestHooks({ checkpoint: async (checkpoint) => {
    if (paused || checkpoint !== "AFTER_STATE_POINTER_UPDATE") return;
    const entries = await readdir(parent); if (entries.length !== 1) return;
    const stateRoot = join(parent, entries[0]!, "state"); const inspection = await inspectRunStorage({ stateRoot, runId: "pre-m8-bounded" });
    if (inspection.workflowState === null || !when(inspection.workflowState)) return;
    paused = true; resolveReached({ root: dirname(stateRoot) }); await pause;
  } });
  const goal: BoundedMutationGoal = {
    objective: "Write exactly two resume-fixture outputs.", stop_condition: "Stop after deterministic verification.", execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] }, required_outputs: ["a.txt", "b.txt"],
    tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [], verification_command_ids: [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["a"], verification_command_ids: [] },
    ],
  };
  const authority: BoundedMutationAuthority = { verification_commands: [{ command_id: "verify", executable: process.execPath, args: ["check.mjs"], cwd: "verify", timeout_ms: 10_000, readable_paths: [{ path: "verify", kind: "PREFIX" }] }], static_max_attempts_per_leaf: 1, static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 } };
  const workflow = runBoundedMutationWorkflowForTests(goal, { cwd: root, authority, retainedArtifactRoot: parent, approveTasks: async ({ plan }) => plan!.content_sha256 as `sha256:${string}` });
  void workflow.then((result) => { if (!paused) rejectReached(new Error(`fixture did not reach requested boundary: ${result.reason}`)); }, rejectReached);
  try {
    const pausedRun = await reached;
    return { root: pausedRun.root, repository: root, release: releasePause, workerEntered, releaseWorker, finish: async () => {
      releasePause(); releaseWorker(); await workflow; configureM5PersistenceTestHooks(undefined); configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
    } };
  } catch (error: unknown) {
    releasePause(); releaseWorker(); configureM5PersistenceTestHooks(undefined); configureBoundedWorkerFauxRuntimeForTests(undefined); await workflow.catch(() => undefined); await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true }); throw error;
  }
}

test("resume point is deterministic at the reducer-settled static DAG ready boundary", () => {
  const policy = staticPolicy();
  assert.equal(deriveStaticDagResumePoint(staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), policy), "STATIC_DAG_SELECT_READY_LEAF:a");
  assert.equal(deriveStaticDagResumePoint(staticState([{ task_id: "a", status: "PASS" }, { task_id: "b", status: "PENDING" }]), policy), "STATIC_DAG_SELECT_READY_LEAF:b");
  const active = { ...staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), active_task_id: "a" } as WorkflowState;
  assert.equal(deriveStaticDagResumePoint(active, policy), null);
});

test("resume inspection fails closed without a retained state root and does not create one", async () => {
  const root = await mkdtemp(join(tmpdir(), "resume-inspect-"));
  const missing = join(root, "missing");
  try {
    const first = await inspectDeterministicResumeEligibility({ retainedRunRoot: missing });
    const second = await inspectDeterministicResumeEligibility({ retainedRunRoot: missing });
    assert.deepEqual(first, { classification: "RESUME_REFUSED", run_id: null, phase: null, resume_point: null, reason: "RESUME_REFUSED_STATE_STORE" });
    assert.deepEqual(second, first);
    assert.deepEqual(await readdir(root), []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("resume-inspect CLI emits one deterministic machine-readable JSON report", async () => {
  const root = await mkdtemp(join(tmpdir(), "resume-inspect-cli-"));
  try {
    const first = await captureStdout(() => workflowCliMain(["resume-inspect", join(root, "missing")]));
    const second = await captureStdout(() => workflowCliMain(["resume-inspect", join(root, "missing")]));
    assert.equal(first.result, 3);
    assert.equal(second.result, 3);
    assert.equal(first.output, second.output);
    assert.deepEqual(JSON.parse(first.output), { classification: "RESUME_REFUSED", run_id: null, phase: null, resume_point: null, reason: "RESUME_REFUSED_STATE_STORE" });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("real retained STATIC_APPROVED_DAG READY state is resumable and inspection is read-only", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "READY" && state.tasks.every((task) => task.status === "PENDING"));
  try {
    const statePath = join(fixture.root, "state", "runs", "pre-m8-bounded", "state.json");
    const [beforePointer, beforeInventory, beforeGit] = await Promise.all([
      readFile(statePath), inventory(join(fixture.root, "state")), resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }).then(captureGitState),
    ]);
    const first = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    const second = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.deepEqual(first, { classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "READY", resume_point: "STATIC_DAG_SELECT_READY_LEAF:a", reason: null });
    assert.equal(canonicalize(first), canonicalize(second));
    assert.deepEqual(await readFile(statePath), beforePointer);
    assert.deepEqual(await inventory(join(fixture.root, "state")), beforeInventory);
    const afterCleanInspectionGit = await captureGitState(await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }));
    assert.equal(canonicalize(afterCleanInspectionGit), canonicalize(beforeGit));
    await writeFile(join(fixture.repository, "unexpected.txt"), "drift\n");
    const drift = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.equal(drift.reason, "RESUME_REFUSED_STATE_DRIFT");
    assert.equal((await readFile(join(fixture.repository, "unexpected.txt"), "utf8")), "drift\n");
    assert.deepEqual(await readFile(statePath), beforePointer);
    assert.deepEqual(await inventory(join(fixture.root, "state")), beforeInventory);
    await execFileAsync("git", ["checkout", "-qb", "resume-identity-drift"], { cwd: fixture.repository });
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_REPOSITORY_IDENTITY");
  } finally { await fixture.finish(); }
});

test("real retained STATIC_APPROVED_DAG accepts an authoritative workflow-owned delta", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "READY" && state.tasks.find((task) => task.task_id === "a")?.status === "PASS");
  try {
    assert.deepEqual(await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root }), {
      classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "READY", resume_point: "STATIC_DAG_SELECT_READY_LEAF:b", reason: null,
    });
  } finally { await fixture.finish(); }
});


test("real retained nonterminal static state outside READY is refused as ambiguous", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "LEAF_FAST_PREFLIGHT");
  try {
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_AMBIGUOUS_RESUME_POINT");
  } finally { await fixture.finish(); }
});


test("real M5 reservation and bounded-worker invocation without a result both refuse resume", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "LEAF_RUNNING", true);
  try {
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    fixture.release(); await fixture.workerEntered;
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    fixture.releaseWorker();
  } finally { await fixture.finish(); }
});


test("missing required baseline authority reaches the baseline refusal gate", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "READY" && state.tasks.every((task) => task.status === "PENDING"));
  try {
    const records = await readM5ManagedRecords({ stateRoot: join(fixture.root, "state"), runId: "pre-m8-bounded" });
    const baseline = records.baselines[0]!;
    await unlink(join(fixture.root, "state", "runs", "pre-m8-bounded", "records", "baselines", `${baseline.content_sha256.slice("sha256:".length)}.json`));
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_BASELINE_AUTHORITY");
  } finally { await fixture.finish(); }
});
