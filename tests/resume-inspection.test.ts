import assert from "node:assert/strict";
import { execFile, fork } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
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
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { inspectDeterministicResumeEligibility, deriveStaticDagResumePoint } from "../src/resume-inspection.js";
import { unsafeWithContentIdentity } from "../src/identity/projections.js";
import { TransitionError, reduceState } from "../src/state-machine/index.js";
import { transitionEvent } from "./helpers.js";
import { runBoundedMutationWorkflowForTests, type BoundedMutationAuthority, type BoundedMutationGoal } from "../src/workflow-controller.js";
import type { ReducerPolicy, WorkflowState } from "../src/schemas/index.js";

const execFileAsync = promisify(execFile);

const digest = (letter: string) => `sha256:${letter.repeat(64)}`;

function staticState(tasks: readonly { readonly task_id: string; readonly status: "PENDING" | "PASS" }[]): WorkflowState {
  // The reducer dry-run oracle validates full state identity, so the fixture carries a real
  // computed content digest instead of a placeholder.
  const runtimeTasks = tasks.map((task) => ({ task_id: task.task_id, status: task.status, attempts: 0, postflight_completed: task.status === "PASS", verification_completed: task.status === "PASS", retry_progress_admitted: false }));
  return unsafeWithContentIdentity({
    schema_id: "pi_gacw_state_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: "resume-test",
    execution_mode: "STATIC_APPROVED_DAG", phase: "READY",
    identities: { objective_sha256: digest("b"), contract_sha256: digest("c"), baseline_approval_sha256: digest("d"), authority_lock_sha256: digest("e"), plan_approval_sha256: digest("f"), task_graph_sha256: digest("0"), scope_sha256: digest("1"), acceptance_sha256: digest("2"), budget_sha256: digest("3") },
    frozen_policy_content_sha256: digest("4"), counters: { worker_invocations: { total: 0, sol_owner: 0, sol_planner: 0, sol_replan: 0, sol_closeout: 0, luna_executor: 0, terra_executor: 0 }, direct_attempts: 0, single_owner_mutation_cycles: 0, constrained_replans: 0, leaves_completed: runtimeTasks.filter((task) => task.status === "PASS").length },
    gates: { planner_completed: false, owner_acceptance_completed: false, closeout_completed: false, closeout_verification_completed: false },
    tasks: runtimeTasks,
    active_task_id: null, baseline_approval_required: false, route_frozen: true, owner_acceptance_required: false, replan_in_progress: false, terminal_reason: null,
  } as Omit<WorkflowState, "content_sha256">) as unknown as WorkflowState;
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


type InterruptedStaticRun = { readonly root: string; readonly repository: string; readonly cleanup: () => Promise<void> };

async function interruptedStaticRun(mode: "READY" | "DELTA" | "M5" | "WORKER" | "AMBIGUOUS"): Promise<InterruptedStaticRun> {
  const child = fork(new URL("./resume-inspection-child.ts", import.meta.url), [mode], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  let message: { readonly root: string; readonly repository: string };
  try {
    message = await new Promise((resolve, reject) => {
      const onExit = (code: number | null, signal: NodeJS.Signals | null): void => reject(new Error(`fixture owner exited before pause: code=${code} signal=${signal}`));
      child.once("exit", onExit);
      child.once("message", (value: unknown) => {
        child.off("exit", onExit);
        if (value !== null && typeof value === "object" && (value as { readonly type?: unknown }).type === "PAUSED" &&
          typeof (value as { readonly root?: unknown }).root === "string" && typeof (value as { readonly repository?: unknown }).repository === "string") {
          resolve(value as { readonly root: string; readonly repository: string });
        } else reject(new Error(`fixture child failed: ${JSON.stringify(value)}`));
      });
    });
    await new Promise<void>((resolve, reject) => { child.once("exit", (_code, signal) => signal === "SIGKILL" ? resolve() : reject(new Error(`fixture owner exited unexpectedly: ${signal}`))); child.kill("SIGKILL"); });
    return { ...message, cleanup: async () => { await rm(dirname(message.root), { recursive: true, force: true }); await rm(message.repository, { recursive: true, force: true }); } };
  } catch (error: unknown) {
    child.kill("SIGKILL"); await new Promise<void>((resolve) => child.once("exit", () => resolve())); throw error;
  }
}

async function eventuallyResumable(root: string): Promise<Awaited<ReturnType<typeof inspectDeterministicResumeEligibility>>> {
  let last = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  for (let attempt = 0; last.classification !== "RESUMABLE" && attempt < 100; attempt += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25)); last = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  }
  return last;
}

test("resume point is deterministic at the reducer-settled static DAG ready boundary", () => {
  const policy = staticPolicy();
  assert.equal(deriveStaticDagResumePoint(staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), policy), "STATIC_DAG_SELECT_READY_LEAF:a");
  assert.equal(deriveStaticDagResumePoint(staticState([{ task_id: "a", status: "PASS" }, { task_id: "b", status: "PENDING" }]), policy), "STATIC_DAG_SELECT_READY_LEAF:b");
  const active = { ...staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), active_task_id: "a" } as WorkflowState;
  assert.equal(deriveStaticDagResumePoint(active, policy), null);
  const selected = { ...staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), phase: "LEAF_FAST_PREFLIGHT", active_task_id: "a" } as WorkflowState;
  assert.equal(deriveStaticDagResumePoint(selected, policy), "STATIC_DAG_START_SELECTED_LEAF:a");
  assert.equal(deriveStaticDagResumePoint({ ...selected, tasks: selected.tasks.map((task) => task.task_id === "a" ? { ...task, attempts: 1 } : task) } as WorkflowState, policy), null);
  assert.equal(deriveStaticDagResumePoint({ ...selected, active_task_id: "b" } as WorkflowState, policy), null);
});

type LeafSpec = { readonly task_id: string; readonly rank: number; readonly priority: number; readonly dependencies?: readonly string[]; readonly status: "PENDING" | "PASS" };

/** Frozen-policy/state fixture pair over arbitrary task orderings for selection-semantics cases. */
function leafFixture(specs: readonly LeafSpec[]): { readonly state: WorkflowState; readonly policy: ReducerPolicy } {
  const base = staticPolicy();
  const policy = unsafeWithContentIdentity({
    ...base,
    content_projection_id: "document-content-v1",
    limits: { ...base.limits, max_leaves: Math.max(specs.length, 1), max_worker_invocations: Math.max(specs.length, 1) },
    tasks: specs.map((spec, index) => ({ task_id: spec.task_id, task_sha256: `sha256:${String(index).padStart(64, "0")}`, topological_rank: spec.rank, priority: spec.priority, dependencies: spec.dependencies ?? [], editable_paths: [`${spec.task_id}.txt`] })),
  } as unknown as Omit<ReducerPolicy, "content_sha256">) as unknown as ReducerPolicy;
  const state = unsafeWithContentIdentity({
    ...staticState(specs.map((spec) => ({ task_id: spec.task_id, status: spec.status }))),
    frozen_policy_content_sha256: policy.content_sha256,
  } as unknown as Omit<WorkflowState, "content_sha256">) as unknown as WorkflowState;
  return { state, policy };
}

/** Oracle is the actual reducer SELECT_READY_LEAF commit result, never a reimplemented sort. */
function reducerSelectedResumePoint(state: WorkflowState, policy: ReducerPolicy): string | null {
  let taskId: string | null;
  try {
    taskId = reduceState(state, transitionEvent("SELECT_READY_LEAF"), policy).active_task_id;
  } catch (error: unknown) {
    if (error instanceof TransitionError && error.code === "NO_READY_LEAF") return null;
    throw error;
  }
  return taskId === null ? null : `STATIC_DAG_SELECT_READY_LEAF:${taskId}`;
}

const SELECTION_CASES: Readonly<Record<string, readonly LeafSpec[]>> = Object.freeze({
  // Tied rank+priority with ASCII/case-sensitive ids: codepoint ordering commits "B";
  // a locale collation could pick "a", so this case pins locale-independence.
  tied_rank_priority_case_sensitive: [
    { task_id: "B", rank: 0, priority: 0, status: "PENDING" },
    { task_id: "a", rank: 0, priority: 0, status: "PENDING" },
  ],
  topological_rank_dominates_input_order: [
    { task_id: "X", rank: 1, priority: 0, status: "PENDING" },
    { task_id: "A", rank: 0, priority: 9, status: "PENDING" },
  ],
  priority_breaks_rank_tie: [
    { task_id: "B", rank: 0, priority: 1, status: "PENDING" },
    { task_id: "a", rank: 0, priority: 0, status: "PENDING" },
  ],
  dependency_not_pass_excluded: [
    { task_id: "d", rank: 0, priority: 0, status: "PENDING" },
    { task_id: "c", rank: 1, priority: 0, dependencies: ["d"], status: "PENDING" },
    { task_id: "e", rank: 2, priority: 0, status: "PENDING" },
  ],
  multiple_ready_candidates: [
    { task_id: "z", rank: 3, priority: 5, status: "PENDING" },
    { task_id: "Y", rank: 3, priority: 5, status: "PENDING" },
    { task_id: "k", rank: 3, priority: 7, status: "PENDING" },
  ],
  no_ready_candidate: [
    { task_id: "n", rank: 0, priority: 0, status: "PENDING" },
    { task_id: "m", rank: 1, priority: 0, dependencies: ["n"], status: "PENDING" },
  ],
  historical_multi_leaf_pass: [
    { task_id: "done1", rank: 0, priority: 0, status: "PASS" },
    { task_id: "done2", rank: 1, priority: 0, status: "PASS" },
    { task_id: "Q", rank: 2, priority: 0, status: "PENDING" },
    { task_id: "p", rank: 3, priority: 0, dependencies: ["done1"], status: "PENDING" },
  ],
});

test("static DAG ready-leaf resume selection equals the reducer SELECT_READY_LEAF commit across orderings", () => {
  for (const [name, specs] of Object.entries(SELECTION_CASES)) {
    const { state, policy } = leafFixture(specs);
    assert.equal(deriveStaticDagResumePoint(state, policy), reducerSelectedResumePoint(state, policy), name);
  }
  // Concrete divergence guard: the locale-sensitive pair must resolve to the codepoint winner
  // and must match whatever the reducer actually committed, not a hard-coded guess alone.
  const tied = leafFixture(SELECTION_CASES["tied_rank_priority_case_sensitive"]!);
  assert.equal(reducerSelectedResumePoint(tied.state, tied.policy), "STATIC_DAG_SELECT_READY_LEAF:B");
  assert.equal(deriveStaticDagResumePoint(tied.state, tied.policy), "STATIC_DAG_SELECT_READY_LEAF:B");
  // Pre-worker selected-leaf boundary also derives from the same reducer semantics.
  const preflight = { ...tied.state, phase: "LEAF_FAST_PREFLIGHT", active_task_id: "B" } as WorkflowState;
  assert.equal(deriveStaticDagResumePoint(preflight, tied.policy), "STATIC_DAG_START_SELECTED_LEAF:B");
  assert.equal(deriveStaticDagResumePoint({ ...preflight, active_task_id: "a" } as WorkflowState, tied.policy), null);
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

test("real retained STATIC_APPROVED_DAG READY state refuses while its live controller owns the worktree lock", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "READY" && state.tasks.every((task) => task.status === "PENDING"));
  try {
    const statePath = join(fixture.root, "state", "runs", "pre-m8-bounded", "state.json");
    const [beforePointer, beforeInventory, beforeGit] = await Promise.all([
      readFile(statePath), inventory(join(fixture.root, "state")), resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }).then(captureGitState),
    ]);
    const first = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    const second = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.deepEqual(first, { classification: "RESUME_REFUSED", run_id: "pre-m8-bounded", phase: "READY", resume_point: null, reason: "RESUME_REFUSED_IN_FLIGHT_OPERATION" });
    assert.equal(canonicalize(first), canonicalize(second));
    assert.deepEqual(await readFile(statePath), beforePointer);
    assert.deepEqual(await inventory(join(fixture.root, "state")), beforeInventory);
    assert.equal(canonicalize(await captureGitState(await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }))), canonicalize(beforeGit));
  } finally { await fixture.finish(); }
});

test("interrupted owner leaves a quiescent retained READY state that is resumable and read-only", async () => {
  const fixture = await interruptedStaticRun("READY");
  try {
    const statePath = join(fixture.root, "state", "runs", "pre-m8-bounded", "state.json");
    const [beforePointer, beforeInventory, beforeGit] = await Promise.all([
      readFile(statePath), inventory(join(fixture.root, "state")), resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }).then(captureGitState),
    ]);
    const first = await eventuallyResumable(fixture.root); const second = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.deepEqual(first, { classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "READY", resume_point: "STATIC_DAG_SELECT_READY_LEAF:a", reason: null });
    assert.equal(canonicalize(first), canonicalize(second));
    assert.deepEqual(await readFile(statePath), beforePointer);
    assert.deepEqual(await inventory(join(fixture.root, "state")), beforeInventory);
    assert.equal(canonicalize(await captureGitState(await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }))), canonicalize(beforeGit));
    const control = await mkdtemp(join(tmpdir(), "resume-inspection-probe-"));
    try {
      const helper = join(control, "uncertain.py"); await writeFile(helper, "import time\ntime.sleep(1)\n", { mode: 0o600 }); await chmod(helper, 0o600);
      configureRepositoryTestHooks({ guardianPath: helper, guardianReadyTimeoutMs: 25 });
      assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
      assert.deepEqual(await readFile(statePath), beforePointer);
      assert.deepEqual(await inventory(join(fixture.root, "state")), beforeInventory);
    } finally { resetRepositoryTestHooks(); await rm(control, { recursive: true, force: true }); }
    await writeFile(join(fixture.repository, "unexpected.txt"), "drift\n");
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_STATE_DRIFT");
    assert.equal(await readFile(join(fixture.repository, "unexpected.txt"), "utf8"), "drift\n");
    assert.deepEqual(await readFile(statePath), beforePointer);
    assert.deepEqual(await inventory(join(fixture.root, "state")), beforeInventory);
    await execFileAsync("git", ["checkout", "-qb", "resume-identity-drift"], { cwd: fixture.repository });
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_REPOSITORY_IDENTITY");
  } finally { await fixture.cleanup(); }
});

test("live workflow-owned delta is refused while its controller owns the worktree lock", async () => {
  const fixture = await pauseStaticRun((state) => state.phase === "READY" && state.tasks.find((task) => task.task_id === "a")?.status === "PASS");
  try {
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
  } finally { await fixture.finish(); }
});

test("quiescent workflow-owned delta is resumable", async () => {
  const fixture = await interruptedStaticRun("DELTA");
  try {
    assert.deepEqual(await eventuallyResumable(fixture.root), {
      classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "READY", resume_point: "STATIC_DAG_SELECT_READY_LEAF:b", reason: null,
    });
  } finally { await fixture.cleanup(); }
});

test("quiescent selected static leaf before START_LEAF_ATTEMPT is resumable", async () => {
  const fixture = await interruptedStaticRun("AMBIGUOUS");
  try {
    assert.deepEqual(await eventuallyResumable(fixture.root), {
      classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "LEAF_FAST_PREFLIGHT", resume_point: "STATIC_DAG_START_SELECTED_LEAF:a", reason: null,
    });
  } finally { await fixture.cleanup(); }
});

// V1-R2C: a committed AUTHORIZE_WORK reservation with no worker invocation is now the exact
// STATIC_DAG_INVOKE_RESERVED_LEAF resume point (crash-safe pre-provider work admission); an existing
// BOUNDED_WORKER_INVOCATION still refuses fail-closed.
test("quiescent committed M5 reservation without a result is the reserved-leaf resume point", async () => {
  const fixture = await interruptedStaticRun("M5");
  try {
    assert.deepEqual(await eventuallyResumable(fixture.root), {
      classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "LEAF_RUNNING", resume_point: "STATIC_DAG_INVOKE_RESERVED_LEAF:a", reason: null,
    });
  } finally { await fixture.cleanup(); }
});

test("quiescent bounded-worker invocation without a result refuses resume", async () => {
  const fixture = await interruptedStaticRun("WORKER");
  try { assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION"); }
  finally { await fixture.cleanup(); }
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
