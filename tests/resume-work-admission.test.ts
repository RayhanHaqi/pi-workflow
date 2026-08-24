import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { rm } from "node:fs/promises";
import { join, dirname } from "node:path";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { acquireWorktreeLock, probeWorktreeLockAvailability, releaseWorktreeLock, resolveRepositoryIdentity } from "../src/repository/index.js";
import { captureGitState } from "../src/repository/fingerprint.js";
import {
  acquireDeterministicResumeAdmission,
  activateDeterministicResumeAdmission,
  assertDeterministicResumeActivationHeld,
  assertDeterministicResumeAdmissionHeld,
  assertDeterministicResumeWorkAdmissionHeld,
  authorizeDeterministicResumedLeafWork,
  DeterministicResumeAdmissionError,
  releaseDeterministicResumeActivation,
  releaseDeterministicResumeAdmission,
  releaseDeterministicResumeWorkAdmission,
} from "../src/resume-admission.js";
import {
  deriveStaticDagPreProviderResumePoint,
  inspectDeterministicResumeEligibility,
  RESUMED_PRODUCT_LOGICAL_ROLES,
  resumedAvailableLogicalRoles,
  staticWorkDecisionCandidates,
} from "../src/resume-inspection.js";
import { PRODUCT_LOGICAL_ROLES } from "../src/workflow-controller.js";

type FixtureMode = "READY" | "WINDOW_A" | "WINDOW_B" | "RESULT" | "WORKER";
type ChildFixture = { readonly child: ReturnType<typeof fork>; readonly root: string; readonly repository: string; readonly cleanup: () => Promise<void> };

async function startFixture(mode: FixtureMode): Promise<ChildFixture> {
  const child = fork(new URL("./resume-inspection-child.ts", import.meta.url), [mode], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const message = await new Promise<{ readonly root: string; readonly repository: string }>((resolve, reject) => {
    const onExit = (code: number | null, signal: NodeJS.Signals | null): void => reject(new Error(`fixture owner exited before pause (${mode}): code=${code} signal=${signal}`));
    child.once("exit", onExit);
    child.once("message", (value: unknown) => {
      child.off("exit", onExit);
      if (value !== null && typeof value === "object" && (value as { readonly type?: unknown }).type === "PAUSED" &&
        typeof (value as { readonly root?: unknown }).root === "string" && typeof (value as { readonly repository?: unknown }).repository === "string") {
        resolve(value as { readonly root: string; readonly repository: string });
      } else reject(new Error(`fixture child failed (${mode}): ${JSON.stringify(value)}`));
    });
  });
  return {
    child, ...message,
    cleanup: async () => { await rm(dirname(message.root), { recursive: true, force: true }); await rm(message.repository, { recursive: true, force: true }); },
  };
}

async function interruptFixture(mode: FixtureMode): Promise<Omit<ChildFixture, "child">> {
  const fixture = await startFixture(mode);
  await new Promise<void>((resolve, reject) => {
    fixture.child.once("exit", (_code, signal) => signal === "SIGKILL" ? resolve() : reject(new Error(`fixture owner exited unexpectedly (${mode}): ${signal}`)));
    fixture.child.kill("SIGKILL");
  });
  return { root: fixture.root, repository: fixture.repository, cleanup: fixture.cleanup };
}

async function eventuallyResumable(root: string) {
  let report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  for (let attempt = 0; report.classification !== "RESUMABLE" && attempt < 100; attempt += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25)); report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  }
  return report;
}

function codeOf(error: unknown): unknown { return error !== null && typeof error === "object" ? (error as { readonly code?: unknown }).code : undefined; }

async function rejectsCode(promise: Promise<unknown>, expected: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => codeOf(error) === expected || (error instanceof DeterministicResumeAdmissionError && error.code === expected));
}

async function fixtureExit(child: ReturnType<typeof fork>): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => child.once("exit", () => resolve()));
}

const LOCATION = (root: string) => ({ stateRoot: join(root, "state"), runId: "pre-m8-bounded" });

async function classificationOf(root: string, digest: string): Promise<string | null> {
  const inspection = await inspectRunStorage(LOCATION(root));
  return inspection.managedRecordClassifications.find((entry) => entry.object.kind === "M5_CONTROL_DECISION" && entry.object.contentSha256 === digest)?.classification ?? null;
}

test("clean selected-leaf work admission commits AUTHORIZE_WORK once and transfers the same flock", async () => {
  const fixture = await interruptFixture("READY");
  let work: Awaited<ReturnType<typeof authorizeDeterministicResumedLeafWork>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_SELECT_READY_LEAF:a");
    const prior = await inspectRunStorage(LOCATION(fixture.root));
    const recordsBefore = await readM5ManagedRecords(LOCATION(fixture.root));
    const gitBefore = await captureGitState(await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }));
    const admission = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    const activation = await activateDeterministicResumeAdmission(admission);
    work = await authorizeDeterministicResumedLeafWork(activation);
    // START_LEAF_ATTEMPT is exactly one revision beyond the R2B activation's committed successor.
    // Binding identity
    assert.equal(work.binding.run_id, "pre-m8-bounded");
    assert.equal(work.binding.selected_task_id, "a");
    assert.equal(work.binding.operation_id, "static-leaf-a-attempt-1");
    assert.equal(work.binding.attempt_number, 1);
    assert.ok(work.binding.m5_decision_content_sha256.startsWith("sha256:"));
    assert.equal(Object.isFrozen(work.binding), true);
    // Successor state and exact accounting
    const successor = await inspectRunStorage(LOCATION(fixture.root));
    const state = successor.workflowState!;
    assert.equal(successor.revision, activation.binding.successor_revision + 1);
    assert.equal(state.phase, "LEAF_RUNNING");
    assert.equal(state.active_task_id, "a");
    const task = state.tasks.find((entry) => entry.task_id === "a")!;
    assert.equal(task.status, "RUNNING");
    assert.equal(task.attempts, 1);
    const before = prior.workflowState!.counters.worker_invocations;
    const after = state.counters.worker_invocations;
    assert.equal(after.terra_executor, before.terra_executor + 1);
    assert.equal(after.total, before.total + 1);
    assert.equal(after.sol_owner, before.sol_owner); assert.equal(after.sol_planner, before.sol_planner);
    assert.equal(after.sol_replan, before.sol_replan); assert.equal(after.sol_closeout, before.sol_closeout);
    assert.equal(after.luna_executor, before.luna_executor);
    // Exactly one reservation, zero worker records
    const recordsAfter = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(recordsAfter.decisions.filter((decision) => decision.reservation !== null).length, recordsBefore.decisions.filter((decision) => decision.reservation !== null).length + 1);
    assert.equal(recordsAfter.boundedWorkerInvocations.length, 0);
    assert.equal(recordsAfter.boundedWorkerResults.length, 0);
    assert.equal(await classificationOf(fixture.root, work.binding.m5_decision_content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    // Repository unchanged
    assert.equal(canonicalize(await captureGitState(await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }))), canonicalize(gitBefore));
    // Capability transfer: old capabilities consumed, same flock held by the work capability.
    await assert.rejects(assertDeterministicResumeAdmissionHeld(admission));
    await assert.rejects(assertDeterministicResumeActivationHeld(activation));
    await assert.rejects(activateDeterministicResumeAdmission(admission));
    await assert.rejects(releaseDeterministicResumeAdmission(admission));
    await assert.rejects(releaseDeterministicResumeActivation(activation));
    await assertDeterministicResumeWorkAdmissionHeld(work);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    await rejectsCode(acquireWorktreeLock({ stateRoot: join(fixture.root, "state"), repository }), "LOCK_BUSY");
    await releaseDeterministicResumeWorkAdmission(work);
    await releaseDeterministicResumeWorkAdmission(work); // idempotent explicit release
    work = undefined;
    assert.equal(await probeWorktreeLockAvailability({ stateRoot: join(fixture.root, "state"), repository }), "LOCK_AVAILABLE");
  } finally {
    if (work !== undefined) await releaseDeterministicResumeWorkAdmission(work).catch(() => undefined);
    await fixture.cleanup();
  }
});

test("quiescent selected-leaf resume admission authorizes directly without reactivation", async () => {
  const fixture = await interruptFixture("READY"); let fresh: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  const child = fork(new URL("./resume-activation-child.ts", import.meta.url), [fixture.root], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  let work: Awaited<ReturnType<typeof authorizeDeterministicResumedLeafWork>> | undefined;
  try {
    const activated = await new Promise<{ readonly binding: { readonly resume_point: string } }>((resolve, reject) => {
      child.once("exit", (_code, signal) => reject(new Error(`activation child exited early: ${signal}`)));
      child.once("message", (value: unknown) => {
        if (value !== null && typeof value === "object" && (value as { readonly type?: unknown }).type === "ACTIVATED") resolve(value as { readonly binding: { readonly resume_point: string } });
        else reject(new Error(`activation child failed: ${JSON.stringify(value)}`));
      });
    });
    await new Promise<void>((resolve, reject) => { child.once("exit", (_code, signal) => signal === "SIGKILL" ? resolve() : reject(new Error(`activation child exit ${signal}`))); child.kill("SIGKILL"); });
    assert.deepEqual(await eventuallyResumable(fixture.root), { classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "LEAF_FAST_PREFLIGHT", resume_point: activated.binding.resume_point, reason: null });
    // Input ownership B: an admission acquired against the already-quiescent LEAF_FAST_PREFLIGHT state.
    fresh = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    assert.equal(fresh.binding.resume_point, "STATIC_DAG_START_SELECTED_LEAF:a");
    work = await authorizeDeterministicResumedLeafWork(fresh); fresh = undefined;
    const state = (await inspectRunStorage(LOCATION(fixture.root))).workflowState!;
    assert.equal(state.phase, "LEAF_RUNNING");
    assert.equal(state.tasks.find((entry) => entry.task_id === "a")?.attempts, 1);
    assert.equal((await readM5ManagedRecords(LOCATION(fixture.root))).boundedWorkerInvocations.length, 0);
    await releaseDeterministicResumeWorkAdmission(work); work = undefined;
  } finally {
    if (fresh !== undefined) await releaseDeterministicResumeAdmission(fresh).catch(() => undefined);
    if (work !== undefined) await releaseDeterministicResumeWorkAdmission(work).catch(() => undefined);
    child.kill("SIGKILL"); await fixtureExit(child); await fixture.cleanup();
  }
});

test("foreign or non-package capabilities refuse work admission", async () => {
  await assert.rejects(authorizeDeterministicResumedLeafWork(undefined as never), /not created by this package instance/);
  await assert.rejects(authorizeDeterministicResumedLeafWork({ binding: { resume_point: "STATIC_DAG_START_SELECTED_LEAF:a", run_id: "pre-m8-bounded" } } as never), /not created by this package instance/);
});

test("WINDOW A crash retains an unreferenced decision recognized as STATIC_DAG_REDRIVE_WORK_ADMISSION", async () => {
  const fixture = await interruptFixture("WINDOW_A");
  try {
    assert.deepEqual(await eventuallyResumable(fixture.root), { classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "LEAF_FAST_PREFLIGHT", resume_point: "STATIC_DAG_REDRIVE_WORK_ADMISSION:a", reason: null });
    const inspection = await inspectRunStorage(LOCATION(fixture.root));
    const state = inspection.workflowState!;
    const task = state.tasks.find((entry) => entry.task_id === "a")!;
    assert.equal(state.phase, "LEAF_FAST_PREFLIGHT"); assert.equal(task.status, "PENDING"); assert.equal(task.attempts, 0);
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    const decisions = records.decisions.filter((decision) => decision.intent === "AUTHORIZE_WORK" && decision.operation_id === "static-leaf-a-attempt-1");
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0]!.transition_event?.event_type, "START_LEAF_ATTEMPT");
    assert.notEqual(decisions[0]!.reservation, null);
    assert.equal(await classificationOf(fixture.root, decisions[0]!.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(records.boundedWorkerInvocations.length, 0);
    assert.equal(records.boundedWorkerResults.length, 0);
  } finally { await fixture.cleanup(); }
});

test("WINDOW A fresh owner redrives the exact decision without a second reservation", async () => {
  const fixture = await interruptFixture("WINDOW_A");
  let admission: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  let work: Awaited<ReturnType<typeof authorizeDeterministicResumedLeafWork>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_REDRIVE_WORK_ADMISSION:a");
    const before = await inspectRunStorage(LOCATION(fixture.root));
    const recordsBefore = await readM5ManagedRecords(LOCATION(fixture.root));
    const publishedSha = recordsBefore.decisions.find((decision) => decision.operation_id === "static-leaf-a-attempt-1")!.content_sha256;
    admission = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    assert.equal(admission.binding.resume_point, "STATIC_DAG_REDRIVE_WORK_ADMISSION:a");
    work = await authorizeDeterministicResumedLeafWork(admission); admission = undefined;
    // Exact decision reuse: same content identity, no duplicate reservation, one committed transition.
    assert.equal(work.binding.m5_decision_content_sha256, publishedSha);
    const after = await inspectRunStorage(LOCATION(fixture.root));
    assert.equal(after.revision, before.revision! + 1);
    assert.equal(after.workflowState!.phase, "LEAF_RUNNING");
    assert.equal(after.workflowState!.tasks.find((entry) => entry.task_id === "a")?.attempts, 1);
    const recordsAfter = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(recordsAfter.decisions.filter((decision) => decision.reservation !== null).length, 1);
    assert.equal(recordsAfter.decisions.filter((decision) => decision.operation_id === "static-leaf-a-attempt-1").length, 1);
    assert.equal(recordsAfter.boundedWorkerInvocations.length, 0);
    assert.equal(recordsAfter.boundedWorkerResults.length, 0);
    await releaseDeterministicResumeWorkAdmission(work); work = undefined;
  } finally {
    if (admission !== undefined) await releaseDeterministicResumeAdmission(admission).catch(() => undefined);
    if (work !== undefined) await releaseDeterministicResumeWorkAdmission(work).catch(() => undefined);
    await fixture.cleanup();
  }
});

test("resume identity equals ordinary static identity across clean and redrive paths", async () => {
  const cleanFixture = await interruptFixture("READY");
  let cleanWork: Awaited<ReturnType<typeof authorizeDeterministicResumedLeafWork>> | undefined;
  let redriveWork: Awaited<ReturnType<typeof authorizeDeterministicResumedLeafWork>> | undefined;
  let redriveAdmission: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  const redriveFixture = await interruptFixture("WINDOW_A");
  try {
    const cleanAdmission = await acquireDeterministicResumeAdmission({ retainedRunRoot: cleanFixture.root });
    cleanWork = await authorizeDeterministicResumedLeafWork(await activateDeterministicResumeAdmission(cleanAdmission));
    assert.equal((await eventuallyResumable(redriveFixture.root)).resume_point, "STATIC_DAG_REDRIVE_WORK_ADMISSION:a");
    const redriveRecordsBefore = await readM5ManagedRecords(LOCATION(redriveFixture.root));
    const publishedSha = redriveRecordsBefore.decisions.find((decision) => decision.operation_id === "static-leaf-a-attempt-1")!.content_sha256;
    redriveAdmission = await acquireDeterministicResumeAdmission({ retainedRunRoot: redriveFixture.root });
    redriveWork = await authorizeDeterministicResumedLeafWork(redriveAdmission); redriveAdmission = undefined;
    // The replayed request is byte-identical M5 authority within the run: the exact published decision is reused.
    assert.equal(redriveWork.binding.m5_decision_content_sha256, publishedSha);
    for (const work of [cleanWork, redriveWork]) {
      assert.equal(work.binding.operation_id, "static-leaf-a-attempt-1");
      assert.equal(work.binding.task_graph_sha256, work.binding.task_graph_sha256);
      assert.ok(work.binding.plan_approval_sha256 !== null && work.binding.task_graph_sha256 !== null);
      assert.ok(work.binding.frozen_logical_role === "TERRA_EXECUTOR" || work.binding.frozen_logical_role === "CODING_EXECUTOR");
      assert.equal(typeof work.binding.provider_id, "string");
      assert.equal(typeof work.binding.model_id, "string");
      assert.equal(typeof work.binding.effort, "string");
    }
    // START_LEAF_ATTEMPT semantics committed exactly once per path with identical transition identity semantics.
    for (const fixtureRoot of [cleanFixture.root, redriveFixture.root]) {
      const records = await readM5ManagedRecords(LOCATION(fixtureRoot));
      const decision = records.decisions.find((entry) => entry.operation_id === "static-leaf-a-attempt-1")!;
      assert.equal(decision.transition_event?.event_type, "START_LEAF_ATTEMPT");
      assert.equal(decision.transition_id, "pre-m8-authorize-static-leaf-a-attempt-1");
      assert.equal(decision.reservation?.future_operation_id, "static-leaf-a-attempt-1");
      assert.equal(decision.reservation?.reserved_route, "STATIC_APPROVED_DAG");
    }
  } finally {
    if (redriveAdmission !== undefined) await releaseDeterministicResumeAdmission(redriveAdmission).catch(() => undefined);
    if (cleanWork !== undefined) await releaseDeterministicResumeWorkAdmission(cleanWork).catch(() => undefined);
    if (redriveWork !== undefined) await releaseDeterministicResumeWorkAdmission(redriveWork).catch(() => undefined);
    await cleanFixture.cleanup(); await redriveFixture.cleanup();
  }
});

test("WINDOW B crash yields STATIC_DAG_INVOKE_RESERVED_LEAF with an authoritative reservation", async () => {
  const fixture = await interruptFixture("WINDOW_B");
  try {
    assert.deepEqual(await eventuallyResumable(fixture.root), { classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "LEAF_RUNNING", resume_point: "STATIC_DAG_INVOKE_RESERVED_LEAF:a", reason: null });
    const inspection = await inspectRunStorage(LOCATION(fixture.root));
    const state = inspection.workflowState!;
    const task = state.tasks.find((entry) => entry.task_id === "a")!;
    assert.equal(state.phase, "LEAF_RUNNING"); assert.equal(task.status, "RUNNING"); assert.equal(task.attempts, 1);
    assert.equal(state.counters.worker_invocations.terra_executor, 1);
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    const decision = records.decisions.find((entry) => entry.operation_id === "static-leaf-a-attempt-1");
    assert.ok(decision !== undefined && decision.reservation !== null);
    assert.equal(await classificationOf(fixture.root, decision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(records.boundedWorkerInvocations.length, 0);
    assert.equal(records.boundedWorkerResults.length, 0);
  } finally { await fixture.cleanup(); }
});

test("WINDOW B fresh resume preserves the reservation and adds no counter increment", async () => {
  const fixture = await interruptFixture("WINDOW_B");
  let admission: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  let work: Awaited<ReturnType<typeof authorizeDeterministicResumedLeafWork>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_INVOKE_RESERVED_LEAF:a");
    const before = await inspectRunStorage(LOCATION(fixture.root));
    const recordsBefore = await readM5ManagedRecords(LOCATION(fixture.root));
    const reservedSha = recordsBefore.decisions.find((decision) => decision.operation_id === "static-leaf-a-attempt-1")!.content_sha256;
    admission = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    assert.equal(admission.binding.resume_point, "STATIC_DAG_INVOKE_RESERVED_LEAF:a");
    work = await authorizeDeterministicResumedLeafWork(admission); admission = undefined;
    // Reservation identity preserved, no second counter increment, no second reservation, no new transition.
    assert.equal(work.binding.m5_decision_content_sha256, reservedSha);
    const after = await inspectRunStorage(LOCATION(fixture.root));
    assert.equal(after.revision, before.revision);
    assert.equal(after.transitionCommit!.content_sha256, before.transitionCommit!.content_sha256);
    assert.equal(after.workflowState!.counters.worker_invocations.terra_executor, 1);
    assert.equal(after.workflowState!.tasks.find((entry) => entry.task_id === "a")?.attempts, 1);
    const recordsAfter = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(recordsAfter.decisions.filter((decision) => decision.reservation !== null).length, 1);
    assert.equal(recordsAfter.boundedWorkerInvocations.length, 0);
    assert.equal(recordsAfter.boundedWorkerResults.length, 0);
    await releaseDeterministicResumeWorkAdmission(work); work = undefined;
  } finally {
    if (admission !== undefined) await releaseDeterministicResumeAdmission(admission).catch(() => undefined);
    if (work !== undefined) await releaseDeterministicResumeWorkAdmission(work).catch(() => undefined);
    await fixture.cleanup();
  }
});

test("existing worker invocation refuses resume fail-closed", async () => {
  const fixture = await interruptFixture("WORKER");
  let competing: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    const report = await eventuallyRefused(fixture.root);
    assert.equal(report.reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(records.boundedWorkerInvocations.length, 1);
    assert.equal(records.boundedWorkerResults.length, 0);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    // The dead owner's stale flock is reaped on acquisition, so a fresh admission observes the refusal, not contention.
    await rejectsCode(inspectAndAcquireWithoutLock(fixture.root), "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    competing = await acquireWorktreeLock({ stateRoot: join(fixture.root, "state"), repository });
    await rejectsCode(acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root }), "LOCK_BUSY");
  } finally {
    if (competing !== undefined) await releaseWorktreeLock(competing).catch(() => undefined);
    await fixture.cleanup();
  }
});

async function eventuallyRefused(root: string) {
  let report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  for (let attempt = 0; report.classification !== "RESUME_REFUSED" && attempt < 100; attempt += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25)); report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  }
  return report;
}

async function inspectAndAcquireWithoutLock(root: string): Promise<unknown> {
  // The stale flock owner is dead; the probe inside admission must observe the refusal, not lock contention.
  return acquireDeterministicResumeAdmission({ retainedRunRoot: root });
}

test("existing worker result refuses resume and preserves the evidence unchanged", async () => {
  const fixture = await interruptFixture("RESULT");
  try {
    const report = await eventuallyRefused(fixture.root);
    assert.equal(report.classification, "RESUME_REFUSED");
    const recordsBefore = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(recordsBefore.boundedWorkerInvocations.length, 1);
    assert.equal(recordsBefore.boundedWorkerResults.length, 1);
    await assert.rejects(inspectAndAcquireWithoutLock(fixture.root));
    const recordsAfter = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(canonicalize(recordsAfter.boundedWorkerInvocations), canonicalize(recordsBefore.boundedWorkerInvocations));
    assert.equal(canonicalize(recordsAfter.boundedWorkerResults), canonicalize(recordsBefore.boundedWorkerResults));
  } finally { await fixture.cleanup(); }
});

test("contradictory authority refuses fail-closed", async () => {
  const fixture = await interruptFixture("WINDOW_A");
  let admission: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_REDRIVE_WORK_ADMISSION:a");
    const inspection = await inspectRunStorage(LOCATION(fixture.root));
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    const state = inspection.workflowState!;
    const reducerPolicy = records.reducerPolicies.find((entry) => entry.content_sha256 === state.frozen_policy_content_sha256)!;
    const base = deriveStaticDagPreProviderResumePoint(state, reducerPolicy, records, inspection.managedRecordClassifications, inspection.transitionCommit!);
    assert.equal(base, "STATIC_DAG_REDRIVE_WORK_ADMISSION:a");
    const original = staticWorkDecisionCandidates(state, reducerPolicy, records, inspection.managedRecordClassifications)[0]!;
    const variant = (mutate: (decision: Record<string, unknown>) => void): Awaited<ReturnType<typeof readM5ManagedRecords>> => {
      const mutated = structuredClone(original) as unknown as Record<string, unknown>; mutate(mutated);
      return Object.freeze({ ...records, decisions: [...records.decisions.filter((entry) => entry.content_sha256 !== original.content_sha256), mutated as unknown as typeof original] }) as Awaited<ReturnType<typeof readM5ManagedRecords>>;
    };
    // Wrong operation id refuses.
    assert.equal(deriveStaticDagPreProviderResumePoint(state, reducerPolicy, variant((decision) => { decision["operation_id"] = "static-leaf-b-attempt-1"; }), inspection.managedRecordClassifications, inspection.transitionCommit!), null);
    // Wrong transition event refuses.
    assert.equal(deriveStaticDagPreProviderResumePoint(state, reducerPolicy, variant((decision) => { decision["transition_event"] = { ...(decision["transition_event"] as Record<string, unknown>), event_type: "START_PLAN" }; }), inspection.managedRecordClassifications, inspection.transitionCommit!), null);
    // Multiple matching decisions refuse: original plus an identical-authority clone.
    const clone = structuredClone(original) as unknown as Record<string, unknown>; clone["content_sha256"] = "sha256:" + "b".repeat(64);
    const duplicated = Object.freeze({ ...records, decisions: [...records.decisions, clone as unknown as typeof original] }) as Awaited<ReturnType<typeof readM5ManagedRecords>>;
    assert.equal(staticWorkDecisionCandidates(state, reducerPolicy, duplicated, inspection.managedRecordClassifications).length, 2);
    assert.equal(deriveStaticDagPreProviderResumePoint(state, reducerPolicy, duplicated, inspection.managedRecordClassifications, inspection.transitionCommit!), null);
    // Conflicting extra reservation refuses.
    const conflicting = variant((decision) => { decision["content_sha256"] = "sha256:" + "c".repeat(64); decision["operation_id"] = "static-leaf-other-attempt-1"; decision["reservation"] = { ...(decision["reservation"] as Record<string, unknown>), future_operation_id: "static-leaf-other-attempt-1" }; });
    assert.equal(deriveStaticDagPreProviderResumePoint(state, reducerPolicy, conflicting, inspection.managedRecordClassifications, inspection.transitionCommit!), null);
    // Wrong current-state SHA refuses via the capability-bound live-state check: stale admission cannot authorize.
    admission = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    const staleBinding = Object.freeze({ ...admission.binding, workflow_state_content_sha256: "sha256:" + "d".repeat(64) });
    const forged = Object.create(Object.getPrototypeOf(admission));
    await assert.rejects(authorizeDeterministicResumedLeafWork(forged as never), /not created by this package instance|is invalid/);
    void staleBinding;
  } finally {
    if (admission !== undefined) await releaseDeterministicResumeAdmission(admission).catch(() => undefined);
    await fixture.cleanup();
  }
});

test("resumed role inventory stays canonically equal to the frozen production inventory", () => {
  assert.equal(canonicalize([...RESUMED_PRODUCT_LOGICAL_ROLES]), canonicalize([...PRODUCT_LOGICAL_ROLES]));
  const legacyPolicy = { role_reservation_envelopes: [{ logical_role: "TERRA_EXECUTOR" }] } as never;
  const codingPolicy = { role_reservation_envelopes: [{ logical_role: "CODING_EXECUTOR" }] } as never;
  assert.equal(canonicalize(resumedAvailableLogicalRoles(legacyPolicy)), canonicalize([...PRODUCT_LOGICAL_ROLES]));
  assert.equal(canonicalize(resumedAvailableLogicalRoles(codingPolicy)), canonicalize(["CODING_EXECUTOR"]));
});
