import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import type { Sha256Digest } from "../src/identity/index.js";
import { commitTransition, initializeRunStorage, inspectRunStorage } from "../src/persistence/index.js";
import {
  establishNodeStaticTimeAuthority,
  establishWorkflowStaticTimeAuthority,
  publishStaticTimeAuthority,
  readM5ManagedRecords,
  readStaticTimeAuthorities,
} from "../src/persistence/store.js";
import {
  resolveApplicableResumeTiming,
  staticDeadlineExpired,
  staticNodeDeadlineExpired,
  staticTimingVerdicts,
  staticWorkflowDeadlineExpired,
} from "../src/persistence/static-time-authority.js";
import type { ManagedRecordClassification } from "../src/persistence/types.js";
import type { RunStorageInspection } from "../src/persistence/types.js";
import type { StaticTimeAuthorityDocument, WorkflowTimeAuthorityDocument } from "../src/schemas/index.js";
import { identifyContractDocument } from "../src/schemas/index.js";
import { configureBoundedWorkerFauxRuntimeForTests, type BoundedWorkerRuntime } from "../src/pi-adapter/bounded-worker.js";
import { createInitialState } from "../src/state-machine/index.js";
import {
  runBoundedMutationWorkflowForTests,
  type BoundedMutationAuthority,
  type BoundedMutationGoal,
  type StaticApprovedDagTimeBudgets,
} from "../src/workflow-controller.js";
import { digest, makePolicy, planApprovalDocument, stateIdentities, transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import { installTestWallClock, sampleWallClockMs, WallClockError } from "../src/wall-clock.js";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Hand-built durable STATIC_APPROVED_DAG ancestry (provider-free, no M3/M5)
// ---------------------------------------------------------------------------

interface TimingLocation {
  readonly stateRoot: string;
  readonly runId: string;
}

interface TimingRun extends TimingLocation {
  readonly policy: ReturnType<typeof makePolicy>;
  /** Exact durable PlanApproval content identity this run's policy freezes. */
  readonly planContentSha256: Sha256Digest;
  /** Canonical source-evidence bytes (budget + plan) attached to a committed transition. */
  readonly evidenceBytes: readonly { readonly bytes: Uint8Array; readonly mediaType: string }[];
}

const STATIC_BUDGETS = { worker_deadline_ms: 1_000, node_wall_ms: 2_000, workflow_wall_ms: 4_000 } as const;
type PolicyLike = ReturnType<typeof makePolicy>;

function budgetDocumentFor(limits: Record<string, unknown>) {
  return identifyContractDocument("pi_gacw_budget_v0", {
    schema_id: "pi_gacw_budget_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    budget_projection_id: "budget-freeze-v1",
    budget_sha256: digest(44),
    limits: limits as never,
    usage: {
      worker_invocation: { value: null, enforcement_class: "UNAVAILABLE" },
      model_turn: { value: null, enforcement_class: "UNAVAILABLE" },
      provider_request: { value: null, enforcement_class: "UNAVAILABLE" },
      tool_call: { value: null, enforcement_class: "UNAVAILABLE" },
    },
  });
}

/**
 * Builds a real STATIC_APPROVED_DAG ancestry whose frozen plan binding names an
 * actual durable PlanApproval record (attached as transition evidence below).
 */
async function createStaticTimingRun(): Promise<TimingRun> {
  const stateRoot = await mkdtemp(join(tmpdir(), "static-time-authority-"));
  // Projection digests are recomputed by identifyContractDocument, so the frozen
  // bindings must name the COMPUTED budget/plan identities, not fixed fixtures.
  const plan = planApprovalDocument("STATIC_APPROVED_DAG") as unknown as Record<string, unknown>;
  const planContentSha256 = plan["content_sha256"] as Sha256Digest;
  const budget = budgetDocumentFor({
    max_leaves: 8, max_attempts_per_leaf: 2, max_replans: 0, max_worker_invocations: 20,
    max_model_turns: 1_000, max_tool_calls: 1_000, max_input_tokens: 100_000, max_output_tokens: 100_000,
    max_cost_microusd: 1_000, max_wall_time_ms: STATIC_BUDGETS.workflow_wall_ms,
    static_time_budgets: { ...STATIC_BUDGETS },
  });
  const base = makePolicy("STATIC_APPROVED_DAG") as unknown as Record<string, unknown>;
  const policy = identifyContractDocument("pi_gacw_reducer_policy_v0", {
    ...base,
    frozen_bindings: {
      ...(base["frozen_bindings"] as Record<string, unknown>),
      plan_approval_sha256: plan["plan_approval_sha256"],
      budget_sha256: (budget as unknown as { budget_sha256: Sha256Digest }).budget_sha256,
    },
  }) as unknown as ReturnType<typeof makePolicy>;
  const runId = policy.run_id;
  const initialState = createInitialState(policy as never, stateIdentities(policy as never));
  await initializeRunStorage({ stateRoot, runId, policy: policy as never, initialState, processMetadata });
  return {
    stateRoot, runId, policy, planContentSha256,
    evidenceBytes: [
      { bytes: Buffer.from(`${canonicalize(budget)}\n`, "utf8"), mediaType: "application/vnd.pi-gacw.budget+json" },
      { bytes: Buffer.from(`${canonicalize(plan)}\n`, "utf8"), mediaType: "application/vnd.pi-gacw.plan-approval+json" },
    ],
  };
}

function loc(run: TimingLocation): TimingLocation {
  return { stateRoot: run.stateRoot, runId: run.runId };
}

async function inspectionOf(run: TimingLocation): Promise<RunStorageInspection> {
  return inspectRunStorage(loc(run));
}

async function commitEvent(
  run: TimingRun,
  eventType: Parameters<typeof transitionEvent>[0],
  payload: Record<string, unknown> = {},
  label = eventType as string,
  evidence?: readonly { readonly bytes: Uint8Array; readonly mediaType: string }[],
): Promise<RunStorageInspection> {
  const current = await inspectionOf(run);
  await commitTransition({
    ...loc(run),
    expectedRevision: current.revision!,
    expectedStatePointerContentSha256: current.statePointer!.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: current.workflowState!.content_sha256 as Sha256Digest,
    transitionId: `timing-${label.toLowerCase()}`,
    policy: run.policy as never,
    event: transitionEvent(eventType, payload),
    ...(evidence === undefined ? {} : { evidence }),
    processMetadata,
  });
  return inspectionOf(run);
}

function sourceEvidence(run: TimingRun): readonly { readonly bytes: Uint8Array; readonly mediaType: string }[] {
  return run.evidenceBytes;
}

/** Advances a fresh run through the common phases to exactly ROUTE_SELECTED. */
async function advanceToRouteSelected(run: TimingRun): Promise<void> {
  await commitEvent(run, "FREEZE_OBJECTIVE", {}, "freeze-objective");
  await commitEvent(run, "ACQUIRE_LOCK", {}, "acquire-lock");
  await commitEvent(run, "CAPTURE_BASELINE", { approval_required: false }, "capture-baseline");
  await commitEvent(run, "ACCEPT_CLEAN_BASELINE", {}, "accept-clean-baseline");
  await commitEvent(run, "PASS_FULL_PREFLIGHT", {}, "pass-full-preflight");
  await commitEvent(run, "VALIDATE_CONTRACT", {}, "validate-contract", sourceEvidence(run));
  await commitEvent(run, "SELECT_ROUTE", { execution_mode: "STATIC_APPROVED_DAG" }, "select-route");
}

async function freezeAndActivate(run: TimingRun, planSha: Sha256Digest): Promise<WorkflowTimeAuthorityDocument> {
  // Exact production order: publish-or-reuse WORKFLOW timing against the exact
  // pre-FREEZE predecessor, then FREEZE_STATIC_DAG, then ACTIVATE_DAG.
  const predecessor = await inspectionOf(run);
  const workflow = await establishWorkflowStaticTimeAuthority({
    ...loc(run),
    approvedPlanContentSha256: planSha,
    workflowWallBudgetMs: STATIC_BUDGETS.workflow_wall_ms,
    epoch: {
      revision: predecessor.revision!,
      workflow_state_content_sha256: predecessor.workflowState!.content_sha256,
      transition_commit_content_sha256: predecessor.transitionCommit!.content_sha256,
    },
  });
  await commitEvent(run, "FREEZE_STATIC_DAG", {}, "freeze-static-dag");
  await commitEvent(run, "ACTIVATE_DAG", {}, "activate-dag");
  return workflow;
}

async function establishPreparedNodeAuthority(run: TimingRun, workflow: WorkflowTimeAuthorityDocument, taskId: string): Promise<ReturnType<typeof establishNodeStaticTimeAuthority>> {
  const ready = await inspectionOf(run);
  return establishNodeStaticTimeAuthority({
    ...loc(run),
    taskId,
    nodeWallBudgetMs: STATIC_BUDGETS.node_wall_ms,
    workflowTimeAuthorityContentSha256: workflow.content_sha256 as Sha256Digest,
    epoch: {
      revision: ready.revision!,
      workflow_state_content_sha256: ready.workflowState!.content_sha256,
      transition_commit_content_sha256: ready.transitionCommit!.content_sha256,
    },
  });
}

async function nodeEpochOf(authority: { predecessor_revision: number; predecessor_workflow_state_content_sha256: string; predecessor_transition_commit_content_sha256: string }) {
  return {
    revision: authority.predecessor_revision,
    workflow_state_content_sha256: authority.predecessor_workflow_state_content_sha256,
    transition_commit_content_sha256: authority.predecessor_transition_commit_content_sha256,
  };
}

function timingClassifications(inspection: RunStorageInspection): readonly ManagedRecordClassification[] {
  return inspection.managedRecordClassifications.filter((entry) => entry.object.kind === "M2_STATIC_TIME_AUTHORITY");
}

async function classificationOfDigest(run: TimingRun, sha: string): Promise<ManagedRecordClassification | undefined> {
  return timingClassifications(await inspectionOf(run)).find((entry: ManagedRecordClassification) => entry.object.contentSha256 === sha);
}

async function establishWorkflowAtTip(run: TimingRun): Promise<WorkflowTimeAuthorityDocument> {
  const predecessor = await inspectionOf(run);
  return establishWorkflowStaticTimeAuthority({
    ...loc(run),
    approvedPlanContentSha256: run.planContentSha256,
    workflowWallBudgetMs: STATIC_BUDGETS.workflow_wall_ms,
    epoch: {
      revision: predecessor.revision!,
      workflow_state_content_sha256: predecessor.workflowState!.content_sha256,
      transition_commit_content_sha256: predecessor.transitionCommit!.content_sha256,
    },
  });
}

async function resumeTiming(run: TimingRun, nowMs: number) {
  const [inspection, records] = await Promise.all([inspectionOf(run), readM5ManagedRecords(loc(run))]);
  return resolveApplicableResumeTiming({
    runId: run.runId,
    state: inspection.workflowState!,
    tipCommit: inspection.transitionCommit!,
    records: {
      transitionCommits: records.transitionCommits,
      workflowStates: records.workflowStates,
      transitionEvents: records.transitionEvents,
      authorities: records.staticTimeAuthorities,
    },
    verdicts: staticTimingVerdicts(inspection.managedRecordClassifications),
    nowMs,
  });
}

test("prepared WORKFLOW timing stays UNREFERENCED until its FREEZE_STATIC_DAG commit, then becomes authoritative", async () => {
  installTestWallClock(() => 10_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const workflow = await establishWorkflowAtTip(run);
    const before = await classificationOfDigest(run, workflow.content_sha256);
    // The record was prepared BEFORE its consuming transition existed.
    assert.equal(before?.classification, "UNREFERENCED_MANAGED_RECORD");
    assert.equal((await inspectionOf(run)).status, "HEALTHY");
    await commitEvent(run, "FREEZE_STATIC_DAG", {}, "freeze-static-dag");
    const after = await classificationOfDigest(run, workflow.content_sha256);
    assert.equal(after?.classification, "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("exact expiry boundary expires at now == started + wall and not before", () => {
  assert.equal(staticDeadlineExpired(1_000, 500, 1_499), false);
  assert.equal(staticDeadlineExpired(1_000, 500, 1_500), true);
  assert.equal(staticDeadlineExpired(1_000, 500, 1_501), true);
  const workflow = { started_at_epoch_ms: 5_000, wall_budget_ms: 100 } as unknown as WorkflowTimeAuthorityDocument;
  const node = { started_at_epoch_ms: 6_000, wall_budget_ms: 50 } as unknown as Parameters<typeof staticNodeDeadlineExpired>[0];
  assert.equal(staticWorkflowDeadlineExpired(workflow, 5_099), false);
  assert.equal(staticWorkflowDeadlineExpired(workflow, 5_100), true);
  assert.equal(staticNodeDeadlineExpired(node, 6_049), false);
  assert.equal(staticNodeDeadlineExpired(node, 6_050), true);
});

test("response-loss reuse returns the exact sampled timestamp without minting a newer one", async () => {
  let now = 20_000;
  installTestWallClock(() => now);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const predecessor = await inspectionOf(run);
    const input = {
      approvedPlanContentSha256: run.planContentSha256,
      workflowWallBudgetMs: STATIC_BUDGETS.workflow_wall_ms,
      epoch: {
        revision: predecessor.revision!,
        workflow_state_content_sha256: predecessor.workflowState!.content_sha256,
        transition_commit_content_sha256: predecessor.transitionCommit!.content_sha256,
      },
    };
    const first = await establishWorkflowStaticTimeAuthority({ ...loc(run), ...input });
    now += 777; // a retry after lost response must never adopt this later sample
    const second = await establishWorkflowStaticTimeAuthority({ ...loc(run), ...input });
    assert.equal(second.started_at_epoch_ms, first.started_at_epoch_ms);
    assert.equal(second.content_sha256, first.content_sha256);
    assert.equal((await readStaticTimeAuthorities(loc(run))).length, 1);
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("same semantic key with different content refuses publication and injected duplicates classify invalid", async () => {
  installTestWallClock(() => 30_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const authority = await freezeAndActivate(run, run.planContentSha256);
    const conflicting = identifyContractDocument("pi_gacw_static_time_authority_v0", {
      ...JSON.parse(canonicalize(authority)) as Record<string, unknown>,
      started_at_epoch_ms: 30_001,
    }) as unknown as StaticTimeAuthorityDocument;
    await assert.rejects(
      publishStaticTimeAuthority({ ...loc(run), document: conflicting }),
      (error: unknown) => (error as { code?: string }).code === "STATIC_TIME_AUTHORITY_CONFLICT",
    );
    assert.equal((await readStaticTimeAuthorities(loc(run))).length, 1);
    // A conflicting file that reaches storage out-of-band poisons the semantic key fail-closed.
    await writeFile(
      join(run.stateRoot, "runs", run.runId, "records", "static-time-authorities", `${conflicting.content_sha256.slice("sha256:".length)}.json`),
      `${canonicalize(conflicting)}\n`,
      { mode: 0o600 },
    );
    const classifications = timingClassifications(await inspectionOf(run));
    assert.deepEqual(classifications.map((entry) => entry.classification).sort(), ["INVALID_MANAGED_RECORD", "INVALID_MANAGED_RECORD"]);
    const resolution = await resumeTiming(run, 31_000);
    assert.equal(resolution.outcome, "REFUSED");
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("two-leaf flow mints one WORKFLOW authority and distinct NODE authorities per READY epoch", async () => {
  installTestWallClock(() => 40_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const workflow = await freezeAndActivate(run, run.planContentSha256);
    const nodeA = await establishPreparedNodeAuthority(run, workflow, "task-a");
    assert.notEqual(nodeA.authority_id, workflow.authority_id);

    await commitEvent(run, "SELECT_READY_LEAF", {}, "select-a");
    await commitEvent(run, "START_LEAF_ATTEMPT", {}, "start-a");
    await commitEvent(run, "COMPLETE_LEAF_ATTEMPT", {}, "complete-a");
    await commitEvent(run, "PASS_LEAF_POSTFLIGHT", {}, "postflight-a");
    const passed = await commitEvent(run, "LEAF_VERIFICATION_PASSED", {}, "verify-a");
    assert.equal(passed.workflowState!.phase, "READY");

    const nodeB = await establishPreparedNodeAuthority(run, workflow, "task-b");
    assert.notEqual(nodeB.authority_id, nodeA.authority_id);
    const authorities = await readStaticTimeAuthorities(loc(run));
    assert.equal(authorities.filter((entry) => entry.authority_scope === "WORKFLOW").length, 1);
    assert.equal(authorities.filter((entry) => entry.authority_scope === "NODE").length, 2);
    // The consumed leaf-a authority stays validly historical while prepared leaf-b waits.
    assert.equal(await (await classificationOfDigest(run, nodeA.content_sha256))?.classification, "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await (await classificationOfDigest(run, nodeB.content_sha256))?.classification, "UNREFERENCED_MANAGED_RECORD");
    assert.equal(await (await classificationOfDigest(run, workflow.content_sha256))?.classification, "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("retry keeps the same NODE started_at by reusing the select-epoch authority", async () => {
  installTestWallClock(() => 50_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const workflow = await freezeAndActivate(run, run.planContentSha256);
    const node = await establishPreparedNodeAuthority(run, workflow, "task-a");
    await commitEvent(run, "SELECT_READY_LEAF", {}, "select-retry");
    await commitEvent(run, "START_LEAF_ATTEMPT", {}, "start-retry");
    await commitEvent(run, "COMPLETE_LEAF_ATTEMPT", {}, "complete-retry");
    await commitEvent(run, "PASS_LEAF_POSTFLIGHT", {}, "postflight-retry");
    const failed = await commitEvent(run, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" }, "fail-retry");
    assert.equal(failed.workflowState!.phase, "LEAF_RETRY_READY");
    const retried = await commitEvent(run, "ADMIT_LEAF_RETRY", { progress_delta: { kind: "NEW_TEST_EVIDENCE", evidence_sha256: digest(77), summary: "progress" } }, "admit-retry");
    assert.equal(retried.workflowState!.phase, "LEAF_FAST_PREFLIGHT");

    // The retry resolves through the SAME select-epoch prepared authority.
    const again = await establishNodeStaticTimeAuthority({
      ...loc(run),
      taskId: "task-a",
      nodeWallBudgetMs: STATIC_BUDGETS.node_wall_ms,
      workflowTimeAuthorityContentSha256: workflow.content_sha256 as Sha256Digest,
      epoch: await nodeEpochOf(node),
    });
    assert.equal(again.started_at_epoch_ms, node.started_at_epoch_ms);
    assert.equal((await readStaticTimeAuthorities(loc(run))).filter((entry) => entry.authority_scope === "NODE").length, 1);
    const resolution = await resumeTiming(run, 51_000);
    assert.equal(resolution.outcome, "OK");
    assert.equal(resolution.outcome === "OK" ? resolution.node?.started_at_epoch_ms : undefined, node.started_at_epoch_ms);
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("READY without NODE timing stays eligible while a selected leaf without it refuses", async () => {
  installTestWallClock(() => 60_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    await freezeAndActivate(run, run.planContentSha256); // workflow authority durable before READY
    const readyResolution = await resumeTiming(run, 61_000);
    assert.equal(readyResolution.outcome, "OK");
    if (readyResolution.outcome === "OK") assert.equal(readyResolution.node, null);

    // Out-of-band select without its prepared NODE authority: refuse, never synthesize.
    await commitEvent(run, "SELECT_READY_LEAF", {}, "select-no-timing");
    const refused = await resumeTiming(run, 61_500);
    assert.equal(refused.outcome, "REFUSED");
    if (refused.outcome === "REFUSED") assert.match(refused.detail, /prepared NODE timing authority/);
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("legacy layout without the timing directory stays structurally healthy, creates nothing on read-only inspection, and refuses timing eligibility", async () => {
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    // An old retained run: the freeze happened under a controller predating this feature.
    await commitEvent(run, "FREEZE_STATIC_DAG", {}, "freeze-static-dag-legacy");
    await commitEvent(run, "ACTIVATE_DAG", {}, "activate-dag-legacy");
    const timingDirectory = join(run.stateRoot, "runs", run.runId, "records", "static-time-authorities");
    await rm(timingDirectory, { recursive: true, force: true });
    const inspection = await inspectionOf(run);
    assert.equal(inspection.status, "HEALTHY");
    assert.equal(existsSync(timingDirectory), false); // read-only inspection must not create it
    assert.deepEqual(await readStaticTimeAuthorities(loc(run)), []);
    await readM5ManagedRecords(loc(run));
    assert.equal(existsSync(timingDirectory), false);
    const resolution = await resumeTiming(run, 70_000);
    assert.equal(resolution.outcome, "REFUSED");
    if (resolution.outcome === "REFUSED") assert.match(resolution.detail, /no valid WORKFLOW timing authority/);
  } finally {
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("tampered wall budget binding classifies INVALID and refuses until removed", async () => {
  installTestWallClock(() => 80_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const authority = await freezeAndActivate(run, run.planContentSha256);
    const tamperedPath = join(run.stateRoot, "runs", run.runId, "records", "static-time-authorities", "tampered.json");
    // Content-addressed duplicate with the same semantic key but a widened budget.
    const tampered = identifyContractDocument("pi_gacw_static_time_authority_v0", {
      ...JSON.parse(canonicalize(authority)) as Record<string, unknown>,
      wall_budget_ms: STATIC_BUDGETS.workflow_wall_ms + 1,
    }) as unknown as StaticTimeAuthorityDocument;
    await writeFile(
      join(run.stateRoot, "runs", run.runId, "records", "static-time-authorities", `${tampered.content_sha256.slice("sha256:".length)}.json`),
      `${canonicalize(tampered)}\n`,
      { mode: 0o600 },
    );
    void tamperedPath;
    const classification = await classificationOfDigest(run, tampered.content_sha256);
    assert.equal(classification?.classification, "INVALID_MANAGED_RECORD");
    assert.match(classification?.detail ?? "", /workflow_wall_ms|authority_id/);
    const resolution = await resumeTiming(run, 81_000);
    assert.equal(resolution.outcome, "REFUSED");
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("forward clock jumps expire conservatively and detectable backward motion refuses", async () => {
  const workflow = { started_at_epoch_ms: 1_000, wall_budget_ms: 100 } as unknown as WorkflowTimeAuthorityDocument;
  assert.equal(staticWorkflowDeadlineExpired(workflow, 1_100), true);
  let probeNow = 900;
  installTestWallClock(() => probeNow);
  assert.equal(sampleWallClockMs(), 900);
  probeNow = 899; // detectable realtime regression within one process
  assert.throws(() => sampleWallClockMs(), (error: unknown) => error instanceof WallClockError && error.code === "WALL_CLOCK_REGRESSED");
  installTestWallClock(null);

  installTestWallClock(() => 90_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const workflowAuthority = await freezeAndActivate(run, run.planContentSha256);
    const node = await establishPreparedNodeAuthority(run, workflowAuthority, "task-a");
    await commitEvent(run, "SELECT_READY_LEAF", {}, "select-fwd");
    const expired = await resumeTiming(run, 90_000 + STATIC_BUDGETS.workflow_wall_ms * 10);
    assert.equal(expired.outcome, "REFUSED");
    if (expired.outcome === "REFUSED") assert.match(expired.detail, /deadline is exhausted/);
    const fresh = await resumeTiming(run, 90_500);
    assert.equal(fresh.outcome, "OK");
    assert.equal(fresh.outcome === "OK" ? fresh.node?.started_at_epoch_ms : undefined, node.started_at_epoch_ms);
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

test("a NODE authority cannot bind a task other than the canonical reducer selection", async () => {
  installTestWallClock(() => 95_000);
  const run = await createStaticTimingRun();
  try {
    await advanceToRouteSelected(run);
    const workflow = await freezeAndActivate(run, run.planContentSha256);
    // Canonical selection on this READY epoch is task-a; binding task-b must be invalid.
    const wrong = await establishPreparedNodeAuthority(run, workflow, "task-b");
    const classification = await classificationOfDigest(run, wrong.content_sha256);
    assert.equal(classification?.classification, "INVALID_MANAGED_RECORD");
    assert.match(classification?.detail ?? "", /canonical ready-leaf selection/);
  } finally {
    installTestWallClock(null);
    await rm(run.stateRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Full-flow downtime semantics (faux runtime; provider-free)
// ---------------------------------------------------------------------------

async function flowFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "static-time-authority-flow-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "time-authority@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "time-authority"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "check.mjs"), "process.exit(0);\n");
  await execFileAsync("git", ["add", "verify"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

function flowGoal(): BoundedMutationGoal {
  return {
    objective: "Write exactly the frozen static outputs.",
    stop_condition: "Stop after deterministic verification.",
    execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] },
    required_outputs: ["a.txt", "b.txt"],
    tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["a"] },
    ],
  };
}

async function runFlow(
  budgets: StaticApprovedDagTimeBudgets,
  runtime: BoundedWorkerRuntime,
): Promise<Awaited<ReturnType<typeof runBoundedMutationWorkflowForTests>>> {
  const root = await flowFixture();
  configureBoundedWorkerFauxRuntimeForTests(() => runtime);
  try {
    return await runBoundedMutationWorkflowForTests(flowGoal(), {
      cwd: root,
      authority: {
        verification_commands: [{ command_id: "check", executable: process.execPath, args: ["check.mjs"], cwd: "verify" }],
        static_time_budgets: budgets,
      } satisfies BoundedMutationAuthority,
      approveTasks: async ({ plan }) => plan!.content_sha256 as `sha256:${string}`,
    });
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(root, { recursive: true, force: true });
  }
}

async function installTestWallClockAround<T>(action: (advance: (milliseconds: number) => void) => Promise<T>): Promise<T> {
  let now = 0;
  installTestWallClock(() => now);
  try {
    return await action((milliseconds) => { now += milliseconds; });
  } finally {
    installTestWallClock(null);
  }
}

test("inter-node downtime accumulates against the one durable workflow anchor across two distinct node epochs", async () => {
  let writes = 0;
  const deadlines: number[] = [];
  const result = await installTestWallClockAround(async (advance) => {
    return await runFlow(
      // worker <= node <= workflow. Leaf a consumes 1.0s of the shared workflow
      // budget; leaf b mints a FRESH NODE authority (unexpired) yet accumulated
      // durable workflow elapsed (1.9s) crosses the frozen 1.8s deadline.
      { worker_deadline_ms: 300_000, node_wall_ms: 1_800_000, workflow_wall_ms: 1_800_000 },
      {
        async execute({ deadlineMs, tools }) {
          deadlines.push(deadlineMs);
          const path = ["a.txt", "b.txt"][writes++]!;
          advance(writes === 1 ? 1_000_000 : 900_000);
          await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
          tools.submitReport(`wrote ${path}`);
          return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        },
      },
    );
  });
  assert.equal(result.outcome, "BLOCKED");
  assert.match(result.reason, /STATIC_WORKFLOW_WALL_DEADLINE_EXCEEDED/);
  assert.equal(result.finalState?.phase, "BLOCKED");
  assert.deepEqual(deadlines, [300_000, 300_000]);
});

test("an exact node-deadline hit blocks inside the same node", async () => {
  let writes = 0;
  const deadlines: number[] = [];
  const result = await installTestWallClockAround(async (advance) => {
    return await runFlow(
      { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 },
      {
        async execute({ deadlineMs, tools }) {
          deadlines.push(deadlineMs);
          const path = ["a.txt", "b.txt"][writes++]!;
          advance(600_000); // exactly the frozen node budget, consumed durably
          await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
          tools.submitReport(`wrote ${path}`);
          return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        },
      },
    );
  });
  assert.equal(result.outcome, "BLOCKED");
  assert.match(result.reason, /STATIC_NODE_WALL_DEADLINE_EXCEEDED/);
  assert.equal(result.finalState?.phase, "BLOCKED");
  assert.deepEqual(deadlines, [300_000]);
});
