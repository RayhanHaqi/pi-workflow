/**
 * Durable static wall-clock timing authority semantics (V1-R2D-TIME, M2-owned).
 *
 * Timing is persisted as ordinary content-addressed immutable records in
 * records/static-time-authorities/ plus a deterministic semantic authority_id.
 * There is no latest-wins, no timestamp ordering, no mutable timing slot, and
 * no heartbeat service: one semantic start epoch may own exactly one immutable
 * document, and same-key/different-content publication fails closed.
 *
 * The deadline is always derived as started_at_epoch_ms + wall_budget_ms under
 * safe-integer arithmetic; a record is expired iff now >= that deadline,
 * exactly matching the historical `elapsed >= wall_ms` semantics.
 */
import { canonicalize } from "../canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "../identity/index.js";
import {
  identifyContractDocument,
  type BudgetDocument,
  type NodeTimeAuthorityDocument,
  type PlanApprovalDocument,
  type ReducerPolicy,
  type StateTransitionCommitDocument,
  type StaticTimeAuthorityDocument,
  type TransitionEvent,
  type WorkflowState,
  type WorkflowTimeAuthorityDocument,
} from "../schemas/index.js";
import { selectReadyLeafUnchecked } from "../state-machine/reducer.js";
import { sampleWallClockMs } from "../wall-clock.js";
import type { ManagedRecordClassification } from "./types.js";

export const STATIC_TIME_AUTHORITY_DOMAIN_WORKFLOW = "pi_gacw_static_time_authority_v0:workflow" as const;
export const STATIC_TIME_AUTHORITY_DOMAIN_NODE = "pi_gacw_static_time_authority_v0:node" as const;

/** The exact committed predecessor transition epoch a timing authority binds. */
export interface StaticTimeEpoch {
  readonly revision: number;
  readonly workflow_state_content_sha256: string;
  readonly transition_commit_content_sha256: string;
}

export function workflowStaticTimeAuthorityIdentity(input: {
  readonly run_id: string;
  readonly approved_plan_content_sha256: string;
  readonly predecessor_transition_commit_content_sha256: string;
}): Sha256Digest {
  return sha256Canonical({
    domain: STATIC_TIME_AUTHORITY_DOMAIN_WORKFLOW,
    run_id: input.run_id,
    approved_plan_content_sha256: input.approved_plan_content_sha256,
    predecessor_transition_commit_content_sha256: input.predecessor_transition_commit_content_sha256,
  });
}

export function nodeStaticTimeAuthorityIdentity(input: {
  readonly run_id: string;
  readonly workflow_time_authority_content_sha256: string;
  readonly predecessor_transition_commit_content_sha256: string;
}): Sha256Digest {
  return sha256Canonical({
    domain: STATIC_TIME_AUTHORITY_DOMAIN_NODE,
    run_id: input.run_id,
    workflow_time_authority_content_sha256: input.workflow_time_authority_content_sha256,
    predecessor_transition_commit_content_sha256: input.predecessor_transition_commit_content_sha256,
  });
}

/** Samples the production clock exactly once for one semantic publication attempt. */
export function sampleStartedAtEpochMs(): number {
  return sampleWallClockMs();
}

function assertSafeDeadline(startedAtEpochMs: number, wallBudgetMs: number): number {
  if (!Number.isSafeInteger(startedAtEpochMs) || !Number.isSafeInteger(wallBudgetMs)) {
    throw new Error("static timing fields must be safe integers");
  }
  const deadline = startedAtEpochMs + wallBudgetMs;
  if (!Number.isSafeInteger(deadline)) throw new Error("static timing deadline exceeds the safe integer range");
  return deadline;
}

/** Expired iff now >= started_at + wall_budget, matching historical elapsed >= wall semantics. */
export function staticDeadlineExpired(startedAtEpochMs: number, wallBudgetMs: number, nowMs: number): boolean {
  return nowMs >= assertSafeDeadline(startedAtEpochMs, wallBudgetMs);
}

export function staticWorkflowDeadlineExpired(authority: WorkflowTimeAuthorityDocument, nowMs: number): boolean {
  return staticDeadlineExpired(authority.started_at_epoch_ms, authority.wall_budget_ms, nowMs);
}

export function staticNodeDeadlineExpired(authority: NodeTimeAuthorityDocument, nowMs: number): boolean {
  return staticDeadlineExpired(authority.started_at_epoch_ms, authority.wall_budget_ms, nowMs);
}

export function buildWorkflowStaticTimeAuthority(input: {
  readonly runId: string;
  readonly approvedPlanContentSha256: Sha256Digest;
  readonly epoch: StaticTimeEpoch;
  readonly workflowWallBudgetMs: number;
  readonly startedAtEpochMs: number;
}): WorkflowTimeAuthorityDocument {
  return identifyContractDocument("pi_gacw_static_time_authority_v0", {
    schema_id: "pi_gacw_static_time_authority_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    authority_scope: "WORKFLOW",
    authority_id: workflowStaticTimeAuthorityIdentity({
      run_id: input.runId,
      approved_plan_content_sha256: input.approvedPlanContentSha256,
      predecessor_transition_commit_content_sha256: input.epoch.transition_commit_content_sha256,
    }),
    approved_plan_content_sha256: input.approvedPlanContentSha256,
    predecessor_revision: input.epoch.revision,
    predecessor_workflow_state_content_sha256: input.epoch.workflow_state_content_sha256,
    predecessor_transition_commit_content_sha256: input.epoch.transition_commit_content_sha256,
    wall_budget_ms: input.workflowWallBudgetMs,
    started_at_epoch_ms: input.startedAtEpochMs,
  }) as unknown as WorkflowTimeAuthorityDocument;
}

export function buildNodeStaticTimeAuthority(input: {
  readonly runId: string;
  readonly taskId: string;
  readonly epoch: StaticTimeEpoch;
  readonly workflowTimeAuthorityContentSha256: Sha256Digest;
  readonly nodeWallBudgetMs: number;
  readonly startedAtEpochMs: number;
}): NodeTimeAuthorityDocument {
  return identifyContractDocument("pi_gacw_static_time_authority_v0", {
    schema_id: "pi_gacw_static_time_authority_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    authority_scope: "NODE",
    authority_id: nodeStaticTimeAuthorityIdentity({
      run_id: input.runId,
      workflow_time_authority_content_sha256: input.workflowTimeAuthorityContentSha256,
      predecessor_transition_commit_content_sha256: input.epoch.transition_commit_content_sha256,
    }),
    workflow_time_authority_content_sha256: input.workflowTimeAuthorityContentSha256,
    predecessor_revision: input.epoch.revision,
    predecessor_workflow_state_content_sha256: input.epoch.workflow_state_content_sha256,
    predecessor_transition_commit_content_sha256: input.epoch.transition_commit_content_sha256,
    task_id: input.taskId,
    wall_budget_ms: input.nodeWallBudgetMs,
    started_at_epoch_ms: input.startedAtEpochMs,
  }) as unknown as NodeTimeAuthorityDocument;
}

// ---------------------------------------------------------------------------
// Immutable M2 transition ancestry
// ---------------------------------------------------------------------------

export interface StaticTimeAncestry {
  readonly commits: ReadonlyMap<string, StateTransitionCommitDocument>;
  readonly states: ReadonlyMap<string, WorkflowState>;
  readonly events: ReadonlyMap<string, TransitionEvent>;
}

const MAX_ANCESTRY_WALK = 10_000;

function epochOfCommit(commit: StateTransitionCommitDocument): StaticTimeEpoch {
  return {
    revision: commit.previous_revision!,
    workflow_state_content_sha256: commit.previous_workflow_state_content_sha256!,
    transition_commit_content_sha256: commit.previous_transition_commit_content_sha256!,
  };
}

function eventType(ancestry: StaticTimeAncestry, commit: StateTransitionCommitDocument): string | null {
  const event = ancestry.events.get(commit.transition_event_content_sha256!);
  return event?.event_type ?? null;
}

/** The exact FREEZE_STATIC_DAG predecessor epoch of an already-started static run. */
export function resolveFreezePredecessorEpoch(ancestry: StaticTimeAncestry): EpochResolution {
  let freeze: StateTransitionCommitDocument | null = null;
  for (const commit of ancestry.commits.values()) {
    if (commit.commit_kind !== "TRANSITION" || eventType(ancestry, commit) !== "FREEZE_STATIC_DAG") continue;
    if (freeze !== null) return { outcome: "REFUSED", detail: "multiple FREEZE_STATIC_DAG commits in committed ancestry" };
    if (commit.previous_revision === null || commit.previous_workflow_state_content_sha256 === null || commit.previous_transition_commit_content_sha256 === null) {
      return { outcome: "REFUSED", detail: "FREEZE_STATIC_DAG commit lacks its exact predecessor epoch" };
    }
    freeze = commit;
  }
  if (freeze === null) return { outcome: "ABSENT" };
  const state = ancestry.states.get(freeze.previous_workflow_state_content_sha256!);
  if (state === undefined) return { outcome: "REFUSED", detail: "FREEZE_STATIC_DAG predecessor state is absent" };
  return { outcome: "RESOLVED", epoch: epochOfCommit(freeze) };
}

/** The current committed epoch itself (used before SELECT while READY). */
export function resolveCurrentCommittedEpoch(tip: StateTransitionCommitDocument, tipState: WorkflowState): EpochResolution {
  if (tip.commit_kind !== "TRANSITION") return { outcome: "ABSENT" };
  return {
    outcome: "RESOLVED",
    epoch: {
      revision: tip.new_revision,
      workflow_state_content_sha256: tip.new_workflow_state_content_sha256,
      transition_commit_content_sha256: tip.content_sha256,
    },
  };
}

/**
 * Walks immutable ancestry back to the SELECT_READY_LEAF that began the current
 * contiguous active_task_id epoch and returns THAT select commit's previous
 * epoch — the exact NODE timing epoch. Never chooses by timestamp or depth.
 */
export function resolveActiveLeafSelectPredecessorEpoch(
  ancestry: StaticTimeAncestry,
  tipCommitSha: string,
  activeTaskId: string,
): EpochResolution {
  let cursorSha: string | null = tipCommitSha;
  for (let steps = 0; cursorSha !== null && steps < MAX_ANCESTRY_WALK; steps += 1) {
    const commit = ancestry.commits.get(cursorSha);
    if (commit === undefined) return { outcome: "REFUSED", detail: "active-leaf ancestry walk left the committed chain" };
    if (commit.commit_kind !== "TRANSITION") return { outcome: "REFUSED", detail: "active-leaf ancestry walk reached a non-transition commit" };
    const newState = ancestry.states.get(commit.new_workflow_state_content_sha256);
    if (newState === undefined || newState.active_task_id !== activeTaskId) {
      return { outcome: "REFUSED", detail: "active-leaf ancestry does not preserve the active task identity" };
    }
    if (
      commit.previous_revision === null || commit.previous_workflow_state_content_sha256 === null ||
      commit.previous_transition_commit_content_sha256 === null
    ) {
      return { outcome: "REFUSED", detail: "active-leaf ancestry lacks a predecessor epoch at the selection boundary" };
    }
    const previousState = ancestry.states.get(commit.previous_workflow_state_content_sha256);
    if (previousState === undefined) {
      return { outcome: "REFUSED", detail: "active-leaf ancestry predecessor state is absent" };
    }
    if (eventType(ancestry, commit) === "SELECT_READY_LEAF") {
      if (previousState.active_task_id !== null) {
        return { outcome: "REFUSED", detail: "selection boundary predecessor is not an unassigned READY state" };
      }
      return {
        outcome: "RESOLVED",
        epoch: {
          revision: commit.previous_revision,
          workflow_state_content_sha256: commit.previous_workflow_state_content_sha256,
          transition_commit_content_sha256: commit.previous_transition_commit_content_sha256,
        },
      };
    }
    // Inside one contiguous active epoch every intermediate transition keeps the active task assigned.
    if (previousState.active_task_id !== activeTaskId) {
      return { outcome: "REFUSED", detail: "active-leaf epoch began without its SELECT_READY_LEAF commit" };
    }
    cursorSha = commit.previous_transition_commit_content_sha256;
  }
  return { outcome: "REFUSED", detail: "active-leaf ancestry walk exceeded its bounded depth" };
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export type StaticTimingDecision =
  | "AUTHORITATIVE_MANAGED_RECORD"
  | "UNREFERENCED_MANAGED_RECORD"
  | "INCOMPLETE_MANAGED_RECORD_CHAIN"
  | "INVALID_MANAGED_RECORD";

export interface StaticTimingVerdict {
  readonly decision: StaticTimingDecision;
  readonly detail: string;
}

function projectedAuthorityId(value: StaticTimeAuthorityDocument, predecessorCommitSha: string): string | null {
  if (value.authority_scope === "WORKFLOW") {
    return workflowStaticTimeAuthorityIdentity({
      run_id: value.run_id,
      approved_plan_content_sha256: value.approved_plan_content_sha256,
      predecessor_transition_commit_content_sha256: predecessorCommitSha,
    });
  }
  return nodeStaticTimeAuthorityIdentity({
    run_id: value.run_id,
    workflow_time_authority_content_sha256: value.workflow_time_authority_content_sha256,
    predecessor_transition_commit_content_sha256: predecessorCommitSha,
  });
}

/** Same semantic key with different immutable content poisons every member: fail closed. */
export function findStaticTimingSemanticConflict(
  authorities: ReadonlyMap<string, StaticTimeAuthorityDocument>,
): string | null {
  const byKey = new Map<string, string>();
  for (const [digest, value] of authorities) {
    const canonical = canonicalize(value);
    const prior = byKey.get(value.authority_id);
    if (prior !== undefined && prior !== canonical) {
      return `conflicting immutable content shares semantic authority_id ${value.authority_id}`;
    }
    byKey.set(value.authority_id, canonical);
  }
  return null;
}

/**
 * The smallest separate M2 timing-classification path. Structural/schema and
 * content-addressing integrity are already enforced by ordinary record reads;
 * this pass adds semantic identity, budget binding, reducer-selection, and
 * duplicate refusal on top. Prepared records that no transition has followed
 * yet remain valid UNREFERENCED evidence; historical authorities never become
 * invalid merely because a later leaf is current.
 */
export function classifyStaticTimeAuthorities(input: {
  readonly runId: string;
  readonly authorities: ReadonlyMap<string, StaticTimeAuthorityDocument>;
  readonly reachableCommits: ReadonlySet<string>;
  readonly reachableStates: ReadonlySet<string>;
  readonly ancestry: StaticTimeAncestry;
  readonly policies: ReadonlyMap<string, ReducerPolicy>;
  readonly budgets: readonly BudgetDocument[];
  readonly planApprovals: readonly PlanApprovalDocument[];
}): ReadonlyMap<string, StaticTimingVerdict> {
  const verdicts = new Map<string, StaticTimingVerdict>();
  const conflict = findStaticTimingSemanticConflict(input.authorities);

  for (const [digest, value] of input.authorities) {
    const invalid = (detail: string): void => { verdicts.set(digest, { decision: "INVALID_MANAGED_RECORD", detail }); };
    if (conflict !== null) { invalid(conflict); continue; }
    if (value.run_id !== input.runId) { invalid(`timing authority names another run (${value.run_id})`); continue; }
    const commit = input.ancestry.commits.get(value.predecessor_transition_commit_content_sha256);
    const epochValid = commit !== undefined && commit.commit_kind === "TRANSITION" &&
      commit.new_revision === value.predecessor_revision &&
      commit.new_workflow_state_content_sha256 === value.predecessor_workflow_state_content_sha256 &&
      input.reachableCommits.has(commit.content_sha256) &&
      input.reachableStates.has(value.predecessor_workflow_state_content_sha256);
    if (!epochValid) {
      invalid("timing authority does not name an exact reachable predecessor transition epoch");
      continue;
    }
    const predecessorState = input.ancestry.states.get(value.predecessor_workflow_state_content_sha256)!;
    if (predecessorState.execution_mode !== "STATIC_APPROVED_DAG") {
      invalid("timing authority predecessor state is not STATIC_APPROVED_DAG");
      continue;
    }
    try { assertSafeDeadline(value.started_at_epoch_ms, value.wall_budget_ms); }
    catch (error: unknown) { invalid(error instanceof Error ? error.message : "unsafe timing arithmetic"); continue; }
    if (projectedAuthorityId(value, value.predecessor_transition_commit_content_sha256) !== value.authority_id) {
      invalid("authority_id does not match its domain-separated semantic projection");
      continue;
    }
  }

  // WORKFLOW first so NODE chain validation can observe referenced verdicts.
  const frozenBudget = (predecessorState: WorkflowState): { workflow_wall_ms: number; node_wall_ms: number } | null => {
    const budget = input.budgets.find((entry) => entry.budget_sha256 === predecessorState.identities.budget_sha256);
    const staticBudgets = budget?.limits.static_time_budgets;
    return staticBudgets === undefined ? null : { workflow_wall_ms: staticBudgets.workflow_wall_ms, node_wall_ms: staticBudgets.node_wall_ms };
  };
  const workflowVerdictByDigest = new Map<string, StaticTimingVerdict>();
  for (const [digest, value] of input.authorities) {
    if (verdicts.has(digest)) { workflowVerdictByDigest.set(digest, verdicts.get(digest)!); continue; }
    if (value.authority_scope !== "WORKFLOW") continue;
    const predecessorState = input.ancestry.states.get(value.predecessor_workflow_state_content_sha256)!;
    const budgets = frozenBudget(predecessorState);
    if (budgets === null) { workflowVerdictByDigest.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "frozen plan carries no static time budgets to bind" }); continue; }
    if (value.wall_budget_ms !== budgets.workflow_wall_ms) { workflowVerdictByDigest.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "wall_budget_ms differs from the frozen plan workflow_wall_ms" }); continue; }
    // Exact approved-plan binding: the named content identity must be a durable
    // PlanApproval whose projection equals the frozen state identity.
    const approvedPlan = input.planApprovals.find((entry) => entry.content_sha256 === value.approved_plan_content_sha256);
    if (approvedPlan === undefined || approvedPlan.plan_approval_sha256 !== predecessorState.identities.plan_approval_sha256) {
      workflowVerdictByDigest.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "approved plan identity differs from the frozen plan approval" }); continue;
    }
    workflowVerdictByDigest.set(digest, { decision: authoritativeWorkflow(input.ancestry, value), detail: "valid workflow timing authority" });
  }

  for (const [digest, verdict] of workflowVerdictByDigest) verdicts.set(digest, verdict);

  for (const [digest, value] of input.authorities) {
    if (verdicts.has(digest)) continue;
    if (value.authority_scope !== "NODE") continue;
    const referenced = input.authorities.get(value.workflow_time_authority_content_sha256);
    const referencedVerdict = referenced === undefined ? undefined : verdicts.get(value.workflow_time_authority_content_sha256);
    if (referenced === undefined || referencedVerdict === undefined || referencedVerdict.decision === "INVALID_MANAGED_RECORD" || referencedVerdict.decision === "INCOMPLETE_MANAGED_RECORD_CHAIN" || referenced.authority_scope !== "WORKFLOW") {
      verdicts.set(digest, { decision: "INCOMPLETE_MANAGED_RECORD_CHAIN", detail: "referenced WORKFLOW timing authority is absent or not valid" });
      continue;
    }
    const workflowAuthority = referenced as WorkflowTimeAuthorityDocument;
    if (value.started_at_epoch_ms < workflowAuthority.started_at_epoch_ms) {
      verdicts.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "node start precedes its workflow start" });
      continue;
    }
    const predecessorState = input.ancestry.states.get(value.predecessor_workflow_state_content_sha256)!;
    const budgets = frozenBudget(predecessorState);
    if (budgets === null) { verdicts.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "frozen plan carries no static time budgets to bind" }); continue; }
    if (value.wall_budget_ms !== budgets.node_wall_ms) { verdicts.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "wall_budget_ms differs from the frozen plan node_wall_ms" }); continue; }
    const policy = input.policies.get(predecessorState.frozen_policy_content_sha256);
    if (policy === undefined) { verdicts.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "predecessor reducer policy is absent" }); continue; }
    if (predecessorState.active_task_id !== null || selectReadyLeafUnchecked(predecessorState, policy) !== value.task_id) {
      verdicts.set(digest, { decision: "INVALID_MANAGED_RECORD", detail: "task_id differs from canonical ready-leaf selection on the exact predecessor state" });
      continue;
    }
    verdicts.set(digest, { decision: authoritativeNode(input.ancestry, value), detail: "valid node timing authority" });
  }
  return verdicts;
}

function authoritativeWorkflow(ancestry: StaticTimeAncestry, value: StaticTimeAuthorityDocument): StaticTimingDecision {
  for (const commit of ancestry.commits.values()) {
    if (commit.commit_kind !== "TRANSITION" || eventType(ancestry, commit) !== "FREEZE_STATIC_DAG") continue;
    if (commit.previous_revision === value.predecessor_revision &&
      commit.previous_workflow_state_content_sha256 === value.predecessor_workflow_state_content_sha256 &&
      commit.previous_transition_commit_content_sha256 === value.predecessor_transition_commit_content_sha256) {
      return "AUTHORITATIVE_MANAGED_RECORD";
    }
  }
  return "UNREFERENCED_MANAGED_RECORD";
}

function authoritativeNode(ancestry: StaticTimeAncestry, value: NodeTimeAuthorityDocument): StaticTimingDecision {
  for (const commit of ancestry.commits.values()) {
    if (commit.commit_kind !== "TRANSITION" || eventType(ancestry, commit) !== "SELECT_READY_LEAF") continue;
    if (commit.previous_revision === value.predecessor_revision &&
      commit.previous_workflow_state_content_sha256 === value.predecessor_workflow_state_content_sha256 &&
      commit.previous_transition_commit_content_sha256 === value.predecessor_transition_commit_content_sha256) {
      const selected = ancestry.states.get(commit.new_workflow_state_content_sha256);
      if (selected !== undefined && selected.active_task_id === value.task_id) return "AUTHORITATIVE_MANAGED_RECORD";
    }
  }
  return "UNREFERENCED_MANAGED_RECORD";
}

// ---------------------------------------------------------------------------
// Resume timing resolution
// ---------------------------------------------------------------------------

export type EpochResolution =
  | { readonly outcome: "RESOLVED"; readonly epoch: StaticTimeEpoch }
  | { readonly outcome: "ABSENT" }
  | { readonly outcome: "REFUSED"; readonly detail: string };

export type StaticTimingResolution<T extends StaticTimeAuthorityDocument> =
  | { readonly outcome: "RESOLVED"; readonly authority: T }
  | { readonly outcome: "ABSENT" }
  | { readonly outcome: "REFUSED"; readonly detail: string };

/** Resolves exactly one matching valid WORKFLOW timing authority; never by timestamp order. */
export function resolveWorkflowTimingAuthority(input: {
  readonly runId: string;
  readonly authorities: ReadonlyMap<string, StaticTimeAuthorityDocument>;
  readonly verdicts: ReadonlyMap<string, StaticTimingVerdict>;
  readonly freezeEpoch: EpochResolution;
}): StaticTimingResolution<WorkflowTimeAuthorityDocument> {
  if (input.freezeEpoch.outcome === "REFUSED") return { outcome: "REFUSED", detail: input.freezeEpoch.detail };
  if (input.freezeEpoch.outcome === "ABSENT") return { outcome: "ABSENT" };
  const conflict = findStaticTimingSemanticConflict(input.authorities);
  if (conflict !== null) return { outcome: "REFUSED", detail: conflict };
  // Same defensive physical-first shape as NODE resolution: every physical record
  // naming the exact freeze epoch counts, whatever its classification.
  const epoch = input.freezeEpoch.epoch;
  const physical = [...input.authorities.values()].filter((value) =>
    value.run_id === input.runId &&
    value.authority_scope === "WORKFLOW" &&
    value.predecessor_revision === epoch.revision &&
    value.predecessor_workflow_state_content_sha256 === epoch.workflow_state_content_sha256 &&
    value.predecessor_transition_commit_content_sha256 === epoch.transition_commit_content_sha256);
  if (physical.length === 0) return { outcome: "ABSENT" };
  const broken = physical.find((value) => {
    const decision = input.verdicts.get(value.content_sha256)?.decision;
    return decision === undefined || decision === "INVALID_MANAGED_RECORD" || decision === "INCOMPLETE_MANAGED_RECORD_CHAIN";
  });
  if (broken !== undefined) {
    const detail = input.verdicts.get(broken.content_sha256)?.detail ?? "current-epoch WORKFLOW timing record is unclassified";
    return { outcome: "REFUSED", detail };
  }
  if (physical.length > 1) {
    return { outcome: "REFUSED", detail: "multiple physical WORKFLOW timing records match the exact epoch" };
  }
  return { outcome: "RESOLVED", authority: physical[0]! as WorkflowTimeAuthorityDocument };
}

/**
 * Resolves exactly one valid NODE timing authority for an exact NODE epoch.
 *
 * V1-R2D-TIME-R1: matching is over ALL PHYSICAL records naming the exact epoch,
 * independent of classification. An invalid or incomplete current-epoch record
 * REFUSES — it must never degrade to ABSENT and invite re-establishment; more
 * than one physical match refuses regardless of ordering. No timestamp order,
 * no latest-wins, no file-order arbitration.
 */
export function resolveNodeTimingAuthorityForEpoch(input: {
  readonly runId: string;
  readonly authorities: ReadonlyMap<string, StaticTimeAuthorityDocument>;
  readonly verdicts: ReadonlyMap<string, StaticTimingVerdict>;
  readonly nodeEpoch: EpochResolution;
}): StaticTimingResolution<NodeTimeAuthorityDocument> {
  if (input.nodeEpoch.outcome === "REFUSED") return { outcome: "REFUSED", detail: input.nodeEpoch.detail };
  if (input.nodeEpoch.outcome === "ABSENT") return { outcome: "ABSENT" };
  const conflict = findStaticTimingSemanticConflict(input.authorities);
  if (conflict !== null) return { outcome: "REFUSED", detail: conflict };
  const epoch = input.nodeEpoch.epoch;
  const physical = [...input.authorities.values()].filter((value) =>
    value.run_id === input.runId &&
    value.authority_scope === "NODE" &&
    value.predecessor_revision === epoch.revision &&
    value.predecessor_workflow_state_content_sha256 === epoch.workflow_state_content_sha256 &&
    value.predecessor_transition_commit_content_sha256 === epoch.transition_commit_content_sha256);
  if (physical.length === 0) return { outcome: "ABSENT" };
  const broken = physical.find((value) => {
    const decision = input.verdicts.get(value.content_sha256)?.decision;
    return decision === undefined || decision === "INVALID_MANAGED_RECORD" || decision === "INCOMPLETE_MANAGED_RECORD_CHAIN";
  });
  if (broken !== undefined) {
    const detail = input.verdicts.get(broken.content_sha256)?.detail ?? "current-epoch NODE timing record is unclassified";
    return { outcome: "REFUSED", detail };
  }
  if (physical.length > 1) {
    return { outcome: "REFUSED", detail: "multiple physical NODE timing records match the exact epoch" };
  }
  return { outcome: "RESOLVED", authority: physical[0]! as NodeTimeAuthorityDocument };
}

// ---------------------------------------------------------------------------
// Resume timing resolution (shared by read-only inspection and R2B/R2C admission)
// ---------------------------------------------------------------------------

export interface StaticResumeTimingRecords {
  readonly transitionCommits: readonly StateTransitionCommitDocument[];
  readonly workflowStates: readonly WorkflowState[];
  readonly transitionEvents: readonly TransitionEvent[];
  readonly authorities: readonly StaticTimeAuthorityDocument[];
}

/** Timing verdicts projected from one inspection's managed-record classifications. */
export function staticTimingVerdicts(classifications: readonly ManagedRecordClassification[]): ReadonlyMap<string, StaticTimingVerdict> {
  return new Map(classifications
    .filter((entry) => entry.object.kind === "M2_STATIC_TIME_AUTHORITY")
    .map((entry): [string, StaticTimingVerdict] => [entry.object.contentSha256, { decision: entry.classification as StaticTimingVerdict["decision"], detail: entry.detail }]));
}

export type StaticResumeTimingResolution =
  | { readonly outcome: "OK"; readonly workflow: WorkflowTimeAuthorityDocument | null; readonly node: NodeTimeAuthorityDocument | null }
  | { readonly outcome: "REFUSED"; readonly detail: string };

/**
 * Resolves the applicable durable timing for one retained state without any
 * latest-wins or timestamp-order heuristic. A READY state with no NODE authority
 * is the legitimate pre-selection boundary; any already-selected or in-progress
 * leaf without its exact NODE authority refuses.
 */
export function resolveApplicableResumeTiming(input: {
  readonly runId: string;
  readonly state: WorkflowState;
  readonly tipCommit: StateTransitionCommitDocument;
  readonly records: StaticResumeTimingRecords;
  readonly verdicts: ReadonlyMap<string, StaticTimingVerdict>;
  readonly nowMs: number;
}): StaticResumeTimingResolution {
  const authorityMap = new Map(input.records.authorities.map((entry) => [entry.content_sha256, entry]));
  const ancestry: StaticTimeAncestry = {
    commits: new Map(input.records.transitionCommits.map((entry) => [entry.content_sha256, entry])),
    states: new Map(input.records.workflowStates.map((entry) => [entry.content_sha256, entry])),
    events: new Map(input.records.transitionEvents.map((entry) => [entry.content_sha256, entry])),
  };
  const freezeEpoch = resolveFreezePredecessorEpoch(ancestry);
  if (freezeEpoch.outcome === "ABSENT") return { outcome: "OK", workflow: null, node: null };
  const workflow = resolveWorkflowTimingAuthority({ runId: input.runId, authorities: authorityMap, verdicts: input.verdicts, freezeEpoch });
  if (workflow.outcome === "REFUSED") return { outcome: "REFUSED", detail: workflow.detail };
  if (workflow.outcome === "ABSENT") return { outcome: "REFUSED", detail: "the started STATIC run has no valid WORKFLOW timing authority" };
  if (staticWorkflowDeadlineExpired(workflow.authority, input.nowMs)) return { outcome: "REFUSED", detail: "the frozen workflow wall deadline is exhausted" };
  let node: StaticTimingResolution<NodeTimeAuthorityDocument>;
  if (input.state.active_task_id !== null) {
    // Selected / in-progress leaf: walk immutable ancestry back to the SELECT_READY_LEAF
    // that began this contiguous active epoch; retries reuse that same epoch's authority.
    const selectEpoch = resolveActiveLeafSelectPredecessorEpoch(ancestry, input.tipCommit.content_sha256, input.state.active_task_id);
    if (selectEpoch.outcome === "REFUSED") return { outcome: "REFUSED", detail: selectEpoch.detail };
    node = resolveNodeTimingAuthorityForEpoch({ runId: input.runId, authorities: authorityMap, verdicts: input.verdicts, nodeEpoch: selectEpoch });
    if (node.outcome === "ABSENT") return { outcome: "REFUSED", detail: "a selected leaf has no valid prepared NODE timing authority" };
  } else if (input.state.phase === "READY" && input.tipCommit.commit_kind === "TRANSITION") {
    const currentEpoch = resolveCurrentCommittedEpoch(input.tipCommit, input.state);
    node = resolveNodeTimingAuthorityForEpoch({ runId: input.runId, authorities: authorityMap, verdicts: input.verdicts, nodeEpoch: currentEpoch });
    if (node.outcome === "ABSENT") {
      // Legitimate boundary before node timing starts; eligible to establish under lock before SELECT.
      return { outcome: "OK", workflow: workflow.authority, node: null };
    }
  } else {
    // No active leaf and not a fresh READY boundary (for example final DAG verification): workflow deadline only.
    return { outcome: "OK", workflow: workflow.authority, node: null };
  }
  if (node.outcome === "REFUSED") return { outcome: "REFUSED", detail: node.detail };
  if (node.outcome === "RESOLVED" && staticNodeDeadlineExpired(node.authority, input.nowMs)) {
    return { outcome: "REFUSED", detail: "the frozen node wall deadline is exhausted" };
  }
  return { outcome: "OK", workflow: workflow.authority, node: node.outcome === "RESOLVED" ? node.authority : null };
}
