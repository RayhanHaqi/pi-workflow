import { realpath, readdir } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { canonicalize } from "./canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { resolveAuthoritativeBoundedExecution, type ResolvedBoundedExecution } from "./persistence/bounded-worker-authority.js";
import { buildBoundedWorkerUsageEvidence } from "./control/usage-evidence.js";
import { inspectRunStorage } from "./persistence/index.js";
import { readM5ManagedRecords } from "./persistence/store.js";
import { resolveApplicableResumeTiming, staticTimingVerdicts } from "./persistence/static-time-authority.js";
import { assertNoGitBlockers, assertRepositoryMatches } from "./repository/preflight.js";
import { selectReadyLeafUnchecked } from "./state-machine/reducer.js";
import { sampleWallClockMs } from "./wall-clock.js";
import { captureGitState } from "./repository/fingerprint.js";
import { resolveRepositoryIdentity } from "./repository/index.js";
import { probeWorktreeLockAvailability } from "./repository/lock.js";
import { loadAuthoritativeToken } from "./repository/token-provenance.js";
import type { ManagedRecordClassification } from "./persistence/types.js";
import type {
  BoundedWorkerInvocationDocument,
  BoundedWorkerResultDocument,
  BudgetDocument,
  ContractDocument,
  M3BaselineApprovalRuntimeDocument,
  M3BaselineRuntimeDocument,
  M3RepositoryIdentityDocument,
  M3RepositoryStateTokenDocument,
  LogicalModelRole,
  M4CommandCatalogDocument,
  M4ScopedToolPolicyDocument,
  M5ControlDecisionDocument,
  M5ControlPolicyDocument,
  PlanApprovalDocument,
  ReducerPolicy,
  RouteMapApprovalDocument,
  RouteMapDocument,
  TaskDocument,
  TaskGraphDocument,
  TransitionEvent,
  WorkflowState,
} from "./schemas/index.js";

export type ResumeRefusalReason =
  | "RESUME_REFUSED_TERMINAL"
  | "RESUME_REFUSED_STATE_STORE"
  | "RESUME_REFUSED_REPOSITORY_IDENTITY"
  | "RESUME_REFUSED_STATE_DRIFT"
  | "RESUME_REFUSED_BASELINE_AUTHORITY"
  | "RESUME_REFUSED_EXECUTION_AUTHORITY"
  | "RESUME_REFUSED_TIMING_AUTHORITY"
  | "RESUME_REFUSED_IN_FLIGHT_OPERATION"
  | "RESUME_REFUSED_AMBIGUOUS_RESUME_POINT";

export interface ResumeEligibilityReport {
  readonly classification: "RESUMABLE" | "RESUME_REFUSED";
  readonly run_id: string | null;
  readonly phase: string | null;
  readonly resume_point: string | null;
  readonly reason: ResumeRefusalReason | null;
}

export interface ResumeInspectionInput {
  /** The retained controller workspace containing exactly one state/runs/<run-id> directory. */
  readonly retainedRunRoot: string;
}

/** Minimal pre-lock target derivation; complete authority is always revalidated under lock. */
export interface DeterministicResumeLockTarget {
  readonly stateRoot: string;
  readonly runId: string;
  readonly repository: M3RepositoryIdentityDocument;
}

function report(
  classification: ResumeEligibilityReport["classification"],
  runId: string | null,
  phase: string | null,
  resumePoint: string | null,
  reason: ResumeRefusalReason | null,
): ResumeEligibilityReport {
  return Object.freeze({ classification, run_id: runId, phase, resume_point: resumePoint, reason });
}

function refused(runId: string | null, state: WorkflowState | null, reason: ResumeRefusalReason): ResumeEligibilityReport {
  return report("RESUME_REFUSED", runId, state?.phase ?? null, null, reason);
}

function authoritative(
  classifications: readonly ManagedRecordClassification[],
  kind: string,
  digest: string,
): boolean {
  return classifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest &&
    entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
}

function exactOne<T extends { readonly content_sha256: string }>(values: readonly T[], digest: string): T | null {
  const matches = values.filter((value) => value.content_sha256 === digest);
  return matches.length === 1 ? matches[0]! : null;
}

function exactOneBy<T>(values: readonly T[], predicate: (value: T) => boolean): T | null {
  const matches = values.filter(predicate); return matches.length === 1 ? matches[0]! : null;
}

function baselineForState(state: WorkflowState, records: Awaited<ReturnType<typeof readM5ManagedRecords>>): M3BaselineRuntimeDocument | undefined {
  return exactOne(records.baselines, state.identities.baseline_approval_sha256) ?? records.baselines.find((entry) =>
    entry.baseline_mode === "APPROVED_BASELINE_DIRTY" && records.approvals.some((approval) =>
      approval.content_sha256 === state.identities.baseline_approval_sha256 && approval.baseline_runtime_content_sha256 === entry.content_sha256));
}

/** Established M3 token-chain semantics: the unique authoritative chain tip, or null when ambiguous. */
export function tokenTip(tokens: readonly M3RepositoryStateTokenDocument[]): M3RepositoryStateTokenDocument | null {
  const predecessors = new Set(tokens.map((token) => token.prior_token_content_sha256).filter((value): value is string => value !== null));
  const tips = tokens.filter((token) => !predecessors.has(token.content_sha256));
  return tips.length === 1 ? tips[0]! : null;
}
function tokenDescendsFrom(
  tokens: readonly M3RepositoryStateTokenDocument[],
  ancestorContentSha256: string,
  tip: M3RepositoryStateTokenDocument,
): boolean {
  const byDigest = new Map(tokens.map((entry) => [entry.content_sha256, entry]));
  const seen = new Set<string>();
  let cursor: M3RepositoryStateTokenDocument | undefined = tip;
  while (cursor !== undefined && !seen.has(cursor.content_sha256)) {
    seen.add(cursor.content_sha256);
    if (cursor.content_sha256 === ancestorContentSha256) return true;
    cursor = cursor.prior_token_content_sha256 === null ? undefined : byDigest.get(cursor.prior_token_content_sha256);
  }
  return false;
}

/** The only V1-R2B supported points are static READY selection and pre-worker selected-leaf start. */
export function deriveStaticDagResumePoint(state: WorkflowState, policy: ReducerPolicy): string | null {
  if (state.execution_mode !== "STATIC_APPROVED_DAG") return null;
  const selected = selectReadyLeafUnchecked(state, policy);
  if (state.phase === "READY" && state.active_task_id === null) return selected === null ? null : `STATIC_DAG_SELECT_READY_LEAF:${selected}`;
  if (state.phase !== "LEAF_FAST_PREFLIGHT" || state.active_task_id === null || selected !== state.active_task_id) return null;
  const task = state.tasks.find((candidate) => candidate.task_id === selected);
  return task?.status === "PENDING" && task.attempts === 0 ? `STATIC_DAG_START_SELECTED_LEAF:${selected}` : null;
}

export function staticLeafOperationId(taskId: string): string { return `static-leaf-${taskId}-attempt-1`; }
export function staticLeafTransitionId(operationId: string): string { return `pre-m8-authorize-${operationId}`; }
export function staticLeafReconciliationTransitionId(taskId: string): string {
  return `r2e-complete-${sha256Canonical({ task_id: taskId }).slice(7, 39)}`;
}
export function staticLeafPostflightTransitionId(taskId: string): string {
  return `r2e-postflight-${sha256Canonical({ task_id: taskId }).slice(7, 39)}`;
}
export function staticLeafVerificationTransitionId(taskId: string, outcome: "PASSED" | "FAILED"): string {
  return `r2e-verification-${outcome.toLowerCase()}-${sha256Canonical({ task_id: taskId }).slice(7, 39)}`;
}

/** Historical frozen product-role inventory; must stay canonically equal to workflow-controller's PRODUCT_ROLES (drift-guarded by resume-work-admission.test). */
export const RESUMED_PRODUCT_LOGICAL_ROLES = Object.freeze(["SOL_OWNER", "SOL_PLANNER", "SOL_REPLAN", "SOL_CLOSEOUT", "LUNA_EXECUTOR", "TERRA_EXECUTOR", "BENCHMARK_VERIFIER", "BENCHMARK_SELECTOR"] as const);

/** Exact production availableLogicalRoles semantics: V2 coding runs reserve only CODING_EXECUTOR; legacy V1 keeps the full inventory. */
export function resumedAvailableLogicalRoles(policy: M5ControlPolicyDocument): readonly LogicalModelRole[] {
  return policy.role_reservation_envelopes.some((entry) => entry.logical_role === "CODING_EXECUTOR")
    ? ["CODING_EXECUTOR" as const]
    : [...RESUMED_PRODUCT_LOGICAL_ROLES];
}

/** Exactly one M5 control policy may own this state's frozen identities; ambiguity refuses. */
export function resolveExactStaticM5Policy(
  state: WorkflowState,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
): M5ControlPolicyDocument | null {
  const matches = records.policies.filter((entry) => entry.run_id === state.run_id && entry.reducer_policy_content_sha256 === state.frozen_policy_content_sha256 &&
    entry.contract_sha256 === state.identities.contract_sha256 && entry.budget_sha256 === state.identities.budget_sha256 &&
    entry.scope_sha256 === state.identities.scope_sha256 && entry.acceptance_sha256 === state.identities.acceptance_sha256 &&
    entry.plan_approval_sha256 === state.identities.plan_approval_sha256 && entry.task_graph_sha256 === state.identities.task_graph_sha256);
  return matches.length === 1 ? matches[0]! : null;
}
function classificationOf(classifications: readonly ManagedRecordClassification[], kind: string, digest: string): string | null {
  return classifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest)?.classification ?? null;
}

/** Worker records bound to exactly one logical operation identity (CURRENT-operation scope, never run-global history). */
export function currentOperationWorkerRecords(
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  operationId: string,
): { readonly invocations: typeof records.boundedWorkerInvocations; readonly results: typeof records.boundedWorkerResults } {
  const invocations = records.boundedWorkerInvocations.filter((invocation) => invocation.operation_id === operationId);
  const invocationShas = new Set(invocations.map((invocation) => invocation.content_sha256));
  const results = records.boundedWorkerResults.filter((result) => invocationShas.has(result.invocation_content_sha256));
  return { invocations, results };
}

/**
 * Settled historical authority proof for every reservation/worker operation OUTSIDE the current decision set:
 * authoritative invocation/result pairs with certain cleanup, no orphans, no unknown outcomes, and each
 * non-current reservation carrying its completed outcome evidence. Legacy M6 evidence always refuses.
 */
function historicalOperationsSettled(
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
  currentDecisionShas: ReadonlySet<string>,
): boolean {
  if (classifications.some((entry) => entry.object.kind === "M6_WORKER_INVOCATION" || entry.object.kind === "M6_WORKER_RESULT")) return false;
  if (records.boundedWorkerInvocations.some((invocation) => !authoritative(classifications, "BOUNDED_WORKER_INVOCATION", invocation.content_sha256))) return false;
  if (records.boundedWorkerResults.some((result) => !authoritative(classifications, "BOUNDED_WORKER_RESULT", result.content_sha256))) return false;
  for (const invocation of records.boundedWorkerInvocations) {
    const results = records.boundedWorkerResults.filter((result) => result.invocation_content_sha256 === invocation.content_sha256);
    if (results.length !== 1 || !results[0]!.cleanup_certain) return false;
  }
  for (const result of records.boundedWorkerResults) {
    if (records.boundedWorkerInvocations.filter((invocation) => invocation.content_sha256 === result.invocation_content_sha256).length !== 1) return false;
  }
  for (const decision of records.decisions) {
    if (decision.reservation === null || currentDecisionShas.has(decision.content_sha256)) continue;
    if (!authoritative(classifications, "M5_CONTROL_DECISION", decision.content_sha256) || decision.reservation.status === "OUTCOME_UNCERTAIN") return false;
    const invocations = records.boundedWorkerInvocations.filter((entry) => entry.m5_reservation_decision_content_sha256 === decision.content_sha256);
    if (invocations.length !== 1 || records.boundedWorkerResults.filter((entry) => entry.invocation_content_sha256 === invocations[0]!.content_sha256).length !== 1) return false;
  }
  return true;
}

function staticWorkDecisionCandidateList(
  state: WorkflowState,
  policy: ReducerPolicy,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
  allowCurrentWorkerEvidence = false,
): readonly M5ControlDecisionDocument[] {
  if (state.execution_mode !== "STATIC_APPROVED_DAG" || state.active_task_id === null) return [];
  const task = state.tasks.find((entry) => entry.task_id === state.active_task_id);
  const frozenTask = policy.tasks.find((entry) => entry.task_id === state.active_task_id);
  const m5Policy = resolveExactStaticM5Policy(state, records);
  if (task === undefined || frozenTask === undefined || m5Policy === null) return [];
  const operationId = staticLeafOperationId(task.task_id);
  const transitionId = staticLeafTransitionId(operationId);
  // Provider-safety boundary is CURRENT-operation scoped, never run-global history: any matching bounded
  // invocation or result proves the provider boundary may already be crossed for this exact operation.
  const current = currentOperationWorkerRecords(records, operationId);
  if (!allowCurrentWorkerEvidence && (current.invocations.length !== 0 || current.results.length !== 0)) return [];
  // FIRST_ATTEMPT_ONLY: any candidate is the attempt-1 operation for the selected task; historical
  // settled predecessor leaves are valid and must not block the next first-attempt leaf.
  const candidates = records.decisions.filter((decision) => decision.intent === "AUTHORIZE_WORK" && decision.outcome === "AUTHORIZE" &&
    decision.operation_id === operationId && decision.transition_id === transitionId && decision.policy_content_sha256 === m5Policy.content_sha256 &&
    decision.reducer_policy_content_sha256 === state.frozen_policy_content_sha256 &&
    decision.transition_event?.event_type === "START_LEAF_ATTEMPT" && decision.reservation?.status === "ACTIVE" &&
    decision.reservation.future_operation_id === operationId && decision.reservation.reserved_policy_content_sha256 === decision.policy_content_sha256 &&
    decision.reservation.reserved_route === "STATIC_APPROVED_DAG");
  if (!historicalOperationsSettled(records, classifications, new Set(candidates.map((decision) => decision.content_sha256)))) return [];
  return candidates;
}

/** Package-internal exact pre-provider AUTHORIZE_WORK decision match under a required managed-record classification. */
export function exactStaticWorkDecision(
  state: WorkflowState,
  policy: ReducerPolicy,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
  requiredClassification: "UNREFERENCED_MANAGED_RECORD" | "AUTHORITATIVE_MANAGED_RECORD",
): M5ControlDecisionDocument | null {
  const candidates = staticWorkDecisionCandidateList(state, policy, records, classifications).filter((decision) =>
    classificationOf(classifications, "M5_CONTROL_DECISION", decision.content_sha256) === requiredClassification);
  if (candidates.length !== 1) return null;
  return candidates[0]!;
}

/** Candidates without a classification requirement; distinguishes a clean first admission from contradictory authority. */
export function staticWorkDecisionCandidates(
  state: WorkflowState,
  policy: ReducerPolicy,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): readonly M5ControlDecisionDocument[] {
  return staticWorkDecisionCandidateList(state, policy, records, classifications);
}

export interface SettledStaticLeafAuthority {
  readonly taskId: string;
  readonly operationId: string;
  readonly policy: M5ControlPolicyDocument;
  readonly reducerPolicy: ReducerPolicy;
  readonly repositoryIdentity: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly baselineApproval: M3BaselineApprovalRuntimeDocument | null;
  readonly contract: ContractDocument;
  readonly budget: BudgetDocument;
  readonly routeMap: RouteMapDocument;
  readonly routeMapApproval: RouteMapApprovalDocument;
  readonly toolPolicy: M4ScopedToolPolicyDocument;
  readonly commandCatalog: M4CommandCatalogDocument;
  readonly plan: PlanApprovalDocument;
  readonly taskGraph: TaskGraphDocument;
  readonly task: TaskDocument;
  readonly reservation: M5ControlDecisionDocument;
  readonly reservationState: WorkflowState;
  readonly invocation: BoundedWorkerInvocationDocument;
  readonly result: BoundedWorkerResultDocument;
  readonly inputStateToken: M3RepositoryStateTokenDocument;
  readonly currentStateToken: M3RepositoryStateTokenDocument;
  readonly resolved: ResolvedBoundedExecution;
}

function classifiedAs(
  classifications: readonly ManagedRecordClassification[],
  kind: string,
  digest: string,
  expected: ManagedRecordClassification["classification"],
): boolean {
  return classifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest && entry.classification === expected);
}

function exactStaticSettledDecisionCandidates(
  state: WorkflowState,
  policy: ReducerPolicy,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): readonly M5ControlDecisionDocument[] {
  return staticWorkDecisionCandidateList(state, policy, records, classifications, true)
    .filter((decision) => classifiedAs(classifications, "M5_CONTROL_DECISION", decision.content_sha256, "AUTHORITATIVE_MANAGED_RECORD"));
}

/**
 * Resolves the exact current settled bounded worker pair. This is deliberately
 * stricter than mere record presence: the sole M5 resolver must accept the
 * invocation/result against its original input token and authoritative
 * reservation, while the current M3 tip may be a descendant of that token.
 */
export function resolveSettledStaticLeafAuthority(
  state: WorkflowState,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): SettledStaticLeafAuthority | null {
  if (state.execution_mode !== "STATIC_APPROVED_DAG" || state.active_task_id === null ||
      !["LEAF_RUNNING", "LEAF_POSTFLIGHT", "LEAF_VERIFYING"].includes(state.phase)) return null;
  const runtimeTask = state.tasks.find((entry) => entry.task_id === state.active_task_id);
  if (runtimeTask === undefined || runtimeTask.status !== "RUNNING" || runtimeTask.attempts !== 1) return null;
  const reducerPolicy = exactOne(records.reducerPolicies, state.frozen_policy_content_sha256);
  const policy = resolveExactStaticM5Policy(state, records);
  if (reducerPolicy === null || policy === null || policy.plan_approval_sha256 === null || policy.task_graph_sha256 === null) return null;
  const decisions = exactStaticSettledDecisionCandidates(state, reducerPolicy, records, classifications);
  if (decisions.length !== 1 || decisions[0]!.operation_id !== staticLeafOperationId(state.active_task_id)) return null;
  const reservation = decisions[0]!;
  const current = currentOperationWorkerRecords(records, reservation.operation_id!);
  if (current.invocations.length !== 1 || current.results.length !== 1) return null;
  const invocation = current.invocations[0]!;
  const result = current.results[0]!;
  if (result.invocation_content_sha256 !== invocation.content_sha256 || result.outcome !== "COMPLETED" || !result.cleanup_certain) return null;
  const reservationState = exactOne(records.workflowStates, reservation.current_state_content_sha256);
  const inputTokens = records.stateTokens.filter((entry) => entry.content_sha256 === invocation.input_m3_state_token_content_sha256 &&
    classifiedAs(classifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD"));
  const baseline = baselineForState(state, records);
  const baselineApproval = baseline?.baseline_mode === "APPROVED_BASELINE_DIRTY"
    ? exactOne(records.approvals, state.identities.baseline_approval_sha256)
    : null;
  const contract = exactOneBy(records.contracts, (entry) => entry.contract_sha256 === policy.contract_sha256);
  const budget = exactOneBy(records.budgets, (entry) => entry.budget_sha256 === policy.budget_sha256);
  const routeMap = exactOneBy(records.routeMaps, (entry) => entry.route_map_sha256 === policy.route_map_sha256);
  const routeMapApproval = exactOneBy(records.routeMapApprovals, (entry) => entry.route_map_approval_sha256 === policy.route_map_approval_sha256);
  const toolPolicy = exactOne(records.toolPolicies, policy.tool_policy_content_sha256);
  const commandCatalog = exactOne(records.commandCatalogs, policy.command_catalog_content_sha256);
  const plan = exactOneBy(records.planApprovals, (entry) => entry.plan_approval_sha256 === policy.plan_approval_sha256);
  const taskGraph = exactOneBy(records.taskGraphs, (entry) => entry.task_graph_sha256 === policy.task_graph_sha256);
  const taskCandidates = records.tasks.filter((entry) => entry.task_id === state.active_task_id && entry.content_sha256 === invocation.task_content_sha256);
  const scopedTokens = records.stateTokens.filter((entry) => entry.run_id === policy.run_id &&
    entry.repository_identity_content_sha256 === policy.repository_identity_content_sha256 && entry.worktree_key === policy.worktree_key &&
    entry.task_scope_identity === policy.scope_sha256 && classifiedAs(classifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD"));
  const currentStateToken = tokenTip(scopedTokens);
  if (reservationState === null || inputTokens.length !== 1 || baseline === undefined || contract === null || budget === null || routeMap === null ||
      routeMapApproval === null || toolPolicy === null || commandCatalog === null || plan === null || taskGraph === null || taskCandidates.length !== 1 ||
      currentStateToken === null || !tokenDescendsFrom(scopedTokens, invocation.input_m3_state_token_content_sha256, currentStateToken) ||
      invocation.task_content_sha256 === null || invocation.task_graph_sha256 !== taskGraph.content_sha256 ||
      invocation.plan_approval_sha256 !== plan.content_sha256) return null;
  const inputStateToken = inputTokens[0]!;
  const resolved = resolveAuthoritativeBoundedExecution({
    invocation, result, reservation, reservationState, policy, baseline, approval: baselineApproval,
    stateToken: inputStateToken, task: taskCandidates[0]!, taskGraph, plan,
    admissionRefusals: new Map(records.admissionRefusals.map((entry) => [entry.content_sha256, entry])), classifications,
  });
  if (!resolved.accepted || resolved.acceptedWorkerInvocations !== 1) return null;
  const acceptedMutation = resolved.acceptedM4Evidence.some((digest) => {
    const receipt = records.mutationReceipts.find((entry) => entry.content_sha256 === digest);
    return receipt !== undefined && receipt.outcome === "APPLIED" && classifiedAs(classifications, "M4_MUTATION_RECEIPT", digest, "AUTHORITATIVE_MANAGED_RECORD");
  });
  if (!acceptedMutation) return null;
  return Object.freeze({
    taskId: state.active_task_id, operationId: reservation.operation_id!, policy, reducerPolicy,
    repositoryIdentity: baseline.repository, baseline, baselineApproval, contract, budget, routeMap, routeMapApproval, toolPolicy, commandCatalog,
    plan, taskGraph, task: taskCandidates[0]!, reservation, reservationState, invocation, result, inputStateToken, currentStateToken, resolved,
  });
}

function transitionEventFor(
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  commit: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["transitionCommit"]>,
): TransitionEvent | undefined {
  return records.transitionEvents.find((entry) => entry.content_sha256 === commit.transition_event_content_sha256);
}

/** Exact M5 usage/COMPLETE authority required after the settled point. */
export function exactStaticLeafReconciliationDecision(
  state: WorkflowState,
  transitionCommit: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["transitionCommit"]>,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
  authority: SettledStaticLeafAuthority,
): M5ControlDecisionDocument | null {
  if (state.phase !== "LEAF_POSTFLIGHT" && state.phase !== "LEAF_VERIFYING") return null;
  const usage = buildBoundedWorkerUsageEvidence({
    runId: state.run_id, policy: authority.policy, decision: authority.reservation,
    executionMode: state.execution_mode, logicalRole: authority.reservation.reservation!.logical_role, result: authority.result,
  });
  const usages = records.usage.filter((entry) => entry.operation_id === authority.operationId);
  if (usages.length !== 1 || canonicalize(usages[0]) !== canonicalize(usage) ||
      !classifiedAs(classifications, "M5_USAGE_EVIDENCE", usage.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")) return null;
  let completeCommit: typeof transitionCommit | undefined;
  let completeStateContentSha256 = state.content_sha256;
  if (state.phase === "LEAF_POSTFLIGHT") {
    const event = transitionEventFor(records, transitionCommit);
    if (event?.event_type !== "COMPLETE_LEAF_ATTEMPT") return null;
    completeCommit = transitionCommit;
  } else {
    const passEvent = transitionEventFor(records, transitionCommit);
    if (passEvent?.event_type !== "PASS_LEAF_POSTFLIGHT" || transitionCommit.transition_id !== staticLeafPostflightTransitionId(authority.taskId) ||
        transitionCommit.previous_workflow_state_content_sha256 === null) return null;
    const candidates = records.transitionCommits.filter((candidate) => candidate.new_workflow_state_content_sha256 === transitionCommit.previous_workflow_state_content_sha256 &&
      transitionEventFor(records, candidate)?.event_type === "COMPLETE_LEAF_ATTEMPT");
    if (candidates.length !== 1) return null;
    completeCommit = candidates[0]!;
    completeStateContentSha256 = transitionCommit.previous_workflow_state_content_sha256;
  }
  const completeEvent = transitionEventFor(records, completeCommit);
  if (completeEvent?.event_type !== "COMPLETE_LEAF_ATTEMPT" || completeCommit.new_workflow_state_content_sha256 !== completeStateContentSha256 ||
      completeCommit.previous_workflow_state_content_sha256 === null || completeCommit.transition_id !== staticLeafReconciliationTransitionId(authority.taskId)) return null;
  const runningState = records.workflowStates.filter((entry) => entry.content_sha256 === completeCommit!.previous_workflow_state_content_sha256 &&
    entry.phase === "LEAF_RUNNING" && entry.active_task_id === authority.taskId);
  if (runningState.length !== 1) return null;
  const candidates = records.decisions.filter((entry) => entry.intent === "AUTHORIZE_CONTINUATION" && entry.outcome === "AUTHORIZE" && entry.reservation === null &&
    entry.operation_id === authority.operationId && entry.policy_content_sha256 === authority.policy.content_sha256 &&
    entry.current_state_content_sha256 === runningState[0]!.content_sha256 && entry.transition_id === staticLeafReconciliationTransitionId(authority.taskId) &&
    entry.selected_route === "CONTINUE_ADMITTED_OPERATION" && entry.transition_event?.event_type === "COMPLETE_LEAF_ATTEMPT" &&
    entry.predicted_next_state_content_sha256 === completeStateContentSha256 && entry.usage_evidence_content_sha256.includes(usage.content_sha256) &&
    classifiedAs(classifications, "M5_CONTROL_DECISION", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD"));
  if (candidates.length !== 1 || candidates[0]!.transition_event?.content_sha256 !== completeCommit.transition_event_content_sha256) return null;
  return candidates[0]!;
}

/** R2E and its two post-M2 continuation points; all are exact durable states. */
export function deriveStaticDagR2EResumePoint(
  state: WorkflowState,
  transitionCommit: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["transitionCommit"]>,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): string | null {
  const authority = resolveSettledStaticLeafAuthority(state, records, classifications);
  if (authority === null) return null;
  if (state.phase === "LEAF_RUNNING") {
    const startEvent = transitionEventFor(records, transitionCommit);
    if (startEvent?.event_type !== "START_LEAF_ATTEMPT" || transitionCommit.new_workflow_state_content_sha256 !== state.content_sha256 ||
        transitionCommit.transition_id !== authority.reservation.transition_id) return null;
    return `STATIC_DAG_RECONCILE_SETTLED_LEAF:${authority.taskId}`;
  }
  if (exactStaticLeafReconciliationDecision(state, transitionCommit, records, classifications, authority) === null) return null;
  if (state.phase === "LEAF_POSTFLIGHT") return `STATIC_DAG_RECONCILE_LEAF_POSTFLIGHT:${authority.taskId}`;
  if (state.phase === "LEAF_VERIFYING") return `STATIC_DAG_RECONCILE_LEAF_VERIFYING:${authority.taskId}`;
  return null;
}

export function deriveStaticDagPreProviderResumePoint(
  state: WorkflowState,
  policy: ReducerPolicy,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
  transitionCommit: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["transitionCommit"]>,
): string | null {
  if (state.execution_mode !== "STATIC_APPROVED_DAG" || state.active_task_id === null) return null;
  const task = state.tasks.find((entry) => entry.task_id === state.active_task_id);
  if (task === undefined || task.attempts > 1) return null;
  if (state.phase === "LEAF_FAST_PREFLIGHT" && task.status === "PENDING" && task.attempts === 0) {
    const decision = exactStaticWorkDecision(state, policy, records, classifications, "UNREFERENCED_MANAGED_RECORD");
    if (decision !== null && decision.current_state_content_sha256 === state.content_sha256 && decision.predicted_next_state_content_sha256 !== null) {
      return `STATIC_DAG_REDRIVE_WORK_ADMISSION:${task.task_id}`;
    }
  }
  if (state.phase === "LEAF_RUNNING" && task.status === "RUNNING" && task.attempts === 1) {
    const decision = exactStaticWorkDecision(state, policy, records, classifications, "AUTHORITATIVE_MANAGED_RECORD");
    const predecessor = decision === null ? null : records.workflowStates.filter((entry) => entry.content_sha256 === decision.current_state_content_sha256);
    if (decision !== null && predecessor?.length === 1 && decision.predicted_next_state_content_sha256 === state.content_sha256 &&
        transitionCommit.previous_workflow_state_content_sha256 === decision.current_state_content_sha256 &&
        transitionCommit.transition_event_content_sha256 === decision.transition_event?.content_sha256 && transitionCommit.transition_id === decision.transition_id) {
      return `STATIC_DAG_INVOKE_RESERVED_LEAF:${task.task_id}`;
    }
  }
  return null;
}

function executionAuthorityComplete(
  state: WorkflowState,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): { readonly policy: ReducerPolicy; readonly baseline: M3BaselineRuntimeDocument } | null {
  const reducerPolicy = exactOne(records.reducerPolicies, state.frozen_policy_content_sha256);
  const contract = exactOneBy(records.contracts, (entry) => entry.contract_sha256 === state.identities.contract_sha256);
  const budget = exactOneBy(records.budgets, (entry) => entry.budget_sha256 === state.identities.budget_sha256);
  const plan = state.identities.plan_approval_sha256 === null ? null : exactOneBy(records.planApprovals, (entry) => entry.plan_approval_sha256 === state.identities.plan_approval_sha256);
  const graph = state.identities.task_graph_sha256 === null ? null : exactOneBy(records.taskGraphs, (entry) => entry.task_graph_sha256 === state.identities.task_graph_sha256);
  const m5 = records.policies.filter((entry) => entry.reducer_policy_content_sha256 === state.frozen_policy_content_sha256 &&
    entry.contract_sha256 === state.identities.contract_sha256 && entry.budget_sha256 === state.identities.budget_sha256);
  const route = m5.length === 1 ? exactOneBy(records.routeMaps, (entry) => entry.route_map_sha256 === m5[0]!.route_map_sha256) : null;
  const routeApproval = contract === null ? null : exactOneBy(records.routeMapApprovals, (entry) => entry.route_map_approval_sha256 === contract.route_map_approval_sha256);
  const toolPolicy = m5.length === 1 ? exactOne(records.toolPolicies, m5[0]!.tool_policy_content_sha256) : null;
  const commandCatalog = m5.length === 1 ? exactOne(records.commandCatalogs, m5[0]!.command_catalog_content_sha256) : null;
  if (reducerPolicy === null || contract === null || budget === null || route === null || routeApproval === null || toolPolicy === null || commandCatalog === null || m5.length !== 1 ||
    (state.identities.plan_approval_sha256 === null) !== (state.identities.task_graph_sha256 === null) ||
    (state.identities.plan_approval_sha256 !== null && (plan === null || graph === null)) ||
    reducerPolicy.execution_mode !== "STATIC_APPROVED_DAG" || contract.execution_mode !== "STATIC_APPROVED_DAG" ||
    contract.baseline_approval_sha256 !== state.identities.baseline_approval_sha256 ||
    routeApproval.route_map_sha256 !== route.route_map_sha256 ||
    plan?.bindings.dag.task_graph_sha256 !== graph?.task_graph_sha256 ||
    plan?.bindings.contract_sha256 !== contract.contract_sha256 ||
    // Before the first worker admission, M4 policy/catalog records are valid immutable
    // sources but intentionally have no M4 consumer edge yet. The authoritative M5 policy
    // above binds their exact identities; requiring a later M4 classification would make the
    // only safe READY boundary impossible to inspect.
    !authoritative(classifications, "M5_CONTROL_POLICY", m5[0]!.content_sha256)) return null;
  const baseline = baselineForState(state, records) ?? null;
  if (baseline === null || !authoritative(classifications, "M3_BASELINE", baseline.content_sha256)) return null;
  if (baseline.baseline_mode === "APPROVED_BASELINE_DIRTY" && !authoritative(classifications, "M3_BASELINE_APPROVAL", state.identities.baseline_approval_sha256)) return null;
  if (baseline.baseline_mode === "CLEAN_REQUIRED" && baseline.content_sha256 !== state.identities.baseline_approval_sha256) return null;
  return { policy: reducerPolicy, baseline };
}

function settledOperations(
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): boolean {
  if (records.boundedWorkerInvocations.length !== 0 && records.boundedWorkerInvocations.some((invocation) =>
    !authoritative(classifications, "BOUNDED_WORKER_INVOCATION", invocation.content_sha256))) return false;
  if (records.boundedWorkerResults.length !== 0 && records.boundedWorkerResults.some((result) =>
    !authoritative(classifications, "BOUNDED_WORKER_RESULT", result.content_sha256))) return false;
  for (const invocation of records.boundedWorkerInvocations) {
    const results = records.boundedWorkerResults.filter((result) => result.invocation_content_sha256 === invocation.content_sha256);
    if (results.length !== 1 || !results[0]!.cleanup_certain) return false;
  }
  for (const result of records.boundedWorkerResults) {
    if (records.boundedWorkerInvocations.filter((invocation) => invocation.content_sha256 === result.invocation_content_sha256).length !== 1) return false;
  }
  for (const decision of records.decisions) {
    if (decision.reservation === null) continue;
    if (!authoritative(classifications, "M5_CONTROL_DECISION", decision.content_sha256) || decision.reservation.status === "OUTCOME_UNCERTAIN") return false;
    const invocations = records.boundedWorkerInvocations.filter((entry) => entry.m5_reservation_decision_content_sha256 === decision.content_sha256);
    if (invocations.length !== 1 || records.boundedWorkerResults.filter((entry) => entry.invocation_content_sha256 === invocations[0]!.content_sha256).length !== 1) return false;
  }
  // STATIC_APPROVED_DAG V1-R1 does not adopt legacy worker evidence, authoritative or otherwise.
  return !classifications.some((entry) => entry.object.kind === "M6_WORKER_INVOCATION" || entry.object.kind === "M6_WORKER_RESULT");
}

function hasSelectedLeafWorkerEvidence(resumePoint: string, state: WorkflowState, policy: ReducerPolicy, records: Awaited<ReturnType<typeof readM5ManagedRecords>>): boolean {
  if (!resumePoint.startsWith("STATIC_DAG_START_SELECTED_LEAF:")) return false;
  const taskId = resumePoint.slice("STATIC_DAG_START_SELECTED_LEAF:".length);
  const task = policy.tasks.find((candidate) => candidate.task_id === taskId);
  return task === undefined || state.active_task_id !== taskId || records.boundedWorkerInvocations.some((invocation) => invocation.task_content_sha256 === task.task_sha256);
}

/**
 * Read-only eligibility inspection. It never acquires durable M3 lock authority or publishes
 * records; its kernel-flock availability probe releases before returning.
 */
async function inspectDeterministicResumeEligibilityInternal(input: ResumeInspectionInput, requireQuiescence: boolean): Promise<ResumeEligibilityReport> {
  if (!isAbsolute(input.retainedRunRoot)) return refused(null, null, "RESUME_REFUSED_STATE_STORE");
  let root: string;
  let runId: string;
  try {
    root = await realpath(input.retainedRunRoot);
    const runs = (await readdir(join(root, "state", "runs"), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    if (runs.length !== 1) return refused(null, null, "RESUME_REFUSED_STATE_STORE");
    runId = runs[0]!;
  } catch {
    return refused(null, null, "RESUME_REFUSED_STATE_STORE");
  }
  const location = { stateRoot: join(root, "state"), runId };
  let inspection: Awaited<ReturnType<typeof inspectRunStorage>>;
  try { inspection = await inspectRunStorage(location); }
  catch { return refused(runId, null, "RESUME_REFUSED_STATE_STORE"); }
  if (inspection.status !== "HEALTHY" || inspection.statePointer === null || inspection.workflowState === null || inspection.revision === null || inspection.transitionCommit === null) {
    return refused(runId, inspection.workflowState, "RESUME_REFUSED_STATE_STORE");
  }
  const state = inspection.workflowState;
  if (state.phase === "PASS" || state.phase === "BLOCKED") return refused(runId, state, "RESUME_REFUSED_TERMINAL");
  if (state.execution_mode !== "STATIC_APPROVED_DAG") return refused(runId, state, "RESUME_REFUSED_EXECUTION_AUTHORITY");

  let records: Awaited<ReturnType<typeof readM5ManagedRecords>>;
  try { records = await readM5ManagedRecords(location); }
  catch { return refused(runId, state, "RESUME_REFUSED_STATE_STORE"); }
  const baseline = baselineForState(state, records);
  if (baseline === undefined || !authoritative(inspection.managedRecordClassifications, "M3_BASELINE", baseline.content_sha256) ||
    (baseline.baseline_mode === "APPROVED_BASELINE_DIRTY" && !authoritative(inspection.managedRecordClassifications, "M3_BASELINE_APPROVAL", state.identities.baseline_approval_sha256))) {
    return refused(runId, state, "RESUME_REFUSED_BASELINE_AUTHORITY");
  }
  if (inspection.managedRecordClassifications.some((entry) => (entry.classification === "INVALID_MANAGED_RECORD" || entry.classification === "UNCOMMITTED_BASELINE_PUBLICATION") &&
    entry.object.kind !== "M3_BASELINE" && entry.object.kind !== "M3_BASELINE_APPROVAL" && entry.object.kind !== "M3_BASELINE_BLOB" && entry.object.kind !== "M2_STATIC_TIME_AUTHORITY")) {
    return refused(runId, state, "RESUME_REFUSED_STATE_STORE");
  }
  const authority = executionAuthorityComplete(state, records, inspection.managedRecordClassifications);
  if (authority === null) return refused(runId, state, "RESUME_REFUSED_EXECUTION_AUTHORITY");
  if (state.execution_mode === "STATIC_APPROVED_DAG") {
    // V1-R2D-TIME: applicable durable timing must resolve and be unexpired.
    // Read-only: never mutates M2 and never creates timing records. A READY state
    // without a NODE authority is not invalid here; a legacy started run without
    // any WORKFLOW timing authority refuses timing eligibility (not STATE_STORE).
    const verdicts = staticTimingVerdicts(inspection.managedRecordClassifications);
    const timing = resolveApplicableResumeTiming({
      runId, state,
      tipCommit: inspection.transitionCommit,
      records: {
        transitionCommits: records.transitionCommits,
        workflowStates: records.workflowStates,
        transitionEvents: records.transitionEvents,
        authorities: records.staticTimeAuthorities,
      },
      verdicts,
      nowMs: sampleWallClockMs(),
    });
    if (timing.outcome === "REFUSED") return refused(runId, state, "RESUME_REFUSED_TIMING_AUTHORITY");
  }
  const r2ePoint = deriveStaticDagR2EResumePoint(state, inspection.transitionCommit, records, inspection.managedRecordClassifications);
  const preProviderPoint = deriveStaticDagPreProviderResumePoint(state, authority.policy, records, inspection.managedRecordClassifications, inspection.transitionCommit);
  if (r2ePoint === null && preProviderPoint === null && !settledOperations(records, inspection.managedRecordClassifications)) return refused(runId, state, "RESUME_REFUSED_IN_FLIGHT_OPERATION");

  const authoritativeTokens = records.stateTokens.filter((token) => authoritative(inspection.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", token.content_sha256));
  const token = tokenTip(authoritativeTokens);
  if (token === null || token.baseline_runtime_content_sha256 !== authority.baseline.content_sha256) return refused(runId, state, "RESUME_REFUSED_BASELINE_AUTHORITY");
  try {
    await loadAuthoritativeToken(location, token, authority.baseline);
  } catch {
    return refused(runId, state, "RESUME_REFUSED_BASELINE_AUTHORITY");
  }
  let currentRepository: Awaited<ReturnType<typeof resolveRepositoryIdentity>>;
  try {
    currentRepository = await resolveRepositoryIdentity({ requestedPath: authority.baseline.repository.worktree_root, requireHead: true });
    assertRepositoryMatches(authority.baseline.repository, currentRepository);
  } catch {
    return refused(runId, state, "RESUME_REFUSED_REPOSITORY_IDENTITY");
  }
  if (requireQuiescence) {
    try {
      if (await probeWorktreeLockAvailability({ stateRoot: location.stateRoot, repository: currentRepository }) !== "LOCK_AVAILABLE") {
        return refused(runId, state, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
      }
    } catch {
      return refused(runId, state, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
  }
  try {
    const currentFingerprint = await captureGitState(currentRepository);
    assertNoGitBlockers(currentFingerprint);
    if (canonicalize(currentFingerprint) !== canonicalize(token.git_fingerprint)) return refused(runId, state, "RESUME_REFUSED_STATE_DRIFT");
  } catch {
    return refused(runId, state, "RESUME_REFUSED_REPOSITORY_IDENTITY");
  }
  const resumePoint = r2ePoint ?? preProviderPoint ?? deriveStaticDagResumePoint(state, authority.policy);
  if (resumePoint === null) return refused(runId, state, "RESUME_REFUSED_AMBIGUOUS_RESUME_POINT");
  if (r2ePoint === null && preProviderPoint === null && hasSelectedLeafWorkerEvidence(resumePoint, state, authority.policy, records)) return refused(runId, state, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
  return report("RESUMABLE", runId, state.phase, resumePoint, null);
}


/** Observational V1-R1 inspection; it probes and releases kernel flock availability. */
export async function inspectDeterministicResumeEligibility(input: ResumeInspectionInput): Promise<ResumeEligibilityReport> {
  return inspectDeterministicResumeEligibilityInternal(input, true);
}

/** V1-R2A uses this only after it owns the matching M3 WorktreeLock. */
export async function revalidateDeterministicResumeEligibilityWhileLocked(input: ResumeInspectionInput): Promise<ResumeEligibilityReport> {
  return inspectDeterministicResumeEligibilityInternal(input, false);
}

export async function loadDeterministicResumeLockTarget(input: ResumeInspectionInput): Promise<DeterministicResumeLockTarget> {
  if (!isAbsolute(input.retainedRunRoot)) throw new Error("retained run root must be absolute");
  const root = await realpath(input.retainedRunRoot);
  const runs = (await readdir(join(root, "state", "runs"), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  if (runs.length !== 1) throw new Error("retained run must contain exactly one run");
  const runId = runs[0]!; const stateRoot = join(root, "state");
  const inspection = await inspectRunStorage({ stateRoot, runId });
  if (inspection.status !== "HEALTHY" || inspection.workflowState === null) throw new Error("retained run state is not healthy");
  const records = await readM5ManagedRecords({ stateRoot, runId });
  const baseline = baselineForState(inspection.workflowState, records);
  if (baseline === undefined) throw new Error("retained run baseline is unavailable");
  return Object.freeze({ stateRoot, runId, repository: baseline.repository });
}
