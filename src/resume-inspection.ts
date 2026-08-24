import { realpath, readdir } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { canonicalize } from "./canonical-json/index.js";
import { inspectRunStorage } from "./persistence/index.js";
import { readM5ManagedRecords } from "./persistence/store.js";
import { assertNoGitBlockers, assertRepositoryMatches } from "./repository/preflight.js";
import { captureGitState } from "./repository/fingerprint.js";
import { resolveRepositoryIdentity } from "./repository/index.js";
import { loadAuthoritativeToken } from "./repository/token-provenance.js";
import type { ManagedRecordClassification } from "./persistence/types.js";
import type { M3BaselineRuntimeDocument, M3RepositoryStateTokenDocument, ReducerPolicy, WorkflowState } from "./schemas/index.js";

export type ResumeRefusalReason =
  | "RESUME_REFUSED_TERMINAL"
  | "RESUME_REFUSED_STATE_STORE"
  | "RESUME_REFUSED_REPOSITORY_IDENTITY"
  | "RESUME_REFUSED_STATE_DRIFT"
  | "RESUME_REFUSED_BASELINE_AUTHORITY"
  | "RESUME_REFUSED_EXECUTION_AUTHORITY"
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

function tokenTip(tokens: readonly M3RepositoryStateTokenDocument[]): M3RepositoryStateTokenDocument | null {
  const predecessors = new Set(tokens.map((token) => token.prior_token_content_sha256).filter((value): value is string => value !== null));
  const tips = tokens.filter((token) => !predecessors.has(token.content_sha256));
  return tips.length === 1 ? tips[0]! : null;
}

/** The only V1-R1 supported point is a reducer-settled static DAG ready-leaf boundary. */
export function deriveStaticDagResumePoint(state: WorkflowState, policy: ReducerPolicy): string | null {
  if (state.execution_mode !== "STATIC_APPROVED_DAG" || state.phase !== "READY" || state.active_task_id !== null) return null;
  const complete = new Set(state.tasks.filter((task) => task.status === "PASS").map((task) => task.task_id));
  const candidates = policy.tasks.filter((task) => state.tasks.some((runtime) => runtime.task_id === task.task_id && runtime.status === "PENDING") &&
    task.dependencies.every((dependency) => complete.has(dependency)))
    .sort((left, right) => left.topological_rank - right.topological_rank || left.priority - right.priority || left.task_id.localeCompare(right.task_id));
  return candidates.length > 0 ? `STATIC_DAG_SELECT_READY_LEAF:${candidates[0]!.task_id}` : null;
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
  const baseline = exactOne(records.baselines, state.identities.baseline_approval_sha256) ??
    records.baselines.find((entry) => entry.baseline_mode === "APPROVED_BASELINE_DIRTY" &&
      records.approvals.some((approval) => approval.content_sha256 === state.identities.baseline_approval_sha256 && approval.baseline_runtime_content_sha256 === entry.content_sha256)) ?? null;
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

/**
 * Read-only eligibility inspection. It deliberately neither acquires an M3 lock nor publishes
 * records: this report is proof about current retained authority, not a resume operation.
 */
export async function inspectDeterministicResumeEligibility(input: ResumeInspectionInput): Promise<ResumeEligibilityReport> {
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
  const baseline = exactOne(records.baselines, state.identities.baseline_approval_sha256) ?? records.baselines.find((entry) =>
    entry.baseline_mode === "APPROVED_BASELINE_DIRTY" && records.approvals.some((approval) =>
      approval.content_sha256 === state.identities.baseline_approval_sha256 && approval.baseline_runtime_content_sha256 === entry.content_sha256));
  if (baseline === undefined || !authoritative(inspection.managedRecordClassifications, "M3_BASELINE", baseline.content_sha256) ||
    (baseline.baseline_mode === "APPROVED_BASELINE_DIRTY" && !authoritative(inspection.managedRecordClassifications, "M3_BASELINE_APPROVAL", state.identities.baseline_approval_sha256))) {
    return refused(runId, state, "RESUME_REFUSED_BASELINE_AUTHORITY");
  }
  if (inspection.managedRecordClassifications.some((entry) => (entry.classification === "INVALID_MANAGED_RECORD" || entry.classification === "UNCOMMITTED_BASELINE_PUBLICATION") &&
    entry.object.kind !== "M3_BASELINE" && entry.object.kind !== "M3_BASELINE_APPROVAL" && entry.object.kind !== "M3_BASELINE_BLOB")) {
    return refused(runId, state, "RESUME_REFUSED_STATE_STORE");
  }
  const authority = executionAuthorityComplete(state, records, inspection.managedRecordClassifications);
  if (authority === null) return refused(runId, state, "RESUME_REFUSED_EXECUTION_AUTHORITY");
  if (!settledOperations(records, inspection.managedRecordClassifications)) return refused(runId, state, "RESUME_REFUSED_IN_FLIGHT_OPERATION");

  const authoritativeTokens = records.stateTokens.filter((token) => authoritative(inspection.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", token.content_sha256));
  const token = tokenTip(authoritativeTokens);
  if (token === null || token.baseline_runtime_content_sha256 !== authority.baseline.content_sha256) return refused(runId, state, "RESUME_REFUSED_BASELINE_AUTHORITY");
  try {
    await loadAuthoritativeToken(location, token, authority.baseline);
  } catch {
    return refused(runId, state, "RESUME_REFUSED_BASELINE_AUTHORITY");
  }
  try {
    const currentRepository = await resolveRepositoryIdentity({ requestedPath: authority.baseline.repository.worktree_root, requireHead: true });
    assertRepositoryMatches(authority.baseline.repository, currentRepository);
    const currentFingerprint = await captureGitState(currentRepository);
    assertNoGitBlockers(currentFingerprint);
    if (canonicalize(currentFingerprint) !== canonicalize(token.git_fingerprint)) return refused(runId, state, "RESUME_REFUSED_STATE_DRIFT");
  } catch {
    return refused(runId, state, "RESUME_REFUSED_REPOSITORY_IDENTITY");
  }
  const resumePoint = deriveStaticDagResumePoint(state, authority.policy);
  return resumePoint === null
    ? refused(runId, state, "RESUME_REFUSED_AMBIGUOUS_RESUME_POINT")
    : report("RESUMABLE", runId, state.phase, resumePoint, null);
}
