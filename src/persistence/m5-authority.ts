import { canonicalize } from "../canonical-json/index.js";
import { evaluateAuthority } from "../control/evaluate.js";
import type { M5AuthoritativeSources } from "../control/types.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { assertDocumentValid, type M4CommandCatalogDocument, type M4ScopedToolPolicyDocument, type M5ControlDecisionDocument, type M5ControlPolicyDocument, type M5UsageEvidenceDocument, type ReducerPolicy, type WorkflowState } from "../schemas/index.js";
import type { InspectedObject, ManagedRecordClassification, StoredObjectKind } from "./types.js";

export interface M5AuthorityInput {
  readonly runId: string;
  readonly workflowState: WorkflowState;
  readonly workflowStates: ReadonlyMap<string, WorkflowState>;
  readonly objects: readonly InspectedObject[];
  readonly priorClassifications: readonly ManagedRecordClassification[];
  readonly policies: ReadonlyMap<string, M5ControlPolicyDocument>;
  readonly usage: ReadonlyMap<string, M5UsageEvidenceDocument>;
  readonly decisions: ReadonlyMap<string, M5ControlDecisionDocument>;
  readonly reducerPolicies?: ReadonlyMap<string, ReducerPolicy>;
  readonly m4Policies?: ReadonlyMap<string, M4ScopedToolPolicyDocument>;
  readonly m4Catalogs?: ReadonlyMap<string, M4CommandCatalogDocument>;
  readonly authoritativeSources?: M5AuthoritativeSources;
  readonly reachableRawEvidence: ReadonlySet<string>;
  readonly typedTransitionDecisionDigests?: ReadonlySet<string>;
  readonly runAuthorityValidatedPolicyDigests?: ReadonlySet<string>;
  readonly committedWorkflowStateDigests?: ReadonlySet<string>;
}

type Class = ManagedRecordClassification["classification"];
type Walk = "VALID" | "INCOMPLETE" | "INVALID";
const AUTHORITATIVE: Class = "AUTHORITATIVE_MANAGED_RECORD";
const UNREFERENCED: Class = "UNREFERENCED_MANAGED_RECORD";
const INCOMPLETE: Class = "INCOMPLETE_MANAGED_RECORD_CHAIN";
const INVALID: Class = "INVALID_MANAGED_RECORD";
function key(kind: StoredObjectKind, digest: string): string { return `${kind}:${digest}`; }
function compare(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
function obligationGrammarMatches(grammar: M5ControlPolicyDocument["obligations"][number]["grammar"], value: string, literal: string | null, prefix: string | null): boolean {
  if (grammar === "HEX") return /^[0-9a-f]+$/u.test(value);
  if (grammar === "UUID") return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab0-9a-f][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value);
  if (grammar === "INTEGER") return /^(?:0|[1-9][0-9]*)$/u.test(value) && Number.isSafeInteger(Number(value));
  if (grammar === "LITERAL") return value === literal;
  if (grammar === "PREFIXED_LITERAL") return prefix !== null && literal !== null && value === `${prefix}${literal}`;
  return value.length > 0 && !value.startsWith("/") && !value.includes("\\") && !value.split("/").some((part) => part === "" || part === "." || part === "..");
}
function result(object: InspectedObject, classification: Class, detail: string): ManagedRecordClassification { return { object, classification, detail }; }
function canonicalBytes(value: unknown): Buffer { return Buffer.from(`${canonicalize(value)}\n`, "utf8"); }

const FAILURE_ACTION: Readonly<Record<string, string>> = Object.freeze({
  TRANSIENT_TOOL_FAILURE: "RETRY_TRANSIENT_TOOL_ONCE", LOCAL_IMPLEMENTATION_DEFECT: "SECOND_LUNA_ATTEMPT",
  COMMAND_CONTRACT_ERROR: "CORRECT_COMMAND_ONCE", CONTEXT_MISSING: "RESTORE_CONTEXT_ONCE", PLAN_INCORRECT: "CONSTRAINED_REPLAN",
  AUTHORITY_CONTRADICTION: "REQUEST_OWNER_DECISION", SAME_FAILURE_TWICE: "CONSTRAINED_REPLAN",
  SCOPE_EXPANSION_REQUIRED: "BLOCK", STATE_DRIFT: "BLOCK", CONCURRENT_WRITER: "BLOCK", TEST_INTEGRITY_VIOLATION: "BLOCK",
  CLEANUP_UNCERTAIN: "BLOCK", CLOSEOUT_DEFECT: "BLOCK", PROCESS_CRASH: "BLOCK", MODEL_UNAVAILABLE: "BLOCK",
  BUDGET_EXHAUSTED: "BLOCK", CONTRACT_UNSATISFIABLE: "BLOCK", ROUTE_UNAVAILABLE: "BLOCK", CAPABILITY_UNAVAILABLE: "BLOCK",
  MUTATION_UNCERTAIN: "BLOCK", EVIDENCE_INVALID: "BLOCK", EVIDENCE_PUBLICATION_FAILURE: "BLOCK", STATE_PUBLICATION_FAILURE: "BLOCK", INTERNAL_CONTROL_ERROR: "BLOCK",
});
const CONTINUATIONS = ["CONTINUE_ADMITTED_OPERATION", "RETRY_TRANSIENT_TOOL_ONCE", "SECOND_LUNA_ATTEMPT", "CORRECT_COMMAND_ONCE", "RESTORE_CONTEXT_ONCE", "CONSTRAINED_REPLAN", "RUN_RESERVED_CLOSEOUT", "REQUEST_OWNER_DECISION", "BLOCK"];

function architectureWorkerLimit(policy: M5ControlPolicyDocument, state: WorkflowState): number {
  if (state.execution_mode === "DIRECT_LUNA_HIGH") return 2;
  if (state.execution_mode === "SINGLE_OWNER_SOL") return 1;
  return Math.min(20, 2 * policy.route_facts.leaf_count + 4);
}

function decisionSemanticError(value: M5ControlDecisionDocument, policy: M5ControlPolicyDocument, state: WorkflowState): string | null {
  if (value.run_id !== policy.run_id || value.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 || value.worktree_key !== policy.worktree_key ||
      value.policy_content_sha256 !== policy.content_sha256 || value.objective_sha256 !== policy.objective_sha256 || value.contract_sha256 !== policy.contract_sha256 ||
      value.budget_sha256 !== policy.budget_sha256 || value.route_map_sha256 !== policy.route_map_sha256 || value.route_map_approval_sha256 !== policy.route_map_approval_sha256 ||
      value.reducer_policy_content_sha256 !== policy.reducer_policy_content_sha256 || value.scope_sha256 !== policy.scope_sha256 || value.acceptance_sha256 !== policy.acceptance_sha256 ||
      value.tool_policy_content_sha256 !== policy.tool_policy_content_sha256 || value.command_catalog_content_sha256 !== policy.command_catalog_content_sha256) return "M5 decision frozen identity differs from policy";
  for (const failure of value.failures) {
    if (FAILURE_ACTION[failure.control_class] !== failure.action) return "Failure action differs from the fixed M5 table";
    const { failure_identity: _identity, ...projection } = failure;
    if (failure.failure_identity !== sha256Canonical(projection)) return "Failure identity is false";
  }
  if (canonicalize(value.progress.evidence_content_sha256) !== canonicalize([...value.progress.evidence_content_sha256].sort(compare)) ||
      value.progress.evidence_set_sha256 !== sha256Canonical(value.progress.evidence_content_sha256)) return "Progress evidence set identity is false";
  const descriptors = new Set(policy.obligations.map((entry) => entry.descriptor_sha256));
  for (const evidence of value.obligation_evidence ?? []) {
    const descriptor = policy.obligations.find((entry) => entry.descriptor_sha256 === evidence.descriptor_sha256);
    if (descriptor === undefined || !obligationGrammarMatches(descriptor.grammar, evidence.value, descriptor.literal, descriptor.prefix)) return "Obligation evidence is not an exact policy-bound value";
  }
  const satisfied = new Set(value.contract_gate.satisfied_obligation_descriptor_sha256);
  const pending = new Set(value.contract_gate.pending_obligation_descriptor_sha256);
  if ([...satisfied].some((digest) => pending.has(digest)) || [...descriptors].some((digest) => !satisfied.has(digest) && !pending.has(digest)) || [...satisfied, ...pending].some((digest) => !descriptors.has(digest))) return "Contract-gate obligation partition differs from policy";
  const detectionCodes = value.contract_gate.detections.map((entry) => entry.code);
  if (new Set(detectionCodes).size !== detectionCodes.length || canonicalize(detectionCodes) !== canonicalize([...detectionCodes].sort(compare))) return "Contract-gate detections are not a unique sorted set";
  const expectedGate = value.contract_gate.status === "INSUFFICIENT_AUTHORITY" ? "INSUFFICIENT_AUTHORITY"
    : value.contract_gate.detections.length > 0
      ? value.contract_gate.detections.some((entry) => entry.code === "ROUTE_UNAVAILABLE" || entry.code === "VERIFICATION_COMMAND_UNAVAILABLE") ? "CURRENTLY_BLOCKED" : "UNSATISFIABLE"
      : pending.size === 0 ? "SATISFIED" : "SATISFIABLE";
  if (value.contract_gate.status !== expectedGate) return "Contract-gate status differs from detections and obligations";
  const budgetDimensions = value.budget.map((entry) => entry.dimension);
  if (new Set(budgetDimensions).size !== policy.limits.length || policy.limits.some((entry) => !budgetDimensions.includes(entry.dimension))) return "Budget dimension inventory differs from policy";
  for (const entry of value.budget) {
    if (!Number.isSafeInteger(entry.validated_amount + entry.observed_reported_amount + entry.active_reservation_amount)) return "Budget charged arithmetic overflows";
  }
  if (value.decision_kind === "INITIAL_MODE") {
    if (value.intent !== "SELECT_ROUTE" || canonicalize(value.routes.map((entry) => entry.route).sort()) !== canonicalize(["DIRECT_LUNA_HIGH", "ROUTED_DAG", "SINGLE_OWNER_SOL"])) return "Initial route inventory or intent is invalid";
  } else if (canonicalize(value.routes.map((entry) => entry.route).sort()) !== canonicalize([...CONTINUATIONS].sort())) return "Continuation route inventory is invalid";
  if (value.outcome === "BLOCK" && value.reservation !== null) return "Blocked decision retains an active reservation";
  if (value.reservation !== null) {
    if (value.intent !== "AUTHORIZE_WORK" || value.outcome !== "AUTHORIZE" || value.reservation.status !== "ACTIVE" || value.reservation.reconciliation_evidence_content_sha256 !== null ||
        value.reservation.reserved_state_content_sha256 !== value.current_state_content_sha256 || value.reservation.reserved_policy_content_sha256 !== policy.content_sha256 ||
        value.reservation.reserved_route !== state.execution_mode || value.reservation.future_operation_id === undefined || value.reservation.source_envelope_index < 0 ||
        value.reservation.source_envelope_index >= policy.role_reservation_envelopes.length) return "Reservation lifecycle or binding is false";
    const envelope = policy.role_reservation_envelopes[value.reservation.source_envelope_index]!;
    if (envelope.logical_role !== value.reservation.logical_role || envelope.purpose !== value.reservation.purpose || canonicalize(envelope.amounts) !== canonicalize(value.reservation.amounts)) return "Reservation envelope is false";
    const expectedRole = value.current_state_content_sha256 === state.content_sha256
      ? state.phase === "READY" ? "SOL_CLOSEOUT" : state.phase === "REPLAN_REQUIRED" ? "SOL_REPLAN" : state.phase === "SINGLE_OWNER_FAST_PREFLIGHT" ? "SOL_OWNER"
        : state.phase === "ROUTE_SELECTED" ? state.execution_mode === "ROUTED_DAG" ? "SOL_PLANNER" : state.execution_mode === "SINGLE_OWNER_SOL" ? "SOL_OWNER" : "LUNA_EXECUTOR"
          : "LUNA_EXECUTOR"
      : null;
    if (expectedRole !== null && value.reservation.logical_role !== expectedRole) return "Reservation role is false for the current phase";
  }
  if (value.transition_event !== null && value.predicted_next_state_content_sha256 === null) return "Transition prediction is absent";
  if (value.outcome === "PASS" && value.predicted_next_state_content_sha256 === null) return "PASS has no predicted committed terminal state";
  if ((value.outcome === "BLOCK") !== (value.transition_event?.event_type === "BLOCK")) return "Block outcome and transition event differ";
  if (value.intent === "SELECT_ROUTE" && value.transition_event !== null && (value.transition_event.event_type !== "SELECT_ROUTE" || value.transition_event.payload["execution_mode"] !== value.selected_route)) return "Route transition payload is false";
  if (value.intent === "VALIDATE_CONTRACT" && value.transition_event !== null && value.transition_event.event_type !== "VALIDATE_CONTRACT") return "Contract transition event is false";
  const reservationIdentity = value.reservation === null ? null : {
    logical_role: value.reservation.logical_role, purpose: value.reservation.purpose, future_operation_id: value.reservation.future_operation_id ?? null,
    reserved_state_content_sha256: value.reservation.reserved_state_content_sha256 ?? null, reserved_policy_content_sha256: value.reservation.reserved_policy_content_sha256 ?? null,
    reserved_route: value.reservation.reserved_route ?? null, amounts: value.reservation.amounts, source_envelope_index: value.reservation.source_envelope_index,
  };
  const expectedKey = sha256Canonical({ run_id: policy.run_id, state: value.current_state_content_sha256, intent: value.intent,
    usage: [...value.usage_evidence_content_sha256].sort(compare), failures: value.failures.map((entry) => entry.failure_identity), gate: value.contract_gate,
    progress: value.progress, selected_route: value.selected_route, reservation: reservationIdentity, request_key: value.request_key ?? null,
    prior: value.prior_relevant_decision_content_sha256 });
  if (value.decision_key !== expectedKey) return "Decision key differs from exact authority projection";
  return null;
}

function deterministicRecalculationError(
  value: M5ControlDecisionDocument,
  policy: M5ControlPolicyDocument,
  state: WorkflowState,
  reducerPolicy: ReducerPolicy,
  input: M5AuthorityInput,
): string | null {
  const chain: M5ControlDecisionDocument[] = [];
  const seen = new Set<string>();
  let cursor = value.prior_relevant_decision_content_sha256;
  while (cursor !== null) {
    if (seen.has(cursor)) return "M5 decision predecessor chain is cyclic";
    seen.add(cursor);
    const prior = input.decisions.get(cursor);
    if (prior === undefined) return "M5 decision predecessor is missing";
    chain.unshift(prior);
    cursor = prior.prior_relevant_decision_content_sha256;
  }
  const progressEvidence = value.progress.classification === "PROGRESS" || value.progress.evidence_content_sha256.length > 0 ? {
    ...(value.progress.kind === null ? {} : { claimedKind: value.progress.kind }),
    ...(value.progress.no_progress_reason === null ? {} : { noProgressReason: value.progress.no_progress_reason }),
    evidenceContentSha256: value.progress.evidence_content_sha256 as readonly Sha256Digest[],
    ...(value.progress.prior_state_or_decision_content_sha256 === null ? {} : { priorStateOrDecisionContentSha256: value.progress.prior_state_or_decision_content_sha256 as Sha256Digest }),
    ...(value.progress.prior_failure_signature === null ? {} : { priorFailureSignature: value.progress.prior_failure_signature as Sha256Digest }),
    ...(value.progress.current_failure_signature === null ? {} : { currentFailureSignature: value.progress.current_failure_signature as Sha256Digest }),
  } : undefined;
  const persistedSources: M5AuthoritativeSources = {
    ...(input.m4Policies?.get(policy.tool_policy_content_sha256) === undefined ? {} : { m4ToolPolicy: input.m4Policies.get(policy.tool_policy_content_sha256)! }),
    ...(input.m4Catalogs?.get(policy.command_catalog_content_sha256) === undefined ? {} : { m4CommandCatalog: input.m4Catalogs.get(policy.command_catalog_content_sha256)! }),
    ...(input.authoritativeSources ?? {}),
  };
  const requestedM4ResultIds = new Set([
    ...value.obligation_evidence.map((entry) => entry.evidence_content_sha256),
    ...value.progress.evidence_content_sha256,
  ]);
  const requestSources: M5AuthoritativeSources = {
    ...(persistedSources.contract === undefined ? {} : { contract: persistedSources.contract }),
    ...(persistedSources.budget === undefined ? {} : { budget: persistedSources.budget }),
    ...(persistedSources.m4ToolPolicy === undefined ? {} : { m4ToolPolicy: persistedSources.m4ToolPolicy }),
    ...(persistedSources.m4CommandCatalog === undefined ? {} : { m4CommandCatalog: persistedSources.m4CommandCatalog }),
    ...(persistedSources.routeMap === undefined ? {} : { routeMap: persistedSources.routeMap }),
    ...(persistedSources.routeMapApproval === undefined ? {} : { routeMapApproval: persistedSources.routeMapApproval }),
    m4CommandResults: (persistedSources.m4CommandResults ?? []).filter((entry) => requestedM4ResultIds.has(entry.content_sha256)),
    m3StateTokens: persistedSources.m3StateTokens ?? [],
    m3Postflights: persistedSources.m3Postflights ?? [],
  };
  const requestBase = {
    intent: value.intent,
    expectedRevision: 0,
    expectedStatePointerContentSha256: state.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest,
    ...(value.transition_id === undefined ? {} : { transitionId: value.transition_id }),
    ...(value.operation_id === null ? {} : { operationId: value.operation_id }),
    usageEvidence: [...value.usage_evidence_content_sha256].map((digest) => input.usage.get(digest)).filter((entry): entry is M5UsageEvidenceDocument => entry !== undefined),
    ...(progressEvidence === undefined ? {} : { progressEvidence }),
    failures: value.failures.map((failure) => ({ sourceLayer: failure.source_layer, sourceErrorCode: failure.source_error_code,
      sourceRecordContentSha256: failure.source_record_content_sha256 as Sha256Digest, normalizedSignature: failure.normalized_signature as Sha256Digest,
      ...(failure.operation_id === undefined ? {} : { operationId: failure.operation_id }),
      ...(failure.scope_identity === undefined ? {} : { scopeIdentity: failure.scope_identity as Sha256Digest }),
      ...(failure.path_identity === undefined ? {} : { pathIdentity: failure.path_identity as Sha256Digest }),
      ...(failure.repository_identity === undefined ? {} : { repositoryIdentity: failure.repository_identity as Sha256Digest }),
      ...(failure.worktree_key === undefined ? {} : { worktreeKey: failure.worktree_key as Sha256Digest }),
      ...(failure.resolution_evidence_content_sha256 === null ? {} : { resolutionEvidenceContentSha256: failure.resolution_evidence_content_sha256 as Sha256Digest }) })),
    obligationEvidence: value.obligation_evidence.map((entry) => ({ descriptorSha256: entry.descriptor_sha256 as Sha256Digest, value: entry.value, evidenceContentSha256: entry.evidence_content_sha256 as Sha256Digest })),
    availableLogicalRoles: value.available_logical_roles,
    authoritativeSources: requestSources,
  } as const;
  const requests = value.intent === "BLOCK" && value.blocking_reason !== null
    ? [requestBase, { ...requestBase, blockReason: value.blocking_reason }]
    : [requestBase];
  try {
    let mismatch: string | undefined;
    let failure: string | undefined;
    for (const request of requests) {
      try {
        const expected = evaluateAuthority({ policy, state, reducerPolicy, request, persistedUsage: [], priorDecisions: chain, authoritativeSources: persistedSources });
        if (canonicalize(expected) === canonicalize(value)) return null;
        mismatch = "Stored M5 decision differs from complete deterministic recalculation";
        for (const field of Object.keys(expected) as (keyof M5ControlDecisionDocument)[]) {
          if (canonicalize(expected[field]) !== canonicalize(value[field])) {
            mismatch = `Stored M5 decision field ${String(field)} differs from deterministic recalculation`;
            break;
          }
        }
      } catch (error: unknown) {
        failure = `Deterministic M5 recalculation failed: ${error instanceof Error ? error.message : String(error)}`;
      }
    }
    return mismatch ?? failure ?? "Deterministic M5 recalculation produced no candidate";
  } catch (error: unknown) {
    return `Deterministic M5 recalculation failed: ${error instanceof Error ? error.message : String(error)}`;
  }
}

export function classifyM5Authority(input: M5AuthorityInput): readonly ManagedRecordClassification[] {
  const objects = new Map(input.objects.map((object) => [key(object.kind, object.contentSha256), object]));
  const objectsByDigest = new Map<string, InspectedObject[]>();
  for (const object of input.objects) objectsByDigest.set(object.contentSha256, [...(objectsByDigest.get(object.contentSha256) ?? []), object]);
  const predecessor = new Map(input.priorClassifications.map((entry) => [key(entry.object.kind, entry.object.contentSha256), entry.classification]));
  const results = new Map<string, ManagedRecordClassification>();
  const validPolicies = new Set<string>();
  const duplicatePolicyContext = new Map<string, number>();
  for (const policy of input.policies.values()) {
    const context = `${policy.run_id}:${policy.starting_state_content_sha256}`;
    duplicatePolicyContext.set(context, (duplicatePolicyContext.get(context) ?? 0) + 1);
  }
  for (const [digest, policy] of input.policies) {
    const object = objects.get(key("M5_CONTROL_POLICY", digest));
    if (object === undefined) continue;
    let structurallyValid = true;
    try { assertDocumentValid("pi_gacw_m5_control_policy_v0", policy); } catch { structurallyValid = false; }
    const context = `${policy.run_id}:${policy.starting_state_content_sha256}`;
    const genesis = input.workflowStates.get(policy.starting_state_content_sha256);
    if (!structurallyValid || policy.content_sha256 !== digest || policy.run_id !== input.runId || (duplicatePolicyContext.get(context) ?? 0) !== 1 || genesis?.phase !== "CREATED" ||
        policy.objective_sha256 !== input.workflowState.identities.objective_sha256 || policy.contract_sha256 !== input.workflowState.identities.contract_sha256 ||
        policy.budget_sha256 !== input.workflowState.identities.budget_sha256 || policy.scope_sha256 !== input.workflowState.identities.scope_sha256 ||
        policy.acceptance_sha256 !== input.workflowState.identities.acceptance_sha256 || policy.reducer_policy_content_sha256 !== input.workflowState.frozen_policy_content_sha256) {
      results.set(key(object.kind, digest), result(object, INVALID, "M5 policy contradicts run, state, or unique policy authority"));
    } else {
      validPolicies.add(digest);
      results.set(key(object.kind, digest), result(object, UNREFERENCED, "Valid M5 policy has no authoritative decision edge"));
    }
  }

  const usageWalk = new Map<string, Walk>();
  const operationGroups = new Map<string, M5UsageEvidenceDocument[]>();
  for (const value of input.usage.values()) operationGroups.set(`${value.run_id}:${value.operation_id}`, [...(operationGroups.get(`${value.run_id}:${value.operation_id}`) ?? []), value]);
  for (const [digest, value] of input.usage) {
    const object = objects.get(key("M5_USAGE_EVIDENCE", digest));
    if (object === undefined) continue;
    const group = operationGroups.get(`${value.run_id}:${value.operation_id}`)!;
    const conflict = new Set(group.map((item) => canonicalize(item))).size > 1;
    let structurallyValid = true;
    try { assertDocumentValid("pi_gacw_m5_usage_evidence_v0", value); } catch { structurallyValid = false; }
    const sourceObjects = objectsByDigest.get(value.source_record_content_sha256) ?? [];
    const sourceClasses = sourceObjects.map((candidate) => predecessor.get(key(candidate.kind, candidate.contentSha256)));
    const expectedLayer: Readonly<Partial<Record<StoredObjectKind, M5UsageEvidenceDocument["source_layer"]>>> = {
      WORKFLOW_STATE: "M1", TRANSITION_EVENT: "M1", TRANSITION_COMMIT: "M2", M3_REPOSITORY_STATE_TOKEN: "M3", M3_POSTFLIGHT: "M3",
      M4_TOOL_POLICY: "M4", M4_COMMAND_CATALOG: "M4", M4_COMMAND_RESULT: "M4", M5_CONTROL_POLICY: "M5", M5_CONTROL_DECISION: "M5",
    };
    const exactSource = sourceObjects.some((candidate) => candidate.kind === value.source_kind && expectedLayer[candidate.kind] === value.source_layer);
    const committedStates = input.committedWorkflowStateDigests ?? new Set([input.workflowState.content_sha256]);
    const validOrigin = committedStates.has(value.originating_state_content_sha256);
    const sourceInvalid = sourceClasses.includes(INVALID);
    const sourceIsM5 = sourceObjects.some((candidate) => candidate.kind === "M5_CONTROL_POLICY" || candidate.kind === "M5_CONTROL_DECISION");
    let walk: Walk = "VALID";
    let detail = "Valid M5 usage has no authoritative decision edge";
    if (!structurallyValid || value.content_sha256 !== digest || value.run_id !== input.runId || !validPolicies.has(value.policy_content_sha256) || conflict || sourceInvalid || !exactSource || !validOrigin) { walk = "INVALID"; detail = "M5 usage has conflicting operation, state, policy, source-kind, or source-layer authority"; }
    else if (sourceObjects.length === 0) { walk = "INCOMPLETE"; detail = "M5 usage source record is missing"; }
    else if (!sourceIsM5 && sourceClasses.every((classification) => classification === undefined || classification === INCOMPLETE)) { walk = "INCOMPLETE"; detail = "M5 usage source authority is incomplete"; }
    usageWalk.set(digest, walk);
    results.set(key(object.kind, digest), result(object, walk === "INVALID" ? INVALID : walk === "INCOMPLETE" ? INCOMPLETE : UNREFERENCED, detail));
  }

  const decisionGroups = new Map<string, M5ControlDecisionDocument[]>();
  for (const value of input.decisions.values()) decisionGroups.set(value.decision_key, [...(decisionGroups.get(value.decision_key) ?? []), value]);
  // Traversal validity is root-relative. The cache key must retain the current depth and
  // expected predecessor kind; identity-only memoization would let a shallow root
  // authorize the same record when reached through a deeper path.
  const memo = new Map<string, Walk>();
  const rootWalk = new Map<string, Walk>();
  const detailByDecision = new Map<string, string>();
  const memoKey = (digest: string, depth: number, expectedKind: StoredObjectKind): string => `${expectedKind}:${digest}:${depth}`;
  const visit = (digest: string, stack: readonly string[], depth: number, expectedKind: StoredObjectKind = "M5_CONTROL_DECISION"): Walk => {
    const cacheKey = memoKey(digest, depth, expectedKind);
    const priorMemo = memo.get(cacheKey); if (priorMemo !== undefined) return priorMemo;
    const value = input.decisions.get(digest);
    const decisionObject = objects.get(key("M5_CONTROL_DECISION", digest));
    if (value === undefined || decisionObject === undefined) {
      const found = objectsByDigest.get(digest) ?? [];
      const missingKind = found.length === 0;
      const classification: Walk = missingKind ? "INCOMPLETE" : "INVALID";
      memo.set(cacheKey, classification);
      return classification;
    }
    if (expectedKind !== "M5_CONTROL_DECISION") { memo.set(cacheKey, "INVALID"); return "INVALID"; }
    if (value === undefined || decisionObject === undefined) { memo.set(cacheKey, "INCOMPLETE"); return "INCOMPLETE"; }
    let structurallyValid = true;
    try { assertDocumentValid("pi_gacw_m5_control_decision_v0", value); } catch { structurallyValid = false; }
    const policy = input.policies.get(value.policy_content_sha256);
    if (policy === undefined) { memo.set(cacheKey, "INCOMPLETE"); return "INCOMPLETE"; }
    if (depth > policy.maximum_authority_depth) { detailByDecision.set(digest, "M5 authority chain exceeds maximum_authority_depth"); memo.set(cacheKey, "INVALID"); return "INVALID"; }
    if (stack.includes(digest)) {
      detailByDecision.set(digest, "M5 authority graph contains a cycle");
      memo.set(cacheKey, "INVALID");
      return "INVALID";
    }
    const group = decisionGroups.get(value.decision_key)!;
    if (new Set(group.map((item) => canonicalize(item))).size > 1) { detailByDecision.set(digest, "M5 decision key has conflicting immutable content"); memo.set(cacheKey, "INVALID"); return "INVALID"; }
    const state = input.workflowStates.get(value.current_state_content_sha256);
    if (!structurallyValid || value.content_sha256 !== digest || value.run_id !== input.runId || !validPolicies.has(value.policy_content_sha256) || state === undefined) { const classification: Walk = state === undefined ? "INCOMPLETE" : "INVALID"; detailByDecision.set(digest, "M5 decision has wrong run, policy, state kind, or document identity"); memo.set(cacheKey, classification); return classification; }
    const semantic = decisionSemanticError(value, policy, state);
    if (semantic !== null) { detailByDecision.set(digest, semantic); memo.set(cacheKey, "INVALID"); return "INVALID"; }
    const reducerPolicy = input.reducerPolicies?.get(value.reducer_policy_content_sha256);
    if (reducerPolicy !== undefined) {
      const recalculation = deterministicRecalculationError(value, policy, state, reducerPolicy, input);
      if (recalculation !== null) { detailByDecision.set(digest, recalculation); memo.set(cacheKey, "INVALID"); return "INVALID"; }
    }
    const nextStack = [...stack, digest];
    let aggregate: Walk = "VALID";
    const merge = (candidate: Walk): void => { if (candidate === "INVALID") aggregate = "INVALID"; else if (candidate === "INCOMPLETE" && aggregate === "VALID") aggregate = "INCOMPLETE"; };
    const prior = value.prior_relevant_decision_content_sha256;
    if (prior !== null) {
      const kinds = objectsByDigest.get(prior) ?? [];
      if (kinds.length > 0 && !kinds.some((object) => object.kind === "M5_CONTROL_DECISION")) merge("INVALID");
      else merge(visit(prior, nextStack, depth + 1, "M5_CONTROL_DECISION"));
    }
    const expectedUsage = [...value.usage_evidence_content_sha256].sort(compare);
    if (value.usage_set_sha256 !== sha256Canonical(expectedUsage)) merge("INVALID");
    for (const usageDigest of expectedUsage) {
      merge(usageWalk.get(usageDigest) ?? "INCOMPLETE");
      const usage = input.usage.get(usageDigest);
      if (usage !== undefined) for (const sourceObject of objectsByDigest.get(usage.source_record_content_sha256) ?? []) {
        if (sourceObject.kind === "M5_CONTROL_DECISION" && input.decisions.has(sourceObject.contentSha256)) merge(visit(sourceObject.contentSha256, nextStack, depth + 1, "M5_CONTROL_DECISION"));
      }
      if (usage?.reservation_decision_content_sha256 !== null && usage?.reservation_decision_content_sha256 !== undefined) {
        const reservationDecision = input.decisions.get(usage.reservation_decision_content_sha256);
        if (reservationDecision === undefined) merge("INCOMPLETE");
        else {
          merge(visit(usage.reservation_decision_content_sha256, nextStack, depth + 1, "M5_CONTROL_DECISION"));
          if (reservationDecision.reservation === null || reservationDecision.run_id !== value.run_id ||
              reservationDecision.reservation.future_operation_id !== usage.operation_id || reservationDecision.reservation.reserved_policy_content_sha256 !== value.policy_content_sha256 ||
              reservationDecision.reservation.reserved_state_content_sha256 !== usage.originating_state_content_sha256 || reservationDecision.reservation.reserved_route !== usage.execution_mode ||
              reservationDecision.reservation.logical_role !== usage.logical_role || usage.originating_state_content_sha256 !== reservationDecision.current_state_content_sha256) merge("INVALID");
        }
      }
    }
    for (const failure of value.failures) {
      const sourceObjects = objectsByDigest.get(failure.source_record_content_sha256) ?? [];
      if (sourceObjects.length === 0) merge("INCOMPLETE");
      else {
        const sourceClasses = sourceObjects.map((candidate) => predecessor.get(key(candidate.kind, candidate.contentSha256)));
        const sourceIsM5 = sourceObjects.some((candidate) => candidate.kind === "M5_CONTROL_POLICY" || candidate.kind === "M5_CONTROL_DECISION");
        if (sourceClasses.includes(INVALID)) merge("INVALID");
        else if (sourceIsM5) {
          for (const sourceObject of sourceObjects) if (sourceObject.kind === "M5_CONTROL_DECISION" && input.decisions.has(sourceObject.contentSha256)) merge(visit(sourceObject.contentSha256, nextStack, depth + 1, "M5_CONTROL_DECISION"));
        } else if (sourceClasses.every((classification) => classification === undefined || classification === INCOMPLETE)) merge("INCOMPLETE");
      }
      const replacement = failure.resolution_evidence_content_sha256;
      if (replacement !== null) {
        if (input.decisions.has(replacement)) merge(visit(replacement, nextStack, depth + 1, "M5_CONTROL_DECISION"));
        else {
          const replacementObjects = objectsByDigest.get(replacement) ?? [];
          if (replacementObjects.length === 0) merge("INCOMPLETE");
          else if (replacementObjects.every((candidate) => predecessor.get(key(candidate.kind, candidate.contentSha256)) === INVALID)) merge("INVALID");
        }
      }
    }
    detailByDecision.set(digest, aggregate === "VALID" ? "Complete M5 authority graph is valid" : aggregate === "INCOMPLETE" ? "M5 authority graph has a missing transitive predecessor" : "M5 authority graph is cyclic, too deep, wrong-kind, or contradictory");
    memo.set(cacheKey, aggregate); return aggregate;
  };

  for (const [digest] of input.decisions) rootWalk.set(digest, visit(digest, [], 0, "M5_CONTROL_DECISION"));
  for (const [digest] of input.decisions) {
    const object = objects.get(key("M5_CONTROL_DECISION", digest));
    if (object === undefined) continue;
    const walk = rootWalk.get(digest) ?? "INCOMPLETE";
    const committed = walk === "VALID" && input.typedTransitionDecisionDigests?.has(digest) === true &&
      input.runAuthorityValidatedPolicyDigests?.has(input.decisions.get(digest)?.policy_content_sha256 ?? "") === true;
    results.set(key(object.kind, digest), result(object, walk === "INVALID" ? INVALID : walk === "INCOMPLETE" ? INCOMPLETE : committed ? AUTHORITATIVE : UNREFERENCED,
      committed ? "Complete M5 semantic authority is reachable from a committed transition" : detailByDecision.get(digest) ?? "M5 authority is incomplete"));
  }

  const root = (digest: string, seen = new Set<string>()): void => {
    if (seen.has(digest) || rootWalk.get(digest) !== "VALID") return;
    seen.add(digest);
    const value = input.decisions.get(digest); if (value === undefined) return;
    const object = objects.get(key("M5_CONTROL_DECISION", digest));
    if (object !== undefined) results.set(key(object.kind, digest), result(object, AUTHORITATIVE, "M5 decision is rooted by a committed transition or decision consumer"));
    const policyObject = objects.get(key("M5_CONTROL_POLICY", value.policy_content_sha256));
    if (policyObject !== undefined) results.set(key(policyObject.kind, policyObject.contentSha256), result(policyObject, AUTHORITATIVE, "M5 policy is rooted by a committed decision"));
    for (const usageDigest of value.usage_evidence_content_sha256) {
      const usageObject = objects.get(key("M5_USAGE_EVIDENCE", usageDigest));
      if (usageObject !== undefined) results.set(key(usageObject.kind, usageDigest), result(usageObject, AUTHORITATIVE, "M5 usage is rooted by a committed decision"));
      const reservation = input.usage.get(usageDigest)?.reservation_decision_content_sha256;
      if (reservation !== null && reservation !== undefined) root(reservation, seen);
    }
    if (value.prior_relevant_decision_content_sha256 !== null) root(value.prior_relevant_decision_content_sha256, seen);
    for (const failure of value.failures) if (failure.resolution_evidence_content_sha256 !== null && input.decisions.has(failure.resolution_evidence_content_sha256)) root(failure.resolution_evidence_content_sha256, seen);
  };
  for (const [digest, decision] of input.decisions) if (rootWalk.get(digest) === "VALID" && input.typedTransitionDecisionDigests?.has(digest) === true &&
      input.runAuthorityValidatedPolicyDigests?.has(decision.policy_content_sha256) === true) root(digest);
  return [...results.values()].sort((a, b) => compare(a.object.relativePath, b.object.relativePath));
}
