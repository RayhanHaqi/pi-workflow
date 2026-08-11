import { canonicalize } from "../canonical-json/index.js";
import { type Sha256Digest } from "../identity/index.js";
import { commitTransition, inspectRunStorage } from "../persistence/index.js";
import { resolveAuthoritativeBoundedExecution } from "../persistence/bounded-worker-authority.js";
import { publishM5ManagedRecord, putEvidence, readM5ManagedRecords, withRunExclusive } from "../persistence/store.js";
import { m5PersistenceCheckpoint } from "../persistence/m5-test-hooks.js";
import {
  assertDocumentValid,
  type BudgetDocument,
  type ContractDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
} from "../schemas/index.js";
import { controlError, ControlDecisionError } from "./errors.js";
import { assertAuthoritativeSources, controlRequestKey, evaluateAuthority, markPersistedBoundedWorkerAuthority, orderDecisionHistory } from "./evaluate.js";
import { assertControlPolicyAuthority, deepFreezeDetached } from "./policy.js";
import type {
  ControlDecisionInspection,
  ControlDecisionKernel,
  ControlDecisionKernelOptions,
  ControlDecisionResult,
  EvaluateControlDecisionInput,
  M5AuthoritativeSources,
} from "./types.js";

function canonicalBytes(value: unknown): Buffer { return Buffer.from(`${canonicalize(value)}\n`, "utf8"); }
function wrap(error: unknown, publication = false): never {
  if (error instanceof ControlDecisionError) throw error;
  const sourceCode = error !== null && typeof error === "object" && "code" in error ? String((error as { code: unknown }).code) : "UNKNOWN";
  throw controlError(publication ? "M5_EVIDENCE_PUBLICATION_FAILED" : "M5_AUTHORITY_INCOMPLETE", "Lower-layer M5 operation failed", error, {
    sourceLayer: "M2", sourceCode, authorityRelevant: true,
  });
}

function assertExpected(input: EvaluateControlDecisionInput, inspection: Awaited<ReturnType<typeof inspectRunStorage>>): void {
  if (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) throw controlError("M5_DECISION_INVALID", "Expected revision is invalid");
  if (inspection.revision !== input.expectedRevision || inspection.statePointer?.content_sha256 !== input.expectedStatePointerContentSha256 || inspection.workflowState?.content_sha256 !== input.expectedWorkflowStateContentSha256) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Expected committed-state authority is stale", undefined, { sourceLayer: "M2", sourceCode: "STALE_EXPECTED_STATE", authorityRelevant: true });
  }
}

function lostResponseRequestKey(decision: M5ControlDecisionDocument, request: EvaluateControlDecisionInput, usageIds: readonly Sha256Digest[]): Sha256Digest {
  return controlRequestKey(request, decision.transition_event?.event_id ?? null, usageIds);
}

type RunInspection = Awaited<ReturnType<typeof inspectRunStorage>>;
type M5Records = Awaited<ReturnType<typeof readM5ManagedRecords>>;

function isPreProviderM4Classification(
  inspection: RunInspection,
  kind: "M4_TOOL_POLICY" | "M4_COMMAND_CATALOG",
  digest: string,
): boolean {
  return inspection.managedRecordClassifications.some((classification) => classification.object.kind === kind && classification.object.contentSha256 === digest &&
    (classification.classification === "AUTHORITATIVE_MANAGED_RECORD" || classification.classification === "UNREFERENCED_MANAGED_RECORD"));
}

function uniquePersistedSource<T>(values: readonly T[], identity: (value: T) => string, expected: string): T | undefined {
  const matches = values.filter((value) => identity(value) === expected);
  return matches.length === 1 ? matches[0] : undefined;
}

function resolvePersistedSources(
  policy: M5ControlPolicyDocument,
  inspection: RunInspection,
  records: M5Records,
  strict: boolean,
): M5AuthoritativeSources {
  const m4Classification = (kind: "M4_TOOL_POLICY" | "M4_COMMAND_CATALOG", digest: string): boolean => strict
    ? isPreProviderM4Classification(inspection, kind, digest)
    : inspection.managedRecordClassifications.some((classification) => classification.object.kind === kind && classification.object.contentSha256 === digest && classification.classification === "AUTHORITATIVE_MANAGED_RECORD");
  const m4ToolPolicy = records.toolPolicies.find((entry) => entry.content_sha256 === policy.tool_policy_content_sha256 &&
    m4Classification("M4_TOOL_POLICY", entry.content_sha256));
  const m4CommandCatalog = records.commandCatalogs.find((entry) => entry.content_sha256 === policy.command_catalog_content_sha256 &&
    m4Classification("M4_COMMAND_CATALOG", entry.content_sha256));
  const contract = strict ? uniquePersistedSource(records.contracts, (entry: ContractDocument) => entry.contract_sha256, policy.contract_sha256) : undefined;
  const budget = strict ? uniquePersistedSource(records.budgets, (entry: BudgetDocument) => entry.budget_sha256, policy.budget_sha256) : undefined;
  const routeMap = strict ? uniquePersistedSource(records.routeMaps, (entry: RouteMapDocument) => entry.route_map_sha256, policy.route_map_sha256) : undefined;
  const routeMapApproval = strict ? uniquePersistedSource(records.routeMapApprovals, (entry: RouteMapApprovalDocument) => entry.route_map_approval_sha256, policy.route_map_approval_sha256) : undefined;
  const planApprovals = strict ? records.planApprovals.filter((entry) => entry.plan_approval_sha256 === policy.plan_approval_sha256) : [];
  const taskGraphs = strict ? records.taskGraphs.filter((entry) => entry.task_graph_sha256 === policy.task_graph_sha256) : [];
  const tasks = strict ? records.tasks : [];
  const resolvedBoundedWorkerResults = records.boundedWorkerResults.filter((result) => {
    const invocation = uniquePersistedSource(records.boundedWorkerInvocations, (entry) => entry.content_sha256, result.invocation_content_sha256);
    if (invocation === undefined) return false;
    const reservation = uniquePersistedSource(records.decisions, (entry) => entry.content_sha256, invocation.m5_reservation_decision_content_sha256);
    if (reservation === undefined) return false;
    const reservationState = uniquePersistedSource(records.workflowStates, (entry) => entry.content_sha256, reservation.current_state_content_sha256);
    if (reservationState === undefined) return false;
    const approval = uniquePersistedSource(records.approvals, (entry) => entry.content_sha256, policy.baseline_approval_sha256) ?? null;
    const baseline = approval === null
      ? uniquePersistedSource(records.baselines, (entry) => entry.content_sha256, policy.baseline_approval_sha256)
      : uniquePersistedSource(records.baselines, (entry) => entry.content_sha256, approval.baseline_runtime_content_sha256);
    const stateToken = uniquePersistedSource(records.stateTokens, (entry) => entry.content_sha256, invocation.input_m3_state_token_content_sha256);
    const task = invocation.task_content_sha256 === null ? null : uniquePersistedSource(records.tasks, (entry) => entry.content_sha256, invocation.task_content_sha256);
    const taskGraph = invocation.task_graph_sha256 === null ? null : uniquePersistedSource(records.taskGraphs, (entry) => entry.content_sha256, invocation.task_graph_sha256);
    const plan = invocation.plan_approval_sha256 === null ? null : uniquePersistedSource(records.planApprovals, (entry) => entry.content_sha256, invocation.plan_approval_sha256);
    if (baseline === undefined || stateToken === undefined ||
        (invocation.task_content_sha256 !== null && task === undefined) ||
        (invocation.task_graph_sha256 !== null && taskGraph === undefined) ||
        (invocation.plan_approval_sha256 !== null && plan === undefined)) return false;
    return resolveAuthoritativeBoundedExecution({ invocation, result, reservation, reservationState, policy, baseline, approval, stateToken,
      task: task ?? null, taskGraph: taskGraph ?? null, plan: plan ?? null,
      admissionRefusals: new Map(records.admissionRefusals.map((entry) => [entry.content_sha256, entry])), classifications: inspection.managedRecordClassifications }).accepted;
  });
  return {
    ...(contract === undefined ? {} : { contract }),
    ...(budget === undefined ? {} : { budget }),
    ...(m4ToolPolicy === undefined ? {} : { m4ToolPolicy }),
    ...(m4CommandCatalog === undefined ? {} : { m4CommandCatalog }),
    ...(routeMap === undefined ? {} : { routeMap }),
    ...(routeMapApproval === undefined ? {} : { routeMapApproval }),
    ...(planApprovals.length === 0 ? {} : { planApprovals }),
    ...(taskGraphs.length === 0 ? {} : { taskGraphs }),
    ...(tasks.length === 0 ? {} : { tasks }),
    boundedWorkerResults: resolvedBoundedWorkerResults,
    m3StateTokens: records.stateTokens.filter((entry) => inspection.managedRecordClassifications.some((classification) =>
      classification.object.kind === "M3_REPOSITORY_STATE_TOKEN" && classification.object.contentSha256 === entry.content_sha256 && classification.classification === "AUTHORITATIVE_MANAGED_RECORD")),
    m3Postflights: records.postflights.filter((entry) => inspection.managedRecordClassifications.some((classification) =>
      classification.object.kind === "M3_POSTFLIGHT" && classification.object.contentSha256 === entry.content_sha256 && classification.classification === "AUTHORITATIVE_MANAGED_RECORD")),
  };
}

function withRunAuthoritySources(
  authority: ControlDecisionKernelOptions["runAuthority"],
  sources: M5AuthoritativeSources | undefined,
): M5AuthoritativeSources | undefined {
  const immutable: M5AuthoritativeSources = authority === undefined ? {} : {
    contract: authority.contract,
    routeMap: authority.routeMap,
    routeMapApproval: authority.routeMapApproval,
  };
  for (const field of ["contract", "routeMap", "routeMapApproval"] as const) {
    const left = immutable[field]; const right = sources?.[field];
    if (left !== undefined && right !== undefined && canonicalize(left) !== canonicalize(right)) {
      throw controlError("M5_AUTHORITY_INCOMPLETE", `${field} differs between immutable run authority and M5 source authority`);
    }
  }
  const merged = { ...immutable, ...(sources ?? {}) };
  return Object.keys(merged).length === 0 ? undefined : merged;
}

/** OWNER_APPROVED source documents are persisted through the existing evidence boundary before M5 publication. */
async function publishStrictSourceEvidence(
  location: { readonly stateRoot: string; readonly runId: string },
  sources: M5AuthoritativeSources | undefined,
): Promise<void> {
  if (sources === undefined) return;
  const entries = [
    [sources.contract, "application/vnd.pi-gacw.contract+json"],
    [sources.budget, "application/vnd.pi-gacw.budget+json"],
    [sources.routeMap, "application/vnd.pi-gacw.route-map+json"],
    [sources.routeMapApproval, "application/vnd.pi-gacw.route-map-approval+json"],
    ...(sources.planApprovals ?? []).map((entry) => [entry, "application/vnd.pi-gacw.plan-approval+json"] as const),
    ...(sources.taskGraphs ?? []).map((entry) => [entry, "application/vnd.pi-gacw.task-graph+json"] as const),
    ...(sources.tasks ?? []).map((entry) => [entry, "application/vnd.pi-gacw.task+json"] as const),
  ] as const;
  for (const [document, mediaType] of entries) if (document !== undefined) {
    await putEvidence({ ...location, bytes: canonicalBytes(document), mediaType });
  }
}

function assertSuppliedStrictSourcesArePersisted(
  supplied: M5AuthoritativeSources | undefined,
  persisted: M5AuthoritativeSources,
  strict: boolean,
): void {
  if (!strict || supplied === undefined) return;
  for (const field of ["contract", "budget", "m4ToolPolicy", "m4CommandCatalog", "routeMap", "routeMapApproval"] as const) {
    const candidate = supplied[field];
    if (candidate === undefined) continue;
    const durable = persisted[field];
    if (durable === undefined || canonicalize(candidate) !== canonicalize(durable)) {
      throw controlError("M5_AUTHORITY_INCOMPLETE", `${field} is not an exact durably reconstructed predecessor`);
    }
  }
  const exactArray = <T extends { readonly content_sha256: string }>(label: string, suppliedValues: readonly T[] | undefined, durableValues: readonly T[] | undefined): void => {
    if (suppliedValues === undefined) return;
    const durable = new Map((durableValues ?? []).map((entry) => [entry.content_sha256, canonicalize(entry)]));
    if (suppliedValues.some((entry) => durable.get(entry.content_sha256) !== canonicalize(entry))) throw controlError("M5_AUTHORITY_INCOMPLETE", `${label} is not an exact durably reconstructed predecessor`);
  };
  exactArray("plan approval", supplied.planApprovals, persisted.planApprovals);
  exactArray("task graph", supplied.taskGraphs, persisted.taskGraphs);
  exactArray("task", supplied.tasks, persisted.tasks);
}

function effectivePersistedSources(
  policy: M5ControlPolicyDocument,
  persisted: M5AuthoritativeSources,
  captured: M5AuthoritativeSources | undefined,
  requested: M5AuthoritativeSources | undefined,
  strict: boolean,
): M5AuthoritativeSources {
  assertAuthoritativeSources(policy, captured, false);
  assertAuthoritativeSources(policy, requested, false);
  assertSuppliedM3AuthorityIsPersisted(captured, persisted);
  assertSuppliedM3AuthorityIsPersisted(requested, persisted);
  assertSuppliedStrictSourcesArePersisted(captured, persisted, strict);
  assertSuppliedStrictSourcesArePersisted(requested, persisted, strict);
  const effective: M5AuthoritativeSources = {
    ...persisted,
    ...(captured ?? {}),
    ...(requested ?? {}),
    // PERSISTED_ONLY_FOR_BOUNDED_WORKER_AUTHORITY: source selection is the
    // resolver-derived persisted reservation scope, never a caller projection.
    boundedWorkerResults: persisted.boundedWorkerResults ?? [],
    // M3 mutation authority is never caller-replaceable. Only records that M3
    // independently classified from this run's persisted predecessor graph apply.
    m3StateTokens: persisted.m3StateTokens ?? [],
    m3Postflights: persisted.m3Postflights ?? [],
  };
  assertAuthoritativeSources(policy, effective, strict);
  return markPersistedBoundedWorkerAuthority(effective);
}

function assertSuppliedM3AuthorityIsPersisted(
  supplied: M5AuthoritativeSources | undefined,
  persisted: M5AuthoritativeSources,
): void {
  const requireExact = (
    label: string,
    values: readonly { readonly content_sha256: string }[] | undefined,
    authoritative: readonly { readonly content_sha256: string }[] | undefined,
  ): void => {
    if (values === undefined) return;
    const byDigest = new Map((authoritative ?? []).map((entry) => [entry.content_sha256, canonicalize(entry)]));
    if (new Set(values.map((entry) => entry.content_sha256)).size !== values.length ||
        values.some((entry) => byDigest.get(entry.content_sha256) !== canonicalize(entry))) {
      throw controlError("M5_AUTHORITY_INCOMPLETE", `${label} is not an exact persisted authoritative predecessor`);
    }
  };
  requireExact("bounded worker-result authority", supplied?.boundedWorkerResults, persisted.boundedWorkerResults);
  requireExact("M3 state-token authority", supplied?.m3StateTokens, persisted.m3StateTokens);
  requireExact("M3 postflight authority", supplied?.m3Postflights, persisted.m3Postflights);
}

export function createControlDecisionKernel(options: ControlDecisionKernelOptions): ControlDecisionKernel {
  const captured = deepFreezeDetached(options);
  const location = { stateRoot: captured.stateRoot, runId: captured.runId };

  return Object.freeze({
    async evaluateControlDecision(requestInput: EvaluateControlDecisionInput): Promise<ControlDecisionResult> {
      const request = deepFreezeDetached(requestInput);
      try {
        return await withRunExclusive(location, async () => {
      let inspection: Awaited<ReturnType<typeof inspectRunStorage>>;
      let records: Awaited<ReturnType<typeof readM5ManagedRecords>>;
      try { inspection = await inspectRunStorage(location); records = await readM5ManagedRecords(location); }
      catch (error: unknown) { wrap(error); }
      if (inspection.workflowState === null || inspection.statePointer === null || inspection.revision === null) throw controlError("M5_AUTHORITY_INCOMPLETE", "Committed state is unavailable");
      assertControlPolicyAuthority(captured.policy, inspection.workflowState, captured.reducerPolicy, captured.runId, captured.production ?? false, captured.runAuthority);
      const incomingUsage: M5UsageEvidenceDocument[] = [];
      for (const usage of request.usageEvidence ?? []) {
        try { assertDocumentValid("pi_gacw_m5_usage_evidence_v0", usage); }
        catch (error: unknown) { throw controlError("USAGE_EVIDENCE_INVALID", "Incoming usage failed validation", error); }
        incomingUsage.push(usage);
      }
      const incomingUsageIds = incomingUsage.map((entry) => entry.content_sha256 as Sha256Digest).sort();
      const strictSources = captured.production === true || captured.policy.production_authority === "OWNER_APPROVED";
      const capturedSources = strictSources ? withRunAuthoritySources(captured.runAuthority, captured.authoritativeSources) : captured.authoritativeSources;
      const requestedSources = strictSources ? withRunAuthoritySources(captured.runAuthority, request.authoritativeSources) : request.authoritativeSources;
      let persistedSources = resolvePersistedSources(captured.policy, inspection, records, strictSources);
      if (strictSources) {
        const suppliedSources: M5AuthoritativeSources = { ...persistedSources, ...(capturedSources ?? {}), ...(requestedSources ?? {}) };
        assertAuthoritativeSources(captured.policy, suppliedSources, true);
        await publishStrictSourceEvidence(location, suppliedSources);
        inspection = await inspectRunStorage(location);
        records = await readM5ManagedRecords(location);
        if (inspection.workflowState === null || inspection.statePointer === null || inspection.revision === null) throw controlError("M5_AUTHORITY_INCOMPLETE", "Committed state is unavailable");
        persistedSources = resolvePersistedSources(captured.policy, inspection, records, strictSources);
      }
      const decisionHistory = orderDecisionHistory(records.decisions.filter((entry) =>
        entry.run_id === captured.runId && entry.policy_content_sha256 === captured.policy.content_sha256));
      const authoritativeSources = effectivePersistedSources(captured.policy, persistedSources, capturedSources, requestedSources, strictSources);
      if (request.intent === "AUTHORIZE_WORK" && (authoritativeSources.m3StateTokens?.length ?? 0) === 0) {
        throw controlError("M5_AUTHORITY_INCOMPLETE", "Repository-affecting work requires exact persisted M3 repository/worktree token authority");
      }
      const decisionRequest = { ...request, authoritativeSources };
      const lostResponse = decisionHistory.find((decision) => decision.policy_content_sha256 === captured.policy.content_sha256 &&
        decision.intent === request.intent && decision.current_state_content_sha256 === request.expectedWorkflowStateContentSha256 &&
        decision.transition_id === request.transitionId &&
        lostResponseRequestKey(decision, decisionRequest, incomingUsageIds) === decision.request_key &&
        canonicalize(incomingUsageIds) === canonicalize([...decision.usage_evidence_content_sha256].sort()));
      if (lostResponse !== undefined && inspection.workflowState.content_sha256 !== request.expectedWorkflowStateContentSha256 &&
          lostResponse.predicted_next_state_content_sha256 === inspection.workflowState.content_sha256 &&
          inspection.transitionCommit?.previous_revision === request.expectedRevision &&
          inspection.transitionCommit.previous_state_pointer_content_sha256 === request.expectedStatePointerContentSha256 &&
          inspection.transitionCommit.previous_workflow_state_content_sha256 === request.expectedWorkflowStateContentSha256) {
        return deepFreezeDetached({ decision: lostResponse, workflowState: inspection.workflowState, committed: true, reusedDecision: true });
      }
      if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") throw controlError("TERMINAL_STATE_IMMUTABLE", "Terminal workflow state cannot accept another M5 decision");
      assertExpected(request, inspection);
      const priorDecisions = lostResponse === undefined
        ? decisionHistory
        : decisionHistory.filter((entry) => entry.content_sha256 !== lostResponse.content_sha256);
      let decision = evaluateAuthority({ policy: captured.policy, state: inspection.workflowState, reducerPolicy: captured.reducerPolicy,
        request: decisionRequest, persistedUsage: records.usage, priorDecisions,
        authoritativeSources, ...(captured.production === undefined ? {} : { production: captured.production }) });
      const duplicate = records.decisions.find((entry) => entry.decision_key === decision.decision_key ||
        (entry.request_key !== undefined && decision.request_key !== undefined && entry.request_key === decision.request_key));
      if (duplicate !== undefined) {
        if (canonicalize(duplicate) !== canonicalize(decision)) throw controlError("M5_DECISION_INVALID", "Deterministic request key has contradictory immutable content");
        decision = duplicate;
        if (decision.transition_event === null) return deepFreezeDetached({ decision, workflowState: inspection.workflowState, committed: false, reusedDecision: true });
        if (decision.predicted_next_state_content_sha256 === inspection.workflowState.content_sha256 && request.expectedWorkflowStateContentSha256 !== inspection.workflowState.content_sha256) {
          return deepFreezeDetached({ decision, workflowState: inspection.workflowState, committed: true, reusedDecision: true });
        }
      } else if (records.decisions.length >= captured.policy.maximum_control_decisions) {
        throw controlError("ROUTE_LIMIT_EXHAUSTED", "M5 control-decision cap reached");
      }
      try {
        await publishM5ManagedRecord({ ...location, kind: "M5_CONTROL_POLICY", document: captured.policy });
        for (const usage of incomingUsage) await publishM5ManagedRecord({ ...location, kind: "M5_USAGE_EVIDENCE", document: usage });
        const publication = await publishM5ManagedRecord({ ...location, kind: "M5_CONTROL_DECISION", document: decision });
        const reread = await readM5ManagedRecords(location);
        const persisted = reread.decisions.find((entry) => entry.content_sha256 === decision.content_sha256);
        if (persisted === undefined || canonicalize(persisted) !== canonicalize(decision)) throw controlError("M5_EVIDENCE_PUBLICATION_FAILED", "Published decision did not reread exactly");
        const precommitInspection = await inspectRunStorage(location);
        const precommitClassification = precommitInspection.managedRecordClassifications.find((entry) => entry.object.kind === "M5_CONTROL_DECISION" && entry.object.contentSha256 === decision.content_sha256);
        if (precommitClassification?.classification !== "UNREFERENCED_MANAGED_RECORD") {
          throw controlError("M5_EVIDENCE_PUBLICATION_FAILED", `Published decision lacks complete pre-transition semantic closure: ${precommitClassification?.detail ?? "classification missing"}`);
        }
        if (decision.transition_event === null) return deepFreezeDetached({ decision, workflowState: inspection.workflowState, committed: false, reusedDecision: publication.reused });
        if (request.transitionId === undefined || request.processMetadata === undefined || decision.predicted_next_state_content_sha256 === null) {
          throw controlError("M5_DECISION_INVALID", "A transition decision requires transitionId, processMetadata, and predicted state authority");
        }
        let committed;
        try {
          committed = await commitTransition({ ...location, expectedRevision: request.expectedRevision,
            expectedStatePointerContentSha256: request.expectedStatePointerContentSha256,
            expectedWorkflowStateContentSha256: request.expectedWorkflowStateContentSha256,
            expectedNextWorkflowStateContentSha256: decision.predicted_next_state_content_sha256 as Sha256Digest,
            transitionId: request.transitionId, policy: captured.reducerPolicy, event: decision.transition_event,
            evidence: [
              { bytes: canonicalBytes(decision), mediaType: "application/vnd.pi-gacw.m5-control-decision+json" },
              { bytes: canonicalBytes(captured.runAuthority!.repositoryIdentity), mediaType: "application/vnd.pi-gacw.repository-identity+json" },
              { bytes: canonicalBytes(captured.runAuthority!.contract), mediaType: "application/vnd.pi-gacw.contract+json" },
              ...(authoritativeSources.budget === undefined ? [] : [{ bytes: canonicalBytes(authoritativeSources.budget), mediaType: "application/vnd.pi-gacw.budget+json" }]),
              { bytes: canonicalBytes(captured.runAuthority!.routeMap), mediaType: "application/vnd.pi-gacw.route-map+json" },
              { bytes: canonicalBytes(captured.runAuthority!.routeMapApproval), mediaType: "application/vnd.pi-gacw.route-map-approval+json" },
            ], processMetadata: request.processMetadata });
        } catch (error: unknown) {
          const sourceCode = error !== null && typeof error === "object" && "code" in error ? String((error as { code: unknown }).code) : "UNKNOWN";
          throw controlError("M5_STATE_PUBLICATION_FAILED", "M2 rejected or could not publish the authorized transition", error, { sourceLayer: "M2", sourceCode, authorityRelevant: true });
        }
        const finalInspection = await inspectRunStorage(location);
        const classification = finalInspection.managedRecordClassifications.find((entry) => entry.object.kind === "M5_CONTROL_DECISION" && entry.object.contentSha256 === decision.content_sha256);
        if (classification?.classification !== "AUTHORITATIVE_MANAGED_RECORD") throw controlError("M5_STATE_PUBLICATION_FAILED", `Committed transition does not root exact M5 decision authority: ${classification?.detail ?? "classification missing"}`);
        await m5PersistenceCheckpoint("AFTER_COMMITTED_STATE_BEFORE_RESPONSE", decision.content_sha256);
        return deepFreezeDetached({ decision, workflowState: committed.workflowState, committed: true, reusedDecision: publication.reused });
      } catch (error: unknown) { wrap(error, true); }
        });
      } catch (error: unknown) { wrap(error); }
    },

    async inspectControlDecision(): Promise<ControlDecisionInspection> {
      try {
        const [inspection, records] = await Promise.all([inspectRunStorage(location), readM5ManagedRecords(location)]);
        if (inspection.workflowState === null) throw controlError("M5_AUTHORITY_INCOMPLETE", "Committed state is unavailable");
        assertControlPolicyAuthority(captured.policy, inspection.workflowState, captured.reducerPolicy, captured.runId, captured.production ?? false, captured.runAuthority);
        const strictSources = captured.production === true || captured.policy.production_authority === "OWNER_APPROVED";
        const persistedSources = resolvePersistedSources(captured.policy, inspection, records, strictSources);
        const capturedSources = strictSources ? withRunAuthoritySources(captured.runAuthority, captured.authoritativeSources) : captured.authoritativeSources;
        effectivePersistedSources(captured.policy, persistedSources, capturedSources, undefined, strictSources);
        const policyClassification = inspection.managedRecordClassifications.find((entry) => entry.object.kind === "M5_CONTROL_POLICY" && entry.object.contentSha256 === captured.policy.content_sha256)?.classification ?? "ABSENT";
        return deepFreezeDetached({ currentState: inspection.workflowState, decisions: records.decisions, usageEvidence: records.usage, policyClassification });
      } catch (error: unknown) { wrap(error); }
    },
  });
}
