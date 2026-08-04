import { canonicalize } from "../canonical-json/index.js";
import { type Sha256Digest } from "../identity/index.js";
import { commitTransition, inspectRunStorage } from "../persistence/index.js";
import { publishM5ManagedRecord, readM5ManagedRecords, withRunExclusive } from "../persistence/store.js";
import { m5PersistenceCheckpoint } from "../persistence/m5-test-hooks.js";
import { assertDocumentValid, type M5ControlDecisionDocument, type M5ControlPolicyDocument, type M5UsageEvidenceDocument } from "../schemas/index.js";
import { controlError, ControlDecisionError } from "./errors.js";
import { assertAuthoritativeSources, controlRequestKey, evaluateAuthority, orderDecisionHistory } from "./evaluate.js";
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

function resolvePersistedSources(
  policy: M5ControlPolicyDocument,
  inspection: RunInspection,
  records: M5Records,
): M5AuthoritativeSources {
  const isAuthoritative = (kind: string, digest: string): boolean => inspection.managedRecordClassifications.some((classification) =>
    classification.object.kind === kind && classification.object.contentSha256 === digest && classification.classification === "AUTHORITATIVE_MANAGED_RECORD");
  const m4ToolPolicy = records.toolPolicies.find((entry) => entry.content_sha256 === policy.tool_policy_content_sha256 && isAuthoritative("M4_TOOL_POLICY", entry.content_sha256));
  const m4CommandCatalog = records.commandCatalogs.find((entry) => entry.content_sha256 === policy.command_catalog_content_sha256 && isAuthoritative("M4_COMMAND_CATALOG", entry.content_sha256));
  return {
    ...(m4ToolPolicy === undefined ? {} : { m4ToolPolicy }),
    ...(m4CommandCatalog === undefined ? {} : { m4CommandCatalog }),
    m3StateTokens: records.stateTokens.filter((entry) => isAuthoritative("M3_REPOSITORY_STATE_TOKEN", entry.content_sha256)),
    m3Postflights: records.postflights.filter((entry) => isAuthoritative("M3_POSTFLIGHT", entry.content_sha256)),
  };
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
  const effective: M5AuthoritativeSources = {
    ...persisted,
    ...(captured ?? {}),
    ...(requested ?? {}),
    // M3 mutation authority is never caller-replaceable. Only records that M3
    // independently classified from this run's persisted predecessor graph apply.
    m3StateTokens: persisted.m3StateTokens ?? [],
    m3Postflights: persisted.m3Postflights ?? [],
  };
  assertAuthoritativeSources(policy, effective, strict);
  return effective;
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
      const decisionHistory = orderDecisionHistory(records.decisions.filter((entry) =>
        entry.run_id === captured.runId && entry.policy_content_sha256 === captured.policy.content_sha256));
      const persistedSources = resolvePersistedSources(captured.policy, inspection, records);
      const authoritativeSources = effectivePersistedSources(captured.policy, persistedSources, captured.authoritativeSources, request.authoritativeSources, strictSources);
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
        const persistedSources = resolvePersistedSources(captured.policy, inspection, records);
        effectivePersistedSources(captured.policy, persistedSources, captured.authoritativeSources, undefined,
          captured.production === true || captured.policy.production_authority === "OWNER_APPROVED");
        const policyClassification = inspection.managedRecordClassifications.find((entry) => entry.object.kind === "M5_CONTROL_POLICY" && entry.object.contentSha256 === captured.policy.content_sha256)?.classification ?? "ABSENT";
        return deepFreezeDetached({ currentState: inspection.workflowState, decisions: records.decisions, usageEvidence: records.usage, policyClassification });
      } catch (error: unknown) { wrap(error); }
    },
  });
}
