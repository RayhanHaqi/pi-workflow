import { canonicalize } from "../canonical-json/index.js";
import {
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3PostflightDocument,
  type M3PreflightDocument,
  type M3RepositoryStateTokenDocument,
  type M3RetentionResultDocument,
  type M3TerminalRetentionAuthorityDocument,
  type WorkflowState,
} from "../schemas/index.js";
import {
  LockAcquisitionRootValidationError,
  assertGlobalLockAcquisition,
} from "../repository/acquisition.js";
import {
  assertDurableBaselineProducerSemantics,
  assertDurableEnvironmentProducerSemantics,
  assertDurablePostflightProducerSemantics,
} from "../repository/semantic-context.js";
import type { InspectedObject, ManagedRecordClassification } from "./types.js";
import {
  M3AuthorityValidationError,
  assertM3BaselineApprovalSemantics,
  assertM3BaselineRuntimeSemantics,
  assertM3FastPreflightRecordSemantics,
  assertM3FullPreflightSourceSemantics,
  assertM3LockAcquisitionSemantics,
  assertM3LockDiagnosticSemantics,
  assertM3PostflightSourceSemantics,
  assertM3RetentionResultSemantics,
  assertM3TerminalRetentionAuthoritySemantics,
  buildM3RetentionAuthorityContext,
  exactM3RetentionDeletionProof,
  m3BaselineQuotaPopulationCandidates,
  validateM3AuthoritativeToken,
  type M3AuthorityResolver,
  type M3TokenAuthority,
  type RetentionAuthorityContext,
} from "./m3-authority.js";

export interface ManagedAuthorityInventory {
  readonly stateRoot: string;
  readonly runId: string;
  readonly workflowState: WorkflowState;
  readonly objects: readonly InspectedObject[];
  readonly baselines: ReadonlyMap<string, M3BaselineRuntimeDocument>;
  readonly approvals: ReadonlyMap<string, M3BaselineApprovalRuntimeDocument>;
  readonly lockAcquisitions: ReadonlyMap<string, M3LockAcquisitionDocument>;
  readonly lockDiagnostics: ReadonlyMap<string, M3LockDiagnosticDocument>;
  readonly preflights: ReadonlyMap<string, M3PreflightDocument>;
  readonly tokens: ReadonlyMap<string, M3RepositoryStateTokenDocument>;
  readonly postflights: ReadonlyMap<string, M3PostflightDocument>;
  readonly results: ReadonlyMap<string, M3RetentionResultDocument>;
  /** Keyed by the raw-evidence physical SHA-256 used by the inspected object. */
  readonly terminalAuthorities: ReadonlyMap<string, M3TerminalRetentionAuthorityDocument | Error>;
  readonly blobDigests: ReadonlySet<string>;
  readonly blobSizes: ReadonlyMap<string, number>;
}

type Classification = ManagedRecordClassification["classification"];
interface Decision { readonly classification: Classification; readonly detail: string }
const AUTHORITATIVE: Decision = { classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "Complete structural and semantic authority chain" };
const UNREFERENCED: Decision = { classification: "UNREFERENCED_MANAGED_RECORD", detail: "Valid immutable record has no authoritative root or successor edge" };
const INCOMPLETE: Decision = { classification: "INCOMPLETE_MANAGED_RECORD_CHAIN", detail: "A claimed semantic authority edge is missing" };
const INVALID: Decision = { classification: "INVALID_MANAGED_RECORD", detail: "Record schema/content identity or semantic cross-binding is invalid" };
const UNCOMMITTED: Decision = { classification: "UNCOMMITTED_BASELINE_PUBLICATION", detail: "UNCOMMITTED_BASELINE_PUBLICATION" };

function compareText(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function objectKey(object: InspectedObject): string { return `${object.kind}:${object.contentSha256}`; }
function failureDecision(error: unknown): Decision {
  return error instanceof M3AuthorityValidationError && error.kind === "MISSING" ||
    error instanceof LockAcquisitionRootValidationError && error.kind === "MISSING" ? INCOMPLETE : INVALID;
}
function same(left: unknown, right: unknown): boolean { return canonicalize(left) === canonicalize(right); }

/**
 * Pure managed-authority classifier. It consumes the same semantic validators
 * and token/proof graph evaluators as operational repository consumers.
 */
export async function classifyManagedAuthority(
  inventory: ManagedAuthorityInventory,
): Promise<readonly ManagedRecordClassification[]> {
  const decisions = new Map<string, Decision>();
  const baselineSemantic = new Set<string>();
  const approvalSemantic = new Set<string>();
  const acquisitionSemantic = new Set<string>();
  const terminalSemantic = new Map<string, M3TerminalRetentionAuthorityDocument>();

  const allBaselines = [...inventory.baselines.values()];
  const baselineProducerMemo = new Map<string, Promise<void>>();
  const acquisitionProducerMemo = new Map<string, Promise<void>>();
  const environmentProducerMemo = new Map<string, Promise<void>>();
  const postflightProducerMemo = new Map<string, Promise<void>>();
  const baselineProducer = (baseline: M3BaselineRuntimeDocument): Promise<void> => {
    const prior = baselineProducerMemo.get(baseline.content_sha256);
    if (prior !== undefined) return prior;
    const pending = assertDurableBaselineProducerSemantics(baseline, allBaselines);
    baselineProducerMemo.set(baseline.content_sha256, pending);
    return pending;
  };
  const acquisitionProducer = (acquisition: M3LockAcquisitionDocument): Promise<void> => {
    const prior = acquisitionProducerMemo.get(acquisition.content_sha256);
    if (prior !== undefined) return prior;
    const pending = assertGlobalLockAcquisition(inventory.stateRoot, acquisition);
    acquisitionProducerMemo.set(acquisition.content_sha256, pending);
    return pending;
  };
  const environmentProducer = (
    source: M3PreflightDocument,
    lockDiagnostic: M3LockDiagnosticDocument,
  ): Promise<void> => {
    const key = `${source.content_sha256}:${lockDiagnostic.content_sha256}`;
    const prior = environmentProducerMemo.get(key);
    if (prior !== undefined) return prior;
    const pending = assertDurableEnvironmentProducerSemantics(source, lockDiagnostic);
    environmentProducerMemo.set(key, pending);
    return pending;
  };
  const postflightProducer = (
    source: M3PostflightDocument,
    prior: M3RepositoryStateTokenDocument,
    baseline: M3BaselineRuntimeDocument,
  ): Promise<void> => {
    const cached = postflightProducerMemo.get(source.content_sha256);
    if (cached !== undefined) return cached;
    const pending = assertDurablePostflightProducerSemantics(source, prior, baseline);
    postflightProducerMemo.set(source.content_sha256, pending);
    return pending;
  };
  for (const [digest, acquisition] of inventory.lockAcquisitions) {
    try {
      assertM3LockAcquisitionSemantics(acquisition);
      await acquisitionProducer(acquisition);
      acquisitionSemantic.add(digest);
    } catch (error: unknown) { decisions.set(`M3_LOCK_ACQUISITION:${digest}`, failureDecision(error)); }
  }
  for (const [digest, baseline] of inventory.baselines) {
    try {
      assertM3BaselineRuntimeSemantics(baseline);
      await baselineProducer(baseline);
      baselineSemantic.add(digest);
    } catch (error: unknown) { decisions.set(`M3_BASELINE:${digest}`, failureDecision(error)); }
  }
  for (const [digest, approval] of inventory.approvals) {
    const baseline = inventory.baselines.get(approval.baseline_runtime_content_sha256);
    if (baseline === undefined) { decisions.set(`M3_BASELINE_APPROVAL:${digest}`, INCOMPLETE); continue; }
    if (!baselineSemantic.has(baseline.content_sha256)) { decisions.set(`M3_BASELINE_APPROVAL:${digest}`, INVALID); continue; }
    try { assertM3BaselineApprovalSemantics(baseline, approval); approvalSemantic.add(digest); }
    catch (error: unknown) { decisions.set(`M3_BASELINE_APPROVAL:${digest}`, failureDecision(error)); }
  }

  for (const [physicalDigest, value] of inventory.terminalAuthorities) {
    const key = `M3_TERMINAL_RETENTION_AUTHORITY:${physicalDigest}`;
    if (value instanceof Error) { decisions.set(key, INVALID); continue; }
    const baseline = inventory.baselines.get(value.baseline_runtime_content_sha256);
    if (baseline === undefined) { decisions.set(key, INCOMPLETE); continue; }
    if (!baselineSemantic.has(baseline.content_sha256)) { decisions.set(key, INVALID); continue; }
    let approval: M3BaselineApprovalRuntimeDocument | null = null;
    if (value.baseline_approval_runtime_content_sha256 !== null) {
      approval = inventory.approvals.get(value.baseline_approval_runtime_content_sha256) ?? null;
      if (approval === null) { decisions.set(key, INCOMPLETE); continue; }
      if (!approvalSemantic.has(approval.content_sha256)) { decisions.set(key, INVALID); continue; }
    }
    try {
      assertM3TerminalRetentionAuthoritySemantics(value, inventory.workflowState, baseline, approval);
      terminalSemantic.set(physicalDigest, value);
    } catch (error: unknown) { decisions.set(key, failureDecision(error)); }
  }

  // Ambiguous authority roots are operationally invalid, not independently authoritative.
  const authorityCounts = new Map<string, number>();
  for (const authority of terminalSemantic.values()) {
    authorityCounts.set(authority.baseline_runtime_content_sha256, (authorityCounts.get(authority.baseline_runtime_content_sha256) ?? 0) + 1);
  }
  for (const [physicalDigest, authority] of [...terminalSemantic]) {
    if ((authorityCounts.get(authority.baseline_runtime_content_sha256) ?? 0) > 1) {
      terminalSemantic.delete(physicalDigest);
      decisions.set(`M3_TERMINAL_RETENTION_AUTHORITY:${physicalDigest}`, INVALID);
    }
  }

  const validApprovals = [...inventory.approvals].filter(([digest]) => approvalSemantic.has(digest)).map(([, value]) => value);
  const validBaselines = [...inventory.baselines].filter(([digest]) => baselineSemantic.has(digest)).map(([, value]) => value);
  const validAuthorities = [...terminalSemantic.values()];
  let retentionContext: RetentionAuthorityContext | null = null;
  try {
    retentionContext = buildM3RetentionAuthorityContext(inventory.workflowState, validBaselines, validApprovals, validAuthorities);
  } catch {
    retentionContext = null;
  }

  const preliminaryValidResults: M3RetentionResultDocument[] = [];
  for (const [digest, result] of inventory.results) {
    const key = `M3_RETENTION_RESULT:${digest}`;
    const baseline = inventory.baselines.get(result.baseline_runtime_content_sha256);
    const authority = [...terminalSemantic.values()].find((candidate) => candidate.content_sha256 === result.terminal_authority_content_sha256);
    if (baseline === undefined || authority === undefined) { decisions.set(key, INCOMPLETE); continue; }
    if (!baselineSemantic.has(baseline.content_sha256) || retentionContext === null) { decisions.set(key, INVALID); continue; }
    try {
      // The complete result set is supplied so idempotent proof edges cannot be selected from a weaker graph.
      assertM3RetentionResultSemantics(result, retentionContext, [...inventory.results.values()]);
      preliminaryValidResults.push(result);
    } catch (error: unknown) { decisions.set(key, failureDecision(error)); }
  }

  // A baseline root is authoritative only when one exact quota-history
  // population is continuous through currently retained blobs or cleanup-only
  // deletion proof. An incomplete predecessor cannot authorize a successor.
  const baselineAuthoritative = new Set<string>();
  for (const [digest, baseline] of inventory.baselines) {
    const key = `M3_BASELINE:${digest}`;
    if (!baselineSemantic.has(digest)) continue;
    let completePopulation = false;
    let invalidPopulation = false;
    let populations: readonly ReadonlyMap<string, number>[] = [];
    try { populations = m3BaselineQuotaPopulationCandidates(baseline, validBaselines); }
    catch { decisions.set(key, INVALID); continue; }
    for (const population of populations) {
      let completeCandidate = true;
      for (const [blobDigest, expectedSize] of population) {
        const retainedSize = inventory.blobSizes.get(blobDigest);
        if (retainedSize !== undefined) {
          if (retainedSize !== expectedSize) { invalidPopulation = true; completeCandidate = false; }
          continue;
        }
        try {
          if (retentionContext === null || exactM3RetentionDeletionProof(preliminaryValidResults, retentionContext, blobDigest) === null) {
            completeCandidate = false;
          }
        } catch { completeCandidate = false; }
      }
      if (completeCandidate) completePopulation = true;
    }
    if (invalidPopulation) decisions.set(key, INVALID);
    else if (completePopulation) { baselineAuthoritative.add(digest); decisions.set(key, AUTHORITATIVE); }
    else decisions.set(key, INCOMPLETE);
  }

  const approvalAuthoritative = new Set<string>();
  for (const [digest, approval] of inventory.approvals) {
    const key = `M3_BASELINE_APPROVAL:${digest}`;
    if (!approvalSemantic.has(digest)) continue;
    if (baselineAuthoritative.has(approval.baseline_runtime_content_sha256)) {
      approvalAuthoritative.add(digest); decisions.set(key, AUTHORITATIVE);
    } else decisions.set(key, INCOMPLETE);
  }

  const resolver: M3AuthorityResolver = {
    baseline: async (digest) => inventory.baselines.get(digest),
    approval: async (digest) => inventory.approvals.get(digest),
    lockAcquisition: async (digest) => inventory.lockAcquisitions.get(digest),
    lockDiagnostic: async (digest) => inventory.lockDiagnostics.get(digest),
    preflight: async (digest) => inventory.preflights.get(digest),
    postflight: async (digest) => inventory.postflights.get(digest),
    token: async (digest) => inventory.tokens.get(digest),
    assertBaselineProducer: baselineProducer,
    assertLockAcquisitionProducer: acquisitionProducer,
    assertEnvironmentProducer: environmentProducer,
    assertPostflightProducer: postflightProducer,
  };
  const tokenMemo = new Map<string, M3TokenAuthority>();
  const tokenAuthorities = new Map<string, M3TokenAuthority>();
  for (const [digest, token] of inventory.tokens) {
    const key = `M3_REPOSITORY_STATE_TOKEN:${digest}`;
    try {
      const authority = await validateM3AuthoritativeToken(token, inventory.runId, resolver, tokenMemo);
      if (!baselineAuthoritative.has(authority.baseline.content_sha256) ||
          (authority.approval !== null && !approvalAuthoritative.has(authority.approval.content_sha256))) {
        decisions.set(key, INCOMPLETE);
      } else {
        tokenAuthorities.set(digest, authority); decisions.set(key, AUTHORITATIVE);
      }
    } catch (error: unknown) { decisions.set(key, failureDecision(error)); }
  }

  for (const [digest, preflight] of inventory.preflights) {
    const key = `M3_PREFLIGHT:${digest}`;
    const baseline = inventory.baselines.get(preflight.baseline_runtime_content_sha256);
    if (baseline === undefined) { decisions.set(key, INCOMPLETE); continue; }
    if (!baselineSemantic.has(baseline.content_sha256)) { decisions.set(key, INVALID); continue; }
    let approval: M3BaselineApprovalRuntimeDocument | null = null;
    if (preflight.baseline_approval_runtime_content_sha256 !== null) {
      approval = inventory.approvals.get(preflight.baseline_approval_runtime_content_sha256) ?? null;
      if (approval === null) { decisions.set(key, INCOMPLETE); continue; }
      if (!approvalSemantic.has(approval.content_sha256)) { decisions.set(key, INVALID); continue; }
    }
    try {
      if (preflight.preflight_kind === "FULL") {
        const lockDiagnostic = inventory.lockDiagnostics.get(preflight.lock_diagnostic_content_sha256);
        if (lockDiagnostic === undefined) { decisions.set(key, INCOMPLETE); continue; }
        const lockAcquisition = inventory.lockAcquisitions.get(lockDiagnostic.lock_acquisition_content_sha256);
        if (lockAcquisition === undefined) { decisions.set(key, INCOMPLETE); continue; }
        if (!acquisitionSemantic.has(lockAcquisition.content_sha256)) {
          decisions.set(key, decisions.get(`M3_LOCK_ACQUISITION:${lockAcquisition.content_sha256}`) ?? INVALID); continue;
        }
        if (!baselineAuthoritative.has(baseline.content_sha256) ||
            (approval !== null && !approvalAuthoritative.has(approval.content_sha256))) {
          decisions.set(key, INCOMPLETE); continue;
        }
        await environmentProducer(preflight, lockDiagnostic);
        assertM3FullPreflightSourceSemantics(preflight, baseline, approval, null, lockDiagnostic, lockAcquisition);
        const rooted = [...inventory.tokens.values()].some((token) => token.source === "FULL_PREFLIGHT" &&
          token.source_content_sha256 === digest && tokenAuthorities.has(token.content_sha256));
        decisions.set(key, rooted ? AUTHORITATIVE : UNREFERENCED);
      } else {
        if (!baselineAuthoritative.has(baseline.content_sha256) ||
            (approval !== null && !approvalAuthoritative.has(approval.content_sha256))) {
          decisions.set(key, INCOMPLETE); continue;
        }
        if (preflight.prior_token_content_sha256 === null) { decisions.set(key, INVALID); continue; }
        const prior = inventory.tokens.get(preflight.prior_token_content_sha256);
        if (prior === undefined) { decisions.set(key, INCOMPLETE); continue; }
        if (!tokenAuthorities.has(prior.content_sha256)) {
          decisions.set(key, decisions.get(`M3_REPOSITORY_STATE_TOKEN:${prior.content_sha256}`)?.classification === "INVALID_MANAGED_RECORD" ? INVALID : INCOMPLETE);
          continue;
        }
        const lockDiagnostic = inventory.lockDiagnostics.get(preflight.lock_diagnostic_content_sha256);
        if (lockDiagnostic === undefined) { decisions.set(key, INCOMPLETE); continue; }
        const lockAcquisition = inventory.lockAcquisitions.get(lockDiagnostic.lock_acquisition_content_sha256);
        if (lockAcquisition === undefined) { decisions.set(key, INCOMPLETE); continue; }
        if (!acquisitionSemantic.has(lockAcquisition.content_sha256)) {
          decisions.set(key, decisions.get(`M3_LOCK_ACQUISITION:${lockAcquisition.content_sha256}`) ?? INVALID); continue;
        }
        await environmentProducer(preflight, lockDiagnostic);
        assertM3FastPreflightRecordSemantics(preflight, prior, baseline, approval, lockDiagnostic, lockAcquisition);
        decisions.set(key, AUTHORITATIVE);
      }
    } catch (error: unknown) { decisions.set(key, failureDecision(error)); }
  }

  for (const [digest] of inventory.lockAcquisitions) {
    const key = `M3_LOCK_ACQUISITION:${digest}`;
    if (decisions.has(key)) continue;
    const rooted = [...tokenAuthorities.values()].some((authority) => authority.lockAcquisition.content_sha256 === digest);
    decisions.set(key, rooted ? AUTHORITATIVE : UNREFERENCED);
  }

  for (const [digest, diagnostic] of inventory.lockDiagnostics) {
    const key = `M3_LOCK_DIAGNOSTIC:${digest}`;
    const sources = [...inventory.preflights.values()].filter((source) => source.lock_diagnostic_content_sha256 === digest);
    if (sources.length === 0) { decisions.set(key, UNREFERENCED); continue; }
    const acquisition = inventory.lockAcquisitions.get(diagnostic.lock_acquisition_content_sha256);
    if (acquisition === undefined) { decisions.set(key, INCOMPLETE); continue; }
    const acquisitionDecision = decisions.get(`M3_LOCK_ACQUISITION:${acquisition.content_sha256}`);
    if (!acquisitionSemantic.has(acquisition.content_sha256)) {
      decisions.set(key, acquisitionDecision?.classification === "INCOMPLETE_MANAGED_RECORD_CHAIN" ? INCOMPLETE : INVALID);
      continue;
    }
    let valid = true;
    let incomplete = false;
    for (const source of sources) {
      const baseline = inventory.baselines.get(source.baseline_runtime_content_sha256);
      if (baseline === undefined) { incomplete = true; continue; }
      try { assertM3LockDiagnosticSemantics(diagnostic, acquisition, baseline); } catch { valid = false; }
    }
    if (!valid) decisions.set(key, INVALID);
    else if ([...tokenAuthorities.values()].some((authority) => authority.rootPreflight.lock_diagnostic_content_sha256 === digest)) {
      decisions.set(key, AUTHORITATIVE);
    } else decisions.set(key, incomplete ? INCOMPLETE : UNREFERENCED);
  }

  for (const [digest, postflight] of inventory.postflights) {
    const key = `M3_POSTFLIGHT:${digest}`;
    const prior = inventory.tokens.get(postflight.prior_token_content_sha256);
    const baseline = inventory.baselines.get(postflight.baseline_runtime_content_sha256);
    if (prior === undefined || baseline === undefined) { decisions.set(key, INCOMPLETE); continue; }
    const priorAuthority = tokenAuthorities.get(prior.content_sha256);
    if (priorAuthority === undefined) {
      const priorDecision = decisions.get(`M3_REPOSITORY_STATE_TOKEN:${prior.content_sha256}`);
      decisions.set(key, priorDecision?.classification === "INVALID_MANAGED_RECORD" ? INVALID : INCOMPLETE);
      continue;
    }
    try {
      await postflightProducer(postflight, prior, baseline);
      assertM3PostflightSourceSemantics(postflight, null, prior, baseline, priorAuthority.approval);
      const rooted = [...inventory.tokens.values()].some((token) => token.source === "POSTFLIGHT" &&
        token.source_content_sha256 === digest && tokenAuthorities.has(token.content_sha256));
      decisions.set(key, rooted ? AUTHORITATIVE : UNREFERENCED);
    } catch (error: unknown) { decisions.set(key, failureDecision(error)); }
  }

  for (const [physicalDigest, authority] of terminalSemantic) {
    const key = `M3_TERMINAL_RETENTION_AUTHORITY:${physicalDigest}`;
    if (!baselineAuthoritative.has(authority.baseline_runtime_content_sha256) ||
        (authority.baseline_approval_runtime_content_sha256 !== null &&
         !approvalAuthoritative.has(authority.baseline_approval_runtime_content_sha256))) decisions.set(key, INCOMPLETE);
    else decisions.set(key, AUTHORITATIVE);
  }

  for (const result of preliminaryValidResults) {
    const key = `M3_RETENTION_RESULT:${result.content_sha256}`;
    const authorityEntry = [...terminalSemantic].find(([, authority]) => authority.content_sha256 === result.terminal_authority_content_sha256);
    if (!baselineAuthoritative.has(result.baseline_runtime_content_sha256) || authorityEntry === undefined ||
        decisions.get(`M3_TERMINAL_RETENTION_AUTHORITY:${authorityEntry[0]}`)?.classification !== "AUTHORITATIVE_MANAGED_RECORD") {
      decisions.set(key, INCOMPLETE);
    } else decisions.set(key, AUTHORITATIVE);
  }

  const authoritativeBlobReferences = new Set<string>();
  for (const digest of baselineAuthoritative) {
    for (const path of inventory.baselines.get(digest)!.paths) if (path.blob !== null) authoritativeBlobReferences.add(path.blob.blob_sha256);
  }
  for (const digest of inventory.blobDigests) {
    decisions.set(`M3_BASELINE_BLOB:${digest}`, authoritativeBlobReferences.has(digest) ? AUTHORITATIVE : UNCOMMITTED);
  }

  return inventory.objects.map((object) => ({
    object,
    ...(decisions.get(objectKey(object)) ?? INVALID),
  })).sort((left, right) => compareText(left.object.relativePath, right.object.relativePath) ||
    compareText(left.object.kind, right.object.kind));
}
