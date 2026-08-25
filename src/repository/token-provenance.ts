import type {
  M3BaselineApprovalRuntimeDocument,
  M3BaselineRuntimeDocument,
  M3LockAcquisitionDocument,
  M3LockDiagnosticDocument,
  M3PostflightDocument,
  M3PreflightDocument,
  M3RepositoryStateTokenDocument,
  M3ResumeLockHandoverDocument,
} from "../schemas/index.js";
import {
  M3AuthorityValidationError,
  validateM3AuthoritativeToken,
  type M3AuthorityResolver,
} from "../persistence/m3-authority.js";
import { assertGlobalLockAcquisition } from "./acquisition.js";
import { assertEnvironmentFingerprintContinuity } from "./environment.js";
import { RepositoryGuardError, repositoryGuardError, type RepositoryGuardErrorCode } from "./errors.js";
import {
  assertBaselineProducerSemantics,
  assertFullEnvironmentProducerSemantics,
  assertPostflightProducerSemantics,
} from "./provenance.js";
import {
  assertManagedRecordAuthoritative,
  canonicalJsonRecordBytes,
  loadM3Record,
  m3RecordExists,
  readM3Records,
  requireExactM3Record,
  type M3RecordKind,
  type M3StorageLocation,
} from "./storage.js";
import { detachedFrozen } from "./utils.js";

const MAX_TOKEN_CHAIN_DEPTH = 64;

type ResolverDocument =
  | M3BaselineRuntimeDocument
  | M3BaselineApprovalRuntimeDocument
  | M3LockAcquisitionDocument
  | M3LockDiagnosticDocument
  | M3PreflightDocument
  | M3PostflightDocument
  | M3ResumeLockHandoverDocument
  | M3RepositoryStateTokenDocument;

async function optionalRecord(
  location: M3StorageLocation,
  kind: M3RecordKind,
  digest: string,
): Promise<ResolverDocument | undefined> {
  if (!await m3RecordExists(location, kind, digest)) return undefined;
  const mismatch: RepositoryGuardErrorCode = kind === "BASELINE"
    ? "BASELINE_RECORD_MISMATCH"
    : kind === "BASELINE_APPROVAL"
      ? "BASELINE_APPROVAL_RECORD_MISMATCH"
      : "STATE_TOKEN_PROVENANCE_INVALID";
  return loadM3Record(location, kind, digest, mismatch, mismatch) as Promise<ResolverDocument>;
}

function resolverFor(location: M3StorageLocation): M3AuthorityResolver {
  const baselines = readM3Records(location, "BASELINE");
  return {
    baseline: async (digest) => optionalRecord(location, "BASELINE", digest) as Promise<M3BaselineRuntimeDocument | undefined>,
    approval: async (digest) => optionalRecord(location, "BASELINE_APPROVAL", digest) as Promise<M3BaselineApprovalRuntimeDocument | undefined>,
    lockAcquisition: async (digest) => optionalRecord(location, "LOCK_ACQUISITION", digest) as Promise<M3LockAcquisitionDocument | undefined>,
    lockDiagnostic: async (digest) => optionalRecord(location, "LOCK_DIAGNOSTIC", digest) as Promise<M3LockDiagnosticDocument | undefined>,
    preflight: async (digest) => optionalRecord(location, "PREFLIGHT", digest) as Promise<M3PreflightDocument | undefined>,
    postflight: async (digest) => optionalRecord(location, "POSTFLIGHT", digest) as Promise<M3PostflightDocument | undefined>,
    resumeHandover: async (digest) => optionalRecord(location, "RESUME_LOCK_HANDOVER", digest) as Promise<M3ResumeLockHandoverDocument | undefined>,
    token: async (digest) => optionalRecord(location, "REPOSITORY_STATE_TOKEN", digest) as Promise<M3RepositoryStateTokenDocument | undefined>,
    assertBaselineProducer: async (baseline) => assertBaselineProducerSemantics(baseline, await baselines),
    assertLockAcquisitionProducer: async (acquisition) => assertGlobalLockAcquisition(location.stateRoot, acquisition),
    assertEnvironmentProducer: assertFullEnvironmentProducerSemantics,
    assertResumeHandoverEnvironment: async (rootPreflight, lockDiagnostic) => {
      // Exact live-environment continuity across the A→B generation change,
      // surfaced as the existing ENVIRONMENT_DRIFT fail-closed code.
      await assertEnvironmentFingerprintContinuity(rootPreflight.environment_fingerprint, rootPreflight.repository, lockDiagnostic);
    },
    assertPostflightProducer: assertPostflightProducerSemantics,
  };
}

function tokenSemanticError(error: M3AuthorityValidationError): RepositoryGuardError {
  const direct = new Set<RepositoryGuardErrorCode>([
    "BASELINE_RECORD_MISSING",
    "BASELINE_APPROVAL_RECORD_MISSING",
    "STATE_TOKEN_RECORD_MISSING",
    "STATE_TOKEN_SOURCE_MISSING",
    "STATE_TOKEN_CHAIN_TOO_DEEP",
    "STATE_TOKEN_CHAIN_LOOP",
  ]);
  const code = direct.has(error.semanticCode as RepositoryGuardErrorCode)
    ? error.semanticCode as RepositoryGuardErrorCode
    : "STATE_TOKEN_PROVENANCE_INVALID";
  return new RepositoryGuardError(code, "Repository-state token semantic provenance is invalid", {}, { cause: error });
}

export interface AuthoritativeToken {
  readonly token: M3RepositoryStateTokenDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly lockAcquisition: M3LockAcquisitionDocument;
  readonly rootPreflight: M3PreflightDocument;
  readonly chainDepth: number;
  readonly mayAdvance: boolean;
}

/** Common authoritative loader shared semantically with managed inspection. */
export async function loadAuthoritativeToken(
  location: M3StorageLocation,
  providedToken: M3RepositoryStateTokenDocument,
  providedBaseline: M3BaselineRuntimeDocument,
): Promise<AuthoritativeToken> {
  try {
    const token = await requireExactM3Record(
      location,
      "REPOSITORY_STATE_TOKEN",
      providedToken,
      "STATE_TOKEN_RECORD_MISSING",
      "STATE_TOKEN_PROVENANCE_INVALID",
    );
    // Every successor is required to retain one baseline. Reconcile that root
    // once rather than recursively re-inspecting the complete managed graph.
    try {
      await assertManagedRecordAuthoritative(location, "M3_BASELINE", providedBaseline.content_sha256);
    } catch (error: unknown) {
      if (error instanceof RepositoryGuardError && error.code === "BASELINE_PROVENANCE_INVALID") {
        throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Accepted token baseline lost retained-population authority", {}, { cause: error });
      }
      throw error;
    }
    const authority = await validateM3AuthoritativeToken(token, location.runId, resolverFor(location));
    if (!canonicalJsonRecordBytes(authority.baseline).equals(canonicalJsonRecordBytes(providedBaseline))) {
      throw new RepositoryGuardError("STATE_TOKEN_PROVENANCE_INVALID", "Caller baseline differs from the token's exact durable baseline");
    }
    return detachedFrozen({
      token,
      baseline: authority.baseline,
      approval: authority.approval,
      lockAcquisition: authority.lockAcquisition,
      rootPreflight: authority.rootPreflight,
      chainDepth: authority.chainDepth,
      mayAdvance: authority.chainDepth < MAX_TOKEN_CHAIN_DEPTH,
    });
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError) throw error;
    if (error instanceof M3AuthorityValidationError) throw tokenSemanticError(error);
    throw repositoryGuardError("STATE_TOKEN_PROVENANCE_INVALID", "Repository-state token provenance could not be verified", error);
  }
}
