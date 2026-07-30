import type {
  M3BaselineApprovalRuntimeDocument,
  M3BaselineRuntimeDocument,
  M3LockAcquisitionDocument,
  M3LockDiagnosticDocument,
  M3PostflightDocument,
  M3PreflightDocument,
  M3RepositoryStateTokenDocument,
  M3TerminalRetentionAuthorityDocument,
  WorkflowState,
} from "../schemas/index.js";
import {
  M3AuthorityValidationError,
  assertM3BaselineApprovalSemantics,
  assertM3BaselineRuntimeSemantics,
  assertM3FastPreflightRecordSemantics,
  assertM3FullPreflightSourceSemantics,
  assertM3PostflightSourceSemantics,
  expectedM3TerminalRetentionAuthority,
  requireM3BaselineApprovalSemantics,
} from "../persistence/m3-authority.js";
import { RepositoryGuardError, type RepositoryGuardErrorCode } from "./errors.js";
import {
  assertDurableBaselineProducerSemantics,
  assertDurableEnvironmentProducerSemantics,
  assertDurablePostflightProducerSemantics,
} from "./semantic-context.js";

function mappedSemanticError(error: unknown, fallback: RepositoryGuardErrorCode): RepositoryGuardError {
  if (!(error instanceof M3AuthorityValidationError)) {
    return new RepositoryGuardError(fallback, "M3 semantic authority validation failed", {}, { cause: error });
  }
  const precise = new Set<RepositoryGuardErrorCode>([
    "BASELINE_PROVENANCE_INVALID",
    "BASELINE_APPROVAL_REPOSITORY_MISMATCH",
    "BASELINE_APPROVAL_WORKTREE_MISMATCH",
    "BASELINE_APPROVAL_BRANCH_MISMATCH",
    "BASELINE_APPROVAL_HEAD_MISMATCH",
    "RETENTION_NOT_TERMINAL",
  ]);
  const code = precise.has(error.semanticCode as RepositoryGuardErrorCode)
    ? error.semanticCode as RepositoryGuardErrorCode
    : fallback;
  return new RepositoryGuardError(code, "M3 durable semantic authority is inconsistent", {}, { cause: error });
}

/** Exact cross-field checks shared by every durable baseline consumer. */
export function assertBaselineRuntimeSemantics(baseline: M3BaselineRuntimeDocument): void {
  try {
    assertM3BaselineRuntimeSemantics(baseline);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "BASELINE_PROVENANCE_INVALID");
  }
}

export async function assertBaselineProducerSemantics(
  baseline: M3BaselineRuntimeDocument,
  allBaselines: readonly M3BaselineRuntimeDocument[],
): Promise<void> {
  try {
    await assertDurableBaselineProducerSemantics(baseline, allBaselines);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "BASELINE_PROVENANCE_INVALID");
  }
}

export async function assertFullEnvironmentProducerSemantics(
  source: M3PreflightDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<void> {
  try {
    await assertDurableEnvironmentProducerSemantics(source, lockDiagnostic);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH");
  }
}

export async function assertPostflightProducerSemantics(
  source: M3PostflightDocument,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
): Promise<void> {
  try {
    await assertDurablePostflightProducerSemantics(source, prior, baseline);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "POSTFLIGHT_DELTA_MISMATCH");
  }
}

/** Exact dirty-approval repository, snapshot, and path-policy binding. */
export function assertBaselineApprovalMatches(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument,
): void {
  try {
    assertM3BaselineApprovalSemantics(baseline, approval);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "BASELINE_APPROVAL_MISMATCH");
  }
}

export function requireBaselineApprovalSemantics(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
): void {
  try {
    requireM3BaselineApprovalSemantics(baseline, approval);
  } catch (error: unknown) {
    if (error instanceof M3AuthorityValidationError &&
        (error.semanticCode === "BASELINE_APPROVAL_RECORD_MISSING" || error.kind === "MISSING")) {
      throw new RepositoryGuardError("BASELINE_DIRTY_NOT_APPROVED", "Approved-dirty baseline requires exact owner approval", {}, { cause: error });
    }
    throw mappedSemanticError(error, "BASELINE_APPROVAL_MISMATCH");
  }
}

export function assertFullPreflightSourceSemantics(
  source: M3PreflightDocument,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  token: M3RepositoryStateTokenDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
  lockAcquisition: M3LockAcquisitionDocument,
): void {
  try {
    assertM3FullPreflightSourceSemantics(source, baseline, approval, token, lockDiagnostic, lockAcquisition);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH");
  }
}

export function assertFastPreflightRecordSemantics(
  source: M3PreflightDocument,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  lockDiagnostic: M3LockDiagnosticDocument,
  lockAcquisition: M3LockAcquisitionDocument,
): void {
  try {
    assertM3FastPreflightRecordSemantics(source, prior, baseline, approval, lockDiagnostic, lockAcquisition);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH");
  }
}

export function assertPostflightSourceSemantics(
  source: M3PostflightDocument,
  successor: M3RepositoryStateTokenDocument,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
): void {
  try {
    assertM3PostflightSourceSemantics(source, successor, prior, baseline, approval);
  } catch (error: unknown) {
    const fallback = error instanceof M3AuthorityValidationError &&
      (error.semanticCode === "POSTFLIGHT_SCOPE_IDENTITY_MISMATCH" ||
       error.semanticCode === "POSTFLIGHT_CLAIMED_PATHS_MISMATCH" ||
       error.semanticCode === "POSTFLIGHT_DELTA_MISMATCH" ||
       error.semanticCode === "POSTFLIGHT_SOURCE_SEMANTIC_MISMATCH")
      ? error.semanticCode as RepositoryGuardErrorCode
      : "STATE_TOKEN_PROVENANCE_INVALID";
    throw mappedSemanticError(error, fallback);
  }
}

export function expectedTerminalRetentionAuthority(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  terminalWorkflowState: WorkflowState,
  terminalTimestamp: string,
): M3TerminalRetentionAuthorityDocument {
  try {
    return expectedM3TerminalRetentionAuthority(baseline, approval, terminalWorkflowState, terminalTimestamp);
  } catch (error: unknown) {
    throw mappedSemanticError(error, "CLEANUP_UNCERTAIN");
  }
}
