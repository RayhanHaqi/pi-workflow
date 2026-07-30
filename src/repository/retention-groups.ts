import type {
  M3BaselineApprovalRuntimeDocument,
  M3BaselineRuntimeDocument,
  M3RetentionResultDocument,
  M3TerminalRetentionAuthorityDocument,
  WorkflowState,
} from "../schemas/index.js";
import {
  M3AuthorityValidationError,
  assertM3RetentionResultSemantics,
  buildM3RetentionAuthorityContext,
  deriveM3RetentionResultAggregate,
  exactM3RetentionDeletionProof,
  type RetentionAuthorityContext,
  type RetentionLogicalReference,
  type RetentionPhysicalGroup,
  type RetentionProof,
} from "../persistence/m3-authority.js";
import { RepositoryGuardError } from "./errors.js";

export type {
  RetentionAuthorityContext,
  RetentionLogicalReference,
  RetentionPhysicalGroup,
  RetentionProof,
};

function cleanupError(error: unknown): RepositoryGuardError {
  if (error instanceof RepositoryGuardError) return error;
  return new RepositoryGuardError(
    "CLEANUP_UNCERTAIN",
    error instanceof M3AuthorityValidationError
      ? "Retention semantic authority is incomplete or inconsistent"
      : "Retention semantic authority could not be validated",
    {},
    { cause: error },
  );
}

/** Shared exact logical-to-physical retention authority projection. */
export function buildRetentionAuthorityContext(
  workflowState: WorkflowState,
  baselines: readonly M3BaselineRuntimeDocument[],
  approvals: readonly M3BaselineApprovalRuntimeDocument[],
  authorities: readonly M3TerminalRetentionAuthorityDocument[],
): RetentionAuthorityContext {
  try {
    return buildM3RetentionAuthorityContext(workflowState, baselines, approvals, authorities);
  } catch (error: unknown) {
    throw cleanupError(error);
  }
}

export function assertRetentionResultSemantics(
  record: M3RetentionResultDocument,
  context: RetentionAuthorityContext,
  allResults: readonly M3RetentionResultDocument[],
): void {
  try {
    assertM3RetentionResultSemantics(record, context, allResults);
  } catch (error: unknown) {
    throw cleanupError(error);
  }
}

export function deriveRetentionResultAggregate(record: M3RetentionResultDocument) {
  try {
    return deriveM3RetentionResultAggregate(record);
  } catch (error: unknown) {
    throw cleanupError(error);
  }
}

/** Shared exact deletion-proof selector used by quota reconciliation and cleanup. */
export function exactRetentionDeletionProof(
  results: readonly M3RetentionResultDocument[],
  context: RetentionAuthorityContext,
  digest: string,
): RetentionProof | null {
  try {
    return exactM3RetentionDeletionProof(results, context, digest);
  } catch (error: unknown) {
    throw cleanupError(error);
  }
}
