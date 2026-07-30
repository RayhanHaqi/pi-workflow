export type RepositoryGuardErrorCode =
  | "INVALID_ARGUMENT"
  | "WRONG_REPOSITORY"
  | "WRONG_WORKTREE"
  | "WRONG_BRANCH"
  | "DETACHED_HEAD_UNEXPECTED"
  | "HEAD_DRIFT"
  | "UPSTREAM_DRIFT"
  | "WORKTREE_LIST_DRIFT"
  | "GIT_OPERATION_IN_PROGRESS"
  | "GIT_CONFLICT_PRESENT"
  | "GIT_INDEX_LOCK_PRESENT"
  | "BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT"
  | "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING"
  | "INVALID_GIT_OUTPUT"
  | "GIT_INSPECTION_FAILED"
  | "NOT_A_GIT_WORKTREE"
  | "MISSING_HEAD"
  | "UNREADABLE_GIT_DIRECTORY"
  | "BASELINE_DIRTY_NOT_APPROVED"
  | "BASELINE_APPROVAL_MISMATCH"
  | "BASELINE_APPROVAL_REPOSITORY_MISMATCH"
  | "BASELINE_APPROVAL_WORKTREE_MISMATCH"
  | "BASELINE_APPROVAL_BRANCH_MISMATCH"
  | "BASELINE_APPROVAL_HEAD_MISMATCH"
  | "BASELINE_APPROVAL_SEMANTIC_MISMATCH"
  | "BASELINE_PATH_UNCLASSIFIED"
  | "BASELINE_SECRET_PRESENT"
  | "BASELINE_SPECIAL_PATH"
  | "BASELINE_BLOB_LIMIT_EXCEEDED"
  | "BASELINE_RECORD_MISSING"
  | "BASELINE_RECORD_MISMATCH"
  | "BASELINE_APPROVAL_RECORD_MISSING"
  | "BASELINE_APPROVAL_RECORD_MISMATCH"
  | "BASELINE_PROVENANCE_INVALID"
  | "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN"
  | "STATE_TOKEN_RECORD_MISSING"
  | "STATE_TOKEN_PROVENANCE_INVALID"
  | "STATE_TOKEN_SOURCE_MISSING"
  | "STATE_TOKEN_CHAIN_TOO_DEEP"
  | "STATE_TOKEN_CHAIN_LOOP"
  | "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN"
  | "STATE_ROOT_LIMIT_EXCEEDED"
  | "INSTRUCTION_DRIFT"
  | "AUTHORITY_DRIFT"
  | "LOCK_BUSY"
  | "LOCK_LOST"
  | "LOCK_GUARDIAN_START_FAILED"
  | "LOCK_RELEASE_FAILED"
  | "INVALID_LOCK_PATH"
  | "UNEXPECTED_REPOSITORY_DELTA"
  | "POSTFLIGHT_SCOPE_IDENTITY_MISMATCH"
  | "POSTFLIGHT_CLAIMED_PATHS_MISMATCH"
  | "POSTFLIGHT_DELTA_MISMATCH"
  | "POSTFLIGHT_SOURCE_SEMANTIC_MISMATCH"
  | "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH"
  | "FORBIDDEN_PATH_CHANGED"
  | "INDEX_DRIFT"
  | "BLOCKED_STATE_DRIFT"
  | "RETENTION_TIMESTAMP_UNAVAILABLE"
  | "RETENTION_NOT_TERMINAL"
  | "RETENTION_DEADLINE_NOT_REACHED"
  | "RETENTION_RESULT_PUBLICATION_FAILED"
  | "CLEANUP_UNCERTAIN"
  | "STATE_STORAGE_INVALID"
  | "UNSUPPORTED_REPOSITORY_STATE"
  | "ENVIRONMENT_DRIFT";

/** Typed, bounded M3 failure. Messages contain metadata only, never repository file bytes. */
export class RepositoryGuardError extends Error {
  public readonly code: RepositoryGuardErrorCode;
  public readonly details: Readonly<Record<string, string | number | boolean | null>>;

  public constructor(
    code: RepositoryGuardErrorCode,
    message: string,
    details: Readonly<Record<string, string | number | boolean | null>> = {},
    options: ErrorOptions = {},
  ) {
    super(`${code}: ${message}`, options);
    this.name = "RepositoryGuardError";
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function repositoryGuardError(
  code: RepositoryGuardErrorCode,
  message: string,
  cause: unknown,
  details: Readonly<Record<string, string | number | boolean | null>> = {},
): RepositoryGuardError {
  return new RepositoryGuardError(code, message, details, { cause });
}
