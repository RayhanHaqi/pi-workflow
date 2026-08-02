export type ScopedToolGatewayErrorCode =
  | "INVALID_ARGUMENT"
  | "SECURE_WRITE_PRIMITIVE_UNAVAILABLE"
  | "SECURE_FS_CAPABILITY_MISMATCH"
  | "REPOSITORY_AUTHORITY_INVALID"
  | "REPOSITORY_ROOT_MISMATCH"
  | "FINAL_TARGET_IDENTITY_MISMATCH"
  | "INVALID_CANONICAL_PATH"
  | "PATH_OUTSIDE_ROOT"
  | "PATH_NOT_READABLE"
  | "PATH_NOT_EDITABLE"
  | "FROZEN_PATH"
  | "OWNERSHIP_FORBIDS_MUTATION"
  | "DATA_POLICY_FORBIDS_READ"
  | "DATA_POLICY_FORBIDS_MUTATION"
  | "SYMLINK_PATH"
  | "MAGICLINK_PATH"
  | "SPECIAL_FILE"
  | "HARDLINK_TARGET"
  | "HARDLINK_WRITE_SCOPE_UNSAFE"
  | "SECRET_METADATA_FORBIDDEN"
  | "EXECUTION_INPUT_DRIFT"
  | "COMMAND_CWD_IDENTITY_DRIFT"
  | "GENERIC_DISPATCHER_FORBIDDEN"
  | "OUTPUT_EVIDENCE_INCONSISTENT"
  | "CAPABILITY_PROVENANCE_INVALID"
  | "M4_RECORD_SEMANTICS_INVALID"
  | "MUTATION_RECEIPT_INCONSISTENT"
  | "ROLLBACK_UNCERTAIN"
  | "PARENT_IDENTITY_DRIFT"
  | "PREIMAGE_MISMATCH"
  | "TARGET_ALREADY_EXISTS"
  | "TARGET_MISSING"
  | "PATCH_LIMIT_EXCEEDED"
  | "READ_LIMIT_EXCEEDED"
  | "SEARCH_LIMIT_EXCEEDED"
  | "LIST_LIMIT_EXCEEDED"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "LOCK_NOT_HELD"
  | "LOCK_LOST"
  | "CONCURRENT_OPERATION"
  | "STATE_TOKEN_PROVENANCE_INVALID"
  | "FAST_PREFLIGHT_FAILED"
  | "POSTFLIGHT_FAILED"
  | "SECURE_WRITE_UNCERTAIN"
  | "RESIDUE_IDENTITY_MISMATCH"
  | "EVIDENCE_PUBLICATION_FAILED"
  | "EVIDENCE_NOT_FOUND"
  | "UNKNOWN_COMMAND_ID"
  | "COMMAND_CLASS_MISMATCH"
  | "COMMAND_SPEC_MISMATCH"
  | "COMMAND_FORBIDDEN"
  | "COMMAND_SANDBOX_UNAVAILABLE"
  | "NETWORK_SANDBOX_UNAVAILABLE"
  | "COMMAND_TIMEOUT"
  | "COMMAND_OUTPUT_LIMIT"
  | "COMMAND_SIGNALLED"
  | "COMMAND_EXIT_CODE_UNEXPECTED"
  | "COMMAND_UNEXPECTED_REPOSITORY_DELTA";

/** Security-relevant M4 gateway failure with metadata-only diagnostics. */
export class ScopedToolGatewayError extends Error {
  public readonly code: ScopedToolGatewayErrorCode;
  public readonly details: Readonly<Record<string, string | number | boolean | null>>;

  public constructor(
    code: ScopedToolGatewayErrorCode,
    message: string,
    details: Readonly<Record<string, string | number | boolean | null>> = {},
    options: ErrorOptions = {},
  ) {
    super(`${code}: ${message}`, options);
    this.name = "ScopedToolGatewayError";
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function scopedToolError(
  code: ScopedToolGatewayErrorCode,
  message: string,
  cause: unknown,
  details: Readonly<Record<string, string | number | boolean | null>> = {},
): ScopedToolGatewayError {
  return new ScopedToolGatewayError(code, message, details, { cause });
}
