export type SecureFilesystemErrorCode =
  | "INVALID_ARGUMENT"
  | "SECURE_WRITE_PRIMITIVE_UNAVAILABLE"
  | "COMMAND_SANDBOX_UNAVAILABLE"
  | "NETWORK_SANDBOX_UNAVAILABLE"
  | "SECURE_FS_CAPABILITY_MISMATCH"
  | "REPOSITORY_AUTHORITY_INVALID"
  | "REPOSITORY_ROOT_MISMATCH"
  | "FINAL_TARGET_IDENTITY_MISMATCH"
  | "ROLLBACK_UNCERTAIN"
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
  | "PARENT_IDENTITY_DRIFT"
  | "PREIMAGE_MISMATCH"
  | "TARGET_ALREADY_EXISTS"
  | "TARGET_MISSING"
  | "PATCH_LIMIT_EXCEEDED"
  | "READ_LIMIT_EXCEEDED"
  | "SEARCH_LIMIT_EXCEEDED"
  | "LIST_LIMIT_EXCEEDED"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "SECURE_WRITE_UNCERTAIN"
  | "RESIDUE_IDENTITY_MISMATCH"
  | "HELPER_PROTOCOL_ERROR";

/** Bounded M4 secure-filesystem failure. Details never contain file bytes. */
export class SecureFilesystemError extends Error {
  public readonly code: SecureFilesystemErrorCode;
  public readonly details: Readonly<Record<string, string | number | boolean | null>>;

  public constructor(
    code: SecureFilesystemErrorCode,
    message: string,
    details: Readonly<Record<string, string | number | boolean | null>> = {},
    options: ErrorOptions = {},
  ) {
    super(`${code}: ${message}`, options);
    this.name = "SecureFilesystemError";
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function secureFilesystemError(
  code: SecureFilesystemErrorCode,
  message: string,
  cause: unknown,
  details: Readonly<Record<string, string | number | boolean | null>> = {},
): SecureFilesystemError {
  return new SecureFilesystemError(code, message, details, { cause });
}
