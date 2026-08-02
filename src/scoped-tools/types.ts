import type { Sha256Digest } from "../identity/index.js";
import type { WorktreeLockHandle, FingerprintedFileInput } from "../repository/index.js";
import type {
  M3BaselineRuntimeDocument,
  M3RepositoryIdentityDocument,
  M3RepositoryStateTokenDocument,
  M4CommandCatalogDocument,
  M4CommandResultDocument,
  M4MutationReceiptDocument,
  M4ScopedToolPolicyDocument,
  M4ToolResultDocument,
} from "../schemas/index.js";
import type { SecureFileMetadata, SecureListEntry } from "../secure-fs/index.js";

export interface CreateScopedToolGatewayInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly repository: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly acceptedState: M3RepositoryStateTokenDocument;
  readonly lock: WorktreeLockHandle;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly editablePaths: readonly string[];
  readonly frozenPaths: readonly string[];
  readonly taskScopeIdentity: Sha256Digest;
  readonly toolPolicy: M4ScopedToolPolicyDocument;
  readonly commandCatalog: M4CommandCatalogDocument;
  readonly temporaryRoot: string;
}

export interface ScopedReadRequest {
  readonly stateTokenContentSha256: Sha256Digest;
  readonly path: string;
  readonly offset: number;
  readonly length: number;
  readonly mode: "TEXT" | "BINARY";
}

export interface ScopedReadResult {
  readonly metadata: SecureFileMetadata;
  readonly dataClass: string;
  readonly content: string | null;
  readonly contentEncoding: "UTF8" | "BASE64" | "METADATA_ONLY";
  readonly resultRecord: M4ToolResultDocument;
}

export interface ScopedListRequest {
  readonly stateTokenContentSha256: Sha256Digest;
  readonly path: string;
  readonly maximumDepth: number;
  readonly hashFiles: boolean;
}

export interface ScopedListResult {
  readonly entries: readonly SecureListEntry[];
  readonly resultRecord: M4ToolResultDocument;
}

export interface ScopedSearchRequest {
  readonly stateTokenContentSha256: Sha256Digest;
  readonly literal: string;
  readonly caseSensitive: boolean;
  readonly includePaths: readonly string[];
  readonly excludePaths: readonly string[];
  readonly maximumFiles: number;
  readonly maximumBytes: number;
  readonly maximumMatches: number;
  readonly maximumLineLength: number;
}

export interface ScopedSearchMatch {
  readonly path: string;
  readonly line: number;
  readonly column: number;
  readonly lineDigest: Sha256Digest;
  readonly preview: string | null;
}

export interface ScopedSearchResult {
  readonly matches: readonly ScopedSearchMatch[];
  readonly filesSearched: number;
  readonly bytesSearched: number;
  readonly resultRecord: M4ToolResultDocument;
}

export type ScopedGitInspection = "STATUS" | "DIFF_NAME_STATUS" | "DIFF_NUMSTAT" | "SHOW_PATH_AT_HEAD" | "LS_FILES" | "WORKTREE_IDENTITY";

export interface ScopedGitInspectionRequest {
  readonly stateTokenContentSha256: Sha256Digest;
  readonly operation: ScopedGitInspection;
  readonly path: string | null;
}

export interface ScopedGitInspectionResult {
  readonly output: string;
  readonly resultRecord: M4ToolResultDocument;
}

export interface ScopedEvidenceReadRequest {
  readonly stateTokenContentSha256: Sha256Digest;
  readonly kind: string;
  readonly contentSha256: Sha256Digest;
}

export interface ScopedEvidenceReadResult {
  readonly document: Readonly<Record<string, unknown>>;
  readonly resultRecord: M4ToolResultDocument;
}

export interface ScopedPatchRequest {
  readonly stateTokenContentSha256: Sha256Digest;
  readonly lockAcquisitionContentSha256: Sha256Digest;
  readonly operation: "CREATE" | "REPLACE" | "DELETE";
  readonly path: string;
  readonly ownershipClass: "OWNER_AUTHORITY" | "OWNER_ACCEPTED_MUTABLE" | "PREEXISTING_UNRELATED" | "GENERATED_ACCEPTED_BASELINE";
  readonly dataClass: "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE" | "SECRET" | "LARGE_BINARY" | "HASH_ONLY";
  readonly expectedPreimageExists: boolean;
  readonly expectedPreimageDigest: Sha256Digest | null;
  readonly expectedPreimageSize: number | null;
  readonly expectedPreimageMode: number | null;
  readonly replacementBytes: Uint8Array | null;
  readonly requestedFinalMode: number | null;
}

export interface ScopedPatchResult {
  readonly receipt: M4MutationReceiptDocument;
  readonly acceptedState: M3RepositoryStateTokenDocument;
}

export interface ScopedCommandRequest {
  readonly commandId: string;
  readonly stateTokenContentSha256: Sha256Digest;
}

export interface ScopedCommandResult {
  readonly record: M4CommandResultDocument;
  readonly stdoutBase64: string;
  readonly stderrBase64: string;
  readonly acceptedState: M3RepositoryStateTokenDocument | null;
}

export interface ScopedToolGateway {
  readonly acceptedState: M3RepositoryStateTokenDocument;
  read_scoped(request: ScopedReadRequest): Promise<ScopedReadResult>;
  list_scoped(request: ScopedListRequest): Promise<ScopedListResult>;
  search_scoped(request: ScopedSearchRequest): Promise<ScopedSearchResult>;
  inspect_git_scoped(request: ScopedGitInspectionRequest): Promise<ScopedGitInspectionResult>;
  read_evidence(request: ScopedEvidenceReadRequest): Promise<ScopedEvidenceReadResult>;
  apply_patch_scoped(request: ScopedPatchRequest): Promise<ScopedPatchResult>;
  run_inspection_command(request: ScopedCommandRequest): Promise<ScopedCommandResult>;
  run_task_command(request: ScopedCommandRequest): Promise<ScopedCommandResult>;
  run_verification_command(request: ScopedCommandRequest): Promise<ScopedCommandResult>;
}
