import type { M3RepositoryIdentityDocument, M4MutationJournal, M4PathRule, M4SecureFilesystemCapabilityDocument } from "../schemas/index.js";
import type { Sha256Digest } from "../identity/index.js";

export interface RootIdentity {
  readonly realpath: string;
  readonly device: number;
  readonly inode: number;
}

export interface SecureFileMetadata {
  readonly digest: `sha256:${string}`;
  readonly size: number;
  readonly mode: number;
  readonly device: number;
  readonly inode: number;
  readonly nlink: number;
}

export interface SecureReadRequest {
  readonly path: string;
  readonly offset: number;
  readonly length: number;
  readonly maximumBytes: number;
  readonly hashLimitBytes: number;
}

export interface SecureReadResult {
  readonly path: string;
  readonly metadata: SecureFileMetadata;
  readonly offset: number;
  readonly byteCount: number;
  readonly dataBase64: string;
}

export type SecureListEntryType = "REGULAR" | "DIRECTORY" | "SYMLINK" | "FIFO" | "SOCKET" | "CHAR_DEVICE" | "BLOCK_DEVICE" | "SPECIAL";

export interface SecureListEntry {
  readonly path: string;
  readonly type: SecureListEntryType;
  readonly mode: number;
  readonly size: number;
  readonly digest: `sha256:${string}` | null;
}

export interface SecureListRequest {
  readonly path: string | null;
  readonly maximumDepth: number;
  readonly maximumEntries: number;
  readonly maximumMetadataBytes: number;
  readonly hashFiles: boolean;
  readonly hashLimitBytes: number;
}

export interface SecureListResult {
  readonly path: string | null;
  readonly entries: readonly SecureListEntry[];
  readonly metadataBytes: number;
}

export interface SecureFilesystemOptions {
  readonly repository: M3RepositoryIdentityDocument;
  readonly capability: M4SecureFilesystemCapabilityDocument;
  readonly readablePaths: readonly M4PathRule[];
}

export interface SecureFilesystem {
  readonly capability: M4SecureFilesystemCapabilityDocument;
  readScoped(request: SecureReadRequest): Promise<SecureReadResult>;
  listScoped(request: SecureListRequest): Promise<SecureListResult>;
}

export type SecureMutationOperation = "CREATE" | "REPLACE" | "DELETE";

export interface SecureMutationRequest {
  readonly operation: SecureMutationOperation;
  readonly path: string;
  readonly expected: { readonly digest: string | null; readonly size: number | null; readonly mode: number | null };
  readonly replacement: Uint8Array | null;
  readonly finalMode: number | null;
  readonly hashLimitBytes: number;
}

/** Internal M3/M4 authority supplied by the scoped gateway; not a package export. */
export interface SecureMutationAuthority {
  readonly runId: string;
  readonly repositoryIdentityContentSha256: Sha256Digest;
  readonly worktreeIdentity: Sha256Digest;
  readonly priorStateTokenContentSha256: Sha256Digest | null;
}

export interface SecureMutationOutcome {
  readonly path: string;
  readonly operation: SecureMutationOperation;
  readonly before: SecureFileMetadata | null;
  readonly after: SecureFileMetadata | null;
  readonly fileFsync: boolean;
  readonly atomicRename: boolean;
  readonly directoryFsync: boolean;
  readonly rollback: "NOT_REQUIRED" | "SUCCEEDED" | "FAILED";
  readonly journal: M4MutationJournal;
}
