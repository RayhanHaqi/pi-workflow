export { SecureFilesystemError } from "./errors.js";
export { probeSecureFilesystemCapabilities } from "./capabilities.js";
export { createSecureFilesystem } from "./client.js";

export type { SecureFilesystemErrorCode } from "./errors.js";
export type {
  SecureFileMetadata,
  SecureFilesystem,
  SecureFilesystemOptions,
  SecureListEntry,
  SecureListEntryType,
  SecureListRequest,
  SecureListResult,
  SecureReadRequest,
  SecureReadResult,
} from "./types.js";
