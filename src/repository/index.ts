export { RepositoryGuardError } from "./errors.js";
export { deriveWorktreeKey, resolveRepositoryIdentity } from "./identity.js";
export {
  acquireWorktreeLock,
  assertWorktreeLockHeld,
  releaseWorktreeLock,
} from "./lock.js";
export {
  captureBaseline,
  createBaselineApproval,
  verifyBaselineApproval,
} from "./baseline.js";
export { runFastPreflight, runFullPreflight } from "./preflight.js";
export { runPostflight } from "./postflight.js";
export {
  applyRetentionCleanup,
  createTerminalRetentionAuthority,
  inspectRetention,
} from "./retention.js";

export type { RepositoryGuardErrorCode } from "./errors.js";
export type {
  DeriveWorktreeKeyInput,
  ResolveRepositoryIdentityInput,
} from "./identity.js";
export type {
  AcquireWorktreeLockInput,
  WorktreeLockHandle,
} from "./lock.js";
export type {
  BaselineApprovalResult,
  BaselineCaptureResult,
  BaselineMode,
  BaselinePathDecision,
  CaptureBaselineInput,
  CaptureMode,
  CreateBaselineApprovalInput,
  DataClass,
  FingerprintedFileInput,
  OwnershipClass,
} from "./baseline.js";
export type {
  FullPreflightResult,
  RequiredEnvironment,
  RunFastPreflightInput,
  RunFullPreflightInput,
} from "./preflight.js";
export type { PostflightResult, RunPostflightInput } from "./postflight.js";
export type {
  CreateTerminalRetentionAuthorityInput,
  RetentionOperationInput,
} from "./retention.js";
