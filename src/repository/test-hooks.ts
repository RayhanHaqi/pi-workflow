export interface RepositoryTestHooks {
  readonly gitOutputLimitBytes?: number;
  readonly guardianPath?: string;
  readonly guardianReadyTimeoutMs?: number;
  readonly stateRootBytes?: number;
  readonly baselineBlobLimitBytes?: number;
  readonly retainedBaselineBlobBytesOverride?: number;
  readonly afterBaselineBlobPublication?: (path: string) => void | Promise<void>;
  readonly beforeBaselineRollbackUnlink?: (path: string) => void | Promise<void>;
  readonly beforeBaselineRollbackDirectorySync?: (path: string) => void | Promise<void>;
  readonly beforeRetentionUnlink?: (path: string) => void | Promise<void>;
  readonly beforeRetentionDirectorySync?: (path: string) => void | Promise<void>;
  readonly beforeRetentionResultPublication?: () => void | Promise<void>;
  readonly beforeRetentionCapacityRecheck?: () => void | Promise<void>;
  readonly afterRetentionLockAcquired?: (guardianPid: number) => void | Promise<void>;
  readonly retentionTargetReadFailureDigest?: string;
}

let hooks: RepositoryTestHooks = {};

export function configureRepositoryTestHooks(next: RepositoryTestHooks): void {
  hooks = { ...next };
}

export function resetRepositoryTestHooks(): void {
  hooks = {};
}

export function repositoryTestHooks(): RepositoryTestHooks {
  return hooks;
}
