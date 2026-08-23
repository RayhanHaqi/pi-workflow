export interface SecureFilesystemTestHooks {
  readonly helperPath?: string;
  readonly sandboxHelperPath?: string;
  readonly checkpointSocket?: string;
  readonly checkpointStage?: string;
  readonly secondaryCheckpointSocket?: string;
  readonly secondaryCheckpointStage?: string;
  readonly failStage?: string;
  readonly forceCapabilityUnavailable?: boolean;
  readonly forceSandboxUnavailable?: boolean;
  readonly forceNetworkUnavailable?: boolean;
  readonly helperKillStage?: string;
  readonly recoveryFailStage?: string;
  readonly recoveryKillStage?: string;
  readonly recoveryCheckpointSocket?: string;
  readonly recoveryCheckpointStage?: string;
  readonly beforeMutationHelperLaunch?: (request: Readonly<Record<string, unknown>>) => Promise<void>;
  readonly beforeRecoveryHelperLaunch?: () => Promise<void>;
  readonly repeatRecovery?: boolean;
  readonly sandboxCheckpointSocket?: string;
  readonly sandboxCheckpointStage?: string;
  readonly beforeRepositoryRevalidation?: () => Promise<void>;
  readonly afterPackageMetadataDiscovery?: (packageRoot: string) => Promise<void>;
  readonly sandboxOutputChunkBytes?: number;
}

let hooks: SecureFilesystemTestHooks = Object.freeze({});

export function setSecureFilesystemTestHooks(next: SecureFilesystemTestHooks): void {
  hooks = Object.freeze({ ...next });
}

export function resetSecureFilesystemTestHooks(): void {
  hooks = Object.freeze({});
}

export function secureFilesystemTestHooks(): SecureFilesystemTestHooks {
  return hooks;
}
