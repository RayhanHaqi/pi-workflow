export const PERSISTENCE_CHECKPOINTS = Object.freeze([
  "EVIDENCE_TEMP_WRITTEN",
  "EVIDENCE_FILE_SYNCED",
  "EVIDENCE_RENAMED",
  "EVIDENCE_DIRECTORY_SYNCED",
  "RECORD_TEMP_WRITTEN",
  "RECORD_FILE_SYNCED",
  "RECORD_RENAMED",
  "RECORD_DIRECTORY_SYNCED",
  "TRANSITION_TEMP_WRITTEN",
  "TRANSITION_FILE_SYNCED",
  "TRANSITION_RENAMED",
  "TRANSITION_DIRECTORY_SYNCED",
  "STATE_TEMP_WRITTEN",
  "STATE_FILE_SYNCED",
  "STATE_RENAMED",
  "RUN_DIRECTORY_SYNCED",
] as const);

export type PersistenceCheckpoint = (typeof PERSISTENCE_CHECKPOINTS)[number];
export type AtomicOperation = "write" | "fileSync" | "rename" | "directorySync";

export interface PersistenceTestHooks {
  readonly checkpoint?: (checkpoint: PersistenceCheckpoint, finalPath: string) => void | Promise<void>;
  readonly beforeOperation?: (operation: AtomicOperation, finalPath: string) => void | Promise<void>;
  readonly temporaryName?: (finalPath: string, generatedName: string) => string;
}

let hooks: PersistenceTestHooks | undefined;

/** Package-internal deterministic test seam; no supported package entrypoint exports it. */
export function configurePersistenceTestHooks(next: PersistenceTestHooks | undefined): void {
  hooks = next;
}

export async function persistenceCheckpoint(checkpoint: PersistenceCheckpoint, finalPath: string): Promise<void> {
  await hooks?.checkpoint?.(checkpoint, finalPath);
}

export async function beforeAtomicOperation(operation: AtomicOperation, finalPath: string): Promise<void> {
  await hooks?.beforeOperation?.(operation, finalPath);
}

export function chooseTemporaryName(finalPath: string, generatedName: string): string {
  return hooks?.temporaryName?.(finalPath, generatedName) ?? generatedName;
}
