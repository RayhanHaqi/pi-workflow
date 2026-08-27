export type ResumeWorkerCheckpoint = "AFTER_RESUME_HANDOVER" | "AFTER_RESUME_GATEWAY_CREATED" | "AFTER_RESUMED_RESULT_PERSISTED";

export interface ResumeWorkerTestHooks {
  readonly checkpoint?: (checkpoint: ResumeWorkerCheckpoint) => void | Promise<void>;
}

let hooks: ResumeWorkerTestHooks | undefined;

/** Package-internal deterministic R2D process-proof seam; no supported entrypoint exports it. */
export function configureResumeWorkerTestHooks(next: ResumeWorkerTestHooks | undefined): void {
  hooks = next;
}

export async function resumeWorkerCheckpoint(checkpoint: ResumeWorkerCheckpoint): Promise<void> {
  await hooks?.checkpoint?.(checkpoint);
}
