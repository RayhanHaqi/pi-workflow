export type ResumeReconciliationCheckpoint =
  | "BEFORE_USAGE_RECONCILIATION"
  | "AFTER_USAGE_RECONCILIATION"
  | "AFTER_COMPLETE_LEAF_ATTEMPT"
  | "BEFORE_VERIFICATION_COMMAND"
  | "AFTER_VERIFICATION_COMMAND"
  | "AFTER_PASS_LEAF_POSTFLIGHT"
  | "AFTER_LEAF_VERIFICATION_TRANSITION"
  | "BEFORE_FINAL_VERIFIER"
  | "AFTER_FINAL_VERIFIER"
  | "BETWEEN_FINAL_VERIFIERS"
  | "AFTER_FINAL_POSTFLIGHT"
  | "AFTER_TERMINAL_DECISION"
  | "AFTER_PASS_TRANSITION";

export interface ResumeReconciliationTestHooks {
  readonly checkpoint?: (checkpoint: ResumeReconciliationCheckpoint) => void | Promise<void>;
}

let hooks: ResumeReconciliationTestHooks | undefined;

export function configureResumeReconciliationTestHooks(next?: ResumeReconciliationTestHooks): void {
  hooks = next;
}

export async function resumeReconciliationCheckpoint(checkpoint: ResumeReconciliationCheckpoint): Promise<void> {
  await hooks?.checkpoint?.(checkpoint);
}
