import { canonicalize } from "./canonical-json/index.js";
import { inspectRunStorage } from "./persistence/index.js";
import {
  acquireWorktreeLock,
  assertWorktreeLockHeld,
  releaseWorktreeLock,
  type WorktreeLockHandle,
} from "./repository/index.js";
import {
  loadDeterministicResumeLockTarget,
  revalidateDeterministicResumeEligibilityWhileLocked,
  type ResumeInspectionInput,
  type ResumeRefusalReason,
} from "./resume-inspection.js";
import type { WorkflowState } from "./schemas/index.js";

export type ResumeAdmissionRefusalCode = ResumeRefusalReason | "LOCK_BUSY";

export class DeterministicResumeAdmissionError extends Error {
  public constructor(readonly code: ResumeAdmissionRefusalCode) {
    super(code); this.name = "DeterministicResumeAdmissionError";
  }
}

export interface DeterministicResumeAdmissionBinding {
  readonly run_id: string;
  readonly state_revision: number;
  readonly workflow_state_content_sha256: string;
  readonly state_pointer_content_sha256: string;
  readonly transition_commit_content_sha256: string;
  readonly repository_identity_content_sha256: string;
  readonly worktree_key: string;
  readonly worktree_root: string;
  readonly git_common_dir: string;
  readonly frozen_policy_content_sha256: string;
  readonly state_identities: WorkflowState["identities"];
  readonly resume_point: string;
}

export interface DeterministicResumeAdmission {
  readonly binding: DeterministicResumeAdmissionBinding;
}

interface AdmissionState {
  readonly lock: WorktreeLockHandle;
  released: boolean;
}

const admissions = new WeakMap<object, AdmissionState>();

class DeterministicResumeAdmissionImpl implements DeterministicResumeAdmission {
  public constructor(public readonly binding: DeterministicResumeAdmissionBinding, state: AdmissionState) {
    admissions.set(this, state); Object.freeze(this);
  }
}

function stateFor(admission: DeterministicResumeAdmission): AdmissionState {
  if (admission === null || typeof admission !== "object") throw new Error("resume admission is invalid");
  const state = admissions.get(admission as object);
  if (state === undefined) throw new Error("resume admission was not created by this package instance");
  return state;
}

function refused(code: ResumeAdmissionRefusalCode): never {
  throw new DeterministicResumeAdmissionError(code);
}

/**
 * Acquires M3's existing worktree flock, then derives this capability only from
 * freshly revalidated authority while that lock remains held. It never resumes work.
 */
export async function acquireDeterministicResumeAdmission(input: ResumeInspectionInput): Promise<DeterministicResumeAdmission> {
  let target: Awaited<ReturnType<typeof loadDeterministicResumeLockTarget>>;
  try { target = await loadDeterministicResumeLockTarget(input); }
  catch { return refused("RESUME_REFUSED_STATE_STORE"); }

  let lock: WorktreeLockHandle | undefined;
  try {
    try { lock = await acquireWorktreeLock({ stateRoot: target.stateRoot, repository: target.repository }); }
    catch (error: unknown) {
      if (error !== null && typeof error === "object" && (error as { readonly code?: unknown }).code === "LOCK_BUSY") return refused("LOCK_BUSY");
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    await assertWorktreeLockHeld(lock);
    const freshTarget = await loadDeterministicResumeLockTarget(input);
    if (freshTarget.stateRoot !== target.stateRoot || freshTarget.runId !== target.runId || canonicalize(freshTarget.repository) !== canonicalize(target.repository)) {
      return refused("RESUME_REFUSED_REPOSITORY_IDENTITY");
    }
    const report = await revalidateDeterministicResumeEligibilityWhileLocked(input);
    if (report.classification !== "RESUMABLE" || report.resume_point === null) return refused(report.reason ?? "RESUME_REFUSED_STATE_STORE");
    await assertWorktreeLockHeld(lock);
    const inspection = await inspectRunStorage({ stateRoot: target.stateRoot, runId: target.runId });
    if (inspection.status !== "HEALTHY" || inspection.revision === null || inspection.statePointer === null || inspection.workflowState === null || inspection.transitionCommit === null) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const binding = Object.freeze({
      run_id: target.runId,
      state_revision: inspection.revision,
      workflow_state_content_sha256: inspection.workflowState.content_sha256,
      state_pointer_content_sha256: inspection.statePointer.content_sha256,
      transition_commit_content_sha256: inspection.transitionCommit.content_sha256,
      repository_identity_content_sha256: target.repository.content_sha256,
      worktree_key: target.repository.worktree_key,
      worktree_root: target.repository.worktree_root,
      git_common_dir: target.repository.git_common_dir,
      frozen_policy_content_sha256: inspection.workflowState.frozen_policy_content_sha256,
      state_identities: Object.freeze({ ...inspection.workflowState.identities }),
      resume_point: report.resume_point,
    });
    const admission = new DeterministicResumeAdmissionImpl(binding, { lock, released: false });
    lock = undefined;
    return admission;
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
  }
}

export async function assertDeterministicResumeAdmissionHeld(admission: DeterministicResumeAdmission): Promise<void> {
  const state = stateFor(admission);
  if (state.released) throw new Error("resume admission has been released");
  await assertWorktreeLockHeld(state.lock);
}

export async function releaseDeterministicResumeAdmission(admission: DeterministicResumeAdmission): Promise<void> {
  const state = stateFor(admission);
  if (state.released) return;
  await releaseWorktreeLock(state.lock); state.released = true;
}
