import { canonicalize } from "./canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { commitTransition, inspectRunStorage } from "./persistence/index.js";
import { readM5ManagedRecords } from "./persistence/store.js";
import {
  acquireWorktreeLock,
  assertWorktreeLockHeld,
  releaseWorktreeLock,
  type WorktreeLockHandle,
} from "./repository/index.js";
import {
  deriveStaticDagResumePoint,
  loadDeterministicResumeLockTarget,
  revalidateDeterministicResumeEligibilityWhileLocked,
  type ResumeInspectionInput,
  type ResumeRefusalReason,
} from "./resume-inspection.js";
import { identifyContractDocument, type ReducerPolicy, type TransitionEvent, type WorkflowState } from "./schemas/index.js";

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

export interface DeterministicResumeActivationBinding {
  readonly run_id: string;
  readonly prior_revision: number;
  readonly prior_workflow_state_content_sha256: string;
  readonly successor_revision: number;
  readonly successor_workflow_state_content_sha256: string;
  readonly successor_state_pointer_content_sha256: string;
  readonly successor_transition_commit_content_sha256: string;
  readonly repository_identity_content_sha256: string;
  readonly worktree_key: string;
  readonly worktree_root: string;
  readonly git_common_dir: string;
  readonly frozen_policy_content_sha256: string;
  readonly state_identities: WorkflowState["identities"];
  readonly selected_task_id: string;
  readonly resume_point: string;
}

export interface DeterministicResumeActivation {
  readonly binding: DeterministicResumeActivationBinding;
}

interface OwnedLockState {
  readonly lock: WorktreeLockHandle;
  readonly stateRoot: string;
  released: boolean;
  consumed: boolean;
}

const admissions = new WeakMap<object, OwnedLockState>();
const activations = new WeakMap<object, OwnedLockState>();

class DeterministicResumeAdmissionImpl implements DeterministicResumeAdmission {
  public constructor(public readonly binding: DeterministicResumeAdmissionBinding, state: OwnedLockState) {
    admissions.set(this, state); Object.freeze(this);
  }
}

class DeterministicResumeActivationImpl implements DeterministicResumeActivation {
  public constructor(public readonly binding: DeterministicResumeActivationBinding, state: OwnedLockState) {
    activations.set(this, state); Object.freeze(this);
  }
}

function admissionState(admission: DeterministicResumeAdmission): OwnedLockState {
  if (admission === null || typeof admission !== "object") throw new Error("resume admission is invalid");
  const state = admissions.get(admission as object);
  if (state === undefined) throw new Error("resume admission was not created by this package instance");
  return state;
}

function activationState(activation: DeterministicResumeActivation): OwnedLockState {
  if (activation === null || typeof activation !== "object") throw new Error("resume activation is invalid");
  const state = activations.get(activation as object);
  if (state === undefined) throw new Error("resume activation was not created by this package instance");
  return state;
}

function refused(code: ResumeAdmissionRefusalCode): never {
  throw new DeterministicResumeAdmissionError(code);
}

function resumeProcessMetadata() {
  return { controller_instance_id: "deterministic-resume-controller", process_id: Math.max(1, process.pid), invocation_id: "deterministic-resume-activation" };
}

function selectEvent(revision: number, statePointerContentSha256: string): TransitionEvent {
  const payload = {};
  return identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    event_id: `resume-select-${revision}-${sha256Canonical({ state_pointer_content_sha256: statePointerContentSha256 }).slice(7, 23)}`,
    event_type: "SELECT_READY_LEAF", payload,
  }) as TransitionEvent;
}

function sameAdmissionState(binding: DeterministicResumeAdmissionBinding, inspection: Awaited<ReturnType<typeof inspectRunStorage>>): inspection is Awaited<ReturnType<typeof inspectRunStorage>> & {
  readonly revision: number;
  readonly statePointer: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["statePointer"]>;
  readonly workflowState: WorkflowState;
  readonly transitionCommit: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["transitionCommit"]>;
} {
  return inspection.status === "HEALTHY" && inspection.revision === binding.state_revision && inspection.statePointer?.content_sha256 === binding.state_pointer_content_sha256 &&
    inspection.workflowState?.content_sha256 === binding.workflow_state_content_sha256 && inspection.transitionCommit?.content_sha256 === binding.transition_commit_content_sha256 &&
    inspection.workflowState?.frozen_policy_content_sha256 === binding.frozen_policy_content_sha256 && canonicalize(inspection.workflowState?.identities) === canonicalize(binding.state_identities);
}

async function releaseOwnedLock(state: OwnedLockState): Promise<void> {
  if (state.released) return;
  await releaseWorktreeLock(state.lock); state.released = true;
}

/** Acquires M3's existing flock and derives admission only from authority freshly revalidated under it. */
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
    if (freshTarget.stateRoot !== target.stateRoot || freshTarget.runId !== target.runId || canonicalize(freshTarget.repository) !== canonicalize(target.repository)) return refused("RESUME_REFUSED_REPOSITORY_IDENTITY");
    const report = await revalidateDeterministicResumeEligibilityWhileLocked(input);
    if (report.classification !== "RESUMABLE" || report.resume_point === null) return refused(report.reason ?? "RESUME_REFUSED_STATE_STORE");
    await assertWorktreeLockHeld(lock);
    const inspection = await inspectRunStorage({ stateRoot: target.stateRoot, runId: target.runId });
    if (inspection.status !== "HEALTHY" || inspection.revision === null || inspection.statePointer === null || inspection.workflowState === null || inspection.transitionCommit === null) return refused("RESUME_REFUSED_STATE_STORE");
    const binding = Object.freeze({
      run_id: target.runId, state_revision: inspection.revision, workflow_state_content_sha256: inspection.workflowState.content_sha256,
      state_pointer_content_sha256: inspection.statePointer.content_sha256, transition_commit_content_sha256: inspection.transitionCommit.content_sha256,
      repository_identity_content_sha256: target.repository.content_sha256, worktree_key: target.repository.worktree_key,
      worktree_root: target.repository.worktree_root, git_common_dir: target.repository.git_common_dir,
      frozen_policy_content_sha256: inspection.workflowState.frozen_policy_content_sha256,
      state_identities: Object.freeze({ ...inspection.workflowState.identities }), resume_point: report.resume_point,
    });
    const admission = new DeterministicResumeAdmissionImpl(binding, { lock, stateRoot: target.stateRoot, released: false, consumed: false });
    lock = undefined;
    return admission;
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock);
  }
}

export async function assertDeterministicResumeAdmissionHeld(admission: DeterministicResumeAdmission): Promise<void> {
  const state = admissionState(admission);
  if (state.released || state.consumed) throw new Error("resume admission is no longer active");
  await assertWorktreeLockHeld(state.lock);
}

export async function releaseDeterministicResumeAdmission(admission: DeterministicResumeAdmission): Promise<void> {
  const state = admissionState(admission);
  if (state.consumed) throw new Error("resume admission ownership was transferred");
  await releaseOwnedLock(state);
}

/** Commits exactly the existing SELECT_READY_LEAF transition and transfers the same M3 lock. */
export async function activateDeterministicResumeAdmission(admission: DeterministicResumeAdmission): Promise<DeterministicResumeActivation> {
  const state = admissionState(admission);
  if (state.released || state.consumed) throw new Error("resume admission is no longer active");
  try {
    await assertWorktreeLockHeld(state.lock);
    const binding = admission.binding; const location = { stateRoot: state.stateRoot, runId: binding.run_id };
    const prior = await inspectRunStorage(location);
    if (!sameAdmissionState(binding, prior)) return refused("RESUME_REFUSED_STATE_STORE");
    const records = await readM5ManagedRecords(location);
    const policies = records.reducerPolicies.filter((policy) => policy.content_sha256 === binding.frozen_policy_content_sha256);
    const policy = policies.length === 1 ? policies[0]! : null;
    if (policy === null || deriveStaticDagResumePoint(prior.workflowState, policy) !== binding.resume_point || !binding.resume_point.startsWith("STATIC_DAG_SELECT_READY_LEAF:")) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const selectedTaskId = binding.resume_point.slice("STATIC_DAG_SELECT_READY_LEAF:".length);
    const selectedBefore = prior.workflowState.tasks.find((task) => task.task_id === selectedTaskId);
    const reservationsBefore = records.decisions.filter((decision) => decision.reservation !== null).length;
    const invocationsBefore = records.boundedWorkerInvocations.length;
    if (selectedBefore === undefined || selectedBefore.status !== "PENDING") return refused("RESUME_REFUSED_STATE_STORE");
    await commitTransition({
      ...location, expectedRevision: prior.revision, expectedStatePointerContentSha256: prior.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: prior.workflowState.content_sha256 as Sha256Digest,
      transitionId: `resume-activate-${prior.revision}`, policy, event: selectEvent(prior.revision, prior.statePointer.content_sha256), processMetadata: resumeProcessMetadata(),
    });
    const successor = await inspectRunStorage(location);
    if (successor.status !== "HEALTHY" || successor.revision !== prior.revision + 1 || successor.statePointer === null || successor.workflowState === null || successor.transitionCommit === null ||
      successor.workflowState.phase !== "LEAF_FAST_PREFLIGHT" || successor.workflowState.active_task_id !== selectedTaskId ||
      deriveStaticDagResumePoint(successor.workflowState, policy) !== `STATIC_DAG_START_SELECTED_LEAF:${selectedTaskId}` ||
      canonicalize(successor.workflowState.counters.worker_invocations) !== canonicalize(prior.workflowState.counters.worker_invocations) ||
      successor.workflowState.tasks.find((task) => task.task_id === selectedTaskId)?.attempts !== selectedBefore.attempts) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const afterRecords = await readM5ManagedRecords(location);
    if (afterRecords.boundedWorkerInvocations.length !== invocationsBefore || afterRecords.decisions.filter((decision) => decision.reservation !== null).length !== reservationsBefore) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    await assertWorktreeLockHeld(state.lock);
    const activationBinding = Object.freeze({
      run_id: binding.run_id, prior_revision: binding.state_revision, prior_workflow_state_content_sha256: binding.workflow_state_content_sha256,
      successor_revision: successor.revision, successor_workflow_state_content_sha256: successor.workflowState.content_sha256,
      successor_state_pointer_content_sha256: successor.statePointer.content_sha256, successor_transition_commit_content_sha256: successor.transitionCommit.content_sha256,
      repository_identity_content_sha256: binding.repository_identity_content_sha256, worktree_key: binding.worktree_key,
      worktree_root: binding.worktree_root, git_common_dir: binding.git_common_dir, frozen_policy_content_sha256: binding.frozen_policy_content_sha256,
      state_identities: Object.freeze({ ...successor.workflowState.identities }), selected_task_id: selectedTaskId,
      resume_point: `STATIC_DAG_START_SELECTED_LEAF:${selectedTaskId}`,
    });
    state.consumed = true;
    return new DeterministicResumeActivationImpl(activationBinding, state);
  } catch (error: unknown) {
    try { await releaseOwnedLock(state); } catch (releaseError: unknown) { throw releaseError; }
    throw error;
  }
}

export async function assertDeterministicResumeActivationHeld(activation: DeterministicResumeActivation): Promise<void> {
  const state = activationState(activation);
  if (state.released) throw new Error("resume activation has been released");
  await assertWorktreeLockHeld(state.lock);
}

export async function releaseDeterministicResumeActivation(activation: DeterministicResumeActivation): Promise<void> {
  await releaseOwnedLock(activationState(activation));
}
