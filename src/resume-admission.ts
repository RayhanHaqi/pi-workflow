import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "./canonical-json/index.js";
import { createControlDecisionKernel } from "./control/kernel.js";
import { mapLowerLayerFailureCode } from "./control/evaluate.js";
import { boundedWorkerSystemPrompt, BOUNDED_WORKER_MAX_TOOL_CALLS, BOUNDED_WORKER_MAX_WALL_TIME_MS, partitionProviderVisibleReadScope, providerVisibleTaskContract } from "./control/launch-authority.js";
import type { BoundedWorkerExecutionResult, RunBoundedWorkerInput } from "./pi-adapter/bounded-worker.js";
import { createScopedToolGateway } from "./scoped-tools/index.js";
import { buildBoundedWorkerUsageEvidence } from "./control/usage-evidence.js";
import type { M5AuthoritativeSources } from "./control/types.js";
import { sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { commitTransition, inspectRunStorage } from "./persistence/index.js";
import { establishNodeStaticTimeAuthority, readM5ManagedRecords } from "./persistence/store.js";
import { resolveApplicableResumeTiming, staticTimingVerdicts } from "./persistence/static-time-authority.js";
import { resolveStaticMaxM4MutationCalls } from "./persistence/m5-authority.js";
import { resolveAuthoritativeBoundedExecution } from "./persistence/bounded-worker-authority.js";
import { sampleWallClockMs } from "./wall-clock.js";
import {
  acquireWorktreeLock,
  resolveRepositoryIdentity,
  assertWorktreeLockHeld,
  releaseWorktreeLock,
  type WorktreeLockHandle,
} from "./repository/index.js";
import { runResumeLockHandover } from "./repository/resume-handover.js";
import { loadAuthoritativeToken } from "./repository/token-provenance.js";
import { resumeWorkerCheckpoint } from "./resume-worker-test-hooks.js";
import { resumeReconciliationCheckpoint } from "./resume-reconciliation-test-hooks.js";
import {
  currentOperationWorkerRecords,
  deriveStaticDagPreProviderResumePoint,
  deriveStaticDagR2EResumePoint,
  deriveStaticDagResumePoint,
  exactStaticWorkDecision,
  loadDeterministicResumeLockTarget,
  resolveExactStaticM5Policy,
  resolveSettledStaticLeafAuthority,
  exactStaticLeafReconciliationDecision,
  staticLeafPostflightTransitionId,
  staticLeafReconciliationTransitionId,
  staticLeafVerificationTransitionId,
  resumedAvailableLogicalRoles,
  revalidateDeterministicResumeEligibilityWhileLocked,
  staticLeafOperationId,
  staticLeafTransitionId,
  staticWorkDecisionCandidates,
  tokenTip,
  type ResumeInspectionInput,
  type ResumeRefusalReason,
} from "./resume-inspection.js";
import { selectReadyLeafUnchecked } from "./state-machine/reducer.js";
import { captureGitState } from "./repository/fingerprint.js";
import { assertNoGitBlockers, assertRepositoryMatches } from "./repository/preflight.js";
import {
  identifyContractDocument,
  type BudgetDocument,
  type ContractDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3PostflightDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandCatalogDocument,
  type M4CommandResultDocument,
  type M4CommandSpecification,
  type M4ScopedToolPolicyDocument,
  type M5ControlPolicyDocument,
  type PlanApprovalDocument,
  type ReducerPolicy,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
  type TaskDocument,
  type TaskGraphDocument,
  type TransitionEvent,
  type WorkflowState,
} from "./schemas/index.js";
import type { ManagedRecordClassification } from "./persistence/types.js";

export type ResumeAdmissionRefusalCode = ResumeRefusalReason | "LOCK_BUSY" | "FROZEN_MUTATION_ALLOWANCE_NOT_DURABLE" | "STATE_TOKEN_CHAIN_TOO_DEEP";

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
  /** Set when an activation consumed this admission (R2B transfer); the shared state stays live for the activation. */
  consumed: boolean;
  /** Set only by a completed V1-R2C work-admission flock transfer. */
  workTransferred: boolean;
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

async function cleanupResumedWorkerOwnership(state: OwnedLockState, temporaryRoot: string | undefined): Promise<void> {
  let cleanupFailed = false;
  let cleanupError: unknown;
  if (temporaryRoot !== undefined) {
    try { await rm(temporaryRoot, { recursive: true, force: true }); }
    catch (error: unknown) { cleanupFailed = true; cleanupError = error; }
  }
  try { await releaseOwnedLock(state); }
  catch (error: unknown) { if (!cleanupFailed) cleanupError = error; cleanupFailed = true; }
  if (cleanupFailed) throw cleanupError;
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
    const admission = new DeterministicResumeAdmissionImpl(binding, { lock, stateRoot: target.stateRoot, released: false, consumed: false, workTransferred: false });
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
    // V1-R2D-TIME NODE START BOUNDARY: the durable SELECT_READY_LEAF below must not
    // begin a node epoch without its timing authority. Resolve applicable timing,
    // then establish-or-reuse the exact prepared NODE authority under this lock
    // BEFORE the select commit so a lost response reuses the same timestamp.
    {
      const timing = resolveApplicableResumeTiming({
        runId: binding.run_id, state: prior.workflowState, tipCommit: prior.transitionCommit,
        records: {
          transitionCommits: records.transitionCommits, workflowStates: records.workflowStates,
          transitionEvents: records.transitionEvents, authorities: records.staticTimeAuthorities,
        },
        verdicts: staticTimingVerdicts(prior.managedRecordClassifications),
        nowMs: sampleWallClockMs(),
      });
      if (timing.outcome === "REFUSED" || timing.workflow === null) return refused("RESUME_REFUSED_TIMING_AUTHORITY");
      // Derived canonical selection must equal the timing record's exact task.
      if (selectReadyLeafUnchecked(prior.workflowState, policy) !== selectedTaskId) return refused("RESUME_REFUSED_STATE_STORE");
      if (timing.node === null) {
        const budget = records.budgets.find((entry) => entry.budget_sha256 === prior.workflowState.identities.budget_sha256);
        const staticBudgets = budget?.limits.static_time_budgets;
        if (budget === undefined || staticBudgets === undefined || staticBudgets.workflow_wall_ms !== timing.workflow.wall_budget_ms) return refused("RESUME_REFUSED_TIMING_AUTHORITY");
        await establishNodeStaticTimeAuthority({
          stateRoot: location.stateRoot, runId: binding.run_id,
          taskId: selectedTaskId,
          nodeWallBudgetMs: staticBudgets.node_wall_ms,
          workflowTimeAuthorityContentSha256: timing.workflow.content_sha256 as Sha256Digest,
          epoch: {
            revision: prior.revision,
            workflow_state_content_sha256: prior.workflowState.content_sha256,
            transition_commit_content_sha256: prior.transitionCommit.content_sha256,
          },
        });
      }
      // V1-R2D-TIME-R4: re-resolve and recheck AFTER NODE establishment/reuse,
      // still under the SAME held flock. Expiry during establishment refuses
      // before the durable select; the prepared authority stays behind as valid
      // UNREFERENCED evidence and is never deleted or resampled later.
      {
        const postEstablish = await inspectRunStorage(location);
        if (postEstablish.status !== "HEALTHY" || !sameAdmissionState(binding, postEstablish)) return refused("RESUME_REFUSED_STATE_STORE");
        const postRecords = await readM5ManagedRecords(location);
        const postTiming = resolveApplicableResumeTiming({
          runId: binding.run_id, state: postEstablish.workflowState!, tipCommit: postEstablish.transitionCommit!,
          records: {
            transitionCommits: postRecords.transitionCommits, workflowStates: postRecords.workflowStates,
            transitionEvents: postRecords.transitionEvents, authorities: postRecords.staticTimeAuthorities,
          },
          verdicts: staticTimingVerdicts(postEstablish.managedRecordClassifications),
          nowMs: sampleWallClockMs(),
        });
        if (postTiming.outcome === "REFUSED" || postTiming.workflow === null || postTiming.node === null) return refused("RESUME_REFUSED_TIMING_AUTHORITY");
        if (postTiming.node.task_id !== selectedTaskId) return refused("RESUME_REFUSED_TIMING_AUTHORITY");
      }
    }
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
  if (state.released || state.workTransferred) throw new Error("resume activation is no longer active");
  await assertWorktreeLockHeld(state.lock);
}

export async function releaseDeterministicResumeActivation(activation: DeterministicResumeActivation): Promise<void> {
  const state = activationState(activation);
  if (state.workTransferred) throw new Error("resume activation ownership was transferred");
  await releaseOwnedLock(state);
}

export interface DeterministicResumeWorkAdmissionBinding {
  readonly run_id: string;
  readonly selected_task_id: string;
  readonly selected_task_content_sha256: Sha256Digest;
  readonly task_graph_sha256: Sha256Digest | null;
  readonly plan_approval_sha256: Sha256Digest | null;
  readonly operation_id: string;
  readonly attempt_number: 1;
  readonly reducer_policy_content_sha256: Sha256Digest;
  readonly m5_policy_content_sha256: Sha256Digest;
  readonly m5_decision_content_sha256: Sha256Digest;
  readonly reservation_decision_key: Sha256Digest | null;
  readonly frozen_logical_role: "TERRA_EXECUTOR" | "CODING_EXECUTOR";
  readonly provider_id: string;
  readonly model_id: string;
  readonly effort: string;
  readonly model_definition_sha256: Sha256Digest | null;
  readonly repository_identity_content_sha256: Sha256Digest;
  readonly worktree_key: Sha256Digest;
  readonly worktree_root: string;
  readonly git_common_dir: string;
  readonly input_m3_state_token_content_sha256: Sha256Digest;
  readonly predecessor_revision: number;
  readonly predecessor_workflow_state_content_sha256: Sha256Digest;
  readonly predecessor_state_pointer_content_sha256: Sha256Digest;
  readonly successor_revision: number;
  readonly successor_workflow_state_content_sha256: Sha256Digest;
  readonly successor_state_pointer_content_sha256: Sha256Digest;
  readonly successor_transition_commit_content_sha256: Sha256Digest;
}

export interface DeterministicResumeWorkAdmission {
  readonly binding: DeterministicResumeWorkAdmissionBinding;
}

const workAdmissions = new WeakMap<object, OwnedLockState>();

class DeterministicResumeWorkAdmissionImpl implements DeterministicResumeWorkAdmission {
  public constructor(public readonly binding: DeterministicResumeWorkAdmissionBinding, state: OwnedLockState) {
    workAdmissions.set(this, state); Object.freeze(this);
  }
}

function classificationOf(classifications: readonly ManagedRecordClassification[], kind: string, digest: string): string | null {
  return classifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest)?.classification ?? null;
}

function workAdmissionState(admission: DeterministicResumeWorkAdmission): OwnedLockState {
  if (admission === null || typeof admission !== "object") throw new Error("resume work admission is invalid");
  const state = workAdmissions.get(admission as object);
  if (state === undefined) throw new Error("resume work admission was not created by this package instance");
  return state;
}

const SELECTED_LEAF_RESUME_PREFIXES = ["STATIC_DAG_START_SELECTED_LEAF:", "STATIC_DAG_REDRIVE_WORK_ADMISSION:", "STATIC_DAG_INVOKE_RESERVED_LEAF:"] as const;

function selectedLeafTaskId(resumePoint: string): string | null {
  const prefix = SELECTED_LEAF_RESUME_PREFIXES.find((entry) => resumePoint.startsWith(entry));
  return prefix === undefined ? null : resumePoint.slice(prefix.length);
}

function resumeCapabilityState(capability: DeterministicResumeActivation | DeterministicResumeAdmission): OwnedLockState | undefined {
  if (capability === null || typeof capability !== "object") return undefined;
  if (workAdmissions.has(capability as object)) return undefined;
  return activations.get(capability as object) ?? admissions.get(capability as object);
}

function uniqueBy<T>(values: readonly T[], identity: (value: T) => string, expected: string): T | null {
  const matches = values.filter((value) => identity(value) === expected);
  return matches.length === 1 ? matches[0]! : null;
}

interface RehydratedStaticLeafAuthority {
  readonly policy: M5ControlPolicyDocument;
  readonly reducerPolicy: ReducerPolicy;
  readonly repositoryIdentity: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly baselineApproval: M3BaselineApprovalRuntimeDocument | null;
  readonly contract: ContractDocument;
  readonly budget: BudgetDocument;
  readonly routeMap: RouteMapDocument;
  readonly routeMapApproval: RouteMapApprovalDocument;
  readonly toolPolicy: M4ScopedToolPolicyDocument;
  readonly commandCatalog: M4CommandCatalogDocument;
  readonly planApprovals: readonly PlanApprovalDocument[];
  readonly taskGraphs: readonly TaskGraphDocument[];
  readonly tasks: readonly TaskDocument[];
  readonly selectedTask: TaskDocument;
  readonly stateToken: M3RepositoryStateTokenDocument;
}

const preProviderM4Classification = (classifications: readonly ManagedRecordClassification[], kind: "M4_TOOL_POLICY" | "M4_COMMAND_CATALOG", digest: string): boolean =>
  classifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest &&
    (entry.classification === "AUTHORITATIVE_MANAGED_RECORD" || entry.classification === "UNREFERENCED_MANAGED_RECORD"));

/** Reconstructs execution authority exactly and uniquely from retained durable records; never from caller-supplied data. */
function rehydrateStaticLeafAuthority(
  state: WorkflowState,
  records: Awaited<ReturnType<typeof readM5ManagedRecords>>,
  classifications: readonly ManagedRecordClassification[],
): RehydratedStaticLeafAuthority | null {
  const reducerPolicies = records.reducerPolicies.filter((entry) => entry.content_sha256 === state.frozen_policy_content_sha256);
  if (reducerPolicies.length !== 1) return null;
  const policy = resolveExactStaticM5Policy(state, records);
  if (policy === null) return null;
  const contract = uniqueBy(records.contracts, (entry) => entry.contract_sha256, policy.contract_sha256);
  const budget = uniqueBy(records.budgets, (entry) => entry.budget_sha256, policy.budget_sha256);
  const routeMap = uniqueBy(records.routeMaps, (entry) => entry.route_map_sha256, policy.route_map_sha256);
  const routeMapApproval = uniqueBy(records.routeMapApprovals, (entry) => entry.route_map_approval_sha256, policy.route_map_approval_sha256);
  const toolPolicyCandidates = records.toolPolicies.filter((entry) => entry.content_sha256 === policy.tool_policy_content_sha256 && preProviderM4Classification(classifications, "M4_TOOL_POLICY", entry.content_sha256));
  const catalogCandidates = records.commandCatalogs.filter((entry) => entry.content_sha256 === policy.command_catalog_content_sha256 && preProviderM4Classification(classifications, "M4_COMMAND_CATALOG", entry.content_sha256));
  const planApprovals = records.planApprovals.filter((entry) => entry.plan_approval_sha256 === policy.plan_approval_sha256);
  const taskGraphs = records.taskGraphs.filter((entry) => entry.task_graph_sha256 === policy.task_graph_sha256);
  if (contract === null || budget === null || routeMap === null || routeMapApproval === null || toolPolicyCandidates.length !== 1 || catalogCandidates.length !== 1 || planApprovals.length !== 1 || taskGraphs.length !== 1) return null;
  const approval = uniqueBy(records.approvals, (entry) => entry.content_sha256, policy.baseline_approval_sha256);
  const baseline = approval === null
    ? uniqueBy(records.baselines, (entry) => entry.content_sha256, policy.baseline_approval_sha256)
    : uniqueBy(records.baselines, (entry) => entry.content_sha256, approval.baseline_runtime_content_sha256);
  if (baseline === null || baseline.repository.content_sha256 !== policy.repository_identity_content_sha256 || baseline.repository.worktree_key !== policy.worktree_key) return null;
  // Multi-leaf runs legitimately retain multiple authoritative M3 tokens; the required authority is the
  // exact unique CURRENT tip of this run/repository/worktree/scope's authoritative token chain.
  const scopeTokens = records.stateTokens.filter((entry) => entry.run_id === policy.run_id &&
    entry.repository_identity_content_sha256 === policy.repository_identity_content_sha256 && entry.worktree_key === policy.worktree_key &&
    entry.task_scope_identity === policy.scope_sha256 && classifications.some((classification) => classification.object.kind === "M3_REPOSITORY_STATE_TOKEN" &&
      classification.object.contentSha256 === entry.content_sha256 && classification.classification === "AUTHORITATIVE_MANAGED_RECORD"));
  const stateToken = tokenTip(scopeTokens);
  const selectedTasks = records.tasks.filter((entry) => state.active_task_id !== null && entry.task_id === state.active_task_id);
  if (stateToken === null || selectedTasks.length !== 1 || state.active_task_id === null) return null;
  return Object.freeze({
    policy, reducerPolicy: reducerPolicies[0]!, repositoryIdentity: baseline.repository, baseline, baselineApproval: approval,
    contract, budget, routeMap, routeMapApproval,
    toolPolicy: toolPolicyCandidates[0]!, commandCatalog: catalogCandidates[0]!, planApprovals, taskGraphs, tasks: records.tasks,
    selectedTask: selectedTasks[0]!, stateToken,
  });
}

/**
 * V1-R2C: crash-safe pre-provider work admission under the SAME M3 flock.
 *
 * Accepts only genuine package-created resume capabilities (an R2B activation or a resume admission bound to the exact
 * quiescent selected-leaf / redrive / reserved-leaf point), rereads and re-verifies the live state under the held lock,
 * rehydrates existing M5 authority from retained records, replays the existing AUTHORIZE_WORK decision for
 * static-leaf-<task>-attempt-1 through the production kernel, and transfers the flock into a new opaque pre-provider
 * work capability. Stops strictly before any BOUNDED_WORKER_INVOCATION publication.
 */
export async function authorizeDeterministicResumedLeafWork(resume: DeterministicResumeActivation | DeterministicResumeAdmission): Promise<DeterministicResumeWorkAdmission> {
  const owned = resumeCapabilityState(resume);
  if (owned === undefined) throw new Error("resume capability was not created by this package instance");
  // An activation shares its admission's lock state whose consumed flag was set by the R2B transfer itself;
  // only an explicit work transfer (or release) retires an activation.
  if (owned.released || owned.workTransferred || (!activations.has(resume as object) && owned.consumed)) {
    throw new Error("resume capability is no longer active");
  }
  const taskId = selectedLeafTaskId(resume.binding.resume_point);
  if (taskId === null) return refused("RESUME_REFUSED_AMBIGUOUS_RESUME_POINT");
  try {
    await assertWorktreeLockHeld(owned.lock);
    const location = { stateRoot: owned.stateRoot, runId: resume.binding.run_id };
    const current = await inspectRunStorage(location);
    if (current.status !== "HEALTHY" || current.revision === null || current.statePointer === null || current.workflowState === null || current.transitionCommit === null) return refused("RESUME_REFUSED_STATE_STORE");
    const state = current.workflowState;
    if (state.execution_mode !== "STATIC_APPROVED_DAG" || state.active_task_id !== taskId) return refused("RESUME_REFUSED_STATE_STORE");
    // Capability-bound live-state verification: the reread state must be exactly the bound one.
    if (activations.has(resume as object)) {
      const binding = (resume as DeterministicResumeActivation).binding;
      if (current.revision !== binding.successor_revision || state.content_sha256 !== binding.successor_workflow_state_content_sha256 ||
        current.statePointer?.content_sha256 !== binding.successor_state_pointer_content_sha256 ||
        current.transitionCommit?.content_sha256 !== binding.successor_transition_commit_content_sha256 ||
        state.frozen_policy_content_sha256 !== binding.frozen_policy_content_sha256 || canonicalize(state.identities) !== canonicalize(binding.state_identities)) {
        return refused("RESUME_REFUSED_STATE_STORE");
      }
      if (binding.resume_point !== `STATIC_DAG_START_SELECTED_LEAF:${taskId}`) return refused("RESUME_REFUSED_STATE_STORE");
    } else {
      const binding = (resume as DeterministicResumeAdmission).binding;
      if (current.revision !== binding.state_revision || state.content_sha256 !== binding.workflow_state_content_sha256 ||
        current.statePointer?.content_sha256 !== binding.state_pointer_content_sha256 ||
        current.transitionCommit?.content_sha256 !== binding.transition_commit_content_sha256 ||
        state.frozen_policy_content_sha256 !== binding.frozen_policy_content_sha256 || canonicalize(state.identities) !== canonicalize(binding.state_identities)) {
        return refused("RESUME_REFUSED_STATE_STORE");
      }
    }
    const records = await readM5ManagedRecords(location);
    const authority = rehydrateStaticLeafAuthority(state, records, current.managedRecordClassifications);
    if (authority === null) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    // Live resume-point re-derivation must reproduce the capability's exact point.
    const livePreProvider = deriveStaticDagPreProviderResumePoint(state, authority.reducerPolicy, records, current.managedRecordClassifications, current.transitionCommit);
    const livePlain = deriveStaticDagResumePoint(state, authority.reducerPolicy);
    if (livePreProvider !== resume.binding.resume_point && livePlain !== resume.binding.resume_point) return refused("RESUME_REFUSED_STATE_STORE");
    const runningAlready = state.phase === "LEAF_RUNNING";
    const candidates = staticWorkDecisionCandidates(state, authority.reducerPolicy, records, current.managedRecordClassifications);
    // Run-global history snapshots: historical settled evidence is allowed to persist unchanged;
    // only CURRENT-operation deltas are constrained by this admission.
    const reservationsBefore = records.decisions.filter((entry) => entry.reservation !== null).length;
    const invocationsBefore = records.boundedWorkerInvocations.length;
    const resultsBefore = records.boundedWorkerResults.length;
    if (runningAlready) {
      // WINDOW B only: exactly the committed authoritative reservation may be replayed.
      if (livePreProvider !== `STATIC_DAG_INVOKE_RESERVED_LEAF:${taskId}` || candidates.length !== 1 ||
        exactStaticWorkDecision(state, authority.reducerPolicy, records, current.managedRecordClassifications, "AUTHORITATIVE_MANAGED_RECORD") === null) {
        return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
      }
    } else if (candidates.length > 1) {
      // Contradictory CURRENT-operation authority: multiple matching decisions refuse.
      // Settled predecessor-leaf reservations are valid history, not contradictions.
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    const operationId = staticLeafOperationId(taskId);
    const transitionId = staticLeafTransitionId(operationId);
    // Predecessor authority: the exact state the AUTHORIZE_WORK request is keyed against. Window B replays against
    // the committed START_LEAF_ATTEMPT predecessor so the existing lost-response recovery path applies.
    const expectedRevision = runningAlready ? current.transitionCommit.previous_revision : current.revision;
    const expectedPointer = runningAlready ? current.transitionCommit.previous_state_pointer_content_sha256 : current.statePointer?.content_sha256;
    const expectedWorkflow = runningAlready ? current.transitionCommit.previous_workflow_state_content_sha256 : state.content_sha256;
    if (expectedRevision === null || expectedPointer === null || expectedPointer === undefined || expectedWorkflow === null) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    // Production binds every accumulated usage-evidence record into the next leaf's AUTHORIZE_WORK request.
    // Usage records are published by the kernel call that consumes them, so a settled predecessor leaf's
    // reconciliation evidence may not be durable yet at this boundary; reconstruct it exactly from its durable
    // reservation+result pair (byte-identical builder; the kernel's exact binding validation fails closed).
    const candidateShas = new Set(candidates.map((decision) => decision.content_sha256));
    const reconstructedUsage = records.decisions
      .filter((decision) => decision.reservation !== null && !candidateShas.has(decision.content_sha256) &&
        !records.usage.some((entry) => entry.reservation_decision_content_sha256 === decision.content_sha256))
      .map((decision) => {
        const invocation = records.boundedWorkerInvocations.find((entry) => entry.m5_reservation_decision_content_sha256 === decision.content_sha256);
        const result = invocation === undefined ? undefined : records.boundedWorkerResults.find((entry) => entry.invocation_content_sha256 === invocation.content_sha256);
        if (invocation === undefined || result === undefined) return null;
        return buildBoundedWorkerUsageEvidence({ runId: resume.binding.run_id, policy: authority.policy, decision,
          executionMode: state.execution_mode, logicalRole: decision.reservation!.logical_role, result });
      })
      .filter((entry): entry is NonNullable<typeof entry> => entry !== null);
    const gitBefore = await captureGitState(authority.repositoryIdentity);
    const authoritativeSources: M5AuthoritativeSources = {
      boundedStaticPreM8: true, contract: authority.contract, budget: authority.budget, routeMap: authority.routeMap, routeMapApproval: authority.routeMapApproval,
      m4ToolPolicy: authority.toolPolicy, m4CommandCatalog: authority.commandCatalog, planApprovals: authority.planApprovals,
      taskGraphs: authority.taskGraphs, tasks: authority.tasks,
    };
    const kernel = createControlDecisionKernel({
      stateRoot: owned.stateRoot, runId: resume.binding.run_id, policy: authority.policy, reducerPolicy: authority.reducerPolicy,
      runAuthority: { repositoryIdentity: authority.repositoryIdentity, contract: authority.contract, routeMap: authority.routeMap, routeMapApproval: authority.routeMapApproval },
      authoritativeSources, production: false,
    });
    // V1-R2D-TIME-R1 GATE 1: load-bearing durable timing check IMMEDIATELY before
    // AUTHORIZE_WORK. R2C always operates on an already-selected leaf, so BOTH
    // workflow and node deadlines must resolve and be unexpired from the freshly
    // reread state and current classifications. On refusal no reservation/decision
    // delta and no worker invocation may occur.
    {
      const gateOneTiming = resolveApplicableResumeTiming({
        runId: resume.binding.run_id, state, tipCommit: current.transitionCommit,
        records: {
          transitionCommits: records.transitionCommits, workflowStates: records.workflowStates,
          transitionEvents: records.transitionEvents, authorities: records.staticTimeAuthorities,
        },
        verdicts: staticTimingVerdicts(current.managedRecordClassifications),
        nowMs: sampleWallClockMs(),
      });
      if (gateOneTiming.outcome === "REFUSED" || gateOneTiming.workflow === null || gateOneTiming.node === null) {
        return refused("RESUME_REFUSED_TIMING_AUTHORITY");
      }
    }
    let result: Awaited<ReturnType<typeof kernel.evaluateControlDecision>>;
    try {
      result = await kernel.evaluateControlDecision({
        intent: "AUTHORIZE_WORK", expectedRevision, expectedStatePointerContentSha256: expectedPointer as Sha256Digest,
        expectedWorkflowStateContentSha256: expectedWorkflow as Sha256Digest, transitionId, operationId,
        processMetadata: resumeProcessMetadata(), authoritativeSources,
        // Exact production slice semantics: persisted usage plus any not-yet-durable settled-leaf evidence.
        usageEvidence: [...reconstructedUsage, ...records.usage],
        availableLogicalRoles: resumedAvailableLogicalRoles(authority.policy),
      });
    } catch {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    if (!result.committed || result.decision.outcome !== "AUTHORIZE" || result.decision.reservation === null || result.decision.operation_id !== operationId) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    if (candidates.length === 1 && result.decision.content_sha256 !== candidates[0]!.content_sha256) return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    // Post-commit verification against freshly reread state and records.
    const successor = await inspectRunStorage(location);
    if (successor.status !== "HEALTHY" || successor.revision === null || successor.statePointer === null || successor.workflowState === null || successor.transitionCommit === null) return refused("RESUME_REFUSED_STATE_STORE");
    const after = successor.workflowState;
    const afterTask = after.tasks.find((entry) => entry.task_id === taskId);
    const countersBefore = state.counters.worker_invocations;
    const countersAfter = after.counters.worker_invocations;
    const expectedDelta = runningAlready ? 0 : 1;
    if (after.phase !== "LEAF_RUNNING" || after.active_task_id !== taskId || afterTask === undefined || afterTask.status !== "RUNNING" || afterTask.attempts !== 1 ||
      countersAfter.terra_executor !== countersBefore.terra_executor + expectedDelta || countersAfter.total !== countersBefore.total + expectedDelta ||
      countersAfter.sol_owner !== countersBefore.sol_owner || countersAfter.sol_planner !== countersBefore.sol_planner ||
      countersAfter.sol_replan !== countersBefore.sol_replan || countersAfter.sol_closeout !== countersBefore.sol_closeout ||
      countersAfter.luna_executor !== countersBefore.luna_executor) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    if (runningAlready) {
      if (successor.revision !== current.revision || successor.transitionCommit.content_sha256 !== current.transitionCommit.content_sha256) return refused("RESUME_REFUSED_STATE_STORE");
    } else if (successor.revision !== current.revision + 1 || successor.transitionCommit.previous_workflow_state_content_sha256 !== expectedWorkflow ||
      successor.transitionCommit.previous_revision !== current.revision || successor.transitionCommit.transition_id !== transitionId) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const recordsAfter = await readM5ManagedRecords(location);
    const afterCandidates = staticWorkDecisionCandidates(after, authority.reducerPolicy, recordsAfter, successor.managedRecordClassifications);
    const afterCurrent = currentOperationWorkerRecords(recordsAfter, operationId);
    // Clean admission adds one CURRENT-operation reservation; a Window A redrive reuses the already-published
    // decision (delta 0); a Window B replay commits nothing new (delta 0).
    const expectedReservationDelta = runningAlready || candidates.length === 1 ? 0 : 1;
    if (afterCandidates.length !== 1 || afterCandidates[0]!.content_sha256 !== result.decision.content_sha256 ||
      afterCurrent.invocations.length !== 0 || afterCurrent.results.length !== 0 ||
      recordsAfter.boundedWorkerInvocations.length !== invocationsBefore || recordsAfter.boundedWorkerResults.length !== resultsBefore ||
      recordsAfter.decisions.filter((entry) => entry.reservation !== null).length !== reservationsBefore + expectedReservationDelta ||
      classificationOf(successor.managedRecordClassifications, "M5_CONTROL_DECISION", result.decision.content_sha256) !== "AUTHORITATIVE_MANAGED_RECORD") {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    const gitAfter = await captureGitState(authority.repositoryIdentity);
    if (canonicalize(gitAfter) !== canonicalize(gitBefore)) return refused("RESUME_REFUSED_STATE_DRIFT");
    await assertWorktreeLockHeld(owned.lock);
    // V1-R2D-TIME-R1 (B): load-bearing final recheck. Immediately before any work
    // authority is constructed or the flock transfers, reread current storage and
    // records again and re-resolve durable timing. Expiry in the meantime refuses
    // here: the committed AUTHORIZE_WORK decision stays put, but NO usable
    // DeterministicResumeWorkAdmission escapes and no worker may ever be invoked.
    {
      const transferInspection = await inspectRunStorage(location);
      if (transferInspection.status !== "HEALTHY" || transferInspection.revision === null || transferInspection.statePointer === null || transferInspection.workflowState === null || transferInspection.transitionCommit === null) {
        return refused("RESUME_REFUSED_STATE_STORE");
      }
      const transferRecords = await readM5ManagedRecords(location);
      const transferTiming = resolveApplicableResumeTiming({
        runId: resume.binding.run_id, state: transferInspection.workflowState!, tipCommit: transferInspection.transitionCommit!,
        records: {
          transitionCommits: transferRecords.transitionCommits, workflowStates: transferRecords.workflowStates,
          transitionEvents: transferRecords.transitionEvents, authorities: transferRecords.staticTimeAuthorities,
        },
        verdicts: staticTimingVerdicts(transferInspection.managedRecordClassifications),
        nowMs: sampleWallClockMs(),
      });
      if (transferTiming.outcome === "REFUSED" || transferTiming.workflow === null || transferTiming.node === null) {
        return refused("RESUME_REFUSED_TIMING_AUTHORITY");
      }
    }
    const reservation = result.decision.reservation;
    if (reservation.logical_role !== "TERRA_EXECUTOR" && reservation.logical_role !== "CODING_EXECUTOR") return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    const frozenRole = reservation.logical_role;
    const roleRoutes = authority.routeMap.routes.filter((entry) => entry.logical_role === frozenRole);
    if (roleRoutes.length !== 1) return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    const roleRoute = roleRoutes[0]!;
    const binding: DeterministicResumeWorkAdmissionBinding = Object.freeze({
      run_id: resume.binding.run_id, selected_task_id: taskId, selected_task_content_sha256: authority.selectedTask.content_sha256 as Sha256Digest,
      task_graph_sha256: (authority.policy.task_graph_sha256 ?? null) as Sha256Digest | null,
      plan_approval_sha256: (authority.policy.plan_approval_sha256 ?? null) as Sha256Digest | null,
      operation_id: operationId, attempt_number: 1, reducer_policy_content_sha256: authority.reducerPolicy.content_sha256 as Sha256Digest,
      m5_policy_content_sha256: authority.policy.content_sha256 as Sha256Digest, m5_decision_content_sha256: result.decision.content_sha256 as Sha256Digest,
      reservation_decision_key: (reservation.reservation_decision_key ?? null) as Sha256Digest | null,
      frozen_logical_role: frozenRole, provider_id: roleRoute.provider_id, model_id: roleRoute.model_id, effort: roleRoute.effort,
      model_definition_sha256: (("model_definition_sha256" in roleRoute ? roleRoute.model_definition_sha256 : null) ?? null) as Sha256Digest | null,
      repository_identity_content_sha256: authority.repositoryIdentity.content_sha256 as Sha256Digest, worktree_key: authority.repositoryIdentity.worktree_key as Sha256Digest,
      worktree_root: authority.repositoryIdentity.worktree_root, git_common_dir: authority.repositoryIdentity.git_common_dir,
      input_m3_state_token_content_sha256: authority.stateToken.content_sha256 as Sha256Digest,
      predecessor_revision: expectedRevision, predecessor_workflow_state_content_sha256: expectedWorkflow as Sha256Digest,
      predecessor_state_pointer_content_sha256: expectedPointer as Sha256Digest, successor_revision: successor.revision,
      successor_workflow_state_content_sha256: after.content_sha256 as Sha256Digest, successor_state_pointer_content_sha256: successor.statePointer.content_sha256 as Sha256Digest,
      successor_transition_commit_content_sha256: successor.transitionCommit.content_sha256 as Sha256Digest,
    });
    owned.consumed = true; owned.workTransferred = true;
    return new DeterministicResumeWorkAdmissionImpl(binding, { lock: owned.lock, stateRoot: owned.stateRoot, released: false, consumed: false, workTransferred: false });
  } catch (error: unknown) {
    try { await releaseOwnedLock(owned); } catch (releaseError: unknown) { throw releaseError; }
    throw error;
  }
}

export async function assertDeterministicResumeWorkAdmissionHeld(admission: DeterministicResumeWorkAdmission): Promise<void> {
  const state = workAdmissionState(admission);
  if (state.released || state.consumed) throw new Error("resume work admission is no longer active");
  await assertWorktreeLockHeld(state.lock);
}

export async function releaseDeterministicResumeWorkAdmission(admission: DeterministicResumeWorkAdmission): Promise<void> {
  const state = workAdmissionState(admission);
  if (state.consumed) throw new Error("resume work admission ownership was transferred");
  await releaseOwnedLock(state);
}

export interface DeterministicResumeWorkerResultBinding {
  readonly run_id: string;
  readonly selected_task_id: string;
  readonly selected_task_content_sha256: Sha256Digest;
  readonly operation_id: string;
  readonly attempt_number: 1;
  readonly m5_decision_content_sha256: Sha256Digest;
  readonly reservation_decision_key: Sha256Digest | null;
  readonly invocation_content_sha256: Sha256Digest;
  readonly result_content_sha256: Sha256Digest;
  readonly input_m3_state_token_content_sha256: Sha256Digest;
  readonly final_gateway_state_token_content_sha256: Sha256Digest;
  readonly accepted_m4_evidence_count: number;
  readonly frozen_logical_role: "TERRA_EXECUTOR" | "CODING_EXECUTOR";
  readonly provider_id: string;
  readonly model_id: string;
  readonly effort: string;
  readonly model_definition_sha256: Sha256Digest | null;
  readonly result_outcome: "COMPLETED" | "BLOCKED";
  readonly cleanup_certain: boolean;
}

export interface DeterministicResumeWorkerResult {
  readonly binding: DeterministicResumeWorkerResultBinding;
}

type ResumedWorkerRunner = (input: RunBoundedWorkerInput) => Promise<BoundedWorkerExecutionResult>;

/**
 * V1-R2D: execute exactly one bounded worker for the admitted resumed leaf through the existing
 * bounded-worker protocol and a freshly recreated M4 scoped-tool gateway, all under the SAME M3 flock.
 * Stops before controller COMPLETE_LEAF_ATTEMPT: reducer reconciliation belongs to R2E.
 */
async function executeResumedLeafWorkerImpl(admission: DeterministicResumeWorkAdmission, runner: ResumedWorkerRunner): Promise<DeterministicResumeWorkerResult> {
  const owned = workAdmissionState(admission);
  if (owned.released || owned.consumed) throw new Error("resume work admission is no longer active");
  let temporaryRoot: string | undefined;
  let cleanupAttempted = false;
  try {
    await assertWorktreeLockHeld(owned.lock);
    const binding = admission.binding;
    const location = { stateRoot: owned.stateRoot, runId: binding.run_id };
    // Fresh revalidation of the exact R2C binding while holding the flock.
    const current = await inspectRunStorage(location);
    if (current.status !== "HEALTHY" || current.revision === null || current.statePointer === null || current.workflowState === null || current.transitionCommit === null) return refused("RESUME_REFUSED_STATE_STORE");
    const state = current.workflowState;
    if (current.revision !== binding.successor_revision || current.statePointer.content_sha256 !== binding.successor_state_pointer_content_sha256 ||
      state.content_sha256 !== binding.successor_workflow_state_content_sha256 ||
      current.transitionCommit.content_sha256 !== binding.successor_transition_commit_content_sha256 ||
      state.frozen_policy_content_sha256 !== binding.reducer_policy_content_sha256) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const taskId = binding.selected_task_id;
    if (state.phase !== "LEAF_RUNNING" || state.active_task_id !== taskId) return refused("RESUME_REFUSED_STATE_STORE");
    const selectedTask = state.tasks.find((entry) => entry.task_id === taskId);
    if (selectedTask === undefined || selectedTask.status !== "RUNNING" || selectedTask.attempts !== 1) return refused("RESUME_REFUSED_STATE_STORE");
    const records = await readM5ManagedRecords(location);
    const authority = rehydrateStaticLeafAuthority(state, records, current.managedRecordClassifications);
    if (authority === null) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    if (!classificationsInclude(current.managedRecordClassifications, "M5_CONTROL_POLICY", authority.policy.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")) {
      return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    }
    if (binding.m5_policy_content_sha256 !== authority.policy.content_sha256 ||
      binding.repository_identity_content_sha256 !== authority.repositoryIdentity.content_sha256 ||
      binding.worktree_key !== authority.repositoryIdentity.worktree_key || binding.worktree_root !== authority.repositoryIdentity.worktree_root ||
      binding.git_common_dir !== authority.repositoryIdentity.git_common_dir) {
      return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    }
    if (binding.selected_task_content_sha256 !== authority.selectedTask.content_sha256 as Sha256Digest ||
      binding.task_graph_sha256 !== (authority.policy.task_graph_sha256 ?? null) ||
      binding.plan_approval_sha256 !== (authority.policy.plan_approval_sha256 ?? null)) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    // Exact M5 decision/reservation identity from the R2C admission.
    const decisions = records.decisions.filter((entry) => entry.content_sha256 === binding.m5_decision_content_sha256);
    const decision = decisions.length === 1 ? decisions[0]! : null;
    if (decision === null || decision.operation_id !== binding.operation_id || decision.reservation === null ||
      decision.policy_content_sha256 !== binding.m5_policy_content_sha256 ||
      decision.reservation.future_operation_id !== binding.operation_id ||
      decision.reservation.reservation_decision_key !== binding.reservation_decision_key ||
      decision.reducer_policy_content_sha256 !== binding.reducer_policy_content_sha256) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    // Exact frozen route identity; no rerouting, no substitution, no fallback.
    const roleRoutes = authority.routeMap.routes.filter((entry) => entry.logical_role === binding.frozen_logical_role);
    const roleRoute = roleRoutes.length === 1 ? roleRoutes[0]! : null;
    if (roleRoute === null || roleRoute.provider_id !== binding.provider_id || roleRoute.model_id !== binding.model_id || roleRoute.effort !== binding.effort ||
      (("model_definition_sha256" in roleRoute ? roleRoute.model_definition_sha256 : null) ?? null) !== binding.model_definition_sha256) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    // Exact bound input M3 token: authoritative, still the unique chain tip, matching the live repository.
    const inputTokens = records.stateTokens.filter((entry) => entry.content_sha256 === binding.input_m3_state_token_content_sha256 &&
      classificationsInclude(current.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD"));
    if (inputTokens.length !== 1 || tokenTip(records.stateTokens.filter((entry) => entry.run_id === authority.policy.run_id &&
      entry.repository_identity_content_sha256 === authority.policy.repository_identity_content_sha256 && entry.worktree_key === authority.policy.worktree_key &&
      entry.task_scope_identity === authority.policy.scope_sha256 && classificationsInclude(current.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")))?.content_sha256 !== binding.input_m3_state_token_content_sha256) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const inputToken = inputTokens[0]!;
    // Provider-safety boundary: no CURRENT-operation worker evidence may exist.
    const priorCurrent = currentOperationWorkerRecords(records, binding.operation_id);
    if (priorCurrent.invocations.length !== 0 || priorCurrent.results.length !== 0) return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    const countersBefore = state.counters.worker_invocations;
    const reservationsBefore = records.decisions.filter((entry) => entry.reservation !== null).length;
    // Gate A: reread durable state and timing immediately before allowance/depth
    // admission. No handover or M4 publication is legal before this check.
    const gateAInspection = await inspectRunStorage(location);
    if (gateAInspection.status !== "HEALTHY" || gateAInspection.revision === null || gateAInspection.statePointer === null ||
      gateAInspection.workflowState === null || gateAInspection.transitionCommit === null ||
      gateAInspection.revision !== binding.successor_revision || gateAInspection.statePointer.content_sha256 !== binding.successor_state_pointer_content_sha256 ||
      gateAInspection.workflowState.content_sha256 !== binding.successor_workflow_state_content_sha256 ||
      gateAInspection.transitionCommit.content_sha256 !== binding.successor_transition_commit_content_sha256) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const gateARecords = await readM5ManagedRecords(location);
    const gateATiming = resolveApplicableResumeTiming({
      runId: binding.run_id, state: gateAInspection.workflowState, tipCommit: gateAInspection.transitionCommit,
      records: { transitionCommits: gateARecords.transitionCommits, workflowStates: gateARecords.workflowStates,
        transitionEvents: gateARecords.transitionEvents, authorities: gateARecords.staticTimeAuthorities },
      verdicts: staticTimingVerdicts(gateAInspection.managedRecordClassifications), nowMs: sampleWallClockMs(),
    });
    if (gateATiming.outcome === "REFUSED" || gateATiming.workflow === null || gateATiming.node === null) {
      return refused("RESUME_REFUSED_TIMING_AUTHORITY");
    }
    let inputTokenAuthority: Awaited<ReturnType<typeof loadAuthoritativeToken>>;
    try {
      inputTokenAuthority = await loadAuthoritativeToken(location, inputToken, authority.baseline);
    } catch {
      return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    }
    const mutation = resolveStaticMaxM4MutationCalls(authority.policy);
    if (mutation.outcome === "NOT_STATIC") return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    if (mutation.outcome === "ABSENT") return refused("FROZEN_MUTATION_ALLOWANCE_NOT_DURABLE");
    if (inputTokenAuthority.token.content_sha256 !== inputToken.content_sha256 ||
      inputTokenAuthority.chainDepth + 1 + mutation.value > 64) {
      return refused("STATE_TOKEN_CHAIN_TOO_DEEP");
    }
    // R2D0: explicitly transfer T_A to a fresh T_B under the same held flock.
    const handover = await runResumeLockHandover({
      stateRoot: owned.stateRoot, runId: binding.run_id, acceptedState: inputToken, baseline: authority.baseline,
      instructionFiles: [], authorityFiles: [], taskScopeIdentity: authority.policy.scope_sha256 as Sha256Digest, lock: owned.lock,
    });
    const workerInputToken = handover.acceptedState;
    if (workerInputToken.content_sha256 === inputToken.content_sha256) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    await resumeWorkerCheckpoint("AFTER_RESUME_HANDOVER");
    // Gate B: timing is reread after T_A -> T_B and before M4 gateway creation.
    const gateBInspection = await inspectRunStorage(location);
    if (gateBInspection.status !== "HEALTHY" || gateBInspection.workflowState === null || gateBInspection.transitionCommit === null) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const gateBRecords = await readM5ManagedRecords(location);
    const gateBTiming = resolveApplicableResumeTiming({
      runId: binding.run_id, state: gateBInspection.workflowState, tipCommit: gateBInspection.transitionCommit,
      records: { transitionCommits: gateBRecords.transitionCommits, workflowStates: gateBRecords.workflowStates,
        transitionEvents: gateBRecords.transitionEvents, authorities: gateBRecords.staticTimeAuthorities },
      verdicts: staticTimingVerdicts(gateBInspection.managedRecordClassifications), nowMs: sampleWallClockMs(),
    });
    if (gateBTiming.outcome === "REFUSED" || gateBTiming.workflow === null || gateBTiming.node === null) {
      return refused("RESUME_REFUSED_TIMING_AUTHORITY");
    }
    const tipAfterHandover = tokenTip(gateBRecords.stateTokens.filter((entry) => entry.run_id === authority.policy.run_id &&
      entry.repository_identity_content_sha256 === authority.policy.repository_identity_content_sha256 && entry.worktree_key === authority.policy.worktree_key &&
      entry.task_scope_identity === authority.policy.scope_sha256 && classificationsInclude(gateBInspection.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")));
    if (tipAfterHandover?.content_sha256 !== workerInputToken.content_sha256) return refused("RESUME_REFUSED_STATE_STORE");
    // Recreate the existing M4 gateway under the same lock with a fresh safe temporary root.
    temporaryRoot = await mkdtemp(join(tmpdir(), "pi-resumed-worker-"));
    const planDocument = authority.planApprovals[0]!;
    const graphDocument = authority.taskGraphs[0]!;
    const gateway = await createScopedToolGateway({
      stateRoot: owned.stateRoot, runId: binding.run_id, repository: authority.repositoryIdentity, baseline: authority.baseline,
      acceptedState: workerInputToken, lock: owned.lock, instructionFiles: [], authorityFiles: [],
      editablePaths: [...planDocument.bindings.scope.editable_paths], frozenPaths: [...planDocument.bindings.scope.frozen_paths],
      taskScopeIdentity: authority.policy.scope_sha256 as Sha256Digest, toolPolicy: authority.toolPolicy, commandCatalog: authority.commandCatalog,
      temporaryRoot: temporaryRoot as string,
    });
    await resumeWorkerCheckpoint("AFTER_RESUME_GATEWAY_CREATED");
    // Gate C: gateway setup is non-provider, but the final pre-provider boundary
    // still rereads timing and rejects any current-operation replay.
    const gateCInspection = await inspectRunStorage(location);
    if (gateCInspection.status !== "HEALTHY" || gateCInspection.workflowState === null || gateCInspection.transitionCommit === null) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const gateCRecords = await readM5ManagedRecords(location);
    const gateCTiming = resolveApplicableResumeTiming({
      runId: binding.run_id, state: gateCInspection.workflowState, tipCommit: gateCInspection.transitionCommit,
      records: { transitionCommits: gateCRecords.transitionCommits, workflowStates: gateCRecords.workflowStates,
        transitionEvents: gateCRecords.transitionEvents, authorities: gateCRecords.staticTimeAuthorities },
      verdicts: staticTimingVerdicts(gateCInspection.managedRecordClassifications), nowMs: sampleWallClockMs(),
    });
    if (gateCTiming.outcome === "REFUSED" || gateCTiming.workflow === null || gateCTiming.node === null) {
      return refused("RESUME_REFUSED_TIMING_AUTHORITY");
    }
    const gateCCurrent = currentOperationWorkerRecords(gateCRecords, binding.operation_id);
    if (gateCCurrent.invocations.length !== 0 || gateCCurrent.results.length !== 0) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    const tipAtGateC = tokenTip(gateCRecords.stateTokens.filter((entry) => entry.run_id === authority.policy.run_id &&
      entry.repository_identity_content_sha256 === authority.policy.repository_identity_content_sha256 && entry.worktree_key === authority.policy.worktree_key &&
      entry.task_scope_identity === authority.policy.scope_sha256 && classificationsInclude(gateCInspection.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")));
    if (tipAtGateC?.content_sha256 !== workerInputToken.content_sha256) return refused("RESUME_REFUSED_STATE_STORE");
    // Launch contract identical to ordinary STATIC_APPROVED_DAG execution for this leaf.
    const readableScope = partitionProviderVisibleReadScope(authority.selectedTask.scope.readable_paths, authority.toolPolicy.path_authorities);
    // Consume the exact durable P0 mutation allowance for both the worker and
    // the pre-handover token-depth reservation; no default or alternate source is used.
    const maxM4MutationCalls = mutation.value;
    const hardMutationToolLimit: 1 | null = maxM4MutationCalls === 1 ? 1 : null;
    const modelTurnBudget = decision.budget.find((entry) => entry.dimension === "MODEL_TURN")?.soft_remaining;
    if (modelTurnBudget === undefined || modelTurnBudget === null) {
      throw Object.assign(new Error("M5 did not provide an enforceable model-turn admission remainder"), { code: "M5_MODEL_TURN_AUTHORITY" });
    }
    await assertWorktreeLockHeld(owned.lock);
    const execution = await runner({
      stateRoot: owned.stateRoot, runId: binding.run_id, operationId: binding.operation_id, reservation: decision,
      task: authority.selectedTask, taskGraph: graphDocument, plan: planDocument, inputStateToken: workerInputToken, lock: owned.lock, gateway,
      route: { logicalRole: binding.frozen_logical_role, providerId: binding.provider_id, modelId: binding.model_id, effort: binding.effort as "high",
        modelDefinitionSha256: binding.model_definition_sha256 },
      profile: "MUTATION_EXECUTOR", systemPrompt: boundedWorkerSystemPrompt("MUTATION_EXECUTOR"),
      userPrompt: providerVisibleTaskContract(authority.selectedTask.objective, readableScope, authority.selectedTask.scope.editable_paths, null, hardMutationToolLimit === 1 ? 1 : null),
      allowedReadPaths: readableScope.regularFilePaths, allowedEditPaths: authority.selectedTask.scope.editable_paths,
      maxM4ToolCalls: roleRoute.tool_policy.maximum_tool_calls ?? BOUNDED_WORKER_MAX_TOOL_CALLS, maxM4MutationCalls,
      maxModelTurns: modelTurnBudget,
      deadlineMs: planDocument.bindings.limits.static_time_budgets?.worker_deadline_ms ?? BOUNDED_WORKER_MAX_WALL_TIME_MS,
    });
    // Durable verification against freshly reread records.
    const successor = await inspectRunStorage(location);
    if (successor.status !== "HEALTHY" || successor.workflowState === null) return refused("RESUME_REFUSED_STATE_STORE");
    const successorTask = successor.workflowState.tasks.find((entry) => entry.task_id === taskId);
    if (successor.workflowState.phase !== "LEAF_RUNNING" || successor.workflowState.active_task_id !== taskId || successorTask?.status !== "RUNNING" || successorTask.attempts !== 1 ||
      canonicalize(successor.workflowState.counters.worker_invocations) !== canonicalize(countersBefore)) {
      return refused("RESUME_REFUSED_STATE_STORE");
    }
    const recordsAfter = await readM5ManagedRecords(location);
    const afterCurrent = currentOperationWorkerRecords(recordsAfter, binding.operation_id);
    if (afterCurrent.invocations.length !== 1 || afterCurrent.results.length !== 1 ||
      afterCurrent.invocations[0]!.content_sha256 !== execution.invocation.content_sha256 || afterCurrent.results[0]!.content_sha256 !== execution.result.content_sha256 ||
      afterCurrent.invocations[0]!.input_m3_state_token_content_sha256 !== workerInputToken.content_sha256 ||
      recordsAfter.boundedWorkerInvocations.length !== records.boundedWorkerInvocations.length + 1 ||
      recordsAfter.boundedWorkerResults.length !== records.boundedWorkerResults.length + 1 ||
      recordsAfter.decisions.filter((entry) => entry.reservation !== null).length !== reservationsBefore ||
      !classificationsInclude(successor.managedRecordClassifications, "BOUNDED_WORKER_INVOCATION", execution.invocation.content_sha256, "AUTHORITATIVE_MANAGED_RECORD") ||
      !classificationsInclude(successor.managedRecordClassifications, "BOUNDED_WORKER_RESULT", execution.result.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    const finalToken = tokenTip(recordsAfter.stateTokens.filter((entry) => entry.run_id === authority.policy.run_id &&
      entry.repository_identity_content_sha256 === authority.policy.repository_identity_content_sha256 && entry.worktree_key === authority.policy.worktree_key &&
      entry.task_scope_identity === authority.policy.scope_sha256 && classificationsInclude(successor.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")));
    if (finalToken?.content_sha256 !== gateway.acceptedState.content_sha256) return refused("RESUME_REFUSED_STATE_STORE");
    const reservationStates = recordsAfter.workflowStates.filter((entry) => entry.content_sha256 === decision.current_state_content_sha256);
    const resolvedExecution = reservationStates.length === 1
      ? resolveAuthoritativeBoundedExecution({
        invocation: execution.invocation, result: execution.result, reservation: decision,
        reservationState: reservationStates[0]!, policy: authority.policy, baseline: authority.baseline, approval: authority.baselineApproval,
        stateToken: workerInputToken, task: authority.selectedTask, taskGraph: graphDocument, plan: planDocument,
        admissionRefusals: new Map(recordsAfter.admissionRefusals.map((entry) => [entry.content_sha256, entry])),
        classifications: successor.managedRecordClassifications,
      })
      : null;
    if (resolvedExecution === null || !resolvedExecution.accepted || resolvedExecution.acceptedWorkerInvocations !== 1) {
      return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
    }
    if (execution.result.outcome === "COMPLETED" && resolvedExecution.acceptedM4Evidence.length === 0) {
      return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    }
    await assertWorktreeLockHeld(owned.lock);
    const resultBinding: DeterministicResumeWorkerResultBinding = Object.freeze({
      run_id: binding.run_id, selected_task_id: taskId, selected_task_content_sha256: binding.selected_task_content_sha256,
      operation_id: binding.operation_id, attempt_number: 1,
      m5_decision_content_sha256: binding.m5_decision_content_sha256, reservation_decision_key: binding.reservation_decision_key,
      invocation_content_sha256: execution.invocation.content_sha256 as Sha256Digest, result_content_sha256: execution.result.content_sha256 as Sha256Digest,
      input_m3_state_token_content_sha256: workerInputToken.content_sha256 as Sha256Digest,
      final_gateway_state_token_content_sha256: gateway.acceptedState.content_sha256 as Sha256Digest,
      accepted_m4_evidence_count: resolvedExecution.acceptedM4Evidence.length,
      frozen_logical_role: binding.frozen_logical_role, provider_id: binding.provider_id, model_id: binding.model_id, effort: binding.effort,
      model_definition_sha256: binding.model_definition_sha256,
      result_outcome: execution.result.outcome, cleanup_certain: execution.result.cleanup_certain,
    });
    await resumeWorkerCheckpoint("AFTER_RESUMED_RESULT_PERSISTED");
    owned.consumed = true; owned.workTransferred = true;
    cleanupAttempted = true;
    await cleanupResumedWorkerOwnership(owned, temporaryRoot);
    temporaryRoot = undefined;
    return Object.freeze({ binding: resultBinding });
  } catch (error: unknown) {
    if (!cleanupAttempted) {
      cleanupAttempted = true;
      await cleanupResumedWorkerOwnership(owned, temporaryRoot);
    }
    throw error;
  }
}

function classificationsInclude(classifications: readonly ManagedRecordClassification[], kind: string, digest: string, classification: string): boolean {
  return classifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest && entry.classification === classification);
}

/** Production entry: executes the resumed leaf through the real bounded-worker path. */
export async function executeDeterministicResumedLeafWorker(admission: DeterministicResumeWorkAdmission): Promise<DeterministicResumeWorkerResult> {
  const { runBoundedWorker } = await import("./pi-adapter/bounded-worker.js");
  return executeResumedLeafWorkerImpl(admission, runBoundedWorker);
}

/** Package-internal faux-runtime-only seam; acceptance tests must use this so REAL_PROVIDER_RUNS stays zero. */
export async function executeDeterministicResumedLeafWorkerForTests(admission: DeterministicResumeWorkAdmission): Promise<DeterministicResumeWorkerResult> {
  const { runBoundedWorkerForTests } = await import("./pi-adapter/bounded-worker.js");
  return executeResumedLeafWorkerImpl(admission, runBoundedWorkerForTests);
}


type R2EInspection = Awaited<ReturnType<typeof inspectRunStorage>>;
type R2ERecords = Awaited<ReturnType<typeof readM5ManagedRecords>>;
type R2EHealthyInspection = R2EInspection & {
  readonly revision: number;
  readonly statePointer: NonNullable<R2EInspection["statePointer"]>;
  readonly workflowState: WorkflowState;
  readonly transitionCommit: NonNullable<R2EInspection["transitionCommit"]>;
};

type R2EVerificationOutcome = "PASSED" | "FAILED";

export interface DeterministicResumeReconciliationResult {
  readonly run_id: string;
  readonly task_id: string;
  readonly operation_id: string;
  readonly invocation_content_sha256: Sha256Digest;
  readonly result_content_sha256: Sha256Digest;
  readonly usage_content_sha256: Sha256Digest;
  readonly command_result_content_sha256: readonly Sha256Digest[];
  readonly postflight_content_sha256: readonly Sha256Digest[];
  readonly verification_outcome: R2EVerificationOutcome;
  readonly failure_class: string | null;
  readonly final_phase: WorkflowState["phase"];
  readonly final_state: WorkflowState;
  readonly m3_tip_content_sha256: Sha256Digest;
  readonly worker_replay: false;
  readonly usage_reconciled: true;
  readonly lock_released: true;
}

interface R2EContext {
  readonly inspection: R2EHealthyInspection;
  readonly records: R2ERecords;
  readonly authority: import("./resume-inspection.js").SettledStaticLeafAuthority;
  readonly currentTokenAuthority: Awaited<ReturnType<typeof loadAuthoritativeToken>>;
}

function isHealthyR2EInspection(value: R2EInspection): value is R2EHealthyInspection {
  return value.status === "HEALTHY" && value.revision !== null && value.statePointer !== null && value.workflowState !== null && value.transitionCommit !== null;
}

function r2eProcessMetadata() {
  return { controller_instance_id: "deterministic-resume-reconciliation", process_id: Math.max(1, process.pid), invocation_id: "deterministic-resume-reconciliation" };
}

function r2eEventId(transitionId: string, state: WorkflowState, payload: Record<string, unknown>): string {
  return `r2e-event-${sha256Canonical({ transitionId, state: state.content_sha256, payload }).slice(7, 39)}`;
}

function assertR2ETiming(context: R2EContext): void {
  const timing = resolveApplicableResumeTiming({
    runId: context.inspection.workflowState.run_id, state: context.inspection.workflowState, tipCommit: context.inspection.transitionCommit,
    records: {
      transitionCommits: context.records.transitionCommits, workflowStates: context.records.workflowStates,
      transitionEvents: context.records.transitionEvents, authorities: context.records.staticTimeAuthorities,
    }, verdicts: staticTimingVerdicts(context.inspection.managedRecordClassifications), nowMs: sampleWallClockMs(),
  });
  if (timing.outcome === "REFUSED" || timing.workflow === null || timing.node === null) return refused("RESUME_REFUSED_TIMING_AUTHORITY");
}

function assertR2ECapacity(context: R2EContext): void {
  const current = context.currentTokenAuthority;
  if (current.token.content_sha256 !== context.authority.currentStateToken.content_sha256) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
  const verifierPostflightCount = context.authority.task.verification_commands.length;
  if (current.chainDepth + 1 + Math.max(1, verifierPostflightCount) > 64) return refused("STATE_TOKEN_CHAIN_TOO_DEEP");
}

function authoritativeTokenChain(
  records: R2ERecords,
  classifications: readonly ManagedRecordClassification[],
  ancestorContentSha256: string,
  tip: M3RepositoryStateTokenDocument,
): readonly M3RepositoryStateTokenDocument[] | null {
  const byDigest = new Map(records.stateTokens.map((entry) => [entry.content_sha256, entry]));
  const chain: M3RepositoryStateTokenDocument[] = [];
  const seen = new Set<string>();
  let cursor: M3RepositoryStateTokenDocument | undefined = tip;
  while (cursor !== undefined && !seen.has(cursor.content_sha256)) {
    seen.add(cursor.content_sha256);
    if (!classificationsInclude(classifications, "M3_REPOSITORY_STATE_TOKEN", cursor.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")) return null;
    chain.push(cursor);
    if (cursor.content_sha256 === ancestorContentSha256) return chain.reverse();
    cursor = cursor.prior_token_content_sha256 === null ? undefined : byDigest.get(cursor.prior_token_content_sha256);
  }
  return null;
}

function workerTerminalToken(
  authority: import("./resume-inspection.js").SettledStaticLeafAuthority,
  records: R2ERecords,
  classifications: readonly ManagedRecordClassification[],
): M3RepositoryStateTokenDocument | null {
  const evidenced = new Set([authority.inputStateToken.content_sha256, ...authority.result.m3_evidence_content_sha256]);
  const tokens = records.stateTokens.filter((entry) => evidenced.has(entry.content_sha256) &&
    classificationsInclude(classifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD"));
  const tips = tokens.filter((entry) => !tokens.some((candidate) => candidate.prior_token_content_sha256 === entry.content_sha256));
  return tips.length === 1 ? tips[0]! : null;
}

async function readR2EContext(admission: DeterministicResumeAdmission, requireBinding: boolean): Promise<R2EContext> {
  const owned = admissionState(admission);
  await assertWorktreeLockHeld(owned.lock);
  const location = { stateRoot: owned.stateRoot, runId: admission.binding.run_id };
  const inspection = await inspectRunStorage(location);
  if (!isHealthyR2EInspection(inspection)) return refused("RESUME_REFUSED_STATE_STORE");
  const records = await readM5ManagedRecords(location);
  const authority = resolveSettledStaticLeafAuthority(inspection.workflowState, records, inspection.managedRecordClassifications);
  if (authority === null) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
  const point = deriveStaticDagR2EResumePoint(inspection.workflowState, inspection.transitionCommit, records, inspection.managedRecordClassifications);
  if (point === null || (requireBinding && point !== admission.binding.resume_point)) return refused("RESUME_REFUSED_STATE_STORE");
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: authority.repositoryIdentity.worktree_root, requireHead: true });
    assertRepositoryMatches(authority.repositoryIdentity, repository);
    const current = await loadAuthoritativeToken(location, authority.currentStateToken, authority.baseline);
    const input = await loadAuthoritativeToken(location, authority.inputStateToken, authority.baseline);
    if (current.token.content_sha256 !== authority.currentStateToken.content_sha256 || input.token.content_sha256 !== authority.inputStateToken.content_sha256 ||
        authoritativeTokenChain(records, inspection.managedRecordClassifications, authority.inputStateToken.content_sha256, authority.currentStateToken) === null) {
      return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    }
    const fingerprint = await captureGitState(repository);
    assertNoGitBlockers(fingerprint);
    if (canonicalize(fingerprint) !== canonicalize(authority.currentStateToken.git_fingerprint)) return refused("RESUME_REFUSED_STATE_DRIFT");
    return { inspection, records, authority, currentTokenAuthority: current };
  } catch {
    return refused("RESUME_REFUSED_REPOSITORY_IDENTITY");
  }
}

function reconciliationSources(context: R2EContext): M5AuthoritativeSources {
  const { authority, records, inspection } = context;
  return {
    boundedStaticPreM8: true, contract: authority.contract, budget: authority.budget, routeMap: authority.routeMap, routeMapApproval: authority.routeMapApproval,
    m4ToolPolicy: authority.toolPolicy, m4CommandCatalog: authority.commandCatalog, planApprovals: [authority.plan], taskGraphs: [authority.taskGraph], tasks: records.tasks,
    boundedWorkerResults: [authority.result],
    m3StateTokens: records.stateTokens.filter((entry) => classificationsInclude(inspection.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")),
    m3Postflights: records.postflights.filter((entry) => classificationsInclude(inspection.managedRecordClassifications, "M3_POSTFLIGHT", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")),
    workflowStates: records.workflowStates, transitionEvents: records.transitionEvents, transitionCommits: records.transitionCommits,
  };
}

async function reconcileSettledWorkerUsage(admission: DeterministicResumeAdmission, context: R2EContext): Promise<R2EContext> {
  const { authority, inspection } = context;
  if (inspection.workflowState.phase !== "LEAF_RUNNING") return context;
  const usage = buildBoundedWorkerUsageEvidence({
    runId: authority.policy.run_id, policy: authority.policy, decision: authority.reservation,
    executionMode: inspection.workflowState.execution_mode, logicalRole: authority.reservation.reservation!.logical_role, result: authority.result,
  });
  assertR2ETiming(context);
  await resumeReconciliationCheckpoint("BEFORE_USAGE_RECONCILIATION");
  const sources = reconciliationSources(context);
  const kernel = createControlDecisionKernel({
    stateRoot: admissionState(admission).stateRoot, runId: authority.policy.run_id, policy: authority.policy, reducerPolicy: authority.reducerPolicy,
    runAuthority: { repositoryIdentity: authority.repositoryIdentity, contract: authority.contract, routeMap: authority.routeMap, routeMapApproval: authority.routeMapApproval },
    authoritativeSources: sources, production: false,
  });
  const startEvent = context.records.transitionEvents.find((entry) => entry.content_sha256 === inspection.transitionCommit.transition_event_content_sha256);
  if (startEvent?.event_type !== "START_LEAF_ATTEMPT") return refused("RESUME_REFUSED_STATE_STORE");
  const result = await kernel.evaluateControlDecision({
    intent: "AUTHORIZE_CONTINUATION", expectedRevision: inspection.revision, expectedStatePointerContentSha256: inspection.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: inspection.workflowState.content_sha256 as Sha256Digest,
    transitionId: staticLeafReconciliationTransitionId(authority.taskId), operationId: authority.operationId, processMetadata: r2eProcessMetadata(),
    authoritativeSources: sources, usageEvidence: [usage],
    progressEvidence: { claimedKind: "STATE_TRANSITION", evidenceContentSha256: [inspection.transitionCommit.content_sha256 as Sha256Digest], priorStateOrDecisionContentSha256: authority.reservation.content_sha256 as Sha256Digest },
    availableLogicalRoles: resumedAvailableLogicalRoles(authority.policy),
  });
  if (!result.committed || result.decision.outcome !== "AUTHORIZE" || result.decision.reservation !== null ||
      result.decision.transition_id !== staticLeafReconciliationTransitionId(authority.taskId) || result.decision.transition_event?.event_type !== "COMPLETE_LEAF_ATTEMPT") {
    return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
  }
  const after = await readR2EContext(admission, false);
  if (after.inspection.workflowState.phase !== "LEAF_POSTFLIGHT" || exactStaticLeafReconciliationDecision(after.inspection.workflowState, after.inspection.transitionCommit, after.records, after.inspection.managedRecordClassifications, after.authority) === null) {
    return refused("RESUME_REFUSED_STATE_STORE");
  }
  await resumeReconciliationCheckpoint("AFTER_USAGE_RECONCILIATION");
  return after;
}

function frozenVerificationSpecs(authority: import("./resume-inspection.js").SettledStaticLeafAuthority): readonly M4CommandSpecification[] {
  return authority.task.verification_commands.map((reference) => {
    const matches = authority.commandCatalog.commands.filter((spec) => spec.command_id === reference.command_id && spec.command_class === "VERIFICATION" &&
      canonicalize(spec.argv) === canonicalize(reference.argv) && (spec.cwd === "REPOSITORY_ROOT" ? "repository" : spec.cwd) === reference.cwd &&
      spec.timeout_ms === reference.timeout_ms && spec.network_policy === reference.network && canonicalize(spec.read_paths ?? null) === canonicalize(reference.readable_paths ?? null));
    if (matches.length !== 1) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    return matches[0]!;
  });
}

interface DurableVerifierEvidence {
  readonly result: M4CommandResultDocument;
  readonly postflight: M3PostflightDocument;
  readonly nextToken: M3RepositoryStateTokenDocument;
}

function durableVerifierEvidence(
  authority: import("./resume-inspection.js").SettledStaticLeafAuthority,
  records: R2ERecords,
  classifications: readonly ManagedRecordClassification[],
  spec: M4CommandSpecification,
  stateTokenBefore: string,
): DurableVerifierEvidence | null {
  const candidates = records.commandResults.filter((entry) => entry.command_id === spec.command_id && entry.command_class === "VERIFICATION" &&
    entry.command_spec_sha256 === spec.command_spec_sha256 && entry.state_token_before === stateTokenBefore);
  if (candidates.length === 0) return null;
  if (candidates.length !== 1) return refused("RESUME_REFUSED_IN_FLIGHT_OPERATION");
  const result = candidates[0]!;
  if (result.run_id !== authority.policy.run_id || !classificationsInclude(classifications, "M4_COMMAND_RESULT", result.content_sha256, "AUTHORITATIVE_MANAGED_RECORD") ||
      result.command_catalog_content_sha256 !== authority.commandCatalog.content_sha256 || result.executable_sha256 !== spec.executable_sha256 ||
      result.argv_identity !== sha256Canonical(spec.argv) || result.cwd !== (spec.cwd === "REPOSITORY_ROOT" ? authority.repositoryIdentity.worktree_root : join(authority.repositoryIdentity.worktree_root, spec.cwd)) ||
      ((result.outcome === "PASS") !== (result.failure_code === null)) || result.postflight_content_sha256 === null || result.state_token_after === null) {
    return refused("RESUME_REFUSED_STATE_STORE");
  }
  const postflight = records.postflights.find((entry) => entry.content_sha256 === result.postflight_content_sha256);
  const nextToken = records.stateTokens.find((entry) => entry.content_sha256 === result.state_token_after);
  if (postflight === undefined || nextToken === undefined || postflight.run_id !== authority.policy.run_id || nextToken.run_id !== authority.policy.run_id ||
      !classificationsInclude(classifications, "M3_POSTFLIGHT", postflight.content_sha256, "AUTHORITATIVE_MANAGED_RECORD") ||
      !classificationsInclude(classifications, "M3_REPOSITORY_STATE_TOKEN", nextToken.content_sha256, "AUTHORITATIVE_MANAGED_RECORD") ||
      postflight.prior_token_content_sha256 !== stateTokenBefore || nextToken.source !== "POSTFLIGHT" || nextToken.source_content_sha256 !== postflight.content_sha256 ||
      nextToken.prior_token_content_sha256 !== stateTokenBefore) return refused("RESUME_REFUSED_STATE_STORE");
  return { result, postflight, nextToken };
}

function advanceResumeHandoverTokens(context: R2EContext, workerTip: M3RepositoryStateTokenDocument, cursor: string): string | null {
  const chain = authoritativeTokenChain(context.records, context.inspection.managedRecordClassifications, workerTip.content_sha256, context.authority.currentStateToken);
  if (chain === null) return null;
  let index = chain.findIndex((entry) => entry.content_sha256 === cursor);
  if (index < 0) return null;
  while (index + 1 < chain.length && chain[index + 1]!.source === "RESUME_LOCK_HANDOVER") index += 1;
  return chain[index]!.content_sha256;
}

interface R2EVerificationRun {
  readonly context: R2EContext;
  readonly commandResults: readonly M4CommandResultDocument[];
  readonly postflights: readonly M3PostflightDocument[];
  readonly failureClass: string | null;
  readonly failureCode: string | null;
}

async function runR2EVerification(
  admission: DeterministicResumeAdmission,
  context: R2EContext,
  gateway: Awaited<ReturnType<typeof createScopedToolGateway>>,
): Promise<R2EVerificationRun> {
  const { authority } = context;
  const specs = frozenVerificationSpecs(authority);
  const workerTip = workerTerminalToken(authority, context.records, context.inspection.managedRecordClassifications);
  if (workerTip === null) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
  let latest = context;
  let cursor = workerTip.content_sha256;
  let commandResults: M4CommandResultDocument[] = [];
  let postflights: M3PostflightDocument[] = [];
  let failureClass: string | null = null;
  let failureCode: string | null = null;
  for (const spec of specs) {
    assertR2ETiming(latest);
    let evidence = durableVerifierEvidence(authority, latest.records, latest.inspection.managedRecordClassifications, spec, cursor);
    if (evidence === null) {
      const advancedCursor = advanceResumeHandoverTokens(latest, workerTip, cursor);
      if (advancedCursor === null) return refused("RESUME_REFUSED_STATE_STORE");
      cursor = advancedCursor;
      evidence = durableVerifierEvidence(authority, latest.records, latest.inspection.managedRecordClassifications, spec, cursor);
    }
    if (evidence === null) {
      if (cursor !== latest.authority.currentStateToken.content_sha256 || gateway.acceptedState.content_sha256 !== cursor) return refused("RESUME_REFUSED_STATE_STORE");
      await resumeReconciliationCheckpoint("BEFORE_VERIFICATION_COMMAND");
      try {
        await gateway.run_verification_command({ commandId: spec.command_id, stateTokenContentSha256: cursor as Sha256Digest });
      } catch {
        // A command failure is recoverable only from the exact durable result and postflight.
      }
      latest = await readR2EContext(admission, false);
      evidence = durableVerifierEvidence(authority, latest.records, latest.inspection.managedRecordClassifications, spec, cursor);
      if (evidence === null || evidence.nextToken.content_sha256 !== latest.authority.currentStateToken.content_sha256) return refused("RESUME_REFUSED_STATE_STORE");
    }
    commandResults.push(evidence.result); postflights.push(evidence.postflight); cursor = evidence.nextToken.content_sha256;
    await resumeReconciliationCheckpoint("AFTER_VERIFICATION_COMMAND");
    assertR2ETiming(latest);
    if (evidence.result.outcome === "BLOCKED") {
      const durableFailureCode = evidence.result.failure_code;
      if (durableFailureCode === null) return refused("RESUME_REFUSED_STATE_STORE");
      failureCode = durableFailureCode;
      failureClass = durableFailureCode === "COMMAND_EXIT_CODE_UNEXPECTED" ? "LOCAL_IMPLEMENTATION_DEFECT" : mapLowerLayerFailureCode(durableFailureCode, "M4");
      break;
    }
  }
  latest = await readR2EContext(admission, false);
  const finalCursor = advanceResumeHandoverTokens(latest, workerTip, cursor);
  if (finalCursor === null || finalCursor !== latest.authority.currentStateToken.content_sha256) return refused("RESUME_REFUSED_STATE_STORE");
  return { context: latest, commandResults, postflights, failureClass, failureCode };
}

async function commitR2ETransition(
  admission: DeterministicResumeAdmission,
  context: R2EContext,
  eventType: TransitionEvent["event_type"],
  transitionId: string,
  payload: Record<string, unknown> = {},
): Promise<void> {
  await assertWorktreeLockHeld(admissionState(admission).lock);
  const event = identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    event_id: r2eEventId(transitionId, context.inspection.workflowState, payload), event_type: eventType, payload,
  }) as unknown as TransitionEvent;
  await commitTransition({
    stateRoot: admissionState(admission).stateRoot, runId: context.inspection.workflowState.run_id,
    expectedRevision: context.inspection.revision, expectedStatePointerContentSha256: context.inspection.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: context.inspection.workflowState.content_sha256 as Sha256Digest, transitionId,
    policy: context.authority.reducerPolicy, event, processMetadata: r2eProcessMetadata(),
  });
}

async function reconcileDeterministicResumeAdmissionImpl(admission: DeterministicResumeAdmission): Promise<Omit<DeterministicResumeReconciliationResult, "lock_released">> {
  const owned = admissionState(admission);
  if (owned.released || owned.consumed || owned.workTransferred) throw new Error("resume admission is no longer active");
  let temporaryRoot: string | undefined;
  let context = await readR2EContext(admission, true);
  if (!context.inspection.workflowState.active_task_id || !admission.binding.resume_point.startsWith("STATIC_DAG_RECONCILE_")) return refused("RESUME_REFUSED_AMBIGUOUS_RESUME_POINT");
  try {
    assertR2ETiming(context);
    assertR2ECapacity(context);
    const handover = await runResumeLockHandover({
      stateRoot: owned.stateRoot, runId: context.authority.policy.run_id, acceptedState: context.authority.currentStateToken, baseline: context.authority.baseline,
      instructionFiles: [], authorityFiles: [], taskScopeIdentity: context.authority.policy.scope_sha256 as Sha256Digest, lock: owned.lock,
    });
    if (handover.acceptedState.content_sha256 === context.authority.currentStateToken.content_sha256) return refused("RESUME_REFUSED_EXECUTION_AUTHORITY");
    context = await readR2EContext(admission, false);
    assertR2ETiming(context);
    context = await reconcileSettledWorkerUsage(admission, context);
    await resumeReconciliationCheckpoint("AFTER_COMPLETE_LEAF_ATTEMPT");
    assertR2ETiming(context);
    temporaryRoot = await mkdtemp(join(tmpdir(), "pi-resumed-reconcile-"));
    const gateway = await createScopedToolGateway({
      stateRoot: owned.stateRoot, runId: context.authority.policy.run_id, repository: context.authority.repositoryIdentity, baseline: context.authority.baseline,
      acceptedState: context.authority.currentStateToken, lock: owned.lock, instructionFiles: [], authorityFiles: [],
      editablePaths: [...context.authority.plan.bindings.scope.editable_paths], frozenPaths: [...context.authority.plan.bindings.scope.frozen_paths],
      taskScopeIdentity: context.authority.policy.scope_sha256 as Sha256Digest, toolPolicy: context.authority.toolPolicy, commandCatalog: context.authority.commandCatalog,
      temporaryRoot,
    });
    assertR2ETiming(context);
    const verification = await runR2EVerification(admission, context, gateway);
    context = verification.context;
    if (context.inspection.workflowState.phase === "LEAF_POSTFLIGHT") {
      assertR2ETiming(context);
      await commitR2ETransition(admission, context, "PASS_LEAF_POSTFLIGHT", staticLeafPostflightTransitionId(context.authority.taskId));
      context = await readR2EContext(admission, false);
      await resumeReconciliationCheckpoint("AFTER_PASS_LEAF_POSTFLIGHT");
    }
    if (context.inspection.workflowState.phase !== "LEAF_VERIFYING") return refused("RESUME_REFUSED_STATE_STORE");
    const outcome: R2EVerificationOutcome = verification.failureClass === null ? "PASSED" : "FAILED";
    assertR2ETiming(context);
    let finalEventType: TransitionEvent["event_type"];
    let finalTransitionId: string;
    let finalPayload: Record<string, unknown>;
    if (verification.failureCode === null) {
      finalEventType = "LEAF_VERIFICATION_PASSED";
      finalTransitionId = staticLeafVerificationTransitionId(context.authority.taskId, "PASSED");
      finalPayload = {};
    } else if (verification.failureClass === "LOCAL_IMPLEMENTATION_DEFECT") {
      finalEventType = "LEAF_VERIFICATION_FAILED";
      finalTransitionId = staticLeafVerificationTransitionId(context.authority.taskId, "FAILED");
      finalPayload = { failure_class: verification.failureClass };
    } else {
      if (verification.failureClass === null) return refused("RESUME_REFUSED_STATE_STORE");
      finalEventType = "BLOCK";
      finalTransitionId = `r2e-verification-blocked-${sha256Canonical({ task_id: context.authority.taskId, failure_class: verification.failureClass, failure_code: verification.failureCode }).slice(7, 39)}`;
      finalPayload = { reason: `BLOCKED_${verification.failureClass}:${verification.failureCode}` };
    }
    await commitR2ETransition(admission, context, finalEventType, finalTransitionId, finalPayload);
    await resumeReconciliationCheckpoint("AFTER_LEAF_VERIFICATION_TRANSITION");
    const final = await readR2EContextAfterTransition(admission);
    return {
      run_id: final.workflowState.run_id, task_id: context.authority.taskId, operation_id: context.authority.operationId,
      invocation_content_sha256: context.authority.invocation.content_sha256 as Sha256Digest, result_content_sha256: context.authority.result.content_sha256 as Sha256Digest,
      usage_content_sha256: buildBoundedWorkerUsageEvidence({ runId: context.authority.policy.run_id, policy: context.authority.policy, decision: context.authority.reservation,
        executionMode: "STATIC_APPROVED_DAG", logicalRole: context.authority.reservation.reservation!.logical_role, result: context.authority.result }).content_sha256 as Sha256Digest,
      command_result_content_sha256: Object.freeze(verification.commandResults.map((entry) => entry.content_sha256 as Sha256Digest)),
      postflight_content_sha256: Object.freeze(verification.postflights.map((entry) => entry.content_sha256 as Sha256Digest)),
      verification_outcome: outcome, failure_class: verification.failureClass, final_phase: final.workflowState.phase, final_state: final.workflowState,
      m3_tip_content_sha256: final.currentToken.content_sha256 as Sha256Digest, worker_replay: false, usage_reconciled: true,
    };
  } finally {
    if (temporaryRoot !== undefined) await rm(temporaryRoot, { recursive: true, force: true });
  }
}

async function readR2EContextAfterTransition(admission: DeterministicResumeAdmission): Promise<R2EHealthyInspection & { readonly currentToken: M3RepositoryStateTokenDocument }> {
  const owned = admissionState(admission);
  const location = { stateRoot: owned.stateRoot, runId: admission.binding.run_id };
  const inspection = await inspectRunStorage(location);
  if (!isHealthyR2EInspection(inspection)) return refused("RESUME_REFUSED_STATE_STORE");
  const records = await readM5ManagedRecords(location);
  const currentToken = tokenTip(records.stateTokens.filter((entry) => entry.run_id === inspection.workflowState.run_id &&
    classificationsInclude(inspection.managedRecordClassifications, "M3_REPOSITORY_STATE_TOKEN", entry.content_sha256, "AUTHORITATIVE_MANAGED_RECORD")));
  if (currentToken === null) return refused("RESUME_REFUSED_STATE_STORE");
  return { ...inspection, currentToken };
}

/** R2E production entrypoint: reconcile one settled resumed leaf without invoking a worker. */
export async function reconcileDeterministicResumedLeaf(input: ResumeInspectionInput): Promise<DeterministicResumeReconciliationResult> {
  const admission = await acquireDeterministicResumeAdmission(input);
  try {
    const result = await reconcileDeterministicResumeAdmissionImpl(admission);
    await releaseDeterministicResumeAdmission(admission);
    return Object.freeze({ ...result, lock_released: true });
  } catch (error: unknown) {
    await releaseDeterministicResumeAdmission(admission).catch(() => undefined);
    throw error;
  }
}
