import { canonicalize } from "../canonical-json/index.js";
import {
  assertReducerPolicy,
  assertStatePolicyConsistency,
  assertTransitionEvent,
  assertWorkflowState,
  identifyContractDocument,
  type ReducerPolicy,
  type TransitionEvent,
  type WorkflowState,
} from "../schemas/index.js";

export class TransitionError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "TransitionError";
    this.code = code;
  }
}

type InvocationRole = "sol_owner" | "sol_planner" | "sol_replan" | "sol_closeout" | "luna_executor";

type StateIdentities = WorkflowState["identities"];
type DeepMutable<T> = T extends readonly (infer Item)[]
  ? DeepMutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: DeepMutable<T[Key]> }
    : T;
type MutableState = DeepMutable<WorkflowState>;

function cloneState(state: WorkflowState): MutableState {
  return structuredClone(state) as MutableState;
}

function sealState(state: MutableState, policy: ReducerPolicy): WorkflowState {
  const sealed = identifyContractDocument("pi_gacw_state_v0", state) as unknown as WorkflowState;
  assertWorkflowState(sealed);
  assertStatePolicyConsistency(sealed, policy);
  return sealed;
}

function invalidTransition(state: WorkflowState, event: TransitionEvent): never {
  throw new TransitionError("INVALID_TRANSITION", `${event.event_type} is not admitted from ${state.phase}`);
}

function requirePhase(state: WorkflowState, expected: WorkflowState["phase"], event: TransitionEvent): void {
  if (state.phase !== expected) invalidTransition(state, event);
}

function requireMode(state: WorkflowState, expected: WorkflowState["execution_mode"], event: TransitionEvent): void {
  if (state.execution_mode !== expected) {
    throw new TransitionError("CROSS_MODE_EVENT", `${event.event_type} is invalid for ${state.execution_mode}`);
  }
}

function incrementInvocation(state: MutableState, role: InvocationRole, policy: ReducerPolicy): void {
  const counters = state.counters.worker_invocations;
  if (counters.total >= policy.limits.max_worker_invocations) {
    throw new TransitionError("INVOCATION_CAP_EXCEEDED", "Frozen worker invocation cap reached");
  }
  const fixedCaps: Readonly<Record<InvocationRole, number>> = {
    sol_owner: 1,
    sol_planner: 1,
    sol_replan: 2,
    sol_closeout: 1,
    luna_executor: state.execution_mode === "ROUTED_DAG" ? policy.tasks.length * policy.limits.max_attempts_per_leaf : 2,
  };
  if (counters[role] >= fixedCaps[role]) {
    throw new TransitionError("ROLE_INVOCATION_CAP_EXCEEDED", `${role} invocation cap reached`);
  }
  counters[role] += 1;
  counters.total += 1;
}

function policyTask(policy: ReducerPolicy, taskId: string) {
  const task = policy.tasks.find((candidate) => candidate.task_id === taskId);
  if (task === undefined) {
    throw new TransitionError("UNKNOWN_TASK", taskId);
  }
  return task;
}

function runtimeTask(state: MutableState, taskId: string) {
  const task = state.tasks.find((candidate) => candidate.task_id === taskId);
  if (task === undefined) {
    throw new TransitionError("UNKNOWN_TASK", taskId);
  }
  return task;
}

function onlyPolicyTask(policy: ReducerPolicy) {
  const task = policy.tasks[0];
  if (task === undefined || policy.tasks.length !== 1) {
    throw new TransitionError("ONE_TASK_REQUIRED", "Execution mode requires one task");
  }
  return task;
}

function initializeTasks(state: MutableState, policy: ReducerPolicy): void {
  if (state.tasks.length !== 0) {
    throw new TransitionError("TASKS_ALREADY_FROZEN", "Task set is immutable after freeze");
  }
  state.tasks = policy.tasks.map((task) => ({
    task_id: task.task_id,
    status: "PENDING" as const,
    attempts: 0,
    postflight_completed: false,
    verification_completed: false,
    retry_progress_admitted: false,
  }));
}

function block(state: MutableState, reason: string): void {
  if (state.active_task_id !== null) {
    const active = state.tasks.find((task) => task.task_id === state.active_task_id);
    if (active !== undefined && active.status !== "PASS") active.status = "BLOCKED";
  }
  state.active_task_id = null;
  state.replan_in_progress = false;
  state.phase = "BLOCKED";
  state.terminal_reason = reason;
}

function passTask(state: MutableState): void {
  if (state.active_task_id === null) {
    throw new TransitionError("NO_ACTIVE_TASK", "No task can be marked PASS");
  }
  const task = runtimeTask(state, state.active_task_id);
  if (!task.postflight_completed) {
    throw new TransitionError("POSTFLIGHT_REQUIRED", "A task cannot PASS before postflight");
  }
  task.verification_completed = true;
  task.status = "PASS";
  state.active_task_id = null;
  state.counters.leaves_completed = state.tasks.filter((candidate) => candidate.status === "PASS").length;
}

function markActivePostflightComplete(state: MutableState): void {
  if (state.active_task_id === null) {
    throw new TransitionError("NO_ACTIVE_TASK", "Postflight requires an active task");
  }
  runtimeTask(state, state.active_task_id).postflight_completed = true;
}

function admitActiveRetryProgress(state: MutableState): void {
  if (state.active_task_id === null) {
    throw new TransitionError("NO_ACTIVE_TASK", "Retry progress requires an active task");
  }
  runtimeTask(state, state.active_task_id).retry_progress_admitted = true;
}

function resetActiveTaskForRetry(state: MutableState): void {
  if (state.active_task_id === null) {
    throw new TransitionError("NO_ACTIVE_TASK", "Retry requires an active task");
  }
  const task = runtimeTask(state, state.active_task_id);
  task.status = "PENDING";
  task.postflight_completed = false;
  task.verification_completed = false;
  task.retry_progress_admitted = false;
}

function assertProgressDelta(delta: { readonly evidence_sha256: string; readonly summary: string }): void {
  if (delta.summary.trim().length === 0 || !/^sha256:[0-9a-f]{64}$/.test(delta.evidence_sha256)) {
    throw new TransitionError("INVALID_PROGRESS_DELTA", "Retry requires typed evidence-backed progress");
  }
}

export function createInitialState(policy: ReducerPolicy, identities: StateIdentities): WorkflowState {
  assertReducerPolicy(policy);
  const state = identifyContractDocument("pi_gacw_state_v0", {
    schema_id: "pi_gacw_state_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: policy.run_id,
    execution_mode: policy.execution_mode,
    phase: "CREATED",
    identities,
    frozen_policy_content_sha256: policy.content_sha256,
    counters: {
      worker_invocations: {
        total: 0,
        sol_owner: 0,
        sol_planner: 0,
        sol_replan: 0,
        sol_closeout: 0,
        luna_executor: 0,
      },
      direct_attempts: 0,
      single_owner_mutation_cycles: 0,
      constrained_replans: 0,
      leaves_completed: 0,
    },
    gates: {
      planner_completed: false,
      owner_acceptance_completed: false,
      closeout_completed: false,
      closeout_verification_completed: false,
    },
    tasks: [],
    active_task_id: null,
    baseline_approval_required: null,
    route_frozen: false,
    owner_acceptance_required: policy.owner_acceptance_required,
    replan_in_progress: false,
    terminal_reason: null,
  }) as unknown as WorkflowState;
  assertWorkflowState(state);
  assertStatePolicyConsistency(state, policy);
  return state;
}

// Called only from reduceRouted after reduceState validates state, policy, binding, mode, and phase.
function selectReadyLeafUnchecked(state: WorkflowState, policy: ReducerPolicy): string | null {
  const statuses = new Map(state.tasks.map((task) => [task.task_id, task.status]));
  const ready = policy.tasks.filter((task) => {
    if (statuses.get(task.task_id) !== "PENDING") return false;
    return task.dependencies.every((dependency) => statuses.get(dependency) === "PASS");
  });
  ready.sort((left, right) => {
    if (left.topological_rank !== right.topological_rank) return left.topological_rank - right.topological_rank;
    if (left.priority !== right.priority) return left.priority - right.priority;
    return left.task_id < right.task_id ? -1 : left.task_id > right.task_id ? 1 : 0;
  });
  return ready[0]?.task_id ?? null;
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  return [...left].sort().join("\u0000") === [...right].sort().join("\u0000");
}

function frozenEdges(policy: ReducerPolicy): readonly { from: string; to: string }[] {
  return policy.tasks.flatMap((task) => task.dependencies.map((dependency) => ({ from: dependency, to: task.task_id })));
}

function sameEdges(
  left: readonly { readonly from: string; readonly to: string }[],
  right: readonly { readonly from: string; readonly to: string }[],
): boolean {
  const normalized = (edges: readonly { readonly from: string; readonly to: string }[]) =>
    edges.map((edge) => canonicalize(edge)).sort().join("\u0000");
  return normalized(left) === normalized(right);
}

function reduceCommon(state: MutableState, event: TransitionEvent): boolean {
  switch (event.event_type) {
    case "FREEZE_OBJECTIVE":
      requirePhase(state, "CREATED", event);
      state.phase = "OBJECTIVE_FROZEN";
      return true;
    case "ACQUIRE_LOCK":
      requirePhase(state, "OBJECTIVE_FROZEN", event);
      state.phase = "LOCK_ACQUIRED";
      return true;
    case "CAPTURE_BASELINE":
      requirePhase(state, "LOCK_ACQUIRED", event);
      state.baseline_approval_required = event.payload.approval_required;
      state.phase = "BASELINE_CAPTURED";
      return true;
    case "REQUEST_BASELINE_APPROVAL":
      requirePhase(state, "BASELINE_CAPTURED", event);
      if (state.baseline_approval_required !== true) {
        throw new TransitionError("BASELINE_APPROVAL_NOT_REQUIRED", "Clean baseline cannot request dirty approval");
      }
      state.phase = "AWAITING_BASELINE_APPROVAL";
      return true;
    case "ACCEPT_CLEAN_BASELINE":
      requirePhase(state, "BASELINE_CAPTURED", event);
      if (state.baseline_approval_required !== false) {
        throw new TransitionError("BASELINE_APPROVAL_REQUIRED", "Dirty baseline must be approved");
      }
      state.phase = "BASELINE_APPROVED";
      return true;
    case "APPROVE_BASELINE":
      requirePhase(state, "AWAITING_BASELINE_APPROVAL", event);
      state.phase = "BASELINE_APPROVED";
      return true;
    case "PASS_FULL_PREFLIGHT":
      requirePhase(state, "BASELINE_APPROVED", event);
      state.phase = "FULL_PREFLIGHT_PASSED";
      return true;
    case "VALIDATE_CONTRACT":
      requirePhase(state, "FULL_PREFLIGHT_PASSED", event);
      state.phase = "CONTRACT_VALIDATED";
      return true;
    case "SELECT_ROUTE":
      requirePhase(state, "CONTRACT_VALIDATED", event);
      if (event.payload.execution_mode !== state.execution_mode) {
        throw new TransitionError("ROUTE_MISMATCH", "Selected route differs from frozen state mode");
      }
      state.phase = "ROUTE_SELECTED";
      return true;
    default:
      return false;
  }
}

function reduceDirect(state: MutableState, event: TransitionEvent, policy: ReducerPolicy): void {
  requireMode(state, "DIRECT_LUNA_HIGH", event);
  switch (event.event_type) {
    case "VALIDATE_DIRECT_CONTRACT":
      requirePhase(state, "ROUTE_SELECTED", event);
      state.phase = "DIRECT_CONTRACT_VALIDATED";
      return;
    case "REQUEST_DIRECT_APPROVAL":
      requirePhase(state, "DIRECT_CONTRACT_VALIDATED", event);
      state.phase = "AWAITING_DIRECT_APPROVAL";
      return;
    case "APPROVE_DIRECT_TASK":
      requirePhase(state, "AWAITING_DIRECT_APPROVAL", event);
      initializeTasks(state, policy);
      state.route_frozen = true;
      state.phase = "DIRECT_TASK_FROZEN";
      return;
    case "PASS_DIRECT_FAST_PREFLIGHT":
      requirePhase(state, "DIRECT_TASK_FROZEN", event);
      state.phase = "DIRECT_FAST_PREFLIGHT";
      return;
    case "START_DIRECT_ATTEMPT": {
      requirePhase(state, "DIRECT_FAST_PREFLIGHT", event);
      if (state.counters.direct_attempts >= policy.limits.max_direct_attempts) {
        throw new TransitionError("ATTEMPT_CAP_EXCEEDED", "A third direct attempt is impossible");
      }
      incrementInvocation(state, "luna_executor", policy);
      state.counters.direct_attempts += 1;
      const task = onlyPolicyTask(policy);
      const runtime = runtimeTask(state, task.task_id);
      if (runtime.attempts > 0 && !runtime.retry_progress_admitted) {
        throw new TransitionError("PROGRESS_DELTA_REQUIRED", "A second direct attempt requires admitted progress");
      }
      runtime.attempts += 1;
      state.active_task_id = task.task_id;
      runtime.status = "RUNNING";
      state.phase = "DIRECT_ATTEMPT_RUNNING";
      return;
    }
    case "COMPLETE_DIRECT_ATTEMPT":
      requirePhase(state, "DIRECT_ATTEMPT_RUNNING", event);
      state.phase = "DIRECT_POSTFLIGHT";
      return;
    case "PASS_DIRECT_POSTFLIGHT":
      requirePhase(state, "DIRECT_POSTFLIGHT", event);
      markActivePostflightComplete(state);
      state.phase = "DIRECT_VERIFYING";
      return;
    case "DIRECT_VERIFICATION_PASSED":
      requirePhase(state, "DIRECT_VERIFYING", event);
      passTask(state);
      state.phase = "PASS";
      state.terminal_reason = "PASS";
      return;
    case "DIRECT_VERIFICATION_FAILED":
      requirePhase(state, "DIRECT_VERIFYING", event);
      if (event.payload.failure_class === "LOCAL_IMPLEMENTATION_DEFECT" && state.counters.direct_attempts < policy.limits.max_direct_attempts) {
        resetActiveTaskForRetry(state);
        state.phase = "DIRECT_RETRY_READY";
      } else {
        block(state, `BLOCKED_${event.payload.failure_class}`);
      }
      return;
    case "ADMIT_DIRECT_RETRY":
      requirePhase(state, "DIRECT_RETRY_READY", event);
      assertProgressDelta(event.payload.progress_delta);
      admitActiveRetryProgress(state);
      state.phase = "DIRECT_FAST_PREFLIGHT";
      return;
    default:
      invalidTransition(state, event);
  }
}

function reduceSingleOwner(state: MutableState, event: TransitionEvent, policy: ReducerPolicy): void {
  requireMode(state, "SINGLE_OWNER_SOL", event);
  switch (event.event_type) {
    case "VALIDATE_SINGLE_OWNER_CONTRACT":
      requirePhase(state, "ROUTE_SELECTED", event);
      state.phase = "SINGLE_OWNER_CONTRACT_VALIDATED";
      return;
    case "REQUEST_SINGLE_OWNER_APPROVAL":
      requirePhase(state, "SINGLE_OWNER_CONTRACT_VALIDATED", event);
      state.phase = "AWAITING_SINGLE_OWNER_APPROVAL";
      return;
    case "APPROVE_SINGLE_OWNER_TASK":
      requirePhase(state, "AWAITING_SINGLE_OWNER_APPROVAL", event);
      initializeTasks(state, policy);
      state.route_frozen = true;
      state.phase = "SINGLE_OWNER_TASK_FROZEN";
      return;
    case "PASS_SINGLE_OWNER_FAST_PREFLIGHT":
      requirePhase(state, "SINGLE_OWNER_TASK_FROZEN", event);
      state.phase = "SINGLE_OWNER_FAST_PREFLIGHT";
      return;
    case "START_SINGLE_OWNER": {
      requirePhase(state, "SINGLE_OWNER_FAST_PREFLIGHT", event);
      if (state.counters.worker_invocations.sol_owner !== 0) {
        throw new TransitionError("SOL_OWNER_CAP_EXCEEDED", "Exactly one SOL_OWNER invocation is allowed");
      }
      incrementInvocation(state, "sol_owner", policy);
      const task = onlyPolicyTask(policy);
      state.active_task_id = task.task_id;
      runtimeTask(state, task.task_id).status = "RUNNING";
      state.phase = "SINGLE_OWNER_RUNNING";
      return;
    }
    case "ADMIT_SINGLE_OWNER_MUTATION_CYCLE":
      requirePhase(state, "SINGLE_OWNER_RUNNING", event);
      if (state.counters.single_owner_mutation_cycles >= policy.limits.max_single_owner_mutation_cycles) {
        throw new TransitionError("MUTATION_CYCLE_CAP_EXCEEDED", "A third mutation cycle is impossible");
      }
      state.counters.single_owner_mutation_cycles += 1;
      return;
    case "COMPLETE_SINGLE_OWNER":
      requirePhase(state, "SINGLE_OWNER_RUNNING", event);
      if (state.counters.single_owner_mutation_cycles === 0) {
        throw new TransitionError("MUTATION_CYCLE_REQUIRED", "At least one admitted mutation cycle is required");
      }
      state.phase = "SINGLE_OWNER_POSTFLIGHT";
      return;
    case "PASS_SINGLE_OWNER_POSTFLIGHT":
      requirePhase(state, "SINGLE_OWNER_POSTFLIGHT", event);
      markActivePostflightComplete(state);
      state.phase = "SINGLE_OWNER_VERIFYING";
      return;
    case "SINGLE_OWNER_VERIFICATION_PASSED":
      requirePhase(state, "SINGLE_OWNER_VERIFYING", event);
      passTask(state);
      if (policy.owner_acceptance_required) {
        state.phase = "AWAITING_DECLARED_OWNER_ACCEPTANCE";
      } else {
        state.phase = "PASS";
        state.terminal_reason = "PASS";
      }
      return;
    case "SINGLE_OWNER_VERIFICATION_FAILED":
      requirePhase(state, "SINGLE_OWNER_VERIFYING", event);
      block(state, `BLOCKED_${event.payload.failure_class}`);
      return;
    case "OWNER_ACCEPTED":
      requirePhase(state, "AWAITING_DECLARED_OWNER_ACCEPTANCE", event);
      if (!policy.owner_acceptance_required) {
        throw new TransitionError("UNDECLARED_OWNER_ACCEPTANCE", "Owner gate is not frozen");
      }
      state.gates.owner_acceptance_completed = true;
      state.phase = "PASS";
      state.terminal_reason = "PASS";
      return;
    case "OWNER_REJECTED":
      requirePhase(state, "AWAITING_DECLARED_OWNER_ACCEPTANCE", event);
      block(state, `BLOCKED_OWNER_REJECTED: ${event.payload.reason}`);
      return;
    default:
      invalidTransition(state, event);
  }
}

function reduceRouted(state: MutableState, event: TransitionEvent, policy: ReducerPolicy): void {
  requireMode(state, "ROUTED_DAG", event);
  switch (event.event_type) {
    case "START_PLAN":
      requirePhase(state, "ROUTE_SELECTED", event);
      incrementInvocation(state, "sol_planner", policy);
      state.phase = "PLAN_RUNNING";
      return;
    case "COMPLETE_PLAN":
      requirePhase(state, "PLAN_RUNNING", event);
      state.gates.planner_completed = true;
      state.phase = "PLAN_VALIDATED";
      return;
    case "REQUEST_PLAN_APPROVAL":
      requirePhase(state, "PLAN_VALIDATED", event);
      state.phase = "AWAITING_PLAN_APPROVAL";
      return;
    case "APPROVE_PLAN":
      requirePhase(state, "AWAITING_PLAN_APPROVAL", event);
      if (
        event.payload.plan_approval_sha256 !== policy.frozen_bindings.plan_approval_sha256 ||
        event.payload.task_graph_sha256 !== policy.frozen_bindings.task_graph_sha256
      ) {
        throw new TransitionError("PLAN_IDENTITY_MISMATCH", "Approval event does not match frozen policy");
      }
      initializeTasks(state, policy);
      state.route_frozen = true;
      state.phase = "DAG_FROZEN";
      return;
    case "ACTIVATE_DAG":
      requirePhase(state, "DAG_FROZEN", event);
      state.phase = "READY";
      return;
    case "SELECT_READY_LEAF": {
      requirePhase(state, "READY", event);
      if (state.active_task_id !== null) {
        throw new TransitionError("CONCURRENT_WRITER", "An active leaf already exists");
      }
      const taskId = selectReadyLeafUnchecked(state, policy);
      if (taskId === null) {
        throw new TransitionError("NO_READY_LEAF", "No dependency-satisfied leaf is ready");
      }
      state.active_task_id = taskId;
      state.phase = "LEAF_FAST_PREFLIGHT";
      return;
    }
    case "START_LEAF_ATTEMPT": {
      requirePhase(state, "LEAF_FAST_PREFLIGHT", event);
      if (state.active_task_id === null) throw new TransitionError("NO_ACTIVE_TASK", "Leaf start requires selection");
      const runtime = runtimeTask(state, state.active_task_id);
      if (runtime.attempts >= policy.limits.max_attempts_per_leaf) {
        throw new TransitionError("ATTEMPT_CAP_EXCEEDED", "A third leaf attempt is impossible");
      }
      if (runtime.attempts > 0 && !runtime.retry_progress_admitted) {
        throw new TransitionError("PROGRESS_DELTA_REQUIRED", "A second leaf attempt requires admitted progress");
      }
      incrementInvocation(state, "luna_executor", policy);
      runtime.attempts += 1;
      runtime.status = "RUNNING";
      state.phase = "LEAF_RUNNING";
      return;
    }
    case "COMPLETE_LEAF_ATTEMPT":
      requirePhase(state, "LEAF_RUNNING", event);
      state.phase = "LEAF_POSTFLIGHT";
      return;
    case "PASS_LEAF_POSTFLIGHT":
      requirePhase(state, "LEAF_POSTFLIGHT", event);
      markActivePostflightComplete(state);
      state.phase = "LEAF_VERIFYING";
      return;
    case "LEAF_VERIFICATION_PASSED":
      requirePhase(state, "LEAF_VERIFYING", event);
      passTask(state);
      state.phase = "READY";
      return;
    case "LEAF_VERIFICATION_FAILED": {
      requirePhase(state, "LEAF_VERIFYING", event);
      if (state.active_task_id === null) throw new TransitionError("NO_ACTIVE_TASK", "Leaf failure requires an active task");
      const active = runtimeTask(state, state.active_task_id);
      if (active.attempts >= policy.limits.max_attempts_per_leaf) {
        block(state, `BLOCKED_${event.payload.failure_class}`);
      } else if (event.payload.failure_class === "LOCAL_IMPLEMENTATION_DEFECT") {
        resetActiveTaskForRetry(state);
        state.phase = "LEAF_RETRY_READY";
      } else if (event.payload.failure_class === "PLAN_INCORRECT") {
        resetActiveTaskForRetry(state);
        state.phase = "REPLAN_REQUIRED";
      } else {
        block(state, `BLOCKED_${event.payload.failure_class}`);
      }
      return;
    }
    case "ADMIT_LEAF_RETRY":
      requirePhase(state, "LEAF_RETRY_READY", event);
      assertProgressDelta(event.payload.progress_delta);
      admitActiveRetryProgress(state);
      state.phase = "LEAF_FAST_PREFLIGHT";
      return;
    case "START_CONSTRAINED_REPLAN":
      requirePhase(state, "REPLAN_REQUIRED", event);
      if (state.replan_in_progress) {
        throw new TransitionError("REPLAN_ALREADY_RUNNING", "Only one constrained replan may run");
      }
      if (state.counters.constrained_replans >= policy.limits.max_replans) {
        throw new TransitionError("REPLAN_CAP_EXCEEDED", "A third constrained replan is impossible");
      }
      incrementInvocation(state, "sol_replan", policy);
      state.counters.constrained_replans += 1;
      state.replan_in_progress = true;
      return;
    case "COMPLETE_CONSTRAINED_REPLAN": {
      requirePhase(state, "REPLAN_REQUIRED", event);
      if (!state.replan_in_progress) {
        throw new TransitionError("REPLAN_NOT_RUNNING", "A constrained replan must be admitted first");
      }
      const expected = policy.frozen_bindings;
      const bindings = event.payload.frozen_bindings;
      if (
        expected.plan_approval_sha256 !== bindings.plan_approval_sha256 ||
        expected.task_graph_sha256 !== bindings.task_graph_sha256 ||
        expected.scope_sha256 !== bindings.scope_sha256 ||
        expected.acceptance_sha256 !== bindings.acceptance_sha256 ||
        expected.budget_sha256 !== bindings.budget_sha256
      ) {
        throw new TransitionError("REPLAN_FROZEN_BINDING_CHANGE", "Scope, acceptance, budget, plan, and graph identities are immutable");
      }
      if (!sameStringSet(event.payload.proposed_task_ids, policy.tasks.map((task) => task.task_id))) {
        throw new TransitionError("DAG_GROWTH_FORBIDDEN", "Constrained replan cannot add or remove leaves");
      }
      if (!sameEdges(event.payload.proposed_edges, frozenEdges(policy))) {
        throw new TransitionError("DAG_TOPOLOGY_CHANGE_FORBIDDEN", "Constrained replan cannot alter DAG topology");
      }
      assertProgressDelta(event.payload.progress_delta);
      state.replan_in_progress = false;
      state.phase = "LEAF_RETRY_READY";
      return;
    }
    case "START_CLOSEOUT":
      requirePhase(state, "READY", event);
      if (state.tasks.length === 0 || state.tasks.some((task) => task.status !== "PASS") || state.active_task_id !== null) {
        throw new TransitionError("CLOSEOUT_NOT_READY", "Every approved leaf must PASS before closeout");
      }
      incrementInvocation(state, "sol_closeout", policy);
      state.phase = "CLOSEOUT_RUNNING";
      return;
    case "COMPLETE_CLOSEOUT":
      requirePhase(state, "CLOSEOUT_RUNNING", event);
      state.gates.closeout_completed = true;
      state.phase = "CLOSEOUT_VERIFYING";
      return;
    case "CLOSEOUT_PASSED":
      requirePhase(state, "CLOSEOUT_VERIFYING", event);
      state.gates.closeout_verification_completed = true;
      state.phase = "PASS";
      state.terminal_reason = "PASS";
      return;
    case "CLOSEOUT_DEFECT":
      requirePhase(state, "CLOSEOUT_VERIFYING", event);
      block(state, `BLOCKED_CLOSEOUT_DEFECT: ${event.payload.reason}`);
      return;
    default:
      invalidTransition(state, event);
  }
}

export function reduceState(current: WorkflowState, event: TransitionEvent, policy: ReducerPolicy): WorkflowState {
  assertWorkflowState(current);
  assertTransitionEvent(event);
  assertReducerPolicy(policy);
  assertStatePolicyConsistency(current, policy);

  if (current.phase === "PASS" || current.phase === "BLOCKED") {
    throw new TransitionError("TERMINAL_STATE_IMMUTABLE", `Cannot apply ${event.event_type} to ${current.phase}`);
  }

  const next = cloneState(current);
  if (event.event_type === "BLOCK") {
    block(next, event.payload.reason);
    return sealState(next, policy);
  }
  if (reduceCommon(next, event)) {
    return sealState(next, policy);
  }

  switch (next.execution_mode) {
    case "DIRECT_LUNA_HIGH":
      reduceDirect(next, event, policy);
      break;
    case "SINGLE_OWNER_SOL":
      reduceSingleOwner(next, event, policy);
      break;
    case "ROUTED_DAG":
      reduceRouted(next, event, policy);
      break;
  }
  return sealState(next, policy);
}
