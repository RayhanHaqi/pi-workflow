import assert from "node:assert/strict";
import test from "node:test";

import {
  ContractValidationError,
  assertStatePolicyConsistency,
  identifyContractDocument,
  verifyContractDocument,
  type ReducerPolicy,
  type WorkflowState,
} from "../src/schemas/index.js";
import {
  TransitionError,
  createInitialState,
  reduceState,
} from "../src/state-machine/index.js";
import {
  advanceCommon,
  applyEvent,
  digest,
  makePolicy,
  progress,
  stateIdentities,
  transitionEvent,
  type MutableJson,
  type TestPolicyTask,
} from "./helpers.js";

function expectTransitionCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => error instanceof TransitionError && error.code === code);
}

function expectContractCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => error instanceof ContractValidationError && error.code === code);
}

function directFastPreflight(policy = makePolicy("DIRECT_LUNA_HIGH")): { policy: ReducerPolicy; state: WorkflowState } {
  let state = advanceCommon(policy);
  state = applyEvent(state, policy, "VALIDATE_DIRECT_CONTRACT");
  state = applyEvent(state, policy, "REQUEST_DIRECT_APPROVAL");
  state = applyEvent(state, policy, "APPROVE_DIRECT_TASK");
  state = applyEvent(state, policy, "PASS_DIRECT_FAST_PREFLIGHT");
  return { policy, state };
}

function singleOwnerFastPreflight(policy = makePolicy("SINGLE_OWNER_SOL")): { policy: ReducerPolicy; state: WorkflowState } {
  let state = advanceCommon(policy);
  state = applyEvent(state, policy, "VALIDATE_SINGLE_OWNER_CONTRACT");
  state = applyEvent(state, policy, "REQUEST_SINGLE_OWNER_APPROVAL");
  state = applyEvent(state, policy, "APPROVE_SINGLE_OWNER_TASK");
  state = applyEvent(state, policy, "PASS_SINGLE_OWNER_FAST_PREFLIGHT");
  return { policy, state };
}

function routedReady(policy = makePolicy("ROUTED_DAG")): { policy: ReducerPolicy; state: WorkflowState } {
  let state = advanceCommon(policy);
  state = applyEvent(state, policy, "START_PLAN");
  state = applyEvent(state, policy, "COMPLETE_PLAN");
  state = applyEvent(state, policy, "REQUEST_PLAN_APPROVAL");
  state = applyEvent(state, policy, "APPROVE_PLAN", {
    plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
  });
  state = applyEvent(state, policy, "ACTIVATE_DAG");
  return { policy, state };
}

function passReadyLeaf(state: WorkflowState, policy: ReducerPolicy, expectedTaskId?: string): WorkflowState {
  let next = applyEvent(state, policy, "SELECT_READY_LEAF");
  assert.notEqual(next.active_task_id, null);
  if (expectedTaskId !== undefined) assert.equal(next.active_task_id, expectedTaskId);
  assert.equal(next.tasks.filter((task) => task.status === "RUNNING").length, 0);
  next = applyEvent(next, policy, "START_LEAF_ATTEMPT");
  assert.equal(next.tasks.filter((task) => task.status === "RUNNING").length, 1);
  next = applyEvent(next, policy, "COMPLETE_LEAF_ATTEMPT");
  next = applyEvent(next, policy, "PASS_LEAF_POSTFLIGHT");
  return applyEvent(next, policy, "LEAF_VERIFICATION_PASSED");
}

function replanCompletionPayload(policy: ReducerPolicy): MutableJson {
  return {
    frozen_bindings: {
      plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
      task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
      scope_sha256: policy.frozen_bindings.scope_sha256,
      acceptance_sha256: policy.frozen_bindings.acceptance_sha256,
      budget_sha256: policy.frozen_bindings.budget_sha256,
    },
    proposed_task_ids: policy.tasks.map((task) => task.task_id),
    proposed_edges: policy.tasks.flatMap((task) => task.dependencies.map((dependency) => ({ from: dependency, to: task.task_id }))),
    progress_delta: progress(80),
  };
}

test("common clean and approved-dirty preflight paths are deterministic", () => {
  const policy = makePolicy("DIRECT_LUNA_HIGH");
  const initial = createInitialState(policy, stateIdentities(policy));
  const freezeEvent = transitionEvent("FREEZE_OBJECTIVE");
  const first = reduceState(initial, freezeEvent, policy);
  const second = reduceState(initial, freezeEvent, policy);
  assert.deepEqual(first, second);
  assert.equal(initial.phase, "CREATED");
  assert.equal(first.phase, "OBJECTIVE_FROZEN");

  let dirty = first;
  dirty = applyEvent(dirty, policy, "ACQUIRE_LOCK");
  dirty = applyEvent(dirty, policy, "CAPTURE_BASELINE", { approval_required: true });
  expectTransitionCode(() => applyEvent(dirty, policy, "ACCEPT_CLEAN_BASELINE"), "BASELINE_APPROVAL_REQUIRED");
  dirty = applyEvent(dirty, policy, "REQUEST_BASELINE_APPROVAL");
  dirty = applyEvent(dirty, policy, "APPROVE_BASELINE");
  assert.equal(dirty.phase, "BASELINE_APPROVED");
});

test("DIRECT_LUNA_HIGH reaches PASS with one Luna High invocation and mandatory postflight", () => {
  const { policy, state: fast } = directFastPreflight();
  expectTransitionCode(() => applyEvent(fast, policy, "START_PLAN"), "INVALID_TRANSITION");

  const running = applyEvent(fast, policy, "START_DIRECT_ATTEMPT");
  assert.equal(fast.phase, "DIRECT_FAST_PREFLIGHT");
  assert.equal(running.phase, "DIRECT_ATTEMPT_RUNNING");
  assert.equal(running.counters.direct_attempts, 1);
  assert.equal(running.tasks[0]?.attempts, 1);
  assert.equal(running.counters.worker_invocations.luna_executor, 1);
  assert.equal(running.counters.worker_invocations.sol_owner, 0);
  assert.equal(running.counters.worker_invocations.sol_planner, 0);
  assert.equal(running.counters.worker_invocations.sol_closeout, 0);
  expectTransitionCode(() => applyEvent(running, policy, "DIRECT_VERIFICATION_PASSED"), "INVALID_TRANSITION");

  let complete = applyEvent(running, policy, "COMPLETE_DIRECT_ATTEMPT");
  expectTransitionCode(() => applyEvent(complete, policy, "DIRECT_VERIFICATION_PASSED"), "INVALID_TRANSITION");
  complete = applyEvent(complete, policy, "PASS_DIRECT_POSTFLIGHT");
  const passed = applyEvent(complete, policy, "DIRECT_VERIFICATION_PASSED");
  assert.equal(passed.phase, "PASS");
  assert.equal(passed.tasks[0]?.status, "PASS");
  assert.equal(passed.tasks[0]?.postflight_completed, true);
  assert.equal(passed.tasks[0]?.verification_completed, true);
  assert.equal(passed.counters.leaves_completed, 1);
  assert.equal(verifyContractDocument("pi_gacw_state_v0", passed), true);
  expectTransitionCode(() => applyEvent(passed, policy, "BLOCK", { reason: "late event" }), "TERMINAL_STATE_IMMUTABLE");
});

test("DIRECT_LUNA_HIGH permits one coherent retry only after typed progress and never a third attempt", () => {
  const { policy, state: fast } = directFastPreflight();
  let state = applyEvent(fast, policy, "START_DIRECT_ATTEMPT");
  state = applyEvent(state, policy, "COMPLETE_DIRECT_ATTEMPT");
  state = applyEvent(state, policy, "PASS_DIRECT_POSTFLIGHT");
  state = applyEvent(state, policy, "DIRECT_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "DIRECT_RETRY_READY");
  assert.equal(state.tasks[0]?.status, "PENDING");

  expectTransitionCode(
    () => applyEvent(state, policy, "ADMIT_DIRECT_RETRY", {
      progress_delta: { ...progress(71), summary: " " },
    }),
    "INVALID_PROGRESS_DELTA",
  );
  state = applyEvent(state, policy, "ADMIT_DIRECT_RETRY", { progress_delta: progress(72) });
  state = applyEvent(state, policy, "START_DIRECT_ATTEMPT");
  assert.equal(state.counters.direct_attempts, 2);
  assert.equal(state.tasks[0]?.attempts, 2);
  assert.equal(state.tasks[0]?.retry_progress_admitted, true);
  state = applyEvent(state, policy, "COMPLETE_DIRECT_ATTEMPT");
  state = applyEvent(state, policy, "PASS_DIRECT_POSTFLIGHT");
  state = applyEvent(state, policy, "DIRECT_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "BLOCKED");
  assert.equal(state.counters.worker_invocations.total, 2);
  assert.equal(state.counters.worker_invocations.luna_executor, 2);
  assert.equal(state.counters.worker_invocations.sol_owner, 0);
  expectTransitionCode(() => applyEvent(state, policy, "START_DIRECT_ATTEMPT"), "TERMINAL_STATE_IMMUTABLE");
});

test("SINGLE_OWNER_SOL admits exactly one owner invocation and at most two internal mutation cycles", () => {
  const { policy, state: fast } = singleOwnerFastPreflight();
  expectTransitionCode(() => applyEvent(fast, policy, "START_PLAN"), "INVALID_TRANSITION");

  let state = applyEvent(fast, policy, "START_SINGLE_OWNER");
  assert.equal(state.counters.worker_invocations.total, 1);
  assert.equal(state.counters.worker_invocations.sol_owner, 1);
  assert.equal(state.counters.worker_invocations.sol_planner, 0);
  assert.equal(state.counters.worker_invocations.sol_closeout, 0);
  expectTransitionCode(() => applyEvent(state, policy, "SINGLE_OWNER_VERIFICATION_PASSED"), "INVALID_TRANSITION");

  state = applyEvent(state, policy, "ADMIT_SINGLE_OWNER_MUTATION_CYCLE");
  state = applyEvent(state, policy, "ADMIT_SINGLE_OWNER_MUTATION_CYCLE");
  assert.equal(state.counters.single_owner_mutation_cycles, 2);
  expectTransitionCode(() => applyEvent(state, policy, "ADMIT_SINGLE_OWNER_MUTATION_CYCLE"), "MUTATION_CYCLE_CAP_EXCEEDED");

  state = applyEvent(state, policy, "COMPLETE_SINGLE_OWNER");
  expectTransitionCode(() => applyEvent(state, policy, "SINGLE_OWNER_VERIFICATION_PASSED"), "INVALID_TRANSITION");
  state = applyEvent(state, policy, "PASS_SINGLE_OWNER_POSTFLIGHT");
  state = applyEvent(state, policy, "SINGLE_OWNER_VERIFICATION_PASSED");
  assert.equal(state.phase, "PASS");
  assert.equal(state.counters.worker_invocations.sol_owner, 1);
  assert.equal(state.tasks[0]?.status, "PASS");
  assert.equal(state.tasks[0]?.postflight_completed, true);
  assert.equal(state.tasks[0]?.verification_completed, true);
});

test("SINGLE_OWNER_SOL requires at least one admitted mutation cycle", () => {
  const { policy, state: fast } = singleOwnerFastPreflight();
  const running = applyEvent(fast, policy, "START_SINGLE_OWNER");
  expectTransitionCode(() => applyEvent(running, policy, "COMPLETE_SINGLE_OWNER"), "MUTATION_CYCLE_REQUIRED");
});

test("declared owner acceptance appears only when frozen and may accept or reject", () => {
  const requiredPolicy = makePolicy("SINGLE_OWNER_SOL", { ownerAcceptanceRequired: true });
  let required = singleOwnerFastPreflight(requiredPolicy).state;
  required = applyEvent(required, requiredPolicy, "START_SINGLE_OWNER");
  required = applyEvent(required, requiredPolicy, "ADMIT_SINGLE_OWNER_MUTATION_CYCLE");
  required = applyEvent(required, requiredPolicy, "COMPLETE_SINGLE_OWNER");
  required = applyEvent(required, requiredPolicy, "PASS_SINGLE_OWNER_POSTFLIGHT");
  required = applyEvent(required, requiredPolicy, "SINGLE_OWNER_VERIFICATION_PASSED");
  assert.equal(required.phase, "AWAITING_DECLARED_OWNER_ACCEPTANCE");
  const accepted = applyEvent(required, requiredPolicy, "OWNER_ACCEPTED");
  assert.equal(accepted.phase, "PASS");
  assert.equal(accepted.gates.owner_acceptance_completed, true);
  const rejected = applyEvent(required, requiredPolicy, "OWNER_REJECTED", { reason: "Declared criterion not accepted" });
  assert.equal(rejected.phase, "BLOCKED");

  const optionalPolicy = makePolicy("SINGLE_OWNER_SOL");
  let optional = singleOwnerFastPreflight(optionalPolicy).state;
  optional = applyEvent(optional, optionalPolicy, "START_SINGLE_OWNER");
  optional = applyEvent(optional, optionalPolicy, "ADMIT_SINGLE_OWNER_MUTATION_CYCLE");
  optional = applyEvent(optional, optionalPolicy, "COMPLETE_SINGLE_OWNER");
  optional = applyEvent(optional, optionalPolicy, "PASS_SINGLE_OWNER_POSTFLIGHT");
  expectTransitionCode(() => applyEvent(optional, optionalPolicy, "OWNER_ACCEPTED"), "INVALID_TRANSITION");
  optional = applyEvent(optional, optionalPolicy, "SINGLE_OWNER_VERIFICATION_PASSED");
  assert.equal(optional.phase, "PASS");
});

test("phase invariants reject zero-work success paths and skipped mandatory gates", async (t) => {
  await t.test("direct zero-attempt postflight", () => {
    const policy = makePolicy("DIRECT_LUNA_HIGH");
    const initial = createInitialState(policy, stateIdentities(policy));
    expectContractCode(() => identifyContractDocument("pi_gacw_state_v0", {
      ...initial,
      phase: "DIRECT_POSTFLIGHT",
      baseline_approval_required: false,
      route_frozen: true,
      tasks: [{
        task_id: "task-only",
        status: "RUNNING",
        attempts: 0,
        postflight_completed: false,
        verification_completed: false,
        retry_progress_admitted: false,
      }],
      active_task_id: "task-only",
    }), "PHASE_INVARIANT_MISMATCH");
  });

  await t.test("single-owner zero-invocation postflight", () => {
    const policy = makePolicy("SINGLE_OWNER_SOL");
    const initial = createInitialState(policy, stateIdentities(policy));
    expectContractCode(() => identifyContractDocument("pi_gacw_state_v0", {
      ...initial,
      phase: "SINGLE_OWNER_POSTFLIGHT",
      baseline_approval_required: false,
      route_frozen: true,
      tasks: [{
        task_id: "task-only",
        status: "RUNNING",
        attempts: 0,
        postflight_completed: false,
        verification_completed: false,
        retry_progress_admitted: false,
      }],
      active_task_id: "task-only",
    }), "PHASE_INVARIANT_MISMATCH");
  });

  await t.test("routed zero-planner zero-closeout verification", () => {
    const policy = makePolicy("ROUTED_DAG");
    const initial = createInitialState(policy, stateIdentities(policy));
    expectContractCode(() => identifyContractDocument("pi_gacw_state_v0", {
      ...initial,
      phase: "CLOSEOUT_VERIFYING",
      baseline_approval_required: false,
      route_frozen: true,
      gates: { ...initial.gates, planner_completed: true, closeout_completed: true },
      tasks: policy.tasks.map((task) => ({
        task_id: task.task_id,
        status: "PASS",
        attempts: 0,
        postflight_completed: true,
        verification_completed: true,
        retry_progress_admitted: false,
      })),
      counters: { ...initial.counters, leaves_completed: policy.tasks.length },
    }), "PHASE_INVARIANT_MISMATCH");
  });

  await t.test("direct postflight cannot be skipped", () => {
    const { policy, state: fast } = directFastPreflight();
    let state = applyEvent(fast, policy, "START_DIRECT_ATTEMPT");
    state = applyEvent(state, policy, "COMPLETE_DIRECT_ATTEMPT");
    expectContractCode(
      () => identifyContractDocument("pi_gacw_state_v0", { ...state, phase: "DIRECT_VERIFYING" }),
      "PHASE_INVARIANT_MISMATCH",
    );
  });

  await t.test("direct verification cannot be skipped", () => {
    const { policy, state: fast } = directFastPreflight();
    let state = applyEvent(fast, policy, "START_DIRECT_ATTEMPT");
    state = applyEvent(state, policy, "COMPLETE_DIRECT_ATTEMPT");
    state = applyEvent(state, policy, "PASS_DIRECT_POSTFLIGHT");
    expectContractCode(() => identifyContractDocument("pi_gacw_state_v0", {
      ...state,
      phase: "PASS",
      terminal_reason: "PASS",
      active_task_id: null,
      tasks: [{ ...state.tasks[0], status: "PASS" }],
      counters: { ...state.counters, leaves_completed: 1 },
    }), "PHASE_INVARIANT_MISMATCH");
  });

  await t.test("declared owner acceptance cannot be skipped", () => {
    const policy = makePolicy("SINGLE_OWNER_SOL", { ownerAcceptanceRequired: true });
    let state = singleOwnerFastPreflight(policy).state;
    state = applyEvent(state, policy, "START_SINGLE_OWNER");
    state = applyEvent(state, policy, "ADMIT_SINGLE_OWNER_MUTATION_CYCLE");
    state = applyEvent(state, policy, "COMPLETE_SINGLE_OWNER");
    state = applyEvent(state, policy, "PASS_SINGLE_OWNER_POSTFLIGHT");
    state = applyEvent(state, policy, "SINGLE_OWNER_VERIFICATION_PASSED");
    expectContractCode(
      () => identifyContractDocument("pi_gacw_state_v0", { ...state, phase: "PASS", terminal_reason: "PASS" }),
      "PHASE_INVARIANT_MISMATCH",
    );
  });

  await t.test("routed closeout completion and verification cannot be skipped", () => {
    const { policy, state: ready } = routedReady();
    let state = passReadyLeaf(ready, policy, "task-a");
    state = passReadyLeaf(state, policy, "task-b");
    state = applyEvent(state, policy, "START_CLOSEOUT");
    expectContractCode(
      () => identifyContractDocument("pi_gacw_state_v0", { ...state, phase: "PASS", terminal_reason: "PASS" }),
      "PHASE_INVARIANT_MISMATCH",
    );
  });
});

test("state rejects any substituted full policy identity after freeze", async (t) => {
  const { policy, state: ready } = routedReady();
  assert.equal(ready.frozen_policy_content_sha256, policy.content_sha256);

  const combined = structuredClone(policy) as MutableJson;
  combined.tasks[0].topological_rank = 1;
  combined.tasks[0].dependencies = ["task-b"];
  combined.tasks[0].editable_paths = ["replacement/a"];
  combined.tasks[1].topological_rank = 0;
  combined.tasks[1].dependencies = [];
  combined.tasks[1].editable_paths = ["replacement/b"];
  const replacement = identifyContractDocument("pi_gacw_reducer_policy_v0", combined) as unknown as ReducerPolicy;
  assert.deepEqual(policy.tasks[0]?.dependencies, []);
  assert.deepEqual(replacement.tasks[0]?.dependencies, ["task-b"]);
  assert.deepEqual(replacement.tasks[1]?.dependencies, []);
  expectContractCode(() => assertStatePolicyConsistency(ready, replacement), "FROZEN_POLICY_IDENTITY_MISMATCH");
  expectContractCode(
    () => reduceState(ready, transitionEvent("SELECT_READY_LEAF"), replacement),
    "FROZEN_POLICY_IDENTITY_MISMATCH",
  );

  const substitutions: readonly [string, (candidate: MutableJson) => void][] = [
    ["topological rank", (candidate) => { candidate.tasks[1].topological_rank = 2; }],
    ["priority", (candidate) => { candidate.tasks[0].priority = -1; }],
    ["task body digest", (candidate) => { candidate.tasks[0].task_sha256 = digest(801); }],
    ["editable path", (candidate) => { candidate.tasks[0].editable_paths = ["replacement/task-a"]; }],
    ["frozen scope binding", (candidate) => { candidate.frozen_bindings.scope_sha256 = digest(802); }],
    ["acceptance binding", (candidate) => { candidate.frozen_bindings.acceptance_sha256 = digest(803); }],
    ["limit", (candidate) => { candidate.limits.max_attempts_per_leaf = 1; }],
  ];
  for (const [label, mutate] of substitutions) {
    await t.test(label, () => {
      const candidate = structuredClone(policy) as MutableJson;
      mutate(candidate);
      const identified = identifyContractDocument("pi_gacw_reducer_policy_v0", candidate) as unknown as ReducerPolicy;
      expectContractCode(() => assertStatePolicyConsistency(ready, identified), "FROZEN_POLICY_IDENTITY_MISMATCH");
    });
  }
});

test("ROUTED_DAG chooses ready leaves by rank, priority, then lexical task_id and reaches PASS", () => {
  const tasks: readonly TestPolicyTask[] = [
    { task_id: "task-z", task_sha256: digest(101), topological_rank: 1, priority: -100, dependencies: [], editable_paths: ["src/z"] },
    { task_id: "task-b", task_sha256: digest(102), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/b"] },
    { task_id: "task-a", task_sha256: digest(103), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/a"] },
    { task_id: "task-c", task_sha256: digest(104), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["src/c"] },
  ];
  const policy = makePolicy("ROUTED_DAG", { tasks });
  let state = routedReady(policy).state;
  assert.equal(state.counters.worker_invocations.sol_planner, 1);
  assert.equal(state.gates.planner_completed, true);
  state = passReadyLeaf(state, policy, "task-c");
  state = passReadyLeaf(state, policy, "task-a");
  state = passReadyLeaf(state, policy, "task-b");
  state = passReadyLeaf(state, policy, "task-z");
  assert.equal(state.counters.leaves_completed, 4);
  assert.equal(state.counters.worker_invocations.luna_executor, 4);

  state = applyEvent(state, policy, "START_CLOSEOUT");
  assert.equal(state.counters.worker_invocations.sol_closeout, 1);
  state = applyEvent(state, policy, "COMPLETE_CLOSEOUT");
  state = applyEvent(state, policy, "CLOSEOUT_PASSED");
  assert.equal(state.phase, "PASS");
  assert.equal(state.gates.closeout_completed, true);
  assert.equal(state.gates.closeout_verification_completed, true);
  assert.equal(state.counters.worker_invocations.total, 6);
  expectTransitionCode(() => applyEvent(state, policy, "SELECT_READY_LEAF"), "TERMINAL_STATE_IMMUTABLE");
});

test("ROUTED_DAG enforces two attempts per leaf and progress before retry", () => {
  const { policy, state: ready } = routedReady();
  let state = applyEvent(ready, policy, "SELECT_READY_LEAF");
  state = applyEvent(state, policy, "START_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, policy, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  expectTransitionCode(
    () => applyEvent(state, policy, "ADMIT_LEAF_RETRY", { progress_delta: { ...progress(90), summary: " " } }),
    "INVALID_PROGRESS_DELTA",
  );
  state = applyEvent(state, policy, "ADMIT_LEAF_RETRY", { progress_delta: progress(91) });
  state = applyEvent(state, policy, "START_LEAF_ATTEMPT");
  assert.equal(state.tasks.find((task) => task.task_id === "task-a")?.attempts, 2);
  state = applyEvent(state, policy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, policy, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "BLOCKED");
  assert.equal(state.counters.worker_invocations.luna_executor, 2);
  expectTransitionCode(() => applyEvent(state, policy, "START_LEAF_ATTEMPT"), "TERMINAL_STATE_IMMUTABLE");
});

test("ROUTED_DAG admits at most two constrained replans across the frozen DAG", () => {
  const tasks: readonly TestPolicyTask[] = [
    { task_id: "task-a", task_sha256: digest(111), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["src/a"] },
    { task_id: "task-b", task_sha256: digest(112), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/b"] },
    { task_id: "task-c", task_sha256: digest(113), topological_rank: 0, priority: 2, dependencies: [], editable_paths: ["src/c"] },
  ];
  const policy = makePolicy("ROUTED_DAG", { tasks });
  let state = routedReady(policy).state;

  for (const evidenceSeed of [120, 130]) {
    state = applyEvent(state, policy, "SELECT_READY_LEAF");
    state = applyEvent(state, policy, "START_LEAF_ATTEMPT");
    state = applyEvent(state, policy, "COMPLETE_LEAF_ATTEMPT");
    state = applyEvent(state, policy, "PASS_LEAF_POSTFLIGHT");
    state = applyEvent(state, policy, "LEAF_VERIFICATION_FAILED", { failure_class: "PLAN_INCORRECT" });
    state = applyEvent(state, policy, "START_CONSTRAINED_REPLAN");
    const payload = replanCompletionPayload(policy);
    payload.progress_delta = progress(evidenceSeed);
    state = applyEvent(state, policy, "COMPLETE_CONSTRAINED_REPLAN", payload);
    state = applyEvent(state, policy, "ADMIT_LEAF_RETRY", { progress_delta: progress(evidenceSeed + 1) });
    state = applyEvent(state, policy, "START_LEAF_ATTEMPT");
    state = applyEvent(state, policy, "COMPLETE_LEAF_ATTEMPT");
    state = applyEvent(state, policy, "PASS_LEAF_POSTFLIGHT");
    state = applyEvent(state, policy, "LEAF_VERIFICATION_PASSED");
  }
  assert.equal(state.counters.constrained_replans, 2);
  assert.equal(state.counters.worker_invocations.sol_replan, 2);

  state = applyEvent(state, policy, "SELECT_READY_LEAF");
  state = applyEvent(state, policy, "START_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, policy, "LEAF_VERIFICATION_FAILED", { failure_class: "PLAN_INCORRECT" });
  expectTransitionCode(() => applyEvent(state, policy, "START_CONSTRAINED_REPLAN"), "REPLAN_CAP_EXCEEDED");
});

test("constrained replans cannot grow the DAG or alter topology, scope, acceptance, budget, plan, or graph identities", async (t) => {
  const { policy, state: ready } = routedReady();
  let state = applyEvent(ready, policy, "SELECT_READY_LEAF");
  state = applyEvent(state, policy, "START_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, policy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, policy, "LEAF_VERIFICATION_FAILED", { failure_class: "PLAN_INCORRECT" });
  const replanning = applyEvent(state, policy, "START_CONSTRAINED_REPLAN");

  const cases: readonly [string, string, (payload: MutableJson) => void][] = [
    ["DAG growth", "DAG_GROWTH_FORBIDDEN", (payload) => { payload.proposed_task_ids.push("task-extra"); }],
    ["topology", "DAG_TOPOLOGY_CHANGE_FORBIDDEN", (payload) => { payload.proposed_edges = []; }],
    ["scope", "REPLAN_FROZEN_BINDING_CHANGE", (payload) => { payload.frozen_bindings.scope_sha256 = digest(201); }],
    ["acceptance", "REPLAN_FROZEN_BINDING_CHANGE", (payload) => { payload.frozen_bindings.acceptance_sha256 = digest(202); }],
    ["budget", "REPLAN_FROZEN_BINDING_CHANGE", (payload) => { payload.frozen_bindings.budget_sha256 = digest(203); }],
    ["plan", "REPLAN_FROZEN_BINDING_CHANGE", (payload) => { payload.frozen_bindings.plan_approval_sha256 = digest(204); }],
    ["graph", "REPLAN_FROZEN_BINDING_CHANGE", (payload) => { payload.frozen_bindings.task_graph_sha256 = digest(205); }],
  ];
  for (const [label, code, mutate] of cases) {
    await t.test(label, () => {
      const payload = replanCompletionPayload(policy);
      mutate(payload);
      expectTransitionCode(() => applyEvent(replanning, policy, "COMPLETE_CONSTRAINED_REPLAN", payload), code);
    });
  }
});

test("approved task and route identities cannot change after freeze", () => {
  const direct = directFastPreflight();
  expectTransitionCode(
    () => applyEvent(direct.state, direct.policy, "SELECT_ROUTE", { execution_mode: "ROUTED_DAG" }),
    "INVALID_TRANSITION",
  );

  const policy = makePolicy("ROUTED_DAG");
  let state = advanceCommon(policy);
  state = applyEvent(state, policy, "START_PLAN");
  state = applyEvent(state, policy, "COMPLETE_PLAN");
  state = applyEvent(state, policy, "REQUEST_PLAN_APPROVAL");
  expectTransitionCode(
    () => applyEvent(state, policy, "APPROVE_PLAN", {
      plan_approval_sha256: digest(250),
      task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
    }),
    "PLAN_IDENTITY_MISMATCH",
  );
  state = applyEvent(state, policy, "APPROVE_PLAN", {
    plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
  });
  expectTransitionCode(() => applyEvent(state, policy, "APPROVE_PLAN", {
    plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
  }), "INVALID_TRANSITION");
});

test("routed closeout is verification-only and an ordinary closeout defect blocks", () => {
  const { policy, state: ready } = routedReady();
  let state = passReadyLeaf(ready, policy, "task-a");
  state = passReadyLeaf(state, policy, "task-b");
  state = applyEvent(state, policy, "START_CLOSEOUT");
  assert.equal(state.phase, "CLOSEOUT_RUNNING");
  expectTransitionCode(() => applyEvent(state, policy, "START_LEAF_ATTEMPT"), "INVALID_TRANSITION");
  expectTransitionCode(() => applyEvent(state, policy, "START_CONSTRAINED_REPLAN"), "INVALID_TRANSITION");
  state = applyEvent(state, policy, "COMPLETE_CLOSEOUT");
  state = applyEvent(state, policy, "CLOSEOUT_DEFECT", { reason: "ordinary defect discovered at closeout" });
  assert.equal(state.phase, "BLOCKED");
  assert.match(state.terminal_reason ?? "", /^BLOCKED_CLOSEOUT_DEFECT:/);
  assert.equal(state.tasks.every((task) => task.status === "PASS"), true);
  expectTransitionCode(() => applyEvent(state, policy, "CLOSEOUT_PASSED"), "TERMINAL_STATE_IMMUTABLE");
});

test("events cannot leak across direct, single-owner, and routed modes", () => {
  const direct = advanceCommon(makePolicy("DIRECT_LUNA_HIGH"));
  const directPolicy = makePolicy("DIRECT_LUNA_HIGH");
  expectTransitionCode(() => applyEvent(direct, directPolicy, "START_PLAN"), "INVALID_TRANSITION");

  const singlePolicy = makePolicy("SINGLE_OWNER_SOL");
  const single = advanceCommon(singlePolicy);
  expectTransitionCode(() => applyEvent(single, singlePolicy, "START_PLAN"), "INVALID_TRANSITION");

  const routedPolicy = makePolicy("ROUTED_DAG");
  const routed = advanceCommon(routedPolicy);
  expectTransitionCode(() => applyEvent(routed, routedPolicy, "VALIDATE_SINGLE_OWNER_CONTRACT"), "INVALID_TRANSITION");
  expectTransitionCode(() => applyEvent(routed, routedPolicy, "VALIDATE_DIRECT_CONTRACT"), "INVALID_TRANSITION");
});

test("BLOCK is terminal from any nonterminal phase and terminal states are immutable", () => {
  const policy = makePolicy("ROUTED_DAG");
  const running = applyEvent(routedReady(policy).state, policy, "SELECT_READY_LEAF");
  const blocked = applyEvent(running, policy, "BLOCK", { reason: "STATE_DRIFT" });
  assert.equal(blocked.phase, "BLOCKED");
  assert.equal(blocked.active_task_id, null);
  assert.equal(blocked.terminal_reason, "STATE_DRIFT");
  expectTransitionCode(() => reduceState(blocked, transitionEvent("FREEZE_OBJECTIVE"), policy), "TERMINAL_STATE_IMMUTABLE");
});
