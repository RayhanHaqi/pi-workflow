import assert from "node:assert/strict";
import test from "node:test";

import {
  ContractValidationError,
  assertDocumentValid,
  identifyContractDocument,
  type ReducerPolicy,
  type TaskDocument,
  type WorkflowState,
} from "../src/schemas/index.js";
import { TransitionError, createInitialState, reduceState } from "../src/state-machine/index.js";
import {
  applyEvent,
  digest,
  makePolicy,
  planApprovalDocument,
  route,
  stateIdentities,
  transitionEvent,
  type MutableJson,
} from "./helpers.js";

function expectCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => error instanceof TransitionError && error.code === code);
}

function staticReady(policy = makePolicy("STATIC_APPROVED_DAG")): { readonly policy: ReducerPolicy; readonly state: WorkflowState } {
  let state = (awaitCommon(policy));
  state = applyEvent(state, policy, "FREEZE_STATIC_DAG");
  state = applyEvent(state, policy, "ACTIVATE_DAG");
  return { policy, state };
}

function awaitCommon(policy: ReducerPolicy): WorkflowState {
  let state = createInitialState(policy, stateIdentities(policy));
  for (const [event, payload] of [
    ["FREEZE_OBJECTIVE", {}], ["ACQUIRE_LOCK", {}], ["CAPTURE_BASELINE", { approval_required: false }],
    ["ACCEPT_CLEAN_BASELINE", {}], ["PASS_FULL_PREFLIGHT", {}], ["VALIDATE_CONTRACT", {}],
    ["SELECT_ROUTE", { execution_mode: "STATIC_APPROVED_DAG" }],
  ] as const) state = applyEvent(state, policy, event, payload);
  return state;
}

function passLeaf(state: WorkflowState, policy: ReducerPolicy, id: string): WorkflowState {
  let next = applyEvent(state, policy, "SELECT_READY_LEAF");
  assert.equal(next.active_task_id, id);
  assert.equal(next.tasks.filter((task) => task.status === "RUNNING").length, 0);
  next = applyEvent(next, policy, "START_LEAF_ATTEMPT");
  assert.equal(next.counters.worker_invocations.terra_executor, next.tasks.reduce((count, task) => count + task.attempts, 0));
  assert.equal(next.tasks.filter((task) => task.status === "RUNNING").length, 1);
  next = applyEvent(next, policy, "COMPLETE_LEAF_ATTEMPT");
  next = applyEvent(next, policy, "PASS_LEAF_POSTFLIGHT");
  return applyEvent(next, policy, "LEAF_VERIFICATION_PASSED");
}

test("STATIC_APPROVED_DAG accepts only the exact frozen Terra High role and route", () => {
  const task = identifyContractDocument("pi_gacw_task_v0", {
    schema_id: "pi_gacw_task_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    task_projection_id: "task-packet-v1", task_sha256: digest(901), task_id: "terra-task", topological_rank: 0, priority: 0,
    dependencies: [], objective: "Implement exactly the frozen task.", scope: { readable_paths: ["src"], editable_paths: ["src/terra"], frozen_paths: ["docs"] },
    required_inputs: ["src"], required_outputs: ["src/terra"], acceptance_criteria: [{ criterion_id: "verify", description: "Deterministic verification passes.", evidence_kind: "COMMAND", owner_acceptance: false }],
    owner_acceptance_criteria: [], verification_commands: [], assigned_role: "TERRA_EXECUTOR", write_owner: "terra-task",
  }) as TaskDocument;
  assertDocumentValid("pi_gacw_task_v0", task);
  assertDocumentValid("pi_gacw_plan_approval_v0", planApprovalDocument("STATIC_APPROVED_DAG"));

  const wrongModel = route("TERRA_EXECUTOR"); wrongModel.model_id = "gpt-5.6-luna";
  assert.throws(() => identifyContractDocument("pi_gacw_route_map_v0", {
    schema_id: "pi_gacw_route_map_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", route_map_projection_id: "route-map-v1",
    routes: [route("SOL_OWNER"), route("SOL_PLANNER"), route("SOL_REPLAN"), route("SOL_CLOSEOUT"), route("LUNA_EXECUTOR"), wrongModel, route("BENCHMARK_VERIFIER"), route("BENCHMARK_SELECTOR")], fallback: false, provider_managed_multi_agent: false,
  }), (error: unknown) => error instanceof ContractValidationError && error.code === "INVALID_TERRA_ROUTE");

  const wrongPlan = planApprovalDocument("STATIC_APPROVED_DAG"); wrongPlan.bindings.logical_routes = [route("LUNA_EXECUTOR")];
  assert.throws(() => identifyContractDocument("pi_gacw_plan_approval_v0", wrongPlan), (error: unknown) => error instanceof ContractValidationError && error.code === "STATIC_DAG_ROUTE_RESTRICTED");
});

test("STATIC_APPROVED_DAG executes a frozen three-node DAG sequentially to PASS without planner or closeout", () => {
  const policy = makePolicy("STATIC_APPROVED_DAG", { tasks: [
    { task_id: "task-a", task_sha256: digest(910), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/a"] },
    { task_id: "task-b", task_sha256: digest(911), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["src/b"] },
    { task_id: "task-c", task_sha256: digest(912), topological_rank: 1, priority: 0, dependencies: ["task-b"], editable_paths: ["src/c"] },
  ] });
  let state = staticReady(policy).state;
  state = passLeaf(state, policy, "task-b");
  state = passLeaf(state, policy, "task-a");
  state = passLeaf(state, policy, "task-c");
  assert.equal(state.phase, "STATIC_DAG_VERIFYING");
  state = applyEvent(state, policy, "STATIC_DAG_VERIFICATION_PASSED");
  assert.equal(state.phase, "PASS");
  assert.equal(state.counters.worker_invocations.terra_executor, 3);
  assert.equal(state.counters.worker_invocations.sol_planner, 0);
  assert.equal(state.counters.worker_invocations.sol_replan, 0);
  assert.equal(state.counters.worker_invocations.sol_closeout, 0);
  assert.equal(state.counters.worker_invocations.luna_executor, 0);
  assert.equal(state.tasks.every((task) => task.status === "PASS"), true);
});

test("STATIC_APPROVED_DAG admits exactly one frozen local-defect repair and otherwise blocks", () => {
  const repairPolicy = makePolicy("STATIC_APPROVED_DAG", { limits: { max_attempts_per_leaf: 2 } });
  let state = staticReady(repairPolicy).state;
  state = applyEvent(state, repairPolicy, "SELECT_READY_LEAF");
  state = applyEvent(state, repairPolicy, "START_LEAF_ATTEMPT");
  state = applyEvent(state, repairPolicy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, repairPolicy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, repairPolicy, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "LEAF_RETRY_READY");
  state = applyEvent(state, repairPolicy, "ADMIT_LEAF_RETRY", { progress_delta: { kind: "NEW_TEST_EVIDENCE", evidence_sha256: digest(920), summary: "Trusted deterministic verifier isolated a local implementation defect." } });
  state = applyEvent(state, repairPolicy, "START_LEAF_ATTEMPT");
  assert.equal(state.counters.worker_invocations.terra_executor, 2);
  state = applyEvent(state, repairPolicy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, repairPolicy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, repairPolicy, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "BLOCKED");

  const noRepair = makePolicy("STATIC_APPROVED_DAG", { limits: { max_attempts_per_leaf: 1 } });
  state = staticReady(noRepair).state;
  state = applyEvent(state, noRepair, "SELECT_READY_LEAF");
  state = applyEvent(state, noRepair, "START_LEAF_ATTEMPT");
  state = applyEvent(state, noRepair, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, noRepair, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, noRepair, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "BLOCKED");

  const unsafe = staticReady(repairPolicy).state;
  let unknown = applyEvent(unsafe, repairPolicy, "SELECT_READY_LEAF");
  unknown = applyEvent(unknown, repairPolicy, "START_LEAF_ATTEMPT");
  unknown = applyEvent(unknown, repairPolicy, "COMPLETE_LEAF_ATTEMPT");
  unknown = applyEvent(unknown, repairPolicy, "PASS_LEAF_POSTFLIGHT");
  unknown = applyEvent(unknown, repairPolicy, "LEAF_VERIFICATION_FAILED", { failure_class: "MODEL_UNAVAILABLE" });
  assert.equal(unknown.phase, "BLOCKED");
  expectCode(() => reduceState(unknown, transitionEvent("START_LEAF_ATTEMPT"), repairPolicy), "TERMINAL_STATE_IMMUTABLE");
});

test("STATIC_APPROVED_DAG cannot invoke replan/closeout or grow its frozen task set", () => {
  const { policy, state } = staticReady();
  expectCode(() => applyEvent(state, policy, "START_PLAN"), "INVALID_TRANSITION");
  expectCode(() => applyEvent(state, policy, "START_CONSTRAINED_REPLAN"), "INVALID_TRANSITION");
  expectCode(() => applyEvent(state, policy, "START_CLOSEOUT"), "INVALID_TRANSITION");
  const substituted = structuredClone(policy) as MutableJson;
  substituted.tasks.push({ task_id: "task-extra", task_sha256: digest(999), topological_rank: 2, priority: 0, dependencies: ["task-b"], editable_paths: ["src/extra"] });
  const grown = identifyContractDocument("pi_gacw_reducer_policy_v0", substituted) as ReducerPolicy;
  assert.throws(() => reduceState(state, transitionEvent("SELECT_READY_LEAF"), grown), (error: unknown) => error instanceof ContractValidationError && error.code === "FROZEN_POLICY_IDENTITY_MISMATCH");
});
