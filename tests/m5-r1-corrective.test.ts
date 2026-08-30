import assert from "node:assert/strict";
import test from "node:test";

import { evaluateAuthority, mapLowerLayerFailureCode } from "../src/control/evaluate.js";
import { sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { classifyM5Authority } from "../src/persistence/m5-authority.js";
import type { InspectedObject } from "../src/persistence/types.js";
import {
  identifyContractDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type ReducerPolicy,
  type WorkflowState,
} from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { advanceCommon, applyEvent, digest, makePolicy, stateIdentities, type MutableJson } from "./helpers.js";

const dimensions = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;

function policyFor(reducer: ReducerPolicy, startingState: Sha256Digest, overrides: MutableJson = {}): M5ControlPolicyDocument {
  const obligation = { declaration: "src/result.ts", direction: "OUTPUT" as const, stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH" as const,
    evidence_kind: "FILE" as const, literal: null, prefix: null };
  const base: MutableJson = {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: reducer.run_id, repository_identity_content_sha256: digest(300), worktree_key: digest(301), starting_state_content_sha256: startingState,
    objective_sha256: digest(50), contract_sha256: digest(51), budget_sha256: reducer.frozen_bindings.budget_sha256,
    route_map_sha256: digest(302), route_map_approval_sha256: digest(303), reducer_policy_content_sha256: reducer.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: reducer.frozen_bindings.scope_sha256,
    acceptance_sha256: reducer.frozen_bindings.acceptance_sha256, plan_approval_sha256: reducer.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: reducer.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(304), command_catalog_content_sha256: digest(305),
    route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: reducer.execution_mode,
    route_facts: reducer.execution_mode === "ROUTED_DAG"
      ? { hard_sol_conditions: [], task_count: 2, coherent_single_task: false, failure_domain_count: 2, deterministic_acceptance: true, ownership_ambiguous: false,
          leaf_count: 2, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true }
      : { hard_sol_conditions: reducer.execution_mode === "SINGLE_OWNER_SOL" ? ["PUBLIC_INTERFACE"] : [], task_count: 1, coherent_single_task: true,
          failure_domain_count: 1, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: 1, dag_valid: true, leaves_separable: true,
          unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
    limits: dimensions.map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? 20 : 100,
      soft_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? 20 : 80,
      enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE"
        : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" : "OBSERVABLE_ONLY" })),
    role_reservation_envelopes: [
      { logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_OWNER", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_PLANNER", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_REPLAN", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_CLOSEOUT", purpose: "REQUIRED_CLOSEOUT", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
    ],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100,
    maximum_usage_records: 100, maximum_authority_depth: 64,
    ...overrides,
  };
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", base) as unknown as M5ControlPolicyDocument;
}

function request(state: WorkflowState, extra: MutableJson = {}): any {
  return { intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: digest(900),
    expectedWorkflowStateContentSha256: state.content_sha256, availableLogicalRoles: ["LUNA_EXECUTOR"], ...extra };
}

function usageFor(policy: M5ControlPolicyDocument, state: WorkflowState, operation: string, amount: number): M5UsageEvidenceDocument {
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: policy.run_id, policy_content_sha256: policy.content_sha256, originating_state_content_sha256: state.content_sha256,
    operation_id: operation, operation_kind: "WORKER_INVOCATION", execution_mode: state.execution_mode, logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: null, source_layer: "M5", source_kind: "M5_CONTROL_POLICY", source_record_content_sha256: policy.content_sha256,
    measurements: [{ dimension: "WORKER_INVOCATION", amount, basis: "VALIDATED", enforcement_class: "HARD_ENFORCEABLE" }],
    disposition: "COMPLETED", duration_ms: null,
  }) as unknown as M5UsageEvidenceDocument;
}

function evaluate(policy: M5ControlPolicyDocument, state: WorkflowState, reducer: ReducerPolicy, extra: MutableJson = {}, prior: readonly M5ControlDecisionDocument[] = []) {
  return evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: prior, request: request(state, extra) });
}

test("M5-R1 composes architecture and M1 limits and rejects unsafe usage arithmetic", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer)); const policy = policyFor(reducer, state.content_sha256 as Sha256Digest);
  const baseline = evaluate(policy, state, reducer);
  assert.equal(baseline.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.hard_limit, 2);
  const exact = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [usageFor(policy, state, "exact", 2)], priorDecisions: [], request: request(state) });
  assert.equal(exact.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.hard_remaining, 0);
  assert.throws(() => evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [usageFor(policy, state, "plus-one", 3)], priorDecisions: [], request: request(state) }),
    (error: unknown) => (error as { code?: string }).code === "BUDGET_EXHAUSTED");
  assert.throws(() => evaluateAuthority({ policy, state, reducerPolicy: reducer,
    persistedUsage: [usageFor(policy, state, "overflow-a", Number.MAX_SAFE_INTEGER), usageFor(policy, state, "overflow-b", 1)], priorDecisions: [], request: request(state) }),
    (error: unknown) => (error as { code?: string }).code === "BUDGET_EVALUATION_INVALID");
});

test("M5-R1 gate ignores forged caller detections and validates all six grammars", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer));
  const policy = policyFor(reducer, state.content_sha256 as Sha256Digest);
  const forged = evaluate(policy, state, reducer, { gateDetections: [
    { code: "CYCLIC_DEPENDENCY" }, { code: "MISSING_DEPENDENCY" }, { code: "BUDGET_ENVELOPE_INFEASIBLE" },
  ] });
  assert.deepEqual(forged.contract_gate.detections, []);
  const definitions = [
    ["HEX", "abcdef01", null, null], ["UUID", "01234567-89ab-cdef-8123-456789abcdef", null, null], ["INTEGER", "42", null, null],
    ["LITERAL", "fixed", "fixed", null], ["PREFIXED_LITERAL", "prefix:fixed", "fixed", "prefix:"], ["PATH", "src/result.ts", null, null],
  ] as const;
  const obligations = definitions.map(([grammar, value, literal, prefix], index) => {
    const projection = { declaration: `output-${index}`, direction: "OUTPUT", stage: index, producer: "task-only", consumers: ["contract"], grammar,
      evidence_kind: "FILE", literal, prefix };
    return { descriptor_sha256: sha256Canonical(projection), value, projection };
  });
  const grammarPolicy = policyFor(reducer, state.content_sha256 as Sha256Digest, {
    obligations: obligations.map(({ descriptor_sha256, projection }) => ({ descriptor_sha256, ...projection })),
  });
  const gate = evaluate(grammarPolicy, state, reducer, { obligationEvidence: obligations.map(({ descriptor_sha256, value }, index) => ({
    descriptorSha256: descriptor_sha256, value, evidenceContentSha256: digest(920 + index),
  })) });
  assert.equal(gate.contract_gate.status, "SATISFIED");
  assert.deepEqual(gate.contract_gate.detections, []);
});

test("M5-R1 lower-layer mapping preserves security and authority distinctions", () => {
  const cases = [
    ["COMMAND_SPEC_MISMATCH", "COMMAND_CONTRACT_ERROR"], ["PATH_OUTSIDE_ROOT", "SCOPE_EXPANSION_REQUIRED"], ["LOCK_LOST", "CONCURRENT_WRITER"],
    ["HEAD_DRIFT", "STATE_DRIFT"], ["ROLLBACK_UNCERTAIN", "CLEANUP_UNCERTAIN"], ["COMMAND_SANDBOX_UNAVAILABLE", "CAPABILITY_UNAVAILABLE"],
    ["SECURE_WRITE_UNCERTAIN", "MUTATION_UNCERTAIN"], ["BASELINE_APPROVAL_MISMATCH", "AUTHORITY_CONTRADICTION"],
    ["EVIDENCE_NOT_FOUND", "CONTEXT_MISSING"], ["new-unknown-code", "EVIDENCE_INVALID"],
  ] as const;
  for (const [code, expected] of cases) assert.equal(mapLowerLayerFailureCode(code), expected, code);
});

test("M5-R1 initial routes cover Direct, Single Owner, Routed, hard-Sol and authority", () => {
  for (const [mode, roles, expected] of [
    ["DIRECT_LUNA_HIGH", ["LUNA_EXECUTOR"], "DIRECT_LUNA_HIGH"],
    ["SINGLE_OWNER_SOL", ["SOL_OWNER"], "SINGLE_OWNER_SOL"],
    ["ROUTED_DAG", ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"], "ROUTED_DAG"],
  ] as const) {
    const reducer = makePolicy(mode); let state = createInitialState(reducer, stateIdentities(reducer)); const policy = policyFor(reducer, state.content_sha256 as Sha256Digest);
    state = applyEvent(state, reducer, "FREEZE_OBJECTIVE"); state = applyEvent(state, reducer, "ACQUIRE_LOCK");
    state = applyEvent(state, reducer, "CAPTURE_BASELINE", { approval_required: false }); state = applyEvent(state, reducer, "ACCEPT_CLEAN_BASELINE");
    state = applyEvent(state, reducer, "PASS_FULL_PREFLIGHT"); state = applyEvent(state, reducer, "VALIDATE_CONTRACT");
    const selected = evaluate(policy, state, reducer, { intent: "SELECT_ROUTE", availableLogicalRoles: roles });
    assert.equal(selected.selected_route, expected);
    const missing = evaluate(policy, state, reducer, { intent: "SELECT_ROUTE", availableLogicalRoles: [] });
    assert.equal(missing.outcome, "BLOCK");
  }
});

test("M5-R1 direct PASS is reducer-predicted and wrong-phase terminal evaluation blocks", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const initial = createInitialState(reducer, stateIdentities(reducer)); const policy = policyFor(reducer, initial.content_sha256 as Sha256Digest);
  const descriptor = policy.obligations[0]!;
  let state = advanceCommon(reducer);
  state = applyEvent(state, reducer, "VALIDATE_DIRECT_CONTRACT"); state = applyEvent(state, reducer, "REQUEST_DIRECT_APPROVAL");
  state = applyEvent(state, reducer, "APPROVE_DIRECT_TASK"); state = applyEvent(state, reducer, "PASS_DIRECT_FAST_PREFLIGHT");
  state = applyEvent(state, reducer, "START_DIRECT_ATTEMPT"); state = applyEvent(state, reducer, "COMPLETE_DIRECT_ATTEMPT"); state = applyEvent(state, reducer, "PASS_DIRECT_POSTFLIGHT");
  const terminal = evaluate(policy, state, reducer, { intent: "EVALUATE_TERMINAL", obligationEvidence: [{ descriptorSha256: descriptor.descriptor_sha256,
    value: "src/result.ts", evidenceContentSha256: digest(940) }] });
  assert.equal(terminal.outcome, "PASS"); assert.equal(terminal.transition_event?.event_type, "DIRECT_VERIFICATION_PASSED");
  assert.notEqual(terminal.predicted_next_state_content_sha256, null);
  const wrong = evaluate(policy, initial, reducer, { intent: "EVALUATE_TERMINAL", obligationEvidence: [{ descriptorSha256: descriptor.descriptor_sha256,
    value: "src/result.ts", evidenceContentSha256: digest(941) }] });
  assert.equal(wrong.outcome, "BLOCK"); assert.equal(wrong.transition_event?.event_type, "BLOCK");
});

function object(kind: InspectedObject["kind"], contentSha256: Sha256Digest): InspectedObject {
  return { kind, contentSha256, relativePath: `${kind.toLowerCase()}/${contentSha256.slice(7)}.json` };
}
function rekey(value: M5ControlDecisionDocument): void {
  (value as MutableJson).decision_key = sha256Canonical({ run_id: value.run_id, state: value.current_state_content_sha256, intent: value.intent,
    usage: [...value.usage_evidence_content_sha256].sort(), failures: value.failures.map((entry) => entry.failure_identity), gate: value.contract_gate,
    prior: value.prior_relevant_decision_content_sha256 });
}

test("M5-R1 authority walker rejects cycles and depth-plus-one and classifies missing predecessors", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer));
  const policy = policyFor(reducer, state.content_sha256 as Sha256Digest, { maximum_authority_depth: 2 });
  const decisions: M5ControlDecisionDocument[] = [];
  for (let index = 0; index < 4; index += 1) decisions.push(evaluate(policy, state, reducer, { blockReason: `BLOCKED_TEST_${index}` }, decisions));
  const baseObjects = [object("WORKFLOW_STATE", state.content_sha256 as Sha256Digest), object("M5_CONTROL_POLICY", policy.content_sha256 as Sha256Digest),
    ...decisions.map((entry) => object("M5_CONTROL_DECISION", entry.content_sha256 as Sha256Digest))];
  const classify = (items: readonly M5ControlDecisionDocument[], objects = baseObjects) => classifyM5Authority({
    runId: reducer.run_id, workflowState: state, workflowStates: new Map([[state.content_sha256, state]]), objects, priorClassifications: [],
    policies: new Map([[policy.content_sha256, policy]]), usage: new Map(), decisions: new Map(items.map((entry) => [entry.content_sha256, entry])), reachableRawEvidence: new Set(),
  });
  const depth = classify(decisions);
  assert.equal(depth.find((entry) => entry.object.contentSha256 === decisions[3]!.content_sha256)?.classification, "INVALID_MANAGED_RECORD");
  const missingObjects = baseObjects.filter((entry) => entry.contentSha256 !== decisions[0]!.content_sha256);
  const missing = classify(decisions.slice(1), missingObjects);
  assert.equal(missing.find((entry) => entry.object.contentSha256 === decisions[1]!.content_sha256)?.classification, "INCOMPLETE_MANAGED_RECORD_CHAIN");
  const first = structuredClone(decisions[0]!); const second = structuredClone(decisions[1]!);
  (first as MutableJson).prior_relevant_decision_content_sha256 = second.content_sha256; rekey(first);
  (second as MutableJson).prior_relevant_decision_content_sha256 = first.content_sha256; rekey(second);
  const cycle = classify([first, second], [object("WORKFLOW_STATE", state.content_sha256 as Sha256Digest), object("M5_CONTROL_POLICY", policy.content_sha256 as Sha256Digest),
    object("M5_CONTROL_DECISION", first.content_sha256 as Sha256Digest), object("M5_CONTROL_DECISION", second.content_sha256 as Sha256Digest)]);
  assert.equal(cycle.filter((entry) => entry.object.kind === "M5_CONTROL_DECISION").every((entry) => entry.classification === "INVALID_MANAGED_RECORD"), true);
});
