import assert from "node:assert/strict";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createControlDecisionKernel, ControlDecisionError } from "../src/control/index.js";
import { evaluateAuthority } from "../src/control/evaluate.js";
import type { M5ImmutableRunAuthoritySources } from "../src/control/types.js";
import { sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { commitTransition, initializeRunStorage, inspectRunStorage } from "../src/persistence/index.js";
import {
  ContractValidationError,
  assertDocumentValid,
  identifyContractDocument,
  validateSchema,
  verifyContractDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type ReducerPolicy,
} from "../src/schemas/index.js";
import { resolveStaticMaxM4MutationCalls } from "../src/persistence/m5-authority.js";
import { createInitialState } from "../src/state-machine/index.js";
import { applyEvent, digest, makePolicy, stateIdentities, transitionEvent, type MutableJson } from "./helpers.js";
import { m5RunAuthority } from "./m5-r3-fixtures.js";
import { processMetadata } from "./persistence-helpers.js";

function m5Policy(reducer: ReducerPolicy, startingState: Sha256Digest, authority?: M5ImmutableRunAuthoritySources): M5ControlPolicyDocument {
  const obligation = { declaration: "src/result.ts", direction: "OUTPUT" as const, stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH" as const,
    evidence_kind: "FILE" as const, literal: null, prefix: null };
  const dimensions = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: reducer.run_id, repository_identity_content_sha256: authority?.repositoryIdentity?.content_sha256 ?? digest(300), worktree_key: authority?.repositoryIdentity?.worktree_key ?? digest(301), starting_state_content_sha256: startingState,
    objective_sha256: digest(50), contract_sha256: authority?.contract?.contract_sha256 ?? digest(51), budget_sha256: reducer.frozen_bindings.budget_sha256,
    route_map_sha256: authority?.routeMap?.route_map_sha256 ?? digest(302), route_map_approval_sha256: authority?.routeMapApproval?.route_map_approval_sha256 ?? digest(303), reducer_policy_content_sha256: reducer.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: reducer.frozen_bindings.scope_sha256,
    acceptance_sha256: reducer.frozen_bindings.acceptance_sha256, plan_approval_sha256: reducer.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: reducer.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(304), command_catalog_content_sha256: digest(305),
    route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "DIRECT_LUNA_HIGH",
    route_facts: { hard_sol_conditions: [], task_count: 1, coherent_single_task: true, failure_domain_count: 1, deterministic_acceptance: true,
      ownership_ambiguous: false, leaf_count: 1, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
    limits: dimensions.map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 100,
      soft_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 80,
      enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const
        : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const })),
    role_reservation_envelopes: [{ logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100,
    maximum_usage_records: 100, maximum_authority_depth: 64,
  }) as unknown as M5ControlPolicyDocument;
}

async function advanceToFullPreflight(stateRoot: string, reducer: ReducerPolicy, initial: Awaited<ReturnType<typeof initializeRunStorage>>) {
  let committed = initial;
  const steps: readonly [string, MutableJson][] = [
    ["FREEZE_OBJECTIVE", {}], ["ACQUIRE_LOCK", {}], ["CAPTURE_BASELINE", { approval_required: false }],
    ["ACCEPT_CLEAN_BASELINE", {}], ["PASS_FULL_PREFLIGHT", {}],
  ];
  for (const [type, payload] of steps) {
    committed = await commitTransition({ stateRoot, runId: reducer.run_id, expectedRevision: committed.statePointer.revision,
      expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: `m5-setup-${type.toLowerCase()}`, policy: reducer, event: transitionEvent(type as any, payload), processMetadata });
  }
  return committed;
}

function usage(policy: M5ControlPolicyDocument, state: Sha256Digest, operation = "operation-1"): M5UsageEvidenceDocument {
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: policy.run_id, policy_content_sha256: policy.content_sha256, originating_state_content_sha256: state,
    operation_id: operation, operation_kind: "TOOL_CALL", execution_mode: "DIRECT_LUNA_HIGH", logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: null, source_layer: "M5", source_kind: "M5_CONTROL_POLICY",
    source_record_content_sha256: policy.content_sha256, measurements: [{ dimension: "TOOL_CALL", amount: 1, basis: "VALIDATED", enforcement_class: "HARD_ENFORCEABLE" }],
    disposition: "COMPLETED", duration_ms: null,
  }) as unknown as M5UsageEvidenceDocument;
}

test("M5 schemas are strict and preserve unavailable usage", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const initial = createInitialState(reducer, stateIdentities(reducer)); const policy = m5Policy(reducer, initial.content_sha256 as Sha256Digest);
  assert.equal(validateSchema("pi_gacw_m5_control_policy_v0", policy).valid, true);
  assert.equal(validateSchema("pi_gacw_m5_usage_evidence_v0", usage(policy, initial.content_sha256 as Sha256Digest)).valid, true);
  assert.equal(validateSchema("pi_gacw_m5_control_policy_v0", { ...policy, extra: true }).valid, false);
  const unavailable = structuredClone(usage(policy, initial.content_sha256 as Sha256Digest)) as MutableJson;
  unavailable.measurements[0] = { dimension: "PROVIDER_REQUEST", amount: 0, basis: "UNAVAILABLE", enforcement_class: "UNAVAILABLE" };
  assert.equal(validateSchema("pi_gacw_m5_usage_evidence_v0", unavailable).valid, true);
  assert.equal(verifyContractDocument("pi_gacw_m5_usage_evidence_v0", unavailable), false);
});

test("M5 validates contract, selects Direct deterministically, publishes authority, and uses M2", async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), "pi-gacw-m5-")); await chmod(stateRoot, 0o700);
  try {
    const reducer = makePolicy("DIRECT_LUNA_HIGH"); const authoritativeSources = m5RunAuthority();
    const initialState = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: authoritativeSources.contract.contract_sha256 });
    const genesis = await initializeRunStorage({ stateRoot, runId: reducer.run_id, policy: reducer, initialState, processMetadata });
    const full = await advanceToFullPreflight(stateRoot, reducer, genesis); const policy = m5Policy(reducer, initialState.content_sha256 as Sha256Digest, authoritativeSources);
    const kernel = createControlDecisionKernel({ stateRoot, runId: reducer.run_id, policy, reducerPolicy: reducer, runAuthority: authoritativeSources });
    const common = { processMetadata, availableLogicalRoles: ["LUNA_EXECUTOR"] as const, obligationEvidence: [] };
    const validated = await kernel.evaluateControlDecision({ intent: "VALIDATE_CONTRACT", expectedRevision: full.statePointer.revision,
      expectedStatePointerContentSha256: full.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: full.workflowState.content_sha256 as Sha256Digest,
      transitionId: "m5-validate-contract", ...common });
    assert.equal(validated.committed, true); assert.equal(validated.workflowState.phase, "CONTRACT_VALIDATED");
    const routed = await kernel.evaluateControlDecision({ intent: "SELECT_ROUTE", expectedRevision: validated.workflowState === full.workflowState ? -1 : full.statePointer.revision + 1,
      expectedStatePointerContentSha256: (await inspectRunStorage({ stateRoot, runId: reducer.run_id })).statePointer!.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: validated.workflowState.content_sha256 as Sha256Digest, transitionId: "m5-select-route", ...common });
    assert.equal(routed.committed, true); assert.equal(routed.decision.selected_route, "DIRECT_LUNA_HIGH"); assert.equal(routed.workflowState.phase, "ROUTE_SELECTED");
    const inspected = await inspectRunStorage({ stateRoot, runId: reducer.run_id });
    assert.equal(inspected.status, "HEALTHY");
    assert.equal(inspected.managedRecordClassifications.find((entry) => entry.object.kind === "M5_CONTROL_DECISION" && entry.object.contentSha256 === routed.decision.content_sha256)?.classification, "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(Object.isFrozen(routed), true); assert.equal(Object.isFrozen(routed.decision), true);
    const publicInspection = await kernel.inspectControlDecision(); assert.equal(Object.isFrozen(publicInspection), true); assert.equal(publicInspection.decisions.length, 2);
  } finally { await rm(stateRoot, { recursive: true, force: true }); }
});

test("M5 rejects production fixtures and conflicting operation usage", async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), "pi-gacw-m5-")); await chmod(stateRoot, 0o700);
  try {
    const reducer = makePolicy("DIRECT_LUNA_HIGH"); const authoritativeSources = m5RunAuthority();
    const initialState = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: authoritativeSources.contract.contract_sha256 });
    const genesis = await initializeRunStorage({ stateRoot, runId: reducer.run_id, policy: reducer, initialState, processMetadata });
    const policy = m5Policy(reducer, initialState.content_sha256 as Sha256Digest, authoritativeSources);
    const production = createControlDecisionKernel({ stateRoot, runId: reducer.run_id, policy, reducerPolicy: reducer, runAuthority: authoritativeSources, production: true });
    await assert.rejects(production.evaluateControlDecision({ intent: "BLOCK", expectedRevision: 0,
      expectedStatePointerContentSha256: genesis.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: genesis.workflowState.content_sha256 as Sha256Digest, transitionId: "m5-prod-block", processMetadata }),
      (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_AUTHORITY_INCOMPLETE");
    const first = usage(policy, initialState.content_sha256 as Sha256Digest); const changed = usage(policy, initialState.content_sha256 as Sha256Digest);
    (changed as MutableJson).measurements[0].amount = 2;
    const identifiedChanged = identifyContractDocument("pi_gacw_m5_usage_evidence_v0", { ...(changed as MutableJson), content_sha256: undefined });
    const kernel = createControlDecisionKernel({ stateRoot, runId: reducer.run_id, policy, reducerPolicy: reducer, runAuthority: authoritativeSources });
    await assert.rejects(kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: 0,
      expectedStatePointerContentSha256: genesis.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: genesis.workflowState.content_sha256 as Sha256Digest, transitionId: "m5-conflict", processMetadata,
      usageEvidence: [first, identifiedChanged as unknown as M5UsageEvidenceDocument] }),
      (error: unknown) => error instanceof ControlDecisionError && error.code === "USAGE_EVIDENCE_INVALID");
  } finally { await rm(stateRoot, { recursive: true, force: true }); }
});

test("M5 fixed failure actions and no-progress blocking are deterministic", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer));
  const policy = m5Policy(reducer, state.content_sha256 as Sha256Digest);
  const cases = [
    ["TRANSIENT_TOOL_FAILURE", "RETRY_TRANSIENT_TOOL_ONCE"], ["LOCAL_IMPLEMENTATION_DEFECT", "SECOND_LUNA_ATTEMPT"],
    ["COMMAND_CONTRACT_ERROR", "CORRECT_COMMAND_ONCE"], ["CONTEXT_MISSING", "RESTORE_CONTEXT_ONCE"],
    ["PLAN_INCORRECT", "CONSTRAINED_REPLAN"], ["AUTHORITY_CONTRADICTION", "REQUEST_OWNER_DECISION"],
    ["SCOPE_EXPANSION_REQUIRED", "BLOCK"], ["STATE_DRIFT", "BLOCK"], ["CONCURRENT_WRITER", "BLOCK"],
    ["TEST_INTEGRITY_VIOLATION", "BLOCK"], ["CLEANUP_UNCERTAIN", "BLOCK"], ["CLOSEOUT_DEFECT", "BLOCK"],
    ["PROCESS_CRASH", "BLOCK"], ["MODEL_UNAVAILABLE", "BLOCK"], ["MUTATION_UNCERTAIN", "BLOCK"],
  ] as const;
  for (const [sourceErrorCode, expected] of cases) {
    const result = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: {
      intent: "AUTHORIZE_CONTINUATION", expectedRevision: 0, expectedStatePointerContentSha256: digest(900),
      expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest,
      progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [policy.content_sha256 as Sha256Digest] },
      failures: [{ sourceLayer: "M5", sourceErrorCode, sourceRecordContentSha256: policy.content_sha256 as Sha256Digest, normalizedSignature: digest(903) }],
    } });
    assert.equal(result.failures[0]?.action, expected, sourceErrorCode);
  }
  const noProgress = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: {
    intent: "AUTHORIZE_CONTINUATION", expectedRevision: 0, expectedStatePointerContentSha256: digest(904),
    expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest,
  } });
  assert.equal(noProgress.outcome, "BLOCK"); assert.equal(noProgress.blocking_reason, "BLOCKED_NO_PROGRESS");
});

test("M5 contract PATH evidence satisfies the bounded gate", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const initial = createInitialState(reducer, stateIdentities(reducer));
  const policy = m5Policy(reducer, initial.content_sha256 as Sha256Digest); const descriptor = policy.obligations[0]!;
  let state = initial;
  state = applyEvent(state, reducer, "FREEZE_OBJECTIVE"); state = applyEvent(state, reducer, "ACQUIRE_LOCK");
  state = applyEvent(state, reducer, "CAPTURE_BASELINE", { approval_required: false }); state = applyEvent(state, reducer, "ACCEPT_CLEAN_BASELINE");
  state = applyEvent(state, reducer, "PASS_FULL_PREFLIGHT"); state = applyEvent(state, reducer, "VALIDATE_CONTRACT");
  const result = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: {
    intent: "SELECT_ROUTE", expectedRevision: 0, expectedStatePointerContentSha256: digest(910),
    expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest, availableLogicalRoles: ["LUNA_EXECUTOR"],
    obligationEvidence: [{ descriptorSha256: descriptor.descriptor_sha256 as Sha256Digest, value: "src/result.ts", evidenceContentSha256: digest(911) }],
  } });
  assert.equal(result.contract_gate.status, "SATISFIED"); assert.equal(result.selected_route, "DIRECT_LUNA_HIGH");
});

test("built control package exposes only the high-level immutable boundary", async () => {
  const control = await import("pi-bounded-coding-workflow/control");
  assert.deepEqual(Object.keys(control).sort(), ["ControlDecisionError", "createControlDecisionKernel"]);
  for (const path of ["pi-bounded-coding-workflow/control/evaluate", "pi-bounded-coding-workflow/src/control/kernel", "pi-bounded-coding-workflow/dist/src/control/evaluate.js"]) {
    await assert.rejects(import(path), (error: unknown) => (error as { code?: string }).code === "ERR_PACKAGE_PATH_NOT_EXPORTED");
  }
});

test("static mutation allowance resolver pins RESOLVED 1/32/ABSENT/NOT_STATIC", () => {
  const base = makePolicy("STATIC_APPROVED_DAG");
  const state = createInitialState(base, stateIdentities(base));
  const dims = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;
  const obligation = { declaration: "src/result.ts", direction: "OUTPUT" as const, stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH" as const, evidence_kind: "FILE" as const, literal: null, prefix: null };
  const limitsFor = (toolHard: number | null) => dims.map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "TOOL_CALL" ? toolHard : 100, soft_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "TOOL_CALL" ? toolHard : 80, enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const }));
  const makeStatic = (value: 1 | 32 | undefined, toolHard: number | null = 100): M5ControlPolicyDocument => {
    const doc: any = {
      schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      run_id: base.run_id, repository_identity_content_sha256: digest(300), worktree_key: digest(301), starting_state_content_sha256: state.content_sha256,
      objective_sha256: digest(50), contract_sha256: digest(51), budget_sha256: base.frozen_bindings.budget_sha256,
      route_map_sha256: digest(302), route_map_approval_sha256: digest(303), reducer_policy_content_sha256: base.content_sha256,
      authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: base.frozen_bindings.scope_sha256,
      acceptance_sha256: base.frozen_bindings.acceptance_sha256, plan_approval_sha256: base.frozen_bindings.plan_approval_sha256,
      task_graph_sha256: base.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(304), command_catalog_content_sha256: digest(305),
      route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "STATIC_APPROVED_DAG",
      route_facts: { hard_sol_conditions: [], task_count: 2, coherent_single_task: false, failure_domain_count: 2, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: 2, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
      obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
      limits: limitsFor(toolHard),
      role_reservation_envelopes: [{ logical_role: "TERRA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
      failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
      route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100, maximum_usage_records: 100, maximum_authority_depth: 64,
      ...(value === undefined ? {} : { static_max_m4_mutation_calls: value }),
    };
    return identifyContractDocument("pi_gacw_m5_control_policy_v0", doc) as unknown as M5ControlPolicyDocument;
  };
  const p1 = makeStatic(1);
  const p32 = makeStatic(32);
  const pAbsent = makeStatic(undefined);
  const nonStatic = (() => {
    const directBase = makePolicy("DIRECT_LUNA_HIGH");
    const directState = createInitialState(directBase, stateIdentities(directBase));
    return identifyContractDocument("pi_gacw_m5_control_policy_v0", {
      schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      run_id: directBase.run_id, repository_identity_content_sha256: digest(310), worktree_key: digest(311), starting_state_content_sha256: directState.content_sha256,
      objective_sha256: digest(50), contract_sha256: digest(51), budget_sha256: directBase.frozen_bindings.budget_sha256,
      route_map_sha256: digest(312), route_map_approval_sha256: digest(313), reducer_policy_content_sha256: directBase.content_sha256,
      authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: directBase.frozen_bindings.scope_sha256,
      acceptance_sha256: directBase.frozen_bindings.acceptance_sha256, plan_approval_sha256: directBase.frozen_bindings.plan_approval_sha256,
      task_graph_sha256: directBase.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(314), command_catalog_content_sha256: digest(315),
      route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "DIRECT_LUNA_HIGH",
      route_facts: { hard_sol_conditions: [], task_count: 1, coherent_single_task: true, failure_domain_count: 1, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: 1, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
      obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
      limits: limitsFor(100),
      role_reservation_envelopes: [{ logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
      failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
      route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100, maximum_usage_records: 100, maximum_authority_depth: 64,
    }) as unknown as M5ControlPolicyDocument;
  })();
  assert.deepEqual(resolveStaticMaxM4MutationCalls(p1), { outcome: "RESOLVED", value: 1 });
  assert.deepEqual(resolveStaticMaxM4MutationCalls(p32), { outcome: "RESOLVED", value: 32 });
  assert.deepEqual(resolveStaticMaxM4MutationCalls(pAbsent), { outcome: "ABSENT" });
  assert.deepEqual(resolveStaticMaxM4MutationCalls(nonStatic), { outcome: "NOT_STATIC" });
  // never default absent to 32
  assert.notDeepEqual(resolveStaticMaxM4MutationCalls(pAbsent), { outcome: "RESOLVED", value: 32 });
});

test("legacy STATIC policy without field remains schema-valid, resolver ABSENT, not rewritten", () => {
  const base = makePolicy("STATIC_APPROVED_DAG");
  const state = createInitialState(base, stateIdentities(base));
  const obligation = { declaration: "src/result.ts", direction: "OUTPUT" as const, stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH" as const, evidence_kind: "FILE" as const, literal: null, prefix: null };
  const dims = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;
  const legacy = identifyContractDocument("pi_gacw_m5_control_policy_v0", {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: base.run_id, repository_identity_content_sha256: digest(300), worktree_key: digest(301), starting_state_content_sha256: state.content_sha256,
    objective_sha256: digest(50), contract_sha256: digest(51), budget_sha256: base.frozen_bindings.budget_sha256,
    route_map_sha256: digest(302), route_map_approval_sha256: digest(303), reducer_policy_content_sha256: base.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: base.frozen_bindings.scope_sha256,
    acceptance_sha256: base.frozen_bindings.acceptance_sha256, plan_approval_sha256: base.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: base.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(304), command_catalog_content_sha256: digest(305),
    route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "STATIC_APPROVED_DAG",
    route_facts: { hard_sol_conditions: [], task_count: 2, coherent_single_task: false, failure_domain_count: 2, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: 2, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
    limits: dims.map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : 100, soft_limit: dimension === "PROVIDER_REQUEST" ? null : 80, enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const })),
    role_reservation_envelopes: [{ logical_role: "TERRA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100, maximum_usage_records: 100, maximum_authority_depth: 64,
  }) as unknown as M5ControlPolicyDocument;
  // schema-valid
  assert.equal(validateSchema("pi_gacw_m5_control_policy_v0", legacy).valid, true);
  // classification/storage would be healthy — via validator
  assertDocumentValid("pi_gacw_m5_control_policy_v0", legacy);
  // resolver returns ABSENT
  assert.deepEqual(resolveStaticMaxM4MutationCalls(legacy), { outcome: "ABSENT" });
  // not rewritten
  assert.equal((legacy as any).static_max_m4_mutation_calls, undefined);
  assert.equal("static_max_m4_mutation_calls" in (legacy as any), false);
  // clone remains without field
  const cloned = structuredClone(legacy) as any;
  assert.equal(cloned.static_max_m4_mutation_calls, undefined);
});

test("M5 policy static_max=2 fails schema validation", () => {
  const base = makePolicy("STATIC_APPROVED_DAG");
  const state = createInitialState(base, stateIdentities(base));
  const bad: any = {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", content_sha256: digest(999),
    run_id: base.run_id, repository_identity_content_sha256: digest(300), worktree_key: digest(301), starting_state_content_sha256: state.content_sha256,
    objective_sha256: digest(50), contract_sha256: digest(51), budget_sha256: base.frozen_bindings.budget_sha256,
    route_map_sha256: digest(302), route_map_approval_sha256: digest(303), reducer_policy_content_sha256: base.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: base.frozen_bindings.scope_sha256,
    acceptance_sha256: base.frozen_bindings.acceptance_sha256, plan_approval_sha256: base.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: base.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(304), command_catalog_content_sha256: digest(305),
    route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "STATIC_APPROVED_DAG",
    route_facts: { hard_sol_conditions: [], task_count: 2, coherent_single_task: false, failure_domain_count: 2, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: 2, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical({ declaration: "src/result.ts", direction: "OUTPUT", stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH", evidence_kind: "FILE", literal: null, prefix: null }), declaration: "src/result.ts", direction: "OUTPUT", stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH", evidence_kind: "FILE", literal: null, prefix: null }],
    limits: (["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const).map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : 100, soft_limit: dimension === "PROVIDER_REQUEST" ? null : 80, enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const })),
    role_reservation_envelopes: [{ logical_role: "TERRA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100, maximum_usage_records: 100, maximum_authority_depth: 64,
    static_max_m4_mutation_calls: 2,
  };
  const result = validateSchema("pi_gacw_m5_control_policy_v0", bad);
  assert.equal(result.valid, false);
  assert.throws(() => identifyContractDocument("pi_gacw_m5_control_policy_v0", bad), (e: unknown) => e instanceof ContractValidationError || (e as any)?.code === "SCHEMA_INVALID" || /SCHEMA_INVALID/.test(String(e)));
});

test("non-STATIC M5 policy with static_max field is rejected by semantic validation", () => {
  const base = makePolicy("DIRECT_LUNA_HIGH");
  const state = createInitialState(base, stateIdentities(base));
  const doc: any = {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", content_sha256: digest(999),
    run_id: base.run_id, repository_identity_content_sha256: digest(320), worktree_key: digest(321), starting_state_content_sha256: state.content_sha256,
    objective_sha256: digest(50), contract_sha256: digest(51), budget_sha256: base.frozen_bindings.budget_sha256,
    route_map_sha256: digest(322), route_map_approval_sha256: digest(323), reducer_policy_content_sha256: base.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: base.frozen_bindings.scope_sha256,
    acceptance_sha256: base.frozen_bindings.acceptance_sha256, plan_approval_sha256: base.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: base.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(324), command_catalog_content_sha256: digest(325),
    route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "DIRECT_LUNA_HIGH",
    route_facts: { hard_sol_conditions: [], task_count: 1, coherent_single_task: true, failure_domain_count: 1, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: 1, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical({ declaration: "src/result.ts", direction: "OUTPUT", stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH", evidence_kind: "FILE", literal: null, prefix: null }), declaration: "src/result.ts", direction: "OUTPUT", stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH", evidence_kind: "FILE", literal: null, prefix: null }],
    limits: (["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const).map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : 100, soft_limit: dimension === "PROVIDER_REQUEST" ? null : 80, enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const })),
    role_reservation_envelopes: [{ logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100, maximum_usage_records: 100, maximum_authority_depth: 64,
    static_max_m4_mutation_calls: 32,
  };
  // schema allows the literal 32, but semantic must reject because mode is not STATIC
  assert.equal(validateSchema("pi_gacw_m5_control_policy_v0", doc).valid, true);
  assert.throws(() => assertDocumentValid("pi_gacw_m5_control_policy_v0", doc), (e: unknown) => e instanceof ContractValidationError && e.code === "STATIC_MUTATION_MODE_MISMATCH");
  assert.throws(() => identifyContractDocument("pi_gacw_m5_control_policy_v0", doc), (e: unknown) => e instanceof ContractValidationError && e.code === "STATIC_MUTATION_MODE_MISMATCH");
});
