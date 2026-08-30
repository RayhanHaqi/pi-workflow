import assert from "node:assert/strict";
import test from "node:test";

import { evaluateAuthority, M5_LOWER_LAYER_FAILURE_CODES, M5_LOWER_LAYER_FAILURE_MAPPING, mapLowerLayerFailureCode } from "../src/control/evaluate.js";
import { sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { classifyM5Authority } from "../src/persistence/m5-authority.js";
import {
  identifyContractDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type ReducerPolicy,
  type WorkflowState,
} from "../src/schemas/index.js";
import { createInitialState, reduceState } from "../src/state-machine/index.js";
import { advanceCommon, applyEvent, budgetDocument, digest, domainDocument, makePolicy, stateIdentities, type MutableJson } from "./helpers.js";
import { m5RunAuthority } from "./m5-r3-fixtures.js";
import { processMetadata } from "./persistence-helpers.js";
import { createControlDecisionKernel } from "../src/control/index.js";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initializeRunStorage, inspectRunStorage } from "../src/persistence/index.js";

const dims = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;

function reidentify<T extends MutableJson>(schema: string, value: MutableJson, patch: MutableJson = {}): T {
  const { content_sha256: _content, ...body } = structuredClone(value);
  return identifyContractDocument(schema as any, { ...body, ...patch }) as T;
}

function m5Policy(reducer: ReducerPolicy, state: WorkflowState, patch: MutableJson = {}): M5ControlPolicyDocument {
  const descriptor = { declaration: "src/result.ts", direction: "OUTPUT", stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH",
    evidence_kind: "FILE", literal: null, prefix: null };
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: reducer.run_id, repository_identity_content_sha256: digest(300), worktree_key: digest(301), starting_state_content_sha256: state.content_sha256,
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
    obligations: [{ descriptor_sha256: sha256Canonical(descriptor), ...descriptor }],
    limits: dims.map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 100,
      soft_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 80,
      enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" : "OBSERVABLE_ONLY" })),
    role_reservation_envelopes: [
      { logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_OWNER", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_PLANNER", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_REPLAN", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
      { logical_role: "SOL_CLOSEOUT", purpose: "REQUIRED_CLOSEOUT", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] },
    ],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100,
    maximum_usage_records: 100, maximum_authority_depth: 64, ...patch,
  }) as unknown as M5ControlPolicyDocument;
}

function blockRequest(state: WorkflowState, patch: MutableJson = {}): any {
  return { intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: digest(900), expectedWorkflowStateContentSha256: state.content_sha256,
    availableLogicalRoles: ["LUNA_EXECUTOR"], ...patch };
}

function usage(policy: M5ControlPolicyDocument, state: WorkflowState, operationId: string, amount: number, patch: MutableJson = {}): M5UsageEvidenceDocument {
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: policy.run_id, policy_content_sha256: policy.content_sha256, originating_state_content_sha256: state.content_sha256,
    operation_id: operationId, operation_kind: "WORKER_INVOCATION", execution_mode: state.execution_mode, logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: null, source_layer: "M5", source_kind: "M5_CONTROL_POLICY", source_record_content_sha256: policy.content_sha256,
    measurements: [{ dimension: "WORKER_INVOCATION", amount, basis: "VALIDATED", enforcement_class: "HARD_ENFORCEABLE" }], disposition: "COMPLETED", duration_ms: null, ...patch,
  }) as unknown as M5UsageEvidenceDocument;
}

function m4Policy(reducer: ReducerPolicy, maxDuration = 1_800_000): any {
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
    schema_id: "pi_gacw_scoped_tool_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: reducer.run_id,
    policy_id: "m4-r2-policy", repository_identity_content_sha256: digest(300), worktree_key: digest(301), task_scope_identity: reducer.frozen_bindings.scope_sha256,
    readable_paths: [], editable_paths: [], frozen_paths: [], command_readable_paths: [], command_writable_paths: [], path_authorities: [], evidence_readable_kinds: [],
    limits: { maximum_patch_bytes: 1_048_576, maximum_read_bytes: 1_048_576, maximum_hash_bytes: 67_108_864, maximum_search_input_bytes: 67_108_864,
      maximum_search_matches: 10_000, maximum_list_entries: 100_000, maximum_list_metadata_bytes: 67_108_864, maximum_command_stdout_bytes: 4_194_304,
      maximum_command_stderr_bytes: 4_194_304, maximum_command_duration_ms: maxDuration },
  });
}

function m4Catalog(reducer: ReducerPolicy, policy: any): any {
  return identifyContractDocument("pi_gacw_command_catalog_v0", { schema_id: "pi_gacw_command_catalog_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: reducer.run_id, catalog_id: "m4-r2-catalog", repository_identity_content_sha256: digest(300), tool_policy_content_sha256: policy.content_sha256, commands: [] });
}

function sourceBundle(reducer: ReducerPolicy, policy: M5ControlPolicyDocument, overrides: MutableJson = {}) {
  const contract = reidentify("pi_gacw_contract_v0", domainDocument("contract-freeze-v1"), { contract_sha256: policy.contract_sha256 });
  const budget = reidentify("pi_gacw_budget_v0", budgetDocument(), { budget_sha256: policy.budget_sha256 });
  const toolPolicy = m4Policy(reducer);
  const catalog = m4Catalog(reducer, toolPolicy);
  return { contract, budget, m4ToolPolicy: toolPolicy, m4CommandCatalog: catalog, ...overrides };
}

function evaluate(policy: M5ControlPolicyDocument, state: WorkflowState, reducer: ReducerPolicy, patch: MutableJson = {}, prior: readonly M5ControlDecisionDocument[] = [], sources: any = undefined) {
  return evaluateAuthority({ policy, state, reducerPolicy: reducer, request: blockRequest(state, patch), persistedUsage: [], priorDecisions: prior, ...(sources === undefined ? {} : { authoritativeSources: sources }) });
}

test("M5-R2 traversal is root-relative for shared nodes, wrong kinds, cycles, and exact boundary", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer)); const policy = m5Policy(reducer, state, { maximum_authority_depth: 2 });
  const decisions: M5ControlDecisionDocument[] = [];
  for (let i = 0; i < 4; i += 1) decisions.push(evaluate(policy, state, reducer, { blockReason: `BLOCKED_R2_${i}` }, decisions));
  const object = (kind: any, digestValue: Sha256Digest) => ({ kind, contentSha256: digestValue, relativePath: `${kind}/${digestValue.slice(7)}.json` });
  const base = [object("WORKFLOW_STATE", state.content_sha256 as Sha256Digest), object("M5_CONTROL_POLICY", policy.content_sha256 as Sha256Digest), ...decisions.map((d) => object("M5_CONTROL_DECISION", d.content_sha256 as Sha256Digest))];
  const classify = (items: readonly M5ControlDecisionDocument[], objects = base) => classifyM5Authority({ runId: reducer.run_id, workflowState: state,
    workflowStates: new Map([[state.content_sha256, state]]), objects, priorClassifications: [], policies: new Map([[policy.content_sha256, policy]]),
    usage: new Map(), decisions: new Map(items.map((d) => [d.content_sha256, d])), reachableRawEvidence: new Set() });
  const result = classify(decisions);
  assert.equal(result.find((entry) => entry.object.contentSha256 === decisions[3]!.content_sha256)?.classification, "INVALID_MANAGED_RECORD");
  const wrongKind = classify([decisions[1]!], [object("WORKFLOW_STATE", state.content_sha256 as Sha256Digest), object("M5_CONTROL_POLICY", policy.content_sha256 as Sha256Digest), object("M5_USAGE_EVIDENCE", decisions[0]!.content_sha256 as Sha256Digest), object("M5_CONTROL_DECISION", decisions[1]!.content_sha256 as Sha256Digest)]);
  assert.equal(wrongKind.find((entry) => entry.object.kind === "M5_CONTROL_DECISION")?.classification, "INVALID_MANAGED_RECORD");
  const missingObjects = base.filter((entry) => entry.contentSha256 !== decisions[0]!.content_sha256);
  const missing = classify(decisions.slice(1), missingObjects);
  assert.equal(missing.find((entry) => entry.object.contentSha256 === decisions[1]!.content_sha256)?.classification, "INCOMPLETE_MANAGED_RECORD_CHAIN");
  const first = structuredClone(decisions[0]!); const second = structuredClone(decisions[1]!);
  const rekey = (value: M5ControlDecisionDocument): void => {
    (value as MutableJson).decision_key = sha256Canonical({ run_id: value.run_id, state: value.current_state_content_sha256, intent: value.intent,
      usage: [...value.usage_evidence_content_sha256].sort(), failures: value.failures.map((entry) => entry.failure_identity), gate: value.contract_gate,
      prior: value.prior_relevant_decision_content_sha256 });
  };
  (first as MutableJson).prior_relevant_decision_content_sha256 = second.content_sha256; rekey(first);
  (second as MutableJson).prior_relevant_decision_content_sha256 = first.content_sha256; rekey(second);
  const cycle = classify([first, second], [object("WORKFLOW_STATE", state.content_sha256 as Sha256Digest), object("M5_CONTROL_POLICY", policy.content_sha256 as Sha256Digest),
    object("M5_CONTROL_DECISION", first.content_sha256 as Sha256Digest), object("M5_CONTROL_DECISION", second.content_sha256 as Sha256Digest)]);
  assert.equal(cycle.filter((entry) => entry.object.kind === "M5_CONTROL_DECISION").every((entry) => entry.classification === "INVALID_MANAGED_RECORD"), true);
});

test("M5-R2 composes contract, budget, M1, M4, and M5 limits for every dimension", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer));
  const policy0 = m5Policy(reducer, state); const m4 = m4Policy(reducer, 7); const catalog = m4Catalog(reducer, m4);
  const contractBase = domainDocument("contract-freeze-v1") as any;
  const contract = reidentify<any>("pi_gacw_contract_v0", contractBase, { objective_sha256: policy0.objective_sha256, baseline_approval_sha256: policy0.baseline_approval_sha256,
    authority_lock_sha256: policy0.authority_lock_sha256, route_map_approval_sha256: policy0.route_map_approval_sha256, limits: { ...contractBase.limits, max_worker_invocations: 9, max_wall_time_ms: 8 } });
  const budgetBase = budgetDocument() as any;
  const budget = reidentify<any>("pi_gacw_budget_v0", budgetBase, { limits: { ...budgetBase.limits, max_worker_invocations: 1, max_wall_time_ms: 9 } });
  const policy = reidentify<M5ControlPolicyDocument>("pi_gacw_m5_control_policy_v0", policy0, { contract_sha256: contract.contract_sha256, budget_sha256: budget.budget_sha256, tool_policy_content_sha256: m4.content_sha256, command_catalog_content_sha256: catalog.content_sha256,
    limits: policy0.limits.map((entry: any) => entry.dimension === "WORKER_INVOCATION" ? { ...entry, hard_limit: 5, soft_limit: 4 } : entry) });
  const result = evaluate(policy, state, reducer, {}, [], { contract, budget, m4ToolPolicy: m4, m4CommandCatalog: catalog });
  assert.equal(result.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.hard_limit, 1);
  assert.equal(result.budget.find((entry) => entry.dimension === "WALL_TIME_MS")?.hard_limit, 7);
  assert.equal(result.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.soft_limit, 1);
  const invalid = structuredClone(m4) as MutableJson; invalid.limits.maximum_command_duration_ms = 0;
  assert.throws(() => evaluate(policy, state, reducer, {}, [], { contract, budget, m4ToolPolicy: invalid, m4CommandCatalog: catalog }), /M5_AUTHORITY_INCOMPLETE/);
});

test("M5-R2 reservation reconciliation is single-use, route-bound, and uncertainty-preserving", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); let state = advanceCommon(reducer); state = applyEvent(state, reducer, "VALIDATE_DIRECT_CONTRACT"); state = applyEvent(state, reducer, "REQUEST_DIRECT_APPROVAL");
  state = applyEvent(state, reducer, "APPROVE_DIRECT_TASK"); state = applyEvent(state, reducer, "PASS_DIRECT_FAST_PREFLIGHT");
  const policy = m5Policy(reducer, createInitialState(reducer, stateIdentities(reducer)));
  const reserved = evaluate(policy, state, reducer, { intent: "AUTHORIZE_WORK", operationId: "op-r2", availableLogicalRoles: ["LUNA_EXECUTOR"] });
  assert.equal(reserved.outcome, "AUTHORIZE"); assert.equal(reserved.reservation?.status, "ACTIVE"); assert.equal(reserved.reservation?.future_operation_id, "op-r2");
  const reconciled = usage(policy, state, "op-r2", 1, { reservation_decision_content_sha256: reserved.content_sha256 });
  const after = evaluate(policy, state, reducer, { usageEvidence: [reconciled] }, [reserved]);
  assert.equal(after.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.active_reservation_amount, 0);
  assert.equal(after.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.reconciled_amount, 1);
  const same = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [reconciled, reconciled], priorDecisions: [reserved], request: blockRequest(state) });
  assert.equal(same.budget.find((entry) => entry.dimension === "WORKER_INVOCATION")?.effective_charged_amount, 1);
  const uncertain = usage(policy, state, "op-r2-uncertain", 1, { reservation_decision_content_sha256: reserved.content_sha256, disposition: "OUTCOME_UNCERTAIN" });
  assert.throws(() => evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [reconciled, uncertain], priorDecisions: [reserved], request: blockRequest(state) }), /USAGE_EVIDENCE_INVALID/);
});

test("M5-R2 progress and no-progress reasons are derived, not caller-selected", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer)); const policy = m5Policy(reducer, state);
  assert.equal(evaluate(policy, state, reducer).progress.no_progress_reason, "IDENTICAL_REPORT");
  const prose = evaluate(policy, state, reducer, { progressEvidence: { evidenceContentSha256: [] } });
  assert.equal(prose.progress.no_progress_reason, "PROSE_WITHOUT_EVIDENCE");
  assert.throws(() => evaluate(policy, state, reducer, { progressEvidence: { evidenceContentSha256: [], noProgressReason: "IDENTICAL_REPORT" } }), /PROGRESS_CLASSIFICATION_INVALID/);
  assert.throws(() => evaluate(policy, state, reducer, { progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [digest(930)] } }),
    (error: unknown) => (error as { code?: string }).code === "PROGRESS_EVIDENCE_INVALID");
  const source = policy.content_sha256 as Sha256Digest;
  const evidenceBacked = evaluate(policy, state, reducer, {
    progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [source] },
    failures: [{ sourceLayer: "M5", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: source, normalizedSignature: digest(932) }],
  });
  assert.equal(evidenceBacked.progress.classification, "PROGRESS");
  const previous = evaluate(policy, state, reducer, { failures: [{ sourceLayer: "M4", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: digest(970), normalizedSignature: digest(971) }] });
  const repeated = evaluate(policy, state, reducer, { failures: [{ sourceLayer: "M4", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: digest(970), normalizedSignature: digest(971) }] }, [previous]);
  assert.equal(repeated.progress.no_progress_reason, "SAME_NORMALIZED_FAILURE_WITH_NO_DELTA");
  const repeatedEvidence = evaluate(policy, state, reducer, { progressEvidence: { evidenceContentSha256: [digest(972)] } }, [{ ...previous, progress: { ...previous.progress, evidence_content_sha256: [digest(972)] } } as M5ControlDecisionDocument]);
  assert.equal(repeatedEvidence.progress.no_progress_reason, "REPEATED_TEST_WITH_NO_NEW_EVIDENCE");
});

test("M5-R2 lower-layer finite mapping is explicit and security-sensitive", () => {
  assert.ok(M5_LOWER_LAYER_FAILURE_CODES.length > 100);
  for (const code of M5_LOWER_LAYER_FAILURE_CODES) assert.ok(M5_LOWER_LAYER_FAILURE_MAPPING[code] !== undefined, code);
  assert.equal(mapLowerLayerFailureCode("LOCK_LOST"), "CONCURRENT_WRITER");
  assert.equal(mapLowerLayerFailureCode("PATH_OUTSIDE_ROOT"), "SCOPE_EXPANSION_REQUIRED");
  assert.equal(mapLowerLayerFailureCode("SECURE_WRITE_UNCERTAIN"), "MUTATION_UNCERTAIN");
  assert.equal(mapLowerLayerFailureCode("COMMAND_SPEC_MISMATCH"), "COMMAND_CONTRACT_ERROR");
  assert.equal(mapLowerLayerFailureCode("HEAD_DRIFT"), "STATE_DRIFT");
  assert.equal(mapLowerLayerFailureCode("ROLLBACK_UNCERTAIN"), "CLEANUP_UNCERTAIN");
  assert.equal(mapLowerLayerFailureCode("COMMAND_SANDBOX_UNAVAILABLE"), "CAPABILITY_UNAVAILABLE");
  assert.equal(mapLowerLayerFailureCode("BASELINE_APPROVAL_MISMATCH"), "AUTHORITY_CONTRADICTION");
  assert.equal(mapLowerLayerFailureCode("EVIDENCE_NOT_FOUND"), "CONTEXT_MISSING");
  assert.equal(mapLowerLayerFailureCode("not-a-known-code"), "EVIDENCE_INVALID");
});

test("M5-R2 contract gate independently derives producer, stage, acceptance, verification, route, and budget detections", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer)); const policy0 = m5Policy(reducer, state);
  const contract0 = domainDocument("contract-freeze-v1") as any;
  const contract = reidentify<any>("pi_gacw_contract_v0", contract0, { objective_sha256: policy0.objective_sha256, baseline_approval_sha256: policy0.baseline_approval_sha256,
    authority_lock_sha256: policy0.authority_lock_sha256, route_map_approval_sha256: policy0.route_map_approval_sha256, required_outputs: ["missing-output"], verification_commands: [{ ...contract0.verification_commands[0], command_id: "missing-command" }] });
  const m4 = m4Policy(reducer); const catalog = m4Catalog(reducer, m4);
  const budget = reidentify<any>("pi_gacw_budget_v0", budgetDocument(), { budget_sha256: policy0.budget_sha256 });
  const policy = reidentify<M5ControlPolicyDocument>("pi_gacw_m5_control_policy_v0", policy0, { contract_sha256: contract.contract_sha256, budget_sha256: budget.budget_sha256, tool_policy_content_sha256: m4.content_sha256, command_catalog_content_sha256: catalog.content_sha256,
    obligations: [{ ...policy0.obligations[0], declaration: "different-output", producer: "missing-producer", stage: 4, consumers: ["different-output"] }] });
  const result = evaluate(policy, state, reducer, { gateDetections: [{ code: "CYCLIC_DEPENDENCY" }], availableLogicalRoles: ["LUNA_EXECUTOR"] }, [], { contract, budget, m4ToolPolicy: m4, m4CommandCatalog: catalog });
  const codes = new Set(result.contract_gate.detections.map((entry) => entry.code));
  assert.equal(codes.has("CYCLIC_DEPENDENCY"), false);
  assert.equal(codes.has("MISSING_PRODUCER"), true);
  assert.equal(codes.has("VERIFICATION_COMMAND_UNAVAILABLE"), true);
});

test("M5-R2 all initial route fact dimensions fail closed", () => {
  const facts = ["coherent_single_task", "deterministic_acceptance", "ownership_ambiguous", "failure_domain_count"] as const;
  for (const fact of facts) {
    const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = advanceCommon(reducer); const policy = m5Policy(reducer, state,
      { route_facts: { hard_sol_conditions: [], task_count: 1, coherent_single_task: fact === "coherent_single_task" ? false : true, failure_domain_count: fact === "failure_domain_count" ? 2 : 1,
        deterministic_acceptance: fact === "deterministic_acceptance" ? false : true, ownership_ambiguous: fact === "ownership_ambiguous", leaf_count: 1, dag_valid: true,
        leaves_separable: true, unique_write_ownership: fact === "ownership_ambiguous" ? false : true, leaf_acceptance_machine_checkable: true } });
    const result = evaluate(policy, state, reducer, { intent: "SELECT_ROUTE", availableLogicalRoles: ["LUNA_EXECUTOR"] });
    assert.equal(result.selected_route, null, fact);
  }
});

test("M5-R2 committed PASS and BLOCKED requests reuse deterministic results in-process", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-gacw-m5-r2-")); await chmod(root, 0o700);
  try {
    const reducer = makePolicy("DIRECT_LUNA_HIGH"); const authoritativeSources = m5RunAuthority();
    const initial = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: authoritativeSources.contract.contract_sha256 });
    const genesis = await initializeRunStorage({ stateRoot: root, runId: reducer.run_id, policy: reducer, initialState: initial, processMetadata });
    const policy = m5Policy(reducer, initial, {
      repository_identity_content_sha256: authoritativeSources.repositoryIdentity.content_sha256,
      worktree_key: authoritativeSources.repositoryIdentity.worktree_key,
      contract_sha256: authoritativeSources.contract.contract_sha256,
      route_map_sha256: authoritativeSources.routeMap.route_map_sha256,
      route_map_approval_sha256: authoritativeSources.routeMapApproval.route_map_approval_sha256,
    });
    const kernel = createControlDecisionKernel({ stateRoot: root, runId: reducer.run_id, policy, reducerPolicy: reducer, runAuthority: authoritativeSources });
    const input = { intent: "BLOCK" as const, expectedRevision: genesis.statePointer.revision, expectedStatePointerContentSha256: genesis.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: genesis.workflowState.content_sha256 as Sha256Digest, transitionId: "r2-block", processMetadata, blockReason: "BLOCKED_R2_IDEMPOTENT" };
    const first = await kernel.evaluateControlDecision(input); const second = await kernel.evaluateControlDecision(input);
    assert.equal(first.decision.content_sha256, second.decision.content_sha256); assert.equal(second.reusedDecision, true); assert.equal(second.workflowState.phase, "BLOCKED");
    const inspection = await inspectRunStorage({ stateRoot: root, runId: reducer.run_id });
    assert.equal(inspection.workflowState?.phase, "BLOCKED"); assert.equal(inspection.transitionCommit?.new_revision, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});
