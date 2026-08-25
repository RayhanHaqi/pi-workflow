import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import type { ReducerPolicy, WorkflowState } from "../src/schemas/index.js";
import {
  advanceCommon,
  applyEvent,
  makePolicy,
  objectiveDocument,
  stateIdentities,
  transitionEvent,
  type MutableJson,
} from "./helpers.js";

const SCHEMAS_PACKAGE: string = "pi-bounded-coding-workflow/schemas";
const STATE_MACHINE_PACKAGE: string = "pi-bounded-coding-workflow/state-machine";

function hasCode(error: unknown, code: string): boolean {
  return error !== null && typeof error === "object" && "code" in error && (error as { readonly code: unknown }).code === code;
}

function expectCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => hasCode(error, code));
}

function assertDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && "value" in descriptor) assertDeepFrozen(descriptor.value, seen);
  }
}

function expectSetRejected(target: object, property: PropertyKey, value: unknown): void {
  assert.equal(Reflect.set(target, property, value), false);
}

function expectDeleteRejected(target: object, property: PropertyKey): void {
  assert.equal(Reflect.deleteProperty(target, property), false);
}

function routedReady(policy: ReducerPolicy): WorkflowState {
  let state = advanceCommon(policy);
  state = applyEvent(state, policy, "START_PLAN");
  state = applyEvent(state, policy, "COMPLETE_PLAN");
  state = applyEvent(state, policy, "REQUEST_PLAN_APPROVAL");
  state = applyEvent(state, policy, "APPROVE_PLAN", {
    plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
  });
  return applyEvent(state, policy, "ACTIVATE_DAG");
}

const canonicalSchemaIds = [
  "pi_gacw_objective_v0",
  "pi_gacw_owner_decisions_v0",
  "pi_gacw_route_map_v0",
  "pi_gacw_route_map_approval_v0",
  "pi_gacw_baseline_v0",
  "pi_gacw_baseline_approval_v0",
  "pi_gacw_authority_lock_v0",
  "pi_gacw_contract_v0",
  "pi_gacw_routing_v0",
  "pi_gacw_budget_v0",
  "pi_gacw_task_v0",
  "pi_gacw_task_graph_v0",
  "pi_gacw_plan_approval_v0",
  "pi_gacw_state_v0",
  "pi_gacw_transition_event_v0",
  "pi_gacw_transition_commit_v0",
  "pi_gacw_final_report_v0",
  "pi_gacw_reducer_policy_v0",
  "pi_gacw_evidence_metadata_v0",
  "pi_gacw_evidence_manifest_v0",
  "pi_gacw_persisted_state_pointer_v0",
  "pi_gacw_process_interruption_v0",
  "pi_gacw_state_transition_commit_v0",
  "pi_gacw_repository_identity_v0",
  "pi_gacw_git_state_fingerprint_v0",
  "pi_gacw_baseline_runtime_v0",
  "pi_gacw_baseline_approval_runtime_v0",
  "pi_gacw_lock_acquisition_v0",
  "pi_gacw_lock_diagnostic_v0",
  "pi_gacw_preflight_v0",
  "pi_gacw_repository_state_token_v0",
  "pi_gacw_postflight_v0",
  "pi_gacw_resume_lock_handover_v0",
  "pi_gacw_terminal_retention_authority_v0",
  "pi_gacw_retention_result_v0",
  "pi_gacw_secure_fs_capability_v0",
  "pi_gacw_sandbox_capability_v0",
  "pi_gacw_scoped_tool_policy_v0",
  "pi_gacw_command_catalog_v0",
  "pi_gacw_tool_request_v0",
  "pi_gacw_patch_request_v0",
  "pi_gacw_mutation_receipt_v0",
  "pi_gacw_tool_result_v0",
  "pi_gacw_command_result_v0",
  "pi_gacw_m4_admission_refusal_v0",
  "pi_gacw_m5_control_policy_v0",
  "pi_gacw_m5_usage_evidence_v0",
  "pi_gacw_m5_control_decision_v0",
  "pi_gacw_m6_worker_invocation_v0",
  "pi_gacw_m6_worker_result_v0",
  "pi_gacw_bounded_worker_invocation_v0",
  "pi_gacw_bounded_worker_result_v0",
] as const;

const removedRuntimeSchemaExports = [
  "AcceptanceCriterionSchema",
  "AuthorityLockSchema",
  "BaselineApprovalSchema",
  "BaselineFileSchema",
  "BaselineSchema",
  "BudgetSchema",
  "CommandPolicySchema",
  "CommandResultSchema",
  "ConcreteExecutionModeSchema",
  "ContractSchema",
  "EdgeSchema",
  "EvidenceManifestEntrySchema",
  "EvidenceManifestSchema",
  "EvidenceMetadataSchema",
  "ExecutionModeSchema",
  "FinalReportSchema",
  "LimitEnvelopeSchema",
  "LogicalModelRoleSchema",
  "ObjectiveSchema",
  "OwnerDecisionsSchema",
  "PlanApprovalSchema",
  "PersistedStatePointerSchema",
  "PlanBindingsSchema",
  "ProcessInterruptionObjectSchema",
  "ProcessInterruptionSchema",
  "ProcessMetadataSchema",
  "ProgressDeltaSchema",
  "ProjectionIdSchema",
  "ReducerPolicySchema",
  "ReducerTaskPolicySchema",
  "RepositoryIdentitySchema",
  "RouteMapApprovalSchema",
  "RouteMapSchema",
  "RouteSchema",
  "RoutingSchema",
  "ScopeSchema",
  "StateCountersSchema",
  "StateGateStatusSchema",
  "StateIdentitiesSchema",
  "StateTransitionCommitSchema",
  "TaskGraphNodeSchema",
  "TaskGraphSchema",
  "TaskRuntimeStatusSchema",
  "TaskSchema",
  "ToolPolicySchema",
  "TransitionCommitSchema",
  "TransitionEventSchema",
  "UsageDimensionsSchema",
  "UsageMeasurementSchema",
  "VerificationCommandSchema",
  "WorkerInvocationCountersSchema",
  "WorkflowPhaseSchema",
  "WorkflowStateSchema",
  "M3RepositoryIdentitySchema",
  "M3GitStateFingerprintSchema",
  "M3BaselineRuntimeSchema",
  "M3BaselineApprovalRuntimeSchema",
  "M3LockDiagnosticSchema",
  "M3PreflightSchema",
  "M3RepositoryStateTokenSchema",
  "M3PostflightSchema",
  "M3TerminalRetentionAuthoritySchema",
  "M3RetentionResultSchema",
  "M4SecureFilesystemCapabilitySchema",
  "M4SandboxCapabilitySchema",
  "M4ScopedToolPolicySchema",
  "M4CommandCatalogSchema",
  "M4ToolRequestSchema",
  "M4PatchRequestSchema",
  "M4MutationReceiptSchema",
  "M4ToolResultSchema",
  "M4CommandResultSchema",
  "M5ControlPolicySchema",
  "M5UsageEvidenceSchema",
  "M5ControlDecisionSchema",
  "M5_BUDGET_DIMENSIONS",
  "M5_OPERATION_KINDS",
  "M5_PROGRESS_KINDS",
  "M5_NO_PROGRESS_REASONS",
  "M5_FAILURE_CLASSES",
  "M5_CONTINUATION_ROUTES",
  "M5_GATE_CODES",
  "SCHEMA_INVENTORY",
  "EXECUTION_MODES",
  "CONCRETE_EXECUTION_MODES",
  "LOGICAL_MODEL_ROLES",
  "EVENT_TYPES",
  "WORKFLOW_PHASES",
  "ENFORCEMENT_CLASSES",
] as const;

test("public-schema-reference-isolation exposes only safe built-package operations", async (t) => {
  const schemas = await import(SCHEMAS_PACKAGE);
  const expectedRuntimeExports = [
    "ContractValidationError",
    "SCHEMA_IDS",
    "SCHEMA_VERSION",
    "assertAuthorityLockSemantics",
    "assertBaselineSemantics",
    "assertDocumentValid",
    "assertPlanApprovalSemantics",
    "assertReducerPolicy",
    "assertReducerPolicySemantics",
    "assertRouteMapSemantics",
    "assertSchema",
    "assertStatePolicyConsistency",
    "assertTaskGraphSemantics",
    "assertTaskSemantics",
    "assertTransitionEvent",
    "assertWorkflowState",
    "assertWorkflowStateSemantics",
    "getSchemaSnapshot",
    "identifyContractDocument",
    "listSchemaSnapshots",
    "validateSchema",
    "verifyContractDocument",
  ].sort();

  await t.test("runtime export inventory", () => {
    assert.deepEqual(Object.keys(schemas).sort(), expectedRuntimeExports);
    assert.deepEqual(schemas.SCHEMA_IDS, canonicalSchemaIds);
    assertDeepFrozen(schemas.SCHEMA_IDS);
    for (const name of removedRuntimeSchemaExports) assert.equal(name in schemas, false, name);
    assert.equal("getInternalSchemaRegistry" in schemas, false);
  });

  for (const subpath of [
    "pi-bounded-coding-workflow/schemas/definitions",
    "pi-bounded-coding-workflow/schemas/validator",
    "pi-bounded-coding-workflow/schemas/emit",
    "pi-bounded-coding-workflow/src/schemas/definitions",
    "pi-bounded-coding-workflow/dist/src/schemas/definitions.js",
    "pi-bounded-coding-workflow/package.json",
    "pi-bounded-coding-workflow",
  ]) {
    await t.test(`blocked internal subpath ${subpath}`, async () => {
      await assert.rejects(import(subpath), (error: unknown) => hasCode(error, "ERR_PACKAGE_PATH_NOT_EXPORTED"));
    });
  }
});

test("schema-authority-consistency snapshots are detached and deeply frozen", async (t) => {
  const schemas = await import(SCHEMAS_PACKAGE);
  const objective = schemas.getSchemaSnapshot("pi_gacw_objective_v0") as MutableJson;
  const objectiveAgain = schemas.getSchemaSnapshot("pi_gacw_objective_v0") as MutableJson;
  const state = schemas.getSchemaSnapshot("pi_gacw_state_v0") as MutableJson;
  const policy = schemas.getSchemaSnapshot("pi_gacw_reducer_policy_v0") as MutableJson;
  const routeMap = schemas.getSchemaSnapshot("pi_gacw_route_map_v0") as MutableJson;
  const event = schemas.getSchemaSnapshot("pi_gacw_transition_event_v0") as MutableJson;
  const budget = schemas.getSchemaSnapshot("pi_gacw_budget_v0") as MutableJson;
  const list = schemas.listSchemaSnapshots() as MutableJson;
  const listAgain = schemas.listSchemaSnapshots() as MutableJson;

  await t.test("independent snapshot allocation", () => {
    assert.notStrictEqual(objective, objectiveAgain);
    assert.notStrictEqual(objective.properties, objectiveAgain.properties);
    assert.notStrictEqual(objective.required, objectiveAgain.required);
    assert.notStrictEqual(list, listAgain);
    for (let index = 0; index < list.length; index += 1) {
      assert.notStrictEqual(list[index], listAgain[index]);
      assert.notStrictEqual(list[index].schema, listAgain[index].schema);
    }
  });

  await t.test("deep runtime immutability", () => {
    for (const value of [objective, objectiveAgain, state, policy, routeMap, event, budget, list, listAgain]) {
      assertDeepFrozen(value);
    }
  });

  const checks: readonly [string, () => void][] = [
    ["root property addition", () => expectSetRejected(objective.properties, "probe_field", { type: "string" })],
    ["root property replacement", () => expectSetRejected(objective.properties, "objective", { type: "number" })],
    ["root property deletion", () => expectDeleteRejected(objective.properties, "objective")],
    ["properties object replacement", () => expectSetRejected(objective, "properties", {})],
    ["additionalProperties change", () => expectSetRejected(objective, "additionalProperties", true)],
    ["required array push", () => assert.throws(() => objective.required.push("probe_field"), TypeError)],
    ["required array pop", () => assert.throws(() => objective.required.pop(), TypeError)],
    ["required array splice", () => assert.throws(() => objective.required.splice(0, 1), TypeError)],
    ["execution-mode enum push", () => assert.throws(() => objective.properties.requested_mode.enum.push("LOCAL_MODE"), TypeError)],
    ["execution-mode enum pop", () => assert.throws(() => objective.properties.requested_mode.enum.pop(), TypeError)],
    ["execution-mode enum splice", () => assert.throws(() => objective.properties.requested_mode.enum.splice(0, 1), TypeError)],
    ["nested property change", () => expectSetRejected(objective.properties.scope.properties.editable_paths, "uniqueItems", false)],
    ["items change", () => expectSetRejected(objective.properties.required_outputs, "items", { type: "number" })],
    ["anyOf array change", () => assert.throws(() => event.anyOf.push({}), TypeError)],
    ["oneOf insertion", () => expectSetRejected(objective, "oneOf", [])],
    ["allOf insertion", () => expectSetRejected(objective, "allOf", [])],
    ["schema ID change", () => expectSetRejected(objective, "$id", "https://local.invalid/changed")],
    ["schema version change", () => expectSetRejected(objective.properties.schema_version, "const", "9.9.9")],
    ["uniqueItems change", () => expectSetRejected(objective.properties.scope.properties.readable_paths, "uniqueItems", false)],
    ["minimum change", () => expectSetRejected(objective.properties.configured_max_leaves, "minimum", 0)],
    ["maximum change", () => expectSetRejected(objective.properties.configured_max_leaves, "maximum", 99)],
    ["pattern change", () => expectSetRejected(objective.properties.primary_failure_domain, "pattern", ".*")],
    ["format insertion", () => expectSetRejected(objective.properties.objective, "format", "email")],
    ["inventory entry replacement", () => expectSetRejected(list, 0, {})],
    ["inventory entry schema replacement", () => expectSetRejected(list[0], "schema", {})],
    ["inventory entry deletion", () => expectDeleteRejected(list, 0)],
    ["inventory insertion", () => assert.throws(() => list.push({}), TypeError)],
    ["inventory pop", () => assert.throws(() => list.pop(), TypeError)],
    ["inventory splice", () => assert.throws(() => list.splice(0, 1), TypeError)],
    ["logical-role enum change", () => assert.throws(() => routeMap.properties.routes.items.properties.logical_role.enum.push("LOCAL_ROLE"), TypeError)],
    ["event-type literal change", () => expectSetRejected(event.anyOf[0].properties.event_type, "const", "LOCAL_EVENT")],
    ["workflow-phase enum change", () => assert.throws(() => state.properties.phase.enum.pop(), TypeError)],
    ["enforcement-class value change", () => expectSetRejected(budget.properties.usage.properties.worker_invocation.anyOf[0].properties.enforcement_class, "const", "LOCAL_CLASS")],
    ["policy concrete-mode enum change", () => assert.throws(() => policy.properties.execution_mode.enum.splice(0, 1), TypeError)],
    ["second independent snapshot change", () => expectSetRejected(objectiveAgain.properties, "probe_field", { type: "string" })],
    ["second list result change", () => expectSetRejected(listAgain[0].schema, "additionalProperties", true)],
    ["cached nested snapshot change", () => {
      const cached = objective.properties.scope.properties.editable_paths;
      expectSetRejected(cached, "items", { type: "number" });
    }],
  ];

  for (const [name, check] of checks) await t.test(name, check);

  await t.test("unknown schema ID is deterministic", () => {
    expectCode(() => schemas.getSchemaSnapshot("pi_gacw_unknown_v0"), "UNKNOWN_SCHEMA");
  });
});

test("state-validation-consistency remains stable after public snapshot modification attempts", async (t) => {
  const schemas = await import(SCHEMAS_PACKAGE);
  const stateMachine = await import(STATE_MACHINE_PACKAGE);
  const validObjective = objectiveDocument();
  const validObjectiveAgain = schemas.identifyContractDocument("pi_gacw_objective_v0", validObjective);

  // Repeat a representative modification through the built public entrypoint in
  // this process before exercising every admission boundary.
  const snapshot = schemas.getSchemaSnapshot("pi_gacw_objective_v0") as MutableJson;
  expectSetRejected(snapshot.properties, "probe_field", { type: "string" });

  const objectiveCases: readonly [string, MutableJson][] = [
    ["unknown-root-field", { ...structuredClone(validObjective), probe_field: 42 }],
    ["root-field-type-mismatch", { ...structuredClone(validObjective), objective: 42 }],
    ["nested-extra-field", (() => {
      const value = structuredClone(validObjective) as MutableJson;
      value.scope.probe_field = 42;
      return value;
    })()],
  ];
  for (const [name, value] of objectiveCases) {
    await t.test(name, () => {
      assert.equal(schemas.validateSchema("pi_gacw_objective_v0", value).valid, false);
      expectCode(() => schemas.assertSchema("pi_gacw_objective_v0", value), "SCHEMA_INVALID");
      expectCode(() => schemas.assertDocumentValid("pi_gacw_objective_v0", value), "SCHEMA_INVALID");
      expectCode(() => schemas.identifyContractDocument("pi_gacw_objective_v0", value), "SCHEMA_INVALID");
      assert.equal(schemas.verifyContractDocument("pi_gacw_objective_v0", value), false);
    });
  }

  await t.test("valid objective identity remains byte-stable", () => {
    const after = schemas.identifyContractDocument("pi_gacw_objective_v0", validObjective);
    assert.deepEqual(after, validObjectiveAgain);
    assert.equal(schemas.verifyContractDocument("pi_gacw_objective_v0", after), true);
  });

  const policy = makePolicy("ROUTED_DAG");
  const ready = routedReady(policy);
  const selectionEvent = transitionEvent("SELECT_READY_LEAF");
  const policyWithExtra = { ...structuredClone(policy), probe_field: 42 };
  const stateWithExtra = { ...structuredClone(ready), probe_field: 42 };

  await t.test("policy-validation-consistency", () => {
    assert.equal(schemas.validateSchema("pi_gacw_reducer_policy_v0", policyWithExtra).valid, false);
    expectCode(() => schemas.assertReducerPolicy(policyWithExtra), "SCHEMA_INVALID");
    expectCode(() => schemas.identifyContractDocument("pi_gacw_reducer_policy_v0", policyWithExtra), "SCHEMA_INVALID");
    assert.equal(schemas.verifyContractDocument("pi_gacw_reducer_policy_v0", policyWithExtra), false);
    expectCode(() => stateMachine.createInitialState(policyWithExtra, stateIdentities(policy)), "SCHEMA_INVALID");
    expectCode(() => stateMachine.reduceState(ready, selectionEvent, policyWithExtra), "SCHEMA_INVALID");
  });

  await t.test("workflow-state validation consistency", () => {
    assert.equal(schemas.validateSchema("pi_gacw_state_v0", stateWithExtra).valid, false);
    expectCode(() => schemas.assertWorkflowState(stateWithExtra), "SCHEMA_INVALID");
    expectCode(() => schemas.identifyContractDocument("pi_gacw_state_v0", stateWithExtra), "SCHEMA_INVALID");
    assert.equal(schemas.verifyContractDocument("pi_gacw_state_v0", stateWithExtra), false);
    expectCode(() => stateMachine.reduceState(stateWithExtra, selectionEvent, policy), "SCHEMA_INVALID");
  });

  await t.test("valid state-machine admission remains unchanged", () => {
    schemas.assertReducerPolicy(policy);
    schemas.assertWorkflowState(ready);
    assert.equal(stateMachine.createInitialState(policy, stateIdentities(policy)).phase, "CREATED");
    const selected = stateMachine.reduceState(ready, selectionEvent, policy);
    assert.equal(selected.active_task_id, "task-a");
    assert.equal("probe_field" in selected, false);
  });
});

test("schema-authority-consistency is identical in two fresh processes", () => {
  const validObjective = objectiveDocument();
  const objectiveWithExtra = { ...structuredClone(validObjective), probe_field: 42 };
  const script = `
    import * as schemas from "pi-bounded-coding-workflow/schemas";
    const valid = JSON.parse(process.env.M1_R3_VALID_OBJECTIVE);
    const invalid = JSON.parse(process.env.M1_R3_INVALID_OBJECTIVE);
    const snapshot = schemas.getSchemaSnapshot("pi_gacw_objective_v0");
    const modificationResult = Reflect.set(snapshot.properties, "probe_field", { type: "string" });
    const identified = schemas.identifyContractDocument("pi_gacw_objective_v0", valid);
    console.log(JSON.stringify({
      exports: Object.keys(schemas).sort(),
      snapshotFrozen: Object.isFrozen(snapshot) && Object.isFrozen(snapshot.properties),
      modificationResult,
      invalidStructuralResult: schemas.validateSchema("pi_gacw_objective_v0", invalid),
      invalidVerified: schemas.verifyContractDocument("pi_gacw_objective_v0", invalid),
      content_sha256: identified.content_sha256,
      objective_sha256: identified.objective_sha256,
      validVerified: schemas.verifyContractDocument("pi_gacw_objective_v0", identified),
    }));
  `;
  const run = (): string => {
    const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        M1_R3_VALID_OBJECTIVE: JSON.stringify(validObjective),
        M1_R3_INVALID_OBJECTIVE: JSON.stringify(objectiveWithExtra),
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    return result.stdout;
  };
  const secondProcess = run();
  const thirdProcess = run();
  assert.equal(secondProcess, thirdProcess);
  const evidence = JSON.parse(secondProcess) as MutableJson;
  assert.equal(evidence.snapshotFrozen, true);
  assert.equal(evidence.modificationResult, false);
  assert.equal(evidence.invalidStructuralResult.valid, false);
  assert.equal(evidence.invalidVerified, false);
  assert.equal(evidence.validVerified, true);
});
