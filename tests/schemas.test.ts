import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { sha256Canonical, type DomainProjectionId } from "../src/identity/index.js";
import {
  CONCRETE_EXECUTION_MODES as internalConcreteExecutionModes,
  MAX_COMMAND_EXECUTABLE_BYTES,
  ENFORCEMENT_CLASSES as internalEnforcementClasses,
  EVENT_TYPES as internalEventTypes,
  EXECUTION_MODES as internalExecutionModes,
  LOGICAL_MODEL_ROLES as internalLogicalModelRoles,
  WORKFLOW_PHASES as internalWorkflowPhases,
  getInternalSchemaRegistry,
} from "../src/schemas/definitions.js";
import {
  SCHEMA_IDS,
  SCHEMA_VERSION,
  ContractValidationError,
  assertDocumentValid,
  assertReducerPolicy,
  assertSchema,
  assertTransitionEvent,
  assertWorkflowState,
  getSchemaSnapshot,
  identifyContractDocument,
  listSchemaSnapshots,
  validateSchema,
} from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import {
  budgetDocument,
  digest,
  domainDocument,
  makePolicy,
  objectiveDocument,
  ownerAcceptanceCriterion,
  planApprovalDocument,
  routeMapDocument,
  schemaIdByProjection,
  stateIdentities,
  taskGraphDocument,
  transitionEvent,
  type MutableJson,
} from "./helpers.js";

function expectCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => error instanceof ContractValidationError && error.code === code);
}

function reidentify(projectionId: DomainProjectionId, document: MutableJson): MutableJson {
  return identifyContractDocument(schemaIdByProjection[projectionId], document) as MutableJson;
}

function assertEveryObjectIsStrict(schema: unknown): void {
  if (schema === null || typeof schema !== "object") return;
  if (Array.isArray(schema)) {
    for (const item of schema) assertEveryObjectIsStrict(item);
    return;
  }
  const record = schema as Record<string, unknown>;
  if (record["type"] === "object") assert.equal(record["additionalProperties"], false);
  for (const value of Object.values(record)) assertEveryObjectIsStrict(value);
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

function commandCatalogDocument(executableSize: number): MutableJson {
  return {
    schema_id: "pi_gacw_command_catalog_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", content_sha256: digest(800),
    run_id: "command-catalog", catalog_id: "catalog", repository_identity_content_sha256: digest(801), tool_policy_content_sha256: digest(802),
    commands: [{
      command_id: "verify", command_spec_sha256: digest(803), command_class: "VERIFICATION", executable_invocation_path: "/usr/bin/node", executable_realpath: "/usr/bin/node",
      executable_device: 1, executable_inode: 1, executable_mode: 0o755, executable_size: executableSize, executable_sha256: digest(804), argv: ["/usr/bin/node"],
      cwd: "REPOSITORY_ROOT", cwd_realpath: "/repository", cwd_device: 1, cwd_inode: 2, execution_inputs: [], environment: [], read_paths: [], write_paths: [], network_policy: "FORBIDDEN",
      timeout_ms: 60_000, stdout_limit: 65_536, stderr_limit: 65_536, expected_exit_codes: [0], repository_side_effect: "NONE", claimed_paths: [], cleanup_paths: [],
    }],
  };
}

test("private canonical schema authority is deeply frozen", () => {
  const registry = getInternalSchemaRegistry();
  assertDeepFrozen(registry);
  for (const values of [
    internalExecutionModes,
    internalConcreteExecutionModes,
    internalLogicalModelRoles,
    internalEnforcementClasses,
    internalWorkflowPhases,
    internalEventTypes,
  ]) assertDeepFrozen(values);
  const objective = registry.find((entry) => entry.schemaId === "pi_gacw_objective_v0");
  assert.ok(objective);
  assert.equal(Reflect.set(objective.schema, "additionalProperties", true), false);
  assert.equal(Reflect.deleteProperty(objective.schema, "$id"), false);
});

test("safe schema inventory contains every required versioned contract through M6", () => {
  const required = [
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
  ];
  assert.deepEqual(SCHEMA_IDS, required);
  const snapshots = listSchemaSnapshots();
  assert.deepEqual(snapshots.map((entry) => entry.schemaId), required);
  assert.equal(new Set(SCHEMA_IDS).size, SCHEMA_IDS.length);
  assert.equal(SCHEMA_VERSION, "0.1.0");
  for (const entry of snapshots) assertEveryObjectIsStrict(entry.schema);
});

test("emitted schemas exactly match defensive snapshots derived from canonical authority", async () => {
  for (const entry of listSchemaSnapshots()) {
    const text = await readFile(new URL(`../schemas/${entry.fileName}`, import.meta.url), "utf8");
    assert.equal(text, `${JSON.stringify(entry.schema, null, 2)}\n`, entry.fileName);
  }
});

test("command-catalog executable file-size capacity admits current Node binaries but remains bounded", () => {
  assert.equal(MAX_COMMAND_EXECUTABLE_BYTES, 134_217_728);
  assertSchema("pi_gacw_command_catalog_v0", commandCatalogDocument(MAX_COMMAND_EXECUTABLE_BYTES));
  expectCode(() => assertSchema("pi_gacw_command_catalog_v0", commandCatalogDocument(MAX_COMMAND_EXECUTABLE_BYTES + 1)), "SCHEMA_INVALID");
});

test("schema snapshots expose the frozen execution, role, event, and phase values", () => {
  const objective = getSchemaSnapshot("pi_gacw_objective_v0") as MutableJson;
  const policy = getSchemaSnapshot("pi_gacw_reducer_policy_v0") as MutableJson;
  const routeMap = getSchemaSnapshot("pi_gacw_route_map_v0") as MutableJson;
  const event = getSchemaSnapshot("pi_gacw_transition_event_v0") as MutableJson;
  const state = getSchemaSnapshot("pi_gacw_state_v0") as MutableJson;
  assert.deepEqual(objective.properties.requested_mode.enum, ["AUTO", "DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG", "STATIC_APPROVED_DAG"]);
  assert.deepEqual(policy.properties.execution_mode.enum, ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG", "STATIC_APPROVED_DAG"]);
  assert.equal(routeMap.properties.routes.items.properties.logical_role.enum.includes("LUNA_EXECUTOR"), true);
  assert.equal(routeMap.properties.routes.items.properties.logical_role.enum.includes("TERRA_EXECUTOR"), true);
  assert.equal(routeMap.properties.routes.items.properties.logical_role.enum.includes("LUNA_MEDIUM"), false);
  const eventTypes = event.anyOf.map((variant: MutableJson) => variant.properties.event_type.const);
  assert.equal(new Set(eventTypes).size, eventTypes.length);
  assert.equal(new Set(state.properties.phase.enum).size, state.properties.phase.enum.length);
});

test("representative objective, route map, budget, graph, plan, state, policy, and event documents validate", () => {
  assertDocumentValid("pi_gacw_objective_v0", objectiveDocument());
  assertDocumentValid("pi_gacw_route_map_v0", routeMapDocument());
  assertDocumentValid("pi_gacw_budget_v0", budgetDocument());
  assertDocumentValid("pi_gacw_task_graph_v0", taskGraphDocument());
  assertDocumentValid("pi_gacw_plan_approval_v0", planApprovalDocument());

  const policy = makePolicy("DIRECT_LUNA_HIGH");
  assertReducerPolicy(policy);
  const state = createInitialState(policy, stateIdentities(policy));
  assertWorkflowState(state);
  assertTransitionEvent(transitionEvent("CAPTURE_BASELINE", { approval_required: false }));
});

test("M4 admission refusal schema fixes producer evidence identity and refusal semantics", () => {
  const value = identifyContractDocument("pi_gacw_m4_admission_refusal_v0", {
    schema_id: "pi_gacw_m4_admission_refusal_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: "m4-refusal", bounded_worker_invocation_content_sha256: digest(70), admission_state_token_content_sha256: digest(71),
    attempted_operation: { projection_id: "m4-admission-attempt-v0", tool_class: "APPLY_PATCH_SCOPED", operation: "REPLACE", target_path: "src/file.ts",
      expected_preimage: { exists: true, content_sha256: digest(73), byte_length: 1, mode: 0o644 }, replacement: { content_sha256: digest(74), byte_length: 2 },
      requested_final_mode: 0o644, ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE" },
    attempted_operation_content_sha256: sha256Canonical({ projection_id: "m4-admission-attempt-v0", tool_class: "APPLY_PATCH_SCOPED", operation: "REPLACE", target_path: "src/file.ts",
      expected_preimage: { exists: true, content_sha256: digest(73), byte_length: 1, mode: 0o644 }, replacement: { content_sha256: digest(74), byte_length: 2 },
      requested_final_mode: 0o644, ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE" }), disposition: "REFUSED", refusal_code: "M4_TOOL_BUDGET_EXHAUSTED",
  }) as MutableJson;
  assertDocumentValid("pi_gacw_m4_admission_refusal_v0", value);
  const schemaWrong = structuredClone(value) as MutableJson; schemaWrong.schema_id = "pi_gacw_bounded_worker_result_v0";
  expectCode(() => assertSchema("pi_gacw_m4_admission_refusal_v0", schemaWrong), "SCHEMA_INVALID");
  const versionWrong = structuredClone(value) as MutableJson; versionWrong.schema_version = "9.9.9";
  expectCode(() => assertSchema("pi_gacw_m4_admission_refusal_v0", versionWrong), "SCHEMA_INVALID");
  const dispositionWrong = structuredClone(value) as MutableJson; dispositionWrong.disposition = "ADMITTED";
  expectCode(() => assertSchema("pi_gacw_m4_admission_refusal_v0", dispositionWrong), "SCHEMA_INVALID");
  const codeWrong = structuredClone(value) as MutableJson; codeWrong.refusal_code = "UNKNOWN_REFUSAL";
  expectCode(() => assertSchema("pi_gacw_m4_admission_refusal_v0", codeWrong), "SCHEMA_INVALID");
  for (const field of ["bounded_worker_invocation_content_sha256", "admission_state_token_content_sha256", "attempted_operation_content_sha256"] as const) {
    const malformed = structuredClone(value) as MutableJson; malformed[field] = "sha256:broken";
    expectCode(() => assertSchema("pi_gacw_m4_admission_refusal_v0", malformed), "SCHEMA_INVALID");
  }
  const identityWrong = structuredClone(value) as MutableJson; identityWrong.refusal_code = "OUT_OF_SCOPE_WRITE";
  expectCode(() => assertDocumentValid("pi_gacw_m4_admission_refusal_v0", identityWrong), "IDENTITY_MISMATCH");
});

test("schemas reject unknown properties at top-level and nested object boundaries", () => {
  const topLevel = objectiveDocument();
  topLevel.unexpected = true;
  expectCode(() => assertSchema("pi_gacw_objective_v0", topLevel), "SCHEMA_INVALID");

  const nested = objectiveDocument();
  nested.scope.unexpected = true;
  expectCode(() => assertSchema("pi_gacw_objective_v0", nested), "SCHEMA_INVALID");
});

test("schemas reject missing identity/version markers and malformed or unknown digests/projections", async (t) => {
  const cases: readonly [string, (document: MutableJson) => void][] = [
    ["missing schema_id", (document) => { delete document.schema_id; }],
    ["missing schema_version", (document) => { delete document.schema_version; }],
    ["missing content projection", (document) => { delete document.content_projection_id; }],
    ["invalid digest", (document) => { document.content_sha256 = "sha256:ABC"; }],
    ["unknown projection ID", (document) => { document.objective_projection_id = "objective-freeze-v999"; }],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, () => {
      const invalid = structuredClone(objectiveDocument()) as MutableJson;
      mutate(invalid);
      expectCode(() => assertSchema("pi_gacw_objective_v0", invalid), "SCHEMA_INVALID");
    });
  }
});

test("required objective, mode, scope, acceptance, and verification fields cannot be omitted", async (t) => {
  const cases: readonly [string, (document: MutableJson) => void][] = [
    ["objective", (document) => { delete document.objective; }],
    ["execution mode", (document) => { delete document.requested_mode; }],
    ["scope", (document) => { delete document.scope; }],
    ["acceptance", (document) => { delete document.acceptance_criteria; }],
    ["verification commands", (document) => { document.verification_commands = []; }],
  ];
  for (const [label, mutate] of cases) {
    await t.test(label, () => {
      const invalid = structuredClone(objectiveDocument()) as MutableJson;
      mutate(invalid);
      expectCode(() => assertSchema("pi_gacw_objective_v0", invalid), "SCHEMA_INVALID");
    });
  }
});

test("repository-relative scope grammar rejects aliases, absolute paths, and root forms", async (t) => {
  const cases: readonly [string, string, string][] = [
    ["absolute", "/docs", "NONCANONICAL_REPOSITORY_PATH"],
    ["root dot", ".", "NONCANONICAL_REPOSITORY_PATH"],
    ["root dot-dot", "..", "NONCANONICAL_REPOSITORY_PATH"],
    ["dot segment", "src/.", "NONCANONICAL_REPOSITORY_PATH"],
    ["dot-dot segment", "src/..", "NONCANONICAL_REPOSITORY_PATH"],
    ["aliasing dot-dot", "src/../docs", "NONCANONICAL_REPOSITORY_PATH"],
    ["empty segment", "src//docs", "NONCANONICAL_REPOSITORY_PATH"],
    ["trailing slash", "src/docs/", "NONCANONICAL_REPOSITORY_PATH"],
    ["backslash", "src\\docs", "NONCANONICAL_REPOSITORY_PATH"],
    ["Windows absolute", "C:/docs", "NONCANONICAL_REPOSITORY_PATH"],
    ["empty", "", "SCHEMA_INVALID"],
    ["repository-root alias", "./", "NONCANONICAL_REPOSITORY_PATH"],
  ];
  for (const [label, path, code] of cases) {
    await t.test(label, () => {
      const invalid = objectiveDocument();
      invalid.scope.editable_paths = [path];
      expectCode(() => identifyContractDocument("pi_gacw_objective_v0", invalid), code);
    });
  }
});

test("scope overlap and write ownership operate only on validated canonical keys", () => {
  const overlappingScope = objectiveDocument();
  overlappingScope.scope.editable_paths = ["src"];
  overlappingScope.scope.frozen_paths = ["src/generated"];
  expectCode(
    () => identifyContractDocument("pi_gacw_objective_v0", overlappingScope),
    "OVERLAPPING_EDITABLE_AND_FROZEN_PATHS",
  );

  expectCode(() => taskGraphDocument(2, 8, true), "AMBIGUOUS_WRITE_OWNERSHIP");

  const aliasedGraph = taskGraphDocument();
  aliasedGraph.tasks[0].editable_paths = ["src/shared/../same"];
  aliasedGraph.tasks[1].editable_paths = ["src/same"];
  expectCode(
    () => identifyContractDocument("pi_gacw_task_graph_v0", aliasedGraph),
    "NONCANONICAL_REPOSITORY_PATH",
  );

  assertDocumentValid("pi_gacw_task_graph_v0", taskGraphDocument());
});

test("attempt, replan, and invocation limits are schema-bounded", async (t) => {
  const cases: readonly [string, string, number][] = [
    ["attempt", "max_attempts_per_leaf", 3],
    ["replan", "max_replans", 3],
    ["invocation", "max_worker_invocations", 21],
  ];
  for (const [label, field, value] of cases) {
    await t.test(label, () => {
      const invalid = planApprovalDocument();
      invalid.bindings.limits[field] = value;
      expectCode(() => assertSchema("pi_gacw_plan_approval_v0", invalid), "SCHEMA_INVALID");
    });
  }
});

test("LUNA_MEDIUM is rejected everywhere a route or execution profile can be typed", () => {
  const invalidRole = routeMapDocument();
  invalidRole.routes[0].logical_role = "LUNA_MEDIUM";
  expectCode(() => assertSchema("pi_gacw_route_map_v0", invalidRole), "SCHEMA_INVALID");

  const invalidEffort = routeMapDocument();
  invalidEffort.routes[0].effort = "medium";
  expectCode(() => assertSchema("pi_gacw_route_map_v0", invalidEffort), "SCHEMA_INVALID");

  const xhighTerra = routeMapDocument();
  xhighTerra.routes.find((candidate: MutableJson) => candidate.logical_role === "TERRA_EXECUTOR").effort = "xhigh";
  assertSchema("pi_gacw_route_map_v0", xhighTerra);
  assertDocumentValid("pi_gacw_route_map_v0", routeMapDocument());

  const invalidModel = routeMapDocument();
  invalidModel.routes[0].model_id = "LUNA_MEDIUM";
  expectCode(() => identifyContractDocument("pi_gacw_route_map_v0", invalidModel), "FORBIDDEN_LUNA_MEDIUM");

  const invalidPolicy = structuredClone(makePolicy("DIRECT_LUNA_HIGH")) as MutableJson;
  invalidPolicy.execution_mode = "LUNA_MEDIUM";
  expectCode(() => assertSchema("pi_gacw_reducer_policy_v0", invalidPolicy), "SCHEMA_INVALID");
});

test("UNAVAILABLE provider_request usage is null and can never masquerade as zero", () => {
  const valid = budgetDocument();
  assert.deepEqual(valid.usage.provider_request, { value: null, enforcement_class: "UNAVAILABLE" });

  const invalid = budgetDocument();
  invalid.usage.provider_request = { value: 0, enforcement_class: "UNAVAILABLE" };
  expectCode(() => identifyContractDocument("pi_gacw_budget_v0", invalid), "SCHEMA_INVALID");
});

test("declared set-like baseline and authority arrays reject exact, path, and alias duplicates", async (t) => {
  const baselineFile = {
    path: "src/a.ts",
    content_sha256: digest(701),
    ownership_class: "OWNER_ACCEPTED_MUTABLE",
    data_class: "PUBLIC_SOURCE",
  };
  const authority = domainDocument("authority-lock-v1").authorities[0];
  const cases: readonly [string, () => unknown, string][] = [
    ["exact baseline entry", () => {
      const value = domainDocument("baseline-snapshot-v1");
      value.files = [baselineFile, structuredClone(baselineFile)];
      return identifyContractDocument("pi_gacw_baseline_v0", value);
    }, "SCHEMA_INVALID"],
    ["duplicate baseline path", () => {
      const value = domainDocument("baseline-snapshot-v1");
      value.files = [baselineFile, { ...baselineFile, content_sha256: digest(702) }];
      return identifyContractDocument("pi_gacw_baseline_v0", value);
    }, "DUPLICATE_BASELINE_PATH"],
    ["exact authority entry", () => {
      const value = domainDocument("authority-lock-v1");
      value.authorities = [authority, structuredClone(authority)];
      return identifyContractDocument("pi_gacw_authority_lock_v0", value);
    }, "SCHEMA_INVALID"],
    ["duplicate authority path", () => {
      const value = domainDocument("authority-lock-v1");
      value.authorities = [authority, { ...authority, role: "SCHEMA", content_sha256: digest(703) }];
      return identifyContractDocument("pi_gacw_authority_lock_v0", value);
    }, "DUPLICATE_AUTHORITY_PATH"],
    ["normalization-equivalent path alias", () => {
      const value = domainDocument("baseline-snapshot-v1");
      value.files = [baselineFile, { ...baselineFile, path: "src/./a.ts", content_sha256: digest(704) }];
      return identifyContractDocument("pi_gacw_baseline_v0", value);
    }, "NONCANONICAL_REPOSITORY_PATH"],
  ];
  for (const [label, action, code] of cases) {
    await t.test(label, () => expectCode(action, code));
  }

  const valid = domainDocument("baseline-snapshot-v1");
  valid.files = [baselineFile, { ...baselineFile, path: "src/b.ts", content_sha256: digest(705) }];
  assertDocumentValid("pi_gacw_baseline_v0", identifyContractDocument("pi_gacw_baseline_v0", valid));
});

test("declared owner acceptance is valid only in SINGLE_OWNER_SOL mode", () => {
  const directPlan = planApprovalDocument("DIRECT_LUNA_HIGH", 1);
  directPlan.bindings.owner_acceptance_criteria = [ownerAcceptanceCriterion];
  expectCode(
    () => reidentify("plan-approval-v1", directPlan),
    "OWNER_ACCEPTANCE_MODE_MISMATCH",
  );

  expectCode(
    () => makePolicy("DIRECT_LUNA_HIGH", { ownerAcceptanceRequired: true }),
    "OWNER_ACCEPTANCE_MODE_MISMATCH",
  );
  assertReducerPolicy(makePolicy("SINGLE_OWNER_SOL", { ownerAcceptanceRequired: true }));
});

test("invalid terminal state and cross-mode state combinations are rejected before identity construction", () => {
  const directPolicy = makePolicy("DIRECT_LUNA_HIGH");
  const initial = createInitialState(directPolicy, stateIdentities(directPolicy));
  expectCode(
    () => identifyContractDocument("pi_gacw_state_v0", { ...initial, phase: "PASS", terminal_reason: null }),
    "INVALID_TERMINAL_STATE",
  );
  expectCode(
    () => identifyContractDocument("pi_gacw_state_v0", { ...initial, phase: "PASS", terminal_reason: "PASS" }),
    "INVALID_TERMINAL_STATE",
  );
  expectCode(
    () => identifyContractDocument("pi_gacw_state_v0", { ...initial, phase: "PLAN_RUNNING" }),
    "CROSS_MODE_STATE",
  );
});

test("invalid event payloads are rejected before identity construction", () => {
  expectCode(() => identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    event_id: "event-invalid",
    event_type: "CAPTURE_BASELINE",
    payload: {},
  }), "SCHEMA_INVALID");

  expectCode(() => identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    event_id: "event-extra",
    event_type: "FREEZE_OBJECTIVE",
    payload: { model_text: "choose a transition" },
  }), "SCHEMA_INVALID");
});

test("configured leaf cap, routed minimum, one-task modes, cycles, and duplicate routes fail closed", () => {
  expectCode(() => taskGraphDocument(3, 2), "TASK_GRAPH_ABOVE_LEAF_CAP");
  expectCode(() => planApprovalDocument("ROUTED_DAG", 1), "ROUTED_DAG_TOO_SMALL");
  expectCode(() => planApprovalDocument("DIRECT_LUNA_HIGH", 2), "ONE_TASK_REQUIRED");

  const cyclic = taskGraphDocument();
  cyclic.tasks[0].dependencies = ["task-1"];
  cyclic.edges.push({ from: "task-1", to: "task-1" });
  expectCode(() => reidentify("task-graph-freeze-v1", cyclic), "CYCLIC_DEPENDENCY");

  const duplicateRoute = routeMapDocument();
  duplicateRoute.routes[1].logical_role = duplicateRoute.routes[0].logical_role;
  expectCode(() => reidentify("route-map-v1", duplicateRoute), "DUPLICATE_LOGICAL_ROUTE");
});

test("route effort, verification-only closeout, owner-acceptance placement, and identity integrity are semantic guards", () => {
  const invalidEffort = routeMapDocument();
  const luna = invalidEffort.routes.find((candidate: MutableJson) => candidate.logical_role === "LUNA_EXECUTOR");
  luna.effort = "max";
  expectCode(() => reidentify("route-map-v1", invalidEffort), "INVALID_LUNA_EFFORT");

  const xhighTerra = routeMapDocument();
  xhighTerra.routes.find((candidate: MutableJson) => candidate.logical_role === "TERRA_EXECUTOR").effort = "xhigh";
  reidentify("route-map-v1", xhighTerra);

  const invalidCloseout = routeMapDocument();
  const closeout = invalidCloseout.routes.find((candidate: MutableJson) => candidate.logical_role === "SOL_CLOSEOUT");
  closeout.tool_policy.mutation_tool = "APPLY_PATCH_SCOPED";
  expectCode(() => reidentify("route-map-v1", invalidCloseout), "CLOSEOUT_NOT_VERIFICATION_ONLY");

  const undeclaredOwner = objectiveDocument();
  undeclaredOwner.acceptance_criteria[0].owner_acceptance = true;
  undeclaredOwner.acceptance_criteria[0].evidence_kind = "OWNER_ACCEPTANCE";
  expectCode(() => reidentify("objective-freeze-v1", undeclaredOwner), "OWNER_ACCEPTANCE_NOT_DECLARED");

  const tampered = objectiveDocument();
  tampered.objective = "tampered after hashing";
  expectCode(() => assertDocumentValid("pi_gacw_objective_v0", tampered), "IDENTITY_MISMATCH");
});

test("schema API rejects unknown schema IDs rather than selecting a fallback", () => {
  assert.throws(
    () => validateSchema("pi_gacw_unknown_v0" as Parameters<typeof validateSchema>[0], {}),
    (error: unknown) => error instanceof ContractValidationError && error.code === "UNKNOWN_SCHEMA",
  );
});
