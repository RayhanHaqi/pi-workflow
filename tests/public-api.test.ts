import assert from "node:assert/strict";
import test from "node:test";

import {
  type ReducerPolicy,
  type WorkflowState,
} from "../src/schemas/index.js";
import {
  advanceCommon,
  applyEvent,
  digest,
  makePolicy,
  objectiveDocument,
  transitionEvent,
  type MutableJson,
  type TestPolicyTask,
} from "./helpers.js";

const STATE_MACHINE_PACKAGE: string = "pi-bounded-coding-workflow/state-machine";
const STATE_MACHINE_PRIVATE_SUBPATH: string = "pi-bounded-coding-workflow/state-machine/reducer";
const IDENTITY_PACKAGE: string = "pi-bounded-coding-workflow/identity";
const IDENTITY_PRIVATE_SUBPATH: string = "pi-bounded-coding-workflow/identity/projections";
const SCHEMAS_PACKAGE: string = "pi-bounded-coding-workflow/schemas";

function hasCode(error: unknown, code: string): boolean {
  return error !== null && typeof error === "object" && "code" in error && (error as { readonly code: unknown }).code === code;
}

function expectCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => hasCode(error, code));
}

function routedDagFrozen(policy: ReducerPolicy): WorkflowState {
  let state = advanceCommon(policy);
  state = applyEvent(state, policy, "START_PLAN");
  state = applyEvent(state, policy, "COMPLETE_PLAN");
  state = applyEvent(state, policy, "REQUEST_PLAN_APPROVAL");
  return applyEvent(state, policy, "APPROVE_PLAN", {
    plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
  });
}

function routedReady(policy: ReducerPolicy): WorkflowState {
  return applyEvent(routedDagFrozen(policy), policy, "ACTIVATE_DAG");
}

function assertDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const nested of Object.values(value)) assertDeepFrozen(nested, seen);
}

test("built state-machine API has no unchecked ready-leaf boundary", async (t) => {
  const stateMachine = await import(STATE_MACHINE_PACKAGE);
  const schemas = await import(SCHEMAS_PACKAGE);
  const selectionEvent = transitionEvent("SELECT_READY_LEAF");
  const policy = makePolicy("ROUTED_DAG");
  const ready = routedReady(policy);

  await t.test("public surface and private subpath", async () => {
    assert.deepEqual(Object.keys(stateMachine).sort(), ["TransitionError", "createInitialState", "reduceState"]);
    assert.equal("selectReadyLeaf" in stateMachine, false);
    await assert.rejects(
      import(STATE_MACHINE_PRIVATE_SUBPATH),
      (error: unknown) => hasCode(error, "ERR_PACKAGE_PATH_NOT_EXPORTED"),
    );
  });

  await t.test("formerly rogue malformed state", () => {
    expectCode(
      () => stateMachine.reduceState(
        { tasks: [{ task_id: "rogue", status: "PENDING" }] },
        selectionEvent,
        { tasks: [{ task_id: "rogue", topological_rank: 0, priority: 0, dependencies: [] }] },
      ),
      "SCHEMA_INVALID",
    );
  });

  await t.test("structurally invalid policy", () => {
    expectCode(() => stateMachine.reduceState(ready, selectionEvent, { tasks: [] }), "SCHEMA_INVALID");
  });

  await t.test("semantically invalid state", () => {
    expectCode(
      () => stateMachine.reduceState({ ...ready, phase: "PASS", terminal_reason: null }, selectionEvent, policy),
      "INVALID_TERMINAL_STATE",
    );
  });

  await t.test("semantically invalid policy", () => {
    const invalid = { ...structuredClone(policy), owner_acceptance_required: true };
    expectCode(() => stateMachine.reduceState(ready, selectionEvent, invalid), "OWNER_ACCEPTANCE_MODE_MISMATCH");
  });

  await t.test("incorrect policy content digest", () => {
    const invalid = { ...policy, content_sha256: digest(1_001) };
    expectCode(() => stateMachine.reduceState(ready, selectionEvent, invalid), "IDENTITY_MISMATCH");
  });

  await t.test("wrong execution mode", () => {
    expectCode(
      () => stateMachine.reduceState(ready, selectionEvent, makePolicy("DIRECT_LUNA_HIGH")),
      "POLICY_STATE_MISMATCH",
    );
  });

  await t.test("wrong workflow phase", () => {
    expectCode(
      () => stateMachine.reduceState(routedDagFrozen(policy), selectionEvent, policy),
      "INVALID_TRANSITION",
    );
  });

  await t.test("active task already present", () => {
    const active = applyEvent(ready, policy, "SELECT_READY_LEAF");
    expectCode(() => stateMachine.reduceState(active, selectionEvent, policy), "INVALID_TRANSITION");
  });

  await t.test("former reversed-topology substitution", () => {
    const candidate = structuredClone(policy) as MutableJson;
    candidate.tasks[0].dependencies = ["task-b"];
    candidate.tasks[0].topological_rank = 1;
    candidate.tasks[0].editable_paths = ["replacement/a"];
    candidate.tasks[1].dependencies = [];
    candidate.tasks[1].topological_rank = 0;
    candidate.tasks[1].editable_paths = ["replacement/b"];
    const replacement = schemas.identifyContractDocument("pi_gacw_reducer_policy_v0", candidate);
    assert.deepEqual(replacement.tasks[1].dependencies, []);
    assert.equal(replacement.tasks[1].topological_rank, 0);
    expectCode(
      () => stateMachine.reduceState(ready, selectionEvent, replacement),
      "FROZEN_POLICY_IDENTITY_MISMATCH",
    );
  });

  const substitutions: readonly [string, (candidate: MutableJson) => void][] = [
    ["changed rank", (candidate) => { candidate.tasks[1].topological_rank = 2; }],
    ["changed priority", (candidate) => { candidate.tasks[0].priority = -1; }],
    ["changed task digest", (candidate) => { candidate.tasks[0].task_sha256 = digest(1_002); }],
    ["changed editable paths", (candidate) => { candidate.tasks[0].editable_paths = ["replacement/task-a"]; }],
    ["changed acceptance binding", (candidate) => { candidate.frozen_bindings.acceptance_sha256 = digest(1_003); }],
    ["changed budget binding", (candidate) => { candidate.frozen_bindings.budget_sha256 = digest(1_004); }],
  ];
  for (const [label, mutate] of substitutions) {
    await t.test(label, () => {
      const candidate = structuredClone(policy) as MutableJson;
      mutate(candidate);
      const replacement = schemas.identifyContractDocument("pi_gacw_reducer_policy_v0", candidate);
      expectCode(
        () => stateMachine.reduceState(ready, selectionEvent, replacement),
        "FROZEN_POLICY_IDENTITY_MISMATCH",
      );
    });
  }

  await t.test("validated reducer preserves ready-leaf ordering", () => {
    const tasks: readonly TestPolicyTask[] = [
      { task_id: "task-z", task_sha256: digest(1_011), topological_rank: 1, priority: -100, dependencies: [], editable_paths: ["src/z"] },
      { task_id: "task-b", task_sha256: digest(1_012), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/b"] },
      { task_id: "task-a", task_sha256: digest(1_013), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/a"] },
      { task_id: "task-c", task_sha256: digest(1_014), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["src/c"] },
    ];
    const orderedPolicy = makePolicy("ROUTED_DAG", { tasks });
    let state = routedReady(orderedPolicy);
    for (const expected of ["task-c", "task-a", "task-b", "task-z"]) {
      state = stateMachine.reduceState(state, selectionEvent, orderedPolicy);
      assert.equal(state.active_task_id, expected);
      state = applyEvent(state, orderedPolicy, "START_LEAF_ATTEMPT");
      state = applyEvent(state, orderedPolicy, "COMPLETE_LEAF_ATTEMPT");
      state = applyEvent(state, orderedPolicy, "PASS_LEAF_POSTFLIGHT");
      state = applyEvent(state, orderedPolicy, "LEAF_VERIFICATION_PASSED");
    }
  });
});

test("built identity introspection cannot mutate canonical projection semantics", async () => {
  const identity = await import(IDENTITY_PACKAGE);
  const schemas = await import(SCHEMAS_PACKAGE);
  const expectedProjectionIds = [
    "objective-freeze-v1",
    "route-map-v1",
    "route-map-approval-v1",
    "baseline-snapshot-v1",
    "baseline-approval-v1",
    "authority-lock-v1",
    "contract-freeze-v1",
    "task-packet-v1",
    "task-graph-freeze-v1",
    "routing-freeze-v1",
    "budget-freeze-v1",
    "plan-approval-v1",
    "transition-commit-v1",
    "final-report-v1",
    "document-content-v1",
  ];

  assert.deepEqual(Object.keys(identity).sort(), [
    "DIGEST_ENCODING",
    "DIGEST_PATTERN",
    "HASH_ALGORITHM",
    "PROJECTION_IDS",
    "ProjectionError",
    "TEXT_ENCODING",
    "assertSha256Digest",
    "getProjectionDefinition",
    "isProjectionId",
    "isSha256Digest",
    "listProjectionDefinitions",
    "sha256Bytes",
    "sha256Canonical",
  ]);
  assert.equal("PROJECTION_REGISTRY" in identity, false);
  assert.equal("getProjection" in identity, false);
  assert.equal("selectReadyLeaf" in identity, false);
  await assert.rejects(
    import(IDENTITY_PRIVATE_SUBPATH),
    (error: unknown) => hasCode(error, "ERR_PACKAGE_PATH_NOT_EXPORTED"),
  );

  const firstInput = objectiveDocument();
  firstInput.scope.readable_paths = ["tests"];
  firstInput.scope.editable_paths = ["src/a", "src/b"];
  firstInput.scope.frozen_paths = ["docs"];
  const secondInput = structuredClone(firstInput) as MutableJson;
  secondInput.scope.editable_paths.reverse();
  const beforeFirst = schemas.identifyContractDocument("pi_gacw_objective_v0", firstInput);
  const beforeSecond = schemas.identifyContractDocument("pi_gacw_objective_v0", secondInput);
  assert.equal(beforeFirst.objective_sha256, beforeSecond.objective_sha256);
  assert.deepEqual(beforeFirst.scope.editable_paths, ["src/a", "src/b"]);
  assert.deepEqual(beforeSecond.scope.editable_paths, ["src/a", "src/b"]);

  const inventoryBefore = identity.listProjectionDefinitions();
  const inventoryAgain = identity.listProjectionDefinitions();
  assert.deepEqual(inventoryBefore.map((definition: MutableJson) => definition.projection_id), expectedProjectionIds);
  assert.notStrictEqual(inventoryBefore, inventoryAgain);
  assertDeepFrozen(identity.PROJECTION_IDS);
  assertDeepFrozen(inventoryBefore);
  for (let index = 0; index < inventoryBefore.length; index += 1) {
    assert.notStrictEqual(inventoryBefore[index], inventoryAgain[index]);
    assert.notStrictEqual(inventoryBefore[index].excluded_json_pointers, inventoryAgain[index].excluded_json_pointers);
    assert.notStrictEqual(inventoryBefore[index].set_like_array_pointers, inventoryAgain[index].set_like_array_pointers);
    assert.notStrictEqual(inventoryBefore[index].normalization_rules, inventoryAgain[index].normalization_rules);
  }

  const definition = identity.getProjectionDefinition("objective-freeze-v1") as MutableJson;
  const independentDefinition = identity.getProjectionDefinition("objective-freeze-v1") as MutableJson;
  const editablePointer = "/scope/editable_paths";
  assert.notStrictEqual(definition, independentDefinition);
  assert.notStrictEqual(definition.set_like_array_pointers, independentDefinition.set_like_array_pointers);
  assert.ok(definition.set_like_array_pointers.includes(editablePointer));
  assert.throws(() => independentDefinition.set_like_array_pointers.pop(), TypeError);
  assert.equal(Reflect.set(independentDefinition.normalization_rules, editablePointer, "independent change"), false);
  assert.equal(Reflect.set(definition, "document_kind", "changed"), false);
  assert.equal(Reflect.set(definition, "excluded_json_pointers", []), false);
  assert.equal(Reflect.set(definition, "set_like_array_pointers", []), false);
  assert.equal(Reflect.set(definition, "normalization_rules", {}), false);
  assert.equal(Reflect.set(definition.normalization_rules, editablePointer, "changed"), false);
  assert.equal(Reflect.deleteProperty(definition.normalization_rules, editablePointer), false);
  assert.throws(() => definition.excluded_json_pointers.push("/objective"), TypeError);
  assert.throws(() => definition.excluded_json_pointers.splice(0, 1), TypeError);
  assert.throws(() => definition.excluded_json_pointers.pop(), TypeError);
  assert.throws(() => definition.set_like_array_pointers.push("/objective"), TypeError);
  assert.throws(() => definition.set_like_array_pointers.splice(definition.set_like_array_pointers.indexOf(editablePointer), 1), TypeError);
  assert.throws(() => definition.set_like_array_pointers.pop(), TypeError);
  assert.throws(() => identity.PROJECTION_IDS.push("unknown-projection-v1"), TypeError);
  assert.throws(() => identity.PROJECTION_IDS.splice(0, 1), TypeError);
  assert.throws(() => identity.PROJECTION_IDS.pop(), TypeError);
  for (const method of ["set", "delete", "clear"]) {
    assert.throws(() => identity.PROJECTION_REGISTRY[method](), TypeError);
  }

  const afterFirst = schemas.identifyContractDocument("pi_gacw_objective_v0", firstInput);
  const afterSecond = schemas.identifyContractDocument("pi_gacw_objective_v0", secondInput);
  assert.deepEqual(afterFirst, beforeFirst);
  assert.deepEqual(afterSecond, beforeSecond);
  assert.equal(afterFirst.objective_sha256, afterSecond.objective_sha256);
  assert.equal(schemas.verifyContractDocument("pi_gacw_objective_v0", afterFirst), true);
  assert.equal(schemas.verifyContractDocument("pi_gacw_objective_v0", afterSecond), true);
  assert.deepEqual(
    identity.listProjectionDefinitions().map((candidate: MutableJson) => candidate.projection_id),
    expectedProjectionIds,
  );
  assert.throws(() => identity.getProjectionDefinition("unknown-projection-v1"), identity.ProjectionError);
});
