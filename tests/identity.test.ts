import assert from "node:assert/strict";
import test from "node:test";

import { CANONICALIZATION_ID } from "../src/canonical-json/index.js";
import * as identitySurface from "../src/identity/index.js";
import {
  DIGEST_ENCODING,
  DIGEST_PATTERN,
  HASH_ALGORITHM,
  PROJECTION_IDS,
  TEXT_ENCODING,
  ProjectionError,
  getProjectionDefinition,
  isProjectionId,
  listProjectionDefinitions,
  sha256Bytes,
  type DomainProjectionId,
} from "../src/identity/index.js";
import {
  ContractValidationError,
  assertDocumentValid,
  identifyContractDocument,
  verifyContractDocument,
} from "../src/schemas/index.js";
import {
  allRoutes,
  budgetDocument,
  digest,
  domainDocument,
  makePolicy,
  objectiveDocument,
  ownerAcceptanceCriterion,
  planApprovalDocument,
  route,
  schemaIdByProjection,
  taskGraphDocument,
  type MutableJson,
} from "./helpers.js";

function expectCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => error instanceof ContractValidationError && error.code === code);
}

function mutateIncludedField(projectionId: DomainProjectionId, document: MutableJson): void {
  switch (projectionId) {
    case "objective-freeze-v1":
      document.objective = "A changed bounded objective.";
      return;
    case "route-map-v1":
      document.routes[0].provider_id = "provider-changed";
      return;
    case "route-map-approval-v1":
      document.approved_by = "owner-changed";
      return;
    case "baseline-snapshot-v1":
      document.git_state_sha256 = digest(401);
      return;
    case "baseline-approval-v1":
      document.approved_by = "owner-changed";
      return;
    case "authority-lock-v1":
      document.authorities[0].content_sha256 = digest(402);
      return;
    case "contract-freeze-v1":
      document.stopping_conditions[0] = "Stop on changed evidence";
      return;
    case "task-packet-v1":
      document.objective = "A changed task objective.";
      return;
    case "task-graph-freeze-v1":
      document.tasks[0].priority = -1;
      return;
    case "routing-freeze-v1":
      document.reasons[0] = "Changed deterministic reason";
      return;
    case "budget-freeze-v1":
      document.limits.max_model_turns += 1;
      return;
    case "plan-approval-v1":
      document.approved_by = "owner-changed";
      return;
    case "transition-commit-v1":
      document.sequence = 2;
      return;
    case "final-report-v1":
      document.reason = "Changed bounded report reason.";
      return;
  }
}

test("SHA-256 constants and bytes use the frozen lowercase-prefixed format", () => {
  assert.equal(HASH_ALGORITHM, "SHA-256");
  assert.equal(DIGEST_ENCODING, "lowercase hexadecimal");
  assert.equal(TEXT_ENCODING, "UTF-8 without BOM");
  assert.equal(DIGEST_PATTERN, "^sha256:[0-9a-f]{64}$");
  assert.equal(
    sha256Bytes(Buffer.from("abc", "utf8")),
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("the immutable projection inventory declares each identity boundary", () => {
  const expected = [
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
  const definitions = listProjectionDefinitions();
  assert.deepEqual([...PROJECTION_IDS], expected);
  assert.deepEqual(definitions.map((definition) => definition.projection_id), expected);
  assert.equal(Object.isFrozen(PROJECTION_IDS), true);
  assert.equal(Object.isFrozen(definitions), true);
  for (const projectionId of PROJECTION_IDS) {
    const definition = getProjectionDefinition(projectionId);
    const independent = getProjectionDefinition(projectionId);
    assert.notStrictEqual(definition, independent);
    assert.notStrictEqual(definition.excluded_json_pointers, independent.excluded_json_pointers);
    assert.notStrictEqual(definition.set_like_array_pointers, independent.set_like_array_pointers);
    assert.equal(Object.isFrozen(definition), true);
    assert.equal(Object.isFrozen(definition.excluded_json_pointers), true);
    assert.equal(Object.isFrozen(definition.normalization_rules), true);
    assert.equal(Object.isFrozen(definition.set_like_array_pointers), true);
    assert.equal(definition.projection_id, projectionId);
    assert.equal(definition.canonicalization_id, CANONICALIZATION_ID);
    assert.ok(definition.inclusion_rule.length > 0);
    assert.ok(definition.ordering_rules.length > 0);
    assert.ok(definition.excluded_json_pointers.includes("/content_sha256"));
  }
  assert.equal(isProjectionId("plan-approval-v1"), true);
  assert.equal(isProjectionId("unknown-projection-v1"), false);
  assert.throws(() => getProjectionDefinition("unknown-projection-v1" as DomainProjectionId), ProjectionError);
});

test("the public identity package surface omits unvalidated contract hashing", () => {
  for (const name of [
    "projectDocument",
    "computeDomainIdentity",
    "computeContentIdentity",
    "withDocumentIdentities",
    "withContentIdentity",
    "verifyDocumentIdentities",
    "verifyContentIdentity",
    "unsafeProjectDocument",
    "unsafeWithDocumentIdentities",
    "PROJECTION_REGISTRY",
    "getProjection",
  ]) {
    assert.equal(name in identitySurface, false, name);
  }
});

test("content identity excludes only itself and verified construction binds included fields", () => {
  const source = {
    schema_id: "pi_gacw_owner_decisions_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    decisions: [{ decision_id: "decision-1", question: "Proceed?", answer: "Yes" }],
  };
  const first = identifyContractDocument("pi_gacw_owner_decisions_v0", source);
  const changedSelf = identifyContractDocument("pi_gacw_owner_decisions_v0", { ...first, content_sha256: digest(2) });
  const changedIncluded = identifyContractDocument("pi_gacw_owner_decisions_v0", {
    ...first,
    decisions: [{ ...first.decisions[0], answer: "No" }],
  });
  assert.equal(first.content_sha256, changedSelf.content_sha256);
  assert.notEqual(first.content_sha256, changedIncluded.content_sha256);
  assert.equal(verifyContractDocument("pi_gacw_owner_decisions_v0", first), true);
  assert.equal(verifyContractDocument("pi_gacw_owner_decisions_v0", { ...first, decisions: [] }), false);
});

test("every validated domain identity excludes identity fields and binds an ordinary field", async (t) => {
  const domainIds = PROJECTION_IDS.filter((projectionId): projectionId is DomainProjectionId => projectionId !== "document-content-v1");
  for (const projectionId of domainIds) {
    await t.test(projectionId, () => {
      const definition = getProjectionDefinition(projectionId);
      assert.notEqual(definition.digest_field, null);
      const original = domainDocument(projectionId);
      const digestField = definition.digest_field as string;
      const changedIdentityFields = identifyContractDocument(schemaIdByProjection[projectionId], {
        ...original,
        [digestField]: digest(410),
        content_sha256: digest(411),
      });
      assert.equal(changedIdentityFields[digestField], original[digestField]);
      assert.equal(changedIdentityFields.content_sha256, original.content_sha256);

      const changedIncluded = structuredClone(original) as MutableJson;
      mutateIncludedField(projectionId, changedIncluded);
      const reidentified = identifyContractDocument(schemaIdByProjection[projectionId], changedIncluded);
      assert.notEqual(reidentified[digestField], original[digestField]);
    });
  }
});

test("validated domain identity is inserted before content identity without a fixed point", () => {
  const identified = objectiveDocument();
  assertDocumentValid("pi_gacw_objective_v0", identified);
  const repeated = identifyContractDocument("pi_gacw_objective_v0", identified);
  assert.deepEqual(repeated, identified);

  const changedDomain = { ...identified, objective_sha256: digest(493) };
  assert.equal(verifyContractDocument("pi_gacw_objective_v0", changedDomain), false);
  expectCode(() => assertDocumentValid("pi_gacw_objective_v0", changedDomain), "IDENTITY_MISMATCH");
  assert.deepEqual(identifyContractDocument("pi_gacw_objective_v0", changedDomain), identified);
});

test("declared set-like arrays normalize by canonical UTF-8 bytes while ordinary arrays preserve order", () => {
  const firstInput = objectiveDocument();
  firstInput.scope.readable_paths = ["𐀀", "\ue000"];
  firstInput.scope.editable_paths = ["z", "a"];
  firstInput.scope.frozen_paths = ["frozen-b", "frozen-a"];
  firstInput.required_outputs = ["output-a", "output-b"];
  const secondInput = structuredClone(firstInput) as MutableJson;
  secondInput.scope.readable_paths.reverse();
  secondInput.scope.editable_paths.reverse();
  secondInput.scope.frozen_paths.reverse();

  const first = identifyContractDocument("pi_gacw_objective_v0", firstInput);
  const reorderedSets = identifyContractDocument("pi_gacw_objective_v0", secondInput);
  assert.equal(first.objective_sha256, reorderedSets.objective_sha256);
  assert.deepEqual(first.scope.readable_paths, ["\ue000", "𐀀"]);
  assert.deepEqual(first.scope.editable_paths, ["a", "z"]);

  const reorderedOrdinary = structuredClone(firstInput) as MutableJson;
  reorderedOrdinary.required_outputs.reverse();
  assert.notEqual(
    first.objective_sha256,
    identifyContractDocument("pi_gacw_objective_v0", reorderedOrdinary).objective_sha256,
  );
});

test("same validated normalized projection always produces the same digest", () => {
  const left = domainDocument("authority-lock-v1");
  left.authorities.push({ path: "docs/schema.md", role: "SCHEMA", content_sha256: digest(501) });
  const right = structuredClone(left) as MutableJson;
  right.authorities.reverse();
  const leftIdentified = identifyContractDocument("pi_gacw_authority_lock_v0", left);
  const rightIdentified = identifyContractDocument("pi_gacw_authority_lock_v0", right);
  assert.deepEqual(leftIdentified, rightIdentified);
});

test("plan-approval-v1 binds every owner-approved field in the validated mutation matrix", async (t) => {
  const routedBase = (): MutableJson => {
    const document = planApprovalDocument("ROUTED_DAG", 2);
    document.bindings.logical_routes = allRoutes();
    document.bindings.owner_acceptance_criteria = [];
    return identifyContractDocument("pi_gacw_plan_approval_v0", document);
  };
  const mutations: readonly [string, () => MutableJson, (document: MutableJson) => void][] = [
    ["objective", routedBase, (document) => { document.bindings.objective_sha256 = digest(601); }],
    ["target repository", routedBase, (document) => { document.bindings.target_repository.head = "1123456789abcdef0123456789abcdef01234567"; }],
    ["execution mode", () => planApprovalDocument("DIRECT_LUNA_HIGH", 1), (document) => { document.bindings.execution_mode = "SINGLE_OWNER_SOL"; }],
    ["baseline approval", routedBase, (document) => { document.bindings.baseline_approval_sha256 = digest(602); }],
    ["authority lock", routedBase, (document) => { document.bindings.authority_lock_sha256 = digest(603); }],
    ["contract", routedBase, (document) => { document.bindings.contract_sha256 = digest(604); }],
    ["DAG edge", routedBase, (document) => { document.bindings.dag.edges[0].to = "task-changed"; }],
    ["task packet", routedBase, (document) => { document.bindings.dag.ordered_task_packet_identities[0] = digest(605); }],
    ["readable path", routedBase, (document) => { document.bindings.scope.readable_paths.push("docs-extra"); }],
    ["editable path", routedBase, (document) => { document.bindings.scope.editable_paths.push("src-extra"); }],
    ["frozen path", routedBase, (document) => { document.bindings.scope.frozen_paths.push("frozen-extra"); }],
    ["required input", routedBase, (document) => { document.bindings.required_inputs.push("input-extra"); }],
    ["required output", routedBase, (document) => { document.bindings.required_outputs.push("output-extra"); }],
    ["acceptance", routedBase, (document) => { document.bindings.acceptance_criteria[0].description = "changed acceptance"; }],
    ["owner acceptance", () => planApprovalDocument("SINGLE_OWNER_SOL", 1), (document) => { document.bindings.owner_acceptance_criteria[0].description = "changed owner acceptance"; }],
    ["verification command", routedBase, (document) => { document.bindings.verification_commands[0].argv.push("--changed"); }],
    ["command policy", routedBase, (document) => { document.bindings.command_policy.network = "OWNER_APPROVED"; }],
    ["logical route", routedBase, (document) => { document.bindings.logical_routes.pop(); }],
    ["provider", routedBase, (document) => { document.bindings.logical_routes[0].provider_id = "provider-changed"; }],
    ["model", routedBase, (document) => { document.bindings.logical_routes[0].model_id = "model-changed"; }],
    ["effort", routedBase, (document) => {
      document.bindings.logical_routes.find((candidate: MutableJson) => candidate.logical_role === "BENCHMARK_VERIFIER").effort = "high";
    }],
    ["tool policy", routedBase, (document) => { document.bindings.logical_routes[0].tool_policy.maximum_tool_calls += 1; }],
    ["leaf cap", routedBase, (document) => { document.bindings.limits.max_leaves = 7; }],
    ["attempt cap", routedBase, (document) => { document.bindings.limits.max_attempts_per_leaf = 1; }],
    ["replan cap", routedBase, (document) => { document.bindings.limits.max_replans = 1; }],
    ["model-turn limit", routedBase, (document) => { document.bindings.limits.max_model_turns += 1; }],
    ["tool-call limit", routedBase, (document) => { document.bindings.limits.max_tool_calls += 1; }],
    ["token budget", routedBase, (document) => { document.bindings.limits.max_input_tokens += 1; }],
    ["cost budget", routedBase, (document) => { document.bindings.limits.max_cost_microusd += 1; }],
    ["wall-time budget", routedBase, (document) => { document.bindings.limits.max_wall_time_ms += 1; }],
    ["stopping condition", routedBase, (document) => { document.bindings.stopping_conditions[0] = "changed stop"; }],
  ];

  for (const [label, makeBase, mutate] of mutations) {
    await t.test(label, () => {
      const base = identifyContractDocument("pi_gacw_plan_approval_v0", makeBase());
      const changed = structuredClone(base) as MutableJson;
      mutate(changed);
      const reidentified = identifyContractDocument("pi_gacw_plan_approval_v0", changed);
      assert.notEqual(reidentified.plan_approval_sha256, base.plan_approval_sha256, `${label} was not bound`);
    });
  }
});

test("plan set-like ordering is normalized but ordered task packets remain ordered", () => {
  const base = planApprovalDocument("ROUTED_DAG", 2);
  base.bindings.logical_routes = [route("SOL_OWNER"), route("LUNA_EXECUTOR")];
  const reorderedSet = structuredClone(base) as MutableJson;
  reorderedSet.bindings.scope.readable_paths.reverse();
  reorderedSet.bindings.logical_routes.reverse();
  const first = identifyContractDocument("pi_gacw_plan_approval_v0", base);
  const second = identifyContractDocument("pi_gacw_plan_approval_v0", reorderedSet);
  assert.equal(first.plan_approval_sha256, second.plan_approval_sha256);

  const reorderedPackets = structuredClone(base) as MutableJson;
  reorderedPackets.bindings.dag.ordered_task_packet_identities.reverse();
  assert.notEqual(
    first.plan_approval_sha256,
    identifyContractDocument("pi_gacw_plan_approval_v0", reorderedPackets).plan_approval_sha256,
  );
});

test("validated identity construction rejects invalid structure and semantics before hashing", async (t) => {
  const cases: readonly [string, string, MutableJson, string][] = [
    ["unknown objective property", "pi_gacw_objective_v0", { ...objectiveDocument(), unknown_property: true }, "SCHEMA_INVALID"],
    ["overlapping objective scope", "pi_gacw_objective_v0", (() => { const value = objectiveDocument(); value.scope.frozen_paths = ["src"]; return value; })(), "OVERLAPPING_EDITABLE_AND_FROZEN_PATHS"],
    ["task graph above cap", "pi_gacw_task_graph_v0", (() => { const value = taskGraphDocument(3, 8); value.configured_max_leaves = 2; return value; })(), "TASK_GRAPH_ABOVE_LEAF_CAP"],
    ["semantically inconsistent policy", "pi_gacw_reducer_policy_v0", (() => { const value = structuredClone(makePolicy("DIRECT_LUNA_HIGH")) as MutableJson; value.owner_acceptance_required = true; return value; })(), "OWNER_ACCEPTANCE_MODE_MISMATCH"],
    ["invalid unavailable usage", "pi_gacw_budget_v0", (() => { const value = budgetDocument(); value.usage.provider_request = { value: 0, enforcement_class: "UNAVAILABLE" }; return value; })(), "SCHEMA_INVALID"],
    ["duplicate declared set", "pi_gacw_authority_lock_v0", (() => { const value = domainDocument("authority-lock-v1"); value.authorities.push(structuredClone(value.authorities[0])); return value; })(), "SCHEMA_INVALID"],
  ];
  for (const [label, schemaId, value, code] of cases) {
    await t.test(label, () => {
      const typedSchemaId = schemaId as Parameters<typeof identifyContractDocument>[0];
      expectCode(() => identifyContractDocument(typedSchemaId, value), code);
      expectCode(() => assertDocumentValid(typedSchemaId, value), code);
      assert.equal(verifyContractDocument(typedSchemaId, value), false);
    });
  }
});
