import assert from "node:assert/strict";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { identifyContractDocument } from "../src/schemas/index.js";
import { buildBoundedWorkerUsageEvidence } from "../src/control/usage-evidence.js";
import type { BoundedWorkerResultDocument, M5ControlDecisionDocument, M5ControlPolicyDocument, M5UsageEvidenceDocument } from "../src/schemas/index.js";

const digest = (letter: string) => `sha256:${letter.repeat(64)}` as const;

function syntheticPolicy(): M5ControlPolicyDocument {
  return { content_sha256: digest("a"), run_id: "usage-equivalence" } as unknown as M5ControlPolicyDocument;
}

function syntheticDecision(): M5ControlDecisionDocument {
  return {
    content_sha256: digest("b"),
    current_state_content_sha256: digest("c"),
    operation_id: "static-leaf-a-attempt-1",
  } as unknown as M5ControlDecisionDocument;
}

function syntheticResult(overrides: Partial<BoundedWorkerResultDocument["actual_usage"]>): BoundedWorkerResultDocument {
  return {
    content_sha256: digest("d"),
    actual_usage: {
      worker_invocations: 1,
      m4_tool_calls: 3,
      model_turns: 2,
      provider_requests: 4,
      input_tokens: 100,
      output_tokens: 200,
      cost_microusd: 1234,
      wall_time_ms: 5678,
      ...overrides,
    },
  } as unknown as BoundedWorkerResultDocument;
}

/** Verbatim historical inline usage() semantics from workflow-controller at a4fccbd; test-only identity witness. */
function historicalUsageEvidence(
  runId: string,
  policy: M5ControlPolicyDocument,
  decision: M5ControlDecisionDocument,
  result: BoundedWorkerResultDocument,
  mode: "STATIC_APPROVED_DAG",
  role: "TERRA_EXECUTOR" | "CODING_EXECUTOR",
): M5UsageEvidenceDocument {
  const value = result.actual_usage;
  type Measurement = M5UsageEvidenceDocument["measurements"][number];
  const measure = (dimension: Measurement["dimension"], amount: number | null, basis: Measurement["basis"], enforcement_class: Measurement["enforcement_class"]): Measurement =>
    ({ dimension, amount, basis, enforcement_class });
  const witness = {
    schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: runId,
    policy_content_sha256: policy.content_sha256, originating_state_content_sha256: decision.current_state_content_sha256,
    operation_id: decision.operation_id!, operation_kind: "WORKER_INVOCATION", execution_mode: mode, logical_role: role,
    reservation_decision_content_sha256: decision.content_sha256, source_layer: "CONTROLLER", source_kind: "BOUNDED_WORKER_RESULT",
    source_record_content_sha256: result.content_sha256,
    measurements: [
      measure("WORKER_INVOCATION", value.worker_invocations, "VALIDATED", "HARD_ENFORCEABLE"),
      measure("TOOL_CALL", value.m4_tool_calls, "VALIDATED", "HARD_ENFORCEABLE"),
      measure("MODEL_TURN", value.model_turns, value.model_turns === null ? "UNAVAILABLE" : "OBSERVED", value.model_turns === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("PROVIDER_REQUEST", value.provider_requests, value.provider_requests === null ? "UNAVAILABLE" : "OBSERVED", value.provider_requests === null ? "UNAVAILABLE" : "OBSERVABLE_ONLY"),
      measure("INPUT_TOKEN", value.input_tokens, value.input_tokens === null ? "UNAVAILABLE" : "OBSERVED", value.input_tokens === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("OUTPUT_TOKEN", value.output_tokens, value.output_tokens === null ? "UNAVAILABLE" : "OBSERVED", value.output_tokens === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("COST_MICROUSD", value.cost_microusd, value.cost_microusd === null ? "UNAVAILABLE" : "OBSERVED", value.cost_microusd === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("WALL_TIME_MS", value.wall_time_ms, "OBSERVED", "SOFT_ENFORCEABLE"),
    ],
    disposition: "COMPLETED", duration_ms: value.wall_time_ms,
  } as unknown as Record<string, unknown>;
  // The historical builder stamped document identity through the same projection call.
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", witness) as unknown as M5UsageEvidenceDocument;
}

test("shared usage builder is byte-identical to the historical inline builder for fully non-null usage including cost", () => {
  const shared = buildBoundedWorkerUsageEvidence({
    runId: "usage-equivalence", policy: syntheticPolicy(), decision: syntheticDecision(),
    executionMode: "STATIC_APPROVED_DAG", logicalRole: "CODING_EXECUTOR", result: syntheticResult({}),
  });
  const historical = historicalUsageEvidence(
    "usage-equivalence", syntheticPolicy(), syntheticDecision(), syntheticResult({}), "STATIC_APPROVED_DAG", "CODING_EXECUTOR",
  );
  // Every dimension compared through the full canonical document, therefore the same content identity.
  assert.equal(canonicalize(shared), canonicalize(historical));
  const cost = shared.measurements.find((entry) => entry.dimension === "COST_MICROUSD")!;
  assert.equal(cost.amount, 1234);
  assert.equal(cost.basis, "OBSERVED");
  assert.equal(cost.enforcement_class, "SOFT_ENFORCEABLE");
});

test("shared usage builder preserves the exact historical COST_MICROUSD semantics", () => {
  const nonNull = buildBoundedWorkerUsageEvidence({
    runId: "usage-equivalence", policy: syntheticPolicy(), decision: syntheticDecision(),
    executionMode: "STATIC_APPROVED_DAG", logicalRole: "TERRA_EXECUTOR", result: syntheticResult({}),
  }).measurements.find((entry) => entry.dimension === "COST_MICROUSD")!;
  assert.deepEqual(nonNull, { dimension: "COST_MICROUSD", amount: 1234, basis: "OBSERVED", enforcement_class: "SOFT_ENFORCEABLE" });
  const nullCost = buildBoundedWorkerUsageEvidence({
    runId: "usage-equivalence", policy: syntheticPolicy(), decision: syntheticDecision(),
    executionMode: "STATIC_APPROVED_DAG", logicalRole: "TERRA_EXECUTOR", result: syntheticResult({ cost_microusd: null }),
  }).measurements.find((entry) => entry.dimension === "COST_MICROUSD")!;
  assert.deepEqual(nullCost, { dimension: "COST_MICROUSD", amount: null, basis: "UNAVAILABLE", enforcement_class: "UNAVAILABLE" });
});

test("null-cost results stay byte-identical to the historical builder", () => {
  const result = syntheticResult({ cost_microusd: null });
  const shared = buildBoundedWorkerUsageEvidence({
    runId: "usage-equivalence", policy: syntheticPolicy(), decision: syntheticDecision(),
    executionMode: "STATIC_APPROVED_DAG", logicalRole: "TERRA_EXECUTOR", result,
  });
  const historical = historicalUsageEvidence(
    "usage-equivalence", syntheticPolicy(), syntheticDecision(), result, "STATIC_APPROVED_DAG", "TERRA_EXECUTOR",
  );
  assert.equal(canonicalize(shared), canonicalize(historical));
});
