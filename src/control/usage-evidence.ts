import { identifyContractDocument } from "../schemas/index.js";
import type { BoundedWorkerResultDocument, ConcreteExecutionMode, LogicalModelRole, M5ControlDecisionDocument, M5ControlPolicyDocument, M5UsageEvidenceDocument } from "../schemas/index.js";

/**
 * Exact bounded-controller usage-evidence identity, extracted verbatim from workflow-controller so the
 * resumed-admission path can reconstruct missing prior-leaf reconciliation evidence without duplicating
 * (and potentially drifting from) the load-bearing document identity.
 */
export function buildBoundedWorkerUsageEvidence(input: {
  readonly runId: string;
  readonly policy: M5ControlPolicyDocument;
  readonly decision: M5ControlDecisionDocument;
  readonly executionMode: ConcreteExecutionMode;
  readonly logicalRole: LogicalModelRole;
  readonly result: BoundedWorkerResultDocument;
}): M5UsageEvidenceDocument {
  const { policy, decision } = input;
  const value = input.result.actual_usage;
  const measure = (dimension: M5UsageEvidenceDocument["measurements"][number]["dimension"], amount: number | null, basis: "VALIDATED" | "OBSERVED" | "UNAVAILABLE", enforcement_class: M5UsageEvidenceDocument["measurements"][number]["enforcement_class"]) => ({ dimension, amount, basis, enforcement_class });
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", { schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: input.runId,
    policy_content_sha256: policy.content_sha256, originating_state_content_sha256: decision.current_state_content_sha256,
    operation_id: decision.operation_id!, operation_kind: "WORKER_INVOCATION", execution_mode: input.executionMode, logical_role: input.logicalRole,
    reservation_decision_content_sha256: decision.content_sha256, source_layer: "CONTROLLER", source_kind: "BOUNDED_WORKER_RESULT", source_record_content_sha256: input.result.content_sha256,
    measurements: [measure("WORKER_INVOCATION", value.worker_invocations, "VALIDATED", "HARD_ENFORCEABLE"), measure("TOOL_CALL", value.m4_tool_calls, "VALIDATED", "HARD_ENFORCEABLE"),
      measure("MODEL_TURN", value.model_turns, value.model_turns === null ? "UNAVAILABLE" : "OBSERVED", value.model_turns === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("PROVIDER_REQUEST", value.provider_requests, value.provider_requests === null ? "UNAVAILABLE" : "OBSERVED", value.provider_requests === null ? "UNAVAILABLE" : "OBSERVABLE_ONLY"),
      measure("INPUT_TOKEN", value.input_tokens, value.input_tokens === null ? "UNAVAILABLE" : "OBSERVED", value.input_tokens === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("OUTPUT_TOKEN", value.output_tokens, value.output_tokens === null ? "UNAVAILABLE" : "OBSERVED", value.output_tokens === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"),
      measure("COST_MICROUSD", value.cost_microusd, value.cost_microusd === null ? "UNAVAILABLE" : "OBSERVED", value.cost_microusd === null ? "UNAVAILABLE" : "OBSERVABLE_ONLY"),
      measure("WALL_TIME_MS", value.wall_time_ms, "OBSERVED", "SOFT_ENFORCEABLE")], disposition: "COMPLETED", duration_ms: value.wall_time_ms }) as unknown as M5UsageEvidenceDocument;
}
