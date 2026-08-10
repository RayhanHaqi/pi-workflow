import { canonicalize } from "../canonical-json/index.js";
import {
  assertDocumentValid,
  type BoundedWorkerInvocationDocument,
  type BoundedWorkerResultDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3RepositoryStateTokenDocument,
  type PlanApprovalDocument,
  type TaskDocument,
  type TaskGraphDocument,
  type WorkflowState,
} from "../schemas/index.js";
import type { InspectedObject, ManagedRecordClassification } from "./types.js";

export interface BoundedWorkerAuthorityInput {
  readonly runId: string;
  readonly objects: readonly InspectedObject[];
  readonly invocations: ReadonlyMap<string, BoundedWorkerInvocationDocument>;
  readonly results: ReadonlyMap<string, BoundedWorkerResultDocument>;
}

function descriptor(kind: string, digest: string): string { return `${kind}:${digest}`; }

function recordClassification(object: InspectedObject, valid: boolean, detail: string): ManagedRecordClassification {
  return {
    object,
    classification: valid ? "AUTHORITATIVE_MANAGED_RECORD" : "INVALID_MANAGED_RECORD",
    detail,
  };
}

function invocationError(value: BoundedWorkerInvocationDocument, runId: string): string | null {
  if (value.run_id !== runId) return "bounded invocation belongs to a different run";
  if ((value.task_graph_sha256 === null) !== (value.plan_approval_sha256 === null)) {
    return "bounded invocation plan and task-graph references must be paired";
  }
  return null;
}

function resultError(value: BoundedWorkerResultDocument, invocation: BoundedWorkerInvocationDocument): string | null {
  if (value.invocation_content_sha256 !== invocation.content_sha256) return "bounded result does not bind its invocation";
  if ((value.first_failure_code === null) !== (value.first_failure_stage === null)) return "bounded result failure fields must be paired";
  if (value.outcome === "COMPLETED" && (value.first_failure_code !== null || !value.cleanup_certain || value.actual_usage.worker_invocations !== 1)) {
    return "completed bounded result lacks clean completion evidence";
  }
  if (value.outcome === "BLOCKED" && value.first_failure_code === null) return "blocked bounded result lacks a first failure";
  return null;
}

/**
 * This is intentionally only a record/link classifier. M3, M4, and M5 facts
 * are resolved by the controller-facing resolver instead of reimplemented here.
 */
export function classifyBoundedWorkerAuthority(input: BoundedWorkerAuthorityInput): readonly ManagedRecordClassification[] {
  const objects = new Map(input.objects.map((object) => [descriptor(object.kind, object.contentSha256), object]));
  const output: ManagedRecordClassification[] = [];
  const invocationKeyCounts = new Map<string, number>();
  for (const value of input.invocations.values()) invocationKeyCounts.set(value.invocation_key, (invocationKeyCounts.get(value.invocation_key) ?? 0) + 1);
  const validInvocations = new Set<string>();

  for (const [digest, value] of input.invocations) {
    const object = objects.get(descriptor("BOUNDED_WORKER_INVOCATION", digest));
    if (object === undefined) continue;
    let error: string | null = null;
    try {
      assertDocumentValid("pi_gacw_bounded_worker_invocation_v0", value);
      error = value.content_sha256 !== digest || invocationKeyCounts.get(value.invocation_key) !== 1
        ? "bounded invocation identity or key uniqueness is invalid"
        : invocationError(value, input.runId);
    } catch { error = "bounded invocation failed schema or identity validation"; }
    if (error === null) validInvocations.add(digest);
    output.push(recordClassification(object, error === null, error ?? "bounded invocation is valid"));
  }

  const resultCounts = new Map<string, number>();
  for (const value of input.results.values()) resultCounts.set(value.invocation_content_sha256, (resultCounts.get(value.invocation_content_sha256) ?? 0) + 1);
  for (const [digest, value] of input.results) {
    const object = objects.get(descriptor("BOUNDED_WORKER_RESULT", digest));
    if (object === undefined) continue;
    const invocation = input.invocations.get(value.invocation_content_sha256);
    let error: string | null = null;
    try {
      assertDocumentValid("pi_gacw_bounded_worker_result_v0", value);
      error = value.content_sha256 !== digest || invocation === undefined || !validInvocations.has(value.invocation_content_sha256) ||
          resultCounts.get(value.invocation_content_sha256) !== 1
        ? "bounded result has an invalid immutable invocation predecessor"
        : resultError(value, invocation);
    } catch { error = "bounded result failed schema or identity validation"; }
    output.push(recordClassification(object, error === null, error ?? "bounded result is valid"));
  }
  return output.sort((left, right) => canonicalize(left.object.relativePath).localeCompare(canonicalize(right.object.relativePath)));
}

export interface BoundedExecutionResolutionInput {
  readonly invocation: BoundedWorkerInvocationDocument;
  readonly result: BoundedWorkerResultDocument;
  readonly reservation: M5ControlDecisionDocument;
  readonly reservationState: WorkflowState;
  readonly policy: M5ControlPolicyDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly stateToken: M3RepositoryStateTokenDocument;
  readonly task: TaskDocument | null;
  readonly taskGraph: TaskGraphDocument | null;
  readonly plan: PlanApprovalDocument | null;
  readonly classifications: readonly ManagedRecordClassification[];
}

export interface ResolvedBoundedExecution {
  readonly accepted: boolean;
  readonly reason: string | null;
  readonly acceptedM3Evidence: readonly string[];
  readonly acceptedM4Evidence: readonly string[];
  readonly acceptedWorkerInvocations: number;
  readonly acceptedM4ToolCalls: number;
}

function authoritative(classifications: readonly ManagedRecordClassification[], kind: string, digest: string): boolean {
  return classifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest &&
    entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
}

/**
 * The sole bounded-worker resolver. It delegates record truth to the existing
 * M3/M4/M5 classifications and only checks exact cross-layer bindings.
 */
export function resolveAuthoritativeBoundedExecution(input: BoundedExecutionResolutionInput): ResolvedBoundedExecution {
  const reject = (reason: string): ResolvedBoundedExecution => ({
    accepted: false, reason, acceptedM3Evidence: [], acceptedM4Evidence: [], acceptedWorkerInvocations: 0, acceptedM4ToolCalls: 0,
  });
  const { invocation, result, reservation, policy, baseline, approval } = input;
  if (policy === undefined || baseline === undefined) return reject("M3_BASELINE_OR_M5_POLICY_MISSING");
  const baselineAuthority = baseline.baseline_mode === "APPROVED_BASELINE_DIRTY"
    ? approval?.content_sha256 ?? null
    : approval === null ? baseline.content_sha256 : null;
  if (baselineAuthority === null ||
      !authoritative(input.classifications, "M3_BASELINE", baseline.content_sha256) ||
      (approval !== null && (!authoritative(input.classifications, "M3_BASELINE_APPROVAL", approval.content_sha256) ||
        approval.baseline_runtime_content_sha256 !== baseline.content_sha256))) return reject("M3_BASELINE_AUTHORITY_MISMATCH");
  if (!authoritative(input.classifications, "BOUNDED_WORKER_INVOCATION", invocation.content_sha256) ||
      !authoritative(input.classifications, "BOUNDED_WORKER_RESULT", result.content_sha256)) return reject("BOUNDED_RECORD_NOT_AUTHORITATIVE");
  if (!authoritative(input.classifications, "M5_CONTROL_POLICY", policy.content_sha256) ||
      !authoritative(input.classifications, "M5_CONTROL_DECISION", reservation.content_sha256) ||
      reservation.policy_content_sha256 !== policy.content_sha256 || reservation.outcome !== "AUTHORIZE" || reservation.reservation === null || reservation.operation_id === null) {
    return reject("M5_RESERVATION_NOT_AUTHORITATIVE");
  }
  if (input.reservationState.content_sha256 !== reservation.current_state_content_sha256 ||
      reservation.reservation.reserved_state_content_sha256 !== reservation.current_state_content_sha256) {
    return reject("M5_RESERVATION_STATE_BINDING_MISMATCH");
  }
  if (policy.baseline_approval_sha256 !== baselineAuthority ||
      input.stateToken.baseline_runtime_content_sha256 !== baseline.content_sha256) return reject("M3_TOKEN_BASELINE_MISMATCH");
  if (invocation.m5_reservation_decision_content_sha256 !== reservation.content_sha256 ||
      invocation.m5_reservation_decision_key !== reservation.reservation.reservation_decision_key ||
      invocation.operation_id !== reservation.operation_id) return reject("M5_RESERVATION_BINDING_MISMATCH");
  if (!authoritative(input.classifications, "M3_REPOSITORY_STATE_TOKEN", input.stateToken.content_sha256) ||
      invocation.input_m3_state_token_content_sha256 !== input.stateToken.content_sha256) return reject("M3_TOKEN_BINDING_MISMATCH");
  if (input.stateToken.run_id !== policy.run_id || input.stateToken.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 ||
      input.stateToken.worktree_key !== policy.worktree_key || input.stateToken.task_scope_identity !== policy.scope_sha256) return reject("M3_TOKEN_POLICY_MISMATCH");
  if (invocation.task_content_sha256 !== (input.task?.content_sha256 ?? null) ||
      invocation.task_graph_sha256 !== (input.taskGraph?.content_sha256 ?? null) ||
      invocation.plan_approval_sha256 !== (input.plan?.content_sha256 ?? null)) return reject("TASK_OR_PLAN_BINDING_MISMATCH");
  if ((input.taskGraph === null) !== (input.plan === null) ||
      (policy.requested_mode !== "ROUTED_DAG" && input.task === null)) return reject("TASK_OR_PLAN_BINDING_MISMATCH");
  if (input.taskGraph !== null && input.plan !== null &&
      (input.taskGraph.task_graph_sha256 !== policy.task_graph_sha256 || input.plan.plan_approval_sha256 !== policy.plan_approval_sha256 ||
        input.plan.bindings.dag.task_graph_sha256 !== input.taskGraph.task_graph_sha256 ||
        input.plan.bindings.contract_sha256 !== policy.contract_sha256 || input.plan.bindings.baseline_approval_sha256 !== policy.baseline_approval_sha256 ||
        canonicalize(input.plan.bindings.dag.edges) !== canonicalize(input.taskGraph.edges))) return reject("TASK_OR_PLAN_POLICY_MISMATCH");
  if (input.task !== null &&
      (input.taskGraph === null
        ? input.task.task_sha256 !== policy.objective_sha256
        : !input.taskGraph.tasks.some((node) => node.task_id === input.task!.task_id && node.task_sha256 === input.task!.task_sha256) ||
          input.plan === null || !input.plan.bindings.dag.ordered_task_packet_identities.includes(input.task.task_sha256))) return reject("TASK_OR_PLAN_POLICY_MISMATCH");
  if (policy.requested_mode === "ROUTED_DAG" &&
      ((input.task !== null && reservation.reservation.logical_role !== "LUNA_EXECUTOR") ||
        (reservation.reservation.logical_role === "LUNA_EXECUTOR" &&
          (input.task === null || input.reservationState.phase !== "LEAF_FAST_PREFLIGHT" ||
            input.reservationState.active_task_id === null || input.reservationState.active_task_id !== input.task.task_id)))) {
    return reject("ROUTED_ACTIVE_TASK_BINDING_MISMATCH");
  }
  if (result.outcome !== "COMPLETED" || !result.cleanup_certain || result.actual_usage.worker_invocations !== 1) return reject(result.cleanup_certain ? "BOUNDED_WORKER_BLOCKED" : "BOUNDED_WORKER_CLEANUP_UNCERTAIN");
  const m3Kinds = new Set(["M3_REPOSITORY_STATE_TOKEN", "M3_POSTFLIGHT"]);
  const m4Kinds = new Set(["M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"]);
  const m3Evidence = result.m3_evidence_content_sha256.filter((digest) =>
    [...m3Kinds].some((kind) => authoritative(input.classifications, kind, digest)));
  const m4Evidence = result.m4_evidence_content_sha256.filter((digest) =>
    [...m4Kinds].some((kind) => authoritative(input.classifications, kind, digest)));
  if (m3Evidence.length !== result.m3_evidence_content_sha256.length || m4Evidence.length !== result.m4_evidence_content_sha256.length ||
      result.actual_usage.m4_tool_calls !== m4Evidence.length) return reject("PRODUCED_EVIDENCE_NOT_AUTHORITATIVE");
  return {
    accepted: true, reason: null, acceptedM3Evidence: m3Evidence, acceptedM4Evidence: m4Evidence,
    acceptedWorkerInvocations: result.actual_usage.worker_invocations,
    acceptedM4ToolCalls: result.actual_usage.m4_tool_calls,
  };
}
