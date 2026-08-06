import { canonicalize } from "../canonical-json/index.js";
import { assertDocumentValid, type M6WorkerInvocationDocument, type M6WorkerResultDocument } from "../schemas/index.js";
import type { InspectedObject, ManagedRecordClassification } from "./types.js";

export interface M6AuthorityInput {
  readonly runId: string;
  readonly objects: readonly InspectedObject[];
  readonly invocations: ReadonlyMap<string, M6WorkerInvocationDocument>;
  readonly results: ReadonlyMap<string, M6WorkerResultDocument>;
}

function key(kind: string, digest: string): string {
  return `${kind}:${digest}`;
}

function classification(
  object: InspectedObject,
  valid: boolean,
  detail: string,
): ManagedRecordClassification {
  return {
    object,
    classification: valid ? "AUTHORITATIVE_MANAGED_RECORD" : "INVALID_MANAGED_RECORD",
    detail,
  };
}

const EXPECTED_MODULES = [
  { specifier: "@earendil-works/pi-agent-core", packageName: "@earendil-works/pi-agent-core" },
  { specifier: "@earendil-works/pi-ai", packageName: "@earendil-works/pi-ai" },
  { specifier: "@earendil-works/pi-ai/providers/all", packageName: "@earendil-works/pi-ai" },
] as const;

function invocationSemanticError(invocation: M6WorkerInvocationDocument): string | null {
  if (invocation.protocol_id !== "m6-direct-read-v0" || invocation.execution_mode !== "DIRECT_LUNA_HIGH" ||
      invocation.continuation_action !== "CONTINUE_ADMITTED_OPERATION" || invocation.logical_role !== "LUNA_EXECUTOR" ||
      invocation.effort !== "high" || invocation.runtime_boundary_policy !== "OA-M6-02") return "M6 invocation fixed protocol identity is invalid";
  if (invocation.pi_modules.length !== EXPECTED_MODULES.length || invocation.pi_modules.some((module, index) => {
    const expected = EXPECTED_MODULES[index]!;
    return module.specifier !== expected.specifier || module.package_name !== expected.packageName || module.package_version !== "0.83.0" ||
      module.registry_integrity.length === 0 || module.registry_resolved.length === 0 || module.resolved_url.length === 0 ||
      module.installed_tree_sha256.length === 0;
  })) return "M6 invocation Pi module identities are invalid";
  if (invocation.pi_modules[2]?.installed_tree_sha256 !== invocation.pi_modules[1]?.installed_tree_sha256) return "M6 providers module is not bound to the verified Pi AI tree";
  const limits = invocation.hard_limits;
  if (limits.provider_turns !== 2 || limits.model_turns !== 2 || limits.read_calls !== 1 || limits.report_submissions !== 1 ||
      limits.tool_calls !== 2 || limits.prompt_bytes < 1 || limits.read_bytes < 1 || limits.tool_result_bytes < 1 ||
      limits.report_canonical_bytes < 1 || limits.wall_deadline_ms < 1) return "M6 invocation fixed resource envelope is invalid";
  if (invocation.read_offset !== 0 || invocation.read_length < 1 || invocation.attempt_number < 1 || invocation.attempt_number > 2) return "M6 invocation bounded read or attempt identity is invalid";
  return null;
}

function nonnegativeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function resultSemanticError(result: M6WorkerResultDocument, invocation: M6WorkerInvocationDocument): string | null {
  if (result.invocation_key !== invocation.invocation_key || result.invocation_content_sha256 !== invocation.content_sha256) return "M6 result does not bind its invocation identity";
  const usage = result.usage;
  const settlement = result.settlement;
  if (!nonnegativeInteger(usage.provider_turns) || !nonnegativeInteger(usage.model_turns) || !nonnegativeInteger(usage.tool_calls) ||
      !nonnegativeInteger(usage.read_calls) || !nonnegativeInteger(usage.report_submissions) || usage.provider_turns > 2 || usage.model_turns > 2 ||
      usage.tool_calls > 2 || usage.read_calls > 1 || usage.report_submissions > 1 || usage.model_turns > usage.provider_turns ||
      (usage.provider_requests !== null && (!nonnegativeInteger(usage.provider_requests) || usage.provider_requests < usage.provider_turns))) return "M6 result usage counts are inconsistent";
  if (settlement.cleanup_certain || settlement.owned_provider_streams < 0 || settlement.owned_child_processes < 0 || settlement.owned_sockets < 0 || settlement.owned_fifos < 0) return "M6 result claims final cleanup certainty before post-publication cleanup";
  if (result.cleanup_failure_code !== null) return "M6 result claims a cleanup failure that occurs after terminal publication";
  if ((result.first_failure_code === null) !== (result.first_failure_stage === null)) return "M6 result failure code and stage are not paired";
  if (usage.read_calls === 0 && result.m4_result_content_sha256 !== null) return "M6 result has M4 identity without a read";
  if (usage.read_calls === 1 && result.m4_result_content_sha256 === null) return "M6 result has a read without M4 identity";
  if (usage.report_submissions === 0 && result.worker_report !== null) return "M6 result has a report without a report submission";
  if (usage.report_submissions === 1) {
    if (result.worker_report === null || result.m4_result_content_sha256 === null || usage.read_calls !== 1 || result.worker_report.status !== "COMPLETED" ||
        result.worker_report.evidence_content_sha256.length !== 1 || result.worker_report.evidence_content_sha256[0] !== result.m4_result_content_sha256) return "M6 worker report evidence is not bound to the single M4 read";
  }
  if (!result.provider_work_started) {
    if (usage.provider_turns !== 0 || usage.model_turns !== 0 || usage.tool_calls !== 0 || usage.read_calls !== 0 || usage.report_submissions !== 0 ||
        result.worker_report !== null || result.m4_result_content_sha256 !== null) return "M6 result claims work before provider start";
  } else if (usage.provider_turns === 0) return "M6 result claims provider work without a provider turn";
  if (result.outcome === "COMPLETED") {
    if (result.first_failure_code !== null || !result.provider_work_started || usage.provider_turns !== 2 || usage.model_turns !== 2 || usage.tool_calls !== 2 ||
        usage.read_calls !== 1 || usage.report_submissions !== 1 || result.worker_report === null || result.m4_result_content_sha256 === null ||
        !settlement.prompt_settled || !settlement.agent_idle || settlement.pending_tool_calls !== 0 || settlement.subscriber_removed || settlement.reset_completed ||
        settlement.timers_cleared || settlement.provider_collection_cleared || settlement.owned_provider_streams !== 0 || settlement.owned_child_processes !== 0 ||
        settlement.owned_sockets !== 0 || settlement.owned_fifos !== 0) return "M6 completed result does not describe the fixed successful protocol before final cleanup";
  } else {
    if (result.first_failure_code === null) return "M6 blocked result has no first failure";
    if (settlement.pending_tool_calls < 0 || settlement.pending_tool_calls > 2) return "M6 blocked result has an invalid pending-tool count";
    if (result.worker_report !== null && (usage.provider_turns !== 2 || usage.model_turns !== 2 || usage.tool_calls !== 2 || usage.read_calls !== 1 || usage.report_submissions !== 1)) return "M6 blocked result contains a terminal report without the complete fixed protocol";
  }
  return null;
}

export function classifyM6Authority(input: M6AuthorityInput): readonly ManagedRecordClassification[] {
  const objects = new Map(input.objects.map((object) => [key(object.kind, object.contentSha256), object]));
  const results: ManagedRecordClassification[] = [];
  const invocationKeyCounts = new Map<string, number>();
  for (const invocation of input.invocations.values()) invocationKeyCounts.set(invocation.invocation_key, (invocationKeyCounts.get(invocation.invocation_key) ?? 0) + 1);
  const validInvocationDigests = new Set<string>();

  for (const [digest, invocation] of input.invocations) {
    const object = objects.get(key("M6_WORKER_INVOCATION", digest));
    if (object === undefined) continue;
    let valid = true;
    let detail = "M6 invocation is a valid immutable authority record";
    try {
      assertDocumentValid("pi_gacw_m6_worker_invocation_v0", invocation);
      const semantic = invocationSemanticError(invocation);
      if (invocation.content_sha256 !== digest || invocation.run_id !== input.runId || invocationKeyCounts.get(invocation.invocation_key) !== 1 || semantic !== null) {
        valid = false;
        detail = semantic ?? "M6 invocation identity, run, or same-key uniqueness is invalid";
      }
    } catch {
      valid = false;
      detail = "M6 invocation failed schema or content identity validation";
    }
    if (valid) validInvocationDigests.add(digest);
    results.push(classification(object, valid, detail));
  }

  const resultKeyCounts = new Map<string, number>();
  for (const result of input.results.values()) resultKeyCounts.set(result.invocation_key, (resultKeyCounts.get(result.invocation_key) ?? 0) + 1);

  for (const [digest, result] of input.results) {
    const object = objects.get(key("M6_WORKER_RESULT", digest));
    if (object === undefined) continue;
    let valid = true;
    let detail = "M6 result is a valid immutable authority record";
    try {
      assertDocumentValid("pi_gacw_m6_worker_result_v0", result);
      const invocation = input.invocations.get(result.invocation_content_sha256);
      const semantic = invocation === undefined ? "M6 result invocation predecessor is missing" : resultSemanticError(result, invocation);
      if (result.content_sha256 !== digest || result.run_id !== input.runId || invocation === undefined || !validInvocationDigests.has(result.invocation_content_sha256) ||
          resultKeyCounts.get(result.invocation_key) !== 1 || semantic !== null) {
        valid = false;
        detail = semantic ?? "M6 result identity or invocation predecessor is invalid";
      }
    } catch {
      valid = false;
      detail = "M6 result failed schema, content identity, or semantic validation";
    }
    results.push(classification(object, valid, detail));
  }

  return results.sort((left, right) => canonicalize(left.object.relativePath).localeCompare(canonicalize(right.object.relativePath)));
}
