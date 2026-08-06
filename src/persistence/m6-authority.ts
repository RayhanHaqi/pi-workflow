import { canonicalize } from "../canonical-json/index.js";
import { type Sha256Digest } from "../identity/index.js";
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

export const M6_RUNTIME_BOUNDARY_POLICY = "OA-M6-02" as const;

export const M6_RUNTIME_MODULES = [
  {
    specifier: "@earendil-works/pi-agent-core",
    package_name: "@earendil-works/pi-agent-core",
    package_version: "0.83.0",
    registry_integrity: "sha512-RorGp9OH5l3ElpuC5a5ZQ2eWcchZGXflXRzVGkV99y3y6tT+LLNyxoYIdVKvTKWEObwhExeQbTH0fI2tE4iX4g==",
    registry_resolved: "https://registry.npmjs.org/@earendil-works/pi-agent-core/-/pi-agent-core-0.83.0.tgz",
    installed_tree_sha256: "sha256:692dbf9c0d91d85a93f93b2f88b27e2113bcf88ab4384a4927c3cba8e9a1bb5d" as Sha256Digest,
  },
  {
    specifier: "@earendil-works/pi-ai",
    package_name: "@earendil-works/pi-ai",
    package_version: "0.83.0",
    registry_integrity: "sha512-m3IZD4g3er0V8TC9+Vpgw/sjTKqcJlkcIBy/JvsgRubuuik3tAVzyugUg4rVrShIkkOT69mEd34NEqKUIsl6JQ==",
    registry_resolved: "https://registry.npmjs.org/@earendil-works/pi-ai/-/pi-ai-0.83.0.tgz",
    installed_tree_sha256: "sha256:1411e4d6e549a4accfdffe5da0a1de613c461592a1f0754d5db6c9d7c1721488" as Sha256Digest,
  },
  {
    specifier: "@earendil-works/pi-ai/providers/all",
    package_name: "@earendil-works/pi-ai",
    package_version: "0.83.0",
    registry_integrity: "sha512-m3IZD4g3er0V8TC9+Vpgw/sjTKqcJlkcIBy/JvsgRubuuik3tAVzyugUg4rVrShIkkOT69mEd34NEqKUIsl6JQ==",
    registry_resolved: "https://registry.npmjs.org/@earendil-works/pi-ai/-/pi-ai-0.83.0.tgz",
    installed_tree_sha256: "sha256:1411e4d6e549a4accfdffe5da0a1de613c461592a1f0754d5db6c9d7c1721488" as Sha256Digest,
  },
] as const;

export const M6_FAILURE_CODES = [
  "AUTHORITY_REJECTED",
  "INVOCATION_ALREADY_INCOMPLETE",
  "SDK_INITIALIZATION_FAILED",
  "RUNTIME_IDENTITY_INVALID",
  "RUNTIME_CAPABILITY_INVALID",
  "PROVIDER_PROTOCOL_INVALID",
  "TOOL_REQUEST_INVALID",
  "TOOL_EXECUTION_FAILED",
  "WORKER_REPORT_INVALID",
  "WORKER_DEADLINE_EXCEEDED",
  "WORKER_ABORTED",
  "RESULT_PERSISTENCE_FAILED",
  "CLEANUP_UNCERTAIN",
] as const;
export type M6FailureCode = (typeof M6_FAILURE_CODES)[number];

export const M6_FAILURE_STAGES = [
  "WORKER",
  "M1_M5_ADMISSION",
  "RUNTIME_IDENTITY",
  "RUNTIME_GUARD",
  "SDK_INITIALIZATION",
  "M6_INVOCATION",
  "REPLAY",
  "READ_TOOL",
  "REPORT_TOOL",
  "PROVIDER_TURN",
  "MODEL_TURN",
  "CREDENTIAL",
  "TOOL_PROTOCOL",
  "PROTOCOL",
  "DEADLINE",
  "ABORT",
  "RESULT_PERSISTENCE",
  "CLEANUP_ABORT",
  "CLEANUP_PROMPT",
  "CLEANUP_IDLE",
  "CLEANUP_SUBSCRIBER",
  "CLEANUP_QUEUE",
  "CLEANUP_RESET",
  "CLEANUP_PROVIDERS",
] as const;
export type M6FailureStage = (typeof M6_FAILURE_STAGES)[number];

export const M6_FAILURE_STAGE_BY_CODE = {
  AUTHORITY_REJECTED: ["M1_M5_ADMISSION", "REPLAY", "CREDENTIAL"],
  INVOCATION_ALREADY_INCOMPLETE: ["REPLAY"],
  SDK_INITIALIZATION_FAILED: ["SDK_INITIALIZATION"],
  RUNTIME_IDENTITY_INVALID: ["RUNTIME_IDENTITY"],
  RUNTIME_CAPABILITY_INVALID: ["RUNTIME_GUARD"],
  PROVIDER_PROTOCOL_INVALID: ["PROVIDER_TURN", "MODEL_TURN", "CREDENTIAL", "PROTOCOL", "WORKER"],
  TOOL_REQUEST_INVALID: ["READ_TOOL", "REPORT_TOOL", "TOOL_PROTOCOL"],
  TOOL_EXECUTION_FAILED: ["READ_TOOL", "TOOL_PROTOCOL", "WORKER"],
  WORKER_REPORT_INVALID: ["REPORT_TOOL", "TOOL_PROTOCOL"],
  WORKER_DEADLINE_EXCEEDED: ["DEADLINE"],
  WORKER_ABORTED: ["M1_M5_ADMISSION", "M6_INVOCATION", "ABORT"],
  RESULT_PERSISTENCE_FAILED: ["RESULT_PERSISTENCE"],
  CLEANUP_UNCERTAIN: ["CLEANUP_ABORT", "CLEANUP_PROMPT", "CLEANUP_IDLE", "CLEANUP_SUBSCRIBER", "CLEANUP_QUEUE", "CLEANUP_RESET", "CLEANUP_PROVIDERS"],
} as const satisfies Readonly<Record<M6FailureCode, readonly M6FailureStage[]>>;

function expectedResolvedUrl(value: string, expected: (typeof M6_RUNTIME_MODULES)[number]): boolean {
  try { return value === import.meta.resolve(expected.specifier); }
  catch { return false; }
}

function isFailureCode(value: string): value is M6FailureCode {
  return (M6_FAILURE_CODES as readonly string[]).includes(value);
}

function isFailureStage(value: string): value is M6FailureStage {
  return (M6_FAILURE_STAGES as readonly string[]).includes(value);
}

function failurePairIsValid(code: M6FailureCode, stage: M6FailureStage): boolean {
  return M6_FAILURE_STAGE_BY_CODE[code].some((candidate) => candidate === stage);
}

function invocationSemanticError(invocation: M6WorkerInvocationDocument): string | null {
  if (invocation.protocol_id !== "m6-direct-read-v0" || invocation.execution_mode !== "DIRECT_LUNA_HIGH" ||
      invocation.continuation_action !== "CONTINUE_ADMITTED_OPERATION" || invocation.logical_role !== "LUNA_EXECUTOR" ||
      invocation.effort !== "high" || invocation.runtime_boundary_policy !== M6_RUNTIME_BOUNDARY_POLICY) return "M6 invocation fixed protocol identity is invalid";
  if (invocation.pi_modules.length !== M6_RUNTIME_MODULES.length || invocation.pi_modules.some((module, index) => {
    const expected = M6_RUNTIME_MODULES[index]!;
    return module.specifier !== expected.specifier || module.package_name !== expected.package_name || module.package_version !== expected.package_version ||
      module.registry_integrity !== expected.registry_integrity || module.registry_resolved !== expected.registry_resolved ||
      !expectedResolvedUrl(module.resolved_url, expected) || module.installed_tree_sha256 !== expected.installed_tree_sha256;
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
  if (result.first_failure_code !== null && !isFailureCode(result.first_failure_code)) return "M6 result has an unknown first failure code";
  if (result.first_failure_stage !== null && !isFailureStage(result.first_failure_stage)) return "M6 result has an unknown first failure stage";
  if (result.cleanup_failure_code !== null && !isFailureCode(result.cleanup_failure_code)) return "M6 result has an unknown cleanup failure code";
  if (result.first_failure_code !== null && result.first_failure_stage !== null &&
      (!failurePairIsValid(result.first_failure_code, result.first_failure_stage) || result.first_failure_code === "INVOCATION_ALREADY_INCOMPLETE")) {
    return "M6 result failure code and stage are not a valid persisted result failure";
  }
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
