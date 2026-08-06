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
      if (invocation.content_sha256 !== digest || invocation.run_id !== input.runId) valid = false;
      if (invocationKeyCounts.get(invocation.invocation_key) !== 1) valid = false;
    } catch {
      valid = false;
    }
    if (valid) validInvocationDigests.add(digest);
    if (!valid) detail = "M6 invocation identity, run, or same-key uniqueness is invalid";
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
      if (
        result.content_sha256 !== digest ||
        result.run_id !== input.runId ||
        invocation === undefined ||
        !validInvocationDigests.has(result.invocation_content_sha256) ||
        invocation.invocation_key !== result.invocation_key ||
        invocation.content_sha256 !== result.invocation_content_sha256 ||
        resultKeyCounts.get(result.invocation_key) !== 1
      ) valid = false;
    } catch {
      valid = false;
    }
    if (!valid) detail = "M6 result identity or invocation predecessor is invalid";
    results.push(classification(object, valid, detail));
  }

  return results.sort((left, right) => canonicalize(left.object.relativePath).localeCompare(canonicalize(right.object.relativePath)));
}
