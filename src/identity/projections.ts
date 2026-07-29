import { CANONICALIZATION_ID, canonicalUtf8, canonicalize, type JsonValue } from "../canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "./digest.js";

export const PROJECTION_IDS = Object.freeze([
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
] as const);

export type ProjectionId = (typeof PROJECTION_IDS)[number];
export type DomainProjectionId = Exclude<ProjectionId, "document-content-v1">;

export interface ProjectionDefinition {
  readonly projection_id: ProjectionId;
  readonly document_kind: string;
  readonly inclusion_rule: string;
  readonly excluded_json_pointers: readonly string[];
  readonly normalization_rules: Readonly<Record<string, string>>;
  readonly ordering_rules: string;
  readonly canonicalization_id: typeof CANONICALIZATION_ID;
  readonly projection_id_field: string;
  readonly digest_field: string | null;
  readonly set_like_array_pointers: readonly string[];
}

const ALL_FIELDS = "Include every schema-declared field recursively except the listed JSON pointers.";
const UTF16_ORDER = "Object member names use raw UTF-16 code-unit order; arrays preserve order except declared set-like arrays, which use canonical-value order.";

function domainProjection(
  projection_id: DomainProjectionId,
  document_kind: string,
  projection_id_field: string,
  digest_field: string,
  set_like_array_pointers: readonly string[] = [],
): ProjectionDefinition {
  return {
    projection_id,
    document_kind,
    inclusion_rule: ALL_FIELDS,
    excluded_json_pointers: [`/${digest_field}`, "/content_sha256"],
    normalization_rules: Object.fromEntries(
      set_like_array_pointers.map((pointer) => [
        pointer,
        "Reject duplicate canonical members during contract validation, then sort ascending by canonical-json-v1 bytes.",
      ]),
    ),
    ordering_rules: UTF16_ORDER,
    canonicalization_id: CANONICALIZATION_ID,
    projection_id_field,
    digest_field,
    set_like_array_pointers,
  };
}

function freezeProjectionDefinition(definition: ProjectionDefinition): ProjectionDefinition {
  return Object.freeze({
    ...definition,
    excluded_json_pointers: Object.freeze([...definition.excluded_json_pointers]),
    normalization_rules: Object.freeze({ ...definition.normalization_rules }),
    set_like_array_pointers: Object.freeze([...definition.set_like_array_pointers]),
  });
}

const definitions: readonly ProjectionDefinition[] = Object.freeze(([
  domainProjection("objective-freeze-v1", "pi_gacw_objective_v0", "objective_projection_id", "objective_sha256", [
    "/scope/readable_paths",
    "/scope/editable_paths",
    "/scope/frozen_paths",
    "/repository_authority_paths",
  ]),
  domainProjection("route-map-v1", "pi_gacw_route_map_v0", "route_map_projection_id", "route_map_sha256", ["/routes"]),
  domainProjection(
    "route-map-approval-v1",
    "pi_gacw_route_map_approval_v0",
    "route_map_approval_projection_id",
    "route_map_approval_sha256",
  ),
  domainProjection("baseline-snapshot-v1", "pi_gacw_baseline_v0", "baseline_projection_id", "baseline_sha256", ["/files"]),
  domainProjection(
    "baseline-approval-v1",
    "pi_gacw_baseline_approval_v0",
    "baseline_approval_projection_id",
    "baseline_approval_sha256",
  ),
  domainProjection("authority-lock-v1", "pi_gacw_authority_lock_v0", "authority_lock_projection_id", "authority_lock_sha256", [
    "/authorities",
  ]),
  domainProjection("contract-freeze-v1", "pi_gacw_contract_v0", "contract_projection_id", "contract_sha256", [
    "/scope/readable_paths",
    "/scope/editable_paths",
    "/scope/frozen_paths",
    "/required_inputs",
    "/required_outputs",
  ]),
  domainProjection("task-packet-v1", "pi_gacw_task_v0", "task_projection_id", "task_sha256", [
    "/dependencies",
    "/scope/readable_paths",
    "/scope/editable_paths",
    "/scope/frozen_paths",
    "/required_inputs",
    "/required_outputs",
  ]),
  domainProjection("task-graph-freeze-v1", "pi_gacw_task_graph_v0", "task_graph_projection_id", "task_graph_sha256", [
    "/tasks",
    "/edges",
  ]),
  domainProjection("routing-freeze-v1", "pi_gacw_routing_v0", "routing_projection_id", "routing_sha256", ["/reasons"]),
  domainProjection("budget-freeze-v1", "pi_gacw_budget_v0", "budget_projection_id", "budget_sha256"),
  domainProjection("plan-approval-v1", "pi_gacw_plan_approval_v0", "plan_approval_projection_id", "plan_approval_sha256", [
    "/bindings/dag/edges",
    "/bindings/scope/readable_paths",
    "/bindings/scope/editable_paths",
    "/bindings/scope/frozen_paths",
    "/bindings/required_inputs",
    "/bindings/required_outputs",
    "/bindings/logical_routes",
  ]),
  domainProjection(
    "transition-commit-v1",
    "pi_gacw_transition_commit_v0",
    "transition_commit_projection_id",
    "transition_commit_sha256",
  ),
  domainProjection("final-report-v1", "pi_gacw_final_report_v0", "final_report_projection_id", "final_report_sha256"),
  {
    projection_id: "document-content-v1",
    document_kind: "any versioned JSON document",
    inclusion_rule: "Include every field recursively except top-level /content_sha256; /content_projection_id remains included.",
    excluded_json_pointers: ["/content_sha256"],
    normalization_rules: {},
    ordering_rules: UTF16_ORDER,
    canonicalization_id: CANONICALIZATION_ID,
    projection_id_field: "content_projection_id",
    digest_field: null,
    set_like_array_pointers: [],
  },
] satisfies readonly ProjectionDefinition[]).map(freezeProjectionDefinition));

const internalProjectionRegistry: ReadonlyMap<ProjectionId, ProjectionDefinition> = new Map(
  definitions.map((definition) => [definition.projection_id, definition]),
);

export class ProjectionError extends TypeError {
  public constructor(message: string) {
    super(message);
    this.name = "ProjectionError";
  }
}

export function isProjectionId(value: unknown): value is ProjectionId {
  return typeof value === "string" && internalProjectionRegistry.has(value as ProjectionId);
}

function getInternalProjection(projectionId: ProjectionId): ProjectionDefinition {
  const definition = internalProjectionRegistry.get(projectionId);
  if (definition === undefined) {
    throw new ProjectionError(`Unknown projection ID: ${projectionId}`);
  }
  return definition;
}

export function getProjectionDefinition(projectionId: ProjectionId): ProjectionDefinition {
  return freezeProjectionDefinition(getInternalProjection(projectionId));
}

export function listProjectionDefinitions(): readonly ProjectionDefinition[] {
  return Object.freeze(PROJECTION_IDS.map((projectionId) => getProjectionDefinition(projectionId)));
}

function decodePointer(pointer: string): string[] {
  if (pointer === "") {
    return [];
  }
  if (!pointer.startsWith("/")) {
    throw new ProjectionError(`Invalid JSON pointer: ${pointer}`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
}

function asMutableJsonRecord(value: JsonValue, label: string): Record<string, JsonValue> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new ProjectionError(`${label} must be a JSON object`);
  }
  return value as Record<string, JsonValue>;
}

function parentAtPointer(root: JsonValue, pointer: string): { parent: Record<string, JsonValue> | JsonValue[]; token: string } | null {
  const tokens = decodePointer(pointer);
  const token = tokens.pop();
  if (token === undefined) {
    return null;
  }

  let current: JsonValue = root;
  for (const segment of tokens) {
    if (Array.isArray(current)) {
      const index = Number(segment);
      if (!Number.isSafeInteger(index) || index < 0 || index >= current.length) {
        return null;
      }
      const next = current[index];
      if (next === undefined) {
        return null;
      }
      current = next;
    } else if (current !== null && typeof current === "object") {
      const next = current[segment];
      if (next === undefined) {
        return null;
      }
      current = next;
    } else {
      return null;
    }
  }

  if (Array.isArray(current) || (current !== null && typeof current === "object")) {
    return { parent: current as Record<string, JsonValue> | JsonValue[], token };
  }
  return null;
}

function removePointer(root: JsonValue, pointer: string): void {
  const location = parentAtPointer(root, pointer);
  if (location === null) {
    return;
  }
  if (Array.isArray(location.parent)) {
    const index = Number(location.token);
    if (Number.isSafeInteger(index) && index >= 0 && index < location.parent.length) {
      location.parent.splice(index, 1);
    }
  } else {
    delete location.parent[location.token];
  }
}

function sortSetLikeArray(root: JsonValue, pointer: string): void {
  const location = parentAtPointer(root, pointer);
  if (location === null) {
    return;
  }
  const value = Array.isArray(location.parent)
    ? location.parent[Number(location.token)]
    : location.parent[location.token];
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value)) {
    throw new ProjectionError(`Normalization target ${pointer} must be an array when present`);
  }
  value.sort((left, right) => Buffer.compare(Buffer.from(canonicalUtf8(left)), Buffer.from(canonicalUtf8(right))));
}

function cloneValidatedJson(document: unknown): JsonValue {
  return JSON.parse(canonicalize(document)) as JsonValue;
}

function assertProjectionMarker(document: Record<string, JsonValue>, definition: ProjectionDefinition): void {
  if (document[definition.projection_id_field] !== definition.projection_id) {
    throw new ProjectionError(
      `${definition.projection_id_field} must equal ${definition.projection_id} for ${definition.document_kind}`,
    );
  }
}

/**
 * Internal unvalidated projection primitives. They enforce canonical JSON and
 * projection markers only. Package consumers must use the schema-aware
 * identity APIs exported by `src/schemas/validator.ts`.
 */
export function unsafeProjectDocument(projectionId: ProjectionId, document: unknown): JsonValue {
  const definition = getInternalProjection(projectionId);
  const projected = cloneValidatedJson(document);
  const record = asMutableJsonRecord(projected, "Projected document");
  assertProjectionMarker(record, definition);

  for (const pointer of definition.excluded_json_pointers) {
    removePointer(projected, pointer);
  }
  for (const pointer of definition.set_like_array_pointers) {
    sortSetLikeArray(projected, pointer);
  }
  return projected;
}

export function unsafeComputeDomainIdentity(projectionId: DomainProjectionId, document: unknown): Sha256Digest {
  return sha256Canonical(unsafeProjectDocument(projectionId, document));
}

export function unsafeComputeContentIdentity(document: unknown): Sha256Digest {
  return sha256Canonical(unsafeProjectDocument("document-content-v1", document));
}

export function unsafeWithContentIdentity<T extends Record<string, unknown>>(document: T): T & { content_sha256: Sha256Digest } {
  const projected = asMutableJsonRecord(unsafeProjectDocument("document-content-v1", document), "Content document");
  const content_sha256 = sha256Canonical(projected);
  return { ...projected, content_sha256 } as T & { content_sha256: Sha256Digest };
}

export function unsafeWithDocumentIdentities<T extends Record<string, unknown>>(
  projectionId: DomainProjectionId,
  document: T,
): T & Record<string, unknown> & { content_sha256: Sha256Digest } {
  const definition = getInternalProjection(projectionId);
  if (definition.digest_field === null) {
    throw new ProjectionError(`${projectionId} is not a domain projection`);
  }

  const domainProjectionValue = asMutableJsonRecord(unsafeProjectDocument(projectionId, document), "Domain document");
  const domainDigest = sha256Canonical(domainProjectionValue);
  const withDomain = { ...domainProjectionValue, [definition.digest_field]: domainDigest };
  const contentDigest = unsafeComputeContentIdentity(withDomain);
  return { ...withDomain, content_sha256: contentDigest } as T & Record<string, unknown> & {
    content_sha256: Sha256Digest;
  };
}

export function unsafeVerifyContentIdentity(document: unknown): boolean {
  const cloned = asMutableJsonRecord(cloneValidatedJson(document), "Content document");
  return typeof cloned["content_sha256"] === "string" && cloned["content_sha256"] === unsafeComputeContentIdentity(cloned);
}

export function unsafeVerifyDocumentIdentities(projectionId: DomainProjectionId, document: unknown): boolean {
  const definition = getInternalProjection(projectionId);
  const cloned = asMutableJsonRecord(cloneValidatedJson(document), "Domain document");
  const digestField = definition.digest_field;
  return (
    digestField !== null &&
    typeof cloned[digestField] === "string" &&
    cloned[digestField] === unsafeComputeDomainIdentity(projectionId, cloned) &&
    unsafeVerifyContentIdentity(cloned)
  );
}
