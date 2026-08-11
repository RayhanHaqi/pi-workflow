import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import {
  identifyContractDocument,
  type M4AdmissionRefusalDocument,
  type M4ToolRequestDocument,
  type M4ToolResultDocument,
} from "../schemas/index.js";
import type { M4StorageLocation } from "./records.js";
import { publishM4AdmissionRefusalRecord, publishM4Record } from "./records.js";

export interface M4AttemptedMutationInput {
  readonly path: string;
  readonly operation: "CREATE" | "REPLACE" | "DELETE";
  readonly replacementBytes: Uint8Array | null;
  readonly expectedPreimageExists: boolean;
  readonly expectedPreimageDigest: Sha256Digest | null;
  readonly expectedPreimageSize: number | null;
  readonly expectedPreimageMode: number | null;
}

/**
 * Producer-owned normalized operation identity. Replacement bytes never enter
 * durable refusal evidence; only their exact digest and length do.
 */
export function m4AttemptedMutationProjection(input: M4AttemptedMutationInput) {
  const replacement = input.replacementBytes === null ? null : Buffer.from(input.replacementBytes);
  return {
    projection_id: "m4-admission-attempt-v0" as const,
    tool_class: "APPLY_PATCH_SCOPED" as const,
    operation: input.operation,
    target_path: input.path,
    expected_preimage: {
      exists: input.expectedPreimageExists,
      content_sha256: input.expectedPreimageDigest,
      byte_length: input.expectedPreimageSize,
      mode: input.expectedPreimageMode,
    },
    replacement: {
      content_sha256: replacement === null ? null : sha256Bytes(replacement),
      byte_length: replacement?.byteLength ?? 0,
    },
    requested_final_mode: input.operation === "DELETE" ? null : 0o644,
    ownership_class: "OWNER_ACCEPTED_MUTABLE" as const,
    data_class: "PUBLIC_SOURCE" as const,
  };
}

export function m4AttemptedMutationIdentity(input: M4AttemptedMutationInput): Sha256Digest {
  return sha256Canonical(m4AttemptedMutationProjection(input));
}

interface M4AdmissionRefusalPublicationInput {
  readonly boundedWorkerInvocationContentSha256: Sha256Digest;
  readonly admissionStateTokenContentSha256: Sha256Digest;
  readonly attemptedMutation: M4AttemptedMutationInput;
  readonly refusalCode: M4AdmissionRefusalDocument["refusal_code"];
}

/** Package-internal producer path used only by the bounded-worker M4 admission closure. */
export async function publishBoundedWorkerM4AdmissionRefusal(
  location: M4StorageLocation,
  input: M4AdmissionRefusalPublicationInput,
): Promise<M4AdmissionRefusalDocument> {
  const document = identifyContractDocument("pi_gacw_m4_admission_refusal_v0", {
    schema_id: "pi_gacw_m4_admission_refusal_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: location.runId,
    bounded_worker_invocation_content_sha256: input.boundedWorkerInvocationContentSha256,
    admission_state_token_content_sha256: input.admissionStateTokenContentSha256,
    attempted_operation: m4AttemptedMutationProjection(input.attemptedMutation),
    attempted_operation_content_sha256: m4AttemptedMutationIdentity(input.attemptedMutation),
    disposition: "REFUSED",
    refusal_code: input.refusalCode,
  }) as M4AdmissionRefusalDocument;
  await publishM4AdmissionRefusalRecord(location, document);
  return document;
}

export async function createToolRequest(
  location: M4StorageLocation,
  kind: M4ToolRequestDocument["request_kind"],
  stateToken: Sha256Digest,
  toolPolicy: Sha256Digest,
  taskScope: Sha256Digest,
  path: string | null,
  commandId: string | null,
  authority: Readonly<{
    secureFilesystem: Sha256Digest | null;
    sandbox: Sha256Digest | null;
    commandCatalog: Sha256Digest | null;
    commandSpecification: Sha256Digest | null;
  }>,
  metadata: unknown,
): Promise<M4ToolRequestDocument> {
  const document = identifyContractDocument("pi_gacw_tool_request_v0", {
    schema_id: "pi_gacw_tool_request_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: location.runId,
    request_kind: kind,
    requested_at: new Date().toISOString(),
    state_token_content_sha256: stateToken,
    tool_policy_content_sha256: toolPolicy,
    task_scope_identity: taskScope,
    path,
    command_id: commandId,
    secure_fs_capability_content_sha256: authority.secureFilesystem,
    sandbox_capability_content_sha256: authority.sandbox,
    command_catalog_content_sha256: authority.commandCatalog,
    command_spec_sha256: authority.commandSpecification,
    request_metadata_sha256: sha256Canonical(metadata),
  }) as M4ToolRequestDocument;
  await publishM4Record(location, "TOOL_REQUEST", document);
  return document;
}

export async function createToolResult(
  location: M4StorageLocation,
  request: M4ToolRequestDocument,
  kind: M4ToolResultDocument["result_kind"],
  path: string | null,
  dataClass: M4ToolResultDocument["data_class"],
  contentDigest: Sha256Digest | null,
  byteCount: number,
  itemCount: number,
  outputDigest: Sha256Digest,
  outcome: M4ToolResultDocument["outcome"],
): Promise<M4ToolResultDocument> {
  const document = identifyContractDocument("pi_gacw_tool_result_v0", {
    schema_id: "pi_gacw_tool_result_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: location.runId,
    request_content_sha256: request.content_sha256,
    result_kind: kind,
    state_token_content_sha256: request.state_token_content_sha256,
    path,
    data_class: dataClass,
    content_digest: contentDigest,
    byte_count: byteCount,
    item_count: itemCount,
    output_digest: outputDigest,
    outcome,
    completed_at: new Date().toISOString(),
  }) as M4ToolResultDocument;
  await publishM4Record(location, "TOOL_RESULT", document);
  return document;
}
