import { sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { identifyContractDocument, type M4ToolRequestDocument, type M4ToolResultDocument } from "../schemas/index.js";
import type { M4StorageLocation } from "./records.js";
import { publishM4Record } from "./records.js";

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
