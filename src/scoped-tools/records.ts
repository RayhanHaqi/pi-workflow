import { lstat, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import type { Sha256Digest } from "../identity/index.js";
import { assertPrivateDirectory, assertRegularPrivateFile, publishImmutableFile } from "../persistence/atomic.js";
import { inspectRunStorage } from "../persistence/index.js";
import { assertStateRootCapacity } from "../repository/storage.js";
import { assertAbsoluteNormalizedPath, assertDigest, assertNonemptyString, detachedFrozen, digestHex } from "../repository/utils.js";
import {
  assertDocumentValid,
  type M4AdmissionRefusalDocument,
  type M4CommandCatalogDocument,
  type M4CommandResultDocument,
  type M4MutationReceiptDocument,
  type M4PatchRequestDocument,
  type M4SandboxCapabilityDocument,
  type M4ScopedToolPolicyDocument,
  type M4SecureFilesystemCapabilityDocument,
  type M4ToolRequestDocument,
  type M4ToolResultDocument,
  type SchemaId,
} from "../schemas/index.js";
import { ScopedToolGatewayError, scopedToolError } from "./errors.js";

export type M4RecordKind =
  | "SECURE_FS_CAPABILITY"
  | "SANDBOX_CAPABILITY"
  | "TOOL_POLICY"
  | "COMMAND_CATALOG"
  | "TOOL_REQUEST"
  | "PATCH_REQUEST"
  | "TOOL_RESULT"
  | "MUTATION_RECEIPT"
  | "COMMAND_RESULT"
  | "ADMISSION_REFUSAL";

export type M4RecordDocumentByKind = {
  readonly ADMISSION_REFUSAL: M4AdmissionRefusalDocument;
  readonly SECURE_FS_CAPABILITY: M4SecureFilesystemCapabilityDocument;
  readonly SANDBOX_CAPABILITY: M4SandboxCapabilityDocument;
  readonly TOOL_POLICY: M4ScopedToolPolicyDocument;
  readonly COMMAND_CATALOG: M4CommandCatalogDocument;
  readonly TOOL_REQUEST: M4ToolRequestDocument;
  readonly PATCH_REQUEST: M4PatchRequestDocument;
  readonly TOOL_RESULT: M4ToolResultDocument;
  readonly MUTATION_RECEIPT: M4MutationReceiptDocument;
  readonly COMMAND_RESULT: M4CommandResultDocument;
};

export const M4_RECORD_DEFINITIONS: Readonly<Record<M4RecordKind, {
  readonly directory: string;
  readonly schemaId: SchemaId;
  readonly persistenceKind: string;
}>> = Object.freeze({
  SECURE_FS_CAPABILITY: { directory: "secure-fs-capabilities", schemaId: "pi_gacw_secure_fs_capability_v0", persistenceKind: "M4_SECURE_FS_CAPABILITY" },
  SANDBOX_CAPABILITY: { directory: "sandbox-capabilities", schemaId: "pi_gacw_sandbox_capability_v0", persistenceKind: "M4_SANDBOX_CAPABILITY" },
  TOOL_POLICY: { directory: "tool-policies", schemaId: "pi_gacw_scoped_tool_policy_v0", persistenceKind: "M4_TOOL_POLICY" },
  COMMAND_CATALOG: { directory: "command-catalogs", schemaId: "pi_gacw_command_catalog_v0", persistenceKind: "M4_COMMAND_CATALOG" },
  TOOL_REQUEST: { directory: "tool-requests", schemaId: "pi_gacw_tool_request_v0", persistenceKind: "M4_TOOL_REQUEST" },
  PATCH_REQUEST: { directory: "patch-requests", schemaId: "pi_gacw_patch_request_v0", persistenceKind: "M4_PATCH_REQUEST" },
  TOOL_RESULT: { directory: "tool-results", schemaId: "pi_gacw_tool_result_v0", persistenceKind: "M4_TOOL_RESULT" },
  MUTATION_RECEIPT: { directory: "mutation-receipts", schemaId: "pi_gacw_mutation_receipt_v0", persistenceKind: "M4_MUTATION_RECEIPT" },
  COMMAND_RESULT: { directory: "command-results", schemaId: "pi_gacw_command_result_v0", persistenceKind: "M4_COMMAND_RESULT" },
  ADMISSION_REFUSAL: { directory: "m4-admission-refusals", schemaId: "pi_gacw_m4_admission_refusal_v0", persistenceKind: "M4_ADMISSION_REFUSAL" },
});

export interface M4StorageLocation { readonly stateRoot: string; readonly runId: string }

function assertLocation(location: M4StorageLocation): void {
  assertAbsoluteNormalizedPath(location.stateRoot, "stateRoot");
  assertNonemptyString(location.runId, "runId", 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(location.runId)) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "runId is invalid");
}

function directory(location: M4StorageLocation, kind: M4RecordKind): string {
  return join(location.stateRoot, "runs", location.runId, "records", M4_RECORD_DEFINITIONS[kind].directory);
}

export function m4RecordPath(location: M4StorageLocation, kind: M4RecordKind, digest: string): string {
  assertLocation(location); assertDigest(digest, "M4 record digest");
  return join(directory(location, kind), `${digestHex(digest)}.json`);
}

export function canonicalM4RecordBytes(value: unknown): Buffer {
  return Buffer.from(`${canonicalize(value)}\n`, "utf8");
}

async function assertUsable(location: M4StorageLocation): Promise<void> {
  const inspection = await inspectRunStorage(location);
  if (inspection.status !== "HEALTHY") throw new ScopedToolGatewayError("EVIDENCE_PUBLICATION_FAILED", "Run storage is not healthy", { status: inspection.status });
}

type GenericM4RecordKind = Exclude<M4RecordKind, "ADMISSION_REFUSAL">;

async function publishRecord<K extends M4RecordKind>(
  location: M4StorageLocation,
  kind: K,
  document: M4RecordDocumentByKind[K],
): Promise<{ readonly relativePath: string; readonly reused: boolean }> {
  assertLocation(location);
  const definition = M4_RECORD_DEFINITIONS[kind];
  try {
    assertDocumentValid(definition.schemaId, document);
    const runId = (document as unknown as Record<string, unknown>)["run_id"];
    if (runId !== undefined && runId !== location.runId) throw new ScopedToolGatewayError("EVIDENCE_PUBLICATION_FAILED", "M4 record run identity differs");
    const bytes = canonicalM4RecordBytes(document);
    await assertUsable(location);
    await assertPrivateDirectory(directory(location, kind));
    await assertStateRootCapacity(location.stateRoot, bytes.byteLength);
    const path = m4RecordPath(location, kind, document.content_sha256);
    const published = await publishImmutableFile(path, bytes, "RECORD");
    return detachedFrozen({ relativePath: relative(join(location.stateRoot, "runs", location.runId), path).split(sep).join("/"), reused: published.reused });
  } catch (error: unknown) {
    if (error instanceof ScopedToolGatewayError) throw error;
    throw scopedToolError("EVIDENCE_PUBLICATION_FAILED", `Cannot publish immutable ${kind} record`, error);
  }
}

/** Generic M4 persistence excludes producer-only admission refusals. */
export async function publishM4Record<K extends GenericM4RecordKind>(
  location: M4StorageLocation,
  kind: K,
  document: M4RecordDocumentByKind[K],
): Promise<{ readonly relativePath: string; readonly reused: boolean }> {
  if ((kind as M4RecordKind) === "ADMISSION_REFUSAL") {
    throw new ScopedToolGatewayError("EVIDENCE_PUBLICATION_FAILED", "M4 admission refusals require the bounded-worker producer path");
  }
  return publishRecord(location, kind, document);
}

/** Package-internal bounded-admission publication path; not exported by ./scoped-tools. */
export async function publishM4AdmissionRefusalRecord(
  location: M4StorageLocation,
  document: M4AdmissionRefusalDocument,
): Promise<{ readonly relativePath: string; readonly reused: boolean }> {
  // Refuse before publication unless the exact immutable invocation already
  // exists as trusted managed authority; this prevents an orphan refusal from
  // ever becoming a substitute for the producer ordering guarantee.
  const predecessor = await inspectRunStorage(location);
  const invocation = predecessor.managedRecordClassifications.find((entry) =>
    entry.object.kind === "BOUNDED_WORKER_INVOCATION" && entry.object.contentSha256 === document.bounded_worker_invocation_content_sha256,
  );
  if (predecessor.status !== "HEALTHY" || invocation?.classification !== "AUTHORITATIVE_MANAGED_RECORD") {
    throw new ScopedToolGatewayError("EVIDENCE_PUBLICATION_FAILED", "M4 admission refusal requires a prior authoritative bounded invocation", {
      invocation: invocation?.classification ?? "ABSENT",
    });
  }
  const published = await publishRecord(location, "ADMISSION_REFUSAL", document);
  const inspection = await inspectRunStorage(location);
  const classification = inspection.managedRecordClassifications.find((entry) =>
    entry.object.kind === "M4_ADMISSION_REFUSAL" && entry.object.contentSha256 === document.content_sha256,
  );
  if (inspection.status !== "HEALTHY" || classification?.classification !== "AUTHORITATIVE_MANAGED_RECORD") {
    throw new ScopedToolGatewayError("EVIDENCE_PUBLICATION_FAILED", "M4 admission refusal lacks exact producer authority", {
      classification: classification?.classification ?? "ABSENT",
    });
  }
  return published;
}

export async function readM4Record<K extends M4RecordKind>(
  location: M4StorageLocation,
  kind: K,
  digest: Sha256Digest,
): Promise<M4RecordDocumentByKind[K]> {
  assertLocation(location); assertDigest(digest, "M4 record digest");
  const definition = M4_RECORD_DEFINITIONS[kind];
  try {
    const path = m4RecordPath(location, kind, digest);
    await assertRegularPrivateFile(path);
    const bytes = await readFile(path);
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    assertDocumentValid(definition.schemaId, value);
    const record = value as Record<string, unknown>;
    if (record["content_sha256"] !== digest || !bytes.equals(canonicalM4RecordBytes(record))) throw new Error("address or canonical bytes mismatch");
    const runId = record["run_id"];
    if (runId !== undefined && runId !== location.runId) throw new Error("run mismatch");
    return detachedFrozen(value as M4RecordDocumentByKind[K]);
  } catch (error: unknown) {
    throw scopedToolError("EVIDENCE_PUBLICATION_FAILED", `Immutable ${kind} record is missing or invalid`, error);
  }
}

export async function m4RecordExists(location: M4StorageLocation, kind: M4RecordKind, digest: Sha256Digest): Promise<boolean> {
  try { return (await lstat(m4RecordPath(location, kind, digest))).isFile(); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}
