import { constants, type Stats } from "node:fs";
import { lstat, open, readFile, readdir } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import { assertSha256Digest, sha256Bytes, type Sha256Digest } from "../identity/index.js";
import {
  assertDocumentValid,
  assertReducerPolicy,
  assertStatePolicyConsistency,
  assertTransitionEvent,
  assertWorkflowState,
  identifyContractDocument,
  type EvidenceManifestDocument,
  type EvidenceMetadataDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3PostflightDocument,
  type M3PreflightDocument,
  type M3RepositoryStateTokenDocument,
  type M3RetentionResultDocument,
  type M3TerminalRetentionAuthorityDocument,
  type M4CommandCatalogDocument,
  type M4CommandResultDocument,
  type M4MutationReceiptDocument,
  type M4PatchRequestDocument,
  type M4SandboxCapabilityDocument,
  type M4ScopedToolPolicyDocument,
  type M4SecureFilesystemCapabilityDocument,
  type M4ToolRequestDocument,
  type M4ToolResultDocument,
  type PersistedStatePointerDocument,
  type ProcessInterruptionDocument,
  type ProcessMetadata,
  type ReducerPolicy,
  type SchemaId,
  type StateTransitionCommitDocument,
  type TransitionEvent,
  type WorkflowState,
} from "../schemas/index.js";
import { createInitialState, reduceState } from "../state-machine/index.js";
import { classifyManagedAuthority } from "./managed-authority.js";
import { classifyM4Authority } from "./m4-authority.js";
import {
  assertPrivateDirectory,
  assertRegularPrivateFile,
  ensurePrivateDirectory,
  publishImmutableFile,
  replaceStateFile,
} from "./atomic.js";
import { StateStoreError, stateStoreError } from "./errors.js";
import type {
  CommitTransitionInput,
  CommittedRunState,
  EvidenceInput,
  EvidenceReceipt,
  InitializeRunStorageInput,
  InspectedObject,
  InspectionIssue,
  ManagedRecordClassification,
  ProcessInterruptionEvidence,
  RunStorageInspection,
  RunStorageLocation,
  StoredObjectKind,
  TerminalizeProcessCrashInput,
} from "./types.js";

const MAX_EVIDENCE_BYTES = 16_777_216;
const MAX_EVIDENCE_PER_TRANSITION = 1024;
const RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST_FILE_PATTERN = /^[0-9a-f]{64}$/;
const JSON_DIGEST_FILE_PATTERN = /^[0-9a-f]{64}\.json$/;

interface RunLayout {
  readonly stateRoot: string;
  readonly locksDirectory: string;
  readonly runsDirectory: string;
  readonly runDirectory: string;
  readonly stateFile: string;
  readonly rawEvidenceDirectory: string;
  readonly baselineBlobDirectory: string;
  readonly recordsDirectory: string;
  readonly evidenceMetadataDirectory: string;
  readonly evidenceManifestDirectory: string;
  readonly workflowStateDirectory: string;
  readonly transitionEventDirectory: string;
  readonly reducerPolicyDirectory: string;
  readonly processAssessmentDirectory: string;
  readonly baselineRecordDirectory: string;
  readonly baselineApprovalRecordDirectory: string;
  readonly lockAcquisitionRecordDirectory: string;
  readonly lockDiagnosticRecordDirectory: string;
  readonly preflightRecordDirectory: string;
  readonly repositoryStateTokenDirectory: string;
  readonly postflightRecordDirectory: string;
  readonly retentionRecordDirectory: string;
  readonly secureFilesystemCapabilityDirectory: string;
  readonly sandboxCapabilityDirectory: string;
  readonly toolPolicyDirectory: string;
  readonly commandCatalogDirectory: string;
  readonly toolRequestDirectory: string;
  readonly patchRequestDirectory: string;
  readonly toolResultDirectory: string;
  readonly mutationReceiptDirectory: string;
  readonly commandResultDirectory: string;
  readonly commitsDirectory: string;
}

type JsonStoredObjectKind = Exclude<StoredObjectKind, "RAW_EVIDENCE" | "M3_BASELINE_BLOB" | "M3_TERMINAL_RETENTION_AUTHORITY">;

interface JsonKindDefinition {
  readonly kind: JsonStoredObjectKind;
  readonly schemaId: SchemaId;
  readonly directory: keyof Pick<
    RunLayout,
    | "evidenceMetadataDirectory"
    | "evidenceManifestDirectory"
    | "workflowStateDirectory"
    | "transitionEventDirectory"
    | "reducerPolicyDirectory"
    | "processAssessmentDirectory"
    | "baselineRecordDirectory"
    | "baselineApprovalRecordDirectory"
    | "lockAcquisitionRecordDirectory"
    | "lockDiagnosticRecordDirectory"
    | "preflightRecordDirectory"
    | "repositoryStateTokenDirectory"
    | "postflightRecordDirectory"
    | "retentionRecordDirectory"
    | "secureFilesystemCapabilityDirectory"
    | "sandboxCapabilityDirectory"
    | "toolPolicyDirectory"
    | "commandCatalogDirectory"
    | "toolRequestDirectory"
    | "patchRequestDirectory"
    | "toolResultDirectory"
    | "mutationReceiptDirectory"
    | "commandResultDirectory"
    | "commitsDirectory"
  >;
}

const JSON_KINDS: readonly JsonKindDefinition[] = Object.freeze([
  { kind: "EVIDENCE_METADATA", schemaId: "pi_gacw_evidence_metadata_v0", directory: "evidenceMetadataDirectory" },
  { kind: "EVIDENCE_MANIFEST", schemaId: "pi_gacw_evidence_manifest_v0", directory: "evidenceManifestDirectory" },
  { kind: "WORKFLOW_STATE", schemaId: "pi_gacw_state_v0", directory: "workflowStateDirectory" },
  { kind: "TRANSITION_EVENT", schemaId: "pi_gacw_transition_event_v0", directory: "transitionEventDirectory" },
  { kind: "REDUCER_POLICY", schemaId: "pi_gacw_reducer_policy_v0", directory: "reducerPolicyDirectory" },
  { kind: "PROCESS_ASSESSMENT", schemaId: "pi_gacw_process_interruption_v0", directory: "processAssessmentDirectory" },
  { kind: "TRANSITION_COMMIT", schemaId: "pi_gacw_state_transition_commit_v0", directory: "commitsDirectory" },
  { kind: "M3_BASELINE", schemaId: "pi_gacw_baseline_runtime_v0", directory: "baselineRecordDirectory" },
  { kind: "M3_BASELINE_APPROVAL", schemaId: "pi_gacw_baseline_approval_runtime_v0", directory: "baselineApprovalRecordDirectory" },
  { kind: "M3_LOCK_ACQUISITION", schemaId: "pi_gacw_lock_acquisition_v0", directory: "lockAcquisitionRecordDirectory" },
  { kind: "M3_LOCK_DIAGNOSTIC", schemaId: "pi_gacw_lock_diagnostic_v0", directory: "lockDiagnosticRecordDirectory" },
  { kind: "M3_PREFLIGHT", schemaId: "pi_gacw_preflight_v0", directory: "preflightRecordDirectory" },
  { kind: "M3_REPOSITORY_STATE_TOKEN", schemaId: "pi_gacw_repository_state_token_v0", directory: "repositoryStateTokenDirectory" },
  { kind: "M3_POSTFLIGHT", schemaId: "pi_gacw_postflight_v0", directory: "postflightRecordDirectory" },
  { kind: "M3_RETENTION_RESULT", schemaId: "pi_gacw_retention_result_v0", directory: "retentionRecordDirectory" },
  { kind: "M4_SECURE_FS_CAPABILITY", schemaId: "pi_gacw_secure_fs_capability_v0", directory: "secureFilesystemCapabilityDirectory" },
  { kind: "M4_SANDBOX_CAPABILITY", schemaId: "pi_gacw_sandbox_capability_v0", directory: "sandboxCapabilityDirectory" },
  { kind: "M4_TOOL_POLICY", schemaId: "pi_gacw_scoped_tool_policy_v0", directory: "toolPolicyDirectory" },
  { kind: "M4_COMMAND_CATALOG", schemaId: "pi_gacw_command_catalog_v0", directory: "commandCatalogDirectory" },
  { kind: "M4_TOOL_REQUEST", schemaId: "pi_gacw_tool_request_v0", directory: "toolRequestDirectory" },
  { kind: "M4_PATCH_REQUEST", schemaId: "pi_gacw_patch_request_v0", directory: "patchRequestDirectory" },
  { kind: "M4_TOOL_RESULT", schemaId: "pi_gacw_tool_result_v0", directory: "toolResultDirectory" },
  { kind: "M4_MUTATION_RECEIPT", schemaId: "pi_gacw_mutation_receipt_v0", directory: "mutationReceiptDirectory" },
  { kind: "M4_COMMAND_RESULT", schemaId: "pi_gacw_command_result_v0", directory: "commandResultDirectory" },
]);

const JSON_KIND_BY_NAME = new Map(JSON_KINDS.map((definition) => [definition.kind, definition]));
const JSON_KIND_BY_DIRECTORY = new Map(JSON_KINDS.map((definition) => [definition.directory, definition]));

function deepFreeze<T>(value: T, seen = new Set<object>()): T {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && "value" in descriptor) deepFreeze(descriptor.value, seen);
  }
  Object.freeze(object);
  return value;
}

function detachedFrozen<T>(value: T): T {
  return deepFreeze(structuredClone(value));
}

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new StateStoreError("INVALID_ARGUMENT", `${label} must be an object`);
  }
}

function assertExactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalize(actual) !== canonicalize(expected)) {
    throw new StateStoreError("INVALID_ARGUMENT", `${label} has unexpected or missing fields`);
  }
}

function assertRequiredAndOptionalKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const actual = new Set(Object.keys(value));
  for (const key of required) {
    if (!actual.has(key)) throw new StateStoreError("INVALID_ARGUMENT", `${label} is missing ${key}`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of actual) {
    if (!allowed.has(key)) throw new StateStoreError("INVALID_ARGUMENT", `${label} contains unexpected field ${key}`);
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertDigestArgument(value: unknown, label: string): asserts value is Sha256Digest {
  try {
    assertSha256Digest(value, label);
  } catch (error: unknown) {
    throw stateStoreError("INVALID_ARGUMENT", `${label} must be a SHA-256 digest`, error);
  }
}

function assertIdentifier(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new StateStoreError("INVALID_ARGUMENT", `${label} is not a valid identifier`);
  }
}

function assertProcessMetadata(value: unknown): asserts value is ProcessMetadata {
  assertRecord(value, "processMetadata");
  assertExactKeys(value, ["controller_instance_id", "process_id", "invocation_id"], "processMetadata");
  assertIdentifier(value["controller_instance_id"], "processMetadata.controller_instance_id");
  assertIdentifier(value["invocation_id"], "processMetadata.invocation_id");
  if (!Number.isInteger(value["process_id"]) || (value["process_id"] as number) < 1 || (value["process_id"] as number) > 2_147_483_647) {
    throw new StateStoreError("INVALID_ARGUMENT", "processMetadata.process_id is out of range");
  }
}

function assertInterruptionEvidence(value: unknown): asserts value is ProcessInterruptionEvidence {
  assertRecord(value, "interruptionEvidence");
  assertExactKeys(
    value,
    ["controller_instance_id", "process_id", "invocation_id", "exit_kind", "detail"],
    "interruptionEvidence",
  );
  assertIdentifier(value["controller_instance_id"], "interruptionEvidence.controller_instance_id");
  assertIdentifier(value["invocation_id"], "interruptionEvidence.invocation_id");
  if (!Number.isInteger(value["process_id"]) || (value["process_id"] as number) < 1 || (value["process_id"] as number) > 2_147_483_647) {
    throw new StateStoreError("INVALID_ARGUMENT", "interruptionEvidence.process_id is out of range");
  }
  if (value["exit_kind"] !== "UNEXPECTED_TERMINATION") {
    throw new StateStoreError("INVALID_ARGUMENT", "interruptionEvidence.exit_kind must be UNEXPECTED_TERMINATION");
  }
  if (typeof value["detail"] !== "string" || value["detail"].trim().length === 0 || value["detail"].length > 4096) {
    throw new StateStoreError("INVALID_ARGUMENT", "interruptionEvidence.detail must be nonempty and bounded");
  }
}

function assertLocation(input: RunStorageLocation): RunLayout {
  assertRecord(input, "persistence input");
  if (
    typeof input.stateRoot !== "string" ||
    input.stateRoot.length === 0 ||
    input.stateRoot.includes("\u0000") ||
    !isAbsolute(input.stateRoot) ||
    resolve(input.stateRoot) !== input.stateRoot
  ) {
    throw new StateStoreError("INVALID_STATE_ROOT", "stateRoot must be an absolute normalized path without NUL");
  }
  if (typeof input.runId !== "string" || !RUN_ID_PATTERN.test(input.runId)) {
    throw new StateStoreError("INVALID_RUN_ID", "runId must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$");
  }
  const locksDirectory = join(input.stateRoot, "locks");
  const runsDirectory = join(input.stateRoot, "runs");
  const runDirectory = join(runsDirectory, input.runId);
  const recordsDirectory = join(runDirectory, "records");
  return {
    stateRoot: input.stateRoot,
    locksDirectory,
    runsDirectory,
    runDirectory,
    stateFile: join(runDirectory, "state.json"),
    rawEvidenceDirectory: join(runDirectory, "evidence", "sha256"),
    baselineBlobDirectory: join(runDirectory, "baseline-blobs", "sha256"),
    recordsDirectory,
    evidenceMetadataDirectory: join(recordsDirectory, "evidence-metadata"),
    evidenceManifestDirectory: join(recordsDirectory, "evidence-manifests"),
    workflowStateDirectory: join(recordsDirectory, "workflow-states"),
    transitionEventDirectory: join(recordsDirectory, "transition-events"),
    reducerPolicyDirectory: join(recordsDirectory, "reducer-policies"),
    processAssessmentDirectory: join(recordsDirectory, "process-assessments"),
    baselineRecordDirectory: join(recordsDirectory, "baselines"),
    baselineApprovalRecordDirectory: join(recordsDirectory, "baseline-approvals"),
    lockAcquisitionRecordDirectory: join(recordsDirectory, "lock-acquisitions"),
    lockDiagnosticRecordDirectory: join(recordsDirectory, "lock-diagnostics"),
    preflightRecordDirectory: join(recordsDirectory, "preflights"),
    repositoryStateTokenDirectory: join(recordsDirectory, "repository-state-tokens"),
    postflightRecordDirectory: join(recordsDirectory, "postflights"),
    retentionRecordDirectory: join(recordsDirectory, "retention"),
    secureFilesystemCapabilityDirectory: join(recordsDirectory, "secure-fs-capabilities"),
    sandboxCapabilityDirectory: join(recordsDirectory, "sandbox-capabilities"),
    toolPolicyDirectory: join(recordsDirectory, "tool-policies"),
    commandCatalogDirectory: join(recordsDirectory, "command-catalogs"),
    toolRequestDirectory: join(recordsDirectory, "tool-requests"),
    patchRequestDirectory: join(recordsDirectory, "patch-requests"),
    toolResultDirectory: join(recordsDirectory, "tool-results"),
    mutationReceiptDirectory: join(recordsDirectory, "mutation-receipts"),
    commandResultDirectory: join(recordsDirectory, "command-results"),
    commitsDirectory: join(runDirectory, "commits"),
  };
}

function digestHex(digest: string): string {
  try {
    assertSha256Digest(digest);
  } catch (error: unknown) {
    throw stateStoreError("INVALID_DIGEST", `Invalid SHA-256 digest ${JSON.stringify(digest)}`, error);
  }
  return digest.slice("sha256:".length);
}

function jsonObjectPath(layout: RunLayout, kind: JsonStoredObjectKind, digest: string): string {
  const definition = JSON_KIND_BY_NAME.get(kind);
  if (definition === undefined) throw new StateStoreError("UNKNOWN_OBJECT_KIND", kind);
  return join(layout[definition.directory], `${digestHex(digest)}.json`);
}

function rawEvidencePath(layout: RunLayout, digest: string): string {
  return join(layout.rawEvidenceDirectory, digestHex(digest));
}

function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(`${canonicalize(value)}\n`, "utf8");
}

function toRelative(layout: RunLayout, path: string): string {
  return relative(layout.runDirectory, path).split(sep).join("/");
}

async function existingStats(path: string): Promise<Stats | undefined> {
  try {
    return await lstat(path);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function initializeLayout(layout: RunLayout): Promise<void> {
  await ensurePrivateDirectory(layout.stateRoot);
  const hasRunsDirectory = await requireInitializableTopLevelLayout(layout, true);
  if (!hasRunsDirectory) await ensurePrivateDirectory(layout.runsDirectory);
  const locksStats = await existingStats(layout.locksDirectory);
  if (locksStats === undefined) await ensurePrivateDirectory(layout.locksDirectory);
  await requireInitializableTopLevelLayout(layout, false);

  const runStats = await existingStats(layout.runDirectory);
  if (runStats !== undefined) {
    await assertPrivateDirectory(layout.runDirectory);
    if ((await readdir(layout.runDirectory)).length !== 0) {
      throw new StateStoreError("RUN_DIRECTORY_NOT_EMPTY", `Run directory is not new or empty: ${layout.runDirectory}`);
    }
  } else {
    await ensurePrivateDirectory(layout.runDirectory);
  }

  await ensurePrivateDirectory(join(layout.runDirectory, "evidence"));
  await ensurePrivateDirectory(layout.rawEvidenceDirectory);
  await ensurePrivateDirectory(join(layout.runDirectory, "baseline-blobs"));
  await ensurePrivateDirectory(layout.baselineBlobDirectory);
  await ensurePrivateDirectory(layout.recordsDirectory);
  await ensurePrivateDirectory(layout.evidenceMetadataDirectory);
  await ensurePrivateDirectory(layout.evidenceManifestDirectory);
  await ensurePrivateDirectory(layout.workflowStateDirectory);
  await ensurePrivateDirectory(layout.transitionEventDirectory);
  await ensurePrivateDirectory(layout.reducerPolicyDirectory);
  await ensurePrivateDirectory(layout.processAssessmentDirectory);
  await ensurePrivateDirectory(layout.baselineRecordDirectory);
  await ensurePrivateDirectory(layout.baselineApprovalRecordDirectory);
  await ensurePrivateDirectory(layout.lockAcquisitionRecordDirectory);
  await ensurePrivateDirectory(layout.lockDiagnosticRecordDirectory);
  await ensurePrivateDirectory(layout.preflightRecordDirectory);
  await ensurePrivateDirectory(layout.repositoryStateTokenDirectory);
  await ensurePrivateDirectory(layout.postflightRecordDirectory);
  await ensurePrivateDirectory(layout.retentionRecordDirectory);
  await ensurePrivateDirectory(layout.secureFilesystemCapabilityDirectory);
  await ensurePrivateDirectory(layout.sandboxCapabilityDirectory);
  await ensurePrivateDirectory(layout.toolPolicyDirectory);
  await ensurePrivateDirectory(layout.commandCatalogDirectory);
  await ensurePrivateDirectory(layout.toolRequestDirectory);
  await ensurePrivateDirectory(layout.patchRequestDirectory);
  await ensurePrivateDirectory(layout.toolResultDirectory);
  await ensurePrivateDirectory(layout.mutationReceiptDirectory);
  await ensurePrivateDirectory(layout.commandResultDirectory);
  await ensurePrivateDirectory(layout.commitsDirectory);
}

async function assertExistingLayout(layout: RunLayout): Promise<void> {
  for (const directory of [
    layout.stateRoot,
    layout.locksDirectory,
    layout.runsDirectory,
    layout.runDirectory,
    join(layout.runDirectory, "evidence"),
    layout.rawEvidenceDirectory,
    join(layout.runDirectory, "baseline-blobs"),
    layout.baselineBlobDirectory,
    layout.recordsDirectory,
    layout.evidenceMetadataDirectory,
    layout.evidenceManifestDirectory,
    layout.workflowStateDirectory,
    layout.transitionEventDirectory,
    layout.reducerPolicyDirectory,
    layout.processAssessmentDirectory,
    layout.baselineRecordDirectory,
    layout.baselineApprovalRecordDirectory,
    layout.lockAcquisitionRecordDirectory,
    layout.lockDiagnosticRecordDirectory,
    layout.preflightRecordDirectory,
    layout.repositoryStateTokenDirectory,
    layout.postflightRecordDirectory,
    layout.retentionRecordDirectory,
    layout.secureFilesystemCapabilityDirectory,
    layout.sandboxCapabilityDirectory,
    layout.toolPolicyDirectory,
    layout.commandCatalogDirectory,
    layout.toolRequestDirectory,
    layout.patchRequestDirectory,
    layout.toolResultDirectory,
    layout.mutationReceiptDirectory,
    layout.commandResultDirectory,
    layout.commitsDirectory,
  ]) {
    await assertPrivateDirectory(directory);
  }
}

async function publishJsonDocument(
  layout: RunLayout,
  kind: JsonStoredObjectKind,
  document: Record<string, unknown>,
): Promise<{ readonly reused: boolean }> {
  const definition = JSON_KIND_BY_NAME.get(kind);
  if (definition === undefined) throw new StateStoreError("UNKNOWN_OBJECT_KIND", kind);
  assertDocumentValid(definition.schemaId, document);
  const digest = document["content_sha256"];
  if (typeof digest !== "string") throw new StateStoreError("IDENTITY_MISMATCH", `${kind} has no content identity`);
  const category = kind === "TRANSITION_COMMIT" ? "TRANSITION" as const : "RECORD" as const;
  return publishImmutableFile(jsonObjectPath(layout, kind, digest), canonicalJsonBytes(document), category);
}

async function readJsonDocument<T extends Record<string, unknown>>(
  layout: RunLayout,
  kind: JsonStoredObjectKind,
  contentSha256: string,
): Promise<T> {
  const definition = JSON_KIND_BY_NAME.get(kind);
  if (definition === undefined) throw new StateStoreError("UNKNOWN_OBJECT_KIND", kind);
  const path = jsonObjectPath(layout, kind, contentSha256);
  await assertRegularPrivateFile(path);
  const bytes = await readFile(path);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error: unknown) {
    throw stateStoreError("MALFORMED_IMMUTABLE_RECORD", `${kind} is not valid JSON: ${toRelative(layout, path)}`, error);
  }
  try {
    assertDocumentValid(definition.schemaId, value);
  } catch (error: unknown) {
    throw stateStoreError("INVALID_IMMUTABLE_RECORD", `${kind} failed schema or identity validation: ${toRelative(layout, path)}`, error);
  }
  const record = value as Record<string, unknown>;
  if (record["content_sha256"] !== contentSha256) {
    throw new StateStoreError("CONTENT_ADDRESS_MISMATCH", `${kind} filename does not match its content identity`);
  }
  if (!bytes.equals(canonicalJsonBytes(value))) {
    throw new StateStoreError("NONCANONICAL_RECORD_BYTES", `${kind} bytes are not canonical`);
  }
  return value as T;
}

async function readStatePointer(layout: RunLayout): Promise<PersistedStatePointerDocument> {
  await assertRegularPrivateFile(layout.stateFile);
  const bytes = await readFile(layout.stateFile);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error: unknown) {
    throw stateStoreError("MALFORMED_STATE_POINTER", "state.json is not valid JSON", error);
  }
  try {
    assertDocumentValid("pi_gacw_persisted_state_pointer_v0", value);
  } catch (error: unknown) {
    throw stateStoreError("INVALID_STATE_POINTER", "state.json failed schema or identity validation", error);
  }
  if (!bytes.equals(canonicalJsonBytes(value))) {
    throw new StateStoreError("NONCANONICAL_STATE_POINTER", "state.json bytes are not canonical");
  }
  return value as PersistedStatePointerDocument;
}

async function readRawEvidence(layout: RunLayout, evidenceSha256: string): Promise<Buffer> {
  const path = rawEvidencePath(layout, evidenceSha256);
  await assertRegularPrivateFile(path);
  const bytes = await readFile(path);
  if (sha256Bytes(bytes) !== evidenceSha256) {
    throw new StateStoreError("EVIDENCE_HASH_MISMATCH", `Raw evidence hash mismatch: ${toRelative(layout, path)}`);
  }
  return bytes;
}

interface CapturedEvidenceInput {
  readonly bytes: Buffer;
  readonly mediaType: string;
}

interface PreparedEvidence extends CapturedEvidenceInput {
  readonly evidenceSha256: Sha256Digest;
  readonly reusedEvidence: boolean;
}

function captureEvidenceInputs(inputs: unknown): readonly CapturedEvidenceInput[] {
  if (!Array.isArray(inputs) || inputs.length > MAX_EVIDENCE_PER_TRANSITION) {
    throw new StateStoreError("INVALID_ARGUMENT", `evidence must contain at most ${MAX_EVIDENCE_PER_TRANSITION} entries`);
  }
  const captured: CapturedEvidenceInput[] = [];
  for (let index = 0; index < inputs.length; index += 1) {
    const input: unknown = inputs[index];
    const label = `evidence[${index}]`;
    assertRecord(input, label);
    assertExactKeys(input, ["bytes", "mediaType"], label);
    const bytesInput = input["bytes"];
    if (!(bytesInput instanceof Uint8Array)) {
      throw new StateStoreError("INVALID_ARGUMENT", `${label}.bytes must be a Uint8Array`);
    }
    if (bytesInput.byteLength > MAX_EVIDENCE_BYTES) {
      throw new StateStoreError("EVIDENCE_TOO_LARGE", `Evidence exceeds ${MAX_EVIDENCE_BYTES} bytes`);
    }
    const mediaType = input["mediaType"];
    if (typeof mediaType !== "string" || mediaType.trim().length === 0 || mediaType.length > 255) {
      throw new StateStoreError("INVALID_ARGUMENT", `${label}.mediaType must be nonempty and at most 255 characters`);
    }
    captured.push({ bytes: Buffer.from(bytesInput), mediaType });
  }
  return captured;
}

async function publishEvidenceBytes(
  layout: RunLayout,
  inputs: readonly CapturedEvidenceInput[],
): Promise<readonly PreparedEvidence[]> {
  const prepared: PreparedEvidence[] = [];
  for (const { bytes, mediaType } of inputs) {
    const evidenceSha256 = sha256Bytes(bytes);
    const publication = await publishImmutableFile(rawEvidencePath(layout, evidenceSha256), bytes, "EVIDENCE");
    prepared.push({ bytes, mediaType, evidenceSha256, reusedEvidence: publication.reused });
  }
  return prepared;
}

async function publishEvidenceMetadata(
  layout: RunLayout,
  runId: string,
  prepared: readonly PreparedEvidence[],
): Promise<readonly EvidenceReceipt[]> {
  const receipts: EvidenceReceipt[] = [];
  for (const item of prepared) {
    const metadata = identifyContractDocument("pi_gacw_evidence_metadata_v0", {
      schema_id: "pi_gacw_evidence_metadata_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: runId,
      evidence_sha256: item.evidenceSha256,
      byte_length: item.bytes.byteLength,
      media_type: item.mediaType,
    }) as unknown as EvidenceMetadataDocument;
    const publication = await publishJsonDocument(layout, "EVIDENCE_METADATA", metadata as unknown as Record<string, unknown>);
    receipts.push({
      evidenceSha256: item.evidenceSha256,
      metadataContentSha256: metadata.content_sha256 as Sha256Digest,
      byteLength: item.bytes.byteLength,
      mediaType: item.mediaType,
      reusedEvidence: item.reusedEvidence,
      reusedMetadata: publication.reused,
    });
  }
  return receipts;
}

function identifiedManifest(runId: string, receipts: readonly EvidenceReceipt[]): EvidenceManifestDocument {
  const entries = receipts
    .map((receipt) => ({
      evidence_sha256: receipt.evidenceSha256,
      metadata_content_sha256: receipt.metadataContentSha256,
    }))
    .sort((left, right) => compareText(left.evidence_sha256, right.evidence_sha256));
  return identifyContractDocument("pi_gacw_evidence_manifest_v0", {
    schema_id: "pi_gacw_evidence_manifest_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: runId,
    entries,
  }) as unknown as EvidenceManifestDocument;
}

function objectDescriptor(layout: RunLayout, kind: StoredObjectKind, digest: Sha256Digest): InspectedObject {
  const path = kind === "RAW_EVIDENCE" || kind === "M3_TERMINAL_RETENTION_AUTHORITY"
    ? rawEvidencePath(layout, digest)
    : kind === "M3_BASELINE_BLOB"
      ? join(layout.baselineBlobDirectory, digestHex(digest))
      : jsonObjectPath(layout, kind, digest);
  return { kind, contentSha256: digest, relativePath: toRelative(layout, path) };
}

function sameIdentity(actual: unknown, expected: string, code: string, label: string): void {
  if (actual !== expected) throw new StateStoreError(code, `${label} does not match the committed identity`);
}

function sameDocument(left: unknown, right: unknown): boolean {
  return canonicalize(left) === canonicalize(right);
}

function reconstructPointer(commit: StateTransitionCommitDocument): PersistedStatePointerDocument {
  return identifyContractDocument("pi_gacw_persisted_state_pointer_v0", {
    schema_id: "pi_gacw_persisted_state_pointer_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: commit.run_id,
    revision: commit.new_revision,
    workflow_state_content_sha256: commit.new_workflow_state_content_sha256,
    transition_commit_content_sha256: commit.content_sha256,
    previous_state_pointer_content_sha256: commit.previous_state_pointer_content_sha256,
  }) as unknown as PersistedStatePointerDocument;
}

interface GraphInspection {
  readonly pointer: PersistedStatePointerDocument;
  readonly currentState: WorkflowState;
  readonly currentCommit: StateTransitionCommitDocument;
  readonly reachable: ReadonlyMap<string, InspectedObject>;
}

async function inspectCommittedGraph(layout: RunLayout): Promise<GraphInspection> {
  const pointer = await readStatePointer(layout);
  if (pointer.run_id !== basename(layout.runDirectory)) {
    throw new StateStoreError("RUN_ID_MISMATCH", "state.json belongs to another run");
  }
  const reachable = new Map<string, InspectedObject>();
  const visitedCommits = new Set<string>();

  const addReachable = (object: InspectedObject): void => {
    reachable.set(object.relativePath, object);
  };

  const visitCommit = async (contentSha256: Sha256Digest): Promise<{ commit: StateTransitionCommitDocument; state: WorkflowState }> => {
    if (visitedCommits.has(contentSha256)) {
      throw new StateStoreError("TRANSITION_COMMIT_CYCLE", `Transition commit cycle at ${contentSha256}`);
    }
    visitedCommits.add(contentSha256);
    const commit = await readJsonDocument<StateTransitionCommitDocument>(layout, "TRANSITION_COMMIT", contentSha256);
    addReachable(objectDescriptor(layout, "TRANSITION_COMMIT", contentSha256));
    if (commit.run_id !== pointer.run_id) throw new StateStoreError("RUN_ID_MISMATCH", "Transition commit belongs to another run");

    const state = await readJsonDocument<WorkflowState>(layout, "WORKFLOW_STATE", commit.new_workflow_state_content_sha256);
    addReachable(objectDescriptor(layout, "WORKFLOW_STATE", commit.new_workflow_state_content_sha256 as Sha256Digest));
    if (state.run_id !== pointer.run_id) throw new StateStoreError("RUN_ID_MISMATCH", "Workflow state belongs to another run");

    const policy = await readJsonDocument<ReducerPolicy>(layout, "REDUCER_POLICY", commit.reducer_policy_content_sha256);
    addReachable(objectDescriptor(layout, "REDUCER_POLICY", commit.reducer_policy_content_sha256 as Sha256Digest));
    assertReducerPolicy(policy);
    assertWorkflowState(state);
    assertStatePolicyConsistency(state, policy);

    const manifest = await readJsonDocument<EvidenceManifestDocument>(layout, "EVIDENCE_MANIFEST", commit.evidence_manifest_content_sha256);
    addReachable(objectDescriptor(layout, "EVIDENCE_MANIFEST", commit.evidence_manifest_content_sha256 as Sha256Digest));
    if (manifest.run_id !== pointer.run_id) throw new StateStoreError("RUN_ID_MISMATCH", "Evidence manifest belongs to another run");
    for (const entry of manifest.entries) {
      const metadata = await readJsonDocument<EvidenceMetadataDocument>(layout, "EVIDENCE_METADATA", entry.metadata_content_sha256);
      addReachable(objectDescriptor(layout, "EVIDENCE_METADATA", entry.metadata_content_sha256 as Sha256Digest));
      if (metadata.run_id !== pointer.run_id || metadata.evidence_sha256 !== entry.evidence_sha256) {
        throw new StateStoreError("EVIDENCE_METADATA_MISMATCH", "Evidence metadata does not match its manifest entry");
      }
      const bytes = await readRawEvidence(layout, entry.evidence_sha256);
      addReachable(objectDescriptor(layout, "RAW_EVIDENCE", entry.evidence_sha256 as Sha256Digest));
      if (bytes.byteLength !== metadata.byte_length) {
        throw new StateStoreError("EVIDENCE_BYTE_COUNT_MISMATCH", "Evidence byte count differs from metadata");
      }
    }

    const hasProcessAssessment = commit.process_assessment_content_sha256 !== null;
    if ((commit.commit_kind === "PROCESS_CRASH") !== hasProcessAssessment) {
      throw new StateStoreError(
        "PROCESS_ASSESSMENT_PRESENCE_MISMATCH",
        "Process assessment presence must match the process-crash commit kind",
      );
    }
    if (commit.process_assessment_content_sha256 !== null) {
      const assessment = await readJsonDocument<ProcessInterruptionDocument>(
        layout,
        "PROCESS_ASSESSMENT",
        commit.process_assessment_content_sha256,
      );
      addReachable(objectDescriptor(layout, "PROCESS_ASSESSMENT", commit.process_assessment_content_sha256 as Sha256Digest));
      if (assessment.run_id !== commit.run_id) {
        throw new StateStoreError("PROCESS_ASSESSMENT_MISMATCH", "Process assessment run ID does not match its commit");
      }
      if (assessment.expected_revision !== commit.previous_revision) {
        throw new StateStoreError("PROCESS_ASSESSMENT_MISMATCH", "Process assessment revision does not match its commit");
      }
      if (assessment.expected_state_pointer_content_sha256 !== commit.previous_state_pointer_content_sha256) {
        throw new StateStoreError("PROCESS_ASSESSMENT_MISMATCH", "Process assessment state-pointer identity does not match its commit");
      }
      if (assessment.expected_workflow_state_content_sha256 !== commit.previous_workflow_state_content_sha256) {
        throw new StateStoreError("PROCESS_ASSESSMENT_MISMATCH", "Process assessment workflow-state identity does not match its commit");
      }
    }

    if (commit.commit_kind === "GENESIS") {
      const expectedInitial = createInitialState(policy, state.identities);
      if (!sameDocument(expectedInitial, state)) {
        throw new StateStoreError("GENESIS_STATE_MISMATCH", "Genesis workflow state is not the M1 initial state");
      }
      return { commit, state };
    }

    if (
      commit.previous_transition_commit_content_sha256 === null ||
      commit.previous_workflow_state_content_sha256 === null ||
      commit.previous_state_pointer_content_sha256 === null ||
      commit.transition_event_content_sha256 === null ||
      commit.previous_revision === null
    ) {
      throw new StateStoreError("INCOMPLETE_TRANSITION_COMMIT", "Non-genesis commit lacks prior references");
    }
    const previous = await visitCommit(commit.previous_transition_commit_content_sha256 as Sha256Digest);
    if (previous.commit.new_revision !== commit.previous_revision) {
      throw new StateStoreError("REVISION_CHAIN_MISMATCH", "Transition revision does not follow its previous commit");
    }
    sameIdentity(
      previous.state.content_sha256,
      commit.previous_workflow_state_content_sha256,
      "PREVIOUS_STATE_MISMATCH",
      "Previous workflow state",
    );
    const previousPointer = reconstructPointer(previous.commit);
    sameIdentity(
      previousPointer.content_sha256,
      commit.previous_state_pointer_content_sha256,
      "PREVIOUS_POINTER_MISMATCH",
      "Previous state pointer",
    );
    const event = await readJsonDocument<TransitionEvent>(layout, "TRANSITION_EVENT", commit.transition_event_content_sha256);
    addReachable(objectDescriptor(layout, "TRANSITION_EVENT", commit.transition_event_content_sha256 as Sha256Digest));
    assertTransitionEvent(event);
    const reduced = reduceState(previous.state, event, policy);
    if (!sameDocument(reduced, state)) {
      throw new StateStoreError("REDUCER_RESULT_MISMATCH", "Committed workflow state is not the M1 reducer result");
    }
    if (commit.commit_kind === "PROCESS_CRASH") {
      if (event.event_type !== "BLOCK" || event.payload.reason !== "BLOCKED_PROCESS_CRASH" || state.phase !== "BLOCKED" || state.terminal_reason !== "BLOCKED_PROCESS_CRASH") {
        throw new StateStoreError("PROCESS_CRASH_TERMINAL_MISMATCH", "Process-crash commit is not the canonical M1 BLOCK transition");
      }
    }
    return { commit, state };
  };

  const current = await visitCommit(pointer.transition_commit_content_sha256 as Sha256Digest);
  if (pointer.revision !== current.commit.new_revision) {
    throw new StateStoreError("STATE_POINTER_REVISION_MISMATCH", "state.json revision differs from its transition commit");
  }
  sameIdentity(current.state.content_sha256, pointer.workflow_state_content_sha256, "STATE_POINTER_STATE_MISMATCH", "Current workflow state");
  const reconstructed = reconstructPointer(current.commit);
  if (!sameDocument(pointer, reconstructed)) {
    throw new StateStoreError("STATE_POINTER_COMMIT_MISMATCH", "state.json is not the exact pointer derived from its transition commit");
  }
  return { pointer, currentState: current.state, currentCommit: current.commit, reachable };
}

interface ScannedLayout {
  readonly objects: readonly InspectedObject[];
  readonly temporaryFiles: readonly string[];
}

class LayoutIssue extends Error {
  public readonly issue: InspectionIssue;

  public constructor(issue: InspectionIssue) {
    super(issue.detail);
    this.issue = issue;
  }
}

function tempBaseName(name: string): string | undefined {
  const match = /^\.(.+)\.tmp-[0-9]+-[0-9a-f]{16}$/.exec(name);
  return match?.[1];
}

async function assertScannedDirectory(
  layout: RunLayout,
  path: string,
  relativePath = toRelative(layout, path),
): Promise<void> {
  let stats: Stats;
  try {
    stats = await lstat(path);
  } catch (error: unknown) {
    throw new LayoutIssue({ code: "MISSING_DIRECTORY", relativePath, detail: "Required state-store directory is missing" });
  }
  if (stats.isSymbolicLink()) {
    throw new LayoutIssue({ code: "SYMLINK_ENTRY", relativePath, detail: "Symlink directory is forbidden" });
  }
  if (!stats.isDirectory()) {
    throw new LayoutIssue({ code: "SPECIAL_FILE_ENTRY", relativePath, detail: "Expected directory is not a directory" });
  }
  if ((stats.mode & 0o777) !== 0o700) {
    throw new LayoutIssue({ code: "PERMISSION_MISMATCH", relativePath, detail: "State-store directory mode must be 0700" });
  }
}

function unexpectedStateRootIssue(stats: Stats, relativePath: string): InspectionIssue {
  if (stats.isSymbolicLink()) {
    return { code: "SYMLINK_ENTRY", relativePath, detail: "State-root symlink entries are forbidden" };
  }
  if (stats.isFile()) {
    return { code: "UNKNOWN_ENTRY", relativePath, detail: "State root permits only runs/ and locks/; unexpected regular file" };
  }
  if (stats.isDirectory()) {
    return { code: "UNKNOWN_ENTRY", relativePath, detail: "State root permits only runs/ and locks/; unexpected directory" };
  }
  return { code: "SPECIAL_FILE_ENTRY", relativePath, detail: "State root permits only runs/ and locks/; unexpected special file" };
}

async function scanLockDirectory(layout: RunLayout): Promise<void> {
  await assertScannedDirectory(layout, layout.locksDirectory, "locks");
  for (const name of (await readdir(layout.locksDirectory)).sort(compareText)) {
    const relativePath = `locks/${name}`;
    if (!/^(?:[0-9a-f]{64}\.(?:lock|owner\.json)|[0-9a-f]{64}\.acquisition-[0-9a-f]{64}\.json)$/.test(name)) {
      throw new LayoutIssue({ code: "UNKNOWN_ENTRY", relativePath, detail: "Lock entries must use a worktree/acquisition-derived name" });
    }
    const stats = await lstat(join(layout.locksDirectory, name));
    if (stats.isSymbolicLink()) throw new LayoutIssue({ code: "SYMLINK_ENTRY", relativePath, detail: "Lock entries cannot be symlinks" });
    if (!stats.isFile()) throw new LayoutIssue({ code: "SPECIAL_FILE_ENTRY", relativePath, detail: "Lock entries must be regular files" });
    if ((stats.mode & 0o777) !== 0o600) {
      throw new LayoutIssue({ code: "PERMISSION_MISMATCH", relativePath, detail: "Lock entries must have mode 0600" });
    }
  }
}

async function scanOwnedTopLevelLayout(layout: RunLayout, allowMissingRuns: boolean): Promise<boolean> {
  await assertScannedDirectory(layout, layout.stateRoot, ".");
  const stateRootEntries = (await readdir(layout.stateRoot)).sort(compareText);
  for (const name of stateRootEntries) {
    if (name === "runs" || name === "locks") continue;
    const relativePath = name;
    throw new LayoutIssue(unexpectedStateRootIssue(await lstat(join(layout.stateRoot, name)), relativePath));
  }
  const hasRuns = stateRootEntries.includes("runs");
  if (!hasRuns && !allowMissingRuns) {
    throw new LayoutIssue({ code: "MISSING_DIRECTORY", relativePath: "runs", detail: "Required runs directory is missing" });
  }
  if (!stateRootEntries.includes("locks")) {
    if (!allowMissingRuns) throw new LayoutIssue({ code: "MISSING_DIRECTORY", relativePath: "locks", detail: "Required locks directory is missing" });
  } else {
    await scanLockDirectory(layout);
  }
  if (!hasRuns) return false;

  await assertScannedDirectory(layout, layout.runsDirectory, "runs");
  for (const name of (await readdir(layout.runsDirectory)).sort(compareText)) {
    const relativePath = `runs/${name}`;
    if (!RUN_ID_PATTERN.test(name)) {
      throw new LayoutIssue({
        code: "INVALID_RUN_DIRECTORY_NAME",
        relativePath,
        detail: "Runs directory entries must match the exact run-ID grammar",
      });
    }
    const stats = await lstat(join(layout.runsDirectory, name));
    if (stats.isSymbolicLink()) {
      throw new LayoutIssue({ code: "SYMLINK_ENTRY", relativePath, detail: "Run directory symlinks are forbidden" });
    }
    if (!stats.isDirectory()) {
      throw new LayoutIssue({
        code: stats.isFile() ? "RUN_ENTRY_NOT_DIRECTORY" : "SPECIAL_FILE_ENTRY",
        relativePath,
        detail: stats.isFile() ? "A runs entry must be a real directory" : "Special files are forbidden in runs/",
      });
    }
    if ((stats.mode & 0o777) !== 0o700) {
      throw new LayoutIssue({ code: "PERMISSION_MISMATCH", relativePath, detail: "Run directory mode must be 0700" });
    }
  }
  return true;
}

async function requireInitializableTopLevelLayout(layout: RunLayout, allowMissingRuns: boolean): Promise<boolean> {
  try {
    return await scanOwnedTopLevelLayout(layout, allowMissingRuns);
  } catch (error: unknown) {
    if (error instanceof LayoutIssue) {
      throw new StateStoreError(
        "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY",
        `${error.issue.code} at ${error.issue.relativePath}: ${error.issue.detail}`,
      );
    }
    throw error;
  }
}

async function scanObjectDirectory(
  layout: RunLayout,
  path: string,
  kind: StoredObjectKind,
  finalPattern: RegExp,
  ignoredFinalNames: ReadonlySet<string> = new Set(),
): Promise<{ objects: InspectedObject[]; temporaryFiles: string[] }> {
  await assertScannedDirectory(layout, path);
  const objects: InspectedObject[] = [];
  const temporaryFiles: string[] = [];
  for (const name of (await readdir(path)).sort()) {
    if (ignoredFinalNames.has(name)) {
      if (!finalPattern.test(name)) {
        throw new LayoutIssue({ code: "UNKNOWN_ENTRY", relativePath: toRelative(layout, join(path, name)), detail: "Ignored target name is not content-addressed" });
      }
      continue;
    }
    const fullPath = join(path, name);
    const stats = await lstat(fullPath);
    const relativePath = toRelative(layout, fullPath);
    if (stats.isSymbolicLink()) throw new LayoutIssue({ code: "SYMLINK_ENTRY", relativePath, detail: "Symlink object is forbidden" });
    if (!stats.isFile()) throw new LayoutIssue({ code: "SPECIAL_FILE_ENTRY", relativePath, detail: "Only regular immutable files are allowed" });
    if ((stats.mode & 0o777) !== 0o600) throw new LayoutIssue({ code: "PERMISSION_MISMATCH", relativePath, detail: "State-store file mode must be 0600" });
    if (finalPattern.test(name)) {
      const digest = `sha256:${name.replace(/\.json$/, "")}` as Sha256Digest;
      objects.push(objectDescriptor(layout, kind, digest));
      continue;
    }
    const base = tempBaseName(name);
    if (base !== undefined && finalPattern.test(base)) {
      temporaryFiles.push(relativePath);
      continue;
    }
    throw new LayoutIssue({ code: base === undefined ? "UNKNOWN_ENTRY" : "INVALID_TEMPORARY_FILE", relativePath, detail: "Unexpected state-store entry" });
  }
  return { objects, temporaryFiles };
}

async function scanLayout(
  layout: RunLayout,
  ignoredBaselineBlobNames: ReadonlySet<string> = new Set(),
): Promise<ScannedLayout> {
  await scanOwnedTopLevelLayout(layout, false);
  await assertScannedDirectory(layout, layout.runDirectory);
  const runNames = new Set(await readdir(layout.runDirectory));
  const allowedRunEntries = new Set(["state.json", "evidence", "baseline-blobs", "records", "commits"]);
  for (const name of runNames) {
    if (allowedRunEntries.has(name)) continue;
    const fullPath = join(layout.runDirectory, name);
    const stats = await lstat(fullPath);
    const relativePath = toRelative(layout, fullPath);
    if (stats.isSymbolicLink()) throw new LayoutIssue({ code: "SYMLINK_ENTRY", relativePath, detail: "Symlink is forbidden" });
    const base = tempBaseName(name);
    if (stats.isFile() && base === "state.json" && (stats.mode & 0o777) === 0o600) continue;
    if (!stats.isFile()) throw new LayoutIssue({ code: "SPECIAL_FILE_ENTRY", relativePath, detail: "Unexpected non-file run entry" });
    throw new LayoutIssue({ code: base === undefined ? "UNKNOWN_ENTRY" : "INVALID_TEMPORARY_FILE", relativePath, detail: "Unexpected run entry" });
  }
  for (const required of allowedRunEntries) {
    if (!runNames.has(required)) {
      throw new LayoutIssue({ code: "MISSING_REQUIRED_ENTRY", relativePath: required, detail: `Missing required entry ${required}` });
    }
  }
  const stateStats = await lstat(layout.stateFile);
  if (stateStats.isSymbolicLink()) {
    throw new LayoutIssue({ code: "SYMLINK_ENTRY", relativePath: "state.json", detail: "state.json cannot be a symlink" });
  }
  if (!stateStats.isFile()) {
    throw new LayoutIssue({ code: "SPECIAL_FILE_ENTRY", relativePath: "state.json", detail: "state.json must be a regular file" });
  }
  if ((stateStats.mode & 0o777) !== 0o600) {
    throw new LayoutIssue({ code: "PERMISSION_MISMATCH", relativePath: "state.json", detail: "state.json mode must be 0600" });
  }

  await assertScannedDirectory(layout, join(layout.runDirectory, "evidence"));
  const evidenceChildren = await readdir(join(layout.runDirectory, "evidence"));
  if (canonicalize(evidenceChildren.sort()) !== canonicalize(["sha256"])) {
    throw new LayoutIssue({ code: "UNKNOWN_ENTRY", relativePath: "evidence", detail: "Evidence directory has an unexpected entry" });
  }
  await assertScannedDirectory(layout, join(layout.runDirectory, "baseline-blobs"));
  const baselineBlobChildren = await readdir(join(layout.runDirectory, "baseline-blobs"));
  if (canonicalize(baselineBlobChildren.sort()) !== canonicalize(["sha256"])) {
    throw new LayoutIssue({ code: "UNKNOWN_ENTRY", relativePath: "baseline-blobs", detail: "Baseline blob directory has an unexpected entry" });
  }
  await assertScannedDirectory(layout, layout.recordsDirectory);
  const expectedRecordNames = [
    "baseline-approvals",
    "baselines",
    "evidence-manifests",
    "evidence-metadata",
    "lock-acquisitions",
    "lock-diagnostics",
    "postflights",
    "preflights",
    "process-assessments",
    "reducer-policies",
    "repository-state-tokens",
    "retention",
    "secure-fs-capabilities",
    "sandbox-capabilities",
    "tool-policies",
    "command-catalogs",
    "tool-requests",
    "patch-requests",
    "tool-results",
    "mutation-receipts",
    "command-results",
    "transition-events",
    "workflow-states",
  ].sort();
  const recordChildren = (await readdir(layout.recordsDirectory)).sort();
  if (canonicalize(recordChildren) !== canonicalize(expectedRecordNames)) {
    throw new LayoutIssue({ code: "UNKNOWN_ENTRY", relativePath: "records", detail: "Records directory has a missing or unexpected entry" });
  }

  const objects: InspectedObject[] = [];
  const temporaryFiles: string[] = [];
  const stateTempNames = [...runNames].filter((name) => tempBaseName(name) === "state.json");
  temporaryFiles.push(...stateTempNames.map((name) => toRelative(layout, join(layout.runDirectory, name))));
  const raw = await scanObjectDirectory(layout, layout.rawEvidenceDirectory, "RAW_EVIDENCE", DIGEST_FILE_PATTERN);
  objects.push(...raw.objects); temporaryFiles.push(...raw.temporaryFiles);
  const baselineBlobs = await scanObjectDirectory(
    layout,
    layout.baselineBlobDirectory,
    "M3_BASELINE_BLOB",
    DIGEST_FILE_PATTERN,
    ignoredBaselineBlobNames,
  );
  objects.push(...baselineBlobs.objects); temporaryFiles.push(...baselineBlobs.temporaryFiles);
  for (const definition of JSON_KINDS) {
    const scanned = await scanObjectDirectory(layout, layout[definition.directory], definition.kind, JSON_DIGEST_FILE_PATTERN);
    objects.push(...scanned.objects); temporaryFiles.push(...scanned.temporaryFiles);
  }
  return {
    objects: objects.sort((left, right) => compareText(left.relativePath, right.relativePath)),
    temporaryFiles: temporaryFiles.sort(),
  };
}

async function validateScannedObject(layout: RunLayout, object: InspectedObject): Promise<void> {
  if (object.kind === "RAW_EVIDENCE" || object.kind === "M3_TERMINAL_RETENTION_AUTHORITY") {
    await readRawEvidence(layout, object.contentSha256);
    return;
  }
  if (object.kind === "M3_BASELINE_BLOB") {
    const path = join(layout.baselineBlobDirectory, digestHex(object.contentSha256));
    await assertRegularPrivateFile(path);
    const bytes = await readFile(path);
    if (sha256Bytes(bytes) !== object.contentSha256) {
      throw new StateStoreError("EVIDENCE_HASH_MISMATCH", `Baseline blob hash mismatch: ${toRelative(layout, path)}`);
    }
    return;
  }
  await readJsonDocument(layout, object.kind, object.contentSha256);
}

const M3_MANAGED_KINDS = new Set<StoredObjectKind>([
  "M3_BASELINE",
  "M3_BASELINE_APPROVAL",
  "M3_LOCK_ACQUISITION",
  "M3_LOCK_DIAGNOSTIC",
  "M3_PREFLIGHT",
  "M3_REPOSITORY_STATE_TOKEN",
  "M3_POSTFLIGHT",
  "M3_RETENTION_RESULT",
  "M3_TERMINAL_RETENTION_AUTHORITY",
  "M3_BASELINE_BLOB",
]);

const M4_MANAGED_KINDS = new Set<StoredObjectKind>([
  "M4_SECURE_FS_CAPABILITY", "M4_SANDBOX_CAPABILITY", "M4_TOOL_POLICY", "M4_COMMAND_CATALOG",
  "M4_TOOL_REQUEST", "M4_PATCH_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT",
]);

const ALL_MANAGED_KINDS = new Set<StoredObjectKind>([...M3_MANAGED_KINDS, ...M4_MANAGED_KINDS]);

async function terminalAuthorityManagedObjects(
  layout: RunLayout,
  scanned: readonly InspectedObject[],
  graph: GraphInspection,
): Promise<readonly InspectedObject[]> {
  const objects: InspectedObject[] = [];
  for (const object of scanned) {
    if (object.kind !== "RAW_EVIDENCE" || !graph.reachable.has(object.relativePath)) continue;
    try {
      const value: unknown = JSON.parse((await readRawEvidence(layout, object.contentSha256)).toString("utf8"));
      if (value !== null && typeof value === "object" && !Array.isArray(value) &&
          (value as Record<string, unknown>)["schema_id"] === "pi_gacw_terminal_retention_authority_v0") {
        objects.push({ ...object, kind: "M3_TERMINAL_RETENTION_AUTHORITY" });
      }
    } catch {
      // Arbitrary raw evidence is not a managed terminal-authority candidate.
    }
  }
  return objects;
}

async function classifyManagedRecords(
  layout: RunLayout,
  objects: readonly InspectedObject[],
  graph: GraphInspection,
): Promise<readonly ManagedRecordClassification[]> {
  const baselines = new Map<string, M3BaselineRuntimeDocument>();
  const approvals = new Map<string, M3BaselineApprovalRuntimeDocument>();
  const lockAcquisitions = new Map<string, M3LockAcquisitionDocument>();
  const lockDiagnostics = new Map<string, M3LockDiagnosticDocument>();
  const preflights = new Map<string, M3PreflightDocument>();
  const tokens = new Map<string, M3RepositoryStateTokenDocument>();
  const postflights = new Map<string, M3PostflightDocument>();
  const results = new Map<string, M3RetentionResultDocument>();
  const terminalAuthorities = new Map<string, M3TerminalRetentionAuthorityDocument | Error>();
  const blobDigests = new Set<string>();
  const blobSizes = new Map<string, number>();
  const secureCapabilities = new Map<string, M4SecureFilesystemCapabilityDocument>();
  const sandboxCapabilities = new Map<string, M4SandboxCapabilityDocument>();
  const policies = new Map<string, M4ScopedToolPolicyDocument>();
  const catalogs = new Map<string, M4CommandCatalogDocument>();
  const toolRequests = new Map<string, M4ToolRequestDocument>();
  const patchRequests = new Map<string, M4PatchRequestDocument>();
  const toolResults = new Map<string, M4ToolResultDocument>();
  const mutationReceipts = new Map<string, M4MutationReceiptDocument>();
  const commandResults = new Map<string, M4CommandResultDocument>();
  for (const object of objects) {
    if (object.kind === "M3_BASELINE") baselines.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_BASELINE_APPROVAL") approvals.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_LOCK_ACQUISITION") lockAcquisitions.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_LOCK_DIAGNOSTIC") lockDiagnostics.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_PREFLIGHT") preflights.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_REPOSITORY_STATE_TOKEN") tokens.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_POSTFLIGHT") postflights.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_RETENTION_RESULT") results.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_BASELINE_BLOB") {
      blobDigests.add(object.contentSha256);
      blobSizes.set(object.contentSha256, (await lstat(join(layout.baselineBlobDirectory, digestHex(object.contentSha256)))).size);
    }
    else if (object.kind === "M4_SECURE_FS_CAPABILITY") secureCapabilities.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_SANDBOX_CAPABILITY") sandboxCapabilities.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_TOOL_POLICY") policies.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_COMMAND_CATALOG") catalogs.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_TOOL_REQUEST") toolRequests.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_PATCH_REQUEST") patchRequests.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_TOOL_RESULT") toolResults.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_MUTATION_RECEIPT") mutationReceipts.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M4_COMMAND_RESULT") commandResults.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_TERMINAL_RETENTION_AUTHORITY") {
      try {
        const bytes = await readRawEvidence(layout, object.contentSha256);
        const value: unknown = JSON.parse(bytes.toString("utf8"));
        assertDocumentValid("pi_gacw_terminal_retention_authority_v0", value);
        const authority = value as M3TerminalRetentionAuthorityDocument;
        if (!bytes.equals(canonicalJsonBytes(authority))) throw new Error("Terminal authority bytes are not canonical");
        terminalAuthorities.set(object.contentSha256, authority);
      } catch (error: unknown) {
        terminalAuthorities.set(object.contentSha256, error instanceof Error ? error : new Error(String(error)));
      }
    }
  }
  const m3Objects = objects.filter((object) => M3_MANAGED_KINDS.has(object.kind));
  const m3 = await classifyManagedAuthority({
    stateRoot: layout.stateRoot,
    runId: basename(layout.runDirectory),
    workflowState: graph.currentState,
    objects: m3Objects,
    baselines,
    approvals,
    lockAcquisitions,
    lockDiagnostics,
    preflights,
    tokens,
    postflights,
    results,
    terminalAuthorities,
    blobDigests,
    blobSizes,
  });
  const m4 = await classifyM4Authority({
    runId: basename(layout.runDirectory), objects, m3Classifications: m3, baselines, locks: lockAcquisitions, tokens, postflights,
    secureCapabilities, sandboxCapabilities, policies, catalogs, toolRequests, patchRequests, toolResults, mutationReceipts, commandResults,
  });
  return [...m3, ...m4].sort((left, right) => compareText(left.object.relativePath, right.object.relativePath));
}

function blockedInspection(
  runId: string,
  status: "BLOCKED_STATE_COMMIT_INCOMPLETE" | "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY",
  issue: InspectionIssue,
  graph?: Partial<GraphInspection>,
): RunStorageInspection {
  return detachedFrozen({
    status,
    runId,
    revision: graph?.pointer?.revision ?? null,
    statePointer: graph?.pointer ?? null,
    workflowState: graph?.currentState ?? null,
    transitionCommit: graph?.currentCommit ?? null,
    reachableObjects: graph?.reachable === undefined ? [] : [...graph.reachable.values()].sort((a, b) => compareText(a.relativePath, b.relativePath)),
    orphanedObjects: [],
    managedObjects: [],
    managedRecordClassifications: [],
    temporaryFiles: [],
    issues: [issue],
  });
}

async function inspectRunStorageInternal(
  input: RunStorageLocation,
  ignoredBaselineBlobNames: ReadonlySet<string>,
): Promise<RunStorageInspection> {
  const layout = assertLocation(input);
  let scanned: ScannedLayout;
  try {
    scanned = await scanLayout(layout, ignoredBaselineBlobNames);
  } catch (error: unknown) {
    const issue = error instanceof LayoutIssue
      ? error.issue
      : { code: "LAYOUT_INSPECTION_FAILED", relativePath: ".", detail: error instanceof Error ? error.message : String(error) };
    const status = issue.code === "MISSING_REQUIRED_ENTRY" && issue.relativePath === "state.json"
      ? "BLOCKED_STATE_COMMIT_INCOMPLETE" as const
      : "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY" as const;
    return blockedInspection(input.runId, status, issue);
  }

  let graph: GraphInspection;
  try {
    graph = await inspectCommittedGraph(layout);
  } catch (error: unknown) {
    return blockedInspection(input.runId, "BLOCKED_STATE_COMMIT_INCOMPLETE", {
      code: error instanceof StateStoreError ? error.code : "COMMITTED_GRAPH_INVALID",
      relativePath: "state.json",
      detail: error instanceof Error ? error.message : String(error),
    });
  }

  for (const object of scanned.objects) {
    try {
      await validateScannedObject(layout, object);
    } catch (error: unknown) {
      const referenced = graph.reachable.has(object.relativePath);
      return blockedInspection(input.runId, referenced ? "BLOCKED_STATE_COMMIT_INCOMPLETE" : "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY", {
        code: error instanceof StateStoreError ? error.code : "OBJECT_INTEGRITY_INVALID",
        relativePath: object.relativePath,
        detail: error instanceof Error ? error.message : String(error),
      }, graph);
    }
  }

  const managedObjects = [
    ...scanned.objects.filter((object) => ALL_MANAGED_KINDS.has(object.kind)),
    ...await terminalAuthorityManagedObjects(layout, scanned.objects, graph),
  ].sort((left, right) => compareText(left.relativePath, right.relativePath) || compareText(left.kind, right.kind));
  const managedRecordClassifications = await classifyManagedRecords(layout, managedObjects, graph);
  const uncommittedBaselineBlobs = managedRecordClassifications.filter((entry) =>
    entry.object.kind === "M3_BASELINE_BLOB" && entry.classification === "UNCOMMITTED_BASELINE_PUBLICATION",
  ).map((entry) => entry.object);
  const orphanedObjects = [
    ...scanned.objects.filter((object) => !ALL_MANAGED_KINDS.has(object.kind) && !graph.reachable.has(object.relativePath)),
    ...uncommittedBaselineBlobs,
  ].sort((left, right) => compareText(left.relativePath, right.relativePath));
  const issues = [
    ...uncommittedBaselineBlobs.map((object) => ({
      code: "UNCOMMITTED_BASELINE_PUBLICATION",
      relativePath: object.relativePath,
      detail: "A baseline blob has no committed durable baseline-runtime reference",
    })),
    ...managedRecordClassifications.filter((entry) => entry.classification === "INVALID_MANAGED_RECORD").map((entry) => ({
      code: "INVALID_MANAGED_RECORD",
      relativePath: entry.object.relativePath,
      detail: entry.detail,
    })),
  ].sort((left, right) => compareText(left.relativePath, right.relativePath) || compareText(left.code, right.code));
  const status = orphanedObjects.length > 0 || scanned.temporaryFiles.length > 0
    ? "ORPHANED_UNCOMMITTED_EVIDENCE" as const
    : "HEALTHY" as const;
  return detachedFrozen({
    status,
    runId: input.runId,
    revision: graph.pointer.revision,
    statePointer: graph.pointer,
    workflowState: graph.currentState,
    transitionCommit: graph.currentCommit,
    reachableObjects: [...graph.reachable.values()].sort((a, b) => compareText(a.relativePath, b.relativePath)),
    orphanedObjects,
    managedObjects,
    managedRecordClassifications,
    temporaryFiles: scanned.temporaryFiles,
    issues,
  });
}

export async function inspectRunStorage(input: RunStorageLocation): Promise<RunStorageInspection> {
  assertRecord(input, "inspect input");
  assertExactKeys(input, ["stateRoot", "runId"], "inspect input");
  return inspectRunStorageInternal(input, new Set());
}

/** Package-internal retention inspection: only exact expected blob targets may be omitted from layout validation. */
export async function inspectRunStorageForRetention(
  input: RunStorageLocation,
  expectedBlobDigests: readonly Sha256Digest[],
): Promise<RunStorageInspection> {
  if (!Array.isArray(expectedBlobDigests) || expectedBlobDigests.length > 100_000) {
    throw new StateStoreError("INVALID_ARGUMENT", "Retention target digest inventory is invalid");
  }
  const names = new Set<string>();
  for (const digest of expectedBlobDigests) {
    assertDigestArgument(digest, "retention target digest");
    const name = digestHex(digest);
    if (names.has(name)) throw new StateStoreError("INVALID_ARGUMENT", "Retention target digest inventory contains a duplicate");
    names.add(name);
  }
  return inspectRunStorageInternal(input, names);
}

function requireUsableInspection(inspection: RunStorageInspection): asserts inspection is RunStorageInspection & {
  readonly statePointer: PersistedStatePointerDocument;
  readonly workflowState: WorkflowState;
  readonly transitionCommit: StateTransitionCommitDocument;
  readonly revision: number;
} {
  if (inspection.status === "BLOCKED_STATE_COMMIT_INCOMPLETE" || inspection.status === "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY") {
    throw new StateStoreError(inspection.status, inspection.issues[0]?.detail ?? "Run storage is blocked");
  }
  if (inspection.statePointer === null || inspection.workflowState === null || inspection.transitionCommit === null || inspection.revision === null) {
    throw new StateStoreError("BLOCKED_STATE_COMMIT_INCOMPLETE", "Inspection has no authoritative committed state");
  }
}

function assertExpectedAuthority(
  inspection: RunStorageInspection & { readonly statePointer: PersistedStatePointerDocument; readonly workflowState: WorkflowState; readonly revision: number },
  expectedRevision: number,
  expectedPointer: string,
  expectedState: string,
): void {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new StateStoreError("INVALID_ARGUMENT", "expectedRevision must be a nonnegative safe integer");
  }
  assertDigestArgument(expectedPointer, "expectedStatePointerContentSha256");
  assertDigestArgument(expectedState, "expectedWorkflowStateContentSha256");
  if (inspection.revision !== expectedRevision) {
    throw new StateStoreError("STALE_EXPECTED_REVISION", `Expected revision ${expectedRevision}, observed ${inspection.revision}`);
  }
  if (inspection.statePointer.content_sha256 !== expectedPointer) {
    throw new StateStoreError("STALE_STATE_POINTER", "Expected state pointer identity is stale");
  }
  if (inspection.workflowState.content_sha256 !== expectedState) {
    throw new StateStoreError("STALE_WORKFLOW_STATE", "Expected workflow-state identity is stale");
  }
}

async function rereadBeforeStateUpdate(
  layout: RunLayout,
  expectedPointer: PersistedStatePointerDocument,
  expectedState: WorkflowState,
): Promise<void> {
  const currentPointer = await readStatePointer(layout);
  if (!sameDocument(currentPointer, expectedPointer)) {
    throw new StateStoreError("OBSERVED_STATE_DRIFT", "state.json changed before the final pointer update");
  }
  const currentState = await readJsonDocument<WorkflowState>(layout, "WORKFLOW_STATE", currentPointer.workflow_state_content_sha256);
  if (!sameDocument(currentState, expectedState)) {
    throw new StateStoreError("OBSERVED_STATE_DRIFT", "Committed workflow state changed before the final pointer update");
  }
}

export async function initializeRunStorage(input: InitializeRunStorageInput): Promise<CommittedRunState> {
  assertRecord(input, "initialize input");
  assertExactKeys(input, ["stateRoot", "runId", "policy", "initialState", "processMetadata"], "initialize input");
  const layout = assertLocation(input);
  assertProcessMetadata(input.processMetadata);
  assertReducerPolicy(input.policy);
  assertWorkflowState(input.initialState);
  if (input.policy.run_id !== input.runId || input.initialState.run_id !== input.runId) {
    throw new StateStoreError("RUN_ID_MISMATCH", "Run ID must match the reducer policy and initial state");
  }
  assertStatePolicyConsistency(input.initialState, input.policy);
  const expectedInitial = createInitialState(input.policy, input.initialState.identities);
  if (!sameDocument(expectedInitial, input.initialState)) {
    throw new StateStoreError("INITIAL_STATE_NOT_REDUCER_DERIVED", "Initial state must equal createInitialState(policy, identities)");
  }

  await initializeLayout(layout);
  const manifest = identifiedManifest(input.runId, []);
  await publishJsonDocument(layout, "REDUCER_POLICY", input.policy as unknown as Record<string, unknown>);
  await publishJsonDocument(layout, "WORKFLOW_STATE", input.initialState as unknown as Record<string, unknown>);
  await publishJsonDocument(layout, "EVIDENCE_MANIFEST", manifest as unknown as Record<string, unknown>);

  const commit = identifyContractDocument("pi_gacw_state_transition_commit_v0", {
    schema_id: "pi_gacw_state_transition_commit_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    commit_protocol_version: "state-commit-v1",
    commit_kind: "GENESIS",
    run_id: input.runId,
    transition_id: "genesis",
    previous_revision: null,
    new_revision: 0,
    previous_state_pointer_content_sha256: null,
    previous_workflow_state_content_sha256: null,
    previous_transition_commit_content_sha256: null,
    transition_event_content_sha256: null,
    reducer_policy_content_sha256: input.policy.content_sha256,
    new_workflow_state_content_sha256: input.initialState.content_sha256,
    evidence_manifest_content_sha256: manifest.content_sha256,
    process_assessment_content_sha256: null,
    process_metadata: input.processMetadata,
  }) as unknown as StateTransitionCommitDocument;
  await publishJsonDocument(layout, "TRANSITION_COMMIT", commit as unknown as Record<string, unknown>);

  // Verify all immutable genesis references from disk before publishing authority.
  await readJsonDocument(layout, "REDUCER_POLICY", commit.reducer_policy_content_sha256);
  await readJsonDocument(layout, "WORKFLOW_STATE", commit.new_workflow_state_content_sha256);
  await readJsonDocument(layout, "EVIDENCE_MANIFEST", commit.evidence_manifest_content_sha256);
  await readJsonDocument(layout, "TRANSITION_COMMIT", commit.content_sha256);

  const pointer = reconstructPointer(commit);
  await replaceStateFile(layout.stateFile, canonicalJsonBytes(pointer));
  return detachedFrozen({ statePointer: pointer, workflowState: input.initialState, transitionCommit: commit, evidence: [] });
}

export async function putEvidence(input: RunStorageLocation & EvidenceInput): Promise<EvidenceReceipt> {
  assertRecord(input, "putEvidence input");
  assertExactKeys(input, ["stateRoot", "runId", "bytes", "mediaType"], "putEvidence input");
  const layout = assertLocation(input);
  const capturedEvidence = captureEvidenceInputs([{ bytes: input.bytes, mediaType: input.mediaType }]);
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  requireUsableInspection(inspection);
  if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
    throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Cannot add evidence to a terminal run");
  }
  const prepared = await publishEvidenceBytes(layout, capturedEvidence);
  const receipts = await publishEvidenceMetadata(layout, input.runId, prepared);
  const receipt = receipts[0];
  if (receipt === undefined) throw new StateStoreError("EVIDENCE_STORE_FAILED", "No evidence receipt was produced");
  return detachedFrozen(receipt);
}

interface PerformCommitInput {
  readonly layout: RunLayout;
  readonly inspection: RunStorageInspection & {
    readonly statePointer: PersistedStatePointerDocument;
    readonly workflowState: WorkflowState;
    readonly transitionCommit: StateTransitionCommitDocument;
    readonly revision: number;
  };
  readonly transitionId: string;
  readonly policy: ReducerPolicy;
  readonly event: TransitionEvent;
  readonly evidence: readonly CapturedEvidenceInput[];
  readonly processMetadata: ProcessMetadata;
  readonly expectedNextWorkflowStateContentSha256?: Sha256Digest;
  readonly commitKind: "TRANSITION" | "PROCESS_CRASH";
  readonly processAssessment?: ProcessInterruptionDocument;
}

async function performCommit(input: PerformCommitInput): Promise<CommittedRunState> {
  const { layout, inspection } = input;
  assertIdentifier(input.transitionId, "transitionId");
  assertProcessMetadata(input.processMetadata);
  assertReducerPolicy(input.policy);
  assertTransitionEvent(input.event);
  if (input.policy.run_id !== inspection.runId || input.event.schema_id !== "pi_gacw_transition_event_v0") {
    throw new StateStoreError("RUN_ID_MISMATCH", "Reducer policy does not belong to the run");
  }
  const nextState = reduceState(inspection.workflowState, input.event, input.policy);
  if (input.expectedNextWorkflowStateContentSha256 !== undefined) {
    assertDigestArgument(input.expectedNextWorkflowStateContentSha256, "expectedNextWorkflowStateContentSha256");
  }
  if (
    input.expectedNextWorkflowStateContentSha256 !== undefined &&
    nextState.content_sha256 !== input.expectedNextWorkflowStateContentSha256
  ) {
    throw new StateStoreError("EXPECTED_NEXT_STATE_MISMATCH", "Reducer-produced state differs from the caller expectation");
  }

  // Phase 1: all raw bytes become immutable before any new JSON record.
  const preparedEvidence = await publishEvidenceBytes(layout, input.evidence);

  // Phase 2: metadata and every immutable JSON record required by this transition.
  const receipts = await publishEvidenceMetadata(layout, inspection.runId, preparedEvidence);
  const manifest = identifiedManifest(inspection.runId, receipts);
  await publishJsonDocument(layout, "REDUCER_POLICY", input.policy as unknown as Record<string, unknown>);
  await publishJsonDocument(layout, "TRANSITION_EVENT", input.event as unknown as Record<string, unknown>);
  await publishJsonDocument(layout, "WORKFLOW_STATE", nextState as unknown as Record<string, unknown>);
  await publishJsonDocument(layout, "EVIDENCE_MANIFEST", manifest as unknown as Record<string, unknown>);
  if (input.processAssessment !== undefined) {
    await publishJsonDocument(layout, "PROCESS_ASSESSMENT", input.processAssessment as unknown as Record<string, unknown>);
  }

  const commitDraft: Record<string, unknown> = {
    schema_id: "pi_gacw_state_transition_commit_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    commit_protocol_version: "state-commit-v1",
    commit_kind: input.commitKind,
    run_id: inspection.runId,
    transition_id: input.transitionId,
    previous_revision: inspection.revision,
    new_revision: inspection.revision + 1,
    previous_state_pointer_content_sha256: inspection.statePointer.content_sha256,
    previous_workflow_state_content_sha256: inspection.workflowState.content_sha256,
    previous_transition_commit_content_sha256: inspection.transitionCommit.content_sha256,
    transition_event_content_sha256: input.event.content_sha256,
    reducer_policy_content_sha256: input.policy.content_sha256,
    new_workflow_state_content_sha256: nextState.content_sha256,
    evidence_manifest_content_sha256: manifest.content_sha256,
    process_assessment_content_sha256: input.processAssessment?.content_sha256 ?? null,
    process_metadata: input.processMetadata,
  };
  const commit = identifyContractDocument(
    "pi_gacw_state_transition_commit_v0",
    commitDraft,
  ) as unknown as StateTransitionCommitDocument;

  // Phase 3 precondition: every exact immutable reference is loaded and verified.
  for (const receipt of receipts) {
    const metadata = await readJsonDocument<EvidenceMetadataDocument>(layout, "EVIDENCE_METADATA", receipt.metadataContentSha256);
    const bytes = await readRawEvidence(layout, receipt.evidenceSha256);
    if (metadata.evidence_sha256 !== receipt.evidenceSha256 || metadata.byte_length !== bytes.byteLength) {
      throw new StateStoreError("EVIDENCE_REFERENCE_INVALID", "Evidence reference failed exact verification");
    }
  }
  await readJsonDocument(layout, "REDUCER_POLICY", commit.reducer_policy_content_sha256);
  await readJsonDocument(layout, "TRANSITION_EVENT", commit.transition_event_content_sha256 as string);
  await readJsonDocument(layout, "WORKFLOW_STATE", commit.new_workflow_state_content_sha256);
  await readJsonDocument(layout, "EVIDENCE_MANIFEST", commit.evidence_manifest_content_sha256);
  if (commit.process_assessment_content_sha256 !== null) {
    await readJsonDocument(layout, "PROCESS_ASSESSMENT", commit.process_assessment_content_sha256);
  }
  await publishJsonDocument(layout, "TRANSITION_COMMIT", commit as unknown as Record<string, unknown>);
  await readJsonDocument(layout, "TRANSITION_COMMIT", commit.content_sha256);

  // One-writer precondition still applies; this catches sequentially observed drift.
  await rereadBeforeStateUpdate(layout, inspection.statePointer, inspection.workflowState);

  // Phase 4: state.json is the sole mutable authority and is published last.
  const pointer = reconstructPointer(commit);
  await replaceStateFile(layout.stateFile, canonicalJsonBytes(pointer));
  return detachedFrozen({ statePointer: pointer, workflowState: nextState, transitionCommit: commit, evidence: receipts });
}

export async function commitTransition(input: CommitTransitionInput): Promise<CommittedRunState> {
  assertRecord(input, "commit input");
  assertRequiredAndOptionalKeys(
    input,
    [
      "stateRoot",
      "runId",
      "expectedRevision",
      "expectedStatePointerContentSha256",
      "expectedWorkflowStateContentSha256",
      "transitionId",
      "policy",
      "event",
      "processMetadata",
    ],
    ["expectedNextWorkflowStateContentSha256", "evidence"],
    "commit input",
  );
  const layout = assertLocation(input);
  const evidence = captureEvidenceInputs(input.evidence === undefined ? [] : input.evidence);
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  requireUsableInspection(inspection);
  assertExpectedAuthority(
    inspection,
    input.expectedRevision,
    input.expectedStatePointerContentSha256,
    input.expectedWorkflowStateContentSha256,
  );
  if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
    throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Cannot commit after terminal workflow state");
  }
  if (inspection.status !== "HEALTHY") {
    throw new StateStoreError("ORPHANED_UNCOMMITTED_EVIDENCE", "Ordinary transition cannot adopt or bypass uncommitted objects");
  }
  return performCommit({
    layout,
    inspection,
    transitionId: input.transitionId,
    policy: input.policy,
    event: input.event,
    evidence,
    processMetadata: input.processMetadata,
    ...(input.expectedNextWorkflowStateContentSha256 === undefined
      ? {}
      : { expectedNextWorkflowStateContentSha256: input.expectedNextWorkflowStateContentSha256 }),
    commitKind: "TRANSITION",
  });
}

export async function terminalizeProcessCrash(input: TerminalizeProcessCrashInput): Promise<CommittedRunState> {
  assertRecord(input, "terminalize input");
  assertExactKeys(
    input,
    [
      "stateRoot",
      "runId",
      "expectedRevision",
      "expectedStatePointerContentSha256",
      "expectedWorkflowStateContentSha256",
      "transitionId",
      "policy",
      "processMetadata",
      "interruptionEvidence",
    ],
    "terminalize input",
  );
  const layout = assertLocation(input);
  assertInterruptionEvidence(input.interruptionEvidence);
  assertProcessMetadata(input.processMetadata);
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  requireUsableInspection(inspection);
  assertExpectedAuthority(
    inspection,
    input.expectedRevision,
    input.expectedStatePointerContentSha256,
    input.expectedWorkflowStateContentSha256,
  );
  if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
    throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Process-crash terminalization requires a nonterminal state");
  }
  assertIdentifier(input.transitionId, "transitionId");
  assertReducerPolicy(input.policy);
  assertStatePolicyConsistency(inspection.workflowState, input.policy);

  const assessment = identifyContractDocument("pi_gacw_process_interruption_v0", {
    schema_id: "pi_gacw_process_interruption_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    expected_revision: input.expectedRevision,
    expected_state_pointer_content_sha256: input.expectedStatePointerContentSha256,
    expected_workflow_state_content_sha256: input.expectedWorkflowStateContentSha256,
    evidence: input.interruptionEvidence,
    orphan_objects: inspection.orphanedObjects
      .map((object) => ({ kind: object.kind, content_sha256: object.contentSha256 }))
      .sort((left, right) => compareText(`${left.kind}:${left.content_sha256}`, `${right.kind}:${right.content_sha256}`)),
    temporary_files: [...inspection.temporaryFiles].sort(),
  }) as unknown as ProcessInterruptionDocument;

  const event = identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    event_id: input.transitionId,
    event_type: "BLOCK",
    payload: { reason: "BLOCKED_PROCESS_CRASH" },
  }) as unknown as TransitionEvent;

  return performCommit({
    layout,
    inspection,
    transitionId: input.transitionId,
    policy: input.policy,
    event,
    evidence: [],
    processMetadata: input.processMetadata,
    commitKind: "PROCESS_CRASH",
    processAssessment: assessment,
  });
}
