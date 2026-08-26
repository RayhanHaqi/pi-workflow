import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { constants, readFileSync, type Stats } from "node:fs";
import { link, lstat, open, readFile, readdir, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import type { M5AuthoritativeSources } from "../control/types.js";
import { assertControlPolicyAuthority } from "../control/policy.js";
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
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M3ResumeLockHandoverDocument,
  type M3RetentionResultDocument,
  type M3TerminalRetentionAuthorityDocument,
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
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type BudgetDocument,
  type BoundedWorkerInvocationDocument,
  type BoundedWorkerResultDocument,
  type M6WorkerInvocationDocument,
  type M6WorkerResultDocument,
  type PersistedStatePointerDocument,
  type ProcessInterruptionDocument,
  type ProcessMetadata,
  type ReducerPolicy,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
  type ContractDocument,
  type PlanApprovalDocument,
  type TaskDocument,
  type TaskGraphDocument,
  type SchemaId,
  type StateTransitionCommitDocument,
  type StaticTimeAuthorityDocument,
  type TransitionEvent,
  type WorkflowState,
  type NodeTimeAuthorityDocument,
  type WorkflowTimeAuthorityDocument,
} from "../schemas/index.js";
import { createInitialState, reduceState } from "../state-machine/index.js";
import {
  buildNodeStaticTimeAuthority,
  buildWorkflowStaticTimeAuthority,
  classifyStaticTimeAuthorities,
  nodeStaticTimeAuthorityIdentity,
  sampleStartedAtEpochMs,
  type StaticTimeAncestry,
  type StaticTimingVerdict,
  workflowStaticTimeAuthorityIdentity,
} from "./static-time-authority.js";
import { classifyManagedAuthority } from "./managed-authority.js";
import { classifyM4Authority } from "./m4-authority.js";
import { classifyM5Authority } from "./m5-authority.js";
import { classifyM6Authority } from "./m6-authority.js";
import { classifyBoundedWorkerAuthority, resolveAuthoritativeBoundedExecution } from "./bounded-worker-authority.js";
import {
  assertPrivateDirectory,
  assertRegularPrivateFile,
  ensurePrivateDirectory,
  publishImmutableFile,
  replaceStateFile,
} from "./atomic.js";
import { StateStoreError, stateStoreError } from "./errors.js";
import { m5PersistenceCheckpoint } from "./m5-test-hooks.js";
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
  readonly resumeLockHandoverRecordDirectory: string;
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
  readonly m4AdmissionRefusalDirectory: string;
  readonly m5ControlPolicyDirectory: string;
  readonly m5UsageEvidenceDirectory: string;
  readonly m5ControlDecisionDirectory: string;
  readonly m6WorkerInvocationDirectory: string;
  readonly m6WorkerResultDirectory: string;
  readonly boundedWorkerInvocationDirectory: string;
  readonly boundedWorkerResultDirectory: string;
  readonly staticTimeAuthorityDirectory: string;
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
    | "resumeLockHandoverRecordDirectory"
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
    | "m4AdmissionRefusalDirectory"
    | "m5ControlPolicyDirectory"
    | "m5UsageEvidenceDirectory"
    | "m5ControlDecisionDirectory"
    | "m6WorkerInvocationDirectory"
    | "m6WorkerResultDirectory"
    | "boundedWorkerInvocationDirectory"
    | "boundedWorkerResultDirectory"
    | "staticTimeAuthorityDirectory"
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
  { kind: "M3_RESUME_LOCK_HANDOVER", schemaId: "pi_gacw_resume_lock_handover_v0", directory: "resumeLockHandoverRecordDirectory" },
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
  { kind: "M4_ADMISSION_REFUSAL", schemaId: "pi_gacw_m4_admission_refusal_v0", directory: "m4AdmissionRefusalDirectory" },
  { kind: "M5_CONTROL_POLICY", schemaId: "pi_gacw_m5_control_policy_v0", directory: "m5ControlPolicyDirectory" },
  { kind: "M5_USAGE_EVIDENCE", schemaId: "pi_gacw_m5_usage_evidence_v0", directory: "m5UsageEvidenceDirectory" },
  { kind: "M5_CONTROL_DECISION", schemaId: "pi_gacw_m5_control_decision_v0", directory: "m5ControlDecisionDirectory" },
  { kind: "M6_WORKER_INVOCATION", schemaId: "pi_gacw_m6_worker_invocation_v0", directory: "m6WorkerInvocationDirectory" },
  { kind: "M6_WORKER_RESULT", schemaId: "pi_gacw_m6_worker_result_v0", directory: "m6WorkerResultDirectory" },
  { kind: "BOUNDED_WORKER_INVOCATION", schemaId: "pi_gacw_bounded_worker_invocation_v0", directory: "boundedWorkerInvocationDirectory" },
  { kind: "BOUNDED_WORKER_RESULT", schemaId: "pi_gacw_bounded_worker_result_v0", directory: "boundedWorkerResultDirectory" },
  { kind: "M2_STATIC_TIME_AUTHORITY", schemaId: "pi_gacw_static_time_authority_v0", directory: "staticTimeAuthorityDirectory" },
]);

const JSON_KIND_BY_NAME = new Map(JSON_KINDS.map((definition) => [definition.kind, definition]));
const JSON_KIND_BY_DIRECTORY = new Map(JSON_KINDS.map((definition) => [definition.directory, definition]));
/** Historical layouts predate this additive evidence collection and remain read-only compatible. */
/** Historical layouts predate these additive collections and remain read-only compatible. */
const LEGACY_OPTIONAL_JSON_KINDS = new Set<JsonStoredObjectKind>(["M4_ADMISSION_REFUSAL", "M3_RESUME_LOCK_HANDOVER", "M2_STATIC_TIME_AUTHORITY"]);
function isLegacyOptionalJsonKind(kind: JsonStoredObjectKind): boolean { return LEGACY_OPTIONAL_JSON_KINDS.has(kind); }

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
    resumeLockHandoverRecordDirectory: join(recordsDirectory, "resume-lock-handovers"),
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
    m4AdmissionRefusalDirectory: join(recordsDirectory, "m4-admission-refusals"),
    m5ControlPolicyDirectory: join(recordsDirectory, "m5-control-policies"),
    m5UsageEvidenceDirectory: join(recordsDirectory, "m5-usage-evidence"),
    m5ControlDecisionDirectory: join(recordsDirectory, "m5-control-decisions"),
    m6WorkerInvocationDirectory: join(recordsDirectory, "m6-worker-invocations"),
    m6WorkerResultDirectory: join(recordsDirectory, "m6-worker-results"),
    boundedWorkerInvocationDirectory: join(recordsDirectory, "bounded-worker-invocations"),
    boundedWorkerResultDirectory: join(recordsDirectory, "bounded-worker-results"),
    staticTimeAuthorityDirectory: join(recordsDirectory, "static-time-authorities"),
    commitsDirectory: join(runDirectory, "commits"),
  };
}

interface RunMutationOwner {
  readonly pid: number;
  readonly lock_id: string;
  readonly process_start_ticks: string;
  readonly device: bigint;
  readonly inode: bigint;
}

const runMutationContext = new AsyncLocalStorage<ReadonlySet<string>>();

function runMutationLockPath(layout: RunLayout): string {
  const runKey = sha256Bytes(Buffer.from(`pi-gacw-run-mutation:${basename(layout.runDirectory)}`, "utf8"));
  return join(layout.locksDirectory, `${runKey.slice("sha256:".length)}.lock`);
}

function processStartTicks(pid: number): string | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    if (close < 0) return undefined;
    const fields = stat.slice(close + 2).trim().split(/\s+/);
    const start = fields[19];
    return start !== undefined && /^[0-9]+$/.test(start) ? start : undefined;
  } catch { return undefined; }
}

function isProcessOwnerAlive(owner: Pick<RunMutationOwner, "pid" | "process_start_ticks">): boolean {
  try { process.kill(owner.pid, 0); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === "ESRCH") return false; }
  return processStartTicks(owner.pid) === owner.process_start_ticks;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function readRunMutationOwner(path: string): Promise<RunMutationOwner | undefined> {
  let before: Stats; let after: Stats; let value: unknown;
  try {
    before = await lstat(path, { bigint: true }) as unknown as Stats;
    value = JSON.parse((await readFile(path, "utf8")).trim());
    after = await lstat(path, { bigint: true }) as unknown as Stats;
  } catch { return undefined; }
  const beforeBig = before as unknown as { dev: bigint; ino: bigint; isFile(): boolean; mode: bigint };
  const afterBig = after as unknown as { dev: bigint; ino: bigint; isFile(): boolean; mode: bigint };
  if (!beforeBig.isFile() || beforeBig.dev !== afterBig.dev || beforeBig.ino !== afterBig.ino ||
      value === null || typeof value !== "object" || Array.isArray(value) || canonicalize(Object.keys(value).sort()) !== canonicalize(["lock_id", "pid", "process_start_ticks"]) ||
      !Number.isInteger((value as Record<string, unknown>)["pid"]) || ((value as Record<string, unknown>)["pid"] as number) < 1 ||
      typeof (value as Record<string, unknown>)["lock_id"] !== "string" || !/^[0-9a-f]{32}$/.test((value as Record<string, unknown>)["lock_id"] as string) ||
      typeof (value as Record<string, unknown>)["process_start_ticks"] !== "string" || !/^[0-9]+$/.test((value as Record<string, unknown>)["process_start_ticks"] as string)) return undefined;
  return { pid: (value as Record<string, unknown>)["pid"] as number, lock_id: (value as Record<string, unknown>)["lock_id"] as string,
    process_start_ticks: (value as Record<string, unknown>)["process_start_ticks"] as string, device: beforeBig.dev, inode: beforeBig.ino };
}

async function sameRunMutationOwner(path: string, owner: RunMutationOwner): Promise<boolean> {
  const current = await readRunMutationOwner(path);
  return current !== undefined && current.pid === owner.pid && current.lock_id === owner.lock_id &&
    current.process_start_ticks === owner.process_start_ticks && current.device === owner.device && current.inode === owner.inode;
}

function runMutationOwnerCandidatePath(layout: RunLayout, lockId: string): string {
  const digest = sha256Bytes(Buffer.from(`pi-gacw-run-owner:${lockId}`, "utf8")).slice("sha256:".length);
  return join(layout.locksDirectory, `${digest}.owner.json`);
}

async function removeStaleOwnerCandidate(layout: RunLayout, owner: RunMutationOwner): Promise<void> {
  const candidatePath = runMutationOwnerCandidatePath(layout, owner.lock_id);
  try {
    const stat = await lstat(candidatePath, { bigint: true }) as unknown as { dev: bigint; ino: bigint; isFile(): boolean };
    if (!stat.isFile() || stat.dev !== owner.device || stat.ino !== owner.inode) return;
    await unlink(candidatePath); await syncDirectory(layout.locksDirectory);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function acquireRunMutationLock(layout: RunLayout): Promise<() => Promise<void>> {
  await assertPrivateDirectory(layout.locksDirectory);
  const path = runMutationLockPath(layout);
  const processStart = processStartTicks(process.pid);
  if (processStart === undefined) throw new StateStoreError("CONCURRENT_WRITER", "Current process start identity is unavailable");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const lockId = randomBytes(16).toString("hex");
    const candidatePath = runMutationOwnerCandidatePath(layout, lockId);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(candidatePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      await m5PersistenceCheckpoint("RUN_LOCK_CANDIDATE_CREATED", candidatePath);
      await handle.writeFile(`${canonicalize({ lock_id: lockId, pid: process.pid, process_start_ticks: processStart })}\n`, "utf8");
      await m5PersistenceCheckpoint("RUN_LOCK_OWNER_METADATA_WRITTEN", candidatePath);
      await handle.sync();
      await m5PersistenceCheckpoint("RUN_LOCK_CANDIDATE_FSYNCED", candidatePath);
      await handle.close(); handle = undefined;
      await m5PersistenceCheckpoint("RUN_LOCK_CANDIDATE_READY", candidatePath);
      await m5PersistenceCheckpoint("RUN_LOCK_BEFORE_NOREPLACE_PUBLICATION", candidatePath);
      await link(candidatePath, path);
      await m5PersistenceCheckpoint("RUN_LOCK_AFTER_NOREPLACE_PUBLICATION", path);
      await syncDirectory(layout.locksDirectory);
      const owner = await readRunMutationOwner(path);
      if (owner === undefined || owner.pid !== process.pid || owner.lock_id !== lockId || owner.process_start_ticks !== processStart) throw new StateStoreError("CONCURRENT_WRITER", "Published run lock owner metadata is incomplete");
      await unlink(candidatePath); await syncDirectory(layout.locksDirectory);
      await m5PersistenceCheckpoint("RUN_LOCK_OWNER_PUBLISHED", path);
      let released = false;
      return async () => {
        if (released) return; released = true;
        if (!await sameRunMutationOwner(path, owner)) throw new StateStoreError("LOCK_RELEASE_FAILED", "Run mutation lock identity changed before release");
        try { await unlink(path); await syncDirectory(layout.locksDirectory); }
        catch (error: unknown) { throw stateStoreError("LOCK_RELEASE_FAILED", `Cannot release run mutation lock ${path}`, error); }
      };
    } catch (error: unknown) {
      if (handle !== undefined) try { await handle.close(); } catch { /* preserve primary failure */ }
      try { await unlink(candidatePath); } catch (cleanup: unknown) { if ((cleanup as NodeJS.ErrnoException).code !== "ENOENT") throw cleanup; }
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const owner = await readRunMutationOwner(path);
      if (owner === undefined) throw new StateStoreError("CONCURRENT_WRITER", "Run mutation lock owner metadata is malformed or publication is incomplete");
      if (isProcessOwnerAlive(owner)) throw new StateStoreError("CONCURRENT_WRITER", "Another live process owns the run mutation lock");
      await m5PersistenceCheckpoint("RUN_LOCK_STALE_OBSERVED", owner.lock_id);
      await m5PersistenceCheckpoint("RUN_LOCK_BEFORE_STALE_REVALIDATION", owner.lock_id);
      if (!await sameRunMutationOwner(path, owner)) throw new StateStoreError("CONCURRENT_WRITER", "Stale run mutation lock changed during inspection");
      await m5PersistenceCheckpoint("RUN_LOCK_AFTER_STALE_REVALIDATION", owner.lock_id);
      await m5PersistenceCheckpoint("RUN_LOCK_BEFORE_STALE_REMOVE", owner.lock_id);
      await m5PersistenceCheckpoint("RUN_LOCK_BEFORE_STALE_UNLINK", owner.lock_id);
      if (!await sameRunMutationOwner(path, owner)) throw new StateStoreError("CONCURRENT_WRITER", "Stale run mutation lock was replaced before removal");
      try {
        await unlink(path); await syncDirectory(layout.locksDirectory);
        await removeStaleOwnerCandidate(layout, owner);
        await m5PersistenceCheckpoint("RUN_LOCK_AFTER_STALE_UNLINK", owner.lock_id);
      }
      catch (unlinkError: unknown) { if ((unlinkError as NodeJS.ErrnoException).code !== "ENOENT") throw stateStoreError("CONCURRENT_WRITER", "A stale run mutation lock could not be removed", unlinkError); }
    }
  }
  throw new StateStoreError("CONCURRENT_WRITER", "Run mutation lock acquisition was inconclusive");
}

export async function withRunExclusive<T>(input: RunStorageLocation, operation: () => Promise<T>): Promise<T> {
  const layout = assertLocation(input);
  const path = runMutationLockPath(layout);
  const held = runMutationContext.getStore();
  if (held?.has(path) === true) return operation();
  const release = await acquireRunMutationLock(layout);
  try {
    return await runMutationContext.run(new Set([...(held ?? []), path]), operation);
  } finally {
    await release();
  }
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
  await ensurePrivateDirectory(layout.resumeLockHandoverRecordDirectory);
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
  await ensurePrivateDirectory(layout.m4AdmissionRefusalDirectory);
  await ensurePrivateDirectory(layout.m5ControlPolicyDirectory);
  await ensurePrivateDirectory(layout.m5UsageEvidenceDirectory);
  await ensurePrivateDirectory(layout.m5ControlDecisionDirectory);
  await ensurePrivateDirectory(layout.m6WorkerInvocationDirectory);
  await ensurePrivateDirectory(layout.m6WorkerResultDirectory);
  await ensurePrivateDirectory(layout.boundedWorkerInvocationDirectory);
  await ensurePrivateDirectory(layout.boundedWorkerResultDirectory);
  await ensurePrivateDirectory(layout.staticTimeAuthorityDirectory);
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
    layout.m5ControlPolicyDirectory,
    layout.m5UsageEvidenceDirectory,
    layout.m5ControlDecisionDirectory,
    layout.m6WorkerInvocationDirectory,
    layout.m6WorkerResultDirectory,
    layout.boundedWorkerInvocationDirectory,
    layout.boundedWorkerResultDirectory,
    layout.commitsDirectory,
  ]) {
    await assertPrivateDirectory(directory);
  }
  if (await existingStats(layout.m4AdmissionRefusalDirectory) !== undefined) {
    await assertPrivateDirectory(layout.m4AdmissionRefusalDirectory);
  }
  if (await existingStats(layout.staticTimeAuthorityDirectory) !== undefined) {
    await assertPrivateDirectory(layout.staticTimeAuthorityDirectory);
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

interface M5SourceEvidenceReference {
  readonly value: ContractDocument | BudgetDocument | RouteMapDocument | RouteMapApprovalDocument | PlanApprovalDocument | TaskGraphDocument | TaskDocument;
  readonly metadataRelativePath: string;
  readonly evidenceRelativePath: string;
}

interface M5SourceCandidates {
  readonly contracts: readonly ContractDocument[];
  readonly budgets: readonly BudgetDocument[];
  readonly routeMaps: readonly RouteMapDocument[];
  readonly routeMapApprovals: readonly RouteMapApprovalDocument[];
  readonly planApprovals: readonly PlanApprovalDocument[];
  readonly taskGraphs: readonly TaskGraphDocument[];
  readonly tasks: readonly TaskDocument[];
  readonly references: readonly M5SourceEvidenceReference[];
}

function sortSourceCandidates<T extends { readonly content_sha256: string }>(values: ReadonlyMap<string, T>): readonly T[] {
  return [...values.values()].sort((left, right) => compareText(left.content_sha256, right.content_sha256));
}

async function readM5SourceCandidates(
  layout: RunLayout,
  available: ReadonlyMap<string, InspectedObject>,
): Promise<M5SourceCandidates> {
  const candidates = {
    contracts: new Map<string, ContractDocument>(),
    budgets: new Map<string, BudgetDocument>(),
    routeMaps: new Map<string, RouteMapDocument>(),
    routeMapApprovals: new Map<string, RouteMapApprovalDocument>(),
    planApprovals: new Map<string, PlanApprovalDocument>(),
    taskGraphs: new Map<string, TaskGraphDocument>(),
    tasks: new Map<string, TaskDocument>(),
  };
  const references: M5SourceEvidenceReference[] = [];
  const parse = async <T extends Record<string, unknown>>(entry: InspectedObject, schemaId: SchemaId): Promise<T | undefined> => {
    try {
      const bytes = await readRawEvidence(layout, entry.contentSha256);
      const value: unknown = JSON.parse(bytes.toString("utf8"));
      assertDocumentValid(schemaId, value);
      if (!bytes.equals(canonicalJsonBytes(value))) return undefined;
      return value as T;
    } catch {
      return undefined;
    }
  };
  for (const object of available.values()) {
    if (object.kind !== "EVIDENCE_METADATA") continue;
    let metadata: EvidenceMetadataDocument;
    try { metadata = await readJsonDocument<EvidenceMetadataDocument>(layout, "EVIDENCE_METADATA", object.contentSha256); }
    catch { continue; }
    const evidence = available.get(objectDescriptor(layout, "RAW_EVIDENCE", metadata.evidence_sha256 as Sha256Digest).relativePath);
    if (evidence === undefined) continue;
    if (metadata.media_type === "application/vnd.pi-gacw.contract+json") {
      const value = await parse<ContractDocument>(evidence, "pi_gacw_contract_v0");
      if (value !== undefined) { candidates.contracts.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    } else if (metadata.media_type === "application/vnd.pi-gacw.budget+json") {
      const value = await parse<BudgetDocument>(evidence, "pi_gacw_budget_v0");
      if (value !== undefined) { candidates.budgets.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    } else if (metadata.media_type === "application/vnd.pi-gacw.route-map+json") {
      const value = await parse<RouteMapDocument>(evidence, "pi_gacw_route_map_v0");
      if (value !== undefined) { candidates.routeMaps.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    } else if (metadata.media_type === "application/vnd.pi-gacw.route-map-approval+json") {
      const value = await parse<RouteMapApprovalDocument>(evidence, "pi_gacw_route_map_approval_v0");
      if (value !== undefined) { candidates.routeMapApprovals.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    } else if (metadata.media_type === "application/vnd.pi-gacw.plan-approval+json") {
      const value = await parse<PlanApprovalDocument>(evidence, "pi_gacw_plan_approval_v0");
      if (value !== undefined) { candidates.planApprovals.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    } else if (metadata.media_type === "application/vnd.pi-gacw.task-graph+json") {
      const value = await parse<TaskGraphDocument>(evidence, "pi_gacw_task_graph_v0");
      if (value !== undefined) { candidates.taskGraphs.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    } else if (metadata.media_type === "application/vnd.pi-gacw.task+json") {
      const value = await parse<TaskDocument>(evidence, "pi_gacw_task_v0");
      if (value !== undefined) { candidates.tasks.set(value.content_sha256, value); references.push({ value, metadataRelativePath: object.relativePath, evidenceRelativePath: evidence.relativePath }); }
    }
  }
  return {
    contracts: sortSourceCandidates(candidates.contracts),
    budgets: sortSourceCandidates(candidates.budgets),
    routeMaps: sortSourceCandidates(candidates.routeMaps),
    routeMapApprovals: sortSourceCandidates(candidates.routeMapApprovals),
    planApprovals: sortSourceCandidates(candidates.planApprovals),
    taskGraphs: sortSourceCandidates(candidates.taskGraphs),
    tasks: sortSourceCandidates(candidates.tasks),
    references: references.sort((left, right) => compareText(left.metadataRelativePath, right.metadataRelativePath)),
  };
}

function selectM5Source<T>(values: readonly T[], identity: (value: T) => string, expected: string): T | undefined {
  const matches = values.filter((value) => identity(value) === expected);
  return matches.length === 1 ? matches[0] : undefined;
}

function selectM5Sources(policy: M5ControlPolicyDocument, candidates: M5SourceCandidates): M5AuthoritativeSources {
  const contract = selectM5Source(candidates.contracts, (value) => value.contract_sha256, policy.contract_sha256);
  const budget = selectM5Source(candidates.budgets, (value) => value.budget_sha256, policy.budget_sha256);
  const routeMap = selectM5Source(candidates.routeMaps, (value) => value.route_map_sha256, policy.route_map_sha256);
  const routeMapApproval = selectM5Source(candidates.routeMapApprovals, (value) => value.route_map_approval_sha256, policy.route_map_approval_sha256);
  const planApproval = candidates.planApprovals.filter((value) => value.plan_approval_sha256 === policy.plan_approval_sha256);
  const taskGraph = candidates.taskGraphs.filter((value) => value.task_graph_sha256 === policy.task_graph_sha256);
  return {
    ...(contract === undefined ? {} : { contract }),
    ...(budget === undefined ? {} : { budget }),
    ...(routeMap === undefined ? {} : { routeMap }),
    ...(routeMapApproval === undefined ? {} : { routeMapApproval }),
    ...(planApproval.length === 0 ? {} : { planApprovals: planApproval }),
    ...(taskGraph.length === 0 ? {} : { taskGraphs: taskGraph }),
    ...(candidates.tasks.length === 0 ? {} : { tasks: candidates.tasks }),
  };
}

function uniqueSourceByContent<T extends { readonly content_sha256: string }>(values: readonly T[], digest: string): T | undefined {
  const matches = values.filter((value) => value.content_sha256 === digest);
  return matches.length === 1 ? matches[0] : undefined;
}

/** M5 source reconstruction iterates the sole bounded-execution resolver; it does not classify results as execution authority itself. */
function resolvedBoundedWorkerResultsForM5(
  results: ReadonlyMap<string, BoundedWorkerResultDocument>,
  invocations: ReadonlyMap<string, BoundedWorkerInvocationDocument>,
  admissionRefusals: ReadonlyMap<string, M4AdmissionRefusalDocument>,
  decisions: ReadonlyMap<string, M5ControlDecisionDocument>,
  policies: ReadonlyMap<string, M5ControlPolicyDocument>,
  baselines: ReadonlyMap<string, M3BaselineRuntimeDocument>,
  approvals: ReadonlyMap<string, M3BaselineApprovalRuntimeDocument>,
  tokens: ReadonlyMap<string, M3RepositoryStateTokenDocument>,
  workflowStates: ReadonlyMap<string, WorkflowState>,
  candidates: M5SourceCandidates,
  classifications: readonly ManagedRecordClassification[],
): readonly BoundedWorkerResultDocument[] {
  const accepted: BoundedWorkerResultDocument[] = [];
  for (const result of results.values()) {
    const invocation = invocations.get(result.invocation_content_sha256);
    if (invocation === undefined) continue;
    const reservation = decisions.get(invocation.m5_reservation_decision_content_sha256);
    if (reservation === undefined) continue;
    const policy = policies.get(reservation.policy_content_sha256);
    if (policy === undefined) continue;
    const approval = approvals.get(policy.baseline_approval_sha256) ?? null;
    const baseline = approval === null
      ? baselines.get(policy.baseline_approval_sha256)
      : baselines.get(approval.baseline_runtime_content_sha256);
    const token = tokens.get(invocation.input_m3_state_token_content_sha256);
    const reservationState = workflowStates.get(reservation.current_state_content_sha256);
    const task = invocation.task_content_sha256 === null ? null : uniqueSourceByContent(candidates.tasks, invocation.task_content_sha256);
    const taskGraph = invocation.task_graph_sha256 === null ? null : uniqueSourceByContent(candidates.taskGraphs, invocation.task_graph_sha256);
    const plan = invocation.plan_approval_sha256 === null ? null : uniqueSourceByContent(candidates.planApprovals, invocation.plan_approval_sha256);
    if (baseline === undefined || token === undefined || reservationState === undefined ||
        (invocation.task_content_sha256 !== null && task === undefined) ||
        (invocation.task_graph_sha256 !== null && taskGraph === undefined) ||
        (invocation.plan_approval_sha256 !== null && plan === undefined)) continue;
    if (resolveAuthoritativeBoundedExecution({ invocation, result, reservation, reservationState, policy, baseline, approval, stateToken: token,
      task: task ?? null, taskGraph: taskGraph ?? null, plan: plan ?? null, admissionRefusals, classifications }).accepted) accepted.push(result);
  }
  return accepted.sort((left, right) => compareText(left.content_sha256, right.content_sha256));
}

function sourceReferenceMatchesPolicy(reference: M5SourceEvidenceReference, policy: M5ControlPolicyDocument): boolean {
  const value = reference.value;
  if (value.schema_id === "pi_gacw_contract_v0") return value.contract_sha256 === policy.contract_sha256;
  if (value.schema_id === "pi_gacw_budget_v0") return value.budget_sha256 === policy.budget_sha256;
  if (value.schema_id === "pi_gacw_route_map_v0") return value.route_map_sha256 === policy.route_map_sha256;
  if (value.schema_id === "pi_gacw_route_map_approval_v0") return value.route_map_approval_sha256 === policy.route_map_approval_sha256;
  if (value.schema_id === "pi_gacw_plan_approval_v0") return value.plan_approval_sha256 === policy.plan_approval_sha256;
  if (value.schema_id === "pi_gacw_task_graph_v0") return value.task_graph_sha256 === policy.task_graph_sha256;
  return value.task_sha256 === policy.objective_sha256 || policy.task_graph_sha256 !== null;
}

async function adoptedM5SourceObjectPaths(
  layout: RunLayout,
  objects: readonly InspectedObject[],
): Promise<ReadonlySet<string>> {
  const available = new Map(objects.map((object) => [object.relativePath, object]));
  const policies: M5ControlPolicyDocument[] = [];
  for (const object of objects) {
    if (object.kind !== "M5_CONTROL_POLICY") continue;
    try {
      const policy = await readJsonDocument<M5ControlPolicyDocument>(layout, object.kind, object.contentSha256);
      if (policy.production_authority === "OWNER_APPROVED") policies.push(policy);
    } catch {
      // Invalid policy records are not allowed to adopt otherwise orphaned evidence.
    }
  }
  if (policies.length === 0) return new Set();
  const candidates = await readM5SourceCandidates(layout, available);
  // A strict policy is the existing durable root for its four typed source documents;
  // this also lets a just-published source bundle pass the ordinary transition gate.
  const adopted = new Set<string>();
  for (const reference of candidates.references) if (policies.some((policy) => sourceReferenceMatchesPolicy(reference, policy))) {
    adopted.add(reference.metadataRelativePath);
    adopted.add(reference.evidenceRelativePath);
  }
  return adopted;
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
    "resume-lock-handovers",
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
    "m4-admission-refusals",
    "transition-events",
    "workflow-states",
    "m5-control-policies",
    "m5-usage-evidence",
    "m5-control-decisions",
    "m6-worker-invocations",
    "m6-worker-results",
    "bounded-worker-invocations",
    "bounded-worker-results",
    "static-time-authorities",
  ].sort();
  const recordChildren = (await readdir(layout.recordsDirectory)).sort();
  const optionalRecordNames = new Set(["m4-admission-refusals", "resume-lock-handovers", "static-time-authorities"]);
  if (recordChildren.some((name) => !expectedRecordNames.includes(name)) ||
      expectedRecordNames.some((name) => !optionalRecordNames.has(name) && !recordChildren.includes(name))) {
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
    if (isLegacyOptionalJsonKind(definition.kind) && await existingStats(layout[definition.directory]) === undefined) continue;
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
  "M3_RESUME_LOCK_HANDOVER",
  "M3_RETENTION_RESULT",
  "M3_TERMINAL_RETENTION_AUTHORITY",
  "M3_BASELINE_BLOB",
]);

const M4_MANAGED_KINDS = new Set<StoredObjectKind>([
  "M4_SECURE_FS_CAPABILITY", "M4_SANDBOX_CAPABILITY", "M4_TOOL_POLICY", "M4_COMMAND_CATALOG",
  "M4_TOOL_REQUEST", "M4_PATCH_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT", "M4_ADMISSION_REFUSAL",
]);

const M5_MANAGED_KINDS = new Set<StoredObjectKind>(["M5_CONTROL_POLICY", "M5_USAGE_EVIDENCE", "M5_CONTROL_DECISION"]);
const M6_MANAGED_KINDS = new Set<StoredObjectKind>(["M6_WORKER_INVOCATION", "M6_WORKER_RESULT"]);
const BOUNDED_WORKER_MANAGED_KINDS = new Set<StoredObjectKind>(["BOUNDED_WORKER_INVOCATION", "BOUNDED_WORKER_RESULT"]);
// V1-R2D-TIME: M2-owned durable wall-clock timing authority. Deliberately NOT a
// member of M3_MANAGED_KINDS; it uses its own smallest separate classification path.
const M2_STATIC_TIME_MANAGED_KINDS = new Set<StoredObjectKind>(["M2_STATIC_TIME_AUTHORITY"]);

const ALL_MANAGED_KINDS = new Set<StoredObjectKind>([...M3_MANAGED_KINDS, ...M4_MANAGED_KINDS, ...M5_MANAGED_KINDS, ...M6_MANAGED_KINDS, ...BOUNDED_WORKER_MANAGED_KINDS, ...M2_STATIC_TIME_MANAGED_KINDS]);

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
  const resumeHandovers = new Map<string, M3ResumeLockHandoverDocument>();
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
  const admissionRefusals = new Map<string, M4AdmissionRefusalDocument>();
  const workflowStates = new Map<string, WorkflowState>();
  const reducerPolicies = new Map<string, ReducerPolicy>();
  const m5Policies = new Map<string, M5ControlPolicyDocument>();
  const m5Usage = new Map<string, M5UsageEvidenceDocument>();
  const m5Decisions = new Map<string, M5ControlDecisionDocument>();
  const m6Invocations = new Map<string, M6WorkerInvocationDocument>();
  const m6Results = new Map<string, M6WorkerResultDocument>();
  const boundedInvocations = new Map<string, BoundedWorkerInvocationDocument>();
  const boundedResults = new Map<string, BoundedWorkerResultDocument>();
  const staticTimeAuthorities = new Map<string, StaticTimeAuthorityDocument>();
  const transitionEvents = new Map<string, TransitionEvent>();
  const transitionCommits = new Map<string, StateTransitionCommitDocument>();
  for (const object of objects) {
    if (object.kind === "WORKFLOW_STATE") workflowStates.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "TRANSITION_EVENT") transitionEvents.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "TRANSITION_COMMIT") transitionCommits.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "REDUCER_POLICY") reducerPolicies.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_BASELINE") baselines.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_BASELINE_APPROVAL") approvals.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_LOCK_ACQUISITION") lockAcquisitions.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_LOCK_DIAGNOSTIC") lockDiagnostics.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_PREFLIGHT") preflights.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_REPOSITORY_STATE_TOKEN") tokens.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_POSTFLIGHT") postflights.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M3_RESUME_LOCK_HANDOVER") resumeHandovers.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
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
    else if (object.kind === "M4_ADMISSION_REFUSAL") admissionRefusals.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M5_CONTROL_POLICY") m5Policies.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M5_USAGE_EVIDENCE") m5Usage.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M5_CONTROL_DECISION") m5Decisions.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M6_WORKER_INVOCATION") m6Invocations.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M6_WORKER_RESULT") m6Results.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "BOUNDED_WORKER_INVOCATION") boundedInvocations.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "BOUNDED_WORKER_RESULT") boundedResults.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
    else if (object.kind === "M2_STATIC_TIME_AUTHORITY") staticTimeAuthorities.set(object.contentSha256, await readJsonDocument(layout, object.kind, object.contentSha256));
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
    resumeHandovers,
    results,
    terminalAuthorities,
    blobDigests,
    blobSizes,
  });
  const m4 = await classifyM4Authority({
    runId: basename(layout.runDirectory), objects, m3Classifications: m3, baselines, locks: lockAcquisitions, tokens, postflights,
    secureCapabilities, sandboxCapabilities, policies, catalogs, toolRequests, patchRequests, toolResults, mutationReceipts, commandResults,
    admissionRefusals, boundedInvocations,
  });
  const reachableRawEvidence = new Set([...graph.reachable.values()].filter((entry) => entry.kind === "RAW_EVIDENCE").map((entry) => entry.contentSha256));
  const committedWorkflowStateDigests = new Set([...graph.reachable.values()].filter((entry) => entry.kind === "WORKFLOW_STATE").map((entry) => entry.contentSha256));
  const typedTransitionDecisionDigests = new Set<string>();
  const runAuthorityValidatedPolicyDigests = new Set<string>();
  const parseTypedEvidence = async <T>(digest: string, schemaId: SchemaId): Promise<T | undefined> => {
    try {
      const bytes = await readRawEvidence(layout, digest);
      const value: unknown = JSON.parse(bytes.toString("utf8"));
      assertDocumentValid(schemaId, value);
      if (!bytes.equals(canonicalJsonBytes(value))) return undefined;
      return value as T;
    } catch { return undefined; }
  };
  for (const commit of transitionCommits.values()) {
    const commitObject = objectDescriptor(layout, "TRANSITION_COMMIT", commit.content_sha256 as Sha256Digest);
    if (!graph.reachable.has(commitObject.relativePath) || commit.commit_kind !== "TRANSITION") continue;
    const manifest = await readJsonDocument<EvidenceManifestDocument>(layout, "EVIDENCE_MANIFEST", commit.evidence_manifest_content_sha256);
    let repository: M3RepositoryIdentityDocument | undefined;
    let contract: ContractDocument | undefined;
    let routeMap: RouteMapDocument | undefined;
    let routeMapApproval: RouteMapApprovalDocument | undefined;
    const decisionEvidence = new Set<string>();
    for (const entry of manifest.entries) {
      const metadata = await readJsonDocument<EvidenceMetadataDocument>(layout, "EVIDENCE_METADATA", entry.metadata_content_sha256);
      if (metadata.media_type === "application/vnd.pi-gacw.m5-control-decision+json") decisionEvidence.add(entry.evidence_sha256);
      else if (metadata.media_type === "application/vnd.pi-gacw.repository-identity+json") repository = await parseTypedEvidence(entry.evidence_sha256, "pi_gacw_repository_identity_v0");
      else if (metadata.media_type === "application/vnd.pi-gacw.contract+json") contract = await parseTypedEvidence(entry.evidence_sha256, "pi_gacw_contract_v0");
      else if (metadata.media_type === "application/vnd.pi-gacw.route-map+json") routeMap = await parseTypedEvidence(entry.evidence_sha256, "pi_gacw_route_map_v0");
      else if (metadata.media_type === "application/vnd.pi-gacw.route-map-approval+json") routeMapApproval = await parseTypedEvidence(entry.evidence_sha256, "pi_gacw_route_map_approval_v0");
    }
    for (const decision of m5Decisions.values()) {
      if (!decisionEvidence.has(sha256Bytes(canonicalJsonBytes(decision)))) continue;
      if (decision.run_id !== commit.run_id || decision.transition_id !== commit.transition_id || decision.current_state_content_sha256 !== commit.previous_workflow_state_content_sha256 ||
          decision.reducer_policy_content_sha256 !== commit.reducer_policy_content_sha256 || decision.transition_event?.content_sha256 !== commit.transition_event_content_sha256 ||
          decision.predicted_next_state_content_sha256 !== commit.new_workflow_state_content_sha256) continue;
      const policy = m5Policies.get(decision.policy_content_sha256);
      const state = workflowStates.get(decision.current_state_content_sha256);
      const reducer = reducerPolicies.get(decision.reducer_policy_content_sha256);
      if (policy === undefined || state === undefined || reducer === undefined || repository === undefined || contract === undefined || routeMap === undefined || routeMapApproval === undefined) continue;
      try {
        assertControlPolicyAuthority(policy, state, reducer, commit.run_id, false, { repositoryIdentity: repository, contract, routeMap, routeMapApproval });
        typedTransitionDecisionDigests.add(decision.content_sha256);
        runAuthorityValidatedPolicyDigests.add(policy.content_sha256);
      } catch { /* typed bytes without exact immutable run authority remain unrooted */ }
    }
  }
  const authoritative = (kind: StoredObjectKind, digest: string): boolean => [...m3, ...m4].some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest && entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
  const classificationFor = (classifications: readonly ManagedRecordClassification[], kind: StoredObjectKind, digest: string): ManagedRecordClassification | undefined =>
    classifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest);
  const m5PolicyContexts = new Map<string, number>();
  for (const policy of m5Policies.values()) {
    const context = `${policy.run_id}:${policy.starting_state_content_sha256}`;
    m5PolicyContexts.set(context, (m5PolicyContexts.get(context) ?? 0) + 1);
  }
  const exactOwnerApprovedM4 = new Set<string>();
  const exactOwnerApprovedPair = (policy: M5ControlPolicyDocument): readonly [string, string] | undefined => {
    if (policy.production_authority !== "OWNER_APPROVED" || policy.run_id !== basename(layout.runDirectory) ||
        m5PolicyContexts.get(`${policy.run_id}:${policy.starting_state_content_sha256}`) !== 1 ||
        !objects.some((object) => object.kind === "M5_CONTROL_POLICY" && object.contentSha256 === policy.content_sha256)) return undefined;
    try { assertDocumentValid("pi_gacw_m5_control_policy_v0", policy); } catch { return undefined; }
    const genesis = workflowStates.get(policy.starting_state_content_sha256);
    if (genesis?.phase !== "CREATED" ||
        policy.objective_sha256 !== graph.currentState.identities.objective_sha256 || policy.contract_sha256 !== graph.currentState.identities.contract_sha256 ||
        policy.budget_sha256 !== graph.currentState.identities.budget_sha256 || policy.scope_sha256 !== graph.currentState.identities.scope_sha256 ||
        policy.acceptance_sha256 !== graph.currentState.identities.acceptance_sha256 || policy.reducer_policy_content_sha256 !== graph.currentState.frozen_policy_content_sha256) return undefined;
    const toolPolicy = policies.get(policy.tool_policy_content_sha256);
    const commandCatalog = catalogs.get(policy.command_catalog_content_sha256);
    if (toolPolicy === undefined || commandCatalog === undefined || toolPolicy.content_sha256 !== policy.tool_policy_content_sha256 ||
        commandCatalog.content_sha256 !== policy.command_catalog_content_sha256 || toolPolicy.run_id !== policy.run_id ||
        toolPolicy.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 || toolPolicy.worktree_key !== policy.worktree_key ||
        toolPolicy.task_scope_identity !== policy.scope_sha256 || commandCatalog.run_id !== policy.run_id ||
        commandCatalog.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 ||
        commandCatalog.tool_policy_content_sha256 !== toolPolicy.content_sha256) return undefined;
    const toolClassification = classificationFor(m4, "M4_TOOL_POLICY", toolPolicy.content_sha256);
    const catalogClassification = classificationFor(m4, "M4_COMMAND_CATALOG", commandCatalog.content_sha256);
    const eligible = (classification: ManagedRecordClassification | undefined): boolean => classification?.classification === "AUTHORITATIVE_MANAGED_RECORD" || classification?.classification === "UNREFERENCED_MANAGED_RECORD";
    if (!eligible(toolClassification) || !eligible(catalogClassification)) return undefined;
    const token = [...tokens.values()].find((candidate) => candidate.run_id === policy.run_id &&
      candidate.repository_identity_content_sha256 === policy.repository_identity_content_sha256 && candidate.worktree_key === policy.worktree_key &&
      candidate.task_scope_identity === policy.scope_sha256 && classificationFor(m3, "M3_REPOSITORY_STATE_TOKEN", candidate.content_sha256)?.classification === "AUTHORITATIVE_MANAGED_RECORD");
    if (token === undefined) return undefined;
    return [toolPolicy.content_sha256, commandCatalog.content_sha256];
  };
  for (const policy of m5Policies.values()) {
    const pair = exactOwnerApprovedPair(policy);
    if (pair !== undefined) {
      exactOwnerApprovedM4.add(`M4_TOOL_POLICY:${pair[0]}`);
      exactOwnerApprovedM4.add(`M4_COMMAND_CATALOG:${pair[1]}`);
    }
  }
  const validPreProviderM4 = (kind: StoredObjectKind, digest: string): boolean => authoritative(kind, digest) || exactOwnerApprovedM4.has(`${kind}:${digest}`);
  const authoritativeM4Policies = new Map([...policies].filter(([digest]) => validPreProviderM4("M4_TOOL_POLICY", digest)));
  const authoritativeM4Catalogs = new Map([...catalogs].filter(([digest]) => validPreProviderM4("M4_COMMAND_CATALOG", digest)));
  const bounded = classifyBoundedWorkerAuthority({
    runId: basename(layout.runDirectory),
    objects: objects.filter((object) => BOUNDED_WORKER_MANAGED_KINDS.has(object.kind)),
    invocations: boundedInvocations,
    results: boundedResults,
  });
  const sourceCandidates = await readM5SourceCandidates(layout, new Map(objects.map((object) => [object.relativePath, object])));
  const sourcePolicies = [...m5Policies.values()].filter((entry) => entry.run_id === basename(layout.runDirectory));
  const persistedM5Sources = sourcePolicies.length === 1 && sourcePolicies[0]!.production_authority === "OWNER_APPROVED"
    ? selectM5Sources(sourcePolicies[0]!, sourceCandidates) : {};
  const boundedResultReservationDecisionDigests = new Map<string, string>();
  for (const [digest, result] of boundedResults) {
    const invocation = boundedInvocations.get(result.invocation_content_sha256);
    if (invocation !== undefined) boundedResultReservationDecisionDigests.set(digest, invocation.m5_reservation_decision_content_sha256);
  }
  const commonM5Sources = {
    ...persistedM5Sources,
    m4CommandResults: [...commandResults.values()].filter((entry) => authoritative("M4_COMMAND_RESULT", entry.content_sha256)),
    m3StateTokens: [...tokens.values()].filter((entry) => authoritative("M3_REPOSITORY_STATE_TOKEN", entry.content_sha256)),
    m3Postflights: [...postflights.values()].filter((entry) => authoritative("M3_POSTFLIGHT", entry.content_sha256)),
    workflowStates: [...workflowStates.values()],
    transitionEvents: [...transitionEvents.values()].filter((entry) => objects.some((object) => object.kind === "TRANSITION_EVENT" && object.contentSha256 === entry.content_sha256 && graph.reachable.has(object.relativePath))),
    transitionCommits: [...transitionCommits.values()].filter((entry) => objects.some((object) => object.kind === "TRANSITION_COMMIT" && object.contentSha256 === entry.content_sha256 && graph.reachable.has(object.relativePath))),
  };
  const classifyM5WithResolvedBounded = (resolved: readonly BoundedWorkerResultDocument[]): readonly ManagedRecordClassification[] => classifyM5Authority({
    runId: basename(layout.runDirectory), workflowState: graph.currentState, workflowStates, objects, priorClassifications: [...m3, ...m4, ...bounded],
    policies: m5Policies, usage: m5Usage, decisions: m5Decisions, reducerPolicies, m4Policies: authoritativeM4Policies, m4Catalogs: authoritativeM4Catalogs, reachableRawEvidence, typedTransitionDecisionDigests, runAuthorityValidatedPolicyDigests, committedWorkflowStateDigests,
    authoritativeSources: { ...commonM5Sources, boundedWorkerResults: resolved },
    boundedResultReservationDecisionDigests,
  });
  // Start with no bounded-worker M5 source. Each bounded result enters the next
  // M5 reconstruction pass only after the sole cross-layer resolver accepted it.
  let resolvedBoundedWorkerResults: readonly BoundedWorkerResultDocument[] = [];
  let m5: readonly ManagedRecordClassification[] = [];
  let resolutionSettled = false;
  for (let iteration = 0; iteration <= boundedResults.size; iteration += 1) {
    m5 = classifyM5WithResolvedBounded(resolvedBoundedWorkerResults);
    const newlyResolved = resolvedBoundedWorkerResultsForM5(boundedResults, boundedInvocations, admissionRefusals, m5Decisions, m5Policies, baselines, approvals, tokens, workflowStates, sourceCandidates, [...m3, ...m4, ...bounded, ...m5]);
    // Resolver acceptance is rooted in the exact pre-existing reservation and
    // must not oscillate when the terminal M5 decision later consumes it.
    const next = [...new Map([...resolvedBoundedWorkerResults, ...newlyResolved].map((entry) => [entry.content_sha256, entry])).values()]
      .sort((left, right) => compareText(left.content_sha256, right.content_sha256));
    if (next.length === resolvedBoundedWorkerResults.length && next.every((entry, index) => entry.content_sha256 === resolvedBoundedWorkerResults[index]?.content_sha256)) {
      resolvedBoundedWorkerResults = next;
      resolutionSettled = true;
      break;
    }
    resolvedBoundedWorkerResults = next;
  }
  if (!resolutionSettled) {
    // A non-convergent reconstruction has no accepted bounded execution source.
    resolvedBoundedWorkerResults = [];
    m5 = classifyM5WithResolvedBounded(resolvedBoundedWorkerResults);
  }
  const rootedByM5 = new Set<string>();
  for (const classification of m5) {
    if (classification.object.kind !== "M5_CONTROL_DECISION" || classification.classification !== "AUTHORITATIVE_MANAGED_RECORD") continue;
    const decision = m5Decisions.get(classification.object.contentSha256);
    if (decision === undefined) continue;
    for (const digest of decision.progress.evidence_content_sha256) rootedByM5.add(digest);
    for (const failure of decision.failures) rootedByM5.add(failure.source_record_content_sha256);
    for (const digest of decision.usage_evidence_content_sha256) {
      const usage = m5Usage.get(digest);
      if (usage !== undefined) rootedByM5.add(usage.source_record_content_sha256);
    }
  }
  const promote = (classification: ManagedRecordClassification): ManagedRecordClassification =>
    rootedByM5.has(classification.object.contentSha256) && classification.classification === "UNREFERENCED_MANAGED_RECORD"
      ? { ...classification, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "M5 committed decision roots this predecessor authority" }
      : classification;
  const m6 = classifyM6Authority({
    runId: basename(layout.runDirectory),
    objects: objects.filter((object) => M6_MANAGED_KINDS.has(object.kind)),
    invocations: m6Invocations,
    results: m6Results,
  });
  // Smallest separate M2 timing-classification pass over the same scanned inventory.
  const reachableCommitDigests = new Set<string>();
  const reachableStateDigests = new Set<string>();
  for (const digest of transitionCommits.keys()) {
    if (graph.reachable.has(objectDescriptor(layout, "TRANSITION_COMMIT", digest as Sha256Digest).relativePath)) reachableCommitDigests.add(digest);
  }
  for (const digest of workflowStates.keys()) {
    if (graph.reachable.has(objectDescriptor(layout, "WORKFLOW_STATE", digest as Sha256Digest).relativePath)) reachableStateDigests.add(digest);
  }
  const staticTimingVerdicts = classifyStaticTimeAuthorities({
    runId: basename(layout.runDirectory),
    authorities: staticTimeAuthorities,
    reachableCommits: reachableCommitDigests,
    reachableStates: reachableStateDigests,
    ancestry: { commits: transitionCommits, states: workflowStates, events: transitionEvents },
    policies: reducerPolicies,
    budgets: sourceCandidates.budgets,
    planApprovals: sourceCandidates.planApprovals,
  });
  const staticTiming = [...staticTimeAuthorities.keys()].map((digest): ManagedRecordClassification => {
    const verdict: StaticTimingVerdict = staticTimingVerdicts.get(digest) ?? { decision: "INVALID_MANAGED_RECORD", detail: "timing authority was not classified" };
    return { object: objectDescriptor(layout, "M2_STATIC_TIME_AUTHORITY", digest as Sha256Digest), classification: verdict.decision, detail: verdict.detail };
  });
  return [...m3.map(promote), ...m4.map(promote), ...m5, ...m6, ...bounded, ...staticTiming].sort((left, right) => compareText(left.object.relativePath, right.object.relativePath));
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
  const managedRecordClassifications = await classifyManagedRecords(layout, [
    ...scanned.objects,
    ...managedObjects.filter((object) => object.kind === "M3_TERMINAL_RETENTION_AUTHORITY"),
  ], graph);
  const adoptedM5SourceObjects = await adoptedM5SourceObjectPaths(layout, scanned.objects);
  const uncommittedBaselineBlobs = managedRecordClassifications.filter((entry) =>
    entry.object.kind === "M3_BASELINE_BLOB" && entry.classification === "UNCOMMITTED_BASELINE_PUBLICATION",
  ).map((entry) => entry.object);
  const adoptedSourceObjects = scanned.objects.filter((object) => adoptedM5SourceObjects.has(object.relativePath));
  const reportedReachableObjects = [...new Map([...graph.reachable.values(), ...adoptedSourceObjects].map((object) => [object.relativePath, object])).values()]
    .sort((left, right) => compareText(left.relativePath, right.relativePath));
  const orphanedObjects = [
    ...scanned.objects.filter((object) => !ALL_MANAGED_KINDS.has(object.kind) && !graph.reachable.has(object.relativePath) && !adoptedM5SourceObjects.has(object.relativePath)),
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
    reachableObjects: reportedReachableObjects,
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

export type M5ManagedRecordKind = "M5_CONTROL_POLICY" | "M5_USAGE_EVIDENCE" | "M5_CONTROL_DECISION";

/** Package-internal M5 publication boundary. It is intentionally absent from ./persistence. */
export async function publishM5ManagedRecord(input: RunStorageLocation & {
  readonly kind: M5ManagedRecordKind;
  readonly document: M5ControlPolicyDocument | M5UsageEvidenceDocument | M5ControlDecisionDocument;
}): Promise<{ readonly reused: boolean }> {
  assertRecord(input, "M5 publication input");
  assertExactKeys(input, ["stateRoot", "runId", "kind", "document"], "M5 publication input");
  if (!M5_MANAGED_KINDS.has(input.kind)) throw new StateStoreError("INVALID_ARGUMENT", "Unknown M5 record kind");
  return withRunExclusive(input, async () => {
    const layout = assertLocation(input);
    const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
    requireUsableInspection(inspection);
    if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
      throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Cannot publish M5 authority to a terminal run");
    }
    if (input.document.run_id !== input.runId) throw new StateStoreError("RUN_ID_MISMATCH", "M5 record belongs to another run");
    const existing = await readM5ManagedRecords(input);
    if (input.kind === "M5_CONTROL_POLICY") {
      const document = input.document as M5ControlPolicyDocument;
      const conflicting = existing.policies.find((entry) => entry.run_id === input.runId && entry.starting_state_content_sha256 === document.starting_state_content_sha256 && entry.content_sha256 !== document.content_sha256);
      if (conflicting !== undefined) throw new StateStoreError("M5_POLICY_CONFLICT", "A different policy already owns this run and starting state");
    } else if (input.kind === "M5_USAGE_EVIDENCE") {
      const document = input.document as M5UsageEvidenceDocument;
      const conflicting = existing.usage.find((entry) => entry.run_id === input.runId && entry.operation_id === document.operation_id && entry.content_sha256 !== document.content_sha256);
      if (conflicting !== undefined) throw new StateStoreError("M5_USAGE_CONFLICT", "A different usage measurement already owns this operation");
    } else {
      const document = input.document as M5ControlDecisionDocument;
      const conflicting = existing.decisions.find((entry) => entry.run_id === input.runId && entry.decision_key === document.decision_key && entry.content_sha256 !== document.content_sha256);
      if (conflicting !== undefined) throw new StateStoreError("M5_DECISION_CONFLICT", "A different immutable decision already owns this decision key");
    }
    const before = input.kind === "M5_CONTROL_POLICY" ? "BEFORE_POLICY_PUBLICATION" as const
      : input.kind === "M5_USAGE_EVIDENCE" ? "BEFORE_USAGE_PUBLICATION" as const : "BEFORE_DECISION_PUBLICATION" as const;
    const after = input.kind === "M5_CONTROL_POLICY" ? "AFTER_POLICY_PUBLICATION" as const
      : input.kind === "M5_USAGE_EVIDENCE" ? "AFTER_USAGE_PUBLICATION" as const : "AFTER_DECISION_PUBLICATION" as const;
    await m5PersistenceCheckpoint(before, input.document.content_sha256);
    const publication = await publishJsonDocument(layout, input.kind, input.document as unknown as Record<string, unknown>);
    await readJsonDocument(layout, input.kind, input.document.content_sha256);
    await m5PersistenceCheckpoint(after, input.document.content_sha256);
    return detachedFrozen(publication);
  });
}

/** Package-internal immutable M5 record loader. */
export async function readM5ManagedRecords(input: RunStorageLocation): Promise<{
  readonly policies: readonly M5ControlPolicyDocument[];
  readonly reducerPolicies: readonly ReducerPolicy[];
  readonly usage: readonly M5UsageEvidenceDocument[];
  readonly decisions: readonly M5ControlDecisionDocument[];
  readonly toolPolicies: readonly M4ScopedToolPolicyDocument[];
  readonly commandCatalogs: readonly M4CommandCatalogDocument[];
  /** Narrow M8 durable-evidence reader; records remain validated immutable M4 authority. */
  readonly toolResults: readonly M4ToolResultDocument[];
  readonly mutationReceipts: readonly M4MutationReceiptDocument[];
  readonly commandResults: readonly M4CommandResultDocument[];
  readonly admissionRefusals: readonly M4AdmissionRefusalDocument[];
  readonly baselines: readonly M3BaselineRuntimeDocument[];
  readonly approvals: readonly M3BaselineApprovalRuntimeDocument[];
  readonly stateTokens: readonly M3RepositoryStateTokenDocument[];
  readonly postflights: readonly M3PostflightDocument[];
  readonly contracts: readonly ContractDocument[];
  readonly budgets: readonly BudgetDocument[];
  readonly routeMaps: readonly RouteMapDocument[];
  readonly routeMapApprovals: readonly RouteMapApprovalDocument[];
  readonly planApprovals: readonly PlanApprovalDocument[];
  readonly taskGraphs: readonly TaskGraphDocument[];
  readonly tasks: readonly TaskDocument[];
  readonly workflowStates: readonly WorkflowState[];
  readonly transitionEvents: readonly TransitionEvent[];
  readonly transitionCommits: readonly StateTransitionCommitDocument[];
  readonly boundedWorkerInvocations: readonly BoundedWorkerInvocationDocument[];
  readonly boundedWorkerResults: readonly BoundedWorkerResultDocument[];
  readonly staticTimeAuthorities: readonly StaticTimeAuthorityDocument[];
}> {
  const layout = assertLocation(input);
  await assertExistingLayout(layout);
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  const sourceCandidates = await readM5SourceCandidates(layout, new Map([...inspection.reachableObjects, ...inspection.orphanedObjects].map((object) => [object.relativePath, object])));
  const load = async <T extends Record<string, unknown>>(kind: JsonStoredObjectKind): Promise<T[]> => {
    const definition = JSON_KIND_BY_NAME.get(kind)!;
    if (isLegacyOptionalJsonKind(kind) && await existingStats(layout[definition.directory]) === undefined) return [];
    const names = (await readdir(layout[definition.directory])).filter((name) => JSON_DIGEST_FILE_PATTERN.test(name)).sort(compareText);
    const values: T[] = [];
    for (const name of names) values.push(await readJsonDocument<T>(layout, kind, `sha256:${name.slice(0, -5)}`));
    return values;
  };
  return detachedFrozen({
    policies: await load<M5ControlPolicyDocument>("M5_CONTROL_POLICY"),
    reducerPolicies: await load<ReducerPolicy>("REDUCER_POLICY"),
    usage: await load<M5UsageEvidenceDocument>("M5_USAGE_EVIDENCE"),
    decisions: await load<M5ControlDecisionDocument>("M5_CONTROL_DECISION"),
    toolPolicies: await load<M4ScopedToolPolicyDocument>("M4_TOOL_POLICY"),
    commandCatalogs: await load<M4CommandCatalogDocument>("M4_COMMAND_CATALOG"),
    toolResults: await load<M4ToolResultDocument>("M4_TOOL_RESULT"),
    mutationReceipts: await load<M4MutationReceiptDocument>("M4_MUTATION_RECEIPT"),
    commandResults: await load<M4CommandResultDocument>("M4_COMMAND_RESULT"),
    admissionRefusals: await load<M4AdmissionRefusalDocument>("M4_ADMISSION_REFUSAL"),
    baselines: await load<M3BaselineRuntimeDocument>("M3_BASELINE"),
    approvals: await load<M3BaselineApprovalRuntimeDocument>("M3_BASELINE_APPROVAL"),
    stateTokens: await load<M3RepositoryStateTokenDocument>("M3_REPOSITORY_STATE_TOKEN"),
    postflights: await load<M3PostflightDocument>("M3_POSTFLIGHT"),
    contracts: sourceCandidates.contracts,
    budgets: sourceCandidates.budgets,
    routeMaps: sourceCandidates.routeMaps,
    routeMapApprovals: sourceCandidates.routeMapApprovals,
    planApprovals: sourceCandidates.planApprovals,
    taskGraphs: sourceCandidates.taskGraphs,
    tasks: sourceCandidates.tasks,
    workflowStates: await load<WorkflowState>("WORKFLOW_STATE"),
    transitionEvents: await load<TransitionEvent>("TRANSITION_EVENT"),
    transitionCommits: await load<StateTransitionCommitDocument>("TRANSITION_COMMIT"),
    boundedWorkerInvocations: await load<BoundedWorkerInvocationDocument>("BOUNDED_WORKER_INVOCATION"),
    boundedWorkerResults: await load<BoundedWorkerResultDocument>("BOUNDED_WORKER_RESULT"),
    staticTimeAuthorities: await load<StaticTimeAuthorityDocument>("M2_STATIC_TIME_AUTHORITY"),
  });
}

export type M6WorkerRecordKind = "M6_WORKER_INVOCATION" | "M6_WORKER_RESULT";
type M6WorkerPublicationInput = RunStorageLocation & (
  | { readonly kind: "M6_WORKER_INVOCATION"; readonly document: M6WorkerInvocationDocument }
  | { readonly kind: "M6_WORKER_RESULT"; readonly document: M6WorkerResultDocument }
);

async function assertPublishedM6Authority(input: M6WorkerPublicationInput): Promise<void> {
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  const classification = inspection.managedRecordClassifications.find((entry) => entry.object.kind === input.kind && entry.object.contentSha256 === input.document.content_sha256);
  if (inspection.status !== "HEALTHY" || classification?.classification !== "AUTHORITATIVE_MANAGED_RECORD") {
    throw new StateStoreError("M6_RECORD_NOT_AUTHORITATIVE", `${input.kind} publication was not classified as authoritative after reread`);
  }
}

export async function publishM6WorkerRecord(input: M6WorkerPublicationInput): Promise<{ readonly reused: boolean }> {
  assertRecord(input, "M6 publication input");
  assertExactKeys(input, ["stateRoot", "runId", "kind", "document"], "M6 publication input");
  if (!M6_MANAGED_KINDS.has(input.kind)) throw new StateStoreError("INVALID_ARGUMENT", "Unknown M6 record kind");
  const document = input.document;
  assertRecord(document, "M6 publication document");
  if (input.kind === "M6_WORKER_INVOCATION") assertDocumentValid("pi_gacw_m6_worker_invocation_v0", document);
  else assertDocumentValid("pi_gacw_m6_worker_result_v0", document);
  if (document.run_id !== input.runId) throw new StateStoreError("RUN_ID_MISMATCH", "M6 record belongs to another run");
  return withRunExclusive(input, async () => {
    const layout = assertLocation(input);
    const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
    requireUsableInspection(inspection);
    if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Cannot publish M6 authority to a terminal run");
    if (input.kind === "M6_WORKER_INVOCATION" && inspection.workflowState.content_sha256 !== input.document.current_state_content_sha256) throw new StateStoreError("M6_STATE_DRIFT", "M6 invocation state differs from the current authoritative state");
    const existing = await readM6WorkerRecords(input);
    const invocationKey = document.invocation_key;
    const sameKind = input.kind === "M6_WORKER_INVOCATION" ? existing.invocations : existing.results;
    const sameKey = sameKind.find((entry) => entry.invocation_key === invocationKey);
    if (sameKey !== undefined) {
      if (sameKey.content_sha256 !== document.content_sha256 || canonicalize(sameKey) !== canonicalize(document)) {
        throw new StateStoreError("M6_RECORD_CONFLICT", "A different immutable M6 record already owns this invocation key");
      }
      return { reused: true };
    }
    if (input.kind === "M6_WORKER_RESULT") {
      const invocation = existing.invocations.find((entry) => entry.content_sha256 === input.document.invocation_content_sha256);
      const invocationIsAuthoritative = invocation !== undefined && inspection.managedRecordClassifications.some((entry) => entry.object.kind === "M6_WORKER_INVOCATION" && entry.object.contentSha256 === input.document.invocation_content_sha256 && entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
      if (invocation === undefined || !invocationIsAuthoritative || invocation.invocation_key !== input.document.invocation_key) {
        throw new StateStoreError("M6_INVOCATION_MISSING", "M6 result does not have its exact immutable invocation predecessor");
      }
    }
    const publication = await publishJsonDocument(layout, input.kind, document);
    await readJsonDocument(layout, input.kind, document.content_sha256);
    await assertPublishedM6Authority(input);
    return detachedFrozen(publication);
  });
}

export async function readM6WorkerRecords(input: RunStorageLocation): Promise<{
  readonly invocations: readonly M6WorkerInvocationDocument[];
  readonly results: readonly M6WorkerResultDocument[];
}> {
  const layout = assertLocation(input);
  await assertExistingLayout(layout);
  const load = async <T extends Record<string, unknown>>(kind: JsonStoredObjectKind): Promise<T[]> => {
    const definition = JSON_KIND_BY_NAME.get(kind);
    if (definition === undefined) throw new StateStoreError("UNKNOWN_OBJECT_KIND", kind);
    const names = (await readdir(layout[definition.directory])).filter((name) => JSON_DIGEST_FILE_PATTERN.test(name)).sort(compareText);
    const values: T[] = [];
    for (const name of names) values.push(await readJsonDocument<T>(layout, kind, `sha256:${name.slice(0, -5)}`));
    return values;
  };
  return detachedFrozen({
    invocations: await load<M6WorkerInvocationDocument>("M6_WORKER_INVOCATION"),
    results: await load<M6WorkerResultDocument>("M6_WORKER_RESULT"),
  });
}

export type BoundedWorkerRecordKind = "BOUNDED_WORKER_INVOCATION" | "BOUNDED_WORKER_RESULT";
type BoundedWorkerPublicationInput = RunStorageLocation & (
  | { readonly kind: "BOUNDED_WORKER_INVOCATION"; readonly document: BoundedWorkerInvocationDocument }
  | { readonly kind: "BOUNDED_WORKER_RESULT"; readonly document: BoundedWorkerResultDocument }
);

async function assertPublishedBoundedWorkerAuthority(input: BoundedWorkerPublicationInput): Promise<void> {
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  const classification = inspection.managedRecordClassifications.find((entry) =>
    entry.object.kind === input.kind && entry.object.contentSha256 === input.document.content_sha256,
  );
  if (inspection.status !== "HEALTHY" || classification?.classification !== "AUTHORITATIVE_MANAGED_RECORD") {
    throw new StateStoreError("BOUNDED_WORKER_RECORD_NOT_AUTHORITATIVE", `${input.kind} publication was not authoritative after reread`);
  }
}

/** Package-internal durable boundary for exactly the two pre-M8 bounded-worker records. */
export async function publishBoundedWorkerRecord(input: BoundedWorkerPublicationInput): Promise<{ readonly reused: boolean }> {
  assertRecord(input, "bounded worker publication input");
  assertExactKeys(input, ["stateRoot", "runId", "kind", "document"], "bounded worker publication input");
  if (!BOUNDED_WORKER_MANAGED_KINDS.has(input.kind)) throw new StateStoreError("INVALID_ARGUMENT", "Unknown bounded worker record kind");
  if (input.kind === "BOUNDED_WORKER_INVOCATION") {
    assertDocumentValid("pi_gacw_bounded_worker_invocation_v0", input.document);
    if (input.document.run_id !== input.runId) throw new StateStoreError("RUN_ID_MISMATCH", "bounded invocation belongs to another run");
  } else assertDocumentValid("pi_gacw_bounded_worker_result_v0", input.document);
  return withRunExclusive(input, async () => {
    const layout = assertLocation(input);
    const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
    requireUsableInspection(inspection);
    if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
      throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Cannot publish bounded worker authority to a terminal run");
    }
    const existing = await readBoundedWorkerRecords(input);
    if (input.kind === "BOUNDED_WORKER_INVOCATION") {
      const document = input.document;
      const same = existing.invocations.find((entry) => entry.invocation_key === document.invocation_key);
      if (same !== undefined) {
        if (same.content_sha256 !== document.content_sha256 || canonicalize(same) !== canonicalize(document)) {
          throw new StateStoreError("BOUNDED_WORKER_RECORD_CONFLICT", "A different bounded invocation owns this key");
        }
        return { reused: true };
      }
    } else {
      const document = input.document;
      const same = existing.results.find((entry) => entry.invocation_content_sha256 === document.invocation_content_sha256);
      if (same !== undefined) {
        if (same.content_sha256 !== document.content_sha256 || canonicalize(same) !== canonicalize(document)) {
          throw new StateStoreError("BOUNDED_WORKER_RECORD_CONFLICT", "A different bounded result owns this invocation");
        }
        return { reused: true };
      }
      const invocation = existing.invocations.find((entry) => entry.content_sha256 === document.invocation_content_sha256);
      const invocationAuthoritative = invocation !== undefined && inspection.managedRecordClassifications.some((entry) =>
        entry.object.kind === "BOUNDED_WORKER_INVOCATION" && entry.object.contentSha256 === document.invocation_content_sha256 &&
        entry.classification === "AUTHORITATIVE_MANAGED_RECORD",
      );
      if (!invocationAuthoritative) throw new StateStoreError("BOUNDED_WORKER_INVOCATION_MISSING", "bounded result lacks its exact invocation");
    }
    const publication = await publishJsonDocument(layout, input.kind, input.document);
    await readJsonDocument(layout, input.kind, input.document.content_sha256);
    await assertPublishedBoundedWorkerAuthority(input);
    return detachedFrozen(publication);
  });
}

export async function readBoundedWorkerRecords(input: RunStorageLocation): Promise<{
  readonly invocations: readonly BoundedWorkerInvocationDocument[];
  readonly results: readonly BoundedWorkerResultDocument[];
}> {
  const layout = assertLocation(input);
  await assertExistingLayout(layout);
  const load = async <T extends Record<string, unknown>>(kind: JsonStoredObjectKind): Promise<T[]> => {
    const definition = JSON_KIND_BY_NAME.get(kind);
    if (definition === undefined) throw new StateStoreError("UNKNOWN_OBJECT_KIND", kind);
    const names = (await readdir(layout[definition.directory])).filter((name) => JSON_DIGEST_FILE_PATTERN.test(name)).sort(compareText);
    const values: T[] = [];
    for (const name of names) values.push(await readJsonDocument<T>(layout, kind, `sha256:${name.slice(0, -5)}`));
    return values;
  };
  return detachedFrozen({
    invocations: await load<BoundedWorkerInvocationDocument>("BOUNDED_WORKER_INVOCATION"),
    results: await load<BoundedWorkerResultDocument>("BOUNDED_WORKER_RESULT"),
  });
}

// ---------------------------------------------------------------------------
// V1-R2D-TIME: durable M2 static wall-clock timing authority
// ---------------------------------------------------------------------------

/** All physical timing records carrying one semantic authority key (cardinality decides uniqueness). */
function timingRecordsForKey(records: readonly StaticTimeAuthorityDocument[], authorityId: string): StaticTimeAuthorityDocument[] {
  return records.filter((entry) => entry.authority_id === authorityId);
}

async function readStaticTimeAuthorityDocuments(layout: RunLayout): Promise<StaticTimeAuthorityDocument[]> {
  if (await existingStats(layout.staticTimeAuthorityDirectory) === undefined) return [];
  const names = (await readdir(layout.staticTimeAuthorityDirectory)).filter((name) => JSON_DIGEST_FILE_PATTERN.test(name)).sort(compareText);
  const values: StaticTimeAuthorityDocument[] = [];
  for (const name of names) values.push(await readJsonDocument<StaticTimeAuthorityDocument>(layout, "M2_STATIC_TIME_AUTHORITY", `sha256:${name.slice(0, -5)}`));
  return values;
}

/** Package-internal immutable timing-authority loader; legacy-optional and read-only safe. */
export async function readStaticTimeAuthorities(input: RunStorageLocation): Promise<readonly StaticTimeAuthorityDocument[]> {
  const layout = assertLocation(input);
  await assertExistingLayout(layout);
  return detachedFrozen(await readStaticTimeAuthorityDocuments(layout));
}

/**
 * Publish-or-reuse one content-addressed timing document for its semantic
 * authority key. No latest-wins: the same key with different immutable content
 * fails closed with a typed conflict.
 */
export async function publishStaticTimeAuthority(input: RunStorageLocation & {
  readonly document: StaticTimeAuthorityDocument;
}): Promise<{ readonly reused: boolean }> {
  assertRecord(input, "static time authority publication input");
  assertExactKeys(input, ["stateRoot", "runId", "document"], "static time authority publication input");
  assertDocumentValid("pi_gacw_static_time_authority_v0", input.document);
  if (input.document.run_id !== input.runId) throw new StateStoreError("RUN_ID_MISMATCH", "static time authority belongs to another run");
  return withRunExclusive(input, async () => {
    const layout = assertLocation(input);
    // Fresh runs initialize the directory normally (initializeLayout); a legacy
    // retained run that somehow reaches real publication creates it exactly here,
    // never during read-only inspection.
    if (await existingStats(layout.staticTimeAuthorityDirectory) === undefined) {
      await ensurePrivateDirectory(layout.staticTimeAuthorityDirectory);
      await syncDirectory(layout.recordsDirectory);
    }
    const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
    requireUsableInspection(inspection);
    if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
      throw new StateStoreError("TERMINAL_STATE_IMMUTABLE", "Cannot publish static time authority to a terminal run");
    }
    const existing = await readStaticTimeAuthorityDocuments(layout);
    // V1-R2D-TIME-R2: semantic uniqueness is decided by CARDINALITY over ALL
    // physical records for this authority_id, never by which file is found first.
    const sameKey = timingRecordsForKey(existing, input.document.authority_id);
    if (sameKey.length > 1) {
      // Out-of-band duplicates poison the semantic key even when the candidate
      // byte-exactly equals one of them: no digest/file-order arbitration.
      throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "multiple immutable timing documents share one semantic authority key");
    }
    if (sameKey.length === 1) {
      if (sameKey[0]!.content_sha256 !== input.document.content_sha256 || canonicalize(sameKey[0]!) !== canonicalize(input.document)) {
        throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "A different immutable timing document already owns this semantic authority key");
      }
      return { reused: true } as const;
    }
    const publication = await publishJsonDocument(layout, "M2_STATIC_TIME_AUTHORITY", input.document as unknown as Record<string, unknown>);
    await readJsonDocument(layout, "M2_STATIC_TIME_AUTHORITY", input.document.content_sha256);
    return detachedFrozen(publication);
  });
}

/** Package-internal post-publication durable reread; cardinality decides, never file order. */
export async function durableStaticTimeAuthority(input: RunStorageLocation, authorityId: string): Promise<StaticTimeAuthorityDocument> {
  const matches = timingRecordsForKey(await readStaticTimeAuthorities(input), authorityId);
  if (matches.length === 0) {
    throw new StateStoreError("STATIC_TIME_AUTHORITY_DURABILITY_UNKNOWN", "the sampled timing document is not durably readable after publication");
  }
  if (matches.length > 1) {
    throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "multiple immutable timing documents share this semantic authority key");
  }
  return matches[0]!;
}

/**
 * Samples the clock ONCE, publishes-or-reuses the WORKFLOW timing document, and
 * returns the exact durable document. A response-loss retry reuses the original
 * timestamp; an uncertain-durability failure refuses instead of resampling.
 */
export async function establishWorkflowStaticTimeAuthority(input: RunStorageLocation & {
  readonly approvedPlanContentSha256: Sha256Digest;
  readonly workflowWallBudgetMs: number;
  readonly epoch: { readonly revision: number; readonly workflow_state_content_sha256: string; readonly transition_commit_content_sha256: string };
}): Promise<WorkflowTimeAuthorityDocument> {
  assertRecord(input, "workflow timing establishment input");
  assertExactKeys(input, ["stateRoot", "runId", "approvedPlanContentSha256", "workflowWallBudgetMs", "epoch"], "workflow timing establishment input");
  // Reuse an already-durable semantic key WITHOUT sampling so a post-crash retry
  // can never mint a newer timestamp for the same epoch. Cardinality first: more
  // than one physical record for this key conflicts before anything else happens.
  const workflowKey = workflowStaticTimeAuthorityIdentity({
    run_id: input.runId,
    approved_plan_content_sha256: input.approvedPlanContentSha256,
    predecessor_transition_commit_content_sha256: input.epoch.transition_commit_content_sha256,
  });
  const workflowMatches = timingRecordsForKey(await readStaticTimeAuthorities(input), workflowKey);
  if (workflowMatches.length > 1) {
    throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "multiple immutable WORKFLOW timing documents share this semantic authority key");
  }
  const reusableWorkflow = workflowMatches.length === 1 ? workflowMatches[0] as WorkflowTimeAuthorityDocument : undefined;
  if (reusableWorkflow !== undefined) {
    // Defense-in-depth: blind reuse by key is not enough. The durable record must
    // exactly match the requested immutable semantics; anything else fails closed
    // WITHOUT resampling.
    const workflowReuse = reusableWorkflow as WorkflowTimeAuthorityDocument;
    if (
      workflowReuse.authority_scope !== "WORKFLOW" ||
      workflowReuse.authority_id !== workflowKey ||
      workflowReuse.approved_plan_content_sha256 !== input.approvedPlanContentSha256 ||
      workflowReuse.predecessor_revision !== input.epoch.revision ||
      workflowReuse.predecessor_workflow_state_content_sha256 !== input.epoch.workflow_state_content_sha256 ||
      workflowReuse.predecessor_transition_commit_content_sha256 !== input.epoch.transition_commit_content_sha256 ||
      workflowReuse.wall_budget_ms !== input.workflowWallBudgetMs
    ) {
      throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "a durable WORKFLOW timing document with this semantic key does not match the requested immutable semantics");
    }
    return workflowReuse;
  }
  const startedAtEpochMs = sampleStartedAtEpochMs();
  const document = buildWorkflowStaticTimeAuthority({
    runId: input.runId,
    approvedPlanContentSha256: input.approvedPlanContentSha256,
    epoch: input.epoch,
    workflowWallBudgetMs: input.workflowWallBudgetMs,
    startedAtEpochMs,
  });
  const expectedKey = workflowKey;
  if (document.authority_id !== expectedKey || document.content_sha256 === null) throw new StateStoreError("IDENTITY_MISMATCH", "workflow timing identity projection failed");
  await publishStaticTimeAuthority({ stateRoot: input.stateRoot, runId: input.runId, document });
  const durable = await durableStaticTimeAuthority({ stateRoot: input.stateRoot, runId: input.runId }, expectedKey);
  if (durable.content_sha256 !== document.content_sha256) throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "a different workflow timing document owns this semantic key");
  return durable as WorkflowTimeAuthorityDocument;
}

/** NODE variant: same single-sample publish-or-reuse semantics bound to one exact READY epoch. */
export async function establishNodeStaticTimeAuthority(input: RunStorageLocation & {
  readonly taskId: string;
  readonly nodeWallBudgetMs: number;
  readonly workflowTimeAuthorityContentSha256: Sha256Digest;
  readonly epoch: { readonly revision: number; readonly workflow_state_content_sha256: string; readonly transition_commit_content_sha256: string };
}): Promise<NodeTimeAuthorityDocument> {
  assertRecord(input, "node timing establishment input");
  assertExactKeys(input, ["stateRoot", "runId", "taskId", "nodeWallBudgetMs", "workflowTimeAuthorityContentSha256", "epoch"], "node timing establishment input");
  // Same reuse-first rule as the WORKFLOW variant, with the same cardinality guard:
  // duplicate physical records for this key conflict BEFORE any clock sample.
  const nodeKey = nodeStaticTimeAuthorityIdentity({
    run_id: input.runId,
    workflow_time_authority_content_sha256: input.workflowTimeAuthorityContentSha256,
    predecessor_transition_commit_content_sha256: input.epoch.transition_commit_content_sha256,
  });
  const nodeMatches = timingRecordsForKey(await readStaticTimeAuthorities(input), nodeKey);
  if (nodeMatches.length > 1) {
    throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "multiple immutable NODE timing documents share this semantic authority key");
  }
  const reusableNode = nodeMatches.length === 1 ? nodeMatches[0] as NodeTimeAuthorityDocument : undefined;
  if (reusableNode !== undefined) {
    // Same defense-in-depth as the WORKFLOW variant: exact requested semantics or
    // typed conflict, never a silent reuse and never a resample.
    const nodeReuse = reusableNode as NodeTimeAuthorityDocument;
    if (
      nodeReuse.authority_scope !== "NODE" ||
      nodeReuse.authority_id !== nodeKey ||
      nodeReuse.workflow_time_authority_content_sha256 !== input.workflowTimeAuthorityContentSha256 ||
      nodeReuse.predecessor_revision !== input.epoch.revision ||
      nodeReuse.predecessor_workflow_state_content_sha256 !== input.epoch.workflow_state_content_sha256 ||
      nodeReuse.predecessor_transition_commit_content_sha256 !== input.epoch.transition_commit_content_sha256 ||
      nodeReuse.task_id !== input.taskId ||
      nodeReuse.wall_budget_ms !== input.nodeWallBudgetMs
    ) {
      throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "a durable NODE timing document with this semantic key does not match the requested immutable semantics");
    }
    return nodeReuse;
  }
  const startedAtEpochMs = sampleStartedAtEpochMs();
  const document = buildNodeStaticTimeAuthority({
    runId: input.runId,
    taskId: input.taskId,
    epoch: input.epoch,
    workflowTimeAuthorityContentSha256: input.workflowTimeAuthorityContentSha256,
    nodeWallBudgetMs: input.nodeWallBudgetMs,
    startedAtEpochMs,
  });
  const expectedKey = nodeKey;
  if (document.authority_id !== expectedKey) throw new StateStoreError("IDENTITY_MISMATCH", "node timing identity projection failed");
  await publishStaticTimeAuthority({ stateRoot: input.stateRoot, runId: input.runId, document });
  const durable = await durableStaticTimeAuthority({ stateRoot: input.stateRoot, runId: input.runId }, expectedKey);
  if (durable.content_sha256 !== document.content_sha256) throw new StateStoreError("STATIC_TIME_AUTHORITY_CONFLICT", "a different node timing document owns this semantic key");
  return durable as NodeTimeAuthorityDocument;
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
  await m5PersistenceCheckpoint("BEFORE_TRANSITION_EVIDENCE_PUBLICATION", input.transitionId);
  const preparedEvidence = await publishEvidenceBytes(layout, input.evidence);

  // Phase 2: metadata and every immutable JSON record required by this transition.
  const receipts = await publishEvidenceMetadata(layout, inspection.runId, preparedEvidence);
  const manifest = identifiedManifest(inspection.runId, receipts);
  await m5PersistenceCheckpoint("AFTER_TRANSITION_EVIDENCE_PUBLICATION", input.transitionId);
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
  await m5PersistenceCheckpoint("BEFORE_TRANSITION_COMMIT_PUBLICATION", input.transitionId);
  await publishJsonDocument(layout, "TRANSITION_COMMIT", commit as unknown as Record<string, unknown>);
  await readJsonDocument(layout, "TRANSITION_COMMIT", commit.content_sha256);
  await m5PersistenceCheckpoint("AFTER_TRANSITION_COMMIT_PUBLICATION", input.transitionId);

  // One-writer precondition still applies; this catches sequentially observed drift.
  await rereadBeforeStateUpdate(layout, inspection.statePointer, inspection.workflowState);

  // Phase 4: state.json is the sole mutable authority and is published last.
  const pointer = reconstructPointer(commit);
  await m5PersistenceCheckpoint("BEFORE_STATE_POINTER_UPDATE", input.transitionId);
  await replaceStateFile(layout.stateFile, canonicalJsonBytes(pointer));
  await m5PersistenceCheckpoint("AFTER_STATE_POINTER_UPDATE", input.transitionId);
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
  const capturedEvidence = captureEvidenceInputs(input.evidence === undefined ? [] : input.evidence);
  return withRunExclusive(input, () => commitTransitionUnlocked(input, capturedEvidence));
}

async function commitTransitionUnlocked(input: CommitTransitionInput, capturedEvidence: readonly CapturedEvidenceInput[]): Promise<CommittedRunState> {
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
  const evidence = capturedEvidence;
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

export interface ProcessCrashTerminalizationAuthority {
  readonly inspection: RunStorageInspection & {
    readonly statePointer: PersistedStatePointerDocument;
    readonly workflowState: WorkflowState;
    readonly transitionCommit: StateTransitionCommitDocument;
    readonly revision: number;
  };
  readonly policy: ReducerPolicy;
}

/** Package-internal exact authority loader for an external lifecycle owner. */
export async function loadProcessCrashTerminalizationAuthority(input: RunStorageLocation): Promise<ProcessCrashTerminalizationAuthority> {
  assertRecord(input, "process-crash authority input");
  assertExactKeys(input, ["stateRoot", "runId"], "process-crash authority input");
  const layout = assertLocation(input);
  const inspection = await inspectRunStorage(input);
  requireUsableInspection(inspection);
  const policy = await readJsonDocument<ReducerPolicy>(layout, "REDUCER_POLICY", inspection.transitionCommit.reducer_policy_content_sha256);
  assertReducerPolicy(policy);
  assertStatePolicyConsistency(inspection.workflowState, policy);
  return detachedFrozen({ inspection, policy });
}

export async function terminalizeProcessCrash(input: TerminalizeProcessCrashInput): Promise<CommittedRunState> {
  return withRunExclusive(input, () => terminalizeProcessCrashUnlocked(input));
}

async function terminalizeProcessCrashUnlocked(input: TerminalizeProcessCrashInput): Promise<CommittedRunState> {
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
