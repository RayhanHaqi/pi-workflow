import { lstat, realpath } from "node:fs/promises";
import { join } from "node:path";

import { sha256Canonical, type Sha256Digest } from "../identity/index.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type BaselineApprovalDocument,
  type BaselineDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselinePath,
  type M3BaselineRuntimeDocument,
  type M3FileSetFingerprint,
  type M3GitStateFingerprintDocument,
  type M3RepositoryIdentityDocument,
} from "../schemas/index.js";
import { RepositoryGuardError, repositoryGuardError } from "./errors.js";
import { captureGitState } from "./fingerprint.js";
import { resolveRepositoryIdentity } from "./identity.js";
import {
  assertWorktreeLockHeld,
  lockMatchesRepository,
  type WorktreeLockHandle,
} from "./lock.js";
import {
  MAX_BASELINE_BLOB_BYTES_PER_RUN,
  MAX_SINGLE_BLOB_BYTES,
  assertManagedRecordAuthoritative,
  assertStateRootCapacity,
  assertUsableM3Storage,
  baselineBlobPath,
  baselineBlobQuotaLimit,
  canonicalJsonRecordBytes,
  checkedBaselineBlobByteSum,
  m3RecordExists,
  publishBaselineBlob,
  publishM3Record,
  readM3Records,
  requireExactM3Record,
  retainedBaselineBlobUsage,
  rollbackBaselinePublication,
  verifyBaselineBlob,
} from "./storage.js";
import {
  assertBaselineApprovalMatches,
  assertBaselineProducerSemantics,
  requireBaselineApprovalSemantics,
} from "./provenance.js";
import {
  assertAbsoluteNormalizedPath,
  assertBoolean,
  assertCanonicalRepositoryPath,
  assertDigest,
  assertExactKeys,
  assertIsoTimestamp,
  assertNonemptyString,
  assertRecord,
  assertSafeNonnegativeInteger,
  compareText,
  detachedFrozen,
  digestHex,
  hashRegularFile,
  lstatOrUndefined,
} from "./utils.js";

export type BaselineMode = "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY";
export type OwnershipClass = "OWNER_AUTHORITY" | "OWNER_ACCEPTED_MUTABLE" | "PREEXISTING_UNRELATED" | "GENERATED_ACCEPTED_BASELINE";
export type DataClass = "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE" | "SECRET" | "LARGE_BINARY" | "HASH_ONLY";
export type CaptureMode = "HASH_ONLY" | "BLOB";

const OWNERSHIP_CLASSES = new Set<OwnershipClass>([
  "OWNER_AUTHORITY", "OWNER_ACCEPTED_MUTABLE", "PREEXISTING_UNRELATED", "GENERATED_ACCEPTED_BASELINE",
]);
const DATA_CLASSES = new Set<DataClass>([
  "PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE", "SECRET", "LARGE_BINARY", "HASH_ONLY",
]);

export interface BaselinePathDecision {
  readonly path: string;
  readonly ownershipClass: OwnershipClass;
  /** null means the required conservative HASH_ONLY default. */
  readonly dataClass: DataClass | null;
  readonly captureMode: CaptureMode;
  readonly explicitBlobApproval: boolean;
  readonly retentionDaysAfterTerminal: number | null;
}

export interface FingerprintedFileInput {
  readonly path: string;
  readonly expectedSha256: Sha256Digest;
}

export interface CaptureBaselineInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly requestedPath: string;
  readonly mode: BaselineMode;
  readonly pathDecisions: readonly BaselinePathDecision[];
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly allowShallow: boolean;
  readonly allowPartialClone: boolean;
  readonly lock: WorktreeLockHandle;
}

export interface BaselineCaptureResult {
  readonly baseline: M3BaselineRuntimeDocument;
  readonly recordRelativePath: string;
}

export interface CreateBaselineApprovalInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approvedBy: string;
  readonly approvedAt: string;
}

export interface BaselineApprovalResult {
  readonly approval: M3BaselineApprovalRuntimeDocument;
  readonly recordRelativePath: string;
}

function assertRunId(runId: unknown): asserts runId is string {
  assertNonemptyString(runId, "runId", 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(runId)) throw new RepositoryGuardError("INVALID_ARGUMENT", "runId is invalid");
}

function assertFingerprintFileInput(value: unknown, label: string): asserts value is FingerprintedFileInput {
  assertRecord(value, label);
  assertExactKeys(value, ["path", "expectedSha256"], label);
  assertAbsoluteNormalizedPath(value["path"], `${label}.path`);
  assertDigest(value["expectedSha256"], `${label}.expectedSha256`);
}

export async function captureFileSetFingerprint(
  inputs: readonly FingerprintedFileInput[],
  driftCode: "INSTRUCTION_DRIFT" | "AUTHORITY_DRIFT",
): Promise<M3FileSetFingerprint> {
  if (!Array.isArray(inputs) || inputs.length > 10_000) throw new RepositoryGuardError("INVALID_ARGUMENT", "Fingerprint file set is invalid");
  const seen = new Set<string>();
  const entries: Array<{ path: string; real_path: string; mode: number; size: number; content_sha256: Sha256Digest }> = [];
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    assertFingerprintFileInput(input, `files[${index}]`);
    if (seen.has(input.path)) throw new RepositoryGuardError("INVALID_ARGUMENT", "Fingerprint file set contains a duplicate path");
    seen.add(input.path);
    let hashed;
    try {
      const before = await lstat(input.path);
      if (!before.isFile() || before.isSymbolicLink()) throw new RepositoryGuardError(driftCode, "A selected fingerprint path is not a regular file");
      hashed = await hashRegularFile(input.path, false);
    } catch (error: unknown) {
      if (error instanceof RepositoryGuardError && error.code === driftCode) throw error;
      throw repositoryGuardError(driftCode, "A selected fingerprint file cannot be verified", error);
    }
    if (hashed.contentSha256 !== input.expectedSha256) {
      throw new RepositoryGuardError(driftCode, "A selected fingerprint file differs from its expected identity", { path: input.path });
    }
    entries.push({
      path: input.path,
      real_path: await realpath(input.path),
      mode: hashed.mode,
      size: hashed.size,
      content_sha256: hashed.contentSha256,
    });
  }
  entries.sort((left, right) => compareText(left.path, right.path));
  return detachedFrozen({ entries, content_sha256: sha256Canonical(entries) });
}

function assertPathDecision(value: unknown, label: string): asserts value is BaselinePathDecision {
  assertRecord(value, label);
  assertExactKeys(value, [
    "path", "ownershipClass", "dataClass", "captureMode", "explicitBlobApproval", "retentionDaysAfterTerminal",
  ], label);
  assertCanonicalRepositoryPath(value["path"], `${label}.path`);
  if (!OWNERSHIP_CLASSES.has(value["ownershipClass"] as OwnershipClass)) {
    throw new RepositoryGuardError("BASELINE_PATH_UNCLASSIFIED", "A baseline path has no valid ownership class");
  }
  if (value["dataClass"] !== null && !DATA_CLASSES.has(value["dataClass"] as DataClass)) {
    throw new RepositoryGuardError("BASELINE_PATH_UNCLASSIFIED", "A baseline path has an unknown data class");
  }
  if (value["captureMode"] !== "HASH_ONLY" && value["captureMode"] !== "BLOB") {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "A baseline capture mode is invalid");
  }
  assertBoolean(value["explicitBlobApproval"], `${label}.explicitBlobApproval`);
  if (value["retentionDaysAfterTerminal"] !== null) {
    assertSafeNonnegativeInteger(value["retentionDaysAfterTerminal"], `${label}.retentionDaysAfterTerminal`);
  }
}

function dirtyPaths(fingerprint: M3GitStateFingerprintDocument): readonly string[] {
  const paths = new Set<string>();
  for (const entry of fingerprint.staged) {
    paths.add(entry.path);
    if (entry.status === "R" && entry.old_path !== null) paths.add(entry.old_path);
  }
  for (const entry of fingerprint.unstaged) {
    paths.add(entry.path);
    if (entry.status === "R" && entry.old_path !== null) paths.add(entry.old_path);
  }
  for (const entry of fingerprint.untracked) paths.add(entry.path);
  for (const entry of fingerprint.conflicts) paths.add(entry.path);
  return [...paths].sort(compareText);
}

function validateCapturePolicy(decision: BaselinePathDecision, dataClass: DataClass, fileType: "REGULAR" | "DELETED"): void {
  if (dataClass === "SECRET") throw new RepositoryGuardError("BASELINE_SECRET_PRESENT", "A SECRET path cannot enter an approved baseline", { path: decision.path });
  if (decision.captureMode === "BLOB") {
    if (fileType !== "REGULAR") throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "Deleted baseline state cannot be copied as a blob", { path: decision.path });
    if (dataClass === "LARGE_BINARY" || dataClass === "HASH_ONLY") {
      throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "The selected data class forbids blob capture", { path: decision.path });
    }
    if ((dataClass === "PRIVATE_SOURCE" || dataClass === "SENSITIVE") && !decision.explicitBlobApproval) {
      throw new RepositoryGuardError("BASELINE_DIRTY_NOT_APPROVED", "Restricted blob capture lacks explicit per-path owner approval", { path: decision.path });
    }
    if (decision.retentionDaysAfterTerminal === null) {
      throw new RepositoryGuardError("INVALID_ARGUMENT", "Copied baseline content requires an explicit retention decision", { path: decision.path });
    }
    const maximum = dataClass === "SENSITIVE" ? 7 : 30;
    if (decision.retentionDaysAfterTerminal < 1 || decision.retentionDaysAfterTerminal > maximum) {
      throw new RepositoryGuardError("INVALID_ARGUMENT", "Baseline retention decision exceeds its classification cap", { path: decision.path });
    }
  } else {
    if (decision.explicitBlobApproval || decision.retentionDaysAfterTerminal !== null) {
      throw new RepositoryGuardError("INVALID_ARGUMENT", "Hash-only baseline paths cannot carry blob approval or retention");
    }
  }
}

interface CurrentPathState {
  readonly contentSha256: Sha256Digest;
  readonly fileType: "REGULAR" | "DELETED";
  readonly mode: number | null;
  readonly size: number | null;
  readonly bytes: Buffer | null;
}

async function currentPathState(
  repository: M3RepositoryIdentityDocument,
  fingerprint: M3GitStateFingerprintDocument,
  path: string,
  captureBytes: boolean,
): Promise<CurrentPathState> {
  const status = statusProjection(fingerprint, path);
  const location = join(repository.worktree_root, path);
  const stats = await lstatOrUndefined(location);
  if (stats === undefined) {
    return {
      contentSha256: sha256Canonical({ path, state: "DELETED", status }),
      fileType: "DELETED",
      mode: null,
      size: null,
      bytes: null,
    };
  }
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "A dirty baseline path is not a regular file", { path });
  }
  const hashed = await hashRegularFile(location, captureBytes);
  return {
    contentSha256: hashed.contentSha256,
    fileType: "REGULAR",
    mode: hashed.mode,
    size: hashed.size,
    bytes: hashed.bytes,
  };
}

function statusProjection(fingerprint: M3GitStateFingerprintDocument, path: string): unknown {
  return {
    staged: fingerprint.staged.filter((entry) => entry.path === path || entry.old_path === path),
    unstaged: fingerprint.unstaged.filter((entry) => entry.path === path || entry.old_path === path),
    untracked: fingerprint.untracked.filter((entry) => entry.path === path),
    conflicts: fingerprint.conflicts.filter((entry) => entry.path === path),
  };
}

function acceptedRepository(repository: M3RepositoryIdentityDocument) {
  return {
    root: repository.worktree_root,
    git_common_dir: repository.git_common_dir,
    worktree: repository.worktree_root,
    branch: repository.branch ?? "DETACHED",
    head: repository.head,
  };
}

function assertRepositoryPolicy(repository: M3RepositoryIdentityDocument, allowShallow: boolean, allowPartialClone: boolean): void {
  if (repository.shallow && !allowShallow) throw new RepositoryGuardError("UNSUPPORTED_REPOSITORY_STATE", "Shallow repositories are disallowed by baseline policy");
  const partial = repository.partial_clone.promisor_remote !== null || repository.partial_clone.filters.length > 0;
  if (partial && !allowPartialClone) throw new RepositoryGuardError("UNSUPPORTED_REPOSITORY_STATE", "Partial-clone repositories are disallowed by baseline policy");
}

export async function captureBaseline(input: CaptureBaselineInput): Promise<BaselineCaptureResult> {
  assertRecord(input, "captureBaseline input");
  assertExactKeys(input, [
    "stateRoot", "runId", "requestedPath", "mode", "pathDecisions", "instructionFiles", "authorityFiles",
    "allowShallow", "allowPartialClone", "lock",
  ], "captureBaseline input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertRunId(input.runId);
  assertAbsoluteNormalizedPath(input.requestedPath, "requestedPath");
  if (input.mode !== "CLEAN_REQUIRED" && input.mode !== "APPROVED_BASELINE_DIRTY") {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "Baseline mode is invalid");
  }
  assertBoolean(input.allowShallow, "allowShallow");
  assertBoolean(input.allowPartialClone, "allowPartialClone");
  if (!Array.isArray(input.pathDecisions) || !Array.isArray(input.instructionFiles) || !Array.isArray(input.authorityFiles)) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "Baseline decision and fingerprint inputs must be arrays");
  }
  await assertUsableM3Storage({ stateRoot: input.stateRoot, runId: input.runId });

  const repository = await resolveRepositoryIdentity({ requestedPath: input.requestedPath, requireHead: true });
  const diagnostic = await assertWorktreeLockHeld(input.lock);
  if (!lockMatchesRepository(input.lock, repository) || diagnostic.worktree_key !== repository.worktree_key) {
    throw new RepositoryGuardError("WRONG_WORKTREE", "Held lock does not belong to the resolved worktree");
  }
  assertRepositoryPolicy(repository, input.allowShallow, input.allowPartialClone);
  const [fingerprint, instructionFingerprint, authorityFingerprint] = await Promise.all([
    captureGitState(repository),
    captureFileSetFingerprint(input.instructionFiles, "INSTRUCTION_DRIFT"),
    captureFileSetFingerprint(input.authorityFiles, "AUTHORITY_DRIFT"),
  ]);
  if (fingerprint.active_operations.length > 0) throw new RepositoryGuardError("GIT_OPERATION_IN_PROGRESS", "A Git operation is active");
  if (fingerprint.index_lock) throw new RepositoryGuardError("GIT_INDEX_LOCK_PRESENT", "Git index.lock is present");
  if (fingerprint.conflicts.length > 0) throw new RepositoryGuardError("GIT_CONFLICT_PRESENT", "Git conflicts are present");

  const paths = dirtyPaths(fingerprint);
  if (input.mode === "CLEAN_REQUIRED" && paths.length > 0) {
    throw new RepositoryGuardError("BASELINE_DIRTY_NOT_APPROVED", "CLEAN_REQUIRED rejects staged, unstaged, or untracked changes");
  }
  if (input.mode === "CLEAN_REQUIRED" && input.pathDecisions.length > 0) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "A clean baseline cannot contain path decisions");
  }

  const decisionByPath = new Map<string, BaselinePathDecision>();
  for (let index = 0; index < input.pathDecisions.length; index += 1) {
    const decision = input.pathDecisions[index];
    assertPathDecision(decision, `pathDecisions[${index}]`);
    if (decisionByPath.has(decision.path)) throw new RepositoryGuardError("INVALID_ARGUMENT", "A baseline path decision is duplicated", { path: decision.path });
    decisionByPath.set(decision.path, decision);
  }
  if (input.mode === "APPROVED_BASELINE_DIRTY") {
    for (const path of paths) {
      if (!decisionByPath.has(path)) throw new RepositoryGuardError("BASELINE_PATH_UNCLASSIFIED", "A dirty baseline path has no decision", { path });
    }
    for (const path of decisionByPath.keys()) {
      if (!paths.includes(path)) throw new RepositoryGuardError("BASELINE_APPROVAL_MISMATCH", "A baseline decision names a path outside the snapshot", { path });
    }
  }

  const runtimePaths: M3BaselinePath[] = [];
  const blobBytes = new Map<Sha256Digest, Buffer>();
  let logicalBytes = 0;
  for (const path of paths) {
    const decision = decisionByPath.get(path);
    if (decision === undefined) throw new RepositoryGuardError("BASELINE_PATH_UNCLASSIFIED", "A dirty path has no owner decision", { path });
    const dataClass = decision.dataClass ?? "HASH_ONLY";
    const state = await currentPathState(repository, fingerprint, path, decision.captureMode === "BLOB");
    validateCapturePolicy(decision, dataClass, state.fileType);
    let blob: M3BaselinePath["blob"] = null;
    if (decision.captureMode === "BLOB") {
      if (state.size === null || state.bytes === null || state.size > MAX_SINGLE_BLOB_BYTES) {
        throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "A selected baseline blob exceeds 1 MiB", { path });
      }
      logicalBytes += state.size;
      if (!Number.isSafeInteger(logicalBytes) || logicalBytes > MAX_BASELINE_BLOB_BYTES_PER_RUN) {
        throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "Logical approved baseline blobs exceed 64 MiB");
      }
      if (!blobBytes.has(state.contentSha256)) blobBytes.set(state.contentSha256, state.bytes);
      blob = {
        blob_sha256: state.contentSha256,
        byte_length: state.size,
        relative_path: `baseline-blobs/sha256/${digestHex(state.contentSha256)}`,
      };
    }
    runtimePaths.push({
      path,
      ownership_class: decision.ownershipClass,
      data_class: dataClass,
      capture_mode: decision.captureMode,
      explicit_blob_approval: decision.explicitBlobApproval,
      retention_days_after_terminal: decision.retentionDaysAfterTerminal,
      content_sha256: state.contentSha256,
      file_type: state.fileType,
      mode: state.mode,
      size: state.size,
      status_sha256: sha256Canonical(statusProjection(fingerprint, path)),
      blob,
    });
  }
  runtimePaths.sort((left, right) => compareText(left.path, right.path));
  const physicalBytes = [...blobBytes.values()].reduce((total, bytes) => checkedBaselineBlobByteSum(total, bytes.byteLength), 0);
  if (physicalBytes > MAX_BASELINE_BLOB_BYTES_PER_RUN) {
    throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "Physical baseline blobs exceed 64 MiB");
  }

  const location = { stateRoot: input.stateRoot, runId: input.runId };
  const retainedBefore = await retainedBaselineBlobUsage(location);
  const retainedByDigest = new Map(retainedBefore.entries.map((entry) => [entry.blobSha256, entry.byteLength]));
  let newBlobBytes = 0;
  for (const [digest, bytes] of blobBytes) {
    const retainedSize = retainedByDigest.get(digest);
    if (retainedSize === undefined) {
      newBlobBytes = checkedBaselineBlobByteSum(newBlobBytes, bytes.byteLength);
    } else if (retainedSize !== bytes.byteLength) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retained blob size differs from proposed deduplicated content");
    } else {
      await verifyBaselineBlob(location, digest, bytes.byteLength);
    }
  }
  const resultingPhysicalBytes = checkedBaselineBlobByteSum(retainedBefore.physicalBytes, newBlobBytes);
  const quotaLimit = baselineBlobQuotaLimit();
  if (retainedBefore.physicalBytes > quotaLimit || resultingPhysicalBytes > quotaLimit) {
    throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "Cumulative retained baseline blobs exceed the per-run limit", {
      existing_physical_bytes: retainedBefore.physicalBytes,
      new_unique_physical_bytes: newBlobBytes,
      resulting_physical_bytes: resultingPhysicalBytes,
      maximum_bytes: quotaLimit,
    });
  }

  const accepted = identifyContractDocument("pi_gacw_baseline_v0", {
    schema_id: "pi_gacw_baseline_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    baseline_projection_id: "baseline-snapshot-v1",
    target_repository: acceptedRepository(repository),
    mode: input.mode,
    git_state_sha256: fingerprint.content_sha256,
    staged_paths: [...new Set(fingerprint.staged.map((entry) => entry.path))].sort(compareText),
    unstaged_paths: [...new Set(fingerprint.unstaged.map((entry) => entry.path))].sort(compareText),
    untracked_paths: fingerprint.untracked.map((entry) => entry.path).sort(compareText),
    files: runtimePaths.map((entry) => ({
      path: entry.path,
      content_sha256: entry.content_sha256,
      ownership_class: entry.ownership_class,
      data_class: entry.data_class,
    })),
  }) as unknown as BaselineDocument;

  const baseline = identifyContractDocument("pi_gacw_baseline_runtime_v0", {
    schema_id: "pi_gacw_baseline_runtime_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    baseline_mode: input.mode,
    repository,
    git_fingerprint: fingerprint,
    accepted_baseline: accepted,
    instruction_fingerprint: instructionFingerprint,
    authority_fingerprint: authorityFingerprint,
    paths: runtimePaths,
    blob_quota: {
      logical_approved_bytes: logicalBytes,
      physical_bytes: physicalBytes,
      deduplicated_bytes: logicalBytes - physicalBytes,
      existing_physical_bytes: retainedBefore.physicalBytes,
      new_unique_physical_bytes: newBlobBytes,
      resulting_physical_bytes: resultingPhysicalBytes,
    },
  }) as unknown as M3BaselineRuntimeDocument;
  // Publication and every durable consumer share exact producer semantics.
  const priorBaselines = await readM3Records(location, "BASELINE");
  await assertBaselineProducerSemantics(baseline, [...priorBaselines, baseline]);

  const retainedBeforePublication = await retainedBaselineBlobUsage(location);
  if (retainedBeforePublication.inventorySha256 !== retainedBefore.inventorySha256 ||
      retainedBeforePublication.physicalBytes !== retainedBefore.physicalBytes) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Retained baseline-blob population changed before publication");
  }
  const recordIsNew = !await m3RecordExists(location, "BASELINE", baseline.content_sha256);
  const recordBytes = recordIsNew ? canonicalJsonRecordBytes(baseline).byteLength : 0;
  await assertStateRootCapacity(input.stateRoot, newBlobBytes + recordBytes);
  const rollbackCandidates = [...blobBytes].filter(([digest]) => !retainedByDigest.has(digest)).map(([digest, bytes]) => ({
    digest,
    byteLength: bytes.byteLength,
  }));
  try {
    for (const [digest, bytes] of blobBytes) {
      const receipt = await publishBaselineBlob(location, bytes);
      if (receipt.digest !== digest) throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Baseline blob bytes changed before publication");
    }
    const record = await publishM3Record(location, "BASELINE", baseline as unknown as Record<string, unknown>);
    return detachedFrozen({ baseline, recordRelativePath: record.relativePath });
  } catch (publicationError: unknown) {
    try {
      await rollbackBaselinePublication(location, baseline, recordIsNew, rollbackCandidates);
    } catch (cleanupError: unknown) {
      if (cleanupError instanceof RepositoryGuardError) throw cleanupError;
      throw repositoryGuardError(
        "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN",
        "Baseline publication rollback could not be proved complete",
        cleanupError,
      );
    }
    throw publicationError;
  }
}

export async function createBaselineApproval(input: CreateBaselineApprovalInput): Promise<BaselineApprovalResult> {
  assertRecord(input, "createBaselineApproval input");
  assertExactKeys(input, ["stateRoot", "runId", "baseline", "approvedBy", "approvedAt"], "createBaselineApproval input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertRunId(input.runId);
  assertNonemptyString(input.approvedBy, "approvedBy", 1024);
  assertIsoTimestamp(input.approvedAt, "approvedAt");
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  if (input.baseline.run_id !== input.runId || input.baseline.baseline_mode !== "APPROVED_BASELINE_DIRTY") {
    throw new RepositoryGuardError("BASELINE_APPROVAL_MISMATCH", "Approval requires the exact dirty baseline and run ID");
  }
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  await assertUsableM3Storage(location);
  const durableBaseline = await requireExactM3Record(
    location,
    "BASELINE",
    input.baseline,
    "BASELINE_RECORD_MISSING",
    "BASELINE_RECORD_MISMATCH",
  );
  const allBaselines = await readM3Records(location, "BASELINE");
  await assertBaselineProducerSemantics(durableBaseline, allBaselines);
  await verifyBaselineBlobs(input.stateRoot, durableBaseline);
  await assertManagedRecordAuthoritative(location, "M3_BASELINE", durableBaseline.content_sha256);
  const acceptedApproval = identifyContractDocument("pi_gacw_baseline_approval_v0", {
    schema_id: "pi_gacw_baseline_approval_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    baseline_approval_projection_id: "baseline-approval-v1",
    baseline_sha256: input.baseline.accepted_baseline.baseline_sha256,
    target_repository: input.baseline.accepted_baseline.target_repository,
    approved_by: input.approvedBy,
  }) as unknown as BaselineApprovalDocument;
  const retentionProjection = input.baseline.paths.map((entry) => ({
    path: entry.path,
    data_class: entry.data_class,
    capture_mode: entry.capture_mode,
    retention_days_after_terminal: entry.retention_days_after_terminal,
    blob: entry.blob,
  }));
  const approval = identifyContractDocument("pi_gacw_baseline_approval_runtime_v0", {
    schema_id: "pi_gacw_baseline_approval_runtime_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    baseline_snapshot_sha256: input.baseline.accepted_baseline.baseline_sha256,
    baseline_snapshot_content_sha256: input.baseline.accepted_baseline.content_sha256,
    accepted_approval: acceptedApproval,
    approved_by: input.approvedBy,
    approved_at: input.approvedAt,
    approval_scope: "EXACT_BASELINE",
    decisions: input.baseline.paths,
    decisions_sha256: sha256Canonical(input.baseline.paths),
    retention_sha256: sha256Canonical(retentionProjection),
  }) as unknown as M3BaselineApprovalRuntimeDocument;
  assertBaselineApprovalMatches(input.baseline, approval);
  const recordIsNew = !await m3RecordExists({ stateRoot: input.stateRoot, runId: input.runId }, "BASELINE_APPROVAL", approval.content_sha256);
  await assertStateRootCapacity(input.stateRoot, recordIsNew ? canonicalJsonRecordBytes(approval).byteLength : 0);
  const record = await publishM3Record(
    { stateRoot: input.stateRoot, runId: input.runId },
    "BASELINE_APPROVAL",
    approval as unknown as Record<string, unknown>,
  );
  return detachedFrozen({ approval, recordRelativePath: record.relativePath });
}

export async function requireDurableBaselineAuthority(
  stateRoot: string,
  runId: string,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  requirePopulationAuthority = true,
): Promise<{ readonly baseline: M3BaselineRuntimeDocument; readonly approval: M3BaselineApprovalRuntimeDocument | null }> {
  const location = { stateRoot, runId };
  const durableBaseline = await requireExactM3Record(
    location,
    "BASELINE",
    baseline,
    "BASELINE_RECORD_MISSING",
    "BASELINE_RECORD_MISMATCH",
  );
  const allBaselines = await readM3Records(location, "BASELINE");
  await assertBaselineProducerSemantics(durableBaseline, allBaselines);
  let durableApproval: M3BaselineApprovalRuntimeDocument | null = null;
  if (approval !== null) {
    durableApproval = await requireExactM3Record(
      location,
      "BASELINE_APPROVAL",
      approval,
      "BASELINE_APPROVAL_RECORD_MISSING",
      "BASELINE_APPROVAL_RECORD_MISMATCH",
    );
  }
  requireBaselineApprovalSemantics(durableBaseline, durableApproval);
  if (requirePopulationAuthority) {
    await assertManagedRecordAuthoritative(location, "M3_BASELINE", durableBaseline.content_sha256);
    if (durableApproval !== null) {
      await assertManagedRecordAuthoritative(location, "M3_BASELINE_APPROVAL", durableApproval.content_sha256);
    }
  }
  return detachedFrozen({ baseline: durableBaseline, approval: durableApproval });
}

export async function verifyBaselineApproval(input: {
  readonly stateRoot: string;
  readonly runId: string;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument;
}): Promise<boolean> {
  try {
    assertRecord(input, "verifyBaselineApproval input");
    assertExactKeys(input, ["stateRoot", "runId", "baseline", "approval"], "verifyBaselineApproval input");
    assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
    assertRunId(input.runId);
    await requireDurableBaselineAuthority(input.stateRoot, input.runId, input.baseline, input.approval);
    return true;
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError || error instanceof TypeError) return false;
    throw error;
  }
}

export function requireBaselineApproval(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
): void {
  requireBaselineApprovalSemantics(baseline, approval);
}

export async function verifyBaselineBlobs(stateRoot: string, baseline: M3BaselineRuntimeDocument): Promise<void> {
  for (const path of baseline.paths) {
    if (path.blob !== null) {
      await verifyBaselineBlob({ stateRoot, runId: baseline.run_id }, path.blob.blob_sha256, path.blob.byte_length);
      if (path.blob.relative_path !== `baseline-blobs/sha256/${digestHex(path.blob.blob_sha256)}` ||
          baselineBlobPath({ stateRoot, runId: baseline.run_id }, path.blob.blob_sha256) !==
            join(stateRoot, "runs", baseline.run_id, path.blob.relative_path)) {
        throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Baseline blob metadata path is invalid");
      }
    }
  }
}
