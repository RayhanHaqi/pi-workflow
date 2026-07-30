import { lstat, readFile, readdir, unlink } from "node:fs/promises";
import { join, relative, sep } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { assertPrivateDirectory, assertRegularPrivateFile, fsyncDirectory, publishImmutableFile } from "../persistence/atomic.js";
import { inspectRunStorage } from "../persistence/index.js";
import { inspectRunStorageForRetention } from "../persistence/store.js";
import {
  assertDocumentValid,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3PostflightDocument,
  type M3PreflightDocument,
  type M3RepositoryStateTokenDocument,
  type M3RetentionResultDocument,
  type M3TerminalRetentionAuthorityDocument,
  type SchemaId,
  type WorkflowState,
} from "../schemas/index.js";
import { RepositoryGuardError, repositoryGuardError, type RepositoryGuardErrorCode } from "./errors.js";
import { assertBaselineProducerSemantics, assertBaselineRuntimeSemantics } from "./provenance.js";
import {
  buildRetentionAuthorityContext,
  exactRetentionDeletionProof,
  type RetentionAuthorityContext,
} from "./retention-groups.js";
import { repositoryTestHooks } from "./test-hooks.js";
import {
  assertAbsoluteNormalizedPath,
  assertDigest,
  assertNonemptyString,
  compareText,
  detachedFrozen,
  digestHex,
  hashRegularFile,
  lstatOrUndefined,
} from "./utils.js";

export const MAX_SINGLE_BLOB_BYTES = 1_048_576;
export const MAX_BASELINE_BLOB_BYTES_PER_RUN = 67_108_864;
export const MAX_STATE_ROOT_BYTES = 2_147_483_648;
const RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const JSON_FILE_PATTERN = /^[0-9a-f]{64}\.json$/;

export type M3RecordKind =
  | "BASELINE"
  | "BASELINE_APPROVAL"
  | "LOCK_ACQUISITION"
  | "LOCK_DIAGNOSTIC"
  | "PREFLIGHT"
  | "REPOSITORY_STATE_TOKEN"
  | "POSTFLIGHT"
  | "RETENTION_RESULT";

const recordDefinitions: Readonly<Record<M3RecordKind, { readonly directory: string; readonly schemaId: SchemaId }>> = Object.freeze({
  BASELINE: { directory: "baselines", schemaId: "pi_gacw_baseline_runtime_v0" },
  BASELINE_APPROVAL: { directory: "baseline-approvals", schemaId: "pi_gacw_baseline_approval_runtime_v0" },
  LOCK_ACQUISITION: { directory: "lock-acquisitions", schemaId: "pi_gacw_lock_acquisition_v0" },
  LOCK_DIAGNOSTIC: { directory: "lock-diagnostics", schemaId: "pi_gacw_lock_diagnostic_v0" },
  PREFLIGHT: { directory: "preflights", schemaId: "pi_gacw_preflight_v0" },
  REPOSITORY_STATE_TOKEN: { directory: "repository-state-tokens", schemaId: "pi_gacw_repository_state_token_v0" },
  POSTFLIGHT: { directory: "postflights", schemaId: "pi_gacw_postflight_v0" },
  RETENTION_RESULT: { directory: "retention", schemaId: "pi_gacw_retention_result_v0" },
});

export interface M3StorageLocation {
  readonly stateRoot: string;
  readonly runId: string;
}

function assertLocation(location: M3StorageLocation): void {
  assertAbsoluteNormalizedPath(location.stateRoot, "stateRoot");
  assertNonemptyString(location.runId, "runId", 64);
  if (!RUN_ID_PATTERN.test(location.runId)) throw new RepositoryGuardError("INVALID_ARGUMENT", "runId is invalid");
}

function runDirectory(location: M3StorageLocation): string {
  return join(location.stateRoot, "runs", location.runId);
}

function recordDirectory(location: M3StorageLocation, kind: M3RecordKind): string {
  return join(runDirectory(location), "records", recordDefinitions[kind].directory);
}

export function m3RecordPath(location: M3StorageLocation, kind: M3RecordKind, digest: string): string {
  return join(recordDirectory(location, kind), `${digestHex(digest)}.json`);
}

export async function m3RecordExists(location: M3StorageLocation, kind: M3RecordKind, digest: string): Promise<boolean> {
  const stats = await lstatOrUndefined(m3RecordPath(location, kind, digest));
  return stats !== undefined;
}

export async function m3RecordIsExact<K extends M3RecordKind>(
  location: M3StorageLocation,
  kind: K,
  document: M3RecordDocumentByKind[K],
): Promise<boolean> {
  if (!await m3RecordExists(location, kind, document.content_sha256)) return false;
  const durable = await loadM3Record(location, kind, document.content_sha256);
  if (!canonicalJsonRecordBytes(durable).equals(canonicalJsonRecordBytes(document))) {
    throw new RepositoryGuardError("STATE_STORAGE_INVALID", `${kind} existing immutable record differs from the proposed object`);
  }
  return true;
}

export function baselineBlobDirectory(location: M3StorageLocation): string {
  return join(runDirectory(location), "baseline-blobs", "sha256");
}

export function baselineBlobPath(location: M3StorageLocation, digest: string): string {
  return join(baselineBlobDirectory(location), digestHex(digest));
}

export async function assertUsableM3Storage(location: M3StorageLocation): Promise<void> {
  assertLocation(location);
  const inspection = await inspectRunStorage(location);
  if (inspection.status !== "HEALTHY") {
    throw new RepositoryGuardError("STATE_STORAGE_INVALID", "Run storage is not a complete healthy M2 graph", { status: inspection.status });
  }
  await assertPrivateDirectory(join(location.stateRoot, "locks"));
  await assertPrivateDirectory(baselineBlobDirectory(location));
  for (const kind of Object.keys(recordDefinitions) as M3RecordKind[]) {
    await assertPrivateDirectory(recordDirectory(location, kind));
  }
}

/** Require the classifier's complete physical/proof authority for one durable record. */
export async function assertManagedRecordAuthoritative(
  location: M3StorageLocation,
  kind: "M3_BASELINE" | "M3_BASELINE_APPROVAL",
  digest: string,
): Promise<void> {
  const inspection = await inspectRunStorage(location);
  const decision = inspection.managedRecordClassifications.find((entry) =>
    entry.object.kind === kind && entry.object.contentSha256 === digest);
  if (decision?.classification === "AUTHORITATIVE_MANAGED_RECORD") return;
  throw new RepositoryGuardError(
    "BASELINE_PROVENANCE_INVALID",
    "Durable baseline authority has incomplete retained-population continuity",
    { kind, classification: decision?.classification ?? "MISSING" },
  );
}

export function baselineBlobQuotaLimit(): number {
  const configured = repositoryTestHooks().baselineBlobLimitBytes;
  if (configured === undefined) return MAX_BASELINE_BLOB_BYTES_PER_RUN;
  if (!Number.isSafeInteger(configured) || configured < 0 || configured > MAX_BASELINE_BLOB_BYTES_PER_RUN) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "Private baseline-blob limit is invalid");
  }
  return configured;
}

export function checkedBaselineBlobByteSum(left: number, right: number): number {
  if (!Number.isSafeInteger(left) || left < 0 || !Number.isSafeInteger(right) || right < 0 ||
      !Number.isSafeInteger(left + right)) {
    throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "Baseline-blob accounting overflowed safe-integer bounds");
  }
  return left + right;
}

type M3RecordDocumentByKind = {
  readonly BASELINE: M3BaselineRuntimeDocument;
  readonly BASELINE_APPROVAL: M3BaselineApprovalRuntimeDocument;
  readonly LOCK_ACQUISITION: M3LockAcquisitionDocument;
  readonly LOCK_DIAGNOSTIC: M3LockDiagnosticDocument;
  readonly PREFLIGHT: M3PreflightDocument;
  readonly REPOSITORY_STATE_TOKEN: M3RepositoryStateTokenDocument;
  readonly POSTFLIGHT: M3PostflightDocument;
  readonly RETENTION_RESULT: M3RetentionResultDocument;
};

async function decodeM3Record<K extends M3RecordKind>(
  location: M3StorageLocation,
  kind: K,
  path: string,
  expectedDigest: string,
  failureCode: RepositoryGuardErrorCode,
): Promise<M3RecordDocumentByKind[K]> {
  try {
    await assertRegularPrivateFile(path);
    const bytes = await readFile(path);
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    assertDocumentValid(recordDefinitions[kind].schemaId, value);
    const document = value as Record<string, unknown>;
    if (document["content_sha256"] !== expectedDigest ||
        (kind !== "LOCK_ACQUISITION" && kind !== "LOCK_DIAGNOSTIC" && document["run_id"] !== location.runId) ||
        !bytes.equals(canonicalJsonRecordBytes(document))) {
      throw new RepositoryGuardError(failureCode, `${kind} metadata address, run, or encoding is invalid`);
    }
    return detachedFrozen(value as M3RecordDocumentByKind[K]);
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError && error.code === failureCode) throw error;
    throw repositoryGuardError(failureCode, `${kind} metadata is missing, unsafe, or malformed`, error);
  }
}

export async function loadM3Record<K extends M3RecordKind>(
  location: M3StorageLocation,
  kind: K,
  digest: string,
  missingCode: RepositoryGuardErrorCode = "STATE_STORAGE_INVALID",
  mismatchCode: RepositoryGuardErrorCode = "STATE_STORAGE_INVALID",
): Promise<M3RecordDocumentByKind[K]> {
  assertLocation(location);
  assertDigest(digest, `${kind} record identity`);
  const path = m3RecordPath(location, kind, digest);
  if (await lstatOrUndefined(path) === undefined) {
    throw new RepositoryGuardError(missingCode, `${kind} durable record is missing`);
  }
  return decodeM3Record(location, kind, path, digest, mismatchCode);
}

export async function requireExactM3Record<K extends M3RecordKind>(
  location: M3StorageLocation,
  kind: K,
  provided: M3RecordDocumentByKind[K],
  missingCode: RepositoryGuardErrorCode,
  mismatchCode: RepositoryGuardErrorCode,
): Promise<M3RecordDocumentByKind[K]> {
  const digest = provided.content_sha256;
  const durable = await loadM3Record(location, kind, digest, missingCode, mismatchCode);
  if (!canonicalJsonRecordBytes(durable).equals(canonicalJsonRecordBytes(provided))) {
    throw new RepositoryGuardError(mismatchCode, `${kind} caller document differs from its exact durable record`);
  }
  return durable;
}

export async function readM3Records<K extends M3RecordKind>(
  location: M3StorageLocation,
  kind: K,
): Promise<readonly M3RecordDocumentByKind[K][]> {
  const directory = recordDirectory(location, kind);
  await assertPrivateDirectory(directory);
  const records: M3RecordDocumentByKind[K][] = [];
  for (const name of (await readdir(directory)).sort(compareText)) {
    if (!JSON_FILE_PATTERN.test(name)) throw new RepositoryGuardError("STATE_STORAGE_INVALID", `${kind} directory contains an unexpected entry`);
    const digest = `sha256:${name.slice(0, -".json".length)}`;
    records.push(await decodeM3Record(location, kind, join(directory, name), digest, "STATE_STORAGE_INVALID"));
  }
  return records;
}

async function committedRetentionAuthorities(
  location: M3StorageLocation,
  expectedTargetDigests: readonly Sha256Digest[] = [],
): Promise<{ readonly workflowState: WorkflowState; readonly authorities: readonly M3TerminalRetentionAuthorityDocument[] }> {
  const inspection = expectedTargetDigests.length === 0
    ? await inspectRunStorage(location)
    : await inspectRunStorageForRetention(location, expectedTargetDigests);
  if (inspection.status !== "HEALTHY" || inspection.workflowState === null) {
    throw new RepositoryGuardError("STATE_STORAGE_INVALID", "Managed baseline authority requires healthy committed storage");
  }
  const authorities: M3TerminalRetentionAuthorityDocument[] = [];
  for (const object of inspection.reachableObjects) {
    if (object.kind !== "RAW_EVIDENCE") continue;
    let value: unknown;
    let bytes: Buffer;
    try {
      bytes = await readFile(join(runDirectory(location), object.relativePath));
      value = JSON.parse(bytes.toString("utf8"));
      assertDocumentValid("pi_gacw_terminal_retention_authority_v0", value);
    } catch {
      continue;
    }
    const authority = value as M3TerminalRetentionAuthorityDocument;
    if (authority.run_id === location.runId &&
        authority.terminal_workflow_state_content_sha256 === inspection.workflowState.content_sha256 &&
        bytes.equals(canonicalJsonRecordBytes(authority))) {
      authorities.push(authority);
    }
  }
  return { workflowState: inspection.workflowState, authorities };
}

export async function loadRetentionAuthorityContext(
  location: M3StorageLocation,
  expectedTargetDigests: readonly Sha256Digest[] = [],
): Promise<RetentionAuthorityContext> {
  const [committed, baselines, approvals] = await Promise.all([
    committedRetentionAuthorities(location, expectedTargetDigests),
    readM3Records(location, "BASELINE"),
    readM3Records(location, "BASELINE_APPROVAL"),
  ]);
  for (const baseline of baselines) await assertBaselineProducerSemantics(baseline, baselines);
  return buildRetentionAuthorityContext(committed.workflowState, baselines, approvals, committed.authorities);
}

export interface RetainedBaselineBlobUsage {
  readonly physicalBytes: number;
  readonly entries: readonly {
    readonly blobSha256: Sha256Digest;
    readonly byteLength: number;
  }[];
  readonly inventorySha256: Sha256Digest;
}

/** Enumerates and reconciles the complete currently retained blob population for one run. */
export async function retainedBaselineBlobUsage(location: M3StorageLocation): Promise<RetainedBaselineBlobUsage> {
  assertLocation(location);
  const directory = baselineBlobDirectory(location);
  await assertPrivateDirectory(directory);
  const entries: Array<{ blobSha256: Sha256Digest; byteLength: number }> = [];
  const byDigest = new Map<string, number>();
  let physicalBytes = 0;
  for (const name of (await readdir(directory)).sort(compareText)) {
    if (!/^[0-9a-f]{64}$/.test(name)) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retained baseline-blob storage contains an unknown entry");
    }
    const path = join(directory, name);
    const stats = await lstat(path);
    if (stats.isSymbolicLink() || !stats.isFile() || (stats.mode & 0o777) !== 0o600) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "A retained baseline blob has an unsafe type or mode");
    }
    if (!Number.isSafeInteger(stats.size) || stats.size < 0 || stats.size > MAX_SINGLE_BLOB_BYTES) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "A retained baseline blob has an unsafe size");
    }
    const hashed = await hashRegularFile(path, false);
    const digest = `sha256:${name}` as Sha256Digest;
    if (hashed.contentSha256 !== digest || hashed.size !== stats.size) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "A retained baseline blob differs from its content address");
    }
    physicalBytes = checkedBaselineBlobByteSum(physicalBytes, stats.size);
    byDigest.set(digest, stats.size);
    entries.push({ blobSha256: digest, byteLength: stats.size });
  }

  let context: RetentionAuthorityContext;
  let results: readonly M3RetentionResultDocument[];
  try {
    [context, results] = await Promise.all([
      loadRetentionAuthorityContext(location),
      readM3Records(location, "RETENTION_RESULT"),
    ]);
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError && error.code === "BASELINE_PROVENANCE_INVALID") {
      throw repositoryGuardError("CLEANUP_UNCERTAIN", "Managed baseline metadata is semantically inconsistent", error);
    }
    throw error;
  }
  const referencedDigests = new Set<string>();
  for (const baseline of context.baselines.values()) {
    for (const path of baseline.paths) {
      if (path.blob === null) continue;
      referencedDigests.add(path.blob.blob_sha256);
      const retainedSize = byDigest.get(path.blob.blob_sha256);
      if (retainedSize !== undefined && retainedSize !== path.blob.byte_length) {
        throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retained blob size disagrees with managed baseline metadata");
      }
      if (retainedSize === undefined && exactRetentionDeletionProof(results, context, path.blob.blob_sha256) === null) {
        throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Managed baseline metadata references an unjustifiably missing blob");
      }
    }
  }
  for (const digest of byDigest.keys()) {
    if (!referencedDigests.has(digest)) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "UNCOMMITTED_BASELINE_PUBLICATION: retained blob has no durable baseline record");
    }
  }

  const override = repositoryTestHooks().retainedBaselineBlobBytesOverride;
  if (override !== undefined) {
    if (!Number.isSafeInteger(override) || override < 0) {
      throw new RepositoryGuardError("INVALID_ARGUMENT", "Private retained baseline-blob accounting override is invalid");
    }
    physicalBytes = override;
  }
  const normalized = entries.sort((left, right) => compareText(left.blobSha256, right.blobSha256));
  return detachedFrozen({
    physicalBytes,
    entries: normalized,
    inventorySha256: sha256Canonical(normalized),
  });
}

export function canonicalJsonRecordBytes(document: unknown): Buffer {
  return Buffer.from(`${canonicalize(document)}\n`, "utf8");
}

export async function publishM3Record(
  location: M3StorageLocation,
  kind: M3RecordKind,
  document: Record<string, unknown>,
): Promise<{ readonly relativePath: string; readonly reused: boolean }> {
  assertLocation(location);
  const definition = recordDefinitions[kind];
  assertDocumentValid(definition.schemaId, document);
  const digest = document["content_sha256"];
  assertDigest(digest, "record content identity");
  const directory = recordDirectory(location, kind);
  await assertPrivateDirectory(directory);
  const finalPath = m3RecordPath(location, kind, digest);
  const result = await publishImmutableFile(finalPath, canonicalJsonRecordBytes(document), "RECORD");
  return {
    relativePath: relative(runDirectory(location), finalPath).split(sep).join("/"),
    reused: result.reused,
  };
}

export async function rollbackNewM3Record<K extends M3RecordKind>(
  location: M3StorageLocation,
  kind: K,
  document: M3RecordDocumentByKind[K],
  wasNew: boolean,
): Promise<void> {
  if (!wasNew) return;
  const path = m3RecordPath(location, kind, document.content_sha256);
  if (await lstatOrUndefined(path) === undefined) return;
  if (!await m3RecordIsExact(location, kind, document)) {
    throw new RepositoryGuardError("STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN", `${kind} rollback target disappeared`);
  }
  try {
    await unlink(path);
    await fsyncDirectory(recordDirectory(location, kind), path);
  } catch (error: unknown) {
    throw repositoryGuardError(
      "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
      `${kind} failed publication could not be durably rolled back`,
      error,
    );
  }
}

export async function publishBaselineBlob(
  location: M3StorageLocation,
  bytes: Uint8Array,
): Promise<{ readonly digest: Sha256Digest; readonly relativePath: string; readonly reused: boolean }> {
  assertLocation(location);
  if (!Number.isSafeInteger(bytes.byteLength) || bytes.byteLength < 0 || bytes.byteLength > MAX_SINGLE_BLOB_BYTES) {
    throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "A baseline blob exceeds the single-blob limit");
  }
  const digest = sha256Bytes(bytes);
  const finalPath = baselineBlobPath(location, digest);
  await assertPrivateDirectory(baselineBlobDirectory(location));
  const result = await publishImmutableFile(finalPath, bytes, "EVIDENCE");
  if (!result.reused) await repositoryTestHooks().afterBaselineBlobPublication?.(finalPath);
  return {
    digest,
    relativePath: relative(runDirectory(location), finalPath).split(sep).join("/"),
    reused: result.reused,
  };
}

/** Rolls back only immutable baseline objects first created by the failed invocation. */
export async function rollbackBaselinePublication(
  location: M3StorageLocation,
  baseline: M3BaselineRuntimeDocument,
  recordWasNew: boolean,
  newlyCreated: readonly { readonly digest: Sha256Digest; readonly byteLength: number }[],
): Promise<void> {
  assertLocation(location);
  let recordRemoved = !recordWasNew;
  if (recordWasNew) {
    const path = m3RecordPath(location, "BASELINE", baseline.content_sha256);
    const stats = await lstatOrUndefined(path);
    if (stats === undefined) {
      recordRemoved = true;
    } else {
      try {
        const durable = await loadM3Record(location, "BASELINE", baseline.content_sha256, "BASELINE_PROVENANCE_INVALID", "BASELINE_PROVENANCE_INVALID");
        if (!canonicalJsonRecordBytes(durable).equals(canonicalJsonRecordBytes(baseline))) {
          throw new RepositoryGuardError("BASELINE_PROVENANCE_INVALID", "Failed publication created a different baseline record");
        }
        await unlink(path);
        await fsyncDirectory(recordDirectory(location, "BASELINE"), path);
        recordRemoved = true;
      } catch (error: unknown) {
        throw repositoryGuardError(
          "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN",
          "Failed baseline record could not be durably rolled back",
          error,
        );
      }
    }
  }
  if (!recordRemoved) {
    throw new RepositoryGuardError("BASELINE_PUBLICATION_CLEANUP_UNCERTAIN", "Baseline record rollback was not proved complete");
  }

  let durableBaselines: readonly M3BaselineRuntimeDocument[];
  try {
    durableBaselines = await readM3Records(location, "BASELINE");
    for (const durable of durableBaselines) assertBaselineRuntimeSemantics(durable);
  } catch (error: unknown) {
    throw repositoryGuardError(
      "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN",
      "Durable baseline references could not be established before blob rollback",
      error,
    );
  }
  const referenced = new Set(durableBaselines.flatMap((document) =>
    document.paths.flatMap((entry) => entry.blob === null ? [] : [entry.blob.blob_sha256]),
  ));
  const failures: string[] = [];
  for (const item of newlyCreated) {
    if (referenced.has(item.digest)) continue;
    const path = baselineBlobPath(location, item.digest);
    try {
      if (await lstatOrUndefined(path) === undefined) continue;
      const stats = await assertRegularPrivateFile(path);
      if (stats.size !== item.byteLength) throw new Error("rollback size mismatch");
      const hashed = await hashRegularFile(path, false);
      if (hashed.contentSha256 !== item.digest || hashed.size !== item.byteLength) throw new Error("rollback digest mismatch");
      await repositoryTestHooks().beforeBaselineRollbackUnlink?.(path);
      await unlink(path);
      await repositoryTestHooks().beforeBaselineRollbackDirectorySync?.(baselineBlobDirectory(location));
      await fsyncDirectory(baselineBlobDirectory(location), path);
    } catch (error: unknown) {
      failures.push(error instanceof Error ? error.name : "UNKNOWN");
    }
  }
  if (failures.length > 0) {
    throw new RepositoryGuardError(
      "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN",
      "One or more newly published baseline blobs could not be durably rolled back",
      { failed_objects: failures.length },
    );
  }
}

async function permissiveTargetBytes(path: string): Promise<number> {
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    if (!Number.isSafeInteger(stats.size) || stats.size < 0) {
      throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Retention-target physical size is unsafe");
    }
    return stats.size;
  }
  let total = 0;
  for (const name of (await readdir(path)).sort(compareText)) {
    const size = await permissiveTargetBytes(join(path, name));
    if (!Number.isSafeInteger(total + size)) {
      throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Retention-target accounting overflowed");
    }
    total += size;
  }
  return total;
}

async function physicalStateRootBytes(path: string, permittedRetentionTargets: ReadonlySet<string> = new Set()): Promise<number> {
  const stats = await lstat(path);
  if (permittedRetentionTargets.has(path)) return permissiveTargetBytes(path);
  if (stats.isSymbolicLink()) throw new RepositoryGuardError("STATE_STORAGE_INVALID", "State-root symlinks are forbidden");
  if (stats.isFile()) {
    if (!Number.isSafeInteger(stats.size) || stats.size < 0) throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "State-root size is unsafe");
    return stats.size;
  }
  if (!stats.isDirectory()) throw new RepositoryGuardError("STATE_STORAGE_INVALID", "State-root special files are forbidden");
  let total = 0;
  for (const name of (await readdir(path)).sort()) {
    const childBytes = await physicalStateRootBytes(join(path, name), permittedRetentionTargets);
    if (!Number.isSafeInteger(total + childBytes)) throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "State-root accounting overflowed");
    total += childBytes;
  }
  return total;
}

export async function stateRootBytes(stateRoot: string): Promise<number> {
  assertAbsoluteNormalizedPath(stateRoot, "stateRoot");
  const override = repositoryTestHooks().stateRootBytes;
  if (override !== undefined) {
    if (!Number.isSafeInteger(override) || override < 0) throw new RepositoryGuardError("INVALID_ARGUMENT", "Private state-root accounting override is invalid");
    return override;
  }
  return physicalStateRootBytes(stateRoot);
}

export async function assertStateRootCapacity(stateRoot: string, additionalBytes: number): Promise<number> {
  if (!Number.isSafeInteger(additionalBytes) || additionalBytes < 0) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "State-root admission size is unsafe");
  }
  const current = await stateRootBytes(stateRoot);
  if (!Number.isSafeInteger(current + additionalBytes) || current + additionalBytes > MAX_STATE_ROOT_BYTES) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "State-root admission exceeds the 2 GiB limit", {
      current_bytes: current,
      additional_bytes: additionalBytes,
      maximum_bytes: MAX_STATE_ROOT_BYTES,
    });
  }
  return current;
}

/** Lock-root admission counts unsafe target entries without following them so retention can inspect and refuse them. */
export async function assertLockAcquisitionCapacity(stateRoot: string, additionalBytes: number): Promise<number> {
  if (!Number.isSafeInteger(additionalBytes) || additionalBytes < 0) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Lock-acquisition admission size is unsafe");
  }
  const override = repositoryTestHooks().stateRootBytes;
  const current = override === undefined ? await permissiveTargetBytes(stateRoot) : override;
  if (!Number.isSafeInteger(current) || current < 0 || !Number.isSafeInteger(current + additionalBytes) ||
      current + additionalBytes > MAX_STATE_ROOT_BYTES) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Lock-acquisition admission exceeds the 2 GiB limit", {
      current_bytes: current,
      additional_bytes: additionalBytes,
      maximum_bytes: MAX_STATE_ROOT_BYTES,
    });
  }
  return current;
}

export async function assertRetentionResultCapacity(
  location: M3StorageLocation,
  targetDigests: readonly string[],
  additionalBytes: number,
): Promise<number> {
  assertLocation(location);
  if (!Number.isSafeInteger(additionalBytes) || additionalBytes < 0) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Retention-result admission size is unsafe");
  }
  const targetPaths = new Set<string>();
  for (const digest of targetDigests) {
    assertDigest(digest, "retention target digest");
    targetPaths.add(baselineBlobPath(location, digest));
  }
  // Exact target entries remain counted, including target-local special entries.
  // Completed unlinks are absent; inspection and failed cleanup subtract nothing.
  const override = repositoryTestHooks().stateRootBytes;
  const current = override === undefined
    ? await physicalStateRootBytes(location.stateRoot, targetPaths)
    : await stateRootBytes(location.stateRoot);
  if (!Number.isSafeInteger(current + additionalBytes) || current + additionalBytes > MAX_STATE_ROOT_BYTES) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Retention-result admission exceeds the 2 GiB limit", {
      current_bytes: current,
      additional_bytes: additionalBytes,
      maximum_bytes: MAX_STATE_ROOT_BYTES,
    });
  }
  return current;
}

export async function assertProjectedRetentionCapacity(
  location: M3StorageLocation,
  removedPhysicalBytes: number,
  additionalBytes: number,
): Promise<number> {
  assertLocation(location);
  if (!Number.isSafeInteger(removedPhysicalBytes) || removedPhysicalBytes < 0 ||
      !Number.isSafeInteger(additionalBytes) || additionalBytes < 0) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Projected retention accounting is unsafe");
  }
  const current = await stateRootBytes(location.stateRoot);
  if (removedPhysicalBytes > current) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Projected retention removal exceeds current physical usage");
  }
  const retained = current - removedPhysicalBytes;
  if (!Number.isSafeInteger(retained + additionalBytes) || retained + additionalBytes > MAX_STATE_ROOT_BYTES) {
    throw new RepositoryGuardError("STATE_ROOT_LIMIT_EXCEEDED", "Projected retention result exceeds the 2 GiB limit", {
      current_bytes: current,
      removed_physical_bytes: removedPhysicalBytes,
      additional_bytes: additionalBytes,
      maximum_bytes: MAX_STATE_ROOT_BYTES,
    });
  }
  return retained;
}

export async function verifyBaselineBlob(
  location: M3StorageLocation,
  digest: string,
  expectedSize: number,
): Promise<void> {
  assertLocation(location);
  assertDigest(digest, "blob digest");
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize > MAX_SINGLE_BLOB_BYTES) {
    throw new RepositoryGuardError("BASELINE_BLOB_LIMIT_EXCEEDED", "Blob metadata size is invalid");
  }
  const path = baselineBlobPath(location, digest);
  let stats;
  try {
    stats = await assertRegularPrivateFile(path);
  } catch (error: unknown) {
    throw repositoryGuardError("CLEANUP_UNCERTAIN", "A retained baseline blob is missing or unsafe", error);
  }
  if (stats.size !== expectedSize) throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "A retained baseline blob has the wrong size");
  const bytes = await readFile(path);
  if (sha256Bytes(bytes) !== digest) throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "A retained baseline blob has the wrong digest");
}

export async function retentionResults(location: M3StorageLocation): Promise<readonly M3RetentionResultDocument[]> {
  assertLocation(location);
  return readM3Records(location, "RETENTION_RESULT");
}

export type RetentionTargetFailureCode =
  | "TARGET_MISSING"
  | "TARGET_SYMLINK"
  | "TARGET_SPECIAL_FILE"
  | "TARGET_DIRECTORY"
  | "TARGET_MODE_MISMATCH"
  | "TARGET_SIZE_MISMATCH"
  | "TARGET_DIGEST_MISMATCH"
  | "TARGET_READ_FAILED"
  | "TARGET_UNLINK_FAILED"
  | "TARGET_DIRECTORY_FSYNC_FAILED";

export interface RetentionTargetValidation {
  readonly valid: boolean;
  readonly failureCode: RetentionTargetFailureCode | null;
}

export async function validateRetentionTarget(
  location: M3StorageLocation,
  digest: string,
  expectedSize: number,
): Promise<RetentionTargetValidation> {
  assertLocation(location);
  assertDigest(digest, "retention target digest");
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize > MAX_SINGLE_BLOB_BYTES) {
    return detachedFrozen({ valid: false, failureCode: "TARGET_SIZE_MISMATCH" });
  }
  const path = baselineBlobPath(location, digest);
  let stats;
  try {
    stats = await lstat(path);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return detachedFrozen({ valid: false, failureCode: "TARGET_MISSING" });
    }
    return detachedFrozen({ valid: false, failureCode: "TARGET_READ_FAILED" });
  }
  if (stats.isSymbolicLink()) return detachedFrozen({ valid: false, failureCode: "TARGET_SYMLINK" });
  if (stats.isDirectory()) return detachedFrozen({ valid: false, failureCode: "TARGET_DIRECTORY" });
  if (!stats.isFile()) return detachedFrozen({ valid: false, failureCode: "TARGET_SPECIAL_FILE" });
  if ((stats.mode & 0o777) !== 0o600) return detachedFrozen({ valid: false, failureCode: "TARGET_MODE_MISMATCH" });
  if (!Number.isSafeInteger(stats.size) || stats.size !== expectedSize) {
    return detachedFrozen({ valid: false, failureCode: "TARGET_SIZE_MISMATCH" });
  }
  if (repositoryTestHooks().retentionTargetReadFailureDigest === digest) {
    return detachedFrozen({ valid: false, failureCode: "TARGET_READ_FAILED" });
  }
  try {
    const hashed = await hashRegularFile(path, false);
    if (hashed.size !== expectedSize) return detachedFrozen({ valid: false, failureCode: "TARGET_SIZE_MISMATCH" });
    if (hashed.contentSha256 !== digest) return detachedFrozen({ valid: false, failureCode: "TARGET_DIGEST_MISMATCH" });
  } catch {
    return detachedFrozen({ valid: false, failureCode: "TARGET_READ_FAILED" });
  }
  return detachedFrozen({ valid: true, failureCode: null });
}

export interface RetentionDeletionResult {
  readonly failureCode: RetentionTargetFailureCode | null;
  readonly unlinkPerformed: boolean;
  readonly directoryFsyncPerformed: boolean;
}

export async function deleteValidatedRetentionTarget(
  location: M3StorageLocation,
  digest: string,
  expectedSize: number,
): Promise<RetentionDeletionResult> {
  const path = baselineBlobPath(location, digest);
  try {
    await repositoryTestHooks().beforeRetentionUnlink?.(path);
  } catch {
    return detachedFrozen({ failureCode: "TARGET_UNLINK_FAILED", unlinkPerformed: false, directoryFsyncPerformed: false });
  }
  const revalidated = await validateRetentionTarget(location, digest, expectedSize);
  if (!revalidated.valid) {
    return detachedFrozen({ failureCode: revalidated.failureCode, unlinkPerformed: false, directoryFsyncPerformed: false });
  }
  try {
    await unlink(path);
  } catch {
    return detachedFrozen({ failureCode: "TARGET_UNLINK_FAILED", unlinkPerformed: false, directoryFsyncPerformed: false });
  }
  try {
    await repositoryTestHooks().beforeRetentionDirectorySync?.(baselineBlobDirectory(location));
    await fsyncDirectory(baselineBlobDirectory(location), path);
  } catch {
    return detachedFrozen({ failureCode: "TARGET_DIRECTORY_FSYNC_FAILED", unlinkPerformed: true, directoryFsyncPerformed: false });
  }
  return detachedFrozen({ failureCode: null, unlinkPerformed: true, directoryFsyncPerformed: true });
}

export async function unlinkVerifiedBaselineBlob(
  location: M3StorageLocation,
  digest: string,
  expectedSize: number,
): Promise<void> {
  const result = await deleteValidatedRetentionTarget(location, digest, expectedSize);
  if (result.failureCode !== null) {
    throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Baseline blob unlink or parent-directory fsync failed", {
      failure_code: result.failureCode,
      unlink_performed: result.unlinkPerformed,
      directory_fsync_performed: result.directoryFsyncPerformed,
    });
  }
}

export async function blobExists(location: M3StorageLocation, digest: string): Promise<boolean> {
  return (await lstatOrUndefined(baselineBlobPath(location, digest))) !== undefined;
}
