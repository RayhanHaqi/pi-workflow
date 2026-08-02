import { randomBytes } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { resolve } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes } from "../identity/index.js";
import { resolveRepositoryIdentity } from "../repository/index.js";
import { assertDocumentValid, type M3RepositoryIdentityDocument, type M4SecureFilesystemCapabilityDocument } from "../schemas/index.js";
import { assertExactKeys, assertRecord, assertSafeNonnegativeInteger, detachedFrozen } from "../repository/utils.js";
import { probeM4Capabilities } from "./capabilities.js";
import { SecureFilesystemError, secureFilesystemError } from "./errors.js";
import {
  assertSecureHelperIdentity,
  attachMutationEvidence,
  invokeSecureFilesystemHelper,
  mutationJournalForError,
  parseMutationJournal,
  type HelperIdentity,
  type MutationRecoveryEvidence,
} from "./helper.js";
import { assertM4CanonicalPath, pathMatchesRules, validatePathRules } from "./path.js";
import { secureFilesystemTestHooks } from "./test-hooks.js";
import type {
  RootIdentity,
  SecureFileMetadata,
  SecureFilesystem,
  SecureFilesystemOptions,
  SecureListEntry,
  SecureListRequest,
  SecureListResult,
  SecureMutationAuthority,
  SecureMutationOutcome,
  SecureMutationRequest,
  SecureReadRequest,
  SecureReadResult,
} from "./types.js";

interface SecureFilesystemState {
  readonly repository: M3RepositoryIdentityDocument;
  readonly root: RootIdentity;
  readonly helper: HelperIdentity;
  readonly readablePaths: ReturnType<typeof validatePathRules>;
}

const states = new WeakMap<object, SecureFilesystemState>();

function stateFor(value: SecureFilesystem): SecureFilesystemState {
  const state = states.get(value as object);
  if (state === undefined) throw new SecureFilesystemError("SECURE_FS_CAPABILITY_MISMATCH", "Secure filesystem handle is invalid");
  return state;
}

function assertSafeMaximum(value: unknown, label: string, maximum: number): asserts value is number {
  assertSafeNonnegativeInteger(value, label);
  if (value > maximum) throw new SecureFilesystemError("INVALID_ARGUMENT", `${label} exceeds its authority maximum`);
}

async function rootIdentity(repository: M3RepositoryIdentityDocument): Promise<RootIdentity> {
  const path = repository.worktree_root;
  const [stats, physical] = await Promise.all([lstat(path), realpath(path)]);
  if (!stats.isDirectory() || stats.isSymbolicLink() || physical !== path || physical !== repository.git_toplevel) {
    throw new SecureFilesystemError("PATH_OUTSIDE_ROOT", "Repository root is not the exact physical M3 worktree root");
  }
  return Object.freeze({ realpath: physical, device: stats.dev, inode: stats.ino });
}

function rootRequest(state: SecureFilesystemState): Record<string, unknown> {
  return { root: state.root.realpath, root_identity: { realpath: state.root.realpath, device: state.root.device, inode: state.root.inode } };
}

function metadata(value: unknown, label: string): SecureFileMetadata {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", `${label} metadata is malformed`);
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "device,digest,inode,mode,nlink,size" || typeof record["digest"] !== "string" ||
      !/^sha256:[0-9a-f]{64}$/.test(record["digest"]) || !["device", "inode", "mode", "nlink", "size"].every((key) => Number.isSafeInteger(record[key]) && (record[key] as number) >= 0)) {
    throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", `${label} metadata is malformed`);
  }
  return Object.freeze(record as unknown as SecureFileMetadata);
}

function nullableMetadata(value: unknown, label: string): SecureFileMetadata | null {
  return value === null ? null : metadata(value, label);
}

async function verifyCurrentHelper(state: SecureFilesystemState, capability: SecureFilesystem["capability"]): Promise<void> {
  const current = await assertSecureHelperIdentity(capability);
  if (current.sha256 !== state.helper.sha256 || current.realpath !== state.helper.realpath || current.python.realpath !== state.helper.python.realpath) {
    throw new SecureFilesystemError("SECURE_FS_CAPABILITY_MISMATCH", "Secure helper changed after gateway construction");
  }
}

class SecureFilesystemImpl implements SecureFilesystem {
  public constructor(
    public readonly capability: SecureFilesystem["capability"],
    state: SecureFilesystemState,
  ) {
    states.set(this, state);
    Object.freeze(this);
  }

  public async readScoped(request: SecureReadRequest): Promise<SecureReadResult> {
    assertRecord(request, "read request");
    assertExactKeys(request, ["path", "offset", "length", "maximumBytes", "hashLimitBytes"], "read request");
    assertM4CanonicalPath(request.path);
    const state = stateFor(this);
    if (!pathMatchesRules(request.path, state.readablePaths)) throw new SecureFilesystemError("PATH_NOT_READABLE", "Path is outside the frozen readable scope", { path: request.path });
    assertSafeMaximum(request.offset, "offset", Number.MAX_SAFE_INTEGER);
    assertSafeMaximum(request.length, "length", 1_048_576);
    assertSafeMaximum(request.maximumBytes, "maximumBytes", 1_048_576);
    assertSafeMaximum(request.hashLimitBytes, "hashLimitBytes", 67_108_864);
    if (request.length > request.maximumBytes) throw new SecureFilesystemError("READ_LIMIT_EXCEEDED", "Requested length exceeds the read bound");
    await verifyCurrentHelper(state, this.capability);
    const raw = await invokeSecureFilesystemHelper(state.helper, {
      operation: "READ", ...rootRequest(state), path: request.path, offset: request.offset, length: request.length,
      maximum: request.maximumBytes, hash_limit: request.hashLimitBytes,
    });
    if (raw === null || Array.isArray(raw) || typeof raw !== "object") throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Read response is malformed");
    const result = raw as Record<string, unknown>;
    if (result["path"] !== request.path || result["offset"] !== request.offset || typeof result["data_base64"] !== "string" || !Number.isSafeInteger(result["bytes"])) {
      throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Read response authority differs");
    }
    const bytes = Buffer.from(result["data_base64"], "base64");
    if (bytes.toString("base64") !== result["data_base64"] || bytes.byteLength !== result["bytes"] || bytes.byteLength > request.maximumBytes) {
      throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Read response encoding or bound is invalid");
    }
    return detachedFrozen({ path: request.path, metadata: metadata(result["metadata"], "read"), offset: request.offset, byteCount: bytes.byteLength, dataBase64: result["data_base64"] });
  }

  public async listScoped(request: SecureListRequest): Promise<SecureListResult> {
    assertRecord(request, "list request");
    assertExactKeys(request, ["path", "maximumDepth", "maximumEntries", "maximumMetadataBytes", "hashFiles", "hashLimitBytes"], "list request");
    if (request.path === null) throw new SecureFilesystemError("PATH_NOT_READABLE", "Repository-root listing requires an explicit canonical prefix");
    assertM4CanonicalPath(request.path);
    const state = stateFor(this);
    const exactPrefix = state.readablePaths.some((rule) => rule.kind === "PREFIX" && rule.path === request.path);
    if (!exactPrefix) throw new SecureFilesystemError("PATH_NOT_READABLE", "List root is not an explicit readable directory prefix", { path: request.path });
    assertSafeMaximum(request.maximumDepth, "maximumDepth", 1024);
    assertSafeMaximum(request.maximumEntries, "maximumEntries", 100_000);
    assertSafeMaximum(request.maximumMetadataBytes, "maximumMetadataBytes", 67_108_864);
    assertSafeMaximum(request.hashLimitBytes, "hashLimitBytes", 67_108_864);
    if (typeof request.hashFiles !== "boolean") throw new SecureFilesystemError("INVALID_ARGUMENT", "hashFiles must be boolean");
    await verifyCurrentHelper(state, this.capability);
    const raw = await invokeSecureFilesystemHelper(state.helper, {
      operation: "LIST", ...rootRequest(state), path: request.path, max_depth: request.maximumDepth,
      max_entries: request.maximumEntries, max_metadata_bytes: request.maximumMetadataBytes,
      hash_files: request.hashFiles, hash_limit: request.hashLimitBytes,
    });
    if (raw === null || Array.isArray(raw) || typeof raw !== "object") throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "List response is malformed");
    const result = raw as Record<string, unknown>;
    if (result["path"] !== request.path || !Array.isArray(result["entries"]) || !Number.isSafeInteger(result["metadata_bytes"]) || result["entries"].length > request.maximumEntries) {
      throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "List response authority or bounds differ");
    }
    const entries: SecureListEntry[] = result["entries"].map((entry: unknown) => {
      if (entry === null || Array.isArray(entry) || typeof entry !== "object") throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "List entry is malformed");
      const item = entry as Record<string, unknown>;
      assertM4CanonicalPath(item["path"], "list entry path");
      if (!(item["path"] === request.path || (item["path"] as string).startsWith(`${request.path}/`)) ||
          typeof item["type"] !== "string" || !Number.isSafeInteger(item["mode"]) || !Number.isSafeInteger(item["size"]) ||
          !(item["digest"] === null || (typeof item["digest"] === "string" && /^sha256:[0-9a-f]{64}$/.test(item["digest"])))) {
        throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "List entry fields are invalid");
      }
      return item as unknown as SecureListEntry;
    });
    const sorted = [...entries].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    if (entries.some((entry, index) => entry.path !== sorted[index]?.path)) throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "List entries are not canonically sorted");
    return detachedFrozen({ path: request.path, entries, metadataBytes: result["metadata_bytes"] as number });
  }
}

function stableCapabilityAuthority(value: M4SecureFilesystemCapabilityDocument): unknown {
  const { content_sha256: _content, probed_at: _time, probe_evidence_sha256: _probe, ...authority } = value;
  return authority;
}

export async function createSecureFilesystem(options: SecureFilesystemOptions): Promise<SecureFilesystem> {
  assertRecord(options, "secure filesystem options");
  assertExactKeys(options, ["repository", "capability", "readablePaths"], "secure filesystem options");
  assertDocumentValid("pi_gacw_repository_identity_v0", options.repository);
  assertDocumentValid("pi_gacw_secure_fs_capability_v0", options.capability);
  if (options.capability.secure_fs_result !== "SECURE_FS_AVAILABLE" || !options.capability.openat2_available ||
      !options.capability.rename_noreplace_available || !options.capability.rename_exchange_available || !options.capability.directory_fsync_available ||
      !["RESOLVE_BENEATH", "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_MAGICLINKS"].every((flag) => options.capability.supported_resolve_flags.includes(flag as never))) {
    throw new SecureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Mandatory secure filesystem primitives are unavailable");
  }
  let resolved: M3RepositoryIdentityDocument;
  try { resolved = await resolveRepositoryIdentity({ requestedPath: options.repository.requested_path, requireHead: true }); }
  catch (error: unknown) { throw secureFilesystemError("REPOSITORY_AUTHORITY_INVALID", "Repository authority cannot be independently resolved", error); }
  if (canonicalize(resolved) !== canonicalize(options.repository)) {
    throw new SecureFilesystemError("REPOSITORY_ROOT_MISMATCH", "Caller repository identity differs from independently resolved M3 authority");
  }
  let currentCapability: M4SecureFilesystemCapabilityDocument;
  try { currentCapability = (await probeM4Capabilities()).secureFilesystem; }
  catch (error: unknown) { throw secureFilesystemError("SECURE_FS_CAPABILITY_MISMATCH", "Capability authority cannot be independently reprobed", error); }
  if (canonicalize(stableCapabilityAuthority(currentCapability)) !== canonicalize(stableCapabilityAuthority(options.capability))) {
    throw new SecureFilesystemError("SECURE_FS_CAPABILITY_MISMATCH", "Caller capability differs from current helper-produced authority");
  }
  const [root, helper] = await Promise.all([rootIdentity(resolved), assertSecureHelperIdentity(options.capability)]);
  await secureFilesystemTestHooks().beforeRepositoryRevalidation?.();
  let revalidated: M3RepositoryIdentityDocument;
  try { revalidated = await resolveRepositoryIdentity({ requestedPath: options.repository.requested_path, requireHead: true }); }
  catch (error: unknown) { throw secureFilesystemError("REPOSITORY_AUTHORITY_INVALID", "Repository authority changed during construction", error); }
  const reboundRoot = await rootIdentity(revalidated);
  if (canonicalize(revalidated) !== canonicalize(resolved) || reboundRoot.device !== root.device || reboundRoot.inode !== root.inode || reboundRoot.realpath !== root.realpath) {
    throw new SecureFilesystemError("REPOSITORY_ROOT_MISMATCH", "Repository authority changed during secure-filesystem construction");
  }
  const readablePaths = validatePathRules(options.readablePaths, "readablePaths");
  return new SecureFilesystemImpl(detachedFrozen(options.capability), { repository: detachedFrozen(revalidated), root: reboundRoot, helper, readablePaths });
}

interface MutationOperationIdentity {
  readonly run_id: string;
  readonly repository_identity_content_sha256: string;
  readonly worktree_identity: string;
  readonly target_path: string;
  readonly parent_path: string;
  readonly operation: SecureMutationRequest["operation"];
  readonly operation_nonce: string;
  readonly temporary_name: string | null;
  readonly tombstone_name: string | null;
  readonly parent_identity: { readonly device: number; readonly inode: number };
  readonly prior_state_token_content_sha256: string | null;
  readonly secure_fs_capability_content_sha256: string;
}

interface RecoveryAttempt { readonly evidence: MutationRecoveryEvidence; readonly error: SecureFilesystemError | null }

function recoveryDetails(evidence: MutationRecoveryEvidence): Readonly<Record<string, string | number | boolean | null>> {
  return {
    operation_nonce: evidence.operationNonce,
    residue_cleanup_attempted: evidence.attempted,
    residue_cleanup_outcome: evidence.outcome,
    remaining_operation_residue_count: evidence.remainingResidueCount,
    target_verification_outcome: evidence.targetVerification,
    recovery_directory_fsync_outcome: evidence.directoryFsync,
    recovery_helper_identity_sha256: evidence.helperSha256,
  };
}

async function createMutationOperationIdentity(
  state: SecureFilesystemState,
  secureCapability: SecureFilesystem["capability"],
  request: SecureMutationRequest,
  authority: SecureMutationAuthority | undefined,
): Promise<MutationOperationIdentity> {
  const parentPath = request.path.includes("/") ? request.path.slice(0, request.path.lastIndexOf("/")) : "";
  const absoluteParent = parentPath === "" ? state.root.realpath : resolve(state.root.realpath, parentPath);
  let parentStats;
  try { parentStats = await lstat(absoluteParent); }
  catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new SecureFilesystemError("TARGET_MISSING", "Mutation parent does not exist");
    throw new SecureFilesystemError("PARENT_IDENTITY_DRIFT", "Mutation parent cannot be inspected", {}, { cause: error });
  }
  let physicalParent: string;
  try { physicalParent = await realpath(absoluteParent); }
  catch (error: unknown) { throw new SecureFilesystemError("PARENT_IDENTITY_DRIFT", "Mutation parent cannot be resolved", {}, { cause: error }); }
  if (!parentStats.isDirectory() || parentStats.isSymbolicLink() || physicalParent !== absoluteParent) {
    throw new SecureFilesystemError("PARENT_IDENTITY_DRIFT", "Mutation parent is not the exact physical canonical directory");
  }
  const name = request.path.slice(request.path.lastIndexOf("/") + 1);
  const operationNonce = randomBytes(16).toString("hex");
  const temporaryName = request.operation === "DELETE" ? null : `.${name}.m4tmp-${operationNonce}`;
  const tombstoneName = request.operation === "DELETE" ? `.${name}.m4tomb-${operationNonce}` : null;
  const context = authority ?? {
    runId: "secure-fs-direct",
    repositoryIdentityContentSha256: state.repository.content_sha256,
    worktreeIdentity: state.repository.worktree_key,
    priorStateTokenContentSha256: null,
  };
  return Object.freeze({
    run_id: context.runId,
    repository_identity_content_sha256: context.repositoryIdentityContentSha256,
    worktree_identity: context.worktreeIdentity,
    target_path: request.path,
    parent_path: parentPath,
    operation: request.operation,
    operation_nonce: operationNonce,
    temporary_name: temporaryName,
    tombstone_name: tombstoneName,
    parent_identity: Object.freeze({ device: parentStats.dev, inode: parentStats.ino }),
    prior_state_token_content_sha256: context.priorStateTokenContentSha256,
    secure_fs_capability_content_sha256: secureCapability.content_sha256,
  });
}

function recoveryFailureEvidence(identity: MutationOperationIdentity, helperSha256: string | null, outcome: "FAILED" | "IDENTITY_MISMATCH"): MutationRecoveryEvidence {
  return Object.freeze({ operationNonce: identity.operation_nonce, attempted: true, outcome, remainingResidueCount: null,
    targetVerification: "UNKNOWN", directoryFsync: "FAILED", helperSha256: helperSha256 as `${"sha256:"}${string}` | null });
}

async function attemptMutationRecovery(
  state: SecureFilesystemState,
  filesystem: SecureFilesystem,
  request: SecureMutationRequest,
  identity: MutationOperationIdentity,
  journal: ReturnType<typeof mutationJournalForError>,
  allowRepeat = true,
): Promise<RecoveryAttempt> {
  try {
    await secureFilesystemTestHooks().beforeRecoveryHelperLaunch?.();
    await verifyCurrentHelper(state, filesystem.capability);
    const raw = await invokeSecureFilesystemHelper(state.helper, {
      operation: "RECOVER", ...rootRequest(state), mutation: request.operation, path: request.path,
      expected: request.expected, replacement_digest: request.replacement === null ? null : sha256Bytes(request.replacement),
      replacement_size: request.replacement?.byteLength ?? null, final_mode: request.finalMode, hash_limit: request.hashLimitBytes,
      operation_identity: identity, observed_journal: journal,
    });
    if (raw === null || Array.isArray(raw) || typeof raw !== "object") throw new SecureFilesystemError("SECURE_WRITE_UNCERTAIN", "Recovery response is malformed");
    const result = raw as Record<string, unknown>;
    const keys = Object.keys(result).sort().join(",");
    if (keys !== "cleanup_attempted,directory_fsync,mutation,operation_nonce,path,recovery_outcome,recovery_residue_count,root_identity,target_verification" ||
        result["path"] !== request.path || result["mutation"] !== request.operation || result["operation_nonce"] !== identity.operation_nonce ||
        result["cleanup_attempted"] !== true || result["recovery_outcome"] !== "SUCCEEDED" || result["directory_fsync"] !== "SUCCEEDED" ||
        !["NOT_RUN", "ABSENT", "PREIMAGE", "REPLACEMENT", "MISMATCH", "UNKNOWN"].includes(String(result["target_verification"])) ||
        !Number.isSafeInteger(result["recovery_residue_count"]) || (result["recovery_residue_count"] as number) !== 0) {
      throw new SecureFilesystemError("SECURE_WRITE_UNCERTAIN", "Recovery response authority is invalid");
    }
    const rootValue = result["root_identity"];
    if (rootValue === null || typeof rootValue !== "object" || Array.isArray(rootValue) || Object.keys(rootValue as object).sort().join(",") !== "device,inode" ||
        (rootValue as Record<string, unknown>)["device"] !== state.root.device || (rootValue as Record<string, unknown>)["inode"] !== state.root.inode) {
      throw new SecureFilesystemError("SECURE_FS_CAPABILITY_MISMATCH", "Recovery root identity differs");
    }
    const first: RecoveryAttempt = { error: null, evidence: Object.freeze({ operationNonce: identity.operation_nonce, attempted: true, outcome: "SUCCEEDED",
      remainingResidueCount: result["recovery_residue_count"] as number, targetVerification: result["target_verification"] as MutationRecoveryEvidence["targetVerification"],
      directoryFsync: "SUCCEEDED", helperSha256: state.helper.sha256 }) };
    if (allowRepeat && secureFilesystemTestHooks().repeatRecovery === true) return attemptMutationRecovery(state, filesystem, request, identity, journal, false);
    return first;
  } catch (error: unknown) {
    const secureError = error instanceof SecureFilesystemError ? error : new SecureFilesystemError("SECURE_WRITE_UNCERTAIN", "Recovery helper failed", {}, { cause: error });
    const outcome = secureError.code === "RESIDUE_IDENTITY_MISMATCH" ? "IDENTITY_MISMATCH" : "FAILED";
    return { error: secureError, evidence: recoveryFailureEvidence(identity, state.helper.sha256, outcome) };
  }
}

function annotateMutationFailure(
  error: unknown,
  identity: MutationOperationIdentity,
  journal: ReturnType<typeof mutationJournalForError>,
  attempt: RecoveryAttempt,
): SecureFilesystemError {
  const original = error instanceof SecureFilesystemError ? error : new SecureFilesystemError("SECURE_WRITE_UNCERTAIN", "Secure mutation result is not authoritative", {}, { cause: error });
  const originalCode = original.code === "HELPER_PROTOCOL_ERROR" ? "SECURE_WRITE_UNCERTAIN" : original.code;
  const code = attempt.evidence.outcome === "IDENTITY_MISMATCH" ? "RESIDUE_IDENTITY_MISMATCH" : originalCode;
  const helperOutcome = ["PREIMAGE_MISMATCH", "TARGET_ALREADY_EXISTS", "TARGET_MISSING", "PATH_NOT_READABLE", "SYMLINK_PATH"].includes(originalCode) ? "BLOCKED" : "UNCERTAIN";
  const mutationCertainty = helperOutcome === "BLOCKED" ? "NOT_APPLIED" : "UNCERTAIN";
  const annotated = new SecureFilesystemError(code, "Secure mutation outcome is uncertain; operation-owned recovery completed or failed as reported", {
    ...original.details, ...recoveryDetails(attempt.evidence), helper_outcome: helperOutcome, mutation_certainty: mutationCertainty,
    recovery_failure_code: attempt.error?.code ?? null, recovery_failure_detail: attempt.error?.message ?? null,
  }, { cause: original });
  attachMutationEvidence(annotated, journal, attempt.evidence);
  return annotated;
}

export async function secureMutation(
  filesystem: SecureFilesystem,
  request: SecureMutationRequest,
  authority?: SecureMutationAuthority,
): Promise<SecureMutationOutcome> {
  assertRecord(request, "secure mutation request");
  assertExactKeys(request, ["operation", "path", "expected", "replacement", "finalMode", "hashLimitBytes"], "secure mutation request");
  assertM4CanonicalPath(request.path);
  if (!["CREATE", "REPLACE", "DELETE"].includes(request.operation)) throw new SecureFilesystemError("INVALID_ARGUMENT", "Mutation operation is invalid");
  assertSafeMaximum(request.hashLimitBytes, "hashLimitBytes", 67_108_864);
  if (request.expected === null || Array.isArray(request.expected) || typeof request.expected !== "object" || Object.keys(request.expected).sort().join(",") !== "digest,mode,size") {
    throw new SecureFilesystemError("INVALID_ARGUMENT", "Mutation preimage is malformed");
  }
  if (request.operation === "CREATE") {
    if (request.expected.digest !== null || request.expected.size !== null || request.expected.mode !== null) throw new SecureFilesystemError("INVALID_ARGUMENT", "CREATE must expect absence");
  } else if (typeof request.expected.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(request.expected.digest) || !Number.isSafeInteger(request.expected.size) || !Number.isSafeInteger(request.expected.mode)) {
    throw new SecureFilesystemError("INVALID_ARGUMENT", "Mutation preimage authority is incomplete");
  }
  if (request.operation === "DELETE") {
    if (request.replacement !== null || request.finalMode !== null) throw new SecureFilesystemError("INVALID_ARGUMENT", "DELETE cannot carry replacement bytes or a final mode");
  } else if (!(request.replacement instanceof Uint8Array) || request.replacement.byteLength > 1_048_576 || !Number.isSafeInteger(request.finalMode) || (request.finalMode as number) < 0 || (request.finalMode as number) > 0o777) {
    throw new SecureFilesystemError("PATCH_LIMIT_EXCEEDED", "Replacement bytes or final mode are invalid");
  }
  const state = stateFor(filesystem);
  await verifyCurrentHelper(state, filesystem.capability);
  const identity = await createMutationOperationIdentity(state, filesystem.capability, request, authority);
  let journal: ReturnType<typeof mutationJournalForError> = null;
  try {
    const helperRequest: Readonly<Record<string, unknown>> = {
      operation: "MUTATE", ...rootRequest(state), mutation: request.operation, path: request.path,
      expected: request.expected, replacement_base64: request.replacement === null ? null : Buffer.from(request.replacement).toString("base64"),
      final_mode: request.finalMode, hash_limit: request.hashLimitBytes, operation_identity: identity,
    };
    await secureFilesystemTestHooks().beforeMutationHelperLaunch?.(helperRequest);
    const raw = await invokeSecureFilesystemHelper(state.helper, helperRequest);
    if (raw === null || Array.isArray(raw) || typeof raw !== "object") throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Mutation response is malformed");
    const result = raw as Record<string, unknown>;
    journal = parseMutationJournal(result["journal"]);
    const rollback = result["rollback"];
    if (journal === null || journal.operation_nonce !== identity.operation_nonce || result["path"] !== request.path || result["mutation"] !== request.operation ||
        result["file_fsync"] !== journal.temporary_file_fsync_completed || result["rename_atomic"] !== journal.atomic_rename_completed ||
        result["directory_fsync"] !== (journal.directory_fsync_completed_count > 0) ||
        (rollback !== "NOT_REQUIRED" && rollback !== "SUCCEEDED" && rollback !== "FAILED") ||
        rollback !== (journal.rollback_completed ? "SUCCEEDED" : "NOT_REQUIRED") || journal.final_verification !== "PASS") {
      throw new SecureFilesystemError("SECURE_WRITE_UNCERTAIN", "Secure mutation outcome authority is invalid");
    }
    return detachedFrozen({ path: request.path, operation: request.operation, before: nullableMetadata(result["before"], "before"), after: nullableMetadata(result["after"], "after"),
      fileFsync: result["file_fsync"], atomicRename: result["rename_atomic"], directoryFsync: result["directory_fsync"], rollback, journal });
  } catch (error: unknown) {
    journal ??= mutationJournalForError(error);
    const attempt = await attemptMutationRecovery(state, filesystem, request, identity, journal);
    throw annotateMutationFailure(error, identity, journal, attempt);
  }
}
