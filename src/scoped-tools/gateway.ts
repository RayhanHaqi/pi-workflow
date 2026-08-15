import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { inspectRunStorage } from "../persistence/index.js";
import { lockMatchesRepository } from "../repository/lock.js";
import {
  assertWorktreeLockHeld,
  runFastPreflight,
  runPostflight,
  type FingerprintedFileInput,
  type WorktreeLockHandle,
} from "../repository/index.js";
import { captureGitState, fingerprintDirtyPaths } from "../repository/fingerprint.js";
import { runGitInspection } from "../repository/git-runner.js";
import { lockAcquisitionAuthority } from "../repository/lock.js";
import { resolveRepositoryIdentity } from "../repository/identity.js";
import { assertUsableM3Storage } from "../repository/storage.js";
import {
  assertAbsoluteNormalizedPath,
  assertDigest,
  assertExactKeys,
  assertRecord,
  assertSafeNonnegativeInteger,
  detachedFrozen,
  pathWithin,
} from "../repository/utils.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type M3BaselineRuntimeDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandCatalogDocument,
  type M4CommandResultDocument,
  type M4MutationReceiptDocument,
  type M4PatchRequestDocument,
  type M4SandboxCapabilityDocument,
  type M4ScopedToolPolicyDocument,
  type M4SecureFilesystemCapabilityDocument,
  type M4ToolRequestDocument,
} from "../schemas/index.js";
import { createSecureFilesystem, type SecureFilesystem, type SecureFileMetadata } from "../secure-fs/index.js";
import { probeM4Capabilities } from "../secure-fs/capabilities.js";
import { secureMutation } from "../secure-fs/client.js";
import { SecureFilesystemError } from "../secure-fs/errors.js";
import { mutationJournalForError } from "../secure-fs/helper.js";
import { assertM4CanonicalPath, pathMatchesRules } from "../secure-fs/path.js";
import { commandForClass, validateCommandCatalog, type ValidatedCommandCatalog } from "./commands.js";
import { ScopedToolGatewayError, scopedToolError, type ScopedToolGatewayErrorCode } from "./errors.js";
import {
  assertMutationPermitted,
  assertReadablePath,
  authorityForPath,
  isSecretPath,
  rawReadPermitted,
  validateToolPolicy,
  type ValidatedToolPolicy,
} from "./policy.js";
import { M4_RECORD_DEFINITIONS, publishM4Record, type M4StorageLocation } from "./records.js";
import { ensureControllerTemporaryRoot, runSandboxedCommand } from "./sandbox.js";
import { createToolRequest, createToolResult } from "./tool-records.js";
import type {
  CreateScopedToolGatewayInput,
  ScopedCommandRequest,
  ScopedCommandResult,
  ScopedEvidenceReadRequest,
  ScopedEvidenceReadResult,
  ScopedGitInspectionRequest,
  ScopedGitInspectionResult,
  ScopedListRequest,
  ScopedListResult,
  ScopedPatchRequest,
  ScopedPatchResult,
  ScopedReadRequest,
  ScopedReadResult,
  ScopedSearchMatch,
  ScopedSearchRequest,
  ScopedSearchResult,
  ScopedToolGateway,
} from "./types.js";

interface GatewayState {
  readonly location: M4StorageLocation;
  readonly repository: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly lock: WorktreeLockHandle;
  readonly instructions: readonly FingerprintedFileInput[];
  readonly authorities: readonly FingerprintedFileInput[];
  readonly editablePaths: readonly string[];
  readonly frozenPaths: readonly string[];
  readonly taskScopeIdentity: Sha256Digest;
  readonly policy: ValidatedToolPolicy;
  readonly catalog: ValidatedCommandCatalog;
  readonly filesystem: SecureFilesystem;
  readonly secureCapability: M4SecureFilesystemCapabilityDocument;
  readonly sandboxCapability: M4SandboxCapabilityDocument;
  readonly temporaryRoot: string;
  acceptedState: M3RepositoryStateTokenDocument;
  busy: boolean;
}

const gatewayStates = new WeakMap<object, GatewayState>();

function stateFor(gateway: ScopedToolGateway): GatewayState {
  const state = gatewayStates.get(gateway as object);
  if (state === undefined) throw new ScopedToolGatewayError("STATE_TOKEN_PROVENANCE_INVALID", "Scoped gateway handle is invalid");
  return state;
}

export interface ScopedToolGatewayAuthorityExpectation {
  readonly stateRoot: string;
  readonly runId: string;
  readonly repository: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly acceptedState: M3RepositoryStateTokenDocument;
  readonly taskScopeIdentity: Sha256Digest;
  readonly toolPolicy: M4ScopedToolPolicyDocument;
  readonly commandCatalog: M4CommandCatalogDocument;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly editablePaths: readonly string[];
  readonly frozenPaths: readonly string[];
}

function sameFingerprintInputs(left: readonly FingerprintedFileInput[], right: readonly FingerprintedFileInput[]): boolean {
  return canonicalize(left) === canonicalize(right);
}

function mapSecurityError(error: unknown): ScopedToolGatewayError {
  if (error instanceof ScopedToolGatewayError) return error;
  if (error instanceof SecureFilesystemError) {
    const exposed = new Set<ScopedToolGatewayErrorCode>([
      "INVALID_ARGUMENT", "SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "COMMAND_SANDBOX_UNAVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE",
      "SECURE_FS_CAPABILITY_MISMATCH", "REPOSITORY_AUTHORITY_INVALID", "REPOSITORY_ROOT_MISMATCH", "FINAL_TARGET_IDENTITY_MISMATCH",
      "INVALID_CANONICAL_PATH", "PATH_OUTSIDE_ROOT", "PATH_NOT_READABLE", "PATH_NOT_EDITABLE",
      "FROZEN_PATH", "OWNERSHIP_FORBIDS_MUTATION", "DATA_POLICY_FORBIDS_READ", "DATA_POLICY_FORBIDS_MUTATION", "SYMLINK_PATH",
      "MAGICLINK_PATH", "SPECIAL_FILE", "HARDLINK_TARGET", "RESIDUE_IDENTITY_MISMATCH", "ROLLBACK_UNCERTAIN", "PARENT_IDENTITY_DRIFT", "PREIMAGE_MISMATCH", "TARGET_ALREADY_EXISTS",
      "TARGET_MISSING", "PATCH_LIMIT_EXCEEDED", "READ_LIMIT_EXCEEDED", "SEARCH_LIMIT_EXCEEDED", "LIST_LIMIT_EXCEEDED",
      "OUTPUT_LIMIT_EXCEEDED", "SECURE_WRITE_UNCERTAIN",
    ]);
    const selected = exposed.has(error.code as ScopedToolGatewayErrorCode) ? error.code as ScopedToolGatewayErrorCode : "SECURE_WRITE_UNCERTAIN";
    return new ScopedToolGatewayError(selected, "Secure filesystem operation was blocked", error.details, { cause: error });
  }
  const code = (error as { readonly code?: unknown }).code;
  if (code === "LOCK_LOST") return scopedToolError("LOCK_LOST", "M3 worktree lock was lost", error);
  if (code === "STATE_TOKEN_PROVENANCE_INVALID" || code === "STATE_TOKEN_RECORD_MISSING") return scopedToolError("STATE_TOKEN_PROVENANCE_INVALID", "M3 token authority is invalid", error);
  if (["INVALID_ARGUMENT", "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING", "SCHEMA_INVALID", "IDENTITY_MISMATCH"].includes(String(code))) {
    return scopedToolError("INVALID_ARGUMENT", "Scoped gateway input is invalid", error);
  }
  return scopedToolError("FAST_PREFLIGHT_FAILED", "M3 authority verification failed", error);
}

async function exclusive<T>(state: GatewayState, operation: () => Promise<T>): Promise<T> {
  if (state.busy) throw new ScopedToolGatewayError("CONCURRENT_OPERATION", "A scoped gateway operation is already active");
  state.busy = true;
  try { return await operation(); }
  catch (error: unknown) { throw mapSecurityError(error); }
  finally { state.busy = false; }
}

function assertCurrentToken(state: GatewayState, value: unknown): asserts value is Sha256Digest {
  assertDigest(value, "stateTokenContentSha256");
  if (value !== state.acceptedState.content_sha256) throw new ScopedToolGatewayError("STATE_TOKEN_PROVENANCE_INVALID", "Tool request uses a stale or forged state token");
}

async function fastPreflight(state: GatewayState): Promise<void> {
  try {
    await assertWorktreeLockHeld(state.lock);
    await runFastPreflight({
      stateRoot: state.location.stateRoot,
      runId: state.location.runId,
      acceptedState: state.acceptedState,
      baseline: state.baseline,
      instructionFiles: state.instructions,
      authorityFiles: state.authorities,
      taskScopeIdentity: state.taskScopeIdentity,
      lock: state.lock,
    });
  } catch (error: unknown) { throw mapSecurityError(error); }
}

function exactInput(value: unknown, keys: readonly string[], label: string): asserts value is Record<string, unknown> {
  assertRecord(value, label); assertExactKeys(value, keys, label);
}

function dataClass(state: GatewayState, path: string): string {
  return authorityForPath(state.policy, path)?.data_class ?? "HASH_ONLY";
}

async function requestRecord(
  state: GatewayState,
  kind: M4ToolRequestDocument["request_kind"],
  path: string | null,
  commandId: string | null,
  metadata: unknown,
): Promise<M4ToolRequestDocument> {
  const command = commandId === null ? undefined : state.catalog.commands.get(commandId);
  return createToolRequest(
    state.location,
    kind,
    state.acceptedState.content_sha256 as Sha256Digest,
    state.policy.document.content_sha256 as Sha256Digest,
    state.taskScopeIdentity,
    path,
    commandId,
    {
      secureFilesystem: kind === "COMMAND" ? null : state.secureCapability.content_sha256 as Sha256Digest,
      sandbox: kind === "COMMAND" ? state.sandboxCapability.content_sha256 as Sha256Digest : null,
      commandCatalog: kind === "COMMAND" ? state.catalog.document.content_sha256 as Sha256Digest : null,
      commandSpecification: kind === "COMMAND" ? command?.command_spec_sha256 as Sha256Digest : null,
    },
    metadata,
  );
}

function decodeUtf8(bytes: Buffer, code: ScopedToolGatewayErrorCode, message: string): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch (error: unknown) { throw scopedToolError(code, message, error); }
}

async function readScoped(state: GatewayState, input: ScopedReadRequest): Promise<ScopedReadResult> {
  exactInput(input, ["stateTokenContentSha256", "path", "offset", "length", "mode"], "readScoped request");
  assertCurrentToken(state, input.stateTokenContentSha256); assertM4CanonicalPath(input.path);
  assertSafeNonnegativeInteger(input.offset, "offset"); assertSafeNonnegativeInteger(input.length, "length");
  if (input.length > state.policy.document.limits.maximum_read_bytes) throw new ScopedToolGatewayError("READ_LIMIT_EXCEEDED", "Read request exceeds tool policy");
  if (input.mode !== "TEXT" && input.mode !== "BINARY") throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Read mode is invalid");
  const authority = assertReadablePath(state.policy, input.path); const raw = rawReadPermitted(authority);
  await fastPreflight(state);
  const request = await requestRecord(state, "READ", input.path, null, { offset: input.offset, length: input.length, mode: input.mode, raw });
  let result: Awaited<ReturnType<SecureFilesystem["readScoped"]>>;
  try {
    result = await state.filesystem.readScoped({
      path: input.path, offset: input.offset, length: raw ? input.length : 0,
      maximumBytes: state.policy.document.limits.maximum_read_bytes,
      hashLimitBytes: state.policy.document.limits.maximum_hash_bytes,
    });
  } catch (error: unknown) {
    if (!(error instanceof SecureFilesystemError) || error.code !== "TARGET_MISSING") throw error;
    const record = await createToolResult(state.location, request, "READ", input.path, (authority?.data_class ?? "HASH_ONLY") as never,
      null, 0, 0, sha256Canonical({ path: input.path, outcome: "MISSING" }), "MISSING");
    // The null value is intentional: absence carries no file digest, size, or mode.
    return detachedFrozen({ metadata: null as never, dataClass: authority?.data_class ?? "HASH_ONLY", content: null, contentEncoding: "METADATA_ONLY", resultRecord: record });
  }
  const bytes = Buffer.from(result.dataBase64, "base64");
  const content = raw ? (input.mode === "TEXT" ? decodeUtf8(bytes, "DATA_POLICY_FORBIDS_READ", "Scoped text is not valid UTF-8") : result.dataBase64) : null;
  const outputDigest = raw ? sha256Bytes(bytes) : sha256Canonical(result.metadata);
  const record = await createToolResult(state.location, request, "READ", input.path, (authority?.data_class ?? "HASH_ONLY") as never,
    result.metadata.digest, result.byteCount, 1, outputDigest, raw ? "RAW" : "METADATA_ONLY");
  return detachedFrozen({ metadata: result.metadata, dataClass: authority?.data_class ?? "HASH_ONLY", content, contentEncoding: raw ? (input.mode === "TEXT" ? "UTF8" : "BASE64") : "METADATA_ONLY", resultRecord: record });
}

async function listScoped(state: GatewayState, input: ScopedListRequest): Promise<ScopedListResult> {
  exactInput(input, ["stateTokenContentSha256", "path", "maximumDepth", "hashFiles"], "listScoped request");
  assertCurrentToken(state, input.stateTokenContentSha256); assertReadablePath(state.policy, input.path);
  assertSafeNonnegativeInteger(input.maximumDepth, "maximumDepth");
  if (typeof input.hashFiles !== "boolean") throw new ScopedToolGatewayError("INVALID_ARGUMENT", "hashFiles must be boolean");
  await fastPreflight(state);
  const request = await requestRecord(state, "LIST", input.path, null, { maximumDepth: input.maximumDepth, hashFiles: input.hashFiles });
  const result = await state.filesystem.listScoped({ path: input.path, maximumDepth: input.maximumDepth,
    maximumEntries: state.policy.document.limits.maximum_list_entries,
    maximumMetadataBytes: state.policy.document.limits.maximum_list_metadata_bytes,
    hashFiles: false, hashLimitBytes: state.policy.document.limits.maximum_hash_bytes });
  const entries = [] as Array<(typeof result.entries)[number]>;
  for (const entry of result.entries) {
    if (isSecretPath(state.policy, entry.path)) continue;
    if (input.hashFiles && entry.type === "REGULAR") {
      const hashed = await state.filesystem.readScoped({ path: entry.path, offset: 0, length: 0, maximumBytes: 0, hashLimitBytes: state.policy.document.limits.maximum_hash_bytes });
      entries.push({ ...entry, digest: hashed.metadata.digest });
    } else entries.push(entry);
  }
  const output = sha256Canonical(entries);
  const record = await createToolResult(state.location, request, "LIST", input.path, dataClass(state, input.path) as never, null,
    Buffer.byteLength(canonicalize(entries)), entries.length, output, "PASS");
  return detachedFrozen({ entries, resultRecord: record });
}

function uniqueCanonicalPaths(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 10_000) throw new ScopedToolGatewayError("INVALID_ARGUMENT", `${label} is invalid`);
  const seen = new Set<string>(); const result: string[] = [];
  for (const path of value) { assertM4CanonicalPath(path, label); if (seen.has(path)) throw new ScopedToolGatewayError("INVALID_ARGUMENT", `${label} contains a duplicate`); seen.add(path); result.push(path); }
  return result.sort();
}

async function searchScoped(state: GatewayState, input: ScopedSearchRequest): Promise<ScopedSearchResult> {
  exactInput(input, ["stateTokenContentSha256", "literal", "caseSensitive", "includePaths", "excludePaths", "maximumFiles", "maximumBytes", "maximumMatches", "maximumLineLength"], "searchScoped request");
  assertCurrentToken(state, input.stateTokenContentSha256);
  if (typeof input.literal !== "string" || input.literal.length === 0 || input.literal.length > 4096 || input.literal.includes("\u0000")) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Search literal is invalid");
  if (typeof input.caseSensitive !== "boolean") throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Search case mode is invalid");
  const includes = uniqueCanonicalPaths(input.includePaths, "includePaths"); const excludes = uniqueCanonicalPaths(input.excludePaths, "excludePaths");
  for (const path of includes) {
    assertReadablePath(state.policy, path);
    if (!state.policy.readable.some((rule) => rule.kind === "PREFIX" && rule.path === path)) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Search include root must be an explicit readable prefix", { path });
  }
  if (includes.length === 0) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Search requires at least one explicit include prefix");
  for (const value of [input.maximumFiles, input.maximumBytes, input.maximumMatches, input.maximumLineLength]) assertSafeNonnegativeInteger(value, "search limit");
  if (input.maximumBytes > state.policy.document.limits.maximum_search_input_bytes || input.maximumMatches > state.policy.document.limits.maximum_search_matches || input.maximumFiles > 100_000 || input.maximumLineLength > 1_048_576) {
    throw new ScopedToolGatewayError("SEARCH_LIMIT_EXCEEDED", "Search limits exceed tool policy");
  }
  await fastPreflight(state);
  const request = await requestRecord(state, "SEARCH", null, null, { literal_sha256: sha256Bytes(Buffer.from(input.literal)), caseSensitive: input.caseSensitive, includes, excludes, maximumFiles: input.maximumFiles, maximumBytes: input.maximumBytes, maximumMatches: input.maximumMatches, maximumLineLength: input.maximumLineLength });
  const filePaths = new Set<string>(); let listedEntries = 0;
  for (const path of includes) {
    const listing = await state.filesystem.listScoped({ path, maximumDepth: 1024, maximumEntries: state.policy.document.limits.maximum_list_entries,
      maximumMetadataBytes: state.policy.document.limits.maximum_list_metadata_bytes, hashFiles: false, hashLimitBytes: state.policy.document.limits.maximum_hash_bytes });
    listedEntries += listing.entries.length;
    if (listedEntries > state.policy.document.limits.maximum_list_entries) throw new ScopedToolGatewayError("SEARCH_LIMIT_EXCEEDED", "Search traversal exceeds its global entry bound");
    for (const entry of listing.entries) {
      if (entry.type !== "REGULAR" || isSecretPath(state.policy, entry.path) || excludes.some((excluded) => pathWithin(entry.path, excluded)) || filePaths.has(entry.path)) continue;
      if (filePaths.size >= input.maximumFiles) throw new ScopedToolGatewayError("SEARCH_LIMIT_EXCEEDED", "Search file count exceeds its bound");
      filePaths.add(entry.path);
    }
  }
  const paths = [...filePaths].sort();
  const matches: ScopedSearchMatch[] = []; let bytesSearched = 0;
  const needle = input.caseSensitive ? input.literal : input.literal.toLowerCase();
  for (const path of paths) {
    const authority = assertReadablePath(state.policy, path);
    if (!rawReadPermitted(authority)) throw new ScopedToolGatewayError("DATA_POLICY_FORBIDS_READ", "Search cannot silently omit a metadata-only path", { path });
    const metadataRead = await state.filesystem.readScoped({ path, offset: 0, length: 0, maximumBytes: 0, hashLimitBytes: state.policy.document.limits.maximum_hash_bytes });
    if (bytesSearched + metadataRead.metadata.size > input.maximumBytes) throw new ScopedToolGatewayError("SEARCH_LIMIT_EXCEEDED", "Search input bytes exceed their bound");
    const file = await state.filesystem.readScoped({ path, offset: 0, length: metadataRead.metadata.size, maximumBytes: Math.min(input.maximumBytes, state.policy.document.limits.maximum_hash_bytes), hashLimitBytes: state.policy.document.limits.maximum_hash_bytes });
    const bytes = Buffer.from(file.dataBase64, "base64"); bytesSearched += bytes.byteLength;
    const text = decodeUtf8(bytes, "DATA_POLICY_FORBIDS_READ", "Search input is not UTF-8 text");
    const lines = text.split("\n");
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      const line = lines[lineIndex]!; if (Buffer.byteLength(line) > input.maximumLineLength) throw new ScopedToolGatewayError("SEARCH_LIMIT_EXCEEDED", "Search line exceeds its bound", { path });
      const haystack = input.caseSensitive ? line : line.toLowerCase(); let from = 0;
      while (true) {
        const column = haystack.indexOf(needle, from); if (column < 0) break;
        if (matches.length >= input.maximumMatches) throw new ScopedToolGatewayError("SEARCH_LIMIT_EXCEEDED", "Search match count exceeds its bound");
        const lineBytes = Buffer.from(line);
        matches.push({ path, line: lineIndex + 1, column: column + 1, lineDigest: sha256Bytes(lineBytes), preview: lineBytes.byteLength <= 1_024 ? line : null });
        from = column + Math.max(needle.length, 1);
      }
    }
  }
  const record = await createToolResult(state.location, request, "SEARCH", null, null, null, bytesSearched, matches.length, sha256Canonical(matches), "PASS");
  return detachedFrozen({ matches, filesSearched: paths.length, bytesSearched, resultRecord: record });
}

async function inspectGitScoped(state: GatewayState, input: ScopedGitInspectionRequest): Promise<ScopedGitInspectionResult> {
  exactInput(input, ["stateTokenContentSha256", "operation", "path"], "inspectGitScoped request"); assertCurrentToken(state, input.stateTokenContentSha256);
  const operations = new Set(["STATUS", "DIFF_NAME_STATUS", "DIFF_NUMSTAT", "SHOW_PATH_AT_HEAD", "LS_FILES", "WORKTREE_IDENTITY"]);
  if (!operations.has(input.operation)) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Git inspection operation is invalid");
  if (input.operation === "SHOW_PATH_AT_HEAD") { if (input.path === null) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "SHOW_PATH_AT_HEAD requires a path"); assertReadablePath(state.policy, input.path); }
  else if (input.path !== null) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Git inspection operation does not accept a path");
  await fastPreflight(state); const request = await requestRecord(state, "INSPECT_GIT", input.path, null, { operation: input.operation });
  let bytes: Buffer; let outcome: "RAW" | "METADATA_ONLY" | "PASS" = "PASS";
  if (input.operation === "STATUS" || input.operation === "DIFF_NAME_STATUS") {
    const fingerprint = await captureGitState(state.repository); const changed = fingerprintDirtyPaths(fingerprint);
    const visible = changed.filter((path) => pathMatchesRules(path, state.policy.readable) && !isSecretPath(state.policy, path));
    const visibleProjection = { branch: fingerprint.branch, head: fingerprint.head, dirty: fingerprint.dirty,
      visible_changed_paths: visible, hidden_changed_path_count: changed.length - visible.length };
    bytes = Buffer.from(canonicalize({ ...visibleProjection, visible_fingerprint_content_sha256: sha256Canonical(visibleProjection) }), "utf8");
  } else if (input.operation === "DIFF_NUMSTAT") {
    const fingerprint = await captureGitState(state.repository); const changed = fingerprintDirtyPaths(fingerprint);
    const visible = changed.filter((path) => pathMatchesRules(path, state.policy.readable) && !isSecretPath(state.policy, path));
    bytes = Buffer.from(canonicalize({ visible_changed_paths: visible, hidden_changed_path_count: changed.length - visible.length }), "utf8"); outcome = "METADATA_ONLY";
  } else if (input.operation === "LS_FILES") {
    const output = (await runGitInspection(state.repository.worktree_root, ["ls-files", "-z"])).stdout;
    const decoded = decodeUtf8(output, "PATH_NOT_READABLE", "Git path inventory is not UTF-8");
    if (decoded.length > 0 && !decoded.endsWith("\0")) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Git path inventory framing is invalid");
    const paths = decoded.length === 0 ? [] : decoded.slice(0, -1).split("\0");
    for (const path of paths) assertM4CanonicalPath(path, "Git path inventory");
    const visible = paths.filter((path) => pathMatchesRules(path, state.policy.readable) && !isSecretPath(state.policy, path));
    bytes = Buffer.from(canonicalize({ visible_paths: visible, hidden_path_count: paths.length - visible.length, visible_inventory_digest: sha256Canonical(visible) }), "utf8");
  } else if (input.operation === "WORKTREE_IDENTITY") {
    const identity = await resolveRepositoryIdentity({ requestedPath: state.repository.requested_path, requireHead: true });
    bytes = Buffer.from(canonicalize({ branch: identity.branch, detached: identity.detached, head: identity.head, head_tree: identity.head_tree,
      upstream_ref: identity.upstream_ref, ahead: identity.ahead, behind: identity.behind, worktree_key: identity.worktree_key,
      worktree_list_sha256: identity.worktree_list_sha256, submodule_state_sha256: identity.submodule_state_sha256 }), "utf8");
  } else {
    const authority = assertReadablePath(state.policy, input.path!); const rawAllowed = rawReadPermitted(authority);
    const content = (await runGitInspection(state.repository.worktree_root, ["show", `${state.repository.head}:${input.path!}`])).stdout;
    bytes = rawAllowed ? content : Buffer.from(canonicalize({ digest: sha256Bytes(content), bytes: content.byteLength }), "utf8"); outcome = rawAllowed ? "RAW" : "METADATA_ONLY";
  }
  if (bytes.byteLength > state.policy.document.limits.maximum_search_input_bytes) throw new ScopedToolGatewayError("OUTPUT_LIMIT_EXCEEDED", "Git inspection output exceeds its bound");
  const output = bytes.toString("base64"); const record = await createToolResult(state.location, request, "INSPECT_GIT", input.path, input.path === null ? null : dataClass(state, input.path) as never, sha256Bytes(bytes), bytes.byteLength, 1, sha256Bytes(bytes), outcome);
  return detachedFrozen({ output, resultRecord: record });
}

const EVIDENCE_SCHEMA: Readonly<Record<string, string>> = Object.freeze({
  EVIDENCE_METADATA: "pi_gacw_evidence_metadata_v0", EVIDENCE_MANIFEST: "pi_gacw_evidence_manifest_v0", WORKFLOW_STATE: "pi_gacw_state_v0",
  TRANSITION_EVENT: "pi_gacw_transition_event_v0", REDUCER_POLICY: "pi_gacw_reducer_policy_v0", PROCESS_ASSESSMENT: "pi_gacw_process_interruption_v0",
  TRANSITION_COMMIT: "pi_gacw_state_transition_commit_v0", M3_BASELINE: "pi_gacw_baseline_runtime_v0", M3_BASELINE_APPROVAL: "pi_gacw_baseline_approval_runtime_v0",
  M3_LOCK_ACQUISITION: "pi_gacw_lock_acquisition_v0", M3_LOCK_DIAGNOSTIC: "pi_gacw_lock_diagnostic_v0", M3_PREFLIGHT: "pi_gacw_preflight_v0",
  M3_REPOSITORY_STATE_TOKEN: "pi_gacw_repository_state_token_v0", M3_POSTFLIGHT: "pi_gacw_postflight_v0", M3_RETENTION_RESULT: "pi_gacw_retention_result_v0",
  M3_TERMINAL_RETENTION_AUTHORITY: "pi_gacw_terminal_retention_authority_v0",
  ...Object.fromEntries(Object.entries(M4_RECORD_DEFINITIONS).map(([, definition]) => [definition.persistenceKind, definition.schemaId])),
});

function containsSecretReference(state: GatewayState, value: unknown, seen = new Set<object>()): boolean {
  if (typeof value === "string") return state.policy.authorities.some((authority) => {
    if (authority.data_class !== "SECRET") return false;
    const secretBase = authority.path.slice(authority.path.lastIndexOf("/") + 1);
    return pathWithin(value, authority.path) || value === secretBase || value.split(/[\\/]/u).includes(secretBase);
  });
  if (value === null || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  return Object.values(value as Record<string, unknown>).some((entry) => containsSecretReference(state, entry, seen));
}

async function readEvidence(state: GatewayState, input: ScopedEvidenceReadRequest): Promise<ScopedEvidenceReadResult> {
  exactInput(input, ["stateTokenContentSha256", "kind", "contentSha256"], "readEvidence request"); assertCurrentToken(state, input.stateTokenContentSha256); assertDigest(input.contentSha256, "contentSha256");
  if (typeof input.kind !== "string" || !state.policy.document.evidence_readable_kinds.includes(input.kind) || EVIDENCE_SCHEMA[input.kind] === undefined) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Evidence kind is not permitted");
  await fastPreflight(state); const request = await requestRecord(state, "READ_EVIDENCE", null, null, { kind: input.kind, digest: input.contentSha256 });
  const inspection = await inspectRunStorage(state.location);
  if (inspection.status !== "HEALTHY") throw new ScopedToolGatewayError("EVIDENCE_PUBLICATION_FAILED", "State storage is not healthy");
  const object = [...inspection.reachableObjects, ...inspection.managedObjects].find((entry) => entry.kind === input.kind && entry.contentSha256 === input.contentSha256);
  if (object === undefined) throw new ScopedToolGatewayError("EVIDENCE_NOT_FOUND", "Evidence object is not reachable or managed");
  const classification = inspection.managedRecordClassifications.find((entry) => entry.object.kind === input.kind && entry.object.contentSha256 === input.contentSha256);
  if (classification !== undefined && ["INVALID_MANAGED_RECORD", "INCOMPLETE_MANAGED_RECORD_CHAIN", "UNCOMMITTED_BASELINE_PUBLICATION"].includes(classification.classification)) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Evidence authority is invalid or incomplete");
  const runRoot = join(state.location.stateRoot, "runs", state.location.runId); const path = resolve(runRoot, object.relativePath);
  if (!(path === runRoot || path.startsWith(`${runRoot}${sep}`))) throw new ScopedToolGatewayError("PATH_OUTSIDE_ROOT", "Evidence path escaped its run root");
  const stats = await lstat(path); if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) throw new ScopedToolGatewayError("SPECIAL_FILE", "Evidence object is not a private regular file");
  const bytes = await readFile(path); let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); assertDocumentValid(EVIDENCE_SCHEMA[input.kind] as never, value); }
  catch (error: unknown) { throw scopedToolError("PATH_NOT_READABLE", "Evidence object is malformed", error); }
  if (value === null || Array.isArray(value) || typeof value !== "object" || (value as Record<string, unknown>)["content_sha256"] !== input.contentSha256 || !bytes.equals(Buffer.from(`${canonicalize(value)}\n`))) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Evidence address or canonical bytes are invalid");
  if (containsSecretReference(state, value)) throw new ScopedToolGatewayError("SECRET_METADATA_FORBIDDEN", "Evidence contains SECRET path metadata");
  const record = await createToolResult(state.location, request, "READ_EVIDENCE", null, null, input.contentSha256, bytes.byteLength, 1, sha256Bytes(bytes), "PASS");
  return detachedFrozen({ document: value as Record<string, unknown>, resultRecord: record });
}

function receiptMetadata(value: SecureFileMetadata | null): { digest: Sha256Digest | null; size: number | null; mode: number | null } {
  return value === null ? { digest: null, size: null, mode: null } : { digest: value.digest, size: value.size, mode: value.mode };
}

function rollbackFact(journal: ReturnType<typeof mutationJournalForError>, uncertain = false): "NOT_REQUIRED" | "SUCCEEDED" | "FAILED" | "UNKNOWN" {
  if (journal === null || uncertain) return "UNKNOWN";
  if (journal.rollback_completed) return "SUCCEEDED";
  if (journal.rollback_attempted) return "FAILED";
  return journal.rollback_required ? "UNKNOWN" : "NOT_REQUIRED";
}

async function applyPatch(state: GatewayState, input: ScopedPatchRequest): Promise<ScopedPatchResult> {
  exactInput(input, ["stateTokenContentSha256", "lockAcquisitionContentSha256", "operation", "path", "ownershipClass", "dataClass", "expectedPreimageExists", "expectedPreimageDigest", "expectedPreimageSize", "expectedPreimageMode", "replacementBytes", "requestedFinalMode"], "applyPatchScoped request");
  assertCurrentToken(state, input.stateTokenContentSha256); assertDigest(input.lockAcquisitionContentSha256, "lockAcquisitionContentSha256"); assertM4CanonicalPath(input.path);
  if (!["CREATE", "REPLACE", "DELETE"].includes(input.operation)) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Patch operation is invalid");
  if (typeof input.expectedPreimageExists !== "boolean") throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Preimage existence is invalid");
  const acquisition = lockAcquisitionAuthority(state.lock);
  if (input.lockAcquisitionContentSha256 !== acquisition.content_sha256) throw new ScopedToolGatewayError("LOCK_NOT_HELD", "Patch request lock-acquisition identity differs");
  const replacement = input.replacementBytes;
  if (input.operation === "DELETE") {
    if (replacement !== null || input.requestedFinalMode !== null) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "DELETE request carries replacement authority");
  } else if (!(replacement instanceof Uint8Array) || replacement.byteLength > state.policy.document.limits.maximum_patch_bytes || !Number.isSafeInteger(input.requestedFinalMode)) {
    throw new ScopedToolGatewayError("PATCH_LIMIT_EXCEEDED", "Patch payload or final mode is invalid");
  }
  if ((input.operation === "CREATE") !== !input.expectedPreimageExists) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Patch operation and preimage existence differ");
  if (input.expectedPreimageExists) {
    assertDigest(input.expectedPreimageDigest, "expectedPreimageDigest"); assertSafeNonnegativeInteger(input.expectedPreimageSize, "expectedPreimageSize"); assertSafeNonnegativeInteger(input.expectedPreimageMode, "expectedPreimageMode");
  } else if (input.expectedPreimageDigest !== null || input.expectedPreimageSize !== null || input.expectedPreimageMode !== null) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Absent preimage carries metadata");
  const modeChanged = input.operation === "REPLACE" && input.expectedPreimageMode !== input.requestedFinalMode;
  assertMutationPermitted(state.policy, input.path, input.operation, input.ownershipClass, input.dataClass, modeChanged);
  const baselinePath = state.baseline.paths.find((entry) => entry.path === input.path);
  if (baselinePath !== undefined && (baselinePath.ownership_class !== input.ownershipClass || baselinePath.data_class !== input.dataClass)) throw new ScopedToolGatewayError("OWNERSHIP_FORBIDS_MUTATION", "Patch request differs from M3 baseline classification", { path: input.path });
  await fastPreflight(state);
  const replacementDigest = replacement === null ? null : sha256Bytes(replacement);
  const patch = identifyContractDocument("pi_gacw_patch_request_v0", {
    schema_id: "pi_gacw_patch_request_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: state.location.runId,
    requested_at: new Date().toISOString(), repository_identity_content_sha256: state.repository.content_sha256, worktree_key: state.repository.worktree_key,
    lock_acquisition_content_sha256: acquisition.content_sha256, prior_state_token_content_sha256: state.acceptedState.content_sha256,
    task_scope_identity: state.taskScopeIdentity, tool_policy_content_sha256: state.policy.document.content_sha256,
    secure_fs_capability_content_sha256: state.secureCapability.content_sha256, operation: input.operation, path: input.path,
    ownership_class: input.ownershipClass, data_class: input.dataClass, expected_preimage_exists: input.expectedPreimageExists,
    expected_preimage_digest: input.expectedPreimageDigest, expected_preimage_size: input.expectedPreimageSize, expected_preimage_mode: input.expectedPreimageMode,
    replacement_digest: replacementDigest, replacement_byte_count: replacement?.byteLength ?? 0, requested_final_mode: input.requestedFinalMode, patch_format_identity: "exact-bytes-v1",
  }) as M4PatchRequestDocument;
  await publishM4Record(state.location, "PATCH_REQUEST", patch);
  let outcome;
  try {
    outcome = await secureMutation(state.filesystem, { operation: input.operation, path: input.path,
      expected: { digest: input.expectedPreimageDigest, size: input.expectedPreimageSize, mode: input.expectedPreimageMode },
      replacement, finalMode: input.requestedFinalMode, hashLimitBytes: state.policy.document.limits.maximum_hash_bytes }, {
        runId: state.location.runId,
        repositoryIdentityContentSha256: state.repository.content_sha256 as Sha256Digest,
        worktreeIdentity: state.repository.worktree_key as Sha256Digest,
        priorStateTokenContentSha256: state.acceptedState.content_sha256 as Sha256Digest,
      });
  } catch (error: unknown) {
    const blockedError = mapSecurityError(error); const helperJournal = mutationJournalForError(error);
    const uncertain = ["SECURE_WRITE_UNCERTAIN", "OUTPUT_LIMIT_EXCEEDED", "ROLLBACK_UNCERTAIN", "FINAL_TARGET_IDENTITY_MISMATCH", "RESIDUE_IDENTITY_MISMATCH"].includes(blockedError.code);
    const activity = helperJournal?.atomic_rename_completed === true || helperJournal?.temporary_file_fsync_completed === true;
    const blocked = identifyContractDocument("pi_gacw_mutation_receipt_v0", {
      schema_id: "pi_gacw_mutation_receipt_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: state.location.runId,
      request_content_sha256: patch.content_sha256, operation: input.operation, path: input.path, before: receiptMetadata(null), after: receiptMetadata(null),
      secure_fs_capability_content_sha256: state.secureCapability.content_sha256, lock_acquisition_content_sha256: acquisition.content_sha256,
      prior_state_token_content_sha256: state.acceptedState.content_sha256, successor_state_token_content_sha256: null, task_scope_identity: state.taskScopeIdentity,
      tool_policy_content_sha256: state.policy.document.content_sha256,
      outcome: blockedError.code === "PREIMAGE_MISMATCH" ? "PREIMAGE_MISMATCH" : uncertain ? "UNCERTAIN" : "BLOCKED",
      helper_outcome: uncertain ? "UNCERTAIN" : activity ? "BLOCKED_AFTER_WRITE" : "BLOCKED",
      file_fsync: helperJournal?.temporary_file_fsync_completed ?? false, atomic_rename: helperJournal?.atomic_rename_completed ?? false,
      directory_fsync: (helperJournal?.directory_fsync_completed_count ?? 0) > 0, rollback_outcome: rollbackFact(helperJournal, uncertain),
      postflight_content_sha256: null, failure_code: blockedError.code, helper_journal: helperJournal, completed_at: new Date().toISOString(),
    }) as M4MutationReceiptDocument;
    try { await publishM4Record(state.location, "MUTATION_RECEIPT", blocked); }
    catch (publicationError: unknown) {
      if (uncertain) throw scopedToolError("SECURE_WRITE_UNCERTAIN", "Secure write and failure-receipt publication are uncertain", publicationError, { path: input.path });
      throw publicationError;
    }
    throw blockedError;
  }
  let progression: Awaited<ReturnType<typeof runPostflight>>;
  try {
    progression = await runPostflight({ stateRoot: state.location.stateRoot, runId: state.location.runId, acceptedState: state.acceptedState,
      baseline: state.baseline, instructionFiles: state.instructions, authorityFiles: state.authorities, editablePaths: state.editablePaths,
      frozenPaths: state.frozenPaths, taskScopeIdentity: state.taskScopeIdentity, claimedWorkflowPaths: [input.path], lock: state.lock });
  } catch (error: unknown) {
    const blocked = identifyContractDocument("pi_gacw_mutation_receipt_v0", {
      schema_id: "pi_gacw_mutation_receipt_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: state.location.runId,
      request_content_sha256: patch.content_sha256, operation: input.operation, path: input.path, before: receiptMetadata(outcome.before), after: receiptMetadata(outcome.after),
      secure_fs_capability_content_sha256: state.secureCapability.content_sha256, lock_acquisition_content_sha256: acquisition.content_sha256,
      prior_state_token_content_sha256: state.acceptedState.content_sha256, successor_state_token_content_sha256: null, task_scope_identity: state.taskScopeIdentity,
      tool_policy_content_sha256: state.policy.document.content_sha256, outcome: "BLOCKED", helper_outcome: "BLOCKED_AFTER_WRITE", file_fsync: outcome.fileFsync,
      atomic_rename: outcome.atomicRename, directory_fsync: outcome.directoryFsync, rollback_outcome: outcome.rollback, postflight_content_sha256: null,
      failure_code: "POSTFLIGHT_FAILED", helper_journal: outcome.journal, completed_at: new Date().toISOString(),
    }) as M4MutationReceiptDocument;
    await publishM4Record(state.location, "MUTATION_RECEIPT", blocked);
    throw scopedToolError("POSTFLIGHT_FAILED", "Secure write completed but M3 postflight failed", error, { path: input.path });
  }
  const receipt = identifyContractDocument("pi_gacw_mutation_receipt_v0", {
    schema_id: "pi_gacw_mutation_receipt_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: state.location.runId,
    request_content_sha256: patch.content_sha256, operation: input.operation, path: input.path, before: receiptMetadata(outcome.before), after: receiptMetadata(outcome.after),
    secure_fs_capability_content_sha256: state.secureCapability.content_sha256, lock_acquisition_content_sha256: acquisition.content_sha256,
    prior_state_token_content_sha256: state.acceptedState.content_sha256, successor_state_token_content_sha256: progression.acceptedState.content_sha256,
    task_scope_identity: state.taskScopeIdentity, tool_policy_content_sha256: state.policy.document.content_sha256, outcome: "APPLIED", helper_outcome: "APPLIED",
    file_fsync: outcome.fileFsync, atomic_rename: outcome.atomicRename, directory_fsync: outcome.directoryFsync,
    rollback_outcome: outcome.rollback, postflight_content_sha256: progression.postflight.content_sha256, failure_code: null,
    helper_journal: outcome.journal, completed_at: new Date().toISOString(),
  }) as M4MutationReceiptDocument;
  await publishM4Record(state.location, "MUTATION_RECEIPT", receipt);
  state.acceptedState = progression.acceptedState;
  return detachedFrozen({ receipt, acceptedState: progression.acceptedState });
}

async function runCommand(state: GatewayState, input: ScopedCommandRequest, expectedClass: "INSPECTION" | "TASK" | "VERIFICATION"): Promise<ScopedCommandResult> {
  exactInput(input, ["commandId", "stateTokenContentSha256"], "command request"); assertCurrentToken(state, input.stateTokenContentSha256);
  const specification = commandForClass(state.catalog, input.commandId, expectedClass); await fastPreflight(state);
  const request = await requestRecord(state, "COMMAND", null, input.commandId, { command_spec_sha256: specification.command_spec_sha256, command_class: expectedClass });
  const beforeToken = state.acceptedState; const sandboxStartedAt = new Date().toISOString();
  let outcome: Awaited<ReturnType<typeof runSandboxedCommand>>;
  try { outcome = await runSandboxedCommand(state.repository, state.temporaryRoot, state.sandboxCapability, specification); }
  catch (error: unknown) {
    const blocked = identifyContractDocument("pi_gacw_command_result_v0", {
      schema_id: "pi_gacw_command_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: state.location.runId,
      request_content_sha256: request.content_sha256, command_catalog_content_sha256: state.catalog.document.content_sha256,
      command_spec_sha256: specification.command_spec_sha256, command_id: specification.command_id, command_class: specification.command_class,
      state_token_before: beforeToken.content_sha256, state_token_after: null, sandbox_capability_content_sha256: state.sandboxCapability.content_sha256,
      executable_sha256: specification.executable_sha256, argv_identity: sha256Canonical(specification.argv),
      cwd: specification.cwd === "REPOSITORY_ROOT" ? state.repository.worktree_root : join(state.repository.worktree_root, specification.cwd),
      environment_identity: sha256Canonical({ LC_ALL: "C", LANG: "C", PATH: "/usr/bin:/bin", HOME: state.temporaryRoot, TMPDIR: state.temporaryRoot, entries: specification.environment }), started_at: sandboxStartedAt, ended_at: new Date().toISOString(),
      exit_code: null, signal: null, stdout_digest: sha256Bytes(Buffer.alloc(0)), stdout_byte_count: 0,
      stdout_observed_digest: sha256Bytes(Buffer.alloc(0)), stdout_observed_byte_count: 0, stdout_overflowed: false, stdout_stream_complete: true,
      stderr_digest: sha256Bytes(Buffer.alloc(0)), stderr_byte_count: 0,
      stderr_observed_digest: sha256Bytes(Buffer.alloc(0)), stderr_observed_byte_count: 0, stderr_overflowed: false, stderr_stream_complete: true,
      repository_delta: [], postflight_content_sha256: null,
      failure_code: error instanceof ScopedToolGatewayError && ["COMMAND_FORBIDDEN", "GENERIC_DISPATCHER_FORBIDDEN", "COMMAND_SPEC_MISMATCH", "EXECUTION_INPUT_DRIFT", "COMMAND_CWD_IDENTITY_DRIFT", "HARDLINK_WRITE_SCOPE_UNSAFE", "COMMAND_SANDBOX_UNAVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE"].includes(error.code)
        ? error.code : "COMMAND_SANDBOX_UNAVAILABLE", outcome: "BLOCKED",
    }) as M4CommandResultDocument;
    await publishM4Record(state.location, "COMMAND_RESULT", blocked);
    throw mapSecurityError(error);
  }
  let progression: Awaited<ReturnType<typeof runPostflight>> | null = null; let postflightError: unknown;
  try {
    progression = await runPostflight({ stateRoot: state.location.stateRoot, runId: state.location.runId, acceptedState: state.acceptedState,
      baseline: state.baseline, instructionFiles: state.instructions, authorityFiles: state.authorities, editablePaths: state.editablePaths,
      frozenPaths: state.frozenPaths, taskScopeIdentity: state.taskScopeIdentity,
      claimedWorkflowPaths: specification.repository_side_effect === "NONE" ? [] : specification.claimed_paths, lock: state.lock });
  } catch (error: unknown) { postflightError = error; }
  const exitUnexpected = outcome.exitCode === null || !specification.expected_exit_codes.includes(outcome.exitCode);
  const processFailure = outcome.failure ?? (exitUnexpected ? "COMMAND_EXIT_CODE_UNEXPECTED" : null);
  const blocked = postflightError !== undefined || processFailure !== null;
  const delta = progression?.postflight.workflow_owned_delta ?? [];
  const record = identifyContractDocument("pi_gacw_command_result_v0", {
    schema_id: "pi_gacw_command_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: state.location.runId,
    request_content_sha256: request.content_sha256, command_catalog_content_sha256: state.catalog.document.content_sha256,
    command_spec_sha256: specification.command_spec_sha256, command_id: specification.command_id, command_class: specification.command_class,
    state_token_before: beforeToken.content_sha256, state_token_after: progression?.acceptedState.content_sha256 ?? null,
    sandbox_capability_content_sha256: state.sandboxCapability.content_sha256, executable_sha256: specification.executable_sha256,
    argv_identity: sha256Canonical(specification.argv), cwd: specification.cwd === "REPOSITORY_ROOT" ? state.repository.worktree_root : join(state.repository.worktree_root, specification.cwd),
    environment_identity: sha256Canonical({ LC_ALL: "C", LANG: "C", PATH: "/usr/bin:/bin", HOME: state.temporaryRoot, TMPDIR: state.temporaryRoot, entries: specification.environment }), started_at: outcome.startedAt, ended_at: outcome.endedAt,
    exit_code: outcome.exitCode, signal: outcome.signal, stdout_digest: sha256Bytes(outcome.stdout), stdout_byte_count: outcome.stdoutBytes,
    stdout_observed_digest: outcome.stdoutObservedDigest, stdout_observed_byte_count: outcome.stdoutObservedBytes, stdout_overflowed: outcome.stdoutOverflowed, stdout_stream_complete: outcome.stdoutStreamComplete,
    stderr_digest: sha256Bytes(outcome.stderr), stderr_byte_count: outcome.stderrBytes,
    stderr_observed_digest: outcome.stderrObservedDigest, stderr_observed_byte_count: outcome.stderrObservedBytes, stderr_overflowed: outcome.stderrOverflowed, stderr_stream_complete: outcome.stderrStreamComplete,
    repository_delta: delta,
    postflight_content_sha256: progression?.postflight.content_sha256 ?? null,
    failure_code: postflightError !== undefined ? "COMMAND_UNEXPECTED_REPOSITORY_DELTA" : processFailure,
    outcome: blocked ? "BLOCKED" : "PASS",
  }) as M4CommandResultDocument;
  await publishM4Record(state.location, "COMMAND_RESULT", record);
  if (progression !== null) state.acceptedState = progression.acceptedState;
  if (postflightError !== undefined) throw scopedToolError("COMMAND_UNEXPECTED_REPOSITORY_DELTA", "Command postflight rejected repository effects", postflightError, { command_id: specification.command_id });
  if (processFailure !== null) throw new ScopedToolGatewayError(processFailure as ScopedToolGatewayErrorCode, "Sandboxed command did not satisfy its frozen execution contract", { command_id: specification.command_id, exit_code: outcome.exitCode, signal: outcome.signal });
  return detachedFrozen({ record, stdoutBase64: outcome.stdout.toString("base64"), stderrBase64: outcome.stderr.toString("base64"), acceptedState: progression?.acceptedState ?? null });
}

class ScopedToolGatewayImpl implements ScopedToolGateway {
  public constructor(state: GatewayState) { gatewayStates.set(this, state); Object.freeze(this); }
  public get acceptedState(): M3RepositoryStateTokenDocument { return detachedFrozen(stateFor(this).acceptedState); }
  public read_scoped(input: ScopedReadRequest): Promise<ScopedReadResult> { const state = stateFor(this); return exclusive(state, () => readScoped(state, input)); }
  public list_scoped(input: ScopedListRequest): Promise<ScopedListResult> { const state = stateFor(this); return exclusive(state, () => listScoped(state, input)); }
  public search_scoped(input: ScopedSearchRequest): Promise<ScopedSearchResult> { const state = stateFor(this); return exclusive(state, () => searchScoped(state, input)); }
  public inspect_git_scoped(input: ScopedGitInspectionRequest): Promise<ScopedGitInspectionResult> { const state = stateFor(this); return exclusive(state, () => inspectGitScoped(state, input)); }
  public read_evidence(input: ScopedEvidenceReadRequest): Promise<ScopedEvidenceReadResult> { const state = stateFor(this); return exclusive(state, () => readEvidence(state, input)); }
  public apply_patch_scoped(input: ScopedPatchRequest): Promise<ScopedPatchResult> { const state = stateFor(this); return exclusive(state, () => applyPatch(state, input)); }
  public run_inspection_command(input: ScopedCommandRequest): Promise<ScopedCommandResult> { const state = stateFor(this); return exclusive(state, () => runCommand(state, input, "INSPECTION")); }
  public run_task_command(input: ScopedCommandRequest): Promise<ScopedCommandResult> { const state = stateFor(this); return exclusive(state, () => runCommand(state, input, "TASK")); }
  public run_verification_command(input: ScopedCommandRequest): Promise<ScopedCommandResult> { const state = stateFor(this); return exclusive(state, () => runCommand(state, input, "VERIFICATION")); }
}

function pathsOverlap(left: string, right: string): boolean { return left === right || pathWithin(left, right) || pathWithin(right, left); }

export async function assertScopedToolGatewayAuthority(
  gateway: ScopedToolGateway,
  expected: ScopedToolGatewayAuthorityExpectation,
  approvedResources: readonly FingerprintedFileInput[],
): Promise<void> {
  const state = stateFor(gateway);
  if (
    state.location.stateRoot !== expected.stateRoot ||
    state.location.runId !== expected.runId ||
    canonicalize(state.repository) !== canonicalize(expected.repository) ||
    canonicalize(state.baseline) !== canonicalize(expected.baseline) ||
    canonicalize(state.acceptedState) !== canonicalize(expected.acceptedState) ||
    state.taskScopeIdentity !== expected.taskScopeIdentity ||
    canonicalize(state.policy.document) !== canonicalize(expected.toolPolicy) ||
    canonicalize(state.catalog.document) !== canonicalize(expected.commandCatalog) ||
    canonicalize(state.editablePaths) !== canonicalize(expected.editablePaths) ||
    canonicalize(state.frozenPaths) !== canonicalize(expected.frozenPaths) ||
    !sameFingerprintInputs(state.instructions, expected.instructionFiles) ||
    !sameFingerprintInputs(state.authorities, expected.authorityFiles) ||
    !sameFingerprintInputs([...state.instructions, ...state.authorities], approvedResources)
  ) {
    throw new ScopedToolGatewayError("STATE_TOKEN_PROVENANCE_INVALID", "Scoped gateway authority differs from the expected M3/M4 provenance");
  }
  try {
    await assertWorktreeLockHeld(state.lock);
    if (!lockMatchesRepository(state.lock, expected.repository)) {
      throw new ScopedToolGatewayError("LOCK_LOST", "Scoped gateway lock does not match the expected repository");
    }
    await runFastPreflight({
      stateRoot: state.location.stateRoot,
      runId: state.location.runId,
      acceptedState: state.acceptedState,
      baseline: state.baseline,
      instructionFiles: state.instructions,
      authorityFiles: state.authorities,
      taskScopeIdentity: state.taskScopeIdentity,
      lock: state.lock,
    });
  } catch (error: unknown) {
    throw mapSecurityError(error);
  }
}

export async function createScopedToolGateway(input: CreateScopedToolGatewayInput): Promise<ScopedToolGateway> {
  exactInput(input, ["stateRoot", "runId", "repository", "baseline", "acceptedState", "lock", "instructionFiles", "authorityFiles", "editablePaths", "frozenPaths", "taskScopeIdentity", "toolPolicy", "commandCatalog", "temporaryRoot"], "createScopedToolGateway input");
  if (![input.instructionFiles, input.authorityFiles, input.editablePaths, input.frozenPaths].every(Array.isArray)) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Gateway path and authority inventories must be arrays");
  input = Object.freeze({ ...input,
    repository: detachedFrozen(input.repository), baseline: detachedFrozen(input.baseline), acceptedState: detachedFrozen(input.acceptedState),
    instructionFiles: detachedFrozen(input.instructionFiles), authorityFiles: detachedFrozen(input.authorityFiles),
    editablePaths: Object.freeze([...input.editablePaths]), frozenPaths: Object.freeze([...input.frozenPaths]),
    toolPolicy: detachedFrozen(input.toolPolicy), commandCatalog: detachedFrozen(input.commandCatalog),
  });
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot"); assertAbsoluteNormalizedPath(input.temporaryRoot, "temporaryRoot");
  assertDocumentValid("pi_gacw_repository_identity_v0", input.repository); assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline); assertDocumentValid("pi_gacw_repository_state_token_v0", input.acceptedState); assertDigest(input.taskScopeIdentity, "taskScopeIdentity");
  if (input.baseline.run_id !== input.runId || input.acceptedState.run_id !== input.runId || input.baseline.repository.content_sha256 !== input.repository.content_sha256 ||
      input.acceptedState.repository_identity_content_sha256 !== input.repository.content_sha256 || input.acceptedState.task_scope_identity !== input.taskScopeIdentity) {
    throw new ScopedToolGatewayError("STATE_TOKEN_PROVENANCE_INVALID", "Gateway M3 authority documents do not agree");
  }
  const repositoryRoot = input.repository.worktree_root;
  if (pathsOverlap(input.temporaryRoot, repositoryRoot) || pathsOverlap(input.temporaryRoot, input.stateRoot)) throw new ScopedToolGatewayError("PATH_OUTSIDE_ROOT", "Controller temporary root must be separate from repository and state roots");
  await assertUsableM3Storage({ stateRoot: input.stateRoot, runId: input.runId }); await ensureControllerTemporaryRoot(input.temporaryRoot);
  const temporaryPhysical = await realpath(input.temporaryRoot);
  if (temporaryPhysical !== input.temporaryRoot || pathsOverlap(temporaryPhysical, repositoryRoot) || pathsOverlap(temporaryPhysical, input.stateRoot)) {
    throw new ScopedToolGatewayError("PATH_OUTSIDE_ROOT", "Controller temporary root physical identity is unsafe");
  }
  const policy = validateToolPolicy(input.toolPolicy, input.runId, input.repository, input.taskScopeIdentity, input.editablePaths, input.frozenPaths);
  const catalog = await validateCommandCatalog(input.commandCatalog, input.runId, input.repository, policy);
  try {
    await runFastPreflight({ stateRoot: input.stateRoot, runId: input.runId, acceptedState: input.acceptedState, baseline: input.baseline,
      instructionFiles: input.instructionFiles, authorityFiles: input.authorityFiles, taskScopeIdentity: input.taskScopeIdentity, lock: input.lock });
  } catch (error: unknown) { throw mapSecurityError(error); }
  let capabilities: Awaited<ReturnType<typeof probeM4Capabilities>>;
  try { capabilities = await probeM4Capabilities(); }
  catch (error: unknown) { throw mapSecurityError(error); }
  if (capabilities.secureFilesystem.secure_fs_result !== "SECURE_FS_AVAILABLE") throw new ScopedToolGatewayError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Secure filesystem capability is unavailable");
  if (capabilities.sandbox.result !== "COMMAND_SANDBOX_AVAILABLE") throw new ScopedToolGatewayError("COMMAND_SANDBOX_UNAVAILABLE", "Command sandbox capability is unavailable");
  if (capabilities.sandbox.network_result !== "NETWORK_SANDBOX_AVAILABLE") throw new ScopedToolGatewayError("NETWORK_SANDBOX_UNAVAILABLE", "Network denial capability is unavailable");
  const filesystem = await createSecureFilesystem({ repository: input.repository, capability: capabilities.secureFilesystem, readablePaths: policy.readable });
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  await publishM4Record(location, "SECURE_FS_CAPABILITY", capabilities.secureFilesystem);
  await publishM4Record(location, "SANDBOX_CAPABILITY", capabilities.sandbox);
  await publishM4Record(location, "TOOL_POLICY", input.toolPolicy);
  await publishM4Record(location, "COMMAND_CATALOG", input.commandCatalog);
  const state: GatewayState = { location, repository: input.repository, baseline: input.baseline, lock: input.lock,
    instructions: Object.freeze([...input.instructionFiles]), authorities: Object.freeze([...input.authorityFiles]),
    editablePaths: Object.freeze([...input.editablePaths]), frozenPaths: Object.freeze([...input.frozenPaths]), taskScopeIdentity: input.taskScopeIdentity,
    policy, catalog, filesystem, secureCapability: capabilities.secureFilesystem, sandboxCapability: capabilities.sandbox,
    temporaryRoot: input.temporaryRoot, acceptedState: input.acceptedState, busy: false };
  return new ScopedToolGatewayImpl(state);
}
