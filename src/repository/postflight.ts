import { lstat } from "node:fs/promises";
import { join } from "node:path";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import {
  M3_SCOPE_PROJECTION_ID,
  M3_SCOPE_SCHEMA_ID,
  M3_SCOPE_VERSION,
  m3ScopeIdentity,
} from "../identity/m3-scope.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type M3BaselinePath,
  type M3BaselineRuntimeDocument,
  type M3DeltaEntry,
  type M3GitStateFingerprintDocument,
  type M3PostflightDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
} from "../schemas/index.js";
import { captureFileSetFingerprint, verifyBaselineBlobs, type FingerprintedFileInput } from "./baseline.js";
import { RepositoryGuardError } from "./errors.js";
import { captureGitState } from "./fingerprint.js";
import { decodeUtf8, runGitInspection } from "./git-runner.js";
import { resolveRepositoryIdentity } from "./identity.js";
import { assertWorktreeLockHeld, lockMatchesRepository, type WorktreeLockHandle } from "./lock.js";
import { assertNoGitBlockers, assertRepositoryMatches } from "./preflight.js";
import { assertPostflightProducerSemantics, assertPostflightSourceSemantics } from "./provenance.js";
import { loadAuthoritativeToken } from "./token-provenance.js";
import {
  assertStateRootCapacity,
  assertUsableM3Storage,
  canonicalJsonRecordBytes,
  m3RecordExists,
  publishM3Record,
  rollbackNewM3Record,
} from "./storage.js";
import {
  assertAbsoluteNormalizedPath,
  assertCanonicalRepositoryPath,
  assertDigest,
  assertExactKeys,
  assertNonemptyString,
  assertRecord,
  assertUniqueCanonicalPaths,
  compareText,
  detachedFrozen,
  hashRegularFile,
  lstatOrUndefined,
  pathWithinAny,
} from "./utils.js";

export interface RunPostflightInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly acceptedState: M3RepositoryStateTokenDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly editablePaths: readonly string[];
  readonly frozenPaths: readonly string[];
  readonly taskScopeIdentity: Sha256Digest;
  readonly claimedWorkflowPaths: readonly string[];
  readonly lock: WorktreeLockHandle;
}

export interface PostflightResult {
  readonly postflight: M3PostflightDocument;
  readonly acceptedState: M3RepositoryStateTokenDocument;
}

interface PathState {
  readonly content: string | null;
  readonly type: "REGULAR" | "DELETED" | null;
  readonly mode: number | null;
  readonly stagedStatus: string | null;
  readonly unstagedStatus: string | null;
  readonly untracked: boolean;
  readonly statusSha256: string;
}

function fingerprintPaths(fingerprint: M3GitStateFingerprintDocument): readonly string[] {
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

function statusProjection(fingerprint: M3GitStateFingerprintDocument, path: string) {
  return {
    staged: fingerprint.staged.filter((entry) => entry.path === path || entry.old_path === path),
    unstaged: fingerprint.unstaged.filter((entry) => entry.path === path || entry.old_path === path),
    untracked: fingerprint.untracked.filter((entry) => entry.path === path),
    conflicts: fingerprint.conflicts.filter((entry) => entry.path === path),
  };
}

async function fingerprintPathState(
  repository: M3RepositoryIdentityDocument,
  fingerprint: M3GitStateFingerprintDocument,
  path: string,
): Promise<PathState> {
  const projection = statusProjection(fingerprint, path);
  const staged = projection.staged[0];
  const unstaged = projection.unstaged.find((entry) => entry.path === path);
  const untracked = projection.untracked[0];
  if (unstaged?.state === "DELETED" || (staged !== undefined && staged.status === "D") ||
      (staged?.old_path === path && staged.status === "R")) {
    const stats = await lstatOrUndefined(join(repository.worktree_root, path));
    if (stats === undefined) {
      return {
        content: null,
        type: "DELETED",
        mode: null,
        stagedStatus: staged?.status ?? null,
        unstagedStatus: unstaged?.status ?? null,
        untracked: false,
        statusSha256: sha256Canonical(projection),
      };
    }
  }
  if (untracked !== undefined) {
    return {
      content: untracked.content_sha256,
      type: "REGULAR",
      mode: untracked.mode,
      stagedStatus: null,
      unstagedStatus: null,
      untracked: true,
      statusSha256: sha256Canonical(projection),
    };
  }
  if (unstaged?.state === "PRESENT") {
    return {
      content: unstaged.content_sha256,
      type: "REGULAR",
      mode: unstaged.mode,
      stagedStatus: staged?.status ?? null,
      unstagedStatus: unstaged.status,
      untracked: false,
      statusSha256: sha256Canonical(projection),
    };
  }
  const location = join(repository.worktree_root, path);
  const stats = await lstatOrUndefined(location);
  if (stats === undefined) {
    return {
      content: null,
      type: "DELETED",
      mode: null,
      stagedStatus: staged?.status ?? null,
      unstagedStatus: null,
      untracked: false,
      statusSha256: sha256Canonical(projection),
    };
  }
  if (!stats.isFile() || stats.isSymbolicLink()) throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "Postflight path is not a regular file", { path });
  const hashed = await hashRegularFile(location, false);
  return {
    content: hashed.contentSha256,
    type: "REGULAR",
    mode: hashed.mode,
    stagedStatus: staged?.status ?? null,
    unstagedStatus: null,
    untracked: false,
    statusSha256: sha256Canonical(projection),
  };
}

async function headPathState(repository: M3RepositoryIdentityDocument, path: string): Promise<PathState | null> {
  const result = await runGitInspection(repository.worktree_root, ["ls-tree", "--full-tree", "-z", repository.head, "--", path]);
  if (result.stdout.byteLength === 0) return null;
  if (result.stdout.at(-1) !== 0 || result.stdout.subarray(0, -1).includes(0)) {
    throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "HEAD path inventory is malformed");
  }
  const record = decodeUtf8(result.stdout.subarray(0, -1), "HEAD path inventory");
  const match = /^([0-7]{6}) blob ([0-9a-f]{40,64})\t(.*)$/s.exec(record);
  if (match === null || match[3] !== path || match[1] === "120000" || match[1] === "160000") {
    throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "HEAD path is not an ordinary regular blob", { path });
  }
  const bytes = await runGitInspection(repository.worktree_root, ["cat-file", "blob", match[2]!]);
  return {
    content: sha256Bytes(bytes.stdout),
    type: "REGULAR",
    mode: Number.parseInt(match[1]!.slice(-3), 8),
    stagedStatus: null,
    unstagedStatus: null,
    untracked: false,
    statusSha256: sha256Canonical({}),
  };
}

function baselinePathState(path: M3BaselinePath): PathState {
  return {
    content: path.file_type === "DELETED" ? null : path.content_sha256,
    type: path.file_type,
    mode: path.mode,
    stagedStatus: null,
    unstagedStatus: null,
    untracked: false,
    statusSha256: path.status_sha256,
  };
}

function sameState(left: PathState, right: PathState): boolean {
  return left.content === right.content && left.type === right.type && left.mode === right.mode && left.statusSha256 === right.statusSha256;
}

function deltaEntry(path: string, before: PathState | null, after: PathState | null, baselineReverted = false): M3DeltaEntry {
  const beforeType = before?.type ?? null;
  const afterType = after?.type ?? null;
  let kind: M3DeltaEntry["change_kind"];
  if (baselineReverted) kind = "BASELINE_REVERTED";
  else if (beforeType === null || beforeType === "DELETED") kind = "ADDED";
  else if (afterType === null || afterType === "DELETED") kind = "DELETED";
  else if (beforeType !== afterType) kind = "TYPE_CHANGED";
  else if (before?.content === after?.content && before?.mode !== after?.mode) kind = "MODE_CHANGED";
  else kind = "MODIFIED";
  return {
    path,
    change_kind: kind,
    before_content_sha256: before?.content ?? null,
    after_content_sha256: after?.content ?? null,
    before_type: beforeType,
    after_type: afterType,
    before_mode: before?.mode ?? null,
    after_mode: after?.mode ?? null,
    staged_status: after?.stagedStatus ?? null,
    unstaged_status: after?.unstagedStatus ?? null,
    untracked: after?.untracked ?? false,
  };
}

async function repositoryGitDelta(
  repository: M3RepositoryIdentityDocument,
  fingerprint: M3GitStateFingerprintDocument,
): Promise<readonly M3DeltaEntry[]> {
  const result: M3DeltaEntry[] = [];
  for (const path of fingerprintPaths(fingerprint)) {
    const [before, after] = await Promise.all([
      headPathState(repository, path),
      fingerprintPathState(repository, fingerprint, path),
    ]);
    result.push(deltaEntry(path, before, after));
  }
  return result.sort((left, right) => compareText(left.path, right.path));
}

async function workflowDelta(
  repository: M3RepositoryIdentityDocument,
  fingerprint: M3GitStateFingerprintDocument,
  baseline: M3BaselineRuntimeDocument,
): Promise<readonly M3DeltaEntry[]> {
  const baselineByPath = new Map(baseline.paths.map((entry) => [entry.path, entry]));
  const currentPaths = new Set(fingerprintPaths(fingerprint));
  const allPaths = [...new Set([...baselineByPath.keys(), ...currentPaths])].sort(compareText);
  const result: M3DeltaEntry[] = [];
  for (const path of allPaths) {
    const baselinePath = baselineByPath.get(path);
    const currentDirty = currentPaths.has(path);
    if (baselinePath === undefined) {
      if (currentDirty) {
        const [before, after] = await Promise.all([
          headPathState(repository, path),
          fingerprintPathState(repository, fingerprint, path),
        ]);
        result.push(deltaEntry(path, before, after));
      }
      continue;
    }
    const before = baselinePathState(baselinePath);
    if (!currentDirty) {
      result.push(deltaEntry(path, before, await cleanCurrentState(repository, path), true));
      continue;
    }
    const after = await fingerprintPathState(repository, fingerprint, path);
    if (!sameState(before, after)) result.push(deltaEntry(path, before, after));
  }
  return result;
}

async function cleanCurrentState(repository: M3RepositoryIdentityDocument, path: string): Promise<PathState | null> {
  const location = join(repository.worktree_root, path);
  const stats = await lstatOrUndefined(location);
  if (stats === undefined) return null;
  if (!stats.isFile() || stats.isSymbolicLink()) throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "Postflight path is not a regular file", { path });
  const hashed = await hashRegularFile(location, false);
  return {
    content: hashed.contentSha256,
    type: "REGULAR",
    mode: hashed.mode,
    stagedStatus: null,
    unstagedStatus: null,
    untracked: false,
    statusSha256: sha256Canonical({}),
  };
}

async function changedSinceAccepted(
  repository: M3RepositoryIdentityDocument,
  before: M3GitStateFingerprintDocument,
  after: M3GitStateFingerprintDocument,
): Promise<readonly string[]> {
  const beforePaths = new Set(fingerprintPaths(before));
  const afterPaths = new Set(fingerprintPaths(after));
  const paths = [...new Set([...beforePaths, ...afterPaths])].sort(compareText);
  const changed: string[] = [];
  for (const path of paths) {
    const beforeState = beforePaths.has(path) ? await fingerprintPathState(repository, before, path) : null;
    const afterState = afterPaths.has(path) ? await fingerprintPathState(repository, after, path) : null;
    if (beforeState === null || afterState === null || !sameState(beforeState, afterState)) changed.push(path);
  }
  return changed;
}

function assertScope(input: RunPostflightInput): { editable: string[]; frozen: string[] } {
  if (!Array.isArray(input.editablePaths) || !Array.isArray(input.frozenPaths) || !Array.isArray(input.claimedWorkflowPaths)) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "Postflight path sets must be arrays");
  }
  assertUniqueCanonicalPaths(input.editablePaths, "editablePaths");
  assertUniqueCanonicalPaths(input.frozenPaths, "frozenPaths");
  assertUniqueCanonicalPaths(input.claimedWorkflowPaths, "claimedWorkflowPaths");
  const editable = [...input.editablePaths].sort(compareText);
  const frozen = [...input.frozenPaths].sort(compareText);
  for (const left of editable) {
    for (const right of frozen) {
      if (left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`)) {
        throw new RepositoryGuardError("INVALID_ARGUMENT", "Editable and frozen path envelopes overlap");
      }
    }
  }
  const computed = m3ScopeIdentity(editable, frozen);
  if (computed !== input.taskScopeIdentity) throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Task scope identity does not match its path envelope");
  return { editable, frozen };
}

function samePathSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((path, index) => path === right[index]);
}

export async function runPostflight(input: RunPostflightInput): Promise<PostflightResult> {
  assertRecord(input, "runPostflight input");
  assertExactKeys(input, [
    "stateRoot", "runId", "acceptedState", "baseline", "instructionFiles", "authorityFiles", "editablePaths",
    "frozenPaths", "taskScopeIdentity", "claimedWorkflowPaths", "lock",
  ], "runPostflight input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertNonemptyString(input.runId, "runId", 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(input.runId)) throw new RepositoryGuardError("INVALID_ARGUMENT", "runId is invalid");
  assertDigest(input.taskScopeIdentity, "taskScopeIdentity");
  assertDocumentValid("pi_gacw_repository_state_token_v0", input.acceptedState);
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  const scope = assertScope(input);
  if (input.runId !== input.acceptedState.run_id || input.runId !== input.baseline.run_id ||
      input.acceptedState.baseline_runtime_content_sha256 !== input.baseline.content_sha256 ||
      input.acceptedState.task_scope_identity !== input.taskScopeIdentity) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Postflight token, baseline, run, or scope identity differs");
  }
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  await assertUsableM3Storage(location);
  const tokenAuthority = await loadAuthoritativeToken(location, input.acceptedState, input.baseline);
  if (!tokenAuthority.mayAdvance) {
    throw new RepositoryGuardError("STATE_TOKEN_CHAIN_TOO_DEEP", "Postflight would exceed the fixed repository-state token chain bound");
  }
  const lockDiagnostic = await assertWorktreeLockHeld(input.lock);
  if (!lockMatchesRepository(input.lock, input.baseline.repository) ||
      lockDiagnostic.content_sha256 !== input.acceptedState.lock_diagnostic_content_sha256) {
    throw new RepositoryGuardError("LOCK_LOST", "Postflight lock identity differs from accepted state");
  }

  const repository = await resolveRepositoryIdentity({ requestedPath: input.baseline.repository.requested_path, requireHead: true });
  assertRepositoryMatches(input.baseline.repository, repository);
  const [fingerprint, instructionFingerprint, authorityFingerprint] = await Promise.all([
    captureGitState(repository),
    captureFileSetFingerprint(input.instructionFiles, "INSTRUCTION_DRIFT"),
    captureFileSetFingerprint(input.authorityFiles, "AUTHORITY_DRIFT"),
  ]);
  assertNoGitBlockers(fingerprint);
  if (instructionFingerprint.content_sha256 !== input.acceptedState.instruction_fingerprint.content_sha256) {
    throw new RepositoryGuardError("INSTRUCTION_DRIFT", "Instruction fingerprint changed during the attempt");
  }
  if (authorityFingerprint.content_sha256 !== input.acceptedState.authority_fingerprint.content_sha256) {
    throw new RepositoryGuardError("AUTHORITY_DRIFT", "Authority fingerprint changed during the attempt");
  }
  if (fingerprint.index_sha256 !== input.baseline.git_fingerprint.index_sha256) {
    throw new RepositoryGuardError("INDEX_DRIFT", "Git index differs from the approved baseline index");
  }
  await verifyBaselineBlobs(input.stateRoot, input.baseline);

  const [repositoryDelta, ownedDelta, attemptChanged] = await Promise.all([
    repositoryGitDelta(repository, fingerprint),
    workflowDelta(repository, fingerprint, input.baseline),
    changedSinceAccepted(repository, input.acceptedState.git_fingerprint, fingerprint),
  ]);
  const claimed = [...input.claimedWorkflowPaths].sort(compareText);
  if (!samePathSet(claimed, attemptChanged)) {
    throw new RepositoryGuardError("UNEXPECTED_REPOSITORY_DELTA", "Observed attempt delta differs from the caller's exact workflow path claim");
  }

  const baselineByPath = new Map(input.baseline.paths.map((entry) => [entry.path, entry]));
  for (const delta of ownedDelta) {
    assertCanonicalRepositoryPath(delta.path, "postflight path");
    const baselinePath = baselineByPath.get(delta.path);
    if (pathWithinAny(delta.path, scope.frozen)) throw new RepositoryGuardError("FORBIDDEN_PATH_CHANGED", "A frozen path changed", { path: delta.path });
    if (baselinePath?.ownership_class === "OWNER_AUTHORITY") {
      throw new RepositoryGuardError("FORBIDDEN_PATH_CHANGED", "An OWNER_AUTHORITY path changed", { path: delta.path });
    }
    if (baselinePath?.ownership_class === "PREEXISTING_UNRELATED") {
      throw new RepositoryGuardError("FORBIDDEN_PATH_CHANGED", "A PREEXISTING_UNRELATED path changed", { path: delta.path });
    }
    if (!pathWithinAny(delta.path, scope.editable)) {
      throw new RepositoryGuardError("FORBIDDEN_PATH_CHANGED", "Workflow-owned delta is outside the editable scope", { path: delta.path });
    }
    if (delta.after_type !== null && delta.after_type !== "REGULAR" && delta.after_type !== "DELETED") {
      throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "Postflight introduced an unsupported path type", { path: delta.path });
    }
  }

  const postflight = identifyContractDocument("pi_gacw_postflight_v0", {
    schema_id: "pi_gacw_postflight_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    prior_token_content_sha256: input.acceptedState.content_sha256,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    repository,
    git_fingerprint: fingerprint,
    repository_git_delta: repositoryDelta,
    workflow_owned_delta: ownedDelta,
    claimed_workflow_paths: claimed,
    scope: {
      schema_id: M3_SCOPE_SCHEMA_ID,
      schema_version: M3_SCOPE_VERSION,
      scope_projection_id: M3_SCOPE_PROJECTION_ID,
      editable_paths: scope.editable,
      frozen_paths: scope.frozen,
      scope_identity: input.taskScopeIdentity,
    },
    lock_diagnostic_content_sha256: lockDiagnostic.content_sha256,
    result: "PASS",
    blockers: [],
  }) as unknown as M3PostflightDocument;
  const nextToken = identifyContractDocument("pi_gacw_repository_state_token_v0", {
    schema_id: "pi_gacw_repository_state_token_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    source: "POSTFLIGHT",
    source_content_sha256: postflight.content_sha256,
    prior_token_content_sha256: input.acceptedState.content_sha256,
    run_id: input.runId,
    repository_identity_content_sha256: repository.content_sha256,
    worktree_key: repository.worktree_key,
    branch: repository.branch,
    head: repository.head,
    worktree_list_sha256: repository.worktree_list_sha256,
    git_fingerprint: fingerprint,
    instruction_fingerprint: instructionFingerprint,
    authority_fingerprint: authorityFingerprint,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    lock_diagnostic_content_sha256: lockDiagnostic.content_sha256,
    task_scope_identity: input.taskScopeIdentity,
    workflow_owned_delta_sha256: sha256Canonical(ownedDelta),
    changed_paths: ownedDelta.map((entry) => entry.path).sort(compareText),
  }) as unknown as M3RepositoryStateTokenDocument;
  await assertPostflightProducerSemantics(postflight, input.acceptedState, input.baseline);
  assertPostflightSourceSemantics(
    postflight,
    nextToken,
    input.acceptedState,
    input.baseline,
    tokenAuthority.approval,
  );

  let additional = 0;
  const postflightWasNew = !await m3RecordExists(location, "POSTFLIGHT", postflight.content_sha256);
  const tokenWasNew = !await m3RecordExists(location, "REPOSITORY_STATE_TOKEN", nextToken.content_sha256);
  if (postflightWasNew) additional += canonicalJsonRecordBytes(postflight).byteLength;
  if (tokenWasNew) additional += canonicalJsonRecordBytes(nextToken).byteLength;
  await assertStateRootCapacity(input.stateRoot, additional);
  try {
    await publishM3Record(location, "POSTFLIGHT", postflight as unknown as Record<string, unknown>);
    await publishM3Record(location, "REPOSITORY_STATE_TOKEN", nextToken as unknown as Record<string, unknown>);
  } catch (publicationError: unknown) {
    try {
      await rollbackNewM3Record(location, "REPOSITORY_STATE_TOKEN", nextToken, tokenWasNew);
    } catch (tokenCleanupError: unknown) {
      try {
        await rollbackNewM3Record(location, "POSTFLIGHT", postflight, postflightWasNew);
      } catch (sourceCleanupError: unknown) {
        throw new RepositoryGuardError(
          "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
          "Postflight/token publication rollback could not break the authority chain",
          {},
          { cause: sourceCleanupError },
        );
      }
      throw new RepositoryGuardError(
        "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
        "Failed postflight-token removal required source-record rollback",
        {},
        { cause: tokenCleanupError },
      );
    }
    throw publicationError;
  }
  return detachedFrozen({ postflight, acceptedState: nextToken });
}
