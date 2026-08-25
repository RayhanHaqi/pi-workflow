import { realpath } from "node:fs/promises";

import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical } from "../identity/index.js";
import {
  type M3BaselinePath,
  type M3BaselineRuntimeDocument,
  type M3DeltaEntry,
  type M3GitStateFingerprintDocument,
  type M3LockDiagnosticDocument,
  type M3PostflightDocument,
  type M3PreflightDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
} from "../schemas/index.js";
import {
  M3AuthorityValidationError,
  assertM3BaselineQuotaHistorySemantics,
  assertM3BaselineRuntimeSemantics,
  m3FingerprintDirtyPaths,
} from "../persistence/m3-authority.js";
import { assertEnvironmentProducerSemantics, assertEnvironmentFingerprintContinuity } from "./environment.js";
import { decodeUtf8, oneLine, runGitInspection } from "./git-runner.js";

interface TreeEntry {
  readonly mode: string;
  readonly object: string;
  readonly type: "blob" | "commit";
  readonly path: string;
}

interface ProducerPathState {
  readonly content: string | null;
  readonly type: "REGULAR" | "DELETED" | null;
  readonly mode: number | null;
  readonly size: number | null;
  readonly stagedStatus: string | null;
  readonly unstagedStatus: string | null;
  readonly untracked: boolean;
  readonly statusSha256: string;
}

function invalid(code: string, message: string): never {
  throw new M3AuthorityValidationError("INVALID", code, message);
}
function compareText(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function same(left: unknown, right: unknown): boolean { return canonicalize(left) === canonicalize(right); }
function zeroObject(value: string): boolean { return /^0+$/.test(value); }
function regularMode(mode: string): number {
  if (mode !== "100644" && mode !== "100755") invalid("BASELINE_PROVENANCE_INVALID", "historical Git path is not a supported regular file");
  return Number.parseInt(mode.slice(-3), 8);
}
function physicalModeMatchesGit(physicalMode: number | null, gitMode: number | null): boolean {
  if (physicalMode === null || gitMode === null) return physicalMode === gitMode;
  return (physicalMode & 0o111) !== 0 === ((gitMode & 0o111) !== 0);
}
function exactGitWorktreeMode(mode: number | null): string {
  if (mode === null) return "000000";
  return (mode & 0o111) !== 0 ? "100755" : "100644";
}

async function historicalTree(repository: M3RepositoryIdentityDocument): Promise<ReadonlyMap<string, TreeEntry>> {
  const [treeId, result, physicalRequested, physicalRoot, physicalCommon, physicalGitDir, gitVersion] = await Promise.all([
    runGitInspection(repository.worktree_root, ["rev-parse", "--verify", `${repository.head}^{tree}`]),
    runGitInspection(repository.worktree_root, ["ls-tree", "-r", "--full-tree", "-z", repository.head]),
    realpath(repository.requested_path),
    realpath(repository.worktree_root),
    realpath(repository.git_common_dir),
    realpath(repository.git_dir),
    runGitInspection(repository.worktree_root, ["--version"]),
  ]);
  if (oneLine(treeId.stdout, "historical HEAD tree") !== repository.head_tree ||
      physicalRequested !== repository.physical_requested_path || physicalRoot !== repository.worktree_root ||
      physicalCommon !== repository.git_common_dir || physicalGitDir !== repository.git_dir ||
      oneLine(gitVersion.stdout, "historical Git version") !== repository.git_version) {
    invalid("BASELINE_PROVENANCE_INVALID", "repository identity is not reproducible from its physical path and historical Git objects");
  }
  if (result.stdout.byteLength > 0 && result.stdout.at(-1) !== 0) {
    invalid("BASELINE_PROVENANCE_INVALID", "historical Git tree is not NUL terminated");
  }
  const entries = new Map<string, TreeEntry>();
  let start = 0;
  for (let index = 0; index < result.stdout.byteLength; index += 1) {
    if (result.stdout[index] !== 0) continue;
    const record = decodeUtf8(result.stdout.subarray(start, index), "historical Git tree entry");
    start = index + 1;
    const match = /^([0-7]{6}) (blob|commit) ([0-9a-f]{40,64})\t(.*)$/s.exec(record);
    if (match === null || match[4]!.length === 0 || entries.has(match[4]!)) {
      invalid("BASELINE_PROVENANCE_INVALID", "historical Git tree inventory is malformed or duplicated");
    }
    entries.set(match[4]!, { mode: match[1]!, type: match[2]! as "blob" | "commit", object: match[3]!, path: match[4]! });
  }
  return entries;
}

function statusProjection(fingerprint: M3GitStateFingerprintDocument, path: string) {
  return {
    staged: fingerprint.staged.filter((entry) => entry.path === path || entry.old_path === path),
    unstaged: fingerprint.unstaged.filter((entry) => entry.path === path || entry.old_path === path),
    untracked: fingerprint.untracked.filter((entry) => entry.path === path),
    conflicts: fingerprint.conflicts.filter((entry) => entry.path === path),
  };
}

interface HistoricalFingerprintContext {
  readonly tree: ReadonlyMap<string, TreeEntry>;
  readonly blobState: (entry: TreeEntry) => Promise<ProducerPathState>;
  readonly fingerprintState: (path: string) => Promise<ProducerPathState>;
}

async function historicalFingerprintContext(
  repository: M3RepositoryIdentityDocument,
  fingerprint: M3GitStateFingerprintDocument,
): Promise<HistoricalFingerprintContext> {
  const tree = await historicalTree(repository);
  const objectCache = new Map<string, { content: string; size: number }>();
  const objectBytes = async (object: string): Promise<{ content: string; size: number }> => {
    const prior = objectCache.get(object);
    if (prior !== undefined) return prior;
    const result = await runGitInspection(repository.worktree_root, ["cat-file", "blob", object]);
    const value = { content: sha256Bytes(result.stdout), size: result.stdout.byteLength };
    objectCache.set(object, value);
    return value;
  };
  const blobState = async (entry: TreeEntry): Promise<ProducerPathState> => {
    if (entry.type !== "blob") invalid("POSTFLIGHT_DELTA_MISMATCH", "historical path is not a regular blob");
    const bytes = await objectBytes(entry.object);
    return { content: bytes.content, type: "REGULAR", mode: regularMode(entry.mode), size: bytes.size,
      stagedStatus: null, unstagedStatus: null, untracked: false, statusSha256: sha256Canonical({}) };
  };

  const index = new Map<string, { mode: string; object: string; stage: number; path: string }>();
  for (const entry of tree.values()) index.set(entry.path, { mode: entry.mode, object: entry.object, stage: 0, path: entry.path });
  for (const staged of fingerprint.staged) {
    const renamed = staged.status === "R" || staged.status === "C";
    if (renamed !== (staged.old_path !== null) || (staged.old_path !== null && staged.old_path === staged.path) ||
        !["A", "C", "D", "M", "R"].includes(staged.status)) {
      invalid("BASELINE_PROVENANCE_INVALID", "staged status and old-path relationship is not producer-supported");
    }
    const headPath = renamed ? staged.old_path! : staged.path;
    const head = tree.get(headPath);
    if (staged.status === "A") {
      if (head !== undefined || staged.head_mode !== "000000" || !zeroObject(staged.head_object)) {
        invalid("BASELINE_PROVENANCE_INVALID", "staged addition has a forged HEAD preimage");
      }
    } else if (head === undefined || head.mode !== staged.head_mode || head.object !== staged.head_object) {
      invalid("BASELINE_PROVENANCE_INVALID", "staged path HEAD mode or object differs from the historical tree");
    }
    if (staged.status === "D") {
      if (staged.index_mode !== "000000" || !zeroObject(staged.index_object)) {
        invalid("BASELINE_PROVENANCE_INVALID", "staged deletion carries an index object");
      }
      index.delete(staged.path);
    } else {
      regularMode(staged.index_mode);
      if (zeroObject(staged.index_object)) invalid("BASELINE_PROVENANCE_INVALID", "staged present path has no index object");
      await objectBytes(staged.index_object);
      index.set(staged.path, { mode: staged.index_mode, object: staged.index_object, stage: 0, path: staged.path });
    }
    const unstagedLayer = fingerprint.unstaged.find((entry) => entry.path === staged.path);
    const expectedWorktreeMode = staged.status === "D"
      ? "000000"
      : unstagedLayer === undefined
        ? staged.index_mode
        : exactGitWorktreeMode(unstagedLayer.mode);
    if (staged.worktree_mode !== expectedWorktreeMode) {
      invalid("BASELINE_PROVENANCE_INVALID", "staged path worktree mode differs from its exact index/worktree layer");
    }
    if (staged.status === "R") index.delete(staged.old_path!);
    if (staged.status === "M" && staged.head_mode === staged.index_mode && staged.head_object === staged.index_object) {
      invalid("BASELINE_PROVENANCE_INVALID", "staged modification does not change its HEAD state");
    }
  }
  const indexEntries = [...index.values()].sort((left, right) => compareText(`${left.path}\0${left.stage}`, `${right.path}\0${right.stage}`));
  if (fingerprint.index_sha256 !== sha256Canonical(indexEntries)) {
    invalid("BASELINE_PROVENANCE_INVALID", "Git index identity is not reconstructible from historical HEAD and staged inventory");
  }
  for (const entry of fingerprint.untracked) {
    if (index.has(entry.path)) {
      invalid("BASELINE_PROVENANCE_INVALID", "untracked path is present in the reconstructed Git index");
    }
  }
  for (const entry of fingerprint.unstaged) {
    const renamed = entry.status === "R" || entry.status === "C";
    const carriesStagedRename = entry.old_path !== null && fingerprint.staged.some((staged) =>
      (staged.status === "R" || staged.status === "C") && staged.path === entry.path && staged.old_path === entry.old_path);
    if ((!renamed && entry.old_path !== null && !carriesStagedRename) ||
        (renamed && entry.old_path === null) || !["C", "D", "M", "R"].includes(entry.status)) {
      invalid("BASELINE_PROVENANCE_INVALID", "unstaged status and old-path relationship is not producer-supported");
    }
    const indexPath = renamed ? entry.old_path! : entry.path;
    const indexed = index.get(indexPath);
    if (indexed === undefined) invalid("BASELINE_PROVENANCE_INVALID", "unstaged path has no reconstructed index preimage");
    if (renamed && index.has(entry.path)) invalid("BASELINE_PROVENANCE_INVALID", "unstaged rename/copy destination already exists in the index");
    if (entry.status === "D") {
      if (entry.state !== "DELETED" || entry.file_type !== "DELETED" || entry.mode !== null || entry.size !== null ||
          entry.content_sha256 !== null) invalid("BASELINE_PROVENANCE_INVALID", "unstaged deletion carries a present path state");
    } else {
      if (entry.state !== "PRESENT" || entry.file_type !== "REGULAR" || entry.mode === null || entry.size === null ||
          entry.content_sha256 === null) invalid("BASELINE_PROVENANCE_INVALID", "unstaged present path lacks exact regular-file state");
      const indexedBytes = await objectBytes(indexed.object);
      if (entry.status === "M" && entry.content_sha256 === indexedBytes.content && entry.mode === regularMode(indexed.mode)) {
        invalid("BASELINE_PROVENANCE_INVALID", "unstaged modification does not change its reconstructed index state");
      }
    }
  }

  const fingerprintState = async (path: string): Promise<ProducerPathState> => {
    const projection = statusProjection(fingerprint, path);
    const staged = fingerprint.staged.find((entry) => entry.path === path);
    const stagedRenameSource = fingerprint.staged.some((entry) => entry.status === "R" && entry.old_path === path);
    const unstaged = fingerprint.unstaged.find((entry) => entry.path === path);
    const unstagedRenameSource = fingerprint.unstaged.some((entry) => entry.status === "R" && entry.old_path === path);
    const untracked = fingerprint.untracked.find((entry) => entry.path === path);
    const statusSha256 = sha256Canonical(projection);
    if (untracked !== undefined) {
      return { content: untracked.content_sha256, type: "REGULAR", mode: untracked.mode, size: untracked.size,
        stagedStatus: staged?.status ?? null, unstagedStatus: unstaged?.status ?? null, untracked: true, statusSha256 };
    }
    if (unstaged?.state === "PRESENT") {
      return { content: unstaged.content_sha256, type: "REGULAR", mode: unstaged.mode, size: unstaged.size,
        stagedStatus: staged?.status ?? null, unstagedStatus: unstaged.status, untracked: false, statusSha256 };
    }
    if (unstaged?.state === "DELETED" || staged?.status === "D" || stagedRenameSource || unstagedRenameSource) {
      return { content: null, type: "DELETED", mode: null, size: null,
        stagedStatus: staged?.status ?? null, unstagedStatus: unstaged?.status ?? null, untracked: false, statusSha256 };
    }
    if (staged === undefined || zeroObject(staged.index_object)) {
      invalid("BASELINE_PROVENANCE_INVALID", "dirty path has no exact resulting index/worktree state");
    }
    const bytes = await objectBytes(staged.index_object);
    return { content: bytes.content, type: "REGULAR", mode: regularMode(staged.index_mode), size: bytes.size,
      stagedStatus: staged.status, unstagedStatus: null, untracked: false, statusSha256 };
  };
  return { tree, blobState, fingerprintState };
}

function baselinePathMatches(entry: M3BaselinePath, state: ProducerPathState, fingerprint: M3GitStateFingerprintDocument): boolean {
  const content = state.type === "DELETED"
    ? sha256Canonical({ path: entry.path, state: "DELETED", status: statusProjection(fingerprint, entry.path) })
    : state.content;
  const exactPhysicalMode = fingerprint.untracked.some((candidate) => candidate.path === entry.path) ||
    fingerprint.unstaged.some((candidate) => candidate.path === entry.path);
  const modeMatches = exactPhysicalMode ? entry.mode === state.mode : physicalModeMatchesGit(entry.mode, state.mode);
  return entry.content_sha256 === content && entry.file_type === state.type && modeMatches && entry.size === state.size;
}

export async function assertDurableBaselineProducerSemantics(
  baseline: M3BaselineRuntimeDocument,
  allBaselines: readonly M3BaselineRuntimeDocument[],
): Promise<void> {
  try {
    assertM3BaselineRuntimeSemantics(baseline);
    assertM3BaselineQuotaHistorySemantics(baseline, allBaselines);
    const historical = await historicalFingerprintContext(baseline.repository, baseline.git_fingerprint);
    for (const path of baseline.paths) {
      const state = await historical.fingerprintState(path.path);
      if (!baselinePathMatches(path, state, baseline.git_fingerprint)) {
        invalid("BASELINE_PROVENANCE_INVALID", "baseline path state differs from its exact historical Git producer state");
      }
    }
  } catch (error: unknown) {
    if (error instanceof M3AuthorityValidationError) throw error;
    throw new M3AuthorityValidationError("INVALID", "BASELINE_PROVENANCE_INVALID", "baseline producer context could not be reconstructed");
  }
}

export async function assertDurableEnvironmentProducerSemantics(
  source: M3PreflightDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<void> {
  try {
    await assertEnvironmentProducerSemantics(source.environment_fingerprint, source.repository, lockDiagnostic);
  } catch (error: unknown) {
    if (error instanceof M3AuthorityValidationError) throw error;
    throw new M3AuthorityValidationError("INVALID", "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "preflight environment producer facts are inconsistent");
  }
}

/** Exact live-environment continuity for a resume-lock-handover lock generation. */
export async function assertDurableResumeHandoverEnvironmentSemantics(
  rootPreflight: M3PreflightDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<void> {
  try {
    await assertEnvironmentFingerprintContinuity(rootPreflight.environment_fingerprint, rootPreflight.repository, lockDiagnostic);
  } catch (error: unknown) {
    if (error instanceof M3AuthorityValidationError) throw error;
    throw new M3AuthorityValidationError("INVALID", "ENVIRONMENT_DRIFT", "resume-lock-handover live environment differs from the frozen root-preflight environment");
  }
}

function absent(state: ProducerPathState | null): boolean { return state === null || state.type === null || state.type === "DELETED"; }
function stateEqual(left: ProducerPathState | null, right: ProducerPathState | null): boolean {
  return (left?.content ?? null) === (right?.content ?? null) && (left?.type ?? null) === (right?.type ?? null) &&
    (left?.mode ?? null) === (right?.mode ?? null) && (left?.statusSha256 ?? sha256Canonical({})) === (right?.statusSha256 ?? sha256Canonical({}));
}
function changeKind(before: ProducerPathState | null, after: ProducerPathState | null, reverted = false): M3DeltaEntry["change_kind"] {
  if (reverted) return "BASELINE_REVERTED";
  if (absent(before) && !absent(after)) return "ADDED";
  if (!absent(before) && absent(after)) return "DELETED";
  if ((before?.type ?? null) !== (after?.type ?? null)) return "TYPE_CHANGED";
  if ((before?.content ?? null) === (after?.content ?? null) && (before?.mode ?? null) !== (after?.mode ?? null)) return "MODE_CHANGED";
  return "MODIFIED";
}
function delta(path: string, before: ProducerPathState | null, after: ProducerPathState | null, reverted = false): M3DeltaEntry {
  return {
    path,
    change_kind: changeKind(before, after, reverted),
    before_content_sha256: before?.content ?? null,
    after_content_sha256: after?.content ?? null,
    before_type: before?.type ?? null,
    after_type: after?.type ?? null,
    before_mode: before?.mode ?? null,
    after_mode: after?.mode ?? null,
    staged_status: after?.stagedStatus ?? null,
    unstaged_status: after?.unstagedStatus ?? null,
    untracked: after?.untracked ?? false,
  };
}
function baselineState(path: M3BaselinePath): ProducerPathState {
  return { content: path.file_type === "DELETED" ? null : path.content_sha256, type: path.file_type, mode: path.mode, size: path.size,
    stagedStatus: null, unstagedStatus: null, untracked: false, statusSha256: path.status_sha256 };
}

export async function assertDurablePostflightProducerSemantics(
  source: M3PostflightDocument,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
): Promise<void> {
  try {
    if (source.git_fingerprint.index_sha256 !== baseline.git_fingerprint.index_sha256 ||
        source.git_fingerprint.index_sha256 !== prior.git_fingerprint.index_sha256) {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "postflight source changes the accepted Git index");
    }
    const historical = await historicalFingerprintContext(source.repository, source.git_fingerprint);
    const dirtyPaths = m3FingerprintDirtyPaths(source.git_fingerprint);
    const baselineByPath = new Map(baseline.paths.map((entry) => [entry.path, entry]));
    const resultingState = async (path: string): Promise<ProducerPathState> => {
      const state = await historical.fingerprintState(path);
      const baselinePath = baselineByPath.get(path);
      const hasExactWorktreeState = source.git_fingerprint.untracked.some((entry) => entry.path === path) ||
        source.git_fingerprint.unstaged.some((entry) => entry.path === path);
      return baselinePath !== undefined && !hasExactWorktreeState && state.type === "REGULAR"
        ? { ...state, mode: baselinePath.mode, size: baselinePath.size }
        : state;
    };
    const repositoryDelta: M3DeltaEntry[] = [];
    for (const path of dirtyPaths) {
      const headEntry = historical.tree.get(path);
      const before = headEntry === undefined ? null : await historical.blobState(headEntry);
      const after = await resultingState(path);
      repositoryDelta.push(delta(path, before, after));
    }
    repositoryDelta.sort((left, right) => compareText(left.path, right.path));
    if (!same(repositoryDelta, source.repository_git_delta)) {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "repository delta is not the exact historical HEAD-to-result transition");
    }

    const dirty = new Set(dirtyPaths);
    const all = [...new Set([...baselineByPath.keys(), ...dirty])].sort(compareText);
    const workflowDelta: M3DeltaEntry[] = [];
    for (const path of all) {
      const baselinePath = baselineByPath.get(path);
      if (baselinePath === undefined) {
        if (!dirty.has(path)) continue;
        const headEntry = historical.tree.get(path);
        workflowDelta.push(delta(path, headEntry === undefined ? null : await historical.blobState(headEntry), await resultingState(path)));
        continue;
      }
      const before = baselineState(baselinePath);
      if (!dirty.has(path)) {
        const headEntry = historical.tree.get(path);
        let after = headEntry === undefined ? null : await historical.blobState(headEntry);
        if (after !== null && baselinePath.mode !== null && physicalModeMatchesGit(baselinePath.mode, after.mode)) {
          // Git stores only executable class. Preserve exact physical permission
          // bits when the approved baseline and stored HEAD share that class.
          after = { ...after, mode: baselinePath.mode };
        }
        workflowDelta.push(delta(path, before, after, true));
        continue;
      }
      const after = await resultingState(path);
      if (!stateEqual(before, after)) workflowDelta.push(delta(path, before, after));
    }
    workflowDelta.sort((left, right) => compareText(left.path, right.path));
    if (!same(workflowDelta, source.workflow_owned_delta)) {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "workflow delta is not the exact approved-baseline-to-result transition");
    }
  } catch (error: unknown) {
    if (error instanceof M3AuthorityValidationError) throw error;
    throw new M3AuthorityValidationError("INVALID", "POSTFLIGHT_DELTA_MISMATCH", "postflight historical producer context could not be reconstructed");
  }
}
