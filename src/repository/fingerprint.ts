import { lstat, readdir } from "node:fs/promises";
import { join } from "node:path";

import { sha256Canonical } from "../identity/index.js";
import { identifyContractDocument, type M3GitStateFingerprintDocument, type M3RepositoryIdentityDocument } from "../schemas/index.js";
import { m3PorcelainIdentityProjection } from "../persistence/m3-authority.js";
import { RepositoryGuardError } from "./errors.js";
import { decodeUtf8, runGitInspection } from "./git-runner.js";
import {
  assertCanonicalRepositoryPath,
  compareText,
  detachedFrozen,
  hashRegularFile,
  lstatOrUndefined,
  modeOf,
} from "./utils.js";

interface OrdinaryStatus {
  readonly kind: "ORDINARY" | "RENAMED";
  readonly xy: string;
  readonly sub: string;
  readonly headMode: string;
  readonly indexMode: string;
  readonly worktreeMode: string;
  readonly headObject: string;
  readonly indexObject: string;
  readonly path: string;
  readonly oldPath: string | null;
  readonly score: string | null;
}

interface UnmergedStatus {
  readonly kind: "UNMERGED";
  readonly xy: string;
  readonly sub: string;
  readonly stage1Mode: string;
  readonly stage2Mode: string;
  readonly stage3Mode: string;
  readonly worktreeMode: string;
  readonly stage1Object: string;
  readonly stage2Object: string;
  readonly stage3Object: string;
  readonly path: string;
}

interface UntrackedStatus {
  readonly kind: "UNTRACKED";
  readonly path: string;
}

type ParsedStatus = OrdinaryStatus | UnmergedStatus | UntrackedStatus;

function decodedNulFields(bytes: Buffer, label: string): string[] {
  const fields: string[] = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    fields.push(decodeUtf8(bytes.subarray(start, index), label));
    start = index + 1;
  }
  if (start !== bytes.length) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", `${label} is not NUL terminated`);
  return fields;
}

function canonicalGitPath(path: string): string {
  try {
    assertCanonicalRepositoryPath(path, "Git path");
    return path;
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError && error.code === "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING") throw error;
    throw new RepositoryGuardError("BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING", "Git returned a path outside the canonical path contract");
  }
}

function parseStatus(bytes: Buffer): readonly ParsedStatus[] {
  const fields = decodedNulFields(bytes, "porcelain-v2 status");
  const records: ParsedStatus[] = [];
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index]!;
    if (field.length === 0) continue;
    if (field.startsWith("1 ")) {
      const match = /^1 (..) (....) ([0-7]{6}) ([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) (.*)$/s.exec(field);
      if (match === null) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Ordinary porcelain-v2 status is malformed");
      records.push({
        kind: "ORDINARY",
        xy: match[1]!, sub: match[2]!, headMode: match[3]!, indexMode: match[4]!, worktreeMode: match[5]!,
        headObject: match[6]!, indexObject: match[7]!, path: canonicalGitPath(match[8]!), oldPath: null, score: null,
      });
      continue;
    }
    if (field.startsWith("2 ")) {
      const match = /^2 (..) (....) ([0-7]{6}) ([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) ([RC][0-9]+) (.*)$/s.exec(field);
      const oldPath = fields[index + 1];
      if (match === null || oldPath === undefined || oldPath.length === 0) {
        throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Rename/copy porcelain-v2 status is malformed");
      }
      index += 1;
      records.push({
        kind: "RENAMED",
        xy: match[1]!, sub: match[2]!, headMode: match[3]!, indexMode: match[4]!, worktreeMode: match[5]!,
        headObject: match[6]!, indexObject: match[7]!, path: canonicalGitPath(match[9]!),
        oldPath: canonicalGitPath(oldPath), score: match[8]!,
      });
      continue;
    }
    if (field.startsWith("u ")) {
      const match = /^u (..) (....) ([0-7]{6}) ([0-7]{6}) ([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) (.*)$/s.exec(field);
      if (match === null) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Unmerged porcelain-v2 status is malformed");
      records.push({
        kind: "UNMERGED", xy: match[1]!, sub: match[2]!, stage1Mode: match[3]!, stage2Mode: match[4]!,
        stage3Mode: match[5]!, worktreeMode: match[6]!, stage1Object: match[7]!, stage2Object: match[8]!,
        stage3Object: match[9]!, path: canonicalGitPath(match[10]!),
      });
      continue;
    }
    if (field.startsWith("? ")) {
      records.push({ kind: "UNTRACKED", path: canonicalGitPath(field.slice(2)) });
      continue;
    }
    if (field.startsWith("! ")) continue;
    throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Unknown porcelain-v2 status record");
  }
  return records.sort((left, right) => compareText(left.path, right.path));
}

function parseIndex(bytes: Buffer): readonly { mode: string; object: string; stage: number; path: string }[] {
  const entries: { mode: string; object: string; stage: number; path: string }[] = [];
  for (const field of decodedNulFields(bytes, "Git index")) {
    if (field.length === 0) continue;
    const match = /^([0-7]{6}) ([0-9a-f]{40,64}) ([0-3])\t(.*)$/s.exec(field);
    if (match === null) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git index inventory is malformed");
    entries.push({ mode: match[1]!, object: match[2]!, stage: Number(match[3]), path: canonicalGitPath(match[4]!) });
  }
  return entries.sort((left, right) => compareText(`${left.path}\u0000${left.stage}`, `${right.path}\u0000${right.stage}`));
}

function assertRelevantGitModes(...modes: string[]): void {
  if (modes.some((mode) => mode === "120000" || mode === "160000")) {
    throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "A dirty symlink or Git link cannot enter a baseline");
  }
}

const MAX_FILESYSTEM_INVENTORY_ENTRIES = 100_000;

async function assertNoUntrackedSpecialEntries(root: string): Promise<void> {
  let observed = 0;
  const visit = async (directory: string, prefix: string): Promise<void> => {
    const names = await readdir(directory, { encoding: "buffer" });
    names.sort((left, right) => Buffer.compare(left, right));
    for (const nameBytes of names) {
      const name = decodeUtf8(nameBytes, "worktree filesystem path");
      const path = prefix.length === 0 ? name : `${prefix}/${name}`;
      if (path === ".git") continue;
      observed += 1;
      if (observed > MAX_FILESYSTEM_INVENTORY_ENTRIES) {
        throw new RepositoryGuardError("BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT", "Worktree filesystem inventory exceeds its supported bound");
      }
      assertCanonicalRepositoryPath(path, "worktree filesystem path");
      const location = join(root, path);
      const stats = await lstat(location);
      if (stats.isDirectory() && !stats.isSymbolicLink()) {
        const ignored = await runGitInspection(root, ["check-ignore", "--quiet", "--", `${path}/`], [0, 1]);
        if (ignored.exitCode === 1) await visit(location, path);
        continue;
      }
      if (stats.isFile() && !stats.isSymbolicLink()) continue;
      const tracked = await runGitInspection(root, ["ls-files", "--error-unmatch", "--", path], [0, 1]);
      if (tracked.exitCode === 0) continue;
      const ignored = await runGitInspection(root, ["check-ignore", "--quiet", "--", path], [0, 1]);
      if (ignored.exitCode === 0) continue;
      throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "An untracked non-ignored worktree entry has an unsupported type", { path });
    }
  };
  await visit(root, "");
}

async function activeGitOperations(identity: M3RepositoryIdentityDocument): Promise<readonly ("MERGE" | "REBASE" | "CHERRY_PICK" | "REVERT" | "BISECT")[]> {
  const operations: ("MERGE" | "REBASE" | "CHERRY_PICK" | "REVERT" | "BISECT")[] = [];
  const exists = async (directory: string, name: string): Promise<boolean> => (await lstatOrUndefined(join(directory, name))) !== undefined;
  if (await exists(identity.git_dir, "MERGE_HEAD")) operations.push("MERGE");
  if (await exists(identity.git_dir, "rebase-merge") || await exists(identity.git_dir, "rebase-apply")) operations.push("REBASE");
  if (await exists(identity.git_dir, "CHERRY_PICK_HEAD")) operations.push("CHERRY_PICK");
  if (await exists(identity.git_dir, "REVERT_HEAD")) operations.push("REVERT");
  if (await exists(identity.git_dir, "BISECT_LOG") || await exists(identity.git_dir, "BISECT_START")) operations.push("BISECT");
  return operations;
}

async function regularWorktreeState(root: string, path: string, status: string) {
  const location = join(root, path);
  const stats = await lstatOrUndefined(location);
  if (stats === undefined) {
    return {
      path, old_path: null, status, state: "DELETED" as const, file_type: "DELETED" as const,
      mode: null, size: null, content_sha256: null,
    };
  }
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "A dirty worktree path is not a regular file");
  }
  const hashed = await hashRegularFile(location, false);
  return {
    path, old_path: null, status, state: "PRESENT" as const, file_type: "REGULAR" as const,
    mode: hashed.mode, size: hashed.size, content_sha256: hashed.contentSha256,
  };
}

export async function captureGitState(identity: M3RepositoryIdentityDocument): Promise<M3GitStateFingerprintDocument> {
  await assertNoUntrackedSpecialEntries(identity.worktree_root);
  const statusArgv = ["status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=none"] as const;
  const indexArgv = ["ls-files", "--stage", "-z"] as const;
  const [statusResult, indexResult, operationsBefore, indexLockStats] = await Promise.all([
    runGitInspection(identity.worktree_root, statusArgv),
    runGitInspection(identity.worktree_root, indexArgv),
    activeGitOperations(identity),
    lstatOrUndefined(join(identity.git_dir, "index.lock")),
  ]);
  const parsed = parseStatus(statusResult.stdout);
  const indexEntries = parseIndex(indexResult.stdout);
  const staged: Array<{
    path: string; old_path: string | null; status: string; head_mode: string; index_mode: string;
    worktree_mode: string; head_object: string; index_object: string;
  }> = [];
  const unstaged: Array<{
    path: string; old_path: string | null; status: string; state: "PRESENT" | "DELETED";
    file_type: "REGULAR" | "DELETED"; mode: number | null; size: number | null;
    content_sha256: `sha256:${string}` | null;
  }> = [];
  const untracked: Array<{
    path: string; file_type: "REGULAR"; mode: number; size: number; content_sha256: `sha256:${string}`;
  }> = [];
  const conflicts: Array<{
    path: string; status: string; stage1_mode: string; stage2_mode: string; stage3_mode: string; worktree_mode: string;
    stage1_object: string; stage2_object: string; stage3_object: string;
  }> = [];

  for (const record of parsed) {
    if (record.kind === "UNTRACKED") {
      const location = join(identity.worktree_root, record.path);
      const stats = await lstat(location);
      if (!stats.isFile() || stats.isSymbolicLink()) {
        throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "An untracked baseline path is not a regular file");
      }
      const hashed = await hashRegularFile(location, false);
      untracked.push({ path: record.path, file_type: "REGULAR", mode: hashed.mode, size: hashed.size, content_sha256: hashed.contentSha256 });
      continue;
    }
    if (record.kind === "UNMERGED") {
      assertRelevantGitModes(record.stage1Mode, record.stage2Mode, record.stage3Mode, record.worktreeMode);
      conflicts.push({
        path: record.path, status: record.xy, stage1_mode: record.stage1Mode, stage2_mode: record.stage2Mode,
        stage3_mode: record.stage3Mode, worktree_mode: record.worktreeMode, stage1_object: record.stage1Object,
        stage2_object: record.stage2Object, stage3_object: record.stage3Object,
      });
      continue;
    }
    assertRelevantGitModes(record.headMode, record.indexMode, record.worktreeMode);
    const indexStatus = record.xy[0]!;
    const worktreeStatus = record.xy[1]!;
    if (indexStatus !== ".") {
      staged.push({
        path: record.path,
        old_path: record.oldPath,
        status: indexStatus,
        head_mode: record.headMode,
        index_mode: record.indexMode,
        worktree_mode: record.worktreeMode,
        head_object: record.headObject,
        index_object: record.indexObject,
      });
    }
    if (worktreeStatus !== ".") {
      const state = await regularWorktreeState(identity.worktree_root, record.path, worktreeStatus);
      unstaged.push({ ...state, old_path: record.oldPath });
    }
  }

  staged.sort((left, right) => compareText(left.path, right.path));
  unstaged.sort((left, right) => compareText(left.path, right.path));
  untracked.sort((left, right) => compareText(left.path, right.path));
  conflicts.sort((left, right) => compareText(left.path, right.path));
  const [statusAfter, indexAfter, operationsAfter, indexLockAfter] = await Promise.all([
    runGitInspection(identity.worktree_root, statusArgv),
    runGitInspection(identity.worktree_root, indexArgv),
    activeGitOperations(identity),
    lstatOrUndefined(join(identity.git_dir, "index.lock")),
  ]);
  await assertNoUntrackedSpecialEntries(identity.worktree_root);
  if (!statusAfter.stdout.equals(statusResult.stdout) || !indexAfter.stdout.equals(indexResult.stdout) ||
      sha256Canonical(operationsAfter) !== sha256Canonical(operationsBefore) || Boolean(indexLockAfter) !== Boolean(indexLockStats)) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Repository state changed during Git fingerprint capture");
  }

  const document = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", {
    schema_id: "pi_gacw_git_state_fingerprint_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    repository_identity_content_sha256: identity.content_sha256,
    branch: identity.branch,
    detached: identity.detached,
    head: identity.head,
    head_tree: identity.head_tree,
    upstream_ref: identity.upstream_ref,
    ahead: identity.ahead,
    behind: identity.behind,
    porcelain_v2_sha256: sha256Canonical(m3PorcelainIdentityProjection({ staged, unstaged, untracked, conflicts })),
    index_sha256: sha256Canonical(indexEntries),
    staged_diff_sha256: sha256Canonical(staged),
    unstaged_diff_sha256: sha256Canonical(unstaged),
    untracked_inventory_sha256: sha256Canonical(untracked),
    staged,
    unstaged,
    untracked,
    conflicts,
    submodule_state_sha256: identity.submodule_state_sha256,
    worktree_list_sha256: identity.worktree_list_sha256,
    active_operations: operationsBefore,
    index_lock: indexLockStats !== undefined,
    dirty: staged.length > 0 || unstaged.length > 0 || untracked.length > 0 || conflicts.length > 0,
  }) as unknown as M3GitStateFingerprintDocument;
  return detachedFrozen(document);
}

export function fingerprintDirtyPaths(fingerprint: M3GitStateFingerprintDocument): readonly string[] {
  return Object.freeze([...new Set([
    ...fingerprint.staged.flatMap((entry) => entry.status === "R" && entry.old_path !== null ? [entry.path, entry.old_path] : [entry.path]),
    ...fingerprint.unstaged.flatMap((entry) => entry.status === "R" && entry.old_path !== null ? [entry.path, entry.old_path] : [entry.path]),
    ...fingerprint.untracked.map((entry) => entry.path),
    ...fingerprint.conflicts.map((entry) => entry.path),
  ])].sort(compareText));
}
