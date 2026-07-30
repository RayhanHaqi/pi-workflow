import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { identifyContractDocument, type M3RepositoryIdentityDocument } from "../schemas/index.js";
import { RepositoryGuardError, repositoryGuardError } from "./errors.js";
import { decodeUtf8, oneLine, optionalOneLine, runGitInspection } from "./git-runner.js";
import {
  assertAbsoluteNormalizedPath,
  assertCanonicalRepositoryPath,
  assertExactKeys,
  assertRecord,
  compareText,
  detachedFrozen,
  lstatOrUndefined,
} from "./utils.js";

export interface ResolveRepositoryIdentityInput {
  readonly requestedPath: string;
  readonly requireHead: boolean;
}

export interface DeriveWorktreeKeyInput {
  readonly gitCommonDir: string;
  readonly worktreeRoot: string;
}

async function requireRealDirectory(path: string, code: "WRONG_WORKTREE" | "UNREADABLE_GIT_DIRECTORY", label: string): Promise<string> {
  let physical: string;
  try {
    physical = await realpath(path);
    const stats = await lstat(physical);
    if (!stats.isDirectory() || stats.isSymbolicLink()) throw new RepositoryGuardError(code, `${label} is not a physical directory`);
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError) throw error;
    throw repositoryGuardError(code, `${label} cannot be resolved as a physical directory`, error);
  }
  return physical;
}

export async function deriveWorktreeKey(input: DeriveWorktreeKeyInput): Promise<Sha256Digest> {
  assertRecord(input, "deriveWorktreeKey input");
  assertExactKeys(input, ["gitCommonDir", "worktreeRoot"], "deriveWorktreeKey input");
  assertAbsoluteNormalizedPath(input.gitCommonDir, "gitCommonDir");
  assertAbsoluteNormalizedPath(input.worktreeRoot, "worktreeRoot");
  const [common, root] = await Promise.all([
    requireRealDirectory(input.gitCommonDir, "UNREADABLE_GIT_DIRECTORY", "Git common directory"),
    requireRealDirectory(input.worktreeRoot, "WRONG_WORKTREE", "Worktree root"),
  ]);
  return sha256Bytes(Buffer.concat([Buffer.from(common, "utf8"), Buffer.from([0]), Buffer.from(root, "utf8")]));
}

interface ParsedWorktree {
  readonly path: string;
  readonly head: string | null;
  readonly branch: string | null;
  readonly detached: boolean;
  readonly locked_reason: string | null;
  readonly prunable_reason: string | null;
}

async function parseWorktreeList(bytes: Buffer): Promise<readonly ParsedWorktree[]> {
  const fields = bytes.toString("binary").split("\u0000");
  const records: Record<string, string | boolean>[] = [];
  let current: Record<string, string | boolean> = {};
  for (const binaryField of fields) {
    if (binaryField.length === 0) {
      if (Object.keys(current).length > 0) records.push(current);
      current = {};
      continue;
    }
    const field = decodeUtf8(Buffer.from(binaryField, "binary"), "Git worktree list");
    const separator = field.indexOf(" ");
    const key = separator < 0 ? field : field.slice(0, separator);
    const value = separator < 0 ? true : field.slice(separator + 1);
    if (key in current) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git worktree list contains a duplicate field");
    current[key] = value;
  }
  if (Object.keys(current).length > 0) records.push(current);
  if (records.length === 0) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git worktree list is empty");

  const parsed: ParsedWorktree[] = [];
  for (const record of records) {
    const path = record["worktree"];
    if (typeof path !== "string" || !isAbsolute(path)) {
      throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git worktree list has an invalid worktree path");
    }
    const physical = await requireRealDirectory(resolve(path), "WRONG_WORKTREE", "Listed worktree");
    const head = record["HEAD"];
    if (head !== undefined && (typeof head !== "string" || !/^[0-9a-f]{40,64}$/.test(head))) {
      throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git worktree list has an invalid HEAD");
    }
    const branchField = record["branch"];
    if (branchField !== undefined && (typeof branchField !== "string" || !branchField.startsWith("refs/heads/"))) {
      throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git worktree list has an invalid branch");
    }
    const locked = record["locked"];
    const prunable = record["prunable"];
    parsed.push({
      path: physical,
      head: typeof head === "string" ? head : null,
      branch: typeof branchField === "string" ? branchField.slice("refs/heads/".length) : null,
      detached: record["detached"] === true,
      locked_reason: locked === undefined ? null : locked === true ? "LOCKED" : String(locked),
      prunable_reason: prunable === undefined ? null : prunable === true ? "PRUNABLE" : String(prunable),
    });
  }
  return parsed.sort((left, right) => compareText(left.path, right.path));
}

interface SubmoduleEntry {
  readonly path: string;
  readonly state: "CLEAN" | "MODIFIED" | "UNINITIALIZED" | "CONFLICT";
  readonly head: string;
  readonly description: string;
}

function parseIndexEntries(bytes: Buffer, prefix: string): readonly { mode: string; oid: string; stage: number; path: string }[] {
  const fields = bytes.subarray(0, bytes.at(-1) === 0 ? -1 : undefined).toString("binary").split("\u0000");
  const entries: { mode: string; oid: string; stage: number; path: string }[] = [];
  for (const binary of fields) {
    if (binary.length === 0) continue;
    const value = decodeUtf8(Buffer.from(binary, "binary"), "Git index inventory");
    const match = /^([0-7]{6}) ([0-9a-f]{40,64}) ([0-3])\t(.*)$/s.exec(value);
    if (match === null) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git index inventory is malformed");
    const path = prefix.length === 0 ? match[4]! : `${prefix}/${match[4]!}`;
    assertCanonicalRepositoryPath(path, "submodule path");
    entries.push({ mode: match[1]!, oid: match[2]!, stage: Number(match[3]), path });
  }
  return entries;
}

async function inspectSubmodules(root: string, prefix = "", depth = 0): Promise<readonly SubmoduleEntry[]> {
  if (depth > 32) throw new RepositoryGuardError("UNSUPPORTED_REPOSITORY_STATE", "Submodule nesting exceeds the supported bound");
  const index = await runGitInspection(root, ["ls-files", "--stage", "-z"]);
  const gitlinks = parseIndexEntries(index.stdout, prefix).filter((entry) => entry.mode === "160000");
  if (gitlinks.length > 10_000) throw new RepositoryGuardError("BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT", "Submodule count exceeds the supported bound");
  const grouped = new Map<string, typeof gitlinks>();
  for (const entry of gitlinks) grouped.set(entry.path, [...(grouped.get(entry.path) ?? []), entry]);
  const result: SubmoduleEntry[] = [];
  for (const [fullPath, entries] of [...grouped].sort(([left], [right]) => compareText(left, right))) {
    const relativePath = prefix.length === 0 ? fullPath : fullPath.slice(prefix.length + 1);
    const location = join(root, relativePath);
    const indexEntry = entries.find((entry) => entry.stage === 0) ?? entries[0];
    if (indexEntry === undefined) continue;
    let state: SubmoduleEntry["state"];
    let description: string;
    const stats = await lstatOrUndefined(location);
    if (entries.some((entry) => entry.stage !== 0)) {
      state = "CONFLICT";
      description = "UNMERGED_GITLINK";
    } else if (stats === undefined) {
      state = "UNINITIALIZED";
      description = "MISSING_WORKTREE";
    } else if (!stats.isDirectory() || stats.isSymbolicLink()) {
      state = "CONFLICT";
      description = "INVALID_WORKTREE_TYPE";
    } else {
      const nestedHead = await runGitInspection(location, ["rev-parse", "--verify", "HEAD"], [0, 128]);
      if (nestedHead.exitCode !== 0) {
        state = "UNINITIALIZED";
        description = "UNINITIALIZED_WORKTREE";
      } else {
        const head = oneLine(nestedHead.stdout, "Submodule HEAD");
        const nestedStatus = await runGitInspection(location, ["status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=none"]);
        state = head === indexEntry.oid && nestedStatus.stdout.byteLength === 0 ? "CLEAN" : "MODIFIED";
        description = state === "CLEAN" ? "MATCHES_INDEX" : "WORKTREE_OR_HEAD_DIFFERS";
        result.push(...await inspectSubmodules(location, fullPath, depth + 1));
      }
    }
    result.push({ path: fullPath, state, head: indexEntry.oid, description });
  }
  return result.sort((left, right) => compareText(left.path, right.path));
}

export async function resolveRepositoryIdentity(input: ResolveRepositoryIdentityInput): Promise<M3RepositoryIdentityDocument> {
  assertRecord(input, "resolveRepositoryIdentity input");
  assertExactKeys(input, ["requestedPath", "requireHead"], "resolveRepositoryIdentity input");
  assertAbsoluteNormalizedPath(input.requestedPath, "requestedPath");
  if (typeof input.requireHead !== "boolean") throw new RepositoryGuardError("INVALID_ARGUMENT", "requireHead must be boolean");

  let physicalRequested: string;
  try {
    physicalRequested = await realpath(input.requestedPath);
    const stats = await lstat(physicalRequested);
    if (!stats.isDirectory() || stats.isSymbolicLink()) throw new RepositoryGuardError("WRONG_WORKTREE", "Requested repository path is not a directory");
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError) throw error;
    throw repositoryGuardError("WRONG_WORKTREE", "Requested repository path cannot be resolved", error);
  }

  const rootResult = await runGitInspection(physicalRequested, ["rev-parse", "--path-format=absolute", "--show-toplevel"], [0, 128]);
  if (rootResult.exitCode !== 0) throw new RepositoryGuardError("NOT_A_GIT_WORKTREE", "Requested path is not inside a Git worktree");
  const gitTopLevelOutput = oneLine(rootResult.stdout, "Git top-level path");
  if (!isAbsolute(gitTopLevelOutput)) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git top-level path is not absolute");
  const worktreeRoot = await requireRealDirectory(resolve(gitTopLevelOutput), "WRONG_WORKTREE", "Git worktree root");

  const [commonResult, gitDirResult, headResult, branchResult, shallowResult, worktreeResult, gitVersionResult, partialRemoteResult, partialFiltersResult] = await Promise.all([
    runGitInspection(worktreeRoot, ["rev-parse", "--path-format=absolute", "--git-common-dir"]),
    runGitInspection(worktreeRoot, ["rev-parse", "--path-format=absolute", "--git-dir"]),
    runGitInspection(worktreeRoot, ["rev-parse", "--verify", "HEAD"], [0, 128]),
    runGitInspection(worktreeRoot, ["symbolic-ref", "--quiet", "--short", "HEAD"], [0, 1, 128]),
    runGitInspection(worktreeRoot, ["rev-parse", "--is-shallow-repository"]),
    runGitInspection(worktreeRoot, ["worktree", "list", "--porcelain", "-z"]),
    runGitInspection(worktreeRoot, ["--version"]),
    runGitInspection(worktreeRoot, ["config", "--local", "--get", "extensions.partialClone"], [0, 1]),
    runGitInspection(worktreeRoot, ["config", "--local", "--null", "--get-regexp", "^remote\\..*\\.partialclonefilter$"], [0, 1]),
  ]);

  if (headResult.exitCode !== 0) {
    if (input.requireHead) throw new RepositoryGuardError("MISSING_HEAD", "The selected repository mode requires HEAD");
    throw new RepositoryGuardError("MISSING_HEAD", "Unborn repositories are not supported by the M3 baseline contract");
  }
  const head = oneLine(headResult.stdout, "HEAD");
  if (!/^[0-9a-f]{40,64}$/.test(head)) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "HEAD is not a valid object identity");
  const treeResult = await runGitInspection(worktreeRoot, ["rev-parse", "--verify", "HEAD^{tree}"]);
  const headTree = oneLine(treeResult.stdout, "HEAD tree");
  if (!/^[0-9a-f]{40,64}$/.test(headTree)) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "HEAD tree is invalid");

  const commonOutput = oneLine(commonResult.stdout, "Git common directory");
  const gitDirOutput = oneLine(gitDirResult.stdout, "Git directory");
  const commonPath = isAbsolute(commonOutput) ? commonOutput : resolve(worktreeRoot, commonOutput);
  const gitDirectoryPath = isAbsolute(gitDirOutput) ? gitDirOutput : resolve(worktreeRoot, gitDirOutput);
  const [gitCommonDir, gitDir] = await Promise.all([
    requireRealDirectory(gitCommonDirPath(commonPath), "UNREADABLE_GIT_DIRECTORY", "Git common directory"),
    requireRealDirectory(gitDirectoryPath, "UNREADABLE_GIT_DIRECTORY", "Worktree Git directory"),
  ]);

  const branch = branchResult.exitCode === 0 ? optionalOneLine(branchResult.stdout, "branch") : null;
  const detached = branch === null;
  const upstreamResult = await runGitInspection(worktreeRoot, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"], [0, 128]);
  const upstreamRef = upstreamResult.exitCode === 0 ? optionalOneLine(upstreamResult.stdout, "upstream ref") : null;
  let ahead: number | null = null;
  let behind: number | null = null;
  if (upstreamRef !== null) {
    const divergence = await runGitInspection(worktreeRoot, ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"]);
    const match = /^(\d+)\s+(\d+)\n?$/.exec(decodeUtf8(divergence.stdout, "upstream divergence"));
    if (match === null) throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Upstream divergence is malformed");
    ahead = Number(match[1]);
    behind = Number(match[2]);
    if (!Number.isSafeInteger(ahead) || !Number.isSafeInteger(behind)) {
      throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Upstream divergence exceeds safe integer bounds");
    }
  }

  const worktrees = await parseWorktreeList(worktreeResult.stdout);
  if (!worktrees.some((entry) => entry.path === worktreeRoot)) {
    throw new RepositoryGuardError("WRONG_WORKTREE", "Resolved worktree is absent from Git's worktree inventory");
  }
  const shallowText = oneLine(shallowResult.stdout, "shallow state");
  if (shallowText !== "true" && shallowText !== "false") throw new RepositoryGuardError("INVALID_GIT_OUTPUT", "Git shallow state is invalid");
  const promisorRemote = partialRemoteResult.exitCode === 0 ? optionalOneLine(partialRemoteResult.stdout, "partial-clone remote") : null;
  const filterText = partialFiltersResult.exitCode === 0 ? decodeUtf8(partialFiltersResult.stdout, "partial-clone filters") : "";
  const filters = filterText.split("\u0000").filter((entry) => entry.length > 0).sort(compareText);
  const submodules = await inspectSubmodules(worktreeRoot);
  const worktreeKey = await deriveWorktreeKey({ gitCommonDir, worktreeRoot });

  const document = identifyContractDocument("pi_gacw_repository_identity_v0", {
    schema_id: "pi_gacw_repository_identity_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    requested_path: input.requestedPath,
    physical_requested_path: physicalRequested,
    worktree_root: worktreeRoot,
    git_toplevel: worktreeRoot,
    git_common_dir: gitCommonDir,
    git_dir: gitDir,
    worktree_git_dir: gitDir,
    branch,
    detached,
    head,
    head_tree: headTree,
    upstream_ref: upstreamRef,
    ahead,
    behind,
    worktrees,
    worktree_list_sha256: sha256Canonical(worktrees),
    shallow: shallowText === "true",
    partial_clone: { promisor_remote: promisorRemote, filters },
    submodules,
    submodule_state_sha256: sha256Canonical(submodules),
    git_version: oneLine(gitVersionResult.stdout, "Git version"),
    worktree_key: worktreeKey,
  }) as unknown as M3RepositoryIdentityDocument;
  return detachedFrozen(document);
}

function gitCommonDirPath(path: string): string {
  return path;
}
