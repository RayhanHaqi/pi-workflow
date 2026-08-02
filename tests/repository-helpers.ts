import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sha256Bytes } from "../src/identity/index.js";
import { m3ScopeIdentity } from "../src/identity/m3-scope.js";
import { resolveRepositoryIdentity } from "../src/repository/identity.js";
import { resolveExecutable } from "../src/repository/lock.js";
import type { FingerprintedFileInput, RequiredEnvironment } from "../src/repository/index.js";
import { initializeRunStorage } from "../src/persistence/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { makePolicy, stateIdentities } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";

const execFileAsync = promisify(execFile);

export async function git(cwd: string, ...argv: string[]): Promise<string> {
  const result = await execFileAsync("git", argv, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, LC_ALL: "C", LANG: "C", GIT_PAGER: "cat" },
    maxBuffer: 32 * 1024 * 1024,
  });
  return result.stdout;
}

export interface RepositoryFixture {
  readonly root: string;
  readonly repository: string;
  readonly stateRoot: string;
  readonly runId: string;
  readonly trackedPath: string;
  readonly instructionPath: string;
  readonly authorityPath: string;
  readonly policy: ReturnType<typeof makePolicy>;
  readonly initialState: ReturnType<typeof createInitialState>;
  readonly committed: Awaited<ReturnType<typeof initializeRunStorage>>;
}

export async function createRepositoryFixture(): Promise<RepositoryFixture> {
  const root = await mkdtemp(join(tmpdir(), "pi-gacw-m3-"));
  await chmod(root, 0o700);
  try {
    const repository = join(root, "repository");
    const stateRoot = join(root, "state");
    await mkdir(repository, { mode: 0o700 });
    await mkdir(stateRoot, { mode: 0o700 });
    await git(repository, "init", "-b", "main");
    await git(repository, "config", "user.name", "M3 Test");
    await git(repository, "config", "user.email", "m3@example.invalid");
    const trackedPath = join(repository, "tracked.txt");
    const instructionPath = join(repository, "AGENTS.md");
    const authorityPath = join(repository, "AUTHORITY.md");
    await writeFile(trackedPath, "initial\n", { mode: 0o644 });
    await writeFile(instructionPath, "M3 test instructions\n", { mode: 0o644 });
    await writeFile(authorityPath, "M3 frozen authority\n", { mode: 0o644 });
    await git(repository, "add", "tracked.txt", "AGENTS.md", "AUTHORITY.md");
    await git(repository, "commit", "-m", "fixture baseline");

    const policy = makePolicy("DIRECT_LUNA_HIGH");
    const runId = policy.run_id;
    const initialState = createInitialState(policy, stateIdentities(policy));
    const committed = await initializeRunStorage({ stateRoot, runId, policy, initialState, processMetadata });
    return { root, repository, stateRoot, runId, trackedPath, instructionPath, authorityPath, policy, initialState, committed };
  } catch (error: unknown) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

export async function removeRepositoryFixture(fixture: RepositoryFixture): Promise<void> {
  await rm(fixture.root, { recursive: true, force: true });
}

export async function fingerprintInput(path: string): Promise<FingerprintedFileInput> {
  return { path, expectedSha256: sha256Bytes(await readFile(path)) };
}

export async function instructionAuthorityInputs(fixture: RepositoryFixture): Promise<{
  readonly instructions: readonly FingerprintedFileInput[];
  readonly authorities: readonly FingerprintedFileInput[];
}> {
  return {
    instructions: [await fingerprintInput(fixture.instructionPath)],
    authorities: [await fingerprintInput(fixture.authorityPath)],
  };
}

export async function requiredEnvironment(repositoryPath: string): Promise<RequiredEnvironment> {
  const identity = await resolveRepositoryIdentity({ requestedPath: repositoryPath, requireHead: true });
  const [nodePath, gitPath, pythonPath] = await Promise.all([
    realpath(process.execPath),
    resolveExecutable("git"),
    resolveExecutable("python3"),
  ]);
  const { stdout, stderr } = await execFileAsync(pythonPath, ["--version"], { encoding: "utf8" });
  return {
    node_version: process.version,
    git_version: identity.git_version,
    python_version: `${stdout}${stderr}`.trim(),
    controller_version: "0.1.0",
    node_path: nodePath,
    git_path: gitPath,
    python_path: pythonPath,
  };
}

export function scopeIdentity(editablePaths: readonly string[], frozenPaths: readonly string[]): `sha256:${string}` {
  return m3ScopeIdentity(editablePaths, frozenPaths);
}
