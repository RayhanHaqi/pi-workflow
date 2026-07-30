import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical } from "../identity/index.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3RepositoryIdentityDocument,
} from "../schemas/index.js";
import { assertPrivateDirectory } from "../persistence/atomic.js";
import { publishGlobalLockAcquisition } from "./acquisition.js";
import { RepositoryGuardError, repositoryGuardError } from "./errors.js";
import { boundedExecutableVersion, resolveExecutable, resolveExecutableIdentity } from "./executable.js";
import { repositoryTestHooks } from "./test-hooks.js";

export { resolveExecutable } from "./executable.js";
import {
  assertAbsoluteNormalizedPath,
  assertExactKeys,
  assertIsoTimestamp,
  assertRecord,
  detachedFrozen,
  digestHex,
  randomNonce,
} from "./utils.js";

const PROTOCOL = "flock-guardian-v1";
const READY_TIMEOUT_MS = 3_000;
const HEALTH_TIMEOUT_MS = 2_000;
const RELEASE_TIMEOUT_MS = 3_000;
const PROTOCOL_OUTPUT_LIMIT = 64 * 1024;

interface GuardianMessage {
  readonly type: string;
  readonly protocol?: string;
  readonly guardian_pid?: number;
  readonly nonce?: string;
  readonly code?: string;
  readonly acquisition_nonce?: string;
}

interface MessageWaiter {
  readonly predicate: (message: GuardianMessage) => boolean;
  readonly resolve: (message: GuardianMessage) => void;
  readonly reject: (error: unknown) => void;
  readonly timer: NodeJS.Timeout;
}

interface LockState {
  readonly child: ChildProcessWithoutNullStreams;
  readonly acquisition: M3LockAcquisitionDocument;
  readonly diagnostics: M3LockDiagnosticDocument;
  readonly channel: GuardianChannel;
  lost: boolean;
  released: boolean;
  releaseRequested: boolean;
  healthInFlight: Promise<M3LockDiagnosticDocument> | null;
}

const handleStates = new WeakMap<object, LockState>();

export interface WorktreeLockHandle {
  readonly diagnostics: M3LockDiagnosticDocument;
}

class WorktreeLockHandleImpl implements WorktreeLockHandle {
  public constructor(state: LockState) {
    handleStates.set(this, state);
    Object.freeze(this);
  }

  public get diagnostics(): M3LockDiagnosticDocument {
    const state = handleStates.get(this);
    if (state === undefined) throw new RepositoryGuardError("LOCK_LOST", "Lock handle is invalid");
    return detachedFrozen(state.diagnostics);
  }
}

class GuardianChannel {
  private readonly messages: GuardianMessage[] = [];
  private readonly waiters: MessageWaiter[] = [];
  private stdoutBuffer = Buffer.alloc(0);
  private outputBytes = 0;
  private terminalError: unknown;

  public constructor(private readonly child: ChildProcessWithoutNullStreams) {
    child.stdout.on("data", (chunk: Buffer) => this.onStdout(chunk));
    child.stderr.on("data", (chunk: Buffer) => {
      this.outputBytes += chunk.byteLength;
      if (this.outputBytes > PROTOCOL_OUTPUT_LIMIT) this.fail(new RepositoryGuardError("LOCK_LOST", "Guardian output exceeded its bound"));
    });
    child.once("error", (error: unknown) => this.fail(repositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Guardian process could not start", error)));
    child.once("close", (code, signal) => {
      this.fail(new RepositoryGuardError("LOCK_LOST", "Guardian process exited", { exit_code: code, signal }));
    });
  }

  private onStdout(chunk: Buffer): void {
    if (this.terminalError !== undefined) return;
    this.outputBytes += chunk.byteLength;
    if (this.outputBytes > PROTOCOL_OUTPUT_LIMIT) {
      this.fail(new RepositoryGuardError("LOCK_LOST", "Guardian output exceeded its bound"));
      this.child.kill("SIGKILL");
      return;
    }
    this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);
    while (true) {
      const newline = this.stdoutBuffer.indexOf(0x0a);
      if (newline < 0) break;
      const line = this.stdoutBuffer.subarray(0, newline);
      this.stdoutBuffer = this.stdoutBuffer.subarray(newline + 1);
      let message: unknown;
      try {
        message = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line));
      } catch (error: unknown) {
        this.fail(repositoryGuardError("LOCK_LOST", "Guardian protocol is malformed", error));
        this.child.kill("SIGKILL");
        return;
      }
      if (message === null || Array.isArray(message) || typeof message !== "object" ||
          typeof (message as Record<string, unknown>)["type"] !== "string") {
        this.fail(new RepositoryGuardError("LOCK_LOST", "Guardian protocol message has an invalid shape"));
        this.child.kill("SIGKILL");
        return;
      }
      this.dispatch(message as GuardianMessage);
    }
  }

  private dispatch(message: GuardianMessage): void {
    const waiterIndex = this.waiters.findIndex((waiter) => waiter.predicate(message));
    if (waiterIndex < 0) {
      this.messages.push(message);
      return;
    }
    const [waiter] = this.waiters.splice(waiterIndex, 1);
    if (waiter !== undefined) {
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    }
  }

  private fail(error: unknown): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  public waitFor(predicate: (message: GuardianMessage) => boolean, timeoutMs: number, timeoutCode: "LOCK_GUARDIAN_START_FAILED" | "LOCK_LOST" | "LOCK_RELEASE_FAILED"): Promise<GuardianMessage> {
    const queuedIndex = this.messages.findIndex(predicate);
    if (queuedIndex >= 0) {
      const [message] = this.messages.splice(queuedIndex, 1);
      if (message !== undefined) return Promise.resolve(message);
    }
    if (this.terminalError !== undefined) return Promise.reject(this.terminalError);
    return new Promise<GuardianMessage>((resolveWaiter, rejectWaiter) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex((waiter) => waiter.resolve === resolveWaiter);
        if (index >= 0) this.waiters.splice(index, 1);
        rejectWaiter(new RepositoryGuardError(timeoutCode, "Guardian protocol deadline expired"));
      }, timeoutMs);
      timer.unref();
      this.waiters.push({ predicate, resolve: resolveWaiter, reject: rejectWaiter, timer });
    });
  }
}

interface GuardianHelperIdentity {
  readonly invocationPath: string;
  readonly realpath: string;
}

async function guardianPath(): Promise<GuardianHelperIdentity> {
  const override = repositoryTestHooks().guardianPath;
  const modulePath = fileURLToPath(import.meta.url);
  const candidates = override === undefined
    ? [
        resolve(dirname(modulePath), "../../helpers/flock_guardian.py"),
        resolve(dirname(modulePath), "../../../helpers/flock_guardian.py"),
      ]
    : [override];
  for (const selected of candidates) {
    try {
      if (!isAbsolute(selected)) continue;
      const candidate = resolve(selected);
      const invocationStats = await lstat(candidate);
      if (!invocationStats.isFile() || invocationStats.isSymbolicLink()) continue;
      const physical = await realpath(candidate);
      const stats = await lstat(physical);
      if (stats.isFile() && !stats.isSymbolicLink()) return { invocationPath: candidate, realpath: physical };
    } catch {
      // Try the packaged/source layout alternative.
    }
  }
  throw new RepositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Packaged flock guardian is unavailable");
}

async function validateLockDirectory(stateRoot: string): Promise<string> {
  assertAbsoluteNormalizedPath(stateRoot, "stateRoot");
  await assertPrivateDirectory(stateRoot);
  const directory = join(stateRoot, "locks");
  try {
    await assertPrivateDirectory(directory);
    for (const name of (await readdir(directory)).sort()) {
      if (!/^(?:[0-9a-f]{64}\.(?:lock|owner\.json)|[0-9a-f]{64}\.acquisition-[0-9a-f]{64}\.json)$/.test(name)) {
        throw new RepositoryGuardError("INVALID_LOCK_PATH", "Locks directory contains an unexpected entry");
      }
      const stats = await lstat(join(directory, name));
      if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) {
        throw new RepositoryGuardError("INVALID_LOCK_PATH", "Locks directory contains an unsafe entry");
      }
    }
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError) throw error;
    throw repositoryGuardError("INVALID_LOCK_PATH", "Locks directory is invalid", error);
  }
  return directory;
}

function stateFor(handle: WorktreeLockHandle): LockState {
  if (handle === null || typeof handle !== "object") throw new RepositoryGuardError("INVALID_ARGUMENT", "lock handle is invalid");
  const state = handleStates.get(handle as object);
  if (state === undefined) throw new RepositoryGuardError("INVALID_ARGUMENT", "lock handle was not created by this package instance");
  return state;
}

function assertProtocol(message: GuardianMessage, type: string): void {
  if (message.type !== type || message.protocol !== PROTOCOL) {
    throw new RepositoryGuardError("LOCK_LOST", "Guardian protocol identity is invalid");
  }
}

export interface AcquireWorktreeLockInput {
  readonly stateRoot: string;
  readonly repository: M3RepositoryIdentityDocument;
}

export function lockAcquisitionAuthority(handle: WorktreeLockHandle): M3LockAcquisitionDocument {
  return detachedFrozen(stateFor(handle).acquisition);
}

export async function acquireWorktreeLock(input: AcquireWorktreeLockInput): Promise<WorktreeLockHandle> {
  assertRecord(input, "acquireWorktreeLock input");
  assertExactKeys(input, ["stateRoot", "repository"], "acquireWorktreeLock input");
  assertDocumentValid("pi_gacw_repository_identity_v0", input.repository);
  const lockDirectory = await validateLockDirectory(input.stateRoot);
  const keyHex = digestHex(input.repository.worktree_key);
  const lockPath = join(lockDirectory, `${keyHex}.lock`);
  const markerPath = join(lockDirectory, `${keyHex}.owner.json`);
  const acquiredAt = new Date().toISOString();
  assertIsoTimestamp(acquiredAt, "acquiredAt");
  const acquisitionNonce = randomNonce();
  const [python, helper] = await Promise.all([resolveExecutableIdentity("python3"), guardianPath()]);
  const [pythonVersion, helperBytes] = await Promise.all([
    boundedExecutableVersion(python.invocationPath),
    readFile(helper.realpath),
  ]);
  const helperSha256 = sha256Bytes(helperBytes);
  const child = spawn(python.invocationPath, [
    helper.realpath,
    lockPath,
    markerPath,
    input.repository.worktree_key,
    input.repository.worktree_root,
    input.repository.git_common_dir,
    acquiredAt,
    String(process.pid),
    acquisitionNonce,
  ], {
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, LC_ALL: "C", LANG: "C", PYTHONIOENCODING: "utf-8" },
  });
  const channel = new GuardianChannel(child);
  const timeout = repositoryTestHooks().guardianReadyTimeoutMs ?? READY_TIMEOUT_MS;
  let ready: GuardianMessage;
  try {
    ready = await channel.waitFor((message) => message.type === "READY" || message.type === "ERROR", timeout, "LOCK_GUARDIAN_START_FAILED");
  } catch (error: unknown) {
    child.kill("SIGKILL");
    if (error instanceof RepositoryGuardError && error.code === "LOCK_LOST") {
      throw new RepositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Guardian exited before READY", {}, { cause: error });
    }
    throw error;
  }
  if (ready.type === "ERROR") {
    child.kill("SIGKILL");
    if (ready.protocol !== PROTOCOL) throw new RepositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Guardian error protocol is invalid");
    if (ready.code === "CONCURRENT_WRITER") throw new RepositoryGuardError("LOCK_BUSY", "A cooperating writer already owns this worktree lock");
    if (ready.code === "INVALID_LOCK_PATH") throw new RepositoryGuardError("INVALID_LOCK_PATH", "Guardian rejected the derived lock path");
    throw new RepositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Guardian rejected lock acquisition");
  }
  assertProtocol(ready, "READY");
  if (!Number.isInteger(ready.guardian_pid) || ready.guardian_pid !== child.pid || ready.acquisition_nonce !== acquisitionNonce) {
    child.kill("SIGKILL");
    throw new RepositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Guardian READY acquisition identity is invalid");
  }
  const readySha256 = sha256Canonical({
    protocol_version: PROTOCOL,
    guardian_pid: ready.guardian_pid,
    acquisition_nonce: acquisitionNonce,
  });
  const acquisition = identifyContractDocument("pi_gacw_lock_acquisition_v0", {
    schema_id: "pi_gacw_lock_acquisition_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    state_root: input.stateRoot,
    protocol_version: PROTOCOL,
    worktree_key: input.repository.worktree_key,
    worktree_root: input.repository.worktree_root,
    git_common_dir: input.repository.git_common_dir,
    lock_path: lockPath,
    owner_marker_path: markerPath,
    guardian_python_invocation_path: python.invocationPath,
    guardian_python_realpath: python.realpath,
    guardian_python_version: pythonVersion,
    guardian_helper_path: helper.invocationPath,
    guardian_helper_realpath: helper.realpath,
    guardian_helper_sha256: helperSha256,
    controller_pid: process.pid,
    guardian_pid: ready.guardian_pid,
    acquired_at: acquiredAt,
    acquisition_nonce: acquisitionNonce,
    guardian_ready_sha256: readySha256,
  }) as unknown as M3LockAcquisitionDocument;
  try {
    const acquisitionBytes = Buffer.byteLength(`${canonicalize(acquisition)}\n`, "utf8");
    const { assertLockAcquisitionCapacity } = await import("./storage.js");
    await assertLockAcquisitionCapacity(input.stateRoot, acquisitionBytes);
    await publishGlobalLockAcquisition(acquisition);
  } catch (error: unknown) {
    child.kill("SIGKILL");
    throw new RepositoryGuardError("LOCK_GUARDIAN_START_FAILED", "Lock acquisition producer root could not be published", {}, { cause: error });
  }
  const diagnostics = identifyContractDocument("pi_gacw_lock_diagnostic_v0", {
    schema_id: "pi_gacw_lock_diagnostic_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    lock_acquisition_content_sha256: acquisition.content_sha256,
    state_root: input.stateRoot,
    protocol_version: PROTOCOL,
    worktree_key: input.repository.worktree_key,
    worktree_root: input.repository.worktree_root,
    git_common_dir: input.repository.git_common_dir,
    lock_path: lockPath,
    owner_marker_path: markerPath,
    guardian_python_invocation_path: python.invocationPath,
    guardian_python_realpath: python.realpath,
    guardian_python_path: python.realpath,
    guardian_python_version: pythonVersion,
    guardian_helper_path: helper.invocationPath,
    guardian_helper_realpath: helper.realpath,
    guardian_helper_sha256: helperSha256,
    controller_pid: process.pid,
    guardian_pid: ready.guardian_pid,
    acquired_at: acquiredAt,
    acquisition_nonce: acquisitionNonce,
    guardian_ready_sha256: readySha256,
  }) as unknown as M3LockDiagnosticDocument;
  const state: LockState = {
    child,
    acquisition: detachedFrozen(acquisition),
    diagnostics: detachedFrozen(diagnostics),
    channel,
    lost: false,
    released: false,
    releaseRequested: false,
    healthInFlight: null,
  };
  child.once("close", () => {
    if (!state.releaseRequested) state.lost = true;
  });
  return new WorktreeLockHandleImpl(state);
}

export async function assertWorktreeLockHeld(handle: WorktreeLockHandle): Promise<M3LockDiagnosticDocument> {
  const state = stateFor(handle);
  if (state.lost || state.released || state.child.exitCode !== null || state.child.signalCode !== null) {
    state.lost = true;
    throw new RepositoryGuardError("LOCK_LOST", "Worktree lock guardian is not alive");
  }
  if (state.healthInFlight !== null) return state.healthInFlight;
  const operation = (async (): Promise<M3LockDiagnosticDocument> => {
    const nonce = randomNonce();
    const responsePromise = state.channel.waitFor(
      (message) => (message.type === "PONG" && message.nonce === nonce) || message.type === "ERROR",
      HEALTH_TIMEOUT_MS,
      "LOCK_LOST",
    );
    if (!state.child.stdin.write(`${JSON.stringify({ type: "PING", nonce })}\n`, "utf8")) {
      await new Promise<void>((resolveDrain, rejectDrain) => {
        state.child.stdin.once("drain", resolveDrain);
        state.child.stdin.once("error", rejectDrain);
      });
    }
    const response = await responsePromise;
    assertProtocol(response, "PONG");
    if (response.nonce !== nonce) throw new RepositoryGuardError("LOCK_LOST", "Guardian health nonce is invalid");
    return detachedFrozen(state.diagnostics);
  })();
  state.healthInFlight = operation;
  try {
    return await operation;
  } catch (error: unknown) {
    state.lost = true;
    throw error instanceof RepositoryGuardError
      ? error
      : repositoryGuardError("LOCK_LOST", "Guardian health check failed", error);
  } finally {
    state.healthInFlight = null;
  }
}

async function awaitExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolveExit, rejectExit) => {
    const timer = setTimeout(() => rejectExit(new RepositoryGuardError("LOCK_RELEASE_FAILED", "Guardian did not exit before the release deadline")), timeoutMs);
    timer.unref();
    child.once("close", () => { clearTimeout(timer); resolveExit(); });
  });
}

export async function releaseWorktreeLock(handle: WorktreeLockHandle): Promise<void> {
  const state = stateFor(handle);
  if (state.released) return;
  if (state.lost || state.child.exitCode !== null || state.child.signalCode !== null) {
    state.lost = true;
    throw new RepositoryGuardError("LOCK_LOST", "Worktree lock was lost before release");
  }
  state.releaseRequested = true;
  try {
    const responsePromise = state.channel.waitFor((message) => message.type === "RELEASED" || message.type === "ERROR", RELEASE_TIMEOUT_MS, "LOCK_RELEASE_FAILED");
    state.child.stdin.end(`${JSON.stringify({ type: "RELEASE" })}\n`, "utf8");
    const response = await responsePromise;
    assertProtocol(response, "RELEASED");
    await awaitExit(state.child, RELEASE_TIMEOUT_MS);
    state.released = true;
  } catch (error: unknown) {
    state.child.kill("SIGTERM");
    try { await awaitExit(state.child, 1_000); } catch { state.child.kill("SIGKILL"); }
    throw error instanceof RepositoryGuardError
      ? error
      : repositoryGuardError("LOCK_RELEASE_FAILED", "Guardian release failed", error);
  }
}

export function lockMatchesRepository(handle: WorktreeLockHandle, repository: M3RepositoryIdentityDocument): boolean {
  const state = stateFor(handle);
  return state.diagnostics.worktree_key === repository.worktree_key &&
    state.diagnostics.worktree_root === repository.worktree_root &&
    state.diagnostics.git_common_dir === repository.git_common_dir;
}
