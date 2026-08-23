import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, realpath, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import type { Readable } from "node:stream";

import type { M3RepositoryIdentityDocument, M4CommandSpecification, M4SandboxCapabilityDocument } from "../schemas/index.js";
import { assertDocumentValid } from "../schemas/index.js";
import { COMMAND_SANDBOX_PROTOCOL, resolveSandboxHelper } from "../secure-fs/sandbox-helper.js";
import { secureFilesystemTestHooks } from "../secure-fs/test-hooks.js";
import { ScopedToolGatewayError, type ScopedToolGatewayErrorCode } from "./errors.js";

export interface SandboxExecutionOutcome {
  readonly startedAt: string;
  readonly endedAt: string;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutObservedBytes: number;
  readonly stderrObservedBytes: number;
  readonly stdoutObservedDigest: `sha256:${string}` | null;
  readonly stderrObservedDigest: `sha256:${string}` | null;
  readonly stdoutOverflowed: boolean;
  readonly stderrOverflowed: boolean;
  readonly stdoutStreamComplete: boolean;
  readonly stderrStreamComplete: boolean;
  readonly setup: Readonly<{ landlockAbi: number; noNewPrivs: true; networkDenied: true }> | null;
  readonly failure: "COMMAND_TIMEOUT" | "COMMAND_OUTPUT_LIMIT" | "COMMAND_SIGNALLED" | null;
}

function absoluteRepositoryPath(repository: M3RepositoryIdentityDocument, path: string): string {
  return join(repository.worktree_root, path);
}

async function systemReadRoots(): Promise<readonly string[]> {
  const roots = new Set<string>();
  for (const path of ["/usr", "/lib", "/lib64"]) {
    try { roots.add(await realpath(path)); } catch { /* unavailable compatibility root */ }
  }
  return [...roots].sort();
}

async function assertSandboxRuleType(path: string, kind: "EXACT" | "PREFIX"): Promise<void> {
  const stats = await lstat(path);
  if ((kind === "EXACT" && !stats.isFile()) || (kind === "PREFIX" && !stats.isDirectory()) || stats.isSymbolicLink() || await realpath(path) !== path) {
    throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Sandbox path-rule kind differs from its physical type");
  }
}

async function sandboxPathIdentity(path: string): Promise<{ readonly path: string; readonly device: number; readonly inode: number }> {
  const stats = await lstat(path);
  if ((!stats.isFile() && !stats.isDirectory() && !(path === "/dev/null" && stats.isCharacterDevice())) || stats.isSymbolicLink() || await realpath(path) !== path) {
    throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Sandbox authority path is not a real file or directory");
  }
  return Object.freeze({ path, device: stats.dev, inode: stats.ino });
}

function setupError(code: unknown, detail: unknown): ScopedToolGatewayError {
  const accepted = new Set<ScopedToolGatewayErrorCode>(["COMMAND_SANDBOX_UNAVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE", "COMMAND_SPEC_MISMATCH", "HARDLINK_WRITE_SCOPE_UNSAFE", "COMMAND_CWD_IDENTITY_DRIFT", "EXECUTION_INPUT_DRIFT"]);
  const selected = typeof code === "string" && accepted.has(code as ScopedToolGatewayErrorCode) ? code as ScopedToolGatewayErrorCode : "COMMAND_SANDBOX_UNAVAILABLE";
  return new ScopedToolGatewayError(selected, typeof detail === "string" ? detail : "Sandbox setup failed");
}

interface PreparedExecutionInputs {
  readonly argv: readonly string[];
  readonly readRoot: string | null;
  cleanup(): Promise<void>;
}

async function prepareExecutionInputs(specification: M4CommandSpecification, temporaryRoot: string): Promise<PreparedExecutionInputs> {
  if (specification.execution_inputs.length === 0) return { argv: specification.argv, readRoot: null, cleanup: async () => {} };
  if (specification.execution_input_layout !== "FLAT") {
    const layout = specification.execution_input_layout;
    const [stats, physical] = await Promise.all([lstat(layout.source_root), realpath(layout.source_root)]);
    if (!stats.isDirectory() || stats.isSymbolicLink() || physical !== layout.source_root || stats.dev !== layout.device || stats.ino !== layout.inode) {
      throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package execution-input root changed before immutable capture");
    }
  }
  const root = await mkdtemp(join(dirname(temporaryRoot), ".m4exec-")); await chmod(root, 0o700);
  const replacements = new Map<string, string>(); const destinations = new Set<string>(); const directories = new Set<string>([root]);
  const cleanup = async (): Promise<void> => {
    for (const directory of [...directories].sort((left, right) => left.length - right.length)) {
      try { await chmod(directory, 0o700); } catch { /* best-effort permission restoration before deterministic removal */ }
    }
    await rm(root, { recursive: true, force: true });
  };
  try {
    for (const input of specification.execution_inputs) {
      const capturePath = specification.execution_input_layout === "FLAT" ? basename(input.path) : input.capture_path!;
      const destination = join(root, capturePath);
      if (destinations.has(destination)) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input capture paths collide");
      destinations.add(destination);
      const destinationDirectory = dirname(destination);
      await mkdir(destinationDirectory, { recursive: true, mode: 0o700 });
      for (let cursor = destinationDirectory; cursor !== dirname(root) && cursor.startsWith(root); cursor = dirname(cursor)) directories.add(cursor);
      const source = await open(input.path, constants.O_RDONLY | constants.O_NOFOLLOW);
      let bytes: Buffer;
      try {
        const before = await source.stat(); bytes = await source.readFile(); const after = await source.stat();
        if (!before.isFile() || before.dev !== input.device || before.ino !== input.inode || before.size !== input.size || (before.mode & 0o7777) !== input.mode ||
            before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mode !== after.mode || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs ||
            `sha256:${createHash("sha256").update(bytes).digest("hex")}` !== input.digest) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution input changed before immutable capture");
      } finally { await source.close(); }
      const target = await open(destination, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      try { await target.writeFile(bytes); await target.sync(); } finally { await target.close(); }
      await chmod(destination, input.mode & 0o555);
      replacements.set(input.path, destination);
    }
    for (const directoryPath of [...directories].sort((left, right) => right.length - left.length)) {
      const directory = await open(directoryPath, constants.O_RDONLY | constants.O_DIRECTORY); try { await directory.sync(); } finally { await directory.close(); }
      await chmod(directoryPath, 0o500);
    }
    return { argv: specification.argv.map((value) => replacements.get(value) ?? value), readRoot: root, cleanup };
  } catch (error: unknown) {
    await cleanup();
    if (error instanceof ScopedToolGatewayError) throw error;
    throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution input is absent or was replaced", {}, { cause: error });
  }
}

export async function runSandboxedCommand(
  repository: M3RepositoryIdentityDocument,
  temporaryRoot: string,
  capability: M4SandboxCapabilityDocument,
  specification: M4CommandSpecification,
): Promise<SandboxExecutionOutcome> {
  assertDocumentValid("pi_gacw_sandbox_capability_v0", capability);
  if (capability.result !== "COMMAND_SANDBOX_AVAILABLE" || capability.network_result !== "NETWORK_SANDBOX_AVAILABLE" ||
      !capability.filesystem_restrictions || !capability.child_inheritance || !capability.no_new_privs || !capability.network_denial) {
    throw new ScopedToolGatewayError("COMMAND_SANDBOX_UNAVAILABLE", "Mandatory command sandbox capability is unavailable");
  }
  const helper = await resolveSandboxHelper();
  if (specification.executable_realpath === temporaryRoot || specification.executable_realpath.startsWith(`${temporaryRoot}/`) ||
      specification.executable_realpath === repository.worktree_root || specification.executable_realpath.startsWith(`${repository.worktree_root}/`)) {
    throw new ScopedToolGatewayError("COMMAND_FORBIDDEN", "Frozen command executable cannot reside in a command-writable or target-repository root");
  }
  if (helper.invocationPath !== capability.helper_invocation_path || helper.realpath !== capability.helper_realpath || helper.sha256 !== capability.helper_sha256 ||
      helper.python.invocationPath !== capability.python_invocation_path || helper.python.realpath !== capability.python_realpath || helper.pythonSha256 !== capability.python_sha256) {
    throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command sandbox helper identity changed");
  }
  const tempStats = await lstat(temporaryRoot);
  if (!tempStats.isDirectory() || tempStats.isSymbolicLink()) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Controller temporary root is unsafe");
  const cwd = specification.cwd === "REPOSITORY_ROOT" ? repository.worktree_root : absoluteRepositoryPath(repository, specification.cwd);
  const cwdStats = await lstat(cwd); const cwdPhysical = await realpath(cwd);
  if (!cwdStats.isDirectory() || cwdStats.isSymbolicLink() || cwdPhysical !== cwd || cwdPhysical !== specification.cwd_realpath ||
      cwdStats.dev !== specification.cwd_device || cwdStats.ino !== specification.cwd_inode) {
    throw new ScopedToolGatewayError("COMMAND_CWD_IDENTITY_DRIFT", "Command cwd differs from its frozen physical authority");
  }
  const prepared = await prepareExecutionInputs(specification, temporaryRoot);
  const executableHandle = await open(specification.executable_realpath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
  const executableBefore = await executableHandle.stat(); const executableBytes = await executableHandle.readFile(); const executableAfter = await executableHandle.stat();
  const invocationPhysical = await realpath(specification.executable_invocation_path); const executablePathStats = await lstat(specification.executable_realpath);
  if (!executableBefore.isFile() || invocationPhysical !== specification.executable_realpath || executableBefore.dev !== specification.executable_device ||
      executableBefore.ino !== specification.executable_inode || (executableBefore.mode & 0o7777) !== specification.executable_mode || executableBefore.size !== specification.executable_size ||
      executableBefore.dev !== executableAfter.dev || executableBefore.ino !== executableAfter.ino || executableBefore.mode !== executableAfter.mode || executableBefore.size !== executableAfter.size ||
      executableBefore.mtimeMs !== executableAfter.mtimeMs || executableBefore.ctimeMs !== executableAfter.ctimeMs || executablePathStats.dev !== executableBefore.dev ||
      executablePathStats.ino !== executableBefore.ino || `sha256:${createHash("sha256").update(executableBytes).digest("hex")}` !== specification.executable_sha256) {
    throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Executable changed before held-FD capture");
  }
  const readPaths = new Set<string>(await systemReadRoots());
  const directoryReadPaths = new Set<string>();
  readPaths.add("/dev/null");
  readPaths.add(await realpath(specification.executable_realpath));
  for (const rule of specification.read_paths) {
    const path = absoluteRepositoryPath(repository, rule.path); await assertSandboxRuleType(path, rule.kind); readPaths.add(path);
    for (let ancestor = dirname(path); ancestor === repository.worktree_root || ancestor.startsWith(`${repository.worktree_root}/`); ancestor = dirname(ancestor)) {
      directoryReadPaths.add(ancestor);
      if (ancestor === repository.worktree_root) break;
    }
  }
  readPaths.add(temporaryRoot);
  if (prepared.readRoot !== null) readPaths.add(prepared.readRoot);
  const writeRules = [] as Array<{ path: string; kind: "EXACT" | "PREFIX" }>;
  for (const rule of specification.write_paths) {
    const path = absoluteRepositoryPath(repository, rule.path); await assertSandboxRuleType(path, rule.kind);
    const stats = await lstat(path); if (rule.kind === "EXACT" && stats.isFile() && stats.nlink > 1) {
      throw new ScopedToolGatewayError("HARDLINK_WRITE_SCOPE_UNSAFE", "Exact command write target is multiply linked");
    }
    writeRules.push({ path, kind: rule.kind });
  }
  writeRules.push({ path: temporaryRoot, kind: "PREFIX" });
  const authorityPaths = [...new Set([...readPaths, ...directoryReadPaths, ...writeRules.map((rule) => rule.path)])].sort();
  const pathIdentities = await Promise.all(authorityPaths.map(sandboxPathIdentity));
  const environment: Record<string, string> = { LC_ALL: "C", LANG: "C", PATH: "/usr/bin:/bin", HOME: temporaryRoot, TMPDIR: temporaryRoot };
  for (const entry of specification.environment) environment[entry.key] = entry.value;
  const request = {
    protocol: COMMAND_SANDBOX_PROTOCOL,
    operation: "EXECUTE",
    executable_invocation_path: specification.executable_invocation_path,
    executable_realpath: specification.executable_realpath,
    executable_identity: { device: specification.executable_device, inode: specification.executable_inode, mode: specification.executable_mode, size: specification.executable_size },
    executable_sha256: specification.executable_sha256,
    execution_inputs: specification.execution_inputs.map(({ capture_path: _capturePath, ...input }) => input),
    argv: prepared.argv,
    cwd,
    cwd_identity: { device: specification.cwd_device, inode: specification.cwd_inode },
    environment,
    read_paths: [...readPaths].sort(),
    directory_read_paths: [...directoryReadPaths].sort(),
    write_rules: writeRules,
    path_identities: pathIdentities,
    network_policy: specification.network_policy,
  };
  const hooks = secureFilesystemTestHooks(); const wireRequest: Record<string, unknown> = { ...request };
  if (hooks.sandboxCheckpointSocket !== undefined) wireRequest["_checkpoint_socket"] = hooks.sandboxCheckpointSocket;
  if (hooks.sandboxCheckpointStage !== undefined) wireRequest["_checkpoint_stage"] = hooks.sandboxCheckpointStage;
  const input = Buffer.from(JSON.stringify(wireRequest), "utf8");
  if (input.byteLength > 1_048_576) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Sandbox execution request exceeds its protocol bound");
  const startedAt = new Date().toISOString();
  return await new Promise<SandboxExecutionOutcome>((resolveOutcome, rejectOutcome) => {
    const child = spawn(helper.python.invocationPath, [helper.invocationPath], {
      shell: false,
      cwd: temporaryRoot,
      env: { LC_ALL: "C", LANG: "C", PYTHONHASHSEED: "0" },
      // The helper creates its own process group, but must inherit the productive
      // invocation session so the external lifecycle owner can terminate it.
      stdio: ["pipe", "pipe", "pipe", "pipe", executableHandle.fd],
    });
    const stdout: Buffer[] = []; const stderr: Buffer[] = []; let stdoutBytes = 0; let stderrBytes = 0;
    let stdoutObservedBytes = 0; let stderrObservedBytes = 0; const stdoutObservedHash = createHash("sha256"); const stderrObservedHash = createHash("sha256");
    let stdoutOverflowed = false; let stderrOverflowed = false; let outputExceeded = false; let timedOut = false; let setup: SandboxExecutionOutcome["setup"] = null; let setupErrorValue: ScopedToolGatewayError | null = null;
    let setupBytes = 0; let setupBuffer = Buffer.alloc(0); let closed = false;
    const killGroup = (): void => {
      if (child.pid === undefined) return;
      try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
    };
    const timer = setTimeout(() => { timedOut = true; killGroup(); }, specification.timeout_ms); timer.unref();
    const chunks = (chunk: Buffer): readonly Buffer[] => {
      const size = hooks.sandboxOutputChunkBytes;
      if (size === undefined || !Number.isSafeInteger(size) || size <= 0) return [chunk];
      const result: Buffer[] = []; for (let offset = 0; offset < chunk.byteLength; offset += size) result.push(chunk.subarray(offset, Math.min(offset + size, chunk.byteLength)));
      return result;
    };
    child.stdout!.on("data", (wire: Buffer) => { for (const chunk of chunks(wire)) {
      stdoutObservedBytes += chunk.byteLength; stdoutObservedHash.update(chunk);
      const capture = Math.min(chunk.byteLength, Math.max(0, specification.stdout_limit - stdoutBytes));
      if (capture > 0) { stdout.push(Buffer.from(chunk.subarray(0, capture))); stdoutBytes += capture; }
      if (stdoutObservedBytes > specification.stdout_limit) { stdoutOverflowed = true; outputExceeded = true; killGroup(); }
    } });
    child.stderr!.on("data", (wire: Buffer) => { for (const chunk of chunks(wire)) {
      stderrObservedBytes += chunk.byteLength; stderrObservedHash.update(chunk);
      const capture = Math.min(chunk.byteLength, Math.max(0, specification.stderr_limit - stderrBytes));
      if (capture > 0) { stderr.push(Buffer.from(chunk.subarray(0, capture))); stderrBytes += capture; }
      if (stderrObservedBytes > specification.stderr_limit) { stderrOverflowed = true; outputExceeded = true; killGroup(); }
    } });
    const status = child.stdio[3] as Readable;
    status.on("data", (chunk: Buffer) => {
      setupBytes += chunk.byteLength;
      if (setupBytes > 64 * 1024) { setupErrorValue = new ScopedToolGatewayError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox setup output exceeded its bound"); killGroup(); return; }
      setupBuffer = Buffer.concat([setupBuffer, chunk]);
    });
    status.once("end", () => {
      if (setupBuffer.byteLength === 0) return;
      try {
        const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(setupBuffer));
        if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("shape");
        const record = value as Record<string, unknown>;
        if (record["protocol"] !== COMMAND_SANDBOX_PROTOCOL) throw new Error("protocol");
        if (record["ok"] === false) { setupErrorValue = setupError(record["code"], record["detail"]); return; }
        if (record["ok"] !== true || !Number.isSafeInteger(record["landlock_abi"]) || record["no_new_privs"] !== true || record["network_denied"] !== true) throw new Error("authority");
        setup = Object.freeze({ landlockAbi: record["landlock_abi"] as number, noNewPrivs: true, networkDenied: true });
      } catch (error: unknown) { setupErrorValue = new ScopedToolGatewayError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox setup response is malformed", {}, { cause: error }); }
    });
    child.once("error", (error: unknown) => {
      if (closed) return; closed = true; clearTimeout(timer);
      rejectOutcome(new ScopedToolGatewayError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox helper could not start", {}, { cause: error }));
    });
    // A command may fork and let its leader exit while descendants retain the
    // output pipes. Tear down the entire isolated process group at leader exit.
    child.once("exit", () => { killGroup(); });
    child.once("close", (code, signal) => {
      if (closed) return; closed = true; clearTimeout(timer);
      if (setupErrorValue !== null) { rejectOutcome(setupErrorValue); return; }
      if (setup === null) { rejectOutcome(new ScopedToolGatewayError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox did not confirm setup")); return; }
      const failure = timedOut ? "COMMAND_TIMEOUT" : outputExceeded ? "COMMAND_OUTPUT_LIMIT" : signal !== null ? "COMMAND_SIGNALLED" : null;
      const streamsComplete = !timedOut && !outputExceeded;
      resolveOutcome(Object.freeze({ startedAt, endedAt: new Date().toISOString(), exitCode: code, signal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), stdoutBytes, stderrBytes,
        stdoutObservedBytes, stderrObservedBytes, stdoutObservedDigest: streamsComplete ? `sha256:${stdoutObservedHash.digest("hex")}` : null,
        stderrObservedDigest: streamsComplete ? `sha256:${stderrObservedHash.digest("hex")}` : null,
        stdoutOverflowed, stderrOverflowed, stdoutStreamComplete: streamsComplete, stderrStreamComplete: streamsComplete, setup, failure }));
    });
    child.stdin!.on("error", () => { /* close/error handlers provide the authoritative outcome */ });
    child.stdin!.end(input);
  }); } finally { await executableHandle.close(); await prepared.cleanup(); }
}

export async function ensureControllerTemporaryRoot(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o700) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Controller temporary root must be a real 0700 directory");
}
