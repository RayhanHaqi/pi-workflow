import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, open, readFile, readdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer } from "node:net";
import { promisify } from "node:util";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture, type RepositoryFixture } from "./repository-helpers.js";

const execFileAsync = promisify(execFile);
function code(error: unknown): unknown { return error instanceof ScopedToolGatewayError ? error.code : (error as { code?: unknown })?.code; }
function token(value: Awaited<ReturnType<typeof createM4Fixture>>): Sha256Digest { return value.gateway.acceptedState.content_sha256 as Sha256Digest; }
async function script(path: string, source: string): Promise<string> { await writeFile(path, source, { mode: 0o600 }); return path; }

interface CommandPaths { ready: string; go: string; timeoutReady: string; timeoutGo: string; forkPid: string; executable: string }
export async function commandSet(fixture: RepositoryFixture, temporaryRoot: string) {
  const paths: CommandPaths = { ready: join(temporaryRoot, "ready.fifo"), go: join(temporaryRoot, "go.fifo"), timeoutReady: join(temporaryRoot, "timeout-ready.fifo"), timeoutGo: join(temporaryRoot, "timeout-go.fifo"), forkPid: join(temporaryRoot, "fork.pid"), executable: join(fixture.root, "fixed-command") };
  for (const fifo of [paths.ready, paths.go, paths.timeoutReady, paths.timeoutGo]) await execFileAsync("mkfifo", [fifo]);
  await writeFile(paths.executable, "#!/usr/bin/python3\nprint('fixed')\n", { mode: 0o700 }); await chmod(paths.executable, 0o700);
  const environment = await script(join(temporaryRoot, "environment.py"), "import json,os\nprint(json.dumps(dict(sorted(os.environ.items())),separators=(',',':')))\n");
  const readAllowed = await script(join(temporaryRoot, "read-allowed.py"), `from pathlib import Path\nprint(Path(${JSON.stringify(join(fixture.repository, "src", "a.txt"))}).read_text(),end='')\n`);
  const readDenied = await script(join(temporaryRoot, "read-denied.py"), `from pathlib import Path\ntry:\n Path(${JSON.stringify(fixture.authorityPath)}).read_text()\n print('ESCAPED')\nexcept PermissionError:\n print('DENIED')\n`);
  const network = await script(join(temporaryRoot, "network.py"), "import ctypes,errno,socket,subprocess,sys\ntry:\n socket.socket()\n print('PARENT_ESCAPED')\nexcept PermissionError:\n print('PARENT_DENIED')\nchild=subprocess.run([sys.executable,__file__+'.child'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nprint('CHILD_DENIED' if child.returncode!=0 else 'CHILD_ESCAPED')\nlibc=ctypes.CDLL(None,use_errno=True); result=libc.syscall(425,0,0)\nprint('IORING_DENIED' if result==-1 and ctypes.get_errno()==errno.EPERM else 'IORING_ESCAPED')\n");
  await script(`${network}.child`, "import socket\nsocket.socket()\n");
  const metadataDenied = await script(join(temporaryRoot, "metadata-denied.py"), `import os\nfor operation in (lambda:os.chmod(${JSON.stringify(fixture.authorityPath)},0o777),lambda:os.utime(${JSON.stringify(fixture.authorityPath)},None)):\n try:\n  operation();print('ESCAPED')\n except PermissionError:\n  print('DENIED')\n`);
  const group = await script(join(temporaryRoot, "process-group.py"), "import subprocess,sys\nchild=subprocess.run([sys.executable,__file__+'.child'],capture_output=True,text=True,check=True)\nprint(child.stdout,end='')\n");
  const groupChild = await script(`${group}.child`, "import os\ntry:\n os.setsid();print('ESCAPED')\nexcept PermissionError:\n print('DENIED')\n");
  const task = await script(join(temporaryRoot, "task.py"), `from pathlib import Path\nPath(${JSON.stringify(fixture.trackedPath)}).write_text('task command\\n')\n`);
  const generated = await script(join(temporaryRoot, "generated-output.py"), `from pathlib import Path\nPath(${JSON.stringify(join(fixture.repository, "generated", "out.txt"))}).write_text('generated\\n')\n`);
  const overflow = await script(join(temporaryRoot, "overflow.py"), "import sys\nsys.stdout.buffer.write(b'x'*100000)\nsys.stdout.flush()\n");
  const timeout = await script(join(temporaryRoot, "timeout.py"), `import os\nfd=os.open(${JSON.stringify(paths.timeoutReady)},os.O_WRONLY);os.write(fd,b'1');os.close(fd)\nfd=os.open(${JSON.stringify(paths.timeoutGo)},os.O_RDONLY);os.read(fd,1)\n`);
  const signalled = await script(join(temporaryRoot, "self-terminate-case.py"), "import ctypes\nctypes.string_at(0)\n");
  const nonzero = await script(join(temporaryRoot, "nonzero.py"), "raise SystemExit(7)\n");
  const fork = await script(join(temporaryRoot, "fork.py"), `import subprocess,sys\nfrom pathlib import Path\np=subprocess.Popen([sys.executable,__file__+'.child'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nPath(${JSON.stringify(paths.forkPid)}).write_text(str(p.pid))\nprint('leader complete')\n`);
  const forkChild = await script(`${fork}.child`, "import signal\nsignal.pause()\n");
  const unexpected = await script(join(temporaryRoot, "unexpected.py"), `import os\nfrom pathlib import Path\nPath(${JSON.stringify(fixture.trackedPath)}).write_text('expected task path\\n')\nfd=os.open(${JSON.stringify(paths.ready)},os.O_WRONLY);os.write(fd,b'1');os.close(fd)\nfd=os.open(${JSON.stringify(paths.go)},os.O_RDONLY);os.read(fd,1);os.close(fd)\n`);
  const root = { repositoryRoot: fixture.repository };
  return { paths, commands: [
    await commandSpecification("inspect-fixed-executable", "INSPECTION", paths.executable, [], root),
    await commandSpecification("inspect-environment", "INSPECTION", "/usr/bin/python3", [environment], root),
    await commandSpecification("inspect-read", "INSPECTION", "/usr/bin/python3", [readAllowed], { ...root, readPaths: [{ path: "src", kind: "PREFIX" }] }),
    await commandSpecification("inspect-denied", "INSPECTION", "/usr/bin/python3", [readDenied], root),
    await commandSpecification("inspect-network", "INSPECTION", "/usr/bin/python3", [network], { ...root, executionInputs: [`${network}.child`] }),
    await commandSpecification("inspect-metadata-denied", "INSPECTION", "/usr/bin/python3", [metadataDenied], root),
    await commandSpecification("inspect-process-group", "INSPECTION", "/usr/bin/python3", [group], { ...root, executionInputs: [groupChild] }),
    await commandSpecification("task-write", "TASK", "/usr/bin/python3", [task], { ...root, writePaths: [{ path: "tracked.txt", kind: "EXACT" }], sideEffect: "EXACT_PATHS", claimedPaths: ["tracked.txt"] }),
    await commandSpecification("verify-generated", "VERIFICATION", "/usr/bin/python3", [generated], { ...root, writePaths: [{ path: "generated", kind: "PREFIX" }], sideEffect: "GENERATED_ONLY", claimedPaths: ["generated/out.txt"] }),
    await commandSpecification("inspect-overflow", "INSPECTION", "/usr/bin/python3", [overflow], { ...root, stdoutLimit: 16 }),
    await commandSpecification("inspect-timeout", "INSPECTION", "/usr/bin/python3", [timeout], { ...root, timeoutMs: 5_000 }),
    await commandSpecification("inspect-signal", "INSPECTION", "/usr/bin/python3", [signalled], root),
    await commandSpecification("inspect-nonzero", "INSPECTION", "/usr/bin/python3", [nonzero], root),
    await commandSpecification("inspect-fork", "INSPECTION", "/usr/bin/python3", [fork], { ...root, executionInputs: [forkChild] }),
    await commandSpecification("task-unexpected", "TASK", "/usr/bin/python3", [unexpected], { ...root, writePaths: [{ path: "tracked.txt", kind: "EXACT" }], sideEffect: "EXACT_PATHS", claimedPaths: ["tracked.txt"] }),
    await commandSpecification("verify", "VERIFICATION", "/usr/bin/printf", ["verified"], root),
  ] };
}

test("M4 gateway blocks when secure filesystem primitives are unavailable", async () => {
  setSecureFilesystemTestHooks({ forceCapabilityUnavailable: true });
  try { await assert.rejects(createM4Fixture(), (error: unknown) => code(error) === "SECURE_WRITE_PRIMITIVE_UNAVAILABLE"); }
  finally { resetSecureFilesystemTestHooks(); }
});

test("M4 gateway blocks when the command sandbox is unavailable", async () => {
  setSecureFilesystemTestHooks({ forceSandboxUnavailable: true });
  try { await assert.rejects(createM4Fixture(), (error: unknown) => code(error) === "COMMAND_SANDBOX_UNAVAILABLE"); }
  finally { resetSecureFilesystemTestHooks(); }
});

test("M4 gateway separately blocks when network denial is unavailable", async () => {
  setSecureFilesystemTestHooks({ forceNetworkUnavailable: true });
  try { await assert.rejects(createM4Fixture(), (error: unknown) => code(error) === "NETWORK_SANDBOX_UNAVAILABLE"); }
  finally { resetSecureFilesystemTestHooks(); }
});

test("M4 frozen command gateway enforces catalog, sandbox, bounds, and deltas", async (t) => {
  let paths!: CommandPaths;
  const value = await createM4Fixture(async (fixture, temporaryRoot) => { const selected = await commandSet(fixture, temporaryRoot); paths = selected.paths; return selected.commands; });
  try {
    await t.test("caller selects only a known ID and matching class", async () => {
      await assert.rejects(value.gateway.run_inspection_command({ commandId: "missing", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "UNKNOWN_COMMAND_ID");
      await assert.rejects(value.gateway.run_task_command({ commandId: "verify", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_CLASS_MISMATCH");
    });
    await t.test("gateway detaches mutable caller command-catalog arrays", async () => {
      const command = value.catalog.commands.find((entry) => entry.command_id === "inspect-environment")!;
      (command.argv as string[])[1] = "/caller-mutated-script"; assert.equal(command.argv[1], "/caller-mutated-script");
      const result = await value.gateway.run_inspection_command({ commandId: "inspect-environment", stateTokenContentSha256: token(value) });
      const environment = JSON.parse(Buffer.from(result.stdoutBase64, "base64").toString()) as Record<string, string>; assert.equal(environment["HOME"], value.temporaryRoot);
    });
    await t.test("sandbox interpreter identity is rechecked against PATH drift", async () => {
      const replacementPython = join(value.temporaryRoot, "python3"); await writeFile(replacementPython, "#!/bin/sh\nexit 99\n", { mode: 0o700 }); await chmod(replacementPython, 0o700);
      const originalPath = process.env["PATH"];
      try {
        process.env["PATH"] = `${value.temporaryRoot}:${originalPath ?? ""}`;
        await assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-environment", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_SPEC_MISMATCH");
      } finally { if (originalPath === undefined) delete process.env["PATH"]; else process.env["PATH"] = originalPath; }
    });
    await t.test("synchronized sandbox path swap is rejected by inode authority", async () => {
      const control = join(value.temporaryRoot, "sandbox-race.sock"); const original = join(value.fixture.repository, "src"); const moved = join(value.fixture.root, "moved-src");
      const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => {
        data += chunk.toString(); if (!data.includes("\n")) return; await rename(original, moved); await mkdir(original); await writeFile(join(original, "a.txt"), "Alpha needle\nsecond line\n"); await writeFile(join(original, "b.txt"), "beta NEEDLE\n"); connection.end("1");
      }); });
      await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject));
      setSecureFilesystemTestHooks({ sandboxCheckpointSocket: control, sandboxCheckpointStage: "BEFORE_LANDLOCK" });
      try {
        await assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-read", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_SPEC_MISMATCH");
      } finally {
        resetSecureFilesystemTestHooks(); await rm(original, { recursive: true, force: true }); await rename(moved, original); await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
    await t.test("executable content identity is rechecked immediately before sandbox execution", async () => {
      await writeFile(paths.executable, "#!/usr/bin/python3\nprint('changed')\n", { mode: 0o700 });
      await assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-fixed-executable", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_SPEC_MISMATCH");
    });
    await t.test("sanitized environment has no inherited secret or loader controls", async () => {
      const result = await value.gateway.run_inspection_command({ commandId: "inspect-environment", stateTokenContentSha256: token(value) });
      const environment = JSON.parse(Buffer.from(result.stdoutBase64, "base64").toString()) as Record<string, string>;
      assert.deepEqual(Object.keys(environment).sort(), ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"]);
      assert.equal(environment["HOME"], value.temporaryRoot); assert.equal(result.record.outcome, "PASS");
    });
    await t.test("declared read works and undeclared repository read is denied", async () => {
      const allowed = await value.gateway.run_inspection_command({ commandId: "inspect-read", stateTokenContentSha256: token(value) });
      assert.match(Buffer.from(allowed.stdoutBase64, "base64").toString(), /Alpha needle/);
      const denied = await value.gateway.run_inspection_command({ commandId: "inspect-denied", stateTokenContentSha256: token(value) });
      assert.equal(Buffer.from(denied.stdoutBase64, "base64").toString().trim(), "DENIED");
    });
    await t.test("network syscalls are denied in the command and descendants", async () => {
      const result = await value.gateway.run_inspection_command({ commandId: "inspect-network", stateTokenContentSha256: token(value) });
      assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "PARENT_DENIED\nCHILD_DENIED\nIORING_DENIED\n");
    });
    await t.test("read-only commands cannot mutate modes or timestamps through unmediated syscalls", async () => {
      const initial = await stat(value.fixture.authorityPath);
      const result = await value.gateway.run_inspection_command({ commandId: "inspect-metadata-denied", stateTokenContentSha256: token(value) });
      assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "DENIED\nDENIED\n"); const after = await stat(value.fixture.authorityPath);
      assert.equal(after.mode & 0o777, initial.mode & 0o777); assert.equal(after.mtimeMs, initial.mtimeMs);
    });
    await t.test("descendants cannot escape process-group cleanup authority", async () => {
      const result = await value.gateway.run_inspection_command({ commandId: "inspect-process-group", stateTokenContentSha256: token(value) });
      assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "DENIED\n");
    });
    await t.test("task command can mutate only its exact frozen claim", async () => {
      const result = await value.gateway.run_task_command({ commandId: "task-write", stateTokenContentSha256: token(value) });
      assert.equal(await readFile(value.fixture.trackedPath, "utf8"), "task command\n"); assert.deepEqual(result.record.repository_delta.map((entry) => entry.path), ["tracked.txt"]);
    });
    await t.test("verification commands support read-only and exact claimed generated output", async () => {
      const result = await value.gateway.run_verification_command({ commandId: "verify", stateTokenContentSha256: token(value) });
      assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "verified");
      const generated = await value.gateway.run_verification_command({ commandId: "verify-generated", stateTokenContentSha256: token(value) });
      assert.equal(await readFile(join(value.fixture.repository, "generated", "out.txt"), "utf8"), "generated\n"); assert.deepEqual(generated.record.repository_delta.map((entry) => entry.path), ["generated/out.txt", "tracked.txt"]);
    });
    await t.test("stdout overflow is killed and recorded without returning bytes", async () => {
      await assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-overflow", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_OUTPUT_LIMIT");
    });
    await t.test("deadline kills a process blocked after an explicit FIFO checkpoint", async () => {
      const outcome = assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-timeout", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_TIMEOUT");
      const ready = await open(paths.timeoutReady, "r"); const byte = Buffer.alloc(1); await ready.read(byte, 0, 1, null); await ready.close(); assert.equal(byte.toString(), "1"); await outcome;
    });
    await t.test("signal and unexpected exit status remain distinct", async () => {
      await assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-signal", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_SIGNALLED");
      await assert.rejects(value.gateway.run_inspection_command({ commandId: "inspect-nonzero", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_EXIT_CODE_UNEXPECTED");
    });
    await t.test("leader exit kills an otherwise persistent descendant process group", async () => {
      const result = await value.gateway.run_inspection_command({ commandId: "inspect-fork", stateTokenContentSha256: token(value) }); assert.equal(result.record.outcome, "PASS");
      const pid = Number(await readFile(paths.forkPid, "utf8")); let state: string | null = null;
      try { state = (await readFile(`/proc/${pid}/stat`, "utf8")).split(" ")[2] ?? null; } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      assert.ok(state === null || state === "Z", `descendant remained live in state ${state}`);
    });
    await t.test("synchronized undeclared delta fails postflight", async () => {
      const execution = value.gateway.run_task_command({ commandId: "task-unexpected", stateTokenContentSha256: token(value) });
      const ready = await open(paths.ready, "r"); const byte = Buffer.alloc(1); await ready.read(byte, 0, 1, null); await ready.close(); assert.equal(byte.toString(), "1");
      await writeFile(join(value.fixture.repository, "src", "a.txt"), "attacker delta\n");
      const go = await open(paths.go, "w"); await go.write(Buffer.from("1")); await go.close();
      await assert.rejects(execution, (error: unknown) => code(error) === "COMMAND_UNEXPECTED_REPOSITORY_DELTA");
    });
    await t.test("immutable command results exist for pass and blocked executions", async () => {
      const directory = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "command-results"); const names = await readdir(directory);
      assert.ok(names.length >= 10); const records = await Promise.all(names.map(async (name) => JSON.parse(await readFile(join(directory, name), "utf8")) as { outcome: string; failure_code: string | null }));
      assert.ok(records.some((record) => record.outcome === "PASS" && record.failure_code === null)); assert.ok(records.some((record) => record.outcome === "BLOCKED" && record.failure_code !== null));
    });
  } finally {
    await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture);
  }
});
