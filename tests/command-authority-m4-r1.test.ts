import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, link, mkdir, open, readFile, readdir, rename, rm, stat, symlink, unlink, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { createServer } from "node:net";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import type { M4CommandResultDocument, M4CommandSpecification } from "../src/schemas/index.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { git, removeRepositoryFixture, type RepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof ScopedToolGatewayError ? error.code : (error as { code?: unknown }).code; }
async function cleanup(value: Awaited<ReturnType<typeof createM4Fixture>>): Promise<void> { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
async function py(path: string, source: string): Promise<string> { await writeFile(path, source, { mode: 0o600 }); return path; }
function token(value: Awaited<ReturnType<typeof createM4Fixture>>): Sha256Digest { return value.gateway.acceptedState.content_sha256 as Sha256Digest; }
async function commandResults(value: Awaited<ReturnType<typeof createM4Fixture>>, commandId: string): Promise<M4CommandResultDocument[]> {
  const root = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "command-results");
  return Promise.all((await readdir(root)).map(async (name) => JSON.parse(await readFile(join(root, name), "utf8")) as M4CommandResultDocument))
    .then((records) => records.filter((record) => record.command_id === commandId));
}
async function server(path: string, action: () => Promise<void>) {
  const value = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => { data += chunk.toString(); if (!data.includes("\n")) return; await action(); connection.end("1"); }); });
  await new Promise<void>((resolve, reject) => value.listen(path, resolve).once("error", reject)); return value;
}

async function writer(fixture: RepositoryFixture, temporaryRoot: string, source: string, id = "write") {
  const script = await py(join(temporaryRoot, `${id}.py`), source);
  return commandSpecification(id, "VERIFICATION", "/usr/bin/python3", [script], { repositoryRoot: fixture.repository,
    writePaths: [{ path: "generated", kind: "PREFIX" }], sideEffect: "GENERATED_ONLY", claimedPaths: [`generated/${id}.out`] });
}

test("command-hardlink-authority: admission rejects every preexisting multiply-linked writable inode", async (t) => {
  const cases: Array<[string, (fixture: RepositoryFixture) => Promise<void>]> = [
    ["alias to frozen authority", async (fixture) => { await link(fixture.authorityPath, join(fixture.repository, "generated", "frozen-alias")); }],
    ["alias to unrelated outside file", async (fixture) => { const outside = join(fixture.root, "outside.txt"); await writeFile(outside, "outside\n"); await link(outside, join(fixture.repository, "generated", "outside-alias")); }],
    ["both aliases inside writable prefix", async (fixture) => { const first = join(fixture.repository, "generated", "first"); await writeFile(first, "linked\n"); await link(first, join(fixture.repository, "generated", "second")); }],
  ];
  for (const [label, prepare] of cases) await t.test(label, async () => {
    let marker = ""; const value = await createM4Fixture(async (fixture, temporaryRoot) => {
      marker = join(temporaryRoot, "body-ran"); return [await writer(fixture, temporaryRoot, `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('ran')\n`, "hardlink")];
    }, null, async (fixture) => { await prepare(fixture); await git(fixture.repository, "add", "generated"); await git(fixture.repository, "commit", "-m", `hardlink ${label}`); });
    try {
      await assert.rejects(value.gateway.run_verification_command({ commandId: "hardlink", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "HARDLINK_WRITE_SCOPE_UNSAFE");
      await assert.rejects(stat(marker), { code: "ENOENT" });
    } finally { await cleanup(value); }
  });
});

test("command-hardlink-authority: link creation is denied in children and ordinary files remain writable", async (t) => {
  let child!: string; let grandchild!: string;
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    child = await py(join(temporaryRoot, "child-link.py"), `import os\nfrom pathlib import Path\ntry:\n os.link(${JSON.stringify(join(fixture.repository, "generated", ".keep"))},${JSON.stringify(join(fixture.repository, "generated", "child-hardlink"))});print('ESCAPED')\nexcept PermissionError: print('DENIED')\nPath(${JSON.stringify(join(fixture.repository, "generated", "child.out"))}).write_text('ordinary')\n`);
    const grand = await py(join(temporaryRoot, "grand.py"), "import subprocess,sys\np=subprocess.run([sys.executable,__file__+'.child'],capture_output=True,text=True,check=True)\nprint(p.stdout,end='')\n");
    grandchild = await py(`${grand}.child`, `import os\nfrom pathlib import Path\ntry:\n os.link(${JSON.stringify(join(fixture.repository, "generated", ".keep"))},${JSON.stringify(join(fixture.repository, "generated", "grand-hardlink"))});print('ESCAPED')\nexcept PermissionError: print('DENIED')\nPath(${JSON.stringify(join(fixture.repository, "generated", "grand.out"))}).write_text('ordinary')\n`);
    const ordinary = await py(join(temporaryRoot, "ordinary.py"), `from pathlib import Path\nPath(${JSON.stringify(join(fixture.repository, "generated", "ordinary.out"))}).write_text('ordinary')\n`);
    return [
      await commandSpecification("child", "VERIFICATION", "/usr/bin/python3", [child], { repositoryRoot: fixture.repository, writePaths: [{ path: "generated", kind: "PREFIX" }], sideEffect: "GENERATED_ONLY", claimedPaths: ["generated/child.out"] }),
      await commandSpecification("grand", "VERIFICATION", "/usr/bin/python3", [grand], { repositoryRoot: fixture.repository, executionInputs: [grandchild], writePaths: [{ path: "generated", kind: "PREFIX" }], sideEffect: "GENERATED_ONLY", claimedPaths: ["generated/grand.out"] }),
      await commandSpecification("ordinary", "VERIFICATION", "/usr/bin/python3", [ordinary], { repositoryRoot: fixture.repository, writePaths: [{ path: "generated", kind: "PREFIX" }], sideEffect: "GENERATED_ONLY", claimedPaths: ["generated/ordinary.out"] }),
    ];
  });
  try {
    for (const id of ["child", "grand"]) {
      const result = await value.gateway.run_verification_command({ commandId: id, stateTokenContentSha256: token(value) });
      assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "DENIED\n"); await assert.rejects(stat(join(value.fixture.repository, "generated", `${id}-hardlink`)), { code: "ENOENT" });
      assert.equal((await stat(join(value.fixture.repository, "generated", `${id}.out`))).nlink, 1);
    }
    await value.gateway.run_verification_command({ commandId: "ordinary", stateTokenContentSha256: token(value) });
    assert.equal(await readFile(join(value.fixture.repository, "generated", "ordinary.out"), "utf8"), "ordinary");
  } finally { await cleanup(value); }
});

test("command-execution-inputs: scripts retain exact path/inode/mode/size/digest authority", async (t) => {
  const paths = new Map<string, string>();
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    const commands: M4CommandSpecification[] = [];
    for (const id of ["unchanged", "content", "inode", "symlink", "mode", "removed"]) {
      const path = await py(join(temporaryRoot, `${id}.py`), `print(${JSON.stringify(`SAFE-${id}`)})\n`); paths.set(id, path);
      commands.push(await commandSpecification(id, "INSPECTION", "/usr/bin/python3", [path], { repositoryRoot: fixture.repository }));
    }
    return commands;
  });
  try {
    const unchanged = await value.gateway.run_inspection_command({ commandId: "unchanged", stateTokenContentSha256: token(value) }); assert.equal(Buffer.from(unchanged.stdoutBase64, "base64").toString(), "SAFE-unchanged\n");
    await writeFile(paths.get("content")!, "print('CHANGED')\n");
    await assert.rejects(value.gateway.run_inspection_command({ commandId: "content", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "EXECUTION_INPUT_DRIFT");
    const inode = paths.get("inode")!; const replacement = `${inode}.replacement`; await writeFile(replacement, await readFile(inode), { mode: 0o600 }); await rename(replacement, inode);
    await assert.rejects(value.gateway.run_inspection_command({ commandId: "inode", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "EXECUTION_INPUT_DRIFT");
    const symlinkPath = paths.get("symlink")!; await unlink(symlinkPath); await symlink(paths.get("unchanged")!, symlinkPath);
    await assert.rejects(value.gateway.run_inspection_command({ commandId: "symlink", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "EXECUTION_INPUT_DRIFT");
    await chmod(paths.get("mode")!, 0o700); await assert.rejects(value.gateway.run_inspection_command({ commandId: "mode", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "EXECUTION_INPUT_DRIFT");
    await unlink(paths.get("removed")!); await assert.rejects(value.gateway.run_inspection_command({ commandId: "removed", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "EXECUTION_INPUT_DRIFT");
  } finally { await cleanup(value); }
});

test("command-execution-inputs: checkpoint drift cannot execute changed script or interpreter bytes", async (t) => {
  for (const selected of ["script", "interpreter"] as const) await t.test(selected, async () => {
    let script = ""; let executable = "/usr/bin/python3"; let marker = "";
    const value = await createM4Fixture(async (fixture, temporaryRoot) => {
      marker = join(temporaryRoot, `${selected}-changed-ran`); script = await py(join(temporaryRoot, `${selected}.py`), "print('SAFE')\n");
      if (selected === "interpreter") { executable = join(fixture.root, "held-python"); await copyFile("/usr/bin/python3", executable); await chmod(executable, 0o700); }
      return [await commandSpecification(selected, "INSPECTION", executable, [script], { repositoryRoot: fixture.repository })];
    });
    const socket = join(value.fixture.root, `${selected}.sock`); let control: ReturnType<typeof createServer> | undefined;
    try {
      control = await server(socket, async () => {
        if (selected === "script") { await unlink(script); await writeFile(script, `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('bad')\n`, { mode: 0o600 }); }
        else await copyFile("/bin/true", executable);
      });
      setSecureFilesystemTestHooks({ sandboxCheckpointSocket: socket, sandboxCheckpointStage: "BEFORE_LANDLOCK" });
      await assert.rejects(value.gateway.run_inspection_command({ commandId: selected, stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "EXECUTION_INPUT_DRIFT");
      await assert.rejects(stat(marker), { code: "ENOENT" });
    } finally { resetSecureFilesystemTestHooks(); if (control !== undefined) await new Promise<void>((resolve) => control!.close(() => resolve())); await cleanup(value); }
  });
});

test("command-cwd-identity: helper fchdir uses the exact admitted directory inode", async () => {
  let marker = "";
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    marker = join(temporaryRoot, "cwd-body"); const body = await py(join(temporaryRoot, "cwd.py"), `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('ran')\n`);
    return [await commandSpecification("cwd", "INSPECTION", "/usr/bin/python3", [body], { repositoryRoot: fixture.repository, cwd: "src" })];
  });
  const src = join(value.fixture.repository, "src"); const moved = join(value.fixture.repository, "src-moved"); const socket = join(value.fixture.root, "cwd.sock");
  try {
    await value.gateway.run_inspection_command({ commandId: "cwd", stateTokenContentSha256: token(value) }); assert.equal(await readFile(marker, "utf8"), "ran"); await unlink(marker);
    const control = await server(socket, async () => { await rename(src, moved); await mkdir(src); await copyFile(join(moved, "a.txt"), join(src, "a.txt")); await copyFile(join(moved, "b.txt"), join(src, "b.txt")); });
    setSecureFilesystemTestHooks({ sandboxCheckpointSocket: socket, sandboxCheckpointStage: "CWD_OPENED" });
    await assert.rejects(value.gateway.run_inspection_command({ commandId: "cwd", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_CWD_IDENTITY_DRIFT");
    await assert.rejects(stat(marker), { code: "ENOENT" }); await new Promise<void>((resolve) => control.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await rm(src, { recursive: true, force: true }); await rename(moved, src).catch(() => {}); await cleanup(value); }
});

test("command-dispatcher-policy: canonical realpath and aliases reject indirect dispatch", async (t) => {
  const cases: Array<[string, (fixture: RepositoryFixture) => Promise<[string, string[]]>]> = [
    ["/usr/bin/env sh -c", async () => ["/usr/bin/env", ["sh", "-c", "printf bad"]]],
    ["/usr/bin/env git", async () => ["/usr/bin/env", ["git", "--version"]]],
    ["env symlink", async (fixture) => { const alias = join(fixture.root, "innocent"); await symlink("/usr/bin/env", alias); return [alias, ["printf", "bad"]]; }],
    ["shell symlink -c", async (fixture) => { const alias = join(fixture.root, "runner"); await symlink("/bin/sh", alias); return [alias, ["-c", "printf bad"]]; }],
  ];
  for (const [label, make] of cases) await t.test(label, async () => {
    await assert.rejects(createM4Fixture(async (fixture) => { const [executable, argv] = await make(fixture); return [await commandSpecification("dispatch", "INSPECTION", executable, argv, { repositoryRoot: fixture.repository })]; }),
      (error: unknown) => ["GENERIC_DISPATCHER_FORBIDDEN", "COMMAND_FORBIDDEN"].includes(String(code(error))));
  });
  await t.test("ordinary direct executable and frozen interpreter script remain allowed", async () => {
    const value = await createM4Fixture(async (fixture, temporaryRoot) => {
      const script = await py(join(temporaryRoot, "allowed.py"), "print('allowed-script')\n"); return [
        await commandSpecification("direct", "INSPECTION", "/usr/bin/printf", ["allowed-direct"], { repositoryRoot: fixture.repository }),
        await commandSpecification("script", "INSPECTION", "/usr/bin/python3", [script], { repositoryRoot: fixture.repository }),
      ];
    }); try {
      assert.equal(Buffer.from((await value.gateway.run_inspection_command({ commandId: "direct", stateTokenContentSha256: token(value) })).stdoutBase64, "base64").toString(), "allowed-direct");
      assert.equal(Buffer.from((await value.gateway.run_inspection_command({ commandId: "script", stateTokenContentSha256: token(value) })).stdoutBase64, "base64").toString(), "allowed-script\n");
    } finally { await cleanup(value); }
  });
});

test("output-evidence-consistency: captured/observed bytes, overflow, completeness, and hashes agree", async () => {
  let fifo = ""; let ready = "";
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    fifo = join(temporaryRoot, "output.fifo"); ready = join(temporaryRoot, "output-ready.fifo");
    for (const path of [fifo, ready]) await new Promise<void>((resolve, reject) => { execFile("mkfifo", [path], (error) => error ? reject(error) : resolve()); });
    const sources: Record<string, string> = {
      zero: "pass\n", below: "import os\nos.write(1,b'abc')\n", exact: "import os\nos.write(1,b'abcd')\n",
      plus: "import os\nos.write(1,b'abcde')\n", multi: "import os\nos.write(1,b'abcd');os.write(1,b'e')\n",
      both: "import os\nos.write(1,b'out');os.write(2,b'err')\n", binary: "import os\nos.write(1,bytes([0,255,1]))\n",
      timeout: `import os\nos.write(1,b'partial');fd=os.open(${JSON.stringify(ready)},os.O_WRONLY);os.write(fd,b'1');os.close(fd);fd=os.open(${JSON.stringify(fifo)},os.O_RDONLY);os.read(fd,1)\n`,
    };
    const commands: M4CommandSpecification[] = [];
    for (const [id, source] of Object.entries(sources)) {
      const path = await py(join(temporaryRoot, `${id}-output.py`), source); commands.push(await commandSpecification(id, "INSPECTION", "/usr/bin/python3", [path], { repositoryRoot: fixture.repository,
        stdoutLimit: ["exact", "plus", "multi"].includes(id) ? 4 : 1024, stderrLimit: 1024, timeoutMs: id === "timeout" ? 5_000 : 30_000 }));
    }
    return commands;
  });
  try {
    for (const [id, expected] of [["zero", Buffer.alloc(0)], ["below", Buffer.from("abc")], ["exact", Buffer.from("abcd")], ["both", Buffer.from("out")], ["binary", Buffer.from([0, 255, 1])]] as const) {
      const result = await value.gateway.run_inspection_command({ commandId: id, stateTokenContentSha256: token(value) }); const captured = Buffer.from(result.stdoutBase64, "base64");
      assert.deepEqual(captured, expected); assert.equal(result.record.stdout_byte_count, expected.byteLength); assert.equal(result.record.stdout_digest, sha256Bytes(expected));
      assert.equal(result.record.stdout_observed_byte_count, expected.byteLength); assert.equal(result.record.stdout_observed_digest, sha256Bytes(expected)); assert.equal(result.record.stdout_stream_complete, true);
      if (id === "both") { assert.equal(result.record.stderr_digest, sha256Bytes(Buffer.from("err"))); assert.equal(result.record.stderr_observed_byte_count, 3); }
    }
    for (const [id, chunkSize] of [["plus", undefined], ["multi", 1]] as const) {
      if (chunkSize !== undefined) setSecureFilesystemTestHooks({ sandboxOutputChunkBytes: chunkSize });
      await assert.rejects(value.gateway.run_inspection_command({ commandId: id, stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_OUTPUT_LIMIT"); resetSecureFilesystemTestHooks();
      const record = (await commandResults(value, id)).at(-1)!; assert.equal(record.stdout_byte_count, 4); assert.equal(record.stdout_digest, sha256Bytes(Buffer.from("abcd")));
      assert.equal(record.stdout_observed_byte_count, 5); assert.equal(record.stdout_observed_digest, null); assert.equal(record.stdout_overflowed, true); assert.equal(record.stdout_stream_complete, false);
    }
    const timed = assert.rejects(value.gateway.run_inspection_command({ commandId: "timeout", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_TIMEOUT");
    const readyHandle = await open(ready, "r"); const readyByte = Buffer.alloc(1); await readyHandle.read(readyByte, 0, 1, null); await readyHandle.close(); assert.equal(readyByte.toString(), "1"); await timed;
    const timeout = (await commandResults(value, "timeout")).at(-1)!; assert.equal(timeout.stdout_digest, sha256Bytes(Buffer.from("partial"))); assert.equal(timeout.stdout_observed_digest, null); assert.equal(timeout.stdout_stream_complete, false);
  } finally { resetSecureFilesystemTestHooks(); await cleanup(value); }
});
