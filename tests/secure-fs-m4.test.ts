import assert from "node:assert/strict";
import { chmod, link, lstat, mkdir, readFile, readdir, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import test from "node:test";

import { sha256Bytes } from "../src/identity/index.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { createSecureFilesystem, probeSecureFilesystemCapabilities, SecureFilesystemError } from "../src/secure-fs/index.js";
import { secureMutation } from "../src/secure-fs/client.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof SecureFilesystemError ? error.code : (error as { code?: unknown })?.code; }

async function secureFixture() {
  const fixture = await createRepositoryFixture();
  await mkdir(join(fixture.repository, "nested"), { mode: 0o755 });
  await writeFile(join(fixture.repository, "nested", "read.txt"), "alpha\nbeta\n", { mode: 0o644 });
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const capability = await probeSecureFilesystemCapabilities();
  const filesystem = await createSecureFilesystem({ repository, capability, readablePaths: [
    { path: "nested", kind: "PREFIX" }, { path: "tracked.txt", kind: "EXACT" },
  ] });
  return { fixture, repository, capability, filesystem };
}

async function expected(path: string) {
  const bytes = await readFile(path); const stats = await stat(path);
  return { digest: sha256Bytes(bytes), size: bytes.byteLength, mode: stats.mode & 0o777 };
}

test("M4 secure capability exercises all mandatory Linux primitives", async () => {
  const value = await probeSecureFilesystemCapabilities();
  assert.equal(value.secure_fs_result, "SECURE_FS_AVAILABLE");
  assert.equal(value.command_sandbox_result, "COMMAND_SANDBOX_AVAILABLE");
  assert.equal(value.network_sandbox_result, "NETWORK_SANDBOX_AVAILABLE");
  assert.deepEqual(value.supported_resolve_flags, ["RESOLVE_BENEATH", "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_MAGICLINKS"]);
  assert.equal(value.rename_noreplace_available, true);
  assert.equal(value.rename_exchange_available, true);
  assert.equal(value.directory_fsync_available, true);
  assert.equal(value.landlock_available, true);
  assert.ok((value.landlock_abi ?? 0) >= 3);
  assert.equal(Object.isFrozen(value), true);
});

test("M4 secure capability fails closed through the unavailable primitive seam", async () => {
  setSecureFilesystemTestHooks({ forceCapabilityUnavailable: true });
  try {
    const value = await probeSecureFilesystemCapabilities();
    assert.equal(value.secure_fs_result, "SECURE_FS_UNAVAILABLE");
    const fixture = await createRepositoryFixture();
    try {
      const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
      await assert.rejects(createSecureFilesystem({ repository, capability: value, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] }), (error: unknown) => code(error) === "SECURE_WRITE_PRIMITIVE_UNAVAILABLE");
    } finally { await removeRepositoryFixture(fixture); }
  } finally { resetSecureFilesystemTestHooks(); }
});

test("M4 secure read and list are FD-relative, bounded, stable, and sorted", async () => {
  const value = await secureFixture();
  try {
    const read = await value.filesystem.readScoped({ path: "nested/read.txt", offset: 6, length: 4, maximumBytes: 4, hashLimitBytes: 1024 });
    assert.equal(Buffer.from(read.dataBase64, "base64").toString(), "beta");
    assert.equal(read.metadata.digest, sha256Bytes(Buffer.from("alpha\nbeta\n")));
    const list = await value.filesystem.listScoped({ path: "nested", maximumDepth: 3, maximumEntries: 10, maximumMetadataBytes: 10_000, hashFiles: true, hashLimitBytes: 1024 });
    assert.deepEqual(list.entries.map((entry) => entry.path), ["nested/read.txt"]);
    assert.equal(list.entries[0]?.digest, read.metadata.digest);
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 secure helper interpreter identity blocks PATH drift", async () => {
  const value = await secureFixture(); const replacement = join(value.fixture.root, "python3"); const originalPath = process.env["PATH"];
  try {
    await writeFile(replacement, "#!/bin/sh\nexit 99\n", { mode: 0o700 }); await chmod(replacement, 0o700); process.env["PATH"] = `${value.fixture.root}:${originalPath ?? ""}`;
    await assert.rejects(value.filesystem.readScoped({ path: "tracked.txt", offset: 0, length: 1, maximumBytes: 1, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "SECURE_FS_CAPABILITY_MISMATCH");
  } finally {
    if (originalPath === undefined) delete process.env["PATH"]; else process.env["PATH"] = originalPath;
    await removeRepositoryFixture(value.fixture);
  }
});

test("M4 canonical path and scope rejection matrix", async (t) => {
  const value = await secureFixture();
  try {
    for (const [label, path] of [
      ["absolute", "/etc/passwd"], ["dot", "."], ["dot-dot", ".."], ["nested dot-dot", "nested/../tracked.txt"],
      ["empty component", "nested//read.txt"], ["trailing separator", "nested/"], ["backslash", "nested\\read.txt"],
      ["NUL", "nested/\0read.txt"], ["Git metadata", ".git/config"], ["outside scope", "AUTHORITY.md"],
    ] as const) {
      await t.test(label, async () => {
        await assert.rejects(value.filesystem.readScoped({ path, offset: 0, length: 1, maximumBytes: 1, hashLimitBytes: 1024 }),
          (error: unknown) => ["INVALID_CANONICAL_PATH", "PATH_NOT_READABLE"].includes(String(code(error))));
      });
    }
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 secure reads reject symlinks and special files without traversal", async (t) => {
  const value = await secureFixture();
  try {
    const outside = join(value.fixture.root, "outside.txt"); await writeFile(outside, "sentinel");
    await symlink(outside, join(value.fixture.repository, "nested", "link"));
    const fifo = join(value.fixture.repository, "nested", "pipe");
    const { execFile } = await import("node:child_process"); await new Promise<void>((resolve, reject) => execFile("mkfifo", [fifo], (error) => error ? reject(error) : resolve()));
    for (const [name, expectedCode] of [["link", "SYMLINK_PATH"], ["pipe", "SPECIAL_FILE"]] as const) {
      await t.test(name, async () => {
        await assert.rejects(value.filesystem.readScoped({ path: `nested/${name}`, offset: 0, length: 8, maximumBytes: 8, hashLimitBytes: 1024 }), (error: unknown) => code(error) === expectedCode);
      });
    }
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 CREATE uses atomic no-replace semantics", async () => {
  const value = await secureFixture();
  try {
    const outcome = await secureMutation(value.filesystem, { operation: "CREATE", path: "created.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("created\n"), finalMode: 0o644, hashLimitBytes: 1024 });
    assert.equal(await readFile(join(value.fixture.repository, "created.txt"), "utf8"), "created\n");
    assert.equal(outcome.before, null); assert.equal(outcome.after?.nlink, 1);
    await assert.rejects(secureMutation(value.filesystem, { operation: "CREATE", path: "created.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("other"), finalMode: 0o644, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "TARGET_ALREADY_EXISTS");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 REPLACE exchanges, validates, and preserves exact mode", async () => {
  const value = await secureFixture();
  try {
    const path = value.fixture.trackedPath; const before = await expected(path);
    const outcome = await secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: before, replacement: Buffer.from("new\n"), finalMode: before.mode, hashLimitBytes: 1024 });
    assert.equal(await readFile(path, "utf8"), "new\n"); assert.deepEqual({ digest: outcome.before?.digest, size: outcome.before?.size, mode: outcome.before?.mode }, before);
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 REPLACE preimage mismatch rolls exchange back", async (t) => {
  for (const field of ["digest", "size", "mode"] as const) {
    await t.test(field, async () => {
      const value = await secureFixture();
      try {
        const path = value.fixture.trackedPath; const before = await expected(path);
        const invalid = { ...before, [field]: field === "digest" ? sha256Bytes(Buffer.from("wrong")) : before[field] + 1 };
        await assert.rejects(secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: invalid, replacement: Buffer.from("new\n"), finalMode: before.mode, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "PREIMAGE_MISMATCH");
        assert.equal(await readFile(path, "utf8"), "initial\n");
      } finally { await removeRepositoryFixture(value.fixture); }
    });
  }
});

test("M4 DELETE tombstones, validates, fsyncs, and removes", async () => {
  const value = await secureFixture();
  try {
    const before = await expected(value.fixture.trackedPath);
    const outcome = await secureMutation(value.filesystem, { operation: "DELETE", path: "tracked.txt", expected: before, replacement: null, finalMode: null, hashLimitBytes: 1024 });
    assert.equal(outcome.after, null); await assert.rejects(readFile(value.fixture.trackedPath), { code: "ENOENT" });
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 mutation rejects hardlinks, symlink targets, and missing targets", async (t) => {
  const value = await secureFixture();
  try {
    const before = await expected(value.fixture.trackedPath);
    await link(value.fixture.trackedPath, join(value.fixture.repository, "alias.txt"));
    await t.test("hardlink", async () => assert.rejects(secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: before, replacement: Buffer.from("x"), finalMode: before.mode, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "HARDLINK_TARGET"));
    await unlink(join(value.fixture.repository, "alias.txt")); await unlink(value.fixture.trackedPath); await symlink("nested/read.txt", value.fixture.trackedPath);
    await t.test("symlink", async () => assert.rejects(secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: before, replacement: Buffer.from("x"), finalMode: before.mode, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "SYMLINK_PATH"));
    await unlink(value.fixture.trackedPath);
    await t.test("missing", async () => assert.rejects(secureMutation(value.filesystem, { operation: "DELETE", path: "tracked.txt", expected: before, replacement: null, finalMode: null, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "TARGET_MISSING"));
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 patch payload boundary is exact", async () => {
  const value = await secureFixture();
  try {
    await secureMutation(value.filesystem, { operation: "CREATE", path: "one-mib.bin", expected: { digest: null, size: null, mode: null }, replacement: Buffer.alloc(1_048_576), finalMode: 0o644, hashLimitBytes: 1_048_576 });
    await assert.rejects(secureMutation(value.filesystem, { operation: "CREATE", path: "too-big.bin", expected: { digest: null, size: null, mode: null }, replacement: Buffer.alloc(1_048_577), finalMode: 0o644, hashLimitBytes: 1_048_577 }), (error: unknown) => code(error) === "PATCH_LIMIT_EXCEEDED");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("M4 deterministic target-symlink race rolls back the exchanged new content", async () => {
  const value = await secureFixture(); const control = join(value.fixture.root, "c.sock");
  try {
    const before = await expected(value.fixture.trackedPath); const outside = join(value.fixture.root, "outside.txt"); await writeFile(outside, "outside\n");
    const server = createServer((connection) => {
      let data = ""; connection.on("data", async (chunk) => {
        data += chunk.toString(); if (!data.includes("\n")) return;
        await unlink(value.fixture.trackedPath); await symlink(outside, value.fixture.trackedPath); connection.end("1");
      });
    });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject));
    setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "BEFORE_RENAME" });
    await assert.rejects(secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: before, replacement: Buffer.from("attacker-wins?\n"), finalMode: before.mode, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "SYMLINK_PATH" || code(error) === "PREIMAGE_MISMATCH");
    assert.equal(await readFile(outside, "utf8"), "outside\n"); assert.equal((await lstat(value.fixture.trackedPath)).isSymbolicLink(), true);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
});

test("M4 deterministic parent replacement race never writes through the replacement symlink", async () => {
  const value = await secureFixture(); const control = join(value.fixture.root, "parent.sock");
  try {
    const outside = join(value.fixture.root, "outside-dir"); const moved = join(value.fixture.repository, "moved-parent"); await mkdir(outside);
    const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => {
      data += chunk.toString(); if (!data.includes("\n")) return;
      await import("node:fs/promises").then(async (fs) => { await fs.rename(join(value.fixture.repository, "nested"), moved); await symlink(outside, join(value.fixture.repository, "nested")); }); connection.end("1");
    }); });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject));
    setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "PARENT_OPENED" });
    await assert.rejects(secureMutation(value.filesystem, { operation: "CREATE", path: "nested/new.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("new\n"), finalMode: 0o644, hashLimitBytes: 1024 }),
      (error: unknown) => code(error) === "PARENT_IDENTITY_DRIFT" || code(error) === "SYMLINK_PATH");
    await assert.rejects(readFile(join(outside, "new.txt")), { code: "ENOENT" }); await assert.rejects(readFile(join(moved, "new.txt")), { code: "ENOENT" });
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
});

test("M4 deterministic same-content inode swap is detected and rolled back", async () => {
  const value = await secureFixture(); const control = join(value.fixture.root, "inode.sock");
  try {
    const before = await expected(value.fixture.trackedPath); const attackerCopy = join(value.fixture.repository, "attacker-old.txt");
    const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => {
      data += chunk.toString(); if (!data.includes("\n")) return;
      await import("node:fs/promises").then(async (fs) => { await fs.rename(value.fixture.trackedPath, attackerCopy); await writeFile(value.fixture.trackedPath, "initial\n", { mode: 0o644 }); }); connection.end("1");
    }); });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject));
    setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "BEFORE_RENAME" });
    await assert.rejects(secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: before, replacement: Buffer.from("new\n"), finalMode: before.mode, hashLimitBytes: 1024 }),
      (error: unknown) => code(error) === "PREIMAGE_MISMATCH");
    assert.equal(await readFile(value.fixture.trackedPath, "utf8"), "initial\n"); assert.equal(await readFile(attackerCopy, "utf8"), "initial\n");
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
});

test("M4 deterministic final-inode replacement produces uncertainty, never false success", async () => {
  const value = await secureFixture(); const control = join(value.fixture.root, "final.sock");
  try {
    const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => {
      data += chunk.toString(); if (!data.includes("\n")) return;
      await unlink(join(value.fixture.repository, "created-race.txt")); await writeFile(join(value.fixture.repository, "created-race.txt"), "new\n", { mode: 0o644 }); connection.end("1");
    }); });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject));
    setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "RENAMED" });
    await assert.rejects(secureMutation(value.filesystem, { operation: "CREATE", path: "created-race.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("new\n"), finalMode: 0o644, hashLimitBytes: 1024 }),
      (error: unknown) => code(error) === "SECURE_WRITE_UNCERTAIN");
    assert.equal(await readFile(join(value.fixture.repository, "created-race.txt"), "utf8"), "new\n");
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
});

test("M4 helper death after rename is reported as write uncertainty", async () => {
  const value = await secureFixture(); const control = join(value.fixture.root, "timeout.sock");
  try {
    const server = createServer((connection) => { let data = ""; connection.on("data", (chunk) => { data += chunk.toString(); if (data.includes("\n")) connection.end("1"); }); });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject));
    setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "RENAMED", helperKillStage: "RENAMED" });
    await assert.rejects(secureMutation(value.filesystem, { operation: "CREATE", path: "timeout-result.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("uncertain\n"), finalMode: 0o644, hashLimitBytes: 1024 }),
      (error: unknown) => code(error) === "SECURE_WRITE_UNCERTAIN");
    assert.equal(await readFile(join(value.fixture.repository, "timeout-result.txt"), "utf8"), "uncertain\n");
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
});

test("M4 injected fsync and rollback failures have typed uncertainty", async (t) => {
  for (const stage of ["FILE_FSYNC", "DIRECTORY_FSYNC"] as const) {
    await t.test(stage, async () => {
      const value = await secureFixture();
      try {
        setSecureFilesystemTestHooks({ failStage: stage }); const before = await expected(value.fixture.trackedPath);
        await assert.rejects(secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: before, replacement: Buffer.from("new\n"), finalMode: before.mode, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "SECURE_WRITE_UNCERTAIN");
        assert.equal((await readdir(value.fixture.repository)).some((name) => name.includes(".m4tmp-") || name.includes(".m4tomb-")), false);
      } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
    });
  }
});
