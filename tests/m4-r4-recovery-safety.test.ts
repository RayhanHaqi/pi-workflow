import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { lstat, readFile, readdir, stat, symlink, writeFile, mkdir } from "node:fs/promises";
import { promisify } from "node:util";
import { createServer, type Server } from "node:net";
import test from "node:test";

import { sha256Bytes } from "../src/identity/index.js";
import { secureMutation } from "../src/secure-fs/client.js";
import { createSecureFilesystem, probeSecureFilesystemCapabilities, SecureFilesystemError } from "../src/secure-fs/index.js";
import { mutationRecoveryForError } from "../src/secure-fs/helper.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

const execFileAsync = promisify(execFile);
type Operation = "CREATE" | "REPLACE" | "DELETE";
type ForeignKind = "REGULAR" | "SYMLINK" | "FIFO" | "DIRECTORY";

async function directFixture() {
  const repositoryFixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: repositoryFixture.repository, requireHead: true });
  const capability = await probeSecureFilesystemCapabilities();
  const filesystem = await createSecureFilesystem({ repository, capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] });
  return { repositoryFixture, filesystem };
}

async function closeServer(server: Server | undefined): Promise<void> {
  if (server !== undefined) await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function replyServer(path: string, action: () => Promise<void>): Promise<Server> {
  const server = createServer((connection) => {
    let data = "";
    connection.on("data", (chunk) => {
      data += chunk.toString();
      if (!data.includes("\n")) return;
      void action().then(() => connection.end("1"), () => connection.destroy());
    });
  });
  await new Promise<void>((resolve, reject) => server.listen(path, resolve).once("error", reject));
  return server;
}

function details(error: unknown): Record<string, unknown> {
  assert.ok(error && typeof error === "object" && "details" in error);
  return (error as { readonly details: Record<string, unknown> }).details;
}

async function assertAbsent(path: string): Promise<void> {
  await assert.rejects(lstat(path), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
}

async function assertRegular(path: string, bytes: Buffer, mode: number): Promise<void> {
  const value = await lstat(path);
  assert.equal(value.isFile(), true); assert.equal(value.isSymbolicLink(), false); assert.equal(value.nlink, 1); assert.equal(value.mode & 0o777, mode);
  assert.deepEqual(await readFile(path), bytes);
}

function residueNames(names: readonly string[]): readonly string[] {
  return names.filter((name) => name.includes(".m4tmp-") || name.includes(".m4tomb-"));
}

async function mutationRequest(value: Awaited<ReturnType<typeof directFixture>>, operation: Operation, path: string): Promise<Parameters<typeof secureMutation>[1]> {
  if (operation === "CREATE") return { operation, path, expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("replacement\n"), finalMode: 0o644, hashLimitBytes: 1024 };
  const bytes = await readFile(value.repositoryFixture.trackedPath); const target = await stat(value.repositoryFixture.trackedPath);
  return operation === "REPLACE"
    ? { operation, path, expected: { digest: sha256Bytes(bytes), size: bytes.byteLength, mode: target.mode & 0o777 }, replacement: Buffer.from("replacement\n"), finalMode: target.mode & 0o777, hashLimitBytes: 1024 }
    : { operation, path, expected: { digest: sha256Bytes(bytes), size: bytes.byteLength, mode: target.mode & 0o777 }, replacement: null, finalMode: null, hashLimitBytes: 1024 };
}

async function installForeign(path: string, kind: ForeignKind): Promise<void> {
  if (kind === "REGULAR") { await writeFile(path, "foreign\n", { mode: 0o600 }); return; }
  if (kind === "SYMLINK") { await symlink("tracked.txt", path); return; }
  if (kind === "FIFO") { await execFileAsync("mkfifo", [path]); return; }
  await mkdir(path, { mode: 0o700 });
}

for (const operation of ["CREATE", "REPLACE", "DELETE"] as const) {
  for (const kind of ["REGULAR", "SYMLINK", "FIFO", "DIRECTORY"] as const) {
    test(`m4-r4 foreign residue safety: ${operation} ${kind}`, async () => {
      const value = await directFixture(); let residuePath = "";
      const target = operation === "CREATE" ? `foreign-${operation}-${kind}.txt` : "tracked.txt";
      try {
        setSecureFilesystemTestHooks({ beforeMutationHelperLaunch: async (request) => {
          const identity = request["operation_identity"] as { readonly temporary_name: string | null; readonly tombstone_name: string | null };
          const name = operation === "DELETE" ? identity.tombstone_name : identity.temporary_name;
          assert.ok(name); residuePath = `${request["root"] as string}/${name}`; await installForeign(residuePath, kind);
        } });
        await assert.rejects(secureMutation(value.filesystem, await mutationRequest(value, operation, target)), (error: unknown) => {
          assert.equal((error as SecureFilesystemError).code, "RESIDUE_IDENTITY_MISMATCH");
          assert.equal(details(error)["residue_cleanup_outcome"], "IDENTITY_MISMATCH");
          assert.equal(mutationRecoveryForError(error)?.outcome, "IDENTITY_MISMATCH");
          return true;
        });
        const residue = await lstat(residuePath); assert.ok(residue.isSymbolicLink() || residue.isFile() || residue.isDirectory() || residue.isFIFO());
        if (operation === "CREATE") await assertAbsent(`${value.repositoryFixture.repository}/${target}`);
        else await assertRegular(value.repositoryFixture.trackedPath, Buffer.from("initial\n"), 0o644);
      } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.repositoryFixture); }
    });
  }
}

test("m4-r4 foreign residue safety: similarly prefixed and unrelated hidden entries are never swept", async () => {
  const value = await directFixture(); const target = "prefix-safe.txt"; let similar = ""; let unrelated = "";
  try {
    setSecureFilesystemTestHooks({ beforeMutationHelperLaunch: async (request) => {
      const identity = request["operation_identity"] as { readonly temporary_name: string };
      const root = request["root"] as string; similar = `${root}/${identity.temporary_name}-foreign`; unrelated = `${root}/.unrelated-hidden`; await writeFile(similar, "similar\n", { mode: 0o600 }); await writeFile(unrelated, "unrelated\n", { mode: 0o600 });
    } });
    const outcome = await secureMutation(value.filesystem, await mutationRequest(value, "CREATE", target));
    assert.equal(outcome.journal.recovery_attempted, false);
    await assertRegular(`${value.repositoryFixture.repository}/${target}`, Buffer.from("replacement\n"), 0o644);
    await assertRegular(similar, Buffer.from("similar\n"), 0o600); await assertRegular(unrelated, Buffer.from("unrelated\n"), 0o600);
    assert.deepEqual(residueNames(await readdir(value.repositoryFixture.repository)), [similar.slice(similar.lastIndexOf("/") + 1)]);
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.repositoryFixture); }
});

for (const [label, recoveryStage] of [["unlink", "DURING_RECOVERY_UNLINK"], ["directory fsync", "DURING_RECOVERY_DIRECTORY_FSYNC"], ["terminated", "__KILL__"]] as const) {
  test(`m4-r4 recovery failure: ${label} remains uncertain and truthful`, async () => {
    const value = await directFixture(); const socket = `${value.repositoryFixture.root}/helper.sock`; let server: Server | undefined;
    try {
      server = await replyServer(socket, async () => {});
      setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "AFTER_TEMPORARY_CREATION", helperKillStage: "AFTER_TEMPORARY_CREATION",
        ...(recoveryStage === "__KILL__" ? { recoveryKillStage: "BEFORE_RECOVERY_UNLINK" } : { recoveryFailStage: recoveryStage }) });
      let caught: unknown;
      try { await secureMutation(value.filesystem, await mutationRequest(value, "CREATE", `recovery-failure-${label}.txt`)); } catch (error: unknown) { caught = error; }
      assert.equal((caught as SecureFilesystemError).code, "SECURE_WRITE_UNCERTAIN");
      assert.equal(details(caught)["residue_cleanup_outcome"], "FAILED"); assert.equal(details(caught)["recovery_directory_fsync_outcome"], "FAILED");
      if (label === "unlink" || label === "terminated") assert.ok(residueNames(await readdir(value.repositoryFixture.repository)).length >= 1);
      else assert.deepEqual(residueNames(await readdir(value.repositoryFixture.repository)), []);
      await assertAbsent(`${value.repositoryFixture.repository}/recovery-failure-${label}.txt`);
    } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(value.repositoryFixture); }
  });
}

test("m4-r4 recovery failure: recovery helper authority failure does not claim cleanup", async () => {
  const value = await directFixture(); const socket = `${value.repositoryFixture.root}/helper.sock`; let server: Server | undefined;
  try {
    server = await replyServer(socket, async () => {});
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "AFTER_TEMPORARY_CREATION", helperKillStage: "AFTER_TEMPORARY_CREATION",
      beforeRecoveryHelperLaunch: async () => setSecureFilesystemTestHooks({ helperPath: `${value.repositoryFixture.root}/missing-helper.py` }) });
    let caught: unknown;
    try { await secureMutation(value.filesystem, await mutationRequest(value, "CREATE", "recovery-helper-failure.txt")); } catch (error: unknown) { caught = error; }
    assert.equal((caught as SecureFilesystemError).code, "SECURE_WRITE_UNCERTAIN"); assert.equal(details(caught)["residue_cleanup_outcome"], "FAILED");
    assert.ok(residueNames(await readdir(value.repositoryFixture.repository)).length >= 1);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(value.repositoryFixture); }
});

test("m4-r4 recovery idempotence: repeated recovery is safe after the first cleanup", async () => {
  const value = await directFixture(); const socket = `${value.repositoryFixture.root}/helper.sock`; let server: Server | undefined;
  try {
    server = await replyServer(socket, async () => {});
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "AFTER_TEMPORARY_CREATION", helperKillStage: "AFTER_TEMPORARY_CREATION", repeatRecovery: true });
    let caught: unknown;
    try { await secureMutation(value.filesystem, await mutationRequest(value, "CREATE", "idempotent-recovery.txt")); } catch (error: unknown) { caught = error; }
    assert.equal((caught as SecureFilesystemError).code, "SECURE_WRITE_UNCERTAIN"); assert.equal(details(caught)["residue_cleanup_outcome"], "SUCCEEDED");
    assert.equal(details(caught)["remaining_operation_residue_count"], 0); await assertAbsent(`${value.repositoryFixture.repository}/idempotent-recovery.txt`);
    assert.deepEqual(residueNames(await readdir(value.repositoryFixture.repository)), []);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(value.repositoryFixture); }
});

test("m4-r4 target verification: recovery does not turn a changed target into success", async () => {
  const value = await directFixture(); const helperSocket = `${value.repositoryFixture.root}/helper.sock`; const recoverySocket = `${value.repositoryFixture.root}/recovery.sock`; let helper: Server | undefined; let recovery: Server | undefined;
  try {
    helper = await replyServer(helperSocket, async () => {});
    recovery = await replyServer(recoverySocket, async () => { await writeFile(`${value.repositoryFixture.repository}/target-verification.txt`, "foreign\n", { mode: 0o644 }); });
    setSecureFilesystemTestHooks({ checkpointSocket: helperSocket, checkpointStage: "AFTER_ATOMIC_RENAME", helperKillStage: "AFTER_ATOMIC_RENAME", recoveryCheckpointSocket: recoverySocket, recoveryCheckpointStage: "BEFORE_RECOVERY_TARGET_VERIFICATION" });
    let caught: unknown;
    try { await secureMutation(value.filesystem, await mutationRequest(value, "CREATE", "target-verification.txt")); } catch (error: unknown) { caught = error; }
    assert.equal((caught as SecureFilesystemError).code, "SECURE_WRITE_UNCERTAIN"); assert.equal(details(caught)["residue_cleanup_outcome"], "SUCCEEDED"); assert.equal(details(caught)["target_verification_outcome"], "MISMATCH");
    await assertRegular(`${value.repositoryFixture.repository}/target-verification.txt`, Buffer.from("foreign\n"), 0o644); assert.deepEqual(residueNames(await readdir(value.repositoryFixture.repository)), []);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(helper); await closeServer(recovery); await removeRepositoryFixture(value.repositoryFixture); }
});
