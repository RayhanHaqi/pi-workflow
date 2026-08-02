import assert from "node:assert/strict";
import { mkdir, readFile, readdir, rename, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer, type Server } from "node:net";
import test from "node:test";

import { sha256Bytes } from "../src/identity/index.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { createSecureFilesystem, probeSecureFilesystemCapabilities, SecureFilesystemError } from "../src/secure-fs/index.js";
import { secureMutation } from "../src/secure-fs/client.js";
import { mutationJournalForError } from "../src/secure-fs/helper.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import type { M4MutationJournal } from "../src/schemas/index.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof SecureFilesystemError ? error.code : error !== null && typeof error === "object" ? (error as { code?: unknown }).code : undefined; }
async function closeServer(server: Server | undefined): Promise<void> { if (server !== undefined) await new Promise<void>((resolve) => server.close(() => resolve())); }
async function controller(path: string, action: (stage: string) => Promise<void>): Promise<Server> {
  const server = createServer((connection) => {
    let data = "";
    connection.on("data", (chunk) => {
      data += chunk.toString();
      if (!data.includes("\n")) return;
      void action(data.slice(0, data.indexOf("\n"))).then(() => connection.end("1"), () => connection.destroy());
    });
  });
  await new Promise<void>((resolve, reject) => server.listen(path, resolve).once("error", reject));
  return server;
}
async function fixture() {
  const repositoryFixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: repositoryFixture.repository, requireHead: true });
  const capability = await probeSecureFilesystemCapabilities();
  const filesystem = await createSecureFilesystem({ repository, capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] });
  return { repositoryFixture, filesystem };
}
async function expected(path: string) { const bytes = await readFile(path); const value = await stat(path); return { digest: sha256Bytes(bytes), size: bytes.byteLength, mode: value.mode & 0o777 }; }
async function temporaryName(repository: string, target: string): Promise<string> {
  const prefix = `.${target}.m4tmp-`; const name = (await readdir(repository)).find((entry) => entry.startsWith(prefix));
  assert.ok(name, `temporary entry for ${target}`); return name;
}
function assertJournal(journal: M4MutationJournal | null): asserts journal is M4MutationJournal {
  assert.ok(journal); assert.ok(journal.directory_fsync_completed_count <= journal.directory_fsync_attempt_count);
  if (journal.temporary_file_fsync_completed) assert.equal(journal.temporary_file_fsync_attempted, true);
  if (journal.atomic_rename_completed) assert.equal(journal.atomic_rename_attempted, true);
  if (journal.rollback_completed) { assert.equal(journal.rollback_required, true); assert.equal(journal.rollback_attempted, true); }
}

const failureStages = [
  ["BEFORE_TEMPORARY_CREATION", { created: false, bytes: 0, fsyncAttempted: false, fsyncCompleted: false, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["AFTER_TEMPORARY_CREATION", { created: true, bytes: 0, fsyncAttempted: false, fsyncCompleted: false, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["AFTER_BYTES_WRITTEN", { created: true, bytes: 12, fsyncAttempted: false, fsyncCompleted: false, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["BEFORE_TEMPORARY_FSYNC", { created: true, bytes: 12, fsyncAttempted: false, fsyncCompleted: false, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["DURING_TEMPORARY_FSYNC", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: false, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["AFTER_TEMPORARY_FSYNC", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["BEFORE_ATOMIC_RENAME", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: false, directoryCompleted: 0, final: "NOT_RUN" }],
  ["AFTER_ATOMIC_RENAME", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: true, directoryCompleted: 0, final: "NOT_RUN" }],
  ["BEFORE_DIRECTORY_FSYNC", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: true, directoryCompleted: 0, final: "NOT_RUN" }],
  ["DURING_DIRECTORY_FSYNC", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: true, directoryCompleted: 0, final: "NOT_RUN" }],
  ["AFTER_DIRECTORY_FSYNC", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: true, directoryCompleted: 1, final: "NOT_RUN" }],
  ["BEFORE_FINAL_VERIFICATION", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: true, directoryCompleted: 1, final: "NOT_RUN" }],
  ["AFTER_FINAL_VERIFICATION", { created: true, bytes: 12, fsyncAttempted: true, fsyncCompleted: true, renameCompleted: true, directoryCompleted: 1, final: "PASS" }],
] as const;

test("m4-mutation-receipt-checkpoints: append-forward journal is monotonic at every non-rollback checkpoint", async (t) => {
  const value = await fixture();
  try {
    for (const [index, [stage, facts]] of failureStages.entries()) await t.test(stage, async () => {
      const path = `checkpoint-${index}.txt`; setSecureFilesystemTestHooks({ failStage: stage }); let caught: unknown;
      try { await secureMutation(value.filesystem, { operation: "CREATE", path, expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("replacement\n"), finalMode: 0o644, hashLimitBytes: 1024 }); }
      catch (error: unknown) { caught = error; }
      finally { resetSecureFilesystemTestHooks(); }
      assert.equal(code(caught), "SECURE_WRITE_UNCERTAIN"); const journal = mutationJournalForError(caught); assertJournal(journal);
      assert.equal(journal.temporary_file_created, facts.created); assert.equal(journal.temporary_bytes_written, facts.bytes);
      assert.equal(journal.temporary_file_fsync_attempted, facts.fsyncAttempted); assert.equal(journal.temporary_file_fsync_completed, facts.fsyncCompleted);
      assert.equal(journal.atomic_rename_completed, facts.renameCompleted); assert.equal(journal.directory_fsync_completed_count, facts.directoryCompleted); assert.equal(journal.final_verification, facts.final);
      assert.equal((await readdir(value.repositoryFixture.repository)).some((name) => name.includes(".m4tmp-") || name.includes(".m4tomb-")), false);
    });
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.repositoryFixture); }
});

test("m4-mutation-receipt-checkpoints: rollback failures preserve completed exchange and monotonic rollback facts", async (t) => {
  const stages = [
    ["BEFORE_ROLLBACK", false, 0, false],
    ["DURING_ROLLBACK", false, 0, false],
    ["AFTER_ROLLBACK_EXCHANGE", true, 0, false],
    ["BEFORE_ROLLBACK_DIRECTORY_FSYNC", true, 0, false],
    ["DURING_ROLLBACK_DIRECTORY_FSYNC", true, 0, false],
    ["AFTER_ROLLBACK_DIRECTORY_FSYNC", true, 1, true],
  ] as const;
  for (const [index, [stage, rollbackCompleted, directoryCompleted, rollbackDirectoryCompleted]] of stages.entries()) await t.test(stage, async () => {
    const value = await fixture(); const path = join(value.repositoryFixture.repository, "tracked.txt"); const original = await readFile(path); const authority = await expected(path);
    const displaced = join(value.repositoryFixture.repository, `displaced-${index}.txt`); const socket = join(value.repositoryFixture.root, `rollback-${index}.sock`); let server: Server | undefined;
    try {
      server = await controller(socket, async () => { await rename(path, displaced); await writeFile(path, original, { mode: authority.mode }); });
      setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "BEFORE_RENAME", failStage: stage }); let caught: unknown;
      try { await secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: authority, replacement: Buffer.from("replacement\n"), finalMode: authority.mode, hashLimitBytes: 1024 }); }
      catch (error: unknown) { caught = error; }
      assert.ok(["SECURE_WRITE_UNCERTAIN", "ROLLBACK_UNCERTAIN"].includes(String(code(caught)))); const journal = mutationJournalForError(caught); assertJournal(journal);
      assert.equal(journal.atomic_rename_completed, true); assert.equal(journal.preimage_validation, "FAIL"); assert.equal(journal.rollback_required, true); assert.equal(journal.rollback_attempted, true);
      assert.equal(journal.rollback_completed, rollbackCompleted); assert.equal(journal.directory_fsync_completed_count, directoryCompleted); assert.equal(journal.rollback_directory_fsync_completed, rollbackDirectoryCompleted);
      if (rollbackCompleted) assert.equal(await readFile(path, "utf8"), "initial\n");
    } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(value.repositoryFixture); }
  });
});

test("m4-installed-inode-races: final and temporary namespace races never report success", async (t) => {
  const cases: ReadonlyArray<{ readonly label: string; readonly operation: "CREATE" | "REPLACE"; readonly stage: string; readonly action: (repository: string, target: string) => Promise<void>; readonly restore?: (repository: string) => Promise<void> }> = [
    { label: "CREATE final removed before final open", operation: "CREATE", stage: "RENAMED_BEFORE_FINAL_OPEN", action: async (root, target) => unlink(join(root, target)) },
    { label: "REPLACE final removed before final open", operation: "REPLACE", stage: "EXCHANGED_BEFORE_FINAL_OPEN", action: async (root, target) => unlink(join(root, target)) },
    { label: "CREATE temporary name replaced", operation: "CREATE", stage: "BEFORE_RENAME", action: async (root, target) => { const name = await temporaryName(root, target); await unlink(join(root, name)); await writeFile(join(root, name), "replacement\n", { mode: 0o644 }); } },
    { label: "REPLACE temporary name replaced", operation: "REPLACE", stage: "BEFORE_RENAME", action: async (root, target) => { const name = await temporaryName(root, target); await unlink(join(root, name)); await writeFile(join(root, name), "replacement\n", { mode: 0o644 }); } },
    { label: "CREATE temporary entry removed", operation: "CREATE", stage: "BEFORE_RENAME", action: async (root, target) => unlink(join(root, await temporaryName(root, target))) },
    { label: "CREATE same-byte different-inode temporary", operation: "CREATE", stage: "BEFORE_RENAME", action: async (root, target) => { const name = await temporaryName(root, target); const bytes = await readFile(join(root, name)); await unlink(join(root, name)); await writeFile(join(root, name), bytes, { mode: 0o644 }); } },
    { label: "CREATE final replaced and restored", operation: "CREATE", stage: "RENAMED", action: async (root, target) => { const held = join(root, `${target}.held`); await rename(join(root, target), held); await writeFile(join(root, target), "replacement\n"); await unlink(join(root, target)); await rename(held, join(root, target)); } },
    { label: "CREATE final changed to symlink", operation: "CREATE", stage: "RENAMED", action: async (root, target) => { await unlink(join(root, target)); await symlink("tracked.txt", join(root, target)); } },
  ];
  for (const [index, item] of cases.entries()) await t.test(item.label, async () => {
    const value = await fixture(); const target = item.operation === "CREATE" ? `race-${index}.txt` : "tracked.txt"; const socket = join(value.repositoryFixture.root, `race-${index}.sock`); let server: Server | undefined;
    try {
      const authority = item.operation === "CREATE" ? { digest: null, size: null, mode: null } : await expected(join(value.repositoryFixture.repository, target));
      server = await controller(socket, async () => item.action(value.repositoryFixture.repository, target));
      setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: item.stage }); let caught: unknown;
      try { await secureMutation(value.filesystem, { operation: item.operation, path: target, expected: authority, replacement: Buffer.from("replacement\n"), finalMode: 0o644, hashLimitBytes: 1024 }); }
      catch (error: unknown) { caught = error; }
      assert.equal(code(caught), "SECURE_WRITE_UNCERTAIN"); const journal = mutationJournalForError(caught); assertJournal(journal);
      if (journal.atomic_rename_completed) assert.notEqual(journal.final_verification, "PASS");
      if (item.operation === "REPLACE") assert.equal(await readFile(join(value.repositoryFixture.repository, target), "utf8"), "initial\n");
    } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(value.repositoryFixture); }
  });
  await t.test("parent replaced during final verification", async () => {
    const value = await fixture(); const parent = join(value.repositoryFixture.repository, "scope"); const moved = `${parent}.held`; const socket = join(value.repositoryFixture.root, "parent-final.sock"); let server: Server | undefined;
    try {
      await mkdir(parent); server = await controller(socket, async () => { await rename(parent, moved); await mkdir(parent); });
      setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "BEFORE_FINAL_VERIFICATION" });
      await assert.rejects(secureMutation(value.filesystem, { operation: "CREATE", path: "scope/new.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("replacement\n"), finalMode: 0o644, hashLimitBytes: 1024 }), (error: unknown) => code(error) === "SECURE_WRITE_UNCERTAIN");
    } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await rm(parent, { recursive: true, force: true }); await rename(moved, parent).catch(() => {}); await removeRepositoryFixture(value.repositoryFixture); }
  });
  await t.test("ordinary CREATE and REPLACE retain their installed inode", async () => {
    const value = await fixture(); try {
      const created = await secureMutation(value.filesystem, { operation: "CREATE", path: "positive.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("same\n"), finalMode: 0o644, hashLimitBytes: 1024 });
      assert.equal(created.journal.final_verification, "PASS"); assert.equal(created.after?.inode, (await stat(join(value.repositoryFixture.repository, "positive.txt"))).ino);
      const authority = await expected(join(value.repositoryFixture.repository, "tracked.txt")); const replaced = await secureMutation(value.filesystem, { operation: "REPLACE", path: "tracked.txt", expected: authority, replacement: Buffer.from("initial\n"), finalMode: 0o644, hashLimitBytes: 1024 });
      assert.equal(replaced.journal.final_verification, "PASS"); assert.equal(replaced.after?.inode, (await stat(join(value.repositoryFixture.repository, "tracked.txt"))).ino);
    } finally { await removeRepositoryFixture(value.repositoryFixture); }
  });
});
