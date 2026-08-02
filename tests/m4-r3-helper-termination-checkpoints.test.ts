import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { lstat, readFile, readdir, stat, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { probeSecureFilesystemCapabilities, createSecureFilesystem } from "../src/secure-fs/index.js";
import { secureMutation } from "../src/secure-fs/client.js";
import { mutationJournalForError } from "../src/secure-fs/helper.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import type { M4MutationJournal } from "../src/schemas/index.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";

const stages = [
  "BEFORE_TEMPORARY_CREATION", "AFTER_TEMPORARY_CREATION", "AFTER_BYTES_WRITTEN", "BEFORE_TEMPORARY_FSYNC", "DURING_TEMPORARY_FSYNC",
  "AFTER_TEMPORARY_FSYNC", "BEFORE_RENAME", "BEFORE_ATOMIC_RENAME", "AFTER_ATOMIC_RENAME", "BEFORE_DIRECTORY_FSYNC", "DURING_DIRECTORY_FSYNC",
  "AFTER_DIRECTORY_FSYNC", "BEFORE_FINAL_VERIFICATION", "AFTER_FINAL_VERIFICATION", "BEFORE_HELPER_RESPONSE_COMPLETION",
] as const;
const rollbackStages = ["BEFORE_ROLLBACK", "AFTER_ROLLBACK_EXCHANGE", "BEFORE_ROLLBACK_DIRECTORY_FSYNC", "DURING_ROLLBACK_DIRECTORY_FSYNC", "AFTER_ROLLBACK_DIRECTORY_FSYNC"] as const;
const PREIMAGE_STAGES = ["BEFORE_PREIMAGE_VALIDATION", "AFTER_FAILED_PREIMAGE_VALIDATION"] as const;

type DirectFixture = Awaited<ReturnType<typeof directFixture>>;

async function directFixture() {
  const repositoryFixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: repositoryFixture.repository, requireHead: true });
  const capability = await probeSecureFilesystemCapabilities();
  const filesystem = await createSecureFilesystem({ repository, capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] });
  return { repositoryFixture, filesystem };
}

async function closeServer(server: Server | undefined): Promise<void> {
  if (server === undefined) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function controller(path: string, action: () => Promise<void>): Promise<Server> {
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

function journal(error: unknown): M4MutationJournal {
  const value = mutationJournalForError(error);
  assert.ok(value, "helper termination must publish its latest journal");
  assert.equal(value.temporary_file_fsync_completed && !value.temporary_file_fsync_attempted, false);
  assert.equal(value.atomic_rename_completed && !value.atomic_rename_attempted, false);
  assert.ok(value.directory_fsync_completed_count <= value.directory_fsync_attempt_count);
  assert.equal(value.rollback_attempted && !value.rollback_required, false);
  assert.equal(value.rollback_completed && (!value.rollback_attempted || !value.atomic_rename_completed), false);
  assert.equal(value.rollback_directory_fsync_completed && !value.rollback_completed, false);
  return value;
}

type TargetExpectation =
  | { readonly kind: "ABSENT" }
  | { readonly kind: "REGULAR"; readonly bytes: Buffer; readonly mode: number; readonly device?: number; readonly inode?: number };

async function assertTarget(path: string, expectation: TargetExpectation): Promise<void> {
  if (expectation.kind === "ABSENT") {
    await assert.rejects(lstat(path), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
    return;
  }
  const identity = await lstat(path);
  assert.equal(identity.isFile(), true); assert.equal(identity.isSymbolicLink(), false); assert.equal(identity.nlink, 1);
  assert.equal(identity.mode & 0o777, expectation.mode);
  if (expectation.device !== undefined) assert.equal(identity.dev, expectation.device);
  if (expectation.inode !== undefined) assert.equal(identity.ino, expectation.inode);
  assert.deepEqual(await readFile(path), expectation.bytes);
}

function recoveryDetails(error: unknown): Record<string, unknown> {
  const value = (error as { readonly details?: unknown }).details;
  assert.ok(value && typeof value === "object");
  return value as Record<string, unknown>;
}

async function assertNoMutationResidue(fixture: DirectFixture, target: string, expectation: TargetExpectation, verification: string, error: unknown): Promise<void> {
  const names = await readdir(fixture.repositoryFixture.repository);
  const mutationEntries = names.filter((name) => name.includes(".m4tmp-") || name.includes(".m4tomb-"));
  assert.deepEqual(mutationEntries, []);
  const inspection = await inspectRunStorage({ stateRoot: fixture.repositoryFixture.stateRoot, runId: fixture.repositoryFixture.runId });
  assert.equal(inspection.status, "HEALTHY");
  await assertTarget(join(fixture.repositoryFixture.repository, target), expectation);
  const details = recoveryDetails(error);
  assert.equal(details["residue_cleanup_attempted"], true);
  assert.equal(details["residue_cleanup_outcome"], "SUCCEEDED");
  assert.equal(details["remaining_operation_residue_count"], 0);
  assert.equal(details["recovery_directory_fsync_outcome"], "SUCCEEDED");
  assert.equal(details["target_verification_outcome"], verification);
}

async function killAtStage(stage: string, index: number): Promise<void> {
  const fixture = await directFixture();
  const socket = join(fixture.repositoryFixture.root, `kill-${index}.sock`);
  let server: Server | undefined;
  const target = `termination-${index}.txt`;
  try {
    server = await controller(socket, async () => {});
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: stage, helperKillStage: stage });
    let caught: unknown;
    try {
      await (await import("../src/secure-fs/client.js")).secureMutation(fixture.filesystem, {
        operation: "CREATE", path: target, expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("termination\n"), finalMode: 0o644, hashLimitBytes: 1024,
      });
    } catch (error: unknown) { caught = error; }
    assert.notEqual(caught, undefined, stage);
    assert.equal((caught as { readonly code?: unknown }).code, "SECURE_WRITE_UNCERTAIN", stage);
    journal(caught);
    const preRename = ["BEFORE_TEMPORARY_CREATION", "AFTER_TEMPORARY_CREATION", "AFTER_BYTES_WRITTEN", "BEFORE_TEMPORARY_FSYNC", "DURING_TEMPORARY_FSYNC", "AFTER_TEMPORARY_FSYNC", "BEFORE_RENAME", "BEFORE_ATOMIC_RENAME"].includes(stage);
    await assertNoMutationResidue(fixture, target, preRename ? { kind: "ABSENT" } : { kind: "REGULAR", bytes: Buffer.from("termination\n"), mode: 0o644 }, preRename ? "ABSENT" : "REPLACEMENT", caught);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(fixture.repositoryFixture); }
}

const REPORTED_PRE_RENAME_STAGES = ["AFTER_TEMPORARY_CREATION", "AFTER_BYTES_WRITTEN", "BEFORE_TEMPORARY_FSYNC", "DURING_TEMPORARY_FSYNC", "AFTER_TEMPORARY_FSYNC", "BEFORE_ATOMIC_RENAME"] as const;
const DELETE_TERMINATION_STAGES = ["BEFORE_RENAME", "BEFORE_ATOMIC_RENAME", "AFTER_ATOMIC_RENAME", "TOMBSTONED", "BEFORE_DIRECTORY_FSYNC", "DURING_DIRECTORY_FSYNC", "AFTER_DIRECTORY_FSYNC", "BEFORE_FINAL_VERIFICATION", "AFTER_FINAL_VERIFICATION", "BEFORE_HELPER_RESPONSE_COMPLETION"] as const;

type MutationOperation = "CREATE" | "REPLACE" | "DELETE";

async function killOperationAtStage(operation: MutationOperation, stage: string, index: number): Promise<void> {
  const fixture = await directFixture(); const socket = join(fixture.repositoryFixture.root, `operation-${operation}-${index}.sock`); let server: Server | undefined;
  const target = operation === "CREATE" ? `operation-${operation}-${index}.txt` : "tracked.txt";
  let before: { readonly bytes: Buffer; readonly mode: number; readonly device: number; readonly inode: number } | undefined;
  try {
    if (operation !== "CREATE") { const bytes = await readFile(fixture.repositoryFixture.trackedPath); const value = await stat(fixture.repositoryFixture.trackedPath); before = { bytes, mode: value.mode & 0o777, device: value.dev, inode: value.ino }; }
    server = await controller(socket, async () => {});
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: stage, helperKillStage: stage });
    let caught: unknown;
    try {
      await secureMutation(fixture.filesystem, operation === "CREATE"
        ? { operation, path: target, expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("operation\n"), finalMode: 0o644, hashLimitBytes: 1024 }
        : operation === "REPLACE"
          ? { operation, path: target, expected: { digest: sha256Bytes(before!.bytes), size: before!.bytes.byteLength, mode: before!.mode }, replacement: Buffer.from("operation\n"), finalMode: before!.mode, hashLimitBytes: 1024 }
          : { operation, path: target, expected: { digest: sha256Bytes(before!.bytes), size: before!.bytes.byteLength, mode: before!.mode }, replacement: null, finalMode: null, hashLimitBytes: 1024 });
    } catch (error: unknown) { caught = error; }
    assert.equal((caught as { readonly code?: unknown }).code, "SECURE_WRITE_UNCERTAIN", `${operation}:${stage}`);
    journal(caught);
    const preRename = operation === "DELETE" ? stage === "BEFORE_RENAME" || stage === "BEFORE_ATOMIC_RENAME" : ["BEFORE_TEMPORARY_CREATION", ...REPORTED_PRE_RENAME_STAGES, "BEFORE_RENAME"].includes(stage as never);
    const expectation: TargetExpectation = operation === "CREATE"
      ? (preRename ? { kind: "ABSENT" } : { kind: "REGULAR", bytes: Buffer.from("operation\n"), mode: 0o644 })
      : operation === "REPLACE"
        ? (preRename ? { kind: "REGULAR", bytes: before!.bytes, mode: before!.mode, device: before!.device, inode: before!.inode } : { kind: "REGULAR", bytes: Buffer.from("operation\n"), mode: before!.mode })
        : (preRename ? { kind: "REGULAR", bytes: before!.bytes, mode: before!.mode, device: before!.device, inode: before!.inode } : { kind: "ABSENT" });
    const verification = operation === "CREATE" ? (preRename ? "ABSENT" : "REPLACEMENT") : operation === "REPLACE" ? (preRename ? "PREIMAGE" : "REPLACEMENT") : (preRename ? "PREIMAGE" : "ABSENT");
    await assertNoMutationResidue(fixture, target, expectation, verification, caught);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(fixture.repositoryFixture); }
}

async function killBeforeOrAfterPreimage(stage: typeof PREIMAGE_STAGES[number], index: number): Promise<void> {
  const fixture = await directFixture();
  const socket = join(fixture.repositoryFixture.root, `preimage-${index}.sock`);
  let server: Server | undefined;
  try {
    server = await controller(socket, async () => {});
    const current = await readFile(fixture.repositoryFixture.trackedPath); const currentStat = await stat(fixture.repositoryFixture.trackedPath);
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: stage, helperKillStage: stage });
    let caught: unknown;
    try {
      await (await import("../src/secure-fs/client.js")).secureMutation(fixture.filesystem, {
        operation: "REPLACE", path: "tracked.txt", expected: { digest: sha256Bytes(Buffer.from("wrong")), size: current.length, mode: currentStat.mode & 0o777 }, replacement: Buffer.from("replacement\n"), finalMode: currentStat.mode & 0o777, hashLimitBytes: 1024,
      });
    } catch (error: unknown) { caught = error; }
    assert.equal((caught as { readonly code?: unknown }).code, "SECURE_WRITE_UNCERTAIN", stage);
    const value = journal(caught); assert.equal(value.temporary_file_created, false); assert.equal(value.atomic_rename_completed, false);
    await assertNoMutationResidue(fixture, "tracked.txt", { kind: "REGULAR", bytes: Buffer.from("initial\n"), mode: currentStat.mode & 0o777, device: currentStat.dev, inode: currentStat.ino }, "MISMATCH", caught);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(fixture.repositoryFixture); }
}

async function killDuringRollback(stage: typeof rollbackStages[number], index: number): Promise<void> {
  const fixture = await directFixture();
  const beforeSocket = join(fixture.repositoryFixture.root, `rollback-before-${index}.sock`);
  const killSocket = join(fixture.repositoryFixture.root, `rollback-kill-${index}.sock`);
  const displaced = join(fixture.repositoryFixture.root, `rollback-displaced-${index}.txt`);
  let beforeServer: Server | undefined; let killServer: Server | undefined;
  try {
    const target = fixture.repositoryFixture.trackedPath; const original = await readFile(target); const authority = await stat(target);
    beforeServer = await controller(beforeSocket, async () => { await rename(target, displaced); await writeFile(target, original, { mode: authority.mode & 0o777 }); });
    killServer = await controller(killSocket, async () => {});
    setSecureFilesystemTestHooks({ checkpointSocket: beforeSocket, checkpointStage: "BEFORE_RENAME", secondaryCheckpointSocket: killSocket, secondaryCheckpointStage: stage, helperKillStage: stage });
    let caught: unknown;
    try {
      await (await import("../src/secure-fs/client.js")).secureMutation(fixture.filesystem, {
        operation: "REPLACE", path: "tracked.txt", expected: { digest: sha256Bytes(original), size: original.length, mode: authority.mode & 0o777 }, replacement: Buffer.from("rollback\n"), finalMode: authority.mode & 0o777, hashLimitBytes: 1024,
      });
    } catch (error: unknown) { caught = error; }
    assert.equal((caught as { readonly code?: unknown }).code, "SECURE_WRITE_UNCERTAIN", stage);
    const value = journal(caught);
    assert.equal(value.atomic_rename_completed, true); assert.equal(value.rollback_required, true); assert.equal(value.rollback_attempted, true);
    await assertNoMutationResidue(fixture, "tracked.txt", { kind: "REGULAR", bytes: Buffer.from("initial\n"), mode: authority.mode & 0o777 }, "MISMATCH", caught);
  } finally { resetSecureFilesystemTestHooks(); await closeServer(beforeServer); await closeServer(killServer); await removeRepositoryFixture(fixture.repositoryFixture); }
}

test("m4-helper-termination-checkpoints: helper death at every forward checkpoint is uncertain and self-cleaning", async (t) => {
  for (const [index, stage] of stages.entries()) await t.test(stage, async () => { await killAtStage(stage, index); });
});

test("m4-r4-helper-termination: all six pre-rename checkpoints recover CREATE, REPLACE, and DELETE", async (t) => {
  let index = 0;
  for (const operation of ["CREATE", "REPLACE"] as const) {
    for (const stage of REPORTED_PRE_RENAME_STAGES) {
      const current = index++;
      await t.test(`${operation}:${stage}`, async () => { await killOperationAtStage(operation, stage, current); });
    }
  }
  for (const stage of ["BEFORE_RENAME", "BEFORE_ATOMIC_RENAME"] as const) {
    const current = index++;
    await t.test(`DELETE:${stage}`, async () => { await killOperationAtStage("DELETE", stage, current); });
  }
});

test("m4-r4-helper-termination: later CREATE, REPLACE, and DELETE checkpoints recover without residue", async (t) => {
  for (const operation of ["CREATE", "REPLACE"] as const) {
    for (const [index, stage] of stages.filter((value) => !["BEFORE_TEMPORARY_CREATION", "AFTER_TEMPORARY_CREATION", "AFTER_BYTES_WRITTEN", "BEFORE_TEMPORARY_FSYNC", "DURING_TEMPORARY_FSYNC", "AFTER_TEMPORARY_FSYNC"].includes(value)).entries()) {
      await t.test(`${operation}:${stage}`, async () => { await killOperationAtStage(operation, stage, 100 + index + (operation === "REPLACE" ? 100 : 0)); });
    }
  }
  for (const [index, stage] of DELETE_TERMINATION_STAGES.entries()) await t.test(`DELETE:${stage}`, async () => { await killOperationAtStage("DELETE", stage, 300 + index); });
});

test("m4-helper-termination-checkpoints: helper death before and after failed preimage validation is classified", async (t) => {
  for (const [index, stage] of PREIMAGE_STAGES.entries()) await t.test(stage, async () => { await killBeforeOrAfterPreimage(stage, index); });
});

test("m4-helper-termination-checkpoints: helper death at every rollback checkpoint never claims success", async (t) => {
  for (const [index, stage] of rollbackStages.entries()) await t.test(stage, async () => { await killDuringRollback(stage, index); });
});
