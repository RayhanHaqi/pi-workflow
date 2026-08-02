import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { readFile, readdir, stat, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import type { M4MutationJournal, M4MutationReceiptDocument } from "../src/schemas/index.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { createM4Fixture } from "./m4-helpers.js";
import { disposeM4, gatewayCode, gatewayToken } from "./m4-r3-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture } from "./repository-helpers.js";

const failureStages = [
  "BEFORE_TEMPORARY_CREATION", "AFTER_TEMPORARY_CREATION", "AFTER_BYTES_WRITTEN", "BEFORE_TEMPORARY_FSYNC", "DURING_TEMPORARY_FSYNC",
  "AFTER_TEMPORARY_FSYNC", "BEFORE_ATOMIC_RENAME", "AFTER_ATOMIC_RENAME", "BEFORE_DIRECTORY_FSYNC", "DURING_DIRECTORY_FSYNC",
  "AFTER_DIRECTORY_FSYNC", "BEFORE_FINAL_VERIFICATION", "AFTER_FINAL_VERIFICATION",
] as const;

type ReceiptStage = typeof failureStages[number];

async function preimage(path: string) {
  const bytes = await readFile(path); const current = await stat(path);
  return { expectedPreimageDigest: sha256Bytes(bytes), expectedPreimageSize: bytes.byteLength, expectedPreimageMode: current.mode & 0o777 } as const;
}

async function receiptFor(value: Awaited<ReturnType<typeof createM4Fixture>>, path: string): Promise<M4MutationReceiptDocument> {
  const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
  const objects = inspection.managedObjects.filter((entry) => entry.kind === "M4_MUTATION_RECEIPT");
  const documents = await Promise.all(objects.map(async (entry) => JSON.parse(await readFile(join(value.fixture.stateRoot, "runs", value.fixture.runId, entry.relativePath), "utf8")) as M4MutationReceiptDocument));
  const receipt = documents.find((entry) => entry.path === path);
  assert.ok(receipt, `persisted receipt for ${path}`);
  return receipt;
}

function assertMonotonicJournal(journal: M4MutationJournal): void {
  assert.equal(journal.temporary_file_fsync_completed && !journal.temporary_file_fsync_attempted, false);
  assert.equal(journal.atomic_rename_completed && !journal.atomic_rename_attempted, false);
  assert.ok(journal.directory_fsync_completed_count <= journal.directory_fsync_attempt_count);
  assert.equal(journal.rollback_attempted && !journal.rollback_required, false);
  assert.equal(journal.rollback_completed && (!journal.rollback_attempted || !journal.atomic_rename_completed), false);
  assert.equal(journal.rollback_directory_fsync_completed && !journal.rollback_completed, false);
  if (journal.final_verification === "PASS") assert.equal(journal.rollback_required, false);
}

async function closeServer(server: Server | undefined): Promise<void> {
  if (server === undefined) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function checkpointController(path: string, action: () => Promise<void>): Promise<Server> {
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

async function runFailedGatewayMutation(stage: ReceiptStage) {
  const value = await createM4Fixture();
  const target = "tracked.txt";
  try {
    const before = await preimage(value.fixture.trackedPath);
    setSecureFilesystemTestHooks({ failStage: stage });
    let caught: unknown;
    try {
      await value.gateway.apply_patch_scoped({
        stateTokenContentSha256: gatewayToken(value),
        lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
        operation: "REPLACE", path: target, ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE",
        expectedPreimageExists: true, ...before, replacementBytes: Buffer.from(`receipt-${stage}\n`), requestedFinalMode: before.expectedPreimageMode,
      });
    } catch (error: unknown) { caught = error; }
    assert.equal(gatewayCode(caught), "SECURE_WRITE_UNCERTAIN", stage);
    const receipt = await receiptFor(value, target);
    assert.equal(receipt.successor_state_token_content_sha256, null);
    assert.equal(receipt.postflight_content_sha256, null);
    assert.notEqual(receipt.failure_code, null);
    assert.equal(receipt.helper_journal === null, false);
    assertMonotonicJournal(receipt.helper_journal!);
    assert.equal(receipt.file_fsync, receipt.helper_journal!.temporary_file_fsync_completed);
    assert.equal(receipt.atomic_rename, receipt.helper_journal!.atomic_rename_completed);
    assert.equal(receipt.directory_fsync, receipt.helper_journal!.directory_fsync_completed_count > 0);
    assert.equal(receipt.outcome === "APPLIED", false);
    assert.equal(receipt.helper_outcome === "APPLIED", false);
    const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
    assert.ok(inspection.managedRecordClassifications.some((entry) => entry.object.contentSha256 === receipt.content_sha256 && entry.classification === "AUTHORITATIVE_MANAGED_RECORD"));
    const names = await readdir(value.fixture.repository);
    assert.equal(names.some((name) => name.includes(".m4tmp-") || name.includes(".m4tomb-")), false, stage);
  } finally {
    resetSecureFilesystemTestHooks();
    await disposeM4(value);
  }
}

test("m4-persisted-receipt-checkpoints: gateway receipts preserve every supported non-rollback checkpoint", async (t) => {
  for (const stage of failureStages) await t.test(stage, async () => { await runFailedGatewayMutation(stage); });
});

test("m4-persisted-receipt-checkpoints: gateway receipts preserve CREATE, REPLACE, and DELETE success authority", async (t) => {
  await t.test("CREATE", async () => {
    const value = await createM4Fixture();
    try {
      const result = await value.gateway.apply_patch_scoped({ stateTokenContentSha256: gatewayToken(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
        operation: "CREATE", path: "created.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE", expectedPreimageExists: false,
        expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null, replacementBytes: Buffer.from("created\n"), requestedFinalMode: 0o644 });
      const persisted = await receiptFor(value, "created.txt");
      assert.deepEqual(persisted, result.receipt); assert.equal(persisted.outcome, "APPLIED"); assert.equal(persisted.failure_code, null);
      assert.equal(persisted.successor_state_token_content_sha256, result.acceptedState.content_sha256);
    } finally { await disposeM4(value); }
  });
  await t.test("REPLACE", async () => {
    const value = await createM4Fixture();
    try {
      const before = await preimage(value.fixture.trackedPath);
      const result = await value.gateway.apply_patch_scoped({ stateTokenContentSha256: gatewayToken(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
        operation: "REPLACE", path: "tracked.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE", expectedPreimageExists: true,
        ...before, replacementBytes: Buffer.from("replaced\n"), requestedFinalMode: before.expectedPreimageMode });
      const persisted = await receiptFor(value, "tracked.txt");
      assert.deepEqual(persisted, result.receipt); assert.deepEqual(persisted.before, { digest: before.expectedPreimageDigest, size: before.expectedPreimageSize, mode: before.expectedPreimageMode });
      assert.equal(persisted.outcome, "APPLIED"); assert.equal(persisted.failure_code, null);
    } finally { await disposeM4(value); }
  });
  await t.test("DELETE", async () => {
    const value = await createM4Fixture();
    try {
      const before = await preimage(value.fixture.trackedPath);
      const result = await value.gateway.apply_patch_scoped({ stateTokenContentSha256: gatewayToken(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
        operation: "DELETE", path: "tracked.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE", expectedPreimageExists: true,
        ...before, replacementBytes: null, requestedFinalMode: null });
      const persisted = await receiptFor(value, "tracked.txt");
      assert.deepEqual(persisted, result.receipt); assert.deepEqual(persisted.after, { digest: null, size: null, mode: null }); assert.equal(persisted.outcome, "APPLIED");
    } finally { await disposeM4(value); }
  });
});

test("m4-persisted-receipt-checkpoints: every gateway rollback checkpoint preserves uncertainty and monotonic activity", async (t) => {
  const stages = ["BEFORE_ROLLBACK", "DURING_ROLLBACK", "AFTER_ROLLBACK_EXCHANGE", "BEFORE_ROLLBACK_DIRECTORY_FSYNC", "DURING_ROLLBACK_DIRECTORY_FSYNC", "AFTER_ROLLBACK_DIRECTORY_FSYNC"] as const;
  for (const [index, stage] of stages.entries()) await t.test(stage, async () => {
    const value = await createM4Fixture();
    const target = value.fixture.trackedPath; const displaced = `${target}.r3-${index}`; const socket = join(value.fixture.root, `receipt-${index}.sock`); let server: Server | undefined;
    try {
      const before = await preimage(target);
      server = await checkpointController(socket, async () => { await rename(target, displaced); await writeFile(target, await readFile(displaced), { mode: before.expectedPreimageMode }); });
      setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "BEFORE_RENAME", failStage: stage });
      let caught: unknown;
      try {
        await value.gateway.apply_patch_scoped({ stateTokenContentSha256: gatewayToken(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
          operation: "REPLACE", path: "tracked.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE", expectedPreimageExists: true,
          ...before, replacementBytes: Buffer.from(`gateway-rollback-${stage}\n`), requestedFinalMode: before.expectedPreimageMode });
      } catch (error: unknown) { caught = error; }
      assert.ok(["SECURE_WRITE_UNCERTAIN", "ROLLBACK_UNCERTAIN"].includes(gatewayCode(caught) ?? ""));
      const receipt = await receiptFor(value, "tracked.txt");
      assert.equal(receipt.outcome, "UNCERTAIN"); assert.equal(receipt.helper_outcome, "UNCERTAIN"); assert.equal(receipt.rollback_outcome, "UNKNOWN");
      assert.equal(receipt.successor_state_token_content_sha256, null); assert.equal(receipt.postflight_content_sha256, null);
      assert.equal(receipt.helper_journal?.rollback_required, true); assert.equal(receipt.helper_journal?.rollback_attempted, true); assertMonotonicJournal(receipt.helper_journal!);
      const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
      assert.ok(inspection.managedRecordClassifications.some((entry) => entry.object.contentSha256 === receipt.content_sha256 && entry.classification === "AUTHORITATIVE_MANAGED_RECORD"));
    } finally { resetSecureFilesystemTestHooks(); await closeServer(server); await disposeM4(value); }
  });
});

test("m4-persisted-receipt-checkpoints: preimage mismatch and rollback failure publish truthful uncertainty", async () => {
  const value = await createM4Fixture();
  const target = value.fixture.trackedPath;
  const original = await readFile(target);
  const displaced = `${target}.r3-displaced`;
  const socket = join(value.fixture.root, "receipt-rollback.sock");
  let server: Server | undefined;
  try {
    const before = await preimage(target);
    server = await checkpointController(socket, async () => {
      await rename(target, displaced);
      await writeFile(target, original, { mode: before.expectedPreimageMode });
    });
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "BEFORE_RENAME", failStage: "BEFORE_ROLLBACK" });
    let caught: unknown;
    try {
      await value.gateway.apply_patch_scoped({ stateTokenContentSha256: gatewayToken(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
        operation: "REPLACE", path: "tracked.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE", expectedPreimageExists: true,
        ...before, replacementBytes: Buffer.from("rollback-uncertain\n"), requestedFinalMode: before.expectedPreimageMode });
    } catch (error: unknown) { caught = error; }
    assert.ok(["SECURE_WRITE_UNCERTAIN", "ROLLBACK_UNCERTAIN"].includes(gatewayCode(caught) ?? ""));
    const receipt = await receiptFor(value, "tracked.txt");
    assert.equal(receipt.outcome, "UNCERTAIN"); assert.equal(receipt.helper_outcome, "UNCERTAIN"); assert.equal(receipt.successor_state_token_content_sha256, null);
    assert.equal(receipt.rollback_outcome, "UNKNOWN"); assert.equal(receipt.helper_journal?.rollback_required, true); assert.equal(receipt.helper_journal?.rollback_attempted, true);
    assert.equal(receipt.helper_journal?.rollback_completed, false); assertMonotonicJournal(receipt.helper_journal!);
  } finally {
    resetSecureFilesystemTestHooks(); await closeServer(server); await removeRepositoryFixture(value.fixture); await releaseAdmission(value.admission);
  }
});
