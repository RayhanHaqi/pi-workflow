import assert from "node:assert/strict";
import { execFile, fork } from "node:child_process";
import { createServer } from "node:net";
import { promisify } from "node:util";
import { chmod, lstat, mkdir, mkdtemp, readdir, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import { commitTransition, inspectRunStorage } from "../src/persistence/index.js";
import { inspectRunStorageForRetention } from "../src/persistence/store.js";
import { identifyContractDocument, type M3RetentionResultDocument } from "../src/schemas/index.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  createTerminalRetentionAuthority,
  inspectRetention,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";
import { baselineBlobPath, canonicalJsonRecordBytes } from "../src/repository/storage.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { reduceState } from "../src/state-machine/index.js";
import { transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import {
  approveDirtyBaseline,
  baselineInput,
  codeOf,
  createTerminalBlobFixture,
  pathDecision,
  readRetentionRecords,
  retentionInput,
} from "./repository-matrix-helpers.js";
import {
  createRepositoryFixture,
  instructionAuthorityInputs,
  removeRepositoryFixture,
} from "./repository-helpers.js";

const execFileAsync = promisify(execFile);

type TerminalValue = Awaited<ReturnType<typeof createTerminalBlobFixture>>;

function blobPath(value: TerminalValue): string {
  const blob = value.baseline.paths[0]?.blob;
  assert.ok(blob);
  return baselineBlobPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, blob.blob_sha256);
}

function cleanupResults(records: readonly Record<string, unknown>[]): readonly M3RetentionResultDocument[] {
  return records.filter((record) => record["operation"] === "CLEANUP") as unknown as readonly M3RetentionResultDocument[];
}

async function assertTargetFailure(
  name: string,
  expectedCode: string,
  mutate: (value: TerminalValue, path: string) => Promise<(() => Promise<void>) | undefined>,
): Promise<void> {
  const sentinel = `RESTRICTED_${name.replaceAll(" ", "_")}_SENTINEL`;
  const value = await createTerminalBlobFixture([{ name: "retained.txt", bytes: sentinel }]);
  let cleanup: (() => Promise<void>) | undefined;
  try {
    const path = blobPath(value);
    cleanup = await mutate(value, path);
    await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
    const firstRecords = await readRetentionRecords(value.fixture);
    const first = cleanupResults(firstRecords).at(-1);
    assert.ok(first);
    assert.equal(first.outcome, "FAILED");
    assert.equal(first.blobs[0]?.result, "FAILED");
    assert.equal(first.blobs[0]?.detail_code, expectedCode);
    assert.equal(first.blobs[0]?.unlink_performed, false);
    assert.equal(first.blobs[0]?.directory_fsync_performed, false);
    assert.equal(JSON.stringify(first).includes(sentinel), false);
    if (expectedCode !== "TARGET_MISSING") await lstat(path);

    const count = firstRecords.length;
    await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
    assert.equal((await readRetentionRecords(value.fixture)).length, count);

    const blob = value.baseline.paths[0]?.blob;
    assert.ok(blob);
    const trusted = await inspectRunStorageForRetention(
      { stateRoot: value.fixture.stateRoot, runId: value.fixture.runId },
      [blob.blob_sha256 as Sha256Digest],
    );
    assert.equal(trusted.status, "HEALTHY");
    assert.equal(trusted.workflowState?.content_sha256, value.terminalState.content_sha256);
  } finally {
    resetRepositoryTestHooks();
    await cleanup?.();
    await removeRepositoryFixture(value.fixture);
  }
}

test("eligible retention target-local failures publish exact immutable no-delete results", async (t) => {
  const cases: readonly [string, string, (value: TerminalValue, path: string) => Promise<(() => Promise<void>) | undefined>][] = [
    ["missing", "TARGET_MISSING", async (_value, path) => { await unlink(path); return undefined; }],
    ["modified digest", "TARGET_DIGEST_MISMATCH", async (_value, path) => {
      const size = (await lstat(path)).size;
      await writeFile(path, Buffer.alloc(size, 0x58), { mode: 0o600 });
      await chmod(path, 0o600);
      return undefined;
    }],
    ["wrong size", "TARGET_SIZE_MISMATCH", async (_value, path) => {
      await writeFile(path, "different-size", { mode: 0o600 });
      await chmod(path, 0o600);
      return undefined;
    }],
    ["wrong mode", "TARGET_MODE_MISMATCH", async (_value, path) => { await chmod(path, 0o640); return undefined; }],
    ["symlink", "TARGET_SYMLINK", async (value, path) => { await unlink(path); await symlink(value.fixture.trackedPath, path); return undefined; }],
    ["directory", "TARGET_DIRECTORY", async (_value, path) => { await unlink(path); await mkdir(path, { mode: 0o700 }); return undefined; }],
    ["FIFO", "TARGET_SPECIAL_FILE", async (_value, path) => { await unlink(path); await execFileAsync("mkfifo", [path]); return undefined; }],
    ["Unix socket", "TARGET_SPECIAL_FILE", async (_value, path) => {
      await unlink(path);
      const alias = await mkdtemp(join(tmpdir(), "s-"));
      await rm(alias, { recursive: true });
      await symlink(dirname(path), alias, "dir");
      const server = createServer();
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(join(alias, basename(path)), resolve);
      });
      return async () => {
        await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
        await rm(alias, { force: true });
      };
    }],
    ["unreadable regular", "TARGET_READ_FAILED", async (value) => {
      const blob = value.baseline.paths[0]?.blob;
      assert.ok(blob);
      configureRepositoryTestHooks({ retentionTargetReadFailureDigest: blob.blob_sha256 });
      return undefined;
    }],
  ];
  for (const [name, code, mutate] of cases) {
    await t.test(name, async () => assertTargetFailure(name, code, mutate));
  }
});

test("retention operational failures report exact unlink/fsync/publication state", async (t) => {
  await t.test("unlink failure preserves target and publishes result", async () => {
    const value = await createTerminalBlobFixture();
    try {
      configureRepositoryTestHooks({ beforeRetentionUnlink: () => { throw new Error("injected unlink failure"); } });
      await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
      const result = cleanupResults(await readRetentionRecords(value.fixture)).at(-1);
      assert.equal(result?.blobs[0]?.detail_code, "TARGET_UNLINK_FAILED");
      assert.equal(result?.blobs[0]?.unlink_performed, false);
      assert.equal(result?.blobs[0]?.directory_fsync_performed, false);
      await lstat(blobPath(value));
    } finally {
      resetRepositoryTestHooks();
      await removeRepositoryFixture(value.fixture);
    }
  });

  await t.test("directory fsync failure records the post-unlink window", async () => {
    const value = await createTerminalBlobFixture();
    try {
      configureRepositoryTestHooks({ beforeRetentionDirectorySync: () => { throw new Error("injected fsync failure"); } });
      await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
      const result = cleanupResults(await readRetentionRecords(value.fixture)).at(-1);
      assert.equal(result?.outcome, "PARTIAL");
      assert.equal(result?.blobs[0]?.detail_code, "TARGET_DIRECTORY_FSYNC_FAILED");
      assert.equal(result?.blobs[0]?.unlink_performed, true);
      assert.equal(result?.blobs[0]?.directory_fsync_performed, false);
      await assert.rejects(lstat(blobPath(value)));
    } finally {
      resetRepositoryTestHooks();
      await removeRepositoryFixture(value.fixture);
    }
  });

  await t.test("failure-result publication failure is distinct and preserves target", async () => {
    const value = await createTerminalBlobFixture();
    try {
      const path = blobPath(value);
      await chmod(path, 0o640);
      configureRepositoryTestHooks({ beforeRetentionResultPublication: () => { throw new Error("injected publication failure"); } });
      await assert.rejects(
        applyRetentionCleanup(retentionInput(value)),
        (error: unknown) => codeOf(error) === "RETENTION_RESULT_PUBLICATION_FAILED",
      );
      assert.equal((await readRetentionRecords(value.fixture)).length, 0);
      await lstat(path);
    } finally {
      resetRepositoryTestHooks();
      await removeRepositoryFixture(value.fixture);
    }
  });

  await t.test("partial multi-blob cleanup reports each durable stage", async () => {
    const value = await createTerminalBlobFixture([{ name: "one.txt" }, { name: "two.txt" }]);
    let calls = 0;
    try {
      configureRepositoryTestHooks({
        beforeRetentionDirectorySync: () => {
          calls += 1;
          if (calls === 1) throw new Error("first fsync fails");
        },
      });
      await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
      const result = cleanupResults(await readRetentionRecords(value.fixture)).at(-1);
      assert.equal(result?.outcome, "PARTIAL");
      assert.deepEqual(result?.blobs.map((blob) => [blob.unlink_performed, blob.directory_fsync_performed]), [
        [true, false],
        [true, true],
      ]);
    } finally {
      resetRepositoryTestHooks();
      await removeRepositoryFixture(value.fixture);
    }
  });
});

test("retention eligibility, deadlines, authority, storage, and lock boundaries are exact", async (t) => {
  await t.test("sensitive seven-day and normal thirty-day deadlines", async () => {
    const sensitive = await createTerminalBlobFixture([{ name: "sensitive.txt", dataClass: "SENSITIVE", retentionDays: 7 }]);
    const normal = await createTerminalBlobFixture([{ name: "normal.txt", retentionDays: 30 }]);
    try {
      await assert.rejects(
        applyRetentionCleanup(retentionInput(sensitive, "2026-01-07T23:59:59.999Z")),
        (error: unknown) => codeOf(error) === "RETENTION_DEADLINE_NOT_REACHED",
      );
      assert.equal((await applyRetentionCleanup(retentionInput(sensitive, "2026-01-08T00:00:00.000Z"))).outcome, "COMPLETE");
      await assert.rejects(
        applyRetentionCleanup(retentionInput(normal, "2026-01-30T23:59:59.999Z")),
        (error: unknown) => codeOf(error) === "RETENTION_DEADLINE_NOT_REACHED",
      );
      assert.equal((await applyRetentionCleanup(retentionInput(normal))).outcome, "COMPLETE");
    } finally {
      await removeRepositoryFixture(sensitive.fixture);
      await removeRepositoryFixture(normal.fixture);
    }
  });

  await t.test("successful cleanup and inspection are result-backed and idempotent", async () => {
    const value = await createTerminalBlobFixture();
    try {
      const inspected = await inspectRetention(retentionInput(value));
      assert.equal(inspected.outcome, "ELIGIBLE");
      assert.equal(inspected.blobs[0]?.unlink_performed, false);
      const success = await applyRetentionCleanup(retentionInput(value));
      assert.equal(success.outcome, "COMPLETE");
      assert.equal(success.worktree_key, value.authority.worktree_key);
      assert.equal(success.terminal_authority_content_sha256, value.authority.content_sha256);
      assert.equal(success.blobs[0]?.result, "SUCCEEDED");
      assert.deepEqual(
        {
          blob_sha256: success.blobs[0]?.blob_sha256,
          byte_length: success.blobs[0]?.byte_length,
          data_class: success.blobs[0]?.data_class,
          retention_deadline: success.blobs[0]?.retention_deadline,
        },
        {
          blob_sha256: value.authority.blobs[0]?.blob_sha256,
          byte_length: value.authority.blobs[0]?.byte_length,
          data_class: value.authority.blobs[0]?.data_class,
          retention_deadline: value.authority.blobs[0]?.retention_deadline,
        },
      );
      assert.equal(Object.isFrozen(success), true);
      assert.equal(Object.isFrozen(success.blobs), true);
      const repeat = await applyRetentionCleanup(retentionInput(value));
      assert.equal(repeat.outcome, "IDEMPOTENT");
      assert.equal(repeat.blobs[0]?.result, "IDEMPOTENT");
      const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
      assert.equal(inspection.status, "HEALTHY");
      assert.ok(inspection.managedObjects.filter((entry) => entry.kind === "M3_RETENTION_RESULT").length >= 3);
    } finally {
      await removeRepositoryFixture(value.fixture);
    }
  });

  await t.test("managed result directory compromise and invalid authority fabricate no result", async () => {
    const compromised = await createTerminalBlobFixture();
    try {
      const directory = join(compromised.fixture.stateRoot, "runs", compromised.fixture.runId, "records", "retention");
      await chmod(directory, 0o755);
      await assert.rejects(applyRetentionCleanup(retentionInput(compromised)), (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID");
      assert.equal((await readdir(directory)).length, 0);
    } finally {
      await removeRepositoryFixture(compromised.fixture);
    }

    const invalid = await createTerminalBlobFixture();
    try {
      const draft = structuredClone(invalid.authority) as unknown as Record<string, unknown>;
      delete draft["content_sha256"];
      draft["baseline_runtime_content_sha256"] = `sha256:${"0".repeat(64)}`;
      const authority = identifyContractDocument("pi_gacw_terminal_retention_authority_v0", draft) as never;
      await assert.rejects(
        applyRetentionCleanup({ ...retentionInput(invalid), terminalAuthority: authority }),
        (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN",
      );
      assert.equal((await readRetentionRecords(invalid.fixture)).length, 0);
    } finally {
      await removeRepositoryFixture(invalid.fixture);
    }
  });

  await t.test("active competing lock and guardian loss block before result publication", async () => {
    const busy = await createTerminalBlobFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: busy.fixture.repository, requireHead: true });
    const held = await acquireWorktreeLock({ stateRoot: busy.fixture.stateRoot, repository });
    try {
      await assert.rejects(applyRetentionCleanup(retentionInput(busy)), (error: unknown) => codeOf(error) === "LOCK_BUSY");
      assert.equal((await readRetentionRecords(busy.fixture)).length, 0);
    } finally {
      await releaseWorktreeLock(held);
      await removeRepositoryFixture(busy.fixture);
    }

    const lost = await createTerminalBlobFixture();
    try {
      configureRepositoryTestHooks({ afterRetentionLockAcquired: (pid) => { process.kill(pid, "SIGKILL"); } });
      await assert.rejects(applyRetentionCleanup(retentionInput(lost)), (error: unknown) => codeOf(error) === "LOCK_LOST");
      assert.equal((await readRetentionRecords(lost.fixture)).length, 0);
    } finally {
      resetRepositoryTestHooks();
      await removeRepositoryFixture(lost.fixture);
    }
  });
});

async function uncommittedRetentionFixture(commitAuthorityEvidence: boolean) {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await writeFile(join(fixture.repository, "retained.txt"), "retained\n");
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("retained.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
    ]))).baseline;
    const approval = await approveDirtyBaseline(fixture, baseline);
    const event = transitionEvent("BLOCK", { reason: "RETENTION_AUTHORITY_MATRIX" });
    const terminalState = reduceState(fixture.initialState, event, fixture.policy);
    const authority = createTerminalRetentionAuthority({ baseline, approval, terminalWorkflowState: terminalState, terminalTimestamp: "2026-01-01T00:00:00.000Z" });
    if (commitAuthorityEvidence) {
      await commitTransition({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        expectedRevision: fixture.committed.statePointer.revision,
        expectedStatePointerContentSha256: fixture.committed.statePointer.content_sha256 as Sha256Digest,
        expectedWorkflowStateContentSha256: fixture.committed.workflowState.content_sha256 as Sha256Digest,
        expectedNextWorkflowStateContentSha256: terminalState.content_sha256 as Sha256Digest,
        transitionId: "retention-authority-matrix",
        policy: fixture.policy,
        event,
        evidence: [],
        processMetadata,
      });
    }
    return { fixture, baseline, authority };
  } finally {
    await releaseWorktreeLock(lock);
  }
}

test("process interruption after unlink/fsync leaves a deterministic unproved-missing state", async () => {
  const value = await createTerminalBlobFixture([{ name: "interrupted.txt", bytes: "INTERRUPTION_RESTRICTED_SENTINEL" }]);
  const inputPath = join(value.fixture.root, "retention-input.json");
  await writeFile(inputPath, JSON.stringify(retentionInput(value)), { mode: 0o600 });
  const child = fork(new URL("../dist/tests/repository-retention-child.js", import.meta.url), [inputPath], {
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  const message = (): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
    const exited = (code: number | null): void => reject(new Error(`retention child exited before checkpoint: ${code}`));
    child.once("exit", exited);
    child.once("message", (value: unknown) => { child.off("exit", exited); resolve(value as Record<string, unknown>); });
  });
  try {
    assert.equal((await message())["type"], "AFTER_UNLINK_AND_DIRECTORY_FSYNC");
    await assert.rejects(lstat(blobPath(value)));
    assert.equal((await readRetentionRecords(value.fixture)).length, 0);
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    child.kill("SIGKILL");
    await exited;

    let observed: unknown;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        await applyRetentionCleanup(retentionInput(value));
      } catch (error: unknown) {
        if (codeOf(error) === "LOCK_BUSY") {
          await new Promise<void>((resolve) => setImmediate(resolve));
          continue;
        }
        observed = error;
        break;
      }
    }
    assert.equal(codeOf(observed), "CLEANUP_UNCERTAIN");
    const result = cleanupResults(await readRetentionRecords(value.fixture)).at(-1);
    assert.equal(result?.outcome, "FAILED");
    assert.equal(result?.blobs[0]?.detail_code, "TARGET_MISSING");
    assert.equal(JSON.stringify(result).includes("INTERRUPTION_RESTRICTED_SENTINEL"), false);
  } finally {
    child.kill("SIGKILL");
    await removeRepositoryFixture(value.fixture);
  }
});

test("nonterminal state and unavailable committed timestamp authority publish no operation result", async (t) => {
  await t.test("nonterminal", async () => {
    const value = await uncommittedRetentionFixture(false);
    try {
      await assert.rejects(
        applyRetentionCleanup({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId, baseline: value.baseline,
          terminalAuthority: value.authority, evaluatedAt: "2026-01-31T00:00:00.000Z" }),
        (error: unknown) => codeOf(error) === "RETENTION_NOT_TERMINAL",
      );
      assert.equal((await readRetentionRecords(value.fixture)).length, 0);
    } finally {
      await removeRepositoryFixture(value.fixture);
    }
  });

  await t.test("terminal timestamp authority not committed as evidence", async () => {
    const value = await uncommittedRetentionFixture(true);
    try {
      await assert.rejects(
        applyRetentionCleanup({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId, baseline: value.baseline,
          terminalAuthority: value.authority, evaluatedAt: "2026-01-31T00:00:00.000Z" }),
        (error: unknown) => codeOf(error) === "RETENTION_TIMESTAMP_UNAVAILABLE",
      );
      assert.equal((await readRetentionRecords(value.fixture)).length, 0);
    } finally {
      await removeRepositoryFixture(value.fixture);
    }
  });
});
