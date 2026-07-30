import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdir, readdir, rename, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { identifyContractDocument } from "../src/schemas/index.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";
import {
  baselineBlobPath,
  canonicalJsonRecordBytes,
  retainedBaselineBlobUsage,
} from "../src/repository/storage.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import {
  baselineInput,
  codeOf,
  createTerminalBlobFixture,
  pathDecision,
  retentionInput,
} from "./repository-matrix-helpers.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

const execFileAsync = promisify(execFile);

async function captureBlob(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  lock: Awaited<ReturnType<typeof acquireWorktreeLock>>,
  path: string,
  bytes: Uint8Array | string,
) {
  await writeFile(join(fixture.repository, path), bytes, { mode: 0o644 });
  return captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
    pathDecision(path, { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
  ]));
}

async function counts(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) {
  const run = join(fixture.stateRoot, "runs", fixture.runId);
  return {
    blobs: (await readdir(join(run, "baseline-blobs", "sha256"))).length,
    baselines: (await readdir(join(run, "records", "baselines"))).length,
  };
}

test("cumulative quota accounts every retained object and admits exact private-seam boundary", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    configureRepositoryTestHooks({ baselineBlobLimitBytes: 6 });
    const empty = await retainedBaselineBlobUsage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(empty.physicalBytes, 0);

    const first = await captureBlob(fixture, lock, "quota.bin", Buffer.from("aa"));
    assert.deepEqual(first.baseline.blob_quota, {
      logical_approved_bytes: 2,
      physical_bytes: 2,
      deduplicated_bytes: 0,
      existing_physical_bytes: 0,
      new_unique_physical_bytes: 2,
      resulting_physical_bytes: 2,
    });
    const second = await captureBlob(fixture, lock, "quota.bin", Buffer.from("bbb"));
    assert.equal(second.baseline.blob_quota.existing_physical_bytes, 2);
    assert.equal(second.baseline.blob_quota.new_unique_physical_bytes, 3);
    assert.equal(second.baseline.blob_quota.resulting_physical_bytes, 5);

    const deduplicatedOld = await captureBlob(fixture, lock, "quota.bin", Buffer.from("bbb"));
    assert.equal(deduplicatedOld.baseline.blob_quota.existing_physical_bytes, 5);
    assert.equal(deduplicatedOld.baseline.blob_quota.new_unique_physical_bytes, 0);
    assert.equal(deduplicatedOld.baseline.blob_quota.resulting_physical_bytes, 5);

    const exact = await captureBlob(fixture, lock, "quota.bin", Buffer.from("c"));
    assert.equal(exact.baseline.blob_quota.resulting_physical_bytes, 6);
    const beforeFailure = await counts(fixture);
    await assert.rejects(
      captureBlob(fixture, lock, "quota.bin", Buffer.from("d")),
      (error: unknown) => codeOf(error) === "BASELINE_BLOB_LIMIT_EXCEEDED" &&
        (error as { details?: Record<string, unknown> }).details?.["resulting_physical_bytes"] === 7,
    );
    assert.deepEqual(await counts(fixture), beforeFailure);
    assert.equal((await retainedBaselineBlobUsage({ stateRoot: fixture.stateRoot, runId: fixture.runId })).physicalBytes, 6);
  } finally {
    resetRepositoryTestHooks();
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("new-path deduplication counts physical content once within and across snapshots", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    configureRepositoryTestHooks({ baselineBlobLimitBytes: 20 });
    await writeFile(join(fixture.repository, "one.bin"), "same");
    await writeFile(join(fixture.repository, "two.bin"), "same");
    const duplicatePair = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("one.bin", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
      pathDecision("two.bin", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
    ]));
    assert.equal(duplicatePair.baseline.blob_quota.logical_approved_bytes, 8);
    assert.equal(duplicatePair.baseline.blob_quota.physical_bytes, 4);
    assert.equal(duplicatePair.baseline.blob_quota.new_unique_physical_bytes, 4);
    assert.equal(duplicatePair.baseline.blob_quota.deduplicated_bytes, 4);

    await writeFile(join(fixture.repository, "two.bin"), "unique");
    const mixed = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("one.bin", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
      pathDecision("two.bin", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
    ]));
    assert.equal(mixed.baseline.blob_quota.existing_physical_bytes, 4);
    assert.equal(mixed.baseline.blob_quota.new_unique_physical_bytes, 6);
    assert.equal(mixed.baseline.blob_quota.resulting_physical_bytes, 10);
  } finally {
    resetRepositoryTestHooks();
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("retained population uncertainty and safe-integer overflow fail before publication", async (t) => {
  const corruptions: readonly [string, (path: string, fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => Promise<void>][] = [
    ["wrong digest", async (path) => { await writeFile(path, "xx", { mode: 0o600 }); }],
    ["wrong filename", async (path) => { await rename(path, `${path}-unknown`); }],
    ["symlink", async (path, fixture) => { await unlink(path); await symlink(fixture.trackedPath, path); }],
    ["directory", async (path) => { await unlink(path); await mkdir(path, { mode: 0o700 }); }],
    ["FIFO", async (path) => { await unlink(path); await execFileAsync("mkfifo", [path]); }],
  ];
  for (const [name, corrupt] of corruptions) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
      const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
      try {
        const captured = await captureBlob(fixture, lock, "retained.bin", "ok");
        const blob = captured.baseline.paths[0]?.blob;
        assert.ok(blob);
        const path = baselineBlobPath({ stateRoot: fixture.stateRoot, runId: fixture.runId }, blob.blob_sha256);
        await corrupt(path, fixture);
        const before = await counts(fixture);
        await assert.rejects(
          captureBlob(fixture, lock, "retained.bin", "new"),
          (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID" || codeOf(error) === "CLEANUP_UNCERTAIN",
        );
        assert.deepEqual(await counts(fixture), before);
      } finally {
        await releaseWorktreeLock(lock);
        await removeRepositoryFixture(fixture);
      }
    });
  }

  await t.test("inconsistent managed metadata", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      const captured = await captureBlob(fixture, lock, "retained.bin", "ok");
      const draft = structuredClone(captured.baseline) as unknown as Record<string, unknown>;
      delete draft["content_sha256"];
      const paths = draft["paths"] as Array<Record<string, unknown>>;
      const blob = paths[0]?.["blob"] as Record<string, unknown>;
      blob["byte_length"] = 1;
      const forged = identifyContractDocument("pi_gacw_baseline_runtime_v0", draft) as unknown as Record<string, unknown>;
      const digest = String(forged["content_sha256"]).slice("sha256:".length);
      await writeFile(
        join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines", `${digest}.json`),
        canonicalJsonRecordBytes(forged),
        { mode: 0o600 },
      );
      await chmod(join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines", `${digest}.json`), 0o600);
      await assert.rejects(
        captureBlob(fixture, lock, "retained.bin", "new"),
        (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN",
      );
    } finally {
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("safe integer overflow", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      configureRepositoryTestHooks({ retainedBaselineBlobBytesOverride: Number.MAX_SAFE_INTEGER });
      const before = await counts(fixture);
      await assert.rejects(
        captureBlob(fixture, lock, "overflow.bin", "x"),
        (error: unknown) => codeOf(error) === "BASELINE_BLOB_LIMIT_EXCEEDED",
      );
      assert.deepEqual(await counts(fixture), before);
    } finally {
      resetRepositoryTestHooks();
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });
});

test("successful retention lowers retained usage while failed retention preserves it", async (t) => {
  await t.test("successful", async () => {
    const value = await createTerminalBlobFixture([{ name: "retained.txt", bytes: "quota-retained" }]);
    try {
      const before = await retainedBaselineBlobUsage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
      assert.equal(before.physicalBytes, 14);
      await applyRetentionCleanup(retentionInput(value));
      const after = await retainedBaselineBlobUsage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
      assert.equal(after.physicalBytes, 0);
      assert.equal(after.entries.length, 0);
    } finally {
      await removeRepositoryFixture(value.fixture);
    }
  });

  await t.test("failed", async () => {
    const value = await createTerminalBlobFixture([{ name: "retained.txt", bytes: "quota-retained" }]);
    try {
      configureRepositoryTestHooks({ beforeRetentionUnlink: () => { throw new Error("injected unlink refusal"); } });
      await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
      resetRepositoryTestHooks();
      const usage = await retainedBaselineBlobUsage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
      assert.equal(usage.physicalBytes, 14);
      assert.equal(usage.entries.length, 1);
    } finally {
      resetRepositoryTestHooks();
      await removeRepositoryFixture(value.fixture);
    }
  });
});
