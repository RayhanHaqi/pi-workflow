import assert from "node:assert/strict";
import { chmod, lstat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  verifyBaselineApproval,
  type BaselinePathDecision,
} from "../src/repository/index.js";
import { MAX_STATE_ROOT_BYTES, assertStateRootCapacity } from "../src/repository/storage.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import {
  createRepositoryFixture,
  git,
  instructionAuthorityInputs,
  removeRepositoryFixture,
} from "./repository-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

async function captureInput(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, lock: Awaited<ReturnType<typeof acquireWorktreeLock>>, mode: "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY", decisions: readonly BaselinePathDecision[]) {
  const selected = await instructionAuthorityInputs(fixture);
  return {
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    requestedPath: fixture.repository,
    mode,
    pathDecisions: decisions,
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    allowShallow: false,
    allowPartialClone: false,
    lock,
  } as const;
}

function decision(
  path: string,
  dataClass: BaselinePathDecision["dataClass"] = "PUBLIC_SOURCE",
  captureMode: BaselinePathDecision["captureMode"] = "HASH_ONLY",
  retentionDaysAfterTerminal: number | null = null,
  explicitBlobApproval = false,
): BaselinePathDecision {
  return {
    path,
    ownershipClass: "OWNER_ACCEPTED_MUTABLE",
    dataClass,
    captureMode,
    explicitBlobApproval,
    retentionDaysAfterTerminal,
  };
}

test("clean baseline is deterministic and rejects every dirty category", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const input = await captureInput(fixture, lock, "CLEAN_REQUIRED", []);
    const first = await captureBaseline(input);
    const second = await captureBaseline(input);
    assert.equal(first.baseline.content_sha256, second.baseline.content_sha256);
    assert.equal(first.baseline.accepted_baseline.baseline_sha256, second.baseline.accepted_baseline.baseline_sha256);
    assert.equal(first.baseline.git_fingerprint.dirty, false);
    assert.equal(Object.isFrozen(first), true);

    await writeFile(fixture.trackedPath, "unstaged\n");
    await assert.rejects(captureBaseline(input), (error: unknown) => codeOf(error) === "BASELINE_DIRTY_NOT_APPROVED");
    await git(fixture.repository, "add", "tracked.txt");
    await assert.rejects(captureBaseline(input), (error: unknown) => codeOf(error) === "BASELINE_DIRTY_NOT_APPROVED");
    await writeFile(join(fixture.repository, "untracked.txt"), "untracked\n");
    await assert.rejects(captureBaseline(input), (error: unknown) => codeOf(error) === "BASELINE_DIRTY_NOT_APPROVED");
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("approved dirty baseline binds staged, unstaged, untracked, decisions, blobs, and exact approval", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const sentinel = "PRIVATE_SENTINEL_DO_NOT_REPORT";
  try {
    await writeFile(fixture.trackedPath, "staged\n");
    await git(fixture.repository, "add", "tracked.txt");
    await writeFile(fixture.trackedPath, "worktree-after-index\n");
    await writeFile(join(fixture.repository, "unknown.txt"), sentinel);
    const decisions = [
      decision("tracked.txt", "PUBLIC_SOURCE", "BLOB", 30),
      decision("unknown.txt", null),
    ];
    const captured = await captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", decisions));
    assert.deepEqual(captured.baseline.accepted_baseline.staged_paths, ["tracked.txt"]);
    assert.deepEqual(captured.baseline.accepted_baseline.unstaged_paths, ["tracked.txt"]);
    assert.deepEqual(captured.baseline.accepted_baseline.untracked_paths, ["unknown.txt"]);
    assert.equal(captured.baseline.paths.find((entry) => entry.path === "unknown.txt")?.data_class, "HASH_ONLY");
    assert.equal(captured.baseline.paths.find((entry) => entry.path === "unknown.txt")?.blob, null);
    const blob = captured.baseline.paths.find((entry) => entry.path === "tracked.txt")?.blob;
    assert.ok(blob);
    const stats = await lstat(join(fixture.stateRoot, "runs", fixture.runId, blob.relative_path));
    assert.equal(stats.mode & 0o777, 0o600);
    assert.equal(JSON.stringify(captured).includes(sentinel), false);

    const approved = await createBaselineApproval({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline: captured.baseline,
      approvedBy: "owner",
      approvedAt: "2026-01-01T00:00:00.000Z",
    });
    assert.equal(await verifyBaselineApproval({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline: captured.baseline,
      approval: approved.approval,
    }), true);

    await writeFile(fixture.trackedPath, "changed-after-approval\n");
    const changed = await captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", decisions));
    assert.notEqual(changed.baseline.content_sha256, captured.baseline.content_sha256);
    assert.equal(await verifyBaselineApproval({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline: changed.baseline,
      approval: approved.approval,
    }), false);
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("rename inventory binds old path and mixed staged/worktree status", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await git(fixture.repository, "mv", "tracked.txt", "renamed ü.txt");
    await writeFile(join(fixture.repository, "renamed ü.txt"), "renamed and unstaged\n");
    const captured = await captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      decision("tracked.txt"),
      decision("renamed ü.txt"),
    ]));
    assert.equal(captured.baseline.git_fingerprint.staged[0]?.old_path, "tracked.txt");
    assert.equal(captured.baseline.git_fingerprint.unstaged[0]?.path, "renamed ü.txt");
    assert.deepEqual(captured.baseline.paths.map((entry) => entry.path), ["renamed ü.txt", "tracked.txt"]);
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("classification policy blocks SECRET and special paths without reporting raw content", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const secret = "SECRET_SENTINEL_NEVER_LOG";
  try {
    await writeFile(join(fixture.repository, "secret.txt"), secret);
    await assert.rejects(
      captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [decision("secret.txt", "SECRET")])),
      (error: unknown) => codeOf(error) === "BASELINE_SECRET_PRESENT" && !String(error).includes(secret),
    );

    await symlink("tracked.txt", join(fixture.repository, "link.txt"));
    await assert.rejects(
      captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        decision("secret.txt", "HASH_ONLY"),
        decision("link.txt", "HASH_ONLY"),
      ])),
      (error: unknown) => codeOf(error) === "BASELINE_SPECIAL_PATH",
    );
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("blob limits accept exact 1 MiB, reject plus one, and account duplicate logical bytes", async (t) => {
  await t.test("exact and deduplicated", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      const bytes = Buffer.alloc(1_048_576, 0x5a);
      await writeFile(join(fixture.repository, "one.bin"), bytes);
      await writeFile(join(fixture.repository, "two.bin"), bytes);
      const captured = await captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        decision("one.bin", "PUBLIC_SOURCE", "BLOB", 30),
        decision("two.bin", "PUBLIC_SOURCE", "BLOB", 30),
      ]));
      assert.equal(captured.baseline.blob_quota.logical_approved_bytes, 2_097_152);
      assert.equal(captured.baseline.blob_quota.physical_bytes, 1_048_576);
      assert.equal(captured.baseline.blob_quota.deduplicated_bytes, 1_048_576);
    } finally {
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("one byte above", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      await writeFile(join(fixture.repository, "large.bin"), Buffer.alloc(1_048_577, 0x41));
      await assert.rejects(
        captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [decision("large.bin", "PUBLIC_SOURCE", "BLOB", 30)])),
        (error: unknown) => codeOf(error) === "BASELINE_BLOB_LIMIT_EXCEEDED",
      );
    } finally {
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });
});

test("PRIVATE_SOURCE and SENSITIVE blob approval and retention caps are explicit", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await writeFile(join(fixture.repository, "private.txt"), "private-content");
    await assert.rejects(
      captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [decision("private.txt", "PRIVATE_SOURCE", "BLOB", 30)])),
      (error: unknown) => codeOf(error) === "BASELINE_DIRTY_NOT_APPROVED",
    );
    const privateCapture = await captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      decision("private.txt", "PRIVATE_SOURCE", "BLOB", 30, true),
    ]));
    assert.ok(privateCapture.baseline.paths[0]?.blob);

    await writeFile(join(fixture.repository, "sensitive.txt"), "sensitive-content");
    await assert.rejects(
      captureBaseline(await captureInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        decision("private.txt", "PRIVATE_SOURCE", "HASH_ONLY"),
        decision("sensitive.txt", "SENSITIVE", "BLOB", 8, true),
      ])),
      (error: unknown) => codeOf(error) === "INVALID_ARGUMENT",
    );
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("state-root accounting accepts the exact boundary and rejects overflow/unsafe sizes", async () => {
  const fixture = await createRepositoryFixture();
  try {
    configureRepositoryTestHooks({ stateRootBytes: MAX_STATE_ROOT_BYTES });
    assert.equal(await assertStateRootCapacity(fixture.stateRoot, 0), MAX_STATE_ROOT_BYTES);
    await assert.rejects(assertStateRootCapacity(fixture.stateRoot, 1), (error: unknown) => codeOf(error) === "STATE_ROOT_LIMIT_EXCEEDED");
    await assert.rejects(assertStateRootCapacity(fixture.stateRoot, -1), (error: unknown) => codeOf(error) === "STATE_ROOT_LIMIT_EXCEEDED");
  } finally {
    resetRepositoryTestHooks();
    await removeRepositoryFixture(fixture);
  }
});
