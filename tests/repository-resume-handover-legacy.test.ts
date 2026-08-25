import assert from "node:assert/strict";
import { chmod, lstat, mkdir, readdir, rm, rmdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  captureBaseline,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runResumeLockHandover,
} from "../src/repository/index.js";
import { assertUsableM3Storage } from "../src/repository/storage.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import {
  createRepositoryFixture,
  git,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
} from "./repository-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

function recordsDirectory(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, name: string): string {
  return join(fixture.stateRoot, "runs", fixture.runId, "records", name);
}

async function pathExists(path: string): Promise<boolean> {
  return lstat(path).then(() => true).catch(() => false);
}

async function inspectionDigest(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return {
    status: inspection.status,
    revision: inspection.revision,
    statePointer: inspection.statePointer?.content_sha256 ?? null,
    workflowState: inspection.workflowState?.content_sha256 ?? null,
    transitionCommit: inspection.transitionCommit?.content_sha256 ?? null,
    reachableCount: inspection.reachableObjects.length,
    managedCount: inspection.managedObjects.length,
    classifications: JSON.stringify(inspection.managedRecordClassifications),
    issues: JSON.stringify(inspection.issues),
  };
}

/** Emulates a pre-ec31ca5 retained run by removing only the empty new-layout directory. */
async function emulateLegacyLayout(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>): Promise<void> {
  const handoverDirectory = recordsDirectory(fixture, "resume-lock-handovers");
  assert.deepEqual(await readdir(handoverDirectory), []);
  await rmdir(handoverDirectory);
  assert.equal(await pathExists(handoverDirectory), false);
}

test("R2D0 legacy retained run stays healthy and read-only until its first real handover", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lockA = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    const selected = await instructionAuthorityInputs(fixture);
    const editable = ["tracked.txt"];
    const frozen = ["AGENTS.md", "AUTHORITY.md"];
    const taskScopeIdentity = scopeIdentity(editable, frozen);
    const environment = await requiredEnvironment(fixture.repository);
    const baseline = (await captureBaseline({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      requestedPath: fixture.repository,
      mode: "CLEAN_REQUIRED",
      pathDecisions: [],
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      allowShallow: false,
      allowPartialClone: false,
      lock: lockA,
    })).baseline;
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRepository: repository,
      expectedWorktreeKey: repository.worktree_key,
      expectedBranch: repository.branch,
      expectedHead: repository.head,
      expectedWorktreeListSha256: repository.worktree_list_sha256,
      baseline,
      approval: null,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      requiredEnvironment: environment,
      taskScopeIdentity,
      allowShallow: false,
      allowPartialClone: false,
      lock: lockA,
    });
    const headBefore = (await git(fixture.repository, "rev-parse", "HEAD")).trim();
    const porcelainBefore = await git(fixture.repository, "status", "--porcelain");

    // Emulate the historical retained-run layout without touching any record bytes.
    await emulateLegacyLayout(fixture);

    // Read-only acceptance of the old run.
    await assertUsableM3Storage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    const first = await inspectionDigest(fixture);
    assert.equal(first.status, "HEALTHY");

    // Repeated read-only inspections are deterministic, mutate nothing, and
    // never recreate the legacy-optional directory as a side effect.
    const second = await inspectionDigest(fixture);
    const third = await inspectionDigest(fixture);
    assert.deepEqual(second, first);
    assert.deepEqual(third, first);
    assert.equal(await pathExists(recordsDirectory(fixture, "resume-lock-handovers")), false);
    assert.equal((await readdir(recordsDirectory(fixture, "repository-state-tokens"))).length, 1);

    // Fresh owner B acquires; old T_A remains LOCK_LOST under B.
    await releaseWorktreeLock(lockA);
    lockB = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    await assert.rejects(runFastPreflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: full.acceptedState,
      baseline,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      taskScopeIdentity,
      lock: lockB,
    }), (error: unknown) => codeOf(error) === "LOCK_LOST");

    // The productive handover materializes only the optional directory safely.
    const handover = await runResumeLockHandover({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: full.acceptedState,
      baseline,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      taskScopeIdentity,
      lock: lockB,
    });
    const stats = await lstat(recordsDirectory(fixture, "resume-lock-handovers"));
    assert.equal(stats.isDirectory(), true);
    assert.equal(stats.isSymbolicLink(), false);
    assert.equal(stats.mode & 0o777, 0o700);
    assert.deepEqual(await readdir(recordsDirectory(fixture, "resume-lock-handovers")),
      [`${handover.source.content_sha256.slice(7)}.json`]);

    // Source and successor token classify authoritative in the upgraded graph.
    const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    const classificationOf = (kind: string, digest: string): string | undefined =>
      inspection.managedRecordClassifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest)?.classification;
    assert.equal(classificationOf("M3_RESUME_LOCK_HANDOVER", handover.source.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(classificationOf("M3_REPOSITORY_STATE_TOKEN", handover.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");

    // Ordinary fast preflight passes for T_B under B with unchanged checks.
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: handover.acceptedState,
      baseline,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      taskScopeIdentity,
      lock: lockB,
    });
    assert.equal(fast.preflight_kind, "FAST");

    // M2 identities and repository bytes remain unchanged throughout.
    const after = await inspectionDigest(fixture);
    assert.equal(after.status, "HEALTHY");
    assert.equal(after.revision, first.revision);
    assert.equal(after.workflowState, first.workflowState);
    assert.equal(after.statePointer, first.statePointer);
    assert.equal(after.transitionCommit, first.transitionCommit);
    assert.equal(await git(fixture.repository, "status", "--porcelain"), porcelainBefore);
    assert.equal((await git(fixture.repository, "rev-parse", "HEAD")).trim(), headBefore);
  } finally {
    await releaseWorktreeLock(lockA).catch(() => undefined);
    if (lockB !== undefined) await releaseWorktreeLock(lockB).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R2D0 narrowness: missing mandatory record directories and unknown entries stay refused", async (t) => {
  await t.test("missing mandatory postflights directory is refused", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await emulateLegacyLayout(fixture);
      await rm(recordsDirectory(fixture, "postflights"), { recursive: true });
      const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "UNKNOWN_ENTRY"); // exact existing classification for a missing mandatory record directory
      await assert.rejects(assertUsableM3Storage({ stateRoot: fixture.stateRoot, runId: fixture.runId }),
        (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID");
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("missing mandatory repository-state-tokens directory is refused", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await emulateLegacyLayout(fixture);
      await rm(recordsDirectory(fixture, "repository-state-tokens"), { recursive: true });
      const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "UNKNOWN_ENTRY"); // exact existing classification for a missing mandatory record directory
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("unknown extra records directory is refused", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await emulateLegacyLayout(fixture);
      await mkdir(recordsDirectory(fixture, "unknown-extra"), { mode: 0o700 });
      const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "UNKNOWN_ENTRY");
      await assert.rejects(assertUsableM3Storage({ stateRoot: fixture.stateRoot, runId: fixture.runId }),
        (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID");
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("symlinked optional handover directory is refused", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await emulateLegacyLayout(fixture);
      await symlink(recordsDirectory(fixture, "preflights"), recordsDirectory(fixture, "resume-lock-handovers"));
      await assert.rejects(assertUsableM3Storage({ stateRoot: fixture.stateRoot, runId: fixture.runId }),
        (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID");
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("regular file at the optional handover path is refused", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await emulateLegacyLayout(fixture);
      await writeFile(recordsDirectory(fixture, "resume-lock-handovers"), "not a directory\n", { mode: 0o600 });
      await assert.rejects(assertUsableM3Storage({ stateRoot: fixture.stateRoot, runId: fixture.runId }),
        (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID");
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("wrong-mode optional handover directory is refused and never replaced", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await emulateLegacyLayout(fixture);
      await mkdir(recordsDirectory(fixture, "resume-lock-handovers"), { mode: 0o755 });
      await chmod(recordsDirectory(fixture, "resume-lock-handovers"), 0o755);
      await assert.rejects(assertUsableM3Storage({ stateRoot: fixture.stateRoot, runId: fixture.runId }),
        (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID");
      // The unsafe existing path must not have been silently replaced.
      const stats = await lstat(recordsDirectory(fixture, "resume-lock-handovers"));
      assert.equal(stats.mode & 0o777, 0o755);
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });
});
