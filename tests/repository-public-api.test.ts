import assert from "node:assert/strict";
import test from "node:test";

import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

const REPOSITORY_PACKAGE = "pi-bounded-coding-workflow/repository";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

function assertDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const nested of Object.values(value)) assertDeepFrozen(nested, seen);
}

test("built repository package exposes only the explicit M3 guard boundary", async (t) => {
  const repository = await import(REPOSITORY_PACKAGE);
  assert.deepEqual(Object.keys(repository).sort(), [
    "RepositoryGuardError",
    "acquireWorktreeLock",
    "applyRetentionCleanup",
    "assertWorktreeLockHeld",
    "captureBaseline",
    "createBaselineApproval",
    "createTerminalRetentionAuthority",
    "deriveWorktreeKey",
    "inspectRetention",
    // V1-R2A added the quiescence probe to the committed guard boundary; this frozen list now records it.
    "probeWorktreeLockAvailability",
    "releaseWorktreeLock",
    "resolveRepositoryIdentity",
    "runFastPreflight",
    "runFullPreflight",
    "runPostflight",
    // V1-R2D0 added the explicit M3 resume-lock-handover admission to the committed guard boundary.
    "runResumeLockHandover",
    "verifyBaselineApproval",
  ]);
  for (const forbidden of [
    "runGit", "execGit", "writePath", "unlinkPath", "forceApproval", "forcePostflight", "adoptDrift",
    "skipClassification", "setBlobLimit", "guardianCheckpoint", "openLockFile", "secureWrite", "applyPatch",
    "runCommand", "commit", "push",
  ]) assert.equal(forbidden in repository, false, forbidden);

  for (const subpath of [
    "pi-bounded-coding-workflow/repository/git-runner",
    "pi-bounded-coding-workflow/repository/storage",
    "pi-bounded-coding-workflow/repository/test-hooks",
    "pi-bounded-coding-workflow/repository/lock",
    "pi-bounded-coding-workflow/repository/acquisition",
    "pi-bounded-coding-workflow/repository/environment",
    "pi-bounded-coding-workflow/repository/executable",
    "pi-bounded-coding-workflow/repository/semantic-context",
    "pi-bounded-coding-workflow/identity/m3-scope",
    "pi-bounded-coding-workflow/persistence/m3-authority",
    "pi-bounded-coding-workflow/persistence/managed-authority",
    "pi-bounded-coding-workflow/src/repository/identity",
    "pi-bounded-coding-workflow/dist/src/repository/git-runner.js",
  ]) {
    await t.test(`blocked internal subpath ${subpath}`, async () => {
      await assert.rejects(import(subpath), (error: unknown) => codeOf(error) === "ERR_PACKAGE_PATH_NOT_EXPORTED");
    });
  }
});

test("built package resolves identity and starts its packaged guardian without source-path dependence", async () => {
  const api = await import(REPOSITORY_PACKAGE);
  const fixture = await createRepositoryFixture();
  try {
    const identity = await api.resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assertDeepFrozen(identity);
    const lock = await api.acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository: identity });
    const diagnostic = await api.assertWorktreeLockHeld(lock);
    assertDeepFrozen(diagnostic);
    assert.equal(diagnostic.worktree_key, identity.worktree_key);
    assert.match(diagnostic.lock_acquisition_content_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(diagnostic.lock_path, /^\//);
    assert.match(diagnostic.guardian_python_invocation_path, /^\//);
    assert.match(diagnostic.guardian_python_realpath, /^\//);
    assert.match(diagnostic.guardian_python_path, /^\//);
    assert.match(diagnostic.guardian_helper_path, /^\//);
    assert.match(diagnostic.guardian_helper_realpath, /^\//);
    assert.match(diagnostic.guardian_helper_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.equal(Reflect.set(diagnostic, "guardian_pid", 1), false);
    await api.releaseWorktreeLock(lock);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("public operations reject missing, unknown, and wrongly typed options", async () => {
  const api = await import(REPOSITORY_PACKAGE);
  const fixture = await createRepositoryFixture();
  try {
    await assert.rejects(
      api.resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true, extra: true } as never),
      (error: unknown) => codeOf(error) === "INVALID_ARGUMENT",
    );
    await assert.rejects(
      api.resolveRepositoryIdentity({ requestedPath: fixture.repository } as never),
      (error: unknown) => codeOf(error) === "INVALID_ARGUMENT",
    );
    await assert.rejects(
      api.deriveWorktreeKey({ gitCommonDir: "relative", worktreeRoot: fixture.repository }),
      (error: unknown) => codeOf(error) === "INVALID_ARGUMENT",
    );
    assert.equal(await api.verifyBaselineApproval({ baseline: {}, approval: {} } as never), false);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});
