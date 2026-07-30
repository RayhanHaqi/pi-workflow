import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { chmod, mkdir, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  assertWorktreeLockHeld,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { digestHex } from "../src/repository/utils.js";
import { createRepositoryFixture, git, removeRepositoryFixture } from "./repository-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

function childMessage(child: ReturnType<typeof fork>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const onExit = (code: number | null): void => reject(new Error(`lock child exited before message: ${code}`));
    child.once("exit", onExit);
    child.once("message", (message: unknown) => {
      child.off("exit", onExit);
      resolve(message as Record<string, unknown>);
    });
  });
}

function lockChild(stateRoot: string, repository: string) {
  return fork(new URL("../dist/tests/repository-lock-child.js", import.meta.url), [stateRoot, repository], {
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
}

async function acquireEventually(stateRoot: string, repository: Awaited<ReturnType<typeof resolveRepositoryIdentity>>) {
  let last: unknown;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      return await acquireWorktreeLock({ stateRoot, repository });
    } catch (error: unknown) {
      last = error;
      if (codeOf(error) !== "LOCK_BUSY") throw error;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
  throw last;
}

test("real flock guardian serializes cooperating controller processes and releases explicitly", async () => {
  const fixture = await createRepositoryFixture();
  const first = lockChild(fixture.stateRoot, fixture.repository);
  try {
    const acquired = await childMessage(first);
    assert.equal(acquired["type"], "ACQUIRED");
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    await assert.rejects(
      acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }),
      (error: unknown) => codeOf(error) === "LOCK_BUSY",
    );
    first.send({ type: "RELEASE" });
    assert.equal((await childMessage(first))["type"], "RELEASED");
    const later = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    assert.equal((await assertWorktreeLockHeld(later)).worktree_key, repository.worktree_key);
    assert.equal(Object.isFrozen(later.diagnostics), true);
    await releaseWorktreeLock(later);
  } finally {
    first.kill("SIGKILL");
    await removeRepositoryFixture(fixture);
  }
});

test("guardian death is detected and controller death releases the kernel lock", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const owned = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    process.kill(owned.diagnostics.guardian_pid, "SIGKILL");
    await assert.rejects(assertWorktreeLockHeld(owned), (error: unknown) => codeOf(error) === "LOCK_LOST");

    const controller = lockChild(fixture.stateRoot, fixture.repository);
    assert.equal((await childMessage(controller))["type"], "ACQUIRED");
    const exited = new Promise<void>((resolve) => controller.once("exit", () => resolve()));
    controller.kill("SIGKILL");
    await exited;
    const afterDeath = await acquireEventually(fixture.stateRoot, repository);
    await releaseWorktreeLock(afterDeath);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("worktree keys converge through symlinks and separate linked worktrees", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const alias = join(fixture.root, "repository-alias");
    await symlink(fixture.repository, alias);
    const ordinary = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const throughAlias = await resolveRepositoryIdentity({ requestedPath: alias, requireHead: true });
    assert.equal(ordinary.worktree_key, throughAlias.worktree_key);

    const linkedPath = join(fixture.root, "linked-worktree");
    await git(fixture.repository, "worktree", "add", "-b", "linked", linkedPath);
    const linked = await resolveRepositoryIdentity({ requestedPath: linkedPath, requireHead: true });
    assert.equal(linked.git_common_dir, ordinary.git_common_dir);
    assert.notEqual(linked.worktree_key, ordinary.worktree_key);
    assert.equal(linked.worktrees.length, 2);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("stale marker is non-authoritative and unsafe lock entries fail closed", async (t) => {
  const fixture = await createRepositoryFixture();
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const hex = digestHex(repository.worktree_key);
    const lockPath = join(fixture.stateRoot, "locks", `${hex}.lock`);
    const markerPath = join(fixture.stateRoot, "locks", `${hex}.owner.json`);
    await writeFile(markerPath, "{}\n", { mode: 0o600 });
    await chmod(markerPath, 0o600);
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    await releaseWorktreeLock(lock);

    await t.test("lock-file symlink", async () => {
      await unlink(lockPath);
      await symlink(markerPath, lockPath);
      await assert.rejects(acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }), (error: unknown) => codeOf(error) === "INVALID_LOCK_PATH");
      await unlink(lockPath);
      await writeFile(lockPath, "", { mode: 0o600 });
      await chmod(lockPath, 0o600);
    });

    await t.test("lock-file directory", async () => {
      await unlink(lockPath);
      await mkdir(lockPath, { mode: 0o700 });
      await assert.rejects(acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }), (error: unknown) => codeOf(error) === "INVALID_LOCK_PATH");
    });
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("guardian READY timeout and malformed protocol fail closed through private seams", async (t) => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  try {
    await t.test("timeout", async () => {
      const helper = join(fixture.root, "timeout.py");
      await writeFile(helper, "import sys\nsys.stdin.read()\n", { mode: 0o600 });
      configureRepositoryTestHooks({ guardianPath: helper, guardianReadyTimeoutMs: 25 });
      await assert.rejects(acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }), (error: unknown) => codeOf(error) === "LOCK_GUARDIAN_START_FAILED");
      resetRepositoryTestHooks();
    });
    await t.test("malformed", async () => {
      const helper = join(fixture.root, "malformed.py");
      await writeFile(helper, "print('not-json', flush=True)\n", { mode: 0o600 });
      configureRepositoryTestHooks({ guardianPath: helper });
      await assert.rejects(acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }), (error: unknown) =>
        codeOf(error) === "LOCK_GUARDIAN_START_FAILED" || codeOf(error) === "LOCK_LOST");
      resetRepositoryTestHooks();
    });
  } finally {
    resetRepositoryTestHooks();
    await removeRepositoryFixture(fixture);
  }
});
