import assert from "node:assert/strict";
import { execFile, fork } from "node:child_process";
import { promisify } from "node:util";
import { readdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";
import { digestHex } from "../src/repository/utils.js";
import { codeOf, createCleanAdmission, releaseAdmission } from "./repository-matrix-helpers.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

const execFileAsync = promisify(execFile);

function lockChild(stateRoot: string, repository: string) {
  return fork(new URL("../dist/tests/repository-lock-child.js", import.meta.url), [stateRoot, repository], {
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
}

function childMessage(child: ReturnType<typeof fork>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const exited = (code: number | null): void => reject(new Error(`lock child exited before IPC: ${code}`));
    child.once("exit", exited);
    child.once("message", (message: unknown) => {
      child.off("exit", exited);
      resolve(message as Record<string, unknown>);
    });
  });
}

test("special lock entry fails closed", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const path = join(fixture.stateRoot, "locks", `${digestHex(repository.worktree_key)}.lock`);
    await execFileAsync("mkfifo", [path]);
    await assert.rejects(acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }),
      (error: unknown) => codeOf(error) === "INVALID_LOCK_PATH");
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("a colliding second controller cannot create a full-preflight token", async () => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  await releaseAdmission(admission);
  const before = (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "repository-state-tokens"))).length;
  const child = lockChild(fixture.stateRoot, fixture.repository);
  try {
    assert.equal((await childMessage(child))["type"], "ACQUIRED");
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    await assert.rejects(acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository }),
      (error: unknown) => codeOf(error) === "LOCK_BUSY");
    assert.equal((await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "repository-state-tokens"))).length, before);
    child.send({ type: "RELEASE" });
    assert.equal((await childMessage(child))["type"], "RELEASED");
    const later = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    await releaseWorktreeLock(later);
  } finally {
    child.kill("SIGKILL");
    await removeRepositoryFixture(fixture);
  }
});
