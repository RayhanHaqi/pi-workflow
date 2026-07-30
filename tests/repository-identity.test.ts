import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import test from "node:test";

import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { createRepositoryFixture, git, removeRepositoryFixture } from "./repository-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

test("repository identity binds branch, HEAD tree, no-upstream state, Git directories, and worktree inventory", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const identity = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(identity.branch, "main");
    assert.equal(identity.detached, false);
    assert.match(identity.head, /^[0-9a-f]{40,64}$/);
    assert.match(identity.head_tree, /^[0-9a-f]{40,64}$/);
    assert.equal(identity.upstream_ref, null);
    assert.equal(identity.ahead, null);
    assert.equal(identity.behind, null);
    assert.equal(identity.worktree_root, fixture.repository);
    assert.equal(identity.git_toplevel, fixture.repository);
    assert.equal(identity.git_dir, identity.worktree_git_dir);
    assert.equal(identity.worktrees.length, 1);
    assert.equal(identity.shallow, false);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("detached HEAD and local upstream divergence are represented exactly", async () => {
  const fixture = await createRepositoryFixture();
  try {
    await git(fixture.repository, "branch", "upstream-local", "main");
    await git(fixture.repository, "branch", "--set-upstream-to=upstream-local", "main");
    await writeFile(fixture.trackedPath, "ahead commit\n");
    await git(fixture.repository, "add", "tracked.txt");
    await git(fixture.repository, "commit", "-m", "ahead");
    const ahead = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(ahead.upstream_ref, "upstream-local");
    assert.equal(ahead.ahead, 1);
    assert.equal(ahead.behind, 0);

    await git(fixture.repository, "checkout", "--detach");
    const detached = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(detached.branch, null);
    assert.equal(detached.detached, true);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("invalid repositories and bounded Git output fail with typed results", async () => {
  const fixture = await createRepositoryFixture();
  try {
    await assert.rejects(
      resolveRepositoryIdentity({ requestedPath: fixture.stateRoot, requireHead: true }),
      (error: unknown) => codeOf(error) === "NOT_A_GIT_WORKTREE",
    );
    configureRepositoryTestHooks({ gitOutputLimitBytes: 1 });
    await assert.rejects(
      resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }),
      (error: unknown) => codeOf(error) === "BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT",
    );
  } finally {
    resetRepositoryTestHooks();
    await removeRepositoryFixture(fixture);
  }
});
