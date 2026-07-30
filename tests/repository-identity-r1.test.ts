import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { captureGitState } from "../src/repository/fingerprint.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { codeOf } from "./repository-matrix-helpers.js";
import { createRepositoryFixture, git, removeRepositoryFixture } from "./repository-helpers.js";

test("local upstream identity distinguishes synchronized, behind, and ahead-and-behind states", async () => {
  const fixture = await createRepositoryFixture();
  try {
    await git(fixture.repository, "branch", "upstream-local", "main");
    await git(fixture.repository, "branch", "--set-upstream-to=upstream-local", "main");
    const synchronized = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(synchronized.upstream_ref, "upstream-local");
    assert.equal(synchronized.ahead, 0);
    assert.equal(synchronized.behind, 0);

    await git(fixture.repository, "checkout", "upstream-local");
    await writeFile(join(fixture.repository, "upstream.txt"), "upstream\n");
    await git(fixture.repository, "add", "upstream.txt");
    await git(fixture.repository, "commit", "-m", "upstream advances");
    await git(fixture.repository, "checkout", "main");
    const behind = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(behind.ahead, 0);
    assert.equal(behind.behind, 1);

    await writeFile(join(fixture.repository, "local.txt"), "local\n");
    await git(fixture.repository, "add", "local.txt");
    await git(fixture.repository, "commit", "-m", "local diverges");
    const diverged = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(diverged.ahead, 1);
    assert.equal(diverged.behind, 1);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("multiple linked worktrees and symlink invocation retain exact physical identity", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const first = join(fixture.root, "linked-one");
    const second = join(fixture.root, "linked-two");
    await git(fixture.repository, "worktree", "add", "-b", "linked-one", first);
    await git(fixture.repository, "worktree", "add", "-b", "linked-two", second);
    const alias = join(fixture.root, "repository-alias-r1");
    await symlink(fixture.repository, alias);
    const ordinary = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const throughAlias = await resolveRepositoryIdentity({ requestedPath: alias, requireHead: true });
    const linked = await resolveRepositoryIdentity({ requestedPath: first, requireHead: true });
    assert.equal(ordinary.worktrees.length, 3);
    assert.equal(throughAlias.worktree_key, ordinary.worktree_key);
    assert.equal(throughAlias.physical_requested_path, ordinary.physical_requested_path);
    assert.notEqual(linked.worktree_key, ordinary.worktree_key);
    assert.equal(linked.git_common_dir, ordinary.git_common_dir);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("local submodule state is recursively represented without network access", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const source = join(fixture.root, "submodule-source");
    await mkdir(source);
    await git(source, "init", "-b", "main");
    await git(source, "config", "user.name", "Submodule Source");
    await git(source, "config", "user.email", "submodule@example.invalid");
    await writeFile(join(source, "sub.txt"), "clean\n");
    await git(source, "add", "sub.txt");
    await git(source, "commit", "-m", "submodule source");
    await git(fixture.repository, "-c", "protocol.file.allow=always", "submodule", "add", source, "sub");
    await git(fixture.repository, "commit", "-am", "add submodule");
    const clean = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.deepEqual(clean.submodules.map((entry) => [entry.path, entry.state]), [["sub", "CLEAN"]]);
    await writeFile(join(fixture.repository, "sub", "sub.txt"), "modified\n");
    const modified = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.deepEqual(modified.submodules.map((entry) => [entry.path, entry.state]), [["sub", "MODIFIED"]]);
    assert.notEqual(modified.submodule_state_sha256, clean.submodule_state_sha256);
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("shallow and local partial-clone configuration are represented exactly", async () => {
  const fixture = await createRepositoryFixture();
  try {
    await writeFile(join(fixture.repository, "second.txt"), "second\n");
    await git(fixture.repository, "add", "second.txt");
    await git(fixture.repository, "commit", "-m", "second for shallow clone");
    const shallowPath = join(fixture.root, "shallow");
    await git(fixture.root, "clone", "--depth", "1", `file://${fixture.repository}`, shallowPath);
    const shallow = await resolveRepositoryIdentity({ requestedPath: shallowPath, requireHead: true });
    assert.equal(shallow.shallow, true);

    await git(fixture.repository, "config", "core.repositoryformatversion", "1");
    await git(fixture.repository, "config", "extensions.partialClone", "origin");
    await git(fixture.repository, "config", "remote.origin.partialclonefilter", "blob:none");
    const partial = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(partial.partial_clone.promisor_remote, "origin");
    assert.ok(partial.partial_clone.filters.some((entry) => entry.includes("blob:none")));
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("malformed Git output, unreadable Git state, output overflow, and unsupported path bytes fail closed", async (t) => {
  await t.test("malformed Git output through executable seam", async () => {
    const fixture = await createRepositoryFixture();
    const bin = await mkdtemp(join(tmpdir(), "m3-r1-fake-git-"));
    const originalPath = process.env["PATH"];
    try {
      const fake = join(bin, "git");
      await writeFile(fake, "#!/bin/sh\nprintf 'bad\\nextra\\n'\n", { mode: 0o755 });
      await chmod(fake, 0o755);
      process.env["PATH"] = bin;
      await assert.rejects(
        resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }),
        (error: unknown) => codeOf(error) === "INVALID_GIT_OUTPUT" || codeOf(error) === "GIT_INSPECTION_FAILED",
      );
    } finally {
      process.env["PATH"] = originalPath;
      await removeRepositoryFixture(fixture);
      await import("node:fs/promises").then(({ rm }) => rm(bin, { recursive: true, force: true }));
    }
  });

  await t.test("unreadable Git directory", async () => {
    const fixture = await createRepositoryFixture();
    const gitDirectory = join(fixture.repository, ".git");
    try {
      await chmod(gitDirectory, 0o000);
      await assert.rejects(
        resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }),
        (error: unknown) => ["GIT_INSPECTION_FAILED", "NOT_A_GIT_WORKTREE", "UNREADABLE_GIT_DIRECTORY"].includes(String(codeOf(error))),
      );
    } finally {
      await chmod(gitDirectory, 0o700).catch(() => undefined);
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("bounded output", async () => {
    const fixture = await createRepositoryFixture();
    try {
      configureRepositoryTestHooks({ gitOutputLimitBytes: 1 });
      await assert.rejects(resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }),
        (error: unknown) => codeOf(error) === "BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT");
    } finally { resetRepositoryTestHooks(); await removeRepositoryFixture(fixture); }
  });

  await t.test("unsupported path encoding", async () => {
    const fixture = await createRepositoryFixture();
    try {
      const prefix = Buffer.from(`${fixture.repository}/`, "utf8");
      const invalidPath = Buffer.concat([prefix, Buffer.from([0xff, 0xfe])]);
      await writeFile(invalidPath, "invalid path bytes\n");
      const identity = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
      await assert.rejects(captureGitState(identity),
        (error: unknown) => codeOf(error) === "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING");
    } finally { await removeRepositoryFixture(fixture); }
  });
});
