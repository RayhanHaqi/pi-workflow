import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runPostflight,
  type OwnershipClass,
} from "../src/repository/index.js";
import {
  baselineInput,
  codeOf,
  createCleanAdmission,
  pathDecision,
  releaseAdmission,
} from "./repository-matrix-helpers.js";
import {
  createRepositoryFixture,
  git,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
} from "./repository-helpers.js";

const execFileAsync = promisify(execFile);

function postOptions(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  admission: Awaited<ReturnType<typeof createCleanAdmission>>,
  claimedWorkflowPaths: readonly string[],
): Parameters<typeof runPostflight>[0] {
  return {
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    acceptedState: admission.full.acceptedState,
    baseline: admission.baseline,
    instructionFiles: admission.selected.instructions,
    authorityFiles: admission.selected.authorities,
    editablePaths: admission.editable,
    frozenPaths: admission.frozen,
    taskScopeIdentity: admission.taskScopeIdentity,
    claimedWorkflowPaths,
    lock: admission.lock,
  };
}

test("postflight accepts exact in-scope modification, deletion, untracked, and multi-path deltas", async (t) => {
  await t.test("one modification", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      await writeFile(fixture.trackedPath, "one\n");
      const result = await runPostflight(postOptions(fixture, admission, ["tracked.txt"]));
      assert.deepEqual(result.postflight.workflow_owned_delta.map((entry) => entry.path), ["tracked.txt"]);
      assert.equal(result.acceptedState.git_fingerprint.content_sha256, result.postflight.git_fingerprint.content_sha256);
      assert.equal(result.acceptedState.source_content_sha256, result.postflight.content_sha256);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("multiple modifications", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await writeFile(join(fixture.repository, "second.txt"), "second\n");
      await git(fixture.repository, "add", "second.txt"); await git(fixture.repository, "commit", "-m", "second path");
      const admission = await createCleanAdmission(fixture, {
        editable: ["tracked.txt", "second.txt"], frozen: ["AGENTS.md", "AUTHORITY.md"],
      });
      try {
        await writeFile(fixture.trackedPath, "one changed\n");
        await writeFile(join(fixture.repository, "second.txt"), "second changed\n");
        const result = await runPostflight(postOptions(fixture, admission, ["second.txt", "tracked.txt"]));
        assert.deepEqual(result.postflight.workflow_owned_delta.map((entry) => entry.path), ["second.txt", "tracked.txt"]);
        assert.deepEqual(result.acceptedState.changed_paths, ["second.txt", "tracked.txt"]);
      } finally { await releaseAdmission(admission); }
    } finally { await removeRepositoryFixture(fixture); }
  });

  await t.test("deletion", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      await unlink(fixture.trackedPath);
      const result = await runPostflight(postOptions(fixture, admission, ["tracked.txt"]));
      assert.equal(result.postflight.workflow_owned_delta[0]?.change_kind, "DELETED");
      assert.equal(result.postflight.workflow_owned_delta[0]?.after_type, "DELETED");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("untracked regular file", async () => {
    const fixture = await createRepositoryFixture();
    const admission = await createCleanAdmission(fixture, {
      editable: ["tracked.txt", "generated"], frozen: ["AGENTS.md", "AUTHORITY.md"],
    });
    try {
      await mkdir(join(fixture.repository, "generated"));
      await writeFile(join(fixture.repository, "generated", "new.txt"), "generated\n");
      const result = await runPostflight(postOptions(fixture, admission, ["generated/new.txt"]));
      assert.equal(result.postflight.workflow_owned_delta[0]?.change_kind, "ADDED");
      assert.equal(result.postflight.workflow_owned_delta[0]?.untracked, true);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
});

test("postflight blocks out-of-scope, frozen, unclaimed, special, and index changes", async (t) => {
  await t.test("out of scope", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      await writeFile(join(fixture.repository, "outside.txt"), "outside\n");
      await assert.rejects(runPostflight(postOptions(fixture, admission, ["outside.txt"])),
        (error: unknown) => codeOf(error) === "FORBIDDEN_PATH_CHANGED");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("frozen path", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await writeFile(join(fixture.repository, "frozen.txt"), "frozen\n");
      await git(fixture.repository, "add", "frozen.txt"); await git(fixture.repository, "commit", "-m", "frozen path");
      const admission = await createCleanAdmission(fixture, {
        editable: ["tracked.txt"], frozen: ["AGENTS.md", "AUTHORITY.md", "frozen.txt"],
      });
      try {
        await writeFile(join(fixture.repository, "frozen.txt"), "changed\n");
        await assert.rejects(runPostflight(postOptions(fixture, admission, ["frozen.txt"])),
          (error: unknown) => codeOf(error) === "FORBIDDEN_PATH_CHANGED");
      } finally { await releaseAdmission(admission); }
    } finally { await removeRepositoryFixture(fixture); }
  });

  for (const [name, mutate, claim] of [
    ["unclaimed changed path", async (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => writeFile(fixture.trackedPath, "changed\n"), []],
    ["unclaimed new path", async (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => writeFile(join(fixture.repository, "new.txt"), "new\n"), []],
  ] as const) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
      try {
        await mutate(fixture);
        await assert.rejects(runPostflight(postOptions(fixture, admission, claim)),
          (error: unknown) => codeOf(error) === "UNEXPECTED_REPOSITORY_DELTA");
      } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
    });
  }

  await t.test("symlink creation", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture, {
      editable: ["tracked.txt", "generated"], frozen: ["AGENTS.md", "AUTHORITY.md"],
    });
    try {
      await execFileAsync("ln", ["-s", "tracked.txt", join(fixture.repository, "generated")]);
      await assert.rejects(runPostflight(postOptions(fixture, admission, ["generated"])),
        (error: unknown) => codeOf(error) === "BASELINE_SPECIAL_PATH");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("FIFO creation", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture, {
      editable: ["tracked.txt", "generated"], frozen: ["AGENTS.md", "AUTHORITY.md"],
    });
    try {
      await execFileAsync("mkfifo", [join(fixture.repository, "generated")]);
      await assert.rejects(runPostflight(postOptions(fixture, admission, ["generated"])),
        (error: unknown) => codeOf(error) === "BASELINE_SPECIAL_PATH");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("index mutation", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      await writeFile(fixture.trackedPath, "indexed\n"); await git(fixture.repository, "add", "tracked.txt");
      await assert.rejects(runPostflight(postOptions(fixture, admission, ["tracked.txt"])),
        (error: unknown) => codeOf(error) === "INDEX_DRIFT");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
});

async function dirtyOwnershipAdmission(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  ownershipClass: OwnershipClass,
  ownerPathEditable = true,
) {
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const selected = await instructionAuthorityInputs(fixture);
  await writeFile(join(fixture.repository, "owner.txt"), "owner baseline\n");
  const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
    pathDecision("owner.txt", { ownershipClass, dataClass: "HASH_ONLY" }),
  ]))).baseline;
  const approval = (await createBaselineApproval({ stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
    approvedBy: "owner", approvedAt: "2026-01-01T00:00:00.000Z" })).approval;
  const editable = ownerPathEditable ? ["owner.txt", "tracked.txt"] : ["tracked.txt"];
  const frozen = ownerPathEditable ? ["AGENTS.md", "AUTHORITY.md"] : ["AGENTS.md", "AUTHORITY.md", "owner.txt"];
  const taskScopeIdentity = scopeIdentity(editable, frozen);
  const full = await runFullPreflight({
    stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
    expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
    expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
    baseline, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
    requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
    allowShallow: false, allowPartialClone: false, lock,
  });
  return { lock, selected, baseline, editable, frozen, taskScopeIdentity, full };
}

test("OWNER_AUTHORITY and PREEXISTING_UNRELATED baseline paths cannot be claimed", async (t) => {
  for (const ownership of ["OWNER_AUTHORITY", "PREEXISTING_UNRELATED"] as const) {
    await t.test(ownership, async () => {
      const fixture = await createRepositoryFixture(); const admission = await dirtyOwnershipAdmission(fixture, ownership);
      try {
        await writeFile(join(fixture.repository, "owner.txt"), "owner changed\n");
        await assert.rejects(runPostflight({
          stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: admission.full.acceptedState,
          baseline: admission.baseline, instructionFiles: admission.selected.instructions,
          authorityFiles: admission.selected.authorities, editablePaths: admission.editable,
          frozenPaths: admission.frozen, taskScopeIdentity: admission.taskScopeIdentity,
          claimedWorkflowPaths: ["owner.txt"], lock: admission.lock,
        }), (error: unknown) => codeOf(error) === "FORBIDDEN_PATH_CHANGED");
      } finally { await releaseWorktreeLock(admission.lock); await removeRepositoryFixture(fixture); }
    });
  }
});

test("postflight blocks mode/index/ref/operation drift and keeps both delta definitions exact", async (t) => {
  await t.test("mode is disclosed and evaluated", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      await chmod(fixture.trackedPath, 0o755);
      const result = await runPostflight(postOptions(fixture, admission, ["tracked.txt"]));
      assert.equal(result.postflight.workflow_owned_delta[0]?.after_mode, 0o755);
      assert.ok(["MODE_CHANGED", "MODIFIED"].includes(result.postflight.workflow_owned_delta[0]?.change_kind ?? ""));
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  const blockers: readonly [string, (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => Promise<void>, readonly string[]][] = [
    ["branch", async (fixture) => { await git(fixture.repository, "checkout", "-b", "post-branch"); }, ["WRONG_BRANCH"]],
    ["HEAD", async (fixture) => { await writeFile(join(fixture.repository, "head.txt"), "head\n"); await git(fixture.repository, "add", "head.txt"); await git(fixture.repository, "commit", "-m", "post HEAD"); }, ["HEAD_DRIFT"]],
    ["active operation", async (fixture) => { await writeFile(join(fixture.repository, ".git", "MERGE_HEAD"), await git(fixture.repository, "rev-parse", "HEAD")); }, ["GIT_OPERATION_IN_PROGRESS"]],
    ["index.lock", async (fixture) => { await writeFile(join(fixture.repository, ".git", "index.lock"), ""); }, ["GIT_INDEX_LOCK_PRESENT"]],
  ];
  for (const [name, mutate, codes] of blockers) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
      try {
        await mutate(fixture);
        await assert.rejects(runPostflight(postOptions(fixture, admission, [])),
          (error: unknown) => codes.includes(String(codeOf(error))));
      } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
    });
  }

  await t.test("dirty baseline makes repository and workflow deltas differ", async () => {
    const fixture = await createRepositoryFixture(); const admission = await dirtyOwnershipAdmission(fixture, "PREEXISTING_UNRELATED", false);
    try {
      await writeFile(fixture.trackedPath, "workflow\n");
      const result = await runPostflight({
        stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: admission.full.acceptedState,
        baseline: admission.baseline, instructionFiles: admission.selected.instructions,
        authorityFiles: admission.selected.authorities, editablePaths: admission.editable,
        frozenPaths: admission.frozen,
        taskScopeIdentity: admission.taskScopeIdentity,
        claimedWorkflowPaths: ["tracked.txt"], lock: admission.lock,
      });
      assert.deepEqual(result.postflight.repository_git_delta.map((entry) => entry.path), ["owner.txt", "tracked.txt"]);
      assert.deepEqual(result.postflight.workflow_owned_delta.map((entry) => entry.path), ["tracked.txt"]);
      assert.notEqual(
        JSON.stringify(result.postflight.repository_git_delta),
        JSON.stringify(result.postflight.workflow_owned_delta),
      );
    } finally { await releaseWorktreeLock(admission.lock); await removeRepositoryFixture(fixture); }
  });
});

test("only the exact successful postflight token advances fast-preflight authority", async () => {
  const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
  try {
    await writeFile(fixture.trackedPath, "postflight\n");
    const post = await runPostflight(postOptions(fixture, admission, ["tracked.txt"]));
    await assert.rejects(runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: admission.full.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    }), (error: unknown) => codeOf(error) === "BLOCKED_STATE_DRIFT");
    const accepted = await runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: post.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    });
    assert.equal(accepted.prior_token_content_sha256, post.acceptedState.content_sha256);
    await writeFile(fixture.trackedPath, "later\n");
    await assert.rejects(runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: post.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    }), (error: unknown) => codeOf(error) === "BLOCKED_STATE_DRIFT");
  } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
});
