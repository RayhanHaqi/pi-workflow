import assert from "node:assert/strict";
import { chmod, writeFile } from "node:fs/promises";
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
  type BaselinePathDecision,
} from "../src/repository/index.js";
import {
  createRepositoryFixture,
  fingerprintInput,
  git,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
} from "./repository-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

async function cleanAdmission(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) {
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const selected = await instructionAuthorityInputs(fixture);
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
    lock,
  })).baseline;
  const editable = ["tracked.txt"];
  const frozen = ["AGENTS.md", "AUTHORITY.md"];
  const taskScopeIdentity = scopeIdentity(editable, frozen);
  const environment = await requiredEnvironment(fixture.repository);
  const full = await runFullPreflight({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    expectedRepository: baseline.repository,
    expectedWorktreeKey: baseline.repository.worktree_key,
    expectedBranch: baseline.repository.branch,
    expectedHead: baseline.repository.head,
    expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
    baseline,
    approval: null,
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    requiredEnvironment: environment,
    taskScopeIdentity,
    allowShallow: false,
    allowPartialClone: false,
    lock,
  });
  return { repository, lock, selected, baseline, editable, frozen, taskScopeIdentity, environment, full };
}

test("full and fast preflight admit only the exact baseline and postflight token", async () => {
  const fixture = await createRepositoryFixture();
  const admitted = await cleanAdmission(fixture);
  try {
    assert.equal(admitted.full.preflight.result, "PASS");
    assert.equal(admitted.full.acceptedState.source, "FULL_PREFLIGHT");
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: admitted.full.acceptedState,
      baseline: admitted.baseline,
      instructionFiles: admitted.selected.instructions,
      authorityFiles: admitted.selected.authorities,
      taskScopeIdentity: admitted.taskScopeIdentity,
      lock: admitted.lock,
    });
    assert.equal(fast.preflight_kind, "FAST");

    await writeFile(fixture.trackedPath, "workflow change\n");
    const postflight = await runPostflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: admitted.full.acceptedState,
      baseline: admitted.baseline,
      instructionFiles: admitted.selected.instructions,
      authorityFiles: admitted.selected.authorities,
      editablePaths: admitted.editable,
      frozenPaths: admitted.frozen,
      taskScopeIdentity: admitted.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"],
      lock: admitted.lock,
    });
    assert.equal(postflight.postflight.workflow_owned_delta.length, 1);
    assert.equal(postflight.postflight.repository_git_delta.length, 1);
    assert.equal(postflight.acceptedState.source, "POSTFLIGHT");

    await runFastPreflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: postflight.acceptedState,
      baseline: admitted.baseline,
      instructionFiles: admitted.selected.instructions,
      authorityFiles: admitted.selected.authorities,
      taskScopeIdentity: admitted.taskScopeIdentity,
      lock: admitted.lock,
    });

    await writeFile(join(fixture.repository, "external.txt"), "external writer\n");
    await assert.rejects(
      runFastPreflight({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        acceptedState: postflight.acceptedState,
        baseline: admitted.baseline,
        instructionFiles: admitted.selected.instructions,
        authorityFiles: admitted.selected.authorities,
        taskScopeIdentity: admitted.taskScopeIdentity,
        lock: admitted.lock,
      }),
      (error: unknown) => codeOf(error) === "BLOCKED_STATE_DRIFT",
    );
  } finally {
    await releaseWorktreeLock(admitted.lock);
    await removeRepositoryFixture(fixture);
  }
});

test("postflight rejects unclaimed external edits, out-of-scope edits, and index drift", async (t) => {
  await t.test("unclaimed and out of scope", async () => {
    const fixture = await createRepositoryFixture();
    const admitted = await cleanAdmission(fixture);
    try {
      await writeFile(fixture.trackedPath, "external edit\n");
      await assert.rejects(
        runPostflight({
          stateRoot: fixture.stateRoot,
          runId: fixture.runId,
          acceptedState: admitted.full.acceptedState,
          baseline: admitted.baseline,
          instructionFiles: admitted.selected.instructions,
          authorityFiles: admitted.selected.authorities,
          editablePaths: admitted.editable,
          frozenPaths: admitted.frozen,
          taskScopeIdentity: admitted.taskScopeIdentity,
          claimedWorkflowPaths: [],
          lock: admitted.lock,
        }),
        (error: unknown) => codeOf(error) === "UNEXPECTED_REPOSITORY_DELTA",
      );
    } finally {
      await releaseWorktreeLock(admitted.lock);
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("index mutation", async () => {
    const fixture = await createRepositoryFixture();
    const admitted = await cleanAdmission(fixture);
    try {
      await writeFile(fixture.trackedPath, "indexed externally\n");
      await git(fixture.repository, "add", "tracked.txt");
      await assert.rejects(
        runPostflight({
          stateRoot: fixture.stateRoot,
          runId: fixture.runId,
          acceptedState: admitted.full.acceptedState,
          baseline: admitted.baseline,
          instructionFiles: admitted.selected.instructions,
          authorityFiles: admitted.selected.authorities,
          editablePaths: admitted.editable,
          frozenPaths: admitted.frozen,
          taskScopeIdentity: admitted.taskScopeIdentity,
          claimedWorkflowPaths: ["tracked.txt"],
          lock: admitted.lock,
        }),
        (error: unknown) => codeOf(error) === "INDEX_DRIFT",
      );
    } finally {
      await releaseWorktreeLock(admitted.lock);
      await removeRepositoryFixture(fixture);
    }
  });
});

test("branch, HEAD, worktree-list, instruction, authority, mode, deletion, and lock drift are typed", async (t) => {
  const scenarios: readonly [string, (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => Promise<void>, string][] = [
    ["branch", async (fixture) => { await git(fixture.repository, "checkout", "-b", "external-branch"); }, "WRONG_BRANCH"],
    ["instruction", async (fixture) => { await writeFile(fixture.instructionPath, "changed instructions\n"); }, "INSTRUCTION_DRIFT"],
    ["authority", async (fixture) => { await writeFile(fixture.authorityPath, "changed authority\n"); }, "AUTHORITY_DRIFT"],
    ["worktree list", async (fixture) => { await git(fixture.repository, "worktree", "add", "-b", "external-linked", join(fixture.root, "external-linked")); }, "WORKTREE_LIST_DRIFT"],
  ];
  for (const [name, mutate, expectedCode] of scenarios) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      const admitted = await cleanAdmission(fixture);
      try {
        await mutate(fixture);
        await assert.rejects(
          runFastPreflight({
            stateRoot: fixture.stateRoot,
            runId: fixture.runId,
            acceptedState: admitted.full.acceptedState,
            baseline: admitted.baseline,
            instructionFiles: admitted.selected.instructions,
            authorityFiles: admitted.selected.authorities,
            taskScopeIdentity: admitted.taskScopeIdentity,
            lock: admitted.lock,
          }),
          (error: unknown) => codeOf(error) === expectedCode,
        );
      } finally {
        await releaseWorktreeLock(admitted.lock);
        await removeRepositoryFixture(fixture);
      }
    });
  }

  await t.test("mode and deletion are disclosed when claimed", async () => {
    const fixture = await createRepositoryFixture();
    const admitted = await cleanAdmission(fixture);
    try {
      await chmod(fixture.trackedPath, 0o755);
      const modeResult = await runPostflight({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        acceptedState: admitted.full.acceptedState,
        baseline: admitted.baseline,
        instructionFiles: admitted.selected.instructions,
        authorityFiles: admitted.selected.authorities,
        editablePaths: admitted.editable,
        frozenPaths: admitted.frozen,
        taskScopeIdentity: admitted.taskScopeIdentity,
        claimedWorkflowPaths: ["tracked.txt"],
        lock: admitted.lock,
      });
      assert.equal(modeResult.postflight.workflow_owned_delta[0]?.change_kind, "MODE_CHANGED");
      assert.equal(modeResult.postflight.workflow_owned_delta[0]?.after_mode, 0o755);
    } finally {
      await releaseWorktreeLock(admitted.lock);
      await removeRepositoryFixture(fixture);
    }
  });
});

test("dirty baseline keeps repository Git delta separate from workflow-owned delta", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await writeFile(join(fixture.repository, "owner.txt"), "owner baseline\n");
    const selected = await instructionAuthorityInputs(fixture);
    const ownerDecision: BaselinePathDecision = {
      path: "owner.txt",
      ownershipClass: "PREEXISTING_UNRELATED",
      dataClass: "HASH_ONLY",
      captureMode: "HASH_ONLY",
      explicitBlobApproval: false,
      retentionDaysAfterTerminal: null,
    };
    const baseline = (await captureBaseline({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      requestedPath: fixture.repository,
      mode: "APPROVED_BASELINE_DIRTY",
      pathDecisions: [ownerDecision],
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      allowShallow: false,
      allowPartialClone: false,
      lock,
    })).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline,
      approvedBy: "owner",
      approvedAt: "2026-01-01T00:00:00.000Z",
    })).approval;
    const editable = ["tracked.txt"];
    const frozen = ["AGENTS.md", "AUTHORITY.md", "owner.txt"];
    const taskScopeIdentity = scopeIdentity(editable, frozen);
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRepository: baseline.repository,
      expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch,
      expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline,
      approval,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository),
      taskScopeIdentity,
      allowShallow: false,
      allowPartialClone: false,
      lock,
    });
    await writeFile(fixture.trackedPath, "workflow-owned\n");
    const post = await runPostflight({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      acceptedState: full.acceptedState,
      baseline,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      editablePaths: editable,
      frozenPaths: frozen,
      taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"],
      lock,
    });
    assert.deepEqual(post.postflight.repository_git_delta.map((entry) => entry.path), ["owner.txt", "tracked.txt"]);
    assert.deepEqual(post.postflight.workflow_owned_delta.map((entry) => entry.path), ["tracked.txt"]);
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});
