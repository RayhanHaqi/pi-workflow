import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { identifyContractDocument, type M3BaselineRuntimeDocument, type M3RepositoryIdentityDocument } from "../src/schemas/index.js";
import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
} from "../src/repository/index.js";
import { baselineBlobPath } from "../src/repository/storage.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
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

async function tokenCount(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>): Promise<number> {
  return (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "repository-state-tokens"))).length;
}

function fullOptions(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  admission: Awaited<ReturnType<typeof createCleanAdmission>>,
  overrides: Partial<Parameters<typeof runFullPreflight>[0]> = {},
): Parameters<typeof runFullPreflight>[0] {
  return {
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    expectedRepository: admission.baseline.repository,
    expectedWorktreeKey: admission.baseline.repository.worktree_key,
    expectedBranch: admission.baseline.repository.branch,
    expectedHead: admission.baseline.repository.head,
    expectedWorktreeListSha256: admission.baseline.repository.worktree_list_sha256,
    baseline: admission.baseline,
    approval: null,
    instructionFiles: admission.selected.instructions,
    authorityFiles: admission.selected.authorities,
    requiredEnvironment: admission.environment,
    taskScopeIdentity: admission.taskScopeIdentity,
    allowShallow: false,
    allowPartialClone: false,
    lock: admission.lock,
    ...overrides,
  };
}

function identifiedClone<T extends Record<string, unknown>>(schemaId: Parameters<typeof identifyContractDocument>[0], value: T): T {
  const draft = structuredClone(value);
  delete (draft as Record<string, unknown>)["content_sha256"];
  return identifyContractDocument(schemaId, draft) as T;
}

function reboundBaseline(
  baseline: M3BaselineRuntimeDocument,
  mutateRepository: (draft: Record<string, unknown>) => void,
): { repository: M3RepositoryIdentityDocument; baseline: M3BaselineRuntimeDocument } {
  const repositoryDraft = structuredClone(baseline.repository) as unknown as Record<string, unknown>;
  delete repositoryDraft["content_sha256"];
  mutateRepository(repositoryDraft);
  const repository = identifyContractDocument("pi_gacw_repository_identity_v0", repositoryDraft) as unknown as M3RepositoryIdentityDocument;

  const fingerprintDraft = structuredClone(baseline.git_fingerprint) as unknown as Record<string, unknown>;
  delete fingerprintDraft["content_sha256"];
  fingerprintDraft["repository_identity_content_sha256"] = repository.content_sha256;
  const fingerprint = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", fingerprintDraft);

  const acceptedDraft = structuredClone(baseline.accepted_baseline) as unknown as Record<string, unknown>;
  delete acceptedDraft["content_sha256"];
  const target = acceptedDraft["target_repository"] as Record<string, unknown>;
  target["root"] = repository.worktree_root;
  target["git_common_dir"] = repository.git_common_dir;
  target["worktree"] = repository.worktree_root;
  target["branch"] = repository.branch ?? "DETACHED";
  target["head"] = repository.head;
  acceptedDraft["git_state_sha256"] = (fingerprint as Record<string, unknown>)["content_sha256"];
  const accepted = identifyContractDocument("pi_gacw_baseline_v0", acceptedDraft);

  const baselineDraft = structuredClone(baseline) as unknown as Record<string, unknown>;
  delete baselineDraft["content_sha256"];
  baselineDraft["repository"] = repository;
  baselineDraft["git_fingerprint"] = fingerprint;
  baselineDraft["accepted_baseline"] = accepted;
  return {
    repository,
    baseline: identifyContractDocument("pi_gacw_baseline_runtime_v0", baselineDraft) as unknown as M3BaselineRuntimeDocument,
  };
}

async function expectFullFailureNoToken(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  options: Parameters<typeof runFullPreflight>[0],
  codes: readonly string[],
): Promise<void> {
  const before = await tokenCount(fixture);
  await assert.rejects(runFullPreflight(options), (error: unknown) => codes.includes(String(codeOf(error))));
  assert.equal(await tokenCount(fixture), before);
}

async function createDirtyBlobAdmission(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) {
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const selected = await instructionAuthorityInputs(fixture);
  await writeFile(join(fixture.repository, "baseline-blob.txt"), "baseline blob\n");
  const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
    pathDecision("baseline-blob.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
  ]))).baseline;
  const approval = (await createBaselineApproval({ stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
    approvedBy: "owner", approvedAt: "2026-01-01T00:00:00.000Z" })).approval;
  const taskScopeIdentity = scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md", "baseline-blob.txt"]);
  const environment = await requiredEnvironment(fixture.repository);
  const full = await runFullPreflight({
    stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
    expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
    expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
    baseline, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
    requiredEnvironment: environment, taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock,
  });
  return { repository, lock, selected, baseline, approval, taskScopeIdentity, environment, full };
}

test("full preflight blocks every physical, Git-directory, worktree-key, branch, HEAD, and token expectation mismatch", async (t) => {
  const identityCases: readonly [string, (draft: Record<string, unknown>) => void, readonly string[]][] = [
    ["physical root", (draft) => { draft["physical_requested_path"] = "/wrong/physical/root"; }, ["WRONG_REPOSITORY"]],
    ["Git root", (draft) => { draft["git_toplevel"] = "/wrong/git/root"; }, ["WRONG_REPOSITORY"]],
    ["common Git directory", (draft) => { draft["git_common_dir"] = "/wrong/common/git"; }, ["LOCK_LOST"]],
    ["worktree Git directory", (draft) => { draft["git_dir"] = "/wrong/worktree/git"; draft["worktree_git_dir"] = "/wrong/worktree/git"; }, ["WRONG_WORKTREE"]],
    ["worktree key", (draft) => { draft["worktree_key"] = `sha256:${"f".repeat(64)}`; }, ["LOCK_LOST"]],
  ];
  for (const [name, mutate, codes] of identityCases) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      const admission = await createCleanAdmission(fixture);
      try {
        const rebound = reboundBaseline(admission.baseline, mutate);
        await expectFullFailureNoToken(fixture, fullOptions(fixture, admission, {
          expectedRepository: rebound.repository,
          expectedWorktreeKey: rebound.repository.worktree_key,
          expectedBranch: rebound.repository.branch,
          expectedHead: rebound.repository.head,
          expectedWorktreeListSha256: rebound.repository.worktree_list_sha256,
          baseline: rebound.baseline,
        }), codes);
      } finally {
        await releaseAdmission(admission);
        await removeRepositoryFixture(fixture);
      }
    });
  }

  const driftCases: readonly [string, (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => Promise<void>, readonly string[]][] = [
    ["wrong branch", async (fixture) => { await git(fixture.repository, "checkout", "-b", "full-branch"); }, ["WRONG_BRANCH"]],
    ["unexpected detached HEAD", async (fixture) => { await git(fixture.repository, "checkout", "--detach"); }, ["DETACHED_HEAD_UNEXPECTED"]],
    ["wrong HEAD", async (fixture) => {
      await writeFile(join(fixture.repository, "head.txt"), "head\n"); await git(fixture.repository, "add", "head.txt"); await git(fixture.repository, "commit", "-m", "move HEAD");
    }, ["HEAD_DRIFT"]],
    ["worktree list", async (fixture) => { await git(fixture.repository, "worktree", "add", "-b", "full-linked", join(fixture.root, "full-linked")); }, ["WORKTREE_LIST_DRIFT"]],
  ];
  for (const [name, mutate, codes] of driftCases) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      const admission = await createCleanAdmission(fixture);
      try {
        await mutate(fixture);
        await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), codes);
      } finally {
        await releaseAdmission(admission);
        await removeRepositoryFixture(fixture);
      }
    });
  }
});

test("full preflight blocks upstream, submodule, shallow, partial-clone, operation, conflict, and index-lock state", async (t) => {
  await t.test("upstream ahead/behind drift", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await writeFile(join(fixture.repository, "second.txt"), "second\n");
      await git(fixture.repository, "add", "second.txt");
      await git(fixture.repository, "commit", "-m", "second");
      await git(fixture.repository, "branch", "upstream-local", "main");
      await git(fixture.repository, "branch", "--set-upstream-to=upstream-local", "main");
      const admission = await createCleanAdmission(fixture);
      try {
        await git(fixture.repository, "branch", "-f", "upstream-local", "HEAD~1");
        await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), ["UPSTREAM_DRIFT"]);
      } finally { await releaseAdmission(admission); }
    } finally { await removeRepositoryFixture(fixture); }
  });

  await t.test("submodule drift", async () => {
    const fixture = await createRepositoryFixture();
    try {
      const subrepo = join(fixture.root, "subrepo");
      await mkdir(subrepo);
      await git(subrepo, "init", "-b", "main");
      await git(subrepo, "config", "user.name", "Submodule Test");
      await git(subrepo, "config", "user.email", "submodule@example.invalid");
      await writeFile(join(subrepo, "sub.txt"), "sub\n");
      await git(subrepo, "add", "sub.txt");
      await git(subrepo, "commit", "-m", "submodule baseline");
      await git(fixture.repository, "-c", "protocol.file.allow=always", "submodule", "add", subrepo, "sub");
      await git(fixture.repository, "commit", "-am", "add local submodule");
      const admission = await createCleanAdmission(fixture);
      try {
        await writeFile(join(fixture.repository, "sub", "sub.txt"), "sub drift\n");
        await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), ["BLOCKED_STATE_DRIFT"]);
      } finally { await releaseAdmission(admission); }
    } finally { await removeRepositoryFixture(fixture); }
  });

  for (const [name, configure, policyField] of [
    ["shallow", async (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => {
      await writeFile(join(fixture.repository, ".git", "shallow"), `${await git(fixture.repository, "rev-parse", "HEAD")}`);
    }, "allowShallow"],
    ["partial clone", async (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => {
      await git(fixture.repository, "config", "core.repositoryformatversion", "1");
      await git(fixture.repository, "config", "extensions.partialClone", "origin");
      await git(fixture.repository, "config", "remote.origin.partialclonefilter", "blob:none");
    }, "allowPartialClone"],
  ] as const) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
      try {
        await configure(fixture);
        const identity = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
        lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository: identity });
        const selected = await instructionAuthorityInputs(fixture);
        const baseline = (await captureBaseline({ ...(await baselineInput(fixture, lock, "CLEAN_REQUIRED", [], {
          allowShallow: true, allowPartialClone: true,
        })) })).baseline;
        await expectFullFailureNoToken(fixture, {
          stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
          expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
          expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
          baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
          requiredEnvironment: await requiredEnvironment(fixture.repository),
          taskScopeIdentity: scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]),
          allowShallow: policyField === "allowShallow" ? false : true,
          allowPartialClone: policyField === "allowPartialClone" ? false : true,
          lock,
        }, ["UNSUPPORTED_REPOSITORY_STATE"]);
      } finally {
        if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
        await removeRepositoryFixture(fixture);
      }
    });
  }

  const markerCases: readonly [string, string, "file" | "directory"][] = [
    ["merge", "MERGE_HEAD", "file"], ["rebase", "rebase-merge", "directory"],
    ["cherry-pick", "CHERRY_PICK_HEAD", "file"], ["revert", "REVERT_HEAD", "file"], ["bisect", "BISECT_LOG", "file"],
  ];
  for (const [name, marker, kind] of markerCases) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      const admission = await createCleanAdmission(fixture);
      try {
        const path = join(fixture.repository, ".git", marker);
        if (kind === "directory") await mkdir(path);
        else await writeFile(path, await git(fixture.repository, "rev-parse", "HEAD"));
        await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), ["GIT_OPERATION_IN_PROGRESS"]);
      } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
    });
  }

  await t.test("unmerged conflict without operation marker", async () => {
    const fixture = await createRepositoryFixture();
    const admission = await createCleanAdmission(fixture);
    try {
      const expectedHead = admission.baseline.repository.head;
      await git(fixture.repository, "checkout", "-b", "full-conflict-side");
      await writeFile(fixture.trackedPath, "side\n");
      await git(fixture.repository, "add", "tracked.txt");
      await git(fixture.repository, "commit", "-m", "full conflict side");
      await git(fixture.repository, "checkout", "main");
      await writeFile(fixture.trackedPath, "main\n");
      await git(fixture.repository, "add", "tracked.txt");
      await git(fixture.repository, "commit", "-m", "full conflict main");
      await assert.rejects(git(fixture.repository, "merge", "full-conflict-side"));
      await git(fixture.repository, "update-ref", "refs/heads/main", expectedHead);
      await unlink(join(fixture.repository, ".git", "MERGE_HEAD"));
      await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), ["GIT_CONFLICT_PRESENT"]);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("index.lock", async () => {
    const fixture = await createRepositoryFixture();
    const admission = await createCleanAdmission(fixture);
    try {
      await writeFile(join(fixture.repository, ".git", "index.lock"), "");
      await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), ["GIT_INDEX_LOCK_PRESENT"]);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
});

test("full preflight blocks authority, instruction, baseline, approval, blob, lock, tool, and capacity failures", async (t) => {
  for (const [name, mutate, code] of [
    ["instruction", async (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => writeFile(fixture.instructionPath, "instruction drift\n"), "INSTRUCTION_DRIFT"],
    ["authority", async (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => writeFile(fixture.authorityPath, "authority drift\n"), "AUTHORITY_DRIFT"],
  ] as const) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
      try { await mutate(fixture); await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), [code]); }
      finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
    });
  }

  await t.test("baseline mismatch", async () => {
    const firstFixture = await createRepositoryFixture();
    const secondFixture = await createRepositoryFixture();
    const first = await createCleanAdmission(firstFixture);
    const second = await createCleanAdmission(secondFixture);
    try {
      await expectFullFailureNoToken(firstFixture, fullOptions(firstFixture, first, { baseline: second.baseline }), ["BASELINE_APPROVAL_MISMATCH"]);
    } finally {
      await releaseAdmission(first); await releaseAdmission(second);
      await removeRepositoryFixture(firstFixture); await removeRepositoryFixture(secondFixture);
    }
  });

  await t.test("missing and wrong dirty approval", async () => {
    const fixture = await createRepositoryFixture();
    const dirty = await createDirtyBlobAdmission(fixture);
    try {
      const base = {
        stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: dirty.baseline.repository,
        expectedWorktreeKey: dirty.baseline.repository.worktree_key, expectedBranch: dirty.baseline.repository.branch,
        expectedHead: dirty.baseline.repository.head, expectedWorktreeListSha256: dirty.baseline.repository.worktree_list_sha256,
        baseline: dirty.baseline, instructionFiles: dirty.selected.instructions, authorityFiles: dirty.selected.authorities,
        requiredEnvironment: dirty.environment, taskScopeIdentity: dirty.taskScopeIdentity,
        allowShallow: false, allowPartialClone: false, lock: dirty.lock,
      };
      await expectFullFailureNoToken(fixture, { ...base, approval: null }, ["BASELINE_DIRTY_NOT_APPROVED"]);
      const wrong = identifiedClone("pi_gacw_baseline_approval_runtime_v0", {
        ...structuredClone(dirty.approval), approved_by: "different-owner",
      } as unknown as Record<string, unknown>) as never;
      await expectFullFailureNoToken(fixture, { ...base, approval: wrong }, ["BASELINE_APPROVAL_MISMATCH"]);
    } finally { await releaseWorktreeLock(dirty.lock); await removeRepositoryFixture(fixture); }
  });

  for (const [name, mutate] of [
    ["baseline blob missing", async (path: string) => unlink(path)],
    ["baseline blob modified", async (path: string) => { const bytes = await readFile(path); await writeFile(path, Buffer.alloc(bytes.length, 0x58), { mode: 0o600 }); await chmod(path, 0o600); }],
  ] as const) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); const dirty = await createDirtyBlobAdmission(fixture);
      try {
        const blob = dirty.baseline.paths[0]?.blob; assert.ok(blob);
        await mutate(baselineBlobPath({ stateRoot: fixture.stateRoot, runId: fixture.runId }, blob.blob_sha256));
        await expectFullFailureNoToken(fixture, {
          stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: dirty.baseline.repository,
          expectedWorktreeKey: dirty.baseline.repository.worktree_key, expectedBranch: dirty.baseline.repository.branch,
          expectedHead: dirty.baseline.repository.head, expectedWorktreeListSha256: dirty.baseline.repository.worktree_list_sha256,
          baseline: dirty.baseline, approval: dirty.approval, instructionFiles: dirty.selected.instructions,
          authorityFiles: dirty.selected.authorities, requiredEnvironment: dirty.environment,
          taskScopeIdentity: dirty.taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock: dirty.lock,
        }, ["STATE_STORAGE_INVALID", "CLEANUP_UNCERTAIN"]);
      } finally { await releaseWorktreeLock(dirty.lock); await removeRepositoryFixture(fixture); }
    });
  }

  await t.test("released lock, guardian loss, and wrong-worktree lock", async () => {
    const releasedFixture = await createRepositoryFixture(); const released = await createCleanAdmission(releasedFixture);
    await releaseWorktreeLock(released.lock);
    try { await expectFullFailureNoToken(releasedFixture, fullOptions(releasedFixture, released), ["LOCK_LOST"]); }
    finally { await removeRepositoryFixture(releasedFixture); }

    const lostFixture = await createRepositoryFixture(); const lost = await createCleanAdmission(lostFixture);
    try {
      process.kill(lost.lock.diagnostics.guardian_pid, "SIGKILL");
      await expectFullFailureNoToken(lostFixture, fullOptions(lostFixture, lost), ["LOCK_LOST"]);
    } finally { await releaseAdmission(lost); await removeRepositoryFixture(lostFixture); }

    const firstFixture = await createRepositoryFixture(); const first = await createCleanAdmission(firstFixture);
    const secondFixture = await createRepositoryFixture();
    const secondRepo = await resolveRepositoryIdentity({ requestedPath: secondFixture.repository, requireHead: true });
    const wrongLock = await acquireWorktreeLock({ stateRoot: firstFixture.stateRoot, repository: secondRepo });
    try {
      await expectFullFailureNoToken(firstFixture, fullOptions(firstFixture, first, { lock: wrongLock }), ["LOCK_LOST"]);
    } finally {
      await releaseWorktreeLock(wrongLock); await releaseAdmission(first);
      await removeRepositoryFixture(firstFixture); await removeRepositoryFixture(secondFixture);
    }
  });

  await t.test("wrong Git origin is rejected while Python remains acquisition-bound", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    const originalPath = process.env["PATH"];
    let bin: string | undefined;
    try {
      await expectFullFailureNoToken(fixture, fullOptions(fixture, admission, {
        requiredEnvironment: { ...admission.environment, git_path: "/wrong/git" },
      }), ["ENVIRONMENT_DRIFT"]);
      bin = await mkdtemp(join(tmpdir(), "m3-r1-tools-"));
      await symlink(admission.environment.git_path, join(bin, "git"));
      process.env["PATH"] = bin;
      const repeated = await runFullPreflight(fullOptions(fixture, admission));
      assert.equal(repeated.preflight.environment_fingerprint.python_path, admission.lock.diagnostics.guardian_python_path);
      assert.equal(repeated.preflight.environment_fingerprint.python_version, admission.lock.diagnostics.guardian_python_version);
    } finally {
      process.env["PATH"] = originalPath;
      if (bin !== undefined) await rm(bin, { recursive: true, force: true });
      await releaseAdmission(admission); await removeRepositoryFixture(fixture);
    }
  });

  await t.test("state-root capacity", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      configureRepositoryTestHooks({ stateRootBytes: 2_147_483_649 });
      await expectFullFailureNoToken(fixture, fullOptions(fixture, admission), ["INVALID_ARGUMENT", "STATE_ROOT_LIMIT_EXCEEDED"]);
    } finally { resetRepositoryTestHooks(); await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
});

function fastOptions(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  admission: Awaited<ReturnType<typeof createCleanAdmission>>,
  overrides: Partial<Parameters<typeof runFastPreflight>[0]> = {},
): Parameters<typeof runFastPreflight>[0] {
  return {
    stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: admission.full.acceptedState,
    baseline: admission.baseline, instructionFiles: admission.selected.instructions,
    authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity,
    lock: admission.lock, ...overrides,
  };
}

test("fast preflight rejects every repository, index, authority, scope, worktree, and lock drift without adoption", async (t) => {
  const cases: readonly [string, (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, admission: Awaited<ReturnType<typeof createCleanAdmission>>) => Promise<void>, readonly string[]][] = [
    ["regular modification", async (fixture) => { await writeFile(fixture.trackedPath, "modified\n"); }, ["BLOCKED_STATE_DRIFT"]],
    ["new regular file", async (fixture) => { await writeFile(join(fixture.repository, "new.txt"), "new\n"); }, ["BLOCKED_STATE_DRIFT"]],
    ["deletion", async (fixture) => { await unlink(fixture.trackedPath); }, ["BLOCKED_STATE_DRIFT"]],
    ["mode", async (fixture) => { await chmod(fixture.trackedPath, 0o755); }, ["BLOCKED_STATE_DRIFT"]],
    ["index", async (fixture) => { await writeFile(fixture.trackedPath, "index\n"); await git(fixture.repository, "add", "tracked.txt"); }, ["BLOCKED_STATE_DRIFT"]],
    ["branch", async (fixture) => { await git(fixture.repository, "checkout", "-b", "fast-branch"); }, ["WRONG_BRANCH"]],
    ["HEAD", async (fixture) => { await writeFile(join(fixture.repository, "head.txt"), "head\n"); await git(fixture.repository, "add", "head.txt"); await git(fixture.repository, "commit", "-m", "fast HEAD"); }, ["HEAD_DRIFT"]],
    ["instruction", async (fixture) => { await writeFile(fixture.instructionPath, "instruction\n"); }, ["INSTRUCTION_DRIFT"]],
    ["authority", async (fixture) => { await writeFile(fixture.authorityPath, "authority\n"); }, ["AUTHORITY_DRIFT"]],
    ["linked worktree added", async (fixture) => { await git(fixture.repository, "worktree", "add", "-b", "fast-linked", join(fixture.root, "fast-linked")); }, ["WORKTREE_LIST_DRIFT"]],
    ["active operation", async (fixture) => { await writeFile(join(fixture.repository, ".git", "MERGE_HEAD"), await git(fixture.repository, "rev-parse", "HEAD")); }, ["GIT_OPERATION_IN_PROGRESS"]],
    ["index.lock", async (fixture) => { await writeFile(join(fixture.repository, ".git", "index.lock"), ""); }, ["GIT_INDEX_LOCK_PRESENT"]],
    ["guardian death", async (_fixture, admission) => { process.kill(admission.lock.diagnostics.guardian_pid, "SIGKILL"); }, ["LOCK_LOST"]],
  ];
  for (const [name, mutate, codes] of cases) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
      const acceptedIdentity = admission.full.acceptedState.content_sha256;
      try {
        await mutate(fixture, admission);
        await assert.rejects(runFastPreflight(fastOptions(fixture, admission)), (error: unknown) => codes.includes(String(codeOf(error))));
        assert.equal(admission.full.acceptedState.content_sha256, acceptedIdentity);
      } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
    });
  }

  await t.test("explicit lock release", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    await releaseWorktreeLock(admission.lock);
    try { await assert.rejects(runFastPreflight(fastOptions(fixture, admission)), (error: unknown) => codeOf(error) === "LOCK_LOST"); }
    finally { await removeRepositoryFixture(fixture); }
  });

  await t.test("wrong task scope", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      await assert.rejects(runFastPreflight(fastOptions(fixture, admission, {
        taskScopeIdentity: sha256Canonical({ different: true }),
      })), (error: unknown) => codeOf(error) === "BLOCKED_STATE_DRIFT");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("upstream divergence", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await writeFile(join(fixture.repository, "second.txt"), "second\n"); await git(fixture.repository, "add", "second.txt"); await git(fixture.repository, "commit", "-m", "second");
      await git(fixture.repository, "branch", "upstream-local", "main"); await git(fixture.repository, "branch", "--set-upstream-to=upstream-local", "main");
      const admission = await createCleanAdmission(fixture);
      try {
        await git(fixture.repository, "branch", "-f", "upstream-local", "HEAD~1");
        await assert.rejects(runFastPreflight(fastOptions(fixture, admission)), (error: unknown) => codeOf(error) === "UPSTREAM_DRIFT");
      } finally { await releaseAdmission(admission); }
    } finally { await removeRepositoryFixture(fixture); }
  });

  await t.test("linked worktree removed", async () => {
    const fixture = await createRepositoryFixture();
    const linked = join(fixture.root, "linked-before");
    try {
      await git(fixture.repository, "worktree", "add", "-b", "linked-before", linked);
      const admission = await createCleanAdmission(fixture);
      try {
        await git(fixture.repository, "worktree", "remove", linked);
        await assert.rejects(runFastPreflight(fastOptions(fixture, admission)), (error: unknown) => codeOf(error) === "WORKTREE_LIST_DRIFT");
      } finally { await releaseAdmission(admission); }
    } finally { await removeRepositoryFixture(fixture); }
  });

  for (const [name, mutate] of [
    ["blob deletion", async (path: string) => unlink(path)],
    ["blob modification", async (path: string) => { const bytes = await readFile(path); await writeFile(path, Buffer.alloc(bytes.length, 0x59), { mode: 0o600 }); await chmod(path, 0o600); }],
  ] as const) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); const dirty = await createDirtyBlobAdmission(fixture);
      try {
        const blob = dirty.baseline.paths[0]?.blob; assert.ok(blob);
        await mutate(baselineBlobPath({ stateRoot: fixture.stateRoot, runId: fixture.runId }, blob.blob_sha256));
        await assert.rejects(runFastPreflight({
          stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: dirty.full.acceptedState,
          baseline: dirty.baseline, instructionFiles: dirty.selected.instructions,
          authorityFiles: dirty.selected.authorities, taskScopeIdentity: dirty.taskScopeIdentity, lock: dirty.lock,
        }), (error: unknown) => codeOf(error) === "STATE_STORAGE_INVALID" || codeOf(error) === "CLEANUP_UNCERTAIN");
      } finally { await releaseWorktreeLock(dirty.lock); await removeRepositoryFixture(fixture); }
    });
  }
});
