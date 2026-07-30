import assert from "node:assert/strict";
import { chmod, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runPostflight,
} from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import {
  identifyContractDocument,
  type M3PostflightDocument,
  type M3RepositoryStateTokenDocument,
} from "../src/schemas/index.js";
import {
  createRepositoryFixture,
  git,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
  type RepositoryFixture,
} from "./repository-helpers.js";
import { baselineInput, pathDecision } from "./repository-matrix-helpers.js";

async function persist(
  fixture: RepositoryFixture,
  directory: string,
  document: { readonly content_sha256: string },
): Promise<void> {
  const path = join(fixture.stateRoot, "runs", fixture.runId, "records", directory, `${document.content_sha256.slice(7)}.json`);
  await writeFile(path, canonicalJsonRecordBytes(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function classification(fixture: RepositoryFixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

interface PreparedReversion {
  readonly paths: readonly string[];
  readonly restore: () => Promise<void>;
  readonly claimed: readonly string[];
  readonly expectedRepositoryPaths: readonly string[];
}

async function runReversion(
  fixture: RepositoryFixture,
  prepared: PreparedReversion,
): Promise<void> {
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const baseline = (await captureBaseline(await baselineInput(
      fixture, lock, "APPROVED_BASELINE_DIRTY", prepared.paths.map((path) => pathDecision(path)),
    ))).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
      approvedBy: "r5-r1-owner", approvedAt: "2026-01-01T00:00:00.000Z",
    })).approval;
    const selected = await instructionAuthorityInputs(fixture);
    const taskScopeIdentity = scopeIdentity(prepared.paths, ["AGENTS.md", "AUTHORITY.md"]);
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
      allowShallow: false, allowPartialClone: false, lock,
    });
    await prepared.restore();
    const result = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      editablePaths: prepared.paths, frozenPaths: ["AGENTS.md", "AUTHORITY.md"], taskScopeIdentity,
      claimedWorkflowPaths: prepared.claimed, lock,
    });
    assert.deepEqual(result.postflight.workflow_owned_delta.map((entry) => entry.path), [...prepared.claimed].sort());
    assert.ok(result.postflight.workflow_owned_delta.every((entry) => entry.change_kind === "BASELINE_REVERTED"));
    assert.deepEqual(result.postflight.repository_git_delta.map((entry) => entry.path), [...prepared.expectedRepositoryPaths].sort());
    assert.equal(await classification(fixture, result.postflight.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(fixture, result.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: result.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities, taskScopeIdentity, lock,
    });
    assert.equal(fast.result, "PASS");
  } finally {
    await releaseWorktreeLock(lock).catch(() => undefined);
  }
}

async function addSecondTrackedFile(fixture: RepositoryFixture): Promise<string> {
  const path = join(fixture.repository, "second.txt");
  await writeFile(path, "second\n");
  await git(fixture.repository, "add", "--", "second.txt");
  await git(fixture.repository, "commit", "-m", "second tracked file");
  return path;
}

test("R5-R1 baseline reversion positive matrix", async (t) => {
  await t.test("deleted baseline restored to stored HEAD", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await unlink(fixture.trackedPath);
      await runReversion(fixture, {
        paths: ["tracked.txt"], claimed: ["tracked.txt"], expectedRepositoryPaths: [],
        restore: async () => writeFile(fixture.trackedPath, "initial\n", { mode: 0o644 }),
      });
    } finally { await removeRepositoryFixture(fixture); }
  });
  await t.test("modified baseline restored to stored HEAD content", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await writeFile(fixture.trackedPath, "dirty\n");
      await runReversion(fixture, {
        paths: ["tracked.txt"], claimed: ["tracked.txt"], expectedRepositoryPaths: [],
        restore: async () => writeFile(fixture.trackedPath, "initial\n"),
      });
    } finally { await removeRepositoryFixture(fixture); }
  });
  await t.test("mode-changed baseline restored to stored HEAD mode", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await chmod(fixture.trackedPath, 0o755);
      await runReversion(fixture, {
        paths: ["tracked.txt"], claimed: ["tracked.txt"], expectedRepositoryPaths: [],
        restore: async () => chmod(fixture.trackedPath, 0o644),
      });
    } finally { await removeRepositoryFixture(fixture); }
  });
  await t.test("added baseline path removed to HEAD absence", async () => {
    const fixture = await createRepositoryFixture(); const added = join(fixture.repository, "added.txt");
    try {
      await writeFile(added, "added\n");
      await runReversion(fixture, {
        paths: ["added.txt"], claimed: ["added.txt"], expectedRepositoryPaths: [],
        restore: async () => unlink(added),
      });
    } finally { await removeRepositoryFixture(fixture); }
  });
  await t.test("mixed multi-path baseline fully reverted", async () => {
    const fixture = await createRepositoryFixture(); const second = await addSecondTrackedFile(fixture); const added = join(fixture.repository, "added.txt");
    try {
      await unlink(fixture.trackedPath); await writeFile(second, "second dirty\n"); await writeFile(added, "added\n");
      await runReversion(fixture, {
        paths: ["added.txt", "second.txt", "tracked.txt"],
        claimed: ["added.txt", "second.txt", "tracked.txt"], expectedRepositoryPaths: [],
        restore: async () => {
          await writeFile(fixture.trackedPath, "initial\n", { mode: 0o644 });
          await writeFile(second, "second\n");
          await unlink(added);
        },
      });
    } finally { await removeRepositoryFixture(fixture); }
  });
  await t.test("partial reversion leaves unmodified baseline dirt in repository delta", async () => {
    const fixture = await createRepositoryFixture(); const second = await addSecondTrackedFile(fixture);
    try {
      await unlink(fixture.trackedPath); await writeFile(second, "second dirty\n");
      await runReversion(fixture, {
        paths: ["second.txt", "tracked.txt"], claimed: ["tracked.txt"], expectedRepositoryPaths: ["second.txt"],
        restore: async () => writeFile(fixture.trackedPath, "initial\n", { mode: 0o644 }),
      });
    } finally { await removeRepositoryFixture(fixture); }
  });
});

test("R5-R1 staged rename reversion is explicitly unsupported because restoring HEAD mutates the frozen index", async () => {
  const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    await git(fixture.repository, "mv", "tracked.txt", "renamed.txt");
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("renamed.txt"), pathDecision("tracked.txt"),
    ]))).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
      approvedBy: "r5-r1-owner", approvedAt: "2026-01-01T00:00:00.000Z",
    })).approval;
    const selected = await instructionAuthorityInputs(fixture);
    const taskScopeIdentity = scopeIdentity(["renamed.txt", "tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
      allowShallow: false, allowPartialClone: false, lock,
    });
    await git(fixture.repository, "reset", "--hard", "HEAD");
    const before = (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "postflights"))).length;
    await assert.rejects(runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      editablePaths: ["renamed.txt", "tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"], taskScopeIdentity,
      claimedWorkflowPaths: ["renamed.txt", "tracked.txt"], lock,
    }));
    assert.equal((await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "postflights"))).length, before);
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

interface PostflightPair {
  readonly source: M3PostflightDocument;
  readonly token: M3RepositoryStateTokenDocument;
}

function forgedPair(
  valid: PostflightPair,
  mutate: (source: Record<string, unknown>) => void,
): PostflightPair {
  const sourceDraft = structuredClone(valid.source) as unknown as Record<string, unknown>;
  mutate(sourceDraft);
  const source = identifyContractDocument("pi_gacw_postflight_v0", sourceDraft) as unknown as M3PostflightDocument;
  const tokenDraft = structuredClone(valid.token) as unknown as Record<string, unknown>;
  tokenDraft["source_content_sha256"] = source.content_sha256;
  tokenDraft["workflow_owned_delta_sha256"] = sha256Canonical(source.workflow_owned_delta);
  tokenDraft["changed_paths"] = source.workflow_owned_delta.map((entry) => entry.path);
  const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft) as unknown as M3RepositoryStateTokenDocument;
  return { source, token };
}

test("R5-R1 deleted-baseline reversion forgery matrix", async (t) => {
  const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    await unlink(fixture.trackedPath);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [pathDecision("tracked.txt")]))).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
      approvedBy: "r5-r1-owner", approvedAt: "2026-01-01T00:00:00.000Z",
    })).approval;
    const selected = await instructionAuthorityInputs(fixture);
    const taskScopeIdentity = scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
      allowShallow: false, allowPartialClone: false, lock,
    });
    await writeFile(fixture.trackedPath, "initial\n", { mode: 0o644 });
    const produced = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      editablePaths: ["tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"], taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"], lock,
    });
    const valid = { source: produced.postflight, token: produced.acceptedState };
    const other = `sha256:${"9".repeat(64)}`;
    const variants: readonly [string, PostflightPair][] = [
      ["restored deletion wrong content", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["after_content_sha256"] = other; })],
      ["restored deletion wrong mode", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["after_mode"] = 0o755; })],
      ["restored deletion wrong type", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["after_type"] = "DIRECTORY"; })],
      ["reversion mislabeled ADDED", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["change_kind"] = "ADDED"; })],
      ["reversion mislabeled MODIFIED", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["change_kind"] = "MODIFIED"; })],
      ["reversion omitted", forgedPair(valid, (d) => { d["workflow_owned_delta"] = []; d["claimed_workflow_paths"] = []; })],
      ["reversion inserted into repository Git delta", forgedPair(valid, (d) => { d["repository_git_delta"] = structuredClone(d["workflow_owned_delta"]); })],
      ["wrong HEAD preimage", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["after_content_sha256"] = other; })],
      ["wrong absent baseline content", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["before_content_sha256"] = other; })],
      ["wrong absent baseline mode", forgedPair(valid, (d) => { (d["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["before_mode"] = 0o644; })],
    ];
    for (const [name, pair] of variants) {
      await t.test(name, async () => {
        await persist(fixture, "postflights", pair.source); await persist(fixture, "repository-state-tokens", pair.token);
        assert.equal(await classification(fixture, pair.source.content_sha256), "INVALID_MANAGED_RECORD");
        assert.equal(await classification(fixture, pair.token.content_sha256), "INVALID_MANAGED_RECORD");
        await assert.rejects(runFastPreflight({
          stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: pair.token, baseline,
          instructionFiles: selected.instructions, authorityFiles: selected.authorities, taskScopeIdentity, lock: lock!,
        }));
      });
    }
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});
