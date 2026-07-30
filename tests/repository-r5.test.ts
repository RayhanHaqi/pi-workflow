import assert from "node:assert/strict";
import { chmod, mkdir, realpath, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { m3PorcelainIdentityProjection } from "../src/persistence/m3-authority.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  createBaselineApproval,
  inspectRetention,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runPostflight,
  verifyBaselineApproval,
} from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import {
  identifyContractDocument,
  type M3BaselineRuntimeDocument,
  type M3RetentionResultDocument,
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
import {
  baselineInput,
  createTerminalBlobFixture,
  pathDecision,
  retentionInput,
} from "./repository-matrix-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { readonly code: unknown }).code
    : undefined;
}

async function persist(
  fixture: RepositoryFixture,
  directory: string,
  document: { readonly content_sha256: string },
): Promise<void> {
  const path = join(
    fixture.stateRoot,
    "runs",
    fixture.runId,
    "records",
    directory,
    `${document.content_sha256.slice("sha256:".length)}.json`,
  );
  await writeFile(path, canonicalJsonRecordBytes(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function classification(fixture: RepositoryFixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

function refreshFingerprint(draft: Record<string, unknown>): void {
  const fingerprint = draft["git_fingerprint"] as Record<string, unknown>;
  fingerprint["staged_diff_sha256"] = sha256Canonical(fingerprint["staged"]);
  fingerprint["unstaged_diff_sha256"] = sha256Canonical(fingerprint["unstaged"]);
  fingerprint["untracked_inventory_sha256"] = sha256Canonical(fingerprint["untracked"]);
  fingerprint["porcelain_v2_sha256"] = sha256Canonical(m3PorcelainIdentityProjection(fingerprint as never));
  const identified = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", fingerprint);
  draft["git_fingerprint"] = identified;
  const accepted = draft["accepted_baseline"] as Record<string, unknown>;
  accepted["git_state_sha256"] = identified.content_sha256;
  draft["accepted_baseline"] = identifyContractDocument("pi_gacw_baseline_v0", accepted);
}

function identifyBaseline(
  baseline: M3BaselineRuntimeDocument,
  mutate: (draft: Record<string, unknown>) => void,
): M3BaselineRuntimeDocument {
  const draft = structuredClone(baseline) as unknown as Record<string, unknown>;
  mutate(draft);
  refreshFingerprint(draft);
  for (const path of draft["paths"] as Array<Record<string, unknown>>) {
    const fingerprint = draft["git_fingerprint"] as M3BaselineRuntimeDocument["git_fingerprint"];
    const name = path["path"] as string;
    path["status_sha256"] = sha256Canonical({
      staged: fingerprint.staged.filter((entry) => entry.path === name || entry.old_path === name),
      unstaged: fingerprint.unstaged.filter((entry) => entry.path === name || entry.old_path === name),
      untracked: fingerprint.untracked.filter((entry) => entry.path === name),
      conflicts: fingerprint.conflicts.filter((entry) => entry.path === name),
    });
  }
  return identifyContractDocument("pi_gacw_baseline_runtime_v0", draft) as unknown as M3BaselineRuntimeDocument;
}

async function assertForgedModeRejected(
  fixture: RepositoryFixture,
  baseline: M3BaselineRuntimeDocument,
): Promise<void> {
  await persist(fixture, "baselines", baseline);
  await assert.rejects(
    createBaselineApproval({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline,
      approvedBy: "r5-owner",
      approvedAt: "2026-01-01T00:00:00.000Z",
    }),
    (error: unknown) => codeOf(error) === "BASELINE_PROVENANCE_INVALID",
  );
  assert.equal(await classification(fixture, baseline.content_sha256), "INVALID_MANAGED_RECORD");
}

test("R5 staged-mode-binding validates the exact HEAD-index-worktree mode layers", async (t) => {
  const cases: readonly [string, (fixture: RepositoryFixture) => Promise<void>, (baseline: M3BaselineRuntimeDocument) => M3BaselineRuntimeDocument][] = [
    [
      "staged-only worktree mode",
      async (fixture) => { await writeFile(fixture.trackedPath, "staged\n"); await git(fixture.repository, "add", "--", "tracked.txt"); },
      (baseline) => identifyBaseline(baseline, (draft) => {
        const staged = ((draft["git_fingerprint"] as Record<string, unknown>)["staged"] as Array<Record<string, unknown>>)[0]!;
        staged["worktree_mode"] = staged["worktree_mode"] === "100755" ? "100644" : "100755";
      }),
    ],
    [
      "mixed staged and unstaged worktree mode",
      async (fixture) => {
        await writeFile(fixture.trackedPath, "index\n"); await git(fixture.repository, "add", "--", "tracked.txt");
        await writeFile(fixture.trackedPath, "worktree\n");
      },
      (baseline) => identifyBaseline(baseline, (draft) => {
        const staged = ((draft["git_fingerprint"] as Record<string, unknown>)["staged"] as Array<Record<string, unknown>>)[0]!;
        staged["worktree_mode"] = staged["worktree_mode"] === "100755" ? "100644" : "100755";
      }),
    ],
    [
      "staged deletion worktree sentinel",
      async (fixture) => { await git(fixture.repository, "rm", "--", "tracked.txt"); },
      (baseline) => identifyBaseline(baseline, (draft) => {
        const staged = ((draft["git_fingerprint"] as Record<string, unknown>)["staged"] as Array<Record<string, unknown>>)[0]!;
        staged["worktree_mode"] = "100644";
      }),
    ],
  ];
  for (const [name, setup, forge] of cases) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
      try {
        await setup(fixture);
        const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
        lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
        const baseline = (await captureBaseline(await baselineInput(
          fixture,
          lock,
          "APPROVED_BASELINE_DIRTY",
          [pathDecision("tracked.txt")],
        ))).baseline;
        assert.equal(await classification(fixture, baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
        await assertForgedModeRejected(fixture, forge(baseline));
      } finally {
        if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
        await removeRepositoryFixture(fixture);
      }
    });
  }
});

test("R5 retained-population-continuity invalidates every dependent authority after unproved loss", async () => {
  const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    await writeFile(join(fixture.repository, "quota.txt"), "quota-bytes\n");
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const owner = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("quota.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
    ]))).baseline;
    const later = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("quota.txt"),
    ]))).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot, runId: fixture.runId, baseline: later,
      approvedBy: "r5-owner", approvedAt: "2026-01-01T00:00:00.000Z",
    })).approval;
    const selected = await instructionAuthorityInputs(fixture);
    const taskScopeIdentity = scopeIdentity(["quota.txt"], ["AGENTS.md", "AUTHORITY.md"]);
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: later.repository, expectedWorktreeKey: later.repository.worktree_key,
      expectedBranch: later.repository.branch, expectedHead: later.repository.head,
      expectedWorktreeListSha256: later.repository.worktree_list_sha256,
      baseline: later, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
      allowShallow: false, allowPartialClone: false, lock,
    });
    const blob = owner.paths[0]!.blob!;
    await unlink(join(fixture.stateRoot, "runs", fixture.runId, blob.relative_path));

    assert.equal(await classification(fixture, owner.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(fixture, later.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(fixture, approval.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(fixture, full.preflight.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(fixture, full.acceptedState.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await verifyBaselineApproval({ stateRoot: fixture.stateRoot, runId: fixture.runId, baseline: later, approval }), false);
    await assert.rejects(runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: later.repository, expectedWorktreeKey: later.repository.worktree_key,
      expectedBranch: later.repository.branch, expectedHead: later.repository.head,
      expectedWorktreeListSha256: later.repository.worktree_list_sha256,
      baseline: later, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
      allowShallow: false, allowPartialClone: false, lock,
    }), (error: unknown) => codeOf(error) === "BASELINE_PROVENANCE_INVALID");
    await assert.rejects(runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState, baseline: later,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities, taskScopeIdentity, lock,
    }));
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R5 exact cleanup proof preserves a removed blob baseline as complete authority", async () => {
  const value = await createTerminalBlobFixture([{ name: "proof.txt", bytes: "proof\n" }]);
  try {
    await applyRetentionCleanup(retentionInput(value));
    assert.equal(await classification(value.fixture, value.baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, value.approval.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("R5 guardian-interpreter-provenance binds acquisition wrapper and helper identity", async () => {
  const fixture = await createRepositoryFixture();
  const wrapperRoot = join(fixture.root, "wrappers");
  const wrapperA = join(wrapperRoot, "a");
  const wrapperB = join(wrapperRoot, "b");
  await mkdir(wrapperA, { recursive: true, mode: 0o700 });
  await mkdir(wrapperB, { recursive: true, mode: 0o700 });
  const python = await realpath("/usr/bin/python3");
  for (const directory of [wrapperA, wrapperB]) {
    const path = join(directory, "python3");
    await writeFile(path, `#!/bin/sh\nexec ${python} "$@"\n`, { mode: 0o700 });
    await chmod(path, 0o700);
  }
  const originalPath = process.env["PATH"];
  let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    process.env["PATH"] = `${wrapperA}:${originalPath}`;
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const requiredA = await requiredEnvironment(fixture.repository);
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", []))).baseline;
    const selected = await instructionAuthorityInputs(fixture);
    const taskScopeIdentity = scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
    process.env["PATH"] = `${wrapperB}:${originalPath}`;
    const full = await runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: requiredA, taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock,
    });
    assert.equal(full.preflight.environment_fingerprint.python_path, await realpath(join(wrapperA, "python3")));
    assert.equal(full.preflight.environment_fingerprint.guardian_helper_path, lock.diagnostics.guardian_helper_path);
    assert.equal(full.preflight.environment_fingerprint.guardian_helper_sha256, lock.diagnostics.guardian_helper_sha256);
    assert.equal(await classification(fixture, full.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");

    const requiredB = await requiredEnvironment(fixture.repository);
    await assert.rejects(runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId,
      expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: requiredB, taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock,
    }), (error: unknown) => codeOf(error) === "ENVIRONMENT_DRIFT");

    const sourceDraft = structuredClone(full.preflight) as any;
    sourceDraft.environment_fingerprint.python_path = await realpath(join(wrapperB, "python3"));
    const { content_sha256: _old, ...projection } = sourceDraft.environment_fingerprint;
    sourceDraft.environment_fingerprint.content_sha256 = sha256Canonical(projection);
    const source = identifyContractDocument("pi_gacw_preflight_v0", sourceDraft);
    const tokenDraft = structuredClone(full.acceptedState) as any;
    tokenDraft.source_content_sha256 = source.content_sha256;
    const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft);
    await persist(fixture, "preflights", source);
    await persist(fixture, "repository-state-tokens", token);
    assert.equal(await classification(fixture, source.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(fixture, token.content_sha256), "INVALID_MANAGED_RECORD");

    await unlink(join(wrapperA, "python3"));
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities, taskScopeIdentity, lock,
    });
    assert.equal(fast.result, "PASS");
  } finally {
    if (originalPath === undefined) delete process.env["PATH"];
    else process.env["PATH"] = originalPath;
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R5 deleted-baseline-reversion produces an authoritative baseline-to-HEAD transition", async () => {
  const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    await unlink(fixture.trackedPath);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const baseline = (await captureBaseline(await baselineInput(
      fixture, lock, "APPROVED_BASELINE_DIRTY", [pathDecision("tracked.txt")],
    ))).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
      approvedBy: "r5-owner", approvedAt: "2026-01-01T00:00:00.000Z",
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
    const postflight = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      editablePaths: ["tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"], taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"], lock,
    });
    assert.deepEqual(postflight.postflight.repository_git_delta, []);
    assert.equal(postflight.postflight.workflow_owned_delta.length, 1);
    const delta = postflight.postflight.workflow_owned_delta[0]!;
    assert.equal(delta.change_kind, "BASELINE_REVERTED");
    assert.equal(delta.before_content_sha256, null);
    assert.equal(delta.before_type, "DELETED");
    assert.equal(delta.before_mode, null);
    assert.equal(delta.after_type, "REGULAR");
    assert.equal(await classification(fixture, postflight.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: postflight.acceptedState, baseline,
      instructionFiles: selected.instructions, authorityFiles: selected.authorities, taskScopeIdentity, lock,
    });
    assert.equal(fast.result, "PASS");
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R5 cleanup-completeness rejects every residual target after a completed target", async (t) => {
  const value = await createTerminalBlobFixture([
    { name: "one.txt", bytes: "one\n" },
    { name: "two.txt", bytes: "two\n" },
  ]);
  try {
    const inspection = await inspectRetention(retentionInput(value));
    const variants: readonly [string, (draft: any) => void][] = [
      ["deleted plus eligible", (draft) => {
        draft.outcome = "COMPLETE";
        Object.assign(draft.blobs[0]!, { status: "DELETED", result: "SUCCEEDED", detail_code: null, unlink_performed: true, directory_fsync_performed: true });
      }],
      ["deleted plus pending", (draft) => {
        draft.outcome = "COMPLETE";
        Object.assign(draft.blobs[0]!, { status: "DELETED", result: "SUCCEEDED", detail_code: null, unlink_performed: true, directory_fsync_performed: true });
        Object.assign(draft.blobs[1]!, { status: "DEADLINE_PENDING", result: "REFUSED", detail_code: "RETENTION_DEADLINE_NOT_REACHED" });
      }],
      ["deleted plus failed", (draft) => {
        draft.outcome = "COMPLETE";
        Object.assign(draft.blobs[0]!, { status: "DELETED", result: "SUCCEEDED", detail_code: null, unlink_performed: true, directory_fsync_performed: true });
        Object.assign(draft.blobs[1]!, { status: "ERROR", result: "FAILED", detail_code: "TARGET_UNLINK_FAILED" });
      }],
    ];
    for (const [name, mutate] of variants) {
      await t.test(name, async () => {
        const draft = structuredClone(inspection) as any;
        draft.operation = "CLEANUP";
        mutate(draft);
        const forged = identifyContractDocument("pi_gacw_retention_result_v0", draft) as unknown as M3RetentionResultDocument;
        await persist(value.fixture, "retention", forged);
        assert.equal(await classification(value.fixture, forged.content_sha256), "INVALID_MANAGED_RECORD");
      });
    }
    await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("R5 inspection-proof-separation keeps observation authoritative but outside cleanup proof graphs", async () => {
  const value = await createTerminalBlobFixture([{ name: "one.txt", bytes: "one\n" }]);
  try {
    const complete = await applyRetentionCleanup(retentionInput(value));
    const observation = await inspectRetention(retentionInput(value));
    assert.equal(observation.operation, "INSPECT");
    assert.equal(observation.blobs[0]!.status, "ALREADY_REMOVED");
    assert.equal(observation.blobs[0]!.prior_successful_result_content_sha256, null);
    assert.equal(await classification(value.fixture, observation.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");

    const forgedInspectionDraft = structuredClone(observation) as any;
    forgedInspectionDraft.blobs[0]!.prior_successful_result_content_sha256 = complete.content_sha256;
    const forgedInspection = identifyContractDocument(
      "pi_gacw_retention_result_v0", forgedInspectionDraft,
    ) as unknown as M3RetentionResultDocument;
    await persist(value.fixture, "retention", forgedInspection);
    assert.equal(await classification(value.fixture, forgedInspection.content_sha256), "INVALID_MANAGED_RECORD");

    const mediatedDraft = structuredClone(observation) as any;
    mediatedDraft.operation = "CLEANUP";
    mediatedDraft.outcome = "IDEMPOTENT";
    mediatedDraft.blobs[0]!.prior_successful_result_content_sha256 = observation.content_sha256;
    const mediated = identifyContractDocument("pi_gacw_retention_result_v0", mediatedDraft) as unknown as M3RetentionResultDocument;
    await persist(value.fixture, "retention", mediated);
    assert.equal(await classification(value.fixture, mediated.content_sha256), "INVALID_MANAGED_RECORD");
    await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("R5 direct cleanup-rooted idempotence remains authoritative", async () => {
  const value = await createTerminalBlobFixture([{ name: "one.txt", bytes: "one\n" }]);
  try {
    const complete = await applyRetentionCleanup(retentionInput(value));
    const idempotent = await applyRetentionCleanup(retentionInput(value));
    assert.equal(idempotent.operation, "CLEANUP");
    assert.equal(idempotent.outcome, "IDEMPOTENT");
    assert.equal(idempotent.blobs[0]!.prior_successful_result_content_sha256, complete.content_sha256);
    assert.equal(await classification(value.fixture, idempotent.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await removeRepositoryFixture(value.fixture); }
});
