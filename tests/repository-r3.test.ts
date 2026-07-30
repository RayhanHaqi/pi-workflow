import assert from "node:assert/strict";
import { chmod, readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { commitTransition, inspectRunStorage } from "../src/persistence/index.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  createBaselineApproval,
  createTerminalRetentionAuthority,
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
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3PostflightDocument,
  type M3RepositoryStateTokenDocument,
} from "../src/schemas/index.js";
import { reduceState } from "../src/state-machine/index.js";
import { transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import {
  baselineInput,
  codeOf,
  createCleanAdmission,
  createTerminalBlobFixture,
  pathDecision,
  releaseAdmission,
  retentionInput,
} from "./repository-matrix-helpers.js";
import {
  createRepositoryFixture,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
} from "./repository-helpers.js";

const RECORD_DIRECTORIES = {
  baseline: "baselines",
  approval: "baseline-approvals",
  lock: "lock-diagnostics",
  preflight: "preflights",
  token: "repository-state-tokens",
  postflight: "postflights",
  retention: "retention",
} as const;

async function persistRecord(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
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
  const expected = canonicalJsonRecordBytes(document);
  try {
    await writeFile(path, expected, { flag: "wx", mode: 0o600 });
    await chmod(path, 0o600);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST" || !(await readFile(path)).equals(expected)) throw error;
  }
}

async function tokenCount(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>): Promise<number> {
  return (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", RECORD_DIRECTORIES.token))).length;
}

async function classification(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  kind: string,
  digest: string,
): Promise<string | null> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) =>
    entry.object.kind === kind && entry.object.contentSha256 === digest)?.classification ?? null;
}

function fullOptions(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  lock: Awaited<ReturnType<typeof acquireWorktreeLock>>,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  selected: Awaited<ReturnType<typeof instructionAuthorityInputs>>,
  environment: Awaited<ReturnType<typeof requiredEnvironment>>,
  taskScopeIdentity: Sha256Digest,
) {
  return {
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
    requiredEnvironment: environment,
    taskScopeIdentity,
    allowShallow: false,
    allowPartialClone: false,
    lock,
  } as const;
}

async function createDirtyAuthorityFixture() {
  const fixture = await createRepositoryFixture();
  await writeFile(join(fixture.repository, "owner-a.txt"), "owner-a\n");
  await writeFile(join(fixture.repository, "owner-b.txt"), "owner-b\n");
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const selected = await instructionAuthorityInputs(fixture);
  const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
    pathDecision("owner-a.txt"), pathDecision("owner-b.txt"),
  ]))).baseline;
  const durableApproval = (await createBaselineApproval({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    baseline,
    approvedBy: "r3-owner",
    approvedAt: "2026-01-01T00:00:00.000Z",
  })).approval;
  const environment = await requiredEnvironment(fixture.repository);
  const taskScopeIdentity = scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
  return { fixture, lock, selected, baseline, approval: durableApproval, environment, taskScopeIdentity };
}

function approvalWith(
  approval: M3BaselineApprovalRuntimeDocument,
  mutate: (draft: Record<string, unknown>) => void,
): M3BaselineApprovalRuntimeDocument {
  const draft = structuredClone(approval) as unknown as Record<string, unknown>;
  mutate(draft);
  return identifyContractDocument("pi_gacw_baseline_approval_runtime_v0", draft) as unknown as M3BaselineApprovalRuntimeDocument;
}

function approvalRepositoryWith(
  approval: M3BaselineApprovalRuntimeDocument,
  mutate: (target: Record<string, unknown>) => void,
): M3BaselineApprovalRuntimeDocument {
  const acceptedDraft = structuredClone(approval.accepted_approval) as unknown as Record<string, unknown>;
  const target = acceptedDraft["target_repository"] as Record<string, unknown>;
  mutate(target);
  const accepted = identifyContractDocument("pi_gacw_baseline_approval_v0", acceptedDraft);
  return approvalWith(approval, (draft) => { draft["accepted_approval"] = accepted; });
}

test("R3 exact dirty-approval semantics reject every altered repository and decision binding", async (t) => {
  const value = await createDirtyAuthorityFixture();
  try {
    const mutations: readonly [string, (approval: M3BaselineApprovalRuntimeDocument) => M3BaselineApprovalRuntimeDocument][] = [
      ["physical/Git root", (approval) => approvalRepositoryWith(approval, (target) => { target["root"] = "/semantic/root"; })],
      ["Git common directory", (approval) => approvalRepositoryWith(approval, (target) => { target["git_common_dir"] = "/semantic/common"; })],
      ["worktree root", (approval) => approvalRepositoryWith(approval, (target) => { target["worktree"] = "/semantic/worktree"; })],
      ["branch", (approval) => approvalRepositoryWith(approval, (target) => { target["branch"] = "semantic-branch"; })],
      ["detached representation", (approval) => approvalRepositoryWith(approval, (target) => { target["branch"] = "DETACHED"; })],
      ["HEAD", (approval) => approvalRepositoryWith(approval, (target) => { target["head"] = "0".repeat(40); })],
      ["baseline runtime identity", (approval) => approvalWith(approval, (draft) => { draft["baseline_runtime_content_sha256"] = `sha256:${"1".repeat(64)}`; })],
      ["baseline snapshot identity", (approval) => approvalWith(approval, (draft) => { draft["baseline_snapshot_content_sha256"] = `sha256:${"2".repeat(64)}`; })],
      ["ownership decision", (approval) => approvalWith(approval, (draft) => { (draft["decisions"] as Array<Record<string, unknown>>)[0]!["ownership_class"] = "OWNER_AUTHORITY"; })],
      ["classification decision", (approval) => approvalWith(approval, (draft) => { (draft["decisions"] as Array<Record<string, unknown>>)[0]!["data_class"] = "HASH_ONLY"; })],
      ["capture decision", (approval) => approvalWith(approval, (draft) => { (draft["decisions"] as Array<Record<string, unknown>>)[0]!["capture_mode"] = "BLOB"; })],
      ["retention decision", (approval) => approvalWith(approval, (draft) => { (draft["decisions"] as Array<Record<string, unknown>>)[0]!["retention_days_after_terminal"] = 1; })],
      ["path membership", (approval) => approvalWith(approval, (draft) => { (draft["decisions"] as Array<Record<string, unknown>>)[0]!["path"] = "other.txt"; })],
      ["decision ordering", (approval) => approvalWith(approval, (draft) => { (draft["decisions"] as unknown[]) = [...(draft["decisions"] as unknown[])].reverse(); })],
    ];
    for (const [name, mutate] of mutations) {
      await t.test(name, async () => {
        const altered = mutate(value.approval);
        await persistRecord(value.fixture, RECORD_DIRECTORIES.approval, altered);
        assert.equal(await verifyBaselineApproval({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId,
          baseline: value.baseline, approval: altered }), false);
        const before = await tokenCount(value.fixture);
        await assert.rejects(runFullPreflight(fullOptions(value.fixture, value.lock, value.baseline, altered,
          value.selected, value.environment, value.taskScopeIdentity)));
        assert.equal(await tokenCount(value.fixture), before);
        assert.equal(
          await classification(value.fixture, "M3_BASELINE_APPROVAL", altered.content_sha256),
          name === "baseline runtime identity" ? "INCOMPLETE_MANAGED_RECORD_CHAIN" : "INVALID_MANAGED_RECORD",
        );
      });
    }
    const valid = await runFullPreflight(fullOptions(value.fixture, value.lock, value.baseline, value.approval,
      value.selected, value.environment, value.taskScopeIdentity));
    assert.equal(valid.preflight.result, "PASS");
    assert.equal(await verifyBaselineApproval({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId,
      baseline: value.baseline, approval: value.approval }), true);
    assert.equal(await classification(value.fixture, "M3_BASELINE_APPROVAL", value.approval.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await releaseWorktreeLock(value.lock).catch(() => undefined);
    await removeRepositoryFixture(value.fixture);
  }
});

function baselineWith(
  baseline: M3BaselineRuntimeDocument,
  mutate: (draft: Record<string, unknown>) => void,
): M3BaselineRuntimeDocument {
  const draft = structuredClone(baseline) as unknown as Record<string, unknown>;
  mutate(draft);
  return identifyContractDocument("pi_gacw_baseline_runtime_v0", draft) as unknown as M3BaselineRuntimeDocument;
}

test("R3 baseline runtime authority rejects internally inconsistent repository and Git bindings", async (t) => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const selected = await instructionAuthorityInputs(fixture);
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", []))).baseline;
    const environment = await requiredEnvironment(fixture.repository);
    const taskScopeIdentity = scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
    const mutations: readonly [string, (draft: Record<string, unknown>) => void][] = [
      ["accepted branch", (draft) => {
        const accepted = structuredClone(draft["accepted_baseline"]) as Record<string, unknown>;
        (accepted["target_repository"] as Record<string, unknown>)["branch"] = "semantic-branch";
        draft["accepted_baseline"] = identifyContractDocument("pi_gacw_baseline_v0", accepted);
      }],
      ["repository Git top-level", (draft) => {
        const repositoryDraft = structuredClone(draft["repository"]) as Record<string, unknown>;
        repositoryDraft["git_toplevel"] = "/semantic/git-top";
        draft["repository"] = identifyContractDocument("pi_gacw_repository_identity_v0", repositoryDraft);
      }],
      ["repository worktree key", (draft) => {
        const repositoryDraft = structuredClone(draft["repository"]) as Record<string, unknown>;
        repositoryDraft["worktree_key"] = `sha256:${"3".repeat(64)}`;
        draft["repository"] = identifyContractDocument("pi_gacw_repository_identity_v0", repositoryDraft);
      }],
      ["repository detached state", (draft) => {
        const repositoryDraft = structuredClone(draft["repository"]) as Record<string, unknown>;
        repositoryDraft["detached"] = true;
        draft["repository"] = identifyContractDocument("pi_gacw_repository_identity_v0", repositoryDraft);
      }],
      ["repository HEAD tree versus fingerprint", (draft) => {
        const repositoryDraft = structuredClone(draft["repository"]) as Record<string, unknown>;
        repositoryDraft["head_tree"] = "4".repeat(40);
        draft["repository"] = identifyContractDocument("pi_gacw_repository_identity_v0", repositoryDraft);
      }],
      ["fingerprint HEAD", (draft) => {
        const fingerprint = structuredClone(draft["git_fingerprint"]) as Record<string, unknown>;
        fingerprint["head"] = "5".repeat(40);
        draft["git_fingerprint"] = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", fingerprint);
      }],
      ["fingerprint upstream divergence", (draft) => {
        const fingerprint = structuredClone(draft["git_fingerprint"]) as Record<string, unknown>;
        fingerprint["upstream_ref"] = "refs/heads/semantic"; fingerprint["ahead"] = 1; fingerprint["behind"] = 1;
        draft["git_fingerprint"] = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", fingerprint);
      }],
    ];
    for (const [name, mutate] of mutations) {
      await t.test(name, async () => {
        const altered = baselineWith(baseline, mutate);
        await persistRecord(fixture, RECORD_DIRECTORIES.baseline, altered);
        const before = await tokenCount(fixture);
        await assert.rejects(runFullPreflight(fullOptions(fixture, lock, altered, null, selected, environment, taskScopeIdentity)));
        assert.equal(await tokenCount(fixture), before);
        assert.equal(await classification(fixture, "M3_BASELINE", altered.content_sha256), "INVALID_MANAGED_RECORD");
      });
    }
    const valid = await runFullPreflight(fullOptions(fixture, lock, baseline, null, selected, environment, taskScopeIdentity));
    assert.equal(valid.preflight.result, "PASS");
    assert.equal(await classification(fixture, "M3_BASELINE", baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

interface PairMutation {
  readonly source?: (draft: Record<string, unknown>) => void;
  readonly token?: (draft: Record<string, unknown>, source: M3PostflightDocument) => void;
  readonly expectedSourceClass?: string;
  readonly expectedTokenClass?: string;
}

test("R3 postflight source semantics reject impossible scope, claim, delta, fingerprint, and token bindings", async (t) => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    await writeFile(fixture.trackedPath, "r3-one-change\n");
    const valid = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: admission.full.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, editablePaths: admission.editable,
      frozenPaths: admission.frozen, taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"], lock: admission.lock,
    });
    const otherDigest = (digit: string) => `sha256:${digit.repeat(64)}`;
    const mutations: readonly [string, PairMutation][] = [
      ["editable paths with stale identity", { source: (draft) => { (draft["scope"] as Record<string, unknown>)["editable_paths"] = ["semantic-edit.txt", "tracked.txt"]; } }],
      ["frozen paths with stale identity", { source: (draft) => { (draft["scope"] as Record<string, unknown>)["frozen_paths"] = ["AGENTS.md", "AUTHORITY.md", "semantic-frozen.txt"]; } }],
      ["editable/frozen overlap", { source: (draft) => { (draft["scope"] as Record<string, unknown>)["frozen_paths"] = ["AGENTS.md", "AUTHORITY.md", "tracked.txt"]; } }],
      ["scope identity only", { source: (draft) => { (draft["scope"] as Record<string, unknown>)["scope_identity"] = otherDigest("6"); }, token: (draft) => { draft["task_scope_identity"] = otherDigest("6"); } }],
      ["extra claimed path", { source: (draft) => { draft["claimed_workflow_paths"] = ["semantic-extra.txt", "tracked.txt"]; } }],
      ["missing claimed path", { source: (draft) => { draft["claimed_workflow_paths"] = []; } }],
      ["claim in frozen scope", { source: (draft) => { draft["claimed_workflow_paths"] = ["AGENTS.md"]; } }],
      ["workflow delta content", { source: (draft) => { (draft["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["after_content_sha256"] = otherDigest("7"); } }],
      ["repository Git delta content", { source: (draft) => { (draft["repository_git_delta"] as Array<Record<string, unknown>>)[0]!["after_content_sha256"] = otherDigest("8"); } }],
      ["deleted-path inventory", { source: (draft) => { const entry = (draft["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!; entry["change_kind"] = "DELETED"; entry["after_content_sha256"] = null; entry["after_type"] = "DELETED"; entry["after_mode"] = null; } }],
      ["mode-change inventory", { source: (draft) => { (draft["workflow_owned_delta"] as Array<Record<string, unknown>>)[0]!["after_mode"] = 493; } }],
      ["prior token identity", { source: (draft) => { draft["prior_token_content_sha256"] = otherDigest("9"); }, token: (draft) => { draft["prior_token_content_sha256"] = otherDigest("9"); }, expectedSourceClass: "INCOMPLETE_MANAGED_RECORD_CHAIN", expectedTokenClass: "INCOMPLETE_MANAGED_RECORD_CHAIN" }],
      ["resulting Git fingerprint", { source: (draft) => { const fingerprint = structuredClone(draft["git_fingerprint"]) as Record<string, unknown>; fingerprint["dirty"] = false; draft["git_fingerprint"] = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", fingerprint); } }],
      ["baseline identity", { source: (draft) => { draft["baseline_runtime_content_sha256"] = otherDigest("a"); }, token: (draft) => { draft["baseline_runtime_content_sha256"] = otherDigest("a"); }, expectedSourceClass: "INCOMPLETE_MANAGED_RECORD_CHAIN", expectedTokenClass: "INCOMPLETE_MANAGED_RECORD_CHAIN" }],
      ["repository worktree key", { source: (draft) => { const repository = structuredClone(draft["repository"]) as Record<string, unknown>; repository["worktree_key"] = otherDigest("b"); draft["repository"] = identifyContractDocument("pi_gacw_repository_identity_v0", repository); }, token: (draft, source) => { draft["repository_identity_content_sha256"] = source.repository.content_sha256; draft["worktree_key"] = source.repository.worktree_key; } }],
      ["lock identity", { source: (draft) => { draft["lock_diagnostic_content_sha256"] = otherDigest("c"); }, token: (draft) => { draft["lock_diagnostic_content_sha256"] = otherDigest("c"); } }],
      ["instruction fingerprint", { expectedSourceClass: "AUTHORITATIVE_MANAGED_RECORD", token: (draft) => { const fingerprint = structuredClone(draft["instruction_fingerprint"]) as Record<string, unknown>; (fingerprint["entries"] as Array<Record<string, unknown>>)[0]!["content_sha256"] = otherDigest("d"); fingerprint["content_sha256"] = sha256Canonical(fingerprint["entries"]); draft["instruction_fingerprint"] = fingerprint; } }],
      ["authority fingerprint", { expectedSourceClass: "AUTHORITATIVE_MANAGED_RECORD", token: (draft) => { const fingerprint = structuredClone(draft["authority_fingerprint"]) as Record<string, unknown>; (fingerprint["entries"] as Array<Record<string, unknown>>)[0]!["content_sha256"] = otherDigest("e"); fingerprint["content_sha256"] = sha256Canonical(fingerprint["entries"]); draft["authority_fingerprint"] = fingerprint; } }],
      ["source identity reference", { token: (draft) => { draft["source_content_sha256"] = otherDigest("f"); }, expectedSourceClass: "AUTHORITATIVE_MANAGED_RECORD", expectedTokenClass: "INCOMPLETE_MANAGED_RECORD_CHAIN" }],
      ["changed-path inventory", { expectedSourceClass: "AUTHORITATIVE_MANAGED_RECORD", token: (draft) => { draft["changed_paths"] = []; } }],
    ];
    for (const [name, mutation] of mutations) {
      await t.test(name, async () => {
        const sourceDraft = structuredClone(valid.postflight) as unknown as Record<string, unknown>;
        mutation.source?.(sourceDraft);
        const source = identifyContractDocument("pi_gacw_postflight_v0", sourceDraft) as unknown as M3PostflightDocument;
        const tokenDraft = structuredClone(valid.acceptedState) as unknown as Record<string, unknown>;
        tokenDraft["source_content_sha256"] = source.content_sha256;
        tokenDraft["workflow_owned_delta_sha256"] = sha256Canonical(source.workflow_owned_delta);
        tokenDraft["changed_paths"] = source.workflow_owned_delta.map((entry) => entry.path);
        mutation.token?.(tokenDraft, source);
        const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft) as unknown as M3RepositoryStateTokenDocument;
        await persistRecord(fixture, RECORD_DIRECTORIES.postflight, source);
        await persistRecord(fixture, RECORD_DIRECTORIES.token, token);
        await assert.rejects(runFastPreflight({
          stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
          baseline: admission.baseline, instructionFiles: admission.selected.instructions,
          authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
        }));
        assert.equal(await classification(fixture, "M3_POSTFLIGHT", source.content_sha256), mutation.expectedSourceClass ?? "INVALID_MANAGED_RECORD");
        assert.equal(await classification(fixture, "M3_REPOSITORY_STATE_TOKEN", token.content_sha256), mutation.expectedTokenClass ?? "INVALID_MANAGED_RECORD");
      });
    }
    assert.equal(await classification(fixture, "M3_POSTFLIGHT", valid.postflight.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(fixture, "M3_REPOSITORY_STATE_TOKEN", valid.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: valid.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    });
    assert.equal(fast.result, "PASS");
  } finally {
    await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
  }
});

test("R3 valid zero-delta and multi-postflight successor chain remains authoritative", async () => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    const zero = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: admission.full.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, editablePaths: admission.editable,
      frozenPaths: admission.frozen, taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: [], lock: admission.lock,
    });
    await writeFile(fixture.trackedPath, "r3-successor-one\n");
    const first = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: zero.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, editablePaths: admission.editable,
      frozenPaths: admission.frozen, taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"], lock: admission.lock,
    });
    await writeFile(fixture.trackedPath, "r3-successor-two\n");
    const second = await runPostflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: first.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, editablePaths: admission.editable,
      frozenPaths: admission.frozen, taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"], lock: admission.lock,
    });
    const fast = await runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: second.acceptedState,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    });
    assert.equal(fast.result, "PASS");
    assert.equal(await classification(fixture, "M3_REPOSITORY_STATE_TOKEN", second.acceptedState.content_sha256),
      "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
  }
});

test("R3 full-preflight lock diagnostics are durable authority, not an arbitrary matching digest", async () => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    const sourceDraft = structuredClone(admission.full.preflight) as unknown as Record<string, unknown>;
    const alteredLock = `sha256:${"a".repeat(64)}`;
    sourceDraft["lock_diagnostic_content_sha256"] = alteredLock;
    const source = identifyContractDocument("pi_gacw_preflight_v0", sourceDraft);
    const tokenDraft = structuredClone(admission.full.acceptedState) as unknown as Record<string, unknown>;
    tokenDraft["source_content_sha256"] = source.content_sha256;
    tokenDraft["lock_diagnostic_content_sha256"] = alteredLock;
    const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft) as unknown as M3RepositoryStateTokenDocument;
    await persistRecord(fixture, RECORD_DIRECTORIES.preflight, source);
    await persistRecord(fixture, RECORD_DIRECTORIES.token, token);
    await assert.rejects(runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    }), (error: unknown) => codeOf(error) === "STATE_TOKEN_PROVENANCE_INVALID");
    assert.equal(await classification(fixture, "M3_PREFLIGHT", source.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(fixture, "M3_REPOSITORY_STATE_TOKEN", token.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");

    const diagnosticDraft = structuredClone(admission.lock.diagnostics) as unknown as Record<string, unknown>;
    diagnosticDraft["worktree_root"] = "/semantic/wrong-worktree";
    const wrongDiagnostic = identifyContractDocument("pi_gacw_lock_diagnostic_v0", diagnosticDraft);
    await persistRecord(fixture, RECORD_DIRECTORIES.lock, wrongDiagnostic as { readonly content_sha256: string });
    const sourceDraft2 = structuredClone(admission.full.preflight) as unknown as Record<string, unknown>;
    sourceDraft2["lock_diagnostic_content_sha256"] = wrongDiagnostic.content_sha256;
    const source2 = identifyContractDocument("pi_gacw_preflight_v0", sourceDraft2);
    const tokenDraft2 = structuredClone(admission.full.acceptedState) as unknown as Record<string, unknown>;
    tokenDraft2["source_content_sha256"] = source2.content_sha256;
    tokenDraft2["lock_diagnostic_content_sha256"] = wrongDiagnostic.content_sha256;
    const token2 = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft2) as unknown as M3RepositoryStateTokenDocument;
    await persistRecord(fixture, RECORD_DIRECTORIES.preflight, source2);
    await persistRecord(fixture, RECORD_DIRECTORIES.token, token2);
    await assert.rejects(runFastPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token2,
      baseline: admission.baseline, instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock,
    }), (error: unknown) => codeOf(error) === "STATE_TOKEN_PROVENANCE_INVALID");
    assert.equal(await classification(fixture, "M3_LOCK_DIAGNOSTIC", wrongDiagnostic.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(fixture, "M3_PREFLIGHT", source2.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(fixture, "M3_REPOSITORY_STATE_TOKEN", token2.content_sha256), "INVALID_MANAGED_RECORD");
  } finally {
    await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
  }
});

test("R3 managed retention classification shares exact result and terminal-authority semantics", async (t) => {
  const value = await createTerminalBlobFixture();
  try {
    const valid = await (await import("../src/repository/index.js")).inspectRetention(retentionInput(value));
    const mutations: readonly [string, (draft: Record<string, unknown>) => void][] = [
      ["logical target count", (draft) => { draft["logical_target_count"] = Number(draft["logical_target_count"]) + 1; }],
      ["logical membership", (draft) => { (((draft["blobs"] as Array<Record<string, unknown>>)[0]!["logical_references"] as Array<Record<string, unknown>>)[0]!)["baseline_path"] = "semantic-other.txt"; }],
      ["worktree", (draft) => { draft["worktree_key"] = `sha256:${"b".repeat(64)}`; }],
      ["deadline", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["retention_deadline"] = "2026-02-01T00:00:00.000Z"; }],
    ];
    for (const [name, mutate] of mutations) {
      await t.test(name, async () => {
        const draft = structuredClone(valid) as unknown as Record<string, unknown>;
        mutate(draft);
        const altered = identifyContractDocument("pi_gacw_retention_result_v0", draft);
        await persistRecord(value.fixture, RECORD_DIRECTORIES.retention, altered as { readonly content_sha256: string });
        assert.equal(await classification(value.fixture, "M3_RETENTION_RESULT", altered.content_sha256), "INVALID_MANAGED_RECORD");
        await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
      });
    }
    assert.equal(await classification(value.fixture, "M3_TERMINAL_RETENTION_AUTHORITY",
      (await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId })).managedObjects.find(
        (object) => object.kind === "M3_TERMINAL_RETENTION_AUTHORITY")!.contentSha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, "M3_RETENTION_RESULT", valid.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await removeRepositoryFixture(value.fixture);
  }
});

test("R3 committed terminal authority with inconsistent worktree semantics is invalid and unusable", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await writeFile(join(fixture.repository, "terminal-r3.txt"), "terminal-r3\n");
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("terminal-r3.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
    ]))).baseline;
    const approval = (await createBaselineApproval({
      stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
      approvedBy: "r3-owner", approvedAt: "2026-01-01T00:00:00.000Z",
    })).approval;
    const event = transitionEvent("BLOCK", { reason: "R3_TERMINAL_AUTHORITY_SEMANTICS" });
    const terminalState = reduceState(fixture.initialState, event, fixture.policy);
    const valid = createTerminalRetentionAuthority({
      baseline, approval, terminalWorkflowState: terminalState, terminalTimestamp: "2026-01-01T00:00:00.000Z",
    });
    const draft = structuredClone(valid) as unknown as Record<string, unknown>;
    draft["worktree_key"] = `sha256:${"c".repeat(64)}`;
    const altered = identifyContractDocument("pi_gacw_terminal_retention_authority_v0", draft);
    const authorityBytes = canonicalJsonRecordBytes(altered);
    await commitTransition({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRevision: fixture.committed.statePointer.revision,
      expectedStatePointerContentSha256: fixture.committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: fixture.committed.workflowState.content_sha256 as Sha256Digest,
      expectedNextWorkflowStateContentSha256: terminalState.content_sha256 as Sha256Digest,
      transitionId: "r3-terminal-authority-semantics",
      policy: fixture.policy,
      event,
      evidence: [{ bytes: authorityBytes, mediaType: "application/vnd.pi-gacw.retention-authority+json" }],
      processMetadata,
    });
    const evidenceDigest = sha256Bytes(authorityBytes);
    assert.equal(await classification(fixture, "M3_TERMINAL_RETENTION_AUTHORITY", evidenceDigest), "INVALID_MANAGED_RECORD");
    await assert.rejects(applyRetentionCleanup({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline,
      terminalAuthority: altered as never,
      evaluatedAt: "2026-01-31T00:00:00.000Z",
    }), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
  } finally {
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R3 classifier distinguishes authoritative, unreferenced, incomplete, invalid, and uncommitted records", async () => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    const source = admission.full.preflight;
    const tokenPath = join(fixture.stateRoot, "runs", fixture.runId, "records", RECORD_DIRECTORIES.token,
      `${admission.full.acceptedState.content_sha256.slice("sha256:".length)}.json`);
    await unlink(tokenPath);
    let inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === source.content_sha256)?.classification,
      "UNREFERENCED_MANAGED_RECORD");
    await persistRecord(fixture, RECORD_DIRECTORIES.token, admission.full.acceptedState);
    const sourcePath = join(fixture.stateRoot, "runs", fixture.runId, "records", RECORD_DIRECTORIES.preflight,
      `${source.content_sha256.slice("sha256:".length)}.json`);
    await unlink(sourcePath);
    inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === admission.full.acceptedState.content_sha256)?.classification,
      "INCOMPLETE_MANAGED_RECORD_CHAIN");
  } finally {
    await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
  }
});
