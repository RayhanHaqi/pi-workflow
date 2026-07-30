import assert from "node:assert/strict";
import { chmod, copyFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { m3PorcelainIdentityProjection } from "../src/persistence/m3-authority.js";
import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFullPreflight,
} from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import { identifyContractDocument, type M3BaselineRuntimeDocument } from "../src/schemas/index.js";
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

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { readonly code: unknown }).code : undefined;
}

async function persist(fixture: RepositoryFixture, baseline: M3BaselineRuntimeDocument): Promise<void> {
  const path = join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines", `${baseline.content_sha256.slice(7)}.json`);
  await writeFile(path, canonicalJsonRecordBytes(baseline), { mode: 0o600 });
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

function forgedBaseline(
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

function toggleGitMode(value: unknown): string {
  return value === "100755" ? "100644" : "100755";
}

async function assertRejectedEverywhere(
  fixture: RepositoryFixture,
  lock: Awaited<ReturnType<typeof acquireWorktreeLock>>,
  valid: M3BaselineRuntimeDocument,
  forged: M3BaselineRuntimeDocument,
): Promise<void> {
  const approval = (await createBaselineApproval({
    stateRoot: fixture.stateRoot, runId: fixture.runId, baseline: valid,
    approvedBy: "r5-r1-owner", approvedAt: "2026-01-01T00:00:00.000Z",
  })).approval;
  await persist(fixture, forged);
  await assert.rejects(createBaselineApproval({
    stateRoot: fixture.stateRoot, runId: fixture.runId, baseline: forged,
    approvedBy: "r5-r1-owner", approvedAt: "2026-01-01T00:00:00.000Z",
  }), (error: unknown) => codeOf(error) === "BASELINE_PROVENANCE_INVALID");
  assert.equal(await classification(fixture, forged.content_sha256), "INVALID_MANAGED_RECORD");
  const selected = await instructionAuthorityInputs(fixture);
  const beforeSources = (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "preflights"))).length;
  const beforeTokens = (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "repository-state-tokens"))).length;
  await assert.rejects(runFullPreflight({
    stateRoot: fixture.stateRoot, runId: fixture.runId,
    expectedRepository: forged.repository, expectedWorktreeKey: forged.repository.worktree_key,
    expectedBranch: forged.repository.branch, expectedHead: forged.repository.head,
    expectedWorktreeListSha256: forged.repository.worktree_list_sha256,
    baseline: forged, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
    requiredEnvironment: await requiredEnvironment(fixture.repository),
    taskScopeIdentity: scopeIdentity(forged.paths.map((entry) => entry.path), ["AGENTS.md", "AUTHORITY.md"]),
    allowShallow: false, allowPartialClone: false, lock,
  }));
  assert.equal((await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "preflights"))).length, beforeSources);
  assert.equal((await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "repository-state-tokens"))).length, beforeTokens);
}

interface ModeCase {
  readonly name: string;
  readonly setup: (fixture: RepositoryFixture) => Promise<readonly string[]>;
  readonly mutate: (draft: Record<string, unknown>) => void;
}

const staged = (draft: Record<string, unknown>): Record<string, unknown> =>
  (((draft["git_fingerprint"] as Record<string, unknown>)["staged"] as Array<Record<string, unknown>>)[0]!);
const unstaged = (draft: Record<string, unknown>): Record<string, unknown> =>
  (((draft["git_fingerprint"] as Record<string, unknown>)["unstaged"] as Array<Record<string, unknown>>)[0]!);

const cases: readonly ModeCase[] = [
  {
    name: "staged-only worktree_mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "staged\n"); await git(f.repository, "add", "--", "tracked.txt"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["worktree_mode"] = toggleGitMode(e["worktree_mode"]); },
  },
  {
    name: "staged-only index_mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "staged\n"); await git(f.repository, "add", "--", "tracked.txt"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["index_mode"] = toggleGitMode(e["index_mode"]); },
  },
  {
    name: "staged-only HEAD mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "staged\n"); await git(f.repository, "add", "--", "tracked.txt"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["head_mode"] = toggleGitMode(e["head_mode"]); },
  },
  {
    name: "unstaged-only index mode identity forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "unstaged\n"); return ["tracked.txt"]; },
    mutate: (d) => { (d["git_fingerprint"] as Record<string, unknown>)["index_sha256"] = `sha256:${"4".repeat(64)}`; },
  },
  {
    name: "unstaged-only worktree mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "unstaged\n"); return ["tracked.txt"]; },
    mutate: (d) => { const e = unstaged(d); e["mode"] = e["mode"] === 0o755 ? 0o644 : 0o755; },
  },
  {
    name: "mixed HEAD mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "index\n"); await git(f.repository, "add", "--", "tracked.txt"); await writeFile(f.trackedPath, "worktree\n"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["head_mode"] = toggleGitMode(e["head_mode"]); },
  },
  {
    name: "mixed index mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "index\n"); await git(f.repository, "add", "--", "tracked.txt"); await writeFile(f.trackedPath, "worktree\n"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["index_mode"] = toggleGitMode(e["index_mode"]); },
  },
  {
    name: "mixed worktree mode forgery",
    setup: async (f) => { await writeFile(f.trackedPath, "index\n"); await git(f.repository, "add", "--", "tracked.txt"); await writeFile(f.trackedPath, "worktree\n"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["worktree_mode"] = toggleGitMode(e["worktree_mode"]); },
  },
  {
    name: "mode-only staged transition",
    setup: async (f) => { await chmod(f.trackedPath, 0o755); await git(f.repository, "add", "--", "tracked.txt"); return ["tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["index_mode"] = e["head_mode"]; },
  },
  {
    name: "mode-only unstaged transition",
    setup: async (f) => { await chmod(f.trackedPath, 0o755); return ["tracked.txt"]; },
    mutate: (d) => { const e = unstaged(d); e["mode"] = 0o644; },
  },
  {
    name: "deletion mode sentinel forgery",
    setup: async (f) => { await git(f.repository, "rm", "--", "tracked.txt"); return ["tracked.txt"]; },
    mutate: (d) => { staged(d)["worktree_mode"] = "100644"; },
  },
  {
    name: "rename source mode forgery",
    setup: async (f) => { await git(f.repository, "mv", "tracked.txt", "renamed.txt"); return ["renamed.txt", "tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["head_mode"] = toggleGitMode(e["head_mode"]); },
  },
  {
    name: "rename destination mode forgery",
    setup: async (f) => { await git(f.repository, "mv", "tracked.txt", "renamed.txt"); return ["renamed.txt", "tracked.txt"]; },
    mutate: (d) => { const e = staged(d); e["index_mode"] = toggleGitMode(e["index_mode"]); },
  },
];

test("R5-R1 staged, unstaged, mixed, mode-only, deletion, and rename mode matrix", async (t) => {
  for (const value of cases) {
    await t.test(value.name, async () => {
      const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
      try {
        const paths = await value.setup(fixture);
        const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
        lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
        const baseline = (await captureBaseline(await baselineInput(
          fixture, lock, "APPROVED_BASELINE_DIRTY", paths.map((path) => pathDecision(path)),
        ))).baseline;
        assert.equal(await classification(fixture, baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
        await assertRejectedEverywhere(fixture, lock, baseline, forgedBaseline(baseline, value.mutate));
      } finally {
        if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
        await removeRepositoryFixture(fixture);
      }
    });
  }
});

test("R5-R1 local Git copy reporting is captured and its exposed destination modes are exact", async () => {
  const fixture = await createRepositoryFixture(); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    await git(fixture.repository, "config", "status.renames", "copies");
    await copyFile(fixture.trackedPath, join(fixture.repository, "copy.txt"));
    await git(fixture.repository, "add", "--", "copy.txt");
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const baseline = (await captureBaseline(await baselineInput(
      fixture, lock, "APPROVED_BASELINE_DIRTY", [pathDecision("copy.txt")],
    ))).baseline;
    const entry = baseline.git_fingerprint.staged.find((candidate) => candidate.path === "copy.txt")!;
    assert.ok(entry.status === "A" || entry.status === "C");
    assert.equal(await classification(fixture, baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const indexForgery = forgedBaseline(baseline, (draft) => {
      const candidate = staged(draft); candidate["index_mode"] = toggleGitMode(candidate["index_mode"]);
    });
    await assertRejectedEverywhere(fixture, lock, baseline, indexForgery);
    const worktreeForgery = forgedBaseline(baseline, (draft) => {
      const candidate = staged(draft); candidate["worktree_mode"] = toggleGitMode(candidate["worktree_mode"]);
    });
    await assertRejectedEverywhere(fixture, lock, baseline, worktreeForgery);
    if (entry.status === "C") {
      const sourceForgery = forgedBaseline(baseline, (draft) => {
        const candidate = staged(draft); candidate["head_mode"] = toggleGitMode(candidate["head_mode"]);
      });
      await assertRejectedEverywhere(fixture, lock, baseline, sourceForgery);
    } else {
      assert.equal(entry.old_path, null, "Git 2.43 reports this local copy as an addition, so no copy-source mode is exposed");
      assert.equal(entry.head_mode, "000000");
    }
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});
