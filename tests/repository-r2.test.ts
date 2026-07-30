import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { chmod, lstat, open, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import { commitTransition, inspectRunStorage } from "../src/persistence/index.js";
import { configurePersistenceTestHooks } from "../src/persistence/test-hooks.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  createBaselineApproval,
  createTerminalRetentionAuthority,
  inspectRetention,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runPostflight,
} from "../src/repository/index.js";
import {
  MAX_STATE_ROOT_BYTES,
  baselineBlobPath,
  canonicalJsonRecordBytes,
  retainedBaselineBlobUsage,
  stateRootBytes,
} from "../src/repository/storage.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { identifyContractDocument, type M3RetentionResultDocument } from "../src/schemas/index.js";
import { reduceState } from "../src/state-machine/index.js";
import { transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import {
  baselineInput,
  createCleanAdmission,
  createTerminalBlobFixture,
  pathDecision,
  readRetentionRecords,
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

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

function recordPath(stateRoot: string, runId: string, directory: string, digest: string): string {
  return join(stateRoot, "runs", runId, "records", directory, `${digest.slice("sha256:".length)}.json`);
}

async function publicationInput(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  lock: Awaited<ReturnType<typeof acquireWorktreeLock>>,
  names: readonly string[],
) {
  const selected = await instructionAuthorityInputs(fixture);
  return {
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    requestedPath: fixture.repository,
    mode: "APPROVED_BASELINE_DIRTY" as const,
    pathDecisions: names.map((name) => pathDecision(name, { captureMode: "BLOB", retentionDaysAfterTerminal: 30 })),
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    allowShallow: false,
    allowPartialClone: false,
    lock,
  };
}

async function directoryCount(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, directory: string): Promise<number> {
  return (await readdir(join(fixture.stateRoot, "runs", fixture.runId, directory))).length;
}

test("R2 baseline publication rollback removes only new unique objects", async (t) => {
  await t.test("single and multiple unique blobs", async () => {
    for (const names of [["one.txt"], ["one.txt", "two.txt"]]) {
      const fixture = await createRepositoryFixture();
      const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
      const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
      try {
        for (const [index, name] of names.entries()) await writeFile(join(fixture.repository, name), `unique-${index}\n`);
        configurePersistenceTestHooks({
          beforeOperation: (operation, path) => {
            if (operation === "rename" && path.includes("/records/baselines/")) throw new Error("publication-consistency");
          },
        });
        await assert.rejects(captureBaseline(await publicationInput(fixture, lock, names)), (error: unknown) => codeOf(error) === "ATOMIC_WRITE_FAILED");
        assert.equal(await directoryCount(fixture, "baseline-blobs/sha256"), 0);
        assert.equal(await directoryCount(fixture, "records/baselines"), 0);
        assert.equal((await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId })).status, "HEALTHY");
      } finally {
        configurePersistenceTestHooks(undefined);
        await releaseWorktreeLock(lock).catch(() => undefined);
        await removeRepositoryFixture(fixture);
      }
    }
  });

  await t.test("pre-existing duplicate survives while new unique content rolls back", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      await writeFile(join(fixture.repository, "existing.txt"), "shared\n");
      await captureBaseline(await publicationInput(fixture, lock, ["existing.txt"]));
      await writeFile(join(fixture.repository, "duplicate.txt"), "shared\n");
      await writeFile(join(fixture.repository, "new.txt"), "new\n");
      configurePersistenceTestHooks({
        beforeOperation: (operation, path) => {
          if (operation === "rename" && path.includes("/records/baselines/")) throw new Error("publication-consistency");
        },
      });
      await assert.rejects(
        captureBaseline(await publicationInput(fixture, lock, ["duplicate.txt", "existing.txt", "new.txt"])),
        (error: unknown) => codeOf(error) === "ATOMIC_WRITE_FAILED",
      );
      assert.equal(await directoryCount(fixture, "baseline-blobs/sha256"), 1);
      assert.equal(await directoryCount(fixture, "records/baselines"), 1);
    } finally {
      configurePersistenceTestHooks(undefined);
      await releaseWorktreeLock(lock).catch(() => undefined);
      await removeRepositoryFixture(fixture);
    }
  });

  for (const [name, hook] of [
    ["rollback unlink", { beforeBaselineRollbackUnlink: () => { throw new Error("rollback unlink"); } }],
    ["rollback directory fsync", { beforeBaselineRollbackDirectorySync: () => { throw new Error("rollback fsync"); } }],
  ] as const) {
    await t.test(`${name} is separately uncertain`, async () => {
      const fixture = await createRepositoryFixture();
      const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
      const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
      try {
        await writeFile(join(fixture.repository, "uncertain.txt"), "uncertain\n");
        configureRepositoryTestHooks(hook);
        configurePersistenceTestHooks({
          beforeOperation: (operation, path) => {
            if (operation === "rename" && path.includes("/records/baselines/")) throw new Error("publication-consistency");
          },
        });
        await assert.rejects(
          captureBaseline(await publicationInput(fixture, lock, ["uncertain.txt"])),
          (error: unknown) => codeOf(error) === "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN",
        );
        assert.equal(await directoryCount(fixture, "records/baselines"), 0);
        if (name === "rollback unlink") {
          const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
          assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
          assert.equal(inspection.issues[0]?.code, "UNCOMMITTED_BASELINE_PUBLICATION");
        } else {
          assert.equal(await directoryCount(fixture, "baseline-blobs/sha256"), 0);
        }
      } finally {
        configurePersistenceTestHooks(undefined);
        resetRepositoryTestHooks();
        await releaseWorktreeLock(lock).catch(() => undefined);
        await removeRepositoryFixture(fixture);
      }
    });
  }
});

test("R2 interrupted publication is classified and never silently adopted", async () => {
  const fixture = await createRepositoryFixture();
  await writeFile(join(fixture.repository, "interrupted.txt"), "interrupted\n");
  const selected = await instructionAuthorityInputs(fixture);
  const inputPath = join(fixture.root, "publication-input.json");
  await writeFile(inputPath, JSON.stringify({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    requestedPath: fixture.repository,
    pathDecisions: [pathDecision("interrupted.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 })],
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
  }), { mode: 0o600 });
  const child = fork(new URL("../dist/tests/repository-baseline-r2-child.js", import.meta.url), [inputPath], {
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  try {
    const message = await new Promise<Record<string, unknown>>((resolve, reject) => {
      child.once("message", (value) => resolve(value as Record<string, unknown>));
      child.once("exit", (code) => reject(new Error(`publication child exited early: ${code}`)));
    });
    assert.equal(message["type"], "UNCOMMITTED_BASELINE_PUBLICATION");
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    child.kill("SIGKILL");
    await exited;
    const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    assert.equal(inspection.issues[0]?.code, "UNCOMMITTED_BASELINE_PUBLICATION");
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    let observed: unknown;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
        try { await captureBaseline({ ...(await publicationInput(fixture, lock, ["interrupted.txt"])) }); }
        finally { await releaseWorktreeLock(lock).catch(() => undefined); }
      } catch (error: unknown) {
        if (codeOf(error) === "LOCK_BUSY") { await new Promise<void>((resolve) => setImmediate(resolve)); continue; }
        observed = error;
      }
      break;
    }
    assert.equal(codeOf(observed), "STATE_STORAGE_INVALID");
  } finally {
    child.kill("SIGKILL");
    await removeRepositoryFixture(fixture);
  }
});

test("R2 durable baseline and approval records are mandatory", async (t) => {
  await t.test("full preflight rejects a deleted baseline record", async () => {
    const fixture = await createRepositoryFixture();
    const admission = await createCleanAdmission(fixture);
    try {
      await unlink(recordPath(fixture.stateRoot, fixture.runId, "baselines", admission.baseline.content_sha256));
      await assert.rejects(runFullPreflight({
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
      }), (error: unknown) => codeOf(error) === "BASELINE_RECORD_MISSING");
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });

  await t.test("full preflight rejects a deleted dirty approval record", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      await writeFile(join(fixture.repository, "approval.txt"), "approval\n");
      const selected = await instructionAuthorityInputs(fixture);
      const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [pathDecision("approval.txt")]))).baseline;
      const approval = (await createBaselineApproval({ stateRoot: fixture.stateRoot, runId: fixture.runId, baseline,
        approvedBy: "owner", approvedAt: "2026-01-01T00:00:00.000Z" })).approval;
      await unlink(recordPath(fixture.stateRoot, fixture.runId, "baseline-approvals", approval.content_sha256));
      await assert.rejects(runFullPreflight({
        stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
        expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
        expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
        baseline, approval, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
        requiredEnvironment: await requiredEnvironment(fixture.repository),
        taskScopeIdentity: scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md", "approval.txt"]),
        allowShallow: false, allowPartialClone: false, lock,
      }), (error: unknown) => codeOf(error) === "BASELINE_APPROVAL_RECORD_MISSING");
    } finally { await releaseWorktreeLock(lock); await removeRepositoryFixture(fixture); }
  });

  await t.test("retention rejects a deleted baseline and preserves its blob", async () => {
    const value = await createTerminalBlobFixture();
    try {
      const blob = value.baseline.paths[0]?.blob; assert.ok(blob);
      await unlink(recordPath(value.fixture.stateRoot, value.fixture.runId, "baselines", value.baseline.content_sha256));
      await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "BASELINE_RECORD_MISSING");
      await lstat(baselineBlobPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, blob.blob_sha256));
      assert.equal((await readRetentionRecords(value.fixture)).length, 0);
    } finally { await removeRepositoryFixture(value.fixture); }
  });
});

test("R2 fast preflight and postflight require an exact durable token/source chain", async () => {
  for (const operation of ["FAST", "POSTFLIGHT"] as const) {
    const fixture = await createRepositoryFixture();
    const admission = await createCleanAdmission(fixture);
    try {
      const draft = structuredClone(admission.full.acceptedState) as unknown as Record<string, unknown>;
      delete draft["content_sha256"];
      draft["source_content_sha256"] = `sha256:${"0".repeat(64)}`;
      const token = identifyContractDocument(
        "pi_gacw_repository_state_token_v0",
        draft,
      ) as unknown as typeof admission.full.acceptedState;
      const invoke = operation === "FAST"
        ? runFastPreflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
          baseline: admission.baseline, instructionFiles: admission.selected.instructions,
          authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock })
        : runPostflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
          baseline: admission.baseline, instructionFiles: admission.selected.instructions,
          authorityFiles: admission.selected.authorities, editablePaths: admission.editable, frozenPaths: admission.frozen,
          taskScopeIdentity: admission.taskScopeIdentity, claimedWorkflowPaths: [], lock: admission.lock });
      await assert.rejects(invoke, (error: unknown) => codeOf(error) === "STATE_TOKEN_RECORD_MISSING");
      await writeFile(
        recordPath(fixture.stateRoot, fixture.runId, "repository-state-tokens", token.content_sha256),
        canonicalJsonRecordBytes(token),
        { mode: 0o600 },
      );
      await assert.rejects(
        operation === "FAST"
          ? runFastPreflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
            baseline: admission.baseline, instructionFiles: admission.selected.instructions,
            authorityFiles: admission.selected.authorities, taskScopeIdentity: admission.taskScopeIdentity, lock: admission.lock })
          : runPostflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
            baseline: admission.baseline, instructionFiles: admission.selected.instructions,
            authorityFiles: admission.selected.authorities, editablePaths: admission.editable, frozenPaths: admission.frozen,
            taskScopeIdentity: admission.taskScopeIdentity, claimedWorkflowPaths: [], lock: admission.lock }),
        (error: unknown) => codeOf(error) === "STATE_TOKEN_SOURCE_MISSING",
      );
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  }
});

test("R2 token publication failure never returns authority and valid postflight chains remain usable", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const selected = await instructionAuthorityInputs(fixture);
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", []))).baseline;
    const taskScopeIdentity = scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
    const input = {
      stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
      expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
      expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository), taskScopeIdentity,
      allowShallow: false, allowPartialClone: false, lock,
    } as const;
    configurePersistenceTestHooks({
      beforeOperation: (operation, path) => {
        if (operation === "rename" && path.includes("/records/repository-state-tokens/")) throw new Error("token publication");
      },
    });
    await assert.rejects(runFullPreflight(input));
    assert.equal(await directoryCount(fixture, "records/repository-state-tokens"), 0);
    assert.equal(await directoryCount(fixture, "records/preflights"), 1);
    const orphanedSource = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(orphanedSource.managedRecordClassifications.find(
      (entry) => entry.object.kind === "M3_PREFLIGHT",
    )?.classification, "UNREFERENCED_MANAGED_RECORD");
    configurePersistenceTestHooks(undefined);
    const full = await runFullPreflight(input);
    const authoritative = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(authoritative.managedRecordClassifications.find(
      (entry) => entry.object.kind === "M3_REPOSITORY_STATE_TOKEN",
    )?.classification, "AUTHORITATIVE_MANAGED_RECORD");
    const post1 = await runPostflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: full.acceptedState,
      baseline, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      editablePaths: ["tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"], taskScopeIdentity,
      claimedWorkflowPaths: [], lock });
    const post2 = await runPostflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: post1.acceptedState,
      baseline, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      editablePaths: ["tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"], taskScopeIdentity,
      claimedWorkflowPaths: [], lock });
    assert.equal((await runFastPreflight({ stateRoot: fixture.stateRoot, runId: fixture.runId,
      acceptedState: post2.acceptedState, baseline, instructionFiles: selected.instructions,
      authorityFiles: selected.authorities, taskScopeIdentity, lock })).result, "PASS");
  } finally {
    configurePersistenceTestHooks(undefined);
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R2 full-preflight source publication failure publishes no token", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const selected = await instructionAuthorityInputs(fixture);
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", []))).baseline;
    configurePersistenceTestHooks({
      beforeOperation: (operation, path) => {
        if (operation === "rename" && path.includes("/records/preflights/")) throw new Error("source publication");
      },
    });
    await assert.rejects(runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
      expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
      expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository),
      taskScopeIdentity: scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]),
      allowShallow: false, allowPartialClone: false, lock,
    }));
    assert.equal(await directoryCount(fixture, "records/repository-state-tokens"), 0);
    assert.equal(await directoryCount(fixture, "records/preflights"), 0);
  } finally {
    configurePersistenceTestHooks(undefined);
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R2 token directory-fsync failure leaves no authoritative token chain", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const selected = await instructionAuthorityInputs(fixture);
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", []))).baseline;
    configurePersistenceTestHooks({
      beforeOperation: (operation, path) => {
        if (operation === "directorySync" && path.includes("/records/repository-state-tokens/")) {
          throw new Error("token directory fsync");
        }
      },
    });
    await assert.rejects(runFullPreflight({
      stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository,
      expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch,
      expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities,
      requiredEnvironment: await requiredEnvironment(fixture.repository),
      taskScopeIdentity: scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]),
      allowShallow: false, allowPartialClone: false, lock,
    }), (error: unknown) => codeOf(error) === "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN");
    assert.equal(await directoryCount(fixture, "records/repository-state-tokens"), 0);
    const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(inspection.managedRecordClassifications.some(
      (entry) => entry.object.kind === "M3_REPOSITORY_STATE_TOKEN" && entry.classification === "AUTHORITATIVE_MANAGED_RECORD",
    ), false);
  } finally {
    configurePersistenceTestHooks(undefined);
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R2 repository-state token chain depth is fixed and cannot advance past the bound", async () => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    let token = admission.full.acceptedState;
    for (let depth = 1; depth <= 64; depth += 1) {
      token = (await runPostflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
        baseline: admission.baseline, instructionFiles: admission.selected.instructions,
        authorityFiles: admission.selected.authorities, editablePaths: admission.editable, frozenPaths: admission.frozen,
        taskScopeIdentity: admission.taskScopeIdentity, claimedWorkflowPaths: [], lock: admission.lock })).acceptedState;
    }
    const before = await directoryCount(fixture, "records/repository-state-tokens");
    await assert.rejects(
      runPostflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, acceptedState: token,
        baseline: admission.baseline, instructionFiles: admission.selected.instructions,
        authorityFiles: admission.selected.authorities, editablePaths: admission.editable, frozenPaths: admission.frozen,
        taskScopeIdentity: admission.taskScopeIdentity, claimedWorkflowPaths: [], lock: admission.lock }),
      (error: unknown) => codeOf(error) === "STATE_TOKEN_CHAIN_TOO_DEEP",
    );
    assert.equal(await directoryCount(fixture, "records/repository-state-tokens"), before);
  } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
});

test("R2 deduplicated physical retention target is unlinked once with grouped proof", async () => {
  const value = await createTerminalBlobFixture([
    { name: "one.txt", bytes: "same\n" },
    { name: "two.txt", bytes: "same\n" },
    { name: "three.txt", bytes: "same\n" },
  ]);
  let unlinks = 0;
  try {
    configureRepositoryTestHooks({ beforeRetentionUnlink: () => { unlinks += 1; } });
    const result = await applyRetentionCleanup(retentionInput(value));
    assert.equal(result.outcome, "COMPLETE");
    assert.equal(result.logical_target_count, 3);
    assert.equal(result.physical_target_count, 1);
    assert.equal(result.blobs[0]?.logical_references.length, 3);
    assert.equal(unlinks, 1);
    const repeat = await applyRetentionCleanup(retentionInput(value));
    assert.equal(repeat.outcome, "IDEMPOTENT");
    assert.equal(repeat.blobs[0]?.prior_successful_result_content_sha256, result.content_sha256);
    const recordCount = (await readRetentionRecords(value.fixture)).length;
    const reused = await applyRetentionCleanup(retentionInput(value));
    assert.equal(reused.content_sha256, repeat.content_sha256);
    assert.equal((await readRetentionRecords(value.fixture)).length, recordCount);
  } finally { resetRepositoryTestHooks(); await removeRepositoryFixture(value.fixture); }
});

async function historicalSharedFixture(
  includeFirstAuthority: boolean,
  firstRetentionDays = 30,
  secondRetentionDays = 30,
) {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await writeFile(join(fixture.repository, "first.txt"), "historical-shared\n");
    const selected = await instructionAuthorityInputs(fixture);
    const first = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("first.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: firstRetentionDays }),
    ]))).baseline;
    const firstApproval = (await createBaselineApproval({ stateRoot: fixture.stateRoot, runId: fixture.runId, baseline: first,
      approvedBy: "historical-owner", approvedAt: "2026-01-01T00:00:00.000Z" })).approval;
    await writeFile(join(fixture.repository, "second.txt"), "historical-shared\n");
    const second = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
      pathDecision("first.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: secondRetentionDays }),
      pathDecision("second.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: secondRetentionDays }),
    ]))).baseline;
    const secondApproval = (await createBaselineApproval({ stateRoot: fixture.stateRoot, runId: fixture.runId, baseline: second,
      approvedBy: "historical-owner", approvedAt: "2026-01-01T00:00:00.000Z" })).approval;
    const event = transitionEvent("BLOCK", { reason: "R2_HISTORICAL_RETENTION" });
    const terminalState = reduceState(fixture.initialState, event, fixture.policy);
    const firstAuthority = createTerminalRetentionAuthority({ baseline: first, approval: firstApproval,
      terminalWorkflowState: terminalState, terminalTimestamp: "2026-01-01T00:00:00.000Z" });
    const secondAuthority = createTerminalRetentionAuthority({ baseline: second, approval: secondApproval,
      terminalWorkflowState: terminalState, terminalTimestamp: "2026-01-01T00:00:00.000Z" });
    await commitTransition({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRevision: fixture.committed.statePointer.revision,
      expectedStatePointerContentSha256: fixture.committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: fixture.committed.workflowState.content_sha256 as Sha256Digest,
      expectedNextWorkflowStateContentSha256: terminalState.content_sha256 as Sha256Digest,
      transitionId: "r2-historical-retention",
      policy: fixture.policy,
      event,
      evidence: [
        ...(includeFirstAuthority ? [{ bytes: canonicalJsonRecordBytes(firstAuthority), mediaType: "application/vnd.pi-gacw.retention-authority+json" }] : []),
        { bytes: canonicalJsonRecordBytes(secondAuthority), mediaType: "application/vnd.pi-gacw.retention-authority+json" },
      ],
      processMetadata,
    });
    await releaseWorktreeLock(lock);
    return { fixture, first, second, firstAuthority, secondAuthority };
  } catch (error: unknown) {
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
    throw error;
  }
}

test("R2 historical logical references jointly govern one physical blob", async (t) => {
  await t.test("all committed references eligible", async () => {
    const value = await historicalSharedFixture(true);
    try {
      const result = await applyRetentionCleanup({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId,
        baseline: value.second, terminalAuthority: value.secondAuthority, evaluatedAt: "2026-01-31T00:00:00.000Z" });
      assert.equal(result.outcome, "COMPLETE");
      assert.equal(result.physical_target_count, 1);
      assert.equal(result.logical_target_count, 3);
      assert.deepEqual(result.blobs[0]?.logical_references.map((entry) => entry.baseline_path).sort(), ["first.txt", "first.txt", "second.txt"]);
    } finally { await removeRepositoryFixture(value.fixture); }
  });

  await t.test("one reference lacking committed authority preserves the physical blob", async () => {
    const value = await historicalSharedFixture(false);
    try {
      await assert.rejects(
        applyRetentionCleanup({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId,
          baseline: value.second, terminalAuthority: value.secondAuthority, evaluatedAt: "2026-01-31T00:00:00.000Z" }),
        (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN",
      );
      const blob = value.second.paths[0]?.blob; assert.ok(blob);
      await lstat(baselineBlobPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, blob.blob_sha256));
      const result = (await readRetentionRecords(value.fixture)).at(-1) as unknown as M3RetentionResultDocument;
      assert.equal(result.outcome, "FAILED");
      assert.equal(result.blobs[0]?.uncovered_references.length, 1);
    } finally { await removeRepositoryFixture(value.fixture); }
  });

  await t.test("one later deadline preserves the physical blob", async () => {
    const value = await historicalSharedFixture(true, 30, 7);
    try {
      await assert.rejects(
        applyRetentionCleanup({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId,
          baseline: value.second, terminalAuthority: value.secondAuthority, evaluatedAt: "2026-01-08T00:00:00.000Z" }),
        (error: unknown) => codeOf(error) === "RETENTION_DEADLINE_NOT_REACHED",
      );
      const blob = value.second.paths[0]?.blob; assert.ok(blob);
      await lstat(baselineBlobPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, blob.blob_sha256));
    } finally { await removeRepositoryFixture(value.fixture); }
  });
});

async function writeForgedSuccessfulResult(
  value: Awaited<ReturnType<typeof createTerminalBlobFixture>>,
  mutate: (draft: Record<string, unknown>) => void,
): Promise<void> {
  const inspected = await inspectRetention(retentionInput(value));
  const draft = structuredClone(inspected) as unknown as Record<string, unknown>;
  delete draft["content_sha256"];
  draft["operation"] = "CLEANUP";
  draft["outcome"] = "COMPLETE";
  const blobs = draft["blobs"] as Array<Record<string, unknown>>;
  for (const blob of blobs) {
    blob["status"] = "DELETED";
    blob["result"] = "SUCCEEDED";
    blob["detail_code"] = null;
    blob["prior_successful_result_content_sha256"] = null;
    blob["unlink_performed"] = true;
    blob["directory_fsync_performed"] = true;
  }
  mutate(draft);
  const forged = identifyContractDocument("pi_gacw_retention_result_v0", draft);
  await writeFile(
    recordPath(value.fixture.stateRoot, value.fixture.runId, "retention", forged.content_sha256),
    canonicalJsonRecordBytes(forged),
    { mode: 0o600 },
  );
  const blob = value.baseline.paths[0]?.blob; assert.ok(blob);
  await unlink(baselineBlobPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, blob.blob_sha256));
}

test("R2 retention proof validation rejects every independently altered binding", async (t) => {
  const zero = `sha256:${"0".repeat(64)}`;
  const cases: readonly [string, (draft: Record<string, unknown>) => void][] = [
    ["run ID", (draft) => { draft["run_id"] = "another-run"; }],
    ["repository identity", (draft) => { draft["repository_identity_content_sha256"] = zero; }],
    ["worktree key", (draft) => { draft["worktree_key"] = zero; }],
    ["terminal authority", (draft) => { draft["terminal_authority_content_sha256"] = zero; }],
    ["terminal state", (draft) => { draft["terminal_workflow_state_content_sha256"] = zero; }],
    ["baseline identity", (draft) => { draft["baseline_runtime_content_sha256"] = zero; }],
    ["approval identity", (draft) => { draft["baseline_approval_runtime_content_sha256"] = zero; }],
    ["blob digest", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["blob_sha256"] = zero; }],
    ["blob size", (draft) => { const blob = (draft["blobs"] as Array<Record<string, unknown>>)[0]!; blob["byte_length"] = (blob["byte_length"] as number) + 1; }],
    ["physical path", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["relative_path"] = "baseline-blobs/sha256/not-authorized"; }],
    ["logical path", (draft) => { const blob = (draft["blobs"] as Array<Record<string, unknown>>)[0]!; (blob["logical_references"] as Array<Record<string, unknown>>)[0]!["baseline_path"] = "another.txt"; }],
    ["classification", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["data_class"] = "PRIVATE_SOURCE"; }],
    ["deadline", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["retention_deadline"] = "2026-01-02T00:00:00.000Z"; }],
    ["unlink flag", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["unlink_performed"] = false; }],
    ["directory-fsync flag", (draft) => { (draft["blobs"] as Array<Record<string, unknown>>)[0]!["directory_fsync_performed"] = false; }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const value = await createTerminalBlobFixture();
      try {
        await writeForgedSuccessfulResult(value, mutate);
        await assert.rejects(
          retainedBaselineBlobUsage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }),
          (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN" || codeOf(error) === "STATE_STORAGE_INVALID",
        );
        await assert.rejects(
          applyRetentionCleanup(retentionInput(value)),
          (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN" || codeOf(error) === "STATE_STORAGE_INVALID",
        );
      } finally { await removeRepositoryFixture(value.fixture); }
    });
  }
});

async function fillStateRootImmediatelyBelowLimit(
  value: Awaited<ReturnType<typeof createTerminalBlobFixture>>,
  filler: string,
): Promise<number> {
  const current = await stateRootBytes(value.fixture.stateRoot);
  const handle = await open(filler, "r+");
  try { await handle.truncate(MAX_STATE_ROOT_BYTES - 1 - current); await handle.sync(); }
  finally { await handle.close(); }
  return stateRootBytes(value.fixture.stateRoot);
}

test("R2 operation-specific retention capacity never exceeds the state-root limit", async (t) => {
  await t.test("inspection and failed cleanup subtract no target bytes", async () => {
    for (const operation of ["INSPECT", "FAILED_CLEANUP"] as const) {
      const value = await createTerminalBlobFixture([{ name: "capacity.bin", bytes: Buffer.alloc(4096, 0x43) }]);
      const filler = join(value.fixture.stateRoot, "locks", `${"0".repeat(64)}.lock`);
      try {
        await writeFile(filler, "", { mode: 0o600 }); await chmod(filler, 0o600);
        if (operation === "FAILED_CLEANUP") {
          const blob = value.baseline.paths[0]?.blob; assert.ok(blob);
          await writeFile(baselineBlobPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, blob.blob_sha256),
            Buffer.alloc(4096, 0x44), { mode: 0o600 });
        }
        let before = 0;
        configureRepositoryTestHooks({ afterRetentionLockAcquired: async () => {
          before = await fillStateRootImmediatelyBelowLimit(value, filler);
        } });
        await assert.rejects(
          operation === "INSPECT" ? inspectRetention(retentionInput(value)) : applyRetentionCleanup(retentionInput(value)),
          (error: unknown) => codeOf(error) === "STATE_ROOT_LIMIT_EXCEEDED",
        );
        resetRepositoryTestHooks();
        assert.equal(before, MAX_STATE_ROOT_BYTES - 1);
        assert.equal(await stateRootBytes(value.fixture.stateRoot), before);
        assert.equal((await readRetentionRecords(value.fixture)).length, 0);
      } finally { resetRepositoryTestHooks(); await removeRepositoryFixture(value.fixture); }
    }
  });

  await t.test("successful grouped cleanup subtracts one actual physical deletion", async () => {
    const value = await createTerminalBlobFixture([
      { name: "one.bin", bytes: Buffer.alloc(16384, 0x43) },
      { name: "two.bin", bytes: Buffer.alloc(16384, 0x43) },
    ]);
    const filler = join(value.fixture.stateRoot, "locks", `${"0".repeat(64)}.lock`);
    try {
      await writeFile(filler, "", { mode: 0o600 }); await chmod(filler, 0o600);
      configureRepositoryTestHooks({ afterRetentionLockAcquired: async () => {
        assert.equal(await fillStateRootImmediatelyBelowLimit(value, filler), MAX_STATE_ROOT_BYTES - 1);
      } });
      const result = await applyRetentionCleanup(retentionInput(value));
      resetRepositoryTestHooks();
      assert.equal(result.outcome, "COMPLETE");
      assert.equal(result.physical_target_count, 1);
      assert.equal(result.logical_target_count, 2);
      assert.ok(await stateRootBytes(value.fixture.stateRoot) <= MAX_STATE_ROOT_BYTES);
    } finally { resetRepositoryTestHooks(); await removeRepositoryFixture(value.fixture); }
  });

  await t.test("capacity drift between checks blocks publication", async () => {
    const value = await createTerminalBlobFixture([{ name: "capacity.bin", bytes: Buffer.alloc(4096, 0x43) }]);
    const filler = join(value.fixture.stateRoot, "locks", `${"0".repeat(64)}.lock`);
    try {
      await writeFile(filler, "", { mode: 0o600 }); await chmod(filler, 0o600);
      configureRepositoryTestHooks({ beforeRetentionCapacityRecheck: async () => {
        const current = await stateRootBytes(value.fixture.stateRoot);
        const handle = await open(filler, "r+");
        try { await handle.truncate(MAX_STATE_ROOT_BYTES - current); await handle.sync(); }
        finally { await handle.close(); }
      } });
      await assert.rejects(inspectRetention(retentionInput(value)), (error: unknown) => codeOf(error) === "STATE_ROOT_LIMIT_EXCEEDED");
      resetRepositoryTestHooks();
      assert.equal(await stateRootBytes(value.fixture.stateRoot), MAX_STATE_ROOT_BYTES);
      assert.equal((await readRetentionRecords(value.fixture)).length, 0);
    } finally { resetRepositoryTestHooks(); await removeRepositoryFixture(value.fixture); }
  });
});
