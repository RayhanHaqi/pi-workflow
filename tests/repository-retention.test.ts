import assert from "node:assert/strict";
import { chmod, lstat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import { commitTransition, inspectRunStorage } from "../src/persistence/index.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  createBaselineApproval,
  createTerminalRetentionAuthority,
  inspectRetention,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";
import { baselineBlobPath, canonicalJsonRecordBytes } from "../src/repository/storage.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";
import { reduceState } from "../src/state-machine/index.js";
import { transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import {
  createRepositoryFixture,
  instructionAuthorityInputs,
  removeRepositoryFixture,
} from "./repository-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

async function terminalBlobFixture(fileNames: readonly string[] = ["retained.txt"]) {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  const selected = await instructionAuthorityInputs(fixture);
  for (const [index, name] of fileNames.entries()) await writeFile(join(fixture.repository, name), `retained-${index}\n`);
  const baseline = (await captureBaseline({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    requestedPath: fixture.repository,
    mode: "APPROVED_BASELINE_DIRTY",
    pathDecisions: fileNames.map((name) => ({
      path: name,
      ownershipClass: "OWNER_ACCEPTED_MUTABLE" as const,
      dataClass: "PUBLIC_SOURCE" as const,
      captureMode: "BLOB" as const,
      explicitBlobApproval: false,
      retentionDaysAfterTerminal: 30,
    })),
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
    approvedBy: "retention-test-owner",
    approvedAt: "2026-01-01T00:00:00.000Z",
  })).approval;
  const event = transitionEvent("BLOCK", { reason: "RETENTION_TEST_TERMINAL" });
  const terminalState = reduceState(fixture.initialState, event, fixture.policy);
  const authority = createTerminalRetentionAuthority({
    baseline,
    approval,
    terminalWorkflowState: terminalState,
    terminalTimestamp: "2026-01-01T00:00:00.000Z",
  });
  await commitTransition({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    expectedRevision: fixture.committed.statePointer.revision,
    expectedStatePointerContentSha256: fixture.committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: fixture.committed.workflowState.content_sha256 as Sha256Digest,
    expectedNextWorkflowStateContentSha256: terminalState.content_sha256 as Sha256Digest,
    transitionId: "retention-terminal",
    policy: fixture.policy,
    event,
    evidence: [{ bytes: canonicalJsonRecordBytes(authority), mediaType: "application/vnd.pi-gacw.retention-authority+json" }],
    processMetadata,
  });
  await releaseWorktreeLock(lock);
  return { fixture, baseline, authority };
}

test("retention requires terminal authority and deadline, then unlinks with metadata and remains idempotent", async () => {
  const { fixture, baseline, authority } = await terminalBlobFixture();
  try {
    const before = await inspectRetention({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline,
      terminalAuthority: authority,
      evaluatedAt: "2026-01-30T23:59:59.999Z",
    });
    assert.equal(before.outcome, "REFUSED");
    assert.equal(before.blobs[0]?.status, "DEADLINE_PENDING");
    await assert.rejects(
      applyRetentionCleanup({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        baseline,
        terminalAuthority: authority,
        evaluatedAt: "2026-01-30T23:59:59.999Z",
      }),
      (error: unknown) => codeOf(error) === "RETENTION_DEADLINE_NOT_REACHED",
    );

    const exactDeadline = await applyRetentionCleanup({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline,
      terminalAuthority: authority,
      evaluatedAt: "2026-01-31T00:00:00.000Z",
    });
    assert.equal(exactDeadline.outcome, "COMPLETE");
    assert.equal(exactDeadline.blobs[0]?.status, "DELETED");
    const blob = baseline.paths[0]?.blob;
    assert.ok(blob);
    await assert.rejects(lstat(baselineBlobPath({ stateRoot: fixture.stateRoot, runId: fixture.runId }, blob.blob_sha256)));

    const repeated = await applyRetentionCleanup({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      baseline,
      terminalAuthority: authority,
      evaluatedAt: "2026-01-31T00:00:00.000Z",
    });
    assert.equal(repeated.outcome, "IDEMPOTENT");
    assert.equal(repeated.blobs[0]?.status, "ALREADY_REMOVED");
    const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(inspection.status, "HEALTHY");
    assert.ok(inspection.managedObjects.some((entry) => entry.kind === "M3_RETENTION_RESULT"));
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("retention refuses missing or modified blobs and records partial cleanup", async (t) => {
  await t.test("missing", async () => {
    const { fixture, baseline, authority } = await terminalBlobFixture();
    try {
      const blob = baseline.paths[0]?.blob;
      assert.ok(blob);
      await unlink(baselineBlobPath({ stateRoot: fixture.stateRoot, runId: fixture.runId }, blob.blob_sha256));
      await assert.rejects(
        applyRetentionCleanup({
          stateRoot: fixture.stateRoot,
          runId: fixture.runId,
          baseline,
          terminalAuthority: authority,
          evaluatedAt: "2026-01-31T00:00:00.000Z",
        }),
        (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN",
      );
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("modified and partial", async () => {
    const { fixture, baseline, authority } = await terminalBlobFixture(["first.txt", "second.txt"]);
    try {
      const second = baseline.paths.find((entry) => entry.path === "second.txt")?.blob;
      assert.ok(second);
      const path = baselineBlobPath({ stateRoot: fixture.stateRoot, runId: fixture.runId }, second.blob_sha256);
      await writeFile(path, Buffer.alloc(second.byte_length, 0x78), { mode: 0o600 });
      await chmod(path, 0o600);
      await assert.rejects(
        applyRetentionCleanup({
          stateRoot: fixture.stateRoot,
          runId: fixture.runId,
          baseline,
          terminalAuthority: authority,
          evaluatedAt: "2026-01-31T00:00:00.000Z",
        }),
        (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN",
      );
      const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });
});

test("retention directory-fsync failure is surfaced through a private deterministic seam", async () => {
  const { fixture, baseline, authority } = await terminalBlobFixture();
  try {
    configureRepositoryTestHooks({
      beforeRetentionDirectorySync: () => { throw new Error("injected directory fsync failure"); },
    });
    await assert.rejects(
      applyRetentionCleanup({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        baseline,
        terminalAuthority: authority,
        evaluatedAt: "2026-01-31T00:00:00.000Z",
      }),
      (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN",
    );
  } finally {
    resetRepositoryTestHooks();
    await removeRepositoryFixture(fixture);
  }
});

test("retention refuses a nonterminal run and uncommitted terminal timestamp", async () => {
  const fixture = await createRepositoryFixture();
  try {
    const fakeBaseline = {};
    assert.throws(
      () => createTerminalRetentionAuthority({
        baseline: fakeBaseline as never,
        approval: null,
        terminalWorkflowState: fixture.initialState,
        terminalTimestamp: "2026-01-01T00:00:00.000Z",
      }),
    );
  } finally {
    await removeRepositoryFixture(fixture);
  }
});
