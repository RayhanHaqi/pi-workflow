import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import { publishImmutableFile } from "../src/persistence/atomic.js";
import {
  commitTransition,
  inspectRunStorage as inspectRunStorageOperation,
  putEvidence as putEvidenceOperation,
} from "../src/persistence/index.js";
import { configurePersistenceTestHooks } from "../src/persistence/test-hooks.js";
import { identifyContractDocument, type ReducerPolicy } from "../src/schemas/index.js";
import {
  commitFirstTransition,
  contentPath,
  createTestRun,
  errorCode,
  evidencePath,
  firstEvent,
  processMetadata,
  rejectsCode,
  removeTestRun,
  runDirectory,
} from "./persistence-helpers.js";
import { transitionEvent } from "./helpers.js";

async function withRun(action: (run: Awaited<ReturnType<typeof createTestRun>>) => Promise<void>): Promise<void> {
  const run = await createTestRun();
  try { await action(run); } finally { await removeTestRun(run); }
}

function inspectRunStorage(input: { readonly stateRoot: string; readonly runId: string }) {
  return inspectRunStorageOperation({ stateRoot: input.stateRoot, runId: input.runId });
}

function putEvidence(input: { readonly stateRoot: string; readonly runId: string; readonly bytes: Uint8Array; readonly mediaType: string }) {
  return putEvidenceOperation({ stateRoot: input.stateRoot, runId: input.runId, bytes: input.bytes, mediaType: input.mediaType });
}

function assertMode(actual: number, expected: number): void {
  assert.equal(actual & 0o777, expected);
}

test("M2 initialization creates a verified genesis commit and private layout", async () => {
  await withRun(async (run) => {
    assert.equal(run.committed.statePointer.revision, 0);
    assert.equal(run.committed.transitionCommit.commit_kind, "GENESIS");
    assert.equal(run.committed.workflowState.phase, "CREATED");
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "HEALTHY");
    assert.equal(inspection.reachableObjects.length, 4);
    assert.equal(inspection.orphanedObjects.length, 0);
    assert.equal(inspection.temporaryFiles.length, 0);
    assertMode((await lstat(run.stateRoot)).mode, 0o700);
    for (const relative of [
      "runs",
      `runs/${run.runId}`,
      `runs/${run.runId}/evidence`,
      `runs/${run.runId}/evidence/sha256`,
      `runs/${run.runId}/records`,
      `runs/${run.runId}/commits`,
    ]) assertMode((await lstat(join(run.stateRoot, relative))).mode, 0o700);
    assertMode((await lstat(join(runDirectory(run), "state.json"))).mode, 0o600);
  });
});

test("run initialization rejects nonempty and ambiguous run directories", async () => {
  const run = await createTestRun();
  try {
    await assert.rejects(
      import("../src/persistence/index.js").then(({ initializeRunStorage }) => initializeRunStorage({
        stateRoot: run.stateRoot,
        runId: run.runId,
        policy: run.policy,
        initialState: run.initialState,
        processMetadata,
      })),
      (error: unknown) => errorCode(error) === "RUN_DIRECTORY_NOT_EMPTY",
    );
  } finally { await removeTestRun(run); }
});

test("evidence storage preserves text, binary, empty, and large byte sequences", async () => {
  await withRun(async (run) => {
    const fixtures = [
      Buffer.from("evidence text\n", "utf8"),
      Buffer.from([0, 255, 1, 128, 10]),
      Buffer.alloc(0),
      Buffer.alloc(1024 * 1024, 0x5a),
    ];
    for (const [index, bytes] of fixtures.entries()) {
      const receipt = await putEvidence({ ...run, bytes, mediaType: `application/x-fixture-${index}` });
      assert.deepEqual(await readFile(evidencePath(run, receipt.evidenceSha256)), bytes);
      assert.equal(receipt.byteLength, bytes.byteLength);
      assertMode((await lstat(evidencePath(run, receipt.evidenceSha256))).mode, 0o600);
      assertMode((await lstat(contentPath(run, "evidence-metadata", receipt.metadataContentSha256))).mode, 0o600);
    }
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    assert.equal(inspection.orphanedObjects.filter((entry) => entry.kind === "RAW_EVIDENCE").length, fixtures.length);
  });
});

test("storing the same evidence twice safely reuses exact immutable objects", async () => {
  await withRun(async (run) => {
    const input = { ...run, bytes: Buffer.from("same"), mediaType: "text/plain" };
    const first = await putEvidence(input);
    const second = await putEvidence(input);
    assert.equal(first.evidenceSha256, second.evidenceSha256);
    assert.equal(first.metadataContentSha256, second.metadataContentSha256);
    assert.equal(first.reusedEvidence, false);
    assert.equal(first.reusedMetadata, false);
    assert.equal(second.reusedEvidence, true);
    assert.equal(second.reusedMetadata, true);
  });
});

test("immutable publication rejects an existing nonidentical regular object", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-gacw-atomic-"));
  await chmod(root, 0o700);
  const target = join(root, "object");
  try {
    await writeFile(target, "different", { mode: 0o600 });
    await chmod(target, 0o600);
    await rejectsCode(publishImmutableFile(target, Buffer.from("expected"), "EVIDENCE"), "IMMUTABLE_OBJECT_MISMATCH");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("atomic primitive cleans handled pre-rename failures and reports post-rename fsync failure", async (t) => {
  for (const operation of ["write", "fileSync", "rename", "directorySync"] as const) {
    await t.test(operation, async () => {
      const root = await mkdtemp(join(tmpdir(), "pi-gacw-atomic-fail-"));
      await chmod(root, 0o700);
      const target = join(root, `${operation}.json`);
      configurePersistenceTestHooks({
        beforeOperation(candidate) {
          if (candidate === operation) throw new Error(`injected ${operation}`);
        },
      });
      try {
        await assert.rejects(publishImmutableFile(target, Buffer.from("value"), "RECORD"));
        const names = await import("node:fs/promises").then(({ readdir }) => readdir(root));
        assert.equal(names.some((name) => name.includes(".tmp-")), false);
        assert.equal(names.includes(`${operation}.json`), operation === "directorySync");
      } finally {
        configurePersistenceTestHooks(undefined);
        await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("atomic primitive rejects temporary collision, symlink, and special final target", async (t) => {
  await t.test("temporary collision", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-gacw-temp-collision-"));
    await chmod(root, 0o700);
    const collision = ".fixed-collision";
    await writeFile(join(root, collision), "owned", { mode: 0o600 });
    configurePersistenceTestHooks({ temporaryName: () => collision });
    try {
      await rejectsCode(publishImmutableFile(join(root, "target"), Buffer.from("x"), "RECORD"), "TEMPORARY_FILE_COLLISION");
      assert.equal(await readFile(join(root, collision), "utf8"), "owned");
    } finally {
      configurePersistenceTestHooks(undefined);
      await rm(root, { recursive: true, force: true });
    }
  });
  await t.test("symlink", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-gacw-symlink-final-"));
    await chmod(root, 0o700);
    await writeFile(join(root, "real"), "x", { mode: 0o600 });
    await symlink("real", join(root, "target"));
    try { await rejectsCode(publishImmutableFile(join(root, "target"), Buffer.from("x"), "RECORD"), "UNSAFE_FILE_TYPE"); }
    finally { await rm(root, { recursive: true, force: true }); }
  });
  await t.test("special file", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-gacw-special-final-"));
    await chmod(root, 0o700);
    const fifo = join(root, "target");
    execFileSync("/usr/bin/mkfifo", [fifo]);
    try { await rejectsCode(publishImmutableFile(fifo, Buffer.from("x"), "RECORD"), "UNSAFE_FILE_TYPE"); }
    finally { await rm(root, { recursive: true, force: true }); }
  });
});

test("valid transition is reducer-derived, revision-exact, and evidence-reachable", async () => {
  await withRun(async (run) => {
    const committed = await commitFirstTransition(run, [{ bytes: Buffer.from([0, 1, 255]), mediaType: "application/octet-stream" }]);
    assert.equal(committed.statePointer.revision, 1);
    assert.equal(committed.workflowState.phase, "OBJECTIVE_FROZEN");
    assert.equal(committed.transitionCommit.previous_revision, 0);
    assert.equal(committed.transitionCommit.commit_kind, "TRANSITION");
    assert.equal(committed.evidence.length, 1);
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "HEALTHY");
    assert.equal(inspection.revision, 1);
    assert.equal(inspection.orphanedObjects.length, 0);
    assert.ok(inspection.reachableObjects.some((entry) => entry.kind === "RAW_EVIDENCE"));
  });
});

test("transition commit rejects stale revision, pointer, state, and arbitrary next-state expectation", async (t) => {
  await withRun(async (run) => {
    const base = {
      stateRoot: run.stateRoot,
      runId: run.runId,
      expectedRevision: 0,
      expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: "transition-validation",
      policy: run.policy,
      event: firstEvent(),
      processMetadata,
    };
    await t.test("stale revision and revision skip", () => rejectsCode(commitTransition({ ...base, expectedRevision: 2 }), "STALE_EXPECTED_REVISION"));
    await t.test("stale pointer", () => rejectsCode(commitTransition({ ...base, expectedStatePointerContentSha256: `sha256:${"1".repeat(64)}` }), "STALE_STATE_POINTER"));
    await t.test("stale state", () => rejectsCode(commitTransition({ ...base, expectedWorkflowStateContentSha256: `sha256:${"2".repeat(64)}` }), "STALE_WORKFLOW_STATE"));
    await t.test("arbitrary next state", () => rejectsCode(commitTransition({ ...base, expectedNextWorkflowStateContentSha256: `sha256:${"3".repeat(64)}` }), "EXPECTED_NEXT_STATE_MISMATCH"));
  });
});

test("transition commit rejects invalid event, invalid policy, and policy not bound to state", async (t) => {
  await withRun(async (run) => {
    const base = {
      stateRoot: run.stateRoot,
      runId: run.runId,
      expectedRevision: 0,
      expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: "transition-invalid-input",
      policy: run.policy,
      event: firstEvent(),
      processMetadata,
    };
    await t.test("invalid event", async () => {
      const event = structuredClone(base.event) as any;
      event.payload.extra = true;
      await assert.rejects(commitTransition({ ...base, event }));
    });
    await t.test("invalid policy", async () => {
      const policy = structuredClone(run.policy) as any;
      policy.extra = true;
      await assert.rejects(commitTransition({ ...base, policy }));
    });
    await t.test("unbound valid policy", async () => {
      const policy = identifyContractDocument("pi_gacw_reducer_policy_v0", {
        ...run.policy,
        content_sha256: undefined,
        limits: { ...run.policy.limits, max_direct_attempts: 1 },
      } as any) as unknown as ReducerPolicy;
      await assert.rejects(commitTransition({ ...base, policy }), (error: unknown) => errorCode(error) === "FROZEN_POLICY_IDENTITY_MISMATCH");
    });
  });
});

test("wrong run ID and invalid run-ID grammar fail closed", async () => {
  await withRun(async (run) => {
    for (const runId of ["", "/absolute", "a/b", "a\\b", ".", "..", "../escape", "a.b", "nul\u0000byte", "control\u0001byte"]) {
      await rejectsCode(inspectRunStorageOperation({ stateRoot: run.stateRoot, runId }), "INVALID_RUN_ID");
    }
    const inspection = await inspectRunStorage({ stateRoot: run.stateRoot, runId: "other-run" });
    assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
  });
});

test("terminal-state continuation is rejected", async () => {
  await withRun(async (run) => {
    const terminal = await commitTransition({
      stateRoot: run.stateRoot,
      runId: run.runId,
      expectedRevision: 0,
      expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: "terminal-block",
      policy: run.policy,
      event: transitionEvent("BLOCK", { reason: "TEST_BLOCK" }),
      processMetadata,
    });
    await rejectsCode(commitTransition({
      stateRoot: run.stateRoot,
      runId: run.runId,
      expectedRevision: 1,
      expectedStatePointerContentSha256: terminal.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: terminal.workflowState.content_sha256 as Sha256Digest,
      transitionId: "after-terminal",
      policy: run.policy,
      event: transitionEvent("ACQUIRE_LOCK"),
      processMetadata,
    }), "TERMINAL_STATE_IMMUTABLE");
  });
});

test("missing or hash-invalid committed evidence blocks the next commit", async (t) => {
  await t.test("missing evidence", async () => {
    await withRun(async (run) => {
      const committed = await commitFirstTransition(run, [{ bytes: Buffer.from("missing"), mediaType: "text/plain" }]);
      const receipt = committed.evidence[0]; assert.ok(receipt);
      await unlink(evidencePath(run, receipt.evidenceSha256));
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
      await rejectsCode(commitTransition({
        stateRoot: run.stateRoot, runId: run.runId,
        expectedRevision: 1,
        expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
        expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
        transitionId: "missing-reference", policy: run.policy,
        event: transitionEvent("ACQUIRE_LOCK"), processMetadata,
      }), "BLOCKED_STATE_COMMIT_INCOMPLETE");
    });
  });
  await t.test("wrong evidence hash and byte count", async () => {
    await withRun(async (run) => {
      const committed = await commitFirstTransition(run, [{ bytes: Buffer.from("correct"), mediaType: "text/plain" }]);
      const receipt = committed.evidence[0]; assert.ok(receipt);
      await writeFile(evidencePath(run, receipt.evidenceSha256), "wrong", { mode: 0o600 });
      await chmod(evidencePath(run, receipt.evidenceSha256), 0o600);
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
      assert.equal(inspection.issues[0]?.code, "EVIDENCE_HASH_MISMATCH");
    });
  });
});
