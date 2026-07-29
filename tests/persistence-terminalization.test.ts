import assert from "node:assert/strict";
import { chmod, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import {
  commitTransition,
  inspectRunStorage as inspectRunStorageOperation,
  putEvidence as putEvidenceOperation,
  terminalizeProcessCrash,
} from "../src/persistence/index.js";
import { transitionEvent } from "./helpers.js";
import {
  commitPath,
  createTestRun,
  processMetadata,
  rejectsCode,
  removeTestRun,
  runDirectory,
} from "./persistence-helpers.js";

const interruptionEvidence = {
  controller_instance_id: "controller-crashed",
  process_id: 5151,
  invocation_id: "invocation-crashed",
  exit_kind: "UNEXPECTED_TERMINATION" as const,
  detail: "The prior controller process terminated before reporting completion.",
};

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

function terminalizeInput(run: Awaited<ReturnType<typeof createTestRun>>) {
  return {
    stateRoot: run.stateRoot,
    runId: run.runId,
    expectedRevision: run.committed.statePointer.revision,
    expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
    transitionId: "process-crash",
    policy: run.policy,
    processMetadata,
    interruptionEvidence,
  };
}

test("valid process interruption terminalizes through the M1 BLOCK reducer transition", async () => {
  await withRun(async (run) => {
    const terminal = await terminalizeProcessCrash(terminalizeInput(run));
    assert.equal(terminal.statePointer.revision, 1);
    assert.equal(terminal.transitionCommit.commit_kind, "PROCESS_CRASH");
    assert.equal(terminal.workflowState.phase, "BLOCKED");
    assert.equal(terminal.workflowState.terminal_reason, "BLOCKED_PROCESS_CRASH");
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "HEALTHY");
    assert.ok(inspection.reachableObjects.some((entry) => entry.kind === "PROCESS_ASSESSMENT"));
    assert.ok(inspection.reachableObjects.some((entry) => entry.kind === "TRANSITION_EVENT"));
  });
});

test("process terminalization inventories but does not adopt existing orphans", async () => {
  await withRun(async (run) => {
    const receipt = await putEvidence({ ...run, bytes: Buffer.from("uncommitted"), mediaType: "text/plain" });
    const before = await inspectRunStorage(run);
    assert.equal(before.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    const terminal = await terminalizeProcessCrash(terminalizeInput(run));
    assert.equal(terminal.workflowState.terminal_reason, "BLOCKED_PROCESS_CRASH");
    const after = await inspectRunStorage(run);
    assert.equal(after.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    assert.ok(after.orphanedObjects.some((entry) => entry.contentSha256 === receipt.evidenceSha256));
    assert.ok(after.reachableObjects.some((entry) => entry.kind === "PROCESS_ASSESSMENT"));
  });
});

test("already terminal runs reject second terminalization and further commits", async () => {
  await withRun(async (run) => {
    const terminal = await terminalizeProcessCrash(terminalizeInput(run));
    const nextInput = {
      ...terminalizeInput(run),
      expectedRevision: terminal.statePointer.revision,
      expectedStatePointerContentSha256: terminal.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: terminal.workflowState.content_sha256 as Sha256Digest,
      transitionId: "process-crash-second",
    };
    await rejectsCode(terminalizeProcessCrash(nextInput), "TERMINAL_STATE_IMMUTABLE");
    await rejectsCode(commitTransition({
      stateRoot: run.stateRoot,
      runId: run.runId,
      expectedRevision: terminal.statePointer.revision,
      expectedStatePointerContentSha256: terminal.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: terminal.workflowState.content_sha256 as Sha256Digest,
      transitionId: "commit-after-crash",
      policy: run.policy,
      event: transitionEvent("FREEZE_OBJECTIVE"),
      processMetadata,
    }), "TERMINAL_STATE_IMMUTABLE");
  });
});

test("terminalization rejects stale expected revision, pointer, and workflow state", async (t) => {
  await withRun(async (run) => {
    const base = terminalizeInput(run);
    await t.test("revision", () => rejectsCode(terminalizeProcessCrash({ ...base, expectedRevision: 1 }), "STALE_EXPECTED_REVISION"));
    await t.test("pointer", () => rejectsCode(terminalizeProcessCrash({ ...base, expectedStatePointerContentSha256: `sha256:${"1".repeat(64)}` }), "STALE_STATE_POINTER"));
    await t.test("state", () => rejectsCode(terminalizeProcessCrash({ ...base, expectedWorkflowStateContentSha256: `sha256:${"2".repeat(64)}` }), "STALE_WORKFLOW_STATE"));
  });
});

test("terminalization requires explicit process-interruption evidence", async () => {
  await withRun(async (run) => {
    await rejectsCode(
      terminalizeProcessCrash({ ...terminalizeInput(run), interruptionEvidence: undefined } as any),
      "INVALID_ARGUMENT",
    );
  });
});

test("terminalization refuses malformed or incomplete committed authority", async (t) => {
  await t.test("malformed pointer", async () => {
    await withRun(async (run) => {
      const statePath = join(runDirectory(run), "state.json");
      await writeFile(statePath, "{", { mode: 0o600 });
      await chmod(statePath, 0o600);
      await rejectsCode(terminalizeProcessCrash(terminalizeInput(run)), "BLOCKED_STATE_COMMIT_INCOMPLETE");
    });
  });
  await t.test("missing transition commit", async () => {
    await withRun(async (run) => {
      await unlink(commitPath(run, run.committed.transitionCommit.content_sha256));
      await rejectsCode(terminalizeProcessCrash(terminalizeInput(run)), "BLOCKED_STATE_COMMIT_INCOMPLETE");
    });
  });
});
