import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import {
  inspectRunStorage as inspectRunStorageOperation,
  putEvidence as putEvidenceOperation,
} from "../src/persistence/index.js";
import { identifyContractDocument } from "../src/schemas/index.js";
import { digest } from "./helpers.js";
import {
  commitPath,
  contentPath,
  createTestRun,
  processMetadata,
  removeTestRun,
  runDirectory,
  writeCanonicalPrivateFile,
} from "./persistence-helpers.js";

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

test("inspection classifies healthy storage and detached immutable results", async () => {
  await withRun(async (run) => {
    const first = await inspectRunStorage(run);
    const second = await inspectRunStorage(run);
    assert.equal(first.status, "HEALTHY");
    assert.notEqual(first, second);
    assert.notEqual(first.statePointer, second.statePointer);
    const assertFrozen = (value: unknown, seen = new Set<object>()): void => {
      if (value === null || typeof value !== "object" || seen.has(value)) return;
      seen.add(value);
      assert.equal(Object.isFrozen(value), true);
      for (const nested of Object.values(value)) assertFrozen(nested, seen);
    };
    assertFrozen(first);
    assert.equal(Reflect.set(first, "status", "HEALTHY"), false);
    assert.equal(Reflect.set(first.statePointer as object, "revision", 99), false);
    assert.equal((await inspectRunStorage(run)).revision, 0);
  });
});

test("inspection classifies orphan raw evidence and metadata without adopting them", async () => {
  await withRun(async (run) => {
    await putEvidence({ ...run, bytes: Buffer.from("orphan"), mediaType: "text/plain" });
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    assert.deepEqual(new Set(inspection.orphanedObjects.map((entry) => entry.kind)), new Set(["RAW_EVIDENCE", "EVIDENCE_METADATA"]));
    assert.equal(inspection.revision, 0);
    assert.equal(inspection.workflowState?.phase, "CREATED");
  });
});

test("inspection classifies orphan JSON records and transition commits", async () => {
  await withRun(async (run) => {
    const metadata = identifyContractDocument("pi_gacw_evidence_metadata_v0", {
      schema_id: "pi_gacw_evidence_metadata_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: run.runId,
      evidence_sha256: digest(900),
      byte_length: 1,
      media_type: "application/octet-stream",
    });
    await writeCanonicalPrivateFile(contentPath(run, "evidence-metadata", metadata.content_sha256), metadata);
    const orphanCommit = identifyContractDocument("pi_gacw_state_transition_commit_v0", {
      schema_id: "pi_gacw_state_transition_commit_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      commit_protocol_version: "state-commit-v1",
      commit_kind: "GENESIS",
      run_id: run.runId,
      transition_id: "orphan-genesis",
      previous_revision: null,
      new_revision: 0,
      previous_state_pointer_content_sha256: null,
      previous_workflow_state_content_sha256: null,
      previous_transition_commit_content_sha256: null,
      transition_event_content_sha256: null,
      reducer_policy_content_sha256: run.policy.content_sha256,
      new_workflow_state_content_sha256: digest(901),
      evidence_manifest_content_sha256: digest(902),
      process_assessment_content_sha256: null,
      process_metadata: processMetadata,
    });
    await writeCanonicalPrivateFile(commitPath(run, orphanCommit.content_sha256), orphanCommit);
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    assert.ok(inspection.orphanedObjects.some((entry) => entry.kind === "EVIDENCE_METADATA"));
    assert.ok(inspection.orphanedObjects.some((entry) => entry.kind === "TRANSITION_COMMIT"));
  });
});

test("inspection reports a valid leftover temporary file separately", async () => {
  await withRun(async (run) => {
    const temp = join(runDirectory(run), ".state.json.tmp-999-0123456789abcdef");
    await writeFile(temp, "uncommitted", { mode: 0o600 });
    await chmod(temp, 0o600);
    const inspection = await inspectRunStorage(run);
    assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
    assert.deepEqual(inspection.temporaryFiles, [".state.json.tmp-999-0123456789abcdef"]);
    assert.equal(await readFile(temp, "utf8"), "uncommitted");
  });
});

test("inspection blocks missing, modified, or malformed committed objects", async (t) => {
  await t.test("missing referenced commit", async () => {
    await withRun(async (run) => {
      await unlink(commitPath(run, run.committed.transitionCommit.content_sha256));
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
    });
  });
  await t.test("modified committed state", async () => {
    await withRun(async (run) => {
      const path = contentPath(run, "workflow-states", run.initialState.content_sha256);
      await writeFile(path, `${canonicalize(run.initialState)} \n`, { mode: 0o600 });
      await chmod(path, 0o600);
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
      assert.equal(inspection.issues[0]?.code, "NONCANONICAL_RECORD_BYTES");
    });
  });
  await t.test("malformed state pointer", async () => {
    await withRun(async (run) => {
      const state = join(runDirectory(run), "state.json");
      await writeFile(state, "{", { mode: 0o600 });
      await chmod(state, 0o600);
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
      assert.equal(inspection.issues[0]?.code, "MALFORMED_STATE_POINTER");
    });
  });
});

test("inspection blocks unknown, symlink, and special entries", async (t) => {
  await t.test("unknown file", async () => {
    await withRun(async (run) => {
      await writeFile(join(runDirectory(run), "unknown.bin"), "x", { mode: 0o600 });
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "UNKNOWN_ENTRY");
    });
  });
  await t.test("symlink entry", async () => {
    await withRun(async (run) => {
      await symlink("state.json", join(runDirectory(run), "link"));
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "SYMLINK_ENTRY");
    });
  });
  await t.test("state pointer symlink", async () => {
    await withRun(async (run) => {
      const statePath = join(runDirectory(run), "state.json");
      await unlink(statePath);
      await symlink("commits", statePath);
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "SYMLINK_ENTRY");
    });
  });
  await t.test("missing state pointer", async () => {
    await withRun(async (run) => {
      await unlink(join(runDirectory(run), "state.json"));
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
      assert.equal(inspection.issues[0]?.code, "MISSING_REQUIRED_ENTRY");
    });
  });
  await t.test("special entry", async () => {
    await withRun(async (run) => {
      const fifo = join(runDirectory(run), "special");
      execFileSync("/usr/bin/mkfifo", [fifo]);
      const inspection = await inspectRunStorage(run);
      assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
      assert.equal(inspection.issues[0]?.code, "SPECIAL_FILE_ENTRY");
    });
  });
});
