import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import test from "node:test";
import { promisify } from "node:util";

import type { Sha256Digest } from "../src/identity/index.js";
import { PERSISTENCE_CHECKPOINTS, type PersistenceCheckpoint } from "../src/persistence/test-hooks.js";
import { createTestRun, firstEvent, processMetadata, removeTestRun } from "./persistence-helpers.js";

const execFileAsync = promisify(execFile);
const testDirectory = dirname(fileURLToPath(import.meta.url));
const childDriver = resolve(testDirectory, "../dist/tests/persistence-child.js");
const stateRenamedIndex = PERSISTENCE_CHECKPOINTS.indexOf("STATE_RENAMED");

async function interruptAt(checkpoint: PersistenceCheckpoint): Promise<{
  readonly inspection: any;
  readonly expectedNewState: boolean;
}> {
  const run = await createTestRun();
  const controlRoot = await mkdtemp(join(tmpdir(), "pi-gacw-process-control-"));
  await chmod(controlRoot, 0o700);
  const inputPath = join(controlRoot, "input.json");
  const input = {
    stateRoot: run.stateRoot,
    runId: run.runId,
    expectedRevision: 0,
    expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
    transitionId: `checkpoint-${checkpoint.toLowerCase().replaceAll("_", "-")}`,
    policy: run.policy,
    event: firstEvent(),
    evidence: [{ base64: Buffer.from("checkpoint evidence").toString("base64"), mediaType: "text/plain" }],
    processMetadata,
  };
  await writeFile(inputPath, JSON.stringify(input), { mode: 0o600 });
  await chmod(inputPath, 0o600);

  try {
    const child = fork(childDriver, ["commit", inputPath, checkpoint], {
      execArgv: [],
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    await new Promise<void>((resolveReached, rejectReached) => {
      let reached = false;
      child.on("message", (message: unknown) => {
        if (
          message !== null &&
          typeof message === "object" &&
          "checkpoint" in message &&
          (message as { readonly checkpoint: unknown }).checkpoint === checkpoint
        ) {
          reached = true;
          resolveReached();
        }
      });
      child.once("exit", (code, signal) => {
        if (!reached) rejectReached(new Error(`child exited before ${checkpoint}: code=${code} signal=${signal} ${stderr}`));
      });
      child.once("error", rejectReached);
    });
    assert.equal(child.kill("SIGKILL"), true);
    await new Promise<void>((resolveExit, rejectExit) => {
      child.once("exit", (_code, signal) => {
        try { assert.equal(signal, "SIGKILL"); resolveExit(); } catch (error) { rejectExit(error); }
      });
      child.once("error", rejectExit);
    });

    const inspected = await execFileAsync(process.execPath, [childDriver, "inspect", inputPath], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
    const inspection = JSON.parse(inspected.stdout) as any;
    const expectedNewState = PERSISTENCE_CHECKPOINTS.indexOf(checkpoint) >= stateRenamedIndex;
    return { inspection, expectedNewState };
  } finally {
    await removeTestRun(run);
    await rm(controlRoot, { recursive: true, force: true });
  }
}

test("process interruption at every atomic protocol checkpoint leaves an old-or-new valid pointer", async (t) => {
  for (const checkpoint of PERSISTENCE_CHECKPOINTS) {
    await t.test(checkpoint, async () => {
      const { inspection, expectedNewState } = await interruptAt(checkpoint);
      assert.equal(inspection.issues.length, 0);
      assert.ok(inspection.statePointer);
      assert.ok(inspection.workflowState);
      assert.ok(inspection.transitionCommit);
      if (expectedNewState) {
        assert.equal(inspection.status, "HEALTHY");
        assert.equal(inspection.revision, 1);
        assert.equal(inspection.workflowState.phase, "OBJECTIVE_FROZEN");
        assert.equal(inspection.orphanedObjects.length, 0);
        assert.equal(inspection.temporaryFiles.length, 0);
      } else {
        assert.equal(inspection.status, "ORPHANED_UNCOMMITTED_EVIDENCE");
        assert.equal(inspection.revision, 0);
        assert.equal(inspection.workflowState.phase, "CREATED");
        assert.ok(inspection.orphanedObjects.length > 0 || inspection.temporaryFiles.length > 0);
      }
    });
  }
});
