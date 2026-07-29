import assert from "node:assert/strict";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { makePolicy, stateIdentities, transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";

const PERSISTENCE_PACKAGE: string = "pi-bounded-coding-workflow/persistence";

function hasCode(error: unknown, code: string): boolean {
  return error !== null && typeof error === "object" && "code" in error && (error as { readonly code: unknown }).code === code;
}

function assertDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const nested of Object.values(value)) assertDeepFrozen(nested, seen);
}

test("built persistence package exposes only the bounded validated API", async (t) => {
  const persistence = await import(PERSISTENCE_PACKAGE);
  assert.deepEqual(Object.keys(persistence).sort(), [
    "StateStoreError",
    "commitTransition",
    "initializeRunStorage",
    "inspectRunStorage",
    "putEvidence",
    "terminalizeProcessCrash",
  ]);
  for (const forbidden of [
    "resumeRun",
    "forceCommit",
    "writePath",
    "rawWrite",
    "overwriteState",
    "adoptOrphan",
    "deleteEvidence",
    "skipFsync",
    "configurePersistenceTestHooks",
  ]) assert.equal(forbidden in persistence, false, forbidden);

  for (const subpath of [
    "pi-bounded-coding-workflow/persistence/store",
    "pi-bounded-coding-workflow/persistence/atomic",
    "pi-bounded-coding-workflow/persistence/test-hooks",
    "pi-bounded-coding-workflow/src/persistence/store",
    "pi-bounded-coding-workflow/dist/src/persistence/store.js",
  ]) {
    await t.test(`blocked internal subpath ${subpath}`, async () => {
      await assert.rejects(import(subpath), (error: unknown) => hasCode(error, "ERR_PACKAGE_PATH_NOT_EXPORTED"));
    });
  }
});

test("built persistence operations validate arguments and return detached frozen inspection data", async () => {
  const persistence = await import(PERSISTENCE_PACKAGE);
  const stateMachine = await import("pi-bounded-coding-workflow/state-machine");
  await assert.rejects(
    persistence.inspectRunStorage({ stateRoot: "relative", runId: "run" }),
    (error: unknown) => hasCode(error, "INVALID_STATE_ROOT"),
  );
  await assert.rejects(
    persistence.inspectRunStorage({ stateRoot: "/tmp", runId: "../escape" }),
    (error: unknown) => hasCode(error, "INVALID_RUN_ID"),
  );

  const stateRoot = await mkdtemp(join(tmpdir(), "pi-gacw-built-persistence-"));
  await chmod(stateRoot, 0o700);
  try {
    const policy = makePolicy("DIRECT_LUNA_HIGH");
    const initialState = stateMachine.createInitialState(policy, stateIdentities(policy));
    const genesis = await persistence.initializeRunStorage({ stateRoot, runId: policy.run_id, policy, initialState, processMetadata });
    const invalidOperations = [
      () => persistence.inspectRunStorage({ stateRoot, runId: policy.run_id, extra: true } as any),
      () => persistence.initializeRunStorage({ stateRoot, runId: policy.run_id, policy, initialState, processMetadata, extra: true } as any),
      () => persistence.putEvidence({ stateRoot, runId: policy.run_id, bytes: Buffer.from("x"), mediaType: "text/plain", extra: true } as any),
      () => persistence.commitTransition({
        stateRoot,
        runId: policy.run_id,
        expectedRevision: 0,
        expectedStatePointerContentSha256: genesis.statePointer.content_sha256,
        expectedWorkflowStateContentSha256: genesis.workflowState.content_sha256,
        transitionId: "strict-options",
        policy,
        event: transitionEvent("FREEZE_OBJECTIVE"),
        processMetadata,
        extra: true,
      } as any),
      () => persistence.terminalizeProcessCrash({
        stateRoot,
        runId: policy.run_id,
        expectedRevision: 0,
        expectedStatePointerContentSha256: genesis.statePointer.content_sha256,
        expectedWorkflowStateContentSha256: genesis.workflowState.content_sha256,
        transitionId: "strict-terminalize-options",
        policy,
        processMetadata,
        interruptionEvidence: {
          controller_instance_id: "controller-test",
          process_id: 1,
          invocation_id: "strict-options",
          exit_kind: "UNEXPECTED_TERMINATION",
          detail: "test",
        },
        extra: true,
      } as any),
    ];
    for (const operation of invalidOperations) {
      await assert.rejects(operation(), (error: unknown) => hasCode(error, "INVALID_ARGUMENT"));
    }
    const first = await persistence.inspectRunStorage({ stateRoot, runId: policy.run_id });
    const second = await persistence.inspectRunStorage({ stateRoot, runId: policy.run_id });
    assert.equal(first.status, "HEALTHY");
    assert.notEqual(first, second);
    assert.notEqual(first.statePointer, second.statePointer);
    assertDeepFrozen(first);
    assert.equal(Reflect.set(first, "status", "ORPHANED_UNCOMMITTED_EVIDENCE"), false);
    assert.equal((await persistence.inspectRunStorage({ stateRoot, runId: policy.run_id })).status, "HEALTHY");
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
});
