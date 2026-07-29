import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import type {
  CommittedRunState,
  RunStorageInspection,
} from "../src/persistence/index.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type PersistedStatePointerDocument,
  type ProcessInterruptionDocument,
  type StateTransitionCommitDocument,
} from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { digest, makePolicy, stateIdentities, transitionEvent } from "./helpers.js";
import {
  commitPath,
  contentPath,
  createTestRun,
  errorCode,
  evidencePath,
  processMetadata,
  removeTestRun,
  runDirectory,
  type TestRun,
  writeCanonicalPrivateFile,
} from "./persistence-helpers.js";

const PERSISTENCE_PACKAGE: string = "pi-bounded-coding-workflow/persistence";
type PersistenceApi = typeof import("../src/persistence/index.js");

const interruptionEvidence = {
  controller_instance_id: "controller-crashed",
  process_id: 5151,
  invocation_id: "invocation-crashed",
  exit_kind: "UNEXPECTED_TERMINATION" as const,
  detail: "The prior controller process terminated before reporting completion.",
};

async function builtPersistence(): Promise<PersistenceApi> {
  return await import(PERSISTENCE_PACKAGE) as PersistenceApi;
}

async function withRun(action: (run: TestRun) => Promise<void>): Promise<void> {
  const run = await createTestRun();
  try {
    await action(run);
  } finally {
    await removeTestRun(run);
  }
}

function firstCommitInput(run: TestRun, evidence: readonly { readonly bytes: Uint8Array; readonly mediaType: string }[] = []) {
  return {
    stateRoot: run.stateRoot,
    runId: run.runId,
    expectedRevision: run.committed.statePointer.revision,
    expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
    transitionId: "boundary-integrity-transition",
    policy: run.policy,
    event: transitionEvent("FREEZE_OBJECTIVE"),
    evidence,
    processMetadata,
  };
}

function terminalizeInput(run: TestRun, authority: CommittedRunState = run.committed, transitionId = "boundary-integrity-crash") {
  return {
    stateRoot: run.stateRoot,
    runId: run.runId,
    expectedRevision: authority.statePointer.revision,
    expectedStatePointerContentSha256: authority.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: authority.workflowState.content_sha256 as Sha256Digest,
    transitionId,
    policy: run.policy,
    processMetadata,
    interruptionEvidence,
  };
}

function assessmentPath(run: TestRun, digestValue: string): string {
  return contentPath(run, "process-assessments", digestValue);
}

function statePath(run: TestRun): string {
  return join(runDirectory(run), "state.json");
}

async function filesystemInventory(root: string): Promise<readonly string[]> {
  const entries: string[] = [];
  const walk = async (path: string, relativePath: string): Promise<void> => {
    const stats = await lstat(path);
    const mode = (stats.mode & 0o777).toString(8).padStart(3, "0");
    let kind = "special";
    let identity = "";
    if (stats.isSymbolicLink()) {
      kind = "symlink";
      identity = await readlink(path);
    } else if (stats.isDirectory()) {
      kind = "directory";
    } else if (stats.isFile()) {
      kind = "file";
      identity = sha256Bytes(await readFile(path));
    } else if (stats.isFIFO()) {
      kind = "fifo";
    }
    entries.push(`${relativePath}|${kind}|${mode}|${identity}`);
    if (stats.isDirectory() && !stats.isSymbolicLink()) {
      for (const name of (await readdir(path)).sort()) {
        await walk(join(path, name), relativePath === "." ? name : `${relativePath}/${name}`);
      }
    }
  };
  await walk(root, ".");
  return entries;
}

async function assertBlockedMutation(
  api: PersistenceApi,
  run: TestRun,
  mutation: "initialize" | "putEvidence" | "commitTransition" | "terminalizeProcessCrash",
): Promise<void> {
  let operation: Promise<unknown>;
  switch (mutation) {
    case "initialize":
      operation = api.initializeRunStorage({
        stateRoot: run.stateRoot,
        runId: run.runId,
        policy: run.policy,
        initialState: run.initialState,
        processMetadata,
      });
      break;
    case "putEvidence":
      operation = api.putEvidence({
        stateRoot: run.stateRoot,
        runId: run.runId,
        bytes: new Uint8Array([1, 2, 3]),
        mediaType: "application/octet-stream",
      });
      break;
    case "commitTransition":
      operation = api.commitTransition(firstCommitInput(run));
      break;
    case "terminalizeProcessCrash":
      operation = api.terminalizeProcessCrash(terminalizeInput(run));
      break;
  }
  await assert.rejects(operation, (error: unknown) => errorCode(error) === "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
}

interface InvalidLayoutCase {
  readonly name: string;
  readonly expectedIssueCode: string;
  readonly expectedRelativePath: string;
  readonly mutation: "initialize" | "putEvidence" | "commitTransition" | "terminalizeProcessCrash";
  readonly inject: (run: TestRun) => Promise<void>;
}

const invalidLayoutCases: readonly InvalidLayoutCase[] = [
  {
    name: "unexpected state-root regular file",
    expectedIssueCode: "UNKNOWN_ENTRY",
    expectedRelativePath: "unexpected-file",
    mutation: "initialize",
    inject: async (run) => {
      await writeFile(join(run.stateRoot, "unexpected-file"), "unexpected", { mode: 0o600 });
      await chmod(join(run.stateRoot, "unexpected-file"), 0o600);
    },
  },
  {
    name: "unexpected state-root directory",
    expectedIssueCode: "UNKNOWN_ENTRY",
    expectedRelativePath: "unexpected-directory",
    mutation: "putEvidence",
    inject: async (run) => {
      await mkdir(join(run.stateRoot, "unexpected-directory"), { mode: 0o700 });
      await chmod(join(run.stateRoot, "unexpected-directory"), 0o700);
    },
  },
  {
    name: "state-root symlink entry",
    expectedIssueCode: "SYMLINK_ENTRY",
    expectedRelativePath: "unexpected-link",
    mutation: "commitTransition",
    inject: async (run) => {
      await symlink("runs", join(run.stateRoot, "unexpected-link"));
    },
  },
  {
    name: "state-root FIFO",
    expectedIssueCode: "SPECIAL_FILE_ENTRY",
    expectedRelativePath: "unexpected-fifo",
    mutation: "terminalizeProcessCrash",
    inject: async (run) => {
      execFileSync("/usr/bin/mkfifo", [join(run.stateRoot, "unexpected-fifo")]);
    },
  },
  {
    name: "invalid run-directory name",
    expectedIssueCode: "INVALID_RUN_DIRECTORY_NAME",
    expectedRelativePath: "runs/not-a-run!",
    mutation: "commitTransition",
    inject: async (run) => {
      await mkdir(join(run.stateRoot, "runs", "not-a-run!"), { mode: 0o700 });
      await chmod(join(run.stateRoot, "runs", "not-a-run!"), 0o700);
    },
  },
  {
    name: "regular file in runs",
    expectedIssueCode: "RUN_ENTRY_NOT_DIRECTORY",
    expectedRelativePath: "runs/sibling-file",
    mutation: "putEvidence",
    inject: async (run) => {
      await writeFile(join(run.stateRoot, "runs", "sibling-file"), "unexpected", { mode: 0o600 });
      await chmod(join(run.stateRoot, "runs", "sibling-file"), 0o600);
    },
  },
  {
    name: "symlink in runs",
    expectedIssueCode: "SYMLINK_ENTRY",
    expectedRelativePath: "runs/sibling-link",
    mutation: "terminalizeProcessCrash",
    inject: async (run) => {
      await symlink(run.runId, join(run.stateRoot, "runs", "sibling-link"));
    },
  },
  {
    name: "FIFO in runs",
    expectedIssueCode: "SPECIAL_FILE_ENTRY",
    expectedRelativePath: "runs/sibling-fifo",
    mutation: "commitTransition",
    inject: async (run) => {
      execFileSync("/usr/bin/mkfifo", [join(run.stateRoot, "runs", "sibling-fifo")]);
    },
  },
  {
    name: "wrong-mode sibling run directory",
    expectedIssueCode: "PERMISSION_MISMATCH",
    expectedRelativePath: "runs/sibling-mode",
    mutation: "commitTransition",
    inject: async (run) => {
      await mkdir(join(run.stateRoot, "runs", "sibling-mode"), { mode: 0o755 });
      await chmod(join(run.stateRoot, "runs", "sibling-mode"), 0o755);
    },
  },
  {
    name: "temporary-looking runs entry",
    expectedIssueCode: "INVALID_RUN_DIRECTORY_NAME",
    expectedRelativePath: "runs/.state.json.tmp-1-0123456789abcdef",
    mutation: "commitTransition",
    inject: async (run) => {
      await writeFile(join(run.stateRoot, "runs", ".state.json.tmp-1-0123456789abcdef"), "temporary", { mode: 0o600 });
      await chmod(join(run.stateRoot, "runs", ".state.json.tmp-1-0123456789abcdef"), 0o600);
    },
  },
];

test("putEvidence captures a shared-buffer view during the built-package invocation", async () => {
  const api = await builtPersistence();
  await withRun(async (run) => {
    const storage = new Uint8Array([90, 1, 2, 3, 4, 91]);
    const original = new Uint8Array(storage.buffer, 1, 4);
    const invocationSnapshot = Uint8Array.from(original);
    const expectedDigest = sha256Bytes(invocationSnapshot);

    const promise = api.putEvidence({
      stateRoot: run.stateRoot,
      runId: run.runId,
      bytes: original,
      mediaType: "application/x-invocation-snapshot",
    });
    storage.fill(255);
    const receipt = await promise;

    assert.equal(receipt.evidenceSha256, expectedDigest);
    assert.equal(receipt.byteLength, invocationSnapshot.byteLength);
    assert.equal(receipt.mediaType, "application/x-invocation-snapshot");
    assert.deepEqual(await readFile(evidencePath(run, receipt.evidenceSha256)), Buffer.from(invocationSnapshot));
    const metadata = JSON.parse(await readFile(contentPath(run, "evidence-metadata", receipt.metadataContentSha256), "utf8")) as {
      readonly evidence_sha256: string;
      readonly byte_length: number;
      readonly media_type: string;
    };
    assert.equal(metadata.evidence_sha256, expectedDigest);
    assert.equal(metadata.byte_length, invocationSnapshot.byteLength);
    assert.equal(metadata.media_type, "application/x-invocation-snapshot");

    original.fill(17);
    assert.deepEqual(await readFile(evidencePath(run, receipt.evidenceSha256)), Buffer.from(invocationSnapshot));
  });
});

test("commitTransition captures multiple entries, entry selection, and shared views during built-package invocation", async () => {
  const api = await builtPersistence();
  await withRun(async (run) => {
    const storage = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const firstView = new Uint8Array(storage.buffer, 0, 4);
    const secondView = new Uint8Array(storage.buffer, 2, 6);
    const firstSnapshot = Uint8Array.from(firstView);
    const secondSnapshot = Uint8Array.from(secondView);
    const evidence: Array<{ bytes: Uint8Array; mediaType: string }> = [
      { bytes: firstView, mediaType: "application/x-first-view" },
      { bytes: secondView, mediaType: "application/x-second-view" },
    ];

    const promise = api.commitTransition(firstCommitInput(run, evidence));
    storage.fill(238);
    evidence[0] = { bytes: new Uint8Array([99]), mediaType: "application/x-replaced" };
    evidence.reverse();
    const committed = await promise;

    assert.equal(committed.evidence.length, 2);
    const firstReceipt = committed.evidence[0];
    const secondReceipt = committed.evidence[1];
    assert.ok(firstReceipt);
    assert.ok(secondReceipt);
    assert.equal(firstReceipt.evidenceSha256, sha256Bytes(firstSnapshot));
    assert.equal(secondReceipt.evidenceSha256, sha256Bytes(secondSnapshot));
    assert.equal(firstReceipt.mediaType, "application/x-first-view");
    assert.equal(secondReceipt.mediaType, "application/x-second-view");
    assert.deepEqual(await readFile(evidencePath(run, firstReceipt.evidenceSha256)), Buffer.from(firstSnapshot));
    assert.deepEqual(await readFile(evidencePath(run, secondReceipt.evidenceSha256)), Buffer.from(secondSnapshot));

    const manifest = JSON.parse(await readFile(
      contentPath(run, "evidence-manifests", committed.transitionCommit.evidence_manifest_content_sha256),
      "utf8",
    )) as { readonly entries: readonly { readonly evidence_sha256: string; readonly metadata_content_sha256: string }[] };
    assert.deepEqual(
      new Set(manifest.entries.map((entry) => `${entry.evidence_sha256}:${entry.metadata_content_sha256}`)),
      new Set(committed.evidence.map((entry) => `${entry.evidenceSha256}:${entry.metadataContentSha256}`)),
    );

    storage.fill(119);
    evidence.splice(0, evidence.length);
    assert.deepEqual(await readFile(evidencePath(run, firstReceipt.evidenceSha256)), Buffer.from(firstSnapshot));
    assert.deepEqual(await readFile(evidencePath(run, secondReceipt.evidenceSha256)), Buffer.from(secondSnapshot));
    assert.equal((await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId })).status, "HEALTHY");
  });
});

test("evidence shape is validated synchronously before invalid layout inspection", async (t) => {
  const api = await builtPersistence();
  await withRun(async (run) => {
    await writeFile(join(run.stateRoot, "unexpected"), "unexpected", { mode: 0o600 });
    await chmod(join(run.stateRoot, "unexpected"), 0o600);
    const base = firstCommitInput(run);

    await t.test("null evidence array", async () => {
      const input = { ...base, evidence: null } as unknown as Parameters<PersistenceApi["commitTransition"]>[0];
      await assert.rejects(api.commitTransition(input), (error: unknown) => errorCode(error) === "INVALID_ARGUMENT");
    });
    await t.test("sparse evidence array", async () => {
      const sparse = new Array<{ readonly bytes: Uint8Array; readonly mediaType: string }>(1);
      await assert.rejects(
        api.commitTransition({ ...base, evidence: sparse }),
        (error: unknown) => errorCode(error) === "INVALID_ARGUMENT",
      );
    });
    await t.test("non-Uint8Array putEvidence bytes", async () => {
      const bytes = new DataView(new ArrayBuffer(4)) as unknown as Uint8Array;
      await assert.rejects(
        api.putEvidence({ stateRoot: run.stateRoot, runId: run.runId, bytes, mediaType: "application/octet-stream" }),
        (error: unknown) => errorCode(error) === "INVALID_ARGUMENT",
      );
    });
  });
});

test("owned state-root and runs-directory entries fail closed before every mutation kind", async (t) => {
  const api = await builtPersistence();
  for (const fixture of invalidLayoutCases) {
    await t.test(fixture.name, async () => {
      await withRun(async (run) => {
        await fixture.inject(run);
        const pointerBefore = await readFile(statePath(run));
        const revisionBefore = (JSON.parse(pointerBefore.toString("utf8")) as { readonly revision: number }).revision;
        const inventoryBefore = await filesystemInventory(run.stateRoot);

        const inspection = await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId });
        assert.notEqual(inspection.status, "HEALTHY");
        assert.equal(inspection.status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
        assert.equal(inspection.issues.length, 1);
        assert.equal(inspection.issues[0]?.code, fixture.expectedIssueCode);
        assert.equal(inspection.issues[0]?.relativePath, fixture.expectedRelativePath);
        assert.ok((inspection.issues[0]?.detail.length ?? 0) > 0);

        await assertBlockedMutation(api, run, fixture.mutation);
        const pointerAfter = await readFile(statePath(run));
        assert.deepEqual(pointerAfter, pointerBefore);
        assert.equal((JSON.parse(pointerAfter.toString("utf8")) as { readonly revision: number }).revision, revisionBefore);
        assert.deepEqual(await filesystemInventory(run.stateRoot), inventoryBefore);
        await lstat(join(run.stateRoot, fixture.expectedRelativePath));
      });
    });
  }
});

test("a valid private sibling run directory is allowed for inspection, transition, and initialization", async () => {
  const api = await builtPersistence();
  await withRun(async (run) => {
    const sibling = join(run.stateRoot, "runs", "valid-sibling");
    await mkdir(sibling, { mode: 0o700 });
    await chmod(sibling, 0o700);
    assert.equal((await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId })).status, "HEALTHY");
    const committed = await api.commitTransition(firstCommitInput(run));
    assert.equal(committed.statePointer.revision, 1);
    assert.equal((await lstat(sibling)).mode & 0o777, 0o700);

    const secondPolicy = makePolicy("SINGLE_OWNER_SOL");
    const secondInitialState = createInitialState(secondPolicy, stateIdentities(secondPolicy));
    const second = await api.initializeRunStorage({
      stateRoot: run.stateRoot,
      runId: secondPolicy.run_id,
      policy: secondPolicy,
      initialState: secondInitialState,
      processMetadata,
    });
    assert.equal(second.statePointer.revision, 0);
    assert.equal((await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: secondPolicy.run_id })).status, "HEALTHY");
    assert.equal((await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId })).status, "HEALTHY");
  });
});

type AssessmentBindingField =
  | "run_id"
  | "expected_revision"
  | "expected_state_pointer_content_sha256"
  | "expected_workflow_state_content_sha256";

interface CraftedAssessmentGraph {
  readonly assessment: ProcessInterruptionDocument;
  readonly commit: StateTransitionCommitDocument;
  readonly pointer: PersistedStatePointerDocument;
}

function withoutContentIdentity(document: object): Record<string, unknown> {
  const body = structuredClone(document) as Record<string, unknown>;
  delete body["content_sha256"];
  return body;
}

async function replaceAssessmentBinding(
  run: TestRun,
  terminal: CommittedRunState,
  field: AssessmentBindingField,
  value: string | number,
): Promise<CraftedAssessmentGraph> {
  const oldAssessmentDigest = terminal.transitionCommit.process_assessment_content_sha256;
  assert.ok(oldAssessmentDigest);
  const oldAssessmentPath = assessmentPath(run, oldAssessmentDigest);
  const oldCommitPath = commitPath(run, terminal.transitionCommit.content_sha256);
  const originalAssessment = JSON.parse(await readFile(oldAssessmentPath, "utf8")) as ProcessInterruptionDocument;

  const assessment = identifyContractDocument("pi_gacw_process_interruption_v0", {
    ...withoutContentIdentity(originalAssessment),
    [field]: value,
  }) as unknown as ProcessInterruptionDocument;
  assertDocumentValid("pi_gacw_process_interruption_v0", assessment);
  await writeCanonicalPrivateFile(assessmentPath(run, assessment.content_sha256), assessment);

  const commit = identifyContractDocument("pi_gacw_state_transition_commit_v0", {
    ...withoutContentIdentity(terminal.transitionCommit),
    process_assessment_content_sha256: assessment.content_sha256,
  }) as unknown as StateTransitionCommitDocument;
  assertDocumentValid("pi_gacw_state_transition_commit_v0", commit);
  await writeCanonicalPrivateFile(commitPath(run, commit.content_sha256), commit);

  const pointer = identifyContractDocument("pi_gacw_persisted_state_pointer_v0", {
    ...withoutContentIdentity(terminal.statePointer),
    transition_commit_content_sha256: commit.content_sha256,
  }) as unknown as PersistedStatePointerDocument;
  assertDocumentValid("pi_gacw_persisted_state_pointer_v0", pointer);
  await writeCanonicalPrivateFile(statePath(run), pointer);
  await unlink(oldAssessmentPath);
  await unlink(oldCommitPath);
  return { assessment, commit, pointer };
}

async function assertAssessmentGraphBlocked(
  api: PersistenceApi,
  run: TestRun,
  field: AssessmentBindingField,
  value: string | number,
  authority: CommittedRunState = run.committed,
): Promise<void> {
  const terminal = await api.terminalizeProcessCrash(terminalizeInput(run, authority, `crash-${field}`));
  const crafted = await replaceAssessmentBinding(run, terminal, field, value);
  assert.equal(crafted.pointer.transition_commit_content_sha256, crafted.commit.content_sha256);
  assert.equal(crafted.commit.process_assessment_content_sha256, crafted.assessment.content_sha256);
  const inspection = await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId });
  assert.equal(inspection.status, "BLOCKED_STATE_COMMIT_INCOMPLETE");
  assert.equal(inspection.issues[0]?.code, "PROCESS_ASSESSMENT_MISMATCH");
}

test("committed graph rejects each independently mismatched process-assessment authority field", async (t) => {
  const api = await builtPersistence();
  const fixtures: readonly { readonly name: string; readonly field: AssessmentBindingField; readonly value: string | number }[] = [
    { name: "run ID", field: "run_id", value: "different-valid-run" },
    { name: "expected revision", field: "expected_revision", value: 1 },
    { name: "state-pointer identity", field: "expected_state_pointer_content_sha256", value: digest(980) },
    { name: "workflow-state identity", field: "expected_workflow_state_content_sha256", value: digest(981) },
  ];
  for (const fixture of fixtures) {
    await t.test(fixture.name, async () => {
      await withRun((run) => assertAssessmentGraphBlocked(api, run, fixture.field, fixture.value));
    });
  }
});

test("historical graph walk rejects an assessment that disagrees with the immediately prior committed authority", async () => {
  const api = await builtPersistence();
  await withRun(async (run) => {
    const first = await api.commitTransition(firstCommitInput(run));
    assert.equal(first.statePointer.revision, 1);
    await assertAssessmentGraphBlocked(
      api,
      run,
      "expected_state_pointer_content_sha256",
      digest(982),
      first,
    );
  });
});

test("normally produced process-crash assessment binds exact prior authority and remains terminal", async () => {
  const api = await builtPersistence();
  await withRun(async (run) => {
    const terminal = await api.terminalizeProcessCrash(terminalizeInput(run));
    const assessmentDigest = terminal.transitionCommit.process_assessment_content_sha256;
    assert.ok(assessmentDigest);
    const assessment = JSON.parse(await readFile(assessmentPath(run, assessmentDigest), "utf8")) as ProcessInterruptionDocument;
    assert.equal(assessment.run_id, terminal.transitionCommit.run_id);
    assert.equal(assessment.expected_revision, terminal.transitionCommit.previous_revision);
    assert.equal(
      assessment.expected_state_pointer_content_sha256,
      terminal.transitionCommit.previous_state_pointer_content_sha256,
    );
    assert.equal(
      assessment.expected_workflow_state_content_sha256,
      terminal.transitionCommit.previous_workflow_state_content_sha256,
    );

    const inspection: RunStorageInspection = await api.inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId });
    assert.equal(inspection.status, "HEALTHY");
    assert.equal(inspection.workflowState?.phase, "BLOCKED");
    assert.equal(inspection.workflowState?.terminal_reason, "BLOCKED_PROCESS_CRASH");
    assert.ok(inspection.reachableObjects.some((object) =>
      object.kind === "PROCESS_ASSESSMENT" && object.contentSha256 === assessment.content_sha256));
    await assert.rejects(
      api.commitTransition({
        ...firstCommitInput(run),
        expectedRevision: terminal.statePointer.revision,
        expectedStatePointerContentSha256: terminal.statePointer.content_sha256 as Sha256Digest,
        expectedWorkflowStateContentSha256: terminal.workflowState.content_sha256 as Sha256Digest,
        transitionId: "after-normal-crash",
      }),
      (error: unknown) => errorCode(error) === "TERMINAL_STATE_IMMUTABLE",
    );
  });
});

test("new empty state root and new empty runs directory remain accepted initialization states", async (t) => {
  const api = await builtPersistence();
  for (const withRuns of [false, true]) {
    await t.test(withRuns ? "empty runs directory" : "empty state root", async () => {
      const stateRoot = await mkdtemp(join(tmpdir(), "pi-gacw-m2-r1-initialize-"));
      await chmod(stateRoot, 0o700);
      try {
        if (withRuns) {
          await mkdir(join(stateRoot, "runs"), { mode: 0o700 });
          await chmod(join(stateRoot, "runs"), 0o700);
        }
        const policy = makePolicy("DIRECT_LUNA_HIGH");
        const initialState = createInitialState(policy, stateIdentities(policy));
        const committed = await api.initializeRunStorage({
          stateRoot,
          runId: policy.run_id,
          policy,
          initialState,
          processMetadata,
        });
        assert.equal(committed.statePointer.revision, 0);
        assert.equal((await api.inspectRunStorage({ stateRoot, runId: policy.run_id })).status, "HEALTHY");
      } finally {
        await rm(stateRoot, { recursive: true, force: true });
      }
    });
  }
});
