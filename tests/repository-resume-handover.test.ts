import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runPostflight,
  runResumeLockHandover,
} from "../src/repository/index.js";
import { createScopedToolGateway } from "../src/scoped-tools/index.js";
import { assertEnvironmentFingerprintContinuity } from "../src/repository/environment.js";
import { loadAuthoritativeToken } from "../src/repository/token-provenance.js";
import { publishM3Record, readM3Records } from "../src/repository/storage.js";
import { lockAcquisitionAuthority } from "../src/repository/lock.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import type { M3BaselineApprovalRuntimeDocument, M3RepositoryStateTokenDocument } from "../src/schemas/index.js";
import { identifyContractDocument } from "../src/schemas/index.js";
import type { Sha256Digest } from "../src/identity/index.js";
import {
  createRepositoryFixture,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
} from "./repository-helpers.js";
import { baselineInput, pathDecision } from "./repository-matrix-helpers.js";
import { m4Limits } from "./m4-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? (error as { code: unknown }).code : undefined;
}

interface Admission {
  readonly fixture: Awaited<ReturnType<typeof createRepositoryFixture>>;
  readonly lockA: Awaited<ReturnType<typeof acquireWorktreeLock>>;
  readonly selected: Awaited<ReturnType<typeof instructionAuthorityInputs>>;
  readonly baseline: Awaited<ReturnType<typeof captureBaseline>>["baseline"];
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly editable: readonly string[];
  readonly frozen: readonly string[];
  readonly taskScopeIdentity: ReturnType<typeof scopeIdentity>;
  readonly environment: Awaited<ReturnType<typeof requiredEnvironment>>;
  readonly full: Awaited<ReturnType<typeof runFullPreflight>>;
}

async function admit(
  mode: "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY",
  prepare?: (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) => Promise<void>,
): Promise<Admission> {
  const fixture = await createRepositoryFixture();
  await prepare?.(fixture);
  const selected = await instructionAuthorityInputs(fixture);
  const editable = ["tracked.txt"];
  const frozen = ["AGENTS.md", "AUTHORITY.md"];
  const taskScopeIdentity = scopeIdentity(editable, frozen);
  let approval: M3BaselineApprovalRuntimeDocument | null = null;
  const decisions = mode === "CLEAN_REQUIRED"
    ? []
    : [pathDecision("tracked.txt")];
  const provisionalLockRepository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lockA = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository: provisionalLockRepository });
  try {
    const baseline = (await captureBaseline(await baselineInput(fixture, lockA, mode, decisions))).baseline;
    if (mode === "APPROVED_BASELINE_DIRTY") {
      approval = (await createBaselineApproval({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        baseline,
        approvedBy: "r2d0-owner",
        approvedAt: "2026-01-01T00:00:00.000Z",
      })).approval;
    }
    const environment = await requiredEnvironment(fixture.repository);
    const full = await runFullPreflight({
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
      lock: lockA,
    });
    return { fixture, lockA, selected, baseline, approval, editable, frozen, taskScopeIdentity, environment, full };
  } catch (error: unknown) {
    await releaseWorktreeLock(lockA).catch(() => undefined);
    await removeRepositoryFixture(fixture);
    throw error;
  }
}

/** Simulates controller death of process A: the flock is freed and a fresh owner acquires it. */
async function succeedOwner(admission: Admission): Promise<Awaited<ReturnType<typeof acquireWorktreeLock>>> {
  await releaseWorktreeLock(admission.lockA);
  return acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: admission.baseline.repository });
}

async function handoverInput(admission: Admission, acceptedState: M3RepositoryStateTokenDocument, lock: Awaited<ReturnType<typeof acquireWorktreeLock>>) {
  return {
    stateRoot: admission.fixture.stateRoot,
    runId: admission.fixture.runId,
    acceptedState,
    baseline: admission.baseline,
    instructionFiles: admission.selected.instructions,
    authorityFiles: admission.selected.authorities,
    taskScopeIdentity: admission.taskScopeIdentity,
    lock,
  };
}

function recordsDirectory(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, name: string): string {
  return join(fixture.stateRoot, "runs", fixture.runId, "records", name);
}

async function classificationOf(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  kind: string,
  digest: string,
): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest)?.classification;
}

async function m2Identities(fixture: Awaited<ReturnType<typeof createRepositoryFixture>>) {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return {
    revision: inspection.revision,
    workflowState: inspection.workflowState?.content_sha256 ?? null,
    statePointer: inspection.statePointer?.content_sha256 ?? null,
    transitionCommit: inspection.transitionCommit?.content_sha256 ?? null,
  };
}

test("R2D0 clean A->B handover admits ordinary M3/M4/M-postflight operations without weakened checks", async () => {
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    // H0: fresh acquisition B with no handover publication leaves T_A the unique durable tip.
    lockB = await succeedOwner(admission);
    const tokensAfterCrash = await readM3Records(
      { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId },
      "REPOSITORY_STATE_TOKEN",
    );
    assert.equal(tokensAfterCrash.length, 1);
    assert.equal(tokensAfterCrash[0]!.content_sha256, admission.full.acceptedState.content_sha256);

    // Existing checks stay intact: the old token cannot be used under lock B.
    await assert.rejects(runFastPreflight({
      stateRoot: admission.fixture.stateRoot,
      runId: admission.fixture.runId,
      acceptedState: admission.full.acceptedState,
      baseline: admission.baseline,
      instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities,
      taskScopeIdentity: admission.taskScopeIdentity,
      lock: lockB!,
    }), (error: unknown) => codeOf(error) === "LOCK_LOST");

    const m2Before = await m2Identities(admission.fixture);
    const headBefore = admission.full.acceptedState.head;

    const handover = await runResumeLockHandover(
      await handoverInput(admission, admission.full.acceptedState, lockB!),
    );
    assert.equal(handover.idempotentReuse, false);
    assert.equal(handover.source.schema_id, "pi_gacw_resume_lock_handover_v0");
    assert.equal(handover.source.prior_token_content_sha256, admission.full.acceptedState.content_sha256);
    assert.equal(handover.source.lock_diagnostic_content_sha256, lockB.diagnostics.content_sha256);
    const successor = handover.acceptedState;
    assert.equal(successor.source, "RESUME_LOCK_HANDOVER");
    assert.equal(successor.prior_token_content_sha256, admission.full.acceptedState.content_sha256);
    assert.equal(successor.workflow_owned_delta_sha256, admission.full.acceptedState.workflow_owned_delta_sha256);
    assert.deepEqual(successor.changed_paths, admission.full.acceptedState.changed_paths);
    assert.equal(successor.git_fingerprint.content_sha256, admission.full.acceptedState.git_fingerprint.content_sha256);

    // M2 unchanged by the M3 handover.
    const m2After = await m2Identities(admission.fixture);
    assert.deepEqual(m2After, m2Before);

    // Repository bytes unchanged.
    const { git } = await import("./repository-helpers.js");
    assert.equal(await git(admission.fixture.repository, "status", "--porcelain"), "");
    assert.equal((await resolveRepositoryIdentity({ requestedPath: admission.fixture.repository, requireHead: true })).head, headBefore);

    // T_B + B fast preflight passes with unchanged lock checks.
    const fast = await runFastPreflight({
      stateRoot: admission.fixture.stateRoot,
      runId: admission.fixture.runId,
      acceptedState: successor,
      baseline: admission.baseline,
      instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities,
      taskScopeIdentity: admission.taskScopeIdentity,
      lock: lockB!,
    });
    assert.equal(fast.preflight_kind, "FAST");

    // Authority projection: current lock acquisition is B; root preflight remains the original FULL_PREFLIGHT.
    const authority = await loadAuthoritativeToken(
      { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId },
      successor,
      admission.baseline,
    );
    assert.equal(authority.lockAcquisition.content_sha256, lockB.diagnostics.lock_acquisition_content_sha256);
    assert.equal(authority.rootPreflight.content_sha256, admission.full.preflight.content_sha256);
    assert.equal(authority.approval, null);

    // Classifications for a complete handover graph.
    assert.equal(await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", handover.source.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classificationOf(admission.fixture, "M3_REPOSITORY_STATE_TOKEN", successor.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");

    // Ordinary postflight under B yields a legal successor whose current
    // lock acquisition is B and whose root preflight is the original one.
    await writeFile(admission.fixture.trackedPath, "workflow change\n");
    const postflight = await runPostflight({
      stateRoot: admission.fixture.stateRoot,
      runId: admission.fixture.runId,
      acceptedState: successor,
      baseline: admission.baseline,
      instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities,
      editablePaths: [...admission.editable],
      frozenPaths: [...admission.frozen],
      taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"],
      lock: lockB!,
    });
    assert.equal(postflight.acceptedState.source, "POSTFLIGHT");
    const postAuthority = await loadAuthoritativeToken(
      { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId },
      postflight.acceptedState,
      admission.baseline,
    );
    assert.equal(postAuthority.lockAcquisition.content_sha256, lockB.diagnostics.lock_acquisition_content_sha256);
    assert.equal(postAuthority.rootPreflight.content_sha256, admission.full.preflight.content_sha256);
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 M4 scoped tool gateway admits a resumed handover successor without a relaxed resume branch", async () => {
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const handover = await runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!));
    const temporaryRoot = join(admission.fixture.root, "controller-tmp");
    await mkdir(temporaryRoot, { mode: 0o700 });
    // Provider-free M4 admission fixture: a scope-exact policy and catalog built
    // with the ordinary producer code paths (no relaxed resume branch exists).
    const policy = identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
      schema_id: "pi_gacw_scoped_tool_policy_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: admission.fixture.runId,
      policy_id: "r2d0-policy",
      repository_identity_content_sha256: admission.baseline.repository.content_sha256,
      worktree_key: admission.baseline.repository.worktree_key,
      task_scope_identity: admission.taskScopeIdentity,
      readable_paths: [{ path: "tracked.txt", kind: "EXACT" }],
      editable_paths: [{ path: "tracked.txt", kind: "EXACT" }],
      frozen_paths: [{ path: "AGENTS.md", kind: "EXACT" }, { path: "AUTHORITY.md", kind: "EXACT" }],
      command_readable_paths: [{ path: "tracked.txt", kind: "EXACT" }],
      command_writable_paths: [{ path: "tracked.txt", kind: "EXACT" }],
      path_authorities: [
        { path: "tracked.txt", kind: "EXACT", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: true, delete: true, mode_change: false },
        { path: "AGENTS.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
        { path: "AUTHORITY.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
      ],
      evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M4_TOOL_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"],
      limits: m4Limits,
    }) as never;
    const catalog = identifyContractDocument("pi_gacw_command_catalog_v0", {
      schema_id: "pi_gacw_command_catalog_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: admission.fixture.runId,
      catalog_id: "r2d0-catalog",
      repository_identity_content_sha256: admission.baseline.repository.content_sha256,
      tool_policy_content_sha256: (policy as { content_sha256: string }).content_sha256,
      commands: [],
    }) as never;
    const gateway = await createScopedToolGateway({
      stateRoot: admission.fixture.stateRoot,
      runId: admission.fixture.runId,
      repository: admission.baseline.repository,
      baseline: admission.baseline,
      acceptedState: handover.acceptedState,
      lock: lockB!,
      instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities,
      editablePaths: [...admission.editable],
      frozenPaths: [...admission.frozen],
      taskScopeIdentity: admission.taskScopeIdentity,
      toolPolicy: policy,
      commandCatalog: catalog,
      temporaryRoot,
    });
    assert.equal(gateway.acceptedState.content_sha256, handover.acceptedState.content_sha256);
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 approved dirty baseline inherits exact baseline and approval identities", async () => {
  const admission = await admit("APPROVED_BASELINE_DIRTY", async (fixture) => {
    await writeFile(fixture.trackedPath, "pre-approved dirty content\n");
  });
  assert.notEqual(admission.approval, null);
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const handover = await runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!));
    const authority = await loadAuthoritativeToken(
      { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId },
      handover.acceptedState,
      admission.baseline,
    );
    assert.equal(authority.approval?.content_sha256, admission.approval!.content_sha256);
    assert.equal(authority.token.workflow_owned_delta_sha256, admission.full.acceptedState.workflow_owned_delta_sha256);
    assert.deepEqual(authority.token.changed_paths, admission.full.acceptedState.changed_paths);
    assert.equal(authority.chainDepth, 1);
    assert.equal(authority.baseline.baseline_mode, "APPROVED_BASELINE_DIRTY");
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 refuses stale, drifted, wrong-worktree, and same-generation handovers", async (t) => {
  await t.test("repository drift refusal before any authority transition", async () => {
    const admission = await admit("CLEAN_REQUIRED");
    let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
    try {
      lockB = await succeedOwner(admission);
      await writeFile(admission.fixture.trackedPath, "external drift\n");
      await assert.rejects(runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!)),
        (error: unknown) => codeOf(error) === "BLOCKED_STATE_DRIFT");
    } finally {
      await releaseWorktreeLock(lockB!).catch(() => undefined);
      await removeRepositoryFixture(admission.fixture);
    }
  });

  await t.test("instruction drift refusal", async () => {
    const admission = await admit("CLEAN_REQUIRED");
    let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
    try {
      lockB = await succeedOwner(admission);
      await writeFile(admission.fixture.instructionPath, "changed instructions\n");
      await assert.rejects(runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!)),
        (error: unknown) => codeOf(error) === "INSTRUCTION_DRIFT");
    } finally {
      await releaseWorktreeLock(lockB!).catch(() => undefined);
      await removeRepositoryFixture(admission.fixture);
    }
  });

  await t.test("authority-file drift refusal", async () => {
    const admission = await admit("CLEAN_REQUIRED");
    let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
    try {
      lockB = await succeedOwner(admission);
      await writeFile(admission.fixture.authorityPath, "changed authority\n");
      await assert.rejects(runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!)),
        (error: unknown) => codeOf(error) === "AUTHORITY_DRIFT");
    } finally {
      await releaseWorktreeLock(lockB!).catch(() => undefined);
      await removeRepositoryFixture(admission.fixture);
    }
  });

  await t.test("wrong-worktree lock refusal", async () => {
    const admission = await admit("CLEAN_REQUIRED");
    const other = await createRepositoryFixture();
    let foreignLock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
    try {
      const otherRepository = await resolveRepositoryIdentity({ requestedPath: other.repository, requireHead: true });
      foreignLock = await acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: otherRepository });
      await assert.rejects(runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, foreignLock!)),
        (error: unknown) => codeOf(error) === "LOCK_LOST");
    } finally {
      await releaseWorktreeLock(admission.lockA).catch(() => undefined);
      await releaseWorktreeLock(foreignLock!).catch(() => undefined);
      await removeRepositoryFixture(admission.fixture);
      await removeRepositoryFixture(other);
    }
  });

  await t.test("same-generation handover refusal (no B -> B)", async () => {
    const admission = await admit("CLEAN_REQUIRED");
    try {
      await assert.rejects(runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, admission.lockA)),
        (error: unknown) => codeOf(error) === "STATE_TOKEN_PROVENANCE_INVALID");
    } finally {
      await releaseWorktreeLock(admission.lockA).catch(() => undefined);
      await removeRepositoryFixture(admission.fixture);
    }
  });

  await t.test("stale capability refused once durable authority advanced past T_A", async () => {
    const admission = await admit("CLEAN_REQUIRED");
    let lockA = admission.lockA;
    let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
    try {
      // Advance durable authority with an ordinary postflight under the original lock.
      await writeFile(admission.fixture.trackedPath, "settled mutation\n");
      const postflight = await runPostflight({
        stateRoot: admission.fixture.stateRoot,
        runId: admission.fixture.runId,
        acceptedState: admission.full.acceptedState,
        baseline: admission.baseline,
        instructionFiles: admission.selected.instructions,
        authorityFiles: admission.selected.authorities,
        editablePaths: [...admission.editable],
        frozenPaths: [...admission.frozen],
        taskScopeIdentity: admission.taskScopeIdentity,
        claimedWorkflowPaths: ["tracked.txt"],
        lock: lockA,
      });
      await releaseWorktreeLock(lockA);
      lockA = undefined as never;
      lockB = await acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: admission.baseline.repository });
      await assert.rejects(runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!)),
        (error: unknown) => codeOf(error) === "STATE_TOKEN_PROVENANCE_INVALID");
      // The exact current tip is accepted instead.
      const handover = await runResumeLockHandover({
        ...await handoverInput(admission, postflight.acceptedState, lockB!),
      });
      assert.equal(handover.acceptedState.prior_token_content_sha256, postflight.acceptedState.content_sha256);
    } finally {
      if (lockA !== undefined) await releaseWorktreeLock(lockA).catch(() => undefined);
      await releaseWorktreeLock(lockB!).catch(() => undefined);
      await removeRepositoryFixture(admission.fixture);
    }
  });
});

test("R2D0 environment continuity refuses deterministic Node/Git/Python/helper drift seams", async (t) => {
  const admission = await admit("CLEAN_REQUIRED");
  try {
    const rootEnv = admission.full.preflight.environment_fingerprint;
    const repository = admission.baseline.repository;
    const diagnostic = admission.lockA.diagnostics;
    await assertEnvironmentFingerprintContinuity(rootEnv, repository, diagnostic);
    // Live-side seams: node/git facts are recomputed from the live process and
    // repository, so deterministic drift is simulated on the frozen expected
    // fingerprint. Any inequality must refuse.
    const expectedMutations: Array<[string, Record<string, unknown>]> = [
      ["node_version", { node_version: "v0.0.0-test" }],
      ["git_version", { git_version: "git version 0.0.0" }],
      ["python_version", { python_version: "Python 0.0.0" }],
      ["node_path", { node_path: "/nonexistent/node" }],
      ["git_path", { git_path: "/nonexistent/git" }],
      ["python_path", { python_path: "/nonexistent/python" }],
      ["guardian_helper_path", { guardian_helper_path: "/nonexistent/helper.py" }],
      ["guardian_helper_sha256", { guardian_helper_sha256: "sha256:" + "0".repeat(64) }],
      ["controller_version", { controller_version: "9.9.9" }],
    ];
    for (const [name, patch] of expectedMutations) {
      await t.test(`frozen ${name} drift refusal`, async () => {
        const drifted = { ...rootEnv, ...patch } as typeof rootEnv;
        await assert.rejects(assertEnvironmentFingerprintContinuity(drifted, repository, diagnostic),
          (error: unknown) => codeOf(error) === "ENVIRONMENT_DRIFT");
      });
    }
    // Generation-side seams: the fresh acquisition's diagnostic carries the
    // Python/guardian facts, so a changed helper or interpreter under B drifts.
    const diagnosticMutations: Array<[string, Record<string, unknown>]> = [
      ["python_version", { guardian_python_version: "Python 0.0.0" }],
      ["python_path", { python_path: "/nonexistent/python", guardian_python_realpath: "/nonexistent/python", guardian_python_path: "/nonexistent/python", guardian_python_invocation_path: "/nonexistent/python" }],
      ["guardian_helper_sha256", { guardian_helper_sha256: "sha256:" + "0".repeat(64) }],
    ];
    for (const [name, patch] of diagnosticMutations) {
      await t.test(`acquisition ${name} drift refusal`, async () => {
        const forged = { ...diagnostic, ...patch } as typeof diagnostic;
        await assert.rejects(assertEnvironmentFingerprintContinuity(rootEnv, repository, forged),
          (error: unknown) => codeOf(error) === "ENVIRONMENT_DRIFT");
      });
    }
  } finally {
    await releaseWorktreeLock(admission.lockA).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 H1 orphan source stays resumable, classifies UNREFERENCED, and same-B retry completes byte-identically", async () => {
  const { identifyContractDocument } = await import("../src/schemas/index.js");
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const predecessor = admission.full.acceptedState;
    const diagnosticB = lockB.diagnostics;
    // Producer-level crash simulation: source persisted, token absent.
    const orphanSource = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
      schema_id: "pi_gacw_resume_lock_handover_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: admission.fixture.runId,
      prior_token_content_sha256: predecessor.content_sha256,
      repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
      git_fingerprint_sha256: predecessor.git_fingerprint.content_sha256,
      instruction_fingerprint_sha256: predecessor.instruction_fingerprint.content_sha256,
      authority_fingerprint_sha256: predecessor.authority_fingerprint.content_sha256,
      lock_diagnostic_content_sha256: diagnosticB.content_sha256,
    });
    const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
    await publishM3Record(location, "LOCK_ACQUISITION", lockAcquisitionAuthority(lockB) as never);
    await publishM3Record(location, "LOCK_DIAGNOSTIC", diagnosticB as never);
    await publishM3Record(location, "RESUME_LOCK_HANDOVER", orphanSource as never);
    assert.equal(orphanSource.schema_id, "pi_gacw_resume_lock_handover_v0");
    assert.equal(await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", (orphanSource as { content_sha256: string }).content_sha256), "UNREFERENCED_MANAGED_RECORD");
    const tokensBefore = (await readM3Records(location, "REPOSITORY_STATE_TOKEN")).length;

    const completed = await runResumeLockHandover(await handoverInput(admission, predecessor, lockB!));
    assert.equal(completed.idempotentReuse, false);
    assert.equal(completed.source.content_sha256, (orphanSource as { content_sha256: string }).content_sha256);
    assert.equal(await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", completed.source.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const tokensAfter = await readM3Records(location, "REPOSITORY_STATE_TOKEN");
    assert.equal(tokensAfter.length, tokensBefore + 1);
    assert.ok(tokensAfter.some((token) => token.content_sha256 === completed.acceptedState.content_sha256));
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 H1 later owner C never adopts B's orphan source and publishes its own", async () => {
  const { identifyContractDocument } = await import("../src/schemas/index.js");
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  let lockC: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const predecessor = admission.full.acceptedState;
    const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
    const bOrphan = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
      schema_id: "pi_gacw_resume_lock_handover_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: admission.fixture.runId,
      prior_token_content_sha256: predecessor.content_sha256,
      repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
      git_fingerprint_sha256: predecessor.git_fingerprint.content_sha256,
      instruction_fingerprint_sha256: predecessor.instruction_fingerprint.content_sha256,
      authority_fingerprint_sha256: predecessor.authority_fingerprint.content_sha256,
      lock_diagnostic_content_sha256: lockB.diagnostics.content_sha256,
    });
    await publishM3Record(location, "LOCK_ACQUISITION", lockAcquisitionAuthority(lockB) as never);
    await publishM3Record(location, "LOCK_DIAGNOSTIC", lockB.diagnostics as never);
    await publishM3Record(location, "RESUME_LOCK_HANDOVER", bOrphan as never);
    const bOrphanDigest = (bOrphan as { content_sha256: string }).content_sha256;

    // B dies; C acquires and legally hands over from the exact durable tip T_A.
    await releaseWorktreeLock(lockB);
    lockB = undefined as never;
    lockC = await acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: admission.baseline.repository });
    const cHandover = await runResumeLockHandover(await handoverInput(admission, predecessor, lockC));
    assert.notEqual(cHandover.source.content_sha256, bOrphanDigest);
    assert.equal(cHandover.source.lock_diagnostic_content_sha256, lockC.diagnostics.content_sha256);
    assert.equal(await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", bOrphanDigest), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", cHandover.source.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await releaseWorktreeLock(lockC!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 H2 lost-response retry reuses the exact published handover idempotently", async () => {
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const first = await runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!));
    const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
    const tokensBefore = (await readM3Records(location, "REPOSITORY_STATE_TOKEN")).length;
    const sourcesBefore = (await readM3Records(location, "RESUME_LOCK_HANDOVER")).length;
    const second = await runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!));
    assert.equal(second.idempotentReuse, true);
    assert.equal(second.acceptedState.content_sha256, first.acceptedState.content_sha256);
    assert.equal(second.source.content_sha256, first.source.content_sha256);
    assert.equal((await readM3Records(location, "REPOSITORY_STATE_TOKEN")).length, tokensBefore);
    assert.equal((await readM3Records(location, "RESUME_LOCK_HANDOVER")).length, sourcesBefore);
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 H3/H4 repeated generations preserve the original root preflight, current lock authority, and bounded depth", async () => {
  const admission = await admit("CLEAN_REQUIRED");
  const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
  let held: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined = admission.lockA;
  try {
    const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
    let tip = admission.full.acceptedState;
    let previousDiagnostic = admission.full.preflight.lock_diagnostic_content_sha256;
    let expectedDepth = 0;
    for (const owner of ["B", "C", "D"]) {
      void owner;
      await releaseWorktreeLock(held);
      held = await acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: admission.baseline.repository });
      const handover = await runResumeLockHandover(await handoverInput(admission, tip, held));
      const authority = await loadAuthoritativeToken(location, handover.acceptedState, admission.baseline);
      expectedDepth += 1;
      assert.equal(handover.acceptedState.source, "RESUME_LOCK_HANDOVER");
      assert.notEqual(handover.acceptedState.lock_diagnostic_content_sha256, previousDiagnostic);
      assert.equal(authority.lockAcquisition.content_sha256, held.diagnostics.lock_acquisition_content_sha256);
      assert.equal(authority.rootPreflight.content_sha256, admission.full.preflight.content_sha256);
      assert.equal(authority.chainDepth, expectedDepth);
      tip = handover.acceptedState;
      previousDiagnostic = tip.lock_diagnostic_content_sha256;
    }
    const finalAuthority = await loadAuthoritativeToken(location, tip, admission.baseline);
    assert.equal(finalAuthority.chainDepth, 3);
  } finally {
    await releaseWorktreeLock(held).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 fork ambiguity keeps per-record validity but refuses current authoritative-tip resolution", async () => {
  const { identifyContractDocument } = await import("../src/schemas/index.js");
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  let lockC: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const predecessor = admission.full.acceptedState;
    const real = await runResumeLockHandover(await handoverInput(admission, predecessor, lockB!));

    // Synthetic conflicting successor: a second handover from T_A bound to a
    // different held generation, published directly as producer-level evidence.
    await releaseWorktreeLock(lockB);
    lockB = undefined as never;
    lockC = await acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: admission.baseline.repository });
    const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
    const forgedSource = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
      schema_id: "pi_gacw_resume_lock_handover_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: admission.fixture.runId,
      prior_token_content_sha256: predecessor.content_sha256,
      repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
      git_fingerprint_sha256: predecessor.git_fingerprint.content_sha256,
      instruction_fingerprint_sha256: predecessor.instruction_fingerprint.content_sha256,
      authority_fingerprint_sha256: predecessor.authority_fingerprint.content_sha256,
      lock_diagnostic_content_sha256: lockC.diagnostics.content_sha256,
    });
    const forgedToken = identifyContractDocument("pi_gacw_repository_state_token_v0", {
      schema_id: "pi_gacw_repository_state_token_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      source: "RESUME_LOCK_HANDOVER",
      source_content_sha256: (forgedSource as { content_sha256: string }).content_sha256,
      prior_token_content_sha256: predecessor.content_sha256,
      run_id: predecessor.run_id,
      repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
      worktree_key: predecessor.worktree_key,
      branch: predecessor.branch,
      head: predecessor.head,
      worktree_list_sha256: predecessor.worktree_list_sha256,
      git_fingerprint: predecessor.git_fingerprint,
      instruction_fingerprint: predecessor.instruction_fingerprint,
      authority_fingerprint: predecessor.authority_fingerprint,
      baseline_runtime_content_sha256: predecessor.baseline_runtime_content_sha256,
      lock_diagnostic_content_sha256: lockC.diagnostics.content_sha256,
      task_scope_identity: predecessor.task_scope_identity,
      workflow_owned_delta_sha256: predecessor.workflow_owned_delta_sha256,
      changed_paths: [...predecessor.changed_paths],
    });
    await publishM3Record(location, "LOCK_ACQUISITION", lockAcquisitionAuthority(lockC) as never);
    await publishM3Record(location, "LOCK_DIAGNOSTIC", lockC.diagnostics as never);
    await publishM3Record(location, "RESUME_LOCK_HANDOVER", forgedSource as never);
    await publishM3Record(location, "REPOSITORY_STATE_TOKEN", forgedToken as never);

    // Per-token semantic validity may remain historical...
    assert.equal(await classificationOf(admission.fixture, "M3_REPOSITORY_STATE_TOKEN", real.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classificationOf(admission.fixture, "M3_REPOSITORY_STATE_TOKEN", (forgedToken as { content_sha256: string }).content_sha256), "AUTHORITATIVE_MANAGED_RECORD");

    // ...but current authoritative-tip resolution becomes ambiguous and resume refuses.
    await assert.rejects(runResumeLockHandover(await handoverInput(admission, predecessor, lockC)),
      (error: unknown) => codeOf(error) === "STATE_TOKEN_PROVENANCE_INVALID");
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await releaseWorktreeLock(lockC!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 incomplete and malformed handover sources classify INCOMPLETE or INVALID without breaking resumability", async () => {
  const { identifyContractDocument } = await import("../src/schemas/index.js");
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const predecessor = admission.full.acceptedState;
    const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
    await publishM3Record(location, "LOCK_ACQUISITION", lockAcquisitionAuthority(lockB) as never);
    await publishM3Record(location, "LOCK_DIAGNOSTIC", lockB.diagnostics as never);
    const base = {
      schema_id: "pi_gacw_resume_lock_handover_v0",
      schema_version: "0.1.0",
      content_projection_id: "document-content-v1",
      run_id: admission.fixture.runId,
      prior_token_content_sha256: predecessor.content_sha256,
      repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
      git_fingerprint_sha256: predecessor.git_fingerprint.content_sha256,
      instruction_fingerprint_sha256: predecessor.instruction_fingerprint.content_sha256,
      authority_fingerprint_sha256: predecessor.authority_fingerprint.content_sha256,
      lock_diagnostic_content_sha256: lockB.diagnostics.content_sha256,
    };

    // C. source missing predecessor -> INCOMPLETE_MANAGED_RECORD_CHAIN.
    const missingPredecessor = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
      ...base,
      prior_token_content_sha256: "sha256:" + "a".repeat(64),
    });
    await publishM3Record(location, "RESUME_LOCK_HANDOVER", missingPredecessor as never);
    assert.equal(
      await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", (missingPredecessor as { content_sha256: string }).content_sha256),
      "INCOMPLETE_MANAGED_RECORD_CHAIN",
    );

    // D. source missing diagnostic/acquisition producer -> INCOMPLETE_MANAGED_RECORD_CHAIN.
    const missingDiagnostic = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
      ...base,
      lock_diagnostic_content_sha256: "sha256:" + "b".repeat(64),
    });
    await publishM3Record(location, "RESUME_LOCK_HANDOVER", missingDiagnostic as never);
    assert.equal(
      await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", (missingDiagnostic as { content_sha256: string }).content_sha256),
      "INCOMPLETE_MANAGED_RECORD_CHAIN",
    );

    // E. malformed/mismatched source (wrong Git fingerprint binding) -> INVALID_MANAGED_RECORD.
    const mismatched = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
      ...base,
      git_fingerprint_sha256: "sha256:" + "c".repeat(64),
    });
    await publishM3Record(location, "RESUME_LOCK_HANDOVER", mismatched as never);
    assert.equal(
      await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", (mismatched as { content_sha256: string }).content_sha256),
      "INVALID_MANAGED_RECORD",
    );
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 historical handover remains semantically valid provenance after later settled successors", async () => {
  const admission = await admit("CLEAN_REQUIRED");
  let lockB: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    lockB = await succeedOwner(admission);
    const handover = await runResumeLockHandover(await handoverInput(admission, admission.full.acceptedState, lockB!));
    await writeFile(admission.fixture.trackedPath, "later mutation\n");
    const postflight = await runPostflight({
      stateRoot: admission.fixture.stateRoot,
      runId: admission.fixture.runId,
      acceptedState: handover.acceptedState,
      baseline: admission.baseline,
      instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities,
      editablePaths: [...admission.editable],
      frozenPaths: [...admission.frozen],
      taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"],
      lock: lockB!,
    });
    // The handover source and its successor token remain authoritative history
    // even though the durable tip has advanced to the postflight successor.
    assert.equal(await classificationOf(admission.fixture, "M3_RESUME_LOCK_HANDOVER", handover.source.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classificationOf(admission.fixture, "M3_REPOSITORY_STATE_TOKEN", handover.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(postflight.acceptedState.source, "POSTFLIGHT");
  } finally {
    await releaseWorktreeLock(lockB!).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});

test("R2D0 depth 62 permits the R2D-safe handover and depth 63 refuses it", async () => {
  const admission = await admit("CLEAN_REQUIRED");
  const location = { stateRoot: admission.fixture.stateRoot, runId: admission.fixture.runId };
  let held: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined = admission.lockA;
  try {
    // Build a settled chain of exactly 62 postflight successors.
    let tip = admission.full.acceptedState;
    for (let index = 0; index < 62; index += 1) {
      await writeFile(admission.fixture.trackedPath, `mutation ${index}\n`);
      const postflight = await runPostflight({
        stateRoot: admission.fixture.stateRoot,
        runId: admission.fixture.runId,
        acceptedState: tip,
        baseline: admission.baseline,
        instructionFiles: admission.selected.instructions,
        authorityFiles: admission.selected.authorities,
        editablePaths: [...admission.editable],
        frozenPaths: [...admission.frozen],
        taskScopeIdentity: admission.taskScopeIdentity,
        claimedWorkflowPaths: ["tracked.txt"],
        lock: held!,
      });
      tip = postflight.acceptedState;
    }
    const depth62Authority = await loadAuthoritativeToken(location, tip, admission.baseline);
    assert.equal(depth62Authority.chainDepth, 62);

    // Depth 62 permits the handover (reserving one slot for the worker mutation).
    await releaseWorktreeLock(held);
    const next = await acquireWorktreeLock({ stateRoot: admission.fixture.stateRoot, repository: admission.baseline.repository });
    held = next;
    const handover = await runResumeLockHandover(await handoverInput(admission, tip, next));
    const handoverAuthority = await loadAuthoritativeToken(location, handover.acceptedState, admission.baseline);
    assert.equal(handoverAuthority.chainDepth, 63);

    // Prior depth 63 refuses any further handover: no postflight capacity would remain.
    await assert.rejects(runResumeLockHandover(await handoverInput(admission, handover.acceptedState, next)),
      (error: unknown) => codeOf(error) === "STATE_TOKEN_CHAIN_TOO_DEEP");
    // Yet the ordinary single postflight advance stays legal within MAX_TOKEN_CHAIN_DEPTH = 64,
    // proving the R2D-safe reservation of the worker mutation slot.
    await writeFile(admission.fixture.trackedPath, "final mutation\n");
    const postflight = await runPostflight({
      stateRoot: admission.fixture.stateRoot,
      runId: admission.fixture.runId,
      acceptedState: handover.acceptedState,
      baseline: admission.baseline,
      instructionFiles: admission.selected.instructions,
      authorityFiles: admission.selected.authorities,
      editablePaths: [...admission.editable],
      frozenPaths: [...admission.frozen],
      taskScopeIdentity: admission.taskScopeIdentity,
      claimedWorkflowPaths: ["tracked.txt"],
      lock: held,
    });
    assert.equal(postflight.acceptedState.source, "POSTFLIGHT");
  } finally {
    await releaseWorktreeLock(held).catch(() => undefined);
    await removeRepositoryFixture(admission.fixture);
  }
});
