import assert from "node:assert/strict";
import { chmod, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import {
  acquireWorktreeLock,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
} from "../src/repository/index.js";
import {
  lockAcquisitionGlobalPath,
} from "../src/repository/acquisition.js";
import { lockAcquisitionAuthority } from "../src/repository/lock.js";
import { canonicalJsonRecordBytes, publishM3Record } from "../src/repository/storage.js";
import {
  identifyContractDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3PreflightDocument,
  type M3RepositoryStateTokenDocument,
} from "../src/schemas/index.js";
import {
  createRepositoryFixture,
  removeRepositoryFixture,
  type RepositoryFixture,
} from "./repository-helpers.js";
import {
  createCleanAdmission,
  releaseAdmission,
} from "./repository-matrix-helpers.js";

type CleanAdmission = Awaited<ReturnType<typeof createCleanAdmission>>;

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { readonly code: unknown }).code
    : undefined;
}

async function persist(
  fixture: RepositoryFixture,
  directory: string,
  document: { readonly content_sha256: string },
): Promise<void> {
  const path = join(
    fixture.stateRoot,
    "runs",
    fixture.runId,
    "records",
    directory,
    `${document.content_sha256.slice("sha256:".length)}.json`,
  );
  await writeFile(path, canonicalJsonRecordBytes(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function classification(fixture: RepositoryFixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

function diagnosticForAcquisition(
  source: M3LockDiagnosticDocument,
  acquisition: M3LockAcquisitionDocument,
): M3LockDiagnosticDocument {
  const draft = structuredClone(source) as unknown as Record<string, unknown>;
  Object.assign(draft, {
    lock_acquisition_content_sha256: acquisition.content_sha256,
    state_root: acquisition.state_root,
    protocol_version: acquisition.protocol_version,
    worktree_key: acquisition.worktree_key,
    worktree_root: acquisition.worktree_root,
    git_common_dir: acquisition.git_common_dir,
    lock_path: acquisition.lock_path,
    owner_marker_path: acquisition.owner_marker_path,
    guardian_python_invocation_path: acquisition.guardian_python_invocation_path,
    guardian_python_realpath: acquisition.guardian_python_realpath,
    guardian_python_path: acquisition.guardian_python_realpath,
    guardian_python_version: acquisition.guardian_python_version,
    guardian_helper_path: acquisition.guardian_helper_path,
    guardian_helper_realpath: acquisition.guardian_helper_realpath,
    guardian_helper_sha256: acquisition.guardian_helper_sha256,
    controller_pid: acquisition.controller_pid,
    guardian_pid: acquisition.guardian_pid,
    acquired_at: acquisition.acquired_at,
    acquisition_nonce: acquisition.acquisition_nonce,
    guardian_ready_sha256: acquisition.guardian_ready_sha256,
  });
  return identifyContractDocument("pi_gacw_lock_diagnostic_v0", draft) as unknown as M3LockDiagnosticDocument;
}

function sourceTokenForDiagnostic(
  admission: CleanAdmission,
  diagnostic: M3LockDiagnosticDocument,
): { readonly source: M3PreflightDocument; readonly token: M3RepositoryStateTokenDocument } {
  const sourceDraft = structuredClone(admission.full.preflight) as unknown as Record<string, unknown>;
  sourceDraft["lock_diagnostic_content_sha256"] = diagnostic.content_sha256;
  const environment = sourceDraft["environment_fingerprint"] as Record<string, unknown>;
  environment["python_path"] = diagnostic.guardian_python_path;
  environment["python_version"] = diagnostic.guardian_python_version;
  environment["guardian_helper_path"] = diagnostic.guardian_helper_path;
  environment["guardian_helper_sha256"] = diagnostic.guardian_helper_sha256;
  const { content_sha256: _prior, ...projection } = environment;
  environment["content_sha256"] = sha256Canonical(projection);
  const source = identifyContractDocument("pi_gacw_preflight_v0", sourceDraft) as unknown as M3PreflightDocument;
  const tokenDraft = structuredClone(admission.full.acceptedState) as unknown as Record<string, unknown>;
  tokenDraft["source_content_sha256"] = source.content_sha256;
  tokenDraft["lock_diagnostic_content_sha256"] = diagnostic.content_sha256;
  const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft) as unknown as M3RepositoryStateTokenDocument;
  return { source, token };
}

async function persistGraph(
  fixture: RepositoryFixture,
  acquisition: M3LockAcquisitionDocument | null,
  diagnostic: M3LockDiagnosticDocument,
  source: M3PreflightDocument,
  token: M3RepositoryStateTokenDocument,
): Promise<void> {
  if (acquisition !== null) await persist(fixture, "lock-acquisitions", acquisition);
  await persist(fixture, "lock-diagnostics", diagnostic);
  await persist(fixture, "preflights", source);
  await persist(fixture, "repository-state-tokens", token);
}

async function assertFastDoesNotPass(
  fixture: RepositoryFixture,
  admission: CleanAdmission,
  token: M3RepositoryStateTokenDocument,
): Promise<void> {
  await assert.rejects(runFastPreflight({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    acceptedState: token,
    baseline: admission.baseline,
    instructionFiles: admission.selected.instructions,
    authorityFiles: admission.selected.authorities,
    taskScopeIdentity: admission.taskScopeIdentity,
    lock: admission.lock,
  }));
}

test("R5-R1 lock acquisition is a non-circular producer root", async () => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const acquisition = lockAcquisitionAuthority(lock);
    assert.equal(Object.isFrozen(acquisition), true);
    assert.equal(acquisition.content_sha256, lock.diagnostics.lock_acquisition_content_sha256);
    assert.equal(acquisition.guardian_python_realpath, lock.diagnostics.guardian_python_path);
    assert.equal(acquisition.guardian_ready_sha256, sha256Canonical({
      protocol_version: acquisition.protocol_version,
      guardian_pid: acquisition.guardian_pid,
      acquisition_nonce: acquisition.acquisition_nonce,
    }));
    await publishM3Record(
      { stateRoot: fixture.stateRoot, runId: fixture.runId },
      "LOCK_ACQUISITION",
      acquisition as unknown as Record<string, unknown>,
    );
    assert.equal(await classification(fixture, acquisition.content_sha256), "UNREFERENCED_MANAGED_RECORD");
  } finally {
    await releaseWorktreeLock(lock).catch(() => undefined);
    await removeRepositoryFixture(fixture);
  }
});

test("R5-R1 coherent diagnostic acquisition-field forgeries cannot bootstrap authority", async (t) => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    const acquisition = lockAcquisitionAuthority(admission.lock);
    const mutations: readonly [string, (draft: Record<string, unknown>) => void][] = [
      ["helper digest", (draft) => { draft["guardian_helper_sha256"] = `sha256:${"a".repeat(64)}`; }],
      ["helper path", (draft) => { draft["guardian_helper_path"] = "/forged/helper.py"; }],
      ["helper realpath", (draft) => { draft["guardian_helper_realpath"] = "/forged/helper.py"; }],
      ["Python invocation path", (draft) => { draft["guardian_python_invocation_path"] = "/forged/python3"; }],
      ["Python realpath", (draft) => { draft["guardian_python_realpath"] = "/forged/python3"; draft["guardian_python_path"] = "/forged/python3"; }],
      ["Python version", (draft) => { draft["guardian_python_version"] = "Python 0.0-forged"; }],
      ["guardian PID", (draft) => { draft["guardian_pid"] = Number(draft["guardian_pid"]) + 1; }],
      ["controller PID", (draft) => { draft["controller_pid"] = Number(draft["controller_pid"]) + 1; }],
      ["worktree key", (draft) => { draft["worktree_key"] = `sha256:${"b".repeat(64)}`; }],
      ["lock path", (draft) => { draft["lock_path"] = "/forged/worktree.lock"; }],
      ["acquisition identity", (draft) => { draft["acquisition_nonce"] = "c".repeat(32); }],
    ];
    for (const [name, mutate] of mutations) {
      await t.test(name, async () => {
        const draft = structuredClone(admission.lock.diagnostics) as unknown as Record<string, unknown>;
        mutate(draft);
        const diagnostic = identifyContractDocument("pi_gacw_lock_diagnostic_v0", draft) as unknown as M3LockDiagnosticDocument;
        const { source, token } = sourceTokenForDiagnostic(admission, diagnostic);
        await persistGraph(fixture, null, diagnostic, source, token);
        assert.equal(await classification(fixture, diagnostic.content_sha256), "INVALID_MANAGED_RECORD");
        assert.equal(await classification(fixture, source.content_sha256), "INVALID_MANAGED_RECORD");
        assert.equal(await classification(fixture, token.content_sha256), "INVALID_MANAGED_RECORD");
        await assertFastDoesNotPass(fixture, admission, token);
      });
    }
    const protocolDraft = structuredClone(admission.lock.diagnostics) as unknown as Record<string, unknown>;
    protocolDraft["protocol_version"] = "forged-protocol";
    assert.throws(() => identifyContractDocument("pi_gacw_lock_diagnostic_v0", protocolDraft));
    assert.equal(await classification(fixture, acquisition.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
  }
});

test("R5-R1 altered acquisition roots are invalid or incomplete and cannot advance", async (t) => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture);
  try {
    const valid = lockAcquisitionAuthority(admission.lock);
    const mutations: readonly [string, (draft: Record<string, unknown>) => void][] = [
      ["helper digest", (draft) => { draft["guardian_helper_sha256"] = `sha256:${"d".repeat(64)}`; }],
      ["helper path", (draft) => { draft["guardian_helper_path"] = "/forged/helper.py"; draft["guardian_helper_realpath"] = "/forged/helper.py"; }],
      ["helper realpath", (draft) => { draft["guardian_helper_realpath"] = "/forged/helper.py"; }],
      ["Python invocation", (draft) => { draft["guardian_python_invocation_path"] = "/forged/python3"; }],
      ["Python realpath", (draft) => { draft["guardian_python_realpath"] = "/forged/python3"; }],
      ["Python version", (draft) => { draft["guardian_python_version"] = "Python forged"; }],
      ["guardian PID", (draft) => {
        draft["guardian_pid"] = Number(draft["guardian_pid"]) + 1;
        draft["guardian_ready_sha256"] = sha256Canonical({
          protocol_version: draft["protocol_version"], guardian_pid: draft["guardian_pid"], acquisition_nonce: draft["acquisition_nonce"],
        });
      }],
      ["controller PID", (draft) => { draft["controller_pid"] = Number(draft["controller_pid"]) + 1; }],
      ["worktree key", (draft) => { draft["worktree_key"] = `sha256:${"e".repeat(64)}`; }],
      ["lock path", (draft) => { draft["lock_path"] = "/forged/worktree.lock"; }],
      ["acquisition nonce", (draft) => {
        draft["acquisition_nonce"] = "f".repeat(32);
        draft["guardian_ready_sha256"] = sha256Canonical({
          protocol_version: draft["protocol_version"], guardian_pid: draft["guardian_pid"], acquisition_nonce: draft["acquisition_nonce"],
        });
      }],
    ];
    for (const [name, mutate] of mutations) {
      await t.test(name, async () => {
        const draft = structuredClone(valid) as unknown as Record<string, unknown>;
        mutate(draft);
        const acquisition = identifyContractDocument("pi_gacw_lock_acquisition_v0", draft) as unknown as M3LockAcquisitionDocument;
        const diagnostic = diagnosticForAcquisition(admission.lock.diagnostics, acquisition);
        const { source, token } = sourceTokenForDiagnostic(admission, diagnostic);
        await persistGraph(fixture, acquisition, diagnostic, source, token);
        assert.ok(["INVALID_MANAGED_RECORD", "INCOMPLETE_MANAGED_RECORD_CHAIN"].includes(
          (await classification(fixture, acquisition.content_sha256)) ?? "MISSING",
        ));
        assert.ok(["INVALID_MANAGED_RECORD", "INCOMPLETE_MANAGED_RECORD_CHAIN"].includes(
          (await classification(fixture, diagnostic.content_sha256)) ?? "MISSING",
        ));
        assert.notEqual(await classification(fixture, source.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
        assert.notEqual(await classification(fixture, token.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
        await assertFastDoesNotPass(fixture, admission, token);
      });
    }
    const protocolDraft = structuredClone(valid) as unknown as Record<string, unknown>;
    protocolDraft["protocol_version"] = "forged-protocol";
    assert.throws(() => identifyContractDocument("pi_gacw_lock_acquisition_v0", protocolDraft));
  } finally {
    await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
  }
});

test("R5-R1 missing acquisition and source edges classify incomplete", async (t) => {
  await t.test("diagnostic acquisition-root reference", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      const draft = structuredClone(admission.lock.diagnostics) as unknown as Record<string, unknown>;
      draft["lock_acquisition_content_sha256"] = `sha256:${"1".repeat(64)}`;
      const diagnostic = identifyContractDocument("pi_gacw_lock_diagnostic_v0", draft) as unknown as M3LockDiagnosticDocument;
      const { source, token } = sourceTokenForDiagnostic(admission, diagnostic);
      await persistGraph(fixture, null, diagnostic, source, token);
      assert.equal(await classification(fixture, diagnostic.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      assert.equal(await classification(fixture, source.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      assert.equal(await classification(fixture, token.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      await assertFastDoesNotPass(fixture, admission, token);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
  await t.test("source diagnostic reference", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      const sourceDraft = structuredClone(admission.full.preflight) as unknown as Record<string, unknown>;
      sourceDraft["lock_diagnostic_content_sha256"] = `sha256:${"2".repeat(64)}`;
      const source = identifyContractDocument("pi_gacw_preflight_v0", sourceDraft) as unknown as M3PreflightDocument;
      const tokenDraft = structuredClone(admission.full.acceptedState) as unknown as Record<string, unknown>;
      tokenDraft["source_content_sha256"] = source.content_sha256;
      tokenDraft["lock_diagnostic_content_sha256"] = sourceDraft["lock_diagnostic_content_sha256"];
      const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft) as unknown as M3RepositoryStateTokenDocument;
      await persist(fixture, "preflights", source); await persist(fixture, "repository-state-tokens", token);
      assert.equal(await classification(fixture, source.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      assert.equal(await classification(fixture, token.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      await assertFastDoesNotPass(fixture, admission, token);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
  await t.test("token source reference", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      const tokenDraft = structuredClone(admission.full.acceptedState) as unknown as Record<string, unknown>;
      tokenDraft["source_content_sha256"] = `sha256:${"3".repeat(64)}`;
      const token = identifyContractDocument("pi_gacw_repository_state_token_v0", tokenDraft) as unknown as M3RepositoryStateTokenDocument;
      await persist(fixture, "repository-state-tokens", token);
      assert.equal(await classification(fixture, token.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      await assertFastDoesNotPass(fixture, admission, token);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
});

test("R5-R1 global acquisition availability and normal release have deterministic history", async (t) => {
  await t.test("missing global root", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      const acquisition = lockAcquisitionAuthority(admission.lock);
      await unlink(lockAcquisitionGlobalPath(fixture.stateRoot, acquisition));
      assert.equal(await classification(fixture, acquisition.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      assert.equal(await classification(fixture, admission.lock.diagnostics.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      assert.equal(await classification(fixture, admission.full.preflight.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      assert.equal(await classification(fixture, admission.full.acceptedState.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
      await assertFastDoesNotPass(fixture, admission, admission.full.acceptedState);
    } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
  });
  await t.test("normal release preserves historical authority", async () => {
    const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
    try {
      const acquisition = lockAcquisitionAuthority(admission.lock);
      await releaseWorktreeLock(admission.lock);
      assert.equal(await classification(fixture, acquisition.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
      assert.equal(await classification(fixture, admission.lock.diagnostics.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
      assert.equal(await classification(fixture, admission.full.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    } finally { await removeRepositoryFixture(fixture); }
  });
});
