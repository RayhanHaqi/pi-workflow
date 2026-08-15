import assert from "node:assert/strict";
import { mkdir, readFile, readdir, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { identifyContractDocument, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { releaseWorktreeLock } from "../src/repository/index.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { git, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof ScopedToolGatewayError ? error.code : (error as { code?: unknown })?.code; }
async function cleanup(value: Awaited<ReturnType<typeof createM4Fixture>>) {
  resetSecureFilesystemTestHooks(); await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture);
}
async function preimage(path: string) { const bytes = await readFile(path); const value = await stat(path); return { expectedPreimageDigest: sha256Bytes(bytes), expectedPreimageSize: bytes.byteLength, expectedPreimageMode: value.mode & 0o777 }; }
function token(value: Awaited<ReturnType<typeof createM4Fixture>>): Sha256Digest { return value.gateway.acceptedState.content_sha256 as Sha256Digest; }
function basePatch(value: Awaited<ReturnType<typeof createM4Fixture>>) { return { stateTokenContentSha256: token(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest, ownershipClass: "OWNER_ACCEPTED_MUTABLE" as const, dataClass: "PUBLIC_SOURCE" as const }; }

test("M4 scoped gateway exposes only high-level fixed operations", async () => {
  const value = await createM4Fixture();
  try {
    assert.deepEqual(Object.getOwnPropertyNames(Object.getPrototypeOf(value.gateway)).filter((name) => name !== "constructor").sort(), ["acceptedState", "apply_patch_scoped", "inspect_git_scoped", "list_scoped", "read_evidence", "read_scoped", "run_inspection_command", "run_task_command", "run_verification_command", "search_scoped"].sort());
    assert.equal("rootFd" in value.gateway, false); assert.equal("runHelper" in value.gateway, false); assert.equal("argv" in value.gateway, false);
    assert.equal(Object.isFrozen(value.gateway), true); assert.equal(Object.isFrozen(value.gateway.acceptedState), true);
  } finally { await cleanup(value); }
});

test("M4 gateway detaches mutable caller policy authority", async () => {
  const value = await createM4Fixture();
  try {
    (value.policy.limits as { maximum_read_bytes: number }).maximum_read_bytes = 0;
    const result = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/a.txt", offset: 0, length: 1, mode: "TEXT" });
    assert.equal(result.content, "A");
  } finally { await cleanup(value); }
});

test("M4 read_scoped returns deterministic text and base64 records", async () => {
  const value = await createM4Fixture();
  try {
    const text = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/a.txt", offset: 0, length: 1_024, mode: "TEXT" });
    assert.equal(text.content, "Alpha needle\nsecond line\n"); assert.equal(text.resultRecord.outcome, "RAW");
    const binary = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/a.txt", offset: 6, length: 6, mode: "BINARY" });
    assert.equal(Buffer.from(binary.content ?? "", "base64").toString(), "needle");
    assert.notEqual(text.resultRecord.request_content_sha256, binary.resultRecord.request_content_sha256);
  } finally { await cleanup(value); }
});

test("M4 authorized missing read publishes nonfatal absence evidence without file metadata", async () => {
  const value = await createM4Fixture();
  try {
    const result = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/absent.txt", offset: 0, length: 1_024, mode: "TEXT" });
    assert.equal(result.resultRecord.outcome, "MISSING");
    assert.equal(result.content, null); assert.equal(result.metadata as unknown, null); assert.equal(result.contentEncoding, "METADATA_ONLY");
    assert.equal(result.resultRecord.content_digest, null); assert.equal(result.resultRecord.byte_count, 0); assert.equal(result.resultRecord.item_count, 0);
    const records = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records");
    assert.equal((await readdir(join(records, "tool-requests"))).length, 1);
    assert.equal((await readdir(join(records, "tool-results"))).length, 1);
    assert.equal((await readdir(join(records, "m4-admission-refusals"))).length, 0);
  } finally { await cleanup(value); }
});

test("M4 distinguishes existing empty files from authorized missing reads", async () => {
  const value = await createM4Fixture([], null, async (fixture) => {
    await writeFile(join(fixture.repository, "src", "empty.txt"), "", { mode: 0o644 });
    await git(fixture.repository, "add", "src/empty.txt"); await git(fixture.repository, "commit", "-m", "add empty M4 read fixture");
  });
  try {
    const result = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/empty.txt", offset: 0, length: 1_024, mode: "TEXT" });
    assert.equal(result.resultRecord.outcome, "RAW");
    assert.equal(result.content, ""); assert.equal(result.metadata.size, 0);
  } finally { await cleanup(value); }
});

test("M4 missing-read handling preserves read scope and special-file failures", async (t) => {
  await t.test("out-of-scope absent path remains fatal before M4 read admission", async () => {
    const value = await createM4Fixture();
    try {
      await assert.rejects(value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "outside-absent.txt", offset: 0, length: 1, mode: "TEXT" }), (error: unknown) => code(error) === "PATH_NOT_READABLE");
      assert.equal((await readdir(join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "tool-results"))).length, 0);
    } finally { await cleanup(value); }
  });
  await t.test("symlink and special file remain fatal and never become MISSING", async () => {
    for (const [name, setup] of [
      ["link.txt", async (path: string) => symlink("a.txt", path)],
      ["pipe", async (path: string) => {
        const { execFile } = await import("node:child_process");
        await new Promise<void>((resolve, reject) => execFile("mkfifo", [path], (error) => error === null ? resolve() : reject(error)));
      }],
    ] as const) {
      const value = await createM4Fixture();
      try {
        await setup(join(value.fixture.repository, "src", name));
        await assert.rejects(value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: `src/${name}`, offset: 0, length: 1, mode: "TEXT" }), (error: unknown) => code(error) === "FAST_PREFLIGHT_FAILED");
        assert.equal((await readdir(join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "tool-results"))).length, 0);
      } finally { await cleanup(value); }
    }
  });
});

test("M4 CREATE remains independently atomic after a missing read", async () => {
  const value = await createM4Fixture();
  try {
    const path = "generated/after-missing.txt";
    const missing = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path, offset: 0, length: 1, mode: "TEXT" });
    assert.equal(missing.resultRecord.outcome, "MISSING"); assert.equal(token(value), missing.resultRecord.state_token_content_sha256, "absence does not advance the M3 token");
    const patch = { ...basePatch(value), ownershipClass: "GENERATED_ACCEPTED_BASELINE" as const, dataClass: "PUBLIC_SOURCE" as const, operation: "CREATE" as const, path,
      expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null, replacementBytes: Buffer.from("created\n"), requestedFinalMode: 0o644 };
    await value.gateway.apply_patch_scoped(patch);
    await assert.rejects(value.gateway.apply_patch_scoped({ ...patch, stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "TARGET_ALREADY_EXISTS");
    assert.equal(await readFile(join(value.fixture.repository, path), "utf8"), "created\n");
  } finally { await cleanup(value); }
});

test("M4 data-class projection returns metadata without restricted bytes", async () => {
  const value = await createM4Fixture([], (base) => {
    const { content_sha256: _identity, ...body } = base;
    const pathAuthorities = base.path_authorities.map((authority) => authority.path === "src"
      ? { ...authority, data_class: "PRIVATE_SOURCE" as const, raw_read_approved: false }
      : authority);
    return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...body,
      command_readable_paths: base.command_readable_paths.filter((rule) => rule.path !== "src"), path_authorities: pathAuthorities,
    }) as M4ScopedToolPolicyDocument;
  });
  try {
    const result = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/a.txt", offset: 0, length: 100, mode: "TEXT" });
    assert.equal(result.content, null); assert.equal(result.contentEncoding, "METADATA_ONLY"); assert.equal(result.dataClass, "PRIVATE_SOURCE"); assert.equal(result.resultRecord.outcome, "METADATA_ONLY");
    const common = { stateTokenContentSha256: token(value), literal: "needle", caseSensitive: true, includePaths: ["src"], excludePaths: [], maximumFiles: 10, maximumBytes: 10_000, maximumMatches: 10, maximumLineLength: 1_000 };
    await assert.rejects(value.gateway.search_scoped(common), (error: unknown) => code(error) === "DATA_POLICY_FORBIDS_READ");
  } finally { await cleanup(value); }
});

test("M4 search_scoped is literal, bounded, case-aware, and deterministically ordered", async () => {
  const value = await createM4Fixture();
  try {
    const common = { stateTokenContentSha256: token(value), literal: "needle", includePaths: ["src"], excludePaths: [], maximumFiles: 10, maximumBytes: 10_000, maximumMatches: 10, maximumLineLength: 1_000 };
    const sensitive = await value.gateway.search_scoped({ ...common, caseSensitive: true });
    assert.deepEqual(sensitive.matches.map((match) => `${match.path}:${match.line}:${match.column}`), ["src/a.txt:1:7"]);
    await assert.rejects(value.gateway.search_scoped({ ...common, caseSensitive: false, maximumMatches: 1 }), (error: unknown) => code(error) === "SEARCH_LIMIT_EXCEEDED");
    await assert.rejects(value.gateway.search_scoped({ ...common, literal: "", caseSensitive: true }), (error: unknown) => code(error) === "INVALID_ARGUMENT");
  } finally { await cleanup(value); }
});

test("M4 list_scoped is sorted and preflight rejects an unadmitted symlink", async () => {
  const value = await createM4Fixture();
  try {
    const list = await value.gateway.list_scoped({ stateTokenContentSha256: token(value), path: "src", maximumDepth: 4, hashFiles: true });
    assert.deepEqual(list.entries.map((entry) => entry.path), ["src/a.txt", "src/b.txt"]);
    await symlink("a.txt", join(value.fixture.repository, "src", "link.txt"));
    await assert.rejects(value.gateway.list_scoped({ stateTokenContentSha256: token(value), path: "src", maximumDepth: 4, hashFiles: false }), (error: unknown) => code(error) === "FAST_PREFLIGHT_FAILED");
  } finally { await cleanup(value); }
});

test("M4 inspect_git_scoped is a fixed structured inspection", async () => {
  const value = await createM4Fixture();
  try {
    const result = await value.gateway.inspect_git_scoped({ stateTokenContentSha256: token(value), operation: "STATUS", path: null });
    const status = JSON.parse(Buffer.from(result.output, "base64").toString()) as { branch: string; dirty: boolean; visible_changed_paths: string[]; hidden_changed_path_count: number; visible_fingerprint_content_sha256: string };
    assert.equal(status.branch, "main"); assert.equal(status.dirty, false); assert.deepEqual(status.visible_changed_paths, []); assert.equal(status.hidden_changed_path_count, 0); assert.equal(typeof status.visible_fingerprint_content_sha256, "string");
    const files = await value.gateway.inspect_git_scoped({ stateTokenContentSha256: token(value), operation: "LS_FILES", path: null });
    const inventory = JSON.parse(Buffer.from(files.output, "base64").toString()) as { visible_paths: string[]; hidden_path_count: number };
    assert.deepEqual(inventory.visible_paths, ["generated/.keep", "src/a.txt", "src/b.txt", "tracked.txt"]); assert.equal(inventory.hidden_path_count, 2);
    await assert.rejects(value.gateway.inspect_git_scoped({ stateTokenContentSha256: token(value), operation: "SHOW_PATH_AT_HEAD", path: "AUTHORITY.md" }), (error: unknown) => code(error) === "PATH_NOT_READABLE");
  } finally { await cleanup(value); }
});

test("M4 read_evidence reads typed immutable records by digest only", async () => {
  const value = await createM4Fixture();
  try {
    const result = await value.gateway.read_evidence({ stateTokenContentSha256: token(value), kind: "M3_REPOSITORY_STATE_TOKEN", contentSha256: token(value) });
    assert.equal((result.document as { content_sha256: string }).content_sha256, value.gateway.acceptedState.content_sha256);
    await assert.rejects(value.gateway.read_evidence({ stateTokenContentSha256: token(value), kind: "M3_REPOSITORY_STATE_TOKEN", contentSha256: sha256Bytes(Buffer.from("absent")) }), (error: unknown) => code(error) === "EVIDENCE_NOT_FOUND");
  } finally { await cleanup(value); }
});

test("M4 create, replace, and delete each enforce exact authority and publish receipts", async (t) => {
  await t.test("CREATE", async () => {
    const value = await createM4Fixture(); try {
      const result = await value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "CREATE", path: "created.txt", expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null, replacementBytes: Buffer.from("created\n"), requestedFinalMode: 0o644 });
      assert.equal(await readFile(join(value.fixture.repository, "created.txt"), "utf8"), "created\n"); assert.equal(result.receipt.helper_outcome, "APPLIED"); assert.deepEqual(result.acceptedState.changed_paths, ["created.txt"]);
    } finally { await cleanup(value); }
  });
  await t.test("REPLACE", async () => {
    const value = await createM4Fixture(); try {
      const before = await preimage(value.fixture.trackedPath); const result = await value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("replaced\n"), requestedFinalMode: before.expectedPreimageMode });
      assert.equal(result.receipt.before?.digest, before.expectedPreimageDigest); assert.equal(result.receipt.after?.digest, sha256Bytes(Buffer.from("replaced\n")));
      const { content_sha256: _identity, ...receiptBody } = result.receipt;
      assert.throws(() => identifyContractDocument("pi_gacw_mutation_receipt_v0", { ...receiptBody, failure_code: "FORGED_FAILURE" }), (error: unknown) => (error as { code?: unknown }).code === "MUTATION_RECEIPT_INCONSISTENT");
    } finally { await cleanup(value); }
  });
  await t.test("DELETE", async () => {
    const value = await createM4Fixture(); try {
      const before = await preimage(value.fixture.trackedPath); const result = await value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "DELETE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: null, requestedFinalMode: null });
      assert.deepEqual(result.receipt.after, { digest: null, size: null, mode: null }); await assert.rejects(readFile(value.fixture.trackedPath), { code: "ENOENT" });
    } finally { await cleanup(value); }
  });
});

test("M4 apply_patch rejects undeclared, frozen, authority-mismatched, and stale requests", async (t) => {
  const cases = [
    ["undeclared", { operation: "CREATE", path: "other.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE" }, "PATH_NOT_EDITABLE"],
    ["frozen", { operation: "REPLACE", path: "AUTHORITY.md", ownershipClass: "OWNER_AUTHORITY", dataClass: "PUBLIC_SOURCE" }, "FROZEN_PATH"],
    ["ownership", { operation: "REPLACE", path: "tracked.txt", ownershipClass: "OWNER_AUTHORITY", dataClass: "PUBLIC_SOURCE" }, "OWNERSHIP_CLASS_MISMATCH"],
    ["data class", { operation: "REPLACE", path: "tracked.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PRIVATE_SOURCE" }, "DATA_CLASS_MISMATCH"],
  ] as const;
  for (const [label, partial, expectedCode] of cases) await t.test(label, async () => {
    const value = await createM4Fixture(); try {
      const before = await preimage(value.fixture.trackedPath); const create = partial.operation === "CREATE";
      await assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), ...partial, expectedPreimageExists: !create,
        expectedPreimageDigest: create ? null : before.expectedPreimageDigest, expectedPreimageSize: create ? null : before.expectedPreimageSize,
        expectedPreimageMode: create ? null : before.expectedPreimageMode, replacementBytes: Buffer.from("x"), requestedFinalMode: before.expectedPreimageMode }),
        (error: unknown) => code(error) === (expectedCode === "OWNERSHIP_CLASS_MISMATCH" || expectedCode === "DATA_CLASS_MISMATCH" ? "OWNERSHIP_FORBIDS_MUTATION" : expectedCode));
    } finally { await cleanup(value); }
  });
  await t.test("stale token", async () => {
    const value = await createM4Fixture(); try {
      const before = await preimage(value.fixture.trackedPath);
      await assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), stateTokenContentSha256: sha256Bytes(Buffer.from("stale")), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("x"), requestedFinalMode: before.expectedPreimageMode }), (error: unknown) => code(error) === "STATE_TOKEN_PROVENANCE_INVALID");
      assert.equal(await readFile(value.fixture.trackedPath, "utf8"), "initial\n");
    } finally { await cleanup(value); }
  });
});

test("M4 exact preimage failure never changes target content", async () => {
  const value = await createM4Fixture();
  try {
    const before = await preimage(value.fixture.trackedPath);
    await assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, expectedPreimageDigest: sha256Bytes(Buffer.from("wrong")), replacementBytes: Buffer.from("x"), requestedFinalMode: before.expectedPreimageMode }), (error: unknown) => code(error) === "PREIMAGE_MISMATCH");
    assert.equal(await readFile(value.fixture.trackedPath, "utf8"), "initial\n");
    const directory = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "mutation-receipts"); const names = await readdir(directory); assert.equal(names.length, 1);
    const receipt = JSON.parse(await readFile(join(directory, names[0]!), "utf8")) as { helper_outcome: string; failure_code: string }; assert.equal(receipt.helper_outcome, "BLOCKED"); assert.equal(receipt.failure_code, "PREIMAGE_MISMATCH");
  } finally { await cleanup(value); }
});

test("M4 mutations require the live exact lock acquisition", async () => {
  const value = await createM4Fixture();
  try {
    const before = await preimage(value.fixture.trackedPath); await releaseWorktreeLock(value.admission.lock);
    await assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("x"), requestedFinalMode: before.expectedPreimageMode }), (error: unknown) => code(error) === "LOCK_LOST");
  } finally { await cleanup(value); }
});

test("M4 fast preflight runs immediately before helper mutation", async () => {
  const value = await createM4Fixture();
  try {
    const before = await preimage(value.fixture.trackedPath); await writeFile(join(value.fixture.repository, "unexpected.txt"), "outside scope\n");
    await assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("x"), requestedFinalMode: before.expectedPreimageMode }), (error: unknown) => code(error) === "FAST_PREFLIGHT_FAILED");
    assert.equal(await readFile(value.fixture.trackedPath, "utf8"), "initial\n");
  } finally { await cleanup(value); }
});

test("M4 postflight advances the token but never writes state.json", async () => {
  const value = await createM4Fixture();
  try {
    const statePath = join(value.fixture.stateRoot, "runs", value.fixture.runId, "state.json"); const stateBytesBefore = await readFile(statePath); const priorToken = token(value);
    const before = await preimage(value.fixture.trackedPath); const result = await value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("new\n"), requestedFinalMode: before.expectedPreimageMode });
    assert.equal(result.acceptedState.prior_token_content_sha256, priorToken);
    assert.deepEqual(await readFile(statePath), stateBytesBefore);
  } finally { await cleanup(value); }
});

test("M4 postflight failure is typed when a synchronized attacker changes frozen authority", async () => {
  const value = await createM4Fixture(); const control = join(value.fixture.root, "post.sock");
  const { createServer } = await import("node:net");
  try {
    const before = await preimage(value.fixture.trackedPath);
    const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => { data += chunk.toString(); if (!data.includes("\n")) return; await writeFile(join(value.fixture.repository, "AUTHORITY.md"), "attacker\n"); connection.end("1"); }); });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject)); setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "BEFORE_RENAME" });
    await assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("new\n"), requestedFinalMode: before.expectedPreimageMode }), (error: unknown) => code(error) === "POSTFLIGHT_FAILED");
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { await cleanup(value); }
});

test("M4 mutation serialization makes a concurrent stale-token call fail deterministically", async () => {
  const value = await createM4Fixture(); const control = join(value.fixture.root, "serial.sock"); const { createServer } = await import("node:net");
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; }); let reached!: () => void; const atCheckpoint = new Promise<void>((resolve) => { reached = resolve; });
  try {
    const before = await preimage(value.fixture.trackedPath);
    const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => { data += chunk.toString(); if (!data.includes("\n")) return; reached(); await gate; connection.end("1"); }); });
    await new Promise<void>((resolve, reject) => server.listen(control, resolve).once("error", reject)); setSecureFilesystemTestHooks({ checkpointSocket: control, checkpointStage: "BEFORE_RENAME" });
    const first = value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("first\n"), requestedFinalMode: before.expectedPreimageMode });
    await atCheckpoint;
    const second = assert.rejects(value.gateway.apply_patch_scoped({ ...basePatch(value), operation: "REPLACE", path: "tracked.txt", expectedPreimageExists: true, ...before, replacementBytes: Buffer.from("second\n"), requestedFinalMode: before.expectedPreimageMode }), (error: unknown) => code(error) === "CONCURRENT_OPERATION");
    release(); await Promise.all([first, second]); assert.equal(await readFile(value.fixture.trackedPath, "utf8"), "first\n");
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { await cleanup(value); }
});

test("M4 evidence directories are immutable content-addressed additions", async () => {
  const value = await createM4Fixture();
  try {
    await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/a.txt", offset: 0, length: 10, mode: "TEXT" });
    const runRoot = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records"); const requests = await readdir(join(runRoot, "tool-requests")); const results = await readdir(join(runRoot, "tool-results"));
    assert.equal(requests.length, 1); assert.equal(results.length, 1); assert.match(requests[0] ?? "", /^[a-f0-9]{64}\.json$/); assert.match(results[0] ?? "", /^[a-f0-9]{64}\.json$/);
    assert.equal((await stat(join(runRoot, "tool-requests", requests[0]!))).mode & 0o777, 0o600);
  } finally { await cleanup(value); }
});
