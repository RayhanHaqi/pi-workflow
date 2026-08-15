import assert from "node:assert/strict";
import { lstat, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import type { Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { publishBoundedWorkerRecord, readM5ManagedRecords } from "../src/persistence/store.js";
import { m4AttemptedMutationIdentity, publishBoundedWorkerM4AdmissionRefusal } from "../src/scoped-tools/tool-records.js";
import { publishM4Record } from "../src/scoped-tools/records.js";
import { identifyContractDocument, type M4CommandResultDocument, type M4MutationReceiptDocument, type M4SecureFilesystemCapabilityDocument, type M4ToolResultDocument, type SchemaId } from "../src/schemas/index.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture } from "./repository-helpers.js";

function token(value: Awaited<ReturnType<typeof createM4Fixture>>): Sha256Digest { return value.gateway.acceptedState.content_sha256 as Sha256Digest; }
async function persist(value: Awaited<ReturnType<typeof createM4Fixture>>, directory: string, document: { readonly content_sha256: string }): Promise<void> {
  await writeFile(join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", directory, `${document.content_sha256.slice(7)}.json`), `${canonicalize(document)}\n`, { mode: 0o600 });
}
function reidentify<T extends { readonly content_sha256: string }>(schema: SchemaId, value: T, mutate: (draft: Record<string, unknown>) => void): T {
  const draft = structuredClone(value) as unknown as Record<string, unknown>; delete draft["content_sha256"]; mutate(draft); return identifyContractDocument(schema, draft) as T;
}
async function classification(value: Awaited<ReturnType<typeof createM4Fixture>>, digest: string) {
  const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

test("M4-managed-semantic-authority: producer roots and complete chains become authoritative", async () => {
  const value = await createM4Fixture(async (fixture) => [await commandSpecification("pass", "INSPECTION", "/usr/bin/printf", ["pass"], { repositoryRoot: fixture.repository })]);
  try {
    const initial = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
    const initialM4 = initial.managedRecordClassifications.filter((entry) => entry.object.kind.startsWith("M4_")); assert.ok(initialM4.length >= 4);
    assert.ok(initialM4.every((entry) => entry.classification === "UNREFERENCED_MANAGED_RECORD"));
    const read = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "tracked.txt", offset: 0, length: 7, mode: "TEXT" });
    const missing = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/absent.txt", offset: 0, length: 7, mode: "TEXT" });
    assert.equal(missing.resultRecord.outcome, "MISSING");
    assert.equal(await classification(value, read.resultRecord.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value, missing.resultRecord.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value, value.policy.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const command = await value.gateway.run_inspection_command({ commandId: "pass", stateTokenContentSha256: token(value) });
    assert.equal(await classification(value, command.record.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(command.record.stdout_stream_complete, true); assert.equal(command.record.stdout_observed_digest, command.record.stdout_digest);
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});

test("M4 admission refusal is producer-only M4 authority with a normalized mutation identity", async () => {
  const value = await createM4Fixture();
  try {
    const invocation = identifyContractDocument("pi_gacw_bounded_worker_invocation_v0", {
      schema_id: "pi_gacw_bounded_worker_invocation_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      invocation_key: `sha256:${"a".repeat(64)}`, run_id: value.fixture.runId, operation_id: "admission-refusal-operation",
      m5_reservation_decision_content_sha256: `sha256:${"b".repeat(64)}`, m5_reservation_decision_key: `sha256:${"c".repeat(64)}`,
      task_content_sha256: null, task_graph_sha256: null, plan_approval_sha256: null, input_m3_state_token_content_sha256: token(value),
      system_prompt_sha256: `sha256:${"d".repeat(64)}`, user_prompt_sha256: `sha256:${"e".repeat(64)}`, created_at: "2026-01-01T00:00:00.000Z",
    });
    await publishBoundedWorkerRecord({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId, kind: "BOUNDED_WORKER_INVOCATION", document: invocation as any });
    const attempt = {
      path: "AGENTS.md", operation: "CREATE" as const, replacementBytes: Buffer.from("one\n"), expectedPreimageExists: false,
      expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null,
    };
    const replacementChanged = { ...attempt, replacementBytes: Buffer.from("two\n") };
    const operationChanged = { ...attempt, operation: "REPLACE" as const, expectedPreimageExists: true, expectedPreimageDigest: `sha256:${"f".repeat(64)}` as Sha256Digest, expectedPreimageSize: 1, expectedPreimageMode: 0o644 };
    const identity = m4AttemptedMutationIdentity(attempt);
    for (const changed of [
      replacementChanged, operationChanged, { ...attempt, path: "created.txt" },
      { ...attempt, expectedPreimageDigest: `sha256:${"0".repeat(64)}` as Sha256Digest },
      { ...attempt, expectedPreimageSize: 99 }, { ...attempt, expectedPreimageMode: 0o600 },
    ]) assert.notEqual(identity, m4AttemptedMutationIdentity(changed));
    const refusal = await publishBoundedWorkerM4AdmissionRefusal({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, {
      boundedWorkerInvocationContentSha256: invocation.content_sha256 as Sha256Digest, admissionStateTokenContentSha256: token(value),
      attemptedMutation: attempt, refusalCode: "OUT_OF_SCOPE_WRITE",
    });
    assert.equal(await classification(value, refusal.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(canonicalize(refusal.attempted_operation).includes("one\\n"), false, "replacement bytes are never durable refusal evidence");
    const refusalDirectory = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "m4-admission-refusals");
    const beforeUnknownInvocation = await readdir(refusalDirectory);
    await assert.rejects(() => publishBoundedWorkerM4AdmissionRefusal({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, {
      boundedWorkerInvocationContentSha256: `sha256:${"0".repeat(64)}` as Sha256Digest, admissionStateTokenContentSha256: token(value), attemptedMutation: attempt, refusalCode: "OUT_OF_SCOPE_WRITE",
    }), /prior authoritative bounded invocation/);
    assert.deepEqual(await readdir(refusalDirectory), beforeUnknownInvocation, "unknown invocation cannot leave an orphan refusal record");
    await assert.rejects(() => (publishM4Record as unknown as (location: unknown, kind: string, document: unknown) => Promise<unknown>)({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, "ADMISSION_REFUSAL", refusal), /bounded-worker producer path/);
    const wrongInvocation = reidentify("pi_gacw_m4_admission_refusal_v0", refusal, (draft) => { draft["bounded_worker_invocation_content_sha256"] = `sha256:${"0".repeat(64)}`; });
    await persist(value, "m4-admission-refusals", wrongInvocation);
    assert.notEqual(await classification(value, wrongInvocation.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});

test("legacy run layouts without the refusal collection remain readable without migration", async () => {
  const value = await createM4Fixture();
  try {
    const directory = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "m4-admission-refusals");
    await rm(directory, { recursive: true, force: true });
    const [inspection, records] = await Promise.all([
      inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }),
      readM5ManagedRecords({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }),
    ]);
    assert.equal(inspection.status, "HEALTHY");
    assert.deepEqual(records.admissionRefusals, []);
    await assert.rejects(() => lstat(directory), { code: "ENOENT" });
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});

test("M4-managed-semantic-authority: coherent impossible records are INVALID, missing chains are INCOMPLETE", async () => {
  const value = await createM4Fixture(async (fixture) => [await commandSpecification("pass", "INSPECTION", "/usr/bin/printf", ["pass"], { repositoryRoot: fixture.repository })]);
  try {
    const read = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "tracked.txt", offset: 0, length: 7, mode: "TEXT" });
    const missingRead = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/absent.txt", offset: 0, length: 7, mode: "TEXT" });
    const patch = await value.gateway.apply_patch_scoped({ stateTokenContentSha256: token(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
      operation: "CREATE", path: "created.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE", expectedPreimageExists: false,
      expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null, replacementBytes: Buffer.from("created\n"), requestedFinalMode: 0o644 });
    const command = await value.gateway.run_inspection_command({ commandId: "pass", stateTokenContentSha256: token(value) });
    const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
    const secureObject = inspection.managedObjects.find((entry) => entry.kind === "M4_SECURE_FS_CAPABILITY");
    assert.ok(secureObject); const securePath = join(value.fixture.stateRoot, "runs", value.fixture.runId, secureObject!.relativePath);
    const secure = JSON.parse(await readFile(securePath, "utf8")) as M4SecureFilesystemCapabilityDocument;
    const falseCapability = reidentify("pi_gacw_secure_fs_capability_v0", secure, (draft) => {
      draft["openat2_available"] = false; draft["supported_resolve_flags"] = []; draft["renameat2_available"] = false; draft["rename_noreplace_available"] = false;
      draft["rename_exchange_available"] = false; draft["directory_fsync_available"] = false; draft["secure_fs_result"] = "SECURE_FS_UNAVAILABLE";
    });
    await persist(value, "secure-fs-capabilities", falseCapability);
    const impossibleCreate = reidentify("pi_gacw_mutation_receipt_v0", patch.receipt, (draft) => { draft["before"] = { digest: command.record.stdout_digest, size: 1, mode: 420 }; }) as M4MutationReceiptDocument;
    await persist(value, "mutation-receipts", impossibleCreate);
    const disallowedPass = reidentify("pi_gacw_command_result_v0", command.record, (draft) => { draft["exit_code"] = 7; }) as M4CommandResultDocument;
    await persist(value, "command-results", disallowedPass);
    const absent = `sha256:${"f".repeat(64)}`;
    const incomplete = reidentify("pi_gacw_tool_result_v0", read.resultRecord, (draft) => { draft["request_content_sha256"] = absent; }) as M4ToolResultDocument;
    await persist(value, "tool-results", incomplete);
    const wrongKind = reidentify("pi_gacw_tool_result_v0", read.resultRecord, (draft) => { draft["request_content_sha256"] = secure.content_sha256; }) as M4ToolResultDocument;
    const malformedMissing = reidentify("pi_gacw_tool_result_v0", missingRead.resultRecord, (draft) => { draft["content_digest"] = read.resultRecord.content_digest; }) as M4ToolResultDocument;
    const unboundMissing = reidentify("pi_gacw_tool_result_v0", missingRead.resultRecord, (draft) => { draft["request_content_sha256"] = absent; }) as M4ToolResultDocument;
    const wrongBoundMissing = reidentify("pi_gacw_tool_result_v0", missingRead.resultRecord, (draft) => { draft["request_content_sha256"] = read.resultRecord.request_content_sha256; }) as M4ToolResultDocument;
    await persist(value, "tool-results", wrongKind); await persist(value, "tool-results", malformedMissing); await persist(value, "tool-results", unboundMissing); await persist(value, "tool-results", wrongBoundMissing);
    for (const record of [falseCapability, impossibleCreate, disallowedPass, wrongKind, malformedMissing, unboundMissing, wrongBoundMissing]) assert.equal(await classification(value, record.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(value, incomplete.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(value, read.resultRecord.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value, missingRead.resultRecord.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});
