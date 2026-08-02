import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import type { Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
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
    assert.equal(await classification(value, read.resultRecord.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value, value.policy.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const command = await value.gateway.run_inspection_command({ commandId: "pass", stateTokenContentSha256: token(value) });
    assert.equal(await classification(value, command.record.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(command.record.stdout_stream_complete, true); assert.equal(command.record.stdout_observed_digest, command.record.stdout_digest);
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});

test("M4-managed-semantic-authority: coherent impossible records are INVALID, missing chains are INCOMPLETE", async () => {
  const value = await createM4Fixture(async (fixture) => [await commandSpecification("pass", "INSPECTION", "/usr/bin/printf", ["pass"], { repositoryRoot: fixture.repository })]);
  try {
    const read = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "tracked.txt", offset: 0, length: 7, mode: "TEXT" });
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
    await persist(value, "tool-results", wrongKind);
    for (const record of [falseCapability, impossibleCreate, disallowedPass, wrongKind]) assert.equal(await classification(value, record.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(value, incomplete.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(value, read.resultRecord.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});
