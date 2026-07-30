import assert from "node:assert/strict";
import { chmod, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { inspectRunStorage } from "../src/persistence/index.js";
import { applyRetentionCleanup, inspectRetention } from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import { identifyContractDocument, type M3RetentionResultDocument } from "../src/schemas/index.js";
import { removeRepositoryFixture, type RepositoryFixture } from "./repository-helpers.js";
import { createTerminalBlobFixture, retentionInput } from "./repository-matrix-helpers.js";

function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { readonly code: unknown }).code : undefined;
}

async function persist(
  fixture: RepositoryFixture,
  document: { readonly content_sha256: string },
): Promise<void> {
  const path = join(fixture.stateRoot, "runs", fixture.runId, "records", "retention", `${document.content_sha256.slice(7)}.json`);
  await writeFile(path, canonicalJsonRecordBytes(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

function recordPath(fixture: RepositoryFixture, document: { readonly content_sha256: string }): string {
  return join(fixture.stateRoot, "runs", fixture.runId, "records", "retention", `${document.content_sha256.slice(7)}.json`);
}

async function classification(fixture: RepositoryFixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

function cleanupPrior(
  source: M3RetentionResultDocument,
  prior: M3RetentionResultDocument,
): M3RetentionResultDocument {
  const draft = structuredClone(source) as unknown as Record<string, unknown>;
  draft["operation"] = "CLEANUP";
  draft["outcome"] = "IDEMPOTENT";
  const blob = (draft["blobs"] as Array<Record<string, unknown>>)[0]!;
  blob["status"] = "ALREADY_REMOVED";
  blob["result"] = "IDEMPOTENT";
  blob["detail_code"] = null;
  blob["unlink_performed"] = false;
  blob["directory_fsync_performed"] = false;
  blob["prior_successful_result_content_sha256"] = prior.content_sha256;
  return identifyContractDocument("pi_gacw_retention_result_v0", draft) as unknown as M3RetentionResultDocument;
}

test("R5-R1 public inspection observations cover present, pending, and proven-removed targets", async (t) => {
  await t.test("present eligible target", async () => {
    const value = await createTerminalBlobFixture();
    try {
      const result = await inspectRetention(retentionInput(value));
      assert.equal(result.operation, "INSPECT"); assert.equal(result.outcome, "ELIGIBLE");
      assert.equal(result.blobs[0]!.status, "ELIGIBLE");
      assert.equal(result.blobs[0]!.prior_successful_result_content_sha256, null);
      assert.equal(await classification(value.fixture, result.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    } finally { await removeRepositoryFixture(value.fixture); }
  });
  await t.test("pending target", async () => {
    const value = await createTerminalBlobFixture();
    try {
      const result = await inspectRetention(retentionInput(value, "2026-01-15T00:00:00.000Z"));
      assert.equal(result.operation, "INSPECT"); assert.equal(result.outcome, "REFUSED");
      assert.equal(result.blobs[0]!.status, "DEADLINE_PENDING");
      assert.equal(result.blobs[0]!.prior_successful_result_content_sha256, null);
      assert.equal(await classification(value.fixture, result.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    } finally { await removeRepositoryFixture(value.fixture); }
  });
  await t.test("proven removed observation has no proof edge", async () => {
    const value = await createTerminalBlobFixture();
    try {
      await applyRetentionCleanup(retentionInput(value));
      const result = await inspectRetention(retentionInput(value));
      assert.equal(result.operation, "INSPECT"); assert.equal(result.blobs[0]!.status, "ALREADY_REMOVED");
      assert.equal(result.blobs[0]!.prior_successful_result_content_sha256, null);
      assert.equal(await classification(value.fixture, result.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    } finally { await removeRepositoryFixture(value.fixture); }
  });
});

test("R5-R1 inspection cannot be a direct, intermediate, or mixed cleanup proof", async () => {
  const value = await createTerminalBlobFixture();
  try {
    const complete = await applyRetentionCleanup(retentionInput(value));
    const observation = await inspectRetention(retentionInput(value));
    const inspectionDraft = structuredClone(observation) as unknown as Record<string, unknown>;
    ((inspectionDraft["blobs"] as Array<Record<string, unknown>>)[0]!)["prior_successful_result_content_sha256"] = complete.content_sha256;
    const edgedInspection = identifyContractDocument("pi_gacw_retention_result_v0", inspectionDraft) as unknown as M3RetentionResultDocument;
    await persist(value.fixture, edgedInspection);
    assert.equal(await classification(value.fixture, edgedInspection.content_sha256), "INVALID_MANAGED_RECORD");

    const direct = cleanupPrior(observation, observation);
    await persist(value.fixture, direct);
    assert.equal(await classification(value.fixture, direct.content_sha256), "INVALID_MANAGED_RECORD");

    const mixed = cleanupPrior(observation, edgedInspection);
    await persist(value.fixture, mixed);
    assert.equal(await classification(value.fixture, mixed.content_sha256), "INVALID_MANAGED_RECORD");
    await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("R5-R1 inspection-only authority cannot reconcile quota or a missing blob", async () => {
  const value = await createTerminalBlobFixture();
  try {
    const complete = await applyRetentionCleanup(retentionInput(value));
    const observation = await inspectRetention(retentionInput(value));
    await unlink(recordPath(value.fixture, complete));
    assert.equal(await classification(value.fixture, observation.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(value.fixture, value.baseline.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(value.fixture, value.approval.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    await assert.rejects(applyRetentionCleanup(retentionInput(value)), (error: unknown) => codeOf(error) === "CLEANUP_UNCERTAIN");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("R5-R1 complete and cleanup-only idempotent chains remain exact proof", async () => {
  const value = await createTerminalBlobFixture();
  try {
    const complete = await applyRetentionCleanup(retentionInput(value));
    const second = await applyRetentionCleanup(retentionInput(value));
    assert.equal(second.operation, "CLEANUP"); assert.equal(second.outcome, "IDEMPOTENT");
    assert.equal(second.blobs[0]!.prior_successful_result_content_sha256, complete.content_sha256);
    const third = cleanupPrior(second, second);
    await persist(value.fixture, third);
    assert.equal(await classification(value.fixture, complete.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, second.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, third.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, value.baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    const publicResult = await applyRetentionCleanup(retentionInput(value));
    assert.equal(publicResult.operation, "CLEANUP"); assert.equal(publicResult.outcome, "IDEMPOTENT");
  } finally { await removeRepositoryFixture(value.fixture); }
});
