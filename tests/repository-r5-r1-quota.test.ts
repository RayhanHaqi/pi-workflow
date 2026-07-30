import assert from "node:assert/strict";
import { chmod, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { inspectRunStorage } from "../src/persistence/index.js";
import {
  M3AuthorityValidationError,
  replayM3QuotaPopulationTransitions,
  type M3QuotaReplayTransition,
} from "../src/persistence/m3-authority.js";
import {
  applyRetentionCleanup,
  inspectRetention,
} from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import { identifyContractDocument, type M3BaselineRuntimeDocument, type M3RetentionResultDocument } from "../src/schemas/index.js";
import { createRepositoryFixture, removeRepositoryFixture, type RepositoryFixture } from "./repository-helpers.js";
import {
  createCleanAdmission,
  createTerminalBlobFixture,
  releaseAdmission,
  retentionInput,
} from "./repository-matrix-helpers.js";

function transition(
  identity: string,
  existing: number,
  added: number,
  resulting: number,
  population: readonly [string, number][],
): M3QuotaReplayTransition {
  return {
    identity,
    existingPhysicalBytes: existing,
    newUniquePhysicalBytes: added,
    resultingPhysicalBytes: resulting,
    ownPopulation: new Map(population),
  };
}

function populationKeys(values: readonly ReadonlyMap<string, number>[]): readonly string[] {
  return values.map((value) => [...value].map(([digest, size]) => `${digest}:${size}`).sort().join("|")).sort();
}

async function persist(
  fixture: RepositoryFixture,
  directory: string,
  document: { readonly content_sha256: string },
): Promise<void> {
  const path = join(fixture.stateRoot, "runs", fixture.runId, "records", directory, `${document.content_sha256.slice(7)}.json`);
  await writeFile(path, canonicalJsonRecordBytes(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function classification(fixture: RepositoryFixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

test("R5-R1 quota replay covers unambiguous, convergent, and bounded ambiguous histories", async (t) => {
  const a = transition("A", 0, 1, 1, [["a", 1]]);
  const b = transition("B", 0, 1, 1, [["b", 1]]);
  const c = transition("C", 0, 1, 1, [["c", 1]]);
  await t.test("one unambiguous transition", () => {
    assert.deepEqual(populationKeys(replayM3QuotaPopulationTransitions("A", [a])), ["a:1"]);
  });
  await t.test("several unambiguous transitions", () => {
    const addB = transition("ADD_B", 1, 1, 2, [["b", 1]]);
    const target = transition("TARGET", 2, 0, 2, []);
    assert.deepEqual(populationKeys(replayM3QuotaPopulationTransitions("TARGET", [a, addB, target])), ["a:1|b:1"]);
  });
  await t.test("two histories converge to one population", () => {
    const addA = transition("ADD_A", 1, 1, 2, [["a", 1]]);
    const addB = transition("ADD_B", 1, 1, 2, [["b", 1]]);
    const target = transition("TARGET", 2, 0, 2, []);
    assert.deepEqual(populationKeys(replayM3QuotaPopulationTransitions("TARGET", [a, b, addA, addB, target])), ["a:1|b:1"]);
  });
  await t.test("ambiguity below the bound is deterministic", () => {
    const target = transition("TARGET", 1, 0, 1, []);
    assert.deepEqual(populationKeys(replayM3QuotaPopulationTransitions("TARGET", [a, b, c, target], 5)), ["a:1", "b:1", "c:1"]);
  });
  await t.test("exact state-limit boundary", () => {
    const target = transition("TARGET", 1, 0, 1, []);
    assert.equal(replayM3QuotaPopulationTransitions("TARGET", [a, b, c, target], 4).length, 3);
  });
  await t.test("state-limit plus one fails closed", () => {
    const d = transition("D", 0, 1, 1, [["d", 1]]);
    const target = transition("TARGET", 1, 0, 1, []);
    assert.throws(
      () => replayM3QuotaPopulationTransitions("TARGET", [a, b, c, d, target], 4),
      (error: unknown) => error instanceof M3AuthorityValidationError && error.semanticCode === "BASELINE_PROVENANCE_INVALID",
    );
  });
  await t.test("conflicting populations are not arbitrarily merged", () => {
    const a2 = transition("A2", 0, 2, 2, [["a", 2]]);
    const target = transition("TARGET", 1, 0, 1, []);
    assert.deepEqual(populationKeys(replayM3QuotaPopulationTransitions("TARGET", [a, a2, target])), ["a:1"]);
  });
});

test("R5-R1 unrelated invalid baseline does not poison a selected valid history", async () => {
  const fixture = await createRepositoryFixture(); const admission = await createCleanAdmission(fixture);
  try {
    const draft = structuredClone(admission.baseline) as unknown as Record<string, unknown>;
    (draft["blob_quota"] as Record<string, unknown>)["resulting_physical_bytes"] = 1;
    const invalid = identifyContractDocument("pi_gacw_baseline_runtime_v0", draft) as unknown as M3BaselineRuntimeDocument;
    await persist(fixture, "baselines", invalid);
    assert.equal(await classification(fixture, invalid.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(fixture, admission.baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(fixture, admission.full.acceptedState.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
});

test("R5-R1 exact grouped proof preserves a deduplicated shared population", async () => {
  const value = await createTerminalBlobFixture([
    { name: "one.txt", bytes: "shared\n" },
    { name: "two.txt", bytes: "shared\n" },
  ]);
  try {
    const result = await applyRetentionCleanup(retentionInput(value));
    assert.equal(result.physical_target_count, 1);
    assert.equal(result.logical_target_count, 2);
    assert.equal(result.blobs[0]!.logical_references.length, 2);
    assert.equal(await classification(value.fixture, result.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, value.baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, value.approval.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await removeRepositoryFixture(value.fixture); }
});

test("R5-R1 partial proof cannot reconcile a missing shared population", async () => {
  const value = await createTerminalBlobFixture([
    { name: "one.txt", bytes: "shared-partial\n" },
    { name: "two.txt", bytes: "shared-partial\n" },
  ]);
  try {
    const observation = await inspectRetention(retentionInput(value));
    const draft = structuredClone(observation) as unknown as Record<string, unknown>;
    draft["operation"] = "CLEANUP";
    draft["outcome"] = "COMPLETE";
    draft["logical_target_count"] = 1;
    const blob = (draft["blobs"] as Array<Record<string, unknown>>)[0]!;
    blob["status"] = "DELETED";
    blob["result"] = "SUCCEEDED";
    blob["detail_code"] = null;
    blob["unlink_performed"] = true;
    blob["directory_fsync_performed"] = true;
    blob["logical_references"] = (blob["logical_references"] as unknown[]).slice(0, 1);
    const forged = identifyContractDocument("pi_gacw_retention_result_v0", draft) as unknown as M3RetentionResultDocument;
    await persist(value.fixture, "retention", forged);
    const physical = value.baseline.paths.find((entry) => entry.blob !== null)!.blob!;
    await unlink(join(value.fixture.stateRoot, "runs", value.fixture.runId, physical.relative_path));
    assert.equal(await classification(value.fixture, forged.content_sha256), "INVALID_MANAGED_RECORD");
    assert.equal(await classification(value.fixture, value.baseline.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    await assert.rejects(applyRetentionCleanup(retentionInput(value)));
  } finally { await removeRepositoryFixture(value.fixture); }
});
