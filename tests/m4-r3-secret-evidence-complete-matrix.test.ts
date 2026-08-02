import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { identifyContractDocument, type M4CommandCatalogDocument, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { createScopedToolGateway, ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { m4RecordPath } from "../src/scoped-tools/records.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { git } from "./repository-helpers.js";
import {
  assertNoForbiddenSecretValues,
  classification,
  disposeM4,
  gatewayCode,
  gatewayToken,
  persistM4,
  reidentify,
} from "./m4-r3-helpers.js";
import { inspectRunStorage } from "../src/persistence/index.js";

const RAW = "R3_SECRET_RAW_CONTENT_8f3c";
const NESTED = "R3_SECRET_NESTED_VALUE_41e9";
const FULL_PATH = "src/secret-zone/b.txt";
const SECRET_SIZE = 37;
const SECRET_MODE = 0o641;
const SECRET_BYTES = `${RAW.padEnd(SECRET_SIZE - 1, "x")}\n`;
const SECRET_DIGEST = sha256Bytes(Buffer.from(SECRET_BYTES));
const SECRET_POLICY_PATH = "src/secret-zone";

function secretPolicy(policy: M4ScopedToolPolicyDocument): M4ScopedToolPolicyDocument {
  const { content_sha256: _content, ...body } = policy;
  const authorities = [
    ...policy.path_authorities.map((entry) => entry.path === "src" ? { ...entry, data_class: "PRIVATE_SOURCE" as const, raw_read_approved: true } : entry),
    { path: FULL_PATH, kind: "EXACT" as const, ownership_class: "OWNER_ACCEPTED_MUTABLE" as const, data_class: "SECRET" as const, raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
    { path: `${SECRET_POLICY_PATH}/nested`, kind: "PREFIX" as const, ownership_class: "OWNER_ACCEPTED_MUTABLE" as const, data_class: "SECRET" as const, raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
  ];
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
    ...body,
    command_readable_paths: policy.command_readable_paths.filter((entry) => entry.path !== "src"),
    path_authorities: authorities,
    evidence_readable_kinds: [...policy.evidence_readable_kinds, "M4_COMMAND_CATALOG", "M4_TOOL_POLICY"],
  }) as M4ScopedToolPolicyDocument;
}

async function secretFixture() {
  return createM4Fixture(async (fixture, temporaryRoot) => [await commandSpecification("secret-catalog", "INSPECTION", "/usr/bin/printf", [RAW, FULL_PATH, NESTED], {
    repositoryRoot: fixture.repository,
    executionInputs: [join(fixture.repository, FULL_PATH), join(fixture.repository, SECRET_POLICY_PATH, "nested", "hidden.txt")],
  })], secretPolicy, async (fixture) => {
    await mkdir(join(fixture.repository, SECRET_POLICY_PATH, "nested"), { recursive: true });
    await writeFile(join(fixture.repository, FULL_PATH), SECRET_BYTES, { mode: SECRET_MODE });
    await chmod(join(fixture.repository, FULL_PATH), SECRET_MODE);
    await writeFile(join(fixture.repository, SECRET_POLICY_PATH, "nested", "hidden.txt"), `${NESTED}\n`, { mode: 0o600 });
    await git(fixture.repository, "add", FULL_PATH, `${SECRET_POLICY_PATH}/nested/hidden.txt`);
    await git(fixture.repository, "commit", "-m", "add secret evidence fixtures");
  });
}

function token(value: Awaited<ReturnType<typeof secretFixture>>): Sha256Digest {
  return gatewayToken(value);
}

async function evidenceError(value: Awaited<ReturnType<typeof secretFixture>>, kind: string, digest: Sha256Digest): Promise<{ readonly code: string | undefined; readonly values: readonly unknown[] }> {
  let caught: unknown;
  try { await value.gateway.read_evidence({ stateTokenContentSha256: token(value), kind, contentSha256: digest }); }
  catch (error: unknown) { caught = error; }
  return { code: gatewayCode(caught), values: [caught, String(caught)] };
}

test("m4-secret-evidence-complete-matrix: PUBLIC and explicitly permitted PRIVATE evidence remains readable", async () => {
  const value = await secretFixture();
  try {
    const publicRead = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "tracked.txt", offset: 0, length: 8, mode: "TEXT" });
    const privateRead = await value.gateway.read_scoped({ stateTokenContentSha256: token(value), path: "src/a.txt", offset: 0, length: 5, mode: "TEXT" });
    const publicEvidence = await value.gateway.read_evidence({ stateTokenContentSha256: token(value), kind: "M4_TOOL_REQUEST", contentSha256: publicRead.resultRecord.request_content_sha256 as Sha256Digest });
    const privateEvidence = await value.gateway.read_evidence({ stateTokenContentSha256: token(value), kind: "M4_TOOL_REQUEST", contentSha256: privateRead.resultRecord.request_content_sha256 as Sha256Digest });
    assert.equal(publicEvidence.document["path"], "tracked.txt");
    assert.equal(privateEvidence.document["path"], "src/a.txt");
    assertNoForbiddenSecretValues(publicEvidence, [FULL_PATH, "b.txt", SECRET_POLICY_PATH, RAW, NESTED, SECRET_DIGEST], [SECRET_SIZE, SECRET_MODE]);
    assertNoForbiddenSecretValues(privateEvidence, [FULL_PATH, "b.txt", SECRET_POLICY_PATH, RAW, NESTED, SECRET_DIGEST], [SECRET_SIZE, SECRET_MODE]);
  } finally { await disposeM4(value); }
});

test("m4-secret-evidence-complete-matrix: exact, descendant, multiple, nested, execution-input, digest, size, and mode references reject without projection", async () => {
  const value = await secretFixture();
  try {
    const catalog = value.catalog;
    const result = await evidenceError(value, "M4_COMMAND_CATALOG", catalog.content_sha256 as Sha256Digest);
    assert.equal(result.code, "SECRET_METADATA_FORBIDDEN");
    for (const exposed of result.values) assertNoForbiddenSecretValues(exposed, [FULL_PATH, "b.txt", SECRET_POLICY_PATH, RAW, NESTED, SECRET_DIGEST], [SECRET_SIZE, SECRET_MODE]);
    const recordsRoot = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records");
    for (const directory of ["tool-results", "command-results", "mutation-receipts"]) {
      for (const name of await readdir(join(recordsRoot, directory))) {
        const record = JSON.parse(await readFile(join(recordsRoot, directory, name), "utf8")) as unknown;
        assertNoForbiddenSecretValues(record, [FULL_PATH, "b.txt", SECRET_POLICY_PATH, RAW, NESTED, SECRET_DIGEST], [SECRET_SIZE, SECRET_MODE]);
      }
    }
  } finally { await disposeM4(value); }
});

test("m4-secret-evidence-complete-matrix: wrong run, repository, incomplete, wrong kind, and wrong identity produce typed authority failures", async () => {
  const value = await secretFixture();
  try {
    const catalog = value.catalog;
    const wrongRun = reidentify("pi_gacw_command_catalog_v0", catalog, (draft) => { draft["run_id"] = "wrong-run"; }) as M4CommandCatalogDocument;
    const wrongRepository = reidentify("pi_gacw_command_catalog_v0", catalog, (draft) => { draft["repository_identity_content_sha256"] = `sha256:${"a".repeat(64)}`; }) as M4CommandCatalogDocument;
    const incomplete = reidentify("pi_gacw_command_catalog_v0", catalog, (draft) => { draft["tool_policy_content_sha256"] = `sha256:${"b".repeat(64)}`; }) as M4CommandCatalogDocument;
    await persistM4(value, "COMMAND_CATALOG", wrongRun);
    await persistM4(value, "COMMAND_CATALOG", wrongRepository);
    await persistM4(value, "COMMAND_CATALOG", incomplete);
    assert.equal((await evidenceError(value, "M4_COMMAND_CATALOG", wrongRun.content_sha256 as Sha256Digest)).code, "PATH_NOT_READABLE");
    assert.equal((await evidenceError(value, "M4_COMMAND_CATALOG", wrongRepository.content_sha256 as Sha256Digest)).code, "PATH_NOT_READABLE");
    assert.equal((await evidenceError(value, "M4_COMMAND_CATALOG", incomplete.content_sha256 as Sha256Digest)).code, "PATH_NOT_READABLE");
    assert.equal((await evidenceError(value, "M4_TOOL_POLICY", catalog.content_sha256 as Sha256Digest)).code, "EVIDENCE_NOT_FOUND");
    assert.equal((await evidenceError(value, "M4_COMMAND_CATALOG", `sha256:${"c".repeat(64)}`)).code, "EVIDENCE_NOT_FOUND");
    for (const digest of [wrongRun.content_sha256, wrongRepository.content_sha256, incomplete.content_sha256]) {
      const error = await evidenceError(value, "M4_COMMAND_CATALOG", digest as Sha256Digest);
      for (const exposed of error.values) assertNoForbiddenSecretValues(exposed, [FULL_PATH, "b.txt", SECRET_POLICY_PATH, RAW, NESTED, SECRET_DIGEST], [SECRET_SIZE, SECRET_MODE]);
    }
  } finally { await disposeM4(value); }
});

test("m4-secret-evidence-complete-matrix: an otherwise valid but unreferenced public record is not promoted or redacted", async () => {
  const value = await secretFixture();
  try {
    const publicCatalog = reidentify("pi_gacw_command_catalog_v0", value.catalog, (draft) => {
      draft["commands"] = [];
      draft["catalog_id"] = "unreferenced-public-catalog";
    }) as M4CommandCatalogDocument;
    await persistM4(value, "COMMAND_CATALOG", publicCatalog);
    assert.equal(await classification(value, publicCatalog.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    const read = await value.gateway.read_evidence({ stateTokenContentSha256: token(value), kind: "M4_COMMAND_CATALOG", contentSha256: publicCatalog.content_sha256 as Sha256Digest });
    assert.deepEqual(read.document["commands"], []);
    assert.equal(read.resultRecord.outcome, "PASS");
  } finally { await disposeM4(value); }
});

test("m4-secret-evidence-complete-matrix: malformed storage is rejected before any secret projection", async () => {
  const value = await secretFixture();
  try {
    const digest = sha256Bytes(Buffer.from("r3-invalid-record")).toString() as Sha256Digest;
    const path = m4RecordPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, "COMMAND_CATALOG", digest);
    await writeFile(path, "{\"schema_id\":\"pi_gacw_command_catalog_v0\"}\n", { mode: 0o600 });
    const result = await evidenceError(value, "M4_COMMAND_CATALOG", digest);
    assert.equal(result.code, "FAST_PREFLIGHT_FAILED");
    for (const exposed of result.values) assertNoForbiddenSecretValues(exposed, [FULL_PATH, "b.txt", SECRET_POLICY_PATH, RAW, NESTED, SECRET_DIGEST], [SECRET_SIZE, SECRET_MODE]);
  } finally { await disposeM4(value); }
});
