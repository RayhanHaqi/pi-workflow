import assert from "node:assert/strict";
import { chmod, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { identifyContractDocument, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { createScopedToolGateway, ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { commandSpecification, createM4Fixture, makeM4Catalog } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { git, removeRepositoryFixture } from "./repository-helpers.js";

const SENTINEL = "TOP_SECRET_SENTINEL_7d2a";
function code(error: unknown): unknown { return error instanceof ScopedToolGatewayError ? error.code : error !== null && typeof error === "object" ? (error as { code?: unknown }).code : undefined; }
function secretPolicy(policy: M4ScopedToolPolicyDocument): M4ScopedToolPolicyDocument {
  const { content_sha256: _content, ...body } = policy;
  const authorities = [
    ...policy.path_authorities.map((entry) => entry.path === "src" ? { ...entry, data_class: "PRIVATE_SOURCE" as const, raw_read_approved: true } : entry),
    { path: "src/b.txt", kind: "EXACT" as const, ownership_class: "OWNER_ACCEPTED_MUTABLE" as const, data_class: "SECRET" as const, raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
    { path: "src/nested", kind: "PREFIX" as const, ownership_class: "OWNER_ACCEPTED_MUTABLE" as const, data_class: "SECRET" as const, raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
  ];
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...body, command_readable_paths: policy.command_readable_paths.filter((entry) => entry.path !== "src"),
    path_authorities: authorities, evidence_readable_kinds: [...policy.evidence_readable_kinds, "M4_COMMAND_CATALOG"] }) as M4ScopedToolPolicyDocument;
}

test("secret-metadata-isolation: restrictive descendants override broad PRIVATE/PUBLIC readability", async () => {
  const value = await createM4Fixture(async (fixture) => [await commandSpecification("evidence-fixture", "INSPECTION", "/usr/bin/printf", ["safe"], {
    repositoryRoot: fixture.repository,
    readPaths: [{ path: "src/b.txt", kind: "EXACT" }, { path: "src/nested", kind: "PREFIX" }],
    executionInputs: [join(fixture.repository, "src", "b.txt"), join(fixture.repository, "src", "nested", "hidden.txt")],
  })], null, async (fixture) => {
    await writeFile(join(fixture.repository, "src", "b.txt"), `${SENTINEL}\n`, { mode: 0o640 });
    await mkdir(join(fixture.repository, "src", "nested")); await writeFile(join(fixture.repository, "src", "nested", "hidden.txt"), `${SENTINEL}-NESTED\n`, { mode: 0o600 });
    await git(fixture.repository, "add", "src/b.txt", "src/nested/hidden.txt"); await git(fixture.repository, "commit", "-m", "add secret projection fixtures");
  });
  const restrictivePolicy = secretPolicy(value.policy); const restrictiveCatalog = makeM4Catalog(value.fixture, value.admission, restrictivePolicy, []);
  const restrictiveTemporaryRoot = join(value.fixture.root, "controller-secret");
  try {
    await mkdir(restrictiveTemporaryRoot, { mode: 0o700 }); await chmod(restrictiveTemporaryRoot, 0o700);
    const restrictiveGateway = await createScopedToolGateway({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId, repository: value.admission.repository,
    baseline: value.admission.baseline, acceptedState: value.admission.full.acceptedState, lock: value.admission.lock,
    instructionFiles: value.admission.selected.instructions, authorityFiles: value.admission.selected.authorities,
    editablePaths: value.admission.editable, frozenPaths: value.admission.frozen, taskScopeIdentity: value.admission.taskScopeIdentity,
      toolPolicy: restrictivePolicy, commandCatalog: restrictiveCatalog, temporaryRoot: restrictiveTemporaryRoot });
    const token = (): Sha256Digest => restrictiveGateway.acceptedState.content_sha256 as Sha256Digest;
  const exposed: string[] = [];
  try {
    for (const hashFiles of [false, true]) {
      const listed = await restrictiveGateway.list_scoped({ stateTokenContentSha256: token(), path: "src", maximumDepth: 8, hashFiles });
      const encoded = JSON.stringify(listed); exposed.push(encoded);
      assert.deepEqual(listed.entries.map((entry) => entry.path), ["src/a.txt"]);
    }
    for (const path of ["src/b.txt", "src/nested", "src/nested/hidden.txt"]) {
      let caught: unknown; try { await restrictiveGateway.read_scoped({ stateTokenContentSha256: token(), path, offset: 0, length: 1024, mode: "TEXT" }); } catch (error: unknown) { caught = error; }
      assert.equal(code(caught), "SECRET_METADATA_FORBIDDEN"); exposed.push(String(caught));
    }
    const searched = await restrictiveGateway.search_scoped({ stateTokenContentSha256: token(), literal: SENTINEL, caseSensitive: true, includePaths: ["src"], excludePaths: [], maximumFiles: 100, maximumBytes: 100_000, maximumMatches: 100, maximumLineLength: 10_000 });
    exposed.push(JSON.stringify(searched)); assert.deepEqual(searched.matches, []); assert.equal(searched.filesSearched, 1);
    const files = await restrictiveGateway.inspect_git_scoped({ stateTokenContentSha256: token(), operation: "LS_FILES", path: null }); exposed.push(Buffer.from(files.output, "base64").toString());
    assert.doesNotMatch(exposed.at(-1)!, /src\/b\.txt|src\/nested/u);
    let gitError: unknown; try { await restrictiveGateway.inspect_git_scoped({ stateTokenContentSha256: token(), operation: "SHOW_PATH_AT_HEAD", path: "src/b.txt" }); } catch (error: unknown) { gitError = error; }
    assert.equal(code(gitError), "SECRET_METADATA_FORBIDDEN"); exposed.push(String(gitError));
    const publicRead = await value.gateway.read_scoped({ stateTokenContentSha256: value.gateway.acceptedState.content_sha256 as Sha256Digest, path: "tracked.txt", offset: 0, length: 7, mode: "TEXT" });
    const privateRead = await value.gateway.read_scoped({ stateTokenContentSha256: value.gateway.acceptedState.content_sha256 as Sha256Digest, path: "src/a.txt", offset: 0, length: 5, mode: "TEXT" });
    for (const safe of [publicRead, privateRead]) {
      const safeEvidence = await restrictiveGateway.read_evidence({ stateTokenContentSha256: token(), kind: "M4_TOOL_REQUEST", contentSha256: safe.resultRecord.request_content_sha256 as Sha256Digest });
      exposed.push(JSON.stringify(safeEvidence));
    }
    let evidenceError: unknown; try { await restrictiveGateway.read_evidence({ stateTokenContentSha256: token(), kind: "M4_COMMAND_CATALOG", contentSha256: value.catalog.content_sha256 as Sha256Digest }); } catch (error: unknown) { evidenceError = error; }
    assert.equal(code(evidenceError), "SECRET_METADATA_FORBIDDEN"); exposed.push(String(evidenceError));
    const secretDigest = sha256Bytes(Buffer.from(`${SENTINEL}\n`));
    for (const forbidden of [SENTINEL, "src/b.txt", "b.txt", "src/nested", "hidden.txt", secretDigest]) assert.equal(exposed.some((entry) => entry.includes(forbidden)), false, forbidden);
    const recordRoot = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records");
    const names = await readdir(recordRoot, { recursive: true });
    for (const name of names) {
      const path = join(recordRoot, name); try { assert.doesNotMatch(await readFile(path, "utf8"), new RegExp(SENTINEL, "u")); } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== "EISDIR") throw error; }
    }
    } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
  } catch (error: unknown) {
    await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); throw error;
  }
});
