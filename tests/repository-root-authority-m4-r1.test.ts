import assert from "node:assert/strict";
import { mkdir, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { identifyContractDocument, type M3RepositoryIdentityDocument } from "../src/schemas/index.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { createSecureFilesystem, probeSecureFilesystemCapabilities, SecureFilesystemError } from "../src/secure-fs/index.js";
import { secureMutation } from "../src/secure-fs/client.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof SecureFilesystemError ? error.code : (error as { code?: unknown }).code; }

async function authorityFixture() {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const capability = await probeSecureFilesystemCapabilities();
  return { fixture, repository, capability };
}

test("repository-root-authority: public factory independently rejects reidentification and root replacement", async (t) => {
  await t.test("unchanged actual Git authority is accepted", async () => {
    const value = await authorityFixture(); try {
      const filesystem = await createSecureFilesystem({ repository: value.repository, capability: value.capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] });
      assert.equal(Buffer.from((await filesystem.readScoped({ path: "tracked.txt", offset: 0, length: 7, maximumBytes: 7, hashLimitBytes: 1024 })).dataBase64, "base64").toString(), "initial");
    } finally { await removeRepositoryFixture(value.fixture); }
  });
  await t.test("reidentified non-Git requested path is rejected", async () => {
    const value = await authorityFixture(); try {
      const nonGit = join(value.fixture.root, "caller-owned"); await mkdir(nonGit);
      const { content_sha256: _content, ...body } = value.repository;
      const forged = identifyContractDocument("pi_gacw_repository_identity_v0", { ...body, requested_path: nonGit, physical_requested_path: nonGit }) as M3RepositoryIdentityDocument;
      await assert.rejects(createSecureFilesystem({ repository: forged, capability: value.capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] }),
        (error: unknown) => ["REPOSITORY_AUTHORITY_INVALID", "REPOSITORY_ROOT_MISMATCH"].includes(String(code(error))));
    } finally { await removeRepositoryFixture(value.fixture); }
  });
  await t.test("construction-time root inode replacement is rejected", async () => {
    const value = await authorityFixture(); const moved = `${value.fixture.repository}.moved`;
    try {
      setSecureFilesystemTestHooks({ beforeRepositoryRevalidation: async () => { await rename(value.fixture.repository, moved); await mkdir(value.fixture.repository); } });
      await assert.rejects(createSecureFilesystem({ repository: value.repository, capability: value.capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] }),
        (error: unknown) => ["REPOSITORY_AUTHORITY_INVALID", "REPOSITORY_ROOT_MISMATCH"].includes(String(code(error))));
    } finally {
      resetSecureFilesystemTestHooks(); await rm(value.fixture.repository, { recursive: true, force: true }); await rename(moved, value.fixture.repository).catch(() => {}); await removeRepositoryFixture(value.fixture);
    }
  });
});

test("installed-inode-binding: retained temporary FD is the installed CREATE inode", async () => {
  const value = await authorityFixture(); try {
    const filesystem = await createSecureFilesystem({ repository: value.repository, capability: value.capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] });
    const outcome = await secureMutation(filesystem, { operation: "CREATE", path: "created.txt", expected: { digest: null, size: null, mode: null }, replacement: Buffer.from("same bytes\n"), finalMode: 0o644, hashLimitBytes: 1024 });
    const installed = await stat(join(value.fixture.repository, "created.txt"));
    assert.equal(outcome.after?.inode, installed.ino); assert.equal(outcome.after?.device, installed.dev); assert.equal(outcome.journal.final_verification, "PASS");
  } finally { await removeRepositoryFixture(value.fixture); }
});
