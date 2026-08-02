import assert from "node:assert/strict";
import { mkdir, readFile, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer } from "node:net";
import test from "node:test";

import { identifyContractDocument, type M3RepositoryIdentityDocument } from "../src/schemas/index.js";
import { sha256Bytes } from "../src/identity/index.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { createSecureFilesystem, probeSecureFilesystemCapabilities, SecureFilesystemError } from "../src/secure-fs/index.js";
import { secureMutation } from "../src/secure-fs/client.js";
import { mutationJournalForError } from "../src/secure-fs/helper.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof SecureFilesystemError ? error.code : (error as { code?: unknown }).code; }
async function listen(path: string, action: () => Promise<void>) {
  const server = createServer((connection) => { let data = ""; connection.on("data", async (chunk) => {
    data += chunk.toString(); if (!data.includes("\n")) return; try { await action(); connection.end("1"); } catch { connection.destroy(); }
  }); });
  await new Promise<void>((resolve, reject) => server.listen(path, resolve).once("error", reject)); return server;
}

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

test("mutation-receipt-journal: exchange/preimage mismatch preserves rollback activity", async () => {
  const value = await authorityFixture(); const socket = join(value.fixture.root, "journal.sock");
  try {
    const filesystem = await createSecureFilesystem({ repository: value.repository, capability: value.capability, readablePaths: [{ path: "tracked.txt", kind: "EXACT" }] });
    const path = value.fixture.trackedPath; const beforeBytes = await readFile(path); const beforeStat = await stat(path);
    const expected = { digest: sha256Bytes(beforeBytes), size: beforeBytes.byteLength, mode: beforeStat.mode & 0o777 };
    const displaced = join(value.fixture.repository, "displaced.txt");
    const server = await listen(socket, async () => { await rename(path, displaced); await writeFile(path, beforeBytes, { mode: expected.mode }); });
    setSecureFilesystemTestHooks({ checkpointSocket: socket, checkpointStage: "BEFORE_RENAME" });
    let caught: unknown;
    try { await secureMutation(filesystem, { operation: "REPLACE", path: "tracked.txt", expected, replacement: Buffer.from("replacement\n"), finalMode: expected.mode, hashLimitBytes: 1024 }); }
    catch (error: unknown) { caught = error; }
    assert.equal(code(caught), "PREIMAGE_MISMATCH"); const journal = mutationJournalForError(caught);
    assert.equal(journal?.atomic_rename_attempted, true); assert.equal(journal?.atomic_rename_completed, true);
    assert.equal(journal?.rollback_required, true); assert.equal(journal?.rollback_attempted, true); assert.equal(journal?.rollback_completed, true);
    assert.equal(journal?.rollback_directory_fsync_completed, true); assert.equal(await readFile(path, "utf8"), "initial\n");
    await new Promise<void>((resolve) => server.close(() => resolve()));
  } finally { resetSecureFilesystemTestHooks(); await removeRepositoryFixture(value.fixture); }
});
