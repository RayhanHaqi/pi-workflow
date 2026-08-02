import assert from "node:assert/strict";
import { copyFile, mkdir, readFile, readdir, rename, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer, type Server } from "node:net";
import test from "node:test";

import type { Sha256Digest } from "../src/identity/index.js";
import type { M4CommandResultDocument } from "../src/schemas/index.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { git, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof ScopedToolGatewayError ? error.code : error !== null && typeof error === "object" ? (error as { code?: unknown }).code : undefined; }
function token(value: Awaited<ReturnType<typeof createM4Fixture>>): Sha256Digest { return value.gateway.acceptedState.content_sha256 as Sha256Digest; }
async function closeServer(server: Server | undefined): Promise<void> { if (server !== undefined) await new Promise<void>((resolve) => server.close(() => resolve())); }
async function controller(path: string, action: () => Promise<void>): Promise<Server> {
  const server = createServer((connection) => { let data = ""; connection.on("data", (chunk) => { data += chunk.toString(); if (!data.includes("\n")) return; void action().then(() => connection.end("1"), () => connection.destroy()); }); });
  await new Promise<void>((resolve, reject) => server.listen(path, resolve).once("error", reject)); return server;
}
async function commandResults(value: Awaited<ReturnType<typeof createM4Fixture>>): Promise<M4CommandResultDocument[]> {
  const root = join(value.fixture.stateRoot, "runs", value.fixture.runId, "records", "command-results");
  return Promise.all((await readdir(root)).map(async (name) => JSON.parse(await readFile(join(root, name), "utf8")) as M4CommandResultDocument));
}
async function cleanup(value: Awaited<ReturnType<typeof createM4Fixture>>): Promise<void> { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }

async function cwdCommand(fixture: { repository: string }, temporaryRoot: string, cwd: string, markerName = "cwd-ran") {
  const marker = join(temporaryRoot, markerName); const script = join(temporaryRoot, `${markerName}.py`);
  await writeFile(script, `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('ran')\n`, { mode: 0o600 });
  return { marker, specification: await commandSpecification(markerName, "INSPECTION", "/usr/bin/python3", [script], { repositoryRoot: fixture.repository, cwd }) };
}

test("m4-command-cwd-identity: catalog admission rejects moved, deleted, replaced, cross-repository, outside, and out-of-policy cwd", async (t) => {
  const cases: ReadonlyArray<[string, (fixture: { repository: string }, temporaryRoot: string) => Promise<Awaited<ReturnType<typeof commandSpecification>>>, string]> = [
    ["moved after catalog construction", async (fixture, temporaryRoot) => { const value = await cwdCommand(fixture, temporaryRoot, "src", "moved"); await rename(join(fixture.repository, "src"), join(fixture.repository, "src-held")); return value.specification; }, "COMMAND_CWD_IDENTITY_DRIFT"],
    ["deleted after catalog construction", async (fixture, temporaryRoot) => { const value = await cwdCommand(fixture, temporaryRoot, "src", "deleted"); await rm(join(fixture.repository, "src"), { recursive: true }); return value.specification; }, "COMMAND_CWD_IDENTITY_DRIFT"],
    ["replaced by identical directory before admission", async (fixture, temporaryRoot) => { const value = await cwdCommand(fixture, temporaryRoot, "src", "identical"); const src = join(fixture.repository, "src"); await rename(src, `${src}-held`); await mkdir(src); await copyFile(join(`${src}-held`, "a.txt"), join(src, "a.txt")); await copyFile(join(`${src}-held`, "b.txt"), join(src, "b.txt")); return value.specification; }, "COMMAND_CWD_IDENTITY_DRIFT"],
    ["replaced by symlink before admission", async (fixture, temporaryRoot) => { const value = await cwdCommand(fixture, temporaryRoot, "src", "symlink"); const src = join(fixture.repository, "src"); await rename(src, `${src}-held`); await symlink(`${src}-held`, src); return value.specification; }, "COMMAND_CWD_IDENTITY_DRIFT"],
    ["outside repository canonical escape", async (fixture, temporaryRoot) => cwdCommand(fixture, temporaryRoot, "../outside", "outside").then((value) => value.specification), "INVALID_CANONICAL_PATH"],
    ["outside command-policy scope", async (fixture, temporaryRoot) => cwdCommand(fixture, temporaryRoot, "unreadable", "scope").then((value) => value.specification), "COMMAND_CWD_IDENTITY_DRIFT"],
    ["noncanonical cwd", async (fixture, temporaryRoot) => cwdCommand(fixture, temporaryRoot, "src/../src", "noncanonical").then((value) => value.specification), "INVALID_CANONICAL_PATH"],
    ["absolute cwd", async (fixture, temporaryRoot) => cwdCommand(fixture, temporaryRoot, fixture.repository, "absolute").then((value) => value.specification), "INVALID_CANONICAL_PATH"],
  ];
  for (const [label, make, expected] of cases) await t.test(label, async () => {
    let caught: unknown;
    try {
      await createM4Fixture(async (fixture, temporaryRoot) => [await make(fixture, temporaryRoot)], null, label === "outside command-policy scope" ? async (fixture) => {
        await mkdir(join(fixture.repository, "unreadable")); await writeFile(join(fixture.repository, "unreadable", "file"), "x\n"); await git(fixture.repository, "add", "unreadable"); await git(fixture.repository, "commit", "-m", "add out-of-policy cwd");
      } : label === "outside repository canonical escape" ? async (fixture) => { await mkdir(join(fixture.root, "outside")); } : null);
    } catch (error: unknown) { caught = error; }
    assert.equal(code(caught), expected, `${label}: ${String(code(caught))}`);
  });
  await t.test("cwd belongs to another valid linked Git worktree", async () => {
    let caught: unknown;
    try {
      await createM4Fixture(async (fixture, temporaryRoot) => [(await cwdCommand(fixture, temporaryRoot, "cwd-worktree", "linked-worktree")).specification], null, async (fixture) => {
        await writeFile(join(fixture.repository, ".git", "info", "exclude"), "cwd-worktree/\n");
        await git(fixture.repository, "worktree", "add", "--detach", join(fixture.repository, "cwd-worktree"));
      });
    } catch (error: unknown) { caught = error; }
    assert.equal(code(caught), "COMMAND_CWD_IDENTITY_DRIFT");
  });
});

test("m4-command-cwd-identity: synchronized replacements are blocked before the command body", async (t) => {
  for (const [label, cwd, stage, mutate] of [
    ["replaced after admission before helper cwd open", "src", "BEFORE_LANDLOCK", async (repository: string) => { const src = join(repository, "src"); await rename(src, `${src}-held`); await mkdir(src); await copyFile(join(`${src}-held`, "a.txt"), join(src, "a.txt")); await copyFile(join(`${src}-held`, "b.txt"), join(src, "b.txt")); }],
    ["replaced after helper retained cwd FD", "src", "CWD_OPENED", async (repository: string) => { const src = join(repository, "src"); await rename(src, `${src}-held`); await mkdir(src); await copyFile(join(`${src}-held`, "a.txt"), join(src, "a.txt")); await copyFile(join(`${src}-held`, "b.txt"), join(src, "b.txt")); }],
    ["cwd parent replaced", "src/nested", "BEFORE_LANDLOCK", async (repository: string) => { const src = join(repository, "src"); await rename(src, `${src}-held`); await mkdir(src); await mkdir(join(src, "nested")); }],
  ] as const) await t.test(label, async () => {
    let marker = ""; const value = await createM4Fixture(async (fixture, temporaryRoot) => { const command = await cwdCommand(fixture, temporaryRoot, cwd, label.replaceAll(" ", "-")); marker = command.marker; return [command.specification]; }, null,
      cwd === "src/nested" ? async (fixture) => { await mkdir(join(fixture.repository, "src", "nested")); await writeFile(join(fixture.repository, "src", "nested", "file"), "x\n"); await git(fixture.repository, "add", "src/nested"); await git(fixture.repository, "commit", "-m", "add nested cwd"); } : null);
    const before = token(value); const socket = join(value.fixture.root, `${stage}-${cwd.replace("/", "-")}.sock`); let server: Server | undefined;
    try {
      server = await controller(socket, async () => mutate(value.fixture.repository)); setSecureFilesystemTestHooks({ sandboxCheckpointSocket: socket, sandboxCheckpointStage: stage });
      await assert.rejects(value.gateway.run_inspection_command({ commandId: label.replaceAll(" ", "-"), stateTokenContentSha256: before }), (error: unknown) => code(error) === "COMMAND_CWD_IDENTITY_DRIFT");
      await assert.rejects(stat(marker), { code: "ENOENT" }); assert.equal(token(value), before);
      const records = await commandResults(value); const record = records.find((entry) => entry.command_id === label.replaceAll(" ", "-")); assert.equal(record?.outcome, "BLOCKED"); assert.equal(record?.failure_code, "COMMAND_CWD_IDENTITY_DRIFT"); assert.equal(record?.state_token_after, null);
    } finally {
      resetSecureFilesystemTestHooks(); await closeServer(server); const src = join(value.fixture.repository, "src"); await rm(src, { recursive: true, force: true }); await rename(`${src}-held`, src).catch(() => {}); await cleanup(value);
    }
  });
});

test("m4-command-cwd-identity: unchanged repository root and permitted nested cwd execute", async () => {
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    const root = await cwdCommand(fixture, temporaryRoot, "REPOSITORY_ROOT", "positive-root"); const nested = await cwdCommand(fixture, temporaryRoot, "src", "positive-nested"); return [root.specification, nested.specification];
  });
  try {
    for (const id of ["positive-root", "positive-nested"]) { const result = await value.gateway.run_inspection_command({ commandId: id, stateTokenContentSha256: token(value) }); assert.equal(result.record.outcome, "PASS"); assert.equal(await readFile(join(value.temporaryRoot, id), "utf8"), "ran"); }
  } finally { await cleanup(value); }
});
