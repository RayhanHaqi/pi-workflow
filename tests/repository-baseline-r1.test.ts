import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:net";
import { promisify } from "node:util";
import { chmod, copyFile, mkdir, readFile, readdir, rename, rm, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  verifyBaselineApproval,
  type BaselinePathDecision,
} from "../src/repository/index.js";
import {
  baselineInput,
  codeOf,
  pathDecision,
} from "./repository-matrix-helpers.js";
import {
  createRepositoryFixture,
  git,
  removeRepositoryFixture,
} from "./repository-helpers.js";

const execFileAsync = promisify(execFile);

async function withLock<T>(
  fixture: Awaited<ReturnType<typeof createRepositoryFixture>>,
  operation: (lock: Awaited<ReturnType<typeof acquireWorktreeLock>>) => Promise<T>,
): Promise<T> {
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    return await operation(lock);
  } finally {
    await releaseWorktreeLock(lock).catch(() => undefined);
  }
}

test("CLEAN_REQUIRED rejects conflicts, every operation marker, and index.lock with no baseline record", async (t) => {
  await t.test("unmerged conflict", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await git(fixture.repository, "checkout", "-b", "conflict-side");
      await writeFile(fixture.trackedPath, "side\n");
      await git(fixture.repository, "add", "tracked.txt");
      await git(fixture.repository, "commit", "-m", "side");
      await git(fixture.repository, "checkout", "main");
      await writeFile(fixture.trackedPath, "main\n");
      await git(fixture.repository, "add", "tracked.txt");
      await git(fixture.repository, "commit", "-m", "main");
      await assert.rejects(git(fixture.repository, "merge", "conflict-side"));
      await unlink(join(fixture.repository, ".git", "MERGE_HEAD"));
      await withLock(fixture, async (lock) => {
        await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", [])),
          (error: unknown) => codeOf(error) === "GIT_CONFLICT_PRESENT");
      });
      assert.equal((await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines"))).length, 0);
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });

  const operationFixtures: readonly [string, string, "file" | "directory"][] = [
    ["merge", "MERGE_HEAD", "file"],
    ["rebase-merge", "rebase-merge", "directory"],
    ["rebase-apply", "rebase-apply", "directory"],
    ["cherry-pick", "CHERRY_PICK_HEAD", "file"],
    ["revert", "REVERT_HEAD", "file"],
    ["bisect", "BISECT_LOG", "file"],
  ];
  for (const [name, marker, kind] of operationFixtures) {
    await t.test(`${name} in progress`, async () => {
      const fixture = await createRepositoryFixture();
      try {
        const gitDirectory = join(fixture.repository, ".git");
        if (kind === "directory") await mkdir(join(gitDirectory, marker), { mode: 0o700 });
        else await writeFile(join(gitDirectory, marker), `${await git(fixture.repository, "rev-parse", "HEAD")}`);
        await withLock(fixture, async (lock) => {
          await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", [])),
            (error: unknown) => codeOf(error) === "GIT_OPERATION_IN_PROGRESS");
        });
        assert.equal((await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines"))).length, 0);
      } finally {
        await removeRepositoryFixture(fixture);
      }
    });
  }

  await t.test("index.lock", async () => {
    const fixture = await createRepositoryFixture();
    try {
      await writeFile(join(fixture.repository, ".git", "index.lock"), "", { mode: 0o600 });
      await withLock(fixture, async (lock) => {
        await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "CLEAN_REQUIRED", [])),
          (error: unknown) => codeOf(error) === "GIT_INDEX_LOCK_PRESENT");
      });
    } finally {
      await removeRepositoryFixture(fixture);
    }
  });
});

test("unchanged clean capture is byte-identical with identical domain and content identities", async () => {
  const fixture = await createRepositoryFixture();
  try {
    await withLock(fixture, async (lock) => {
      const input = await baselineInput(fixture, lock, "CLEAN_REQUIRED", []);
      const first = await captureBaseline(input);
      const bytes = await readFile(join(fixture.stateRoot, "runs", fixture.runId, first.recordRelativePath));
      const second = await captureBaseline(input);
      assert.equal(second.recordRelativePath, first.recordRelativePath);
      assert.equal(second.baseline.content_sha256, first.baseline.content_sha256);
      assert.equal(second.baseline.accepted_baseline.content_sha256, first.baseline.accepted_baseline.content_sha256);
      assert.equal(second.baseline.accepted_baseline.baseline_sha256, first.baseline.accepted_baseline.baseline_sha256);
      assert.deepEqual(await readFile(join(fixture.stateRoot, "runs", fixture.runId, second.recordRelativePath)), bytes);
    });
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("approved dirty inventory is NUL-safe across status, file, rename, deletion, mode, and content forms", async () => {
  const fixture = await createRepositoryFixture();
  try {
    for (const name of ["delete.txt", "mode.txt", "rename.txt", "mixed.txt", "staged.txt", "unstaged.txt"]) {
      await writeFile(join(fixture.repository, name), `${name}\n`);
    }
    await git(fixture.repository, "add", "delete.txt", "mode.txt", "rename.txt", "mixed.txt", "staged.txt", "unstaged.txt");
    await git(fixture.repository, "commit", "-m", "dirty matrix sources");

    await writeFile(join(fixture.repository, "staged.txt"), "staged-only\n");
    await git(fixture.repository, "add", "staged.txt");
    await writeFile(join(fixture.repository, "unstaged.txt"), "unstaged-only\n");
    await writeFile(join(fixture.repository, "mixed.txt"), "mixed-index\n");
    await git(fixture.repository, "add", "mixed.txt");
    await writeFile(join(fixture.repository, "mixed.txt"), "mixed-worktree\n");
    await git(fixture.repository, "mv", "rename.txt", "renamed ü.txt");
    await unlink(join(fixture.repository, "delete.txt"));
    await chmod(join(fixture.repository, "mode.txt"), 0o755);
    await writeFile(join(fixture.repository, "empty.txt"), "");
    await writeFile(join(fixture.repository, "binary.bin"), Buffer.from([0, 255, 1, 254]));
    await writeFile(join(fixture.repository, "line\nbreak.txt"), "newline-name\n");

    const expectedPaths = [
      "binary.bin", "delete.txt", "empty.txt", "line\nbreak.txt", "mixed.txt", "mode.txt", "rename.txt",
      "renamed ü.txt", "staged.txt", "unstaged.txt",
    ].sort();
    await withLock(fixture, async (lock) => {
      const captured = await captureBaseline(await baselineInput(
        fixture,
        lock,
        "APPROVED_BASELINE_DIRTY",
        expectedPaths.map((path) => pathDecision(path)),
      ));
      assert.deepEqual(captured.baseline.paths.map((entry) => entry.path), expectedPaths);
      assert.ok(captured.baseline.git_fingerprint.staged.some((entry) => entry.path === "staged.txt"));
      assert.ok(captured.baseline.git_fingerprint.unstaged.some((entry) => entry.path === "unstaged.txt"));
      assert.ok(captured.baseline.git_fingerprint.staged.some((entry) => entry.path === "mixed.txt"));
      assert.ok(captured.baseline.git_fingerprint.unstaged.some((entry) => entry.path === "mixed.txt"));
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "delete.txt")?.file_type, "DELETED");
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "mode.txt")?.mode, 0o755);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "empty.txt")?.size, 0);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "binary.bin")?.size, 4);
      assert.ok(captured.baseline.paths.some((entry) => entry.path.includes("\n")));
    });
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

test("staged copy inventory is exact where local Git reports copy detection", async () => {
  const fixture = await createRepositoryFixture();
  try {
    await git(fixture.repository, "config", "status.renames", "copies");
    await copyFile(fixture.trackedPath, join(fixture.repository, "copied.txt"));
    await git(fixture.repository, "add", "copied.txt");
    await withLock(fixture, async (lock) => {
      const captured = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [pathDecision("copied.txt")]));
      const entry = captured.baseline.git_fingerprint.staged.find((item) => item.path === "copied.txt");
      assert.ok(entry);
      assert.ok(entry.status === "A" || entry.status === "C");
      if (entry.status === "C") assert.equal(entry.old_path, "tracked.txt");
    });
  } finally {
    await removeRepositoryFixture(fixture);
  }
});

async function approvalScenario(
  mutate: (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, decision: BaselinePathDecision) => Promise<BaselinePathDecision>,
): Promise<void> {
  const fixture = await createRepositoryFixture();
  try {
    await writeFile(join(fixture.repository, "owner.txt"), "owner-v1\n");
    await withLock(fixture, async (lock) => {
      const initialDecision = pathDecision("owner.txt");
      const first = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [initialDecision]));
      const approval = (await createBaselineApproval({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        baseline: first.baseline,
        approvedBy: "owner",
        approvedAt: "2026-01-01T00:00:00.000Z",
      })).approval;
      assert.equal(await verifyBaselineApproval({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        baseline: first.baseline,
        approval,
      }), true);
      const nextDecision = await mutate(fixture, initialDecision);
      const next = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [nextDecision]));
      assert.equal(await verifyBaselineApproval({
        stateRoot: fixture.stateRoot,
        runId: fixture.runId,
        baseline: next.baseline,
        approval,
      }), false);
    });
  } finally {
    await removeRepositoryFixture(fixture);
  }
}

test("dirty approval invalidates on every bound repository, status, policy, and byte decision", async (t) => {
  const cases: readonly [string, (fixture: Awaited<ReturnType<typeof createRepositoryFixture>>, decision: BaselinePathDecision) => Promise<BaselinePathDecision>][] = [
    ["bytes", async (fixture, decision) => { await writeFile(join(fixture.repository, "owner.txt"), "owner-v2\n"); return decision; }],
    ["mode", async (fixture, decision) => { await chmod(join(fixture.repository, "owner.txt"), 0o755); return decision; }],
    ["staged classification", async (fixture, decision) => { await git(fixture.repository, "add", "owner.txt"); return decision; }],
    ["branch", async (fixture, decision) => { await git(fixture.repository, "checkout", "-b", "approval-branch"); return decision; }],
    ["HEAD", async (fixture, decision) => {
      await writeFile(join(fixture.repository, "head-change.txt"), "head\n");
      await git(fixture.repository, "add", "head-change.txt");
      await git(fixture.repository, "commit", "-m", "HEAD changes while owner path remains dirty");
      return decision;
    }],
    ["ownership", async (_fixture, decision) => ({ ...decision, ownershipClass: "PREEXISTING_UNRELATED" })],
    ["data classification", async (_fixture, decision) => ({ ...decision, dataClass: "HASH_ONLY" })],
    ["capture mode", async (_fixture, decision) => ({ ...decision, captureMode: "BLOB", retentionDaysAfterTerminal: 30 })],
    ["retention decision", async (_fixture, decision) => ({ ...decision, captureMode: "BLOB", retentionDaysAfterTerminal: 29 })],
  ];
  for (const [name, mutate] of cases) await t.test(name, async () => approvalScenario(mutate));
});

test("dirty decision set rejects missing, duplicate, extra, and malformed path authority", async (t) => {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    await writeFile(join(fixture.repository, "owner.txt"), "owner\n");
    await t.test("snapshot path without decision and unclassified path", async () => {
      await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [])),
        (error: unknown) => codeOf(error) === "BASELINE_PATH_UNCLASSIFIED");
    });
    await t.test("duplicate decision", async () => {
      const value = pathDecision("owner.txt");
      await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [value, value])),
        (error: unknown) => codeOf(error) === "INVALID_ARGUMENT");
    });
    await t.test("approval path outside snapshot", async () => {
      await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        pathDecision("owner.txt"), pathDecision("tracked.txt"),
      ])), (error: unknown) => codeOf(error) === "BASELINE_APPROVAL_MISMATCH");
    });
    await t.test("unsupported NUL path", async () => {
      await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        pathDecision("owner\u0000.txt"),
      ])), (error: unknown) => codeOf(error) === "INVALID_ARGUMENT" || codeOf(error) === "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING");
    });
  } finally {
    await releaseWorktreeLock(lock);
    await removeRepositoryFixture(fixture);
  }
});

test("all data classes, conservative defaults, descendants, and restricted-content redaction are enforced", async (t) => {
  await t.test("public, private, sensitive, large, hash-only, unknown, and secret", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const restricted = "RESTRICTED_CLASSIFICATION_SENTINEL";
    try {
      for (const name of ["public.txt", "private.txt", "sensitive-hash.txt", "sensitive.txt", "large.bin", "hash.txt", "unknown.txt"]) {
        await writeFile(join(fixture.repository, name), restricted);
      }
      const decisions = [
        pathDecision("public.txt", { captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
        pathDecision("private.txt", { dataClass: "PRIVATE_SOURCE", captureMode: "HASH_ONLY" }),
        pathDecision("sensitive-hash.txt", { dataClass: "SENSITIVE", captureMode: "HASH_ONLY" }),
        pathDecision("sensitive.txt", { dataClass: "SENSITIVE", captureMode: "BLOB", explicitBlobApproval: true, retentionDaysAfterTerminal: 7 }),
        pathDecision("large.bin", { dataClass: "LARGE_BINARY" }),
        pathDecision("hash.txt", { dataClass: "HASH_ONLY" }),
        pathDecision("unknown.txt", { dataClass: null }),
      ];
      const captured = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", decisions));
      assert.ok(captured.baseline.paths.find((entry) => entry.path === "public.txt")?.blob);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "private.txt")?.blob, null);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "sensitive-hash.txt")?.blob, null);
      assert.ok(captured.baseline.paths.find((entry) => entry.path === "sensitive.txt")?.blob);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "large.bin")?.blob, null);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "hash.txt")?.blob, null);
      assert.equal(captured.baseline.paths.find((entry) => entry.path === "unknown.txt")?.data_class, "HASH_ONLY");
      assert.equal(JSON.stringify(captured).includes(restricted), false);

      await writeFile(join(fixture.repository, "secret.txt"), restricted);
      await assert.rejects(
        captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
          ...decisions,
          pathDecision("secret.txt", { dataClass: "SECRET" }),
        ])),
        (error: unknown) => codeOf(error) === "BASELINE_SECRET_PRESENT" &&
          !String(error).includes(restricted) && !JSON.stringify(error).includes(restricted),
      );
    } finally {
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("private and sensitive explicit approval and seven-day cap", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      await writeFile(join(fixture.repository, "private.txt"), "private");
      await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        pathDecision("private.txt", { dataClass: "PRIVATE_SOURCE", captureMode: "BLOB", retentionDaysAfterTerminal: 30 }),
      ])), (error: unknown) => codeOf(error) === "BASELINE_DIRTY_NOT_APPROVED");
      await writeFile(join(fixture.repository, "sensitive.txt"), "sensitive");
      await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        pathDecision("private.txt", { dataClass: "PRIVATE_SOURCE" }),
        pathDecision("sensitive.txt", { dataClass: "SENSITIVE", captureMode: "BLOB", explicitBlobApproval: true, retentionDaysAfterTerminal: 8 }),
      ])), (error: unknown) => codeOf(error) === "INVALID_ARGUMENT");
    } finally {
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });

  await t.test("directory inventory is represented only by regular descendants", async () => {
    const fixture = await createRepositoryFixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    try {
      await mkdir(join(fixture.repository, "directory"));
      await writeFile(join(fixture.repository, "directory", "child.txt"), "child");
      const captured = await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
        pathDecision("directory/child.txt"),
      ]));
      assert.deepEqual(captured.baseline.paths.map((entry) => entry.path), ["directory/child.txt"]);
    } finally {
      await releaseWorktreeLock(lock);
      await removeRepositoryFixture(fixture);
    }
  });
});

test("untracked FIFO, socket, and available device-like special entries fail closed", async (t) => {
  const specialCases: readonly [string, (path: string) => Promise<(() => Promise<void>) | undefined>][] = [
    ["FIFO", async (path) => { await execFileAsync("mkfifo", [path]); return undefined; }],
    ["socket", async (path) => {
      const server = createServer();
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(path, resolve); });
      return async () => new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
    }],
  ];
  for (const [name, create] of specialCases) {
    await t.test(name, async () => {
      const fixture = await createRepositoryFixture();
      const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
      const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
      let cleanup: (() => Promise<void>) | undefined;
      try {
        cleanup = await create(join(fixture.repository, "special-entry"));
        await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
          pathDecision("special-entry"),
        ])), (error: unknown) => codeOf(error) === "BASELINE_SPECIAL_PATH");
      } finally {
        await cleanup?.();
        await releaseWorktreeLock(lock);
        await removeRepositoryFixture(fixture);
      }
    });
  }

  await t.test("device fixture is fail-closed when local mknod is permitted", async () => {
    const fixture = await createRepositoryFixture();
    const path = join(fixture.repository, "device-entry");
    let created = false;
    let creationError: unknown;
    try {
      try {
        await execFileAsync("mknod", [path, "c", "1", "3"]);
        created = true;
      } catch (error: unknown) {
        creationError = error;
      }
      if (created) {
        const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
        const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
        try {
          await assert.rejects(captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [
            pathDecision("device-entry"),
          ])), (error: unknown) => codeOf(error) === "BASELINE_SPECIAL_PATH");
        } finally {
          await releaseWorktreeLock(lock);
        }
      } else {
        assert.ok(creationError instanceof Error, "unsupported local device fixtures must fail explicitly");
      }
    } finally {
      await rm(path, { force: true }).catch(() => undefined);
      await removeRepositoryFixture(fixture);
    }
  });
});
