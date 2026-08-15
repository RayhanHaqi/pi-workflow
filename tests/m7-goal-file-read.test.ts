import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  GoalFileReadError,
  MAX_GOAL_FILE_BYTES,
  readGoalFileText,
} from "../src/workflow.js";

async function withTemporaryDirectory(run: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "m7-goal-reader-"));
  try { await run(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

async function rejectsWith(
  operation: () => Promise<unknown>,
  code: GoalFileReadError["code"],
): Promise<void> {
  await assert.rejects(operation, (error: unknown) => error instanceof GoalFileReadError && error.code === code);
}

test("M7 Goal reader accepts bounded UTF-8 text without parsing it", async () => {
  await withTemporaryDirectory(async (root) => {
    const goal = join(root, "goal.json");
    await writeFile(goal, "{not JSON", "utf8");
    assert.equal(await readGoalFileText(goal), "{not JSON");
  });
});

test("M7 Goal reader rejects oversized, non-regular, symlinked, and invalid UTF-8 inputs", async () => {
  await withTemporaryDirectory(async (root) => {
    const oversized = join(root, "oversized.json");
    const directory = join(root, "directory");
    const target = join(root, "target.json");
    const link = join(root, "link.json");
    const invalidUtf8 = join(root, "invalid-utf8.json");
    await Promise.all([
      writeFile(oversized, Buffer.alloc(MAX_GOAL_FILE_BYTES + 1)),
      mkdir(directory),
      writeFile(target, "{}", "utf8"),
      writeFile(invalidUtf8, Buffer.from([0xff])),
    ]);
    await symlink(target, link);

    await rejectsWith(() => readGoalFileText(oversized), "GOAL_FILE_TOO_LARGE");
    await rejectsWith(() => readGoalFileText(directory), "GOAL_FILE_NOT_REGULAR");
    await rejectsWith(() => readGoalFileText(link), "GOAL_FILE_NOT_REGULAR");
    await rejectsWith(() => readGoalFileText(invalidUtf8), "GOAL_FILE_INVALID_UTF8");
  });
});

test("M7 Goal reader rejects relative and non-normalized paths", async () => {
  await withTemporaryDirectory(async (root) => {
    const goal = join(root, "goal.json");
    await writeFile(goal, "{}", "utf8");
    await rejectsWith(() => readGoalFileText("goal.json"), "GOAL_FILE_PATH_INVALID");
    await rejectsWith(() => readGoalFileText(`${root}/./goal.json`), "GOAL_FILE_PATH_INVALID");
  });
});
