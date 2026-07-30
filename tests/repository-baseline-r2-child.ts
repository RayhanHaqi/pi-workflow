import { readFile } from "node:fs/promises";

import { acquireWorktreeLock, captureBaseline, releaseWorktreeLock, resolveRepositoryIdentity } from "../src/repository/index.js";
import { configureRepositoryTestHooks, resetRepositoryTestHooks } from "../src/repository/test-hooks.js";

const inputPath = process.argv[2];
if (inputPath === undefined) throw new Error("missing child input");
const input = JSON.parse(await readFile(inputPath, "utf8")) as {
  stateRoot: string;
  runId: string;
  requestedPath: string;
  pathDecisions: Parameters<typeof captureBaseline>[0]["pathDecisions"];
  instructionFiles: Parameters<typeof captureBaseline>[0]["instructionFiles"];
  authorityFiles: Parameters<typeof captureBaseline>[0]["authorityFiles"];
};
const repository = await resolveRepositoryIdentity({ requestedPath: input.requestedPath, requireHead: true });
const lock = await acquireWorktreeLock({ stateRoot: input.stateRoot, repository });
try {
  configureRepositoryTestHooks({
    afterBaselineBlobPublication: () => {
      process.send?.({ type: "UNCOMMITTED_BASELINE_PUBLICATION" });
      return new Promise<void>(() => undefined);
    },
  });
  await captureBaseline({
    ...input,
    mode: "APPROVED_BASELINE_DIRTY",
    allowShallow: false,
    allowPartialClone: false,
    lock,
  });
} finally {
  resetRepositoryTestHooks();
  await releaseWorktreeLock(lock).catch(() => undefined);
}
