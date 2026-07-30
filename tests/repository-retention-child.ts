import { readFile } from "node:fs/promises";

import { applyRetentionCleanup, type RetentionOperationInput } from "../src/repository/index.js";
import { configureRepositoryTestHooks } from "../src/repository/test-hooks.js";

const inputPath = process.argv[2];
if (inputPath === undefined || process.send === undefined) {
  throw new Error("repository-retention-child requires input JSON and IPC");
}

const input = JSON.parse(await readFile(inputPath, "utf8")) as RetentionOperationInput;
configureRepositoryTestHooks({
  beforeRetentionResultPublication: async () => {
    process.send?.({ type: "AFTER_UNLINK_AND_DIRECTORY_FSYNC" });
    await new Promise<void>((resolve) => process.once("message", () => resolve()));
  },
});

try {
  await applyRetentionCleanup(input);
  process.send({ type: "UNEXPECTED_COMPLETE" });
  process.exitCode = 2;
} catch (error: unknown) {
  process.send({ type: "ERROR", code: (error as { code?: unknown }).code ?? "UNKNOWN" });
  process.exitCode = 1;
}
