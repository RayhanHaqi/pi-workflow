import { readFile } from "node:fs/promises";

import { configurePersistenceTestHooks, type PersistenceCheckpoint } from "../src/persistence/test-hooks.js";
import type { CommitTransitionInput } from "../src/persistence/types.js";

interface ChildCommitInput extends Omit<CommitTransitionInput, "evidence"> {
  readonly evidence: readonly { readonly base64: string; readonly mediaType: string }[];
}

async function main(): Promise<void> {
  const mode = process.argv[2];
  const inputPath = process.argv[3];
  if (inputPath === undefined) throw new Error("input path is required");
  const persistence = await import("pi-bounded-coding-workflow/persistence");
  const input = JSON.parse(await readFile(inputPath, "utf8")) as ChildCommitInput;

  if (mode === "inspect") {
    const inspection = await persistence.inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
    process.stdout.write(`${JSON.stringify(inspection)}\n`);
    return;
  }
  if (mode !== "commit") throw new Error(`unknown child mode ${mode}`);
  const target = process.argv[4] as PersistenceCheckpoint | undefined;
  if (target === undefined) throw new Error("checkpoint is required");
  configurePersistenceTestHooks({
    async checkpoint(checkpoint) {
      if (checkpoint !== target) return;
      process.send?.({ checkpoint });
      await new Promise<void>(() => { /* parent terminates this process deterministically */ });
    },
  });
  await persistence.commitTransition({
    ...input,
    evidence: input.evidence.map((entry) => ({ bytes: Buffer.from(entry.base64, "base64"), mediaType: entry.mediaType })),
  });
  throw new Error(`checkpoint ${target} was not reached`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
