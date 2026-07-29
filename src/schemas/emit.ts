import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { getInternalSchemaRegistry } from "./definitions.js";

function render(schema: unknown): string {
  return `${JSON.stringify(schema, null, 2)}\n`;
}

export async function emitSchemas(checkOnly: boolean): Promise<void> {
  const sourceDirectory = dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = resolve(sourceDirectory, "../..");
  const schemaDirectory = resolve(repositoryRoot, "schemas");

  for (const entry of getInternalSchemaRegistry()) {
    const target = resolve(schemaDirectory, entry.fileName);
    const expected = render(entry.schema);
    if (checkOnly) {
      let actual: string;
      try {
        actual = await readFile(target, "utf8");
      } catch (error: unknown) {
        throw new Error(`Missing generated schema ${entry.fileName}`, { cause: error });
      }
      if (actual !== expected) {
        throw new Error(`Generated schema is stale: ${entry.fileName}`);
      }
    } else {
      await writeFile(target, expected, { encoding: "utf8" });
    }
  }
}

const isMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  await emitSchemas(process.argv.includes("--check"));
}
