import { readFile } from "node:fs/promises";

async function identity(): Promise<{ readonly pid: number; readonly start_ticks: string; readonly process_group: number; readonly session_id: number }> {
  const value = await readFile(`/proc/${process.pid}/stat`, "utf8"); const fields = value.slice(value.lastIndexOf(")") + 1).trim().split(/\s+/u);
  return { pid: process.pid, start_ticks: fields[19]!, process_group: Number(fields[2]), session_id: Number(fields[3]) };
}

async function main(): Promise<void> {
  process.stdout.write(`${JSON.stringify(await identity())}\n`);
  if (process.argv[2] === "hang") {
    const wait = new Int32Array(new SharedArrayBuffer(4)); Atomics.wait(wait, 0, 0, 60_000);
  }
}

main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exitCode = 2; });
