#!/usr/bin/env node

import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { executeStaticApprovedDag } from "../static-approved-dag-launcher.js";

interface CliArguments {
  readonly specPath: string;
  readonly approvedSpecSha256: string;
}

function parseArguments(argv: readonly string[]): CliArguments {
  const positional: string[] = []; let approved: string | null = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--approved-spec-sha256") { if (approved !== null || argv[index + 1] === undefined) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest>"); approved = argv[++index]!; continue; }
    if (argument === "--report") throw new Error("--report is not supported; reports are emitted on stdout only");
    if (argument.startsWith("--")) throw new Error("unknown launcher argument");
    positional.push(argument);
  }
  if (positional.length !== 1 || approved === null) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest>");
  return { specPath: positional[0]!, approvedSpecSha256: approved };
}


function render(report: unknown): string { return `${JSON.stringify(report)}\n`; }

type StaticApprovedDagExecutor = typeof executeStaticApprovedDag;

export async function main(argv = process.argv.slice(2), execute: StaticApprovedDagExecutor = executeStaticApprovedDag): Promise<number> {
  let argumentsValue: CliArguments;
  try { argumentsValue = parseArguments(argv); } catch (error: unknown) { process.stdout.write(render({ classification: "INVALID", spec_sha256: null, run_label: null, reason: error instanceof Error ? error.message : "invalid arguments", workflow: null, telemetry: null })); return 2; }
  let spec: unknown;
  try { spec = JSON.parse(await readFile(argumentsValue.specPath, "utf8")) as unknown; } catch (error: unknown) { process.stdout.write(render({ classification: "INVALID", spec_sha256: null, run_label: null, reason: error instanceof Error ? error.message : "invalid spec file", workflow: null, telemetry: null })); return 2; }
  const report = await execute({ spec, approved_spec_sha256: argumentsValue.approvedSpecSha256, cwd: process.cwd() });
  process.stdout.write(render(report));
  return report.classification === "PASS" ? 0 : report.classification === "VALID_BLOCKED" ? 3 : 2;
}

if (process.argv[1] !== undefined) {
  const invokedPath = await realpath(process.argv[1]).catch(() => "");
  if (invokedPath === fileURLToPath(import.meta.url)) {
    void main().then((code) => { process.exitCode = code; });
  }
}
