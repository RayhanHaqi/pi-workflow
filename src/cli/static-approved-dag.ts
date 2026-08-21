#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

import { executeStaticApprovedDag } from "../static-approved-dag-launcher.js";

interface CliArguments {
  readonly specPath: string;
  readonly approvedSpecSha256: string;
  readonly reportPath: string | null;
}

function parseArguments(argv: readonly string[]): CliArguments {
  const positional: string[] = []; let approved: string | null = null; let report: string | null = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--approved-spec-sha256") { if (approved !== null || argv[index + 1] === undefined) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest> [--report <path>]"); approved = argv[++index]!; continue; }
    if (argument === "--report") { if (report !== null || argv[index + 1] === undefined) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest> [--report <path>]"); report = argv[++index]!; continue; }
    if (argument.startsWith("--")) throw new Error("unknown launcher argument");
    positional.push(argument);
  }
  if (positional.length !== 1 || approved === null) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest> [--report <path>]");
  return { specPath: positional[0]!, approvedSpecSha256: approved, reportPath: report };
}

function reportTarget(path: string, repositoryRoot: string): string {
  const target = resolve(path);
  if (!isAbsolute(path) && !path.startsWith("../")) throw new Error("--report must be absolute or an explicit path outside the repository");
  if (target === repositoryRoot || target.startsWith(`${repositoryRoot}/`)) throw new Error("--report must be outside the repository");
  return target;
}

function render(report: unknown): string { return `${JSON.stringify(report)}\n`; }

export async function main(argv = process.argv.slice(2)): Promise<number> {
  let argumentsValue: CliArguments;
  try { argumentsValue = parseArguments(argv); } catch (error: unknown) { process.stdout.write(render({ classification: "INVALID", spec_sha256: null, run_label: null, reason: error instanceof Error ? error.message : "invalid arguments", workflow: null, telemetry: null })); return 2; }
  let spec: unknown;
  try { spec = JSON.parse(await readFile(argumentsValue.specPath, "utf8")) as unknown; } catch (error: unknown) { process.stdout.write(render({ classification: "INVALID", spec_sha256: null, run_label: null, reason: error instanceof Error ? error.message : "invalid spec file", workflow: null, telemetry: null })); return 2; }
  const report = await executeStaticApprovedDag({ spec, approved_spec_sha256: argumentsValue.approvedSpecSha256, cwd: process.cwd() });
  try {
    if (argumentsValue.reportPath === null) process.stdout.write(render(report));
    else await writeFile(reportTarget(argumentsValue.reportPath, process.cwd()), render(report), { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error: unknown) {
    process.stdout.write(render({ classification: "INVALID", spec_sha256: report.spec_sha256, run_label: report.run_label, reason: error instanceof Error ? error.message : "report generation failed", workflow: report.workflow, telemetry: null }));
    return 2;
  }
  return report.classification === "PASS" ? 0 : report.classification === "VALID_BLOCKED" ? 3 : 2;
}

if (process.argv[1] !== undefined) {
  void main().then((code) => { process.exitCode = code; });
}
