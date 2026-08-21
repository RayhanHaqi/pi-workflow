#!/usr/bin/env node

import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { executeStaticApprovedDag, inspectStaticApprovedDagSpec, type StaticApprovedDagInspectionReport } from "../static-approved-dag-launcher.js";

interface CliArguments { readonly mode: "execute" | "inspect"; readonly specPath: string; readonly approvedSpecSha256: string; }

function parseArguments(argv: readonly string[]): CliArguments {
  const inspect = argv[0] === "inspect"; const positional: string[] = []; let approved: string | null = null;
  for (let index = inspect ? 1 : 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--approved-spec-sha256") { if (approved !== null || argv[index + 1] === undefined) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest>"); approved = argv[++index]!; continue; }
    if (argument === "--report") throw new Error("--report is not supported; reports are emitted on stdout only");
    if (argument.startsWith("--")) throw new Error("unknown launcher argument");
    positional.push(argument);
  }
  if (inspect) {
    if (positional.length !== 1) throw new Error("usage: static-approved-dag inspect <spec.json>");
    if (approved !== null) throw new Error("usage: static-approved-dag inspect <spec.json> (inspection never executes and takes no approval digest)");
    return { mode: "inspect", specPath: positional[0]!, approvedSpecSha256: "" };
  }
  if (positional.length !== 1 || approved === null) throw new Error("usage: static-approved-dag <spec.json> --approved-spec-sha256 sha256:<digest>");
  return { mode: "execute", specPath: positional[0]!, approvedSpecSha256: approved };
}


function render(report: unknown): string { return `${JSON.stringify(report)}\n`; }

type StaticApprovedDagExecutor = typeof executeStaticApprovedDag;
type StaticApprovedDagInspector = typeof inspectStaticApprovedDagSpec;
// Pre-execution failures stay mode-specific: execute keeps its pre-inspection INVALID shape, inspect uses the inspection shape.
const requestsInspection = (argv: readonly string[]): boolean => argv[0] === "inspect";
const invalidExecutionReport = (reason: string): Record<string, unknown> => ({ classification: "INVALID", spec_sha256: null, run_label: null, reason, workflow: null, telemetry: null });
const invalidInspectionReport = (reason: string): StaticApprovedDagInspectionReport => ({ classification: "INVALID", spec_version: null, spec_sha256: null, run_label: null, reason, repository: null, graph: null, route: null, budgets: null, verification_commands: null });

export async function main(argv = process.argv.slice(2), execute: StaticApprovedDagExecutor = executeStaticApprovedDag, inspect: StaticApprovedDagInspector = inspectStaticApprovedDagSpec): Promise<number> {
  let argumentsValue: CliArguments;
  try { argumentsValue = parseArguments(argv); } catch (error: unknown) { process.stdout.write(render(requestsInspection(argv) ? invalidInspectionReport(error instanceof Error ? error.message : "invalid arguments") : invalidExecutionReport(error instanceof Error ? error.message : "invalid arguments"))); return 2; }
  let spec: unknown;
  try { spec = JSON.parse(await readFile(argumentsValue.specPath, "utf8")) as unknown; } catch (error: unknown) { process.stdout.write(render(argumentsValue.mode === "inspect" ? invalidInspectionReport(error instanceof Error ? error.message : "invalid spec file") : invalidExecutionReport(error instanceof Error ? error.message : "invalid spec file"))); return 2; }
  if (argumentsValue.mode === "inspect") {
    const report = inspect(spec);
    process.stdout.write(render(report));
    return report.classification === "INSPECTED" ? 0 : 2;
  }
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
