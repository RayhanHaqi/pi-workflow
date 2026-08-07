#!/usr/bin/env node

import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  approvalLine,
  prepareWorkflow,
  renderTaskPreview,
  runApprovedWorkflow,
  type WorkflowRunResult,
  WorkflowValidationError,
} from "../workflow.js";

function output(value: string): void {
  process.stdout.write(`${value}\n`);
}

async function stdinText(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function reportResult(result: WorkflowRunResult): number {
  output(result.outcome);
  output(result.reason);
  return result.outcome === "PASS" ? 0 : 3;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  if (argv.length !== 1) {
    output("BLOCKED (not started): usage is pi-workflow <goal.json>");
    return 2;
  }
  let prepared;
  try {
    const source = await readFile(argv[0]!, "utf8");
    prepared = prepareWorkflow(JSON.parse(source) as unknown);
  } catch (error: unknown) {
    output(`BLOCKED (not started): ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }

  output(renderTaskPreview(prepared));
  output("CAPABILITY READ_ONLY_REPORT_ONLY; editable_paths=[]; mutation_tools=[]; network=FORBIDDEN; workers=1");
  output(`APPROVAL_REQUIRED ${prepared.task.content_sha256}`);

  let confirmation: string;
  try {
    confirmation = (await stdinText()).trim();
  } catch (error: unknown) {
    output(`BLOCKED (not started): approval input unavailable (${error instanceof Error ? error.message : String(error)})`);
    return 2;
  }
  if (confirmation !== approvalLine(prepared.task.content_sha256)) {
    output("BLOCKED (not started): exact TaskDocument approval was not supplied");
    return 2;
  }

  try {
    return reportResult(await runApprovedWorkflow(prepared, prepared.task.content_sha256, { cwd: process.cwd() }));
  } catch (error: unknown) {
    const detail = error instanceof WorkflowValidationError || error instanceof Error ? error.message : String(error);
    output(`BLOCKED: ${detail}`);
    return 3;
  }
}

if (process.argv[1] !== undefined) {
  const invokedPath = await realpath(process.argv[1]).catch(() => "");
  if (invokedPath === fileURLToPath(import.meta.url)) {
    main().then((code) => { process.exitCode = code; }, (error: unknown) => {
      output(`BLOCKED: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 3;
    });
  }
}
