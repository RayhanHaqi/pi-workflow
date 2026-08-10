#!/usr/bin/env node

import { readFile, realpath } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import { runBoundedMutationWorkflow } from "../workflow-controller.js";
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

function reportResult(result: Pick<WorkflowRunResult, "outcome" | "reason">): number {
  output(result.outcome);
  output(result.reason);
  return result.outcome === "PASS" ? 0 : 3;
}

async function runMutationCommand(argv: readonly string[]): Promise<number> {
  if (argv.length !== 2) {
    output("BLOCKED (not started): usage is pi-workflow mutate <goal.json>");
    return 2;
  }
  let goal: unknown;
  try { goal = JSON.parse(await readFile(argv[1]!, "utf8")) as unknown; }
  catch (error: unknown) {
    output(`BLOCKED (not started): ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
  // The CLI deliberately has no executable authority. A host/controller must
  // supply the separate controller-owned verification authority programmatically.
  const approvals = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const result = await runBoundedMutationWorkflow(goal, {
      cwd: process.cwd(),
      approveBaseline: async (baseline) => {
        output(`DIRTY_BASELINE_APPROVAL_REQUIRED ${baseline.content_sha256}`);
        output(JSON.stringify(baseline.paths.map((entry) => ({ path: entry.path, ownership_class: entry.ownership_class, data_class: entry.data_class, capture_mode: entry.capture_mode, retention_days_after_terminal: entry.retention_days_after_terminal }))));
        const response = (await approvals.question("Enter APPROVE_BASELINE <baseline-content-sha256> <approved-by> <approved-at-utc>: ")).trim();
        const match = /^APPROVE_BASELINE\s+(sha256:[0-9a-f]{64})\s+(\S+)\s+(\S+)$/u.exec(response);
        return match?.[1] === baseline.content_sha256
          ? { baseline_content_sha256: baseline.content_sha256 as `sha256:${string}`, approved_by: match[2]!, approved_at: match[3]! }
          : null;
      },
      approveTasks: async ({ contract, plan }) => {
        const target = plan?.content_sha256 ?? contract.content_sha256;
        output(`EXECUTION_APPROVAL_REQUIRED ${plan === null ? "CONTRACT" : "PLAN"} ${target}`);
        return (await approvals.question(`Enter ${approvalLine(target as `sha256:${string}`)}: `)).trim() === approvalLine(target as `sha256:${string}`)
          ? target as `sha256:${string}` : null;
      },
      approveOwnerAcceptance: async ({ finalState }) => {
        output(`OWNER_ACCEPTANCE_REQUIRED ${finalState.content_sha256}`);
        return (await approvals.question(`Enter OWNER_ACCEPT ${finalState.content_sha256}: `)).trim() === `OWNER_ACCEPT ${finalState.content_sha256}`;
      },
    });
    return reportResult(result);
  } finally {
    approvals.close();
  }
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  if (argv[0] === "mutate") return runMutationCommand(argv);
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
