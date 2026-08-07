import { execFile as execFileCallback, spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import assert from "node:assert/strict";

import {
  compileGoalToTask,
  prepareWorkflow,
  runApprovedWorkflow,
  type WorkflowRunResult,
  WorkflowValidationError,
} from "../src/workflow.js";
import type { M6WorkerExecutionResult } from "../src/pi-adapter/worker.js";
import workflowExtension from "../src/pi-extension/workflow.js";

const execFile = promisify(execFileCallback);

async function runProcess(command: string, args: readonly string[], cwd: string): Promise<{ readonly code: number; readonly stdout: string; readonly stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { cwd });
    const stdout: Buffer[] = []; const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code) => resolve({ code: code ?? 1, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") }));
    child.stdin.end();
  });
}

function goal(commandPath = "/usr/bin/true"): Record<string, any> {
  return {
    objective: "Inspect one selected source and report its bounded state.",
    resources: [{ path: "README.md", max_bytes: 1024, data_class: "PUBLIC_SOURCE" }],
    non_goals: ["Do not edit files", "Do not use network"],
    deliverable: "One structured report.",
    acceptance_criteria: [{ criterion_id: "report", description: "The report is completed.", evidence_kind: "DIGEST", owner_acceptance: false }],
    verification_commands: [{ command_id: "verify", argv: [commandPath], cwd: "REPOSITORY_ROOT", timeout_ms: 1000, network: "FORBIDDEN" }],
    budget: { max_worker_invocations: 1, max_model_turns: 2, max_tool_calls: 2, max_wall_time_ms: 120000, max_read_bytes: 1024 },
    stop_condition: "Stop after one report.",
  };
}

function fakeWorker(outcome: "COMPLETED" | "BLOCKED" = "COMPLETED"): (input: unknown) => Promise<M6WorkerExecutionResult> {
  return async () => ({
    invocation: { fake: true },
    result: {
      outcome,
      usage: {
        provider_turns: 2,
        model_turns: 2,
        provider_requests: 2,
        tool_calls: 2,
        read_calls: 1,
        report_submissions: 1,
        input_tokens: null,
        output_tokens: null,
        cost_microusd: null,
        wall_time_ms: 10,
      },
    },
    replayed: false,
  } as unknown as M6WorkerExecutionResult);
}

async function gitRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "m7-workflow-test-"));
  await execFile("git", ["-C", root, "init", "-q", "-b", "main"]);
  await execFile("git", ["-C", root, "config", "user.name", "M7 test"]);
  await execFile("git", ["-C", root, "config", "user.email", "m7@example.invalid"]);
  await writeFile(join(root, "README.md"), "M7 test source\n", "utf8");
  await execFile("git", ["-C", root, "add", "README.md"]);
  await execFile("git", ["-C", root, "commit", "-q", "-m", "initial"]);
  return root;
}

async function productionRun(
  input: Record<string, unknown>,
  worker: (input: unknown) => Promise<M6WorkerExecutionResult>,
): Promise<WorkflowRunResult> {
  const root = await gitRepository();
  try {
    const prepared = prepareWorkflow(input);
    return await runApprovedWorkflow(prepared, prepared.task.content_sha256, { cwd: root, worker });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("M7 compilation is deterministic and binds every Goal execution field", () => {
  const input = goal();
  const first = compileGoalToTask(input);
  const second = compileGoalToTask(structuredClone(input));
  assert.deepEqual(first, second);
  assert.equal(first.task_id, "task-only");
  assert.equal(first.objective.includes("goal_sha256"), false);
  assert.equal(first.objective.includes("m7-ephemeral-goal-v1"), true);
  assert.equal(first.content_sha256, "sha256:0ed7a60fbc24c09acee1ac6b98467c9b00b8159f2b425fbe3f43c960d9bc234d");
  assert.equal(first.task_sha256, "sha256:00b29683517846330747e3fd0df5c1d7f43b8ceaa95a22d8c4df90979ff586d1");

  const variants: Array<(value: Record<string, any>) => void> = [
    (value) => { value["objective"] += " changed"; },
    (value) => { value["resources"][0].path = "package.json"; },
    (value) => { value["resources"][0].max_bytes = 2048; },
    (value) => { value["resources"][0].data_class = "PRIVATE_SOURCE"; },
    (value) => { value["non_goals"][0] = "A different non-goal"; },
    (value) => { value["deliverable"] += " changed"; },
    (value) => { value["acceptance_criteria"][0].description += " changed"; },
    (value) => { value["verification_commands"][0].timeout_ms = 2000; },
    (value) => { value["budget"]["max_wall_time_ms"] = 110000; },
    (value) => { value["budget"]["max_read_bytes"] = 512; },
    (value) => { value["stop_condition"] += " changed"; },
  ];
  for (const mutate of variants) {
    const variant = structuredClone(input) as Record<string, any>;
    mutate(variant);
    assert.notEqual(compileGoalToTask(variant).content_sha256, first.content_sha256);
  }
});

test("M7 rejects unknown Goal fields, unsafe commands, and widened budgets before execution", () => {
  assert.throws(() => compileGoalToTask({ ...goal(), unknown: true }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), budget: { ...goal()["budget"], max_worker_invocations: 2 } }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), verification_commands: [{ ...goal()["verification_commands"][0], network: "ALLOW" }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), verification_commands: [{ ...goal()["verification_commands"][0], argv: ["/bin/sh", "-c", "true"] }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), resources: [{ path: "../README.md", max_bytes: 1, data_class: "PUBLIC_SOURCE" }] }), WorkflowValidationError);
  assert.throws(() => compileGoalToTask({ ...goal(), budget: { ...goal()["budget"], max_wall_time_ms: 500 }, verification_commands: [{ ...goal()["verification_commands"][0], timeout_ms: 1000 }] }), WorkflowValidationError);
});

test("approval mismatch and tampering do not reach the shared execution hook", async () => {
  const prepared = prepareWorkflow(goal());
  let executions = 0;
  const executeApproved = async (): Promise<WorkflowRunResult> => {
    executions += 1;
    return { outcome: "PASS", reason: "test", task: prepared.task };
  };
  await assert.rejects(() => runApprovedWorkflow(prepared, "sha256:" + "0".repeat(64), { executeApproved }), WorkflowValidationError);
  assert.equal(executions, 0);
  const tampered = { ...prepared, goal: { ...prepared.goal, objective: "tampered" } } as typeof prepared;
  await assert.rejects(() => runApprovedWorkflow(tampered, prepared.task.content_sha256, { executeApproved }), WorkflowValidationError);
  assert.equal(executions, 0);
});

test("M5 authorization invokes exactly one worker and a completed worker reaches authoritative PASS", async () => {
  let calls = 0;
  const result = await productionRun(goal(), async (input) => { calls += 1; return fakeWorker()(input); });
  assert.equal(calls, 1);
  assert.equal(result.outcome, "PASS");
  assert.equal(result.finalState?.phase, "PASS");
  assert.equal(result.m5Decision?.outcome, "PASS");
});

test("M5 BLOCK and M6 BLOCKED both stop without retry", async () => {
  let blockedWorkerCalls = 0;
  const verificationBlocked = await productionRun(goal("/usr/bin/false"), async (input) => { blockedWorkerCalls += 1; return fakeWorker()(input); });
  assert.equal(verificationBlocked.outcome, "BLOCKED");
  assert.equal(blockedWorkerCalls, 0);

  let m6Calls = 0;
  const m6Blocked = await productionRun(goal(), async (input) => { m6Calls += 1; return fakeWorker("BLOCKED")(input); });
  assert.equal(m6Blocked.outcome, "BLOCKED");
  assert.equal(m6Calls, 1);

  const thrown = await productionRun(goal(), async () => { m6Calls += 1; throw new Error("synthetic M6 failure"); });
  assert.equal(thrown.outcome, "BLOCKED");
  assert.equal(m6Calls, 2);
});

test("/workflow registers one human command and rejects without UI approval", async () => {
  let registered: { name: string; handler: (args: string, context: any) => Promise<void> } | undefined;
  workflowExtension({ registerCommand: (name, options) => { registered = { name, handler: options.handler }; } });
  assert.equal(registered?.name, "workflow");
  const root = await mkdtemp(join(tmpdir(), "m7-extension-test-"));
  try {
    await writeFile(join(root, "goal.json"), JSON.stringify(goal()), "utf8");
    const notifications: string[] = [];
    let confirmed = 0;
    const context = {
      cwd: root,
      hasUI: true,
      signal: undefined,
      ui: {
        setWidget: () => undefined,
        setStatus: () => undefined,
        notify: (message: string) => { notifications.push(message); },
        confirm: async () => { confirmed += 1; return false; },
      },
    };
    await registered!.handler("goal.json", context);
    assert.equal(confirmed, 1);
    assert.equal(notifications.some((message) => message.includes("BLOCKED (not started)")), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI has no approval bypass and rejects before workflow start", async () => {
  const root = await mkdtemp(join(tmpdir(), "m7-cli-test-"));
  try {
    const goalPath = join(root, "goal.json");
    await writeFile(goalPath, JSON.stringify(goal()), "utf8");
    const cli = join(process.cwd(), "dist/src/cli/pi-workflow.js");
    const rejected = await runProcess(process.execPath, [cli, goalPath], root);
    assert.equal(rejected.code, 2);
    assert.match(rejected.stdout, /APPROVAL_REQUIRED sha256:/u);
    assert.match(rejected.stdout, /BLOCKED \(not started\)/u);
    const bypass = await runProcess(process.execPath, [cli, goalPath, "--yes"], root);
    assert.equal(bypass.code, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
