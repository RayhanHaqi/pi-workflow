import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  runBoundedMutationWorkflowForTests,
  type BoundedMutationAuthority,
  type BoundedMutationOptions,
  type BoundedMutationGoal,
  type StaticApprovedDagTimeBudgets,
} from "../src/workflow-controller.js";
import { configureBoundedWorkerFauxRuntimeForTests, type BoundedWorkerRuntime } from "../src/pi-adapter/bounded-worker.js";
import { identifyContractDocument, type PlanApprovalDocument } from "../src/schemas/index.js";
import { installTestWallClock } from "../src/wall-clock.js";

const execFileAsync = promisify(execFile);

async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "static-time-budgets-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "time-budgets@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "time-budgets"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "check.mjs"), "process.exit(0);\n");
  await execFileAsync("git", ["add", "verify"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

function goal(): BoundedMutationGoal {
  return {
    objective: "Write exactly the frozen static outputs.",
    stop_condition: "Stop after deterministic verification.",
    execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] },
    required_outputs: ["a.txt", "b.txt"],
    tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["a"] },
    ],
  };
}

function authority(static_time_budgets?: StaticApprovedDagTimeBudgets): BoundedMutationAuthority {
  return {
    verification_commands: [{ command_id: "check", executable: process.execPath, args: ["check.mjs"], cwd: "verify" }],
    ...(static_time_budgets === undefined ? {} : { static_time_budgets }),
  };
}

function mutationRuntime(deadlines: number[], afterMutation?: () => void): BoundedWorkerRuntime {
  let output = 0;
  return {
    async execute({ profile, deadlineMs, tools }) {
      assert.equal(profile, "MUTATION_EXECUTOR");
      deadlines.push(deadlineMs);
      const path = ["a.txt", "b.txt"][output++]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport(`wrote ${path}`);
      afterMutation?.();
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  };
}

type ApprovalInput = Parameters<NonNullable<BoundedMutationOptions["approveTasks"]>>[0];

async function runStatic(
  budgets: StaticApprovedDagTimeBudgets | undefined,
  runtime: BoundedWorkerRuntime,
  onApproval?: (input: ApprovalInput) => `sha256:${string}` | void,
) {
  const root = await fixture();
  configureBoundedWorkerFauxRuntimeForTests(() => runtime);
  try {
    return await runBoundedMutationWorkflowForTests(goal(), {
      cwd: root,
      authority: authority(budgets),
      approveTasks: async (input) => {
        const approved = onApproval?.(input);
        return approved ?? (input.plan!.content_sha256 as `sha256:${string}`);
      },
    });
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(root, { recursive: true, force: true });
  }
}

// V1-R2D-TIME: durable timing consumes the package clock seam, so tests override
// time through it instead of monkey-patching Date.now (which the backward-motion
// guard must keep rejecting).
async function withFakeDate<T>(action: (advance: (milliseconds: number) => void) => Promise<T>): Promise<T> {
  let now = 0;
  installTestWallClock(() => now);
  try {
    return await action((milliseconds) => { now += milliseconds; });
  } finally {
    installTestWallClock(null);
  }
}

test("STATIC_APPROVED_DAG freezes explicit R5 budgets in the approved plan and sends Terra the exact worker deadline", async () => {
  const budgets = { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 } as const;
  const deadlines: number[] = [];
  let planIdentity = "";
  let approvedPlan: PlanApprovalDocument | undefined;
  let executionBudget: StaticApprovedDagTimeBudgets | undefined;
  const result = await runStatic(budgets, mutationRuntime(deadlines), ({ plan, executionAuthority }) => {
    planIdentity = plan!.content_sha256;
    approvedPlan = plan!;
    assert.deepEqual(plan!.bindings.limits.static_time_budgets, budgets);
    executionBudget = executionAuthority.budget.limits.static_time_budgets;
    assert.equal(executionAuthority.budget.limits.max_wall_time_ms, budgets.workflow_wall_ms);
  });
  assert.equal(result.outcome, "PASS", result.reason);
  assert.deepEqual(deadlines, [300_000, 300_000]);
  assert.deepEqual(executionBudget, budgets);

  for (const changed of [
    { ...budgets, worker_deadline_ms: 299_999 },
    { ...budgets, node_wall_ms: 599_999 },
    { ...budgets, workflow_wall_ms: 1_799_999 },
  ]) {
    const candidate = structuredClone(approvedPlan!) as unknown as { bindings: { limits: { max_wall_time_ms: number; static_time_budgets: StaticApprovedDagTimeBudgets } } } & Record<string, unknown>;
    candidate.bindings.limits.static_time_budgets = changed;
    candidate.bindings.limits.max_wall_time_ms = changed.workflow_wall_ms;
    const changedIdentity = identifyContractDocument("pi_gacw_plan_approval_v0", candidate).content_sha256;
    assert.notEqual(changedIdentity, planIdentity);
  }
  const rejectedDeadlines: number[] = [];
  const rejected = await runStatic({ ...budgets, worker_deadline_ms: 299_999 }, mutationRuntime(rejectedDeadlines), () => planIdentity as `sha256:${string}`);
  assert.equal(rejected.outcome, "BLOCKED");
  assert.match(rejected.reason, /EXECUTION_APPROVAL_MISMATCH/);
  assert.deepEqual(rejectedDeadlines, []);
});

test("STATIC_APPROVED_DAG preserves legacy worker and workflow defaults without frozen budgets", async () => {
  const deadlines: number[] = [];
  let legacyWorkflowBudget: number | undefined;
  const result = await runStatic(undefined, mutationRuntime(deadlines), ({ executionAuthority }) => {
    legacyWorkflowBudget = executionAuthority.budget.limits.max_wall_time_ms;
    assert.equal(executionAuthority.budget.limits.static_time_budgets, undefined);
  });
  assert.equal(result.outcome, "PASS", result.reason);
  assert.deepEqual(deadlines, [120_000, 120_000]);
  assert.equal(legacyWorkflowBudget, 240_000);
});

test("STATIC_APPROVED_DAG rejects invalid frozen time budgets deterministically", async () => {
  const invalid: unknown[] = [
    { worker_deadline_ms: 0, node_wall_ms: 1, workflow_wall_ms: 1 },
    { worker_deadline_ms: -1, node_wall_ms: 1, workflow_wall_ms: 1 },
    { worker_deadline_ms: 1.5, node_wall_ms: 2, workflow_wall_ms: 2 },
    { worker_deadline_ms: Number.POSITIVE_INFINITY, node_wall_ms: 2, workflow_wall_ms: 2 },
    { worker_deadline_ms: Number.MAX_SAFE_INTEGER + 1, node_wall_ms: Number.MAX_SAFE_INTEGER + 1, workflow_wall_ms: Number.MAX_SAFE_INTEGER + 1 },
    { worker_deadline_ms: 3, node_wall_ms: 2, workflow_wall_ms: 3 },
    { worker_deadline_ms: 1, node_wall_ms: 3, workflow_wall_ms: 2 },
  ];
  for (const value of invalid) {
    const result = await runBoundedMutationWorkflowForTests(goal(), { authority: authority(value as StaticApprovedDagTimeBudgets) });
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /INVALID_STATIC_TIME_BUDGETS/);
  }
});

test("STATIC_APPROVED_DAG node and workflow deadlines block before additional productive progression", async (t) => {
  const r5 = { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 } as const;
  await t.test("node deadline", async () => {
    const deadlines: number[] = [];
    const result = await withFakeDate(async (advance) => await runStatic(r5, mutationRuntime(deadlines, () => advance(600_000))));
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /STATIC_NODE_WALL_DEADLINE_EXCEEDED/);
    assert.equal(result.finalState?.phase, "BLOCKED");
    assert.deepEqual(deadlines, [300_000]);
  });
  await t.test("workflow deadline", async () => {
    const deadlines: number[] = [];
    const result = await withFakeDate(async (advance) => await runStatic(r5, mutationRuntime(deadlines, () => advance(1_800_000))));
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /STATIC_WORKFLOW_WALL_DEADLINE_EXCEEDED/);
    assert.equal(result.finalState?.phase, "BLOCKED");
    assert.deepEqual(deadlines, [300_000]);
  });
});

test("STATIC_APPROVED_DAG ignores a runtime attempt to extend a frozen deadline", async () => {
  const budgets = { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 };
  const deadlines: number[] = [];
  const runtime = mutationRuntime(deadlines);
  const root = await fixture();
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute(input) { return { ...(await runtime.execute(input)), worker_deadline_ms: 600_000 }; },
  }));
  try {
    const result = await runBoundedMutationWorkflowForTests(goal(), {
      cwd: root,
      authority: authority(budgets),
      approveTasks: async ({ plan }) => plan!.content_sha256 as `sha256:${string}`,
    });
    assert.equal(result.outcome, "PASS", result.reason);
    assert.deepEqual(deadlines, [300_000, 300_000]);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(root, { recursive: true, force: true });
  }
});
