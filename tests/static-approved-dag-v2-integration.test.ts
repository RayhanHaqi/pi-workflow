import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  createStaticApprovedDagPlanApproval,
  executeStaticApprovedDag,
  normalizeStaticApprovedDagLaunchSpec,
  staticApprovedDagSpecSha256,
} from "../src/static-approved-dag-launcher.js";
import { runBoundedMutationWorkflowForTests, type BoundedMutationAuthority, type BoundedMutationGoal } from "../src/workflow-controller.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";

const exec = promisify(execFile);

/** Temporary repository with every readable path present; workload mirrors the frozen OXQ-001 shape at integration scale. */
async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "static-dag-v2-integration-"));
  await exec("git", ["init", "-q"], { cwd: root });
  await exec("git", ["config", "user.email", "v2-integration@example.invalid"], { cwd: root });
  await exec("git", ["config", "user.name", "v2-integration"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "a.mjs"), "process.exit(0);\n");
  await writeFile(join(root, "verify", "b.mjs"), "process.exit(0);\n");
  await exec("git", ["add", "verify"], { cwd: root });
  await exec("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

async function v2Spec(root: string): Promise<ReturnType<typeof normalizeStaticApprovedDagLaunchSpec>> {
  const [branch, head, tree] = await Promise.all([
    exec("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root }).then((r) => r.stdout.trim()),
    exec("git", ["rev-parse", "HEAD"], { cwd: root }).then((r) => r.stdout.trim()),
    exec("git", ["write-tree"], { cwd: root }).then((r) => r.stdout.trim()),
  ]);
  const goal: BoundedMutationGoal = {
    objective: "Write exactly two integrated outputs.", stop_condition: "Stop after deterministic verification.", execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["a.txt", "b.txt", "verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] }, required_outputs: ["a.txt", "b.txt"],
    tasks: [
      { task_id: "integration-a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] },
      { task_id: "integration-b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["integration-a"] },
    ],
  };
  const authorityCommands = [
    { command_id: "verify-a", executable: process.execPath, args: ["a.mjs"], cwd: "verify", timeout_ms: 60_000 },
    { command_id: "verify-b", executable: process.execPath, args: ["b.mjs"], cwd: "verify", timeout_ms: 60_000 },
  ];
  return normalizeStaticApprovedDagLaunchSpec({
    spec_version: "static-approved-dag-launch-v2", run_label: "v2-integration", expected_repository_branch: branch, expected_head: head, expected_tree: tree,
    goal, verification_commands: authorityCommands,
    static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
    expected_route: { logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false },
  });
}

function v2Authority(spec: ReturnType<typeof normalizeStaticApprovedDagLaunchSpec>): BoundedMutationAuthority {
  // Exact same authority construction as the launcher's V2 branch.
  return {
    verification_commands: spec.verification_commands as BoundedMutationAuthority["verification_commands"],
    static_time_budgets: spec.static_time_budgets,
    static_max_attempts_per_leaf: spec.static_max_attempts_per_leaf,
    static_coding_route: { provider_id: spec.expected_route.provider_id as string, model_id: spec.expected_route.model_id as string, effort: "high" as const },
  };
}

test("V2 launch spec is accepted by the REAL controller approval boundary and admits exactly the approved coding route", async () => {
  const root = await fixture(); let workerRoutes: unknown[] = []; let workerInvocations = 0;
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ route, tools }) {
      workerRoutes.push({ ...route }); workerInvocations += 1;
      const path = ["a.txt", "b.txt"][workerRoutes.length - 1]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("v2 integration mutation");
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  }));
  try {
    const spec = await v2Spec(root);
    const result = await executeStaticApprovedDag({
      spec: JSON.parse(JSON.stringify(spec)), approved_spec_sha256: staticApprovedDagSpecSha256(spec), cwd: root,
      controller: runBoundedMutationWorkflowForTests,
    });
    assert.equal(result.classification, "PASS", result.reason);
    assert.equal(result.workflow?.outcome, "PASS");
    assert.equal(result.workflow?.coding_worker_invocations, 2);
    assert.ok(result.workflow?.tasks.every((task) => task.status === "PASS"));
    for (const route of workerRoutes) {
      assert.deepEqual(route, { logicalRole: "CODING_EXECUTOR", providerId: "openrouter", modelId: "stealth/ox-alpha", effort: "high" });
    }
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(root, { recursive: true, force: true });
  }
});

test("launcher matcher accepts the exact real controller authority and rejects relevant frozen mutations before admission", async () => {
  const root = await fixture(); let workerEntries = 0; let captured: any = null;
  configureBoundedWorkerFauxRuntimeForTests(() => ({ async execute() { workerEntries += 1; return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 }; } }));
  try {
    const spec = await v2Spec(root); const authority = v2Authority(spec);
    // Capture the ACTUAL controller-generated approval input; returning null must block before any worker admission.
    const blocked = await runBoundedMutationWorkflowForTests(spec.goal, { cwd: root, authority, approveTasks: async (input) => { captured = JSON.parse(JSON.stringify(input)); return null; } });
    assert.equal(blocked.outcome, "BLOCKED"); assert.match(blocked.reason, /EXECUTION_APPROVAL_MISMATCH/);
    assert.equal(workerEntries, 0);
    assert.notEqual(captured, null);
    const approve = createStaticApprovedDagPlanApproval(spec);
    // Baseline acceptance of the unmutated real authority.
    assert.equal(await approve(captured), captured.plan.content_sha256);
    // Negative: substituted model identity in the admitted CODING_EXECUTOR route.
    const substitutedModel = JSON.parse(JSON.stringify(captured));
    substitutedModel.executionAuthority.route_map.routes.find((route: any) => route.logical_role === "CODING_EXECUTOR").model_id = "stealth/other";
    assert.equal(await approve(substitutedModel), null);
    // Negative: a dropped frozen DAG edge.
    const droppedEdge = JSON.parse(JSON.stringify(captured));
    droppedEdge.executionAuthority.task_graph.edges.pop();
    assert.equal(await approve(droppedEdge), null);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(root, { recursive: true, force: true });
  }
});
