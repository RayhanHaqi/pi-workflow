import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { main as workflowCliMain } from "../src/cli/pi-workflow.js";
import { deriveStaticDagResumePoint, inspectDeterministicResumeEligibility } from "../src/resume-inspection.js";
import type { ReducerPolicy, WorkflowState } from "../src/schemas/index.js";

const digest = (letter: string) => `sha256:${letter.repeat(64)}`;

function staticState(tasks: readonly { readonly task_id: string; readonly status: "PENDING" | "PASS" }[]): WorkflowState {
  return {
    schema_id: "pi_gacw_state_v0", schema_version: "0.1.0", content_sha256: digest("a"), run_id: "resume-test",
    execution_mode: "STATIC_APPROVED_DAG", phase: "READY",
    identities: { objective_sha256: digest("b"), contract_sha256: digest("c"), baseline_approval_sha256: digest("d"), authority_lock_sha256: digest("e"), plan_approval_sha256: digest("f"), task_graph_sha256: digest("0"), scope_sha256: digest("1"), acceptance_sha256: digest("2"), budget_sha256: digest("3") },
    frozen_policy_content_sha256: digest("4"), counters: { worker_invocations: { total: 0, sol_owner: 0, sol_planner: 0, sol_replan: 0, sol_closeout: 0, luna_executor: 0, terra_executor: 0 }, direct_attempts: 0, single_owner_mutation_cycles: 0, constrained_replans: 0, leaves_completed: 0 },
    gates: { planner_completed: false, owner_acceptance_completed: false, closeout_completed: false, closeout_verification_completed: false },
    tasks: tasks.map((task) => ({ task_id: task.task_id, status: task.status, attempts: 0, postflight_completed: task.status === "PASS", verification_completed: task.status === "PASS", retry_progress_admitted: false })),
    active_task_id: null, baseline_approval_required: false, route_frozen: true, owner_acceptance_required: false, replan_in_progress: false, terminal_reason: null,
  } as WorkflowState;
}

function staticPolicy(): ReducerPolicy {
  return {
    schema_id: "pi_gacw_reducer_policy_v0", schema_version: "0.1.0", content_sha256: digest("4"), run_id: "resume-test", execution_mode: "STATIC_APPROVED_DAG", owner_acceptance_required: false,
    limits: { max_direct_attempts: 1, max_single_owner_mutation_cycles: 1, max_attempts_per_leaf: 1, max_replans: 0, max_leaves: 2, max_worker_invocations: 2 },
    tasks: [
      { task_id: "a", task_sha256: digest("5"), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["a.txt"] },
      { task_id: "b", task_sha256: digest("6"), topological_rank: 1, priority: 0, dependencies: ["a"], editable_paths: ["b.txt"] },
    ],
    frozen_bindings: { plan_approval_sha256: digest("f"), task_graph_sha256: digest("0"), scope_sha256: digest("1"), acceptance_sha256: digest("2"), budget_sha256: digest("3") },
  } as ReducerPolicy;
}

async function captureStdout<T>(action: () => Promise<T>): Promise<{ readonly result: T; readonly output: string }> {
  const stdout = process.stdout as unknown as { write(chunk: string | Uint8Array): boolean };
  const write = stdout.write; let output = "";
  stdout.write = (chunk) => { if (typeof chunk === "string") output += chunk; return true; };
  try { return { result: await action(), output }; } finally { stdout.write = write; }
}

test("resume point is deterministic at the reducer-settled static DAG ready boundary", () => {
  const policy = staticPolicy();
  assert.equal(deriveStaticDagResumePoint(staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), policy), "STATIC_DAG_SELECT_READY_LEAF:a");
  assert.equal(deriveStaticDagResumePoint(staticState([{ task_id: "a", status: "PASS" }, { task_id: "b", status: "PENDING" }]), policy), "STATIC_DAG_SELECT_READY_LEAF:b");
  const active = { ...staticState([{ task_id: "a", status: "PENDING" }, { task_id: "b", status: "PENDING" }]), active_task_id: "a" } as WorkflowState;
  assert.equal(deriveStaticDagResumePoint(active, policy), null);
});

test("resume inspection fails closed without a retained state root and does not create one", async () => {
  const root = await mkdtemp(join(tmpdir(), "resume-inspect-"));
  const missing = join(root, "missing");
  try {
    const first = await inspectDeterministicResumeEligibility({ retainedRunRoot: missing });
    const second = await inspectDeterministicResumeEligibility({ retainedRunRoot: missing });
    assert.deepEqual(first, { classification: "RESUME_REFUSED", run_id: null, phase: null, resume_point: null, reason: "RESUME_REFUSED_STATE_STORE" });
    assert.deepEqual(second, first);
    assert.deepEqual(await readdir(root), []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("resume-inspect CLI emits one deterministic machine-readable JSON report", async () => {
  const root = await mkdtemp(join(tmpdir(), "resume-inspect-cli-"));
  try {
    const first = await captureStdout(() => workflowCliMain(["resume-inspect", join(root, "missing")]));
    const second = await captureStdout(() => workflowCliMain(["resume-inspect", join(root, "missing")]));
    assert.equal(first.result, 3);
    assert.equal(second.result, 3);
    assert.equal(first.output, second.output);
    assert.deepEqual(JSON.parse(first.output), { classification: "RESUME_REFUSED", run_id: null, phase: null, resume_point: null, reason: "RESUME_REFUSED_STATE_STORE" });
  } finally { await rm(root, { recursive: true, force: true }); }
});
