import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  ContractValidationError,
  assertDocumentValid,
  identifyContractDocument,
  type ReducerPolicy,
  type TaskDocument,
  type WorkflowState,
} from "../src/schemas/index.js";
import { TransitionError, createInitialState, reduceState } from "../src/state-machine/index.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { runBoundedMutationWorkflowForTests, type BoundedMutationAuthority, type BoundedMutationGoal } from "../src/workflow-controller.js";
import { configureBoundedWorkerFauxRuntimeForTests, type BoundedWorkerRuntime } from "../src/pi-adapter/bounded-worker.js";
import {
  applyEvent,
  digest,
  makePolicy,
  planApprovalDocument,
  route,
  stateIdentities,
  transitionEvent,
  type MutableJson,
} from "./helpers.js";

const execFileAsync = promisify(execFile);

function expectCode(action: () => unknown, code: string): void {
  assert.throws(action, (error: unknown) => error instanceof TransitionError && error.code === code);
}

async function selectionFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "static-dag-selection-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "static-dag@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "static-dag"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "a.mjs"), "process.exit(0);\n");
  await writeFile(join(root, "verify", "b.mjs"), "process.exit(0);\n");
  await execFileAsync("git", ["add", "verify"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

function selectionGoal(verificationCommandIds?: readonly string[]): BoundedMutationGoal {
  const task = (taskId: string, output: string, dependencies: readonly string[]) => ({
    task_id: taskId, objective: `Write ${output}.`, editable_paths: [output], required_outputs: [output], dependencies,
    ...(verificationCommandIds === undefined ? {} : { verification_command_ids: verificationCommandIds }),
  });
  return {
    objective: "Write the static selection outputs.", stop_condition: "Stop after deterministic verification.", execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["a.txt", "b.txt", "verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] }, required_outputs: ["a.txt", "b.txt"],
    tasks: [task("selection-a", "a.txt", []), task("selection-b", "b.txt", ["selection-a"])],
  };
}

function selectionAuthority(): BoundedMutationAuthority {
  return { verification_commands: [
    { command_id: "verify-a", executable: process.execPath, args: ["a.mjs"], cwd: "verify" },
    { command_id: "verify-b", executable: process.execPath, args: ["b.mjs"], cwd: "verify" },
  ] };
}

function selectionRuntime(): BoundedWorkerRuntime {
  let index = 0;
  return {
    async execute({ route, tools }) {
      assert.equal(route.logicalRole, "TERRA_EXECUTOR");
      const path = ["a.txt", "b.txt"][index++]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("static selection mutation");
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  };
}

async function assertNonStaticSelectionRejectedBeforeAdmission(execution_mode: "DIRECT_LUNA_HIGH" | "SINGLE_OWNER_SOL" | "ROUTED_DAG"): Promise<void> {
  const root = await selectionFixture(); let workerProviderEntries = 0; let taskApprovals = 0;
  const goal = execution_mode === "ROUTED_DAG"
    ? { ...selectionGoal(["verify-a"]), execution_mode }
    : { ...selectionGoal(["verify-a"]), execution_mode, required_outputs: ["a.txt"], tasks: [{ task_id: "single", objective: "single", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [], verification_command_ids: ["verify-a"] }] };
  configureBoundedWorkerFauxRuntimeForTests(() => ({ async execute() { workerProviderEntries += 1; return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 }; } }));
  try {
    const result = await runBoundedMutationWorkflowForTests(goal, {
      cwd: root, authority: selectionAuthority(), approveTasks: async () => { taskApprovals += 1; return null; },
    });
    assert.equal(result.outcome, "BLOCKED"); assert.match(result.reason, /verification_command_ids is restricted to STATIC_APPROVED_DAG/);
    assert.equal(taskApprovals, 0); assert.equal(workerProviderEntries, 0);
    const status = await execFileAsync("git", ["status", "--porcelain"], { cwd: root });
    assert.equal(status.stdout, "");
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(root, { recursive: true, force: true });
  }
}

function staticReady(policy = makePolicy("STATIC_APPROVED_DAG")): { readonly policy: ReducerPolicy; readonly state: WorkflowState } {
  let state = (awaitCommon(policy));
  state = applyEvent(state, policy, "FREEZE_STATIC_DAG");
  state = applyEvent(state, policy, "ACTIVATE_DAG");
  return { policy, state };
}

function awaitCommon(policy: ReducerPolicy): WorkflowState {
  let state = createInitialState(policy, stateIdentities(policy));
  for (const [event, payload] of [
    ["FREEZE_OBJECTIVE", {}], ["ACQUIRE_LOCK", {}], ["CAPTURE_BASELINE", { approval_required: false }],
    ["ACCEPT_CLEAN_BASELINE", {}], ["PASS_FULL_PREFLIGHT", {}], ["VALIDATE_CONTRACT", {}],
    ["SELECT_ROUTE", { execution_mode: "STATIC_APPROVED_DAG" }],
  ] as const) state = applyEvent(state, policy, event, payload);
  return state;
}

function passLeaf(state: WorkflowState, policy: ReducerPolicy, id: string): WorkflowState {
  let next = applyEvent(state, policy, "SELECT_READY_LEAF");
  assert.equal(next.active_task_id, id);
  assert.equal(next.tasks.filter((task) => task.status === "RUNNING").length, 0);
  next = applyEvent(next, policy, "START_LEAF_ATTEMPT");
  assert.equal(next.counters.worker_invocations.terra_executor, next.tasks.reduce((count, task) => count + task.attempts, 0));
  assert.equal(next.tasks.filter((task) => task.status === "RUNNING").length, 1);
  next = applyEvent(next, policy, "COMPLETE_LEAF_ATTEMPT");
  next = applyEvent(next, policy, "PASS_LEAF_POSTFLIGHT");
  return applyEvent(next, policy, "LEAF_VERIFICATION_PASSED");
}

test("STATIC_APPROVED_DAG accepts only the exact frozen Terra role and canonical route", () => {
  const task = identifyContractDocument("pi_gacw_task_v0", {
    schema_id: "pi_gacw_task_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    task_projection_id: "task-packet-v1", task_sha256: digest(901), task_id: "terra-task", topological_rank: 0, priority: 0,
    dependencies: [], objective: "Implement exactly the frozen task.", scope: { readable_paths: ["src"], editable_paths: ["src/terra"], frozen_paths: ["docs"] },
    required_inputs: ["src"], required_outputs: ["src/terra"], acceptance_criteria: [{ criterion_id: "verify", description: "Deterministic verification passes.", evidence_kind: "COMMAND", owner_acceptance: false }],
    owner_acceptance_criteria: [], verification_commands: [], assigned_role: "TERRA_EXECUTOR", write_owner: "terra-task",
  }) as TaskDocument;
  assertDocumentValid("pi_gacw_task_v0", task);
  assertDocumentValid("pi_gacw_plan_approval_v0", planApprovalDocument("STATIC_APPROVED_DAG"));

  const wrongModel = route("TERRA_EXECUTOR"); wrongModel.model_id = "gpt-5.6-luna";
  assert.throws(() => identifyContractDocument("pi_gacw_route_map_v0", {
    schema_id: "pi_gacw_route_map_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", route_map_projection_id: "route-map-v1",
    routes: [route("SOL_OWNER"), route("SOL_PLANNER"), route("SOL_REPLAN"), route("SOL_CLOSEOUT"), route("LUNA_EXECUTOR"), wrongModel, route("BENCHMARK_VERIFIER"), route("BENCHMARK_SELECTOR")], fallback: false, provider_managed_multi_agent: false,
  }), (error: unknown) => error instanceof ContractValidationError && error.code === "INVALID_TERRA_ROUTE");

  const wrongPlan = planApprovalDocument("STATIC_APPROVED_DAG"); wrongPlan.bindings.logical_routes = [route("LUNA_EXECUTOR")];
  assert.throws(() => identifyContractDocument("pi_gacw_plan_approval_v0", wrongPlan), (error: unknown) => error instanceof ContractValidationError && error.code === "STATIC_DAG_ROUTE_RESTRICTED");
});

test("STATIC_APPROVED_DAG executes a frozen three-node DAG sequentially to PASS without planner or closeout", () => {
  const policy = makePolicy("STATIC_APPROVED_DAG", { tasks: [
    { task_id: "task-a", task_sha256: digest(910), topological_rank: 0, priority: 1, dependencies: [], editable_paths: ["src/a"] },
    { task_id: "task-b", task_sha256: digest(911), topological_rank: 0, priority: 0, dependencies: [], editable_paths: ["src/b"] },
    { task_id: "task-c", task_sha256: digest(912), topological_rank: 1, priority: 0, dependencies: ["task-b"], editable_paths: ["src/c"] },
  ] });
  let state = staticReady(policy).state;
  state = passLeaf(state, policy, "task-b");
  state = passLeaf(state, policy, "task-a");
  state = passLeaf(state, policy, "task-c");
  assert.equal(state.phase, "STATIC_DAG_VERIFYING");
  state = applyEvent(state, policy, "STATIC_DAG_VERIFICATION_PASSED");
  assert.equal(state.phase, "PASS");
  assert.equal(state.counters.worker_invocations.terra_executor, 3);
  assert.equal(state.counters.worker_invocations.sol_planner, 0);
  assert.equal(state.counters.worker_invocations.sol_replan, 0);
  assert.equal(state.counters.worker_invocations.sol_closeout, 0);
  assert.equal(state.counters.worker_invocations.luna_executor, 0);
  assert.equal(state.tasks.every((task) => task.status === "PASS"), true);
});

test("STATIC_APPROVED_DAG admits exactly one frozen local-defect repair and otherwise blocks", () => {
  const repairPolicy = makePolicy("STATIC_APPROVED_DAG", { limits: { max_attempts_per_leaf: 2 } });
  let state = staticReady(repairPolicy).state;
  state = applyEvent(state, repairPolicy, "SELECT_READY_LEAF");
  state = applyEvent(state, repairPolicy, "START_LEAF_ATTEMPT");
  state = applyEvent(state, repairPolicy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, repairPolicy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, repairPolicy, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "LEAF_RETRY_READY");
  state = applyEvent(state, repairPolicy, "ADMIT_LEAF_RETRY", { progress_delta: { kind: "NEW_TEST_EVIDENCE", evidence_sha256: digest(920), summary: "Trusted deterministic verifier isolated a local implementation defect." } });
  state = applyEvent(state, repairPolicy, "START_LEAF_ATTEMPT");
  assert.equal(state.counters.worker_invocations.terra_executor, 2);
  state = applyEvent(state, repairPolicy, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, repairPolicy, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, repairPolicy, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "BLOCKED");

  const noRepair = makePolicy("STATIC_APPROVED_DAG", { limits: { max_attempts_per_leaf: 1 } });
  state = staticReady(noRepair).state;
  state = applyEvent(state, noRepair, "SELECT_READY_LEAF");
  state = applyEvent(state, noRepair, "START_LEAF_ATTEMPT");
  state = applyEvent(state, noRepair, "COMPLETE_LEAF_ATTEMPT");
  state = applyEvent(state, noRepair, "PASS_LEAF_POSTFLIGHT");
  state = applyEvent(state, noRepair, "LEAF_VERIFICATION_FAILED", { failure_class: "LOCAL_IMPLEMENTATION_DEFECT" });
  assert.equal(state.phase, "BLOCKED");

  const unsafe = staticReady(repairPolicy).state;
  let unknown = applyEvent(unsafe, repairPolicy, "SELECT_READY_LEAF");
  unknown = applyEvent(unknown, repairPolicy, "START_LEAF_ATTEMPT");
  unknown = applyEvent(unknown, repairPolicy, "COMPLETE_LEAF_ATTEMPT");
  unknown = applyEvent(unknown, repairPolicy, "PASS_LEAF_POSTFLIGHT");
  unknown = applyEvent(unknown, repairPolicy, "LEAF_VERIFICATION_FAILED", { failure_class: "MODEL_UNAVAILABLE" });
  assert.equal(unknown.phase, "BLOCKED");
  expectCode(() => reduceState(unknown, transitionEvent("START_LEAF_ATTEMPT"), repairPolicy), "TERMINAL_STATE_IMMUTABLE");
});

test("STATIC_APPROVED_DAG cannot invoke replan/closeout or grow its frozen task set", () => {
  const { policy, state } = staticReady();
  expectCode(() => applyEvent(state, policy, "START_PLAN"), "INVALID_TRANSITION");
  expectCode(() => applyEvent(state, policy, "START_CONSTRAINED_REPLAN"), "INVALID_TRANSITION");
  expectCode(() => applyEvent(state, policy, "START_CLOSEOUT"), "INVALID_TRANSITION");
  const substituted = structuredClone(policy) as MutableJson;
  substituted.tasks.push({ task_id: "task-extra", task_sha256: digest(999), topological_rank: 2, priority: 0, dependencies: ["task-b"], editable_paths: ["src/extra"] });
  const grown = identifyContractDocument("pi_gacw_reducer_policy_v0", substituted) as ReducerPolicy;
  assert.throws(() => reduceState(state, transitionEvent("SELECT_READY_LEAF"), grown), (error: unknown) => error instanceof ContractValidationError && error.code === "FROZEN_POLICY_IDENTITY_MISMATCH");
});

test("STATIC_APPROVED_DAG binds optional selected verifiers fail-closed and preserves the Terra-only route", async (t) => {
  const runSelection = async (verificationCommandIds: readonly string[] | undefined, expectedTaskCommands: readonly string[], expectedRecords: readonly string[]) => {
    const root = await selectionFixture(); const retained = await mkdtemp(join(tmpdir(), "static-dag-selection-evidence-"));
    const taskCommands: string[][][] = []; const runtime = selectionRuntime();
    configureBoundedWorkerFauxRuntimeForTests(() => runtime);
    try {
      const result = await runBoundedMutationWorkflowForTests(selectionGoal(verificationCommandIds), {
        cwd: root, authority: selectionAuthority(), retainedArtifactRoot: retained,
        approveTasks: async ({ contract, plan, tasks }) => {
          taskCommands.push(tasks.map((task) => task.verification_commands.map((command) => command.command_id)));
          return (plan?.content_sha256 ?? contract.content_sha256) as `sha256:${string}`;
        },
      });
      assert.equal(result.outcome, "PASS", result.reason);
      assert.deepEqual(taskCommands, [[expectedTaskCommands, expectedTaskCommands]]);
      assert.equal(result.finalState?.counters.worker_invocations.terra_executor, 2);
      assert.equal(result.finalState?.counters.worker_invocations.sol_planner, 0);
      assert.equal(result.finalState?.counters.worker_invocations.sol_closeout, 0);
      assert.equal(result.finalState?.counters.worker_invocations.luna_executor, 0);
      const records = await readM5ManagedRecords({ stateRoot: join(result.evidenceRoot!, "state"), runId: "pre-m8-bounded" });
      assert.deepEqual(records.commandResults.map((record) => record.command_id).sort(), [...expectedRecords].sort());
    } finally {
      configureBoundedWorkerFauxRuntimeForTests(undefined);
      await rm(retained, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
    }
  };

  await t.test("absence defaults every leaf to all frozen commands", async () => {
    await runSelection(undefined, ["verify-a", "verify-b"], ["verify-a", "verify-b", "verify-a", "verify-b", "verify-a", "verify-b"]);
  });
  await t.test("selected-only leaves exclude unselected verifiers while final verification remains complete", async () => {
    await runSelection(["verify-b"], ["verify-b"], ["verify-b", "verify-b", "verify-a", "verify-b"]);
  });
  await t.test("selected identifiers resolve in frozen controller-command order", async () => {
    await runSelection(["verify-b", "verify-a"], ["verify-a", "verify-b"], ["verify-a", "verify-b", "verify-a", "verify-b", "verify-a", "verify-b"]);
  });

  const invalid = async (goal: unknown, expectedReason: string) => {
    const result = await runBoundedMutationWorkflowForTests(goal, { authority: selectionAuthority() });
    assert.equal(result.outcome, "BLOCKED"); assert.match(result.reason, new RegExp(expectedReason));
  };
  await t.test("malformed and duplicate selections reject deterministically", async () => {
    await invalid(selectionGoal(["not valid"]), "invalid identifiers");
    await invalid(selectionGoal(["verify-a", "verify-a"]), "invalid identifiers");
  });
  await t.test("unknown selection blocks before Terra worker admission", async () => {
    const root = await selectionFixture(); let calls = 0;
    configureBoundedWorkerFauxRuntimeForTests(() => ({ async execute() { calls += 1; return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 }; } }));
    try {
      const result = await runBoundedMutationWorkflowForTests(selectionGoal(["unknown"]), { cwd: root, authority: selectionAuthority() });
      assert.equal(result.outcome, "BLOCKED"); assert.match(result.reason, /UNKNOWN_STATIC_VERIFICATION_COMMAND/); assert.equal(calls, 0);
    } finally {
      configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(root, { recursive: true, force: true });
    }
  });
});

test("verification selection rejects DIRECT_LUNA_HIGH, SINGLE_OWNER_SOL, and ROUTED_DAG before worker/provider admission or mutation", async (t) => {
  for (const execution_mode of ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const) {
    await t.test(execution_mode, async () => { await assertNonStaticSelectionRejectedBeforeAdmission(execution_mode); });
  }
});


test("STATIC_APPROVED_DAG binds only the owner-selected Terra effort and never escalates", async (t) => {
  for (const [label, effort] of [["default high", "high"], ["explicit xhigh", "xhigh"]] as const) {
    await t.test(label, async () => {
      const root = await selectionFixture();
      const retained = await mkdtemp(join(tmpdir(), "static-dag-effort-"));
      const workerEfforts: string[] = [];
      const planEfforts: string[] = [];
      configureBoundedWorkerFauxRuntimeForTests(() => ({
        async execute({ route }) {
          workerEfforts.push(route.effort);
          return { completed: false, firstFailureCode: "MODEL_UNAVAILABLE", firstFailureStage: "PROVIDER", cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        },
      }));
      try {
        const result = await runBoundedMutationWorkflowForTests(selectionGoal(["verify-a"]), {
          cwd: root,
          authority: { ...selectionAuthority(), ...(effort === "xhigh" ? { static_terra_effort: "xhigh" as const } : {}) },
          retainedArtifactRoot: retained,
          approveTasks: async ({ plan, executionAuthority }) => {
            planEfforts.push(plan!.bindings.logical_routes[0]!.effort);
            assert.equal(executionAuthority.route_map.routes.find((route) => route.logical_role === "TERRA_EXECUTOR")?.effort, effort);
            return plan!.content_sha256 as `sha256:${string}`;
          },
        });
        assert.equal(result.outcome, "BLOCKED");
        assert.deepEqual(planEfforts, [effort]);
        assert.deepEqual(workerEfforts, [effort]);
      } finally {
        configureBoundedWorkerFauxRuntimeForTests(undefined);
        await rm(retained, { recursive: true, force: true });
        await rm(root, { recursive: true, force: true });
      }
    });
  }

  for (const execution_mode of ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const) {
    const result = await runBoundedMutationWorkflowForTests({
      objective: "mode isolation", stop_condition: "stop", execution_mode,
      scope: execution_mode === "ROUTED_DAG" ? { readable_paths: ["a.txt", "b.txt"], editable_paths: ["a.txt", "b.txt"], frozen_paths: [] } : { readable_paths: ["a.txt"], editable_paths: ["a.txt"], frozen_paths: [] },
      required_outputs: execution_mode === "ROUTED_DAG" ? ["a.txt", "b.txt"] : ["a.txt"],
      tasks: execution_mode === "ROUTED_DAG"
        ? [{ task_id: "a", objective: "a", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] }, { task_id: "b", objective: "b", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["a"] }]
        : [{ task_id: "a", objective: "a", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] }],
    }, { authority: { verification_commands: [], static_terra_effort: "xhigh" } });
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /INVALID_STATIC_TERRA_EFFORT/);
  }

  const rejectedMax = await runBoundedMutationWorkflowForTests(selectionGoal(), {
    authority: { verification_commands: [], static_terra_effort: "max" as never },
  });
  assert.equal(rejectedMax.outcome, "BLOCKED");
  assert.match(rejectedMax.reason, /INVALID_STATIC_TERRA_EFFORT/);

  const root = await selectionFixture();
  const retained = await mkdtemp(join(tmpdir(), "static-dag-no-escalation-"));
  const efforts: string[] = [];
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ route }) {
      efforts.push(route.effort);
      return { completed: false, firstFailureCode: "MODEL_UNAVAILABLE", firstFailureStage: "PROVIDER", cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  }));
  try {
    const result = await runBoundedMutationWorkflowForTests(selectionGoal(["verify-a"]), {
      cwd: root, retainedArtifactRoot: retained,
      authority: { ...selectionAuthority(), static_max_attempts_per_leaf: 2 },
      approveTasks: async ({ plan }) => plan!.content_sha256 as `sha256:${string}`,
    });
    assert.equal(result.outcome, "BLOCKED");
    assert.deepEqual(efforts, ["high"]);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(retained, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test("STATIC_APPROVED_DAG forwards the exact V2 coding route to the bounded worker without substitution", async () => {
  const root = await selectionFixture();
  const retained = await mkdtemp(join(tmpdir(), "static-dag-coding-route-"));
  const workerRoutes: unknown[] = [];
  const planRoutes: unknown[] = [];
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ route, tools }) {
      workerRoutes.push({ ...route });
      const path = ["a.txt", "b.txt"][workerRoutes.length - 1]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("coding executor mutation");
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  }));
  try {
    const result = await runBoundedMutationWorkflowForTests(selectionGoal(), {
      cwd: root, retainedArtifactRoot: retained,
      authority: { ...selectionAuthority(), static_coding_route: { provider_id: "provider-a", model_id: "model-a", effort: "high" } },
      approveTasks: async ({ plan, executionAuthority }) => {
        planRoutes.push(plan!.bindings.logical_routes.map(({ logical_role, provider_id, model_id, effort }) => ({ logical_role, provider_id, model_id, effort })));
        const codingRoute = executionAuthority.route_map.routes.find((route) => route.logical_role === "CODING_EXECUTOR");
        assert.equal(codingRoute?.provider_id, "provider-a");
        assert.equal(codingRoute?.model_id, "model-a");
        assert.equal(codingRoute?.effort, "high");
        assert.equal(executionAuthority.route_map.fallback, false);
        return plan!.content_sha256 as `sha256:${string}`;
      },
    });
    assert.equal(result.outcome, "PASS", result.reason);
    assert.deepEqual(planRoutes, [[{ logical_role: "CODING_EXECUTOR", provider_id: "provider-a", model_id: "model-a", effort: "high" }]]);
    assert.equal(workerRoutes.length, 2);
    for (const route of workerRoutes) assert.deepEqual(route, { logicalRole: "CODING_EXECUTOR", providerId: "provider-a", modelId: "model-a", effort: "high" });
    // The legacy persisted storage slot keeps counting static coding invocations.
    assert.equal(result.finalState?.counters.worker_invocations.terra_executor, 2);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(retained, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("V2 coding route authority is bounded: escalation, dual authority, malformed identity, and non-static modes reject before admission", async (t) => {
  const invalidAuthority = async (authority: BoundedMutationAuthority, pattern: RegExp) => {
    const result = await runBoundedMutationWorkflowForTests(selectionGoal(), { authority });
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, pattern);
  };
  await t.test("xhigh effort rejects", () => invalidAuthority({ ...selectionAuthority(), static_coding_route: { provider_id: "provider-a", model_id: "model-a", effort: "xhigh" as never } }, /INVALID_STATIC_CODING_ROUTE/));
  await t.test("max effort rejects", () => invalidAuthority({ ...selectionAuthority(), static_coding_route: { provider_id: "provider-a", model_id: "model-a", effort: "max" as never } }, /INVALID_STATIC_CODING_ROUTE/));
  await t.test("unbounded provider identifier rejects", () => invalidAuthority({ ...selectionAuthority(), static_coding_route: { provider_id: "bad provider", model_id: "model-a", effort: "high" } }, /INVALID_STATIC_CODING_ROUTE/));
  await t.test("dual Terra and coding authority rejects", () => invalidAuthority({ ...selectionAuthority(), static_terra_effort: "xhigh", static_coding_route: { provider_id: "provider-a", model_id: "model-a", effort: "high" } }, /INVALID_STATIC_CODING_ROUTE/));
  await t.test("non-static mode rejects", () => {
    const result = runBoundedMutationWorkflowForTests({
      objective: "mode isolation", stop_condition: "stop", execution_mode: "DIRECT_LUNA_HIGH",
      scope: { readable_paths: ["a.txt"], editable_paths: ["a.txt"], frozen_paths: [] }, required_outputs: ["a.txt"],
      tasks: [{ task_id: "a", objective: "a", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] }],
    }, { authority: { verification_commands: [], static_coding_route: { provider_id: "provider-a", model_id: "model-a", effort: "high" } } });
    return result.then((outcome) => { assert.equal(outcome.outcome, "BLOCKED"); assert.match(outcome.reason, /INVALID_STATIC_CODING_ROUTE/); });
  });
});

test("STATIC_APPROVED_DAG forwards the exact discovered Ox route (openrouter / stealth/ox-alpha) without rewriting", async () => {
  const root = await selectionFixture();
  const retained = await mkdtemp(join(tmpdir(), "static-dag-ox-route-"));
  const workerRoutes: unknown[] = [];
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ route, tools }) {
      workerRoutes.push({ ...route });
      const path = ["a.txt", "b.txt"][workerRoutes.length - 1]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("ox route mutation");
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  }));
  try {
    const result = await runBoundedMutationWorkflowForTests(selectionGoal(), {
      cwd: root, retainedArtifactRoot: retained,
      authority: { ...selectionAuthority(), static_coding_route: { provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high" } },
      approveTasks: async ({ plan, executionAuthority }) => {
        const codingRoute = executionAuthority.route_map.routes.find((route) => route.logical_role === "CODING_EXECUTOR");
        assert.equal(codingRoute?.provider_id, "openrouter");
        assert.equal(codingRoute?.model_id, "stealth/ox-alpha");
        assert.equal(codingRoute?.effort, "high");
        assert.deepEqual(plan!.bindings.logical_routes.map(({ logical_role, provider_id, model_id, effort }) => ({ logical_role, provider_id, model_id, effort })), [{ logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high" }]);
        return plan!.content_sha256 as `sha256:${string}`;
      },
    });
    assert.equal(result.outcome, "PASS", result.reason);
    assert.equal(workerRoutes.length, 2);
    for (const route of workerRoutes) assert.deepEqual(route, { logicalRole: "CODING_EXECUTOR", providerId: "openrouter", modelId: "stealth/ox-alpha", effort: "high" });
    assert.equal(result.finalState?.counters.worker_invocations.terra_executor, 2);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(retained, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("V2 controller authority rejects malformed routing identities before admission", async (t) => {
  const invalidAuthority = async (providerId: string, modelId: string) => {
    const result = await runBoundedMutationWorkflowForTests(selectionGoal(), { authority: { ...selectionAuthority(), static_coding_route: { provider_id: providerId, model_id: modelId, effort: "high" } } });
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /INVALID_STATIC_CODING_ROUTE/);
  };
  await t.test("empty provider rejects", () => invalidAuthority("", "stealth/ox-alpha"));
  await t.test("embedded whitespace rejects", () => invalidAuthority("open router", "stealth/ox-alpha"));
  await t.test("newline rejects", () => invalidAuthority("openrouter", "stealth/\nox-alpha"));
  await t.test("oversize model id rejects", () => invalidAuthority("openrouter", `a${"x".repeat(128)}`));
});
