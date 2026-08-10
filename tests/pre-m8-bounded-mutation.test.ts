import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createControlDecisionKernel } from "../src/control/index.js";
import { ControlDecisionError } from "../src/control/errors.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { resolveAuthoritativeBoundedExecution } from "../src/persistence/bounded-worker-authority.js";
import { publishBoundedWorkerRecord, readM5ManagedRecords } from "../src/persistence/store.js";
import { releaseWorktreeLock, resolveRepositoryIdentity } from "../src/repository/index.js";
import {
  runBoundedMutationWorkflow,
  runBoundedMutationWorkflowForTests,
  type BoundedMutationAuthority,
  type BoundedMutationGoal,
} from "../src/workflow-controller.js";
import { configureBoundedWorkerFauxRuntimeForTests, type BoundedWorkerRuntime } from "../src/pi-adapter/bounded-worker.js";
import { configureM6FauxRuntimeForTests, runBoundedPiAgent, runBoundedPiAgentForTests } from "../src/pi-adapter/worker.js";
import { assertDocumentValid, identifyContractDocument } from "../src/schemas/index.js";
import { createM5R3Fixture, removeM5R3Fixture, r3ProcessMetadata } from "./m5-r3-fixtures.js";

const execFileAsync = promisify(execFile);

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value as JsonRecord;
}

function method(value: JsonRecord, name: string): (...args: readonly unknown[]) => unknown {
  const candidate = value[name];
  assert.equal(typeof candidate, "function", `${name} must be callable`);
  return (...args) => Reflect.apply(candidate as (...values: readonly unknown[]) => unknown, value, args);
}

function installBoundedPiFauxRuntime(toolNames: readonly string[]): () => number {
  let providerCalls = 0;
  configureM6FauxRuntimeForTests({ providerId: "bounded-faux", modelId: "bounded-faux-model" }, ({ aiModule, providerId, modelId }) => {
    const ai = record(aiModule, "Pi AI module");
    const faux = record(method(ai, "fauxProvider")({
      api: "bounded-faux-api", provider: providerId, models: [{ id: modelId, name: modelId, reasoning: true, input: ["text"] }], tokensPerSecond: 0,
    }), "faux provider");
    const models = record(method(ai, "createModels")(), "faux models");
    method(models, "setProvider")(faux["provider"]);
    const model = method(models, "getModel")(providerId, modelId);
    const assistant = method(ai, "fauxAssistantMessage");
    const toolCall = method(ai, "fauxToolCall");
    method(faux, "setResponses")(toolNames.map((name) => assistant(toolCall(name, {}), { stopReason: "toolUse" })));
    return {
      models,
      model,
      streamFn: (streamModel: unknown, context: unknown, options?: unknown): unknown => {
        providerCalls += 1;
        return method(models, "streamSimple")(streamModel, context, options);
      },
      clearProviderState: (): void => { method(faux, "setResponses")([]); },
      pendingResponseCount: (): unknown => method(faux, "getPendingResponseCount")(),
    };
  });
  return () => providerCalls;
}

function boundedPiAgentInput(maxModelTurns: number): Parameters<typeof runBoundedPiAgent>[0] {
  return {
    providerId: "bounded-faux", modelId: "bounded-faux-model", effort: "high", systemPrompt: "bounded", userPrompt: "bounded",
    tools: [
      { name: "observe", label: "observe", description: "observe", parameters: { type: "object", additionalProperties: false }, async execute() { return { content: [], details: {} }; } },
      { name: "submit_report", label: "submit", description: "submit", parameters: { type: "object", additionalProperties: false }, async execute() { return { content: [], details: {} }; } },
    ],
    maxM4ToolCalls: 4, maxModelTurns, deadlineMs: 5_000,
  };
}

function unresolvedBoundedDocuments(runId: string, policyContentSha256: string, stateContentSha256: string) {
  const digest = (character: string) => `sha256:${character.repeat(64)}`;
  const invocation = identifyContractDocument("pi_gacw_bounded_worker_invocation_v0", {
    schema_id: "pi_gacw_bounded_worker_invocation_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    invocation_key: digest("a"), run_id: runId, operation_id: "unresolved-operation", m5_reservation_decision_content_sha256: digest("b"),
    m5_reservation_decision_key: digest("c"), task_content_sha256: null, task_graph_sha256: null, plan_approval_sha256: null,
    input_m3_state_token_content_sha256: digest("d"), system_prompt_sha256: digest("e"), user_prompt_sha256: digest("f"), created_at: "2026-01-01T00:00:00.000Z",
  });
  const result = identifyContractDocument("pi_gacw_bounded_worker_result_v0", {
    schema_id: "pi_gacw_bounded_worker_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    invocation_content_sha256: invocation.content_sha256, outcome: "COMPLETED", first_failure_code: null, first_failure_stage: null,
    m3_evidence_content_sha256: [], m4_evidence_content_sha256: [],
    actual_usage: { worker_invocations: 1, m4_tool_calls: 0, model_turns: null, provider_requests: null, input_tokens: null, output_tokens: null, cost_microusd: null, wall_time_ms: 0 },
    cleanup_certain: true, advisory_report: null, completed_at: "2026-01-01T00:00:00.000Z",
  });
  const usage = identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: runId, policy_content_sha256: policyContentSha256, originating_state_content_sha256: stateContentSha256,
    operation_id: "unresolved-operation", operation_kind: "WORKER_INVOCATION", execution_mode: "DIRECT_LUNA_HIGH", logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: null, source_layer: "CONTROLLER", source_kind: "BOUNDED_WORKER_RESULT", source_record_content_sha256: result.content_sha256,
    measurements: [{ dimension: "WORKER_INVOCATION", amount: 1, basis: "VALIDATED", enforcement_class: "HARD_ENFORCEABLE" }], disposition: "COMPLETED", duration_ms: null,
  });
  return { invocation, result, usage };
}

async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "pre-m8-test-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "pre-m8@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "pre-m8"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "input.txt"), "input\n");
  await execFileAsync("git", ["add", "verify/input.txt"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

function authority(executable = "/usr/bin/true"): BoundedMutationAuthority {
  return { verification_commands: [{ command_id: "verify", executable, cwd: "verify" }] };
}

function goal(mode: BoundedMutationGoal["execution_mode"], outputs = ["out.txt"], editable = outputs): BoundedMutationGoal {
  const base = {
    objective: "Write the exact bounded output.",
    stop_condition: "Stop after the one bounded mutation path.",
    execution_mode: mode,
    scope: { readable_paths: [...new Set([...editable, "verify", "verify/input.txt"])], editable_paths: editable, frozen_paths: [] },
    required_outputs: outputs,
  } as const;
  if (mode !== "ROUTED_DAG") return base;
  return {
    ...base,
    tasks: outputs.map((output, index) => ({
      task_id: `leaf-${index + 1}`,
      objective: `Write ${output}.`,
      editable_paths: [output],
      required_outputs: [output],
      dependencies: index === 0 ? [] : [`leaf-${index}`],
    })),
  };
}

function writer(paths: readonly string[], options: { readonly cleanupCertain?: boolean; readonly plannerIdentity?: boolean; readonly modelTurns?: number | null } = {}): BoundedWorkerRuntime {
  let index = 0;
  return {
    async execute({ profile, tools, userPrompt }) {
      if (profile === "MUTATION_EXECUTOR") {
        const path = paths[index++]!;
        await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`written:${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      }
      if (profile === "SOL_PLANNER") {
        const digest = /candidate_plan_sha256:(sha256:[0-9a-f]{64})/u.exec(userPrompt)?.[1] ?? "missing";
        tools.submitReport(options.plannerIdentity === false ? "candidate_plan_sha256:sha256:deadbeef" : `candidate_plan_sha256:${digest}`);
      } else tools.submitReport("bounded report");
      return { completed: true, cleanupCertain: options.cleanupCertain ?? true, modelTurns: options.modelTurns ?? null, providerRequests: null };
    },
  };
}

async function run(root: string, input: BoundedMutationGoal, runtime: BoundedWorkerRuntime, extra: Parameters<typeof runBoundedMutationWorkflowForTests>[1] = {}) {
  configureBoundedWorkerFauxRuntimeForTests(() => runtime);
  try {
    return await runBoundedMutationWorkflowForTests(input, {
      cwd: root,
      authority: authority(),
      approveTasks: async ({ contract, plan }) => (plan?.content_sha256 ?? contract.content_sha256) as `sha256:${string}`,
      approveOwnerAcceptance: async () => true,
      ...extra,
    });
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
  }
}

const productionRuntimeInjectionMustRemainRejected: Parameters<typeof runBoundedMutationWorkflow>[1] = {
  // @ts-expect-error Production controller options never accept a caller runtime.
  runtime: {} as BoundedWorkerRuntime,
};
void productionRuntimeInjectionMustRemainRejected;

test("pre-M8 Direct Luna, Single Owner Sol, and sequential Routed DAG pass through the same bounded controller", async (t) => {
  for (const mode of ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const) await t.test(mode, async () => {
    const root = await fixture();
    try {
      const outputs = mode === "ROUTED_DAG" ? ["a.txt", "b.txt"] : ["out.txt"];
      const result = await run(root, goal(mode, outputs), writer(outputs));
      assert.equal(result.outcome, "PASS", result.reason);
      assert.equal(result.finalState?.phase, "PASS");
      assert.equal(result.finalState?.counters.worker_invocations.total, mode === "ROUTED_DAG" ? outputs.length + 2 : 1);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

test("out-of-scope, wrong-output, missing/failed verification, and late drift block", async (t) => {
  await t.test("out-of-scope worker write", async () => {
    const root = await fixture();
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["outside.txt"]));
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /WORKER_AUTHORITY|OUT_OF_SCOPE_WRITE/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  await t.test("unexpected in-scope output", async () => {
    const root = await fixture();
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH", ["out.txt"], ["out.txt", "extra.txt"]), writer(["extra.txt"]));
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /OUTPUT_DELTA_MISMATCH/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  await t.test("missing controller verification authority", async () => {
    const root = await fixture();
    try {
      let called = false;
      const injected: Parameters<typeof runBoundedMutationWorkflow>[1] & { readonly runtime: BoundedWorkerRuntime } = {
        cwd: root, authority: { verification_commands: [] }, runtime: { async execute() { called = true; return { completed: true, cleanupCertain: true }; } },
      };
      const result = await runBoundedMutationWorkflow(goal("DIRECT_LUNA_HIGH"), injected);
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /MISSING_REQUIRED_VERIFICATION/);
      assert.equal(called, false);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  await t.test("failed verification", async () => {
    const root = await fixture();
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["out.txt"]), {
        authority: authority("/usr/bin/false"),
      });
      assert.equal(result.outcome, "BLOCKED");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  await t.test("late drift after final verification", async () => {
    const root = await fixture();
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["out.txt"]), { beforeFinalPostflight: async () => writeFile(join(root, "out.txt"), "late drift\n") });
      assert.equal(result.outcome, "BLOCKED");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

test("dirty baseline needs exact approval before a worker can execute", async (t) => {
  const root = await fixture();
  try {
    await writeFile(join(root, "dirty.txt"), "dirty\n");
    const dirtyAuthority: BoundedMutationAuthority = {
      ...authority(),
      dirty_baseline_decisions: [{ path: "dirty.txt", ownershipClass: "PREEXISTING_UNRELATED", dataClass: null, captureMode: "HASH_ONLY", explicitBlobApproval: false, retentionDaysAfterTerminal: null }],
    };
    let calls = 0;
    const runtime: BoundedWorkerRuntime = { async execute() { calls += 1; return { completed: true, cleanupCertain: true }; } };
    const denied = await run(root, { ...goal("DIRECT_LUNA_HIGH"), baseline_mode: "APPROVED_BASELINE_DIRTY" }, runtime, { authority: dirtyAuthority });
    assert.equal(denied.outcome, "BLOCKED");
    assert.equal(calls, 0);
    const substituted = await run(root, { ...goal("DIRECT_LUNA_HIGH"), baseline_mode: "APPROVED_BASELINE_DIRTY" }, runtime, {
      authority: dirtyAuthority,
      approveBaseline: async () => ({ baseline_content_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000", approved_by: "owner", approved_at: "2026-01-01T00:00:00.000Z" }),
    });
    assert.equal(substituted.outcome, "BLOCKED");
    assert.equal(calls, 0);

    let approvedBaseline: { readonly content_sha256: string } | undefined;
    let finalContract: { readonly baseline_approval_sha256: string } | undefined;
    const accepted = await run(root, { ...goal("DIRECT_LUNA_HIGH"), baseline_mode: "APPROVED_BASELINE_DIRTY" }, writer(["out.txt"]), {
      authority: dirtyAuthority,
      approveBaseline: async (baseline) => {
        approvedBaseline = baseline;
        return { baseline_content_sha256: baseline.content_sha256 as `sha256:${string}`, approved_by: "owner", approved_at: "2026-01-01T00:00:00.000Z" };
      },
      approveTasks: async ({ contract }) => {
        finalContract = contract;
        return contract.content_sha256 as `sha256:${string}`;
      },
    });
    assert.equal(accepted.outcome, "PASS", accepted.reason);
    assert.notEqual(finalContract?.baseline_approval_sha256, approvedBaseline?.content_sha256, "dirty Contract must bind the exact BaselineApproval, not the raw baseline");
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("clean baseline identity is the exact final Contract authority and changes with the baseline", async () => {
  const root = await fixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: root, requireHead: true });
  const retainedControllerRoot = join(tmpdir(), `pi-pre-m8-bounded-${repository.worktree_key.slice(7)}`);
  const capture = async () => {
    let contract: { readonly baseline_approval_sha256: string } | undefined;
    const result = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["out.txt"]), {
      approveTasks: async ({ contract: candidate }) => { contract = candidate; return candidate.content_sha256 as `sha256:${string}`; },
      releaseLock: async (handle) => { await releaseWorktreeLock(handle); throw new Error("preserve test authority records"); },
    });
    assert.equal(result.outcome, "BLOCKED");
    assert.equal(result.finalState?.phase, "PASS");
    const records = await readM5ManagedRecords({ stateRoot: join(retainedControllerRoot, "state"), runId: "pre-m8-bounded" });
    assert.equal(records.approvals.length, 0);
    assert.equal(records.baselines.length, 1);
    assert.equal(contract?.baseline_approval_sha256, records.baselines[0]!.content_sha256);
    await rm(retainedControllerRoot, { recursive: true, force: true });
    return { baseline: records.baselines[0]!.content_sha256, contract: contract!.baseline_approval_sha256 };
  };
  try {
    const first = await capture();
    await rm(join(root, "out.txt"));
    await writeFile(join(root, "verify", "input.txt"), "changed baseline\n");
    await execFileAsync("git", ["add", "verify/input.txt"], { cwd: root });
    await execFileAsync("git", ["commit", "-qm", "changed baseline"], { cwd: root });
    const second = await capture();
    assert.notEqual(first.baseline, second.baseline);
    assert.notEqual(first.contract, second.contract);
  } finally { await rm(retainedControllerRoot, { recursive: true, force: true }); await rm(root, { recursive: true, force: true }); }
});

test("task and Plan identities cannot substitute for final execution approval", async (t) => {
  for (const mode of ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const) await t.test(mode, async () => {
    const root = await fixture();
    let calls = 0;
    const runtime: BoundedWorkerRuntime = {
      async execute({ tools, profile }) {
        calls += 1;
        if (profile === "MUTATION_EXECUTOR") await tools.writePath({ path: "out.txt", operation: "CREATE", replacementBytes: Buffer.from("out\n"), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
        return { completed: true, cleanupCertain: true };
      },
    };
    try {
      const result = await run(root, goal(mode, mode === "ROUTED_DAG" ? ["a.txt", "b.txt"] : ["out.txt"]), runtime, {
        approveTasks: async ({ contract, tasks }) => tasks[0]!.content_sha256 as `sha256:${string}`,
      });
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /EXECUTION_APPROVAL_MISMATCH/);
      assert.equal(calls, 0, "no planner or mutation worker may start under a task-only approval");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

test("cleanup uncertainty and lock-release uncertainty never produce an outward pass", async (t) => {
  await t.test("worker cleanup uncertainty", async () => {
    const root = await fixture();
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["out.txt"], { cleanupCertain: false }));
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /WORKER_AUTHORITY|CLEANUP/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  await t.test("lock release uncertainty", async () => {
    const root = await fixture();
    const repository = await resolveRepositoryIdentity({ requestedPath: root, requireHead: true });
    const retainedControllerRoot = join(tmpdir(), `pi-pre-m8-bounded-${repository.worktree_key.slice(7)}`);
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["out.txt"]), {
        releaseLock: async (handle) => { await releaseWorktreeLock(handle); throw new Error("test release acknowledgement lost"); },
      });
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /BLOCKED_CLEANUP_UNCERTAIN/);
      assert.equal(result.finalState?.phase, "PASS");
    } finally { await rm(root, { recursive: true, force: true }); await rm(retainedControllerRoot, { recursive: true, force: true }); }
  });
});

test("bounded-worker result preserves unavailable telemetry as null", () => {
  const result = identifyContractDocument("pi_gacw_bounded_worker_result_v0", {
    schema_id: "pi_gacw_bounded_worker_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    invocation_content_sha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    outcome: "COMPLETED", first_failure_code: null, first_failure_stage: null, m3_evidence_content_sha256: [], m4_evidence_content_sha256: [],
    actual_usage: { worker_invocations: 1, m4_tool_calls: 0, model_turns: null, provider_requests: null, input_tokens: null, output_tokens: null, cost_microusd: null, wall_time_ms: 0 },
    cleanup_certain: true, advisory_report: null, completed_at: "2026-01-01T00:00:00.000Z",
  });
  assertDocumentValid("pi_gacw_bounded_worker_result_v0", result);
  assert.equal(result.actual_usage.model_turns, null);
  assert.equal(result.actual_usage.provider_requests, null);
});

test("test-only bounded runtime requires explicit registered provenance", async () => {
  const root = await fixture();
  configureBoundedWorkerFauxRuntimeForTests(undefined);
  try {
    const result = await runBoundedMutationWorkflowForTests(goal("DIRECT_LUNA_HIGH"), {
      cwd: root, authority: authority(),
      approveTasks: async ({ contract }) => contract.content_sha256 as `sha256:${string}`,
    });
    assert.equal(result.outcome, "BLOCKED");
    assert.equal(result.finalState?.phase, "BLOCKED");
    assert.match(result.reason, /No registered test-only bounded runtime provenance is active/);
  } finally { configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(root, { recursive: true, force: true }); }
});

test("zero remaining model turns reject before Pi runtime or provider admission", async () => {
  const result = await runBoundedPiAgent({
    providerId: "must-not-be-loaded", modelId: "must-not-be-loaded", effort: "high", systemPrompt: "bounded", userPrompt: "bounded",
    tools: [{ name: "report", label: "report", description: "report", parameters: {}, async execute() { return { content: [], details: {} }; } }],
    maxM4ToolCalls: 1, maxModelTurns: 0, deadlineMs: 1,
  });
  assert.equal(result.completed, false);
  assert.equal(result.firstFailureCode, "MODEL_TURN_BUDGET_EXHAUSTED");
  assert.equal(result.firstFailureStage, "MODEL_TURN_ADMISSION");
  assert.equal(result.modelTurns, 0);
  assert.equal(result.providerRequests, 0);
});

test("bounded Pi telemetry counts only genuinely started generations", async (t) => {
  await t.test("pre-generation rejection starts no provider stream or model turn", async () => {
    const providerCalls = installBoundedPiFauxRuntime([]);
    try {
      const result = await runBoundedPiAgentForTests(boundedPiAgentInput(0));
      assert.equal(result.completed, false);
      assert.equal(result.firstFailureCode, "MODEL_TURN_BUDGET_EXHAUSTED");
      assert.equal(providerCalls(), 0);
      assert.equal(result.providerRequests, 0);
      assert.equal(result.modelTurns, 0);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });
  await t.test("one started generation increments once", async () => {
    const providerCalls = installBoundedPiFauxRuntime(["submit_report"]);
    try {
      const result = await runBoundedPiAgentForTests(boundedPiAgentInput(1));
      assert.equal(result.completed, true);
      assert.equal(providerCalls(), 1);
      assert.equal(result.providerRequests, 1);
      assert.equal(result.modelTurns, 1);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });
  await t.test("two started generations count as two", async () => {
    const providerCalls = installBoundedPiFauxRuntime(["observe", "submit_report"]);
    try {
      const result = await runBoundedPiAgentForTests(boundedPiAgentInput(2));
      assert.equal(result.completed, true);
      assert.equal(providerCalls(), 2);
      assert.equal(result.providerRequests, 2);
      assert.equal(result.modelTurns, 2);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });
  await t.test("rejection after one real generation has no phantom second turn", async () => {
    const providerCalls = installBoundedPiFauxRuntime(["observe"]);
    try {
      const result = await runBoundedPiAgentForTests(boundedPiAgentInput(1));
      assert.equal(result.completed, false);
      assert.equal(result.firstFailureCode, "MODEL_TURN_BUDGET_EXHAUSTED");
      assert.equal(providerCalls(), 1);
      assert.equal(result.providerRequests, 1);
      assert.equal(result.modelTurns, 1);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });
  await t.test("actual admitted count is never clamped", async () => {
    const providerCalls = installBoundedPiFauxRuntime(["observe", "observe", "submit_report"]);
    try {
      const result = await runBoundedPiAgentForTests(boundedPiAgentInput(3));
      assert.equal(result.completed, true);
      assert.equal(providerCalls(), 3);
      assert.equal(result.providerRequests, 3);
      assert.equal(result.modelTurns, 3);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });
});

test("observed soft model-turn exhaustion blocks later productive work and terminal PASS", async () => {
  const root = await fixture();
  let calls = 0;
  let admittedTurns: number | undefined;
  const runtime: BoundedWorkerRuntime = {
    async execute({ tools, profile, maxModelTurns }) {
      calls += 1; admittedTurns = maxModelTurns;
      if (profile === "MUTATION_EXECUTOR") await tools.writePath({ path: "out.txt", operation: "CREATE", replacementBytes: Buffer.from("out\n"), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      return { completed: true, cleanupCertain: true, modelTurns: maxModelTurns };
    },
  };
  try {
    const result = await run(root, goal("DIRECT_LUNA_HIGH"), runtime);
    assert.equal(admittedTurns, 32, "the adapter receives the M5-selected remaining model-turn envelope");
    assert.equal(calls, 1);
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /BLOCKED_BUDGET_EXHAUSTED/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("M3 worktree lock permits only one active bounded writer", async () => {
  const root = await fixture();
  let start!: () => void;
  let release!: () => void;
  const started = new Promise<void>((resolve) => { start = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const holdingRuntime: BoundedWorkerRuntime = {
    async execute({ tools, profile }) {
      if (profile === "MUTATION_EXECUTOR") { start(); await gate; await tools.writePath({ path: "out.txt", operation: "CREATE", replacementBytes: Buffer.from("one\n"), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null }); }
      return { completed: true, cleanupCertain: true };
    },
  };
  try {
    const first = run(root, goal("DIRECT_LUNA_HIGH"), holdingRuntime);
    await started;
    const second = await run(root, goal("DIRECT_LUNA_HIGH"), writer(["out.txt"]));
    assert.equal(second.outcome, "BLOCKED");
    release();
    const completed = await first;
    assert.equal(completed.outcome, "PASS", completed.reason);
  } finally { release?.(); await rm(root, { recursive: true, force: true }); }
});

test("bounded execution resolver admits only the exact M3/M4/M5/Task/Graph/Plan and active-leaf join", () => {
  const digest = (character: string) => `sha256:${character.repeat(64)}`;
  const baseline = { content_sha256: digest("a"), baseline_mode: "CLEAN_REQUIRED" };
  const policy = { content_sha256: digest("b"), baseline_approval_sha256: baseline.content_sha256, run_id: "run", repository_identity_content_sha256: digest("4"), worktree_key: "worktree", scope_sha256: digest("5"), requested_mode: "ROUTED_DAG", task_graph_sha256: digest("6"), plan_approval_sha256: digest("7"), contract_sha256: digest("8") };
  const reservationState = { content_sha256: digest("c"), phase: "LEAF_FAST_PREFLIGHT", active_task_id: "task-a" };
  const reservation = { content_sha256: digest("d"), current_state_content_sha256: reservationState.content_sha256, policy_content_sha256: policy.content_sha256, outcome: "AUTHORIZE", operation_id: "operation", reservation: { reservation_decision_key: digest("e"), reserved_state_content_sha256: reservationState.content_sha256, logical_role: "LUNA_EXECUTOR" } };
  const token = { content_sha256: digest("f"), baseline_runtime_content_sha256: baseline.content_sha256, run_id: policy.run_id, repository_identity_content_sha256: policy.repository_identity_content_sha256, worktree_key: policy.worktree_key, task_scope_identity: policy.scope_sha256 };
  const task = { content_sha256: digest("0"), task_id: "task-a", task_sha256: digest("1") };
  const alternateTask = { content_sha256: digest("2"), task_id: "task-b", task_sha256: digest("3") };
  const graph = { content_sha256: digest("4"), task_graph_sha256: policy.task_graph_sha256, tasks: [{ task_id: task.task_id, task_sha256: task.task_sha256 }, { task_id: alternateTask.task_id, task_sha256: alternateTask.task_sha256 }], edges: [] };
  const plan = { content_sha256: digest("5"), plan_approval_sha256: policy.plan_approval_sha256, bindings: { contract_sha256: policy.contract_sha256, baseline_approval_sha256: policy.baseline_approval_sha256, dag: { task_graph_sha256: graph.task_graph_sha256, edges: graph.edges, ordered_task_packet_identities: [task.task_sha256, alternateTask.task_sha256] } } };
  const invocation = { content_sha256: digest("6"), operation_id: reservation.operation_id, m5_reservation_decision_content_sha256: reservation.content_sha256, m5_reservation_decision_key: reservation.reservation.reservation_decision_key, input_m3_state_token_content_sha256: token.content_sha256, task_content_sha256: task.content_sha256, task_graph_sha256: graph.content_sha256, plan_approval_sha256: plan.content_sha256 };
  const result = { content_sha256: digest("7"), invocation_content_sha256: invocation.content_sha256, outcome: "COMPLETED", cleanup_certain: true, actual_usage: { worker_invocations: 1, m4_tool_calls: 0 }, m3_evidence_content_sha256: [], m4_evidence_content_sha256: [] };
  const classifications = [
    ["M3_BASELINE", baseline.content_sha256], ["M5_CONTROL_POLICY", policy.content_sha256], ["M5_CONTROL_DECISION", reservation.content_sha256], ["M3_REPOSITORY_STATE_TOKEN", token.content_sha256], ["BOUNDED_WORKER_INVOCATION", invocation.content_sha256], ["BOUNDED_WORKER_RESULT", result.content_sha256],
  ].map(([kind, contentSha256]) => ({ object: { kind, contentSha256, relativePath: `${kind}.json` }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" }));
  const resolve = (overrides: Record<string, unknown> = {}) => resolveAuthoritativeBoundedExecution({ invocation, result, reservation, reservationState, policy, baseline, approval: null, stateToken: token, task, taskGraph: graph, plan, classifications, ...overrides } as any);
  assert.equal(resolve().accepted, true, "the exact active routed leaf is accepted");
  const managedButUnresolved = resolve({ classifications: classifications.filter((entry) => entry.object.kind !== "M5_CONTROL_DECISION") });
  assert.equal(managedButUnresolved.accepted, false, "managed bounded records alone cannot resolve into M5 authority");
  assert.equal(managedButUnresolved.acceptedWorkerInvocations, 0);
  const alternateInvocation = { ...invocation, content_sha256: digest("8"), task_content_sha256: alternateTask.content_sha256 };
  const alternateResult = { ...result, content_sha256: digest("9"), invocation_content_sha256: alternateInvocation.content_sha256 };
  const alternate = resolve({
    invocation: alternateInvocation,
    result: alternateResult,
    task: alternateTask,
    classifications: [...classifications,
      { object: { kind: "BOUNDED_WORKER_INVOCATION", contentSha256: alternateInvocation.content_sha256, relativePath: "alternate-invocation.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
      { object: { kind: "BOUNDED_WORKER_RESULT", contentSha256: alternateResult.content_sha256, relativePath: "alternate-result.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
    ],
  });
  assert.equal(alternate.accepted, false, "a valid sibling leaf cannot use another leaf reservation");
  assert.equal(alternate.reason, "ROUTED_ACTIVE_TASK_BINDING_MISMATCH");
  assert.equal(alternate.acceptedWorkerInvocations, 0);
  assert.equal(alternate.acceptedM4ToolCalls, 0);
  const missingTaskInvocation = { ...invocation, content_sha256: digest("a"), task_content_sha256: null };
  const missingTaskResult = { ...result, content_sha256: digest("b"), invocation_content_sha256: missingTaskInvocation.content_sha256 };
  const missingTask = resolve({ invocation: missingTaskInvocation, result: missingTaskResult, task: null, classifications: [...classifications,
    { object: { kind: "BOUNDED_WORKER_INVOCATION", contentSha256: missingTaskInvocation.content_sha256, relativePath: "missing-task-invocation.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
    { object: { kind: "BOUNDED_WORKER_RESULT", contentSha256: missingTaskResult.content_sha256, relativePath: "missing-task-result.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
  ] });
  assert.equal(missingTask.accepted, false, "a routed executor cannot omit its active leaf task");
  assert.equal(missingTask.reason, "ROUTED_ACTIVE_TASK_BINDING_MISMATCH");
  assert.equal(missingTask.acceptedWorkerInvocations, 0);
  const resolveNonLeaf = (logicalRole: "SOL_PLANNER" | "SOL_CLOSEOUT", phase: "ROUTE_SELECTED" | "READY", marker: string) => {
    const nonLeafState = { content_sha256: digest(marker), phase, active_task_id: null };
    const nonLeafReservation = { ...reservation, content_sha256: digest(marker === "a" ? "b" : "c"), current_state_content_sha256: nonLeafState.content_sha256,
      reservation: { ...reservation.reservation, reservation_decision_key: digest(marker === "a" ? "d" : "e"), reserved_state_content_sha256: nonLeafState.content_sha256, logical_role: logicalRole } };
    const nonLeafInvocation = { ...invocation, content_sha256: digest(marker === "a" ? "e" : "f"), m5_reservation_decision_content_sha256: nonLeafReservation.content_sha256,
      m5_reservation_decision_key: nonLeafReservation.reservation.reservation_decision_key, task_content_sha256: null };
    const nonLeafResult = { ...result, content_sha256: digest(marker === "a" ? "f" : "a"), invocation_content_sha256: nonLeafInvocation.content_sha256 };
    return resolve({ invocation: nonLeafInvocation, result: nonLeafResult, reservation: nonLeafReservation, reservationState: nonLeafState, task: null, classifications: [...classifications,
      { object: { kind: "M5_CONTROL_DECISION", contentSha256: nonLeafReservation.content_sha256, relativePath: `${logicalRole}-reservation.json` }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
      { object: { kind: "BOUNDED_WORKER_INVOCATION", contentSha256: nonLeafInvocation.content_sha256, relativePath: `${logicalRole}-invocation.json` }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
      { object: { kind: "BOUNDED_WORKER_RESULT", contentSha256: nonLeafResult.content_sha256, relativePath: `${logicalRole}-result.json` }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
    ] });
  };
  assert.equal(resolveNonLeaf("SOL_PLANNER", "ROUTE_SELECTED", "a").accepted, true, "planner remains a non-leaf routed execution");
  assert.equal(resolveNonLeaf("SOL_CLOSEOUT", "READY", "b").accepted, true, "closeout remains a non-leaf routed execution");
  const progressedState = { content_sha256: digest("a"), phase: "LEAF_FAST_PREFLIGHT", active_task_id: alternateTask.task_id };
  const progressedReservation = { ...reservation, content_sha256: digest("b"), current_state_content_sha256: progressedState.content_sha256,
    reservation: { ...reservation.reservation, reservation_decision_key: digest("c"), reserved_state_content_sha256: progressedState.content_sha256 } };
  const staleInvocation = { ...invocation, content_sha256: digest("d"), m5_reservation_decision_content_sha256: progressedReservation.content_sha256,
    m5_reservation_decision_key: progressedReservation.reservation.reservation_decision_key };
  const staleResult = { ...result, content_sha256: digest("e"), invocation_content_sha256: staleInvocation.content_sha256 };
  const stale = resolve({ invocation: staleInvocation, result: staleResult, reservation: progressedReservation, reservationState: progressedState, classifications: [...classifications,
    { object: { kind: "M5_CONTROL_DECISION", contentSha256: progressedReservation.content_sha256, relativePath: "progressed-reservation.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
    { object: { kind: "BOUNDED_WORKER_INVOCATION", contentSha256: staleInvocation.content_sha256, relativePath: "stale-invocation.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
    { object: { kind: "BOUNDED_WORKER_RESULT", contentSha256: staleResult.content_sha256, relativePath: "stale-result.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD", detail: "test" },
  ] });
  assert.equal(stale.accepted, false, "a prior leaf cannot be reused after the active leaf progresses");
  assert.equal(stale.acceptedWorkerInvocations, 0);
  assert.equal(stale.acceptedM4ToolCalls, 0);
  for (const [label, overrides] of [ 
    ["reservation", { invocation: { ...invocation, m5_reservation_decision_key: digest("a") } }],
    ["reservation state", { reservationState: { ...reservationState, content_sha256: digest("b") } }],
    ["token", { invocation: { ...invocation, input_m3_state_token_content_sha256: digest("c") } }],
    ["task", { invocation: { ...invocation, task_content_sha256: digest("d") } }],
    ["graph", { invocation: { ...invocation, task_graph_sha256: digest("e") } }],
    ["plan", { invocation: { ...invocation, plan_approval_sha256: digest("f") } }],
    ["M4 evidence", { result: { ...result, m4_evidence_content_sha256: [digest("0")] } }],
    ["worker outcome", { result: { ...result, outcome: "BLOCKED", cleanup_certain: true } }],
  ] as const) {
    const rejected = resolve(overrides);
    assert.equal(rejected.accepted, false, label);
    assert.equal(rejected.acceptedWorkerInvocations, 0, label);
    assert.equal(rejected.acceptedM4ToolCalls, 0, label);
  }
});

test("managed-only bounded records cannot bypass resolver-exclusive live or persisted M5 sources", async () => {
  const state = await createM5R3Fixture();
  try {
    const raw = unresolvedBoundedDocuments(state.runId, state.policy.content_sha256, state.committed.workflowState.content_sha256);
    await publishBoundedWorkerRecord({ stateRoot: state.stateRoot, runId: state.runId, kind: "BOUNDED_WORKER_INVOCATION", document: raw.invocation as any });
    await publishBoundedWorkerRecord({ stateRoot: state.stateRoot, runId: state.runId, kind: "BOUNDED_WORKER_RESULT", document: raw.result as any });
    const kernel = createControlDecisionKernel({ stateRoot: state.stateRoot, runId: state.runId, policy: state.policy, reducerPolicy: state.reducer, runAuthority: state.runAuthority });
    const request = {
      intent: "BLOCK" as const, expectedRevision: state.committed.statePointer.revision,
      expectedStatePointerContentSha256: state.committed.statePointer.content_sha256,
      expectedWorkflowStateContentSha256: state.committed.workflowState.content_sha256,
      transitionId: "pre-m8-unresolved-bounded", processMetadata: r3ProcessMetadata, blockReason: "BLOCKED_TEST",
    };
    await assert.rejects(kernel.evaluateControlDecision({ ...request, usageEvidence: [raw.usage as any] } as any),
      (error: unknown) => error instanceof ControlDecisionError && error.code === "USAGE_EVIDENCE_INVALID");
    const callerSupplied = createControlDecisionKernel({ stateRoot: state.stateRoot, runId: state.runId, policy: state.policy, reducerPolicy: state.reducer,
      runAuthority: state.runAuthority, authoritativeSources: { boundedWorkerResults: [raw.result as any] } });
    await assert.rejects(callerSupplied.evaluateControlDecision(request as any),
      (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_AUTHORITY_INCOMPLETE");
    const [records, inspection] = await Promise.all([
      readM5ManagedRecords({ stateRoot: state.stateRoot, runId: state.runId }),
      inspectRunStorage({ stateRoot: state.stateRoot, runId: state.runId }),
    ]);
    assert.equal(records.usage.length, 0);
    assert.equal(records.decisions.length, 0);
    assert.equal(records.boundedWorkerResults.length, 1);
    assert.equal(inspection.revision, state.committed.statePointer.revision);
    assert.equal(inspection.workflowState?.content_sha256, state.committed.workflowState.content_sha256);
    assert.notEqual(inspection.workflowState?.phase, "PASS");
  } finally { await removeM5R3Fixture(state); }
});

test("planner identity expansion and rejected resolver bindings fail closed with zero accepted usage", async () => {
  const root = await fixture();
  try {
    const routed = goal("ROUTED_DAG", ["a.txt", "b.txt"]);
    const result = await run(root, routed, writer(["a.txt", "b.txt"], { plannerIdentity: false }));
    assert.equal(result.outcome, "BLOCKED");
    assert.match(result.reason, /PLAN_EXPANSION_OR_IDENTITY_MISMATCH/);
  } finally { await rm(root, { recursive: true, force: true }); }

  const invocation = { content_sha256: "sha256:invocation", operation_id: "op", m5_reservation_decision_content_sha256: "sha256:decision", m5_reservation_decision_key: "sha256:key", input_m3_state_token_content_sha256: "sha256:token", task_content_sha256: "sha256:wrong-task", task_graph_sha256: null, plan_approval_sha256: null } as any;
  const result = { content_sha256: "sha256:result", invocation_content_sha256: "sha256:invocation", outcome: "COMPLETED", cleanup_certain: true, actual_usage: { worker_invocations: 1, m4_tool_calls: 1 }, m3_evidence_content_sha256: [], m4_evidence_content_sha256: [] } as any;
  const reservation = { content_sha256: "sha256:decision", outcome: "AUTHORIZE", operation_id: "op", reservation: { reservation_decision_key: "sha256:key" } } as any;
  const classifications = [
    ["BOUNDED_WORKER_INVOCATION", "sha256:invocation"], ["BOUNDED_WORKER_RESULT", "sha256:result"], ["M5_CONTROL_DECISION", "sha256:decision"], ["M3_REPOSITORY_STATE_TOKEN", "sha256:token"],
  ].map(([kind, contentSha256]) => ({ object: { kind, contentSha256, relativePath: `${kind}.json` }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" }));
  const resolved = resolveAuthoritativeBoundedExecution({ invocation, result, reservation, stateToken: { content_sha256: "sha256:token" }, task: { content_sha256: "sha256:task" }, taskGraph: null, plan: null, classifications } as any);
  assert.equal(resolved.accepted, false);
  assert.equal(resolved.acceptedWorkerInvocations, 0);
  assert.equal(resolved.acceptedM4ToolCalls, 0);
});
