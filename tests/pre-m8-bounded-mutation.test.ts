import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createControlDecisionKernel } from "../src/control/index.js";
import { evaluateAuthority } from "../src/control/evaluate.js";
import { ControlDecisionError } from "../src/control/errors.js";
import type { M5FailureInput } from "../src/control/types.js";
import { sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
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
import { configureM6FauxRuntimeForTests, M6WorkerError, runBoundedPiAgent, runBoundedPiAgentForTests } from "../src/pi-adapter/worker.js";
import { assertDocumentValid, identifyContractDocument } from "../src/schemas/index.js";
import { assertM4CanonicalPath } from "../src/secure-fs/path.js";
import { createM5R3Fixture, directFastPreflightFixture, removeM5R3Fixture, r3ProcessMetadata } from "./m5-r3-fixtures.js";

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

interface BoundedPiFauxCall {
  readonly name: string;
  readonly args: JsonRecord;
}

function installBoundedPiFauxRuntimeCalls(calls: readonly BoundedPiFauxCall[]): () => number {
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
    method(faux, "setResponses")(calls.map((call) => assistant(toolCall(call.name, call.args), { stopReason: "toolUse" })));
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

function installBoundedPiFauxRuntime(toolNames: readonly string[]): () => number {
  return installBoundedPiFauxRuntimeCalls(toolNames.map((name) => ({ name, args: {} })));
}

interface BoundedPiFauxHooks {
  readonly onPreparation?: () => void;
  readonly onProviderStart?: (input: { readonly ai: JsonRecord; readonly models: JsonRecord; readonly calls: number; readonly streamModel: unknown; readonly context: unknown; readonly options: unknown }) => unknown | undefined;
}

function installControllableBoundedPiFauxRuntime(toolNames: readonly string[], hooks: BoundedPiFauxHooks = {}): () => number {
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
    hooks.onPreparation?.();
    return {
      models,
      model,
      streamFn: (streamModel: unknown, context: unknown, options?: unknown): unknown => {
        providerCalls += 1;
        return hooks.onProviderStart?.({ ai, models, calls: providerCalls, streamModel, context, options }) ?? method(models, "streamSimple")(streamModel, context, options);
      },
      clearProviderState: (): void => { method(faux, "setResponses")([]); },
      pendingResponseCount: (): unknown => method(faux, "getPendingResponseCount")(),
    };
  });
  return () => providerCalls;
}

function uncooperativeToolStream(ai: JsonRecord, toolName: string, delivered?: () => void): unknown {
  const stream = record(method(ai, "createAssistantMessageEventStream")(), "uncooperative faux stream");
  const message = method(ai, "fauxAssistantMessage")(method(ai, "fauxToolCall")(toolName, {}), { stopReason: "toolUse" });
  queueMicrotask(() => {
    delivered?.();
    method(stream, "push")({ type: "done", reason: "toolUse", message });
    method(stream, "end")(message);
  });
  return stream;
}

function uncooperativeFailureStream(ai: JsonRecord, delivered?: () => void): unknown {
  const stream = record(method(ai, "createAssistantMessageEventStream")(), "uncooperative faux stream");
  const message = method(ai, "fauxAssistantMessage")("", { stopReason: "error", errorMessage: "synthetic provider failure after cancellation" });
  queueMicrotask(() => {
    delivered?.();
    method(stream, "push")({ type: "error", reason: "error", error: message });
    method(stream, "end")(message);
  });
  return stream;
}

function boundedPiAgentInput(maxModelTurns: number): Parameters<typeof runBoundedPiAgent>[0] {
  return {
    providerId: "bounded-faux", modelId: "bounded-faux-model", effort: "high", systemPrompt: "bounded", userPrompt: "bounded",
    tools: [
      { name: "observe", label: "observe", description: "observe", parameters: { type: "object", additionalProperties: false }, async execute() { return { content: [], details: {} }; } },
      { name: "submit_report", label: "submit", description: "submit", parameters: { type: "object", additionalProperties: false }, async execute() { return { content: [], details: {} }; } },
    ],
    maxModelTurns, deadlineMs: 5_000,
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

const s01MechanicalObjective = "Mutate only src/service-a.conf and src/service-b.conf.\nIn each file, replace exactly:\n\nlog_level=info\\n\n\nwith:\n\nlog_level=warning\\n";
function s01SingleOwnerGoal(): BoundedMutationGoal {
  const task = {
    task_id: "sol-m8-s01",
    objective: s01MechanicalObjective,
    editable_paths: ["src/service-a.conf", "src/service-b.conf"],
    required_outputs: ["src/service-a.conf", "src/service-b.conf"],
    dependencies: [],
  } as const;
  return {
    objective: s01MechanicalObjective,
    stop_condition: "Stop at deterministic acceptance.",
    execution_mode: "SINGLE_OWNER_SOL",
    scope: { readable_paths: ["src/service-a.conf", "src/service-b.conf", "verify", "verify/check.mjs"], editable_paths: task.editable_paths, frozen_paths: ["verify"] },
    required_outputs: task.required_outputs,
    tasks: [task],
  };
}
async function s01Fixture(): Promise<string> {
  const root = await fixture();
  await mkdir(join(root, "src"));
  await writeFile(join(root, "src", "service-a.conf"), "log_level=info\n");
  await writeFile(join(root, "src", "service-b.conf"), "log_level=info\n");
  await writeFile(join(root, "verify", "check.mjs"), "process.exit(0);\n");
  await chmod(join(root, "src", "service-a.conf"), 0o644);
  await chmod(join(root, "src", "service-b.conf"), 0o644);
  await chmod(join(root, "verify", "check.mjs"), 0o644);
  await execFileAsync("git", ["add", "src/service-a.conf", "src/service-b.conf", "verify/check.mjs"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "add S01 files"], { cwd: root });
  return root;
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

interface PiMutationRuntimeCounters {
  readToolExecutions: number;
  patchToolExecutions: number;
  providerReadResults?: unknown[];
}

/** Exercises the shared Pi loop with the real bounded-worker tool closures. */
function piMutationRuntime(counters: PiMutationRuntimeCounters): BoundedWorkerRuntime {
  return {
    async execute({ profile, systemPrompt, userPrompt, tools, maxModelTurns, deadlineMs, signal }) {
      if (profile !== "MUTATION_EXECUTOR") throw new Error("test Pi mutation runtime only supports mutation execution");
      return runBoundedPiAgentForTests({
        providerId: "bounded-faux", modelId: "bounded-faux-model", effort: "high", systemPrompt, userPrompt,
        tools: [
          {
            name: "read_scoped", label: "Scoped read", description: "Read one allowed repository path through M4.",
            parameters: { type: "object", additionalProperties: false, required: ["path"], properties: { path: { type: "string" } } },
            async execute(_id, params) {
              const value = record(params, "Pi read parameters"); const path = value["path"];
              if (typeof path !== "string" || path.length === 0) throw new Error("Pi read path is invalid");
              counters.readToolExecutions += 1;
              const result = await tools.readPath(path);
              const providerResult = { content: [{ type: "text", text: result.content ?? "" }], details: {} };
              counters.providerReadResults?.push(providerResult);
              return providerResult;
            },
          },
          {
            name: "apply_patch_scoped", label: "Scoped patch", description: "Apply exact bytes to one allowed path through M4.",
            parameters: { type: "object", additionalProperties: false, required: ["path", "operation", "replacement_base64", "expected_preimage_exists"], properties: {
              path: { type: "string" }, operation: { type: "string", enum: ["CREATE", "REPLACE", "DELETE"] }, replacement_base64: { type: ["string", "null"] }, expected_preimage_exists: { type: "boolean" }, expected_preimage_digest: { type: ["string", "null"] }, expected_preimage_size: { type: ["integer", "null"] }, expected_preimage_mode: { type: ["integer", "null"] },
            } },
            async execute(_id, params) {
              const value = record(params, "Pi patch parameters"); const path = value["path"]; const operation = value["operation"];
              const replacement = value["replacement_base64"]; const exists = value["expected_preimage_exists"];
              const digest = value["expected_preimage_digest"]; const size = value["expected_preimage_size"]; const mode = value["expected_preimage_mode"];
              const hasDigest = Object.hasOwn(value, "expected_preimage_digest"); const hasSize = Object.hasOwn(value, "expected_preimage_size"); const hasMode = Object.hasOwn(value, "expected_preimage_mode");
              if (typeof path !== "string" || path.length === 0 || (operation !== "CREATE" && operation !== "REPLACE" && operation !== "DELETE") ||
                  (replacement !== null && typeof replacement !== "string") || typeof exists !== "boolean" ||
                  (hasDigest && digest !== null && typeof digest !== "string") || (hasSize && size !== null && (typeof size !== "number" || !Number.isSafeInteger(size))) ||
                  (hasMode && mode !== null && (typeof mode !== "number" || !Number.isSafeInteger(mode)))) throw new Error("Pi patch parameters are invalid");
              counters.patchToolExecutions += 1;
              await tools.writePath({ path, operation, replacementBytes: replacement === null ? null : Buffer.from(replacement, "base64"), expectedPreimageExists: exists,
                ...(hasDigest ? { expectedPreimageDigest: digest as Sha256Digest | null } : {}),
                ...(hasSize ? { expectedPreimageSize: size as number | null } : {}),
                ...(hasMode ? { expectedPreimageMode: mode as number | null } : {}), });
              return { content: [], details: {} };
            },
          },
          {
            name: "submit_worker_report", label: "Bounded report", description: "Submit one bounded advisory report and end this worker.",
            parameters: { type: "object", additionalProperties: false, required: ["report"], properties: { report: { type: "string", maxLength: 8192 } } },
            async execute(_id, params) {
              const value = record(params, "Pi report parameters"); const report = value["report"];
              if (typeof report !== "string" || report.length === 0) throw new Error("Pi report is invalid");
              tools.submitReport(report);
              return { content: [], details: {}, terminate: true };
            },
          },
        ],
        maxModelTurns, deadlineMs,
        ...(signal === undefined ? {} : { signal }),
      });
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

test("provider-visible S01 contract exposes only frozen task scope and exact reads remain bounded", async () => {
  const root = await s01Fixture();
  const retained = await mkdtemp(join(tmpdir(), "pre-m8-s01-contract-"));
  let providerPrompt = "";
  try {
    const result = await run(root, s01SingleOwnerGoal(), {
      async execute({ profile, tools, userPrompt }) {
        try {
          assert.equal(profile, "MUTATION_EXECUTOR");
          providerPrompt = userPrompt;
          const paths = ["src/service-a.conf", "src/service-b.conf"] as const;
          for (const path of paths) {
            const before = await tools.readPath(path);
            await tools.writePath({ path, operation: "REPLACE", replacementBytes: Buffer.from("log_level=warning\n"), expectedPreimageExists: true,
              expectedPreimageDigest: before.metadata.digest, expectedPreimageSize: before.metadata.size, expectedPreimageMode: before.metadata.mode });
          }
          tools.submitReport("bounded S01 fixture report");
          return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        } catch (error: unknown) {
          return { completed: false, firstFailureCode: error !== null && typeof error === "object" && "code" in error ? String(error.code) : "TEST_RUNTIME_FAILURE", firstFailureStage: "TEST", firstFailureMessage: error instanceof Error ? error.message : String(error), cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        }
      },
    }, { retainedArtifactRoot: retained });
    assert.equal(result.outcome, "PASS", result.reason);
    assert.match(providerPrompt, new RegExp(`Objective \\(exact frozen text\\):\\n${s01MechanicalObjective.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`));
    assert.match(providerPrompt, /Readable paths \(exact frozen scope\):\n- src\/service-a\.conf\n- src\/service-b\.conf\n- verify\n- verify\/check\.mjs/);
    assert.match(providerPrompt, /Editable paths \(exact frozen scope\):\n- src\/service-a\.conf\n- src\/service-b\.conf/);
    assert.match(providerPrompt, /exact canonical repository-relative paths/);
    assert.match(providerPrompt, /Repository-root aliases and discovery are not authorized/);
    assert.match(providerPrompt, /Invalid forms include \., an empty path, \.\/\.\.\., root aliases, \.\. or traversal, and absolute paths/);
    assert.ok(result.evidenceRoot !== undefined);
    const records = await readM5ManagedRecords({ stateRoot: join(result.evidenceRoot, "state"), runId: "pre-m8-bounded" });
    assert.deepEqual(records.toolResults.map((entry) => entry.path).sort(), ["src/service-a.conf", "src/service-b.conf"], "both exact authorized regular files reached M4");
  } finally {
    await rm(retained, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test("read_scoped root aliases and out-of-scope nested paths fail before read gateway admission", async (t) => {
  const rejectedRead = async (requestedPath: string) => {
    const root = await s01Fixture();
    const retained = await mkdtemp(join(tmpdir(), "pre-m8-s01-read-refusal-"));
    try {
      const result = await run(root, s01SingleOwnerGoal(), {
        async execute({ tools }) {
          try {
            await tools.readPath(requestedPath);
            return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
          } catch (error: unknown) {
            return { completed: false, firstFailureCode: error !== null && typeof error === "object" && "code" in error ? String(error.code) : "TEST_RUNTIME_FAILURE", firstFailureStage: "TEST", cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
          }
        },
      }, { retainedArtifactRoot: retained });
      assert.equal(result.outcome, "BLOCKED");
      assert.ok(result.evidenceRoot !== undefined);
      const records = await readM5ManagedRecords({ stateRoot: join(result.evidenceRoot, "state"), runId: "pre-m8-bounded" });
      assert.equal(records.toolResults.length, 0, `${requestedPath} was rejected before gateway read admission`);
      assert.equal(records.mutationReceipts.length, 0);
    } finally {
      await rm(retained, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  };

  await t.test("repository root alias dot", () => rejectedRead("."));
  await t.test("canonical but task-external nested path", () => rejectedRead("src/service-a.conf/nested"));
  for (const path of ["", "./src/service-a.conf", "../src/service-a.conf", "/tmp/service-a.conf"] as const) {
    assert.throws(() => assertM4CanonicalPath(path), /INVALID_CANONICAL_PATH/, `${path || "empty path"} remains non-canonical`);
  }
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
  await t.test("forged runtime refusal provenance", async () => {
    const root = await fixture();
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH"), { async execute() {
        return { completed: false, firstFailureCode: "M4_TOOL_BUDGET_EXHAUSTED", firstFailureStage: "M4_TOOL_ADMISSION", cleanupCertain: true };
      } });
      assert.equal(result.outcome, "BLOCKED");
      assert.match(result.reason, /WORKER_AUTHORITY/);
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

test("M6WorkerError diagnostics reach the bounded-worker result safely and remain optional", async () => {
  const root = await fixture();
  const retained = await mkdtemp(join(tmpdir(), "pre-m8-retained-"));
  const rawMessage = `bounded\u0000diagnostic\r\nmessage\u007f ${"x".repeat(1_024)}`;
  const expectedPrefix = "bounded diagnostic message ";
  configureM6FauxRuntimeForTests({ providerId: "bounded-faux", modelId: "bounded-faux-model" }, () => {
    throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", rawMessage, "RUNTIME_GUARD");
  });
  try {
    const execution = await run(root, goal("DIRECT_LUNA_HIGH"), {
      async execute({ systemPrompt, userPrompt, maxModelTurns, deadlineMs, signal }) {
        return runBoundedPiAgentForTests({
          providerId: "bounded-faux", modelId: "bounded-faux-model", effort: "high", systemPrompt, userPrompt, tools: [], maxModelTurns, deadlineMs,
          ...(signal === undefined ? {} : { signal }),
        });
      },
    }, { retainedArtifactRoot: retained });
    assert.equal(execution.outcome, "BLOCKED");
    assert.ok(execution.evidenceRoot !== undefined);
    const records = await readM5ManagedRecords({ stateRoot: join(execution.evidenceRoot, "state"), runId: "pre-m8-bounded" });
    const result = records.boundedWorkerResults.find((entry) => entry.outcome === "BLOCKED");
    assert.notEqual(result, undefined);
    assert.equal(result!.first_failure_code, "RUNTIME_CAPABILITY_INVALID");
    assert.equal(result!.first_failure_stage, "RUNTIME_GUARD");
    assert.equal(result!.first_failure_message, `${expectedPrefix}${"x".repeat(512 - expectedPrefix.length)}`);
    assert.equal(result!.first_failure_message!.length, 512);
    assert.doesNotMatch(result!.first_failure_message!, /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/u);

    const withoutDiagnostic = identifyContractDocument("pi_gacw_bounded_worker_result_v0", {
      schema_id: "pi_gacw_bounded_worker_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      invocation_content_sha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      outcome: "COMPLETED", first_failure_code: null, first_failure_stage: null, m3_evidence_content_sha256: [], m4_evidence_content_sha256: [],
      actual_usage: { worker_invocations: 1, m4_tool_calls: 0, model_turns: null, provider_requests: null, input_tokens: null, output_tokens: null, cost_microusd: null, wall_time_ms: 0 },
      cleanup_certain: true, advisory_report: null, completed_at: "2026-01-01T00:00:00.000Z",
    });
    assertDocumentValid("pi_gacw_bounded_worker_result_v0", withoutDiagnostic);
    assert.equal(Object.hasOwn(withoutDiagnostic, "first_failure_message"), false);
    assert.equal(withoutDiagnostic.actual_usage.model_turns, null);
    assert.equal(withoutDiagnostic.actual_usage.provider_requests, null);
  } finally {
    configureM6FauxRuntimeForTests(undefined);
    await rm(retained, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test("Pi afterToolCall retains only a bounded safe tool failure diagnostic", async () => {
  const root = await fixture();
  const retained = await mkdtemp(join(tmpdir(), "pre-m8-retained-"));
  const replacementPayload = "UNSAFE_REPLACEMENT_BASE64_PAYLOAD";
  const errorText = `Pi-provided tool failure ${"x".repeat(1_024)}`;
  const patchArguments = {
    path: "src/safe-target.ts", operation: "REPLACE", replacement_base64: replacementPayload, expected_preimage_exists: true,
    expected_preimage_digest: `sha256:${"a".repeat(64)}`, expected_preimage_size: 17, expected_preimage_mode: 0o644,
  };
  const failingInput = (execute: () => Promise<never>, signal?: AbortSignal): Parameters<typeof runBoundedPiAgentForTests>[0] => ({
    providerId: "bounded-faux", modelId: "bounded-faux-model", effort: "high", systemPrompt: "bounded", userPrompt: "bounded", maxModelTurns: 1, deadlineMs: 5_000,
    tools: [{
      name: "apply_patch_scoped", label: "Scoped patch", description: "Scoped patch", parameters: {
        type: "object", additionalProperties: false, required: ["path", "operation", "replacement_base64", "expected_preimage_exists"], properties: {
          path: { type: "string" }, operation: { type: "string", enum: ["CREATE", "REPLACE", "DELETE"] }, replacement_base64: { type: ["string", "null"] }, expected_preimage_exists: { type: "boolean" }, expected_preimage_digest: { type: ["string", "null"] }, expected_preimage_size: { type: ["integer", "null"] }, expected_preimage_mode: { type: ["integer", "null"] },
        },
      },
      async execute() { return execute(); },
    }],
    ...(signal === undefined ? {} : { signal }),
  });
  try {
    const providerCalls = installBoundedPiFauxRuntimeCalls([{ name: "apply_patch_scoped", args: patchArguments }]);
    const execution = await run(root, goal("DIRECT_LUNA_HIGH"), {
      async execute({ signal }) { return runBoundedPiAgentForTests(failingInput(async () => { throw new Error(errorText); }, signal)); },
    }, { retainedArtifactRoot: retained });
    assert.equal(execution.outcome, "BLOCKED");
    assert.equal(providerCalls(), 1);
    assert.ok(execution.evidenceRoot !== undefined);
    const records = await readM5ManagedRecords({ stateRoot: join(execution.evidenceRoot, "state"), runId: "pre-m8-bounded" });
    const result = records.boundedWorkerResults.find((entry) => entry.outcome === "BLOCKED");
    assert.notEqual(result, undefined);
    assert.equal(result!.first_failure_code, "TOOL_EXECUTION_FAILED");
    assert.equal(result!.first_failure_stage, "TOOL_EXECUTION");
    assert.match(result!.first_failure_message!, /tool=apply_patch_scoped/u);
    assert.match(result!.first_failure_message!, /path=src\/safe-target\.ts/u);
    assert.match(result!.first_failure_message!, /operation=REPLACE/u);
    assert.match(result!.first_failure_message!, /Pi-provided tool failure/u);
    assert.doesNotMatch(result!.first_failure_message!, /replacement_base64|UNSAFE_REPLACEMENT_BASE64_PAYLOAD/u);
    assert.ok([...result!.first_failure_message!].length <= 480);

    const controller = new AbortController();
    const secondProviderCalls = installBoundedPiFauxRuntimeCalls([{ name: "apply_patch_scoped", args: patchArguments }]);
    const alreadyLatched = await runBoundedPiAgentForTests(failingInput(async () => {
      controller.abort();
      throw new Error("later tool failure must not replace the first latch");
    }, controller.signal));
    assert.equal(secondProviderCalls(), 1);
    assert.equal(alreadyLatched.firstFailureCode, "WORKER_ABORTED");
    assert.equal(alreadyLatched.firstFailureStage, "ABORT");
    assert.equal(alreadyLatched.firstFailureMessage, undefined);
  } finally {
    configureM6FauxRuntimeForTests(undefined);
    await rm(retained, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
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
    maxModelTurns: 0, deadlineMs: 1,
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

test("actual Pi ordering delegates M4 admission to the bounded worker", async (t) => {
  const patch = (path: string, text: string): BoundedPiFauxCall => ({
    name: "apply_patch_scoped",
    args: {
      path, operation: "CREATE", replacement_base64: Buffer.from(text, "utf8").toString("base64"), expected_preimage_exists: false,
      expected_preimage_digest: null, expected_preimage_size: null, expected_preimage_mode: null,
    },
  });

  await t.test("S09: a read does not consume the mutation cap, and the second mutation reaches bounded refusal", async () => {
    const root = await fixture();
    const retained = await mkdtemp(join(tmpdir(), "pre-m8-retained-"));
    const counters: PiMutationRuntimeCounters = { readToolExecutions: 0, patchToolExecutions: 0 };
    const providerCalls = installBoundedPiFauxRuntimeCalls([
      { name: "read_scoped", args: { path: "verify/input.txt" } },
      patch("first.txt", "first\n"),
      patch("second.txt", "second\n"),
    ]);
    try {
      const result = await run(root, goal("DIRECT_LUNA_HIGH", ["first.txt", "second.txt"]), piMutationRuntime(counters), {
        authority: { ...authority(), hard_mutation_tool_limit: 1 }, retainedArtifactRoot: retained,
      });
      assert.equal(result.outcome, "BLOCKED", result.reason);
      assert.equal(result.finalState?.phase, "BLOCKED");
      assert.match(result.reason, /WORKER_PRODUCTIVE_REFUSAL:M4_TOOL_BUDGET_EXHAUSTED/);
      assert.equal(counters.readToolExecutions, 1);
      assert.equal(counters.patchToolExecutions, 2, "the second tool request passed Pi beforeToolCall and reached bounded admission");
      assert.equal(providerCalls(), 3, "only genuinely started Pi generations contribute telemetry");
      assert.ok(result.evidenceRoot !== undefined);

      const stateRoot = join(result.evidenceRoot, "state");
      const [records, inspection] = await Promise.all([
        readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" }),
        inspectRunStorage({ stateRoot, runId: "pre-m8-bounded" }),
      ]);
      const refusal = records.admissionRefusals.filter((entry) => entry.refusal_code === "M4_TOOL_BUDGET_EXHAUSTED");
      const receipts = records.mutationReceipts.filter((entry) => entry.outcome === "APPLIED");
      assert.ok(records.routeMaps[0]!.routes.every((route) => route.tool_policy.maximum_tool_calls === 32), "the hard mutation cap does not shrink the total route tool envelope");
      assert.equal(records.budgets[0]!.limits.max_tool_calls, 32, "M5 total TOOL_CALL accounting remains distinct from the mutation cap");
      const worker = records.boundedWorkerResults.find((entry) => entry.outcome === "BLOCKED");
      assert.equal(refusal.length, 1);
      assert.equal(receipts.length, 1, "the denied second mutation never reached the M4 mutation gateway");
      assert.equal(receipts[0]!.path, "first.txt");
      assert.notEqual(worker, undefined);
      assert.equal(worker!.first_failure_code, "M4_TOOL_BUDGET_EXHAUSTED");
      assert.equal(worker!.first_failure_stage, "M4_TOOL_ADMISSION");
      assert.equal(worker!.actual_usage.m4_tool_calls, 2, "accepted read plus accepted mutation are the sole total M4 usage");
      assert.equal(worker!.actual_usage.model_turns, 3);
      assert.equal(worker!.actual_usage.provider_requests, 3);
      assert.ok(worker!.m4_evidence_content_sha256.includes(refusal[0]!.content_sha256));
      assert.ok(worker!.m3_evidence_content_sha256.includes(refusal[0]!.admission_state_token_content_sha256));
      assert.ok(inspection.managedRecordClassifications.some((entry) => entry.object.kind === "BOUNDED_WORKER_RESULT" && entry.object.contentSha256 === worker!.content_sha256 && entry.classification === "AUTHORITATIVE_MANAGED_RECORD"));
      const usage = records.usage.find((entry) => entry.source_record_content_sha256 === worker!.content_sha256);
      const terminal = records.decisions.find((entry) => entry.outcome === "BLOCK");
      assert.notEqual(usage, undefined);
      assert.equal(usage!.measurements.find((entry) => entry.dimension === "TOOL_CALL")?.amount, 2);
      assert.notEqual(terminal, undefined);
      assert.equal(terminal!.pass_authority, false);
      assert.equal(terminal!.failures.length, 1);
      assert.equal(terminal!.failures[0]!.source_record_content_sha256, worker!.content_sha256);
      assert.equal(terminal!.failures[0]!.source_error_code, "M4_TOOL_BUDGET_EXHAUSTED");
      const status = await execFileAsync("git", ["status", "--porcelain"], { cwd: root });
      assert.match(status.stdout, /first\.txt/);
      assert.doesNotMatch(status.stdout, /second\.txt/);
    } finally {
      configureM6FauxRuntimeForTests(undefined);
      await rm(retained, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  });

  await t.test("S10: a task-external mutation reaches bounded scope refusal before the globally permitting gateway", async () => {
    const root = await fixture();
    const retained = await mkdtemp(join(tmpdir(), "pre-m8-retained-"));
    const counters: PiMutationRuntimeCounters = { readToolExecutions: 0, patchToolExecutions: 0 };
    const providerCalls = installBoundedPiFauxRuntimeCalls([patch("outside.txt", "outside\n")]);
    const broadGoal = goal("DIRECT_LUNA_HIGH", ["in-scope.txt"], ["in-scope.txt", "outside.txt"]);
    const taskScopedGoal: BoundedMutationGoal = {
      ...broadGoal,
      tasks: [{ task_id: "task-owned-path", objective: "Own only the in-scope path.", editable_paths: ["in-scope.txt"], required_outputs: ["in-scope.txt"], dependencies: [] }],
    };
    try {
      const result = await run(root, taskScopedGoal, piMutationRuntime(counters), { retainedArtifactRoot: retained });
      assert.equal(result.outcome, "BLOCKED", result.reason);
      assert.equal(result.finalState?.phase, "BLOCKED");
      assert.match(result.reason, /WORKER_PRODUCTIVE_REFUSAL:OUT_OF_SCOPE_WRITE/);
      assert.equal(counters.readToolExecutions, 0);
      assert.equal(counters.patchToolExecutions, 1, "the request passed Pi sequencing and reached bounded scope admission");
      assert.equal(providerCalls(), 1);
      assert.ok(result.evidenceRoot !== undefined);

      const stateRoot = join(result.evidenceRoot, "state");
      const records = await readM5ManagedRecords({ stateRoot, runId: "pre-m8-bounded" });
      const refusal = records.admissionRefusals.filter((entry) => entry.refusal_code === "OUT_OF_SCOPE_WRITE");
      const worker = records.boundedWorkerResults.find((entry) => entry.outcome === "BLOCKED");
      assert.ok(records.toolPolicies[0]!.editable_paths.some((rule) => rule.path === "outside.txt"), "the target is globally M4-editable and must be stopped by task scope before gateway execution");
      assert.equal(refusal.length, 1);
      assert.equal(records.mutationReceipts.length, 0, "the globally permitting M4 gateway was never invoked");
      assert.notEqual(worker, undefined);
      assert.equal(worker!.first_failure_code, "OUT_OF_SCOPE_WRITE");
      assert.equal(worker!.first_failure_stage, "M4_TOOL_ADMISSION");
      assert.equal(worker!.actual_usage.m4_tool_calls, 0);
      assert.equal(worker!.actual_usage.model_turns, 1);
      assert.equal(worker!.actual_usage.provider_requests, 1);
      assert.ok(worker!.m4_evidence_content_sha256.includes(refusal[0]!.content_sha256));
      const invocation = records.boundedWorkerInvocations.find((entry) => entry.content_sha256 === worker!.invocation_content_sha256);
      assert.notEqual(invocation, undefined);
      assert.equal(refusal[0]!.admission_state_token_content_sha256, invocation!.input_m3_state_token_content_sha256);
      const usage = records.usage.find((entry) => entry.source_record_content_sha256 === worker!.content_sha256);
      const terminal = records.decisions.find((entry) => entry.outcome === "BLOCK");
      assert.notEqual(usage, undefined);
      assert.equal(usage!.measurements.find((entry) => entry.dimension === "TOOL_CALL")?.amount, 0);
      assert.notEqual(terminal, undefined);
      assert.equal(terminal!.pass_authority, false);
      assert.equal(terminal!.failures.length, 1);
      assert.equal(terminal!.failures[0]!.source_record_content_sha256, worker!.content_sha256);
      assert.equal(terminal!.failures[0]!.source_error_code, "OUT_OF_SCOPE_WRITE");
      const status = await execFileAsync("git", ["status", "--porcelain"], { cwd: root });
      assert.equal(status.stdout, "", "the repository remains unchanged when bounded scope refuses before gateway execution");
    } finally {
      configureM6FauxRuntimeForTests(undefined);
      await rm(retained, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("F-01 Option B fills only omitted CAS preimage facts without exposing them to the provider", async (t) => {
  const complete = { expected_preimage_digest: `sha256:${"0".repeat(64)}`, expected_preimage_size: 6, expected_preimage_mode: 0o644 };
  const patch = (path: string, operation: "CREATE" | "REPLACE" | "DELETE", fields: JsonRecord = {}): BoundedPiFauxCall => ({
    name: "apply_patch_scoped",
    args: {
      path, operation, replacement_base64: operation === "DELETE" ? null : Buffer.from(`changed:${path}\n`, "utf8").toString("base64"),
      expected_preimage_exists: operation !== "CREATE", ...fields,
    },
  });
  const report: BoundedPiFauxCall = { name: "submit_worker_report", args: { report: "bounded report" } };
  const targetGoal = (path: string) => goal("DIRECT_LUNA_HIGH", [path], [path]);
  const exercise = async (path: string, calls: readonly BoundedPiFauxCall[]) => {
    const root = await fixture();
    if (path === "verify/input.txt") await chmod(join(root, path), 0o644);
    const retained = await mkdtemp(join(tmpdir(), "pre-m8-f01-"));
    const counters: PiMutationRuntimeCounters = { readToolExecutions: 0, patchToolExecutions: 0 };
    const providerCalls = installBoundedPiFauxRuntimeCalls(calls);
    try {
      const result = await run(root, targetGoal(path), piMutationRuntime(counters), { retainedArtifactRoot: retained });
      assert.ok(result.evidenceRoot !== undefined);
      const records = await readM5ManagedRecords({ stateRoot: join(result.evidenceRoot, "state"), runId: "pre-m8-bounded" });
      return { result, records, counters, providerCalls: providerCalls() };
    } finally {
      configureM6FauxRuntimeForTests(undefined);
      await rm(retained, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  };

  await t.test("CREATE normalizes omitted preimage fields to null without a read", async () => {
    const outcome = await exercise("created.txt", [patch("created.txt", "CREATE"), report]);
    assert.equal(outcome.result.outcome, "PASS", outcome.result.reason);
    assert.equal(outcome.counters.patchToolExecutions, 1);
    assert.equal(outcome.counters.readToolExecutions, 0);
    assert.equal(outcome.records.toolResults.length, 0, "CREATE issued no preimage read");
    assert.equal(outcome.records.mutationReceipts[0]!.before.digest, null);
    assert.equal(outcome.records.mutationReceipts[0]!.before.size, null);
    assert.equal(outcome.records.mutationReceipts[0]!.before.mode, null);
  });

  await t.test("REPLACE and DELETE reacquire omitted preimages through one bounded read", async (nested) => {
    for (const operation of ["REPLACE", "DELETE"] as const) await nested.test(operation, async () => {
      const outcome = await exercise("verify/input.txt", [patch("verify/input.txt", operation), report]);
      assert.equal(outcome.result.outcome, "PASS", outcome.result.reason);
      assert.equal(outcome.counters.patchToolExecutions, 1);
      assert.equal(outcome.counters.readToolExecutions, 0, "the preimage read is internal, not provider-requested");
      assert.equal(outcome.records.toolResults.length, 1, "exactly one internal read produced M4 evidence");
      assert.equal(outcome.records.mutationReceipts[0]!.outcome, "APPLIED");
      assert.equal(outcome.records.mutationReceipts[0]!.before.size, 6);
      assert.equal(outcome.records.mutationReceipts[0]!.before.mode, 0o644);
    });
  });

  await t.test("partial omission fills only absent fields and preserves explicit CAS assertions", async () => {
    const outcome = await exercise("verify/input.txt", [patch("verify/input.txt", "REPLACE", { expected_preimage_size: complete.expected_preimage_size }), report]);
    assert.equal(outcome.result.outcome, "PASS", outcome.result.reason);
    assert.equal(outcome.records.toolResults.length, 1);
    assert.equal(outcome.records.mutationReceipts[0]!.before.size, complete.expected_preimage_size);
    assert.notEqual(outcome.records.mutationReceipts[0]!.before.digest, null);
    assert.notEqual(outcome.records.mutationReceipts[0]!.before.mode, null);
  });

  await t.test("stale explicit CAS and explicit null remain M4 rejections", async () => {
    const stale = await exercise("verify/input.txt", [patch("verify/input.txt", "REPLACE", { expected_preimage_digest: complete.expected_preimage_digest })]);
    assert.equal(stale.result.outcome, "BLOCKED");
    assert.equal(stale.records.toolResults.length, 1, "only absent fields were internally filled");
    assert.equal(stale.records.mutationReceipts[0]!.outcome, "PREIMAGE_MISMATCH", "the stale explicit digest reached M4 unchanged");

    const explicitNull = await exercise("verify/input.txt", [patch("verify/input.txt", "REPLACE", { expected_preimage_digest: null })]);
    assert.equal(explicitNull.result.outcome, "BLOCKED");
    assert.equal(explicitNull.records.toolResults.length, 1, "explicit null was not replaced, although absent siblings were filled");
    assert.equal(explicitNull.records.mutationReceipts.length, 0, "M4 rejected the explicit null before mutation admission");
  });

  await t.test("provider-visible reads remain text-only", async () => {
    const root = await fixture();
    const retained = await mkdtemp(join(tmpdir(), "pre-m8-f01-provider-"));
    const providerReadResults: unknown[] = [];
    const counters: PiMutationRuntimeCounters = { readToolExecutions: 0, patchToolExecutions: 0, providerReadResults };
    installBoundedPiFauxRuntimeCalls([{ name: "read_scoped", args: { path: "verify/input.txt" } }, report]);
    try {
      await run(root, targetGoal("out.txt"), piMutationRuntime(counters), { retainedArtifactRoot: retained });
      assert.equal(counters.readToolExecutions, 1);
      assert.deepEqual(providerReadResults, [{ content: [{ type: "text", text: "input\n" }], details: {} }]);
      assert.doesNotMatch(JSON.stringify(providerReadResults), /digest|size|mode/u);
    } finally {
      configureM6FauxRuntimeForTests(undefined);
      await rm(retained, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("R2 controller cancellation reaches every generic Pi generation and tool admission seam", async (t) => {
  await t.test("R2-T01: pre-aborted signal prevents runtime preparation and provider generation", async () => {
    const controller = new AbortController(); controller.abort();
    let preparations = 0;
    configureM6FauxRuntimeForTests({ providerId: "bounded-faux", modelId: "bounded-faux-model" }, () => { preparations += 1; throw new Error("runtime preparation must not begin"); });
    try {
      const result = await runBoundedPiAgentForTests({ ...boundedPiAgentInput(2), signal: controller.signal });
      assert.equal(preparations, 0);
      assert.equal(result.firstFailureCode, "WORKER_ABORTED");
      assert.equal(result.modelTurns, 0);
      assert.equal(result.providerRequests, 0);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });

  await t.test("R2-T02: cancellation after generation one rejects generation two without a phantom turn", async () => {
    const controller = new AbortController();
    const providerCalls = installControllableBoundedPiFauxRuntime(["observe", "submit_report"]);
    try {
      const input = boundedPiAgentInput(2);
      const result = await runBoundedPiAgentForTests({
        ...input,
        signal: controller.signal,
        tools: input.tools.map((tool) => tool.name !== "observe" ? tool : {
          ...tool,
          async execute() { controller.abort(); return { content: [], details: {} }; },
        }),
      });
      assert.equal(providerCalls(), 1);
      assert.equal(result.modelTurns, 1);
      assert.equal(result.providerRequests, 1);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });

  await t.test("R2-T03: cancellation during runtime preparation prevents provider generation after preparation returns", async () => {
    const controller = new AbortController();
    const providerCalls = installControllableBoundedPiFauxRuntime(["submit_report"], { onPreparation: () => controller.abort() });
    try {
      const result = await runBoundedPiAgentForTests({ ...boundedPiAgentInput(1), signal: controller.signal });
      assert.equal(providerCalls(), 0);
      assert.equal(result.firstFailureCode, "WORKER_ABORTED");
      assert.equal(result.modelTurns, 0);
      assert.equal(result.providerRequests, 0);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });

  await t.test("R2-T04: cancellation before productive tool admission rejects the tool", async () => {
    const controller = new AbortController();
    let toolExecutions = 0;
    const providerCalls = installControllableBoundedPiFauxRuntime([], {
      onProviderStart: ({ ai }) => { controller.abort(); return uncooperativeToolStream(ai, "observe"); },
    });
    try {
      const input = boundedPiAgentInput(2);
      const result = await runBoundedPiAgentForTests({
        ...input,
        signal: controller.signal,
        tools: input.tools.map((tool) => tool.name !== "observe" ? tool : {
          ...tool,
          async execute() { toolExecutions += 1; return { content: [], details: {} }; },
        }),
      });
      assert.equal(providerCalls(), 1);
      assert.equal(toolExecutions, 0);
      assert.equal(result.modelTurns, 1);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });

  await t.test("R2-T05: a non-cooperative admitted generation cannot admit a later generation", async () => {
    const controller = new AbortController();
    let deliveredAfterAbort = false;
    const providerCalls = installControllableBoundedPiFauxRuntime([], {
      onProviderStart: ({ ai }) => {
        controller.abort();
        return uncooperativeToolStream(ai, "observe", () => { deliveredAfterAbort = controller.signal.aborted; });
      },
    });
    try {
      const result = await runBoundedPiAgentForTests({ ...boundedPiAgentInput(2), signal: controller.signal });
      assert.equal(deliveredAfterAbort, true, "the faux generation deliberately ignored local abort after admission");
      assert.equal(providerCalls(), 1);
      assert.equal(result.modelTurns, 1);
      assert.equal(result.providerRequests, 1);
    } finally { configureM6FauxRuntimeForTests(undefined); }
  });

  await t.test("R2-T06: post-cancellation synthetic failure/turn-end activity cannot create a phantom generation", async () => {
    const controller = new AbortController();
    let deliveredAfterAbort = false;
    const providerCalls = installControllableBoundedPiFauxRuntime([], {
      onProviderStart: ({ ai }) => {
        controller.abort();
        return uncooperativeFailureStream(ai, () => { deliveredAfterAbort = controller.signal.aborted; });
      },
    });
    try {
      const result = await runBoundedPiAgentForTests({ ...boundedPiAgentInput(2), signal: controller.signal });
      assert.equal(deliveredAfterAbort, true);
      assert.equal(providerCalls(), 1);
      assert.equal(result.modelTurns, 1);
      assert.equal(result.providerRequests, 1);
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
  const task = { content_sha256: digest("0"), task_id: "task-a", task_sha256: digest("1"), scope: { editable_paths: ["task-a.txt"] } };
  const alternateTask = { content_sha256: digest("2"), task_id: "task-b", task_sha256: digest("3") };
  const graph = { content_sha256: digest("4"), task_graph_sha256: policy.task_graph_sha256, tasks: [{ task_id: task.task_id, task_sha256: task.task_sha256 }, { task_id: alternateTask.task_id, task_sha256: alternateTask.task_sha256 }], edges: [] };
  const plan = { content_sha256: digest("5"), plan_approval_sha256: policy.plan_approval_sha256, bindings: { contract_sha256: policy.contract_sha256, baseline_approval_sha256: policy.baseline_approval_sha256, dag: { task_graph_sha256: graph.task_graph_sha256, edges: graph.edges, ordered_task_packet_identities: [task.task_sha256, alternateTask.task_sha256] } } };
  const invocation = { content_sha256: digest("6"), run_id: "run", operation_id: reservation.operation_id, m5_reservation_decision_content_sha256: reservation.content_sha256, m5_reservation_decision_key: reservation.reservation.reservation_decision_key, input_m3_state_token_content_sha256: token.content_sha256, task_content_sha256: task.content_sha256, task_graph_sha256: graph.content_sha256, plan_approval_sha256: plan.content_sha256 };
  const result = { content_sha256: digest("7"), invocation_content_sha256: invocation.content_sha256, outcome: "COMPLETED", cleanup_certain: true, actual_usage: { worker_invocations: 1, m4_tool_calls: 0 }, m3_evidence_content_sha256: [], m4_evidence_content_sha256: [] };
  const classifications = [
    ["M3_BASELINE", baseline.content_sha256], ["M5_CONTROL_POLICY", policy.content_sha256], ["M5_CONTROL_DECISION", reservation.content_sha256], ["M3_REPOSITORY_STATE_TOKEN", token.content_sha256], ["BOUNDED_WORKER_INVOCATION", invocation.content_sha256], ["BOUNDED_WORKER_RESULT", result.content_sha256],
  ].map(([kind, contentSha256]) => ({ object: { kind, contentSha256, relativePath: `${kind}.json` }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" }));
  const resolve = (overrides: Record<string, unknown> = {}) => resolveAuthoritativeBoundedExecution({ invocation, result, reservation, reservationState, policy, baseline, approval: null, stateToken: token, task, taskGraph: graph, plan, admissionRefusals: new Map(), classifications, ...overrides } as any);
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

  const acceptedReceiptEvidence = digest("8");
  const successorToken = digest("9");
  const refusalRecord = (code: "M4_TOOL_BUDGET_EXHAUSTED" | "OUT_OF_SCOPE_WRITE", state: string, path: string) => {
    const attemptedOperation = { projection_id: "m4-admission-attempt-v0", tool_class: "APPLY_PATCH_SCOPED", operation: "REPLACE", target_path: path,
      expected_preimage: { exists: true, content_sha256: digest("a"), byte_length: 1, mode: 0o644 }, replacement: { content_sha256: digest("b"), byte_length: 2 },
      requested_final_mode: 0o644, ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE" };
    return identifyContractDocument("pi_gacw_m4_admission_refusal_v0", { schema_id: "pi_gacw_m4_admission_refusal_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      run_id: "run", bounded_worker_invocation_content_sha256: invocation.content_sha256, admission_state_token_content_sha256: state,
      attempted_operation: attemptedOperation, attempted_operation_content_sha256: sha256Canonical(attemptedOperation), disposition: "REFUSED", refusal_code: code });
  };
  const budgetRecord = refusalRecord("M4_TOOL_BUDGET_EXHAUSTED", successorToken, "task-a.txt");
  const refusalClassifications = (blocked: { readonly content_sha256: string }, record: { readonly content_sha256: string }, includeReceipt = true) => [
    ...classifications.filter((entry) => entry.object.kind !== "BOUNDED_WORKER_RESULT"),
    { object: { kind: "BOUNDED_WORKER_RESULT", contentSha256: blocked.content_sha256, relativePath: "terminal-refusal.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" },
    { object: { kind: "M4_ADMISSION_REFUSAL", contentSha256: record.content_sha256, relativePath: "m4-admission-refusal.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" },
    { object: { kind: "M3_REPOSITORY_STATE_TOKEN", contentSha256: successorToken, relativePath: "successor-token.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" },
    ...(includeReceipt ? [{ object: { kind: "M4_MUTATION_RECEIPT", contentSha256: acceptedReceiptEvidence, relativePath: "accepted-mutation.json" }, classification: "AUTHORITATIVE_MANAGED_RECORD" as const, detail: "test" }] : []),
  ];
  const budgetRefusal = { ...result, content_sha256: digest("c"), outcome: "BLOCKED" as const, first_failure_code: "M4_TOOL_BUDGET_EXHAUSTED", first_failure_stage: "M4_TOOL_ADMISSION",
    actual_usage: { worker_invocations: 1, m4_tool_calls: 1 }, m3_evidence_content_sha256: [successorToken], m4_evidence_content_sha256: [acceptedReceiptEvidence, budgetRecord.content_sha256] };
  const resolvedBudgetRefusal = resolve({ result: budgetRefusal, admissionRefusals: new Map([[budgetRecord.content_sha256, budgetRecord]]), classifications: refusalClassifications(budgetRefusal, budgetRecord) });
  assert.equal(resolvedBudgetRefusal.accepted, true, resolvedBudgetRefusal.reason ?? "a settled budget refusal resolves only with producer evidence");
  assert.equal(resolvedBudgetRefusal.acceptedWorkerInvocations, 1);
  assert.equal(resolvedBudgetRefusal.acceptedM4ToolCalls, 1, "the refusal contributes zero accepted M4 usage");

  const scopeRecord = refusalRecord("OUT_OF_SCOPE_WRITE", token.content_sha256, "frozen.txt");
  const scopeRefusal = { ...budgetRefusal, content_sha256: digest("d"), first_failure_code: "OUT_OF_SCOPE_WRITE", actual_usage: { worker_invocations: 1, m4_tool_calls: 0 }, m3_evidence_content_sha256: [], m4_evidence_content_sha256: [scopeRecord.content_sha256] };
  const resolvedScopeRefusal = resolve({ result: scopeRefusal, admissionRefusals: new Map([[scopeRecord.content_sha256, scopeRecord]]), classifications: refusalClassifications(scopeRefusal, scopeRecord, false) });
  assert.equal(resolvedScopeRefusal.accepted, true, "a settled scope refusal resolves only with producer evidence");
  assert.equal(resolvedScopeRefusal.acceptedM4ToolCalls, 0);

  const editedCode = refusalRecord("OUT_OF_SCOPE_WRITE", successorToken, "task-a.txt");
  const wrongStateRecord = refusalRecord("M4_TOOL_BUDGET_EXHAUSTED", digest("e"), "task-a.txt");
  const wrongStateResult = { ...budgetRefusal, m4_evidence_content_sha256: [acceptedReceiptEvidence, wrongStateRecord.content_sha256] };
  const refusalAttacks: readonly [string, Record<string, unknown>][] = [
    ["caller-authored BLOCKED without refusal record", { result: budgetRefusal, classifications: classifications }],
    ["wrong invocation", { result: budgetRefusal, admissionRefusals: new Map([[budgetRecord.content_sha256, { ...budgetRecord, bounded_worker_invocation_content_sha256: digest("e") }]]), classifications: refusalClassifications(budgetRefusal, budgetRecord) }],
    ["wrong reservation", { result: budgetRefusal, admissionRefusals: new Map([[budgetRecord.content_sha256, budgetRecord]]), classifications: refusalClassifications(budgetRefusal, budgetRecord), reservation: { ...reservation, content_sha256: digest("f") } }],
    ["edited refusal code", { result: budgetRefusal, admissionRefusals: new Map([[budgetRecord.content_sha256, editedCode]]), classifications: refusalClassifications(budgetRefusal, budgetRecord) }],
    ["edited refusal stage", { result: { ...budgetRefusal, first_failure_stage: "BOUNDED_WORKER" }, admissionRefusals: new Map([[budgetRecord.content_sha256, budgetRecord]]), classifications: refusalClassifications(budgetRefusal, budgetRecord) }],
    ["wrong current M3 state", { result: wrongStateResult, admissionRefusals: new Map([[wrongStateRecord.content_sha256, wrongStateRecord]]), classifications: refusalClassifications(wrongStateResult, wrongStateRecord) }],
    ["accepted evidence substituted for refusal", { result: { ...budgetRefusal, m4_evidence_content_sha256: [acceptedReceiptEvidence] }, admissionRefusals: new Map([[budgetRecord.content_sha256, budgetRecord]]), classifications: refusalClassifications(budgetRefusal, budgetRecord) }],
    ["refusal counted as accepted usage", { result: { ...scopeRefusal, actual_usage: { worker_invocations: 1, m4_tool_calls: 1 } }, admissionRefusals: new Map([[scopeRecord.content_sha256, scopeRecord]]), classifications: refusalClassifications(scopeRefusal, scopeRecord, false) }],
    ["cleanup uncertainty", { result: { ...budgetRefusal, cleanup_certain: false }, admissionRefusals: new Map([[budgetRecord.content_sha256, budgetRecord]]), classifications: refusalClassifications(budgetRefusal, budgetRecord) }],
  ];
  for (const [label, overrides] of refusalAttacks) {
    const rejected = resolve(overrides);
    assert.equal(rejected.accepted, false, label);
    assert.equal(rejected.acceptedWorkerInvocations, 0, label);
    assert.equal(rejected.acceptedM4ToolCalls, 0, label);
  }
});

test("caller-authored M5 terminal refusal claims cannot bypass persisted sole-resolver authority", async () => {
  const fixtureState = await createM5R3Fixture();
  try {
    const committed = await directFastPreflightFixture(fixtureState); const state = committed.workflowState;
    const operationId = "terminal-refusal-operation";
    const admission = evaluateAuthority({ policy: fixtureState.policy, state, reducerPolicy: fixtureState.reducer, persistedUsage: [], priorDecisions: [], request: {
      intent: "AUTHORIZE_WORK", expectedRevision: committed.statePointer.revision, expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest, operationId, availableLogicalRoles: ["LUNA_EXECUTOR"],
    } });
    assert.equal(admission.outcome, "AUTHORIZE"); assert.notEqual(admission.reservation, null);
    const result = identifyContractDocument("pi_gacw_bounded_worker_result_v0", {
      schema_id: "pi_gacw_bounded_worker_result_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      invocation_content_sha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111", outcome: "BLOCKED",
      first_failure_code: "M4_TOOL_BUDGET_EXHAUSTED", first_failure_stage: "M4_TOOL_ADMISSION", m3_evidence_content_sha256: [], m4_evidence_content_sha256: [],
      actual_usage: { worker_invocations: 1, m4_tool_calls: 0, model_turns: null, provider_requests: null, input_tokens: null, output_tokens: null, cost_microusd: null, wall_time_ms: 0 },
      cleanup_certain: true, advisory_report: null, completed_at: "2026-01-01T00:00:00.000Z",
    }) as any;
    const failure: M5FailureInput = {
      sourceLayer: "CONTROLLER", sourceErrorCode: result.first_failure_code, sourceRecordContentSha256: result.content_sha256,
      normalizedSignature: sha256Canonical({ protocol: "bounded-worker-terminal-refusal-v1", bounded_worker_result_content_sha256: result.content_sha256,
        first_failure_code: result.first_failure_code, first_failure_stage: result.first_failure_stage, operation_id: operationId,
        reservation_decision_content_sha256: admission.content_sha256 }),
      operationId, scopeIdentity: fixtureState.policy.scope_sha256 as Sha256Digest, repositoryIdentity: fixtureState.policy.repository_identity_content_sha256 as Sha256Digest, worktreeKey: fixtureState.policy.worktree_key as Sha256Digest,
    };
    const base = { policy: fixtureState.policy, state, reducerPolicy: fixtureState.reducer, persistedUsage: [], priorDecisions: [admission],
      authoritativeSources: { boundedWorkerResults: [result] }, request: { expectedRevision: committed.statePointer.revision, expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
        expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest, availableLogicalRoles: ["LUNA_EXECUTOR"], operationId } } as const;
    const rejects = (request: Record<string, unknown>): void => assert.throws(() => evaluateAuthority({ ...base, request: { ...base.request, ...request } as any }),
      (error: unknown) => error instanceof ControlDecisionError && error.code === "FAILURE_CLASSIFICATION_INVALID");
    rejects({ intent: "BLOCK", blockReason: "BLOCKED_TERMINAL_REFUSAL", failures: [failure] });
    rejects({ intent: "EVALUATE_TERMINAL", failures: [] });
    rejects({ intent: "AUTHORIZE_CONTINUATION", failures: [] });
    rejects({ intent: "BLOCK", blockReason: "BLOCKED_TERMINAL_REFUSAL", failures: [] });
    rejects({ intent: "BLOCK", blockReason: "BLOCKED_TERMINAL_REFUSAL", failures: [{ ...failure, sourceErrorCode: "OUT_OF_SCOPE_WRITE" }] });
    rejects({ intent: "BLOCK", blockReason: "BLOCKED_TERMINAL_REFUSAL", failures: [{ ...failure, normalizedSignature: "sha256:2222222222222222222222222222222222222222222222222222222222222222" }] });
  } finally { await removeM5R3Fixture(fixtureState); }
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
