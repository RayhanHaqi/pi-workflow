import { mkdir, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { createControlDecisionKernel } from "../src/control/index.js";
import { inspectRunStorage, readM6WorkerRecords } from "../src/persistence/store.js";
import { configurePersistenceTestHooks } from "../src/persistence/test-hooks.js";
import { acquireWorktreeLock, releaseWorktreeLock, runFullPreflight } from "../src/repository/index.js";
import { configureM6FauxRuntimeForTests, runDirectReadOnlyLunaWorker, runDirectReadOnlyLunaWorkerForTests, runM6ReportSubmissionProtocolForTests } from "../src/pi-adapter/worker.js";
import type { M6DirectReadOnlyWorkerInput } from "../src/pi-adapter/worker.js";
import { identifyContractDocument, type M3BaselineRuntimeDocument, type M3RepositoryIdentityDocument, type M3RepositoryStateTokenDocument, type M4CommandCatalogDocument, type M4ScopedToolPolicyDocument, type M5ControlDecisionDocument, type TaskDocument } from "../src/schemas/index.js";
import { createScopedToolGateway } from "../src/scoped-tools/index.js";
import { createM5R3Fixture, directFastPreflightFixture, m5Policy, removeM5R3Fixture, r3ProcessMetadata } from "./m5-r3-fixtures.js";
import { digest } from "./helpers.js";
import { canonicalize } from "../src/canonical-json/index.js";
import { type Sha256Digest } from "../src/identity/index.js";
import { m3ScopeIdentity } from "../src/identity/m3-scope.js";
import type { ScopedToolGateway } from "../src/scoped-tools/types.js";
import { fingerprintInput, requiredEnvironment } from "./repository-helpers.js";
import type { M5ControlPolicyDocument } from "../src/schemas/index.js";

const limits = { maximum_patch_bytes: 1_048_576, maximum_read_bytes: 1_048_576, maximum_hash_bytes: 67_108_864, maximum_search_input_bytes: 67_108_864, maximum_search_matches: 10_000, maximum_list_entries: 100_000, maximum_list_metadata_bytes: 67_108_864, maximum_command_stdout_bytes: 4_194_304, maximum_command_stderr_bytes: 4_194_304, maximum_command_duration_ms: 1_800_000 } as const;
const editable = ["tracked.txt"] as const;
const frozen = ["AGENTS.md", "AUTHORITY.md"] as const;
const taskScopeIdentity = m3ScopeIdentity(editable, frozen);

type Mode = "SUCCESS" | "TEXT_ONLY" | "UNKNOWN_TOOL" | "SECOND_READ" | "REPORT_BEFORE_READ" | "EXTRA_EVIDENCE" | "INVALID_STATUS" | "EMPTY_SUMMARY" | "OVERSIZED_SUMMARY" | "PROVIDER_FAILURE" | "ACTIVE_ABORT" | "CLEANUP_FAILURE";
let mode: Mode = "SUCCESS";
let reportSummary = "Bounded report.";
let observedReportParameters: Record<string, unknown> | undefined;
let activeAbortController: AbortController | undefined;

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is not an object`);
  return value as Record<string, unknown>;
}

function arrayValue(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} is not an array`);
  return value;
}

function methodValue(value: unknown, name: string, label: string): (...args: readonly unknown[]) => unknown {
  const object = objectValue(value, label);
  const method = object[name];
  if (typeof method !== "function") throw new Error(`${label}.${name} is not callable`);
  return (...args: readonly unknown[]) => Reflect.apply(method, object, args);
}

function reportArguments(): Record<string, unknown> {
  const summary = mode === "EMPTY_SUMMARY" ? "" : mode === "OVERSIZED_SUMMARY" ? "x".repeat(660) : reportSummary;
  const argumentsValue: Record<string, unknown> = { status: mode === "INVALID_STATUS" ? "BLOCKED" : "COMPLETED", summary };
  if (mode === "EXTRA_EVIDENCE") argumentsValue["evidence_content_sha256"] = [digest(999)];
  return argumentsValue;
}

function secondSuccess(aiModule: Record<string, unknown>, _contextValue: unknown): unknown {
  const assistant = methodValue(aiModule, "fauxAssistantMessage", "AI module");
  const toolCall = methodValue(aiModule, "fauxToolCall", "AI module");
  return assistant(toolCall("submit_worker_report", reportArguments()), { stopReason: "toolUse" });
}

function installFauxRuntime(nextMode: Mode, nextSummary = "Bounded report."): void {
  mode = nextMode;
  reportSummary = nextSummary;
  observedReportParameters = undefined;
  configureM6FauxRuntimeForTests({ providerId: "provider-primary", modelId: "luna-high" }, ({ aiModule, providerId, modelId }) => {
    if (providerId !== "provider-primary" || modelId !== "luna-high") return undefined;
    const faux = objectValue(methodValue(aiModule, "fauxProvider", "AI module")({ api: "m6-repair-faux-api", provider: providerId, models: [{ id: modelId, name: modelId, reasoning: true, input: ["text"] }], tokensPerSecond: 0 }), "faux provider");
    const models = objectValue(methodValue(aiModule, "createModels", "AI module")(), "models");
    methodValue(models, "setProvider", "models")(faux["provider"]);
    const model = methodValue(models, "getModel", "models")(providerId, modelId);
    const assistant = methodValue(aiModule, "fauxAssistantMessage", "AI module");
    const toolCall = methodValue(aiModule, "fauxToolCall", "AI module");
    const read = assistant(toolCall(mode === "UNKNOWN_TOOL" ? "unknown_tool" : "read_scoped", { read_id: "primary" }), { stopReason: "toolUse" });
    const report = assistant(toolCall("submit_worker_report", { status: "COMPLETED", summary: "Premature report." }), { stopReason: "toolUse" });
    const secondRead = assistant(toolCall("read_scoped", { read_id: "primary" }), { stopReason: "toolUse" });
    const text = assistant("text only", { stopReason: "stop" });
    const responses = mode === "TEXT_ONLY" ? [text] : mode === "REPORT_BEFORE_READ" ? [report] : mode === "SECOND_READ" ? [read, secondRead] : [read, (context: unknown) => secondSuccess(aiModule, context)];
    methodValue(faux, "setResponses", "faux provider") (responses);
    const streamSimple = methodValue(models, "streamSimple", "models");
    return {
      models,
      model,
      streamFn: (streamModel: unknown, context: unknown, options?: unknown): unknown => {
        if (context !== null && typeof context === "object" && !Array.isArray(context)) {
          const contextTools = (context as Record<string, unknown>)["tools"];
          if (Array.isArray(contextTools)) {
            const reportTool = contextTools.map((value) => objectValue(value, "model-visible tool")).find((value) => value["name"] === "submit_worker_report");
            const parameters = reportTool?.["parameters"];
            if (parameters !== undefined) observedReportParameters = objectValue(parameters, "submit_worker_report parameters");
          }
        }
        if (mode === "PROVIDER_FAILURE") throw new Error("provider stream failure");
        if (mode === "ACTIVE_ABORT") {
          activeAbortController?.abort();
          throw new Error("provider stream aborted");
        }
        return streamSimple(streamModel, context, options);
      },
      clearProviderState: (): void => {
        if (mode === "CLEANUP_FAILURE") throw new Error("cleanup failure");
        methodValue(faux, "setResponses", "faux provider")([]);
      },
      fauxCallCount: (): unknown => objectValue(faux["state"], "faux state")["callCount"],
      pendingResponseCount: (): unknown => methodValue(faux, "getPendingResponseCount", "faux provider")(),
    };
  });
}

interface Scenario {
  readonly fixture: Awaited<ReturnType<typeof createM5R3Fixture>>;
  readonly lock: Awaited<ReturnType<typeof acquireWorktreeLock>>;
  readonly input: M6DirectReadOnlyWorkerInput;
  readonly targetPath: string;
  readonly credentials: { value: number };
}

function buildInput(value: {
  fixture: Awaited<ReturnType<typeof createM5R3Fixture>>;
  lock: Awaited<ReturnType<typeof acquireWorktreeLock>>;
  repository: M3RepositoryIdentityDocument;
  baseline: M3BaselineRuntimeDocument;
  instruction: Awaited<ReturnType<typeof fingerprintInput>>;
  authority: Awaited<ReturnType<typeof fingerprintInput>>;
  gateway: ScopedToolGateway;
  m4Policy: M4ScopedToolPolicyDocument;
  m4Catalog: M4CommandCatalogDocument;
  task: TaskDocument;
  m3StateToken: M3RepositoryStateTokenDocument;
  policy: M5ControlPolicyDocument;
  decision: M5ControlDecisionDocument;
  credentials: { value: number };
}): M6DirectReadOnlyWorkerInput {
  const credentialStore = {
    read: async () => undefined,
    list: async () => [],
    modify: async () => undefined,
    delete: async () => undefined,
  };
  return {
    stateRoot: value.fixture.stateRoot, runId: value.fixture.runId, reducerPolicy: value.fixture.reducer, m5Policy: value.policy, m5Decision: value.decision,
    runAuthority: { ...value.fixture.runAuthority, task: value.task }, repository: value.repository, baseline: value.baseline, m3StateToken: value.m3StateToken, lock: value.lock,
    instructionFiles: [value.instruction], authorityFiles: [value.authority], gateway: value.gateway, m4ToolPolicy: value.m4Policy, m4CommandCatalog: value.m4Catalog,
    task: { task_id: value.task.task_id, task_sha256: value.task.task_sha256 }, approvedResources: [{ path: value.instruction.path, contentSha256: value.instruction.expectedSha256, dataClass: "PUBLIC_SOURCE" as const }, { path: value.authority.path, contentSha256: value.authority.expectedSha256, dataClass: "PUBLIC_SOURCE" as const }],
    systemPrompt: "Bounded repair worker.", userPrompt: "Read the primary target and submit the terminal report.", credentialStoreCallback: () => { value.credentials.value += 1; return credentialStore; },
  };
}

async function createScenario(): Promise<Scenario> {
  const fixture = await createM5R3Fixture();
  let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    const repository = fixture.runAuthority.repositoryIdentity;
    const baselinePath = join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines", `${fixture.m3StateToken.baseline_runtime_content_sha256.slice("sha256:".length)}.json`);
    const baseline = JSON.parse(await readFile(baselinePath, "utf8")) as M3BaselineRuntimeDocument;
    assert.equal(baseline.run_id, fixture.runId);
    const instruction = await fingerprintInput(join(fixture.verifierRoot, "repository", "AGENTS.md"));
    const authority = await fingerprintInput(join(fixture.verifierRoot, "repository", "AUTHORITY.md"));
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const refreshed = await runFullPreflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256, baseline, approval: null, instructionFiles: [instruction], authorityFiles: [authority], requiredEnvironment: await requiredEnvironment(repository.worktree_root), taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock });
    const m3StateToken = refreshed.acceptedState;
    const m4Policy = identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
      schema_id: "pi_gacw_scoped_tool_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: fixture.runId, policy_id: "m6-repair-policy", repository_identity_content_sha256: repository.content_sha256, worktree_key: repository.worktree_key, task_scope_identity: taskScopeIdentity,
      readable_paths: [{ path: "tracked.txt", kind: "EXACT" }], editable_paths: [{ path: "tracked.txt", kind: "EXACT" }], frozen_paths: frozen.map((path) => ({ path, kind: "EXACT" as const })), command_readable_paths: [{ path: "tracked.txt", kind: "EXACT" }], command_writable_paths: [],
      path_authorities: [
        { path: "tracked.txt", kind: "EXACT", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: true, delete: true, mode_change: true },
        { path: "AGENTS.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
        { path: "AUTHORITY.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
      ], evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M4_TOOL_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"], limits,
    }) as M4ScopedToolPolicyDocument;
    const m4Catalog = identifyContractDocument("pi_gacw_command_catalog_v0", { schema_id: "pi_gacw_command_catalog_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: fixture.runId, catalog_id: "m6-repair-catalog", repository_identity_content_sha256: repository.content_sha256, tool_policy_content_sha256: m4Policy.content_sha256, commands: [] }) as M4CommandCatalogDocument;
    const gateway = await createScopedToolGateway({ stateRoot: fixture.stateRoot, runId: fixture.runId, repository, baseline, acceptedState: m3StateToken, lock, instructionFiles: [instruction], authorityFiles: [authority], editablePaths: [...editable], frozenPaths: [...frozen], taskScopeIdentity, toolPolicy: m4Policy, commandCatalog: m4Catalog, temporaryRoot: join(fixture.verifierRoot, "controller-tmp") });
    const task = identifyContractDocument("pi_gacw_task_v0", { schema_id: "pi_gacw_task_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", task_projection_id: "task-packet-v1", task_sha256: digest(30), task_id: "task-only", topological_rank: 0, priority: 0, dependencies: [], objective: "Read the bounded target.", scope: { readable_paths: ["tracked.txt"], editable_paths: [...editable], frozen_paths: [...frozen] }, required_inputs: ["input"], required_outputs: ["report"], acceptance_criteria: [{ criterion_id: "m6-accept", description: "The report is durably published.", evidence_kind: "FILE", owner_acceptance: false }], owner_acceptance_criteria: [], verification_commands: [{ command_id: "verify", argv: ["true"], cwd: "/work", timeout_ms: 1000, network: "FORBIDDEN" }], assigned_role: "LUNA_EXECUTOR", write_owner: "writer" }) as TaskDocument;
    const baseM5 = m5Policy(fixture.reducer, fixture.initialState.content_sha256 as Sha256Digest, fixture.runAuthority);
    const { content_sha256: _ignored, ...m5Body } = structuredClone(baseM5) as Record<string, unknown>;
    const policy = identifyContractDocument("pi_gacw_m5_control_policy_v0", { ...m5Body, limits: (m5Body["limits"] as Array<Record<string, unknown>>).map((entry) => entry["dimension"] === "WALL_TIME_MS" ? { ...entry, hard_limit: 120000, soft_limit: 120000 } : entry), tool_policy_content_sha256: m4Policy.content_sha256, command_catalog_content_sha256: m4Catalog.content_sha256, obligations: [] }) as unknown as M5ControlPolicyDocument;
    const fast = await directFastPreflightFixture(fixture);
    const kernel = createControlDecisionKernel({ stateRoot: fixture.stateRoot, runId: fixture.runId, policy, reducerPolicy: fixture.reducer, runAuthority: fixture.runAuthority });
    const decision = (await kernel.evaluateControlDecision({ intent: "AUTHORIZE_WORK", operationId: "m6-repair-operation", availableLogicalRoles: ["LUNA_EXECUTOR"], expectedRevision: fast.statePointer.revision, expectedStatePointerContentSha256: fast.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fast.workflowState.content_sha256 as Sha256Digest, transitionId: "m6-repair-start", processMetadata: r3ProcessMetadata })).decision;
    const credentials = { value: 0 };
    const input = buildInput({ fixture, lock, repository, baseline, instruction, authority, gateway, m4Policy, m4Catalog, task, m3StateToken, policy, decision, credentials });
    return { fixture, lock, input, targetPath: join(fixture.verifierRoot, "repository", "tracked.txt"), credentials };
  } catch (error: unknown) {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeM5R3Fixture(fixture);
    throw error;
  }
}

async function cleanupScenario(scenario: Scenario): Promise<void> {
  configurePersistenceTestHooks(undefined);
  configureM6FauxRuntimeForTests(undefined);
  activeAbortController = undefined;
  await releaseWorktreeLock(scenario.lock).catch(() => undefined);
  await removeM5R3Fixture(scenario.fixture);
}

function errorCode(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error ? error.code : undefined;
}

test("OpenAI Codex OAuth route uses the Pi credential store without network or fallback", async () => {
  const aiSpecifier: string = "@earendil-works/pi-ai";
  const providersSpecifier: string = "@earendil-works/pi-ai/providers/all";
  const aiModule = objectValue(await import(aiSpecifier), "AI module");
  const providersModule = objectValue(await import(providersSpecifier), "providers module");
  const officialProvider = arrayValue(methodValue(providersModule, "builtinProviders", "providers module")(), "providers").map((value) => objectValue(value, "provider")).find((value) => value["id"] === "openai-codex");
  if (officialProvider === undefined) throw new Error("OpenAI Codex provider is absent");
  const lunaModel = arrayValue(methodValue(providersModule, "getBuiltinModels", "providers module")("openai-codex"), "OpenAI Codex models").map((value) => objectValue(value, "model")).find((value) => value["id"] === "gpt-5.6-luna");
  if (lunaModel === undefined) throw new Error("gpt-5.6-luna is absent");
  const access = ["m6", "synthetic", "access"].join(":");
  const refresh = ["m6", "synthetic", "refresh"].join(":");
  let storeReads = 0;
  let storeModifications = 0;
  let environmentReads = 0;
  let providerCalls = 0;
  let observedProviderApiKey: unknown;
  const credentials = {
    read: async (providerId: string): Promise<unknown> => {
      storeReads += 1;
      return providerId === "openai-codex" ? { type: "oauth", access, refresh, expires: Date.now() + 60 * 60 * 1000 } : undefined;
    },
    list: async (): Promise<readonly unknown[]> => [{ providerId: "openai-codex", type: "oauth" }],
    modify: async (_providerId: string, _fn: unknown): Promise<unknown> => { storeModifications += 1; return undefined; },
    delete: async (_providerId: string): Promise<unknown> => undefined,
  };
  const authContext = {
    env: async (_name: string): Promise<string | undefined> => { environmentReads += 1; return "m6-generic-fallback"; },
    fileExists: async (_path: string): Promise<boolean> => false,
  };
  const faux = objectValue(methodValue(aiModule, "fauxProvider", "AI module")({ api: "m6-oauth-faux-api", provider: "openai-codex", models: [{ id: "gpt-5.6-luna", reasoning: true, input: ["text"] }], tokensPerSecond: 0 }), "faux provider");
  methodValue(faux, "setResponses", "faux provider")( [methodValue(aiModule, "fauxAssistantMessage", "AI module")("offline", { stopReason: "stop" })] );
  const fauxProvider = objectValue(faux["provider"], "faux provider implementation");
  const fauxStream = methodValue(fauxProvider, "stream", "faux provider");
  const fauxStreamSimple = methodValue(fauxProvider, "streamSimple", "faux provider");
  const wrappedProvider = methodValue(aiModule, "createProvider", "AI module")({
    id: officialProvider["id"], name: officialProvider["name"], baseUrl: officialProvider["baseUrl"], auth: officialProvider["auth"], models: [lunaModel],
    api: {
      stream: (model: unknown, context: unknown, options: unknown): unknown => { providerCalls += 1; observedProviderApiKey = objectValue(options, "provider options")["apiKey"]; return fauxStream(model, context, options); },
      streamSimple: (model: unknown, context: unknown, options: unknown): unknown => { providerCalls += 1; observedProviderApiKey = objectValue(options, "provider options")["apiKey"]; return fauxStreamSimple(model, context, options); },
    },
  });
  const models = objectValue(methodValue(aiModule, "createModels", "AI module")({ credentials, authContext }), "models");
  methodValue(models, "setProvider", "models")(wrappedProvider);
  const selected = methodValue(models, "getModel", "models")("openai-codex", "gpt-5.6-luna");
  if (selected === undefined) throw new Error("Exact OpenAI Codex model lookup failed");
  assert.equal(objectValue(selected, "selected model")["provider"], "openai-codex");
  assert.equal(objectValue(selected, "selected model")["id"], "gpt-5.6-luna");
  const levels = arrayValue(methodValue(aiModule, "getSupportedThinkingLevels", "AI module")(selected), "thinking levels");
  assert.ok(levels.includes("high"));
  const auth = objectValue(await methodValue(models, "getAuth", "models")(selected), "OAuth resolution");
  assert.equal(auth["source"], "OAuth");
  const stream = objectValue(methodValue(models, "streamSimple", "models")(selected, { systemPrompt: "", messages: [] }, { reasoning: "high" }), "provider stream");
  await methodValue(stream, "result", "provider stream")();
  assert.equal(observedProviderApiKey, access);
  assert.equal(storeReads, 2);
  assert.equal(storeModifications, 0);
  assert.equal(environmentReads, 0);
  assert.equal(providerCalls, 1);

  const unavailableCredentials = { ...credentials, read: async (): Promise<undefined> => undefined };
  const unavailableModels = objectValue(methodValue(aiModule, "createModels", "AI module")({ credentials: unavailableCredentials, authContext }), "unavailable models");
  methodValue(unavailableModels, "setProvider", "unavailable models")(wrappedProvider);
  assert.equal(await methodValue(unavailableModels, "getAuth", "unavailable models")(selected), undefined);
  assert.equal(providerCalls, 1);
});

test("M6 terminal report binding rejects duplicate, missing-authority, and substituted submissions", () => {
  const validEvidence = digest(700);
  const validReport = { status: "COMPLETED", summary: "Bounded report." };
  const duplicate = runM6ReportSubmissionProtocolForTests(validEvidence, [validReport, validReport]);
  assert.equal(duplicate.acceptedCount, 1);
  assert.equal(duplicate.failures.length, 1);
  assert.equal(duplicate.failures[0]?.code, "WORKER_REPORT_INVALID");
  assert.deepEqual(duplicate.report?.["evidence_content_sha256"], [validEvidence]);

  const missing = runM6ReportSubmissionProtocolForTests(undefined, [validReport]);
  assert.equal(missing.acceptedCount, 0);
  assert.equal(missing.failures[0]?.code, "WORKER_REPORT_INVALID");

  const substituted = runM6ReportSubmissionProtocolForTests(validEvidence, [{ ...validReport, evidence_content_sha256: [digest(701)] }]);
  assert.equal(substituted.acceptedCount, 0);
  assert.equal(substituted.failures[0]?.code, "WORKER_REPORT_INVALID");
});

test("M6 terminal report summary bound is proven at the durable byte boundary", async () => {
  const evidence = digest(1);
  const report = (summary: string): Record<string, unknown> => ({ status: "COMPLETED", summary, evidence_content_sha256: [evidence] });
  assert.equal(Buffer.byteLength(canonicalize(report("")), "utf8"), 137);
  assert.equal(Buffer.byteLength(canonicalize(report("\u0000".repeat(659))), "utf8"), 4_091);
  assert.ok(Buffer.byteLength(canonicalize(report("\u0000".repeat(660))), "utf8") > 4_096);
  const multibyte = "😀".repeat(659);
  assert.equal(multibyte.length, 1_318);
  assert.equal([...multibyte].length, 659);
  assert.ok(Buffer.byteLength(canonicalize(report(multibyte)), "utf8") <= 4_096);

  const scenario = await createScenario();
  installFauxRuntime("SUCCESS", multibyte);
  try {
    const execution = await runDirectReadOnlyLunaWorkerForTests(scenario.input);
    assert.equal(execution.result.outcome, "COMPLETED");
    assert.equal(execution.result.worker_report?.summary, multibyte);
    assert.equal(execution.result.usage.report_submissions, 1);
    assert.deepEqual(observedReportParameters, { type: "object", properties: { status: { type: "string", const: "COMPLETED" }, summary: { type: "string", minLength: 1, maxLength: 659 } }, required: ["status", "summary"], additionalProperties: false });
  } finally { await cleanupScenario(scenario); }
});

test("official Pi 0.83.0 OpenAI Responses serialization excludes tool details", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../node_modules/@earendil-works/pi-ai/package.json", import.meta.url), "utf8")) as Record<string, unknown>;
  assert.equal(packageJson["version"], "0.83.0");
  const serializerSpecifier: string = "@earendil-works/pi-ai/api/openai-responses-shared";
  const shared = objectValue(await import(serializerSpecifier), "OpenAI Responses shared API");
  const convert = shared["convertResponsesMessages"];
  if (typeof convert !== "function") throw new Error("Pi OpenAI Responses converter is not callable");
  const m4Digest = digest(701);
  const contentDigest = digest(702);
  const model = {
    provider: "openai-codex", api: "openai-codex-responses", id: "gpt-5.6-luna", reasoning: true, input: ["text"],
  };
  const messages = (convert as (model: unknown, context: unknown, allowed: ReadonlySet<string>) => readonly unknown[])(model, {
    systemPrompt: "",
    messages: [
      { role: "assistant", content: [{ type: "toolCall", id: "call-1|fc_item-1", name: "read_scoped", arguments: { read_id: "primary" } }], api: "faux", provider: "faux", model: "faux", stopReason: "toolUse", timestamp: 1 },
      { role: "toolResult", toolCallId: "call-1|fc_item-1", toolName: "read_scoped", content: [{ type: "text", text: "model-visible read content" }], details: { m4ResultContentSha256: m4Digest, contentSha256: contentDigest }, isError: false, timestamp: 2 },
    ],
  }, new Set(["openai-codex"]));
  const serialized = JSON.stringify(messages);
  assert.match(serialized, /model-visible read content/);
  assert.doesNotMatch(serialized, new RegExp(m4Digest));
  assert.doesNotMatch(serialized, new RegExp(contentDigest));
  assert.doesNotMatch(serialized, /details|m4ResultContentSha256|contentSha256/);
  const output = messages.find((value) => objectValue(value, "serialized Responses item")["type"] === "function_call_output");
  assert.ok(output);
  assert.equal(objectValue(output, "serialized tool result")["output"], "model-visible read content");
});

test("M6 production-path protocol and lifecycle negatives remain bounded", async (t) => {
  await t.test("production entrypoint rejects TEST_FIXTURE authority before any work", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    try {
      await assert.rejects(runDirectReadOnlyLunaWorker(scenario.input), (error: unknown) => errorCode(error) === "AUTHORITY_REJECTED");
      const records = await readM6WorkerRecords(scenario.input);
      assert.equal(records.invocations.length, 0); assert.equal(records.results.length, 0); assert.equal(scenario.credentials.value, 0);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("unavailable Pi credential authority is rejected before provider work", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    try {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests({ ...scenario.input, credentialStoreCallback: () => undefined }), (error: unknown) => errorCode(error) === "AUTHORITY_REJECTED");
      const records = await readM6WorkerRecords(scenario.input);
      assert.equal(records.invocations.length, 0); assert.equal(records.results.length, 0); assert.equal(scenario.credentials.value, 0);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("wrong faux route provenance is rejected before publication", async () => {
    const scenario = await createScenario();
    configureM6FauxRuntimeForTests({ providerId: "wrong-provider", modelId: "wrong-model" }, () => undefined);
    try {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests(scenario.input), (error: unknown) => errorCode(error) === "AUTHORITY_REJECTED");
      const records = await readM6WorkerRecords(scenario.input);
      assert.equal(records.invocations.length, 0); assert.equal(records.results.length, 0); assert.equal(scenario.credentials.value, 0);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("authoritative pre-seeded incomplete invocation refuses provider work", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    try {
      await runDirectReadOnlyLunaWorkerForTests(scenario.input);
      const first = await readM6WorkerRecords(scenario.input);
      const result = first.results[0]; assert.ok(result);
      await unlink(join(scenario.input.stateRoot, "runs", scenario.input.runId, "records", "m6-worker-results", `${result.content_sha256.slice("sha256:".length)}.json`));
      const beforeCredentials = scenario.credentials.value;
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests(scenario.input), (error: unknown) => errorCode(error) === "INVOCATION_ALREADY_INCOMPLETE");
      const after = await readM6WorkerRecords(scenario.input);
      assert.equal(after.invocations.length, 1); assert.equal(after.results.length, 0); assert.equal(scenario.credentials.value, beforeCredentials);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("abort during admission publishes no M6 record", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    let reads = 0;
    const signal = { get aborted(): boolean { reads += 1; return reads > 1; } } as unknown as AbortSignal;
    try {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests({ ...scenario.input, signal }), (error: unknown) => errorCode(error) === "WORKER_ABORTED");
      const records = await readM6WorkerRecords(scenario.input);
      assert.equal(records.invocations.length, 0); assert.equal(records.results.length, 0); assert.equal(scenario.credentials.value, 0);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("abort after invocation publication leaves no provider work", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    const controller = new AbortController();
    configurePersistenceTestHooks({ checkpoint: async (checkpoint, finalPath) => {
      if (checkpoint === "RECORD_DIRECTORY_SYNCED" && finalPath.includes("m6-worker-invocations")) controller.abort();
    } });
    try {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests({ ...scenario.input, signal: controller.signal }), (error: unknown) => errorCode(error) === "WORKER_ABORTED");
      const records = await readM6WorkerRecords(scenario.input);
      assert.equal(records.invocations.length, 1); assert.equal(records.results.length, 0); assert.equal(scenario.credentials.value, 1);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("active-provider abort settles a blocked result and cleans up", async () => {
    const scenario = await createScenario(); installFauxRuntime("ACTIVE_ABORT");
    const controller = new AbortController(); activeAbortController = controller;
    try {
      const execution = await runDirectReadOnlyLunaWorkerForTests({ ...scenario.input, signal: controller.signal });
      assert.equal(execution.result.outcome, "BLOCKED"); assert.equal(execution.result.first_failure_code, "WORKER_ABORTED");
      assert.equal(execution.result.provider_work_started, true); assert.equal(execution.result.settlement.pending_tool_calls, 0);
      assert.equal((await readM6WorkerRecords(scenario.input)).results.length, 1);
    } finally { await cleanupScenario(scenario); }
  });

  for (const negative of ["TEXT_ONLY", "UNKNOWN_TOOL", "SECOND_READ", "REPORT_BEFORE_READ", "INVALID_STATUS", "EMPTY_SUMMARY", "OVERSIZED_SUMMARY", "EXTRA_EVIDENCE"] as const) {
    await t.test(`${negative} is rejected without a completed result`, async () => {
      const scenario = await createScenario();
      installFauxRuntime(negative);
      try {
        const execution = await runDirectReadOnlyLunaWorkerForTests(scenario.input);
        assert.equal(execution.result.outcome, "BLOCKED");
        assert.notEqual(execution.result.first_failure_code, null);
        assert.equal((await readM6WorkerRecords(scenario.input)).results.length, 1);
        if (negative === "REPORT_BEFORE_READ" || negative === "EXTRA_EVIDENCE" || negative === "INVALID_STATUS" || negative === "EMPTY_SUMMARY" || negative === "OVERSIZED_SUMMARY") {
          assert.equal(execution.result.usage.report_submissions, 0);
          assert.equal(execution.result.worker_report, null);
        }
      } finally { await cleanupScenario(scenario); }
    });
  }

  await t.test("provider failure preserves the first operational error", async () => {
    const scenario = await createScenario(); installFauxRuntime("PROVIDER_FAILURE");
    try {
      const execution = await runDirectReadOnlyLunaWorkerForTests(scenario.input);
      assert.equal(execution.result.outcome, "BLOCKED"); assert.equal(execution.result.first_failure_code, "PROVIDER_PROTOCOL_INVALID"); assert.equal(execution.result.provider_work_started, true);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("M4 read failure produces a bounded blocked result", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    configurePersistenceTestHooks({ checkpoint: async (checkpoint, finalPath) => { if (checkpoint === "RECORD_DIRECTORY_SYNCED" && finalPath.includes("m6-worker-invocations")) await unlink(scenario.targetPath); } });
    try {
      const execution = await runDirectReadOnlyLunaWorkerForTests(scenario.input);
      assert.equal(execution.result.outcome, "BLOCKED"); assert.equal(execution.result.first_failure_code, "TOOL_EXECUTION_FAILED"); assert.equal(execution.result.usage.read_calls, 0);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("result publication failure does not fabricate a terminal result", async () => {
    const scenario = await createScenario(); installFauxRuntime("SUCCESS");
    configurePersistenceTestHooks({ checkpoint: async (checkpoint, finalPath) => { if (checkpoint === "RECORD_TEMP_WRITTEN" && finalPath.includes("m6-worker-results")) throw new Error("injected result publication failure"); } });
    try {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests(scenario.input), (error: unknown) => errorCode(error) === "RESULT_PERSISTENCE_FAILED");
      const records = await readM6WorkerRecords(scenario.input); assert.equal(records.results.length, 0); assert.equal(records.invocations.length, 1);
    } finally { await cleanupScenario(scenario); }
  });

  await t.test("cleanup uncertainty after result publication does not rewrite the result", async () => {
    const scenario = await createScenario(); installFauxRuntime("CLEANUP_FAILURE");
    try {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests(scenario.input), (error: unknown) => errorCode(error) === "CLEANUP_UNCERTAIN");
      const records = await readM6WorkerRecords(scenario.input); assert.equal(records.results.length, 1); assert.equal(records.results[0]?.outcome, "COMPLETED"); assert.equal(records.results[0]?.cleanup_failure_code, null); assert.equal(records.results[0]?.settlement.cleanup_certain, false);
      const inspection = await inspectRunStorage({ stateRoot: scenario.input.stateRoot, runId: scenario.input.runId }); assert.equal(inspection.managedRecordClassifications.filter((entry) => entry.object.kind === "M6_WORKER_RESULT" && entry.classification === "AUTHORITATIVE_MANAGED_RECORD").length, 1);
    } finally { await cleanupScenario(scenario); }
  });
});
