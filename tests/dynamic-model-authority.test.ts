import assert from "node:assert/strict";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { assertDocumentValid, identifyContractDocument } from "../src/schemas/index.js";
import { normalizeStaticApprovedDagLaunchSpec, staticApprovedDagSpecSha256 } from "../src/static-approved-dag-launcher.js";
import { admitDynamicPiModelForTests, M6WorkerError, prepareDynamicPiRuntimeForTests, releasePreparedRuntimeForTests } from "../src/pi-adapter/worker.js";
import { allRoutes } from "./helpers.js";

const HEAD = "a".repeat(40);
const TREE = "b".repeat(40);

// ---------------------------------------------------------------------------
// Frozen authority constants
// ---------------------------------------------------------------------------

const V1_FROZEN_HIGH_DIGEST = "sha256:c557d053d284175ae8bd683341679f456a58ec799593ab183888255aeb1c1ed8";
const V1_FROZEN_XHIGH_DIGEST = "sha256:792fa269f752717023643b977307ef11cb0904952c6fcfb48104c2a842b58fbc";

/** The exact owner-frozen Ox execution authority (no name, no cost, thinking_level_map literal ABSENT). */
const OX_MODEL_EXECUTION_DEFINITION = {
  api: "openai-completions",
  base_url: "https://openrouter.ai/api/v1",
  canonicalization_id: "canonical-json-v1",
  compat: { supportsDeveloperRole: false, thinkingFormat: "openrouter" },
  context_window: 1_048_576,
  headers: {},
  input: ["text", "image"],
  max_tokens: 131_072,
  model_id: "stealth/ox-alpha",
  provider_id: "openrouter",
  reasoning: true,
  schema_id: "pi_gacw_model_execution_definition_v1",
  thinking_level_map: "ABSENT",
} as const;
const OX_MODEL_DEFINITION_SHA256 = "sha256:106eb60535677cea92ae32ddf9f83176c1479035a2e49d140dcf5c82e8eadad6";

/** The exact resolved Pi model object the offline overlay restores for the Ox route. */
const OX_RESOLVED_MODEL = {
  id: "stealth/ox-alpha",
  name: "Ox Alpha",
  api: "openai-completions",
  baseUrl: "https://openrouter.ai/api/v1",
  provider: "openrouter",
  reasoning: true,
  input: ["text", "image"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 1_048_576,
  maxTokens: 131_072,
  compat: { supportsDeveloperRole: false, thinkingFormat: "openrouter" },
};

function v1PinSpec(): Record<string, unknown> {
  return {
    spec_version: "static-approved-dag-launch-v1", run_label: "launcher-test", expected_repository_branch: "main", expected_head: HEAD, expected_tree: TREE,
    goal: { objective: "Write exactly two outputs.", stop_condition: "Stop after verification.", execution_mode: "STATIC_APPROVED_DAG", scope: { readable_paths: ["node_modules"], editable_paths: ["out/a.txt", "out/b.txt"], frozen_paths: ["node_modules"] }, required_outputs: ["out/a.txt", "out/b.txt"], tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["out/a.txt"], required_outputs: ["out/a.txt"], dependencies: [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["out/b.txt"], required_outputs: ["out/b.txt"], dependencies: ["a"] },
    ] },
    verification_commands: [{ command_id: "tsx", executable: "/usr/bin/tsx", args: ["--version"], cwd: "node_modules", timeout_ms: 60_000 }],
    static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
    expected_route: { logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort: "high", fallback: false },
  };
}

function v2Spec(expectedRoute: Record<string, unknown>): Record<string, unknown> {
  return {
    spec_version: "static-approved-dag-launch-v2", run_label: "launcher-test", expected_repository_branch: "main", expected_head: HEAD, expected_tree: TREE,
    goal: { objective: "Write exactly two outputs.", stop_condition: "Stop after verification.", execution_mode: "STATIC_APPROVED_DAG", scope: { readable_paths: ["node_modules"], editable_paths: ["out/a.txt", "out/b.txt"], frozen_paths: ["node_modules"] }, required_outputs: ["out/a.txt", "out/b.txt"], tasks: [
      { task_id: "a", objective: "Write a.", editable_paths: ["out/a.txt"], required_outputs: ["out/a.txt"], dependencies: [] },
      { task_id: "b", objective: "Write b.", editable_paths: ["out/b.txt"], required_outputs: ["out/b.txt"], dependencies: ["a"] },
    ] },
    verification_commands: [{ command_id: "tsx", executable: "/usr/bin/tsx", args: ["--version"], cwd: "node_modules", timeout_ms: 60_000, readable_paths: [{ path: "node_modules", kind: "PREFIX" }] }],
    static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
    expected_route: expectedRoute,
  };
}

// In-memory Pi ModelsStore fixture; read-only under offline refresh (write must never run).
function modelsStoreFixture(models: readonly unknown[]): { store: unknown; writes: number } {
  let writes = 0;
  // lastModified must exceed the builtin catalog timestamp for the offline overlay restore to accept it.
  const entry = { models: [...models], checkedAt: Date.now(), lastModified: Date.now() };
  const store = {
    async read(): Promise<unknown> { return structuredClone(entry); },
    async write(): Promise<void> { writes += 1; throw new Error("models store write must never happen offline"); },
    async delete(): Promise<void> { throw new Error("models store delete must never happen offline"); },
  };
  return { store, get writes() { return writes; } };
}

function credentialStoreFixture(): unknown {
  // Dummy stored api_key so Pi's offline auth resolution reaches the catalog restore path.
  // It is never transmitted: no stream seam is touched by admission.
  return {
    async read(providerId: string): Promise<unknown> { return providerId === "openrouter" ? { type: "api_key", key: "DUMMY-TEST-NOT-A-SECRET", env: undefined } : undefined; },
    async list(): Promise<unknown> { return []; },
    async modify(): Promise<unknown> { throw new Error("credential mutation is forbidden in tests"); },
    async delete(): Promise<void> { throw new Error("credential deletion is forbidden in tests"); },
  };
}

async function expectDynamicAdmissionFailure(models: readonly unknown[], digest: string, pattern: RegExp): Promise<void> {
  const { store } = modelsStoreFixture(models);
  await assert.rejects(
    admitDynamicPiModelForTests({ providerId: "openrouter", modelId: "stealth/ox-alpha", modelDefinitionSha256: digest as never, credentialStore: credentialStoreFixture() as never, modelsStore: store }),
    (error: unknown) => error instanceof M6WorkerError && error.code === "RUNTIME_CAPABILITY_INVALID" && pattern.test(error.message),
  );
}

// ---------------------------------------------------------------------------
// Launcher authority
// ---------------------------------------------------------------------------

test("exact Ox definition normalizes, keeps V2 fallback=false, and derives exactly the frozen digest", () => {
  const spec = normalizeStaticApprovedDagLaunchSpec(v2Spec({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false,
    model_execution_definition: structuredClone(OX_MODEL_EXECUTION_DEFINITION),
  }));
  const expectedRoute = spec.expected_route as Extract<typeof spec.expected_route, { logical_role: "CODING_EXECUTOR" }>;
  assert.equal(expectedRoute.fallback, false);
  assert.deepEqual(expectedRoute.model_execution_definition, OX_MODEL_EXECUTION_DEFINITION);
  assert.equal(staticApprovedDagSpecSha256(v2Spec({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false,
    model_execution_definition: structuredClone(OX_MODEL_EXECUTION_DEFINITION),
  })), staticApprovedDagSpecSha256(v2Spec({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false,
    model_execution_definition: JSON.parse(JSON.stringify(OX_MODEL_EXECUTION_DEFINITION)),
  })));
  assert.equal(sha256Canonical(OX_MODEL_EXECUTION_DEFINITION), OX_MODEL_DEFINITION_SHA256);
});

test("definition identity drift against the route rejects at normalization", () => {
  const drifted = structuredClone(OX_MODEL_EXECUTION_DEFINITION) as Record<string, unknown>;
  drifted["model_id"] = "stealth/other";
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(v2Spec({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false,
    model_execution_definition: drifted,
  })), /identity differs from the approved route/);
});

test("non-empty definition headers reject at normalization", () => {
  const headers = structuredClone(OX_MODEL_EXECUTION_DEFINITION) as Record<string, unknown>;
  headers["headers"] = { "x-custom": "value" };
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(v2Spec({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false, model_execution_definition: headers,
  })), /headers must be empty/);
});

// The previous assertion form is awkward; use direct throws checks instead.
test("present thinking_level_map rejects at normalization", () => {
  const map = structuredClone(OX_MODEL_EXECUTION_DEFINITION) as Record<string, unknown>;
  map["thinking_level_map"] = { high: "high" };
  assert.throws(() => normalizeStaticApprovedDagLaunchSpec(v2Spec({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false, model_execution_definition: map,
  })), /must be the literal "ABSENT"/);
});

test("legacy roles cannot carry model_definition_sha256 in route documents", () => {
  const routes = allRoutes();
  const build = (candidate: unknown[]): unknown => identifyContractDocument("pi_gacw_route_map_v0", {
    schema_id: "pi_gacw_route_map_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    route_map_projection_id: "route-map-v1", route_map_sha256: OX_MODEL_DEFINITION_SHA256, routes: candidate,
    fallback: false, provider_managed_multi_agent: false,
  });
  assertDocumentValid("pi_gacw_route_map_v0", build(routes));
  const withLegacyDigest = structuredClone(routes) as Record<string, unknown>[];
  withLegacyDigest[0]!["model_definition_sha256"] = OX_MODEL_DEFINITION_SHA256;
  assert.throws(() => assertDocumentValid("pi_gacw_route_map_v0", build(withLegacyDigest)));
  const withExecutorDigest = structuredClone(routes) as Record<string, unknown>[];
  withExecutorDigest.push({
    logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high",
    model_definition_sha256: OX_MODEL_DEFINITION_SHA256,
    tool_policy: { policy_id: "tools-coding_executor", built_in_tools_disabled: true, mutation_tool: "APPLY_PATCH_SCOPED", command_gateway: "TASK_AND_VERIFICATION", maximum_tool_calls: 100 },
  });
  assertDocumentValid("pi_gacw_route_map_v0", build(withExecutorDigest));
});

// ---------------------------------------------------------------------------
// Runtime dynamic-model admission (provider-free)
// ---------------------------------------------------------------------------

test("the exact Ox candidate resolves offline and is admitted with the exact frozen digest", async () => {
  const { store, writes } = modelsStoreFixture([structuredClone(OX_RESOLVED_MODEL)]);
  const admitted = await admitDynamicPiModelForTests({
    providerId: "openrouter", modelId: "stealth/ox-alpha", modelDefinitionSha256: OX_MODEL_DEFINITION_SHA256 as never,
    credentialStore: credentialStoreFixture() as never, modelsStore: store,
  });
  assert.equal(admitted.digest, OX_MODEL_DEFINITION_SHA256);
  assert.deepEqual(admitted.projection, OX_MODEL_EXECUTION_DEFINITION);
  assert.equal(writes, 0, "offline admission must never write the models store");
});

test("network access is neither needed nor attempted during admission", async () => {
  const { store } = modelsStoreFixture([structuredClone(OX_RESOLVED_MODEL)]);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (async () => { fetchCalls += 1; throw new Error("network is forbidden during admission"); }) as typeof fetch;
  try {
    const admitted = await admitDynamicPiModelForTests({
      providerId: "openrouter", modelId: "stealth/ox-alpha", modelDefinitionSha256: OX_MODEL_DEFINITION_SHA256 as never,
      credentialStore: credentialStoreFixture() as never, modelsStore: store,
    });
    assert.equal(admitted.digest, OX_MODEL_DEFINITION_SHA256);
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("baseUrl drift rejects before provider generation", async () => {
  const drifted = structuredClone(OX_RESOLVED_MODEL) as Record<string, unknown>;
  drifted["baseUrl"] = "https://evil.example/v1";
  await expectDynamicAdmissionFailure([drifted], OX_MODEL_DEFINITION_SHA256, /differs from the frozen authority/);
});

test("compat, reasoning, context-window, max-token, and modality drift reject before provider generation", async () => {
  const cases: Array<(model: Record<string, unknown>) => void> = [
    (model) => { (model["compat"] as Record<string, unknown>)["thinkingFormat"] = "openai"; },
    (model) => { (model["compat"] as Record<string, unknown>)["supportsDeveloperRole"] = true; },
    (model) => { (model["compat"] as Record<string, unknown>)["supportsStore"] = true; },
    (model) => { model["reasoning"] = false; },
    (model) => { model["contextWindow"] = 128_000; },
    (model) => { model["maxTokens"] = 8_192; },
    (model) => { model["input"] = ["text"]; },
  ];
  for (const mutate of cases) {
    const model = structuredClone(OX_RESOLVED_MODEL) as Record<string, unknown>;
    mutate(model);
    await expectDynamicAdmissionFailure([model], OX_MODEL_DEFINITION_SHA256, /differs from the frozen authority|unsupported by ModelExecutionDefinitionV1/);
  }
});

test("a resolved thinkingLevelMap rejects closed before provider generation", async () => {
  const mapped = structuredClone(OX_RESOLVED_MODEL) as Record<string, unknown>;
  mapped["thinkingLevelMap"] = { high: "high" };
  await expectDynamicAdmissionFailure([mapped], OX_MODEL_DEFINITION_SHA256, /thinkingLevelMap/);
});

test("non-empty resolved headers reject closed before provider generation", async () => {
  const headed = structuredClone(OX_RESOLVED_MODEL) as Record<string, unknown>;
  headed["headers"] = { "x-injected": "value" };
  await expectDynamicAdmissionFailure([headed], OX_MODEL_DEFINITION_SHA256, /non-empty headers/);
});

test("a missing or stale dynamic model rejects before provider generation", async () => {
  await expectDynamicAdmissionFailure([], OX_MODEL_DEFINITION_SHA256, /absent from the offline Pi runtime catalogue/);
  const stale = structuredClone(OX_RESOLVED_MODEL) as Record<string, unknown>;
  stale["id"] = "stealth/ox-beta";
  await expectDynamicAdmissionFailure([stale], OX_MODEL_DEFINITION_SHA256, /absent from the offline Pi runtime catalogue|differs from the frozen authority/);
});

// ---------------------------------------------------------------------------
// Runtime lifecycle cleanup certainty (production prepare + production release)
// ---------------------------------------------------------------------------

test("dynamic runtime lifecycle reaches truthful clean settlement through the real Pi cleanup primitive", async () => {
  const { store, writes } = modelsStoreFixture([structuredClone(OX_RESOLVED_MODEL)]);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (async () => { fetchCalls += 1; throw new Error("network is forbidden during the lifecycle"); }) as typeof fetch;
  let runtime: Awaited<ReturnType<typeof prepareDynamicPiRuntimeForTests>> | undefined;
  try {
    runtime = await prepareDynamicPiRuntimeForTests({
      providerId: "openrouter", modelId: "stealth/ox-alpha", effort: "high",
      modelDefinitionSha256: OX_MODEL_DEFINITION_SHA256 as never,
      credentialStore: credentialStoreFixture() as never, modelsStore: store,
    });
    // Dynamic ModelRuntime was created; the exact model is admitted by frozen digest.
    const admitted = runtime.models.getModel("openrouter", "stealth/ox-alpha") as Record<string, unknown>;
    assert.notEqual(admitted, undefined);
    assert.equal(admitted["id"], "stealth/ox-alpha");
    assert.equal(admitted["provider"], "openrouter");
    assert.equal(admitted["baseUrl"], "https://openrouter.ai/api/v1");
    assert.equal(runtime.models.getSupportedThinkingLevels(admitted).includes("high"), true);
    // The provider registry is genuinely populated before cleanup (no synthetic empty view).
    const providersBeforeCleanup = runtime.models.getProviders().length;
    assert.ok(providersBeforeCleanup >= 1);
    // No generation seam was touched.
    assert.equal(typeof runtime.streamFn, "function");
    // Exact production cleanup sequence from runBoundedPiAgentImpl:
    //   clearProviderState(); clearProviders(); prove registry empty and no pending responses.
    // Pre-repair, the no-op clearProviders left providersBeforeCleanup observable here and
    // the same check produced CLEANUP_UNCERTAIN.
    runtime.clearProviderState();
    runtime.models.clearProviders();
    const providerCollectionCleared = runtime.models.getProviders().length === 0 && runtime.pendingResponseCount() === 0;
    assert.equal(providerCollectionCleared, true);
    // Repeated cleanup (the production path can issue it on failure latches) is safe/idempotent.
    releasePreparedRuntimeForTests(runtime);
    assert.equal(runtime.models.getProviders().length, 0);
    assert.equal(runtime.pendingResponseCount(), 0);
    assert.equal(writes, 0);
    assert.equal(fetchCalls, 0);
    runtime = undefined;
  } finally {
    globalThis.fetch = originalFetch;
    if (runtime !== undefined) { try { releasePreparedRuntimeForTests(runtime); } catch { /* already settled above */ } }
  }
});
