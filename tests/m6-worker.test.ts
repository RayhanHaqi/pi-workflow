import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { createControlDecisionKernel } from "../src/control/index.js";
import { inspectRunStorage, readM6WorkerRecords } from "../src/persistence/store.js";
import { acquireWorktreeLock, releaseWorktreeLock, runFullPreflight } from "../src/repository/index.js";
import { requiredEnvironment, fingerprintInput } from "./repository-helpers.js";
import { identifyContractDocument, assertDocumentValid, type M3BaselineRuntimeDocument, type M4CommandCatalogDocument, type M4ScopedToolPolicyDocument, type TaskDocument } from "../src/schemas/index.js";
import { createScopedToolGateway } from "../src/scoped-tools/index.js";
import { configureM6FauxRuntimeForTests, runDirectReadOnlyLunaWorker, runDirectReadOnlyLunaWorkerForTests } from "../src/pi-adapter/worker.js";
import { configurePersistenceTestHooks } from "../src/persistence/test-hooks.js";
import { classifyM6Authority } from "../src/persistence/m6-authority.js";
import { createM5R3Fixture, directFastPreflightFixture, m5Policy, removeM5R3Fixture, r3ProcessMetadata } from "./m5-r3-fixtures.js";
import { digest } from "./helpers.js";
import { type Sha256Digest } from "../src/identity/index.js";
import { m3ScopeIdentity } from "../src/identity/m3-scope.js";
import type { M5ControlPolicyDocument } from "../src/schemas/index.js";

const limits = { maximum_patch_bytes: 1_048_576, maximum_read_bytes: 1_048_576, maximum_hash_bytes: 67_108_864, maximum_search_input_bytes: 67_108_864, maximum_search_matches: 10_000, maximum_list_entries: 100_000, maximum_list_metadata_bytes: 67_108_864, maximum_command_stdout_bytes: 4_194_304, maximum_command_stderr_bytes: 4_194_304, maximum_command_duration_ms: 1_800_000 } as const;
const editable = ["tracked.txt"] as const;
const frozen = ["AGENTS.md", "AUTHORITY.md"] as const;
const taskScopeIdentity = m3ScopeIdentity(editable, frozen);

type FauxResponse = unknown | ((context: unknown) => unknown);
const fauxEvents: string[] = [];
let fauxResponses: readonly FauxResponse[] = [];

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is not an object`);
  return value as Record<string, unknown>;
}

function methodValue(value: unknown, name: string, label: string): (...args: readonly unknown[]) => unknown {
  const object = objectValue(value, label);
  const method = object[name];
  if (typeof method !== "function") throw new Error(`${label}.${name} is not callable`);
  return (...args: readonly unknown[]) => Reflect.apply(method, object, args);
}

function fauxSecondResponse(aiModule: Record<string, unknown>, contextValue: unknown): unknown {
  const context = objectValue(contextValue, "faux response context");
  const messages = context["messages"];
  if (!Array.isArray(messages)) throw new Error("faux response messages are not an array");
  let evidence: string | undefined;
  for (const messageValue of messages) {
    const message = objectValue(messageValue, "faux response message");
    if (message["role"] !== "toolResult" || message["toolName"] !== "read_scoped") continue;
    const details = objectValue(message["details"], "read tool result details");
    if (typeof details["m4ResultContentSha256"] === "string") evidence = details["m4ResultContentSha256"];
  }
  const assistant = methodValue(aiModule, "fauxAssistantMessage", "AI module");
  if (evidence === undefined) return assistant("missing read evidence", { stopReason: "stop" });
  const toolCall = methodValue(aiModule, "fauxToolCall", "AI module")( "submit_worker_report", {
    status: "COMPLETED", summary: "Completed the bounded read-only task from the authoritative primary evidence.", evidence_content_sha256: [evidence],
  });
  return assistant(toolCall, { stopReason: "toolUse" });
}

function installFauxRuntime(events: string[], responses: readonly FauxResponse[] = []): void {
  fauxEvents.length = 0;
  fauxEvents.push(...events);
  fauxResponses = responses;
  configureM6FauxRuntimeForTests({ providerId: "provider-primary", modelId: "luna-high" }, ({ aiModule, providerId, modelId }) => {
    if (providerId !== "provider-primary" || modelId !== "luna-high") return undefined;
    const faux = objectValue(methodValue(aiModule, "fauxProvider", "AI module")({
      api: "m6-direct-faux-api", provider: providerId, models: [{ id: modelId, name: modelId, reasoning: true, input: ["text"] }], tokensPerSecond: 0,
    }), "faux provider");
    const models = objectValue(methodValue(aiModule, "createModels", "AI module")(), "models");
    methodValue(models, "setProvider", "models")(faux["provider"]);
    const model = methodValue(models, "getModel", "models")(providerId, modelId);
    const assistant = methodValue(aiModule, "fauxAssistantMessage", "AI module");
    const toolCall = methodValue(aiModule, "fauxToolCall", "AI module");
    const first = assistant(toolCall("read_scoped", { read_id: "primary" }), { stopReason: "toolUse" });
    const second = (context: unknown): unknown => fauxSecondResponse(aiModule, context);
    const setResponses = methodValue(faux, "setResponses", "faux provider");
    setResponses(fauxResponses.length === 0 ? [first, second] : fauxResponses);
    const state = objectValue(faux["state"], "faux provider state");
    const streamSimple = methodValue(models, "streamSimple", "models");
    return {
      models,
      model,
      streamFn: (streamModel: unknown, context: unknown, options?: unknown): unknown => {
        fauxEvents.push("provider-call");
        return streamSimple(streamModel, context, options);
      },
      clearProviderState: (): void => { fauxEvents.push("cleanup-provider"); setResponses([]); },
      fauxCallCount: (): unknown => state["callCount"],
      pendingResponseCount: (): unknown => methodValue(faux, "getPendingResponseCount", "faux provider")(),
    };
  });
}

test("M6 direct read-only worker executes once and replays its immutable result", async (t) => {
  const fixture = await createM5R3Fixture();
  let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    const repository = fixture.runAuthority.repositoryIdentity;
    const baselinePath = join(fixture.stateRoot, "runs", fixture.runId, "records", "baselines", `${fixture.m3StateToken.baseline_runtime_content_sha256.slice("sha256:".length)}.json`);
    const baseline = JSON.parse(await readFile(baselinePath, "utf8")) as M3BaselineRuntimeDocument;
    assertDocumentValid("pi_gacw_baseline_runtime_v0", baseline);
    const instruction = await fingerprintInput(join(fixture.verifierRoot, "repository", "AGENTS.md"));
    const authority = await fingerprintInput(join(fixture.verifierRoot, "repository", "AUTHORITY.md"));
    lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
    const environment = await requiredEnvironment(repository.worktree_root);
    const refreshed = await runFullPreflight({ stateRoot: fixture.stateRoot, runId: fixture.runId, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256, baseline, approval: null, instructionFiles: [instruction], authorityFiles: [authority], requiredEnvironment: environment, taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock });
    const m3StateToken = refreshed.acceptedState;
    const m4Policy = identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
      schema_id: "pi_gacw_scoped_tool_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      run_id: fixture.runId, policy_id: "m4-smoke-policy", repository_identity_content_sha256: repository.content_sha256, worktree_key: repository.worktree_key,
      task_scope_identity: taskScopeIdentity,
      readable_paths: [{ path: "tracked.txt", kind: "EXACT" }], editable_paths: [{ path: "tracked.txt", kind: "EXACT" }], frozen_paths: frozen.map((path) => ({ path, kind: "EXACT" as const })),
      command_readable_paths: [{ path: "tracked.txt", kind: "EXACT" }], command_writable_paths: [],
      path_authorities: [
        { path: "tracked.txt", kind: "EXACT", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: true, delete: true, mode_change: true },
        { path: "AGENTS.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
        { path: "AUTHORITY.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
      ],
      evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M4_TOOL_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"], limits,
    }) as M4ScopedToolPolicyDocument;
    const m4Catalog = identifyContractDocument("pi_gacw_command_catalog_v0", {
      schema_id: "pi_gacw_command_catalog_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: fixture.runId,
      catalog_id: "m4-smoke-catalog", repository_identity_content_sha256: repository.content_sha256, tool_policy_content_sha256: m4Policy.content_sha256, commands: [],
    }) as M4CommandCatalogDocument;
    const temporaryRoot = join(fixture.verifierRoot, "controller-tmp"); await mkdir(temporaryRoot, { mode: 0o700 });
    const gateway = await createScopedToolGateway({ stateRoot: fixture.stateRoot, runId: fixture.runId, repository, baseline, acceptedState: m3StateToken, lock,
      instructionFiles: [instruction], authorityFiles: [authority], editablePaths: [...editable], frozenPaths: [...frozen], taskScopeIdentity, toolPolicy: m4Policy, commandCatalog: m4Catalog, temporaryRoot });
    const task = identifyContractDocument("pi_gacw_task_v0", {
      schema_id: "pi_gacw_task_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", task_projection_id: "task-packet-v1", task_sha256: digest(30), task_id: "task-only", topological_rank: 0, priority: 0, dependencies: [], objective: "Read the bounded target.", scope: { readable_paths: ["tracked.txt"], editable_paths: [...editable], frozen_paths: [...frozen] }, required_inputs: ["input"], required_outputs: ["report"], acceptance_criteria: [{ criterion_id: "m6-accept", description: "The report is durably published.", evidence_kind: "FILE", owner_acceptance: false }], owner_acceptance_criteria: [], verification_commands: [{ command_id: "verify", argv: ["true"], cwd: "/work", timeout_ms: 1000, network: "FORBIDDEN" }], assigned_role: "LUNA_EXECUTOR", write_owner: "writer" });
    const baseM5 = m5Policy(fixture.reducer, fixture.initialState.content_sha256 as Sha256Digest, fixture.runAuthority);
    const { content_sha256: _ignored, ...m5Body } = structuredClone(baseM5) as Record<string, unknown>;
    const policy = identifyContractDocument("pi_gacw_m5_control_policy_v0", { ...m5Body, limits: (m5Body["limits"] as Array<Record<string, unknown>>).map((entry) => entry["dimension"] === "WALL_TIME_MS" ? { ...entry, hard_limit: 120000, soft_limit: 120000 } : entry), tool_policy_content_sha256: m4Policy.content_sha256, command_catalog_content_sha256: m4Catalog.content_sha256, obligations: [] }) as unknown as M5ControlPolicyDocument;
    const fast = await directFastPreflightFixture(fixture);
    const kernel = createControlDecisionKernel({ stateRoot: fixture.stateRoot, runId: fixture.runId, policy, reducerPolicy: fixture.reducer, runAuthority: fixture.runAuthority });
    const decisionResult = await kernel.evaluateControlDecision({ intent: "AUTHORIZE_WORK", operationId: "m6-smoke-operation", availableLogicalRoles: ["LUNA_EXECUTOR"], expectedRevision: fast.statePointer.revision, expectedStatePointerContentSha256: fast.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fast.workflowState.content_sha256 as Sha256Digest, transitionId: "m6-smoke-start", processMetadata: r3ProcessMetadata });
    installFauxRuntime([]);
    configurePersistenceTestHooks({ checkpoint: async (checkpoint, finalPath) => {
      if (checkpoint !== "RECORD_DIRECTORY_SYNCED") return;
      if (finalPath.includes("m6-worker-invocations")) fauxEvents.push("invocation-written");
      if (finalPath.includes("m6-worker-results")) {
        fauxEvents.push("result-written");
        const published = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
        if (published.managedRecordClassifications.some((entry) => entry.object.kind === "M6_WORKER_RESULT" && entry.classification === "AUTHORITATIVE_MANAGED_RECORD")) fauxEvents.push("result-classified");
      }
    } });
    let credentials = 0;
    const workerInput = { stateRoot: fixture.stateRoot, runId: fixture.runId, reducerPolicy: fixture.reducer, m5Policy: policy, m5Decision: decisionResult.decision, runAuthority: { ...fixture.runAuthority, task: task as TaskDocument }, repository, baseline, m3StateToken: m3StateToken, lock, instructionFiles: [instruction], authorityFiles: [authority], gateway, m4ToolPolicy: m4Policy, m4CommandCatalog: m4Catalog, task: { task_id: task.task_id, task_sha256: task.task_sha256 }, approvedResources: [{ path: instruction.path, contentSha256: instruction.expectedSha256, dataClass: "PUBLIC_SOURCE" }, { path: authority.path, contentSha256: authority.expectedSha256, dataClass: "PUBLIC_SOURCE" }], systemPrompt: "Bounded smoke worker.", userPrompt: "Read the primary target and submit the terminal report.", credentialCallback: () => { credentials += 1; return "m6-faux-test-key"; } } as const;
    const assertAuthorityRejectedWithoutWork = async (candidate: typeof workerInput): Promise<void> => {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests(candidate), (error: unknown) => error !== null && typeof error === "object" && (error as { readonly code?: unknown }).code === "AUTHORITY_REJECTED");
      const records = await readM6WorkerRecords({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      const after = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(records.invocations.length, 0); assert.equal(records.results.length, 0);
      assert.equal(after.managedRecordClassifications.filter((entry) => entry.object.kind === "M4_TOOL_RESULT" && entry.classification === "AUTHORITATIVE_MANAGED_RECORD").length, 0);
      assert.equal(credentials, 0);
    };
    await t.test("forged durable M5 decision is rejected before provider or M4 work", async () => {
      await assertAuthorityRejectedWithoutWork({ ...workerInput, m5Decision: { ...decisionResult.decision, operation_id: "forged-operation" } as typeof decisionResult.decision });
    });
    await t.test("modified task content and wrong task identity are rejected before publication", async () => {
      await assertAuthorityRejectedWithoutWork({ ...workerInput, task: { ...workerInput.task, task_sha256: digest(998) } });
      for (const fields of [
        { assigned_role: "SOL_OWNER" },
        { dependencies: ["other-task"] },
        { scope: { readable_paths: ["other.txt"] } },
      ] as const) {
        await assertAuthorityRejectedWithoutWork({ ...workerInput, task: { ...workerInput.task, ...fields } as unknown as typeof workerInput.task });
      }
      await assertAuthorityRejectedWithoutWork({ ...workerInput, approvedResources: [{ ...workerInput.approvedResources[0]!, contentSha256: digest(999) }, workerInput.approvedResources[1]!] });
    });
    await t.test("pre-admission abort performs no provider, M4, or M6 work", async () => {
      const controller = new AbortController(); controller.abort();
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests({ ...workerInput, signal: controller.signal }), (error: unknown) => error !== null && typeof error === "object" && (error as { readonly code?: unknown }).code === "WORKER_ABORTED");
      const records = await readM6WorkerRecords({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(records.invocations.length, 0); assert.equal(records.results.length, 0); assert.equal(credentials, 0);
    });
    const result = await runDirectReadOnlyLunaWorkerForTests(workerInput);
    assert.equal(result.result.outcome, "COMPLETED"); assert.equal(result.result.usage.provider_turns, 2); assert.equal(result.result.usage.read_calls, 1); assert.equal(result.result.usage.report_submissions, 1); assert.equal(result.result.settlement.cleanup_certain, false); assert.equal(credentials, 2);
    assert.ok(fauxEvents.indexOf("invocation-written") >= 0);
    assert.ok(fauxEvents.indexOf("invocation-written") < fauxEvents.indexOf("provider-call"));
    assert.ok(fauxEvents.indexOf("result-classified") >= 0);
    assert.ok(fauxEvents.indexOf("result-classified") < fauxEvents.indexOf("cleanup-provider"));
    const persisted = await readM6WorkerRecords({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(persisted.invocations.length, 1); assert.equal(persisted.results.length, 1); assert.equal(persisted.results[0]?.content_sha256, result.result.content_sha256);
    assert.equal(result.result.m4_result_content_sha256 !== null, true);
    assert.deepEqual(result.result.worker_report?.evidence_content_sha256, [result.result.m4_result_content_sha256]);
    const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
    assert.equal(inspection.status, "HEALTHY");
    assert.equal(inspection.managedRecordClassifications.filter((entry) => entry.object.kind === "M6_WORKER_INVOCATION" && entry.classification === "AUTHORITATIVE_MANAGED_RECORD").length, 1);
    assert.equal(inspection.managedRecordClassifications.filter((entry) => entry.object.kind === "M6_WORKER_RESULT" && entry.classification === "AUTHORITATIVE_MANAGED_RECORD").length, 1);
    await t.test("completed authority conflict is rejected before a new invocation publication", async () => {
      await assert.rejects(runDirectReadOnlyLunaWorkerForTests({ ...workerInput, userPrompt: "A conflicting prompt identity." }), (error: unknown) => error !== null && typeof error === "object" && (error as { readonly code?: unknown }).code === "AUTHORITY_REJECTED");
      const records = await readM6WorkerRecords({ stateRoot: fixture.stateRoot, runId: fixture.runId });
      assert.equal(records.invocations.length, 1); assert.equal(records.results.length, 1); assert.equal(credentials, 2);
    });
    const replay = await runDirectReadOnlyLunaWorkerForTests(workerInput);
    assert.equal(replay.replayed, true); assert.equal(replay.result.content_sha256, result.result.content_sha256); assert.equal(credentials, 2);
    await t.test("semantic M6 classifier rejects schema-valid contradictory terminal records", async () => {
      const invalidResult = (patch: Record<string, unknown>): typeof result.result => {
        const { content_sha256: _contentSha256, ...body } = structuredClone(result.result) as Record<string, unknown>;
        return identifyContractDocument("pi_gacw_m6_worker_result_v0", { ...body, ...patch }) as typeof result.result;
      };
      const assertInvalid = (candidate: typeof result.result): void => {
        const classifications = classifyM6Authority({
          runId: fixture.runId,
          objects: [
            { kind: "M6_WORKER_INVOCATION", contentSha256: result.invocation.content_sha256 as Sha256Digest, relativePath: "records/m6-worker-invocations/invocation.json" },
            { kind: "M6_WORKER_RESULT", contentSha256: candidate.content_sha256 as Sha256Digest, relativePath: "records/m6-worker-results/result.json" },
          ],
          invocations: new Map([[result.invocation.content_sha256, result.invocation]]),
          results: new Map([[candidate.content_sha256, candidate]]),
        });
        assert.equal(classifications.find((entry) => entry.object.kind === "M6_WORKER_RESULT")?.classification, "INVALID_MANAGED_RECORD");
      };
      const invalidInvocation = (patch: Record<string, unknown>): typeof result.invocation => {
        const { content_sha256: _contentSha256, ...body } = structuredClone(result.invocation) as Record<string, unknown>;
        return identifyContractDocument("pi_gacw_m6_worker_invocation_v0", { ...body, ...patch }) as typeof result.invocation;
      };
      const assertInvalidInvocation = (candidate: typeof result.invocation): void => {
        const classifications = classifyM6Authority({
          runId: fixture.runId,
          objects: [
            { kind: "M6_WORKER_INVOCATION", contentSha256: candidate.content_sha256 as Sha256Digest, relativePath: "records/m6-worker-invocations/invocation.json" },
            { kind: "M6_WORKER_RESULT", contentSha256: result.result.content_sha256 as Sha256Digest, relativePath: "records/m6-worker-results/result.json" },
          ],
          invocations: new Map([[candidate.content_sha256, candidate]]),
          results: new Map([[result.result.content_sha256, result.result]]),
        });
        assert.equal(classifications.find((entry) => entry.object.kind === "M6_WORKER_INVOCATION")?.classification, "INVALID_MANAGED_RECORD");
      };
      const changedModules = (index: number, patch: Record<string, unknown>): readonly Record<string, unknown>[] => result.invocation.pi_modules.map((module, moduleIndex) => moduleIndex === index ? { ...module, ...patch } : { ...module });
      assertInvalidInvocation(invalidInvocation({ pi_modules: changedModules(1, { package_version: "0.82.0" }) }));
      assertInvalidInvocation(invalidInvocation({ pi_modules: changedModules(1, { registry_integrity: "sha512-substituted" }) }));
      assertInvalidInvocation(invalidInvocation({ pi_modules: changedModules(1, { installed_tree_sha256: digest(991) }) }));
      assertInvalidInvocation(invalidInvocation({ pi_modules: changedModules(2, { specifier: "@earendil-works/pi-ai" }) }));
      assertInvalidInvocation(invalidInvocation({ pi_modules: changedModules(1, { resolved_url: "file:///wrong.js" }) }));
      assertInvalid(invalidResult({ outcome: "BLOCKED", first_failure_code: "UNKNOWN_FAILURE", first_failure_stage: "PROTOCOL" }));
      assertInvalid(invalidResult({ first_failure_code: "AUTHORITY_REJECTED", first_failure_stage: "FORGED" }));
      assertInvalid(invalidResult({ outcome: "BLOCKED", first_failure_code: null, first_failure_stage: null }));
      assertInvalid(invalidResult({ provider_work_started: false, outcome: "BLOCKED", first_failure_code: "WORKER_ABORTED", first_failure_stage: "ABORT", usage: { ...result.result.usage, provider_turns: 1 } }));
      assertInvalid(invalidResult({ usage: { ...result.result.usage, report_submissions: 0 } }));
      assertInvalid(invalidResult({ invocation_content_sha256: digest(999) }));
    });
  } finally {
    configurePersistenceTestHooks(undefined);
    configureM6FauxRuntimeForTests(undefined);
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await removeM5R3Fixture(fixture);
  }
});
