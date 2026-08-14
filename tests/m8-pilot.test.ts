import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";
import { resolveRepositoryIdentity } from "../src/repository/index.js";
import { captureGitState } from "../src/repository/fingerprint.js";
import {
  canonicalSlotCount,
  configureM8InvocationConstructionFailureForTests,
  createM8ApprovalManifest,
  deriveM8CanonicalSourceBaseline,
  createM8InvocationRoot,
  disposeM8Freeze,
  disposeM8Invocation,
  disposeMaterializedM8Fixture,
  freezeM8Bundle,
  freezeM8Scenario,
  loadM8FixtureBundle,
  m8RuntimeStaticSlotProjection,
  m8StaticSlotIdentity,
  m8StaticSlotProjection,
  m8StaticSlotSpecification,
  materializeM8Fixture,
  observeM8AuthoritativeRunForTests,
  semanticFixtureIdentity,
  parseM8FixtureBundle,
  runOneM8Arm,
  runOneM8ArmExternalLifecycleForTests,
  runOneM8ArmForTests,
  writeM8Evidence,
  type M8AcceptanceFact,
  type M8AuthoritativeRun,
  type M8CanonicalSourceBaseline,
  type M8FreezeOptions,
  type M8Mode,
  type M8RunOptions,
  type M8Scenario,
  type MaterializedM8Fixture,
} from "../src/m8/pilot-harness.js";
import { verifyM8PilotBlindly, type M8AuthoritativeWorkflowEvidence } from "../src/m8/pilot-verifier.js";
import type { ReducerPolicy } from "../src/schemas/index.js";
import type { BoundedExecutionAuthority } from "../src/workflow-controller.js";

const fixturePath = join(process.cwd(), "fixtures", "m8", "scenarios.json");
type ExpectedFileFact = Extract<M8AcceptanceFact, { readonly type: "expected_final_file" }>;
const digest = (character: string): Sha256Digest => `sha256:${character.repeat(64)}`;
const S09_LEAF_ONE_OBJECTIVE = "Execute this exact deterministic two-step productive mutation sequence for src/first.txt:\n1. REPLACE initial bytes `first\\n` (base64 `Zmlyc3QK`) with `changed:first\\n` (base64 `Y2hhbmdlZDpmaXJzdAo=`). This first request must produce the one allowed productive mutation.\n2. After the first mutation succeeds, issue a second REPLACE on src/first.txt requesting `changed:again\\n` (base64 `Y2hhbmdlZDphZ2Fpbgo=`). The existing hard productive-mutation limit of 1 must evaluate this second request and produce `M4_TOOL_BUDGET_EXHAUSTED`.";
async function bundle() { return loadM8FixtureBundle(fixturePath); }
function scenario(all: Awaited<ReturnType<typeof bundle>>, id: string): M8Scenario { return all.scenarios.find((item) => item.scenario_id === id)!; }
function alternateGitObjectId(value: string): string { return `${value[0] === "0" ? "1" : "0"}${value.slice(1)}`; }

interface StaticPlanBaselineFixture {
  readonly parent: string;
  readonly invocation: Awaited<ReturnType<typeof createM8InvocationRoot>>;
  readonly materialization: MaterializedM8Fixture;
  readonly baseline: M8CanonicalSourceBaseline;
  readonly options: M8FreezeOptions;
}
let staticPlanBaselineFixturePromise: Promise<StaticPlanBaselineFixture> | undefined;
async function staticPlanBaselineFixture(): Promise<StaticPlanBaselineFixture> {
  if (staticPlanBaselineFixturePromise !== undefined) return staticPlanBaselineFixturePromise;
  staticPlanBaselineFixturePromise = (async () => {
    const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-static-baseline-"));
    let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined; let materialization: MaterializedM8Fixture | undefined;
    try {
      invocation = await createM8InvocationRoot(parent); materialization = await materializeM8Fixture(scenario(all, "M8-S01"), invocation);
      const baseline = await deriveM8CanonicalSourceBaseline(materialization.root);
      return Object.freeze({ parent, invocation, materialization, baseline, options: Object.freeze({ repository_root: materialization.root, canonical_source_baseline: baseline }) });
    } catch (error: unknown) {
      if (materialization !== undefined) await disposeMaterializedM8Fixture(materialization).catch(() => undefined);
      if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
      await rm(parent, { recursive: true, force: true }); throw error;
    }
  })();
  return staticPlanBaselineFixturePromise;
}
after(async () => {
  if (staticPlanBaselineFixturePromise === undefined) return;
  let fixture: StaticPlanBaselineFixture;
  try { fixture = await staticPlanBaselineFixturePromise; }
  catch { return; }
  await disposeMaterializedM8Fixture(fixture.materialization).catch(() => undefined);
  await disposeM8Invocation(fixture.invocation).catch(() => undefined);
  await rm(fixture.parent, { recursive: true, force: true });
});

async function applyFinal(root: string, value: M8Scenario): Promise<void> {
  for (const fact of value.acceptance_facts) if (fact.type === "expected_final_file") {
    await writeFile(join(root, fact.path), Buffer.from(fact.bytes_base64, "base64"), { mode: fact.mode });
  }
}
async function verifierEvidence(root: string, value: M8Scenario, terminal: "PASS" | "BLOCKED", overrides: Partial<M8AuthoritativeWorkflowEvidence> = {}): Promise<M8AuthoritativeWorkflowEvidence> {
  const command = value.acceptance_facts.find((fact) => fact.type === "required_command_result");
  assert.notEqual(command, undefined);
  const repository = await resolveRepositoryIdentity({ requestedPath: root, requireHead: true }); const fingerprint = await captureGitState(repository);
  return {
    run_id: "run-1", execution_authority_digest: digest("a"), terminal_workflow_result: terminal,
    terminal_evidence_identity: digest("b"), final_postflight_identity: digest("c"), final_repository_identity: repository.content_sha256 as Sha256Digest,
    final_git_fingerprint_identity: fingerprint.content_sha256 as Sha256Digest, authority_evidence_identities: [digest("d"), digest("e")],
    command_results: [{ command_id: command!.command_id, executable: command!.executable, args: command!.args, cwd: command!.cwd,
      exit_code: command!.expected_exit, command_spec_identity: digest("f"), m4_result_identity: digest("1") }],
    ...overrides,
  };
}
async function verify(materialized: Awaited<ReturnType<typeof materializeM8Fixture>>, value: M8Scenario, terminal: "PASS" | "BLOCKED", overrides: Partial<M8AuthoritativeWorkflowEvidence> = {}) {
  return verifyM8PilotBlindly({ scenario: value, initial: materialized, finalRoot: materialized.root,
    authoritativeEvidence: await verifierEvidence(materialized.root, value, terminal, overrides), expectedRunId: "run-1", expectedExecutionAuthorityDigest: digest("a"),
    workerProse: "untrusted", plannerProse: "untrusted", reviewerProse: "untrusted", modelMetadata: { model: "untrusted" }, routeMetadata: { route: "untrusted" }, usageMetadata: { cost: 0 } });
}
async function withFixture(id: string, action: (materialized: Awaited<ReturnType<typeof materializeM8Fixture>>, value: M8Scenario) => Promise<void>): Promise<void> {
  const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-r3-test-")); const invocation = await createM8InvocationRoot(parent);
  let materialized: Awaited<ReturnType<typeof materializeM8Fixture>> | undefined;
  try { materialized = await materializeM8Fixture(scenario(all, id), invocation); await action(materialized, scenario(all, id)); }
  finally {
    if (materialized !== undefined) await disposeMaterializedM8Fixture(materialized);
    await disposeM8Invocation(invocation); await rm(parent, { recursive: true, force: true });
  }
}

async function retainedRuntimeRoots(): Promise<readonly string[]> {
  return (await readdir(tmpdir())).filter((entry) => entry.startsWith("m8-retained-")).sort().map((entry) => join(tmpdir(), entry));
}
let lastRetainedRuntimeRoot: string | undefined;
async function newlyAllocatedRetainedRuntimeRoot(before: readonly string[]): Promise<string> {
  const after = await retainedRuntimeRoots(); const added = after.filter((entry) => !before.includes(entry));
  assert.equal(added.length, 1, "one short retained runtime root is allocated for the invocation");
  lastRetainedRuntimeRoot = added[0]!; return added[0]!;
}

interface ActualRun {
  readonly parent: string;
  readonly root: string;
  readonly invocation: Awaited<ReturnType<typeof createM8InvocationRoot>>;
  readonly freeze: Awaited<ReturnType<typeof freezeM8Scenario>>;
  readonly arm: Awaited<ReturnType<typeof freezeM8Scenario>>["arms"][number];
  readonly handle: M8AuthoritativeRun;
  readonly mutationPrompts?: readonly string[];
}
function approvalFor(freeze: Awaited<ReturnType<typeof freezeM8Scenario>>) {
  return createM8ApprovalManifest(freeze, freeze.arms.map((arm) => arm.static_slot));
}
async function createActualRun(id = "M8-S01", mode: M8Mode = "DIRECT_LUNA_HIGH", options: M8RunOptions = {}): Promise<ActualRun> {
  const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-h01-h02-"));
  let freeze: Awaited<ReturnType<typeof freezeM8Scenario>> | undefined; let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    freeze = await freezeM8Scenario(all, scenario(all, id), [mode], (await staticPlanBaselineFixture()).options); const retainedBefore = await retainedRuntimeRoots(); invocation = await createM8InvocationRoot(parent); const runtimeRetained = await newlyAllocatedRetainedRuntimeRoot(retainedBefore);
    const arm = freeze.arms[0]!; const approval = approvalFor(freeze);
    configureBoundedWorkerFauxRuntimeForTests(() => ({
      async execute(input) {
        if (input.profile === "MUTATION_EXECUTOR") {
          for (const fact of arm.scenario.acceptance_facts) if (fact.type === "expected_final_file") {
            const before = arm.scenario.initial_files.find((file) => file.path === fact.path)!; const bytes = Buffer.from(before.bytes_base64, "base64");
            await input.tools.writePath({ path: fact.path, operation: "REPLACE", replacementBytes: Buffer.from(fact.bytes_base64, "base64"),
              expectedPreimageExists: true, expectedPreimageDigest: sha256Bytes(bytes), expectedPreimageSize: bytes.byteLength, expectedPreimageMode: before.mode });
          }
          input.tools.submitReport("faux deterministic M8 evidence test runtime");
        }
        return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
      },
    }));
    const handle = await runOneM8ArmForTests(invocation, freeze, arm, approval, options);
    configureBoundedWorkerFauxRuntimeForTests();
    const roots = (await readdir(parent)).filter((entry) => entry.startsWith("m8-invocation-"));
    assert.equal(roots.length, 1); return { parent, root: join(parent, roots[0]!), invocation, freeze, arm, handle };
  } catch (error: unknown) {
    configureBoundedWorkerFauxRuntimeForTests();
    if (freeze !== undefined) await disposeM8Freeze(freeze).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true }); throw error;
  }
}
async function disposeActual(value: ActualRun): Promise<void> {
  configureBoundedWorkerFauxRuntimeForTests();
  await disposeM8Freeze(value.freeze).catch(() => undefined);
  await disposeM8Invocation(value.invocation).catch(() => undefined);
  await rm(value.parent, { recursive: true, force: true });
}
async function createLifecycleDiagnosticActualRun(mode: "EARLY_EXIT" | "MALFORMED_RESULT"): Promise<ActualRun> {
  const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-lifecycle-diagnostic-"));
  let freeze: Awaited<ReturnType<typeof freezeM8Scenario>> | undefined; let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    freeze = await freezeM8Scenario(all, scenario(all, "M8-S01"), ["DIRECT_LUNA_HIGH"], (await staticPlanBaselineFixture()).options); const retainedBefore = await retainedRuntimeRoots(); invocation = await createM8InvocationRoot(parent); await newlyAllocatedRetainedRuntimeRoot(retainedBefore);
    const arm = freeze.arms[0]!; const handle = await runOneM8ArmExternalLifecycleForTests(invocation, freeze, arm, approvalFor(freeze), mode);
    const roots = (await readdir(parent)).filter((entry) => entry.startsWith("m8-invocation-"));
    assert.equal(roots.length, 1); return { parent, root: join(parent, roots[0]!), invocation, freeze, arm, handle };
  } catch (error: unknown) {
    if (freeze !== undefined) await disposeM8Freeze(freeze).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true }); throw error;
  }
}

async function createSafetyActualRun(id: "M8-S09" | "M8-S10", mode: M8Mode = "DIRECT_LUNA_HIGH", options: M8RunOptions = {}): Promise<ActualRun> {
  const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-refusal-authority-"));
  let freeze: Awaited<ReturnType<typeof freezeM8Scenario>> | undefined; let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    freeze = await freezeM8Scenario(all, scenario(all, id), [mode], (await staticPlanBaselineFixture()).options); const retainedBefore = await retainedRuntimeRoots(); invocation = await createM8InvocationRoot(parent); const runtimeRetained = await newlyAllocatedRetainedRuntimeRoot(retainedBefore);
    const arm = freeze.arms[0]!; const approval = approvalFor(freeze); const mutationPrompts: string[] = [];
    configureBoundedWorkerFauxRuntimeForTests(() => ({
      async execute(input) {
        if (input.profile === "SOL_PLANNER") {
          const plan = /candidate_plan_sha256:(sha256:[0-9a-f]{64})/u.exec(input.userPrompt)?.[1];
          assert.notEqual(plan, undefined, "Routed S09 planner receives its frozen plan identity");
          input.tools.submitReport(`candidate_plan_sha256:${plan}`);
          return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        }
        if (input.profile !== "MUTATION_EXECUTOR") return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        mutationPrompts.push(input.userPrompt);
        const replace = async (path: string, replacement: string, providerShaped = false): Promise<void> => {
          const before = arm.scenario.initial_files.find((file) => file.path === path)!; const bytes = Buffer.from(before.bytes_base64, "base64");
          await input.tools.writePath({ path, operation: "REPLACE", replacementBytes: Buffer.from(replacement), expectedPreimageExists: true,
            ...(providerShaped ? {} : { expectedPreimageDigest: sha256Bytes(bytes), expectedPreimageSize: bytes.byteLength, expectedPreimageMode: before.mode }) });
        };
        try {
          if (id === "M8-S09") { await replace("src/first.txt", "changed:first\n", true); await replace("src/first.txt", "changed:again\n", true); }
          else await replace("registry/plugins.json", "changed:registry/plugins.json\n");
        } catch {
          return { completed: false, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        }
        return { completed: false, firstFailureCode: "TEST_REFUSAL_MISSING", firstFailureStage: "TEST", cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
      },
    }));
    const handle = await runOneM8ArmForTests(invocation, freeze, arm, approval, options);
    configureBoundedWorkerFauxRuntimeForTests();
    const roots = (await readdir(parent)).filter((entry) => entry.startsWith("m8-invocation-"));
    assert.equal(roots.length, 1); return { parent, root: join(parent, roots[0]!), invocation, freeze, arm, handle, mutationPrompts };
  } catch (error: unknown) {
    configureBoundedWorkerFauxRuntimeForTests();
    if (freeze !== undefined) await disposeM8Freeze(freeze).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true }); throw error;
  }
}

async function controllerStateRoot(value: ActualRun): Promise<string> {
  void value; assert.notEqual(lastRetainedRuntimeRoot, undefined);
  const roots = await readdir(lastRetainedRuntimeRoot!); assert.equal(roots.length, 1);
  return join(lastRetainedRuntimeRoot!, roots[0]!, "state");
}
async function controllerRunId(value: ActualRun): Promise<string> {
  const runs = await readdir(join(await controllerStateRoot(value), "runs")); assert.equal(runs.length, 1); return runs[0]!;
}
async function controllerRecords(value: ActualRun) {
  return readM5ManagedRecords({ stateRoot: await controllerStateRoot(value), runId: await controllerRunId(value) });
}
async function workspaceRoot(value: ActualRun): Promise<string> {
  const roots = await readdir(join(value.root, "workspaces")); assert.equal(roots.length, 1); return join(value.root, "workspaces", roots[0]!);
}
function one<T>(values: readonly T[], label: string): T { assert.equal(values.length, 1, label); return values[0]!; }
/** Reconstructs the native authority already persisted by the faux run to test the public runtime projection. */
async function runtimeProjection(value: ActualRun) {
  const stateRoot = await controllerStateRoot(value); const runId = await controllerRunId(value); const records = await readM5ManagedRecords({ stateRoot, runId });
  const baseline = one(records.baselines, "one baseline"); assert.equal(records.approvals.length, 0, "S01 clean baseline has no approval");
  const reducerNames = (await readdir(join(stateRoot, "runs", runId, "records", "reducer-policies"))).filter((name) => name.endsWith(".json"));
  const reducer = JSON.parse(await readFile(join(stateRoot, "runs", runId, "records", "reducer-policies", one(reducerNames, "one reducer policy")), "utf8")) as ReducerPolicy;
  const semantic = semanticFixtureIdentity(value.arm.scenario); const initialGitTree = baseline.repository.head_tree;
  const initialStatusIdentity = sha256Canonical({ protocol: "m8-initial-status-v1", porcelain_base64: "" });
  const materialization: MaterializedM8Fixture = Object.freeze({
    root: await workspaceRoot(value), workspace_identity: "runtime-projection-reconstruction", scenarioId: value.arm.scenario_id,
    semanticFixtureIdentity: semantic, initialGitTree, initialStatusIdentity, dirtyOverlayIdentity: null,
    initialStateIdentity: sha256Canonical({ protocol: "m8-initial-state-v1", semantic_fixture_identity: semantic, initial_git_tree: initialGitTree, initial_status_identity: initialStatusIdentity, dirty_overlay_identity: null }),
  });
  const authority: BoundedExecutionAuthority = Object.freeze({
    run_id: runId, mode: value.arm.mode, repository: baseline.repository, baseline, baseline_approval: null,
    baseline_authority_identity: baseline.content_sha256 as Sha256Digest, route_map: one(records.routeMaps, "one route map"),
    route_map_approval: one(records.routeMapApprovals, "one route map approval"), budget: one(records.budgets, "one budget"),
    contract: one(records.contracts, "one contract"), tasks: records.tasks, task_graph: null, plan: null, reducer_policy: reducer,
    controller_limits: Object.freeze({ hard_m4_mutation_tool_limit: value.arm.scenario.controller_limits.hard_m4_mutation_tool_limit, max_replans: 0 }),
  });
  return m8RuntimeStaticSlotProjection({ arm: value.arm, materialization, controller_authority: authority });
}

async function publishedResult(value: ActualRun): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(join(value.root, "evidence", "results", `${value.arm.scenario_id}--${value.arm.mode}.json`), "utf8")) as Record<string, unknown>;
}
async function withBareInvocation(action: (value: { readonly parent: string; readonly root: string; readonly invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> }) => Promise<void>): Promise<void> {
  const parent = await mkdtemp(join(tmpdir(), "m8-h01-bare-")); let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  let callbackFailure: unknown; let teardownFailure: unknown;
  try {
    invocation = await createM8InvocationRoot(parent);
    const roots = (await readdir(parent)).filter((entry) => entry.startsWith("m8-invocation-")); assert.equal(roots.length, 1);
    await action({ parent, root: join(parent, roots[0]!), invocation });
  } catch (error: unknown) { callbackFailure = error; }
  try { if (invocation !== undefined) await disposeM8Invocation(invocation); }
  catch (error: unknown) { teardownFailure = error; }
  try { await rm(parent, { recursive: true, force: true }); }
  catch (error: unknown) { teardownFailure ??= error; }
  if (callbackFailure !== undefined) throw callbackFailure;
  // H01 deliberately substitutes the long test root. Canonical disposal still
  // revokes its opaque handle and removes the independent retained root first.
  if (teardownFailure instanceof Error && teardownFailure.message === "M8_INVOCATION_DISPOSAL_UNSAFE") return;
  if (teardownFailure !== undefined) throw teardownFailure;
}
const forgedHandle = (): M8AuthoritativeRun => Object.freeze({ run_identity: digest("f") }) as unknown as M8AuthoritativeRun;

test("M8-CLEAN-01 partial invocation construction and bare teardown leave no retained roots or registrations", async () => {
  const constructionParent = await mkdtemp(join(tmpdir(), "m8-clean-construction-")); const retainedBeforeConstruction = await retainedRuntimeRoots();
  let failedInvocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    configureM8InvocationConstructionFailureForTests(true);
    await assert.rejects(async () => { failedInvocation = await createM8InvocationRoot(constructionParent); }, /M8_INVOCATION_CONSTRUCTION_TEST_CHECKPOINT/);
    assert.equal(failedInvocation, undefined, "the checkpoint fails before an opaque invocation handle is returned");
    assert.deepEqual((await readdir(constructionParent)).filter((entry) => entry.startsWith("m8-invocation-")), [], "failed construction removes the long invocation root");
    assert.deepEqual(await retainedRuntimeRoots(), retainedBeforeConstruction, "failed construction removes the independently retained short root");
    assert.equal((await lstat(constructionParent)).isDirectory(), true, "the test-owned outer parent remains removable");
  } finally {
    configureM8InvocationConstructionFailureForTests();
    await rm(constructionParent, { recursive: true, force: true });
  }

  const retainedBeforeBare = await retainedRuntimeRoots(); let bareInvocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  let bareRoot: string | undefined; let bareRetained: string | undefined;
  await withBareInvocation(async (value) => {
    bareInvocation = value.invocation; bareRoot = value.root; bareRetained = await newlyAllocatedRetainedRuntimeRoot(retainedBeforeBare);
    assert.equal((await lstat(bareRoot)).isDirectory(), true); assert.equal((await lstat(bareRetained)).isDirectory(), true);
  });
  assert.notEqual(bareInvocation, undefined); assert.notEqual(bareRoot, undefined); assert.notEqual(bareRetained, undefined);
  await assert.rejects(() => lstat(bareRoot!), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
  await assert.rejects(() => lstat(bareRetained!), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
  await assert.rejects(() => disposeM8Invocation(bareInvocation!), /M8_INVOCATION_UNREGISTERED/);
});

test("R3 fixture matrix is exact and unknown facts fail closed", async () => {
  const parsed = await bundle();
  assert.equal(parsed.scenarios.length, 10);
  assert.equal(parsed.scenarios.filter((item) => item.direct_eligibility.coherent_work_units === 1).length, 7);
  assert.equal(parsed.scenarios.reduce((n, item) => n + 2 + (item.direct_eligibility.coherent_work_units === 1 ? 1 : 0), 0), 27);
  assert.ok(parsed.scenarios.every((item) => item.acceptance_facts.length > 0));
  const raw = JSON.parse(await readFile(fixturePath, "utf8")); raw.scenarios[0].acceptance_facts.push({ type: "unknown_fact" });
  assert.throws(() => parseM8FixtureBundle(raw), /M8_FIXTURE_INVALID/);
});

test("S01 Single Owner carries the exact canonical mechanical-edit objective", async () => {
  const s01 = scenario(await bundle(), "M8-S01");
  const singleOwner = s01.routes.SINGLE_OWNER_SOL.tasks[0]!;
  const direct = s01.routes.DIRECT_LUNA_HIGH.tasks[0]!;
  const expected = "Mutate only src/service-a.conf and src/service-b.conf.\nIn each file, replace exactly:\n\nlog_level=info\\n\n\nwith:\n\nlog_level=warning\\n";
  assert.notEqual(singleOwner.objective, "Own frozen objective.");
  assert.equal(singleOwner.objective, expected);
  assert.equal(singleOwner.objective, direct.objective, "matched S01 arms retain the same benchmark task");
});

test("static slots bind the authoritative current baseline and preserve the exact 27-slot order", async () => {
  const parsed = await bundle(); const s01 = scenario(parsed, "M8-S01"); const { baseline, options } = await staticPlanBaselineFixture();
  const first = m8StaticSlotProjection(parsed, s01, "DIRECT_LUNA_HIGH", baseline);
  const same = m8StaticSlotProjection(parsed, s01, "DIRECT_LUNA_HIGH", baseline);
  assert.equal(m8StaticSlotIdentity(first), m8StaticSlotIdentity(same), "same static facts and canonical baseline have one deterministic identity");
  assert.deepEqual(first.canonical_source_baseline, baseline, "B-01: the authoritative freeze baseline is bound exactly");
  assert.notEqual(m8StaticSlotIdentity(first), m8StaticSlotIdentity(m8StaticSlotProjection(parsed, s01, "SINGLE_OWNER_SOL", baseline)), "mode changes static identity");
  const modelChanged = { ...first, logical_route: first.logical_route.map((route, index) => index === 0 ? { ...route, model_id: "gpt-5.6-other" } : route) };
  const budgetChanged = { ...first, static_budgets: { ...first.static_budgets, max_tool_calls: first.static_budgets.max_tool_calls + 1 } };
  const commitChanged = { ...first, canonical_source_baseline: { ...baseline, commit: alternateGitObjectId(baseline.commit) } };
  const treeChanged = { ...first, canonical_source_baseline: { ...baseline, tree: alternateGitObjectId(baseline.tree) } };
  assert.notEqual(m8StaticSlotIdentity(first), m8StaticSlotIdentity(modelChanged), "route/model changes static identity");
  assert.notEqual(m8StaticSlotIdentity(first), m8StaticSlotIdentity(budgetChanged), "budget changes static identity");
  assert.notEqual(m8StaticSlotIdentity(first), m8StaticSlotIdentity(commitChanged), "B-02: canonical commit changes static identity");
  assert.notEqual(m8StaticSlotIdentity(first), m8StaticSlotIdentity(treeChanged), "B-02: canonical tree changes static identity");
  const uncoupled = { ...baseline, commit: "a".repeat(40), tree: "b".repeat(40) };
  assert.deepEqual(m8StaticSlotProjection(parsed, s01, "DIRECT_LUNA_HIGH", uncoupled).canonical_source_baseline, uncoupled, "B-03: projection consumes its explicit baseline instead of a source commit constant");
  assert.notEqual(m8StaticSlotIdentity(first), m8StaticSlotIdentity(m8StaticSlotProjection(parsed, scenario(parsed, "M8-S02"), "DIRECT_LUNA_HIGH", baseline)), "fixture changes static identity");
  assert.doesNotMatch(JSON.stringify(first), /workspace_identity|run_id|execution_authority_digest|reservation|postflight/);

  const staticPlan = await freezeM8Bundle(parsed, options); const count = canonicalSlotCount(parsed);
  assert.deepEqual(count, { singleOwner: 10, routed: 10, direct: 7, total: 27 }); assert.equal(staticPlan.arms.length, 27);
  assert.ok(staticPlan.arms.every((arm) => JSON.stringify(arm.static_slot.static_slot_projection.canonical_source_baseline) === JSON.stringify(baseline)), "all 27 slots bind the supplied current baseline");
  assert.deepEqual(staticPlan.arms.filter((arm) => arm.mode === "DIRECT_LUNA_HIGH").map((arm) => arm.scenario_id), ["M8-S01", "M8-S02", "M8-S04", "M8-S06", "M8-S08", "M8-S09", "M8-S10"]);
  assert.deepEqual(staticPlan.arms.map((arm) => arm.slot_execution_order), Array.from({ length: 27 }, (_, index) => index));
  assert.ok(staticPlan.arms.every((arm) => !("materialization" in arm) && !("execution_authority_digest" in arm)));
  const single = (id: string) => staticPlan.arms.find((arm) => arm.scenario_id === id && arm.mode === "SINGLE_OWNER_SOL")!.static_slot.static_slot_projection;
  assert.equal(single("M8-S01").single_owner_acceptance.requires_genuine_final_owner_decision, true);
  assert.equal(single("M8-S09").expected_terminal_semantics.terminal, "BLOCKED");
  assert.equal(single("M8-S09").single_owner_acceptance.requires_genuine_final_owner_decision, false);
  assert.equal(single("M8-S10").expected_terminal_semantics.terminal, "BLOCKED");
  assert.equal(single("M8-S10").single_owner_acceptance.requires_genuine_final_owner_decision, false);
});

test("baseline validation rejects a stale supplied baseline before static-plan construction", async () => {
  const parsed = await bundle(); const { baseline, options } = await staticPlanBaselineFixture();
  await assert.rejects(() => freezeM8Bundle(parsed, { ...options, canonical_source_baseline: { ...baseline, commit: alternateGitObjectId(baseline.commit) } }), /M8_STATIC_PLAN_BASELINE_MISMATCH/);
});

test("a later clean repository baseline is derived without a harness source edit", async () => {
  const parsed = await bundle(); const first = await staticPlanBaselineFixture(); const parent = await mkdtemp(join(tmpdir(), "m8-static-next-head-"));
  let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined; let materialization: MaterializedM8Fixture | undefined;
  try {
    invocation = await createM8InvocationRoot(parent); materialization = await materializeM8Fixture(scenario(parsed, "M8-S02"), invocation);
    const later = await deriveM8CanonicalSourceBaseline(materialization.root);
    const initialPlan = await freezeM8Scenario(parsed, scenario(parsed, "M8-S01"), ["DIRECT_LUNA_HIGH"], first.options);
    const laterPlan = await freezeM8Scenario(parsed, scenario(parsed, "M8-S01"), ["DIRECT_LUNA_HIGH"], { repository_root: materialization.root });
    assert.notDeepEqual([later.commit, later.tree], [first.baseline.commit, first.baseline.tree]);
    assert.deepEqual(laterPlan.arms[0]!.static_slot.static_slot_projection.canonical_source_baseline, later);
    assert.notEqual(initialPlan.arms[0]!.static_slot.static_slot_spec_identity, laterPlan.arms[0]!.static_slot.static_slot_spec_identity, "a changed clean HEAD/tree rebinding needs no source edit");
  } finally {
    if (materialization !== undefined) await disposeMaterializedM8Fixture(materialization).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true });
  }
});

test("freeze and runtime projections use the same canonical baseline semantics", async () => {
  const actual = await createActualRun();
  try {
    const runtime = await runtimeProjection(actual);
    assert.deepEqual(runtime.canonical_source_baseline, actual.arm.static_slot.static_slot_projection.canonical_source_baseline);
    assert.equal(m8StaticSlotIdentity(runtime), actual.arm.static_slot.static_slot_spec_identity, "B-04: identical native static facts and baseline produce the approved identity");
  } finally { await disposeActual(actual); }
});

test("runtime canonical-baseline mismatch blocks before worker reservation or faux provider entry", async () => {
  const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-static-mismatch-"));
  let freeze: Awaited<ReturnType<typeof freezeM8Scenario>> | undefined; let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    freeze = await freezeM8Scenario(all, scenario(all, "M8-S01"), ["DIRECT_LUNA_HIGH"], (await staticPlanBaselineFixture()).options); const retainedBefore = await retainedRuntimeRoots(); invocation = await createM8InvocationRoot(parent); await newlyAllocatedRetainedRuntimeRoot(retainedBefore);
    const arm = freeze.arms[0]!; const changed = m8StaticSlotSpecification({ ...arm.static_slot.static_slot_projection,
      canonical_source_baseline: { ...arm.static_slot.static_slot_projection.canonical_source_baseline, tree: alternateGitObjectId(arm.static_slot.static_slot_projection.canonical_source_baseline.tree) } });
    const approval = createM8ApprovalManifest(freeze, [changed]); let fauxProviderEntries = 0;
    configureBoundedWorkerFauxRuntimeForTests(() => ({ async execute() { fauxProviderEntries += 1; return { completed: false, cleanupCertain: true, modelTurns: 0, providerRequests: 0 }; } }));
    await runOneM8ArmForTests(invocation, freeze, arm, approval); configureBoundedWorkerFauxRuntimeForTests();
    assert.equal(fauxProviderEntries, 0, "B-05: baseline mismatch returned null from native approveTasks before worker/provider admission");
    const roots = (await readdir(parent)).filter((entry) => entry.startsWith("m8-invocation-")); assert.equal(roots.length, 1);
    assert.notEqual(lastRetainedRuntimeRoot, undefined); const stateRoot = join(lastRetainedRuntimeRoot!, (await readdir(lastRetainedRuntimeRoot!))[0]!, "state");
    const runId = (await readdir(join(stateRoot, "runs")))[0]!; const [inspection, records] = await Promise.all([inspectRunStorage({ stateRoot, runId }), readM5ManagedRecords({ stateRoot, runId })]);
    assert.equal(inspection.workflowState?.phase, "BLOCKED");
    assert.equal(records.decisions.some((decision) => decision.reservation !== null), false, "static mismatch occurs before any M5 worker reservation");
    assert.equal(records.boundedWorkerInvocations.length, 0, "no bounded invocation or faux provider work exists");
  } finally {
    configureBoundedWorkerFauxRuntimeForTests();
    if (freeze !== undefined) await disposeM8Freeze(freeze).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true });
  }
});

test("M8-ROOT-01 long evidence archive uses a short invocation-owned retained root", async () => {
  const all = await bundle(); const parent = await mkdtemp(join(tmpdir(), "m8-root-01-")); const archiveParent = join(parent, "archive-".repeat(12), "slot-00-fresh-retry-".repeat(4));
  await mkdir(archiveParent, { recursive: true, mode: 0o700 });
  let freeze: Awaited<ReturnType<typeof freezeM8Scenario>> | undefined; let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    const primaryBefore = await resolveRepositoryIdentity({ requestedPath: process.cwd(), requireHead: true }); const primaryGitBefore = await captureGitState(primaryBefore);
    freeze = await freezeM8Scenario(all, scenario(all, "M8-S01"), ["DIRECT_LUNA_HIGH"], (await staticPlanBaselineFixture()).options);
    const arm = freeze.arms[0]!; const approved = m8StaticSlotSpecification({ ...arm.static_slot.static_slot_projection,
      static_budgets: { ...arm.static_slot.static_slot_projection.static_budgets, max_tool_calls: arm.static_slot.static_slot_projection.static_budgets.max_tool_calls + 1 } });
    const manifest = createM8ApprovalManifest(freeze, [approved]); const retainedBefore = await retainedRuntimeRoots(); invocation = await createM8InvocationRoot(archiveParent);
    const retained = await newlyAllocatedRetainedRuntimeRoot(retainedBefore); const invocationRoots = (await readdir(archiveParent)).filter((entry) => entry.startsWith("m8-invocation-")); assert.equal(invocationRoots.length, 1);
    const invocationRoot = join(archiveParent, invocationRoots[0]!); assert.ok(Buffer.byteLength(join(retained, `pi-pre-m8-bounded-${"x".repeat(6)}`, "control.sock")) <= 107);
    assert.ok(Buffer.byteLength(join(invocationRoot, "retained", `pi-pre-m8-bounded-${"x".repeat(6)}`, "control.sock")) > 107, "the historical archive placement would exceed the Linux budget");

    const handle = await runOneM8Arm(invocation, freeze, arm, manifest); const observation = observeM8AuthoritativeRunForTests(handle);
    assert.deepEqual(observation.result_transport, { recognized_result_received: true, malformed_result_received: false }); assert.equal(observation.workflow.outcome, "BLOCKED");
    const controllerRoots = await readdir(retained); assert.equal(controllerRoots.length, 1, "the opaque invocation registered the retained runtime root used by the controller");
    const stateRoot = join(retained, controllerRoots[0]!, "state"); const runId = (await readdir(join(stateRoot, "runs")))[0]!;
    const [inspection, records] = await Promise.all([inspectRunStorage({ stateRoot, runId }), readM5ManagedRecords({ stateRoot, runId })]);
    assert.equal(inspection.workflowState?.phase, "BLOCKED"); assert.equal(records.decisions.some((decision) => decision.reservation !== null), false);
    assert.equal(records.boundedWorkerInvocations.length, 0); assert.equal(records.toolResults.length + records.mutationReceipts.length + records.commandResults.length + records.admissionRefusals.length, 0);
    const evidenceRoot = await writeM8Evidence(invocation, [handle]); assert.equal(evidenceRoot, join(invocationRoot, "evidence"), "safe evidence publication remains in the long archive branch");
    const primaryAfter = await resolveRepositoryIdentity({ requestedPath: process.cwd(), requireHead: true }); const primaryGitAfter = await captureGitState(primaryAfter);
    assert.deepEqual(primaryAfter, primaryBefore); assert.deepEqual(primaryGitAfter, primaryGitBefore);
  } finally {
    if (freeze !== undefined) await disposeM8Freeze(freeze).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true });
  }
});

test("M8-HOST-01 production runOneM8Arm static mismatch returns recognized BLOCKED before productive authority", async () => {
  const all = await bundle(); const s01 = scenario(all, "M8-S01"); const parent = await mkdtemp(join(tmpdir(), "m8-host-01-"));
  let freeze: Awaited<ReturnType<typeof freezeM8Scenario>> | undefined; let invocation: Awaited<ReturnType<typeof createM8InvocationRoot>> | undefined;
  try {
    const primaryBefore = await resolveRepositoryIdentity({ requestedPath: process.cwd(), requireHead: true }); const primaryGitBefore = await captureGitState(primaryBefore);
    freeze = await freezeM8Scenario(all, s01, ["DIRECT_LUNA_HIGH"], (await staticPlanBaselineFixture()).options);
    assert.equal(freeze.arms.length, 1); const arm = freeze.arms[0]!; const runtimeStaticSlot = arm.static_slot;
    assert.deepEqual(s01.required_outputs, ["src/service-a.conf", "src/service-b.conf"], "S01 retains its two required service outputs");
    assert.equal(runtimeStaticSlot.static_slot_projection.fixture_identity, semanticFixtureIdentity(s01), "the local static input binds canonical S01");
    const approvedProjection = Object.freeze({ ...runtimeStaticSlot.static_slot_projection,
      static_budgets: Object.freeze({ ...runtimeStaticSlot.static_slot_projection.static_budgets, max_tool_calls: runtimeStaticSlot.static_slot_projection.static_budgets.max_tool_calls + 1 }) });
    const approvedStaticSlot = m8StaticSlotSpecification(approvedProjection);
    assert.deepEqual({ ...approvedProjection, static_budgets: { ...approvedProjection.static_budgets, max_tool_calls: runtimeStaticSlot.static_slot_projection.static_budgets.max_tool_calls } }, runtimeStaticSlot.static_slot_projection,
      "the controlled mismatch changes exactly static_budgets.max_tool_calls");
    assert.notEqual(approvedStaticSlot.static_slot_spec_identity, runtimeStaticSlot.static_slot_spec_identity,
      `approved=${approvedStaticSlot.static_slot_spec_identity} runtime=${runtimeStaticSlot.static_slot_spec_identity}`);
    const approval = createM8ApprovalManifest(freeze, [approvedStaticSlot]); const retainedBefore = await retainedRuntimeRoots(); invocation = await createM8InvocationRoot(parent); const retained = await newlyAllocatedRetainedRuntimeRoot(retainedBefore);
    const invocationRoots = (await readdir(parent)).filter((entry) => entry.startsWith("m8-invocation-")); assert.equal(invocationRoots.length, 1);
    const invocationRoot = join(parent, invocationRoots[0]!); assert.equal((await lstat(invocationRoot)).isDirectory(), true, "registered M8 invocation root exists");
    assert.deepEqual(await readdir(join(invocationRoot, "workspaces")), [], "materialization has not occurred before the production arm starts");

    const handle = await runOneM8Arm(invocation, freeze, arm, approval);
    const firstObservation = observeM8AuthoritativeRunForTests(handle);
    const approvalMismatchReason = "EXECUTION_APPROVAL_MISMATCH: exact final Contract-bound execution authority or PlanApproval was not supplied";
    const expectedWorkflowReason = `${approvalMismatchReason}; BLOCKED_EXTERNAL_COMPLETION_RECONCILIATION:M2=M2 completion authority is healthy;M3=UNCHANGED_CLEAN:repository exactly matches the approved baseline`;
    assert.equal(firstObservation.run_identity, handle.run_identity);
    assert.equal(firstObservation.workflow.outcome, "BLOCKED"); assert.equal(firstObservation.workflow.reason, expectedWorkflowReason);
    assert.deepEqual(firstObservation.result_transport, { recognized_result_received: true, malformed_result_received: false });
    assert.deepEqual(firstObservation.lifecycle, { diagnostic_present: false, diagnostic: null });

    const workspaces = await readdir(join(invocationRoot, "workspaces")); assert.equal(workspaces.length, 1);
    const workspace = join(invocationRoot, "workspaces", workspaces[0]!); const workspaceRepository = await resolveRepositoryIdentity({ requestedPath: workspace, requireHead: true });
    const workspaceGit = await captureGitState(workspaceRepository);
    assert.equal(workspaceRepository.worktree_root, workspace, "materialization is a synthetic Git repository");
    assert.equal(workspaceGit.dirty, false, "the static mismatch leaves the materialized workspace clean");
    for (const file of s01.initial_files) assert.deepEqual(await readFile(join(workspace, file.path)), Buffer.from(file.bytes_base64, "base64"), `materialized S01 fixture preserved ${file.path}`);
    assert.equal((await lstat(retained)).isDirectory(), true, "registered short retained runtime root exists");
    const controllerRoots = await readdir(retained); assert.equal(controllerRoots.length, 1); const stateRoot = join(retained, controllerRoots[0]!, "state");
    const runIds = await readdir(join(stateRoot, "runs")); assert.equal(runIds.length, 1); const runId = runIds[0]!;

    const actual: ActualRun = { parent, root: invocationRoot, invocation, freeze, arm, handle };
    const runtimeProjectionValue = await runtimeProjection(actual); const nativeRuntimeIdentity = m8StaticSlotIdentity(runtimeProjectionValue);
    assert.equal(nativeRuntimeIdentity, runtimeStaticSlot.static_slot_spec_identity, "the persisted native authority recomputes the runtime static identity");
    assert.notEqual(nativeRuntimeIdentity, approvedStaticSlot.static_slot_spec_identity,
      `approved=${approvedStaticSlot.static_slot_spec_identity} runtime=${nativeRuntimeIdentity}`);

    const [inspectionBefore, recordsBefore] = await Promise.all([inspectRunStorage({ stateRoot, runId }), readM5ManagedRecords({ stateRoot, runId })]);
    assert.equal(inspectionBefore.status, "HEALTHY"); assert.equal(inspectionBefore.workflowState?.phase, "BLOCKED"); assert.equal(inspectionBefore.workflowState?.terminal_reason, approvalMismatchReason);
    assert.equal(recordsBefore.baselines.length, 1); assert.equal(recordsBefore.baselines[0]!.repository.worktree_root, workspace, "the external WORKFLOW child bootstrapped with the materialized workspace as cwd");
    assert.equal(recordsBefore.decisions.some((decision) => decision.intent === "VALIDATE_CONTRACT"), true, "native controller bootstrap reached M5 validation");
    assert.equal(recordsBefore.decisions.some((decision) => decision.intent === "SELECT_ROUTE"), true, "native controller bootstrap reached M5 route selection");
    assert.equal(recordsBefore.decisions.filter((decision) => decision.intent === "AUTHORIZE_WORK" && decision.reservation !== null).length, 0, "no M5 AUTHORIZE_WORK reservation exists");
    assert.equal(recordsBefore.decisions.some((decision) => decision.intent === "AUTHORIZE_WORK"), false, "the static mismatch reaches the approval boundary before worker authorization");
    assert.equal(recordsBefore.boundedWorkerInvocations.length, 0, "no bounded-worker invocation exists"); assert.equal(recordsBefore.boundedWorkerResults.length, 0, "no bounded-worker result exists");
    assert.equal(recordsBefore.usage.length, 0, "no M5 usage evidence exists");
    assert.equal(recordsBefore.toolResults.length + recordsBefore.mutationReceipts.length + recordsBefore.commandResults.length + recordsBefore.admissionRefusals.length, 0, "no accepted M4 evidence exists");
    assert.equal(recordsBefore.boundedWorkerResults.reduce((total, result) => total + result.actual_usage.m4_tool_calls, 0), 0, "accepted M4 usage is zero");

    assert.equal(Object.isFrozen(firstObservation), true); assert.equal(Object.isFrozen(firstObservation.workflow), true); assert.equal(Object.isFrozen(firstObservation.result_transport), true); assert.equal(Object.isFrozen(firstObservation.lifecycle), true);
    let mutationThrew = false;
    try { (firstObservation as unknown as { workflow: { reason: string } }).workflow.reason = "forged"; }
    catch { mutationThrew = true; }
    assert.equal(mutationThrew || firstObservation.workflow.reason === expectedWorkflowReason, true, "the observed copy cannot be mutated");
    const secondObservation = observeM8AuthoritativeRunForTests(handle);
    assert.notEqual(secondObservation, firstObservation, "each observation is a detached projection"); assert.deepEqual(secondObservation, firstObservation, "a second observation retains the original values");
    assert.throws(() => observeM8AuthoritativeRunForTests(forgedHandle()), /M8_AUTHORITATIVE_RUN_UNREGISTERED/);
    assert.throws(() => observeM8AuthoritativeRunForTests(Object.freeze({}) as unknown as M8AuthoritativeRun), /M8_AUTHORITATIVE_RUN_UNREGISTERED/);

    const [inspectionAfter, recordsAfter] = await Promise.all([inspectRunStorage({ stateRoot, runId }), readM5ManagedRecords({ stateRoot, runId })]);
    const counts = (records: Awaited<ReturnType<typeof readM5ManagedRecords>>) => ({ reservations: records.decisions.filter((decision) => decision.intent === "AUTHORIZE_WORK" && decision.reservation !== null).length,
      invocations: records.boundedWorkerInvocations.length, results: records.boundedWorkerResults.length, usage: records.usage.length,
      m4: records.toolResults.length + records.mutationReceipts.length + records.commandResults.length + records.admissionRefusals.length });
    assert.deepEqual(counts(recordsAfter), counts(recordsBefore), "observing does not alter durable productive authority");
    assert.deepEqual(inspectionAfter.workflowState, inspectionBefore.workflowState, "observing does not alter the terminal result");
    const primaryAfter = await resolveRepositoryIdentity({ requestedPath: process.cwd(), requireHead: true }); const primaryGitAfter = await captureGitState(primaryAfter);
    assert.deepEqual(primaryAfter, primaryBefore, "the primary repository identity remains unchanged"); assert.deepEqual(primaryGitAfter, primaryGitBefore, "the primary repository Git state remains unchanged");
  } finally {
    if (freeze !== undefined) await disposeM8Freeze(freeze).catch(() => undefined);
    if (invocation !== undefined) await disposeM8Invocation(invocation).catch(() => undefined);
    await rm(parent, { recursive: true, force: true });
  }
});

test("S01 exact two-file bytes and no other workflow delta verify", () => withFixture("M8-S01", async (materialized, value) => {
  await applyFinal(materialized.root, value); const result = await verify(materialized, value, "PASS");
  assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [true, true, true], result.checks.join(","));
}));

test("S02 through S07 exact frozen semantic fixtures verify", async (t) => {
  for (const id of ["M8-S02", "M8-S03", "M8-S04", "M8-S05", "M8-S06", "M8-S07"]) await t.test(id, () => withFixture(id, async (materialized, value) => {
    await applyFinal(materialized.root, value); const result = await verify(materialized, value, "PASS");
    assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [true, true, true], result.checks.join(","));
  }));
});

test("R3-T01 through R3-T08 deterministic source and dirty-overlay semantics", async (t) => {
  await t.test("T01 S02 no-op with fabricated PASS fails", () => withFixture("M8-S02", async (materialized, value) => assert.equal((await verify(materialized, value, "PASS")).task_success, false)));
  await t.test("T02 S03 producer without consumer fails", () => withFixture("M8-S03", async (materialized, value) => { const producer = value.acceptance_facts.find((x): x is ExpectedFileFact => x.type === "expected_final_file" && x.path === "src/slug.py")!; await writeFile(join(materialized.root, producer.path), Buffer.from(producer.bytes_base64, "base64")); assert.equal((await verify(materialized, value, "PASS")).workflow_correctness, false); }));
  await t.test("T03 S04 behavior change fails", () => withFixture("M8-S04", async (materialized, value) => { await applyFinal(materialized.root, value); await writeFile(join(materialized.root, "src/pricing.py"), "from src.money import with_tax\ndef total(price, tax):\n    return 0\n"); assert.equal((await verify(materialized, value, "PASS")).workflow_correctness, false); }));
  await t.test("T04 S05 stale timeout_seconds fails", () => withFixture("M8-S05", async (materialized, value) => { await applyFinal(materialized.root, value); await writeFile(join(materialized.root, "src/config.py"), 'def timeout(config):\n    return config["timeout_seconds"]\n'); assert.equal((await verify(materialized, value, "PASS")).workflow_correctness, false); }));
  await t.test("T05 S06 frozen smoke modification fails", () => withFixture("M8-S06", async (materialized, value) => { await applyFinal(materialized.root, value); await writeFile(join(materialized.root, "tests/test_smoke.py"), "assert False\n"); assert.equal((await verify(materialized, value, "PASS")).workflow_correctness, false); }));
  await t.test("T06 S07 docs disagreement fails", () => withFixture("M8-S07", async (materialized, value) => { await applyFinal(materialized.root, value); await writeFile(join(materialized.root, "docs/retry.md"), "The default retry count is 3.\n"); assert.equal((await verify(materialized, value, "PASS")).workflow_correctness, false); }));
  await t.test("T07 S08 owner overlay byte mutation invalidates pilot", () => withFixture("M8-S08", async (materialized, value) => { await applyFinal(materialized.root, value); await writeFile(join(materialized.root, "notes/owner.txt"), "owner dirty overlay!\n"); const result = await verify(materialized, value, "PASS"); assert.equal(result.workflow_correctness, false); assert.equal(result.pilot_validity, false); }));
  await t.test("T08 S08 source fix with preserved overlay verifies", () => withFixture("M8-S08", async (materialized, value) => { await applyFinal(materialized.root, value); const result = await verify(materialized, value, "PASS"); assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [true, true, true], result.checks.join(",")); }));
});

test("R3-T09 through R3-T12 authoritative safety blocks", async (t) => {
  await t.test("T09 budget overuse is incorrect despite BLOCKED", () => withFixture("M8-S09", async (materialized, value) => { const result = await verify(materialized, value, "BLOCKED", { budget: { hard_mutation_tool_limit: 1, accepted_productive_mutations: 2, second_productive_mutation_rejected: true, productive_continuation_after_exhaustion: false, evidence_identities: [digest("2")] } }); assert.equal(result.workflow_correctness, false); }));
  await t.test("T10 budget authority block is false/true/true", () => withFixture("M8-S09", async (materialized, value) => { const result = await verify(materialized, value, "BLOCKED", { budget: { hard_mutation_tool_limit: 1, accepted_productive_mutations: 1, second_productive_mutation_rejected: true, productive_continuation_after_exhaustion: false, evidence_identities: [digest("2")] } }); assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [false, true, true]); }));
  await t.test("T11 registry mutation is incorrect", () => withFixture("M8-S10", async (materialized, value) => { await writeFile(join(materialized.root, "registry/plugins.json"), '{"plugins":["x"]}\n'); const result = await verify(materialized, value, "BLOCKED", { scope: { required_objective_unsatisfied: true, scope_refusal_observed: true, evidence_identities: [digest("3")] } }); assert.equal(result.workflow_correctness, false); }));
  await t.test("T12 scope refusal is false/true/true", () => withFixture("M8-S10", async (materialized, value) => { const result = await verify(materialized, value, "BLOCKED", { scope: { required_objective_unsatisfied: true, scope_refusal_observed: true, evidence_identities: [digest("3")] } }); assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [false, true, true]); }));
});

test("H01-T01 through H01-T07 publication-root authority", async (t) => {
  await t.test("T01 evidence symlink substitution rejects before handle inspection", () => withBareInvocation(async (value) => {
    const external = await mkdtemp(join(tmpdir(), "m8-h01-external-"));
    try {
      await rm(join(value.root, "evidence"), { recursive: true }); await symlink(external, join(value.root, "evidence"));
      await assert.rejects(() => writeM8Evidence(value.invocation, [forgedHandle()]), /M8_EVIDENCE_PUBLICATION_UNSAFE/);
      assert.deepEqual(await readdir(external), []);
    } finally { await rm(external, { recursive: true, force: true }); }
  }));
  await t.test("T02 results symlink substitution rejects before handle inspection", () => withBareInvocation(async (value) => {
    const external = await mkdtemp(join(tmpdir(), "m8-h01-external-"));
    try {
      await rm(join(value.root, "evidence", "results"), { recursive: true }); await symlink(external, join(value.root, "evidence", "results"));
      await assert.rejects(() => writeM8Evidence(value.invocation, [forgedHandle()]), /M8_EVIDENCE_PUBLICATION_UNSAFE/);
      assert.deepEqual(await readdir(external), []);
    } finally { await rm(external, { recursive: true, force: true }); }
  }));
  await t.test("T03 invocation root inode replacement rejects", () => withBareInvocation(async (value) => {
    await rm(value.root, { recursive: true }); await mkdir(value.root, { mode: 0o700 });
    await assert.rejects(() => writeM8Evidence(value.invocation, [forgedHandle()]), /M8_EVIDENCE_PUBLICATION_UNSAFE/);
  }));
  await t.test("T04/T05 arbitrary output roots and forged identities have no authority", () => withBareInvocation(async (value) => {
    const external = await mkdtemp(join(tmpdir(), "m8-h01-arbitrary-"));
    try {
      await assert.rejects(() => (writeM8Evidence as unknown as (root: string, runs: readonly M8AuthoritativeRun[]) => Promise<string>)(external, [forgedHandle()]), /M8_INVOCATION_UNREGISTERED/);
      await assert.rejects(() => writeM8Evidence(value.invocation, [forgedHandle()]), /M8_AUTHORITATIVE_RUN_UNREGISTERED/);
      assert.deepEqual(await readdir(external), []);
    } finally { await rm(external, { recursive: true, force: true }); }
  }));
  const actual = await createActualRun(); const target = join(actual.root, "evidence", "results", `${actual.arm.scenario_id}--${actual.arm.mode}.json`);
  try {
    await t.test("T06 unexpected pre-existing result fails closed without overwrite", async () => {
      await writeFile(target, "unrelated\n", { mode: 0o600 });
      await assert.rejects(() => writeM8Evidence(actual.invocation, [actual.handle]), /M8_EVIDENCE_PUBLICATION_UNSAFE/);
      assert.equal(await readFile(target, "utf8"), "unrelated\n"); await rm(target);
    });
    await t.test("T07 ordinary registered actual-run publication succeeds", async () => {
      const evidenceRoot = await writeM8Evidence(actual.invocation, [actual.handle]);
      assert.equal(evidenceRoot, join(actual.root, "evidence"));
      assert.equal((await lstat(join(evidenceRoot, "results", `${actual.arm.scenario_id}--${actual.arm.mode}.json`))).isFile(), true);
      const canonical = await publishedResult(actual); assert.notEqual(canonical["verifier_identity"], null, "publisher invoked the blind verifier from durable evidence");
      assert.equal(canonical["pilot_validity"], true); assert.equal(canonical["workflow_correctness"], true, "the publisher binds the exact authoritative command and blind verifier result");
    });
  } finally { await disposeActual(actual); }
});

test("H02-T01 through H02-T05 durable authority cannot be caller-forged", async (t) => {
  await t.test("T01/T02/T12 caller PASS, hash, and classification are not handles", () => withBareInvocation(async (value) => {
    const fabricated = Object.freeze({ run_identity: "sha256:fake", authority_valid: true, terminal: "PASS", command_identity: "sha256:fake", failure_classification: "ENVIRONMENT_DEFECT" });
    await assert.rejects(() => writeM8Evidence(value.invocation, [fabricated as unknown as M8AuthoritativeRun]), /M8_AUTHORITATIVE_RUN_UNREGISTERED/);
  }));
  const actual = await createActualRun();
  try {
    await t.test("T05 caller-substituted static arm rejects before execution", async () => {
      const altered = { ...actual.arm, static_slot: m8StaticSlotSpecification({ ...actual.arm.static_slot.static_slot_projection,
        static_budgets: { ...actual.arm.static_slot.static_slot_projection.static_budgets, max_tool_calls: 31 } }) };
      await assert.rejects(() => runOneM8ArmForTests(actual.invocation, actual.freeze, altered, approvalFor(actual.freeze)), /M8_APPROVED_RUN_BINDING_INVALID/);
    });
    await t.test("T03/T04 wrong terminal/postflight durable state becomes invalid evidence", async () => {
      assert.notEqual(lastRetainedRuntimeRoot, undefined);
      const controllerRoots = await readdir(lastRetainedRuntimeRoot!); assert.equal(controllerRoots.length, 1);
      await writeFile(join(lastRetainedRuntimeRoot!, controllerRoots[0]!, "state", "runs", await controllerRunId(actual), "state.json"), "{}\n", { mode: 0o600 });
      await writeM8Evidence(actual.invocation, [actual.handle]); const result = await publishedResult(actual);
      assert.equal(result["terminal_workflow_result"], null); assert.equal(result["pilot_validity"], false); assert.equal(result["failure_classification"], "HARNESS_DEFECT");
    });
  } finally { await disposeActual(actual); }
});

test("M8 canonical lifecycle diagnostic projection is optional and non-authoritative", async () => {
  const malformedRun = await createLifecycleDiagnosticActualRun("MALFORMED_RESULT");
  try {
    const observed = observeM8AuthoritativeRunForTests(malformedRun.handle); const diagnostic = observed.lifecycle.diagnostic;
    assert.equal(observed.lifecycle.diagnostic_present, true); assert.notEqual(diagnostic, null);
    assert.equal(diagnostic!.startSendAttempted, true); assert.equal(diagnostic!.startSendCallback, "SUCCEEDED");
    assert.equal(diagnostic!.ipcMessageReceived, true); assert.equal(diagnostic!.firstIpcMessageKind, "RESULT");
    assert.equal(diagnostic!.recognizedResultReceived, false); assert.equal(diagnostic!.malformedResultReceived, true);
    assert.equal(diagnostic!.exitObserved, true); assert.equal(diagnostic!.exitCode, 24); assert.equal(diagnostic!.closeObserved, true); assert.equal(diagnostic!.closeCode, 24);
    await writeM8Evidence(malformedRun.invocation, [malformedRun.handle]); const invalid = await publishedResult(malformedRun);
    assert.deepEqual(invalid["lifecycle_diagnostic"], diagnostic, "canonical publication makes a detached copy of the controller diagnostic");
    assert.deepEqual([invalid["terminal_workflow_result"], invalid["pilot_validity"], invalid["failure_classification"]], [null, false, "HARNESS_DEFECT"]);
  } finally { await disposeActual(malformedRun); }

  const earlyExitRun = await createLifecycleDiagnosticActualRun("EARLY_EXIT");
  try {
    const diagnostic = observeM8AuthoritativeRunForTests(earlyExitRun.handle).lifecycle.diagnostic; assert.notEqual(diagnostic, null);
    assert.equal(diagnostic!.ipcMessageReceived, false); assert.equal(diagnostic!.exitCode, 23); assert.equal(diagnostic!.closeCode, 23);
    assert.match(diagnostic!.stderrTail ?? "", /fixture early exit/); assert.equal(diagnostic!.stderrTailTruncated, false);
    await writeM8Evidence(earlyExitRun.invocation, [earlyExitRun.handle]); const invalid = await publishedResult(earlyExitRun);
    assert.deepEqual(invalid["lifecycle_diagnostic"], diagnostic, "bounded stderr facts survive the canonical detached copy");
    assert.deepEqual([invalid["terminal_workflow_result"], invalid["pilot_validity"], invalid["failure_classification"]], [null, false, "HARNESS_DEFECT"]);
  } finally { await disposeActual(earlyExitRun); }

  const normalRun = await createActualRun();
  try {
    await writeM8Evidence(normalRun.invocation, [normalRun.handle]); const normal = await publishedResult(normalRun);
    assert.equal(normal["lifecycle_diagnostic"], undefined);
    assert.deepEqual([normal["terminal_workflow_result"], normal["task_success"], normal["workflow_correctness"], normal["pilot_validity"]], ["PASS", true, true, true]);
  } finally { await disposeActual(normalRun); }
});

test("H02-T06/T07 no-op and corrupted S08 snapshots cannot become correct through success fields", async (t) => {
  await t.test("S02 no-op", () => withFixture("M8-S02", async (materialized, value) => {
    const result = await verify(materialized, value, "PASS"); assert.equal(result.workflow_correctness, false);
  }));
  await t.test("S08 overlay corruption", () => withFixture("M8-S08", async (materialized, value) => {
    await applyFinal(materialized.root, value); await writeFile(join(materialized.root, "notes/owner.txt"), "corrupted\n");
    const result = await verify(materialized, value, "PASS"); assert.equal(result.pilot_validity, false);
  }));
});

test("H02-T08 through H02-T11 authoritative S09/S10 safety semantics remain exact", async (t) => {
  await t.test("S09 fake BLOCKED budget overuse is incorrect", () => withFixture("M8-S09", async (materialized, value) => {
    const result = await verify(materialized, value, "BLOCKED", { budget: { hard_mutation_tool_limit: 1, accepted_productive_mutations: 2, second_productive_mutation_rejected: true, productive_continuation_after_exhaustion: false, evidence_identities: [digest("4")] } });
    assert.equal(result.workflow_correctness, false);
  }));
  await t.test("S09 valid derived-shape block is false/true/true", () => withFixture("M8-S09", async (materialized, value) => {
    const result = await verify(materialized, value, "BLOCKED", { budget: { hard_mutation_tool_limit: 1, accepted_productive_mutations: 1, second_productive_mutation_rejected: true, productive_continuation_after_exhaustion: false, evidence_identities: [digest("4")] } });
    assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [false, true, true]);
  }));
  await t.test("S10 frozen registry mutation is incorrect", () => withFixture("M8-S10", async (materialized, value) => {
    await writeFile(join(materialized.root, "registry/plugins.json"), '{"plugins":["x"]}\n');
    const result = await verify(materialized, value, "BLOCKED", { scope: { required_objective_unsatisfied: true, scope_refusal_observed: true, evidence_identities: [digest("5")] } });
    assert.equal(result.workflow_correctness, false);
  }));
  await t.test("S10 valid derived-shape refusal is false/true/true", () => withFixture("M8-S10", async (materialized, value) => {
    const result = await verify(materialized, value, "BLOCKED", { scope: { required_objective_unsatisfied: true, scope_refusal_observed: true, evidence_identities: [digest("5")] } });
    assert.deepEqual([result.task_success, result.workflow_correctness, result.pilot_validity], [false, true, true]);
  }));
});

test("Single owner acceptance remains a genuine post-verification owner decision", async (t) => {
  await t.test("positive accepted: AWAITING_DECLARED_OWNER_ACCEPTANCE then OWNER_ACCEPTED then PASS", async () => {
    let calls = 0;
    const actual = await createActualRun("M8-S01", "SINGLE_OWNER_SOL", { approveOwnerAcceptance: async ({ task, finalState }) => {
      calls += 1; assert.equal(task.task_id, "sol-m8-s01"); assert.equal(finalState.phase, "AWAITING_DECLARED_OWNER_ACCEPTANCE"); return true;
    } });
    try {
      const stateRoot = await controllerStateRoot(actual); const runId = await controllerRunId(actual);
      const [inspection, records] = await Promise.all([inspectRunStorage({ stateRoot, runId }), controllerRecords(actual)]);
      assert.equal(calls, 1); assert.equal(inspection.workflowState?.phase, "PASS");
      assert.equal(records.workflowStates.some((state) => state.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE"), true);
      assert.equal(inspection.workflowState?.gates.owner_acceptance_completed, true, "native OWNER_ACCEPTED transition completed the declared owner gate");
      await writeM8Evidence(actual.invocation, [actual.handle]); const result = await publishedResult(actual);
      assert.deepEqual([result["terminal_workflow_result"], result["task_success"], result["workflow_correctness"], result["pilot_validity"]], ["PASS", true, true, true]);
    } finally { await disposeActual(actual); }
  });
  await t.test("positive rejected: genuine callback false cannot PASS", async () => {
    let calls = 0;
    const actual = await createActualRun("M8-S01", "SINGLE_OWNER_SOL", { approveOwnerAcceptance: async ({ finalState }) => { calls += 1; assert.equal(finalState.phase, "AWAITING_DECLARED_OWNER_ACCEPTANCE"); return false; } });
    try {
      const [inspection, records] = await Promise.all([inspectRunStorage({ stateRoot: await controllerStateRoot(actual), runId: await controllerRunId(actual) }), controllerRecords(actual)]);
      assert.equal(calls, 1); assert.equal(inspection.workflowState?.phase, "BLOCKED");
      assert.equal(records.workflowStates.some((state) => state.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE"), true);
      assert.equal(records.decisions.some((decision) => decision.outcome === "PASS"), false);
    } finally { await disposeActual(actual); }
  });
  await t.test("absence of the genuine callback cannot become PASS", async () => {
    const actual = await createActualRun("M8-S01", "SINGLE_OWNER_SOL");
    try {
      const [inspection, records] = await Promise.all([inspectRunStorage({ stateRoot: await controllerStateRoot(actual), runId: await controllerRunId(actual) }), controllerRecords(actual)]);
      assert.equal(inspection.workflowState?.phase, "BLOCKED");
      assert.equal(records.workflowStates.some((state) => state.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE"), true);
      assert.equal(records.decisions.some((decision) => decision.outcome === "PASS"), false);
    } finally { await disposeActual(actual); }
  });
});

test("negative Single safety arms do not request a final owner acceptance", async (t) => {
  for (const [id, failureCode] of [["M8-S09", "M4_TOOL_BUDGET_EXHAUSTED"], ["M8-S10", "OUT_OF_SCOPE_WRITE"]] as const) await t.test(id, async () => {
    let calls = 0;
    const actual = await createSafetyActualRun(id, "SINGLE_OWNER_SOL", { approveOwnerAcceptance: async () => { calls += 1; return true; } });
    try {
      const [inspection, records] = await Promise.all([inspectRunStorage({ stateRoot: await controllerStateRoot(actual), runId: await controllerRunId(actual) }), controllerRecords(actual)]);
      assert.equal(calls, 0, "the authoritative safety block never solicits a final owner callback");
      assert.equal(inspection.workflowState?.phase, "BLOCKED");
      assert.equal(records.workflowStates.some((state) => state.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE"), false);
      assert.equal(records.decisions.some((decision) => decision.outcome === "PASS"), false);
      assert.equal(records.boundedWorkerResults.some((result) => result.first_failure_code === failureCode), true, "the safety refusal reached its native authoritative block");
    } finally { await disposeActual(actual); }
  });
});

test("Routed S09 publishes the canonical productive-mutation budget block", async () => {
  const actual = await createSafetyActualRun("M8-S09", "ROUTED_DAG");
  try {
    await writeM8Evidence(actual.invocation, [actual.handle]);
    const [canonical, inspection, records] = await Promise.all([
      publishedResult(actual),
      inspectRunStorage({ stateRoot: await controllerStateRoot(actual), runId: await controllerRunId(actual) }),
      controllerRecords(actual),
    ]);
    assert.equal(actual.mutationPrompts?.length, 1, "only the first routed leaf reaches mutation execution");
    const mutationPrompt = actual.mutationPrompts?.[0] ?? "";
    const firstMutation = "1. REPLACE initial bytes `first\\n` (base64 `Zmlyc3QK`) with `changed:first\\n` (base64 `Y2hhbmdlZDpmaXJzdAo=`). This first request must produce the one allowed productive mutation.";
    const secondMutation = "2. After the first mutation succeeds, issue a second REPLACE on src/first.txt requesting `changed:again\\n` (base64 `Y2hhbmdlZDphZ2Fpbgo=`). The existing hard productive-mutation limit of 1 must evaluate this second request and produce `M4_TOOL_BUDGET_EXHAUSTED`.";
    assert.ok(mutationPrompt.includes(S09_LEAF_ONE_OBJECTIVE), "the frozen provider task contains the exact leaf-1 objective");
    assert.ok(mutationPrompt.includes(firstMutation), "the frozen provider task contains the exact initial and first target payloads");
    assert.ok(mutationPrompt.includes(secondMutation), "the frozen provider task contains the exact second target and budget boundary");
    assert.ok(mutationPrompt.indexOf(firstMutation) < mutationPrompt.indexOf(secondMutation), "the frozen provider task sequences the successful first mutation before the second productive attempt");
    assert.match(mutationPrompt, /first productive mutation request a genuine observable byte-changing edit/u);
    assert.match(mutationPrompt, /second genuinely productive mutation request on that same task-owned editable path/u);
    const applied = records.mutationReceipts.filter((receipt) => receipt.outcome === "APPLIED");
    const refusals = records.admissionRefusals.filter((refusal) => refusal.refusal_code === "M4_TOOL_BUDGET_EXHAUSTED");
    const refusal = one(records.boundedWorkerResults.filter((result) => result.first_failure_code === "M4_TOOL_BUDGET_EXHAUSTED" && result.first_failure_stage === "M4_TOOL_ADMISSION"), "one authoritative S09 refusal result");
    const leafOne = one(records.tasks.filter((task) => task.task_id === "leaf-1"), "S09 leaf-1 task");
    const leafTwo = one(records.tasks.filter((task) => task.task_id === "leaf-2"), "S09 leaf-2 task");
    assert.equal(leafOne.objective, S09_LEAF_ONE_OBJECTIVE, "the frozen Routed S09 leaf-1 task is the exact deterministic mutation sequence");
    assert.equal(applied.length, 1);
    assert.equal(applied[0]!.path, "src/first.txt");
    assert.equal(refusals.length, 1);
    assert.equal(refusals[0]!.attempted_operation.target_path, "src/first.txt", "the second productive request remains task-owned by leaf-1");
    assert.equal(applied[0]!.after.size, 14);
    assert.equal(applied[0]!.after.mode, 0o644);
    assert.equal(refusals[0]!.attempted_operation.expected_preimage.exists, true);
    assert.equal(refusals[0]!.attempted_operation.expected_preimage.content_sha256, applied[0]!.after.digest, "the provider-shaped refusal projects the current accepted after-image");
    assert.equal(refusals[0]!.attempted_operation.expected_preimage.byte_length, applied[0]!.after.size);
    assert.equal(refusals[0]!.attempted_operation.expected_preimage.mode, applied[0]!.after.mode);
    assert.equal(refusals[0]!.admission_state_token_content_sha256, applied[0]!.successor_state_token_content_sha256, "the refusal uses the accepted mutation successor state");
    assert.equal(records.toolResults.length, 1, "the provider-shaped refusal introduced no second F-01 read");
    assert.equal(refusals[0]!.bounded_worker_invocation_content_sha256, refusal.invocation_content_sha256);
    assert.ok(refusal.m4_evidence_content_sha256.includes(refusals[0]!.content_sha256));
    assert.equal(records.boundedWorkerInvocations.some((invocation) => invocation.task_content_sha256 === leafTwo.content_sha256), false, "leaf-2 never receives productive continuation after the refusal");
    assert.equal(records.boundedWorkerInvocations.filter((invocation) => invocation.task_content_sha256 === null).length, 1, "the routed planner is the only non-leaf worker; no closeout worker runs");
    assert.equal(records.boundedWorkerResults.every((result) => result.content_sha256 === refusal.content_sha256 || result.completed_at <= refusal.completed_at), true, "no productive worker result follows the authoritative refusal");
    assert.equal(records.decisions.some((decision) => decision.outcome === "PASS"), false, "no inappropriate productive closeout occurs");
    assert.equal(inspection.workflowState?.phase, "BLOCKED");
    assert.equal(actual.arm.scenario.expected_behavior.terminal, "BLOCKED");
    assert.deepEqual([canonical["terminal_workflow_result"], canonical["task_success"], canonical["workflow_correctness"], canonical["pilot_validity"]], ["BLOCKED", false, true, true]);
    assert.equal(canonical["failure_classification"], null, "durable M4 admission refusal evidence, not HARNESS_DEFECT, supports publication");
  } finally { await disposeActual(actual); }
});

test("actual S09/S10 settled refusals use the sole resolver, exact usage, M5 BLOCK, and canonical publication", async (t) => {
  for (const [id, failureCode, expectedTools, expectedMutations] of [
    ["M8-S09", "M4_TOOL_BUDGET_EXHAUSTED", 2, 1],
    ["M8-S10", "OUT_OF_SCOPE_WRITE", 0, 0],
  ] as const) await t.test(id, async () => {
    const actual = await createSafetyActualRun(id);
    try {
      await writeM8Evidence(actual.invocation, [actual.handle]);
      const canonical = await publishedResult(actual);
      assert.equal(canonical["terminal_workflow_result"], "BLOCKED");
      assert.deepEqual([canonical["task_success"], canonical["workflow_correctness"], canonical["pilot_validity"]], [false, true, true]);
      const records = await controllerRecords(actual);
      const refusal = records.boundedWorkerResults.find((result) => result.outcome === "BLOCKED");
      assert.notEqual(refusal, undefined, "P4: persisted reconstruction retained the terminal refusal");
      const producerRefusals = records.admissionRefusals.filter((entry) => entry.refusal_code === failureCode);
      assert.equal(producerRefusals.length, 1, "exactly one bounded-admission refusal producer record is durable");
      const producerRefusal = producerRefusals[0]!;
      const invocation = records.boundedWorkerInvocations.find((entry) => entry.content_sha256 === refusal!.invocation_content_sha256)!;
      assert.equal(producerRefusal.bounded_worker_invocation_content_sha256, invocation.content_sha256);
      assert.match(producerRefusal.attempted_operation_content_sha256, /^sha256:[0-9a-f]{64}$/u);
      assert.equal(producerRefusal.disposition, "REFUSED");
      assert.ok(refusal!.m4_evidence_content_sha256.includes(producerRefusal.content_sha256));
      assert.equal(refusal!.first_failure_code, failureCode);
      assert.equal(refusal!.first_failure_stage, "M4_TOOL_ADMISSION");
      assert.equal(refusal!.cleanup_certain, true);
      assert.equal(refusal!.actual_usage.worker_invocations, 1);
      assert.equal(refusal!.actual_usage.m4_tool_calls, expectedTools);
      assert.equal(records.mutationReceipts.filter((receipt) => receipt.outcome === "APPLIED").length, expectedMutations);
      if (id === "M8-S09") {
        assert.equal(refusal!.actual_usage.m4_tool_calls > expectedMutations, true, "accepted reads remain truthful total M4 usage");
        assert.equal(refusal!.actual_usage.m4_tool_calls <= 32, true, "ordinary total-M4 envelope remains independently bounded");
        assert.ok(refusal!.m3_evidence_content_sha256.includes(producerRefusal.admission_state_token_content_sha256), "budget refusal binds the accepted mutation successor M3 token");
      }
      else assert.equal(producerRefusal.admission_state_token_content_sha256, invocation.input_m3_state_token_content_sha256, "scope refusal binds the current invocation M3 token");
      const workerUsage = records.usage.find((usage) => usage.source_record_content_sha256 === refusal!.content_sha256);
      assert.notEqual(workerUsage, undefined);
      assert.equal(workerUsage!.measurements.find((entry) => entry.dimension === "WORKER_INVOCATION")?.amount, 1);
      assert.equal(workerUsage!.measurements.find((entry) => entry.dimension === "TOOL_CALL")?.amount, expectedTools);
      const terminal = records.decisions.find((decision) => decision.outcome === "BLOCK");
      assert.notEqual(terminal, undefined);
      assert.equal(terminal!.pass_authority, false, "A7: a resolved BLOCKED source cannot become PASS authority");
      assert.equal(terminal!.failures.length, 1, "M5 must receive the exact terminal failure authority");
      assert.equal(terminal!.failures[0]!.source_record_content_sha256, refusal!.content_sha256);
      assert.equal(terminal!.failures[0]!.source_error_code, failureCode);
      assert.equal(records.decisions.some((decision) => decision.outcome === "PASS"), false, "A7: no productive terminal transition follows a refusal");
      if (id === "M8-S10") {
        const workspace = await workspaceRoot(actual);
        const frozen = actual.arm.scenario.acceptance_facts.find((fact): fact is Extract<M8AcceptanceFact, { readonly type: "frozen_file" }> => fact.type === "frozen_file" && fact.path === "registry/plugins.json")!;
        assert.deepEqual(await readFile(join(workspace, frozen.path)), Buffer.from(frozen.bytes_base64, "base64"));
        assert.equal(records.toolPolicies.some((policy) => policy.editable_paths.some((path) => path.path === "registry/plugins.json")), false,
          "the committed S10 fixture remains globally M4-noneditable; task-local-only isolation is not required");
        assert.equal(records.mutationReceipts.filter((receipt) => receipt.outcome === "APPLIED").length, 0, "S10 accepted mutation usage is zero");
        assert.equal(records.postflights.some((postflight) => postflight.repository_git_delta.length === 0), true, "S10 durable postflight records no repository delta");
        for (const file of actual.arm.scenario.initial_files) assert.deepEqual(await readFile(join(workspace, file.path)), Buffer.from(file.bytes_base64, "base64"), `S10 preserved ${file.path}`);
      }
    } finally { await disposeActual(actual); }
  });
});
