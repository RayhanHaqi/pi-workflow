import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { createControlDecisionKernel, ControlDecisionError } from "../src/control/index.js";
import type { M5AuthoritativeSources, M5ImmutableRunAuthoritySources } from "../src/control/types.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { m3ScopeIdentity } from "../src/identity/m3-scope.js";
import { inspectRunStorage, initializeRunStorage, publishM5ManagedRecord, readM6WorkerRecords, readM5ManagedRecords, commitTransition } from "../src/persistence/store.js";
import { configureM5PersistenceTestHooks } from "../src/persistence/m5-test-hooks.js";
import { acquireWorktreeLock, captureBaseline, releaseWorktreeLock, resolveRepositoryIdentity, runFullPreflight } from "../src/repository/index.js";
import { createScopedToolGateway } from "../src/scoped-tools/index.js";
import { commandSpecification } from "./m4-helpers.js";
import {
  identifyContractDocument,
  type BudgetDocument,
  type ContractDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandCatalogDocument,
  type M4CommandSpecification,
  type M4ScopedToolPolicyDocument,
  type M5ControlPolicyDocument,
  type ReducerPolicy,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
} from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { digest, budgetDocument, makePolicy, stateIdentities, transitionEvent, type MutableJson } from "./helpers.js";
import { requiredEnvironment, fingerprintInput, git } from "./repository-helpers.js";
import { m5RunAuthority } from "./m5-r3-fixtures.js";
import { processMetadata } from "./persistence-helpers.js";

const execFileAsync = promisify(execFile);
const childDriver = resolve("dist/tests/m5-r3-child.js");
const taskScope = m3ScopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]);
const m4Limits = {
  maximum_patch_bytes: 1_048_576,
  maximum_read_bytes: 1_048_576,
  maximum_hash_bytes: 67_108_864,
  maximum_search_input_bytes: 67_108_864,
  maximum_search_matches: 10_000,
  maximum_list_entries: 100_000,
  maximum_list_metadata_bytes: 67_108_864,
  maximum_command_stdout_bytes: 4_194_304,
  maximum_command_stderr_bytes: 4_194_304,
  maximum_command_duration_ms: 1_800_000,
} as const;

type SourceOmission = "contract" | "budget" | "routeMap" | "routeMapApproval" | "m4ToolPolicy" | "m4CommandCatalog" | undefined;

interface OwnerRun {
  readonly root: string;
  readonly repository: string;
  readonly stateRoot: string;
  readonly runId: string;
  readonly reducer: ReducerPolicy;
  readonly initialState: ReturnType<typeof createInitialState>;
  readonly runAuthority: M5ImmutableRunAuthoritySources;
  readonly budget: BudgetDocument;
  readonly m3StateToken: M3RepositoryStateTokenDocument;
  readonly verificationCommand: M4CommandSpecification;
  readonly instructionPath: string;
  readonly authorityPath: string;
  readonly committed: Awaited<ReturnType<typeof initializeRunStorage>>;
}

interface PreparedOwnerRun extends OwnerRun {
  readonly lock: Awaited<ReturnType<typeof acquireWorktreeLock>>;
  readonly m4ToolPolicy: M4ScopedToolPolicyDocument;
  readonly m4CommandCatalog: M4CommandCatalogDocument;
  readonly fast: Awaited<ReturnType<typeof initializeRunStorage>>;
  readonly policy: M5ControlPolicyDocument;
  readonly sources: M5AuthoritativeSources;
}

interface PersistedM4Pair {
  readonly m4ToolPolicy: M4ScopedToolPolicyDocument;
  readonly m4CommandCatalog: M4CommandCatalogDocument;
}

function bytes(value: unknown): Buffer {
  return Buffer.from(`${canonicalize(value)}\n`, "utf8");
}

function ownerPolicy(
  reducer: ReducerPolicy,
  startingState: Sha256Digest,
  authority: M5ImmutableRunAuthoritySources,
  budget: BudgetDocument,
  m4ToolPolicy: M4ScopedToolPolicyDocument,
  m4CommandCatalog: M4CommandCatalogDocument,
): M5ControlPolicyDocument {
  const dimensions = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;
  const obligation = { declaration: "output.txt", direction: "OUTPUT" as const, stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH" as const,
    evidence_kind: "COMMAND" as const, literal: null, prefix: null };
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: reducer.run_id, repository_identity_content_sha256: authority.repositoryIdentity.content_sha256, worktree_key: authority.repositoryIdentity.worktree_key,
    starting_state_content_sha256: startingState, objective_sha256: digest(50), contract_sha256: authority.contract.contract_sha256,
    budget_sha256: budget.budget_sha256, route_map_sha256: authority.routeMap.route_map_sha256,
    route_map_approval_sha256: authority.routeMapApproval.route_map_approval_sha256, reducer_policy_content_sha256: reducer.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: reducer.frozen_bindings.scope_sha256,
    acceptance_sha256: reducer.frozen_bindings.acceptance_sha256, plan_approval_sha256: reducer.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: reducer.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: m4ToolPolicy.content_sha256,
    command_catalog_content_sha256: m4CommandCatalog.content_sha256, route_map_approved: true, production_authority: "OWNER_APPROVED",
    requested_mode: "DIRECT_LUNA_HIGH",
    route_facts: { hard_sol_conditions: [], task_count: 1, coherent_single_task: true, failure_domain_count: 1, deterministic_acceptance: true,
      ownership_ambiguous: false, leaf_count: 1, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
    limits: dimensions.map((dimension) => ({ dimension,
      hard_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 100,
      soft_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 80,
      enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const
        : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const,
    })),
    role_reservation_envelopes: [{ logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100,
    maximum_usage_records: 100, maximum_authority_depth: 64,
  }) as unknown as M5ControlPolicyDocument;
}

async function createOwnerRun(): Promise<OwnerRun> {
  const root = await mkdtemp(join(tmpdir(), "m6-owner-approved-"));
  try {
    const repository = join(root, "repository"); const stateRoot = join(root, "state");
    await mkdir(repository, { mode: 0o700 }); await mkdir(stateRoot, { mode: 0o700 }); await chmod(stateRoot, 0o700);
    await git(repository, "init", "-b", "main"); await git(repository, "config", "user.name", "M6 owner test"); await git(repository, "config", "user.email", "m6-owner@example.invalid");
    const trackedPath = join(repository, "tracked.txt"); const instructionPath = join(repository, "AGENTS.md"); const authorityPath = join(repository, "AUTHORITY.md");
    await writeFile(trackedPath, "initial\n", { mode: 0o644 }); await writeFile(instructionPath, "owner-approved test instructions\n", { mode: 0o644 }); await writeFile(authorityPath, "owner-approved frozen authority\n", { mode: 0o644 });
    await git(repository, "add", "tracked.txt", "AGENTS.md", "AUTHORITY.md"); await git(repository, "commit", "-m", "owner approved baseline");
    const repositoryIdentity = await resolveRepositoryIdentity({ requestedPath: repository, requireHead: true });
    const verificationCommand = await commandSpecification("verify-1", "VERIFICATION", "/usr/bin/true", [], { repositoryRoot: repository, timeoutMs: 30_000 });
    const baseAuthority = m5RunAuthority(repositoryIdentity);
    const { content_sha256: _contractContent, contract_sha256: _contractIdentity, ...contractBody } = structuredClone(baseAuthority.contract) as MutableJson;
    const contract = identifyContractDocument("pi_gacw_contract_v0", {
      ...contractBody, required_outputs: ["output.txt"],
      acceptance_criteria: [{ criterion_id: "owner-command", description: "The owner-approved verification command is available.", evidence_kind: "COMMAND", owner_acceptance: false }],
      verification_commands: [{ command_id: verificationCommand.command_id, argv: [...verificationCommand.argv], cwd: "REPOSITORY_ROOT", timeout_ms: verificationCommand.timeout_ms, network: verificationCommand.network_policy }],
    }) as unknown as ContractDocument;
    const runAuthority = { ...baseAuthority, contract };
    const budget = budgetDocument() as unknown as BudgetDocument;
    const baseReducer = makePolicy("DIRECT_LUNA_HIGH");
    const reducer = identifyContractDocument("pi_gacw_reducer_policy_v0", {
      ...structuredClone(baseReducer), content_sha256: undefined,
      frozen_bindings: { ...baseReducer.frozen_bindings, scope_sha256: taskScope, budget_sha256: budget.budget_sha256 },
    }) as unknown as ReducerPolicy;
    const initialState = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: runAuthority.contract.contract_sha256 });
    const committed = await initializeRunStorage({ stateRoot, runId: reducer.run_id, policy: reducer, initialState, processMetadata });
    let lock = await acquireWorktreeLock({ stateRoot, repository: repositoryIdentity });
    try {
      const instructions = [await fingerprintInput(instructionPath)]; const authorities = [await fingerprintInput(authorityPath)];
      const baseline = (await captureBaseline({ stateRoot, runId: reducer.run_id, requestedPath: repository, mode: "CLEAN_REQUIRED", pathDecisions: [],
        instructionFiles: instructions, authorityFiles: authorities, allowShallow: false, allowPartialClone: false, lock })).baseline;
      const full = await runFullPreflight({ stateRoot, runId: reducer.run_id, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
        expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
        baseline, approval: null, instructionFiles: instructions, authorityFiles: authorities, requiredEnvironment: await requiredEnvironment(repository),
        taskScopeIdentity: taskScope, allowShallow: false, allowPartialClone: false, lock });
      await releaseWorktreeLock(lock); lock = undefined as never;
      return { root, repository, stateRoot, runId: reducer.run_id, reducer, initialState, runAuthority, budget, verificationCommand,
        m3StateToken: full.acceptedState, instructionPath, authorityPath, committed };
    } finally {
      if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    }
  } catch (error: unknown) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

async function prepareOwnerRun(run: OwnerRun): Promise<PreparedOwnerRun> {
  const repositoryIdentity = run.runAuthority.repositoryIdentity;
  const lock = await acquireWorktreeLock({ stateRoot: run.stateRoot, repository: repositoryIdentity });
  try {
    const m4ToolPolicy = identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
      schema_id: "pi_gacw_scoped_tool_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
      run_id: run.runId, policy_id: "m6-owner-approved-policy", repository_identity_content_sha256: repositoryIdentity.content_sha256,
      worktree_key: repositoryIdentity.worktree_key, task_scope_identity: taskScope,
      readable_paths: [{ path: "tracked.txt", kind: "EXACT" }], editable_paths: [{ path: "tracked.txt", kind: "EXACT" }],
      frozen_paths: [{ path: "AGENTS.md", kind: "EXACT" }, { path: "AUTHORITY.md", kind: "EXACT" }],
      command_readable_paths: [{ path: "tracked.txt", kind: "EXACT" }], command_writable_paths: [],
      path_authorities: [
        { path: "tracked.txt", kind: "EXACT", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: true, delete: true, mode_change: true },
        { path: "AGENTS.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
        { path: "AUTHORITY.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
      ],
      evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M4_TOOL_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"], limits: m4Limits,
    }) as M4ScopedToolPolicyDocument;
    const m4CommandCatalog = identifyContractDocument("pi_gacw_command_catalog_v0", {
      schema_id: "pi_gacw_command_catalog_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: run.runId,
      catalog_id: "m6-owner-approved-catalog", repository_identity_content_sha256: repositoryIdentity.content_sha256,
      tool_policy_content_sha256: m4ToolPolicy.content_sha256, commands: [run.verificationCommand],
    }) as M4CommandCatalogDocument;
    const baselinePath = join(run.stateRoot, "runs", run.runId, "records", "baselines", `${run.m3StateToken.baseline_runtime_content_sha256.slice(7)}.json`);
    const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
    const instructions = [await fingerprintInput(run.instructionPath)]; const authorities = [await fingerprintInput(run.authorityPath)];
    const refreshed = await runFullPreflight({ stateRoot: run.stateRoot, runId: run.runId, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval: null, instructionFiles: instructions, authorityFiles: authorities, requiredEnvironment: await requiredEnvironment(run.repository),
      taskScopeIdentity: taskScope, allowShallow: false, allowPartialClone: false, lock });
    const m3StateToken = refreshed.acceptedState;
    await createScopedToolGateway({ stateRoot: run.stateRoot, runId: run.runId, repository: repositoryIdentity, baseline, acceptedState: m3StateToken, lock,
      instructionFiles: instructions, authorityFiles: authorities, editablePaths: ["tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"],
      taskScopeIdentity: taskScope, toolPolicy: m4ToolPolicy, commandCatalog: m4CommandCatalog, temporaryRoot: join(run.root, "controller-tmp") });

    let fast = run.committed;
    const setup: readonly [string, MutableJson, boolean][] = [
      ["FREEZE_OBJECTIVE", {}, false], ["ACQUIRE_LOCK", {}, false], ["CAPTURE_BASELINE", { approval_required: false }, false],
      ["ACCEPT_CLEAN_BASELINE", {}, false], ["PASS_FULL_PREFLIGHT", {}, false], ["VALIDATE_CONTRACT", {}, false],
      ["SELECT_ROUTE", { execution_mode: "DIRECT_LUNA_HIGH" }, false], ["VALIDATE_DIRECT_CONTRACT", {}, false],
      ["REQUEST_DIRECT_APPROVAL", {}, false], ["APPROVE_DIRECT_TASK", {}, false], ["PASS_DIRECT_FAST_PREFLIGHT", {}, true],
    ];
    for (const [index, [eventType, payload]] of setup.entries()) {
      const evidence: readonly { readonly bytes: Buffer; readonly mediaType: string }[] = [];
      fast = await commitTransition({ stateRoot: run.stateRoot, runId: run.runId, expectedRevision: fast.statePointer.revision,
        expectedStatePointerContentSha256: fast.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fast.workflowState.content_sha256 as Sha256Digest,
        transitionId: `m6-owner-setup-${index}-${eventType.toLowerCase()}`, policy: run.reducer, event: transitionEvent(eventType as never, payload), evidence, processMetadata });
    }
    const policy = ownerPolicy(run.reducer, run.initialState.content_sha256 as Sha256Digest, run.runAuthority, run.budget, m4ToolPolicy, m4CommandCatalog);
    const sources: M5AuthoritativeSources = { contract: run.runAuthority.contract, budget: run.budget, m4ToolPolicy, m4CommandCatalog,
      routeMap: run.runAuthority.routeMap, routeMapApproval: run.runAuthority.routeMapApproval, m3StateTokens: [m3StateToken] };
    return { ...run, m3StateToken, lock, m4ToolPolicy, m4CommandCatalog, fast, policy, sources };
  } catch (error: unknown) {
    await releaseWorktreeLock(lock).catch(() => undefined); throw error;
  }
}

async function createUnrelatedM4Pair(run: PreparedOwnerRun, suffix = "unrelated"): Promise<PersistedM4Pair> {
  const repositoryIdentity = run.runAuthority.repositoryIdentity;
  const m4ToolPolicy = identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
    ...structuredClone(run.m4ToolPolicy), content_sha256: undefined, policy_id: `m6-${suffix}-policy`,
  }) as unknown as M4ScopedToolPolicyDocument;
  const m4CommandCatalog = identifyContractDocument("pi_gacw_command_catalog_v0", {
    ...structuredClone(run.m4CommandCatalog), content_sha256: undefined, catalog_id: `m6-${suffix}-catalog`,
    tool_policy_content_sha256: m4ToolPolicy.content_sha256,
  }) as unknown as M4CommandCatalogDocument;
  const baselinePath = join(run.stateRoot, "runs", run.runId, "records", "baselines", `${run.m3StateToken.baseline_runtime_content_sha256.slice(7)}.json`);
  const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
  const instructions = [await fingerprintInput(run.instructionPath)]; const authorities = [await fingerprintInput(run.authorityPath)];
  await createScopedToolGateway({ stateRoot: run.stateRoot, runId: run.runId, repository: repositoryIdentity, baseline, acceptedState: run.m3StateToken, lock: run.lock,
    instructionFiles: instructions, authorityFiles: authorities, editablePaths: ["tracked.txt"], frozenPaths: ["AGENTS.md", "AUTHORITY.md"],
    taskScopeIdentity: taskScope, toolPolicy: m4ToolPolicy, commandCatalog: m4CommandCatalog, temporaryRoot: join(run.root, `controller-tmp-${suffix}`) });
  return { m4ToolPolicy, m4CommandCatalog };
}

interface RejectionSnapshot {
  readonly pointerBytes: string;
  readonly revision: number | null;
  readonly statePointerContentSha256: string | null;
  readonly workflowStateContentSha256: string | null;
  readonly transitionCommitContentSha256: string | null;
  readonly transitionGraph: readonly { readonly kind: string; readonly contentSha256: string; readonly relativePath: string }[];
  readonly storageHealth: { readonly status: string; readonly issues: unknown; readonly orphanedObjects: unknown; readonly temporaryFiles: unknown };
  readonly m5Inventory: { readonly policies: unknown; readonly usage: unknown; readonly decisions: unknown };
  readonly m6Inventory: { readonly invocations: unknown; readonly results: unknown };
}

async function rejectionSnapshot(run: PreparedOwnerRun): Promise<RejectionSnapshot> {
  const inspection = await inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId });
  const records = await readM5ManagedRecords({ stateRoot: run.stateRoot, runId: run.runId });
  const m6 = await readM6WorkerRecords({ stateRoot: run.stateRoot, runId: run.runId });
  const pointerBytes = await readFile(join(run.stateRoot, "runs", run.runId, "state.json"));
  const transitionKinds = new Set(["WORKFLOW_STATE", "TRANSITION_EVENT", "TRANSITION_COMMIT"]);
  return {
    pointerBytes: pointerBytes.toString("hex"), revision: inspection.revision,
    statePointerContentSha256: inspection.statePointer?.content_sha256 ?? null,
    workflowStateContentSha256: inspection.workflowState?.content_sha256 ?? null,
    transitionCommitContentSha256: inspection.transitionCommit?.content_sha256 ?? null,
    transitionGraph: inspection.reachableObjects.filter((object) => transitionKinds.has(object.kind)).map((object) => ({ kind: object.kind, contentSha256: object.contentSha256, relativePath: object.relativePath })),
    storageHealth: { status: inspection.status, issues: inspection.issues, orphanedObjects: inspection.orphanedObjects, temporaryFiles: inspection.temporaryFiles },
    m5Inventory: { policies: records.policies, usage: records.usage, decisions: records.decisions },
    m6Inventory: { invocations: m6.invocations, results: m6.results },
  };
}

function assertRejectionPreserved(before: RejectionSnapshot, after: RejectionSnapshot): void {
  assert.equal(after.pointerBytes, before.pointerBytes);
  assert.equal(after.revision, before.revision);
  assert.equal(after.statePointerContentSha256, before.statePointerContentSha256);
  assert.equal(after.workflowStateContentSha256, before.workflowStateContentSha256);
  assert.equal(after.transitionCommitContentSha256, before.transitionCommitContentSha256);
  assert.deepEqual(after.transitionGraph, before.transitionGraph);
  assert.deepEqual(after.storageHealth, before.storageHealth);
  assert.deepEqual(after.m5Inventory, before.m5Inventory);
  assert.deepEqual(after.m6Inventory, before.m6Inventory);
}

async function cleanupPrepared(run: PreparedOwnerRun): Promise<void> {
  configureM5PersistenceTestHooks(undefined);
  await releaseWorktreeLock(run.lock).catch(() => undefined);
  await rm(run.root, { recursive: true, force: true });
}

async function freshInspect(run: PreparedOwnerRun): Promise<any> {
  const inputPath = join(run.root, "fresh-inspect.json");
  await writeFile(inputPath, JSON.stringify({ stateRoot: run.stateRoot, runId: run.runId }), { mode: 0o600 });
  const output = await execFileAsync(process.execPath, [childDriver, "inspect", inputPath], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(output.stdout);
}

function recordClassification(inspection: any, kind: string, digestValue: string): string | undefined {
  return inspection.managedRecordClassifications.find((entry: any) => entry.object.kind === kind && entry.object.contentSha256 === digestValue)?.classification;
}

function decisionClassification(inspection: any, digestValue: string): string | undefined {
  return recordClassification(inspection, "M5_CONTROL_DECISION", digestValue);
}

async function assertNoAdmission(run: PreparedOwnerRun, omission?: SourceOmission): Promise<void> {
  await publishM5ManagedRecord({ stateRoot: run.stateRoot, runId: run.runId, kind: "M5_CONTROL_POLICY", document: run.policy });
  const before = await rejectionSnapshot(run);
  const sources = { ...run.sources };
  if (omission !== undefined) delete sources[omission];
  const runAuthority = omission === "contract" || omission === "routeMap" || omission === "routeMapApproval" ? undefined : run.runAuthority;
  const kernel = createControlDecisionKernel({ stateRoot: run.stateRoot, runId: run.runId, policy: run.policy, reducerPolicy: run.reducer,
    ...(runAuthority === undefined ? {} : { runAuthority }), authoritativeSources: sources, production: true });
  await assert.rejects(kernel.evaluateControlDecision({ intent: "AUTHORIZE_WORK", operationId: "owner-negative-operation", availableLogicalRoles: ["LUNA_EXECUTOR"],
    expectedRevision: before.revision!, expectedStatePointerContentSha256: before.statePointerContentSha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: before.workflowStateContentSha256 as Sha256Digest, transitionId: "owner-negative-start", processMetadata,
    authoritativeSources: sources }), (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_AUTHORITY_INCOMPLETE");
  const after = await rejectionSnapshot(run);
  assertRejectionPreserved(before, after);
  assert.equal(after.workflowStateContentSha256, before.workflowStateContentSha256);
  assert.equal((after.m5Inventory.decisions as readonly unknown[]).length, 0);
  assert.equal((after.m6Inventory.invocations as readonly unknown[]).length, 0);
}

test("OWNER_APPROVED strict predecessors survive publication and fresh reconstruction", async () => {
  const owner = await createOwnerRun(); const run = await prepareOwnerRun(owner); const unrelated = await createUnrelatedM4Pair(run);
  let precommit: any;
  configureM5PersistenceTestHooks({ checkpoint: async (checkpoint) => {
    if (checkpoint !== "AFTER_DECISION_PUBLICATION") return;
    precommit = await inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId });
  } });
  try {
    const kernel = createControlDecisionKernel({ stateRoot: run.stateRoot, runId: run.runId, policy: run.policy, reducerPolicy: run.reducer,
      runAuthority: run.runAuthority, authoritativeSources: run.sources, production: true });
    const result = await kernel.evaluateControlDecision({ intent: "AUTHORIZE_WORK", operationId: "owner-approved-operation", availableLogicalRoles: ["LUNA_EXECUTOR"],
      expectedRevision: run.fast.statePointer.revision, expectedStatePointerContentSha256: run.fast.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: run.fast.workflowState.content_sha256 as Sha256Digest, transitionId: "owner-approved-start", processMetadata,
      authoritativeSources: run.sources });
    assert.equal(run.policy.production_authority, "OWNER_APPROVED"); assert.equal(decisionClassification(precommit, result.decision.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(precommit, "M4_TOOL_POLICY", run.m4ToolPolicy.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(precommit, "M4_COMMAND_CATALOG", run.m4CommandCatalog.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(precommit, "M4_TOOL_POLICY", unrelated.m4ToolPolicy.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(precommit, "M4_COMMAND_CATALOG", unrelated.m4CommandCatalog.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(result.committed, true); assert.equal(result.workflowState.phase, "DIRECT_ATTEMPT_RUNNING");
    assert.equal(result.decision.outcome, "AUTHORIZE"); assert.equal(result.decision.selected_route, "CONTINUE_ADMITTED_OPERATION");
    assert.equal(result.decision.reservation?.logical_role, "LUNA_EXECUTOR"); assert.equal(result.decision.reservation?.reserved_route, "DIRECT_LUNA_HIGH");
    assert.equal(result.decision.contract_sha256, run.runAuthority.contract.contract_sha256); assert.equal(result.decision.budget_sha256, run.budget.budget_sha256);
    assert.equal(result.decision.route_map_sha256, run.runAuthority.routeMap.route_map_sha256); assert.equal(result.decision.route_map_approval_sha256, run.runAuthority.routeMapApproval.route_map_approval_sha256);
    assert.equal(result.decision.tool_policy_content_sha256, run.m4ToolPolicy.content_sha256); assert.equal(result.decision.command_catalog_content_sha256, run.m4CommandCatalog.content_sha256);
    const fresh = await freshInspect(run);
    assert.equal(fresh.inspection.status, "HEALTHY"); assert.equal(fresh.inspection.workflowState.phase, "DIRECT_ATTEMPT_RUNNING");
    assert.equal(fresh.records.contracts.length, 1); assert.equal(fresh.records.contracts[0].contract_sha256, run.runAuthority.contract.contract_sha256);
    assert.equal(fresh.records.budgets.length, 1); assert.equal(fresh.records.budgets[0].budget_sha256, run.budget.budget_sha256);
    assert.equal(fresh.records.routeMaps.length, 1); assert.equal(fresh.records.routeMaps[0].route_map_sha256, run.runAuthority.routeMap.route_map_sha256);
    assert.equal(fresh.records.routeMapApprovals.length, 1); assert.equal(fresh.records.routeMapApprovals[0].route_map_approval_sha256, run.runAuthority.routeMapApproval.route_map_approval_sha256);
    assert.equal(decisionClassification(fresh.inspection, result.decision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(recordClassification(fresh.inspection, "M4_TOOL_POLICY", run.m4ToolPolicy.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(fresh.inspection, "M4_COMMAND_CATALOG", run.m4CommandCatalog.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(fresh.inspection, "M4_TOOL_POLICY", unrelated.m4ToolPolicy.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(fresh.inspection, "M4_COMMAND_CATALOG", unrelated.m4CommandCatalog.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    const freshDecision = fresh.records.decisions.find((entry: any) => entry.content_sha256 === result.decision.content_sha256);
    assert.ok(freshDecision); assert.equal(freshDecision.reservation.logical_role, "LUNA_EXECUTOR"); assert.equal(freshDecision.reservation.reserved_route, "DIRECT_LUNA_HIGH");
    assert.equal(freshDecision.contract_sha256, run.runAuthority.contract.contract_sha256); assert.equal(freshDecision.budget_sha256, run.budget.budget_sha256);
    assert.equal(freshDecision.route_map_sha256, run.runAuthority.routeMap.route_map_sha256); assert.equal(freshDecision.route_map_approval_sha256, run.runAuthority.routeMapApproval.route_map_approval_sha256);
    assert.equal(freshDecision.tool_policy_content_sha256, run.m4ToolPolicy.content_sha256); assert.equal(freshDecision.command_catalog_content_sha256, run.m4CommandCatalog.content_sha256);
    const m6 = await readM6WorkerRecords({ stateRoot: run.stateRoot, runId: run.runId }); assert.equal(m6.invocations.length, 0); assert.equal(m6.results.length, 0);
    assert.equal(fresh.inspection.managedRecordClassifications.some((entry: any) => entry.object.kind === "M4_TOOL_RESULT"), false);
  } finally { await cleanupPrepared(run); }
});

test("OWNER_APPROVED exact M4 pair is not substituted by another valid pair", async () => {
  const owner = await createOwnerRun(); const run = await prepareOwnerRun(owner); const unrelated = await createUnrelatedM4Pair(run, "substitute");
  try {
    await unlink(join(run.stateRoot, "runs", run.runId, "records", "tool-policies", `${run.m4ToolPolicy.content_sha256.slice(7)}.json`));
    await unlink(join(run.stateRoot, "runs", run.runId, "records", "command-catalogs", `${run.m4CommandCatalog.content_sha256.slice(7)}.json`));
    const { m4ToolPolicy: _toolPolicy, m4CommandCatalog: _commandCatalog, ...withoutM4 } = run.sources;
    await assertNoAdmission({ ...run, sources: withoutM4 }, "m4ToolPolicy");
    const inspection = await inspectRunStorage({ stateRoot: run.stateRoot, runId: run.runId });
    assert.equal(recordClassification(inspection, "M4_TOOL_POLICY", unrelated.m4ToolPolicy.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(inspection, "M4_COMMAND_CATALOG", unrelated.m4CommandCatalog.content_sha256), "UNREFERENCED_MANAGED_RECORD");
    assert.equal(recordClassification(inspection, "M4_TOOL_POLICY", run.m4ToolPolicy.content_sha256), undefined);
    assert.equal(recordClassification(inspection, "M4_COMMAND_CATALOG", run.m4CommandCatalog.content_sha256), undefined);
  } finally { await cleanupPrepared(run); }
});

test("OWNER_APPROVED missing predecessors fail closed before publication", async (t) => {
  for (const omission of ["contract", "budget", "routeMap", "routeMapApproval", "m4ToolPolicy", "m4CommandCatalog"] as const) {
    await t.test(`missing ${omission}`, async () => {
      const owner = await createOwnerRun(); const run = await prepareOwnerRun(owner);
      try {
        if (omission === "m4ToolPolicy") await unlink(join(run.stateRoot, "runs", run.runId, "records", "tool-policies", `${run.m4ToolPolicy.content_sha256.slice(7)}.json`));
        if (omission === "m4CommandCatalog") await unlink(join(run.stateRoot, "runs", run.runId, "records", "command-catalogs", `${run.m4CommandCatalog.content_sha256.slice(7)}.json`));
        await assertNoAdmission(run, omission);
      } finally { await cleanupPrepared(run); }
    });
  }
});

test("OWNER_APPROVED source identity substitutions fail closed before transition", async (t) => {
  const cases: readonly [string, (run: PreparedOwnerRun) => M5AuthoritativeSources][] = [
    ["wrong budget", (run) => ({ ...run.sources, budget: identifyContractDocument("pi_gacw_budget_v0", { ...structuredClone(run.budget), content_sha256: undefined, limits: { ...run.budget.limits, max_tool_calls: run.budget.limits.max_tool_calls + 1 } }) as unknown as BudgetDocument })],
    ["approval bound to another route map", (run) => {
      const { content_sha256: _routeContent, ...routeBody } = structuredClone(run.runAuthority.routeMap) as MutableJson;
      const otherRoute = identifyContractDocument("pi_gacw_route_map_v0", { ...routeBody, routes: routeBody.routes.map((route: MutableJson, index: number) => index === 0 ? { ...route, model_id: "substituted-model" } : route) }) as unknown as RouteMapDocument;
      const { content_sha256: _approvalContent, ...approvalBody } = structuredClone(run.runAuthority.routeMapApproval) as MutableJson;
      const approval = identifyContractDocument("pi_gacw_route_map_approval_v0", { ...approvalBody, route_map_sha256: otherRoute.route_map_sha256 });
      return { ...run.sources, routeMapApproval: approval as unknown as RouteMapApprovalDocument };
    }],
    ["catalog bound to another policy", (run) => ({ ...run.sources, m4CommandCatalog: identifyContractDocument("pi_gacw_command_catalog_v0", { ...structuredClone(run.m4CommandCatalog), content_sha256: undefined, tool_policy_content_sha256: digest(990) }) as unknown as M4CommandCatalogDocument })],
    ["M4 policy from another run", (run) => ({ ...run.sources, m4ToolPolicy: identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...structuredClone(run.m4ToolPolicy), content_sha256: undefined, run_id: "another-run" }) as unknown as M4ScopedToolPolicyDocument })],
    ["M4 catalog from another repository", (run) => ({ ...run.sources, m4CommandCatalog: identifyContractDocument("pi_gacw_command_catalog_v0", { ...structuredClone(run.m4CommandCatalog), content_sha256: undefined, repository_identity_content_sha256: digest(991) }) as unknown as M4CommandCatalogDocument })],
    ["M4 policy from another worktree", (run) => ({ ...run.sources, m4ToolPolicy: identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...structuredClone(run.m4ToolPolicy), content_sha256: undefined, worktree_key: digest(992) }) as unknown as M4ScopedToolPolicyDocument })],
    ["M4 policy from another M3 token scope", (run) => ({ ...run.sources, m4ToolPolicy: identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...structuredClone(run.m4ToolPolicy), content_sha256: undefined, task_scope_identity: digest(993) }) as unknown as M4ScopedToolPolicyDocument })],
    ["M4 policy scope substitution", (run) => ({ ...run.sources, m4ToolPolicy: identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...structuredClone(run.m4ToolPolicy), content_sha256: undefined, task_scope_identity: digest(994) }) as unknown as M4ScopedToolPolicyDocument })],
  ];
  for (const [name, substitute] of cases) {
    await t.test(name, async () => {
      const owner = await createOwnerRun(); const run = await prepareOwnerRun(owner);
      try {
        const candidate = { ...run, sources: substitute(run) };
        await assertNoAdmission(candidate);
      } finally { await cleanupPrepared(run); }
    });
  }
});
