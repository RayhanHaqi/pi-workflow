import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import type { M5ImmutableRunAuthoritySources } from "../src/control/types.js";
import { commitTransition, initializeRunStorage, type CommittedRunState } from "../src/persistence/index.js";
import { acquireWorktreeLock, captureBaseline, releaseWorktreeLock, resolveRepositoryIdentity, runFullPreflight } from "../src/repository/index.js";
import { identifyContractDocument, type ContractDocument, type M3RepositoryIdentityDocument, type M3RepositoryStateTokenDocument, type M5ControlPolicyDocument, type M5UsageEvidenceDocument, type ReducerPolicy, type RouteMapApprovalDocument, type RouteMapDocument, type TransitionEvent, type WorkflowState } from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { digest, domainDocument, makePolicy, repositoryIdentity as staticRepositoryIdentity, stateIdentities, transitionEvent, type MutableJson } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import { git, instructionAuthorityInputs, requiredEnvironment, scopeIdentity } from "./repository-helpers.js";

export interface M5R3Fixture {
  readonly verifierRoot: string;
  readonly stateRoot: string;
  readonly runId: string;
  readonly reducer: ReducerPolicy;
  readonly initialState: WorkflowState;
  readonly policy: M5ControlPolicyDocument;
  readonly runAuthority: M5ImmutableRunAuthoritySources;
  readonly m3StateToken: M3RepositoryStateTokenDocument;
  readonly committed: CommittedRunState;
}

export function m5RunAuthority(repositoryOverride?: M3RepositoryIdentityDocument): M5ImmutableRunAuthoritySources {
  const worktrees = [{ path: staticRepositoryIdentity.worktree, head: staticRepositoryIdentity.head, branch: staticRepositoryIdentity.branch, detached: false, locked_reason: null, prunable_reason: null }];
  const repository = repositoryOverride ?? identifyContractDocument("pi_gacw_repository_identity_v0", {
    schema_id: "pi_gacw_repository_identity_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    requested_path: staticRepositoryIdentity.root, physical_requested_path: staticRepositoryIdentity.root, worktree_root: staticRepositoryIdentity.worktree,
    git_toplevel: staticRepositoryIdentity.root, git_common_dir: staticRepositoryIdentity.git_common_dir, git_dir: `${staticRepositoryIdentity.git_common_dir}`,
    worktree_git_dir: `${staticRepositoryIdentity.git_common_dir}`, branch: staticRepositoryIdentity.branch, detached: false, head: staticRepositoryIdentity.head,
    head_tree: staticRepositoryIdentity.head, upstream_ref: null, ahead: null, behind: null, worktrees, worktree_list_sha256: sha256Canonical(worktrees),
    shallow: false, partial_clone: { promisor_remote: null, filters: [] }, submodules: [], submodule_state_sha256: sha256Canonical([]),
    git_version: "git version fixture", worktree_key: sha256Bytes(Buffer.concat([Buffer.from(staticRepositoryIdentity.git_common_dir), Buffer.from([0]), Buffer.from(staticRepositoryIdentity.worktree)])),
  }) as unknown as M3RepositoryIdentityDocument;
  const routeMap = domainDocument("route-map-v1") as unknown as RouteMapDocument;
  const approvalBase = domainDocument("route-map-approval-v1") as RouteMapApprovalDocument;
  const { content_sha256: _approvalContent, route_map_approval_sha256: _approvalIdentity, ...approvalBody } = structuredClone(approvalBase);
  const routeMapApproval = identifyContractDocument("pi_gacw_route_map_approval_v0", { ...approvalBody, route_map_sha256: routeMap.route_map_sha256 }) as unknown as RouteMapApprovalDocument;
  const contractBase = domainDocument("contract-freeze-v1") as ContractDocument;
  const { content_sha256: _contractContent, contract_sha256: _contractIdentity, ...contractBody } = structuredClone(contractBase);
  const contract = identifyContractDocument("pi_gacw_contract_v0", {
    ...contractBody, objective_sha256: digest(50), target_repository: {
      root: repository.git_toplevel, git_common_dir: repository.git_common_dir, worktree: repository.worktree_root,
      branch: repository.branch ?? "DETACHED", head: repository.head,
    }, baseline_approval_sha256: digest(52), authority_lock_sha256: digest(53), route_map_approval_sha256: routeMapApproval.route_map_approval_sha256,
  }) as unknown as ContractDocument;
  return { repositoryIdentity: repository, contract, routeMap, routeMapApproval };
}

export function m5Policy(
  reducer: ReducerPolicy,
  startingState: Sha256Digest,
  authority?: M5ImmutableRunAuthoritySources,
): M5ControlPolicyDocument {
  const obligation = { declaration: "src/result.ts", direction: "OUTPUT" as const, stage: 1, producer: "task-only", consumers: ["contract"], grammar: "PATH" as const,
    evidence_kind: "FILE" as const, literal: null, prefix: null };
  const dimensions = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", {
    schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: reducer.run_id, repository_identity_content_sha256: authority?.repositoryIdentity.content_sha256 ?? digest(300), worktree_key: authority?.repositoryIdentity.worktree_key ?? digest(301), starting_state_content_sha256: startingState,
    objective_sha256: digest(50), contract_sha256: authority?.contract.contract_sha256 ?? digest(51), budget_sha256: reducer.frozen_bindings.budget_sha256,
    route_map_sha256: authority?.routeMap.route_map_sha256 ?? digest(302), route_map_approval_sha256: authority?.routeMapApproval.route_map_approval_sha256 ?? digest(303), reducer_policy_content_sha256: reducer.content_sha256,
    authority_lock_sha256: digest(53), baseline_approval_sha256: digest(52), scope_sha256: reducer.frozen_bindings.scope_sha256,
    acceptance_sha256: reducer.frozen_bindings.acceptance_sha256, plan_approval_sha256: reducer.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: reducer.frozen_bindings.task_graph_sha256, tool_policy_content_sha256: digest(304), command_catalog_content_sha256: digest(305),
    route_map_approved: true, production_authority: "TEST_FIXTURE", requested_mode: "DIRECT_LUNA_HIGH",
    route_facts: { hard_sol_conditions: [], task_count: 1, coherent_single_task: true, failure_domain_count: 1, deterministic_acceptance: true,
      ownership_ambiguous: false, leaf_count: 1, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations: [{ descriptor_sha256: sha256Canonical(obligation), ...obligation }],
    limits: dimensions.map((dimension) => ({ dimension, hard_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 100,
      soft_limit: dimension === "PROVIDER_REQUEST" ? null : dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : 80,
      enforcement_class: dimension === "WORKER_INVOCATION" || dimension === "TOOL_CALL" ? "HARD_ENFORCEABLE" as const
        : dimension === "MODEL_TURN" ? "SOFT_ENFORCEABLE" as const : dimension === "PROVIDER_REQUEST" ? "UNAVAILABLE" as const : "OBSERVABLE_ONLY" as const })),
    role_reservation_envelopes: [{ logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK", maximum_control_decisions: 100,
    maximum_usage_records: 100, maximum_authority_depth: 64,
  }) as unknown as M5ControlPolicyDocument;
}

export function usage(policy: M5ControlPolicyDocument, state: Sha256Digest, operation = "r3-operation-1", amount = 1): M5UsageEvidenceDocument {
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: policy.run_id, policy_content_sha256: policy.content_sha256, originating_state_content_sha256: state,
    operation_id: operation, operation_kind: "TOOL_CALL", execution_mode: "DIRECT_LUNA_HIGH", logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: null, source_layer: "M5", source_kind: "M5_CONTROL_POLICY",
    source_record_content_sha256: policy.content_sha256, measurements: [{ dimension: "TOOL_CALL", amount, basis: "VALIDATED", enforcement_class: "HARD_ENFORCEABLE" }],
    disposition: "COMPLETED", duration_ms: null,
  }) as unknown as M5UsageEvidenceDocument;
}

export async function createM5R3Fixture(parentRoot?: string): Promise<M5R3Fixture> {
  const verifierRoot = await mkdtemp(join(parentRoot ?? tmpdir(), parentRoot === undefined ? "m5r3." : "fixture."));
  try {
    const repositoryPath = join(verifierRoot, "repository"); const stateRoot = join(verifierRoot, "state");
    await mkdir(repositoryPath, { mode: 0o700 }); await mkdir(stateRoot, { mode: 0o700 }); await chmod(stateRoot, 0o700);
    await git(repositoryPath, "init", "-b", "main"); await git(repositoryPath, "config", "user.name", "M5 Test"); await git(repositoryPath, "config", "user.email", "m5@example.invalid");
    await writeFile(join(repositoryPath, "tracked.txt"), "initial\n", { mode: 0o644 });
    await writeFile(join(repositoryPath, "AGENTS.md"), "M5 test instructions\n", { mode: 0o644 });
    await writeFile(join(repositoryPath, "AUTHORITY.md"), "M5 frozen authority\n", { mode: 0o644 });
    await git(repositoryPath, "add", "tracked.txt", "AGENTS.md", "AUTHORITY.md"); await git(repositoryPath, "commit", "-m", "fixture baseline");
    const repository = await resolveRepositoryIdentity({ requestedPath: repositoryPath, requireHead: true });
    const editable = ["tracked.txt"]; const frozen = ["AGENTS.md", "AUTHORITY.md"]; const taskScopeIdentity = scopeIdentity(editable, frozen);
    const baseReducer = makePolicy("DIRECT_LUNA_HIGH");
    const reducer = identifyContractDocument("pi_gacw_reducer_policy_v0", { ...structuredClone(baseReducer), content_sha256: undefined,
      frozen_bindings: { ...baseReducer.frozen_bindings, scope_sha256: taskScopeIdentity } }) as unknown as ReducerPolicy;
    const runAuthority = m5RunAuthority(repository); const initialState = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: runAuthority.contract.contract_sha256 });
    const committed = await initializeRunStorage({ stateRoot, runId: reducer.run_id, policy: reducer, initialState, processMetadata });
    const lock = await acquireWorktreeLock({ stateRoot, repository });
    try {
      const selected = await instructionAuthorityInputs({ repository: repositoryPath, stateRoot, runId: reducer.run_id,
        trackedPath: join(repositoryPath, "tracked.txt"), instructionPath: join(repositoryPath, "AGENTS.md"), authorityPath: join(repositoryPath, "AUTHORITY.md") } as never);
      const baseline = (await captureBaseline({ stateRoot, runId: reducer.run_id, requestedPath: repositoryPath, mode: "CLEAN_REQUIRED", pathDecisions: [],
        instructionFiles: selected.instructions, authorityFiles: selected.authorities, allowShallow: false, allowPartialClone: false, lock })).baseline;
      const environment = await requiredEnvironment(repositoryPath);
      const full = await runFullPreflight({ stateRoot, runId: reducer.run_id, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key,
        expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
        baseline, approval: null, instructionFiles: selected.instructions, authorityFiles: selected.authorities, requiredEnvironment: environment,
        taskScopeIdentity, allowShallow: false, allowPartialClone: false, lock });
      return { verifierRoot, stateRoot, runId: reducer.run_id, reducer, initialState,
        policy: m5Policy(reducer, initialState.content_sha256 as Sha256Digest, runAuthority), runAuthority, m3StateToken: full.acceptedState, committed };
    } finally { await releaseWorktreeLock(lock); }
  } catch (error: unknown) { await rm(verifierRoot, { recursive: true, force: true }); throw error; }
}

export async function removeM5R3Fixture(fixture: Pick<M5R3Fixture, "verifierRoot">): Promise<void> {
  await rm(fixture.verifierRoot, { recursive: true, force: true });
}

export async function commitSetup(fixture: M5R3Fixture, events: readonly { type: TransitionEvent["event_type"]; payload?: MutableJson }[]): Promise<CommittedRunState> {
  let committed = fixture.committed;
  for (const [index, item] of events.entries()) {
    committed = await commitTransition({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRevision: committed.statePointer.revision,
      expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: `r3-setup-${index}-${item.type.toLowerCase()}`,
      policy: fixture.reducer,
      event: transitionEvent(item.type, item.payload ?? {}),
      processMetadata,
    });
  }
  return committed;
}

export async function directFastPreflightFixture(fixture: M5R3Fixture): Promise<CommittedRunState> {
  return commitSetup(fixture, [
    { type: "FREEZE_OBJECTIVE" }, { type: "ACQUIRE_LOCK" }, { type: "CAPTURE_BASELINE", payload: { approval_required: false } },
    { type: "ACCEPT_CLEAN_BASELINE" }, { type: "PASS_FULL_PREFLIGHT" }, { type: "VALIDATE_CONTRACT" }, { type: "SELECT_ROUTE", payload: { execution_mode: "DIRECT_LUNA_HIGH" } },
    { type: "VALIDATE_DIRECT_CONTRACT" }, { type: "REQUEST_DIRECT_APPROVAL" }, { type: "APPROVE_DIRECT_TASK" }, { type: "PASS_DIRECT_FAST_PREFLIGHT" },
  ]);
}

export async function directVerifyingFixture(fixture: M5R3Fixture): Promise<CommittedRunState> {
  const fast = await directFastPreflightFixture(fixture);
  let committed = fast;
  const events: readonly { type: TransitionEvent["event_type"]; payload?: MutableJson }[] = [
    { type: "START_DIRECT_ATTEMPT" }, { type: "COMPLETE_DIRECT_ATTEMPT" }, { type: "PASS_DIRECT_POSTFLIGHT" },
  ];
  for (const [index, item] of events.entries()) {
    committed = await commitTransition({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRevision: committed.statePointer.revision,
      expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: `r3-verifying-${index}-${item.type.toLowerCase()}`,
      policy: fixture.reducer,
      event: transitionEvent(item.type, item.payload ?? {}),
      processMetadata,
    });
  }
  return committed;
}

export const r3ProcessMetadata = processMetadata;
