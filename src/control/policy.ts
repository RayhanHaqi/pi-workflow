import { canonicalize } from "../canonical-json/index.js";
import { assertM3RepositoryIdentitySemantics } from "../persistence/m3-authority.js";
import {
  assertDocumentValid,
  type ContractDocument,
  type M3RepositoryIdentityDocument,
  type M5ControlPolicyDocument,
  type ReducerPolicy,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
  type WorkflowState,
} from "../schemas/index.js";
import { createInitialState } from "../state-machine/index.js";
import { controlError } from "./errors.js";

export interface ImmutableM5RunAuthority {
  readonly repositoryIdentity?: M3RepositoryIdentityDocument;
  readonly contract?: ContractDocument;
  readonly routeMap?: RouteMapDocument;
  readonly routeMapApproval?: RouteMapApprovalDocument;
}

function repositoryTarget(repository: M3RepositoryIdentityDocument): ContractDocument["target_repository"] {
  return {
    root: repository.git_toplevel,
    git_common_dir: repository.git_common_dir,
    worktree: repository.worktree_root,
    branch: repository.branch ?? "DETACHED",
    head: repository.head,
  };
}

/** Package-private immutable run-origin check shared by live admission and disk reconstruction. */
export function assertImmutableM5RunAuthority(
  policy: M5ControlPolicyDocument,
  state: WorkflowState,
  authority: ImmutableM5RunAuthority | undefined,
): asserts authority is Required<ImmutableM5RunAuthority> {
  const repository = authority?.repositoryIdentity;
  const contract = authority?.contract;
  const routeMap = authority?.routeMap;
  const approval = authority?.routeMapApproval;
  if (repository === undefined || contract === undefined || routeMap === undefined || approval === undefined) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Immutable repository, contract, and route authority is incomplete");
  }
  try {
    assertM3RepositoryIdentitySemantics(repository);
    assertDocumentValid("pi_gacw_contract_v0", contract);
    assertDocumentValid("pi_gacw_route_map_v0", routeMap);
    assertDocumentValid("pi_gacw_route_map_approval_v0", approval);
  } catch (error: unknown) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Immutable run authority failed structural or semantic validation", error);
  }
  if (repository.content_sha256 !== policy.repository_identity_content_sha256 || repository.worktree_key !== policy.worktree_key ||
      !same(repositoryTarget(repository), contract.target_repository)) {
    throw controlError("M5_POLICY_INVALID", "Policy repository/worktree identity differs from the contract-bound M3 repository authority");
  }
  if (contract.contract_sha256 !== state.identities.contract_sha256 || contract.contract_sha256 !== policy.contract_sha256 ||
      contract.objective_sha256 !== state.identities.objective_sha256 || contract.objective_sha256 !== policy.objective_sha256 ||
      contract.baseline_approval_sha256 !== state.identities.baseline_approval_sha256 || contract.baseline_approval_sha256 !== policy.baseline_approval_sha256 ||
      contract.authority_lock_sha256 !== state.identities.authority_lock_sha256 || contract.authority_lock_sha256 !== policy.authority_lock_sha256 ||
      contract.route_map_approval_sha256 !== policy.route_map_approval_sha256 || contract.execution_mode !== state.execution_mode) {
    throw controlError("M5_POLICY_INVALID", "Policy or state differs from immutable contract authority");
  }
  if (routeMap.route_map_sha256 !== policy.route_map_sha256 || approval.route_map_sha256 !== routeMap.route_map_sha256 ||
      approval.route_map_approval_sha256 !== policy.route_map_approval_sha256 || approval.route_map_approval_sha256 !== contract.route_map_approval_sha256 ||
      approval.approved_by.length === 0) {
    throw controlError("M5_POLICY_INVALID", "Policy route authority differs from the contract-bound approved route map");
  }
}

function same(left: unknown, right: unknown): boolean { return canonicalize(left) === canonicalize(right); }

export function assertControlPolicyAuthority(
  policy: M5ControlPolicyDocument,
  state: WorkflowState,
  reducerPolicy: ReducerPolicy,
  runId: string,
  production: boolean,
  authority?: ImmutableM5RunAuthority,
): void {
  try { assertDocumentValid("pi_gacw_m5_control_policy_v0", policy); }
  catch (error: unknown) { throw controlError("M5_POLICY_INVALID", "Control policy failed structural, identity, or semantic validation", error); }
  if (policy.run_id !== runId || state.run_id !== runId || reducerPolicy.run_id !== runId) {
    throw controlError("M5_POLICY_INVALID", "Run authority differs between policy, state, and reducer policy");
  }
  if (production && policy.production_authority !== "OWNER_APPROVED") {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Production route map and budget authority are not owner approved");
  }
  assertImmutableM5RunAuthority(policy, state, authority);
  const genesis = createInitialState(reducerPolicy, state.identities);
  if (policy.starting_state_content_sha256 !== genesis.content_sha256) {
    throw controlError("M5_POLICY_INVALID", "Policy starting-state identity differs from the reducer-derived committed genesis state");
  }
  if (
    policy.objective_sha256 !== state.identities.objective_sha256 ||
    policy.contract_sha256 !== state.identities.contract_sha256 ||
    policy.budget_sha256 !== state.identities.budget_sha256 ||
    policy.authority_lock_sha256 !== state.identities.authority_lock_sha256 ||
    policy.baseline_approval_sha256 !== state.identities.baseline_approval_sha256 ||
    policy.scope_sha256 !== state.identities.scope_sha256 ||
    policy.acceptance_sha256 !== state.identities.acceptance_sha256 ||
    policy.plan_approval_sha256 !== state.identities.plan_approval_sha256 ||
    policy.task_graph_sha256 !== state.identities.task_graph_sha256
  ) throw controlError("M5_POLICY_INVALID", "Policy frozen identities differ from committed workflow state");
  if (policy.reducer_policy_content_sha256 !== reducerPolicy.content_sha256 || state.frozen_policy_content_sha256 !== reducerPolicy.content_sha256) {
    throw controlError("M5_POLICY_INVALID", "Policy reducer authority differs from committed state");
  }
  if (policy.requested_mode !== "AUTO" && policy.requested_mode !== state.execution_mode) {
    throw controlError("M5_POLICY_INVALID", "Explicit requested mode differs from the committed concrete mode");
  }
  if (policy.route_facts.task_count !== reducerPolicy.tasks.length || ((state.execution_mode === "ROUTED_DAG" || state.execution_mode === "STATIC_APPROVED_DAG") && policy.route_facts.leaf_count !== reducerPolicy.tasks.length) ||
      (state.execution_mode !== "ROUTED_DAG" && state.execution_mode !== "STATIC_APPROVED_DAG" && policy.route_facts.leaf_count !== 1)) {
    throw controlError("M5_POLICY_INVALID", "M5 route facts differ from the accepted reducer task authority");
  }
  if (policy.limits.find((entry) => entry.dimension === "WORKER_INVOCATION")?.hard_limit! > reducerPolicy.limits.max_worker_invocations) {
    throw controlError("M5_POLICY_INVALID", "M5 worker limit raises the accepted reducer limit");
  }
  if (!same(reducerPolicy.frozen_bindings, {
    plan_approval_sha256: policy.plan_approval_sha256,
    task_graph_sha256: policy.task_graph_sha256,
    scope_sha256: policy.scope_sha256,
    acceptance_sha256: policy.acceptance_sha256,
    budget_sha256: policy.budget_sha256,
  })) throw controlError("M5_POLICY_INVALID", "M5 policy differs from reducer frozen bindings");
}

export function deepFreezeDetached<T>(value: T): T {
  const clone = structuredClone(value);
  const freeze = (candidate: unknown, seen = new Set<object>()): void => {
    if (candidate === null || typeof candidate !== "object" || seen.has(candidate)) return;
    seen.add(candidate);
    for (const nested of Object.values(candidate)) freeze(nested, seen);
    Object.freeze(candidate);
  };
  freeze(clone);
  return clone;
}
