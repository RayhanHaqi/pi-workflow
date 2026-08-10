import { execFile } from "node:child_process";
import { lstat, mkdir, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";

import { canonicalize } from "./canonical-json/index.js";
import { createControlDecisionKernel } from "./control/index.js";
import type { M5AuthoritativeSources, M5ObligationEvidenceInput } from "./control/types.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { m3ScopeIdentity } from "./identity/m3-scope.js";
import { commitTransition, initializeRunStorage, inspectRunStorage, type CommittedRunState } from "./persistence/index.js";
import { readBoundedWorkerRecords, readM5ManagedRecords } from "./persistence/store.js";
import { resolveAuthoritativeBoundedExecution } from "./persistence/bounded-worker-authority.js";
import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFullPreflight,
  runPostflight,
  type BaselinePathDecision,
  type RequiredEnvironment,
  type WorktreeLockHandle,
} from "./repository/index.js";
import { resolveExecutable } from "./repository/executable.js";
import { createScopedToolGateway } from "./scoped-tools/index.js";
import { assertM4CanonicalPath } from "./secure-fs/path.js";
import {
  identifyContractDocument,
  type BudgetDocument,
  type ConcreteExecutionMode,
  type ContractDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandSpecification,
  type M4ScopedToolPolicyDocument,
  type M4CommandCatalogDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type PlanApprovalDocument,
  type ReducerPolicy,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
  type TaskDocument,
  type TaskGraphDocument,
  type TransitionEvent,
  type WorkflowState,
} from "./schemas/index.js";
import { createInitialState } from "./state-machine/index.js";
import { runBoundedWorker, runBoundedWorkerForTests, type BoundedWorkerRoute } from "./pi-adapter/bounded-worker.js";

const execFileAsync = promisify(execFile);
const RUN_ID = "pre-m8-bounded";
const CONTROLLER_VERSION = "0.1.0";
const MAX_TOOL_CALLS_PER_WORKER = 32;
const MAX_WALL_TIME_MS = 120_000;
const PRODUCT_ROLES = ["SOL_OWNER", "SOL_PLANNER", "SOL_REPLAN", "SOL_CLOSEOUT", "LUNA_EXECUTOR", "BENCHMARK_VERIFIER", "BENCHMARK_SELECTOR"] as const;

type GoalMode = ConcreteExecutionMode;
type GoalScope = { readonly readable_paths: readonly string[]; readonly editable_paths: readonly string[]; readonly frozen_paths: readonly string[] };
type CandidateTask = { readonly task_id: string; readonly objective: string; readonly editable_paths: readonly string[]; readonly required_outputs: readonly string[]; readonly dependencies: readonly string[] };

export class BoundedWorkflowError extends Error {
  public constructor(public readonly code: string, message: string) { super(message); this.name = "BoundedWorkflowError"; }
}

/** Semantic-only request data. It deliberately has no provider, model, argv, credential, or tool authority. */
export interface BoundedMutationGoal {
  readonly objective: string;
  readonly stop_condition: string;
  readonly execution_mode: GoalMode;
  readonly scope: GoalScope;
  readonly required_outputs: readonly string[];
  readonly tasks?: readonly CandidateTask[];
  readonly baseline_mode?: "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY";
}

/** Controller-owned executable authority, intentionally outside the user Goal. */
export interface ControllerVerificationCommand {
  readonly command_id: string;
  readonly executable: string;
  readonly args?: readonly string[];
  readonly cwd: string;
  readonly timeout_ms?: number;
}

export interface BoundedMutationAuthority {
  readonly verification_commands: readonly ControllerVerificationCommand[];
  readonly dirty_baseline_decisions?: readonly BaselinePathDecision[];
}

export interface BaselineApprovalRequest {
  readonly baseline_content_sha256: Sha256Digest;
  readonly approved_by: string;
  readonly approved_at: string;
}

export interface BoundedMutationOptions {
  readonly cwd?: string;
  readonly authority?: BoundedMutationAuthority;
  readonly approveBaseline?: (baseline: M3BaselineRuntimeDocument) => Promise<BaselineApprovalRequest | null>;
  readonly approveTasks?: (input: { readonly mode: GoalMode; readonly contract: ContractDocument; readonly tasks: readonly TaskDocument[]; readonly plan: PlanApprovalDocument | null }) => Promise<Sha256Digest | null>;
  readonly approveOwnerAcceptance?: (input: { readonly task: TaskDocument; readonly finalState: WorkflowState }) => Promise<boolean>;
  readonly beforeFinalPostflight?: () => Promise<void> | void;
  readonly releaseLock?: (handle: WorktreeLockHandle) => Promise<void>;
}

export interface BoundedMutationRunResult {
  readonly outcome: "PASS" | "BLOCKED";
  readonly reason: string;
  readonly finalState: WorkflowState | null;
  readonly evidenceRoot?: string;
  readonly hygieneWarning?: string;
}

function fail(code: string, detail: string): never { throw new BoundedWorkflowError(code, detail); }
function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_GOAL", `${label} must be an object`);
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort(); const wanted = [...keys].sort();
  if (actual.length !== wanted.length || actual.some((entry, index) => entry !== wanted[index])) fail("INVALID_GOAL", `${label} has unknown or missing fields`);
}
function text(value: unknown, label: string, max = 16_384): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) fail("INVALID_GOAL", `${label} must be bounded non-empty text`);
  return value;
}
function path(value: unknown, label: string): string {
  const result = text(value, label, 4_096);
  try { assertM4CanonicalPath(result, label); } catch { fail("INVALID_GOAL", `${label} is not a canonical repository path`); }
  return result;
}
function paths(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 10_000) fail("INVALID_GOAL", `${label} must be a bounded array`);
  const result = value.map((entry, index) => path(entry, `${label}[${index}]`)).sort();
  if (new Set(result).size !== result.length) fail("INVALID_GOAL", `${label} has duplicate paths`);
  return result;
}
function ids(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 128) fail("INVALID_GOAL", `${label} must be bounded`);
  const result = value.map((entry, index) => text(entry, `${label}[${index}]`, 128)).sort();
  if (new Set(result).size !== result.length || result.some((entry) => !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(entry))) fail("INVALID_GOAL", `${label} has invalid identifiers`);
  return result;
}
function within(pathValue: string, roots: readonly string[]): boolean { return roots.some((root) => pathValue === root || pathValue.startsWith(`${root}/`)); }
function mode(value: unknown): GoalMode {
  if (value === "DIRECT_LUNA_HIGH" || value === "SINGLE_OWNER_SOL" || value === "ROUTED_DAG") return value;
  return fail("INVALID_GOAL", "execution_mode is unsupported");
}

function normalizeGoal(value: unknown): BoundedMutationGoal & { readonly tasks: readonly CandidateTask[]; readonly baseline_mode: "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY" } {
  const input = asRecord(value, "Goal");
  const allowed = ["objective", "stop_condition", "execution_mode", "scope", "required_outputs", "tasks", "baseline_mode"];
  for (const key of Object.keys(input)) if (!allowed.includes(key)) fail("INVALID_GOAL", "Goal contains executable or unknown authority");
  for (const key of ["objective", "stop_condition", "execution_mode", "scope", "required_outputs"]) if (!(key in input)) fail("INVALID_GOAL", `Goal.${key} is required`);
  const scopeInput = asRecord(input["scope"], "Goal.scope"); exactKeys(scopeInput, ["readable_paths", "editable_paths", "frozen_paths"], "Goal.scope");
  const scope: GoalScope = { readable_paths: paths(scopeInput["readable_paths"], "Goal.scope.readable_paths"), editable_paths: paths(scopeInput["editable_paths"], "Goal.scope.editable_paths"), frozen_paths: paths(scopeInput["frozen_paths"], "Goal.scope.frozen_paths") };
  if (scope.editable_paths.some((entry) => within(entry, scope.frozen_paths)) || scope.frozen_paths.some((entry) => within(entry, scope.editable_paths))) fail("INVALID_GOAL", "editable and frozen scope overlaps");
  const required = paths(input["required_outputs"], "Goal.required_outputs");
  if (required.length === 0 || required.some((entry) => !within(entry, scope.editable_paths))) fail("INVALID_GOAL", "all required outputs must be exact editable paths");
  const selectedMode = mode(input["execution_mode"]);
  const baseline = input["baseline_mode"] === undefined ? "CLEAN_REQUIRED" : input["baseline_mode"];
  if (baseline !== "CLEAN_REQUIRED" && baseline !== "APPROVED_BASELINE_DIRTY") fail("INVALID_GOAL", "baseline_mode is invalid");
  let candidate: CandidateTask[] = [];
  if (input["tasks"] !== undefined) {
    if (!Array.isArray(input["tasks"]) || input["tasks"].length > 8) fail("INVALID_GOAL", "tasks must contain at most eight static leaves");
    candidate = input["tasks"].map((raw, index) => {
      const taskInput = asRecord(raw, `Goal.tasks[${index}]`);
      exactKeys(taskInput, ["task_id", "objective", "editable_paths", "required_outputs", "dependencies"], `Goal.tasks[${index}]`);
      return { task_id: text(taskInput["task_id"], `Goal.tasks[${index}].task_id`, 128), objective: text(taskInput["objective"], `Goal.tasks[${index}].objective`),
        editable_paths: paths(taskInput["editable_paths"], `Goal.tasks[${index}].editable_paths`), required_outputs: paths(taskInput["required_outputs"], `Goal.tasks[${index}].required_outputs`), dependencies: ids(taskInput["dependencies"], `Goal.tasks[${index}].dependencies`) };
    });
  }
  if (selectedMode === "ROUTED_DAG") {
    if (candidate.length < 2 || candidate.length > 8) fail("INVALID_GOAL", "Routed DAG requires 2–8 leaves");
    const seen = new Set<string>();
    for (let index = 0; index < candidate.length; index += 1) {
      const task = candidate[index]!;
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(task.task_id) || seen.has(task.task_id)) fail("INVALID_GOAL", "task IDs must be unique identifiers");
      seen.add(task.task_id);
      if (task.editable_paths.length === 0 || task.required_outputs.length === 0 || task.editable_paths.some((entry) => !within(entry, scope.editable_paths)) || task.required_outputs.some((entry) => !required.includes(entry))) fail("INVALID_GOAL", "routed task scope or output is invalid");
      const expected = index === 0 ? [] : [candidate[index - 1]!.task_id];
      if (canonicalize(task.dependencies) !== canonicalize(expected)) fail("INVALID_GOAL", "Routed DAG must be static sequential leaves");
    }
    if (canonicalize([...candidate.flatMap((task) => task.required_outputs)].sort()) !== canonicalize(required)) fail("INVALID_GOAL", "each expected output must have exactly one routed task owner");
  } else {
    if (candidate.length > 1) fail("INVALID_GOAL", "Direct and Single Owner support exactly one task");
    candidate = candidate.length === 1 ? candidate : [{ task_id: "mutation-task", objective: text(input["objective"], "Goal.objective"), editable_paths: scope.editable_paths, required_outputs: required, dependencies: [] }];
    const only = candidate[0]!;
    if (only.dependencies.length !== 0 || canonicalize(only.required_outputs) !== canonicalize(required)) fail("INVALID_GOAL", "single-task mode must own every required output");
  }
  return Object.freeze({ objective: text(input["objective"], "Goal.objective"), stop_condition: text(input["stop_condition"], "Goal.stop_condition"), execution_mode: selectedMode,
    scope, required_outputs: required, tasks: Object.freeze(candidate), baseline_mode: baseline });
}

function processMetadata() { return { controller_instance_id: "pre-m8-bounded-controller", process_id: Math.max(1, process.pid), invocation_id: "pre-m8-bounded-invocation" }; }
function evidence(value: unknown): { readonly bytes: Buffer; readonly mediaType: string } { return { bytes: Buffer.from(`${canonicalize(value)}\n`, "utf8"), mediaType: "application/json" }; }
function event(type: TransitionEvent["event_type"], payload: Record<string, unknown> = {}): TransitionEvent {
  return identifyContractDocument("pi_gacw_transition_event_v0", { schema_id: "pi_gacw_transition_event_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    event_id: `pre-m8-${type.toLowerCase()}-${sha256Canonical(payload).slice(7, 23)}`, event_type: type, payload }) as TransitionEvent;
}
function fixed(label: string): Sha256Digest { return sha256Canonical({ protocol: "pre-m8-fixed-v1", label }); }
function target(repository: M3RepositoryIdentityDocument): ContractDocument["target_repository"] { return { root: repository.git_toplevel, git_common_dir: repository.git_common_dir, worktree: repository.worktree_root, branch: repository.branch ?? "DETACHED", head: repository.head }; }

function routeMap(): RouteMapDocument {
  const routes = PRODUCT_ROLES.map((logical_role) => {
    const luna = logical_role === "LUNA_EXECUTOR";
    const mutates = logical_role === "LUNA_EXECUTOR" || logical_role === "SOL_OWNER";
    return { logical_role, provider_id: "openai-codex", model_id: luna ? "gpt-5.6-luna" : "gpt-5.6-sol", effort: luna ? "high" as const : "max" as const,
      tool_policy: { policy_id: `pre-m8-${logical_role.toLowerCase()}`, built_in_tools_disabled: true as const, mutation_tool: mutates ? "APPLY_PATCH_SCOPED" as const : "NONE" as const,
        command_gateway: logical_role === "SOL_CLOSEOUT" ? "VERIFICATION_ONLY" as const : logical_role === "SOL_PLANNER" ? "INSPECTION_ONLY" as const : "TASK_AND_VERIFICATION" as const,
        maximum_tool_calls: MAX_TOOL_CALLS_PER_WORKER } };
  });
  return identifyContractDocument("pi_gacw_route_map_v0", { schema_id: "pi_gacw_route_map_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    route_map_projection_id: "route-map-v1", route_map_sha256: fixed("route-map"), routes, fallback: false, provider_managed_multi_agent: false }) as RouteMapDocument;
}
function routeApproval(route: RouteMapDocument): RouteMapApprovalDocument {
  return identifyContractDocument("pi_gacw_route_map_approval_v0", { schema_id: "pi_gacw_route_map_approval_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    route_map_approval_projection_id: "route-map-approval-v1", route_map_approval_sha256: fixed("route-approval"), route_map_sha256: route.route_map_sha256,
    approved_by: "pre-m8-product-owner", approval_token_sha256: fixed("route-token") }) as RouteMapApprovalDocument;
}
function verificationDocuments(commands: readonly M4CommandSpecification[]): ContractDocument["verification_commands"] {
  return commands.map((entry) => ({ command_id: entry.command_id, argv: entry.argv, cwd: entry.cwd === "REPOSITORY_ROOT" ? "repository" : entry.cwd, timeout_ms: entry.timeout_ms, network: "FORBIDDEN" as const }));
}
function acceptance(goal: ReturnType<typeof normalizeGoal>, commands: readonly M4CommandSpecification[]) {
  return [
    ...goal.required_outputs.map((entry, index) => ({ criterion_id: `file-${index + 1}`, description: `Exact expected final workflow-owned path ${entry}`, evidence_kind: "FILE" as const, owner_acceptance: false })),
    ...commands.map((entry) => ({ criterion_id: `command-${entry.command_id}`, description: `Controller-owned verification command ${entry.command_id} passes`, evidence_kind: "COMMAND" as const, owner_acceptance: false })),
  ];
}
function ownerAcceptance(goal: ReturnType<typeof normalizeGoal>) {
  return goal.execution_mode === "SINGLE_OWNER_SOL" ? [{ criterion_id: "owner-acceptance", description: "Declared owner accepts the exact final evidence", evidence_kind: "OWNER_ACCEPTANCE" as const, owner_acceptance: true }] : [];
}
function budget(goal: ReturnType<typeof normalizeGoal>): BudgetDocument {
  const workers = goal.execution_mode === "ROUTED_DAG" ? goal.tasks.length + 2 : 1;
  return identifyContractDocument("pi_gacw_budget_v0", { schema_id: "pi_gacw_budget_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", budget_projection_id: "budget-freeze-v1", budget_sha256: fixed(`budget:${workers}`),
    limits: { max_leaves: goal.execution_mode === "ROUTED_DAG" ? 8 : 1, max_attempts_per_leaf: 1, max_replans: 0, max_worker_invocations: workers, max_model_turns: workers * 32,
      max_tool_calls: workers * MAX_TOOL_CALLS_PER_WORKER, max_input_tokens: 1_000_000, max_output_tokens: 100_000, max_cost_microusd: 5_000_000, max_wall_time_ms: workers * MAX_WALL_TIME_MS },
    usage: { worker_invocation: { value: 0, enforcement_class: "HARD_ENFORCEABLE" }, model_turn: { value: 0, enforcement_class: "SOFT_ENFORCEABLE" }, provider_request: { value: null, enforcement_class: "UNAVAILABLE" }, tool_call: { value: 0, enforcement_class: "HARD_ENFORCEABLE" } } }) as BudgetDocument;
}
function taskDocument(goal: ReturnType<typeof normalizeGoal>, candidate: CandidateTask, index: number, verification: ContractDocument["verification_commands"]): TaskDocument {
  return identifyContractDocument("pi_gacw_task_v0", { schema_id: "pi_gacw_task_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", task_projection_id: "task-packet-v1", task_sha256: fixed(`task:${candidate.task_id}`),
    task_id: candidate.task_id, topological_rank: index, priority: index, dependencies: candidate.dependencies, objective: candidate.objective,
    scope: { readable_paths: goal.scope.readable_paths, editable_paths: candidate.editable_paths, frozen_paths: goal.scope.frozen_paths }, required_inputs: goal.scope.readable_paths,
    required_outputs: candidate.required_outputs, acceptance_criteria: acceptance({ ...goal, required_outputs: candidate.required_outputs }, []) , owner_acceptance_criteria: ownerAcceptance(goal), verification_commands: verification,
    assigned_role: goal.execution_mode === "SINGLE_OWNER_SOL" ? "SOL_OWNER" : "LUNA_EXECUTOR", write_owner: candidate.task_id }) as unknown as TaskDocument;
}
function taskGraph(goal: ReturnType<typeof normalizeGoal>, tasks: readonly TaskDocument[]): TaskGraphDocument | null {
  if (goal.execution_mode !== "ROUTED_DAG") return null;
  return identifyContractDocument("pi_gacw_task_graph_v0", { schema_id: "pi_gacw_task_graph_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", task_graph_projection_id: "task-graph-freeze-v1",
    task_graph_sha256: fixed("task-graph"), tasks: tasks.map((task) => ({ task_id: task.task_id, task_sha256: task.task_sha256, topological_rank: task.topological_rank, priority: task.priority, dependencies: task.dependencies, editable_paths: task.scope.editable_paths, write_owner: task.write_owner })),
    edges: tasks.flatMap((task) => task.dependencies.map((dependency) => ({ from: dependency, to: task.task_id }))), configured_max_leaves: 8, write_ownership: "ONE_ACTIVE_WRITER" }) as TaskGraphDocument;
}
function contract(goal: ReturnType<typeof normalizeGoal>, repository: M3RepositoryIdentityDocument, tasks: readonly TaskDocument[], route: RouteMapApprovalDocument, budgetDocument: BudgetDocument, verification: ContractDocument["verification_commands"], baselineAuthority: Sha256Digest): ContractDocument {
  const criteria = acceptance(goal, verification as unknown as readonly M4CommandSpecification[]);
  return identifyContractDocument("pi_gacw_contract_v0", { schema_id: "pi_gacw_contract_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", contract_projection_id: "contract-freeze-v1", contract_sha256: fixed("contract"),
    objective_sha256: tasks[0]!.task_sha256, target_repository: target(repository), execution_mode: goal.execution_mode, baseline_approval_sha256: baselineAuthority, authority_lock_sha256: fixed("authority-lock"), route_map_approval_sha256: route.route_map_approval_sha256,
    scope: goal.scope, required_inputs: goal.scope.readable_paths, required_outputs: goal.required_outputs, acceptance_criteria: criteria,
    owner_acceptance_criteria: ownerAcceptance(goal), verification_commands: verification,
    command_policy: { shell: false, network: "FORBIDDEN", allowed_executables: [...new Set(verification.map((entry) => entry.argv[0]!))], forbidden_operations: ["INSTALL", "COMMIT", "PUSH", "TAG", "MERGE", "REBASE", "RESET", "RESTORE", "CLEAN", "SWITCH_BRANCH", "MODIFY_REMOTE"] },
    limits: budgetDocument.limits, stopping_conditions: [goal.stop_condition] }) as ContractDocument;
}
function plan(goal: ReturnType<typeof normalizeGoal>, repository: M3RepositoryIdentityDocument, tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, contractDocument: ContractDocument, route: RouteMapDocument, verification: ContractDocument["verification_commands"], budgetDocument: BudgetDocument): PlanApprovalDocument | null {
  if (graph === null) return null;
  return identifyContractDocument("pi_gacw_plan_approval_v0", { schema_id: "pi_gacw_plan_approval_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", plan_approval_projection_id: "plan-approval-v1", plan_approval_sha256: fixed("plan"),
    bindings: { objective_sha256: contractDocument.objective_sha256, target_repository: target(repository), execution_mode: goal.execution_mode, baseline_approval_sha256: contractDocument.baseline_approval_sha256, authority_lock_sha256: contractDocument.authority_lock_sha256, contract_sha256: contractDocument.contract_sha256,
      dag: { task_graph_sha256: graph.task_graph_sha256, edges: graph.edges, ordered_task_packet_identities: tasks.map((task) => task.task_sha256) }, scope: goal.scope, required_inputs: goal.scope.readable_paths, required_outputs: goal.required_outputs,
      acceptance_criteria: contractDocument.acceptance_criteria, owner_acceptance_criteria: ownerAcceptance(goal), verification_commands: verification, command_policy: contractDocument.command_policy,
      logical_routes: route.routes.filter((entry) => ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"].includes(entry.logical_role)), limits: budgetDocument.limits, stopping_conditions: [goal.stop_condition] }, approved_by: "owner-confirmation-required" }) as unknown as PlanApprovalDocument;
}
function reducer(goal: ReturnType<typeof normalizeGoal>, tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, planDocument: PlanApprovalDocument | null, budgetDocument: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest): ReducerPolicy {
  return identifyContractDocument("pi_gacw_reducer_policy_v0", { schema_id: "pi_gacw_reducer_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, execution_mode: goal.execution_mode,
    owner_acceptance_required: goal.execution_mode === "SINGLE_OWNER_SOL", limits: { max_direct_attempts: 1, max_single_owner_mutation_cycles: 1, max_attempts_per_leaf: 1, max_replans: 0, max_leaves: goal.execution_mode === "ROUTED_DAG" ? 8 : 1, max_worker_invocations: budgetDocument.limits.max_worker_invocations },
    tasks: tasks.map((task) => ({ task_id: task.task_id, task_sha256: task.task_sha256, topological_rank: task.topological_rank, priority: task.priority, dependencies: task.dependencies, editable_paths: task.scope.editable_paths })),
    frozen_bindings: { plan_approval_sha256: planDocument?.plan_approval_sha256 ?? null, task_graph_sha256: graph?.task_graph_sha256 ?? null, scope_sha256: scopeSha, acceptance_sha256: acceptanceSha, budget_sha256: budgetDocument.budget_sha256 } }) as ReducerPolicy;
}
function initialIdentities(tasks: readonly TaskDocument[], contractDocument: ContractDocument, planDocument: PlanApprovalDocument | null, graph: TaskGraphDocument | null, budgetDocument: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest): WorkflowState["identities"] {
  return { objective_sha256: tasks[0]!.task_sha256, contract_sha256: contractDocument.contract_sha256, baseline_approval_sha256: contractDocument.baseline_approval_sha256, authority_lock_sha256: contractDocument.authority_lock_sha256,
    plan_approval_sha256: planDocument?.plan_approval_sha256 ?? null, task_graph_sha256: graph?.task_graph_sha256 ?? null, scope_sha256: scopeSha, acceptance_sha256: acceptanceSha, budget_sha256: budgetDocument.budget_sha256 };
}
function canonicalBaselineAuthority(baseline: M3BaselineRuntimeDocument, approval: M3BaselineApprovalRuntimeDocument | null): Sha256Digest {
  if (baseline.baseline_mode === "CLEAN_REQUIRED") {
    if (approval !== null) fail("BASELINE_AUTHORITY_MISMATCH", "clean baseline cannot carry a dirty approval");
    return baseline.content_sha256 as Sha256Digest;
  }
  if (approval === null || approval.baseline_runtime_content_sha256 !== baseline.content_sha256) {
    fail("BASELINE_AUTHORITY_MISMATCH", "dirty baseline approval does not bind the exact runtime baseline");
  }
  return approval.content_sha256 as Sha256Digest;
}

function baselineStagingPolicy(goal: ReturnType<typeof normalizeGoal>, tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, budgetDocument: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest): ReducerPolicy {
  return identifyContractDocument("pi_gacw_reducer_policy_v0", { schema_id: "pi_gacw_reducer_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, execution_mode: goal.execution_mode,
    owner_acceptance_required: goal.execution_mode === "SINGLE_OWNER_SOL", limits: { max_direct_attempts: 1, max_single_owner_mutation_cycles: 1, max_attempts_per_leaf: 1, max_replans: 0, max_leaves: goal.execution_mode === "ROUTED_DAG" ? 8 : 1, max_worker_invocations: budgetDocument.limits.max_worker_invocations },
    tasks: tasks.map((task) => ({ task_id: task.task_id, task_sha256: task.task_sha256, topological_rank: task.topological_rank, priority: task.priority, dependencies: task.dependencies, editable_paths: task.scope.editable_paths })),
    // This graph is M3 capture-only: it has no Contract, M4, M5, or worker path.
    frozen_bindings: { plan_approval_sha256: graph?.task_graph_sha256 ?? null, task_graph_sha256: graph?.task_graph_sha256 ?? null, scope_sha256: scopeSha, acceptance_sha256: acceptanceSha, budget_sha256: budgetDocument.budget_sha256 } }) as ReducerPolicy;
}

function baselineStagingIdentities(tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, budgetDocument: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest, lock: WorktreeLockHandle): WorkflowState["identities"] {
  const stagingIdentity = lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest;
  return { objective_sha256: tasks[0]!.task_sha256, contract_sha256: tasks[0]!.task_sha256, baseline_approval_sha256: stagingIdentity, authority_lock_sha256: stagingIdentity,
    plan_approval_sha256: graph?.task_graph_sha256 ?? null, task_graph_sha256: graph?.task_graph_sha256 ?? null, scope_sha256: scopeSha, acceptance_sha256: acceptanceSha, budget_sha256: budgetDocument.budget_sha256 };
}

async function stageBaselineAuthority(input: {
  readonly stateRoot: string;
  readonly cwd: string;
  readonly goal: ReturnType<typeof normalizeGoal>;
  readonly tasks: readonly TaskDocument[];
  readonly graph: TaskGraphDocument | null;
  readonly budget: BudgetDocument;
  readonly scopeSha: Sha256Digest;
  readonly acceptanceSha: Sha256Digest;
  readonly authority: BoundedMutationAuthority;
  readonly lock: WorktreeLockHandle;
  readonly approveBaseline: BoundedMutationOptions["approveBaseline"];
}): Promise<{ readonly baseline: M3BaselineRuntimeDocument; readonly approval: M3BaselineApprovalRuntimeDocument | null; readonly approvalRequest: BaselineApprovalRequest | null }> {
  await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
  await mkdir(join(input.stateRoot, "locks"), { recursive: true, mode: 0o700 });
  const policy = baselineStagingPolicy(input.goal, input.tasks, input.graph, input.budget, input.scopeSha, input.acceptanceSha);
  let committed = await initializeRunStorage({ stateRoot: input.stateRoot, runId: RUN_ID, policy,
    initialState: createInitialState(policy, baselineStagingIdentities(input.tasks, input.graph, input.budget, input.scopeSha, input.acceptanceSha, input.lock)), processMetadata: processMetadata() });
  const commit = async (type: TransitionEvent["event_type"], index: number, payload: Record<string, unknown> = {}, records: readonly unknown[] = []): Promise<void> => {
    const current = await inspectRunStorage({ stateRoot: input.stateRoot, runId: RUN_ID });
    if (current.status !== "HEALTHY" || current.statePointer === null || current.workflowState === null || current.revision === null) throw new BoundedWorkflowError("BASELINE_STAGING_STATE", "baseline staging state is unavailable");
    committed = await commitTransition({ stateRoot: input.stateRoot, runId: RUN_ID, expectedRevision: current.revision, expectedStatePointerContentSha256: current.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: current.workflowState.content_sha256 as Sha256Digest, transitionId: `pre-m8-baseline-stage-${index}-${type.toLowerCase()}`, policy, event: event(type, payload), evidence: records.map(evidence), processMetadata: processMetadata() });
  };
  await commit("FREEZE_OBJECTIVE", 1); await commit("ACQUIRE_LOCK", 2);
  const capture = await captureBaseline({ stateRoot: input.stateRoot, runId: RUN_ID, requestedPath: input.cwd, mode: input.goal.baseline_mode,
    pathDecisions: input.authority.dirty_baseline_decisions ?? [], instructionFiles: [], authorityFiles: [], allowShallow: false, allowPartialClone: false, lock: input.lock });
  await commit("CAPTURE_BASELINE", 3, { approval_required: input.goal.baseline_mode === "APPROVED_BASELINE_DIRTY" }, [capture.baseline]);
  if (input.goal.baseline_mode === "CLEAN_REQUIRED") {
    await commit("ACCEPT_CLEAN_BASELINE", 4);
    return { baseline: capture.baseline, approval: null, approvalRequest: null };
  }
  await commit("REQUEST_BASELINE_APPROVAL", 4);
  const request = await input.approveBaseline?.(capture.baseline) ?? null;
  if (request === null || request.baseline_content_sha256 !== capture.baseline.content_sha256) {
    throw new BoundedWorkflowError("BASELINE_APPROVAL_MISMATCH", "exact dirty BaselineApproval was not supplied");
  }
  const approval = (await createBaselineApproval({ stateRoot: input.stateRoot, runId: RUN_ID, baseline: capture.baseline, approvedBy: request.approved_by, approvedAt: request.approved_at })).approval;
  await commit("APPROVE_BASELINE", 5, {}, [approval]);
  return { baseline: capture.baseline, approval, approvalRequest: request };
}

function m5Policy(repository: M3RepositoryIdentityDocument, state: WorkflowState, reducerPolicy: ReducerPolicy, contractDocument: ContractDocument, budgetDocument: BudgetDocument, routes: RouteMapDocument, approval: RouteMapApprovalDocument, toolPolicy: M4ScopedToolPolicyDocument, catalog: M4CommandCatalogDocument, goal: ReturnType<typeof normalizeGoal>): M5ControlPolicyDocument {
  const obligations = [
    ...goal.required_outputs.map((value) => ({ declaration: value, direction: "OUTPUT" as const, stage: 1, producer: goal.tasks.find((task) => task.required_outputs.includes(value))!.task_id, consumers: ["contract"], grammar: "LITERAL" as const, evidence_kind: "FILE" as const, literal: value, prefix: null })),
    ...catalog.commands.map((entry) => ({ declaration: `command:${entry.command_id}`, direction: "OUTPUT" as const, stage: 1, producer: goal.tasks.at(-1)!.task_id, consumers: ["contract"], grammar: "LITERAL" as const, evidence_kind: "COMMAND" as const, literal: entry.command_id, prefix: null })),
    ...(goal.execution_mode === "SINGLE_OWNER_SOL" ? [{ declaration: "owner-acceptance", direction: "OUTPUT" as const, stage: 1, producer: goal.tasks[0]!.task_id, consumers: ["contract"], grammar: "LITERAL" as const, evidence_kind: "OWNER_ACCEPTANCE" as const, literal: "ACCEPTED", prefix: null }] : []),
  ].map((entry) => ({ descriptor_sha256: sha256Canonical(entry), ...entry }));
  const roles = goal.execution_mode === "DIRECT_LUNA_HIGH" ? ["LUNA_EXECUTOR"] as const : goal.execution_mode === "SINGLE_OWNER_SOL" ? ["SOL_OWNER"] as const : ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"] as const;
  const leaves = goal.execution_mode === "ROUTED_DAG" ? goal.tasks.length : 1;
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", { schema_id: "pi_gacw_m5_control_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID,
    repository_identity_content_sha256: repository.content_sha256, worktree_key: repository.worktree_key, starting_state_content_sha256: state.content_sha256, objective_sha256: contractDocument.objective_sha256, contract_sha256: contractDocument.contract_sha256, budget_sha256: budgetDocument.budget_sha256,
    route_map_sha256: routes.route_map_sha256, route_map_approval_sha256: approval.route_map_approval_sha256, reducer_policy_content_sha256: reducerPolicy.content_sha256, authority_lock_sha256: contractDocument.authority_lock_sha256, baseline_approval_sha256: contractDocument.baseline_approval_sha256,
    scope_sha256: state.identities.scope_sha256, acceptance_sha256: state.identities.acceptance_sha256, plan_approval_sha256: state.identities.plan_approval_sha256, task_graph_sha256: state.identities.task_graph_sha256, tool_policy_content_sha256: toolPolicy.content_sha256, command_catalog_content_sha256: catalog.content_sha256,
    route_map_approved: true, production_authority: "OWNER_APPROVED", requested_mode: goal.execution_mode,
    route_facts: { hard_sol_conditions: goal.execution_mode === "SINGLE_OWNER_SOL" ? ["JUDGMENT_ACCEPTANCE"] : [], task_count: goal.tasks.length, coherent_single_task: goal.tasks.length === 1, failure_domain_count: goal.tasks.length, deterministic_acceptance: true, ownership_ambiguous: false, leaf_count: leaves, dag_valid: true, leaves_separable: true, unique_write_ownership: true, leaf_acceptance_machine_checkable: true },
    obligations, limits: [
      { dimension: "WORKER_INVOCATION", hard_limit: budgetDocument.limits.max_worker_invocations, soft_limit: budgetDocument.limits.max_worker_invocations, enforcement_class: "HARD_ENFORCEABLE" },
      { dimension: "MODEL_TURN", hard_limit: null, soft_limit: budgetDocument.limits.max_model_turns, enforcement_class: "SOFT_ENFORCEABLE" },
      { dimension: "PROVIDER_REQUEST", hard_limit: null, soft_limit: null, enforcement_class: "UNAVAILABLE" },
      { dimension: "TOOL_CALL", hard_limit: budgetDocument.limits.max_tool_calls, soft_limit: budgetDocument.limits.max_tool_calls, enforcement_class: "HARD_ENFORCEABLE" },
      { dimension: "INPUT_TOKEN", hard_limit: null, soft_limit: budgetDocument.limits.max_input_tokens, enforcement_class: "SOFT_ENFORCEABLE" },
      { dimension: "OUTPUT_TOKEN", hard_limit: null, soft_limit: budgetDocument.limits.max_output_tokens, enforcement_class: "SOFT_ENFORCEABLE" },
      { dimension: "COST_MICROUSD", hard_limit: null, soft_limit: budgetDocument.limits.max_cost_microusd, enforcement_class: "SOFT_ENFORCEABLE" },
      { dimension: "WALL_TIME_MS", hard_limit: null, soft_limit: budgetDocument.limits.max_wall_time_ms, enforcement_class: "SOFT_ENFORCEABLE" },
    ],
    role_reservation_envelopes: roles.map((logical_role) => ({ logical_role, purpose: logical_role === "SOL_CLOSEOUT" ? "REQUIRED_CLOSEOUT" as const : "ORDINARY" as const, amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] })),
    failure_action_table_version: "m5-failure-actions-v1", progress_rule_version: "m5-progress-v1", contract_gate_rule_version: "m5-contract-gate-v1", route_selection_rule_version: "m5-route-selection-v1", insufficient_routing_evidence: "BLOCK",
    maximum_control_decisions: Math.max(16, leaves * 8), maximum_usage_records: budgetDocument.limits.max_worker_invocations, maximum_authority_depth: 64 }) as unknown as M5ControlPolicyDocument;
}

async function environment(repository: M3RepositoryIdentityDocument): Promise<RequiredEnvironment> {
  const python = await resolveExecutable("python3"); const version = await execFileAsync(python, ["--version"], { encoding: "utf8", maxBuffer: 4096 });
  return { node_version: process.version, git_version: repository.git_version, python_version: `${version.stdout}${version.stderr}`.trim(), controller_version: CONTROLLER_VERSION, node_path: await realpath(process.execPath), git_path: await resolveExecutable("git"), python_path: python };
}
async function commandSpecs(repository: M3RepositoryIdentityDocument, commands: readonly ControllerVerificationCommand[], scope: GoalScope): Promise<readonly M4CommandSpecification[]> {
  if (commands.length === 0) fail("MISSING_REQUIRED_VERIFICATION", "positive mutation requires controller-owned verification authority");
  const ids = new Set<string>();
  const specs: M4CommandSpecification[] = [];
  for (const command of commands) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(command.command_id) || ids.has(command.command_id) || !isAbsolute(command.executable) || command.executable !== resolve(command.executable)) fail("INVALID_COMMAND_AUTHORITY", "verification command identity is invalid");
    ids.add(command.command_id); assertM4CanonicalPath(command.cwd, "verification cwd");
    if (!within(command.cwd, scope.readable_paths)) fail("INVALID_COMMAND_AUTHORITY", "verification cwd is outside readable scope");
    const [exePhysical, exeStats, exeBytes, cwdStats, cwdPhysical] = await Promise.all([realpath(command.executable), lstat(command.executable), readFile(command.executable), lstat(join(repository.worktree_root, command.cwd)), realpath(join(repository.worktree_root, command.cwd))]);
    if (!exeStats.isFile() || exeStats.isSymbolicLink() || !cwdStats.isDirectory() || cwdPhysical !== join(repository.worktree_root, command.cwd)) fail("INVALID_COMMAND_AUTHORITY", "verification command executable or cwd is unsafe");
    const argv = [command.executable, ...(command.args ?? [])];
    const readable = (await Promise.all(scope.readable_paths.map(async (entry) => {
      try { const stats = await lstat(join(repository.worktree_root, entry)); return stats.isFile() ? { path: entry, kind: "EXACT" as const } : null; }
      catch { return null; }
    }))).filter((entry): entry is { readonly path: string; readonly kind: "EXACT" } => entry !== null);
    const projection = { command_id: command.command_id, command_class: "VERIFICATION" as const, executable_invocation_path: command.executable, executable_realpath: exePhysical, executable_device: exeStats.dev, executable_inode: exeStats.ino, executable_mode: exeStats.mode & 0o7777, executable_size: exeStats.size, executable_sha256: sha256Bytes(exeBytes), argv, cwd: command.cwd, cwd_realpath: cwdPhysical, cwd_device: cwdStats.dev, cwd_inode: cwdStats.ino,
      execution_inputs: [], environment: [], read_paths: readable, write_paths: [], network_policy: "FORBIDDEN" as const, timeout_ms: command.timeout_ms ?? 60_000, stdout_limit: 65_536, stderr_limit: 65_536, expected_exit_codes: [0], repository_side_effect: "NONE" as const, claimed_paths: [], cleanup_paths: [] };
    specs.push({ ...projection, command_spec_sha256: sha256Canonical(projection) });
  }
  return specs;
}
function toolPolicy(repository: M3RepositoryIdentityDocument, token: M3RepositoryStateTokenDocument, goal: ReturnType<typeof normalizeGoal>): M4ScopedToolPolicyDocument {
  const all = [...new Set([...goal.scope.readable_paths, ...goal.scope.editable_paths, ...goal.scope.frozen_paths])];
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { schema_id: "pi_gacw_scoped_tool_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, policy_id: "pre-m8-bounded-policy", repository_identity_content_sha256: repository.content_sha256, worktree_key: repository.worktree_key, task_scope_identity: token.task_scope_identity,
    readable_paths: goal.scope.readable_paths.map((path) => ({ path, kind: "EXACT" as const })), editable_paths: goal.scope.editable_paths.map((path) => ({ path, kind: "EXACT" as const })), frozen_paths: goal.scope.frozen_paths.map((path) => ({ path, kind: "EXACT" as const })),
    command_readable_paths: goal.scope.readable_paths.map((path) => ({ path, kind: "EXACT" as const })), command_writable_paths: [],
    path_authorities: all.map((path) => ({ path, kind: "EXACT" as const, ownership_class: goal.scope.editable_paths.includes(path) ? "OWNER_ACCEPTED_MUTABLE" as const : "PREEXISTING_UNRELATED" as const, data_class: "PUBLIC_SOURCE" as const, raw_read_approved: true,
      create: goal.scope.editable_paths.includes(path), replace: goal.scope.editable_paths.includes(path), delete: goal.scope.editable_paths.includes(path), mode_change: false })),
    evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M3_POSTFLIGHT", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT", "BOUNDED_WORKER_RESULT"],
    limits: { maximum_patch_bytes: 1_048_576, maximum_read_bytes: 65_536, maximum_hash_bytes: 1_048_576, maximum_search_input_bytes: 65_536, maximum_search_matches: 1_000, maximum_list_entries: 1_000, maximum_list_metadata_bytes: 1_048_576, maximum_command_stdout_bytes: 65_536, maximum_command_stderr_bytes: 65_536, maximum_command_duration_ms: 60_000 } }) as M4ScopedToolPolicyDocument;
}
function catalog(repository: M3RepositoryIdentityDocument, policy: M4ScopedToolPolicyDocument, specs: readonly M4CommandSpecification[]): M4CommandCatalogDocument {
  return identifyContractDocument("pi_gacw_command_catalog_v0", { schema_id: "pi_gacw_command_catalog_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, catalog_id: "pre-m8-controller-owned-verification", repository_identity_content_sha256: repository.content_sha256, tool_policy_content_sha256: policy.content_sha256, commands: specs }) as M4CommandCatalogDocument;
}
function sourceBundle(contractDocument: ContractDocument, budgetDocument: BudgetDocument, routes: RouteMapDocument, approval: RouteMapApprovalDocument, policy: M4ScopedToolPolicyDocument, catalogDocument: M4CommandCatalogDocument, token: M3RepositoryStateTokenDocument, tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, planDocument: PlanApprovalDocument | null): M5AuthoritativeSources {
  return { boundedStaticPreM8: true, contract: contractDocument, budget: budgetDocument, routeMap: routes, routeMapApproval: approval, m4ToolPolicy: policy, m4CommandCatalog: catalogDocument, m3StateTokens: [token], tasks,
    ...(graph === null ? {} : { taskGraphs: [graph] }), ...(planDocument === null ? {} : { planApprovals: [planDocument] }) };
}
function usage(policy: M5ControlPolicyDocument, decision: M5ControlDecisionDocument, result: Awaited<ReturnType<typeof runBoundedWorker>>["result"], mode: GoalMode, role: BoundedWorkerRoute["logicalRole"]): M5UsageEvidenceDocument {
  const value = result.actual_usage; const measure = (dimension: M5UsageEvidenceDocument["measurements"][number]["dimension"], amount: number | null, basis: M5UsageEvidenceDocument["measurements"][number]["basis"], enforcement: M5UsageEvidenceDocument["measurements"][number]["enforcement_class"]) => ({ dimension, amount, basis, enforcement_class: enforcement });
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", { schema_id: "pi_gacw_m5_usage_evidence_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, policy_content_sha256: policy.content_sha256, originating_state_content_sha256: decision.current_state_content_sha256,
    operation_id: decision.operation_id!, operation_kind: "WORKER_INVOCATION", execution_mode: mode, logical_role: role, reservation_decision_content_sha256: decision.content_sha256, source_layer: "CONTROLLER", source_kind: "BOUNDED_WORKER_RESULT", source_record_content_sha256: result.content_sha256,
    measurements: [measure("WORKER_INVOCATION", value.worker_invocations, "VALIDATED", "HARD_ENFORCEABLE"), measure("TOOL_CALL", value.m4_tool_calls, "VALIDATED", "HARD_ENFORCEABLE"), measure("MODEL_TURN", value.model_turns, value.model_turns === null ? "UNAVAILABLE" : "OBSERVED", value.model_turns === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"), measure("PROVIDER_REQUEST", value.provider_requests, value.provider_requests === null ? "UNAVAILABLE" : "OBSERVED", value.provider_requests === null ? "UNAVAILABLE" : "OBSERVABLE_ONLY"), measure("INPUT_TOKEN", value.input_tokens, value.input_tokens === null ? "UNAVAILABLE" : "OBSERVED", value.input_tokens === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"), measure("OUTPUT_TOKEN", value.output_tokens, value.output_tokens === null ? "UNAVAILABLE" : "OBSERVED", value.output_tokens === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"), measure("COST_MICROUSD", value.cost_microusd, value.cost_microusd === null ? "UNAVAILABLE" : "OBSERVED", value.cost_microusd === null ? "UNAVAILABLE" : "SOFT_ENFORCEABLE"), measure("WALL_TIME_MS", value.wall_time_ms, "OBSERVED", "SOFT_ENFORCEABLE")], disposition: "COMPLETED", duration_ms: value.wall_time_ms }) as M5UsageEvidenceDocument;
}

type BoundedWorkerRunner = typeof runBoundedWorker;

/** Shared controller implementation; production and explicit test provenance differ only at the worker entrypoint. */
async function runBoundedMutationWorkflowImpl(value: unknown, options: BoundedMutationOptions, workerRunner: BoundedWorkerRunner): Promise<BoundedMutationRunResult> {
  let goal: ReturnType<typeof normalizeGoal>;
  try { goal = normalizeGoal(value); } catch (error: unknown) { return { outcome: "BLOCKED", reason: error instanceof Error ? error.message : "INVALID_GOAL", finalState: null }; }
  if (options.authority === undefined) return { outcome: "BLOCKED", reason: "CONTROLLER_VERIFICATION_AUTHORITY_REQUIRED", finalState: null };
  let ownedRoot: string | undefined; let stateRoot = ""; let temporaryRoot = ""; let createdStateRoot = false;
  let lock: WorktreeLockHandle | undefined; let finalState: WorkflowState | null = null; let reason = "BLOCKED"; let outcome: "PASS" | "BLOCKED" = "BLOCKED"; let hygieneWarning: string | undefined; let releaseCertain = true;
  let terminalBlock: ((detail: string) => Promise<void>) | undefined;
  try {
    const cwd = options.cwd ?? process.cwd(); const repository = await resolveRepositoryIdentity({ requestedPath: cwd, requireHead: true });
    const specs = await commandSpecs(repository, options.authority.verification_commands, goal.scope); const verification = verificationDocuments(specs);
    ownedRoot = join(tmpdir(), `pi-pre-m8-bounded-${repository.worktree_key.slice(7)}`); stateRoot = join(ownedRoot, "state"); temporaryRoot = join(ownedRoot, "tools");
    createdStateRoot = await lstat(stateRoot).then(() => false, () => true);
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await mkdir(join(stateRoot, "locks"), { recursive: true, mode: 0o700 });
    lock = await acquireWorktreeLock({ stateRoot, repository });
    if (!createdStateRoot) throw new BoundedWorkflowError("STALE_OR_CONCURRENT_STATE_ROOT", "existing M3 controller state root is not resumed or replaced");
    await mkdir(temporaryRoot, { recursive: true, mode: 0o700 });
    const route = routeMap(); const routeApprovalDocument = routeApproval(route); const budgetDocument = budget(goal); const tasks = goal.tasks.map((candidate, index) => taskDocument(goal, candidate, index, verification));
    const graph = taskGraph(goal, tasks); const scopeSha = m3ScopeIdentity(goal.scope.editable_paths, goal.scope.frozen_paths);
    const acceptanceSha = sha256Canonical(acceptance(goal, verification as unknown as readonly M4CommandSpecification[]));
    // The staging graph has no M4/M5/worker path. It obtains the exact M3
    // baseline authority that the final execution graph must reproduce.
    const stagedBaseline = await stageBaselineAuthority({ stateRoot: join(ownedRoot, "baseline-staging"), cwd, goal, tasks, graph, budget: budgetDocument,
      scopeSha, acceptanceSha, authority: options.authority, lock: lock!, approveBaseline: options.approveBaseline });
    const baselineAuthority = canonicalBaselineAuthority(stagedBaseline.baseline, stagedBaseline.approval);
    const contractDocument = contract(goal, repository, tasks, routeApprovalDocument, budgetDocument, verification, baselineAuthority);
    const planDocument = plan(goal, repository, tasks, graph, contractDocument, route, verification, budgetDocument);
    const reducerPolicy = reducer(goal, tasks, graph, planDocument, budgetDocument, scopeSha, acceptanceSha);
    const initialState = createInitialState(reducerPolicy, initialIdentities(tasks, contractDocument, planDocument, graph, budgetDocument, scopeSha, acceptanceSha));
    let committed = await initializeRunStorage({ stateRoot, runId: RUN_ID, policy: reducerPolicy, initialState, processMetadata: processMetadata() });
    const commit = async (type: TransitionEvent["event_type"], index: number, payload: Record<string, unknown> = {}, records: readonly unknown[] = []): Promise<void> => {
      const current = await inspectRunStorage({ stateRoot, runId: RUN_ID });
      if (current.status !== "HEALTHY" || current.statePointer === null || current.workflowState === null || current.revision === null) throw new Error("committed controller state is unavailable");
      committed = await commitTransition({ stateRoot, runId: RUN_ID, expectedRevision: current.revision, expectedStatePointerContentSha256: current.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: current.workflowState.content_sha256 as Sha256Digest,
        transitionId: `pre-m8-${index}-${type.toLowerCase()}`, policy: reducerPolicy, event: event(type, payload), evidence: records.map(evidence), processMetadata: processMetadata() });
      finalState = committed.workflowState;
    };
    await commit("FREEZE_OBJECTIVE", 1); await commit("ACQUIRE_LOCK", 2);
    const baselineCapture = await captureBaseline({ stateRoot, runId: RUN_ID, requestedPath: cwd, mode: goal.baseline_mode, pathDecisions: options.authority.dirty_baseline_decisions ?? [], instructionFiles: [], authorityFiles: [], allowShallow: false, allowPartialClone: false, lock });
    const baseline = baselineCapture.baseline;
    if (baseline.content_sha256 !== stagedBaseline.baseline.content_sha256) {
      throw new BoundedWorkflowError("BASELINE_AUTHORITY_DRIFT", "final M3 baseline differs from the exact staged baseline authority");
    }
    await commit("CAPTURE_BASELINE", 3, { approval_required: goal.baseline_mode === "APPROVED_BASELINE_DIRTY" }, [baseline]);
    let approval: M3BaselineApprovalRuntimeDocument | null = null;
    if (goal.baseline_mode === "APPROVED_BASELINE_DIRTY") {
      const requested = stagedBaseline.approvalRequest;
      if (requested === null || stagedBaseline.approval === null) throw new BoundedWorkflowError("BASELINE_APPROVAL_MISMATCH", "staged dirty BaselineApproval is absent");
      await commit("REQUEST_BASELINE_APPROVAL", 4);
      approval = (await createBaselineApproval({ stateRoot, runId: RUN_ID, baseline, approvedBy: requested.approved_by, approvedAt: requested.approved_at })).approval;
      if (approval.content_sha256 !== stagedBaseline.approval.content_sha256) {
        throw new BoundedWorkflowError("BASELINE_AUTHORITY_DRIFT", "final dirty BaselineApproval differs from the staged exact approval");
      }
      await commit("APPROVE_BASELINE", 5, {}, [approval]);
    } else await commit("ACCEPT_CLEAN_BASELINE", 5);
    if (canonicalBaselineAuthority(baseline, approval) !== baselineAuthority) {
      throw new BoundedWorkflowError("BASELINE_AUTHORITY_DRIFT", "final canonical baseline authority differs from the frozen Contract root");
    }
    const full = await runFullPreflight({ stateRoot, runId: RUN_ID, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval, instructionFiles: [], authorityFiles: [], requiredEnvironment: await environment(repository), taskScopeIdentity: scopeSha, allowShallow: false, allowPartialClone: false, lock });
    await commit("PASS_FULL_PREFLIGHT", 6, {}, [full.preflight]);
    const m4Policy = toolPolicy(repository, full.acceptedState, goal); const commandCatalog = catalog(repository, m4Policy, specs);
    const gateway = await createScopedToolGateway({ stateRoot, runId: RUN_ID, repository, baseline, acceptedState: full.acceptedState, lock: lock!, instructionFiles: [], authorityFiles: [], editablePaths: goal.scope.editable_paths, frozenPaths: goal.scope.frozen_paths, taskScopeIdentity: scopeSha, toolPolicy: m4Policy, commandCatalog, temporaryRoot });
    const m5 = m5Policy(repository, initialState, reducerPolicy, contractDocument, budgetDocument, route, routeApprovalDocument, m4Policy, commandCatalog, goal);
    let sources = sourceBundle(contractDocument, budgetDocument, route, routeApprovalDocument, m4Policy, commandCatalog, gateway.acceptedState, tasks, graph, planDocument);
    const kernel = createControlDecisionKernel({ stateRoot, runId: RUN_ID, policy: m5, reducerPolicy, runAuthority: { repositoryIdentity: repository, contract: contractDocument, routeMap: route, routeMapApproval: routeApprovalDocument }, authoritativeSources: sources, production: true });
    const expected = async () => {
      const inspection = await inspectRunStorage({ stateRoot, runId: RUN_ID });
      if (inspection.status !== "HEALTHY" || inspection.statePointer === null || inspection.workflowState === null || inspection.revision === null) throw new Error("committed controller state is unavailable");
      return { inspection, expectedRevision: inspection.revision, expectedStatePointerContentSha256: inspection.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: inspection.workflowState.content_sha256 as Sha256Digest };
    };
    const decision = async (intent: "VALIDATE_CONTRACT" | "SELECT_ROUTE" | "AUTHORIZE_WORK" | "EVALUATE_TERMINAL" | "BLOCK", transitionId: string, extra: Record<string, unknown> = {}) => {
      const current = await expected(); const result = await kernel.evaluateControlDecision({ intent, expectedRevision: current.expectedRevision, expectedStatePointerContentSha256: current.expectedStatePointerContentSha256, expectedWorkflowStateContentSha256: current.expectedWorkflowStateContentSha256, transitionId, processMetadata: processMetadata(), authoritativeSources: sources, availableLogicalRoles: PRODUCT_ROLES, ...extra } as Parameters<typeof kernel.evaluateControlDecision>[0]);
      finalState = result.workflowState; return result.decision;
    };
    terminalBlock = async (detail: string): Promise<void> => {
      const current = await expected(); const state = current.inspection.workflowState!;
      if (state.phase === "PASS" || state.phase === "BLOCKED") return;
      const blocked = await kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: current.expectedRevision, expectedStatePointerContentSha256: current.expectedStatePointerContentSha256,
        expectedWorkflowStateContentSha256: current.expectedWorkflowStateContentSha256, transitionId: `pre-m8-block-${sha256Canonical({ detail, state: state.content_sha256 }).slice(7, 23)}`, 
        blockReason: detail.slice(0, 255), processMetadata: processMetadata(), authoritativeSources: sources, availableLogicalRoles: PRODUCT_ROLES });
      finalState = blocked.workflowState;
    };
    const validated = await decision("VALIDATE_CONTRACT", "pre-m8-validate"); if (validated.outcome === "BLOCK") throw new BoundedWorkflowError("M5_CONTRACT", validated.blocking_reason ?? "contract blocked");
    const selected = await decision("SELECT_ROUTE", "pre-m8-route"); if (selected.outcome === "BLOCK") throw new BoundedWorkflowError("M5_ROUTE", selected.blocking_reason ?? "route blocked");
    const approvalDigest = async (): Promise<Sha256Digest> => {
      const approved = await options.approveTasks?.({ mode: goal.execution_mode, contract: contractDocument, tasks, plan: planDocument }) ?? null;
      const expectedApproval = goal.execution_mode === "ROUTED_DAG" ? planDocument!.content_sha256 : contractDocument.content_sha256;
      if (approved === null || approved !== expectedApproval) throw new BoundedWorkflowError("EXECUTION_APPROVAL_MISMATCH", "exact final Contract-bound execution authority or PlanApproval was not supplied");
      return approved;
    };
    // Exact execution authority is supplied before *any* M5 worker reservation,
    // including the routed planner. The existing approved reducer event roots
    // the exact Contract or Plan evidence that this callback verified.
    await approvalDigest();
    const usages: M5UsageEvidenceDocument[] = [];
    let publishedUsageCount = 0;
    const invoke = async (operationId: string, task: TaskDocument | null, workerPlan: PlanApprovalDocument | null, profile: "MUTATION_EXECUTOR" | "SOL_PLANNER" | "SOL_CLOSEOUT", routeRole: BoundedWorkerRoute["logicalRole"]): Promise<Awaited<ReturnType<typeof runBoundedWorker>>["result"]> => {
      sources = { ...sources, m3StateTokens: [gateway.acceptedState] };
      const admission = await decision("AUTHORIZE_WORK", `pre-m8-authorize-${operationId}`, { operationId, usageEvidence: usages.slice(publishedUsageCount) });
      publishedUsageCount = usages.length;
      if (admission.outcome !== "AUTHORIZE" || admission.reservation === null) throw new BoundedWorkflowError("M5_ADMISSION", admission.blocking_reason ?? "M5 refused worker");
      const selectedRoute = route.routes.find((entry) => entry.logical_role === routeRole);
      if (selectedRoute === undefined) throw new Error("product route is absent");
      const invocationState = gateway.acceptedState;
      const execution = await workerRunner({ stateRoot, runId: RUN_ID, operationId, reservation: admission, task, taskGraph: graph, plan: workerPlan, inputStateToken: invocationState, lock: lock!, gateway,
        route: { logicalRole: routeRole, providerId: selectedRoute.provider_id, modelId: selectedRoute.model_id, effort: selectedRoute.effort }, profile,
        systemPrompt: `Pre-M8 bounded ${profile}; use only supplied M4 tools; no retry, replan, commands, shell, filesystem, or network.`,
        userPrompt: profile === "SOL_PLANNER" ? `${goal.objective}\nSubmit exactly candidate_plan_sha256:${workerPlan!.content_sha256}; topology, scope, and identity expansion are forbidden.` : task?.objective ?? goal.objective,
        allowedReadPaths: goal.scope.readable_paths, allowedEditPaths: task?.scope.editable_paths ?? [], maxM4ToolCalls: MAX_TOOL_CALLS_PER_WORKER,
        maxModelTurns: (() => { const remaining = admission.budget.find((entry) => entry.dimension === "MODEL_TURN")?.soft_remaining; if (remaining === undefined || remaining === null) throw new BoundedWorkflowError("M5_MODEL_TURN_AUTHORITY", "M5 did not provide an enforceable model-turn admission remainder"); return remaining; })(), deadlineMs: MAX_WALL_TIME_MS });
      const [inspection, records, m5Records] = await Promise.all([inspectRunStorage({ stateRoot, runId: RUN_ID }), readBoundedWorkerRecords({ stateRoot, runId: RUN_ID }), readM5ManagedRecords({ stateRoot, runId: RUN_ID })]);
      const persistedInvocation = records.invocations.find((entry) => entry.content_sha256 === execution.invocation.content_sha256); const persistedResult = records.results.find((entry) => entry.content_sha256 === execution.result.content_sha256);
      const reservationStates = m5Records.workflowStates.filter((entry) => entry.content_sha256 === admission.current_state_content_sha256);
      if (persistedInvocation === undefined || persistedResult === undefined || reservationStates.length !== 1) throw new BoundedWorkflowError("WORKER_RECORD_MISSING", "persisted bounded worker record or reservation state is absent");
      const reservationState = reservationStates[0]!;
      const resolved = resolveAuthoritativeBoundedExecution({ invocation: persistedInvocation, result: persistedResult, reservation: admission, reservationState, policy: m5, baseline, approval, stateToken: invocationState, task, taskGraph: graph, plan: workerPlan, classifications: inspection.managedRecordClassifications });
      if (!resolved.accepted) throw new BoundedWorkflowError("WORKER_AUTHORITY", resolved.reason ?? "worker result rejected");
      if (profile === "MUTATION_EXECUTOR" && !resolved.acceptedM4Evidence.length) throw new BoundedWorkflowError("WORKER_NO_MUTATION_EVIDENCE", "mutation executor produced no accepted M4 evidence");
      sources = { ...sources, boundedWorkerResults: [...(sources.boundedWorkerResults ?? []), persistedResult] };
      usages.push(usage(m5, admission, persistedResult, goal.execution_mode, routeRole));
      return persistedResult;
    };
    if (goal.execution_mode === "DIRECT_LUNA_HIGH") {
      await commit("VALIDATE_DIRECT_CONTRACT", 10); await commit("REQUEST_DIRECT_APPROVAL", 11);
      await commit("APPROVE_DIRECT_TASK", 12, {}, [contractDocument, ...tasks]); await commit("PASS_DIRECT_FAST_PREFLIGHT", 13);
      await invoke("direct-worker", tasks[0]!, null, "MUTATION_EXECUTOR", "LUNA_EXECUTOR"); await commit("COMPLETE_DIRECT_ATTEMPT", 14); await commit("PASS_DIRECT_POSTFLIGHT", 15);
    } else if (goal.execution_mode === "SINGLE_OWNER_SOL") {
      await commit("VALIDATE_SINGLE_OWNER_CONTRACT", 20); await commit("REQUEST_SINGLE_OWNER_APPROVAL", 21);
      await commit("APPROVE_SINGLE_OWNER_TASK", 22, {}, [contractDocument, ...tasks]); await commit("PASS_SINGLE_OWNER_FAST_PREFLIGHT", 23);
      await invoke("single-owner-worker", tasks[0]!, null, "MUTATION_EXECUTOR", "SOL_OWNER"); await commit("ADMIT_SINGLE_OWNER_MUTATION_CYCLE", 24); await commit("COMPLETE_SINGLE_OWNER", 25); await commit("PASS_SINGLE_OWNER_POSTFLIGHT", 26);
    } else {
      const plannerResult = await invoke("planner", null, planDocument, "SOL_PLANNER", "SOL_PLANNER");
      if (plannerResult.advisory_report !== `candidate_plan_sha256:${planDocument!.content_sha256}`) throw new BoundedWorkflowError("PLAN_EXPANSION_OR_IDENTITY_MISMATCH", "planner did not submit the exact static candidate plan identity");
      await commit("COMPLETE_PLAN", 30); await commit("REQUEST_PLAN_APPROVAL", 31);
      await commit("APPROVE_PLAN", 32, { plan_approval_sha256: planDocument!.plan_approval_sha256, task_graph_sha256: graph!.task_graph_sha256 }, [planDocument, graph, ...tasks]); await commit("ACTIVATE_DAG", 33);
      for (const [index, task] of tasks.entries()) { await commit("SELECT_READY_LEAF", 40 + index * 4); await invoke(`leaf-${task.task_id}`, task, planDocument, "MUTATION_EXECUTOR", "LUNA_EXECUTOR"); await commit("COMPLETE_LEAF_ATTEMPT", 41 + index * 4); await commit("PASS_LEAF_POSTFLIGHT", 42 + index * 4); await commit("LEAF_VERIFICATION_PASSED", 43 + index * 4); }
      await invoke("closeout", null, planDocument, "SOL_CLOSEOUT", "SOL_CLOSEOUT"); await commit("COMPLETE_CLOSEOUT", 90);
    }
    const commandResults = [] as Awaited<ReturnType<typeof gateway.run_verification_command>>["record"][];
    for (const spec of specs) { const result = await gateway.run_verification_command({ commandId: spec.command_id, stateTokenContentSha256: gateway.acceptedState.content_sha256 as Sha256Digest }); commandResults.push(result.record); }
    await options.beforeFinalPostflight?.();
    const postflight = await runPostflight({ stateRoot, runId: RUN_ID, acceptedState: gateway.acceptedState, baseline, instructionFiles: [], authorityFiles: [], editablePaths: goal.scope.editable_paths, frozenPaths: goal.scope.frozen_paths, taskScopeIdentity: scopeSha, claimedWorkflowPaths: [], lock: lock! });
    if (canonicalize(postflight.postflight.workflow_owned_delta.map((entry) => entry.path).sort()) !== canonicalize(goal.required_outputs)) throw new BoundedWorkflowError("OUTPUT_DELTA_MISMATCH", "final M3 output delta does not exactly equal expected outputs");
    if (commandResults.length !== specs.length || commandResults.some((entry) => entry.outcome !== "PASS")) throw new BoundedWorkflowError("VERIFICATION_FAILED", "a required controller-owned verification command failed");
    sources = { ...sources, m3StateTokens: [postflight.acceptedState], m3Postflights: [postflight.postflight], m4CommandResults: commandResults };
    const obligations: M5ObligationEvidenceInput[] = [
      ...goal.required_outputs.map((value) => ({ descriptorSha256: m5.obligations.find((entry) => entry.literal === value)!.descriptor_sha256 as Sha256Digest, value, evidenceContentSha256: postflight.postflight.content_sha256 as Sha256Digest })),
      ...commandResults.map((entry) => ({ descriptorSha256: m5.obligations.find((candidate) => candidate.literal === entry.command_id)!.descriptor_sha256 as Sha256Digest, value: entry.command_id, evidenceContentSha256: entry.content_sha256 as Sha256Digest })),
      ...(goal.execution_mode === "SINGLE_OWNER_SOL" ? [{ descriptorSha256: m5.obligations.find((entry) => entry.literal === "ACCEPTED")!.descriptor_sha256 as Sha256Digest, value: "ACCEPTED", evidenceContentSha256: postflight.postflight.content_sha256 as Sha256Digest }] : []),
    ];
    let terminal = await decision("EVALUATE_TERMINAL", "pre-m8-terminal", { usageEvidence: usages.slice(publishedUsageCount), obligationEvidence: obligations });
    publishedUsageCount = usages.length;
    const afterTerminal = (await expected()).inspection.workflowState!;
    if (afterTerminal.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE") {
      if (!(await options.approveOwnerAcceptance?.({ task: tasks[0]!, finalState: afterTerminal }) ?? false)) throw new BoundedWorkflowError("OWNER_ACCEPTANCE_REJECTED", "declared owner acceptance was not supplied");
      terminal = await decision("EVALUATE_TERMINAL", "pre-m8-owner-terminal", { obligationEvidence: obligations });
    }
    finalState = (await expected()).inspection.workflowState!;
    outcome = terminal.outcome === "PASS" && finalState!.phase === "PASS" ? "PASS" : "BLOCKED"; reason = outcome === "PASS" ? "PASS" : terminal.blocking_reason ?? "M5_TERMINAL_BLOCK";
  } catch (error: unknown) {
    reason = error instanceof Error ? `${error instanceof BoundedWorkflowError ? error.code : "BLOCKED"}: ${error.message}` : "BLOCKED_CONTROLLER_FAILURE";
    try { await terminalBlock?.(reason); }
    catch (terminalError: unknown) { reason = `BLOCKED_TERMINALIZATION_UNCERTAIN:${reason}:${terminalError instanceof Error ? terminalError.message : String(terminalError)}`; }
    try { finalState = (await inspectRunStorage({ stateRoot, runId: RUN_ID })).workflowState; }
    catch { /* The owned temporary root is still cleaned only after lock release. */ }
    outcome = "BLOCKED";
  } finally {
    if (lock !== undefined) {
      try { await (options.releaseLock ?? releaseWorktreeLock)(lock); }
      catch (error: unknown) { releaseCertain = false; outcome = "BLOCKED"; reason = `BLOCKED_CLEANUP_UNCERTAIN:LOCK_RELEASE:${error instanceof Error ? error.message : String(error)}`; hygieneWarning = "worktree lock release could not be proved"; }
    }
    if (ownedRoot !== undefined && createdStateRoot && releaseCertain) try { await rm(ownedRoot, { recursive: true, force: true }); }
    catch (error: unknown) { hygieneWarning ??= `temporary evidence cleanup failed: ${error instanceof Error ? error.message : String(error)}`; }
  }
  return { outcome, reason, finalState, ...(hygieneWarning === undefined ? {} : { hygieneWarning }) };
}

/** Production entrypoint: runtime provenance is fixed to the verified official Pi adapter. */
export async function runBoundedMutationWorkflow(value: unknown, options: BoundedMutationOptions = {}): Promise<BoundedMutationRunResult> {
  return runBoundedMutationWorkflowImpl(value, options, runBoundedWorker);
}

/** Package-internal test-only entrypoint; the worker itself requires registered faux provenance. */
export async function runBoundedMutationWorkflowForTests(value: unknown, options: BoundedMutationOptions = {}): Promise<BoundedMutationRunResult> {
  return runBoundedMutationWorkflowImpl(value, options, runBoundedWorkerForTests);
}
