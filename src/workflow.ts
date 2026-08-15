import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

import { canonicalize } from "./canonical-json/index.js";
import { createControlDecisionKernel } from "./control/index.js";
import type { M5AuthoritativeSources } from "./control/types.js";
import { deepFreezeDetached } from "./control/policy.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { m3ScopeIdentity } from "./identity/m3-scope.js";
import {
  commitTransition,
  initializeRunStorage,
  inspectRunStorage,
  type CommittedRunState,
} from "./persistence/index.js";
import {
  acquireWorktreeLock,
  captureBaseline,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFullPreflight,
  type FingerprintedFileInput,
  type RequiredEnvironment,
  type WorktreeLockHandle,
} from "./repository/index.js";
import { createScopedToolGateway } from "./scoped-tools/index.js";

import { assertM4CanonicalPath } from "./secure-fs/path.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type BudgetDocument,
  type ContractDocument,
  type M3BaselineRuntimeDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandCatalogDocument,
  type M4ScopedToolPolicyDocument,
  type M4ToolResultDocument,
  type M5ControlDecisionDocument,
  type M6WorkerInvocationDocument,
  type M6WorkerResultDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type ProcessMetadata,
  type ReducerPolicy,
  type RouteMapApprovalDocument,
  type RouteMapDocument,
  type TaskDocument,
  type TransitionEvent,
  type WorkflowState,
} from "./schemas/index.js";
import { createInitialState } from "./state-machine/index.js";
import { classifyM6Authority } from "./persistence/m6-authority.js";
import { readM5ManagedRecords, readM6WorkerRecords } from "./persistence/store.js";
import { readM4Record } from "./scoped-tools/records.js";
import { runDirectReadOnlyLunaWorker, type M6DirectReadOnlyWorkerInput, type M6WorkerExecutionResult } from "./pi-adapter/worker.js";
import type { ScopedToolGateway } from "./scoped-tools/types.js";
import { resolveExecutable } from "./repository/lock.js";

const execFileAsync = promisify(execFile);

const RUN_ID = "m7-workflow";
const TASK_ID = "task-only";
const WRITE_OWNER = "m7-read-only";
const CONTROLLER_VERSION = "0.1.0" as const;

// These are the current fixed M6/M4 bounds. The compiler accepts no value
// outside the existing worker and scoped-tool envelopes.
const M6_MODEL_TURNS = 2;
const M6_TOOL_CALLS = 2;
const M6_MAX_READ_BYTES = 65_536;
const M6_MAX_WALL_TIME_MS = 120_000;
const M4_MAX_COMMAND_TIME_MS = 1_800_000;
const M4_MAX_STDOUT_BYTES = 4_194_304;
const M4_MAX_STDERR_BYTES = 4_194_304;
const M4_MAX_HASH_BYTES = 67_108_864;
const M4_MAX_SEARCH_INPUT_BYTES = 67_108_864;
const M4_MAX_SEARCH_MATCHES = 10_000;
const M4_MAX_LIST_ENTRIES = 100_000;
const M4_MAX_LIST_METADATA_BYTES = 67_108_864;
const M4_MAX_PATCH_BYTES = 1_048_576;

const GOAL_KEYS = [
  "objective",
  "resources",
  "non_goals",
  "deliverable",
  "acceptance_criteria",
  "verification_commands",
  "budget",
  "stop_condition",
] as const;
const RESOURCE_KEYS = ["path", "max_bytes", "data_class"] as const;
const ACCEPTANCE_KEYS = ["criterion_id", "description", "evidence_kind", "owner_acceptance"] as const;
const BUDGET_KEYS = [
  "max_worker_invocations",
  "max_model_turns",
  "max_tool_calls",
  "max_wall_time_ms",
  "max_read_bytes",
] as const;

export type WorkflowOutcome = "PASS" | "BLOCKED";
export type GoalDataClass = "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE" | "HASH_ONLY";
export type GoalEvidenceKind = "DIGEST";

export interface GoalResource {
  readonly path: string;
  readonly max_bytes: number;
  readonly data_class: GoalDataClass;
}

export interface GoalAcceptanceCriterion {
  readonly criterion_id: string;
  readonly description: string;
  readonly evidence_kind: GoalEvidenceKind;
  readonly owner_acceptance: false;
}

export interface GoalBudget {
  readonly max_worker_invocations: 1;
  readonly max_model_turns: 2;
  readonly max_tool_calls: 2;
  readonly max_wall_time_ms: number;
  readonly max_read_bytes: number;
}

/**
 * The only M7 input shape. It is intentionally an ordinary ephemeral value,
 * not a document or a persisted authority record.
 */
export interface EphemeralGoal {
  readonly objective: string;
  readonly resources: readonly GoalResource[];
  readonly non_goals: readonly string[];
  readonly deliverable: string;
  readonly acceptance_criteria: readonly GoalAcceptanceCriterion[];
  /** Compatibility field; V0 accepts only an empty array and creates no executable authority. */
  readonly verification_commands: readonly [];
  readonly budget: GoalBudget;
  readonly stop_condition: string;
}

export interface PreparedWorkflow {
  readonly goal: EphemeralGoal;
  readonly task: TaskDocument;
  readonly preview: string;
}

export interface WorkflowRunResult {
  readonly outcome: WorkflowOutcome;
  readonly reason: string;
  readonly task: TaskDocument;
  /** Present only when durable post-admission terminalization is uncertain. */
  readonly evidenceRoot?: string;
  readonly finalState?: WorkflowState;
  readonly m5Decision?: M5ControlDecisionDocument;
  readonly m6?: M6WorkerExecutionResult;
}

export class WorkflowValidationError extends Error {
  public readonly code: "INVALID_GOAL" | "APPROVAL_REQUIRED" | "APPROVAL_MISMATCH" | "GOAL_TAMPERED";

  public constructor(code: WorkflowValidationError["code"], message: string) {
    super(message);
    this.name = "WorkflowValidationError";
    this.code = code;
  }
}

export interface WorkflowExecutionHookContext {
  readonly goal: EphemeralGoal;
  readonly task: TaskDocument;
  readonly approvedContentSha256: Sha256Digest;
  readonly cwd: string;
}

export interface WorkflowExecutionOptions {
  readonly cwd?: string;
  /** Package-private deterministic seam used by M7 tests; production uses M3/M4/M5/M6 below. */
  readonly executeApproved?: (context: WorkflowExecutionHookContext) => Promise<WorkflowRunResult>;
  /** Package-private M6 seam used only with a verifier-owned faux runtime. */
  readonly worker?: (input: M6DirectReadOnlyWorkerInput) => Promise<M6WorkerExecutionResult>;
  /** Package-private public-credential seam used only with deterministic tests. */
  readonly credentialReader?: (providerId: string) => Promise<unknown> | unknown;
  readonly signal?: AbortSignal;
}

function invalid(message: string): never {
  throw new WorkflowValidationError("INVALID_GOAL", message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((entry, index) => entry !== wanted[index])) {
    invalid(`${label} has unknown or missing fields`);
  }
}

function nonempty(value: unknown, label: string, maximum = 16_384): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) invalid(`${label} must be a bounded non-empty string`);
  return value;
}

function safeInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) invalid(`${label} is outside its authority bound`);
  return value as number;
}

function sortedStrings(values: readonly string[]): readonly string[] {
  return [...values].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
}

function canonicalSorted<T>(values: readonly T[]): readonly T[] {
  return [...values].sort((left, right) => {
    const a = canonicalize(left); const b = canonicalize(right);
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function normalizeGoal(value: unknown): EphemeralGoal {
  const input = record(value, "Goal");
  exactKeys(input, GOAL_KEYS, "Goal");
  const objective = nonempty(input["objective"], "Goal.objective");
  const deliverable = nonempty(input["deliverable"], "Goal.deliverable");
  const stopCondition = nonempty(input["stop_condition"], "Goal.stop_condition");

  if (!Array.isArray(input["resources"]) || input["resources"].length !== 1) {
    invalid("Goal.resources must contain exactly one primary readable resource for the existing M6 worker");
  }
  const resources = (input["resources"] as readonly unknown[]).map((candidate, index): GoalResource => {
    const resource = record(candidate, `Goal.resources[${index}]`);
    exactKeys(resource, RESOURCE_KEYS, `Goal.resources[${index}]`);
    const path = nonempty(resource["path"], `Goal.resources[${index}].path`, 4096);
    try { assertM4CanonicalPath(path, `Goal.resources[${index}].path`); }
    catch { invalid(`Goal.resources[${index}].path is not a canonical repository-relative path`); }
    if (isAbsolute(path)) invalid(`Goal.resources[${index}].path must be repository-relative`);
    const maxBytes = safeInteger(resource["max_bytes"], `Goal.resources[${index}].max_bytes`, 1, M6_MAX_READ_BYTES);
    const dataClass = resource["data_class"];
    if (dataClass !== "PUBLIC_SOURCE" && dataClass !== "PRIVATE_SOURCE" && dataClass !== "SENSITIVE" && dataClass !== "HASH_ONLY") {
      invalid(`Goal.resources[${index}].data_class is unsupported`);
    }
    if (dataClass === "HASH_ONLY") invalid("The existing M6 raw-read worker cannot admit HASH_ONLY as its primary resource");
    return { path, max_bytes: maxBytes, data_class: dataClass };
  });
  if (new Set(resources.map((resource) => resource.path)).size !== resources.length) invalid("Goal.resources contains duplicate normalized paths");

  if (!Array.isArray(input["non_goals"]) || (input["non_goals"] as readonly unknown[]).length > 128) invalid("Goal.non_goals must be a bounded string array");
  const nonGoals = (input["non_goals"] as readonly unknown[]).map((candidate, index) => nonempty(candidate, `Goal.non_goals[${index}]`, 4096));
  if (new Set(nonGoals).size !== nonGoals.length) invalid("Goal.non_goals contains duplicate values");

  if (!Array.isArray(input["acceptance_criteria"]) || (input["acceptance_criteria"] as readonly unknown[]).length !== 1) {
    invalid("M7 V0 accepts exactly one fixed report acceptance criterion");
  }
  const acceptance = (input["acceptance_criteria"] as readonly unknown[]).map((candidate, index): GoalAcceptanceCriterion => {
    const criterion = record(candidate, `Goal.acceptance_criteria[${index}]`);
    exactKeys(criterion, ACCEPTANCE_KEYS, `Goal.acceptance_criteria[${index}]`);
    const criterionId = nonempty(criterion["criterion_id"], `Goal.acceptance_criteria[${index}].criterion_id`, 128);
    if (criterionId !== "report") invalid("M7 V0 supports only the fixed report acceptance criterion");
    const description = nonempty(criterion["description"], `Goal.acceptance_criteria[${index}].description`);
    if (criterion["evidence_kind"] !== "DIGEST") invalid("M7 V0 acceptance must use the fixed authoritative DIGEST evidence shape");
    if (criterion["owner_acceptance"] !== false) invalid("M7 does not admit owner-acceptance criteria");
    return { criterion_id: criterionId, description, evidence_kind: "DIGEST", owner_acceptance: false };
  });

  if (!Array.isArray(input["verification_commands"]) || (input["verification_commands"] as readonly unknown[]).length !== 0) {
    invalid("M7 V0 does not admit Goal verification commands or executable authority");
  }
  const verification = [] as const;

  const budgetInput = record(input["budget"], "Goal.budget");
  exactKeys(budgetInput, BUDGET_KEYS, "Goal.budget");
  const workerInvocations = safeInteger(budgetInput["max_worker_invocations"], "Goal.budget.max_worker_invocations", 1, 1);
  const modelTurns = safeInteger(budgetInput["max_model_turns"], "Goal.budget.max_model_turns", M6_MODEL_TURNS, M6_MODEL_TURNS);
  const toolCalls = safeInteger(budgetInput["max_tool_calls"], "Goal.budget.max_tool_calls", M6_TOOL_CALLS, M6_TOOL_CALLS);
  const wallTime = safeInteger(budgetInput["max_wall_time_ms"], "Goal.budget.max_wall_time_ms", 1, M6_MAX_WALL_TIME_MS);
  const readBytes = safeInteger(budgetInput["max_read_bytes"], "Goal.budget.max_read_bytes", 1, M6_MAX_READ_BYTES);
  const budget = {
    max_worker_invocations: workerInvocations,
    max_model_turns: modelTurns,
    max_tool_calls: toolCalls,
    max_wall_time_ms: wallTime,
    max_read_bytes: readBytes,
  } as GoalBudget;

  return {
    objective,
    resources: canonicalSorted(resources),
    non_goals: sortedStrings(nonGoals),
    deliverable,
    acceptance_criteria: canonicalSorted(acceptance),
    verification_commands: [] as const,
    budget,
    stop_condition: stopCondition,
  };
}

function goalEnvelope(goal: EphemeralGoal): Record<string, unknown> {
  return {
    version: "m7-ephemeral-goal-v1",
    objective: goal.objective,
    resources: goal.resources,
    non_goals: goal.non_goals,
    deliverable: goal.deliverable,
    acceptance_criteria: goal.acceptance_criteria,
    verification_commands: goal.verification_commands,
    budget: goal.budget,
    stop_condition: goal.stop_condition,
    capability: {
      mode: "READ_ONLY_REPORT_ONLY",
      editable_paths: [],
      mutation_tools: [],
      network: "FORBIDDEN",
      workers: 1,
    },
  };
}

function taskFromGoal(goal: EphemeralGoal): TaskDocument {
  const envelope = goalEnvelope(goal);
  const objective = `${goal.objective}\n\n[M7_EPHEMERAL_GOAL_V1]\n${canonicalize(envelope)}`;
  if (Buffer.byteLength(objective, "utf8") > 16_384) invalid("The complete execution-bound Goal envelope exceeds the Task objective bound");
  const task = identifyContractDocument("pi_gacw_task_v0", {
    schema_id: "pi_gacw_task_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    task_projection_id: "task-packet-v1",
    task_sha256: `sha256:${"0".repeat(64)}`,
    task_id: TASK_ID,
    topological_rank: 0,
    priority: 0,
    dependencies: [],
    objective,
    scope: {
      readable_paths: goal.resources.map((resource) => resource.path),
      editable_paths: [],
      frozen_paths: [],
    },
    required_inputs: goal.resources.map((resource) => resource.path),
    required_outputs: ["report"],
    acceptance_criteria: goal.acceptance_criteria,
    owner_acceptance_criteria: [],
    verification_commands: goal.verification_commands,
    assigned_role: "LUNA_EXECUTOR",
    write_owner: WRITE_OWNER,
  }) as unknown as TaskDocument;
  assertDocumentValid("pi_gacw_task_v0", task);
  return task;
}

export function validateGoal(value: unknown): EphemeralGoal {
  try { return deepFreezeDetached(normalizeGoal(value)); }
  catch (error: unknown) {
    if (error instanceof WorkflowValidationError) throw error;
    throw new WorkflowValidationError("INVALID_GOAL", `Goal validation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function compileGoalToTask(value: unknown): TaskDocument {
  const goal = validateGoal(value);
  return taskFromGoal(goal);
}

export function prepareWorkflow(value: unknown): PreparedWorkflow {
  const goal = validateGoal(value);
  const task = taskFromGoal(goal);
  const prepared = deepFreezeDetached({ goal, task, preview: `${canonicalize(task)}\n` });
  return prepared as PreparedWorkflow;
}

function assertDigest(value: unknown, label: string): asserts value is Sha256Digest {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) throw new WorkflowValidationError("APPROVAL_MISMATCH", `${label} is not a SHA-256 content identity`);
}

function revalidateApproval(prepared: PreparedWorkflow, approvedContentSha256: string): PreparedWorkflow {
  assertDigest(approvedContentSha256, "approved TaskDocument.content_sha256");
  let recompiled: TaskDocument;
  try { recompiled = taskFromGoal(prepared.goal); }
  catch (error: unknown) { throw new WorkflowValidationError("GOAL_TAMPERED", `Post-approval Goal recompilation failed: ${error instanceof Error ? error.message : String(error)}`); }
  if (prepared.task.content_sha256 !== approvedContentSha256 || recompiled.content_sha256 !== approvedContentSha256 || canonicalize(recompiled) !== canonicalize(prepared.task)) {
    throw new WorkflowValidationError("APPROVAL_MISMATCH", "Approved TaskDocument identity does not match the revalidated ephemeral Goal");
  }
  return prepared;
}

function processMetadata(): ProcessMetadata {
  return {
    controller_instance_id: "m7-controller",
    process_id: Math.max(1, process.pid),
    invocation_id: "m7-invocation",
  };
}

function transitionEvent(eventType: TransitionEvent["event_type"], payload: Record<string, unknown> = {}): TransitionEvent {
  return identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    event_id: `m7-${eventType.toLowerCase()}-${sha256Canonical(payload).slice(7, 23)}`,
    event_type: eventType,
    payload,
  }) as unknown as TransitionEvent;
}

function canonicalEvidence(value: unknown): { readonly bytes: Buffer; readonly mediaType: string } {
  return { bytes: Buffer.from(`${canonicalize(value)}\n`, "utf8"), mediaType: "application/json" };
}

async function commitEvent(
  stateRoot: string,
  committed: Pick<CommittedRunState, "statePointer" | "workflowState">,
  reducerPolicy: ReducerPolicy,
  eventType: TransitionEvent["event_type"],
  index: number,
  payload: Record<string, unknown> = {},
  evidence: readonly { readonly bytes: Buffer; readonly mediaType: string }[] = [],
): Promise<CommittedRunState> {
  return commitTransition({
    stateRoot,
    runId: reducerPolicy.run_id,
    expectedRevision: committed.statePointer.revision,
    expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
    transitionId: `m7-${index}-${eventType.toLowerCase()}`,
    policy: reducerPolicy,
    event: transitionEvent(eventType, payload),
    evidence,
    processMetadata: processMetadata(),
  });
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

function fixedIdentity(label: string): Sha256Digest {
  return sha256Canonical({ protocol: "m7-fixed-authority-v1", label });
}

function routeMap(): RouteMapDocument {
  const roles = ["SOL_OWNER", "SOL_PLANNER", "SOL_REPLAN", "SOL_CLOSEOUT", "LUNA_EXECUTOR", "TERRA_EXECUTOR", "BENCHMARK_VERIFIER", "BENCHMARK_SELECTOR"] as const;
  const routes = roles.map((logical_role) => ({
    logical_role,
    provider_id: "openai-codex",
    model_id: logical_role === "TERRA_EXECUTOR" ? "gpt-5.6-terra" : "gpt-5.6-luna",
    effort: logical_role === "LUNA_EXECUTOR" || logical_role === "TERRA_EXECUTOR" ? "high" as const : "max" as const,
    tool_policy: {
      policy_id: `m7-${logical_role.toLowerCase()}`,
      built_in_tools_disabled: true as const,
      mutation_tool: "NONE" as const,
      command_gateway: logical_role === "SOL_CLOSEOUT" ? "VERIFICATION_ONLY" as const : "INSPECTION_ONLY" as const,
      maximum_tool_calls: M6_TOOL_CALLS,
    },
  }));
  return identifyContractDocument("pi_gacw_route_map_v0", {
    schema_id: "pi_gacw_route_map_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    route_map_projection_id: "route-map-v1",
    route_map_sha256: `sha256:${"0".repeat(64)}`,
    routes,
    fallback: false,
    provider_managed_multi_agent: false,
  }) as unknown as RouteMapDocument;
}

function routeMapApproval(route: RouteMapDocument): RouteMapApprovalDocument {
  return identifyContractDocument("pi_gacw_route_map_approval_v0", {
    schema_id: "pi_gacw_route_map_approval_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    route_map_approval_projection_id: "route-map-approval-v1",
    route_map_approval_sha256: `sha256:${"0".repeat(64)}`,
    route_map_sha256: route.route_map_sha256,
    approved_by: "m7-owner",
    approval_token_sha256: fixedIdentity("route-map-approval-token"),
  }) as unknown as RouteMapApprovalDocument;
}

function budgetDocument(goal: EphemeralGoal): BudgetDocument {
  return identifyContractDocument("pi_gacw_budget_v0", {
    schema_id: "pi_gacw_budget_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    budget_projection_id: "budget-freeze-v1",
    budget_sha256: `sha256:${"0".repeat(64)}`,
    limits: {
      max_leaves: 1,
      max_attempts_per_leaf: 1,
      max_replans: 0,
      max_worker_invocations: goal.budget.max_worker_invocations,
      max_model_turns: goal.budget.max_model_turns,
      max_tool_calls: goal.budget.max_tool_calls,
      max_input_tokens: 1_000_000,
      max_output_tokens: 100_000,
      max_cost_microusd: 5_000_000,
      max_wall_time_ms: goal.budget.max_wall_time_ms,
    },
    usage: {
      worker_invocation: { value: 0, enforcement_class: "HARD_ENFORCEABLE" },
      model_turn: { value: 0, enforcement_class: "SOFT_ENFORCEABLE" },
      provider_request: { value: null, enforcement_class: "UNAVAILABLE" },
      tool_call: { value: 0, enforcement_class: "HARD_ENFORCEABLE" },
    },
  }) as unknown as BudgetDocument;
}

function contractDocument(goal: EphemeralGoal, task: TaskDocument, routeApproval: RouteMapApprovalDocument, budget: BudgetDocument): ContractDocument {
  return identifyContractDocument("pi_gacw_contract_v0", {
    schema_id: "pi_gacw_contract_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    contract_projection_id: "contract-freeze-v1",
    contract_sha256: `sha256:${"0".repeat(64)}`,
    objective_sha256: task.task_sha256,
    target_repository: {
      root: "M7_REPOSITORY_ROOT_PENDING",
      git_common_dir: "M7_GIT_COMMON_DIR_PENDING",
      worktree: "M7_WORKTREE_PENDING",
      branch: "M7_BRANCH_PENDING",
      head: "0123456789012345678901234567890123456789",
    },
    execution_mode: "DIRECT_LUNA_HIGH",
    baseline_approval_sha256: fixedIdentity("clean-baseline"),
    authority_lock_sha256: fixedIdentity("empty-authority-lock"),
    route_map_approval_sha256: routeApproval.route_map_approval_sha256,
    scope: task.scope,
    required_inputs: task.required_inputs,
    required_outputs: task.required_outputs,
    acceptance_criteria: goal.acceptance_criteria,
    owner_acceptance_criteria: [],
    verification_commands: [],
    command_policy: {
      shell: false,
      network: "FORBIDDEN",
      allowed_executables: [],
      forbidden_operations: ["INSTALL", "COMMIT", "PUSH", "TAG", "MERGE", "REBASE", "RESET", "RESTORE", "CLEAN", "SWITCH_BRANCH", "MODIFY_REMOTE"],
    },
    limits: {
      max_leaves: 1,
      max_attempts_per_leaf: 1,
      max_replans: 0,
      max_worker_invocations: budget.limits.max_worker_invocations,
      max_model_turns: goal.budget.max_model_turns,
      max_tool_calls: goal.budget.max_tool_calls,
      max_input_tokens: 1_000_000,
      max_output_tokens: 100_000,
      max_cost_microusd: 5_000_000,
      max_wall_time_ms: goal.budget.max_wall_time_ms,
    },
    stopping_conditions: [goal.stop_condition],
  }) as unknown as ContractDocument;
}

function reducerPolicy(goal: EphemeralGoal, task: TaskDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest, budget: BudgetDocument): ReducerPolicy {
  return identifyContractDocument("pi_gacw_reducer_policy_v0", {
    schema_id: "pi_gacw_reducer_policy_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: RUN_ID,
    execution_mode: "DIRECT_LUNA_HIGH",
    owner_acceptance_required: false,
    limits: {
      max_direct_attempts: 1,
      max_single_owner_mutation_cycles: 1,
      max_attempts_per_leaf: 1,
      max_replans: 0,
      max_leaves: 1,
      max_worker_invocations: budget.limits.max_worker_invocations,
    },
    tasks: [{
      task_id: task.task_id,
      task_sha256: task.task_sha256,
      topological_rank: task.topological_rank,
      priority: task.priority,
      dependencies: task.dependencies,
      editable_paths: [],
    }],
    frozen_bindings: {
      plan_approval_sha256: null,
      task_graph_sha256: null,
      scope_sha256: scopeSha,
      acceptance_sha256: acceptanceSha,
      budget_sha256: budget.budget_sha256,
    },
  }) as unknown as ReducerPolicy;
}

function m5Policy(
  repository: M3RepositoryIdentityDocument,
  initialState: WorkflowState,
  reducer: ReducerPolicy,
  contract: ContractDocument,
  budget: BudgetDocument,
  route: RouteMapDocument,
  routeApproval: RouteMapApprovalDocument,
  toolPolicy: M4ScopedToolPolicyDocument,
  catalog: M4CommandCatalogDocument,
  scopeSha: Sha256Digest,
  acceptanceSha: Sha256Digest,
): M5ControlPolicyDocument {
  const dimensions = [
    ["WORKER_INVOCATION", budget.limits.max_worker_invocations, budget.limits.max_worker_invocations, "HARD_ENFORCEABLE"],
    ["MODEL_TURN", 2, 2, "HARD_ENFORCEABLE"],
    ["PROVIDER_REQUEST", null, null, "UNAVAILABLE"],
    ["TOOL_CALL", 2, 2, "HARD_ENFORCEABLE"],
    ["INPUT_TOKEN", null, null, "UNAVAILABLE"],
    ["OUTPUT_TOKEN", null, null, "UNAVAILABLE"],
    ["COST_MICROUSD", null, null, "UNAVAILABLE"],
    ["WALL_TIME_MS", contract.limits.max_wall_time_ms, contract.limits.max_wall_time_ms, "HARD_ENFORCEABLE"],
  ] as const;
  return identifyContractDocument("pi_gacw_m5_control_policy_v0", {
    schema_id: "pi_gacw_m5_control_policy_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: RUN_ID,
    repository_identity_content_sha256: repository.content_sha256,
    worktree_key: repository.worktree_key,
    starting_state_content_sha256: initialState.content_sha256,
    objective_sha256: contract.objective_sha256,
    contract_sha256: contract.contract_sha256,
    budget_sha256: budget.budget_sha256,
    route_map_sha256: route.route_map_sha256,
    route_map_approval_sha256: routeApproval.route_map_approval_sha256,
    reducer_policy_content_sha256: reducer.content_sha256,
    authority_lock_sha256: contract.authority_lock_sha256,
    baseline_approval_sha256: contract.baseline_approval_sha256,
    scope_sha256: scopeSha,
    acceptance_sha256: acceptanceSha,
    plan_approval_sha256: null,
    task_graph_sha256: null,
    tool_policy_content_sha256: toolPolicy.content_sha256,
    command_catalog_content_sha256: catalog.content_sha256,
    route_map_approved: true,
    production_authority: "OWNER_APPROVED",
    requested_mode: "DIRECT_LUNA_HIGH",
    route_facts: {
      hard_sol_conditions: [],
      task_count: 1,
      coherent_single_task: true,
      failure_domain_count: 1,
      deterministic_acceptance: true,
      ownership_ambiguous: false,
      leaf_count: 1,
      dag_valid: true,
      leaves_separable: true,
      unique_write_ownership: true,
      leaf_acceptance_machine_checkable: true,
    },
    obligations: acceptanceObligationsFromContract(),
    limits: dimensions.map(([dimension, hard_limit, soft_limit, enforcement_class]) => ({ dimension, hard_limit, soft_limit, enforcement_class })),
    role_reservation_envelopes: [{ logical_role: "LUNA_EXECUTOR", purpose: "ORDINARY", amounts: [{ dimension: "WORKER_INVOCATION", amount: 1 }] }],
    failure_action_table_version: "m5-failure-actions-v1",
    progress_rule_version: "m5-progress-v1",
    contract_gate_rule_version: "m5-contract-gate-v1",
    route_selection_rule_version: "m5-route-selection-v1",
    insufficient_routing_evidence: "BLOCK",
    maximum_control_decisions: 32,
    maximum_usage_records: 8,
    maximum_authority_depth: 64,
  }) as unknown as M5ControlPolicyDocument;
}

function acceptanceObligationsFromContract(): M5ControlPolicyDocument["obligations"] {
  const report = {
    declaration: "report",
    direction: "OUTPUT" as const,
    stage: 1,
    producer: TASK_ID,
    consumers: ["contract"],
    grammar: "LITERAL" as const,
    evidence_kind: "DIGEST" as const,
    literal: "COMPLETED",
    prefix: null,
  };
  return [{ descriptor_sha256: sha256Canonical(report), ...report }];
}

function m4Limits(goal: EphemeralGoal) {
  return {
    maximum_patch_bytes: M4_MAX_PATCH_BYTES,
    maximum_read_bytes: Math.min(goal.budget.max_read_bytes, goal.resources[0]!.max_bytes),
    maximum_hash_bytes: M4_MAX_HASH_BYTES,
    maximum_search_input_bytes: M4_MAX_SEARCH_INPUT_BYTES,
    maximum_search_matches: M4_MAX_SEARCH_MATCHES,
    maximum_list_entries: M4_MAX_LIST_ENTRIES,
    maximum_list_metadata_bytes: M4_MAX_LIST_METADATA_BYTES,
    maximum_command_stdout_bytes: M4_MAX_STDOUT_BYTES,
    maximum_command_stderr_bytes: M4_MAX_STDERR_BYTES,
    maximum_command_duration_ms: Math.min(M4_MAX_COMMAND_TIME_MS, goal.budget.max_wall_time_ms),
  } as const;
}

async function fingerprintInputs(): Promise<{ readonly instructions: readonly FingerprintedFileInput[]; readonly authorities: readonly FingerprintedFileInput[] }> {
  // M7 does not invent authority files. Repository-local M3 authority is empty
  // unless a future existing controller supplies it explicitly.
  return { instructions: [], authorities: [] };
}

async function requiredEnvironment(repository: M3RepositoryIdentityDocument): Promise<RequiredEnvironment> {
  const pythonPath = await resolveExecutable("python3");
  const version = await execFileAsync(pythonPath, ["--version"], { encoding: "utf8", maxBuffer: 4096 });
  return {
    node_version: process.version,
    git_version: repository.git_version,
    python_version: `${version.stdout}${version.stderr}`.trim(),
    controller_version: CONTROLLER_VERSION,
    node_path: await realpath(process.execPath),
    git_path: await resolveExecutable("git"),
    python_path: pythonPath,
  };
}

async function toolPolicy(
  repository: M3RepositoryIdentityDocument,
  task: TaskDocument,
  m3State: M3RepositoryStateTokenDocument,
  goal: EphemeralGoal,
): Promise<M4ScopedToolPolicyDocument> {
  const resource = goal.resources[0]!;
  const dataClass = resource.data_class === "HASH_ONLY" ? "HASH_ONLY" : resource.data_class;
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
    schema_id: "pi_gacw_scoped_tool_policy_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: RUN_ID,
    policy_id: "m7-read-only-policy",
    repository_identity_content_sha256: repository.content_sha256,
    worktree_key: repository.worktree_key,
    task_scope_identity: m3State.task_scope_identity,
    readable_paths: [{ path: resource.path, kind: "EXACT" }],
    editable_paths: [],
    frozen_paths: [],
    command_readable_paths: [],
    command_writable_paths: [],
    path_authorities: [{
      path: resource.path,
      kind: "EXACT",
      ownership_class: "PREEXISTING_UNRELATED",
      data_class: dataClass,
      raw_read_approved: true,
      create: false,
      replace: false,
      delete: false,
      mode_change: false,
    }],
    evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M4_TOOL_REQUEST", "M4_TOOL_RESULT", "M4_COMMAND_RESULT"],
    limits: m4Limits(goal),
  }) as unknown as M4ScopedToolPolicyDocument;
}

function catalog(repository: M3RepositoryIdentityDocument): M4CommandCatalogDocument {
  return identifyContractDocument("pi_gacw_command_catalog_v0", {
    schema_id: "pi_gacw_command_catalog_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: RUN_ID,
    catalog_id: "m7-controller-owned-empty-catalog",
    repository_identity_content_sha256: repository.content_sha256,
    tool_policy_content_sha256: `sha256:${"0".repeat(64)}`,
    commands: [],
  }) as unknown as M4CommandCatalogDocument;
}

function withCatalogPolicy(catalogDocument: M4CommandCatalogDocument, policy: M4ScopedToolPolicyDocument): M4CommandCatalogDocument {
  return identifyContractDocument("pi_gacw_command_catalog_v0", {
    ...catalogDocument,
    content_sha256: undefined,
    tool_policy_content_sha256: policy.content_sha256,
  }) as unknown as M4CommandCatalogDocument;
}

function initialIdentities(task: TaskDocument, contract: ContractDocument, budget: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest): WorkflowState["identities"] {
  return {
    objective_sha256: task.task_sha256 as Sha256Digest,
    contract_sha256: contract.contract_sha256,
    baseline_approval_sha256: contract.baseline_approval_sha256,
    authority_lock_sha256: contract.authority_lock_sha256,
    plan_approval_sha256: null,
    task_graph_sha256: null,
    scope_sha256: scopeSha,
    acceptance_sha256: acceptanceSha,
    budget_sha256: budget.budget_sha256,
  };
}

function sourceBundle(
  contract: ContractDocument,
  budget: BudgetDocument,
  route: RouteMapDocument,
  approval: RouteMapApprovalDocument,
  policy: M4ScopedToolPolicyDocument,
  catalogDocument: M4CommandCatalogDocument,
  m3State: M3RepositoryStateTokenDocument,
): M5AuthoritativeSources {
  return {
    contract,
    budget,
    routeMap: route,
    routeMapApproval: approval,
    m4ToolPolicy: policy,
    m4CommandCatalog: catalogDocument,
    m3StateTokens: [m3State],
  };
}

function expectedInput(stateRoot: string, state: WorkflowState, pointer: { readonly content_sha256: string; readonly revision: number }): { readonly expectedRevision: number; readonly expectedStatePointerContentSha256: Sha256Digest; readonly expectedWorkflowStateContentSha256: Sha256Digest } {
  return {
    expectedRevision: pointer.revision,
    expectedStatePointerContentSha256: pointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: state.content_sha256 as Sha256Digest,
  };
}

async function currentExpected(stateRoot: string, runId: string) {
  const inspection = await inspectRunStorage({ stateRoot, runId });
  if (inspection.status !== "HEALTHY" || inspection.workflowState === null || inspection.statePointer === null || inspection.revision === null) throw new Error("M7 committed workflow state is unavailable");
  return { inspection, ...expectedInput(stateRoot, inspection.workflowState, inspection.statePointer) };
}

function usageEvidence(
  policy: M5ControlPolicyDocument,
  decision: M5ControlDecisionDocument,
  result: M6WorkerResultDocument,
): M5UsageEvidenceDocument {
  const usage = result.usage;
  const amount = (dimension: string, value: number | null, basis: "VALIDATED" | "OBSERVED" | "REPORTED" | "UNAVAILABLE", enforcement_class: M5UsageEvidenceDocument["measurements"][number]["enforcement_class"]) => ({ dimension, amount: value, basis, enforcement_class });
  const measurements = [
    amount("WORKER_INVOCATION", 1, "VALIDATED", "HARD_ENFORCEABLE"),
    amount("MODEL_TURN", usage.model_turns, "OBSERVED", "HARD_ENFORCEABLE"),
    amount("PROVIDER_REQUEST", usage.provider_requests, usage.provider_requests === null ? "UNAVAILABLE" : "OBSERVED", usage.provider_requests === null ? "UNAVAILABLE" : "HARD_ENFORCEABLE"),
    amount("TOOL_CALL", usage.tool_calls, "OBSERVED", "HARD_ENFORCEABLE"),
    amount("INPUT_TOKEN", usage.input_tokens, "UNAVAILABLE", "UNAVAILABLE"),
    amount("OUTPUT_TOKEN", usage.output_tokens, "UNAVAILABLE", "UNAVAILABLE"),
    amount("COST_MICROUSD", usage.cost_microusd, "UNAVAILABLE", "UNAVAILABLE"),
    amount("WALL_TIME_MS", usage.wall_time_ms, "OBSERVED", "HARD_ENFORCEABLE"),
  ] as const;
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: policy.run_id,
    policy_content_sha256: policy.content_sha256,
    originating_state_content_sha256: decision.current_state_content_sha256,
    operation_id: decision.operation_id!,
    operation_kind: "WORKER_INVOCATION",
    execution_mode: "DIRECT_LUNA_HIGH",
    logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: decision.content_sha256,
    source_layer: "M5",
    source_kind: "M5_CONTROL_DECISION",
    source_record_content_sha256: decision.content_sha256,
    measurements,
    disposition: "COMPLETED",
    duration_ms: usage.wall_time_ms,
  }) as unknown as M5UsageEvidenceDocument;
}

function blockedM6UsageEvidence(
  policy: M5ControlPolicyDocument,
  decision: M5ControlDecisionDocument,
): M5UsageEvidenceDocument {
  return identifyContractDocument("pi_gacw_m5_usage_evidence_v0", {
    schema_id: "pi_gacw_m5_usage_evidence_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: policy.run_id,
    policy_content_sha256: policy.content_sha256,
    originating_state_content_sha256: decision.current_state_content_sha256,
    operation_id: decision.operation_id!,
    operation_kind: "WORKER_INVOCATION",
    execution_mode: "DIRECT_LUNA_HIGH",
    logical_role: "LUNA_EXECUTOR",
    reservation_decision_content_sha256: decision.content_sha256,
    source_layer: "M5",
    source_kind: "M5_CONTROL_DECISION",
    source_record_content_sha256: decision.content_sha256,
    measurements: [{ dimension: "WORKER_INVOCATION", amount: 0, basis: "VALIDATED", enforcement_class: "HARD_ENFORCEABLE" }],
    disposition: "BLOCKED_BEFORE_START",
    duration_ms: null,
  }) as unknown as M5UsageEvidenceDocument;
}

const PI_CODING_AGENT_SPECIFIER: string = "@earendil-works/pi-coding-agent";
const PI_AI_SPECIFIER: string = "@earendil-works/pi-ai";
type CredentialReader = (providerId: string) => Promise<unknown> | unknown;

async function publicCredentialStore(providerId: string, reader?: CredentialReader): Promise<unknown> {
  const moduleValue: unknown = await import(PI_CODING_AGENT_SPECIFIER);
  if (moduleValue === null || typeof moduleValue !== "object" ||
      (moduleValue as Record<string, unknown>)["VERSION"] !== "0.83.0" ||
      typeof (moduleValue as Record<string, unknown>)["readStoredCredential"] !== "function") {
    throw new Error("Public Pi 0.83.0 credential boundary is unavailable");
  }
  const publicReader = reader ?? ((moduleValue as Record<string, unknown>)["readStoredCredential"] as CredentialReader);
  const credential = await publicReader(providerId);
  if (credential === undefined) throw new Error("Public Pi credential is unavailable for the selected provider");
  const aiModule: unknown = await import(PI_AI_SPECIFIER);
  if (aiModule === null || typeof aiModule !== "object" || typeof (aiModule as Record<string, unknown>)["InMemoryCredentialStore"] !== "function") {
    throw new Error("Public Pi InMemoryCredentialStore boundary is unavailable");
  }
  const Store = (aiModule as Record<string, unknown>)["InMemoryCredentialStore"] as new () => { modify: (id: string, fn: (current: unknown) => Promise<unknown>) => Promise<unknown> };
  const store = new Store();
  await store.modify(providerId, async () => credential);
  return store;
}

interface ResolvedM6Execution {
  readonly invocation: M6WorkerInvocationDocument;
  readonly result: M6WorkerResultDocument;
  readonly replayed: boolean;
  readonly m4Read?: M4ToolResultDocument;
  readonly evidence: readonly { readonly bytes: Buffer; readonly mediaType: string }[];
}

function returnedDigest(value: unknown, label: string): Sha256Digest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`M6 ${label} locator is missing`);
  const digest = (value as Record<string, unknown>)["content_sha256"];
  if (typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(digest)) throw new Error(`M6 ${label} locator is schema-invalid`);
  return digest as Sha256Digest;
}

function managedClass(
  inspection: Awaited<ReturnType<typeof inspectRunStorage>>,
  kind: string,
  digest: string,
): string | undefined {
  return inspection.managedRecordClassifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest)?.classification;
}

async function exactPersistedEvidence(
  stateRoot: string,
  runId: string,
  inspection: Awaited<ReturnType<typeof inspectRunStorage>>,
  kind: "M6_WORKER_INVOCATION" | "M6_WORKER_RESULT",
  digest: Sha256Digest,
  value: object,
): Promise<{ readonly bytes: Buffer; readonly mediaType: string }> {
  const object = inspection.managedObjects.find((entry) => entry.kind === kind && entry.contentSha256 === digest);
  if (object === undefined) throw new Error(`M6 ${kind} persisted locator is absent`);
  const bytes = await readFile(join(stateRoot, "runs", runId, object.relativePath));
  if (!bytes.equals(Buffer.from(`${canonicalize(value)}\n`, "utf8"))) throw new Error(`M6 ${kind} persisted bytes are not the canonical authority record`);
  return { bytes, mediaType: "application/json" };
}

async function resolveAuthoritativeM6Execution(
  input: M6DirectReadOnlyWorkerInput,
  execution: M6WorkerExecutionResult,
): Promise<ResolvedM6Execution> {
  try {
    assertDocumentValid("pi_gacw_m6_worker_invocation_v0", execution.invocation);
    assertDocumentValid("pi_gacw_m6_worker_result_v0", execution.result);
  } catch (error: unknown) {
    throw new Error(`M6 returned schema-invalid authority reference: ${error instanceof Error ? error.message : String(error)}`);
  }
  const invocationDigest = returnedDigest(execution.invocation, "invocation");
  const resultDigest = returnedDigest(execution.result, "result");
  if (execution.invocation.run_id !== input.runId || execution.result.run_id !== input.runId || execution.result.invocation_content_sha256 !== invocationDigest) {
    throw new Error("M6 returned locators are bound to the wrong run or invocation");
  }
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  const [inspection, records, m5Records] = await Promise.all([
    inspectRunStorage(location),
    readM6WorkerRecords(location),
    readM5ManagedRecords(location),
  ]);
  if (inspection.status !== "HEALTHY" || inspection.workflowState === null || inspection.statePointer === null || inspection.transitionCommit === null || inspection.revision === null) {
    throw new Error("M6 persisted authority is unavailable from a healthy committed run");
  }
  const persistedInvocation = records.invocations.find((value) => value.content_sha256 === invocationDigest);
  const persistedResult = records.results.find((value) => value.content_sha256 === resultDigest);
  if (persistedInvocation === undefined || persistedResult === undefined) throw new Error("M6 returned locator does not identify a persisted record");
  const classifications = classifyM6Authority({
    runId: input.runId,
    objects: inspection.managedObjects.filter((object) => object.kind === "M6_WORKER_INVOCATION" || object.kind === "M6_WORKER_RESULT"),
    invocations: new Map(records.invocations.map((value) => [value.content_sha256, value])),
    results: new Map(records.results.map((value) => [value.content_sha256, value])),
  });
  for (const [kind, digest] of [["M6_WORKER_INVOCATION", invocationDigest], ["M6_WORKER_RESULT", resultDigest]] as const) {
    const classification = classifications.find((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest);
    if (classification?.classification !== "AUTHORITATIVE_MANAGED_RECORD") throw new Error(`M6 ${kind} is not an authoritative managed record`);
  }

  const persistedPolicy = m5Records.policies.find((value) => value.content_sha256 === input.m5Policy.content_sha256);
  const persistedDecision = m5Records.decisions.find((value) => value.content_sha256 === input.m5Decision.content_sha256);
  if (persistedPolicy === undefined || persistedDecision === undefined || canonicalize(persistedPolicy) !== canonicalize(input.m5Policy) || canonicalize(persistedDecision) !== canonicalize(input.m5Decision)) {
    throw new Error("M6 outer M5 authority is not the exact persisted policy and decision");
  }
  if (managedClass(inspection, "M5_CONTROL_POLICY", persistedPolicy.content_sha256) !== "AUTHORITATIVE_MANAGED_RECORD" ||
      managedClass(inspection, "M5_CONTROL_DECISION", persistedDecision.content_sha256) !== "AUTHORITATIVE_MANAGED_RECORD") {
    throw new Error("M6 outer M5 authority is not classified as authoritative");
  }
  const catalogClass = managedClass(inspection, "M4_COMMAND_CATALOG", input.m4CommandCatalog.content_sha256);
  if (managedClass(inspection, "M3_REPOSITORY_STATE_TOKEN", input.m3StateToken.content_sha256) !== "AUTHORITATIVE_MANAGED_RECORD" ||
      managedClass(inspection, "M4_TOOL_POLICY", input.m4ToolPolicy.content_sha256) !== "AUTHORITATIVE_MANAGED_RECORD" ||
      (catalogClass !== "AUTHORITATIVE_MANAGED_RECORD" && catalogClass !== "UNREFERENCED_MANAGED_RECORD")) {
    throw new Error("M6 outer M3/M4 authority is not current");
  }
  if (input.m4CommandCatalog.commands.length !== 0) throw new Error("M7 M4 command catalog contains executable Goal-derived authority");

  const route = input.runAuthority.routeMap.routes.find((candidate) => candidate.logical_role === "LUNA_EXECUTOR");
  const taskPath = input.runAuthority.task.scope.readable_paths[0];
  const reservationKey = input.m5Decision.reservation?.reservation_decision_key ?? null;
  const commit = inspection.transitionCommit;
  if (persistedInvocation.attempt_number !== 1) {
    throw new Error("M6 invocation attempt_number is not 1 for the sole authorized direct attempt");
  }
  if (route === undefined || taskPath === undefined ||
      persistedInvocation.run_id !== input.runId ||
      persistedInvocation.revision !== inspection.revision ||
      persistedInvocation.state_pointer_content_sha256 !== inspection.statePointer.content_sha256 ||
      persistedInvocation.current_state_content_sha256 !== inspection.workflowState.content_sha256 ||
      persistedInvocation.predecessor_state_content_sha256 !== commit.previous_workflow_state_content_sha256 ||
      persistedInvocation.transition_commit_content_sha256 !== commit.content_sha256 ||
      persistedInvocation.m5_decision_content_sha256 !== persistedDecision.content_sha256 ||
      persistedInvocation.m5_policy_content_sha256 !== persistedPolicy.content_sha256 ||
      persistedInvocation.m5_reservation_decision_key !== reservationKey ||
      persistedInvocation.operation_id !== input.m5Decision.operation_id ||
      persistedInvocation.transition_event_content_sha256 !== commit.transition_event_content_sha256 ||
      persistedInvocation.predicted_next_state_content_sha256 !== input.m5Decision.predicted_next_state_content_sha256 ||
      persistedInvocation.repository_identity_content_sha256 !== input.repository.content_sha256 ||
      persistedInvocation.worktree_key !== input.repository.worktree_key ||
      persistedInvocation.m3_state_token_content_sha256 !== input.m3StateToken.content_sha256 ||
      persistedInvocation.m4_tool_policy_content_sha256 !== input.m4ToolPolicy.content_sha256 ||
      persistedInvocation.m4_command_catalog_content_sha256 !== input.m4CommandCatalog.content_sha256 ||
      persistedInvocation.task_content_sha256 !== input.runAuthority.task.content_sha256 ||
      persistedInvocation.task_scope_identity !== input.m3StateToken.task_scope_identity ||
      persistedInvocation.route_map_sha256 !== input.runAuthority.routeMap.route_map_sha256 ||
      persistedInvocation.route_map_approval_sha256 !== input.runAuthority.routeMapApproval.route_map_approval_sha256 ||
      persistedInvocation.provider_id !== route.provider_id || persistedInvocation.model_id !== route.model_id || persistedInvocation.effort !== "high" ||
      persistedInvocation.read_path !== taskPath || persistedInvocation.read_offset !== 0 ||
      persistedInvocation.system_prompt_sha256 !== sha256Bytes(Buffer.from(input.systemPrompt, "utf8")) ||
      persistedInvocation.user_prompt_sha256 !== sha256Bytes(Buffer.from(input.userPrompt, "utf8")) ||
      canonicalize(persistedInvocation.approved_resources) !== canonicalize(input.approvedResources)) {
    throw new Error("M6 invocation is not bound to the exact current M3/M4/M5/task/route authority");
  }
  if (persistedInvocation.read_length < 1 || persistedInvocation.read_length > input.m4ToolPolicy.limits.maximum_read_bytes ||
      persistedInvocation.hard_limits.read_bytes !== persistedInvocation.read_length) {
    throw new Error("M6 invocation read authority exceeds the current M4 policy");
  }
  if (persistedResult.invocation_key !== persistedInvocation.invocation_key || persistedResult.invocation_content_sha256 !== persistedInvocation.content_sha256 || persistedResult.run_id !== input.runId) {
    throw new Error("M6 persisted result is not bound to the exact persisted invocation");
  }

  let m4Read: M4ToolResultDocument | undefined;
  if (persistedResult.m4_result_content_sha256 !== null) {
    const m4Digest = persistedResult.m4_result_content_sha256;
    if (managedClass(inspection, "M4_TOOL_RESULT", m4Digest) !== "AUTHORITATIVE_MANAGED_RECORD") throw new Error("M6 result M4 identity is not an authoritative managed record");
    const result = await readM4Record(location, "TOOL_RESULT", m4Digest as Sha256Digest);
    if (managedClass(inspection, "M4_TOOL_REQUEST", result.request_content_sha256) !== "AUTHORITATIVE_MANAGED_RECORD") throw new Error("M6 M4 read request is not authoritative");
    const request = await readM4Record(location, "TOOL_REQUEST", result.request_content_sha256 as Sha256Digest);
    const authority = input.m4ToolPolicy.path_authorities.find((entry) => entry.path === taskPath && entry.kind === "EXACT");
    if (authority === undefined || !authority.raw_read_approved ||
        request.run_id !== input.runId || request.request_kind !== "READ" || request.path !== taskPath || request.command_id !== null ||
        request.state_token_content_sha256 !== input.m3StateToken.content_sha256 || request.tool_policy_content_sha256 !== input.m4ToolPolicy.content_sha256 ||
        request.task_scope_identity !== input.m3StateToken.task_scope_identity ||
        request.request_metadata_sha256 !== sha256Canonical({ offset: 0, length: persistedInvocation.read_length, mode: "TEXT", raw: true }) ||
        result.run_id !== input.runId || result.request_content_sha256 !== request.content_sha256 || result.result_kind !== "READ" || result.path !== taskPath ||
        result.state_token_content_sha256 !== input.m3StateToken.content_sha256 || result.data_class !== authority.data_class || result.outcome !== "RAW") {
      throw new Error("M6 result does not bind the exact authoritative M4 read request, policy, path, and state token");
    }
    m4Read = result;
  }
  if (persistedResult.outcome === "COMPLETED" && (m4Read === undefined || persistedResult.worker_report === null || persistedResult.worker_report.evidence_content_sha256[0] !== m4Read.content_sha256)) {
    throw new Error("Completed M6 result is not bound to the exact authoritative M4 read");
  }
  const evidence = [
    await exactPersistedEvidence(input.stateRoot, input.runId, inspection, "M6_WORKER_INVOCATION", persistedInvocation.content_sha256 as Sha256Digest, persistedInvocation),
    await exactPersistedEvidence(input.stateRoot, input.runId, inspection, "M6_WORKER_RESULT", persistedResult.content_sha256 as Sha256Digest, persistedResult),
  ];
  return { invocation: persistedInvocation, result: persistedResult, replayed: execution.replayed, ...(m4Read === undefined ? {} : { m4Read }), evidence };
}

async function m5Block(
  kernel: ReturnType<typeof createControlDecisionKernel>,
  stateRoot: string,
  policy: M5ControlPolicyDocument,
  baseSources: M5AuthoritativeSources,
  reason: string,
  usage: readonly M5UsageEvidenceDocument[] = [],
): Promise<{ readonly decision: M5ControlDecisionDocument; readonly state: WorkflowState }> {
  const current = await currentExpected(stateRoot, RUN_ID);
  if (current.inspection.workflowState === null) throw new Error("M7 state disappeared before BLOCK");
  const result = await kernel.evaluateControlDecision({
    intent: "BLOCK",
    ...current,
    transitionId: `m7-block-${sha256Canonical({ reason, state: current.inspection.workflowState.content_sha256 }).slice(7, 23)}`,
    blockReason: reason,
    processMetadata: processMetadata(),
    usageEvidence: usage,
    authoritativeSources: baseSources,
  });
  return { decision: result.decision, state: result.workflowState };
}

async function executeProduction(prepared: PreparedWorkflow, approvedContentSha256: Sha256Digest, options: WorkflowExecutionOptions): Promise<WorkflowRunResult> {
  const cwd = options.cwd ?? process.cwd();
  const goal = prepared.goal;
  const task = prepared.task;
  const scopeSha = m3ScopeIdentity([], []);
  const acceptanceSha = sha256Canonical(goal.acceptance_criteria);
  const ownedRoot = await mkdtemp(join(tmpdir(), "pi-workflow-m7-"));
  const stateRoot = join(ownedRoot, "state");
  const temporaryRoot = join(ownedRoot, "tools");
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  await mkdir(temporaryRoot, { recursive: true, mode: 0o700 });
  let lock: WorktreeLockHandle | undefined;
  let currentM5Decision: M5ControlDecisionDocument | undefined;
  let finalState: WorkflowState | undefined;
  let admissionBegun = false;
  let terminalizationAttempted = false;
  let preserveOwnedRoot = false;
  let terminalizePostAdmission: ((reason: string, usage?: readonly M5UsageEvidenceDocument[], m6?: M6WorkerExecutionResult) => Promise<WorkflowRunResult>) | undefined;
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: cwd, requireHead: true });
    const route = routeMap();
    const approval = routeMapApproval(route);
    const budget = budgetDocument(goal);
    const contractBase = contractDocument(goal, task, approval, budget);
    // Replace the temporary repository target with the exact M3 identity before
    // constructing the canonical contract. No Goal value is introduced here.
    const contract = identifyContractDocument("pi_gacw_contract_v0", {
      ...contractBase,
      content_sha256: undefined,
      target_repository: repositoryTarget(repository),
    }) as unknown as ContractDocument;
    const reducer = reducerPolicy(goal, task, scopeSha, acceptanceSha, budget);
    const initialState = createInitialState(reducer, initialIdentities(task, contract, budget, scopeSha, acceptanceSha));
    let committed = await initializeRunStorage({ stateRoot, runId: RUN_ID, policy: reducer, initialState, processMetadata: processMetadata() });
    lock = await acquireWorktreeLock({ stateRoot, repository });
    const selected = await fingerprintInputs();
    const baseline = (await captureBaseline({
      stateRoot,
      runId: RUN_ID,
      requestedPath: cwd,
      mode: "CLEAN_REQUIRED",
      pathDecisions: [],
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      allowShallow: false,
      allowPartialClone: false,
      lock,
    })).baseline;
    const environment = await requiredEnvironment(repository);
    const full = await runFullPreflight({
      stateRoot,
      runId: RUN_ID,
      expectedRepository: baseline.repository,
      expectedWorktreeKey: baseline.repository.worktree_key,
      expectedBranch: baseline.repository.branch,
      expectedHead: baseline.repository.head,
      expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline,
      approval: null,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      requiredEnvironment: environment,
      taskScopeIdentity: scopeSha,
      allowShallow: false,
      allowPartialClone: false,
      lock,
    });
    committed = await commitEvent(stateRoot, committed, reducer, "FREEZE_OBJECTIVE", 1);
    committed = await commitEvent(stateRoot, committed, reducer, "ACQUIRE_LOCK", 2);
    committed = await commitEvent(stateRoot, committed, reducer, "CAPTURE_BASELINE", 3, { approval_required: false });
    committed = await commitEvent(stateRoot, committed, reducer, "ACCEPT_CLEAN_BASELINE", 4);
    committed = await commitEvent(stateRoot, committed, reducer, "PASS_FULL_PREFLIGHT", 5);
    const policy = await toolPolicy(repository, task, full.acceptedState, goal);
    const catalogDraft = catalog(repository);
    const catalogDocument = withCatalogPolicy(catalogDraft, policy);
    const gateway: ScopedToolGateway = await createScopedToolGateway({
      stateRoot,
      runId: RUN_ID,
      repository,
      baseline,
      acceptedState: full.acceptedState,
      lock,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      editablePaths: [],
      frozenPaths: [],
      taskScopeIdentity: scopeSha,
      toolPolicy: policy,
      commandCatalog: catalogDocument,
      temporaryRoot,
    });
    const admittedState = gateway.acceptedState;
    const m5 = m5Policy(repository, initialState, reducer, contract, budget, route, approval, policy, catalogDocument, scopeSha, acceptanceSha);
    const sources = sourceBundle(contract, budget, route, approval, policy, catalogDocument, admittedState);
    const kernel = createControlDecisionKernel({
      stateRoot,
      runId: RUN_ID,
      policy: m5,
      reducerPolicy: reducer,
      runAuthority: { repositoryIdentity: repository, contract, routeMap: route, routeMapApproval: approval },
      authoritativeSources: sources,
      production: true,
    });
    terminalizePostAdmission = async (reason: string, usage: readonly M5UsageEvidenceDocument[] = [], m6?: M6WorkerExecutionResult): Promise<WorkflowRunResult> => {
      terminalizationAttempted = true;
      try {
        const blocked = await m5Block(kernel, stateRoot, m5, sources, reason, usage);
        finalState = blocked.state;
        currentM5Decision = blocked.decision;
        return { outcome: "BLOCKED", reason: blocked.decision.blocking_reason ?? reason, task, finalState, m5Decision: currentM5Decision, ...(m6 === undefined ? {} : { m6 }) };
      } catch (error: unknown) {
        preserveOwnedRoot = true;
        try { finalState = (await currentExpected(stateRoot, RUN_ID)).inspection.workflowState!; } catch { /* preserve the evidence root even when state inspection is unavailable */ }
        return {
          outcome: "BLOCKED",
          reason: `BLOCKED_TERMINALIZATION_UNCERTAIN:STATE_PUBLICATION_FAILURE:${reason}:${error instanceof Error ? error.message : String(error)}`,
          task,
          evidenceRoot: ownedRoot,
          ...(finalState === undefined ? {} : { finalState }),
          ...(currentM5Decision === undefined ? {} : { m5Decision: currentM5Decision }),
        };
      }
    };
    const validateExpected = await currentExpected(stateRoot, RUN_ID);
    let decisionResult = await kernel.evaluateControlDecision({
      intent: "VALIDATE_CONTRACT",
      ...validateExpected,
      transitionId: "m7-validate-contract",
      processMetadata: processMetadata(),
      availableLogicalRoles: ["LUNA_EXECUTOR"],
      authoritativeSources: sources,
    });
    currentM5Decision = decisionResult.decision;
    committed = { statePointer: validateExpected.inspection.statePointer!, workflowState: decisionResult.workflowState, transitionCommit: validateExpected.inspection.transitionCommit!, evidence: [] };
    if (decisionResult.decision.outcome === "BLOCK") {
      finalState = decisionResult.workflowState;
      return { outcome: "BLOCKED", reason: decisionResult.decision.blocking_reason ?? "BLOCKED_M5_CONTRACT", task, finalState, m5Decision: currentM5Decision };
    }
    const selectedExpected = await currentExpected(stateRoot, RUN_ID);
    decisionResult = await kernel.evaluateControlDecision({
      intent: "SELECT_ROUTE",
      ...selectedExpected,
      transitionId: "m7-select-route",
      processMetadata: processMetadata(),
      availableLogicalRoles: ["LUNA_EXECUTOR"],
      authoritativeSources: sources,
    });
    currentM5Decision = decisionResult.decision;
    if (decisionResult.decision.outcome === "BLOCK") {
      finalState = decisionResult.workflowState;
      return { outcome: "BLOCKED", reason: decisionResult.decision.blocking_reason ?? "BLOCKED_M5_ROUTE", task, finalState, m5Decision: currentM5Decision };
    }
    const afterSelectExpected = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: afterSelectExpected.inspection.statePointer!, workflowState: afterSelectExpected.inspection.workflowState! }, reducer, "VALIDATE_DIRECT_CONTRACT", 20);
    const afterDirectContract = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: afterDirectContract.inspection.statePointer!, workflowState: afterDirectContract.inspection.workflowState! }, reducer, "REQUEST_DIRECT_APPROVAL", 21);
    const afterRequestApproval = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: afterRequestApproval.inspection.statePointer!, workflowState: afterRequestApproval.inspection.workflowState! }, reducer, "APPROVE_DIRECT_TASK", 22, {}, [canonicalEvidence(task)]);
    const afterTaskFrozen = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: afterTaskFrozen.inspection.statePointer!, workflowState: afterTaskFrozen.inspection.workflowState! }, reducer, "PASS_DIRECT_FAST_PREFLIGHT", 23);
    const authorizeExpected = await currentExpected(stateRoot, RUN_ID);
    decisionResult = await kernel.evaluateControlDecision({
      intent: "AUTHORIZE_WORK",
      ...authorizeExpected,
      transitionId: "m7-authorize-worker",
      operationId: "m7-worker-operation",
      processMetadata: processMetadata(),
      availableLogicalRoles: ["LUNA_EXECUTOR"],
      authoritativeSources: sources,
    });
    currentM5Decision = decisionResult.decision;
    finalState = decisionResult.workflowState;
    if (decisionResult.decision.outcome !== "AUTHORIZE" || decisionResult.decision.reservation === null) {
      return { outcome: "BLOCKED", reason: decisionResult.decision.blocking_reason ?? "BLOCKED_M5_ADMISSION", task, finalState, m5Decision: currentM5Decision };
    }
    admissionBegun = true;
    const workerInput: M6DirectReadOnlyWorkerInput = {
      stateRoot,
      runId: RUN_ID,
      reducerPolicy: reducer,
      m5Policy: m5,
      m5Decision: decisionResult.decision,
      runAuthority: { repositoryIdentity: repository, contract, routeMap: route, routeMapApproval: approval, task },
      repository,
      baseline,
      m3StateToken: admittedState,
      lock,
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      gateway,
      m4ToolPolicy: policy,
      m4CommandCatalog: catalogDocument,
      task: { task_id: task.task_id, task_sha256: task.task_sha256 as Sha256Digest },
      approvedResources: [],
      systemPrompt: "You are the one bounded M7 read-only/report-only worker. Use exactly one scoped read and one structured terminal report. Never mutate, execute commands, or request another worker.",
      userPrompt: task.objective,
      credentialStoreCallback: (providerId) => publicCredentialStore(providerId, options.credentialReader),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    };
    const worker = options.worker ?? runDirectReadOnlyLunaWorker;
    let execution: M6WorkerExecutionResult;
    try {
      execution = await worker(workerInput);
    } catch (error: unknown) {
      return await terminalizePostAdmission!( `BLOCKED_M6_${error instanceof Error ? error.name : "FAILURE"}`);
    }
    let resolved: ResolvedM6Execution;
    try {
      resolved = await resolveAuthoritativeM6Execution(workerInput, execution);
    } catch (error: unknown) {
      return await terminalizePostAdmission(
        `BLOCKED_M7_M6_AUTHORITY:${error instanceof Error ? error.message : String(error)}`,
        [blockedM6UsageEvidence(m5, decisionResult.decision)],
      );
    }
    const usage = usageEvidence(m5, decisionResult.decision, resolved.result);
    if (resolved.result.outcome !== "COMPLETED") {
      return await terminalizePostAdmission("BLOCKED_M6_RESULT", [usage], resolved);
    }
    const runningExpected = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: runningExpected.inspection.statePointer!, workflowState: runningExpected.inspection.workflowState! }, reducer, "COMPLETE_DIRECT_ATTEMPT", 24, {}, resolved.evidence);
    const afterVerificationExpected = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: afterVerificationExpected.inspection.statePointer!, workflowState: afterVerificationExpected.inspection.workflowState! }, reducer, "PASS_DIRECT_POSTFLIGHT", 25);
    const terminalExpected = await currentExpected(stateRoot, RUN_ID);
    const reportObligation = m5.obligations.find((obligation) => obligation.declaration === "report");
    if (reportObligation === undefined) throw new Error("Fixed M7 report obligation is absent from M5 policy");
    const obligationEvidence = [{
      descriptorSha256: reportObligation.descriptor_sha256 as Sha256Digest,
      value: "COMPLETED",
      evidenceContentSha256: terminalExpected.inspection.workflowState!.content_sha256 as Sha256Digest,
    }];
    const terminal = await kernel.evaluateControlDecision({
      intent: "EVALUATE_TERMINAL",
      ...terminalExpected,
      transitionId: "m7-evaluate-terminal",
      processMetadata: processMetadata(),
      availableLogicalRoles: ["LUNA_EXECUTOR"],
      authoritativeSources: sources,
      usageEvidence: [usage],
      obligationEvidence,
    });
    currentM5Decision = terminal.decision;
    finalState = terminal.workflowState;
    return {
      outcome: terminal.decision.outcome === "PASS" && terminal.workflowState.phase === "PASS" ? "PASS" : "BLOCKED",
      reason: terminal.decision.outcome === "PASS" ? "PASS" : terminal.decision.blocking_reason ?? "BLOCKED_M5_TERMINAL",
      task,
      finalState,
      m5Decision: currentM5Decision,
      m6: resolved,
    };
  } catch (error: unknown) {
    if (admissionBegun && !terminalizationAttempted && terminalizePostAdmission !== undefined) {
      return await terminalizePostAdmission(`BLOCKED_M7_POST_ADMISSION_FAILURE:${error instanceof Error ? error.message : String(error)}`);
    }
    return { outcome: "BLOCKED", reason: error instanceof Error ? error.message : "BLOCKED_M7_ORCHESTRATION", task, ...(finalState === undefined ? {} : { finalState }), ...(currentM5Decision === undefined ? {} : { m5Decision: currentM5Decision }) };
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    if (!preserveOwnedRoot) await rm(ownedRoot, { recursive: true, force: true }).catch(() => undefined);
  }
}

export async function runApprovedWorkflow(
  prepared: PreparedWorkflow,
  approvedContentSha256: string,
  options: WorkflowExecutionOptions = {},
): Promise<WorkflowRunResult> {
  const approved = revalidateApproval(prepared, approvedContentSha256);
  if (options.executeApproved !== undefined) {
    return options.executeApproved({ goal: approved.goal, task: approved.task, approvedContentSha256: approved.task.content_sha256 as Sha256Digest, cwd: options.cwd ?? process.cwd() });
  }
  return executeProduction(approved, approved.task.content_sha256 as Sha256Digest, options);
}

export function renderTaskPreview(prepared: PreparedWorkflow): string {
  return prepared.preview;
}

export function approvalLine(value: string): string {
  return `APPROVE ${value}`;
}
