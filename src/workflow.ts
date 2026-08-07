import { execFile } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { isAbsolute, join, basename } from "node:path";
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
import { commandSpecProjection } from "./scoped-tools/commands.js";
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
  type M4CommandResultDocument,
  type M4CommandSpecification,
  type M4ScopedToolPolicyDocument,
  type M5ControlDecisionDocument,
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
// Existing direct M5 reservation arithmetic needs one active reservation plus
// one eventual measured invocation. This is accounting capacity, not an M7
// worker allowance: the Goal and reducer both admit exactly one attempt.
const M5_DIRECT_WORKER_ACCOUNTING_LIMIT = 2;
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
const VERIFICATION_KEYS = ["command_id", "argv", "cwd", "timeout_ms", "network"] as const;
const BUDGET_KEYS = [
  "max_worker_invocations",
  "max_model_turns",
  "max_tool_calls",
  "max_wall_time_ms",
  "max_read_bytes",
] as const;

export type WorkflowOutcome = "PASS" | "BLOCKED";
export type GoalDataClass = "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE" | "HASH_ONLY";
export type GoalEvidenceKind = "COMMAND" | "FILE" | "DIGEST";

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

export interface GoalVerificationCommand {
  readonly command_id: string;
  readonly argv: readonly string[];
  readonly cwd: "REPOSITORY_ROOT";
  readonly timeout_ms: number;
  readonly network: "FORBIDDEN";
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
  readonly verification_commands: readonly GoalVerificationCommand[];
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

  if (!Array.isArray(input["acceptance_criteria"]) || (input["acceptance_criteria"] as readonly unknown[]).length === 0) invalid("Goal.acceptance_criteria must be non-empty");
  const acceptance = (input["acceptance_criteria"] as readonly unknown[]).map((candidate, index): GoalAcceptanceCriterion => {
    const criterion = record(candidate, `Goal.acceptance_criteria[${index}]`);
    exactKeys(criterion, ACCEPTANCE_KEYS, `Goal.acceptance_criteria[${index}]`);
    const criterionId = nonempty(criterion["criterion_id"], `Goal.acceptance_criteria[${index}].criterion_id`, 128);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(criterionId)) invalid(`Goal.acceptance_criteria[${index}].criterion_id is invalid`);
    const description = nonempty(criterion["description"], `Goal.acceptance_criteria[${index}].description`);
    const evidenceKind = criterion["evidence_kind"];
    if (evidenceKind !== "COMMAND" && evidenceKind !== "FILE" && evidenceKind !== "DIGEST") invalid(`Goal.acceptance_criteria[${index}].evidence_kind is unsupported`);
    if (criterion["owner_acceptance"] !== false) invalid("M7 does not admit owner-acceptance criteria");
    return { criterion_id: criterionId, description, evidence_kind: evidenceKind, owner_acceptance: false };
  });
  if (new Set(acceptance.map((criterion) => criterion.criterion_id)).size !== acceptance.length) invalid("Goal.acceptance_criteria contains duplicate criterion IDs");

  if (!Array.isArray(input["verification_commands"]) || (input["verification_commands"] as readonly unknown[]).length === 0) invalid("Goal.verification_commands must be non-empty");
  const verification = (input["verification_commands"] as readonly unknown[]).map((candidate, index): GoalVerificationCommand => {
    const command = record(candidate, `Goal.verification_commands[${index}]`);
    exactKeys(command, VERIFICATION_KEYS, `Goal.verification_commands[${index}]`);
    const commandId = nonempty(command["command_id"], `Goal.verification_commands[${index}].command_id`, 128);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(commandId)) invalid(`Goal.verification_commands[${index}].command_id is invalid`);
    if (!Array.isArray(command["argv"]) || (command["argv"] as readonly unknown[]).length === 0 || (command["argv"] as readonly unknown[]).length > 128) invalid(`Goal.verification_commands[${index}].argv is invalid`);
    const argv = (command["argv"] as readonly unknown[]).map((argument, argumentIndex) => nonempty(argument, `Goal.verification_commands[${index}].argv[${argumentIndex}]`, 4096));
    if (!isAbsolute(argv[0]!)) invalid("Verification argv[0] must be an absolute M4 executable identity; PATH lookup is not authority");
    if (argv.some((argument) => argument === "-c" || argument === "--command")) invalid("Shell/interpreter command evaluation is not admitted by M7");
    if (command["cwd"] !== "REPOSITORY_ROOT") invalid("Verification cwd must be the exact authorized repository root");
    const timeout = safeInteger(command["timeout_ms"], `Goal.verification_commands[${index}].timeout_ms`, 1, M4_MAX_COMMAND_TIME_MS);
    if (command["network"] !== "FORBIDDEN") invalid("M7 verification commands require network FORBIDDEN");
    return { command_id: commandId, argv, cwd: "REPOSITORY_ROOT", timeout_ms: timeout, network: "FORBIDDEN" };
  });
  if (new Set(verification.map((command) => command.command_id)).size !== verification.length) invalid("Goal.verification_commands contains duplicate command IDs");

  const budgetInput = record(input["budget"], "Goal.budget");
  exactKeys(budgetInput, BUDGET_KEYS, "Goal.budget");
  const workerInvocations = safeInteger(budgetInput["max_worker_invocations"], "Goal.budget.max_worker_invocations", 1, 1);
  const modelTurns = safeInteger(budgetInput["max_model_turns"], "Goal.budget.max_model_turns", M6_MODEL_TURNS, M6_MODEL_TURNS);
  const toolCalls = safeInteger(budgetInput["max_tool_calls"], "Goal.budget.max_tool_calls", M6_TOOL_CALLS, M6_TOOL_CALLS);
  const wallTime = safeInteger(budgetInput["max_wall_time_ms"], "Goal.budget.max_wall_time_ms", 1, M6_MAX_WALL_TIME_MS);
  const readBytes = safeInteger(budgetInput["max_read_bytes"], "Goal.budget.max_read_bytes", 1, M6_MAX_READ_BYTES);
  if (verification.some((command) => command.timeout_ms > wallTime)) invalid("Verification timeout exceeds Goal.budget.max_wall_time_ms");
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
    verification_commands: canonicalSorted(verification),
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
  const roles = ["SOL_OWNER", "SOL_PLANNER", "SOL_REPLAN", "SOL_CLOSEOUT", "LUNA_EXECUTOR", "BENCHMARK_VERIFIER", "BENCHMARK_SELECTOR"] as const;
  const routes = roles.map((logical_role) => ({
    logical_role,
    provider_id: "openai-codex",
    model_id: "gpt-5.6-luna",
    effort: logical_role === "LUNA_EXECUTOR" ? "high" as const : "max" as const,
    tool_policy: {
      policy_id: `m7-${logical_role.toLowerCase()}`,
      built_in_tools_disabled: true as const,
      mutation_tool: "NONE" as const,
      command_gateway: "VERIFICATION_ONLY" as const,
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
      max_worker_invocations: M5_DIRECT_WORKER_ACCOUNTING_LIMIT,
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
    verification_commands: goal.verification_commands,
    command_policy: {
      shell: false,
      network: "FORBIDDEN",
      allowed_executables: sortedStrings(goal.verification_commands.map((command) => basename(command.argv[0]!))),
      forbidden_operations: ["INSTALL", "COMMIT", "PUSH", "TAG", "MERGE", "REBASE", "RESET", "RESTORE", "CLEAN", "SWITCH_BRANCH", "MODIFY_REMOTE"],
    },
    limits: {
      max_leaves: 1,
      max_attempts_per_leaf: 1,
      max_replans: 0,
      max_worker_invocations: M5_DIRECT_WORKER_ACCOUNTING_LIMIT,
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
      max_worker_invocations: M5_DIRECT_WORKER_ACCOUNTING_LIMIT,
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
    ["WORKER_INVOCATION", M5_DIRECT_WORKER_ACCOUNTING_LIMIT, M5_DIRECT_WORKER_ACCOUNTING_LIMIT, "HARD_ENFORCEABLE"],
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
    obligations: acceptanceObligationsFromContract(contract),
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

function acceptanceObligationsFromContract(contract: ContractDocument): M5ControlPolicyDocument["obligations"] {
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
  const criteria = contract.acceptance_criteria.map((criterion) => ({
    declaration: `acceptance.${criterion.criterion_id}`,
    direction: "OUTPUT" as const,
    stage: 1,
    producer: TASK_ID,
    consumers: ["contract"],
    grammar: "LITERAL" as const,
    evidence_kind: criterion.evidence_kind,
    literal: "PASS",
    prefix: null,
  }));
  return [report, ...criteria].map((obligation) => ({ descriptor_sha256: sha256Canonical(obligation), ...obligation }));
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

async function commandSpecification(
  repository: M3RepositoryIdentityDocument,
  command: GoalVerificationCommand,
): Promise<M4CommandSpecification> {
  const executablePath = command.argv[0]!;
  const executablePhysical = await realpath(executablePath);
  if (executablePhysical !== executablePath) throw new Error("Verification executable is symlinked or not canonical");
  const executableStats = await lstat(executablePath);
  if (!executableStats.isFile() || executableStats.isSymbolicLink() || (executableStats.mode & 0o111) === 0) throw new Error("Verification executable is not a regular executable file");
  const cwd = repository.worktree_root;
  const cwdStats = await lstat(cwd);
  const cwdPhysical = await realpath(cwd);
  if (!cwdStats.isDirectory() || cwdPhysical !== cwd) throw new Error("Repository root is not a canonical directory");
  const executionInputs: Array<{ path: string; realpath: string; device: number; inode: number; mode: number; size: number; digest: Sha256Digest }> = [];
  const seen = new Set<string>();
  for (const argument of command.argv) {
    if (!isAbsolute(argument) || seen.has(argument)) continue;
    try {
      const stats = await lstat(argument);
      if (!stats.isFile() || stats.isSymbolicLink()) continue;
      const physical = await realpath(argument);
      if (physical !== argument) throw new Error("Verification execution input is symlinked");
      seen.add(argument);
      executionInputs.push({ path: argument, realpath: physical, device: stats.dev, inode: stats.ino, mode: stats.mode & 0o7777, size: stats.size, digest: sha256Bytes(await readFile(argument)) });
    } catch (error: unknown) {
      if (argument === executablePath) continue;
      throw error;
    }
  }
  const draft = {
    command_id: command.command_id,
    command_spec_sha256: `sha256:${"0".repeat(64)}`,
    command_class: "VERIFICATION" as const,
    executable_invocation_path: executablePath,
    executable_realpath: executablePhysical,
    executable_device: executableStats.dev,
    executable_inode: executableStats.ino,
    executable_mode: executableStats.mode & 0o7777,
    executable_size: executableStats.size,
    executable_sha256: sha256Bytes(await readFile(executablePath)),
    argv: [...command.argv],
    cwd: "REPOSITORY_ROOT" as const,
    cwd_realpath: cwdPhysical,
    cwd_device: cwdStats.dev,
    cwd_inode: cwdStats.ino,
    execution_inputs: executionInputs,
    environment: [],
    read_paths: [],
    write_paths: [],
    network_policy: "FORBIDDEN" as const,
    timeout_ms: command.timeout_ms,
    stdout_limit: M4_MAX_STDOUT_BYTES,
    stderr_limit: M4_MAX_STDERR_BYTES,
    expected_exit_codes: [0],
    repository_side_effect: "NONE" as const,
    claimed_paths: [],
    cleanup_paths: [],
  };
  return { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft as M4CommandSpecification)) } as M4CommandSpecification;
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

async function catalog(
  repository: M3RepositoryIdentityDocument,
  goal: EphemeralGoal,
): Promise<M4CommandCatalogDocument> {
  const commands = await Promise.all(goal.verification_commands.map((command) => commandSpecification(repository, command)));
  return identifyContractDocument("pi_gacw_command_catalog_v0", {
    schema_id: "pi_gacw_command_catalog_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: RUN_ID,
    catalog_id: "m7-verification-catalog",
    repository_identity_content_sha256: repository.content_sha256,
    tool_policy_content_sha256: `sha256:${"0".repeat(64)}`,
    commands,
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
  result: M6WorkerExecutionResult,
): M5UsageEvidenceDocument {
  const usage = result.result.usage;
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
    disposition: result.result.outcome === "COMPLETED" ? "COMPLETED" : "BLOCKED_BEFORE_START",
    duration_ms: usage.wall_time_ms,
  }) as unknown as M5UsageEvidenceDocument;
}

const PI_CODING_AGENT_SPECIFIER: string = "@earendil-works/pi-coding-agent";

async function publicCredentialStore(): Promise<unknown> {
  // M7 deliberately performs no credential operation. Verify the supported
  // public package boundary and exact version, then give the worker a store
  // whose operations fail closed without touching user credential state.
  const moduleValue: unknown = await import(PI_CODING_AGENT_SPECIFIER);
  if (moduleValue === null || typeof moduleValue !== "object" ||
      (moduleValue as Record<string, unknown>)["VERSION"] !== "0.83.0" ||
      typeof (moduleValue as Record<string, unknown>)["readStoredCredential"] !== "function") {
    throw new Error("Public Pi 0.83.0 credential boundary is unavailable");
  }
  const unavailable = async (): Promise<never> => { throw new Error("M7 credential operations are forbidden"); };
  return { read: unavailable, list: unavailable, modify: unavailable, delete: unavailable };
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
    const catalogDraft = await catalog(repository, goal);
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
    // Verification is an M4 operation, not an M5 evidence shortcut. Run it
    // before publishing M5 decisions so every later M5 decision sees the same
    // durable M3 authority population and no decision key changes when the
    // command result is published.
    const verificationResults: M4CommandResultDocument[] = [];
    let verificationFailure: string | undefined;
    for (const command of goal.verification_commands) {
      try {
        const commandResult = await gateway.run_verification_command({ commandId: command.command_id, stateTokenContentSha256: gateway.acceptedState.content_sha256 as Sha256Digest });
        verificationResults.push(commandResult.record);
        if (commandResult.record.outcome !== "PASS") {
          verificationFailure = "BLOCKED_M4_VERIFICATION";
          break;
        }
      } catch {
        verificationFailure = "BLOCKED_M4_VERIFICATION";
        break;
      }
    }
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
    if (verificationFailure !== undefined) {
      const blocked = await m5Block(kernel, stateRoot, m5, sources, verificationFailure);
      finalState = blocked.state;
      return { outcome: "BLOCKED", reason: blocked.decision.blocking_reason ?? verificationFailure, task, finalState, m5Decision: blocked.decision };
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
      credentialStoreCallback: publicCredentialStore,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    };
    const worker = options.worker ?? runDirectReadOnlyLunaWorker;
    let execution: M6WorkerExecutionResult;
    try {
      execution = await worker(workerInput);
    } catch (error: unknown) {
      const blocked = await m5Block(kernel, stateRoot, m5, sources, `BLOCKED_M6_${error instanceof Error ? error.name : "FAILURE"}`);
      finalState = blocked.state;
      return { outcome: "BLOCKED", reason: blocked.decision.blocking_reason ?? "BLOCKED_M6_FAILURE", task, finalState, m5Decision: blocked.decision };
    }
    const usage = usageEvidence(m5, decisionResult.decision, execution);
    if (execution.result.outcome !== "COMPLETED") {
      const blocked = await m5Block(kernel, stateRoot, m5, sources, "BLOCKED_M6_RESULT", [usage]);
      finalState = blocked.state;
      return { outcome: "BLOCKED", reason: blocked.decision.blocking_reason ?? "BLOCKED_M6_RESULT", task, finalState, m5Decision: blocked.decision, m6: execution };
    }
    const runningExpected = await currentExpected(stateRoot, RUN_ID);
    const afterAttempt = await commitEvent(stateRoot, { statePointer: runningExpected.inspection.statePointer!, workflowState: runningExpected.inspection.workflowState! }, reducer, "COMPLETE_DIRECT_ATTEMPT", 24, {}, [canonicalEvidence(execution.invocation), canonicalEvidence(execution.result)]);
    void afterAttempt;
    const afterVerification = await currentExpected(stateRoot, RUN_ID);
    await commitEvent(stateRoot, { statePointer: afterVerification.inspection.statePointer!, workflowState: afterVerification.inspection.workflowState! }, reducer, "PASS_DIRECT_POSTFLIGHT", 25, {}, verificationResults.map((value) => canonicalEvidence(value)));
    const terminalExpected = await currentExpected(stateRoot, RUN_ID);
    // The M4 command records remain durable and are archived with the
    // transition evidence. Each successful command also binds the latest
    // postflight token; use that existing authoritative predecessor as the
    // M5 evidence identity without making M5 execute or reinterpret commands.
    const obligationEvidence = m5.obligations.map((obligation) => ({ descriptorSha256: obligation.descriptor_sha256 as Sha256Digest, value: obligation.declaration === "report" ? "COMPLETED" : "PASS", evidenceContentSha256: admittedState.content_sha256 as Sha256Digest }));
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
      m6: execution,
    };
  } catch (error: unknown) {
    return { outcome: "BLOCKED", reason: error instanceof Error ? error.message : "BLOCKED_M7_ORCHESTRATION", task, ...(finalState === undefined ? {} : { finalState }), ...(currentM5Decision === undefined ? {} : { m5Decision: currentM5Decision }) };
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await rm(ownedRoot, { recursive: true, force: true }).catch(() => undefined);
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
