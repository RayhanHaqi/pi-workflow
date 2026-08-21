import { isAbsolute, join, normalize, resolve } from "node:path";

import { canonicalize } from "./canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { captureGitState } from "./repository/fingerprint.js";
import { resolveRepositoryIdentity } from "./repository/index.js";
import { assertM4CanonicalPath } from "./secure-fs/path.js";
import {
  runBoundedMutationWorkflow,
  type BoundedMutationAuthority,
  type BoundedMutationOptions,
  type BoundedMutationRunResult,
  type ControllerVerificationCommand,
  type StaticApprovedDagTimeBudgets,
} from "./workflow-controller.js";

export const STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION = "static-approved-dag-launch-v1" as const;
export const STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS = 60_000;

export class StaticApprovedDagLaunchError extends Error {
  public constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "StaticApprovedDagLaunchError";
  }
}

type JsonRecord = Record<string, unknown>;
type StaticWorkflowTaskSummary = Readonly<{ readonly task_id: string; readonly status: "PENDING" | "RUNNING" | "PASS" | "BLOCKED"; readonly attempts: number; readonly postflight_completed: boolean; readonly verification_completed: boolean; readonly retry_progress_admitted: boolean }>;
type StaticWorkflowStateSummary = Readonly<{ readonly outcome: "PASS" | "BLOCKED"; readonly final_phase: string | null; readonly terminal_reason: string | null; readonly active_task_id: string | null; readonly leaves_completed: number | null; readonly terra_worker_invocations: number | null; readonly tasks: readonly StaticWorkflowTaskSummary[] }>;
type StaticGoalScope = Readonly<{ readonly readable_paths: readonly string[]; readonly editable_paths: readonly string[]; readonly frozen_paths: readonly string[] }>;
type StaticGoalTask = Readonly<{ readonly task_id: string; readonly objective: string; readonly editable_paths: readonly string[]; readonly required_outputs: readonly string[]; readonly dependencies: readonly string[]; readonly verification_command_ids?: readonly string[] }>;

export interface StaticApprovedDagLaunchSpec {
  readonly spec_version: typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION;
  readonly run_label: string;
  readonly expected_repository_branch: string;
  readonly expected_head: string;
  readonly expected_tree: string;
  readonly goal: Readonly<{ readonly objective: string; readonly stop_condition: string; readonly execution_mode: "STATIC_APPROVED_DAG"; readonly scope: StaticGoalScope; readonly required_outputs: readonly string[]; readonly tasks: readonly StaticGoalTask[] }>;
  readonly verification_commands: readonly Readonly<{ readonly command_id: string; readonly executable: string; readonly args: readonly string[]; readonly cwd: string; readonly timeout_ms: number }>[];
  readonly static_time_budgets: StaticApprovedDagTimeBudgets;
  readonly static_max_attempts_per_leaf: 1 | 2;
  readonly expected_route: Readonly<{ readonly logical_role: "TERRA_EXECUTOR"; readonly provider_id: "openai-codex"; readonly model_id: "gpt-5.6-terra"; readonly effort: "high" | "xhigh"; readonly fallback: false }>;
}

export interface StaticApprovedDagRepositoryFacts {
  readonly repository_root: string;
  readonly branch: string | null;
  readonly head: string;
  readonly tree: string;
  readonly clean: boolean;
  readonly active_operations: readonly string[];
  readonly index_lock: boolean;
}

export interface StaticApprovedDagLaunchReport {
  readonly classification: "PASS" | "VALID_BLOCKED" | "INVALID";
  readonly spec_sha256: Sha256Digest | null;
  readonly run_label: string | null;
  readonly reason: string;
  readonly workflow: StaticWorkflowStateSummary | null;
  readonly evidence_root: string | null;
  readonly hygiene_warning: string | null;
  readonly telemetry: null;
}

export type StaticApprovedDagController = (value: unknown, options?: BoundedMutationOptions) => Promise<BoundedMutationRunResult>;

export interface ExecuteStaticApprovedDagInput {
  readonly spec: unknown;
  readonly approved_spec_sha256: string;
  readonly cwd?: string;
  readonly controller?: StaticApprovedDagController;
  readonly repositoryFacts?: (cwd: string) => Promise<StaticApprovedDagRepositoryFacts>;
}

function fail(code: string, message: string): never { throw new StaticApprovedDagLaunchError(code, message); }
function record(value: unknown, label: string): JsonRecord { if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_SPEC", `${label} must be an object`); return value as JsonRecord; }
function exactKeys(value: JsonRecord, keys: readonly string[], label: string): void { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (canonicalize(actual) !== canonicalize(expected)) fail("INVALID_SPEC", `${label} contains unknown or missing fields`); }
function string(value: unknown, label: string, maximum = 4096): string { if (typeof value !== "string" || value.length === 0 || value.length > maximum) fail("INVALID_SPEC", `${label} must be a bounded non-empty string`); return value; }
function positiveSafeInteger(value: unknown, label: string): number { if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) fail("INVALID_SPEC", `${label} must be a positive safe integer`); return value; }
function sortedUniqueStrings(value: unknown, label: string, maximum: number): readonly string[] { if (!Array.isArray(value) || value.length > maximum) fail("INVALID_SPEC", `${label} must be a bounded array`); const result = value.map((entry, index) => string(entry, `${label}[${index}]`, 4096)).sort(); if (new Set(result).size !== result.length) fail("INVALID_SPEC", `${label} contains duplicates`); return Object.freeze(result); }
function paths(value: unknown, label: string): readonly string[] { const result = sortedUniqueStrings(value, label, 128); for (const entry of result) { try { assertM4CanonicalPath(entry, label); } catch { fail("INVALID_SPEC", `${label} contains a non-canonical repository path`); } } return result; }
function taskId(value: unknown, label: string): string { const result = string(value, label, 128); if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(result)) fail("INVALID_SPEC", `${label} is not an identifier`); return result; }
function within(value: string, roots: readonly string[]): boolean { return roots.some((root) => value === root || value.startsWith(`${root}/`)); }

function normalizeGoal(value: unknown): StaticApprovedDagLaunchSpec["goal"] {
  const input = record(value, "goal"); exactKeys(input, ["objective", "stop_condition", "execution_mode", "scope", "required_outputs", "tasks"], "goal");
  if (input["execution_mode"] !== "STATIC_APPROVED_DAG") fail("STATIC_ROUTE_RESTRICTED", "goal.execution_mode must be STATIC_APPROVED_DAG");
  const scopeInput = record(input["scope"], "goal.scope"); exactKeys(scopeInput, ["readable_paths", "editable_paths", "frozen_paths"], "goal.scope");
  const scope: StaticGoalScope = Object.freeze({ readable_paths: paths(scopeInput["readable_paths"], "goal.scope.readable_paths"), editable_paths: paths(scopeInput["editable_paths"], "goal.scope.editable_paths"), frozen_paths: paths(scopeInput["frozen_paths"], "goal.scope.frozen_paths") });
  if (scope.editable_paths.some((entry) => within(entry, scope.frozen_paths)) || scope.frozen_paths.some((entry) => within(entry, scope.editable_paths))) fail("INVALID_SPEC", "goal editable and frozen scope overlaps");
  const requiredOutputs = paths(input["required_outputs"], "goal.required_outputs");
  if (requiredOutputs.length === 0 || requiredOutputs.some((entry) => !within(entry, scope.editable_paths))) fail("INVALID_SPEC", "goal required outputs must be editable");
  if (!Array.isArray(input["tasks"]) || input["tasks"].length < 2 || input["tasks"].length > 8) fail("INVALID_SPEC", "goal.tasks must contain 2–8 leaves");
  const seen = new Set<string>();
  const tasks = input["tasks"].map((value, index) => {
    const candidate = record(value, `goal.tasks[${index}]`); const hasSelection = Object.hasOwn(candidate, "verification_command_ids");
    exactKeys(candidate, hasSelection ? ["task_id", "objective", "editable_paths", "required_outputs", "dependencies", "verification_command_ids"] : ["task_id", "objective", "editable_paths", "required_outputs", "dependencies"], `goal.tasks[${index}]`);
    const id = taskId(candidate["task_id"], `goal.tasks[${index}].task_id`); if (seen.has(id)) fail("INVALID_SPEC", "goal task IDs must be unique"); seen.add(id);
    const editable = paths(candidate["editable_paths"], `goal.tasks[${index}].editable_paths`); const outputs = paths(candidate["required_outputs"], `goal.tasks[${index}].required_outputs`); const dependencies = sortedUniqueStrings(candidate["dependencies"], `goal.tasks[${index}].dependencies`, 128).map((entry) => taskId(entry, `goal.tasks[${index}].dependencies`));
    if (editable.length === 0 || outputs.length === 0 || editable.some((entry) => !within(entry, scope.editable_paths)) || outputs.some((entry) => !requiredOutputs.includes(entry))) fail("INVALID_SPEC", "goal task scope or output is invalid");
    const selected = hasSelection ? sortedUniqueStrings(candidate["verification_command_ids"], `goal.tasks[${index}].verification_command_ids`, 128).map((entry) => taskId(entry, `goal.tasks[${index}].verification_command_ids`)) : undefined;
    return Object.freeze({ task_id: id, objective: string(candidate["objective"], `goal.tasks[${index}].objective`), editable_paths: editable, required_outputs: outputs, dependencies, ...(selected === undefined ? {} : { verification_command_ids: selected }) });
  });
  if (canonicalize([...tasks.flatMap((task) => task.required_outputs)].sort()) !== canonicalize(requiredOutputs)) fail("INVALID_SPEC", "each required output must have exactly one task owner");
  return Object.freeze({ objective: string(input["objective"], "goal.objective"), stop_condition: string(input["stop_condition"], "goal.stop_condition"), execution_mode: "STATIC_APPROVED_DAG", scope, required_outputs: requiredOutputs, tasks: Object.freeze(tasks) });
}

function normalizeCommands(value: unknown): StaticApprovedDagLaunchSpec["verification_commands"] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) fail("INVALID_SPEC", "verification_commands must be a non-empty bounded array");
  const ids = new Set<string>();
  return Object.freeze(value.map((entry, index) => {
    const command = record(entry, `verification_commands[${index}]`); exactKeys(command, ["command_id", "executable", "args", "cwd", "timeout_ms"], `verification_commands[${index}]`);
    const commandId = taskId(command["command_id"], `verification_commands[${index}].command_id`); if (ids.has(commandId)) fail("INVALID_SPEC", "verification command IDs must be unique"); ids.add(commandId);
    const executable = string(command["executable"], `verification_commands[${index}].executable`); if (!isAbsolute(executable) || normalize(executable) !== executable) fail("INVALID_SPEC", "verification executable must be an absolute normalized path accepted by controller authority");
    if (!Array.isArray(command["args"]) || command["args"].length > 127) fail("INVALID_SPEC", "verification args must be bounded");
    const args = Object.freeze(command["args"].map((arg, argIndex) => string(arg, `verification_commands[${index}].args[${argIndex}]`, 4096)));
    const cwd = string(command["cwd"], `verification_commands[${index}].cwd`); if (cwd === "." || cwd === "REPOSITORY_ROOT" || isAbsolute(cwd)) fail("INVALID_SPEC", "verification cwd must be a non-root canonical repository-relative path");
    try { assertM4CanonicalPath(cwd, `verification_commands[${index}].cwd`); } catch { fail("INVALID_SPEC", "verification cwd must be canonical and traversal-free"); }
    const timeout = positiveSafeInteger(command["timeout_ms"], `verification_commands[${index}].timeout_ms`); if (timeout > STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS) fail("INVALID_SPEC", `verification timeout exceeds ${STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS}`);
    return Object.freeze({ command_id: commandId, executable, args, cwd, timeout_ms: timeout });
  }));
}

export function normalizeStaticApprovedDagLaunchSpec(value: unknown): StaticApprovedDagLaunchSpec {
  const input = record(value, "launch spec"); exactKeys(input, ["spec_version", "run_label", "expected_repository_branch", "expected_head", "expected_tree", "goal", "verification_commands", "static_time_budgets", "static_max_attempts_per_leaf", "expected_route"], "launch spec");
  if (input["spec_version"] !== STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION) fail("INVALID_SPEC_VERSION", "launch spec version is unsupported");
  const branch = string(input["expected_repository_branch"], "expected_repository_branch", 512); const head = string(input["expected_head"], "expected_head", 64); const tree = string(input["expected_tree"], "expected_tree", 64);
  if (!/^[0-9a-f]{40,64}$/u.test(head) || !/^[0-9a-f]{40,64}$/u.test(tree)) fail("INVALID_SPEC", "expected HEAD and tree must be Git object IDs");
  const budgetInput = record(input["static_time_budgets"], "static_time_budgets"); exactKeys(budgetInput, ["worker_deadline_ms", "node_wall_ms", "workflow_wall_ms"], "static_time_budgets");
  const budgets = Object.freeze({ worker_deadline_ms: positiveSafeInteger(budgetInput["worker_deadline_ms"], "worker_deadline_ms"), node_wall_ms: positiveSafeInteger(budgetInput["node_wall_ms"], "node_wall_ms"), workflow_wall_ms: positiveSafeInteger(budgetInput["workflow_wall_ms"], "workflow_wall_ms") });
  if (budgets.worker_deadline_ms > budgets.node_wall_ms || budgets.node_wall_ms > budgets.workflow_wall_ms) fail("INVALID_SPEC", "static time budgets must satisfy worker <= node <= workflow");
  const attempts = input["static_max_attempts_per_leaf"]; if (attempts !== 1 && attempts !== 2) fail("INVALID_SPEC", "static_max_attempts_per_leaf must be 1 or 2");
  const route = record(input["expected_route"], "expected_route"); exactKeys(route, ["logical_role", "provider_id", "model_id", "effort", "fallback"], "expected_route");
  const effort = route["effort"];
  if (route["logical_role"] !== "TERRA_EXECUTOR" || route["provider_id"] !== "openai-codex" || route["model_id"] !== "gpt-5.6-terra" || (effort !== "high" && effort !== "xhigh") || route["fallback"] !== false) fail("STATIC_ROUTE_RESTRICTED", "only frozen Terra High or XHigh without fallback is authorized");
  const spec: StaticApprovedDagLaunchSpec = { spec_version: STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION, run_label: taskId(input["run_label"], "run_label"), expected_repository_branch: branch, expected_head: head, expected_tree: tree, goal: normalizeGoal(input["goal"]), verification_commands: normalizeCommands(input["verification_commands"]), static_time_budgets: budgets, static_max_attempts_per_leaf: attempts, expected_route: Object.freeze({ logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort, fallback: false }) };
  for (const task of spec.goal.tasks) if (task.verification_command_ids?.some((id) => !spec.verification_commands.some((command) => command.command_id === id))) fail("INVALID_SPEC", "task selected an unknown verification command");
  return JSON.parse(canonicalize(spec)) as StaticApprovedDagLaunchSpec;
}

export function staticApprovedDagSpecSha256(value: unknown): Sha256Digest { return sha256Canonical(normalizeStaticApprovedDagLaunchSpec(value)); }

export async function readStaticApprovedDagRepositoryFacts(cwd: string): Promise<StaticApprovedDagRepositoryFacts> {
  const repository = await resolveRepositoryIdentity({ requestedPath: cwd, requireHead: true });
  const fingerprint = await captureGitState(repository);
  return Object.freeze({ repository_root: repository.worktree_root, branch: repository.branch, head: repository.head, tree: repository.head_tree, clean: !fingerprint.dirty, active_operations: fingerprint.active_operations, index_lock: fingerprint.index_lock });
}

export async function verifyStaticApprovedDagRepositoryPreflight(spec: StaticApprovedDagLaunchSpec, cwd: string, reader = readStaticApprovedDagRepositoryFacts): Promise<string> {
  const facts = await reader(cwd); const requested = resolve(cwd);
  if (facts.repository_root !== requested) fail("WRONG_REPOSITORY", "launcher must be invoked from the repository root");
  if (facts.branch !== spec.expected_repository_branch) fail("WRONG_BRANCH", "repository branch differs from approved launch spec");
  if (facts.head !== spec.expected_head) fail("HEAD_DRIFT", "repository HEAD differs from approved launch spec");
  if (facts.tree !== spec.expected_tree) fail("TREE_DRIFT", "repository tree differs from approved launch spec");
  if (!facts.clean) fail("DIRTY_WORKTREE", "repository staged, unstaged, or untracked state is not clean");
  if (facts.active_operations.length > 0) fail("GIT_OPERATION_IN_PROGRESS", "repository has an active Git operation");
  if (facts.index_lock) fail("GIT_INDEX_LOCK_PRESENT", "repository index.lock is present");
  return facts.repository_root;
}

function same(left: unknown, right: unknown): boolean { return canonicalize(left) === canonicalize(right); }
function asRecord(value: unknown): JsonRecord | null { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : null; }
function stateString(value: unknown): string | null { return typeof value === "string" ? value : null; }
function stateCount(value: unknown): number | null { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null; }
function stateBoolean(value: unknown): boolean | null { return typeof value === "boolean" ? value : null; }

const WORKFLOW_TASK_STATUSES = ["PENDING", "RUNNING", "PASS", "BLOCKED"] as const;

/** Project only schema-bounded WorkflowState facts; never fabricate counters or tasks for partial states. */
function workflowStateSummary(result: BoundedMutationRunResult): StaticWorkflowStateSummary {
  const state = asRecord(result.finalState);
  const counters = state === null ? null : asRecord(state["counters"]);
  const invocations = counters === null ? null : asRecord(counters["worker_invocations"]);
  const tasks: StaticWorkflowTaskSummary[] = [];
  if (state !== null && Array.isArray(state["tasks"])) {
    for (const entry of state["tasks"] as unknown[]) {
      const task = asRecord(entry);
      if (task === null) continue;
      const task_id = stateString(task["task_id"]); const status = stateString(task["status"]);
      const attempts = stateCount(task["attempts"]); const postflight_completed = stateBoolean(task["postflight_completed"]);
      const verification_completed = stateBoolean(task["verification_completed"]); const retry_progress_admitted = stateBoolean(task["retry_progress_admitted"]);
      if (task_id === null || status === null || attempts === null || postflight_completed === null || verification_completed === null || retry_progress_admitted === null) continue;
      if (!(WORKFLOW_TASK_STATUSES as readonly string[]).includes(status)) continue;
      tasks.push({ task_id, status: status as StaticWorkflowTaskSummary["status"], attempts, postflight_completed, verification_completed, retry_progress_admitted });
    }
  }
  return Object.freeze({
    outcome: result.outcome,
    final_phase: state === null ? null : stateString(state["phase"]),
    terminal_reason: state === null ? null : stateString(state["terminal_reason"]),
    active_task_id: state === null ? null : stateString(state["active_task_id"]),
    leaves_completed: counters === null ? null : stateCount(counters["leaves_completed"]),
    terra_worker_invocations: invocations === null ? null : stateCount(invocations["terra_executor"]),
    tasks: Object.freeze(tasks),
  });
}
function selectedCommands(spec: StaticApprovedDagLaunchSpec, task: StaticGoalTask): readonly StaticApprovedDagLaunchSpec["verification_commands"][number][] { const selected = task.verification_command_ids === undefined ? null : new Set(task.verification_command_ids); return spec.verification_commands.filter((command) => selected === null || selected.has(command.command_id)); }
function commandsMatch(spec: readonly StaticApprovedDagLaunchSpec["verification_commands"][number][], actual: unknown, repositoryRoot: string): boolean {
  if (!Array.isArray(actual) || actual.length !== spec.length) return false;
  return actual.every((entry, index) => {
    const command = spec[index]!; const actualRecord = entry as JsonRecord;
    if (actualRecord === null || typeof actualRecord !== "object" || Array.isArray(actualRecord) || actualRecord["command_id"] !== command.command_id || actualRecord["cwd"] !== command.cwd || actualRecord["timeout_ms"] !== command.timeout_ms || actualRecord["network"] !== "FORBIDDEN") return false;
    const argv = actualRecord["argv"]; if (!Array.isArray(argv) || argv.length !== command.args.length + 1 || argv[0] !== command.executable) return false;
    const direct = [command.executable, ...command.args];
    const scopedScript = command.args.length === 0 ? direct : [command.executable, join(repositoryRoot, command.cwd, command.args[0]!), ...command.args.slice(1)];
    return same(argv, direct) || same(argv, scopedScript);
  });
}

/** Deterministic parent-side authority check; it does not construct a plan or execute work. */
export function createStaticApprovedDagPlanApproval(spec: StaticApprovedDagLaunchSpec): NonNullable<BoundedMutationOptions["approveTasks"]> {
  return async ({ mode, plan, tasks, executionAuthority }) => {
    if (mode !== "STATIC_APPROVED_DAG" || plan === null || executionAuthority.plan === null || plan.content_sha256 !== executionAuthority.plan.content_sha256) return null;
    const bindings = plan.bindings;
    if (executionAuthority.mode !== "STATIC_APPROVED_DAG" || executionAuthority.repository.branch !== spec.expected_repository_branch || executionAuthority.repository.head !== spec.expected_head || executionAuthority.repository.head_tree !== spec.expected_tree) return null;
    if (!same(bindings.scope, spec.goal.scope) || !same(bindings.required_inputs, spec.goal.scope.readable_paths) || !same(bindings.required_outputs, spec.goal.required_outputs) || !same(bindings.limits.static_time_budgets, spec.static_time_budgets) || bindings.limits.max_wall_time_ms !== spec.static_time_budgets.workflow_wall_ms || bindings.limits.max_attempts_per_leaf !== spec.static_max_attempts_per_leaf) return null;
    const route = { logical_role: spec.expected_route.logical_role, provider_id: spec.expected_route.provider_id, model_id: spec.expected_route.model_id, effort: spec.expected_route.effort };
    if (executionAuthority.route_map.fallback !== false || !same(bindings.logical_routes.map(({ logical_role, provider_id, model_id, effort }) => ({ logical_role, provider_id, model_id, effort })), [route]) || !same(executionAuthority.route_map.routes.filter((candidate) => candidate.logical_role === "TERRA_EXECUTOR").map(({ logical_role, provider_id, model_id, effort }) => ({ logical_role, provider_id, model_id, effort })), [route]) || !commandsMatch(spec.verification_commands, bindings.verification_commands, executionAuthority.repository.worktree_root)) return null;
    if (tasks.length !== executionAuthority.tasks.length || tasks.some((task, index) => task.content_sha256 !== executionAuthority.tasks[index]?.content_sha256) || executionAuthority.tasks.length !== spec.goal.tasks.length || !same(executionAuthority.task_graph?.edges, spec.goal.tasks.flatMap((task) => task.dependencies.map((dependency) => ({ from: dependency, to: task.task_id }))))) return null;
    for (let index = 0; index < spec.goal.tasks.length; index += 1) {
      const expected = spec.goal.tasks[index]!; const actual = executionAuthority.tasks[index]!;
      if (actual.task_id !== expected.task_id || actual.objective !== expected.objective || actual.assigned_role !== "TERRA_EXECUTOR" || actual.write_owner !== expected.task_id || !same(actual.dependencies, expected.dependencies) || !same(actual.scope, { readable_paths: spec.goal.scope.readable_paths, editable_paths: expected.editable_paths, frozen_paths: spec.goal.scope.frozen_paths }) || !same(actual.required_inputs, spec.goal.scope.readable_paths) || !same(actual.required_outputs, expected.required_outputs) || !commandsMatch(selectedCommands(spec, expected), actual.verification_commands, executionAuthority.repository.worktree_root)) return null;
    }
    return plan.content_sha256 as Sha256Digest;
  };
}

function resultReport(spec: StaticApprovedDagLaunchSpec | null, digest: Sha256Digest | null, result: BoundedMutationRunResult | null, error: unknown): StaticApprovedDagLaunchReport {
  const reason = result?.reason ?? (error instanceof Error ? error.message : "launcher failed"); const boundedReason = reason.slice(0, 4096);
  const phase = result?.finalState?.phase ?? null;
  const classification = result?.outcome === "PASS" && phase === "PASS" ? "PASS" : result?.outcome === "BLOCKED" && phase === "BLOCKED" ? "VALID_BLOCKED" : "INVALID";
  // No authoritative finalState means no state summary; never fabricate counters or tasks.
  const workflow = result !== null && asRecord(result.finalState) !== null ? workflowStateSummary(result) : null;
  return Object.freeze({
    classification,
    spec_sha256: digest,
    run_label: spec?.run_label ?? null,
    reason: boundedReason,
    workflow,
    evidence_root: typeof result?.evidenceRoot === "string" ? result.evidenceRoot : null,
    hygiene_warning: typeof result?.hygieneWarning === "string" ? result.hygieneWarning.slice(0, 4096) : null,
    telemetry: null,
  });
}

export async function executeStaticApprovedDag(input: ExecuteStaticApprovedDagInput): Promise<StaticApprovedDagLaunchReport> {
  let spec: StaticApprovedDagLaunchSpec | null = null; let digest: Sha256Digest | null = null;
  try {
    spec = normalizeStaticApprovedDagLaunchSpec(input.spec); digest = sha256Canonical(spec);
    if (input.approved_spec_sha256 !== digest) fail("APPROVED_SPEC_MISMATCH", "--approved-spec-sha256 does not match the normalized launch spec");
    const cwd = input.cwd ?? process.cwd(); await verifyStaticApprovedDagRepositoryPreflight(spec, cwd, input.repositoryFacts);
    const authority: BoundedMutationAuthority = { verification_commands: spec.verification_commands as readonly ControllerVerificationCommand[], static_time_budgets: spec.static_time_budgets, static_max_attempts_per_leaf: spec.static_max_attempts_per_leaf, ...(spec.expected_route.effort === "xhigh" ? { static_terra_effort: "xhigh" as const } : {}) };
    const result = await (input.controller ?? runBoundedMutationWorkflow)(spec.goal, { cwd, authority, approveTasks: createStaticApprovedDagPlanApproval(spec) });
    return resultReport(spec, digest, result, null);
  } catch (error: unknown) {
    return resultReport(spec, digest, null, error);
  }
}
