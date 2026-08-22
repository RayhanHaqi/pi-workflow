import { isAbsolute, join, normalize, resolve } from "node:path";

import { canonicalize } from "./canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { captureGitState } from "./repository/fingerprint.js";
import { resolveRepositoryIdentity } from "./repository/index.js";
import { assertM4CanonicalPath } from "./secure-fs/path.js";
import { isBoundedRoutingIdentity, type ModelExecutionDefinitionV1 } from "./schemas/definitions.js";
import {
  runBoundedMutationWorkflow,
  type BoundedMutationAuthority,
  type BoundedMutationOptions,
  type BoundedMutationRunResult,
  type ControllerVerificationCommand,
  type StaticApprovedDagTimeBudgets,
} from "./workflow-controller.js";

export const STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION = "static-approved-dag-launch-v1" as const;
/** Capability-oriented coding route; model identity is exact owner-selected routing data, never a brand bound into the engine. */
export const STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION_V2 = "static-approved-dag-launch-v2" as const;
export const STATIC_APPROVED_DAG_COMMAND_TIMEOUT_MAX_MS = 60_000;

export class StaticApprovedDagLaunchError extends Error {
  public constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "StaticApprovedDagLaunchError";
  }
}

type JsonRecord = Record<string, unknown>;
type StaticWorkflowTaskSummary = Readonly<{ readonly task_id: string; readonly status: "PENDING" | "RUNNING" | "PASS" | "BLOCKED"; readonly attempts: number; readonly postflight_completed: boolean; readonly verification_completed: boolean; readonly retry_progress_admitted: boolean }>;
type StaticWorkflowStateSummary = Readonly<{ readonly outcome: "PASS" | "BLOCKED"; readonly final_phase: string | null; readonly terminal_reason: string | null; readonly active_task_id: string | null; readonly leaves_completed: number | null; readonly terra_worker_invocations: number | null; readonly coding_worker_invocations: number | null; readonly tasks: readonly StaticWorkflowTaskSummary[] }>;
type StaticGoalScope = Readonly<{ readonly readable_paths: readonly string[]; readonly editable_paths: readonly string[]; readonly frozen_paths: readonly string[] }>;
type StaticGoalTask = Readonly<{ readonly task_id: string; readonly objective: string; readonly editable_paths: readonly string[]; readonly required_outputs: readonly string[]; readonly dependencies: readonly string[]; readonly verification_command_ids?: readonly string[] }>;
/** Frozen legacy V1 route: Terra only. Normalization and digest semantics are immutable historical authority. */
type StaticRouteV1 = Readonly<{ readonly logical_role: "TERRA_EXECUTOR"; readonly provider_id: "openai-codex"; readonly model_id: "gpt-5.6-terra"; readonly effort: "high" | "xhigh"; readonly fallback: false }>;
/** V2 route: capability-oriented CODING_EXECUTOR with exact bounded provider/model routing data, high effort, no fallback. */
type StaticRouteV2 = Readonly<{ readonly logical_role: "CODING_EXECUTOR"; readonly provider_id: string; readonly model_id: string; readonly effort: "high"; readonly fallback: false; readonly model_execution_definition?: ModelExecutionDefinitionV1 }>;

export interface StaticApprovedDagLaunchSpec {
  readonly spec_version: typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION | typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION_V2;
  readonly run_label: string;
  readonly expected_repository_branch: string;
  readonly expected_head: string;
  readonly expected_tree: string;
  readonly goal: Readonly<{ readonly objective: string; readonly stop_condition: string; readonly execution_mode: "STATIC_APPROVED_DAG"; readonly scope: StaticGoalScope; readonly required_outputs: readonly string[]; readonly tasks: readonly StaticGoalTask[] }>;
  readonly verification_commands: readonly Readonly<{ readonly command_id: string; readonly executable: string; readonly args: readonly string[]; readonly cwd: string; readonly timeout_ms: number }>[];
  readonly static_time_budgets: StaticApprovedDagTimeBudgets;
  readonly static_max_attempts_per_leaf: 1 | 2;
  readonly expected_route: StaticRouteV1 | StaticRouteV2;
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

/** Exact bounded routing identity for V2 provider/model routing data; shared grammar authority lives in schemas/definitions. */
function routeIdentifier(value: unknown, label: string): string { const result = string(value, label, 128); if (!isBoundedRoutingIdentity(result)) fail("INVALID_SPEC", `${label} is not a bounded routing identifier`); return result; }

/**
 * Strict V1 dynamic-model execution authority shape. The object is authority; its canonical
 * digest is derived, never independently supplied. Unsupported shapes fail closed here so a
 * mutated or future-shaped definition can never silently widen execution authority.
 */
function normalizeModelExecutionDefinition(value: unknown, route: Readonly<{ readonly provider_id: string; readonly model_id: string }>): ModelExecutionDefinitionV1 {
  const label = "expected_route.model_execution_definition";
  const input = record(value, label);
  exactKeys(input, ["schema_id", "canonicalization_id", "provider_id", "model_id", "api", "base_url", "reasoning", "input", "context_window", "max_tokens", "compat", "headers", "thinking_level_map"], label);
  if (input["schema_id"] !== "pi_gacw_model_execution_definition_v1") fail("INVALID_SPEC", `${label}.schema_id is unsupported`);
  if (input["canonicalization_id"] !== "canonical-json-v1") fail("INVALID_SPEC", `${label}.canonicalization_id is unsupported`);
  const provider_id = routeIdentifier(input["provider_id"], `${label}.provider_id`);
  const model_id = routeIdentifier(input["model_id"], `${label}.model_id`);
  if (provider_id !== route.provider_id || model_id !== route.model_id) fail("INVALID_SPEC", `${label} identity differs from the approved route`);
  const api = string(input["api"], `${label}.api`, 128);
  const base_url = string(input["base_url"], `${label}.base_url`, 2048);
  if (typeof input["reasoning"] !== "boolean") fail("INVALID_SPEC", `${label}.reasoning must be a boolean`);
  const inputModalities: string[] = [];
  if (!Array.isArray(input["input"]) || input["input"].length === 0 || input["input"].length > 8) fail("INVALID_SPEC", `${label}.input must be a bounded non-empty modality array`);
  for (const entry of input["input"]) inputModalities.push(string(entry, `${label}.input`, 32));
  const context_window = positiveSafeInteger(input["context_window"], `${label}.context_window`);
  const max_tokens = positiveSafeInteger(input["max_tokens"], `${label}.max_tokens`);
  const compatInput = record(input["compat"], `${label}.compat`);
  exactKeys(compatInput, ["supportsDeveloperRole", "thinkingFormat"], `${label}.compat`);
  if (typeof compatInput["supportsDeveloperRole"] !== "boolean") fail("INVALID_SPEC", `${label}.compat.supportsDeveloperRole must be a boolean`);
  const thinkingFormat = string(compatInput["thinkingFormat"], `${label}.compat.thinkingFormat`, 64);
  const headersInput = record(input["headers"], `${label}.headers`);
  if (Object.keys(headersInput).length !== 0) fail("INVALID_SPEC", `${label}.headers must be empty; non-empty model headers are unsupported by ModelExecutionDefinitionV1`);
  if (input["thinking_level_map"] !== "ABSENT") fail("INVALID_SPEC", `${label}.thinking_level_map must be the literal "ABSENT"; present thinking-level maps are unsupported`);
  return Object.freeze({
    schema_id: "pi_gacw_model_execution_definition_v1", canonicalization_id: "canonical-json-v1", provider_id, model_id, api, base_url,
    reasoning: input["reasoning"] as boolean, input: Object.freeze(inputModalities), context_window, max_tokens,
    compat: Object.freeze({ supportsDeveloperRole: compatInput["supportsDeveloperRole"] as boolean, thinkingFormat }),
    headers: Object.freeze({}), thinking_level_map: "ABSENT" as const,
  });
}

/** V1 keeps its frozen legacy Terra normalization byte-for-byte; V2 admits only the capability-oriented coding route. */
function normalizeExpectedRoute(value: unknown, specVersion: typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION | typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION_V2): StaticRouteV1 | StaticRouteV2 {
  const route = record(value, "expected_route");
  // V1 rejects a model execution definition outright; V2 admits it as optional derived authority.
  const hasDefinition = specVersion === STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION_V2 && Object.hasOwn(route, "model_execution_definition");
  exactKeys(route, hasDefinition ? ["logical_role", "provider_id", "model_id", "effort", "fallback", "model_execution_definition"] : ["logical_role", "provider_id", "model_id", "effort", "fallback"], "expected_route");
  if (route["fallback"] !== false) fail("STATIC_ROUTE_RESTRICTED", "expected_route.fallback must be false; no fallback is authorized");
  if (specVersion === STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION) {
    const effort = route["effort"];
    if (route["logical_role"] !== "TERRA_EXECUTOR" || route["provider_id"] !== "openai-codex" || route["model_id"] !== "gpt-5.6-terra" || (effort !== "high" && effort !== "xhigh")) fail("STATIC_ROUTE_RESTRICTED", "only frozen Terra High or XHigh without fallback is authorized");
    return Object.freeze({ logical_role: "TERRA_EXECUTOR", provider_id: "openai-codex", model_id: "gpt-5.6-terra", effort, fallback: false });
  }
  if (route["logical_role"] !== "CODING_EXECUTOR") fail("STATIC_ROUTE_RESTRICTED", "static-approved-dag-launch-v2 authorizes only the CODING_EXECUTOR role");
  if (route["effort"] !== "high") fail("STATIC_ROUTE_RESTRICTED", "static-approved-dag-launch-v2 binds exactly high effort; xhigh and max require a future qualification");
  const provider_id = routeIdentifier(route["provider_id"], "expected_route.provider_id");
  const model_id = routeIdentifier(route["model_id"], "expected_route.model_id");
  const model_execution_definition = hasDefinition ? normalizeModelExecutionDefinition(route["model_execution_definition"], { provider_id, model_id }) : undefined;
  return Object.freeze({ logical_role: "CODING_EXECUTOR", provider_id, model_id, effort: "high" as const, fallback: false as const, ...(model_execution_definition === undefined ? {} : { model_execution_definition }) });
}

export function normalizeStaticApprovedDagLaunchSpec(value: unknown): StaticApprovedDagLaunchSpec {
  const input = record(value, "launch spec"); exactKeys(input, ["spec_version", "run_label", "expected_repository_branch", "expected_head", "expected_tree", "goal", "verification_commands", "static_time_budgets", "static_max_attempts_per_leaf", "expected_route"], "launch spec");
  const specVersion = input["spec_version"];
  if (specVersion !== STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION && specVersion !== STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION_V2) fail("INVALID_SPEC_VERSION", "launch spec version is unsupported");
  const branch = string(input["expected_repository_branch"], "expected_repository_branch", 512); const head = string(input["expected_head"], "expected_head", 64); const tree = string(input["expected_tree"], "expected_tree", 64);
  if (!/^[0-9a-f]{40,64}$/u.test(head) || !/^[0-9a-f]{40,64}$/u.test(tree)) fail("INVALID_SPEC", "expected HEAD and tree must be Git object IDs");
  const budgetInput = record(input["static_time_budgets"], "static_time_budgets"); exactKeys(budgetInput, ["worker_deadline_ms", "node_wall_ms", "workflow_wall_ms"], "static_time_budgets");
  const budgets = Object.freeze({ worker_deadline_ms: positiveSafeInteger(budgetInput["worker_deadline_ms"], "worker_deadline_ms"), node_wall_ms: positiveSafeInteger(budgetInput["node_wall_ms"], "node_wall_ms"), workflow_wall_ms: positiveSafeInteger(budgetInput["workflow_wall_ms"], "workflow_wall_ms") });
  if (budgets.worker_deadline_ms > budgets.node_wall_ms || budgets.node_wall_ms > budgets.workflow_wall_ms) fail("INVALID_SPEC", "static time budgets must satisfy worker <= node <= workflow");
  const attempts = input["static_max_attempts_per_leaf"]; if (attempts !== 1 && attempts !== 2) fail("INVALID_SPEC", "static_max_attempts_per_leaf must be 1 or 2");
  const expectedRoute = normalizeExpectedRoute(input["expected_route"], specVersion);
  const spec: StaticApprovedDagLaunchSpec = { spec_version: specVersion, run_label: taskId(input["run_label"], "run_label"), expected_repository_branch: branch, expected_head: head, expected_tree: tree, goal: normalizeGoal(input["goal"]), verification_commands: normalizeCommands(input["verification_commands"]), static_time_budgets: budgets, static_max_attempts_per_leaf: attempts, expected_route: expectedRoute };
  for (const task of spec.goal.tasks) if (task.verification_command_ids?.some((id) => !spec.verification_commands.some((command) => command.command_id === id))) fail("INVALID_SPEC", "task selected an unknown verification command");
  return JSON.parse(canonicalize(spec)) as StaticApprovedDagLaunchSpec;
}

export function staticApprovedDagSpecSha256(value: unknown): Sha256Digest { return sha256Canonical(normalizeStaticApprovedDagLaunchSpec(value)); }

export type StaticApprovedDagInspectionReport = Readonly<{ classification: "INSPECTED" | "INVALID"; spec_version: typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION | typeof STATIC_APPROVED_DAG_LAUNCH_SPEC_VERSION_V2 | null; spec_sha256: Sha256Digest | null; run_label: string | null; reason: string; repository: Readonly<{ expected_branch: string; expected_head: string; expected_tree: string }> | null; graph: Readonly<{ node_count: number; edge_count: number; nodes: readonly Readonly<{ task_id: string; dependencies: readonly string[]; editable_paths: readonly string[]; required_outputs: readonly string[]; verification_command_ids: readonly string[] }>[]; edges: readonly Readonly<{ from: string; to: string }>[] }> | null; route: StaticApprovedDagLaunchSpec["expected_route"] | null; budgets: Readonly<StaticApprovedDagTimeBudgets & { max_attempts_per_leaf: 1 | 2 }> | null; verification_commands: readonly Readonly<{ command_id: string; cwd: string; timeout_ms: number }>[] | null }>;

/**
 * Provider-free owner inspection of a prospective frozen launch spec: normalize, compute the
 * canonical digest, and project a bounded topology summary. Pure — no filesystem, Git, prompt,
 * or controller access; invalid specs stay INVALID via the existing normalization boundary.
 */
export function inspectStaticApprovedDagSpec(value: unknown): StaticApprovedDagInspectionReport {
  try {
    const spec = normalizeStaticApprovedDagLaunchSpec(value);
    // Omitted per-task selections mean every defined command applies at execution; project that exact semantics instead of inventing a subset.
    const nodes = spec.goal.tasks.map((task) => Object.freeze({ task_id: task.task_id, dependencies: task.dependencies, editable_paths: task.editable_paths, required_outputs: task.required_outputs, verification_command_ids: task.verification_command_ids ?? spec.verification_commands.map((command) => command.command_id) }));
    const edges = spec.goal.tasks.flatMap((task) => task.dependencies.map((dependency) => Object.freeze({ from: dependency, to: task.task_id })));
    return Object.freeze({
      classification: "INSPECTED",
      spec_version: spec.spec_version,
      spec_sha256: sha256Canonical(spec),
      run_label: spec.run_label,
      reason: "INSPECTED",
      repository: Object.freeze({ expected_branch: spec.expected_repository_branch, expected_head: spec.expected_head, expected_tree: spec.expected_tree }),
      graph: Object.freeze({ node_count: nodes.length, edge_count: edges.length, nodes: Object.freeze(nodes), edges: Object.freeze(edges) }),
      route: spec.expected_route,
      budgets: Object.freeze({ ...spec.static_time_budgets, max_attempts_per_leaf: spec.static_max_attempts_per_leaf }),
      verification_commands: Object.freeze(spec.verification_commands.map(({ command_id, cwd, timeout_ms }) => Object.freeze({ command_id, cwd, timeout_ms }))),
    });
  } catch (error: unknown) {
    return Object.freeze({ classification: "INVALID", spec_version: null, spec_sha256: null, run_label: null, reason: (error instanceof Error ? error.message : "inspection failed").slice(0, 4096), repository: null, graph: null, route: null, budgets: null, verification_commands: null });
  }
}

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
function workflowStateSummary(result: BoundedMutationRunResult, codingExecutor: boolean): StaticWorkflowStateSummary {
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
  // The persisted state machine stores static coding invocations in the legacy
  // `terra_executor` counter slot; the active product surface reports it under
  // the capability-oriented name for V2 runs and the legacy name for V1 runs.
  const staticWorkerInvocations = invocations === null ? null : stateCount(invocations["terra_executor"]);
  return Object.freeze({
    outcome: result.outcome,
    final_phase: state === null ? null : stateString(state["phase"]),
    terminal_reason: state === null ? null : stateString(state["terminal_reason"]),
    active_task_id: state === null ? null : stateString(state["active_task_id"]),
    leaves_completed: counters === null ? null : stateCount(counters["leaves_completed"]),
    terra_worker_invocations: codingExecutor ? null : staticWorkerInvocations,
    coding_worker_invocations: codingExecutor ? staticWorkerInvocations : null,
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

/** TaskGraph and PlanApproval identity projections treat edges as a set; match the projected representation, not insertion order. */
function edgeIdentity(value: unknown): string | null {
  const record = asRecord(value);
  if (record === null || Object.keys(record).sort().join(",") !== "from,to") return null;
  return typeof record["from"] === "string" && typeof record["to"] === "string" ? `${record["from"]}\u0000${record["to"]}` : null;
}
function sameEdgeSet(actual: unknown, expected: readonly Readonly<{ readonly from: string; readonly to: string }>[]): boolean {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  const identities: string[] = [];
  for (const entry of actual) { const identity = edgeIdentity(entry); if (identity === null) return false; identities.push(identity); }
  return same(identities.sort(), expected.map((edge) => `${edge.from}\u0000${edge.to}`).sort());
}

/** The dynamic-model digest is derived authority: recomputed from the frozen definition, never trusted from the caller. */
function approvedModelDefinitionDigest(route: StaticApprovedDagLaunchSpec["expected_route"]): Sha256Digest | null {
  return route.logical_role === "CODING_EXECUTOR" && route.model_execution_definition !== undefined ? sha256Canonical(route.model_execution_definition) : null;
}

/** Deterministic parent-side authority check; it does not construct a plan or execute work. */
export function createStaticApprovedDagPlanApproval(spec: StaticApprovedDagLaunchSpec): NonNullable<BoundedMutationOptions["approveTasks"]> {
  return async ({ mode, plan, tasks, executionAuthority }) => {
    if (mode !== "STATIC_APPROVED_DAG" || plan === null || executionAuthority.plan === null || plan.content_sha256 !== executionAuthority.plan.content_sha256) return null;
    const bindings = plan.bindings;
    if (executionAuthority.mode !== "STATIC_APPROVED_DAG" || executionAuthority.repository.branch !== spec.expected_repository_branch || executionAuthority.repository.head !== spec.expected_head || executionAuthority.repository.head_tree !== spec.expected_tree) return null;
    if (!same(bindings.scope, spec.goal.scope) || !same(bindings.required_inputs, spec.goal.scope.readable_paths) || !same(bindings.required_outputs, spec.goal.required_outputs) || !same(bindings.limits.static_time_budgets, spec.static_time_budgets) || bindings.limits.max_wall_time_ms !== spec.static_time_budgets.workflow_wall_ms || bindings.limits.max_attempts_per_leaf !== spec.static_max_attempts_per_leaf) return null;
    const executorRole = spec.expected_route.logical_role;
    const route = { logical_role: spec.expected_route.logical_role, provider_id: spec.expected_route.provider_id, model_id: spec.expected_route.model_id, effort: spec.expected_route.effort };
    const modelDefinitionDigest = approvedModelDefinitionDigest(spec.expected_route);
    if (executionAuthority.route_map.fallback !== false || !same(bindings.logical_routes.map(({ logical_role, provider_id, model_id, effort }) => ({ logical_role, provider_id, model_id, effort })), [route]) || !same(executionAuthority.route_map.routes.filter((candidate) => candidate.logical_role === executorRole).map(({ logical_role, provider_id, model_id, effort }) => ({ logical_role, provider_id, model_id, effort })), [route]) || !commandsMatch(spec.verification_commands, bindings.verification_commands, executionAuthority.repository.worktree_root)) return null;
    if (modelDefinitionDigest !== null) {
      const executorEntries = executionAuthority.route_map.routes.filter((candidate) => candidate.logical_role === executorRole);
      if (executorEntries.length !== 1 || !("model_definition_sha256" in executorEntries[0]!) || executorEntries[0]!.model_definition_sha256 !== modelDefinitionDigest) return null;
    }
    else if (executionAuthority.route_map.routes.some((candidate) => "model_definition_sha256" in candidate)) return null;
    if (tasks.length !== executionAuthority.tasks.length || tasks.some((task, index) => task.content_sha256 !== executionAuthority.tasks[index]?.content_sha256) || executionAuthority.tasks.length !== spec.goal.tasks.length || !sameEdgeSet(executionAuthority.task_graph?.edges, spec.goal.tasks.flatMap((task) => task.dependencies.map((dependency) => ({ from: dependency, to: task.task_id }))))) return null;
    for (let index = 0; index < spec.goal.tasks.length; index += 1) {
      const expected = spec.goal.tasks[index]!; const actual = executionAuthority.tasks[index]!;
      if (actual.task_id !== expected.task_id || actual.objective !== expected.objective || actual.assigned_role !== executorRole || actual.write_owner !== expected.task_id || !same(actual.dependencies, expected.dependencies) || !same(actual.scope, { readable_paths: spec.goal.scope.readable_paths, editable_paths: expected.editable_paths, frozen_paths: spec.goal.scope.frozen_paths }) || !same(actual.required_inputs, spec.goal.scope.readable_paths) || !same(actual.required_outputs, expected.required_outputs) || !commandsMatch(selectedCommands(spec, expected), actual.verification_commands, executionAuthority.repository.worktree_root)) return null;
    }
    return plan.content_sha256 as Sha256Digest;
  };
}

function resultReport(spec: StaticApprovedDagLaunchSpec | null, digest: Sha256Digest | null, result: BoundedMutationRunResult | null, error: unknown): StaticApprovedDagLaunchReport {
  const reason = result?.reason ?? (error instanceof Error ? error.message : "launcher failed"); const boundedReason = reason.slice(0, 4096);
  const phase = result?.finalState?.phase ?? null;
  const classification = result?.outcome === "PASS" && phase === "PASS" ? "PASS" : result?.outcome === "BLOCKED" && phase === "BLOCKED" ? "VALID_BLOCKED" : "INVALID";
  // No authoritative finalState means no state summary; never fabricate counters or tasks.
  const workflow = result !== null && asRecord(result.finalState) !== null ? workflowStateSummary(result, spec !== null && spec.expected_route.logical_role === "CODING_EXECUTOR") : null;
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
    // Route authority is bound transitively: the exact approved route becomes
    // controller authority; no layer may rewrite provider, model, effort, or
    // logical role, and no fallback exists.
    const authority: BoundedMutationAuthority = spec.expected_route.logical_role === "CODING_EXECUTOR"
      ? { verification_commands: spec.verification_commands as readonly ControllerVerificationCommand[], static_time_budgets: spec.static_time_budgets, static_max_attempts_per_leaf: spec.static_max_attempts_per_leaf,
          static_coding_route: { provider_id: spec.expected_route.provider_id, model_id: spec.expected_route.model_id, effort: spec.expected_route.effort,
            ...(approvedModelDefinitionDigest(spec.expected_route) !== null ? { model_definition_sha256: approvedModelDefinitionDigest(spec.expected_route)! } : {}) } }
      : { verification_commands: spec.verification_commands as readonly ControllerVerificationCommand[], static_time_budgets: spec.static_time_budgets, static_max_attempts_per_leaf: spec.static_max_attempts_per_leaf, ...(spec.expected_route.effort === "xhigh" ? { static_terra_effort: "xhigh" as const } : {}) };
    const result = await (input.controller ?? runBoundedMutationWorkflow)(spec.goal, { cwd, authority, approveTasks: createStaticApprovedDagPlanApproval(spec) });
    return resultReport(spec, digest, result, null);
  } catch (error: unknown) {
    return resultReport(spec, digest, null, error);
  }
}
