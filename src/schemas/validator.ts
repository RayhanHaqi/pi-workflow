import { Ajv, type ErrorObject, type ValidateFunction } from "ajv";

import { canonicalize } from "../canonical-json/index.js";
import {
  getProjectionDefinition,
  unsafeVerifyContentIdentity,
  unsafeVerifyDocumentIdentities,
  unsafeWithContentIdentity,
  unsafeWithDocumentIdentities,
  type DomainProjectionId,
} from "../identity/projections.js";
import {
  CONCRETE_EXECUTION_MODES,
  LOGICAL_MODEL_ROLES,
  isBoundedRoutingIdentity,
  getInternalSchemaRegistry,
  type AuthorityLockDocument,
  type BaselineDocument,
  type ContractDocument,
  type EvidenceManifestDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type ObjectiveDocument,
  type PersistedStatePointerDocument,
  type PlanApprovalDocument,
  type ReducerPolicy,
  type RouteMapDocument,
  type SchemaId,
  type StateTransitionCommitDocument,
  type TaskDocument,
  type TaskGraphDocument,
  type TransitionEvent,
  type WorkflowState,
} from "./definitions.js";

export class ContractValidationError extends TypeError {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "ContractValidationError";
    this.code = code;
  }
}

export type JsonSchemaSnapshot =
  | null
  | boolean
  | number
  | string
  | { readonly [key: string]: JsonSchemaSnapshot }
  | readonly JsonSchemaSnapshot[];

export interface SchemaSnapshot {
  readonly schemaId: SchemaId;
  readonly fileName: string;
  readonly schema: JsonSchemaSnapshot;
}

function cloneSerializable<T>(value: unknown): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function deepFreezeSnapshot<T>(value: T, seen = new Set<object>()): T {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && "value" in descriptor) deepFreezeSnapshot(descriptor.value, seen);
  }
  Object.freeze(object);
  return value;
}

const internalSchemaEntries = getInternalSchemaRegistry();

/** Stable IDs only; canonical schema objects remain package-private. */
export const SCHEMA_IDS: readonly SchemaId[] = Object.freeze(
  internalSchemaEntries.map((entry) => entry.schemaId),
);

/** Returns a fresh, detached, deeply frozen, serializable schema snapshot. */
export function getSchemaSnapshot(schemaId: SchemaId): JsonSchemaSnapshot {
  const entry = internalSchemaEntries.find((candidate) => candidate.schemaId === schemaId);
  if (entry === undefined) {
    throw new ContractValidationError("UNKNOWN_SCHEMA", `Unknown schema ID ${schemaId}`);
  }
  return deepFreezeSnapshot(cloneSerializable<JsonSchemaSnapshot>(entry.schema));
}

/** Returns fresh, detached, deeply frozen snapshots of the complete schema inventory. */
export function listSchemaSnapshots(): readonly SchemaSnapshot[] {
  return deepFreezeSnapshot(
    internalSchemaEntries.map((entry) => ({
      schemaId: entry.schemaId,
      fileName: entry.fileName,
      schema: cloneSerializable<JsonSchemaSnapshot>(entry.schema),
    })),
  );
}

const ajv = new Ajv({ allErrors: true, strict: true, validateFormats: false });
const validators = new Map<SchemaId, ValidateFunction>();
for (const entry of internalSchemaEntries) {
  // Ajv receives an exact serialized clone, never the frozen canonical object.
  validators.set(entry.schemaId, ajv.compile(cloneSerializable(entry.schema)));
}

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  if (errors === null || errors === undefined || errors.length === 0) {
    return "unknown schema validation error";
  }
  return errors
    .map((error) => `${error.instancePath || "/"} ${error.message ?? error.keyword}`)
    .sort()
    .join("; ");
}

export function validateSchema(schemaId: SchemaId, value: unknown): { readonly valid: true } | { readonly valid: false; readonly errors: string } {
  const validator = validators.get(schemaId);
  if (validator === undefined) {
    throw new ContractValidationError("UNKNOWN_SCHEMA", `Unknown schema ID ${schemaId}`);
  }
  return validator(value) ? { valid: true } : { valid: false, errors: formatErrors(validator.errors) };
}

export function assertSchema(schemaId: SchemaId, value: unknown): void {
  const result = validateSchema(schemaId, value);
  if (!result.valid) {
    throw new ContractValidationError("SCHEMA_INVALID", `${schemaId}: ${result.errors}`);
  }
}

function recordOf(value: unknown): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new ContractValidationError("DOCUMENT_NOT_OBJECT", "Document must be an object");
  }
  return value as Record<string, unknown>;
}

function canonicalRepositoryPath(path: string, label: string): string {
  if (
    path.length === 0 ||
    path.startsWith("/") ||
    /^[A-Za-z]:/.test(path) ||
    path.includes("\\") ||
    path.includes("\u0000") ||
    path.endsWith("/")
  ) {
    throw new ContractValidationError("NONCANONICAL_REPOSITORY_PATH", `${label} must be a canonical repository-relative path: ${JSON.stringify(path)}`);
  }
  const segments = path.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new ContractValidationError("NONCANONICAL_REPOSITORY_PATH", `${label} contains an empty, dot, or dot-dot segment: ${JSON.stringify(path)}`);
  }
  return path;
}

function assertCanonicalPathList(kind: string, paths: readonly string[]): void {
  const seen = new Set<string>();
  for (const path of paths) {
    const canonical = canonicalRepositoryPath(path, `${kind} path`);
    if (seen.has(canonical)) {
      throw new ContractValidationError("DUPLICATE_REPOSITORY_PATH", `${kind} path ${path} is duplicated`);
    }
    seen.add(canonical);
  }
}

function pathsOverlap(left: string, right: string): boolean {
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`);
}

function assertNoScopeOverlap(scope: {
  readable_paths?: readonly string[];
  editable_paths: readonly string[];
  frozen_paths: readonly string[];
}): void {
  assertCanonicalPathList("readable", scope.readable_paths ?? []);
  assertCanonicalPathList("editable", scope.editable_paths);
  assertCanonicalPathList("frozen", scope.frozen_paths);

  for (const editable of scope.editable_paths) {
    for (const frozen of scope.frozen_paths) {
      if (pathsOverlap(editable, frozen)) {
        throw new ContractValidationError(
          "OVERLAPPING_EDITABLE_AND_FROZEN_PATHS",
          `${editable} overlaps ${frozen}`,
        );
      }
    }
  }
}

function assertUniqueBy<T>(values: readonly T[], selector: (value: T) => string, code: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    const key = selector(value);
    if (seen.has(key)) {
      throw new ContractValidationError(code, `Duplicate value ${key}`);
    }
    seen.add(key);
  }
}

function valueAtJsonPointer(document: Record<string, unknown>, pointer: string): unknown {
  let current: unknown = document;
  for (const encoded of pointer.slice(1).split("/")) {
    const token = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (current === null || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[token];
  }
  return current;
}

function assertDeclaredSetUniqueness(schemaId: SchemaId, document: Record<string, unknown>): void {
  const projectionId = domainProjectionBySchema[schemaId];
  if (projectionId === undefined) return;
  const definition = getProjectionDefinition(projectionId);
  for (const pointer of definition.set_like_array_pointers) {
    const value = valueAtJsonPointer(document, pointer);
    if (!Array.isArray(value)) continue;
    const seen = new Set<string>();
    for (const member of value) {
      const key = canonicalize(member);
      if (seen.has(key)) {
        throw new ContractValidationError("DUPLICATE_SET_MEMBER", `${pointer} contains duplicate canonical member ${key}`);
      }
      seen.add(key);
    }
  }
}

function sameMembers(left: readonly string[], right: readonly string[]): boolean {
  const normalizedLeft = [...left].sort();
  const normalizedRight = [...right].sort();
  return normalizedLeft.length === normalizedRight.length && normalizedLeft.every((value, index) => value === normalizedRight[index]);
}

/** Exact bounded routing identity: model identity is owner-selected routing data; the grammar is shared authority from definitions. */
function boundedRouteIdentifier(value: string): boolean {
  return isBoundedRoutingIdentity(value);
}

function assertRouteSemantics(routes: RouteMapDocument["routes"] | PlanApprovalDocument["bindings"]["logical_routes"]): void {
  assertUniqueBy(routes, (route) => route.logical_role, "DUPLICATE_LOGICAL_ROUTE");
  for (const route of routes) {
    for (const [field, value] of [["provider_id", route.provider_id], ["model_id", route.model_id]] as const) {
      if (value.replaceAll("-", "_").toUpperCase() === "LUNA_MEDIUM") {
        throw new ContractValidationError("FORBIDDEN_LUNA_MEDIUM", `${field} cannot select LUNA_MEDIUM`);
      }
    }
    if (route.effort === "xhigh" && route.logical_role !== "TERRA_EXECUTOR") {
      throw new ContractValidationError("XHIGH_TERRA_ONLY", `${route.logical_role} cannot use xhigh effort`);
    }
    if (route.logical_role === "LUNA_EXECUTOR" && route.effort !== "high") {
      throw new ContractValidationError("INVALID_LUNA_EFFORT", "LUNA_EXECUTOR must use high effort");
    }
    if (route.logical_role === "TERRA_EXECUTOR" &&
        (route.provider_id !== "openai-codex" || route.model_id !== "gpt-5.6-terra" || (route.effort !== "high" && route.effort !== "xhigh"))) {
      throw new ContractValidationError("INVALID_TERRA_ROUTE", "TERRA_EXECUTOR must use openai-codex / gpt-5.6-terra / high or xhigh");
    }
    if (route.logical_role === "CODING_EXECUTOR" &&
        (route.effort !== "high" || !boundedRouteIdentifier(route.provider_id) || !boundedRouteIdentifier(route.model_id))) {
      throw new ContractValidationError("INVALID_CODING_ROUTE", "CODING_EXECUTOR requires bounded provider/model identifiers and exactly high effort without escalation");
    }
    if (route.logical_role.startsWith("SOL_") && route.effort !== "max") {
      throw new ContractValidationError("INVALID_SOL_EFFORT", `${route.logical_role} must use max effort`);
    }
    if (route.logical_role === "SOL_CLOSEOUT") {
      if (route.tool_policy.mutation_tool !== "NONE" || route.tool_policy.command_gateway !== "VERIFICATION_ONLY") {
        throw new ContractValidationError("CLOSEOUT_NOT_VERIFICATION_ONLY", "SOL_CLOSEOUT cannot receive mutation tools");
      }
    }
  }
}

export function assertRouteMapSemantics(routeMap: RouteMapDocument): void {
  assertRouteSemantics(routeMap.routes);
  const actual = new Set(routeMap.routes.map((route) => route.logical_role));
  for (const required of LOGICAL_MODEL_ROLES) {
    if (!actual.has(required)) {
      throw new ContractValidationError("MISSING_LOGICAL_ROUTE", `Missing route ${required}`);
    }
  }
}

interface CriterionLike {
  readonly criterion_id: string;
  readonly owner_acceptance: boolean;
  readonly evidence_kind: string;
}

function assertAcceptanceSemantics(
  acceptanceCriteria: readonly CriterionLike[],
  ownerAcceptanceCriteria: readonly CriterionLike[],
): void {
  for (const criterion of acceptanceCriteria) {
    if (criterion.owner_acceptance || criterion.evidence_kind === "OWNER_ACCEPTANCE") {
      throw new ContractValidationError(
        "OWNER_ACCEPTANCE_NOT_DECLARED",
        `${criterion.criterion_id} must be placed in owner_acceptance_criteria`,
      );
    }
  }
  for (const criterion of ownerAcceptanceCriteria) {
    if (!criterion.owner_acceptance || criterion.evidence_kind !== "OWNER_ACCEPTANCE") {
      throw new ContractValidationError(
        "INVALID_OWNER_ACCEPTANCE_CRITERION",
        "Declared owner-acceptance criteria must use OWNER_ACCEPTANCE evidence",
      );
    }
  }
  assertUniqueBy(
    [...acceptanceCriteria, ...ownerAcceptanceCriteria],
    (criterion) => criterion.criterion_id,
    "DUPLICATE_ACCEPTANCE_CRITERION",
  );
}

function assertOwnerAcceptanceMode(mode: string, ownerAcceptanceCount: number): void {
  if (ownerAcceptanceCount > 0 && mode !== "AUTO" && mode !== "SINGLE_OWNER_SOL") {
    throw new ContractValidationError(
      "OWNER_ACCEPTANCE_MODE_MISMATCH",
      `${mode} has no declared-owner-acceptance state`,
    );
  }
}

function assertTaskScopesDoNotOverlap(tasks: readonly { task_id: string; editable_paths: readonly string[] }[]): void {
  for (const task of tasks) assertCanonicalPathList(`${task.task_id} editable`, task.editable_paths);
  for (let leftIndex = 0; leftIndex < tasks.length; leftIndex += 1) {
    const left = tasks[leftIndex];
    if (left === undefined) continue;
    for (let rightIndex = leftIndex + 1; rightIndex < tasks.length; rightIndex += 1) {
      const right = tasks[rightIndex];
      if (right === undefined) continue;
      for (const leftPath of left.editable_paths) {
        for (const rightPath of right.editable_paths) {
          if (pathsOverlap(leftPath, rightPath)) {
            throw new ContractValidationError(
              "AMBIGUOUS_WRITE_OWNERSHIP",
              `${left.task_id}:${leftPath} overlaps ${right.task_id}:${rightPath}`,
            );
          }
        }
      }
    }
  }
}

interface GraphTask {
  readonly task_id: string;
  readonly topological_rank: number;
  readonly dependencies: readonly string[];
  readonly editable_paths: readonly string[];
}

function assertGraphSemantics(tasks: readonly GraphTask[], edges: readonly { from: string; to: string }[], configuredMaxLeaves: number): void {
  if (tasks.length > configuredMaxLeaves) {
    throw new ContractValidationError(
      "TASK_GRAPH_ABOVE_LEAF_CAP",
      `${tasks.length} tasks exceeds configured cap ${configuredMaxLeaves}`,
    );
  }
  assertUniqueBy(tasks, (task) => task.task_id, "DUPLICATE_TASK_ID");
  assertUniqueBy(edges, (edge) => `${edge.from}\u0000${edge.to}`, "DUPLICATE_EDGE");
  const byId = new Map(tasks.map((task) => [task.task_id, task]));
  const edgeSet = new Set(edges.map((edge) => `${edge.from}\u0000${edge.to}`));

  for (const edge of edges) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    if (from === undefined || to === undefined) {
      throw new ContractValidationError("MISSING_DEPENDENCY", `Unknown edge ${edge.from} -> ${edge.to}`);
    }
    if (edge.from === edge.to) {
      throw new ContractValidationError("CYCLIC_DEPENDENCY", `Self edge ${edge.from}`);
    }
    if (from.topological_rank >= to.topological_rank) {
      throw new ContractValidationError("INVALID_TOPOLOGICAL_RANK", `${edge.from} must rank before ${edge.to}`);
    }
  }

  for (const task of tasks) {
    for (const dependency of task.dependencies) {
      if (!byId.has(dependency)) {
        throw new ContractValidationError("MISSING_DEPENDENCY", `${task.task_id} depends on unknown ${dependency}`);
      }
      if (!edgeSet.has(`${dependency}\u0000${task.task_id}`)) {
        throw new ContractValidationError("DEPENDENCY_EDGE_MISMATCH", `Missing edge ${dependency} -> ${task.task_id}`);
      }
    }
    for (const edge of edges.filter((candidate) => candidate.to === task.task_id)) {
      if (!task.dependencies.includes(edge.from)) {
        throw new ContractValidationError("DEPENDENCY_EDGE_MISMATCH", `Edge ${edge.from} -> ${task.task_id} is not declared`);
      }
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (taskId: string): void => {
    if (visiting.has(taskId)) {
      throw new ContractValidationError("CYCLIC_DEPENDENCY", `Cycle reaches ${taskId}`);
    }
    if (visited.has(taskId)) return;
    visiting.add(taskId);
    const task = byId.get(taskId);
    if (task === undefined) {
      throw new ContractValidationError("MISSING_DEPENDENCY", taskId);
    }
    for (const dependency of task.dependencies) visit(dependency);
    visiting.delete(taskId);
    visited.add(taskId);
  };
  for (const task of tasks) visit(task.task_id);

  assertTaskScopesDoNotOverlap(tasks);
}

export function assertTaskGraphSemantics(taskGraph: TaskGraphDocument, configuredMaxLeaves = taskGraph.configured_max_leaves): void {
  assertGraphSemantics(taskGraph.tasks, taskGraph.edges, Math.min(configuredMaxLeaves, taskGraph.configured_max_leaves));
}

export function assertTaskSemantics(task: TaskDocument): void {
  assertNoScopeOverlap(task.scope);
  assertAcceptanceSemantics(task.acceptance_criteria, task.owner_acceptance_criteria);
  if ((task.assigned_role === "LUNA_EXECUTOR" || task.assigned_role === "TERRA_EXECUTOR" || task.assigned_role === "CODING_EXECUTOR") && task.owner_acceptance_criteria.length > 0) {
    throw new ContractValidationError("EXECUTOR_OWNER_ACCEPTANCE_FORBIDDEN", "Executor leaf acceptance must be machine-checkable");
  }
}

export function assertBaselineSemantics(baseline: BaselineDocument): void {
  assertCanonicalPathList("baseline staged", baseline.staged_paths);
  assertCanonicalPathList("baseline unstaged", baseline.unstaged_paths);
  assertCanonicalPathList("baseline untracked", baseline.untracked_paths);
  for (const file of baseline.files) canonicalRepositoryPath(file.path, "baseline file path");
  assertUniqueBy(baseline.files, (file) => file.path, "DUPLICATE_BASELINE_PATH");
}

export function assertAuthorityLockSemantics(authorityLock: AuthorityLockDocument): void {
  for (const authority of authorityLock.authorities) canonicalRepositoryPath(authority.path, "authority path");
  assertUniqueBy(authorityLock.authorities, (authority) => authority.path, "DUPLICATE_AUTHORITY_PATH");
}

export function assertPlanApprovalSemantics(plan: PlanApprovalDocument): void {
  assertNoScopeOverlap(plan.bindings.scope);
  assertAcceptanceSemantics(plan.bindings.acceptance_criteria, plan.bindings.owner_acceptance_criteria);
  assertOwnerAcceptanceMode(plan.bindings.execution_mode, plan.bindings.owner_acceptance_criteria.length);
  assertRouteSemantics(plan.bindings.logical_routes);
  if (plan.bindings.logical_routes.some((route) => route.effort === "xhigh") && plan.bindings.execution_mode !== "STATIC_APPROVED_DAG") {
    throw new ContractValidationError("XHIGH_REQUIRES_STATIC_DAG", "xhigh effort is restricted to STATIC_APPROVED_DAG");
  }
  const taskCount = plan.bindings.dag.ordered_task_packet_identities.length;
  if (taskCount > plan.bindings.limits.max_leaves) {
    throw new ContractValidationError("TASK_GRAPH_ABOVE_LEAF_CAP", `${taskCount} tasks exceeds plan cap`);
  }
  if ((plan.bindings.execution_mode === "ROUTED_DAG" || plan.bindings.execution_mode === "STATIC_APPROVED_DAG") && taskCount < 2) {
    throw new ContractValidationError(plan.bindings.execution_mode === "ROUTED_DAG" ? "ROUTED_DAG_TOO_SMALL" : "DAG_TOO_SMALL", `${plan.bindings.execution_mode} requires at least two leaves`);
  }
  if (plan.bindings.execution_mode === "STATIC_APPROVED_DAG" &&
      (plan.bindings.logical_routes.length !== 1 || !['TERRA_EXECUTOR', 'CODING_EXECUTOR'].includes(plan.bindings.logical_routes[0]?.logical_role as string))) {
    throw new ContractValidationError("STATIC_DAG_ROUTE_RESTRICTED", "STATIC_APPROVED_DAG permits exactly one executor route: legacy TERRA_EXECUTOR or capability-oriented CODING_EXECUTOR");
  }
  const timeBudgets = plan.bindings.limits.static_time_budgets;
  if (timeBudgets !== undefined) {
    if (plan.bindings.execution_mode !== "STATIC_APPROVED_DAG") {
      throw new ContractValidationError("STATIC_TIME_BUDGETS_MODE_INVALID", "static time budgets are restricted to STATIC_APPROVED_DAG");
    }
    if (timeBudgets.worker_deadline_ms > timeBudgets.node_wall_ms || timeBudgets.node_wall_ms > timeBudgets.workflow_wall_ms ||
        plan.bindings.limits.max_wall_time_ms !== timeBudgets.workflow_wall_ms) {
      throw new ContractValidationError("STATIC_TIME_BUDGETS_INVALID", "static time budgets must bind worker <= node <= workflow and the workflow limit");
    }
  }
  if (plan.bindings.execution_mode !== "ROUTED_DAG" && plan.bindings.execution_mode !== "STATIC_APPROVED_DAG" && taskCount !== 1) {
    throw new ContractValidationError("ONE_TASK_REQUIRED", `${plan.bindings.execution_mode} requires exactly one task`);
  }
}

const commonPhases = new Set([
  "CREATED",
  "OBJECTIVE_FROZEN",
  "LOCK_ACQUIRED",
  "BASELINE_CAPTURED",
  "AWAITING_BASELINE_APPROVAL",
  "BASELINE_APPROVED",
  "FULL_PREFLIGHT_PASSED",
  "CONTRACT_VALIDATED",
  "ROUTE_SELECTED",
  "PASS",
  "BLOCKED",
]);
const directPhases = new Set([
  "DIRECT_CONTRACT_VALIDATED",
  "AWAITING_DIRECT_APPROVAL",
  "DIRECT_TASK_FROZEN",
  "DIRECT_FAST_PREFLIGHT",
  "DIRECT_ATTEMPT_RUNNING",
  "DIRECT_POSTFLIGHT",
  "DIRECT_VERIFYING",
  "DIRECT_RETRY_READY",
]);
const singleOwnerPhases = new Set([
  "SINGLE_OWNER_CONTRACT_VALIDATED",
  "AWAITING_SINGLE_OWNER_APPROVAL",
  "SINGLE_OWNER_TASK_FROZEN",
  "SINGLE_OWNER_FAST_PREFLIGHT",
  "SINGLE_OWNER_RUNNING",
  "SINGLE_OWNER_POSTFLIGHT",
  "SINGLE_OWNER_VERIFYING",
  "AWAITING_DECLARED_OWNER_ACCEPTANCE",
]);
const routedPhases = new Set([
  "PLAN_RUNNING",
  "PLAN_VALIDATED",
  "AWAITING_PLAN_APPROVAL",
  "DAG_FROZEN",
  "READY",
  "LEAF_FAST_PREFLIGHT",
  "LEAF_RUNNING",
  "LEAF_POSTFLIGHT",
  "LEAF_VERIFYING",
  "LEAF_RETRY_READY",
  "REPLAN_REQUIRED",
  "CLOSEOUT_RUNNING",
  "CLOSEOUT_VERIFYING",
]);

function phaseInvariant(state: WorkflowState, condition: boolean, detail: string): void {
  if (!condition) {
    throw new ContractValidationError("PHASE_INVARIANT_MISMATCH", `${state.execution_mode}:${state.phase}: ${detail}`);
  }
}

function allInvocationCountersAreZero(state: WorkflowState): boolean {
  const invocations = state.counters.worker_invocations;
  return (
    invocations.total === 0 &&
    invocations.sol_owner === 0 &&
    invocations.sol_planner === 0 &&
    invocations.sol_replan === 0 &&
    invocations.sol_closeout === 0 &&
    invocations.luna_executor === 0 &&
    invocations.terra_executor === 0
  );
}

function allGatesAreZero(state: WorkflowState): boolean {
  return (
    !state.gates.planner_completed &&
    !state.gates.owner_acceptance_completed &&
    !state.gates.closeout_completed &&
    !state.gates.closeout_verification_completed
  );
}

function assertNoModeWork(state: WorkflowState): void {
  phaseInvariant(state, !state.route_frozen, "route must not be frozen");
  phaseInvariant(state, state.tasks.length === 0 && state.active_task_id === null, "tasks must not be frozen");
  phaseInvariant(state, allInvocationCountersAreZero(state), "worker counters must be zero");
  phaseInvariant(
    state,
    state.counters.direct_attempts === 0 &&
      state.counters.single_owner_mutation_cycles === 0 &&
      state.counters.constrained_replans === 0 &&
      state.counters.leaves_completed === 0,
    "mode counters must be zero",
  );
  phaseInvariant(state, allGatesAreZero(state), "completion gates must be clear");
  phaseInvariant(state, !state.replan_in_progress, "replan cannot be active");
}

function assertPostBaseline(state: WorkflowState): void {
  phaseInvariant(state, state.baseline_approval_required !== null, "baseline disposition must be recorded");
}

function onlyRuntimeTask(state: WorkflowState): WorkflowState["tasks"][number] {
  const task = state.tasks[0];
  if (task === undefined || state.tasks.length !== 1) {
    throw new ContractValidationError("PHASE_INVARIANT_MISMATCH", `${state.execution_mode}:${state.phase}: exactly one runtime task is required`);
  }
  return task;
}

function assertTaskLifecycle(state: WorkflowState): void {
  for (const task of state.tasks) {
    phaseInvariant(state, !task.verification_completed || task.postflight_completed, `${task.task_id} verification requires postflight`);
    phaseInvariant(state, !task.retry_progress_admitted || task.attempts >= 1, `${task.task_id} retry progress requires a prior attempt`);
    if (task.status === "PENDING") {
      phaseInvariant(state, !task.postflight_completed && !task.verification_completed, `${task.task_id} pending lifecycle flags must be clear`);
    } else if (task.status === "RUNNING") {
      phaseInvariant(state, !task.verification_completed, `${task.task_id} cannot verify while running`);
    } else if (task.status === "PASS") {
      phaseInvariant(state, task.postflight_completed && task.verification_completed, `${task.task_id} PASS requires postflight and verification`);
    } else {
      phaseInvariant(state, !task.verification_completed, `${task.task_id} BLOCKED cannot be verified`);
    }
    if (state.execution_mode === "SINGLE_OWNER_SOL") {
      phaseInvariant(state, task.attempts === 0 && !task.retry_progress_admitted, `${task.task_id} owner task cannot contain Luna attempt evidence`);
    } else if (task.attempts === 2) {
      phaseInvariant(state, task.retry_progress_admitted, `${task.task_id} second attempt requires admitted progress`);
    }
  }
  phaseInvariant(
    state,
    !state.gates.closeout_verification_completed || state.gates.closeout_completed,
    "closeout verification requires closeout completion",
  );
  phaseInvariant(
    state,
    !state.gates.owner_acceptance_completed || (state.execution_mode === "SINGLE_OWNER_SOL" && state.owner_acceptance_required),
    "owner acceptance completion requires a declared single-owner gate",
  );
  phaseInvariant(
    state,
    !state.replan_in_progress || (state.execution_mode === "ROUTED_DAG" && state.phase === "REPLAN_REQUIRED"),
    "replan activity is valid only in REPLAN_REQUIRED",
  );
}

function assertDirectPhaseInvariants(state: WorkflowState): void {
  const invocations = state.counters.worker_invocations;
  phaseInvariant(state, allGatesAreZero(state), "direct mode cannot complete planner, owner, or closeout gates");
  assertPostBaseline(state);

  if (state.phase === "DIRECT_CONTRACT_VALIDATED" || state.phase === "AWAITING_DIRECT_APPROVAL") {
    assertNoModeWork(state);
    return;
  }

  const task = onlyRuntimeTask(state);
  const directCountMatches =
    invocations.total === task.attempts &&
    invocations.luna_executor === task.attempts &&
    state.counters.direct_attempts === task.attempts;
  phaseInvariant(state, directCountMatches, "direct invocation and task-attempt counters must match");

  switch (state.phase) {
    case "DIRECT_TASK_FROZEN":
      phaseInvariant(state, task.status === "PENDING" && task.attempts === 0 && state.active_task_id === null, "newly frozen task must be pending");
      return;
    case "DIRECT_FAST_PREFLIGHT": {
      const initial = task.status === "PENDING" && task.attempts === 0 && state.active_task_id === null && !task.retry_progress_admitted;
      const retry = task.status === "PENDING" && task.attempts === 1 && state.active_task_id === task.task_id && task.retry_progress_admitted;
      phaseInvariant(state, initial || retry, "fast preflight must describe an initial or progress-admitted retry attempt");
      return;
    }
    case "DIRECT_ATTEMPT_RUNNING":
    case "DIRECT_POSTFLIGHT":
    case "DIRECT_VERIFYING": {
      phaseInvariant(state, task.status === "RUNNING" && state.active_task_id === task.task_id, "attempt phase requires one active running task");
      phaseInvariant(state, task.attempts >= 1 && task.attempts <= 2, "attempt phase requires one or two attempts");
      phaseInvariant(state, task.retry_progress_admitted === (task.attempts === 2), "retry evidence must match the attempt number");
      const expectedPostflight = state.phase === "DIRECT_VERIFYING";
      phaseInvariant(state, task.postflight_completed === expectedPostflight && !task.verification_completed, "postflight/verification flags do not match phase");
      return;
    }
    case "DIRECT_RETRY_READY":
      phaseInvariant(
        state,
        task.status === "PENDING" && task.attempts === 1 && state.active_task_id === task.task_id && !task.retry_progress_admitted,
        "retry-ready requires one failed attempt awaiting progress",
      );
      return;
    case "PASS":
      phaseInvariant(state, task.status === "PASS" && state.active_task_id === null, "direct PASS requires one completed task");
      phaseInvariant(state, task.attempts >= 1 && task.attempts <= 2, "direct PASS requires one or two Luna attempts");
      phaseInvariant(state, task.retry_progress_admitted === (task.attempts === 2), "direct PASS retry evidence must match attempts");
      return;
    default:
      throw new ContractValidationError("PHASE_INVARIANT_MISMATCH", `Unhandled direct phase ${state.phase}`);
  }
}

function assertSingleOwnerPhaseInvariants(state: WorkflowState): void {
  const invocations = state.counters.worker_invocations;
  assertPostBaseline(state);
  phaseInvariant(
    state,
    !state.gates.planner_completed && !state.gates.closeout_completed && !state.gates.closeout_verification_completed,
    "single-owner mode cannot complete planner or closeout gates",
  );

  if (state.phase === "SINGLE_OWNER_CONTRACT_VALIDATED" || state.phase === "AWAITING_SINGLE_OWNER_APPROVAL") {
    assertNoModeWork(state);
    return;
  }

  const task = onlyRuntimeTask(state);
  switch (state.phase) {
    case "SINGLE_OWNER_TASK_FROZEN":
    case "SINGLE_OWNER_FAST_PREFLIGHT":
      phaseInvariant(state, invocations.total === 0 && invocations.sol_owner === 0, "owner invocation must not start before execution");
      phaseInvariant(state, state.counters.single_owner_mutation_cycles === 0, "mutation cycles must not start before execution");
      phaseInvariant(state, task.status === "PENDING" && state.active_task_id === null, "frozen owner task must be pending");
      phaseInvariant(state, !state.gates.owner_acceptance_completed, "owner acceptance cannot complete before verification");
      return;
    case "SINGLE_OWNER_RUNNING":
    case "SINGLE_OWNER_POSTFLIGHT":
    case "SINGLE_OWNER_VERIFYING": {
      phaseInvariant(state, invocations.total === 1 && invocations.sol_owner === 1, "exactly one owner invocation is required");
      phaseInvariant(state, task.status === "RUNNING" && state.active_task_id === task.task_id, "owner execution requires one active task");
      const needsCycles = state.phase !== "SINGLE_OWNER_RUNNING";
      phaseInvariant(
        state,
        state.counters.single_owner_mutation_cycles >= (needsCycles ? 1 : 0) && state.counters.single_owner_mutation_cycles <= 2,
        "mutation-cycle count does not match phase",
      );
      const expectedPostflight = state.phase === "SINGLE_OWNER_VERIFYING";
      phaseInvariant(state, task.postflight_completed === expectedPostflight && !task.verification_completed, "postflight/verification flags do not match phase");
      phaseInvariant(state, !state.gates.owner_acceptance_completed, "owner acceptance cannot precede verification");
      return;
    }
    case "AWAITING_DECLARED_OWNER_ACCEPTANCE":
      phaseInvariant(state, state.owner_acceptance_required, "owner acceptance must be declared");
      phaseInvariant(state, invocations.total === 1 && invocations.sol_owner === 1, "exactly one owner invocation is required");
      phaseInvariant(state, state.counters.single_owner_mutation_cycles >= 1 && state.counters.single_owner_mutation_cycles <= 2, "one or two mutation cycles are required");
      phaseInvariant(state, task.status === "PASS" && state.active_task_id === null, "verified owner task must be complete");
      phaseInvariant(state, !state.gates.owner_acceptance_completed, "owner gate is still awaiting acceptance");
      return;
    case "PASS":
      phaseInvariant(state, invocations.total === 1 && invocations.sol_owner === 1, "single-owner PASS requires exactly one owner invocation");
      phaseInvariant(state, state.counters.single_owner_mutation_cycles >= 1 && state.counters.single_owner_mutation_cycles <= 2, "single-owner PASS requires one or two mutation cycles");
      phaseInvariant(state, task.status === "PASS" && state.active_task_id === null, "single-owner PASS requires one completed task");
      phaseInvariant(
        state,
        state.gates.owner_acceptance_completed === state.owner_acceptance_required,
        "declared owner acceptance must complete exactly when required",
      );
      return;
    default:
      throw new ContractValidationError("PHASE_INVARIANT_MISMATCH", `Unhandled single-owner phase ${state.phase}`);
  }
}

function routedSettledTaskIsValid(task: WorkflowState["tasks"][number]): boolean {
  return task.status === "PASS"
    ? task.attempts >= 1 && task.attempts <= 2 && task.postflight_completed && task.verification_completed
    : task.status === "PENDING" && task.attempts === 0 && !task.postflight_completed && !task.verification_completed && !task.retry_progress_admitted;
}

function assertRoutedPlannerCounters(state: WorkflowState): void {
  const invocations = state.counters.worker_invocations;
  phaseInvariant(state, invocations.sol_planner === 1, "routed execution requires one planner invocation");
  phaseInvariant(state, state.gates.planner_completed, "planner completion must be recorded");
  phaseInvariant(state, !state.gates.owner_acceptance_completed, "routed execution cannot complete owner acceptance");
}

function assertStaticApprovedDagPhaseInvariants(state: WorkflowState): void {
  const invocations = state.counters.worker_invocations;
  assertPostBaseline(state);
  phaseInvariant(state, !state.gates.planner_completed && !state.gates.owner_acceptance_completed && !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "static DAG cannot invoke planner, owner acceptance, or closeout");
  phaseInvariant(state, state.tasks.length >= 2 && state.route_frozen, "static DAG requires a frozen multi-node DAG");
  phaseInvariant(state, invocations.sol_owner === 0 && invocations.sol_planner === 0 && invocations.sol_replan === 0 && invocations.sol_closeout === 0 && invocations.luna_executor === 0, "static DAG permits only Terra invocations");
  if (state.phase === "DAG_FROZEN" || state.phase === "READY") {
    phaseInvariant(state, state.active_task_id === null && state.tasks.every((task) => task.status === "PENDING" || (task.status === "PASS" && task.postflight_completed && task.verification_completed)), "static DAG settled nodes must be pending or verified");
    return;
  }
  if (["LEAF_FAST_PREFLIGHT", "LEAF_RUNNING", "LEAF_POSTFLIGHT", "LEAF_VERIFYING", "LEAF_RETRY_READY"].includes(state.phase)) {
    const active = state.tasks.find((task) => task.task_id === state.active_task_id);
    phaseInvariant(state, active !== undefined, "static leaf phase requires an active task");
    phaseInvariant(state, state.tasks.filter((task) => task.task_id !== state.active_task_id).every((task) => task.status === "PENDING" || (task.status === "PASS" && task.postflight_completed && task.verification_completed)), "static DAG retains one active writer");
    if (active === undefined) return;
    if (state.phase === "LEAF_FAST_PREFLIGHT") phaseInvariant(state, (active.attempts === 0 && active.status === "PENDING" && !active.retry_progress_admitted) || (active.attempts === 1 && active.status === "PENDING" && active.retry_progress_admitted), "static leaf preflight must be initial or its one admitted repair");
    else if (["LEAF_RUNNING", "LEAF_POSTFLIGHT", "LEAF_VERIFYING"].includes(state.phase)) phaseInvariant(state, active.status === "RUNNING" && active.attempts >= 1 && active.attempts <= 2 && active.retry_progress_admitted === (active.attempts === 2) && active.postflight_completed === (state.phase === "LEAF_VERIFYING"), "static leaf attempt lifecycle is invalid");
    else phaseInvariant(state, active.status === "PENDING" && active.attempts === 1 && !active.retry_progress_admitted, "static repair must await admission");
    return;
  }
  if (state.phase === "STATIC_DAG_VERIFYING" || state.phase === "PASS") {
    phaseInvariant(state, state.active_task_id === null && state.tasks.every((task) => task.status === "PASS" && task.attempts >= 1 && task.attempts <= 2), "static DAG completion requires every node to verify");
    return;
  }
  throw new ContractValidationError("PHASE_INVARIANT_MISMATCH", `Unhandled static DAG phase ${state.phase}`);
}

function assertRoutedPhaseInvariants(state: WorkflowState): void {
  const invocations = state.counters.worker_invocations;
  assertPostBaseline(state);

  if (state.phase === "PLAN_RUNNING") {
    phaseInvariant(state, !state.route_frozen && state.tasks.length === 0 && state.active_task_id === null, "plan must run before DAG freeze");
    phaseInvariant(state, invocations.total === 1 && invocations.sol_planner === 1, "plan running requires one planner invocation");
    phaseInvariant(state, !state.gates.planner_completed && !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "planner/closeout gates do not match PLAN_RUNNING");
    phaseInvariant(state, state.counters.constrained_replans === 0 && !state.replan_in_progress, "replans cannot precede plan approval");
    return;
  }
  if (state.phase === "PLAN_VALIDATED" || state.phase === "AWAITING_PLAN_APPROVAL") {
    phaseInvariant(state, !state.route_frozen && state.tasks.length === 0 && state.active_task_id === null, "DAG must not freeze before approval");
    phaseInvariant(state, invocations.total === 1 && invocations.sol_planner === 1, "validated plan requires one planner invocation");
    phaseInvariant(state, state.gates.planner_completed && !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "planner/closeout gates do not match plan validation");
    phaseInvariant(state, state.counters.constrained_replans === 0 && !state.replan_in_progress, "replans cannot precede plan approval");
    return;
  }

  assertRoutedPlannerCounters(state);
  phaseInvariant(state, state.tasks.length >= 2, "routed state requires at least two frozen leaves");
  phaseInvariant(state, state.route_frozen, "routed task phases require a frozen DAG");

  if (state.phase === "DAG_FROZEN") {
    phaseInvariant(state, state.active_task_id === null && state.tasks.every(routedSettledTaskIsValid), "newly frozen DAG must contain untouched pending tasks");
    phaseInvariant(state, state.tasks.every((task) => task.status === "PENDING"), "no leaf may complete before DAG activation");
    phaseInvariant(state, invocations.sol_closeout === 0 && !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "closeout cannot precede leaves");
    return;
  }
  if (state.phase === "READY") {
    phaseInvariant(state, state.active_task_id === null && state.tasks.every(routedSettledTaskIsValid), "READY requires only untouched pending or verified PASS leaves");
    phaseInvariant(state, invocations.sol_closeout === 0 && !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "closeout has not started in READY");
    return;
  }

  if (["LEAF_FAST_PREFLIGHT", "LEAF_RUNNING", "LEAF_POSTFLIGHT", "LEAF_VERIFYING", "LEAF_RETRY_READY", "REPLAN_REQUIRED"].includes(state.phase)) {
    const active = state.tasks.find((task) => task.task_id === state.active_task_id);
    phaseInvariant(state, active !== undefined, "leaf phase requires an active task");
    phaseInvariant(state, state.tasks.filter((task) => task.task_id !== state.active_task_id).every(routedSettledTaskIsValid), "non-active leaves must be untouched or verified");
    phaseInvariant(state, invocations.sol_closeout === 0 && !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "closeout cannot overlap leaf execution");
    if (active === undefined) return;

    switch (state.phase) {
      case "LEAF_FAST_PREFLIGHT": {
        const initial = active.status === "PENDING" && active.attempts === 0 && !active.retry_progress_admitted;
        const retry = active.status === "PENDING" && active.attempts === 1 && active.retry_progress_admitted;
        phaseInvariant(state, initial || retry, "leaf preflight must describe an initial or progress-admitted retry");
        break;
      }
      case "LEAF_RUNNING":
      case "LEAF_POSTFLIGHT":
      case "LEAF_VERIFYING":
        phaseInvariant(state, active.status === "RUNNING" && active.attempts >= 1 && active.attempts <= 2, "leaf attempt requires an active running task");
        phaseInvariant(state, active.retry_progress_admitted === (active.attempts === 2), "leaf retry evidence must match attempt number");
        phaseInvariant(state, active.postflight_completed === (state.phase === "LEAF_VERIFYING") && !active.verification_completed, "leaf postflight/verification flags do not match phase");
        break;
      case "LEAF_RETRY_READY":
        phaseInvariant(state, active.status === "PENDING" && active.attempts === 1 && !active.retry_progress_admitted, "leaf retry must await admitted progress");
        phaseInvariant(state, !state.replan_in_progress, "replan cannot remain active after completion");
        break;
      case "REPLAN_REQUIRED":
        phaseInvariant(state, active.status === "PENDING" && active.attempts === 1 && !active.retry_progress_admitted, "replan requires one failed leaf attempt");
        break;
      default:
        break;
    }
    return;
  }

  const everyLeafPassed = state.tasks.every((task) => task.status === "PASS" && task.attempts >= 1 && task.attempts <= 2);
  if (state.phase === "CLOSEOUT_RUNNING") {
    phaseInvariant(state, everyLeafPassed && state.active_task_id === null, "closeout requires every leaf to PASS");
    phaseInvariant(state, invocations.sol_closeout === 1, "closeout running requires one closeout invocation");
    phaseInvariant(state, !state.gates.closeout_completed && !state.gates.closeout_verification_completed, "closeout completion must follow execution");
    return;
  }
  if (state.phase === "CLOSEOUT_VERIFYING") {
    phaseInvariant(state, everyLeafPassed && state.active_task_id === null, "closeout verification requires every leaf to PASS");
    phaseInvariant(state, invocations.sol_closeout === 1, "closeout verification requires one closeout invocation");
    phaseInvariant(state, state.gates.closeout_completed && !state.gates.closeout_verification_completed, "closeout must complete before verification");
    return;
  }
  if (state.phase === "PASS") {
    phaseInvariant(state, everyLeafPassed && state.active_task_id === null, "routed PASS requires every leaf to PASS");
    phaseInvariant(state, invocations.sol_closeout === 1, "routed PASS requires one closeout invocation");
    phaseInvariant(state, state.gates.closeout_completed && state.gates.closeout_verification_completed, "routed PASS requires completed closeout verification");
    return;
  }
  throw new ContractValidationError("PHASE_INVARIANT_MISMATCH", `Unhandled routed phase ${state.phase}`);
}

function assertPhaseInvariants(state: WorkflowState): void {
  assertTaskLifecycle(state);
  if (state.phase === "BLOCKED") return;

  if (["CREATED", "OBJECTIVE_FROZEN", "LOCK_ACQUIRED", "BASELINE_CAPTURED", "AWAITING_BASELINE_APPROVAL", "BASELINE_APPROVED", "FULL_PREFLIGHT_PASSED", "CONTRACT_VALIDATED", "ROUTE_SELECTED"].includes(state.phase)) {
    assertNoModeWork(state);
    if (["CREATED", "OBJECTIVE_FROZEN", "LOCK_ACQUIRED"].includes(state.phase)) {
      phaseInvariant(state, state.baseline_approval_required === null, "baseline disposition must not be set yet");
    } else if (state.phase === "AWAITING_BASELINE_APPROVAL") {
      phaseInvariant(state, state.baseline_approval_required === true, "dirty baseline approval must be required");
    } else {
      phaseInvariant(state, state.baseline_approval_required !== null, "baseline disposition must be recorded");
    }
    return;
  }

  if (state.execution_mode === "DIRECT_LUNA_HIGH") {
    assertDirectPhaseInvariants(state);
  } else if (state.execution_mode === "SINGLE_OWNER_SOL") {
    assertSingleOwnerPhaseInvariants(state);
  } else if (state.execution_mode === "STATIC_APPROVED_DAG") {
    assertStaticApprovedDagPhaseInvariants(state);
  } else {
    assertRoutedPhaseInvariants(state);
  }
}

export function assertWorkflowStateSemantics(state: WorkflowState): void {
  const modePhases =
    state.execution_mode === "DIRECT_LUNA_HIGH"
      ? directPhases
      : state.execution_mode === "SINGLE_OWNER_SOL"
        ? singleOwnerPhases
        : state.execution_mode === "STATIC_APPROVED_DAG"
          ? new Set([...routedPhases, "STATIC_DAG_VERIFYING"])
          : routedPhases;
  if (!commonPhases.has(state.phase) && !modePhases.has(state.phase)) {
    throw new ContractValidationError("CROSS_MODE_STATE", `${state.phase} is invalid for ${state.execution_mode}`);
  }

  const terminal = state.phase === "PASS" || state.phase === "BLOCKED";
  if (
    terminal !== (state.terminal_reason !== null) ||
    (terminal && state.active_task_id !== null) ||
    (state.phase === "PASS" && (
      state.terminal_reason !== "PASS" ||
      !state.route_frozen ||
      state.tasks.length === 0 ||
      state.tasks.some((task) => task.status !== "PASS")
    ))
  ) {
    throw new ContractValidationError("INVALID_TERMINAL_STATE", "Terminal reason, active task, freeze, and task outcomes must match terminal semantics");
  }
  if (state.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE" && !state.owner_acceptance_required) {
    throw new ContractValidationError("UNDECLARED_OWNER_ACCEPTANCE", "Owner acceptance was not frozen as required");
  }
  if (state.owner_acceptance_required && state.execution_mode !== "SINGLE_OWNER_SOL") {
    throw new ContractValidationError("OWNER_ACCEPTANCE_MODE_MISMATCH", `${state.execution_mode} has no owner-acceptance state`);
  }

  const frozenPhases =
    state.execution_mode === "DIRECT_LUNA_HIGH"
      ? new Set(["DIRECT_TASK_FROZEN", "DIRECT_FAST_PREFLIGHT", "DIRECT_ATTEMPT_RUNNING", "DIRECT_POSTFLIGHT", "DIRECT_VERIFYING", "DIRECT_RETRY_READY"])
      : state.execution_mode === "SINGLE_OWNER_SOL"
        ? new Set(["SINGLE_OWNER_TASK_FROZEN", "SINGLE_OWNER_FAST_PREFLIGHT", "SINGLE_OWNER_RUNNING", "SINGLE_OWNER_POSTFLIGHT", "SINGLE_OWNER_VERIFYING", "AWAITING_DECLARED_OWNER_ACCEPTANCE"])
        : state.execution_mode === "STATIC_APPROVED_DAG"
          ? new Set(["DAG_FROZEN", "READY", "LEAF_FAST_PREFLIGHT", "LEAF_RUNNING", "LEAF_POSTFLIGHT", "LEAF_VERIFYING", "LEAF_RETRY_READY", "STATIC_DAG_VERIFYING"])
          : new Set(["DAG_FROZEN", "READY", "LEAF_FAST_PREFLIGHT", "LEAF_RUNNING", "LEAF_POSTFLIGHT", "LEAF_VERIFYING", "LEAF_RETRY_READY", "REPLAN_REQUIRED", "CLOSEOUT_RUNNING", "CLOSEOUT_VERIFYING"]);
  if (!terminal && state.route_frozen !== frozenPhases.has(state.phase)) {
    throw new ContractValidationError("ROUTE_FREEZE_MISMATCH", "route_frozen does not match the workflow phase");
  }

  const invocations = state.counters.worker_invocations;
  if (
    invocations.total !==
    invocations.sol_owner + invocations.sol_planner + invocations.sol_replan + invocations.sol_closeout + invocations.luna_executor + invocations.terra_executor
  ) {
    throw new ContractValidationError("INVOCATION_COUNTER_MISMATCH", "Worker invocation dimensions do not sum to total");
  }

  if (state.execution_mode === "DIRECT_LUNA_HIGH") {
    if (
      invocations.sol_owner !== 0 ||
      invocations.sol_planner !== 0 ||
      invocations.sol_replan !== 0 ||
      invocations.sol_closeout !== 0 ||
      invocations.terra_executor !== 0 ||
      state.counters.single_owner_mutation_cycles !== 0 ||
      state.counters.constrained_replans !== 0 ||
      invocations.luna_executor !== state.counters.direct_attempts
    ) {
      throw new ContractValidationError("CROSS_MODE_COUNTER", "Direct mode contains non-direct counters");
    }
  } else if (state.execution_mode === "SINGLE_OWNER_SOL") {
    if (
      invocations.sol_planner !== 0 ||
      invocations.sol_replan !== 0 ||
      invocations.sol_closeout !== 0 ||
      invocations.luna_executor !== 0 ||
      invocations.terra_executor !== 0 ||
      state.counters.direct_attempts !== 0 ||
      state.counters.constrained_replans !== 0 ||
      (state.counters.single_owner_mutation_cycles > 0 && invocations.sol_owner !== 1)
    ) {
      throw new ContractValidationError("CROSS_MODE_COUNTER", "Single-owner mode contains non-owner counters");
    }
  } else if (state.execution_mode === "STATIC_APPROVED_DAG") {
    if (invocations.sol_owner !== 0 || invocations.sol_planner !== 0 || invocations.sol_replan !== 0 || invocations.sol_closeout !== 0 || invocations.luna_executor !== 0 || state.counters.direct_attempts !== 0 || state.counters.single_owner_mutation_cycles !== 0 || state.counters.constrained_replans !== 0) {
      throw new ContractValidationError("CROSS_MODE_COUNTER", "Static DAG contains non-Terra counters");
    }
  } else if (
    invocations.sol_owner !== 0 || invocations.terra_executor !== 0 ||
    state.counters.direct_attempts !== 0 ||
    state.counters.single_owner_mutation_cycles !== 0 ||
    state.counters.constrained_replans !== invocations.sol_replan
  ) {
    throw new ContractValidationError("CROSS_MODE_COUNTER", "Routed mode contains non-routed counters");
  }

  assertUniqueBy(state.tasks, (task) => task.task_id, "DUPLICATE_TASK_STATUS");
  const running = state.tasks.filter((task) => task.status === "RUNNING");
  if (running.length > 1) {
    throw new ContractValidationError("AMBIGUOUS_WRITE_OWNERSHIP", "More than one task is RUNNING");
  }
  const active = state.active_task_id === null ? undefined : state.tasks.find((task) => task.task_id === state.active_task_id);
  if ((running.length === 1 && active?.task_id !== running[0]?.task_id) || (state.active_task_id !== null && active === undefined)) {
    throw new ContractValidationError("ACTIVE_TASK_MISMATCH", "active_task_id must identify the one running task when present");
  }
  if (active?.status === "PASS" || active?.status === "BLOCKED") {
    throw new ContractValidationError("ACTIVE_TASK_MISMATCH", "A terminal task cannot remain active");
  }

  const taskAttemptTotal = state.tasks.reduce((total, task) => total + task.attempts, 0);
  if (
    (state.execution_mode === "DIRECT_LUNA_HIGH" && state.tasks.length > 0 && taskAttemptTotal !== state.counters.direct_attempts) ||
    (state.execution_mode === "SINGLE_OWNER_SOL" && taskAttemptTotal !== 0) ||
    (state.execution_mode === "ROUTED_DAG" && taskAttemptTotal !== invocations.luna_executor) ||
    (state.execution_mode === "STATIC_APPROVED_DAG" && taskAttemptTotal !== invocations.terra_executor)
  ) {
    throw new ContractValidationError("ATTEMPT_COUNTER_MISMATCH", "Task attempts do not match mode counters");
  }
  if (state.counters.leaves_completed !== state.tasks.filter((task) => task.status === "PASS").length) {
    throw new ContractValidationError("LEAF_COUNTER_MISMATCH", "leaves_completed does not equal PASS task count");
  }
  assertPhaseInvariants(state);
}

export function assertReducerPolicySemantics(policy: ReducerPolicy): void {
  if (!CONCRETE_EXECUTION_MODES.includes(policy.execution_mode)) {
    throw new ContractValidationError("INVALID_EXECUTION_MODE", policy.execution_mode);
  }
  if (policy.owner_acceptance_required && policy.execution_mode !== "SINGLE_OWNER_SOL") {
    throw new ContractValidationError("OWNER_ACCEPTANCE_MODE_MISMATCH", `${policy.execution_mode} has no owner-acceptance state`);
  }
  assertTaskScopesDoNotOverlap(policy.tasks);
  if (policy.execution_mode === "ROUTED_DAG" || policy.execution_mode === "STATIC_APPROVED_DAG") {
    if (policy.tasks.length < 2) {
      throw new ContractValidationError(policy.execution_mode === "ROUTED_DAG" ? "ROUTED_DAG_TOO_SMALL" : "DAG_TOO_SMALL", `${policy.execution_mode} requires at least two leaves`);
    }
    if (policy.execution_mode === "STATIC_APPROVED_DAG" && (policy.owner_acceptance_required || policy.limits.max_replans !== 0)) {
      throw new ContractValidationError("STATIC_DAG_TOPOLOGY_INVALID", "STATIC_APPROVED_DAG cannot require owner acceptance or replanning");
    }
    const edges = policy.tasks.flatMap((task) => task.dependencies.map((dependency) => ({ from: dependency, to: task.task_id })));
    assertGraphSemantics(policy.tasks, edges, policy.limits.max_leaves);
    if (policy.frozen_bindings.plan_approval_sha256 === null || policy.frozen_bindings.task_graph_sha256 === null) {
      throw new ContractValidationError("MISSING_PLAN_IDENTITY", "ROUTED_DAG requires frozen plan and graph identities");
    }
  } else {
    if (policy.tasks.length !== 1) {
      throw new ContractValidationError("ONE_TASK_REQUIRED", `${policy.execution_mode} requires exactly one task`);
    }
    if (policy.frozen_bindings.task_graph_sha256 !== null) {
      throw new ContractValidationError("UNEXPECTED_TASK_GRAPH", `${policy.execution_mode} has no DAG`);
    }
  }
}

export function assertStatePolicyConsistency(state: WorkflowState, policy: ReducerPolicy): void {
  if (state.run_id !== policy.run_id || state.execution_mode !== policy.execution_mode) {
    throw new ContractValidationError("POLICY_STATE_MISMATCH", "run_id or execution mode differs");
  }
  if (state.frozen_policy_content_sha256 !== policy.content_sha256) {
    throw new ContractValidationError("FROZEN_POLICY_IDENTITY_MISMATCH", "State is bound to a different complete reducer policy");
  }
  if (state.owner_acceptance_required !== policy.owner_acceptance_required) {
    throw new ContractValidationError("POLICY_STATE_MISMATCH", "owner acceptance flag differs");
  }
  for (const identity of ["plan_approval_sha256", "task_graph_sha256", "scope_sha256", "acceptance_sha256", "budget_sha256"] as const) {
    if (state.identities[identity] !== policy.frozen_bindings[identity]) {
      throw new ContractValidationError("FROZEN_IDENTITY_MISMATCH", identity);
    }
  }
  if (state.counters.worker_invocations.total > policy.limits.max_worker_invocations) {
    throw new ContractValidationError("INVOCATION_CAP_EXCEEDED", "State exceeds frozen invocation cap");
  }
  if (state.counters.direct_attempts > policy.limits.max_direct_attempts) {
    throw new ContractValidationError("ATTEMPT_CAP_EXCEEDED", "State exceeds direct attempt cap");
  }
  if (state.counters.single_owner_mutation_cycles > policy.limits.max_single_owner_mutation_cycles) {
    throw new ContractValidationError("MUTATION_CYCLE_CAP_EXCEEDED", "State exceeds mutation-cycle cap");
  }
  if (state.counters.constrained_replans > policy.limits.max_replans) {
    throw new ContractValidationError("REPLAN_CAP_EXCEEDED", "State exceeds replan cap");
  }

  if (state.route_frozen) {
    if (!sameMembers(state.tasks.map((task) => task.task_id), policy.tasks.map((task) => task.task_id))) {
      throw new ContractValidationError("FROZEN_TASK_SET_MISMATCH", "State task IDs differ from the frozen policy");
    }
  } else if (state.tasks.length !== 0) {
    throw new ContractValidationError("TASKS_FROZEN_TOO_EARLY", "Tasks cannot exist before route/task freeze");
  }
  for (const task of state.tasks) {
    const attemptCap = state.execution_mode === "DIRECT_LUNA_HIGH"
      ? policy.limits.max_direct_attempts
      : state.execution_mode === "ROUTED_DAG" || state.execution_mode === "STATIC_APPROVED_DAG"
        ? policy.limits.max_attempts_per_leaf
        : 0;
    if (task.attempts > attemptCap) {
      throw new ContractValidationError("ATTEMPT_CAP_EXCEEDED", `${task.task_id} exceeds its frozen attempt cap`);
    }
  }
}

const domainProjectionBySchema: Partial<Record<SchemaId, DomainProjectionId>> = {
  pi_gacw_objective_v0: "objective-freeze-v1",
  pi_gacw_route_map_v0: "route-map-v1",
  pi_gacw_route_map_approval_v0: "route-map-approval-v1",
  pi_gacw_baseline_v0: "baseline-snapshot-v1",
  pi_gacw_baseline_approval_v0: "baseline-approval-v1",
  pi_gacw_authority_lock_v0: "authority-lock-v1",
  pi_gacw_contract_v0: "contract-freeze-v1",
  pi_gacw_routing_v0: "routing-freeze-v1",
  pi_gacw_budget_v0: "budget-freeze-v1",
  pi_gacw_task_v0: "task-packet-v1",
  pi_gacw_task_graph_v0: "task-graph-freeze-v1",
  pi_gacw_plan_approval_v0: "plan-approval-v1",
  pi_gacw_transition_commit_v0: "transition-commit-v1",
  pi_gacw_final_report_v0: "final-report-v1",
};

export interface SemanticValidationOptions {
  readonly configuredMaxLeaves?: number;
}

function assertPersistenceDocumentSemantics(schemaId: SchemaId, value: unknown): void {
  if (schemaId === "pi_gacw_mutation_receipt_v0") {
    const receipt = recordOf(value); const outcome = receipt["helper_outcome"]; const failure = receipt["failure_code"];
    const successor = receipt["successor_state_token_content_sha256"]; const postflight = receipt["postflight_content_sha256"];
    if (outcome === "APPLIED") {
      if (failure !== null || successor === null || postflight === null || receipt["atomic_rename"] !== true || receipt["directory_fsync"] !== true || receipt["rollback_outcome"] === "UNKNOWN") {
        throw new ContractValidationError("MUTATION_RECEIPT_INCONSISTENT", "Applied mutation receipt lacks complete successful authority");
      }
    } else if (typeof failure !== "string" || successor !== null || postflight !== null) {
      throw new ContractValidationError("MUTATION_RECEIPT_INCONSISTENT", "Blocked mutation receipt lacks exact failure authority");
    }
    if (outcome === "BLOCKED" && (receipt["file_fsync"] !== false || receipt["atomic_rename"] !== false || receipt["directory_fsync"] !== false || receipt["rollback_outcome"] !== "NOT_REQUIRED")) {
      throw new ContractValidationError("MUTATION_RECEIPT_INCONSISTENT", "Pre-write blocked receipt claims mutation progress");
    }
    if (outcome === "UNCERTAIN" && receipt["rollback_outcome"] !== "UNKNOWN") {
      throw new ContractValidationError("MUTATION_RECEIPT_INCONSISTENT", "Uncertain mutation receipt must retain unknown rollback state");
    }
    return;
  }
  if (schemaId === "pi_gacw_command_result_v0") {
    const result = recordOf(value); const passed = result["outcome"] === "PASS";
    if (passed !== (result["failure_code"] === null) || (passed && (result["state_token_after"] === null || result["postflight_content_sha256"] === null))) {
      throw new ContractValidationError("COMMAND_RESULT_INCONSISTENT", "Command result outcome, failure, and postflight authority differ");
    }
    return;
  }
  if (schemaId === "pi_gacw_evidence_manifest_v0") {
    const manifest = value as EvidenceManifestDocument;
    assertUniqueBy(manifest.entries, (entry) => entry.evidence_sha256, "DUPLICATE_EVIDENCE_IDENTITY");
    assertUniqueBy(manifest.entries, (entry) => entry.metadata_content_sha256, "DUPLICATE_METADATA_IDENTITY");
    return;
  }
  if (schemaId === "pi_gacw_persisted_state_pointer_v0") {
    const pointer = value as PersistedStatePointerDocument;
    if ((pointer.revision === 0) !== (pointer.previous_state_pointer_content_sha256 === null)) {
      throw new ContractValidationError(
        "STATE_POINTER_REVISION_MISMATCH",
        "Only the genesis pointer may have a null previous pointer identity",
      );
    }
    return;
  }
  if (schemaId === "pi_gacw_state_transition_commit_v0") {
    const commit = value as StateTransitionCommitDocument;
    const previousReferences = [
      commit.previous_state_pointer_content_sha256,
      commit.previous_workflow_state_content_sha256,
      commit.previous_transition_commit_content_sha256,
      commit.transition_event_content_sha256,
    ];
    if (commit.commit_kind === "GENESIS") {
      if (
        commit.previous_revision !== null ||
        commit.new_revision !== 0 ||
        previousReferences.some((identity) => identity !== null) ||
        commit.process_assessment_content_sha256 !== null
      ) {
        throw new ContractValidationError("INVALID_GENESIS_COMMIT", "Genesis must start revision zero without previous or event references");
      }
      return;
    }
    if (
      commit.previous_revision === null ||
      commit.new_revision !== commit.previous_revision + 1 ||
      previousReferences.some((identity) => identity === null)
    ) {
      throw new ContractValidationError("INVALID_TRANSITION_REVISION", "A transition must increment one revision and bind all previous/event references");
    }
    if ((commit.commit_kind === "PROCESS_CRASH") !== (commit.process_assessment_content_sha256 !== null)) {
      throw new ContractValidationError(
        "PROCESS_ASSESSMENT_MISMATCH",
        "Exactly process-crash commits must bind a process-interruption assessment",
      );
    }
  }
}

function assertM5PolicyDocumentSemantics(policy: M5ControlPolicyDocument): void {
  if (!policy.route_map_approved) throw new ContractValidationError("UNAPPROVED_ROUTE_MAP", "M5 policy requires an owner-approved route map");
  assertUniqueBy(policy.limits, (entry) => entry.dimension, "DUPLICATE_M5_BUDGET_DIMENSION");
  if (policy.limits.length !== 8) throw new ContractValidationError("MISSING_M5_BUDGET_DIMENSION", "All eight M5 budget dimensions are required");
  for (const entry of policy.limits) {
    if (entry.soft_limit !== null && entry.hard_limit !== null && entry.soft_limit > entry.hard_limit) {
      throw new ContractValidationError("CONTRADICTORY_M5_LIMIT", `${entry.dimension} soft limit exceeds hard limit`);
    }
    if (entry.enforcement_class === "UNAVAILABLE" && (entry.soft_limit !== null || entry.hard_limit !== null)) {
      throw new ContractValidationError("UNAVAILABLE_M5_LIMIT", `${entry.dimension} unavailable authority cannot claim limits`);
    }
    if (entry.dimension === "PROVIDER_REQUEST" && entry.enforcement_class === "HARD_ENFORCEABLE") {
      throw new ContractValidationError("HARD_PROVIDER_REQUEST_FORBIDDEN", "V0 has no hard provider-request admission seam");
    }
  }
  assertUniqueBy(policy.obligations, (entry) => `${entry.direction}\u0000${entry.declaration}`, "DUPLICATE_M5_OBLIGATION");
  assertUniqueBy(policy.obligations, (entry) => entry.descriptor_sha256, "DUPLICATE_M5_OBLIGATION_IDENTITY");
  for (const obligation of policy.obligations) {
    const needsLiteral = obligation.grammar === "LITERAL";
    const needsPrefix = obligation.grammar === "PREFIXED_LITERAL";
    if ((obligation.literal !== null) !== (needsLiteral || needsPrefix) || (obligation.prefix !== null) !== needsPrefix) {
      throw new ContractValidationError("INVALID_M5_OBLIGATION_GRAMMAR", `${obligation.declaration} grammar parameters are inconsistent`);
    }
  }
  assertUniqueBy(policy.role_reservation_envelopes, (entry) => `${entry.logical_role}\u0000${entry.purpose}`, "DUPLICATE_M5_RESERVATION_ENVELOPE");
  for (const envelope of policy.role_reservation_envelopes) {
    if (envelope.amounts.length === 0 || envelope.amounts.some((entry) => entry.amount <= 0)) throw new ContractValidationError("INVALID_M5_RESERVATION_ENVELOPE", "A reservation envelope must reserve a positive bounded amount");
    assertUniqueBy(envelope.amounts, (entry) => entry.dimension, "DUPLICATE_M5_RESERVATION_DIMENSION");
  }
  const facts = policy.route_facts;
  if (facts.coherent_single_task && facts.task_count !== 1) throw new ContractValidationError("CONTRADICTORY_M5_ROUTE_FACTS", "A coherent single task requires task_count=1");
  if (facts.leaf_count > facts.task_count || facts.unique_write_ownership === facts.ownership_ambiguous) {
    throw new ContractValidationError("CONTRADICTORY_M5_ROUTE_FACTS", "Leaf/task or ownership facts contradict");
  }
}

function assertM5UsageDocumentSemantics(usage: M5UsageEvidenceDocument): void {
  assertUniqueBy(usage.measurements, (entry) => entry.dimension, "DUPLICATE_M5_USAGE_DIMENSION");
  if (!usage.measurements.some((entry) => entry.dimension === usage.operation_kind)) throw new ContractValidationError("M5_OPERATION_DIMENSION_MISMATCH", "Operation evidence must include its operation dimension");
  for (const measurement of usage.measurements) {
    const unavailable = measurement.basis === "UNAVAILABLE";
    if (unavailable !== (measurement.amount === null) || unavailable !== (measurement.enforcement_class === "UNAVAILABLE")) {
      throw new ContractValidationError("M5_USAGE_NULL_MISMATCH", `${measurement.dimension} null, basis and enforcement authority differ`);
    }
    if (measurement.basis === "ESTIMATED" && measurement.enforcement_class !== "ESTIMATED_ONLY") {
      throw new ContractValidationError("M5_ESTIMATE_CLASS_MISMATCH", "Estimated usage must remain ESTIMATED_ONLY");
    }
  }
  const wallMeasurement = usage.measurements.find((entry) => entry.dimension === "WALL_TIME_MS");
  if ((usage.duration_ms === null) !== !(wallMeasurement !== undefined && wallMeasurement.amount !== null) ||
      (usage.duration_ms !== null && wallMeasurement?.amount !== usage.duration_ms)) {
    throw new ContractValidationError("M5_DURATION_MISMATCH", "Duration evidence must match the wall-time measurement");
  }
  if ((usage.disposition === "NOT_STARTED" || usage.disposition === "BLOCKED_BEFORE_START") && usage.measurements.some((entry) => entry.amount !== null && entry.amount > 0)) {
    throw new ContractValidationError("M5_PRESTART_USAGE", "A pre-start operation cannot claim positive usage");
  }
  if (usage.disposition === "OUTCOME_UNCERTAIN" && usage.reservation_decision_content_sha256 === null) {
    throw new ContractValidationError("M5_UNCERTAIN_WITHOUT_RESERVATION", "An uncertain operation must retain its reservation");
  }
  if (usage.reservation_decision_content_sha256 !== null && (usage.execution_mode === null || usage.logical_role === null)) {
    throw new ContractValidationError("M5_RESERVATION_BINDING_REQUIRED", "Reserved usage must bind route and logical role");
  }
}

function assertM5DecisionDocumentSemantics(decision: M5ControlDecisionDocument): void {
  assertUniqueBy(decision.budget, (entry) => entry.dimension, "DUPLICATE_M5_BUDGET_SNAPSHOT_DIMENSION");
  assertUniqueBy(decision.routes, (entry) => entry.route, "DUPLICATE_M5_ROUTE");
  assertUniqueBy(decision.failures, (entry) => entry.failure_identity, "DUPLICATE_M5_FAILURE");
  if (decision.progress.classification === "PROGRESS" ? decision.progress.kind === null || decision.progress.no_progress_reason !== null : decision.progress.kind !== null || decision.progress.no_progress_reason === null) {
    throw new ContractValidationError("M5_PROGRESS_RESULT_MISMATCH", "Progress classification and reason fields differ");
  }
  if ((decision.outcome === "BLOCK") !== (decision.blocking_reason !== null) || (decision.outcome === "PASS") !== decision.pass_authority) {
    throw new ContractValidationError("M5_OUTCOME_MISMATCH", "Decision outcome, blocking reason and PASS authority differ");
  }
  if ((decision.transition_event === null) !== (decision.predicted_next_state_content_sha256 === null)) {
    throw new ContractValidationError("M5_EVENT_PREDICTION_MISMATCH", "An event and predicted state identity must appear together");
  }
  if (decision.selected_route !== null && !decision.routes.some((route) => route.route === decision.selected_route && route.eligibility === "ELIGIBLE")) {
    throw new ContractValidationError("M5_SELECTED_ROUTE_INELIGIBLE", "Selected route is not uniquely eligible in the inventory");
  }
  if (decision.outcome === "AUTHORIZE" && decision.selected_route === null) throw new ContractValidationError("M5_ROUTE_REQUIRED", "Authorization requires a selected route");
  if (decision.contract_gate.status === "SATISFIED" && decision.contract_gate.pending_obligation_descriptor_sha256.length > 0) {
    throw new ContractValidationError("M5_GATE_RESULT_MISMATCH", "SATISFIED gate retains pending obligations");
  }
  if (decision.obligation_evidence !== undefined) {
    assertUniqueBy(decision.obligation_evidence, (entry) => entry.descriptor_sha256, "DUPLICATE_M5_OBLIGATION_EVIDENCE");
  }
  if (decision.reservation !== null) {
    const reservation = decision.reservation;
    assertUniqueBy(reservation.amounts, (entry) => entry.dimension, "DUPLICATE_M5_RESERVATION_DIMENSION");
    if (reservation.future_operation_id !== undefined && reservation.future_operation_id.length === 0) {
      throw new ContractValidationError("M5_RESERVATION_OPERATION_INVALID", "A reservation future operation identity must be nonempty");
    }
    if (reservation.status === "OUTCOME_UNCERTAIN" && reservation.reconciliation_evidence_content_sha256 !== null) {
      throw new ContractValidationError("M5_UNCERTAIN_RECONCILIATION", "An uncertain reservation cannot carry a completed reconciliation");
    }
    if (reservation.reserved_policy_content_sha256 !== undefined && reservation.reserved_policy_content_sha256 !== decision.policy_content_sha256) {
      throw new ContractValidationError("M5_RESERVATION_POLICY_MISMATCH", "Reservation policy identity differs from its decision");
    }
    if (reservation.reserved_state_content_sha256 !== undefined && reservation.reserved_state_content_sha256 !== decision.current_state_content_sha256) {
      throw new ContractValidationError("M5_RESERVATION_STATE_MISMATCH", "Reservation state identity differs from its decision");
    }
    if (reservation.reservation_decision_key !== undefined && reservation.reservation_decision_key !== decision.decision_key) {
      throw new ContractValidationError("M5_RESERVATION_DECISION_MISMATCH", "Reservation decision key differs from its decision");
    }
  }
}

function assertDocumentSemantics(schemaId: SchemaId, value: unknown, options: SemanticValidationOptions): void {
  const document = recordOf(value);
  assertDeclaredSetUniqueness(schemaId, document);
  assertPersistenceDocumentSemantics(schemaId, value);

  switch (schemaId) {
    case "pi_gacw_objective_v0": {
      const objective = value as ObjectiveDocument;
      assertNoScopeOverlap(objective.scope);
      assertCanonicalPathList("repository authority", objective.repository_authority_paths);
      assertAcceptanceSemantics(objective.acceptance_criteria, objective.owner_acceptance_criteria);
      assertOwnerAcceptanceMode(objective.requested_mode, objective.owner_acceptance_criteria.length);
      break;
    }
    case "pi_gacw_baseline_v0":
      assertBaselineSemantics(value as BaselineDocument);
      break;
    case "pi_gacw_authority_lock_v0":
      assertAuthorityLockSemantics(value as AuthorityLockDocument);
      break;
    case "pi_gacw_contract_v0": {
      const contract = value as ContractDocument;
      assertNoScopeOverlap(contract.scope);
      assertAcceptanceSemantics(contract.acceptance_criteria, contract.owner_acceptance_criteria);
      assertOwnerAcceptanceMode(contract.execution_mode, contract.owner_acceptance_criteria.length);
      break;
    }
    case "pi_gacw_route_map_v0":
      assertRouteMapSemantics(value as RouteMapDocument);
      break;
    case "pi_gacw_task_v0":
      assertTaskSemantics(value as TaskDocument);
      break;
    case "pi_gacw_task_graph_v0":
      assertTaskGraphSemantics(value as TaskGraphDocument, options.configuredMaxLeaves);
      break;
    case "pi_gacw_plan_approval_v0":
      assertPlanApprovalSemantics(value as PlanApprovalDocument);
      break;
    case "pi_gacw_state_v0":
      assertWorkflowStateSemantics(value as WorkflowState);
      break;
    case "pi_gacw_reducer_policy_v0":
      assertReducerPolicySemantics(value as ReducerPolicy);
      break;
    case "pi_gacw_m5_control_policy_v0":
      assertM5PolicyDocumentSemantics(value as M5ControlPolicyDocument);
      break;
    case "pi_gacw_m5_usage_evidence_v0":
      assertM5UsageDocumentSemantics(value as M5UsageEvidenceDocument);
      break;
    case "pi_gacw_m5_control_decision_v0":
      assertM5DecisionDocumentSemantics(value as M5ControlDecisionDocument);
      break;
    default:
      break;
  }
}

export function assertDocumentValid(schemaId: SchemaId, value: unknown, options: SemanticValidationOptions = {}): void {
  assertSchema(schemaId, value);
  assertDocumentSemantics(schemaId, value, options);
  const document = recordOf(value);
  const projection = domainProjectionBySchema[schemaId];
  const valid = projection === undefined
    ? unsafeVerifyContentIdentity(document)
    : unsafeVerifyDocumentIdentities(projection, document);
  if (!valid) {
    throw new ContractValidationError("IDENTITY_MISMATCH", `${schemaId} identity verification failed`);
  }
}

const IDENTITY_PLACEHOLDER = `sha256:${"0".repeat(64)}`;

/**
 * The only public contract-document identity constructor. Structure and
 * semantics are checked before any projection or hash is computed.
 */
export function identifyContractDocument<T extends Record<string, unknown>>(
  schemaId: SchemaId,
  value: T,
  options: SemanticValidationOptions = {},
): T & { readonly content_sha256: string } {
  const source = recordOf(value);
  const candidate: Record<string, unknown> = { ...source };
  if (candidate["content_sha256"] === undefined) candidate["content_sha256"] = IDENTITY_PLACEHOLDER;
  const projection = domainProjectionBySchema[schemaId];
  if (projection !== undefined) {
    const digestField = getProjectionDefinition(projection).digest_field;
    if (digestField === null) {
      throw new ContractValidationError("IDENTITY_CONFIGURATION_ERROR", `${projection} has no domain digest field`);
    }
    if (candidate[digestField] === undefined) candidate[digestField] = IDENTITY_PLACEHOLDER;
  }

  assertSchema(schemaId, candidate);
  assertDocumentSemantics(schemaId, candidate, options);
  const identified = projection === undefined
    ? unsafeWithContentIdentity(candidate)
    : unsafeWithDocumentIdentities(projection, candidate);
  assertDocumentValid(schemaId, identified, options);
  return identified as T & { readonly content_sha256: string };
}

export function verifyContractDocument(schemaId: SchemaId, value: unknown, options: SemanticValidationOptions = {}): boolean {
  try {
    assertDocumentValid(schemaId, value, options);
    return true;
  } catch (error) {
    if (error instanceof ContractValidationError || error instanceof TypeError) return false;
    throw error;
  }
}

export function assertTransitionEvent(value: unknown): asserts value is TransitionEvent {
  assertDocumentValid("pi_gacw_transition_event_v0", value);
}

export function assertWorkflowState(value: unknown): asserts value is WorkflowState {
  assertDocumentValid("pi_gacw_state_v0", value);
}

export function assertReducerPolicy(value: unknown): asserts value is ReducerPolicy {
  assertDocumentValid("pi_gacw_reducer_policy_v0", value);
}
