import { Type, type Static, type TProperties, type TSchema } from "@sinclair/typebox";

import { DIGEST_PATTERN } from "../identity/digest.js";
import { PROJECTION_IDS } from "../identity/projections.js";

export const SCHEMA_VERSION = "0.1.0" as const;

function deepFreeze<T>(value: T, seen = new Set<object>()): T {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && "value" in descriptor) deepFreeze(descriptor.value, seen);
  }
  Object.freeze(object);
  return value;
}

export const EXECUTION_MODES = ["AUTO", "DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const;
export const CONCRETE_EXECUTION_MODES = ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const;
export const LOGICAL_MODEL_ROLES = [
  "SOL_OWNER",
  "SOL_PLANNER",
  "SOL_REPLAN",
  "SOL_CLOSEOUT",
  "LUNA_EXECUTOR",
  "BENCHMARK_VERIFIER",
  "BENCHMARK_SELECTOR",
] as const;
export const ENFORCEMENT_CLASSES = [
  "HARD_ENFORCEABLE",
  "SOFT_ENFORCEABLE",
  "OBSERVABLE_ONLY",
  "ESTIMATED_ONLY",
  "UNAVAILABLE",
] as const;
export const WORKFLOW_PHASES = [
  "CREATED",
  "OBJECTIVE_FROZEN",
  "LOCK_ACQUIRED",
  "BASELINE_CAPTURED",
  "AWAITING_BASELINE_APPROVAL",
  "BASELINE_APPROVED",
  "FULL_PREFLIGHT_PASSED",
  "CONTRACT_VALIDATED",
  "ROUTE_SELECTED",
  "DIRECT_CONTRACT_VALIDATED",
  "AWAITING_DIRECT_APPROVAL",
  "DIRECT_TASK_FROZEN",
  "DIRECT_FAST_PREFLIGHT",
  "DIRECT_ATTEMPT_RUNNING",
  "DIRECT_POSTFLIGHT",
  "DIRECT_VERIFYING",
  "DIRECT_RETRY_READY",
  "SINGLE_OWNER_CONTRACT_VALIDATED",
  "AWAITING_SINGLE_OWNER_APPROVAL",
  "SINGLE_OWNER_TASK_FROZEN",
  "SINGLE_OWNER_FAST_PREFLIGHT",
  "SINGLE_OWNER_RUNNING",
  "SINGLE_OWNER_POSTFLIGHT",
  "SINGLE_OWNER_VERIFYING",
  "AWAITING_DECLARED_OWNER_ACCEPTANCE",
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
  "PASS",
  "BLOCKED",
] as const;

export const EVENT_TYPES = [
  "FREEZE_OBJECTIVE",
  "ACQUIRE_LOCK",
  "CAPTURE_BASELINE",
  "REQUEST_BASELINE_APPROVAL",
  "ACCEPT_CLEAN_BASELINE",
  "APPROVE_BASELINE",
  "PASS_FULL_PREFLIGHT",
  "VALIDATE_CONTRACT",
  "SELECT_ROUTE",
  "VALIDATE_DIRECT_CONTRACT",
  "REQUEST_DIRECT_APPROVAL",
  "APPROVE_DIRECT_TASK",
  "PASS_DIRECT_FAST_PREFLIGHT",
  "START_DIRECT_ATTEMPT",
  "COMPLETE_DIRECT_ATTEMPT",
  "PASS_DIRECT_POSTFLIGHT",
  "DIRECT_VERIFICATION_PASSED",
  "DIRECT_VERIFICATION_FAILED",
  "ADMIT_DIRECT_RETRY",
  "VALIDATE_SINGLE_OWNER_CONTRACT",
  "REQUEST_SINGLE_OWNER_APPROVAL",
  "APPROVE_SINGLE_OWNER_TASK",
  "PASS_SINGLE_OWNER_FAST_PREFLIGHT",
  "START_SINGLE_OWNER",
  "ADMIT_SINGLE_OWNER_MUTATION_CYCLE",
  "COMPLETE_SINGLE_OWNER",
  "PASS_SINGLE_OWNER_POSTFLIGHT",
  "SINGLE_OWNER_VERIFICATION_PASSED",
  "SINGLE_OWNER_VERIFICATION_FAILED",
  "OWNER_ACCEPTED",
  "OWNER_REJECTED",
  "START_PLAN",
  "COMPLETE_PLAN",
  "REQUEST_PLAN_APPROVAL",
  "APPROVE_PLAN",
  "ACTIVATE_DAG",
  "SELECT_READY_LEAF",
  "START_LEAF_ATTEMPT",
  "COMPLETE_LEAF_ATTEMPT",
  "PASS_LEAF_POSTFLIGHT",
  "LEAF_VERIFICATION_PASSED",
  "LEAF_VERIFICATION_FAILED",
  "ADMIT_LEAF_RETRY",
  "START_CONSTRAINED_REPLAN",
  "COMPLETE_CONSTRAINED_REPLAN",
  "START_CLOSEOUT",
  "COMPLETE_CLOSEOUT",
  "CLOSEOUT_PASSED",
  "CLOSEOUT_DEFECT",
  "BLOCK",
] as const;

function StringEnum<const Values extends readonly string[]>(values: Values) {
  return Type.Unsafe<Values[number]>({ type: "string", enum: [...values] });
}

function StrictObject<const Properties extends TProperties>(
  properties: Properties,
  options: { readonly $id?: string; readonly title?: string } = {},
) {
  return Type.Object(properties, { ...options, additionalProperties: false });
}

function NonEmptyString(maxLength = 16_384) {
  return Type.String({ minLength: 1, maxLength });
}

function Identifier() {
  return Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" });
}

function RunId() {
  return Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$" });
}

function Digest() {
  return Type.String({ pattern: DIGEST_PATTERN });
}

function NullableDigest() {
  return Type.Union([Digest(), Type.Null()]);
}

function PathString() {
  return Type.String({ minLength: 1, maxLength: 4096 });
}

function BoundedInteger(maximum = 1_000_000_000) {
  return Type.Integer({ minimum: 0, maximum });
}

function DocumentFields<const SchemaId extends string>(schemaId: SchemaId) {
  return {
    schema_id: Type.Literal(schemaId),
    schema_version: Type.Literal(SCHEMA_VERSION),
    content_projection_id: Type.Literal("document-content-v1"),
    content_sha256: Digest(),
  };
}

export const ExecutionModeSchema = StringEnum(EXECUTION_MODES);
export const ConcreteExecutionModeSchema = StringEnum(CONCRETE_EXECUTION_MODES);
export const LogicalModelRoleSchema = StringEnum(LOGICAL_MODEL_ROLES);
export const WorkflowPhaseSchema = StringEnum(WORKFLOW_PHASES);
export const ProjectionIdSchema = StringEnum(PROJECTION_IDS);

export const RepositoryIdentitySchema = StrictObject({
  root: PathString(),
  git_common_dir: PathString(),
  worktree: PathString(),
  branch: NonEmptyString(512),
  head: Type.String({ pattern: "^[0-9a-f]{40,64}$" }),
});

export const ScopeSchema = StrictObject({
  readable_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 10_000 }),
  editable_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 10_000 }),
  frozen_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 10_000 }),
});

export const AcceptanceCriterionSchema = StrictObject({
  criterion_id: Identifier(),
  description: NonEmptyString(),
  evidence_kind: StringEnum(["COMMAND", "FILE", "DIGEST", "OWNER_ACCEPTANCE"] as const),
  owner_acceptance: Type.Boolean(),
});

export const VerificationCommandSchema = StrictObject({
  command_id: Identifier(),
  argv: Type.Array(NonEmptyString(4096), { minItems: 1, maxItems: 128 }),
  cwd: PathString(),
  timeout_ms: Type.Integer({ minimum: 1, maximum: 86_400_000 }),
  network: StringEnum(["FORBIDDEN", "OWNER_APPROVED"] as const),
});

export const CommandPolicySchema = StrictObject({
  shell: Type.Literal(false),
  network: StringEnum(["FORBIDDEN", "OWNER_APPROVED"] as const),
  allowed_executables: Type.Array(NonEmptyString(1024), { minItems: 0, maxItems: 1024, uniqueItems: true }),
  forbidden_operations: Type.Array(
    StringEnum(["INSTALL", "COMMIT", "PUSH", "TAG", "MERGE", "REBASE", "RESET", "RESTORE", "CLEAN", "SWITCH_BRANCH", "MODIFY_REMOTE"] as const),
    { minItems: 1, uniqueItems: true },
  ),
});

export const ToolPolicySchema = StrictObject({
  policy_id: Identifier(),
  built_in_tools_disabled: Type.Literal(true),
  mutation_tool: StringEnum(["NONE", "APPLY_PATCH_SCOPED"] as const),
  command_gateway: StringEnum(["INSPECTION_ONLY", "TASK_AND_VERIFICATION", "VERIFICATION_ONLY"] as const),
  maximum_tool_calls: Type.Integer({ minimum: 0, maximum: 1_000_000 }),
});

export const RouteSchema = StrictObject({
  logical_role: LogicalModelRoleSchema,
  provider_id: Identifier(),
  model_id: Identifier(),
  effort: StringEnum(["max", "high"] as const),
  tool_policy: ToolPolicySchema,
});

export const EdgeSchema = StrictObject({
  from: Identifier(),
  to: Identifier(),
});

export const UsageMeasurementSchema = Type.Union([
  StrictObject({
    value: Type.Null(),
    enforcement_class: Type.Literal("UNAVAILABLE"),
  }),
  StrictObject({
    value: BoundedInteger(1_000_000_000_000),
    enforcement_class: StringEnum([
      "HARD_ENFORCEABLE",
      "SOFT_ENFORCEABLE",
      "OBSERVABLE_ONLY",
      "ESTIMATED_ONLY",
    ] as const),
  }),
]);

export const UsageDimensionsSchema = StrictObject({
  worker_invocation: UsageMeasurementSchema,
  model_turn: UsageMeasurementSchema,
  provider_request: UsageMeasurementSchema,
  tool_call: UsageMeasurementSchema,
});

export const LimitEnvelopeSchema = StrictObject({
  max_leaves: Type.Integer({ minimum: 1, maximum: 8 }),
  max_attempts_per_leaf: Type.Integer({ minimum: 1, maximum: 2 }),
  max_replans: Type.Integer({ minimum: 0, maximum: 2 }),
  max_worker_invocations: Type.Integer({ minimum: 1, maximum: 20 }),
  max_model_turns: Type.Integer({ minimum: 1, maximum: 1_000_000 }),
  max_tool_calls: Type.Integer({ minimum: 0, maximum: 1_000_000 }),
  max_input_tokens: Type.Integer({ minimum: 1, maximum: 1_000_000_000 }),
  max_output_tokens: Type.Integer({ minimum: 1, maximum: 1_000_000_000 }),
  max_cost_microusd: Type.Integer({ minimum: 0, maximum: 1_000_000_000_000 }),
  max_wall_time_ms: Type.Integer({ minimum: 1, maximum: 604_800_000 }),
});

export const ObjectiveSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_objective_v0"),
    objective_projection_id: Type.Literal("objective-freeze-v1"),
    objective_sha256: Digest(),
    target_repository: RepositoryIdentitySchema,
    requested_mode: ExecutionModeSchema,
    objective: NonEmptyString(),
    primary_failure_domain: Identifier(),
    scope: ScopeSchema,
    repository_authority_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 10_000 }),
    frozen_invariants: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000, uniqueItems: true }),
    required_outputs: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000, uniqueItems: true }),
    acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { minItems: 1, maxItems: 10_000 }),
    verification_commands: Type.Array(VerificationCommandSchema, { minItems: 1, maxItems: 10_000 }),
    owner_acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { maxItems: 10_000 }),
    command_policy: CommandPolicySchema,
    baseline_mode: StringEnum(["CLEAN_REQUIRED", "APPROVED_BASELINE_DIRTY"] as const),
    configured_max_leaves: Type.Integer({ minimum: 1, maximum: 8 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_objective_v0.schema.json" },
);

export const OwnerDecisionsSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_owner_decisions_v0"),
    decisions: Type.Array(
      StrictObject({
        decision_id: Identifier(),
        question: NonEmptyString(),
        answer: NonEmptyString(),
      }),
      { minItems: 1, maxItems: 10_000 },
    ),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_owner_decisions_v0.schema.json" },
);

export const RouteMapSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_route_map_v0"),
    route_map_projection_id: Type.Literal("route-map-v1"),
    route_map_sha256: Digest(),
    routes: Type.Array(RouteSchema, { minItems: 7, maxItems: 7, uniqueItems: true }),
    fallback: Type.Literal(false),
    provider_managed_multi_agent: Type.Literal(false),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_route_map_v0.schema.json" },
);

export const RouteMapApprovalSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_route_map_approval_v0"),
    route_map_approval_projection_id: Type.Literal("route-map-approval-v1"),
    route_map_approval_sha256: Digest(),
    route_map_sha256: Digest(),
    approved_by: NonEmptyString(1024),
    approval_token_sha256: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_route_map_approval_v0.schema.json" },
);

export const BaselineFileSchema = StrictObject({
  path: PathString(),
  content_sha256: Digest(),
  ownership_class: StringEnum([
    "OWNER_AUTHORITY",
    "OWNER_ACCEPTED_MUTABLE",
    "PREEXISTING_UNRELATED",
    "GENERATED_ACCEPTED_BASELINE",
  ] as const),
  data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE", "LARGE_BINARY", "HASH_ONLY"] as const),
});

export const BaselineSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_baseline_v0"),
    baseline_projection_id: Type.Literal("baseline-snapshot-v1"),
    baseline_sha256: Digest(),
    target_repository: RepositoryIdentitySchema,
    mode: StringEnum(["CLEAN_REQUIRED", "APPROVED_BASELINE_DIRTY"] as const),
    git_state_sha256: Digest(),
    staged_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 100_000 }),
    unstaged_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 100_000 }),
    untracked_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 100_000 }),
    files: Type.Array(BaselineFileSchema, { maxItems: 100_000, uniqueItems: true }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_baseline_v0.schema.json" },
);

export const BaselineApprovalSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_baseline_approval_v0"),
    baseline_approval_projection_id: Type.Literal("baseline-approval-v1"),
    baseline_approval_sha256: Digest(),
    baseline_sha256: Digest(),
    target_repository: RepositoryIdentitySchema,
    approved_by: NonEmptyString(1024),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_baseline_approval_v0.schema.json" },
);

export const AuthorityLockSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_authority_lock_v0"),
    authority_lock_projection_id: Type.Literal("authority-lock-v1"),
    authority_lock_sha256: Digest(),
    authorities: Type.Array(
      StrictObject({
        path: PathString(),
        role: StringEnum([
          "OWNER_DECISION",
          "REPOSITORY_INSTRUCTION",
          "PUBLIC_API",
          "SCHEMA",
          "PROTOCOL",
          "SECURITY_POLICY",
          "BUILD_MANIFEST",
          "TEST_CONTRACT",
          "DOCUMENTATION_NORMATIVE",
          "IMPLEMENTATION_CONTEXT",
        ] as const),
        content_sha256: Digest(),
      }),
      { minItems: 1, maxItems: 10_000, uniqueItems: true },
    ),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_authority_lock_v0.schema.json" },
);

export const ContractSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_contract_v0"),
    contract_projection_id: Type.Literal("contract-freeze-v1"),
    contract_sha256: Digest(),
    objective_sha256: Digest(),
    target_repository: RepositoryIdentitySchema,
    execution_mode: ConcreteExecutionModeSchema,
    baseline_approval_sha256: Digest(),
    authority_lock_sha256: Digest(),
    route_map_approval_sha256: Digest(),
    scope: ScopeSchema,
    required_inputs: Type.Array(NonEmptyString(), { maxItems: 10_000, uniqueItems: true }),
    required_outputs: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000, uniqueItems: true }),
    acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { minItems: 1, maxItems: 10_000 }),
    owner_acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { maxItems: 10_000 }),
    verification_commands: Type.Array(VerificationCommandSchema, { minItems: 0, maxItems: 10_000 }),
    command_policy: CommandPolicySchema,
    limits: LimitEnvelopeSchema,
    stopping_conditions: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_contract_v0.schema.json" },
);

export const RoutingSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_routing_v0"),
    routing_projection_id: Type.Literal("routing-freeze-v1"),
    routing_sha256: Digest(),
    requested_mode: ExecutionModeSchema,
    selected_mode: ConcreteExecutionModeSchema,
    reasons: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 1024, uniqueItems: true }),
    route_map_approval_sha256: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_routing_v0.schema.json" },
);

export const BudgetSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_budget_v0"),
    budget_projection_id: Type.Literal("budget-freeze-v1"),
    budget_sha256: Digest(),
    limits: LimitEnvelopeSchema,
    usage: UsageDimensionsSchema,
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_budget_v0.schema.json" },
);

export const TaskSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_task_v0"),
    task_projection_id: Type.Literal("task-packet-v1"),
    task_sha256: Digest(),
    task_id: Identifier(),
    topological_rank: BoundedInteger(1_000_000),
    priority: Type.Integer({ minimum: -1_000_000, maximum: 1_000_000 }),
    dependencies: Type.Array(Identifier(), { uniqueItems: true, maxItems: 8 }),
    objective: NonEmptyString(),
    scope: ScopeSchema,
    required_inputs: Type.Array(NonEmptyString(), { maxItems: 10_000, uniqueItems: true }),
    required_outputs: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000, uniqueItems: true }),
    acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { minItems: 1, maxItems: 10_000 }),
    owner_acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { maxItems: 10_000 }),
    verification_commands: Type.Array(VerificationCommandSchema, { minItems: 0, maxItems: 10_000 }),
    assigned_role: StringEnum(["SOL_OWNER", "LUNA_EXECUTOR"] as const),
    write_owner: Identifier(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_task_v0.schema.json" },
);

export const TaskGraphNodeSchema = StrictObject({
  task_id: Identifier(),
  task_sha256: Digest(),
  topological_rank: BoundedInteger(1_000_000),
  priority: Type.Integer({ minimum: -1_000_000, maximum: 1_000_000 }),
  dependencies: Type.Array(Identifier(), { uniqueItems: true, maxItems: 8 }),
  editable_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 10_000 }),
  write_owner: Identifier(),
});

export const TaskGraphSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_task_graph_v0"),
    task_graph_projection_id: Type.Literal("task-graph-freeze-v1"),
    task_graph_sha256: Digest(),
    tasks: Type.Array(TaskGraphNodeSchema, { minItems: 1, maxItems: 8, uniqueItems: true }),
    edges: Type.Array(EdgeSchema, { maxItems: 56, uniqueItems: true }),
    configured_max_leaves: Type.Integer({ minimum: 1, maximum: 8 }),
    write_ownership: Type.Literal("ONE_ACTIVE_WRITER"),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_task_graph_v0.schema.json" },
);

export const PlanBindingsSchema = StrictObject({
  objective_sha256: Digest(),
  target_repository: RepositoryIdentitySchema,
  execution_mode: ConcreteExecutionModeSchema,
  baseline_approval_sha256: Digest(),
  authority_lock_sha256: Digest(),
  contract_sha256: Digest(),
  dag: StrictObject({
    task_graph_sha256: Digest(),
    edges: Type.Array(EdgeSchema, { maxItems: 56, uniqueItems: true }),
    ordered_task_packet_identities: Type.Array(Digest(), { minItems: 1, maxItems: 8, uniqueItems: true }),
  }),
  scope: ScopeSchema,
  required_inputs: Type.Array(NonEmptyString(), { maxItems: 10_000, uniqueItems: true }),
  required_outputs: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000, uniqueItems: true }),
  acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { minItems: 1, maxItems: 10_000 }),
  owner_acceptance_criteria: Type.Array(AcceptanceCriterionSchema, { maxItems: 10_000 }),
  verification_commands: Type.Array(VerificationCommandSchema, { minItems: 1, maxItems: 10_000 }),
  command_policy: CommandPolicySchema,
  logical_routes: Type.Array(RouteSchema, { minItems: 1, maxItems: 7, uniqueItems: true }),
  limits: LimitEnvelopeSchema,
  stopping_conditions: Type.Array(NonEmptyString(), { minItems: 1, maxItems: 10_000 }),
});

export const PlanApprovalSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_plan_approval_v0"),
    plan_approval_projection_id: Type.Literal("plan-approval-v1"),
    plan_approval_sha256: Digest(),
    bindings: PlanBindingsSchema,
    approved_by: NonEmptyString(1024),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_plan_approval_v0.schema.json" },
);

export const WorkerInvocationCountersSchema = StrictObject({
  total: Type.Integer({ minimum: 0, maximum: 20 }),
  sol_owner: Type.Integer({ minimum: 0, maximum: 1 }),
  sol_planner: Type.Integer({ minimum: 0, maximum: 1 }),
  sol_replan: Type.Integer({ minimum: 0, maximum: 2 }),
  sol_closeout: Type.Integer({ minimum: 0, maximum: 1 }),
  luna_executor: Type.Integer({ minimum: 0, maximum: 16 }),
});

export const StateCountersSchema = StrictObject({
  worker_invocations: WorkerInvocationCountersSchema,
  direct_attempts: Type.Integer({ minimum: 0, maximum: 2 }),
  single_owner_mutation_cycles: Type.Integer({ minimum: 0, maximum: 2 }),
  constrained_replans: Type.Integer({ minimum: 0, maximum: 2 }),
  leaves_completed: Type.Integer({ minimum: 0, maximum: 8 }),
});

export const TaskRuntimeStatusSchema = StrictObject({
  task_id: Identifier(),
  status: StringEnum(["PENDING", "RUNNING", "PASS", "BLOCKED"] as const),
  attempts: Type.Integer({ minimum: 0, maximum: 2 }),
  postflight_completed: Type.Boolean(),
  verification_completed: Type.Boolean(),
  retry_progress_admitted: Type.Boolean(),
});

export const StateGateStatusSchema = StrictObject({
  planner_completed: Type.Boolean(),
  owner_acceptance_completed: Type.Boolean(),
  closeout_completed: Type.Boolean(),
  closeout_verification_completed: Type.Boolean(),
});

export const StateIdentitiesSchema = StrictObject({
  objective_sha256: Digest(),
  contract_sha256: Digest(),
  baseline_approval_sha256: Digest(),
  authority_lock_sha256: Digest(),
  plan_approval_sha256: NullableDigest(),
  task_graph_sha256: NullableDigest(),
  scope_sha256: Digest(),
  acceptance_sha256: Digest(),
  budget_sha256: Digest(),
});

export const WorkflowStateSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_state_v0"),
    run_id: Identifier(),
    execution_mode: ConcreteExecutionModeSchema,
    phase: WorkflowPhaseSchema,
    identities: StateIdentitiesSchema,
    frozen_policy_content_sha256: Digest(),
    counters: StateCountersSchema,
    gates: StateGateStatusSchema,
    tasks: Type.Array(TaskRuntimeStatusSchema, { maxItems: 8 }),
    active_task_id: Type.Union([Identifier(), Type.Null()]),
    baseline_approval_required: Type.Union([Type.Boolean(), Type.Null()]),
    route_frozen: Type.Boolean(),
    owner_acceptance_required: Type.Boolean(),
    replan_in_progress: Type.Boolean(),
    terminal_reason: Type.Union([NonEmptyString(4096), Type.Null()]),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_state_v0.schema.json" },
);

export const ReducerTaskPolicySchema = StrictObject({
  task_id: Identifier(),
  task_sha256: Digest(),
  topological_rank: BoundedInteger(1_000_000),
  priority: Type.Integer({ minimum: -1_000_000, maximum: 1_000_000 }),
  dependencies: Type.Array(Identifier(), { uniqueItems: true, maxItems: 8 }),
  editable_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 10_000 }),
});

export const ReducerPolicySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_reducer_policy_v0"),
    run_id: Identifier(),
    execution_mode: ConcreteExecutionModeSchema,
    owner_acceptance_required: Type.Boolean(),
    limits: StrictObject({
      max_direct_attempts: Type.Integer({ minimum: 1, maximum: 2 }),
      max_single_owner_mutation_cycles: Type.Integer({ minimum: 1, maximum: 2 }),
      max_attempts_per_leaf: Type.Integer({ minimum: 1, maximum: 2 }),
      max_replans: Type.Integer({ minimum: 0, maximum: 2 }),
      max_leaves: Type.Integer({ minimum: 1, maximum: 8 }),
      max_worker_invocations: Type.Integer({ minimum: 1, maximum: 20 }),
    }),
    tasks: Type.Array(ReducerTaskPolicySchema, { minItems: 1, maxItems: 8 }),
    frozen_bindings: StrictObject({
      plan_approval_sha256: NullableDigest(),
      task_graph_sha256: NullableDigest(),
      scope_sha256: Digest(),
      acceptance_sha256: Digest(),
      budget_sha256: Digest(),
    }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_reducer_policy_v0.schema.json" },
);

export const ProgressDeltaSchema = StrictObject({
  kind: StringEnum([
    "VALID_REPOSITORY_DELTA",
    "NEW_TEST_EVIDENCE",
    "EVIDENCE_BACKED_DIAGNOSIS",
    "FAILURE_RECLASSIFICATION",
    "CONTEXT_RESTORATION",
  ] as const),
  evidence_sha256: Digest(),
  summary: NonEmptyString(4096),
});

const FailureClassSchema = StringEnum([
  "LOCAL_IMPLEMENTATION_DEFECT",
  "PLAN_INCORRECT",
  "SAME_FAILURE_TWICE",
  "SCOPE_EXPANSION_REQUIRED",
  "STATE_DRIFT",
  "TEST_INTEGRITY_VIOLATION",
  "MODEL_UNAVAILABLE",
] as const);

function EventVariant<const EventType extends (typeof EVENT_TYPES)[number], const Payload extends TProperties>(
  eventType: EventType,
  payload: Payload,
) {
  return StrictObject({
    ...DocumentFields("pi_gacw_transition_event_v0"),
    event_id: Identifier(),
    event_type: Type.Literal(eventType),
    payload: StrictObject(payload),
  });
}

const EmptyPayload = {};
const eventVariants = [
  EventVariant("FREEZE_OBJECTIVE", EmptyPayload),
  EventVariant("ACQUIRE_LOCK", EmptyPayload),
  EventVariant("CAPTURE_BASELINE", { approval_required: Type.Boolean() }),
  EventVariant("REQUEST_BASELINE_APPROVAL", EmptyPayload),
  EventVariant("ACCEPT_CLEAN_BASELINE", EmptyPayload),
  EventVariant("APPROVE_BASELINE", EmptyPayload),
  EventVariant("PASS_FULL_PREFLIGHT", EmptyPayload),
  EventVariant("VALIDATE_CONTRACT", EmptyPayload),
  EventVariant("SELECT_ROUTE", { execution_mode: ConcreteExecutionModeSchema }),
  EventVariant("VALIDATE_DIRECT_CONTRACT", EmptyPayload),
  EventVariant("REQUEST_DIRECT_APPROVAL", EmptyPayload),
  EventVariant("APPROVE_DIRECT_TASK", EmptyPayload),
  EventVariant("PASS_DIRECT_FAST_PREFLIGHT", EmptyPayload),
  EventVariant("START_DIRECT_ATTEMPT", EmptyPayload),
  EventVariant("COMPLETE_DIRECT_ATTEMPT", EmptyPayload),
  EventVariant("PASS_DIRECT_POSTFLIGHT", EmptyPayload),
  EventVariant("DIRECT_VERIFICATION_PASSED", EmptyPayload),
  EventVariant("DIRECT_VERIFICATION_FAILED", { failure_class: FailureClassSchema }),
  EventVariant("ADMIT_DIRECT_RETRY", { progress_delta: ProgressDeltaSchema }),
  EventVariant("VALIDATE_SINGLE_OWNER_CONTRACT", EmptyPayload),
  EventVariant("REQUEST_SINGLE_OWNER_APPROVAL", EmptyPayload),
  EventVariant("APPROVE_SINGLE_OWNER_TASK", EmptyPayload),
  EventVariant("PASS_SINGLE_OWNER_FAST_PREFLIGHT", EmptyPayload),
  EventVariant("START_SINGLE_OWNER", EmptyPayload),
  EventVariant("ADMIT_SINGLE_OWNER_MUTATION_CYCLE", EmptyPayload),
  EventVariant("COMPLETE_SINGLE_OWNER", EmptyPayload),
  EventVariant("PASS_SINGLE_OWNER_POSTFLIGHT", EmptyPayload),
  EventVariant("SINGLE_OWNER_VERIFICATION_PASSED", EmptyPayload),
  EventVariant("SINGLE_OWNER_VERIFICATION_FAILED", { failure_class: FailureClassSchema }),
  EventVariant("OWNER_ACCEPTED", EmptyPayload),
  EventVariant("OWNER_REJECTED", { reason: NonEmptyString(4096) }),
  EventVariant("START_PLAN", EmptyPayload),
  EventVariant("COMPLETE_PLAN", EmptyPayload),
  EventVariant("REQUEST_PLAN_APPROVAL", EmptyPayload),
  EventVariant("APPROVE_PLAN", { plan_approval_sha256: Digest(), task_graph_sha256: Digest() }),
  EventVariant("ACTIVATE_DAG", EmptyPayload),
  EventVariant("SELECT_READY_LEAF", EmptyPayload),
  EventVariant("START_LEAF_ATTEMPT", EmptyPayload),
  EventVariant("COMPLETE_LEAF_ATTEMPT", EmptyPayload),
  EventVariant("PASS_LEAF_POSTFLIGHT", EmptyPayload),
  EventVariant("LEAF_VERIFICATION_PASSED", EmptyPayload),
  EventVariant("LEAF_VERIFICATION_FAILED", { failure_class: FailureClassSchema }),
  EventVariant("ADMIT_LEAF_RETRY", { progress_delta: ProgressDeltaSchema }),
  EventVariant("START_CONSTRAINED_REPLAN", EmptyPayload),
  EventVariant("COMPLETE_CONSTRAINED_REPLAN", {
    frozen_bindings: StrictObject({
      plan_approval_sha256: Digest(),
      task_graph_sha256: Digest(),
      scope_sha256: Digest(),
      acceptance_sha256: Digest(),
      budget_sha256: Digest(),
    }),
    proposed_task_ids: Type.Array(Identifier(), { minItems: 2, maxItems: 8, uniqueItems: true }),
    proposed_edges: Type.Array(EdgeSchema, { maxItems: 56 }),
    progress_delta: ProgressDeltaSchema,
  }),
  EventVariant("START_CLOSEOUT", EmptyPayload),
  EventVariant("COMPLETE_CLOSEOUT", EmptyPayload),
  EventVariant("CLOSEOUT_PASSED", EmptyPayload),
  EventVariant("CLOSEOUT_DEFECT", { reason: NonEmptyString(4096) }),
  EventVariant("BLOCK", { reason: NonEmptyString(4096) }),
] as const;

export const TransitionEventSchema = Type.Union([...eventVariants], {
  $id: "https://pi-gacw.invalid/schemas/pi_gacw_transition_event_v0.schema.json",
});

export const TransitionCommitSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_transition_commit_v0"),
    transition_commit_projection_id: Type.Literal("transition-commit-v1"),
    transition_commit_sha256: Digest(),
    sequence: Type.Integer({ minimum: 1, maximum: Number.MAX_SAFE_INTEGER }),
    from_state_sha256: Digest(),
    event_sha256: Digest(),
    to_state_sha256: Digest(),
    evidence_sha256: Type.Array(Digest(), { maxItems: 100_000, uniqueItems: true }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_transition_commit_v0.schema.json" },
);

export const ProcessMetadataSchema = StrictObject({
  controller_instance_id: Identifier(),
  process_id: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
  invocation_id: Identifier(),
});

export const EvidenceMetadataSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_evidence_metadata_v0"),
    run_id: RunId(),
    evidence_sha256: Digest(),
    byte_length: Type.Integer({ minimum: 0, maximum: 16_777_216 }),
    media_type: NonEmptyString(255),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_evidence_metadata_v0.schema.json" },
);

export const EvidenceManifestEntrySchema = StrictObject({
  evidence_sha256: Digest(),
  metadata_content_sha256: Digest(),
});

export const EvidenceManifestSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_evidence_manifest_v0"),
    run_id: RunId(),
    entries: Type.Array(EvidenceManifestEntrySchema, { maxItems: 1024, uniqueItems: true }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_evidence_manifest_v0.schema.json" },
);

export const PersistedStatePointerSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_persisted_state_pointer_v0"),
    run_id: RunId(),
    revision: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
    workflow_state_content_sha256: Digest(),
    transition_commit_content_sha256: Digest(),
    previous_state_pointer_content_sha256: NullableDigest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_persisted_state_pointer_v0.schema.json" },
);

export const ProcessInterruptionObjectSchema = StrictObject({
  kind: StringEnum([
    "RAW_EVIDENCE",
    "EVIDENCE_METADATA",
    "EVIDENCE_MANIFEST",
    "WORKFLOW_STATE",
    "TRANSITION_EVENT",
    "REDUCER_POLICY",
    "PROCESS_ASSESSMENT",
    "TRANSITION_COMMIT",
  ] as const),
  content_sha256: Digest(),
});

export const ProcessInterruptionSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_process_interruption_v0"),
    run_id: RunId(),
    expected_revision: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
    expected_state_pointer_content_sha256: Digest(),
    expected_workflow_state_content_sha256: Digest(),
    evidence: StrictObject({
      controller_instance_id: Identifier(),
      process_id: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
      invocation_id: Identifier(),
      exit_kind: Type.Literal("UNEXPECTED_TERMINATION"),
      detail: NonEmptyString(4096),
    }),
    orphan_objects: Type.Array(ProcessInterruptionObjectSchema, { maxItems: 100_000, uniqueItems: true }),
    temporary_files: Type.Array(PathString(), { maxItems: 100_000, uniqueItems: true }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_process_interruption_v0.schema.json" },
);

export const StateTransitionCommitSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_state_transition_commit_v0"),
    commit_protocol_version: Type.Literal("state-commit-v1"),
    commit_kind: StringEnum(["GENESIS", "TRANSITION", "PROCESS_CRASH"] as const),
    run_id: RunId(),
    transition_id: Identifier(),
    previous_revision: Type.Union([
      Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER - 1 }),
      Type.Null(),
    ]),
    new_revision: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
    previous_state_pointer_content_sha256: NullableDigest(),
    previous_workflow_state_content_sha256: NullableDigest(),
    previous_transition_commit_content_sha256: NullableDigest(),
    transition_event_content_sha256: NullableDigest(),
    reducer_policy_content_sha256: Digest(),
    new_workflow_state_content_sha256: Digest(),
    evidence_manifest_content_sha256: Digest(),
    process_assessment_content_sha256: NullableDigest(),
    process_metadata: ProcessMetadataSchema,
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_state_transition_commit_v0.schema.json" },
);

export const CommandResultSchema = StrictObject({
  command_id: Identifier(),
  exit_code: Type.Integer({ minimum: 0, maximum: 255 }),
  output_sha256: Digest(),
});

const NullableStringSchema = Type.Union([NonEmptyString(), Type.Null()]);
const NullablePathSchema = Type.Union([PathString(), Type.Null()]);
const NullableSafeIntegerSchema = Type.Union([
  Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  Type.Null(),
]);
const GitObjectIdSchema = Type.String({ pattern: "^[0-9a-f]{40,64}$" });
const GitModeSchema = Type.String({ pattern: "^[0-7]{6}$" });
const NullableGitObjectIdSchema = Type.Union([GitObjectIdSchema, Type.Null()]);
const NullableGitModeSchema = Type.Union([GitModeSchema, Type.Null()]);

export const M3WorktreeEntrySchema = StrictObject({
  path: PathString(),
  head: NullableGitObjectIdSchema,
  branch: NullableStringSchema,
  detached: Type.Boolean(),
  locked_reason: NullableStringSchema,
  prunable_reason: NullableStringSchema,
});

export const M3PartialCloneSchema = StrictObject({
  promisor_remote: NullableStringSchema,
  filters: Type.Array(NonEmptyString(4096), { maxItems: 1024, uniqueItems: true }),
});

export const M3SubmoduleEntrySchema = StrictObject({
  path: PathString(),
  state: StringEnum(["CLEAN", "MODIFIED", "UNINITIALIZED", "CONFLICT"] as const),
  head: GitObjectIdSchema,
  description: NonEmptyString(4096),
});

export const M3RepositoryIdentitySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_repository_identity_v0"),
    requested_path: PathString(),
    physical_requested_path: PathString(),
    worktree_root: PathString(),
    git_toplevel: PathString(),
    git_common_dir: PathString(),
    git_dir: PathString(),
    worktree_git_dir: PathString(),
    branch: NullableStringSchema,
    detached: Type.Boolean(),
    head: GitObjectIdSchema,
    head_tree: GitObjectIdSchema,
    upstream_ref: NullableStringSchema,
    ahead: NullableSafeIntegerSchema,
    behind: NullableSafeIntegerSchema,
    worktrees: Type.Array(M3WorktreeEntrySchema, { minItems: 1, maxItems: 1024 }),
    worktree_list_sha256: Digest(),
    shallow: Type.Boolean(),
    partial_clone: M3PartialCloneSchema,
    submodules: Type.Array(M3SubmoduleEntrySchema, { maxItems: 10_000 }),
    submodule_state_sha256: Digest(),
    git_version: NonEmptyString(255),
    worktree_key: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_repository_identity_v0.schema.json" },
);

export const M3StagedEntrySchema = StrictObject({
  path: PathString(),
  old_path: NullablePathSchema,
  status: NonEmptyString(8),
  head_mode: GitModeSchema,
  index_mode: GitModeSchema,
  worktree_mode: GitModeSchema,
  head_object: GitObjectIdSchema,
  index_object: GitObjectIdSchema,
});

export const M3WorktreeEntryStateSchema = StrictObject({
  path: PathString(),
  old_path: NullablePathSchema,
  status: NonEmptyString(8),
  state: StringEnum(["PRESENT", "DELETED"] as const),
  file_type: StringEnum(["REGULAR", "DELETED"] as const),
  mode: NullableSafeIntegerSchema,
  size: NullableSafeIntegerSchema,
  content_sha256: NullableDigest(),
});

export const M3UntrackedEntrySchema = StrictObject({
  path: PathString(),
  file_type: Type.Literal("REGULAR"),
  mode: Type.Integer({ minimum: 0, maximum: 4095 }),
  size: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  content_sha256: Digest(),
});

export const M3ConflictEntrySchema = StrictObject({
  path: PathString(),
  status: NonEmptyString(8),
  stage1_mode: GitModeSchema,
  stage2_mode: GitModeSchema,
  stage3_mode: GitModeSchema,
  worktree_mode: GitModeSchema,
  stage1_object: GitObjectIdSchema,
  stage2_object: GitObjectIdSchema,
  stage3_object: GitObjectIdSchema,
});

export const M3GitStateFingerprintSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_git_state_fingerprint_v0"),
    repository_identity_content_sha256: Digest(),
    branch: NullableStringSchema,
    detached: Type.Boolean(),
    head: GitObjectIdSchema,
    head_tree: GitObjectIdSchema,
    upstream_ref: NullableStringSchema,
    ahead: NullableSafeIntegerSchema,
    behind: NullableSafeIntegerSchema,
    porcelain_v2_sha256: Digest(),
    index_sha256: Digest(),
    staged_diff_sha256: Digest(),
    unstaged_diff_sha256: Digest(),
    untracked_inventory_sha256: Digest(),
    staged: Type.Array(M3StagedEntrySchema, { maxItems: 100_000 }),
    unstaged: Type.Array(M3WorktreeEntryStateSchema, { maxItems: 100_000 }),
    untracked: Type.Array(M3UntrackedEntrySchema, { maxItems: 100_000 }),
    conflicts: Type.Array(M3ConflictEntrySchema, { maxItems: 100_000 }),
    submodule_state_sha256: Digest(),
    worktree_list_sha256: Digest(),
    active_operations: Type.Array(
      StringEnum(["MERGE", "REBASE", "CHERRY_PICK", "REVERT", "BISECT"] as const),
      { maxItems: 5, uniqueItems: true },
    ),
    index_lock: Type.Boolean(),
    dirty: Type.Boolean(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_git_state_fingerprint_v0.schema.json" },
);

export const M3FingerprintFileEntrySchema = StrictObject({
  path: PathString(),
  real_path: PathString(),
  mode: Type.Integer({ minimum: 0, maximum: 4095 }),
  size: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  content_sha256: Digest(),
});

export const M3FileSetFingerprintSchema = StrictObject({
  entries: Type.Array(M3FingerprintFileEntrySchema, { maxItems: 10_000 }),
  content_sha256: Digest(),
});

export const M3BlobMetadataSchema = StrictObject({
  blob_sha256: Digest(),
  byte_length: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  relative_path: PathString(),
});

export const M3BaselinePathSchema = StrictObject({
  path: PathString(),
  ownership_class: StringEnum([
    "OWNER_AUTHORITY",
    "OWNER_ACCEPTED_MUTABLE",
    "PREEXISTING_UNRELATED",
    "GENERATED_ACCEPTED_BASELINE",
  ] as const),
  data_class: StringEnum([
    "PUBLIC_SOURCE",
    "PRIVATE_SOURCE",
    "SENSITIVE",
    "SECRET",
    "LARGE_BINARY",
    "HASH_ONLY",
  ] as const),
  capture_mode: StringEnum(["HASH_ONLY", "BLOB"] as const),
  explicit_blob_approval: Type.Boolean(),
  retention_days_after_terminal: Type.Union([Type.Integer({ minimum: 1, maximum: 30 }), Type.Null()]),
  content_sha256: Digest(),
  file_type: StringEnum(["REGULAR", "DELETED"] as const),
  mode: NullableSafeIntegerSchema,
  size: NullableSafeIntegerSchema,
  status_sha256: Digest(),
  blob: Type.Union([M3BlobMetadataSchema, Type.Null()]),
});

export const M3BlobQuotaSchema = StrictObject({
  logical_approved_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  physical_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  deduplicated_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  existing_physical_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  new_unique_physical_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  resulting_physical_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
});

export const M3BaselineRuntimeSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_baseline_runtime_v0"),
    run_id: RunId(),
    baseline_mode: StringEnum(["CLEAN_REQUIRED", "APPROVED_BASELINE_DIRTY"] as const),
    repository: Type.Ref(M3RepositoryIdentitySchema),
    git_fingerprint: Type.Ref(M3GitStateFingerprintSchema),
    accepted_baseline: Type.Ref(BaselineSchema),
    instruction_fingerprint: M3FileSetFingerprintSchema,
    authority_fingerprint: M3FileSetFingerprintSchema,
    paths: Type.Array(M3BaselinePathSchema, { maxItems: 100_000 }),
    blob_quota: M3BlobQuotaSchema,
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_baseline_runtime_v0.schema.json" },
);

export const M3BaselineApprovalRuntimeSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_baseline_approval_runtime_v0"),
    run_id: RunId(),
    baseline_runtime_content_sha256: Digest(),
    baseline_snapshot_sha256: Digest(),
    baseline_snapshot_content_sha256: Digest(),
    accepted_approval: Type.Ref(BaselineApprovalSchema),
    approved_by: NonEmptyString(1024),
    approved_at: NonEmptyString(64),
    approval_scope: Type.Literal("EXACT_BASELINE"),
    decisions: Type.Array(M3BaselinePathSchema, { maxItems: 100_000 }),
    decisions_sha256: Digest(),
    retention_sha256: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_baseline_approval_runtime_v0.schema.json" },
);

export const M3LockAcquisitionSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_lock_acquisition_v0"),
    state_root: PathString(),
    protocol_version: Type.Literal("flock-guardian-v1"),
    worktree_key: Digest(),
    worktree_root: PathString(),
    git_common_dir: PathString(),
    lock_path: PathString(),
    owner_marker_path: PathString(),
    guardian_python_invocation_path: PathString(),
    guardian_python_realpath: PathString(),
    guardian_python_version: NonEmptyString(255),
    guardian_helper_path: PathString(),
    guardian_helper_realpath: PathString(),
    guardian_helper_sha256: Digest(),
    controller_pid: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    guardian_pid: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    acquired_at: NonEmptyString(64),
    acquisition_nonce: NonEmptyString(64),
    guardian_ready_sha256: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_lock_acquisition_v0.schema.json" },
);

export const M3LockDiagnosticSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_lock_diagnostic_v0"),
    lock_acquisition_content_sha256: Digest(),
    state_root: PathString(),
    protocol_version: Type.Literal("flock-guardian-v1"),
    worktree_key: Digest(),
    worktree_root: PathString(),
    git_common_dir: PathString(),
    lock_path: PathString(),
    owner_marker_path: PathString(),
    guardian_python_invocation_path: PathString(),
    guardian_python_realpath: PathString(),
    guardian_python_path: PathString(),
    guardian_python_version: NonEmptyString(255),
    guardian_helper_path: PathString(),
    guardian_helper_realpath: PathString(),
    guardian_helper_sha256: Digest(),
    controller_pid: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    guardian_pid: Type.Integer({ minimum: 1, maximum: 2_147_483_647 }),
    acquired_at: NonEmptyString(64),
    acquisition_nonce: NonEmptyString(64),
    guardian_ready_sha256: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_lock_diagnostic_v0.schema.json" },
);

export const M3EnvironmentFingerprintSchema = StrictObject({
  node_version: NonEmptyString(255),
  git_version: NonEmptyString(255),
  python_version: NonEmptyString(255),
  controller_version: Type.Literal("0.1.0"),
  node_path: PathString(),
  git_path: PathString(),
  python_path: PathString(),
  guardian_helper_path: PathString(),
  guardian_helper_sha256: Digest(),
  content_sha256: Digest(),
});

export const M3PreflightSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_preflight_v0"),
    preflight_kind: StringEnum(["FULL", "FAST"] as const),
    run_id: RunId(),
    prior_token_content_sha256: NullableDigest(),
    repository: Type.Ref(M3RepositoryIdentitySchema),
    worktree_key: Digest(),
    lock_diagnostic_content_sha256: Digest(),
    baseline_runtime_content_sha256: Digest(),
    baseline_snapshot_sha256: Digest(),
    baseline_approval_runtime_content_sha256: NullableDigest(),
    git_fingerprint: Type.Ref(M3GitStateFingerprintSchema),
    instruction_fingerprint: M3FileSetFingerprintSchema,
    authority_fingerprint: M3FileSetFingerprintSchema,
    environment_fingerprint: M3EnvironmentFingerprintSchema,
    task_scope_identity: Digest(),
    result: Type.Literal("PASS"),
    blockers: Type.Array(NonEmptyString(255), { maxItems: 0 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_preflight_v0.schema.json" },
);

export const M3RepositoryStateTokenSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_repository_state_token_v0"),
    source: StringEnum(["FULL_PREFLIGHT", "POSTFLIGHT"] as const),
    source_content_sha256: Digest(),
    prior_token_content_sha256: NullableDigest(),
    run_id: RunId(),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    branch: NullableStringSchema,
    head: GitObjectIdSchema,
    worktree_list_sha256: Digest(),
    git_fingerprint: Type.Ref(M3GitStateFingerprintSchema),
    instruction_fingerprint: M3FileSetFingerprintSchema,
    authority_fingerprint: M3FileSetFingerprintSchema,
    baseline_runtime_content_sha256: Digest(),
    lock_diagnostic_content_sha256: Digest(),
    task_scope_identity: Digest(),
    workflow_owned_delta_sha256: Digest(),
    changed_paths: Type.Array(PathString(), { maxItems: 100_000, uniqueItems: true }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_repository_state_token_v0.schema.json" },
);

export const M3DeltaEntrySchema = StrictObject({
  path: PathString(),
  change_kind: StringEnum(["ADDED", "MODIFIED", "DELETED", "TYPE_CHANGED", "MODE_CHANGED", "BASELINE_REVERTED"] as const),
  before_content_sha256: NullableDigest(),
  after_content_sha256: NullableDigest(),
  before_type: NullableStringSchema,
  after_type: NullableStringSchema,
  before_mode: NullableSafeIntegerSchema,
  after_mode: NullableSafeIntegerSchema,
  staged_status: NullableStringSchema,
  unstaged_status: NullableStringSchema,
  untracked: Type.Boolean(),
});

export const M3ScopeSchema = StrictObject({
  schema_id: Type.Literal("pi_gacw_task_scope_v0"),
  schema_version: Type.Literal("0.1.0"),
  scope_projection_id: Type.Literal("m3-task-scope-v1"),
  editable_paths: Type.Array(PathString(), { maxItems: 10_000, uniqueItems: true }),
  frozen_paths: Type.Array(PathString(), { maxItems: 10_000, uniqueItems: true }),
  scope_identity: Digest(),
});

export const M3PostflightSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_postflight_v0"),
    run_id: RunId(),
    prior_token_content_sha256: Digest(),
    baseline_runtime_content_sha256: Digest(),
    repository: Type.Ref(M3RepositoryIdentitySchema),
    git_fingerprint: Type.Ref(M3GitStateFingerprintSchema),
    repository_git_delta: Type.Array(M3DeltaEntrySchema, { maxItems: 100_000 }),
    workflow_owned_delta: Type.Array(M3DeltaEntrySchema, { maxItems: 100_000 }),
    claimed_workflow_paths: Type.Array(PathString(), { maxItems: 100_000, uniqueItems: true }),
    scope: M3ScopeSchema,
    lock_diagnostic_content_sha256: Digest(),
    result: Type.Literal("PASS"),
    blockers: Type.Array(NonEmptyString(255), { maxItems: 0 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_postflight_v0.schema.json" },
);

export const M3RetentionBlobAuthoritySchema = StrictObject({
  baseline_path: PathString(),
  blob_sha256: Digest(),
  byte_length: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  relative_path: PathString(),
  data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE"] as const),
  retention_deadline: NonEmptyString(64),
});

export const M3TerminalRetentionAuthoritySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_terminal_retention_authority_v0"),
    run_id: RunId(),
    baseline_runtime_content_sha256: Digest(),
    baseline_approval_runtime_content_sha256: NullableDigest(),
    repository_identity_content_sha256: Digest(),
    terminal_workflow_state_content_sha256: Digest(),
    terminal_timestamp: NonEmptyString(64),
    worktree_key: Digest(),
    blobs: Type.Array(M3RetentionBlobAuthoritySchema, { maxItems: 100_000 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_terminal_retention_authority_v0.schema.json" },
);

export const M3RetentionLogicalReferenceSchema = StrictObject({
  baseline_runtime_content_sha256: Digest(),
  baseline_approval_runtime_content_sha256: NullableDigest(),
  terminal_authority_content_sha256: Digest(),
  terminal_workflow_state_content_sha256: Digest(),
  repository_identity_content_sha256: Digest(),
  worktree_key: Digest(),
  baseline_path: PathString(),
  blob_sha256: Digest(),
  byte_length: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  relative_path: PathString(),
  data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE"] as const),
  retention_deadline: NonEmptyString(64),
});

export const M3RetentionBlobResultSchema = StrictObject({
  blob_sha256: Digest(),
  byte_length: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  relative_path: PathString(),
  data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE"] as const),
  retention_deadline: NonEmptyString(64),
  logical_references: Type.Array(M3RetentionLogicalReferenceSchema, { minItems: 1, maxItems: 100_000 }),
  uncovered_references: Type.Array(StrictObject({
    baseline_runtime_content_sha256: Digest(),
    baseline_path: PathString(),
  }), { maxItems: 100_000 }),
  prior_successful_result_content_sha256: NullableDigest(),
  status: StringEnum(["ELIGIBLE", "DEADLINE_PENDING", "DELETED", "ALREADY_REMOVED", "MISSING", "MISMATCH", "ERROR"] as const),
  result: StringEnum(["ELIGIBLE", "REFUSED", "SUCCEEDED", "FAILED", "IDEMPOTENT"] as const),
  detail_code: NullableStringSchema,
  unlink_performed: Type.Boolean(),
  directory_fsync_performed: Type.Boolean(),
});

export const M3RetentionResultSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_retention_result_v0"),
    operation: StringEnum(["INSPECT", "CLEANUP"] as const),
    run_id: RunId(),
    terminal_authority_content_sha256: Digest(),
    terminal_workflow_state_content_sha256: Digest(),
    baseline_runtime_content_sha256: Digest(),
    baseline_approval_runtime_content_sha256: NullableDigest(),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    evaluated_at: NonEmptyString(64),
    logical_target_count: Type.Integer({ minimum: 0, maximum: 100_000 }),
    physical_target_count: Type.Integer({ minimum: 0, maximum: 100_000 }),
    outcome: StringEnum(["ELIGIBLE", "REFUSED", "COMPLETE", "PARTIAL", "IDEMPOTENT", "FAILED"] as const),
    blobs: Type.Array(M3RetentionBlobResultSchema, { maxItems: 100_000 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_retention_result_v0.schema.json" },
);

export const M4PathRuleSchema = StrictObject({
  path: PathString(),
  kind: StringEnum(["EXACT", "PREFIX"] as const),
});

export const M4PathAuthoritySchema = StrictObject({
  path: PathString(),
  kind: StringEnum(["EXACT", "PREFIX"] as const),
  ownership_class: StringEnum(["OWNER_AUTHORITY", "OWNER_ACCEPTED_MUTABLE", "PREEXISTING_UNRELATED", "GENERATED_ACCEPTED_BASELINE"] as const),
  data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE", "SECRET", "LARGE_BINARY", "HASH_ONLY"] as const),
  raw_read_approved: Type.Boolean(),
  create: Type.Boolean(),
  replace: Type.Boolean(),
  delete: Type.Boolean(),
  mode_change: Type.Boolean(),
});

export const M4LimitsSchema = StrictObject({
  maximum_patch_bytes: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  maximum_read_bytes: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  maximum_hash_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  maximum_search_input_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  maximum_search_matches: Type.Integer({ minimum: 0, maximum: 10_000 }),
  maximum_list_entries: Type.Integer({ minimum: 0, maximum: 100_000 }),
  maximum_list_metadata_bytes: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  maximum_command_stdout_bytes: Type.Integer({ minimum: 0, maximum: 4_194_304 }),
  maximum_command_stderr_bytes: Type.Integer({ minimum: 0, maximum: 4_194_304 }),
  maximum_command_duration_ms: Type.Integer({ minimum: 1, maximum: 1_800_000 }),
});

export const M4SecureFilesystemCapabilitySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_secure_fs_capability_v0"),
    capability_protocol: Type.Literal("secure-fs-capability-v1"),
    probed_at: NonEmptyString(64),
    probe_evidence_sha256: Digest(),
    helper_protocol_version: Type.Literal("pi-gacw-secure-fs-v1"),
    helper_invocation_path: PathString(),
    helper_realpath: PathString(),
    helper_sha256: Digest(),
    python_invocation_path: PathString(),
    python_realpath: PathString(),
    python_sha256: Digest(),
    python_version: NonEmptyString(255),
    kernel_release: NonEmptyString(255),
    architecture: NonEmptyString(255),
    libc_identity: NonEmptyString(1024),
    openat2_available: Type.Boolean(),
    supported_resolve_flags: Type.Array(StringEnum(["RESOLVE_BENEATH", "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_MAGICLINKS"] as const), { uniqueItems: true, maxItems: 3 }),
    renameat2_available: Type.Boolean(),
    rename_noreplace_available: Type.Boolean(),
    rename_exchange_available: Type.Boolean(),
    directory_fsync_available: Type.Boolean(),
    landlock_available: Type.Boolean(),
    landlock_abi: Type.Union([Type.Integer({ minimum: 1, maximum: 255 }), Type.Null()]),
    no_new_privs_available: Type.Boolean(),
    network_denial_available: Type.Boolean(),
    secure_fs_result: StringEnum(["SECURE_FS_AVAILABLE", "SECURE_FS_UNAVAILABLE"] as const),
    command_sandbox_result: StringEnum(["COMMAND_SANDBOX_AVAILABLE", "COMMAND_SANDBOX_UNAVAILABLE"] as const),
    network_sandbox_result: StringEnum(["NETWORK_SANDBOX_AVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE"] as const),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_secure_fs_capability_v0.schema.json" },
);

export const M4SandboxCapabilitySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_sandbox_capability_v0"),
    capability_protocol: Type.Literal("command-sandbox-capability-v1"),
    probed_at: NonEmptyString(64),
    probe_evidence_sha256: Digest(),
    helper_protocol_version: Type.Literal("pi-gacw-command-sandbox-v1"),
    helper_invocation_path: PathString(),
    helper_realpath: PathString(),
    helper_sha256: Digest(),
    python_invocation_path: PathString(),
    python_realpath: PathString(),
    python_sha256: Digest(),
    python_version: NonEmptyString(255),
    landlock_available: Type.Boolean(),
    landlock_abi: Type.Union([Type.Integer({ minimum: 1, maximum: 255 }), Type.Null()]),
    filesystem_restrictions: Type.Boolean(),
    child_inheritance: Type.Boolean(),
    no_new_privs: Type.Boolean(),
    seccomp_available: Type.Boolean(),
    network_denial: Type.Boolean(),
    result: StringEnum(["COMMAND_SANDBOX_AVAILABLE", "COMMAND_SANDBOX_UNAVAILABLE"] as const),
    network_result: StringEnum(["NETWORK_SANDBOX_AVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE"] as const),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_sandbox_capability_v0.schema.json" },
);

export const M4ScopedToolPolicySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_scoped_tool_policy_v0"),
    run_id: RunId(),
    policy_id: Identifier(),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    task_scope_identity: Digest(),
    readable_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
    editable_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
    frozen_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
    command_readable_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
    command_writable_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
    path_authorities: Type.Array(M4PathAuthoritySchema, { maxItems: 100_000 }),
    evidence_readable_kinds: Type.Array(NonEmptyString(128), { uniqueItems: true, maxItems: 128 }),
    limits: M4LimitsSchema,
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_scoped_tool_policy_v0.schema.json" },
);

export const M4CommandEnvironmentEntrySchema = StrictObject({ key: NonEmptyString(255), value: Type.String({ maxLength: 16_384 }) });
export const M4ExecutionInputSchema = StrictObject({
  path: PathString(),
  realpath: PathString(),
  device: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  inode: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  mode: Type.Integer({ minimum: 0, maximum: 0o7777 }),
  size: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  digest: Digest(),
});
export const M4CommandSpecificationSchema = StrictObject({
  command_id: Identifier(),
  command_spec_sha256: Digest(),
  command_class: StringEnum(["INSPECTION", "TASK", "VERIFICATION"] as const),
  executable_invocation_path: PathString(),
  executable_realpath: PathString(),
  executable_device: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  executable_inode: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  executable_mode: Type.Integer({ minimum: 0, maximum: 0o7777 }),
  executable_size: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
  executable_sha256: Digest(),
  argv: Type.Array(NonEmptyString(4096), { minItems: 1, maxItems: 128 }),
  cwd: Type.Union([Type.Literal("REPOSITORY_ROOT"), PathString()]),
  cwd_realpath: PathString(),
  cwd_device: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  cwd_inode: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
  execution_inputs: Type.Array(M4ExecutionInputSchema, { maxItems: 128 }),
  environment: Type.Array(M4CommandEnvironmentEntrySchema, { uniqueItems: true, maxItems: 256 }),
  read_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
  write_paths: Type.Array(M4PathRuleSchema, { maxItems: 10_000 }),
  network_policy: Type.Literal("FORBIDDEN"),
  timeout_ms: Type.Integer({ minimum: 1, maximum: 1_800_000 }),
  stdout_limit: Type.Integer({ minimum: 0, maximum: 4_194_304 }),
  stderr_limit: Type.Integer({ minimum: 0, maximum: 4_194_304 }),
  expected_exit_codes: Type.Array(Type.Integer({ minimum: 0, maximum: 255 }), { minItems: 1, uniqueItems: true, maxItems: 256 }),
  repository_side_effect: StringEnum(["NONE", "EXACT_PATHS", "GENERATED_ONLY"] as const),
  claimed_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 100_000 }),
  cleanup_paths: Type.Array(PathString(), { uniqueItems: true, maxItems: 100_000 }),
});

export const M4CommandCatalogSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_command_catalog_v0"),
    run_id: RunId(),
    catalog_id: Identifier(),
    repository_identity_content_sha256: Digest(),
    tool_policy_content_sha256: Digest(),
    commands: Type.Array(M4CommandSpecificationSchema, { maxItems: 10_000 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_command_catalog_v0.schema.json" },
);

export const M4ToolRequestSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_tool_request_v0"),
    run_id: RunId(),
    request_kind: StringEnum(["READ", "LIST", "SEARCH", "INSPECT_GIT", "READ_EVIDENCE", "COMMAND"] as const),
    requested_at: NonEmptyString(64),
    state_token_content_sha256: Digest(),
    tool_policy_content_sha256: Digest(),
    task_scope_identity: Digest(),
    path: Type.Union([PathString(), Type.Null()]),
    command_id: Type.Union([Identifier(), Type.Null()]),
    secure_fs_capability_content_sha256: NullableDigest(),
    sandbox_capability_content_sha256: NullableDigest(),
    command_catalog_content_sha256: NullableDigest(),
    command_spec_sha256: NullableDigest(),
    request_metadata_sha256: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_tool_request_v0.schema.json" },
);

export const M4PatchRequestSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_patch_request_v0"),
    run_id: RunId(),
    requested_at: NonEmptyString(64),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    lock_acquisition_content_sha256: Digest(),
    prior_state_token_content_sha256: Digest(),
    task_scope_identity: Digest(),
    tool_policy_content_sha256: Digest(),
    secure_fs_capability_content_sha256: Digest(),
    operation: StringEnum(["CREATE", "REPLACE", "DELETE"] as const),
    path: PathString(),
    ownership_class: StringEnum(["OWNER_AUTHORITY", "OWNER_ACCEPTED_MUTABLE", "PREEXISTING_UNRELATED", "GENERATED_ACCEPTED_BASELINE"] as const),
    data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE", "SECRET", "LARGE_BINARY", "HASH_ONLY"] as const),
    expected_preimage_exists: Type.Boolean(),
    expected_preimage_digest: NullableDigest(),
    expected_preimage_size: NullableSafeIntegerSchema,
    expected_preimage_mode: NullableSafeIntegerSchema,
    replacement_digest: NullableDigest(),
    replacement_byte_count: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
    requested_final_mode: NullableSafeIntegerSchema,
    patch_format_identity: Type.Literal("exact-bytes-v1"),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_patch_request_v0.schema.json" },
);

export const M4FileMetadataSchema = StrictObject({
  digest: NullableDigest(), size: NullableSafeIntegerSchema, mode: NullableSafeIntegerSchema,
});

export const M4MutationJournalSchema = StrictObject({
  temporary_file_created: Type.Boolean(),
  temporary_bytes_written: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
  temporary_file_fsync_attempted: Type.Boolean(),
  temporary_file_fsync_completed: Type.Boolean(),
  atomic_operation: StringEnum(["NONE", "RENAME_NOREPLACE", "RENAME_EXCHANGE", "TOMBSTONE_NOREPLACE"] as const),
  atomic_rename_attempted: Type.Boolean(),
  atomic_rename_completed: Type.Boolean(),
  directory_fsync_attempt_count: Type.Integer({ minimum: 0, maximum: 8 }),
  directory_fsync_completed_count: Type.Integer({ minimum: 0, maximum: 8 }),
  preimage_validation: StringEnum(["NOT_RUN", "PASS", "FAIL"] as const),
  rollback_required: Type.Boolean(),
  rollback_attempted: Type.Boolean(),
  rollback_completed: Type.Boolean(),
  rollback_directory_fsync_completed: Type.Boolean(),
  final_verification: StringEnum(["NOT_RUN", "PASS", "FAIL"] as const),
  operation_nonce: Type.Optional(Type.Union([Type.String({ pattern: "^[0-9a-f]{32}$" }), Type.Null()])),
  temporary_device: Type.Optional(NullableSafeIntegerSchema),
  temporary_inode: Type.Optional(NullableSafeIntegerSchema),
  temporary_nlink: Type.Optional(NullableSafeIntegerSchema),
  tombstone_created: Type.Optional(Type.Boolean()),
  tombstone_device: Type.Optional(NullableSafeIntegerSchema),
  tombstone_inode: Type.Optional(NullableSafeIntegerSchema),
  tombstone_nlink: Type.Optional(NullableSafeIntegerSchema),
  preimage_device: Type.Optional(NullableSafeIntegerSchema),
  preimage_inode: Type.Optional(NullableSafeIntegerSchema),
  preimage_nlink: Type.Optional(NullableSafeIntegerSchema),
  recovery_attempted: Type.Optional(Type.Boolean()),
  recovery_outcome: Type.Optional(StringEnum(["NOT_RUN", "SUCCEEDED", "FAILED", "IDENTITY_MISMATCH"] as const)),
  recovery_residue_count: Type.Optional(NullableSafeIntegerSchema),
  recovery_target_verification: Type.Optional(StringEnum(["NOT_RUN", "ABSENT", "PREIMAGE", "REPLACEMENT", "MISMATCH", "UNKNOWN"] as const)),
  recovery_directory_fsync: Type.Optional(StringEnum(["NOT_RUN", "SUCCEEDED", "FAILED"] as const)),
  recovery_helper_sha256: Type.Optional(NullableDigest()),
});

export const M4MutationReceiptSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_mutation_receipt_v0"),
    run_id: RunId(),
    request_content_sha256: Digest(),
    operation: StringEnum(["CREATE", "REPLACE", "DELETE"] as const),
    path: PathString(),
    before: M4FileMetadataSchema,
    after: M4FileMetadataSchema,
    secure_fs_capability_content_sha256: Digest(),
    lock_acquisition_content_sha256: Digest(),
    prior_state_token_content_sha256: Digest(),
    successor_state_token_content_sha256: NullableDigest(),
    task_scope_identity: Digest(),
    tool_policy_content_sha256: Digest(),
    outcome: StringEnum(["APPLIED", "PREIMAGE_MISMATCH", "BLOCKED", "UNCERTAIN"] as const),
    helper_outcome: StringEnum(["APPLIED", "BLOCKED", "UNCERTAIN", "BLOCKED_AFTER_WRITE"] as const),
    file_fsync: Type.Boolean(),
    atomic_rename: Type.Boolean(),
    directory_fsync: Type.Boolean(),
    rollback_outcome: StringEnum(["NOT_REQUIRED", "SUCCEEDED", "FAILED", "UNKNOWN"] as const),
    postflight_content_sha256: NullableDigest(),
    failure_code: Type.Union([NonEmptyString(128), Type.Null()]),
    helper_journal: Type.Union([M4MutationJournalSchema, Type.Null()]),
    completed_at: NonEmptyString(64),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_mutation_receipt_v0.schema.json" },
);

export const M4ToolResultSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_tool_result_v0"),
    run_id: RunId(),
    request_content_sha256: Digest(),
    result_kind: StringEnum(["READ", "LIST", "SEARCH", "INSPECT_GIT", "READ_EVIDENCE"] as const),
    state_token_content_sha256: Digest(),
    path: Type.Union([PathString(), Type.Null()]),
    data_class: Type.Union([StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE", "SECRET", "LARGE_BINARY", "HASH_ONLY"] as const), Type.Null()]),
    content_digest: NullableDigest(),
    byte_count: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
    item_count: Type.Integer({ minimum: 0, maximum: 100_000 }),
    output_digest: Digest(),
    outcome: StringEnum(["RAW", "METADATA_ONLY", "PASS"] as const),
    completed_at: NonEmptyString(64),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_tool_result_v0.schema.json" },
);

export const M4CommandResultSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_command_result_v0"),
    run_id: RunId(),
    request_content_sha256: Digest(),
    command_catalog_content_sha256: Digest(),
    command_spec_sha256: Digest(),
    command_id: Identifier(),
    command_class: StringEnum(["INSPECTION", "TASK", "VERIFICATION"] as const),
    state_token_before: Digest(),
    state_token_after: NullableDigest(),
    sandbox_capability_content_sha256: Digest(),
    executable_sha256: Digest(),
    argv_identity: Digest(),
    cwd: PathString(),
    environment_identity: Digest(),
    started_at: NonEmptyString(64),
    ended_at: NonEmptyString(64),
    exit_code: Type.Union([Type.Integer({ minimum: 0, maximum: 255 }), Type.Null()]),
    signal: Type.Union([NonEmptyString(64), Type.Null()]),
    stdout_digest: Digest(),
    stdout_byte_count: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
    stdout_observed_digest: NullableDigest(),
    stdout_observed_byte_count: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
    stdout_overflowed: Type.Boolean(),
    stdout_stream_complete: Type.Boolean(),
    stderr_digest: Digest(),
    stderr_byte_count: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
    stderr_observed_digest: NullableDigest(),
    stderr_observed_byte_count: Type.Integer({ minimum: 0, maximum: 67_108_864 }),
    stderr_overflowed: Type.Boolean(),
    stderr_stream_complete: Type.Boolean(),
    repository_delta: Type.Array(M3DeltaEntrySchema, { maxItems: 100_000 }),
    postflight_content_sha256: NullableDigest(),
    failure_code: Type.Union([StringEnum(["COMMAND_FORBIDDEN", "GENERIC_DISPATCHER_FORBIDDEN", "COMMAND_SPEC_MISMATCH", "EXECUTION_INPUT_DRIFT", "COMMAND_CWD_IDENTITY_DRIFT", "HARDLINK_WRITE_SCOPE_UNSAFE", "COMMAND_SANDBOX_UNAVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE", "COMMAND_TIMEOUT", "COMMAND_OUTPUT_LIMIT", "COMMAND_SIGNALLED", "COMMAND_EXIT_CODE_UNEXPECTED", "COMMAND_UNEXPECTED_REPOSITORY_DELTA"] as const), Type.Null()]),
    outcome: StringEnum(["PASS", "BLOCKED"] as const),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_command_result_v0.schema.json" },
);

export const M5_BUDGET_DIMENSIONS = [
  "WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL",
  "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS",
] as const;
export const M5_OPERATION_KINDS = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL"] as const;
export const M5_PROGRESS_KINDS = [
  "STATE_TRANSITION", "APPROVED_PLAN_REVISION", "VALID_REPOSITORY_DELTA", "NEW_TEST_EVIDENCE",
  "EVIDENCE_BACKED_DIAGNOSIS", "FAILURE_RECLASSIFICATION", "CONTEXT_RESTORATION", "TERMINAL_RESULT",
] as const;
export const M5_NO_PROGRESS_REASONS = [
  "IDENTICAL_REPORT", "SAME_NORMALIZED_FAILURE_WITH_NO_DELTA", "REPEATED_TEST_WITH_NO_NEW_EVIDENCE",
  "OUT_OF_SCOPE_PATCH", "PROSE_WITHOUT_EVIDENCE",
] as const;
export const M5_FAILURE_CLASSES = [
  "TRANSIENT_TOOL_FAILURE", "LOCAL_IMPLEMENTATION_DEFECT", "COMMAND_CONTRACT_ERROR", "CONTEXT_MISSING",
  "PLAN_INCORRECT", "AUTHORITY_CONTRADICTION", "SCOPE_EXPANSION_REQUIRED", "STATE_DRIFT",
  "CONCURRENT_WRITER", "TEST_INTEGRITY_VIOLATION", "CLEANUP_UNCERTAIN", "SAME_FAILURE_TWICE",
  "CLOSEOUT_DEFECT", "PROCESS_CRASH", "MODEL_UNAVAILABLE", "BUDGET_EXHAUSTED",
  "CONTRACT_UNSATISFIABLE", "ROUTE_UNAVAILABLE", "CAPABILITY_UNAVAILABLE", "MUTATION_UNCERTAIN",
  "EVIDENCE_INVALID", "EVIDENCE_PUBLICATION_FAILURE", "STATE_PUBLICATION_FAILURE", "INTERNAL_CONTROL_ERROR",
] as const;
export const M5_CONTINUATION_ROUTES = [
  "CONTINUE_ADMITTED_OPERATION", "RETRY_TRANSIENT_TOOL_ONCE", "SECOND_LUNA_ATTEMPT", "CORRECT_COMMAND_ONCE",
  "RESTORE_CONTEXT_ONCE", "CONSTRAINED_REPLAN", "RUN_RESERVED_CLOSEOUT", "REQUEST_OWNER_DECISION", "BLOCK",
] as const;
export const M5_GATE_CODES = [
  "MISSING_DEPENDENCY", "CYCLIC_DEPENDENCY", "MISSING_PRODUCER", "AMBIGUOUS_PRODUCER",
  "FUTURE_STAGE_DEPENDENCY", "REQUIRED_OUTPUT_UNAVAILABLE", "IDENTITY_FORMAT_MISMATCH",
  "OVERLAPPING_WRITE_OWNERSHIP", "ACCEPTANCE_WITHOUT_EVIDENCE", "VERIFICATION_COMMAND_UNAVAILABLE",
  "ROUTE_UNAVAILABLE", "BUDGET_ENVELOPE_INFEASIBLE", "UNSUPPORTED_CONTRACT_CONSTRUCT",
] as const;

const M5BudgetDimensionSchema = StringEnum(M5_BUDGET_DIMENSIONS);
const M5OperationKindSchema = StringEnum(M5_OPERATION_KINDS);
const M5ActualOrNullSchema = Type.Union([Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }), Type.Null()]);
const M5DigestListSchema = Type.Array(Digest(), { uniqueItems: true, maxItems: 100_000 });

export const M5ControlPolicySchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_m5_control_policy_v0"),
    run_id: RunId(),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    starting_state_content_sha256: Digest(),
    objective_sha256: Digest(),
    contract_sha256: Digest(),
    budget_sha256: Digest(),
    route_map_sha256: Digest(),
    route_map_approval_sha256: Digest(),
    reducer_policy_content_sha256: Digest(),
    authority_lock_sha256: Digest(),
    baseline_approval_sha256: Digest(),
    scope_sha256: Digest(),
    acceptance_sha256: Digest(),
    plan_approval_sha256: NullableDigest(),
    task_graph_sha256: NullableDigest(),
    tool_policy_content_sha256: Digest(),
    command_catalog_content_sha256: Digest(),
    route_map_approved: Type.Boolean(),
    production_authority: StringEnum(["OWNER_APPROVED", "TEST_FIXTURE"] as const),
    requested_mode: ExecutionModeSchema,
    route_facts: StrictObject({
      hard_sol_conditions: Type.Array(StringEnum([
        "UNRESOLVED_AUTHORITY", "PUBLIC_INTERFACE", "SECURITY_BOUNDARY", "LIFECYCLE_OR_PROVENANCE",
        "MIGRATION_SEMANTICS", "JUDGMENT_ACCEPTANCE", "INSEPARABLE_HIGH_COUPLING",
      ] as const), { uniqueItems: true, maxItems: 7 }),
      task_count: Type.Integer({ minimum: 0, maximum: 8 }),
      coherent_single_task: Type.Boolean(),
      failure_domain_count: Type.Integer({ minimum: 0, maximum: 8 }),
      deterministic_acceptance: Type.Boolean(),
      ownership_ambiguous: Type.Boolean(),
      leaf_count: Type.Integer({ minimum: 0, maximum: 8 }),
      dag_valid: Type.Boolean(),
      leaves_separable: Type.Boolean(),
      unique_write_ownership: Type.Boolean(),
      leaf_acceptance_machine_checkable: Type.Boolean(),
    }),
    obligations: Type.Array(StrictObject({
      descriptor_sha256: Digest(),
      declaration: NonEmptyString(),
      direction: StringEnum(["INPUT", "OUTPUT"] as const),
      stage: Type.Integer({ minimum: 0, maximum: 1_000_000 }),
      producer: NonEmptyString(128),
      consumers: Type.Array(NonEmptyString(128), { minItems: 1, maxItems: 1024, uniqueItems: true }),
      grammar: StringEnum(["HEX", "UUID", "INTEGER", "LITERAL", "PREFIXED_LITERAL", "PATH"] as const),
      evidence_kind: StringEnum(["COMMAND", "FILE", "DIGEST", "OWNER_ACCEPTANCE", "STATE", "CONTEXT"] as const),
      literal: Type.Union([Type.String({ maxLength: 16_384 }), Type.Null()]),
      prefix: Type.Union([Type.String({ maxLength: 1024 }), Type.Null()]),
    }), { maxItems: 20_000 }),
    limits: Type.Array(StrictObject({
      dimension: M5BudgetDimensionSchema,
      hard_limit: M5ActualOrNullSchema,
      soft_limit: M5ActualOrNullSchema,
      enforcement_class: StringEnum(ENFORCEMENT_CLASSES),
    }), { minItems: 8, maxItems: 8 }),
    role_reservation_envelopes: Type.Array(StrictObject({
      logical_role: LogicalModelRoleSchema,
      purpose: StringEnum(["ORDINARY", "REQUIRED_CLOSEOUT"] as const),
      amounts: Type.Array(StrictObject({ dimension: M5BudgetDimensionSchema, amount: BoundedInteger(Number.MAX_SAFE_INTEGER) }), { maxItems: 8 }),
    }), { maxItems: 16 }),
    failure_action_table_version: Type.Literal("m5-failure-actions-v1"),
    progress_rule_version: Type.Literal("m5-progress-v1"),
    contract_gate_rule_version: Type.Literal("m5-contract-gate-v1"),
    route_selection_rule_version: Type.Literal("m5-route-selection-v1"),
    insufficient_routing_evidence: StringEnum(["SINGLE_OWNER_SOL", "BLOCK"] as const),
    maximum_control_decisions: Type.Integer({ minimum: 1, maximum: 100_000 }),
    maximum_usage_records: Type.Integer({ minimum: 0, maximum: 100_000 }),
    maximum_authority_depth: Type.Integer({ minimum: 1, maximum: 64 }),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_m5_control_policy_v0.schema.json" },
);

export const M5UsageEvidenceSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_m5_usage_evidence_v0"),
    run_id: RunId(),
    policy_content_sha256: Digest(),
    originating_state_content_sha256: Digest(),
    operation_id: Identifier(),
    operation_kind: M5OperationKindSchema,
    execution_mode: Type.Union([ConcreteExecutionModeSchema, Type.Null()]),
    logical_role: Type.Union([LogicalModelRoleSchema, Type.Null()]),
    reservation_decision_content_sha256: NullableDigest(),
    source_layer: StringEnum(["M1", "M2", "M3", "M4", "M5", "CONTROLLER"] as const),
    source_kind: NonEmptyString(128),
    source_record_content_sha256: Digest(),
    measurements: Type.Array(StrictObject({
      dimension: M5BudgetDimensionSchema,
      amount: M5ActualOrNullSchema,
      basis: StringEnum(["VALIDATED", "OBSERVED", "REPORTED", "ESTIMATED", "UNAVAILABLE"] as const),
      enforcement_class: StringEnum(ENFORCEMENT_CLASSES),
    }), { minItems: 1, maxItems: 8 }),
    disposition: StringEnum(["COMPLETED", "NOT_STARTED", "BLOCKED_BEFORE_START", "OUTCOME_UNCERTAIN"] as const),
    duration_ms: M5ActualOrNullSchema,
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_m5_usage_evidence_v0.schema.json" },
);

const M5BudgetSnapshotEntrySchema = StrictObject({
  dimension: M5BudgetDimensionSchema,
  hard_limit: M5ActualOrNullSchema,
  soft_limit: M5ActualOrNullSchema,
  opening_amount: M5ActualOrNullSchema,
  validated_amount: BoundedInteger(Number.MAX_SAFE_INTEGER),
  observed_reported_amount: BoundedInteger(Number.MAX_SAFE_INTEGER),
  estimated_amount: BoundedInteger(Number.MAX_SAFE_INTEGER),
  active_reservation_amount: BoundedInteger(Number.MAX_SAFE_INTEGER),
  reconciled_amount: BoundedInteger(Number.MAX_SAFE_INTEGER),
  effective_charged_amount: BoundedInteger(Number.MAX_SAFE_INTEGER),
  hard_remaining: M5ActualOrNullSchema,
  soft_remaining: M5ActualOrNullSchema,
  enforcement_class: StringEnum(ENFORCEMENT_CLASSES),
  status: StringEnum(["BELOW_SOFT_LIMIT", "SOFT_LIMIT_REACHED", "HARD_LIMIT_REACHED", "UNAVAILABLE"] as const),
});

export const M5ControlDecisionSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_m5_control_decision_v0"),
    run_id: RunId(),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    current_state_content_sha256: Digest(),
    policy_content_sha256: Digest(),
    objective_sha256: Digest(),
    contract_sha256: Digest(),
    budget_sha256: Digest(),
    route_map_sha256: Digest(),
    route_map_approval_sha256: Digest(),
    reducer_policy_content_sha256: Digest(),
    scope_sha256: Digest(),
    acceptance_sha256: Digest(),
    tool_policy_content_sha256: Digest(),
    command_catalog_content_sha256: Digest(),
    usage_set_sha256: Digest(),
    usage_evidence_content_sha256: M5DigestListSchema,
    budget: Type.Array(M5BudgetSnapshotEntrySchema, { minItems: 8, maxItems: 8 }),
    progress: StrictObject({
      classification: StringEnum(["PROGRESS", "NO_PROGRESS"] as const),
      kind: Type.Union([StringEnum(M5_PROGRESS_KINDS), Type.Null()]),
      no_progress_reason: Type.Union([StringEnum(M5_NO_PROGRESS_REASONS), Type.Null()]),
      prior_state_or_decision_content_sha256: NullableDigest(),
      evidence_content_sha256: M5DigestListSchema,
      evidence_set_sha256: Digest(),
      prior_failure_signature: NullableDigest(),
      current_failure_signature: NullableDigest(),
    }),
    failures: Type.Array(StrictObject({
      failure_identity: Digest(),
      source_layer: StringEnum(["M1", "M2", "M3", "M4", "M5", "CONTROLLER"] as const),
      source_error_code: NonEmptyString(128),
      source_record_content_sha256: Digest(),
      normalized_signature: Digest(),
      operation_id: Type.Optional(Identifier()),
      scope_identity: Type.Optional(Digest()),
      path_identity: Type.Optional(Digest()),
      repository_identity: Type.Optional(Digest()),
      worktree_key: Type.Optional(Digest()),
      control_class: StringEnum(M5_FAILURE_CLASSES),
      action: StringEnum(M5_CONTINUATION_ROUTES),
      occurrence_count: Type.Integer({ minimum: 1, maximum: 100_000 }),
      resolution_evidence_content_sha256: NullableDigest(),
    }), { maxItems: 1024 }),
    contract_gate: StrictObject({
      status: StringEnum(["SATISFIED", "SATISFIABLE", "CURRENTLY_BLOCKED", "UNSATISFIABLE", "INSUFFICIENT_AUTHORITY"] as const),
      detections: Type.Array(StrictObject({ code: StringEnum(M5_GATE_CODES), evidence_content_sha256: NullableDigest() }), { maxItems: 13 }),
      satisfied_obligation_descriptor_sha256: M5DigestListSchema,
      pending_obligation_descriptor_sha256: M5DigestListSchema,
    }),
    obligation_evidence: Type.Array(StrictObject({ descriptor_sha256: Digest(), value: NonEmptyString(), evidence_content_sha256: Digest() }), { maxItems: 20_000, uniqueItems: true }),
    available_logical_roles: Type.Array(LogicalModelRoleSchema, { uniqueItems: true, maxItems: 7 }),
    operation_id: Type.Union([Identifier(), Type.Null()]),
    transition_id: Type.Optional(Identifier()),
    decision_kind: StringEnum(["INITIAL_MODE", "CONTINUATION"] as const),
    intent: StringEnum(["VALIDATE_CONTRACT", "SELECT_ROUTE", "AUTHORIZE_WORK", "AUTHORIZE_CONTINUATION", "EVALUATE_TERMINAL", "BLOCK"] as const),
    routes: Type.Array(StrictObject({
      route: StringEnum([...CONCRETE_EXECUTION_MODES, ...M5_CONTINUATION_ROUTES] as const),
      eligibility: StringEnum(["ELIGIBLE", "INELIGIBLE", "MISSING_AUTHORITY"] as const),
      reasons: Type.Array(NonEmptyString(128), { uniqueItems: true, maxItems: 32 }),
    }), { minItems: 3, maxItems: 9 }),
    selected_route: Type.Union([StringEnum([...CONCRETE_EXECUTION_MODES, ...M5_CONTINUATION_ROUTES] as const), Type.Null()]),
    reservation: Type.Union([StrictObject({
      logical_role: LogicalModelRoleSchema,
      purpose: StringEnum(["ORDINARY", "REQUIRED_CLOSEOUT"] as const),
      future_operation_id: Type.Optional(Identifier()),
      reservation_decision_key: Type.Optional(Digest()),
      reserved_state_content_sha256: Type.Optional(Digest()),
      reserved_policy_content_sha256: Type.Optional(Digest()),
      reserved_route: Type.Optional(StringEnum([...CONCRETE_EXECUTION_MODES, ...M5_CONTINUATION_ROUTES] as const)),
      amounts: Type.Array(StrictObject({ dimension: M5BudgetDimensionSchema, amount: BoundedInteger(Number.MAX_SAFE_INTEGER) }), { minItems: 1, maxItems: 8 }),
      source_envelope_index: Type.Integer({ minimum: 0, maximum: 15 }),
      status: StringEnum(["ACTIVE", "RECONCILED", "RELEASED", "OUTCOME_UNCERTAIN"] as const),
      reconciliation_evidence_content_sha256: NullableDigest(),
    }), Type.Null()]),
    outcome: StringEnum(["AUTHORIZE", "PASS", "BLOCK"] as const),
    blocking_reason: Type.Union([NonEmptyString(255), Type.Null()]),
    pass_authority: Type.Boolean(),
    transition_event: Type.Union([Type.Ref(TransitionEventSchema), Type.Null()]),
    predicted_next_state_content_sha256: NullableDigest(),
    prior_relevant_decision_content_sha256: NullableDigest(),
    request_key: Type.Optional(Digest()),
    decision_key: Digest(),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_m5_control_decision_v0.schema.json" },
);

const M6ModuleIdentitySchema = StrictObject({
  specifier: NonEmptyString(255),
  package_name: NonEmptyString(255),
  package_version: NonEmptyString(64),
  registry_integrity: NonEmptyString(512),
  registry_resolved: NonEmptyString(2048),
  resolved_url: NonEmptyString(4096),
  installed_tree_sha256: Digest(),
});

const M6ApprovedResourceSchema = StrictObject({
  path: PathString(),
  content_sha256: Digest(),
  data_class: StringEnum(["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE", "HASH_ONLY"] as const),
});

const M6HardLimitsSchema = StrictObject({
  provider_turns: Type.Integer({ minimum: 1, maximum: 2 }),
  model_turns: Type.Integer({ minimum: 1, maximum: 2 }),
  read_calls: Type.Integer({ minimum: 1, maximum: 1 }),
  tool_calls: Type.Integer({ minimum: 1, maximum: 2 }),
  report_submissions: Type.Integer({ minimum: 1, maximum: 1 }),
  prompt_bytes: Type.Integer({ minimum: 1, maximum: 32_768 }),
  read_bytes: Type.Integer({ minimum: 1, maximum: 65_536 }),
  tool_result_bytes: Type.Integer({ minimum: 1, maximum: 69_632 }),
  report_canonical_bytes: Type.Integer({ minimum: 1, maximum: 4_096 }),
  wall_deadline_ms: Type.Integer({ minimum: 1, maximum: 120_000 }),
});

export const M6WorkerInvocationSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_m6_worker_invocation_v0"),
    invocation_key: Digest(),
    protocol_id: Type.Literal("m6-direct-read-v0"),
    run_id: RunId(),
    revision: BoundedInteger(Number.MAX_SAFE_INTEGER),
    state_pointer_content_sha256: Digest(),
    current_state_content_sha256: Digest(),
    predecessor_state_content_sha256: Digest(),
    transition_commit_content_sha256: Digest(),
    m5_decision_content_sha256: Digest(),
    m5_policy_content_sha256: Digest(),
    m5_reservation_decision_key: NullableDigest(),
    operation_id: Identifier(),
    transition_event_content_sha256: Digest(),
    predicted_next_state_content_sha256: Digest(),
    execution_mode: Type.Literal("DIRECT_LUNA_HIGH"),
    continuation_action: Type.Literal("CONTINUE_ADMITTED_OPERATION"),
    logical_role: Type.Literal("LUNA_EXECUTOR"),
    repository_identity_content_sha256: Digest(),
    worktree_key: Digest(),
    m3_state_token_content_sha256: Digest(),
    m4_tool_policy_content_sha256: Digest(),
    m4_command_catalog_content_sha256: Digest(),
    task_content_sha256: Digest(),
    task_scope_identity: Digest(),
    route_map_sha256: Digest(),
    route_map_approval_sha256: Digest(),
    provider_id: Identifier(),
    model_id: Identifier(),
    effort: Type.Literal("high"),
    runtime_boundary_policy: Type.Literal("OA-M6-02"),
    pi_modules: Type.Array(M6ModuleIdentitySchema, { minItems: 3, maxItems: 3 }),
    approved_resources: Type.Array(M6ApprovedResourceSchema, { maxItems: 10_000 }),
    system_prompt_sha256: Digest(),
    user_prompt_sha256: Digest(),
    read_path: PathString(),
    read_offset: Type.Integer({ minimum: 0, maximum: 65_536 }),
    read_length: Type.Integer({ minimum: 1, maximum: 65_536 }),
    hard_limits: M6HardLimitsSchema,
    attempt_number: Type.Integer({ minimum: 1, maximum: 2 }),
    admitted_at: NonEmptyString(64),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_m6_worker_invocation_v0.schema.json" },
);

const M6WorkerReportSchema = StrictObject({
  status: Type.Literal("COMPLETED"),
  summary: NonEmptyString(2_048),
  evidence_content_sha256: Type.Array(Digest(), { minItems: 1, maxItems: 1, uniqueItems: true }),
});

const M6UsageSummarySchema = StrictObject({
  provider_turns: Type.Integer({ minimum: 0, maximum: 2 }),
  model_turns: Type.Integer({ minimum: 0, maximum: 2 }),
  provider_requests: Type.Union([Type.Integer({ minimum: 0, maximum: 2 }), Type.Null()]),
  tool_calls: Type.Integer({ minimum: 0, maximum: 2 }),
  read_calls: Type.Integer({ minimum: 0, maximum: 1 }),
  report_submissions: Type.Integer({ minimum: 0, maximum: 1 }),
  input_tokens: Type.Union([Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }), Type.Null()]),
  output_tokens: Type.Union([Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }), Type.Null()]),
  cost_microusd: Type.Union([Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }), Type.Null()]),
  wall_time_ms: Type.Union([Type.Integer({ minimum: 0, maximum: 120_000 }), Type.Null()]),
});

const M6SettlementSchema = StrictObject({
  prompt_settled: Type.Boolean(),
  agent_idle: Type.Boolean(),
  pending_tool_calls: Type.Integer({ minimum: 0, maximum: 2 }),
  subscriber_removed: Type.Boolean(),
  queues_empty: Type.Boolean(),
  reset_completed: Type.Boolean(),
  timers_cleared: Type.Boolean(),
  provider_collection_cleared: Type.Boolean(),
  owned_provider_streams: Type.Integer({ minimum: 0, maximum: 1 }),
  owned_child_processes: Type.Integer({ minimum: 0, maximum: 1 }),
  owned_sockets: Type.Integer({ minimum: 0, maximum: 1 }),
  owned_fifos: Type.Integer({ minimum: 0, maximum: 1 }),
  cleanup_certain: Type.Boolean(),
});

export const M6WorkerResultSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_m6_worker_result_v0"),
    invocation_key: Digest(),
    invocation_content_sha256: Digest(),
    run_id: RunId(),
    outcome: Type.Union([Type.Literal("COMPLETED"), Type.Literal("BLOCKED")]),
    provider_work_started: Type.Boolean(),
    first_failure_code: Type.Union([NonEmptyString(128), Type.Null()]),
    first_failure_stage: Type.Union([NonEmptyString(128), Type.Null()]),
    worker_report: Type.Union([M6WorkerReportSchema, Type.Null()]),
    m4_result_content_sha256: NullableDigest(),
    usage: M6UsageSummarySchema,
    settlement: M6SettlementSchema,
    cleanup_failure_code: Type.Union([NonEmptyString(128), Type.Null()]),
    completed_at: NonEmptyString(64),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_m6_worker_result_v0.schema.json" },
);

const BoundedWorkerTelemetrySchema = StrictObject({
  worker_invocations: Type.Integer({ minimum: 0, maximum: 1 }),
  m4_tool_calls: BoundedInteger(Number.MAX_SAFE_INTEGER),
  model_turns: M5ActualOrNullSchema,
  provider_requests: M5ActualOrNullSchema,
  input_tokens: M5ActualOrNullSchema,
  output_tokens: M5ActualOrNullSchema,
  cost_microusd: M5ActualOrNullSchema,
  wall_time_ms: BoundedInteger(Number.MAX_SAFE_INTEGER),
});

/** Durable pre-provider authority for the constrained pre-M8 worker path. */
export const BoundedWorkerInvocationSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_bounded_worker_invocation_v0"),
    invocation_key: Digest(),
    run_id: RunId(),
    operation_id: Identifier(),
    m5_reservation_decision_content_sha256: Digest(),
    m5_reservation_decision_key: Digest(),
    task_content_sha256: NullableDigest(),
    task_graph_sha256: NullableDigest(),
    plan_approval_sha256: NullableDigest(),
    input_m3_state_token_content_sha256: Digest(),
    system_prompt_sha256: Digest(),
    user_prompt_sha256: Digest(),
    created_at: NonEmptyString(64),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_bounded_worker_invocation_v0.schema.json" },
);

/** Durable outcome containing references, observed usage, and no executable authority. */
export const BoundedWorkerResultSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_bounded_worker_result_v0"),
    invocation_content_sha256: Digest(),
    outcome: Type.Union([Type.Literal("COMPLETED"), Type.Literal("BLOCKED")]),
    first_failure_code: Type.Union([NonEmptyString(128), Type.Null()]),
    first_failure_stage: Type.Union([NonEmptyString(128), Type.Null()]),
    m3_evidence_content_sha256: Type.Array(Digest(), { uniqueItems: true, maxItems: 100_000 }),
    m4_evidence_content_sha256: Type.Array(Digest(), { uniqueItems: true, maxItems: 100_000 }),
    actual_usage: BoundedWorkerTelemetrySchema,
    cleanup_certain: Type.Boolean(),
    advisory_report: Type.Union([Type.String({ maxLength: 8_192 }), Type.Null()]),
    completed_at: NonEmptyString(64),
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_bounded_worker_result_v0.schema.json" },
);

export const FinalReportSchema = StrictObject(
  {
    ...DocumentFields("pi_gacw_final_report_v0"),
    final_report_projection_id: Type.Literal("final-report-v1"),
    final_report_sha256: Digest(),
    run_id: Identifier(),
    outcome: StringEnum(["PASS", "BLOCKED"] as const),
    reason: NonEmptyString(),
    objective_sha256: Digest(),
    contract_sha256: Digest(),
    plan_approval_sha256: NullableDigest(),
    final_state_sha256: Digest(),
    command_results: Type.Array(CommandResultSchema, { maxItems: 100_000 }),
    usage: UsageDimensionsSchema,
  },
  { $id: "https://pi-gacw.invalid/schemas/pi_gacw_final_report_v0.schema.json" },
);

const internalSchemaRegistry = [
  { schemaId: "pi_gacw_objective_v0", fileName: "pi_gacw_objective_v0.schema.json", schema: ObjectiveSchema },
  { schemaId: "pi_gacw_owner_decisions_v0", fileName: "pi_gacw_owner_decisions_v0.schema.json", schema: OwnerDecisionsSchema },
  { schemaId: "pi_gacw_route_map_v0", fileName: "pi_gacw_route_map_v0.schema.json", schema: RouteMapSchema },
  { schemaId: "pi_gacw_route_map_approval_v0", fileName: "pi_gacw_route_map_approval_v0.schema.json", schema: RouteMapApprovalSchema },
  { schemaId: "pi_gacw_baseline_v0", fileName: "pi_gacw_baseline_v0.schema.json", schema: BaselineSchema },
  { schemaId: "pi_gacw_baseline_approval_v0", fileName: "pi_gacw_baseline_approval_v0.schema.json", schema: BaselineApprovalSchema },
  { schemaId: "pi_gacw_authority_lock_v0", fileName: "pi_gacw_authority_lock_v0.schema.json", schema: AuthorityLockSchema },
  { schemaId: "pi_gacw_contract_v0", fileName: "pi_gacw_contract_v0.schema.json", schema: ContractSchema },
  { schemaId: "pi_gacw_routing_v0", fileName: "pi_gacw_routing_v0.schema.json", schema: RoutingSchema },
  { schemaId: "pi_gacw_budget_v0", fileName: "pi_gacw_budget_v0.schema.json", schema: BudgetSchema },
  { schemaId: "pi_gacw_task_v0", fileName: "pi_gacw_task_v0.schema.json", schema: TaskSchema },
  { schemaId: "pi_gacw_task_graph_v0", fileName: "pi_gacw_task_graph_v0.schema.json", schema: TaskGraphSchema },
  { schemaId: "pi_gacw_plan_approval_v0", fileName: "pi_gacw_plan_approval_v0.schema.json", schema: PlanApprovalSchema },
  { schemaId: "pi_gacw_state_v0", fileName: "pi_gacw_state_v0.schema.json", schema: WorkflowStateSchema },
  { schemaId: "pi_gacw_transition_event_v0", fileName: "pi_gacw_transition_event_v0.schema.json", schema: TransitionEventSchema },
  { schemaId: "pi_gacw_transition_commit_v0", fileName: "pi_gacw_transition_commit_v0.schema.json", schema: TransitionCommitSchema },
  { schemaId: "pi_gacw_final_report_v0", fileName: "pi_gacw_final_report_v0.schema.json", schema: FinalReportSchema },
  { schemaId: "pi_gacw_reducer_policy_v0", fileName: "pi_gacw_reducer_policy_v0.schema.json", schema: ReducerPolicySchema },
  { schemaId: "pi_gacw_evidence_metadata_v0", fileName: "pi_gacw_evidence_metadata_v0.schema.json", schema: EvidenceMetadataSchema },
  { schemaId: "pi_gacw_evidence_manifest_v0", fileName: "pi_gacw_evidence_manifest_v0.schema.json", schema: EvidenceManifestSchema },
  { schemaId: "pi_gacw_persisted_state_pointer_v0", fileName: "pi_gacw_persisted_state_pointer_v0.schema.json", schema: PersistedStatePointerSchema },
  { schemaId: "pi_gacw_process_interruption_v0", fileName: "pi_gacw_process_interruption_v0.schema.json", schema: ProcessInterruptionSchema },
  { schemaId: "pi_gacw_state_transition_commit_v0", fileName: "pi_gacw_state_transition_commit_v0.schema.json", schema: StateTransitionCommitSchema },
  { schemaId: "pi_gacw_repository_identity_v0", fileName: "pi_gacw_repository_identity_v0.schema.json", schema: M3RepositoryIdentitySchema },
  { schemaId: "pi_gacw_git_state_fingerprint_v0", fileName: "pi_gacw_git_state_fingerprint_v0.schema.json", schema: M3GitStateFingerprintSchema },
  { schemaId: "pi_gacw_baseline_runtime_v0", fileName: "pi_gacw_baseline_runtime_v0.schema.json", schema: M3BaselineRuntimeSchema },
  { schemaId: "pi_gacw_baseline_approval_runtime_v0", fileName: "pi_gacw_baseline_approval_runtime_v0.schema.json", schema: M3BaselineApprovalRuntimeSchema },
  { schemaId: "pi_gacw_lock_acquisition_v0", fileName: "pi_gacw_lock_acquisition_v0.schema.json", schema: M3LockAcquisitionSchema },
  { schemaId: "pi_gacw_lock_diagnostic_v0", fileName: "pi_gacw_lock_diagnostic_v0.schema.json", schema: M3LockDiagnosticSchema },
  { schemaId: "pi_gacw_preflight_v0", fileName: "pi_gacw_preflight_v0.schema.json", schema: M3PreflightSchema },
  { schemaId: "pi_gacw_repository_state_token_v0", fileName: "pi_gacw_repository_state_token_v0.schema.json", schema: M3RepositoryStateTokenSchema },
  { schemaId: "pi_gacw_postflight_v0", fileName: "pi_gacw_postflight_v0.schema.json", schema: M3PostflightSchema },
  { schemaId: "pi_gacw_terminal_retention_authority_v0", fileName: "pi_gacw_terminal_retention_authority_v0.schema.json", schema: M3TerminalRetentionAuthoritySchema },
  { schemaId: "pi_gacw_retention_result_v0", fileName: "pi_gacw_retention_result_v0.schema.json", schema: M3RetentionResultSchema },
  { schemaId: "pi_gacw_secure_fs_capability_v0", fileName: "pi_gacw_secure_fs_capability_v0.schema.json", schema: M4SecureFilesystemCapabilitySchema },
  { schemaId: "pi_gacw_sandbox_capability_v0", fileName: "pi_gacw_sandbox_capability_v0.schema.json", schema: M4SandboxCapabilitySchema },
  { schemaId: "pi_gacw_scoped_tool_policy_v0", fileName: "pi_gacw_scoped_tool_policy_v0.schema.json", schema: M4ScopedToolPolicySchema },
  { schemaId: "pi_gacw_command_catalog_v0", fileName: "pi_gacw_command_catalog_v0.schema.json", schema: M4CommandCatalogSchema },
  { schemaId: "pi_gacw_tool_request_v0", fileName: "pi_gacw_tool_request_v0.schema.json", schema: M4ToolRequestSchema },
  { schemaId: "pi_gacw_patch_request_v0", fileName: "pi_gacw_patch_request_v0.schema.json", schema: M4PatchRequestSchema },
  { schemaId: "pi_gacw_mutation_receipt_v0", fileName: "pi_gacw_mutation_receipt_v0.schema.json", schema: M4MutationReceiptSchema },
  { schemaId: "pi_gacw_tool_result_v0", fileName: "pi_gacw_tool_result_v0.schema.json", schema: M4ToolResultSchema },
  { schemaId: "pi_gacw_command_result_v0", fileName: "pi_gacw_command_result_v0.schema.json", schema: M4CommandResultSchema },
  { schemaId: "pi_gacw_m5_control_policy_v0", fileName: "pi_gacw_m5_control_policy_v0.schema.json", schema: M5ControlPolicySchema },
  { schemaId: "pi_gacw_m5_usage_evidence_v0", fileName: "pi_gacw_m5_usage_evidence_v0.schema.json", schema: M5UsageEvidenceSchema },
  { schemaId: "pi_gacw_m5_control_decision_v0", fileName: "pi_gacw_m5_control_decision_v0.schema.json", schema: M5ControlDecisionSchema },
  { schemaId: "pi_gacw_m6_worker_invocation_v0", fileName: "pi_gacw_m6_worker_invocation_v0.schema.json", schema: M6WorkerInvocationSchema },
  { schemaId: "pi_gacw_m6_worker_result_v0", fileName: "pi_gacw_m6_worker_result_v0.schema.json", schema: M6WorkerResultSchema },
  { schemaId: "pi_gacw_bounded_worker_invocation_v0", fileName: "pi_gacw_bounded_worker_invocation_v0.schema.json", schema: BoundedWorkerInvocationSchema },
  { schemaId: "pi_gacw_bounded_worker_result_v0", fileName: "pi_gacw_bounded_worker_result_v0.schema.json", schema: BoundedWorkerResultSchema },
] as const;

// The package-private registry is the sole runtime and emission authority. Every
// reachable schema node and every semantic enum backing array is frozen before
// validators or snapshots can observe it.
deepFreeze(EXECUTION_MODES);
deepFreeze(CONCRETE_EXECUTION_MODES);
deepFreeze(LOGICAL_MODEL_ROLES);
deepFreeze(ENFORCEMENT_CLASSES);
deepFreeze(WORKFLOW_PHASES);
deepFreeze(EVENT_TYPES);
deepFreeze(eventVariants);
deepFreeze(ProjectionIdSchema);
deepFreeze(internalSchemaRegistry);

export type SchemaId = (typeof internalSchemaRegistry)[number]["schemaId"];

export interface InternalSchemaEntry {
  readonly schemaId: SchemaId;
  readonly fileName: string;
  readonly schema: TSchema;
}

/** Package-internal access only; the supported `./schemas` entrypoint does not export this function. */
export function getInternalSchemaRegistry(): readonly InternalSchemaEntry[] {
  return internalSchemaRegistry;
}

export type ExecutionMode = Static<typeof ExecutionModeSchema>;
export type ConcreteExecutionMode = Static<typeof ConcreteExecutionModeSchema>;
export type LogicalModelRole = Static<typeof LogicalModelRoleSchema>;
export type WorkflowPhase = Static<typeof WorkflowPhaseSchema>;
export type ObjectiveDocument = Static<typeof ObjectiveSchema>;
export type OwnerDecisionsDocument = Static<typeof OwnerDecisionsSchema>;
export type RouteMapDocument = Static<typeof RouteMapSchema>;
export type RouteMapApprovalDocument = Static<typeof RouteMapApprovalSchema>;
export type BaselineDocument = Static<typeof BaselineSchema>;
export type BaselineApprovalDocument = Static<typeof BaselineApprovalSchema>;
export type AuthorityLockDocument = Static<typeof AuthorityLockSchema>;
export type ContractDocument = Static<typeof ContractSchema>;
export type RoutingDocument = Static<typeof RoutingSchema>;
export type BudgetDocument = Static<typeof BudgetSchema>;
export type TaskDocument = Static<typeof TaskSchema>;
export type TaskGraphDocument = Static<typeof TaskGraphSchema>;
export type PlanApprovalDocument = Static<typeof PlanApprovalSchema>;
export type WorkflowState = Static<typeof WorkflowStateSchema>;
export type TransitionEvent = Static<typeof TransitionEventSchema>;
export type TransitionCommitDocument = Static<typeof TransitionCommitSchema>;
export type FinalReportDocument = Static<typeof FinalReportSchema>;
export type ReducerPolicy = Static<typeof ReducerPolicySchema>;
export type ProcessMetadata = Static<typeof ProcessMetadataSchema>;
export type EvidenceMetadataDocument = Static<typeof EvidenceMetadataSchema>;
export type EvidenceManifestDocument = Static<typeof EvidenceManifestSchema>;
export type PersistedStatePointerDocument = Static<typeof PersistedStatePointerSchema>;
export type ProcessInterruptionDocument = Static<typeof ProcessInterruptionSchema>;
export type StateTransitionCommitDocument = Static<typeof StateTransitionCommitSchema>;
export type ProgressDelta = Static<typeof ProgressDeltaSchema>;
export type M3RepositoryIdentityDocument = Static<typeof M3RepositoryIdentitySchema>;
export type M3GitStateFingerprintDocument = Static<typeof M3GitStateFingerprintSchema>;
export type M3FileSetFingerprint = Static<typeof M3FileSetFingerprintSchema>;
export type M3BaselinePath = Static<typeof M3BaselinePathSchema>;
export type M3BaselineRuntimeDocument = Static<typeof M3BaselineRuntimeSchema>;
export type M3BaselineApprovalRuntimeDocument = Static<typeof M3BaselineApprovalRuntimeSchema>;
export type M3LockAcquisitionDocument = Static<typeof M3LockAcquisitionSchema>;
export type M3LockDiagnosticDocument = Static<typeof M3LockDiagnosticSchema>;
export type M3EnvironmentFingerprint = Static<typeof M3EnvironmentFingerprintSchema>;
export type M3PreflightDocument = Static<typeof M3PreflightSchema>;
export type M3RepositoryStateTokenDocument = Static<typeof M3RepositoryStateTokenSchema>;
export type M3DeltaEntry = Static<typeof M3DeltaEntrySchema>;
export type M3PostflightDocument = Static<typeof M3PostflightSchema>;
export type M3TerminalRetentionAuthorityDocument = Static<typeof M3TerminalRetentionAuthoritySchema>;
export type M3RetentionResultDocument = Static<typeof M3RetentionResultSchema>;
export type M4PathRule = Static<typeof M4PathRuleSchema>;
export type M4PathAuthority = Static<typeof M4PathAuthoritySchema>;
export type M4Limits = Static<typeof M4LimitsSchema>;
export type M4SecureFilesystemCapabilityDocument = Static<typeof M4SecureFilesystemCapabilitySchema>;
export type M4SandboxCapabilityDocument = Static<typeof M4SandboxCapabilitySchema>;
export type M4ScopedToolPolicyDocument = Static<typeof M4ScopedToolPolicySchema>;
export type M4CommandSpecification = Static<typeof M4CommandSpecificationSchema>;
export type M4CommandCatalogDocument = Static<typeof M4CommandCatalogSchema>;
export type M4ToolRequestDocument = Static<typeof M4ToolRequestSchema>;
export type M4PatchRequestDocument = Static<typeof M4PatchRequestSchema>;
export type M4MutationJournal = Static<typeof M4MutationJournalSchema>;
export type M4MutationReceiptDocument = Static<typeof M4MutationReceiptSchema>;
export type M4ToolResultDocument = Static<typeof M4ToolResultSchema>;
export type M4CommandResultDocument = Static<typeof M4CommandResultSchema>;
export type M5ControlPolicyDocument = Static<typeof M5ControlPolicySchema>;
export type M5UsageEvidenceDocument = Static<typeof M5UsageEvidenceSchema>;
export type M5ControlDecisionDocument = Static<typeof M5ControlDecisionSchema>;
export type M6WorkerInvocationDocument = Static<typeof M6WorkerInvocationSchema>;
export type M6WorkerResultDocument = Static<typeof M6WorkerResultSchema>;
export type BoundedWorkerInvocationDocument = Static<typeof BoundedWorkerInvocationSchema>;
export type BoundedWorkerResultDocument = Static<typeof BoundedWorkerResultSchema>;
