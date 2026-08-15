import { type DomainProjectionId, type Sha256Digest } from "../src/identity/index.js";
import {
  identifyContractDocument,
  type ConcreteExecutionMode,
  type LogicalModelRole,
  type ReducerPolicy,
  type SchemaId,
  type TransitionEvent,
  type WorkflowState,
} from "../src/schemas/index.js";
import { createInitialState, reduceState } from "../src/state-machine/index.js";

// Deliberately dynamic for constructing malformed JSON fixtures that static schema types reject.
export type MutableJson = any;

export function digest(seed: number): Sha256Digest {
  return `sha256:${seed.toString(16).padStart(64, "0")}`;
}

export const repositoryIdentity = {
  root: "/work/repository",
  git_common_dir: "/work/repository/.git",
  worktree: "/work/repository",
  branch: "main",
  head: "0123456789abcdef0123456789abcdef01234567",
} as const;

export const scope = {
  readable_paths: ["src", "tests"],
  editable_paths: ["src"],
  frozen_paths: ["docs"],
} as const;

export const acceptanceCriterion = {
  criterion_id: "criterion-1",
  description: "The deterministic verification command passes.",
  evidence_kind: "COMMAND",
  owner_acceptance: false,
} as const;

export const ownerAcceptanceCriterion = {
  criterion_id: "owner-criterion-1",
  description: "The owner accepts the declared result.",
  evidence_kind: "OWNER_ACCEPTANCE",
  owner_acceptance: true,
} as const;

export const verificationCommand = {
  command_id: "verify-1",
  argv: ["npm", "test"],
  cwd: "/work/repository",
  timeout_ms: 60_000,
  network: "FORBIDDEN",
} as const;

export const commandPolicy = {
  shell: false,
  network: "FORBIDDEN",
  allowed_executables: ["npm"],
  forbidden_operations: ["INSTALL", "COMMIT", "PUSH", "RESET", "CLEAN"],
} as const;

export const limitEnvelope = {
  max_leaves: 8,
  max_attempts_per_leaf: 2,
  max_replans: 2,
  max_worker_invocations: 20,
  max_model_turns: 100,
  max_tool_calls: 200,
  max_input_tokens: 1_000_000,
  max_output_tokens: 100_000,
  max_cost_microusd: 5_000_000,
  max_wall_time_ms: 3_600_000,
} as const;

export function route(logicalRole: LogicalModelRole): MutableJson {
  const closeout = logicalRole === "SOL_CLOSEOUT";
  return {
    logical_role: logicalRole,
    provider_id: logicalRole === "TERRA_EXECUTOR" ? "openai-codex" : "provider-primary",
    model_id: logicalRole === "LUNA_EXECUTOR" ? "luna-high" : logicalRole === "TERRA_EXECUTOR" ? "gpt-5.6-terra" : "sol-max",
    effort: logicalRole === "LUNA_EXECUTOR" || logicalRole === "TERRA_EXECUTOR" ? "high" : "max",
    tool_policy: {
      policy_id: `tools-${logicalRole.toLowerCase()}`,
      built_in_tools_disabled: true,
      mutation_tool: closeout ? "NONE" : "APPLY_PATCH_SCOPED",
      command_gateway: closeout ? "VERIFICATION_ONLY" : "TASK_AND_VERIFICATION",
      maximum_tool_calls: closeout ? 20 : 100,
    },
  };
}

export function allRoutes(): MutableJson[] {
  const roles: readonly LogicalModelRole[] = [
    "SOL_OWNER",
    "SOL_PLANNER",
    "SOL_REPLAN",
    "SOL_CLOSEOUT",
    "LUNA_EXECUTOR",
    "TERRA_EXECUTOR",
    "BENCHMARK_VERIFIER",
    "BENCHMARK_SELECTOR",
  ];
  return roles.map((role) => route(role));
}

export function objectiveDocument(): MutableJson {
  return identifyContractDocument("pi_gacw_objective_v0", {
    schema_id: "pi_gacw_objective_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    objective_projection_id: "objective-freeze-v1",
    target_repository: repositoryIdentity,
    requested_mode: "DIRECT_LUNA_HIGH",
    objective: "Apply one bounded deterministic change.",
    primary_failure_domain: "implementation",
    scope,
    repository_authority_paths: ["AGENTS.md"],
    frozen_invariants: ["No scope expansion"],
    required_outputs: ["src/result.ts"],
    acceptance_criteria: [acceptanceCriterion],
    verification_commands: [verificationCommand],
    owner_acceptance_criteria: [],
    command_policy: commandPolicy,
    baseline_mode: "CLEAN_REQUIRED",
    configured_max_leaves: 8,
  }) as MutableJson;
}

export function routeMapDocument(): MutableJson {
  return identifyContractDocument("pi_gacw_route_map_v0", {
    schema_id: "pi_gacw_route_map_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    route_map_projection_id: "route-map-v1",
    routes: allRoutes(),
    fallback: false,
    provider_managed_multi_agent: false,
  }) as MutableJson;
}

export function budgetDocument(): MutableJson {
  return identifyContractDocument("pi_gacw_budget_v0", {
    schema_id: "pi_gacw_budget_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    budget_projection_id: "budget-freeze-v1",
    limits: limitEnvelope,
    usage: {
      worker_invocation: { value: 0, enforcement_class: "HARD_ENFORCEABLE" },
      model_turn: { value: 0, enforcement_class: "SOFT_ENFORCEABLE" },
      provider_request: { value: null, enforcement_class: "UNAVAILABLE" },
      tool_call: { value: 0, enforcement_class: "HARD_ENFORCEABLE" },
    },
  }) as MutableJson;
}

export function taskGraphDocument(taskCount = 2, configuredMaxLeaves = 8, overlapping = false): MutableJson {
  const tasks = Array.from({ length: taskCount }, (_, index) => ({
    task_id: `task-${index + 1}`,
    task_sha256: digest(100 + index),
    topological_rank: index,
    priority: index,
    dependencies: index === 0 ? [] : [`task-${index}`],
    editable_paths: [overlapping ? "src/shared" : `src/task-${index + 1}`],
    write_owner: `writer-${index + 1}`,
  }));
  const edges = tasks.slice(1).map((task, index) => ({ from: `task-${index + 1}`, to: task.task_id }));
  return identifyContractDocument("pi_gacw_task_graph_v0", {
    schema_id: "pi_gacw_task_graph_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    task_graph_projection_id: "task-graph-freeze-v1",
    tasks,
    edges,
    configured_max_leaves: configuredMaxLeaves,
    write_ownership: "ONE_ACTIVE_WRITER",
  }) as MutableJson;
}

export function planApprovalDocument(mode: ConcreteExecutionMode = "DIRECT_LUNA_HIGH", taskCount = mode === "ROUTED_DAG" || mode === "STATIC_APPROVED_DAG" ? 2 : 1): MutableJson {
  const edges = Array.from({ length: Math.max(0, taskCount - 1) }, (_, index) => ({
    from: `task-${index + 1}`,
    to: `task-${index + 2}`,
  }));
  return identifyContractDocument("pi_gacw_plan_approval_v0", {
    schema_id: "pi_gacw_plan_approval_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    plan_approval_projection_id: "plan-approval-v1",
    bindings: {
      objective_sha256: digest(1),
      target_repository: repositoryIdentity,
      execution_mode: mode,
      baseline_approval_sha256: digest(2),
      authority_lock_sha256: digest(3),
      contract_sha256: digest(4),
      dag: {
        task_graph_sha256: digest(5),
        edges,
        ordered_task_packet_identities: Array.from({ length: taskCount }, (_, index) => digest(10 + index)),
      },
      scope,
      required_inputs: ["input-contract"],
      required_outputs: ["src/result.ts"],
      acceptance_criteria: [acceptanceCriterion],
      owner_acceptance_criteria: mode === "SINGLE_OWNER_SOL" ? [ownerAcceptanceCriterion] : [],
      verification_commands: [verificationCommand],
      command_policy: commandPolicy,
      logical_routes: mode === "ROUTED_DAG"
        ? [route("SOL_PLANNER"), route("SOL_REPLAN"), route("SOL_CLOSEOUT"), route("LUNA_EXECUTOR")]
        : mode === "STATIC_APPROVED_DAG"
          ? [route("TERRA_EXECUTOR")]
          : [route(mode === "SINGLE_OWNER_SOL" ? "SOL_OWNER" : "LUNA_EXECUTOR")],
      limits: limitEnvelope,
      stopping_conditions: ["Stop on scope expansion"],
    },
    approved_by: "owner",
  }) as MutableJson;
}

export const schemaIdByProjection: Readonly<Record<DomainProjectionId, SchemaId>> = {
  "objective-freeze-v1": "pi_gacw_objective_v0",
  "route-map-v1": "pi_gacw_route_map_v0",
  "route-map-approval-v1": "pi_gacw_route_map_approval_v0",
  "baseline-snapshot-v1": "pi_gacw_baseline_v0",
  "baseline-approval-v1": "pi_gacw_baseline_approval_v0",
  "authority-lock-v1": "pi_gacw_authority_lock_v0",
  "contract-freeze-v1": "pi_gacw_contract_v0",
  "task-packet-v1": "pi_gacw_task_v0",
  "task-graph-freeze-v1": "pi_gacw_task_graph_v0",
  "routing-freeze-v1": "pi_gacw_routing_v0",
  "budget-freeze-v1": "pi_gacw_budget_v0",
  "plan-approval-v1": "pi_gacw_plan_approval_v0",
  "transition-commit-v1": "pi_gacw_transition_commit_v0",
  "final-report-v1": "pi_gacw_final_report_v0",
};

export function domainDocument(projectionId: DomainProjectionId): MutableJson {
  switch (projectionId) {
    case "objective-freeze-v1":
      return objectiveDocument();
    case "route-map-v1":
      return routeMapDocument();
    case "route-map-approval-v1":
      return identifyContractDocument("pi_gacw_route_map_approval_v0", {
        schema_id: "pi_gacw_route_map_approval_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        route_map_approval_projection_id: "route-map-approval-v1",
        route_map_sha256: digest(201),
        approved_by: "owner",
        approval_token_sha256: digest(202),
      });
    case "baseline-snapshot-v1":
      return identifyContractDocument("pi_gacw_baseline_v0", {
        schema_id: "pi_gacw_baseline_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        baseline_projection_id: "baseline-snapshot-v1",
        target_repository: repositoryIdentity,
        mode: "CLEAN_REQUIRED",
        git_state_sha256: digest(203),
        staged_paths: [],
        unstaged_paths: [],
        untracked_paths: [],
        files: [],
      });
    case "baseline-approval-v1":
      return identifyContractDocument("pi_gacw_baseline_approval_v0", {
        schema_id: "pi_gacw_baseline_approval_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        baseline_approval_projection_id: "baseline-approval-v1",
        baseline_sha256: digest(204),
        target_repository: repositoryIdentity,
        approved_by: "owner",
      });
    case "authority-lock-v1":
      return identifyContractDocument("pi_gacw_authority_lock_v0", {
        schema_id: "pi_gacw_authority_lock_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        authority_lock_projection_id: "authority-lock-v1",
        authorities: [{ path: "AGENTS.md", role: "REPOSITORY_INSTRUCTION", content_sha256: digest(205) }],
      });
    case "contract-freeze-v1":
      return identifyContractDocument("pi_gacw_contract_v0", {
        schema_id: "pi_gacw_contract_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        contract_projection_id: "contract-freeze-v1",
        objective_sha256: digest(206),
        target_repository: repositoryIdentity,
        execution_mode: "DIRECT_LUNA_HIGH",
        baseline_approval_sha256: digest(207),
        authority_lock_sha256: digest(208),
        route_map_approval_sha256: digest(209),
        scope,
        required_inputs: ["contract-input"],
        required_outputs: ["src/result.ts"],
        acceptance_criteria: [acceptanceCriterion],
        owner_acceptance_criteria: [],
        verification_commands: [verificationCommand],
        command_policy: commandPolicy,
        limits: limitEnvelope,
        stopping_conditions: ["Stop on scope expansion"],
      });
    case "task-packet-v1":
      return identifyContractDocument("pi_gacw_task_v0", {
        schema_id: "pi_gacw_task_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        task_projection_id: "task-packet-v1",
        task_id: "task-domain",
        topological_rank: 0,
        priority: 0,
        dependencies: [],
        objective: "Implement the bounded task.",
        scope,
        required_inputs: ["contract-input"],
        required_outputs: ["src/result.ts"],
        acceptance_criteria: [acceptanceCriterion],
        owner_acceptance_criteria: [],
        verification_commands: [verificationCommand],
        assigned_role: "LUNA_EXECUTOR",
        write_owner: "writer-domain",
      });
    case "task-graph-freeze-v1":
      return taskGraphDocument();
    case "routing-freeze-v1":
      return identifyContractDocument("pi_gacw_routing_v0", {
        schema_id: "pi_gacw_routing_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        routing_projection_id: "routing-freeze-v1",
        requested_mode: "AUTO",
        selected_mode: "DIRECT_LUNA_HIGH",
        reasons: ["One coherent task"],
        route_map_approval_sha256: digest(210),
      });
    case "budget-freeze-v1":
      return budgetDocument();
    case "plan-approval-v1":
      return planApprovalDocument();
    case "transition-commit-v1":
      return identifyContractDocument("pi_gacw_transition_commit_v0", {
        schema_id: "pi_gacw_transition_commit_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        transition_commit_projection_id: "transition-commit-v1",
        sequence: 1,
        from_state_sha256: digest(211),
        event_sha256: digest(212),
        to_state_sha256: digest(213),
        evidence_sha256: [digest(214)],
      });
    case "final-report-v1":
      return identifyContractDocument("pi_gacw_final_report_v0", {
        schema_id: "pi_gacw_final_report_v0",
        schema_version: "0.1.0",
        content_projection_id: "document-content-v1",
        final_report_projection_id: "final-report-v1",
        run_id: "run-final",
        outcome: "PASS",
        reason: "All bounded checks passed.",
        objective_sha256: digest(215),
        contract_sha256: digest(216),
        plan_approval_sha256: null,
        final_state_sha256: digest(217),
        command_results: [],
        usage: {
          worker_invocation: { value: 1, enforcement_class: "HARD_ENFORCEABLE" },
          model_turn: { value: 1, enforcement_class: "SOFT_ENFORCEABLE" },
          provider_request: { value: null, enforcement_class: "UNAVAILABLE" },
          tool_call: { value: 0, enforcement_class: "HARD_ENFORCEABLE" },
        },
      });
  }
}

export interface TestPolicyTask {
  readonly task_id: string;
  readonly task_sha256: Sha256Digest;
  readonly topological_rank: number;
  readonly priority: number;
  readonly dependencies: readonly string[];
  readonly editable_paths: readonly string[];
}

export interface PolicyOptions {
  readonly ownerAcceptanceRequired?: boolean;
  readonly tasks?: readonly TestPolicyTask[];
  readonly limits?: Partial<ReducerPolicy["limits"]>;
}

export function makePolicy(mode: ConcreteExecutionMode, options: PolicyOptions = {}): ReducerPolicy {
  const defaultTasks: readonly TestPolicyTask[] = mode === "ROUTED_DAG" || mode === "STATIC_APPROVED_DAG"
    ? [
        {
          task_id: "task-a",
          task_sha256: digest(31),
          topological_rank: 0,
          priority: 0,
          dependencies: [],
          editable_paths: ["src/a"],
        },
        {
          task_id: "task-b",
          task_sha256: digest(32),
          topological_rank: 1,
          priority: 0,
          dependencies: ["task-a"],
          editable_paths: ["src/b"],
        },
      ]
    : [
        {
          task_id: "task-only",
          task_sha256: digest(30),
          topological_rank: 0,
          priority: 0,
          dependencies: [],
          editable_paths: ["src/only"],
        },
      ];
  const tasks = options.tasks ?? defaultTasks;
  const defaults: ReducerPolicy["limits"] = {
    max_direct_attempts: 2,
    max_single_owner_mutation_cycles: 2,
    max_attempts_per_leaf: 2,
    max_replans: mode === "ROUTED_DAG" ? 2 : 0,
    max_leaves: mode === "ROUTED_DAG" || mode === "STATIC_APPROVED_DAG" ? 8 : 1,
    max_worker_invocations: mode === "SINGLE_OWNER_SOL" ? 1 : mode === "DIRECT_LUNA_HIGH" ? 2 : 20,
  };
  const policy = identifyContractDocument("pi_gacw_reducer_policy_v0", {
    schema_id: "pi_gacw_reducer_policy_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: `run-${mode.toLowerCase()}`,
    execution_mode: mode,
    owner_acceptance_required: options.ownerAcceptanceRequired ?? false,
    limits: { ...defaults, ...options.limits },
    tasks,
    frozen_bindings: {
      plan_approval_sha256: digest(40),
      task_graph_sha256: mode === "ROUTED_DAG" || mode === "STATIC_APPROVED_DAG" ? digest(41) : null,
      scope_sha256: digest(42),
      acceptance_sha256: digest(43),
      budget_sha256: digest(44),
    },
  });
  return policy as unknown as ReducerPolicy;
}

export function stateIdentities(policy: ReducerPolicy): WorkflowState["identities"] {
  return {
    objective_sha256: digest(50),
    contract_sha256: digest(51),
    baseline_approval_sha256: digest(52),
    authority_lock_sha256: digest(53),
    plan_approval_sha256: policy.frozen_bindings.plan_approval_sha256,
    task_graph_sha256: policy.frozen_bindings.task_graph_sha256,
    scope_sha256: policy.frozen_bindings.scope_sha256,
    acceptance_sha256: policy.frozen_bindings.acceptance_sha256,
    budget_sha256: policy.frozen_bindings.budget_sha256,
  };
}

export function transitionEvent(eventType: TransitionEvent["event_type"], payload: MutableJson = {}): TransitionEvent {
  return identifyContractDocument("pi_gacw_transition_event_v0", {
    schema_id: "pi_gacw_transition_event_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    event_id: `event-${eventType.toLowerCase()}`,
    event_type: eventType,
    payload,
  }) as unknown as TransitionEvent;
}

export function applyEvent(
  state: WorkflowState,
  policy: ReducerPolicy,
  eventType: TransitionEvent["event_type"],
  payload: MutableJson = {},
): WorkflowState {
  return reduceState(state, transitionEvent(eventType, payload), policy);
}

export function advanceCommon(policy: ReducerPolicy): WorkflowState {
  let state = createInitialState(policy, stateIdentities(policy));
  state = applyEvent(state, policy, "FREEZE_OBJECTIVE");
  state = applyEvent(state, policy, "ACQUIRE_LOCK");
  state = applyEvent(state, policy, "CAPTURE_BASELINE", { approval_required: false });
  state = applyEvent(state, policy, "ACCEPT_CLEAN_BASELINE");
  state = applyEvent(state, policy, "PASS_FULL_PREFLIGHT");
  state = applyEvent(state, policy, "VALIDATE_CONTRACT");
  return applyEvent(state, policy, "SELECT_ROUTE", { execution_mode: policy.execution_mode });
}

export function progress(seed = 70): MutableJson {
  return {
    kind: "NEW_TEST_EVIDENCE",
    evidence_sha256: digest(seed),
    summary: "New deterministic test evidence demonstrates progress.",
  };
}
