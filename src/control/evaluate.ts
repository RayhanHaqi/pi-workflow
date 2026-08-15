import { canonicalize } from "../canonical-json/index.js";
import { sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE } from "../persistence/bounded-worker-authority.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type BoundedWorkerResultDocument,
  type LogicalModelRole,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M5UsageEvidenceDocument,
  type ReducerPolicy,
  type TransitionEvent,
  type WorkflowState,
} from "../schemas/index.js";
import { reduceState } from "../state-machine/index.js";
import { controlError } from "./errors.js";
import type { EvaluateControlDecisionInput, M5AuthoritativeSources, M5FailureInput } from "./types.js";

const DIMENSIONS = ["WORKER_INVOCATION", "MODEL_TURN", "PROVIDER_REQUEST", "TOOL_CALL", "INPUT_TOKEN", "OUTPUT_TOKEN", "COST_MICROUSD", "WALL_TIME_MS"] as const;
const CONTINUATION_ROUTES = ["CONTINUE_ADMITTED_OPERATION", "RETRY_TRANSIENT_TOOL_ONCE", "SECOND_LUNA_ATTEMPT", "CORRECT_COMMAND_ONCE", "RESTORE_CONTEXT_ONCE", "CONSTRAINED_REPLAN", "RUN_RESERVED_CLOSEOUT", "REQUEST_OWNER_DECISION", "BLOCK"] as const;
type FailureClass = M5ControlDecisionDocument["failures"][number]["control_class"];
type ContinuationRoute = (typeof CONTINUATION_ROUTES)[number];
type BudgetEntry = M5ControlDecisionDocument["budget"][number];

const ACTION_BY_CLASS: Readonly<Record<FailureClass, ContinuationRoute>> = Object.freeze({
  TRANSIENT_TOOL_FAILURE: "RETRY_TRANSIENT_TOOL_ONCE",
  LOCAL_IMPLEMENTATION_DEFECT: "SECOND_LUNA_ATTEMPT",
  COMMAND_CONTRACT_ERROR: "CORRECT_COMMAND_ONCE",
  CONTEXT_MISSING: "RESTORE_CONTEXT_ONCE",
  PLAN_INCORRECT: "CONSTRAINED_REPLAN",
  AUTHORITY_CONTRADICTION: "REQUEST_OWNER_DECISION",
  SCOPE_EXPANSION_REQUIRED: "BLOCK",
  STATE_DRIFT: "BLOCK",
  CONCURRENT_WRITER: "BLOCK",
  TEST_INTEGRITY_VIOLATION: "BLOCK",
  CLEANUP_UNCERTAIN: "BLOCK",
  SAME_FAILURE_TWICE: "CONSTRAINED_REPLAN",
  CLOSEOUT_DEFECT: "BLOCK",
  PROCESS_CRASH: "BLOCK",
  MODEL_UNAVAILABLE: "BLOCK",
  BUDGET_EXHAUSTED: "BLOCK",
  CONTRACT_UNSATISFIABLE: "BLOCK",
  ROUTE_UNAVAILABLE: "BLOCK",
  CAPABILITY_UNAVAILABLE: "BLOCK",
  MUTATION_UNCERTAIN: "BLOCK",
  EVIDENCE_INVALID: "BLOCK",
  EVIDENCE_PUBLICATION_FAILURE: "BLOCK",
  STATE_PUBLICATION_FAILURE: "BLOCK",
  INTERNAL_CONTROL_ERROR: "BLOCK",
});

const SOURCE_CLASS: Readonly<Record<string, FailureClass>> = Object.freeze({
  TRANSIENT_TOOL_FAILURE: "TRANSIENT_TOOL_FAILURE", COMMAND_TIMEOUT: "TRANSIENT_TOOL_FAILURE",
  LOCAL_IMPLEMENTATION_DEFECT: "LOCAL_IMPLEMENTATION_DEFECT", COMMAND_CONTRACT_ERROR: "COMMAND_CONTRACT_ERROR",
  CONTEXT_MISSING: "CONTEXT_MISSING", PLAN_INCORRECT: "PLAN_INCORRECT", AUTHORITY_CONTRADICTION: "AUTHORITY_CONTRADICTION",
  SCOPE_EXPANSION_REQUIRED: "SCOPE_EXPANSION_REQUIRED", STATE_DRIFT: "STATE_DRIFT", CONCURRENT_WRITER: "CONCURRENT_WRITER",
  TEST_INTEGRITY_VIOLATION: "TEST_INTEGRITY_VIOLATION", CLEANUP_UNCERTAIN: "CLEANUP_UNCERTAIN",
  SAME_FAILURE_TWICE: "SAME_FAILURE_TWICE", CLOSEOUT_DEFECT: "CLOSEOUT_DEFECT", PROCESS_CRASH: "PROCESS_CRASH",
  MODEL_UNAVAILABLE: "MODEL_UNAVAILABLE", BUDGET_EXHAUSTED: "BUDGET_EXHAUSTED", CONTRACT_UNSATISFIABLE: "CONTRACT_UNSATISFIABLE",
  ROUTE_UNAVAILABLE: "ROUTE_UNAVAILABLE", CAPABILITY_UNAVAILABLE: "CAPABILITY_UNAVAILABLE", MUTATION_UNCERTAIN: "MUTATION_UNCERTAIN",
  WRITE_UNCERTAIN: "MUTATION_UNCERTAIN", EVIDENCE_PUBLICATION_FAILURE: "EVIDENCE_PUBLICATION_FAILURE",
  EVIDENCE_PUBLICATION_FAILED: "EVIDENCE_PUBLICATION_FAILURE", STATE_PUBLICATION_FAILURE: "STATE_PUBLICATION_FAILURE",
  INTERNAL_CONTROL_ERROR: "INTERNAL_CONTROL_ERROR",
});

/**
 * Explicitly reviewed lower-layer vocabulary. The arrays are deliberately kept
 * here rather than inferred from error-message text: adding a finite source code
 * requires a visible M5 mapping decision and a focused test.
 */
const EXPLICIT_LOWER_LAYER_GROUPS: Readonly<Partial<Record<FailureClass, readonly string[]>>> = Object.freeze({
  COMMAND_CONTRACT_ERROR: [
    "COMMAND_FORBIDDEN", "GENERIC_DISPATCHER_FORBIDDEN", "COMMAND_SPEC_MISMATCH", "COMMAND_CLASS_MISMATCH", "UNKNOWN_COMMAND_ID",
    "EXECUTION_INPUT_DRIFT", "COMMAND_CWD_IDENTITY_DRIFT", "COMMAND_OUTPUT_LIMIT", "COMMAND_SIGNALLED", "COMMAND_EXIT_CODE_UNEXPECTED",
    "COMMAND_UNEXPECTED_REPOSITORY_DELTA", "HELPER_PROTOCOL_ERROR",
  ],
  SCOPE_EXPANSION_REQUIRED: [
    "OUT_OF_SCOPE_WRITE", "PATH_OUTSIDE_ROOT", "PATH_NOT_EDITABLE", "FROZEN_PATH", "OWNERSHIP_FORBIDS_MUTATION", "DATA_POLICY_FORBIDS_MUTATION",
    "HARDLINK_WRITE_SCOPE_UNSAFE", "FORBIDDEN_PATH_CHANGED", "BASELINE_PATH_UNCLASSIFIED", "BASELINE_SECRET_PRESENT", "BASELINE_SPECIAL_PATH",
    "UNEXPECTED_REPOSITORY_DELTA", "POSTFLIGHT_CLAIMED_PATHS_MISMATCH", "POSTFLIGHT_DELTA_MISMATCH",
  ],
  CONCURRENT_WRITER: [
    "CONCURRENT_WRITER", "CONCURRENT_OPERATION", "LOCK_BUSY", "LOCK_LOST", "LOCK_NOT_HELD", "GIT_OPERATION_IN_PROGRESS", "GIT_INDEX_LOCK_PRESENT",
  ],
  STATE_DRIFT: [
    "WRONG_REPOSITORY", "WRONG_WORKTREE", "WRONG_BRANCH", "DETACHED_HEAD_UNEXPECTED", "HEAD_DRIFT", "UPSTREAM_DRIFT", "WORKTREE_LIST_DRIFT",
    "REPOSITORY_ROOT_MISMATCH", "FINAL_TARGET_IDENTITY_MISMATCH", "PARENT_IDENTITY_DRIFT", "PREIMAGE_MISMATCH", "STATE_TOKEN_PROVENANCE_INVALID",
    "STATE_TOKEN_SOURCE_MISSING", "STATE_TOKEN_CHAIN_TOO_DEEP", "STATE_TOKEN_CHAIN_LOOP", "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
    "POSTFLIGHT_SCOPE_IDENTITY_MISMATCH", "POSTFLIGHT_SOURCE_SEMANTIC_MISMATCH", "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "INDEX_DRIFT",
    "BLOCKED_STATE_DRIFT", "ENVIRONMENT_DRIFT", "OBSERVED_STATE_DRIFT", "STALE_EXPECTED_REVISION", "STALE_STATE_POINTER", "STALE_WORKFLOW_STATE",
    "PREVIOUS_STATE_MISMATCH", "PREVIOUS_POINTER_MISMATCH", "REVISION_CHAIN_MISMATCH", "STATE_POINTER_COMMIT_MISMATCH", "STATE_POINTER_REVISION_MISMATCH",
    "GENESIS_STATE_MISMATCH", "REDUCER_RESULT_MISMATCH", "RUN_ID_MISMATCH", "CROSS_MODE_EVENT", "ROUTE_MISMATCH", "PLAN_IDENTITY_MISMATCH",
  ],
  CLEANUP_UNCERTAIN: [
    "CLEANUP_UNCERTAIN", "ROLLBACK_UNCERTAIN", "SECURE_WRITE_UNCERTAIN", "RESIDUE_IDENTITY_MISMATCH", "MUTATION_RECEIPT_INCONSISTENT",
    "BASELINE_PUBLICATION_CLEANUP_UNCERTAIN", "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN", "TEMPORARY_CLEANUP_FAILED", "DIRECTORY_FSYNC_FAILED",
    "RETENTION_RESULT_PUBLICATION_FAILED", "RETENTION_RESULT_PUBLICATION_FAILED", "EVIDENCE_PUBLICATION_CLEANUP_UNCERTAIN",
  ],
  CAPABILITY_UNAVAILABLE: [
    "SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "COMMAND_SANDBOX_UNAVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE", "SECURE_FS_CAPABILITY_MISMATCH",
    "CAPABILITY_PROVENANCE_INVALID", "UNSUPPORTED_REPOSITORY_STATE", "SECURE_FS_UNAVAILABLE", "COMMAND_SANDBOX_UNAVAILABLE",
  ],
  MUTATION_UNCERTAIN: [
    "FINAL_TARGET_IDENTITY_MISMATCH", "SECURE_WRITE_UNCERTAIN", "OUTPUT_EVIDENCE_INCONSISTENT", "MUTATION_RECEIPT_INCONSISTENT", "PARENT_IDENTITY_DRIFT",
  ],
  AUTHORITY_CONTRADICTION: [
    "AUTHORITY_DRIFT", "INSTRUCTION_DRIFT", "REPOSITORY_AUTHORITY_INVALID", "BASELINE_APPROVAL_MISMATCH", "BASELINE_APPROVAL_REPOSITORY_MISMATCH",
    "BASELINE_APPROVAL_WORKTREE_MISMATCH", "BASELINE_APPROVAL_BRANCH_MISMATCH", "BASELINE_APPROVAL_HEAD_MISMATCH", "BASELINE_APPROVAL_SEMANTIC_MISMATCH",
    "BASELINE_RECORD_MISMATCH", "BASELINE_APPROVAL_RECORD_MISMATCH", "BASELINE_PROVENANCE_INVALID", "STATE_TOKEN_PROVENANCE_INVALID",
    "CAPABILITY_PROVENANCE_INVALID", "M4_RECORD_SEMANTICS_INVALID", "M5_RECORD_SEMANTICS_INVALID", "IDENTITY_MISMATCH", "CONTENT_ADDRESS_MISMATCH",
  ],
  CONTEXT_MISSING: [
    "BASELINE_RECORD_MISSING", "BASELINE_APPROVAL_RECORD_MISSING", "STATE_TOKEN_RECORD_MISSING", "STATE_TOKEN_SOURCE_MISSING", "EVIDENCE_NOT_FOUND",
    "FILE_MISSING", "STATE_DIRECTORY_MISSING", "STATE_STORAGE_INVALID", "TARGET_MISSING", "UNKNOWN_TASK", "NO_ACTIVE_TASK", "NO_READY_LEAF",
  ],
  EVIDENCE_PUBLICATION_FAILURE: [
    "EVIDENCE_PUBLICATION_FAILED", "EVIDENCE_STORE_FAILED", "EVIDENCE_REFERENCE_INVALID", "EVIDENCE_METADATA_MISMATCH", "EVIDENCE_BYTE_COUNT_MISMATCH",
    "EVIDENCE_HASH_MISMATCH", "ATOMIC_WRITE_FAILED", "DIRECTORY_CREATE_FAILED", "SHORT_WRITE", "TEMPORARY_FILE_COLLISION",
    "IMMUTABLE_OBJECT_MISMATCH", "NONCANONICAL_RECORD_BYTES", "MALFORMED_IMMUTABLE_RECORD", "INVALID_IMMUTABLE_RECORD",
  ],
  STATE_PUBLICATION_FAILURE: [
    "STATE_PUBLICATION_FAILURE", "BLOCKED_STATE_COMMIT_INCOMPLETE", "EXPECTED_NEXT_STATE_MISMATCH", "INCOMPLETE_TRANSITION_COMMIT",
    "PROCESS_ASSESSMENT_MISMATCH", "PROCESS_ASSESSMENT_PRESENCE_MISMATCH", "PROCESS_CRASH_TERMINAL_MISMATCH", "NONCANONICAL_STATE_POINTER",
    "MALFORMED_STATE_POINTER", "INVALID_STATE_POINTER", "TERMINAL_STATE_IMMUTABLE",
  ],
  BUDGET_EXHAUSTED: [
    "M4_TOOL_BUDGET_EXHAUSTED", "INVOCATION_CAP_EXCEEDED", "ROLE_INVOCATION_CAP_EXCEEDED", "ATTEMPT_CAP_EXCEEDED", "SOL_OWNER_CAP_EXCEEDED", "MUTATION_CYCLE_CAP_EXCEEDED",
    "REPLAN_CAP_EXCEEDED", "PATCH_LIMIT_EXCEEDED", "READ_LIMIT_EXCEEDED", "SEARCH_LIMIT_EXCEEDED", "LIST_LIMIT_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED",
  ],
  ROUTE_UNAVAILABLE: ["ONE_TASK_REQUIRED", "NO_READY_LEAF", "ROUTE_MISMATCH", "ROUTE_NOT_ELIGIBLE", "NO_ELIGIBLE_ROUTE"],
  CLOSEOUT_DEFECT: ["CLOSEOUT_NOT_READY", "POSTFLIGHT_REQUIRED"],
  PROCESS_CRASH: ["PROCESS_CRASH", "UNEXPECTED_TERMINATION"],
  EVIDENCE_INVALID: [
    "INVALID_ARGUMENT", "INVALID_STATE_ROOT", "INVALID_RUN_ID", "INVALID_DIGEST", "UNKNOWN_OBJECT_KIND", "INVALID_GIT_OUTPUT", "GIT_INSPECTION_FAILED",
    "BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT", "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING", "INVALID_CANONICAL_PATH", "SPECIAL_FILE", "SYMLINK_PATH",
    "MAGICLINK_PATH", "HARDLINK_TARGET", "INVALID_LOCK_PATH", "INVALID_TEMPORARY_NAME", "UNSAFE_DIRECTORY_TYPE", "UNSAFE_FILE_TYPE",
    "DIRECTORY_PERMISSION_MISMATCH", "FILE_PERMISSION_MISMATCH", "EVIDENCE_TOO_LARGE", "EVIDENCE_STORE_FAILED", "SHORT_WRITE",
    "INVALID_TRANSITION", "INVALID_PROGRESS_DELTA", "TERMINAL_STATE_IMMUTABLE", "TARGET_ALREADY_EXISTS",
  ],
});
const REVIEWED_LOWER_LAYER_GROUPS: Readonly<Partial<Record<FailureClass, readonly string[]>>> = Object.freeze({
  EVIDENCE_INVALID: [
    "INVALID_ARGUMENT", "INVALID_RUN_ID", "INVALID_STATE_ROOT", "INVALID_CANONICAL_PATH", "INVALID_LOCK_PATH", "INVALID_TEMPORARY_NAME",
    "INVALID_GIT_OUTPUT", "GIT_INSPECTION_FAILED", "BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT", "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING", "NOT_A_GIT_WORKTREE",
    "MISSING_HEAD", "UNREADABLE_GIT_DIRECTORY", "UNKNOWN_OBJECT_KIND", "UNKNOWN_SCHEMA", "SCHEMA_INVALID", "DOCUMENT_NOT_OBJECT", "MALFORMED_RECORD",
    "SHORT_WRITE", "ATOMIC_WRITE_FAILED", "DIRECTORY_CREATE_FAILED", "LAYOUT_INSPECTION_FAILED", "MISSING_DIRECTORY", "MISSING_REQUIRED_ENTRY",
    "UNSAFE_DIRECTORY_TYPE", "UNSAFE_FILE_TYPE", "SPECIAL_FILE_ENTRY", "SYMLINK_ENTRY", "UNKNOWN_ENTRY", "PERMISSION_MISMATCH",
    "INVALID_EXECUTION_MODE", "INVALID_LUNA_EFFORT", "INVALID_SOL_EFFORT", "INVALID_TOPOLOGICAL_RANK", "INVALID_TERMINAL_STATE", "INVALID",
    "INVALID_TRANSITION", "INVALID_PROGRESS_DELTA", "PROGRESS_DELTA_REQUIRED", "MUTATION_CYCLE_REQUIRED", "TARGET_ALREADY_EXISTS",
  ],
  STATE_DRIFT: [
    "WRONG_REPOSITORY", "WRONG_WORKTREE", "WRONG_BRANCH", "DETACHED_HEAD_UNEXPECTED", "HEAD_DRIFT", "UPSTREAM_DRIFT", "WORKTREE_LIST_DRIFT",
    "REPOSITORY_ROOT_MISMATCH", "GIT_CONFLICT_PRESENT", "UNREADABLE_GIT_DIRECTORY", "INDEX_DRIFT", "BLOCKED_STATE_DRIFT", "ENVIRONMENT_DRIFT",
    "STALE_EXPECTED_REVISION", "STALE_STATE_POINTER", "STALE_WORKFLOW_STATE", "PREVIOUS_STATE_MISMATCH", "PREVIOUS_POINTER_MISMATCH", "REVISION_CHAIN_MISMATCH",
    "STATE_POINTER_COMMIT_MISMATCH", "STATE_POINTER_REVISION_MISMATCH", "GENESIS_STATE_MISMATCH", "REDUCER_RESULT_MISMATCH", "RUN_ID_MISMATCH",
    "CROSS_MODE_EVENT", "CROSS_MODE_STATE", "CROSS_MODE_COUNTER", "PHASE_INVARIANT_MISMATCH", "ATTEMPT_COUNTER_MISMATCH", "INVOCATION_COUNTER_MISMATCH",
    "LEAF_COUNTER_MISMATCH", "ACTIVE_TASK_MISMATCH", "STATE_TOKEN_CHAIN_TOO_DEEP", "STATE_TOKEN_CHAIN_LOOP", "FAST_PREFLIGHT_FAILED", "POSTFLIGHT_FAILED",
    "PREIMAGE_MISMATCH", "EXECUTION_INPUT_DRIFT", "COMMAND_CWD_IDENTITY_DRIFT", "TRANSITION_COMMIT_CYCLE",
  ],
  AUTHORITY_CONTRADICTION: [
    "REPOSITORY_AUTHORITY_INVALID", "AUTHORITY_DRIFT", "INSTRUCTION_DRIFT", "BASELINE_APPROVAL_MISMATCH", "BASELINE_APPROVAL_REPOSITORY_MISMATCH",
    "BASELINE_APPROVAL_WORKTREE_MISMATCH", "BASELINE_APPROVAL_BRANCH_MISMATCH", "BASELINE_APPROVAL_HEAD_MISMATCH", "BASELINE_APPROVAL_SEMANTIC_MISMATCH",
    "BASELINE_RECORD_MISMATCH", "BASELINE_APPROVAL_RECORD_MISMATCH", "BASELINE_PROVENANCE_INVALID", "STATE_TOKEN_PROVENANCE_INVALID", "CAPABILITY_PROVENANCE_INVALID",
    "M4_RECORD_SEMANTICS_INVALID", "M5_RECORD_SEMANTICS_INVALID", "IDENTITY_MISMATCH", "CONTENT_ADDRESS_MISMATCH", "FROZEN_IDENTITY_MISMATCH",
    "FROZEN_POLICY_IDENTITY_MISMATCH", "FROZEN_TASK_SET_MISMATCH", "POLICY_STATE_MISMATCH", "INITIAL_STATE_NOT_REDUCER_DERIVED", "ROUTE_FREEZE_MISMATCH",
    "PLAN_IDENTITY_MISMATCH", "REPLAN_FROZEN_BINDING_CHANGE", "DAG_GROWTH_FORBIDDEN", "DAG_TOPOLOGY_CHANGE_FORBIDDEN", "TASKS_FROZEN_TOO_EARLY",
    "TASKS_ALREADY_FROZEN", "UNAPPROVED_ROUTE_MAP", "LOCK_GUARDIAN_START_FAILED", "LOCK_RELEASE_FAILED", "UNDECLARED_OWNER_ACCEPTANCE",
    "OWNER_ACCEPTANCE_MODE_MISMATCH", "LUNA_OWNER_ACCEPTANCE_FORBIDDEN", "BASELINE_APPROVAL_REQUIRED", "BASELINE_APPROVAL_NOT_REQUIRED",
  ],
  SCOPE_EXPANSION_REQUIRED: [
    "POSTFLIGHT_SCOPE_IDENTITY_MISMATCH", "POSTFLIGHT_CLAIMED_PATHS_MISMATCH", "POSTFLIGHT_DELTA_MISMATCH", "BASELINE_DIRTY_NOT_APPROVED", "SECRET_METADATA_FORBIDDEN",
    "DATA_POLICY_FORBIDS_READ", "PATH_NOT_READABLE", "FORBIDDEN_PATH_CHANGED", "DUPLICATE_REPOSITORY_PATH", "NONCANONICAL_REPOSITORY_PATH",
  ],
  CONTEXT_MISSING: [
    "BASELINE_RECORD_MISSING", "BASELINE_APPROVAL_RECORD_MISSING", "STATE_TOKEN_RECORD_MISSING", "STATE_TOKEN_SOURCE_MISSING", "EVIDENCE_NOT_FOUND",
    "FILE_MISSING", "STATE_DIRECTORY_MISSING", "STATE_STORAGE_INVALID", "TARGET_MISSING", "UNKNOWN_TASK", "NO_ACTIVE_TASK", "MISSING_PLAN_IDENTITY",
    "MISSING_LOGICAL_ROUTE", "MISSING", "MISSING_REQUIRED_ENTRY",
  ],
  BUDGET_EXHAUSTED: [
    "BASELINE_BLOB_LIMIT_EXCEEDED", "STATE_ROOT_LIMIT_EXCEEDED", "INVOCATION_CAP_EXCEEDED", "ROLE_INVOCATION_CAP_EXCEEDED", "ATTEMPT_CAP_EXCEEDED",
    "SOL_OWNER_CAP_EXCEEDED", "MUTATION_CYCLE_CAP_EXCEEDED", "REPLAN_CAP_EXCEEDED", "PATCH_LIMIT_EXCEEDED", "READ_LIMIT_EXCEEDED", "SEARCH_LIMIT_EXCEEDED",
    "LIST_LIMIT_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED", "TASK_GRAPH_ABOVE_LEAF_CAP",
  ],
  CONTRACT_UNSATISFIABLE: ["AMBIGUOUS_WRITE_OWNERSHIP", "DUPLICATE_SET_MEMBER", "DEPENDENCY_EDGE_MISMATCH", "ONE_TASK_REQUIRED", "ROUTED_DAG_TOO_SMALL"],
  ROUTE_UNAVAILABLE: ["NO_READY_LEAF", "NO_ACTIVE_TASK", "ONE_TASK_REQUIRED", "MISSING_LOGICAL_ROUTE", "FORBIDDEN_LUNA_MEDIUM", "ROUTED_DAG_TOO_SMALL"],
  CLOSEOUT_DEFECT: ["CLOSEOUT_NOT_READY", "CLOSEOUT_NOT_VERIFICATION_ONLY", "POSTFLIGHT_REQUIRED"],
  CONCURRENT_WRITER: ["GIT_OPERATION_IN_PROGRESS", "GIT_INDEX_LOCK_PRESENT", "LOCK_BUSY", "LOCK_LOST", "LOCK_NOT_HELD", "CONCURRENT_OPERATION", "CONCURRENT_WRITER"],
  CLEANUP_UNCERTAIN: ["BASELINE_PUBLICATION_CLEANUP_UNCERTAIN", "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN", "RETENTION_RESULT_PUBLICATION_FAILED", "ROLLBACK_UNCERTAIN", "CLEANUP_UNCERTAIN"],
  MUTATION_UNCERTAIN: ["FINAL_TARGET_IDENTITY_MISMATCH", "PARENT_IDENTITY_DRIFT", "MUTATION_RECEIPT_INCONSISTENT", "OUTPUT_EVIDENCE_INCONSISTENT", "SECURE_WRITE_UNCERTAIN"],
  CAPABILITY_UNAVAILABLE: ["SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "COMMAND_SANDBOX_UNAVAILABLE", "NETWORK_SANDBOX_UNAVAILABLE", "SECURE_FS_CAPABILITY_MISMATCH", "UNSUPPORTED_REPOSITORY_STATE"],
  COMMAND_CONTRACT_ERROR: ["UNKNOWN_COMMAND_ID", "COMMAND_CLASS_MISMATCH", "COMMAND_SPEC_MISMATCH", "COMMAND_FORBIDDEN", "GENERIC_DISPATCHER_FORBIDDEN", "HELPER_PROTOCOL_ERROR", "COMMAND_OUTPUT_LIMIT", "COMMAND_SIGNALLED", "COMMAND_EXIT_CODE_UNEXPECTED", "COMMAND_UNEXPECTED_REPOSITORY_DELTA"],
  TRANSIENT_TOOL_FAILURE: ["COMMAND_TIMEOUT"],
  PROCESS_CRASH: ["PROCESS_CRASH", "UNEXPECTED_TERMINATION"],
});
export function buildLowerLayerFailureMap(definitions: readonly (readonly [string, FailureClass])[]): Readonly<Record<string, FailureClass>> {
  const entries = new Map<string, FailureClass>();
  for (const [code, failureClass] of definitions) {
    if (entries.has(code)) throw controlError("FAILURE_CLASSIFICATION_INVALID", `Duplicate lower-layer failure mapping for ${code}`);
    entries.set(code, failureClass);
  }
  return Object.freeze(Object.fromEntries(entries));
}
const EXPLICIT_LOWER_LAYER_MAP: Readonly<Record<string, FailureClass>> = (() => {
  // The legacy reviewed groups are input vocabularies only. Resolve them once into
  // unique definitions, preserving the first explicit classification rather than
  // allowing Map.set to silently overwrite it.
  const resolved = new Map<string, FailureClass>();
  for (const groups of [EXPLICIT_LOWER_LAYER_GROUPS, REVIEWED_LOWER_LAYER_GROUPS]) {
    for (const [failureClass, codes] of Object.entries(groups)) for (const code of codes ?? []) if (!resolved.has(code)) resolved.set(code, failureClass as FailureClass);
  }
  for (const [code, failureClass] of Object.entries(SOURCE_CLASS)) if (!resolved.has(code)) resolved.set(code, failureClass);
  const reviewedCorrections: Readonly<Record<string, FailureClass>> = Object.freeze({
    EVIDENCE_STORE_FAILED: "EVIDENCE_PUBLICATION_FAILURE", SHORT_WRITE: "EVIDENCE_PUBLICATION_FAILURE", TERMINAL_STATE_IMMUTABLE: "STATE_PUBLICATION_FAILURE",
    SECURE_WRITE_UNCERTAIN: "MUTATION_UNCERTAIN", FINAL_TARGET_IDENTITY_MISMATCH: "MUTATION_UNCERTAIN", PARENT_IDENTITY_DRIFT: "MUTATION_UNCERTAIN",
    RETENTION_DEADLINE_NOT_REACHED: "AUTHORITY_CONTRADICTION", RETENTION_NOT_TERMINAL: "STATE_DRIFT", RETENTION_TIMESTAMP_UNAVAILABLE: "CONTEXT_MISSING",
    M5_DECISION_CONFLICT: "AUTHORITY_CONTRADICTION", M5_POLICY_CONFLICT: "AUTHORITY_CONTRADICTION", M5_USAGE_CONFLICT: "AUTHORITY_CONTRADICTION",
    ORPHANED_UNCOMMITTED_EVIDENCE: "EVIDENCE_PUBLICATION_FAILURE", RUN_DIRECTORY_NOT_EMPTY: "STATE_DRIFT",
    BLOCKED_UNEXPECTED_STATE_STORE_ENTRY: "STATE_PUBLICATION_FAILURE", COMMITTED_GRAPH_INVALID: "STATE_PUBLICATION_FAILURE", INVALID_RUN_DIRECTORY_NAME: "EVIDENCE_INVALID",
    INVALID_TEMPORARY_FILE: "EVIDENCE_INVALID", OBJECT_INTEGRITY_INVALID: "EVIDENCE_INVALID", RUN_ENTRY_NOT_DIRECTORY: "EVIDENCE_INVALID",
    STATE_POINTER_STATE_MISMATCH: "STATE_DRIFT", UNCOMMITTED_BASELINE_PUBLICATION: "EVIDENCE_PUBLICATION_FAILURE", REPLAN_ALREADY_RUNNING: "STATE_DRIFT", REPLAN_NOT_RUNNING: "STATE_DRIFT",
    M5_POLICY_INVALID: "AUTHORITY_CONTRADICTION", USAGE_EVIDENCE_INVALID: "EVIDENCE_INVALID", BUDGET_EVALUATION_INVALID: "EVIDENCE_INVALID",
    PROGRESS_EVIDENCE_INVALID: "EVIDENCE_INVALID", PROGRESS_CLASSIFICATION_INVALID: "EVIDENCE_INVALID", FAILURE_CLASSIFICATION_INVALID: "EVIDENCE_INVALID",
    CONTRACT_GATE_INVALID: "CONTRACT_UNSATISFIABLE", CONTRACT_GATE_BLOCKED: "CONTRACT_UNSATISFIABLE", ROUTE_INVENTORY_INVALID: "ROUTE_UNAVAILABLE",
    ROUTE_LIMIT_EXHAUSTED: "BUDGET_EXHAUSTED", M5_DECISION_INVALID: "EVIDENCE_INVALID", M5_AUTHORITY_INCOMPLETE: "CONTEXT_MISSING",
    M5_EVIDENCE_PUBLICATION_FAILED: "EVIDENCE_PUBLICATION_FAILURE", M5_STATE_PUBLICATION_FAILED: "STATE_PUBLICATION_FAILURE",
  });
  for (const [code, failureClass] of Object.entries(reviewedCorrections)) resolved.set(code, failureClass);
  return buildLowerLayerFailureMap([...resolved.entries()]);
})();
const FAILURE_SOURCE_LAYERS = ["M1", "M2", "M3", "M4", "M5", "CONTROLLER"] as const;
type FailureSourceLayer = (typeof FAILURE_SOURCE_LAYERS)[number];
export function buildLayeredLowerLayerFailureMap(definitions: readonly (readonly [FailureSourceLayer, string, FailureClass])[]): Readonly<Record<string, FailureClass>> {
  const entries = new Map<string, FailureClass>();
  for (const [layer, code, failureClass] of definitions) {
    const exact = `${layer}:${code}`;
    if (entries.has(exact)) throw controlError("FAILURE_CLASSIFICATION_INVALID", `Duplicate lower-layer failure mapping for ${exact}`);
    entries.set(exact, failureClass);
  }
  return Object.freeze(Object.fromEntries(entries));
}
const LAYERED_LOWER_LAYER_MAP = buildLayeredLowerLayerFailureMap(FAILURE_SOURCE_LAYERS.flatMap((layer) => Object.entries(EXPLICIT_LOWER_LAYER_MAP).map(([code, failureClass]) => [layer, code, failureClass] as const)));
export const M5_LOWER_LAYER_FAILURE_CODES = Object.freeze(Object.keys(EXPLICIT_LOWER_LAYER_MAP).sort());
export const M5_LOWER_LAYER_FAILURE_MAPPING = EXPLICIT_LOWER_LAYER_MAP;

/** Package-private finite lower-layer mapping. Unknown codes fail closed as invalid evidence. */
export function mapLowerLayerFailureCode(code: string, sourceLayer: FailureSourceLayer = "CONTROLLER"): FailureClass {
  return LAYERED_LOWER_LAYER_MAP[`${sourceLayer}:${code}`] ?? "EVIDENCE_INVALID";
}

function compare(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function checkedAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw controlError("BUDGET_EVALUATION_INVALID", "Usage arithmetic exceeds the safe-integer range");
  return result;
}
function sortedUnique(values: readonly string[]): string[] { return [...new Set(values)].sort(compare); }
function recordIdentity(value: object): Sha256Digest { return sha256Canonical(value) as Sha256Digest; }

/** Package-private explicit predecessor chronology. Content-addressed filenames never define order. */
export function orderDecisionHistory(values: readonly M5ControlDecisionDocument[]): readonly M5ControlDecisionDocument[] {
  if (values.length === 0) return [];
  const byDigest = new Map<string, M5ControlDecisionDocument>();
  const runId = values[0]!.run_id;
  const policyId = values[0]!.policy_content_sha256;
  for (const value of values) {
    if (value.run_id !== runId || value.policy_content_sha256 !== policyId) {
      throw controlError("M5_DECISION_INVALID", "Decision history crosses run or policy authority");
    }
    if (byDigest.has(value.content_sha256)) throw controlError("M5_DECISION_INVALID", "Decision history contains a duplicate identity");
    byDigest.set(value.content_sha256, value);
  }
  const successors = new Map<string, M5ControlDecisionDocument>();
  const roots: M5ControlDecisionDocument[] = [];
  for (const value of values) {
    const prior = value.prior_relevant_decision_content_sha256;
    if (prior === null) roots.push(value);
    else {
      if (!byDigest.has(prior)) throw controlError("M5_AUTHORITY_INCOMPLETE", "Decision predecessor is missing");
      if (successors.has(prior)) throw controlError("M5_DECISION_INVALID", "Decision history branches from one predecessor");
      successors.set(prior, value);
    }
  }
  if (roots.length === 0) throw controlError("M5_DECISION_INVALID", "Decision history has no explicit root");
  const visited = new Set<string>();
  const chains = roots.map((root) => {
    const chain: M5ControlDecisionDocument[] = [];
    const local = new Set<string>();
    let cursor: M5ControlDecisionDocument | undefined = root;
    while (cursor !== undefined) {
      if (local.has(cursor.content_sha256)) throw controlError("M5_DECISION_INVALID", "Decision history is cyclic");
      local.add(cursor.content_sha256); visited.add(cursor.content_sha256); chain.push(cursor); cursor = successors.get(cursor.content_sha256);
    }
    return chain;
  }).sort((left, right) => right.length - left.length);
  if (visited.size !== values.length) throw controlError("M5_DECISION_INVALID", "Decision history is cyclic or disconnected");
  if (chains.length > 1 && chains[0]!.length === chains[1]!.length) {
    throw controlError("M5_DECISION_INVALID", "Decision history has ambiguous disconnected roots");
  }
  // A uniquely shorter disconnected component is an unrelated publication, not
  // chronology authority. The unique longest explicit predecessor chain wins.
  return chains[0]!;
}

function sourceProjection(sources: M5AuthoritativeSources | undefined): readonly Sha256Digest[] {
  if (sources === undefined) return [];
  // The bounded static controller deliberately excludes growing runtime sets so
  // later M3/M4 evidence cannot rewrite a historical request identity. Accepted
  // M5 behavior remains byte-for-byte unchanged for every other policy.
  const values = sources.boundedStaticPreM8 === true
    ? [sources.contract, sources.budget, sources.m4ToolPolicy, sources.m4CommandCatalog, sources.routeMap, sources.routeMapApproval,
      ...(sources.planApprovals ?? []), ...(sources.taskGraphs ?? []), ...(sources.tasks ?? [])]
    : Object.values(sources);
  const ids: Sha256Digest[] = [];
  for (const value of values) {
    if (Array.isArray(value)) for (const entry of value) if (entry !== null && typeof entry === "object" && "content_sha256" in entry) ids.push((entry as { content_sha256: Sha256Digest }).content_sha256);
    else if (value !== null && typeof value === "object" && "content_sha256" in value) ids.push((value as { content_sha256: Sha256Digest }).content_sha256);
  }
  return sortedUnique(ids) as Sha256Digest[];
}

/** Package-private complete canonical request identity shared by evaluation and lost-response handling. */
export function controlRequestKey(request: EvaluateControlDecisionInput, transitionEventId: string | null, usageIds: readonly Sha256Digest[]): Sha256Digest {
  return sha256Canonical({
    expectedWorkflowStateContentSha256: request.expectedWorkflowStateContentSha256,
    intent: request.intent, transitionId: transitionEventId, operationId: request.operationId ?? null,
    authoritativeSources: sourceProjection(request.authoritativeSources), usage: [...usageIds].sort(compare),
    progress: request.progressEvidence ?? null,
    failures: (request.failures ?? []).map((failure) => ({
      sourceLayer: failure.sourceLayer, sourceErrorCode: failure.sourceErrorCode, sourceRecordContentSha256: failure.sourceRecordContentSha256,
      normalizedSignature: failure.normalizedSignature, operationId: failure.operationId ?? null, scopeIdentity: failure.scopeIdentity ?? null,
      pathIdentity: failure.pathIdentity ?? null, repositoryIdentity: failure.repositoryIdentity ?? null, worktreeKey: failure.worktreeKey ?? null,
      resolutionEvidenceContentSha256: failure.resolutionEvidenceContentSha256 ?? null,
    })),
    obligationEvidence: request.obligationEvidence ?? [], gateDetections: request.gateDetections ?? [],
    availableLogicalRoles: sortedUnique(request.availableLogicalRoles ?? []), requiredLogicalRole: request.requiredLogicalRole ?? null,
    blockReason: request.blockReason ?? null,
  }) as Sha256Digest;
}

const persistedBoundedWorkerSourceProvenance = new WeakSet<object>();

/** Internal capability marker: only persisted resolver reconstruction may supply bounded execution authority to M5. */
export function markPersistedBoundedWorkerAuthority<T extends M5AuthoritativeSources>(sources: T): T {
  persistedBoundedWorkerSourceProvenance.add(sources as object);
  return sources;
}

function hasPersistedBoundedWorkerAuthority(sources: M5AuthoritativeSources): boolean {
  return persistedBoundedWorkerSourceProvenance.has(sources as object);
}

export function assertUsageForPolicy(usage: M5UsageEvidenceDocument, policy: M5ControlPolicyDocument): void {
  try { assertDocumentValid("pi_gacw_m5_usage_evidence_v0", usage); }
  catch (error: unknown) { throw controlError("USAGE_EVIDENCE_INVALID", "Usage evidence failed validation", error); }
  if (usage.run_id !== policy.run_id || usage.policy_content_sha256 !== policy.content_sha256) {
    throw controlError("USAGE_EVIDENCE_INVALID", "Usage evidence belongs to another run or policy");
  }
}

function completeUsageSet(usage: readonly M5UsageEvidenceDocument[], policy: M5ControlPolicyDocument): readonly M5UsageEvidenceDocument[] {
  if (usage.length > policy.maximum_usage_records) throw controlError("USAGE_EVIDENCE_INVALID", "Usage record cap exceeded");
  const byOperation = new Map<string, M5UsageEvidenceDocument>();
  const byReservation = new Map<string, M5UsageEvidenceDocument>();
  const byContent = new Map<string, M5UsageEvidenceDocument>();
  for (const item of usage) {
    assertUsageForPolicy(item, policy);
    const prior = byOperation.get(item.operation_id);
    if (prior !== undefined && canonicalize(prior) !== canonicalize(item)) throw controlError("USAGE_EVIDENCE_INVALID", `Conflicting evidence for operation ${item.operation_id}`);
    if (item.reservation_decision_content_sha256 !== null) {
      const reservationPrior = byReservation.get(item.reservation_decision_content_sha256);
      if (reservationPrior !== undefined && canonicalize(reservationPrior) !== canonicalize(item)) throw controlError("USAGE_EVIDENCE_INVALID", "A reservation has more than one reconciliation");
      byReservation.set(item.reservation_decision_content_sha256, item);
    }
    byOperation.set(item.operation_id, item); byContent.set(item.content_sha256, item);
  }
  return [...byContent.values()].sort((a, b) => compare(a.content_sha256, b.content_sha256));
}

function assertBoundedWorkerUsage(item: M5UsageEvidenceDocument, result: BoundedWorkerResultDocument): void {
  const value = result.actual_usage;
  const expected = new Map<M5UsageEvidenceDocument["measurements"][number]["dimension"], number | null>([
    ["WORKER_INVOCATION", value.worker_invocations], ["TOOL_CALL", value.m4_tool_calls], ["MODEL_TURN", value.model_turns],
    ["PROVIDER_REQUEST", value.provider_requests], ["INPUT_TOKEN", value.input_tokens], ["OUTPUT_TOKEN", value.output_tokens],
    ["COST_MICROUSD", value.cost_microusd], ["WALL_TIME_MS", value.wall_time_ms],
  ]);
  if (item.operation_kind !== "WORKER_INVOCATION" || item.disposition !== "COMPLETED" || item.duration_ms !== value.wall_time_ms ||
      item.measurements.length !== expected.size || new Set(item.measurements.map((entry) => entry.dimension)).size !== expected.size) {
    throw controlError("USAGE_EVIDENCE_INVALID", "Bounded worker usage does not describe one settled exact worker invocation");
  }
  for (const measurement of item.measurements) {
    if (!expected.has(measurement.dimension) || measurement.amount !== expected.get(measurement.dimension)) {
      throw controlError("USAGE_EVIDENCE_INVALID", "Bounded worker usage differs from exact durable telemetry");
    }
  }
}

function assertUsageSourceAuthority(
  usage: readonly M5UsageEvidenceDocument[], policy: M5ControlPolicyDocument, state: WorkflowState,
  priorDecisions: readonly M5ControlDecisionDocument[], sources: M5AuthoritativeSources, input: EvaluateControlDecisionInput,
): void {
  const sourceKinds = new Map<string, { readonly kind: string; readonly layer: M5UsageEvidenceDocument["source_layer"] }>();
  const boundedWorkerResults = new Map<string, BoundedWorkerResultDocument>();
  for (const result of sources.boundedWorkerResults ?? []) {
    const prior = boundedWorkerResults.get(result.content_sha256);
    if (prior !== undefined && canonicalize(prior) !== canonicalize(result)) throw controlError("USAGE_EVIDENCE_INVALID", "Bounded worker source identity is ambiguous");
    boundedWorkerResults.set(result.content_sha256, result);
  }
  const add = (digest: string, kind: string, layer: M5UsageEvidenceDocument["source_layer"]): void => {
    const prior = sourceKinds.get(digest);
    if (prior !== undefined && (prior.kind !== kind || prior.layer !== layer)) throw controlError("USAGE_EVIDENCE_INVALID", "A source identity aliases different stored record kinds");
    sourceKinds.set(digest, { kind, layer });
  };
  add(policy.content_sha256, "M5_CONTROL_POLICY", "M5"); add(state.content_sha256, "WORKFLOW_STATE", "M1");
  for (const value of priorDecisions) add(value.content_sha256, "M5_CONTROL_DECISION", "M5");
  const singular: readonly [object | undefined, string, M5UsageEvidenceDocument["source_layer"]][] = [
    [sources.contract, "CONTRACT", "M1"], [sources.budget, "BUDGET", "M1"], [sources.m4ToolPolicy, "M4_TOOL_POLICY", "M4"],
    [sources.m4CommandCatalog, "M4_COMMAND_CATALOG", "M4"], [sources.routeMap, "ROUTE_MAP", "M1"], [sources.routeMapApproval, "ROUTE_MAP_APPROVAL", "M1"],
  ];
  for (const [value, kind, layer] of singular) if (value !== undefined && "content_sha256" in value) add(String((value as { content_sha256: string }).content_sha256), kind, layer);
  const groups: readonly [readonly { readonly content_sha256: string }[] | undefined, string, M5UsageEvidenceDocument["source_layer"]][] = [
    [sources.m4CommandResults, "M4_COMMAND_RESULT", "M4"], [sources.boundedWorkerResults, "BOUNDED_WORKER_RESULT", "CONTROLLER"], [sources.m3StateTokens, "M3_REPOSITORY_STATE_TOKEN", "M3"],
    [sources.m3Postflights, "M3_POSTFLIGHT", "M3"], [sources.workflowStates, "WORKFLOW_STATE", "M1"],
    [sources.transitionEvents, "TRANSITION_EVENT", "M1"], [sources.transitionCommits, "TRANSITION_COMMIT", "M2"],
    [sources.planApprovals, "PLAN_APPROVAL", "M1"], [sources.taskGraphs, "TASK_GRAPH", "M1"], [sources.tasks, "TASK", "M1"],
  ];
  for (const [values, kind, layer] of groups) for (const value of values ?? []) add(value.content_sha256, kind, layer);
  for (const item of usage) {
    const source = sourceKinds.get(item.source_record_content_sha256);
    if (source === undefined) throw controlError("USAGE_EVIDENCE_INVALID", "Usage evidence source is not an exact authoritative predecessor");
    if (item.source_kind !== source.kind || item.source_layer !== source.layer) throw controlError("USAGE_EVIDENCE_INVALID", "Usage source kind or layer differs from the loaded predecessor");
    if (source.kind === "BOUNDED_WORKER_RESULT" && source.layer === "CONTROLLER") {
      const result = boundedWorkerResults.get(item.source_record_content_sha256);
      if (result === undefined) throw controlError("USAGE_EVIDENCE_INVALID", "Bounded worker usage source is absent");
      assertBoundedWorkerUsage(item, result);
    }
    const admittedStates = new Set([state.content_sha256, ...priorDecisions.map((decision) => decision.current_state_content_sha256)]);
    if (item.reservation_decision_content_sha256 === null && !admittedStates.has(item.originating_state_content_sha256)) throw controlError("USAGE_EVIDENCE_INVALID", "Unreserved usage does not originate at the current state or an exact predecessor admission state");
    if (item.execution_mode !== null && item.execution_mode !== state.execution_mode) throw controlError("USAGE_EVIDENCE_INVALID", "Usage execution mode differs from committed route authority");
    if (item.logical_role !== null && !policy.role_reservation_envelopes.some((envelope) => envelope.logical_role === item.logical_role)) throw controlError("USAGE_EVIDENCE_INVALID", "Usage logical role lacks policy-bound route authority");
    if (item.reservation_decision_content_sha256 !== null && (item.execution_mode === null || item.logical_role === null)) throw controlError("USAGE_EVIDENCE_INVALID", "Reserved usage must bind execution mode and logical role");
  }
}

function assertBlockedBoundedWorkerTerminalRequest(
  request: EvaluateControlDecisionInput,
  policy: M5ControlPolicyDocument,
  priorDecisions: readonly M5ControlDecisionDocument[],
  sources: M5AuthoritativeSources,
): void {
  const blocked = (sources.boundedWorkerResults ?? []).filter((result) => result.outcome === "BLOCKED");
  if (blocked.length === 0) return;
  if (!hasPersistedBoundedWorkerAuthority(sources)) {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal refusal authority must come from persisted sole-resolver reconstruction");
  }
  if (blocked.length !== 1 || new Set(blocked.map((result) => result.content_sha256)).size !== 1) {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal refusal authority is ambiguous");
  }
  const result = blocked[0]!;
  if (!result.cleanup_certain || result.actual_usage.worker_invocations !== 1 || result.first_failure_code === null ||
      result.first_failure_stage !== BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE) {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal refusal lacks settled durable failure authority");
  }
  if (request.intent !== "BLOCK") {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "A resolved bounded terminal refusal can only consume M5 BLOCK authority");
  }
  const supplied = request.failures ?? [];
  if (supplied.length !== 1) throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal BLOCK requires one exact refusal failure");
  const failure = supplied[0]!;
  if (failure.sourceLayer !== "CONTROLLER" || failure.sourceRecordContentSha256 !== result.content_sha256 ||
      failure.sourceErrorCode !== result.first_failure_code || failure.operationId === undefined || request.operationId !== failure.operationId ||
      failure.scopeIdentity !== policy.scope_sha256 || failure.repositoryIdentity !== policy.repository_identity_content_sha256 || failure.worktreeKey !== policy.worktree_key) {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal BLOCK failure does not bind the exact result identity");
  }
  const reservations = priorDecisions.filter((decision) => decision.outcome === "AUTHORIZE" && decision.operation_id === failure.operationId &&
    decision.reservation !== null && decision.reservation.future_operation_id === failure.operationId);
  if (reservations.length !== 1) throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal BLOCK lacks one exact reservation predecessor");
  const reservation = reservations[0]!;
  const expectedSignature = sha256Canonical({
    protocol: "bounded-worker-terminal-refusal-v1",
    bounded_worker_result_content_sha256: result.content_sha256,
    first_failure_code: result.first_failure_code,
    first_failure_stage: result.first_failure_stage,
    operation_id: failure.operationId,
    reservation_decision_content_sha256: reservation.content_sha256,
  });
  if (failure.normalizedSignature !== expectedSignature) {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "Bounded terminal BLOCK failure does not bind the exact reservation and failure provenance");
  }
}

function minDefined(values: readonly (number | null | undefined)[]): number | null {
  const defined = values.filter((value): value is number => value !== null && value !== undefined);
  return defined.length === 0 ? null : Math.min(...defined);
}

export function assertAuthoritativeSources(policy: M5ControlPolicyDocument, sources: M5AuthoritativeSources | undefined, strict: boolean): M5AuthoritativeSources {
  const actual = sources ?? {};
  const missing = strict ? [
    actual.contract === undefined ? "contract" : null,
    actual.budget === undefined ? "budget" : null,
    actual.m4ToolPolicy === undefined ? "m4 tool policy" : null,
    actual.m4CommandCatalog === undefined ? "M4 command catalog" : null,
    actual.routeMap === undefined ? "route map" : null,
    actual.routeMapApproval === undefined ? "route-map approval" : null,
  ].filter((value): value is string => value !== null) : [];
  if (missing.length > 0) throw controlError("M5_AUTHORITY_INCOMPLETE", `Missing authoritative predecessor records: ${missing.join(", ")}`);
  const validate = (schema: Parameters<typeof assertDocumentValid>[0], value: object | undefined, label: string): void => {
    if (value === undefined) return;
    try { assertDocumentValid(schema, value); }
    catch (error: unknown) { throw controlError("M5_AUTHORITY_INCOMPLETE", `${label} is not authoritative`, error); }
  };
  validate("pi_gacw_contract_v0", actual.contract, "Contract authority");
  validate("pi_gacw_budget_v0", actual.budget, "Budget authority");
  validate("pi_gacw_scoped_tool_policy_v0", actual.m4ToolPolicy, "M4 tool-policy authority");
  validate("pi_gacw_command_catalog_v0", actual.m4CommandCatalog, "M4 command-catalog authority");
  validate("pi_gacw_route_map_v0", actual.routeMap, "Route-map authority");
  validate("pi_gacw_route_map_approval_v0", actual.routeMapApproval, "Route-map approval authority");
  for (const result of actual.m4CommandResults ?? []) validate("pi_gacw_command_result_v0", result, "M4 command result");
  for (const result of actual.boundedWorkerResults ?? []) validate("pi_gacw_bounded_worker_result_v0", result, "Bounded worker result");
  for (const token of actual.m3StateTokens ?? []) validate("pi_gacw_repository_state_token_v0", token, "M3 state-token authority");
  for (const postflight of actual.m3Postflights ?? []) validate("pi_gacw_postflight_v0", postflight, "M3 postflight authority");
  for (const state of actual.workflowStates ?? []) validate("pi_gacw_state_v0", state, "Workflow-state authority");
  for (const event of actual.transitionEvents ?? []) validate("pi_gacw_transition_event_v0", event, "Transition-event authority");
  for (const commit of actual.transitionCommits ?? []) validate("pi_gacw_state_transition_commit_v0", commit, "Transition-commit authority");
  for (const approval of actual.planApprovals ?? []) validate("pi_gacw_plan_approval_v0", approval, "Plan-approval authority");
  for (const graph of actual.taskGraphs ?? []) validate("pi_gacw_task_graph_v0", graph, "Task-graph authority");
  for (const approval of actual.planApprovals ?? []) if (policy.plan_approval_sha256 === null || approval.plan_approval_sha256 !== policy.plan_approval_sha256) throw controlError("M5_AUTHORITY_INCOMPLETE", "Plan-approval authority identity differs from M5 policy");
  for (const graph of actual.taskGraphs ?? []) if (policy.task_graph_sha256 === null || graph.task_graph_sha256 !== policy.task_graph_sha256) throw controlError("M5_AUTHORITY_INCOMPLETE", "Task-graph authority identity differs from M5 policy");
  for (const task of actual.tasks ?? []) validate("pi_gacw_task_v0", task, "Task authority");
  for (const token of actual.m3StateTokens ?? []) if (token.run_id !== policy.run_id || token.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 || token.worktree_key !== policy.worktree_key || token.task_scope_identity !== policy.scope_sha256) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "M3 state-token authority identity differs from M5 policy");
  }
  for (const postflight of actual.m3Postflights ?? []) if (postflight.run_id !== policy.run_id || postflight.scope.scope_identity !== policy.scope_sha256) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "M3 postflight authority identity differs from M5 policy");
  }
  for (const result of actual.m4CommandResults ?? []) if (result.run_id !== policy.run_id || result.command_catalog_content_sha256 !== policy.command_catalog_content_sha256) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "M4 command-result authority identity differs from M5 policy");
  }
  if (actual.contract !== undefined && (actual.contract.contract_sha256 !== policy.contract_sha256 ||
      actual.contract.objective_sha256 !== policy.objective_sha256 || actual.contract.baseline_approval_sha256 !== policy.baseline_approval_sha256 ||
      actual.contract.authority_lock_sha256 !== policy.authority_lock_sha256 || actual.contract.route_map_approval_sha256 !== policy.route_map_approval_sha256 ||
      (policy.requested_mode !== "AUTO" && actual.contract.execution_mode !== policy.requested_mode))) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Contract authority identity differs from M5 policy");
  }
  if (actual.budget !== undefined && actual.budget.budget_sha256 !== policy.budget_sha256) throw controlError("M5_AUTHORITY_INCOMPLETE", "Budget authority identity differs from M5 policy");
  if (actual.m4ToolPolicy !== undefined && (actual.m4ToolPolicy.content_sha256 !== policy.tool_policy_content_sha256 || actual.m4ToolPolicy.run_id !== policy.run_id || actual.m4ToolPolicy.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 || actual.m4ToolPolicy.worktree_key !== policy.worktree_key || actual.m4ToolPolicy.task_scope_identity !== policy.scope_sha256)) throw controlError("M5_AUTHORITY_INCOMPLETE", "M4 tool-policy authority identity differs from M5 policy");
  if (actual.m4CommandCatalog !== undefined && (actual.m4CommandCatalog.content_sha256 !== policy.command_catalog_content_sha256 || actual.m4CommandCatalog.run_id !== policy.run_id || actual.m4CommandCatalog.repository_identity_content_sha256 !== policy.repository_identity_content_sha256 || actual.m4CommandCatalog.tool_policy_content_sha256 !== policy.tool_policy_content_sha256)) throw controlError("M5_AUTHORITY_INCOMPLETE", "M4 command-catalog authority identity differs from M5 policy");
  if (actual.routeMap !== undefined && actual.routeMap.route_map_sha256 !== policy.route_map_sha256) throw controlError("M5_AUTHORITY_INCOMPLETE", "Route-map authority identity differs from M5 policy");
  if (actual.routeMapApproval !== undefined && (actual.routeMapApproval.route_map_approval_sha256 !== policy.route_map_approval_sha256 || actual.routeMapApproval.route_map_sha256 !== policy.route_map_sha256 || actual.routeMapApproval.approved_by.length === 0)) throw controlError("M5_AUTHORITY_INCOMPLETE", "Route-map approval identity differs from M5 policy");
  return actual;
}

function isBoundedStaticPreM8(policy: M5ControlPolicyDocument): boolean {
  const worker = policy.limits.find((entry) => entry.dimension === "WORKER_INVOCATION");
  const model = policy.limits.find((entry) => entry.dimension === "MODEL_TURN");
  const expectedWorkerLimit = policy.requested_mode === "STATIC_APPROVED_DAG"
    ? [policy.route_facts.leaf_count, policy.route_facts.leaf_count * 2]
    : [policy.route_facts.leaf_count + (policy.requested_mode === "ROUTED_DAG" ? 2 : 0)];
  return expectedWorkerLimit.includes(worker?.hard_limit ?? -1) &&
    model?.enforcement_class === "SOFT_ENFORCEABLE" && model.hard_limit === null &&
    policy.role_reservation_envelopes.every((entry) => entry.logical_role !== "SOL_REPLAN");
}

function sourceHardLimits(
  dimension: (typeof DIMENSIONS)[number],
  state: WorkflowState,
  reducer: ReducerPolicy,
  sources: M5AuthoritativeSources,
): readonly (number | null)[] {
  const boundedStaticRouted = reducer.limits.max_attempts_per_leaf === 1 && reducer.limits.max_replans === 0 &&
    reducer.limits.max_worker_invocations === reducer.tasks.length + 2;
  const architecture = dimension === "WORKER_INVOCATION"
    ? state.execution_mode === "DIRECT_LUNA_HIGH" ? 2 : state.execution_mode === "SINGLE_OWNER_SOL" ? 1
      : boundedStaticRouted ? Math.min(20, reducer.tasks.length + 2) : Math.min(20, 2 * reducer.tasks.length + 4)
    : null;
  const m1 = dimension === "WORKER_INVOCATION" ? reducer.limits.max_worker_invocations : null;
  const contract = sources.contract?.limits;
  const budget = sources.budget?.limits;
  const fromEnvelope = (envelope: typeof contract): number | null => {
    if (envelope === undefined) return null;
    if (dimension === "WORKER_INVOCATION") return envelope.max_worker_invocations;
    if (dimension === "MODEL_TURN") return envelope.max_model_turns;
    if (dimension === "TOOL_CALL") return envelope.max_tool_calls;
    if (dimension === "INPUT_TOKEN") return envelope.max_input_tokens;
    if (dimension === "OUTPUT_TOKEN") return envelope.max_output_tokens;
    if (dimension === "COST_MICROUSD") return envelope.max_cost_microusd;
    if (dimension === "WALL_TIME_MS") return envelope.max_wall_time_ms;
    return null;
  };
  const m4 = dimension === "WALL_TIME_MS" ? sources.m4ToolPolicy?.limits.maximum_command_duration_ms ?? null : null;
  return [architecture, m1, fromEnvelope(contract), fromEnvelope(budget), m4];
}

const ENFORCEMENT_STRENGTH = Object.freeze({ UNAVAILABLE: 0, ESTIMATED_ONLY: 1, OBSERVABLE_ONLY: 2, SOFT_ENFORCEABLE: 3, HARD_ENFORCEABLE: 4 } as const);
function effectiveEnforcementClass(
  declared: M5ControlPolicyDocument["limits"][number]["enforcement_class"],
  authoritativeHardLimits: readonly (number | null)[],
  boundedStaticPreM8: boolean,
): BudgetEntry["enforcement_class"] {
  // A declared SOFT class is deliberate telemetry reconciliation authority only
  // for the new bounded path. Existing M5 policies retain lower-layer upgrades.
  if (boundedStaticPreM8 && declared === "SOFT_ENFORCEABLE") return declared;
  const lower = authoritativeHardLimits.some((value) => value !== null) ? "HARD_ENFORCEABLE" as const : "UNAVAILABLE" as const;
  return ENFORCEMENT_STRENGTH[lower] > ENFORCEMENT_STRENGTH[declared] ? lower : declared;
}

function aggregateBudget(
  policy: M5ControlPolicyDocument,
  state: WorkflowState,
  reducer: ReducerPolicy,
  usage: readonly M5UsageEvidenceDocument[],
  priorDecisions: readonly M5ControlDecisionDocument[],
  candidateReservation: M5ControlDecisionDocument["reservation"],
  sources: M5AuthoritativeSources,
  allowHistoricalReservationOverflow = false,
): readonly BudgetEntry[] {
  const boundedStaticPreM8 = isBoundedStaticPreM8(policy);
  const reconciliations = new Map<string, M5UsageEvidenceDocument>();
  for (const item of usage) {
    if (item.reservation_decision_content_sha256 === null) continue;
    const prior = reconciliations.get(item.reservation_decision_content_sha256);
    if (prior !== undefined && canonicalize(prior) !== canonicalize(item)) throw controlError("USAGE_EVIDENCE_INVALID", "A reservation has conflicting reconciliation evidence");
    reconciliations.set(item.reservation_decision_content_sha256, item);
  }
  for (const item of usage) {
    if (item.reservation_decision_content_sha256 === null) continue;
    const reservedBy = priorDecisions.find((entry) => entry.content_sha256 === item.reservation_decision_content_sha256);
    if (reservedBy?.reservation === undefined || reservedBy.reservation === null || reservedBy.run_id !== policy.run_id ||
        reservedBy.reservation.future_operation_id !== item.operation_id || reservedBy.reservation.reserved_policy_content_sha256 !== policy.content_sha256 ||
        reservedBy.reservation.reserved_state_content_sha256 !== item.originating_state_content_sha256 || reservedBy.reservation.reserved_route !== item.execution_mode ||
        item.originating_state_content_sha256 !== reservedBy.current_state_content_sha256 ||
        reservedBy.reservation.logical_role !== item.logical_role) {
      throw controlError("USAGE_EVIDENCE_INVALID", "Usage reconciliation does not bind the exact reservation, state, route, and role");
    }
  }
  return DIMENSIONS.map((dimension) => {
    const declared = policy.limits.find((entry) => entry.dimension === dimension)!;
    const lowerHardLimits = sourceHardLimits(dimension, state, reducer, sources);
    // The bounded controller's numeric telemetry envelopes do not upgrade a
    // declared soft dimension into a hard provider/process authority.
    const hardLimit = boundedStaticPreM8 && declared.enforcement_class === "SOFT_ENFORCEABLE"
      ? declared.hard_limit
      : minDefined([...lowerHardLimits, declared.hard_limit]);
    const contractSoft = dimension === "WORKER_INVOCATION" ? null : null;
    const softLimit = minDefined([declared.soft_limit, contractSoft, hardLimit]);
    let validated = 0; let observed = 0; let estimated = 0; let active = 0; let reconciled = 0;
    for (const operation of usage) for (const measurement of operation.measurements) {
      if (measurement.dimension !== dimension || measurement.amount === null) continue;
      if (measurement.basis === "VALIDATED") validated = checkedAdd(validated, measurement.amount);
      else if (measurement.basis === "OBSERVED" || measurement.basis === "REPORTED") observed = checkedAdd(observed, measurement.amount);
      else if (measurement.basis === "ESTIMATED") estimated = checkedAdd(estimated, measurement.amount);
    }
    for (const decision of priorDecisions) {
      const reservation = decision.reservation;
      if (reservation === null) continue;
      const amount = reservation.amounts.find((entry) => entry.dimension === dimension)?.amount ?? 0;
      const outcomes = usage.filter((entry) => entry.reservation_decision_content_sha256 === decision.content_sha256);
      if (outcomes.some((entry) => entry.disposition === "COMPLETED" || entry.disposition === "NOT_STARTED" || entry.disposition === "BLOCKED_BEFORE_START")) reconciled = checkedAdd(reconciled, amount);
      else active = checkedAdd(active, amount);
    }
    if (candidateReservation !== null) active = checkedAdd(active, candidateReservation.amounts.find((entry) => entry.dimension === dimension)?.amount ?? 0);
    const measured = checkedAdd(validated, observed);
    const opening = dimension === "WORKER_INVOCATION" ? state.counters.worker_invocations.total : 0;
    const charged = Math.max(opening, measured);
    const authorityAmount = checkedAdd(charged, active);
    const enforcement = effectiveEnforcementClass(declared.enforcement_class, lowerHardLimits, boundedStaticPreM8);
    const enforceable = ["HARD_ENFORCEABLE", "SOFT_ENFORCEABLE"].includes(enforcement);
    // An unresolved historical reservation can overlap a state counter that
    // already reflects its admission. Bounded terminal BLOCK may snapshot that
    // fail-closed condition so it can terminalize/reconcile; all other paths
    // retain the existing arithmetic rejection.
    if (hardLimit !== null && authorityAmount > hardLimit && enforceable && !allowHistoricalReservationOverflow) throw controlError("BUDGET_EXHAUSTED", `${dimension} reservation exceeds the effective hard limit`);
    const hardRemaining = hardLimit === null ? null : Math.max(0, hardLimit - authorityAmount);
    const softRemaining = softLimit === null ? null : Math.max(0, softLimit - authorityAmount);
    const status: BudgetEntry["status"] = enforcement === "UNAVAILABLE" ? "UNAVAILABLE"
      : hardLimit !== null && authorityAmount >= hardLimit ? "HARD_LIMIT_REACHED"
      : softLimit !== null && authorityAmount >= softLimit ? "SOFT_LIMIT_REACHED" : "BELOW_SOFT_LIMIT";
    return { dimension, hard_limit: hardLimit, soft_limit: softLimit, opening_amount: enforcement === "UNAVAILABLE" ? null : opening,
      validated_amount: validated, observed_reported_amount: observed, estimated_amount: estimated, active_reservation_amount: active,
      reconciled_amount: reconciled, effective_charged_amount: charged, hard_remaining: hardRemaining, soft_remaining: softRemaining,
      enforcement_class: enforcement, status };
  });
}

function progressEvaluation(
  input: EvaluateControlDecisionInput,
  policy: M5ControlPolicyDocument,
  state: WorkflowState,
  reducer: ReducerPolicy,
  usage: readonly M5UsageEvidenceDocument[],
  priorDecisions: readonly M5ControlDecisionDocument[],
  sources: M5AuthoritativeSources,
): M5ControlDecisionDocument["progress"] {
  const strictAuthority = policy.production_authority === "OWNER_APPROVED";
  const claim = input.progressEvidence;
  const evidence = sortedUnique(claim?.evidenceContentSha256 ?? []) as Sha256Digest[];
  const claimedKind = claim?.claimedKind ?? null;
  const prior = claim?.priorStateOrDecisionContentSha256 === undefined ? undefined : priorDecisions.find((entry) => entry.content_sha256 === claim.priorStateOrDecisionContentSha256);
  const priorEvidence = new Set(priorDecisions.flatMap((entry) => entry.progress.evidence_content_sha256));
  const sourceEvidence = new Set([
    policy.content_sha256, reducer.content_sha256, policy.plan_approval_sha256, state.content_sha256,
    ...usage.map((entry) => entry.source_record_content_sha256),
    ...(sources.m4CommandResults ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.boundedWorkerResults ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.m4CommandCatalog === undefined ? [] : [sources.m4CommandCatalog.content_sha256 as Sha256Digest]),
    ...(sources.m3StateTokens ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.m3Postflights ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.workflowStates ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.transitionEvents ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.transitionCommits ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.planApprovals ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.taskGraphs ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...(sources.tasks ?? []).map((entry) => entry.content_sha256 as Sha256Digest),
    ...priorDecisions.map((entry) => entry.content_sha256 as Sha256Digest),
  ].filter((value): value is Sha256Digest => value !== null));
  const everyEvidenceAuthoritative = evidence.length > 0 && evidence.every((digest) => sourceEvidence.has(digest));
  const failureSame = (input.failures ?? []).some((failure) => priorDecisions.at(-1)?.failures.some((previous) => previous.normalized_signature === failure.normalizedSignature) === true);
  const repeatedTest = evidence.some((digest) => priorEvidence.has(digest));
  const sourceFor = (digest: Sha256Digest): boolean => sourceEvidence.has(digest);
  let validProgress = false;
  let permittedNoProgressReason: M5ControlDecisionDocument["progress"]["no_progress_reason"] = null;
  if (claimedKind === "STATE_TRANSITION") {
    const commit = sources.transitionCommits?.find((candidate) => candidate.new_workflow_state_content_sha256 === state.content_sha256 &&
      (prior === undefined || candidate.previous_workflow_state_content_sha256 === prior.current_state_content_sha256) && evidence.includes(candidate.content_sha256 as Sha256Digest));
    const event = commit === undefined ? undefined : sources.transitionEvents?.find((candidate) => candidate.content_sha256 === commit.transition_event_content_sha256);
    const predecessorState = commit === undefined ? undefined : sources.workflowStates?.find((candidate) => candidate.content_sha256 === commit.previous_workflow_state_content_sha256);
    const reduced = commit !== undefined && event !== undefined && predecessorState !== undefined ? (() => { try { return reduceState(predecessorState, event, reducer); } catch { return null; } })() : null;
    validProgress = commit !== undefined && event !== undefined && reduced?.content_sha256 === state.content_sha256;
    if (!strictAuthority && sources.transitionCommits === undefined && prior !== undefined) validProgress = prior.predicted_next_state_content_sha256 === state.content_sha256 && evidence.includes(prior.content_sha256 as Sha256Digest);
  } else if (claimedKind === "APPROVED_PLAN_REVISION") {
    validProgress = (sources.planApprovals ?? []).some((approval) => evidence.includes(approval.content_sha256 as Sha256Digest) && approval.content_sha256 !== policy.plan_approval_sha256 && claim?.priorStateOrDecisionContentSha256 !== undefined);
    if (!strictAuthority && sources.planApprovals === undefined) validProgress = policy.plan_approval_sha256 !== null && evidence.includes(policy.plan_approval_sha256 as Sha256Digest) && claim?.priorStateOrDecisionContentSha256 !== undefined;
  } else if (claimedKind === "VALID_REPOSITORY_DELTA") {
    const postflight = (sources.m3Postflights ?? []).find((entry) => evidence.includes(entry.content_sha256 as Sha256Digest));
    const token = (sources.m3StateTokens ?? []).find((entry) => evidence.includes(entry.content_sha256 as Sha256Digest) && entry.source === "POSTFLIGHT");
    validProgress = postflight !== undefined && token !== undefined && token.source_content_sha256 === postflight.content_sha256 && postflight.workflow_owned_delta.length > 0 && postflight.blockers.length === 0;
    if (!validProgress && postflight !== undefined && everyEvidenceAuthoritative && postflight.blockers.length > 0) permittedNoProgressReason = "OUT_OF_SCOPE_PATCH";
  } else if (claimedKind === "NEW_TEST_EVIDENCE") {
    const result = (sources.m4CommandResults ?? []).find((entry) => evidence.includes(entry.content_sha256 as Sha256Digest) && entry.command_class === "VERIFICATION");
    const catalogEntry = result === undefined ? undefined : sources.m4CommandCatalog?.commands.find((command) => command.command_id === result.command_id && command.command_spec_sha256 === result.command_spec_sha256 && command.command_class === "VERIFICATION");
    const testEvidenceReady = result !== undefined && catalogEntry !== undefined && everyEvidenceAuthoritative;
    validProgress = testEvidenceReady && !repeatedTest;
    if (!validProgress && testEvidenceReady && repeatedTest) permittedNoProgressReason = "REPEATED_TEST_WITH_NO_NEW_EVIDENCE";
  } else if (claimedKind === "EVIDENCE_BACKED_DIAGNOSIS") {
    validProgress = everyEvidenceAuthoritative && (input.failures ?? []).some((entry) => evidence.includes(entry.sourceRecordContentSha256) && !priorEvidence.has(entry.sourceRecordContentSha256));
    if (!validProgress && everyEvidenceAuthoritative && failureSame) permittedNoProgressReason = "SAME_NORMALIZED_FAILURE_WITH_NO_DELTA";
  } else if (claimedKind === "FAILURE_RECLASSIFICATION") {
    const previous = priorDecisions.flatMap((entry) => entry.failures).find((failure) => failure.normalized_signature === claim?.priorFailureSignature);
    validProgress = previous !== undefined && everyEvidenceAuthoritative && claim?.currentFailureSignature !== undefined && claim.currentFailureSignature !== claim.priorFailureSignature &&
      (input.failures ?? []).some((entry) => entry.normalizedSignature === claim.currentFailureSignature && entry.resolutionEvidenceContentSha256 !== undefined && evidence.includes(entry.resolutionEvidenceContentSha256) && sourceFor(entry.resolutionEvidenceContentSha256));
  } else if (claimedKind === "CONTEXT_RESTORATION") {
    validProgress = prior !== undefined && prior.failures.some((failure) => failure.control_class === "CONTEXT_MISSING") && everyEvidenceAuthoritative && evidence.some((digest) => !priorEvidence.has(digest));
  } else if (claimedKind === "TERMINAL_RESULT") {
    const commit = (sources.transitionCommits ?? []).find((candidate) => candidate.new_workflow_state_content_sha256 === state.content_sha256 && evidence.includes(candidate.content_sha256 as Sha256Digest));
    validProgress = (state.phase === "PASS" || state.phase === "BLOCKED") && commit !== undefined;
  }
  if (claimedKind !== null && !validProgress && permittedNoProgressReason === null) throw controlError("PROGRESS_EVIDENCE_INVALID", `${claimedKind} lacks its required authoritative predecessor relationship`);
  let noProgressReason: M5ControlDecisionDocument["progress"]["no_progress_reason"] = null;
  if (!validProgress) {
    noProgressReason = permittedNoProgressReason ?? (claim === undefined ? failureSame ? "SAME_NORMALIZED_FAILURE_WITH_NO_DELTA" : "IDENTICAL_REPORT"
      : evidence.length === 0 ? "PROSE_WITHOUT_EVIDENCE"
        : failureSame ? "SAME_NORMALIZED_FAILURE_WITH_NO_DELTA"
          : repeatedTest ? "REPEATED_TEST_WITH_NO_NEW_EVIDENCE"
            : claimedKind === "VALID_REPOSITORY_DELTA" ? "OUT_OF_SCOPE_PATCH" : "IDENTICAL_REPORT");
    if (claim?.noProgressReason !== undefined && claim.noProgressReason !== null && claim.noProgressReason !== noProgressReason) throw controlError("PROGRESS_CLASSIFICATION_INVALID", "Caller no-progress reason differs from deterministic derivation");
  }
  return {
    classification: validProgress ? "PROGRESS" : "NO_PROGRESS", kind: validProgress ? claimedKind : null, no_progress_reason: noProgressReason,
    prior_state_or_decision_content_sha256: claim?.priorStateOrDecisionContentSha256 ?? null, evidence_content_sha256: evidence,
    evidence_set_sha256: sha256Canonical(evidence), prior_failure_signature: claim?.priorFailureSignature ?? null, current_failure_signature: claim?.currentFailureSignature ?? null,
  };
}

function classifyFailures(
  inputs: readonly M5FailureInput[],
  priorDecisions: readonly M5ControlDecisionDocument[],
): readonly M5ControlDecisionDocument["failures"][number][] {
  const currentBySignature = new Map<string, M5FailureInput>();
  for (const input of inputs) {
    const prior = currentBySignature.get(input.normalizedSignature);
    if (prior !== undefined && (prior.sourceLayer !== input.sourceLayer || prior.sourceErrorCode !== input.sourceErrorCode || prior.sourceRecordContentSha256 !== input.sourceRecordContentSha256 ||
        prior.operationId !== input.operationId || prior.scopeIdentity !== input.scopeIdentity || prior.pathIdentity !== input.pathIdentity || prior.repositoryIdentity !== input.repositoryIdentity || prior.worktreeKey !== input.worktreeKey)) {
      throw controlError("FAILURE_CLASSIFICATION_INVALID", "Distinct authority-relevant failures share one normalized signature");
    }
    currentBySignature.set(input.normalizedSignature, input);
  }
  const last = priorDecisions.at(-1);
  const failures = inputs.map((input) => {
    const collisions = priorDecisions.flatMap((decision) => decision.failures).filter((failure) => failure.normalized_signature === input.normalizedSignature &&
      (failure.source_layer !== input.sourceLayer || failure.source_error_code !== input.sourceErrorCode || failure.source_record_content_sha256 !== input.sourceRecordContentSha256 ||
       failure.operation_id !== input.operationId || failure.scope_identity !== (input.scopeIdentity ?? undefined) || failure.path_identity !== (input.pathIdentity ?? undefined) ||
       failure.repository_identity !== (input.repositoryIdentity ?? undefined) || failure.worktree_key !== (input.worktreeKey ?? undefined)));
    if (collisions.length > 0) throw controlError("FAILURE_CLASSIFICATION_INVALID", "Distinct authority-relevant failures share one normalized signature");
    const controlClass = mapLowerLayerFailureCode(input.sourceErrorCode, input.sourceLayer);
    const consecutive = last?.progress.classification !== "PROGRESS" && last?.failures.some((failure) => failure.normalized_signature === input.normalizedSignature && failure.resolution_evidence_content_sha256 === null) === true;
    const occurrence = input.resolutionEvidenceContentSha256 === undefined && consecutive
      ? Math.min(100_000, 1 + Math.max(...last!.failures.filter((failure) => failure.normalized_signature === input.normalizedSignature).map((failure) => failure.occurrence_count))) : 1;
    const effectiveClass: FailureClass = occurrence >= 2 && controlClass !== "EVIDENCE_INVALID" ? "SAME_FAILURE_TWICE" : controlClass;
    const base = { source_layer: input.sourceLayer, source_error_code: input.sourceErrorCode, source_record_content_sha256: input.sourceRecordContentSha256,
      normalized_signature: input.normalizedSignature, ...(input.operationId === undefined ? {} : { operation_id: input.operationId }),
      ...(input.scopeIdentity === undefined ? {} : { scope_identity: input.scopeIdentity }), ...(input.pathIdentity === undefined ? {} : { path_identity: input.pathIdentity }),
      ...(input.repositoryIdentity === undefined ? {} : { repository_identity: input.repositoryIdentity }), ...(input.worktreeKey === undefined ? {} : { worktree_key: input.worktreeKey }),
      control_class: effectiveClass, action: ACTION_BY_CLASS[effectiveClass], occurrence_count: occurrence,
      resolution_evidence_content_sha256: input.resolutionEvidenceContentSha256 ?? null };
    return { failure_identity: recordIdentity(base), ...base };
  });
  const unique = new Map(failures.map((failure) => [failure.failure_identity, failure]));
  return [...unique.values()].sort((a, b) => compare(a.failure_identity, b.failure_identity));
}

function grammarMatches(grammar: M5ControlPolicyDocument["obligations"][number]["grammar"], value: string, literal: string | null, prefix: string | null): boolean {
  if (grammar === "HEX") return /^[0-9a-f]+$/u.test(value);
  if (grammar === "UUID") return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab0-9a-f][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value);
  if (grammar === "INTEGER") return /^(?:0|[1-9][0-9]*)$/u.test(value) && Number.isSafeInteger(Number(value));
  if (grammar === "LITERAL") return value === literal;
  if (grammar === "PREFIXED_LITERAL") return prefix !== null && literal !== null && value === `${prefix}${literal}`;
  return value.length > 0 && !value.startsWith("/") && !value.includes("\\") && !value.split("/").some((part) => part === "" || part === "." || part === "..");
}

function contractGate(
  policy: M5ControlPolicyDocument,
  state: WorkflowState,
  reducer: ReducerPolicy,
  input: EvaluateControlDecisionInput,
  sources: M5AuthoritativeSources,
): M5ControlDecisionDocument["contract_gate"] {
  const evidence = new Map<string, NonNullable<EvaluateControlDecisionInput["obligationEvidence"]>[number]>();
  for (const entry of input.obligationEvidence ?? []) {
    const prior = evidence.get(entry.descriptorSha256);
    if (prior !== undefined && canonicalize(prior) !== canonicalize(entry)) throw controlError("CONTRACT_GATE_INVALID", "Conflicting obligation evidence was supplied");
    evidence.set(entry.descriptorSha256, entry);
  }
  const detections: Array<M5ControlDecisionDocument["contract_gate"]["detections"][number]> = [];
  const add = (code: M5ControlDecisionDocument["contract_gate"]["detections"][number]["code"], evidenceContentSha256: Sha256Digest | null = null): void => {
    detections.push({ code, evidence_content_sha256: evidenceContentSha256 });
  };
  const strict = policy.production_authority === "OWNER_APPROVED";
  const authoritativeEvidenceIds = new Set<string>([policy.content_sha256, state.content_sha256]);
  if (policy.plan_approval_sha256 !== null) authoritativeEvidenceIds.add(policy.plan_approval_sha256);
  for (const value of [sources.contract, sources.budget, sources.m4ToolPolicy, sources.m4CommandCatalog]) if (value !== undefined) authoritativeEvidenceIds.add(value.content_sha256);
  for (const values of [sources.m4CommandResults, sources.boundedWorkerResults, sources.m3StateTokens, sources.m3Postflights, sources.workflowStates, sources.transitionEvents, sources.transitionCommits, sources.planApprovals]) {
    for (const value of values ?? []) authoritativeEvidenceIds.add(value.content_sha256);
  }
  const sourceBundlePresent = sources.contract !== undefined || sources.budget !== undefined || sources.m4ToolPolicy !== undefined || sources.m4CommandCatalog !== undefined ||
    sources.routeMap !== undefined || sources.routeMapApproval !== undefined;
  if (sourceBundlePresent && (sources.contract === undefined || sources.budget === undefined || sources.m4CommandCatalog === undefined)) {
    add("REQUIRED_OUTPUT_UNAVAILABLE", null);
  }
  const descriptors = new Set(policy.obligations.map((entry) => entry.descriptor_sha256));
  if (strict) for (const item of evidence.values()) if (!authoritativeEvidenceIds.has(item.evidenceContentSha256)) add("IDENTITY_FORMAT_MISMATCH", item.evidenceContentSha256);
  for (const [descriptorSha, item] of evidence) {
    if (!descriptors.has(descriptorSha)) add("IDENTITY_FORMAT_MISMATCH", item.evidenceContentSha256);
  }
  for (const descriptor of policy.obligations) {
    const item = evidence.get(descriptor.descriptor_sha256);
    if (item !== undefined && !grammarMatches(descriptor.grammar, item.value, descriptor.literal, descriptor.prefix)) add("IDENTITY_FORMAT_MISMATCH", item.evidenceContentSha256);
  }

  const tasks = sources.tasks ?? [];
  const taskIds = new Set([...reducer.tasks.map((task) => task.task_id), ...tasks.map((task) => task.task_id)]);
  const graph = new Map<string, string[]>();
  for (const task of reducer.tasks) graph.set(task.task_id, [...task.dependencies]);
  for (const task of tasks) graph.set(task.task_id, [...task.dependencies]);
  let missingDependency = false;
  for (const taskGraph of sources.taskGraphs ?? []) {
    const graphIds = new Set(taskGraph.tasks.map((task) => task.task_id));
    for (const node of taskGraph.tasks) {
      if (!graph.has(node.task_id)) graph.set(node.task_id, [...node.dependencies]);
      if (node.dependencies.some((dependency) => !graphIds.has(dependency))) missingDependency = true;
    }
    for (const edge of taskGraph.edges) {
      if (!graphIds.has(edge.from) || !graphIds.has(edge.to)) missingDependency = true;
      else graph.set(edge.to, [...(graph.get(edge.to) ?? []), edge.from]);
    }
  }
  const syntheticNodes = new Set(["task-only", "contract", "controller", "owner"]);
  for (const descriptor of policy.obligations) {
    if (!syntheticNodes.has(descriptor.producer) && !taskIds.has(descriptor.producer)) missingDependency = true;
    const producerNode = descriptor.producer;
    if (!graph.has(producerNode)) graph.set(producerNode, []);
    for (const consumer of descriptor.consumers) {
      if (!syntheticNodes.has(consumer) && !taskIds.has(consumer) && !policy.obligations.some((entry) => entry.declaration === consumer)) missingDependency = true;
      graph.get(producerNode)!.push(consumer);
    }
  }
  const visiting = new Set<string>(); const visited = new Set<string>();
  const cyclic = (node: string): boolean => {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    visiting.add(node);
    const found = (graph.get(node) ?? []).some((next) => graph.has(next) && cyclic(next));
    visiting.delete(node); visited.add(node); return found;
  };
  if (reducer.tasks.some((task) => task.dependencies.some((dependency) => !taskIds.has(dependency))) ||
      tasks.some((task) => task.dependencies.some((dependency) => !taskIds.has(dependency))) || missingDependency) {
    add("MISSING_DEPENDENCY", reducer.content_sha256 as Sha256Digest);
  }
  if ([...graph.keys()].some((node) => cyclic(node))) add("CYCLIC_DEPENDENCY", reducer.content_sha256 as Sha256Digest);
  const requiredOutputs = new Set([...(sources.contract?.required_outputs ?? []), ...policy.obligations.filter((entry) => entry.direction === "OUTPUT").map((entry) => entry.declaration)]);
  for (const output of requiredOutputs) {
    const producers = new Set<string>();
    for (const descriptor of policy.obligations) if (descriptor.direction === "OUTPUT" && descriptor.declaration === output &&
      (syntheticNodes.has(descriptor.producer) || taskIds.has(descriptor.producer))) producers.add(descriptor.producer);
    for (const task of tasks) if (task.required_outputs.includes(output)) producers.add(task.task_id);
    if (producers.size === 0) add("MISSING_PRODUCER", policy.content_sha256 as Sha256Digest);
    else if (producers.size > 1) add("AMBIGUOUS_PRODUCER", policy.content_sha256 as Sha256Digest);
    const availableAtGate = [...evidence.entries()].some(([descriptorSha, item]) => policy.obligations.some((entry) => entry.declaration === output && entry.descriptor_sha256 === descriptorSha && grammarMatches(entry.grammar, item.value, entry.literal, entry.prefix)));
    if ((input.intent === "EVALUATE_TERMINAL" || stateIsTerminalPhase(state)) && !availableAtGate) add("REQUIRED_OUTPUT_UNAVAILABLE", policy.content_sha256 as Sha256Digest);
  }
  for (const descriptor of policy.obligations) {
    for (const consumer of descriptor.consumers) {
      const consumerDescriptor = policy.obligations.find((candidate) => candidate.declaration === consumer);
      if (consumerDescriptor !== undefined && descriptor.stage >= consumerDescriptor.stage) add("FUTURE_STAGE_DEPENDENCY", descriptor.descriptor_sha256 as Sha256Digest);
    }
  }
  const editable = [...reducer.tasks.map((task) => task.editable_paths.map((path) => ({ path, owner: task.task_id }))), ...tasks.map((task) => task.scope.editable_paths.map((path) => ({ path, owner: task.task_id })))]
    .flat().sort((a, b) => compare(a.path, b.path));
  if (editable.some((left, index) => editable.slice(index + 1).some((right) => left.owner !== right.owner && (left.path === right.path || left.path.startsWith(`${right.path}/`) || right.path.startsWith(`${left.path}/`))))) add("OVERLAPPING_WRITE_OWNERSHIP", reducer.content_sha256 as Sha256Digest);

  const acceptance = sources.contract?.acceptance_criteria ?? [];
  for (const criterion of acceptance) {
    const matching = policy.obligations.filter((entry) => entry.evidence_kind === criterion.evidence_kind || (criterion.evidence_kind === "DIGEST" && entry.evidence_kind === "STATE"));
    if (matching.length === 0) add("ACCEPTANCE_WITHOUT_EVIDENCE", policy.contract_sha256 as Sha256Digest);
    else if ((input.intent === "EVALUATE_TERMINAL" || stateIsTerminalPhase(state)) && !matching.some((entry) => evidence.has(entry.descriptor_sha256))) add("ACCEPTANCE_WITHOUT_EVIDENCE", policy.contract_sha256 as Sha256Digest);
  }
  if (sources.contract !== undefined && sources.m4CommandCatalog !== undefined) {
    const commandIds = new Map(sources.m4CommandCatalog.commands.map((command) => [command.command_id, command]));
    for (const command of sources.contract.verification_commands) {
      const found = commandIds.get(command.command_id);
      const exact = found !== undefined && found.command_class === "VERIFICATION" && canonicalize(found.argv) === canonicalize(command.argv) && found.cwd === command.cwd &&
        found.timeout_ms === command.timeout_ms && found.network_policy === command.network;
      if (!exact) add("VERIFICATION_COMMAND_UNAVAILABLE", sources.m4CommandCatalog.content_sha256 as Sha256Digest);
    }
    const referencedResults = sources.m4CommandResults ?? [];
    for (const result of referencedResults) {
      const command = commandIds.get(result.command_id);
      if (command === undefined || command.command_spec_sha256 !== result.command_spec_sha256 || command.command_class !== "VERIFICATION") add("VERIFICATION_COMMAND_UNAVAILABLE", result.content_sha256 as Sha256Digest);
    }
  }
  const routeRoles = new Set(sources.routeMap?.routes.map((route) => route.logical_role) ?? []);
  const available = new Set(input.availableLogicalRoles ?? []);
  const routeAvailable = new Set([...available].filter((role) => routeRoles.size === 0 || routeRoles.has(role as LogicalModelRole)));
  const desired = selectInitialRoute(policy, state, routeAvailable).selected;
  if (desired === null) add("ROUTE_UNAVAILABLE", policy.route_map_approval_sha256 as Sha256Digest);
  const boundedStaticRouted = isBoundedStaticPreM8(policy) && policy.requested_mode === "ROUTED_DAG";
  const requiredInvocations = desired === "STATIC_APPROVED_DAG" ? policy.route_facts.leaf_count * reducer.limits.max_attempts_per_leaf : desired === "ROUTED_DAG" ? boundedStaticRouted ? policy.route_facts.leaf_count + 2 : 2 * policy.route_facts.leaf_count + 4 : 1;
  const requiredByDimension: Readonly<Record<(typeof DIMENSIONS)[number], number>> = {
    WORKER_INVOCATION: requiredInvocations, MODEL_TURN: desired === null ? 1 : 1, PROVIDER_REQUEST: 0, TOOL_CALL: desired === "ROUTED_DAG" ? policy.route_facts.leaf_count : 0,
    INPUT_TOKEN: 0, OUTPUT_TOKEN: 0, COST_MICROUSD: 0, WALL_TIME_MS: 0,
  };
  for (const dimension of DIMENSIONS) {
    const hard = minDefined([...sourceHardLimits(dimension, state, reducer, sources), policy.limits.find((entry) => entry.dimension === dimension)?.hard_limit]);
    if (hard !== null && requiredByDimension[dimension] > hard) {
      add("BUDGET_ENVELOPE_INFEASIBLE", policy.budget_sha256 as Sha256Digest);
    }
  }
  if (desired === "ROUTED_DAG") {
    const leafCaps = [policy.route_facts.leaf_count, sources.contract?.limits.max_leaves, sources.budget?.limits.max_leaves].filter((value): value is number => value !== undefined);
    if (leafCaps.length > 0 && policy.route_facts.leaf_count > Math.min(...leafCaps)) add("BUDGET_ENVELOPE_INFEASIBLE", policy.budget_sha256 as Sha256Digest);
  }
  if (policy.obligations.some((entry) => !["HEX", "UUID", "INTEGER", "LITERAL", "PREFIXED_LITERAL", "PATH"].includes(entry.grammar))) add("UNSUPPORTED_CONTRACT_CONSTRUCT", policy.contract_sha256 as Sha256Digest);

  const deduplicated = new Map(detections.map((entry) => [entry.code, entry]));
  const sortedDetections = [...deduplicated.values()].sort((a, b) => compare(a.code, b.code));
  const satisfied = policy.obligations.filter((entry) => evidence.has(entry.descriptor_sha256) && grammarMatches(entry.grammar, evidence.get(entry.descriptor_sha256)!.value, entry.literal, entry.prefix)).map((entry) => entry.descriptor_sha256 as Sha256Digest).sort(compare);
  const satisfiedSet = new Set<string>(satisfied);
  const pending = policy.obligations.filter((entry) => !satisfiedSet.has(entry.descriptor_sha256)).map((entry) => entry.descriptor_sha256 as Sha256Digest).sort(compare);
  const incomplete = sourceBundlePresent && (sources.contract === undefined || sources.budget === undefined || sources.m4ToolPolicy === undefined || sources.m4CommandCatalog === undefined);
  const status: M5ControlDecisionDocument["contract_gate"]["status"] = incomplete ? "INSUFFICIENT_AUTHORITY"
    : sortedDetections.some((entry) => entry.code === "ROUTE_UNAVAILABLE" || entry.code === "VERIFICATION_COMMAND_UNAVAILABLE") ? "CURRENTLY_BLOCKED"
      : sortedDetections.length > 0 ? "UNSATISFIABLE" : pending.length === 0 ? "SATISFIED" : "SATISFIABLE";
  return { status, detections: sortedDetections, satisfied_obligation_descriptor_sha256: satisfied, pending_obligation_descriptor_sha256: pending };
}

function stateIsTerminalPhase(state: WorkflowState): boolean {
  return ["DIRECT_VERIFYING", "SINGLE_OWNER_VERIFYING", "CLOSEOUT_VERIFYING", "STATIC_DAG_VERIFYING", "AWAITING_DECLARED_OWNER_ACCEPTANCE", "PASS", "BLOCKED"].includes(state.phase);
}

function initialRoutes(policy: M5ControlPolicyDocument, available: ReadonlySet<string>): M5ControlDecisionDocument["routes"] {
  const f = policy.route_facts; const hard = f.hard_sol_conditions.length > 0;
  const direct = !hard && f.task_count === 1 && f.coherent_single_task && f.failure_domain_count === 1 && f.deterministic_acceptance && !f.ownership_ambiguous;
  const routed = !hard && f.task_count >= 2 && f.leaf_count >= 2 && f.leaf_count <= 8 && f.dag_valid && f.leaves_separable && f.unique_write_ownership && f.leaf_acceptance_machine_checkable;
  const requirements: Readonly<Record<string, readonly LogicalModelRole[]>> = {
    DIRECT_LUNA_HIGH: ["LUNA_EXECUTOR"], SINGLE_OWNER_SOL: ["SOL_OWNER"], ROUTED_DAG: ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"], STATIC_APPROVED_DAG: ["TERRA_EXECUTOR"],
  };
  const inventory = policy.requested_mode === "STATIC_APPROVED_DAG"
    ? ["STATIC_APPROVED_DAG"] as const
    : ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const;
  return inventory.map((route) => {
    const factEligible = route === "DIRECT_LUNA_HIGH" ? direct : route === "ROUTED_DAG" || route === "STATIC_APPROVED_DAG" ? routed
      : hard || policy.requested_mode === "SINGLE_OWNER_SOL" || policy.insufficient_routing_evidence === "SINGLE_OWNER_SOL";
    const missing = requirements[route]!.filter((role) => !available.has(role));
    return { route, eligibility: missing.length > 0 ? "MISSING_AUTHORITY" as const : factEligible ? "ELIGIBLE" as const : "INELIGIBLE" as const,
      reasons: missing.length > 0 ? missing.map((role) => `MISSING_ROLE_${role}`) : [factEligible ? "ROUTE_FACTS_SATISFIED" : "ROUTE_FACTS_NOT_SATISFIED"] };
  });
}

function preferredInitialRoute(policy: M5ControlPolicyDocument): "DIRECT_LUNA_HIGH" | "SINGLE_OWNER_SOL" | "ROUTED_DAG" | "STATIC_APPROVED_DAG" | null {
  if (policy.requested_mode !== "AUTO") return policy.requested_mode;
  if (policy.route_facts.hard_sol_conditions.length > 0) return "SINGLE_OWNER_SOL";
  if (policy.route_facts.task_count === 1) return "DIRECT_LUNA_HIGH";
  if (policy.route_facts.leaf_count >= 2) return "ROUTED_DAG";
  return null;
}
function selectInitialRoute(policy: M5ControlPolicyDocument, state: WorkflowState, available: ReadonlySet<string>): { readonly routes: M5ControlDecisionDocument["routes"]; readonly selected: "DIRECT_LUNA_HIGH" | "SINGLE_OWNER_SOL" | "ROUTED_DAG" | "STATIC_APPROVED_DAG" | null; readonly preferred: string | null } {
  const routes = initialRoutes(policy, available); const preferred = preferredInitialRoute(policy);
  const eligible = (route: string): boolean => route === state.execution_mode && routes.some((entry) => entry.route === route && entry.eligibility === "ELIGIBLE");
  if (preferred !== null && eligible(preferred)) return { routes, selected: preferred, preferred };
  if (policy.requested_mode === "AUTO" && policy.insufficient_routing_evidence === "SINGLE_OWNER_SOL" && eligible("SINGLE_OWNER_SOL")) return { routes, selected: "SINGLE_OWNER_SOL", preferred };
  return { routes, selected: null, preferred };
}

function continuationRoutes(action: ContinuationRoute, allowed: boolean, reason = "FIXED_ACTION_MATCH"): M5ControlDecisionDocument["routes"] {
  return CONTINUATION_ROUTES.map((route) => ({ route, eligibility: allowed && route === action ? "ELIGIBLE" as const : "INELIGIBLE" as const,
    reasons: [allowed && route === action ? reason : "FIXED_ACTION_MISMATCH"] }));
}

const RUNNING_OPERATION_PHASES = new Set<WorkflowState["phase"]>(["DIRECT_ATTEMPT_RUNNING", "SINGLE_OWNER_RUNNING", "LEAF_RUNNING", "PLAN_RUNNING", "CLOSEOUT_RUNNING"]);
const WORK_ADMISSION_PHASES = new Set<WorkflowState["phase"]>(["DIRECT_FAST_PREFLIGHT", "SINGLE_OWNER_FAST_PREFLIGHT", "ROUTE_SELECTED", "LEAF_FAST_PREFLIGHT", "REPLAN_REQUIRED", "READY"]);
function hasOperationAuthority(input: EvaluateControlDecisionInput, priorDecisions: readonly M5ControlDecisionDocument[]): boolean {
  if (input.operationId === undefined || (input.failures ?? []).some((failure) => failure.operationId !== input.operationId)) return false;
  return priorDecisions.some((decision) => decision.reservation?.future_operation_id === input.operationId && decision.outcome === "AUTHORIZE");
}
function continuationAllowed(action: ContinuationRoute, state: WorkflowState, input: EvaluateControlDecisionInput, priorDecisions: readonly M5ControlDecisionDocument[]): boolean {
  const available = new Set(input.availableLogicalRoles ?? []);
  if (input.intent === "VALIDATE_CONTRACT" || input.intent === "EVALUATE_TERMINAL" || input.intent === "BLOCK") return true;
  if (input.intent === "AUTHORIZE_WORK") return WORK_ADMISSION_PHASES.has(state.phase) && input.operationId !== undefined && (action === "CONTINUE_ADMITTED_OPERATION" || action === "RUN_RESERVED_CLOSEOUT");
  const last = priorDecisions.at(-1);
  const repeatedWithoutProgress = last?.selected_route === action && last.progress.classification === "NO_PROGRESS";
  const activeOperation = RUNNING_OPERATION_PHASES.has(state.phase) && hasOperationAuthority(input, priorDecisions);
  if (action === "CONTINUE_ADMITTED_OPERATION" && input.intent === "AUTHORIZE_CONTINUATION") return activeOperation;
  if (action === "SECOND_LUNA_ATTEMPT") {
    if (state.execution_mode === "STATIC_APPROVED_DAG") {
      const active = state.active_task_id === null ? undefined : state.tasks.find((task) => task.task_id === state.active_task_id);
      return available.has("TERRA_EXECUTOR") && state.phase === "LEAF_RETRY_READY" && active !== undefined &&
        active.attempts < 2 && hasOperationAuthority(input, priorDecisions);
    }
    return available.has("LUNA_EXECUTOR") && ["DIRECT_RETRY_READY", "LEAF_RETRY_READY"].includes(state.phase) && hasOperationAuthority(input, priorDecisions) && state.counters.direct_attempts < 2;
  }
  if (action === "CONSTRAINED_REPLAN") return available.has("SOL_REPLAN") && state.phase === "REPLAN_REQUIRED" && !state.replan_in_progress && state.counters.constrained_replans < 2 && !repeatedWithoutProgress;
  if (action === "RUN_RESERVED_CLOSEOUT") return available.has("SOL_CLOSEOUT") && state.phase === "READY" && !repeatedWithoutProgress;
  if (action === "RETRY_TRANSIENT_TOOL_ONCE" || action === "CORRECT_COMMAND_ONCE" || action === "RESTORE_CONTEXT_ONCE") return activeOperation && !repeatedWithoutProgress;
  if (action === "REQUEST_OWNER_DECISION" || action === "BLOCK") return true;
  return false;
}

function requiredRole(state: WorkflowState, input: EvaluateControlDecisionInput): LogicalModelRole | null {
  if (input.requiredLogicalRole !== undefined) return input.requiredLogicalRole;
  if (state.phase === "DIRECT_FAST_PREFLIGHT" || state.phase === "LEAF_FAST_PREFLIGHT") return state.execution_mode === "STATIC_APPROVED_DAG" ? "TERRA_EXECUTOR" : "LUNA_EXECUTOR";
  if (state.phase === "SINGLE_OWNER_FAST_PREFLIGHT") return "SOL_OWNER";
  if (state.phase === "ROUTE_SELECTED") return state.execution_mode === "ROUTED_DAG" ? "SOL_PLANNER" : state.execution_mode === "SINGLE_OWNER_SOL" ? "SOL_OWNER" : state.execution_mode === "STATIC_APPROVED_DAG" ? null : "LUNA_EXECUTOR";
  if (state.phase === "REPLAN_REQUIRED") return "SOL_REPLAN";
  if (state.phase === "READY") return "SOL_CLOSEOUT";
  return null;
}

function createEvent(type: TransitionEvent["event_type"], payload: Record<string, unknown>, seed: object): TransitionEvent {
  const eventId = `m5-${sha256Canonical(seed).slice(7, 39)}`;
  return identifyContractDocument("pi_gacw_transition_event_v0", { schema_id: "pi_gacw_transition_event_v0", schema_version: "0.1.0",
    content_projection_id: "document-content-v1", event_id: eventId, event_type: type, payload }) as unknown as TransitionEvent;
}

function transitionFor(
  input: EvaluateControlDecisionInput,
  state: WorkflowState,
  selected: string | null,
  outcome: "AUTHORIZE" | "PASS" | "BLOCK",
  blockingReason: string | null,
  progress: M5ControlDecisionDocument["progress"],
): TransitionEvent | null {
  const seed = { state: state.content_sha256, intent: input.intent, transitionId: input.transitionId ?? null, selected, outcome, blockingReason, evidence: progress.evidence_set_sha256 };
  if (outcome === "BLOCK") return createEvent("BLOCK", { reason: blockingReason ?? "BLOCKED_M5_AUTHORITY_INCOMPLETE" }, seed);
  if (input.intent === "VALIDATE_CONTRACT") return createEvent("VALIDATE_CONTRACT", {}, seed);
  if (input.intent === "SELECT_ROUTE" && selected !== null && ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG", "STATIC_APPROVED_DAG"].includes(selected)) return createEvent("SELECT_ROUTE", { execution_mode: selected }, seed);
  if (input.intent === "AUTHORIZE_WORK") {
    const byPhase: Partial<Record<WorkflowState["phase"], TransitionEvent["event_type"]>> = {
      DIRECT_FAST_PREFLIGHT: "START_DIRECT_ATTEMPT", SINGLE_OWNER_FAST_PREFLIGHT: "START_SINGLE_OWNER", ROUTE_SELECTED: "START_PLAN",
      LEAF_FAST_PREFLIGHT: "START_LEAF_ATTEMPT", REPLAN_REQUIRED: "START_CONSTRAINED_REPLAN", READY: "START_CLOSEOUT",
    };
    const type = byPhase[state.phase]; return type === undefined ? null : createEvent(type, {}, seed);
  }
  if (input.intent === "AUTHORIZE_CONTINUATION") {
    if (selected === "SECOND_LUNA_ATTEMPT" && state.phase === "DIRECT_RETRY_READY") return createEvent("ADMIT_DIRECT_RETRY", { progress_delta: { kind: progress.kind, evidence_sha256: progress.evidence_content_sha256[0], summary: "M5 evidence-backed progress" } }, seed);
    if (selected === "SECOND_LUNA_ATTEMPT" && state.phase === "LEAF_RETRY_READY") return createEvent("ADMIT_LEAF_RETRY", { progress_delta: { kind: progress.kind, evidence_sha256: progress.evidence_content_sha256[0], summary: "M5 evidence-backed progress" } }, seed);
    if (selected === "CONSTRAINED_REPLAN" && state.phase === "REPLAN_REQUIRED") return createEvent("START_CONSTRAINED_REPLAN", {}, seed);
    return null;
  }
  if (input.intent === "EVALUATE_TERMINAL") {
    const byPhase: Partial<Record<WorkflowState["phase"], TransitionEvent["event_type"]>> = {
      DIRECT_VERIFYING: "DIRECT_VERIFICATION_PASSED", SINGLE_OWNER_VERIFYING: "SINGLE_OWNER_VERIFICATION_PASSED", CLOSEOUT_VERIFYING: "CLOSEOUT_PASSED", STATIC_DAG_VERIFYING: "STATIC_DAG_VERIFICATION_PASSED",
      AWAITING_DECLARED_OWNER_ACCEPTANCE: "OWNER_ACCEPTED",
    };
    const type = byPhase[state.phase]; return type === undefined ? null : createEvent(type, {}, seed);
  }
  return null;
}

export interface EvaluateAuthorityInput {
  readonly policy: M5ControlPolicyDocument;
  readonly state: WorkflowState;
  readonly reducerPolicy: ReducerPolicy;
  readonly request: EvaluateControlDecisionInput;
  readonly persistedUsage: readonly M5UsageEvidenceDocument[];
  readonly priorDecisions: readonly M5ControlDecisionDocument[];
  readonly authoritativeSources?: M5AuthoritativeSources;
  readonly production?: boolean;
}

export function evaluateAuthority(input: EvaluateAuthorityInput): M5ControlDecisionDocument {
  const { policy, state, reducerPolicy, request } = input;
  const priorDecisions = orderDecisionHistory(input.priorDecisions);
  try { assertDocumentValid("pi_gacw_m5_control_policy_v0", policy); }
  catch (error: unknown) { throw controlError("M5_POLICY_INVALID", "Control policy failed structural or semantic validation", error); }
  const strictSources = input.production === true || policy.production_authority === "OWNER_APPROVED";
  const sources = assertAuthoritativeSources(policy, request.authoritativeSources ?? input.authoritativeSources, strictSources);
  if (sources.contract !== undefined && policy.requested_mode === "AUTO" && sources.contract.execution_mode !== state.execution_mode) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Contract execution mode differs from the committed route mode");
  }
  if (strictSources && request.intent === "AUTHORIZE_WORK" && (sources.m3StateTokens?.length ?? 0) === 0) {
    throw controlError("M5_AUTHORITY_INCOMPLETE", "Repository-affecting work requires exact M3 repository/worktree token authority");
  }
  if (request.intent === "AUTHORIZE_WORK" && (!WORK_ADMISSION_PHASES.has(state.phase) || request.operationId === undefined)) {
    throw controlError("ROUTE_NOT_ELIGIBLE", "Work authorization requires an exact M1 admission phase and future operation identity");
  }
  assertBlockedBoundedWorkerTerminalRequest(request, policy, priorDecisions, sources);
  const usage = completeUsageSet([...input.persistedUsage, ...(request.usageEvidence ?? [])], policy);
  assertUsageSourceAuthority(usage, policy, state, priorDecisions, sources, request);
  const failures = classifyFailures(request.failures ?? [], priorDecisions);
  if (strictSources) {
    const sourceIds = new Set<string>([policy.content_sha256, state.content_sha256, reducerPolicy.content_sha256, ...priorDecisions.map((entry) => entry.content_sha256)]);
    for (const value of [sources.contract, sources.budget, sources.m4ToolPolicy, sources.m4CommandCatalog]) if (value !== undefined) sourceIds.add(value.content_sha256);
    for (const values of [sources.m4CommandResults, sources.boundedWorkerResults, sources.m3StateTokens, sources.m3Postflights, sources.workflowStates, sources.transitionEvents, sources.transitionCommits, sources.planApprovals, sources.taskGraphs, sources.tasks]) {
      for (const value of values ?? []) sourceIds.add(value.content_sha256);
    }
    for (const failure of request.failures ?? []) {
      if (!sourceIds.has(failure.sourceRecordContentSha256) || (failure.resolutionEvidenceContentSha256 !== undefined && !sourceIds.has(failure.resolutionEvidenceContentSha256))) {
        throw controlError("FAILURE_CLASSIFICATION_INVALID", "Failure evidence is not an authoritative predecessor");
      }
    }
  }
  const progress = progressEvaluation(request, policy, state, reducerPolicy, usage, priorDecisions, sources);
  for (const failure of failures) if (failure.resolution_evidence_content_sha256 !== null && !progress.evidence_content_sha256.includes(failure.resolution_evidence_content_sha256)) {
    throw controlError("FAILURE_CLASSIFICATION_INVALID", "Failure reclassification lacks matching progress evidence");
  }
  const gate = contractGate(policy, state, reducerPolicy, request, sources);
  const available = new Set(request.availableLogicalRoles ?? []);
  const initial = request.intent === "SELECT_ROUTE";
  let routes: M5ControlDecisionDocument["routes"]; let selected: string | null = null; let blockingReason: string | null = null;
  if (initial) {
    const initialSelection = selectInitialRoute(policy, state, available); routes = initialSelection.routes; selected = initialSelection.selected;
    if (!["SATISFIED", "SATISFIABLE"].includes(gate.status)) { selected = null; blockingReason = gate.detections[0] === undefined ? "BLOCKED_M5_AUTHORITY_INCOMPLETE" : `BLOCKED_CONTRACT_${gate.detections[0]!.code}`; }
    else if (selected === null) blockingReason = policy.requested_mode !== "AUTO" && initialSelection.preferred !== state.execution_mode ? "BLOCKED_AUTHORITY_CONTRADICTION" : "BLOCKED_ROUTE_UNAVAILABLE";
  } else {
    const actions = sortedUnique(failures.map((failure) => failure.action));
    let action: ContinuationRoute = actions.length === 0 ? "CONTINUE_ADMITTED_OPERATION" : actions.includes("BLOCK") ? "BLOCK" : actions.length === 1 ? actions[0] as ContinuationRoute : "BLOCK";
    if (actions.length > 1 && !actions.includes("BLOCK")) blockingReason = "BLOCKED_CONFLICTING_FAILURE_ACTIONS";
    if (request.intent === "AUTHORIZE_CONTINUATION" && progress.classification === "NO_PROGRESS" && !(failures.some((failure) => failure.control_class === "SAME_FAILURE_TWICE") && action === "CONSTRAINED_REPLAN")) { action = "BLOCK"; blockingReason = "BLOCKED_NO_PROGRESS"; }
    if (!["SATISFIED", "SATISFIABLE"].includes(gate.status)) { action = "BLOCK"; blockingReason ??= gate.detections[0] === undefined ? "BLOCKED_M5_AUTHORITY_INCOMPLETE" : `BLOCKED_CONTRACT_${gate.detections[0].code}`; }
    if (request.intent === "BLOCK") { action = "BLOCK"; blockingReason = request.blockReason ?? "BLOCKED_M5_AUTHORITY_INCOMPLETE"; }
    if (request.intent === "EVALUATE_TERMINAL" && gate.status === "SATISFIED" && failures.length === 0) action = "CONTINUE_ADMITTED_OPERATION";
    if (request.intent === "AUTHORIZE_WORK" && state.phase === "READY" && actions.length === 0) action = "RUN_RESERVED_CLOSEOUT";
    if (!continuationAllowed(action, state, request, priorDecisions)) { action = "BLOCK"; blockingReason ??= "BLOCKED_ROUTE_NOT_ELIGIBLE"; }
    routes = continuationRoutes(action, true); selected = action;
  }
  const role = requiredRole(state, request);
  let reservation: M5ControlDecisionDocument["reservation"] = null;
  if (request.intent === "AUTHORIZE_WORK" && selected !== "BLOCK" && role !== null) {
    const roleToCounter: Readonly<Record<LogicalModelRole, keyof WorkflowState["counters"]["worker_invocations"]>> = {
      SOL_OWNER: "sol_owner", SOL_PLANNER: "sol_planner", SOL_REPLAN: "sol_replan", SOL_CLOSEOUT: "sol_closeout", LUNA_EXECUTOR: "luna_executor", TERRA_EXECUTOR: "terra_executor",
      BENCHMARK_VERIFIER: "luna_executor", BENCHMARK_SELECTOR: "sol_owner",
    };
    const counter = roleToCounter[role];
    const fixedCap = role === "SOL_OWNER" ? 1 : role === "SOL_PLANNER" ? 1 : role === "SOL_REPLAN" ? reducerPolicy.limits.max_replans
      : role === "SOL_CLOSEOUT" ? 1 : state.execution_mode === "ROUTED_DAG" || state.execution_mode === "STATIC_APPROVED_DAG" ? reducerPolicy.tasks.length * reducerPolicy.limits.max_attempts_per_leaf : reducerPolicy.limits.max_direct_attempts;
    if (!(request.availableLogicalRoles ?? []).includes(role) || state.counters.worker_invocations[counter] >= fixedCap) {
      selected = "BLOCK"; blockingReason = "BLOCKED_BUDGET_EXHAUSTED"; routes = continuationRoutes("BLOCK", true);
    }
    const purpose = role === "SOL_CLOSEOUT" ? "REQUIRED_CLOSEOUT" : "ORDINARY";
    const futureOperationId = request.operationId ?? `${request.intent}:${state.phase}:${role}`;
    const alreadyActive = priorDecisions.some((decision) => decision.reservation !== null && decision.reservation.future_operation_id === futureOperationId &&
      !usage.some((entry) => entry.reservation_decision_content_sha256 === decision.content_sha256 && ["COMPLETED", "NOT_STARTED", "BLOCKED_BEFORE_START"].includes(entry.disposition)));
    if (alreadyActive) { selected = "BLOCK"; blockingReason = "BLOCKED_DUPLICATE_RESERVATION"; routes = continuationRoutes("BLOCK", true); }
    const index = policy.role_reservation_envelopes.findIndex((entry) => entry.logical_role === role && entry.purpose === purpose);
    if (index < 0) { selected = "BLOCK"; blockingReason = "BLOCKED_BUDGET_EXHAUSTED"; routes = continuationRoutes("BLOCK", true); }
    else if (selected !== "BLOCK") reservation = { logical_role: role, purpose, future_operation_id: futureOperationId,
      reserved_state_content_sha256: state.content_sha256, reserved_policy_content_sha256: policy.content_sha256,
      reserved_route: state.execution_mode, amounts: policy.role_reservation_envelopes[index]!.amounts, source_envelope_index: index,
      status: "ACTIVE", reconciliation_evidence_content_sha256: null };
  }
  const openingBudget = aggregateBudget(policy, state, reducerPolicy, usage, priorDecisions, null, sources,
    request.intent === "BLOCK" && isBoundedStaticPreM8(policy));
  const openingHardReached = openingBudget.some((entry) => entry.status === "HARD_LIMIT_REACHED" && ["HARD_ENFORCEABLE", "SOFT_ENFORCEABLE"].includes(entry.enforcement_class));
  const openingSoftReached = openingBudget.some((entry) => entry.status === "SOFT_LIMIT_REACHED");
  let budget = openingBudget;
  if (reservation !== null) {
    try { budget = aggregateBudget(policy, state, reducerPolicy, usage, priorDecisions, reservation, sources); }
    catch (error: unknown) {
      if (!(error instanceof Error) || !("code" in error) || (error as { code: unknown }).code !== "BUDGET_EXHAUSTED") throw error;
      selected = "BLOCK"; blockingReason = "BLOCKED_BUDGET_EXHAUSTED"; reservation = null; routes = continuationRoutes("BLOCK", true);
    }
  }
  const candidateHardReached = budget.some((entry) => {
    if (entry.status !== "HARD_LIMIT_REACHED" || !["HARD_ENFORCEABLE", "SOFT_ENFORCEABLE"].includes(entry.enforcement_class)) return false;
    // A first worker reservation may exactly consume its hard limit. The
    // aggregateBudget overflow check above still rejects current usage plus a
    // candidate reservation when it exceeds the limit.
    if (request.intent === "AUTHORIZE_WORK" && entry.dimension === "WORKER_INVOCATION" && entry.hard_limit !== null &&
        entry.active_reservation_amount > 0 && entry.effective_charged_amount + entry.active_reservation_amount <= entry.hard_limit) return false;
    return true;
  });
  const candidateSoftReached = budget.some((entry) => entry.status === "SOFT_LIMIT_REACHED");
  if (request.intent === "AUTHORIZE_WORK" && (openingHardReached || candidateHardReached || openingSoftReached || candidateSoftReached)) {
    selected = "BLOCK"; blockingReason = "BLOCKED_BUDGET_EXHAUSTED"; reservation = null; routes = continuationRoutes("BLOCK", true); budget = openingBudget;
  }
  if (request.intent === "AUTHORIZE_CONTINUATION" && (openingHardReached || openingSoftReached)) {
    selected = "BLOCK"; blockingReason = "BLOCKED_BUDGET_EXHAUSTED"; routes = continuationRoutes("BLOCK", true);
  }
  const unresolvedReservation = priorDecisions.some((decision) => decision.reservation !== null &&
    !usage.some((entry) => entry.reservation_decision_content_sha256 === decision.content_sha256 && entry.disposition !== "OUTCOME_UNCERTAIN"));
  const terminalPhase = ["DIRECT_VERIFYING", "SINGLE_OWNER_VERIFYING", "CLOSEOUT_VERIFYING", "STATIC_DAG_VERIFYING", "AWAITING_DECLARED_OWNER_ACCEPTANCE"].includes(state.phase);
  let pass = request.intent === "EVALUATE_TERMINAL" && terminalPhase && gate.status === "SATISFIED" && failures.length === 0 && !unresolvedReservation && !openingSoftReached;
  if (request.intent === "EVALUATE_TERMINAL" && !pass) {
    selected = "BLOCK"; blockingReason ??= unresolvedReservation ? "BLOCKED_UNRECONCILED_RESERVATION" : openingSoftReached ? "BLOCKED_BUDGET_EXHAUSTED" : "BLOCKED_TERMINAL_PRECONDITION"; routes = continuationRoutes("BLOCK", true);
  }
  let blocked = selected === null || selected === "BLOCK" || selected === "REQUEST_OWNER_DECISION" || blockingReason !== null;
  let outcome: "AUTHORIZE" | "PASS" | "BLOCK" = pass ? "PASS" : blocked ? "BLOCK" : "AUTHORIZE";
  if (outcome === "BLOCK" && blockingReason === null) blockingReason = selected === "REQUEST_OWNER_DECISION" ? "BLOCKED_AUTHORITY_CONTRADICTION" : "BLOCKED_M5_AUTHORITY_INCOMPLETE";
  let event = transitionFor(request, state, selected, outcome, blockingReason, progress);
  let predicted: WorkflowState | null = null;
  if (event !== null) {
    try { predicted = reduceState(state, event, reducerPolicy); }
    catch (error: unknown) { throw controlError("M5_DECISION_INVALID", "Selected authority cannot produce an accepted M1 transition", error, { sourceLayer: "M1", sourceCode: error instanceof Error && "code" in error ? String((error as { code: unknown }).code) : "INVALID_TRANSITION", authorityRelevant: true }); }
  }
  if (pass && predicted?.phase !== "PASS") {
    pass = false;
    if (predicted !== null && predicted.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE") outcome = "AUTHORIZE";
    else {
      selected = "BLOCK"; blockingReason = "BLOCKED_TERMINAL_PRECONDITION"; routes = continuationRoutes("BLOCK", true); outcome = "BLOCK";
      event = transitionFor({ ...request, intent: "BLOCK" }, state, selected, outcome, blockingReason, progress);
      predicted = event === null ? null : reduceState(state, event, reducerPolicy);
    }
  }
  blocked = outcome === "BLOCK";
  const usageIds = usage.map((entry) => entry.content_sha256).sort(compare);
  const prior = priorDecisions.at(-1)?.content_sha256 ?? null;
  const requestKey = controlRequestKey(request, event?.event_id ?? null, usageIds as Sha256Digest[]);
  const reservationIdentity = reservation === null ? null : {
    logical_role: reservation.logical_role, purpose: reservation.purpose, future_operation_id: reservation.future_operation_id ?? null,
    reserved_state_content_sha256: reservation.reserved_state_content_sha256 ?? null, reserved_policy_content_sha256: reservation.reserved_policy_content_sha256 ?? null,
    reserved_route: reservation.reserved_route ?? null, amounts: reservation.amounts, source_envelope_index: reservation.source_envelope_index,
  };
  const decisionKey = sha256Canonical({ run_id: policy.run_id, state: state.content_sha256, intent: request.intent, usage: usageIds,
    failures: failures.map((entry) => entry.failure_identity), gate, progress, selected_route: selected, reservation: reservationIdentity, request_key: requestKey, prior });
  if (reservation !== null) reservation = { ...reservation, reservation_decision_key: decisionKey };
  const document = identifyContractDocument("pi_gacw_m5_control_decision_v0", {
    schema_id: "pi_gacw_m5_control_decision_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    run_id: policy.run_id, repository_identity_content_sha256: policy.repository_identity_content_sha256, worktree_key: policy.worktree_key,
    current_state_content_sha256: state.content_sha256, policy_content_sha256: policy.content_sha256, objective_sha256: policy.objective_sha256,
    contract_sha256: policy.contract_sha256, budget_sha256: policy.budget_sha256, route_map_sha256: policy.route_map_sha256,
    route_map_approval_sha256: policy.route_map_approval_sha256, reducer_policy_content_sha256: policy.reducer_policy_content_sha256,
    scope_sha256: policy.scope_sha256, acceptance_sha256: policy.acceptance_sha256, tool_policy_content_sha256: policy.tool_policy_content_sha256,
    command_catalog_content_sha256: policy.command_catalog_content_sha256, usage_set_sha256: sha256Canonical(usageIds),
    usage_evidence_content_sha256: usageIds, budget, progress, failures, contract_gate: gate,
    obligation_evidence: (request.obligationEvidence ?? []).map((entry) => ({ descriptor_sha256: entry.descriptorSha256, value: entry.value, evidence_content_sha256: entry.evidenceContentSha256 })),
    available_logical_roles: [...available].sort(), operation_id: request.operationId ?? null, ...(request.transitionId === undefined ? {} : { transition_id: request.transitionId }),
    decision_kind: initial ? "INITIAL_MODE" : "CONTINUATION", intent: request.intent,
    routes, selected_route: selected, reservation, outcome, blocking_reason: blocked ? blockingReason : null,
    pass_authority: outcome === "PASS", transition_event: event, predicted_next_state_content_sha256: predicted?.content_sha256 ?? null,
    prior_relevant_decision_content_sha256: prior, request_key: requestKey, decision_key: decisionKey,
  }) as unknown as M5ControlDecisionDocument;
  assertDocumentValid("pi_gacw_m5_control_decision_v0", document);
  return document;
}

export function assertDecisionRecalculation(actual: M5ControlDecisionDocument, expected: M5ControlDecisionDocument): void {
  if (canonicalize(actual) !== canonicalize(expected)) throw controlError("M5_DECISION_INVALID", "Stored decision differs from deterministic recalculation");
}
