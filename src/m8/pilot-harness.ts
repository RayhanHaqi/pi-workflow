import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, realpath, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { promisify } from "node:util";

import { canonicalize } from "../canonical-json/index.js";
import { assertSha256Digest, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { inspectRunStorage } from "../persistence/index.js";
import { resolveAuthoritativeBoundedExecution } from "../persistence/bounded-worker-authority.js";
import { readM5ManagedRecords } from "../persistence/store.js";
import { captureGitState } from "../repository/fingerprint.js";
import { resolveRepositoryIdentity } from "../repository/index.js";
import {
  assertDocumentValid,
  type BoundedWorkerInvocationDocument,
  type BoundedWorkerResultDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3PostflightDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandResultDocument,
  type M4MutationReceiptDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type PlanApprovalDocument,
  type TaskDocument,
  type TaskGraphDocument,
  type WorkflowState,
} from "../schemas/index.js";
import {
  runBoundedMutationWorkflow,
  runBoundedMutationWorkflowForTests,
  type BoundedExecutionAuthority,
  type BoundedMutationAuthority,
  type BoundedMutationGoal,
  type BoundedMutationRunResult,
} from "../workflow-controller.js";
import type { M8AuthoritativeWorkflowEvidence } from "./pilot-verifier.js";

const execFileAsync = promisify(execFile);
const FIXTURE_PROTOCOL = "m8-scenario-fixtures-v1";
const FREEZE_PROTOCOL = "m8-static-plan-v2";
const STATIC_SLOT_PROTOCOL = "m8-static-slot-spec-v1";
const EVIDENCE_PROTOCOL = "m8-evidence-v2";
const MATRIX_PROTOCOL = "m8-canonical-matrix-v1";
const EXECUTION_AUTHORITY_PROTOCOL = "m8-execution-authority-v2";
const APPROVAL_MANIFEST_PROTOCOL = "m8-static-approval-manifest-v3";
const M8_FIXTURE_APPROVER = "m8-fixture-freeze";
const M8_FIXTURE_APPROVED_AT = "2000-01-01T00:00:00.000Z";
const TOTAL_M4_TOOL_LIMIT = 32;
const MAX_WALL_TIME_MS = 120_000;

/** Immutable architecture/version identities; commit/tree are derived at static-plan freeze time. */
const M8_ARCHITECTURE_IDENTITY = "b20e4a5a349f2bc0389bd2f70369481ebffd7c635922bb064b8c83b3af7dc3ea" as Sha256Digest;
const M8_V0_IDENTITY = "3ee98de02c95aeea99345fd02389b2ab0b43a749c98aea380d194c6ab232ada6" as Sha256Digest;
const MODES = ["DIRECT_LUNA_HIGH", "SINGLE_OWNER_SOL", "ROUTED_DAG"] as const;
const SCENARIO_IDS = ["M8-S01", "M8-S02", "M8-S03", "M8-S04", "M8-S05", "M8-S06", "M8-S07", "M8-S08", "M8-S09", "M8-S10"] as const;
const DIRECT_IDS = new Set(["M8-S01", "M8-S02", "M8-S04", "M8-S06", "M8-S08", "M8-S09", "M8-S10"]);
const SCENARIO_CLASSES = new Map<string, string>([["M8-S01", "mechanical edit"], ["M8-S02", "bounded bug fix"], ["M8-S03", "multi-file feature"], ["M8-S04", "refactor"], ["M8-S05", "schema/config migration"], ["M8-S06", "CI repair"], ["M8-S07", "docs + code"], ["M8-S08", "approved dirty baseline"], ["M8-S09", "budget exhaustion"], ["M8-S10", "scope expansion"]]);

export type M8Mode = typeof MODES[number];
export type M8Terminal = "PASS" | "BLOCKED";

/** Freeze-time canonical repository facts bound into every static slot. */
export interface M8CanonicalSourceBaseline {
  readonly commit: string;
  readonly tree: string;
  readonly architecture_identity: Sha256Digest;
  readonly v0_identity: Sha256Digest;
}

/** Optional explicit baseline must exactly match the clean repository being frozen. */
export interface M8FreezeOptions {
  readonly repository_root?: string;
  readonly canonical_source_baseline?: M8CanonicalSourceBaseline;
}

export interface M8FileManifest {
  readonly path: string;
  readonly mode: number;
  readonly bytes_base64: string;
}

export interface M8RouteTask {
  readonly task_id: string;
  readonly objective: string;
  readonly editable_paths: readonly string[];
  readonly required_outputs: readonly string[];
  readonly dependencies: readonly string[];
}

export type M8AcceptanceFact =
  | Readonly<{ readonly type: "expected_final_file"; readonly path: string; readonly mode: number; readonly bytes_base64: string }>
  | Readonly<{ readonly type: "frozen_file"; readonly path: string; readonly mode: number; readonly bytes_base64: string }>
  | Readonly<{ readonly type: "approved_dirty_overlay"; readonly path: string; readonly mode: number; readonly bytes_base64: string }>
  | Readonly<{ readonly type: "required_changed_path"; readonly path: string }>
  | Readonly<{ readonly type: "allowed_changed_path"; readonly path: string }>
  | Readonly<{ readonly type: "required_command_result"; readonly command_id: string; readonly executable: string; readonly args: readonly string[]; readonly cwd: string; readonly expected_exit: number }>
  | Readonly<{ readonly type: "expected_terminal"; readonly terminal: M8Terminal }>
  | Readonly<{ readonly type: "required_budget_fact"; readonly hard_mutation_tool_limit: 1; readonly accepted_productive_mutations_at_most: 1; readonly second_productive_mutation_rejected: true; readonly no_productive_continuation_after_exhaustion: true }>
  | Readonly<{ readonly type: "required_scope_refusal"; readonly required_objective_unsatisfied: true; readonly scope_refusal_observed: true }>;

export interface M8Scenario {
  readonly scenario_id: typeof SCENARIO_IDS[number];
  readonly scenario_class: string;
  readonly objective: string;
  readonly representative_rationale: string;
  readonly initial_files: readonly M8FileManifest[];
  readonly approved_dirty_overlay: readonly M8FileManifest[] | null;
  readonly readable_paths: readonly string[];
  readonly editable_paths: readonly string[];
  readonly frozen_paths: readonly string[];
  readonly required_outputs: readonly string[];
  readonly expected_behavior: { readonly terminal: M8Terminal; readonly task_success: boolean; readonly workflow_correctness: boolean; readonly pilot_validity: boolean };
  readonly acceptance_properties: readonly string[];
  /** Closed, typed M8 fixture facts consumed by the blind verifier. */
  readonly acceptance_facts: readonly M8AcceptanceFact[];
  readonly verification: { readonly executable: string; readonly args: readonly string[]; readonly cwd: string; readonly timeout_ms: number; readonly expected_exit: number; readonly expected_result: M8Terminal };
  readonly stopping_conditions: readonly string[];
  readonly direct_eligibility: { readonly coherent_work_units: number; readonly primary_failure_domains: number; readonly scope_definition_complete: boolean; readonly deterministic_acceptance: boolean; readonly semantics_frozen: boolean; readonly ambiguous_write_ownership: boolean; readonly hard_sol_conditions: readonly string[] };
  readonly controller_limits: { readonly hard_m4_mutation_tool_limit: 1 | null; readonly max_replans: 0 };
  readonly routes: Readonly<Record<M8Mode, { readonly tasks: readonly M8RouteTask[] }>>;
  readonly expected_terminal_policy: M8Terminal;
}

export interface M8FixtureBundle {
  readonly protocol: typeof FIXTURE_PROTOCOL;
  readonly scenarios: readonly M8Scenario[];
}

export interface M8Invocation {
  /** Opaque handle; paths are never accepted back as deletion authority. */
  readonly invocation_identity: string;
}

export interface MaterializedM8Fixture {
  /** Read-only location for the controller; it is not a disposal capability. */
  readonly root: string;
  readonly workspace_identity: string;
  readonly scenarioId: string;
  readonly semanticFixtureIdentity: Sha256Digest;
  readonly initialGitTree: string;
  readonly initialStatusIdentity: Sha256Digest;
  readonly dirtyOverlayIdentity: Sha256Digest | null;
  readonly initialStateIdentity: Sha256Digest;
}

export interface M8StaticLogicalRoute {
  readonly logical_role: string;
  readonly provider_id: string;
  readonly model_id: string;
  readonly effort: "high" | "max";
  readonly tool_policy: Readonly<{
    readonly built_in_tools_disabled: boolean;
    readonly mutation_tool: string;
    readonly command_gateway: string;
    readonly maximum_tool_calls: number;
  }>;
}

/** Harness-native owner-controlled facts only; it deliberately excludes all run identities and digests. */
export interface M8StaticSlotProjection {
  readonly protocol: typeof STATIC_SLOT_PROTOCOL;
  readonly canonical_source_baseline: M8CanonicalSourceBaseline;
  readonly fixture_bundle_identity: Sha256Digest;
  readonly fixture_identity: Sha256Digest;
  readonly scenario: Readonly<{ readonly scenario_id: string; readonly scenario_class: string }>;
  readonly mode: M8Mode;
  readonly direct_eligible: boolean;
  readonly logical_route: readonly M8StaticLogicalRoute[];
  readonly baseline_mode: "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY";
  readonly static_scope: Readonly<{
    readonly readable_paths: readonly string[];
    readonly editable_paths: readonly string[];
    readonly frozen_paths: readonly string[];
    readonly required_outputs: readonly string[];
    readonly stopping_conditions: readonly string[];
  }>;
  readonly static_tasks: readonly Readonly<{
    readonly task_id: string;
    readonly objective: string;
    readonly editable_paths: readonly string[];
    readonly required_outputs: readonly string[];
    readonly dependencies: readonly string[];
    readonly topological_rank: number;
    readonly assigned_role: string;
    readonly write_owner: string;
  }>[];
  readonly static_budgets: Readonly<{
    readonly hard_m4_mutation_tool_limit: 1 | null;
    readonly max_replans: 0;
    readonly route_maximum_tool_calls: number;
    readonly max_leaves: number;
    readonly max_attempts_per_leaf: number;
    readonly max_worker_invocations: number;
    readonly max_model_turns: number;
    readonly max_tool_calls: number;
    readonly max_input_tokens: number;
    readonly max_output_tokens: number;
    readonly max_cost_microusd: number;
    readonly max_wall_time_ms: number;
  }>;
  readonly verification_command_specification: readonly Readonly<{
    readonly command_id: string;
    readonly executable: string;
    readonly args: readonly string[];
    readonly cwd: string;
    readonly timeout_ms: number;
    readonly expected_exit: number;
    readonly expected_result: M8Terminal;
  }>[];
  readonly expected_terminal_semantics: Readonly<{
    readonly terminal: M8Terminal;
    readonly task_success: boolean;
    readonly workflow_correctness: boolean;
    readonly pilot_validity: boolean;
  }>;
  readonly s09_mutation_limit_semantics: Readonly<{
    readonly hard_mutation_tool_limit: 1;
    readonly accepted_productive_mutations_at_most: 1;
    readonly second_productive_mutation_rejected: true;
    readonly no_productive_continuation_after_exhaustion: true;
  }> | null;
  readonly s10_scope_refusal_semantics: Readonly<{
    readonly required_objective_unsatisfied: true;
    readonly scope_refusal_observed: true;
  }> | null;
  readonly single_owner_acceptance: Readonly<{
    readonly requires_genuine_final_owner_decision: boolean;
    readonly static_plan_is_not_final_owner_acceptance: true;
  }>;
  readonly slot_execution_order: number;
}

export interface M8StaticSlotSpecification {
  readonly static_slot_projection: M8StaticSlotProjection;
  readonly static_slot_spec_identity: Sha256Digest;
}

/** Static plan arm: it has no workspace, M3, Contract, Task, Plan, or execution digest. */
export interface FrozenM8Arm {
  readonly fixture_bundle_identity: Sha256Digest;
  readonly matrix_identity: Sha256Digest;
  readonly scenario: M8Scenario;
  readonly scenario_id: string;
  readonly mode: M8Mode;
  readonly slot_execution_order: number;
  readonly static_slot: M8StaticSlotSpecification;
}

export interface M8FreezeResult {
  readonly protocol: typeof FREEZE_PROTOCOL;
  readonly bundle: M8FixtureBundle;
  readonly fixture_bundle_identity: Sha256Digest;
  readonly matrix_identity: Sha256Digest;
  readonly arms: readonly FrozenM8Arm[];
}

/** The sole harness owner-approval record; every entry is prospective static authority. */
export interface M8ApprovalManifest {
  readonly protocol: typeof APPROVAL_MANIFEST_PROTOCOL;
  readonly fixture_bundle_identity: Sha256Digest;
  readonly matrix_identity: Sha256Digest;
  readonly approved_static_slots: readonly M8StaticSlotSpecification[];
  readonly approval_manifest_identity: Sha256Digest;
}

export type M8FailureClassification = "REPOSITORY_DEFECT" | "REQUIREMENT_OR_AUTHORITY_DEFECT" | "ENVIRONMENT_DEFECT" | "HARNESS_DEFECT" | "ORCHESTRATION_DEFECT" | "USER_DECISION_REQUIRED";
/** Canonical output only; publication never accepts this structure from a caller. */
export interface M8EvidenceResult {
  readonly scenario_id: string;
  readonly mode: M8Mode;
  /** Null only when native authority never reached the approval callback. */
  readonly run_id: string | null;
  readonly execution_authority_digest: Sha256Digest | null;
  readonly terminal_workflow_result: M8Terminal | null;
  readonly task_success: boolean;
  readonly workflow_correctness: boolean;
  readonly pilot_validity: boolean;
  readonly failure_classification: M8FailureClassification | null;
  readonly verifier_identity: Sha256Digest | null;
  readonly terminal_evidence_identity: Sha256Digest | null;
  readonly final_postflight_identity: Sha256Digest | null;
  readonly command_result_identity: Sha256Digest | null;
}

/** Opaque registered result of one actual bounded-controller execution. */
export interface M8AuthoritativeRun {
  readonly run_identity: string;
}

type DirectoryRole = "INVOCATION_ROOT" | "WORKSPACES" | "EVIDENCE" | "RESULTS" | "RETAINED" | "CONTROLLER_ROOT" | "CONTROLLER_STATE";
interface DirectoryRegistration {
  readonly path: string;
  readonly device: number;
  readonly inode: number;
  readonly uid: number;
  readonly mode: number;
  readonly role: DirectoryRole;
}
interface InvocationRecord {
  readonly root: string;
  readonly workspaces: string;
  readonly evidence: string;
  readonly results: string;
  readonly retained: string;
  readonly rootRegistration: DirectoryRegistration;
  readonly workspaceRegistration: DirectoryRegistration;
  readonly evidenceRegistration: DirectoryRegistration;
  readonly resultsRegistration: DirectoryRegistration;
  readonly retainedRegistration: DirectoryRegistration;
}
interface WorkspaceRecord {
  readonly invocation: M8Invocation;
  readonly root: string;
  readonly device: number;
  readonly inode: number;
}
interface ExecutedM8Arm {
  readonly static_arm: FrozenM8Arm;
  readonly fixture_bundle_identity: Sha256Digest;
  readonly matrix_identity: Sha256Digest;
  readonly scenario: M8Scenario;
  readonly scenario_id: string;
  readonly mode: M8Mode;
  readonly slot_execution_order: number;
  readonly static_slot: M8StaticSlotSpecification;
  readonly approved_static_slot: M8StaticSlotSpecification;
  readonly runtime_static_slot: M8StaticSlotSpecification;
  readonly static_match: boolean;
  readonly materialization: MaterializedM8Fixture;
  readonly controller_authority: BoundedExecutionAuthority;
  readonly run_id: string;
  readonly execution_authority_digest: Sha256Digest;
}
interface AuthoritativeRunRecord {
  readonly invocation: M8Invocation;
  readonly freeze: M8FreezeResult;
  readonly approval: M8ApprovalManifest;
  readonly arm: FrozenM8Arm;
  /** Registered only after this run materializes its isolated workspace. */
  readonly materialization: MaterializedM8Fixture;
  readonly runtime: ExecutedM8Arm | null;
  readonly controllerResult: BoundedMutationRunResult;
  readonly controllerRoot: DirectoryRegistration | null;
  readonly stateRoot: DirectoryRegistration | null;
  readonly registrationError: string | null;
}

const invocationRecords = new Map<M8Invocation, InvocationRecord>();
const workspaceRecords = new Map<MaterializedM8Fixture, WorkspaceRecord>();
const authoritativeRunRecords = new Map<M8AuthoritativeRun, AuthoritativeRunRecord>();

function invalid(detail: string): never { throw new Error(`M8_FIXTURE_INVALID: ${detail}`); }
function binding(detail: string): never { throw new Error(`M8_APPROVAL_BINDING_MISMATCH: ${detail}`); }
function staticPlanBaselineMismatch(detail: string): never { throw new Error(`M8_STATIC_PLAN_BASELINE_MISMATCH: ${detail}`); }
function authorityInvalid(detail: string): never { throw new Error(`M8_EXECUTION_AUTHORITY_INVALID: ${detail}`); }
function gitObjectIdentity(value: unknown, label: string, reject: (detail: string) => never): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/u.test(value)) reject(`${label} is not a Git object identity`);
  return value;
}
function canonicalSourceBaseline(value: unknown, reject: (detail: string) => never): M8CanonicalSourceBaseline {
  if (value === null || typeof value !== "object" || Array.isArray(value)) reject("canonical source baseline is not an object");
  const record = value as Record<string, unknown>; const actual = Object.keys(record).sort(); const expected = ["architecture_identity", "commit", "tree", "v0_identity"];
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) reject("canonical source baseline has unknown or missing fields");
  const commit = gitObjectIdentity(record["commit"], "canonical source commit", reject);
  const tree = gitObjectIdentity(record["tree"], "canonical source tree", reject);
  if (record["architecture_identity"] !== M8_ARCHITECTURE_IDENTITY || record["v0_identity"] !== M8_V0_IDENTITY) reject("canonical source Architecture or V0 identity differs");
  return Object.freeze({ commit, tree, architecture_identity: M8_ARCHITECTURE_IDENTITY, v0_identity: M8_V0_IDENTITY });
}
function staticProjectionBaseline(value: unknown): M8CanonicalSourceBaseline { return canonicalSourceBaseline(value, binding); }
function freezeOptions(value: M8FreezeOptions | undefined): M8FreezeOptions {
  if (value === undefined) return Object.freeze({});
  if (value === null || typeof value !== "object" || Array.isArray(value)) staticPlanBaselineMismatch("freeze options are not an object");
  const record = value as Record<string, unknown>; const actual = Object.keys(record).sort(); const expected = ["canonical_source_baseline", "repository_root"];
  if ((actual.length !== expected.length && !(actual.length === 0 || actual.length === 1)) || actual.some((entry) => !expected.includes(entry))) staticPlanBaselineMismatch("freeze options have unknown fields");
  const root = record["repository_root"];
  if (root !== undefined && (typeof root !== "string" || root.length === 0 || root.includes("\0") || !isAbsolute(root) || resolve(root) !== root)) staticPlanBaselineMismatch("freeze repository root is not an absolute normalized path");
  const supplied = record["canonical_source_baseline"];
  const baseline = supplied === undefined ? undefined : canonicalSourceBaseline(supplied, staticPlanBaselineMismatch);
  return Object.freeze({ ...(root === undefined ? {} : { repository_root: root }), ...(baseline === undefined ? {} : { canonical_source_baseline: baseline }) });
}
function canonicalRepositoryIsClean(state: Awaited<ReturnType<typeof captureGitState>>): boolean {
  // A clean stable capture has no staged/conflict entries, so the real index is
  // exactly HEAD's tree; captureGitState snapshots both status and index twice.
  return !state.dirty && state.staged.length === 0 && state.unstaged.length === 0 && state.untracked.length === 0 &&
    state.conflicts.length === 0 && state.active_operations.length === 0 && !state.index_lock;
}
/** Derives the live clean repository baseline; no source commit/tree is retained in the harness. */
export async function deriveM8CanonicalSourceBaseline(repositoryRoot = process.cwd()): Promise<M8CanonicalSourceBaseline> {
  if (typeof repositoryRoot !== "string" || repositoryRoot.length === 0 || repositoryRoot.includes("\0") || !isAbsolute(repositoryRoot) || resolve(repositoryRoot) !== repositoryRoot) {
    staticPlanBaselineMismatch("canonical repository root is not an absolute normalized path");
  }
  const initial = await resolveRepositoryIdentity({ requestedPath: repositoryRoot, requireHead: true });
  const initialState = await captureGitState(initial);
  if (!canonicalRepositoryIsClean(initialState) || initialState.head !== initial.head || initialState.head_tree !== initial.head_tree) {
    staticPlanBaselineMismatch("canonical repository is not clean at baseline capture");
  }
  const current = await resolveRepositoryIdentity({ requestedPath: repositoryRoot, requireHead: true });
  if (current.worktree_root !== initial.worktree_root || current.head !== initial.head || current.head_tree !== initial.head_tree) {
    staticPlanBaselineMismatch("canonical repository HEAD or tree changed during baseline capture");
  }
  const currentState = await captureGitState(current);
  if (!canonicalRepositoryIsClean(currentState) || currentState.head !== current.head || currentState.head_tree !== current.head_tree) {
    staticPlanBaselineMismatch("canonical repository is not clean at baseline validation");
  }
  return Object.freeze({ commit: current.head, tree: current.head_tree, architecture_identity: M8_ARCHITECTURE_IDENTITY, v0_identity: M8_V0_IDENTITY });
}
async function freezeCanonicalSourceBaseline(options: M8FreezeOptions | undefined): Promise<M8CanonicalSourceBaseline> {
  const input = freezeOptions(options); const derived = await deriveM8CanonicalSourceBaseline(input.repository_root ?? process.cwd());
  if (input.canonical_source_baseline === undefined) return derived;
  const supplied = canonicalSourceBaseline(input.canonical_source_baseline, staticPlanBaselineMismatch);
  if (canonicalize(supplied) !== canonicalize(derived)) staticPlanBaselineMismatch("supplied canonical source baseline differs from current HEAD/tree or immutable identities");
  return derived;
}
function exact(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`);
  const record = value as Record<string, unknown>; const actual = Object.keys(record).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((entry, index) => entry !== expected[index])) invalid(`${label} has unknown or missing fields`);
  return record;
}
function text(value: unknown, label: string, max = 16_384): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.includes("\0")) invalid(`${label} must be bounded text`);
  return value;
}
function bool(value: unknown, label: string): boolean { if (typeof value !== "boolean") invalid(`${label} must be boolean`); return value; }
function number(value: unknown, label: string, minimum: number, maximum: number): number { if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) invalid(`${label} is out of bounds`); return value as number; }
function path(value: unknown, label: string): string {
  const result = text(value, label, 1_024);
  if (isAbsolute(result) || result === "." || result.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..") || resolve("/fixture", result) === "/fixture") invalid(`${label} is not a canonical relative path`);
  return result;
}
function sortedUnique(values: readonly string[], label: string): readonly string[] {
  if (new Set(values).size !== values.length || values.some((entry, index) => index > 0 && values[index - 1]! >= entry)) invalid(`${label} must be sorted and unique`);
  return Object.freeze([...values]);
}
function pathArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) invalid(`${label} must be a nonempty bounded array`);
  return sortedUnique(value.map((entry, index) => path(entry, `${label}[${index}]`)), label);
}
function textArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 64) invalid(`${label} must be a bounded array`);
  return Object.freeze(value.map((entry, index) => text(entry, `${label}[${index}]`)));
}
function sameStrings(left: readonly string[], right: readonly string[]): boolean { return canonicalize(left) === canonicalize(right); }
function contains(root: string, candidate: string): boolean { return candidate === root || candidate.startsWith(`${root}/`); }
function sameDigestArray(left: readonly Sha256Digest[], right: readonly Sha256Digest[]): boolean { return canonicalize(left) === canonicalize(right); }
function digest(value: unknown, label: string): Sha256Digest {
  try { assertSha256Digest(value, label); return value; }
  catch { binding(`${label} is not a SHA-256 digest`); }
}
function currentUid(): number { return typeof process.getuid === "function" ? process.getuid() : -1; }
function publicationUnsafe(detail: string): never { throw new Error(`M8_EVIDENCE_PUBLICATION_UNSAFE:${detail}`); }
function physicallyWithin(parent: string, candidate: string): boolean {
  const relation = relative(parent, candidate);
  return relation.length > 0 && !relation.startsWith("../") && relation !== ".." && !isAbsolute(relation);
}
async function registerPrivateDirectory(pathValue: string, role: DirectoryRole): Promise<DirectoryRegistration> {
  const canonical = resolve(pathValue);
  let stats; let physical: string;
  try { [stats, physical] = await Promise.all([lstat(canonical), realpath(canonical)]); }
  catch { publicationUnsafe(`${role} is unavailable during registration`); }
  if (!stats!.isDirectory() || stats!.isSymbolicLink() || physical! !== canonical ||
      (currentUid() !== -1 && stats!.uid !== currentUid()) || (stats!.mode & 0o777) !== 0o700) {
    publicationUnsafe(`${role} is not a private canonical directory during registration`);
  }
  return Object.freeze({ path: canonical, device: stats!.dev, inode: stats!.ino, uid: stats!.uid, mode: stats!.mode & 0o777, role });
}
async function revalidatePrivateDirectory(registration: DirectoryRegistration, parent?: DirectoryRegistration): Promise<void> {
  let stats; let physical: string;
  try { [stats, physical] = await Promise.all([lstat(registration.path), realpath(registration.path)]); }
  catch { publicationUnsafe(`${registration.role} is unavailable`); }
  if (!stats!.isDirectory() || stats!.isSymbolicLink() || physical! !== registration.path ||
      stats!.dev !== registration.device || stats!.ino !== registration.inode || stats!.uid !== registration.uid ||
      (stats!.mode & 0o777) !== registration.mode || (stats!.mode & 0o777) !== 0o700) {
    publicationUnsafe(`${registration.role} physical identity changed`);
  }
  if (parent !== undefined && (dirname(registration.path) !== parent.path || !physicallyWithin(parent.path, registration.path))) {
    publicationUnsafe(`${registration.role} is not its registered direct child`);
  }
}
async function revalidatePublicationTree(invocation: M8Invocation): Promise<InvocationRecord> {
  const owner = ownedInvocation(invocation);
  await revalidatePrivateDirectory(owner.rootRegistration);
  await revalidatePrivateDirectory(owner.workspaceRegistration, owner.rootRegistration);
  await revalidatePrivateDirectory(owner.evidenceRegistration, owner.rootRegistration);
  await revalidatePrivateDirectory(owner.resultsRegistration, owner.evidenceRegistration);
  await revalidatePrivateDirectory(owner.retainedRegistration, owner.rootRegistration);
  if (owner.root === owner.evidence || owner.root === owner.results || owner.root === owner.retained || owner.root === process.cwd() ||
      owner.root === resolve(process.cwd()) || !physicallyWithin(owner.root, owner.evidence) || !physicallyWithin(owner.evidence, owner.results)) {
    publicationUnsafe("registered publication tree is not invocation-owned");
  }
  return owner;
}

function fileManifest(value: unknown, label: string): M8FileManifest {
  const input = exact(value, ["path", "mode", "bytes_base64"], label); const bytes = text(input["bytes_base64"], `${label}.bytes_base64`, 1_048_576);
  let decoded: Buffer;
  try { decoded = Buffer.from(bytes, "base64"); } catch { invalid(`${label}.bytes_base64 is invalid`); }
  if (decoded.byteLength === 0 || decoded.toString("base64") !== bytes) invalid(`${label}.bytes_base64 is not canonical`);
  return Object.freeze({ path: path(input["path"], `${label}.path`), mode: number(input["mode"], `${label}.mode`, 0, 0o777), bytes_base64: bytes });
}
function fileArray(value: unknown, label: string): readonly M8FileManifest[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) invalid(`${label} must be a nonempty bounded array`);
  const files = value.map((entry, index) => fileManifest(entry, `${label}[${index}]`));
  if (new Set(files.map((entry) => entry.path)).size !== files.length || files.some((entry, index) => index > 0 && files[index - 1]!.path >= entry.path)) invalid(`${label} paths must be sorted and unique`);
  return Object.freeze(files);
}
function routeTask(value: unknown, label: string): M8RouteTask {
  const input = exact(value, ["task_id", "objective", "editable_paths", "required_outputs", "dependencies"], label);
  const id = text(input["task_id"], `${label}.task_id`, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(id)) invalid(`${label}.task_id is invalid`);
  return Object.freeze({ task_id: id, objective: text(input["objective"], `${label}.objective`), editable_paths: pathArray(input["editable_paths"], `${label}.editable_paths`), required_outputs: pathArray(input["required_outputs"], `${label}.required_outputs`), dependencies: sortedUnique(textArray(input["dependencies"], `${label}.dependencies`), `${label}.dependencies`) });
}
function parseRoute(value: unknown, label: string): { readonly tasks: readonly M8RouteTask[] } {
  const input = exact(value, ["tasks"], label);
  if (!Array.isArray(input["tasks"]) || input["tasks"].length === 0 || input["tasks"].length > 8) invalid(`${label}.tasks is invalid`);
  return Object.freeze({ tasks: Object.freeze(input["tasks"].map((entry, index) => routeTask(entry, `${label}.tasks[${index}]`))) });
}
function acceptanceFact(value: unknown, label: string): M8AcceptanceFact {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be an object`);
  const input = value as Record<string, unknown>; const kind = input["type"];
  if (kind === "expected_final_file" || kind === "frozen_file" || kind === "approved_dirty_overlay") {
    const record = exact(input, ["type", "path", "mode", "bytes_base64"], label);
    const manifest = fileManifest({ path: record["path"], mode: record["mode"], bytes_base64: record["bytes_base64"] }, label);
    return Object.freeze({ type: kind, ...manifest });
  }
  if (kind === "required_changed_path" || kind === "allowed_changed_path") {
    return Object.freeze({ type: kind, path: path(exact(input, ["type", "path"], label)["path"], `${label}.path`) });
  }
  if (kind === "required_command_result") {
    const record = exact(input, ["type", "command_id", "executable", "args", "cwd", "expected_exit"], label);
    const executable = text(record["executable"], `${label}.executable`, 4_096);
    if (!isAbsolute(executable) || resolve(executable) !== executable) invalid(`${label}.executable is not absolute`);
    const cwd = text(record["cwd"], `${label}.cwd`, 1_024);
    if (cwd !== ".") path(cwd, `${label}.cwd`);
    return Object.freeze({ type: kind, command_id: text(record["command_id"], `${label}.command_id`, 128), executable, args: textArray(record["args"], `${label}.args`), cwd, expected_exit: number(record["expected_exit"], `${label}.expected_exit`, 0, 255) });
  }
  if (kind === "expected_terminal") {
    const terminal = exact(input, ["type", "terminal"], label)["terminal"];
    if (terminal !== "PASS" && terminal !== "BLOCKED") invalid(`${label}.terminal is invalid`);
    return Object.freeze({ type: kind, terminal });
  }
  if (kind === "required_budget_fact") {
    const record = exact(input, ["type", "hard_mutation_tool_limit", "accepted_productive_mutations_at_most", "second_productive_mutation_rejected", "no_productive_continuation_after_exhaustion"], label);
    if (record["hard_mutation_tool_limit"] !== 1 || record["accepted_productive_mutations_at_most"] !== 1 || record["second_productive_mutation_rejected"] !== true || record["no_productive_continuation_after_exhaustion"] !== true) invalid(`${label} budget fact is not canonical`);
    return Object.freeze({ type: kind, hard_mutation_tool_limit: 1, accepted_productive_mutations_at_most: 1, second_productive_mutation_rejected: true, no_productive_continuation_after_exhaustion: true });
  }
  if (kind === "required_scope_refusal") {
    const record = exact(input, ["type", "required_objective_unsatisfied", "scope_refusal_observed"], label);
    if (record["required_objective_unsatisfied"] !== true || record["scope_refusal_observed"] !== true) invalid(`${label} scope fact is not canonical`);
    return Object.freeze({ type: kind, required_objective_unsatisfied: true, scope_refusal_observed: true });
  }
  invalid(`${label}.type is unknown`);
}
function acceptanceFacts(value: unknown, label: string): readonly M8AcceptanceFact[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) invalid(`${label} must be a nonempty bounded array`);
  return Object.freeze(value.map((entry, index) => acceptanceFact(entry, `${label}[${index}]`)));
}
function directEligible(facts: M8Scenario["direct_eligibility"]): boolean {
  return facts.coherent_work_units === 1 && facts.primary_failure_domains === 1 && facts.scope_definition_complete && facts.deterministic_acceptance && facts.semantics_frozen && !facts.ambiguous_write_ownership && facts.hard_sol_conditions.length === 0;
}

function validateRouteSemantics(scenario: M8Scenario): void {
  for (const mode of MODES) {
    const tasks = scenario.routes[mode].tasks;
    if (mode === "ROUTED_DAG") {
      if (tasks.length < 2 || tasks.length > 8) invalid(`${scenario.scenario_id} Routed route must have 2–8 leaves`);
      const ids = new Set<string>(); const outputs: string[] = [];
      for (const [index, task] of tasks.entries()) {
        if (ids.has(task.task_id) || task.editable_paths.some((entry) => !scenario.editable_paths.includes(entry)) || task.required_outputs.some((entry) => !scenario.required_outputs.includes(entry)) || task.editable_paths.length === 0) invalid(`${scenario.scenario_id} Routed task scope is invalid`);
        ids.add(task.task_id); outputs.push(...task.required_outputs);
        if (!sameStrings(task.dependencies, index === 0 ? [] : [tasks[index - 1]!.task_id])) invalid(`${scenario.scenario_id} Routed leaves are not static sequential`);
      }
      if (!sameStrings([...outputs].sort(), scenario.required_outputs)) invalid(`${scenario.scenario_id} Routed outputs lack unique ownership`);
    } else {
      if (tasks.length !== 1 || tasks[0]!.dependencies.length !== 0 || !sameStrings(tasks[0]!.editable_paths, scenario.editable_paths) || !sameStrings(tasks[0]!.required_outputs, scenario.required_outputs)) invalid(`${scenario.scenario_id} ${mode} must have one coherent owner task`);
    }
  }
}

function scenario(value: unknown, label: string): M8Scenario {
  const input = exact(value, ["scenario_id", "scenario_class", "objective", "representative_rationale", "initial_files", "approved_dirty_overlay", "readable_paths", "editable_paths", "frozen_paths", "required_outputs", "expected_behavior", "acceptance_properties", "acceptance_facts", "verification", "stopping_conditions", "direct_eligibility", "controller_limits", "routes", "expected_terminal_policy"], label);
  const id = text(input["scenario_id"], `${label}.scenario_id`, 16);
  if (!(SCENARIO_IDS as readonly string[]).includes(id)) invalid(`${label}.scenario_id is not canonical`);
  const initial = fileArray(input["initial_files"], `${label}.initial_files`);
  const overlay = input["approved_dirty_overlay"] === null ? null : fileArray(input["approved_dirty_overlay"], `${label}.approved_dirty_overlay`);
  if (overlay !== null && initial.some((entry) => overlay.some((dirty) => dirty.path === entry.path))) invalid(`${label}.dirty overlay overlaps baseline`);
  const behaviorInput = exact(input["expected_behavior"], ["terminal", "task_success", "workflow_correctness", "pilot_validity"], `${label}.expected_behavior`);
  if (behaviorInput["terminal"] !== "PASS" && behaviorInput["terminal"] !== "BLOCKED") invalid(`${label}.expected terminal is invalid`);
  const verificationInput = exact(input["verification"], ["executable", "args", "cwd", "timeout_ms", "expected_exit", "expected_result"], `${label}.verification`);
  const factsInput = exact(input["direct_eligibility"], ["coherent_work_units", "primary_failure_domains", "scope_definition_complete", "deterministic_acceptance", "semantics_frozen", "ambiguous_write_ownership", "hard_sol_conditions"], `${label}.direct_eligibility`);
  const limitsInput = exact(input["controller_limits"], ["hard_m4_mutation_tool_limit", "max_replans"], `${label}.controller_limits`);
  const routesInput = exact(input["routes"], MODES, `${label}.routes`);
  const scenarioClass = text(input["scenario_class"], `${label}.scenario_class`);
  if (SCENARIO_CLASSES.get(id) !== scenarioClass) invalid(`${label}.scenario_class is not canonical for its ID`);
  if (typeof verificationInput["executable"] !== "string" || !isAbsolute(verificationInput["executable"]) || resolve(verificationInput["executable"]) !== verificationInput["executable"]) invalid(`${label}.verification.executable is not an absolute canonical executable`);
  const result: M8Scenario = Object.freeze({
    scenario_id: id as M8Scenario["scenario_id"], scenario_class: scenarioClass, objective: text(input["objective"], `${label}.objective`), representative_rationale: text(input["representative_rationale"], `${label}.representative_rationale`), initial_files: initial, approved_dirty_overlay: overlay,
    readable_paths: pathArray(input["readable_paths"], `${label}.readable_paths`), editable_paths: pathArray(input["editable_paths"], `${label}.editable_paths`), frozen_paths: pathArray(input["frozen_paths"], `${label}.frozen_paths`), required_outputs: pathArray(input["required_outputs"], `${label}.required_outputs`),
    expected_behavior: Object.freeze({ terminal: behaviorInput["terminal"] as M8Terminal, task_success: bool(behaviorInput["task_success"], `${label}.expected_behavior.task_success`), workflow_correctness: bool(behaviorInput["workflow_correctness"], `${label}.expected_behavior.workflow_correctness`), pilot_validity: bool(behaviorInput["pilot_validity"], `${label}.expected_behavior.pilot_validity`) }),
    acceptance_properties: textArray(input["acceptance_properties"], `${label}.acceptance_properties`),
    acceptance_facts: acceptanceFacts(input["acceptance_facts"], `${label}.acceptance_facts`),
    verification: Object.freeze({ executable: text(verificationInput["executable"], `${label}.verification.executable`, 4_096), args: textArray(verificationInput["args"], `${label}.verification.args`), cwd: verificationInput["cwd"] === "." ? "." : path(verificationInput["cwd"], `${label}.verification.cwd`), timeout_ms: number(verificationInput["timeout_ms"], `${label}.verification.timeout_ms`, 1, 1_800_000), expected_exit: number(verificationInput["expected_exit"], `${label}.verification.expected_exit`, 0, 255), expected_result: verificationInput["expected_result"] === "PASS" || verificationInput["expected_result"] === "BLOCKED" ? verificationInput["expected_result"] : invalid(`${label}.verification.expected_result is invalid`) }),
    stopping_conditions: textArray(input["stopping_conditions"], `${label}.stopping_conditions`),
    direct_eligibility: Object.freeze({ coherent_work_units: number(factsInput["coherent_work_units"], `${label}.direct_eligibility.coherent_work_units`, 1, 8), primary_failure_domains: number(factsInput["primary_failure_domains"], `${label}.direct_eligibility.primary_failure_domains`, 1, 8), scope_definition_complete: bool(factsInput["scope_definition_complete"], `${label}.direct_eligibility.scope_definition_complete`), deterministic_acceptance: bool(factsInput["deterministic_acceptance"], `${label}.direct_eligibility.deterministic_acceptance`), semantics_frozen: bool(factsInput["semantics_frozen"], `${label}.direct_eligibility.semantics_frozen`), ambiguous_write_ownership: bool(factsInput["ambiguous_write_ownership"], `${label}.direct_eligibility.ambiguous_write_ownership`), hard_sol_conditions: textArray(factsInput["hard_sol_conditions"], `${label}.direct_eligibility.hard_sol_conditions`) }),
    controller_limits: Object.freeze({ hard_m4_mutation_tool_limit: limitsInput["hard_m4_mutation_tool_limit"] === null ? null : limitsInput["hard_m4_mutation_tool_limit"] === 1 ? 1 : invalid(`${label}.controller hard limit is invalid`), max_replans: limitsInput["max_replans"] === 0 ? 0 : invalid(`${label}.controller max_replans is invalid`) }),
    routes: Object.freeze({ DIRECT_LUNA_HIGH: parseRoute(routesInput["DIRECT_LUNA_HIGH"], `${label}.routes.DIRECT_LUNA_HIGH`), SINGLE_OWNER_SOL: parseRoute(routesInput["SINGLE_OWNER_SOL"], `${label}.routes.SINGLE_OWNER_SOL`), ROUTED_DAG: parseRoute(routesInput["ROUTED_DAG"], `${label}.routes.ROUTED_DAG`) }),
    expected_terminal_policy: input["expected_terminal_policy"] === "PASS" || input["expected_terminal_policy"] === "BLOCKED" ? input["expected_terminal_policy"] : invalid(`${label}.expected_terminal_policy is invalid`),
  });
  if (result.initial_files.some((entry) => !result.readable_paths.includes(entry.path)) || result.approved_dirty_overlay?.some((entry) => !result.readable_paths.includes(entry.path)) || result.editable_paths.some((entry) => result.frozen_paths.some((frozen) => contains(frozen, entry)))) invalid(`${label} path authorities conflict`);
  const terminalFacts = result.acceptance_facts.filter((fact) => fact.type === "expected_terminal");
  const commandFacts = result.acceptance_facts.filter((fact) => fact.type === "required_command_result");
  if (terminalFacts.length !== 1 || terminalFacts[0]!.terminal !== result.expected_terminal_policy || commandFacts.length !== 1 ||
      result.expected_behavior.terminal !== result.expected_terminal_policy || result.verification.expected_result !== result.expected_terminal_policy || (result.expected_terminal_policy === "PASS") !== result.expected_behavior.task_success || !result.expected_behavior.workflow_correctness || !result.expected_behavior.pilot_validity) invalid(`${label} expected safety policy or typed acceptance is inconsistent`);
  if (result.acceptance_facts.some((fact) => (fact.type === "expected_final_file" || fact.type === "frozen_file" || fact.type === "approved_dirty_overlay") && !result.readable_paths.includes(fact.path))) invalid(`${label} acceptance fact escapes readable paths`);
  validateRouteSemantics(result);
  return result;
}

export function parseM8FixtureBundle(value: unknown): M8FixtureBundle {
  const input = exact(value, ["protocol", "scenarios"], "fixture bundle");
  if (input["protocol"] !== FIXTURE_PROTOCOL || !Array.isArray(input["scenarios"]) || input["scenarios"].length !== SCENARIO_IDS.length) invalid("fixture bundle protocol or scenario count is invalid");
  const scenarios = input["scenarios"].map((entry, index) => scenario(entry, `scenarios[${index}]`));
  if (!sameStrings(scenarios.map((entry) => entry.scenario_id), SCENARIO_IDS)) invalid("scenario IDs are not exactly canonical and ordered");
  const direct = scenarios.filter((entry) => directEligible(entry.direct_eligibility)).map((entry) => entry.scenario_id);
  if (!sameStrings(direct, [...DIRECT_IDS].sort())) invalid("Direct eligibility is not prospectively canonical");
  if (scenarios.find((entry) => entry.scenario_id === "M8-S09")?.controller_limits.hard_m4_mutation_tool_limit !== 1 || scenarios.filter((entry) => entry.scenario_id !== "M8-S09").some((entry) => entry.controller_limits.hard_m4_mutation_tool_limit !== null)) invalid("only M8-S09 may own the hard tool limit");
  const s01 = scenarios[0]!;
  if (s01.scenario_class !== "mechanical edit" || !sameStrings(s01.editable_paths, ["src/service-a.conf", "src/service-b.conf"]) || s01.routes.ROUTED_DAG.tasks.length !== 2) invalid("M8-S01 two-file mechanical semantics are not canonical");
  return Object.freeze({ protocol: FIXTURE_PROTOCOL, scenarios: Object.freeze(scenarios) });
}

export async function loadM8FixtureBundle(pathValue: string): Promise<M8FixtureBundle> { return parseM8FixtureBundle(JSON.parse(await readFile(pathValue, "utf8")) as unknown); }
export function semanticFixtureIdentity(value: M8Scenario): Sha256Digest { return sha256Canonical({ protocol: "m8-semantic-fixture-v1", scenario: value }); }
export function fixtureBundleIdentity(bundle: M8FixtureBundle): Sha256Digest { return sha256Canonical({ protocol: "m8-fixture-bundle-v1", scenarios: bundle.scenarios.map((entry) => semanticFixtureIdentity(entry)) }); }
export function directEligibleScenario(value: M8Scenario): boolean { return directEligible(value.direct_eligibility); }
export function canonicalSlotCount(bundle: M8FixtureBundle): { readonly singleOwner: number; readonly routed: number; readonly direct: number; readonly total: number } {
  const direct = bundle.scenarios.filter(directEligibleScenario).length;
  return Object.freeze({ singleOwner: bundle.scenarios.length, routed: bundle.scenarios.length, direct, total: bundle.scenarios.length * 2 + direct });
}
export function m8MatrixIdentity(bundle: M8FixtureBundle): Sha256Digest {
  return sha256Canonical({
    protocol: MATRIX_PROTOCOL,
    fixture_bundle_identity: fixtureBundleIdentity(bundle),
    slots: bundle.scenarios.flatMap((entry) => MODES.filter((mode) => mode !== "DIRECT_LUNA_HIGH" || directEligibleScenario(entry)).map((mode) => ({ scenario_id: entry.scenario_id, mode }))),
  });
}

async function git(root: string, args: readonly string[]): Promise<string> {
  const environment = { ...process.env, GIT_AUTHOR_NAME: "M8 Fixture", GIT_AUTHOR_EMAIL: "m8-fixture@example.invalid", GIT_COMMITTER_NAME: "M8 Fixture", GIT_COMMITTER_EMAIL: "m8-fixture@example.invalid", GIT_AUTHOR_DATE: "2000-01-01T00:00:00.000Z", GIT_COMMITTER_DATE: "2000-01-01T00:00:00.000Z" };
  const result = await execFileAsync("git", [...args], { cwd: root, env: environment, encoding: "utf8", maxBuffer: 1_048_576 });
  return result.stdout.trimEnd();
}
async function materializeFiles(root: string, files: readonly M8FileManifest[]): Promise<void> {
  for (const file of files) {
    const target = join(root, file.path); await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, Buffer.from(file.bytes_base64, "base64"), { mode: file.mode, flag: "wx" }); await chmod(target, file.mode);
  }
}
async function statusIdentity(root: string): Promise<Sha256Digest> {
  const result = await execFileAsync("git", ["status", "--porcelain=v1", "-z"], { cwd: root, encoding: "buffer", maxBuffer: 1_048_576 });
  return sha256Canonical({ protocol: "m8-initial-status-v1", porcelain_base64: Buffer.from(result.stdout).toString("base64") });
}

/** Creates one private absolute root for an M8 invocation and registers every owned publication directory. */
export async function createM8InvocationRoot(temporaryParent = tmpdir()): Promise<M8Invocation> {
  const requestedParent = resolve(temporaryParent); await mkdir(requestedParent, { recursive: true, mode: 0o700 });
  const [parentStat, parent] = await Promise.all([lstat(requestedParent), realpath(requestedParent)]);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) throw new Error("M8_INVOCATION_PARENT_INVALID");
  const root = await mkdtemp(join(parent, "m8-invocation-")); await chmod(root, 0o700);
  const workspaces = join(root, "workspaces"); const evidence = join(root, "evidence"); const results = join(evidence, "results"); const retained = join(root, "retained");
  await Promise.all([mkdir(workspaces, { mode: 0o700 }), mkdir(evidence, { mode: 0o700 }), mkdir(retained, { mode: 0o700 })]);
  await mkdir(results, { mode: 0o700 });
  const [rootRegistration, workspaceRegistration, evidenceRegistration, resultsRegistration, retainedRegistration] = await Promise.all([
    registerPrivateDirectory(root, "INVOCATION_ROOT"), registerPrivateDirectory(workspaces, "WORKSPACES"), registerPrivateDirectory(evidence, "EVIDENCE"),
    registerPrivateDirectory(results, "RESULTS"), registerPrivateDirectory(retained, "RETAINED"),
  ]);
  const invocation = Object.freeze({ invocation_identity: sha256Canonical({ protocol: "m8-invocation-v1", root }) });
  invocationRecords.set(invocation, Object.freeze({ root, workspaces, evidence, results, retained, rootRegistration, workspaceRegistration, evidenceRegistration, resultsRegistration, retainedRegistration }));
  return invocation;
}
function ownedInvocation(value: M8Invocation): InvocationRecord {
  const record = invocationRecords.get(value); if (record === undefined) throw new Error("M8_INVOCATION_UNREGISTERED"); return record;
}
/** Explicit owner cleanup only; it never accepts a path and refuses unsafe or substituted trees. */
export async function disposeM8Invocation(value: M8Invocation): Promise<void> {
  const owner = ownedInvocation(value); if ([...workspaceRecords.values()].some((workspace) => workspace.invocation === value)) throw new Error("M8_INVOCATION_WORKSPACES_LIVE");
  try { await revalidatePublicationTree(value); }
  catch { throw new Error("M8_INVOCATION_DISPOSAL_UNSAFE"); }
  await rm(owner.root, { recursive: true, force: false });
  invocationRecords.delete(value);
  for (const [handle, record] of authoritativeRunRecords) if (record.invocation === value) authoritativeRunRecords.delete(handle);
}
/** Synthetic, Git-isolated materialization under a registered invocation root. */
export async function materializeM8Fixture(scenarioValue: M8Scenario, invocationOrParent: M8Invocation | string = tmpdir()): Promise<MaterializedM8Fixture> {
  const invocation = typeof invocationOrParent === "string" ? await createM8InvocationRoot(invocationOrParent) : invocationOrParent;
  const owner = ownedInvocation(invocation); await revalidatePrivateDirectory(owner.rootRegistration); await revalidatePrivateDirectory(owner.workspaceRegistration, owner.rootRegistration);
  const root = await mkdtemp(join(owner.workspaces, "workspace-")); await chmod(root, 0o700);
  try {
    await git(root, ["init", "-q", "-b", "main"]); await git(root, ["config", "user.name", "M8 Fixture"]); await git(root, ["config", "user.email", "m8-fixture@example.invalid"]);
    await materializeFiles(root, scenarioValue.initial_files); await git(root, ["add", "--", "."]); await git(root, ["commit", "-qm", "M8 synthetic baseline"]);
    const initialGitTree = await git(root, ["rev-parse", "HEAD^{tree}"]);
    if (scenarioValue.approved_dirty_overlay !== null) await materializeFiles(root, scenarioValue.approved_dirty_overlay);
    const dirtyOverlayIdentity = scenarioValue.approved_dirty_overlay === null ? null : sha256Canonical({ protocol: "m8-dirty-overlay-v1", files: scenarioValue.approved_dirty_overlay });
    const initialStatusIdentity = await statusIdentity(root); const semantic = semanticFixtureIdentity(scenarioValue); const stats = await lstat(root);
    const result = Object.freeze({ root, workspace_identity: sha256Canonical({ protocol: "m8-workspace-v1", invocation_identity: invocation.invocation_identity, root }), scenarioId: scenarioValue.scenario_id, semanticFixtureIdentity: semantic, initialGitTree, initialStatusIdentity, dirtyOverlayIdentity, initialStateIdentity: sha256Canonical({ protocol: "m8-initial-state-v1", semantic_fixture_identity: semantic, initial_git_tree: initialGitTree, initial_status_identity: initialStatusIdentity, dirty_overlay_identity: dirtyOverlayIdentity }) });
    workspaceRecords.set(result, { invocation, root, device: stats.dev, inode: stats.ino }); return result;
  } catch (error: unknown) { await rm(root, { recursive: true, force: true }); throw error; }
}
/** Registered opaque object identity is required; no caller path can be deleted. */
export async function disposeMaterializedM8Fixture(value: MaterializedM8Fixture): Promise<void> {
  const owned = workspaceRecords.get(value); if (owned === undefined) throw new Error("M8_WORKSPACE_UNREGISTERED"); const invocation = ownedInvocation(owned.invocation);
  try { await revalidatePrivateDirectory(invocation.rootRegistration); await revalidatePrivateDirectory(invocation.workspaceRegistration, invocation.rootRegistration); }
  catch { throw new Error("M8_WORKSPACE_DISPOSAL_UNSAFE"); }
  const stats = await lstat(owned.root); const physical = await realpath(owned.root);
  if (!stats.isDirectory() || stats.isSymbolicLink() || stats.dev !== owned.device || stats.ino !== owned.inode || physical !== owned.root ||
      dirname(physical) !== invocation.workspaces || !physicallyWithin(invocation.workspaces, physical) || physical === invocation.root || physical === invocation.workspaces) {
    throw new Error("M8_WORKSPACE_DISPOSAL_UNSAFE");
  }
  await rm(physical, { recursive: true, force: false }); workspaceRecords.delete(value);
}

function controllerGoal(scenarioValue: M8Scenario, mode: M8Mode): BoundedMutationGoal {
  const route = scenarioValue.routes[mode];
  return Object.freeze({
    objective: scenarioValue.objective,
    stop_condition: scenarioValue.stopping_conditions.join("\n"),
    execution_mode: mode,
    scope: Object.freeze({ readable_paths: scenarioValue.readable_paths, editable_paths: scenarioValue.editable_paths, frozen_paths: scenarioValue.frozen_paths }),
    required_outputs: scenarioValue.required_outputs,
    tasks: Object.freeze(route.tasks.map((task) => Object.freeze({ task_id: task.task_id, objective: task.objective, editable_paths: task.editable_paths, required_outputs: task.required_outputs, dependencies: task.dependencies }))),
    ...(scenarioValue.approved_dirty_overlay === null ? {} : { baseline_mode: "APPROVED_BASELINE_DIRTY" as const }),
  });
}

function controllerVerificationAuthority(scenarioValue: M8Scenario): BoundedMutationAuthority["verification_commands"][number] {
  const verification = scenarioValue.verification;
  const command = scenarioValue.acceptance_facts.find((fact): fact is Extract<M8AcceptanceFact, { readonly type: "required_command_result" }> => fact.type === "required_command_result");
  if (command === undefined) throw new Error("M8_CONTROLLER_VERIFICATION_COMMAND_ABSENT");
  if (verification.cwd !== ".") return Object.freeze({ command_id: command.command_id, executable: verification.executable, args: verification.args, cwd: verification.cwd, timeout_ms: verification.timeout_ms });
  const entry = verification.args[0]; const slash = entry?.lastIndexOf("/") ?? -1;
  if (slash <= 0) throw new Error("M8_CONTROLLER_VERIFICATION_SCOPE_UNREPRESENTABLE");
  const cwd = entry!.slice(0, slash); const script = entry!.slice(slash + 1);
  if (!scenarioValue.readable_paths.includes(cwd) || script.length === 0) throw new Error("M8_CONTROLLER_VERIFICATION_SCOPE_UNREPRESENTABLE");
  // The frozen fixture's root-relative script is represented through the
  // bounded controller's exact readable directory; the actual Contract binds
  // the resulting executable/cwd/argv identity before approval.
  return Object.freeze({ command_id: command.command_id, executable: verification.executable, args: Object.freeze([script, ...verification.args.slice(1)]), cwd, timeout_ms: verification.timeout_ms });
}

function controllerAuthority(scenarioValue: M8Scenario): BoundedMutationAuthority {
  const dirty = scenarioValue.approved_dirty_overlay === null ? undefined : scenarioValue.approved_dirty_overlay.map((file) => Object.freeze({
    path: file.path,
    ownershipClass: "PREEXISTING_UNRELATED" as const,
    dataClass: null,
    captureMode: "HASH_ONLY" as const,
    explicitBlobApproval: false,
    retentionDaysAfterTerminal: null,
  }));
  return Object.freeze({
    verification_commands: Object.freeze([controllerVerificationAuthority(scenarioValue)]),
    ...(dirty === undefined ? {} : { dirty_baseline_decisions: Object.freeze(dirty) }),
    ...(scenarioValue.controller_limits.hard_m4_mutation_tool_limit === null ? {} : { hard_mutation_tool_limit: 1 as const }),
  });
}

function frozenBaselineApproval(scenarioValue: M8Scenario): ((baseline: { readonly content_sha256: string }) => Promise<{ readonly baseline_content_sha256: Sha256Digest; readonly approved_by: string; readonly approved_at: string } | null>) | undefined {
  if (scenarioValue.approved_dirty_overlay === null) return undefined;
  return async (baseline) => Object.freeze({ baseline_content_sha256: baseline.content_sha256 as Sha256Digest, approved_by: M8_FIXTURE_APPROVER, approved_at: M8_FIXTURE_APPROVED_AT });
}

function assertControllerAuthority(value: BoundedExecutionAuthority): void {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) authorityInvalid("controller authority is not an object");
    assertDocumentValid("pi_gacw_repository_identity_v0", value.repository);
    assertDocumentValid("pi_gacw_baseline_runtime_v0", value.baseline);
    if (value.baseline_approval !== null) assertDocumentValid("pi_gacw_baseline_approval_runtime_v0", value.baseline_approval);
    assertDocumentValid("pi_gacw_route_map_v0", value.route_map);
    assertDocumentValid("pi_gacw_route_map_approval_v0", value.route_map_approval);
    assertDocumentValid("pi_gacw_budget_v0", value.budget);
    assertDocumentValid("pi_gacw_contract_v0", value.contract);
    for (const task of value.tasks) assertDocumentValid("pi_gacw_task_v0", task);
    if (value.task_graph !== null) assertDocumentValid("pi_gacw_task_graph_v0", value.task_graph);
    if (value.plan !== null) assertDocumentValid("pi_gacw_plan_approval_v0", value.plan);
    assertDocumentValid("pi_gacw_reducer_policy_v0", value.reducer_policy);
    if (value.run_id.length === 0 || value.baseline.run_id !== value.run_id || value.reducer_policy.run_id !== value.run_id) authorityInvalid("run ID is not the exact controller run");
    const baselineIdentity = value.baseline.baseline_mode === "CLEAN_REQUIRED"
      ? value.baseline_approval === null ? value.baseline.content_sha256 : authorityInvalid("clean baseline has an approval")
      : value.baseline_approval === null || value.baseline_approval.baseline_runtime_content_sha256 !== value.baseline.content_sha256
        ? authorityInvalid("dirty baseline approval does not bind the baseline")
        : value.baseline_approval.content_sha256;
    if (value.baseline_authority_identity !== baselineIdentity || value.contract.baseline_approval_sha256 !== baselineIdentity) authorityInvalid("baseline authority differs from Contract authority");
    if (value.contract.execution_mode !== value.mode || value.reducer_policy.execution_mode !== value.mode) authorityInvalid("mode differs from controller documents");
    if (value.route_map_approval.route_map_sha256 !== value.route_map.route_map_sha256 || value.contract.route_map_approval_sha256 !== value.route_map_approval.route_map_approval_sha256) authorityInvalid("route authority differs from Contract authority");
    if (value.controller_limits.max_replans !== 0 || value.reducer_policy.limits.max_replans !== 0 || value.budget.limits.max_replans !== 0) authorityInvalid("controller replan limit is not zero");
    // The route/M5 cap is total accepted M4 usage. A hard mutation cap is a
    // separate bounded-admission fact and never shrinks read/evidence capacity.
    const totalM4ToolLimit = TOTAL_M4_TOOL_LIMIT;
    if (value.route_map.routes.some((entry) => entry.tool_policy.maximum_tool_calls !== totalM4ToolLimit)) authorityInvalid("controller route total M4 tool limit differs");
    const workerCount = value.mode === "ROUTED_DAG" ? value.tasks.length + 2 : 1;
    if (value.budget.limits.max_tool_calls !== workerCount * totalM4ToolLimit) authorityInvalid("controller budget total M4 tool limit differs");
    if (value.mode === "ROUTED_DAG") {
      if (value.task_graph === null || value.plan === null || value.plan.bindings.contract_sha256 !== value.contract.contract_sha256 || value.plan.bindings.dag.task_graph_sha256 !== value.task_graph.task_graph_sha256 || !sameStrings(value.plan.bindings.dag.ordered_task_packet_identities, value.tasks.map((task) => task.task_sha256))) authorityInvalid("routed TaskGraph or Plan differs from controller authority");
    } else if (value.task_graph !== null || value.plan !== null) authorityInvalid("non-routed execution carries DAG authority");
  } catch (error: unknown) {
    if (error instanceof Error && error.message.startsWith("M8_EXECUTION_AUTHORITY_INVALID:")) throw error;
    authorityInvalid(error instanceof Error ? error.message : "controller authority validation failed");
  }
}

function assertMaterialization(scenarioValue: M8Scenario, materialization: MaterializedM8Fixture): void {
  if (materialization.scenarioId !== scenarioValue.scenario_id || materialization.semanticFixtureIdentity !== semanticFixtureIdentity(scenarioValue)) binding("materialized fixture semantic identity differs");
  const expectedOverlay = scenarioValue.approved_dirty_overlay === null ? null : sha256Canonical({ protocol: "m8-dirty-overlay-v1", files: scenarioValue.approved_dirty_overlay });
  if (materialization.dirtyOverlayIdentity !== expectedOverlay) binding("materialized dirty-overlay identity differs");
  const expectedInitial = sha256Canonical({ protocol: "m8-initial-state-v1", semantic_fixture_identity: materialization.semanticFixtureIdentity, initial_git_tree: materialization.initialGitTree, initial_status_identity: materialization.initialStatusIdentity, dirty_overlay_identity: materialization.dirtyOverlayIdentity });
  if (materialization.initialStateIdentity !== expectedInitial) binding("materialized initial-state identity differs");
}

/** The run-specific digest is constructed only from the native authority created for this materialized workspace. */
export function m8ExecutionAuthorityDigest(input: {
  readonly fixture_bundle_identity: Sha256Digest;
  readonly scenario: M8Scenario;
  readonly mode: M8Mode;
  readonly materialization: MaterializedM8Fixture;
  readonly controller_authority: BoundedExecutionAuthority;
}): Sha256Digest {
  assertControllerAuthority(input.controller_authority);
  assertMaterialization(input.scenario, input.materialization);
  if (input.controller_authority.mode !== input.mode) authorityInvalid("controller mode differs from arm mode");
  return sha256Canonical({
    protocol: EXECUTION_AUTHORITY_PROTOCOL,
    fixture_bundle_identity: input.fixture_bundle_identity,
    scenario_id: input.scenario.scenario_id,
    run_id: input.controller_authority.run_id,
    mode: input.mode,
    fixture_initial_state_identity: input.materialization.initialStateIdentity,
    controller_authority: {
      baseline_authority_identity: input.controller_authority.baseline_authority_identity,
      route_map_content_sha256: input.controller_authority.route_map.content_sha256,
      route_map_approval_content_sha256: input.controller_authority.route_map_approval.content_sha256,
      budget_content_sha256: input.controller_authority.budget.content_sha256,
      contract_content_sha256: input.controller_authority.contract.content_sha256,
      task_content_sha256: input.controller_authority.tasks.map((task) => task.content_sha256),
      task_graph_content_sha256: input.controller_authority.task_graph?.content_sha256 ?? null,
      plan_content_sha256: input.controller_authority.plan?.content_sha256 ?? null,
      reducer_policy_content_sha256: input.controller_authority.reducer_policy.content_sha256,
      controller_limits: input.controller_authority.controller_limits,
    },
  });
}

function canonicalBundle(bundle: M8FixtureBundle): M8FixtureBundle { return parseM8FixtureBundle(bundle); }
function scenarioFromBundle(bundle: M8FixtureBundle, scenarioValue: M8Scenario): M8Scenario {
  const selected = bundle.scenarios.find((entry) => entry.scenario_id === scenarioValue.scenario_id);
  if (selected === undefined || semanticFixtureIdentity(selected) !== semanticFixtureIdentity(scenarioValue)) throw new Error("M8_STATIC_SLOT_SCENARIO_NOT_IN_BUNDLE");
  return selected;
}
function fixtureCommand(scenarioValue: M8Scenario): Extract<M8AcceptanceFact, { readonly type: "required_command_result" }> {
  const command = scenarioValue.acceptance_facts.find((fact): fact is Extract<M8AcceptanceFact, { readonly type: "required_command_result" }> => fact.type === "required_command_result");
  if (command === undefined) throw new Error("M8_STATIC_SLOT_VERIFICATION_COMMAND_ABSENT");
  return command;
}
function canonicalSlotDescriptors(bundle: M8FixtureBundle): readonly Readonly<{ readonly scenario: M8Scenario; readonly mode: M8Mode; readonly slot_execution_order: number }>[] {
  const slots: Readonly<{ readonly scenario: M8Scenario; readonly mode: M8Mode; readonly slot_execution_order: number }>[] = [];
  for (const scenarioValue of bundle.scenarios) for (const mode of MODES) {
    if (mode === "DIRECT_LUNA_HIGH" && !directEligibleScenario(scenarioValue)) continue;
    slots.push(Object.freeze({ scenario: scenarioValue, mode, slot_execution_order: slots.length }));
  }
  return Object.freeze(slots);
}
function slotExecutionOrder(bundle: M8FixtureBundle, scenarioValue: M8Scenario, mode: M8Mode): number {
  const slot = canonicalSlotDescriptors(bundle).find((entry) => entry.scenario.scenario_id === scenarioValue.scenario_id && entry.mode === mode);
  if (slot === undefined) throw new Error("M8_STATIC_SLOT_NOT_CANONICAL");
  return slot.slot_execution_order;
}
function logicalRoles(mode: M8Mode): readonly string[] {
  return mode === "DIRECT_LUNA_HIGH" ? ["LUNA_EXECUTOR"] : mode === "SINGLE_OWNER_SOL" ? ["SOL_OWNER"] : ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"];
}
function staticLogicalRoute(role: string): M8StaticLogicalRoute {
  const luna = role === "LUNA_EXECUTOR"; const mutates = role === "LUNA_EXECUTOR" || role === "SOL_OWNER";
  return Object.freeze({ logical_role: role, provider_id: "openai-codex", model_id: luna ? "gpt-5.6-luna" : "gpt-5.6-sol", effort: (luna ? "high" : "max") as "high" | "max",
    tool_policy: Object.freeze({ built_in_tools_disabled: true, mutation_tool: mutates ? "APPLY_PATCH_SCOPED" : "NONE",
      command_gateway: role === "SOL_CLOSEOUT" ? "VERIFICATION_ONLY" : role === "SOL_PLANNER" ? "INSPECTION_ONLY" : "TASK_AND_VERIFICATION", maximum_tool_calls: TOTAL_M4_TOOL_LIMIT }) });
}
function staticLogicalRoutes(mode: M8Mode): readonly M8StaticLogicalRoute[] { return Object.freeze(logicalRoles(mode).map(staticLogicalRoute)); }
function staticTasks(scenarioValue: M8Scenario, mode: M8Mode): M8StaticSlotProjection["static_tasks"] {
  const role = mode === "SINGLE_OWNER_SOL" ? "SOL_OWNER" : "LUNA_EXECUTOR";
  return Object.freeze(scenarioValue.routes[mode].tasks.map((task, index) => Object.freeze({ task_id: task.task_id, objective: task.objective,
    editable_paths: Object.freeze([...task.editable_paths]), required_outputs: Object.freeze([...task.required_outputs]), dependencies: Object.freeze([...task.dependencies]),
    topological_rank: index, assigned_role: role, write_owner: task.task_id })));
}
function staticBudget(scenarioValue: M8Scenario, mode: M8Mode): M8StaticSlotProjection["static_budgets"] {
  const workers = mode === "ROUTED_DAG" ? scenarioValue.routes[mode].tasks.length + 2 : 1;
  return Object.freeze({ hard_m4_mutation_tool_limit: scenarioValue.controller_limits.hard_m4_mutation_tool_limit, max_replans: 0 as const,
    route_maximum_tool_calls: TOTAL_M4_TOOL_LIMIT, max_leaves: mode === "ROUTED_DAG" ? 8 : 1, max_attempts_per_leaf: 1,
    max_worker_invocations: workers, max_model_turns: workers * TOTAL_M4_TOOL_LIMIT, max_tool_calls: workers * TOTAL_M4_TOOL_LIMIT,
    max_input_tokens: 1_000_000, max_output_tokens: 100_000, max_cost_microusd: 5_000_000, max_wall_time_ms: workers * MAX_WALL_TIME_MS });
}
function staticS09Semantics(scenarioValue: M8Scenario): M8StaticSlotProjection["s09_mutation_limit_semantics"] {
  const fact = scenarioValue.acceptance_facts.find((entry): entry is Extract<M8AcceptanceFact, { readonly type: "required_budget_fact" }> => entry.type === "required_budget_fact");
  return fact === undefined ? null : Object.freeze({ hard_mutation_tool_limit: fact.hard_mutation_tool_limit, accepted_productive_mutations_at_most: fact.accepted_productive_mutations_at_most,
    second_productive_mutation_rejected: fact.second_productive_mutation_rejected, no_productive_continuation_after_exhaustion: fact.no_productive_continuation_after_exhaustion });
}
function staticS10Semantics(scenarioValue: M8Scenario): M8StaticSlotProjection["s10_scope_refusal_semantics"] {
  const fact = scenarioValue.acceptance_facts.find((entry): entry is Extract<M8AcceptanceFact, { readonly type: "required_scope_refusal" }> => entry.type === "required_scope_refusal");
  return fact === undefined ? null : Object.freeze({ required_objective_unsatisfied: fact.required_objective_unsatisfied, scope_refusal_observed: fact.scope_refusal_observed });
}
/** A final owner decision belongs only to a Single slot whose successful terminal is PASS. */
function requiresGenuineFinalOwnerDecision(scenarioValue: M8Scenario, mode: M8Mode): boolean {
  return mode === "SINGLE_OWNER_SOL" && scenarioValue.expected_terminal_policy === "PASS";
}
function staticSlotProjectionFor(bundle: M8FixtureBundle, scenarioValue: M8Scenario, mode: M8Mode, order: number, canonicalSourceBaseline: M8CanonicalSourceBaseline): M8StaticSlotProjection {
  const command = fixtureCommand(scenarioValue);
  const projection: M8StaticSlotProjection = Object.freeze({
    protocol: STATIC_SLOT_PROTOCOL,
    canonical_source_baseline: canonicalSourceBaseline,
    fixture_bundle_identity: fixtureBundleIdentity(bundle),
    fixture_identity: semanticFixtureIdentity(scenarioValue),
    scenario: Object.freeze({ scenario_id: scenarioValue.scenario_id, scenario_class: scenarioValue.scenario_class }),
    mode,
    direct_eligible: directEligibleScenario(scenarioValue),
    logical_route: staticLogicalRoutes(mode),
    baseline_mode: scenarioValue.approved_dirty_overlay === null ? "CLEAN_REQUIRED" : "APPROVED_BASELINE_DIRTY",
    static_scope: Object.freeze({ readable_paths: Object.freeze([...scenarioValue.readable_paths]), editable_paths: Object.freeze([...scenarioValue.editable_paths]),
      frozen_paths: Object.freeze([...scenarioValue.frozen_paths]), required_outputs: Object.freeze([...scenarioValue.required_outputs]), stopping_conditions: Object.freeze([scenarioValue.stopping_conditions.join("\n")]) }),
    static_tasks: staticTasks(scenarioValue, mode),
    static_budgets: staticBudget(scenarioValue, mode),
    verification_command_specification: Object.freeze([Object.freeze({ command_id: command.command_id, executable: command.executable,
      args: Object.freeze([...command.args]), cwd: command.cwd, timeout_ms: scenarioValue.verification.timeout_ms,
      expected_exit: command.expected_exit, expected_result: scenarioValue.verification.expected_result })]),
    expected_terminal_semantics: Object.freeze({ terminal: scenarioValue.expected_terminal_policy, task_success: scenarioValue.expected_behavior.task_success,
      workflow_correctness: scenarioValue.expected_behavior.workflow_correctness, pilot_validity: scenarioValue.expected_behavior.pilot_validity }),
    s09_mutation_limit_semantics: staticS09Semantics(scenarioValue),
    s10_scope_refusal_semantics: staticS10Semantics(scenarioValue),
    single_owner_acceptance: Object.freeze({ requires_genuine_final_owner_decision: requiresGenuineFinalOwnerDecision(scenarioValue, mode), static_plan_is_not_final_owner_acceptance: true }),
    slot_execution_order: order,
  });
  assertStaticSlotProjection(projection);
  return projection;
}

/** Deterministic prospective projection for one slot; it contains no workspace path or native run record. */
export function m8StaticSlotProjection(bundleValue: M8FixtureBundle, scenarioValue: M8Scenario, mode: M8Mode, canonicalSourceBaseline: M8CanonicalSourceBaseline): M8StaticSlotProjection {
  const bundle = canonicalBundle(bundleValue); const selected = scenarioFromBundle(bundle, scenarioValue);
  if (!MODES.includes(mode) || (mode === "DIRECT_LUNA_HIGH" && !directEligibleScenario(selected))) throw new Error("M8_STATIC_SLOT_MODE_INVALID");
  return staticSlotProjectionFor(bundle, selected, mode, slotExecutionOrder(bundle, selected, mode), staticProjectionBaseline(canonicalSourceBaseline));
}
export function m8StaticSlotIdentity(projection: M8StaticSlotProjection): Sha256Digest { return sha256Canonical(projection); }
function assertStaticSlotProjection(projection: M8StaticSlotProjection): void {
  if (projection === null || typeof projection !== "object" || Array.isArray(projection) || projection.protocol !== STATIC_SLOT_PROTOCOL) binding("static slot projection is invalid");
  staticProjectionBaseline(projection.canonical_source_baseline);
  digest(projection.fixture_bundle_identity, "static slot fixture bundle identity"); digest(projection.fixture_identity, "static slot fixture identity");
  const requiresOwnerDecision = projection.mode === "SINGLE_OWNER_SOL" && projection.expected_terminal_semantics.terminal === "PASS";
  if (!MODES.includes(projection.mode) || !Number.isSafeInteger(projection.slot_execution_order) || projection.slot_execution_order < 0 || projection.slot_execution_order >= 27 ||
      projection.static_budgets.max_replans !== 0 || projection.static_budgets.hard_m4_mutation_tool_limit !== null && projection.static_budgets.hard_m4_mutation_tool_limit !== 1 ||
      (projection.expected_terminal_semantics.terminal !== "PASS" && projection.expected_terminal_semantics.terminal !== "BLOCKED") ||
      projection.single_owner_acceptance.requires_genuine_final_owner_decision !== requiresOwnerDecision ||
      projection.single_owner_acceptance.static_plan_is_not_final_owner_acceptance !== true) binding("static slot projection fields are invalid");
  const encoded = canonicalize(projection);
  for (const field of ["workspace_identity", "initial_state_identity", "m3_state_token", "run_id", "contract_content_sha256", "task_content_sha256", "task_graph_content_sha256", "plan_content_sha256", "execution_authority_digest", "reservation", "bounded_invocation", "bounded_worker_invocation", "m4_evidence", "terminal_evidence_identity", "terminal_workflow_result", "postflight_identity", "final_postflight_identity"]) {
    if (encoded.includes(`\"${field}\"`)) binding("static slot projection includes a run-specific field");
  }
}
export function m8StaticSlotSpecification(projection: M8StaticSlotProjection): M8StaticSlotSpecification {
  assertStaticSlotProjection(projection);
  return Object.freeze({ static_slot_projection: projection, static_slot_spec_identity: m8StaticSlotIdentity(projection) });
}
function assertStaticSlotSpecification(value: M8StaticSlotSpecification): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) binding("static slot specification is invalid");
  assertStaticSlotProjection(value.static_slot_projection); digest(value.static_slot_spec_identity, "static slot specification identity");
  if (value.static_slot_spec_identity !== m8StaticSlotIdentity(value.static_slot_projection)) binding("static slot specification identity was not recomputed");
}
function runtimeLogicalRoutes(authority: BoundedExecutionAuthority, mode: M8Mode): readonly M8StaticLogicalRoute[] {
  return Object.freeze(logicalRoles(mode).map((role) => {
    const route = authority.route_map.routes.find((entry) => entry.logical_role === role);
    if (route === undefined) binding("native controller route is absent");
    return Object.freeze({ logical_role: route.logical_role, provider_id: route.provider_id, model_id: route.model_id, effort: route.effort,
      tool_policy: Object.freeze({ built_in_tools_disabled: route.tool_policy.built_in_tools_disabled, mutation_tool: route.tool_policy.mutation_tool,
        command_gateway: route.tool_policy.command_gateway, maximum_tool_calls: route.tool_policy.maximum_tool_calls }) });
  }));
}
function runtimeArgument(value: string, root: string): string {
  if (!isAbsolute(value)) return value;
  const canonicalRoot = resolve(root); const canonical = resolve(value);
  const relation = relative(canonicalRoot, canonical);
  return relation.length > 0 && !relation.startsWith("../") && relation !== ".." && !isAbsolute(relation) ? relation : value;
}
/** Projects native controller facts back into the same prospective static form without copying its run-specific identities. */
export function m8RuntimeStaticSlotProjection(input: {
  readonly arm: FrozenM8Arm;
  readonly materialization: MaterializedM8Fixture;
  readonly controller_authority: BoundedExecutionAuthority;
}): M8StaticSlotProjection {
  const { arm, materialization, controller_authority: authority } = input;
  assertStaticSlotSpecification(arm.static_slot); const canonicalSourceBaseline = staticProjectionBaseline(arm.static_slot.static_slot_projection.canonical_source_baseline);
  assertMaterialization(arm.scenario, materialization); assertControllerAuthority(authority);
  if (authority.mode !== arm.mode) binding("native controller mode differs from static slot");
  const commands = authority.contract.verification_commands.map((command) => {
    const executable = command.argv[0]; if (executable === undefined) binding("native verification command is empty");
    return Object.freeze({ command_id: command.command_id, executable, args: Object.freeze(command.argv.slice(1).map((value) => runtimeArgument(value, materialization.root))),
      cwd: command.cwd, timeout_ms: command.timeout_ms, expected_exit: arm.scenario.verification.expected_exit, expected_result: arm.scenario.verification.expected_result });
  });
  const runtime: M8StaticSlotProjection = Object.freeze({
    protocol: STATIC_SLOT_PROTOCOL,
    canonical_source_baseline: canonicalSourceBaseline,
    fixture_bundle_identity: arm.fixture_bundle_identity,
    fixture_identity: materialization.semanticFixtureIdentity,
    scenario: Object.freeze({ scenario_id: materialization.scenarioId, scenario_class: arm.scenario.scenario_class }),
    mode: authority.mode,
    direct_eligible: directEligibleScenario(arm.scenario),
    logical_route: runtimeLogicalRoutes(authority, authority.mode),
    baseline_mode: authority.baseline.baseline_mode,
    static_scope: Object.freeze({ readable_paths: Object.freeze([...authority.contract.scope.readable_paths]), editable_paths: Object.freeze([...authority.contract.scope.editable_paths]),
      frozen_paths: Object.freeze([...authority.contract.scope.frozen_paths]), required_outputs: Object.freeze([...authority.contract.required_outputs]), stopping_conditions: Object.freeze([...authority.contract.stopping_conditions]) }),
    static_tasks: Object.freeze(authority.tasks.map((task) => Object.freeze({ task_id: task.task_id, objective: task.objective, editable_paths: Object.freeze([...task.scope.editable_paths]),
      required_outputs: Object.freeze([...task.required_outputs]), dependencies: Object.freeze([...task.dependencies]), topological_rank: task.topological_rank,
      assigned_role: task.assigned_role, write_owner: task.write_owner }))),
    static_budgets: Object.freeze({ hard_m4_mutation_tool_limit: authority.controller_limits.hard_m4_mutation_tool_limit, max_replans: authority.controller_limits.max_replans,
      route_maximum_tool_calls: authority.route_map.routes.find((entry) => entry.logical_role === logicalRoles(authority.mode)[0])!.tool_policy.maximum_tool_calls,
      max_leaves: authority.budget.limits.max_leaves, max_attempts_per_leaf: authority.budget.limits.max_attempts_per_leaf, max_worker_invocations: authority.budget.limits.max_worker_invocations,
      max_model_turns: authority.budget.limits.max_model_turns, max_tool_calls: authority.budget.limits.max_tool_calls, max_input_tokens: authority.budget.limits.max_input_tokens,
      max_output_tokens: authority.budget.limits.max_output_tokens, max_cost_microusd: authority.budget.limits.max_cost_microusd, max_wall_time_ms: authority.budget.limits.max_wall_time_ms }),
    verification_command_specification: Object.freeze(commands),
    expected_terminal_semantics: Object.freeze({ terminal: arm.scenario.expected_terminal_policy, task_success: arm.scenario.expected_behavior.task_success,
      workflow_correctness: arm.scenario.expected_behavior.workflow_correctness, pilot_validity: arm.scenario.expected_behavior.pilot_validity }),
    s09_mutation_limit_semantics: staticS09Semantics(arm.scenario),
    s10_scope_refusal_semantics: staticS10Semantics(arm.scenario),
    single_owner_acceptance: Object.freeze({ requires_genuine_final_owner_decision: requiresGenuineFinalOwnerDecision(arm.scenario, authority.mode),
      static_plan_is_not_final_owner_acceptance: true }),
    slot_execution_order: arm.slot_execution_order,
  });
  assertStaticSlotProjection(runtime);
  return runtime;
}

function freezeArm(bundle: M8FixtureBundle, scenarioValue: M8Scenario, mode: M8Mode, canonicalSourceBaseline: M8CanonicalSourceBaseline): FrozenM8Arm {
  const projection = m8StaticSlotProjection(bundle, scenarioValue, mode, canonicalSourceBaseline);
  return Object.freeze({ fixture_bundle_identity: fixtureBundleIdentity(bundle), matrix_identity: m8MatrixIdentity(bundle), scenario: scenarioValue,
    scenario_id: scenarioValue.scenario_id, mode, slot_execution_order: projection.slot_execution_order, static_slot: m8StaticSlotSpecification(projection) });
}
function freezeResult(bundle: M8FixtureBundle, arms: readonly FrozenM8Arm[]): M8FreezeResult {
  return Object.freeze({ protocol: FREEZE_PROTOCOL, bundle, fixture_bundle_identity: fixtureBundleIdentity(bundle), matrix_identity: m8MatrixIdentity(bundle), arms: Object.freeze([...arms]) });
}
function assertModeSet(scenarioValue: M8Scenario, modes: readonly M8Mode[]): void {
  if (new Set(modes).size !== modes.length || modes.some((mode) => !MODES.includes(mode))) throw new Error("M8_FREEZE_INVALID_MODE_SET");
  if (modes.some((mode) => mode === "DIRECT_LUNA_HIGH" && !directEligibleScenario(scenarioValue))) throw new Error("M8_DIRECT_INELIGIBLE");
}
/** Static-plan construction does not materialize a fixture or construct native execution authority. */
export async function freezeM8Scenario(bundleValue: M8FixtureBundle, scenarioValue: M8Scenario, modes: readonly M8Mode[] = MODES, options: M8FreezeOptions = {}): Promise<M8FreezeResult> {
  const canonicalSourceBaseline = await freezeCanonicalSourceBaseline(options);
  const bundle = canonicalBundle(bundleValue); const selected = scenarioFromBundle(bundle, scenarioValue); assertModeSet(selected, modes);
  const arms = modes.map((mode) => freezeArm(bundle, selected, mode, canonicalSourceBaseline)).sort((left, right) => left.slot_execution_order - right.slot_execution_order);
  return freezeResult(bundle, arms);
}
/** The complete static matrix is deterministic: one planned owner decision per canonical slot, no future run records. */
export async function freezeM8Bundle(bundleValue: M8FixtureBundle, options: M8FreezeOptions = {}): Promise<M8FreezeResult> {
  const canonicalSourceBaseline = await freezeCanonicalSourceBaseline(options); const bundle = canonicalBundle(bundleValue);
  return freezeResult(bundle, canonicalSlotDescriptors(bundle).map((slot) => freezeArm(bundle, slot.scenario, slot.mode, canonicalSourceBaseline)));
}
/** Static plans own no workspace. It only retires actual materializations created later for this exact plan. */
export async function disposeM8Freeze(value: M8FreezeResult): Promise<void> {
  assertFreeze(value);
  const owned = [...authoritativeRunRecords.entries()].filter(([, record]) => record.freeze === value);
  for (const [handle, record] of owned) {
    if (workspaceRecords.has(record.materialization)) await disposeMaterializedM8Fixture(record.materialization);
    authoritativeRunRecords.delete(handle);
  }
}

function assertFrozenArm(arm: FrozenM8Arm, bundle: M8FixtureBundle, fixtureIdentity: Sha256Digest, matrixIdentity: Sha256Digest, canonicalSourceBaseline: M8CanonicalSourceBaseline): void {
  try {
    const canonicalScenario = scenarioFromBundle(bundle, arm.scenario);
    if (arm.scenario_id !== canonicalScenario.scenario_id || !MODES.includes(arm.mode) || (arm.mode === "DIRECT_LUNA_HIGH" && !directEligibleScenario(canonicalScenario))) binding("scenario or mode is not an eligible canonical arm");
    if (arm.fixture_bundle_identity !== fixtureIdentity || arm.matrix_identity !== matrixIdentity) binding("fixture bundle or matrix identity differs");
    const expected = m8StaticSlotSpecification(m8StaticSlotProjection(bundle, canonicalScenario, arm.mode, canonicalSourceBaseline));
    if (arm.slot_execution_order !== expected.static_slot_projection.slot_execution_order || canonicalize(arm.static_slot) !== canonicalize(expected)) binding("static arm differs from canonical slot specification");
  } catch (error: unknown) {
    if (error instanceof Error && error.message.startsWith("M8_APPROVAL_BINDING_MISMATCH:")) throw error;
    binding(error instanceof Error ? error.message : "frozen arm validation failed");
  }
}
function assertFreeze(value: M8FreezeResult): void {
  try {
    if (value.protocol !== FREEZE_PROTOCOL || !Array.isArray(value.arms)) binding("freeze protocol or arms are invalid");
    const bundle = canonicalBundle(value.bundle); const fixtureIdentity = fixtureBundleIdentity(bundle); const matrixIdentity = m8MatrixIdentity(bundle);
    if (value.fixture_bundle_identity !== fixtureIdentity || value.matrix_identity !== matrixIdentity) binding("freeze fixture bundle or matrix identity is invalid");
    let priorOrder = -1; let canonicalSourceBaseline: M8CanonicalSourceBaseline | undefined; const slots = new Set<string>();
    for (const arm of value.arms) {
      const armBaseline = staticProjectionBaseline(arm.static_slot.static_slot_projection.canonical_source_baseline);
      if (canonicalSourceBaseline === undefined) canonicalSourceBaseline = armBaseline;
      else if (canonicalize(canonicalSourceBaseline) !== canonicalize(armBaseline)) binding("freeze contains multiple canonical source baselines");
      assertFrozenArm(arm, bundle, fixtureIdentity, matrixIdentity, canonicalSourceBaseline);
      const slot = `${arm.scenario_id}--${arm.mode}`;
      if (slots.has(slot) || arm.slot_execution_order <= priorOrder) binding("freeze contains duplicate or unordered static slots");
      slots.add(slot); priorOrder = arm.slot_execution_order;
    }
  } catch (error: unknown) {
    if (error instanceof Error && error.message.startsWith("M8_APPROVAL_BINDING_MISMATCH:")) throw error;
    binding(error instanceof Error ? error.message : "freeze validation failed");
  }
}
function manifestBody(manifest: Pick<M8ApprovalManifest, "fixture_bundle_identity" | "matrix_identity" | "approved_static_slots">) {
  return { protocol: APPROVAL_MANIFEST_PROTOCOL, fixture_bundle_identity: manifest.fixture_bundle_identity, matrix_identity: manifest.matrix_identity,
    approved_static_slots: Object.freeze([...manifest.approved_static_slots]) } as const;
}
function assertManifest(manifest: M8ApprovalManifest): void {
  try {
    if (manifest.protocol !== APPROVAL_MANIFEST_PROTOCOL || !Array.isArray(manifest.approved_static_slots) || manifest.approved_static_slots.length === 0) binding("approval manifest static slots are invalid");
    digest(manifest.fixture_bundle_identity, "approval manifest fixture bundle identity"); digest(manifest.matrix_identity, "approval manifest matrix identity");
    let priorOrder = -1;
    for (const slot of manifest.approved_static_slots) {
      assertStaticSlotSpecification(slot);
      if (slot.static_slot_projection.slot_execution_order <= priorOrder) binding("approval manifest static slot order is not canonical");
      priorOrder = slot.static_slot_projection.slot_execution_order;
    }
    if (manifest.approval_manifest_identity !== sha256Canonical(manifestBody(manifest))) binding("approval manifest identity was not recomputed");
  } catch (error: unknown) {
    if (error instanceof Error && error.message.startsWith("M8_APPROVAL_BINDING_MISMATCH:")) throw error;
    binding(error instanceof Error ? error.message : "approval manifest validation failed");
  }
}
/** Creates the existing single harness approval record from explicit owner-supplied static slot specifications. */
export function createM8ApprovalManifest(freeze: M8FreezeResult, approved: readonly M8StaticSlotSpecification[]): M8ApprovalManifest {
  assertFreeze(freeze);
  if (approved.length !== freeze.arms.length || approved.some((slot, index) => slot.static_slot_projection.slot_execution_order !== freeze.arms[index]?.slot_execution_order)) {
    throw new Error("M8_APPROVAL_MANIFEST_SLOT_SET_MISMATCH");
  }
  for (const slot of approved) assertStaticSlotSpecification(slot);
  const body = manifestBody({ fixture_bundle_identity: freeze.fixture_bundle_identity, matrix_identity: freeze.matrix_identity, approved_static_slots: Object.freeze([...approved]) });
  return Object.freeze({ ...body, approval_manifest_identity: sha256Canonical(body) });
}
/** Finds the explicit owner-approved static slot. Native equality is checked only when approveTasks supplies actual authority. */
export function assertM8ArmApproved(arm: FrozenM8Arm, manifest: M8ApprovalManifest): M8StaticSlotSpecification {
  assertManifest(manifest);
  if (manifest.fixture_bundle_identity !== arm.fixture_bundle_identity || manifest.matrix_identity !== arm.matrix_identity) binding("approval manifest does not bind this arm's fixture matrix");
  const approved = manifest.approved_static_slots.filter((slot) => slot.static_slot_projection.slot_execution_order === arm.slot_execution_order);
  if (approved.length !== 1) binding("owner-approved static slot is absent or ambiguous");
  return approved[0]!;
}
function captureActualControllerAuthority(arm: FrozenM8Arm, approved: M8StaticSlotSpecification, materialization: MaterializedM8Fixture, input: {
  readonly mode: M8Mode;
  readonly contract: BoundedExecutionAuthority["contract"];
  readonly tasks: readonly BoundedExecutionAuthority["tasks"][number][];
  readonly plan: BoundedExecutionAuthority["plan"];
  readonly executionAuthority: BoundedExecutionAuthority;
}): ExecutedM8Arm {
  const actual = input.executionAuthority;
  if (input.mode !== arm.mode || input.mode !== actual.mode || input.contract.content_sha256 !== actual.contract.content_sha256 ||
      canonicalize(input.tasks.map((task) => task.content_sha256)) !== canonicalize(actual.tasks.map((task) => task.content_sha256)) ||
      (input.plan?.content_sha256 ?? null) !== (actual.plan?.content_sha256 ?? null)) binding("controller approval callback payload differs from actual authority");
  const runtimeProjection = m8RuntimeStaticSlotProjection({ arm, materialization, controller_authority: actual });
  const runtimeStaticSlot = m8StaticSlotSpecification(runtimeProjection);
  const execution = m8ExecutionAuthorityDigest({ fixture_bundle_identity: arm.fixture_bundle_identity, scenario: arm.scenario, mode: arm.mode, materialization, controller_authority: actual });
  return Object.freeze({ static_arm: arm, fixture_bundle_identity: arm.fixture_bundle_identity, matrix_identity: arm.matrix_identity, scenario: arm.scenario,
    scenario_id: arm.scenario_id, mode: arm.mode, slot_execution_order: arm.slot_execution_order, static_slot: arm.static_slot, approved_static_slot: approved, runtime_static_slot: runtimeStaticSlot,
    static_match: canonicalize(runtimeStaticSlot.static_slot_projection) === canonicalize(approved.static_slot_projection) && runtimeStaticSlot.static_slot_spec_identity === approved.static_slot_spec_identity,
    materialization, controller_authority: actual, run_id: actual.run_id, execution_authority_digest: execution });
}
function nativeApprovalDigest(runtime: ExecutedM8Arm): Sha256Digest {
  return runtime.controller_authority.mode === "ROUTED_DAG" ? runtime.controller_authority.plan!.content_sha256 as Sha256Digest : runtime.controller_authority.contract.content_sha256 as Sha256Digest;
}

export interface M8RunOptions {
  /** Existing native final-Single owner callback; absence remains a rejection, never automatic acceptance. */
  readonly approveOwnerAcceptance?: (input: { readonly task: TaskDocument; readonly finalState: WorkflowState }) => Promise<boolean>;
}
type M8ControllerRunner = typeof runBoundedMutationWorkflow;
type DurableInspection = Awaited<ReturnType<typeof inspectRunStorage>>;
type DurableRecords = Awaited<ReturnType<typeof readM5ManagedRecords>>;
let activeArm: string | null = null;

function sameCanonical(left: unknown, right: unknown): boolean { return canonicalize(left) === canonicalize(right); }
function exactlyOne<T>(values: readonly T[], predicate: (value: T) => boolean, label: string): T {
  const matches = values.filter(predicate);
  if (matches.length !== 1) throw new Error(`M8_DURABLE_AUTHORITY_INVALID:${label}`);
  return matches[0]!;
}
function isAuthoritative(inspection: DurableInspection, kind: string, identity: string): boolean {
  return inspection.managedRecordClassifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === identity &&
    entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
}
function registeredWorkspace(materialization: MaterializedM8Fixture, invocation: M8Invocation): WorkspaceRecord {
  const workspace = workspaceRecords.get(materialization);
  if (workspace === undefined || workspace.invocation !== invocation || workspace.root !== materialization.root) {
    throw new Error("M8_HARNESS_WORKSPACE_REGISTRATION_INVALID");
  }
  return workspace;
}
async function revalidateRegisteredWorkspace(materialization: MaterializedM8Fixture, invocation: M8Invocation): Promise<void> {
  const workspace = registeredWorkspace(materialization, invocation); const owner = ownedInvocation(invocation);
  await revalidatePrivateDirectory(owner.rootRegistration); await revalidatePrivateDirectory(owner.workspaceRegistration, owner.rootRegistration);
  let stats; let physical: string;
  try { [stats, physical] = await Promise.all([lstat(workspace.root), realpath(workspace.root)]); }
  catch { throw new Error("M8_HARNESS_WORKSPACE_UNAVAILABLE"); }
  if (!stats!.isDirectory() || stats!.isSymbolicLink() || stats!.dev !== workspace.device || stats!.ino !== workspace.inode ||
      physical! !== workspace.root || dirname(workspace.root) !== owner.workspaces || !physicallyWithin(owner.workspaces, workspace.root)) {
    throw new Error("M8_HARNESS_WORKSPACE_IDENTITY_INVALID");
  }
}
async function registerActualRun(
  invocation: M8Invocation,
  freeze: M8FreezeResult,
  arm: FrozenM8Arm,
  approval: M8ApprovalManifest,
  materialization: MaterializedM8Fixture,
  runtime: ExecutedM8Arm | null,
  controllerResult: BoundedMutationRunResult,
): Promise<M8AuthoritativeRun> {
  const owner = ownedInvocation(invocation);
  let controllerRoot: DirectoryRegistration | null = null; let stateRoot: DirectoryRegistration | null = null; let registrationError: string | null = null;
  try {
    await revalidatePrivateDirectory(owner.rootRegistration); await revalidatePrivateDirectory(owner.retainedRegistration, owner.rootRegistration);
    if (controllerResult.evidenceRoot === undefined || resolve(controllerResult.evidenceRoot) !== controllerResult.evidenceRoot ||
        dirname(controllerResult.evidenceRoot) !== owner.retained || !physicallyWithin(owner.retained, controllerResult.evidenceRoot)) {
      throw new Error("M8_HARNESS_CONTROLLER_ROOT_UNBOUND");
    }
    controllerRoot = await registerPrivateDirectory(controllerResult.evidenceRoot, "CONTROLLER_ROOT");
    await revalidatePrivateDirectory(controllerRoot, owner.retainedRegistration);
    stateRoot = await registerPrivateDirectory(join(controllerRoot.path, "state"), "CONTROLLER_STATE");
    await revalidatePrivateDirectory(stateRoot, controllerRoot);
  } catch (error: unknown) {
    registrationError = error instanceof Error ? error.message : "M8_HARNESS_CONTROLLER_ROOT_REGISTRATION_FAILED";
    controllerRoot = null; stateRoot = null;
  }
  const handle = Object.freeze({ run_identity: sha256Canonical({ protocol: "m8-authoritative-run-v2", static_slot_spec_identity: arm.static_slot.static_slot_spec_identity,
    execution_authority_digest: runtime?.execution_authority_digest ?? null, nonce: randomBytes(32).toString("hex") }) });
  authoritativeRunRecords.set(handle, Object.freeze({ invocation, freeze, approval, arm, materialization, runtime, controllerResult, controllerRoot, stateRoot, registrationError }));
  return handle;
}

async function runApprovedM8Arm(invocation: M8Invocation, freeze: M8FreezeResult, arm: FrozenM8Arm, manifest: M8ApprovalManifest, controller: M8ControllerRunner, options: M8RunOptions): Promise<M8AuthoritativeRun> {
  assertFreeze(freeze); const approved = assertM8ArmApproved(arm, manifest);
  if (!freeze.arms.includes(arm) || manifest.fixture_bundle_identity !== freeze.fixture_bundle_identity || manifest.matrix_identity !== freeze.matrix_identity) {
    throw new Error("M8_APPROVED_RUN_BINDING_INVALID");
  }
  const owner = ownedInvocation(invocation); const identity = `${arm.scenario_id}--${arm.mode}`;
  if (activeArm !== null) throw new Error(`M8_ONE_ACTIVE_ARM:${activeArm}`);
  activeArm = identity;
  let materialization: MaterializedM8Fixture | undefined; let runtime: ExecutedM8Arm | null = null;
  try {
    // Materialization happens only after static owner input is registered. The
    // callback receives native authority before M5 reserves any worker.
    materialization = await materializeM8Fixture(arm.scenario, invocation);
    const result = await controller(controllerGoal(arm.scenario, arm.mode), {
      cwd: materialization.root,
      authority: controllerAuthority(arm.scenario),
      retainedArtifactRoot: owner.retained,
      ...(frozenBaselineApproval(arm.scenario) === undefined ? {} : { approveBaseline: frozenBaselineApproval(arm.scenario)! }),
      approveTasks: async (input) => {
        runtime = captureActualControllerAuthority(arm, approved, materialization!, input);
        return runtime.static_match ? nativeApprovalDigest(runtime) : null;
      },
      ...(options.approveOwnerAcceptance === undefined ? {} : { approveOwnerAcceptance: options.approveOwnerAcceptance }),
    });
    return await registerActualRun(invocation, freeze, arm, manifest, materialization, runtime, result);
  } catch (error: unknown) {
    if (materialization !== undefined && workspaceRecords.has(materialization)) await disposeMaterializedM8Fixture(materialization).catch(() => undefined);
    throw error;
  } finally { activeArm = null; }
}

/** Production M8 admission accepts only owner static input plus the existing genuine final-Single callback. */
export async function runOneM8Arm(invocation: M8Invocation, freeze: M8FreezeResult, arm: FrozenM8Arm, manifest: M8ApprovalManifest, options: M8RunOptions = {}): Promise<M8AuthoritativeRun> {
  return runApprovedM8Arm(invocation, freeze, arm, manifest, runBoundedMutationWorkflow, options);
}

/** Test-only faux entrypoint: it retains the same controller implementation but never selects a provider runtime. */
export async function runOneM8ArmForTests(invocation: M8Invocation, freeze: M8FreezeResult, arm: FrozenM8Arm, manifest: M8ApprovalManifest, options: M8RunOptions = {}): Promise<M8AuthoritativeRun> {
  return runApprovedM8Arm(invocation, freeze, arm, manifest, runBoundedMutationWorkflowForTests, options);
}
export function activeM8ArmForTests(): string | null { return activeArm; }

function terminalDecision(
  records: DurableRecords,
  inspection: DurableInspection,
  state: WorkflowState,
  runId: string,
): M5ControlDecisionDocument {
  const expectedOutcome = state.phase === "PASS" ? "PASS" : "BLOCK";
  return exactlyOne(records.decisions, (decision) => decision.run_id === runId && decision.outcome === expectedOutcome &&
    decision.predicted_next_state_content_sha256 === state.content_sha256 && decision.transition_event !== null &&
    isAuthoritative(inspection, "M5_CONTROL_DECISION", decision.content_sha256), "terminal M5 decision");
}
function expectedCommand(scenarioValue: M8Scenario): Extract<M8AcceptanceFact, { readonly type: "required_command_result" }> {
  const value = scenarioValue.acceptance_facts.find((fact): fact is Extract<M8AcceptanceFact, { readonly type: "required_command_result" }> => fact.type === "required_command_result");
  if (value === undefined) throw new Error("M8_DURABLE_AUTHORITY_INVALID:fixture command fact absent");
  return value;
}
function optionalFinalPostflight(
  arm: ExecutedM8Arm,
  records: DurableRecords,
  inspection: DurableInspection,
  terminal: M5ControlDecisionDocument,
): M3PostflightDocument | null {
  const terminalReferences = new Set(terminal.obligation_evidence.map((entry) => entry.evidence_content_sha256));
  const matching = (references: ReadonlySet<string>): readonly M3PostflightDocument[] => records.postflights.filter((postflight) => postflight.run_id === arm.run_id &&
    postflight.baseline_runtime_content_sha256 === arm.controller_authority.baseline.content_sha256 &&
    postflight.repository.content_sha256 === arm.controller_authority.repository.content_sha256 && references.has(postflight.content_sha256) &&
    isAuthoritative(inspection, "M3_POSTFLIGHT", postflight.content_sha256));
  // PASS terminal obligations directly name the controller's final M3
  // postflight. Do not make that exact terminal identity ambiguous merely
  // because its preceding frozen verification also emitted a postflight.
  const direct = matching(terminalReferences);
  if (direct.length === 1) return direct[0]!;
  if (direct.length > 1) return null;
  // A terminal BLOCK after a real verification command has no successful
  // output obligation. Its exact authoritative M4 command result instead
  // roots the one permitted final M3 postflight.
  const commandReferences = new Set(records.commandResults.filter((command) => command.run_id === arm.run_id && command.command_class === "VERIFICATION" &&
    command.postflight_content_sha256 !== null && isAuthoritative(inspection, "M4_COMMAND_RESULT", command.content_sha256)).map((command) => command.postflight_content_sha256!));
  const fallback = matching(commandReferences);
  return fallback.length === 1 ? fallback[0]! : null;
}
function resolvedCommandEvidence(
  arm: ExecutedM8Arm,
  policy: M5ControlPolicyDocument,
  records: DurableRecords,
  inspection: DurableInspection,
): M8AuthoritativeWorkflowEvidence["command_results"] {
  const fixture = expectedCommand(arm.scenario);
  const catalog = exactlyOne(records.commandCatalogs, (entry) => entry.content_sha256 === policy.command_catalog_content_sha256 &&
    isAuthoritative(inspection, "M4_COMMAND_CATALOG", entry.content_sha256), "M4 command catalog");
  const specification = catalog.commands.filter((entry) => entry.command_id === fixture.command_id);
  const frozen = arm.controller_authority.contract.verification_commands.filter((entry) => entry.command_id === fixture.command_id);
  if (specification.length !== 1 || frozen.length !== 1 || fixture.args.length === 0) return Object.freeze([]);
  const fixtureScript = fixture.args[0]!;
  const cwdRelativeScript = fixture.cwd === "." ? fixtureScript : fixtureScript.startsWith(`${fixture.cwd}/`) ? fixtureScript.slice(fixture.cwd.length + 1) : fixtureScript;
  if (cwdRelativeScript.length === 0) return Object.freeze([]);
  const expectedArgv = Object.freeze([fixture.executable, join(arm.materialization.root, fixture.cwd, cwdRelativeScript), ...fixture.args.slice(1)]);
  const spec = specification[0]!; const frozenCommand = frozen[0]!;
  if (spec.command_class !== "VERIFICATION" || spec.executable_invocation_path !== fixture.executable || spec.cwd !== fixture.cwd ||
      !sameCanonical(spec.argv, expectedArgv) || !sameCanonical(frozenCommand.argv, expectedArgv) || frozenCommand.cwd !== fixture.cwd ||
      !spec.expected_exit_codes.includes(fixture.expected_exit)) return Object.freeze([]);
  const matches = records.commandResults.filter((result) => result.run_id === arm.run_id && result.command_id === fixture.command_id &&
    result.command_class === "VERIFICATION" && result.command_catalog_content_sha256 === catalog.content_sha256 &&
    result.command_spec_sha256 === spec.command_spec_sha256 && result.argv_identity === sha256Canonical(spec.argv) &&
    result.cwd === join(arm.materialization.root, fixture.cwd) && result.executable_sha256 === spec.executable_sha256 &&
    isAuthoritative(inspection, "M4_COMMAND_RESULT", result.content_sha256));
  if (matches.length !== 1) return Object.freeze([]);
  const result = matches[0]!;
  return Object.freeze([Object.freeze({ command_id: fixture.command_id, executable: fixture.executable, args: fixture.args, cwd: fixture.cwd,
    exit_code: result.exit_code, command_spec_identity: result.command_spec_sha256 as Sha256Digest, m4_result_identity: result.content_sha256 as Sha256Digest })]);
}
function resolvedBudgetEvidence(
  arm: ExecutedM8Arm,
  policy: M5ControlPolicyDocument,
  records: DurableRecords,
  inspection: DurableInspection,
  terminal: M5ControlDecisionDocument,
): M8AuthoritativeWorkflowEvidence["budget"] | undefined {
  if (!arm.scenario.acceptance_facts.some((fact) => fact.type === "required_budget_fact")) return undefined;
  const hardLimit = arm.controller_authority.controller_limits.hard_m4_mutation_tool_limit;
  const totalM4ToolLimit = arm.controller_authority.budget.limits.max_tool_calls;
  const routeLimitsAreStatic = arm.controller_authority.route_map.routes.every((route) => route.tool_policy.maximum_tool_calls === TOTAL_M4_TOOL_LIMIT);
  const receipts = records.mutationReceipts.filter((receipt) => receipt.run_id === arm.run_id && receipt.outcome === "APPLIED" &&
    isAuthoritative(inspection, "M4_MUTATION_RECEIPT", receipt.content_sha256));
  const refusals = records.admissionRefusals.filter((refusal) => refusal.run_id === arm.run_id && refusal.refusal_code === "M4_TOOL_BUDGET_EXHAUSTED" &&
    isAuthoritative(inspection, "M4_ADMISSION_REFUSAL", refusal.content_sha256));
  const results = records.boundedWorkerResults.filter((result) => {
    const invocation = records.boundedWorkerInvocations.find((entry) => entry.content_sha256 === result.invocation_content_sha256);
    return invocation?.run_id === arm.run_id && isAuthoritative(inspection, "BOUNDED_WORKER_RESULT", result.content_sha256);
  });
  const exhaustion = results.filter((result) => {
    const linked = refusals.filter((refusal) => refusal.bounded_worker_invocation_content_sha256 === result.invocation_content_sha256 && result.m4_evidence_content_sha256.includes(refusal.content_sha256));
    return result.first_failure_code === "M4_TOOL_BUDGET_EXHAUSTED" && result.first_failure_stage === "M4_TOOL_ADMISSION" && linked.length === 1;
  });
  const refusalFollowsAcceptedMutation = receipts.length === 1 && refusals.length === 1 &&
    receipts[0]!.successor_state_token_content_sha256 === refusals[0]!.admission_state_token_content_sha256;
  const acceptedM4ToolCalls = results.reduce((total, result) => total + result.actual_usage.m4_tool_calls, 0);
  const exhaustionCompletedAt = exhaustion.length === 1 ? exhaustion[0]!.completed_at : null;
  const totalUsageBounded = exhaustion.length === 1 && acceptedM4ToolCalls >= receipts.length && acceptedM4ToolCalls <= totalM4ToolLimit;
  const noProductiveContinuation = refusalFollowsAcceptedMutation && receipts.length <= 1 && exhaustionCompletedAt !== null &&
    results.every((result) => result.content_sha256 === exhaustion[0]!.content_sha256 || result.completed_at <= exhaustionCompletedAt);
  const exactRefusal = hardLimit === 1 && routeLimitsAreStatic && refusals.length === 1 && exhaustion.length === 1 && totalUsageBounded && refusalFollowsAcceptedMutation;
  const identities = [policy.content_sha256, terminal.content_sha256, ...receipts.map((entry) => entry.content_sha256), ...refusals.map((entry) => entry.content_sha256), ...exhaustion.map((entry) => entry.content_sha256)] as Sha256Digest[];
  identities.sort();
  return Object.freeze({ hard_mutation_tool_limit: hardLimit ?? 0, accepted_productive_mutations: receipts.length,
    accepted_m4_tool_calls: acceptedM4ToolCalls, total_m4_tool_limit: totalM4ToolLimit,
    second_productive_mutation_rejected: exactRefusal, productive_continuation_after_exhaustion: !noProductiveContinuation,
    evidence_identities: Object.freeze([...new Set(identities)]) });
}
function resolvedScopeEvidence(
  arm: ExecutedM8Arm,
  policy: M5ControlPolicyDocument,
  records: DurableRecords,
  inspection: DurableInspection,
  state: WorkflowState,
  terminal: M5ControlDecisionDocument,
  postflight: M3PostflightDocument,
): M8AuthoritativeWorkflowEvidence["scope"] | undefined {
  if (!arm.scenario.acceptance_facts.some((fact) => fact.type === "required_scope_refusal")) return undefined;
  const applied = records.mutationReceipts.filter((receipt) => receipt.run_id === arm.run_id && receipt.outcome === "APPLIED" &&
    isAuthoritative(inspection, "M4_MUTATION_RECEIPT", receipt.content_sha256));
  const refusals = records.admissionRefusals.filter((refusal) => refusal.run_id === arm.run_id && refusal.refusal_code === "OUT_OF_SCOPE_WRITE" &&
    isAuthoritative(inspection, "M4_ADMISSION_REFUSAL", refusal.content_sha256));
  const blocked = records.boundedWorkerResults.filter((result) => result.first_failure_code === "OUT_OF_SCOPE_WRITE" && result.first_failure_stage === "M4_TOOL_ADMISSION" &&
    refusals.some((refusal) => refusal.bounded_worker_invocation_content_sha256 === result.invocation_content_sha256 && result.m4_evidence_content_sha256.includes(refusal.content_sha256)) &&
    isAuthoritative(inspection, "BOUNDED_WORKER_RESULT", result.content_sha256));
  const repositoryUnchanged = postflight.repository_git_delta.length === 0;
  const scopeRefusal = refusals.length === 1 && blocked.length === 1 && applied.length === 0 && repositoryUnchanged;
  const identities = [policy.content_sha256, terminal.content_sha256, postflight.content_sha256, ...applied.map((entry) => entry.content_sha256), ...refusals.map((entry) => entry.content_sha256), ...blocked.map((entry) => entry.content_sha256)] as Sha256Digest[];
  identities.sort();
  return Object.freeze({ required_objective_unsatisfied: state.phase === "BLOCKED" && scopeRefusal,
    scope_refusal_observed: scopeRefusal, accepted_productive_mutations: applied.length, repository_unchanged: repositoryUnchanged,
    evidence_identities: Object.freeze([...new Set(identities)]) });
}
function requireControllerSources(arm: ExecutedM8Arm, records: DurableRecords, inspection: DurableInspection, policy: M5ControlPolicyDocument): void {
  const authority = arm.controller_authority;
  if (policy.run_id !== arm.run_id || policy.reducer_policy_content_sha256 !== authority.reducer_policy.content_sha256 ||
      policy.contract_sha256 !== authority.contract.contract_sha256 || policy.budget_sha256 !== authority.budget.budget_sha256 ||
      policy.route_map_sha256 !== authority.route_map.route_map_sha256 || policy.route_map_approval_sha256 !== authority.route_map_approval.route_map_approval_sha256 ||
      policy.baseline_approval_sha256 !== authority.baseline_authority_identity) throw new Error("M8_DURABLE_AUTHORITY_INVALID:M5 policy differs from frozen execution authority");
  const source = <T extends { readonly content_sha256: string }>(values: readonly T[], expected: T, label: string): void => {
    if (!values.some((value) => value.content_sha256 === expected.content_sha256 && sameCanonical(value, expected))) {
      throw new Error(`M8_DURABLE_AUTHORITY_INVALID:${label} source is absent or substituted`);
    }
  };
  source(records.contracts, authority.contract, "Contract"); source(records.budgets, authority.budget, "Budget");
  source(records.routeMaps, authority.route_map, "RouteMap"); source(records.routeMapApprovals, authority.route_map_approval, "RouteMapApproval");
  const baseline = exactlyOne(records.baselines, (entry) => entry.content_sha256 === authority.baseline.content_sha256 &&
    sameCanonical(entry, authority.baseline) && isAuthoritative(inspection, "M3_BASELINE", entry.content_sha256), "M3 baseline");
  void baseline;
  if (authority.baseline_approval !== null) {
    exactlyOne(records.approvals, (entry) => entry.content_sha256 === authority.baseline_approval!.content_sha256 &&
      sameCanonical(entry, authority.baseline_approval) && isAuthoritative(inspection, "M3_BASELINE_APPROVAL", entry.content_sha256), "M3 baseline approval");
  }
}
function requireResolvedBoundedExecutions(
  arm: ExecutedM8Arm,
  policy: M5ControlPolicyDocument,
  records: DurableRecords,
  inspection: DurableInspection,
): void {
  const authority = arm.controller_authority;
  const baseline = exactlyOne(records.baselines, (entry) => entry.content_sha256 === authority.baseline.content_sha256, "bounded baseline");
  const approval = authority.baseline_approval === null ? null : exactlyOne(records.approvals, (entry) => entry.content_sha256 === authority.baseline_approval!.content_sha256, "bounded approval");
  for (const result of records.boundedWorkerResults) {
    if (!isAuthoritative(inspection, "BOUNDED_WORKER_RESULT", result.content_sha256)) {
      throw new Error("M8_DURABLE_AUTHORITY_INVALID:bounded worker result is not authoritative");
    }
    const invocation = records.boundedWorkerInvocations.find((entry) => entry.content_sha256 === result.invocation_content_sha256);
    if (invocation === undefined || !isAuthoritative(inspection, "BOUNDED_WORKER_INVOCATION", invocation.content_sha256)) {
      throw new Error("M8_DURABLE_AUTHORITY_INVALID:bounded worker invocation is absent or non-authoritative");
    }
    const reservation = records.decisions.find((entry) => entry.content_sha256 === invocation.m5_reservation_decision_content_sha256);
    const reservationState = reservation === undefined ? undefined : records.workflowStates.find((entry) => entry.content_sha256 === reservation.current_state_content_sha256);
    const stateToken = records.stateTokens.find((entry) => entry.content_sha256 === invocation.input_m3_state_token_content_sha256);
    const task = invocation.task_content_sha256 === null ? null : records.tasks.find((entry) => entry.content_sha256 === invocation.task_content_sha256) ?? null;
    const graph = invocation.task_graph_sha256 === null ? null : records.taskGraphs.find((entry) => entry.content_sha256 === invocation.task_graph_sha256) ?? null;
    const plan = invocation.plan_approval_sha256 === null ? null : records.planApprovals.find((entry) => entry.content_sha256 === invocation.plan_approval_sha256) ?? null;
    if (reservation === undefined || reservationState === undefined || stateToken === undefined ||
        (invocation.task_content_sha256 !== null && task === null) || (invocation.task_graph_sha256 !== null && graph === null) ||
        (invocation.plan_approval_sha256 !== null && plan === null)) {
      throw new Error("M8_DURABLE_AUTHORITY_INVALID:bounded worker predecessor is absent");
    }
    const resolved = resolveAuthoritativeBoundedExecution({ invocation: invocation as BoundedWorkerInvocationDocument, result: result as BoundedWorkerResultDocument,
      reservation, reservationState, policy, baseline: baseline as M3BaselineRuntimeDocument, approval: approval as M3BaselineApprovalRuntimeDocument | null,
      stateToken: stateToken as M3RepositoryStateTokenDocument, task: task as TaskDocument | null, taskGraph: graph as TaskGraphDocument | null,
      plan: plan as PlanApprovalDocument | null, admissionRefusals: new Map(records.admissionRefusals.map((entry) => [entry.content_sha256, entry])), classifications: inspection.managedRecordClassifications });
    if (resolved.accepted) continue;
    throw new Error(`M8_DURABLE_AUTHORITY_INVALID:bounded worker resolution failed:${resolved.reason ?? "unknown"}`);
  }
}
async function resolveDurableEvidence(record: AuthoritativeRunRecord): Promise<{ readonly evidence: M8AuthoritativeWorkflowEvidence; readonly finalRoot: string }> {
  const arm = record.runtime;
  if (arm === null) throw new Error("M8_DURABLE_AUTHORITY_INVALID:native execution authority was never constructed");
  if (!arm.static_match) throw new Error("M8_STATIC_SLOT_MISMATCH:owner static slot did not match native authority");
  if (record.registrationError !== null || record.controllerRoot === null || record.stateRoot === null) {
    throw new Error(record.registrationError ?? "M8_HARNESS_CONTROLLER_ROOT_REGISTRATION_MISSING");
  }
  await revalidateRegisteredWorkspace(record.materialization, record.invocation);
  if (record.materialization !== arm.materialization) throw new Error("M8_DURABLE_AUTHORITY_INVALID:runtime workspace record differs");
  const owner = ownedInvocation(record.invocation);
  await revalidatePrivateDirectory(owner.rootRegistration); await revalidatePrivateDirectory(owner.retainedRegistration, owner.rootRegistration);
  await revalidatePrivateDirectory(record.controllerRoot, owner.retainedRegistration); await revalidatePrivateDirectory(record.stateRoot, record.controllerRoot);
  const location = { stateRoot: record.stateRoot.path, runId: arm.run_id };
  const [inspection, records] = await Promise.all([inspectRunStorage(location), readM5ManagedRecords(location)]);
  const state = inspection.workflowState;
  if (inspection.status !== "HEALTHY" || state === null || (state.phase !== "PASS" && state.phase !== "BLOCKED")) {
    throw new Error("M8_DURABLE_AUTHORITY_INVALID:terminal M2 state is unavailable");
  }
  if (record.controllerResult.finalState === null || !sameCanonical(record.controllerResult.finalState, state) || record.controllerResult.outcome !== state.phase) {
    throw new Error("M8_DURABLE_AUTHORITY_INVALID:controller result disagrees with persisted terminal state");
  }
  const policy = exactlyOne(records.policies, (entry) => entry.run_id === arm.run_id &&
    entry.reducer_policy_content_sha256 === arm.controller_authority.reducer_policy.content_sha256 &&
    isAuthoritative(inspection, "M5_CONTROL_POLICY", entry.content_sha256), "M5 policy");
  requireControllerSources(arm, records, inspection, policy); requireResolvedBoundedExecutions(arm, policy, records, inspection);
  const terminal = terminalDecision(records, inspection, state, arm.run_id);
  const postflight = optionalFinalPostflight(arm, records, inspection, terminal);
  if (postflight === null) throw new Error("M8_DURABLE_AUTHORITY_INVALID:exact final M3 postflight is absent");
  const commands = resolvedCommandEvidence(arm, policy, records, inspection);
  const budget = resolvedBudgetEvidence(arm, policy, records, inspection, terminal);
  const scope = resolvedScopeEvidence(arm, policy, records, inspection, state, terminal, postflight);
  const authorityIds = [state.content_sha256, terminal.content_sha256, policy.content_sha256, arm.controller_authority.baseline.content_sha256,
    ...(arm.controller_authority.baseline_approval === null ? [] : [arm.controller_authority.baseline_approval.content_sha256]), postflight.content_sha256] as Sha256Digest[];
  authorityIds.sort();
  return Object.freeze({ evidence: Object.freeze({ run_id: arm.run_id, execution_authority_digest: arm.execution_authority_digest,
    terminal_workflow_result: state.phase, terminal_evidence_identity: state.content_sha256 as Sha256Digest, final_postflight_identity: postflight.content_sha256 as Sha256Digest,
    final_repository_identity: postflight.repository.content_sha256 as Sha256Digest, final_git_fingerprint_identity: postflight.git_fingerprint.content_sha256 as Sha256Digest,
    authority_evidence_identities: Object.freeze([...new Set(authorityIds)]), command_results: commands,
    ...(budget === undefined ? {} : { budget }), ...(scope === undefined ? {} : { scope }),
  }), finalRoot: record.materialization.root });
}
function invalidCanonicalResult(record: AuthoritativeRunRecord, classification: M8FailureClassification): M8EvidenceResult {
  const runtime = record.runtime;
  return Object.freeze({ scenario_id: record.arm.scenario_id, mode: record.arm.mode, run_id: runtime?.run_id ?? null,
    execution_authority_digest: runtime?.execution_authority_digest ?? null, terminal_workflow_result: null, task_success: false,
    workflow_correctness: false, pilot_validity: false, failure_classification: classification, verifier_identity: null,
    terminal_evidence_identity: null, final_postflight_identity: null, command_result_identity: null });
}
function resolutionClassification(error: unknown): M8FailureClassification {
  const detail = error instanceof Error ? error.message : "";
  if (detail.startsWith("M8_STATIC_SLOT_MISMATCH")) return "ORCHESTRATION_DEFECT";
  return detail.startsWith("M8_HARNESS") || detail.startsWith("M8_DURABLE_AUTHORITY_INVALID") || detail.startsWith("M8_EVIDENCE_PUBLICATION_UNSAFE")
    ? "HARNESS_DEFECT" : "ENVIRONMENT_DEFECT";
}
async function deriveCanonicalResult(record: AuthoritativeRunRecord): Promise<M8EvidenceResult> {
  try {
    const resolved = await resolveDurableEvidence(record); const arm = record.runtime!;
    const { verifyM8PilotBlindly } = await import("./pilot-verifier.js");
    const verifier = await verifyM8PilotBlindly({ scenario: arm.scenario, initial: arm.materialization, finalRoot: resolved.finalRoot,
      authoritativeEvidence: resolved.evidence, expectedRunId: arm.run_id, expectedExecutionAuthorityDigest: arm.execution_authority_digest });
    return Object.freeze({ scenario_id: arm.scenario_id, mode: arm.mode, run_id: arm.run_id,
      execution_authority_digest: arm.execution_authority_digest, terminal_workflow_result: resolved.evidence.terminal_workflow_result,
      task_success: verifier.task_success, workflow_correctness: verifier.workflow_correctness, pilot_validity: verifier.pilot_validity,
      failure_classification: null, verifier_identity: verifier.verifier_identity, terminal_evidence_identity: resolved.evidence.terminal_evidence_identity,
      final_postflight_identity: resolved.evidence.final_postflight_identity, command_result_identity: resolved.evidence.command_results[0]?.m4_result_identity ?? null });
  } catch (error: unknown) { return invalidCanonicalResult(record, resolutionClassification(error)); }
}

async function assertPublicationTargetAbsent(pathValue: string): Promise<void> {
  try { await lstat(pathValue); publicationUnsafe(`publication target already exists:${pathValue}`); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}
async function syncDirectory(pathValue: string): Promise<void> {
  const handle = await open(pathValue, constants.O_RDONLY | constants.O_DIRECTORY);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function publishCanonicalOwned(invocation: M8Invocation, parentRole: "EVIDENCE" | "RESULTS", filename: string, value: unknown): Promise<void> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,191}\.json$/u.test(filename)) publicationUnsafe("derived publication filename is invalid");
  let owner = await revalidatePublicationTree(invocation);
  const parent = parentRole === "EVIDENCE" ? owner.evidenceRegistration : owner.resultsRegistration;
  const target = join(parent.path, filename);
  if (dirname(target) !== parent.path || target === owner.root || target === owner.evidence || target === owner.results || !physicallyWithin(owner.root, target)) {
    publicationUnsafe("derived target escapes registered publication directory");
  }
  await assertPublicationTargetAbsent(target);
  const temporary = join(parent.path, `.m8-${randomBytes(16).toString("hex")}.tmp`);
  // O_EXCL + O_NOFOLLOW prevents a substituted temporary/result pathname from
  // becoming authority. link(2) gives atomic no-replace final visibility; Node
  // exposes no rename-no-replace primitive, and ordinary rename would clobber.
  const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  let temporaryStats: Awaited<ReturnType<typeof lstat>>;
  try {
    temporaryStats = await handle.stat();
    if (!temporaryStats.isFile() || temporaryStats.isSymbolicLink() || temporaryStats.uid !== currentUid() || (temporaryStats.mode & 0o777) !== 0o600) {
      publicationUnsafe("temporary publication file is unsafe");
    }
    owner = await revalidatePublicationTree(invocation);
    if ((parentRole === "EVIDENCE" ? owner.evidenceRegistration.path : owner.resultsRegistration.path) !== parent.path) publicationUnsafe("publication parent changed before write");
    await handle.writeFile(`${canonicalize(value)}\n`, "utf8"); await handle.sync();
  } finally { await handle.close(); }
  owner = await revalidatePublicationTree(invocation);
  const checkedTemp = await lstat(temporary);
  if (!checkedTemp.isFile() || checkedTemp.isSymbolicLink() || checkedTemp.dev !== temporaryStats!.dev || checkedTemp.ino !== temporaryStats!.ino ||
      checkedTemp.uid !== temporaryStats!.uid || (checkedTemp.mode & 0o777) !== 0o600) publicationUnsafe("temporary publication identity changed");
  await assertPublicationTargetAbsent(target);
  await link(temporary, target);
  const published = await lstat(target);
  if (!published.isFile() || published.isSymbolicLink() || published.dev !== checkedTemp.dev || published.ino !== checkedTemp.ino || published.uid !== checkedTemp.uid) {
    publicationUnsafe("atomic publication target identity is unsafe");
  }
  await revalidatePublicationTree(invocation);
  const tempBeforeUnlink = await lstat(temporary);
  if (tempBeforeUnlink.dev !== checkedTemp.dev || tempBeforeUnlink.ino !== checkedTemp.ino || !tempBeforeUnlink.isFile() || tempBeforeUnlink.isSymbolicLink()) {
    publicationUnsafe("temporary publication identity changed before retirement");
  }
  await unlink(temporary); await syncDirectory(parent.path);
}
/** Deterministic summary projection; it neither selects nor replaces any slot. */
export function m8Summary(freeze: M8FreezeResult, results: readonly M8EvidenceResult[]): unknown {
  const ordered = [...results].sort((left, right) => `${left.scenario_id}--${left.mode}`.localeCompare(`${right.scenario_id}--${right.mode}`));
  const valid = ordered.filter((result) => result.pilot_validity); const completed = valid.filter((result) => result.terminal_workflow_result !== null);
  const classifications = ordered.filter((result) => !result.pilot_validity && result.failure_classification !== null).map((result) => result.failure_classification!).sort();
  return Object.freeze({ protocol: "m8-summary-v4", fixture_bundle_identity: freeze.fixture_bundle_identity, matrix_identity: freeze.matrix_identity,
    planned_slots: freeze.arms.length, valid_completed_slots: completed.length, invalid_slots: ordered.length - valid.length,
    product_PASS_count: completed.filter((result) => result.terminal_workflow_result === "PASS").length,
    product_BLOCKED_count: completed.filter((result) => result.terminal_workflow_result === "BLOCKED").length,
    task_success_count: completed.filter((result) => result.task_success).length, workflow_correctness_count: completed.filter((result) => result.workflow_correctness).length,
    missing_slots: freeze.arms.length - ordered.length, failure_classifications: classifications, outcomes: ordered });
}
/**
 * Canonical publication accepts only opaque handles created by actual execution.
 * It resolves durable M2–M5 evidence and invokes the blind verifier itself.
 */
export async function writeM8Evidence(invocation: M8Invocation, runs: readonly M8AuthoritativeRun[]): Promise<string> {
  if (!Array.isArray(runs) || runs.length === 0) throw new Error("M8_EVIDENCE_RUN_REQUIRED");
  // Revalidate the owned publication chain before even inspecting a supplied
  // opaque handle, so a substituted root cannot be masked by API misuse.
  const owner = await revalidatePublicationTree(invocation);
  const first = authoritativeRunRecords.get(runs[0]!); if (first === undefined) throw new Error("M8_AUTHORITATIVE_RUN_UNREGISTERED");
  const freeze = first.freeze; const approval = first.approval; assertFreeze(freeze); assertManifest(approval);
  if (first.invocation !== invocation) throw new Error("M8_EVIDENCE_INVOCATION_MISMATCH");
  if (approval.fixture_bundle_identity !== freeze.fixture_bundle_identity || approval.matrix_identity !== freeze.matrix_identity) binding("evidence approval does not bind freeze matrix");
  const selected: AuthoritativeRunRecord[] = [];
  const slots = new Set<string>();
  for (const handle of runs) {
    const record = authoritativeRunRecords.get(handle); if (record === undefined) throw new Error("M8_AUTHORITATIVE_RUN_UNREGISTERED");
    if (record.invocation !== invocation || record.freeze !== freeze || record.approval !== approval || !freeze.arms.includes(record.arm)) {
      throw new Error("M8_AUTHORITATIVE_RUN_BINDING_INVALID");
    }
    assertM8ArmApproved(record.arm, approval);
    const slot = `${record.arm.scenario_id}--${record.arm.mode}`;
    if (slots.has(slot)) throw new Error("M8_EVIDENCE_DUPLICATE_SLOT");
    slots.add(slot); selected.push(record);
  }
  // Validate every known target before the first write. A pre-existing result
  // is never treated as idempotent and no cleanup is attempted.
  await revalidatePublicationTree(invocation);
  const resultNames = selected.map((record) => `${record.arm.scenario_id}--${record.arm.mode}.json`);
  for (const name of ["manifest.json", "approval-request.json", "approval-manifest.json", "summary.json"]) await assertPublicationTargetAbsent(join(owner.evidence, name));
  for (const name of resultNames) await assertPublicationTargetAbsent(join(owner.results, name));
  const canonicalResults: M8EvidenceResult[] = [];
  for (const record of selected) canonicalResults.push(await deriveCanonicalResult(record));
  const ordered = canonicalResults.sort((left, right) => `${left.scenario_id}--${left.mode}`.localeCompare(`${right.scenario_id}--${right.mode}`));
  const manifest = Object.freeze({ protocol: EVIDENCE_PROTOCOL, fixture_bundle_identity: freeze.fixture_bundle_identity, matrix_identity: freeze.matrix_identity,
    approval_manifest_identity: approval.approval_manifest_identity,
    static_slots: freeze.arms.map((arm) => ({ scenario_id: arm.scenario_id, mode: arm.mode, slot_execution_order: arm.slot_execution_order,
      static_slot_spec_identity: arm.static_slot.static_slot_spec_identity })),
    executed_slots: selected.map((record) => ({ scenario_id: record.arm.scenario_id, mode: record.arm.mode, slot_execution_order: record.arm.slot_execution_order,
      run_id: record.runtime?.run_id ?? null, execution_authority_digest: record.runtime?.execution_authority_digest ?? null,
      workspace_identity: record.materialization.workspace_identity, initial_state_identity: record.materialization.initialStateIdentity })) });
  await publishCanonicalOwned(invocation, "EVIDENCE", "manifest.json", manifest);
  await publishCanonicalOwned(invocation, "EVIDENCE", "approval-request.json", freeze.arms.map((arm) => arm.static_slot));
  await publishCanonicalOwned(invocation, "EVIDENCE", "approval-manifest.json", approval);
  for (const result of ordered) await publishCanonicalOwned(invocation, "RESULTS", `${result.scenario_id}--${result.mode}.json`, result);
  await publishCanonicalOwned(invocation, "EVIDENCE", "summary.json", m8Summary(freeze, ordered));
  return owner.evidence;
}
