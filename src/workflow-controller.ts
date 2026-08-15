import { execFile, spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, unlink } from "node:fs/promises";
import { createServer, connect, type Server } from "node:net";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { canonicalize } from "./canonical-json/index.js";
import { createControlDecisionKernel } from "./control/index.js";
import type { M5AuthoritativeSources, M5FailureInput, M5ObligationEvidenceInput } from "./control/types.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "./identity/index.js";
import { m3ScopeIdentity } from "./identity/m3-scope.js";
import { commitTransition, initializeRunStorage, inspectRunStorage, terminalizeProcessCrash, type CommittedRunState } from "./persistence/index.js";
import { loadProcessCrashTerminalizationAuthority, readBoundedWorkerRecords, readM5ManagedRecords } from "./persistence/store.js";
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
import { captureGitState } from "./repository/fingerprint.js";
import { assertNoGitBlockers, assertRepositoryMatches } from "./repository/preflight.js";
import { loadAuthoritativeToken } from "./repository/token-provenance.js";
import { createScopedToolGateway } from "./scoped-tools/index.js";
import { isInterpreterExecutablePath } from "./scoped-tools/commands.js";
import { assertM4CanonicalPath } from "./secure-fs/path.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type BudgetDocument,
  type ConcreteExecutionMode,
  type ContractDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3PostflightDocument,
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
import { configureBoundedWorkerFauxRuntimeForTests, runBoundedWorker, runBoundedWorkerForTests, type BoundedWorkerRoute } from "./pi-adapter/bounded-worker.js";

const execFileAsync = promisify(execFile);
const RUN_ID = "pre-m8-bounded";
const CONTROLLER_VERSION = "0.1.0";
const MAX_TOOL_CALLS_PER_WORKER = 32;
const MAX_WALL_TIME_MS = 120_000;
const PRODUCT_ROLES = ["SOL_OWNER", "SOL_PLANNER", "SOL_REPLAN", "SOL_CLOSEOUT", "LUNA_EXECUTOR", "TERRA_EXECUTOR", "BENCHMARK_VERIFIER", "BENCHMARK_SELECTOR"] as const;

type GoalMode = ConcreteExecutionMode;
type GoalScope = { readonly readable_paths: readonly string[]; readonly editable_paths: readonly string[]; readonly frozen_paths: readonly string[] };
type CandidateTask = { readonly task_id: string; readonly objective: string; readonly editable_paths: readonly string[]; readonly required_outputs: readonly string[]; readonly dependencies: readonly string[]; readonly verification_command_ids?: readonly string[] };

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
  /** Narrow controller-owned accepted-mutation admission cap; goals and workers cannot set it. */
  readonly hard_mutation_tool_limit?: 1;
  /** Frozen STATIC_APPROVED_DAG repair edge cap; absent means no repair edge. */
  readonly static_max_attempts_per_leaf?: 1 | 2;
}

export interface BaselineApprovalRequest {
  readonly baseline_content_sha256: Sha256Digest;
  readonly approved_by: string;
  readonly approved_at: string;
}

export interface ForceStopCapabilityPresentation {
  readonly path: string;
  readonly runId: string;
  readonly repositoryRoot: string;
  readonly worktreeKey: string;
}

/** Exact static authority constructed by the bounded controller before worker reservation. */
export interface BoundedExecutionAuthority {
  readonly run_id: string;
  readonly mode: ConcreteExecutionMode;
  readonly repository: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly baseline_approval: M3BaselineApprovalRuntimeDocument | null;
  readonly baseline_authority_identity: Sha256Digest;
  readonly route_map: RouteMapDocument;
  readonly route_map_approval: RouteMapApprovalDocument;
  readonly budget: BudgetDocument;
  readonly contract: ContractDocument;
  readonly tasks: readonly TaskDocument[];
  readonly task_graph: TaskGraphDocument | null;
  readonly plan: PlanApprovalDocument | null;
  readonly reducer_policy: ReducerPolicy;
  readonly controller_limits: Readonly<{ readonly hard_m4_mutation_tool_limit: 1 | null; readonly max_replans: 0 }>;
}

export interface BoundedMutationOptions {
  readonly cwd?: string;
  readonly authority?: BoundedMutationAuthority;
  readonly approveBaseline?: (baseline: M3BaselineRuntimeDocument) => Promise<BaselineApprovalRequest | null>;
  readonly approveTasks?: (input: { readonly mode: GoalMode; readonly contract: ContractDocument; readonly tasks: readonly TaskDocument[]; readonly plan: PlanApprovalDocument | null; readonly executionAuthority: BoundedExecutionAuthority }) => Promise<Sha256Digest | null>;
  readonly approveOwnerAcceptance?: (input: { readonly task: TaskDocument; readonly finalState: WorkflowState }) => Promise<boolean>;
  readonly beforeFinalPostflight?: () => Promise<void> | void;
  readonly releaseLock?: (handle: WorktreeLockHandle) => Promise<void>;
  /** Cooperative cancellation is controller authority, not worker advice. */
  readonly signal?: AbortSignal;
  /** Existing, caller-owned directory for inspectable lifecycle and M2–M5 artifacts. */
  readonly retainedArtifactRoot?: string;
  /** Called synchronously before the first worker/provider/tool admission. */
  readonly onControlCapability?: (capability: ForceStopCapabilityPresentation) => Promise<void> | void;
}

export interface ExternalLifecycleErrorEvidence {
  readonly errorClass: string;
  readonly message: string;
}

/** Parent-observed, bounded diagnostics for a child that never supplied a recognized RESULT. */
export interface ExternalLifecycleDiagnosticEvidence {
  readonly childPid: number | null;
  readonly childExecPath: string;
  readonly childCwd: string;
  readonly spawnObserved: boolean;
  readonly spawnError: ExternalLifecycleErrorEvidence | null;
  readonly processError: ExternalLifecycleErrorEvidence | null;
  readonly startSendAttempted: boolean;
  readonly startSendCallback: "NOT_ATTEMPTED" | "PENDING" | "SUCCEEDED" | "FAILED";
  readonly startSendError: ExternalLifecycleErrorEvidence | null;
  readonly ipcMessageReceived: boolean;
  readonly firstIpcMessageKind: "RESULT" | "FIXTURE_STAGE" | "CALLBACK" | "UNKNOWN" | null;
  readonly recognizedResultReceived: boolean;
  readonly malformedResultReceived: boolean;
  readonly ipcDisconnected: boolean;
  readonly exitObserved: boolean;
  readonly exitCode: number | null;
  readonly exitSignal: NodeJS.Signals | null;
  readonly closeObserved: boolean;
  readonly closeCode: number | null;
  readonly closeSignal: NodeJS.Signals | null;
  readonly childExitPhase: "NOT_OBSERVED" | "BEFORE_START_ACKNOWLEDGEMENT" | "AFTER_START_ACKNOWLEDGEMENT" | "AFTER_IPC_MESSAGE";
  readonly stderrTail: string | null;
  readonly stderrTailTruncated: boolean;
}

export interface BoundedMutationRunResult {
  readonly outcome: "PASS" | "BLOCKED";
  readonly reason: string;
  readonly finalState: WorkflowState | null;
  readonly evidenceRoot?: string;
  readonly hygieneWarning?: string;
  /** Never grants completion authority; absent after a recognized child RESULT. */
  readonly lifecycleDiagnostic?: ExternalLifecycleDiagnosticEvidence;
}

const FORCE_STOP_PROTOCOL = "pi-workflow-invocation-control-v1";
const FORCE_STOP_VERSION = 1;
const FORCE_STOP_GRACE_MS = 1_000;
const FORCE_STOP_EXIT_WAIT_MS = 2_000;
const FORCE_STOP_REQUEST_TIMEOUT_MS = 15_000;
const EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES = 4_096;
const EXTERNAL_LIFECYCLE_ERROR_TEXT_BYTES = 1_024;
// Linux sun_path holds 108 bytes including its terminating NUL.
const LINUX_UNIX_SOCKET_PATH_MAX_BYTES = 107;

interface ActiveControlCapability {
  readonly path: string;
  readonly device: number;
  readonly inode: number;
  readonly record: ForceStopCapabilityRecord;
}

interface ForceStopCapabilityRecord {
  readonly protocol: typeof FORCE_STOP_PROTOCOL;
  readonly version: typeof FORCE_STOP_VERSION;
  /** Collision resistance for capability filenames, not same-UID authentication. */
  readonly nonce: string;
  readonly parent_pid: number;
  readonly parent_start_ticks: string;
  readonly productive_pid: number;
  readonly productive_start_ticks: string;
  readonly invocation_session_id: number;
  readonly control_root: string;
  readonly control_socket: string;
  readonly state_root: string;
  readonly run_id: string;
  readonly repository_root: string;
  readonly worktree_key: string;
  readonly created_at: string;
}

interface CompletionClaim {
  readonly protocol: typeof FORCE_STOP_PROTOCOL;
  readonly version: typeof FORCE_STOP_VERSION;
  readonly winner: "CANCELLED" | "COMPLETED";
  readonly detail: string;
  readonly created_at: string;
}

interface ProcIdentity {
  readonly pid: number;
  readonly state: string;
  readonly startTicks: string;
  readonly processGroup: number;
  readonly sessionId: number;
}

interface CheckedControlCapability {
  readonly capability: ForceStopCapabilityRecord;
  readonly stats: Awaited<ReturnType<typeof lstat>>;
  readonly parent: ProcIdentity | null;
  readonly productive: ProcIdentity | null;
  readonly claim: CompletionClaim | null;
}

export type ForceStopDisposition =
  | "BLOCKED_CANCELLED"
  | "BLOCKED_FORCE_TERMINATED"
  | "BLOCKED_FORCE_STOP_CAPABILITY_INVALID"
  | "BLOCKED_FORCE_STOP_DESCENDANT_UNCERTAIN"
  | "BLOCKED_FORCE_STOP_RECONCILIATION_UNCERTAIN"
  | "ALREADY_TERMINAL";

export interface ForceStopResult {
  readonly disposition: ForceStopDisposition;
  readonly detail: string;
  readonly retiredCapabilityPath: string | null;
}

class ForceStopCapabilityError extends Error {
  public constructor(message: string) { super(message); this.name = "ForceStopCapabilityError"; }
}

function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error ? String((error as { readonly code: unknown }).code) : undefined;
}
function currentUid(): number | undefined { return typeof process.getuid === "function" ? process.getuid() : undefined; }
function physicalChild(pathValue: string, root: string): boolean {
  const candidate = resolve(pathValue); const parent = resolve(root);
  return candidate === parent || candidate.startsWith(`${parent}/`);
}
function validAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 1 && value.length <= 4_096 && isAbsolute(value) && resolve(value) === value && !value.includes("\0");
}
function assertLinuxControlSocketPathBudget(pathValue: string): void {
  if (process.platform !== "linux") throw new BoundedWorkflowError("CONTROL_SOCKET_PLATFORM_UNSUPPORTED", "control sockets require the supported Linux pathname budget");
  if (Buffer.byteLength(pathValue) > LINUX_UNIX_SOCKET_PATH_MAX_BYTES) {
    throw new BoundedWorkflowError("CONTROL_SOCKET_PATH_TOO_LONG", "control socket pathname exceeds the Linux sun_path budget");
  }
}
async function canonicalOwnedDirectory(pathValue: string, label: string): Promise<string> {
  if (!validAbsolutePath(pathValue)) throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", `${label} must be an absolute normalized path`);
  let stats;
  try { stats = await lstat(pathValue); }
  catch { throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", `${label} is unavailable`); }
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", `${label} must be a regular directory`);
  const uid = currentUid();
  if ((uid !== undefined && stats.uid !== uid) || (stats.mode & 0o022) !== 0) throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", `${label} must be privately owned by the caller`);
  let physical: string;
  try { physical = await realpath(pathValue); }
  catch { throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", `${label} cannot be resolved`); }
  if (physical !== pathValue) throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", `${label} may not traverse a symlink`);
  return physical;
}

function exactRecord(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new ForceStopCapabilityError(`${label} is not an object`);
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort(); const wanted = [...keys].sort();
  if (actual.length !== wanted.length || actual.some((entry, index) => entry !== wanted[index])) throw new ForceStopCapabilityError(`${label} has unknown or missing fields`);
  return record;
}

async function readProcIdentity(pid: number): Promise<ProcIdentity | null> {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new ForceStopCapabilityError("PID is invalid");
  let value: string;
  try { value = await readFile(`/proc/${pid}/stat`, "utf8"); }
  catch (error: unknown) {
    const code = errorCode(error);
    if (code === "ENOENT" || code === "ENOTDIR" || code === "ESRCH") return null;
    throw new ForceStopCapabilityError(`cannot inspect /proc/${pid}/stat`);
  }
  const closing = value.lastIndexOf(")"); const opening = value.indexOf(" (");
  if (opening < 1 || closing <= opening) throw new ForceStopCapabilityError(`/proc/${pid}/stat is malformed`);
  const parsedPid = Number(value.slice(0, opening)); const fields = value.slice(closing + 1).trim().split(/\s+/u);
  const state = fields[0]; const processGroup = Number(fields[2]); const sessionId = Number(fields[3]); const startTicks = fields[19];
  if (parsedPid !== pid || state === undefined || !/^[A-Z]$/u.test(state) || !Number.isSafeInteger(processGroup) || processGroup < 0 ||
      !Number.isSafeInteger(sessionId) || sessionId < 0 || startTicks === undefined || !/^\d+$/u.test(startTicks)) {
    throw new ForceStopCapabilityError(`/proc/${pid}/stat identity is malformed`);
  }
  return { pid, state, startTicks, processGroup, sessionId };
}

async function processSnapshot(): Promise<ReadonlyMap<number, ProcIdentity>> {
  let entries;
  try { entries = await readdir("/proc", { withFileTypes: true }); }
  catch { throw new ForceStopCapabilityError("cannot enumerate /proc"); }
  const identifiers = entries.map((entry) => entry.name).filter((entry) => /^\d+$/u.test(entry)).map((entry) => Number(entry)).filter((entry) => Number.isSafeInteger(entry) && entry > 1);
  const values = await Promise.all(identifiers.map(async (pid) => readProcIdentity(pid)));
  return new Map(values.filter((value): value is ProcIdentity => value !== null).map((value) => [value.pid, value]));
}

function sameProcess(left: ProcIdentity | null, pid: number, startTicks: string): left is ProcIdentity {
  return left !== null && left.pid === pid && left.startTicks === startTicks;
}

function completionClaimPath(capability: ForceStopCapabilityRecord): string {
  return join(capability.control_root, "completion.claim.json");
}

async function publishControlCapability(record: ForceStopCapabilityRecord): Promise<ActiveControlCapability> {
  const pathValue = join(record.control_root, `.pi-workflow-control-${randomBytes(16).toString("hex")}.json`);
  let created = false;
  try {
    const handle = await open(pathValue, "wx", 0o600); created = true;
    try { await handle.writeFile(`${canonicalize(record)}\n`, "utf8"); await handle.chmod(0o600); await handle.sync(); }
    finally { await handle.close(); }
    const stats = await lstat(pathValue);
    if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) {
      throw new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", "control capability file is unsafe");
    }
    return { path: pathValue, device: stats.dev, inode: stats.ino, record };
  } catch (error: unknown) {
    if (created) await unlink(pathValue).catch(() => undefined);
    throw error;
  }
}

async function readCompletionClaim(capability: ForceStopCapabilityRecord): Promise<CompletionClaim | null> {
  const pathValue = completionClaimPath(capability);
  let stats;
  try { stats = await lstat(pathValue); }
  catch (error: unknown) { if (errorCode(error) === "ENOENT") return null; throw new ForceStopCapabilityError("completion claim is unavailable"); }
  if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) throw new ForceStopCapabilityError("completion claim is unsafe");
  const uid = currentUid(); if (uid !== undefined && stats.uid !== uid) throw new ForceStopCapabilityError("completion claim owner is invalid");
  if (await realpath(pathValue) !== pathValue) throw new ForceStopCapabilityError("completion claim is symlinked");
  let parsed: unknown;
  try { parsed = JSON.parse(await readFile(pathValue, "utf8")) as unknown; }
  catch { throw new ForceStopCapabilityError("completion claim is malformed"); }
  const value = exactRecord(parsed, ["protocol", "version", "winner", "detail", "created_at"], "completion claim");
  if (value["protocol"] !== FORCE_STOP_PROTOCOL || value["version"] !== FORCE_STOP_VERSION ||
      (value["winner"] !== "CANCELLED" && value["winner"] !== "COMPLETED") || typeof value["detail"] !== "string" || value["detail"].length > 4_096 || typeof value["created_at"] !== "string") {
    throw new ForceStopCapabilityError("completion claim fields are invalid");
  }
  return value as unknown as CompletionClaim;
}

async function claimCompletion(capability: ForceStopCapabilityRecord, winner: CompletionClaim["winner"], detail: string): Promise<{ readonly claim: CompletionClaim; readonly won: boolean }> {
  const pathValue = completionClaimPath(capability);
  const claim: CompletionClaim = { protocol: FORCE_STOP_PROTOCOL, version: FORCE_STOP_VERSION, winner, detail: detail.slice(0, 4_096), created_at: new Date().toISOString() };
  try {
    const handle = await open(pathValue, "wx", 0o600);
    try { await handle.writeFile(`${canonicalize(claim)}\n`, "utf8"); await handle.chmod(0o600); await handle.sync(); }
    finally { await handle.close(); }
    const stats = await lstat(pathValue);
    if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) throw new ForceStopCapabilityError("completion claim publication is unsafe");
    return { claim, won: true };
  } catch (error: unknown) {
    if (errorCode(error) !== "EEXIST") throw error;
    const existing = await readCompletionClaim(capability);
    if (existing === null) throw new ForceStopCapabilityError("completion claim disappeared during arbitration");
    return { claim: existing, won: false };
  }
}

async function checkedControlCapability(pathValue: string): Promise<CheckedControlCapability> {
  if (!validAbsolutePath(pathValue)) throw new ForceStopCapabilityError("capability path is not absolute and normalized");
  let stats;
  try { stats = await lstat(pathValue); }
  catch { throw new ForceStopCapabilityError("capability file is unavailable"); }
  if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) throw new ForceStopCapabilityError("capability file mode or type is invalid");
  const uid = currentUid(); if (uid !== undefined && stats.uid !== uid) throw new ForceStopCapabilityError("capability file owner is invalid");
  if (await realpath(pathValue) !== pathValue) throw new ForceStopCapabilityError("capability file is symlinked");
  let parsed: unknown;
  try { parsed = JSON.parse(await readFile(pathValue, "utf8")) as unknown; }
  catch { throw new ForceStopCapabilityError("capability file is not valid JSON"); }
  const value = exactRecord(parsed, ["protocol", "version", "nonce", "parent_pid", "parent_start_ticks", "productive_pid", "productive_start_ticks", "invocation_session_id", "control_root", "control_socket", "state_root", "run_id", "repository_root", "worktree_key", "created_at"], "capability");
  if (value["protocol"] !== FORCE_STOP_PROTOCOL || value["version"] !== FORCE_STOP_VERSION || typeof value["nonce"] !== "string" || !/^[0-9a-f]{64}$/u.test(value["nonce"]) ||
      !Number.isSafeInteger(value["parent_pid"]) || (value["parent_pid"] as number) <= 1 || typeof value["parent_start_ticks"] !== "string" || !/^\d+$/u.test(value["parent_start_ticks"]) ||
      !Number.isSafeInteger(value["productive_pid"]) || (value["productive_pid"] as number) <= 1 || typeof value["productive_start_ticks"] !== "string" || !/^\d+$/u.test(value["productive_start_ticks"]) ||
      !Number.isSafeInteger(value["invocation_session_id"]) || (value["invocation_session_id"] as number) <= 1 || !validAbsolutePath(value["control_root"]) || !validAbsolutePath(value["control_socket"]) ||
      !validAbsolutePath(value["state_root"]) || typeof value["run_id"] !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value["run_id"]) || !validAbsolutePath(value["repository_root"]) ||
      typeof value["worktree_key"] !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value["worktree_key"]) || typeof value["created_at"] !== "string") {
    throw new ForceStopCapabilityError("capability fields are invalid");
  }
  const capability = value as unknown as ForceStopCapabilityRecord;
  if (!physicalChild(capability.control_socket, capability.control_root)) throw new ForceStopCapabilityError("control socket escapes the invocation root");
  for (const [location, label] of [[capability.control_root, "control root"], [capability.state_root, "state root"], [capability.repository_root, "repository root"]] as const) {
    let locationStats;
    try { locationStats = await lstat(location); }
    catch { throw new ForceStopCapabilityError(`${label} is unavailable`); }
    if (!locationStats.isDirectory() || locationStats.isSymbolicLink() || await realpath(location) !== location) throw new ForceStopCapabilityError(`${label} is structurally invalid`);
    if ((label === "control root" || label === "state root") && ((uid !== undefined && locationStats.uid !== uid) || (locationStats.mode & 0o077) !== 0)) {
      throw new ForceStopCapabilityError(`${label} is not private to the lifecycle owner`);
    }
  }
  const [parent, productive, claim] = await Promise.all([
    readProcIdentity(capability.parent_pid), readProcIdentity(capability.productive_pid), readCompletionClaim(capability),
  ]);
  if (parent !== null && !sameProcess(parent, capability.parent_pid, capability.parent_start_ticks)) throw new ForceStopCapabilityError("parent PID/start identity is stale or reused");
  if (productive !== null && (!sameProcess(productive, capability.productive_pid, capability.productive_start_ticks) || productive.sessionId !== capability.invocation_session_id || productive.processGroup !== capability.productive_pid)) {
    throw new ForceStopCapabilityError("productive PID/start/session identity is stale or reused");
  }
  if (claim === null) {
    let socketStats;
    try { socketStats = await lstat(capability.control_socket); }
    catch { throw new ForceStopCapabilityError("active control socket is unavailable"); }
    if (!socketStats.isSocket() || (socketStats.mode & 0o777) !== 0o600 || (uid !== undefined && socketStats.uid !== uid)) throw new ForceStopCapabilityError("active control socket is unsafe");
  }
  const after = await lstat(pathValue);
  if (after.dev !== stats.dev || after.ino !== stats.ino || !after.isFile() || after.isSymbolicLink()) throw new ForceStopCapabilityError("capability changed while being validated");
  return { capability, stats, parent, productive, claim };
}

function checkedForceStopResult(value: unknown): ForceStopResult {
  const record = exactRecord(value, ["disposition", "detail", "retiredCapabilityPath"], "force-stop response");
  const dispositions = new Set<ForceStopDisposition>(["BLOCKED_CANCELLED", "BLOCKED_FORCE_TERMINATED", "BLOCKED_FORCE_STOP_CAPABILITY_INVALID", "BLOCKED_FORCE_STOP_DESCENDANT_UNCERTAIN", "BLOCKED_FORCE_STOP_RECONCILIATION_UNCERTAIN", "ALREADY_TERMINAL"]);
  if (!dispositions.has(record["disposition"] as ForceStopDisposition) || typeof record["detail"] !== "string" || record["detail"].length > 4_096 || (record["retiredCapabilityPath"] !== null && !validAbsolutePath(record["retiredCapabilityPath"]))) {
    throw new ForceStopCapabilityError("force-stop response is invalid");
  }
  return record as unknown as ForceStopResult;
}

async function requestForceStop(capability: ForceStopCapabilityRecord, graceMs: number): Promise<ForceStopResult> {
  return new Promise<ForceStopResult>((resolveResult, rejectResult) => {
    const socket = connect(capability.control_socket); let buffer = ""; let settled = false;
    const fail = (error: unknown): void => { if (!settled) { settled = true; clearTimeout(timer); rejectResult(error); } };
    const timer = setTimeout(() => { socket.destroy(); fail(new ForceStopCapabilityError("external lifecycle owner did not respond")); }, FORCE_STOP_REQUEST_TIMEOUT_MS); timer.unref();
    socket.once("error", fail);
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > 16_384) { socket.destroy(); fail(new ForceStopCapabilityError("force-stop response exceeded its bound")); return; }
      const newline = buffer.indexOf("\n"); if (newline < 0) return;
      try {
        const response = checkedForceStopResult(JSON.parse(buffer.slice(0, newline)) as unknown);
        if (!settled) { settled = true; clearTimeout(timer); resolveResult(response); }
        socket.end();
      } catch (error: unknown) { fail(error); }
    });
    socket.once("connect", () => { socket.end(`${JSON.stringify({ protocol: FORCE_STOP_PROTOCOL, operation: "FORCE_STOP", grace_ms: graceMs, capability_content_sha256: sha256Canonical(capability) })}\n`); });
  });
}

/** Routes force-stop requests to the responsive invocation-local lifecycle owner. */
export async function forceStopBoundedMutationWorkflow(capabilityPath: string, graceMs = FORCE_STOP_GRACE_MS): Promise<ForceStopResult> {
  let checked: CheckedControlCapability;
  try { checked = await checkedControlCapability(capabilityPath); }
  catch (error: unknown) { return { disposition: "BLOCKED_FORCE_STOP_CAPABILITY_INVALID", detail: error instanceof Error ? error.message : "capability validation failed", retiredCapabilityPath: null }; }
  if (checked.claim?.winner === "COMPLETED") return { disposition: "ALREADY_TERMINAL", detail: "COMPLETED already won after lifecycle settlement", retiredCapabilityPath: capabilityPath };
  if (checked.claim?.winner === "CANCELLED") return { disposition: "BLOCKED_CANCELLED", detail: "CANCELLED already won", retiredCapabilityPath: capabilityPath };
  if (!sameProcess(checked.parent, checked.capability.parent_pid, checked.capability.parent_start_ticks)) {
    return { disposition: "BLOCKED_FORCE_STOP_CAPABILITY_INVALID", detail: "external lifecycle owner PID/start identity is unavailable", retiredCapabilityPath: null };
  }
  const grace = Number.isSafeInteger(graceMs) && graceMs >= 0 && graceMs <= 30_000 ? graceMs : FORCE_STOP_GRACE_MS;
  try { return await requestForceStop(checked.capability, grace); }
  catch (error: unknown) {
    // A normal completion may retire the socket between validation and connect.
    // Re-read the immutable claim before reporting a control-channel failure.
    try {
      const after = await checkedControlCapability(capabilityPath);
      if (after.claim?.winner === "COMPLETED") return { disposition: "ALREADY_TERMINAL", detail: "COMPLETED won while force-stop was connecting", retiredCapabilityPath: capabilityPath };
      if (after.claim?.winner === "CANCELLED") return { disposition: "BLOCKED_CANCELLED", detail: "CANCELLED won while force-stop was connecting", retiredCapabilityPath: capabilityPath };
    } catch { /* Preserve the original fail-closed control-channel result. */ }
    return { disposition: "BLOCKED_FORCE_STOP_CAPABILITY_INVALID", detail: error instanceof Error ? error.message : "external lifecycle owner is unavailable", retiredCapabilityPath: null };
  }
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
  if (value === "DIRECT_LUNA_HIGH" || value === "SINGLE_OWNER_SOL" || value === "ROUTED_DAG" || value === "STATIC_APPROVED_DAG") return value;
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
      const requiredTaskKeys = ["task_id", "objective", "editable_paths", "required_outputs", "dependencies"];
      const allowedTaskKeys = [...requiredTaskKeys, "verification_command_ids"];
      for (const key of Object.keys(taskInput)) if (!allowedTaskKeys.includes(key)) fail("INVALID_GOAL", `Goal.tasks[${index}] has unknown authority`);
      for (const key of requiredTaskKeys) if (!(key in taskInput)) fail("INVALID_GOAL", `Goal.tasks[${index}].${key} is required`);
      const verificationCommandIds = taskInput["verification_command_ids"] === undefined ? undefined : ids(taskInput["verification_command_ids"], `Goal.tasks[${index}].verification_command_ids`);
      return { task_id: text(taskInput["task_id"], `Goal.tasks[${index}].task_id`, 128), objective: text(taskInput["objective"], `Goal.tasks[${index}].objective`),
        editable_paths: paths(taskInput["editable_paths"], `Goal.tasks[${index}].editable_paths`), required_outputs: paths(taskInput["required_outputs"], `Goal.tasks[${index}].required_outputs`), dependencies: ids(taskInput["dependencies"], `Goal.tasks[${index}].dependencies`),
        ...(verificationCommandIds === undefined ? {} : { verification_command_ids: verificationCommandIds }) };
    });
  }
  if (selectedMode !== "STATIC_APPROVED_DAG" && candidate.some((task) => task.verification_command_ids !== undefined)) fail("INVALID_GOAL", "verification_command_ids is restricted to STATIC_APPROVED_DAG");
  if (selectedMode === "ROUTED_DAG" || selectedMode === "STATIC_APPROVED_DAG") {
    if (candidate.length < 2 || candidate.length > 8) fail("INVALID_GOAL", `${selectedMode} requires 2–8 leaves`);
    const seen = new Set<string>();
    for (let index = 0; index < candidate.length; index += 1) {
      const task = candidate[index]!;
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(task.task_id) || seen.has(task.task_id)) fail("INVALID_GOAL", "task IDs must be unique identifiers");
      seen.add(task.task_id);
      if (task.editable_paths.length === 0 || task.required_outputs.length === 0 || task.editable_paths.some((entry) => !within(entry, scope.editable_paths)) || task.required_outputs.some((entry) => !required.includes(entry))) fail("INVALID_GOAL", "routed task scope or output is invalid");
      const expected = index === 0 ? [] : [candidate[index - 1]!.task_id];
      if (selectedMode === "ROUTED_DAG" && canonicalize(task.dependencies) !== canonicalize(expected)) fail("INVALID_GOAL", "Routed DAG must be static sequential leaves");
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

type ProviderVisibleReadScope = {
  readonly regularFilePaths: readonly string[];
  readonly prefixPaths: readonly string[];
};

function partitionProviderVisibleReadScope(readablePaths: readonly string[], pathAuthorities: M4ScopedToolPolicyDocument["path_authorities"]): ProviderVisibleReadScope {
  const authorityKinds = new Map(pathAuthorities.map((entry) => [entry.path, entry.kind]));
  const regularFilePaths: string[] = [];
  const prefixPaths: string[] = [];
  for (const readablePath of readablePaths) {
    const kind = authorityKinds.get(readablePath);
    if (kind === "EXACT") regularFilePaths.push(readablePath);
    else if (kind === "PREFIX") prefixPaths.push(readablePath);
    else fail("CONTROLLER_AUTHORITY_INVALID", `frozen readable path ${readablePath} has no M4 path-kind authority`);
  }
  return { regularFilePaths, prefixPaths };
}

function providerVisibleTaskContract(objective: string, readableScope: ProviderVisibleReadScope, editablePaths: readonly string[], plannerPlan: PlanApprovalDocument | null, hardMutationToolLimit: 1 | null): string {
  const paths = (values: readonly string[]) => values.map((entry) => `- ${entry}`).join("\n") || "- (none)";
  const plannerInstruction = plannerPlan === null ? "" : `\nPlanner instruction: submit exactly candidate_plan_sha256:${plannerPlan.content_sha256}; topology, scope, and identity expansion are forbidden.`;
  const boundedMutationInstruction = hardMutationToolLimit !== 1 ? "" : "\n\nFrozen productive mutation sequence:\n- Make the first productive mutation request a genuine observable byte-changing edit to one task-owned editable path; a no-op replacement is not productive.\n- After that first productive mutation succeeds, do not stop: issue a second genuinely productive mutation request on that same task-owned editable path, requesting another byte-changing edit from its then-current contents.\n- Do not simulate the second attempt. Use only the supplied bounded tools and let the controller/M4 mutation-budget boundary decide that request.";
  return `Frozen task contract\n\nObjective (exact frozen text):\n${objective}\n\nReadable paths (exact frozen scope):\nRegular-file read targets (valid read_scoped.path values):\n${paths(readableScope.regularFilePaths)}\n\nDirectory/prefix authority (not valid read_scoped.path values):\n${paths(readableScope.prefixPaths)}\n\nEditable paths (exact frozen scope):\n${paths(editablePaths)}\n\nScoped path requirements:\n- Scoped tool path arguments are exact canonical repository-relative paths; use the listed spelling exactly.\n- read_scoped.path must name one authorized regular-file read target listed above.\n- Directory/prefix authority establishes frozen scope and command/cwd authority; it is not a regular-file read target and must not be passed directly to read_scoped.path.\n- Repository-root aliases and discovery are not authorized. Invalid forms include ., an empty path, ./..., root aliases, .. or traversal, and absolute paths.\n- Do not normalize an alias into another path.${boundedMutationInstruction}${plannerInstruction}`;
}
function processMetadata() { return { controller_instance_id: "pre-m8-bounded-controller", process_id: Math.max(1, process.pid), invocation_id: "pre-m8-bounded-invocation" }; }
function evidence(value: unknown): { readonly bytes: Buffer; readonly mediaType: string } { return { bytes: Buffer.from(`${canonicalize(value)}\n`, "utf8"), mediaType: "application/json" }; }
function event(type: TransitionEvent["event_type"], payload: Record<string, unknown> = {}): TransitionEvent {
  return identifyContractDocument("pi_gacw_transition_event_v0", { schema_id: "pi_gacw_transition_event_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    event_id: `pre-m8-${type.toLowerCase()}-${sha256Canonical(payload).slice(7, 23)}`, event_type: type, payload }) as TransitionEvent;
}
function fixed(label: string): Sha256Digest { return sha256Canonical({ protocol: "pre-m8-fixed-v1", label }); }
function target(repository: M3RepositoryIdentityDocument): ContractDocument["target_repository"] { return { root: repository.git_toplevel, git_common_dir: repository.git_common_dir, worktree: repository.worktree_root, branch: repository.branch ?? "DETACHED", head: repository.head }; }

function routeMap(maxToolCalls: number): RouteMapDocument {
  const routes = PRODUCT_ROLES.map((logical_role) => {
    const luna = logical_role === "LUNA_EXECUTOR";
    const terra = logical_role === "TERRA_EXECUTOR";
    const mutates = luna || terra || logical_role === "SOL_OWNER";
    return { logical_role, provider_id: "openai-codex", model_id: terra ? "gpt-5.6-terra" : luna ? "gpt-5.6-luna" : "gpt-5.6-sol", effort: luna || terra ? "high" as const : "max" as const,
      tool_policy: { policy_id: `pre-m8-${logical_role.toLowerCase()}`, built_in_tools_disabled: true as const, mutation_tool: mutates ? "APPLY_PATCH_SCOPED" as const : "NONE" as const,
        command_gateway: logical_role === "SOL_CLOSEOUT" ? "VERIFICATION_ONLY" as const : logical_role === "SOL_PLANNER" ? "INSPECTION_ONLY" as const : "TASK_AND_VERIFICATION" as const,
        maximum_tool_calls: maxToolCalls } };
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
function controllerMutationLimit(authority: BoundedMutationAuthority): number {
  if (authority.hard_mutation_tool_limit === undefined) return MAX_TOOL_CALLS_PER_WORKER;
  if (authority.hard_mutation_tool_limit !== 1) fail("INVALID_CONTROLLER_TOOL_LIMIT", "only the frozen hard mutation limit of 1 is supported");
  return 1;
}

function budget(goal: ReturnType<typeof normalizeGoal>, maxToolCalls: number, staticAttemptsPerLeaf = 1): BudgetDocument {
  if (staticAttemptsPerLeaf !== 1 && staticAttemptsPerLeaf !== 2) fail("INVALID_STATIC_REPAIR_EDGE", "STATIC_APPROVED_DAG permits at most one frozen repair edge per node");
  const workers = goal.execution_mode === "STATIC_APPROVED_DAG" ? goal.tasks.length * staticAttemptsPerLeaf : goal.execution_mode === "ROUTED_DAG" ? goal.tasks.length + 2 : 1;
  return identifyContractDocument("pi_gacw_budget_v0", { schema_id: "pi_gacw_budget_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", budget_projection_id: "budget-freeze-v1", budget_sha256: fixed(`budget:${workers}`),
    limits: { max_leaves: goal.execution_mode === "ROUTED_DAG" || goal.execution_mode === "STATIC_APPROVED_DAG" ? 8 : 1, max_attempts_per_leaf: goal.execution_mode === "STATIC_APPROVED_DAG" ? staticAttemptsPerLeaf : 1, max_replans: 0, max_worker_invocations: workers, max_model_turns: workers * 32,
      max_tool_calls: workers * maxToolCalls, max_input_tokens: 1_000_000, max_output_tokens: 100_000, max_cost_microusd: 5_000_000, max_wall_time_ms: workers * MAX_WALL_TIME_MS },
    usage: { worker_invocation: { value: 0, enforcement_class: "HARD_ENFORCEABLE" }, model_turn: { value: 0, enforcement_class: "SOFT_ENFORCEABLE" }, provider_request: { value: null, enforcement_class: "UNAVAILABLE" }, tool_call: { value: 0, enforcement_class: "HARD_ENFORCEABLE" } } }) as BudgetDocument;
}
function selectedTaskVerificationCommands(goal: ReturnType<typeof normalizeGoal>, candidate: CandidateTask, verification: ContractDocument["verification_commands"]): ContractDocument["verification_commands"] {
  if (goal.execution_mode !== "STATIC_APPROVED_DAG" || candidate.verification_command_ids === undefined) return verification;
  const selected = new Set(candidate.verification_command_ids);
  if (candidate.verification_command_ids.some((commandId) => !verification.some((command) => command.command_id === commandId))) {
    fail("UNKNOWN_STATIC_VERIFICATION_COMMAND", "STATIC_APPROVED_DAG selected an unknown controller verification command");
  }
  return verification.filter((command) => selected.has(command.command_id));
}

function taskDocument(goal: ReturnType<typeof normalizeGoal>, candidate: CandidateTask, index: number, verification: ContractDocument["verification_commands"]): TaskDocument {
  return identifyContractDocument("pi_gacw_task_v0", { schema_id: "pi_gacw_task_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", task_projection_id: "task-packet-v1", task_sha256: fixed(`task:${candidate.task_id}`),
    task_id: candidate.task_id, topological_rank: index, priority: index, dependencies: candidate.dependencies, objective: candidate.objective,
    scope: { readable_paths: goal.scope.readable_paths, editable_paths: candidate.editable_paths, frozen_paths: goal.scope.frozen_paths }, required_inputs: goal.scope.readable_paths,
    required_outputs: candidate.required_outputs, acceptance_criteria: acceptance({ ...goal, required_outputs: candidate.required_outputs }, []) , owner_acceptance_criteria: ownerAcceptance(goal), verification_commands: selectedTaskVerificationCommands(goal, candidate, verification),
    assigned_role: goal.execution_mode === "SINGLE_OWNER_SOL" ? "SOL_OWNER" : goal.execution_mode === "STATIC_APPROVED_DAG" ? "TERRA_EXECUTOR" : "LUNA_EXECUTOR", write_owner: candidate.task_id }) as unknown as TaskDocument;
}
function taskGraph(goal: ReturnType<typeof normalizeGoal>, tasks: readonly TaskDocument[]): TaskGraphDocument | null {
  if (goal.execution_mode !== "ROUTED_DAG" && goal.execution_mode !== "STATIC_APPROVED_DAG") return null;
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
      logical_routes: route.routes.filter((entry) => goal.execution_mode === "STATIC_APPROVED_DAG" ? entry.logical_role === "TERRA_EXECUTOR" : ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"].includes(entry.logical_role)), limits: budgetDocument.limits, stopping_conditions: [goal.stop_condition] }, approved_by: "owner-confirmation-required" }) as unknown as PlanApprovalDocument;
}
function reducer(goal: ReturnType<typeof normalizeGoal>, tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, planDocument: PlanApprovalDocument | null, budgetDocument: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest): ReducerPolicy {
  return identifyContractDocument("pi_gacw_reducer_policy_v0", { schema_id: "pi_gacw_reducer_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, execution_mode: goal.execution_mode,
    owner_acceptance_required: goal.execution_mode === "SINGLE_OWNER_SOL", limits: { max_direct_attempts: 1, max_single_owner_mutation_cycles: 1, max_attempts_per_leaf: budgetDocument.limits.max_attempts_per_leaf, max_replans: 0, max_leaves: goal.execution_mode === "ROUTED_DAG" || goal.execution_mode === "STATIC_APPROVED_DAG" ? 8 : 1, max_worker_invocations: budgetDocument.limits.max_worker_invocations },
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

/** One controller-owned snapshot is handed to approval before any worker reservation. */
function executionAuthority(input: {
  readonly goal: ReturnType<typeof normalizeGoal>;
  readonly repository: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly route: RouteMapDocument;
  readonly routeApproval: RouteMapApprovalDocument;
  readonly budget: BudgetDocument;
  readonly contract: ContractDocument;
  readonly tasks: readonly TaskDocument[];
  readonly graph: TaskGraphDocument | null;
  readonly plan: PlanApprovalDocument | null;
  readonly reducerPolicy: ReducerPolicy;
  readonly maxM4MutationCalls: number;
}): BoundedExecutionAuthority {
  const maxReplans = input.reducerPolicy.limits.max_replans;
  if (maxReplans !== 0 || (input.maxM4MutationCalls !== 1 && input.maxM4MutationCalls !== MAX_TOOL_CALLS_PER_WORKER)) {
    fail("CONTROLLER_AUTHORITY_INVALID", "bounded execution authority has an unsupported controller limit");
  }
  return Object.freeze({
    run_id: RUN_ID,
    mode: input.goal.execution_mode,
    repository: input.repository,
    baseline: input.baseline,
    baseline_approval: input.approval,
    baseline_authority_identity: canonicalBaselineAuthority(input.baseline, input.approval),
    route_map: input.route,
    route_map_approval: input.routeApproval,
    budget: input.budget,
    contract: input.contract,
    tasks: Object.freeze([...input.tasks]),
    task_graph: input.graph,
    plan: input.plan,
    reducer_policy: input.reducerPolicy,
    controller_limits: Object.freeze({ hard_m4_mutation_tool_limit: input.maxM4MutationCalls === 1 ? 1 : null, max_replans: 0 }),
  });
}

function baselineStagingPolicy(goal: ReturnType<typeof normalizeGoal>, tasks: readonly TaskDocument[], graph: TaskGraphDocument | null, budgetDocument: BudgetDocument, scopeSha: Sha256Digest, acceptanceSha: Sha256Digest): ReducerPolicy {
  return identifyContractDocument("pi_gacw_reducer_policy_v0", { schema_id: "pi_gacw_reducer_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, execution_mode: goal.execution_mode,
    owner_acceptance_required: goal.execution_mode === "SINGLE_OWNER_SOL", limits: { max_direct_attempts: 1, max_single_owner_mutation_cycles: 1, max_attempts_per_leaf: 1, max_replans: 0, max_leaves: goal.execution_mode === "ROUTED_DAG" || goal.execution_mode === "STATIC_APPROVED_DAG" ? 8 : 1, max_worker_invocations: budgetDocument.limits.max_worker_invocations },
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
  const roles = goal.execution_mode === "DIRECT_LUNA_HIGH" ? ["LUNA_EXECUTOR"] as const : goal.execution_mode === "SINGLE_OWNER_SOL" ? ["SOL_OWNER"] as const : goal.execution_mode === "STATIC_APPROVED_DAG" ? ["TERRA_EXECUTOR"] as const : ["SOL_PLANNER", "LUNA_EXECUTOR", "SOL_CLOSEOUT"] as const;
  const leaves = goal.execution_mode === "ROUTED_DAG" || goal.execution_mode === "STATIC_APPROVED_DAG" ? goal.tasks.length : 1;
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
    let argv = [command.executable, ...(command.args ?? [])];
    let executionInputs: { readonly path: string; readonly realpath: string; readonly device: number; readonly inode: number; readonly mode: number; readonly size: number; readonly digest: Sha256Digest }[] = [];
    if (isInterpreterExecutablePath(command.executable)) {
      const scriptArgument = command.args?.[0];
      if (scriptArgument === undefined) fail("INVALID_COMMAND_AUTHORITY", "interpreter verification requires one scoped script argument");
      assertM4CanonicalPath(scriptArgument, "interpreter verification script");
      const scriptPath = join(repository.worktree_root, command.cwd, scriptArgument);
      const scriptRelative = command.cwd === "." ? scriptArgument : join(command.cwd, scriptArgument);
      assertM4CanonicalPath(scriptRelative, "interpreter verification script path");
      if (!within(scriptRelative, scope.readable_paths)) fail("INVALID_COMMAND_AUTHORITY", "interpreter verification script is outside readable scope");
      const [scriptStats, scriptPhysical, scriptBytes] = await Promise.all([lstat(scriptPath), realpath(scriptPath), readFile(scriptPath)]);
      if (!scriptStats.isFile() || scriptStats.isSymbolicLink() || scriptPhysical !== scriptPath) fail("INVALID_COMMAND_AUTHORITY", "interpreter verification script is unsafe");
      argv = [command.executable, scriptPhysical, ...(command.args ?? []).slice(1)];
      executionInputs = [{ path: scriptPath, realpath: scriptPhysical, device: scriptStats.dev, inode: scriptStats.ino, mode: scriptStats.mode & 0o7777, size: scriptStats.size, digest: sha256Bytes(scriptBytes) }];
    }
    const readableCandidates = (await Promise.all(scope.readable_paths.map(async (entry) => {
      try {
        const stats = await lstat(join(repository.worktree_root, entry));
        return stats.isFile() ? { path: entry, kind: "EXACT" as const } : stats.isDirectory() ? { path: entry, kind: "PREFIX" as const } : null;
      } catch { return null; }
    }))).filter((entry): entry is { readonly path: string; readonly kind: "EXACT" | "PREFIX" } => entry !== null);
    const readable = readableCandidates.filter((entry, index) => !readableCandidates.slice(0, index).some((prior) => prior.kind === "PREFIX" && (entry.path === prior.path || entry.path.startsWith(`${prior.path}/`))));
    // Node otherwise follows the system OpenSSL configuration symlink into
    // /etc, which is intentionally outside the frozen M4 read authority.
    // /dev/null is already a mandatory sandbox path and this exact value is
    // frozen into the command specification before any worker admission.
    const environment = basename(exePhysical) === "node" ? [{ key: "OPENSSL_CONF", value: "/dev/null" }] : [];
    const projection = { command_id: command.command_id, command_class: "VERIFICATION" as const, executable_invocation_path: command.executable, executable_realpath: exePhysical, executable_device: exeStats.dev, executable_inode: exeStats.ino, executable_mode: exeStats.mode & 0o7777, executable_size: exeStats.size, executable_sha256: sha256Bytes(exeBytes), argv, cwd: command.cwd, cwd_realpath: cwdPhysical, cwd_device: cwdStats.dev, cwd_inode: cwdStats.ino,
      execution_inputs: executionInputs, environment, read_paths: readable, write_paths: [], network_policy: "FORBIDDEN" as const, timeout_ms: command.timeout_ms ?? 60_000, stdout_limit: 65_536, stderr_limit: 65_536, expected_exit_codes: [0], repository_side_effect: "NONE" as const, claimed_paths: [], cleanup_paths: [] };
    specs.push({ ...projection, command_spec_sha256: sha256Canonical(projection) });
  }
  return specs;
}
async function toolPolicy(repository: M3RepositoryIdentityDocument, token: M3RepositoryStateTokenDocument, goal: ReturnType<typeof normalizeGoal>): Promise<M4ScopedToolPolicyDocument> {
  const all = [...new Set([...goal.scope.readable_paths, ...goal.scope.editable_paths, ...goal.scope.frozen_paths])];
  const commandReadableCandidates = await Promise.all(goal.scope.readable_paths.map(async (path) => {
    try { return (await lstat(join(repository.worktree_root, path))).isDirectory() ? { path, kind: "PREFIX" as const } : { path, kind: "EXACT" as const }; }
    catch { return { path, kind: "EXACT" as const }; }
  }));
  const commandReadable = commandReadableCandidates.filter((entry, index) => !commandReadableCandidates.slice(0, index).some((prior) => prior.kind === "PREFIX" && (entry.path === prior.path || entry.path.startsWith(`${prior.path}/`))));
  const pathAuthorities = await Promise.all(all.map(async (path) => {
    let kind: "EXACT" | "PREFIX" = "EXACT";
    try { if ((await lstat(join(repository.worktree_root, path))).isDirectory()) kind = "PREFIX"; } catch { /* a prospective output remains exact */ }
    return { path, kind, ownership_class: goal.scope.editable_paths.includes(path) ? "OWNER_ACCEPTED_MUTABLE" as const : "PREEXISTING_UNRELATED" as const, data_class: "PUBLIC_SOURCE" as const, raw_read_approved: true,
      create: goal.scope.editable_paths.includes(path), replace: goal.scope.editable_paths.includes(path), delete: goal.scope.editable_paths.includes(path), mode_change: false };
  }));
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { schema_id: "pi_gacw_scoped_tool_policy_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1", run_id: RUN_ID, policy_id: "pre-m8-bounded-policy", repository_identity_content_sha256: repository.content_sha256, worktree_key: repository.worktree_key, task_scope_identity: token.task_scope_identity,
    readable_paths: commandReadable, editable_paths: goal.scope.editable_paths.map((path) => ({ path, kind: "EXACT" as const })), frozen_paths: goal.scope.frozen_paths.map((path) => ({ path, kind: "EXACT" as const })),
    command_readable_paths: commandReadable, command_writable_paths: [],
    path_authorities: pathAuthorities,
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

interface ResolvedWorkerInvocation {
  readonly result: Awaited<ReturnType<typeof runBoundedWorker>>["result"];
  readonly operationId: string;
  readonly reservationContentSha256: Sha256Digest;
}

function boundedTerminalRefusalFailure(
  execution: ResolvedWorkerInvocation,
  policy: M5ControlPolicyDocument,
): M5FailureInput {
  const result = execution.result;
  if (result.outcome !== "BLOCKED" || result.first_failure_code === null || result.first_failure_stage === null) {
    throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_AUTHORITY_INVALID", "resolved terminal refusal lacks an exact durable failure identity");
  }
  return {
    sourceLayer: "CONTROLLER",
    sourceErrorCode: result.first_failure_code,
    sourceRecordContentSha256: result.content_sha256 as Sha256Digest,
    normalizedSignature: sha256Canonical({
      protocol: "bounded-worker-terminal-refusal-v1",
      bounded_worker_result_content_sha256: result.content_sha256,
      first_failure_code: result.first_failure_code,
      first_failure_stage: result.first_failure_stage,
      operation_id: execution.operationId,
      reservation_decision_content_sha256: execution.reservationContentSha256,
    }),
    operationId: execution.operationId,
    scopeIdentity: policy.scope_sha256 as Sha256Digest,
    repositoryIdentity: policy.repository_identity_content_sha256 as Sha256Digest,
    worktreeKey: policy.worktree_key as Sha256Digest,
  };
}

type ProductiveInvocationOptions = BoundedMutationOptions & {
  /** Parent-owned root passed only across the dedicated productive process boundary. */
  readonly invocationRoot?: string;
};

/** Productive M2–M5 controller; external lifecycle ownership is deliberately outside this function. */
async function runBoundedMutationWorkflowImpl(value: unknown, options: ProductiveInvocationOptions, workerRunner: BoundedWorkerRunner): Promise<BoundedMutationRunResult> {
  let goal: ReturnType<typeof normalizeGoal>;
  try { goal = normalizeGoal(value); } catch (error: unknown) { return { outcome: "BLOCKED", reason: error instanceof Error ? error.message : "INVALID_GOAL", finalState: null }; }
  if (options.authority === undefined) return { outcome: "BLOCKED", reason: "CONTROLLER_VERIFICATION_AUTHORITY_REQUIRED", finalState: null };
  const controllerAbort = new AbortController();
  let cancellationObserved = options.signal?.aborted === true;
  const observeCancellation = (): void => { cancellationObserved = true; controllerAbort.abort(); };
  if (options.signal !== undefined) options.signal.addEventListener("abort", observeCancellation, { once: true });
  if (cancellationObserved) {
    if (options.signal !== undefined) options.signal.removeEventListener("abort", observeCancellation);
    return { outcome: "BLOCKED", reason: "BLOCKED_CANCELLED: cancellation observed before worker admission", finalState: null };
  }
  const assertNotCancelled = (stage: string): void => {
    if (controllerAbort.signal.aborted || cancellationObserved) throw new BoundedWorkflowError("CANCELLED", `cancellation observed before ${stage}`);
  };
  let ownedRoot: string | undefined; let stateRoot = ""; let temporaryRoot = ""; let createdStateRoot = false; let retainedArtifacts = false; let parentOwnedRoot = false;
  let lock: WorktreeLockHandle | undefined; let finalState: WorkflowState | null = null; let reason = "BLOCKED"; let outcome: "PASS" | "BLOCKED" = "BLOCKED"; let hygieneWarning: string | undefined; let releaseCertain = true;
  const usages: M5UsageEvidenceDocument[] = []; let publishedUsageCount = 0;
  let terminalRefusalFailure: M5FailureInput | undefined;
  let terminalBlock: ((detail: string, failures?: readonly M5FailureInput[], obligationEvidence?: readonly M5ObligationEvidenceInput[]) => Promise<void>) | undefined;
  try {
    assertNotCancelled("repository admission");
    const cwd = options.cwd ?? process.cwd(); const repository = await resolveRepositoryIdentity({ requestedPath: cwd, requireHead: true });
    assertNotCancelled("controller authority construction");
    const specs = await commandSpecs(repository, options.authority.verification_commands, goal.scope); const verification = verificationDocuments(specs);
    if (options.invocationRoot !== undefined) {
      ownedRoot = await canonicalOwnedDirectory(options.invocationRoot, "invocationRoot"); parentOwnedRoot = true; retainedArtifacts = true; createdStateRoot = true;
    } else if (options.retainedArtifactRoot !== undefined) {
      const retainedRoot = await canonicalOwnedDirectory(options.retainedArtifactRoot, "retainedArtifactRoot");
      if (physicalChild(retainedRoot, repository.worktree_root) || physicalChild(repository.worktree_root, retainedRoot)) {
        throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", "retainedArtifactRoot must not be the repository or an ancestor/descendant of it");
      }
      ownedRoot = await mkdtemp(join(retainedRoot, "pi-pre-m8-bounded-")); retainedArtifacts = true; createdStateRoot = true;
    } else {
      ownedRoot = join(tmpdir(), `pi-pre-m8-bounded-${repository.worktree_key.slice(7)}`);
      stateRoot = join(ownedRoot, "state"); createdStateRoot = await lstat(stateRoot).then(() => false, () => true);
    }
    stateRoot = join(ownedRoot, "state"); temporaryRoot = join(ownedRoot, "tools");
    await mkdir(stateRoot, { recursive: true, mode: 0o700 });
    await mkdir(join(stateRoot, "locks"), { recursive: true, mode: 0o700 });
    assertNotCancelled("lock acquisition");
    lock = await acquireWorktreeLock({ stateRoot, repository });
    if (!parentOwnedRoot && !createdStateRoot) throw new BoundedWorkflowError("STALE_OR_CONCURRENT_STATE_ROOT", "existing M3 controller state root is not resumed or replaced");
    await mkdir(temporaryRoot, { recursive: true, mode: 0o700 });
    assertNotCancelled("baseline staging");
    // M5/route TOOL_CALL remains the total accepted-M4 envelope. The optional
    // owner cap is a distinct bounded mutation-admission limit.
    const maxM4ToolCalls = MAX_TOOL_CALLS_PER_WORKER;
    const maxM4MutationCalls = controllerMutationLimit(options.authority);
    const route = routeMap(maxM4ToolCalls); const routeApprovalDocument = routeApproval(route); const staticAttemptsPerLeaf = options.authority.static_max_attempts_per_leaf ?? 1;
    const budgetDocument = budget(goal, maxM4ToolCalls, staticAttemptsPerLeaf); const tasks = goal.tasks.map((candidate, index) => taskDocument(goal, candidate, index, verification));
    const graph = taskGraph(goal, tasks); const scopeSha = m3ScopeIdentity(goal.scope.editable_paths, goal.scope.frozen_paths);
    const acceptanceSha = sha256Canonical(acceptance(goal, verification as unknown as readonly M4CommandSpecification[]));
    // The staging graph has no M4/M5/worker path. It obtains the exact M3
    // baseline authority that the final execution graph must reproduce.
    const stagedBaseline = await stageBaselineAuthority({ stateRoot: join(ownedRoot, "baseline-staging"), cwd, goal, tasks, graph, budget: budgetDocument,
      scopeSha, acceptanceSha, authority: options.authority, lock: lock!, approveBaseline: options.approveBaseline });
    assertNotCancelled("final baseline capture");
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
    assertNotCancelled("full preflight");
    const full = await runFullPreflight({ stateRoot, runId: RUN_ID, expectedRepository: baseline.repository, expectedWorktreeKey: baseline.repository.worktree_key, expectedBranch: baseline.repository.branch, expectedHead: baseline.repository.head, expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
      baseline, approval, instructionFiles: [], authorityFiles: [], requiredEnvironment: await environment(repository), taskScopeIdentity: scopeSha, allowShallow: false, allowPartialClone: false, lock });
    await commit("PASS_FULL_PREFLIGHT", 6, {}, [full.preflight]);
    assertNotCancelled("M4 gateway admission");
    const m4Policy = await toolPolicy(repository, full.acceptedState, goal); const commandCatalog = catalog(repository, m4Policy, specs);
    const gateway = await createScopedToolGateway({ stateRoot, runId: RUN_ID, repository, baseline, acceptedState: full.acceptedState, lock: lock!, instructionFiles: [], authorityFiles: [], editablePaths: goal.scope.editable_paths, frozenPaths: goal.scope.frozen_paths, taskScopeIdentity: scopeSha, toolPolicy: m4Policy, commandCatalog, temporaryRoot });
    const m5 = m5Policy(repository, initialState, reducerPolicy, contractDocument, budgetDocument, route, routeApprovalDocument, m4Policy, commandCatalog, goal);
    const approvedExecutionAuthority = executionAuthority({ goal, repository, baseline, approval, route, routeApproval: routeApprovalDocument, budget: budgetDocument,
      contract: contractDocument, tasks, graph, plan: planDocument, reducerPolicy, maxM4MutationCalls });
    let sources = sourceBundle(contractDocument, budgetDocument, route, routeApprovalDocument, m4Policy, commandCatalog, gateway.acceptedState, tasks, graph, planDocument);
    const kernel = createControlDecisionKernel({ stateRoot, runId: RUN_ID, policy: m5, reducerPolicy, runAuthority: { repositoryIdentity: repository, contract: contractDocument, routeMap: route, routeMapApproval: routeApprovalDocument }, authoritativeSources: sources, production: true });
    const expected = async () => {
      const inspection = await inspectRunStorage({ stateRoot, runId: RUN_ID });
      if (inspection.status !== "HEALTHY" || inspection.statePointer === null || inspection.workflowState === null || inspection.revision === null) throw new Error("committed controller state is unavailable");
      return { inspection, expectedRevision: inspection.revision, expectedStatePointerContentSha256: inspection.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: inspection.workflowState.content_sha256 as Sha256Digest };
    };
    const decision = async (intent: "VALIDATE_CONTRACT" | "SELECT_ROUTE" | "AUTHORIZE_WORK" | "AUTHORIZE_CONTINUATION" | "EVALUATE_TERMINAL" | "BLOCK", transitionId: string, extra: Record<string, unknown> = {}) => {
      const current = await expected(); const result = await kernel.evaluateControlDecision({ intent, expectedRevision: current.expectedRevision, expectedStatePointerContentSha256: current.expectedStatePointerContentSha256, expectedWorkflowStateContentSha256: current.expectedWorkflowStateContentSha256, transitionId, processMetadata: processMetadata(), authoritativeSources: sources, availableLogicalRoles: PRODUCT_ROLES, ...extra } as Parameters<typeof kernel.evaluateControlDecision>[0]);
      finalState = result.workflowState; return result.decision;
    };
    terminalBlock = async (detail: string, failures: readonly M5FailureInput[] = [], obligationEvidence: readonly M5ObligationEvidenceInput[] = []): Promise<void> => {
      const current = await expected(); const state = current.inspection.workflowState!;
      if (state.phase === "PASS" || state.phase === "BLOCKED") return;
      const blocked = await kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: current.expectedRevision, expectedStatePointerContentSha256: current.expectedStatePointerContentSha256,
        expectedWorkflowStateContentSha256: current.expectedWorkflowStateContentSha256, transitionId: `pre-m8-block-${sha256Canonical({ detail, state: state.content_sha256 }).slice(7, 23)}`,
        blockReason: detail.slice(0, 255), processMetadata: processMetadata(), authoritativeSources: sources, availableLogicalRoles: PRODUCT_ROLES,
        ...(failures[0]?.operationId === undefined ? {} : { operationId: failures[0].operationId }),
        usageEvidence: usages.slice(publishedUsageCount), failures, obligationEvidence });
      publishedUsageCount = usages.length;
      finalState = blocked.workflowState;
    };
    const validated = await decision("VALIDATE_CONTRACT", "pre-m8-validate"); if (validated.outcome === "BLOCK") throw new BoundedWorkflowError("M5_CONTRACT", validated.blocking_reason ?? "contract blocked");
    const selected = await decision("SELECT_ROUTE", "pre-m8-route"); if (selected.outcome === "BLOCK") throw new BoundedWorkflowError("M5_ROUTE", selected.blocking_reason ?? "route blocked");
    const approvalDigest = async (): Promise<Sha256Digest> => {
      assertNotCancelled("execution approval");
      const approved = await options.approveTasks?.({ mode: goal.execution_mode, contract: contractDocument, tasks, plan: planDocument, executionAuthority: approvedExecutionAuthority }) ?? null;
      assertNotCancelled("worker reservation");
      const expectedApproval = goal.execution_mode === "ROUTED_DAG" || goal.execution_mode === "STATIC_APPROVED_DAG" ? planDocument!.content_sha256 : contractDocument.content_sha256;
      if (approved === null || approved !== expectedApproval) throw new BoundedWorkflowError("EXECUTION_APPROVAL_MISMATCH", "exact final Contract-bound execution authority or PlanApproval was not supplied");
      return approved;
    };
    // Exact execution authority is supplied before *any* M5 worker reservation,
    // including the routed planner. The existing approved reducer event roots
    // the exact Contract or Plan evidence that this callback verified.
    await approvalDigest();
    const invoke = async (operationId: string, task: TaskDocument | null, workerPlan: PlanApprovalDocument | null, profile: "MUTATION_EXECUTOR" | "SOL_PLANNER" | "SOL_CLOSEOUT", routeRole: BoundedWorkerRoute["logicalRole"]): Promise<ResolvedWorkerInvocation> => {
      assertNotCancelled("worker reservation");
      sources = { ...sources, m3StateTokens: [gateway.acceptedState] };
      const admission = await decision("AUTHORIZE_WORK", `pre-m8-authorize-${operationId}`, { operationId, usageEvidence: usages.slice(publishedUsageCount) });
      publishedUsageCount = usages.length;
      assertNotCancelled("worker invocation");
      if (admission.outcome !== "AUTHORIZE" || admission.reservation === null) throw new BoundedWorkflowError("M5_ADMISSION", admission.blocking_reason ?? "M5 refused worker");
      const selectedRoute = route.routes.find((entry) => entry.logical_role === routeRole);
      if (selectedRoute === undefined) throw new Error("product route is absent");
      const invocationState = gateway.acceptedState;
      const readableScope = partitionProviderVisibleReadScope(task?.scope.readable_paths ?? goal.scope.readable_paths, m4Policy.path_authorities);
      const execution = await workerRunner({ stateRoot, runId: RUN_ID, operationId, reservation: admission, task, taskGraph: graph, plan: workerPlan, inputStateToken: invocationState, lock: lock!, gateway,
        route: { logicalRole: routeRole, providerId: selectedRoute.provider_id, modelId: selectedRoute.model_id, effort: selectedRoute.effort }, profile,
        systemPrompt: `Pre-M8 bounded ${profile}; use only supplied M4 tools; no retry, replan, commands, shell, filesystem, or network.`,
        userPrompt: providerVisibleTaskContract(task?.objective ?? goal.objective, readableScope, task?.scope.editable_paths ?? goal.scope.editable_paths, profile === "SOL_PLANNER" ? workerPlan : null, maxM4MutationCalls === 1 ? 1 : null),
        allowedReadPaths: readableScope.regularFilePaths, allowedEditPaths: task?.scope.editable_paths ?? [], maxM4ToolCalls, maxM4MutationCalls,
        maxModelTurns: (() => { const remaining = admission.budget.find((entry) => entry.dimension === "MODEL_TURN")?.soft_remaining; if (remaining === undefined || remaining === null) throw new BoundedWorkflowError("M5_MODEL_TURN_AUTHORITY", "M5 did not provide an enforceable model-turn admission remainder"); return remaining; })(), deadlineMs: MAX_WALL_TIME_MS, signal: controllerAbort.signal });
      const [inspection, records, m5Records] = await Promise.all([inspectRunStorage({ stateRoot, runId: RUN_ID }), readBoundedWorkerRecords({ stateRoot, runId: RUN_ID }), readM5ManagedRecords({ stateRoot, runId: RUN_ID })]);
      const persistedInvocation = records.invocations.find((entry) => entry.content_sha256 === execution.invocation.content_sha256); const persistedResult = records.results.find((entry) => entry.content_sha256 === execution.result.content_sha256);
      const reservationStates = m5Records.workflowStates.filter((entry) => entry.content_sha256 === admission.current_state_content_sha256);
      if (persistedInvocation === undefined || persistedResult === undefined || reservationStates.length !== 1) throw new BoundedWorkflowError("WORKER_RECORD_MISSING", "persisted bounded worker record or reservation state is absent");
      const reservationState = reservationStates[0]!;
      const resolved = resolveAuthoritativeBoundedExecution({ invocation: persistedInvocation, result: persistedResult, reservation: admission, reservationState, policy: m5, baseline, approval, stateToken: invocationState, task, taskGraph: graph, plan: workerPlan,
        admissionRefusals: new Map(m5Records.admissionRefusals.map((entry) => [entry.content_sha256, entry])), classifications: inspection.managedRecordClassifications });
      if (!resolved.accepted) throw new BoundedWorkflowError("WORKER_AUTHORITY", resolved.reason ?? "worker result rejected");
      if (profile === "MUTATION_EXECUTOR" && persistedResult.outcome === "COMPLETED" && !resolved.acceptedM4Evidence.length) {
        throw new BoundedWorkflowError("WORKER_NO_MUTATION_EVIDENCE", "mutation executor produced no accepted M4 evidence");
      }
      sources = { ...sources, boundedWorkerResults: [...(sources.boundedWorkerResults ?? []), persistedResult] };
      usages.push(usage(m5, admission, persistedResult, goal.execution_mode, routeRole));
      return { result: persistedResult, operationId, reservationContentSha256: admission.content_sha256 as Sha256Digest };
    };
    const terminalRefusal = { value: null as ResolvedWorkerInvocation | null };
    const closeProductiveAuthority = (execution: ResolvedWorkerInvocation): boolean => {
      if (execution.result.outcome !== "BLOCKED") return false;
      terminalRefusal.value = execution;
      terminalRefusalFailure = boundedTerminalRefusalFailure(execution, m5);
      return true;
    };
    if (goal.execution_mode === "DIRECT_LUNA_HIGH") {
      await commit("VALIDATE_DIRECT_CONTRACT", 10); await commit("REQUEST_DIRECT_APPROVAL", 11);
      await commit("APPROVE_DIRECT_TASK", 12, {}, [contractDocument, ...tasks]); await commit("PASS_DIRECT_FAST_PREFLIGHT", 13);
      const worker = await invoke("direct-worker", tasks[0]!, null, "MUTATION_EXECUTOR", "LUNA_EXECUTOR");
      if (!closeProductiveAuthority(worker)) { await commit("COMPLETE_DIRECT_ATTEMPT", 14); await commit("PASS_DIRECT_POSTFLIGHT", 15); }
    } else if (goal.execution_mode === "SINGLE_OWNER_SOL") {
      await commit("VALIDATE_SINGLE_OWNER_CONTRACT", 20); await commit("REQUEST_SINGLE_OWNER_APPROVAL", 21);
      await commit("APPROVE_SINGLE_OWNER_TASK", 22, {}, [contractDocument, ...tasks]); await commit("PASS_SINGLE_OWNER_FAST_PREFLIGHT", 23);
      const worker = await invoke("single-owner-worker", tasks[0]!, null, "MUTATION_EXECUTOR", "SOL_OWNER");
      if (!closeProductiveAuthority(worker)) { await commit("ADMIT_SINGLE_OWNER_MUTATION_CYCLE", 24); await commit("COMPLETE_SINGLE_OWNER", 25); await commit("PASS_SINGLE_OWNER_POSTFLIGHT", 26); }
    } else if (goal.execution_mode === "STATIC_APPROVED_DAG") {
      await commit("FREEZE_STATIC_DAG", 30, {}, [planDocument!, graph!, ...tasks]);
      await commit("ACTIVATE_DAG", 31);
      let staticTransitionIndex = 40;
      let staticStopped = false;
      const staticCommit = async (type: TransitionEvent["event_type"], payload: Record<string, unknown> = {}): Promise<void> => {
        await commit(type, staticTransitionIndex, payload);
        staticTransitionIndex += 1;
      };
      const staticVerification = async (task: TaskDocument) => {
        const taskSpecs = task.verification_commands.map((command) => {
          const spec = specs.find((candidate) => candidate.command_id === command.command_id);
          if (spec === undefined) throw new BoundedWorkflowError("STATIC_LEAF_VERIFICATION_AUTHORITY_MISSING", "frozen task verification command is absent from controller authority");
          return spec;
        });
        const results: Awaited<ReturnType<typeof gateway.run_verification_command>>["record"][] = [];
        const postflights: M3PostflightDocument[] = [];
        for (const spec of taskSpecs) {
          const tokenBefore = gateway.acceptedState.content_sha256 as Sha256Digest;
          let record: Awaited<ReturnType<typeof gateway.run_verification_command>>["record"] | undefined;
          try {
            record = (await gateway.run_verification_command({ commandId: spec.command_id, stateTokenContentSha256: tokenBefore })).record;
          } catch {
            const durable = await readM5ManagedRecords({ stateRoot, runId: RUN_ID });
            record = durable.commandResults.find((candidate) => candidate.command_id === spec.command_id && candidate.state_token_before === tokenBefore);
            if (record === undefined) throw new BoundedWorkflowError("STATIC_LEAF_VERIFICATION_EVIDENCE_MISSING", "failed frozen verification did not retain its command result");
          }
          const durable = await readM5ManagedRecords({ stateRoot, runId: RUN_ID });
          const persisted = durable.commandResults.find((candidate) => candidate.content_sha256 === record.content_sha256);
          const postflight = record.postflight_content_sha256 === null ? undefined : durable.postflights.find((candidate) => candidate.content_sha256 === record.postflight_content_sha256);
          if (persisted === undefined || canonicalize(persisted) !== canonicalize(record) || postflight === undefined) {
            throw new BoundedWorkflowError("STATIC_LEAF_POSTFLIGHT_EVIDENCE_MISSING", "frozen verification has no durable authoritative postflight");
          }
          results.push(record); postflights.push(postflight);
          if (record.outcome !== "PASS") break;
        }
        sources = {
          ...sources,
          m3StateTokens: [gateway.acceptedState],
          m3Postflights: [...(sources.m3Postflights ?? []), ...postflights],
          m4CommandResults: [...(sources.m4CommandResults ?? []), ...results],
        };
        return { results, postflights };
      };
      for (let index = 0; index < tasks.length && !staticStopped; index += 1) {
        await staticCommit("SELECT_READY_LEAF");
        const taskId = (await expected()).inspection.workflowState!.active_task_id;
        const task = tasks.find((candidate) => candidate.task_id === taskId);
        if (task === undefined) throw new BoundedWorkflowError("STATIC_DAG_READY_NODE_MISSING", "ready-node selection did not identify a frozen task");
        for (let attempt = 1; !staticStopped; attempt += 1) {
          const worker = await invoke(`static-leaf-${task.task_id}-attempt-${attempt}`, task, planDocument, "MUTATION_EXECUTOR", "TERRA_EXECUTOR");
          if (closeProductiveAuthority(worker)) { staticStopped = true; break; }
          await staticCommit("COMPLETE_LEAF_ATTEMPT");
          const verified = await staticVerification(task);
          const failure = verified.results.find((record) => record.outcome !== "PASS");
          await staticCommit("PASS_LEAF_POSTFLIGHT");
          if (failure === undefined) {
            await staticCommit("LEAF_VERIFICATION_PASSED");
            break;
          }
          // A completed verifier with only its frozen expected-exit assertion
          // failing is the existing LOCAL_IMPLEMENTATION_DEFECT semantic. All
          // gateway, authority, scope, and provider uncertainty retains its
          // exact lower-layer code and therefore fails closed in the reducer.
          const failureClass = failure.failure_code === "COMMAND_EXIT_CODE_UNEXPECTED" ? "LOCAL_IMPLEMENTATION_DEFECT" : failure.failure_code ?? "INTERNAL_CONTROL_ERROR";
          await staticCommit("LEAF_VERIFICATION_FAILED", { failure_class: failureClass });
          const afterFailure = (await expected()).inspection.workflowState!;
          if (afterFailure.phase !== "LEAF_RETRY_READY") { staticStopped = true; break; }
          const failureInput: M5FailureInput = {
            sourceLayer: "M4", sourceErrorCode: failureClass, sourceRecordContentSha256: failure.content_sha256 as Sha256Digest,
            normalizedSignature: sha256Canonical({ protocol: "static-leaf-verification-v1", task_id: task.task_id, failure_code: failureClass }),
            operationId: worker.operationId, scopeIdentity: m5.scope_sha256 as Sha256Digest,
            repositoryIdentity: m5.repository_identity_content_sha256 as Sha256Digest, worktreeKey: m5.worktree_key as Sha256Digest,
          };
          const continuation = await decision("AUTHORIZE_CONTINUATION", `pre-m8-static-repair-${task.task_id}-${attempt}`, {
            operationId: worker.operationId,
            progressEvidence: { claimedKind: "NEW_TEST_EVIDENCE", evidenceContentSha256: [failure.content_sha256 as Sha256Digest] },
            failures: [failureInput],
          });
          if (continuation.outcome !== "AUTHORIZE") throw new BoundedWorkflowError("STATIC_LEAF_REPAIR_NOT_AUTHORIZED", continuation.blocking_reason ?? "M5 refused frozen Terra repair");
          if ((await expected()).inspection.workflowState!.phase !== "LEAF_FAST_PREFLIGHT") throw new BoundedWorkflowError("STATIC_LEAF_REPAIR_TRANSITION_INVALID", "authorized static repair did not enter its existing fast-preflight state");
        }
      }
    } else {
      const plannerResult = await invoke("planner", null, planDocument, "SOL_PLANNER", "SOL_PLANNER");
      if (!closeProductiveAuthority(plannerResult)) {
        if (plannerResult.result.advisory_report !== `candidate_plan_sha256:${planDocument!.content_sha256}`) throw new BoundedWorkflowError("PLAN_EXPANSION_OR_IDENTITY_MISMATCH", "planner did not submit the exact static candidate plan identity");
        await commit("COMPLETE_PLAN", 30); await commit("REQUEST_PLAN_APPROVAL", 31);
        await commit("APPROVE_PLAN", 32, { plan_approval_sha256: planDocument!.plan_approval_sha256, task_graph_sha256: graph!.task_graph_sha256 }, [planDocument, graph, ...tasks]); await commit("ACTIVATE_DAG", 33);
        for (const [index, task] of tasks.entries()) {
          await commit("SELECT_READY_LEAF", 40 + index * 4);
          const worker = await invoke(`leaf-${task.task_id}`, task, planDocument, "MUTATION_EXECUTOR", "LUNA_EXECUTOR");
          if (closeProductiveAuthority(worker)) break;
          await commit("COMPLETE_LEAF_ATTEMPT", 41 + index * 4); await commit("PASS_LEAF_POSTFLIGHT", 42 + index * 4); await commit("LEAF_VERIFICATION_PASSED", 43 + index * 4);
        }
        if (terminalRefusal.value === null) {
          const closeout = await invoke("closeout", null, planDocument, "SOL_CLOSEOUT", "SOL_CLOSEOUT");
          if (!closeProductiveAuthority(closeout)) await commit("COMPLETE_CLOSEOUT", 90);
        }
      }
    }
    const commandResults = [] as Awaited<ReturnType<typeof gateway.run_verification_command>>["record"][];
    if (terminalRefusal.value !== null) {
      // A trusted productive refusal is terminal for workers and M4 mutations,
      // not for frozen controller-only verification/reconciliation.
      for (const spec of specs) {
        assertNotCancelled("refusal closeout verification admission");
        const result = await gateway.run_verification_command({ commandId: spec.command_id, stateTokenContentSha256: gateway.acceptedState.content_sha256 as Sha256Digest });
        commandResults.push(result.record);
      }
      if (commandResults.length !== specs.length || commandResults.some((entry) => entry.outcome !== "PASS")) {
        throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_VERIFICATION_FAILED", "frozen controller closeout verification did not pass");
      }
      const durable = await readM5ManagedRecords({ stateRoot, runId: RUN_ID });
      const postflights = commandResults.map((command) => {
        if (command.postflight_content_sha256 === null) throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_POSTFLIGHT_ABSENT", "controller verification has no final M3 postflight");
        const persistedCommand = durable.commandResults.find((entry) => entry.content_sha256 === command.content_sha256);
        const postflight = durable.postflights.find((entry) => entry.content_sha256 === command.postflight_content_sha256);
        if (persistedCommand === undefined || canonicalize(persistedCommand) !== canonicalize(command) || postflight === undefined) {
          throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_EVIDENCE_MISSING", "controller closeout evidence was not durably retained");
        }
        return postflight;
      });
      sources = { ...sources, m3StateTokens: [gateway.acceptedState], m3Postflights: postflights, m4CommandResults: commandResults };
      const commandObligations: M5ObligationEvidenceInput[] = commandResults.map((entry) => {
        const descriptor = m5.obligations.find((candidate) => candidate.literal === entry.command_id);
        if (descriptor === undefined) throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_COMMAND_OBLIGATION_MISSING", "frozen command obligation is absent");
        return { descriptorSha256: descriptor.descriptor_sha256 as Sha256Digest, value: entry.command_id, evidenceContentSha256: entry.content_sha256 as Sha256Digest };
      });
      const refusalCode = terminalRefusal.value.result.first_failure_code;
      if (refusalCode === null || terminalRefusalFailure === undefined || terminalBlock === undefined) throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_AUTHORITY_INVALID", "resolved refusal or terminal authority is absent");
      await terminalBlock(`WORKER_PRODUCTIVE_REFUSAL:${refusalCode}`, [terminalRefusalFailure], commandObligations);
      finalState = (await expected()).inspection.workflowState!;
      if (finalState.phase !== "BLOCKED") throw new BoundedWorkflowError("REFUSAL_CLOSEOUT_TERMINAL_INVALID", "resolved refusal did not reach durable BLOCKED terminal state");
      outcome = "BLOCKED"; reason = `WORKER_PRODUCTIVE_REFUSAL:${refusalCode}`;
    } else {
      for (const spec of specs) { assertNotCancelled("verification command admission"); const result = await gateway.run_verification_command({ commandId: spec.command_id, stateTokenContentSha256: gateway.acceptedState.content_sha256 as Sha256Digest }); commandResults.push(result.record); }
      assertNotCancelled("final postflight");
      await options.beforeFinalPostflight?.();
      assertNotCancelled("final postflight");
      const postflight = await runPostflight({ stateRoot, runId: RUN_ID, acceptedState: gateway.acceptedState, baseline, instructionFiles: [], authorityFiles: [], editablePaths: goal.scope.editable_paths, frozenPaths: goal.scope.frozen_paths, taskScopeIdentity: scopeSha, claimedWorkflowPaths: [], lock: lock! });
      if (canonicalize(postflight.postflight.workflow_owned_delta.map((entry) => entry.path).sort()) !== canonicalize(goal.required_outputs)) throw new BoundedWorkflowError("OUTPUT_DELTA_MISMATCH", "final M3 output delta does not exactly equal expected outputs");
      if (commandResults.length !== specs.length || commandResults.some((entry) => entry.outcome !== "PASS")) throw new BoundedWorkflowError("VERIFICATION_FAILED", "a required controller-owned verification command failed");
      sources = { ...sources, m3StateTokens: [postflight.acceptedState], m3Postflights: [postflight.postflight], m4CommandResults: commandResults };
      const obligations: M5ObligationEvidenceInput[] = [
        ...goal.required_outputs.map((value) => ({ descriptorSha256: m5.obligations.find((entry) => entry.literal === value)!.descriptor_sha256 as Sha256Digest, value, evidenceContentSha256: postflight.postflight.content_sha256 as Sha256Digest })),
        ...commandResults.map((entry) => ({ descriptorSha256: m5.obligations.find((candidate) => candidate.literal === entry.command_id)!.descriptor_sha256 as Sha256Digest, value: entry.command_id, evidenceContentSha256: entry.content_sha256 as Sha256Digest })),
        ...(goal.execution_mode === "SINGLE_OWNER_SOL" ? [{ descriptorSha256: m5.obligations.find((entry) => entry.literal === "ACCEPTED")!.descriptor_sha256 as Sha256Digest, value: "ACCEPTED", evidenceContentSha256: postflight.postflight.content_sha256 as Sha256Digest }] : []),
      ];
      assertNotCancelled("terminal evaluation");
      let terminal = await decision("EVALUATE_TERMINAL", "pre-m8-terminal", { usageEvidence: usages.slice(publishedUsageCount), obligationEvidence: obligations });
      publishedUsageCount = usages.length;
      const afterTerminal = (await expected()).inspection.workflowState!;
      if (afterTerminal.phase === "AWAITING_DECLARED_OWNER_ACCEPTANCE") {
        if (!(await options.approveOwnerAcceptance?.({ task: tasks[0]!, finalState: afterTerminal }) ?? false)) throw new BoundedWorkflowError("OWNER_ACCEPTANCE_REJECTED", "declared owner acceptance was not supplied");
        terminal = await decision("EVALUATE_TERMINAL", "pre-m8-owner-terminal", { obligationEvidence: obligations });
      }
      finalState = (await expected()).inspection.workflowState!;
      assertNotCancelled("outward completion");
      outcome = terminal.outcome === "PASS" && finalState!.phase === "PASS" ? "PASS" : "BLOCKED"; reason = outcome === "PASS" ? "PASS" : terminal.blocking_reason ?? "M5_TERMINAL_BLOCK";
    }
  } catch (error: unknown) {
    const cancelled = controllerAbort.signal.aborted || cancellationObserved || (error instanceof BoundedWorkflowError && error.code === "CANCELLED");
    reason = cancelled
      ? `BLOCKED_CANCELLED: ${error instanceof Error ? error.message : "controller cancellation"}`
      : error instanceof Error ? `${error instanceof BoundedWorkflowError ? error.code : "BLOCKED"}: ${error.message}` : "BLOCKED_CONTROLLER_FAILURE";
    try { await terminalBlock?.(reason, terminalRefusalFailure === undefined ? [] : [terminalRefusalFailure]); }
    catch (terminalError: unknown) { reason = `BLOCKED_TERMINALIZATION_UNCERTAIN:${reason}:${terminalError instanceof Error ? terminalError.message : String(terminalError)}`; }
    try { finalState = (await inspectRunStorage({ stateRoot, runId: RUN_ID })).workflowState; }
    catch { /* The owned temporary root is retained only if cleanup cannot be proved. */ }
    outcome = "BLOCKED";
  } finally {
    if (lock !== undefined) {
      try { await (options.releaseLock ?? releaseWorktreeLock)(lock); }
      catch (error: unknown) { releaseCertain = false; outcome = "BLOCKED"; reason = `BLOCKED_CLEANUP_UNCERTAIN:LOCK_RELEASE:${error instanceof Error ? error.message : String(error)}`; hygieneWarning = "worktree lock release could not be proved"; }
    }
    if (controllerAbort.signal.aborted || cancellationObserved) {
      outcome = "BLOCKED";
      if (!reason.startsWith("BLOCKED_CANCELLED") && !reason.startsWith("BLOCKED_TERMINALIZATION_UNCERTAIN")) {
        reason = finalState?.phase === "PASS" ? "BLOCKED_CANCELLED_AFTER_INTERNAL_PASS" : "BLOCKED_CANCELLED";
      }
    }
    if (ownedRoot !== undefined && createdStateRoot && releaseCertain && !retainedArtifacts && !parentOwnedRoot) try { await rm(ownedRoot, { recursive: true, force: true }); }
    catch (error: unknown) { hygieneWarning ??= `temporary evidence cleanup failed: ${error instanceof Error ? error.message : String(error)}`; }
    if (options.signal !== undefined) options.signal.removeEventListener("abort", observeCancellation);
  }
  return { outcome, reason, finalState, ...(retainedArtifacts && ownedRoot !== undefined ? { evidenceRoot: ownedRoot } : {}), ...(hygieneWarning === undefined ? {} : { hygieneWarning }) };
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolveValue!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolveValue = resolvePromise; });
  return { promise, resolve: resolveValue };
}

interface InvocationWorkspace {
  readonly root: string;
  readonly stateRoot: string;
  readonly retained: boolean;
}

type ProductiveChildKind = "WORKFLOW" | "FIXTURE";
export type ExternalLifecycleFixtureMode = "HANG" | "WRITE_AND_HANG" | "INTERNAL_PASS_WAIT" | "COMPLETE" | "EARLY_EXIT" | "MALFORMED_RESULT";

interface ProductiveStartMessage {
  readonly type: "START";
  readonly kind: ProductiveChildKind;
  readonly fixtureMode?: ExternalLifecycleFixtureMode;
  readonly value: unknown;
  readonly cwd: string;
  readonly authority: BoundedMutationAuthority;
  readonly invocationRoot: string;
}

function boundedDiagnosticText(value: string, maximumBytes: number): string {
  let result = ""; let bytes = 0;
  for (const character of value) {
    const size = Buffer.byteLength(character, "utf8");
    if (bytes + size > maximumBytes) break;
    result += character; bytes += size;
  }
  return result;
}

function lifecycleErrorEvidence(error: unknown): ExternalLifecycleErrorEvidence {
  const source = error instanceof Error ? error : new Error("external lifecycle error");
  return {
    errorClass: boundedDiagnosticText(source.name.length === 0 ? "Error" : source.name, 128),
    message: boundedDiagnosticText(source.message.length === 0 ? "external lifecycle error" : source.message, EXTERNAL_LIFECYCLE_ERROR_TEXT_BYTES),
  };
}

class ExternalLifecycleDiagnostics {
  private childPid: number | null = null;
  private spawnObserved = false;
  private spawnError: ExternalLifecycleErrorEvidence | null = null;
  private processError: ExternalLifecycleErrorEvidence | null = null;
  private startSendAttempted = false;
  private startSendCallback: ExternalLifecycleDiagnosticEvidence["startSendCallback"] = "NOT_ATTEMPTED";
  private startSendError: ExternalLifecycleErrorEvidence | null = null;
  private ipcMessageReceived = false;
  private firstIpcMessageKind: ExternalLifecycleDiagnosticEvidence["firstIpcMessageKind"] = null;
  private recognizedResultReceived = false;
  private malformedResultReceived = false;
  private ipcDisconnected = false;
  private exitObserved = false;
  private exitCode: number | null = null;
  private exitSignal: NodeJS.Signals | null = null;
  private closeObserved = false;
  private closeCode: number | null = null;
  private closeSignal: NodeJS.Signals | null = null;
  private stderrTail = Buffer.alloc(0);
  private stderrTailTruncated = false;

  public constructor(private readonly childExecPath: string, private readonly childCwd: string) {}

  public observe(child: ChildProcess): void {
    this.childPid = child.pid ?? null;
    child.once("spawn", () => { this.spawnObserved = true; this.childPid = child.pid ?? null; });
    child.once("error", (error: Error) => {
      const evidence = lifecycleErrorEvidence(error);
      if (this.spawnObserved) { if (!this.exitObserved) this.processError ??= evidence; }
      else this.spawnError ??= evidence;
    });
    child.once("exit", (code, signal) => { this.exitObserved = true; this.exitCode = code; this.exitSignal = signal; });
    child.once("close", (code, signal) => { this.closeObserved = true; this.closeCode = code; this.closeSignal = signal; });
    child.once("disconnect", () => { this.ipcDisconnected = true; });
    child.on("message", (message: unknown) => { this.recordIpcMessage(message); });
    child.stderr?.on("data", (chunk: Buffer) => { this.recordStderr(chunk); });
    child.stderr?.once("error", (error: Error) => { if (!this.exitObserved) this.processError ??= lifecycleErrorEvidence(error); });
  }

  public recordSpawnFailure(error: unknown): void { this.spawnError ??= lifecycleErrorEvidence(error); }

  public recordStartSendAttempt(): void {
    this.startSendAttempted = true; this.startSendCallback = "PENDING"; this.startSendError = null;
  }

  public recordStartSendCallback(error: Error | null | undefined): void {
    if (error === null || error === undefined) { this.startSendCallback = "SUCCEEDED"; return; }
    this.startSendCallback = "FAILED"; this.startSendError ??= lifecycleErrorEvidence(error);
  }

  public recordStartSendFailure(error: unknown): void {
    this.startSendCallback = "FAILED"; this.startSendError ??= lifecycleErrorEvidence(error);
  }

  public recordRecognizedResult(): void { this.recognizedResultReceived = true; }
  public recordMalformedResult(): void { this.malformedResultReceived = true; }
  public get hasRecognizedResult(): boolean { return this.recognizedResultReceived; }
  public get hasObservedExit(): boolean { return this.exitObserved; }
  public get hasObservedClose(): boolean { return this.closeObserved; }
  public get hasObservedTerminalFailure(): boolean { return this.exitObserved || this.spawnError !== null || this.processError !== null; }
  public get hasSpawnError(): boolean { return this.spawnError !== null; }

  public snapshot(): ExternalLifecycleDiagnosticEvidence {
    const decodedStderr = this.stderrTail.toString("utf8");
    const stderrTail = decodedStderr.length === 0 ? null : boundedDiagnosticText(decodedStderr, EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES);
    return {
      childPid: this.childPid, childExecPath: this.childExecPath, childCwd: this.childCwd,
      spawnObserved: this.spawnObserved, spawnError: this.spawnError, processError: this.processError,
      startSendAttempted: this.startSendAttempted, startSendCallback: this.startSendCallback, startSendError: this.startSendError,
      ipcMessageReceived: this.ipcMessageReceived, firstIpcMessageKind: this.firstIpcMessageKind,
      recognizedResultReceived: this.recognizedResultReceived, malformedResultReceived: this.malformedResultReceived, ipcDisconnected: this.ipcDisconnected,
      exitObserved: this.exitObserved, exitCode: this.exitCode, exitSignal: this.exitSignal,
      closeObserved: this.closeObserved, closeCode: this.closeCode, closeSignal: this.closeSignal,
      childExitPhase: !this.exitObserved ? "NOT_OBSERVED" : this.startSendCallback !== "SUCCEEDED" ? "BEFORE_START_ACKNOWLEDGEMENT" : this.ipcMessageReceived ? "AFTER_IPC_MESSAGE" : "AFTER_START_ACKNOWLEDGEMENT",
      stderrTail, stderrTailTruncated: this.stderrTailTruncated || Buffer.byteLength(decodedStderr, "utf8") > EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES,
    };
  }

  private recordIpcMessage(message: unknown): void {
    this.ipcMessageReceived = true;
    if (this.firstIpcMessageKind !== null) return;
    if (message !== null && typeof message === "object" && !Array.isArray(message)) {
      const type = (message as Record<string, unknown>)["type"];
      if (type === "RESULT" || type === "FIXTURE_STAGE" || type === "CALLBACK") { this.firstIpcMessageKind = type; return; }
    }
    this.firstIpcMessageKind = "UNKNOWN";
  }

  private recordStderr(chunk: Buffer): void {
    const prior = this.stderrTail;
    if (chunk.byteLength >= EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES) {
      this.stderrTail = Buffer.from(chunk.subarray(chunk.byteLength - EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES));
      this.stderrTailTruncated ||= chunk.byteLength > EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES || prior.byteLength > 0;
      return;
    }
    const retainedPriorBytes = EXTERNAL_LIFECYCLE_STDERR_TAIL_BYTES - chunk.byteLength;
    if (prior.byteLength > retainedPriorBytes) this.stderrTailTruncated = true;
    const prefix = prior.subarray(Math.max(0, prior.byteLength - retainedPriorBytes));
    this.stderrTail = Buffer.concat([prefix, chunk], prefix.byteLength + chunk.byteLength);
  }
}

function withExternalLifecycleDiagnostic(result: BoundedMutationRunResult, diagnostics: ExternalLifecycleDiagnostics | undefined): BoundedMutationRunResult {
  return diagnostics === undefined || diagnostics.hasRecognizedResult ? result : { ...result, lifecycleDiagnostic: diagnostics.snapshot() };
}

type SessionTermination =
  | { readonly settled: true; readonly forced: boolean; readonly detail: string }
  | { readonly settled: false; readonly forced: boolean; readonly detail: string };

type SessionSignal = { readonly outcome: "SENT" | "GONE" | "UNCERTAIN"; readonly detail: string };

type M3ReconciliationClassification = "UNCHANGED_CLEAN" | "KNOWN_WORKFLOW_OWNED_DELTA" | "UNEXPECTED_DRIFT" | "UNCERTAIN";

interface M2Reconciliation {
  readonly certain: boolean;
  readonly state: WorkflowState | null;
  readonly detail: string;
}

interface M3Reconciliation {
  readonly classification: M3ReconciliationClassification;
  readonly detail: string;
}

function externalProcessMetadata() {
  return { controller_instance_id: "pre-m8-external-owner", process_id: Math.max(1, process.pid), invocation_id: "pre-m8-bounded-invocation" };
}

async function waitForSessionSettlement(capability: ForceStopCapabilityRecord, timeoutMs: number): Promise<SessionTermination> {
  const deadline = Date.now() + Math.max(0, timeoutMs);
  while (true) {
    let snapshot: ReadonlyMap<number, ProcIdentity>;
    try { snapshot = await processSnapshot(); }
    catch (error: unknown) { return { settled: false, forced: false, detail: error instanceof Error ? error.message : "cannot enumerate invocation session" }; }
    const members = [...snapshot.values()].filter((candidate) => candidate.sessionId === capability.invocation_session_id);
    if (members.every((candidate) => candidate.state === "Z")) return { settled: true, forced: false, detail: "productive invocation session is settled" };
    if (Date.now() >= deadline) return { settled: false, forced: false, detail: "productive invocation session did not settle before its deadline" };
    await delay(20);
  }
}

async function verifySessionLeader(capability: ForceStopCapabilityRecord): Promise<"LIVE" | "GONE"> {
  const leader = await readProcIdentity(capability.productive_pid);
  if (leader === null || leader.state === "Z") return "GONE";
  if (!sameProcess(leader, capability.productive_pid, capability.productive_start_ticks) || leader.sessionId !== capability.invocation_session_id || leader.processGroup !== capability.productive_pid) {
    throw new ForceStopCapabilityError("productive PID/start/session identity changed before signaling");
  }
  return "LIVE";
}

async function signalInvocationSession(capability: ForceStopCapabilityRecord, signal: NodeJS.Signals): Promise<SessionSignal> {
  try { await verifySessionLeader(capability); }
  catch (error: unknown) { return { outcome: "UNCERTAIN", detail: error instanceof Error ? error.message : "productive leader identity is unavailable" }; }
  let snapshot: ReadonlyMap<number, ProcIdentity>;
  try { snapshot = await processSnapshot(); }
  catch (error: unknown) { return { outcome: "UNCERTAIN", detail: error instanceof Error ? error.message : "invocation session enumeration failed" }; }
  const members = [...snapshot.values()].filter((candidate) => candidate.sessionId === capability.invocation_session_id && candidate.state !== "Z");
  if (members.length === 0) return { outcome: "GONE", detail: "no live invocation-session member remains" };
  const groups = [...new Set(members.map((candidate) => candidate.processGroup))].sort((left, right) => left - right);
  for (const group of groups) {
    const groupMembers = [...snapshot.values()].filter((candidate) => candidate.processGroup === group && candidate.state !== "Z");
    if (groupMembers.length === 0 || groupMembers.some((candidate) => candidate.sessionId !== capability.invocation_session_id)) {
      return { outcome: "UNCERTAIN", detail: `process group ${group} is not exclusively in the invocation session` };
    }
    for (const candidate of groupMembers) {
      let current: ProcIdentity | null;
      try { current = await readProcIdentity(candidate.pid); }
      catch (firstError: unknown) {
        // A process can disappear while /proc is being read after an earlier
        // session signal. One bounded reread distinguishes that normal race
        // from a persistent inability to validate a live target.
        await delay(10);
        try { current = await readProcIdentity(candidate.pid); }
        catch (error: unknown) { return { outcome: "UNCERTAIN", detail: error instanceof Error ? `cannot revalidate ${candidate.pid}: ${error.message}` : `cannot revalidate ${candidate.pid}` }; }
        void firstError;
      }
      if (current === null || current.state === "Z") continue;
      if (!sameProcess(current, candidate.pid, candidate.startTicks) || current.sessionId !== capability.invocation_session_id || current.processGroup !== group) {
        return { outcome: "UNCERTAIN", detail: `process ${candidate.pid} changed identity/session/group before signaling` };
      }
    }
    try { process.kill(-group, signal); }
    catch (error: unknown) { if (errorCode(error) !== "ESRCH") return { outcome: "UNCERTAIN", detail: error instanceof Error ? `cannot signal process group ${group}: ${error.message}` : `cannot signal process group ${group}` }; }
  }
  return { outcome: "SENT", detail: `signaled ${groups.length} invocation process group(s)` };
}

async function terminateInvocationSession(capability: ForceStopCapabilityRecord, graceMs: number): Promise<SessionTermination> {
  const cooperative = await waitForSessionSettlement(capability, graceMs);
  if (cooperative.settled) return cooperative;
  const term = await signalInvocationSession(capability, "SIGTERM");
  if (term.outcome === "UNCERTAIN") return { settled: false, forced: false, detail: `invocation session identity could not be safely signaled: ${term.detail}` };
  const afterTerm = await waitForSessionSettlement(capability, FORCE_STOP_EXIT_WAIT_MS);
  if (afterTerm.settled) return { ...afterTerm, forced: term.outcome === "SENT" };
  const kill = await signalInvocationSession(capability, "SIGKILL");
  if (kill.outcome === "UNCERTAIN") return { settled: false, forced: true, detail: `invocation session could not be safely hard-signaled: ${kill.detail}` };
  const afterKill = await waitForSessionSettlement(capability, FORCE_STOP_EXIT_WAIT_MS);
  return afterKill.settled
    ? { ...afterKill, forced: true }
    : { settled: false, forced: true, detail: "invocation session did not prove termination" };
}

async function reconcileM2AfterProductiveDeath(capability: ForceStopCapabilityRecord): Promise<M2Reconciliation> {
  try {
    const inspection = await inspectRunStorage({ stateRoot: capability.state_root, runId: capability.run_id });
    if (inspection.workflowState === null || inspection.statePointer === null || inspection.revision === null) {
      return { certain: false, state: null, detail: "M2 has no authoritative committed state" };
    }
    if (inspection.workflowState.phase === "PASS" || inspection.workflowState.phase === "BLOCKED") {
      return { certain: inspection.status === "HEALTHY", state: inspection.workflowState, detail: inspection.workflowState.phase === "PASS" ? "internal terminal PASS is preserved" : "existing M2 BLOCKED state is preserved" };
    }
    const authority = await loadProcessCrashTerminalizationAuthority({ stateRoot: capability.state_root, runId: capability.run_id });
    const terminal = await terminalizeProcessCrash({
      stateRoot: capability.state_root,
      runId: capability.run_id,
      expectedRevision: authority.inspection.revision,
      expectedStatePointerContentSha256: authority.inspection.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: authority.inspection.workflowState.content_sha256 as Sha256Digest,
      transitionId: `pre-m8-process-crash-${randomBytes(8).toString("hex")}`,
      policy: authority.policy,
      processMetadata: externalProcessMetadata(),
      interruptionEvidence: {
        controller_instance_id: "pre-m8-bounded-controller",
        process_id: capability.productive_pid,
        invocation_id: "pre-m8-bounded-invocation",
        exit_kind: "UNEXPECTED_TERMINATION",
        detail: "The productive invocation session terminated before the external lifecycle owner published completion.",
      },
    });
    return { certain: true, state: terminal.workflowState, detail: "M2 terminalizeProcessCrash committed BLOCKED_PROCESS_CRASH" };
  } catch (error: unknown) {
    return { certain: false, state: null, detail: error instanceof Error ? error.message : "M2 process-crash reconciliation failed" };
  }
}

async function inspectM2ForCompletion(capability: ForceStopCapabilityRecord): Promise<M2Reconciliation> {
  try {
    const inspection = await inspectRunStorage({ stateRoot: capability.state_root, runId: capability.run_id });
    if (inspection.status !== "HEALTHY" || inspection.workflowState === null) return { certain: false, state: inspection.workflowState, detail: "M2 completion authority is not healthy" };
    return { certain: true, state: inspection.workflowState, detail: "M2 completion authority is healthy" };
  } catch (error: unknown) {
    return { certain: false, state: null, detail: error instanceof Error ? error.message : "M2 completion authority is unavailable" };
  }
}

async function reconcileM3AfterProductiveDeath(capability: ForceStopCapabilityRecord): Promise<M3Reconciliation> {
  let lock: WorktreeLockHandle | undefined;
  let result: M3Reconciliation = { classification: "UNCERTAIN", detail: "M3 reconciliation did not start" };
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: capability.repository_root, requireHead: true });
    if (repository.worktree_root !== capability.repository_root || repository.worktree_key !== capability.worktree_key) {
      result = { classification: "UNCERTAIN", detail: "repository/worktree identity differs from the invocation record" };
    } else {
      lock = await acquireWorktreeLock({ stateRoot: capability.state_root, repository });
      const records = await readM5ManagedRecords({ stateRoot: capability.state_root, runId: capability.run_id });
      const candidates = records.baselines.filter((baseline) => baseline.run_id === capability.run_id && baseline.repository.worktree_root === capability.repository_root && baseline.repository.worktree_key === capability.worktree_key);
      if (candidates.length !== 1) {
        result = { classification: "UNCERTAIN", detail: "M3 has no unique authoritative baseline for this invocation" };
      } else {
        const baseline = candidates[0]!;
        try { assertRepositoryMatches(baseline.repository, repository); }
        catch (error: unknown) { result = { classification: "UNEXPECTED_DRIFT", detail: error instanceof Error ? error.message : "repository identity drifted" }; }
        if (result.classification !== "UNEXPECTED_DRIFT") {
          const fingerprint = await captureGitState(repository);
          try { assertNoGitBlockers(fingerprint); }
          catch (error: unknown) { result = { classification: "UNEXPECTED_DRIFT", detail: error instanceof Error ? error.message : "repository blockers remain" }; }
          if (result.classification !== "UNEXPECTED_DRIFT") {
            if (fingerprint.content_sha256 === baseline.git_fingerprint.content_sha256) {
              result = { classification: "UNCHANGED_CLEAN", detail: "repository exactly matches the approved baseline" };
            } else {
              const tokens = records.stateTokens.filter((token) => token.run_id === capability.run_id && token.worktree_key === capability.worktree_key && token.baseline_runtime_content_sha256 === baseline.content_sha256);
              let latest: Awaited<ReturnType<typeof loadAuthoritativeToken>> | undefined;
              let latestAmbiguous = false;
              for (const token of tokens) {
                const authoritative = await loadAuthoritativeToken({ stateRoot: capability.state_root, runId: capability.run_id }, token, baseline);
                if (latest === undefined || authoritative.chainDepth > latest.chainDepth) { latest = authoritative; latestAmbiguous = false; }
                else if (authoritative.chainDepth === latest.chainDepth && authoritative.token.content_sha256 !== latest.token.content_sha256) latestAmbiguous = true;
              }
              if (latestAmbiguous) result = { classification: "UNCERTAIN", detail: "M3 latest authoritative token tip is ambiguous" };
              else if (latest !== undefined && latest.token.git_fingerprint.content_sha256 === fingerprint.content_sha256) {
                result = { classification: "KNOWN_WORKFLOW_OWNED_DELTA", detail: "repository matches the latest validated authoritative M3 state token" };
              } else result = { classification: "UNEXPECTED_DRIFT", detail: "repository differs from baseline and the latest authoritative M3 state token" };
            }
          }
        }
      }
    }
  } catch (error: unknown) {
    result = { classification: "UNCERTAIN", detail: error instanceof Error ? error.message : "M3 reconciliation failed" };
  } finally {
    if (lock !== undefined) {
      try { await releaseWorktreeLock(lock); }
      catch (error: unknown) { result = { classification: "UNCERTAIN", detail: error instanceof Error ? `M3 lock release failed: ${error.message}` : "M3 lock release failed" }; }
    }
  }
  return result;
}

function checkedChildResult(value: unknown): BoundedMutationRunResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new ForceStopCapabilityError("productive child result is malformed");
  const record = value as Record<string, unknown>;
  if ((record["outcome"] !== "PASS" && record["outcome"] !== "BLOCKED") || typeof record["reason"] !== "string" || record["reason"].length > 4_096 || !(record["finalState"] === null || (typeof record["finalState"] === "object" && !Array.isArray(record["finalState"])))) {
    throw new ForceStopCapabilityError("productive child result fields are invalid");
  }
  if (record["finalState"] !== null) assertDocumentValid("pi_gacw_state_v0", record["finalState"]);
  return {
    outcome: record["outcome"], reason: record["reason"], finalState: record["finalState"] as WorkflowState | null,
    ...(typeof record["hygieneWarning"] === "string" ? { hygieneWarning: record["hygieneWarning"] } : {}),
  };
}

class InvocationLifecycleOwner {
  private readonly completion = deferred<BoundedMutationRunResult>();
  private capability: ActiveControlCapability | null = null;
  private readonly childExitCompletion = deferred<void>();
  private readonly childCloseCompletion = deferred<void>();
  private childResult: BoundedMutationRunResult | null = null;
  private childExited = false;
  private childClosed = false;
  private server: Server | null = null;
  private finalResult: BoundedMutationRunResult | null = null;
  private cancellation: Promise<ForceStopResult> | null = null;
  private normalCompletion: Promise<void> | null = null;

  public constructor(
    private readonly workspace: InvocationWorkspace,
    private readonly record: ForceStopCapabilityRecord,
    private readonly child: ChildProcess,
    private readonly diagnostics: ExternalLifecycleDiagnostics,
    private readonly options: BoundedMutationOptions,
    private readonly kind: ProductiveChildKind,
    private readonly fixtureMode: ExternalLifecycleFixtureMode | undefined,
    private readonly onFixtureEvent: ((stage: string) => void) | undefined,
  ) {
    child.once("exit", () => { this.noteChildExit(); });
    child.once("close", () => { this.childClosed = true; this.childCloseCompletion.resolve(); });
    child.on("message", (message: unknown) => { void this.onChildMessage(message); });
    child.once("error", () => { this.noteChildExit(); });
    if (this.diagnostics.hasObservedClose) { this.childClosed = true; this.childCloseCompletion.resolve(); }
    if (this.diagnostics.hasObservedTerminalFailure) {
      this.childExited = true; this.childExitCompletion.resolve();
      queueMicrotask(() => { void this.onChildExit(); });
    }
  }

  public get result(): Promise<BoundedMutationRunResult> { return this.completion.promise; }

  public async listen(): Promise<void> {
    const server = createServer({ allowHalfOpen: true }, (socket) => { void this.handleSocket(socket); }); this.server = server;
    await new Promise<void>((resolveListen, rejectListen) => {
      server.once("error", rejectListen); server.listen(this.record.control_socket, () => { server.removeListener("error", rejectListen); resolveListen(); });
    });
    const before = await lstat(this.record.control_socket);
    const uid = currentUid();
    if (before.isSymbolicLink() || !before.isSocket() || (uid !== undefined && before.uid !== uid)) throw new ForceStopCapabilityError("control socket identity is unsafe");
    await chmod(this.record.control_socket, 0o600);
    const after = await lstat(this.record.control_socket);
    if (after.isSymbolicLink() || !after.isSocket() || after.dev !== before.dev || after.ino !== before.ino ||
        (after.mode & 0o777) !== 0o600 || (uid !== undefined && after.uid !== uid)) throw new ForceStopCapabilityError("control socket mode is unsafe");
  }

  public async publishCapability(): Promise<ActiveControlCapability> {
    if (!this.server?.listening) throw new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", "control socket is not listening");
    const capability = await publishControlCapability(this.record); this.capability = capability;
    return capability;
  }

  public async cleanupBeforeStart(): Promise<void> {
    try {
      if (this.server?.listening) await new Promise<void>((resolveClose, rejectClose) => { this.server!.close((error) => error === undefined ? resolveClose() : rejectClose(error)); });
    } catch { /* The outer lifecycle result remains fail-closed. */ }
    try { await unlink(this.record.control_socket); }
    catch (error: unknown) { if (errorCode(error) !== "ENOENT") throw error; }
  }

  private activeCapability(): ActiveControlCapability {
    if (this.capability === null) throw new ForceStopCapabilityError("control capability is unavailable");
    return this.capability;
  }

  public start(value: unknown, cwd: string, authority: BoundedMutationAuthority): void {
    const message = { type: "START", kind: this.kind, ...(this.fixtureMode === undefined ? {} : { fixtureMode: this.fixtureMode }), value, cwd, authority, invocationRoot: this.workspace.root } satisfies ProductiveStartMessage;
    this.diagnostics.recordStartSendAttempt();
    if (this.child.send === undefined) {
      const error = new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", "productive child IPC channel is unavailable");
      this.diagnostics.recordStartSendFailure(error); throw error;
    }
    try { this.child.send(message, (error) => { this.diagnostics.recordStartSendCallback(error); }); }
    catch (error: unknown) { this.diagnostics.recordStartSendFailure(error); throw error; }
  }

  public async requestCancellation(detail: string, graceMs = FORCE_STOP_GRACE_MS): Promise<ForceStopResult> {
    if (this.cancellation !== null) return this.cancellation;
    const operation = this.performCancellation(detail, graceMs); this.cancellation = operation;
    return operation;
  }

  private async handleSocket(socket: import("node:net").Socket): Promise<void> {
    let buffer = "";
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > 4_096) socket.destroy();
    });
    socket.once("end", async () => {
      let response: ForceStopResult;
      try {
        const message = JSON.parse(buffer.trim()) as unknown;
        const request = exactRecord(message, ["protocol", "operation", "grace_ms", "capability_content_sha256"], "force-stop request");
        if (request["protocol"] !== FORCE_STOP_PROTOCOL || request["operation"] !== "FORCE_STOP" || !Number.isSafeInteger(request["grace_ms"]) || (request["grace_ms"] as number) < 0 || (request["grace_ms"] as number) > 30_000 || request["capability_content_sha256"] !== sha256Canonical(this.record)) throw new ForceStopCapabilityError("force-stop request is invalid");
        response = await this.requestCancellation("external force-stop request", request["grace_ms"] as number);
      } catch (error: unknown) {
        response = { disposition: "BLOCKED_FORCE_STOP_CAPABILITY_INVALID", detail: error instanceof Error ? error.message : "force-stop request failed", retiredCapabilityPath: null };
      }
      socket.end(`${JSON.stringify(response)}\n`);
    });
  }

  private async onChildMessage(message: unknown): Promise<void> {
    if (message === null || typeof message !== "object" || Array.isArray(message)) return;
    const record = message as Record<string, unknown>;
    if (record["type"] === "RESULT") {
      try { this.childResult = checkedChildResult(record["result"]); this.diagnostics.recordRecognizedResult(); }
      catch { this.diagnostics.recordMalformedResult(); this.childResult = { outcome: "BLOCKED", reason: "BLOCKED_CHILD_RESULT_INVALID", finalState: null }; }
      return;
    }
    if (record["type"] === "FIXTURE_STAGE" && typeof record["stage"] === "string") { this.onFixtureEvent?.(record["stage"]); return; }
    if (record["type"] !== "CALLBACK" || !Number.isSafeInteger(record["id"]) || typeof record["kind"] !== "string") return;
    const id = record["id"] as number; let value: unknown = null;
    try {
      if (record["kind"] === "approveBaseline") value = await this.options.approveBaseline?.(record["payload"] as M3BaselineRuntimeDocument) ?? null;
      else if (record["kind"] === "approveTasks") value = await this.options.approveTasks?.(record["payload"] as { readonly mode: GoalMode; readonly contract: ContractDocument; readonly tasks: readonly TaskDocument[]; readonly plan: PlanApprovalDocument | null; readonly executionAuthority: BoundedExecutionAuthority }) ?? null;
      else if (record["kind"] === "approveOwnerAcceptance") value = await this.options.approveOwnerAcceptance?.(record["payload"] as { readonly task: TaskDocument; readonly finalState: WorkflowState }) ?? false;
      else if (record["kind"] === "beforeFinalPostflight") { await this.options.beforeFinalPostflight?.(); value = null; }
      else throw new ForceStopCapabilityError("productive child requested an unknown parent callback");
      this.child.send?.({ type: "CALLBACK_RESULT", id, ok: true, value });
    } catch (error: unknown) {
      this.child.send?.({ type: "CALLBACK_RESULT", id, ok: false, detail: error instanceof Error ? error.message.slice(0, 1_024) : "parent callback failed" });
    }
  }

  private noteChildExit(): void {
    this.childExited = true; this.childExitCompletion.resolve(); void this.onChildExit();
  }

  private async onChildExit(): Promise<void> {
    if (this.finalResult !== null) return;
    await delay(0);
    if (this.diagnostics.hasObservedExit) await this.waitForChildClose(FORCE_STOP_EXIT_WAIT_MS);
    if (this.cancellation !== null) { await this.cancellation; return; }
    if (this.normalCompletion === null) this.normalCompletion = this.completeNormally();
    await this.normalCompletion;
  }

  private async waitForChildClose(timeoutMs: number): Promise<boolean> {
    if (this.childClosed || this.diagnostics.hasObservedClose) return true;
    return Promise.race([this.childCloseCompletion.promise.then(() => true), delay(timeoutMs).then(() => false)]);
  }

  private async waitForChildExit(timeoutMs: number): Promise<boolean> {
    const started = Date.now();
    const exited = this.childExited || await Promise.race([this.childExitCompletion.promise.then(() => true), delay(timeoutMs).then(() => false)]);
    if (exited && this.diagnostics.hasObservedExit) await this.waitForChildClose(Math.max(0, timeoutMs - (Date.now() - started)));
    return exited;
  }

  private async performCancellation(detail: string, graceMs: number): Promise<ForceStopResult> {
    let claim;
    try { claim = await claimCompletion(this.record, "CANCELLED", detail); }
    catch (error: unknown) {
      const result = { outcome: "BLOCKED" as const, reason: `BLOCKED_LIFECYCLE_CLAIM_UNCERTAIN:${error instanceof Error ? error.message : "unknown"}`, finalState: null };
      await this.finish(result, false); return { disposition: "BLOCKED_FORCE_STOP_RECONCILIATION_UNCERTAIN", detail: result.reason, retiredCapabilityPath: null };
    }
    if (claim.claim.winner === "COMPLETED") return { disposition: "ALREADY_TERMINAL", detail: "COMPLETED won before force-stop", retiredCapabilityPath: this.activeCapability().path };
    if (!claim.won) return { disposition: "BLOCKED_CANCELLED", detail: "CANCELLED was already being resolved", retiredCapabilityPath: this.activeCapability().path };
    try { this.child.send?.({ type: "CANCEL" }); } catch { /* session termination below is the hard boundary */ }
    const terminated = await terminateInvocationSession(this.record, graceMs);
    if (!terminated.settled) {
      const result = { outcome: "BLOCKED" as const, reason: `BLOCKED_FORCE_STOP_DESCENDANT_UNCERTAIN:${terminated.detail}`, finalState: null };
      await this.finish(result, false);
      return { disposition: "BLOCKED_FORCE_STOP_DESCENDANT_UNCERTAIN", detail: terminated.detail, retiredCapabilityPath: null };
    }
    if (!await this.waitForChildExit(FORCE_STOP_EXIT_WAIT_MS)) {
      const result = { outcome: "BLOCKED" as const, reason: "BLOCKED_PROCESS_CRASH_RECONCILIATION_UNCERTAIN:productive child was not reaped", finalState: null };
      await this.finish(result, false);
      return { disposition: "BLOCKED_FORCE_STOP_RECONCILIATION_UNCERTAIN", detail: result.reason, retiredCapabilityPath: null };
    }
    const [m2, m3] = await Promise.all([reconcileM2AfterProductiveDeath(this.record), reconcileM3AfterProductiveDeath(this.record)]);
    const uncertainty = !m2.certain || m3.classification === "UNCERTAIN";
    const reason = uncertainty
      ? `BLOCKED_PROCESS_CRASH_RECONCILIATION_UNCERTAIN:M2=${m2.detail};M3=${m3.detail}`
      : `BLOCKED_CANCELLED:M2=${m2.detail};M3=${m3.classification}`;
    await this.finish({ outcome: "BLOCKED", reason, finalState: m2.state }, true);
    return uncertainty
      ? { disposition: "BLOCKED_FORCE_STOP_RECONCILIATION_UNCERTAIN", detail: reason, retiredCapabilityPath: this.activeCapability().path }
      : { disposition: terminated.forced ? "BLOCKED_FORCE_TERMINATED" : "BLOCKED_CANCELLED", detail: reason, retiredCapabilityPath: this.activeCapability().path };
  }

  private async completeNormally(): Promise<void> {
    if (this.childResult === null) { await this.requestCancellation("productive child exited without a validated result", 0); return; }
    const settled = await waitForSessionSettlement(this.record, FORCE_STOP_EXIT_WAIT_MS);
    if (!settled.settled) { await this.requestCancellation("productive child/session did not settle before completion", 0); return; }
    const [m2, m3] = await Promise.all([inspectM2ForCompletion(this.record), reconcileM3AfterProductiveDeath(this.record)]);
    if (!m2.certain || m3.classification === "UNCERTAIN") {
      let interrupted;
      try { interrupted = await claimCompletion(this.record, "CANCELLED", "completion reconciliation was uncertain"); }
      catch (error: unknown) {
        await this.finish({ outcome: "BLOCKED", reason: `BLOCKED_LIFECYCLE_CLAIM_UNCERTAIN:${error instanceof Error ? error.message : "unknown"}`, finalState: m2.state ?? this.childResult.finalState }, true); return;
      }
      if (interrupted.claim.winner === "COMPLETED") {
        await this.finish({ outcome: "BLOCKED", reason: "BLOCKED_EXTERNAL_COMPLETION_RECONCILIATION:completion claim was already held", finalState: m2.state ?? this.childResult.finalState }, true); return;
      }
      if (this.cancellation !== null) { await this.cancellation; return; }
      const reason = `${this.childResult.outcome === "BLOCKED" ? `${this.childResult.reason}; ` : ""}BLOCKED_EXTERNAL_COMPLETION_RECONCILIATION:M2=${m2.detail};M3=${m3.classification}:${m3.detail}`;
      await this.finish({ outcome: "BLOCKED", reason, finalState: m2.state ?? this.childResult.finalState }, true); return;
    }
    let claim;
    try { claim = await claimCompletion(this.record, "COMPLETED", "productive child exited, session settled, and parent reconciliation completed"); }
    catch (error: unknown) {
      await this.finish({ outcome: "BLOCKED", reason: `BLOCKED_LIFECYCLE_CLAIM_UNCERTAIN:${error instanceof Error ? error.message : "unknown"}`, finalState: m2.state ?? this.childResult.finalState }, true); return;
    }
    if (claim.claim.winner === "CANCELLED") { if (this.cancellation !== null) await this.cancellation; else await this.finish({ outcome: "BLOCKED", reason: "BLOCKED_CANCELLED", finalState: m2.state ?? this.childResult.finalState }, true); return; }
    const pass = claim.won && this.childResult.outcome === "PASS" && m2.certain && m2.state?.phase === "PASS" &&
      (m3.classification === "UNCHANGED_CLEAN" || m3.classification === "KNOWN_WORKFLOW_OWNED_DELTA");
    const reconciliation = `M2=${m2.detail};M3=${m3.classification}:${m3.detail}`;
    const reason = pass ? "PASS" : this.childResult.outcome === "BLOCKED"
      ? `${this.childResult.reason}; BLOCKED_EXTERNAL_COMPLETION_RECONCILIATION:${reconciliation}`
      : `BLOCKED_EXTERNAL_COMPLETION_RECONCILIATION:${reconciliation}`;
    await this.finish({ outcome: pass ? "PASS" : "BLOCKED", reason, finalState: m2.state ?? this.childResult.finalState }, true);
  }

  private async finish(result: BoundedMutationRunResult, sessionSettled: boolean): Promise<void> {
    if (this.finalResult !== null) return;
    // The parent, not the productive child, is authoritative for the retained
    // evidence-root path that it created and validates.
    this.finalResult = withExternalLifecycleDiagnostic(this.workspace.retained ? { ...result, evidenceRoot: this.workspace.root } : result, this.diagnostics);
    try { if (this.server?.listening) this.server.close(); }
    catch { this.finalResult = { ...this.finalResult, outcome: "BLOCKED", reason: "BLOCKED_CLEANUP_UNCERTAIN:CONTROL_SOCKET" }; }
    try { await unlink(this.record.control_socket); }
    catch (error: unknown) { if (errorCode(error) !== "ENOENT") this.finalResult = { ...this.finalResult, outcome: "BLOCKED", reason: "BLOCKED_CLEANUP_UNCERTAIN:CONTROL_SOCKET" }; }
    if (!this.workspace.retained && sessionSettled) {
      try { await rm(this.workspace.root, { recursive: true, force: true }); }
      catch (error: unknown) { this.finalResult = { ...this.finalResult, outcome: "BLOCKED", reason: `BLOCKED_CLEANUP_UNCERTAIN:INVOCATION_ROOT:${error instanceof Error ? error.message : "unknown"}` }; }
    }
    this.completion.resolve(this.finalResult);
  }
}

async function createInvocationWorkspace(options: BoundedMutationOptions, repository: M3RepositoryIdentityDocument): Promise<InvocationWorkspace> {
  let root: string; let retained = false;
  if (options.retainedArtifactRoot !== undefined) {
    const parent = await canonicalOwnedDirectory(options.retainedArtifactRoot, "retainedArtifactRoot");
    if (physicalChild(parent, repository.worktree_root) || physicalChild(repository.worktree_root, parent)) throw new BoundedWorkflowError("RETAINED_ARTIFACT_ROOT_INVALID", "retainedArtifactRoot must not overlap the repository");
    root = await mkdtemp(join(parent, "pi-pre-m8-bounded-")); retained = true;
  } else root = await mkdtemp(join(tmpdir(), "pi-pre-m8-bounded-"));
  await chmod(root, 0o700); const stateRoot = join(root, "state");
  await mkdir(join(stateRoot, "locks"), { recursive: true, mode: 0o700 });
  return { root, stateRoot, retained };
}

async function waitForChildIdentity(child: ChildProcess, diagnostics: ExternalLifecycleDiagnostics): Promise<ProcIdentity> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.pid !== undefined) {
      const identity = await readProcIdentity(child.pid);
      if (identity !== null) return identity;
    }
    if (diagnostics.hasSpawnError) throw new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", "productive child PID is unavailable");
    await delay(10);
  }
  throw new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", child.pid === undefined ? "productive child PID is unavailable" : "productive child /proc identity is unavailable");
}

async function runExternalLifecycleOwner(
  value: unknown,
  options: BoundedMutationOptions,
  kind: ProductiveChildKind,
  fixtureMode?: ExternalLifecycleFixtureMode,
  onFixtureEvent?: (stage: string) => void,
): Promise<BoundedMutationRunResult> {
  let normalized: ReturnType<typeof normalizeGoal>;
  try { normalized = normalizeGoal(value); }
  catch (error: unknown) { return { outcome: "BLOCKED", reason: error instanceof Error ? error.message : "INVALID_GOAL", finalState: null }; }
  void normalized;
  if (options.authority === undefined) return { outcome: "BLOCKED", reason: "CONTROLLER_VERIFICATION_AUTHORITY_REQUIRED", finalState: null };
  if (options.signal?.aborted === true) return { outcome: "BLOCKED", reason: "BLOCKED_CANCELLED: cancellation observed before productive child creation", finalState: null };
  let workspace: InvocationWorkspace | undefined; let child: ChildProcess | undefined; let owner: InvocationLifecycleOwner | undefined; let diagnostics: ExternalLifecycleDiagnostics | undefined;
  try {
    const cwd = options.cwd ?? process.cwd(); const repository = await resolveRepositoryIdentity({ requestedPath: cwd, requireHead: true });
    diagnostics = new ExternalLifecycleDiagnostics(process.execPath, cwd);
    workspace = await createInvocationWorkspace(options, repository);
    assertLinuxControlSocketPathBudget(join(workspace.root, "control.sock"));
    const parent = await readProcIdentity(process.pid);
    if (parent === null) throw new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", "external parent /proc identity is unavailable");
    const childExecArgv: string[] = [];
    for (let index = 0; index < process.execArgv.length; index += 1) {
      const entry = process.execArgv[index]!;
      if (entry === "--test" || entry.startsWith("--test-")) continue;
      // A tsx -e host carries its original program in execArgv. Replaying it
      // would recursively invoke this lifecycle parent instead of the child.
      if (entry === "--eval" || entry === "-e") { index += 1; continue; }
      if (entry.startsWith("--eval=")) continue;
      // --input-type is valid only for string input, never the child file entrypoint.
      if (entry === "--input-type") { index += 1; continue; }
      if (entry.startsWith("--input-type=")) continue;
      // tsx resolves this relative operator-local configuration after the child changes cwd.
      if (entry === "--tsconfig") { index += 1; continue; }
      // Resolve the required tsx bootstrap before the productive child changes cwd.
      if (entry === "--import" && process.execArgv[index + 1] === "tsx") { childExecArgv.push(entry, import.meta.resolve("tsx")); index += 1; continue; }
      childExecArgv.push(entry);
    }
    try {
      child = spawn(process.execPath, [...childExecArgv, fileURLToPath(import.meta.url), "--pi-workflow-productive-child"], {
        cwd, detached: true, stdio: ["ignore", "ignore", "pipe", "ipc"], env: { ...process.env },
      });
    } catch (error: unknown) { diagnostics.recordSpawnFailure(error); throw error; }
    diagnostics.observe(child);
    const productive = await waitForChildIdentity(child, diagnostics);
    if (productive.sessionId !== productive.pid || productive.processGroup !== productive.pid) throw new BoundedWorkflowError("CONTROL_CAPABILITY_UNAVAILABLE", "productive child did not enter a dedicated invocation session");
    const record: ForceStopCapabilityRecord = {
      protocol: FORCE_STOP_PROTOCOL, version: FORCE_STOP_VERSION, nonce: randomBytes(32).toString("hex"),
      parent_pid: parent.pid, parent_start_ticks: parent.startTicks, productive_pid: productive.pid, productive_start_ticks: productive.startTicks,
      invocation_session_id: productive.sessionId, control_root: workspace.root, control_socket: join(workspace.root, "control.sock"), state_root: workspace.stateRoot,
      run_id: RUN_ID, repository_root: repository.worktree_root, worktree_key: repository.worktree_key, created_at: new Date().toISOString(),
    };
    owner = new InvocationLifecycleOwner(workspace, record, child, diagnostics, options, kind, fixtureMode, onFixtureEvent);
    await owner.listen();
    const capability = await owner.publishCapability();
    const cancel = (): void => { void owner!.requestCancellation("caller cancellation", FORCE_STOP_GRACE_MS); };
    options.signal?.addEventListener("abort", cancel, { once: true });
    try {
      await options.onControlCapability?.({ path: capability.path, runId: record.run_id, repositoryRoot: record.repository_root, worktreeKey: record.worktree_key });
      owner.start(value, cwd, options.authority);
      return await owner.result;
    } catch (error: unknown) {
      await owner.requestCancellation(`parent startup failure:${error instanceof Error ? error.message : "unknown"}`, 0);
      return await owner.result;
    } finally { options.signal?.removeEventListener("abort", cancel); }
  } catch (error: unknown) {
    await owner?.cleanupBeforeStart().catch(() => undefined);
    try { child?.kill("SIGKILL"); } catch { /* child never became a valid invocation session */ }
    if (child !== undefined) await Promise.race([new Promise<void>((resolveClose) => child!.once("close", () => resolveClose())), delay(FORCE_STOP_EXIT_WAIT_MS)]);
    // No START was sent on this path, so no retained lifecycle authority may
    // remain for a failed preflight, bind, readiness, or publication attempt.
    if (workspace !== undefined) await rm(workspace.root, { recursive: true, force: true }).catch(() => undefined);
    return withExternalLifecycleDiagnostic({ outcome: "BLOCKED", reason: error instanceof Error ? `${error instanceof BoundedWorkflowError ? error.code : "BLOCKED"}: ${error.message}` : "BLOCKED_EXTERNAL_LIFECYCLE_START", finalState: null }, diagnostics);
  }
}

/** Production entrypoint: parent owns external lifecycle while the child owns M2–M5 work. */
export async function runBoundedMutationWorkflow(value: unknown, options: BoundedMutationOptions = {}): Promise<BoundedMutationRunResult> {
  return runExternalLifecycleOwner(value, options, "WORKFLOW");
}

/** Package-internal test-only entrypoint; existing faux-runtime tests stay in-process. */
export async function runBoundedMutationWorkflowForTests(value: unknown, options: BoundedMutationOptions = {}): Promise<BoundedMutationRunResult> {
  return runBoundedMutationWorkflowImpl(value, options, runBoundedWorkerForTests);
}

/** Test-only lifecycle fixture; it exercises the same parent/session boundary without a provider. */
export async function runBoundedMutationWorkflowExternalForTests(
  value: unknown,
  options: BoundedMutationOptions = {},
  mode: ExternalLifecycleFixtureMode = "HANG",
  onFixtureEvent?: (stage: string) => void,
): Promise<BoundedMutationRunResult> {
  return runExternalLifecycleOwner(value, options, "FIXTURE", mode, onFixtureEvent);
}

function childMessageRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is malformed`);
  return value as Record<string, unknown>;
}

async function sendChildResult(result: BoundedMutationRunResult): Promise<void> {
  if (typeof process.send !== "function") return;
  await new Promise<void>((resolveSend) => {
    try { process.send!({ type: "RESULT", result }, () => resolveSend()); }
    catch { resolveSend(); }
  });
}

async function productiveChildMain(): Promise<void> {
  const start = await new Promise<ProductiveStartMessage>((resolveStart, rejectStart) => {
    const timer = setTimeout(() => rejectStart(new Error("parent did not start productive child")), FORCE_STOP_REQUEST_TIMEOUT_MS); timer.unref();
    process.once("message", (message: unknown) => {
      try {
        const record = childMessageRecord(message, "productive start");
        if (record["type"] !== "START" || (record["kind"] !== "WORKFLOW" && record["kind"] !== "FIXTURE") || typeof record["cwd"] !== "string" || !validAbsolutePath(record["cwd"]) ||
            record["authority"] === null || typeof record["authority"] !== "object" || Array.isArray(record["authority"]) || typeof record["invocationRoot"] !== "string" || !validAbsolutePath(record["invocationRoot"])) throw new Error("productive start is invalid");
        clearTimeout(timer); resolveStart(record as unknown as ProductiveStartMessage);
      } catch (error: unknown) { clearTimeout(timer); rejectStart(error); }
    });
  });
  const abort = new AbortController(); const pending = new Map<number, { readonly resolve: (value: unknown) => void; readonly reject: (error: Error) => void }>(); let nextCallback = 1;
  const requestParent = async (kind: string, payload: unknown): Promise<unknown> => new Promise<unknown>((resolveRequest, rejectRequest) => {
    const id = nextCallback++; pending.set(id, { resolve: resolveRequest, reject: rejectRequest }); process.send?.({ type: "CALLBACK", id, kind, payload });
  });
  process.on("message", (message: unknown) => {
    if (message === null || typeof message !== "object" || Array.isArray(message)) return;
    const record = message as Record<string, unknown>;
    if (record["type"] === "CANCEL") { abort.abort(); return; }
    if (record["type"] !== "CALLBACK_RESULT" || !Number.isSafeInteger(record["id"])) return;
    const callback = pending.get(record["id"] as number); if (callback === undefined) return; pending.delete(record["id"] as number);
    if (record["ok"] === true) callback.resolve(record["value"]); else callback.reject(new Error(typeof record["detail"] === "string" ? record["detail"] : "parent callback failed"));
  });
  const callbacks: ProductiveInvocationOptions = {
    cwd: start.cwd, authority: start.authority, invocationRoot: start.invocationRoot, signal: abort.signal,
    approveBaseline: async (baseline) => await requestParent("approveBaseline", baseline) as BaselineApprovalRequest | null,
    approveTasks: async (input) => await requestParent("approveTasks", input) as Sha256Digest | null,
    approveOwnerAcceptance: async (input) => await requestParent("approveOwnerAcceptance", input) as boolean,
    beforeFinalPostflight: async () => { await requestParent("beforeFinalPostflight", null); },
  };
  let result: BoundedMutationRunResult;
  try {
    if (start.kind === "FIXTURE") {
      const mode = start.fixtureMode;
      if (mode !== "HANG" && mode !== "WRITE_AND_HANG" && mode !== "INTERNAL_PASS_WAIT" && mode !== "COMPLETE" && mode !== "EARLY_EXIT" && mode !== "MALFORMED_RESULT") throw new Error("fixture mode is invalid");
      if (mode === "COMPLETE") process.send?.({ type: "FIXTURE_STAGE", stage: "START_RECEIVED" });
      if (mode === "EARLY_EXIT") {
        await new Promise<void>((resolveWrite) => { process.stderr.write("fixture early exit\n", () => resolveWrite()); });
        await delay(25); process.exitCode = 23; return;
      }
      if (mode === "MALFORMED_RESULT") {
        if (typeof process.send === "function") await new Promise<void>((resolveSend) => {
          try { process.send!({ type: "RESULT", result: { outcome: "MALFORMED" } }, () => resolveSend()); }
          catch { resolveSend(); }
        });
        await delay(25); process.exitCode = 24; return;
      }
      configureBoundedWorkerFauxRuntimeForTests(() => ({
        async execute(input) {
          if (input.profile === "MUTATION_EXECUTOR") {
            if (mode !== "HANG") {
              await input.tools.writePath({ path: "out.txt", operation: "CREATE", replacementBytes: Buffer.from("fixture output\n"), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
              input.tools.submitReport("fixture");
            }
            if (mode === "HANG" || mode === "WRITE_AND_HANG") {
              process.send?.({ type: "FIXTURE_STAGE", stage: mode }); const wait = new Int32Array(new SharedArrayBuffer(4)); Atomics.wait(wait, 0, 0, 60_000);
            }
          }
          return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
        },
      }));
      result = await runBoundedMutationWorkflowImpl(start.value, callbacks, runBoundedWorkerForTests);
      configureBoundedWorkerFauxRuntimeForTests(undefined);
      if (mode === "INTERNAL_PASS_WAIT" && result.finalState?.phase === "PASS") {
        process.send?.({ type: "FIXTURE_STAGE", stage: "INTERNAL_PASS" }); const wait = new Int32Array(new SharedArrayBuffer(4)); Atomics.wait(wait, 0, 0, 60_000);
      }
    } else result = await runBoundedMutationWorkflowImpl(start.value, callbacks, runBoundedWorker);
    await sendChildResult(result);
  } catch (error: unknown) {
    await sendChildResult({ outcome: "BLOCKED", reason: error instanceof Error ? `BLOCKED_CHILD_FAILURE:${error.message}` : "BLOCKED_CHILD_FAILURE", finalState: null });
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined); process.disconnect?.();
  }
}

if (process.argv.at(-1) === "--pi-workflow-productive-child") {
  productiveChildMain().catch(async (error: unknown) => {
    await sendChildResult({ outcome: "BLOCKED", reason: error instanceof Error ? `BLOCKED_CHILD_START:${error.message}` : "BLOCKED_CHILD_START", finalState: null }); process.exitCode = 3;
  });
}
