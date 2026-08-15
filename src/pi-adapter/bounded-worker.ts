import { performance } from "node:perf_hooks";

import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE } from "../persistence/bounded-worker-authority.js";
import { publishBoundedWorkerRecord } from "../persistence/store.js";
import type { WorktreeLockHandle } from "../repository/index.js";
import { lockAcquisitionAuthority } from "../repository/lock.js";
import { runBoundedPiAgent } from "./worker.js";
import { publishBoundedWorkerM4AdmissionRefusal } from "../scoped-tools/tool-records.js";
import type { ScopedToolGateway } from "../scoped-tools/types.js";
import {
  identifyContractDocument,
  type BoundedWorkerInvocationDocument,
  type BoundedWorkerResultDocument,
  type M3RepositoryStateTokenDocument,
  type M5ControlDecisionDocument,
  type PlanApprovalDocument,
  type TaskDocument,
  type TaskGraphDocument,
} from "../schemas/index.js";

export type BoundedWorkerToolProfile = "MUTATION_EXECUTOR" | "SOL_PLANNER" | "SOL_CLOSEOUT";
type M4AdmissionRefusalCode = "M4_TOOL_BUDGET_EXHAUSTED" | "OUT_OF_SCOPE_WRITE";

const MAX_FIRST_FAILURE_MESSAGE_LENGTH = 512;
const MAX_SCOPED_READ_LENGTH = 65_536;

/** Retain only a compact, log-safe M6 diagnostic; never retain an Error object or stack. */
function boundedFailureMessage(message: string | undefined): string | undefined {
  if (message === undefined) return undefined;
  const utf8 = Buffer.from(message.slice(0, MAX_FIRST_FAILURE_MESSAGE_LENGTH * 4), "utf8").toString("utf8");
  const normalized = utf8.replace(/[\u0000-\u001F\u007F-\u009F\u2028\u2029]/gu, " ").replace(/\s+/gu, " ").trim();
  const bounded = [...normalized].slice(0, MAX_FIRST_FAILURE_MESSAGE_LENGTH).join("");
  return bounded.length === 0 ? undefined : bounded;
}

export interface BoundedWorkerRoute {
  readonly logicalRole: "LUNA_EXECUTOR" | "TERRA_EXECUTOR" | "SOL_OWNER" | "SOL_PLANNER" | "SOL_CLOSEOUT";
  readonly providerId: string;
  readonly modelId: string;
  readonly effort: "high" | "max";
}

export interface BoundedWorkerTools {
  /** Trusted metadata is internal to this adapter; provider-visible reads remain text-only. */
  readonly readPath: (path: string, offset?: number, length?: number) => Promise<{
    readonly content: string | null;
    readonly resultContentSha256: Sha256Digest;
    readonly metadata: { readonly digest: Sha256Digest; readonly size: number; readonly mode: number };
  }>;
  readonly writePath: (input: {
    readonly path: string;
    readonly operation: "CREATE" | "REPLACE" | "DELETE";
    readonly replacementBytes: Uint8Array | null;
    readonly expectedPreimageExists: boolean;
    readonly expectedPreimageDigest?: Sha256Digest | null;
    readonly expectedPreimageSize?: number | null;
    readonly expectedPreimageMode?: number | null;
  }) => Promise<Sha256Digest>;
  readonly readEvidence: (kind: string, contentSha256: Sha256Digest) => Promise<Sha256Digest>;
  readonly submitReport: (report: string) => void;
}

/** A narrow seam for deterministic tests and the accepted Pi runtime adapter. */
export interface BoundedWorkerRuntime {
  execute(input: {
    readonly route: BoundedWorkerRoute;
    readonly profile: BoundedWorkerToolProfile;
    readonly systemPrompt: string;
    readonly userPrompt: string;
    readonly tools: BoundedWorkerTools;
    readonly maxModelTurns: number;
    readonly deadlineMs: number;
    /** Controller-owned cancellation reaches runtime and every profiled tool. */
    readonly signal?: AbortSignal;
  }): Promise<{
    readonly completed: boolean;
    readonly firstFailureCode?: string;
    readonly firstFailureStage?: string;
    readonly firstFailureMessage?: string;
    readonly modelTurns?: number | null;
    readonly providerRequests?: number | null;
    readonly inputTokens?: number | null;
    readonly outputTokens?: number | null;
    readonly costMicrousd?: number | null;
    readonly cleanupCertain: boolean;
  }>;
}

export interface RunBoundedWorkerInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly operationId: string;
  readonly reservation: M5ControlDecisionDocument;
  readonly task: TaskDocument | null;
  readonly taskGraph: TaskGraphDocument | null;
  readonly plan: PlanApprovalDocument | null;
  readonly inputStateToken: M3RepositoryStateTokenDocument;
  readonly lock: WorktreeLockHandle;
  readonly gateway: ScopedToolGateway;
  readonly route: BoundedWorkerRoute;
  readonly profile: BoundedWorkerToolProfile;
  readonly systemPrompt: string;
  readonly userPrompt: string;
  readonly allowedReadPaths: readonly string[];
  readonly allowedEditPaths: readonly string[];
  /** Total accepted M4 evidence cap; reads and accepted mutations both count. */
  readonly maxM4ToolCalls: number;
  /** Accepted mutation-admission cap; reads and evidence reads never count. */
  readonly maxM4MutationCalls: number;
  readonly maxModelTurns: number;
  readonly deadlineMs: number;
  /** Controller-owned signal; callers cannot replace it from worker prose. */
  readonly signal?: AbortSignal;
  readonly now?: () => string;
}

export interface BoundedWorkerExecutionResult {
  readonly invocation: BoundedWorkerInvocationDocument;
  readonly result: BoundedWorkerResultDocument;
}

function dateNow(input: RunBoundedWorkerInput): string { return (input.now ?? (() => new Date().toISOString()))(); }
function canonicalPathAllowed(path: string, values: readonly string[]): boolean { return values.includes(path); }
function failure(error: unknown): { readonly code: string; readonly stage: string } {
  const code = error !== null && typeof error === "object" && "code" in error ? String((error as { readonly code: unknown }).code) : "RUNTIME_FAILURE";
  const stage = error !== null && typeof error === "object" && "stage" in error ? String((error as { readonly stage: unknown }).stage) : "BOUNDED_WORKER";
  return { code: code.slice(0, 128) || "RUNTIME_FAILURE", stage: stage.slice(0, 128) || "BOUNDED_WORKER" };
}
function abortError(stage: string): Error {
  return Object.assign(new Error("Worker cancellation blocks productive admission"), { code: "WORKER_ABORTED", stage });
}
function untrustedRuntimeFailure(error: unknown): { readonly code: string; readonly stage: string } {
  const captured = failure(error);
  return captured.stage === BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE ? { ...captured, stage: "BOUNDED_WORKER" } : captured;
}

/** A producer-owned M4 admission seam, not a runtime/model failure claim. */
class M4ToolAdmissionRefusalError extends Error {
  public readonly stage = BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE;
  public constructor(public readonly code: string, message: string) { super(message); }
}
function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true; }

function toolResult(text: string, terminate = false): { readonly content: readonly Record<string, unknown>[]; readonly details: Record<string, unknown>; readonly terminate?: boolean } {
  return { content: [{ type: "text", text }], details: {}, ...(terminate ? { terminate: true } : {}) };
}
function toolParams(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw Object.assign(new Error("tool parameters must be an object"), { code: "TOOL_REQUEST_INVALID" });
  return value as Record<string, unknown>;
}
function stringParam(value: Record<string, unknown>, key: string): string {
  const result = value[key];
  if (typeof result !== "string" || result.length === 0) throw Object.assign(new Error(`tool parameter ${key} is invalid`), { code: "TOOL_REQUEST_INVALID" });
  return result;
}
function boundedIntegerParam(value: Record<string, unknown>, key: string, minimum: number, maximum: number, fallback: number): number {
  const result = value[key];
  if (result === undefined) return fallback;
  if (typeof result !== "number" || !Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw Object.assign(new Error(`tool parameter ${key} is invalid`), { code: "TOOL_REQUEST_INVALID" });
  }
  return result;
}
function boundedReadRange(offset: number, length: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1 || length > MAX_SCOPED_READ_LENGTH) {
    throw Object.assign(new Error("bounded read range is invalid"), { code: "TOOL_REQUEST_INVALID" });
  }
}

/** The production default is the accepted guarded Pi runtime, not a provider shim. */
const acceptedPiRuntime: BoundedWorkerRuntime = Object.freeze({
  async execute(input: Parameters<BoundedWorkerRuntime["execute"]>[0]) {
    const rejectCancelledToolAdmission = (): void => {
      if (cancelled(input.signal)) throw abortError("PRE_TOOL_ADMISSION");
    };
    const readTool = {
      name: "read_scoped", label: "Scoped read", description: "Read one bounded TEXT window from an allowed repository regular file through M4. path must be one canonical repository-relative regular-file path within the frozen allowed read scope; offset defaults to 0 and must be a non-negative integer; length defaults to 65536 and must be an integer from 1 through 65536. No mode or metadata arguments are accepted.",
      parameters: { type: "object", additionalProperties: false, required: ["path"], properties: {
        path: { type: "string" }, offset: { type: "integer", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }, length: { type: "integer", minimum: 1, maximum: MAX_SCOPED_READ_LENGTH },
      } },
      async execute(_id: string, params: unknown) {
        rejectCancelledToolAdmission();
        const value = toolParams(params);
        const result = await input.tools.readPath(
          stringParam(value, "path"),
          boundedIntegerParam(value, "offset", 0, Number.MAX_SAFE_INTEGER, 0),
          boundedIntegerParam(value, "length", 1, MAX_SCOPED_READ_LENGTH, MAX_SCOPED_READ_LENGTH),
        );
        return toolResult(result.content ?? "");
      },
    };
    const patchTool = {
      name: "apply_patch_scoped", label: "Scoped patch", description: "Apply exact bytes to one allowed path through M4. For REPLACE, replacement bytes must produce an observable content change from the current regular-file contents; identical bytes are not a successful productive mutation because they cannot satisfy repository-delta postflight. Trusted CAS preimage digest, size, and mode are controller-acquired; do not supply CAS metadata.",
      parameters: { type: "object", additionalProperties: false, required: ["path", "operation", "replacement_base64", "expected_preimage_exists"], properties: {
        path: { type: "string" }, operation: { type: "string", enum: ["CREATE", "REPLACE", "DELETE"] }, replacement_base64: { type: ["string", "null"] }, expected_preimage_exists: { type: "boolean" },
      } },
      async execute(_id: string, params: unknown) {
        rejectCancelledToolAdmission();
        const value = toolParams(params); const operation = stringParam(value, "operation");
        if (operation !== "CREATE" && operation !== "REPLACE" && operation !== "DELETE") throw Object.assign(new Error("patch operation is invalid"), { code: "TOOL_REQUEST_INVALID" });
        const exists = value["expected_preimage_exists"]; if (typeof exists !== "boolean") throw Object.assign(new Error("preimage existence is invalid"), { code: "TOOL_REQUEST_INVALID" });
        const content = value["replacement_base64"]; const replacementBytes = content === null ? null : typeof content === "string" ? Buffer.from(content, "base64") : (() => { throw Object.assign(new Error("replacement bytes are invalid"), { code: "TOOL_REQUEST_INVALID" }); })();
        await input.tools.writePath({ path: stringParam(value, "path"), operation, replacementBytes, expectedPreimageExists: exists });
        return toolResult("applied");
      },
    };
    const evidenceTool = {
      name: "read_authoritative_evidence", label: "Authoritative evidence read", description: "Read only an allowed durable evidence record through M4.",
      parameters: { type: "object", additionalProperties: false, required: ["kind", "content_sha256"], properties: { kind: { type: "string" }, content_sha256: { type: "string" } } },
      async execute(_id: string, params: unknown) { rejectCancelledToolAdmission(); const value = toolParams(params); await input.tools.readEvidence(stringParam(value, "kind"), stringParam(value, "content_sha256") as Sha256Digest); return toolResult("evidence read"); },
    };
    const submitName = input.profile === "SOL_PLANNER" ? "submit_candidate_plan_report" : input.profile === "SOL_CLOSEOUT" ? "submit_closeout_report" : "submit_worker_report";
    const submitTool = {
      name: submitName, label: "Bounded report", description: "Submit one bounded advisory report and end this worker.",
      parameters: { type: "object", additionalProperties: false, required: ["report"], properties: { report: { type: "string", maxLength: 8192 } } },
      async execute(_id: string, params: unknown) { rejectCancelledToolAdmission(); const value = toolParams(params); input.tools.submitReport(stringParam(value, "report")); return toolResult("accepted", true); },
    };
    const tools = input.profile === "MUTATION_EXECUTOR" ? [readTool, patchTool, submitTool] : input.profile === "SOL_PLANNER" ? [readTool, submitTool] : [evidenceTool, submitTool];
    if (cancelled(input.signal)) return { completed: false, firstFailureCode: "WORKER_ABORTED", firstFailureStage: "PRE_PROVIDER_ADMISSION", modelTurns: 0, providerRequests: 0, inputTokens: null, outputTokens: null, costMicrousd: null, cleanupCertain: true };
    // The Pi adapter owns Agent cleanup. Scoped closures below remain the hard
    // cancellation gate for every productive tool admission.
    return runBoundedPiAgent({ providerId: input.route.providerId, modelId: input.route.modelId, effort: input.route.effort, systemPrompt: input.systemPrompt, userPrompt: input.userPrompt,
      tools, maxModelTurns: input.maxModelTurns, deadlineMs: input.deadlineMs,
      ...(input.signal === undefined ? {} : { signal: input.signal }) });
  },
});

export type BoundedWorkerFauxRuntimeFactory = (route: BoundedWorkerRoute) => BoundedWorkerRuntime | undefined;

const fauxRuntimeProvenance = new WeakMap<object, BoundedWorkerFauxRuntimeFactory>();
let activeFauxRuntimeAuthority: object | undefined;

/** Package-internal test-only registration; production never reads this provenance. */
export function configureBoundedWorkerFauxRuntimeForTests(factory?: BoundedWorkerFauxRuntimeFactory): void {
  activeFauxRuntimeAuthority = undefined;
  if (factory === undefined) return;
  const authority = Object.freeze(Object.create(null)) as object;
  fauxRuntimeProvenance.set(authority, factory);
  activeFauxRuntimeAuthority = authority;
}

/**
 * Persist-before-provider bounded worker. Its runtime receives only selected
 * route facts and the narrowly profiled M4 closures; it never receives a shell,
 * filesystem handle, command registry, credential, or controller authority.
 */
async function runBoundedWorkerImpl(input: RunBoundedWorkerInput, runtime: BoundedWorkerRuntime): Promise<BoundedWorkerExecutionResult> {
  if (cancelled(input.signal)) throw abortError("PRE_WORKER_ADMISSION");
  if (input.reservation.outcome !== "AUTHORIZE" || input.reservation.reservation === null || input.reservation.operation_id !== input.operationId ||
      input.reservation.reservation.logical_role !== input.route.logicalRole || input.reservation.reservation.reservation_decision_key === undefined) {
    throw new Error("Bounded worker requires an exact active M5 reservation");
  }
  const createdAt = dateNow(input);
  const invocation = identifyContractDocument("pi_gacw_bounded_worker_invocation_v0", {
    schema_id: "pi_gacw_bounded_worker_invocation_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    invocation_key: sha256Canonical({ run: input.runId, operation: input.operationId, reservation: input.reservation.content_sha256 }),
    run_id: input.runId,
    operation_id: input.operationId,
    m5_reservation_decision_content_sha256: input.reservation.content_sha256,
    m5_reservation_decision_key: input.reservation.reservation.reservation_decision_key,
    task_content_sha256: input.task?.content_sha256 ?? null,
    task_graph_sha256: input.taskGraph?.content_sha256 ?? null,
    plan_approval_sha256: input.plan?.content_sha256 ?? null,
    input_m3_state_token_content_sha256: input.inputStateToken.content_sha256,
    system_prompt_sha256: sha256Bytes(Buffer.from(input.systemPrompt, "utf8")),
    user_prompt_sha256: sha256Bytes(Buffer.from(input.userPrompt, "utf8")),
    created_at: createdAt,
  }) as BoundedWorkerInvocationDocument;
  await publishBoundedWorkerRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "BOUNDED_WORKER_INVOCATION", document: invocation });

  const m3Evidence = new Set<Sha256Digest>();
  const m4Evidence = new Set<Sha256Digest>();
  let acceptedM4ToolCalls = 0;
  let acceptedMutationAdmissions = 0;
  let advisoryReport: string | null = null;
  let terminalRefusal: { readonly code: string; readonly stage: typeof BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE } | null = null;
  /** Accepted mutation receipts are the sole current-path authority retained by this worker. */
  const trustedCurrentPathMetadata = new Map<string, {
    readonly stateTokenContentSha256: Sha256Digest;
    readonly digest: Sha256Digest;
    readonly size: number;
    readonly mode: number;
  }>();
  let productiveAuthorityClosed = false;
  const start = performance.now();
  const assertProductiveAuthorityOpen = (): void => {
    if (productiveAuthorityClosed) throw Object.assign(new Error("trusted terminal refusal already closed productive authority"), { code: "PRODUCTIVE_AUTHORITY_CLOSED", stage: "PRODUCTIVE_AUTHORITY" });
  };
  const addM4Evidence = (identity: Sha256Digest, accepted: boolean): void => {
    if (m4Evidence.has(identity)) throw Object.assign(new Error("one M4 operation reused an evidence identity"), { code: "M4_EVIDENCE_DUPLICATE" });
    m4Evidence.add(identity);
    if (accepted) acceptedM4ToolCalls += 1;
  };
  const requireAcceptedM4ToolBudget = (): void => {
    assertProductiveAuthorityOpen();
    if (cancelled(input.signal)) throw abortError("PRE_TOOL_ADMISSION");
    if (acceptedM4ToolCalls >= input.maxM4ToolCalls) {
      throw Object.assign(new Error("accepted M4 tool-call budget exhausted before non-mutation admission"), { code: "M4_TOOL_BUDGET_EXHAUSTED", stage: "BOUNDED_WORKER" });
    }
    if (performance.now() - start > input.deadlineMs) throw Object.assign(new Error("bounded worker deadline exceeded"), { code: "WORKER_DEADLINE_EXCEEDED" });
  };
  const refusalAttemptedMutation = (request: Parameters<BoundedWorkerTools["writePath"]>[0]) => {
    const trusted = trustedCurrentPathMetadata.get(request.path);
    const currentTrustedPath = request.operation !== "CREATE" && request.expectedPreimageExists === true &&
      trusted?.stateTokenContentSha256 === input.gateway.acceptedState.content_sha256 ? trusted : undefined;
    return {
      ...request,
      // Early admission happens before normal F-01 normalization. For a
      // same-path non-CREATE retry, only an accepted mutation receipt bound to
      // the current successor state can complete omitted provider CAS facts.
      // Otherwise preserve fail-closed nulls; never invent or newly read facts.
      expectedPreimageDigest: request.expectedPreimageDigest === undefined ? currentTrustedPath?.digest ?? null : request.expectedPreimageDigest,
      expectedPreimageSize: request.expectedPreimageSize === undefined ? currentTrustedPath?.size ?? null : request.expectedPreimageSize,
      expectedPreimageMode: request.expectedPreimageMode === undefined ? currentTrustedPath?.mode ?? null : request.expectedPreimageMode,
    };
  };
  const refuseMutationAdmission = async (
    request: Parameters<BoundedWorkerTools["writePath"]>[0],
    code: M4AdmissionRefusalCode,
    message: string,
  ): Promise<never> => {
    // Close first: even an adversarial runtime issuing concurrent tool calls
    // cannot produce a second durable refusal while this one is publishing.
    productiveAuthorityClosed = true;
    const refusal = await publishBoundedWorkerM4AdmissionRefusal({ stateRoot: input.stateRoot, runId: input.runId }, {
      boundedWorkerInvocationContentSha256: invocation.content_sha256 as Sha256Digest,
      admissionStateTokenContentSha256: input.gateway.acceptedState.content_sha256 as Sha256Digest,
      attemptedMutation: refusalAttemptedMutation(request),
      refusalCode: code,
    });
    addM4Evidence(refusal.content_sha256 as Sha256Digest, false);
    terminalRefusal = { code, stage: BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE };
    throw new M4ToolAdmissionRefusalError(code, message);
  };
  const tools: BoundedWorkerTools = {
    async readPath(path, offset = 0, length = MAX_SCOPED_READ_LENGTH) {
      assertProductiveAuthorityOpen();
      boundedReadRange(offset, length);
      if (!canonicalPathAllowed(path, input.allowedReadPaths)) throw Object.assign(new Error("path is outside task read scope"), { code: "OUT_OF_SCOPE_READ" });
      if (input.profile === "SOL_CLOSEOUT") throw Object.assign(new Error("closeout can read evidence only"), { code: "PROFILE_TOOL_DENIED" });
      requireAcceptedM4ToolBudget();
      const result = await input.gateway.read_scoped({ stateTokenContentSha256: input.gateway.acceptedState.content_sha256 as Sha256Digest, path, offset, length, mode: "TEXT" });
      addM4Evidence(result.resultRecord.content_sha256 as Sha256Digest, true);
      return {
        content: result.content,
        resultContentSha256: result.resultRecord.content_sha256 as Sha256Digest,
        metadata: { digest: result.metadata.digest as Sha256Digest, size: result.metadata.size, mode: result.metadata.mode },
      };
    },
    async writePath(request) {
      assertProductiveAuthorityOpen();
      if (input.profile !== "MUTATION_EXECUTOR") throw Object.assign(new Error("worker profile cannot mutate"), { code: "PROFILE_TOOL_DENIED" });
      if (cancelled(input.signal)) throw abortError("PRE_TOOL_ADMISSION");
      if (!canonicalPathAllowed(request.path, input.allowedEditPaths)) await refuseMutationAdmission(request, "OUT_OF_SCOPE_WRITE", "path is outside task edit scope");
      if (acceptedMutationAdmissions >= input.maxM4MutationCalls) await refuseMutationAdmission(request, "M4_TOOL_BUDGET_EXHAUSTED", "M4 mutation-admission budget exhausted");
      if (acceptedM4ToolCalls >= input.maxM4ToolCalls) await refuseMutationAdmission(request, "M4_TOOL_BUDGET_EXHAUSTED", "accepted M4 tool-call budget exhausted");
      if (performance.now() - start > input.deadlineMs) throw Object.assign(new Error("bounded worker deadline exceeded"), { code: "WORKER_DEADLINE_EXCEEDED" });
      const needsPreimage = request.operation !== "CREATE" && request.expectedPreimageExists === true &&
        (request.expectedPreimageDigest === undefined || request.expectedPreimageSize === undefined || request.expectedPreimageMode === undefined);
      const preimage = needsPreimage ? await tools.readPath(request.path) : undefined;
      const expectedPreimageDigest = request.expectedPreimageDigest === undefined ? preimage?.metadata.digest ?? null : request.expectedPreimageDigest;
      const expectedPreimageSize = request.expectedPreimageSize === undefined ? preimage?.metadata.size ?? null : request.expectedPreimageSize;
      const expectedPreimageMode = request.expectedPreimageMode === undefined ? preimage?.metadata.mode ?? null : request.expectedPreimageMode;
      const normalizedRequest = { ...request, expectedPreimageDigest, expectedPreimageSize, expectedPreimageMode };
      if (acceptedM4ToolCalls >= input.maxM4ToolCalls) await refuseMutationAdmission(normalizedRequest, "M4_TOOL_BUDGET_EXHAUSTED", "accepted M4 tool-call budget exhausted");
      const result = await input.gateway.apply_patch_scoped({
        stateTokenContentSha256: input.gateway.acceptedState.content_sha256 as Sha256Digest,
        lockAcquisitionContentSha256: lockAcquisitionAuthority(input.lock).content_sha256 as Sha256Digest,
        operation: normalizedRequest.operation,
        path: normalizedRequest.path,
        ownershipClass: "OWNER_ACCEPTED_MUTABLE",
        dataClass: "PUBLIC_SOURCE",
        expectedPreimageExists: normalizedRequest.expectedPreimageExists,
        expectedPreimageDigest: normalizedRequest.expectedPreimageDigest,
        expectedPreimageSize: normalizedRequest.expectedPreimageSize,
        expectedPreimageMode: normalizedRequest.expectedPreimageMode,
        replacementBytes: normalizedRequest.replacementBytes,
        requestedFinalMode: normalizedRequest.operation === "DELETE" ? null : 0o644,
      });
      addM4Evidence(result.receipt.content_sha256 as Sha256Digest, true);
      acceptedMutationAdmissions += 1;
      m3Evidence.add(result.acceptedState.content_sha256 as Sha256Digest);
      const after = result.receipt.after;
      if (result.receipt.outcome === "APPLIED" && result.receipt.successor_state_token_content_sha256 === result.acceptedState.content_sha256 &&
          after.digest !== null && after.size !== null && after.mode !== null) {
        trustedCurrentPathMetadata.set(normalizedRequest.path, {
          stateTokenContentSha256: result.acceptedState.content_sha256 as Sha256Digest,
          digest: after.digest as Sha256Digest,
          size: after.size,
          mode: after.mode,
        });
      } else trustedCurrentPathMetadata.delete(normalizedRequest.path);
      return result.receipt.content_sha256 as Sha256Digest;
    },
    async readEvidence(kind, contentSha256) {
      assertProductiveAuthorityOpen();
      if (input.profile !== "SOL_CLOSEOUT") throw Object.assign(new Error("worker profile cannot read evidence"), { code: "PROFILE_TOOL_DENIED" });
      requireAcceptedM4ToolBudget();
      const result = await input.gateway.read_evidence({ stateTokenContentSha256: input.gateway.acceptedState.content_sha256 as Sha256Digest, kind, contentSha256 });
      addM4Evidence(result.resultRecord.content_sha256 as Sha256Digest, true);
      return result.resultRecord.content_sha256 as Sha256Digest;
    },
    submitReport(report) {
      assertProductiveAuthorityOpen();
      if (cancelled(input.signal)) throw abortError("REPORT_ADMISSION");
      if (report.length > 8_192) throw Object.assign(new Error("advisory report exceeds bound"), { code: "REPORT_TOO_LARGE" });
      advisoryReport = report;
    },
  };

  let report: Awaited<ReturnType<BoundedWorkerRuntime["execute"]>> | undefined;
  let first: { readonly code: string; readonly stage: string; readonly message?: string } | null = null;
  try {
    if (cancelled(input.signal)) throw abortError("PRE_PROVIDER_ADMISSION");
    report = await runtime.execute({
      route: input.route, profile: input.profile, systemPrompt: input.systemPrompt, userPrompt: input.userPrompt, tools,
      maxModelTurns: input.maxModelTurns, deadlineMs: input.deadlineMs,
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
    if (cancelled(input.signal)) first = { code: "WORKER_ABORTED", stage: "POST_RUNTIME" };
    else if (terminalRefusal !== null) first = terminalRefusal;
    else if (!report.completed) {
      const reported = {
        code: report.firstFailureCode ?? "WORKER_BLOCKED",
        stage: report.firstFailureStage ?? "BOUNDED_WORKER",
        ...(report.firstFailureMessage === undefined ? {} : { message: report.firstFailureMessage }),
      };
      first = reported.stage === BOUNDED_WORKER_TRUSTED_REFUSAL_STAGE ? { ...reported, stage: "BOUNDED_WORKER" } : reported;
    }
  } catch (error: unknown) {
    if (error instanceof M4ToolAdmissionRefusalError && terminalRefusal !== null) first = terminalRefusal;
    else first = untrustedRuntimeFailure(error);
  }
  const cleanupCertain = report?.cleanupCertain === true;
  const completed = first === null && report?.completed === true && cleanupCertain;
  if (!completed && first === null) first = { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP" };
  const firstFailureMessage = boundedFailureMessage(first?.message);
  const result = identifyContractDocument("pi_gacw_bounded_worker_result_v0", {
    schema_id: "pi_gacw_bounded_worker_result_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    invocation_content_sha256: invocation.content_sha256,
    outcome: completed ? "COMPLETED" : "BLOCKED",
    first_failure_code: first?.code ?? null,
    first_failure_stage: first?.stage ?? null,
    ...(firstFailureMessage === undefined ? {} : { first_failure_message: firstFailureMessage }),
    m3_evidence_content_sha256: [...m3Evidence].sort(),
    m4_evidence_content_sha256: [...m4Evidence].sort(),
    actual_usage: {
      worker_invocations: 1,
      m4_tool_calls: acceptedM4ToolCalls,
      model_turns: report?.modelTurns ?? null,
      provider_requests: report?.providerRequests ?? null,
      input_tokens: report?.inputTokens ?? null,
      output_tokens: report?.outputTokens ?? null,
      cost_microusd: report?.costMicrousd ?? null,
      wall_time_ms: Math.max(0, Math.ceil(performance.now() - start)),
    },
    cleanup_certain: cleanupCertain,
    advisory_report: advisoryReport,
    completed_at: dateNow(input),
  }) as BoundedWorkerResultDocument;
  await publishBoundedWorkerRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "BOUNDED_WORKER_RESULT", document: result });
  return { invocation, result };
}

/** Production entrypoint: the verified official Pi runtime is not caller-replaceable. */
export async function runBoundedWorker(input: RunBoundedWorkerInput): Promise<BoundedWorkerExecutionResult> {
  return runBoundedWorkerImpl(input, acceptedPiRuntime);
}

/** Package-internal test-only entrypoint; provenance must be registered first. */
export async function runBoundedWorkerForTests(input: RunBoundedWorkerInput): Promise<BoundedWorkerExecutionResult> {
  const authority = activeFauxRuntimeAuthority;
  const factory = authority === undefined ? undefined : fauxRuntimeProvenance.get(authority);
  if (factory === undefined) throw Object.assign(new Error("No registered test-only bounded runtime provenance is active"), { code: "TEST_RUNTIME_PROVENANCE_REQUIRED" });
  const runtime = factory(input.route);
  if (runtime === undefined) throw Object.assign(new Error("Test-only bounded runtime provenance does not bind the selected route"), { code: "TEST_RUNTIME_ROUTE_MISMATCH" });
  return runBoundedWorkerImpl(input, runtime);
}
