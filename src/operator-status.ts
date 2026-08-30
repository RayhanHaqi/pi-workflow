import { readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import {
  readPersistedStaticProviderTelemetry,
  type BoundedProviderTelemetrySummary,
} from "./workflow-controller.js";
import {
  inspectDeterministicResumeEligibility,
  type ResumeEligibilityReport,
} from "./resume-inspection.js";
import { inspectRunStorage } from "./persistence/index.js";
import { readM5ManagedRecords } from "./persistence/store.js";
import {
  resolveApplicableResumeTiming,
  staticTimingVerdicts,
} from "./persistence/static-time-authority.js";
import { sampleWallClockMs } from "./wall-clock.js";
import { M5_BUDGET_DIMENSIONS } from "./schemas/definitions.js";
import type { M5ControlDecisionDocument, WorkflowState } from "./schemas/index.js";
import type {
  InspectionIssue,
  RunStorageInspection,
  RunStorageInspectionStatus,
} from "./persistence/types.js";
import type { Sha256Digest } from "./identity/index.js";

type M5ManagedRecords = Awaited<ReturnType<typeof readM5ManagedRecords>>;

export type OperatorStatusClassification = "PASS" | "VALID_BLOCKED" | "IN_PROGRESS" | "INCOMPLETE" | "INVALID";
export type OperatorInputKind = "BASELINE_APPROVAL" | "DIRECT_APPROVAL" | "SINGLE_OWNER_APPROVAL" | "PLAN_APPROVAL" | "OWNER_ACCEPTANCE";
export type OperatorNoticeKind = "AUTHORITY_INPUT_REQUIRED" | "UNRECOVERABLE_BLOCK" | "BUDGET_EXHAUSTED" | "TIME_EXHAUSTED" | "COMPLETION";
export type OperatorTimeScope = "WORKFLOW" | "NODE" | "WORKER";
export type OperatorBudgetDimension = (typeof M5_BUDGET_DIMENSIONS)[number];
export type OperatorBudgetSnapshot = Readonly<M5ControlDecisionDocument["budget"][number]>;

export interface OperatorNotice {
  readonly kind: OperatorNoticeKind;
  readonly message: string;
  readonly level: "info" | "warning";
}

export interface OperatorStatusReport {
  readonly classification: OperatorStatusClassification;
  readonly retained_run_root: string;
  readonly run_id: string | null;
  readonly storage_status: RunStorageInspectionStatus | "UNAVAILABLE";
  readonly revision: number | null;
  readonly state_pointer_content_sha256: Sha256Digest | null;
  readonly workflow_state_content_sha256: Sha256Digest | null;
  readonly transition_commit_content_sha256: Sha256Digest | null;
  readonly phase: WorkflowState["phase"] | null;
  readonly terminal_classification: "PASS" | "VALID_BLOCKED" | null;
  readonly terminal_reason: string | null;
  readonly terminal: boolean | null;
  readonly workflow: OperatorWorkflowSummary | null;
  readonly operator_input: Readonly<{ readonly required: boolean | null; readonly kind: OperatorInputKind | null }>;
  readonly budget: Readonly<{
    readonly exhausted: boolean | null;
    readonly exhausted_dimensions: readonly OperatorBudgetDimension[] | null;
    readonly snapshot: readonly OperatorBudgetSnapshot[] | null;
  }>;
  readonly time: Readonly<{
    readonly exhausted: boolean | null;
    readonly scopes: readonly OperatorTimeScope[] | null;
  }>;
  readonly completion: Readonly<{ readonly completed: boolean | null; readonly outcome: "PASS" | "BLOCKED" | null }>;
  readonly resumability: ResumeEligibilityReport | null;
  readonly telemetry: BoundedProviderTelemetrySummary | null;
  readonly notice: OperatorNotice | null;
  readonly issues: readonly InspectionIssue[];
}

export interface OperatorWorkflowSummary {
  readonly active_task_id: string | null;
  readonly baseline_approval_required: boolean | null;
  readonly owner_acceptance_required: boolean;
  readonly route_frozen: boolean;
  readonly replan_in_progress: boolean;
  readonly counters: WorkflowState["counters"];
  readonly gates: WorkflowState["gates"];
  readonly tasks: readonly WorkflowState["tasks"][number][];
}

interface OperatorStatusSignals {
  readonly operatorInputKind: OperatorInputKind | null;
  readonly budgetExhausted: boolean | null;
  readonly timeExhausted: boolean | null;
}

const AWAITING_INPUT_PHASES: Readonly<Record<string, OperatorInputKind>> = Object.freeze({
  AWAITING_BASELINE_APPROVAL: "BASELINE_APPROVAL",
  AWAITING_DIRECT_APPROVAL: "DIRECT_APPROVAL",
  AWAITING_SINGLE_OWNER_APPROVAL: "SINGLE_OWNER_APPROVAL",
  AWAITING_PLAN_APPROVAL: "PLAN_APPROVAL",
  AWAITING_DECLARED_OWNER_ACCEPTANCE: "OWNER_ACCEPTANCE",
});

const EMPTY_OPERATOR_INPUT = Object.freeze({ required: null, kind: null });
const EMPTY_BUDGET = Object.freeze({ exhausted: null, exhausted_dimensions: null, snapshot: null });
const EMPTY_TIME = Object.freeze({ exhausted: null, scopes: null });
const EMPTY_COMPLETION = Object.freeze({ completed: null, outcome: null });

function bounded(value: string | null | undefined): string {
  return (value ?? "").slice(0, 4096);
}

function issue(code: string, detail: string, relativePath = "."): InspectionIssue {
  return Object.freeze({ code, relativePath, detail: bounded(detail) });
}

function validRoot(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && !value.includes("\u0000") && isAbsolute(value) && resolve(value) === value;
}

function inputKindForPhase(phase: string | null | undefined): OperatorInputKind | null {
  return phase === undefined || phase === null ? null : AWAITING_INPUT_PHASES[phase] ?? null;
}

export function operatorInputKindForPhase(phase: string | null | undefined): OperatorInputKind | null {
  return inputKindForPhase(phase);
}

function isBudgetReason(value: string): boolean {
  return /(?:BUDGET|CAP_EXCEEDED|ATTEMPT_CAP_EXCEEDED|MUTATION_CYCLE_CAP_EXCEEDED|INVOCATION_CAP_EXCEEDED)/u.test(value);
}

function timeScopeForReason(value: string): OperatorTimeScope | null {
  if (/STATIC_NODE_WALL_DEADLINE_EXCEEDED|frozen node wall deadline|node wall deadline/u.test(value)) return "NODE";
  if (/WORKER_DEADLINE_EXCEEDED|worker deadline/u.test(value)) return "WORKER";
  if (/STATIC_WORKFLOW_WALL_DEADLINE_EXCEEDED|WALL_TIME|workflow wall deadline|workflow deadline|deadline/u.test(value)) return "WORKFLOW";
  return null;
}


export interface OperatorNoticeInput {
  readonly phase: string | null;
  readonly outcome?: "PASS" | "BLOCKED" | null;
  readonly terminal_reason?: string | null;
  readonly reason?: string | null;
  readonly operator_input_kind?: OperatorInputKind | null;
  readonly budget_exhausted?: boolean | null;
  readonly time_exhausted?: boolean | null;
}

/** Pure semantic projection. It never reads or writes authority and emits nothing for ordinary progress. */
export function classifyOperatorNotice(input: OperatorNoticeInput): OperatorNotice | null {
  const operatorInputKind = input.operator_input_kind ?? inputKindForPhase(input.phase);
  const reason = bounded(input.terminal_reason ?? input.reason);
  if (input.outcome !== "BLOCKED" && input.phase === "PASS") return Object.freeze({ kind: "COMPLETION", message: "workflow completed successfully", level: "info" });
  if (operatorInputKind !== null) return Object.freeze({ kind: "AUTHORITY_INPUT_REQUIRED", message: `operator input required: ${operatorInputKind}`, level: "info" });
  if (input.time_exhausted === true || timeScopeForReason(reason) !== null) {
    return Object.freeze({ kind: "TIME_EXHAUSTED", message: reason.length === 0 ? "workflow time budget exhausted" : `workflow time budget exhausted: ${reason}`, level: "warning" });
  }
  if (input.budget_exhausted === true || isBudgetReason(reason)) {
    return Object.freeze({ kind: "BUDGET_EXHAUSTED", message: reason.length === 0 ? "workflow budget exhausted" : `workflow budget exhausted: ${reason}`, level: "warning" });
  }
  if (input.phase === "BLOCKED" || input.outcome === "BLOCKED") {
    return Object.freeze({ kind: "UNRECOVERABLE_BLOCK", message: reason.length === 0 ? "workflow blocked" : `workflow blocked: ${reason}`, level: "warning" });
  }
  return null;
}

function workflowSummary(state: WorkflowState): OperatorWorkflowSummary {
  const counters = Object.freeze({
    ...state.counters,
    worker_invocations: Object.freeze({ ...state.counters.worker_invocations }),
  });
  const gates = Object.freeze({ ...state.gates });
  const tasks = Object.freeze(state.tasks.map((task) => Object.freeze({ ...task })));
  return Object.freeze({
    active_task_id: state.active_task_id,
    baseline_approval_required: state.baseline_approval_required,
    owner_acceptance_required: state.owner_acceptance_required,
    route_frozen: state.route_frozen,
    replan_in_progress: state.replan_in_progress,
    counters,
    gates,
    tasks,
  });
}

function authoritative(inspection: RunStorageInspection, kind: string, digest: string): boolean {
  const matches = inspection.managedRecordClassifications.filter((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest);
  return matches.length === 1 && matches[0]!.classification === "AUTHORITATIVE_MANAGED_RECORD";
}

function currentDecision(
  inspection: RunStorageInspection,
  records: M5ManagedRecords,
  state: WorkflowState,
): M5ControlDecisionDocument | null {
  const candidates = records.decisions.filter((decision) =>
    decision.run_id === state.run_id && decision.predicted_next_state_content_sha256 === state.content_sha256 &&
    authoritative(inspection, "M5_CONTROL_DECISION", decision.content_sha256),
  );
  return candidates.length === 1 ? candidates[0]! : null;
}

function budgetProjection(decision: M5ControlDecisionDocument | null, texts: string[]): OperatorStatusReport["budget"] {
  const snapshot = decision === null ? null : Object.freeze(decision.budget.map((entry) => Object.freeze({ ...entry })));
  const exhaustedDimensions = snapshot === null
    ? null
    : Object.freeze(snapshot.filter((entry) => entry.status === "HARD_LIMIT_REACHED" || entry.status === "SOFT_LIMIT_REACHED").map((entry) => entry.dimension).sort());
  const nonTimeExhausted = exhaustedDimensions?.some((dimension) => dimension !== "WALL_TIME_MS") === true;
  const exhausted = decision === null
    ? (texts.some(isBudgetReason) ? true : null)
    : (texts.some(isBudgetReason) || nonTimeExhausted);
  return Object.freeze({ exhausted, exhausted_dimensions: exhaustedDimensions, snapshot });
}

function timeProjection(
  inspection: RunStorageInspection,
  records: M5ManagedRecords | null,
  decision: M5ControlDecisionDocument | null,
  state: WorkflowState,
  texts: readonly string[],
): OperatorStatusReport["time"] {
  const scopes = new Set<OperatorTimeScope>();
  for (const text of texts) {
    const scope = timeScopeForReason(text);
    if (scope !== null) scopes.add(scope);
  }
  const terminal = state.phase === "PASS" || state.phase === "BLOCKED";
  let timingKnown = terminal;
  if (!terminal && decision?.budget.some((entry) => entry.dimension === "WALL_TIME_MS" && (entry.status === "HARD_LIMIT_REACHED" || entry.status === "SOFT_LIMIT_REACHED"))) {
    scopes.add("WORKFLOW");
  }
  if (!terminal && state.execution_mode === "STATIC_APPROVED_DAG" && records !== null && inspection.transitionCommit !== null) {
    try {
      const timing = resolveApplicableResumeTiming({
        runId: state.run_id,
        state,
        tipCommit: inspection.transitionCommit,
        records: {
          transitionCommits: records.transitionCommits,
          workflowStates: records.workflowStates,
          transitionEvents: records.transitionEvents,
          authorities: records.staticTimeAuthorities,
        },
        verdicts: staticTimingVerdicts(inspection.managedRecordClassifications),
        nowMs: sampleWallClockMs(),
      });
      if (timing.outcome === "OK") timingKnown = true;
      else {
        const scope = timeScopeForReason(timing.detail);
        if (scope !== null) scopes.add(scope);
      }
    } catch {
      // A timing authority that cannot be resolved is unavailable, not exhausted.
    }
  }
  if (decision !== null && state.execution_mode !== "STATIC_APPROVED_DAG" && scopes.size === 0 && !texts.some((text) => timeScopeForReason(text) !== null)) timingKnown = true;
  if (scopes.size === 0 && !timingKnown) return EMPTY_TIME;
  const orderedScopes = Object.freeze([...scopes].sort());
  return Object.freeze({ exhausted: scopes.size > 0, scopes: orderedScopes });
}

function terminalClassification(state: WorkflowState): "PASS" | "VALID_BLOCKED" | null {
  return state.phase === "PASS" ? "PASS" : state.phase === "BLOCKED" ? "VALID_BLOCKED" : null;
}

function incompleteReport(
  retainedRunRoot: string,
  runId: string | null,
  storageStatus: RunStorageInspectionStatus | "UNAVAILABLE",
  issues: readonly InspectionIssue[],
  classification: "INCOMPLETE" | "INVALID",
): OperatorStatusReport {
  return Object.freeze({
    classification,
    retained_run_root: retainedRunRoot,
    run_id: runId,
    storage_status: storageStatus,
    revision: null,
    state_pointer_content_sha256: null,
    workflow_state_content_sha256: null,
    transition_commit_content_sha256: null,
    phase: null,
    terminal_classification: null,
    terminal_reason: null,
    terminal: null,
    workflow: null,
    operator_input: EMPTY_OPERATOR_INPUT,
    budget: EMPTY_BUDGET,
    time: EMPTY_TIME,
    completion: EMPTY_COMPLETION,
    resumability: null,
    telemetry: null,
    notice: null,
    issues: Object.freeze([...issues]),
  });
}

async function locateRun(retainedRunRoot: string): Promise<{ readonly root: string; readonly stateRoot: string; readonly runId: string } | null> {
  const root = await realpath(retainedRunRoot);
  const entries = await readdir(join(root, "state", "runs"), { withFileTypes: true });
  const runDirectories = entries.filter((entry) => entry.isDirectory() && !entry.isSymbolicLink()).map((entry) => entry.name).sort();
  if (runDirectories.length !== 1) return null;
  return Object.freeze({ root, stateRoot: join(root, "state"), runId: runDirectories[0]! });
}

async function healthyReport(
  located: { readonly root: string; readonly stateRoot: string; readonly runId: string },
  inspection: RunStorageInspection & {
    readonly revision: number;
    readonly statePointer: NonNullable<RunStorageInspection["statePointer"]>;
    readonly workflowState: WorkflowState;
    readonly transitionCommit: NonNullable<RunStorageInspection["transitionCommit"]>;
  },
): Promise<OperatorStatusReport> {
  const state = inspection.workflowState;
  if (state.run_id !== located.runId) {
    return incompleteReport(located.root, located.runId, inspection.status, [issue("RUN_ID_MISMATCH", "workflow state run_id differs from its retained run directory")], "INCOMPLETE");
  }

  let records: M5ManagedRecords | null = null;
  const issues: InspectionIssue[] = [...inspection.issues];
  try {
    records = await readM5ManagedRecords({ stateRoot: located.stateRoot, runId: located.runId });
  } catch (error: unknown) {
    issues.push(issue("M5_RECORDS_UNAVAILABLE", error instanceof Error ? error.message : String(error)));
  }

  const decision = records === null ? null : currentDecision(inspection, records, state);
  const texts = [
    state.terminal_reason,
    decision?.blocking_reason,
    ...(decision?.failures.flatMap((failure) => [failure.source_error_code, failure.control_class]) ?? []),
  ].filter((value): value is string => typeof value === "string");
  const budget = budgetProjection(decision, texts);
  const time = timeProjection(inspection, records, decision, state, texts);
  const terminal = state.phase === "PASS" || state.phase === "BLOCKED";
  const terminalOutcome = state.phase === "PASS" ? "PASS" : state.phase === "BLOCKED" ? "BLOCKED" : null;
  const operatorInputKind = inputKindForPhase(state.phase);
  let resumability: ResumeEligibilityReport | null = null;
  try {
    resumability = await inspectDeterministicResumeEligibility({ retainedRunRoot: located.root });
  } catch (error: unknown) {
    issues.push(issue("RESUMABILITY_UNAVAILABLE", error instanceof Error ? error.message : String(error)));
  }
  let telemetry: BoundedProviderTelemetrySummary | null = null;
  if (state.execution_mode === "STATIC_APPROVED_DAG" && terminal && records !== null) {
    try {
      telemetry = await readPersistedStaticProviderTelemetry({
        stateRoot: located.stateRoot,
        runId: located.runId,
        finalState: state,
        outcome: terminalOutcome === "PASS" ? "PASS" : "BLOCKED",
      });
    } catch {
      telemetry = null;
    }
  }
  const classification = terminalClassification(state) ?? "IN_PROGRESS";
  // Snapshot limit statuses are diagnostic; only an explicit persisted failure reason emits a budget notice.
  const signals: OperatorStatusSignals = { operatorInputKind, budgetExhausted: texts.some(isBudgetReason), timeExhausted: time.exhausted };
  const notice = classifyOperatorNotice({
    phase: state.phase,
    terminal_reason: state.terminal_reason,
    operator_input_kind: signals.operatorInputKind,
    budget_exhausted: signals.budgetExhausted,
    time_exhausted: signals.timeExhausted,
  });
  return Object.freeze({
    classification,
    retained_run_root: located.root,
    run_id: state.run_id,
    storage_status: inspection.status,
    revision: inspection.revision,
    state_pointer_content_sha256: inspection.statePointer.content_sha256 as Sha256Digest,
    workflow_state_content_sha256: state.content_sha256 as Sha256Digest,
    transition_commit_content_sha256: inspection.transitionCommit.content_sha256 as Sha256Digest,
    phase: state.phase,
    terminal_classification: terminalClassification(state),
    terminal_reason: state.terminal_reason,
    terminal,
    workflow: workflowSummary(state),
    operator_input: Object.freeze({ required: operatorInputKind !== null, kind: operatorInputKind }),
    budget,
    time,
    completion: Object.freeze({ completed: terminal, outcome: terminalOutcome }),
    resumability,
    telemetry,
    notice,
    issues: Object.freeze(issues),
  });
}

/** Provider-free, read-only reconstruction from one retained controller workspace. */
export async function readOperatorStatus(retainedRunRoot: string): Promise<OperatorStatusReport> {
  if (!validRoot(retainedRunRoot)) {
    return incompleteReport(typeof retainedRunRoot === "string" ? retainedRunRoot : "", null, "UNAVAILABLE", [issue("INVALID_RETAINED_RUN_ROOT", "retainedRunRoot must be an absolute normalized path")], "INVALID");
  }
  let located: Awaited<ReturnType<typeof locateRun>>;
  try {
    located = await locateRun(retainedRunRoot);
  } catch (error: unknown) {
    return incompleteReport(retainedRunRoot, null, "UNAVAILABLE", [issue("RETAINED_RUN_UNAVAILABLE", error instanceof Error ? error.message : String(error))], "INVALID");
  }
  if (located === null) {
    return incompleteReport(retainedRunRoot, null, "UNAVAILABLE", [issue("RETAINED_RUN_AMBIGUOUS", "retained run must contain exactly one non-symlink state/runs directory")], "INVALID");
  }

  let inspection: Awaited<ReturnType<typeof inspectRunStorage>>;
  try {
    inspection = await inspectRunStorage({ stateRoot: located.stateRoot, runId: located.runId });
  } catch (error: unknown) {
    return incompleteReport(located.root, located.runId, "UNAVAILABLE", [issue("STATE_STORAGE_UNAVAILABLE", error instanceof Error ? error.message : String(error))], "INVALID");
  }
  if (inspection.status !== "HEALTHY") {
    return incompleteReport(located.root, located.runId, inspection.status, inspection.issues, "INCOMPLETE");
  }
  if (inspection.revision === null || inspection.statePointer === null || inspection.workflowState === null || inspection.transitionCommit === null) {
    return incompleteReport(located.root, located.runId, inspection.status, [issue("STATE_COMMIT_INCOMPLETE", "healthy inspection returned no complete committed state")], "INCOMPLETE");
  }
  return healthyReport(located as NonNullable<typeof located>, inspection as Parameters<typeof healthyReport>[1]);
}
