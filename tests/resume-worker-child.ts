import { fork } from "node:child_process";

import { inspectRunStorage } from "../src/persistence/index.js";
import { installTestWallClock } from "../src/wall-clock.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";
import {
  acquireDeterministicResumeAdmission,
  activateDeterministicResumeAdmission,
  authorizeDeterministicResumedLeafWork,
  executeDeterministicResumedLeafWorkerForTests,
} from "../src/resume-admission.js";
import { configureResumeWorkerTestHooks } from "../src/resume-worker-test-hooks.js";
import { inspectDeterministicResumeEligibility } from "../src/resume-inspection.js";

const retainedRunRoot = process.argv[2]!;
const mode = process.argv[3]!;
if (process.send === undefined || retainedRunRoot === undefined || !["EXECUTE", "HANG_IN_RUNTIME", "RESULT_PAUSE", "HANDOVER_PAUSE", "DEPTH_REFUSE", "EXPIRE_BEFORE_HANDOVER", "EXPIRE_AFTER_HANDOVER", "EXPIRE_BEFORE_INVOCATION"].includes(mode ?? "")) {
  throw new Error("resume-worker-child requires a retained run root, a mode, and IPC");
}

let hung = false;
configureBoundedWorkerFauxRuntimeForTests(() => ({
  async execute({ tools }) {
    // One bounded mutation through the REAL M4 gateway: secure write → postflight → mutation receipt.
    await tools.writePath({ path: `${taskId()}.txt`, operation: "CREATE", replacementBytes: Buffer.from(`${taskId()}-resumed\n`),
      expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
    if (mode === "HANG_IN_RUNTIME" && !hung) {
      // The BOUNDED_WORKER_INVOCATION is durable; the result can never be proven absent after this boundary.
      hung = true; process.send?.({ type: "HUNG" });
      await new Promise<void>(() => {});
    }
    tools.submitReport(`wrote ${taskId()}.txt`);
    return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0, inputTokens: 10, outputTokens: 20, costMicrousd: 1234 };
  },
}));

function taskId(): string {
  // Deterministic single selected leaf per run: first-leaf fixtures select a, two-leaf fixtures select b.
  return activeTaskId;
}
let activeTaskId = "a";

function installExpiredWallClock(): void {
  const expiredNow = Date.now() + 10_000_000;
  installTestWallClock(() => expiredNow);
}

function codeOf(error: unknown): string | null {
  if (error !== null && typeof error === "object" && "code" in error) return String((error as { readonly code: unknown }).code);
  return null;
}

async function main(): Promise<void> {
  let report = await inspectDeterministicResumeEligibility({ retainedRunRoot });
  for (let attempt = 0; report.classification !== "RESUMABLE" && attempt < 100; attempt += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
    report = await inspectDeterministicResumeEligibility({ retainedRunRoot });
  }
  if (report.classification !== "RESUMABLE") throw new Error(`fixture run is not resumable: ${report.reason}`);
  if (["RESULT_PAUSE", "HANDOVER_PAUSE", "EXPIRE_AFTER_HANDOVER", "EXPIRE_BEFORE_INVOCATION"].includes(mode)) {
    configureResumeWorkerTestHooks({ checkpoint: async (checkpoint) => {
      if (mode === "RESULT_PAUSE" && checkpoint === "AFTER_RESUMED_RESULT_PERSISTED") {
        // Durable result exists; the R2D response is not returned before cleanup.
        process.send?.({ type: "RESULT_PERSISTED" });
        await new Promise<void>(() => {});
      } else if (mode === "HANDOVER_PAUSE" && checkpoint === "AFTER_RESUME_HANDOVER") {
        // T_A -> T_B is durable; the resumed worker has not crossed its provider boundary.
        process.send?.({ type: "HANDOVER_PERSISTED" });
        await new Promise<void>(() => {});
      } else if (mode === "EXPIRE_AFTER_HANDOVER" && checkpoint === "AFTER_RESUME_HANDOVER") {
        installExpiredWallClock();
      } else if (mode === "EXPIRE_BEFORE_INVOCATION" && checkpoint === "AFTER_RESUME_GATEWAY_CREATED") {
        installExpiredWallClock();
      }
    } });
  }
  const admission = await acquireDeterministicResumeAdmission({ retainedRunRoot });
  const activation = admission.binding.resume_point.startsWith("STATIC_DAG_SELECT_READY_LEAF:")
    ? await activateDeterministicResumeAdmission(admission)
    : undefined;
  activeTaskId = activation?.binding.selected_task_id ?? admission.binding.resume_point.slice(admission.binding.resume_point.lastIndexOf(":") + 1);
  const work = await authorizeDeterministicResumedLeafWork(activation ?? admission);
  process.send?.({ type: "AUTHORIZED", resumePoint: (activation ?? admission).binding.resume_point, taskId: activeTaskId });
  if (mode === "EXPIRE_BEFORE_HANDOVER") installExpiredWallClock();
  let result;
  try {
    result = await executeDeterministicResumedLeafWorkerForTests(work);
  } catch (error: unknown) {
    if (["DEPTH_REFUSE", "EXPIRE_BEFORE_HANDOVER", "EXPIRE_AFTER_HANDOVER", "EXPIRE_BEFORE_INVOCATION"].includes(mode)) {
      process.send?.({ type: "REFUSED", code: codeOf(error), message: error instanceof Error ? error.message : String(error) });
      return;
    }
    throw error;
  }
  const runs = await import("node:fs/promises").then((fs) => fs.readdir(`${retainedRunRoot}/state/runs`));
  const state = (await inspectRunStorage({ stateRoot: `${retainedRunRoot}/state`, runId: runs[0]! })).workflowState;
  process.send?.({ type: "EXECUTED", binding: result.binding,
    phase: state?.phase, terraExecutor: state?.counters.worker_invocations.terra_executor, taskId: activeTaskId });
}

main().catch((error: unknown) => {
  console.error("RESUME_WORKER_CHILD_ERROR", error);
  process.send?.({ type: "ERROR", error: error instanceof Error ? `${(error as { code?: string }).code ?? ""} ${error.message}`.trim() : String(error) });
  process.exitCode = 1;
});
