import { readFile } from "node:fs/promises";

import { createControlDecisionKernel } from "../src/control/index.js";
import { orderDecisionHistory } from "../src/control/evaluate.js";
import { configureM5PersistenceTestHooks, type M5PublicationCheckpoint } from "../src/persistence/m5-test-hooks.js";
import { configurePersistenceTestHooks, type PersistenceCheckpoint } from "../src/persistence/test-hooks.js";
import { commitTransition, inspectRunStorage, publishM5ManagedRecord, readM5ManagedRecords, withRunExclusive } from "../src/persistence/store.js";
import type { EvaluateControlDecisionInput, M5ImmutableRunAuthoritySources } from "../src/control/types.js";
import type { M5ControlDecisionDocument, M5ControlPolicyDocument, ReducerPolicy } from "../src/schemas/index.js";

interface EvaluateInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly policy: M5ControlPolicyDocument;
  readonly reducerPolicy: ReducerPolicy;
  readonly runAuthority: M5ImmutableRunAuthoritySources;
  readonly request?: EvaluateControlDecisionInput;
  readonly decisions?: readonly M5ControlDecisionDocument[];
  readonly manualTransition?: {
    readonly expectedRevision: number;
    readonly expectedStatePointerContentSha256: string;
    readonly expectedWorkflowStateContentSha256: string;
    readonly expectedNextWorkflowStateContentSha256: string;
    readonly transitionId: string;
    readonly event: Record<string, unknown>;
    readonly processMetadata: Record<string, unknown>;
    readonly mediaType: string;
    readonly evidenceText: string;
  };
  readonly checkpoint?: M5PublicationCheckpoint;
}

function errorDetails(error: unknown): Record<string, unknown> {
  if (error === null || typeof error !== "object") return { code: "UNKNOWN", message: String(error) };
  const value = error as { code?: unknown; sourceCode?: unknown; message?: unknown; cause?: unknown };
  const cause = value.cause;
  return {
    code: typeof value.code === "string" ? value.code : "UNKNOWN",
    sourceCode: typeof value.sourceCode === "string" ? value.sourceCode : undefined,
    causeCode: cause !== null && typeof cause === "object" && typeof (cause as { code?: unknown }).code === "string" ? (cause as { code: string }).code : undefined,
    message: typeof value.message === "string" ? value.message : String(error),
  };
}

async function main(): Promise<void> {
  const mode = process.argv[2];
  const inputPath = process.argv[3];
  if (inputPath === undefined) throw new Error("m5-r3 child requires an input path");
  const input = JSON.parse(await readFile(inputPath, "utf8")) as EvaluateInput;
  if (mode === "inspect") {
    const [inspection, records] = await Promise.all([
      inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId }),
      readM5ManagedRecords({ stateRoot: input.stateRoot, runId: input.runId }),
    ]);
    process.stdout.write(`${JSON.stringify({ inspection, records })}\n`);
    return;
  }
  if (mode === "seed-history") {
    await publishM5ManagedRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "M5_CONTROL_POLICY", document: input.policy });
    for (const decision of input.decisions ?? []) await publishM5ManagedRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "M5_CONTROL_DECISION", document: decision });
    process.stdout.write(`${JSON.stringify({ seeded: input.decisions?.length ?? 0 })}\n`); return;
  }
  if (mode === "history") {
    const records = await readM5ManagedRecords({ stateRoot: input.stateRoot, runId: input.runId });
    process.stdout.write(`${JSON.stringify({ ordered: orderDecisionHistory(records.decisions).map((entry) => entry.content_sha256) })}\n`); return;
  }
  if (mode === "history-inline") {
    process.stdout.write(`${JSON.stringify({ ordered: orderDecisionHistory(input.decisions ?? []).map((entry) => entry.content_sha256) })}\n`); return;
  }
  if (mode === "manual-transition") {
    const manual = input.manualTransition; if (manual === undefined || input.decisions?.[0] === undefined) throw new Error("manual transition input is incomplete");
    await publishM5ManagedRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "M5_CONTROL_POLICY", document: input.policy });
    await publishM5ManagedRecord({ stateRoot: input.stateRoot, runId: input.runId, kind: "M5_CONTROL_DECISION", document: input.decisions[0] });
    await commitTransition({ stateRoot: input.stateRoot, runId: input.runId, expectedRevision: manual.expectedRevision,
      expectedStatePointerContentSha256: manual.expectedStatePointerContentSha256 as never, expectedWorkflowStateContentSha256: manual.expectedWorkflowStateContentSha256 as never,
      expectedNextWorkflowStateContentSha256: manual.expectedNextWorkflowStateContentSha256 as never, transitionId: manual.transitionId,
      policy: input.reducerPolicy, event: manual.event as never, evidence: [{ bytes: Buffer.from(manual.evidenceText, "utf8"), mediaType: manual.mediaType }], processMetadata: manual.processMetadata as never });
    process.stdout.write(`${JSON.stringify({ committed: true })}\n`); return;
  }
  if (mode !== "evaluate" && mode !== "lock") throw new Error(`unknown m5-r3 child mode ${mode}`);

  let reached = false;
  const waitAt = async (checkpoint: M5PublicationCheckpoint): Promise<void> => {
    if (reached || input.checkpoint !== checkpoint) return;
    reached = true;
    process.send?.({ type: "checkpoint", checkpoint });
    await new Promise<void>((resolve) => {
      process.once("message", (message: unknown) => {
        if (message === "CONTINUE") resolve();
      });
    });
  };
  const conceptualFromAtomic = (checkpoint: PersistenceCheckpoint, finalPath: string): M5PublicationCheckpoint | undefined => {
    if (checkpoint === "RECORD_TEMP_WRITTEN") {
      if (finalPath.includes("/m5-control-policies/")) return "DURING_POLICY_TEMPORARY_WRITE";
      if (finalPath.includes("/m5-usage-evidence/")) return "DURING_USAGE_TEMPORARY_WRITE";
      if (finalPath.includes("/m5-control-decisions/")) return "DURING_DECISION_TEMPORARY_WRITE";
    }
    if (checkpoint === "EVIDENCE_TEMP_WRITTEN" && finalPath.includes("/evidence/sha256/")) return "DURING_TRANSITION_EVIDENCE_PUBLICATION";
    if (checkpoint === "TRANSITION_TEMP_WRITTEN" && finalPath.includes("/commits/")) return "DURING_TRANSITION_COMMIT_PUBLICATION";
    if (checkpoint === "STATE_TEMP_WRITTEN" && finalPath.endsWith("/state.json")) return "DURING_STATE_POINTER_UPDATE";
    return undefined;
  };
  configureM5PersistenceTestHooks({ checkpoint: waitAt });
  configurePersistenceTestHooks({ checkpoint: async (checkpoint, finalPath) => {
    const conceptual = conceptualFromAtomic(checkpoint, finalPath);
    if (conceptual !== undefined) await waitAt(conceptual);
  }});

  if (mode === "lock") {
    await withRunExclusive({ stateRoot: input.stateRoot, runId: input.runId }, async () => {
      process.send?.({ type: "acquired" });
      await new Promise<void>((resolve) => process.once("message", (message: unknown) => { if (message === "RELEASE") resolve(); }));
    });
    process.send?.({ type: "released" }); process.disconnect?.(); return;
  }

  if (process.argv[4] === "GATE") {
    process.send?.({ type: "ready" });
    await new Promise<void>((resolve) => {
      process.once("message", (message: unknown) => {
        if (message === "GO") resolve();
      });
    });
  }

  try {
    const kernel = createControlDecisionKernel({ stateRoot: input.stateRoot, runId: input.runId, policy: input.policy, reducerPolicy: input.reducerPolicy, runAuthority: input.runAuthority });
    if (input.request === undefined) throw new Error("evaluate mode requires a request");
    const result = await kernel.evaluateControlDecision(input.request);
    const message = { type: "result", result: {
      decisionContentSha256: result.decision.content_sha256,
      decisionKey: result.decision.decision_key,
      outcome: result.decision.outcome,
      phase: result.workflowState.phase,
      workflowStateContentSha256: result.workflowState.content_sha256,
      committed: result.committed,
      reusedDecision: result.reusedDecision,
    }};
    if (process.send === undefined) process.stdout.write(`${JSON.stringify(message)}\n`);
    else { process.send(message); process.disconnect?.(); }
  } catch (error: unknown) {
    process.send?.({ type: "error", error: errorDetails(error) });
    process.disconnect?.();
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
