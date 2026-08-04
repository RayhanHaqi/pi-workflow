import assert from "node:assert/strict";
import { execFile, fork } from "node:child_process";
import { chmod, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { promisify } from "node:util";

import type { ChildProcess } from "node:child_process";
import type { Sha256Digest } from "../src/identity/index.js";
import { M5_PUBLICATION_CHECKPOINTS, type M5PublicationCheckpoint } from "../src/persistence/m5-test-hooks.js";
import type { EvaluateControlDecisionInput } from "../src/control/types.js";
import { publishM5ManagedRecord } from "../src/persistence/store.js";
import { identifyContractDocument, type M5ControlDecisionDocument } from "../src/schemas/index.js";
import {
  commitSetup,
  createM5R3Fixture,
  directFastPreflightFixture,
  directVerifyingFixture,
  m5Policy,
  removeM5R3Fixture,
  r3ProcessMetadata,
  usage,
  type M5R3Fixture,
} from "./m5-r3-fixtures.js";
import { digest } from "./helpers.js";

const execFileAsync = promisify(execFile);
const testDirectory = dirname(fileURLToPath(import.meta.url));
const childDriver = resolve(testDirectory, "../dist/tests/m5-r3-child.js");

type Inspection = any;
type ChildSummary = {
  readonly decisionContentSha256: string;
  readonly decisionKey: string;
  readonly outcome: string;
  readonly phase: string;
  readonly workflowStateContentSha256: string;
  readonly committed: boolean;
  readonly reusedDecision: boolean;
};
type ChildError = { readonly code: string; readonly sourceCode?: string; readonly causeCode?: string; readonly message: string };
type ChildMessage = { readonly type: "result"; readonly result: ChildSummary } | { readonly type: "error"; readonly error: ChildError };
type Fresh = { readonly inspection: Inspection; readonly records: any };

const liveChildren = new Set<ChildProcess>();

function expectedFields(fixture: M5R3Fixture, committed: { statePointer: any; workflowState: any }): Pick<EvaluateControlDecisionInput, "expectedRevision" | "expectedStatePointerContentSha256" | "expectedWorkflowStateContentSha256"> {
  return {
    expectedRevision: committed.statePointer.revision,
    expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
  };
}

function requestFor(
  fixture: M5R3Fixture,
  committed: { statePointer: any; workflowState: any },
  patch: Record<string, unknown> = {},
): EvaluateControlDecisionInput {
  return {
    intent: "BLOCK",
    ...expectedFields(fixture, committed),
    transitionId: "r3-block-transition",
    processMetadata: r3ProcessMetadata,
    ...patch,
  } as EvaluateControlDecisionInput;
}

async function inputFile(fixture: M5R3Fixture, name: string, request: EvaluateControlDecisionInput, checkpoint?: M5PublicationCheckpoint): Promise<string> {
  const path = join(fixture.verifierRoot, `${name}.json`);
  await writeFile(path, JSON.stringify({ stateRoot: fixture.stateRoot, runId: fixture.runId, policy: fixture.policy, reducerPolicy: fixture.reducer, runAuthority: fixture.runAuthority, request, ...(checkpoint === undefined ? {} : { checkpoint }) }), { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

function childExit(child: ChildProcess): Promise<{ readonly code: number | null; readonly signal: NodeJS.Signals | null }> {
  return new Promise((resolveExit, rejectExit) => {
    child.once("exit", (code, signal) => { liveChildren.delete(child); resolveExit({ code, signal }); });
    child.once("error", rejectExit);
  });
}

function spawnEvaluate(path: string, gated = false): ChildProcess {
  const child = fork(childDriver, ["evaluate", path, ...(gated ? ["GATE"] : [])], { execArgv: [], stdio: ["ignore", "pipe", "pipe", "ipc"] });
  liveChildren.add(child);
  return child;
}

async function freshInspect(path: string): Promise<Fresh> {
  const result = await execFileAsync(process.execPath, [childDriver, "inspect", path], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  return JSON.parse(result.stdout) as Fresh;
}

async function runEvaluate(path: string, gated = false): Promise<ChildMessage> {
  const child = spawnEvaluate(path, gated);
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  const message = await new Promise<ChildMessage>((resolveMessage, rejectMessage) => {
    const onMessage = (value: unknown): void => {
      if (value !== null && typeof value === "object" && ((value as { type?: unknown }).type === "result" || (value as { type?: unknown }).type === "error")) {
        child.off("message", onMessage);
        resolveMessage(value as ChildMessage);
      }
    };
    child.on("message", onMessage);
    child.once("exit", (code, signal) => rejectMessage(new Error(`child exited before result: code=${code} signal=${signal} ${stderr}`)));
    child.once("error", rejectMessage);
  });
  const exit = await childExit(child);
  if (message.type === "result") assert.deepEqual(exit, { code: 0, signal: null });
  else assert.equal(exit.code, 1);
  return message;
}

async function killAt(path: string, checkpoint: M5PublicationCheckpoint): Promise<Fresh> {
  const child = spawnEvaluate(path);
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  await new Promise<void>((resolveReached, rejectReached) => {
    let reached = false;
    child.on("message", (value: unknown) => {
      if (value !== null && typeof value === "object" && (value as { type?: unknown }).type === "checkpoint" && (value as { checkpoint?: unknown }).checkpoint === checkpoint) {
        reached = true;
        resolveReached();
      }
    });
    child.once("exit", (code, signal) => {
      if (!reached) rejectReached(new Error(`child exited before ${checkpoint}: code=${code} signal=${signal} ${stderr}`));
    });
    child.once("error", rejectReached);
  });
  assert.equal(child.kill("SIGKILL"), true);
  const exit = await childExit(child);
  assert.deepEqual(exit, { code: null, signal: "SIGKILL" });
  return freshInspect(path);
}

function classification(fresh: Fresh, kind: string, contentSha256: string): string | undefined {
  return fresh.inspection.managedRecordClassifications.find((entry: any) => entry.object.kind === kind && entry.object.contentSha256 === contentSha256)?.classification;
}

function currentCommitCount(fresh: Fresh): number {
  return fresh.inspection.reachableObjects.filter((entry: any) => entry.kind === "TRANSITION_COMMIT").length;
}

async function assertNoLiveChildren(): Promise<void> {
  assert.equal(liveChildren.size, 0);
}

const publicationCases: readonly { readonly checkpoint: M5PublicationCheckpoint; readonly family: "policy" | "usage" | "decision"; readonly expectedPolicies: number; readonly expectedUsage: number; readonly expectedDecisions: number }[] = [
  { checkpoint: "BEFORE_POLICY_PUBLICATION", family: "policy", expectedPolicies: 0, expectedUsage: 0, expectedDecisions: 0 },
  { checkpoint: "DURING_POLICY_TEMPORARY_WRITE", family: "policy", expectedPolicies: 0, expectedUsage: 0, expectedDecisions: 0 },
  { checkpoint: "AFTER_POLICY_PUBLICATION", family: "policy", expectedPolicies: 1, expectedUsage: 0, expectedDecisions: 0 },
  { checkpoint: "BEFORE_USAGE_PUBLICATION", family: "usage", expectedPolicies: 1, expectedUsage: 0, expectedDecisions: 0 },
  { checkpoint: "DURING_USAGE_TEMPORARY_WRITE", family: "usage", expectedPolicies: 1, expectedUsage: 0, expectedDecisions: 0 },
  { checkpoint: "AFTER_USAGE_PUBLICATION", family: "usage", expectedPolicies: 1, expectedUsage: 1, expectedDecisions: 0 },
  { checkpoint: "BEFORE_DECISION_PUBLICATION", family: "decision", expectedPolicies: 1, expectedUsage: 1, expectedDecisions: 0 },
  { checkpoint: "DURING_DECISION_TEMPORARY_WRITE", family: "decision", expectedPolicies: 1, expectedUsage: 1, expectedDecisions: 0 },
  { checkpoint: "AFTER_DECISION_PUBLICATION", family: "decision", expectedPolicies: 1, expectedUsage: 1, expectedDecisions: 1 },
];

test("M5-R3 policy, usage, and decision publication checkpoints are process-reconstructable", async (t) => {
  for (const item of publicationCases) {
    await t.test(item.checkpoint, async () => {
      const fixture = await createM5R3Fixture();
      try {
        const persistedUsage = usage(fixture.policy, fixture.initialState.content_sha256 as Sha256Digest, `r3-${item.family}`);
        const request = requestFor(fixture, fixture.committed, { usageEvidence: [persistedUsage] });
        const path = await inputFile(fixture, item.family, request, item.checkpoint);
        const fresh = await killAt(path, item.checkpoint);
        assert.equal(fresh.inspection.statePointer.content_sha256, fixture.committed.statePointer.content_sha256);
        assert.equal(fresh.inspection.workflowState.content_sha256, fixture.committed.workflowState.content_sha256);
        assert.equal(fresh.inspection.revision, 0);
        assert.equal(fresh.records.policies.length, item.expectedPolicies);
        assert.equal(fresh.records.usage.length, item.expectedUsage);
        assert.equal(fresh.records.decisions.length, item.expectedDecisions);
        if (item.checkpoint.includes("DURING_")) assert.ok(fresh.inspection.temporaryFiles.length > 0);
        else assert.equal(fresh.inspection.temporaryFiles.length, 0);
        if (item.checkpoint === "AFTER_POLICY_PUBLICATION") assert.equal(classification(fresh, "M5_CONTROL_POLICY", fixture.policy.content_sha256), "UNREFERENCED_MANAGED_RECORD");
        if (item.checkpoint === "AFTER_USAGE_PUBLICATION") assert.equal(classification(fresh, "M5_USAGE_EVIDENCE", persistedUsage.content_sha256), "UNREFERENCED_MANAGED_RECORD");
        if (item.checkpoint === "AFTER_DECISION_PUBLICATION") assert.equal(classification(fresh, "M5_CONTROL_DECISION", fresh.records.decisions[0].content_sha256), "UNREFERENCED_MANAGED_RECORD");
      } finally {
        await removeM5R3Fixture(fixture);
      }
    });
  }
  await assertNoLiveChildren();
});

const transitionCases: readonly M5PublicationCheckpoint[] = [
  "BEFORE_TRANSITION_EVIDENCE_PUBLICATION", "DURING_TRANSITION_EVIDENCE_PUBLICATION", "AFTER_TRANSITION_EVIDENCE_PUBLICATION",
  "BEFORE_TRANSITION_COMMIT_PUBLICATION", "DURING_TRANSITION_COMMIT_PUBLICATION", "AFTER_TRANSITION_COMMIT_PUBLICATION",
  "BEFORE_STATE_POINTER_UPDATE", "DURING_STATE_POINTER_UPDATE", "AFTER_STATE_POINTER_UPDATE",
];

test("M5-R3 transition evidence, commit, and state-pointer boundaries are fresh-process exact", async (t) => {
  for (const checkpoint of transitionCases) {
    await t.test(checkpoint, async () => {
      const fixture = await createM5R3Fixture();
      try {
        const committed = await directFastPreflightFixture(fixture);
        const request = requestFor(fixture, committed, {
          intent: "AUTHORIZE_WORK", transitionId: "r3-transition-work", operationId: "r3-transition-operation",
          availableLogicalRoles: ["LUNA_EXECUTOR"],
        });
        const path = await inputFile(fixture, checkpoint.toLowerCase(), request, checkpoint);
        const fresh = await killAt(path, checkpoint);
        const oldPointer = committed.statePointer.content_sha256;
        if (checkpoint === "AFTER_STATE_POINTER_UPDATE") {
          assert.equal(fresh.inspection.status, "HEALTHY");
          assert.equal(fresh.inspection.revision, committed.statePointer.revision + 1);
          assert.equal(fresh.inspection.workflowState.phase, "DIRECT_ATTEMPT_RUNNING");
          assert.equal(fresh.records.decisions.length, 1);
          assert.equal(classification(fresh, "M5_CONTROL_DECISION", fresh.records.decisions[0].content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
        } else {
          assert.equal(fresh.inspection.statePointer.content_sha256, oldPointer);
          assert.equal(fresh.inspection.workflowState.content_sha256, committed.workflowState.content_sha256);
          assert.equal(fresh.inspection.revision, committed.statePointer.revision);
          assert.equal(fresh.records.decisions.length, 1);
          if (checkpoint.includes("DURING_")) assert.ok(fresh.inspection.temporaryFiles.length > 0);
          if (checkpoint === "AFTER_TRANSITION_EVIDENCE_PUBLICATION" || checkpoint === "AFTER_TRANSITION_COMMIT_PUBLICATION" || checkpoint === "BEFORE_STATE_POINTER_UPDATE") {
            assert.ok(fresh.inspection.orphanedObjects.length > 0);
          }
          assert.notEqual(classification(fresh, "M5_CONTROL_DECISION", fresh.records.decisions[0].content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
        }
      } finally {
        await removeM5R3Fixture(fixture);
      }
    });
  }
  await assertNoLiveChildren();
});

async function runLostResponseCase(kind: "nonterminal" | "pass" | "blocked"): Promise<void> {
  const fixture = await createM5R3Fixture();
  try {
    const committed = kind === "nonterminal" ? await directFastPreflightFixture(fixture)
      : kind === "pass" ? await directVerifyingFixture(fixture) : fixture.committed;
    const request = kind === "nonterminal"
      ? requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-lost-nonterminal", operationId: "r3-lost-operation", availableLogicalRoles: ["LUNA_EXECUTOR"] })
      : kind === "pass"
        ? requestFor(fixture, committed, { intent: "EVALUATE_TERMINAL", transitionId: "r3-lost-pass", availableLogicalRoles: ["LUNA_EXECUTOR"], obligationEvidence: [{ descriptorSha256: fixture.policy.obligations[0]!.descriptor_sha256, value: "src/result.ts", evidenceContentSha256: digest(800) }] })
        : requestFor(fixture, committed, { intent: "BLOCK", transitionId: "r3-lost-blocked", blockReason: "BLOCKED_R3_PROCESS_PROOF" });
    const path = await inputFile(fixture, `lost-${kind}`, request, "AFTER_COMMITTED_STATE_BEFORE_RESPONSE");
    const afterKill = await killAt(path, "AFTER_COMMITTED_STATE_BEFORE_RESPONSE");
    assert.equal(afterKill.inspection.workflowState.phase, kind === "nonterminal" ? "DIRECT_ATTEMPT_RUNNING" : kind === "pass" ? "PASS" : "BLOCKED");
    const beforeCount = currentCommitCount(afterKill);
    const repeat = await runEvaluate(path);
    assert.equal(repeat.type, "result");
    if (repeat.type === "result") {
      assert.equal(repeat.result.reusedDecision, true);
      assert.equal(repeat.result.committed, true);
      assert.equal(repeat.result.phase, afterKill.inspection.workflowState.phase);
      assert.equal(repeat.result.decisionContentSha256, afterKill.records.decisions[0].content_sha256);
    }
    const afterRepeat = await freshInspect(path);
    assert.equal(currentCommitCount(afterRepeat), beforeCount);
    assert.equal(afterRepeat.records.decisions.length, 1);
    if (kind === "pass" || kind === "blocked") {
      const conflicting = kind === "blocked"
        ? { ...request, blockReason: "BLOCKED_R3_CONFLICTING_REASON" }
        : { ...request, obligationEvidence: [] };
      const conflictPath = await inputFile(fixture, `lost-${kind}-conflict`, conflicting);
      const conflict = await runEvaluate(conflictPath);
      assert.equal(conflict.type, "error");
      if (conflict.type === "error") assert.equal(conflict.error.code, "TERMINAL_STATE_IMMUTABLE");
      await rm(conflictPath, { force: true });
    }
  } finally {
    await removeM5R3Fixture(fixture);
  }
}

test("M5-R3 lost nonterminal response is idempotent after fresh reconstruction", async () => { await runLostResponseCase("nonterminal"); await assertNoLiveChildren(); });
test("M5-R3 lost PASS response is terminally immutable and idempotent", async () => { await runLostResponseCase("pass"); await assertNoLiveChildren(); });
test("M5-R3 lost BLOCKED response preserves blocking evidence and is idempotent", async () => { await runLostResponseCase("blocked"); await assertNoLiveChildren(); });

async function waitReady(children: readonly ChildProcess[]): Promise<void> {
  await Promise.all(children.map((child) => new Promise<void>((resolveReady, rejectReady) => {
    child.on("message", (message: unknown) => { if (message !== null && typeof message === "object" && (message as { type?: unknown }).type === "ready") resolveReady(); });
    child.once("exit", (code, signal) => rejectReady(new Error(`gated child exited before ready: ${code}/${signal}`)));
    child.once("error", rejectReady);
  })));
}

async function concurrentEvaluate(paths: readonly string[]): Promise<readonly ChildMessage[]> {
  const children = paths.map((path) => spawnEvaluate(path, true));
  const messagePromises = children.map((child) => new Promise<ChildMessage>((resolveMessage, rejectMessage) => {
    child.on("message", (message: unknown) => {
      if (message !== null && typeof message === "object" && ((message as { type?: unknown }).type === "result" || (message as { type?: unknown }).type === "error")) resolveMessage(message as ChildMessage);
    });
    child.once("exit", (code, signal) => {
      if (code !== 0) rejectMessage(new Error(`concurrent child exited before result: ${code}/${signal}`));
    });
    child.once("error", rejectMessage);
  }));
  const exitPromises = children.map((child) => childExit(child));
  await waitReady(children);
  for (const child of children) child.send("GO");
  const messages = await Promise.all(messagePromises);
  await Promise.all(exitPromises);
  return messages;
}

function successfulResults(messages: readonly ChildMessage[]): readonly ChildSummary[] {
  return messages.filter((message): message is { type: "result"; result: ChildSummary } => message.type === "result").map((message) => message.result);
}

test("M5-R3 concurrent identical usage is charged once and fresh reconstruction is stable", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const committed = await directFastPreflightFixture(fixture);
    const evidence = usage(fixture.policy, committed.workflowState.content_sha256 as Sha256Digest, "r3-concurrent-identical");
    const request = requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-usage-admission", operationId: "r3-identical-active", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [evidence] });
    const paths = [await inputFile(fixture, "usage-identical-a", request), await inputFile(fixture, "usage-identical-b", request)];
    const messages = await concurrentEvaluate(paths);
    assert.ok(messages.every((message) => message.type === "result" || message.type === "error"));
    const fresh = await freshInspect(paths[0]!);
    assert.equal(fresh.records.usage.length, 1);
    assert.equal(fresh.records.decisions.length, 1);
    assert.equal(fresh.inspection.workflowState.phase, "DIRECT_ATTEMPT_RUNNING");
    assert.equal(classification(fresh, "M5_USAGE_EVIDENCE", evidence.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 concurrent conflicting usage is rejected without double charging", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const committed = await directFastPreflightFixture(fixture);
    const first = usage(fixture.policy, committed.workflowState.content_sha256 as Sha256Digest, "r3-concurrent-conflict", 1);
    const second = usage(fixture.policy, committed.workflowState.content_sha256 as Sha256Digest, "r3-concurrent-conflict", 2);
    const paths = [await inputFile(fixture, "usage-conflict-a", requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-usage-admission", operationId: "r3-conflict-active", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [first] })), await inputFile(fixture, "usage-conflict-b", requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-usage-admission", operationId: "r3-conflict-active", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [second] }))];
    const messages = await concurrentEvaluate(paths);
    const fresh = await freshInspect(paths[0]!);
    assert.equal(fresh.records.usage.length, 1);
    assert.ok(messages.some((message) => message.type === "error"));
    const persisted = fresh.records.usage[0];
    assert.ok(persisted.content_sha256 === first.content_sha256 || persisted.content_sha256 === second.content_sha256);
    assert.equal(fresh.inspection.workflowState.phase, "DIRECT_ATTEMPT_RUNNING");
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 independent operation IDs remain separately reconstructable", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const committed = await directFastPreflightFixture(fixture);
    const first = usage(fixture.policy, committed.workflowState.content_sha256 as Sha256Digest, "r3-independent-1");
    const second = usage(fixture.policy, committed.workflowState.content_sha256 as Sha256Digest, "r3-independent-2");
    const paths = [await inputFile(fixture, "usage-independent-a", requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-independent-a", operationId: "r3-independent-active-a", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [first] })), await inputFile(fixture, "usage-independent-b", requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-independent-b", operationId: "r3-independent-active-b", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [second] }))];
    await concurrentEvaluate(paths);
    let fresh = await freshInspect(paths[0]!);
    if (fresh.records.usage.length === 1) {
      const activeDecision = fresh.records.decisions.find((entry: any) => entry.reservation?.future_operation_id !== undefined);
      const activeOperation = activeDecision.reservation.future_operation_id as string;
      const combinedPath = await inputFile(fixture, "usage-independent-combined", requestFor(fixture, { statePointer: fresh.inspection.statePointer, workflowState: fresh.inspection.workflowState }, {
        intent: "AUTHORIZE_CONTINUATION", transitionId: "r3-usage-continuation", operationId: activeOperation, availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [first, second],
        progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [fixture.policy.content_sha256] },
        failures: [{ sourceLayer: "M5", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: fixture.policy.content_sha256, normalizedSignature: digest(735), operationId: activeOperation }],
      }));
      const secondEvaluation = await runEvaluate(combinedPath);
      assert.equal(secondEvaluation.type, "result", secondEvaluation.type === "error" ? JSON.stringify(secondEvaluation.error) : undefined);
      fresh = await freshInspect(combinedPath);
    }
    assert.equal(fresh.records.usage.length, 2);
    assert.equal(new Set(fresh.records.usage.map((entry: any) => entry.operation_id)).size, 2);
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 concurrent identical decisions have one committed result and exact fresh reuse", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const request = requestFor(fixture, fixture.committed, { blockReason: "BLOCKED_R3_DUPLICATE" });
    const paths = [await inputFile(fixture, "decision-identical-a", request), await inputFile(fixture, "decision-identical-b", request)];
    const messages = await concurrentEvaluate(paths);
    const fresh = await freshInspect(paths[0]!);
    assert.equal(fresh.records.decisions.length, 1);
    assert.equal(fresh.inspection.workflowState.phase, "BLOCKED");
    assert.ok(successfulResults(messages).length >= 1);
    const repeat = await runEvaluate(paths[1]!);
    assert.equal(repeat.type, "result");
    if (repeat.type === "result") assert.equal(repeat.result.reusedDecision, true);
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 conflicting immutable decision content for one key is rejected before publication", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const committed = await directFastPreflightFixture(fixture);
    const request = requestFor(fixture, committed, { intent: "AUTHORIZE_WORK", transitionId: "r3-conflicting-record", operationId: "r3-conflicting-active", availableLogicalRoles: ["LUNA_EXECUTOR"] });
    const path = await inputFile(fixture, "decision-record", request);
    const result = await runEvaluate(path);
    assert.equal(result.type, "result");
    const fresh = await freshInspect(path);
    const original = fresh.records.decisions[0] as M5ControlDecisionDocument;
    const { content_sha256: _content, ...body } = structuredClone(original) as any;
    const forged = identifyContractDocument("pi_gacw_m5_control_decision_v0", { ...body, available_logical_roles: original.available_logical_roles?.length === 0 ? ["LUNA_EXECUTOR"] : [] }) as unknown as M5ControlDecisionDocument;
    await assert.rejects(publishM5ManagedRecord({ stateRoot: fixture.stateRoot, runId: fixture.runId, kind: "M5_CONTROL_DECISION", document: forged }), (error: unknown) => (error as { code?: string }).code === "M5_DECISION_CONFLICT");
    const after = await freshInspect(path);
    assert.equal(after.records.decisions.length, 1);
    assert.equal(after.records.decisions[0].content_sha256, original.content_sha256);
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 concurrent conflicting decisions cannot create a second terminal transition", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const a = requestFor(fixture, fixture.committed, { transitionId: "r3-conflict-a", blockReason: "BLOCKED_R3_A" });
    const b = requestFor(fixture, fixture.committed, { transitionId: "r3-conflict-b", blockReason: "BLOCKED_R3_B" });
    const paths = [await inputFile(fixture, "decision-conflict-a", a), await inputFile(fixture, "decision-conflict-b", b)];
    const messages = await concurrentEvaluate(paths);
    const fresh = await freshInspect(paths[0]!);
    assert.equal(fresh.records.decisions.length, 1);
    assert.equal(fresh.inspection.workflowState.phase, "BLOCKED");
    assert.equal(currentCommitCount(fresh), 2);
    assert.ok(messages.some((message) => message.type === "error") || successfulResults(messages).length === 1);
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 stale expected-state competition has one winner and no conflicting authoritative graph", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const a = requestFor(fixture, fixture.committed, { transitionId: "r3-stale-a", blockReason: "BLOCKED_R3_STALE_A" });
    const b = requestFor(fixture, fixture.committed, { transitionId: "r3-stale-b", blockReason: "BLOCKED_R3_STALE_B" });
    const paths = [await inputFile(fixture, "stale-a", a), await inputFile(fixture, "stale-b", b)];
    const messages = await concurrentEvaluate(paths);
    const fresh = await freshInspect(paths[0]!);
    assert.equal(fresh.inspection.workflowState.phase, "BLOCKED");
    assert.equal(fresh.inspection.revision, 1);
    assert.equal(currentCommitCount(fresh), 2);
    assert.equal(fresh.records.decisions.length, 1);
    const loserPath = messages[0]?.type === "error" ? paths[0]! : paths[1]!;
    const stale = await runEvaluate(loserPath);
    assert.equal(stale.type, "error");
    if (stale.type === "error") assert.ok(["M5_AUTHORITY_INCOMPLETE", "TERMINAL_STATE_IMMUTABLE", "M5_EVIDENCE_PUBLICATION_FAILED"].includes(stale.error.code));
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 fresh-process graph reconstruction recalculates records, classifications, and terminal authority", async () => {
  const fixture = await createM5R3Fixture();
  try {
    const request = requestFor(fixture, fixture.committed, { blockReason: "BLOCKED_R3_RECONSTRUCTION" });
    const path = await inputFile(fixture, "reconstruction", request);
    const result = await runEvaluate(path);
    assert.equal(result.type, "result");
    const fresh = await freshInspect(path);
    assert.equal(fresh.inspection.workflowState.phase, "BLOCKED");
    assert.equal(fresh.inspection.status, "HEALTHY");
    assert.equal(fresh.records.decisions.length, 1);
    assert.equal(fresh.records.policies.length, 1);
    assert.equal(classification(fresh, "M5_CONTROL_DECISION", fresh.records.decisions[0].content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(fresh.records.decisions[0].outcome, "BLOCK");
    assert.equal(fresh.records.decisions[0].blocking_reason, "BLOCKED_R3_RECONSTRUCTION");
  } finally { await removeM5R3Fixture(fixture); await assertNoLiveChildren(); }
});

test("M5-R3 packed persisted evaluation preserves the public control boundary", async () => {
  const fixture = await createM5R3Fixture();
  const packageRoot = join(fixture.verifierRoot, "package");
  const consumerRoot = join(fixture.verifierRoot, "consumer");
  try {
    await mkdir(packageRoot, { recursive: true, mode: 0o700 });
    await mkdir(consumerRoot, { recursive: true, mode: 0o700 });
    const packed = await execFileAsync("npm", ["pack", "--ignore-scripts", "--pack-destination", packageRoot], { cwd: resolve(testDirectory, ".."), encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
    const tarball = (await import("node:fs/promises")).readdir(packageRoot).then((names) => names.find((name) => name.endsWith(".tgz")));
    const archive = await tarball;
    assert.ok(archive, packed.stdout);
    const packageDirectory = join(consumerRoot, "node_modules", "pi-bounded-coding-workflow");
    await mkdir(packageDirectory, { recursive: true, mode: 0o700 });
    await execFileAsync("tar", ["-xzf", join(packageRoot, archive), "--strip-components=1", "-C", packageDirectory]);
    await mkdir(join(consumerRoot, "node_modules", "@sinclair"), { recursive: true, mode: 0o700 });
    await symlink(resolve(testDirectory, "../node_modules/ajv"), join(consumerRoot, "node_modules", "ajv"));
    await symlink(resolve(testDirectory, "../node_modules/@sinclair/typebox"), join(consumerRoot, "node_modules", "@sinclair", "typebox"));
    const input = requestFor(fixture, fixture.committed, { blockReason: "BLOCKED_R3_PACKED" });
    const inputPath = await inputFile(fixture, "packed-input", input);
    const script = join(consumerRoot, "consumer.mjs");
    await writeFile(script, `import { createControlDecisionKernel } from "pi-bounded-coding-workflow/control";\nimport { readFile } from "node:fs/promises";\nconst input = JSON.parse(await readFile(process.argv[2], "utf8"));\nconst kernel = createControlDecisionKernel({ stateRoot: input.stateRoot, runId: input.runId, policy: input.policy, reducerPolicy: input.reducerPolicy, runAuthority: input.runAuthority });\nconst result = await kernel.evaluateControlDecision(input.request);\nconsole.log(JSON.stringify({ phase: result.workflowState.phase, outcome: result.decision.outcome, reused: result.reusedDecision }));\n`, { mode: 0o600 });
    const first = await execFileAsync(process.execPath, [script, inputPath], { cwd: consumerRoot, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
    assert.deepEqual(JSON.parse(first.stdout), { phase: "BLOCKED", outcome: "BLOCK", reused: false });
    const second = await execFileAsync(process.execPath, [script, inputPath], { cwd: consumerRoot, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
    assert.deepEqual(JSON.parse(second.stdout), { phase: "BLOCKED", outcome: "BLOCK", reused: true });
    for (const subpath of ["pi-bounded-coding-workflow/src/persistence/m5-test-hooks.js", "pi-bounded-coding-workflow/src/persistence/store.js", "pi-bounded-coding-workflow/src/control/evaluate.js"]) {
      await assert.rejects(import(subpath), (error: unknown) => (error as { code?: string }).code === "ERR_PACKAGE_PATH_NOT_EXPORTED");
    }
  } finally {
    await removeM5R3Fixture(fixture);
  }
});

test("M5-R3 process harness leaves no tracked-state IPC or child residue", async () => {
  await assertNoLiveChildren();
  assert.deepEqual(M5_PUBLICATION_CHECKPOINTS.length, 32);
});

// Keep the imported type visible in this process-proof suite: the on-disk decision is
// intentionally checked as an immutable M5 document rather than as an opaque message.
void (undefined as M5ControlDecisionDocument | undefined);
