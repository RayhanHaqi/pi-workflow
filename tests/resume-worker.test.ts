import assert from "node:assert/strict";
import { access, cp, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { fork } from "node:child_process";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { configureM5PersistenceTestHooks } from "../src/persistence/m5-test-hooks.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { loadAuthoritativeToken } from "../src/repository/token-provenance.js";
import { acquireWorktreeLock, probeWorktreeLockAvailability, releaseWorktreeLock, resolveRepositoryIdentity, runResumeLockHandover } from "../src/repository/index.js";
import { acquireDeterministicResumeAdmission, completeDeterministicResumedStaticDag, DeterministicResumeAdmissionError, reconcileDeterministicResumedLeaf } from "../src/resume-admission.js";
import {
  boundedWorkerSystemPrompt,
  BOUNDED_WORKER_MAX_TOOL_CALLS,
  partitionProviderVisibleReadScope,
  providerVisibleTaskContract,
} from "../src/control/launch-authority.js";
import {
  partitionProviderVisibleReadScope as controllerPartition,
  providerVisibleTaskContract as controllerTaskContract,
} from "../src/workflow-controller.js";
import { inspectDeterministicResumeEligibility } from "../src/resume-inspection.js";
import { configureResumeReconciliationTestHooks } from "../src/resume-reconciliation-test-hooks.js";
import { installTestWallClock } from "../src/wall-clock.js";

type FixtureMode = "READY" | "READY_LIMIT_1" | "DELTA" | "READY_VERIFY" | "READY_VERIFY_FAIL" | "READY_VERIFY_RETRY" | "READY_VERIFY_TWO" | "READY_VERIFY_TIMEOUT" | "DELTA_VERIFY";
type ChildFixture = { readonly root: string; readonly repository: string; readonly cleanup: () => Promise<void> };

async function interruptFixture(mode: FixtureMode): Promise<ChildFixture> {
  const child = fork(new URL("./resume-inspection-child.ts", import.meta.url), [mode], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const message = await new Promise<{ readonly root: string; readonly repository: string }>((resolve, reject) => {
    child.once("exit", (_code, signal) => reject(new Error(`fixture owner exited before pause (${mode}): ${signal}`)));
    child.once("message", (value: unknown) => {
      if (value !== null && typeof value === "object" && (value as { readonly type?: unknown }).type === "PAUSED") {
        resolve(value as unknown as { readonly root: string; readonly repository: string });
      }
    });
  });
  child.kill("SIGKILL");
  await new Promise<void>((resolve) => { child.once("exit", (_code, signal) => { if (signal === "SIGKILL") resolve(); }); });
  return { root: message.root, repository: message.repository, cleanup: async () => { await rm(dirname(message.root), { recursive: true, force: true }); await rm(message.repository, { recursive: true, force: true }); } };
}

type WorkerMessage = Record<string, unknown>;
type WorkerChild = { readonly child: ReturnType<typeof fork>; readonly next: (label: string) => Promise<WorkerMessage> };

function startWorkerChild(root: string, mode: "EXECUTE" | "HANG_IN_RUNTIME" | "RESULT_PAUSE" | "HANDOVER_PAUSE" | "DEPTH_REFUSE" | "EXPIRE_BEFORE_HANDOVER" | "EXPIRE_AFTER_HANDOVER" | "EXPIRE_BEFORE_INVOCATION", waitMs = 120_000): WorkerChild {
  const child = fork(new URL("./resume-worker-child.ts", import.meta.url), [root, mode], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const queue: WorkerMessage[] = [];
  const waiters: ((message: WorkerMessage) => void)[] = [];
  child.on("message", (value: unknown) => {
    if (value === null || typeof value !== "object") return;
    const waiter = waiters.shift();
    if (waiter === undefined) queue.push(value as WorkerMessage);
    else waiter(value as WorkerMessage);
  });
  return {
    child,
    next: (label: string) => new Promise<WorkerMessage>((resolve, reject) => {
      const attempt = (): boolean => {
        const errorIndex = queue.findIndex((message) => message["type"] === "ERROR");
        if (errorIndex !== -1) {
          const [error] = queue.splice(errorIndex, 1);
          reject(new Error(`worker child error: ${JSON.stringify(error)}`));
          return true;
        }
        const index = queue.findIndex((message) => message["type"] === label);
        if (index === -1) return false;
        const [matched] = queue.splice(index, 1);
        if (matched === undefined) return false;
        resolve(matched);
        return true;
      };
      if (attempt()) return;
      const timer = setTimeout(() => {
        child.off("message", onMessage);
        reject(new Error(`worker child timed out waiting for ${label} (${mode}); buffered: ${queue.map((entry) => String(entry["type"])).join(",")}`));
      }, waitMs);
      const onMessage = (value: unknown): void => {
        if (value === null || typeof value !== "object") return;
        const type = (value as { readonly type?: unknown }).type;
        if (type === "ERROR") {
          clearTimeout(timer);
          child.off("message", onMessage);
          reject(new Error(`worker child error: ${JSON.stringify(value)}`));
          return;
        }
        if (type !== label) return;
        clearTimeout(timer);
        child.off("message", onMessage);
        resolve(value as WorkerMessage);
      };
      child.on("message", onMessage);
    }),
  };
}

async function stopChild(child: ReturnType<typeof fork> | undefined): Promise<void> {
  if (child === undefined) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGKILL");
  await new Promise<void>((resolve) => child.once("exit", () => resolve()));
}

const LOCATION = (root: string) => ({ stateRoot: join(root, "state"), runId: "pre-m8-bounded" });

function codeOf(error: unknown): unknown { return error !== null && typeof error === "object" ? (error as { readonly code?: unknown }).code : undefined; }

function durableTokenTip(records: Awaited<ReturnType<typeof readM5ManagedRecords>>): typeof records.stateTokens[number] {
  const referenced = new Set(records.stateTokens.flatMap((token) => token.prior_token_content_sha256 === null ? [] : [token.prior_token_content_sha256]));
  const tips = records.stateTokens.filter((token) => !referenced.has(token.content_sha256));
  assert.equal(tips.length, 1);
  return tips[0]!;
}

async function advanceTokenChain(fixture: ChildFixture, targetDepth: number): Promise<void> {
  const location = LOCATION(fixture.root);
  const records = await readM5ManagedRecords(location);
  const policy = records.policies.find((entry) => entry.requested_mode === "STATIC_APPROVED_DAG");
  const baseline = records.baselines[0];
  if (policy === undefined || baseline === undefined) throw new Error("resume depth fixture lacks static M5/baseline authority");
  let token = durableTokenTip(records);
  let authority = await loadAuthoritativeToken(location, token, baseline);
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  while (authority.chainDepth < targetDepth) {
    const lock = await acquireWorktreeLock({ stateRoot: location.stateRoot, repository });
    try {
      token = (await runResumeLockHandover({
        stateRoot: location.stateRoot, runId: location.runId, acceptedState: token, baseline,
        instructionFiles: [], authorityFiles: [], taskScopeIdentity: policy.scope_sha256 as Sha256Digest, lock,
      })).acceptedState;
    } finally {
      await releaseWorktreeLock(lock);
    }
    authority = await loadAuthoritativeToken(location, token, baseline);
  }
  assert.equal(authority.chainDepth, targetDepth);
}

async function rejectsCode(promise: Promise<unknown>, expected: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => codeOf(error) === expected || (error instanceof DeterministicResumeAdmissionError && error.code === expected));
}

async function eventuallyResumable(root: string) {
  let report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  for (let attempt = 0; report.classification !== "RESUMABLE" && attempt < 100; attempt += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25)); report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  }
  return report;
}

async function settledWorkerFixture(mode: Extract<FixtureMode, "READY_VERIFY" | "READY_VERIFY_FAIL" | "READY_VERIFY_RETRY" | "READY_VERIFY_TWO" | "READY_VERIFY_TIMEOUT" | "DELTA_VERIFY">): Promise<ChildFixture> {
  const fixture = await interruptFixture(mode);
  const worker = startWorkerChild(fixture.root, "EXECUTE");
  try {
    const executed = await worker.next("EXECUTED");
    assert.equal(executed["type"], "EXECUTED");
    await stopChild(worker.child);
    return fixture;
  } catch (error: unknown) {
    await stopChild(worker.child).catch(() => undefined);
    await fixture.cleanup().catch(() => undefined);
    throw error;
  }
}

async function expectedWorkerRefusal(root: string, mode: "DEPTH_REFUSE" | "EXPIRE_BEFORE_HANDOVER" | "EXPIRE_AFTER_HANDOVER" | "EXPIRE_BEFORE_INVOCATION"): Promise<WorkerMessage> {
  const worker = startWorkerChild(root, mode);
  try {
    await worker.next("AUTHORIZED");
    const refused = await worker.next("REFUSED");
    assert.equal(refused["type"], "REFUSED");
    return refused;
  } finally {
    await stopChild(worker.child);
  }
}

test("shared launch authority is byte-identical to the historical controller construction", () => {
  // Scope partition equivalence across EXACT/PREFIX authorities and the missing-authority refusal.
  const authorities = [
    { path: "verify", kind: "PREFIX" as const },
    { path: "a.txt", kind: "EXACT" as const },
  ] as never;
  assert.equal(canonicalize(partitionProviderVisibleReadScope(["verify", "a.txt"], authorities)),
    canonicalize(controllerPartition(["verify", "a.txt"], authorities)));
  assert.throws(() => partitionProviderVisibleReadScope(["unknown.txt"], authorities), (error: unknown) => codeOf(error) === "CONTROLLER_AUTHORITY_INVALID");
  assert.throws(() => controllerPartition(["unknown.txt"], authorities));
  // Task-contract equivalence across planner-plan and mutation-limit variants.
  for (const hardLimit of [1, null] as const) {
    assert.equal(providerVisibleTaskContract("Write a.", partitionProviderVisibleReadScope(["a.txt"], authorities), ["a.txt"], null, hardLimit),
      controllerTaskContract("Write a.", controllerPartition(["a.txt"], authorities), ["a.txt"], null, hardLimit));
    const plan = { content_sha256: digest("f") } as never;
    assert.equal(providerVisibleTaskContract("Write a.", partitionProviderVisibleReadScope(["verify", "a.txt"], authorities), ["a.txt"], plan, hardLimit),
      controllerTaskContract("Write a.", controllerPartition(["verify", "a.txt"], authorities), ["a.txt"], plan, hardLimit));
  }
  // No resume wording may ever enter provider-visible prose.
  for (const text of [providerVisibleTaskContract("o", { regularFilePaths: [], prefixPaths: [] }, [], null, null), boundedWorkerSystemPrompt("MUTATION_EXECUTOR")]) {
    assert.ok(!text.includes("resum"), text);
  }
});

function digest(letter: string): `sha256:${string}` { return `sha256:${letter.repeat(64)}`; }

test("first-leaf resumed faux worker executes through the real M4 path with exact authority transfer", async () => {
  const fixture = await interruptFixture("READY");
  const temporaryRootsBefore = new Set((await readdir(tmpdir())).filter((entry) => entry.startsWith("pi-resumed-worker-")));
  const worker = startWorkerChild(fixture.root, "EXECUTE");
  try {
    // READY fixtures pause at selection; the resumed-worker child performs admission → activation → authorization.
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_SELECT_READY_LEAF:a");
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    const stateBefore = (await inspectRunStorage(LOCATION(fixture.root))).workflowState!;
    const counterBefore = stateBefore.counters.worker_invocations;
    const tokenA = durableTokenTip(before);
    const executed = await worker.next("EXECUTED") as unknown as {
      readonly type: string; readonly taskId: string; readonly phase: string | null; readonly terraExecutor: number | undefined;
      readonly binding: {
        readonly operation_id: string; readonly m5_decision_content_sha256: Sha256Digest; readonly invocation_content_sha256: Sha256Digest;
        readonly result_content_sha256: Sha256Digest; readonly input_m3_state_token_content_sha256: Sha256Digest;
        readonly final_gateway_state_token_content_sha256: Sha256Digest; readonly accepted_m4_evidence_count: number;
        readonly result_outcome: string; readonly cleanup_certain: boolean; readonly provider_id: string; readonly model_id: string; readonly effort: string;
      };
    };
    assert.equal(executed.type, "EXECUTED");
    assert.equal(await probeWorktreeLockAvailability({ stateRoot: join(fixture.root, "state"), repository: await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }) }), "LOCK_AVAILABLE"); // R2D released ownership before returning EXECUTED
    // WORKER_AUTHORITY_REHYDRATION + identity binding
    assert.equal(executed.binding.operation_id, "static-leaf-a-attempt-1");
    assert.equal(executed.binding.result_outcome, "COMPLETED");
    assert.equal(executed.binding.cleanup_certain, true);
    assert.equal(executed.phase, "LEAF_RUNNING"); // STOP STATE: no COMPLETE_LEAF_ATTEMPT
    assert.equal(executed.taskId, "a");
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    const invocations = records.boundedWorkerInvocations.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1");
    const results = records.boundedWorkerResults.filter((result) => result.invocation_content_sha256 === executed.binding.invocation_content_sha256);
    const handovers = records.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER" && token.prior_token_content_sha256 === tokenA.content_sha256);
    assert.equal(handovers.length, 1);
    const tokenB = handovers[0]!;
    assert.notEqual(tokenA.content_sha256, tokenB.content_sha256); // T_A != T_B
    assert.equal(invocations[0]!.input_m3_state_token_content_sha256, tokenB.content_sha256); // invocation input == T_B
    assert.equal(records.mutationReceipts[0]?.prior_state_token_content_sha256, tokenB.content_sha256); // gateway acceptedState == T_B
    // EXACT_ONE_CURRENT_INVOCATION / RESULT
    assert.equal(invocations.length, 1); assert.equal(results.length, 1);
    assert.equal(invocations[0]!.content_sha256, executed.binding.invocation_content_sha256);
    assert.equal(results[0]!.content_sha256, executed.binding.result_content_sha256);
    // INPUT_TOKEN_BOUND + FINAL_GATEWAY_TOKEN_BOUND
    assert.equal(invocations[0]!.input_m3_state_token_content_sha256, executed.binding.input_m3_state_token_content_sha256);
    assert.notEqual(executed.binding.final_gateway_state_token_content_sha256, executed.binding.input_m3_state_token_content_sha256);
    // CURRENT_RESULT_AUTHORITY_ACCEPTED + M4_MUTATION_EVIDENCE_ACCEPTED
    const successor = await inspectRunStorage(LOCATION(fixture.root));
    const authoritative = (kind: string, sha: string): boolean =>
      successor.managedRecordClassifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === sha && entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(authoritative("BOUNDED_WORKER_INVOCATION", executed.binding.invocation_content_sha256), true);
    assert.equal(authoritative("BOUNDED_WORKER_RESULT", executed.binding.result_content_sha256), true);
    assert.ok(executed.binding.accepted_m4_evidence_count > 0);
    // REAL M4 MUTATION through tools.writePath → secure mutation → postflight
    await assert.doesNotReject(() => access(join(fixture.repository, "a.txt")));
    assert.equal(await readFile(join(fixture.repository, "a.txt"), "utf8"), "a-resumed\n");
    // BUDGET ACCOUNTING: R2D adds no M2 counter or reservation delta; R2C
    // already charged the selected leaf before this worker starts.
    assert.equal(executed.terraExecutor, counterBefore.terra_executor + 1);
    assert.equal(successor.workflowState!.counters.worker_invocations.terra_executor, counterBefore.terra_executor + 1);
    assert.equal(successor.workflowState!.counters.worker_invocations.total, counterBefore.total + 1);
    assert.equal(records.decisions.filter((decision) => decision.reservation !== null).length,
      before.decisions.filter((decision) => decision.reservation !== null).length + 1);
    // PROMPT IDENTITY: invocation binds exactly the shared launch-authority prompt bytes
    const policyRecords = records.reducerPolicies.find((entry) => entry.content_sha256 === successor.workflowState!.frozen_policy_content_sha256)!;
    const contract = records.contracts.find((entry) => entry.contract_sha256 === successor.workflowState!.identities.contract_sha256)!;
    void policyRecords; void contract;
    const toolPolicy = records.toolPolicies[0]!;
    const taskObjective = records.tasks.find((task) => task.task_id === "a")!.objective;
    const expectedUserPrompt = providerVisibleTaskContract(taskObjective, partitionProviderVisibleReadScope(["verify"], toolPolicy.path_authorities), ["a.txt"], null, null);
    assert.equal(invocations[0]!.system_prompt_sha256, sha256Bytes(Buffer.from(boundedWorkerSystemPrompt("MUTATION_EXECUTOR"), "utf8")));
    assert.equal(invocations[0]!.user_prompt_sha256, sha256Bytes(Buffer.from(expectedUserPrompt, "utf8")));
    // CAPABILITY TRANSFER: work admission is consumed; R2D returns only immutable data binding.
    const temporaryRootsAfter = (await readdir(tmpdir())).filter((entry) => entry.startsWith("pi-resumed-worker-") && !temporaryRootsBefore.has(entry));
    assert.deepEqual(temporaryRootsAfter, []); // successful release removes the controller-owned temporary root
    await stopChild(worker.child);
    await fixture.cleanup();
  } catch (error) {
    await stopChild(worker.child).catch(() => undefined);
    await fixture.cleanup().catch(() => undefined);
    throw error;
  }
});

test("two-leaf resumed faux worker executes leaf b without touching settled a evidence", async () => {
  const fixture = await interruptFixture("DELTA");
  const worker = startWorkerChild(fixture.root, "EXECUTE");
  try {
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_SELECT_READY_LEAF:b");
    const history = await readM5ManagedRecords(LOCATION(fixture.root));
    const aInvocation = history.boundedWorkerInvocations.find((entry) => entry.operation_id === "static-leaf-a-attempt-1")!;
    const aResult = history.boundedWorkerResults[0]!;
    const executed = await worker.next("EXECUTED") as unknown as { readonly type: string; readonly taskId: string; readonly phase: string | null;
      readonly terraExecutor: number | undefined;
      readonly binding: { readonly operation_id: string; readonly invocation_content_sha256: Sha256Digest; readonly result_content_sha256: Sha256Digest } };
    assert.equal(executed.type, "EXECUTED");
    assert.equal(executed.taskId, "b");
    assert.equal(executed.binding.operation_id, "static-leaf-b-attempt-1");
    assert.equal(executed.phase, "LEAF_RUNNING");
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    // HISTORICAL_LEAF_EVIDENCE_PRESERVED: byte-for-byte untouched.
    assert.equal(records.boundedWorkerInvocations.filter((entry) => entry.content_sha256 === aInvocation.content_sha256).length, 1);
    assert.equal(records.boundedWorkerResults.filter((entry) => entry.content_sha256 === aResult.content_sha256).length, 1);
    assert.equal(canonicalize(records.boundedWorkerInvocations.find((entry) => entry.content_sha256 === aInvocation.content_sha256)), canonicalize(aInvocation));
    // Exactly one b invocation/result; b scope isolated to b.txt only.
    assert.equal(records.boundedWorkerInvocations.filter((entry) => entry.operation_id === "static-leaf-b-attempt-1").length, 1);
    assert.equal(records.boundedWorkerResults.filter((result) => result.invocation_content_sha256 === executed.binding.invocation_content_sha256).length, 1);
    await assert.doesNotReject(() => access(join(fixture.repository, "b.txt")));
    assert.equal(await readFile(join(fixture.repository, "a.txt"), "utf8"), "a.txt\n"); // b never rewrote a's settled output
    // B_COUNTER_DELTA = 0 during R2D (R2C already charged both leaves).
    assert.equal(executed.terraExecutor, 2);
    await stopChild(worker.child);
    await fixture.cleanup();
  } catch (error) {
    await stopChild(worker.child).catch(() => undefined);
    await fixture.cleanup().catch(() => undefined);
    throw error;
  }
});

test("crash after invocation publication refuses fresh resume without any replay", async () => {
  const fixture = await interruptFixture("READY");
  const worker = startWorkerChild(fixture.root, "HANG_IN_RUNTIME");
  try {
    const hung = await worker.next("HUNG") as unknown as { readonly type: string };
    assert.equal(hung.type, "HUNG");
    worker.child.kill("SIGKILL");
    await new Promise<void>((resolve) => worker.child.once("exit", () => resolve()));
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(records.boundedWorkerInvocations.length, 1);
    assert.equal(records.boundedWorkerResults.length, 0);
    const report = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.equal(report.classification, "RESUME_REFUSED");
    assert.equal(report.reason, "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    await rejectsCode(acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_IN_FLIGHT_OPERATION");
    const reread = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(reread.boundedWorkerInvocations.length, 1); // no duplicate created
    assert.equal(reread.boundedWorkerResults.length, 0);
    await fixture.cleanup();
  } catch (error) {
    worker.child.kill("SIGKILL");
    await fixture.cleanup().catch(() => undefined);
    throw error;
  }
});

test("result-persisted crash leaves durable evidence with no worker replay", async () => {
  const fixture = await interruptFixture("READY");
  const worker = startWorkerChild(fixture.root, "RESULT_PAUSE");
  try {
    const paused = await worker.next("RESULT_PERSISTED") as unknown as { readonly type: string };
    assert.equal(paused.type, "RESULT_PERSISTED");
    worker.child.kill("SIGKILL");
    await new Promise<void>((resolve) => worker.child.once("exit", () => resolve()));
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(records.boundedWorkerInvocations.length, 1);
    assert.equal(records.boundedWorkerResults.length, 1);
    const state = (await inspectRunStorage(LOCATION(fixture.root))).workflowState!;
    assert.equal(state.phase, "LEAF_RUNNING");
    const report = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.deepEqual(report, { classification: "RESUMABLE", run_id: "pre-m8-bounded", phase: "LEAF_RUNNING", resume_point: "STATIC_DAG_RECONCILE_SETTLED_LEAF:a", reason: null });
    assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "LEAF_RUNNING");
    const reread = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(reread.boundedWorkerInvocations.length, 1); // WORKER_REPLAY_AFTER_RESULT = NO
    assert.equal(reread.boundedWorkerResults.length, 1);     // DUPLICATE_RESULT_CREATED = NO
    await fixture.cleanup();
  } catch (error) {
    worker.child.kill("SIGKILL");
    await fixture.cleanup().catch(() => undefined);
    throw error;
  }
});

test("crash after durable T_A→T_B handover is recovered by a fresh R2C without provider replay", async () => {
  const fixture = await interruptFixture("READY");
  const first = startWorkerChild(fixture.root, "HANDOVER_PAUSE");
  let recovery: WorkerChild | undefined;
  try {
    await first.next("AUTHORIZED");
    const paused = await first.next("HANDOVER_PERSISTED");
    assert.equal(paused["type"], "HANDOVER_PERSISTED");
    const beforeCrash = await readM5ManagedRecords(LOCATION(fixture.root));
    const handoverB = beforeCrash.stateTokens.find((token) => token.source === "RESUME_LOCK_HANDOVER");
    assert.ok(handoverB !== undefined);
    const tokenA = beforeCrash.stateTokens.find((token) => token.content_sha256 === handoverB.prior_token_content_sha256);
    assert.ok(tokenA !== undefined);
    assert.notEqual(tokenA.content_sha256, handoverB.content_sha256);
    assert.equal(beforeCrash.boundedWorkerInvocations.length, 0);
    assert.equal(beforeCrash.boundedWorkerResults.length, 0);
    await stopChild(first.child);

    const afterCrash = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(afterCrash.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, 1);
    assert.equal(afterCrash.boundedWorkerInvocations.length, 0); // crash before invocation
    assert.equal(afterCrash.boundedWorkerResults.length, 0);

    recovery = startWorkerChild(fixture.root, "EXECUTE");
    await recovery.next("AUTHORIZED"); // fresh R2C binds the durable current tip T_B
    const executed = await recovery.next("EXECUTED") as unknown as { readonly type: string; readonly phase: string | null; readonly binding: { readonly input_m3_state_token_content_sha256: Sha256Digest; readonly result_content_sha256: Sha256Digest } };
    assert.equal(executed.type, "EXECUTED");
    assert.equal(executed.phase, "LEAF_RUNNING");
    const afterRecovery = await readM5ManagedRecords(LOCATION(fixture.root));
    const handoverC = afterRecovery.stateTokens.find((token) => token.source === "RESUME_LOCK_HANDOVER" && token.prior_token_content_sha256 === handoverB.content_sha256);
    assert.ok(handoverC !== undefined);
    assert.equal(executed.binding.input_m3_state_token_content_sha256, handoverC.content_sha256);
    assert.equal(afterRecovery.boundedWorkerInvocations.length, 1);
    assert.equal(afterRecovery.boundedWorkerResults.length, 1);
    assert.equal(afterRecovery.boundedWorkerResults[0]!.content_sha256, executed.binding.result_content_sha256);
    assert.equal(afterRecovery.decisions.filter((decision) => decision.operation_id === "static-leaf-a-attempt-1" && decision.reservation !== null).length,
      beforeCrash.decisions.filter((decision) => decision.operation_id === "static-leaf-a-attempt-1" && decision.reservation !== null).length);
  } finally {
    await stopChild(first.child).catch(() => undefined);
    await stopChild(recovery?.child).catch(() => undefined);
    await fixture.cleanup().catch(() => undefined);
  }
});

test("R2D timing Gates A/B/C refuse expired durable execution without provider replay", async (t) => {
  await t.test("Gate A expiry before handover", async () => {
    const fixture = await interruptFixture("READY");
    try {
      const before = await readM5ManagedRecords(LOCATION(fixture.root));
      const refused = await expectedWorkerRefusal(fixture.root, "EXPIRE_BEFORE_HANDOVER");
      assert.equal(refused["code"], "RESUME_REFUSED_TIMING_AUTHORITY");
      const after = await readM5ManagedRecords(LOCATION(fixture.root));
      assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
        before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length);
      assert.equal(after.boundedWorkerInvocations.length, 0);
      assert.equal(after.boundedWorkerResults.length, 0);
    } finally {
      await fixture.cleanup().catch(() => undefined);
    }
  });

  await t.test("Gate B expiry after handover", async () => {
    const fixture = await interruptFixture("READY");
    try {
      const before = await readM5ManagedRecords(LOCATION(fixture.root));
      const refused = await expectedWorkerRefusal(fixture.root, "EXPIRE_AFTER_HANDOVER");
      assert.equal(refused["code"], "RESUME_REFUSED_TIMING_AUTHORITY");
      const after = await readM5ManagedRecords(LOCATION(fixture.root));
      assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
        before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length + 1);
      assert.equal(after.boundedWorkerInvocations.length, 0);
      assert.equal(after.boundedWorkerResults.length, 0);
    } finally {
      await fixture.cleanup().catch(() => undefined);
    }
  });

  await t.test("Gate C expiry immediately before invocation", async () => {
    const fixture = await interruptFixture("READY");
    try {
      const before = await readM5ManagedRecords(LOCATION(fixture.root));
      const refused = await expectedWorkerRefusal(fixture.root, "EXPIRE_BEFORE_INVOCATION");
      assert.equal(refused["code"], "RESUME_REFUSED_TIMING_AUTHORITY");
      const after = await readM5ManagedRecords(LOCATION(fixture.root));
      assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
        before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length + 1);
      assert.equal(after.boundedWorkerInvocations.length, 0); // Gate C is before provider/runtime admission
      assert.equal(after.boundedWorkerResults.length, 0);
    } finally {
      await fixture.cleanup().catch(() => undefined);
    }
  });
});

test("R2D M3 depth gate N=1 exact boundary depth 62 succeeds and reaches depth 64", async () => {
  const fixture = await interruptFixture("READY_LIMIT_1");
  let worker: WorkerChild | undefined;
  try {
    await advanceTokenChain(fixture, 62);
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    worker = startWorkerChild(fixture.root, "EXECUTE", 600_000);
    const executed = await worker.next("EXECUTED") as unknown as { readonly type: string; readonly binding: { readonly final_gateway_state_token_content_sha256: Sha256Digest } };
    assert.equal(executed.type, "EXECUTED");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    const finalAuthority = await loadAuthoritativeToken(LOCATION(fixture.root), durableTokenTip(after), after.baselines[0]!);
    assert.equal(finalAuthority.chainDepth, 64);
    assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
      before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length + 1);
    assert.equal(executed.binding.final_gateway_state_token_content_sha256, durableTokenTip(after).content_sha256);
  } finally {
    await stopChild(worker?.child).catch(() => undefined);
    await fixture.cleanup().catch(() => undefined);
  }
});

test("R2D M3 depth gate N=1 overflow depth 63 refuses before handover", async () => {
  const fixture = await interruptFixture("READY_LIMIT_1");
  try {
    await advanceTokenChain(fixture, 63);
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    const tipBefore = durableTokenTip(before);
    const refused = await expectedWorkerRefusal(fixture.root, "DEPTH_REFUSE");
    assert.equal(refused["code"], "STATE_TOKEN_CHAIN_TOO_DEEP");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(durableTokenTip(after).content_sha256, tipBefore.content_sha256);
    assert.equal(after.stateTokens.length, before.stateTokens.length);
    assert.equal(after.boundedWorkerInvocations.length, 0);
    assert.equal(after.boundedWorkerResults.length, 0);
  } finally {
    await fixture.cleanup().catch(() => undefined);
  }
});

test("R2D M3 depth gate N=32 exact boundary depth 31 succeeds", async () => {
  const fixture = await interruptFixture("READY");
  let worker: WorkerChild | undefined;
  try {
    await advanceTokenChain(fixture, 31);
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    worker = startWorkerChild(fixture.root, "EXECUTE");
    const executed = await worker.next("EXECUTED") as unknown as { readonly type: string };
    assert.equal(executed.type, "EXECUTED");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
      before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length + 1);
  } finally {
    await stopChild(worker?.child).catch(() => undefined);
    await fixture.cleanup().catch(() => undefined);
  }
});

test("R2D M3 depth gate N=32 overflow depth 32 refuses before handover", async () => {
  const fixture = await interruptFixture("READY");
  try {
    await advanceTokenChain(fixture, 32);
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    const tipBefore = durableTokenTip(before);
    const refused = await expectedWorkerRefusal(fixture.root, "DEPTH_REFUSE");
    assert.equal(refused["code"], "STATE_TOKEN_CHAIN_TOO_DEEP");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(durableTokenTip(after).content_sha256, tipBefore.content_sha256);
    assert.equal(after.stateTokens.length, before.stateTokens.length);
    assert.equal(after.boundedWorkerInvocations.length, 0);
    assert.equal(after.boundedWorkerResults.length, 0);
  } finally {
    await fixture.cleanup().catch(() => undefined);
  }
});


async function r2eCounts(root: string): Promise<{ readonly usage: number; readonly decisions: number; readonly invocations: number; readonly results: number; readonly commandResults: number; readonly postflights: number }> {
  const records = await readM5ManagedRecords(LOCATION(root));
  return {
    usage: records.usage.length, decisions: records.decisions.length, invocations: records.boundedWorkerInvocations.length,
    results: records.boundedWorkerResults.length, commandResults: records.commandResults.length, postflights: records.postflights.length,
  };
}

async function r2eWorkflowAuthority(root: string) {
  const records = await readM5ManagedRecords(LOCATION(root));
  const authority = records.staticTimeAuthorities.find((entry) => entry.authority_scope === "WORKFLOW");
  assert.ok(authority, "R2E fixture has no workflow timing authority");
  return authority;
}
async function snapshotStateRoot(root: string): Promise<{ readonly restore: () => Promise<void>; readonly cleanup: () => Promise<void> }> {
  const backupRoot = await mkdtemp(join(tmpdir(), "r2e-capacity-state-"));
  const stateRoot = join(root, "state");
  await cp(stateRoot, join(backupRoot, "state"), { recursive: true });
  return {
    restore: async () => { await rm(stateRoot, { recursive: true, force: true }); await cp(join(backupRoot, "state"), stateRoot, { recursive: true }); },
    cleanup: async () => { await rm(backupRoot, { recursive: true, force: true }); },
  };
}

async function crashR2EAt(fixture: ChildFixture, checkpoint: "AFTER_VERIFICATION_COMMAND" | "AFTER_PASS_LEAF_POSTFLIGHT"): Promise<void> {
  configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
    if (value === checkpoint) throw new Error(`R2E crash at ${checkpoint}`);
  } });
  try {
    await assert.rejects(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), /R2E crash/);
  } finally {
    configureResumeReconciliationTestHooks(undefined);
  }
}

async function crashR2FAt(fixture: ChildFixture, checkpoint: "BEFORE_FINAL_VERIFIER" | "AFTER_FINAL_VERIFIER" | "BETWEEN_FINAL_VERIFIERS" | "AFTER_FINAL_POSTFLIGHT" | "AFTER_TERMINAL_DECISION" | "AFTER_PASS_TRANSITION"): Promise<void> {
  configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
    if (value === checkpoint) throw new Error(`R2F crash at ${checkpoint}`);
  } });
  try {
    await assert.rejects(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), /R2F crash/);
  } finally {
    configureResumeReconciliationTestHooks(undefined);
  }
}

test("R2E reconciles a settled leaf exactly once through verification to READY", async () => {
  const fixture = await settledWorkerFixture("READY_VERIFY");
  try {
    const before = await r2eCounts(fixture.root);
    const report = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    assert.equal(report.resume_point, "STATIC_DAG_RECONCILE_SETTLED_LEAF:a");
    const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(result.worker_replay, false);
    assert.equal(result.usage_reconciled, true);
    assert.equal(result.lock_released, true);
    assert.equal(result.verification_outcome, "PASSED");
    assert.equal(result.final_phase, "READY");
    assert.equal(result.command_result_content_sha256.length, 1);
    assert.equal(result.postflight_content_sha256.length, 1);
    const after = await r2eCounts(fixture.root);
    assert.equal(after.invocations, before.invocations);
    assert.equal(after.results, before.results);
    assert.equal(after.usage, before.usage + 1);
    assert.equal(after.decisions, before.decisions + 1);
    assert.equal(after.commandResults, before.commandResults + 1);
    assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.tasks.find((task) => task.task_id === "a")?.status, "PASS");
    assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.active_task_id, null);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    assert.equal(await probeWorktreeLockAvailability({ stateRoot: join(fixture.root, "state"), repository }), "LOCK_AVAILABLE");
    const usage = (await readM5ManagedRecords(LOCATION(fixture.root))).usage.find((entry) => entry.operation_id === "static-leaf-a-attempt-1");
    assert.ok(usage);
    assert.equal(usage.source_kind, "BOUNDED_WORKER_RESULT");
    assert.equal(usage.source_record_content_sha256, result.result_content_sha256);
  } finally {
    await fixture.cleanup();
  }
});

test("R2E preserves prior settled history and reaches STATIC_DAG_VERIFYING on the final leaf", async () => {
  const fixture = await settledWorkerFixture("DELTA_VERIFY");
  try {
    const recordsBefore = await readM5ManagedRecords(LOCATION(fixture.root));
    const priorInvocation = recordsBefore.boundedWorkerInvocations.find((entry) => entry.operation_id === "static-leaf-a-attempt-1");
    const priorResult = recordsBefore.boundedWorkerResults.find((entry) => entry.invocation_content_sha256 === priorInvocation?.content_sha256);
    assert.ok(priorInvocation); assert.ok(priorResult);
    const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(result.task_id, "b");
    assert.equal(result.final_phase, "STATIC_DAG_VERIFYING");
    assert.equal(result.verification_outcome, "PASSED");
    const recordsAfter = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(canonicalize(recordsAfter.boundedWorkerInvocations.find((entry) => entry.content_sha256 === priorInvocation.content_sha256)), canonicalize(priorInvocation));
    assert.equal(canonicalize(recordsAfter.boundedWorkerResults.find((entry) => entry.content_sha256 === priorResult.content_sha256)), canonicalize(priorResult));
    assert.equal(recordsAfter.usage.filter((entry) => entry.operation_id === "static-leaf-b-attempt-1").length, 1);
    assert.equal(recordsAfter.boundedWorkerInvocations.length, 2);
    assert.equal(recordsAfter.boundedWorkerResults.length, 2);
    assert.ok((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.tasks.every((task) => task.status === "PASS"));
  } finally {
    await fixture.cleanup();
  }
});

test("R2F completes a final static DAG without replaying workers", async () => {
  const fixture = await settledWorkerFixture("DELTA_VERIFY");
  try {
    const r2e = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(r2e.final_phase, "STATIC_DAG_VERIFYING");
    assert.equal((await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root })).resume_point, "STATIC_DAG_COMPLETE");
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
    assert.equal(result.final_phase, "PASS");
    assert.equal(result.terminal_reason, "PASS");
    assert.equal(result.static_dag_verification_passed, true);
    assert.equal(result.worker_started, false);
    assert.equal(result.provider_call, false);
    assert.equal(result.attempt_2_started, false);
    assert.equal(result.command_result_content_sha256.length, 1);
    assert.equal(result.postflight_content_sha256.length, 2);
    assert.equal(result.output_delta.map((entry) => entry.path).sort().join(","), "a.txt,b.txt");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(after.boundedWorkerInvocations.length, before.boundedWorkerInvocations.length);
    assert.equal(after.boundedWorkerResults.length, before.boundedWorkerResults.length);
    assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "PASS");
  } finally {
    await fixture.cleanup();
  }
});

test("R2F confirms READY next-leaf boundary without worker execution", async () => {
  const fixture = await interruptFixture("READY");
  try {
    const before = await readM5ManagedRecords(LOCATION(fixture.root));
    const inspected = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
    const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
    assert.equal(result.final_phase, "READY");
    assert.equal(result.next_leaf_task_id, "a");
    assert.equal(result.next_leaf_boundary, inspected.resume_point);
    assert.equal(result.worker_started, false);
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(after.boundedWorkerInvocations.length, before.boundedWorkerInvocations.length);
    assert.equal(after.commandResults.length, before.commandResults.length);
  } finally {
    await fixture.cleanup();
  }
});

test("R2F crash replay reuses final evidence and terminal authority", async (t) => {
  const fixture = await settledWorkerFixture("DELTA_VERIFY");
  try {
    const r2e = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(r2e.final_phase, "STATIC_DAG_VERIFYING");
    const snapshot = await snapshotStateRoot(fixture.root);
    try {
      await t.test("before any final verifier", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        await crashR2FAt(fixture, "BEFORE_FINAL_VERIFIER");
        const crashed = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(crashed.commandResults.length, before.commandResults.length);
        assert.equal(crashed.postflights.length, before.postflights.length);
        const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "PASS");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.commandResults.length, before.commandResults.length + 1);
      });

      await t.test("after final verifier", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        await crashR2FAt(fixture, "AFTER_FINAL_VERIFIER");
        const crashed = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "STATIC_DAG_VERIFYING");
        assert.equal(crashed.commandResults.length, before.commandResults.length + 1);
        const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "PASS");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.commandResults.length, crashed.commandResults.length);
        assert.equal(after.postflights.length, crashed.postflights.length + 1);
        assert.equal(after.boundedWorkerInvocations.length, before.boundedWorkerInvocations.length);
      });

      await t.test("after final postflight", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        await crashR2FAt(fixture, "AFTER_FINAL_POSTFLIGHT");
        const crashed = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "STATIC_DAG_VERIFYING");
        assert.equal(crashed.commandResults.length, before.commandResults.length + 1);
        const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "PASS");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.commandResults.length, crashed.commandResults.length);
        assert.equal(after.postflights.length, crashed.postflights.length);
      });

      await t.test("after terminal decision publication", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        configureM5PersistenceTestHooks({ checkpoint: async (checkpoint) => {
          if (checkpoint === "AFTER_DECISION_PUBLICATION") throw new Error("R2F crash after terminal decision publication");
        } });
        try {
          await assert.rejects(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), /M5_EVIDENCE_PUBLICATION_FAILED/);
        } finally {
          configureM5PersistenceTestHooks(undefined);
        }
        const crashed = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "STATIC_DAG_VERIFYING");
        assert.equal(crashed.decisions.filter((entry) => entry.intent === "EVALUATE_TERMINAL").length, 1);
        assert.equal(crashed.commandResults.length, before.commandResults.length + 1);
        const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "PASS");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.decisions.filter((entry) => entry.intent === "EVALUATE_TERMINAL").length, 1);
      });

      await t.test("after PASS transition", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        await crashR2FAt(fixture, "AFTER_PASS_TRANSITION");
        const crashed = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "PASS");
        const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "PASS");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.commandResults.length, crashed.commandResults.length);
        assert.equal(after.postflights.length, crashed.postflights.length);
        assert.equal(after.decisions.filter((entry) => entry.intent === "EVALUATE_TERMINAL").length, 1);
        assert.equal(after.boundedWorkerInvocations.length, before.boundedWorkerInvocations.length);
      });
    } finally {
      await snapshot.cleanup();
    }
  } finally {
    await fixture.cleanup();
  }
});

test("R2F runs two frozen final verifiers in order", async () => {
  const fixture = await settledWorkerFixture("READY_VERIFY_TWO");
  try {
    const first = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(first.final_phase, "READY");
    const worker = startWorkerChild(fixture.root, "EXECUTE");
    try {
      assert.equal((await worker.next("EXECUTED"))["taskId"], "b");
    } finally {
      await stopChild(worker.child);
    }
    const second = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(second.final_phase, "STATIC_DAG_VERIFYING");
    const snapshot = await snapshotStateRoot(fixture.root);
    try {
      const before = await readM5ManagedRecords(LOCATION(fixture.root));
      await crashR2FAt(fixture, "BETWEEN_FINAL_VERIFIERS");
      const crashed = await readM5ManagedRecords(LOCATION(fixture.root));
      assert.equal(crashed.commandResults.filter((entry) => entry.command_id === "verify").length, before.commandResults.filter((entry) => entry.command_id === "verify").length + 1);
      assert.equal(crashed.commandResults.filter((entry) => entry.command_id === "verify2").length, before.commandResults.filter((entry) => entry.command_id === "verify2").length);
      const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
      assert.equal(result.final_phase, "PASS");
      assert.equal(result.command_result_content_sha256.length, 2);
      assert.equal(result.postflight_content_sha256.length, 3);
    } finally {
      await snapshot.cleanup();
    }
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(records.boundedWorkerInvocations.length, 2);
    assert.equal(records.boundedWorkerResults.length, 2);
    assert.equal(records.decisions.filter((entry) => entry.intent === "EVALUATE_TERMINAL").length, 1);
  } finally {
    await fixture.cleanup();
  }
});

test("R2F reserves exact final verifier, postflight, and handover capacity", async (t) => {
  const fixture = await settledWorkerFixture("DELTA_VERIFY");
  try {
    const r2e = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(r2e.final_phase, "STATIC_DAG_VERIFYING");
    await advanceTokenChain(fixture, 61);
    const boundary = await snapshotStateRoot(fixture.root);
    try {
      await t.test("depth 61 fits one handover, verifier, and final postflight", async () => {
        await boundary.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        const result = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "PASS");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.stateTokens.filter((entry) => entry.source === "RESUME_LOCK_HANDOVER").length, before.stateTokens.filter((entry) => entry.source === "RESUME_LOCK_HANDOVER").length + 1);
        assert.equal(after.commandResults.length, before.commandResults.length + 1);
        assert.equal((await loadAuthoritativeToken(LOCATION(fixture.root), durableTokenTip(after), after.baselines[0]!)).chainDepth, 64);
        const stableCounts = { tokens: after.stateTokens.length, commands: after.commandResults.length, postflights: after.postflights.length, decisions: after.decisions.length };
        const repeated = await completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root });
        assert.equal(repeated.final_phase, "PASS");
        const stable = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.deepEqual({ tokens: stable.stateTokens.length, commands: stable.commandResults.length, postflights: stable.postflights.length, decisions: stable.decisions.length }, stableCounts);
      });

      await t.test("depth 62 refuses before any fresh handover", async () => {
        await boundary.restore();
        await advanceTokenChain(fixture, 62);
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "STATE_TOKEN_CHAIN_TOO_DEEP");
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "STATIC_DAG_VERIFYING");
        assert.equal(after.stateTokens.length, before.stateTokens.length);
        assert.equal(after.commandResults.length, before.commandResults.length);
        assert.equal(after.postflights.length, before.postflights.length);
      });
    } finally {
      await boundary.cleanup();
    }
  } finally {
    await fixture.cleanup();
  }
});

test("R2F enforces the durable workflow timing gates", async (t) => {
  const fixture = await settledWorkerFixture("DELTA_VERIFY");
  try {
    const r2e = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(r2e.final_phase, "STATIC_DAG_VERIFYING");
    const workflow = await r2eWorkflowAuthority(fixture.root);
    const snapshot = await snapshotStateRoot(fixture.root);
    try {
      await t.test("workflow expiry before final verification", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        installTestWallClock(() => workflow.started_at_epoch_ms + workflow.wall_budget_ms);
        try {
          await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
        } finally {
          installTestWallClock(null);
        }
        const after = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(after.commandResults.length, before.commandResults.length);
        assert.equal(after.postflights.length, before.postflights.length);
      });

      await t.test("expiry after durable final verifier evidence", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
          if (value === "AFTER_FINAL_VERIFIER") installTestWallClock(() => workflow.started_at_epoch_ms + workflow.wall_budget_ms);
        } });
        try {
          await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
        } finally {
          configureResumeReconciliationTestHooks(undefined);
        }
        const afterEvidence = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(afterEvidence.commandResults.length, before.commandResults.length + 1);
        assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "STATIC_DAG_VERIFYING");
        await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
        installTestWallClock(null);
      });

      await t.test("expiry before terminal evaluation", async () => {
        await snapshot.restore();
        const before = await readM5ManagedRecords(LOCATION(fixture.root));
        configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
          if (value === "AFTER_FINAL_POSTFLIGHT") installTestWallClock(() => workflow.started_at_epoch_ms + workflow.wall_budget_ms);
        } });
        try {
          await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
        } finally {
          configureResumeReconciliationTestHooks(undefined);
        }
        const afterPostflight = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(afterPostflight.commandResults.length, before.commandResults.length + 1);
        assert.equal(afterPostflight.postflights.length, before.postflights.length + 2);
        assert.equal(afterPostflight.decisions.filter((entry) => entry.intent === "EVALUATE_TERMINAL").length, 0);
        await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
        installTestWallClock(null);
      });
    } finally {
      installTestWallClock(null);
      await snapshot.cleanup();
    }
  } finally {
    await fixture.cleanup();
  }
});

test("R2E maps verifier failure without starting a repair worker", async (t) => {
  for (const [mode, expectedPhase] of [["READY_VERIFY_FAIL", "BLOCKED"], ["READY_VERIFY_RETRY", "LEAF_RETRY_READY"]] as const) {
    await t.test(mode, async () => {
      const fixture = await settledWorkerFixture(mode);
      try {
        const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
        assert.equal(result.verification_outcome, "FAILED");
        assert.equal(result.failure_class, "LOCAL_IMPLEMENTATION_DEFECT");
        assert.equal(result.final_phase, expectedPhase);
        if (expectedPhase === "LEAF_RETRY_READY") await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_EXECUTION_AUTHORITY");
        else await rejectsCode(completeDeterministicResumedStaticDag({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TERMINAL");
        const records = await readM5ManagedRecords(LOCATION(fixture.root));
        assert.equal(records.boundedWorkerInvocations.length, 1);
        assert.equal(records.boundedWorkerResults.length, 1);
        assert.equal(records.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
        assert.equal(records.commandResults.length, 1);
      } finally {
        await fixture.cleanup();
      }
    });
  }
});

test("R2E maps non-local verifier failure to a common BLOCK with exact lower-layer reason", async () => {
  const fixture = await settledWorkerFixture("READY_VERIFY_TIMEOUT");
  try {
    const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
    assert.equal(result.verification_outcome, "FAILED");
    assert.equal(result.failure_class, "TRANSIENT_TOOL_FAILURE");
    assert.equal(result.final_phase, "BLOCKED");
    assert.equal(result.final_state.terminal_reason, "BLOCKED_TRANSIENT_TOOL_FAILURE:COMMAND_TIMEOUT");
    const records = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(records.boundedWorkerInvocations.length, 1);
    assert.equal(records.boundedWorkerResults.length, 1);
    assert.equal(records.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
    assert.equal(records.commandResults.length, 1);
    assert.equal(records.commandResults[0]!.outcome, "BLOCKED");
    assert.equal(records.commandResults[0]!.failure_code, "COMMAND_TIMEOUT");
    assert.notEqual(records.commandResults[0]!.postflight_content_sha256, null);
    assert.ok(records.transitionEvents.some((event) => event.event_type === "PASS_LEAF_POSTFLIGHT"));
    assert.ok(records.workflowStates.some((state) => state.phase === "LEAF_VERIFYING"));
    const block = records.transitionEvents.find((event) => event.event_type === "BLOCK");
    assert.equal(block?.payload.reason, "BLOCKED_TRANSIENT_TOOL_FAILURE:COMMAND_TIMEOUT");
  } finally {
    await fixture.cleanup();
  }
});

test("R2E capacity reserves the fresh handover and every frozen verifier postflight", async (t) => {
  const single = await settledWorkerFixture("READY_VERIFY");
  try {
    await advanceTokenChain(single, 62);
    const singleDepth62 = await snapshotStateRoot(single.root);
    try {
      await t.test("single verifier at depth 63 refuses before handover", async () => {
        await advanceTokenChain(single, 63);
        const before = await readM5ManagedRecords(LOCATION(single.root));
        const tipBefore = durableTokenTip(before).content_sha256;
        const handoversBefore = before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length;
        const workflow = await r2eWorkflowAuthority(single.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: single.root }), "STATE_TOKEN_CHAIN_TOO_DEEP");
        } finally {
          installTestWallClock(null);
        }
        const after = await readM5ManagedRecords(LOCATION(single.root));
        assert.equal((await inspectRunStorage(LOCATION(single.root))).workflowState?.phase, "LEAF_RUNNING");
        assert.equal(durableTokenTip(after).content_sha256, tipBefore);
        assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, handoversBefore);
        assert.equal(after.usage.length, before.usage.length);
        assert.equal(after.commandResults.length, before.commandResults.length);
        assert.equal(after.boundedWorkerInvocations.length, before.boundedWorkerInvocations.length);
        assert.equal(after.boundedWorkerResults.length, before.boundedWorkerResults.length);
      });

      await singleDepth62.restore();
      await t.test("single verifier at depth 62 reaches depth 64", async () => {
        const before = await readM5ManagedRecords(LOCATION(single.root));
        const workflow = await r2eWorkflowAuthority(single.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: single.root });
          assert.equal(result.final_phase, "READY");
        } finally {
          installTestWallClock(null);
        }
        const after = await readM5ManagedRecords(LOCATION(single.root));
        assert.equal((await loadAuthoritativeToken(LOCATION(single.root), durableTokenTip(after), after.baselines[0]!)).chainDepth, 64);
        assert.equal(after.usage.length, before.usage.length + 1);
        assert.equal(after.commandResults.length, before.commandResults.length + 1);
      });
    } finally {
      await singleDepth62.cleanup();
    }
  } finally {
    await single.cleanup();
  }

  const two = await settledWorkerFixture("READY_VERIFY_TWO");
  try {
    await advanceTokenChain(two, 61);
    const twoDepth61 = await snapshotStateRoot(two.root);
    try {
      await t.test("two verifiers at depth 62 refuse before handover", async () => {
        await advanceTokenChain(two, 62);
        const before = await readM5ManagedRecords(LOCATION(two.root));
        const tipBefore = durableTokenTip(before).content_sha256;
        const handoversBefore = before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length;
        const workflow = await r2eWorkflowAuthority(two.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: two.root }), "STATE_TOKEN_CHAIN_TOO_DEEP");
        } finally {
          installTestWallClock(null);
        }
        const after = await readM5ManagedRecords(LOCATION(two.root));
        assert.equal((await inspectRunStorage(LOCATION(two.root))).workflowState?.phase, "LEAF_RUNNING");
        assert.equal(durableTokenTip(after).content_sha256, tipBefore);
        assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, handoversBefore);
        assert.equal(after.usage.length, before.usage.length);
        assert.equal(after.commandResults.length, before.commandResults.length);
        assert.equal(after.boundedWorkerInvocations.length, before.boundedWorkerInvocations.length);
        assert.equal(after.boundedWorkerResults.length, before.boundedWorkerResults.length);
      });

      await twoDepth61.restore();
      await t.test("two verifiers at depth 61 reach depth 64", async () => {
        const before = await readM5ManagedRecords(LOCATION(two.root));
        const workflow = await r2eWorkflowAuthority(two.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: two.root });
          assert.equal(result.final_phase, "READY");
        } finally {
          installTestWallClock(null);
        }
        const after = await readM5ManagedRecords(LOCATION(two.root));
        assert.equal((await loadAuthoritativeToken(LOCATION(two.root), durableTokenTip(after), after.baselines[0]!)).chainDepth, 64);
        assert.equal(after.usage.length, before.usage.length + 1);
        assert.equal(after.commandResults.length, before.commandResults.length + 2);
      });
    } finally {
      await twoDepth61.cleanup();
    }
  } finally {
    await two.cleanup();
  }
});

test("R2E capacity is restart-aware at verifier boundaries", async (t) => {
  const single = await settledWorkerFixture("READY_VERIFY");
  try {
    await advanceTokenChain(single, 62);
    const singleDepth62 = await snapshotStateRoot(single.root);
    try {
      await t.test("single verifier after durable result resumes at depth 64 without handover or rerun", async () => {
        const workflow = await r2eWorkflowAuthority(single.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          await crashR2EAt(single, "AFTER_VERIFICATION_COMMAND");
          const crashed = await readM5ManagedRecords(LOCATION(single.root));
          const crashedDepth = await loadAuthoritativeToken(LOCATION(single.root), durableTokenTip(crashed), crashed.baselines[0]!);
          assert.equal((await inspectRunStorage(LOCATION(single.root))).workflowState?.phase, "LEAF_POSTFLIGHT");
          assert.equal(crashedDepth.chainDepth, 64);
          assert.equal(crashed.commandResults.length, 1);
          assert.equal(crashed.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
          const handoversBefore = crashed.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length;
          const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: single.root });
          assert.equal(result.final_phase, "READY");
          const after = await readM5ManagedRecords(LOCATION(single.root));
          assert.equal(result.m3_tip_content_sha256, durableTokenTip(after).content_sha256);
          assert.deepEqual(result.command_result_content_sha256, [crashed.commandResults[0]!.content_sha256]);
          assert.deepEqual(result.postflight_content_sha256, [crashed.postflights.find((entry) => entry.content_sha256 === crashed.commandResults[0]!.postflight_content_sha256)!.content_sha256]);
          const afterDepth = await loadAuthoritativeToken(LOCATION(single.root), durableTokenTip(after), after.baselines[0]!);
          assert.equal(afterDepth.chainDepth, 64);
          assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, handoversBefore);
          assert.equal(after.commandResults.length, 1);
          assert.equal(after.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
          assert.equal(after.transitionEvents.filter((event) => event.event_type === "PASS_LEAF_POSTFLIGHT").length, 1);
          assert.equal(after.transitionEvents.filter((event) => event.event_type === "LEAF_VERIFICATION_PASSED").length, 1);
        } finally {
          installTestWallClock(null);
        }
      });

      await singleDepth62.restore();
      await t.test("single verifier from LEAF_VERIFYING resumes at depth 64 with only the final transition", async () => {
        const workflow = await r2eWorkflowAuthority(single.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          await crashR2EAt(single, "AFTER_PASS_LEAF_POSTFLIGHT");
          const crashed = await readM5ManagedRecords(LOCATION(single.root));
          const crashedDepth = await loadAuthoritativeToken(LOCATION(single.root), durableTokenTip(crashed), crashed.baselines[0]!);
          assert.equal((await inspectRunStorage(LOCATION(single.root))).workflowState?.phase, "LEAF_VERIFYING");
          assert.equal(crashedDepth.chainDepth, 64);
          const handoversBefore = crashed.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length;
          const commandsBefore = crashed.commandResults.length;
          const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: single.root });
          assert.equal(result.final_phase, "READY");
          const after = await readM5ManagedRecords(LOCATION(single.root));
          const afterDepth = await loadAuthoritativeToken(LOCATION(single.root), durableTokenTip(after), after.baselines[0]!);
          assert.equal(afterDepth.chainDepth, 64);
          assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, handoversBefore);
          assert.equal(after.commandResults.length, commandsBefore);
          assert.equal(after.transitionEvents.filter((event) => event.event_type === "PASS_LEAF_POSTFLIGHT").length, crashed.transitionEvents.filter((event) => event.event_type === "PASS_LEAF_POSTFLIGHT").length);
          assert.equal(after.transitionEvents.filter((event) => event.event_type === "LEAF_VERIFICATION_PASSED").length, crashed.transitionEvents.filter((event) => event.event_type === "LEAF_VERIFICATION_PASSED").length + 1);
          assert.equal(after.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
        } finally {
          installTestWallClock(null);
        }
      });
    } finally {
      await singleDepth62.cleanup();
    }
  } finally {
    await single.cleanup();
  }

  const two = await settledWorkerFixture("READY_VERIFY_TWO");
  try {
    await advanceTokenChain(two, 60);
    const twoDepth60 = await snapshotStateRoot(two.root);
    try {
      await t.test("two verifiers resume from a durable prefix with only the remaining verifier", async () => {
        const workflow = await r2eWorkflowAuthority(two.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          await crashR2EAt(two, "AFTER_VERIFICATION_COMMAND");
          const crashed = await readM5ManagedRecords(LOCATION(two.root));
          const crashedDepth = await loadAuthoritativeToken(LOCATION(two.root), durableTokenTip(crashed), crashed.baselines[0]!);
          assert.equal((await inspectRunStorage(LOCATION(two.root))).workflowState?.phase, "LEAF_POSTFLIGHT");
          assert.equal(crashedDepth.chainDepth, 62);
          assert.equal(crashed.commandResults.filter((entry) => entry.command_id === "verify").length, 1);
          assert.equal(crashed.commandResults.filter((entry) => entry.command_id === "verify2").length, 0);
          assert.equal(crashed.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
          const handoversBefore = crashed.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length;
          const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: two.root });
          assert.equal(result.final_phase, "READY");
          const after = await readM5ManagedRecords(LOCATION(two.root));
          const afterDepth = await loadAuthoritativeToken(LOCATION(two.root), durableTokenTip(after), after.baselines[0]!);
          assert.equal(afterDepth.chainDepth, 64);
          assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, handoversBefore + 1);
          assert.equal(after.commandResults.length, 2);
          assert.equal(after.commandResults.filter((entry) => entry.command_id === "verify").length, 1);
          assert.equal(after.commandResults.filter((entry) => entry.command_id === "verify2").length, 1);
          assert.equal(after.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
        } finally {
          installTestWallClock(null);
        }
      });

      await twoDepth60.restore();
      await t.test("two verifiers refuse when the remaining prefix cannot fit", async () => {
        await advanceTokenChain(two, 61);
        const workflow = await r2eWorkflowAuthority(two.root);
        installTestWallClock(() => workflow.started_at_epoch_ms);
        try {
          await crashR2EAt(two, "AFTER_VERIFICATION_COMMAND");
          const crashed = await readM5ManagedRecords(LOCATION(two.root));
          const crashedDepth = await loadAuthoritativeToken(LOCATION(two.root), durableTokenTip(crashed), crashed.baselines[0]!);
          assert.equal(crashedDepth.chainDepth, 63);
          assert.equal(crashed.commandResults.length, 1);
          assert.equal(crashed.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
          const handoversBefore = crashed.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length;
          await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: two.root }), "STATE_TOKEN_CHAIN_TOO_DEEP");
          const after = await readM5ManagedRecords(LOCATION(two.root));
          assert.equal((await inspectRunStorage(LOCATION(two.root))).workflowState?.phase, "LEAF_POSTFLIGHT");
          assert.equal((await loadAuthoritativeToken(LOCATION(two.root), durableTokenTip(after), after.baselines[0]!)).chainDepth, 63);
          assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length, handoversBefore);
          assert.equal(after.commandResults.length, 1);
          assert.equal(after.usage.filter((entry) => entry.operation_id === "static-leaf-a-attempt-1").length, 1);
        } finally {
          installTestWallClock(null);
        }
      });
    } finally {
      await twoDepth60.cleanup();
    }
  } finally {
    await two.cleanup();
  }
});

test("R2E restart windows reuse exact durable worker, usage, and verifier evidence", async (t) => {
  const cases = [
    ["BEFORE_USAGE_RECONCILIATION", "LEAF_RUNNING", "settled"],
    ["AFTER_COMPLETE_LEAF_ATTEMPT", "LEAF_POSTFLIGHT", "postflight"],
    ["AFTER_VERIFICATION_COMMAND", "LEAF_POSTFLIGHT", "postflight"],
    ["AFTER_PASS_LEAF_POSTFLIGHT", "LEAF_VERIFYING", "verifying"],
  ] as const;
  for (const [checkpoint, expectedPhase, expectedPoint] of cases) {
    await t.test(checkpoint, async () => {
      const fixture = await settledWorkerFixture("READY_VERIFY");
      try {
        configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
          if (value === checkpoint) throw new Error(`R2E crash at ${checkpoint}`);
        } });
        await assert.rejects(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), /R2E crash/);
        configureResumeReconciliationTestHooks(undefined);
        const crashed = await inspectRunStorage(LOCATION(fixture.root));
        assert.equal(crashed.workflowState?.phase, expectedPhase);
        const countsBeforeRetry = await r2eCounts(fixture.root);
        const report = await inspectDeterministicResumeEligibility({ retainedRunRoot: fixture.root });
        assert.equal(report.resume_point, expectedPhase === "LEAF_RUNNING" ? "STATIC_DAG_RECONCILE_SETTLED_LEAF:a" : expectedPhase === "LEAF_POSTFLIGHT" ? "STATIC_DAG_RECONCILE_LEAF_POSTFLIGHT:a" : "STATIC_DAG_RECONCILE_LEAF_VERIFYING:a");
        const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
        assert.equal(result.final_phase, "READY");
        const after = await r2eCounts(fixture.root);
        assert.equal(after.invocations, 1);
        assert.equal(after.results, 1);
        assert.equal(after.usage, 1);
        if (checkpoint === "AFTER_VERIFICATION_COMMAND" || checkpoint === "AFTER_PASS_LEAF_POSTFLIGHT") {
          assert.equal(after.commandResults, countsBeforeRetry.commandResults);
        }
      } finally {
        configureResumeReconciliationTestHooks(undefined);
        await fixture.cleanup();
      }
    });
  }
  await t.test("AFTER_USAGE_PUBLICATION", async () => {
    const fixture = await settledWorkerFixture("READY_VERIFY");
    try {
      configureM5PersistenceTestHooks({ checkpoint: async (value) => {
        if (value === "AFTER_USAGE_PUBLICATION") throw new Error("R2E crash after usage publication");
      } });
      await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), "M5_EVIDENCE_PUBLICATION_FAILED");
      configureM5PersistenceTestHooks(undefined);
      assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "LEAF_RUNNING");
      assert.equal((await r2eCounts(fixture.root)).usage, 1);
      const result = await reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root });
      assert.equal(result.final_phase, "READY");
      assert.equal((await r2eCounts(fixture.root)).usage, 1);
    } finally {
      configureM5PersistenceTestHooks(undefined);
      await fixture.cleanup();
    }
  });
});

test("R2E timing expiry refuses before reconciliation, after completion, and before verification transition", async (t) => {
  await t.test("before reconciliation", async () => {
    const fixture = await settledWorkerFixture("READY_VERIFY");
    try {
      const workflow = await r2eWorkflowAuthority(fixture.root);
      installTestWallClock(() => workflow.started_at_epoch_ms + workflow.wall_budget_ms);
      await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
      assert.deepEqual(await r2eCounts(fixture.root), { usage: 0, decisions: 3, invocations: 1, results: 1, commandResults: 0, postflights: 1 });
    } finally {
      installTestWallClock(null); await fixture.cleanup();
    }
  });

  await t.test("after COMPLETE_LEAF_ATTEMPT", async () => {
    const fixture = await settledWorkerFixture("READY_VERIFY");
    try {
      const workflow = await r2eWorkflowAuthority(fixture.root);
      configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
        if (value === "AFTER_COMPLETE_LEAF_ATTEMPT") installTestWallClock(() => workflow.started_at_epoch_ms + workflow.wall_budget_ms);
      } });
      await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
      assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "LEAF_POSTFLIGHT");
      assert.equal((await r2eCounts(fixture.root)).commandResults, 0);
    } finally {
      configureResumeReconciliationTestHooks(undefined); installTestWallClock(null); await fixture.cleanup();
    }
  });

  await t.test("before verification transition", async () => {
    const fixture = await settledWorkerFixture("READY_VERIFY");
    try {
      const workflow = await r2eWorkflowAuthority(fixture.root);
      configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
        if (value === "AFTER_VERIFICATION_COMMAND") installTestWallClock(() => workflow.started_at_epoch_ms + workflow.wall_budget_ms);
      } });
      await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_TIMING_AUTHORITY");
      assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "LEAF_POSTFLIGHT");
      assert.equal((await r2eCounts(fixture.root)).commandResults, 1);
    } finally {
      configureResumeReconciliationTestHooks(undefined); installTestWallClock(null); await fixture.cleanup();
    }
  });
});

test("R2E does not repeat a committed final verification transition", async () => {
  const fixture = await settledWorkerFixture("READY_VERIFY");
  try {
    configureResumeReconciliationTestHooks({ checkpoint: async (value) => {
      if (value === "AFTER_LEAF_VERIFICATION_TRANSITION") throw new Error("R2E final transition response lost");
    } });
    await assert.rejects(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), /R2E final transition response lost/);
    configureResumeReconciliationTestHooks(undefined);
    const before = await r2eCounts(fixture.root);
    assert.equal((await inspectRunStorage(LOCATION(fixture.root))).workflowState?.phase, "READY");
    await rejectsCode(reconcileDeterministicResumedLeaf({ retainedRunRoot: fixture.root }), "RESUME_REFUSED_EXECUTION_AUTHORITY");
    assert.deepEqual(await r2eCounts(fixture.root), before);
  } finally {
    configureResumeReconciliationTestHooks(undefined); await fixture.cleanup();
  }
});
