import assert from "node:assert/strict";
import { access, readdir, readFile } from "node:fs/promises";
import { fork } from "node:child_process";
import { rm } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import { loadAuthoritativeToken } from "../src/repository/token-provenance.js";
import { acquireWorktreeLock, probeWorktreeLockAvailability, releaseWorktreeLock, resolveRepositoryIdentity, runResumeLockHandover } from "../src/repository/index.js";
import { acquireDeterministicResumeAdmission, DeterministicResumeAdmissionError } from "../src/resume-admission.js";
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

type FixtureMode = "READY" | "READY_LIMIT_1" | "DELTA";
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

function startWorkerChild(root: string, mode: "EXEC_HOLD" | "HANG_IN_RUNTIME" | "RESULT_PAUSE" | "HANDOVER_PAUSE" | "DEPTH_REFUSE" | "EXPIRE_BEFORE_HANDOVER" | "EXPIRE_AFTER_HANDOVER" | "EXPIRE_BEFORE_INVOCATION", waitMs = 120_000): WorkerChild {
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
  const worker = startWorkerChild(fixture.root, "EXEC_HOLD");
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
    // CAPABILITY TRANSFER: old work admission consumed; result capability holds the same flock.
    await rejectsCode(acquireWorktreeLock({ stateRoot: join(fixture.root, "state"), repository: await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }) }), "LOCK_BUSY");
    worker.child.send({ command: "RELEASE" });
    await worker.next("RELEASED");
    const temporaryRootsAfter = (await readdir(tmpdir())).filter((entry) => entry.startsWith("pi-resumed-worker-") && !temporaryRootsBefore.has(entry));
    assert.deepEqual(temporaryRootsAfter, []); // successful release removes the controller-owned temporary root
    assert.equal(await probeWorktreeLockAvailability({ stateRoot: join(fixture.root, "state"), repository: await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true }) }), "LOCK_AVAILABLE");
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
  const worker = startWorkerChild(fixture.root, "EXEC_HOLD");
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
    worker.child.send({ command: "RELEASE" });
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
    assert.equal(report.classification, "RESUME_REFUSED");
    await assert.rejects(acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root }));
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

    recovery = startWorkerChild(fixture.root, "EXEC_HOLD");
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
    recovery.child.send({ command: "RELEASE" });
    await recovery.next("RELEASED");
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
    worker = startWorkerChild(fixture.root, "EXEC_HOLD", 600_000);
    const executed = await worker.next("EXECUTED") as unknown as { readonly type: string; readonly binding: { readonly final_gateway_state_token_content_sha256: Sha256Digest } };
    assert.equal(executed.type, "EXECUTED");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    const finalAuthority = await loadAuthoritativeToken(LOCATION(fixture.root), durableTokenTip(after), after.baselines[0]!);
    assert.equal(finalAuthority.chainDepth, 64);
    assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
      before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length + 1);
    assert.equal(executed.binding.final_gateway_state_token_content_sha256, durableTokenTip(after).content_sha256);
    worker.child.send({ command: "RELEASE" });
    await worker.next("RELEASED");
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
    worker = startWorkerChild(fixture.root, "EXEC_HOLD");
    const executed = await worker.next("EXECUTED") as unknown as { readonly type: string };
    assert.equal(executed.type, "EXECUTED");
    const after = await readM5ManagedRecords(LOCATION(fixture.root));
    assert.equal(after.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length,
      before.stateTokens.filter((token) => token.source === "RESUME_LOCK_HANDOVER").length + 1);
    worker.child.send({ command: "RELEASE" });
    await worker.next("RELEASED");
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
