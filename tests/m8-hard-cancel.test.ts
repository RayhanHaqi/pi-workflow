import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { inspectRunStorage } from "../src/persistence/index.js";
import { forceStopBoundedMutationWorkflow, runBoundedMutationWorkflowExternalForTests, type BoundedMutationGoal, type ExternalLifecycleFixtureMode } from "../src/workflow-controller.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture } from "./repository-helpers.js";

const execFileAsync = promisify(execFile);

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "m8-r1-repo-"));
  await execFileAsync("git", ["init", "-q", "-b", "main"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "m8@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "M8"], { cwd: root });
  await mkdir(join(root, "verify")); await writeFile(join(root, "verify", "input.txt"), "verify\n");
  await execFileAsync("git", ["add", "verify/input.txt"], { cwd: root }); await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

function authority() { return { verification_commands: [{ command_id: "verify", executable: "/usr/bin/true", cwd: "verify" }] } as const; }
function goal(): BoundedMutationGoal {
  return {
    objective: "bounded external lifecycle fixture", stop_condition: "stop on cancellation", execution_mode: "DIRECT_LUNA_HIGH",
    scope: { readable_paths: ["verify", "verify/input.txt"], editable_paths: ["out.txt"], frozen_paths: [] }, required_outputs: ["out.txt"],
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve };
}

interface StartedFixture {
  readonly root: string;
  readonly retained: string;
  readonly capability: string;
  readonly record: Record<string, unknown>;
  readonly pending: Promise<Awaited<ReturnType<typeof runBoundedMutationWorkflowExternalForTests>>>;
}

async function startFixture(mode: ExternalLifecycleFixtureMode, waitForStage = true): Promise<StartedFixture> {
  const root = await repository(); const retained = await mkdtemp(join(tmpdir(), "m8-r1-retained-")); const capability = deferred<string>(); const stage = deferred<string>();
  const pending = runBoundedMutationWorkflowExternalForTests(goal(), {
    cwd: root, authority: authority(), retainedArtifactRoot: retained,
    approveTasks: async ({ contract }) => contract.content_sha256 as `sha256:${string}`,
    onControlCapability: ({ path }) => { capability.resolve(path); },
  }, mode, (value) => stage.resolve(value));
  const path = await capability.promise;
  if (waitForStage) await stage.promise;
  return { root, retained, capability: path, record: JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>, pending };
}

async function dispose(value: Pick<StartedFixture, "root" | "retained">): Promise<void> {
  await rm(value.root, { recursive: true, force: true }); await rm(value.retained, { recursive: true, force: true });
}

async function pidGone(pid: number): Promise<boolean> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { process.kill(pid, 0); } catch (error: unknown) { if ((error as { code?: string }).code === "ESRCH") return true; }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}

async function sessionPids(sessionId: number): Promise<number[]> {
  const entries = await (await import("node:fs/promises")).readdir("/proc"); const result: number[] = [];
  for (const entry of entries) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const value = await readFile(`/proc/${entry}/stat`, "utf8"); const close = value.lastIndexOf(")"); const fields = value.slice(close + 1).trim().split(/\s+/u);
      if (Number(fields[3]) === sessionId && fields[0] !== "Z") result.push(Number(entry));
    } catch { /* process exited during bounded inspection */ }
  }
  return result.sort((left, right) => left - right);
}

function stateRoot(value: StartedFixture): string { return value.record["state_root"] as string; }
function productivePid(value: StartedFixture): number { return value.record["productive_pid"] as number; }

async function stop(value: StartedFixture, grace = 20) {
  const forced = await forceStopBoundedMutationWorkflow(value.capability, grace); const result = await value.pending; return { forced, result };
}

async function cliForceStop(capability: string): Promise<{ readonly code: number; readonly stdout: string }> {
  const child = spawn(process.execPath, ["--import", "tsx", join(process.cwd(), "src", "cli", "pi-workflow.ts"), "force-stop", capability], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
  const output: Buffer[] = []; child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
  const code = await new Promise<number>((resolve, reject) => { child.once("error", reject); child.once("close", (value) => resolve(value ?? 1)); });
  return { code, stdout: Buffer.concat(output).toString("utf8") };
}

test("R1-T01 parent remains responsive and hard-stops a hung productive controller", async () => {
  const value = await startFixture("HANG");
  try {
    const started = Date.now(); const { forced, result } = await stop(value);
    assert.ok(Date.now() - started < 12_000, "external parent remained responsive while child event loop was blocked");
    assert.ok(["BLOCKED_CANCELLED", "BLOCKED_FORCE_TERMINATED"].includes(forced.disposition), forced.detail);
    assert.equal(result.outcome, "BLOCKED"); assert.notEqual(result.outcome, "PASS");
    assert.equal(await pidGone(productivePid(value)), true);
  } finally { await dispose(value); }
});

test("R1 external CLI force-stop reaches the invocation-local parent", async () => {
  const value = await startFixture("HANG");
  try {
    const cli = await cliForceStop(value.capability); const result = await value.pending;
    assert.equal(cli.code, 0, cli.stdout); assert.match(cli.stdout, /BLOCKED_(?:CANCELLED|FORCE_TERMINATED)/); assert.equal(result.outcome, "BLOCKED");
  } finally { await dispose(value); }
});

test("R1-T02/R1-T04 CANCELLED atomically wins over internal PASS before outward completion", async () => {
  const value = await startFixture("INTERNAL_PASS_WAIT");
  try {
    const { forced, result } = await stop(value);
    assert.ok(["BLOCKED_CANCELLED", "BLOCKED_FORCE_TERMINATED"].includes(forced.disposition), forced.detail);
    const claim = JSON.parse(await readFile(join(dirname(value.capability), "completion.claim.json"), "utf8")) as Record<string, unknown>;
    assert.equal(claim["winner"], "CANCELLED"); assert.equal(result.outcome, "BLOCKED");
    assert.equal(result.finalState?.phase, "PASS", "immutable internal PASS history is not rewritten to fake cancellation consistency");
  } finally { await dispose(value); }
});

test("D-01/R1-T03 COMPLETE remains a recognized successful lifecycle result", async () => {
  const value = await startFixture("COMPLETE", false);
  try {
    const result = await value.pending;
    assert.equal(result.outcome, "PASS", result.reason);
    assert.equal(result.lifecycleDiagnostic, undefined, "a recognized RESULT must retain existing successful lifecycle semantics");
    assert.equal(result.evidenceRoot, dirname(value.capability), "the external parent preserves its caller-retained evidence root");
    const forced = await forceStopBoundedMutationWorkflow(value.capability, 0);
    assert.equal(forced.disposition, "ALREADY_TERMINAL", forced.detail);
    const claim = JSON.parse(await readFile(join(dirname(value.capability), "completion.claim.json"), "utf8")) as Record<string, unknown>;
    assert.equal(claim["winner"], "COMPLETED");
  } finally { await dispose(value); }
});

test("D-02/D-05 early provider-free exit retains process evidence and admits no productive authority", async () => {
  const root = await repository(); const retained = await mkdtemp(join(tmpdir(), "m8-r1-retained-")); let baselineApprovals = 0; let taskApprovals = 0;
  try {
    const result = await runBoundedMutationWorkflowExternalForTests(goal(), {
      cwd: root, authority: authority(), retainedArtifactRoot: retained,
      approveBaseline: async () => { baselineApprovals += 1; return null; },
      approveTasks: async () => { taskApprovals += 1; return null; },
    }, "EARLY_EXIT");
    assert.equal(result.outcome, "BLOCKED"); assert.notEqual(result.outcome, "PASS"); assert.equal(result.finalState, null);
    assert.match(result.reason, /^BLOCKED_PROCESS_CRASH_RECONCILIATION_UNCERTAIN:/, "early child death remains fail-closed");
    assert.equal(baselineApprovals, 0); assert.equal(taskApprovals, 0, "child death precedes M5 reservation and provider admission");
    const evidenceRoot = result.evidenceRoot; assert.ok(evidenceRoot !== undefined);
    await assert.rejects(lstat(join(evidenceRoot, "state", "runs")), { code: "ENOENT" }, "no M2/M5 run exists before the fixture exits");
    const diagnostic = result.lifecycleDiagnostic; assert.ok(diagnostic !== undefined);
    assert.ok(diagnostic.childPid !== null && diagnostic.childPid > 1); assert.equal(diagnostic.childExecPath, process.execPath); assert.equal(diagnostic.childCwd, root);
    assert.equal(diagnostic.spawnObserved, true); assert.equal(diagnostic.spawnError, null); assert.equal(diagnostic.processError, null);
    assert.equal(diagnostic.startSendAttempted, true); assert.equal(diagnostic.startSendCallback, "SUCCEEDED"); assert.equal(diagnostic.startSendError, null);
    assert.equal(diagnostic.ipcMessageReceived, false); assert.equal(diagnostic.firstIpcMessageKind, null); assert.equal(diagnostic.recognizedResultReceived, false); assert.equal(diagnostic.malformedResultReceived, false); assert.equal(diagnostic.ipcDisconnected, true);
    assert.equal(diagnostic.exitObserved, true); assert.equal(diagnostic.exitCode, 23); assert.equal(diagnostic.exitSignal, null);
    assert.equal(diagnostic.closeObserved, true); assert.equal(diagnostic.closeCode, 23); assert.equal(diagnostic.closeSignal, null);
    assert.equal(diagnostic.childExitPhase, "AFTER_START_ACKNOWLEDGEMENT"); assert.match(diagnostic.stderrTail ?? "", /fixture early exit/); assert.equal(diagnostic.stderrTailTruncated, false);
  } finally { await dispose({ root, retained }); }
});

test("D-04 malformed RESULT remains distinct from no RESULT", async () => {
  const root = await repository(); const retained = await mkdtemp(join(tmpdir(), "m8-r1-retained-"));
  try {
    const result = await runBoundedMutationWorkflowExternalForTests(goal(), {
      cwd: root, authority: authority(), retainedArtifactRoot: retained,
      approveTasks: async ({ contract }) => contract.content_sha256 as `sha256:${string}`,
    }, "MALFORMED_RESULT");
    assert.equal(result.outcome, "BLOCKED"); assert.match(result.reason, /BLOCKED_CHILD_RESULT_INVALID/);
    const diagnostic = result.lifecycleDiagnostic; assert.ok(diagnostic !== undefined);
    assert.equal(diagnostic.recognizedResultReceived, false); assert.equal(diagnostic.malformedResultReceived, true);
    assert.equal(diagnostic.ipcMessageReceived, true); assert.equal(diagnostic.firstIpcMessageKind, "RESULT");
    assert.equal(diagnostic.exitCode, 24); assert.equal(diagnostic.exitSignal, null); assert.equal(diagnostic.closeCode, 24); assert.equal(diagnostic.closeSignal, null);
    assert.equal(diagnostic.childExitPhase, "AFTER_IPC_MESSAGE");
  } finally { await dispose({ root, retained }); }
});

test("R1-T05/R1-T06/R1-T07 invocation session containment leaves unrelated sessions untouched", async () => {
  const value = await startFixture("HANG"); const unrelated = spawn(process.execPath, ["-e", "setInterval(() => undefined, 1000);"], { stdio: "ignore" });
  try {
    const sessionId = value.record["invocation_session_id"] as number; const before = await sessionPids(sessionId);
    assert.ok(before.includes(productivePid(value)), "productive child leads the recorded invocation session");
    const { forced } = await stop(value); assert.ok(["BLOCKED_CANCELLED", "BLOCKED_FORCE_TERMINATED"].includes(forced.disposition), forced.detail);
    for (const pid of before) assert.equal(await pidGone(pid), true, `session member ${pid} is no longer productive`);
    assert.notEqual(unrelated.pid, undefined); assert.equal(await pidGone(unrelated.pid!), false, "unrelated control process is outside the invocation session");
  } finally { try { unrelated.kill("SIGKILL"); } catch { /* already gone */ } await dispose(value); }
});

test("R1-T08 PID/start/session mismatch fails closed without destructive signaling", async () => {
  const value = await startFixture("HANG");
  try {
    const altered = { ...value.record, productive_start_ticks: "0" };
    await writeFile(value.capability, `${JSON.stringify(altered)}\n`, { mode: 0o600 }); await chmod(value.capability, 0o600);
    const invalid = await forceStopBoundedMutationWorkflow(value.capability, 0);
    assert.equal(invalid.disposition, "BLOCKED_FORCE_STOP_CAPABILITY_INVALID"); assert.equal(await pidGone(productivePid(value)), false);
    const mismatchedWorktree = { ...value.record, worktree_key: `sha256:${"0".repeat(64)}` };
    await writeFile(value.capability, `${JSON.stringify(mismatchedWorktree)}\n`, { mode: 0o600 }); await chmod(value.capability, 0o600);
    const mismatched = await forceStopBoundedMutationWorkflow(value.capability, 0);
    assert.equal(mismatched.disposition, "BLOCKED_FORCE_STOP_CAPABILITY_INVALID"); assert.equal(await pidGone(productivePid(value)), false);
    await writeFile(value.capability, `${JSON.stringify(value.record)}\n`, { mode: 0o600 }); await chmod(value.capability, 0o600);
    await stop(value);
  } finally { await dispose(value); }
});

test("R1-T09 M2 crash terminalization is reused after abnormal child death", async () => {
  const value = await startFixture("HANG");
  try {
    const { result } = await stop(value); const inspection = await inspectRunStorage({ stateRoot: stateRoot(value), runId: "pre-m8-bounded" });
    assert.equal(result.outcome, "BLOCKED"); assert.equal(inspection.workflowState?.phase, "BLOCKED"); assert.equal(inspection.workflowState?.terminal_reason, "BLOCKED_PROCESS_CRASH");
  } finally { await dispose(value); }
});

test("R1-T10 M3 reconciliation distinguishes clean, known owned, and unexpected deltas", async (t) => {
  await t.test("clean", async () => {
    const value = await startFixture("HANG");
    try { const { forced } = await stop(value); assert.match(forced.detail, /M3=UNCHANGED_CLEAN/); } finally { await dispose(value); }
  });
  await t.test("known workflow-owned delta", async () => {
    const value = await startFixture("WRITE_AND_HANG");
    try { const { forced } = await stop(value); assert.match(forced.detail, /M3=KNOWN_WORKFLOW_OWNED_DELTA/); } finally { await dispose(value); }
  });
  await t.test("unexpected drift", async () => {
    const value = await startFixture("WRITE_AND_HANG");
    try {
      await writeFile(join(value.root, "verify", "input.txt"), "unexpected drift\n");
      const { forced, result } = await stop(value); assert.match(forced.detail, /M3=UNEXPECTED_DRIFT/); assert.equal(result.outcome, "BLOCKED");
    } finally { await dispose(value); }
  });
});

test("R1-T11 lock uncertainty fails closed and R1-T12 has no automatic replacement", async () => {
  const value = await startFixture("HANG");
  try {
    await writeFile(join(stateRoot(value), "locks", "unexpected"), "unsafe\n", { mode: 0o600 });
    const { forced, result } = await stop(value);
    assert.equal(forced.disposition, "BLOCKED_FORCE_STOP_RECONCILIATION_UNCERTAIN"); assert.equal(result.outcome, "BLOCKED");
    assert.equal(await pidGone(productivePid(value)), true); assert.equal((await sessionPids(value.record["invocation_session_id"] as number)).length, 0);
  } finally { await dispose(value); }
});

test("R1-T05 M4 sandbox keeps its own process group while retaining its inherited session", async () => {
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    const script = join(temporaryRoot, "session.py"); await writeFile(script, "import os\nprint(f'{os.getsid(0)} {os.getpgrp()}')\n", { mode: 0o600 });
    return [await commandSpecification("session", "INSPECTION", "/usr/bin/python3", [script], { repositoryRoot: fixture.repository })];
  });
  try {
    const result = await value.gateway.run_inspection_command({ commandId: "session", stateTokenContentSha256: value.gateway.acceptedState.content_sha256 as `sha256:${string}` });
    const [sandboxSession, sandboxGroup] = Buffer.from(result.stdoutBase64, "base64").toString("utf8").trim().split(" ").map(Number);
    const self = await readFile(`/proc/${process.pid}/stat`, "utf8"); const fields = self.slice(self.lastIndexOf(")") + 1).trim().split(/\s+/u);
    assert.equal(sandboxSession, Number(fields[3])); assert.notEqual(sandboxGroup, Number(fields[2]));
  } finally { await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture); }
});
