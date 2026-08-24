import assert from "node:assert/strict";
import { execFile, fork } from "node:child_process";
import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalize } from "../src/canonical-json/index.js";
import type { Sha256Digest } from "../src/identity/index.js";
import { commitTransition, inspectRunStorage } from "../src/persistence/index.js";
import { readM5ManagedRecords } from "../src/persistence/store.js";
import {
  acquireWorktreeLock,
  probeWorktreeLockAvailability,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";
import {
  acquireDeterministicResumeAdmission,
  assertDeterministicResumeAdmissionHeld,
  DeterministicResumeAdmissionError,
  releaseDeterministicResumeAdmission,
} from "../src/resume-admission.js";
import { inspectDeterministicResumeEligibility } from "../src/resume-inspection.js";
import { captureGitState } from "../src/repository/fingerprint.js";
import { processMetadata } from "./persistence-helpers.js";
import { transitionEvent } from "./helpers.js";

const execFileAsync = promisify(execFile);

type FixtureMode = "READY" | "DELTA";
type ChildFixture = { readonly child: ReturnType<typeof fork>; readonly root: string; readonly repository: string; readonly cleanup: () => Promise<void> };

async function startFixture(mode: FixtureMode): Promise<ChildFixture> {
  const child = fork(new URL("./resume-inspection-child.ts", import.meta.url), [mode], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const message = await new Promise<{ readonly root: string; readonly repository: string }>((resolve, reject) => {
    const onExit = (code: number | null, signal: NodeJS.Signals | null): void => reject(new Error(`fixture owner exited before pause: code=${code} signal=${signal}`));
    child.once("exit", onExit);
    child.once("message", (value: unknown) => {
      child.off("exit", onExit);
      if (value !== null && typeof value === "object" && (value as { readonly type?: unknown }).type === "PAUSED" &&
        typeof (value as { readonly root?: unknown }).root === "string" && typeof (value as { readonly repository?: unknown }).repository === "string") {
        resolve(value as { readonly root: string; readonly repository: string });
      } else reject(new Error(`fixture child failed: ${JSON.stringify(value)}`));
    });
  });
  return {
    child,
    ...message,
    cleanup: async () => { await rm(dirname(message.root), { recursive: true, force: true }); await rm(message.repository, { recursive: true, force: true }); },
  };
}

async function interruptFixture(mode: FixtureMode): Promise<Omit<ChildFixture, "child">> {
  const fixture = await startFixture(mode);
  await new Promise<void>((resolve, reject) => {
    fixture.child.once("exit", (_code, signal) => signal === "SIGKILL" ? resolve() : reject(new Error(`fixture owner exited unexpectedly: ${signal}`)));
    fixture.child.kill("SIGKILL");
  });
  return { root: fixture.root, repository: fixture.repository, cleanup: fixture.cleanup };
}

async function inventory(root: string): Promise<readonly string[]> {
  const visit = async (directory: string, prefix = ""): Promise<string[]> => {
    const output: string[] = [];
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((left, right) => left.name.localeCompare(right.name))) {
      const path = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
      output.push(path); if (entry.isDirectory() && !entry.isSymbolicLink()) output.push(...await visit(join(directory, entry.name), path));
    }
    return output;
  };
  return visit(root);
}

async function eventuallyResumable(root: string) {
  let report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  for (let attempt = 0; report.classification !== "RESUMABLE" && attempt < 100; attempt += 1) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25)); report = await inspectDeterministicResumeEligibility({ retainedRunRoot: root });
  }
  return report;
}

function codeOf(error: unknown): unknown { return error !== null && typeof error === "object" ? (error as { readonly code?: unknown }).code : undefined; }

async function rejectsCode(promise: Promise<unknown>, expected: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => codeOf(error) === expected || (error instanceof DeterministicResumeAdmissionError && error.code === expected));
}

async function m2Snapshot(root: string, repository: string) {
  const statePath = join(root, "state", "runs", "pre-m8-bounded", "state.json");
  return Promise.all([readFile(statePath), inventory(join(root, "state", "runs")), resolveRepositoryIdentity({ requestedPath: repository, requireHead: true }).then(captureGitState)]);
}

test("quiescent READY admission binds fresh state while retaining the M3 flock until release", async () => {
  const fixture = await interruptFixture("READY"); let admission: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).classification, "RESUMABLE");
    const [stateBefore, inventoryBefore, gitBefore] = await m2Snapshot(fixture.root, fixture.repository);
    admission = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    assert.equal(admission.binding.resume_point, "STATIC_DAG_SELECT_READY_LEAF:a");
    assert.equal(admission.binding.run_id, "pre-m8-bounded");
    assert.equal(Object.isFrozen(admission.binding), true);
    await assertDeterministicResumeAdmissionHeld(admission);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    await rejectsCode(acquireWorktreeLock({ stateRoot: join(fixture.root, "state"), repository }), "LOCK_BUSY");
    const [stateAfter, inventoryAfter, gitAfter] = await m2Snapshot(fixture.root, fixture.repository);
    assert.deepEqual(stateAfter, stateBefore); assert.deepEqual(inventoryAfter, inventoryBefore); assert.equal(canonicalize(gitAfter), canonicalize(gitBefore));
    await releaseDeterministicResumeAdmission(admission); admission = undefined;
    assert.equal(await probeWorktreeLockAvailability({ stateRoot: join(fixture.root, "state"), repository }), "LOCK_AVAILABLE");
  } finally {
    if (admission !== undefined) await releaseDeterministicResumeAdmission(admission).catch(() => undefined);
    await fixture.cleanup();
  }
});

test("live owner and post-inspection competing lock both refuse admission without state changes", async () => {
  const live = await startFixture("READY");
  try {
    const [stateBefore, inventoryBefore, gitBefore] = await m2Snapshot(live.root, live.repository);
    await rejectsCode(acquireDeterministicResumeAdmission({ retainedRunRoot: live.root }), "LOCK_BUSY");
    const [stateAfter, inventoryAfter, gitAfter] = await m2Snapshot(live.root, live.repository);
    assert.deepEqual(stateAfter, stateBefore); assert.deepEqual(inventoryAfter, inventoryBefore); assert.equal(canonicalize(gitAfter), canonicalize(gitBefore));
  } finally { live.child.kill("SIGKILL"); await fixtureExit(live.child); await live.cleanup(); }

  const fixture = await interruptFixture("READY"); let competing: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).classification, "RESUMABLE");
    const [stateBefore, inventoryBefore, gitBefore] = await m2Snapshot(fixture.root, fixture.repository);
    const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
    competing = await acquireWorktreeLock({ stateRoot: join(fixture.root, "state"), repository });
    await rejectsCode(acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root }), "LOCK_BUSY");
    const [stateAfter, inventoryAfter, gitAfter] = await m2Snapshot(fixture.root, fixture.repository);
    assert.deepEqual(stateAfter, stateBefore); assert.deepEqual(inventoryAfter, inventoryBefore); assert.equal(canonicalize(gitAfter), canonicalize(gitBefore));
  } finally {
    if (competing !== undefined) await releaseWorktreeLock(competing).catch(() => undefined);
    await fixture.cleanup();
  }
});

async function fixtureExit(child: ReturnType<typeof fork>): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => child.once("exit", () => resolve()));
}

test("under-lock repository drift and fresh state-pointer revalidation refuse stale observational reports", async () => {
  const drift = await interruptFixture("READY");
  try {
    assert.equal((await eventuallyResumable(drift.root)).classification, "RESUMABLE");
    const [stateBefore, inventoryBefore] = await m2Snapshot(drift.root, drift.repository);
    await writeFile(join(drift.repository, "unexpected.txt"), "drift\n");
    await rejectsCode(acquireDeterministicResumeAdmission({ retainedRunRoot: drift.root }), "RESUME_REFUSED_STATE_DRIFT");
    assert.equal(await readFile(join(drift.repository, "unexpected.txt"), "utf8"), "drift\n");
    const [stateAfter, inventoryAfter] = await m2Snapshot(drift.root, drift.repository);
    assert.deepEqual(stateAfter, stateBefore); assert.deepEqual(inventoryAfter, inventoryBefore);
  } finally { await drift.cleanup(); }

  const stale = await interruptFixture("READY"); let lock: Awaited<ReturnType<typeof acquireWorktreeLock>> | undefined;
  try {
    assert.equal((await eventuallyResumable(stale.root)).classification, "RESUMABLE");
    const location = { stateRoot: join(stale.root, "state"), runId: "pre-m8-bounded" };
    const initial = await inspectRunStorage(location); const records = await readM5ManagedRecords(location);
    const policy = records.reducerPolicies.find((entry) => entry.content_sha256 === initial.workflowState!.frozen_policy_content_sha256)!;
    const repository = await resolveRepositoryIdentity({ requestedPath: stale.repository, requireHead: true });
    lock = await acquireWorktreeLock({ stateRoot: location.stateRoot, repository });
    await commitTransition({
      ...location,
      expectedRevision: initial.revision!, expectedStatePointerContentSha256: initial.statePointer!.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: initial.workflowState!.content_sha256 as Sha256Digest, transitionId: "resume-admission-stale-point", policy,
      event: transitionEvent("SELECT_READY_LEAF"), processMetadata,
    });
    await releaseWorktreeLock(lock); lock = undefined;
    assert.equal((await eventuallyResumable(stale.root)).reason, "RESUME_REFUSED_AMBIGUOUS_RESUME_POINT");
    await rejectsCode(acquireDeterministicResumeAdmission({ retainedRunRoot: stale.root }), "RESUME_REFUSED_AMBIGUOUS_RESUME_POINT");
  } finally {
    if (lock !== undefined) await releaseWorktreeLock(lock).catch(() => undefined);
    await stale.cleanup();
  }
});

test("quiescent workflow-owned delta admits the fresh deterministic leaf", async () => {
  const fixture = await interruptFixture("DELTA"); let admission: Awaited<ReturnType<typeof acquireDeterministicResumeAdmission>> | undefined;
  try {
    assert.equal((await eventuallyResumable(fixture.root)).resume_point, "STATIC_DAG_SELECT_READY_LEAF:b");
    admission = await acquireDeterministicResumeAdmission({ retainedRunRoot: fixture.root });
    assert.equal(admission.binding.resume_point, "STATIC_DAG_SELECT_READY_LEAF:b");
    await assertDeterministicResumeAdmissionHeld(admission);
  } finally {
    if (admission !== undefined) await releaseDeterministicResumeAdmission(admission).catch(() => undefined);
    await fixture.cleanup();
  }
});
