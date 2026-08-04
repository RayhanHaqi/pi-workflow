import assert from "node:assert/strict";
import { execFile, fork, type ChildProcess } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalize } from "../src/canonical-json/index.js";
import { evaluateAuthority, orderDecisionHistory } from "../src/control/evaluate.js";
import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { identifyContractDocument, type M3RepositoryStateTokenDocument, type M5ControlDecisionDocument } from "../src/schemas/index.js";
import { digest, transitionEvent, type MutableJson } from "./helpers.js";
import { createM5R3Fixture, directFastPreflightFixture, removeM5R3Fixture, usage, type M5R3Fixture } from "./m5-r3-fixtures.js";
import { processMetadata } from "./persistence-helpers.js";

const execFileAsync = promisify(execFile);
const verifierRoot = await mkdtemp("/tmp/m5r5."); await chmod(verifierRoot, 0o700);
const childDriver = resolve("dist/tests/m5-r3-child.js");
type ChildExit = { readonly code: number | null; readonly signal: NodeJS.Signals | null };
type ChildRegistry = {
  readonly live: Set<ChildProcess>;
  readonly all: Set<ChildProcess>;
  readonly exits: WeakMap<ChildProcess, Promise<ChildExit>>;
  readonly modes: WeakMap<ChildProcess, string>;
  readonly states: WeakMap<ChildProcess, string>;
  readonly errors: Map<ChildProcess, Error>;
};
const registryByChild = new WeakMap<ChildProcess, ChildRegistry>();
function createChildRegistry(): ChildRegistry {
  return { live: new Set(), all: new Set(), exits: new WeakMap(), modes: new WeakMap(), states: new WeakMap(), errors: new Map() };
}
async function waitBounded(promise: Promise<unknown>, milliseconds: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  try { return await Promise.race([promise.then(() => true), new Promise<false>((resolveWait) => { timer = setTimeout(() => resolveWait(false), milliseconds); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && typeof (error as { code?: unknown }).code === "string" ? (error as { code: string }).code : undefined;
}
async function cleanupChildren(registry: ChildRegistry): Promise<void> {
  let failure: unknown;
  const note = (error: unknown): void => { if (failure === undefined && errorCode(error) !== "ERR_IPC_CHANNEL_CLOSED" && errorCode(error) !== "ESRCH") failure = error; };
  const send = (child: ChildProcess, message: string): void => {
    if (!child.connected || child.killed) return;
    try { child.send(message); } catch (error: unknown) { note(error); }
  };
  for (const child of registry.live) {
    if (registry.modes.get(child) === "lock" && registry.states.get(child) === "checkpoint") { send(child, "CONTINUE"); send(child, "RELEASE"); }
    else if (registry.modes.get(child) === "lock") send(child, "RELEASE");
    else send(child, "CONTINUE");
  }
  const exits = [...registry.all].map((child) => registry.exits.get(child)!);
  await waitBounded(Promise.all(exits), 500);
  for (const child of registry.live) { try { child.kill("SIGTERM"); } catch (error: unknown) { note(error); } }
  await waitBounded(Promise.all(exits), 500);
  for (const child of registry.live) { try { child.kill("SIGKILL"); } catch (error: unknown) { note(error); } }
  await Promise.all(exits);
  for (const child of registry.all) {
    try { if (child.connected) child.disconnect(); } catch (error: unknown) { note(error); }
    try { child.stdout?.destroy(); child.stderr?.destroy(); } catch (error: unknown) { note(error); }
  }
  const childError = [...registry.errors.values()][0]; if (failure === undefined && childError !== undefined) failure = childError;
  if (failure !== undefined) throw failure;
}
async function countOwnedArtifacts(root: string): Promise<{ readonly sockets: number; readonly fifos: number; readonly checkpointFiles: number }> {
  let sockets = 0; let fifos = 0; let checkpointFiles = 0;
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory() && !entry.isSymbolicLink()) { await walk(path); continue; }
      const stats = await lstat(path); if (stats.isSocket()) sockets += 1; if (stats.isFIFO()) fifos += 1; if (/checkpoint/i.test(entry.name)) checkpointFiles += 1;
    }
  };
  await walk(root); return { sockets, fifos, checkpointFiles };
}
async function cleanupFixture(registry: ChildRegistry, fixture: M5R3Fixture): Promise<void> {
  let failure: unknown;
  const note = (error: unknown): void => { if (failure === undefined) failure = error; };
  try { await cleanupChildren(registry); assert.equal(registry.live.size, 0); assert.equal([...registry.all].some((child) => child.connected), false); }
  catch (error: unknown) { note(error); }
  try { for (const name of await m5LockNames(fixture)) await unlink(join(fixture.stateRoot, "locks", name)); assert.deepEqual(await m5LockNames(fixture), []); }
  catch (error: unknown) { note(error); }
  try { assert.deepEqual(await countOwnedArtifacts(fixture.verifierRoot), { sockets: 0, fifos: 0, checkpointFiles: 0 }); }
  catch (error: unknown) { note(error); }
  try { await removeM5R3Fixture(fixture); assert.equal(await pathExists(fixture.verifierRoot), false); }
  catch (error: unknown) { note(error); }
  if (failure !== undefined) throw failure;
}
test.after(async () => { await rm(verifierRoot, { recursive: true, force: true }); });

function request(f: M5R3Fixture, patch: Record<string, unknown> = {}) {
  return { intent: "BLOCK", expectedRevision: f.committed.statePointer.revision, expectedStatePointerContentSha256: f.committed.statePointer.content_sha256,
    expectedWorkflowStateContentSha256: f.committed.workflowState.content_sha256, transitionId: "r5-block", processMetadata,
    authoritativeSources: { m3StateTokens: [f.m3StateToken] }, ...patch };
}
async function input(f: M5R3Fixture, name: string, extra: Record<string, unknown> = {}): Promise<string> {
  const path = join(f.verifierRoot, `${name}.json`);
  await writeFile(path, JSON.stringify({ stateRoot: f.stateRoot, runId: f.runId, policy: f.policy, reducerPolicy: f.reducer, runAuthority: f.runAuthority, ...extra }), { mode: 0o600 });
  return path;
}
async function run(mode: string, path: string): Promise<any> {
  const result = await execFileAsync(process.execPath, [childDriver, mode, path], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  return JSON.parse(result.stdout);
}
function spawn(registry: ChildRegistry, mode: string, path: string): ChildProcess {
  const child = fork(childDriver, [mode, path], { execArgv: [], stdio: ["ignore", "pipe", "pipe", "ipc"] });
  registry.all.add(child); registry.live.add(child); registry.modes.set(child, mode); registry.states.set(child, "running"); registryByChild.set(child, registry);
  const exit = new Promise<ChildExit>((resolveExit) => child.once("exit", (code, signal) => { registry.live.delete(child); registry.states.set(child, "exited"); resolveExit({ code, signal }); }));
  child.once("error", (error) => { registry.errors.set(child, error); }); registry.exits.set(child, exit);
  return child;
}
function waitMessage(child: ChildProcess, predicate: (value: any) => boolean): Promise<any> {
  return new Promise((resolveMessage, reject) => {
    const timeout = setTimeout(() => reject(new Error("bounded child IPC timeout")), 30_000);
    const onMessage = (value: unknown) => {
      const registry = registryByChild.get(child); if (value !== null && typeof value === "object" && typeof (value as { type?: unknown }).type === "string") registry?.states.set(child, (value as { type: string }).type);
      if (predicate(value)) { clearTimeout(timeout); child.off("message", onMessage); resolveMessage(value); }
    };
    child.on("message", onMessage); child.once("error", reject); child.once("exit", (code, signal) => { if (code !== 0 && signal !== "SIGKILL") { clearTimeout(timeout); reject(new Error(`child exited ${code}/${signal}`)); } });
  });
}
function exitOf(registry: ChildRegistry, child: ChildProcess): Promise<ChildExit> {
  const exit = registry.exits.get(child); if (exit === undefined) throw new Error("child is not owned by this test registry"); return exit;
}
function classification(value: any, digestValue: string): string | undefined {
  return value.inspection.managedRecordClassifications.find((entry: any) => entry.object.contentSha256 === digestValue)?.classification;
}
function reidentifyDecision(value: M5ControlDecisionDocument, patch: MutableJson): M5ControlDecisionDocument {
  const { content_sha256: _content, ...body } = structuredClone(value) as MutableJson;
  return identifyContractDocument("pi_gacw_m5_control_decision_v0", { ...body, ...patch }) as unknown as M5ControlDecisionDocument;
}
function reidentifyToken(value: M3RepositoryStateTokenDocument, patch: MutableJson): M3RepositoryStateTokenDocument {
  const { content_sha256: _content, ...body } = structuredClone(value) as MutableJson;
  return identifyContractDocument("pi_gacw_repository_state_token_v0", { ...body, ...patch }) as unknown as M3RepositoryStateTokenDocument;
}
function digestHex(value: string): string { return value.startsWith("sha256:") ? value.slice("sha256:".length) : value; }
function lockNamespace(f: M5R3Fixture): { readonly directory: string; readonly m3Base: string; readonly m5Base: string; readonly m5Path: string } {
  const m3Base = digestHex(f.policy.worktree_key);
  const m5Base = digestHex(sha256Bytes(Buffer.from(`pi-gacw-run-mutation:${f.runId}`, "utf8")));
  assert.notEqual(m3Base, m5Base);
  return { directory: join(f.stateRoot, "locks"), m3Base, m5Base, m5Path: join(f.stateRoot, "locks", `${m5Base}.lock`) };
}
function isM5CandidateName(name: string, m3Base: string): boolean {
  return /^[0-9a-f]{64}\.owner\.json$/.test(name) && name !== `${m3Base}.owner.json`;
}
async function m3LockNames(f: M5R3Fixture): Promise<readonly string[]> {
  const { directory, m3Base } = lockNamespace(f); const prefix = `${m3Base}.`;
  return (await readdir(directory)).filter((name) => name === `${m3Base}.lock` || name === `${m3Base}.owner.json` || name.startsWith(`${prefix}acquisition-`)).sort();
}
async function m5LockNames(f: M5R3Fixture): Promise<readonly string[]> {
  const { directory, m3Base, m5Base } = lockNamespace(f);
  return (await readdir(directory)).filter((name) => name === `${m5Base}.lock` || isM5CandidateName(name, m3Base)).sort();
}
async function assertM3LockPreserved(f: M5R3Fixture, expected: readonly string[]): Promise<void> {
  assert.deepEqual(await m3LockNames(f), expected);
}
async function pathExists(path: string): Promise<boolean> {
  try { await lstat(path); return true; }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}

function historyFixture(f: M5R3Fixture): readonly M5ControlDecisionDocument[] {
  const base = { intent: "BLOCK" as const, expectedRevision: 0, expectedStatePointerContentSha256: digest(950), expectedWorkflowStateContentSha256: f.initialState.content_sha256 as Sha256Digest,
    authoritativeSources: { m3StateTokens: [f.m3StateToken] } };
  for (let seed = 0; seed < 500; seed += 1) {
    const first = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [], request: { ...base, blockReason: `BLOCKED_R5_FIRST_${seed}` } });
    const failure = { sourceLayer: "M5" as const, sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: f.policy.content_sha256 as Sha256Digest, normalizedSignature: digest(951) };
    const second = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [first], request: { ...base, blockReason: `BLOCKED_R5_SECOND_${seed}`, failures: [failure] } });
    const third = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [first, second], request: { ...base, blockReason: `BLOCKED_R5_THIRD_${seed}`, failures: [failure] } });
    const newFailure = { ...failure, sourceRecordContentSha256: third.content_sha256 as Sha256Digest, normalizedSignature: digest(952) };
    const progress = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [first, second, third], request: { ...base, blockReason: `BLOCKED_R5_PROGRESS_${seed}`,
      failures: [newFailure], progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [third.content_sha256 as Sha256Digest] } } });
    const afterBreak = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [first, second, third, progress], request: { ...base, blockReason: `BLOCKED_R5_AFTER_${seed}`, failures: [failure] } });
    const values = [first, second, third, progress, afterBreak];
    if (values.map((entry) => entry.content_sha256).join() !== [...values].sort((a, b) => a.content_sha256.localeCompare(b.content_sha256)).map((entry) => entry.content_sha256).join()) return values;
  }
  throw new Error("could not construct opposite lexical chronology fixture");
}

test("M5-R5 fresh-process predecessor chronology defeats hash order and preserves failure/progress semantics", async () => {
  const f = await createM5R3Fixture(verifierRoot);
  try {
    const decisions = historyFixture(f); assert.equal(decisions[2]!.failures[0]!.control_class, "SAME_FAILURE_TWICE");
    assert.equal(decisions[3]!.progress.classification, "PROGRESS"); assert.equal(decisions[4]!.failures[0]!.occurrence_count, 1);
    assert.equal(decisions.filter((entry) => entry.selected_route === decisions[0]!.selected_route).length, decisions.length);
    const unrelated = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [],
      request: { intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: digest(949), expectedWorkflowStateContentSha256: f.initialState.content_sha256 as Sha256Digest, blockReason: "BLOCKED_UNRELATED" } });
    const seedPath = await input(f, "history-seed", { decisions: [...decisions, unrelated] }); assert.deepEqual(await run("seed-history", seedPath), { seeded: 6 });
    const fresh = await run("history", seedPath); assert.deepEqual(fresh.ordered, decisions.map((entry) => entry.content_sha256));
    assert.notDeepEqual(fresh.ordered, [...fresh.ordered].sort());
    const missing = reidentifyDecision(decisions[4]!, { prior_relevant_decision_content_sha256: digest(953) });
    const branch = reidentifyDecision(decisions[1]!, { content_sha256: digest(954), blocking_reason: "BLOCKED_BRANCH" } as never);
    const wrongKind = reidentifyDecision(decisions[1]!, { prior_relevant_decision_content_sha256: f.policy.content_sha256 });
    const anotherRun = reidentifyDecision(decisions[1]!, { run_id: "run-another-authority" });
    const cyclicA = { ...structuredClone(decisions[0]!), content_sha256: digest(955), prior_relevant_decision_content_sha256: digest(956) };
    const cyclicB = { ...structuredClone(decisions[1]!), content_sha256: digest(956), prior_relevant_decision_content_sha256: digest(955) };
    const selfCycle = { ...structuredClone(decisions[0]!), content_sha256: digest(961), prior_relevant_decision_content_sha256: digest(961) };
    for (const [name, variants] of [
      ["missing", [missing]], ["wrong-kind", [decisions[0], wrongKind]], ["branch", [decisions[0], decisions[1], branch]],
      ["self-cycle", [selfCycle]], ["cycle", [cyclicA, cyclicB]], ["another-run", [decisions[0], anotherRun]],
    ] as const) {
      const path = await input(f, `history-${name}`, { decisions: variants });
      await assert.rejects(execFileAsync(process.execPath, [childDriver, "history-inline", path]), (error: any) => error.code !== 0 || error.stderr?.includes("M5_"));
    }
  } finally { await removeM5R3Fixture(f); }

  const future = await createM5R3Fixture(verifierRoot);
  try {
    const decision = reidentifyDecision(historyFixture(future)[0]!, { current_state_content_sha256: digest(957) });
    const path = await input(future, "history-future-state", { decisions: [decision] });
    await run("seed-history", path); const fresh = await run("inspect", path);
    assert.equal(classification(fresh, decision.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
  } finally { await removeM5R3Fixture(future); }
});

test("M5-R5 fresh-process typed transition consumer requires exact media and immutable run witnesses", async () => {
  const valid = await createM5R3Fixture(verifierRoot);
  try {
    const validPath = await input(valid, "typed-valid", { request: request(valid, { blockReason: "BLOCKED_R5_TYPED" }) });
    const evaluated = await run("evaluate", validPath); assert.equal(evaluated.type, "result");
    const fresh = await run("inspect", validPath); const decision = fresh.records.decisions[0];
    assert.equal(classification(fresh, decision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await removeM5R3Fixture(valid); }

  for (const mediaType of ["text/plain", "application/json", "application/vnd.pi-gacw.m5-usage-evidence+json", "application/vnd.pi-gacw.m5-control-decision+json"]) {
    const f = await createM5R3Fixture(verifierRoot);
    try {
      const decision = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [], request: request(f, { blockReason: "BLOCKED_R5_FORGED", transitionId: "r5-forged" }) as any });
      const event = mediaType.endsWith("control-decision+json") ? transitionEvent("FREEZE_OBJECTIVE", {}) : decision.transition_event!;
      const predicted = (await import("../src/state-machine/index.js")).reduceState(f.initialState, event, f.reducer);
      const path = await input(f, `typed-${mediaType.replaceAll("/", "-")}`, { decisions: [decision], manualTransition: {
        expectedRevision: 0, expectedStatePointerContentSha256: f.committed.statePointer.content_sha256, expectedWorkflowStateContentSha256: f.initialState.content_sha256,
        expectedNextWorkflowStateContentSha256: predicted.content_sha256, transitionId: "r5-forged", event, processMetadata, mediaType,
        evidenceText: mediaType === "text/plain" ? `embedded:${canonicalize(decision)}\n` : `${canonicalize(decision)}\n`,
      } });
      await run("manual-transition", path); const fresh = await run("inspect", path);
      assert.notEqual(classification(fresh, decision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    } finally { await removeM5R3Fixture(f); }
  }

  for (const [name, patch] of [
    ["wrong-predecessor", { current_state_content_sha256: digest(958) }],
    ["wrong-reducer", { reducer_policy_content_sha256: digest(959) }],
    ["wrong-successor", { predicted_next_state_content_sha256: digest(960) }],
    ["wrong-event", { transition_event: transitionEvent("FREEZE_OBJECTIVE", {}) }],
  ] as const) {
    const f = await createM5R3Fixture(verifierRoot);
    try {
      const base = evaluateAuthority({ policy: f.policy, state: f.initialState, reducerPolicy: f.reducer, persistedUsage: [], priorDecisions: [], request: request(f, { blockReason: "BLOCKED_R5_TYPED_FIELD", transitionId: `r5-${name}` }) as any });
      const decision = reidentifyDecision(base, patch as MutableJson); const event = base.transition_event!;
      const path = await input(f, `typed-${name}`, { decisions: [decision], manualTransition: {
        expectedRevision: 0, expectedStatePointerContentSha256: f.committed.statePointer.content_sha256, expectedWorkflowStateContentSha256: f.initialState.content_sha256,
        expectedNextWorkflowStateContentSha256: base.predicted_next_state_content_sha256, transitionId: `r5-${name}`, event, processMetadata,
        mediaType: "application/vnd.pi-gacw.m5-control-decision+json", evidenceText: `${canonicalize(decision)}\n`,
      } });
      await run("manual-transition", path); const fresh = await run("inspect", path);
      assert.notEqual(classification(fresh, decision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    } finally { await removeM5R3Fixture(f); }
  }

  const orphan = await createM5R3Fixture(verifierRoot);
  try {
    const decision = evaluateAuthority({ policy: orphan.policy, state: orphan.initialState, reducerPolicy: orphan.reducer, persistedUsage: [], priorDecisions: [], request: request(orphan, { blockReason: "BLOCKED_R5_ORPHAN" }) as any });
    const path = await input(orphan, "typed-orphan", { decisions: [decision] }); await run("seed-history", path);
    const fresh = await run("inspect", path); assert.equal(classification(fresh, decision.content_sha256), "UNREFERENCED_MANAGED_RECORD");
  } finally { await removeM5R3Fixture(orphan); }

  const unselected = await createM5R3Fixture(verifierRoot);
  try {
    const decision = evaluateAuthority({ policy: unselected.policy, state: unselected.initialState, reducerPolicy: unselected.reducer, persistedUsage: [], priorDecisions: [], request: request(unselected, { blockReason: "BLOCKED_R5_UNSELECTED", transitionId: "r5-unselected" }) as any });
    const path = await input(unselected, "typed-unselected", { decisions: [decision], manualTransition: {
      expectedRevision: 0, expectedStatePointerContentSha256: unselected.committed.statePointer.content_sha256, expectedWorkflowStateContentSha256: unselected.initialState.content_sha256,
      expectedNextWorkflowStateContentSha256: decision.predicted_next_state_content_sha256, transitionId: "r5-unselected", event: decision.transition_event!, processMetadata,
      mediaType: "application/vnd.pi-gacw.m5-control-decision+json", evidenceText: `${canonicalize(decision)}\n`,
    } });
    await run("manual-transition", path);
    await writeFile(join(unselected.stateRoot, "runs", unselected.runId, "state.json"), `${canonicalize(unselected.committed.statePointer)}\n`, { mode: 0o600 });
    const fresh = await run("inspect", path); assert.notEqual(classification(fresh, decision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await removeM5R3Fixture(unselected); }
});

test("M5-R5 fresh-process lock publication, competition, dead-owner recovery, and stale replacement are fail-closed", async () => {
  const registry = createChildRegistry(); const f = await createM5R3Fixture(verifierRoot); const namespace = lockNamespace(f); const m3Before = await m3LockNames(f);
  try {
    const path = await input(f, "lock", {});
    const owner = spawn(registry, "lock", path); await waitMessage(owner, (value) => value?.type === "acquired");
    const loser = spawn(registry, "lock", path); const loserExit = await exitOf(registry, loser); assert.equal(loserExit.code, 1);
    owner.send("RELEASE"); await waitMessage(owner, (value) => value?.type === "released"); await exitOf(registry, owner);
    assert.deepEqual(await m5LockNames(f), []); await assertM3LockPreserved(f, m3Before);

    const locks = namespace.directory; const lockPath = namespace.m5Path;
    const prepPath = await input(f, "lock-preparation", { checkpoint: "RUN_LOCK_BEFORE_NOREPLACE_PUBLICATION" });
    const preparing = spawn(registry, "lock", prepPath); await waitMessage(preparing, (value) => value?.type === "checkpoint" && value.checkpoint === "RUN_LOCK_BEFORE_NOREPLACE_PUBLICATION");
    const preparingNames = await readdir(locks); const preparingCandidates = preparingNames.filter((name) => isM5CandidateName(name, namespace.m3Base));
    assert.equal(await pathExists(lockPath), false); assert.equal(preparingCandidates.length, 1); assert.notEqual(preparingCandidates[0], `${namespace.m5Base}.lock`);
    const candidateMetadata = JSON.parse(await readFile(join(locks, preparingCandidates[0]!), "utf8")) as Record<string, unknown>;
    assert.deepEqual(Object.keys(candidateMetadata).sort(), ["lock_id", "pid", "process_start_ticks"]);
    assert.match(candidateMetadata["lock_id"] as string, /^[0-9a-f]{32}$/); assert.equal(typeof candidateMetadata["pid"], "number"); assert.match(candidateMetadata["process_start_ticks"] as string, /^[0-9]+$/);
    assert.deepEqual(preparingNames.filter((name) => name.startsWith(`${namespace.m3Base}.`)).sort(), m3Before.filter((name) => name.startsWith(`${namespace.m3Base}.`)).sort());
    const preparationCompetitor = spawn(registry, "lock", path); await waitMessage(preparationCompetitor, (value) => value?.type === "acquired");
    preparing.send("CONTINUE"); assert.equal((await exitOf(registry, preparing)).code, 1);
    preparationCompetitor.send("RELEASE"); await exitOf(registry, preparationCompetitor); assert.deepEqual(await m5LockNames(f), []); await assertM3LockPreserved(f, m3Before);

    const inodePath = await input(f, "lock-inode", { checkpoint: "RUN_LOCK_AFTER_NOREPLACE_PUBLICATION" });
    const inodeOwner = spawn(registry, "lock", inodePath); await waitMessage(inodeOwner, (value) => value?.type === "checkpoint" && value.checkpoint === "RUN_LOCK_AFTER_NOREPLACE_PUBLICATION");
    const inodeCandidates = (await readdir(locks)).filter((name) => isM5CandidateName(name, namespace.m3Base)); assert.equal(inodeCandidates.length, 1);
    const [candidateStat, publishedStat] = await Promise.all([lstat(join(locks, inodeCandidates[0]!)), lstat(lockPath)]);
    assert.equal(candidateStat.ino, publishedStat.ino); assert.equal(candidateStat.dev, publishedStat.dev);
    inodeOwner.send("CONTINUE"); await waitMessage(inodeOwner, (value) => value?.type === "acquired"); inodeOwner.send("RELEASE"); await exitOf(registry, inodeOwner);
    assert.deepEqual(await m5LockNames(f), []); await assertM3LockPreserved(f, m3Before);

    const publishedDeathPath = await input(f, "lock-killed-publication", { checkpoint: "RUN_LOCK_AFTER_NOREPLACE_PUBLICATION" });
    const publishedDeath = spawn(registry, "lock", publishedDeathPath); await waitMessage(publishedDeath, (value) => value?.type === "checkpoint" && value.checkpoint === "RUN_LOCK_AFTER_NOREPLACE_PUBLICATION");
    const immediateCompetitor = spawn(registry, "lock", path); assert.equal((await exitOf(registry, immediateCompetitor)).code, 1);
    publishedDeath.kill("SIGKILL"); assert.equal((await exitOf(registry, publishedDeath)).signal, "SIGKILL");
    const afterPublishedDeath = spawn(registry, "lock", path); await waitMessage(afterPublishedDeath, (value) => value?.type === "acquired"); afterPublishedDeath.send("RELEASE"); await exitOf(registry, afterPublishedDeath);
    assert.deepEqual(await m5LockNames(f), []); await assertM3LockPreserved(f, m3Before);

    const killedPath = await input(f, "lock-killed-preparation", { checkpoint: "RUN_LOCK_CANDIDATE_CREATED" });
    const killed = spawn(registry, "lock", killedPath); await waitMessage(killed, (value) => value?.type === "checkpoint" && value.checkpoint === "RUN_LOCK_CANDIDATE_CREATED");
    assert.equal(await pathExists(lockPath), false); assert.equal((await readdir(locks)).filter((name) => isM5CandidateName(name, namespace.m3Base)).length, 1);
    killed.kill("SIGKILL"); assert.equal((await exitOf(registry, killed)).signal, "SIGKILL");
    for (const name of await m5LockNames(f)) await unlink(join(locks, name));
    assert.deepEqual(await m5LockNames(f), []); await assertM3LockPreserved(f, m3Before);

    await writeFile(lockPath, `${canonicalize({ lock_id: "11111111111111111111111111111111", pid: 2_147_483_647, process_start_ticks: "0" })}\n`, { mode: 0o600 });
    const stalePath = await input(f, "lock-stale", { checkpoint: "RUN_LOCK_BEFORE_STALE_UNLINK" }); const stale = spawn(registry, "lock", stalePath);
    await waitMessage(stale, (value) => value?.type === "checkpoint" && value.checkpoint === "RUN_LOCK_BEFORE_STALE_UNLINK");
    await unlink(lockPath); const replacement = `${canonicalize({ lock_id: "22222222222222222222222222222222", pid: process.pid, process_start_ticks: "0" })}\n`; await writeFile(lockPath, replacement, { mode: 0o600 });
    stale.send("CONTINUE"); const staleExit = await exitOf(registry, stale); assert.equal(staleExit.code, 1); assert.equal(await readFile(lockPath, "utf8"), replacement); await assertM3LockPreserved(f, m3Before);
    await rm(lockPath);

    await writeFile(lockPath, "{", { mode: 0o600 }); const malformed = spawn(registry, "lock", path); assert.equal((await exitOf(registry, malformed)).code, 1); assert.equal(await readFile(lockPath, "utf8"), "{"); await rm(lockPath);
    await writeFile(lockPath, `${canonicalize({ lock_id: "33333333333333333333333333333333", pid: 2_147_483_647, process_start_ticks: "0" })}\n`, { mode: 0o600 });
    const recovered = spawn(registry, "lock", path); await waitMessage(recovered, (value) => value?.type === "acquired"); recovered.send("RELEASE"); await exitOf(registry, recovered);
    await writeFile(lockPath, `${canonicalize({ lock_id: "44444444444444444444444444444444", pid: process.pid, process_start_ticks: "0" })}\n`, { mode: 0o600 });
    const pidReuseRecovery = spawn(registry, "lock", path); await waitMessage(pidReuseRecovery, (value) => value?.type === "acquired"); pidReuseRecovery.send("RELEASE"); await exitOf(registry, pidReuseRecovery);
    assert.deepEqual(await m5LockNames(f), []); await assertM3LockPreserved(f, m3Before);
  } finally { await cleanupFixture(registry, f); }
});

async function killAfterCommit(registry: ChildRegistry, path: string): Promise<void> {
  const child = spawn(registry, "evaluate", path); await waitMessage(child, (value) => value?.type === "checkpoint" && value.checkpoint === "AFTER_COMMITTED_STATE_BEFORE_RESPONSE");
  assert.equal(child.kill("SIGKILL"), true); assert.equal((await exitOf(registry, child)).signal, "SIGKILL");
}

test("M5-R5 fresh-process lost-response identity reuses only exact validated authority", async () => {
  const registry = createChildRegistry(); const f = await createM5R3Fixture(verifierRoot);
  try {
    const source = f.policy.content_sha256 as Sha256Digest;
    const base = request(f, { blockReason: "BLOCKED_R5_LOST", failures: [{ sourceLayer: "M5", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: source,
      normalizedSignature: digest(970), operationId: "operation", scopeIdentity: digest(971), pathIdentity: digest(972), repositoryIdentity: f.policy.repository_identity_content_sha256, worktreeKey: f.policy.worktree_key }] });
    const basePath = await input(f, "lost-base", { request: base, checkpoint: "AFTER_COMMITTED_STATE_BEFORE_RESPONSE" }); await killAfterCommit(registry, basePath);
    const exact = await run("evaluate", basePath); assert.equal(exact.type, "result"); assert.equal(exact.result.reusedDecision, true);
    const before = await run("inspect", basePath); assert.equal(before.records.decisions.length, 1);
    const failure = (base as any).failures[0];
    const wrongM3 = reidentifyToken(f.m3StateToken, { worktree_key: digest(985) });
    const variants: readonly [string, any][] = [
      ["operation", { ...base, failures: [{ ...failure, operationId: "changed" }] }], ["scope", { ...base, failures: [{ ...failure, scopeIdentity: digest(973) }] }],
      ["path", { ...base, failures: [{ ...failure, pathIdentity: digest(974) }] }], ["repository", { ...base, failures: [{ ...failure, repositoryIdentity: digest(975) }] }],
      ["worktree", { ...base, failures: [{ ...failure, worktreeKey: digest(976) }] }], ["layer", { ...base, failures: [{ ...failure, sourceLayer: "M4" }] }],
      ["code", { ...base, failures: [{ ...failure, sourceErrorCode: "INVALID_ARGUMENT" }] }], ["record", { ...base, failures: [{ ...failure, sourceRecordContentSha256: digest(977) }] }],
      ["signature", { ...base, failures: [{ ...failure, normalizedSignature: digest(978) }] }], ["intent", { ...base, intent: "EVALUATE_TERMINAL" }],
      ["top-level-operation", { ...base, operationId: "changed-operation" }], ["transition", { ...base, transitionId: "changed-transition" }],
      ["expected-revision", { ...base, expectedRevision: 99 }], ["expected-pointer", { ...base, expectedStatePointerContentSha256: digest(982) }],
      ["expected-state", { ...base, expectedWorkflowStateContentSha256: digest(981) }], ["block", { ...base, blockReason: "BLOCKED_CHANGED" }],
      ["roles", { ...base, availableLogicalRoles: ["SOL_OWNER"] }], ["required-role", { ...base, requiredLogicalRole: "SOL_OWNER" }],
      ["evidence-set", { ...base, progressEvidence: { evidenceContentSha256: [source] } }], ["usage", { ...base, usageEvidence: [{}] }],
      ["invalid-failure", { ...base, failures: [null] }], ["m3-authority", { ...base, authoritativeSources: { m3StateTokens: [wrongM3] } }],
      ["route-authority", { ...base, authoritativeSources: { routeMap: { content_sha256: f.runAuthority.routeMap.content_sha256 } } }],
    ];
    for (const [name, changed] of variants) {
      const changedPath = await input(f, `lost-${name}`, { request: changed });
      await assert.rejects(execFileAsync(process.execPath, [childDriver, "evaluate", changedPath]), (error: any) => error.code !== 0);
      const fresh = await run("inspect", changedPath); assert.equal(fresh.records.decisions.length, 1); assert.equal(fresh.records.usage.length, 0);
      assert.equal(fresh.records.decisions[0].reservation, null); assert.equal(fresh.inspection.revision, 1); assert.ok(fresh.inspection.transitionCommit);
    }
    for (const [name, patch] of [
      ["repository", { repository_identity_content_sha256: digest(979) }], ["mode", { requested_mode: "ROUTED_DAG" }],
      ["route", { route_map_sha256: digest(983) }], ["scope", { scope_sha256: digest(984) }],
    ] as const) {
      const forgedPolicy = identifyContractDocument("pi_gacw_m5_control_policy_v0", { ...structuredClone(f.policy), content_sha256: undefined, ...patch });
      const badPolicyPath = join(f.verifierRoot, `lost-policy-${name}.json`); await writeFile(badPolicyPath, JSON.stringify({ stateRoot: f.stateRoot, runId: f.runId, policy: forgedPolicy, reducerPolicy: f.reducer, runAuthority: f.runAuthority, request: base }), { mode: 0o600 });
      await assert.rejects(execFileAsync(process.execPath, [childDriver, "evaluate", badPolicyPath]));
      const fresh = await run("inspect", basePath); assert.equal(fresh.records.decisions.length, 1); assert.equal(fresh.records.usage.length, 0); assert.equal(fresh.inspection.revision, 1);
    }
  } finally { await cleanupFixture(registry, f); }
});

test("M5-R5 integrated restart preserves authority, chronology, typed rooting, one writer, exact reuse, and wrong-policy rejection", async () => {
  const registry = createChildRegistry(); const f = await createM5R3Fixture(verifierRoot);
  try {
    const committed = await directFastPreflightFixture(f);
    const history = historyFixture(f); const seedPath = await input(f, "integrated-history", { decisions: history }); await run("seed-history", seedPath);
    const evidence = usage(f.policy, committed.workflowState.content_sha256 as Sha256Digest, "integrated-usage");
    const workRequest = { intent: "AUTHORIZE_WORK", operationId: "integrated-work", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [evidence],
      authoritativeSources: { m3StateTokens: [f.m3StateToken] }, expectedRevision: committed.statePointer.revision,
      expectedStatePointerContentSha256: committed.statePointer.content_sha256, expectedWorkflowStateContentSha256: committed.workflowState.content_sha256,
      transitionId: "r5-integrated-work", processMetadata };
    const path = await input(f, "integrated", { request: workRequest, checkpoint: "AFTER_COMMITTED_STATE_BEFORE_RESPONSE" });
    await killAfterCommit(registry, path); const first = await run("inspect", path); assert.equal(first.inspection.status, "HEALTHY");
    const transitionDecision = first.records.decisions.find((entry: any) => entry.transition_id === "r5-integrated-work"); assert.ok(transitionDecision);
    assert.equal(classification(first, transitionDecision.content_sha256), "AUTHORITATIVE_MANAGED_RECORD"); assert.ok(transitionDecision.reservation);
    const ordered = await run("history", path); assert.deepEqual(ordered.ordered.slice(0, history.length), history.map((entry) => entry.content_sha256));
    assert.notDeepEqual(ordered.ordered.slice(0, history.length), [...ordered.ordered.slice(0, history.length)].sort());
    const exact = await run("evaluate", path); assert.equal(exact.result.reusedDecision, true);
    const changedPath = await input(f, "integrated-changed", { request: { ...workRequest, operationId: "integrated-changed" } });
    await assert.rejects(execFileAsync(process.execPath, [childDriver, "evaluate", changedPath]));
    const lock = spawn(registry, "lock", path); await waitMessage(lock, (value) => value?.type === "acquired");
    const competitor = spawn(registry, "lock", path); assert.equal((await exitOf(registry, competitor)).code, 1); lock.send("RELEASE"); await exitOf(registry, lock);
    const bad = identifyContractDocument("pi_gacw_m5_control_policy_v0", { ...structuredClone(f.policy), content_sha256: undefined, worktree_key: digest(980) });
    const badPath = join(f.verifierRoot, "integrated-bad.json"); await writeFile(badPath, JSON.stringify({ stateRoot: f.stateRoot, runId: f.runId, policy: bad, reducerPolicy: f.reducer, runAuthority: f.runAuthority, request: workRequest }), { mode: 0o600 });
    await assert.rejects(execFileAsync(process.execPath, [childDriver, "evaluate", badPath]));
    const wrongM3Request = { ...workRequest, authoritativeSources: { m3StateTokens: [reidentifyToken(f.m3StateToken, { worktree_key: digest(986) })] } };
    const wrongM3Path = await input(f, "integrated-wrong-m3", { request: wrongM3Request });
    await assert.rejects(execFileAsync(process.execPath, [childDriver, "evaluate", wrongM3Path]));
    const final = await run("inspect", path); assert.equal(final.records.decisions.length, history.length + 1); assert.equal(final.records.usage.length, 1);
    assert.equal(final.records.decisions.filter((entry: any) => entry.transition_id === "r5-integrated-work").length, 1);
    assert.equal(final.inspection.revision, committed.statePointer.revision + 1); assert.equal(final.inspection.status, "HEALTHY"); assert.ok(final.inspection.transitionCommit);
  } finally { await cleanupFixture(registry, f); }
});

void orderDecisionHistory;
void lstat;
void mkdir;
