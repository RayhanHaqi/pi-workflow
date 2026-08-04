import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalize } from "../src/canonical-json/index.js";
import { createControlDecisionKernel, ControlDecisionError } from "../src/control/index.js";
import { buildLayeredLowerLayerFailureMap, buildLowerLayerFailureMap, evaluateAuthority, mapLowerLayerFailureCode, orderDecisionHistory } from "../src/control/evaluate.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { classifyM5Authority } from "../src/persistence/m5-authority.js";
import { configureM5PersistenceTestHooks } from "../src/persistence/m5-test-hooks.js";
import { commitTransition, initializeRunStorage, inspectRunStorage } from "../src/persistence/index.js";
import { publishM5ManagedRecord, withRunExclusive } from "../src/persistence/store.js";
import { identifyContractDocument, validateSchema, type M5ControlDecisionDocument, type M5ControlPolicyDocument, type M5UsageEvidenceDocument, type ReducerPolicy, type WorkflowState } from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { advanceCommon, applyEvent, digest, makePolicy, stateIdentities, transitionEvent, type MutableJson } from "./helpers.js";
import { m5Policy, m5RunAuthority, usage } from "./m5-r3-fixtures.js";
import { processMetadata } from "./persistence-helpers.js";

function reidentify<T>(schema: "pi_gacw_m5_control_policy_v0" | "pi_gacw_m5_usage_evidence_v0" | "pi_gacw_m5_control_decision_v0", value: object, patch: MutableJson): T {
  const { content_sha256: _content, ...body } = structuredClone(value) as MutableJson;
  return identifyContractDocument(schema, { ...body, ...patch }) as unknown as T;
}

function directFast(reducer: ReducerPolicy): { readonly initial: WorkflowState; readonly state: WorkflowState; readonly policy: M5ControlPolicyDocument } {
  const initial = createInitialState(reducer, stateIdentities(reducer)); let state = advanceCommon(reducer);
  state = applyEvent(state, reducer, "VALIDATE_DIRECT_CONTRACT"); state = applyEvent(state, reducer, "REQUEST_DIRECT_APPROVAL");
  state = applyEvent(state, reducer, "APPROVE_DIRECT_TASK"); state = applyEvent(state, reducer, "PASS_DIRECT_FAST_PREFLIGHT");
  return { initial, state, policy: m5Policy(reducer, initial.content_sha256 as Sha256Digest) };
}

function pureRequest(state: WorkflowState, patch: MutableJson = {}): any {
  return { intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: digest(800), expectedWorkflowStateContentSha256: state.content_sha256, ...patch };
}

async function makeStorage(name: string) {
  const root = await mkdtemp(join(tmpdir(), `m5r4-${name}-`)); await chmod(root, 0o700);
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const runAuthority = m5RunAuthority();
  const initial = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: runAuthority.contract.contract_sha256 });
  const genesis = await initializeRunStorage({ stateRoot: root, runId: reducer.run_id, policy: reducer, initialState: initial, processMetadata });
  return { root, reducer, initial, genesis, policy: m5Policy(reducer, initial.content_sha256 as Sha256Digest, runAuthority), runAuthority };
}

test("F01 exact phase and operation guards reject invalid work/continuation and admit exact work phase with an event", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const created = createInitialState(reducer, stateIdentities(reducer)); const policy = m5Policy(reducer, created.content_sha256 as Sha256Digest);
  assert.throws(() => evaluateAuthority({ policy, state: created, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(created, { intent: "AUTHORIZE_WORK", operationId: "wrong-phase", availableLogicalRoles: ["LUNA_EXECUTOR"] }) }),
    (error: unknown) => (error as { code?: string }).code === "ROUTE_NOT_ELIGIBLE");
  const source = policy.content_sha256 as Sha256Digest;
  const retry = evaluateAuthority({ policy, state: created, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(created, { intent: "AUTHORIZE_CONTINUATION", operationId: "not-admitted", availableLogicalRoles: ["LUNA_EXECUTOR"], progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [source] }, failures: [{ sourceLayer: "M5", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: source, normalizedSignature: digest(801), operationId: "not-admitted" }] }) });
  assert.equal(retry.outcome, "BLOCK"); assert.equal(retry.selected_route, "BLOCK");
  const fixture = directFast(reducer); const admitted = evaluateAuthority({ policy: fixture.policy, state: fixture.state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(fixture.state, { intent: "AUTHORIZE_WORK", operationId: "admitted", availableLogicalRoles: ["LUNA_EXECUTOR"] }) });
  assert.equal(admitted.outcome, "AUTHORIZE"); assert.equal(admitted.transition_event?.event_type, "START_DIRECT_ATTEMPT");
});

test("F02 evaluation, precommit recalculation, typed transition, and fresh inspection remain semantically closed", async () => {
  const fixture = await makeStorage("f02");
  try {
    const kernel = createControlDecisionKernel({ stateRoot: fixture.root, runId: fixture.reducer.run_id, policy: fixture.policy, reducerPolicy: fixture.reducer, runAuthority: fixture.runAuthority }); const source = fixture.policy.content_sha256 as Sha256Digest;
    const result = await kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: fixture.genesis.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fixture.initial.content_sha256 as Sha256Digest, transitionId: "f02-block", processMetadata, progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS", evidenceContentSha256: [source] }, failures: [{ sourceLayer: "M5", sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: source, normalizedSignature: digest(802) }] });
    assert.equal(result.workflowState.phase, "BLOCKED");
    const fresh = await inspectRunStorage({ stateRoot: fixture.root, runId: fixture.reducer.run_id });
    assert.equal(fresh.issues.some((issue) => issue.code === "INVALID_MANAGED_RECORD"), false);
    assert.equal(fresh.managedRecordClassifications.find((entry) => entry.object.contentSha256 === result.decision.content_sha256)?.classification, "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test("F03 usage binds exact committed state, loaded source kind/layer, route, and role", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const fixture = directFast(reducer); const valid = usage(fixture.policy, fixture.state.content_sha256 as Sha256Digest, "f03-valid");
  const badState = reidentify<M5UsageEvidenceDocument>("pi_gacw_m5_usage_evidence_v0", valid, { originating_state_content_sha256: digest(803) });
  const badKind = reidentify<M5UsageEvidenceDocument>("pi_gacw_m5_usage_evidence_v0", valid, { source_kind: "FORGED_KIND" });
  const badRole = reidentify<M5UsageEvidenceDocument>("pi_gacw_m5_usage_evidence_v0", valid, { logical_role: "SOL_OWNER" });
  for (const evidence of [badState, badKind, badRole]) assert.throws(() => evaluateAuthority({ policy: fixture.policy, state: fixture.state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(fixture.state, { intent: "AUTHORIZE_WORK", operationId: "f03-work", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [evidence] }) }), (error: unknown) => (error as { code?: string }).code === "USAGE_EVIDENCE_INVALID");
});

test("F04 policy genesis binding remains immutable after state advancement", async () => {
  const fixture = await makeStorage("f04");
  try {
    const advanced = await commitTransition({ stateRoot: fixture.root, runId: fixture.reducer.run_id, expectedRevision: 0, expectedStatePointerContentSha256: fixture.genesis.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fixture.initial.content_sha256 as Sha256Digest, transitionId: "f04-freeze", policy: fixture.reducer, event: transitionEvent("FREEZE_OBJECTIVE", {}), processMetadata });
    const bad = reidentify<M5ControlPolicyDocument>("pi_gacw_m5_control_policy_v0", fixture.policy, { starting_state_content_sha256: digest(804) });
    const kernel = createControlDecisionKernel({ stateRoot: fixture.root, runId: fixture.reducer.run_id, policy: bad, reducerPolicy: fixture.reducer, runAuthority: fixture.runAuthority });
    await assert.rejects(kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: advanced.statePointer.revision, expectedStatePointerContentSha256: advanced.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: advanced.workflowState.content_sha256 as Sha256Digest, transitionId: "f04-forged", processMetadata }), (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_POLICY_INVALID");
    assert.equal((await inspectRunStorage({ stateRoot: fixture.root, runId: fixture.reducer.run_id })).workflowState?.phase, "OBJECTIVE_FROZEN");
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test("F05 lower-layer hard enforcement cannot be weakened by an observable M5 declaration", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const fixture = directFast(reducer);
  const weak = reidentify<M5ControlPolicyDocument>("pi_gacw_m5_control_policy_v0", fixture.policy, { limits: fixture.policy.limits.map((entry) => entry.dimension === "WORKER_INVOCATION" ? { ...entry, hard_limit: 20, soft_limit: 20, enforcement_class: "OBSERVABLE_ONLY" } : entry) as never });
  const decision = evaluateAuthority({ policy: weak, state: fixture.state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(fixture.state, { intent: "AUTHORIZE_WORK", operationId: "f05-work", availableLogicalRoles: ["LUNA_EXECUTOR"] }) });
  const worker = decision.budget.find((entry) => entry.dimension === "WORKER_INVOCATION"); assert.equal(worker?.hard_limit, 2); assert.equal(worker?.enforcement_class, "HARD_ENFORCEABLE");
});

test("F06 explicit predecessor chronology is independent of lexical content hashes and rejects branches", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer)); const policy = m5Policy(reducer, state.content_sha256 as Sha256Digest); let pair: readonly M5ControlDecisionDocument[] | undefined;
  for (let index = 0; index < 200 && pair === undefined; index += 1) {
    const first = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(state, { blockReason: `BLOCKED_F06_A_${index}` }) });
    const second = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [first], request: pureRequest(state, { blockReason: `BLOCKED_F06_B_${index}` }) });
    if ([first, second].sort((a, b) => a.content_sha256.localeCompare(b.content_sha256)).at(-1)?.content_sha256 !== second.content_sha256) pair = [first, second];
  }
  assert.ok(pair); const chronological = pair; const lexical = [...chronological].sort((a, b) => a.content_sha256.localeCompare(b.content_sha256)); assert.deepEqual(orderDecisionHistory(lexical).map((entry) => entry.content_sha256), chronological.map((entry) => entry.content_sha256));
  const branch = reidentify<M5ControlDecisionDocument>("pi_gacw_m5_control_decision_v0", chronological[1]!, { blocking_reason: "BLOCKED_F06_BRANCH" });
  assert.throws(() => orderDecisionHistory([chronological[0]!, chronological[1]!, branch]), (error: unknown) => (error as { code?: string }).code === "M5_DECISION_INVALID");
});

test("F07 only exact typed transition-consumer evidence roots an M5 decision", async () => {
  const fixture = await makeStorage("f07");
  try {
    const decision = evaluateAuthority({ policy: fixture.policy, state: fixture.initial, reducerPolicy: fixture.reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(fixture.initial, { transitionId: "intended-f07", blockReason: "BLOCKED_F07" }) });
    await publishM5ManagedRecord({ stateRoot: fixture.root, runId: fixture.reducer.run_id, kind: "M5_CONTROL_POLICY", document: fixture.policy }); await publishM5ManagedRecord({ stateRoot: fixture.root, runId: fixture.reducer.run_id, kind: "M5_CONTROL_DECISION", document: decision });
    await commitTransition({ stateRoot: fixture.root, runId: fixture.reducer.run_id, expectedRevision: 0, expectedStatePointerContentSha256: fixture.genesis.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fixture.initial.content_sha256 as Sha256Digest, transitionId: "unrelated-f07", policy: fixture.reducer, event: transitionEvent("FREEZE_OBJECTIVE", {}), evidence: [{ bytes: Buffer.from(`${canonicalize(decision)}\n`), mediaType: "text/plain" }], processMetadata });
    const fresh = await inspectRunStorage({ stateRoot: fixture.root, runId: fixture.reducer.run_id }); assert.equal(fresh.managedRecordClassifications.find((entry) => entry.object.contentSha256 === decision.content_sha256)?.classification, "UNREFERENCED_MANAGED_RECORD");
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test("F08 run lock publishes complete owner bytes atomically and preserves malformed locks", async () => {
  const fixture = await makeStorage("f08");
  try {
    let candidateChecked = false; let publishedChecked = false;
    configureM5PersistenceTestHooks({ checkpoint: async (checkpoint, detail) => {
      if (checkpoint === "RUN_LOCK_CANDIDATE_READY") { const value = JSON.parse(await readFile(detail, "utf8")); assert.deepEqual(Object.keys(value).sort(), ["lock_id", "pid", "process_start_ticks"]); assert.match(value.process_start_ticks, /^[0-9]+$/); assert.equal((await readdir(join(fixture.root, "locks"))).some((name) => name.endsWith(".lock")), false); candidateChecked = true; }
      if (checkpoint === "RUN_LOCK_OWNER_PUBLISHED") { const value = JSON.parse(await readFile(detail, "utf8")); assert.equal(value.pid, process.pid); publishedChecked = true; }
    } });
    await withRunExclusive({ stateRoot: fixture.root, runId: fixture.reducer.run_id }, async () => undefined); configureM5PersistenceTestHooks(undefined);
    assert.equal(candidateChecked, true); assert.equal(publishedChecked, true); assert.deepEqual(await readdir(join(fixture.root, "locks")), []);
    let entered!: () => void; const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    let release!: () => void; const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const firstOwner = withRunExclusive({ stateRoot: fixture.root, runId: fixture.reducer.run_id }, async () => { entered(); await releasePromise; });
    await enteredPromise;
    await assert.rejects(withRunExclusive({ stateRoot: fixture.root, runId: fixture.reducer.run_id }, async () => undefined), (error: unknown) => (error as { code?: string }).code === "CONCURRENT_WRITER");
    release(); await firstOwner; assert.deepEqual(await readdir(join(fixture.root, "locks")), []);
    const lockName = `${sha256Bytes(Buffer.from(`pi-gacw-run-mutation:${fixture.reducer.run_id}`, "utf8")).slice(7)}.lock`; const lockPath = join(fixture.root, "locks", lockName); await writeFile(lockPath, "{", { mode: 0o600 });
    await assert.rejects(withRunExclusive({ stateRoot: fixture.root, runId: fixture.reducer.run_id }, async () => undefined), (error: unknown) => (error as { code?: string }).code === "CONCURRENT_WRITER"); assert.equal(await readFile(lockPath, "utf8"), "{");
    await rm(lockPath); await writeFile(lockPath, `${canonicalize({ lock_id: "0123456789abcdef0123456789abcdef", pid: 2_147_483_647, process_start_ticks: "0" })}\n`, { mode: 0o600 });
    await withRunExclusive({ stateRoot: fixture.root, runId: fixture.reducer.run_id }, async () => undefined); assert.deepEqual(await readdir(join(fixture.root, "locks")), []);
  } finally { configureM5PersistenceTestHooks(undefined); await rm(fixture.root, { recursive: true, force: true }); }
});

test("F09 AUTO selects frozen Single Owner fallback only when it is eligible", () => {
  const reducer = makePolicy("SINGLE_OWNER_SOL"); const initial = createInitialState(reducer, stateIdentities(reducer)); let state = initial;
  for (const type of ["FREEZE_OBJECTIVE", "ACQUIRE_LOCK", "CAPTURE_BASELINE", "ACCEPT_CLEAN_BASELINE", "PASS_FULL_PREFLIGHT", "VALIDATE_CONTRACT"] as const) state = applyEvent(state, reducer, type, type === "CAPTURE_BASELINE" ? { approval_required: false } : {});
  const base = m5Policy(reducer, initial.content_sha256 as Sha256Digest); const policy = reidentify<M5ControlPolicyDocument>("pi_gacw_m5_control_policy_v0", base, { requested_mode: "AUTO", insufficient_routing_evidence: "SINGLE_OWNER_SOL", route_facts: { ...base.route_facts, deterministic_acceptance: false } as never });
  const decision = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(state, { intent: "SELECT_ROUTE", availableLogicalRoles: ["SOL_OWNER"] }) }); assert.equal(decision.selected_route, "SINGLE_OWNER_SOL"); assert.equal(decision.outcome, "AUTHORIZE");
});

test("F10 lost-response reuse requires complete failure authority equivalence", async () => {
  const fixture = await makeStorage("f10");
  try {
    const kernel = createControlDecisionKernel({ stateRoot: fixture.root, runId: fixture.reducer.run_id, policy: fixture.policy, reducerPolicy: fixture.reducer, runAuthority: fixture.runAuthority }); const source = fixture.policy.content_sha256 as Sha256Digest;
    const base = { intent: "BLOCK" as const, expectedRevision: 0, expectedStatePointerContentSha256: fixture.genesis.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: fixture.initial.content_sha256 as Sha256Digest, transitionId: "f10-block", processMetadata, progressEvidence: { claimedKind: "EVIDENCE_BACKED_DIAGNOSIS" as const, evidenceContentSha256: [source] }, failures: [{ sourceLayer: "M5" as const, sourceErrorCode: "COMMAND_TIMEOUT", sourceRecordContentSha256: source, normalizedSignature: digest(810), operationId: "f10-op", scopeIdentity: digest(811) }] };
    const first = await kernel.evaluateControlDecision(base); assert.equal((await kernel.evaluateControlDecision(base)).reusedDecision, true);
    const originalFailure = base.failures[0]!;
    await assert.rejects(kernel.evaluateControlDecision({ ...base, failures: [{ sourceLayer: originalFailure.sourceLayer, sourceErrorCode: originalFailure.sourceErrorCode, sourceRecordContentSha256: originalFailure.sourceRecordContentSha256, normalizedSignature: originalFailure.normalizedSignature, operationId: originalFailure.operationId, scopeIdentity: digest(812) }] }), (error: unknown) => error instanceof ControlDecisionError && error.code === "TERMINAL_STATE_IMMUTABLE"); assert.equal(first.workflowState.phase, "BLOCKED");
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test("F11 finite failure mappings include rejected omissions and duplicate definitions fail initialization", () => {
  const expected = { RETENTION_DEADLINE_NOT_REACHED: "AUTHORITY_CONTRADICTION", RETENTION_NOT_TERMINAL: "STATE_DRIFT", RETENTION_TIMESTAMP_UNAVAILABLE: "CONTEXT_MISSING", M5_DECISION_CONFLICT: "AUTHORITY_CONTRADICTION", M5_POLICY_CONFLICT: "AUTHORITY_CONTRADICTION", M5_USAGE_CONFLICT: "AUTHORITY_CONTRADICTION", ORPHANED_UNCOMMITTED_EVIDENCE: "EVIDENCE_PUBLICATION_FAILURE", RUN_DIRECTORY_NOT_EMPTY: "STATE_DRIFT", EVIDENCE_STORE_FAILED: "EVIDENCE_PUBLICATION_FAILURE", SHORT_WRITE: "EVIDENCE_PUBLICATION_FAILURE", TERMINAL_STATE_IMMUTABLE: "STATE_PUBLICATION_FAILURE" } as const;
  for (const [code, classification] of Object.entries(expected)) assert.equal(mapLowerLayerFailureCode(code), classification, code); assert.equal(mapLowerLayerFailureCode("unknown-runtime-value"), "EVIDENCE_INVALID");
  assert.throws(() => buildLowerLayerFailureMap([["DUPLICATE", "STATE_DRIFT"], ["DUPLICATE", "EVIDENCE_INVALID"]]), (error: unknown) => (error as { code?: string }).code === "FAILURE_CLASSIFICATION_INVALID");
  assert.throws(() => buildLayeredLowerLayerFailureMap([["M2", "DUPLICATE", "STATE_DRIFT"], ["M2", "DUPLICATE", "EVIDENCE_INVALID"]]), (error: unknown) => (error as { code?: string }).code === "FAILURE_CLASSIFICATION_INVALID");
});

test("F12 omitted semantic inputs cannot bypass managed deterministic recalculation", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const state = createInitialState(reducer, stateIdentities(reducer)); const policy = m5Policy(reducer, state.content_sha256 as Sha256Digest);
  const decision = evaluateAuthority({ policy, state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(state, { transitionId: "f12", blockReason: "BLOCKED_F12" }) }); const { available_logical_roles: _roles, content_sha256: _content, ...body } = structuredClone(decision) as any; const omitted = { ...body, content_sha256: sha256Canonical(body) } as M5ControlDecisionDocument;
  assert.equal(validateSchema("pi_gacw_m5_control_decision_v0", omitted).valid, false);
  const object = (kind: any, contentSha256: Sha256Digest) => ({ kind, contentSha256, relativePath: `${kind}/${contentSha256.slice(7)}.json` });
  const classes = classifyM5Authority({ runId: reducer.run_id, workflowState: state, workflowStates: new Map([[state.content_sha256, state]]), objects: [object("WORKFLOW_STATE", state.content_sha256 as Sha256Digest), object("M5_CONTROL_POLICY", policy.content_sha256 as Sha256Digest), object("M5_CONTROL_DECISION", omitted.content_sha256 as Sha256Digest)], priorClassifications: [], policies: new Map([[policy.content_sha256, policy]]), usage: new Map(), decisions: new Map([[omitted.content_sha256, omitted]]), reducerPolicies: new Map([[reducer.content_sha256, reducer]]), reachableRawEvidence: new Set(), typedTransitionDecisionDigests: new Set([omitted.content_sha256]) });
  assert.equal(classes.find((entry) => entry.object.kind === "M5_CONTROL_DECISION")?.classification, "INVALID_MANAGED_RECORD");
});

test("M5-R4 cross-finding integration rejects forged usage before it can affect budget or route admission", () => {
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const fixture = directFast(reducer); const forged = reidentify<M5UsageEvidenceDocument>("pi_gacw_m5_usage_evidence_v0", usage(fixture.policy, fixture.state.content_sha256 as Sha256Digest, "integrated"), { source_kind: "M5_CONTROL_DECISION" });
  assert.throws(() => evaluateAuthority({ policy: fixture.policy, state: fixture.state, reducerPolicy: reducer, persistedUsage: [], priorDecisions: [], request: pureRequest(fixture.state, { intent: "AUTHORIZE_WORK", operationId: "integrated-work", availableLogicalRoles: ["LUNA_EXECUTOR"], usageEvidence: [forged] }) }), (error: unknown) => (error as { code?: string }).code === "USAGE_EVIDENCE_INVALID");
});
