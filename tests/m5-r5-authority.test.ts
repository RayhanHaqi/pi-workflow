import assert from "node:assert/strict";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createControlDecisionKernel, ControlDecisionError } from "../src/control/index.js";
import type { M5ImmutableRunAuthoritySources } from "../src/control/types.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { initializeRunStorage, inspectRunStorage } from "../src/persistence/index.js";
import { identifyContractDocument, type M3RepositoryIdentityDocument, type M3RepositoryStateTokenDocument, type M5ControlPolicyDocument } from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { digest, makePolicy, stateIdentities, transitionEvent, type MutableJson } from "./helpers.js";
import { m5Policy, m5RunAuthority } from "./m5-r3-fixtures.js";
import { processMetadata } from "./persistence-helpers.js";

function reidentify<T>(schema: Parameters<typeof identifyContractDocument>[0], value: object, patch: MutableJson): T {
  const { content_sha256: _content, ...body } = structuredClone(value) as MutableJson;
  return identifyContractDocument(schema, { ...body, ...patch }) as T;
}

async function fixture(name: string) {
  const root = await mkdtemp(join(tmpdir(), `m5r5-${name}-`)); await chmod(root, 0o700);
  const reducer = makePolicy("DIRECT_LUNA_HIGH"); const runAuthority = m5RunAuthority();
  const initial = createInitialState(reducer, { ...stateIdentities(reducer), contract_sha256: runAuthority.contract.contract_sha256 });
  const genesis = await initializeRunStorage({ stateRoot: root, runId: reducer.run_id, policy: reducer, initialState: initial, processMetadata });
  const policy = m5Policy(reducer, initial.content_sha256 as Sha256Digest, runAuthority);
  return { root, reducer, runAuthority, initial, genesis, policy };
}

function forgedRepository(authority: M5ImmutableRunAuthoritySources, patch: MutableJson): M3RepositoryIdentityDocument {
  const repository = reidentify<M3RepositoryIdentityDocument>("pi_gacw_repository_identity_v0", authority.repositoryIdentity, patch);
  return repository;
}

function unpersistedM3Token(policy: M5ControlPolicyDocument, authority: M5ImmutableRunAuthoritySources): M3RepositoryStateTokenDocument {
  const empty: readonly never[] = [];
  const fingerprint = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", {
    schema_id: "pi_gacw_git_state_fingerprint_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    repository_identity_content_sha256: policy.repository_identity_content_sha256, branch: authority.repositoryIdentity.branch,
    detached: authority.repositoryIdentity.detached, head: authority.repositoryIdentity.head, head_tree: authority.repositoryIdentity.head_tree,
    upstream_ref: null, ahead: null, behind: null, porcelain_v2_sha256: sha256Canonical({ staged: empty, unstaged: empty, untracked: empty, conflicts: empty }),
    index_sha256: digest(920), staged_diff_sha256: sha256Canonical(empty), unstaged_diff_sha256: sha256Canonical(empty),
    untracked_inventory_sha256: sha256Canonical(empty), staged: empty, unstaged: empty, untracked: empty, conflicts: empty,
    submodule_state_sha256: sha256Canonical(empty), worktree_list_sha256: authority.repositoryIdentity.worktree_list_sha256,
    active_operations: empty, index_lock: false, dirty: false,
  });
  const fileSet = { entries: empty, content_sha256: sha256Canonical(empty) };
  return identifyContractDocument("pi_gacw_repository_state_token_v0", {
    schema_id: "pi_gacw_repository_state_token_v0", schema_version: "0.1.0", content_projection_id: "document-content-v1",
    source: "FULL_PREFLIGHT", source_content_sha256: digest(921), prior_token_content_sha256: null, run_id: policy.run_id,
    repository_identity_content_sha256: policy.repository_identity_content_sha256, worktree_key: policy.worktree_key,
    branch: authority.repositoryIdentity.branch, head: authority.repositoryIdentity.head,
    worktree_list_sha256: authority.repositoryIdentity.worktree_list_sha256, git_fingerprint: fingerprint,
    instruction_fingerprint: fileSet, authority_fingerprint: fileSet, baseline_runtime_content_sha256: digest(922),
    lock_diagnostic_content_sha256: digest(923), task_scope_identity: policy.scope_sha256,
    workflow_owned_delta_sha256: sha256Canonical(empty), changed_paths: empty,
  }) as unknown as M3RepositoryStateTokenDocument;
}

async function rejectsWithoutPublication(f: Awaited<ReturnType<typeof fixture>>, policy: M5ControlPolicyDocument, runAuthority: M5ImmutableRunAuthoritySources): Promise<void> {
  const before = await inspectRunStorage({ stateRoot: f.root, runId: f.reducer.run_id });
  assert.ok(before.workflowState && before.statePointer && before.revision !== null);
  const kernel = createControlDecisionKernel({ stateRoot: f.root, runId: f.reducer.run_id, policy, reducerPolicy: f.reducer, runAuthority });
  await assert.rejects(kernel.inspectControlDecision(), (error: unknown) => error instanceof ControlDecisionError && ["M5_POLICY_INVALID", "M5_AUTHORITY_INCOMPLETE"].includes(error.code));
  await assert.rejects(kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: before.revision, expectedStatePointerContentSha256: before.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: before.workflowState.content_sha256 as Sha256Digest, transitionId: "r5-invalid", processMetadata, blockReason: "BLOCKED_INVALID_POLICY" }),
  (error: unknown) => error instanceof ControlDecisionError && ["M5_POLICY_INVALID", "M5_AUTHORITY_INCOMPLETE"].includes(error.code));
  const disk = await inspectRunStorage({ stateRoot: f.root, runId: f.reducer.run_id });
  assert.equal(disk.revision, before.revision); assert.equal(disk.workflowState?.content_sha256, before.workflowState.content_sha256);
  assert.equal(disk.managedRecordClassifications.some((entry) => entry.object.kind.startsWith("M5_")), false);
}

test("M5-R5 immutable policy authority remains valid at genesis, after transitions, on inspection, BLOCK, and terminal exact repeat", async () => {
  const f = await fixture("valid");
  try {
    const kernel = createControlDecisionKernel({ stateRoot: f.root, runId: f.reducer.run_id, policy: f.policy, reducerPolicy: f.reducer, runAuthority: f.runAuthority });
    assert.equal((await kernel.inspectControlDecision()).policyClassification, "ABSENT");
    const blocked = await kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: f.genesis.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: f.initial.content_sha256 as Sha256Digest, transitionId: "r5-valid-block", processMetadata, blockReason: "BLOCKED_R5_VALID" });
    assert.equal(blocked.workflowState.phase, "BLOCKED");
    const repeat = await kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: 0, expectedStatePointerContentSha256: f.genesis.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: f.initial.content_sha256 as Sha256Digest, transitionId: "r5-valid-block", processMetadata, blockReason: "BLOCKED_R5_VALID" });
    assert.equal(repeat.reusedDecision, true); assert.equal((await kernel.inspectControlDecision()).policyClassification, "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("M5-R5 forged policy tuple is non-authoritative on inspection and BLOCK paths", async (t) => {
  const cases: readonly [string, (f: Awaited<ReturnType<typeof fixture>>) => { policy: M5ControlPolicyDocument; authority: M5ImmutableRunAuthoritySources }][] = [
    ["wrong genesis", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { starting_state_content_sha256: digest(901) }), authority: f.runAuthority })],
    ["wrong repository identity", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { repository_identity_content_sha256: digest(902) }), authority: f.runAuthority })],
    ["wrong worktree", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { worktree_key: digest(903) }), authority: f.runAuthority })],
    ["wrong contract", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { contract_sha256: digest(904) }), authority: f.runAuthority })],
    ["wrong scope", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { scope_sha256: digest(905) }), authority: f.runAuthority })],
    ["wrong route map", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { route_map_sha256: digest(906) }), authority: f.runAuthority })],
    ["wrong route approval", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { route_map_approval_sha256: digest(907) }), authority: f.runAuthority })],
    ["wrong reducer", (f) => ({ policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { reducer_policy_content_sha256: digest(908) }), authority: f.runAuthority })],
    ["forged repository source", (f) => ({ policy: f.policy, authority: { ...f.runAuthority, repositoryIdentity: forgedRepository(f.runAuthority, { head: "abcdefabcdefabcdefabcdefabcdefabcdefabcd" }) } })],
    ["forged worktree source", (f) => ({ policy: f.policy, authority: { ...f.runAuthority, repositoryIdentity: forgedRepository(f.runAuthority, { worktree_key: digest(909) }) } })],
    ["policy and repository source forged together", (f) => { const repositoryIdentity = forgedRepository(f.runAuthority, { head: "abcdefabcdefabcdefabcdefabcdefabcdefabcd" }); return { policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { repository_identity_content_sha256: repositoryIdentity.content_sha256 }), authority: { ...f.runAuthority, repositoryIdentity } }; }],
    ["policy and contract target forged together", (f) => { const target = { ...f.runAuthority.contract.target_repository, head: "abcdefabcdefabcdefabcdefabcdefabcdefabcd" }; const contract = reidentify<typeof f.runAuthority.contract>("pi_gacw_contract_v0", f.runAuthority.contract, { target_repository: target }); return { policy: reidentify("pi_gacw_m5_control_policy_v0", f.policy, { contract_sha256: contract.contract_sha256 }), authority: { ...f.runAuthority, contract } }; }],
  ];
  for (const [name, create] of cases) await t.test(name, async () => {
    const f = await fixture(name.replaceAll(" ", "-")); try { const value = create(f); await rejectsWithoutPublication(f, value.policy, value.authority); }
    finally { await rm(f.root, { recursive: true, force: true }); }
  });
});

test("M5-R5 supplied M3 authority must be an exact persisted authoritative predecessor before any publication", async (t) => {
  for (const source of ["kernel", "request"] as const) await t.test(source, async () => {
    const f = await fixture(`m3-${source}`);
    try {
      const token = unpersistedM3Token(f.policy, f.runAuthority);
      const kernel = createControlDecisionKernel({ stateRoot: f.root, runId: f.reducer.run_id, policy: f.policy, reducerPolicy: f.reducer,
        runAuthority: f.runAuthority, ...(source === "kernel" ? { authoritativeSources: { m3StateTokens: [token] } } : {}) });
      if (source === "kernel") await assert.rejects(kernel.inspectControlDecision(),
        (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_AUTHORITY_INCOMPLETE");
      await assert.rejects(kernel.evaluateControlDecision({ intent: "BLOCK", expectedRevision: 0,
        expectedStatePointerContentSha256: f.genesis.statePointer.content_sha256 as Sha256Digest,
        expectedWorkflowStateContentSha256: f.initial.content_sha256 as Sha256Digest, transitionId: `r5-m3-${source}`, processMetadata,
        blockReason: "BLOCKED_UNPERSISTED_M3", ...(source === "request" ? { authoritativeSources: { m3StateTokens: [token] } } : {}) }),
      (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_AUTHORITY_INCOMPLETE");
      const disk = await inspectRunStorage({ stateRoot: f.root, runId: f.reducer.run_id });
      assert.equal(disk.revision, 0);
      assert.equal(disk.managedRecordClassifications.some((entry) => entry.object.kind.startsWith("M5_")), false);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
});

test("M5-R5 repository-affecting authorization requires persisted M3 token provenance", async () => {
  const f = await fixture("missing-m3-work");
  try {
    let committed = f.genesis;
    const events = [
      ["FREEZE_OBJECTIVE", {}], ["ACQUIRE_LOCK", {}], ["CAPTURE_BASELINE", { approval_required: false }], ["ACCEPT_CLEAN_BASELINE", {}],
      ["PASS_FULL_PREFLIGHT", {}], ["VALIDATE_CONTRACT", {}], ["SELECT_ROUTE", { execution_mode: "DIRECT_LUNA_HIGH" }],
      ["VALIDATE_DIRECT_CONTRACT", {}], ["REQUEST_DIRECT_APPROVAL", {}], ["APPROVE_DIRECT_TASK", {}], ["PASS_DIRECT_FAST_PREFLIGHT", {}],
    ] as const;
    for (const [index, [type, payload]] of events.entries()) committed = await (await import("../src/persistence/index.js")).commitTransition({
      stateRoot: f.root, runId: f.reducer.run_id, expectedRevision: committed.statePointer.revision,
      expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest,
      transitionId: `r5-missing-m3-${index}`, policy: f.reducer, event: transitionEvent(type, payload as MutableJson), processMetadata,
    });
    const kernel = createControlDecisionKernel({ stateRoot: f.root, runId: f.reducer.run_id, policy: f.policy, reducerPolicy: f.reducer, runAuthority: f.runAuthority });
    await assert.rejects(kernel.evaluateControlDecision({ intent: "AUTHORIZE_WORK", operationId: "missing-m3-work", availableLogicalRoles: ["LUNA_EXECUTOR"],
      expectedRevision: committed.statePointer.revision, expectedStatePointerContentSha256: committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: committed.workflowState.content_sha256 as Sha256Digest, transitionId: "r5-missing-m3-work", processMetadata }),
    (error: unknown) => error instanceof ControlDecisionError && error.code === "M5_AUTHORITY_INCOMPLETE");
    const disk = await inspectRunStorage({ stateRoot: f.root, runId: f.reducer.run_id });
    assert.equal(disk.workflowState?.phase, "DIRECT_FAST_PREFLIGHT"); assert.equal(disk.managedRecordClassifications.some((entry) => entry.object.kind.startsWith("M5_")), false);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("M5-R5 policy genesis remains bound after nonterminal state advancement", async () => {
  const f = await fixture("advanced");
  try {
    const advanced = await (await import("../src/persistence/index.js")).commitTransition({ stateRoot: f.root, runId: f.reducer.run_id, expectedRevision: 0,
      expectedStatePointerContentSha256: f.genesis.statePointer.content_sha256 as Sha256Digest, expectedWorkflowStateContentSha256: f.initial.content_sha256 as Sha256Digest,
      transitionId: "r5-freeze", policy: f.reducer, event: transitionEvent("FREEZE_OBJECTIVE", {}), processMetadata });
    const kernel = createControlDecisionKernel({ stateRoot: f.root, runId: f.reducer.run_id, policy: f.policy, reducerPolicy: f.reducer, runAuthority: f.runAuthority });
    assert.equal((await kernel.inspectControlDecision()).currentState.content_sha256, advanced.workflowState.content_sha256);
    const bad = reidentify<M5ControlPolicyDocument>("pi_gacw_m5_control_policy_v0", f.policy, { starting_state_content_sha256: advanced.workflowState.content_sha256 });
    await rejectsWithoutPublication({ ...f, genesis: advanced }, bad, f.runAuthority);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

// Keep the exact derived worktree identity formula visible in this focused authority suite.
assert.equal(m5RunAuthority().repositoryIdentity.worktree_key, sha256Bytes(Buffer.concat([Buffer.from("/work/repository/.git"), Buffer.from([0]), Buffer.from("/work/repository")])));
assert.ok(sha256Canonical(m5RunAuthority().contract.target_repository).startsWith("sha256:"));
