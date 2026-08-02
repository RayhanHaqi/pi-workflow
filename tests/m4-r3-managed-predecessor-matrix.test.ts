import assert from "node:assert/strict";
import test from "node:test";

import { m3ScopeIdentity } from "../src/identity/m3-scope.js";
import { runPostflight } from "../src/repository/index.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import {
  classification,
  disposeM4,
  gatewayToken,
  persistM4,
  reidentify,
  storedM4ByDigest,
  storedM4Document,
} from "./m4-r3-helpers.js";
import type {
  M4CommandResultDocument,
  M4CommandSpecification,
  M4CommandCatalogDocument,
  M4MutationReceiptDocument,
  M4PatchRequestDocument,
  M4ScopedToolPolicyDocument,
  M4ToolRequestDocument,
  M4ToolResultDocument,
} from "../src/schemas/index.js";

const ABSENT = `sha256:${"f".repeat(64)}` as const;
const WRONG_KIND = `sha256:${"e".repeat(64)}` as const;

async function chainFixture() {
  const value = await createM4Fixture(async (fixture, temporaryRoot) => [
    await commandSpecification("pass", "INSPECTION", "/usr/bin/printf", ["pass"], { repositoryRoot: fixture.repository }),
    await commandSpecification("other", "INSPECTION", "/usr/bin/printf", ["other"], { repositoryRoot: fixture.repository }),
  ]);
  const read = await value.gateway.read_scoped({ stateTokenContentSha256: gatewayToken(value), path: "tracked.txt", offset: 0, length: 8, mode: "TEXT" });
  const alternateRead = await value.gateway.read_scoped({ stateTokenContentSha256: gatewayToken(value), path: "src/a.txt", offset: 0, length: 8, mode: "TEXT" });
  const patchResult = await value.gateway.apply_patch_scoped({
    stateTokenContentSha256: gatewayToken(value),
    lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as `sha256:${string}`,
    operation: "CREATE", path: "created.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE",
    expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null,
    replacementBytes: Buffer.from("created\n"), requestedFinalMode: 0o644,
  });
  const command = await value.gateway.run_inspection_command({ commandId: "pass", stateTokenContentSha256: gatewayToken(value) });
  const alternateCommand = await value.gateway.run_inspection_command({ commandId: "other", stateTokenContentSha256: gatewayToken(value) });
  const secure = await storedM4Document(value, "SECURE_FS_CAPABILITY");
  const sandbox = await storedM4Document(value, "SANDBOX_CAPABILITY");
  const policy = await storedM4Document(value, "TOOL_POLICY");
  const catalog = await storedM4Document(value, "COMMAND_CATALOG");
  const readRequest = await storedM4ByDigest(value, "TOOL_REQUEST", read.resultRecord.request_content_sha256);
  const alternateReadRequest = await storedM4ByDigest(value, "TOOL_REQUEST", alternateRead.resultRecord.request_content_sha256);
  const readResult = await storedM4ByDigest(value, "TOOL_RESULT", read.resultRecord.content_sha256);
  const patch = await storedM4ByDigest(value, "PATCH_REQUEST", patchResult.receipt.request_content_sha256);
  const receipt = await storedM4ByDigest(value, "MUTATION_RECEIPT", patchResult.receipt.content_sha256);
  const commandRequest = await storedM4ByDigest(value, "TOOL_REQUEST", command.record.request_content_sha256);
  const commandResult = await storedM4ByDigest(value, "COMMAND_RESULT", command.record.content_sha256);
  const alternateCommandResult = await storedM4ByDigest(value, "COMMAND_RESULT", alternateCommand.record.content_sha256);
  return { value, secure, sandbox, policy, catalog, readRequest, alternateReadRequest, readResult, patch, receipt, commandRequest, commandResult, alternateCommandResult };
}

test("m4-r3-managed-predecessor-matrix: complete producer and successor chains are authoritative", async () => {
  const fixture = await chainFixture();
  try {
    for (const document of [fixture.secure, fixture.sandbox, fixture.policy, fixture.catalog, fixture.readRequest, fixture.readResult,
      fixture.patch, fixture.receipt, fixture.commandRequest, fixture.commandResult]) {
      assert.equal(await classification(fixture.value, document.content_sha256), "AUTHORITATIVE_MANAGED_RECORD", document.schema_id);
    }
    assert.notEqual(fixture.commandResult.state_token_after, null);
    assert.notEqual(fixture.receipt.successor_state_token_content_sha256, null);
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: missing direct predecessors remain incomplete across every dependent M4 kind", async () => {
  const fixture = await chainFixture();
  try {
    const cases: ReadonlyArray<[string, Parameters<typeof persistM4>[1], Record<string, unknown>, string]> = [
      ["command catalog policy", "COMMAND_CATALOG", fixture.catalog as unknown as Record<string, unknown>, "tool_policy_content_sha256"],
      ["read request policy", "TOOL_REQUEST", fixture.readRequest as unknown as Record<string, unknown>, "tool_policy_content_sha256"],
      ["patch policy", "PATCH_REQUEST", fixture.patch as unknown as Record<string, unknown>, "tool_policy_content_sha256"],
      ["tool result request", "TOOL_RESULT", fixture.readResult as unknown as Record<string, unknown>, "request_content_sha256"],
      ["mutation receipt request", "MUTATION_RECEIPT", fixture.receipt as unknown as Record<string, unknown>, "request_content_sha256"],
      ["command result request", "COMMAND_RESULT", fixture.commandResult as unknown as Record<string, unknown>, "request_content_sha256"],
    ];
    for (const [label, kind, base, field] of cases) {
      const document = reidentify(base["schema_id"] as never, base as never, (draft) => { draft[field] = ABSENT; }) as { readonly content_sha256: string };
      await persistM4(fixture.value, kind as never, document as never);
      assert.equal(await classification(fixture.value, document.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN", label);
    }
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: transitive missing dependencies propagate through a valid catalog", async () => {
  const fixture = await chainFixture();
  try {
    const editable = [...fixture.policy.editable_paths, { path: "missing-scope", kind: "EXACT" as const }];
    const frozen = fixture.policy.frozen_paths;
    const missingScopePolicy = reidentify("pi_gacw_scoped_tool_policy_v0", fixture.policy, (draft) => {
      draft["editable_paths"] = editable;
      draft["task_scope_identity"] = m3ScopeIdentity(editable.map((entry) => entry.path), frozen.map((entry) => entry.path));
      draft["policy_id"] = "missing-scope-policy";
    }) as M4ScopedToolPolicyDocument;
    const transitiveCatalog = reidentify("pi_gacw_command_catalog_v0", fixture.catalog, (draft) => {
      draft["tool_policy_content_sha256"] = missingScopePolicy.content_sha256;
      draft["catalog_id"] = "transitive-missing-catalog";
    }) as M4CommandCatalogDocument;
    await persistM4(fixture.value, "TOOL_POLICY", missingScopePolicy);
    await persistM4(fixture.value, "COMMAND_CATALOG", transitiveCatalog);
    assert.equal(await classification(fixture.value, missingScopePolicy.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
    assert.equal(await classification(fixture.value, transitiveCatalog.content_sha256), "INCOMPLETE_MANAGED_RECORD_CHAIN");
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: wrong-kind predecessor identities are invalid", async () => {
  const fixture = await chainFixture();
  try {
    const cases: ReadonlyArray<[Parameters<typeof persistM4>[1], Record<string, unknown>, string]> = [
      ["COMMAND_CATALOG", fixture.catalog as unknown as Record<string, unknown>, "tool_policy_content_sha256"],
      ["TOOL_REQUEST", fixture.readRequest as unknown as Record<string, unknown>, "tool_policy_content_sha256"],
      ["PATCH_REQUEST", fixture.patch as unknown as Record<string, unknown>, "tool_policy_content_sha256"],
      ["TOOL_RESULT", fixture.readResult as unknown as Record<string, unknown>, "request_content_sha256"],
      ["MUTATION_RECEIPT", fixture.receipt as unknown as Record<string, unknown>, "request_content_sha256"],
      ["COMMAND_RESULT", fixture.commandResult as unknown as Record<string, unknown>, "request_content_sha256"],
    ];
    for (const [kind, base, field] of cases) {
      const document = reidentify(base["schema_id"] as never, base as never, (draft) => { draft[field] = fixture.secure.content_sha256; }) as { readonly content_sha256: string };
      await persistM4(fixture.value, kind as never, document as never);
      assert.equal(await classification(fixture.value, document.content_sha256), "INVALID_MANAGED_RECORD", `${kind}: wrong kind`);
    }
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: producer-local contradictions are invalid even without predecessors", async () => {
  const fixture = await chainFixture();
  try {
    const badSecure = reidentify("pi_gacw_secure_fs_capability_v0", fixture.secure, (draft) => {
      draft["openat2_available"] = false;
      draft["supported_resolve_flags"] = [];
      draft["secure_fs_result"] = "SECURE_FS_AVAILABLE";
    });
    const badSandbox = reidentify("pi_gacw_sandbox_capability_v0", fixture.sandbox, (draft) => {
      draft["landlock_available"] = false;
      draft["landlock_abi"] = null;
      draft["result"] = "COMMAND_SANDBOX_AVAILABLE";
    });
    const badPolicy = reidentify("pi_gacw_scoped_tool_policy_v0", fixture.policy, (draft) => {
      draft["task_scope_identity"] = `sha256:${"a".repeat(64)}`;
    });
    for (const [kind, document] of [["SECURE_FS_CAPABILITY", badSecure], ["SANDBOX_CAPABILITY", badSandbox], ["TOOL_POLICY", badPolicy]] as const) {
      await persistM4(fixture.value, kind, document as never);
      assert.equal(await classification(fixture.value, document.content_sha256), "INVALID_MANAGED_RECORD", kind);
    }
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: wrong repository, worktree, and run are invalid rather than incomplete", async () => {
  const fixture = await chainFixture();
  try {
    const wrongRunPolicy = reidentify("pi_gacw_scoped_tool_policy_v0", fixture.policy, (draft) => { draft["run_id"] = "wrong-run"; });
    const wrongRepositoryPolicy = reidentify("pi_gacw_scoped_tool_policy_v0", fixture.policy, (draft) => { draft["repository_identity_content_sha256"] = `sha256:${"b".repeat(64)}`; });
    const wrongWorktreePolicy = reidentify("pi_gacw_scoped_tool_policy_v0", fixture.policy, (draft) => { draft["worktree_key"] = `sha256:${"c".repeat(64)}`; });
    const wrongRunCatalog = reidentify("pi_gacw_command_catalog_v0", fixture.catalog, (draft) => { draft["run_id"] = "wrong-run"; });
    const wrongRepositoryCatalog = reidentify("pi_gacw_command_catalog_v0", fixture.catalog, (draft) => { draft["repository_identity_content_sha256"] = `sha256:${"d".repeat(64)}`; });
    for (const [kind, document] of [
      ["TOOL_POLICY", wrongRunPolicy], ["TOOL_POLICY", wrongRepositoryPolicy], ["TOOL_POLICY", wrongWorktreePolicy],
      ["COMMAND_CATALOG", wrongRunCatalog], ["COMMAND_CATALOG", wrongRepositoryCatalog],
    ] as const) {
      await persistM4(fixture.value, kind, document as never);
      assert.equal(await classification(fixture.value, document.content_sha256), "INVALID_MANAGED_RECORD", `${kind}: context`);
    }
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: contradictory same-kind predecessors and local invalidity take precedence", async () => {
  const fixture = await chainFixture();
  try {
    const wrongReadResult = reidentify("pi_gacw_tool_result_v0", fixture.readResult, (draft) => {
      draft["request_content_sha256"] = fixture.alternateReadRequest.content_sha256;
    }) as M4ToolResultDocument;
    const alternatePatch = reidentify("pi_gacw_patch_request_v0", fixture.patch, (draft) => {
      draft["path"] = "generated/alternate.txt";
    }) as M4PatchRequestDocument;
    const wrongReceipt = reidentify("pi_gacw_mutation_receipt_v0", fixture.receipt, (draft) => {
      draft["request_content_sha256"] = alternatePatch.content_sha256;
    }) as M4MutationReceiptDocument;
    const wrongCommandResult = reidentify("pi_gacw_command_result_v0", fixture.commandResult, (draft) => {
      draft["request_content_sha256"] = fixture.alternateCommandResult.request_content_sha256;
    }) as M4CommandResultDocument;
    const invalidAndMissingRequest = reidentify("pi_gacw_tool_request_v0", fixture.readRequest, (draft) => {
      draft["request_kind"] = "COMMAND";
      draft["path"] = "tracked.txt";
      draft["tool_policy_content_sha256"] = ABSENT;
      draft["command_id"] = null;
    }) as M4ToolRequestDocument;
    await persistM4(fixture.value, "TOOL_RESULT", wrongReadResult);
    await persistM4(fixture.value, "PATCH_REQUEST", alternatePatch);
    await persistM4(fixture.value, "MUTATION_RECEIPT", wrongReceipt);
    await persistM4(fixture.value, "COMMAND_RESULT", wrongCommandResult);
    await persistM4(fixture.value, "TOOL_REQUEST", invalidAndMissingRequest);
    for (const document of [wrongReadResult, wrongReceipt, wrongCommandResult, invalidAndMissingRequest]) {
      assert.equal(await classification(fixture.value, document.content_sha256), "INVALID_MANAGED_RECORD", document.schema_id);
    }
  } finally { await disposeM4(fixture.value); }
});

test("m4-r3-managed-predecessor-matrix: cycles and depth-plus-one are fail-closed at the content-addressing boundary", async () => {
  const fixture = await chainFixture();
  try {
    // M4's schema edge graph is acyclic: producer capabilities have no M4
    // predecessor, catalogs point to policies, requests point to catalogs or
    // capabilities, and results/receipts point backwards. A self-reference
    // therefore cannot be canonically identified; a forged identity is local
    // invalidity, not a missing dependency or an accepted cycle.
    const forgedCycle = reidentify("pi_gacw_command_catalog_v0", fixture.catalog, (draft) => {
      draft["tool_policy_content_sha256"] = fixture.catalog.content_sha256;
    });
    await persistM4(fixture.value, "COMMAND_CATALOG", forgedCycle);
    assert.equal(await classification(fixture.value, forgedCycle.content_sha256), "INVALID_MANAGED_RECORD");
    // M4 successor records depend on the M3 token authority. Verify the
    // actual exact-boundary producer chain and its plus-one rejection rather
    // than asserting a constant in isolation.
    const depthFixture = await createM4Fixture();
    try {
      let token = depthFixture.admission.full.acceptedState;
      for (let depth = 1; depth <= 64; depth += 1) {
        token = (await runPostflight({ stateRoot: depthFixture.fixture.stateRoot, runId: depthFixture.fixture.runId, acceptedState: token,
          baseline: depthFixture.admission.baseline, instructionFiles: depthFixture.admission.selected.instructions,
          authorityFiles: depthFixture.admission.selected.authorities, editablePaths: depthFixture.admission.editable,
          frozenPaths: depthFixture.admission.frozen, taskScopeIdentity: depthFixture.admission.taskScopeIdentity,
          claimedWorkflowPaths: [], lock: depthFixture.admission.lock })).acceptedState;
      }
      assert.equal(token.prior_token_content_sha256 !== null, true);
      await assert.rejects(runPostflight({ stateRoot: depthFixture.fixture.stateRoot, runId: depthFixture.fixture.runId, acceptedState: token,
        baseline: depthFixture.admission.baseline, instructionFiles: depthFixture.admission.selected.instructions,
        authorityFiles: depthFixture.admission.selected.authorities, editablePaths: depthFixture.admission.editable,
        frozenPaths: depthFixture.admission.frozen, taskScopeIdentity: depthFixture.admission.taskScopeIdentity,
        claimedWorkflowPaths: [], lock: depthFixture.admission.lock }), (error: unknown) => (error as { readonly code?: unknown }).code === "STATE_TOKEN_CHAIN_TOO_DEEP");
    } finally { await disposeM4(depthFixture); }
  } finally { await disposeM4(fixture.value); }
});
