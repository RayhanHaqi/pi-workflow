import assert from "node:assert/strict";
import { lstat } from "node:fs/promises";
import test from "node:test";

import { identifyContractDocument, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture } from "./repository-helpers.js";

async function absent(path: string): Promise<void> {
  await assert.rejects(lstat(path), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
}

test("m4-test-resource-cleanup: fixture ownership begins before command setup and survives setup failure", async () => {
  let callbackRoot = "";
  await assert.rejects(createM4Fixture(async (fixture) => {
    callbackRoot = fixture.root;
    throw new Error("intentional R3 setup failure");
  }), /intentional R3 setup failure/u);
  assert.notEqual(callbackRoot, "");
  await absent(callbackRoot);
});

test("m4-test-resource-cleanup: repository preparation and gateway construction failures remove their roots", async () => {
  let prepareRoot = "";
  await assert.rejects(createM4Fixture([], null, async (fixture) => {
    prepareRoot = fixture.root;
    throw new Error("intentional repository preparation failure");
  }), /intentional repository preparation failure/u);
  await absent(prepareRoot);

  let gatewayRoot = "";
  const invalidPolicy = (policy: M4ScopedToolPolicyDocument): M4ScopedToolPolicyDocument => {
    const { content_sha256: _identity, ...body } = policy;
    return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...body, task_scope_identity: `sha256:${"f".repeat(64)}` }) as M4ScopedToolPolicyDocument;
  };
  await assert.rejects(createM4Fixture(async (fixture) => {
    gatewayRoot = fixture.root;
    return [];
  }, invalidPolicy), /Tool policy authority differs|STATE_TOKEN_PROVENANCE_INVALID|M3 authority/u);
  assert.notEqual(gatewayRoot, "");
  await absent(gatewayRoot);
});

test("m4-test-resource-cleanup: assertion failure inside lexical fixture ownership still releases lock and root", async () => {
  let ownedRoot = "";
  async function ownedAssertionFailure(): Promise<void> {
    const value = await createM4Fixture();
    ownedRoot = value.fixture.root;
    try {
      assert.fail("intentional assertion failure owned by this fixture");
    } finally {
      await releaseAdmission(value.admission);
      await removeRepositoryFixture(value.fixture);
    }
  }
  await assert.rejects(ownedAssertionFailure, /intentional assertion failure owned by this fixture/u);
  assert.notEqual(ownedRoot, "");
  await absent(ownedRoot);
});

test("m4-test-resource-cleanup: normal completion has no verifier-owned fixture residue or active server handles", async () => {
  const value = await createM4Fixture();
  const root = value.fixture.root;
  try {
    assert.equal(Object.isFrozen(value.gateway), true);
  } finally {
    await releaseAdmission(value.admission);
    await removeRepositoryFixture(value.fixture);
  }
  await absent(root);
  const handles = (process as unknown as { _getActiveHandles?: () => unknown[] })._getActiveHandles?.() ?? [];
  assert.equal(handles.some((handle) => handle !== process.stdin && handle !== process.stdout && handle !== process.stderr && handle?.constructor?.name === "Server"), false);
});
