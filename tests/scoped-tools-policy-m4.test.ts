import assert from "node:assert/strict";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { identifyContractDocument, type M4CommandSpecification, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { commandSpecProjection, validateCommandCatalog } from "../src/scoped-tools/commands.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { validateToolPolicy } from "../src/scoped-tools/policy.js";
import { commandSpecification, makeM4Catalog, makeM4Policy } from "./m4-helpers.js";
import { createCleanAdmission, releaseAdmission } from "./repository-matrix-helpers.js";
import { createRepositoryFixture, removeRepositoryFixture } from "./repository-helpers.js";

function code(error: unknown): unknown { return error instanceof ScopedToolGatewayError ? error.code : (error as { code?: unknown })?.code; }
function reidentify(policy: M4ScopedToolPolicyDocument, overrides: Record<string, unknown>): M4ScopedToolPolicyDocument {
  const { content_sha256: _identity, ...body } = policy;
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...body, ...overrides }) as M4ScopedToolPolicyDocument;
}
function identifySpec(specification: M4CommandSpecification, overrides: Partial<M4CommandSpecification>): M4CommandSpecification {
  const draft = { ...specification, ...overrides } as M4CommandSpecification;
  return { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft)) };
}

test("M4 policy and catalog reject scope amplification and unsafe authority", async (t) => {
  const fixture = await createRepositoryFixture();
  const admission = await createCleanAdmission(fixture, { editable: ["created.txt", "generated", "src", "tracked.txt"], frozen: ["AGENTS.md", "AUTHORITY.md"] });
  const base = makeM4Policy(fixture, admission);
  try {
    const validate = (policy: M4ScopedToolPolicyDocument) => validateToolPolicy(policy, fixture.runId, admission.repository, admission.taskScopeIdentity, admission.editable, admission.frozen);
    await t.test("command write PREFIX cannot widen an editable EXACT rule", () => {
      const policy = reidentify(base, { command_writable_paths: [{ path: "tracked.txt", kind: "PREFIX" }] });
      assert.throws(() => validate(policy), (error: unknown) => code(error) === "PATH_NOT_EDITABLE");
    });
    await t.test("command read PREFIX cannot widen an exact path authority", () => {
      const policy = reidentify(base, { command_readable_paths: [{ path: "tracked.txt", kind: "PREFIX" }] });
      assert.throws(() => validate(policy), (error: unknown) => code(error) === "DATA_POLICY_FORBIDS_READ");
    });
    await t.test("verifier read authority may be broader than worker readable scope without widening it", () => {
      const policy = reidentify(base, { command_readable_paths: [...base.command_readable_paths, { path: "created.txt", kind: "EXACT" }] });
      const validated = validate(policy);
      assert.ok(validated.commandReadable.some((rule) => rule.path === "created.txt"));
      assert.ok(!validated.readable.some((rule) => rule.path === "created.txt"));
    });
    await t.test("command raw read cannot bypass SECRET projection", () => {
      const authorities = base.path_authorities.map((authority) => authority.path === "tracked.txt" ? { ...authority, data_class: "SECRET" as const, raw_read_approved: false } : authority);
      const policy = reidentify(base, { path_authorities: authorities });
      assert.throws(() => validate(policy), (error: unknown) => code(error) === "DATA_POLICY_FORBIDS_READ");
    });
    await t.test("command write cannot bypass baseline ownership", () => {
      const authorities = base.path_authorities.map((authority) => authority.path === "tracked.txt" ? { ...authority, ownership_class: "PREEXISTING_UNRELATED" as const } : authority);
      const policy = reidentify(base, { path_authorities: authorities });
      assert.throws(() => validate(policy), (error: unknown) => code(error) === "OWNERSHIP_FORBIDS_MUTATION");
    });
    const validated = validate(base);
    await t.test("catalog read PREFIX cannot widen policy command EXACT", async () => {
      const command = await commandSpecification("widen", "INSPECTION", "/usr/bin/printf", ["ok"], { repositoryRoot: fixture.repository, readPaths: [{ path: "tracked.txt", kind: "PREFIX" }] });
      const catalog = makeM4Catalog(fixture, admission, base, [command]);
      await assert.rejects(validateCommandCatalog(catalog, fixture.runId, admission.repository, validated), (error: unknown) => code(error) === "COMMAND_SPEC_MISMATCH");
    });
    await t.test("catalog rejects forbidden environment controls", async () => {
      const command = await commandSpecification("environment", "INSPECTION", "/usr/bin/printf", ["ok"], { repositoryRoot: fixture.repository });
      const altered = identifySpec(command, { environment: [{ key: "LD_PRELOAD", value: "/tmp/x" }] });
      const catalog = makeM4Catalog(fixture, admission, base, [altered]);
      await assert.rejects(validateCommandCatalog(catalog, fixture.runId, admission.repository, validated), (error: unknown) => code(error) === "COMMAND_FORBIDDEN");
    });
    await t.test("catalog rejects shell executables even without a shell expression", async () => {
      const command = await commandSpecification("shell", "INSPECTION", "/usr/bin/bash", ["--version"], { repositoryRoot: fixture.repository });
      const catalog = makeM4Catalog(fixture, admission, base, [command]);
      await assert.rejects(validateCommandCatalog(catalog, fixture.runId, admission.repository, validated), (error: unknown) => code(error) === "COMMAND_FORBIDDEN");
    });
    await t.test("catalog rejects package-manager symlink invocation paths", async () => {
      const command = await commandSpecification("package-manager", "INSPECTION", "/usr/bin/npm", ["--version"], { repositoryRoot: fixture.repository });
      const catalog = makeM4Catalog(fixture, admission, base, [command]);
      await assert.rejects(validateCommandCatalog(catalog, fixture.runId, admission.repository, validated), (error: unknown) => code(error) === "COMMAND_FORBIDDEN");
    });
    await t.test("catalog command-spec identity is mandatory", async () => {
      const command = await commandSpecification("identity", "INSPECTION", "/usr/bin/printf", ["ok"], { repositoryRoot: fixture.repository });
      const altered = { ...command, argv: [command.argv[0]!, "changed"] } as M4CommandSpecification;
      const catalog = makeM4Catalog(fixture, admission, base, [altered]);
      await assert.rejects(validateCommandCatalog(catalog, fixture.runId, admission.repository, validated), (error: unknown) => code(error) === "COMMAND_SPEC_MISMATCH");
    });
  } finally { await releaseAdmission(admission); await removeRepositoryFixture(fixture); }
});
