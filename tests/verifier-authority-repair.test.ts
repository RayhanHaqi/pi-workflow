import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { resolveRepositoryIdentity } from "../src/repository/identity.js";
import { identifyContractDocument, type M4CommandSpecification, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { probeM4Capabilities } from "../src/secure-fs/capabilities.js";
import { commandSpecProjection, freezePackageExecutionInputs } from "../src/scoped-tools/commands.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/errors.js";
import { runSandboxedCommand } from "../src/scoped-tools/sandbox.js";
import { freezeControllerVerificationCommandsForTests } from "../src/workflow-controller.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { git, removeRepositoryFixture } from "./repository-helpers.js";

const ROOT = process.cwd();
const TSC = join(ROOT, "node_modules", "typescript", "bin", "tsc");
const TSX = join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");

function token(value: Awaited<ReturnType<typeof createM4Fixture>>): Sha256Digest {
  return value.gateway.acceptedState.content_sha256 as Sha256Digest;
}

function code(error: unknown): unknown {
  return error instanceof ScopedToolGatewayError ? error.code : (error as { code?: unknown }).code;
}

async function cleanup(value: Awaited<ReturnType<typeof createM4Fixture>>): Promise<void> {
  await releaseAdmission(value.admission);
  await removeRepositoryFixture(value.fixture);
}

function reidentifyPolicy(base: M4ScopedToolPolicyDocument, changes: Partial<M4ScopedToolPolicyDocument>): M4ScopedToolPolicyDocument {
  const { content_sha256: _identity, ...body } = base;
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", { ...body, ...changes }) as M4ScopedToolPolicyDocument;
}

async function packageSpecification(
  commandId: string,
  script: string,
  args: readonly string[],
  repositoryRoot: string,
  readPaths: readonly { readonly path: string; readonly kind: "EXACT" | "PREFIX" }[] = [],
): Promise<M4CommandSpecification> {
  const base = await commandSpecification(commandId, "VERIFICATION", process.execPath, [script, ...args], { repositoryRoot, readPaths, timeoutMs: 60_000 });
  const sourceRootStats = await lstat(ROOT);
  const draft = {
    ...base,
    execution_input_layout: { kind: "PACKAGE_TREE" as const, source_root: ROOT, device: sourceRootStats.dev, inode: sourceRootStats.ino },
    execution_inputs: await freezePackageExecutionInputs(ROOT, script),
    environment: [{ key: "OPENSSL_CONF", value: "/dev/null" }],
  };
  return { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft)) } as M4CommandSpecification;
}

async function assertCaptureCleaned(root: string): Promise<void> {
  assert.deepEqual((await readdir(root)).filter((name) => name.startsWith(".m4exec-")).sort(), []);
}

test("production controller command authority executes the actual TypeScript, tsx, and project verifier entrypoints", async () => {
  const repository = await resolveRepositoryIdentity({ requestedPath: ROOT, requireHead: true });
  const commands = [
    { command_id: "controller-typescript", executable: process.execPath, args: ["typescript/bin/tsc", "--version"], cwd: "node_modules", timeout_ms: 60_000, readable_paths: [{ path: "node_modules", kind: "PREFIX" as const }] },
    { command_id: "controller-tsx", executable: process.execPath, args: ["tsx/dist/cli.mjs", "--version"], cwd: "node_modules", timeout_ms: 60_000, readable_paths: [{ path: "node_modules", kind: "PREFIX" as const }] },
    { command_id: "controller-project", executable: process.execPath, args: ["typescript/bin/tsc", "--noEmit", "--project", "../tsconfig.json", "--pretty", "false"], cwd: "node_modules", timeout_ms: 60_000,
      readable_paths: [{ path: "node_modules", kind: "PREFIX" as const }, { path: "package.json", kind: "EXACT" as const }, { path: "src", kind: "PREFIX" as const }, { path: "tests", kind: "PREFIX" as const }, { path: "tsconfig.json", kind: "EXACT" as const }] },
  ];
  const specifications = await freezeControllerVerificationCommandsForTests(repository, commands, { readable_paths: [], editable_paths: [], frozen_paths: [] });
  assert.equal(specifications.length, 3);
  assert.ok(specifications.every((specification) => specification.execution_input_layout !== "FLAT" && specification.write_paths.length === 0 && specification.network_policy === "FORBIDDEN"));
  const temporaryRoot = await mkdtemp(join(tmpdir(), "controller-verifier-authority-")); await chmod(temporaryRoot, 0o700);
  const capturesBefore = new Set((await readdir(tmpdir())).filter((name) => name.startsWith(".m4exec-")));
  try {
    const capability = (await probeM4Capabilities()).sandbox;
    const outcomes = [];
    for (const specification of specifications) outcomes.push(await runSandboxedCommand(repository, temporaryRoot, capability, specification));
    assert.deepEqual(outcomes.map((outcome) => outcome.exitCode), [0, 0, 0]);
    assert.deepEqual(outcomes.map((outcome) => outcome.setup?.noNewPrivs), [true, true, true]);
    assert.deepEqual(outcomes.map((outcome) => outcome.setup?.networkDenied), [true, true, true]);
    assert.match(outcomes[0]!.stdout.toString(), /^Version 5\.8\.3\n$/u);
    assert.match(outcomes[1]!.stdout.toString(), /^tsx v4\.19\.3\nnode v22\.22\.3\n$/u);
    const capturesAfter = (await readdir(tmpdir())).filter((name) => name.startsWith(".m4exec-") && !capturesBefore.has(name));
    assert.deepEqual(capturesAfter, [], "production immutable captures are deterministically cleaned");
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test("real TypeScript CLI executes from a content-bound package-relative immutable capture", async () => {
  let frozen!: M4CommandSpecification;
  const value = await createM4Fixture(async (fixture) => {
    frozen = await packageSpecification("typescript-real", TSC, ["--version"], fixture.repository);
    return [frozen];
  });
  try {
    assert.equal(frozen.execution_input_layout === "FLAT", false);
    assert.ok(frozen.execution_inputs.some((input) => input.capture_path === "node_modules/typescript/bin/tsc"));
    assert.ok(frozen.execution_inputs.some((input) => input.capture_path === "node_modules/typescript/lib/_tsc.js"));
    assert.deepEqual(frozen.read_paths, [], "the original mutable package tree is not sandbox-readable");
    const result = await value.gateway.run_verification_command({ commandId: "typescript-real", stateTokenContentSha256: token(value) });
    assert.equal(result.record.outcome, "PASS");
    assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "Version 5.8.3\n");
    assert.match(result.record.sandbox_capability_content_sha256, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(result.record.exit_code, 0);
    await assertCaptureCleaned(value.fixture.root);
  } finally { await cleanup(value); }
});

test("real tsx CLI resolves relative chunks and external package ancestry only from its immutable closure", async () => {
  let frozen!: M4CommandSpecification;
  const value = await createM4Fixture(async (fixture) => {
    frozen = await packageSpecification("tsx-real", TSX, ["--version"], fixture.repository);
    return [frozen];
  });
  try {
    const captures = new Set(frozen.execution_inputs.map((input) => input.capture_path));
    for (const required of [
      "node_modules/tsx/dist/cli.mjs",
      "node_modules/tsx/dist/package--YiorJOq.mjs",
      "node_modules/esbuild/lib/main.js",
      "node_modules/esbuild/package.json",
      "node_modules/@esbuild/linux-x64/bin/esbuild",
      "node_modules/get-tsconfig/dist/index.mjs",
      "node_modules/resolve-pkg-maps/dist/index.mjs",
    ]) assert.ok(captures.has(required), required);
    assert.deepEqual(frozen.read_paths, [], "Node cannot fall through to the original node_modules tree");
    const result = await value.gateway.run_verification_command({ commandId: "tsx-real", stateTokenContentSha256: token(value) });
    assert.equal(result.record.outcome, "PASS");
    assert.match(Buffer.from(result.stdoutBase64, "base64").toString(), /^tsx v4\.19\.3\nnode v22\.22\.3\n$/u);
    assert.equal(result.record.exit_code, 0);
    await assertCaptureCleaned(value.fixture.root);
  } finally { await cleanup(value); }
});

test("an original frozen prospective EXACT authority reads an M4-created output without gaining other read or write authority", async () => {
  let originalDigest = "";
  const value = await createM4Fixture(async (fixture, temporaryRoot) => {
    const script = join(temporaryRoot, "prospective-reader.mjs");
    const denied = join(fixture.root, "outside-secret.txt"); await writeFile(denied, "secret\n");
    await writeFile(script, `import { readFileSync, writeFileSync } from "node:fs";\nconst [approved, denied] = process.argv.slice(2);\nconst result = { approved: readFileSync(approved, "utf8") };\nfor (const [key, action] of [["unapprovedRead", () => readFileSync(denied, "utf8")], ["approvedWrite", () => writeFileSync(approved, "changed")], ["unapprovedWrite", () => writeFileSync(denied + ".new", "changed")]]) { try { action(); result[key] = "ESCAPED"; } catch (error) { result[key] = error.code; } }\nconsole.log(JSON.stringify(result));\n`);
    const base = await commandSpecification("prospective", "VERIFICATION", process.execPath, [script, join(fixture.repository, "created.txt"), denied], {
      repositoryRoot: fixture.repository, readPaths: [{ path: "created.txt", kind: "EXACT" }],
    });
    const draft = { ...base, execution_inputs: base.execution_inputs.filter((input) => input.path === script), environment: [{ key: "OPENSSL_CONF", value: "/dev/null" }] };
    const specification = { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft)) } as M4CommandSpecification;
    originalDigest = specification.command_spec_sha256;
    return [specification];
  }, (base) => reidentifyPolicy(base, { command_readable_paths: [...base.command_readable_paths, { path: "created.txt", kind: "EXACT" }] }));
  try {
    assert.equal(value.catalog.commands[0]!.command_spec_sha256, originalDigest);
    assert.ok(!value.policy.readable_paths.some((rule) => rule.path === "created.txt"), "worker readable scope remains narrow");
    assert.ok(value.policy.command_readable_paths.some((rule) => rule.path === "created.txt" && rule.kind === "EXACT"));
    const mutation = await value.gateway.apply_patch_scoped({
      stateTokenContentSha256: token(value), lockAcquisitionContentSha256: value.admission.lock.diagnostics.lock_acquisition_content_sha256 as Sha256Digest,
      operation: "CREATE", path: "created.txt", ownershipClass: "OWNER_ACCEPTED_MUTABLE", dataClass: "PUBLIC_SOURCE",
      expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null,
      replacementBytes: Buffer.from("prospective\n"), requestedFinalMode: 0o644,
    });
    assert.equal(mutation.receipt.outcome, "APPLIED");
    assert.equal(value.catalog.commands[0]!.command_spec_sha256, originalDigest, "authority was not regenerated");
    const result = await value.gateway.run_verification_command({ commandId: "prospective", stateTokenContentSha256: token(value) });
    const output = JSON.parse(Buffer.from(result.stdoutBase64, "base64").toString()) as Record<string, string>;
    assert.deepEqual(output, { approved: "prospective\n", unapprovedRead: "EACCES", approvedWrite: "EACCES", unapprovedWrite: "EACCES" });
    assert.equal(await readFile(join(value.fixture.repository, "created.txt"), "utf8"), "prospective\n");
    assert.deepEqual(value.catalog.commands[0]!.write_paths, []);
  } finally { await cleanup(value); }
});

test("actual TypeScript project enumeration fails with an insufficient read envelope and passes with frozen src/tests prefixes", async () => {
  const verifierReads = [{ path: "src", kind: "PREFIX" as const }, { path: "tests", kind: "PREFIX" as const }, { path: "tsconfig.json", kind: "EXACT" as const }];
  const value = await createM4Fixture(async (fixture) => [
    await packageSpecification("project-insufficient", TSC, ["--noEmit", "--project", "tsconfig.json", "--pretty", "false"], fixture.repository, [{ path: "tsconfig.json", kind: "EXACT" }]),
    await packageSpecification("project-complete", TSC, ["--noEmit", "--project", "tsconfig.json", "--pretty", "false"], fixture.repository, verifierReads),
  ], (base) => reidentifyPolicy(base, {
    command_readable_paths: [...base.command_readable_paths, { path: "tests", kind: "PREFIX" }, { path: "tsconfig.json", kind: "EXACT" }],
    path_authorities: [...base.path_authorities,
      { path: "tests", kind: "PREFIX", ownership_class: "PREEXISTING_UNRELATED", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: false, delete: false, mode_change: false },
      { path: "tsconfig.json", kind: "EXACT", ownership_class: "PREEXISTING_UNRELATED", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: false, delete: false, mode_change: false },
    ],
  }), async (fixture) => {
    await mkdir(join(fixture.repository, "tests"));
    await writeFile(join(fixture.repository, "src", "project.ts"), "export const value: number = 1;\n");
    await writeFile(join(fixture.repository, "tests", "project.test.ts"), "const tested: number = 1; void tested;\n");
    await writeFile(join(fixture.repository, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: true, noEmit: true, types: [] }, include: ["src/**/*.ts", "tests/**/*.ts"] }));
    await git(fixture.repository, "add", "src/project.ts", "tests/project.test.ts", "tsconfig.json");
    await git(fixture.repository, "commit", "-m", "project-shaped TypeScript fixture");
  });
  try {
    await assert.rejects(value.gateway.run_verification_command({ commandId: "project-insufficient", stateTokenContentSha256: token(value) }), (error: unknown) => code(error) === "COMMAND_EXIT_CODE_UNEXPECTED");
    const complete = await value.gateway.run_verification_command({ commandId: "project-complete", stateTokenContentSha256: token(value) });
    assert.equal(complete.record.outcome, "PASS");
    assert.equal(complete.record.exit_code, 0);
    assert.deepEqual(value.catalog.commands.find((command) => command.command_id === "project-complete")!.read_paths, verifierReads);
    assert.deepEqual(value.catalog.commands.find((command) => command.command_id === "project-complete")!.write_paths, []);
    assert.ok(!value.policy.readable_paths.some((rule) => rule.path === "tests"), "project enumeration authority is verifier-only");
    await assertCaptureCleaned(value.fixture.root);
  } finally { await cleanup(value); }
});
