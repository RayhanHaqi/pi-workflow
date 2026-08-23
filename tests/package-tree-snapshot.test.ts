import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical, type Sha256Digest } from "../src/identity/index.js";
import { resolveRepositoryIdentity } from "../src/repository/identity.js";
import type { M4CommandSpecification } from "../src/schemas/index.js";
import { resetSecureFilesystemTestHooks, setSecureFilesystemTestHooks } from "../src/secure-fs/test-hooks.js";
import { probeM4Capabilities } from "../src/secure-fs/capabilities.js";
import { commandSpecProjection, freezePackageExecutionInputs } from "../src/scoped-tools/commands.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/errors.js";
import { runSandboxedCommand } from "../src/scoped-tools/sandbox.js";
import { commandSpecification, createM4Fixture } from "./m4-helpers.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture } from "./repository-helpers.js";

interface PackageTree { readonly root: string; readonly app: string; readonly appMetadata: string; readonly depA: string; readonly depAMetadata: string; readonly depB: string }

function errorCode(error: unknown): unknown {
  return error instanceof ScopedToolGatewayError ? error.code : (error as { code?: unknown }).code;
}

async function writePackage(root: string, name: string, metadata: Record<string, unknown>, source = `export default ${JSON.stringify(name)};\n`): Promise<string> {
  const directory = join(root, "node_modules", name); await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "package.json"), JSON.stringify({ name, version: "1.0.0", type: "module", exports: "./index.mjs", ...metadata }));
  await writeFile(join(directory, "index.mjs"), source);
  return directory;
}

async function packageTree(): Promise<PackageTree> {
  const root = await mkdtemp(join(tmpdir(), "package-tree-snapshot-"));
  const app = await writePackage(root, "app", { dependencies: { "dep-a": "1.0.0" } }, `import value from "dep-a"; console.log(value);\n`);
  const depA = await writePackage(root, "dep-a", {}); const depB = await writePackage(root, "dep-b", {});
  return { root, app, appMetadata: join(app, "package.json"), depA, depAMetadata: join(depA, "package.json"), depB };
}

async function packageSpecification(commandId: string, tree: PackageTree, repositoryRoot: string): Promise<M4CommandSpecification> {
  const script = join(tree.app, "index.mjs");
  const base = await commandSpecification(commandId, "VERIFICATION", process.execPath, [script], { repositoryRoot, timeoutMs: 30_000 });
  const rootStats = await lstat(tree.root);
  const draft = {
    ...base,
    execution_input_layout: { kind: "PACKAGE_TREE" as const, source_root: tree.root, device: rootStats.dev, inode: rootStats.ino },
    execution_inputs: await freezePackageExecutionInputs(tree.root, script),
    environment: [{ key: "OPENSSL_CONF", value: "/dev/null" }],
  };
  return { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft)) } as M4CommandSpecification;
}

async function cleanupFixture(value: Awaited<ReturnType<typeof createM4Fixture>>): Promise<void> {
  await releaseAdmission(value.admission); await removeRepositoryFixture(value.fixture);
}

test("PACKAGE_TREE discovery and capture fail closed on deterministic metadata races", async (t) => {
  await t.test("stable package tree captures one complete content-bound closure", async () => {
    const tree = await packageTree();
    try {
      const inputs = await freezePackageExecutionInputs(tree.root, join(tree.app, "index.mjs"));
      const captures = new Set(inputs.map((input) => input.capture_path));
      assert.ok(captures.has("node_modules/app/package.json")); assert.ok(captures.has("node_modules/dep-a/package.json"));
      assert.ok(!captures.has("node_modules/dep-b/package.json"), "undeclared packages are outside authority");
    } finally { resetSecureFilesystemTestHooks(); await rm(tree.root, { recursive: true, force: true }); }
  });

  await t.test("nested node_modules dependency follows Node ancestry without duplicate capture", async () => {
    const tree = await packageTree();
    try {
      await rm(tree.depA, { recursive: true, force: true }); await writePackage(tree.app, "dep-a", {});
      const inputs = await freezePackageExecutionInputs(tree.root, join(tree.app, "index.mjs"));
      const captures = inputs.map((input) => input.capture_path);
      assert.ok(captures.includes("node_modules/app/node_modules/dep-a/package.json"));
      assert.equal(new Set(captures).size, captures.length);
    } finally { resetSecureFilesystemTestHooks(); await rm(tree.root, { recursive: true, force: true }); }
  });

  await t.test("package.json byte change with the same dependency set is rejected", async () => {
    const tree = await packageTree(); let changed = false;
    try {
      setSecureFilesystemTestHooks({ afterPackageMetadataDiscovery: async (root) => {
        if (root !== tree.app || changed) return; changed = true;
        await writeFile(tree.appMetadata, JSON.stringify({ name: "app", version: "2.0.0", type: "module", exports: "./index.mjs", dependencies: { "dep-a": "1.0.0" } }));
      } });
      await assert.rejects(freezePackageExecutionInputs(tree.root, join(tree.app, "index.mjs")), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
    } finally { resetSecureFilesystemTestHooks(); await rm(tree.root, { recursive: true, force: true }); }
  });

  await t.test("dependency declaration A to B is rejected instead of capturing B with closure A", async () => {
    const tree = await packageTree(); let changed = false;
    try {
      setSecureFilesystemTestHooks({ afterPackageMetadataDiscovery: async (root) => {
        if (root !== tree.app || changed) return; changed = true;
        await writeFile(tree.appMetadata, JSON.stringify({ name: "app", version: "2.0.0", type: "module", exports: "./index.mjs", dependencies: { "dep-b": "1.0.0" } }));
      } });
      await assert.rejects(freezePackageExecutionInputs(tree.root, join(tree.app, "index.mjs")), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
    } finally { resetSecureFilesystemTestHooks(); await rm(tree.root, { recursive: true, force: true }); }
  });

  await t.test("required dependency disappearance during discovery is rejected", async () => {
    const tree = await packageTree(); let changed = false;
    try {
      setSecureFilesystemTestHooks({ afterPackageMetadataDiscovery: async (root) => {
        if (root !== tree.app || changed) return; changed = true; await rm(tree.depA, { recursive: true, force: true });
      } });
      await assert.rejects(freezePackageExecutionInputs(tree.root, join(tree.app, "index.mjs")), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
    } finally { resetSecureFilesystemTestHooks(); await rm(tree.root, { recursive: true, force: true }); }
  });

  await t.test("nested dependency metadata change during its discovery is rejected", async () => {
    const tree = await packageTree(); let changed = false;
    try {
      setSecureFilesystemTestHooks({ afterPackageMetadataDiscovery: async (root) => {
        if (root !== tree.depA || changed) return; changed = true;
        await writeFile(tree.depAMetadata, JSON.stringify({ name: "dep-a", version: "2.0.0", type: "module", exports: "./index.mjs", optionalDependencies: { "dep-b": "1.0.0" } }));
      } });
      await assert.rejects(freezePackageExecutionInputs(tree.root, join(tree.app, "index.mjs")), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
    } finally { resetSecureFilesystemTestHooks(); await rm(tree.root, { recursive: true, force: true }); }
  });
});

test("catalog admission re-derives PACKAGE_TREE closure from content-bound metadata", async () => {
  const tree = await packageTree();
  try {
    await assert.rejects(createM4Fixture(async (fixture) => {
      const valid = await packageSpecification("missing-dependency", tree, fixture.repository);
      const executionInputs = valid.execution_inputs.filter((input) => !input.capture_path!.startsWith("node_modules/dep-a/"));
      const draft = { ...valid, execution_inputs: executionInputs };
      return [{ ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft)) } as M4CommandSpecification];
    }), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
  } finally { await rm(tree.root, { recursive: true, force: true }); }
});

test("pre-execution immutable capture re-derives closure from captured metadata bytes", async () => {
  const tree = await packageTree(); const temporaryRoot = await mkdtemp(join(tmpdir(), "package-tree-pre-exec-")); await chmod(temporaryRoot, 0o700);
  try {
    const valid = await packageSpecification("pre-execution-closure", tree, process.cwd());
    const executionInputs = valid.execution_inputs.filter((input) => !input.capture_path!.startsWith("node_modules/dep-a/"));
    const draft = { ...valid, execution_inputs: executionInputs };
    const forged = { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft)) } as M4CommandSpecification;
    const repository = await resolveRepositoryIdentity({ requestedPath: process.cwd(), requireHead: true });
    await assert.rejects(runSandboxedCommand(repository, temporaryRoot, (await probeM4Capabilities()).sandbox, forged), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
  } finally { await Promise.all([rm(tree.root, { recursive: true, force: true }), rm(temporaryRoot, { recursive: true, force: true })]); }
});

test("stable synthetic PACKAGE_TREE executes and post-catalog metadata drift fails before immutable execution", async () => {
  const stableTree = await packageTree(); let stable: Awaited<ReturnType<typeof createM4Fixture>> | undefined;
  try {
    stable = await createM4Fixture(async (fixture) => [await packageSpecification("stable-package", stableTree, fixture.repository)]);
    const result = await stable.gateway.run_verification_command({ commandId: "stable-package", stateTokenContentSha256: stable.gateway.acceptedState.content_sha256 as Sha256Digest });
    assert.equal(result.record.outcome, "PASS"); assert.equal(Buffer.from(result.stdoutBase64, "base64").toString(), "dep-a\n");
  } finally { if (stable !== undefined) await cleanupFixture(stable); await rm(stableTree.root, { recursive: true, force: true }); }

  const driftTree = await packageTree(); let drift: Awaited<ReturnType<typeof createM4Fixture>> | undefined;
  try {
    drift = await createM4Fixture(async (fixture) => [await packageSpecification("drift-package", driftTree, fixture.repository)]);
    await writeFile(driftTree.appMetadata, JSON.stringify({ name: "app", version: "2.0.0", type: "module", exports: "./index.mjs", dependencies: { "dep-b": "1.0.0" } }));
    await assert.rejects(drift.gateway.run_verification_command({ commandId: "drift-package", stateTokenContentSha256: drift.gateway.acceptedState.content_sha256 as Sha256Digest }), (error: unknown) => errorCode(error) === "EXECUTION_INPUT_DRIFT");
  } finally { if (drift !== undefined) await cleanupFixture(drift); await rm(driftTree.root, { recursive: true, force: true }); }
});
