import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const SECURE_PACKAGE = "pi-bounded-coding-workflow/secure-fs";
const SCOPED_PACKAGE = "pi-bounded-coding-workflow/scoped-tools";
function hasCode(error: unknown, expected: string): boolean { return (error as { code?: unknown })?.code === expected; }

test("M4 built public entrypoints are minimal and private implementation paths stay blocked", async () => {
  const secure = await import(SECURE_PACKAGE); const scoped = await import(SCOPED_PACKAGE);
  assert.deepEqual(Object.keys(secure).sort(), ["SecureFilesystemError", "createSecureFilesystem", "probeSecureFilesystemCapabilities"]);
  assert.deepEqual(Object.keys(scoped).sort(), ["ScopedToolGatewayError", "createScopedToolGateway"]);
  for (const subpath of [
    "pi-bounded-coding-workflow/secure-fs/client", "pi-bounded-coding-workflow/secure-fs/helper", "pi-bounded-coding-workflow/secure-fs/test-hooks",
    "pi-bounded-coding-workflow/scoped-tools/gateway", "pi-bounded-coding-workflow/scoped-tools/records", "pi-bounded-coding-workflow/scoped-tools/sandbox",
  ]) await assert.rejects(import(subpath), (error: unknown) => hasCode(error, "ERR_PACKAGE_PATH_NOT_EXPORTED"));
  const capability = await secure.probeSecureFilesystemCapabilities();
  assert.equal(capability.secure_fs_result, "SECURE_FS_AVAILABLE"); assert.equal(capability.command_sandbox_result, "COMMAND_SANDBOX_AVAILABLE"); assert.equal(capability.network_sandbox_result, "NETWORK_SANDBOX_AVAILABLE");
});

test("M4 packed artifact contains both helpers and resolves them from extracted dist", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-gacw-m4-pack-")); await chmod(root, 0o700);
  try {
    const packed = await execFileAsync("npm", ["pack", "--json", "--pack-destination", root], { cwd: process.cwd(), encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, LC_ALL: "C", LANG: "C", npm_config_audit: "false", npm_config_fund: "false", npm_config_update_notifier: "false" } });
    const report = JSON.parse(packed.stdout) as Array<{ filename: string; files: Array<{ path: string }> }>;
    assert.equal(report.length, 1); const entry = report[0]!; const paths = entry.files.map((file) => file.path).sort();
    assert.ok(paths.includes("helpers/secure_fs_guardian.py")); assert.ok(paths.includes("helpers/command_sandbox.py"));
    assert.ok(paths.includes("dist/src/secure-fs/index.js")); assert.ok(paths.includes("dist/src/scoped-tools/index.js"));
    await execFileAsync("tar", ["-xzf", join(root, entry.filename), "-C", root]);
    await symlink(await realpath(join(process.cwd(), "node_modules")), join(root, "package", "node_modules"), "dir");
    const secure = await import(`${pathToFileURL(join(root, "package", "dist", "src", "secure-fs", "index.js")).href}?packed=m4`);
    const capability = await secure.probeSecureFilesystemCapabilities();
    assert.equal(capability.secure_fs_result, "SECURE_FS_AVAILABLE"); assert.equal(capability.network_sandbox_result, "NETWORK_SANDBOX_AVAILABLE");
    const packageJson = JSON.parse(await readFile(join(root, "package", "package.json"), "utf8")) as { exports: Record<string, string> };
    assert.equal(packageJson.exports["./secure-fs"], "./dist/src/secure-fs/index.js"); assert.equal(packageJson.exports["./scoped-tools"], "./dist/src/scoped-tools/index.js");
  } finally { await rm(root, { recursive: true, force: true }); }
});
