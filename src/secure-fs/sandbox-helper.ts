import { spawn } from "node:child_process";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { sha256Bytes, type Sha256Digest } from "../identity/index.js";
import { resolveExecutableIdentity, type ResolvedExecutableIdentity } from "../repository/executable.js";
import { SecureFilesystemError, secureFilesystemError } from "./errors.js";
import { secureFilesystemTestHooks } from "./test-hooks.js";

export const COMMAND_SANDBOX_PROTOCOL = "pi-gacw-command-sandbox-v1" as const;

export interface SandboxHelperIdentity {
  readonly invocationPath: string;
  readonly realpath: string;
  readonly sha256: Sha256Digest;
  readonly python: ResolvedExecutableIdentity;
  readonly pythonSha256: Sha256Digest;
}

function candidates(): readonly string[] {
  const override = secureFilesystemTestHooks().sandboxHelperPath;
  if (override !== undefined) return [override];
  const modulePath = fileURLToPath(import.meta.url);
  return [resolve(dirname(modulePath), "../../helpers/command_sandbox.py"), resolve(dirname(modulePath), "../../../helpers/command_sandbox.py")];
}

export async function resolveSandboxHelper(): Promise<SandboxHelperIdentity> {
  for (const selected of candidates()) {
    try {
      if (!isAbsolute(selected)) continue;
      const invocationPath = resolve(selected);
      const invocation = await lstat(invocationPath);
      if (!invocation.isFile() || invocation.isSymbolicLink()) continue;
      const physical = await realpath(invocationPath);
      const stats = await lstat(physical);
      if (!stats.isFile() || stats.isSymbolicLink()) continue;
      const [bytes, python] = await Promise.all([readFile(physical), resolveExecutableIdentity("python3")]);
      const pythonSha256 = sha256Bytes(await readFile(python.realpath));
      return Object.freeze({ invocationPath, realpath: physical, sha256: sha256Bytes(bytes), python, pythonSha256 });
    } catch { /* try packaged/source alternative */ }
  }
  throw new SecureFilesystemError("COMMAND_SANDBOX_UNAVAILABLE", "Packaged command sandbox helper is unavailable");
}

export async function invokeSandboxProbe(identity: SandboxHelperIdentity): Promise<Record<string, unknown>> {
  const input = Buffer.from(JSON.stringify({ protocol: COMMAND_SANDBOX_PROTOCOL, operation: "PROBE" }), "utf8");
  return new Promise((resolveProbe, rejectProbe) => {
    const child = spawn(identity.python.invocationPath, [identity.invocationPath], {
      shell: false, stdio: ["pipe", "pipe", "pipe"], env: { LC_ALL: "C", LANG: "C", PYTHONHASHSEED: "0" },
    });
    const chunks: Buffer[] = []; let bytes = 0; let stderr = 0; let exceeded = false;
    const timer = setTimeout(() => { exceeded = true; child.kill("SIGKILL"); }, 30_000); timer.unref();
    child.stdout.on("data", (chunk: Buffer) => { bytes += chunk.byteLength; if (bytes > 64 * 1024) { exceeded = true; child.kill("SIGKILL"); } else chunks.push(Buffer.from(chunk)); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.byteLength; if (stderr > 64 * 1024) { exceeded = true; child.kill("SIGKILL"); } });
    child.once("error", (error: unknown) => { clearTimeout(timer); rejectProbe(secureFilesystemError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox probe could not start", error)); });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (exceeded || code !== 0 || signal !== null) { rejectProbe(new SecureFilesystemError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox capability probe failed")); return; }
      try {
        const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, bytes)));
        if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("shape");
        const record = value as Record<string, unknown>;
        if (record["ok"] !== true || record["protocol"] !== COMMAND_SANDBOX_PROTOCOL || record["result"] === null || typeof record["result"] !== "object") throw new Error("protocol");
        resolveProbe(record["result"] as Record<string, unknown>);
      } catch (error: unknown) { rejectProbe(secureFilesystemError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox probe response is invalid", error)); }
    });
    child.stdin.on("error", () => { /* close/error handlers provide the authoritative outcome */ });
    child.stdin.end(input);
  });
}
