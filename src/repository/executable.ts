import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, lstat, realpath } from "node:fs/promises";
import { delimiter, isAbsolute, resolve } from "node:path";

import { RepositoryGuardError, repositoryGuardError } from "./errors.js";

export interface ResolvedExecutableIdentity {
  readonly invocationPath: string;
  readonly realpath: string;
}

/** Resolve one executable through absolute PATH entries and retain both the invoked and physical paths. */
export async function resolveExecutableIdentity(name: string): Promise<ResolvedExecutableIdentity> {
  if (name.length === 0 || name.includes("/") || name.includes("\u0000")) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "Executable name is invalid");
  }
  const pathValue = process.env["PATH"] ?? "";
  for (const entry of pathValue.split(delimiter)) {
    if (entry.length === 0 || !isAbsolute(entry)) continue;
    const candidate = resolve(entry, name);
    try {
      await access(candidate, constants.X_OK);
      const physical = await realpath(candidate);
      const stats = await lstat(physical);
      if (stats.isFile() && !stats.isSymbolicLink()) return { invocationPath: candidate, realpath: physical };
    } catch {
      // Continue deterministic PATH search.
    }
  }
  throw new RepositoryGuardError("ENVIRONMENT_DRIFT", `Required executable ${name} is unavailable`);
}

/** Resolve one executable to the canonical path used by existing environment fingerprints. */
export async function resolveExecutable(name: string): Promise<string> {
  return (await resolveExecutableIdentity(name)).realpath;
}

/** Execute a bounded, single-line version probe against an already-resolved executable. */
export async function boundedExecutableVersion(executable: string): Promise<string> {
  return new Promise<string>((resolveVersion, rejectVersion) => {
    const child = spawn(executable, ["--version"], {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, LC_ALL: "C", LANG: "C" },
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let exceeded = false;
    let settled = false;
    const rejectOnce = (error: unknown): void => {
      if (settled) return;
      settled = true;
      rejectVersion(error);
    };
    const collect = (chunk: Buffer): void => {
      bytes += chunk.byteLength;
      if (bytes > 4096) {
        exceeded = true;
        child.kill("SIGKILL");
        return;
      }
      chunks.push(Buffer.from(chunk));
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.once("error", (error: unknown) => {
      rejectOnce(repositoryGuardError("ENVIRONMENT_DRIFT", "Required version probe could not start", error));
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      if (exceeded) {
        rejectOnce(new RepositoryGuardError("ENVIRONMENT_DRIFT", "Required version output exceeded its bound"));
        return;
      }
      if (code !== 0 || signal !== null) {
        rejectOnce(new RepositoryGuardError("ENVIRONMENT_DRIFT", "Required version probe failed", { exit_code: code, signal }));
        return;
      }
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, bytes)).trim();
      } catch (error: unknown) {
        rejectOnce(repositoryGuardError("ENVIRONMENT_DRIFT", "Required version output is not UTF-8", error));
        return;
      }
      if (text.length === 0 || text.includes("\n") || text.includes("\r")) {
        rejectOnce(new RepositoryGuardError("ENVIRONMENT_DRIFT", "Required version output is malformed"));
        return;
      }
      settled = true;
      resolveVersion(text);
    });
  });
}
