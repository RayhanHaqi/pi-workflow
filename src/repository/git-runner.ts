import { spawn } from "node:child_process";

import { RepositoryGuardError, repositoryGuardError } from "./errors.js";
import { repositoryTestHooks } from "./test-hooks.js";

const DEFAULT_OUTPUT_LIMIT = 16 * 1024 * 1024;

export interface InspectionResult {
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly exitCode: number;
  readonly signal: NodeJS.Signals | null;
}

function boundedLimit(): number {
  const configured = repositoryTestHooks().gitOutputLimitBytes;
  if (configured === undefined) return DEFAULT_OUTPUT_LIMIT;
  if (!Number.isSafeInteger(configured) || configured < 1) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "Private Git output limit is invalid");
  }
  return configured;
}

export async function runGitInspection(
  cwd: string,
  argv: readonly string[],
  acceptedExitCodes: readonly number[] = [0],
): Promise<InspectionResult> {
  const limit = boundedLimit();
  const gitArgv = ["-c", "color.ui=false", "-c", "core.quotepath=false", ...argv];
  return new Promise<InspectionResult>((resolve, reject) => {
    const child = spawn("git", gitArgv, {
      cwd,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        LC_ALL: "C",
        LANG: "C",
        GIT_PAGER: "cat",
        GIT_OPTIONAL_LOCKS: "0",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
      },
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let exceeded = false;
    let spawnFailure: unknown;

    child.once("error", (error: unknown) => {
      spawnFailure = error;
    });
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > limit) {
        exceeded = true;
        child.kill("SIGKILL");
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > limit) {
        exceeded = true;
        child.kill("SIGKILL");
        return;
      }
      stderr.push(Buffer.from(chunk));
    });
    child.once("close", (exitCode, signal) => {
      if (exceeded) {
        reject(new RepositoryGuardError(
          "BLOCKED_GIT_INSPECTION_OUTPUT_LIMIT",
          "A required Git inspection exceeded its bounded output limit",
          { output_limit_bytes: limit },
        ));
        return;
      }
      if (spawnFailure !== undefined) {
        reject(repositoryGuardError("GIT_INSPECTION_FAILED", "Git inspection could not start", spawnFailure));
        return;
      }
      if (exitCode === null) {
        reject(new RepositoryGuardError("GIT_INSPECTION_FAILED", "Git inspection ended without an exit code", { signal }));
        return;
      }
      const result = {
        stdout: Buffer.concat(stdout, stdoutBytes),
        stderr: Buffer.concat(stderr, stderrBytes),
        exitCode,
        signal,
      };
      if (!acceptedExitCodes.includes(exitCode)) {
        reject(new RepositoryGuardError(
          "GIT_INSPECTION_FAILED",
          "A required read-only Git inspection failed",
          { exit_code: exitCode, signal },
        ));
        return;
      }
      resolve(result);
    });
  });
}

export function decodeUtf8(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error: unknown) {
    throw repositoryGuardError(
      "BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING",
      `${label} contains bytes outside the canonical UTF-8 string contract`,
      error,
    );
  }
}

export function oneLine(bytes: Uint8Array, label: string): string {
  const text = decodeUtf8(bytes, label);
  const normalized = text.endsWith("\n") ? text.slice(0, -1) : text;
  if (normalized.length === 0 || normalized.includes("\n") || normalized.includes("\r") || normalized.includes("\u0000")) {
    throw new RepositoryGuardError("INVALID_GIT_OUTPUT", `${label} did not contain exactly one nonempty line`);
  }
  return normalized;
}

export function optionalOneLine(bytes: Uint8Array, label: string): string | null {
  if (bytes.byteLength === 0) return null;
  return oneLine(bytes, label);
}
