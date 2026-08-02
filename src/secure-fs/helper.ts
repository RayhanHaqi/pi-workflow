import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { sha256Bytes, type Sha256Digest } from "../identity/index.js";
import { resolveExecutableIdentity, type ResolvedExecutableIdentity } from "../repository/executable.js";
import type { M4MutationJournal, M4SecureFilesystemCapabilityDocument } from "../schemas/index.js";
import { SecureFilesystemError, secureFilesystemError, type SecureFilesystemErrorCode } from "./errors.js";
import { secureFilesystemTestHooks } from "./test-hooks.js";

export const SECURE_FS_PROTOCOL = "pi-gacw-secure-fs-v1" as const;
const OUTPUT_LIMIT = 8 * 1024 * 1024;
const TIMEOUT_MS = 30_000;
const HELPER_ERROR_CODES = new Set<SecureFilesystemErrorCode>([
  "INVALID_ARGUMENT", "SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "SECURE_FS_CAPABILITY_MISMATCH", "INVALID_CANONICAL_PATH", "PATH_OUTSIDE_ROOT",
  "PATH_NOT_READABLE", "PATH_NOT_EDITABLE", "FROZEN_PATH", "OWNERSHIP_FORBIDS_MUTATION", "DATA_POLICY_FORBIDS_READ",
  "DATA_POLICY_FORBIDS_MUTATION", "SYMLINK_PATH", "MAGICLINK_PATH", "SPECIAL_FILE", "HARDLINK_TARGET", "PARENT_IDENTITY_DRIFT",
  "REPOSITORY_AUTHORITY_INVALID", "REPOSITORY_ROOT_MISMATCH", "FINAL_TARGET_IDENTITY_MISMATCH", "ROLLBACK_UNCERTAIN", "RESIDUE_IDENTITY_MISMATCH", "PREIMAGE_MISMATCH", "TARGET_ALREADY_EXISTS", "TARGET_MISSING", "PATCH_LIMIT_EXCEEDED", "READ_LIMIT_EXCEEDED",
  "SEARCH_LIMIT_EXCEEDED", "LIST_LIMIT_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED", "SECURE_WRITE_UNCERTAIN", "HELPER_PROTOCOL_ERROR",
]);

export interface HelperIdentity {
  readonly invocationPath: string;
  readonly realpath: string;
  readonly sha256: Sha256Digest;
  readonly python: ResolvedExecutableIdentity;
  readonly pythonSha256: Sha256Digest;
}

export type MutationRecoveryOutcome = "SUCCEEDED" | "FAILED" | "IDENTITY_MISMATCH";
export type MutationTargetVerification = "NOT_RUN" | "ABSENT" | "PREIMAGE" | "REPLACEMENT" | "MISMATCH" | "UNKNOWN";
export type MutationRecoveryDirectoryFsync = "NOT_RUN" | "SUCCEEDED" | "FAILED";

export interface MutationRecoveryEvidence {
  readonly operationNonce: string;
  readonly attempted: boolean;
  readonly outcome: MutationRecoveryOutcome;
  readonly remainingResidueCount: number | null;
  readonly targetVerification: MutationTargetVerification;
  readonly directoryFsync: MutationRecoveryDirectoryFsync;
  readonly helperSha256: Sha256Digest | null;
}

function helperCandidates(): readonly string[] {
  const override = secureFilesystemTestHooks().helperPath;
  if (override !== undefined) return [override];
  const modulePath = fileURLToPath(import.meta.url);
  return [
    resolve(dirname(modulePath), "../../helpers/secure_fs_guardian.py"),
    resolve(dirname(modulePath), "../../../helpers/secure_fs_guardian.py"),
  ];
}

export async function resolveSecureFilesystemHelper(): Promise<HelperIdentity> {
  for (const candidate of helperCandidates()) {
    try {
      if (!isAbsolute(candidate)) continue;
      const invocationPath = resolve(candidate);
      const invocationStats = await lstat(invocationPath);
      if (!invocationStats.isFile() || invocationStats.isSymbolicLink()) continue;
      const physical = await realpath(invocationPath);
      const stats = await lstat(physical);
      if (!stats.isFile() || stats.isSymbolicLink()) continue;
      const [bytes, python] = await Promise.all([readFile(physical), resolveExecutableIdentity("python3")]);
      const pythonSha256 = sha256Bytes(await readFile(python.realpath));
      return Object.freeze({ invocationPath, realpath: physical, sha256: sha256Bytes(bytes), python, pythonSha256 });
    } catch {
      // Try the source/packaged layout alternative.
    }
  }
  throw new SecureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Packaged secure filesystem helper is unavailable");
}

export async function assertSecureHelperIdentity(capability: M4SecureFilesystemCapabilityDocument): Promise<HelperIdentity> {
  const identity = await resolveSecureFilesystemHelper();
  if (identity.invocationPath !== capability.helper_invocation_path || identity.realpath !== capability.helper_realpath ||
      identity.sha256 !== capability.helper_sha256 || identity.python.invocationPath !== capability.python_invocation_path ||
      identity.python.realpath !== capability.python_realpath || identity.pythonSha256 !== capability.python_sha256) {
    throw new SecureFilesystemError("SECURE_FS_CAPABILITY_MISMATCH", "Secure filesystem helper authority changed");
  }
  return identity;
}

interface HelperFailure {
  readonly ok: false;
  readonly protocol: string;
  readonly code: string;
  readonly detail: string;
  readonly journal: M4MutationJournal | null;
}

interface HelperSuccess {
  readonly ok: true;
  readonly protocol: string;
  readonly result: unknown;
}

function parseResponse(bytes: Buffer): HelperSuccess | HelperFailure {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error: unknown) {
    throw secureFilesystemError("HELPER_PROTOCOL_ERROR", "Secure helper returned malformed output", error);
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Secure helper response is not an object");
  }
  const record = value as Record<string, unknown>;
  if (record["protocol"] !== SECURE_FS_PROTOCOL || typeof record["ok"] !== "boolean") {
    throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Secure helper protocol identity is invalid");
  }
  if (record["ok"] === true && Object.keys(record).sort().join(",") === "ok,protocol,result") return value as HelperSuccess;
  if (record["ok"] === false && Object.keys(record).sort().join(",") === "code,detail,journal,ok,protocol" &&
      typeof record["code"] === "string" && typeof record["detail"] === "string") {
    return { ...record, journal: parseMutationJournal(record["journal"]) } as HelperFailure;
  }
  throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Secure helper response shape is invalid");
}

const mutationErrorJournals = new WeakMap<object, M4MutationJournal>();
const mutationErrorRecoveries = new WeakMap<object, MutationRecoveryEvidence>();

const BASE_JOURNAL_KEYS = ["temporary_file_created", "temporary_bytes_written", "temporary_file_fsync_attempted", "temporary_file_fsync_completed",
  "atomic_operation", "atomic_rename_attempted", "atomic_rename_completed", "directory_fsync_attempt_count", "directory_fsync_completed_count",
  "preimage_validation", "rollback_required", "rollback_attempted", "rollback_completed", "rollback_directory_fsync_completed", "final_verification"] as const;
const EXTENDED_JOURNAL_KEYS = ["operation_nonce", "temporary_device", "temporary_inode", "temporary_nlink", "tombstone_created", "tombstone_device", "tombstone_inode", "tombstone_nlink", "preimage_device", "preimage_inode", "preimage_nlink",
  "recovery_attempted", "recovery_outcome", "recovery_residue_count", "recovery_target_verification", "recovery_directory_fsync", "recovery_helper_sha256"] as const;
const JOURNAL_DEFAULTS = {
  operation_nonce: null, temporary_device: null, temporary_inode: null, temporary_nlink: null, tombstone_created: false,
  tombstone_device: null, tombstone_inode: null, tombstone_nlink: null, preimage_device: null, preimage_inode: null, preimage_nlink: null, recovery_attempted: false,
  recovery_outcome: "NOT_RUN", recovery_residue_count: null, recovery_target_verification: "NOT_RUN",
  recovery_directory_fsync: "NOT_RUN", recovery_helper_sha256: null,
} as const;

export function parseMutationJournal(value: unknown): M4MutationJournal | null {
  if (value === null) return null;
  if (value === undefined || Array.isArray(value) || typeof value !== "object") throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Mutation journal is malformed");
  const raw = value as Record<string, unknown>;
  const keys = Object.keys(raw).sort(); const base = [...BASE_JOURNAL_KEYS].sort(); const extended = [...BASE_JOURNAL_KEYS, ...EXTENDED_JOURNAL_KEYS].sort();
  if (keys.join(",") !== base.join(",") && keys.join(",") !== extended.join(",")) throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Mutation journal is malformed");
  const record = { ...JOURNAL_DEFAULTS, ...raw } as Record<string, unknown>;
  const booleans = ["temporary_file_created", "temporary_file_fsync_attempted", "temporary_file_fsync_completed", "atomic_rename_attempted",
    "atomic_rename_completed", "rollback_required", "rollback_attempted", "rollback_completed", "rollback_directory_fsync_completed", "recovery_attempted", "tombstone_created"];
  const nullableIntegers = ["temporary_device", "temporary_inode", "temporary_nlink", "tombstone_device", "tombstone_inode", "tombstone_nlink", "preimage_device", "preimage_inode", "preimage_nlink", "recovery_residue_count"];
  if (booleans.some((key) => typeof record[key] !== "boolean") ||
      !["temporary_bytes_written", "directory_fsync_attempt_count", "directory_fsync_completed_count"].every((key) => Number.isSafeInteger(record[key]) && (record[key] as number) >= 0) ||
      nullableIntegers.some((key) => record[key] !== null && (!Number.isSafeInteger(record[key]) || (record[key] as number) < 0)) ||
      (record["operation_nonce"] !== null && (typeof record["operation_nonce"] !== "string" || !/^[0-9a-f]{32}$/u.test(record["operation_nonce"]))) ||
      (record["recovery_helper_sha256"] !== null && (typeof record["recovery_helper_sha256"] !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(record["recovery_helper_sha256"]))) ||
      !["NONE", "RENAME_NOREPLACE", "RENAME_EXCHANGE", "TOMBSTONE_NOREPLACE"].includes(String(record["atomic_operation"])) ||
      !["NOT_RUN", "PASS", "FAIL"].includes(String(record["preimage_validation"])) || !["NOT_RUN", "PASS", "FAIL"].includes(String(record["final_verification"])) ||
      !["NOT_RUN", "SUCCEEDED", "FAILED", "IDENTITY_MISMATCH"].includes(String(record["recovery_outcome"])) ||
      !["NOT_RUN", "ABSENT", "PREIMAGE", "REPLACEMENT", "MISMATCH", "UNKNOWN"].includes(String(record["recovery_target_verification"])) ||
      !["NOT_RUN", "SUCCEEDED", "FAILED"].includes(String(record["recovery_directory_fsync"])) ||
      ((record["temporary_bytes_written"] as number) > 0 && record["temporary_file_created"] !== true) ||
      (record["temporary_file_fsync_completed"] === true && record["temporary_file_fsync_attempted"] !== true) ||
      (record["atomic_rename_completed"] === true && record["atomic_rename_attempted"] !== true) ||
      ((record["directory_fsync_completed_count"] as number) > (record["directory_fsync_attempt_count"] as number)) ||
      (record["rollback_attempted"] === true && record["rollback_required"] !== true) ||
      (record["rollback_completed"] === true && (record["rollback_attempted"] !== true || record["atomic_rename_completed"] !== true)) ||
      (record["rollback_directory_fsync_completed"] === true && record["rollback_completed"] !== true) ||
      (record["recovery_outcome"] !== "NOT_RUN" && record["recovery_attempted"] !== true)) {
    throw new SecureFilesystemError("HELPER_PROTOCOL_ERROR", "Mutation journal fields are invalid");
  }
  return Object.freeze(record) as M4MutationJournal;
}

export function mutationJournalForError(error: unknown): M4MutationJournal | null {
  return error !== null && typeof error === "object" ? mutationErrorJournals.get(error) ?? null : null;
}

export function mutationRecoveryForError(error: unknown): MutationRecoveryEvidence | null {
  return error !== null && typeof error === "object" ? mutationErrorRecoveries.get(error) ?? null : null;
}

export function journalWithRecovery(journal: M4MutationJournal | null, evidence: MutationRecoveryEvidence): M4MutationJournal | null {
  if (journal === null) return null;
  return parseMutationJournal({ ...journal, recovery_attempted: evidence.attempted, recovery_outcome: evidence.outcome,
    recovery_residue_count: evidence.remainingResidueCount, recovery_target_verification: evidence.targetVerification,
    recovery_directory_fsync: evidence.directoryFsync, recovery_helper_sha256: evidence.helperSha256 });
}

export function attachMutationEvidence(error: SecureFilesystemError, journal: M4MutationJournal | null, evidence: MutationRecoveryEvidence): SecureFilesystemError {
  const enriched = journalWithRecovery(journal, evidence);
  if (enriched !== null) mutationErrorJournals.set(error, enriched);
  mutationErrorRecoveries.set(error, evidence);
  return error;
}

function attachJournal(error: SecureFilesystemError, journal: M4MutationJournal | null): SecureFilesystemError {
  if (journal !== null) mutationErrorJournals.set(error, journal);
  return error;
}

export async function invokeSecureFilesystemHelper(
  identity: HelperIdentity,
  request: Readonly<Record<string, unknown>>,
): Promise<unknown> {
  const hooks = secureFilesystemTestHooks();
  const complete: Record<string, unknown> = { protocol: SECURE_FS_PROTOCOL, ...request };
  if (hooks.checkpointSocket !== undefined) complete["_checkpoint_socket"] = hooks.checkpointSocket;
  if (hooks.checkpointStage !== undefined) complete["_checkpoint_stage"] = hooks.checkpointStage;
  if (hooks.secondaryCheckpointSocket !== undefined) complete["_secondary_checkpoint_socket"] = hooks.secondaryCheckpointSocket;
  if (hooks.secondaryCheckpointStage !== undefined) complete["_secondary_checkpoint_stage"] = hooks.secondaryCheckpointStage;
  if (hooks.failStage !== undefined) complete["_fail_stage"] = hooks.failStage;
  if (hooks.helperKillStage !== undefined) complete["_kill_stage"] = hooks.helperKillStage;
  if (hooks.recoveryFailStage !== undefined) complete["_recovery_fail_stage"] = hooks.recoveryFailStage;
  if (hooks.recoveryKillStage !== undefined) complete["_recovery_kill_stage"] = hooks.recoveryKillStage;
  if (hooks.recoveryCheckpointSocket !== undefined) complete["_recovery_checkpoint_socket"] = hooks.recoveryCheckpointSocket;
  if (hooks.recoveryCheckpointStage !== undefined) complete["_recovery_checkpoint_stage"] = hooks.recoveryCheckpointStage;
  const input = Buffer.from(JSON.stringify(complete), "utf8");
  const mutation = request["operation"] === "MUTATE" || request["operation"] === "RECOVER";
  const transportFailureCode: SecureFilesystemErrorCode = mutation ? "SECURE_WRITE_UNCERTAIN" : "OUTPUT_LIMIT_EXCEEDED";
  return new Promise<unknown>((resolveResult, rejectResult) => {
    const child = spawn(identity.python.invocationPath, [identity.invocationPath], {
      shell: false,
      stdio: ["pipe", "pipe", "pipe", "pipe"],
      env: { LC_ALL: "C", LANG: "C", PYTHONHASHSEED: "0" },
    });
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let exceeded = false;
    let settled = false;
    let latestJournal: M4MutationJournal | null = null;
    let journalBuffer = "";
    const journalStream = child.stdio[3];
    journalStream?.on("data", (chunk: Buffer) => {
      journalBuffer += chunk.toString("utf8");
      if (journalBuffer.length > 64 * 1024) { exceeded = true; child.kill("SIGKILL"); return; }
      let newline: number;
      while ((newline = journalBuffer.indexOf("\n")) >= 0) {
        const line = journalBuffer.slice(0, newline); journalBuffer = journalBuffer.slice(newline + 1);
        try {
          const value = JSON.parse(line) as Record<string, unknown>;
          if (value["protocol"] !== SECURE_FS_PROTOCOL || Object.keys(value).sort().join(",") !== "mutation_journal,protocol") throw new Error("journal envelope");
          latestJournal = parseMutationJournal(value["mutation_journal"]);
        } catch { exceeded = true; child.kill("SIGKILL"); }
      }
    });
    const timer = setTimeout(() => {
      if (settled) return;
      child.kill("SIGKILL");
      settled = true;
      rejectResult(attachJournal(new SecureFilesystemError(transportFailureCode, "Secure helper deadline expired"), latestJournal));
    }, TIMEOUT_MS);
    timer.unref();
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > OUTPUT_LIMIT) { exceeded = true; child.kill("SIGKILL"); return; }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > 64 * 1024) { exceeded = true; child.kill("SIGKILL"); }
    });
    child.once("error", (error: unknown) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      rejectResult(secureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Secure helper could not start", error));
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (exceeded) { rejectResult(attachJournal(new SecureFilesystemError(transportFailureCode, "Secure helper output exceeded its bound"), latestJournal)); return; }
      if (code !== 0 || signal !== null) {
        rejectResult(attachJournal(new SecureFilesystemError(mutation ? "SECURE_WRITE_UNCERTAIN" : "HELPER_PROTOCOL_ERROR", "Secure helper exited unexpectedly", { exit_code: code, signal }), latestJournal));
        return;
      }
      try {
        const response = parseResponse(Buffer.concat(stdout, stdoutBytes));
        if (!response.ok) {
          const journal = response.journal ?? latestJournal;
          const unresolvedInstalledMutation = mutation && journal?.atomic_rename_completed === true && journal.rollback_completed !== true && journal.final_verification !== "PASS";
          const selected = (response.code === "FINAL_TARGET_IDENTITY_MISMATCH" || unresolvedInstalledMutation) && mutation
            ? "SECURE_WRITE_UNCERTAIN"
            : HELPER_ERROR_CODES.has(response.code as SecureFilesystemErrorCode)
              ? response.code as SecureFilesystemErrorCode
              : mutation ? "SECURE_WRITE_UNCERTAIN" : "HELPER_PROTOCOL_ERROR";
          rejectResult(attachJournal(new SecureFilesystemError(selected, response.detail), journal));
          return;
        }
        resolveResult(response.result);
      } catch (error: unknown) {
        rejectResult(mutation ? attachJournal(secureFilesystemError("SECURE_WRITE_UNCERTAIN", "Secure mutation helper response is not authoritative", error), latestJournal) : error);
      }
    });
    child.stdin.on("error", () => { /* close/error handlers provide the authoritative outcome */ });
    child.stdin.end(input);
  });
}

export function sha256FileBytes(bytes: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
