import { createHash, randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import { assertSha256Digest, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { RepositoryGuardError, repositoryGuardError } from "./errors.js";

export function deepFreeze<T>(value: T, seen = new Set<object>()): T {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && "value" in descriptor) deepFreeze(descriptor.value, seen);
  }
  return Object.freeze(value);
}

export function detachedFrozen<T>(value: T): T {
  return deepFreeze(structuredClone(value));
}

export function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} must be an object`);
  }
}

export function assertExactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  if (canonicalize(actual) !== canonicalize(expected)) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} has unexpected or missing fields`);
  }
}

export function assertRequiredOptionalKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const actual = new Set(Object.keys(value));
  for (const key of required) {
    if (!actual.has(key)) throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} is missing ${key}`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of actual) {
    if (!allowed.has(key)) throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} contains unexpected field ${key}`);
  }
}

export function assertNonemptyString(value: unknown, label: string, maximum = 16_384): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.includes("\u0000")) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} must be a nonempty bounded string without NUL`);
  }
}

export function assertBoolean(value: unknown, label: string): asserts value is boolean {
  if (typeof value !== "boolean") throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} must be boolean`);
}

export function assertSafeNonnegativeInteger(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} must be a nonnegative safe integer`);
  }
}

export function assertDigest(value: unknown, label: string): asserts value is Sha256Digest {
  try {
    assertSha256Digest(value, label);
  } catch (error: unknown) {
    throw repositoryGuardError("INVALID_ARGUMENT", `${label} is not a SHA-256 digest`, error);
  }
}

export function assertAbsoluteNormalizedPath(value: unknown, label: string): asserts value is string {
  assertNonemptyString(value, label, 4096);
  if (!isAbsolute(value) || resolve(value) !== value) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} must be an absolute normalized path`);
  }
}

export function assertCanonicalRepositoryPath(value: unknown, label = "path"): asserts value is string {
  assertNonemptyString(value, label, 4096);
  if (
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    value.includes("\\") ||
    value.endsWith("/") ||
    /[\uD800-\uDFFF]/u.test(value)
  ) {
    throw new RepositoryGuardError("BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING", `${label} is not a canonical repository-relative path`);
  }
  const parts = value.split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    throw new RepositoryGuardError("BLOCKED_UNSUPPORTED_GIT_PATH_ENCODING", `${label} contains a forbidden path segment`);
  }
}

export function assertUniqueCanonicalPaths(paths: readonly unknown[], label: string): asserts paths is readonly string[] {
  const seen = new Set<string>();
  for (const path of paths) {
    assertCanonicalRepositoryPath(path, label);
    if (seen.has(path)) throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} contains a duplicate path`);
    seen.add(path);
  }
}

export function pathWithin(path: string, envelope: string): boolean {
  return path === envelope || path.startsWith(`${envelope}/`);
}

export function pathWithinAny(path: string, envelopes: readonly string[]): boolean {
  return envelopes.some((envelope) => pathWithin(path, envelope));
}

export function assertIsoTimestamp(value: unknown, label: string): asserts value is string {
  assertNonemptyString(value, label, 64);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", `${label} must be an exact UTC ISO-8601 millisecond timestamp`);
  }
}

export function addUtcDays(timestamp: string, days: number): string {
  assertIsoTimestamp(timestamp, "timestamp");
  if (!Number.isSafeInteger(days) || days < 1 || days > 30) {
    throw new RepositoryGuardError("INVALID_ARGUMENT", "retention days must be an integer from 1 through 30");
  }
  const milliseconds = Date.parse(timestamp) + days * 86_400_000;
  if (!Number.isSafeInteger(milliseconds)) throw new RepositoryGuardError("INVALID_ARGUMENT", "retention timestamp overflows");
  return new Date(milliseconds).toISOString();
}

export function modeOf(stats: Stats): number {
  return stats.mode & 0o7777;
}

export async function lstatOrUndefined(path: string): Promise<Stats | undefined> {
  try {
    return await lstat(path);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export interface HashedRegularFile {
  readonly realPath: string;
  readonly mode: number;
  readonly size: number;
  readonly contentSha256: Sha256Digest;
  readonly bytes: Buffer | null;
}

function sameFileState(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

/** Opens with O_NOFOLLOW, hashes exact bytes, and verifies the inode did not change while read. */
export async function hashRegularFile(path: string, captureBytes: boolean): Promise<HashedRegularFile> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error: unknown) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ELOOP") throw repositoryGuardError("BASELINE_SPECIAL_PATH", "A symlink cannot be inspected as baseline content", error);
    throw repositoryGuardError("BASELINE_SPECIAL_PATH", "A baseline path cannot be opened safely", error);
  }
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new RepositoryGuardError("BASELINE_SPECIAL_PATH", "A baseline path is not a regular file");
    if (!Number.isSafeInteger(before.size) || before.size < 0) {
      throw new RepositoryGuardError("INVALID_ARGUMENT", "A baseline file has an unsafe size");
    }
    const hash = createHash("sha256");
    const chunks: Buffer[] = [];
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < before.size) {
      const requested = Math.min(buffer.byteLength, before.size - position);
      const { bytesRead } = await handle.read(buffer, 0, requested, position);
      if (bytesRead <= 0) throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "A baseline file changed during hashing");
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      if (captureBytes) chunks.push(Buffer.from(chunk));
      position += bytesRead;
    }
    const after = await handle.stat();
    if (!sameFileState(before, after)) throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "A baseline file changed during hashing");
    const physical = await realpath(path);
    return {
      realPath: physical,
      mode: modeOf(before),
      size: before.size,
      contentSha256: `sha256:${hash.digest("hex")}`,
      bytes: captureBytes ? Buffer.concat(chunks, before.size) : null,
    };
  } finally {
    await handle.close();
  }
}

export function sha256Normalized(value: unknown): Sha256Digest {
  return sha256Canonical(value);
}

export function randomNonce(): string {
  return randomBytes(16).toString("hex");
}

export function digestHex(digest: string): string {
  assertDigest(digest, "digest");
  return digest.slice("sha256:".length);
}
