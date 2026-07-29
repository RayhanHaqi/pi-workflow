import { constants, type Stats } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

import { StateStoreError, stateStoreError } from "./errors.js";
import {
  beforeAtomicOperation,
  chooseTemporaryName,
  persistenceCheckpoint,
  type PersistenceCheckpoint,
} from "./test-hooks.js";

export type AtomicWriteCategory = "EVIDENCE" | "RECORD" | "TRANSITION" | "STATE";

const checkpoints: Readonly<Record<AtomicWriteCategory, readonly [PersistenceCheckpoint, PersistenceCheckpoint, PersistenceCheckpoint, PersistenceCheckpoint]>> = {
  EVIDENCE: ["EVIDENCE_TEMP_WRITTEN", "EVIDENCE_FILE_SYNCED", "EVIDENCE_RENAMED", "EVIDENCE_DIRECTORY_SYNCED"],
  RECORD: ["RECORD_TEMP_WRITTEN", "RECORD_FILE_SYNCED", "RECORD_RENAMED", "RECORD_DIRECTORY_SYNCED"],
  TRANSITION: ["TRANSITION_TEMP_WRITTEN", "TRANSITION_FILE_SYNCED", "TRANSITION_RENAMED", "TRANSITION_DIRECTORY_SYNCED"],
  STATE: ["STATE_TEMP_WRITTEN", "STATE_FILE_SYNCED", "STATE_RENAMED", "RUN_DIRECTORY_SYNCED"],
};

function modeOf(stats: Stats): number {
  return stats.mode & 0o777;
}

async function maybeLstat(path: string): Promise<Stats | undefined> {
  try {
    return await lstat(path);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export async function fsyncDirectory(path: string, finalPathForHooks = path): Promise<void> {
  await beforeAtomicOperation("directorySync", finalPathForHooks);
  const directory = await open(path, constants.O_RDONLY);
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

export async function assertPrivateDirectory(path: string): Promise<void> {
  let stats: Stats;
  try {
    stats = await lstat(path);
  } catch (error: unknown) {
    throw stateStoreError("STATE_DIRECTORY_MISSING", `Required directory is missing: ${path}`, error);
  }
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new StateStoreError("UNSAFE_DIRECTORY_TYPE", `Expected a real directory: ${path}`);
  }
  if (modeOf(stats) !== 0o700) {
    throw new StateStoreError("DIRECTORY_PERMISSION_MISMATCH", `${path} must have mode 0700`);
  }
}

export async function ensurePrivateDirectory(path: string): Promise<"CREATED" | "EXISTING"> {
  const existing = await maybeLstat(path);
  if (existing !== undefined) {
    await assertPrivateDirectory(path);
    return "EXISTING";
  }
  try {
    await mkdir(path, { mode: 0o700 });
    await chmod(path, 0o700);
    await fsyncDirectory(dirname(path), path);
    await assertPrivateDirectory(path);
    return "CREATED";
  } catch (error: unknown) {
    if (error instanceof StateStoreError) throw error;
    throw stateStoreError("DIRECTORY_CREATE_FAILED", `Cannot create private directory ${path}`, error);
  }
}

export async function assertRegularPrivateFile(path: string): Promise<Stats> {
  let stats: Stats;
  try {
    stats = await lstat(path);
  } catch (error: unknown) {
    throw stateStoreError("FILE_MISSING", `Required file is missing: ${path}`, error);
  }
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new StateStoreError("UNSAFE_FILE_TYPE", `Expected a regular file: ${path}`);
  }
  if (modeOf(stats) !== 0o600) {
    throw new StateStoreError("FILE_PERMISSION_MISMATCH", `${path} must have mode 0600`);
  }
  return stats;
}

async function writeCompletely(handle: Awaited<ReturnType<typeof open>>, bytes: Uint8Array, finalPath: string): Promise<void> {
  await beforeAtomicOperation("write", finalPath);
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (result.bytesWritten <= 0) {
      throw new StateStoreError("SHORT_WRITE", `No progress while writing ${finalPath}`);
    }
    offset += result.bytesWritten;
  }
  if (offset !== bytes.byteLength) {
    throw new StateStoreError("SHORT_WRITE", `Incomplete write for ${finalPath}`);
  }
}

function temporaryPath(finalPath: string): string {
  const generated = `.${basename(finalPath)}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  const selected = chooseTemporaryName(finalPath, generated);
  if (selected !== basename(selected) || selected.length === 0 || selected.includes("\u0000")) {
    throw new StateStoreError("INVALID_TEMPORARY_NAME", "The internal temporary name must remain a basename");
  }
  return join(dirname(finalPath), selected);
}

async function existingImmutableMatches(finalPath: string, bytes: Uint8Array): Promise<boolean> {
  const stats = await maybeLstat(finalPath);
  if (stats === undefined) return false;
  await assertRegularPrivateFile(finalPath);
  const existing = await readFile(finalPath);
  if (!existing.equals(Buffer.from(bytes))) {
    throw new StateStoreError("IMMUTABLE_OBJECT_MISMATCH", `Existing immutable object differs: ${finalPath}`);
  }
  return true;
}

async function atomicWrite(
  finalPath: string,
  bytes: Uint8Array,
  category: AtomicWriteCategory,
  immutable: boolean,
): Promise<{ readonly reused: boolean }> {
  await assertPrivateDirectory(dirname(finalPath));
  if (immutable && await existingImmutableMatches(finalPath, bytes)) return { reused: true };
  if (!immutable) {
    const existing = await maybeLstat(finalPath);
    if (existing !== undefined) await assertRegularPrivateFile(finalPath);
  }

  const tempPath = temporaryPath(finalPath);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let createdTemp = false;
  let renamed = false;
  const [tempWritten, fileSynced, fileRenamed, directorySynced] = checkpoints[category];

  try {
    try {
      handle = await open(tempPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      createdTemp = true;
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw stateStoreError("TEMPORARY_FILE_COLLISION", `Temporary file already exists: ${tempPath}`, error);
      }
      throw error;
    }
    await handle.chmod(0o600);
    await writeCompletely(handle, bytes, finalPath);
    await persistenceCheckpoint(tempWritten, finalPath);
    await beforeAtomicOperation("fileSync", finalPath);
    await handle.sync();
    await persistenceCheckpoint(fileSynced, finalPath);
    await handle.close();
    handle = undefined;

    if (immutable && await existingImmutableMatches(finalPath, bytes)) {
      await unlink(tempPath);
      createdTemp = false;
      return { reused: true };
    }
    await beforeAtomicOperation("rename", finalPath);
    await rename(tempPath, finalPath);
    createdTemp = false;
    renamed = true;
    await persistenceCheckpoint(fileRenamed, finalPath);
    await fsyncDirectory(dirname(finalPath), finalPath);
    await persistenceCheckpoint(directorySynced, finalPath);
    return { reused: false };
  } catch (error: unknown) {
    if (handle !== undefined) {
      try { await handle.close(); } catch { /* preserve the primary failure */ }
    }
    if (createdTemp && !renamed) {
      try { await unlink(tempPath); } catch (cleanupError: unknown) {
        if ((cleanupError as NodeJS.ErrnoException).code !== "ENOENT") {
          throw stateStoreError("TEMPORARY_CLEANUP_FAILED", `Cannot remove ${tempPath}`, cleanupError);
        }
      }
    }
    if (error instanceof StateStoreError) throw error;
    throw stateStoreError("ATOMIC_WRITE_FAILED", `Atomic ${category.toLowerCase()} write failed for ${finalPath}`, error);
  }
}

export async function publishImmutableFile(
  finalPath: string,
  bytes: Uint8Array,
  category: Exclude<AtomicWriteCategory, "STATE">,
): Promise<{ readonly reused: boolean }> {
  return atomicWrite(finalPath, bytes, category, true);
}

export async function replaceStateFile(finalPath: string, bytes: Uint8Array): Promise<void> {
  await atomicWrite(finalPath, bytes, "STATE", false);
}
