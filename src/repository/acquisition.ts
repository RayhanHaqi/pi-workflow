import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical } from "../identity/index.js";
import { publishImmutableFile } from "../persistence/atomic.js";
import {
  assertDocumentValid,
  type M3LockAcquisitionDocument,
} from "../schemas/index.js";
import { digestHex } from "./utils.js";

export class LockAcquisitionRootValidationError extends Error {
  public constructor(
    public readonly kind: "MISSING" | "INVALID",
    message: string,
    options: ErrorOptions = {},
  ) {
    super(message, options);
    this.name = "LockAcquisitionRootValidationError";
  }
}

function canonicalRecordBytes(document: unknown): Buffer {
  return Buffer.from(`${canonicalize(document)}\n`, "utf8");
}

function exactAbsolute(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path && !path.includes("\u0000");
}

export function lockAcquisitionGlobalPath(
  stateRoot: string,
  acquisition: Pick<M3LockAcquisitionDocument, "worktree_key" | "content_sha256">,
): string {
  return join(
    stateRoot,
    "locks",
    `${digestHex(acquisition.worktree_key)}.acquisition-${digestHex(acquisition.content_sha256)}.json`,
  );
}

/** Pure producer-fact validation shared by live consumers and historical classification. */
export function assertLockAcquisitionSemantics(acquisition: M3LockAcquisitionDocument): void {
  assertDocumentValid("pi_gacw_lock_acquisition_v0", acquisition);
  for (const path of [
    acquisition.state_root,
    acquisition.worktree_root,
    acquisition.git_common_dir,
    acquisition.lock_path,
    acquisition.owner_marker_path,
    acquisition.guardian_python_invocation_path,
    acquisition.guardian_python_realpath,
    acquisition.guardian_helper_path,
    acquisition.guardian_helper_realpath,
  ]) {
    if (!exactAbsolute(path)) throw new LockAcquisitionRootValidationError("INVALID", "Lock acquisition path is not exact and absolute");
  }
  const key = sha256Bytes(Buffer.concat([
    Buffer.from(acquisition.git_common_dir, "utf8"),
    Buffer.from([0]),
    Buffer.from(acquisition.worktree_root, "utf8"),
  ]));
  const lockBase = digestHex(acquisition.worktree_key);
  if (key !== acquisition.worktree_key ||
      acquisition.lock_path !== join(acquisition.state_root, "locks", `${lockBase}.lock`) ||
      acquisition.owner_marker_path !== join(acquisition.state_root, "locks", `${lockBase}.owner.json`) ||
      acquisition.guardian_helper_path !== acquisition.guardian_helper_realpath ||
      !/^[0-9a-f]{32}$/.test(acquisition.acquisition_nonce) ||
      new Date(acquisition.acquired_at).toISOString() !== acquisition.acquired_at ||
      acquisition.guardian_ready_sha256 !== sha256Canonical({
        protocol_version: acquisition.protocol_version,
        guardian_pid: acquisition.guardian_pid,
        acquisition_nonce: acquisition.acquisition_nonce,
      })) {
    throw new LockAcquisitionRootValidationError("INVALID", "Lock acquisition producer facts are inconsistent");
  }
}

/** Publish the state-root/worktree producer root only after guardian READY. */
export async function publishGlobalLockAcquisition(acquisition: M3LockAcquisitionDocument): Promise<void> {
  assertLockAcquisitionSemantics(acquisition);
  await publishImmutableFile(
    lockAcquisitionGlobalPath(acquisition.state_root, acquisition),
    canonicalRecordBytes(acquisition),
    "RECORD",
  );
}

/** Require the exact independently published producer root; source/token records cannot create this edge. */
export async function assertGlobalLockAcquisition(
  stateRoot: string,
  acquisition: M3LockAcquisitionDocument,
): Promise<void> {
  try {
    assertLockAcquisitionSemantics(acquisition);
    if (acquisition.state_root !== stateRoot) {
      throw new LockAcquisitionRootValidationError("INVALID", "Lock acquisition belongs to another state root");
    }
    const path = lockAcquisitionGlobalPath(stateRoot, acquisition);
    let stats;
    try {
      stats = await lstat(path);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new LockAcquisitionRootValidationError("MISSING", "Global lock acquisition producer root is missing", { cause: error });
      }
      throw error;
    }
    if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600) {
      throw new LockAcquisitionRootValidationError("INVALID", "Global lock acquisition producer root is unsafe");
    }
    const bytes = await readFile(path);
    if (!bytes.equals(canonicalRecordBytes(acquisition))) {
      throw new LockAcquisitionRootValidationError("INVALID", "Global lock acquisition producer root differs from its run record");
    }
  } catch (error: unknown) {
    if (error instanceof LockAcquisitionRootValidationError) throw error;
    throw new LockAcquisitionRootValidationError("INVALID", "Global lock acquisition producer root is invalid", { cause: error });
  }
}
