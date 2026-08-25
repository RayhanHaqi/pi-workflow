import { realpath } from "node:fs/promises";

import { sha256Canonical } from "../identity/index.js";
import type {
  M3EnvironmentFingerprint,
  M3LockDiagnosticDocument,
  M3RepositoryIdentityDocument,
} from "../schemas/index.js";
import { RepositoryGuardError } from "./errors.js";
import { boundedExecutableVersion, resolveExecutable } from "./executable.js";
import { detachedFrozen } from "./utils.js";

export interface RequiredEnvironment {
  readonly node_version: string;
  readonly git_version: string;
  readonly python_version: string;
  readonly controller_version: "0.1.0";
  readonly node_path: string;
  readonly git_path: string;
  readonly python_path: string;
}

export async function currentEnvironmentFingerprint(
  repository: M3RepositoryIdentityDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<M3EnvironmentFingerprint> {
  const [nodePath, gitPath] = await Promise.all([
    realpath(process.execPath),
    resolveExecutable("git"),
  ]);
  const [nodeVersion, gitVersion] = await Promise.all([
    boundedExecutableVersion(nodePath),
    boundedExecutableVersion(gitPath),
  ]);
  if (nodeVersion !== process.version || gitVersion !== repository.git_version) {
    throw new RepositoryGuardError("ENVIRONMENT_DRIFT", "Controller or Git inspection executable identity changed");
  }
  const projection = {
    node_version: nodeVersion,
    git_version: gitVersion,
    python_version: lockDiagnostic.guardian_python_version,
    controller_version: "0.1.0" as const,
    node_path: nodePath,
    git_path: gitPath,
    python_path: lockDiagnostic.guardian_python_path,
    guardian_helper_path: lockDiagnostic.guardian_helper_path,
    guardian_helper_sha256: lockDiagnostic.guardian_helper_sha256,
  };
  return detachedFrozen({ ...projection, content_sha256: sha256Canonical(projection) });
}

export async function assertEnvironmentProducerSemantics(
  environment: M3EnvironmentFingerprint,
  repository: M3RepositoryIdentityDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<void> {
  const actual = await currentEnvironmentFingerprint(repository, lockDiagnostic);
  for (const key of [
    "node_version", "git_version", "python_version", "controller_version",
    "node_path", "git_path", "python_path", "guardian_helper_path", "guardian_helper_sha256", "content_sha256",
  ] as const) {
    if (environment[key] !== actual[key]) {
      throw new RepositoryGuardError("PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", `Environment producer field ${key} is inconsistent`);
    }
  }
}

/**
 * Exact live-environment continuity across a lock-generation change. The
 * environment fingerprint deliberately contains no generation-specific PID,
 * acquired_at, or acquisition nonce, so exact equality with a frozen root
 * preflight is meaningful for a resumed process holding a fresh acquisition.
 */
export async function assertEnvironmentFingerprintContinuity(
  expected: M3EnvironmentFingerprint,
  repository: M3RepositoryIdentityDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<void> {
  const actual = await currentEnvironmentFingerprint(repository, lockDiagnostic);
  for (const key of [
    "node_version", "git_version", "python_version", "controller_version",
    "node_path", "git_path", "python_path", "guardian_helper_path", "guardian_helper_sha256",
  ] as const) {
    if (expected[key] !== actual[key]) {
      throw new RepositoryGuardError("ENVIRONMENT_DRIFT", `Live environment field ${key} differs from the frozen root-preflight environment`);
    }
  }
}
