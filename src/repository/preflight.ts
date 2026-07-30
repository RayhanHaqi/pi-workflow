import { sha256Canonical, type Sha256Digest } from "../identity/index.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3EnvironmentFingerprint,
  type M3GitStateFingerprintDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3PreflightDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
} from "../schemas/index.js";
import {
  captureFileSetFingerprint,
  requireDurableBaselineAuthority,
  verifyBaselineBlobs,
  type FingerprintedFileInput,
} from "./baseline.js";
import { RepositoryGuardError } from "./errors.js";
import {
  assertEnvironmentProducerSemantics,
  currentEnvironmentFingerprint,
  type RequiredEnvironment,
} from "./environment.js";
import { captureGitState } from "./fingerprint.js";
import { resolveRepositoryIdentity } from "./identity.js";
import {
  assertWorktreeLockHeld,
  lockAcquisitionAuthority,
  lockMatchesRepository,
  type WorktreeLockHandle,
} from "./lock.js";
import {
  assertStateRootCapacity,
  assertUsableM3Storage,
  canonicalJsonRecordBytes,
  m3RecordExists,
  publishM3Record,
  rollbackNewM3Record,
} from "./storage.js";
import {
  assertBaselineApprovalMatches,
  assertFastPreflightRecordSemantics,
  assertFullPreflightSourceSemantics,
} from "./provenance.js";
import { loadAuthoritativeToken } from "./token-provenance.js";
import {
  assertAbsoluteNormalizedPath,
  assertBoolean,
  assertDigest,
  assertExactKeys,
  assertNonemptyString,
  assertRecord,
  compareText,
  detachedFrozen,
} from "./utils.js";

export type { RequiredEnvironment } from "./environment.js";

export interface RunFullPreflightInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly expectedRepository: M3RepositoryIdentityDocument;
  readonly expectedWorktreeKey: string;
  readonly expectedBranch: string | null;
  readonly expectedHead: string;
  readonly expectedWorktreeListSha256: string;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly requiredEnvironment: RequiredEnvironment;
  readonly taskScopeIdentity: Sha256Digest;
  readonly allowShallow: boolean;
  readonly allowPartialClone: boolean;
  readonly lock: WorktreeLockHandle;
}

export interface FullPreflightResult {
  readonly preflight: M3PreflightDocument;
  readonly acceptedState: M3RepositoryStateTokenDocument;
}

export interface RunFastPreflightInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly acceptedState: M3RepositoryStateTokenDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly taskScopeIdentity: Sha256Digest;
  readonly lock: WorktreeLockHandle;
}

function assertRequiredEnvironment(value: unknown): asserts value is RequiredEnvironment {
  assertRecord(value, "requiredEnvironment");
  assertExactKeys(value, [
    "node_version", "git_version", "python_version", "controller_version", "node_path", "git_path", "python_path",
  ], "requiredEnvironment");
  for (const field of ["node_version", "git_version", "python_version", "node_path", "git_path", "python_path"] as const) {
    assertNonemptyString(value[field], `requiredEnvironment.${field}`, 4096);
  }
  if (value["controller_version"] !== "0.1.0") throw new RepositoryGuardError("INVALID_ARGUMENT", "Controller version requirement is invalid");
}

export async function captureEnvironmentFingerprint(
  repository: M3RepositoryIdentityDocument,
  required: RequiredEnvironment,
  lockDiagnostic: M3LockDiagnosticDocument,
): Promise<M3EnvironmentFingerprint> {
  assertRequiredEnvironment(required);
  const actual = await currentEnvironmentFingerprint(repository, lockDiagnostic);
  for (const key of [
    "node_version", "git_version", "python_version", "controller_version", "node_path", "git_path", "python_path",
  ] as const) {
    if (actual[key] !== required[key]) {
      throw new RepositoryGuardError("ENVIRONMENT_DRIFT", `Required environment field ${key} changed`);
    }
  }
  return actual;
}

function assertRunId(value: unknown): asserts value is string {
  assertNonemptyString(value, "runId", 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value)) throw new RepositoryGuardError("INVALID_ARGUMENT", "runId is invalid");
}

export function assertRepositoryMatches(expected: M3RepositoryIdentityDocument, current: M3RepositoryIdentityDocument): void {
  if (current.physical_requested_path !== expected.physical_requested_path || current.worktree_root !== expected.worktree_root || current.git_toplevel !== expected.git_toplevel) {
    throw new RepositoryGuardError("WRONG_REPOSITORY", "Physical or Git repository root changed");
  }
  if (current.git_common_dir !== expected.git_common_dir || current.git_dir !== expected.git_dir || current.worktree_key !== expected.worktree_key) {
    throw new RepositoryGuardError("WRONG_WORKTREE", "Git common/worktree directory identity changed");
  }
  if (current.detached !== expected.detached) throw new RepositoryGuardError("DETACHED_HEAD_UNEXPECTED", "Detached-head state changed");
  if (current.branch !== expected.branch) throw new RepositoryGuardError("WRONG_BRANCH", "Branch identity changed");
  if (current.head !== expected.head || current.head_tree !== expected.head_tree) throw new RepositoryGuardError("HEAD_DRIFT", "HEAD identity changed");
  if (current.upstream_ref !== expected.upstream_ref || current.ahead !== expected.ahead || current.behind !== expected.behind) {
    throw new RepositoryGuardError("UPSTREAM_DRIFT", "Upstream identity or divergence changed");
  }
  if (current.worktree_list_sha256 !== expected.worktree_list_sha256) throw new RepositoryGuardError("WORKTREE_LIST_DRIFT", "Git worktree inventory changed");
  if (current.submodule_state_sha256 !== expected.submodule_state_sha256) throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Submodule state changed");
}

export function assertNoGitBlockers(fingerprint: M3GitStateFingerprintDocument): void {
  if (fingerprint.active_operations.length > 0) throw new RepositoryGuardError("GIT_OPERATION_IN_PROGRESS", "A Git operation is active");
  if (fingerprint.conflicts.length > 0) throw new RepositoryGuardError("GIT_CONFLICT_PRESENT", "Git conflicts are present");
  if (fingerprint.index_lock) throw new RepositoryGuardError("GIT_INDEX_LOCK_PRESENT", "Git index.lock is present");
}

function assertRepositoryPolicy(repository: M3RepositoryIdentityDocument, allowShallow: boolean, allowPartialClone: boolean): void {
  if (repository.shallow && !allowShallow) throw new RepositoryGuardError("UNSUPPORTED_REPOSITORY_STATE", "Shallow repository is disallowed");
  const partial = repository.partial_clone.promisor_remote !== null || repository.partial_clone.filters.length > 0;
  if (partial && !allowPartialClone) throw new RepositoryGuardError("UNSUPPORTED_REPOSITORY_STATE", "Partial-clone repository is disallowed");
}

async function persistPreflightAndToken(
  stateRoot: string,
  runId: string,
  preflight: M3PreflightDocument,
  token: M3RepositoryStateTokenDocument | null,
  lockAcquisition: M3LockAcquisitionDocument | null,
  lockDiagnostic: M3LockDiagnosticDocument | null,
): Promise<void> {
  const location = { stateRoot, runId };
  let additional = 0;
  const acquisitionWasNew = lockAcquisition !== null && !await m3RecordExists(location, "LOCK_ACQUISITION", lockAcquisition.content_sha256);
  const lockWasNew = lockDiagnostic !== null && !await m3RecordExists(location, "LOCK_DIAGNOSTIC", lockDiagnostic.content_sha256);
  const preflightWasNew = !await m3RecordExists(location, "PREFLIGHT", preflight.content_sha256);
  const tokenWasNew = token !== null && !await m3RecordExists(location, "REPOSITORY_STATE_TOKEN", token.content_sha256);
  if (lockAcquisition !== null && acquisitionWasNew) additional += canonicalJsonRecordBytes(lockAcquisition).byteLength;
  if (lockDiagnostic !== null && lockWasNew) additional += canonicalJsonRecordBytes(lockDiagnostic).byteLength;
  if (preflightWasNew) additional += canonicalJsonRecordBytes(preflight).byteLength;
  if (token !== null && tokenWasNew) additional += canonicalJsonRecordBytes(token).byteLength;
  await assertStateRootCapacity(stateRoot, additional);
  try {
    if (lockAcquisition !== null) {
      await publishM3Record(location, "LOCK_ACQUISITION", lockAcquisition as unknown as Record<string, unknown>);
    }
    if (lockDiagnostic !== null) {
      await publishM3Record(location, "LOCK_DIAGNOSTIC", lockDiagnostic as unknown as Record<string, unknown>);
    }
    await publishM3Record(location, "PREFLIGHT", preflight as unknown as Record<string, unknown>);
    if (token !== null) await publishM3Record(location, "REPOSITORY_STATE_TOKEN", token as unknown as Record<string, unknown>);
  } catch (publicationError: unknown) {
    if (token === null) {
      await rollbackNewM3Record(location, "PREFLIGHT", preflight, preflightWasNew);
      throw publicationError;
    }
    try {
      // A source without its token is explicitly unreferenced and harmless. The
      // token itself must not survive a failed pair publication.
      await rollbackNewM3Record(location, "REPOSITORY_STATE_TOKEN", token, tokenWasNew);
    } catch (tokenCleanupError: unknown) {
      try {
        // Breaking the source edge keeps an uncertain token non-authoritative.
        await rollbackNewM3Record(location, "PREFLIGHT", preflight, preflightWasNew);
      } catch (sourceCleanupError: unknown) {
        throw new RepositoryGuardError(
          "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
          "Preflight/token publication rollback could not break the authority chain",
          {},
          { cause: sourceCleanupError },
        );
      }
      throw new RepositoryGuardError(
        "STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
        "Failed token removal required source-record rollback",
        {},
        { cause: tokenCleanupError },
      );
    }
    throw publicationError;
  }
}

function validateFullInput(input: RunFullPreflightInput): void {
  assertRecord(input, "runFullPreflight input");
  assertExactKeys(input, [
    "stateRoot", "runId", "expectedRepository", "expectedWorktreeKey", "expectedBranch", "expectedHead",
    "expectedWorktreeListSha256", "baseline", "approval", "instructionFiles", "authorityFiles", "requiredEnvironment",
    "taskScopeIdentity", "allowShallow", "allowPartialClone", "lock",
  ], "runFullPreflight input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertRunId(input.runId);
  assertDocumentValid("pi_gacw_repository_identity_v0", input.expectedRepository);
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  if (input.approval !== null) assertDocumentValid("pi_gacw_baseline_approval_runtime_v0", input.approval);
  assertDigest(input.expectedWorktreeKey, "expectedWorktreeKey");
  assertDigest(input.expectedWorktreeListSha256, "expectedWorktreeListSha256");
  assertDigest(input.taskScopeIdentity, "taskScopeIdentity");
  if (input.expectedBranch !== null) assertNonemptyString(input.expectedBranch, "expectedBranch", 512);
  if (typeof input.expectedHead !== "string" || !/^[0-9a-f]{40,64}$/.test(input.expectedHead)) throw new RepositoryGuardError("INVALID_ARGUMENT", "expectedHead is invalid");
  assertBoolean(input.allowShallow, "allowShallow");
  assertBoolean(input.allowPartialClone, "allowPartialClone");
  assertRequiredEnvironment(input.requiredEnvironment);
}

export async function runFullPreflight(input: RunFullPreflightInput): Promise<FullPreflightResult> {
  validateFullInput(input);
  await assertUsableM3Storage({ stateRoot: input.stateRoot, runId: input.runId });
  if (input.baseline.run_id !== input.runId || input.baseline.repository.content_sha256 !== input.expectedRepository.content_sha256 ||
      input.expectedWorktreeKey !== input.expectedRepository.worktree_key || input.expectedBranch !== input.expectedRepository.branch ||
      input.expectedHead !== input.expectedRepository.head || input.expectedWorktreeListSha256 !== input.expectedRepository.worktree_list_sha256) {
    throw new RepositoryGuardError("BASELINE_APPROVAL_MISMATCH", "Full-preflight expectations do not match the exact baseline repository identity");
  }
  // Preserve established live-repository failure ordering; complete semantic
  // validation is performed by the exact durable loader before publication.
  if (input.baseline.baseline_mode === "APPROVED_BASELINE_DIRTY" && input.approval === null) {
    throw new RepositoryGuardError("BASELINE_DIRTY_NOT_APPROVED", "Approved-dirty baseline requires exact owner approval");
  }
  if (input.baseline.baseline_mode === "CLEAN_REQUIRED" && input.approval !== null) {
    throw new RepositoryGuardError("BASELINE_APPROVAL_MISMATCH", "Clean baseline must not use a dirty approval");
  }
  if (input.approval !== null) assertBaselineApprovalMatches(input.baseline, input.approval);
  const lockDiagnostic = await assertWorktreeLockHeld(input.lock);
  const lockAcquisition = lockAcquisitionAuthority(input.lock);
  if (!lockMatchesRepository(input.lock, input.expectedRepository) || lockDiagnostic.worktree_key !== input.expectedWorktreeKey ||
      lockDiagnostic.lock_acquisition_content_sha256 !== lockAcquisition.content_sha256) {
    throw new RepositoryGuardError("LOCK_LOST", "Held lock does not match full-preflight worktree identity");
  }

  const currentRepository = await resolveRepositoryIdentity({ requestedPath: input.expectedRepository.requested_path, requireHead: true });
  assertRepositoryMatches(input.expectedRepository, currentRepository);
  assertRepositoryPolicy(currentRepository, input.allowShallow, input.allowPartialClone);
  const [fingerprint, instructionFingerprint, authorityFingerprint, environmentFingerprint] = await Promise.all([
    captureGitState(currentRepository),
    captureFileSetFingerprint(input.instructionFiles, "INSTRUCTION_DRIFT"),
    captureFileSetFingerprint(input.authorityFiles, "AUTHORITY_DRIFT"),
    captureEnvironmentFingerprint(currentRepository, input.requiredEnvironment, lockDiagnostic),
  ]);
  assertNoGitBlockers(fingerprint);
  if (fingerprint.content_sha256 !== input.baseline.git_fingerprint.content_sha256) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Current Git state differs from the exact baseline snapshot");
  }
  if (instructionFingerprint.content_sha256 !== input.baseline.instruction_fingerprint.content_sha256) {
    throw new RepositoryGuardError("INSTRUCTION_DRIFT", "Instruction fingerprint differs from baseline");
  }
  if (authorityFingerprint.content_sha256 !== input.baseline.authority_fingerprint.content_sha256) {
    throw new RepositoryGuardError("AUTHORITY_DRIFT", "Authority fingerprint differs from baseline");
  }
  await verifyBaselineBlobs(input.stateRoot, input.baseline);
  await requireDurableBaselineAuthority(input.stateRoot, input.runId, input.baseline, input.approval);
  await assertStateRootCapacity(input.stateRoot, 0);

  const preflight = identifyContractDocument("pi_gacw_preflight_v0", {
    schema_id: "pi_gacw_preflight_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    preflight_kind: "FULL",
    run_id: input.runId,
    prior_token_content_sha256: null,
    repository: currentRepository,
    worktree_key: currentRepository.worktree_key,
    lock_diagnostic_content_sha256: lockDiagnostic.content_sha256,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    baseline_snapshot_sha256: input.baseline.accepted_baseline.baseline_sha256,
    baseline_approval_runtime_content_sha256: input.approval?.content_sha256 ?? null,
    git_fingerprint: fingerprint,
    instruction_fingerprint: instructionFingerprint,
    authority_fingerprint: authorityFingerprint,
    environment_fingerprint: environmentFingerprint,
    task_scope_identity: input.taskScopeIdentity,
    result: "PASS",
    blockers: [],
  }) as unknown as M3PreflightDocument;
  const token = identifyContractDocument("pi_gacw_repository_state_token_v0", {
    schema_id: "pi_gacw_repository_state_token_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    source: "FULL_PREFLIGHT",
    source_content_sha256: preflight.content_sha256,
    prior_token_content_sha256: null,
    run_id: input.runId,
    repository_identity_content_sha256: currentRepository.content_sha256,
    worktree_key: currentRepository.worktree_key,
    branch: currentRepository.branch,
    head: currentRepository.head,
    worktree_list_sha256: currentRepository.worktree_list_sha256,
    git_fingerprint: fingerprint,
    instruction_fingerprint: instructionFingerprint,
    authority_fingerprint: authorityFingerprint,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    lock_diagnostic_content_sha256: lockDiagnostic.content_sha256,
    task_scope_identity: input.taskScopeIdentity,
    workflow_owned_delta_sha256: sha256Canonical([]),
    changed_paths: [],
  }) as unknown as M3RepositoryStateTokenDocument;
  await assertEnvironmentProducerSemantics(preflight.environment_fingerprint, preflight.repository, lockDiagnostic);
  assertFullPreflightSourceSemantics(preflight, input.baseline, input.approval, token, lockDiagnostic, lockAcquisition);
  await persistPreflightAndToken(input.stateRoot, input.runId, preflight, token, lockAcquisition, lockDiagnostic);
  return detachedFrozen({ preflight, acceptedState: token });
}

function validateFastInput(input: RunFastPreflightInput): void {
  assertRecord(input, "runFastPreflight input");
  assertExactKeys(input, [
    "stateRoot", "runId", "acceptedState", "baseline", "instructionFiles", "authorityFiles", "taskScopeIdentity", "lock",
  ], "runFastPreflight input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertRunId(input.runId);
  assertDocumentValid("pi_gacw_repository_state_token_v0", input.acceptedState);
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  assertDigest(input.taskScopeIdentity, "taskScopeIdentity");
}

export async function runFastPreflight(input: RunFastPreflightInput): Promise<M3PreflightDocument> {
  validateFastInput(input);
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  await assertUsableM3Storage(location);
  const authority = await loadAuthoritativeToken(location, input.acceptedState, input.baseline);
  if (input.acceptedState.run_id !== input.runId || input.baseline.run_id !== input.runId ||
      input.acceptedState.baseline_runtime_content_sha256 !== input.baseline.content_sha256 ||
      input.acceptedState.task_scope_identity !== input.taskScopeIdentity) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Fast-preflight token, baseline, run, or task scope identity differs");
  }
  const lockDiagnostic = await assertWorktreeLockHeld(input.lock);
  const heldAcquisition = lockAcquisitionAuthority(input.lock);
  if (!lockMatchesRepository(input.lock, input.baseline.repository) ||
      lockDiagnostic.content_sha256 !== input.acceptedState.lock_diagnostic_content_sha256 ||
      heldAcquisition.content_sha256 !== authority.lockAcquisition.content_sha256) {
    throw new RepositoryGuardError("LOCK_LOST", "Fast-preflight lock identity differs from the accepted state");
  }
  const currentRepository = await resolveRepositoryIdentity({ requestedPath: input.baseline.repository.requested_path, requireHead: true });
  assertRepositoryMatches(input.baseline.repository, currentRepository);
  if (currentRepository.content_sha256 !== input.acceptedState.repository_identity_content_sha256 ||
      currentRepository.worktree_key !== input.acceptedState.worktree_key ||
      currentRepository.branch !== input.acceptedState.branch || currentRepository.head !== input.acceptedState.head ||
      currentRepository.worktree_list_sha256 !== input.acceptedState.worktree_list_sha256) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Repository identity differs from the exact accepted state token");
  }
  const [fingerprint, instructionFingerprint, authorityFingerprint] = await Promise.all([
    captureGitState(currentRepository),
    captureFileSetFingerprint(input.instructionFiles, "INSTRUCTION_DRIFT"),
    captureFileSetFingerprint(input.authorityFiles, "AUTHORITY_DRIFT"),
  ]);
  assertNoGitBlockers(fingerprint);
  if (fingerprint.content_sha256 !== input.acceptedState.git_fingerprint.content_sha256) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Current repository fingerprint differs from the exact accepted state");
  }
  if (instructionFingerprint.content_sha256 !== input.acceptedState.instruction_fingerprint.content_sha256) {
    throw new RepositoryGuardError("INSTRUCTION_DRIFT", "Instruction fingerprint changed after accepted state");
  }
  if (authorityFingerprint.content_sha256 !== input.acceptedState.authority_fingerprint.content_sha256) {
    throw new RepositoryGuardError("AUTHORITY_DRIFT", "Authority fingerprint changed after accepted state");
  }
  await verifyBaselineBlobs(input.stateRoot, input.baseline);

  // Fast preflight does not advance repository authority; it records only the successful comparison.
  const environment = await currentEnvironmentFingerprint(currentRepository, lockDiagnostic);
  const preflight = identifyContractDocument("pi_gacw_preflight_v0", {
    schema_id: "pi_gacw_preflight_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    preflight_kind: "FAST",
    run_id: input.runId,
    prior_token_content_sha256: input.acceptedState.content_sha256,
    repository: currentRepository,
    worktree_key: currentRepository.worktree_key,
    lock_diagnostic_content_sha256: lockDiagnostic.content_sha256,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    baseline_snapshot_sha256: input.baseline.accepted_baseline.baseline_sha256,
    baseline_approval_runtime_content_sha256: authority.approval?.content_sha256 ?? null,
    git_fingerprint: fingerprint,
    instruction_fingerprint: instructionFingerprint,
    authority_fingerprint: authorityFingerprint,
    environment_fingerprint: environment,
    task_scope_identity: input.taskScopeIdentity,
    result: "PASS",
    blockers: [],
  }) as unknown as M3PreflightDocument;
  await assertEnvironmentProducerSemantics(preflight.environment_fingerprint, preflight.repository, lockDiagnostic);
  assertFastPreflightRecordSemantics(preflight, input.acceptedState, input.baseline, authority.approval, lockDiagnostic, authority.lockAcquisition);
  await persistPreflightAndToken(input.stateRoot, input.runId, preflight, null, null, null);
  return detachedFrozen(preflight);
}
