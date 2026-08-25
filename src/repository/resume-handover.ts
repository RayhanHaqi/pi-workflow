import { assertDocumentValid, identifyContractDocument } from "../schemas/index.js";
import type {
  M3BaselineRuntimeDocument,
  M3LockDiagnosticDocument,
  M3PreflightDocument,
  M3RepositoryIdentityDocument,
  M3RepositoryStateTokenDocument,
  M3ResumeLockHandoverDocument,
} from "../schemas/index.js";
import { sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { assertM3ResumeLockHandoverSemantics } from "../persistence/m3-authority.js";
import { captureFileSetFingerprint, verifyBaselineBlobs, type FingerprintedFileInput } from "./baseline.js";
import { currentEnvironmentFingerprint } from "./environment.js";
import { RepositoryGuardError } from "./errors.js";
import { captureGitState } from "./fingerprint.js";
import { resolveRepositoryIdentity } from "./identity.js";
import {
  assertWorktreeLockHeld,
  lockAcquisitionAuthority,
  lockMatchesRepository,
  type WorktreeLockHandle,
} from "./lock.js";
import { assertNoGitBlockers, assertRepositoryMatches } from "./preflight.js";
import { loadAuthoritativeToken } from "./token-provenance.js";
import {
  assertStateRootCapacity,
  assertUsableM3Storage,
  canonicalJsonRecordBytes,
  ensureResumeLockHandoverDirectory,
  loadM3Record,
  m3RecordExists,
  publishM3Record,
  readM3Records,
  rollbackNewM3Record,
} from "./storage.js";
import {
  assertAbsoluteNormalizedPath,
  assertDigest,
  assertExactKeys,
  assertNonemptyString,
  assertRecord,
  detachedFrozen,
} from "./utils.js";

const ENVIRONMENT_FIELDS = [
  "node_version", "git_version", "python_version", "controller_version",
  "node_path", "git_path", "python_path", "guardian_helper_path", "guardian_helper_sha256", "content_sha256",
] as const;

/**
 * Explicit M3 resume-lock-handover admission.
 *
 * A fresh process holding an exclusive worktree-lock acquisition B legally
 * continues ordinary M3/M4 operations by publishing an immutable
 * RESUME_LOCK_HANDOVER source plus successor token for the exact durable
 * authoritative tip. The predecessor is resolved from durable authority while
 * the lock is held; a genuine historical capability token can never force a
 * handover once durable authority has advanced.
 */
export interface RunResumeLockHandoverInput {
  readonly stateRoot: string;
  readonly runId: string;
  /** Opaque historical resume capability; honored only when it equals the durable tip. */
  readonly acceptedState: M3RepositoryStateTokenDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly taskScopeIdentity: Sha256Digest;
  readonly lock: WorktreeLockHandle;
}

export interface ResumeLockHandoverResult {
  readonly source: M3ResumeLockHandoverDocument;
  readonly acceptedState: M3RepositoryStateTokenDocument;
  /** True when an identical published handover was detected and reused (lost-response completion). */
  readonly idempotentReuse: boolean;
}

function assertRunId(value: unknown): asserts value is string {
  assertNonemptyString(value, "runId", 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value)) throw new RepositoryGuardError("INVALID_ARGUMENT", "runId is invalid");
}

function exactSource(
  location: { readonly stateRoot: string; readonly runId: string },
  digest: string,
): Promise<M3ResumeLockHandoverDocument> {
  return loadM3Record(location, "RESUME_LOCK_HANDOVER", digest, "STATE_TOKEN_SOURCE_MISSING", "STATE_TOKEN_PROVENANCE_INVALID") as
    Promise<M3ResumeLockHandoverDocument>;
}

export async function runResumeLockHandover(input: RunResumeLockHandoverInput): Promise<ResumeLockHandoverResult> {
  assertRecord(input, "runResumeLockHandover input");
  assertExactKeys(input, [
    "stateRoot", "runId", "acceptedState", "baseline", "instructionFiles", "authorityFiles", "taskScopeIdentity", "lock",
  ], "runResumeLockHandover input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertRunId(input.runId);
  assertDigest(input.taskScopeIdentity, "taskScopeIdentity");
  assertDocumentValid("pi_gacw_repository_state_token_v0", input.acceptedState);
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  await assertUsableM3Storage(location);

  // The currently-held opaque lock handle is the only provenance for generation
  // B. Caller-supplied diagnostic or acquisition documents are never truth.
  const diagnosticB = await assertWorktreeLockHeld(input.lock);
  const acquisitionB = lockAcquisitionAuthority(input.lock);
  if (!lockMatchesRepository(input.lock, input.baseline.repository)) {
    throw new RepositoryGuardError("LOCK_LOST", "Held lock does not match the baseline worktree identity");
  }

  // Resolve the exact durable authoritative scope-matching tip while lock B is held.
  const tokens = await readM3Records(location, "REPOSITORY_STATE_TOKEN");
  const scopeMatching = tokens.filter((token) => token.run_id === input.runId &&
    token.task_scope_identity === input.taskScopeIdentity &&
    token.baseline_runtime_content_sha256 === input.baseline.content_sha256);
  if (!scopeMatching.some((token) => token.content_sha256 === input.acceptedState.content_sha256)) {
    throw new RepositoryGuardError("STATE_TOKEN_RECORD_MISSING", "The presented resume capability has no durable record in this run");
  }
  const referenced = new Set(scopeMatching.flatMap((token) => token.prior_token_content_sha256 === null ? [] : [token.prior_token_content_sha256]));
  const tips = scopeMatching.filter((token) => !referenced.has(token.content_sha256));
  if (tips.length !== 1) {
    throw new RepositoryGuardError("STATE_TOKEN_PROVENANCE_INVALID",
      tips.length === 0 ? "No durable authoritative repository-state tip exists" : "Durable authoritative repository-state tip is ambiguous");
  }
  const tip = tips[0]!;
  const tipAuthority = await loadAuthoritativeToken(location, tip, input.baseline);

  // Case B: the durable tip is the exact already-published RESUME_LOCK_HANDOVER
  // successor of the expected capability for the currently held acquisition.
  // This is the H2 lost-response/idempotent completion path.
  if (tip.content_sha256 !== input.acceptedState.content_sha256) {
    const reuse = tip.source === "RESUME_LOCK_HANDOVER" &&
      tip.prior_token_content_sha256 === input.acceptedState.content_sha256 &&
      tip.lock_diagnostic_content_sha256 === diagnosticB.content_sha256 &&
      tipAuthority.lockAcquisition.content_sha256 === acquisitionB.content_sha256;
    if (!reuse) {
      throw new RepositoryGuardError("STATE_TOKEN_PROVENANCE_INVALID",
        "Stale resume capability differs from the exact durable authoritative tip");
    }
    const source = await exactSource(location, tip.source_content_sha256);
    return detachedFrozen({ source, acceptedState: tip, idempotentReuse: true });
  }

  // Case A: perform (or finish) the T_A -> T_B handover from the exact tip.
  const predecessor = input.acceptedState;
  // R2D-safe depth admission (checked before any publication or generation
  // transition): reserve one successor slot for this handover and one for the
  // imminent real M4 mutation postflight.
  if (tipAuthority.chainDepth >= 63) {
    throw new RepositoryGuardError("STATE_TOKEN_CHAIN_TOO_DEEP",
      "Resume-lock-handover would leave no postflight capacity within the fixed chain bound");
  }
  // Same-generation rule: never create B -> B successors.
  if (diagnosticB.content_sha256 === predecessor.lock_diagnostic_content_sha256 ||
      acquisitionB.content_sha256 === tipAuthority.lockAcquisition.content_sha256) {
    throw new RepositoryGuardError("STATE_TOKEN_PROVENANCE_INVALID",
      "Resume-lock-handover requires a new lock generation distinct from the predecessor authority");
  }
  await verifyBaselineBlobs(input.stateRoot, input.baseline);

  // Environment continuity: recompute the live environment under acquisition B
  // using the existing environment machinery and require exact semantic equality
  // with the frozen root preflight before any publication.
  const liveEnvironment = await currentEnvironmentFingerprint(input.baseline.repository, diagnosticB);
  for (const key of ENVIRONMENT_FIELDS) {
    if (liveEnvironment[key] !== tipAuthority.rootPreflight.environment_fingerprint[key]) {
      throw new RepositoryGuardError("ENVIRONMENT_DRIFT",
        `Live environment field ${key} differs from the frozen root-preflight environment`);
    }
  }

  // Repository continuity while B remains held: prove byte-exact equality to the
  // predecessor state before any authority transition.
  const currentRepository = await resolveRepositoryIdentity({ requestedPath: input.baseline.repository.requested_path, requireHead: true });
  assertRepositoryMatches(input.baseline.repository, currentRepository);
  if (currentRepository.content_sha256 !== predecessor.repository_identity_content_sha256 ||
      currentRepository.worktree_key !== predecessor.worktree_key ||
      currentRepository.branch !== predecessor.branch || currentRepository.head !== predecessor.head ||
      currentRepository.worktree_list_sha256 !== predecessor.worktree_list_sha256) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Repository identity differs from the exact predecessor state token");
  }
  const [fingerprint, instructionFingerprint, authorityFingerprint] = await Promise.all([
    captureGitState(currentRepository),
    captureFileSetFingerprint(input.instructionFiles, "INSTRUCTION_DRIFT"),
    captureFileSetFingerprint(input.authorityFiles, "AUTHORITY_DRIFT"),
  ]);
  assertNoGitBlockers(fingerprint);
  if (fingerprint.content_sha256 !== predecessor.git_fingerprint.content_sha256) {
    throw new RepositoryGuardError("BLOCKED_STATE_DRIFT", "Live Git fingerprint differs from the exact predecessor state");
  }
  if (instructionFingerprint.content_sha256 !== predecessor.instruction_fingerprint.content_sha256) {
    throw new RepositoryGuardError("INSTRUCTION_DRIFT", "Instruction fingerprint differs from the exact predecessor state");
  }
  if (authorityFingerprint.content_sha256 !== predecessor.authority_fingerprint.content_sha256) {
    throw new RepositoryGuardError("AUTHORITY_DRIFT", "Authority fingerprint differs from the exact predecessor state");
  }

  // Deterministic source identity: no timestamp and no generation-specific
  // fields beyond the held diagnostic, so a same-owner crash retry reconstructs
  // the byte-identical source.
  const source = identifyContractDocument("pi_gacw_resume_lock_handover_v0", {
    schema_id: "pi_gacw_resume_lock_handover_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: input.runId,
    prior_token_content_sha256: predecessor.content_sha256,
    repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
    git_fingerprint_sha256: predecessor.git_fingerprint.content_sha256,
    instruction_fingerprint_sha256: predecessor.instruction_fingerprint.content_sha256,
    authority_fingerprint_sha256: predecessor.authority_fingerprint.content_sha256,
    lock_diagnostic_content_sha256: diagnosticB.content_sha256,
  }) as unknown as M3ResumeLockHandoverDocument;
  // The successor token preserves the predecessor's exact repository-state
  // representation byte-exact (including any approved dirty workflow-owned
  // delta) and changes only its current lock generation.
  const successor = identifyContractDocument("pi_gacw_repository_state_token_v0", {
    schema_id: "pi_gacw_repository_state_token_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    source: "RESUME_LOCK_HANDOVER",
    source_content_sha256: source.content_sha256,
    prior_token_content_sha256: predecessor.content_sha256,
    run_id: predecessor.run_id,
    repository_identity_content_sha256: predecessor.repository_identity_content_sha256,
    worktree_key: predecessor.worktree_key,
    branch: predecessor.branch,
    head: predecessor.head,
    worktree_list_sha256: predecessor.worktree_list_sha256,
    git_fingerprint: fingerprint,
    instruction_fingerprint: instructionFingerprint,
    authority_fingerprint: authorityFingerprint,
    baseline_runtime_content_sha256: predecessor.baseline_runtime_content_sha256,
    lock_diagnostic_content_sha256: diagnosticB.content_sha256,
    task_scope_identity: predecessor.task_scope_identity,
    workflow_owned_delta_sha256: predecessor.workflow_owned_delta_sha256,
    changed_paths: [...predecessor.changed_paths],
  }) as unknown as M3RepositoryStateTokenDocument;

  // Explicitly validate the inherited projection and handover semantics; never
  // construct and assume equality.
  assertM3ResumeLockHandoverSemantics(
    source, successor, predecessor, tipAuthority, input.baseline, tipAuthority.approval, diagnosticB, acquisitionB,
  );

  let additional = 0;
  const acquisitionWasNew = !await m3RecordExists(location, "LOCK_ACQUISITION", acquisitionB.content_sha256);
  const diagnosticWasNew = !await m3RecordExists(location, "LOCK_DIAGNOSTIC", diagnosticB.content_sha256);
  const sourceWasNew = !await m3RecordExists(location, "RESUME_LOCK_HANDOVER", source.content_sha256);
  const tokenWasNew = !await m3RecordExists(location, "REPOSITORY_STATE_TOKEN", successor.content_sha256);
  if (acquisitionWasNew) additional += canonicalJsonRecordBytes(acquisitionB).byteLength;
  if (diagnosticWasNew) additional += canonicalJsonRecordBytes(diagnosticB).byteLength;
  if (sourceWasNew) additional += canonicalJsonRecordBytes(source).byteLength;
  if (tokenWasNew) additional += canonicalJsonRecordBytes(successor).byteLength;
  await assertStateRootCapacity(input.stateRoot, additional);

  // Publication order: run-local B diagnostic evidence, then the immutable
  // handover source, then the successor token. The held lock is re-proven at
  // every boundary and after publication. A source without its token remains a
  // harmless resumable orphan (H1).
  await assertWorktreeLockHeld(input.lock);
  // First productive handover write into a retained pre-R2D0 run materializes
  // only this exact legacy-optional record directory, safely and mode 0700.
  await ensureResumeLockHandoverDirectory(location);
  if (acquisitionWasNew) {
    await publishM3Record(location, "LOCK_ACQUISITION", acquisitionB as unknown as Record<string, unknown>);
  }
  if (diagnosticWasNew) {
    await publishM3Record(location, "LOCK_DIAGNOSTIC", diagnosticB as unknown as Record<string, unknown>);
  }
  await publishM3Record(location, "RESUME_LOCK_HANDOVER", source as unknown as Record<string, unknown>);
  await assertWorktreeLockHeld(input.lock);
  try {
    await publishM3Record(location, "REPOSITORY_STATE_TOKEN", successor as unknown as Record<string, unknown>);
  } catch (error: unknown) {
    try {
      await rollbackNewM3Record(location, "REPOSITORY_STATE_TOKEN", successor, tokenWasNew);
    } catch (cleanupError: unknown) {
      throw new RepositoryGuardError("STATE_TOKEN_PUBLICATION_CLEANUP_UNCERTAIN",
        "Failed handover-token publication could not be rolled back", {}, { cause: cleanupError });
    }
    throw error;
  }
  await assertWorktreeLockHeld(input.lock);
  return detachedFrozen({ source, acceptedState: successor, idempotentReuse: false });
}
