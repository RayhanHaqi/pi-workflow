import { inspectRunStorageForRetention } from "../persistence/store.js";
import { sha256Bytes, type Sha256Digest } from "../identity/index.js";
import {
  assertDocumentValid,
  assertWorkflowState,
  identifyContractDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselineRuntimeDocument,
  type M3RetentionResultDocument,
  type M3TerminalRetentionAuthorityDocument,
  type WorkflowState,
} from "../schemas/index.js";
import { requireDurableBaselineAuthority } from "./baseline.js";
import { RepositoryGuardError } from "./errors.js";
import {
  acquireWorktreeLock,
  assertWorktreeLockHeld,
  releaseWorktreeLock,
  type WorktreeLockHandle,
} from "./lock.js";
import { expectedTerminalRetentionAuthority } from "./provenance.js";
import {
  assertRetentionResultSemantics,
  deriveRetentionResultAggregate,
  exactRetentionDeletionProof,
  type RetentionAuthorityContext,
  type RetentionPhysicalGroup,
  type RetentionProof,
} from "./retention-groups.js";
import {
  assertProjectedRetentionCapacity,
  assertRetentionResultCapacity,
  canonicalJsonRecordBytes,
  deleteValidatedRetentionTarget,
  loadM3Record,
  loadRetentionAuthorityContext,
  m3RecordIsExact,
  publishM3Record,
  retentionResults,
  validateRetentionTarget,
  type RetentionTargetFailureCode,
} from "./storage.js";
import { repositoryTestHooks } from "./test-hooks.js";
import {
  assertAbsoluteNormalizedPath,
  assertExactKeys,
  assertIsoTimestamp,
  assertNonemptyString,
  assertRecord,
  compareText,
  detachedFrozen,
  digestHex,
} from "./utils.js";

export interface CreateTerminalRetentionAuthorityInput {
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly terminalWorkflowState: WorkflowState;
  readonly terminalTimestamp: string;
}

export interface RetentionOperationInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly terminalAuthority: M3TerminalRetentionAuthorityDocument;
  readonly evaluatedAt: string;
}

type BlobResult = M3RetentionResultDocument["blobs"][number];
type TrustedInspection = Awaited<ReturnType<typeof inspectRunStorageForRetention>>;

export function createTerminalRetentionAuthority(
  input: CreateTerminalRetentionAuthorityInput,
): M3TerminalRetentionAuthorityDocument {
  assertRecord(input, "createTerminalRetentionAuthority input");
  assertExactKeys(input, ["baseline", "approval", "terminalWorkflowState", "terminalTimestamp"], "createTerminalRetentionAuthority input");
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  if (input.approval !== null) assertDocumentValid("pi_gacw_baseline_approval_runtime_v0", input.approval);
  assertWorkflowState(input.terminalWorkflowState);
  assertIsoTimestamp(input.terminalTimestamp, "terminalTimestamp");
  return detachedFrozen(expectedTerminalRetentionAuthority(
    input.baseline,
    input.approval,
    input.terminalWorkflowState,
    input.terminalTimestamp,
  ));
}

function validateRetentionInput(input: RetentionOperationInput): void {
  assertRecord(input, "retention input");
  assertExactKeys(input, ["stateRoot", "runId", "baseline", "terminalAuthority", "evaluatedAt"], "retention input");
  assertAbsoluteNormalizedPath(input.stateRoot, "stateRoot");
  assertNonemptyString(input.runId, "runId", 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(input.runId)) throw new RepositoryGuardError("INVALID_ARGUMENT", "runId is invalid");
  assertIsoTimestamp(input.evaluatedAt, "evaluatedAt");
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  assertDocumentValid("pi_gacw_terminal_retention_authority_v0", input.terminalAuthority);
  if (input.runId !== input.baseline.run_id || input.runId !== input.terminalAuthority.run_id ||
      input.terminalAuthority.baseline_runtime_content_sha256 !== input.baseline.content_sha256 ||
      input.terminalAuthority.repository_identity_content_sha256 !== input.baseline.repository.content_sha256 ||
      input.terminalAuthority.worktree_key !== input.baseline.repository.worktree_key) {
    throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retention input identities disagree");
  }
  for (const blob of input.terminalAuthority.blobs) {
    if (blob.relative_path !== `baseline-blobs/sha256/${digestHex(blob.blob_sha256)}`) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retention blob path is not digest-derived");
    }
  }
}

async function trustedRetentionInspection(input: RetentionOperationInput): Promise<TrustedInspection> {
  const uniqueDigests = [...new Set(input.terminalAuthority.blobs.map((blob) => blob.blob_sha256 as Sha256Digest))];
  const inspection = await inspectRunStorageForRetention(
    { stateRoot: input.stateRoot, runId: input.runId },
    uniqueDigests,
  );
  if (inspection.status !== "HEALTHY" || inspection.workflowState === null || inspection.statePointer === null ||
      inspection.transitionCommit === null) {
    throw new RepositoryGuardError("STATE_STORAGE_INVALID", "Retention foundational storage or committed authority is invalid", {
      status: inspection.status,
    });
  }
  return inspection;
}

function verifyCommittedTerminalAuthority(
  input: RetentionOperationInput,
  approval: M3BaselineApprovalRuntimeDocument | null,
  inspection: TrustedInspection,
): WorkflowState {
  const state = inspection.workflowState;
  if (state === null) throw new RepositoryGuardError("STATE_STORAGE_INVALID", "Retention inspection has no committed state");
  if (state.phase !== "PASS" && state.phase !== "BLOCKED") {
    throw new RepositoryGuardError("RETENTION_NOT_TERMINAL", "Retention cleanup requires terminal committed workflow state");
  }
  if (state.content_sha256 !== input.terminalAuthority.terminal_workflow_state_content_sha256) {
    throw new RepositoryGuardError("RETENTION_TIMESTAMP_UNAVAILABLE", "Terminal retention authority does not bind the committed terminal state");
  }
  const expected = expectedTerminalRetentionAuthority(input.baseline, approval, state, input.terminalAuthority.terminal_timestamp);
  if (expected.content_sha256 !== input.terminalAuthority.content_sha256) {
    throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Terminal retention authority metadata differs from durable baseline policy");
  }
  const evidenceDigest = sha256Bytes(canonicalJsonRecordBytes(input.terminalAuthority));
  if (!inspection.reachableObjects.some((entry) => entry.kind === "RAW_EVIDENCE" && entry.contentSha256 === evidenceDigest)) {
    throw new RepositoryGuardError("RETENTION_TIMESTAMP_UNAVAILABLE", "Terminal timestamp authority is not committed as terminal-transition evidence");
  }
  return state;
}

function groupResult(
  group: RetentionPhysicalGroup,
  status: BlobResult["status"],
  result: BlobResult["result"],
  detailCode: string | null,
  priorProof: RetentionProof | null = null,
  unlinkPerformed = false,
  directoryFsyncPerformed = false,
): BlobResult {
  if (group.retentionDeadline === null || group.references.length === 0) {
    throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retention group lacks primary durable authority");
  }
  return {
    blob_sha256: group.blobSha256,
    byte_length: group.byteLength,
    relative_path: group.relativePath,
    data_class: group.dataClass,
    retention_deadline: group.retentionDeadline,
    logical_references: [...group.references],
    uncovered_references: group.uncoveredReferences.map((entry) => ({
      baseline_runtime_content_sha256: entry.baselineContentSha256,
      baseline_path: entry.baselinePath,
    })),
    prior_successful_result_content_sha256: priorProof?.record.content_sha256 ?? null,
    status,
    result,
    detail_code: detailCode,
    unlink_performed: unlinkPerformed,
    directory_fsync_performed: directoryFsyncPerformed,
  };
}

function resultDocument(
  operation: "INSPECT" | "CLEANUP",
  input: RetentionOperationInput,
  outcome: M3RetentionResultDocument["outcome"],
  blobs: M3RetentionResultDocument["blobs"],
): M3RetentionResultDocument {
  const sorted = [...blobs].sort((left, right) => compareText(left.blob_sha256, right.blob_sha256));
  const document = identifyContractDocument("pi_gacw_retention_result_v0", {
    schema_id: "pi_gacw_retention_result_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    operation,
    run_id: input.runId,
    terminal_authority_content_sha256: input.terminalAuthority.content_sha256,
    terminal_workflow_state_content_sha256: input.terminalAuthority.terminal_workflow_state_content_sha256,
    baseline_runtime_content_sha256: input.baseline.content_sha256,
    baseline_approval_runtime_content_sha256: input.terminalAuthority.baseline_approval_runtime_content_sha256,
    repository_identity_content_sha256: input.baseline.repository.content_sha256,
    worktree_key: input.baseline.repository.worktree_key,
    evaluated_at: input.evaluatedAt,
    logical_target_count: sorted.reduce(
      (total, entry) => total + entry.logical_references.length + entry.uncovered_references.length,
      0,
    ),
    physical_target_count: sorted.length,
    outcome,
    blobs: sorted,
  }) as unknown as M3RetentionResultDocument;
  deriveRetentionResultAggregate(document);
  return document;
}

async function resultAdditionalBytes(input: RetentionOperationInput, result: M3RetentionResultDocument): Promise<number> {
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  return await m3RecordIsExact(location, "RETENTION_RESULT", result) ? 0 : canonicalJsonRecordBytes(result).byteLength;
}

async function persistResult(input: RetentionOperationInput, result: M3RetentionResultDocument): Promise<void> {
  try {
    await repositoryTestHooks().beforeRetentionResultPublication?.();
    const location = { stateRoot: input.stateRoot, runId: input.runId };
    let additional = await resultAdditionalBytes(input, result);
    const targetDigests = result.blobs.map((entry) => entry.blob_sha256);
    await assertRetentionResultCapacity(location, targetDigests, additional);
    await repositoryTestHooks().beforeRetentionCapacityRecheck?.();
    additional = await resultAdditionalBytes(input, result);
    await assertRetentionResultCapacity(location, targetDigests, additional);
    await publishM3Record(location, "RETENTION_RESULT", result as unknown as Record<string, unknown>);
  } catch (error: unknown) {
    if (error instanceof RepositoryGuardError &&
        (error.code === "RETENTION_RESULT_PUBLICATION_FAILED" || error.code === "STATE_ROOT_LIMIT_EXCEEDED")) throw error;
    throw new RepositoryGuardError(
      "RETENTION_RESULT_PUBLICATION_FAILED",
      "Immutable retention result publication failed",
      {},
      { cause: error },
    );
  }
}

function failureStatus(code: RetentionTargetFailureCode): BlobResult["status"] {
  if (code === "TARGET_MISSING") return "MISSING";
  if (code === "TARGET_MODE_MISMATCH" || code === "TARGET_SIZE_MISMATCH" || code === "TARGET_DIGEST_MISMATCH") return "MISMATCH";
  return "ERROR";
}

interface RetentionContext {
  readonly lock: WorktreeLockHandle;
  readonly prior: readonly M3RetentionResultDocument[];
  readonly authority: RetentionAuthorityContext;
  readonly groups: readonly RetentionPhysicalGroup[];
}

async function persistValidatedResult(
  input: RetentionOperationInput,
  context: RetentionContext,
  result: M3RetentionResultDocument,
): Promise<void> {
  assertRetentionResultSemantics(result, context.authority, [...context.prior, result]);
  await persistResult(input, result);
}

function operationGroups(input: RetentionOperationInput, authority: RetentionAuthorityContext): readonly RetentionPhysicalGroup[] {
  const groups: RetentionPhysicalGroup[] = [];
  const digests = [...new Set(input.terminalAuthority.blobs.map((entry) => entry.blob_sha256))].sort(compareText);
  for (const digest of digests) {
    const group = authority.groups.get(digest);
    if (group === undefined || !group.references.some((entry) => entry.terminal_authority_content_sha256 === input.terminalAuthority.content_sha256)) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Primary retention authority has no exact durable logical-reference group");
    }
    groups.push(group);
  }
  return groups;
}

async function acquireTrustedContext(input: RetentionOperationInput): Promise<RetentionContext> {
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  const approval = input.terminalAuthority.baseline_approval_runtime_content_sha256 === null
    ? null
    : await loadM3Record(
      location,
      "BASELINE_APPROVAL",
      input.terminalAuthority.baseline_approval_runtime_content_sha256,
      "BASELINE_APPROVAL_RECORD_MISSING",
      "BASELINE_APPROVAL_RECORD_MISMATCH",
    );
  // Retention must be able to publish an exact failed observation for a
  // missing/mismatched target; deletion authority is still withheld by target
  // and proof validation below.
  await requireDurableBaselineAuthority(input.stateRoot, input.runId, input.baseline, approval, false);
  const preliminary = await trustedRetentionInspection(input);
  verifyCommittedTerminalAuthority(input, approval, preliminary);
  const lock = await acquireWorktreeLock({ stateRoot: input.stateRoot, repository: input.baseline.repository });
  try {
    await repositoryTestHooks().afterRetentionLockAcquired?.(lock.diagnostics.guardian_pid);
    const diagnostic = await assertWorktreeLockHeld(lock);
    if (diagnostic.worktree_key !== input.terminalAuthority.worktree_key) {
      throw new RepositoryGuardError("LOCK_LOST", "Retention lock does not match terminal authority");
    }
    const inspection = await trustedRetentionInspection(input);
    verifyCommittedTerminalAuthority(input, approval, inspection);
    const authority = await loadRetentionAuthorityContext(
      { stateRoot: input.stateRoot, runId: input.runId },
      [...new Set(input.terminalAuthority.blobs.map((entry) => entry.blob_sha256 as Sha256Digest))],
    );
    if (!authority.authorities.has(input.terminalAuthority.content_sha256)) {
      throw new RepositoryGuardError("RETENTION_TIMESTAMP_UNAVAILABLE", "Exact terminal retention authority is not durably committed");
    }
    const prior = await retentionResults({ stateRoot: input.stateRoot, runId: input.runId });
    for (const result of prior) assertRetentionResultSemantics(result, authority, prior);
    return {
      lock,
      prior,
      groups: operationGroups(input, authority),
      authority,
    };
  } catch (error: unknown) {
    await releaseWorktreeLock(lock).catch(() => undefined);
    throw error;
  }
}

async function releaseAfterRetention(lock: WorktreeLockHandle, primaryError: unknown): Promise<void> {
  try {
    await releaseWorktreeLock(lock);
  } catch (releaseError: unknown) {
    if (primaryError === undefined) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retention lock release failed", {}, { cause: releaseError });
    }
  }
}

function groupNotEligible(group: RetentionPhysicalGroup, input: RetentionOperationInput): string | null {
  if (group.uncoveredReferences.length > 0 || group.references.length !== group.logicalReferenceCount) {
    return "LIVE_REFERENCE_AUTHORITY_MISSING";
  }
  if (group.references.some((entry) => entry.worktree_key !== input.terminalAuthority.worktree_key)) {
    return "LIVE_REFERENCE_WORKTREE_MISMATCH";
  }
  return null;
}

export async function inspectRetention(input: RetentionOperationInput): Promise<M3RetentionResultDocument> {
  validateRetentionInput(input);
  const context = await acquireTrustedContext(input);
  let primaryError: unknown;
  try {
    let pending = false;
    let failed = false;
    const blobs: BlobResult[] = [];
    for (const group of context.groups) {
      const ineligible = groupNotEligible(group, input);
      if (ineligible !== null) {
        failed = true;
        blobs.push(groupResult(group, "ERROR", "FAILED", ineligible));
        continue;
      }
      if (Date.parse(input.evaluatedAt) < Date.parse(group.retentionDeadline!)) {
        pending = true;
        blobs.push(groupResult(group, "DEADLINE_PENDING", "REFUSED", "RETENTION_DEADLINE_NOT_REACHED"));
        continue;
      }
      const validation = await validateRetentionTarget(
        { stateRoot: input.stateRoot, runId: input.runId }, group.blobSha256, group.byteLength,
      );
      if (validation.valid) {
        blobs.push(groupResult(group, "ELIGIBLE", "ELIGIBLE", null));
      } else if (validation.failureCode === "TARGET_MISSING") {
        const proof = exactRetentionDeletionProof(context.prior, context.authority, group.blobSha256);
        if (proof !== null) {
          // Inspection records may report a proven observation, but never
          // publish a deletion-proof edge.
          blobs.push(groupResult(group, "ALREADY_REMOVED", "IDEMPOTENT", null));
        } else {
          failed = true;
          blobs.push(groupResult(group, "MISSING", "FAILED", "TARGET_MISSING"));
        }
      } else {
        failed = true;
        const code = validation.failureCode ?? "TARGET_READ_FAILED";
        blobs.push(groupResult(group, failureStatus(code), "FAILED", code));
      }
    }
    const result = resultDocument("INSPECT", input, failed ? "FAILED" : pending ? "REFUSED" : "ELIGIBLE", blobs);
    await persistValidatedResult(input, context, result);
    return detachedFrozen(result);
  } catch (error: unknown) {
    primaryError = error;
    throw error;
  } finally {
    await releaseAfterRetention(context.lock, primaryError);
  }
}

export async function applyRetentionCleanup(input: RetentionOperationInput): Promise<M3RetentionResultDocument> {
  validateRetentionInput(input);
  const context = await acquireTrustedContext(input);
  let primaryError: unknown;
  try {
    const eligibility = context.groups.map((group) => ({
      group,
      failure: groupNotEligible(group, input),
      pending: Date.parse(input.evaluatedAt) < Date.parse(group.retentionDeadline!),
    }));
    if (eligibility.some((entry) => entry.failure !== null)) {
      const result = resultDocument("CLEANUP", input, "FAILED", eligibility.map((entry) =>
        entry.failure === null
          ? groupResult(entry.group, entry.pending ? "DEADLINE_PENDING" : "ELIGIBLE", entry.pending ? "REFUSED" : "ELIGIBLE",
            entry.pending ? "RETENTION_DEADLINE_NOT_REACHED" : null)
          : groupResult(entry.group, "ERROR", "FAILED", entry.failure),
      ));
      await persistValidatedResult(input, context, result);
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "At least one live logical reference lacks compatible retention authority");
    }
    if (eligibility.some((entry) => entry.pending)) {
      const result = resultDocument("CLEANUP", input, "REFUSED", eligibility.map((entry) =>
        entry.pending
          ? groupResult(entry.group, "DEADLINE_PENDING", "REFUSED", "RETENTION_DEADLINE_NOT_REACHED")
          : groupResult(entry.group, "ELIGIBLE", "ELIGIBLE", null),
      ));
      await persistValidatedResult(input, context, result);
      throw new RepositoryGuardError("RETENTION_DEADLINE_NOT_REACHED", "At least one logical retention deadline has not been reached");
    }

    const validated: Array<{ group: RetentionPhysicalGroup; result: BlobResult; delete: boolean; proof: RetentionProof | null }> = [];
    let targetFailures = 0;
    for (const group of context.groups) {
      const validation = await validateRetentionTarget(
        { stateRoot: input.stateRoot, runId: input.runId }, group.blobSha256, group.byteLength,
      );
      if (validation.valid) {
        validated.push({ group, result: groupResult(group, "ELIGIBLE", "ELIGIBLE", null), delete: true, proof: null });
      } else if (validation.failureCode === "TARGET_MISSING") {
        const proof = exactRetentionDeletionProof(context.prior, context.authority, group.blobSha256);
        if (proof !== null) {
          validated.push({ group, result: groupResult(group, "ALREADY_REMOVED", "IDEMPOTENT", null, proof), delete: false, proof });
        } else {
          targetFailures += 1;
          validated.push({ group, result: groupResult(group, "MISSING", "FAILED", "TARGET_MISSING"), delete: false, proof: null });
        }
      } else {
        targetFailures += 1;
        const code = validation.failureCode ?? "TARGET_READ_FAILED";
        validated.push({ group, result: groupResult(group, failureStatus(code), "FAILED", code), delete: false, proof: null });
      }
    }
    if (targetFailures > 0) {
      const result = resultDocument("CLEANUP", input, "FAILED", validated.map((entry) => entry.result));
      await persistValidatedResult(input, context, result);
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Retention target validation failed; no target was deleted");
    }

    const projectedBlobs = validated.map((entry) => entry.delete
      ? groupResult(entry.group, "DELETED", "SUCCEEDED", null, null, true, true)
      : groupResult(entry.group, "ALREADY_REMOVED", "IDEMPOTENT", null, entry.proof));
    const projected = resultDocument(
      "CLEANUP",
      input,
      validated.length > 0 && validated.every((entry) => !entry.delete) ? "IDEMPOTENT" : "COMPLETE",
      projectedBlobs,
    );
    const projectedAdditional = await resultAdditionalBytes(input, projected);
    const removedBytes = validated.filter((entry) => entry.delete).reduce((total, entry) => total + entry.group.byteLength, 0);
    await assertProjectedRetentionCapacity(
      { stateRoot: input.stateRoot, runId: input.runId },
      removedBytes,
      projectedAdditional,
    );

    let deleted = 0;
    let already = 0;
    let operationFailures = 0;
    const blobResults: BlobResult[] = [];
    for (const entry of validated) {
      if (!entry.delete) {
        already += 1;
        blobResults.push(entry.result);
        continue;
      }
      const deletion = await deleteValidatedRetentionTarget(
        { stateRoot: input.stateRoot, runId: input.runId }, entry.group.blobSha256, entry.group.byteLength,
      );
      if (deletion.failureCode === null) {
        deleted += 1;
        blobResults.push(groupResult(entry.group, "DELETED", "SUCCEEDED", null, null, true, true));
      } else {
        operationFailures += 1;
        blobResults.push(groupResult(
          entry.group,
          failureStatus(deletion.failureCode),
          "FAILED",
          deletion.failureCode,
          null,
          deletion.unlinkPerformed,
          deletion.directoryFsyncPerformed,
        ));
      }
    }
    const outcome = operationFailures > 0
      ? (deleted > 0 || blobResults.some((entry) => entry.unlink_performed) ? "PARTIAL" : "FAILED")
      : deleted === 0 && already > 0 ? "IDEMPOTENT" : "COMPLETE";
    const result = resultDocument("CLEANUP", input, outcome, blobResults);
    await persistValidatedResult(input, context, result);
    if (operationFailures > 0) {
      throw new RepositoryGuardError("CLEANUP_UNCERTAIN", "Baseline retention cleanup was partial or uncertain");
    }
    return detachedFrozen(result);
  } catch (error: unknown) {
    primaryError = error;
    throw error;
  } finally {
    await releaseAfterRetention(context.lock, primaryError);
  }
}
