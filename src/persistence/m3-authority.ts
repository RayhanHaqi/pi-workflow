import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import {
  M3_SCOPE_PROJECTION_ID,
  M3_SCOPE_SCHEMA_ID,
  M3_SCOPE_VERSION,
  m3ScopeIdentity,
} from "../identity/m3-scope.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type M3BaselineApprovalRuntimeDocument,
  type M3BaselinePath,
  type M3BaselineRuntimeDocument,
  type M3DeltaEntry,
  type M3GitStateFingerprintDocument,
  type M3LockAcquisitionDocument,
  type M3LockDiagnosticDocument,
  type M3PostflightDocument,
  type M3PreflightDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M3ResumeLockHandoverDocument,
  type M3RetentionResultDocument,
  type M3TerminalRetentionAuthorityDocument,
  type WorkflowState,
} from "../schemas/index.js";
import { assertLockAcquisitionSemantics } from "../repository/acquisition.js";

export type M3AuthorityFailureKind = "INVALID" | "MISSING" | "LOOP" | "TOO_DEEP";

/** Package-internal semantic failure shared by operational and inspection paths. */
export class M3AuthorityValidationError extends Error {
  public readonly kind: M3AuthorityFailureKind;
  public readonly semanticCode: string;

  public constructor(kind: M3AuthorityFailureKind, semanticCode: string, message: string) {
    super(`${semanticCode}: ${message}`);
    this.name = "M3AuthorityValidationError";
    this.kind = kind;
    this.semanticCode = semanticCode;
  }
}

function invalid(code: string, message: string): never {
  throw new M3AuthorityValidationError("INVALID", code, message);
}

function missing(code: string, message: string): never {
  throw new M3AuthorityValidationError("MISSING", code, message);
}

function same(left: unknown, right: unknown): boolean {
  return canonicalize(left) === canonicalize(right);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertExactUtcTimestamp(value: string, code: string, label: string): void {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(code, `${label} is not an exact UTC ISO-8601 millisecond timestamp`);
  }
}

function addUtcDays(timestamp: string, days: number): string {
  assertExactUtcTimestamp(timestamp, "RETENTION_AUTHORITY_SEMANTIC_MISMATCH", "terminal timestamp");
  const milliseconds = Date.parse(timestamp) + days * 86_400_000;
  if (!Number.isSafeInteger(days) || days < 1 || days > 30 || !Number.isSafeInteger(milliseconds)) {
    invalid("RETENTION_AUTHORITY_SEMANTIC_MISMATCH", "retention deadline arithmetic is invalid");
  }
  return new Date(milliseconds).toISOString();
}

function digestHex(digest: string): string {
  return digest.slice("sha256:".length);
}

function pathWithin(path: string, envelope: string): boolean {
  return path === envelope || path.startsWith(`${envelope}/`);
}

function pathWithinAny(path: string, envelopes: readonly string[]): boolean {
  return envelopes.some((envelope) => pathWithin(path, envelope));
}

function assertCanonicalSortedUniquePaths(paths: readonly string[], code: string, label: string): void {
  const sorted = [...paths].sort(compareText);
  if (!same(paths, sorted) || new Set(paths).size !== paths.length) {
    invalid(code, `${label} is not a canonical sorted unique path set`);
  }
}

function assertCanonicalSortedUniqueByPath<T extends { readonly path: string }>(
  values: readonly T[],
  code: string,
  label: string,
): void {
  const sorted = [...values].sort((left, right) => compareText(left.path, right.path));
  if (!same(values, sorted) || new Set(values.map((entry) => entry.path)).size !== values.length) {
    invalid(code, `${label} is not canonical and unique by path`);
  }
}

function worktreeKey(repository: M3RepositoryIdentityDocument): Sha256Digest {
  return sha256Bytes(Buffer.concat([
    Buffer.from(repository.git_common_dir, "utf8"),
    Buffer.from([0]),
    Buffer.from(repository.worktree_root, "utf8"),
  ]));
}

export function assertM3RepositoryIdentitySemantics(repository: M3RepositoryIdentityDocument): void {
  assertDocumentValid("pi_gacw_repository_identity_v0", repository);
  if (repository.git_toplevel !== repository.worktree_root || repository.git_dir !== repository.worktree_git_dir ||
      repository.detached !== (repository.branch === null) || repository.worktree_key !== worktreeKey(repository) ||
      repository.worktree_list_sha256 !== sha256Canonical(repository.worktrees) ||
      repository.submodule_state_sha256 !== sha256Canonical(repository.submodules) ||
      (repository.upstream_ref === null && (repository.ahead !== null || repository.behind !== null)) ||
      (repository.upstream_ref !== null && (repository.ahead === null || repository.behind === null))) {
    invalid("BASELINE_PROVENANCE_INVALID", "repository identity has inconsistent derived fields");
  }
  const paths = repository.worktrees.map((entry) => entry.path);
  if (new Set(paths).size !== paths.length || !same(paths, [...paths].sort(compareText)) ||
      !repository.worktrees.some((entry) => entry.path === repository.worktree_root &&
        entry.head === repository.head && entry.branch === repository.branch && entry.detached === repository.detached)) {
    invalid("BASELINE_PROVENANCE_INVALID", "repository worktree inventory is inconsistent");
  }
  const filters = [...repository.partial_clone.filters].sort(compareText);
  if (!same(filters, repository.partial_clone.filters) || new Set(filters).size !== filters.length) {
    invalid("BASELINE_PROVENANCE_INVALID", "partial-clone filter inventory is not canonical");
  }
  const submodulePaths = repository.submodules.map((entry) => entry.path);
  if (!same(submodulePaths, [...submodulePaths].sort(compareText)) || new Set(submodulePaths).size !== submodulePaths.length) {
    invalid("BASELINE_PROVENANCE_INVALID", "submodule inventory is not canonical");
  }
}

export function m3PorcelainIdentityProjection(fingerprint: Pick<
  M3GitStateFingerprintDocument,
  "staged" | "unstaged" | "untracked" | "conflicts"
>): unknown {
  return {
    staged: fingerprint.staged,
    unstaged: fingerprint.unstaged,
    untracked: fingerprint.untracked,
    conflicts: fingerprint.conflicts,
  };
}

function fingerprintStatusProjection(fingerprint: M3GitStateFingerprintDocument, path: string): unknown {
  return {
    staged: fingerprint.staged.filter((entry) => entry.path === path || entry.old_path === path),
    unstaged: fingerprint.unstaged.filter((entry) => entry.path === path || entry.old_path === path),
    untracked: fingerprint.untracked.filter((entry) => entry.path === path),
    conflicts: fingerprint.conflicts.filter((entry) => entry.path === path),
  };
}

export function m3FingerprintDirtyPaths(fingerprint: M3GitStateFingerprintDocument): readonly string[] {
  return [...new Set([
    ...fingerprint.staged.flatMap((entry) => entry.status === "R" && entry.old_path !== null ? [entry.path, entry.old_path] : [entry.path]),
    ...fingerprint.unstaged.flatMap((entry) => entry.status === "R" && entry.old_path !== null ? [entry.path, entry.old_path] : [entry.path]),
    ...fingerprint.untracked.map((entry) => entry.path),
    ...fingerprint.conflicts.map((entry) => entry.path),
  ])].sort(compareText);
}

export function assertM3GitFingerprintSemantics(
  fingerprint: M3GitStateFingerprintDocument,
  repository: M3RepositoryIdentityDocument,
): void {
  assertM3RepositoryIdentitySemantics(repository);
  assertDocumentValid("pi_gacw_git_state_fingerprint_v0", fingerprint);
  assertCanonicalSortedUniqueByPath(fingerprint.staged, "BASELINE_PROVENANCE_INVALID", "staged fingerprint inventory");
  assertCanonicalSortedUniqueByPath(fingerprint.unstaged, "BASELINE_PROVENANCE_INVALID", "unstaged fingerprint inventory");
  assertCanonicalSortedUniqueByPath(fingerprint.untracked, "BASELINE_PROVENANCE_INVALID", "untracked fingerprint inventory");
  assertCanonicalSortedUniqueByPath(fingerprint.conflicts, "BASELINE_PROVENANCE_INVALID", "conflict fingerprint inventory");
  if (fingerprint.repository_identity_content_sha256 !== repository.content_sha256 ||
      fingerprint.branch !== repository.branch || fingerprint.detached !== repository.detached ||
      fingerprint.head !== repository.head || fingerprint.head_tree !== repository.head_tree ||
      fingerprint.upstream_ref !== repository.upstream_ref || fingerprint.ahead !== repository.ahead ||
      fingerprint.behind !== repository.behind || fingerprint.submodule_state_sha256 !== repository.submodule_state_sha256 ||
      fingerprint.worktree_list_sha256 !== repository.worktree_list_sha256 ||
      fingerprint.porcelain_v2_sha256 !== sha256Canonical(m3PorcelainIdentityProjection(fingerprint)) ||
      fingerprint.staged_diff_sha256 !== sha256Canonical(fingerprint.staged) ||
      fingerprint.unstaged_diff_sha256 !== sha256Canonical(fingerprint.unstaged) ||
      fingerprint.untracked_inventory_sha256 !== sha256Canonical(fingerprint.untracked) ||
      fingerprint.dirty !== (m3FingerprintDirtyPaths(fingerprint).length > 0)) {
    invalid("BASELINE_PROVENANCE_INVALID", "Git fingerprint does not bind its repository or derived inventories");
  }
  if (new Set(fingerprint.active_operations).size !== fingerprint.active_operations.length) {
    invalid("BASELINE_PROVENANCE_INVALID", "Git operation inventory contains duplicates");
  }
  if (fingerprint.active_operations.length > 0 || fingerprint.conflicts.length > 0 || fingerprint.index_lock) {
    invalid("BASELINE_PROVENANCE_INVALID", "successful M3 authority contains a Git blocker");
  }
}

function acceptedRepository(baseline: M3BaselineRuntimeDocument) {
  return {
    root: baseline.repository.worktree_root,
    git_common_dir: baseline.repository.git_common_dir,
    worktree: baseline.repository.worktree_root,
    branch: baseline.repository.branch ?? "DETACHED",
    head: baseline.repository.head,
  };
}

function fingerprintFileSetSemantics(
  value: M3BaselineRuntimeDocument["instruction_fingerprint"],
  label: string,
): void {
  const entries = [...value.entries].sort((left, right) => compareText(left.path, right.path));
  if (!same(entries, value.entries) || new Set(entries.map((entry) => entry.path)).size !== entries.length ||
      value.content_sha256 !== sha256Canonical(value.entries)) {
    invalid("BASELINE_PROVENANCE_INVALID", `${label} fingerprint is inconsistent`);
  }
}

function assertBaselinePathState(
  baseline: M3BaselineRuntimeDocument,
  entry: M3BaselinePath,
): void {
  const status = fingerprintStatusProjection(baseline.git_fingerprint, entry.path);
  if (entry.status_sha256 !== sha256Canonical(status)) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline path status identity is inconsistent");
  }
  const untracked = baseline.git_fingerprint.untracked.find((candidate) => candidate.path === entry.path);
  const unstaged = baseline.git_fingerprint.unstaged.find((candidate) => candidate.path === entry.path);
  if (untracked !== undefined) {
    if (entry.file_type !== "REGULAR" || entry.content_sha256 !== untracked.content_sha256 ||
        entry.mode !== untracked.mode || entry.size !== untracked.size) {
      invalid("BASELINE_PROVENANCE_INVALID", "baseline untracked path state differs from its Git fingerprint");
    }
    return;
  }
  if (unstaged !== undefined && unstaged.state === "PRESENT") {
    if (entry.file_type !== "REGULAR" || entry.content_sha256 !== unstaged.content_sha256 ||
        entry.mode !== unstaged.mode || entry.size !== unstaged.size || unstaged.file_type !== "REGULAR") {
      invalid("BASELINE_PROVENANCE_INVALID", "baseline unstaged path state differs from its Git fingerprint");
    }
    return;
  }
  const stagedDeletion = baseline.git_fingerprint.staged.some((candidate) =>
    (candidate.path === entry.path && candidate.status === "D") ||
    (candidate.old_path === entry.path && candidate.status === "R"));
  const unstagedRenameSource = baseline.git_fingerprint.unstaged.some((candidate) =>
    candidate.old_path === entry.path && candidate.status === "R");
  if (unstaged?.state === "DELETED" || stagedDeletion || unstagedRenameSource) {
    const expected = sha256Canonical({ path: entry.path, state: "DELETED", status });
    if (entry.file_type !== "DELETED" || entry.content_sha256 !== expected || entry.mode !== null ||
        entry.size !== null || entry.blob !== null || entry.capture_mode !== "HASH_ONLY") {
      invalid("BASELINE_PROVENANCE_INVALID", "baseline deleted path state is inconsistent");
    }
    return;
  }
  if (!baseline.git_fingerprint.staged.some((candidate) => candidate.path === entry.path)) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline path has no producer state in its Git fingerprint");
  }
  if (entry.file_type !== "REGULAR" || entry.mode === null || entry.size === null) {
    invalid("BASELINE_PROVENANCE_INVALID", "staged baseline path is not a regular present state");
  }
}

export function assertM3BaselineRuntimeSemantics(baseline: M3BaselineRuntimeDocument): void {
  assertDocumentValid("pi_gacw_baseline_runtime_v0", baseline);
  assertM3GitFingerprintSemantics(baseline.git_fingerprint, baseline.repository);
  assertDocumentValid("pi_gacw_baseline_v0", baseline.accepted_baseline);
  fingerprintFileSetSemantics(baseline.instruction_fingerprint, "instruction");
  fingerprintFileSetSemantics(baseline.authority_fingerprint, "authority");
  const paths = [...baseline.paths].sort((left, right) => compareText(left.path, right.path));
  if (!same(paths, baseline.paths) || new Set(paths.map((entry) => entry.path)).size !== paths.length ||
      !same(paths.map((entry) => entry.path), m3FingerprintDirtyPaths(baseline.git_fingerprint))) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline path inventory is not the exact canonical Git dirty-path inventory");
  }
  if (baseline.accepted_baseline.mode !== baseline.baseline_mode ||
      !same(baseline.accepted_baseline.target_repository, acceptedRepository(baseline)) ||
      baseline.git_fingerprint.content_sha256 !== baseline.accepted_baseline.git_state_sha256) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline accepted repository or fingerprint projection is inconsistent");
  }
  const acceptedFiles = paths.map((entry) => ({
    path: entry.path,
    content_sha256: entry.content_sha256,
    ownership_class: entry.ownership_class,
    data_class: entry.data_class,
  })).sort((left, right) => compareText(canonicalize(left), canonicalize(right)));
  const staged = [...new Set(baseline.git_fingerprint.staged.map((entry) => entry.path))].sort(compareText);
  const unstaged = [...new Set(baseline.git_fingerprint.unstaged.map((entry) => entry.path))].sort(compareText);
  const untracked = baseline.git_fingerprint.untracked.map((entry) => entry.path).sort(compareText);
  if (!same(acceptedFiles, baseline.accepted_baseline.files) ||
      !same(staged, baseline.accepted_baseline.staged_paths) ||
      !same(unstaged, baseline.accepted_baseline.unstaged_paths) ||
      !same(untracked, baseline.accepted_baseline.untracked_paths)) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline accepted-snapshot path projection is inconsistent");
  }

  let logical = 0;
  const physical = new Map<string, number>();
  for (const entry of paths) {
    assertBaselinePathState(baseline, entry);
    if (entry.data_class === "SECRET") invalid("BASELINE_PROVENANCE_INVALID", "SECRET path entered a durable baseline");
    if (entry.file_type === "REGULAR" && (entry.mode === null || entry.size === null) ||
        entry.file_type === "DELETED" && (entry.mode !== null || entry.size !== null)) {
      invalid("BASELINE_PROVENANCE_INVALID", "baseline path type, mode, or size is inconsistent");
    }
    if (entry.capture_mode === "BLOB") {
      if (entry.blob === null || entry.file_type !== "REGULAR" || entry.size !== entry.blob.byte_length ||
          entry.content_sha256 !== entry.blob.blob_sha256 || entry.retention_days_after_terminal === null ||
          entry.blob.relative_path !== `baseline-blobs/sha256/${digestHex(entry.blob.blob_sha256)}` ||
          !["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE"].includes(entry.data_class)) {
        invalid("BASELINE_PROVENANCE_INVALID", "baseline blob metadata is inconsistent");
      }
      if ((entry.data_class === "PRIVATE_SOURCE" || entry.data_class === "SENSITIVE") && !entry.explicit_blob_approval) {
        invalid("BASELINE_PROVENANCE_INVALID", "restricted baseline blob lacks explicit approval");
      }
      if (entry.retention_days_after_terminal > (entry.data_class === "SENSITIVE" ? 7 : 30)) {
        invalid("BASELINE_PROVENANCE_INVALID", "baseline retention exceeds its classification cap");
      }
      logical += entry.blob.byte_length;
      const prior = physical.get(entry.blob.blob_sha256);
      if (prior !== undefined && prior !== entry.blob.byte_length) {
        invalid("BASELINE_PROVENANCE_INVALID", "one baseline digest has inconsistent sizes");
      }
      physical.set(entry.blob.blob_sha256, entry.blob.byte_length);
    } else if (entry.blob !== null || entry.explicit_blob_approval || entry.retention_days_after_terminal !== null) {
      invalid("BASELINE_PROVENANCE_INVALID", "hash-only baseline path carries blob authority");
    }
  }
  const physicalBytes = [...physical.values()].reduce((total, size) => total + size, 0);
  const quota = baseline.blob_quota;
  if (!Number.isSafeInteger(logical) || !Number.isSafeInteger(physicalBytes) ||
      quota.logical_approved_bytes !== logical || quota.physical_bytes !== physicalBytes ||
      quota.deduplicated_bytes !== logical - physicalBytes ||
      !Number.isSafeInteger(quota.existing_physical_bytes + quota.new_unique_physical_bytes) ||
      quota.resulting_physical_bytes !== quota.existing_physical_bytes + quota.new_unique_physical_bytes ||
      quota.new_unique_physical_bytes > physicalBytes) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline quota projection is inconsistent");
  }
}

function baselineBlobPopulation(baseline: M3BaselineRuntimeDocument): ReadonlyMap<string, number> {
  const blobs = new Map<string, number>();
  for (const path of baseline.paths) {
    if (path.blob === null) continue;
    const prior = blobs.get(path.blob.blob_sha256);
    if (prior !== undefined && prior !== path.blob.byte_length) {
      invalid("BASELINE_PROVENANCE_INVALID", "baseline blob digest has inconsistent physical sizes");
    }
    blobs.set(path.blob.blob_sha256, path.blob.byte_length);
  }
  return blobs;
}

export interface M3QuotaReplayTransition {
  readonly identity: string;
  readonly existingPhysicalBytes: number;
  readonly newUniquePhysicalBytes: number;
  readonly resultingPhysicalBytes: number;
  readonly ownPopulation: ReadonlyMap<string, number>;
}

/** Private deterministic seam over the exact production replay loop. */
export function replayM3QuotaPopulationTransitions(
  targetIdentity: string,
  transitions: readonly M3QuotaReplayTransition[],
  stateLimit = 4096,
): readonly ReadonlyMap<string, number>[] {
  if (!Number.isSafeInteger(stateLimit) || stateLimit < 1 || stateLimit > 4096) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline quota history state limit is invalid");
  }
  const states = new Map<string, ReadonlyMap<string, number>>([["", new Map()]]);
  const pending = [new Map<string, number>()];
  const targetPopulations = new Map<string, ReadonlyMap<string, number>>();
  while (pending.length > 0) {
    const retained = pending.shift()!;
    const existingBytes = [...retained.values()].reduce((total, size) => total + size, 0);
    for (const transition of transitions) {
      let newBytes = 0;
      let compatible = true;
      for (const [blobDigest, size] of transition.ownPopulation) {
        const prior = retained.get(blobDigest);
        if (prior === undefined) newBytes += size;
        else if (prior !== size) compatible = false;
      }
      if (!compatible || transition.existingPhysicalBytes !== existingBytes ||
          transition.newUniquePhysicalBytes !== newBytes ||
          transition.resultingPhysicalBytes !== existingBytes + newBytes) continue;
      const next = new Map(retained);
      for (const [blobDigest, size] of transition.ownPopulation) next.set(blobDigest, size);
      const key = [...next].sort(([left], [right]) => compareText(left, right))
        .map(([blobDigest, size]) => `${blobDigest}:${size}`).join("|");
      if (transition.identity === targetIdentity) targetPopulations.set(key, next);
      if (newBytes === 0 || states.has(key)) continue;
      if (states.size >= stateLimit) invalid("BASELINE_PROVENANCE_INVALID", "baseline quota history exceeds its bounded ambiguity limit");
      states.set(key, next);
      pending.push(next);
    }
  }
  return [...targetPopulations.values()];
}

/**
 * Replays every possible monotonic one-writer retained-population prefix. A
 * baseline is quota-authoritative only when at least one durable prefix yields
 * its exact existing/new/resulting transition.
 */
export function m3BaselineQuotaPopulationCandidates(
  target: M3BaselineRuntimeDocument,
  allBaselines: readonly M3BaselineRuntimeDocument[],
): readonly ReadonlyMap<string, number>[] {
  assertM3BaselineRuntimeSemantics(target);
  const unique = new Map<string, M3BaselineRuntimeDocument>();
  for (const baseline of allBaselines) {
    try {
      assertM3BaselineRuntimeSemantics(baseline);
      unique.set(baseline.content_sha256, baseline);
    } catch (error: unknown) {
      if (baseline.content_sha256 === target.content_sha256) throw error;
      // Unrelated invalid objects are classified separately and never become
      // predecessor transitions in a selected quota history.
    }
  }
  if (!unique.has(target.content_sha256)) unique.set(target.content_sha256, target);
  const transitions = [...unique].map(([digest, baseline]): M3QuotaReplayTransition => ({
    identity: digest,
    existingPhysicalBytes: baseline.blob_quota.existing_physical_bytes,
    newUniquePhysicalBytes: baseline.blob_quota.new_unique_physical_bytes,
    resultingPhysicalBytes: baseline.blob_quota.resulting_physical_bytes,
    ownPopulation: baselineBlobPopulation(baseline),
  }));
  return replayM3QuotaPopulationTransitions(target.content_sha256, transitions);
}

export function assertM3BaselineQuotaHistorySemantics(
  target: M3BaselineRuntimeDocument,
  allBaselines: readonly M3BaselineRuntimeDocument[],
): void {
  if (m3BaselineQuotaPopulationCandidates(target, allBaselines).length === 0) {
    invalid("BASELINE_PROVENANCE_INVALID", "baseline quota is not a possible durable retained-population transition");
  }
}

export function assertM3BaselineApprovalSemantics(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument,
): void {
  assertM3BaselineRuntimeSemantics(baseline);
  assertDocumentValid("pi_gacw_baseline_approval_runtime_v0", approval);
  assertDocumentValid("pi_gacw_baseline_approval_v0", approval.accepted_approval);
  if (baseline.baseline_mode !== "APPROVED_BASELINE_DIRTY" || approval.run_id !== baseline.run_id ||
      approval.baseline_runtime_content_sha256 !== baseline.content_sha256 ||
      approval.baseline_snapshot_sha256 !== baseline.accepted_baseline.baseline_sha256 ||
      approval.baseline_snapshot_content_sha256 !== baseline.accepted_baseline.content_sha256 ||
      approval.accepted_approval.baseline_sha256 !== baseline.accepted_baseline.baseline_sha256) {
    invalid("BASELINE_APPROVAL_SEMANTIC_MISMATCH", "approval does not bind the exact baseline runtime and snapshot");
  }
  const accepted = approval.accepted_approval.target_repository;
  const expected = baseline.accepted_baseline.target_repository;
  if (accepted.root !== expected.root || accepted.root !== baseline.repository.worktree_root ||
      accepted.worktree !== expected.worktree || accepted.worktree !== baseline.repository.worktree_root) {
    invalid("BASELINE_APPROVAL_REPOSITORY_MISMATCH", "approval physical/Git worktree root differs from the baseline");
  }
  if (accepted.git_common_dir !== expected.git_common_dir || accepted.git_common_dir !== baseline.repository.git_common_dir) {
    invalid("BASELINE_APPROVAL_WORKTREE_MISMATCH", "approval Git common directory differs from the baseline");
  }
  if (accepted.branch !== expected.branch || accepted.branch !== (baseline.repository.branch ?? "DETACHED")) {
    invalid("BASELINE_APPROVAL_BRANCH_MISMATCH", "approval branch/detached representation differs from the baseline");
  }
  if (accepted.head !== expected.head || accepted.head !== baseline.repository.head) {
    invalid("BASELINE_APPROVAL_HEAD_MISMATCH", "approval HEAD differs from the baseline");
  }
  const retention = baseline.paths.map((entry) => ({
    path: entry.path,
    data_class: entry.data_class,
    capture_mode: entry.capture_mode,
    retention_days_after_terminal: entry.retention_days_after_terminal,
    blob: entry.blob,
  }));
  if (approval.approved_by !== approval.accepted_approval.approved_by || approval.approval_scope !== "EXACT_BASELINE" ||
      approval.decisions_sha256 !== sha256Canonical(baseline.paths) ||
      approval.retention_sha256 !== sha256Canonical(retention) || !same(approval.decisions, baseline.paths)) {
    invalid("BASELINE_APPROVAL_SEMANTIC_MISMATCH", "approval decisions do not exactly cover the baseline path policy");
  }
  assertExactUtcTimestamp(approval.approved_at, "BASELINE_APPROVAL_SEMANTIC_MISMATCH", "approval timestamp");
}

export function requireM3BaselineApprovalSemantics(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
): void {
  assertM3BaselineRuntimeSemantics(baseline);
  if (baseline.baseline_mode === "CLEAN_REQUIRED") {
    if (approval !== null) invalid("BASELINE_APPROVAL_SEMANTIC_MISMATCH", "clean baseline carries a dirty approval");
    return;
  }
  if (approval === null) missing("BASELINE_APPROVAL_RECORD_MISSING", "approved-dirty baseline has no approval");
  assertM3BaselineApprovalSemantics(baseline, approval);
}

export function assertM3LockAcquisitionSemantics(acquisition: M3LockAcquisitionDocument): void {
  try {
    assertLockAcquisitionSemantics(acquisition);
  } catch {
    invalid("LOCK_ACQUISITION_SEMANTIC_MISMATCH", "lock acquisition producer root is inconsistent");
  }
}

export function assertM3LockDiagnosticSemantics(
  diagnostic: M3LockDiagnosticDocument,
  acquisition: M3LockAcquisitionDocument,
  baseline: M3BaselineRuntimeDocument,
): void {
  assertDocumentValid("pi_gacw_lock_diagnostic_v0", diagnostic);
  assertM3LockAcquisitionSemantics(acquisition);
  if (diagnostic.lock_acquisition_content_sha256 !== acquisition.content_sha256 ||
      diagnostic.state_root !== acquisition.state_root ||
      diagnostic.protocol_version !== acquisition.protocol_version ||
      diagnostic.worktree_key !== acquisition.worktree_key ||
      diagnostic.worktree_root !== acquisition.worktree_root ||
      diagnostic.git_common_dir !== acquisition.git_common_dir ||
      diagnostic.lock_path !== acquisition.lock_path ||
      diagnostic.owner_marker_path !== acquisition.owner_marker_path ||
      diagnostic.guardian_python_invocation_path !== acquisition.guardian_python_invocation_path ||
      diagnostic.guardian_python_realpath !== acquisition.guardian_python_realpath ||
      diagnostic.guardian_python_path !== acquisition.guardian_python_realpath ||
      diagnostic.guardian_python_version !== acquisition.guardian_python_version ||
      diagnostic.guardian_helper_path !== acquisition.guardian_helper_path ||
      diagnostic.guardian_helper_realpath !== acquisition.guardian_helper_realpath ||
      diagnostic.guardian_helper_sha256 !== acquisition.guardian_helper_sha256 ||
      diagnostic.controller_pid !== acquisition.controller_pid ||
      diagnostic.guardian_pid !== acquisition.guardian_pid ||
      diagnostic.acquired_at !== acquisition.acquired_at ||
      diagnostic.acquisition_nonce !== acquisition.acquisition_nonce ||
      diagnostic.guardian_ready_sha256 !== acquisition.guardian_ready_sha256 ||
      diagnostic.worktree_key !== baseline.repository.worktree_key ||
      diagnostic.worktree_root !== baseline.repository.worktree_root ||
      diagnostic.git_common_dir !== baseline.repository.git_common_dir) {
    invalid("PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "lock diagnostic does not exactly bind its acquisition root and baseline worktree");
  }
  assertExactUtcTimestamp(diagnostic.acquired_at, "PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "lock acquisition timestamp");
}

function environmentSemantics(
  environment: M3PreflightDocument["environment_fingerprint"],
  repository: M3RepositoryIdentityDocument,
  lockDiagnostic: M3LockDiagnosticDocument,
): void {
  const { content_sha256: _identity, ...projection } = environment;
  if (environment.content_sha256 !== sha256Canonical(projection) ||
      environment.git_version !== repository.git_version ||
      environment.python_path !== lockDiagnostic.guardian_python_path ||
      environment.python_version !== lockDiagnostic.guardian_python_version ||
      environment.guardian_helper_path !== lockDiagnostic.guardian_helper_path ||
      environment.guardian_helper_sha256 !== lockDiagnostic.guardian_helper_sha256) {
    invalid("PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "environment fingerprint or guardian acquisition binding is inconsistent");
  }
}

function commonTokenSemantics(token: M3RepositoryStateTokenDocument): void {
  assertDocumentValid("pi_gacw_repository_state_token_v0", token);
  if (token.repository_identity_content_sha256 !== token.git_fingerprint.repository_identity_content_sha256 ||
      token.branch !== token.git_fingerprint.branch || token.head !== token.git_fingerprint.head ||
      token.worktree_list_sha256 !== token.git_fingerprint.worktree_list_sha256 ||
      token.instruction_fingerprint.content_sha256 !== sha256Canonical(token.instruction_fingerprint.entries) ||
      token.authority_fingerprint.content_sha256 !== sha256Canonical(token.authority_fingerprint.entries) ||
      !same(token.changed_paths, [...token.changed_paths].sort(compareText)) ||
      new Set(token.changed_paths).size !== token.changed_paths.length) {
    invalid("STATE_TOKEN_PROVENANCE_INVALID", "repository-state token has inconsistent embedded identities");
  }
}

export function assertM3FullPreflightSourceSemantics(
  source: M3PreflightDocument,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  token: M3RepositoryStateTokenDocument | null,
  lockDiagnostic: M3LockDiagnosticDocument,
  lockAcquisition: M3LockAcquisitionDocument,
): void {
  assertDocumentValid("pi_gacw_preflight_v0", source);
  requireM3BaselineApprovalSemantics(baseline, approval);
  assertM3GitFingerprintSemantics(source.git_fingerprint, source.repository);
  assertM3LockDiagnosticSemantics(lockDiagnostic, lockAcquisition, baseline);
  environmentSemantics(source.environment_fingerprint, source.repository, lockDiagnostic);
  if (source.preflight_kind !== "FULL" || source.result !== "PASS" || source.prior_token_content_sha256 !== null ||
      source.run_id !== baseline.run_id || source.baseline_runtime_content_sha256 !== baseline.content_sha256 ||
      source.baseline_snapshot_sha256 !== baseline.accepted_baseline.baseline_sha256 ||
      source.baseline_approval_runtime_content_sha256 !== (approval?.content_sha256 ?? null) ||
      !same(source.repository, baseline.repository) || source.worktree_key !== baseline.repository.worktree_key ||
      !same(source.git_fingerprint, baseline.git_fingerprint) ||
      !same(source.instruction_fingerprint, baseline.instruction_fingerprint) ||
      !same(source.authority_fingerprint, baseline.authority_fingerprint) ||
      source.lock_diagnostic_content_sha256 !== lockDiagnostic.content_sha256) {
    invalid("PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "full-preflight source does not bind the exact baseline authority");
  }
  if (token === null) return;
  commonTokenSemantics(token);
  if (token.source !== "FULL_PREFLIGHT" || token.source_content_sha256 !== source.content_sha256 ||
      token.prior_token_content_sha256 !== null || token.run_id !== source.run_id ||
      token.repository_identity_content_sha256 !== source.repository.content_sha256 ||
      token.worktree_key !== source.worktree_key || token.branch !== source.repository.branch ||
      token.head !== source.repository.head || token.worktree_list_sha256 !== source.repository.worktree_list_sha256 ||
      !same(token.git_fingerprint, source.git_fingerprint) ||
      !same(token.instruction_fingerprint, source.instruction_fingerprint) ||
      !same(token.authority_fingerprint, source.authority_fingerprint) ||
      token.baseline_runtime_content_sha256 !== source.baseline_runtime_content_sha256 ||
      token.lock_diagnostic_content_sha256 !== source.lock_diagnostic_content_sha256 ||
      token.task_scope_identity !== source.task_scope_identity ||
      token.workflow_owned_delta_sha256 !== sha256Canonical([]) || token.changed_paths.length !== 0) {
    invalid("STATE_TOKEN_PROVENANCE_INVALID", "full-preflight token does not exactly bind its source");
  }
}

export function assertM3FastPreflightRecordSemantics(
  source: M3PreflightDocument,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  lockDiagnostic: M3LockDiagnosticDocument,
  lockAcquisition: M3LockAcquisitionDocument,
): void {
  assertDocumentValid("pi_gacw_preflight_v0", source);
  requireM3BaselineApprovalSemantics(baseline, approval);
  commonTokenSemantics(prior);
  assertM3GitFingerprintSemantics(source.git_fingerprint, source.repository);
  assertM3LockDiagnosticSemantics(lockDiagnostic, lockAcquisition, baseline);
  environmentSemantics(source.environment_fingerprint, source.repository, lockDiagnostic);
  if (source.preflight_kind !== "FAST" || source.result !== "PASS" ||
      source.prior_token_content_sha256 !== prior.content_sha256 || source.run_id !== prior.run_id ||
      source.run_id !== baseline.run_id || source.baseline_runtime_content_sha256 !== baseline.content_sha256 ||
      source.baseline_snapshot_sha256 !== baseline.accepted_baseline.baseline_sha256 ||
      source.baseline_approval_runtime_content_sha256 !== (approval?.content_sha256 ?? null) ||
      source.repository.content_sha256 !== prior.repository_identity_content_sha256 ||
      source.worktree_key !== prior.worktree_key || source.lock_diagnostic_content_sha256 !== prior.lock_diagnostic_content_sha256 ||
      source.task_scope_identity !== prior.task_scope_identity || !same(source.git_fingerprint, prior.git_fingerprint) ||
      !same(source.instruction_fingerprint, prior.instruction_fingerprint) ||
      !same(source.authority_fingerprint, prior.authority_fingerprint)) {
    invalid("PREFLIGHT_SOURCE_SEMANTIC_MISMATCH", "fast-preflight record does not exactly bind its prior authority");
  }
}

function assertScopeSemantics(scope: M3PostflightDocument["scope"]): void {
  assertCanonicalSortedUniquePaths(scope.editable_paths, "POSTFLIGHT_SCOPE_IDENTITY_MISMATCH", "editable scope");
  assertCanonicalSortedUniquePaths(scope.frozen_paths, "POSTFLIGHT_SCOPE_IDENTITY_MISMATCH", "frozen scope");
  for (const editable of scope.editable_paths) {
    for (const frozen of scope.frozen_paths) {
      if (pathWithin(editable, frozen) || pathWithin(frozen, editable)) {
        invalid("POSTFLIGHT_SCOPE_IDENTITY_MISMATCH", "editable and frozen scope envelopes overlap");
      }
    }
  }
  if (scope.schema_id !== M3_SCOPE_SCHEMA_ID || scope.schema_version !== M3_SCOPE_VERSION ||
      scope.scope_projection_id !== M3_SCOPE_PROJECTION_ID ||
      scope.scope_identity !== m3ScopeIdentity(scope.editable_paths, scope.frozen_paths)) {
    invalid("POSTFLIGHT_SCOPE_IDENTITY_MISMATCH", "stored postflight scope identity domain or path projection is stale");
  }
}

function deltaEntrySemantics(entry: M3DeltaEntry, label: string): void {
  const beforeAbsent = entry.before_type === null || entry.before_type === "DELETED";
  const afterAbsent = entry.after_type === null || entry.after_type === "DELETED";
  if ((beforeAbsent !== (entry.before_content_sha256 === null && entry.before_mode === null)) ||
      (afterAbsent !== (entry.after_content_sha256 === null && entry.after_mode === null))) {
    invalid("POSTFLIGHT_DELTA_MISMATCH", `${label} has incoherent content/type/mode fields`);
  }
  if ((entry.change_kind === "ADDED" && (!beforeAbsent || afterAbsent)) ||
      (entry.change_kind === "DELETED" && (beforeAbsent || !afterAbsent)) ||
      (entry.change_kind === "TYPE_CHANGED" && (entry.before_type === entry.after_type || beforeAbsent || afterAbsent)) ||
      (entry.change_kind === "MODE_CHANGED" && (beforeAbsent || afterAbsent || entry.before_type !== entry.after_type ||
        entry.before_content_sha256 !== entry.after_content_sha256 || entry.before_mode === entry.after_mode)) ||
      (entry.change_kind === "MODIFIED" && (beforeAbsent || afterAbsent || entry.before_type !== entry.after_type ||
        entry.before_content_sha256 === entry.after_content_sha256))) {
    invalid("POSTFLIGHT_DELTA_MISMATCH", `${label} change kind is inconsistent with its path states`);
  }
}

function assertDeltaInventory(entries: readonly M3DeltaEntry[], label: string): void {
  assertCanonicalSortedUniqueByPath(entries, "POSTFLIGHT_DELTA_MISMATCH", label);
  for (const entry of entries) deltaEntrySemantics(entry, label);
}

function fingerprintPathSignature(fingerprint: M3GitStateFingerprintDocument, path: string): string {
  return canonicalize(fingerprintStatusProjection(fingerprint, path));
}

function changedFingerprintPaths(
  before: M3GitStateFingerprintDocument,
  after: M3GitStateFingerprintDocument,
): readonly string[] {
  const all = [...new Set([...m3FingerprintDirtyPaths(before), ...m3FingerprintDirtyPaths(after)])].sort(compareText);
  return all.filter((path) => fingerprintPathSignature(before, path) !== fingerprintPathSignature(after, path));
}

function statusForDelta(fingerprint: M3GitStateFingerprintDocument, path: string) {
  const staged = fingerprint.staged.find((entry) => entry.path === path);
  const unstaged = fingerprint.unstaged.find((entry) => entry.path === path);
  const untracked = fingerprint.untracked.find((entry) => entry.path === path);
  return { staged, unstaged, untracked };
}

function assertDeltaAfterMatchesFingerprint(entry: M3DeltaEntry, fingerprint: M3GitStateFingerprintDocument): void {
  const { staged, unstaged, untracked } = statusForDelta(fingerprint, entry.path);
  if (entry.staged_status !== (staged?.status ?? null) || entry.unstaged_status !== (unstaged?.status ?? null) ||
      entry.untracked !== (untracked !== undefined)) {
    invalid("POSTFLIGHT_DELTA_MISMATCH", "delta status does not match the resulting Git fingerprint");
  }
  const state = untracked ?? unstaged;
  if (state !== undefined && "content_sha256" in state) {
    const present = state.content_sha256 !== null;
    if (entry.after_content_sha256 !== state.content_sha256 ||
        entry.after_type !== (present ? "REGULAR" : "DELETED") || entry.after_mode !== state.mode) {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "delta resulting path state does not match the Git fingerprint");
    }
  }
}

function expectedWorkflowDeltaPaths(
  baseline: M3BaselineRuntimeDocument,
  fingerprint: M3GitStateFingerprintDocument,
  repositoryDelta: readonly M3DeltaEntry[],
): readonly string[] {
  const baselineByPath = new Map(baseline.paths.map((entry) => [entry.path, entry]));
  const repositoryByPath = new Map(repositoryDelta.map((entry) => [entry.path, entry]));
  const dirty = new Set(m3FingerprintDirtyPaths(fingerprint));
  const all = [...new Set([...baselineByPath.keys(), ...dirty])].sort(compareText);
  const expected: string[] = [];
  for (const path of all) {
    const prior = baselineByPath.get(path);
    if (prior === undefined) {
      if (dirty.has(path)) expected.push(path);
      continue;
    }
    if (!dirty.has(path)) {
      expected.push(path);
      continue;
    }
    const after = repositoryByPath.get(path);
    if (after === undefined || prior.content_sha256 !== after.after_content_sha256 || prior.file_type !== after.after_type ||
        prior.mode !== after.after_mode || prior.status_sha256 !== sha256Canonical(fingerprintStatusProjection(fingerprint, path))) {
      expected.push(path);
    }
  }
  return expected;
}

function assertWorkflowDeltaSemantics(
  source: M3PostflightDocument,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
): void {
  const repositoryPaths = source.repository_git_delta.map((entry) => entry.path);
  if (!same(repositoryPaths, m3FingerprintDirtyPaths(source.git_fingerprint))) {
    invalid("POSTFLIGHT_DELTA_MISMATCH", "repository Git delta does not cover the resulting fingerprint path inventory");
  }
  for (const entry of source.repository_git_delta) assertDeltaAfterMatchesFingerprint(entry, source.git_fingerprint);
  const expectedOwned = expectedWorkflowDeltaPaths(baseline, source.git_fingerprint, source.repository_git_delta);
  if (!same(source.workflow_owned_delta.map((entry) => entry.path), expectedOwned)) {
    invalid("POSTFLIGHT_DELTA_MISMATCH", "workflow-owned delta is not the exact baseline-to-resulting-state path set");
  }
  const baselineByPath = new Map(baseline.paths.map((entry) => [entry.path, entry]));
  const repositoryByPath = new Map(source.repository_git_delta.map((entry) => [entry.path, entry]));
  const dirty = new Set(m3FingerprintDirtyPaths(source.git_fingerprint));
  for (const entry of source.workflow_owned_delta) {
    const baselinePath = baselineByPath.get(entry.path);
    const baselineBeforeContent = baselinePath?.file_type === "DELETED" ? null : baselinePath?.content_sha256;
    if (baselinePath !== undefined && (entry.before_content_sha256 !== baselineBeforeContent ||
        entry.before_type !== baselinePath.file_type || entry.before_mode !== baselinePath.mode)) {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "workflow delta before-state differs from the baseline");
    }
    if (dirty.has(entry.path)) {
      const repositoryEntry = repositoryByPath.get(entry.path);
      if (repositoryEntry === undefined || entry.after_content_sha256 !== repositoryEntry.after_content_sha256 ||
          entry.after_type !== repositoryEntry.after_type || entry.after_mode !== repositoryEntry.after_mode ||
          entry.staged_status !== repositoryEntry.staged_status || entry.unstaged_status !== repositoryEntry.unstaged_status ||
          entry.untracked !== repositoryEntry.untracked) {
        invalid("POSTFLIGHT_DELTA_MISMATCH", "workflow delta after-state differs from the repository delta");
      }
    } else if (entry.change_kind !== "BASELINE_REVERTED") {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "clean resulting baseline path is not represented as a baseline reversion");
    }
    if (baselinePath?.ownership_class === "OWNER_AUTHORITY" || baselinePath?.ownership_class === "PREEXISTING_UNRELATED") {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "workflow delta claims a path outside mutable ownership");
    }
  }
  const expectedClaims = changedFingerprintPaths(prior.git_fingerprint, source.git_fingerprint);
  if (!same(source.claimed_workflow_paths, expectedClaims)) {
    invalid("POSTFLIGHT_CLAIMED_PATHS_MISMATCH", "claimed paths do not equal the exact prior-to-resulting fingerprint change set");
  }
  for (const path of source.claimed_workflow_paths) {
    if (!pathWithinAny(path, source.scope.editable_paths) || pathWithinAny(path, source.scope.frozen_paths)) {
      invalid("POSTFLIGHT_CLAIMED_PATHS_MISMATCH", "claimed path is outside editable scope or inside frozen scope");
    }
  }
  for (const entry of source.workflow_owned_delta) {
    if (!pathWithinAny(entry.path, source.scope.editable_paths) || pathWithinAny(entry.path, source.scope.frozen_paths)) {
      invalid("POSTFLIGHT_DELTA_MISMATCH", "workflow delta is outside editable scope or inside frozen scope");
    }
  }
}

export function assertM3PostflightSourceSemantics(
  source: M3PostflightDocument,
  successor: M3RepositoryStateTokenDocument | null,
  prior: M3RepositoryStateTokenDocument,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
): void {
  assertDocumentValid("pi_gacw_postflight_v0", source);
  requireM3BaselineApprovalSemantics(baseline, approval);
  commonTokenSemantics(prior);
  assertM3GitFingerprintSemantics(source.git_fingerprint, source.repository);
  assertScopeSemantics(source.scope);
  assertCanonicalSortedUniquePaths(source.claimed_workflow_paths, "POSTFLIGHT_CLAIMED_PATHS_MISMATCH", "claimed workflow paths");
  assertDeltaInventory(source.repository_git_delta, "repository Git delta");
  assertDeltaInventory(source.workflow_owned_delta, "workflow-owned delta");
  if (source.result !== "PASS" || source.run_id !== prior.run_id || source.run_id !== baseline.run_id ||
      source.prior_token_content_sha256 !== prior.content_sha256 ||
      source.baseline_runtime_content_sha256 !== baseline.content_sha256 || !same(source.repository, baseline.repository) ||
      source.lock_diagnostic_content_sha256 !== prior.lock_diagnostic_content_sha256 ||
      source.scope.scope_identity !== prior.task_scope_identity) {
    invalid("POSTFLIGHT_SOURCE_SEMANTIC_MISMATCH", "postflight source does not bind its prior token and baseline authority");
  }
  assertWorkflowDeltaSemantics(source, prior, baseline);
  if (successor === null) return;
  commonTokenSemantics(successor);
  if (successor.source !== "POSTFLIGHT" || successor.source_content_sha256 !== source.content_sha256 ||
      successor.prior_token_content_sha256 !== prior.content_sha256 || successor.run_id !== source.run_id ||
      successor.baseline_runtime_content_sha256 !== baseline.content_sha256 ||
      successor.repository_identity_content_sha256 !== source.repository.content_sha256 ||
      successor.worktree_key !== source.repository.worktree_key || successor.branch !== source.repository.branch ||
      successor.head !== source.repository.head || successor.worktree_list_sha256 !== source.repository.worktree_list_sha256 ||
      !same(successor.git_fingerprint, source.git_fingerprint) ||
      !same(successor.instruction_fingerprint, prior.instruction_fingerprint) ||
      !same(successor.authority_fingerprint, prior.authority_fingerprint) ||
      successor.lock_diagnostic_content_sha256 !== source.lock_diagnostic_content_sha256 ||
      successor.task_scope_identity !== source.scope.scope_identity ||
      successor.workflow_owned_delta_sha256 !== sha256Canonical(source.workflow_owned_delta) ||
      !same(successor.changed_paths, source.workflow_owned_delta.map((entry) => entry.path))) {
    invalid("STATE_TOKEN_PROVENANCE_INVALID", "postflight successor token does not exactly bind its semantic source");
  }
}

export function assertM3ResumeLockHandoverSemantics(
  source: M3ResumeLockHandoverDocument,
  successor: M3RepositoryStateTokenDocument | null,
  prior: M3RepositoryStateTokenDocument,
  priorAuthority: Pick<M3TokenAuthority, "lockAcquisition">,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  lockDiagnostic: M3LockDiagnosticDocument,
  lockAcquisition: M3LockAcquisitionDocument,
): void {
  assertDocumentValid("pi_gacw_resume_lock_handover_v0", source);
  requireM3BaselineApprovalSemantics(baseline, approval);
  commonTokenSemantics(prior);
  assertM3LockDiagnosticSemantics(lockDiagnostic, lockAcquisition, baseline);
  // The handover source binds exactly the predecessor's immutable environment
  // projection identities and the current held lock generation.
  if (source.run_id !== prior.run_id || source.run_id !== baseline.run_id ||
      source.prior_token_content_sha256 !== prior.content_sha256 ||
      source.repository_identity_content_sha256 !== prior.repository_identity_content_sha256 ||
      source.git_fingerprint_sha256 !== prior.git_fingerprint.content_sha256 ||
      source.instruction_fingerprint_sha256 !== prior.instruction_fingerprint.content_sha256 ||
      source.authority_fingerprint_sha256 !== prior.authority_fingerprint.content_sha256 ||
      source.lock_diagnostic_content_sha256 !== lockDiagnostic.content_sha256) {
    invalid("STATE_TOKEN_PROVENANCE_INVALID", "resume-lock-handover source does not exactly bind its predecessor authority");
  }
  // Same-generation rule: a handover must cross a real lock-generation change.
  if (lockDiagnostic.content_sha256 === prior.lock_diagnostic_content_sha256 ||
      lockAcquisition.content_sha256 === priorAuthority.lockAcquisition.content_sha256) {
    invalid("STATE_TOKEN_PROVENANCE_INVALID", "resume-lock-handover does not advance to a new lock generation");
  }
  if (successor === null) return;
  commonTokenSemantics(successor);
  // The successor token preserves the predecessor's exact repository-state
  // representation byte-exact and changes only its current lock generation.
  if (successor.source !== "RESUME_LOCK_HANDOVER" || successor.source_content_sha256 !== source.content_sha256 ||
      successor.prior_token_content_sha256 !== prior.content_sha256 || successor.run_id !== source.run_id ||
      successor.baseline_runtime_content_sha256 !== prior.baseline_runtime_content_sha256 ||
      successor.repository_identity_content_sha256 !== prior.repository_identity_content_sha256 ||
      successor.worktree_key !== prior.worktree_key || successor.branch !== prior.branch ||
      successor.head !== prior.head || successor.worktree_list_sha256 !== prior.worktree_list_sha256 ||
      !same(successor.git_fingerprint, prior.git_fingerprint) ||
      !same(successor.instruction_fingerprint, prior.instruction_fingerprint) ||
      !same(successor.authority_fingerprint, prior.authority_fingerprint) ||
      successor.task_scope_identity !== prior.task_scope_identity ||
      successor.workflow_owned_delta_sha256 !== prior.workflow_owned_delta_sha256 ||
      !same(successor.changed_paths, prior.changed_paths) ||
      successor.lock_diagnostic_content_sha256 !== lockDiagnostic.content_sha256) {
    invalid("STATE_TOKEN_PROVENANCE_INVALID", "resume-lock-handover successor token does not exactly bind its semantic source");
  }
}

export interface M3AuthorityResolver {
  readonly baseline: (digest: string) => Promise<M3BaselineRuntimeDocument | undefined>;
  readonly approval: (digest: string) => Promise<M3BaselineApprovalRuntimeDocument | undefined>;
  readonly lockAcquisition: (digest: string) => Promise<M3LockAcquisitionDocument | undefined>;
  readonly lockDiagnostic: (digest: string) => Promise<M3LockDiagnosticDocument | undefined>;
  readonly preflight: (digest: string) => Promise<M3PreflightDocument | undefined>;
  readonly postflight: (digest: string) => Promise<M3PostflightDocument | undefined>;
  readonly resumeHandover: (digest: string) => Promise<M3ResumeLockHandoverDocument | undefined>;
  readonly token: (digest: string) => Promise<M3RepositoryStateTokenDocument | undefined>;
  readonly assertBaselineProducer: (baseline: M3BaselineRuntimeDocument) => Promise<void>;
  readonly assertLockAcquisitionProducer: (acquisition: M3LockAcquisitionDocument) => Promise<void>;
  readonly assertEnvironmentProducer: (
    source: M3PreflightDocument,
    lockDiagnostic: M3LockDiagnosticDocument,
  ) => Promise<void>;
  /** Live-environment continuity between the frozen root preflight and the current held lock generation. */
  readonly assertResumeHandoverEnvironment: (
    rootPreflight: M3PreflightDocument,
    lockDiagnostic: M3LockDiagnosticDocument,
  ) => Promise<void>;
  readonly assertPostflightProducer: (
    source: M3PostflightDocument,
    prior: M3RepositoryStateTokenDocument,
    baseline: M3BaselineRuntimeDocument,
  ) => Promise<void>;
}

export interface M3TokenAuthority {
  readonly token: M3RepositoryStateTokenDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly approval: M3BaselineApprovalRuntimeDocument | null;
  readonly lockAcquisition: M3LockAcquisitionDocument;
  readonly rootPreflight: M3PreflightDocument;
  readonly chainDepth: number;
}

export async function validateM3AuthoritativeToken(
  token: M3RepositoryStateTokenDocument,
  runId: string,
  resolver: M3AuthorityResolver,
  memo: Map<string, M3TokenAuthority> = new Map(),
  visiting: Set<string> = new Set(),
  depth = 0,
): Promise<M3TokenAuthority> {
  const cached = memo.get(token.content_sha256);
  if (cached !== undefined) return cached;
  if (depth > 64) throw new M3AuthorityValidationError("TOO_DEEP", "STATE_TOKEN_CHAIN_TOO_DEEP", "token chain exceeds 64 successors");
  if (visiting.has(token.content_sha256)) throw new M3AuthorityValidationError("LOOP", "STATE_TOKEN_CHAIN_LOOP", "token chain contains a loop");
  visiting.add(token.content_sha256);
  try {
    commonTokenSemantics(token);
    if (token.run_id !== runId) invalid("STATE_TOKEN_PROVENANCE_INVALID", "token belongs to another run");
    const baseline = await resolver.baseline(token.baseline_runtime_content_sha256);
    if (baseline === undefined) missing("BASELINE_RECORD_MISSING", "token baseline is missing");
    assertM3BaselineRuntimeSemantics(baseline);
    await resolver.assertBaselineProducer(baseline);
    let authority: M3TokenAuthority;
    if (token.source === "FULL_PREFLIGHT") {
      if (token.prior_token_content_sha256 !== null) invalid("STATE_TOKEN_PROVENANCE_INVALID", "full-preflight token has a prior token");
      const source = await resolver.preflight(token.source_content_sha256);
      if (source === undefined) missing("STATE_TOKEN_SOURCE_MISSING", "full-preflight token source is missing");
      let approval: M3BaselineApprovalRuntimeDocument | null = null;
      if (source.baseline_approval_runtime_content_sha256 !== null) {
        approval = await resolver.approval(source.baseline_approval_runtime_content_sha256) ??
          missing("BASELINE_APPROVAL_RECORD_MISSING", "token root approval is missing");
      }
      const lockDiagnostic = await resolver.lockDiagnostic(source.lock_diagnostic_content_sha256);
      if (lockDiagnostic === undefined) missing("STATE_TOKEN_LOCK_DIAGNOSTIC_MISSING", "full-preflight lock diagnostic is missing");
      const lockAcquisition = await resolver.lockAcquisition(lockDiagnostic.lock_acquisition_content_sha256);
      if (lockAcquisition === undefined) missing("STATE_TOKEN_LOCK_ACQUISITION_MISSING", "full-preflight lock acquisition root is missing");
      await resolver.assertLockAcquisitionProducer(lockAcquisition);
      await resolver.assertEnvironmentProducer(source, lockDiagnostic);
      assertM3FullPreflightSourceSemantics(source, baseline, approval, token, lockDiagnostic, lockAcquisition);
      authority = { token, baseline, approval, lockAcquisition, rootPreflight: source, chainDepth: 0 };
    } else if (token.source === "RESUME_LOCK_HANDOVER") {
      if (token.prior_token_content_sha256 === null) invalid("STATE_TOKEN_PROVENANCE_INVALID", "resume-lock-handover token has no prior token");
      const prior = await resolver.token(token.prior_token_content_sha256);
      if (prior === undefined) missing("STATE_TOKEN_RECORD_MISSING", "resume-lock-handover prior token is missing");
      const priorAuthority = await validateM3AuthoritativeToken(prior, runId, resolver, memo, visiting, depth + 1);
      if (priorAuthority.baseline.content_sha256 !== baseline.content_sha256) {
        invalid("STATE_TOKEN_PROVENANCE_INVALID", "resume-lock-handover token changes baseline authority");
      }
      const source = await resolver.resumeHandover(token.source_content_sha256);
      if (source === undefined) missing("STATE_TOKEN_SOURCE_MISSING", "resume-lock-handover token source is missing");
      if (source.prior_token_content_sha256 !== prior.content_sha256) {
        invalid("STATE_TOKEN_PROVENANCE_INVALID", "resume-lock-handover source binds another predecessor");
      }
      const lockDiagnostic = await resolver.lockDiagnostic(source.lock_diagnostic_content_sha256);
      if (lockDiagnostic === undefined) missing("STATE_TOKEN_LOCK_DIAGNOSTIC_MISSING", "resume-lock-handover lock diagnostic is missing");
      const lockAcquisition = await resolver.lockAcquisition(lockDiagnostic.lock_acquisition_content_sha256);
      if (lockAcquisition === undefined) missing("STATE_TOKEN_LOCK_ACQUISITION_MISSING", "resume-lock-handover lock acquisition root is missing");
      await resolver.assertLockAcquisitionProducer(lockAcquisition);
      await resolver.assertResumeHandoverEnvironment(priorAuthority.rootPreflight, lockDiagnostic);
      assertM3ResumeLockHandoverSemantics(source, token, prior, priorAuthority, baseline, priorAuthority.approval, lockDiagnostic, lockAcquisition);
      // The meaning of lockAcquisition becomes the CURRENT lock-generation
      // authority; the historical rootPreflight remains the original FULL_PREFLIGHT.
      authority = {
        token,
        baseline,
        approval: priorAuthority.approval,
        lockAcquisition,
        rootPreflight: priorAuthority.rootPreflight,
        chainDepth: priorAuthority.chainDepth + 1,
      };
    } else {
      if (token.prior_token_content_sha256 === null) invalid("STATE_TOKEN_PROVENANCE_INVALID", "postflight token has no prior token");
      const prior = await resolver.token(token.prior_token_content_sha256);
      if (prior === undefined) missing("STATE_TOKEN_RECORD_MISSING", "postflight prior token is missing");
      const priorAuthority = await validateM3AuthoritativeToken(prior, runId, resolver, memo, visiting, depth + 1);
      if (priorAuthority.baseline.content_sha256 !== baseline.content_sha256) {
        invalid("STATE_TOKEN_PROVENANCE_INVALID", "postflight token changes baseline authority");
      }
      const source = await resolver.postflight(token.source_content_sha256);
      if (source === undefined) missing("STATE_TOKEN_SOURCE_MISSING", "postflight token source is missing");
      await resolver.assertPostflightProducer(source, prior, baseline);
      assertM3PostflightSourceSemantics(source, token, prior, baseline, priorAuthority.approval);
      authority = {
        token,
        baseline,
        approval: priorAuthority.approval,
        lockAcquisition: priorAuthority.lockAcquisition,
        rootPreflight: priorAuthority.rootPreflight,
        chainDepth: priorAuthority.chainDepth + 1,
      };
    }
    memo.set(token.content_sha256, authority);
    return authority;
  } finally {
    visiting.delete(token.content_sha256);
  }
}

export function expectedM3TerminalRetentionAuthority(
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
  terminalWorkflowState: WorkflowState,
  terminalTimestamp: string,
): M3TerminalRetentionAuthorityDocument {
  requireM3BaselineApprovalSemantics(baseline, approval);
  assertExactUtcTimestamp(terminalTimestamp, "RETENTION_AUTHORITY_SEMANTIC_MISMATCH", "terminal timestamp");
  if (terminalWorkflowState.run_id !== baseline.run_id ||
      (terminalWorkflowState.phase !== "PASS" && terminalWorkflowState.phase !== "BLOCKED")) {
    invalid("RETENTION_NOT_TERMINAL", "retention authority requires the exact terminal state for the run");
  }
  const blobs = baseline.paths.filter((entry) => entry.blob !== null).map((entry) => {
    if (entry.blob === null || entry.retention_days_after_terminal === null ||
        !["PUBLIC_SOURCE", "PRIVATE_SOURCE", "SENSITIVE"].includes(entry.data_class)) {
      invalid("RETENTION_AUTHORITY_SEMANTIC_MISMATCH", "copied baseline path lacks retention metadata");
    }
    return {
      baseline_path: entry.path,
      blob_sha256: entry.blob.blob_sha256,
      byte_length: entry.blob.byte_length,
      relative_path: entry.blob.relative_path,
      data_class: entry.data_class as "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE",
      retention_deadline: addUtcDays(terminalTimestamp, entry.retention_days_after_terminal),
    };
  }).sort((left, right) => compareText(left.baseline_path, right.baseline_path));
  return identifyContractDocument("pi_gacw_terminal_retention_authority_v0", {
    schema_id: "pi_gacw_terminal_retention_authority_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: baseline.run_id,
    baseline_runtime_content_sha256: baseline.content_sha256,
    baseline_approval_runtime_content_sha256: approval?.content_sha256 ?? null,
    repository_identity_content_sha256: baseline.repository.content_sha256,
    terminal_workflow_state_content_sha256: terminalWorkflowState.content_sha256,
    terminal_timestamp: terminalTimestamp,
    worktree_key: baseline.repository.worktree_key,
    blobs,
  }) as unknown as M3TerminalRetentionAuthorityDocument;
}

export function assertM3TerminalRetentionAuthoritySemantics(
  authority: M3TerminalRetentionAuthorityDocument,
  workflowState: WorkflowState,
  baseline: M3BaselineRuntimeDocument,
  approval: M3BaselineApprovalRuntimeDocument | null,
): void {
  assertDocumentValid("pi_gacw_terminal_retention_authority_v0", authority);
  const expected = expectedM3TerminalRetentionAuthority(baseline, approval, workflowState, authority.terminal_timestamp);
  if (!same(expected, authority)) invalid("RETENTION_AUTHORITY_SEMANTIC_MISMATCH", "terminal authority is not the exact baseline projection");
}

export type RetentionLogicalReference = M3RetentionResultDocument["blobs"][number]["logical_references"][number];
export interface RetentionPhysicalGroup {
  readonly blobSha256: string;
  readonly byteLength: number;
  readonly relativePath: string;
  readonly dataClass: "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE";
  readonly retentionDeadline: string | null;
  readonly logicalReferenceCount: number;
  readonly references: readonly RetentionLogicalReference[];
  readonly uncoveredReferences: readonly { readonly baselineContentSha256: string; readonly baselinePath: string }[];
}
export interface RetentionAuthorityContext {
  readonly workflowState: WorkflowState;
  readonly baselines: ReadonlyMap<string, M3BaselineRuntimeDocument>;
  readonly approvals: ReadonlyMap<string, M3BaselineApprovalRuntimeDocument>;
  readonly authorities: ReadonlyMap<string, M3TerminalRetentionAuthorityDocument>;
  readonly groups: ReadonlyMap<string, RetentionPhysicalGroup>;
}

function aggregateDataClass(references: readonly RetentionLogicalReference[]): "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE" {
  if (references.some((entry) => entry.data_class === "SENSITIVE")) return "SENSITIVE";
  if (references.some((entry) => entry.data_class === "PRIVATE_SOURCE")) return "PRIVATE_SOURCE";
  return "PUBLIC_SOURCE";
}
function referenceOrder(left: RetentionLogicalReference, right: RetentionLogicalReference): number {
  return compareText(left.baseline_runtime_content_sha256, right.baseline_runtime_content_sha256) || compareText(left.baseline_path, right.baseline_path);
}

export function buildM3RetentionAuthorityContext(
  workflowState: WorkflowState,
  baselinesInput: readonly M3BaselineRuntimeDocument[],
  approvalsInput: readonly M3BaselineApprovalRuntimeDocument[],
  authoritiesInput: readonly M3TerminalRetentionAuthorityDocument[],
): RetentionAuthorityContext {
  const baselines = new Map<string, M3BaselineRuntimeDocument>();
  for (const baseline of baselinesInput) { assertM3BaselineRuntimeSemantics(baseline); baselines.set(baseline.content_sha256, baseline); }
  const approvals = new Map(approvalsInput.map((approval) => [approval.content_sha256, approval]));
  const authorities = new Map<string, M3TerminalRetentionAuthorityDocument>();
  const byBaseline = new Map<string, M3TerminalRetentionAuthorityDocument[]>();
  for (const authority of authoritiesInput) {
    const baseline = baselines.get(authority.baseline_runtime_content_sha256);
    if (baseline === undefined) missing("RETENTION_AUTHORITY_BASELINE_MISSING", "terminal authority baseline is missing");
    let approval: M3BaselineApprovalRuntimeDocument | null = null;
    if (authority.baseline_approval_runtime_content_sha256 !== null) {
      approval = approvals.get(authority.baseline_approval_runtime_content_sha256) ?? null;
      if (approval === null) missing("RETENTION_AUTHORITY_APPROVAL_MISSING", "terminal authority approval is missing");
    }
    assertM3TerminalRetentionAuthoritySemantics(authority, workflowState, baseline, approval);
    authorities.set(authority.content_sha256, authority);
    const list = byBaseline.get(baseline.content_sha256) ?? [];
    list.push(authority); byBaseline.set(baseline.content_sha256, list);
  }
  const mutable = new Map<string, { byteLength: number; relativePath: string; logicalReferenceCount: number; references: RetentionLogicalReference[]; uncoveredReferences: Array<{ baselineContentSha256: string; baselinePath: string }> }>();
  for (const baseline of baselines.values()) {
    const candidates = byBaseline.get(baseline.content_sha256) ?? [];
    if (candidates.length > 1) invalid("RETENTION_AUTHORITY_SEMANTIC_MISMATCH", "baseline has ambiguous terminal authorities");
    const authority = candidates[0];
    for (const path of baseline.paths) {
      if (path.blob === null) continue;
      let group = mutable.get(path.blob.blob_sha256);
      if (group === undefined) {
        group = { byteLength: path.blob.byte_length, relativePath: path.blob.relative_path, logicalReferenceCount: 0, references: [], uncoveredReferences: [] };
        mutable.set(path.blob.blob_sha256, group);
      }
      if (group.byteLength !== path.blob.byte_length || group.relativePath !== path.blob.relative_path) {
        invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "logical references disagree about one physical blob");
      }
      group.logicalReferenceCount += 1;
      const authorized = authority?.blobs.find((entry) => entry.baseline_path === path.path);
      if (authority === undefined || authorized === undefined || authorized.blob_sha256 !== path.blob.blob_sha256 ||
          authorized.byte_length !== path.blob.byte_length || authorized.relative_path !== path.blob.relative_path ||
          authorized.data_class !== path.data_class) {
        group.uncoveredReferences.push({ baselineContentSha256: baseline.content_sha256, baselinePath: path.path });
        continue;
      }
      group.references.push({
        baseline_runtime_content_sha256: baseline.content_sha256,
        baseline_approval_runtime_content_sha256: authority.baseline_approval_runtime_content_sha256,
        terminal_authority_content_sha256: authority.content_sha256,
        terminal_workflow_state_content_sha256: authority.terminal_workflow_state_content_sha256,
        repository_identity_content_sha256: baseline.repository.content_sha256,
        worktree_key: baseline.repository.worktree_key,
        baseline_path: path.path, blob_sha256: authorized.blob_sha256, byte_length: authorized.byte_length,
        relative_path: authorized.relative_path, data_class: authorized.data_class, retention_deadline: authorized.retention_deadline,
      });
    }
  }
  const groups = new Map<string, RetentionPhysicalGroup>();
  for (const [digest, group] of mutable) {
    const references = group.references.sort(referenceOrder);
    const deadlines = references.map((entry) => entry.retention_deadline).sort(compareText);
    groups.set(digest, {
      blobSha256: digest, byteLength: group.byteLength, relativePath: group.relativePath,
      dataClass: aggregateDataClass(references), retentionDeadline: deadlines.at(-1) ?? null,
      logicalReferenceCount: group.logicalReferenceCount, references,
      uncoveredReferences: group.uncoveredReferences.sort((left, right) => compareText(left.baselineContentSha256, right.baselineContentSha256) || compareText(left.baselinePath, right.baselinePath)),
    });
  }
  return { workflowState, baselines, approvals, authorities, groups };
}

export interface RetentionProof { readonly record: M3RetentionResultDocument; readonly rootRecord: M3RetentionResultDocument }
function exactGroupResult(blob: M3RetentionResultDocument["blobs"][number], group: RetentionPhysicalGroup): boolean {
  return group.retentionDeadline !== null &&
    blob.blob_sha256 === group.blobSha256 && blob.byte_length === group.byteLength && blob.relative_path === group.relativePath &&
    blob.data_class === group.dataClass && blob.retention_deadline === group.retentionDeadline && same(blob.logical_references, group.references) &&
    same(blob.uncovered_references, group.uncoveredReferences.map((entry) => ({ baseline_runtime_content_sha256: entry.baselineContentSha256, baseline_path: entry.baselinePath })));
}

const RETENTION_MISMATCH_DETAILS = new Set([
  "TARGET_MODE_MISMATCH", "TARGET_SIZE_MISMATCH", "TARGET_DIGEST_MISMATCH",
]);
const RETENTION_ERROR_DETAILS = new Set([
  "TARGET_SYMLINK", "TARGET_SPECIAL_FILE", "TARGET_DIRECTORY", "TARGET_READ_FAILED",
  "TARGET_UNLINK_FAILED", "TARGET_DIRECTORY_FSYNC_FAILED",
  "LIVE_REFERENCE_AUTHORITY_MISSING", "LIVE_REFERENCE_WORKTREE_MISMATCH",
]);

export interface M3RetentionResultAggregate {
  readonly outcome: M3RetentionResultDocument["outcome"];
  readonly deletionProofDigests: readonly string[];
}

/** Deterministic operation/result state machine used by producers, consumers, proofs, and inspection. */
export function deriveM3RetentionResultAggregate(record: M3RetentionResultDocument): M3RetentionResultAggregate {
  let failed = false;
  let pending = false;
  let deletionActivity = false;
  let deleted = 0;
  let idempotent = 0;
  let eligible = 0;
  const proofs: string[] = [];
  for (const blob of record.blobs) {
    if (blob.directory_fsync_performed && !blob.unlink_performed) {
      invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result attributes directory fsync without unlink");
    }
    const noOperation = !blob.unlink_performed && !blob.directory_fsync_performed;
    if (blob.status === "ELIGIBLE") {
      if (blob.result !== "ELIGIBLE" || blob.detail_code !== null || !noOperation ||
          blob.prior_successful_result_content_sha256 !== null) {
        invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "eligible retention target has an impossible result state");
      }
      eligible += 1;
    } else if (blob.status === "DEADLINE_PENDING") {
      if (blob.result !== "REFUSED" || blob.detail_code !== "RETENTION_DEADLINE_NOT_REACHED" || !noOperation ||
          blob.prior_successful_result_content_sha256 !== null) {
        invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "pending retention target has an impossible result state");
      }
      pending = true;
    } else if (blob.status === "DELETED") {
      if (record.operation !== "CLEANUP" || blob.result !== "SUCCEEDED" || blob.detail_code !== null ||
          !blob.unlink_performed || !blob.directory_fsync_performed || blob.prior_successful_result_content_sha256 !== null) {
        invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "deleted retention target has an impossible operation state");
      }
      deletionActivity = true;
      deleted += 1;
      proofs.push(blob.blob_sha256);
    } else if (blob.status === "ALREADY_REMOVED") {
      const inspectObservation = record.operation === "INSPECT";
      if (blob.result !== "IDEMPOTENT" || blob.detail_code !== null || !noOperation ||
          (inspectObservation ? blob.prior_successful_result_content_sha256 !== null :
            blob.prior_successful_result_content_sha256 === null)) {
        invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "already-removed target has invalid observation or cleanup proof authority");
      }
      idempotent += 1;
      if (!inspectObservation) proofs.push(blob.blob_sha256);
    } else {
      failed = true;
      if (blob.result !== "FAILED" || blob.prior_successful_result_content_sha256 !== null) {
        invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "failed retention target carries success authority");
      }
      if (blob.status === "MISSING") {
        if (blob.detail_code !== "TARGET_MISSING" || !noOperation) {
          invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "missing retention target has an impossible detail or operation state");
        }
      } else if (blob.status === "MISMATCH") {
        if (blob.detail_code === null || !RETENTION_MISMATCH_DETAILS.has(blob.detail_code) || !noOperation) {
          invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "mismatched retention target has an impossible detail or operation state");
        }
      } else if (blob.status === "ERROR") {
        if (blob.detail_code === null || !RETENTION_ERROR_DETAILS.has(blob.detail_code)) {
          invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "errored retention target has an unknown detail");
        }
        if (blob.detail_code === "TARGET_DIRECTORY_FSYNC_FAILED") {
          if (!blob.unlink_performed || blob.directory_fsync_performed) {
            invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "directory-fsync failure does not bind the post-unlink state");
          }
          deletionActivity = true;
        } else if (!noOperation) {
          invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention failure attributes an impossible unlink or fsync");
        }
      }
    }
  }
  let outcome: M3RetentionResultDocument["outcome"];
  if (record.operation === "INSPECT") {
    if (deletionActivity) invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "inspection result claims deletion activity");
    outcome = failed ? "FAILED" : pending ? "REFUSED" : "ELIGIBLE";
  } else if (failed) {
    outcome = deleted + idempotent > 0 || deletionActivity ? "PARTIAL" : "FAILED";
  } else if (pending) {
    outcome = deleted + idempotent > 0 || deletionActivity ? "PARTIAL" : "REFUSED";
  } else if (eligible > 0) {
    if (deleted + idempotent > 0 || deletionActivity) {
      invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "cleanup result leaves an eligible target after another target completed");
    }
    invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "cleanup result stopped at an inspection-only eligible state");
  } else if (deleted > 0) {
    outcome = "COMPLETE";
  } else if (idempotent > 0) {
    outcome = "IDEMPOTENT";
  } else if (record.blobs.length === 0) {
    outcome = "COMPLETE";
  } else {
    invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "cleanup result has no derived terminal aggregate");
  }
  if (record.outcome !== outcome) {
    invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result top-level outcome does not match its target aggregate");
  }
  return { outcome, deletionProofDigests: proofs.sort(compareText) };
}

export function assertM3RetentionResultStructure(record: M3RetentionResultDocument, context: RetentionAuthorityContext): void {
  assertDocumentValid("pi_gacw_retention_result_v0", record);
  assertExactUtcTimestamp(record.evaluated_at, "RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result timestamp");
  const authority = context.authorities.get(record.terminal_authority_content_sha256);
  const baseline = context.baselines.get(record.baseline_runtime_content_sha256);
  if (authority === undefined || baseline === undefined || authority.baseline_runtime_content_sha256 !== baseline.content_sha256 ||
      record.run_id !== baseline.run_id || record.terminal_workflow_state_content_sha256 !== authority.terminal_workflow_state_content_sha256 ||
      record.baseline_approval_runtime_content_sha256 !== authority.baseline_approval_runtime_content_sha256 ||
      record.repository_identity_content_sha256 !== baseline.repository.content_sha256 || record.worktree_key !== baseline.repository.worktree_key) {
    invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result top-level provenance is inconsistent");
  }
  const expectedDigests = [...new Set(authority.blobs.map((entry) => entry.blob_sha256))].sort(compareText);
  const actualDigests = record.blobs.map((entry) => entry.blob_sha256);
  if (!same(expectedDigests, actualDigests) || new Set(actualDigests).size !== actualDigests.length ||
      record.physical_target_count !== record.blobs.length ||
      record.logical_target_count !== record.blobs.reduce((total, entry) => total + entry.logical_references.length + entry.uncovered_references.length, 0)) {
    invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result target inventory is inconsistent");
  }
  for (const blob of record.blobs) {
    const group = context.groups.get(blob.blob_sha256);
    if (group === undefined || !exactGroupResult(blob, group)) invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result does not bind the exact logical-reference group");
    const evaluated = Date.parse(record.evaluated_at); const deadline = Date.parse(blob.retention_deadline);
    if (blob.status === "DEADLINE_PENDING" && evaluated >= deadline ||
        (blob.status === "ELIGIBLE" || blob.status === "DELETED" || blob.status === "ALREADY_REMOVED") && evaluated < deadline) {
      invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result status contradicts its deadline");
    }
    if (blob.status === "DELETED" && (blob.result !== "SUCCEEDED" || !blob.unlink_performed || !blob.directory_fsync_performed || blob.prior_successful_result_content_sha256 !== null) ||
        blob.status === "ALREADY_REMOVED" && (blob.result !== "IDEMPOTENT" || blob.unlink_performed || blob.directory_fsync_performed ||
          (record.operation === "INSPECT" ? blob.prior_successful_result_content_sha256 !== null : blob.prior_successful_result_content_sha256 === null)) ||
        blob.status === "ELIGIBLE" && blob.result !== "ELIGIBLE" || blob.status === "DEADLINE_PENDING" && blob.result !== "REFUSED" ||
        (["MISSING", "MISMATCH", "ERROR"].includes(blob.status) && blob.result !== "FAILED")) {
      invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result status/outcome flags are inconsistent");
    }
  }
  deriveM3RetentionResultAggregate(record);
}

function resolveRetentionProof(record: M3RetentionResultDocument, digest: string, context: RetentionAuthorityContext, records: ReadonlyMap<string, M3RetentionResultDocument>, visiting: Set<string>, depth: number): RetentionProof {
  if (record.operation !== "CLEANUP") invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "inspection records cannot enter a deletion-proof chain");
  if (depth > 64 || visiting.has(record.content_sha256)) invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention proof chain is cyclic or too deep");
  visiting.add(record.content_sha256);
  try {
    assertM3RetentionResultStructure(record, context);
    const blob = record.blobs.find((entry) => entry.blob_sha256 === digest);
    const group = context.groups.get(digest);
    if (blob === undefined || group === undefined || group.uncoveredReferences.length > 0 ||
        group.references.length !== group.logicalReferenceCount ||
        Date.parse(record.evaluated_at) < Date.parse(blob.retention_deadline)) {
      invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention proof omits, predates, or incompletely authorizes its target");
    }
    if (blob.status === "DELETED" && blob.result === "SUCCEEDED" && blob.unlink_performed && blob.directory_fsync_performed && blob.prior_successful_result_content_sha256 === null) return { record, rootRecord: record };
    if (blob.status === "ALREADY_REMOVED" && blob.result === "IDEMPOTENT" && !blob.unlink_performed && !blob.directory_fsync_performed && blob.prior_successful_result_content_sha256 !== null) {
      const prior = records.get(blob.prior_successful_result_content_sha256);
      if (prior === undefined) missing("RETENTION_RESULT_PRIOR_MISSING", "idempotent proof prior result is missing");
      const root = resolveRetentionProof(prior, digest, context, records, visiting, depth + 1);
      return { record, rootRecord: root.rootRecord };
    }
    invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "retention result is not successful deletion proof");
  } finally { visiting.delete(record.content_sha256); }
}

export function exactM3RetentionDeletionProof(results: readonly M3RetentionResultDocument[], context: RetentionAuthorityContext, digest: string): RetentionProof | null {
  const byDigest = new Map(results.map((record) => [record.content_sha256, record]));
  const proofs: RetentionProof[] = [];
  for (const record of results) {
    if (record.operation !== "CLEANUP") continue;
    const blob = record.blobs.find((entry) => entry.blob_sha256 === digest);
    if (blob === undefined) continue;
    if ((blob.status === "DELETED" && blob.result === "SUCCEEDED") || (blob.status === "ALREADY_REMOVED" && blob.result === "IDEMPOTENT")) {
      proofs.push(resolveRetentionProof(record, digest, context, byDigest, new Set(), 0));
    }
  }
  const roots = new Set(proofs.map((proof) => proof.rootRecord.content_sha256));
  if (roots.size > 1) invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "conflicting deletion proof roots claim one target");
  const root = proofs[0]?.rootRecord;
  return root === undefined ? null : { record: root, rootRecord: root };
}

export function assertM3RetentionResultSemantics(
  record: M3RetentionResultDocument,
  context: RetentionAuthorityContext,
  allResults: readonly M3RetentionResultDocument[],
): void {
  assertM3RetentionResultStructure(record, context);
  const byDigest = new Map(allResults.map((candidate) => [candidate.content_sha256, candidate]));
  for (const blob of record.blobs) {
    if (record.operation === "CLEANUP" && (blob.status === "DELETED" || blob.status === "ALREADY_REMOVED")) {
      resolveRetentionProof(record, blob.blob_sha256, context, byDigest, new Set(), 0);
    } else if (blob.prior_successful_result_content_sha256 !== null) {
      invalid("RETENTION_RESULT_SEMANTIC_MISMATCH", "non-proof retention result carries prior proof authority");
    }
  }
}
