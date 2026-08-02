import { readdir, readFile, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { Sha256Digest } from "../src/identity/index.js";
import { commitTransition } from "../src/persistence/index.js";
import {
  acquireWorktreeLock,
  captureBaseline,
  createBaselineApproval,
  createTerminalRetentionAuthority,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFullPreflight,
  type BaselinePathDecision,
  type WorktreeLockHandle,
} from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import { reduceState } from "../src/state-machine/index.js";
import { transitionEvent } from "./helpers.js";
import { processMetadata } from "./persistence-helpers.js";
import {
  createRepositoryFixture,
  instructionAuthorityInputs,
  requiredEnvironment,
  scopeIdentity,
  type RepositoryFixture,
} from "./repository-helpers.js";

export function codeOf(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { code: unknown }).code
    : undefined;
}

export function pathDecision(
  path: string,
  overrides: Partial<Omit<BaselinePathDecision, "path">> = {},
): BaselinePathDecision {
  return {
    path,
    ownershipClass: "OWNER_ACCEPTED_MUTABLE",
    dataClass: "PUBLIC_SOURCE",
    captureMode: "HASH_ONLY",
    explicitBlobApproval: false,
    retentionDaysAfterTerminal: null,
    ...overrides,
  };
}

export async function baselineInput(
  fixture: RepositoryFixture,
  lock: WorktreeLockHandle,
  mode: "CLEAN_REQUIRED" | "APPROVED_BASELINE_DIRTY",
  pathDecisions: readonly BaselinePathDecision[],
  policy: { readonly allowShallow?: boolean; readonly allowPartialClone?: boolean } = {},
) {
  const selected = await instructionAuthorityInputs(fixture);
  return {
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    requestedPath: fixture.repository,
    mode,
    pathDecisions,
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    allowShallow: policy.allowShallow ?? false,
    allowPartialClone: policy.allowPartialClone ?? false,
    lock,
  } as const;
}

export async function createCleanAdmission(
  fixture: RepositoryFixture,
  scope: { readonly editable?: readonly string[]; readonly frozen?: readonly string[] } = {},
) {
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const selected = await instructionAuthorityInputs(fixture);
  const baseline = (await captureBaseline({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    requestedPath: fixture.repository,
    mode: "CLEAN_REQUIRED",
    pathDecisions: [],
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    allowShallow: false,
    allowPartialClone: false,
    lock,
  })).baseline;
  const editable = [...(scope.editable ?? ["tracked.txt"])];
  const frozen = [...(scope.frozen ?? ["AGENTS.md", "AUTHORITY.md"])];
  const taskScopeIdentity = scopeIdentity(editable, frozen);
  const environment = await requiredEnvironment(fixture.repository);
  const full = await runFullPreflight({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    expectedRepository: baseline.repository,
    expectedWorktreeKey: baseline.repository.worktree_key,
    expectedBranch: baseline.repository.branch,
    expectedHead: baseline.repository.head,
    expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
    baseline,
    approval: null,
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    requiredEnvironment: environment,
    taskScopeIdentity,
    allowShallow: false,
    allowPartialClone: false,
    lock,
  });
  return { repository, lock, selected, baseline, editable, frozen, taskScopeIdentity, environment, full };
  } catch (error: unknown) {
    await releaseWorktreeLock(lock).catch(() => undefined);
    throw error;
  }
}

export async function releaseAdmission(admission: { readonly lock: WorktreeLockHandle }): Promise<void> {
  await releaseWorktreeLock(admission.lock).catch(() => undefined);
}

export interface TerminalBlobSpec {
  readonly name: string;
  readonly bytes?: Uint8Array | string;
  readonly dataClass?: "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE";
  readonly retentionDays?: number;
}

export async function createTerminalBlobFixture(
  specs: readonly TerminalBlobSpec[] = [{ name: "retained.txt" }],
) {
  const fixture = await createRepositoryFixture();
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const selected = await instructionAuthorityInputs(fixture);
    for (const [index, spec] of specs.entries()) {
      await writeFile(join(fixture.repository, spec.name), spec.bytes ?? `retained-${index}\n`);
    }
    const baseline = (await captureBaseline({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      requestedPath: fixture.repository,
      mode: "APPROVED_BASELINE_DIRTY",
      pathDecisions: specs.map((spec) => pathDecision(spec.name, {
        dataClass: spec.dataClass ?? "PUBLIC_SOURCE",
        captureMode: "BLOB",
        explicitBlobApproval: spec.dataClass === "PRIVATE_SOURCE" || spec.dataClass === "SENSITIVE",
        retentionDaysAfterTerminal: spec.retentionDays ?? (spec.dataClass === "SENSITIVE" ? 7 : 30),
      })),
      instructionFiles: selected.instructions,
      authorityFiles: selected.authorities,
      allowShallow: false,
      allowPartialClone: false,
      lock,
    })).baseline;
    const approval = await approveDirtyBaseline(fixture, baseline);
    const event = transitionEvent("BLOCK", { reason: "RETENTION_MATRIX_TERMINAL" });
    const terminalState = reduceState(fixture.initialState, event, fixture.policy);
    const authority = createTerminalRetentionAuthority({
      baseline,
      approval,
      terminalWorkflowState: terminalState,
      terminalTimestamp: "2026-01-01T00:00:00.000Z",
    });
    await commitTransition({
      stateRoot: fixture.stateRoot,
      runId: fixture.runId,
      expectedRevision: fixture.committed.statePointer.revision,
      expectedStatePointerContentSha256: fixture.committed.statePointer.content_sha256 as Sha256Digest,
      expectedWorkflowStateContentSha256: fixture.committed.workflowState.content_sha256 as Sha256Digest,
      expectedNextWorkflowStateContentSha256: terminalState.content_sha256 as Sha256Digest,
      transitionId: "retention-matrix-terminal",
      policy: fixture.policy,
      event,
      evidence: [{
        bytes: canonicalJsonRecordBytes(authority),
        mediaType: "application/vnd.pi-gacw.retention-authority+json",
      }],
      processMetadata,
    });
    return { fixture, baseline, approval, authority, terminalState };
  } finally {
    await releaseWorktreeLock(lock).catch(() => undefined);
  }
}

export function retentionInput(
  value: Awaited<ReturnType<typeof createTerminalBlobFixture>>,
  evaluatedAt = "2026-01-31T00:00:00.000Z",
) {
  return {
    stateRoot: value.fixture.stateRoot,
    runId: value.fixture.runId,
    baseline: value.baseline,
    terminalAuthority: value.authority,
    evaluatedAt,
  } as const;
}

export async function readRetentionRecords(fixture: RepositoryFixture): Promise<readonly Record<string, unknown>[]> {
  const directory = join(fixture.stateRoot, "runs", fixture.runId, "records", "retention");
  const records: Record<string, unknown>[] = [];
  for (const name of (await readdir(directory)).sort()) {
    records.push(JSON.parse(await readFile(join(directory, name), "utf8")) as Record<string, unknown>);
  }
  return records;
}

export async function physical(path: string): Promise<string> {
  return realpath(path);
}

export async function approveDirtyBaseline(
  fixture: RepositoryFixture,
  baseline: Awaited<ReturnType<typeof captureBaseline>>["baseline"],
) {
  return (await createBaselineApproval({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    baseline,
    approvedBy: "matrix-owner",
    approvedAt: "2026-01-01T00:00:00.000Z",
  })).approval;
}
