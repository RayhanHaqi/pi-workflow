import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalize } from "../src/canonical-json/index.js";
import type { Sha256Digest } from "../src/identity/index.js";
import {
  commitTransition,
  initializeRunStorage,
  type CommittedRunState,
} from "../src/persistence/index.js";
import type { ProcessMetadata, ReducerPolicy, TransitionEvent, WorkflowState } from "../src/schemas/index.js";
import { createInitialState } from "../src/state-machine/index.js";
import { makePolicy, stateIdentities, transitionEvent } from "./helpers.js";

export const processMetadata: ProcessMetadata = {
  controller_instance_id: "controller-test",
  process_id: 4242,
  invocation_id: "invocation-test",
};

export interface TestRun {
  readonly stateRoot: string;
  readonly runId: string;
  readonly policy: ReducerPolicy;
  readonly initialState: WorkflowState;
  readonly committed: CommittedRunState;
}

export async function createTestRun(): Promise<TestRun> {
  const stateRoot = await mkdtemp(join(tmpdir(), "pi-gacw-m2-"));
  await chmod(stateRoot, 0o700);
  const policy = makePolicy("DIRECT_LUNA_HIGH");
  const runId = policy.run_id;
  const initialState = createInitialState(policy, stateIdentities(policy));
  const committed = await initializeRunStorage({ stateRoot, runId, policy, initialState, processMetadata });
  return { stateRoot, runId, policy, initialState, committed };
}

export async function removeTestRun(run: Pick<TestRun, "stateRoot">): Promise<void> {
  await rm(run.stateRoot, { recursive: true, force: true });
}

export function firstEvent(): TransitionEvent {
  return transitionEvent("FREEZE_OBJECTIVE");
}

export async function commitFirstTransition(
  run: TestRun,
  evidence: readonly { readonly bytes: Uint8Array; readonly mediaType: string }[] = [],
): Promise<CommittedRunState> {
  return commitTransition({
    stateRoot: run.stateRoot,
    runId: run.runId,
    expectedRevision: run.committed.statePointer.revision,
    expectedStatePointerContentSha256: run.committed.statePointer.content_sha256 as Sha256Digest,
    expectedWorkflowStateContentSha256: run.committed.workflowState.content_sha256 as Sha256Digest,
    transitionId: "transition-first",
    policy: run.policy,
    event: firstEvent(),
    evidence,
    processMetadata,
  });
}

export function errorCode(error: unknown): unknown {
  return error !== null && typeof error === "object" && "code" in error
    ? (error as { readonly code: unknown }).code
    : undefined;
}

export async function rejectsCode(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => errorCode(error) === code);
}

export function runDirectory(run: Pick<TestRun, "stateRoot" | "runId">): string {
  return join(run.stateRoot, "runs", run.runId);
}

export function contentPath(
  run: Pick<TestRun, "stateRoot" | "runId">,
  kind:
    | "evidence-metadata"
    | "evidence-manifests"
    | "workflow-states"
    | "transition-events"
    | "reducer-policies"
    | "process-assessments",
  digest: string,
): string {
  return join(runDirectory(run), "records", kind, `${digest.slice("sha256:".length)}.json`);
}

export function commitPath(run: Pick<TestRun, "stateRoot" | "runId">, digest: string): string {
  return join(runDirectory(run), "commits", `${digest.slice("sha256:".length)}.json`);
}

export function evidencePath(run: Pick<TestRun, "stateRoot" | "runId">, digest: string): string {
  return join(runDirectory(run), "evidence", "sha256", digest.slice("sha256:".length));
}

export async function writeCanonicalPrivateFile(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
  await writeFile(path, `${canonicalize(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}
