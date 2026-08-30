import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { main as staticApprovedDagCliMain } from "../src/cli/static-approved-dag.js";
import { inspectRunStorage, readM5ManagedRecords } from "../src/persistence/store.js";
import { inspectDeterministicResumeEligibility } from "../src/resume-inspection.js";
import { readOperatorStatus } from "../src/operator-status.js";
import { main as workflowCliMain } from "../src/cli/pi-workflow.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";
import {
  executeStaticApprovedDag,
  normalizeStaticApprovedDagLaunchSpec,
  staticApprovedDagSpecSha256,
} from "../src/static-approved-dag-launcher.js";
import {
  runBoundedMutationWorkflowExternalForTests,
  runBoundedMutationWorkflowForTests,
  type BoundedMutationAuthority,
  type BoundedMutationGoal,
  readPersistedStaticProviderTelemetry,
} from "../src/workflow-controller.js";

const execFileAsync = promisify(execFile);

/** Exact owner-frozen Ox dynamic-model execution authority (digest derived by the launcher). */
const OX_MODEL_EXECUTION_DEFINITION = {
  api: "openai-completions", base_url: "https://openrouter.ai/api/v1", canonicalization_id: "canonical-json-v1",
  compat: { supportsDeveloperRole: false, thinkingFormat: "openrouter" }, context_window: 1_048_576, headers: {},
  input: ["text", "image"], max_tokens: 131_072, model_id: "stealth/ox-alpha", provider_id: "openrouter",
  reasoning: true, schema_id: "pi_gacw_model_execution_definition_v1", thinking_level_map: "ABSENT",
} as const;
const OX_MODEL_DEFINITION_SHA256 = "sha256:106eb60535677cea92ae32ddf9f83176c1479035a2e49d140dcf5c82e8eadad6";

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "static-dag-retention-repo-"));
  await execFileAsync("git", ["init", "-q"], { cwd: root });
  await execFileAsync("git", ["config", "user.email", "retention@example.invalid"], { cwd: root });
  await execFileAsync("git", ["config", "user.name", "retention"], { cwd: root });
  await mkdir(join(root, "verify"));
  await writeFile(join(root, "verify", "a.mjs"), "process.exit(0);\n");
  await writeFile(join(root, "verify", "b.mjs"), "process.exit(0);\n");
  await execFileAsync("git", ["add", "verify"], { cwd: root });
  await execFileAsync("git", ["commit", "-qm", "initial"], { cwd: root });
  return root;
}

async function repositoryStatus(root: string): Promise<readonly string[]> {
  const status = await execFileAsync("git", ["status", "--porcelain"], { cwd: root });
  return status.stdout.trimEnd() === "" ? [] : status.stdout.trimEnd().split("\n");
}

async function assertClean(root: string): Promise<void> {
  assert.deepEqual(await repositoryStatus(root), []);
}

async function assertOnlyApprovedOutputs(root: string, outputs: readonly string[]): Promise<void> {
  assert.deepEqual(await repositoryStatus(root), outputs.map((path) => `?? ${path}`));
}

async function v2Spec(root: string): Promise<ReturnType<typeof normalizeStaticApprovedDagLaunchSpec>> {
  const [branch, head, tree] = await Promise.all([
    execFileAsync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root }).then((r) => r.stdout.trim()),
    execFileAsync("git", ["rev-parse", "HEAD"], { cwd: root }).then((r) => r.stdout.trim()),
    execFileAsync("git", ["write-tree"], { cwd: root }).then((r) => r.stdout.trim()),
  ]);
  const goal: BoundedMutationGoal = {
    objective: "Write exactly two retained-evidence outputs.", stop_condition: "Stop after deterministic verification.", execution_mode: "STATIC_APPROVED_DAG",
    scope: { readable_paths: ["a.txt", "b.txt", "verify"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["verify"] }, required_outputs: ["a.txt", "b.txt"],
    tasks: [
      { task_id: "retention-a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [], verification_command_ids: [] },
      { task_id: "retention-b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["retention-a"], verification_command_ids: [] },
    ],
  };
  const verifierReads = [{ path: "verify", kind: "PREFIX" as const }];
  return normalizeStaticApprovedDagLaunchSpec({
    spec_version: "static-approved-dag-launch-v2", run_label: "retention-regression", expected_repository_branch: branch, expected_head: head, expected_tree: tree,
    goal,
    verification_commands: [
      { command_id: "verify-a", executable: process.execPath, args: ["a.mjs"], cwd: "verify", timeout_ms: 60_000, readable_paths: verifierReads },
    ],
    static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
    expected_route: { logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false, model_execution_definition: OX_MODEL_EXECUTION_DEFINITION },
  });
}

async function launchV2(root: string, options?: { readonly retainedArtifactRoot?: string }): Promise<Awaited<ReturnType<typeof executeStaticApprovedDag>>> {
  const spec = await v2Spec(root);
  return executeStaticApprovedDag({
    spec: JSON.parse(JSON.stringify(spec)), approved_spec_sha256: staticApprovedDagSpecSha256(spec), cwd: root,
    controller: runBoundedMutationWorkflowForTests,
    ...(options?.retainedArtifactRoot === undefined ? {} : { retainedArtifactRoot: options.retainedArtifactRoot }),
  });
}

async function captureStdout<T>(action: () => Promise<T>): Promise<{ readonly result: T; readonly output: string }> {
  const stdout = process.stdout as unknown as { write(chunk: string | Uint8Array): boolean };
  const originalWrite = stdout.write; let output = "";
  stdout.write = (chunk) => { if (typeof chunk === "string") output += chunk; return true; };
  try { return { result: await action(), output }; }
  finally { stdout.write = originalWrite; }
}

test("CLI accepts exactly one absolute --retain-artifacts and forwards it to the launcher untouched", async () => {
  const directory = await mkdtemp(join(tmpdir(), "static-dag-retention-cli-"));
  const specPath = join(directory, "spec.json");
  await writeFile(specPath, "{}", "utf8");
  try {
    let calls = 0; let capturedRetainedArtifactRoot: string | undefined;
    const capturedRoot = "/safe/private/artifact-parent";
    const run = await captureStdout(() => staticApprovedDagCliMain(
      [specPath, "--approved-spec-sha256", `sha256:${"a".repeat(64)}`, "--retain-artifacts", capturedRoot],
      async (input) => {
        calls += 1;
        capturedRetainedArtifactRoot = input.retainedArtifactRoot;
        return { classification: "PASS", spec_sha256: null, run_label: null, reason: "PASS", workflow: null, evidence_root: `${capturedRoot}/pi-pre-m8-bounded-x`, hygiene_warning: null, telemetry: null } as any;
      },
    ));
    assert.equal(run.result, 0); assert.equal(calls, 1);
    assert.equal(capturedRetainedArtifactRoot, capturedRoot);
    assert.equal(JSON.parse(run.output).evidence_root, `${capturedRoot}/pi-pre-m8-bounded-x`);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("CLI rejects duplicate, valueless, relative, inspect-mode, and unknown retention arguments before any execution", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "static-dag-retention-cli-"));
  const specPath = join(directory, "spec.json");
  await writeFile(specPath, "{}", "utf8");
  try {
    const expectRejected = async (argv: readonly string[], pattern: RegExp): Promise<void> => {
      let calls = 0;
      const run = await captureStdout(() => staticApprovedDagCliMain([...argv], async () => { calls += 1; return {} as any; }));
      assert.equal(run.result, 2, argv.join(" ")); assert.equal(calls, 0, argv.join(" "));
      let reason = ""; try { reason = String(JSON.parse(run.output).reason); } catch { reason = run.output; }
      assert.match(reason, new RegExp(pattern.source, "u"), argv.join(" "));
      assert.equal(JSON.parse(run.output).classification, "INVALID", argv.join(" "));
    };
    const approved = ["--approved-spec-sha256", `sha256:${"a".repeat(64)}`];
    await t.test("duplicate --retain-artifacts rejects", () => expectRejected([specPath, ...approved, "--retain-artifacts", "/tmp/a", "--retain-artifacts", "/tmp/b"], /exactly one/));
    await t.test("missing --retain-artifacts value rejects", () => expectRejected([specPath, ...approved, "--retain-artifacts"], /requires an absolute directory value/));
    await t.test("relative --retain-artifacts value rejects", () => expectRejected([specPath, ...approved, "--retain-artifacts", "relative/evidence"], /absolute directory/));
    await t.test("inspect mode rejects --retain-artifacts", () => expectRejected(["inspect", specPath, "--retain-artifacts", "/tmp/a"], /inspection creates no productive workspace/));
    await t.test("unknown flags keep rejecting", () => expectRejected([specPath, ...approved, "--retain-artifacts-x", "/tmp/a"], /unknown launcher argument/));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("launcher propagates retainedArtifactRoot: PASS returns a unique surviving evidence workspace with readable bounded-worker records", async () => {
  const root = await repository();
  const parent = await mkdtemp(join(tmpdir(), "static-dag-retained-parent-"));
  try {
    let invocations = 0;
    configureBoundedWorkerFauxRuntimeForTests(() => ({
      async execute({ route, tools }) {
        invocations += 1;
        assert.deepEqual(route, { logicalRole: "CODING_EXECUTOR", providerId: "openrouter", modelId: "stealth/ox-alpha", effort: "high", modelDefinitionSha256: OX_MODEL_DEFINITION_SHA256 });
        const path = ["a.txt", "b.txt"][invocations - 1]!;
        await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
        tools.submitReport("retained mutation");
        return { completed: true, cleanupCertain: true, modelTurns: 3, providerRequests: 2, inputTokens: 11, outputTokens: 22, costMicrousd: 1234 };
      },
    }));
    const report = await (async () => {
      const spec = await v2Spec(root);
      const approved = staticApprovedDagSpecSha256(spec);
      return executeStaticApprovedDag({
        spec: JSON.parse(JSON.stringify(spec)), approved_spec_sha256: approved, cwd: root,
        controller: runBoundedMutationWorkflowForTests, retainedArtifactRoot: parent,
      });
    })();
    assert.equal(report.classification, "PASS", report.reason);
    assert.ok(typeof report.evidence_root === "string" && report.evidence_root.length > 0);
    const evidence = report.evidence_root!;
    // Exactly one unique child workspace was created beneath the operator parent.
    const entries = await readdir(parent);
    assert.deepEqual(entries, [basename(evidence)]);
    assert.match(basename(evidence), /^pi-pre-m8-bounded-/u);
    // Evidence physically remains after terminal settlement.
    const stats = await lstat(evidence);
    assert.equal(stats.isDirectory(), true);
    // Bounded-worker invocation and result records remain readable and bound together.
    assert.deepEqual(await inspectDeterministicResumeEligibility({ retainedRunRoot: evidence }), {
      classification: "RESUME_REFUSED", run_id: "pre-m8-bounded", phase: "PASS", resume_point: null, reason: "RESUME_REFUSED_TERMINAL",
    });
    const records = await readM5ManagedRecords({ stateRoot: join(evidence, "state"), runId: "pre-m8-bounded" });
    assert.equal(records.boundedWorkerInvocations.length, 2);
    assert.equal(records.boundedWorkerResults.length, 2);
    const invocationDigests = new Set(records.boundedWorkerInvocations.map((entry) => entry.content_sha256));
    for (const result of records.boundedWorkerResults) {
      assert.equal(result.outcome, "COMPLETED");
      assert.equal(invocationDigests.has(result.invocation_content_sha256), true, "every result binds a persisted invocation");
      assert.equal(result.actual_usage.worker_invocations, 1);
      assert.equal(result.actual_usage.model_turns, 3);
      assert.equal(result.actual_usage.provider_requests, 2);
      assert.equal(result.actual_usage.input_tokens, 11);
      assert.equal(result.actual_usage.output_tokens, 22);
      assert.equal(result.actual_usage.cost_microusd, 1234);
      assert.equal(result.cleanup_certain, true);
    }
    assert.notEqual(report.telemetry, null);
    assert.equal(report.telemetry!.source, "PERSISTED_AUTHORITATIVE_M5_USAGE_EVIDENCE");
    assert.equal(report.telemetry!.provider_request_scope, "LOGICAL_PI_PROVIDER_STREAM_DISPATCH_ONLY");
    assert.deepEqual(report.telemetry!.usage_evidence_content_sha256, records.usage.map((entry) => entry.content_sha256).sort());
    assert.equal(report.telemetry!.worker_invocation_count.value, 2);
    assert.equal(report.telemetry!.worker_invocation_count.basis, "VALIDATED");
    assert.equal(report.telemetry!.worker_invocation_count.enforcement_class, "HARD_ENFORCEABLE");
    assert.equal(report.telemetry!.model_turn_count.value, 6);
    assert.equal(report.telemetry!.model_turn_count.basis, "OBSERVED");
    assert.equal(report.telemetry!.model_turn_count.enforcement_class, "SOFT_ENFORCEABLE");
    assert.equal(report.telemetry!.provider_request_count.value, 4);
    assert.equal(report.telemetry!.provider_request_count.basis, "OBSERVED");
    assert.equal(report.telemetry!.provider_request_count.enforcement_class, "OBSERVABLE_ONLY");
    assert.equal(report.telemetry!.accepted_m4_tool_call_count.value, 2);
    assert.equal(report.telemetry!.accepted_m4_tool_call_count.enforcement_class, "HARD_ENFORCEABLE");
    for (const field of ["input_tokens", "output_tokens", "cached_tokens", "reasoning_tokens", "estimated_cost_microusd", "provider_reported_cost_microusd", "transport_attempt_count"] as const) {
      assert.equal(report.telemetry![field].value, null, `${field} stays unavailable`);
      assert.equal(report.telemetry![field].basis, "UNAVAILABLE", `${field} stays unavailable`);
      assert.equal(report.telemetry![field].enforcement_class, "UNAVAILABLE", `${field} stays unavailable`);
    }
    const finalInspection = await inspectRunStorage({ stateRoot: join(evidence, "state"), runId: "pre-m8-bounded" });
    const replayedTelemetry = await readPersistedStaticProviderTelemetry({ stateRoot: join(evidence, "state"), finalState: finalInspection.workflowState, outcome: "PASS" });
    assert.deepEqual(replayedTelemetry, report.telemetry, "replay reuses the persisted telemetry projection without a provider call");
    assert.equal(invocations, 2);
    assert.equal(report.workflow?.coding_worker_invocations, 2);
    await assertOnlyApprovedOutputs(root, ["a.txt", "b.txt"]);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});
test("VALID_BLOCKED report projects trusted persisted telemetry without transport claims", async () => {
  const root = await repository();
  const parent = await mkdtemp(join(tmpdir(), "static-dag-blocked-telemetry-parent-"));
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ tools }) {
      try {
        await tools.writePath({ path: "outside.txt", operation: "CREATE", replacementBytes: Buffer.from("outside\n"), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      } catch (error: unknown) {
        assert.match(error instanceof Error ? error.message : String(error), /outside task edit scope/u);
      }
      return { completed: false, cleanupCertain: true, modelTurns: null, providerRequests: null };
    },
  }));
  try {
    const report = await launchV2(root, { retainedArtifactRoot: parent });
    assert.equal(report.classification, "VALID_BLOCKED", report.reason);
    assert.notEqual(report.telemetry, null);
    assert.equal(report.telemetry!.worker_invocation_count.value, 1);
    assert.equal(report.telemetry!.model_turn_count.value, null);
    assert.equal(report.telemetry!.model_turn_count.basis, "UNAVAILABLE");
    assert.equal(report.telemetry!.provider_request_count.value, null);
    assert.equal(report.telemetry!.provider_request_count.basis, "UNAVAILABLE");
    assert.equal(report.telemetry!.provider_request_count.enforcement_class, "UNAVAILABLE");
    assert.equal(report.telemetry!.accepted_m4_tool_call_count.value, 0);
    assert.equal(report.telemetry!.transport_attempt_count.value, null);
    const evidence = report.evidence_root!;
    const records = await readM5ManagedRecords({ stateRoot: join(evidence, "state"), runId: "pre-m8-bounded" });
    assert.equal(records.usage.length, 1);
    assert.deepEqual(report.telemetry!.usage_evidence_content_sha256, records.usage.map((entry) => entry.content_sha256));
    assert.deepEqual(report.telemetry!.accepted_m4_tool_call_count.source_record_content_sha256, [records.boundedWorkerResults[0]!.content_sha256]);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("BLOCKED untrusted-refusal worker results stay diagnosable under retention (R8/R9 evidence contract)", async () => {
  const KNOWN = { modelTurns: 3, providerRequests: 2 } as const;
  const root = await repository();
  const parent = await mkdtemp(join(tmpdir(), "static-dag-blocked-parent-"));
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute() {
      return { completed: false, firstFailureCode: "TEST_RUNTIME_FAILURE", firstFailureStage: "TEST_RUNTIME", cleanupCertain: true, modelTurns: KNOWN.modelTurns, providerRequests: KNOWN.providerRequests };
    },
  }));
  try {
    const report = await launchV2(root, { retainedArtifactRoot: parent });
    assert.equal(report.classification, "VALID_BLOCKED");
    assert.match(report.reason, /^WORKER_AUTHORITY: BOUNDED_WORKER_UNTRUSTED_REFUSAL$/u);
    assert.ok(typeof report.evidence_root === "string");
    const evidence = report.evidence_root!;
    await lstat(evidence);
    assert.deepEqual(await inspectDeterministicResumeEligibility({ retainedRunRoot: evidence }), {
      classification: "RESUME_REFUSED", run_id: "pre-m8-bounded", phase: "BLOCKED", resume_point: null, reason: "RESUME_REFUSED_TERMINAL",
    });
    const records = await readM5ManagedRecords({ stateRoot: join(evidence, "state"), runId: "pre-m8-bounded" });
    assert.ok(records.boundedWorkerResults.length >= 1);
    const blocked = records.boundedWorkerResults.find((entry) => entry.outcome === "BLOCKED");
    assert.notEqual(blocked, undefined);
    assert.equal(blocked!.first_failure_code, "TEST_RUNTIME_FAILURE");
    assert.equal(blocked!.first_failure_stage, "TEST_RUNTIME");
    assert.equal(blocked!.actual_usage.worker_invocations, 1);
    assert.equal(blocked!.actual_usage.m4_tool_calls, 0);
    assert.equal(blocked!.actual_usage.model_turns, KNOWN.modelTurns);
    assert.equal(blocked!.actual_usage.provider_requests, KNOWN.providerRequests);
    assert.equal(blocked!.cleanup_certain, true);
    const invocation = records.boundedWorkerInvocations.find((entry) => entry.content_sha256 === blocked!.invocation_content_sha256);
    assert.notEqual(invocation, undefined, "blocked result keeps its exact invocation binding");
    assert.equal(report.workflow?.coding_worker_invocations, 1);
    await assertClean(root);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("default execution without --retain-artifacts keeps evidence_root null and existing cleanup semantics", async () => {
  const root = await repository();
  const prefix = "pi-pre-m8-bounded-";
  const snapshot = async (): Promise<Set<string>> => new Set((await readdir(tmpdir())).filter((entry) => entry.startsWith(prefix)));
  let invocations = 0;
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ tools }) {
      const path = ["a.txt", "b.txt"][invocations++]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("default cleanup mutation");
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  }));
  try {
    const spec = await v2Spec(root);
    const before = await snapshot();
    const report = await executeStaticApprovedDag({
      spec: JSON.parse(JSON.stringify(spec)), approved_spec_sha256: staticApprovedDagSpecSha256(spec), cwd: root,
      controller: runBoundedMutationWorkflowForTests,
    });
    assert.equal(report.classification, "PASS", report.reason);
    assert.equal(report.evidence_root, null);
    assert.notEqual(report.telemetry, null);
    assert.equal(report.telemetry!.worker_invocation_count.value, 2);
    assert.equal(report.telemetry!.model_turn_count.value, 0);
    assert.equal(report.telemetry!.provider_request_count.value, 0);
    assert.equal(report.telemetry!.provider_request_count.enforcement_class, "OBSERVABLE_ONLY");
    const after = await snapshot();
    assert.deepEqual([...after].filter((entry) => !before.has(entry)), [], "temporary invocation evidence is removed after settled execution");
    await assertOnlyApprovedOutputs(root, ["a.txt", "b.txt"]);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(root, { recursive: true, force: true });
  }
});

test("the controller rejects unsafe retained-artifact parents through the launcher before any worker admission", async (t) => {
  const cases: readonly (readonly [string, (context: { readonly root: string; readonly base: string }) => Promise<string>])[] = [
    ["missing parent", async ({ base }) => join(base, "does-not-exist")],
    ["parent is a file", async ({ base }) => { const path = join(base, "plain-file"); await writeFile(path, "not a directory\n"); return path; }],
    ["parent is a symlink", async ({ base }) => { const real = join(base, "real-dir"); await mkdir(real, { mode: 0o700 }); const link = join(base, "linked-dir"); await symlink(real, link); return link; }],
    ["group/world writable parent", async ({ base }) => { const path = join(base, "loose-dir"); await mkdir(path, { mode: 0o700 }); await chmod(path, 0o777); return path; }],
    ["parent overlaps the repository", async ({ root }) => join(root, "verify")],
    ["parent contains the repository", async ({ root }) => dirname(root)],
  ];
  for (const [label, build] of cases) {
    await t.test(label, async () => {
      const root = await repository();
      const base = await mkdtemp(join(tmpdir(), "static-dag-retention-guard-"));
      let workerEntries = 0;
      configureBoundedWorkerFauxRuntimeForTests(() => ({ async execute() { workerEntries += 1; return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 }; } }));
      try {
        const retainedArtifactRoot = await build({ root, base });
        const report = await launchV2(root, { retainedArtifactRoot });
        assert.equal(report.classification, "INVALID");
        assert.match(report.reason, /RETAINED_ARTIFACT_ROOT_INVALID/u);
        assert.equal(workerEntries, 0);
        assert.equal(report.evidence_root, null);
        await assertClean(root);
      } finally {
        configureBoundedWorkerFauxRuntimeForTests(undefined);
        await rm(base, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
      }
    });
  }
});

test("provider-free R9-shaped blocked run crosses the real external lifecycle and preserves exact retained evidence", async () => {
  const root = await repository();
  const parent = await mkdtemp(join(tmpdir(), "static-dag-lifecycle-parent-"));
  try {
    const spec = await v2Spec(root);
    assert.deepEqual(spec.expected_route, {
      logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false,
      model_execution_definition: OX_MODEL_EXECUTION_DEFINITION,
    });
    const approved = staticApprovedDagSpecSha256(spec);
    const report = await executeStaticApprovedDag({
      spec: JSON.parse(JSON.stringify(spec)), approved_spec_sha256: approved, cwd: root, retainedArtifactRoot: parent,
      controller: (value, options) => runBoundedMutationWorkflowExternalForTests(value, options, "STATIC_DAG_BLOCKED"),
    });
    assert.equal(report.classification, "VALID_BLOCKED");
    assert.match(report.reason, /^WORKER_AUTHORITY: BOUNDED_WORKER_UNTRUSTED_REFUSAL; BLOCKED_EXTERNAL_COMPLETION_RECONCILIATION:M2=.*;M3=UNCHANGED_CLEAN:/u);
    assert.equal(report.spec_sha256, approved);
    assert.equal(report.workflow?.coding_worker_invocations, 1);
    assert.ok(typeof report.evidence_root === "string");
    const evidence = report.evidence_root!;
    assert.deepEqual(await readdir(parent), [basename(evidence)]);
    assert.match(basename(evidence), /^pi-pre-m8-bounded-/u);
    await lstat(evidence);
    const records = await readM5ManagedRecords({ stateRoot: join(evidence, "state"), runId: "pre-m8-bounded" });
    assert.equal(records.boundedWorkerInvocations.length, 1);
    assert.equal(records.boundedWorkerResults.length, 1);
    const blocked = records.boundedWorkerResults[0]!;
    assert.equal(blocked.outcome, "BLOCKED");
    assert.equal(blocked.first_failure_code, "TEST_RUNTIME_FAILURE");
    assert.equal(blocked.first_failure_stage, "TEST_RUNTIME");
    assert.equal(blocked.cleanup_certain, true);
    assert.equal(blocked.actual_usage.worker_invocations, 1);
    assert.equal(blocked.actual_usage.m4_tool_calls, 0);
    assert.equal(blocked.actual_usage.model_turns, 3);
    // Faux-runtime observation only; no real provider request occurred.
    assert.equal(blocked.actual_usage.provider_requests, 0);
    assert.equal(blocked.invocation_content_sha256, records.boundedWorkerInvocations[0]!.content_sha256);
    await assertClean(root);
  } finally {
    await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("external lifecycle default cleanup removes temporary evidence when retention is not requested", async () => {
  const root = await repository();
  let workspaceRoot: string | null = null;
  try {
    const goal: BoundedMutationGoal = {
      objective: "Apply the frozen cleanup edit objective.", stop_condition: "Stop at deterministic acceptance.", execution_mode: "DIRECT_LUNA_HIGH",
      scope: { readable_paths: ["verify", "verify/a.mjs"], editable_paths: ["out.txt"], frozen_paths: [] }, required_outputs: ["out.txt"],
    };
    const authority: BoundedMutationAuthority = { verification_commands: [{ command_id: "cleanup-verify", executable: "/usr/bin/true", cwd: "verify", timeout_ms: 10_000 }] };
    const result = await runBoundedMutationWorkflowExternalForTests(goal, {
      cwd: root, authority,
      approveTasks: async ({ contract }) => contract.content_sha256 as `sha256:${string}`,
      onControlCapability: ({ path }) => { workspaceRoot = dirname(path); },
    }, "COMPLETE");
    assert.equal(result.outcome, "PASS", result.reason);
    assert.equal(result.evidenceRoot, undefined);
    assert.notEqual(workspaceRoot, null);
    await assert.rejects(lstat(workspaceRoot!), (error: unknown) => (error as { readonly code?: string }).code === "ENOENT", "settled non-retained workspace is physically removed");
    await assertOnlyApprovedOutputs(root, ["out.txt"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});


test("pi-workflow status reconstructs a retained PASS from persisted authority in a fresh process", async () => {
  const root = await repository();
  const parent = await mkdtemp(join(tmpdir(), "operator-status-pass-parent-"));
  let invocations = 0;
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ tools }) {
      invocations += 1;
      const path = invocations === 1 ? "a.txt" : "b.txt";
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("operator status pass");
      return { completed: true, cleanupCertain: true, modelTurns: 3, providerRequests: 2, inputTokens: 11, outputTokens: 22, costMicrousd: 1234 };
    },
  }));
  try {
    const report = await launchV2(root, { retainedArtifactRoot: parent });
    assert.equal(report.classification, "PASS", report.reason);
    const evidence = report.evidence_root!;
    const before = (await readdir(evidence, { recursive: true })).sort();
    const status = await readOperatorStatus(evidence);
    const repeated = await readOperatorStatus(evidence);
    assert.deepEqual(repeated, status);
    assert.equal(status.classification, "PASS");
    assert.equal(status.storage_status, "HEALTHY");
    assert.equal(status.run_id, "pre-m8-bounded");
    assert.equal(status.phase, "PASS");
    assert.equal(status.terminal_classification, "PASS");
    assert.equal(status.terminal, true);
    assert.deepEqual(status.completion, { completed: true, outcome: "PASS" });
    assert.deepEqual(status.operator_input, { required: false, kind: null });
    assert.equal(status.notice?.kind, "COMPLETION");
    assert.deepEqual(status.telemetry, report.telemetry);
    assert.deepEqual((await readdir(evidence, { recursive: true })).sort(), before, "status reads do not change retained evidence");

    const fresh = await execFileAsync(process.execPath, [join(process.cwd(), "dist", "src", "cli", "pi-workflow.js"), "status", evidence], {
      cwd: process.cwd(), env: { ...process.env, REAL_PROVIDER_RUNS: "0" },
    });
    assert.deepEqual(JSON.parse(fresh.stdout), status, "fresh status process uses persisted evidence rather than runtime memory");
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("operator status reconstructs VALID_BLOCKED and preserves unavailable telemetry fields", async () => {
  const root = await repository();
  const parent = await mkdtemp(join(tmpdir(), "operator-status-blocked-parent-"));
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute() {
      return { completed: false, firstFailureCode: "TEST_RUNTIME_FAILURE", firstFailureStage: "TEST_RUNTIME", cleanupCertain: true, modelTurns: null, providerRequests: null };
    },
  }));
  try {
    const report = await launchV2(root, { retainedArtifactRoot: parent });
    assert.equal(report.classification, "VALID_BLOCKED", report.reason);
    const status = await readOperatorStatus(report.evidence_root!);
    assert.equal(status.classification, "VALID_BLOCKED");
    assert.equal(status.phase, "BLOCKED");
    assert.equal(status.terminal_classification, "VALID_BLOCKED");
    assert.equal(status.terminal, true);
    assert.deepEqual(status.completion, { completed: true, outcome: "BLOCKED" });
    assert.equal(status.notice?.kind, "UNRECOVERABLE_BLOCK");
    assert.deepEqual(status.telemetry, report.telemetry);
    if (status.telemetry !== null) {
      assert.equal(status.telemetry.model_turn_count.value, null);
      assert.equal(status.telemetry.model_turn_count.basis, "UNAVAILABLE");
      assert.equal(status.telemetry.provider_request_count.value, null);
      assert.equal(status.telemetry.provider_request_count.enforcement_class, "UNAVAILABLE");
      for (const field of ["input_tokens", "output_tokens", "cached_tokens", "reasoning_tokens", "estimated_cost_microusd", "provider_reported_cost_microusd", "transport_attempt_count"] as const) {
        assert.equal(status.telemetry[field].value, null, `${field} remains unavailable`);
        assert.equal(status.telemetry[field].basis, "UNAVAILABLE", `${field} remains unavailable`);
      }
    }
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined);
    await rm(parent, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});

test("status CLI preserves the read-only invalid/incomplete distinction", async () => {
  const missing = await readOperatorStatus(join(tmpdir(), "operator-status-does-not-exist"));
  assert.equal(missing.classification, "INVALID");
  assert.equal(missing.storage_status, "UNAVAILABLE");
  const root = await mkdtemp(join(tmpdir(), "operator-status-incomplete-"));
  try {
    await mkdir(join(root, "state"), { recursive: true, mode: 0o700 });
    await mkdir(join(root, "state", "runs"), { recursive: true, mode: 0o700 });
    await mkdir(join(root, "state", "runs", "run"), { recursive: true, mode: 0o700 });
    const first = await captureStdout(() => workflowCliMain(["status", root]));
    assert.equal(first.result, 3);
    assert.equal(JSON.parse(first.output).classification, "INCOMPLETE");
    const output = await readOperatorStatus(root);
    assert.equal(output.classification, "INCOMPLETE");
    assert.equal(output.storage_status, "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY");
    assert.equal(output.phase, null);
    assert.equal(output.telemetry, null);
    assert.equal(output.notice, null);
  } finally { await rm(root, { recursive: true, force: true }); }
});
