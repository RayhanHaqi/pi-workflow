import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  executeStaticApprovedDag,
  normalizeStaticApprovedDagLaunchSpec,
  staticApprovedDagSpecSha256,
} from "../src/static-approved-dag-launcher.js";
import { resolveRepositoryIdentity } from "../src/repository/identity.js";
import { canonicalPathRuleUnion, validatePathRules } from "../src/secure-fs/path.js";
import { probeM4Capabilities } from "../src/secure-fs/capabilities.js";
import { runSandboxedCommand } from "../src/scoped-tools/sandbox.js";
import type { M4PathRule } from "../src/schemas/index.js";
import { configureBoundedWorkerFauxRuntimeForTests } from "../src/pi-adapter/bounded-worker.js";
import { sha256Canonical } from "../src/identity/index.js";
import {
  freezeControllerVerificationCommandsForTests,
  runBoundedMutationWorkflowForTests,
  scopedToolPolicyForTests,
  type BoundedMutationGoal,
} from "../src/workflow-controller.js";

const exec = promisify(execFile);

const rule = (path: string, kind: "EXACT" | "PREFIX"): M4PathRule => ({ path, kind });
const sortRules = (rules: readonly M4PathRule[]): readonly M4PathRule[] =>
  [...rules].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : a.kind < b.kind ? -1 : 1);

test("canonical path-rule union reduces every coverage shape deterministically and stays validatePathRules-clean", () => {
  const cases: readonly { readonly input: readonly M4PathRule[]; readonly expected: readonly M4PathRule[] }[] = [
    { input: [rule("a", "EXACT"), rule("a", "EXACT")], expected: [rule("a", "EXACT")] },
    { input: [rule("a", "PREFIX"), rule("a", "PREFIX")], expected: [rule("a", "PREFIX")] },
    { input: [rule("a", "PREFIX"), rule("a/b", "EXACT")], expected: [rule("a", "PREFIX")] },
    { input: [rule("a", "PREFIX"), rule("a/b", "PREFIX")], expected: [rule("a", "PREFIX")] },
    { input: [rule("a", "EXACT"), rule("a", "PREFIX")], expected: [rule("a", "PREFIX")] },
    { input: [rule("a", "EXACT"), rule("a/b", "EXACT")], expected: [rule("a", "EXACT"), rule("a/b", "EXACT")] },
    { input: [rule("a/b", "PREFIX"), rule("a", "PREFIX")], expected: [rule("a", "PREFIX")] },
    { input: [rule("a", "PREFIX"), rule("b", "PREFIX")], expected: [rule("a", "PREFIX"), rule("b", "PREFIX")] },
    // Sibling descendants on different branches are both absorbed by the outer prefix.
    { input: [rule("a", "PREFIX"), rule("a/b", "EXACT"), rule("a/c", "EXACT")], expected: [rule("a", "PREFIX")] },
    // A PREFIX elsewhere never absorbs an unrelated exact file sharing only a basename.
    { input: [rule("x/a", "PREFIX"), rule("y/a", "EXACT")], expected: [rule("x/a", "PREFIX"), rule("y/a", "EXACT")] },
  ];
  for (const { input, expected } of cases) {
    const forward = canonicalPathRuleUnion(input);
    const backward = canonicalPathRuleUnion([...input].reverse());
    assert.deepEqual(forward, sortRules(expected));
    assert.deepEqual(backward, forward, "result must be independent of input ordering");
    assert.doesNotThrow(() => validatePathRules(JSON.parse(JSON.stringify(forward)), "union"), JSON.stringify({ input, forward }));
  }
});

/** Temporary repository whose verifier authority mirrors the frozen R7 V01/V02 rule shapes. */
async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "command-union-r8-"));
  await exec("git", ["init", "-q"], { cwd: root });
  await exec("git", ["config", "user.email", "union-repair@example.invalid"], { cwd: root });
  await exec("git", ["config", "user.name", "union-repair"], { cwd: root });
  await mkdir(join(root, "node_modules", "verifier"), { recursive: true });
  await mkdir(join(root, "src"), { recursive: true });
  await mkdir(join(root, "tests"), { recursive: true });
  await writeFile(join(root, "package.json"), "{}\n");
  await writeFile(join(root, "tsconfig.json"), "{}\n");
  await writeFile(join(root, "src", "index.ts"), "export const value = 1;\n");
  await writeFile(join(root, "tests", "other.txt"), "prefix readable\n");
  await writeFile(join(root, "tests", "canonical-json-json-text.test.ts"), "exact readable\n");
  await writeFile(join(root, "node_modules", "verifier", "package.json"), "{\"private\":true}\n");
  await writeFile(join(root, "node_modules", "verifier", "v01.mjs"),
    `import { readFileSync } from "node:fs";\nreadFileSync("../tests/other.txt", "utf8");\nconsole.log("V01_PREFIX_OK");\n`);
  await writeFile(join(root, "node_modules", "verifier", "v02.mjs"),
    `import { readFileSync } from "node:fs";\nconst result = {};\ntry { result.approved = readFileSync("../tests/canonical-json-json-text.test.ts", "utf8").length; } catch (error) { result.approved = error.code; }\ntry { readFileSync("../tests/other.txt", "utf8"); result.broad = "ESCAPED"; } catch (error) { result.broad = error.code; }\nconsole.log(JSON.stringify(result));\n`);
  await exec("git", ["add", "node_modules", "src", "tests", "package.json", "tsconfig.json"], { cwd: root });
  await exec("git", ["commit", "-qm", "r7-shaped verifier authority fixture"], { cwd: root });
  return root;
}

const V01_READS: readonly M4PathRule[] = [rule("node_modules", "PREFIX"), rule("package.json", "EXACT"), rule("src", "PREFIX"), rule("tests", "PREFIX"), rule("tsconfig.json", "EXACT")];
const V02_READS: readonly M4PathRule[] = [rule("node_modules", "PREFIX"), rule("package.json", "EXACT"), rule("src", "PREFIX"), rule("tests/canonical-json-json-text.test.ts", "EXACT"), rule("tsconfig.json", "EXACT")];

const verificationCommands = [
  { command_id: "V01", executable: process.execPath, args: ["verifier/v01.mjs"], cwd: "node_modules", timeout_ms: 60_000, readable_paths: V01_READS },
  { command_id: "V02", executable: process.execPath, args: ["verifier/v02.mjs"], cwd: "node_modules", timeout_ms: 60_000, readable_paths: V02_READS },
];

const goal: BoundedMutationGoal = {
  objective: "Write exactly two integrated outputs.", stop_condition: "Stop after deterministic verification.", execution_mode: "STATIC_APPROVED_DAG",
  scope: { readable_paths: ["a.txt", "b.txt", "node_modules", "src", "tests", "package.json", "tsconfig.json"], editable_paths: ["a.txt", "b.txt"], frozen_paths: ["node_modules"] },
  required_outputs: ["a.txt", "b.txt"],
  tasks: [
    { task_id: "task-a", objective: "Write a.", editable_paths: ["a.txt"], required_outputs: ["a.txt"], dependencies: [] },
    { task_id: "task-b", objective: "Write b.", editable_paths: ["b.txt"], required_outputs: ["b.txt"], dependencies: ["task-a"] },
  ],
};

async function r7ShapedSpec(root: string): Promise<ReturnType<typeof normalizeStaticApprovedDagLaunchSpec>> {
  const [branch, head, tree] = await Promise.all([
    exec("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root }).then((r) => r.stdout.trim()),
    exec("git", ["rev-parse", "HEAD"], { cwd: root }).then((r) => r.stdout.trim()),
    exec("git", ["write-tree"], { cwd: root }).then((r) => r.stdout.trim()),
  ]);
  return normalizeStaticApprovedDagLaunchSpec({
    spec_version: "static-approved-dag-launch-v2", run_label: "r7-overlap-regression", expected_repository_branch: branch, expected_head: head, expected_tree: tree,
    goal, verification_commands: verificationCommands,
    static_time_budgets: { worker_deadline_ms: 300_000, node_wall_ms: 600_000, workflow_wall_ms: 1_800_000 }, static_max_attempts_per_leaf: 1,
    expected_route: { logical_role: "CODING_EXECUTOR", provider_id: "openrouter", model_id: "stealth/ox-alpha", effort: "high", fallback: false },
  });
}

test("real-controller full preflight accepts the exact R7 overlap shape and the aggregate envelope is the canonical union", async () => {
  const root = await fixture(); let workerInvocations = 0;
  configureBoundedWorkerFauxRuntimeForTests(() => ({
    async execute({ tools }) {
      workerInvocations += 1;
      const path = ["a.txt", "b.txt"][workerInvocations - 1]!;
      await tools.writePath({ path, operation: "CREATE", replacementBytes: Buffer.from(`${path}\n`), expectedPreimageExists: false, expectedPreimageDigest: null, expectedPreimageSize: null, expectedPreimageMode: null });
      tools.submitReport("r7 overlap regression mutation");
      return { completed: true, cleanupCertain: true, modelTurns: 0, providerRequests: 0 };
    },
  }));
  try {
    // Aggregate envelope seam over the SAME production constructor with the SAME R7-shaped commands,
    // captured before the workflow mutates the fixture worktree.
    const repository = await resolveRepositoryIdentity({ requestedPath: root, requireHead: true });
    const specs = await freezeControllerVerificationCommandsForTests(repository, verificationCommands, goal.scope);
    const policy = await scopedToolPolicyForTests(repository, sha256Canonical("task-scope-identity-seam"), goal, specs);
    // Canonical semantic union: tests:PREFIX survives because V01 legitimately owns it;
    // the descendant EXACT contributed by V02 is absorbed and must not appear redundantly.
    assert.deepEqual(policy.command_readable_paths, [
      rule("node_modules", "PREFIX"), rule("package.json", "EXACT"), rule("src", "PREFIX"), rule("tests", "PREFIX"), rule("tsconfig.json", "EXACT"),
    ]);
    assert.ok(!policy.command_readable_paths.some((entry) => entry.path === "tests/canonical-json-json-text.test.ts"));
    assert.doesNotThrow(() => validatePathRules(policy.command_readable_paths, "aggregate command_readable_paths"));

    // Per-command verifier authority is unchanged: no widening, no shrinking.
    assert.deepEqual(specs.find((s) => s.command_id === "V01")!.read_paths, sortRules(V01_READS));
    assert.deepEqual(specs.find((s) => s.command_id === "V02")!.read_paths, sortRules(V02_READS));

    // Worker read scope remains exactly the frozen goal projection; verifiers never widen it.
    const workerExpected: readonly M4PathRule[] = [
      rule("a.txt", "EXACT"), rule("b.txt", "EXACT"), rule("node_modules", "PREFIX"), rule("package.json", "EXACT"),
      rule("src", "PREFIX"), rule("tests", "PREFIX"), rule("tsconfig.json", "EXACT"),
    ];
    assert.deepEqual(policy.readable_paths, sortRules(workerExpected));

    // Full production path through the REAL controller: commandSpecs -> toolPolicy -> gateway admission
    // (validateToolPolicy) -> faux worker execution -> sandboxed verifiers. Zero provider generation.
    const spec = await r7ShapedSpec(root);
    const result = await executeStaticApprovedDag({
      spec: JSON.parse(JSON.stringify(spec)), approved_spec_sha256: staticApprovedDagSpecSha256(spec), cwd: root,
      controller: runBoundedMutationWorkflowForTests,
    });
    assert.equal(result.classification, "PASS", `${result.classification}: ${result.reason}`);
    assert.equal(result.workflow?.outcome, "PASS");
    assert.equal(result.workflow?.coding_worker_invocations, 2);
    assert.equal(workerInvocations, 2);
  } finally {
    configureBoundedWorkerFauxRuntimeForTests(undefined); await rm(root, { recursive: true, force: true });
  }
});

test("V02 executes in the production sandbox with only its exact test-file authority while V01 keeps prefix reads", async () => {
  const root = await fixture();
  const temporaryRoot = await mkdtemp(join(tmpdir(), "command-union-sandbox-")); await chmod(temporaryRoot, 0o700);
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: root, requireHead: true });
    const [v01, v02] = await freezeControllerVerificationCommandsForTests(repository, verificationCommands, goal.scope);
    const capability = (await probeM4Capabilities()).sandbox;
    const v01Outcome = await runSandboxedCommand(repository, temporaryRoot, capability, v01!);
    assert.equal(v01Outcome.exitCode, 0, JSON.stringify({ stderr: v01Outcome.stderr.toString() }));
    assert.equal(v01Outcome.stdout.toString(), "V01_PREFIX_OK\n");
    const v02Outcome = await runSandboxedCommand(repository, temporaryRoot, capability, v02!);
    assert.equal(v02Outcome.exitCode, 0, JSON.stringify({ stderr: v02Outcome.stderr.toString() }));
    const observed = JSON.parse(v02Outcome.stdout.toString()) as Record<string, unknown>;
    const expectedLength = (await readFile(join(root, "tests", "canonical-json-json-text.test.ts"), "utf8")).length;
    assert.equal(observed["approved"], expectedLength, "V02 reads exactly its declared EXACT test file");
    assert.equal(observed["broad"], "EACCES", "V02 must NOT inherit tests:PREFIX from the aggregate envelope or V01");
    assert.equal(v02Outcome.setup?.networkDenied, true);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true }); await rm(root, { recursive: true, force: true });
  }
});
