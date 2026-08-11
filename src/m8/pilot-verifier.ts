import { execFile } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { assertSha256Digest, sha256Bytes, sha256Canonical, type Sha256Digest } from "../identity/index.js";
import { resolveRepositoryIdentity } from "../repository/index.js";
import { captureGitState } from "../repository/fingerprint.js";
import { semanticFixtureIdentity, type M8Scenario, type MaterializedM8Fixture, type M8Terminal } from "./pilot-harness.js";

const execFileAsync = promisify(execFile);

/** Derived only by the retained M2–M5 resolver in the harness publication path. */
export interface M8AuthoritativeCommandEvidence {
  readonly command_id: string;
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly exit_code: number | null;
  readonly command_spec_identity: Sha256Digest;
  readonly m4_result_identity: Sha256Digest;
}

/**
 * This structure is a verifier input, not a publication API. Production obtains
 * it only by resolving registered actual-run durable evidence.
 */
export interface M8AuthoritativeWorkflowEvidence {
  readonly run_id: string;
  readonly execution_authority_digest: Sha256Digest;
  readonly terminal_workflow_result: M8Terminal | null;
  readonly terminal_evidence_identity: Sha256Digest | null;
  readonly final_postflight_identity: Sha256Digest | null;
  readonly final_repository_identity: Sha256Digest | null;
  readonly final_git_fingerprint_identity: Sha256Digest | null;
  readonly authority_evidence_identities: readonly Sha256Digest[];
  readonly command_results: readonly M8AuthoritativeCommandEvidence[];
  readonly budget?: Readonly<{
    readonly hard_mutation_tool_limit: number;
    readonly accepted_productive_mutations: number;
    readonly second_productive_mutation_rejected: boolean;
    readonly productive_continuation_after_exhaustion: boolean;
    readonly evidence_identities: readonly Sha256Digest[];
  }>;
  readonly scope?: Readonly<{
    readonly required_objective_unsatisfied: boolean;
    readonly scope_refusal_observed: boolean;
    readonly evidence_identities: readonly Sha256Digest[];
  }>;
}

export interface M8BlindVerifierInput {
  readonly scenario: M8Scenario;
  readonly initial: Pick<MaterializedM8Fixture, "semanticFixtureIdentity" | "initialGitTree" | "initialStatusIdentity" | "dirtyOverlayIdentity" | "initialStateIdentity">;
  readonly finalRoot: string;
  readonly authoritativeEvidence: M8AuthoritativeWorkflowEvidence;
  /** Binding values come from the frozen invocation arm/evidence manifest. */
  readonly expectedRunId: string;
  readonly expectedExecutionAuthorityDigest: Sha256Digest;
  /** Deliberately ignored narrative and benchmark metadata. */
  readonly workerProse?: unknown;
  readonly plannerProse?: unknown;
  readonly reviewerProse?: unknown;
  readonly modelMetadata?: unknown;
  readonly routeMetadata?: unknown;
  readonly modeMetadata?: unknown;
  readonly usageMetadata?: unknown;
}

export interface M8BlindVerifierResult {
  readonly task_success: boolean;
  readonly workflow_correctness: boolean;
  readonly pilot_validity: boolean;
  readonly verifier_identity: Sha256Digest;
  readonly checks: readonly string[];
}

type FileState = Readonly<{ readonly path: string; readonly mode: number; readonly bytes_sha256: Sha256Digest }>;

function same<T>(left: readonly T[], right: readonly T[]): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function child(root: string, path: string): string { return join(root, path); }
function validDigest(value: unknown): value is Sha256Digest {
  try { assertSha256Digest(value, "M8 evidence identity"); return true; }
  catch { return false; }
}
function validUniqueDigests(values: readonly Sha256Digest[]): boolean {
  return values.length > 0 && new Set(values).size === values.length && values.every((value) => validDigest(value));
}
async function fileEquals(root: string, path: string, mode: number, bytes: string): Promise<boolean> {
  try {
    const [actual, stat] = await Promise.all([readFile(child(root, path)), lstat(child(root, path))]);
    return actual.equals(Buffer.from(bytes, "base64")) && (stat.mode & 0o777) === mode && !stat.isSymbolicLink();
  } catch { return false; }
}
async function statusPaths(root: string): Promise<readonly string[] | null> {
  try {
    const output = (await execFileAsync("git", ["status", "--porcelain=v1", "-z"], { cwd: root, encoding: "buffer", maxBuffer: 1_048_576 })).stdout;
    const fields = Buffer.from(output).toString("utf8").split("\0").filter(Boolean); const paths: string[] = [];
    for (const field of fields) { if (field.length < 4) return null; paths.push(field.slice(3)); }
    return Object.freeze(paths.sort());
  } catch { return null; }
}
async function manifest(root: string, paths: readonly string[]): Promise<readonly FileState[] | null> {
  try {
    return Object.freeze(await Promise.all([...paths].sort().map(async (path) => {
      const [bytes, stat] = await Promise.all([readFile(child(root, path)), lstat(child(root, path))]);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("not regular");
      return Object.freeze({ path, mode: stat.mode & 0o777, bytes_sha256: sha256Bytes(bytes) });
    })));
  } catch { return null; }
}
function commandFact(scenario: M8Scenario) { return scenario.acceptance_facts.find((fact): fact is Extract<typeof fact, { readonly type: "required_command_result" }> => fact.type === "required_command_result"); }
function terminalFact(scenario: M8Scenario) { return scenario.acceptance_facts.find((fact): fact is Extract<typeof fact, { readonly type: "expected_terminal" }> => fact.type === "expected_terminal"); }

/** Binds the current physical workspace to the final durable M3 postflight. */
async function finalPostflightMatches(root: string, evidence: M8AuthoritativeWorkflowEvidence): Promise<boolean> {
  if (evidence.final_postflight_identity === null || evidence.final_repository_identity === null || evidence.final_git_fingerprint_identity === null ||
      !validDigest(evidence.final_postflight_identity) || !validDigest(evidence.final_repository_identity) || !validDigest(evidence.final_git_fingerprint_identity)) return false;
  try {
    const repository = await resolveRepositoryIdentity({ requestedPath: root, requireHead: true });
    if (repository.content_sha256 !== evidence.final_repository_identity) return false;
    return (await captureGitState(repository)).content_sha256 === evidence.final_git_fingerprint_identity;
  } catch { return false; }
}

/**
 * Deliberately blind to model, route, mode, cost, token, and narrative fields.
 * It consumes facts resolved from actual durable M2/M3/M4/M5/controller records.
 */
export async function verifyM8PilotBlindly(input: M8BlindVerifierInput): Promise<M8BlindVerifierResult> {
  const checks: string[] = [];
  const evidence = input.authoritativeEvidence; const expectedCommand = commandFact(input.scenario); const expectedTerminal = terminalFact(input.scenario);
  const semantic = input.initial.semanticFixtureIdentity === semanticFixtureIdentity(input.scenario);
  const expectedOverlay = input.scenario.approved_dirty_overlay === null ? null : sha256Canonical({ protocol: "m8-dirty-overlay-v1", files: input.scenario.approved_dirty_overlay });
  const overlayIdentity = input.initial.dirtyOverlayIdentity === expectedOverlay;
  const authorityBinding = evidence.run_id === input.expectedRunId && evidence.execution_authority_digest === input.expectedExecutionAuthorityDigest &&
    evidence.terminal_workflow_result !== null && evidence.terminal_evidence_identity !== null && validDigest(evidence.terminal_evidence_identity) &&
    validUniqueDigests(evidence.authority_evidence_identities);
  checks.push(semantic ? "semantic-fixture-identity" : "semantic-fixture-identity-mismatch");
  checks.push(overlayIdentity ? "dirty-overlay-identity" : "dirty-overlay-identity-mismatch");
  checks.push(authorityBinding ? "authoritative-run-binding" : "authoritative-run-binding-mismatch");

  const allFixtureFiles = [...input.scenario.initial_files, ...(input.scenario.approved_dirty_overlay ?? [])];
  const finalManifest = await manifest(input.finalRoot, allFixtureFiles.map((file) => file.path));
  const status = await statusPaths(input.finalRoot);
  const manifestIdentity = finalManifest === null ? null : sha256Canonical({ protocol: "m8-final-file-status-manifest-v1", files: finalManifest, status_paths: status });
  // Capture both before and after file checks so a concurrent changed final
  // workspace cannot be paired with a stale M3 postflight identity.
  const postflightBefore = await finalPostflightMatches(input.finalRoot, evidence);

  let filesCorrect = finalManifest !== null;
  for (const fact of input.scenario.acceptance_facts) if (fact.type === "expected_final_file" || fact.type === "frozen_file") {
    if (!await fileEquals(input.finalRoot, fact.path, fact.mode, fact.bytes_base64)) filesCorrect = false;
  }
  const overlays = input.scenario.acceptance_facts.filter((fact): fact is Extract<typeof fact, { readonly type: "approved_dirty_overlay" }> => fact.type === "approved_dirty_overlay");
  let overlayPreserved = true;
  for (const overlay of overlays) if (!await fileEquals(input.finalRoot, overlay.path, overlay.mode, overlay.bytes_base64)) overlayPreserved = false;

  const initialByPath = new Map(input.scenario.initial_files.map((file) => [file.path, file]));
  const overlayPaths = new Set((input.scenario.approved_dirty_overlay ?? []).map((file) => file.path));
  const workflowChanged: string[] = [];
  for (const file of input.scenario.initial_files) if (!await fileEquals(input.finalRoot, file.path, file.mode, file.bytes_base64)) workflowChanged.push(file.path);
  if (status !== null) for (const path of status) if (!initialByPath.has(path) && !overlayPaths.has(path) && ![...overlayPaths].some((overlay) => overlay.startsWith(path))) workflowChanged.push(path);
  workflowChanged.sort();
  const allowed = input.scenario.acceptance_facts.filter((fact): fact is Extract<typeof fact, { readonly type: "allowed_changed_path" }> => fact.type === "allowed_changed_path").map((fact) => fact.path).sort();
  const required = input.scenario.acceptance_facts.filter((fact): fact is Extract<typeof fact, { readonly type: "required_changed_path" }> => fact.type === "required_changed_path").map((fact) => fact.path).sort();
  const pathsCorrect = status !== null && workflowChanged.every((path) => allowed.includes(path)) && required.every((path) => workflowChanged.includes(path));

  const commands = expectedCommand === undefined ? [] : evidence.command_results.filter((actual) =>
    actual.command_id === expectedCommand.command_id && actual.executable === expectedCommand.executable && same(actual.args, expectedCommand.args) &&
    actual.cwd === expectedCommand.cwd && actual.exit_code === expectedCommand.expected_exit &&
    validDigest(actual.command_spec_identity) && validDigest(actual.m4_result_identity));
  const commandCorrect = commands.length === 1;
  const terminalCorrect = expectedTerminal !== undefined && evidence.terminal_workflow_result === expectedTerminal.terminal;

  let specialCorrect = true;
  for (const fact of input.scenario.acceptance_facts) {
    if (fact.type === "required_budget_fact") {
      const budget = evidence.budget;
      specialCorrect &&= budget !== undefined && validUniqueDigests(budget.evidence_identities) &&
        budget.hard_mutation_tool_limit === fact.hard_mutation_tool_limit && budget.accepted_productive_mutations <= fact.accepted_productive_mutations_at_most &&
        budget.second_productive_mutation_rejected === fact.second_productive_mutation_rejected && budget.productive_continuation_after_exhaustion === false;
    }
    if (fact.type === "required_scope_refusal") {
      const scope = evidence.scope;
      specialCorrect &&= scope !== undefined && validUniqueDigests(scope.evidence_identities) &&
        scope.required_objective_unsatisfied === fact.required_objective_unsatisfied && scope.scope_refusal_observed === fact.scope_refusal_observed;
    }
  }

  const postflightAfter = await finalPostflightMatches(input.finalRoot, evidence);
  const postflightBinding = manifestIdentity !== null && postflightBefore && postflightAfter;
  checks.push(postflightBinding ? "final-M3-postflight-manifest" : "final-M3-postflight-manifest-mismatch");
  checks.push(filesCorrect ? "typed-file-facts" : "typed-file-facts-mismatch");
  checks.push(overlayPreserved ? "approved-dirty-overlay-preserved" : "approved-dirty-overlay-corrupted");
  checks.push(pathsCorrect ? "workflow-owned-changed-paths" : "workflow-owned-changed-paths-mismatch");
  checks.push(commandCorrect ? "authoritative-command-result" : "authoritative-command-result-mismatch");
  checks.push(terminalCorrect ? "authoritative-terminal" : "authoritative-terminal-mismatch");
  checks.push(specialCorrect ? "authority-budget-scope-facts" : "authority-budget-scope-facts-mismatch");

  const workflow_correctness = semantic && overlayIdentity && authorityBinding && postflightBinding && filesCorrect && overlayPreserved && pathsCorrect && commandCorrect && terminalCorrect && specialCorrect;
  const task_success = workflow_correctness && evidence.terminal_workflow_result === "PASS";
  // A wrong product outcome can still be valid evidence; an unbound final
  // postflight or corrupted approved owner overlay cannot.
  const pilot_validity = authorityBinding && postflightBinding && overlayPreserved;
  return Object.freeze({
    task_success,
    workflow_correctness,
    pilot_validity,
    verifier_identity: sha256Canonical({ protocol: "m8-blind-verifier-v3", scenario: input.scenario.scenario_id, initial_state_identity: input.initial.initialStateIdentity,
      final_manifest_identity: manifestIdentity, run_id: input.expectedRunId, execution_authority_digest: input.expectedExecutionAuthorityDigest,
      terminal: evidence.terminal_workflow_result, checks }),
    checks: Object.freeze(checks),
  });
}
