import type { M4ScopedToolPolicyDocument, PlanApprovalDocument } from "../schemas/index.js";

/**
 * Shared bounded-worker launch authority, extracted verbatim from workflow-controller so resumed
 * execution (V1-R2D) constructs byte-identical prompts and scopes without duplicating identity.
 * Drift is guarded by tests/launch-authority-equivalence.test.ts against the controller originals.
 */

/** Historical MAX_TOOL_CALLS_PER_WORKER: total accepted M4 evidence cap per worker. */
export const BOUNDED_WORKER_MAX_TOOL_CALLS = 32;
/** Historical MAX_WALL_TIME_MS fallback deadline for workers outside frozen static time budgets. */
export const BOUNDED_WORKER_MAX_WALL_TIME_MS = 120_000;

export type ProviderVisibleReadScope = {
  readonly regularFilePaths: readonly string[];
  readonly prefixPaths: readonly string[];
};

export function partitionProviderVisibleReadScope(readablePaths: readonly string[], pathAuthorities: M4ScopedToolPolicyDocument["path_authorities"]): ProviderVisibleReadScope {
  const authorityKinds = new Map(pathAuthorities.map((entry) => [entry.path, entry.kind]));
  const regularFilePaths: string[] = [];
  const prefixPaths: string[] = [];
  for (const readablePath of readablePaths) {
    const kind = authorityKinds.get(readablePath);
    if (kind === "EXACT") regularFilePaths.push(readablePath);
    else if (kind === "PREFIX") prefixPaths.push(readablePath);
    else throw Object.assign(new Error(`frozen readable path ${readablePath} has no M4 path-kind authority`), { code: "CONTROLLER_AUTHORITY_INVALID" });
  }
  return { regularFilePaths, prefixPaths };
}

export function providerVisibleTaskContract(objective: string, readableScope: ProviderVisibleReadScope, editablePaths: readonly string[], plannerPlan: PlanApprovalDocument | null, hardMutationToolLimit: 1 | null): string {
  const paths = (values: readonly string[]) => values.map((entry) => `- ${entry}`).join("\n") || "- (none)";
  const plannerInstruction = plannerPlan === null ? "" : `\nPlanner instruction: submit exactly candidate_plan_sha256:${plannerPlan.content_sha256}; topology, scope, and identity expansion are forbidden.`;
  const boundedMutationInstruction = hardMutationToolLimit !== 1 ? "" : "\n\nFrozen productive mutation sequence:\n- Make the first productive mutation request a genuine observable byte-changing edit to one task-owned editable path; a no-op replacement is not productive.\n- After that first productive mutation succeeds, do not stop: issue a second genuinely productive mutation request on that same task-owned editable path, requesting another byte-changing edit from its then-current contents.\n- Do not simulate the second attempt. Use only the supplied bounded tools and let the controller/M4 mutation-budget boundary decide that request.";
  return `Frozen task contract\n\nObjective (exact frozen text):\n${objective}\n\nReadable paths (exact frozen scope):\nRegular-file read targets (valid read_scoped.path values):\n${paths(readableScope.regularFilePaths)}\n\nDirectory/prefix authority (not valid read_scoped.path values):\n${paths(readableScope.prefixPaths)}\n\nEditable paths (exact frozen scope):\n${paths(editablePaths)}\n\nScoped path requirements:\n- Scoped tool path arguments are exact canonical repository-relative paths; use the listed spelling exactly.\n- read_scoped.path must name one authorized regular-file read target listed above.\n- Directory/prefix authority establishes frozen scope and command/cwd authority; it is not a regular-file read target and must not be passed directly to read_scoped.path.\n- Repository-root aliases and discovery are not authorized. Invalid forms include ., an empty path, ./..., root aliases, .. or traversal, and absolute paths.\n- Do not normalize an alias into another path.${boundedMutationInstruction}${plannerInstruction}`;
}

export function boundedWorkerSystemPrompt(profile: "MUTATION_EXECUTOR" | "SOL_PLANNER" | "SOL_CLOSEOUT"): string {
  return `Pre-M8 bounded ${profile}; use only supplied M4 tools; no retry, replan, commands, shell, filesystem, or network.`;
}
