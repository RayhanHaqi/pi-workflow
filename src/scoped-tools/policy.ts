import type { M3RepositoryIdentityDocument, M4PathAuthority, M4PathRule, M4ScopedToolPolicyDocument } from "../schemas/index.js";
import { assertDocumentValid } from "../schemas/index.js";
import { compareText, detachedFrozen, pathWithin } from "../repository/utils.js";
import { assertM4CanonicalPath, pathMatchesRules, validatePathRules } from "../secure-fs/path.js";
import { ScopedToolGatewayError } from "./errors.js";

export interface ValidatedToolPolicy {
  readonly document: M4ScopedToolPolicyDocument;
  readonly readable: readonly M4PathRule[];
  readonly editable: readonly M4PathRule[];
  readonly frozen: readonly M4PathRule[];
  readonly commandReadable: readonly M4PathRule[];
  readonly commandWritable: readonly M4PathRule[];
  readonly authorities: readonly M4PathAuthority[];
}

function overlap(left: M4PathRule, right: M4PathRule): boolean {
  if (left.path === right.path) return true;
  if (left.kind === "PREFIX" && pathWithin(right.path, left.path)) return true;
  return right.kind === "PREFIX" && pathWithin(left.path, right.path);
}

function pathSet(rules: readonly M4PathRule[]): readonly string[] {
  return rules.map((rule) => rule.path).sort(compareText);
}

function ruleWithinEnvelope(rule: M4PathRule, envelope: readonly M4PathRule[]): boolean {
  return envelope.some((authority) => {
    if (authority.kind === "EXACT") return rule.kind === "EXACT" && rule.path === authority.path;
    return rule.path === authority.path || pathWithin(rule.path, authority.path);
  });
}

function equal(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function validateToolPolicy(
  policy: M4ScopedToolPolicyDocument,
  runId: string,
  repository: M3RepositoryIdentityDocument,
  taskScopeIdentity: string,
  editablePaths: readonly string[],
  frozenPaths: readonly string[],
): ValidatedToolPolicy {
  policy = detachedFrozen(policy);
  assertDocumentValid("pi_gacw_scoped_tool_policy_v0", policy);
  if (policy.run_id !== runId || policy.repository_identity_content_sha256 !== repository.content_sha256 ||
      policy.worktree_key !== repository.worktree_key || policy.task_scope_identity !== taskScopeIdentity) {
    throw new ScopedToolGatewayError("STATE_TOKEN_PROVENANCE_INVALID", "Tool policy authority differs from M3 authority");
  }
  const readable = validatePathRules(policy.readable_paths, "policy.readable_paths");
  const editable = validatePathRules(policy.editable_paths, "policy.editable_paths");
  const frozen = validatePathRules(policy.frozen_paths, "policy.frozen_paths");
  const commandReadable = validatePathRules(policy.command_readable_paths, "policy.command_readable_paths");
  const commandWritable = validatePathRules(policy.command_writable_paths, "policy.command_writable_paths");
  if (!equal(pathSet(editable), [...editablePaths].sort(compareText)) || !equal(pathSet(frozen), [...frozenPaths].sort(compareText))) {
    throw new ScopedToolGatewayError("STATE_TOKEN_PROVENANCE_INVALID", "Tool policy path envelope differs from the M3 task scope");
  }
  for (const left of editable) for (const right of frozen) if (overlap(left, right)) throw new ScopedToolGatewayError("FROZEN_PATH", "Editable and frozen policy rules overlap");
  for (const rule of commandWritable) {
    if (!ruleWithinEnvelope(rule, editable) || frozen.some((item) => overlap(rule, item))) {
      throw new ScopedToolGatewayError("PATH_NOT_EDITABLE", "Command write rule is outside editable authority");
    }
  }
  // Deterministic verifier reads are independently bounded by command_readable_paths and path_authorities; they do not widen worker readable_paths.
  if (!Array.isArray(policy.path_authorities) || policy.path_authorities.length > 100_000) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Path authority inventory is invalid");
  const authorities: M4PathAuthority[] = policy.path_authorities.map((authority) => {
    assertM4CanonicalPath(authority.path, "path authority");
    if (authority.kind !== "EXACT" && authority.kind !== "PREFIX") throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Path authority kind is invalid");
    return Object.freeze({ ...authority });
  }).sort((a, b) => compareText(a.path, b.path));
  for (let index = 0; index < authorities.length; index += 1) {
    const left = authorities[index]!;
    for (let other = index + 1; other < authorities.length; other += 1) {
      const right = authorities[other]!;
      if (left.path === right.path) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Path authority entries duplicate an effective path");
      const overlaps = (left.kind === "PREFIX" && pathWithin(right.path, left.path)) || (right.kind === "PREFIX" && pathWithin(left.path, right.path));
      if (overlaps && left.path.length === right.path.length) throw new ScopedToolGatewayError("INVALID_ARGUMENT", "Path authority precedence is ambiguous");
    }
  }
  const authorityForRule = (rule: M4PathRule): M4PathAuthority | null => authorities.find((authority) =>
    authority.kind === "EXACT" ? rule.kind === "EXACT" && authority.path === rule.path : authority.path === rule.path || pathWithin(rule.path, authority.path),
  ) ?? null;
  for (const rule of commandReadable) {
    const authority = authorityForRule(rule);
    const containsRestrictedDescendant = rule.kind === "PREFIX" && authorities.some((candidate) =>
      pathWithin(candidate.path, rule.path) && (candidate.data_class === "SECRET" || candidate.data_class === "HASH_ONLY" ||
        (["PRIVATE_SOURCE", "SENSITIVE", "LARGE_BINARY"].includes(candidate.data_class) && !candidate.raw_read_approved)),
    );
    if (authority === null || containsRestrictedDescendant || (rule.kind === "PREFIX" && authority.kind !== "PREFIX") || authority.data_class === "SECRET" || authority.data_class === "HASH_ONLY" ||
        (["PRIVATE_SOURCE", "SENSITIVE", "LARGE_BINARY"].includes(authority.data_class) && !authority.raw_read_approved)) {
      throw new ScopedToolGatewayError("DATA_POLICY_FORBIDS_READ", "Command read rule lacks raw-read authority for every descendant", { path: rule.path });
    }
  }
  for (const rule of commandWritable) {
    const authority = authorityForRule(rule);
    if (authority === null || (rule.kind === "PREFIX" && authority.kind !== "PREFIX") ||
        !["OWNER_ACCEPTED_MUTABLE", "GENERATED_ACCEPTED_BASELINE"].includes(authority.ownership_class) ||
        ["SECRET", "LARGE_BINARY", "HASH_ONLY"].includes(authority.data_class) || !authority.replace ||
        (rule.kind === "PREFIX" && (!authority.create || !authority.delete))) {
      throw new ScopedToolGatewayError("OWNERSHIP_FORBIDS_MUTATION", "Command write rule lacks complete path authority", { path: rule.path });
    }
  }
  const limits = policy.limits;
  const maxima: Readonly<Record<keyof typeof limits, number>> = {
    maximum_patch_bytes: 1_048_576,
    maximum_read_bytes: 1_048_576,
    maximum_hash_bytes: 67_108_864,
    maximum_search_input_bytes: 67_108_864,
    maximum_search_matches: 10_000,
    maximum_list_entries: 100_000,
    maximum_list_metadata_bytes: 67_108_864,
    maximum_command_stdout_bytes: 4_194_304,
    maximum_command_stderr_bytes: 4_194_304,
    maximum_command_duration_ms: 1_800_000,
  };
  for (const key of Object.keys(maxima) as Array<keyof typeof limits>) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 0 || limits[key] > maxima[key]) throw new ScopedToolGatewayError("INVALID_ARGUMENT", `Tool-policy limit ${key} is invalid`);
  }
  return Object.freeze({ document: policy, readable, editable, frozen, commandReadable, commandWritable, authorities: Object.freeze(authorities) });
}

export function authorityForPath(policy: ValidatedToolPolicy, path: string): M4PathAuthority | null {
  const matches = policy.authorities.filter((authority) => authority.kind === "EXACT" ? authority.path === path : pathWithin(path, authority.path));
  return matches.sort((left, right) => right.path.length - left.path.length || (left.kind === "EXACT" ? -1 : 1))[0] ?? null;
}

export function isSecretPath(policy: ValidatedToolPolicy, path: string): boolean {
  return policy.authorities.some((authority) => authority.data_class === "SECRET" && pathWithin(path, authority.path));
}

export function assertReadablePath(policy: ValidatedToolPolicy, path: string): M4PathAuthority | null {
  assertM4CanonicalPath(path);
  if (!pathMatchesRules(path, policy.readable)) throw new ScopedToolGatewayError("PATH_NOT_READABLE", "Path is outside readable scope", { path });
  const authority = authorityForPath(policy, path);
  if (isSecretPath(policy, path)) throw new ScopedToolGatewayError("SECRET_METADATA_FORBIDDEN", "SECRET path authority is never observable");
  return authority;
}

export function rawReadPermitted(authority: M4PathAuthority | null): boolean {
  if (authority === null) return false;
  if (authority.data_class === "PUBLIC_SOURCE") return true;
  if (["PRIVATE_SOURCE", "SENSITIVE", "LARGE_BINARY"].includes(authority.data_class)) return authority.raw_read_approved;
  return false;
}

export function assertMutationPermitted(
  policy: ValidatedToolPolicy,
  path: string,
  operation: "CREATE" | "REPLACE" | "DELETE",
  requestedOwnership: M4PathAuthority["ownership_class"],
  requestedDataClass: M4PathAuthority["data_class"],
  modeChanged: boolean,
): M4PathAuthority {
  assertM4CanonicalPath(path);
  if (pathMatchesRules(path, policy.frozen)) throw new ScopedToolGatewayError("FROZEN_PATH", "Frozen path cannot be mutated", { path });
  if (!pathMatchesRules(path, policy.editable)) throw new ScopedToolGatewayError("PATH_NOT_EDITABLE", "Path is outside editable scope", { path });
  const authority = authorityForPath(policy, path);
  if (authority === null || authority.ownership_class !== requestedOwnership || authority.data_class !== requestedDataClass) {
    throw new ScopedToolGatewayError("OWNERSHIP_FORBIDS_MUTATION", "Path ownership or data-class authority is absent or differs", { path });
  }
  if (authority.ownership_class === "OWNER_AUTHORITY" || authority.ownership_class === "PREEXISTING_UNRELATED") {
    throw new ScopedToolGatewayError("OWNERSHIP_FORBIDS_MUTATION", "Path ownership forbids mutation", { path });
  }
  if (["SECRET", "LARGE_BINARY", "HASH_ONLY"].includes(authority.data_class)) throw new ScopedToolGatewayError("DATA_POLICY_FORBIDS_MUTATION", "Path data class forbids mutation", { path });
  const permission = operation === "CREATE" ? authority.create : operation === "REPLACE" ? authority.replace : authority.delete;
  if (!permission) throw new ScopedToolGatewayError("PATH_NOT_EDITABLE", `Policy does not permit ${operation}`, { path });
  if (modeChanged && !authority.mode_change) throw new ScopedToolGatewayError("PATH_NOT_EDITABLE", "Policy does not permit a mode change", { path });
  return authority;
}
