import type { M4PathRule } from "../schemas/index.js";
import { assertCanonicalRepositoryPath, pathWithin } from "../repository/utils.js";
import { SecureFilesystemError } from "./errors.js";

export function assertM4CanonicalPath(value: unknown, label = "path"): asserts value is string {
  try {
    assertCanonicalRepositoryPath(value, label);
    if (value === ".git" || value.startsWith(".git/")) throw new Error("Git metadata is outside the tool root");
  } catch (error: unknown) {
    throw new SecureFilesystemError("INVALID_CANONICAL_PATH", `${label} is not canonical`, {}, { cause: error });
  }
}

export function validatePathRules(value: unknown, label: string): readonly M4PathRule[] {
  if (!Array.isArray(value) || value.length > 10_000) throw new SecureFilesystemError("INVALID_ARGUMENT", `${label} must be a bounded array`);
  const result: M4PathRule[] = [];
  for (const item of value) {
    if (item === null || Array.isArray(item) || typeof item !== "object" || Object.keys(item).sort().join(",") !== "kind,path") {
      throw new SecureFilesystemError("INVALID_ARGUMENT", `${label} contains an invalid rule`);
    }
    const record = item as Record<string, unknown>;
    assertM4CanonicalPath(record["path"], `${label}.path`);
    if (record["kind"] !== "EXACT" && record["kind"] !== "PREFIX") throw new SecureFilesystemError("INVALID_ARGUMENT", `${label}.kind is invalid`);
    result.push({ path: record["path"], kind: record["kind"] });
  }
  result.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : a.kind < b.kind ? -1 : 1);
  for (let index = 0; index < result.length; index += 1) {
    for (let other = index + 1; other < result.length; other += 1) {
      const left = result[index]!; const right = result[other]!;
      if (left.path === right.path || (left.kind === "PREFIX" && pathWithin(right.path, left.path)) || (right.kind === "PREFIX" && pathWithin(left.path, right.path))) {
        throw new SecureFilesystemError("INVALID_ARGUMENT", `${label} contains overlapping or ambiguous rules`);
      }
    }
  }
  return Object.freeze(result.map((entry) => Object.freeze({ ...entry })));
}

export function pathMatchesRule(path: string, rule: M4PathRule): boolean {
  return rule.kind === "EXACT" ? path === rule.path : pathWithin(path, rule.path);
}

export function pathMatchesRules(path: string, rules: readonly M4PathRule[]): boolean {
  return rules.some((rule) => pathMatchesRule(path, rule));
}

/**
 * Canonical semantic union of path rules: identical rules collapse to one, and every rule covered
 * by a PREFIX rule (the prefix itself, a descendant exact, or a nested prefix) is represented by
 * that PREFIX alone. Unrelated rules are preserved. Deterministic and input-order independent; the
 * result passes validatePathRules whenever each input collection does.
 */
export function canonicalPathRuleUnion(rules: readonly M4PathRule[]): readonly M4PathRule[] {
  const unique = [...new Map(rules.map((rule) => [`${rule.kind}\u0000${rule.path}`, rule] as const).values()).values()];
  const reduced = unique.filter((rule) => !unique.some((other) => other.kind === "PREFIX" &&
    (rule.kind === "EXACT" || other.path !== rule.path) && pathWithin(rule.path, other.path)));
  reduced.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : a.kind < b.kind ? -1 : 1);
  return Object.freeze(reduced.map((entry) => Object.freeze({ ...entry })));
}
