import { sha256Canonical, type Sha256Digest } from "./index.js";

export const M3_SCOPE_SCHEMA_ID = "pi_gacw_task_scope_v0" as const;
export const M3_SCOPE_VERSION = "0.1.0" as const;
export const M3_SCOPE_PROJECTION_ID = "m3-task-scope-v1" as const;

export interface M3ScopeIdentityProjection {
  readonly schema_id: typeof M3_SCOPE_SCHEMA_ID;
  readonly schema_version: typeof M3_SCOPE_VERSION;
  readonly scope_projection_id: typeof M3_SCOPE_PROJECTION_ID;
  readonly editable_paths: readonly string[];
  readonly frozen_paths: readonly string[];
}

export function m3ScopeIdentityProjection(
  editablePaths: readonly string[],
  frozenPaths: readonly string[],
): M3ScopeIdentityProjection {
  return {
    schema_id: M3_SCOPE_SCHEMA_ID,
    schema_version: M3_SCOPE_VERSION,
    scope_projection_id: M3_SCOPE_PROJECTION_ID,
    editable_paths: [...editablePaths].sort(),
    frozen_paths: [...frozenPaths].sort(),
  };
}

export function m3ScopeIdentity(
  editablePaths: readonly string[],
  frozenPaths: readonly string[],
): Sha256Digest {
  return sha256Canonical(m3ScopeIdentityProjection(editablePaths, frozenPaths));
}
