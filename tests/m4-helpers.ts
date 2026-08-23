import { chmod, lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { sha256Bytes, sha256Canonical } from "../src/identity/index.js";
import { identifyContractDocument, type M4CommandCatalogDocument, type M4CommandSpecification, type M4ScopedToolPolicyDocument } from "../src/schemas/index.js";
import { createScopedToolGateway } from "../src/scoped-tools/index.js";
import { commandSpecProjection } from "../src/scoped-tools/commands.js";
import { createCleanAdmission, releaseAdmission } from "./repository-matrix-helpers.js";
import { createRepositoryFixture, git, removeRepositoryFixture, type RepositoryFixture } from "./repository-helpers.js";

export const m4Limits = Object.freeze({
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
});

export function makeM4Policy(
  fixture: RepositoryFixture,
  admission: Awaited<ReturnType<typeof createCleanAdmission>>,
): M4ScopedToolPolicyDocument {
  return identifyContractDocument("pi_gacw_scoped_tool_policy_v0", {
    schema_id: "pi_gacw_scoped_tool_policy_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: fixture.runId,
    policy_id: "m4-test-policy",
    repository_identity_content_sha256: admission.repository.content_sha256,
    worktree_key: admission.repository.worktree_key,
    task_scope_identity: admission.taskScopeIdentity,
    readable_paths: [{ path: "generated", kind: "PREFIX" }, { path: "src", kind: "PREFIX" }, { path: "tracked.txt", kind: "EXACT" }],
    editable_paths: admission.editable.map((path) => ({ path, kind: path === "src" || path === "generated" ? "PREFIX" : "EXACT" })),
    frozen_paths: admission.frozen.map((path) => ({ path, kind: "EXACT" })),
    command_readable_paths: [{ path: "generated", kind: "PREFIX" }, { path: "src", kind: "PREFIX" }, { path: "tracked.txt", kind: "EXACT" }],
    command_writable_paths: [{ path: "generated", kind: "PREFIX" }, { path: "tracked.txt", kind: "EXACT" }],
    path_authorities: [
      { path: "generated", kind: "PREFIX", ownership_class: "GENERATED_ACCEPTED_BASELINE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: true, replace: true, delete: true, mode_change: false },
      { path: "src", kind: "PREFIX", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: false, delete: false, mode_change: false },
      { path: "tracked.txt", kind: "EXACT", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: false, replace: true, delete: true, mode_change: true },
      { path: "created.txt", kind: "EXACT", ownership_class: "OWNER_ACCEPTED_MUTABLE", data_class: "PUBLIC_SOURCE", raw_read_approved: true, create: true, replace: false, delete: false, mode_change: false },
      { path: "AGENTS.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
      { path: "AUTHORITY.md", kind: "EXACT", ownership_class: "OWNER_AUTHORITY", data_class: "PUBLIC_SOURCE", raw_read_approved: false, create: false, replace: false, delete: false, mode_change: false },
    ],
    evidence_readable_kinds: ["M3_REPOSITORY_STATE_TOKEN", "M4_TOOL_REQUEST", "M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"],
    limits: m4Limits,
  }) as M4ScopedToolPolicyDocument;
}

export async function commandSpecification(
  commandId: string,
  commandClass: "INSPECTION" | "TASK" | "VERIFICATION",
  executable: string,
  argv: readonly string[],
  options: {
    readonly repositoryRoot: string;
    readonly cwd?: "REPOSITORY_ROOT" | string;
    readonly executionInputs?: readonly string[];
    readonly readPaths?: readonly { readonly path: string; readonly kind: "EXACT" | "PREFIX" }[];
    readonly writePaths?: readonly { readonly path: string; readonly kind: "EXACT" | "PREFIX" }[];
    readonly sideEffect?: "NONE" | "EXACT_PATHS" | "GENERATED_ONLY";
    readonly claimedPaths?: readonly string[];
    readonly timeoutMs?: number;
    readonly stdoutLimit?: number;
    readonly stderrLimit?: number;
    readonly expectedExitCodes?: readonly number[];
  },
): Promise<M4CommandSpecification> {
  const physical = await realpath(executable); const executableStats = await lstat(physical);
  const cwd = options.cwd ?? "REPOSITORY_ROOT"; const cwdPath = cwd === "REPOSITORY_ROOT" ? options.repositoryRoot : isAbsolute(cwd) ? cwd : join(options.repositoryRoot, cwd);
  const cwdPhysical = await realpath(cwdPath); const cwdStats = await lstat(cwdPath);
  const executionPaths = [...new Set([...argv.filter((value) => value.startsWith("/")), ...(options.executionInputs ?? [])])];
  const executionInputs = [] as Array<{ path: string; realpath: string; device: number; inode: number; mode: number; size: number; digest: string }>;
  for (const path of executionPaths) {
    try {
      const stats = await lstat(path); if (!stats.isFile() || stats.isSymbolicLink()) continue;
      const resolved = await realpath(path); if (resolved !== path) continue;
      executionInputs.push({ path, realpath: resolved, device: stats.dev, inode: stats.ino, mode: stats.mode & 0o7777, size: stats.size, digest: sha256Bytes(await readFile(path)) });
    } catch { /* non-file argv values are ordinary arguments */ }
  }
  const draft = {
    command_id: commandId,
    command_spec_sha256: `sha256:${"0".repeat(64)}`,
    command_class: commandClass,
    executable_invocation_path: executable,
    executable_realpath: physical,
    executable_device: executableStats.dev,
    executable_inode: executableStats.ino,
    executable_mode: executableStats.mode & 0o7777,
    executable_size: executableStats.size,
    executable_sha256: sha256Bytes(await readFile(physical)),
    argv: [executable, ...argv],
    cwd,
    cwd_realpath: cwdPhysical,
    cwd_device: cwdStats.dev,
    cwd_inode: cwdStats.ino,
    execution_input_layout: "FLAT" as const,
    execution_inputs: executionInputs,
    environment: [],
    read_paths: [...(options.readPaths ?? [])],
    write_paths: [...(options.writePaths ?? [])],
    network_policy: "FORBIDDEN" as const,
    timeout_ms: options.timeoutMs ?? 30_000,
    stdout_limit: options.stdoutLimit ?? 1_048_576,
    stderr_limit: options.stderrLimit ?? 1_048_576,
    expected_exit_codes: [...(options.expectedExitCodes ?? [0])],
    repository_side_effect: options.sideEffect ?? "NONE",
    claimed_paths: [...(options.claimedPaths ?? [])],
    cleanup_paths: [],
  };
  return { ...draft, command_spec_sha256: sha256Canonical(commandSpecProjection(draft as M4CommandSpecification)) } as M4CommandSpecification;
}

export function makeM4Catalog(
  fixture: RepositoryFixture,
  admission: Awaited<ReturnType<typeof createCleanAdmission>>,
  policy: M4ScopedToolPolicyDocument,
  commands: readonly M4CommandSpecification[] = [],
): M4CommandCatalogDocument {
  return identifyContractDocument("pi_gacw_command_catalog_v0", {
    schema_id: "pi_gacw_command_catalog_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    run_id: fixture.runId,
    catalog_id: "m4-test-catalog",
    repository_identity_content_sha256: admission.repository.content_sha256,
    tool_policy_content_sha256: policy.content_sha256,
    commands: [...commands],
  }) as M4CommandCatalogDocument;
}

export async function createM4Fixture(
  commands: readonly M4CommandSpecification[] | ((fixture: RepositoryFixture, temporaryRoot: string) => Promise<readonly M4CommandSpecification[]>) = [],
  transformPolicy: ((policy: M4ScopedToolPolicyDocument) => M4ScopedToolPolicyDocument) | null = null,
  prepareRepository: ((fixture: RepositoryFixture) => Promise<void>) | null = null,
) {
  const fixture = await createRepositoryFixture();
  let admission: Awaited<ReturnType<typeof createCleanAdmission>> | undefined;
  try {
    await mkdir(join(fixture.repository, "src"), { mode: 0o755 });
    await mkdir(join(fixture.repository, "generated"), { mode: 0o755 });
    await writeFile(join(fixture.repository, "generated", ".keep"), "generated fixture\n", { mode: 0o644 });
    await writeFile(join(fixture.repository, "src", "a.txt"), "Alpha needle\nsecond line\n", { mode: 0o644 });
    await writeFile(join(fixture.repository, "src", "b.txt"), "beta NEEDLE\n", { mode: 0o644 });
    await git(fixture.repository, "add", "generated/.keep", "src/a.txt", "src/b.txt");
    await git(fixture.repository, "commit", "-m", "add m4 read fixtures");
    await prepareRepository?.(fixture);
    admission = await createCleanAdmission(fixture, { editable: ["created.txt", "generated", "src", "tracked.txt"], frozen: ["AGENTS.md", "AUTHORITY.md"] });
    const basePolicy = makeM4Policy(fixture, admission); const policy = transformPolicy?.(basePolicy) ?? basePolicy;
    const temporaryRoot = join(fixture.root, "controller-tmp");
    await mkdir(temporaryRoot, { mode: 0o700 }); await chmod(temporaryRoot, 0o700);
    const selectedCommands = typeof commands === "function" ? await commands(fixture, temporaryRoot) : commands;
    const catalog = makeM4Catalog(fixture, admission, policy, selectedCommands);
    const gateway = await createScopedToolGateway({ stateRoot: fixture.stateRoot, runId: fixture.runId, repository: admission.repository,
      baseline: admission.baseline, acceptedState: admission.full.acceptedState, lock: admission.lock,
      instructionFiles: admission.selected.instructions, authorityFiles: admission.selected.authorities,
      editablePaths: admission.editable, frozenPaths: admission.frozen, taskScopeIdentity: admission.taskScopeIdentity,
      toolPolicy: policy, commandCatalog: catalog, temporaryRoot });
    return { fixture, admission, policy, catalog, temporaryRoot, gateway };
  } catch (error: unknown) {
    if (admission !== undefined) await releaseAdmission(admission);
    await removeRepositoryFixture(fixture);
    throw error;
  }
}
