import { constants } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { lstat, open, readFile, readdir, realpath } from "node:fs/promises";

import { sha256Bytes, sha256Canonical } from "../identity/index.js";
import { MAX_COMMAND_EXECUTABLE_BYTES } from "../schemas/definitions.js";
import { assertDocumentValid, type M3RepositoryIdentityDocument, type M4CommandCatalogDocument, type M4CommandSpecification } from "../schemas/index.js";
import { resolveRepositoryIdentity } from "../repository/identity.js";
import { detachedFrozen } from "../repository/utils.js";
import { assertM4CanonicalPath, pathMatchesRules, validatePathRules } from "../secure-fs/path.js";
import { ScopedToolGatewayError } from "./errors.js";
import type { ValidatedToolPolicy } from "./policy.js";

const FORBIDDEN_EXECUTABLES = new Set([
  "sh", "bash", "dash", "zsh", "fish", "env", "xargs", "git", "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "curl", "wget",
  "mount", "umount", "unshare", "nsenter", "strace", "gdb", "modprobe", "insmod", "rmmod",
]);
const FORBIDDEN_ENV = /^(?:NODE_OPTIONS|PYTHONPATH|PERL5LIB|RUBYOPT|LD_PRELOAD|LD_LIBRARY_PATH|GIT_CONFIG(?:_|$)|GIT_DIR$|GIT_WORK_TREE$|SSH_AUTH_SOCK$)/;
const INTERPRETER_BASENAMES = new Set(["node", "python", "bash", "sh", "dash", "zsh", "perl", "ruby", "fish"]);
export const MAX_EXECUTION_INPUT_FILES = 1024;
export const MAX_EXECUTION_INPUT_BYTES = 67_108_864;

export function isInterpreterExecutablePath(path: string): boolean {
  const name = basename(path).replace(/\.(?:exe|cmd)$/i, "");
  return INTERPRETER_BASENAMES.has(name) || /^python3(?:\.\d+)?$/u.test(name);
}

interface FrozenFileIdentity {
  readonly realpath: string;
  readonly device: number;
  readonly inode: number;
  readonly mode: number;
  readonly size: number;
  readonly digest: `sha256:${string}`;
}

async function frozenFileIdentity(path: string): Promise<FrozenFileIdentity> {
  const physical = await realpath(path); const handle = await open(physical, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat(); const bytes = await handle.readFile(); const after = await handle.stat(); const current = await lstat(physical);
    if (!before.isFile() || before.size > MAX_COMMAND_EXECUTABLE_BYTES || before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || before.dev !== current.dev || before.ino !== current.ino) {
      throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Executable changed while its authority was captured");
    }
    return Object.freeze({ realpath: physical, device: before.dev, inode: before.ino, mode: before.mode & 0o7777,
      size: before.size, digest: sha256Bytes(bytes) });
  } finally { await handle.close(); }
}

function packageDependencyNames(value: unknown): Readonly<{ required: readonly string[]; optional: readonly string[] }> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package metadata is malformed");
  const record = value as Record<string, unknown>;
  const names = (field: "dependencies" | "optionalDependencies"): readonly string[] => {
    const candidate = record[field];
    if (candidate === undefined) return [];
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate) || Object.values(candidate).some((entry) => typeof entry !== "string")) {
      throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", `Package ${field} metadata is malformed`);
    }
    return Object.keys(candidate).sort();
  };
  return Object.freeze({ required: names("dependencies"), optional: names("optionalDependencies") });
}

async function resolveInstalledPackage(sourceRoot: string, fromPackage: string, name: string): Promise<string | null> {
  let cursor = fromPackage;
  for (;;) {
    const candidate = join(cursor, "node_modules", name);
    try {
      const [stats, physical] = await Promise.all([lstat(candidate), realpath(candidate)]);
      if (!stats.isDirectory() || stats.isSymbolicLink() || physical !== candidate || (candidate !== sourceRoot && !candidate.startsWith(`${sourceRoot}/`))) {
        throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Installed package dependency escapes its frozen source root");
      }
      return candidate;
    } catch (error: unknown) {
      if (error instanceof ScopedToolGatewayError) throw error;
    }
    if (cursor === sourceRoot) return null;
    const parent = dirname(cursor);
    if (parent === cursor || (parent !== sourceRoot && !parent.startsWith(`${sourceRoot}/`))) return null;
    cursor = parent;
  }
}

async function packageDirectoryForScript(sourceRoot: string, scriptPath: string): Promise<string> {
  const modulesRoot = join(sourceRoot, "node_modules");
  if (!scriptPath.startsWith(`${modulesRoot}/`)) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package-tree entrypoint is outside node_modules");
  const parts = relative(modulesRoot, scriptPath).split("/");
  const packageParts = parts[0]?.startsWith("@") ? parts.slice(0, 2) : parts.slice(0, 1);
  if (packageParts.length === 0 || packageParts.some((part) => part.length === 0)) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package-tree entrypoint has no package root");
  const packageRoot = join(modulesRoot, ...packageParts);
  const [stats, physical] = await Promise.all([lstat(packageRoot), realpath(packageRoot)]);
  if (!stats.isDirectory() || stats.isSymbolicLink() || physical !== packageRoot) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package-tree package root is unsafe");
  return packageRoot;
}

/** Freeze an installed entrypoint's declared package dependency closure as an explicit relative tree. */
export async function freezePackageExecutionInputs(sourceRoot: string, scriptPath: string): Promise<M4CommandSpecification["execution_inputs"]> {
  const [rootStats, rootPhysical, scriptPhysical] = await Promise.all([lstat(sourceRoot), realpath(sourceRoot), realpath(scriptPath)]);
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink() || rootPhysical !== sourceRoot || scriptPhysical !== scriptPath) {
    throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package-tree source authority is unsafe");
  }
  const pending = [await packageDirectoryForScript(sourceRoot, scriptPath)];
  const packages = new Set<string>();
  while (pending.length > 0) {
    const packageRoot = pending.shift()!;
    if (packages.has(packageRoot)) continue;
    packages.add(packageRoot);
    const metadataPath = join(packageRoot, "package.json");
    let dependencies: ReturnType<typeof packageDependencyNames>;
    try { dependencies = packageDependencyNames(JSON.parse(await readFile(metadataPath, "utf8"))); }
    catch (error: unknown) {
      if (error instanceof ScopedToolGatewayError) throw error;
      throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package metadata is absent or invalid", {}, { cause: error });
    }
    for (const name of dependencies.required) {
      const dependency = await resolveInstalledPackage(sourceRoot, packageRoot, name);
      if (dependency === null) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", `Required package dependency ${name} is absent`);
      pending.push(dependency);
    }
    for (const name of dependencies.optional) {
      const dependency = await resolveInstalledPackage(sourceRoot, packageRoot, name);
      if (dependency !== null) pending.push(dependency);
    }
  }

  const files: Array<M4CommandSpecification["execution_inputs"][number]> = [];
  const visit = async (directory: string): Promise<void> => {
    const entries = (await readdir(directory, { withFileTypes: true })).sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package closure contains an unsupported filesystem object");
      if (entry.isDirectory()) await visit(path);
      else {
        const identity = await frozenFileIdentity(path);
        const capturePath = relative(sourceRoot, path);
        assertM4CanonicalPath(capturePath, "package execution-input capture path");
        files.push({ path, realpath: identity.realpath, capture_path: capturePath, device: identity.device, inode: identity.inode, mode: identity.mode, size: identity.size, digest: identity.digest });
        if (files.length > MAX_EXECUTION_INPUT_FILES || files.reduce((total, file) => total + file.size, 0) > MAX_EXECUTION_INPUT_BYTES) {
          throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package execution-input closure exceeds its explicit bound");
        }
      }
    }
  };
  for (const packageRoot of [...packages].sort()) await visit(packageRoot);
  files.sort((left, right) => left.capture_path! < right.capture_path! ? -1 : left.capture_path! > right.capture_path! ? 1 : 0);
  if (!files.some((file) => file.path === scriptPath)) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package execution-input closure omits its entrypoint");
  return files.map((file) => Object.freeze(file));
}

interface ForbiddenIdentity { readonly kind: "DISPATCHER" | "FORBIDDEN"; readonly realpath: string; readonly device: number; readonly inode: number; readonly digest: string }
let forbiddenIdentityPromise: Promise<readonly ForbiddenIdentity[]> | undefined;
function forbiddenIdentities(): Promise<readonly ForbiddenIdentity[]> {
  forbiddenIdentityPromise ??= (async () => {
    const result: ForbiddenIdentity[] = []; const seen = new Set<string>();
    for (const name of ["env", "xargs", "sh", "bash", "dash", "zsh", "fish", "git", "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "curl", "wget"]) {
      for (const directory of ["/usr/bin", "/bin"]) {
        try {
          const identity = await frozenFileIdentity(join(directory, name)); const key = `${identity.device}:${identity.inode}:${name}`;
          if (seen.has(key)) continue; seen.add(key);
          result.push({ kind: ["env", "xargs"].includes(name) ? "DISPATCHER" : "FORBIDDEN", realpath: identity.realpath,
            device: identity.device, inode: identity.inode, digest: identity.digest });
        } catch { /* Optional system executable is absent. */ }
      }
    }
    return Object.freeze(result);
  })();
  return forbiddenIdentityPromise;
}

export interface ValidatedCommandCatalog {
  readonly document: M4CommandCatalogDocument;
  readonly commands: ReadonlyMap<string, M4CommandSpecification>;
}

export function commandSpecProjection(specification: M4CommandSpecification): Omit<M4CommandSpecification, "command_spec_sha256"> {
  const { command_spec_sha256: _identity, ...projection } = specification;
  return projection;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  const a = [...left].sort(); const b = [...right].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function ruleWithinEnvelope(rule: { readonly path: string; readonly kind: "EXACT" | "PREFIX" }, envelope: readonly { readonly path: string; readonly kind: "EXACT" | "PREFIX" }[]): boolean {
  return envelope.some((authority) => authority.kind === "EXACT"
    ? rule.kind === "EXACT" && rule.path === authority.path
    : rule.path === authority.path || pathMatchesRules(rule.path, [authority]));
}

function cwdPath(repository: M3RepositoryIdentityDocument, cwd: string): string {
  if (cwd === "REPOSITORY_ROOT") return repository.worktree_root;
  assertM4CanonicalPath(cwd, "command cwd");
  return join(repository.worktree_root, cwd);
}

export async function validateCommandCatalog(
  catalog: M4CommandCatalogDocument,
  runId: string,
  repository: M3RepositoryIdentityDocument,
  policy: ValidatedToolPolicy,
): Promise<ValidatedCommandCatalog> {
  catalog = detachedFrozen(catalog);
  assertDocumentValid("pi_gacw_command_catalog_v0", catalog);
  if (catalog.run_id !== runId || catalog.repository_identity_content_sha256 !== repository.content_sha256 || catalog.tool_policy_content_sha256 !== policy.document.content_sha256) {
    throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command catalog authority differs from gateway authority");
  }
  const commands = new Map<string, M4CommandSpecification>();
  for (const spec of catalog.commands) {
    if (Buffer.byteLength(JSON.stringify(spec), "utf8") > 262_144) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command specification exceeds its execution-protocol bound", { command_id: spec.command_id });
    if (commands.has(spec.command_id)) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command catalog contains a duplicate ID");
    if (spec.command_spec_sha256 !== sha256Canonical(commandSpecProjection(spec))) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command specification identity is invalid", { command_id: spec.command_id });
    if (!isAbsolute(spec.executable_invocation_path) || resolve(spec.executable_invocation_path) !== spec.executable_invocation_path ||
        !isAbsolute(spec.executable_realpath) || resolve(spec.executable_realpath) !== spec.executable_realpath) {
      throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Executable paths must be absolute normalized paths");
    }
    const executable = await frozenFileIdentity(spec.executable_invocation_path); const physical = executable.realpath;
    if (physical !== spec.executable_realpath || executable.device !== spec.executable_device || executable.inode !== spec.executable_inode ||
        executable.mode !== spec.executable_mode || executable.size !== spec.executable_size || executable.digest !== spec.executable_sha256) {
      throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Executable identity is invalid", { command_id: spec.command_id });
    }
    const executableNames = [spec.executable_invocation_path, physical].map((path) => basename(path).replace(/\.(?:exe|cmd)$/i, ""));
    const forbiddenIdentity = (await forbiddenIdentities()).find((candidate) => candidate.realpath === physical ||
      (candidate.device === executable.device && candidate.inode === executable.inode) || candidate.digest === executable.digest);
    if (executableNames.some((name) => FORBIDDEN_EXECUTABLES.has(name)) || forbiddenIdentity !== undefined) {
      const dispatcher = executableNames.some((name) => ["env", "xargs"].includes(name)) || forbiddenIdentity?.kind === "DISPATCHER";
      throw new ScopedToolGatewayError(dispatcher ? "GENERIC_DISPATCHER_FORBIDDEN" : "COMMAND_FORBIDDEN", "Command executable class is forbidden", { command_id: spec.command_id });
    }
    if (spec.argv[0] !== spec.executable_invocation_path) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "argv[0] must equal the frozen invocation path");
    const cwd = cwdPath(repository, spec.cwd);
    let cwdStats: Awaited<ReturnType<typeof lstat>>; let cwdPhysical: string; let cwdRepository: M3RepositoryIdentityDocument;
    try { [cwdStats, cwdPhysical, cwdRepository] = await Promise.all([lstat(cwd), realpath(cwd), resolveRepositoryIdentity({ requestedPath: cwd, requireHead: true })]); }
    catch (error: unknown) { throw new ScopedToolGatewayError("COMMAND_CWD_IDENTITY_DRIFT", "Command cwd authority cannot be resolved", { command_id: spec.command_id }, { cause: error }); }
    if (!cwdStats.isDirectory() || cwdStats.isSymbolicLink() || cwdPhysical !== cwd || spec.cwd_realpath !== cwdPhysical ||
        spec.cwd_device !== cwdStats.dev || spec.cwd_inode !== cwdStats.ino || cwdRepository.worktree_root !== repository.worktree_root ||
        cwdRepository.git_common_dir !== repository.git_common_dir || (spec.cwd !== "REPOSITORY_ROOT" && !pathMatchesRules(spec.cwd, policy.commandReadable))) {
      throw new ScopedToolGatewayError("COMMAND_CWD_IDENTITY_DRIFT", "Command cwd physical, repository, or policy authority is invalid", { command_id: spec.command_id });
    }
    const packageLayout = typeof spec.execution_input_layout === "object" ? spec.execution_input_layout : null;
    if (spec.execution_input_layout !== "FLAT" && (packageLayout === null || packageLayout.kind !== "PACKAGE_TREE" || !isAbsolute(packageLayout.source_root) || resolve(packageLayout.source_root) !== packageLayout.source_root)) {
      throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input layout authority is invalid", { command_id: spec.command_id });
    }
    if (packageLayout !== null) {
      const [rootStats, rootPhysical] = await Promise.all([lstat(packageLayout.source_root), realpath(packageLayout.source_root)]);
      if (!rootStats.isDirectory() || rootStats.isSymbolicLink() || rootPhysical !== packageLayout.source_root || rootStats.dev !== packageLayout.device || rootStats.ino !== packageLayout.inode) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Package execution-input root identity is invalid", { command_id: spec.command_id });
    }
    const seenInputs = new Set<string>(); const seenCapturePaths = new Set<string>(); let executionInputBytes = 0;
    for (const input of spec.execution_inputs) {
      if (!isAbsolute(input.path) || resolve(input.path) !== input.path || !isAbsolute(input.realpath) || resolve(input.realpath) !== input.realpath || seenInputs.has(input.path)) {
        throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input path authority is invalid", { command_id: spec.command_id });
      }
      if (packageLayout === null ? input.capture_path !== undefined : input.capture_path === undefined) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input relative layout is incomplete", { command_id: spec.command_id });
      if (packageLayout !== null) {
        assertM4CanonicalPath(input.capture_path!, "execution-input capture path");
        if (seenCapturePaths.has(input.capture_path!) || join(packageLayout.source_root, input.capture_path!) !== input.path) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input relative layout is invalid", { command_id: spec.command_id });
        seenCapturePaths.add(input.capture_path!);
      }
      seenInputs.add(input.path); executionInputBytes += input.size;
      if (seenInputs.size > MAX_EXECUTION_INPUT_FILES || executionInputBytes > MAX_EXECUTION_INPUT_BYTES) throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input closure exceeds its explicit bound", { command_id: spec.command_id });
      const inputPhysical = await realpath(input.path); const inputStats = await lstat(input.path);
      if (inputPhysical !== input.realpath || inputPhysical !== input.path || !inputStats.isFile() || inputStats.isSymbolicLink() || inputStats.dev !== input.device || inputStats.ino !== input.inode ||
          (inputStats.mode & 0o7777) !== input.mode || inputStats.size !== input.size || sha256Bytes(await readFile(input.path)) !== input.digest) {
        throw new ScopedToolGatewayError("EXECUTION_INPUT_DRIFT", "Execution-input identity is invalid", { command_id: spec.command_id });
      }
    }
    const interpreter = executableNames.some((name) => isInterpreterExecutablePath(name));
    if (interpreter) {
      const script = spec.argv[1];
      if (script === undefined || script.startsWith("-") || !isAbsolute(script) || !seenInputs.has(script)) {
        throw new ScopedToolGatewayError("COMMAND_FORBIDDEN", "Interpreter commands require a frozen absolute script as argv[1]", { command_id: spec.command_id });
      }
    }
    const seenEnvironment = new Set<string>();
    for (const entry of spec.environment) {
      if (seenEnvironment.has(entry.key) || FORBIDDEN_ENV.test(entry.key) || !/^[A-Za-z_][A-Za-z0-9_]{0,254}$/.test(entry.key)) {
        throw new ScopedToolGatewayError("COMMAND_FORBIDDEN", "Command environment contains a forbidden or duplicate key", { command_id: spec.command_id });
      }
      seenEnvironment.add(entry.key);
    }
    const readRules = validatePathRules(spec.read_paths, `command ${spec.command_id} read_paths`);
    const writeRules = validatePathRules(spec.write_paths, `command ${spec.command_id} write_paths`);
    for (const path of [...spec.claimed_paths, ...spec.cleanup_paths]) assertM4CanonicalPath(path, `command ${spec.command_id} path claim`);
    for (const rule of readRules) if (!ruleWithinEnvelope(rule, policy.commandReadable)) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command read path exceeds policy", { command_id: spec.command_id });
    for (const rule of writeRules) if (!ruleWithinEnvelope(rule, policy.commandWritable)) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command write path exceeds policy", { command_id: spec.command_id });
    if (spec.timeout_ms > policy.document.limits.maximum_command_duration_ms || spec.stdout_limit > policy.document.limits.maximum_command_stdout_bytes || spec.stderr_limit > policy.document.limits.maximum_command_stderr_bytes) {
      throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Command execution bounds exceed tool policy", { command_id: spec.command_id });
    }
    if (spec.command_class === "INSPECTION" && (spec.repository_side_effect !== "NONE" || writeRules.length !== 0 || spec.claimed_paths.length !== 0)) {
      throw new ScopedToolGatewayError("COMMAND_CLASS_MISMATCH", "Inspection command must be read-only", { command_id: spec.command_id });
    }
    if (spec.command_class === "TASK") {
      if (spec.repository_side_effect !== "EXACT_PATHS" || writeRules.length === 0 || writeRules.some((rule) => rule.kind !== "EXACT") ||
          !sameStrings(spec.claimed_paths, writeRules.map((rule) => rule.path))) {
        throw new ScopedToolGatewayError("COMMAND_CLASS_MISMATCH", "Task command requires exact write and claim paths", { command_id: spec.command_id });
      }
    }
    if (spec.command_class === "VERIFICATION") {
      if (spec.repository_side_effect === "EXACT_PATHS") throw new ScopedToolGatewayError("COMMAND_CLASS_MISMATCH", "Verification command cannot mutate tracked source", { command_id: spec.command_id });
      if (spec.repository_side_effect === "NONE" && (writeRules.length !== 0 || spec.claimed_paths.length !== 0)) throw new ScopedToolGatewayError("COMMAND_CLASS_MISMATCH", "Read-only verification command has write authority", { command_id: spec.command_id });
      if (spec.repository_side_effect === "GENERATED_ONLY" && (writeRules.length === 0 || spec.claimed_paths.length === 0 ||
          spec.claimed_paths.some((path) => !ruleWithinEnvelope({ path, kind: "EXACT" }, writeRules)))) {
        throw new ScopedToolGatewayError("COMMAND_CLASS_MISMATCH", "Generated-output verification command lacks exact claims inside its write authority", { command_id: spec.command_id });
      }
    }
    if (spec.cleanup_paths.length !== 0) throw new ScopedToolGatewayError("COMMAND_SPEC_MISMATCH", "Controller cleanup paths are reserved for a later milestone", { command_id: spec.command_id });
    commands.set(spec.command_id, Object.freeze({ ...spec }));
  }
  return Object.freeze({ document: catalog, commands });
}

export function commandForClass(catalog: ValidatedCommandCatalog, commandId: string, expectedClass: M4CommandSpecification["command_class"]): M4CommandSpecification {
  if (typeof commandId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(commandId)) throw new ScopedToolGatewayError("UNKNOWN_COMMAND_ID", "Command ID is invalid");
  const command = catalog.commands.get(commandId);
  if (command === undefined) throw new ScopedToolGatewayError("UNKNOWN_COMMAND_ID", "Command ID is not present in the frozen catalog", { command_id: commandId });
  if (command.command_class !== expectedClass) throw new ScopedToolGatewayError("COMMAND_CLASS_MISMATCH", "Command class differs from requested gateway operation", { command_id: commandId });
  return command;
}
