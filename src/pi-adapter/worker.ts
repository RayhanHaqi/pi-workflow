import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalize } from "../canonical-json/index.js";
import { assertControlPolicyAuthority } from "../control/policy.js";
import { sha256Bytes, sha256Canonical, assertSha256Digest, type Sha256Digest } from "../identity/index.js";
import { m3ScopeIdentity } from "../identity/m3-scope.js";
import {
  inspectRunStorage,
  publishM6WorkerRecord,
  readM5ManagedRecords,
  readM6WorkerRecords,
  withRunExclusive,
} from "../persistence/store.js";
import {
  assertScopedToolGatewayAuthority,
  type ScopedToolGatewayAuthorityExpectation,
} from "../scoped-tools/gateway.js";
import type { ScopedToolGateway } from "../scoped-tools/types.js";
import {
  assertDocumentValid,
  identifyContractDocument,
  type M3BaselineRuntimeDocument,
  type M3RepositoryIdentityDocument,
  type M3RepositoryStateTokenDocument,
  type M4CommandCatalogDocument,
  type M4ScopedToolPolicyDocument,
  type M5ControlDecisionDocument,
  type M5ControlPolicyDocument,
  type M6WorkerInvocationDocument,
  type M6WorkerResultDocument,
  type ReducerPolicy,
  type TaskDocument,
} from "../schemas/index.js";
import type { FingerprintedFileInput, WorktreeLockHandle } from "../repository/index.js";
import type { M5ImmutableRunAuthoritySources } from "../control/types.js";
import type { RunStorageLocation } from "../persistence/types.js";

const AGENT_MODULE_SPECIFIER = "@earendil-works/pi-agent-core" as const;
const AI_MODULE_SPECIFIER = "@earendil-works/pi-ai" as const;
const PROVIDERS_MODULE_SPECIFIER = "@earendil-works/pi-ai/providers/all" as const;
const PROTOCOL_ID = "m6-direct-read-v0";
const RUNTIME_BOUNDARY_POLICY = "OA-M6-02";
const EXPECTED_VERSION = "0.83.0";
const EXPECTED_AGENT_INTEGRITY = "sha512-RorGp9OH5l3ElpuC5a5ZQ2eWcchZGXflXRzVGkV99y3y6tT+LLNyxoYIdVKvTKWEObwhExeQbTH0fI2tE4iX4g==";
const EXPECTED_AI_INTEGRITY = "sha512-m3IZD4g3er0V8TC9+Vpgw/sjTKqcJlkcIBy/JvsgRubuuik3tAVzyugUg4rVrShIkkOT69mEd34NEqKUIsl6JQ==";
const EXPECTED_AGENT_TARBALL = "https://registry.npmjs.org/@earendil-works/pi-agent-core/-/pi-agent-core-0.83.0.tgz";
const EXPECTED_AI_TARBALL = "https://registry.npmjs.org/@earendil-works/pi-ai/-/pi-ai-0.83.0.tgz";
const EXPECTED_AGENT_TREE_SHA256 = "sha256:692dbf9c0d91d85a93f93b2f88b27e2113bcf88ab4384a4927c3cba8e9a1bb5d";
const EXPECTED_AI_TREE_SHA256 = "sha256:1411e4d6e549a4accfdffe5da0a1de613c461592a1f0754d5db6c9d7c1721488";
const SYNTHETIC_PROVIDER_ID = "provider-primary";
const SYNTHETIC_MODEL_ID = "luna-high";
const MAX_PROMPT_BYTES = 32_768;
const MAX_READ_BYTES = 65_536;
const MAX_TOOL_RESULT_BYTES = 69_632;
const MAX_REPORT_BYTES = 4_096;
const MAX_WALL_TIME_MS = 120_000;

type JsonRecord = { readonly [key: string]: unknown };
type UnknownCallable = (...args: readonly unknown[]) => unknown;

type M6FailureCode =
  | "AUTHORITY_REJECTED"
  | "INVOCATION_ALREADY_INCOMPLETE"
  | "SDK_INITIALIZATION_FAILED"
  | "RUNTIME_IDENTITY_INVALID"
  | "RUNTIME_CAPABILITY_INVALID"
  | "PROVIDER_PROTOCOL_INVALID"
  | "TOOL_REQUEST_INVALID"
  | "TOOL_EXECUTION_FAILED"
  | "WORKER_REPORT_INVALID"
  | "WORKER_DEADLINE_EXCEEDED"
  | "WORKER_ABORTED"
  | "RESULT_PERSISTENCE_FAILED"
  | "CLEANUP_UNCERTAIN";

export class M6WorkerError extends Error {
  public readonly code: M6FailureCode;
  public readonly stage: string;

  public constructor(code: M6FailureCode, message: string, stage = "WORKER") {
    super(message);
    this.name = "M6WorkerError";
    this.code = code;
    this.stage = stage;
  }
}

export interface M6ApprovedResourceInput {
  readonly path: string;
  readonly contentSha256: Sha256Digest;
  readonly dataClass: "PUBLIC_SOURCE" | "PRIVATE_SOURCE" | "SENSITIVE" | "HASH_ONLY";
}

export interface M6DirectReadOnlyWorkerInput {
  readonly stateRoot: string;
  readonly runId: string;
  readonly reducerPolicy: ReducerPolicy;
  readonly m5Policy: M5ControlPolicyDocument;
  readonly m5Decision: M5ControlDecisionDocument;
  readonly runAuthority: M5ImmutableRunAuthoritySources;
  readonly repository: M3RepositoryIdentityDocument;
  readonly baseline: M3BaselineRuntimeDocument;
  readonly m3StateToken: M3RepositoryStateTokenDocument;
  readonly lock: WorktreeLockHandle;
  readonly instructionFiles: readonly FingerprintedFileInput[];
  readonly authorityFiles: readonly FingerprintedFileInput[];
  readonly gateway: ScopedToolGateway;
  readonly m4ToolPolicy: M4ScopedToolPolicyDocument;
  readonly m4CommandCatalog: M4CommandCatalogDocument;
  readonly task: TaskDocument;
  readonly approvedResources: readonly M6ApprovedResourceInput[];
  readonly systemPrompt: string;
  readonly userPrompt: string;
  readonly credentialCallback: (providerId: string) => Promise<string | undefined> | string | undefined;
  readonly signal?: AbortSignal;
}

export interface M6WorkerExecutionResult {
  readonly invocation: M6WorkerInvocationDocument;
  readonly result: M6WorkerResultDocument;
  readonly replayed: boolean;
}

interface ResolvedTarget {
  readonly specifier: string;
  readonly url: string;
  readonly entryPath: string;
}

interface PackageIdentity {
  readonly specifier: string;
  readonly package_name: string;
  readonly package_version: string;
  readonly registry_integrity: string;
  readonly registry_resolved: string;
  readonly resolved_url: string;
  readonly installed_tree_sha256: Sha256Digest;
  readonly rootPath: string;
}

interface RuntimeBoundary {
  readonly agentModule: JsonRecord;
  readonly aiModule: JsonRecord;
  readonly providersModule: JsonRecord;
  readonly agentIdentity: PackageIdentity;
  readonly aiIdentity: PackageIdentity;
  readonly providersTarget: ResolvedTarget;
}

interface ModelsRuntime {
  readonly getProviders: () => readonly unknown[];
  readonly getProvider: (provider: string) => unknown;
  readonly getModel: (provider: string, model: string) => unknown;
  readonly getSupportedThinkingLevels: (model: unknown) => readonly string[];
  readonly streamSimple: (model: unknown, context: unknown, options: unknown) => unknown;
  readonly setProvider: (provider: unknown) => void;
  readonly clearProviders: () => void;
}

interface AgentStateRuntime {
  readonly messages: readonly unknown[];
  readonly pendingToolCalls: ReadonlySet<string>;
  readonly isStreaming: boolean;
  readonly model: unknown;
  readonly thinkingLevel: string;
}

interface AgentRuntime {
  readonly state: AgentStateRuntime;
  readonly prompt: (input: string) => Promise<void>;
  readonly abort: () => void;
  readonly waitForIdle: () => Promise<void>;
  readonly subscribe: (listener: (event: unknown, signal: AbortSignal) => Promise<void> | void) => () => void;
  readonly clearAllQueues: () => void;
  readonly hasQueuedMessages: () => boolean;
  readonly reset: () => void;
}

interface ToolResultRuntime {
  readonly content: readonly JsonRecord[];
  readonly details: JsonRecord;
  readonly terminate?: boolean;
}

interface ToolRuntime {
  readonly name: string;
  readonly label: string;
  readonly description: string;
  readonly parameters: JsonRecord;
  readonly execute: (toolCallId: string, params: unknown, signal?: AbortSignal) => Promise<ToolResultRuntime>;
}

interface PreparedRuntime {
  readonly models: ModelsRuntime;
  readonly model: unknown;
  readonly streamFn: (model: unknown, context: unknown, options?: unknown) => unknown;
  readonly clearProviderState: () => void;
  readonly fauxCallCount: () => number;
  readonly pendingResponseCount: () => number;
}

interface Admission {
  readonly inspection: Awaited<ReturnType<typeof inspectRunStorage>> & {
    readonly revision: number;
    readonly statePointer: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["statePointer"]>;
    readonly workflowState: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["workflowState"]>;
    readonly transitionCommit: NonNullable<Awaited<ReturnType<typeof inspectRunStorage>>["transitionCommit"]>;
  };
  readonly providerId: string;
  readonly modelId: string;
  readonly taskPath: string;
  readonly taskScopeIdentity: Sha256Digest;
  readonly predecessorStateContentSha256: Sha256Digest;
  readonly transitionEventContentSha256: Sha256Digest;
  readonly predictedNextStateContentSha256: Sha256Digest;
  readonly operationId: string;
  readonly reservationDecisionKey: Sha256Digest | null;
  readonly readLength: number;
  readonly attemptNumber: number;
  readonly wallDeadlineMs: number;
}

interface FailureLatch {
  readonly code: M6FailureCode;
  readonly stage: string;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function record(value: unknown, label: string): JsonRecord {
  if (!isJsonRecord(value)) throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} must be an object`, "RUNTIME_GUARD");
  return value;
}

function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} must be an array`, "RUNTIME_GUARD");
  return value;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string") throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} must be a string`, "RUNTIME_GUARD");
  return value;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} must be boolean`, "RUNTIME_GUARD");
  return value;
}

function callable(value: unknown, label: string): UnknownCallable {
  if (typeof value !== "function") throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} must be callable`, "RUNTIME_GUARD");
  return (...args: readonly unknown[]) => Reflect.apply(value, undefined, args);
}

function method(value: JsonRecord, key: string, label: string): UnknownCallable {
  const candidate = value[key];
  if (typeof candidate !== "function") throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label}.${key} must be callable`, "RUNTIME_GUARD");
  return (...args: readonly unknown[]) => Reflect.apply(candidate, value, args);
}

function promiseLike(value: unknown): value is PromiseLike<unknown> {
  return value !== null && typeof value === "object" && "then" in value && typeof value.then === "function";
}

async function promiseResult(value: unknown, label: string): Promise<unknown> {
  if (!promiseLike(value)) throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} did not return a promise`, "RUNTIME_GUARD");
  return value;
}

function readProperty(value: JsonRecord, key: string, label: string): unknown {
  if (!(key in value)) throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label}.${key} is missing`, "RUNTIME_GUARD");
  return value[key];
}

function exactString(value: unknown, expected: string, label: string): void {
  if (value !== expected) throw new M6WorkerError("RUNTIME_CAPABILITY_INVALID", `${label} identity mismatch`, "RUNTIME_GUARD");
}

function safeDigest(value: unknown, label: string): Sha256Digest {
  assertSha256Digest(value, label);
  return value;
}

function fail(code: M6FailureCode, message: string, stage: string): never {
  throw new M6WorkerError(code, message, stage);
}

function isWithin(path: string, root: string): boolean {
  const normalizedPath = resolve(path);
  const normalizedRoot = resolve(root);
  return normalizedPath === normalizedRoot || normalizedPath.startsWith(`${normalizedRoot}/`);
}

async function canonicalDirectory(path: string, label: string): Promise<string> {
  const normalized = resolve(path);
  const stats = await lstat(normalized);
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail("RUNTIME_IDENTITY_INVALID", `${label} is not a regular canonical directory`, "RUNTIME_IDENTITY");
  const physical = await realpath(normalized);
  if (physical !== normalized) fail("RUNTIME_IDENTITY_INVALID", `${label} is symlinked`, "RUNTIME_IDENTITY");
  return normalized;
}

async function canonicalFile(path: string, label: string): Promise<string> {
  const normalized = resolve(path);
  const stats = await lstat(normalized);
  if (!stats.isFile() || stats.isSymbolicLink()) fail("RUNTIME_IDENTITY_INVALID", `${label} is not a regular canonical file`, "RUNTIME_IDENTITY");
  const physical = await realpath(normalized);
  if (physical !== normalized) fail("RUNTIME_IDENTITY_INVALID", `${label} is symlinked`, "RUNTIME_IDENTITY");
  return normalized;
}

async function readJsonRecord(path: string, label: string): Promise<JsonRecord> {
  try {
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    return record(value, label);
  } catch (error: unknown) {
    if (error instanceof M6WorkerError) throw error;
    fail("RUNTIME_IDENTITY_INVALID", `${label} is not valid JSON`, "RUNTIME_IDENTITY");
  }
}

function isNotFound(error: unknown): boolean {
  return error !== null && typeof error === "object" && "code" in error && error["code"] === "ENOENT";
}

async function optionalJsonRecord(path: string, label: string): Promise<JsonRecord | undefined> {
  try { await canonicalFile(path, label); }
  catch (error: unknown) { if (isNotFound(error)) return undefined; throw error; }
  return readJsonRecord(path, label);
}

async function collectRegularFiles(root: string, current: string): Promise<readonly string[]> {
  const entries = await readdir(current, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = join(current, entry.name);
    if (entry.isSymbolicLink()) fail("RUNTIME_IDENTITY_INVALID", `Symlink in installed tree: ${path}`, "RUNTIME_IDENTITY");
    if (entry.isDirectory()) files.push(...await collectRegularFiles(root, path));
    else if (entry.isFile()) files.push(path);
    else fail("RUNTIME_IDENTITY_INVALID", `Special file in installed tree: ${path}`, "RUNTIME_IDENTITY");
  }
  return files;
}

async function installedTreeDigest(root: string): Promise<Sha256Digest> {
  const files = [...await collectRegularFiles(root, root)].sort((left, right) => {
    const a = relative(root, left);
    const b = relative(root, right);
    return a < b ? -1 : a > b ? 1 : 0;
  });
  const hash = createHash("sha256");
  for (const file of files) {
    const relativePath = relative(root, file);
    const bytes = await readFile(file);
    hash.update(`file\0${relativePath}\0${bytes.byteLength}\0`);
    hash.update(bytes);
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

function parseFileUrl(value: string, label: string): URL {
  let parsed: URL;
  try { parsed = new URL(value); }
  catch { fail("RUNTIME_IDENTITY_INVALID", `${label} is not a URL`, "RUNTIME_IDENTITY"); }
  if (parsed.protocol !== "file:" || parsed.username !== "" || parsed.password !== "" || parsed.host !== "" || parsed.search !== "" || parsed.hash !== "") {
    fail("RUNTIME_IDENTITY_INVALID", `${label} is not a plain file URL`, "RUNTIME_IDENTITY");
  }
  return parsed;
}

async function resolvePublicEsm(specifier: string, nodeModulesRoot: string): Promise<ResolvedTarget> {
  let resolvedUrl: string;
  try { resolvedUrl = import.meta.resolve(specifier); }
  catch { fail("RUNTIME_IDENTITY_INVALID", `${specifier} ESM resolution failed`, "RUNTIME_IDENTITY"); }
  const parsed = parseFileUrl(resolvedUrl, `${specifier} ESM resolution`);
  const entryPath = resolve(fileURLToPath(parsed));
  if (!isWithin(entryPath, nodeModulesRoot)) fail("RUNTIME_IDENTITY_INVALID", `${specifier} resolves outside node_modules`, "RUNTIME_IDENTITY");
  await canonicalFile(entryPath, `${specifier} ESM target`);
  return { specifier, url: resolvedUrl, entryPath };
}

async function findPackageRoot(entryPath: string, packageName: string, expectedVersion: string, nodeModulesRoot: string): Promise<string> {
  const boundary = resolve(nodeModulesRoot);
  let current = resolve(dirname(entryPath));
  while (current !== boundary) {
    if (!isWithin(current, boundary)) fail("RUNTIME_IDENTITY_INVALID", `${packageName} package-root walk escaped node_modules`, "RUNTIME_IDENTITY");
    await canonicalDirectory(current, `${packageName} package-root walk`);
    const packageJson = await optionalJsonRecord(join(current, "package.json"), `${packageName} package.json`);
    if (packageJson !== undefined) {
      exactString(packageJson["name"], packageName, `${packageName} package name`);
      exactString(packageJson["version"], expectedVersion, `${packageName} package version`);
      return current;
    }
    current = resolve(current, "..");
  }
  fail("RUNTIME_IDENTITY_INVALID", `${packageName} package root was not found`, "RUNTIME_IDENTITY");
}

async function matchingPackageRoots(root: string, packageName: string, current: string): Promise<readonly string[]> {
  const entries = await readdir(current, { withFileTypes: true });
  const matches: string[] = [];
  const packageJson = await optionalJsonRecord(join(current, "package.json"), `${packageName} package.json`);
  if (packageJson !== undefined && packageJson["name"] === packageName) matches.push(resolve(current));
  for (const entry of entries) {
    const path = join(current, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) matches.push(...await matchingPackageRoots(root, packageName, path));
  }
  return matches;
}

function lockEntry(lock: JsonRecord, packagePath: string, label: string): JsonRecord {
  const packages = record(lock["packages"], `${label}.packages`);
  return record(packages[packagePath], `${label}.${packagePath}`);
}

async function verifyPackage(
  target: ResolvedTarget,
  packageName: string,
  expectedIntegrity: string,
  expectedResolved: string,
  expectedTree: Sha256Digest,
  nodeModulesRoot: string,
  lock: JsonRecord,
): Promise<PackageIdentity> {
  const rootPath = await findPackageRoot(target.entryPath, packageName, EXPECTED_VERSION, nodeModulesRoot);
  const expectedRoot = resolve(nodeModulesRoot, packageName);
  if (rootPath !== expectedRoot || !isWithin(rootPath, nodeModulesRoot)) fail("RUNTIME_IDENTITY_INVALID", `${packageName} package root is unexpected`, "RUNTIME_IDENTITY");
  await canonicalDirectory(rootPath, `${packageName} package root`);
  const packageJson = await readJsonRecord(join(rootPath, "package.json"), `${packageName} package.json`);
  exactString(packageJson["name"], packageName, `${packageName} package name`);
  exactString(packageJson["version"], EXPECTED_VERSION, `${packageName} package version`);
  const entry = lockEntry(lock, `node_modules/${packageName}`, packageName);
  exactString(entry["version"], EXPECTED_VERSION, `${packageName} lock version`);
  exactString(entry["resolved"], expectedResolved, `${packageName} lock resolved`);
  exactString(entry["integrity"], expectedIntegrity, `${packageName} lock integrity`);
  const roots = await matchingPackageRoots(nodeModulesRoot, packageName, nodeModulesRoot);
  if (roots.length !== 1 || roots[0] !== rootPath) fail("RUNTIME_IDENTITY_INVALID", `${packageName} has duplicate or substituted roots`, "RUNTIME_IDENTITY");
  const tree = await installedTreeDigest(rootPath);
  if (tree !== expectedTree) fail("RUNTIME_IDENTITY_INVALID", `${packageName} installed-tree digest mismatch`, "RUNTIME_IDENTITY");
  return {
    specifier: target.specifier,
    package_name: packageName,
    package_version: EXPECTED_VERSION,
    registry_integrity: expectedIntegrity,
    registry_resolved: expectedResolved,
    resolved_url: target.url,
    installed_tree_sha256: tree,
    rootPath,
  };
}

function moduleIdentity(identity: PackageIdentity): JsonRecord {
  return {
    specifier: identity.specifier,
    package_name: identity.package_name,
    package_version: identity.package_version,
    registry_integrity: identity.registry_integrity,
    registry_resolved: identity.registry_resolved,
    resolved_url: identity.resolved_url,
    installed_tree_sha256: identity.installed_tree_sha256,
  };
}

async function installationRoot(): Promise<string> {
  let current = resolve(dirname(fileURLToPath(import.meta.url)));
  while (true) {
    const candidate = join(current, "package.json");
    try {
      const packageJson = await optionalJsonRecord(candidate, candidate);
      if (packageJson?.["name"] === "pi-bounded-coding-workflow") return current;
    } catch (error: unknown) {
      if (!isNotFound(error)) throw error;
    }
    const parent = resolve(current, "..");
    if (parent === current) fail("RUNTIME_IDENTITY_INVALID", "Installation package root was not found", "RUNTIME_IDENTITY");
    current = parent;
  }
}

async function loadRuntimeBoundary(): Promise<RuntimeBoundary> {
  const root = await installationRoot();
  const nodeModulesRoot = await canonicalDirectory(join(root, "node_modules"), "installation node_modules");
  const lockPath = await canonicalFile(join(root, "package-lock.json"), "installation package-lock.json");
  const lock = await readJsonRecord(lockPath, "installation package-lock.json");
  const rootEntry = lockEntry(lock, "", "installation lockfile");
  const rootDependencies = record(rootEntry["dependencies"], "installation root dependencies");
  exactString(rootDependencies["@earendil-works/pi-agent-core"], EXPECTED_VERSION, "root Agent dependency");
  exactString(rootDependencies["@earendil-works/pi-ai"], EXPECTED_VERSION, "root AI dependency");
  const agentTarget = await resolvePublicEsm(AGENT_MODULE_SPECIFIER, nodeModulesRoot);
  const aiTarget = await resolvePublicEsm(AI_MODULE_SPECIFIER, nodeModulesRoot);
  const providersTarget = await resolvePublicEsm(PROVIDERS_MODULE_SPECIFIER, nodeModulesRoot);
  const agentIdentity = await verifyPackage(agentTarget, "@earendil-works/pi-agent-core", EXPECTED_AGENT_INTEGRITY, EXPECTED_AGENT_TARBALL, EXPECTED_AGENT_TREE_SHA256, nodeModulesRoot, lock);
  const aiIdentity = await verifyPackage(aiTarget, "@earendil-works/pi-ai", EXPECTED_AI_INTEGRITY, EXPECTED_AI_TARBALL, EXPECTED_AI_TREE_SHA256, nodeModulesRoot, lock);
  if (!isWithin(providersTarget.entryPath, aiIdentity.rootPath)) fail("RUNTIME_IDENTITY_INVALID", "providers/all is outside the verified Pi AI root", "RUNTIME_IDENTITY");
  const providersRoot = await findPackageRoot(providersTarget.entryPath, "@earendil-works/pi-ai", EXPECTED_VERSION, nodeModulesRoot);
  if (providersRoot !== aiIdentity.rootPath) fail("RUNTIME_IDENTITY_INVALID", "providers/all root differs from Pi AI root", "RUNTIME_IDENTITY");

  type FixedRuntimeSpecifier = typeof AGENT_MODULE_SPECIFIER | typeof AI_MODULE_SPECIFIER | typeof PROVIDERS_MODULE_SPECIFIER;
  const importFixed = async (specifier: FixedRuntimeSpecifier): Promise<unknown> => import(specifier);
  const agentModule = record(await importFixed(AGENT_MODULE_SPECIFIER), "Agent module");
  const aiModule = record(await importFixed(AI_MODULE_SPECIFIER), "AI module");
  const providersModule = record(await importFixed(PROVIDERS_MODULE_SPECIFIER), "providers module");
  const agentAfter = await resolvePublicEsm(AGENT_MODULE_SPECIFIER, nodeModulesRoot);
  const aiAfter = await resolvePublicEsm(AI_MODULE_SPECIFIER, nodeModulesRoot);
  const providersAfter = await resolvePublicEsm(PROVIDERS_MODULE_SPECIFIER, nodeModulesRoot);
  if (agentAfter.url !== agentTarget.url || aiAfter.url !== aiTarget.url || providersAfter.url !== providersTarget.url) {
    fail("RUNTIME_IDENTITY_INVALID", "ESM URL changed across import", "RUNTIME_IDENTITY");
  }
  if (agentAfter.entryPath !== agentTarget.entryPath || aiAfter.entryPath !== aiTarget.entryPath || providersAfter.entryPath !== providersTarget.entryPath) {
    fail("RUNTIME_IDENTITY_INVALID", "ESM entry path changed across import", "RUNTIME_IDENTITY");
  }
  await verifyPackage(agentAfter, "@earendil-works/pi-agent-core", EXPECTED_AGENT_INTEGRITY, EXPECTED_AGENT_TARBALL, EXPECTED_AGENT_TREE_SHA256, nodeModulesRoot, lock);
  await verifyPackage(aiAfter, "@earendil-works/pi-ai", EXPECTED_AI_INTEGRITY, EXPECTED_AI_TARBALL, EXPECTED_AI_TREE_SHA256, nodeModulesRoot, lock);
  const agentExport = readProperty(agentModule, "Agent", "Agent module");
  if (typeof agentExport !== "function") fail("RUNTIME_CAPABILITY_INVALID", "Agent export is not constructible", "RUNTIME_GUARD");
  try { Reflect.construct(String, [], agentExport); }
  catch { fail("RUNTIME_CAPABILITY_INVALID", "Agent export is not constructible", "RUNTIME_GUARD"); }
  for (const name of ["createModels", "fauxProvider", "fauxAssistantMessage", "fauxToolCall", "getSupportedThinkingLevels"]) {
    callable(readProperty(aiModule, name, "AI module"), `AI module.${name}`);
  }
  for (const name of ["builtinModels", "getBuiltinProviders", "getBuiltinModels"]) {
    callable(readProperty(providersModule, name, "providers module"), `providers module.${name}`);
  }
  return { agentModule, aiModule, providersModule, agentIdentity, aiIdentity, providersTarget };
}

function guardModels(value: unknown): ModelsRuntime {
  const object = record(value, "Models collection");
  const getProvidersMethod = method(object, "getProviders", "Models");
  const getProviderMethod = method(object, "getProvider", "Models");
  const getModelMethod = method(object, "getModel", "Models");
  const streamSimpleMethod = method(object, "streamSimple", "Models");
  const setProviderMethod = method(object, "setProvider", "Models");
  const clearProvidersMethod = method(object, "clearProviders", "Models");
  return {
    getProviders: () => array(getProvidersMethod(), "Models providers"),
    getProvider: (provider) => getProviderMethod(provider),
    getModel: (provider, model) => getModelMethod(provider, model),
    getSupportedThinkingLevels: () => [],
    streamSimple: (model, context, options) => streamSimpleMethod(model, context, options),
    setProvider: (provider) => { setProviderMethod(provider); },
    clearProviders: () => { clearProvidersMethod(); },
  };
}

function assertAgentTools(value: unknown): void {
  const tools = array(value, "Agent state tools");
  if (tools.length !== 2) fail("RUNTIME_CAPABILITY_INVALID", "Agent must expose exactly two tools", "RUNTIME_GUARD");
  const names = tools.map((tool, index) => {
    const toolRecord = record(tool, `Agent tool ${index}`);
    string(toolRecord["label"], `Agent tool ${index} label`);
    string(toolRecord["description"], `Agent tool ${index} description`);
    record(toolRecord["parameters"], `Agent tool ${index} parameters`);
    callable(toolRecord["execute"], `Agent tool ${index}.execute`);
    return string(toolRecord["name"], `Agent tool ${index} name`);
  });
  if (names[0] !== "read_scoped" || names[1] !== "submit_worker_report" || new Set(names).size !== 2) fail("RUNTIME_CAPABILITY_INVALID", "Agent tool registration is not the bounded direct pair", "RUNTIME_GUARD");
}

function guardAgent(value: unknown): AgentRuntime {
  const object = record(value, "Agent instance");
  const promptMethod = method(object, "prompt", "Agent");
  const abortMethod = method(object, "abort", "Agent");
  const idleMethod = method(object, "waitForIdle", "Agent");
  const subscribeMethod = method(object, "subscribe", "Agent");
  const clearQueuesMethod = method(object, "clearAllQueues", "Agent");
  const queuedMethod = method(object, "hasQueuedMessages", "Agent");
  const resetMethod = method(object, "reset", "Agent");
  const stateValue = (): AgentStateRuntime => {
    const state = record(object["state"], "Agent state");
    const messages = array(state["messages"], "Agent state messages");
    assertAgentTools(state["tools"]);
    const pending = state["pendingToolCalls"];
    if (!(pending instanceof Set)) fail("RUNTIME_CAPABILITY_INVALID", "Agent pendingToolCalls is not a Set", "RUNTIME_GUARD");
    return {
      messages,
      pendingToolCalls: pending,
      isStreaming: boolean(state["isStreaming"], "Agent state isStreaming"),
      model: state["model"],
      thinkingLevel: string(state["thinkingLevel"], "Agent state thinkingLevel"),
    };
  };
  return {
    get state() { return stateValue(); },
    prompt: async (input) => { await promiseResult(promptMethod(input), "Agent.prompt"); },
    abort: () => { abortMethod(); },
    waitForIdle: async () => { await promiseResult(idleMethod(), "Agent.waitForIdle"); },
    subscribe: (listener) => {
      const unsubscribe = subscribeMethod(listener);
      if (typeof unsubscribe !== "function") fail("RUNTIME_CAPABILITY_INVALID", "Agent.subscribe did not return an unsubscribe function", "RUNTIME_GUARD");
      return () => { Reflect.apply(unsubscribe, undefined, []); };
    },
    clearAllQueues: () => { clearQueuesMethod(); },
    hasQueuedMessages: () => boolean(queuedMethod(), "Agent queue state"),
    reset: () => { resetMethod(); },
  };
}

function constructAgent(moduleValue: JsonRecord, options: JsonRecord): AgentRuntime {
  const constructorValue = readProperty(moduleValue, "Agent", "Agent module");
  if (typeof constructorValue !== "function") fail("RUNTIME_CAPABILITY_INVALID", "Agent export is not constructible", "RUNTIME_GUARD");
  let value: object;
  try { value = Reflect.construct(constructorValue, [options]); }
  catch { fail("SDK_INITIALIZATION_FAILED", "Agent construction failed", "SDK_INITIALIZATION"); }
  return guardAgent(value);
}

function providerIdsFromCatalogue(moduleValue: JsonRecord): readonly string[] {
  const providers = array(method(moduleValue, "getBuiltinProviders", "providers module")(), "official provider catalogue");
  const ids = providers.map((value, index) => string(value, `official provider catalogue[${index}]`));
  if (new Set(ids).size !== ids.length) fail("RUNTIME_CAPABILITY_INVALID", "Official provider catalogue contains duplicate IDs", "RUNTIME_GUARD");
  return ids;
}

function verifyOfficialCatalogue(moduleValue: JsonRecord): readonly string[] {
  const ids = providerIdsFromCatalogue(moduleValue);
  const getModels = method(moduleValue, "getBuiltinModels", "providers module");
  for (const providerId of ids) {
    const models = array(getModels(providerId), `official models for ${providerId}`);
    const modelIds = models.map((value, index) => {
      const model = record(value, `official model ${providerId}[${index}]`);
      exactString(model["provider"], providerId, `official model ${providerId}[${index}] provider`);
      return string(model["id"], `official model ${providerId}[${index}] ID`);
    });
    if (new Set(modelIds).size !== modelIds.length) fail("RUNTIME_CAPABILITY_INVALID", `Official model catalogue contains duplicate IDs for ${providerId}`, "RUNTIME_GUARD");
  }
  return ids;
}

function modelFromCatalogue(moduleValue: JsonRecord, providerId: string, modelId: string): unknown {
  const models = array(method(moduleValue, "getBuiltinModels", "providers module")(providerId), "official model catalogue");
  const selected = models.find((value) => record(value, "official model")["id"] === modelId);
  if (selected === undefined) fail("RUNTIME_CAPABILITY_INVALID", "M5 model is absent from the official catalogue", "RUNTIME_GUARD");
  return selected;
}

function modelIdentity(model: unknown, providerId: string, modelId: string): void {
  const value = record(model, "selected model");
  exactString(value["provider"], providerId, "selected model provider");
  exactString(value["id"], modelId, "selected model ID");
}

function assistantToolMessage(aiModule: JsonRecord, toolName: string, arguments_: JsonRecord): unknown {
  const toolCall = method(aiModule, "fauxToolCall", "AI module") (toolName, arguments_);
  return method(aiModule, "fauxAssistantMessage", "AI module")(toolCall, { stopReason: "toolUse" });
}

function fauxSecondResponse(aiModule: JsonRecord, contextValue: unknown): unknown {
  const context = record(contextValue, "faux response context");
  const messages = array(context["messages"], "faux response messages");
  let evidence: string | undefined;
  for (const messageValue of messages) {
    const message = record(messageValue, "faux response message");
    if (message["role"] !== "toolResult" || message["toolName"] !== "read_scoped") continue;
    const details = record(message["details"], "read tool result details");
    const candidate = details["m4ResultContentSha256"];
    if (typeof candidate === "string") evidence = candidate;
  }
  if (evidence === undefined) return method(aiModule, "fauxAssistantMessage", "AI module")("missing read evidence", { stopReason: "stop" });
  return assistantToolMessage(aiModule, "submit_worker_report", {
    status: "COMPLETED",
    summary: "Completed the bounded read-only task from the authoritative primary evidence.",
    evidence_content_sha256: [evidence],
  });
}

function streamOptions(value: unknown): JsonRecord {
  if (!isJsonRecord(value)) return { maxRetries: 0, maxRetryDelayMs: 0 };
  return { ...value, maxRetries: 0, maxRetryDelayMs: 0 };
}

function prepareRuntime(boundary: RuntimeBoundary, providerId: string, modelId: string): PreparedRuntime {
  const getSupportedThinkingLevels = method(boundary.aiModule, "getSupportedThinkingLevels", "AI module");
  const createModels = method(boundary.aiModule, "createModels", "AI module");
  const builtinModels = method(boundary.providersModule, "builtinModels", "providers module");
  const officialIds = verifyOfficialCatalogue(boundary.providersModule);
  let models: ModelsRuntime;
  let model: unknown;
  let clearProviderState: () => void = () => undefined;
  let fauxCallCount: () => number = () => 0;
  let pendingResponseCount: () => number = () => 0;

  if (providerId === SYNTHETIC_PROVIDER_ID && modelId === SYNTHETIC_MODEL_ID) {
    const faux = record(method(boundary.aiModule, "fauxProvider", "AI module")({
      api: "m6-direct-faux-api",
      provider: SYNTHETIC_PROVIDER_ID,
      models: [{ id: SYNTHETIC_MODEL_ID, name: SYNTHETIC_MODEL_ID, reasoning: true, input: ["text"] }],
      tokensPerSecond: 0,
    }), "faux provider");
    const provider = readProperty(faux, "provider", "faux provider");
    models = guardModels(createModels());
    models.setProvider(provider);
    const registeredProvider = record(models.getProvider(providerId), "registered faux provider");
    exactString(registeredProvider["id"], providerId, "registered faux provider ID");
    model = models.getModel(providerId, modelId);
    const setResponses = method(faux, "setResponses", "faux provider");
    const getPendingResponseCount = method(faux, "getPendingResponseCount", "faux provider");
    pendingResponseCount = () => {
      const count = getPendingResponseCount();
      if (typeof count !== "number" || !Number.isSafeInteger(count)) return -1;
      return count;
    };
    const first = assistantToolMessage(boundary.aiModule, "read_scoped", { read_id: "primary" });
    const second = (context: unknown): unknown => fauxSecondResponse(boundary.aiModule, context);
    setResponses([first, second]);
    clearProviderState = () => { setResponses([]); };
    const state = record(readProperty(faux, "state", "faux provider"), "faux provider state");
    fauxCallCount = () => {
      const count = readProperty(state, "callCount", "faux provider state");
      if (typeof count !== "number" || !Number.isSafeInteger(count)) return 0;
      return count;
    };
  } else {
    if (!officialIds.includes(providerId)) fail("RUNTIME_CAPABILITY_INVALID", "M5 provider is absent from the official catalogue", "RUNTIME_GUARD");
    modelFromCatalogue(boundary.providersModule, providerId, modelId);
    models = guardModels(builtinModels());
    const registeredProvider = record(models.getProvider(providerId), "registered catalogue provider");
    exactString(registeredProvider["id"], providerId, "registered catalogue provider ID");
    model = models.getModel(providerId, modelId);
  }
  if (model === undefined) fail("RUNTIME_CAPABILITY_INVALID", "Exact provider/model lookup returned no model", "RUNTIME_GUARD");
  modelIdentity(model, providerId, modelId);
  const levels = array(getSupportedThinkingLevels(model), "supported thinking levels").map((value, index) => string(value, `thinking level[${index}]`));
  if (!levels.includes("high")) fail("RUNTIME_CAPABILITY_INVALID", "Selected model does not support high effort", "RUNTIME_GUARD");
  const preparedModels: ModelsRuntime = {
    ...models,
    getSupportedThinkingLevels: () => levels,
  };
  return {
    models: preparedModels,
    model,
    clearProviderState,
    streamFn: (streamModel, context, options) => {
      const stream = preparedModels.streamSimple(streamModel, context, streamOptions(options));
      const streamRecord = record(stream, "provider stream");
      if (typeof streamRecord["result"] !== "function" || !(Symbol.asyncIterator in streamRecord)) {
        fail("RUNTIME_CAPABILITY_INVALID", "Provider stream lacks async iteration and result settlement", "RUNTIME_GUARD");
      }
      return stream;
    },
    fauxCallCount,
    pendingResponseCount,
  };
}

function reportResource(resource: M6ApprovedResourceInput): JsonRecord {
  return { path: resource.path, content_sha256: resource.contentSha256, data_class: resource.dataClass };
}

function assertResources(input: M6DirectReadOnlyWorkerInput): void {
  const expected = [...input.instructionFiles, ...input.authorityFiles];
  if (input.approvedResources.length !== expected.length) fail("AUTHORITY_REJECTED", "Approved resource inventory is incomplete", "M1_M5_ADMISSION");
  const actual = new Map(input.approvedResources.map((resource) => [resource.path, resource]));
  for (const item of expected) {
    const resource = actual.get(item.path);
    if (resource === undefined || resource.contentSha256 !== item.expectedSha256) fail("AUTHORITY_REJECTED", "Approved resource identity differs from M3 authority", "M1_M5_ADMISSION");
    if (resource.dataClass === "HASH_ONLY") continue;
  }
  if (input.approvedResources.some((resource) => resource.dataClass === "HASH_ONLY" && resource.path.length === 0)) {
    fail("AUTHORITY_REJECTED", "Approved resource path is invalid", "M1_M5_ADMISSION");
  }
}

function limitFromPolicy(policy: M5ControlPolicyDocument, dimension: string, fallback: number): number {
  const value = policy.limits.find((entry) => entry.dimension === dimension)?.hard_limit;
  return value === null || value === undefined ? fallback : Math.min(fallback, value);
}

async function admit(input: M6DirectReadOnlyWorkerInput, completedReplayAuthority = false): Promise<Admission> {
  for (const document of [input.reducerPolicy, input.m5Policy, input.m5Decision, input.runAuthority.repositoryIdentity, input.runAuthority.contract, input.runAuthority.routeMap, input.runAuthority.routeMapApproval, input.repository, input.baseline, input.m3StateToken, input.m4ToolPolicy, input.m4CommandCatalog, input.task]) {
    if (document === undefined) fail("AUTHORITY_REJECTED", "Required authority document is absent", "M1_M5_ADMISSION");
  }
  assertDocumentValid("pi_gacw_repository_identity_v0", input.repository);
  assertDocumentValid("pi_gacw_baseline_runtime_v0", input.baseline);
  assertDocumentValid("pi_gacw_repository_state_token_v0", input.m3StateToken);
  assertDocumentValid("pi_gacw_scoped_tool_policy_v0", input.m4ToolPolicy);
  assertDocumentValid("pi_gacw_command_catalog_v0", input.m4CommandCatalog);
  assertDocumentValid("pi_gacw_task_v0", input.task);
  if (input.repository.content_sha256 !== input.runAuthority.repositoryIdentity.content_sha256) fail("AUTHORITY_REJECTED", "Repository authority differs from M5 authority", "M1_M5_ADMISSION");
  if (input.baseline.repository.content_sha256 !== input.repository.content_sha256 || input.m3StateToken.repository_identity_content_sha256 !== input.repository.content_sha256) fail("AUTHORITY_REJECTED", "M3 repository provenance differs", "M1_M5_ADMISSION");
  if (input.baseline.run_id !== input.runId || input.m3StateToken.run_id !== input.runId || input.m4ToolPolicy.run_id !== input.runId || input.m4CommandCatalog.run_id !== input.runId || input.task.content_sha256 === undefined) fail("AUTHORITY_REJECTED", "M3/M4/task run identity differs", "M1_M5_ADMISSION");
  assertResources(input);
  if (input.systemPrompt.length === 0 || input.userPrompt.length === 0 || Buffer.byteLength(input.systemPrompt, "utf8") + Buffer.byteLength(input.userPrompt, "utf8") > MAX_PROMPT_BYTES) fail("AUTHORITY_REJECTED", "Prompt envelope is empty or exceeds its bound", "M1_M5_ADMISSION");
  const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
  if (inspection.status !== "HEALTHY" || inspection.revision === null || inspection.statePointer === null || inspection.workflowState === null || inspection.transitionCommit === null) fail("AUTHORITY_REJECTED", "Run storage is not healthy and authoritative", "M1_M5_ADMISSION");
  const committedInspection: Admission["inspection"] = {
    ...inspection,
    revision: inspection.revision,
    statePointer: inspection.statePointer,
    workflowState: inspection.workflowState,
    transitionCommit: inspection.transitionCommit,
  };
  try { assertControlPolicyAuthority(input.m5Policy, committedInspection.workflowState, input.reducerPolicy, input.runId, false, input.runAuthority); }
  catch { fail("AUTHORITY_REJECTED", "M5 policy or immutable route authority is invalid", "M1_M5_ADMISSION"); }
  const records = await readM5ManagedRecords({ stateRoot: input.stateRoot, runId: input.runId });
  if (!records.policies.some((value) => value.content_sha256 === input.m5Policy.content_sha256) || !records.decisions.some((value) => value.content_sha256 === input.m5Decision.content_sha256)) fail("AUTHORITY_REJECTED", "M5 policy or decision is not durably published", "M1_M5_ADMISSION");
  const isAuthoritative = (kind: string, digest: string): boolean => inspection.managedRecordClassifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest && entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
  if (!completedReplayAuthority && (!isAuthoritative("M5_CONTROL_POLICY", input.m5Policy.content_sha256) || !isAuthoritative("M5_CONTROL_DECISION", input.m5Decision.content_sha256))) fail("AUTHORITY_REJECTED", "M5 policy or decision is not authoritative", "M1_M5_ADMISSION");
  if (!isAuthoritative("M3_REPOSITORY_STATE_TOKEN", input.m3StateToken.content_sha256)) fail("AUTHORITY_REJECTED", "M3 state token is not authoritative", "M1_M5_ADMISSION");
  const m4PolicyClass = inspection.managedRecordClassifications.find((entry) => entry.object.kind === "M4_TOOL_POLICY" && entry.object.contentSha256 === input.m4ToolPolicy.content_sha256);
  const m4CatalogClass = inspection.managedRecordClassifications.find((entry) => entry.object.kind === "M4_COMMAND_CATALOG" && entry.object.contentSha256 === input.m4CommandCatalog.content_sha256);
  if (m4PolicyClass === undefined || m4CatalogClass === undefined || m4PolicyClass.classification === "INVALID_MANAGED_RECORD" || m4CatalogClass.classification === "INVALID_MANAGED_RECORD") fail("AUTHORITY_REJECTED", "M4 policy or catalog is absent or invalid", "M1_M5_ADMISSION");
  const state = committedInspection.workflowState;
  const commit = committedInspection.transitionCommit;
  if (state.execution_mode !== "DIRECT_LUNA_HIGH" || state.phase !== "DIRECT_ATTEMPT_RUNNING" || state.active_task_id !== input.task.task_id) fail("AUTHORITY_REJECTED", "Current state is not the direct running task phase", "M1_M5_ADMISSION");
  const runtimeTask = state.tasks.find((task) => task.task_id === input.task.task_id);
  if (runtimeTask === undefined || runtimeTask.status !== "RUNNING" || runtimeTask.attempts !== 1 || runtimeTask.verification_completed || runtimeTask.postflight_completed) fail("AUTHORITY_REJECTED", "Active task lifecycle is not the first running attempt", "M1_M5_ADMISSION");
  const reducerTask = input.reducerPolicy.tasks.find((task) => task.task_id === input.task.task_id);
  if (reducerTask === undefined || input.task.assigned_role !== "LUNA_EXECUTOR") fail("AUTHORITY_REJECTED", "Task is not the exact M1/M5 LUNA_EXECUTOR task", "M1_M5_ADMISSION");
  if (input.task.scope.readable_paths.length !== 1) fail("AUTHORITY_REJECTED", "Read-only task does not have exactly one readable target", "M1_M5_ADMISSION");
  const taskPath = input.task.scope.readable_paths[0];
  if (taskPath === undefined || !input.m4ToolPolicy.readable_paths.some((rule) => rule.kind === "EXACT" && rule.path === taskPath)) fail("AUTHORITY_REJECTED", "The sole task target is not an exact M4 readable path", "M1_M5_ADMISSION");
  const route = input.runAuthority.routeMap.routes.find((candidate) => candidate.logical_role === "LUNA_EXECUTOR");
  if (route === undefined || route.effort !== "high" || route.provider_id.length === 0 || route.model_id.length === 0) fail("AUTHORITY_REJECTED", "LUNA_EXECUTOR route authority is invalid", "M1_M5_ADMISSION");
  if (input.runAuthority.routeMap.fallback || input.runAuthority.routeMap.provider_managed_multi_agent || !input.m5Policy.route_map_approved) fail("AUTHORITY_REJECTED", "Fallback or provider-managed multi-agent authority is enabled", "M1_M5_ADMISSION");
  const decision = input.m5Decision;
  const reservation = decision.reservation;
  if (decision.run_id !== input.runId || decision.repository_identity_content_sha256 !== input.repository.content_sha256 || decision.worktree_key !== input.repository.worktree_key || decision.policy_content_sha256 !== input.m5Policy.content_sha256 || decision.tool_policy_content_sha256 !== input.m4ToolPolicy.content_sha256 || decision.command_catalog_content_sha256 !== input.m4CommandCatalog.content_sha256 || decision.current_state_content_sha256 !== commit.previous_workflow_state_content_sha256 || decision.predicted_next_state_content_sha256 !== state.content_sha256 || decision.transition_event === null || decision.transition_event.content_sha256 !== commit.transition_event_content_sha256 || decision.transition_event.event_type !== "START_DIRECT_ATTEMPT" || decision.decision_kind !== "CONTINUATION" || decision.intent !== "AUTHORIZE_WORK" || decision.outcome !== "AUTHORIZE" || decision.selected_route !== "CONTINUE_ADMITTED_OPERATION" || decision.operation_id === null || reservation === null || reservation.status !== "ACTIVE" || reservation.logical_role !== "LUNA_EXECUTOR" || reservation.reserved_route !== "DIRECT_LUNA_HIGH" || reservation.future_operation_id !== decision.operation_id || reservation.reserved_state_content_sha256 !== commit.previous_workflow_state_content_sha256 || reservation.reserved_policy_content_sha256 !== input.m5Policy.content_sha256) fail("AUTHORITY_REJECTED", "M5 direct continuation decision or reservation is invalid", "M1_M5_ADMISSION");
  if (decision.operation_id === null || reservation === null) fail("AUTHORITY_REJECTED", "M5 decision lacks a direct operation reservation", "M1_M5_ADMISSION");
  const predecessorStateContentSha256 = safeDigest(commit.previous_workflow_state_content_sha256, "M5 predecessor state");
  const transitionEventContentSha256 = safeDigest(commit.transition_event_content_sha256, "M5 transition event");
  const predictedNextStateContentSha256 = safeDigest(decision.predicted_next_state_content_sha256, "M5 predicted state");
  const taskScopeIdentity = safeDigest(input.m3StateToken.task_scope_identity, "M3 task scope identity");
  if (m3ScopeIdentity(input.task.scope.editable_paths, input.task.scope.frozen_paths) !== taskScopeIdentity || input.m5Policy.scope_sha256 !== taskScopeIdentity) fail("AUTHORITY_REJECTED", "Task scope identity differs from M3/M5 authority", "M1_M5_ADMISSION");
  if (input.m5Policy.tool_policy_content_sha256 !== input.m4ToolPolicy.content_sha256 || input.m5Policy.command_catalog_content_sha256 !== input.m4CommandCatalog.content_sha256) fail("AUTHORITY_REJECTED", "M5 policy does not bind the supplied M4 authorities", "M1_M5_ADMISSION");
  const reservationDecisionKey = reservation.reservation_decision_key === undefined ? null : safeDigest(reservation.reservation_decision_key, "M5 reservation decision key");
  const workerReservation = reservation.amounts.find((entry) => entry.dimension === "WORKER_INVOCATION");
  if (workerReservation === undefined || workerReservation.amount < 1) fail("AUTHORITY_REJECTED", "M5 reservation has no active worker envelope", "M1_M5_ADMISSION");
  if (input.m4ToolPolicy.repository_identity_content_sha256 !== input.repository.content_sha256 || input.m4ToolPolicy.worktree_key !== input.repository.worktree_key || input.m4ToolPolicy.task_scope_identity !== taskScopeIdentity) fail("AUTHORITY_REJECTED", "M4 policy identity differs from task/repository authority", "M1_M5_ADMISSION");
  const gatewayExpectation: ScopedToolGatewayAuthorityExpectation = {
    stateRoot: input.stateRoot,
    runId: input.runId,
    repository: input.repository,
    baseline: input.baseline,
    acceptedState: input.m3StateToken,
    taskScopeIdentity,
    toolPolicy: input.m4ToolPolicy,
    commandCatalog: input.m4CommandCatalog,
    instructionFiles: input.instructionFiles,
    authorityFiles: input.authorityFiles,
    editablePaths: input.task.scope.editable_paths,
    frozenPaths: input.task.scope.frozen_paths,
  };
  await assertScopedToolGatewayAuthority(input.gateway, gatewayExpectation, input.instructionFiles.concat(input.authorityFiles));
  const hardWall = limitFromPolicy(input.m5Policy, "WALL_TIME_MS", MAX_WALL_TIME_MS);
  if (hardWall < 1 || limitFromPolicy(input.m5Policy, "MODEL_TURN", 2) < 2 || limitFromPolicy(input.m5Policy, "PROVIDER_REQUEST", 2) < 2 || limitFromPolicy(input.m5Policy, "TOOL_CALL", 2) < 2) fail("AUTHORITY_REJECTED", "M5 budget cannot admit the fixed two-turn worker envelope", "M1_M5_ADMISSION");
  const readLength = Math.min(MAX_READ_BYTES, input.m4ToolPolicy.limits.maximum_read_bytes);
  if (readLength < 1) fail("AUTHORITY_REJECTED", "M4 read budget is exhausted", "M1_M5_ADMISSION");
  return {
    inspection: committedInspection,
    providerId: route.provider_id,
    modelId: route.model_id,
    taskPath,
    taskScopeIdentity,
    predecessorStateContentSha256,
    transitionEventContentSha256,
    predictedNextStateContentSha256,
    operationId: decision.operation_id,
    reservationDecisionKey,
    readLength,
    attemptNumber: runtimeTask.attempts,
    wallDeadlineMs: hardWall,
  };
}

function invocationProjection(input: M6DirectReadOnlyWorkerInput, admission: Admission, runtime: RuntimeBoundary, promptHashes: { readonly system: Sha256Digest; readonly user: Sha256Digest }, resources: readonly JsonRecord[], hardLimits: JsonRecord): JsonRecord {
  const state = admission.inspection.workflowState;
  return {
    protocol_id: PROTOCOL_ID,
    run_id: input.runId,
    revision: admission.inspection.revision,
    state_pointer_content_sha256: admission.inspection.statePointer.content_sha256,
    current_state_content_sha256: state.content_sha256,
    predecessor_state_content_sha256: admission.predecessorStateContentSha256,
    transition_commit_content_sha256: admission.inspection.transitionCommit.content_sha256,
    m5_decision_content_sha256: input.m5Decision.content_sha256,
    m5_policy_content_sha256: input.m5Policy.content_sha256,
    m5_reservation_decision_key: admission.reservationDecisionKey,
    operation_id: admission.operationId,
    transition_event_content_sha256: admission.transitionEventContentSha256,
    predicted_next_state_content_sha256: admission.predictedNextStateContentSha256,
    execution_mode: "DIRECT_LUNA_HIGH",
    continuation_action: "CONTINUE_ADMITTED_OPERATION",
    logical_role: "LUNA_EXECUTOR",
    repository_identity_content_sha256: input.repository.content_sha256,
    worktree_key: input.repository.worktree_key,
    m3_state_token_content_sha256: input.m3StateToken.content_sha256,
    m4_tool_policy_content_sha256: input.m4ToolPolicy.content_sha256,
    m4_command_catalog_content_sha256: input.m4CommandCatalog.content_sha256,
    task_content_sha256: input.task.content_sha256,
    task_scope_identity: admission.taskScopeIdentity,
    route_map_sha256: input.runAuthority.routeMap.route_map_sha256,
    route_map_approval_sha256: input.runAuthority.routeMapApproval.route_map_approval_sha256,
    provider_id: admission.providerId,
    model_id: admission.modelId,
    effort: "high",
    runtime_boundary_policy: RUNTIME_BOUNDARY_POLICY,
    pi_modules: [moduleIdentity(runtime.agentIdentity), moduleIdentity(runtime.aiIdentity), {
      specifier: PROVIDERS_MODULE_SPECIFIER,
      package_name: runtime.aiIdentity.package_name,
      package_version: runtime.aiIdentity.package_version,
      registry_integrity: runtime.aiIdentity.registry_integrity,
      registry_resolved: runtime.aiIdentity.registry_resolved,
      resolved_url: runtime.providersTarget.url,
      installed_tree_sha256: runtime.aiIdentity.installed_tree_sha256,
    }],
    approved_resources: resources,
    system_prompt_sha256: promptHashes.system,
    user_prompt_sha256: promptHashes.user,
    read_path: admission.taskPath,
    read_offset: 0,
    read_length: admission.readLength,
    hard_limits: hardLimits,
    attempt_number: admission.attemptNumber,
  };
}

function workerTools(
  input: M6DirectReadOnlyWorkerInput,
  admission: Admission,
  state: { readResult: M4ReadMemory | undefined; report: JsonRecord | undefined; readCalls: number; reportCalls: number },
  latch: (code: M6FailureCode, stage: string) => void,
): readonly ToolRuntime[] {
  const readTool: ToolRuntime = {
    name: "read_scoped",
    label: "Read scoped primary target",
    description: "Read the controller-selected primary task target exactly once.",
    parameters: {
      type: "object",
      properties: { read_id: { type: "string", const: "primary" } },
      required: ["read_id"],
      additionalProperties: false,
    },
    execute: async (_toolCallId, params, signal) => {
      if (signal?.aborted === true) fail("WORKER_ABORTED", "Read was aborted", "READ_TOOL");
      if (state.readCalls !== 0) fail("TOOL_REQUEST_INVALID", "A second read was requested", "READ_TOOL");
      const args = record(params, "read_scoped arguments");
      if (Object.keys(args).length !== 1 || args["read_id"] !== "primary") fail("TOOL_REQUEST_INVALID", "read_scoped arguments are invalid", "READ_TOOL");
      state.readCalls += 1;
      try {
        const token = safeDigest(input.gateway.acceptedState.content_sha256, "M4 state token");
        const result = await input.gateway.read_scoped({ stateTokenContentSha256: token, path: admission.taskPath, offset: 0, length: admission.readLength, mode: "TEXT" });
        if (result.content === null || Buffer.byteLength(result.content, "utf8") > MAX_TOOL_RESULT_BYTES) fail("TOOL_EXECUTION_FAILED", "M4 read returned no bounded UTF-8 content", "READ_TOOL");
        const resultDigest = safeDigest(result.resultRecord.content_sha256, "M4 result identity");
        const inspection = await inspectRunStorage({ stateRoot: input.stateRoot, runId: input.runId });
        if (inspection.status !== "HEALTHY" || !inspection.managedRecordClassifications.some((entry) => entry.object.kind === "M4_TOOL_RESULT" && entry.object.contentSha256 === resultDigest && entry.classification === "AUTHORITATIVE_MANAGED_RECORD")) fail("TOOL_EXECUTION_FAILED", "M4 read result is not authoritative", "READ_TOOL");
        state.readResult = { recordContentSha256: resultDigest, contentDigest: safeDigest(result.metadata.digest, "M4 read content identity"), content: result.content };
        return {
          content: [{ type: "text", text: result.content }],
          details: { m4ResultContentSha256: resultDigest, contentSha256: result.metadata.digest },
        };
      } catch (error: unknown) {
        if (error instanceof M6WorkerError) { latch(error.code, error.stage); throw error; }
        latch("TOOL_EXECUTION_FAILED", "READ_TOOL");
        throw new M6WorkerError("TOOL_EXECUTION_FAILED", "M4 read failed", "READ_TOOL");
      }
    },
  };
  const reportTool: ToolRuntime = {
    name: "submit_worker_report",
    label: "Submit terminal worker report",
    description: "Submit exactly one structured terminal report grounded in the primary read result.",
    parameters: {
      type: "object",
      properties: {
        status: { type: "string", const: "COMPLETED" },
        summary: { type: "string", minLength: 1, maxLength: 2048 },
        evidence_content_sha256: { type: "array", minItems: 1, maxItems: 1, items: { type: "string", pattern: "^sha256:[0-9a-f]{64}$" } },
      },
      required: ["status", "summary", "evidence_content_sha256"],
      additionalProperties: false,
    },
    execute: async (_toolCallId, params, signal) => {
      if (signal?.aborted === true) fail("WORKER_ABORTED", "Report was aborted", "REPORT_TOOL");
      if (state.reportCalls !== 0 || state.readResult === undefined) fail("WORKER_REPORT_INVALID", "Report is premature or duplicated", "REPORT_TOOL");
      const args = record(params, "submit_worker_report arguments");
      if (Object.keys(args).length !== 3 || args["status"] !== "COMPLETED" || typeof args["summary"] !== "string" || args["summary"].length === 0 || args["summary"].length > 2_048 || !Array.isArray(args["evidence_content_sha256"]) || args["evidence_content_sha256"].length !== 1) fail("WORKER_REPORT_INVALID", "Worker report arguments are invalid", "REPORT_TOOL");
      const evidence = safeDigest(args["evidence_content_sha256"][0], "worker report evidence");
      if (evidence !== state.readResult.recordContentSha256) fail("WORKER_REPORT_INVALID", "Worker report evidence does not identify the M4 read result", "REPORT_TOOL");
      if (Buffer.byteLength(canonicalize(args), "utf8") > MAX_REPORT_BYTES) fail("WORKER_REPORT_INVALID", "Worker report exceeds its canonical byte bound", "REPORT_TOOL");
      state.reportCalls += 1;
      state.report = { status: "COMPLETED", summary: args["summary"], evidence_content_sha256: [evidence] };
      return {
        content: [{ type: "text", text: "Terminal worker report accepted." }],
        details: { status: "COMPLETED", evidence_content_sha256: [evidence] },
        terminate: true,
      };
    },
  };
  return [readTool, reportTool];
}

function firstErrorCode(error: unknown): M6FailureCode {
  if (error instanceof M6WorkerError) return error.code;
  const code = error !== null && typeof error === "object" && "code" in error ? error.code : undefined;
  if (code === "ERR_PACKAGE_PATH_NOT_EXPORTED") return "RUNTIME_IDENTITY_INVALID";
  return "PROVIDER_PROTOCOL_INVALID";
}

function firstErrorStage(error: unknown): string {
  return error instanceof M6WorkerError ? error.stage : "WORKER";
}

function stateMessages(agent: AgentRuntime): readonly JsonRecord[] {
  return agent.state.messages.map((value, index) => record(value, `Agent message ${index}`));
}

function assertProtocol(
  agent: AgentRuntime,
  counts: { readonly providerTurns: number; readonly modelTurns: number; readonly readCalls: number; readonly reportCalls: number; readonly toolCalls: number },
  report: JsonRecord | undefined,
): void {
  if (counts.providerTurns !== 2 || counts.modelTurns !== 2 || counts.readCalls !== 1 || counts.reportCalls !== 1 || counts.toolCalls !== 2 || report === undefined) fail("PROVIDER_PROTOCOL_INVALID", "Direct worker protocol counts did not match", "PROTOCOL");
  const messages = stateMessages(agent);
  const assistants = messages.filter((message) => message["role"] === "assistant");
  if (assistants.length !== 2 || messages.some((message) => message["role"] === "assistant" && Array.isArray(message["content"]) && message["content"].some((content) => record(content, "assistant content")["type"] === "toolCall" && !["read_scoped", "submit_worker_report"].includes(String(record(content, "tool call")["name"]))))) fail("PROVIDER_PROTOCOL_INVALID", "Direct worker assistant protocol is invalid", "PROTOCOL");
}

async function waitWithDeadline(value: Promise<void>, milliseconds: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<false>((resolveTimeout) => {
    timer = setTimeout(() => resolveTimeout(false), milliseconds);
    timer.unref();
  });
  const completed = await Promise.race([value.then(() => true, () => true), timeout]);
  if (timer !== undefined) clearTimeout(timer);
  return completed;
}

function makeHardLimits(input: M6DirectReadOnlyWorkerInput, admission: Admission): JsonRecord {
  return {
    provider_turns: Math.min(2, limitFromPolicy(input.m5Policy, "PROVIDER_REQUEST", 2)),
    model_turns: Math.min(2, limitFromPolicy(input.m5Policy, "MODEL_TURN", 2)),
    read_calls: 1,
    tool_calls: Math.min(2, limitFromPolicy(input.m5Policy, "TOOL_CALL", 2)),
    report_submissions: 1,
    prompt_bytes: MAX_PROMPT_BYTES,
    read_bytes: admission.readLength,
    tool_result_bytes: MAX_TOOL_RESULT_BYTES,
    report_canonical_bytes: MAX_REPORT_BYTES,
    wall_deadline_ms: admission.wallDeadlineMs,
  };
}

function assertM6InvocationDocument(value: unknown): asserts value is M6WorkerInvocationDocument {
  assertDocumentValid("pi_gacw_m6_worker_invocation_v0", value);
}

function assertM6ResultDocument(value: unknown): asserts value is M6WorkerResultDocument {
  assertDocumentValid("pi_gacw_m6_worker_result_v0", value);
}

function buildInvocation(input: M6DirectReadOnlyWorkerInput, admission: Admission, runtime: RuntimeBoundary): M6WorkerInvocationDocument {
  const systemHash = sha256Bytes(Buffer.from(input.systemPrompt, "utf8"));
  const userHash = sha256Bytes(Buffer.from(input.userPrompt, "utf8"));
  const resources = input.approvedResources.map(reportResource);
  const hardLimits = makeHardLimits(input, admission);
  const projection = invocationProjection(input, admission, runtime, { system: systemHash, user: userHash }, resources, hardLimits);
  const invocation = identifyContractDocument("pi_gacw_m6_worker_invocation_v0", {
    schema_id: "pi_gacw_m6_worker_invocation_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    ...projection,
    invocation_key: sha256Canonical(projection),
    admitted_at: new Date().toISOString(),
  });
  assertM6InvocationDocument(invocation);
  return invocation;
}

function buildResult(
  input: M6DirectReadOnlyWorkerInput,
  invocation: M6WorkerInvocationDocument,
  firstFailure: FailureLatch | undefined,
  cleanupFailure: FailureLatch | undefined,
  promptSettled: boolean,
  agentIdle: boolean,
  pendingToolCalls: number,
  subscriberRemoved: boolean,
  queuesEmpty: boolean,
  resetCompleted: boolean,
  timersCleared: boolean,
  providerCollectionCleared: boolean,
  providerWorkStarted: boolean,
  providerTurns: number,
  modelTurns: number,
  toolCalls: number,
  readCalls: number,
  reportCalls: number,
  report: JsonRecord | undefined,
  readResult: M4ReadMemory | undefined,
  startedAt: number,
): M6WorkerResultDocument {
  const completed = firstFailure === undefined && cleanupFailure === undefined && report !== undefined && readResult !== undefined && providerTurns === 2 && modelTurns === 2 && toolCalls === 2 && readCalls === 1 && reportCalls === 1 && promptSettled && agentIdle && subscriberRemoved && queuesEmpty && resetCompleted && timersCleared && providerCollectionCleared;
  const settlement = {
    prompt_settled: promptSettled,
    agent_idle: agentIdle,
    pending_tool_calls: pendingToolCalls,
    subscriber_removed: subscriberRemoved,
    queues_empty: queuesEmpty,
    reset_completed: resetCompleted,
    timers_cleared: timersCleared,
    provider_collection_cleared: providerCollectionCleared,
    owned_provider_streams: agentIdle ? 0 : 1,
    owned_child_processes: 0,
    owned_sockets: 0,
    owned_fifos: 0,
    cleanup_certain: cleanupFailure === undefined && promptSettled && agentIdle && subscriberRemoved && queuesEmpty && resetCompleted && timersCleared && providerCollectionCleared,
  };
  const result = identifyContractDocument("pi_gacw_m6_worker_result_v0", {
    schema_id: "pi_gacw_m6_worker_result_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    invocation_key: invocation.invocation_key,
    invocation_content_sha256: invocation.content_sha256,
    run_id: input.runId,
    outcome: completed ? "COMPLETED" as const : "BLOCKED" as const,
    provider_work_started: providerWorkStarted,
    first_failure_code: firstFailure?.code ?? (cleanupFailure === undefined ? null : "CLEANUP_UNCERTAIN"),
    first_failure_stage: firstFailure?.stage ?? (cleanupFailure?.stage ?? null),
    worker_report: report ?? null,
    m4_result_content_sha256: readResult?.recordContentSha256 ?? null,
    usage: {
      provider_turns: providerTurns,
      model_turns: modelTurns,
      provider_requests: null,
      tool_calls: toolCalls,
      read_calls: readCalls,
      report_submissions: reportCalls,
      input_tokens: null,
      output_tokens: null,
      cost_microusd: null,
      wall_time_ms: Math.min(Date.now() - startedAt, MAX_WALL_TIME_MS),
    },
    settlement,
    cleanup_failure_code: cleanupFailure?.code ?? null,
    completed_at: new Date().toISOString(),
  });
  assertM6ResultDocument(result);
  return result;
}

interface M4ReadMemory {
  readonly recordContentSha256: Sha256Digest;
  readonly contentDigest: Sha256Digest | null;
  readonly content: string;
}

async function completedM6ResultForDecision(input: M6DirectReadOnlyWorkerInput): Promise<boolean> {
  const location = { stateRoot: input.stateRoot, runId: input.runId };
  const [records, inspection] = await Promise.all([readM6WorkerRecords(location), inspectRunStorage(location)]);
  return inspection.status === "HEALTHY" && records.results.some((result) => result.run_id === input.runId && inspection.managedRecordClassifications.some((entry) => entry.object.kind === "M6_WORKER_RESULT" && entry.object.contentSha256 === result.content_sha256 && entry.classification === "AUTHORITATIVE_MANAGED_RECORD") && records.invocations.some((invocation) => invocation.content_sha256 === result.invocation_content_sha256 && inspection.managedRecordClassifications.some((entry) => entry.object.kind === "M6_WORKER_INVOCATION" && entry.object.contentSha256 === invocation.content_sha256 && entry.classification === "AUTHORITATIVE_MANAGED_RECORD") && invocation.m5_decision_content_sha256 === input.m5Decision.content_sha256));
}

export async function runDirectReadOnlyLunaWorker(input: M6DirectReadOnlyWorkerInput): Promise<M6WorkerExecutionResult> {
  const startedAt = Date.now();
  const completedReplayAuthority = await completedM6ResultForDecision(input);
  const admission = await admit(input, completedReplayAuthority);
  const runtimeBoundary = await loadRuntimeBoundary();
  const invocation = buildInvocation(input, admission, runtimeBoundary);
  const location: RunStorageLocation = { stateRoot: input.stateRoot, runId: input.runId };
  const replay = await withRunExclusive(location, async () => {
    const records = await readM6WorkerRecords(location);
    const inspection = await inspectRunStorage(location);
    const isAuthoritative = (kind: string, digest: string): boolean => inspection.status === "HEALTHY" && inspection.managedRecordClassifications.some((entry) => entry.object.kind === kind && entry.object.contentSha256 === digest && entry.classification === "AUTHORITATIVE_MANAGED_RECORD");
    const existingResult = records.results.find((value) => value.invocation_key === invocation.invocation_key);
    if (existingResult !== undefined) {
      const existingInvocation = records.invocations.find((value) => value.content_sha256 === existingResult.invocation_content_sha256);
      if (existingInvocation === undefined || existingInvocation.invocation_key !== invocation.invocation_key || !isAuthoritative("M6_WORKER_INVOCATION", existingInvocation.content_sha256) || !isAuthoritative("M6_WORKER_RESULT", existingResult.content_sha256)) fail("AUTHORITY_REJECTED", "Completed M6 result has an invalid invocation predecessor", "REPLAY");
      return { invocation: existingInvocation, result: existingResult };
    }
    const existingInvocation = records.invocations.find((value) => value.invocation_key === invocation.invocation_key);
    if (existingInvocation !== undefined) {
      if (!isAuthoritative("M6_WORKER_INVOCATION", existingInvocation.content_sha256)) fail("AUTHORITY_REJECTED", "An incomplete M6 invocation is not authoritative", "REPLAY");
      fail("INVOCATION_ALREADY_INCOMPLETE", "An identical M6 invocation is already incomplete", "REPLAY");
    }
    await publishM6WorkerRecord({ ...location, kind: "M6_WORKER_INVOCATION", document: invocation });
    return undefined;
  });
  if (replay !== undefined) return { invocation: replay.invocation, result: replay.result, replayed: true };
  if (completedReplayAuthority) fail("AUTHORITY_REJECTED", "A completed M6 result exists for this M5 decision but the invocation identity differs", "REPLAY");

  let runtime: PreparedRuntime | undefined;
  let agent: AgentRuntime | undefined;
  let unsubscribe: (() => void) | undefined;
  let deadlineTimer: NodeJS.Timeout | undefined;
  let abortListener: (() => void) | undefined;
  let promptPromise: Promise<void> | undefined;
  let promptSettled = false;
  let agentIdle = false;
  let subscriberRemoved = false;
  let queuesEmpty = false;
  let resetCompleted = false;
  let timersCleared = false;
  let providerCollectionCleared = false;
  let providerWorkStarted = false;
  let credentialCallbackCount = 0;
  let providerTurns = 0;
  let modelTurns = 0;
  let toolCalls = 0;
  const toolState: { readResult: M4ReadMemory | undefined; report: JsonRecord | undefined; readCalls: number; reportCalls: number } = { readResult: undefined, report: undefined, readCalls: 0, reportCalls: 0 };
  let firstFailure: FailureLatch | undefined;
  let cleanupFailure: FailureLatch | undefined;
  const latch = (code: M6FailureCode, stage: string): void => { firstFailure ??= { code, stage }; };
  try {
    runtime = prepareRuntime(runtimeBoundary, admission.providerId, admission.modelId);
    let abortAgent: (() => void) | undefined;
    const tools = workerTools(input, admission, toolState, latch);
    const toolCallNames: string[] = [];
    const options: JsonRecord = {
      initialState: { systemPrompt: input.systemPrompt, model: runtime.model, thinkingLevel: "high", tools },
      streamFn: (model: unknown, context: unknown, optionsValue?: unknown): unknown => {
        providerWorkStarted = true;
        if (providerTurns >= 2) {
          latch("PROVIDER_PROTOCOL_INVALID", "PROVIDER_TURN");
          fail("PROVIDER_PROTOCOL_INVALID", "A third provider turn was requested", "PROVIDER_TURN");
        }
        providerTurns += 1;
        return runtime?.streamFn(model, context, optionsValue);
      },
      getApiKey: async (provider: string): Promise<string | undefined> => {
        if (provider !== admission.providerId) fail("AUTHORITY_REJECTED", "Credential callback received the wrong provider ID", "CREDENTIAL");
        credentialCallbackCount += 1;
        const credential = await input.credentialCallback(provider);
        if (credential !== undefined && typeof credential !== "string") fail("AUTHORITY_REJECTED", "Credential callback returned a non-string value", "CREDENTIAL");
        return credential;
      },
      toolExecution: "sequential",
      maxRetryDelayMs: 0,
      beforeToolCall: async (context: unknown): Promise<JsonRecord | undefined> => {
        const value = record(context, "beforeToolCall context");
        const call = record(value["toolCall"], "tool call");
        const name = string(call["name"], "tool call name");
        toolCallNames.push(name);
        if (toolCallNames.length > 2 || (toolCallNames.length === 1 && name !== "read_scoped") || (toolCallNames.length === 2 && name !== "submit_worker_report")) {
          latch("TOOL_REQUEST_INVALID", "TOOL_PROTOCOL");
          return { block: true, reason: "The bounded direct protocol permits one read followed by one report." };
        }
        return undefined;
      },
      afterToolCall: async (context: unknown): Promise<JsonRecord | undefined> => {
        const value = record(context, "afterToolCall context");
        const call = record(value["toolCall"], "tool call");
        const name = string(call["name"], "tool call name");
        const isError = boolean(value["isError"], "tool result error state");
        if (isError) {
          latch(name === "submit_worker_report" ? "WORKER_REPORT_INVALID" : "TOOL_EXECUTION_FAILED", "TOOL_PROTOCOL");
          abortAgent?.();
          return { terminate: true };
        }
        if (name === "submit_worker_report") return { terminate: true };
        return undefined;
      },
    };
    agent = constructAgent(runtimeBoundary.agentModule, options);
    const initialState = agent.state;
    if (initialState.model !== runtime.model || initialState.thinkingLevel !== "high") fail("RUNTIME_CAPABILITY_INVALID", "Agent initial model or effort is not authoritative", "RUNTIME_GUARD");
    if (initialState.messages.length !== 0 || initialState.pendingToolCalls.size !== 0) fail("RUNTIME_CAPABILITY_INVALID", "Fresh Agent state is not empty", "RUNTIME_GUARD");
    abortAgent = () => { agent?.abort(); };
    unsubscribe = agent.subscribe(async (event: unknown) => {
      const value = record(event, "Agent event");
      const type = string(value["type"], "Agent event type");
      if (type === "turn_end") {
        if (modelTurns >= 2) latch("PROVIDER_PROTOCOL_INVALID", "MODEL_TURN");
        else modelTurns += 1;
      }
      if (type === "tool_execution_start") {
        if (toolCalls >= 2) latch("PROVIDER_PROTOCOL_INVALID", "TOOL_PROTOCOL");
        else toolCalls += 1;
      }
      if (type === "tool_execution_end" && value["isError"] === true) latch("TOOL_EXECUTION_FAILED", "TOOL_PROTOCOL");
    });
    const deadline = Math.min(admission.wallDeadlineMs, MAX_WALL_TIME_MS);
    deadlineTimer = setTimeout(() => {
      latch("WORKER_DEADLINE_EXCEEDED", "DEADLINE");
      abortAgent?.();
    }, deadline);
    deadlineTimer.unref();
    if (input.signal !== undefined) {
      abortListener = () => { latch("WORKER_ABORTED", "ABORT"); abortAgent?.(); };
      if (input.signal.aborted) abortListener();
      else input.signal.addEventListener("abort", abortListener, { once: true });
    }
    try {
      promptPromise = agent.prompt(input.userPrompt);
      await promptPromise;
      promptSettled = true;
    } catch (error: unknown) {
      promptSettled = true;
      latch(firstErrorCode(error), firstErrorStage(error));
    }
    try {
      await agent.waitForIdle();
      agentIdle = true;
    } catch (error: unknown) {
      latch(firstErrorCode(error), firstErrorStage(error));
    }
    if (credentialCallbackCount !== providerTurns || providerTurns !== 2) latch("PROVIDER_PROTOCOL_INVALID", "CREDENTIAL");
    if (admission.providerId === SYNTHETIC_PROVIDER_ID && admission.modelId === SYNTHETIC_MODEL_ID && (runtime?.fauxCallCount() !== 2 || runtime?.pendingResponseCount() !== 0)) {
      latch("PROVIDER_PROTOCOL_INVALID", "PROTOCOL");
    }
    try { assertProtocol(agent, { providerTurns, modelTurns, readCalls: toolState.readCalls, reportCalls: toolState.reportCalls, toolCalls }, toolState.report); }
    catch (error: unknown) { latch(firstErrorCode(error), firstErrorStage(error)); }
  } catch (error: unknown) {
    latch(firstErrorCode(error), firstErrorStage(error));
  } finally {
    if (agent !== undefined) {
      try { agent.abort(); } catch { cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_ABORT" }; }
      if (promptPromise !== undefined && !promptSettled) {
        promptSettled = await waitWithDeadline(promptPromise.then(() => undefined), 5_000);
        if (!promptSettled) cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_PROMPT" };
      }
      try { agentIdle = await waitWithDeadline(agent.waitForIdle(), 5_000); if (!agentIdle) cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_IDLE" }; }
      catch { cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_IDLE" }; }
      if (unsubscribe !== undefined) {
        try { unsubscribe(); subscriberRemoved = true; } catch { cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_SUBSCRIBER" }; }
      }
      try { agent.clearAllQueues(); queuesEmpty = !agent.hasQueuedMessages(); if (!queuesEmpty) cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_QUEUE" }; }
      catch { cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_QUEUE" }; }
      try {
        agent.reset();
        const resetState = agent.state;
        resetCompleted = resetState.messages.length === 0 && resetState.pendingToolCalls.size === 0 && !resetState.isStreaming;
        if (!resetCompleted) cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_RESET" };
      }
      catch { cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_RESET" }; }
    }
    if (deadlineTimer !== undefined) { clearTimeout(deadlineTimer); deadlineTimer = undefined; timersCleared = true; }
    else timersCleared = true;
    if (input.signal !== undefined && abortListener !== undefined) input.signal.removeEventListener("abort", abortListener);
    if (runtime !== undefined) {
      try {
        runtime.clearProviderState();
        runtime.models.clearProviders();
        providerCollectionCleared = runtime.models.getProviders().length === 0 && runtime.pendingResponseCount() === 0;
        if (!providerCollectionCleared) cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_PROVIDERS" };
      }
      catch { cleanupFailure ??= { code: "CLEANUP_UNCERTAIN", stage: "CLEANUP_PROVIDERS" }; }
    } else providerCollectionCleared = true;
    if (unsubscribe === undefined) subscriberRemoved = true;
    if (agent === undefined) { agentIdle = true; queuesEmpty = true; resetCompleted = true; promptSettled = true; }
  }
  const pendingToolCalls = agent?.state.pendingToolCalls.size ?? 0;
  const result = buildResult(input, invocation, firstFailure, cleanupFailure, promptSettled, agentIdle, pendingToolCalls, subscriberRemoved, queuesEmpty, resetCompleted, timersCleared, providerCollectionCleared, providerWorkStarted, providerTurns, modelTurns, toolCalls, toolState.readCalls, toolState.reportCalls, toolState.report, toolState.readResult, startedAt);
  runtime = undefined;
  agent = undefined;
  unsubscribe = undefined;
  promptPromise = undefined;
  abortListener = undefined;
  try {
    await publishM6WorkerRecord({ ...location, kind: "M6_WORKER_RESULT", document: result });
  } catch (error: unknown) {
    throw new M6WorkerError("RESULT_PERSISTENCE_FAILED", "M6 terminal result could not be durably published", "RESULT_PERSISTENCE");
  }
  if (cleanupFailure !== undefined) throw new M6WorkerError("CLEANUP_UNCERTAIN", "M6 cleanup certainty was not established", cleanupFailure.stage);
  return { invocation, result, replayed: false };
}
