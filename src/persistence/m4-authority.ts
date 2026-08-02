import { canonicalize } from "../canonical-json/index.js";
import { sha256Bytes, sha256Canonical } from "../identity/index.js";
import { m3ScopeIdentity } from "../identity/m3-scope.js";
import { currentM4CapabilityProducerAuthority, probeM4Capabilities } from "../secure-fs/capabilities.js";
import { validateCommandCatalog, commandSpecProjection, type ValidatedCommandCatalog } from "../scoped-tools/commands.js";
import { assertMutationPermitted, validateToolPolicy, type ValidatedToolPolicy } from "../scoped-tools/policy.js";
import type {
  M3BaselineRuntimeDocument,
  M3LockAcquisitionDocument,
  M3PostflightDocument,
  M3RepositoryStateTokenDocument,
  M4CommandCatalogDocument,
  M4CommandResultDocument,
  M4MutationJournal,
  M4MutationReceiptDocument,
  M4PatchRequestDocument,
  M4SandboxCapabilityDocument,
  M4ScopedToolPolicyDocument,
  M4SecureFilesystemCapabilityDocument,
  M4ToolRequestDocument,
  M4ToolResultDocument,
} from "../schemas/index.js";
import type { InspectedObject, ManagedRecordClassification, StoredObjectKind } from "./types.js";

export interface M4AuthorityInput {
  readonly runId: string;
  readonly objects: readonly InspectedObject[];
  readonly m3Classifications: readonly ManagedRecordClassification[];
  readonly baselines: ReadonlyMap<string, M3BaselineRuntimeDocument>;
  readonly locks: ReadonlyMap<string, M3LockAcquisitionDocument>;
  readonly tokens: ReadonlyMap<string, M3RepositoryStateTokenDocument>;
  readonly postflights: ReadonlyMap<string, M3PostflightDocument>;
  readonly secureCapabilities: ReadonlyMap<string, M4SecureFilesystemCapabilityDocument>;
  readonly sandboxCapabilities: ReadonlyMap<string, M4SandboxCapabilityDocument>;
  readonly policies: ReadonlyMap<string, M4ScopedToolPolicyDocument>;
  readonly catalogs: ReadonlyMap<string, M4CommandCatalogDocument>;
  readonly toolRequests: ReadonlyMap<string, M4ToolRequestDocument>;
  readonly patchRequests: ReadonlyMap<string, M4PatchRequestDocument>;
  readonly toolResults: ReadonlyMap<string, M4ToolResultDocument>;
  readonly mutationReceipts: ReadonlyMap<string, M4MutationReceiptDocument>;
  readonly commandResults: ReadonlyMap<string, M4CommandResultDocument>;
}

type M4Kind = Extract<StoredObjectKind, `M4_${string}`>;
interface Ref { readonly kind: StoredObjectKind; readonly digest: string }
interface Node { readonly object: InspectedObject; readonly refs: Ref[]; error: string | null; missing: string | null }
const EMPTY = sha256Bytes(Buffer.alloc(0));

function key(kind: StoredObjectKind, digest: string): string { return `${kind}:${digest}`; }
function fail(node: Node, detail: string): void { node.error ??= detail; }
function missing(node: Node, detail: string): void { node.missing ??= detail; }
function same(left: unknown, right: unknown): boolean { return canonicalize(left) === canonicalize(right); }
function stableCapability(value: Record<string, unknown>): Record<string, unknown> {
  const { content_sha256: _content, probed_at: _time, ...stable } = value; return stable;
}
function matchingBaseline(input: M4AuthorityInput, repositoryDigest: string, worktreeKey?: string): M3BaselineRuntimeDocument | undefined {
  return [...input.baselines.values()].find((baseline) => baseline.run_id === input.runId && baseline.repository.content_sha256 === repositoryDigest &&
    (worktreeKey === undefined || baseline.repository.worktree_key === worktreeKey));
}
function contextMismatch(input: M4AuthorityInput, repositoryDigest: string, worktreeKey?: string): boolean {
  return [...input.baselines.values()].some((baseline) =>
    (baseline.run_id === input.runId && baseline.repository.content_sha256 !== repositoryDigest) ||
    (baseline.run_id !== input.runId && baseline.repository.content_sha256 === repositoryDigest) ||
    (worktreeKey !== undefined && baseline.run_id === input.runId && baseline.repository.content_sha256 === repositoryDigest && baseline.repository.worktree_key !== worktreeKey));
}
function pathSet(value: readonly { readonly path: string }[]): readonly string[] { return [...new Set(value.map((entry) => entry.path))].sort(); }
function allNull(value: { readonly digest: string | null; readonly size: number | null; readonly mode: number | null }): boolean {
  return value.digest === null && value.size === null && value.mode === null;
}
function allPresent(value: { readonly digest: string | null; readonly size: number | null; readonly mode: number | null }): boolean {
  return value.digest !== null && value.size !== null && value.mode !== null;
}
function add(node: Node, kind: StoredObjectKind, digest: string | null): void {
  if (digest !== null) node.refs.push({ kind, digest });
}

function validateJournal(node: Node, journal: M4MutationJournal | null): void {
  if (journal === null) return;
  if (journal.temporary_bytes_written > 0 && !journal.temporary_file_created) fail(node, "Mutation journal reports bytes without a temporary file");
  if (journal.temporary_file_fsync_attempted && !journal.temporary_file_created) fail(node, "Mutation journal fsync lacks a temporary file");
  if (journal.temporary_file_fsync_completed && !journal.temporary_file_fsync_attempted) fail(node, "Mutation journal completes an unattempted file fsync");
  if (journal.atomic_rename_completed && !journal.atomic_rename_attempted) fail(node, "Mutation journal completes an unattempted atomic operation");
  if (journal.atomic_rename_attempted !== (journal.atomic_operation !== "NONE")) fail(node, "Mutation journal atomic-operation facts disagree");
  if (journal.directory_fsync_completed_count > journal.directory_fsync_attempt_count) fail(node, "Mutation journal completes unattempted directory fsyncs");
  if (journal.rollback_attempted && !journal.rollback_required) fail(node, "Mutation journal attempts an unrequired rollback");
  if (journal.rollback_completed && (!journal.rollback_attempted || !journal.atomic_rename_completed)) fail(node, "Mutation journal rollback completion is impossible");
  if (journal.rollback_directory_fsync_completed && !journal.rollback_completed) fail(node, "Mutation journal rollback fsync precedes rollback completion");
  if (journal.final_verification === "PASS" && journal.rollback_required) fail(node, "Mutation journal passes final verification while rollback is required");
  if (journal.recovery_outcome !== undefined && journal.recovery_outcome !== "NOT_RUN" && journal.recovery_attempted !== true) fail(node, "Mutation journal reports recovery without an attempt");
  if (journal.recovery_residue_count !== undefined && journal.recovery_residue_count !== null && journal.recovery_residue_count < 0) fail(node, "Mutation journal reports a negative recovery residue count");
  if (journal.recovery_outcome === "SUCCEEDED" && (journal.recovery_residue_count !== 0 || journal.recovery_directory_fsync !== "SUCCEEDED")) fail(node, "Mutation journal reports successful recovery without durable zero residue");
  if (journal.recovery_helper_sha256 !== undefined && journal.recovery_helper_sha256 !== null && !/^sha256:[0-9a-f]{64}$/u.test(journal.recovery_helper_sha256)) fail(node, "Mutation journal recovery helper identity is malformed");
  if (journal.tombstone_created === false && [journal.tombstone_device, journal.tombstone_inode, journal.tombstone_nlink].some((value) => value !== undefined && value !== null)) fail(node, "Mutation journal reports tombstone identity without a tombstone");
}

function validateToolRequest(node: Node, value: M4ToolRequestDocument): void {
  if (value.run_id === "" || value.task_scope_identity === "") fail(node, "Tool request authority is empty");
  add(node, "M3_REPOSITORY_STATE_TOKEN", value.state_token_content_sha256);
  add(node, "M4_TOOL_POLICY", value.tool_policy_content_sha256);
  const command = value.request_kind === "COMMAND";
  if (command) {
    if (value.path !== null || value.command_id === null || value.secure_fs_capability_content_sha256 !== null || value.sandbox_capability_content_sha256 === null ||
        value.command_catalog_content_sha256 === null || value.command_spec_sha256 === null) fail(node, "Command tool request has impossible authority fields");
    add(node, "M4_SANDBOX_CAPABILITY", value.sandbox_capability_content_sha256);
    add(node, "M4_COMMAND_CATALOG", value.command_catalog_content_sha256);
  } else {
    if ((["READ", "LIST"] as const).includes(value.request_kind as "READ" | "LIST") && value.path === null) fail(node, "Path tool request omits its path");
    if (value.command_id !== null || value.secure_fs_capability_content_sha256 === null || value.sandbox_capability_content_sha256 !== null ||
        value.command_catalog_content_sha256 !== null || value.command_spec_sha256 !== null) fail(node, "Non-command tool request has impossible authority fields");
    add(node, "M4_SECURE_FS_CAPABILITY", value.secure_fs_capability_content_sha256);
  }
}

function validateOutput(node: Node, value: M4CommandResultDocument, catalog: M4CommandCatalogDocument | undefined): void {
  const specification = catalog?.commands.find((entry) => entry.command_id === value.command_id);
  if (specification === undefined) { fail(node, "Command result specification is absent from its catalog"); return; }
  if (specification.command_spec_sha256 !== value.command_spec_sha256 || specification.command_class !== value.command_class ||
      specification.executable_sha256 !== value.executable_sha256 || sha256Canonical(specification.argv) !== value.argv_identity) fail(node, "Command result differs from its frozen specification");
  for (const stream of ["stdout", "stderr"] as const) {
    const captured = value[`${stream}_byte_count`]; const observed = value[`${stream}_observed_byte_count`];
    const digest = value[`${stream}_observed_digest`]; const overflow = value[`${stream}_overflowed`]; const complete = value[`${stream}_stream_complete`];
    const limit = stream === "stdout" ? specification.stdout_limit : specification.stderr_limit;
    if (captured > observed || captured > limit || overflow !== (observed > limit)) fail(node, `${stream} output counts or overflow facts are inconsistent`);
    if (complete !== (digest !== null) || (!complete && !overflow && value.failure_code !== "COMMAND_TIMEOUT")) fail(node, `${stream} stream completeness is inconsistent`);
    if (complete && observed === 0 && digest !== EMPTY) fail(node, `${stream} empty observed digest is false`);
    if (captured === 0 && value[`${stream}_digest`] !== EMPTY) fail(node, `${stream} empty captured digest is false`);
  }
  if (value.outcome === "PASS") {
    if (value.failure_code !== null || value.signal !== null || value.exit_code === null || !specification.expected_exit_codes.includes(value.exit_code) ||
        !value.stdout_stream_complete || !value.stderr_stream_complete || value.stdout_overflowed || value.stderr_overflowed) fail(node, "PASS command result contradicts its execution contract");
  } else if (value.failure_code === null) fail(node, "BLOCKED command result omits its failure");
}

export async function classifyM4Authority(input: M4AuthorityInput): Promise<readonly ManagedRecordClassification[]> {
  const nodes = new Map<string, Node>(); const policies = new Map<string, ValidatedToolPolicy>(); const catalogs = new Map<string, ValidatedCommandCatalog>();
  for (const object of input.objects.filter((entry) => entry.kind.startsWith("M4_"))) nodes.set(key(object.kind, object.contentSha256), { object, refs: [], error: null, missing: null });
  let actual: Awaited<ReturnType<typeof probeM4Capabilities>> | null = currentM4CapabilityProducerAuthority();
  if (actual === null && (input.secureCapabilities.size > 0 || input.sandboxCapabilities.size > 0)) {
    try { actual = await probeM4Capabilities(); } catch { actual = null; }
  }
  for (const [digest, value] of input.secureCapabilities) {
    const node = nodes.get(key("M4_SECURE_FS_CAPABILITY", digest))!;
    const flags = [value.openat2_available, value.renameat2_available, value.rename_noreplace_available, value.rename_exchange_available, value.directory_fsync_available];
    const expectedAvailable = flags.every(Boolean) && ["RESOLVE_BENEATH", "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_MAGICLINKS"].every((flag) => value.supported_resolve_flags.includes(flag as never));
    if ((value.secure_fs_result === "SECURE_FS_AVAILABLE") !== expectedAvailable) fail(node, "Secure-filesystem capability result contradicts its facts");
    if ((value.command_sandbox_result === "COMMAND_SANDBOX_AVAILABLE") !== (value.landlock_available && value.landlock_abi !== null && value.no_new_privs_available)) fail(node, "Secure capability sandbox summary contradicts its facts");
    if ((value.network_sandbox_result === "NETWORK_SANDBOX_AVAILABLE") !== value.network_denial_available) fail(node, "Secure capability network summary contradicts its facts");
    if (actual === null) missing(node, "Secure capability producer authority is unavailable");
    else if (!same(stableCapability(value as unknown as Record<string, unknown>), stableCapability(actual.secureFilesystem as unknown as Record<string, unknown>))) fail(node, "Secure capability contradicts current helper-probe producer authority");
  }
  for (const [digest, value] of input.sandboxCapabilities) {
    const node = nodes.get(key("M4_SANDBOX_CAPABILITY", digest))!;
    const available = value.landlock_available && value.landlock_abi !== null && value.filesystem_restrictions && value.child_inheritance && value.no_new_privs && value.seccomp_available;
    if ((value.result === "COMMAND_SANDBOX_AVAILABLE") !== available || (value.network_result === "NETWORK_SANDBOX_AVAILABLE") !== value.network_denial) fail(node, "Sandbox capability result contradicts its facts");
    if (actual === null) missing(node, "Sandbox capability producer authority is unavailable");
    else if (!same(stableCapability(value as unknown as Record<string, unknown>), stableCapability(actual.sandbox as unknown as Record<string, unknown>))) fail(node, "Sandbox capability contradicts current helper-probe producer authority");
  }
  const m3Classes = new Map(input.m3Classifications.map((entry) => [key(entry.object.kind, entry.object.contentSha256), entry.classification]));
  for (const [digest, value] of input.policies) {
    const node = nodes.get(key("M4_TOOL_POLICY", digest))!; const baseline = matchingBaseline(input, value.repository_identity_content_sha256, value.worktree_key);
    if (value.run_id !== input.runId) fail(node, "Tool policy run authority contradicts its storage run");
    if (baseline === undefined) {
      if (contextMismatch(input, value.repository_identity_content_sha256, value.worktree_key)) fail(node, "Tool policy repository or worktree authority differs");
      else missing(node, "Tool policy repository baseline is absent");
    }
    else {
      add(node, "M3_BASELINE", baseline.content_sha256);
      const editable = pathSet(value.editable_paths); const frozen = pathSet(value.frozen_paths);
      if (m3ScopeIdentity(editable, frozen) !== value.task_scope_identity) fail(node, "Tool policy scope identity is false");
      try { policies.set(digest, validateToolPolicy(value, input.runId, baseline.repository, value.task_scope_identity, editable, frozen)); }
      catch { fail(node, "Tool policy semantic validation failed"); }
      const token = [...input.tokens.values()].find((entry) => entry.run_id === input.runId && entry.repository_identity_content_sha256 === value.repository_identity_content_sha256 && entry.worktree_key === value.worktree_key && entry.task_scope_identity === value.task_scope_identity && m3Classes.get(key("M3_REPOSITORY_STATE_TOKEN", entry.content_sha256)) === "AUTHORITATIVE_MANAGED_RECORD");
      if (token === undefined) missing(node, "Tool policy authoritative M3 token root is absent"); else add(node, "M3_REPOSITORY_STATE_TOKEN", token.content_sha256);
    }
  }
  for (const [digest, value] of input.catalogs) {
    const node = nodes.get(key("M4_COMMAND_CATALOG", digest))!; add(node, "M4_TOOL_POLICY", value.tool_policy_content_sha256);
    const policy = policies.get(value.tool_policy_content_sha256); const baseline = matchingBaseline(input, value.repository_identity_content_sha256);
    if (value.run_id !== input.runId) fail(node, "Command catalog run authority contradicts its storage run");
    if (baseline === undefined) {
      if (contextMismatch(input, value.repository_identity_content_sha256)) fail(node, "Command catalog repository authority differs");
      else missing(node, "Command catalog repository baseline is absent");
    }
    if (policy !== undefined && policy.document.repository_identity_content_sha256 !== value.repository_identity_content_sha256) fail(node, "Command catalog policy repository authority differs");
    if (policy !== undefined && baseline !== undefined) try { catalogs.set(digest, await validateCommandCatalog(value, input.runId, baseline.repository, policy)); }
    catch { fail(node, "Command catalog semantic validation failed"); }
    if (new Set(value.commands.map((entry) => entry.command_id)).size !== value.commands.length || value.commands.some((entry) => entry.command_spec_sha256 !== sha256Canonical(commandSpecProjection(entry)))) fail(node, "Command catalog IDs or specification identities are invalid");
  }
  for (const [digest, value] of input.toolRequests) {
    const node = nodes.get(key("M4_TOOL_REQUEST", digest))!; if (value.run_id !== input.runId) fail(node, "Tool request run differs"); validateToolRequest(node, value);
    const token = input.tokens.get(value.state_token_content_sha256); const policy = input.policies.get(value.tool_policy_content_sha256);
    if (token !== undefined && (token.run_id !== value.run_id || token.task_scope_identity !== value.task_scope_identity)) fail(node, "Tool request token relationship is invalid");
    if (policy !== undefined && (policy.task_scope_identity !== value.task_scope_identity || (token !== undefined && token.repository_identity_content_sha256 !== policy.repository_identity_content_sha256))) fail(node, "Tool request policy or repository relationship is invalid");
    if (value.request_kind === "COMMAND" && value.command_catalog_content_sha256 !== null && value.command_spec_sha256 !== null) {
      const catalog = input.catalogs.get(value.command_catalog_content_sha256);
      if (catalog !== undefined) {
        const spec = catalog.commands.find((entry) => entry.command_id === value.command_id);
        if (spec === undefined || spec.command_spec_sha256 !== value.command_spec_sha256 || catalog.tool_policy_content_sha256 !== value.tool_policy_content_sha256) fail(node, "Command request catalog membership is invalid");
      }
    }
  }
  for (const [digest, value] of input.patchRequests) {
    const node = nodes.get(key("M4_PATCH_REQUEST", digest))!; add(node, "M3_REPOSITORY_STATE_TOKEN", value.prior_state_token_content_sha256); add(node, "M3_LOCK_ACQUISITION", value.lock_acquisition_content_sha256);
    add(node, "M4_TOOL_POLICY", value.tool_policy_content_sha256); add(node, "M4_SECURE_FS_CAPABILITY", value.secure_fs_capability_content_sha256);
    const token = input.tokens.get(value.prior_state_token_content_sha256); const policy = policies.get(value.tool_policy_content_sha256);
    if (value.run_id !== input.runId) fail(node, "Patch request run authority contradicts its storage run");
    if (token !== undefined && (token.repository_identity_content_sha256 !== value.repository_identity_content_sha256 || token.worktree_key !== value.worktree_key || token.task_scope_identity !== value.task_scope_identity)) fail(node, "Patch request M3 relationship is invalid");
    if (policy !== undefined && (policy.document.repository_identity_content_sha256 !== value.repository_identity_content_sha256 || policy.document.worktree_key !== value.worktree_key || policy.document.task_scope_identity !== value.task_scope_identity)) fail(node, "Patch request policy relationship is invalid");
    if (value.operation === "CREATE" ? value.expected_preimage_exists || value.expected_preimage_digest !== null || value.expected_preimage_size !== null || value.expected_preimage_mode !== null : !value.expected_preimage_exists || value.expected_preimage_digest === null || value.expected_preimage_size === null || value.expected_preimage_mode === null) fail(node, "Patch request preimage facts are impossible");
    if (value.operation === "DELETE" ? value.replacement_digest !== null || value.replacement_byte_count !== 0 || value.requested_final_mode !== null : value.replacement_digest === null || value.requested_final_mode === null) fail(node, "Patch request replacement facts are impossible");
    if (policy !== undefined) try { assertMutationPermitted(policy, value.path, value.operation, value.ownership_class, value.data_class, value.operation === "REPLACE" && value.expected_preimage_mode !== value.requested_final_mode); }
    catch { fail(node, "Patch request exceeds tool policy"); }
  }
  for (const [digest, value] of input.toolResults) {
    const node = nodes.get(key("M4_TOOL_RESULT", digest))!; add(node, "M4_TOOL_REQUEST", value.request_content_sha256);
    const request = input.toolRequests.get(value.request_content_sha256);
    if (value.run_id !== input.runId || value.data_class === "SECRET") fail(node, "Tool result local authority or SECRET projection is invalid");
    if (request !== undefined && (request.request_kind !== value.result_kind || request.path !== value.path || request.state_token_content_sha256 !== value.state_token_content_sha256)) fail(node, "Tool result predecessor relationship is invalid");
  }
  for (const [digest, value] of input.mutationReceipts) {
    const node = nodes.get(key("M4_MUTATION_RECEIPT", digest))!; add(node, "M4_PATCH_REQUEST", value.request_content_sha256); add(node, "M4_SECURE_FS_CAPABILITY", value.secure_fs_capability_content_sha256);
    add(node, "M3_LOCK_ACQUISITION", value.lock_acquisition_content_sha256); add(node, "M3_REPOSITORY_STATE_TOKEN", value.prior_state_token_content_sha256); add(node, "M4_TOOL_POLICY", value.tool_policy_content_sha256);
    const request = input.patchRequests.get(value.request_content_sha256); validateJournal(node, value.helper_journal);
    if (value.run_id !== input.runId) fail(node, "Mutation receipt run authority contradicts its storage run");
    if (request !== undefined && (request.run_id !== value.run_id || request.operation !== value.operation || request.path !== value.path || request.lock_acquisition_content_sha256 !== value.lock_acquisition_content_sha256 || request.prior_state_token_content_sha256 !== value.prior_state_token_content_sha256 || request.tool_policy_content_sha256 !== value.tool_policy_content_sha256 || request.secure_fs_capability_content_sha256 !== value.secure_fs_capability_content_sha256)) fail(node, "Mutation receipt predecessor relationship is invalid");
    if (request !== undefined) {
      const expected = { digest: request.expected_preimage_digest, size: request.expected_preimage_size, mode: request.expected_preimage_mode };
      if (value.operation === "CREATE" ? !allNull(value.before) : value.helper_outcome === "APPLIED" && !same(value.before, expected)) fail(node, "Mutation receipt before-state facts are impossible");
      if (value.helper_outcome === "APPLIED") {
        if (value.outcome !== "APPLIED" || value.failure_code !== null || value.successor_state_token_content_sha256 === null || value.postflight_content_sha256 === null || value.helper_journal === null || value.helper_journal.final_verification !== "PASS" || !value.atomic_rename || !value.directory_fsync) fail(node, "Applied mutation receipt is incomplete");
        if (value.operation === "DELETE" ? !allNull(value.after) : !allPresent(value.after) || value.after.digest !== request.replacement_digest || value.after.size !== request.replacement_byte_count || value.after.mode !== request.requested_final_mode) fail(node, "Applied mutation receipt after-state facts are impossible");
      } else if (value.successor_state_token_content_sha256 !== null || value.postflight_content_sha256 !== null || value.failure_code === null) fail(node, "Blocked mutation receipt claims a successor or omits failure");
      if (value.outcome === "PREIMAGE_MISMATCH" && (value.failure_code !== "PREIMAGE_MISMATCH" || value.helper_journal === null || (value.helper_journal.atomic_rename_completed && (!value.helper_journal.rollback_required || !value.helper_journal.rollback_completed || value.rollback_outcome !== "SUCCEEDED")))) fail(node, "PREIMAGE_MISMATCH receipt loses exchange/rollback activity");
    }
    if (value.file_fsync !== (value.helper_journal?.temporary_file_fsync_completed ?? false) || value.atomic_rename !== (value.helper_journal?.atomic_rename_completed ?? false) || value.directory_fsync !== ((value.helper_journal?.directory_fsync_completed_count ?? 0) > 0)) fail(node, "Mutation receipt summary contradicts its journal");
    if (value.successor_state_token_content_sha256 !== null) { add(node, "M3_REPOSITORY_STATE_TOKEN", value.successor_state_token_content_sha256); add(node, "M3_POSTFLIGHT", value.postflight_content_sha256); }
  }
  for (const [digest, value] of input.commandResults) {
    const node = nodes.get(key("M4_COMMAND_RESULT", digest))!; add(node, "M4_TOOL_REQUEST", value.request_content_sha256); add(node, "M4_COMMAND_CATALOG", value.command_catalog_content_sha256); add(node, "M4_SANDBOX_CAPABILITY", value.sandbox_capability_content_sha256); add(node, "M3_REPOSITORY_STATE_TOKEN", value.state_token_before);
    if (value.state_token_after !== null) { add(node, "M3_REPOSITORY_STATE_TOKEN", value.state_token_after); add(node, "M3_POSTFLIGHT", value.postflight_content_sha256); }
    const request = input.toolRequests.get(value.request_content_sha256); const catalog = input.catalogs.get(value.command_catalog_content_sha256);
    if (value.run_id !== input.runId) fail(node, "Command result run authority contradicts its storage run");
    if (request !== undefined && (request.run_id !== value.run_id || request.request_kind !== "COMMAND" || request.command_id !== value.command_id || request.command_catalog_content_sha256 !== value.command_catalog_content_sha256 || request.command_spec_sha256 !== value.command_spec_sha256 || request.sandbox_capability_content_sha256 !== value.sandbox_capability_content_sha256 || request.state_token_content_sha256 !== value.state_token_before)) fail(node, "Command result predecessor relationship is invalid");
    if (catalog !== undefined) validateOutput(node, value, catalog);
    if (value.state_token_after === null ? value.postflight_content_sha256 !== null : value.postflight_content_sha256 === null) fail(node, "Command result successor/postflight relationship is incomplete");
  }

  const allKinds = new Map<string, StoredObjectKind[]>();
  for (const object of [...input.objects, ...input.m3Classifications.map((entry) => entry.object)]) allKinds.set(object.contentSha256, [...(allKinds.get(object.contentSha256) ?? []), object.kind]);
  const state = new Map<string, "VALID" | "INVALID" | "INCOMPLETE">();
  const visit = (nodeKey: string, stack: Set<string>, depth: number): "VALID" | "INVALID" | "INCOMPLETE" => {
    const cached = state.get(nodeKey); if (cached !== undefined) return cached;
    const node = nodes.get(nodeKey); if (node === undefined) return "INCOMPLETE";
    if (node.error !== null) { state.set(nodeKey, "INVALID"); return "INVALID"; }
    if (depth > 64 || stack.has(nodeKey)) { node.error = "Managed authority graph loops or exceeds depth"; state.set(nodeKey, "INVALID"); return "INVALID"; }
    const next = new Set(stack); next.add(nodeKey); let decision: "VALID" | "INVALID" | "INCOMPLETE" = node.missing === null ? "VALID" : "INCOMPLETE";
    for (const ref of node.refs) {
      const m3 = m3Classes.get(key(ref.kind, ref.digest));
      if (m3 !== undefined) {
        if (m3 === "INVALID_MANAGED_RECORD") decision = "INVALID";
        else if (m3 !== "AUTHORITATIVE_MANAGED_RECORD") decision = decision === "INVALID" ? decision : "INCOMPLETE";
        continue;
      }
      const dependencyKey = key(ref.kind, ref.digest);
      if (!nodes.has(dependencyKey)) {
        decision = allKinds.has(ref.digest) ? "INVALID" : decision === "INVALID" ? decision : "INCOMPLETE";
        continue;
      }
      const dependency = visit(dependencyKey, next, depth + 1);
      if (dependency === "INVALID") decision = "INVALID"; else if (dependency === "INCOMPLETE" && decision !== "INVALID") decision = "INCOMPLETE";
    }
    state.set(nodeKey, decision); return decision;
  };
  for (const nodeKey of nodes.keys()) visit(nodeKey, new Set(), 0);
  const authoritative = new Set<string>(); const mark = (nodeKey: string): void => {
    if (authoritative.has(nodeKey) || state.get(nodeKey) !== "VALID") return; authoritative.add(nodeKey);
    for (const ref of nodes.get(nodeKey)?.refs ?? []) if (nodes.has(key(ref.kind, ref.digest))) mark(key(ref.kind, ref.digest));
  };
  for (const [nodeKey, node] of nodes) if (state.get(nodeKey) === "VALID" && ["M4_TOOL_RESULT", "M4_MUTATION_RECEIPT", "M4_COMMAND_RESULT"].includes(node.object.kind)) mark(nodeKey);
  return [...nodes.entries()].map(([nodeKey, node]) => {
    const decision = state.get(nodeKey)!;
    return { object: node.object,
      classification: decision === "INVALID" ? "INVALID_MANAGED_RECORD" : decision === "INCOMPLETE" ? "INCOMPLETE_MANAGED_RECORD_CHAIN" : authoritative.has(nodeKey) ? "AUTHORITATIVE_MANAGED_RECORD" : "UNREFERENCED_MANAGED_RECORD",
      detail: node.error ?? node.missing ?? (decision === "INCOMPLETE" ? "M4 managed authority predecessor is missing or incomplete" : authoritative.has(nodeKey) ? "Complete M4 semantic authority chain" : "Valid M4 record has no authoritative result edge") } as ManagedRecordClassification;
  });
}
