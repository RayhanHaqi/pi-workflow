import { arch, release } from "node:os";

import { sha256Canonical } from "../identity/index.js";
import { identifyContractDocument, type M4SandboxCapabilityDocument, type M4SecureFilesystemCapabilityDocument } from "../schemas/index.js";
import { boundedExecutableVersion } from "../repository/executable.js";
import { detachedFrozen } from "../repository/utils.js";
import { SecureFilesystemError, secureFilesystemError } from "./errors.js";
import { invokeSecureFilesystemHelper, resolveSecureFilesystemHelper } from "./helper.js";
import { invokeSandboxProbe, resolveSandboxHelper } from "./sandbox-helper.js";
import { secureFilesystemTestHooks } from "./test-hooks.js";

export interface M4CapabilityProbeResult {
  readonly secureFilesystem: M4SecureFilesystemCapabilityDocument;
  readonly sandbox: M4SandboxCapabilityDocument;
}

let lastProducedCapability: M4CapabilityProbeResult | null = null;

/** Private in-process producer authority; package exports do not expose this path. */
export function currentM4CapabilityProducerAuthority(): M4CapabilityProbeResult | null {
  return lastProducedCapability;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new SecureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", `${label} probe result is invalid`);
  return value;
}

function integerOrNull(value: unknown, label: string): number | null {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 255) {
    throw new SecureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", `${label} probe result is invalid`);
  }
  return value as number;
}

function libcIdentity(): string {
  const report = process.report.getReport() as unknown as { readonly header?: { readonly glibcVersionRuntime?: string; readonly glibcVersionCompiler?: string } };
  return `glibc-runtime=${report.header?.glibcVersionRuntime ?? "unknown"};glibc-compiler=${report.header?.glibcVersionCompiler ?? "unknown"}`;
}

export async function probeM4Capabilities(): Promise<M4CapabilityProbeResult> {
  const [secureHelper, sandboxHelper] = await Promise.all([resolveSecureFilesystemHelper(), resolveSandboxHelper()]);
  const [pythonVersion, sandboxPythonVersion, secureRaw, sandboxRaw] = await Promise.all([
    boundedExecutableVersion(secureHelper.python.invocationPath).catch((error: unknown) => { throw secureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Secure-helper Python version probe failed", error); }),
    boundedExecutableVersion(sandboxHelper.python.invocationPath).catch((error: unknown) => { throw secureFilesystemError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox-helper Python version probe failed", error); }),
    secureFilesystemTestHooks().forceCapabilityUnavailable === true
      ? Promise.resolve({ openat2: false, resolve_beneath: false, resolve_no_symlinks: false, resolve_no_magiclinks: false, renameat2: false, rename_noreplace: false, rename_exchange: false, directory_fsync: false, landlock_abi: null })
      : invokeSecureFilesystemHelper(secureHelper, { operation: "PROBE" }) as Promise<Record<string, unknown>>,
    secureFilesystemTestHooks().forceSandboxUnavailable === true
      ? Promise.resolve({ landlock_available: false, landlock_abi: null, filesystem_restrictions: false, child_inheritance: false, no_new_privs: false, seccomp_available: false, network_denial: false })
      : invokeSandboxProbe(sandboxHelper).then((result) => secureFilesystemTestHooks().forceNetworkUnavailable === true ? { ...result, network_denial: false } : result),
  ]);
  if (secureRaw === null || Array.isArray(secureRaw) || typeof secureRaw !== "object") {
    throw new SecureFilesystemError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Secure filesystem probe result is invalid");
  }
  const secure = secureRaw as Record<string, unknown>;
  const sandbox = sandboxRaw;
  const openat2 = boolean(secure["openat2"], "openat2");
  const resolveBeneath = boolean(secure["resolve_beneath"], "RESOLVE_BENEATH");
  const resolveNoSymlinks = boolean(secure["resolve_no_symlinks"], "RESOLVE_NO_SYMLINKS");
  const resolveNoMagiclinks = boolean(secure["resolve_no_magiclinks"], "RESOLVE_NO_MAGICLINKS");
  const renameat2 = boolean(secure["renameat2"], "renameat2");
  const noReplace = boolean(secure["rename_noreplace"], "RENAME_NOREPLACE");
  const exchange = boolean(secure["rename_exchange"], "RENAME_EXCHANGE");
  const directoryFsync = boolean(secure["directory_fsync"], "directory fsync");
  const landlock = boolean(sandbox["landlock_available"], "Landlock");
  const landlockAbi = integerOrNull(sandbox["landlock_abi"], "Landlock ABI");
  const filesystemRestrictions = boolean(sandbox["filesystem_restrictions"], "filesystem restriction");
  const childInheritance = boolean(sandbox["child_inheritance"], "sandbox child inheritance");
  const noNewPrivs = boolean(sandbox["no_new_privs"], "no_new_privs");
  const seccomp = boolean(sandbox["seccomp_available"], "seccomp");
  const networkDenial = boolean(sandbox["network_denial"], "network denial");
  const secureAvailable = openat2 && resolveBeneath && resolveNoSymlinks && resolveNoMagiclinks && renameat2 && noReplace && exchange && directoryFsync;
  const sandboxAvailable = landlock && landlockAbi !== null && filesystemRestrictions && childInheritance && noNewPrivs && seccomp;
  const timestamp = new Date().toISOString();
  const secureProbeEvidence = sha256Canonical({ protocol: "secure-fs-probe-evidence-v1", helper_sha256: secureHelper.sha256,
    python_sha256: secureHelper.pythonSha256, kernel_release: release(), architecture: arch(), libc_identity: libcIdentity(),
    openat2, resolve_beneath: resolveBeneath, resolve_no_symlinks: resolveNoSymlinks, resolve_no_magiclinks: resolveNoMagiclinks,
    renameat2, rename_noreplace: noReplace, rename_exchange: exchange, directory_fsync: directoryFsync });
  const sandboxProbeEvidence = sha256Canonical({ protocol: "command-sandbox-probe-evidence-v1", helper_sha256: sandboxHelper.sha256,
    python_sha256: sandboxHelper.pythonSha256, landlock, landlock_abi: landlockAbi, filesystem_restrictions: filesystemRestrictions,
    child_inheritance: childInheritance, no_new_privs: noNewPrivs, seccomp, network_denial: networkDenial });
  const sandboxDocument = identifyContractDocument("pi_gacw_sandbox_capability_v0", {
    schema_id: "pi_gacw_sandbox_capability_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    capability_protocol: "command-sandbox-capability-v1",
    probed_at: timestamp,
    probe_evidence_sha256: sandboxProbeEvidence,
    helper_protocol_version: "pi-gacw-command-sandbox-v1",
    helper_invocation_path: sandboxHelper.invocationPath,
    helper_realpath: sandboxHelper.realpath,
    helper_sha256: sandboxHelper.sha256,
    python_invocation_path: sandboxHelper.python.invocationPath,
    python_realpath: sandboxHelper.python.realpath,
    python_sha256: sandboxHelper.pythonSha256,
    python_version: sandboxPythonVersion,
    landlock_available: landlock,
    landlock_abi: landlockAbi,
    filesystem_restrictions: filesystemRestrictions,
    child_inheritance: childInheritance,
    no_new_privs: noNewPrivs,
    seccomp_available: seccomp,
    network_denial: networkDenial,
    result: sandboxAvailable ? "COMMAND_SANDBOX_AVAILABLE" : "COMMAND_SANDBOX_UNAVAILABLE",
    network_result: networkDenial ? "NETWORK_SANDBOX_AVAILABLE" : "NETWORK_SANDBOX_UNAVAILABLE",
  }) as M4SandboxCapabilityDocument;
  const secureDocument = identifyContractDocument("pi_gacw_secure_fs_capability_v0", {
    schema_id: "pi_gacw_secure_fs_capability_v0",
    schema_version: "0.1.0",
    content_projection_id: "document-content-v1",
    capability_protocol: "secure-fs-capability-v1",
    probed_at: timestamp,
    probe_evidence_sha256: secureProbeEvidence,
    helper_protocol_version: "pi-gacw-secure-fs-v1",
    helper_invocation_path: secureHelper.invocationPath,
    helper_realpath: secureHelper.realpath,
    helper_sha256: secureHelper.sha256,
    python_invocation_path: secureHelper.python.invocationPath,
    python_realpath: secureHelper.python.realpath,
    python_sha256: secureHelper.pythonSha256,
    python_version: pythonVersion,
    kernel_release: release(),
    architecture: arch(),
    libc_identity: libcIdentity(),
    openat2_available: openat2,
    supported_resolve_flags: [
      ...(resolveBeneath ? ["RESOLVE_BENEATH" as const] : []),
      ...(resolveNoSymlinks ? ["RESOLVE_NO_SYMLINKS" as const] : []),
      ...(resolveNoMagiclinks ? ["RESOLVE_NO_MAGICLINKS" as const] : []),
    ],
    renameat2_available: renameat2,
    rename_noreplace_available: noReplace,
    rename_exchange_available: exchange,
    directory_fsync_available: directoryFsync,
    landlock_available: landlock,
    landlock_abi: landlockAbi,
    no_new_privs_available: noNewPrivs,
    network_denial_available: networkDenial,
    secure_fs_result: secureAvailable ? "SECURE_FS_AVAILABLE" : "SECURE_FS_UNAVAILABLE",
    command_sandbox_result: sandboxAvailable ? "COMMAND_SANDBOX_AVAILABLE" : "COMMAND_SANDBOX_UNAVAILABLE",
    network_sandbox_result: networkDenial ? "NETWORK_SANDBOX_AVAILABLE" : "NETWORK_SANDBOX_UNAVAILABLE",
  }) as M4SecureFilesystemCapabilityDocument;
  lastProducedCapability = detachedFrozen({ secureFilesystem: secureDocument, sandbox: sandboxDocument });
  return lastProducedCapability;
}

export async function probeSecureFilesystemCapabilities(): Promise<M4SecureFilesystemCapabilityDocument> {
  return (await probeM4Capabilities()).secureFilesystem;
}
