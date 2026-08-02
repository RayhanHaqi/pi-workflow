import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";

import { canonicalize } from "../src/canonical-json/index.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { sha256Bytes, type Sha256Digest } from "../src/identity/index.js";
import {
  identifyContractDocument,
  type M4CommandCatalogDocument,
  type M4CommandResultDocument,
  type M4MutationReceiptDocument,
  type M4PatchRequestDocument,
  type M4SandboxCapabilityDocument,
  type M4ScopedToolPolicyDocument,
  type M4SecureFilesystemCapabilityDocument,
  type M4ToolRequestDocument,
  type M4ToolResultDocument,
  type SchemaId,
} from "../src/schemas/index.js";
import { M4_RECORD_DEFINITIONS, canonicalM4RecordBytes, m4RecordPath, type M4RecordDocumentByKind, type M4RecordKind } from "../src/scoped-tools/records.js";
import { ScopedToolGatewayError } from "../src/scoped-tools/index.js";
import { releaseAdmission } from "./repository-matrix-helpers.js";
import { removeRepositoryFixture } from "./repository-helpers.js";
import type { createM4Fixture } from "./m4-helpers.js";

export type M4Fixture = Awaited<ReturnType<typeof createM4Fixture>>;
export type M4Document =
  | M4CommandCatalogDocument
  | M4CommandResultDocument
  | M4MutationReceiptDocument
  | M4PatchRequestDocument
  | M4SandboxCapabilityDocument
  | M4ScopedToolPolicyDocument
  | M4SecureFilesystemCapabilityDocument
  | M4ToolRequestDocument
  | M4ToolResultDocument;

export function gatewayCode(error: unknown): string | undefined {
  return error instanceof ScopedToolGatewayError
    ? error.code
    : error !== null && typeof error === "object" && typeof (error as { readonly code?: unknown }).code === "string"
      ? (error as { readonly code: string }).code
      : undefined;
}

export function gatewayToken(value: M4Fixture): Sha256Digest {
  return value.gateway.acceptedState.content_sha256 as Sha256Digest;
}

export async function disposeM4(value: M4Fixture): Promise<void> {
  await releaseAdmission(value.admission);
  await removeRepositoryFixture(value.fixture);
}

export async function storedM4Document<K extends M4RecordKind>(value: M4Fixture, kind: K): Promise<M4RecordDocumentByKind[K]> {
  const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
  const object = inspection.managedObjects.find((entry) => entry.kind === M4_RECORD_DEFINITIONS[kind].persistenceKind);
  assert.ok(object, `stored ${kind} record`);
  return JSON.parse(await readFile(join(value.fixture.stateRoot, "runs", value.fixture.runId, object.relativePath), "utf8")) as M4RecordDocumentByKind[K];
}

export async function storedM4ByDigest<K extends M4RecordKind>(value: M4Fixture, kind: K, digest: string): Promise<M4RecordDocumentByKind[K]> {
  const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
  const object = inspection.managedObjects.find((entry) => entry.kind === M4_RECORD_DEFINITIONS[kind].persistenceKind && entry.contentSha256 === digest);
  assert.ok(object, `stored ${kind} record ${digest}`);
  return JSON.parse(await readFile(join(value.fixture.stateRoot, "runs", value.fixture.runId, object.relativePath), "utf8")) as M4RecordDocumentByKind[K];
}

export async function persistM4<K extends M4RecordKind>(value: M4Fixture, kind: K, document: M4RecordDocumentByKind[K]): Promise<void> {
  const path = m4RecordPath({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId }, kind, document.content_sha256 as Sha256Digest);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, canonicalM4RecordBytes(document), { mode: 0o600 });
}

export function reidentify<T extends M4Document>(schema: SchemaId, value: T, mutate: (draft: Record<string, unknown>) => void): T {
  const draft = structuredClone(value) as unknown as Record<string, unknown>;
  delete draft["content_sha256"];
  mutate(draft);
  return identifyContractDocument(schema, draft) as T;
}

export async function classification(value: M4Fixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

export async function allPersistedM4Text(value: M4Fixture): Promise<string> {
  const inspection = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
  const paths = inspection.managedObjects.filter((entry) => entry.kind.startsWith("M4_")).map((entry) => join(value.fixture.stateRoot, "runs", value.fixture.runId, entry.relativePath));
  return (await Promise.all(paths.map((path) => readFile(path, "utf8")))).join("\n");
}

export function containsForbiddenSecretValue(value: unknown, strings: readonly string[], numbers: readonly number[]): boolean {
  if (typeof value === "string") return strings.some((sentinel) => value.includes(sentinel));
  if (typeof value === "number") return numbers.includes(value);
  if (value === null || typeof value !== "object") return false;
  return Object.values(value as Record<string, unknown>).some((entry) => containsForbiddenSecretValue(entry, strings, numbers));
}

export function assertNoForbiddenSecretValues(value: unknown, strings: readonly string[], numbers: readonly number[]): void {
  assert.equal(containsForbiddenSecretValue(value, strings, numbers), false);
}

export function sha256Text(value: string): Sha256Digest {
  return sha256Bytes(Buffer.from(value, "utf8"));
}

export function canonicalText(value: unknown): string {
  return canonicalize(value);
}

export async function removeIfPresent(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

export type M4RecordFixtures = {
  readonly secure: M4SecureFilesystemCapabilityDocument;
  readonly sandbox: M4SandboxCapabilityDocument;
  readonly policy: M4ScopedToolPolicyDocument;
  readonly catalog: M4CommandCatalogDocument;
  readonly readRequest: M4ToolRequestDocument;
  readonly readResult: M4ToolResultDocument;
  readonly patch: M4PatchRequestDocument;
  readonly receipt: M4MutationReceiptDocument;
  readonly commandRequest: M4ToolRequestDocument;
  readonly commandResult: M4CommandResultDocument;
};
