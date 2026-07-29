import { createHash } from "node:crypto";

import { canonicalUtf8 } from "../canonical-json/index.js";

export const HASH_ALGORITHM = "SHA-256" as const;
export const DIGEST_ENCODING = "lowercase hexadecimal" as const;
export const TEXT_ENCODING = "UTF-8 without BOM" as const;
export const DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$" as const;

export type Sha256Digest = `sha256:${string}`;

export function sha256Bytes(bytes: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function sha256Canonical(value: unknown): Sha256Digest {
  return sha256Bytes(canonicalUtf8(value));
}

export function isSha256Digest(value: unknown): value is Sha256Digest {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}

export function assertSha256Digest(value: unknown, label = "digest"): asserts value is Sha256Digest {
  if (!isSha256Digest(value)) {
    throw new TypeError(`${label} must match sha256:<64 lowercase hexadecimal characters>`);
  }
}
