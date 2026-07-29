export const CANONICALIZATION_ID = "canonical-json-v1" as const;

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };

export class CanonicalJsonError extends TypeError {
  public constructor(message: string) {
    super(message);
    this.name = "CanonicalJsonError";
  }
}

function assertUnicodeScalarString(value: string, location: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalJsonError(`Unpaired high surrogate at ${location}`);
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new CanonicalJsonError(`Unpaired low surrogate at ${location}`);
    }
  }
}

function isPlainRecord(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function ownEnumerableDataValue(object: object, key: string, location: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
    throw new CanonicalJsonError(`Unsupported property descriptor at ${location}`);
  }
  return descriptor.value;
}

function serialize(value: unknown, location: string, ancestors: Set<object>): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number": {
      if (!Number.isFinite(value)) {
        throw new CanonicalJsonError(`Non-finite number at ${location}`);
      }
      return JSON.stringify(value);
    }
    case "string": {
      assertUnicodeScalarString(value, location);
      return JSON.stringify(value);
    }
    case "bigint":
    case "function":
    case "symbol":
    case "undefined":
      throw new CanonicalJsonError(`Unsupported ${typeof value} at ${location}`);
    case "object":
      break;
    default:
      throw new CanonicalJsonError(`Unsupported value at ${location}`);
  }

  const objectValue = value as object;
  if (ancestors.has(objectValue)) {
    throw new CanonicalJsonError(`Cyclic value at ${location}`);
  }
  ancestors.add(objectValue);

  try {
    if (Array.isArray(value)) {
      for (const key of Reflect.ownKeys(value)) {
        if (typeof key !== "string") {
          throw new CanonicalJsonError(`Unsupported symbol property at ${location}`);
        }
        if (key === "length") continue;
        const index = Number(key);
        if (!Number.isSafeInteger(index) || index < 0 || index >= value.length || String(index) !== key) {
          throw new CanonicalJsonError(`Unsupported array property ${key} at ${location}`);
        }
      }

      const entries: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const itemLocation = `${location}/${index}`;
        if (!Object.hasOwn(value, index)) {
          throw new CanonicalJsonError(`Sparse array entry at ${itemLocation}`);
        }
        entries.push(serialize(ownEnumerableDataValue(value, String(index), itemLocation), itemLocation, ancestors));
      }
      return `[${entries.join(",")}]`;
    }

    if (!isPlainRecord(objectValue)) {
      throw new CanonicalJsonError(`Non-plain object at ${location}`);
    }

    const record = value as Record<string, unknown>;
    const keys: string[] = [];
    for (const key of Reflect.ownKeys(record)) {
      if (typeof key !== "string") {
        throw new CanonicalJsonError(`Unsupported symbol property at ${location}`);
      }
      assertUnicodeScalarString(key, `${location}/<key>`);
      ownEnumerableDataValue(record, key, `${location}/${escapePointerToken(key)}`);
      keys.push(key);
    }
    keys.sort();
    const entries = keys.map((key) => {
      const memberLocation = `${location}/${escapePointerToken(key)}`;
      return `${JSON.stringify(key)}:${serialize(ownEnumerableDataValue(record, key, memberLocation), memberLocation, ancestors)}`;
    });
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(objectValue);
  }
}

function escapePointerToken(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

/**
 * Serializes an already parsed JSON-domain value according to canonical-json-v1.
 *
 * This value-level boundary cannot detect duplicate member names that an earlier
 * ordinary JSON.parse call discarded. Callers that need duplicate-name proof
 * must perform it before invoking this function.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, "", new Set<object>());
}

export function canonicalUtf8(value: unknown): Uint8Array {
  return Buffer.from(canonicalize(value), "utf8");
}
