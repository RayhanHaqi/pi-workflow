import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CANONICALIZATION_ID,
  CanonicalJsonError,
  canonicalUtf8,
  canonicalize,
} from "../src/canonical-json/index.js";

test("canonical-json-v1 orders object keys by raw UTF-16 code units", () => {
  const value = {
    "\u20ac": "Euro Sign",
    "\r": "Carriage Return",
    "\ufb33": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\ud83d\ude00": "Emoji: Grinning Face",
    "\u0080": "Control",
    "\u00f6": "Latin Small Letter O With Diaeresis",
  };

  assert.equal(CANONICALIZATION_ID, "canonical-json-v1");
  assert.equal(
    canonicalize(value),
    "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}",
  );
});

test("arrays preserve order and canonical output has no insignificant whitespace", () => {
  assert.equal(canonicalize({ z: [3, 2, 1], a: true }), "{\"a\":true,\"z\":[3,2,1]}");
  assert.notEqual(canonicalize(["a", "b"]), canonicalize(["b", "a"]));
});

test("finite ECMAScript JSON numbers use the JCS representation", () => {
  assert.equal(canonicalize([333333333.33333329, 1e30, 4.5, 0.002, 1e-27, -0]), "[333333333.3333333,1e+30,4.5,0.002,1e-27,0]");
  assert.equal(canonicalize([Number.MIN_VALUE, Number.MAX_VALUE]), "[5e-324,1.7976931348623157e+308]");
});

test("NaN and both infinities are rejected", () => {
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    assert.throws(() => canonicalize(value), CanonicalJsonError);
    assert.throws(() => canonicalize({ value }), CanonicalJsonError);
  }
});

test("UTF-8 bytes are stable and strings are not Unicode-normalized", () => {
  const decomposed = "e\u0301";
  const composed = "é";
  assert.deepEqual(canonicalUtf8({ text: "€雪" }), Buffer.from('{"text":"€雪"}', "utf8"));
  assert.equal(Buffer.from(canonicalUtf8({ text: "€雪" })).toString("hex"), "7b2274657874223a22e282ace99baa227d");
  assert.notEqual(canonicalize({ text: decomposed }), canonicalize({ text: composed }));
});

test("ordering is locale-independent and does not call localeCompare", () => {
  const original = String.prototype.localeCompare;
  String.prototype.localeCompare = function forbiddenLocaleCompare(): never {
    throw new Error("localeCompare must not be called");
  };
  try {
    assert.equal(canonicalize({ ä: 1, z: 2, a: 3 }), '{"a":3,"z":2,"ä":1}');
  } finally {
    String.prototype.localeCompare = original;
  }
});

test("the RFC 8785 number-and-string fixture canonicalizes exactly", async () => {
  const fixtureText = await readFile(new URL("../fixtures/canonical-json/rfc8785-number-string.json", import.meta.url), "utf8");
  const fixture = JSON.parse(fixtureText) as { readonly input: unknown; readonly canonical: string };
  assert.equal(canonicalize(fixture.input), fixture.canonical);
});

test("unsupported JavaScript-domain inputs are rejected", () => {
  const cyclic: Record<string, unknown> = {};
  cyclic["self"] = cyclic;
  const sparse = new Array(2);
  sparse[0] = "present";
  const symbolProperty = { ordinary: true } as Record<PropertyKey, unknown>;
  symbolProperty[Symbol("hidden")] = false;
  const extraArrayProperty = [1] as number[] & { extra?: number };
  extraArrayProperty.extra = 2;
  const nonEnumerable = { visible: true };
  Object.defineProperty(nonEnumerable, "hidden", { value: false, enumerable: false });
  const accessor = {};
  Object.defineProperty(accessor, "value", { get: () => 1, enumerable: true });

  const unsupported: unknown[] = [
    undefined,
    1n,
    Symbol("value"),
    () => undefined,
    new Date(0),
    cyclic,
    sparse,
    symbolProperty,
    extraArrayProperty,
    nonEnumerable,
    accessor,
    { nested: undefined },
    "\ud800",
    { "\udc00": true },
  ];
  for (const value of unsupported) {
    assert.throws(() => canonicalize(value), CanonicalJsonError);
  }
});

test("plain null-prototype JSON records remain supported", () => {
  const record = Object.create(null) as Record<string, unknown>;
  record["b"] = 2;
  record["a"] = 1;
  assert.equal(canonicalize(record), '{"a":1,"b":2}');
});
