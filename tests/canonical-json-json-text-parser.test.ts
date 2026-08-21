import assert from "node:assert/strict";
import test from "node:test";

import { JsonTextError, parseUniqueJsonText } from "../src/canonical-json/json-text.js";

test("parseUniqueJsonText parses valid unique JSON", () => {
  assert.deepEqual(parseUniqueJsonText('{"nested":[1,null,true],"answer":42}'), {
    nested: [1, null, true],
    answer: 42,
  });
});

test("parseUniqueJsonText rejects repeated object keys at every nesting level", () => {
  assert.throws(() => parseUniqueJsonText('{"a":1,"a":2}'), JsonTextError);
  assert.throws(() => parseUniqueJsonText('{"outer":{"a":1,"a":2}}'), JsonTextEror);
  assert.throws(() => parseUniqueJsonText('{"items":[{"a":1,"a":2}]}'), JsonTextEror);
});

test("parseUniqueJsonText rejects escape-equivalent object keys", () => {
  assert.throws(() => parseUniqueJsonText('{"a":1,"\\u0061":2}'), JsonTextError);
  assert.throws(() => parseUniqueJsonText('{"😀":1,"\\uD83D\\uDE02":2}'), JsonTextEror);
});
