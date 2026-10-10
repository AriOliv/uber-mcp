import { test } from "node:test";
import assert from "node:assert/strict";

import { encodePathSegment, redact, validateToolArgs, ValidationError } from "../src/security.js";
import { executeToolValidated, toolDefinitions } from "../src/index.js";

const schema = {
  type: "object",
  properties: {
    query: { type: "string" },
    latitude: { type: "number" },
    type: { type: "string", enum: ["PICKUP", "DROPOFF"] },
    nested: { type: "object", properties: { a: { type: "boolean" } } },
  },
  required: ["query", "latitude"],
};

test("accepts valid args", () => {
  assert.deepEqual(validateToolArgs(schema, { query: "Av. Paulista", latitude: -23.5 }), {
    query: "Av. Paulista",
    latitude: -23.5,
  });
});

test("rejects wrong types, missing, enum, unknown properties", () => {
  assert.throws(() => validateToolArgs(schema, { query: 1, latitude: 1 }), ValidationError);
  assert.throws(() => validateToolArgs(schema, { query: "x" }), ValidationError);
  assert.throws(() => validateToolArgs(schema, { query: "x", latitude: 1, type: "OTHER" }), ValidationError);
  assert.throws(() => validateToolArgs(schema, { query: "x", latitude: 1, extra: 1 }), ValidationError);
  assert.throws(() => validateToolArgs(schema, { query: "x", latitude: NaN }), ValidationError);
  assert.throws(() => validateToolArgs(schema, "nope"), ValidationError);
});

test("rejects prototype pollution keys, control chars and oversized strings", () => {
  assert.throws(
    () => validateToolArgs(schema, JSON.parse('{"query":"x","latitude":1,"__proto__":{"a":1}}')),
    ValidationError
  );
  assert.throws(() => validateToolArgs(schema, { query: "a\u0000b", latitude: 1 }), ValidationError);
  assert.throws(() => validateToolArgs(schema, { query: "a".repeat(10_000), latitude: 1 }), ValidationError);
});

test("path params are encoded and traversal is rejected", () => {
  assert.equal(encodePathSegment("a/b?c#d"), "a%2Fb%3Fc%23d");
  assert.throws(() => encodePathSegment(".."), ValidationError);
});

test("redact strips tokens, cookies and PII", () => {
  const out = redact(
    "Bearer abcdef1234567890 cookie=sid_secret_value email me@example.com phone +55 11 91234-5678 eyJhbGciOi.eyJzdWIiOi.sigsigsig"
  );
  for (const leaked of ["abcdef1234567890", "sid_secret_value", "me@example.com", "91234-5678", "eyJhbGciOi"]) {
    assert.ok(!out.includes(leaked), `leaked ${leaked}: ${out}`);
  }
});

test("every tool schema is a valid object schema", () => {
  for (const def of toolDefinitions) {
    assert.equal((def.inputSchema as { type?: string }).type, "object", def.name);
  }
});

test("executeToolValidated rejects bad args before any network call", async () => {
  const def = toolDefinitions.find((d) => d.name === "uber_status_get")!;
  const r = await executeToolValidated(def, { latitude: "x", longitude: 0 });
  assert.equal(r.isError, true);
  assert.match((r.content[0] as { text: string }).text, /Invalid arguments/);
});
