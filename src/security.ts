/**
 * Security helpers: strict tool-argument validation against the declared
 * JSON schema, path-parameter encoding, and redaction of secrets/PII from
 * anything that leaves the process (errors, logs, tool output).
 */

type Schema = {
  type?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  enum?: unknown[];
  items?: Schema;
  additionalProperties?: boolean | Schema;
  minimum?: number;
  maximum?: number;
  maxLength?: number;
};

export const MAX_STRING_LENGTH = 4096;
const MAX_DEPTH = 8;
const MAX_ARRAY_LENGTH = 256;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export class ValidationError extends Error {}

function validateValue(value: unknown, schema: Schema, path: string, depth: number): unknown {
  if (depth > MAX_DEPTH) throw new ValidationError(`${path}: nesting too deep`);

  if (schema.enum && !schema.enum.includes(value)) {
    throw new ValidationError(`${path}: must be one of ${schema.enum.map(String).join(", ")}`);
  }

  switch (schema.type) {
    case "string": {
      if (typeof value !== "string") throw new ValidationError(`${path}: must be a string`);
      if (value.length > (schema.maxLength ?? MAX_STRING_LENGTH)) {
        throw new ValidationError(`${path}: string too long`);
      }
      // eslint-disable-next-line no-control-regex
      if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value)) {
        throw new ValidationError(`${path}: contains control characters`);
      }
      return value;
    }
    case "number":
    case "integer": {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new ValidationError(`${path}: must be a finite number`);
      }
      if (schema.type === "integer" && !Number.isInteger(value)) {
        throw new ValidationError(`${path}: must be an integer`);
      }
      if (schema.minimum !== undefined && value < schema.minimum) {
        throw new ValidationError(`${path}: below minimum`);
      }
      if (schema.maximum !== undefined && value > schema.maximum) {
        throw new ValidationError(`${path}: above maximum`);
      }
      return value;
    }
    case "boolean":
      if (typeof value !== "boolean") throw new ValidationError(`${path}: must be a boolean`);
      return value;
    case "array": {
      if (!Array.isArray(value)) throw new ValidationError(`${path}: must be an array`);
      if (value.length > MAX_ARRAY_LENGTH) throw new ValidationError(`${path}: array too long`);
      const items = schema.items;
      return items ? value.map((v, i) => validateValue(v, items, `${path}[${i}]`, depth + 1)) : value;
    }
    case "object":
      return validateObject(value, schema, path, depth + 1);
    default:
      // Untyped schema node: still bound the size and reject poisoned keys.
      assertPlain(value, path, depth);
      return value;
  }
}

function assertPlain(value: unknown, path: string, depth: number): void {
  if (depth > MAX_DEPTH) throw new ValidationError(`${path}: nesting too deep`);
  if (typeof value === "string" && value.length > MAX_STRING_LENGTH * 4) {
    throw new ValidationError(`${path}: string too long`);
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_LENGTH) throw new ValidationError(`${path}: array too long`);
    value.forEach((v, i) => assertPlain(v, `${path}[${i}]`, depth + 1));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(k)) throw new ValidationError(`${path}: forbidden key`);
      assertPlain(v, `${path}.${k}`, depth + 1);
    }
  }
}

function validateObject(value: unknown, schema: Schema, path: string, depth: number): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ValidationError(`${path}: must be an object`);
  }
  const props = schema.properties ?? {};
  const input = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};

  for (const key of Object.keys(input)) {
    if (FORBIDDEN_KEYS.has(key)) throw new ValidationError(`${path}: forbidden key`);
    if (!Object.prototype.hasOwnProperty.call(props, key)) {
      if (schema.additionalProperties === true || typeof schema.additionalProperties === "object") {
        const sub = typeof schema.additionalProperties === "object" ? schema.additionalProperties : {};
        out[key] = validateValue(input[key], sub, `${path}.${key}`, depth);
        continue;
      }
      // Free-form object nodes (no declared properties) are accepted but bounded.
      if (Object.keys(props).length === 0) {
        assertPlain(input[key], `${path}.${key}`, depth);
        out[key] = input[key];
        continue;
      }
      throw new ValidationError(`${path}: unexpected property "${key.slice(0, 64)}"`);
    }
    out[key] = validateValue(input[key], props[key], `${path}.${key}`, depth);
  }
  for (const req of schema.required ?? []) {
    if (out[req] === undefined) throw new ValidationError(`${path}: missing required "${req}"`);
  }
  return out;
}

/** Validate tool arguments against the tool's input schema. Throws ValidationError. */
export function validateToolArgs(
  schema: Record<string, unknown>,
  args: unknown
): Record<string, unknown> {
  return validateObject(args ?? {}, schema as Schema, "args", 0);
}

/** Percent-encode a value for safe use as a single URL path segment. */
export function encodePathSegment(value: unknown): string {
  const s = String(value);
  if (s === "." || s === "..") throw new ValidationError("invalid path parameter");
  return encodeURIComponent(s);
}

/* ------------------------------- redaction -------------------------------- */

const REDACTIONS: Array<[RegExp, string]> = [
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [REDACTED]"],
  [/\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g, "[REDACTED_JWT]"],
  [
    /\b(cookie|set-cookie|authorization|x-csrf-token|access_token|refresh_token|id_token|token|password|passwd|secret|sid|csid|jwt-session)(["']?\s*[:=]\s*["']?)[^\s"';,&}]{3,}/gi,
    "$1$2[REDACTED]",
  ],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED_EMAIL]"],
  [/(?<![\d.])\+?\d[\d\s().-]{8,}\d(?![\d.])/g, "[REDACTED_PHONE]"],
];

/** Strip tokens, cookies and common PII from free text. */
export function redact(input: unknown, maxLength = 500): string {
  let s = typeof input === "string" ? input : safeStringify(input);
  for (const [re, rep] of REDACTIONS) s = s.replace(re, rep);
  return s.length > maxLength ? `${s.slice(0, maxLength)}…` : s;
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}
