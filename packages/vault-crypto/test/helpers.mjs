// Shared fixtures. Every value, token, and key here is synthetic.
import assert from "node:assert/strict";

import { KeyProviderError, RecordCryptoError } from "@redact-secret/vault-contracts";

export const NAMESPACE = "support-synthetic";
export const TENANT = "tenant-acme-synthetic";
export const OTHER_TENANT = "tenant-northwind-synthetic";
export const CAPTURE_A = "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa";
export const CAPTURE_B = "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb";
export const SESSION = "session-synthetic-0001";
export const CREATED_AT = 1_790_000_000_000;
export const EXPIRES_AT = CREATED_AT + 3_600_000;
export const TOKENS = ["<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>", "<rsv_abcdefghijklmnopqrstuvwxyz>"];
export const VALUES = ["SYNTHETIC-VALUE-0001", "SYNTHETIC-VALUE-0002", "SYNTHETIC-VALUE-0003"];
export const FIXED_DEK = Uint8Array.from({ length: 32 }, (_unused, i) => i + 1);
export const CONTEXT = Object.freeze({ namespace: NAMESPACE, tenant: TENANT, captureId: CAPTURE_A });

const text = new TextEncoder();
export const utf8 = (value) => text.encode(value);
export const fromUtf8 = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
export const hex = (bytes) => Buffer.from(bytes).toString("hex");
export const unhex = (value) => Uint8Array.from(Buffer.from(value, "hex"));
export const base64 = (bytes) => Buffer.from(bytes).toString("base64");

/** A distinct, well-formed entry identifier per index. */
export const entryId = (index) => index.toString(16).padStart(64, "0");

export function binding(overrides = {}) {
  return {
    namespace: NAMESPACE,
    tenant: TENANT,
    captureId: CAPTURE_A,
    entryId: entryId(1),
    sessionId: null,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    maxUses: 1,
    ...overrides,
  };
}

export function payload(value = VALUES[0], overrides = {}) {
  return {
    value: typeof value === "string" ? utf8(value) : value,
    type: "synthetic-finding-type",
    grants: [{ sink: "sink-a", paths: ["body"] }],
    policyRevision: null,
    ...overrides,
  };
}

/**
 * A provider whose data key is fixed and whose wrapped key is a label. It
 * counts calls and remembers the arrays it handed out, so a test can see
 * that they were overwritten.
 */
export function fakeProvider({ dek = FIXED_DEK, keyRef = "fake:1" } = {}) {
  const calls = { generate: 0, unwrap: 0, rewrap: 0 };
  const handedOut = [];
  return {
    profile: "fake-test-only",
    calls,
    handedOut,
    async generateDataKey() {
      calls.generate += 1;
      const plaintextKey = dek.slice();
      handedOut.push(plaintextKey);
      return { keyRef, wrappedKey: utf8("synthetic-wrapped-key"), plaintextKey };
    },
    async unwrapDataKey() {
      calls.unwrap += 1;
      const plaintextKey = dek.slice();
      handedOut.push(plaintextKey);
      return plaintextKey;
    },
    async rewrapDataKey() {
      calls.rewrap += 1;
      return { keyRef: "fake:2", wrappedKey: utf8("synthetic-rewrapped-key") };
    },
  };
}

/** Strings that must never appear in any error of this suite. */
export const ALWAYS_FORBIDDEN = [
  ...VALUES,
  ...TOKENS,
  "SYNTHETIC-VALUE",
  "rsv_",
  hex(FIXED_DEK),
  base64(FIXED_DEK),
];

const ALLOWED_OWN = new Set(["stack", "message", "name", "code"]);

/**
 * The error hygiene every error of this package must satisfy: the fixed
 * message of its code, no `cause`, no property beyond `code`, and none of
 * the forbidden strings in any rendering of it.
 */
export function assertClean(error, forbidden = []) {
  assert.ok(error instanceof RecordCryptoError || error instanceof KeyProviderError, `foreign error: ${String(error)}`);
  const Class = error instanceof RecordCryptoError ? RecordCryptoError : KeyProviderError;
  assert.equal(error.constructor, Class);
  assert.equal(error.message, new Class(error.code).message, "message is not the fixed message of the code");
  assert.equal(error.cause, undefined);
  assert.equal("cause" in error, false);
  for (const name of Object.getOwnPropertyNames(error)) assert.ok(ALLOWED_OWN.has(name), `unexpected property ${name}`);
  assert.deepEqual(Object.getOwnPropertySymbols(error), []);
  const renderings = [
    JSON.stringify(error),
    JSON.stringify({ ...error }),
    String(error),
    String(error.stack),
    ...Object.getOwnPropertyNames(error).map((name) => String(error[name])),
  ];
  for (const rendering of renderings) {
    for (const needle of [...ALWAYS_FORBIDDEN, ...forbidden]) {
      assert.ok(!rendering.includes(needle), "an error rendering contains forbidden material");
    }
  }
}

/** Awaits `run`, requires it to fail with `Class` and `code`, checks hygiene, and returns the error. */
export async function rejectsWith(run, Class, code, forbidden = []) {
  let error;
  try {
    await (typeof run === "function" ? run() : run);
  } catch (caught) {
    error = caught;
  }
  assert.ok(error !== undefined, `expected ${code}, but the call succeeded`);
  assertClean(error, forbidden);
  assert.ok(error instanceof Class, `expected ${Class.name}, got ${error.name}`);
  const codes = Array.isArray(code) ? code : [code];
  assert.ok(codes.includes(error.code), `expected ${codes.join(" or ")}, got ${error.code}`);
  return error;
}

export const recordError = (run, code, forbidden) => rejectsWith(run, RecordCryptoError, code, forbidden);
export const keyError = (run, code, forbidden) => rejectsWith(run, KeyProviderError, code, forbidden);
