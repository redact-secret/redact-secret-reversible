// Shared fixtures. Every identifier, ARN, and key here is synthetic.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { KeyProviderError } from "@redact-secret/vault-contracts";

import { ACCOUNT, SDK_REQUEST_ID, SDK_TEXT } from "./fake-kms.mjs";

export const NAMESPACE = "support-synthetic";
export const OTHER_NAMESPACE = "billing-synthetic";
export const TENANT = "tenant-acme-synthetic";
export const OTHER_TENANT = "tenant-globex-synthetic";
export const CAPTURE_A = "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa";
export const CAPTURE_B = "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb";
export const CONTEXT = Object.freeze({ namespace: NAMESPACE, tenant: TENANT, captureId: CAPTURE_A });
export const SCOPE = Object.freeze({ namespaces: [NAMESPACE, OTHER_NAMESPACE], tenants: [TENANT, OTHER_TENANT] });

export const hex = (bytes) => Buffer.from(bytes).toString("hex");

function lp16(text) {
  const bytes = Buffer.from(text, "utf8");
  const length = Buffer.alloc(2);
  length.writeUInt16BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/** The context digest, computed here independently of the package. */
export function expectedDigest(context) {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from("rsv-kms-context-v1\0", "utf8"), lp16(context.namespace), lp16(context.tenant), lp16(context.captureId)]))
    .digest("base64url");
}

const ALLOWED_OWN = new Set(["stack", "message", "name", "code"]);

/**
 * The error hygiene of specification §4.1: a `KeyProviderError` with the
 * fixed message of its code, no `cause`, no property beyond `code`, and no
 * SDK text, request id, ARN, account id, or other forbidden string in any
 * rendering of it.
 */
export function assertClean(error, forbidden = []) {
  assert.ok(error instanceof KeyProviderError, `foreign error: ${String(error)}`);
  assert.equal(error.constructor, KeyProviderError);
  assert.equal(error.message, new KeyProviderError(error.code).message, "message is not the fixed message of the code");
  assert.equal(error.cause, undefined);
  assert.equal("cause" in error, false);
  for (const name of Object.getOwnPropertyNames(error)) assert.ok(ALLOWED_OWN.has(name), `unexpected property ${name}`);
  assert.deepEqual(Object.getOwnPropertySymbols(error), []);
  const own = {};
  for (const name of Object.getOwnPropertyNames(error)) own[name] = error[name];
  const renderings = [error.message, error.stack ?? "", String(error), JSON.stringify(error), JSON.stringify(own)].join("\n");
  for (const text of [SDK_TEXT, SDK_REQUEST_ID, "arn:aws", ACCOUNT, "$metadata", "requestId", ...forbidden]) {
    assert.equal(renderings.includes(text), false, "an error rendering contains forbidden text");
  }
}

/** Awaits a rejection, checks its hygiene and code, and returns it. */
export async function keyError(promise, code, forbidden = []) {
  let error;
  try {
    const value = await promise;
    if (value instanceof Uint8Array) value.fill(0);
  } catch (caught) {
    error = caught;
  }
  assert.ok(error !== undefined, `expected ${code}, but the call succeeded`);
  assertClean(error, forbidden);
  assert.equal(error.code, code);
  return error;
}

/** Synchronous variant, for construction. */
export function keyErrorSync(fn, code) {
  let error;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  assert.ok(error !== undefined, `expected ${code}, but construction succeeded`);
  assertClean(error);
  assert.equal(error.code, code);
  return error;
}

const CONTEXT_FIELDS = {
  GenerateDataKeyCommand: ["EncryptionContext"],
  DecryptCommand: ["EncryptionContext"],
  ReEncryptCommand: ["SourceEncryptionContext", "DestinationEncryptionContext"],
};
const KEY_ARN = /^arn:aws:kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/;

/**
 * Checks every command a client received:
 * - each encryption context is exactly `rsv:ctx` (43 base64url characters),
 *   `rsv:v` = "1", and the given labels;
 * - nothing in the request, apart from the wrapped key bytes, contains an
 *   identifier of a `KeyContext` (`identifiers`, and anything that looks like
 *   a capture identifier);
 * - `Decrypt` names its key by full ARN, and `ReEncrypt` names both keys.
 */
export function assertCommands(calls, identifiers, labels = {}) {
  for (const { name, input } of calls) {
    const fields = CONTEXT_FIELDS[name];
    assert.ok(fields !== undefined, `unexpected command ${name}`);
    for (const field of fields) {
      const context = input[field];
      assert.ok(context !== undefined, `${name} was sent without ${field}`);
      assert.deepEqual(Object.keys(context).sort(), ["rsv:ctx", "rsv:v", ...Object.keys(labels)].sort());
      assert.match(context["rsv:ctx"], /^[A-Za-z0-9_-]{43}$/);
      assert.equal(context["rsv:v"], "1");
      for (const [key, value] of Object.entries(labels)) assert.equal(context[key], value);
    }
    if (name === "GenerateDataKeyCommand") {
      assert.match(input.KeyId, KEY_ARN);
      assert.equal(input.KeySpec, "AES_256");
      assert.deepEqual(Object.keys(input).sort(), ["EncryptionContext", "KeyId", "KeySpec"]);
    }
    if (name === "DecryptCommand") {
      assert.match(input.KeyId ?? "", KEY_ARN, "Decrypt was sent without an explicit key ARN");
      assert.deepEqual(Object.keys(input).sort(), ["CiphertextBlob", "EncryptionContext", "KeyId"]);
    }
    if (name === "ReEncryptCommand") {
      assert.match(input.SourceKeyId ?? "", KEY_ARN, "ReEncrypt was sent without an explicit source key ARN");
      assert.match(input.DestinationKeyId ?? "", KEY_ARN);
      assert.deepEqual(input.SourceEncryptionContext, input.DestinationEncryptionContext);
    }
    const text = JSON.stringify(input, (key, value) => (key === "CiphertextBlob" ? undefined : value));
    assert.equal(/cap_[a-z0-9]/.test(text), false, `${name} carries a capture identifier`);
    for (const identifier of identifiers) {
      assert.equal(text.includes(identifier), false, `${name} carries an identifier of the key context`);
    }
  }
}
