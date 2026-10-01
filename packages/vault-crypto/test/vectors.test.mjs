// Known-answer tests against conformance/persistent/v1/vectors.json.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { generateVectors, serializeVectors, VECTORS_PATH } from "../../../conformance/persistent/v1/generate-vectors.mjs";
import {
  createDigester,
  createRecordCrypto,
  decodeEnvelope,
  decodePayload,
  deriveEntryId,
  deriveEntryKey,
  encodeAad,
  encodeEnvelope,
  encodePayload,
} from "../dist/index.js";
import { createLocalKeyProvider } from "../dist/local-key-provider.js";
import { hex, keyError, recordError, unhex } from "./helpers.mjs";

const committed = await readFile(VECTORS_PATH, "utf8");
const vectors = JSON.parse(committed);
const subtle = globalThis.crypto.subtle;

/** A provider that returns one given data key. Test-only. */
const fixedKeyProvider = (dekHex) => ({
  profile: "fixed-test-only",
  generateDataKey: async () => ({ keyRef: "fixed:1", wrappedKey: Uint8Array.of(1), plaintextKey: unhex(dekHex) }),
  unwrapDataKey: async () => unhex(dekHex),
  rewrapDataKey: async () => ({ keyRef: "fixed:1", wrappedKey: Uint8Array.of(1) }),
});
const contextOf = (binding) => ({ namespace: binding.namespace, tenant: binding.tenant, captureId: binding.captureId });
const openVector = (vector) =>
  createRecordCrypto({ keyProvider: fixedKeyProvider(vector.dek) }).openCapture({
    context: contextOf(vector.binding),
    keyRef: "fixed:1",
    wrappedKey: Uint8Array.of(1),
    records: [{ binding: vector.binding, envelope: unhex(vector.envelope) }],
  });
const localProvider = (vector) =>
  createLocalKeyProvider({
    keys: [{ id: vector.keyId, material: unhex(vector.material), state: "active" }],
    scope: { namespaces: [vector.context.namespace], tenants: [vector.context.tenant] },
  });

test("the committed vectors are exactly what the generator produces", async () => {
  const regenerated = await generateVectors();
  assert.deepEqual(regenerated, vectors);
  assert.equal(serializeVectors(regenerated), committed);
});

test("every group is present and non-empty", () => {
  for (const group of ["entryId", "sessionTag", "requestDigest", "entryKey", "aad", "payload", "envelope", "localWrap"]) {
    assert.ok(vectors[group].length > 0, group);
  }
  for (const group of ["envelope", "payload", "open", "localUnwrap"]) assert.ok(vectors.negative[group].length > 0, group);
});

test("entryId", async () => {
  for (const vector of vectors.entryId) {
    assert.equal(await deriveEntryId(vector.namespace, vector.tenant, vector.token), vector.entryId);
  }
});

test("sessionTag, keyed and unkeyed", async () => {
  assert.deepEqual([...new Set(vectors.sessionTag.map((vector) => vector.mode))].sort(), ["keyed", "unkeyed"]);
  for (const vector of vectors.sessionTag) {
    const digester = vector.mode === "keyed" ? createDigester({ key: unhex(vector.key) }) : createDigester({ unkeyed: true });
    assert.equal(await digester.sessionTag(vector.input), vector.sessionTag);
  }
});

test("requestDigest, keyed and unkeyed, including inputs given out of canonical order", async () => {
  assert.deepEqual([...new Set(vectors.requestDigest.map((vector) => vector.mode))].sort(), ["keyed", "unkeyed"]);
  for (const vector of vectors.requestDigest) {
    const digester = vector.mode === "keyed" ? createDigester({ key: unhex(vector.key) }) : createDigester({ unkeyed: true });
    assert.equal(hex(await digester.requestDigest(vector.input)), vector.requestDigest, vector.name);
  }
});

test("entryKey: the derived key encrypts as the vector's raw key does", async () => {
  for (const vector of vectors.entryKey) {
    const derived = await deriveEntryKey(unhex(vector.dek), vector.entryId);
    const raw = await subtle.importKey("raw", unhex(vector.entryKey), "AES-GCM", false, ["encrypt"]);
    const params = { name: "AES-GCM", iv: new Uint8Array(12), tagLength: 128 };
    const message = new Uint8Array(32);
    assert.equal(hex(new Uint8Array(await subtle.encrypt(params, derived, message))), hex(new Uint8Array(await subtle.encrypt(params, raw, message))));
  }
});

test("aad", () => {
  for (const vector of vectors.aad) assert.equal(hex(encodeAad(vector.binding)), vector.aad, vector.name);
});

test("payload: encoding, and decoding back to the canonical grants", () => {
  for (const vector of vectors.payload) {
    const payload = { ...vector.payload, value: unhex(vector.payload.value) };
    assert.equal(hex(encodePayload(payload)), vector.bytes, vector.name);
    const decoded = decodePayload(unhex(vector.bytes));
    assert.equal(hex(decoded.value), vector.payload.value);
    assert.equal(decoded.type, vector.payload.type);
    assert.deepEqual(decoded.grants, vector.canonicalGrants);
    assert.equal(decoded.policyRevision, vector.payload.policyRevision);
  }
});

test("envelope: binding and payload give the envelope under the fixed key and nonce, and it opens", async () => {
  for (const vector of vectors.envelope) {
    const key = await deriveEntryKey(unhex(vector.dek), vector.binding.entryId);
    const aad = encodeAad(vector.binding);
    assert.equal(hex(aad), vector.aad);
    const plaintext = encodePayload({ ...vector.payload, value: unhex(vector.payload.value) });
    assert.equal(hex(plaintext), vector.plaintext);
    const nonce = unhex(vector.nonce);
    const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext));
    assert.equal(hex(encodeEnvelope({ nonce, ciphertext: sealed })), vector.envelope, vector.name);
    assert.equal(hex(decodeEnvelope(unhex(vector.envelope)).nonce), vector.nonce);

    const [opened] = await openVector(vector);
    assert.equal(hex(opened.value), vector.payload.value);
    assert.equal(opened.type, vector.payload.type);
    assert.equal(opened.policyRevision, vector.payload.policyRevision);
  }
});

test("localWrap: the provider unwraps the vector's wrapped key to its data key", async () => {
  for (const vector of vectors.localWrap) {
    const provider = localProvider(vector);
    const dek = await provider.unwrapDataKey({ keyRef: vector.keyRef, wrappedKey: unhex(vector.wrappedKey), context: vector.context });
    assert.equal(hex(dek), vector.dek);
    assert.equal((await provider.generateDataKey(vector.context)).keyRef, vector.keyRef);
  }
});

test("negative: envelopes", async () => {
  for (const vector of vectors.negative.envelope) {
    const error = await recordError(() => decodeEnvelope(unhex(vector.envelope)), vector.error);
    assert.equal(error.code, vector.error, vector.name);
  }
});

test("negative: payloads", async () => {
  for (const vector of vectors.negative.payload) {
    const error = await recordError(() => decodePayload(unhex(vector.payload)), [vector.error]).catch((failure) => {
      throw new Error(`${vector.name}: ${failure.message}`);
    });
    assert.equal(error.code, vector.error, vector.name);
  }
});

test("negative: open", async () => {
  for (const vector of vectors.negative.open) {
    await recordError(() => openVector(vector), [vector.error]).catch((failure) => {
      throw new Error(`${vector.name}: ${failure.message}`);
    });
  }
});

test("negative: local unwrap", async () => {
  for (const vector of vectors.negative.localUnwrap) {
    const provider = createLocalKeyProvider({
      keys: [{ id: vector.keyId, material: unhex(vector.material), state: "active" }],
      scope: { namespaces: ["support-synthetic", "support-synthetic-2"] },
    });
    await keyError(() => provider.unwrapDataKey({ keyRef: vector.keyRef, wrappedKey: unhex(vector.wrappedKey), context: vector.context }), [vector.error]).catch(
      (failure) => {
        throw new Error(`${vector.name}: ${failure.message}`);
      },
    );
  }
});
