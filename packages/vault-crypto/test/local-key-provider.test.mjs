// The local key provider of specification §6.3.
import assert from "node:assert/strict";
import test from "node:test";

import { createLocalKeyProvider, LOCAL_KEY_PROVIDER_PROFILE } from "../dist/local-key-provider.js";
import { base64, CAPTURE_A, CAPTURE_B, CONTEXT, hex, keyError, NAMESPACE, OTHER_TENANT, TENANT } from "./helpers.mjs";

const material = (start) => Uint8Array.from({ length: 32 }, (_unused, i) => (start + i) & 0xff);
const SCOPE = { namespaces: [NAMESPACE, "support-synthetic-2"] };
const single = (overrides = {}) =>
  createLocalKeyProvider({ keys: [{ id: "2026-10", material: material(0x80), state: "active" }], scope: SCOPE, ...overrides });
const rotated = (oldState = "decrypt-only") =>
  createLocalKeyProvider({
    keys: [
      { id: "2026-10", material: material(0x10), state: "active" },
      { id: "2026-07", material: material(0x80), state: oldState },
    ],
    scope: SCOPE,
  });

test("generate returns a fresh 32-byte key, a 61-byte wrapped key, and the active key reference", async () => {
  const provider = single();
  assert.equal(provider.profile, LOCAL_KEY_PROVIDER_PROFILE);
  assert.equal(provider.profile, "local-hkdf-aes-256-gcm-v1");
  const a = await provider.generateDataKey(CONTEXT);
  const b = await provider.generateDataKey(CONTEXT);
  assert.equal(a.keyRef, "local:2026-10");
  assert.equal(a.plaintextKey.length, 32);
  assert.equal(a.wrappedKey.length, 1 + 12 + 32 + 16);
  assert.equal(a.wrappedKey[0], 1);
  assert.notEqual(hex(a.plaintextKey), hex(b.plaintextKey));
  assert.notEqual(hex(a.wrappedKey.subarray(1, 13)), hex(b.wrappedKey.subarray(1, 13)), "wrap nonces repeat");
  assert.ok(!hex(a.wrappedKey).includes(hex(a.plaintextKey)), "the data key is readable in its wrapped form");
  assert.deepEqual(await provider.unwrapDataKey({ keyRef: a.keyRef, wrappedKey: a.wrappedKey, context: CONTEXT }), a.plaintextKey);
});

test("200 wraps use 200 distinct nonces", async () => {
  const provider = single();
  const nonces = new Set();
  for (let i = 0; i < 200; i += 1) nonces.add(hex((await provider.generateDataKey(CONTEXT)).wrappedKey.subarray(1, 13)));
  assert.equal(nonces.size, 200);
});

test("rotation: the active and the decrypt-only key both unwrap, and generate uses the active one", async () => {
  const old = single();
  const wrappedUnderOld = await old.generateDataKey(CONTEXT);
  const provider = rotated();
  const fresh = await provider.generateDataKey(CONTEXT);
  assert.equal(fresh.keyRef, "local:2026-10");
  assert.deepEqual(await provider.unwrapDataKey({ keyRef: fresh.keyRef, wrappedKey: fresh.wrappedKey, context: CONTEXT }), fresh.plaintextKey);
  // The key the old provider called 2026-10 is this provider's 2026-07.
  assert.deepEqual(
    await provider.unwrapDataKey({ keyRef: "local:2026-07", wrappedKey: wrappedUnderOld.wrappedKey, context: CONTEXT }),
    wrappedUnderOld.plaintextKey,
  );
  // It unwraps with exactly the named key and never tries another.
  await keyError(() => provider.unwrapDataKey({ keyRef: "local:2026-10", wrappedKey: wrappedUnderOld.wrappedKey, context: CONTEXT }), "KEY_INTEGRITY", [
    hex(wrappedUnderOld.plaintextKey),
    base64(wrappedUnderOld.plaintextKey),
  ]);
});

test("a retired key and an unknown key reference are KEY_UNAVAILABLE", async () => {
  const wrappedUnderOld = await single().generateDataKey(CONTEXT);
  const provider = rotated("retired");
  await keyError(() => provider.unwrapDataKey({ keyRef: "local:2026-07", wrappedKey: wrappedUnderOld.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  await keyError(() => provider.rewrapDataKey({ keyRef: "local:2026-07", wrappedKey: wrappedUnderOld.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  for (const keyRef of ["local:2025-01", "local:", "2026-10", "LOCAL:2026-10", "local:2026-10 ", "kms:2026-10", "local:local:2026-10", ""]) {
    await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: wrappedUnderOld.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  }
});

test("unwrapping under a different context is KEY_INTEGRITY, for each field", async () => {
  const provider = single();
  const { keyRef, wrappedKey } = await provider.generateDataKey(CONTEXT);
  for (const change of [{ namespace: "support-synthetic-2" }, { tenant: OTHER_TENANT }, { captureId: CAPTURE_B }]) {
    await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey, context: { ...CONTEXT, ...change } }), "KEY_INTEGRITY");
    await keyError(() => provider.rewrapDataKey({ keyRef, wrappedKey, context: { ...CONTEXT, ...change } }), "KEY_INTEGRITY");
  }
  // Field boundaries are length-prefixed: moving a character between fields is a different context.
  const shifted = createLocalKeyProvider({ keys: [{ id: "2026-10", material: material(0x80), state: "active" }], scope: { namespaces: ["ns-a", "ns-"] } });
  const made = await shifted.generateDataKey({ namespace: "ns-a", tenant: "b-tenant", captureId: CAPTURE_A });
  await keyError(() => shifted.unwrapDataKey({ ...made, context: { namespace: "ns-", tenant: "ab-tenant", captureId: CAPTURE_A } }), "KEY_INTEGRITY");
});

test("a context outside the scope is KEY_UNAVAILABLE for every operation", async () => {
  const provider = createLocalKeyProvider({
    keys: [{ id: "2026-10", material: material(0x80), state: "active" }],
    scope: { namespaces: [NAMESPACE], tenants: [TENANT] },
  });
  const { keyRef, wrappedKey } = await provider.generateDataKey(CONTEXT);
  for (const outside of [{ ...CONTEXT, namespace: "support-synthetic-2" }, { ...CONTEXT, tenant: OTHER_TENANT }]) {
    await keyError(() => provider.generateDataKey(outside), "KEY_UNAVAILABLE");
    await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey, context: outside }), "KEY_UNAVAILABLE");
    await keyError(() => provider.rewrapDataKey({ keyRef, wrappedKey, context: outside }), "KEY_UNAVAILABLE");
  }
  // Without a tenant list, every tenant of an allowed namespace is in scope.
  const anyTenant = single();
  await anyTenant.generateDataKey({ ...CONTEXT, tenant: OTHER_TENANT });
  await keyError(() => anyTenant.generateDataKey({ ...CONTEXT, namespace: "support-synthetic-3" }), "KEY_UNAVAILABLE");
});

test("construction requires exactly one active key, unique identifiers, valid material, and an explicit scope", async () => {
  const key = (overrides = {}) => ({ id: "k1", material: material(1), state: "active", ...overrides });
  const aesKey = await globalThis.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const hkdfBitsOnly = await globalThis.crypto.subtle.importKey("raw", material(1), "HKDF", false, ["deriveBits"]);
  const hmacKey = await globalThis.crypto.subtle.importKey("raw", material(1), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const invalid = [
    undefined,
    null,
    {},
    { keys: [key()] }, // no scope
    { keys: [key()], scope: {} },
    { keys: [key()], scope: { namespaces: [] } },
    { keys: [key()], scope: { namespaces: "support-synthetic" } },
    { keys: [key()], scope: { namespaces: ["bad namespace"] } },
    { keys: [key()], scope: { namespaces: [NAMESPACE], tenants: [] } },
    { keys: [key()], scope: { namespaces: [NAMESPACE], tenants: [""] } },
    { keys: [key()], scope: { namespaces: [NAMESPACE], tenants: TENANT } },
    { keys: [], scope: SCOPE },
    { keys: "keys", scope: SCOPE },
    { scope: SCOPE },
    { keys: [key({ state: "decrypt-only" })], scope: SCOPE }, // zero active
    { keys: [key({ state: "retired" })], scope: SCOPE },
    { keys: [key(), key({ id: "k2" })], scope: SCOPE }, // two active
    { keys: [key(), key({ state: "decrypt-only" })], scope: SCOPE }, // duplicate id
    { keys: [key({ state: "enabled" })], scope: SCOPE },
    { keys: [key({ state: undefined })], scope: SCOPE },
    { keys: [key({ id: "" })], scope: SCOPE },
    { keys: [key({ id: "has space" })], scope: SCOPE },
    { keys: [key({ id: "has:colon" })], scope: SCOPE },
    { keys: [key({ id: "k".repeat(65) })], scope: SCOPE },
    { keys: [key({ id: 7 })], scope: SCOPE },
    { keys: [key({ material: new Uint8Array(31) })], scope: SCOPE },
    { keys: [key({ material: new Uint8Array(33) })], scope: SCOPE },
    { keys: [key({ material: new Uint8Array(16) })], scope: SCOPE },
    { keys: [key({ material: new Uint8Array(0) })], scope: SCOPE },
    { keys: [key({ material: "m".repeat(32) })], scope: SCOPE },
    { keys: [key({ material: Array.from({ length: 32 }, () => 1) })], scope: SCOPE },
    { keys: [key({ material: undefined })], scope: SCOPE },
    { keys: [key({ material: aesKey })], scope: SCOPE },
    { keys: [key({ material: hkdfBitsOnly })], scope: SCOPE },
    { keys: [key({ material: hmacKey })], scope: SCOPE },
    { keys: [key(), key({ id: "k2", state: "retired", material: new Uint8Array(8) })], scope: SCOPE },
    { keys: [null], scope: SCOPE },
  ];
  for (const options of invalid) await keyError(() => createLocalKeyProvider(options), "KEY_INVALID_ARGUMENT");
  createLocalKeyProvider({ keys: [key({ id: "A-z.0_9" }), key({ id: "k".repeat(64), state: "retired" })], scope: SCOPE });
});

test("a non-extractable HKDF CryptoKey is accepted and wraps like the bytes it was made from", async () => {
  const bytes = material(0x80);
  const cryptoKey = await globalThis.crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveKey"]);
  const fromKey = createLocalKeyProvider({ keys: [{ id: "2026-10", material: cryptoKey, state: "active" }], scope: SCOPE });
  const fromBytes = single();
  const made = await fromKey.generateDataKey(CONTEXT);
  assert.deepEqual(await fromBytes.unwrapDataKey({ keyRef: made.keyRef, wrappedKey: made.wrappedKey, context: CONTEXT }), made.plaintextKey);
});

test("the caller's material array can be overwritten once the provider exists", async () => {
  const bytes = material(0x80);
  const provider = createLocalKeyProvider({ keys: [{ id: "2026-10", material: bytes, state: "active" }], scope: SCOPE });
  bytes.fill(0);
  const made = await provider.generateDataKey(CONTEXT);
  assert.deepEqual(await provider.unwrapDataKey({ keyRef: made.keyRef, wrappedKey: made.wrappedKey, context: CONTEXT }), made.plaintextKey);
  // It is the original material that is in use, not the zeroed array.
  assert.deepEqual(await single().unwrapDataKey({ keyRef: made.keyRef, wrappedKey: made.wrappedKey, context: CONTEXT }), made.plaintextKey);
  const zeroKeyed = createLocalKeyProvider({ keys: [{ id: "2026-10", material: new Uint8Array(32), state: "active" }], scope: SCOPE });
  await keyError(() => zeroKeyed.unwrapDataKey({ keyRef: made.keyRef, wrappedKey: made.wrappedKey, context: CONTEXT }), "KEY_INTEGRITY");
});

test("a tampered or malformed wrapped key is KEY_INTEGRITY", async () => {
  const provider = single();
  const { keyRef, wrappedKey, plaintextKey } = await provider.generateDataKey(CONTEXT);
  const secrets = [hex(plaintextKey), base64(plaintextKey)];
  for (let index = 0; index < wrappedKey.length; index += 1) {
    const tampered = wrappedKey.slice();
    tampered[index] ^= 0x01;
    await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: tampered, context: CONTEXT }), "KEY_INTEGRITY", secrets);
  }
  for (const length of [1, 12, 13, 44, 60]) {
    await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: wrappedKey.slice(0, length), context: CONTEXT }), "KEY_INTEGRITY", secrets);
  }
  const longer = new Uint8Array(62);
  longer.set(wrappedKey);
  await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: longer, context: CONTEXT }), "KEY_INTEGRITY", secrets);
  await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: new Uint8Array(0), context: CONTEXT }), "KEY_INTEGRITY", secrets);
});

test("rewrap moves the key reference to the active key and keeps the data key", async () => {
  const old = single();
  const original = await old.generateDataKey(CONTEXT);
  const provider = rotated();
  const rewrapped = await provider.rewrapDataKey({ keyRef: "local:2026-07", wrappedKey: original.wrappedKey, context: CONTEXT });
  assert.equal(rewrapped.keyRef, "local:2026-10");
  assert.deepEqual(Object.keys(rewrapped).sort(), ["keyRef", "wrappedKey"], "rewrap returned more than a stored key");
  assert.notEqual(hex(rewrapped.wrappedKey), hex(original.wrappedKey));
  assert.deepEqual(await provider.unwrapDataKey({ ...rewrapped, context: CONTEXT }), original.plaintextKey);
  // Rewrapping a key already under the active version gives a new wrapping of the same key.
  const again = await provider.rewrapDataKey({ ...rewrapped, context: CONTEXT });
  assert.equal(again.keyRef, "local:2026-10");
  assert.notEqual(hex(again.wrappedKey), hex(rewrapped.wrappedKey));
  assert.deepEqual(await provider.unwrapDataKey({ ...again, context: CONTEXT }), original.plaintextKey);
  // The context is kept: the rewrapped key does not open under another capture.
  await keyError(() => provider.unwrapDataKey({ ...rewrapped, context: { ...CONTEXT, captureId: CAPTURE_B } }), "KEY_INTEGRITY");
});

test("an aborted signal is KEY_ABORTED, and malformed input is KEY_INVALID_ARGUMENT", async () => {
  const provider = single();
  const { keyRef, wrappedKey } = await provider.generateDataKey(CONTEXT);
  const signal = AbortSignal.abort();
  await keyError(() => provider.generateDataKey(CONTEXT, { signal }), "KEY_ABORTED");
  await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey, context: CONTEXT }, { signal }), "KEY_ABORTED");
  await keyError(() => provider.rewrapDataKey({ keyRef, wrappedKey, context: CONTEXT }, { signal }), "KEY_ABORTED");
  await provider.generateDataKey(CONTEXT, { signal: new AbortController().signal });
  await provider.generateDataKey(CONTEXT, {});

  await keyError(() => provider.generateDataKey(null), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.generateDataKey({ ...CONTEXT, captureId: "cap_x" }), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.generateDataKey({ ...CONTEXT, tenant: "bad-\ud800" }), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.generateDataKey({ ...CONTEXT, namespace: "bad namespace" }), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.generateDataKey(CONTEXT, "options"), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.unwrapDataKey(null), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.unwrapDataKey({ keyRef: 7, wrappedKey, context: CONTEXT }), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: hex(wrappedKey), context: CONTEXT }), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey: new Uint8Array(4097), context: CONTEXT }), "KEY_INVALID_ARGUMENT");
  await keyError(() => provider.unwrapDataKey({ keyRef, wrappedKey }), "KEY_INVALID_ARGUMENT");
});

test("the provider holds no cache: each unwrap returns a separate array", async () => {
  const provider = single();
  const { keyRef, wrappedKey, plaintextKey } = await provider.generateDataKey(CONTEXT);
  const first = await provider.unwrapDataKey({ keyRef, wrappedKey, context: CONTEXT });
  first.fill(0);
  plaintextKey.fill(0);
  const second = await provider.unwrapDataKey({ keyRef, wrappedKey, context: CONTEXT });
  assert.ok(second.some((byte) => byte !== 0), "overwriting one result changed a later one");
});

test("the provider reads no environment variable", async () => {
  const seen = [];
  const original = process.env;
  process.env = new Proxy(original, {
    get(target, name) {
      seen.push(String(name));
      return target[name];
    },
  });
  try {
    const provider = single();
    const made = await provider.generateDataKey(CONTEXT);
    await provider.unwrapDataKey({ keyRef: made.keyRef, wrappedKey: made.wrappedKey, context: CONTEXT });
  } finally {
    process.env = original;
  }
  assert.deepEqual(seen, []);
});
