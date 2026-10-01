// What a party that can write the store can try: changed bindings, swapped
// rows, flipped bits, truncation, and algorithm confusion.
import assert from "node:assert/strict";
import test from "node:test";

import { KeyProviderError, RecordCryptoError } from "@redact-secret/vault-contracts";

import { createRecordCrypto } from "../dist/index.js";
import { createLocalKeyProvider } from "../dist/local-key-provider.js";
import {
  base64,
  binding,
  CAPTURE_A,
  CAPTURE_B,
  CONTEXT,
  CREATED_AT,
  entryId,
  EXPIRES_AT,
  fakeProvider,
  fromUtf8,
  hex,
  NAMESPACE,
  OTHER_TENANT,
  payload,
  recordError,
  rejectsWith,
  SESSION,
  TENANT,
  VALUES,
} from "./helpers.mjs";

const leak = (envelope) => [hex(envelope), base64(envelope), hex(envelope.subarray(22)), base64(envelope.subarray(22))];

async function sealOne(crypto, bindingOverrides = {}, context = CONTEXT) {
  const record = { binding: binding(bindingOverrides), payload: payload() };
  const sealed = await crypto.sealCapture({ context, records: [record] });
  return { record, sealed, envelope: sealed.envelopes[0] };
}

function open(crypto, sealed, bindingAtOpen, envelope, context = CONTEXT) {
  return crypto.openCapture({
    context,
    keyRef: sealed.keyRef,
    wrappedKey: sealed.wrappedKey,
    records: [{ binding: bindingAtOpen, envelope }],
  });
}

const AAD_CHANGES = [
  ["namespace", {}, { namespace: "support-synthetic-2" }],
  ["tenant", {}, { tenant: OTHER_TENANT }],
  ["captureId", {}, { captureId: CAPTURE_B }],
  ["entryId", {}, { entryId: entryId(2) }],
  ["session, bound to another", { sessionId: SESSION }, { sessionId: "session-synthetic-0002" }],
  ["session, bound to none", { sessionId: SESSION }, { sessionId: null }],
  ["session, none to bound", { sessionId: null }, { sessionId: SESSION }],
  ["createdAt", {}, { createdAt: CREATED_AT + 1 }],
  ["expiresAt", {}, { expiresAt: EXPIRES_AT + 1 }],
  ["expiresAt, earlier", {}, { expiresAt: EXPIRES_AT - 1 }],
  ["maxUses", {}, { maxUses: 2 }],
  ["maxUses, to the ceiling", {}, { maxUses: 1000 }],
];

for (const [name, atSeal, atOpen] of AAD_CHANGES) {
  test(`a changed ${name} at open is RECORD_INTEGRITY`, async () => {
    // The fake provider returns the same data key for any context, so the
    // failure below comes from the associated data alone.
    const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
    const { record, sealed, envelope } = await sealOne(crypto, atSeal);
    const changed = { ...record.binding, ...atOpen };
    const context = { namespace: changed.namespace, tenant: changed.tenant, captureId: changed.captureId };
    await recordError(() => open(crypto, sealed, changed, envelope, context), "RECORD_INTEGRITY", leak(envelope));
    const [opened] = await open(crypto, sealed, record.binding, envelope);
    assert.equal(fromUtf8(opened.value), VALUES[0], "the unchanged binding still opens");
  });
}

test("the session identifier is not folded into a neighbouring field", async () => {
  // sessionBound 0 with an empty identifier and sessionBound 1 can never encode alike.
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const { record, sealed, envelope } = await sealOne(crypto, { sessionId: "a" });
  await recordError(() => open(crypto, sealed, { ...record.binding, sessionId: "b" }, envelope), "RECORD_INTEGRITY");
});

test("two envelopes swapped between entries of one capture fail, and nothing is returned", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const records = [1, 2].map((i) => ({ binding: binding({ entryId: entryId(i) }), payload: payload(VALUES[i]) }));
  const sealed = await crypto.sealCapture({ context: CONTEXT, records });
  const swapped = [
    { binding: records[0].binding, envelope: sealed.envelopes[1] },
    { binding: records[1].binding, envelope: sealed.envelopes[0] },
  ];
  await recordError(() => crypto.openCapture({ context: CONTEXT, ...sealed, records: swapped }), "RECORD_INTEGRITY", [
    ...leak(sealed.envelopes[0]),
    ...leak(sealed.envelopes[1]),
  ]);
});

test("one bad envelope after good ones fails the whole capture", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const records = [1, 2, 3].map((i) => ({ binding: binding({ entryId: entryId(i) }), payload: payload(VALUES[i - 1]) }));
  const sealed = await crypto.sealCapture({ context: CONTEXT, records });
  const last = sealed.envelopes[2].slice();
  last[last.length - 1] ^= 1;
  const stored = [0, 1, 2].map((i) => ({ binding: records[i].binding, envelope: i === 2 ? last : sealed.envelopes[i] }));
  const result = await crypto.openCapture({ context: CONTEXT, ...sealed, records: stored }).catch((error) => error);
  assert.ok(result instanceof RecordCryptoError, "a partial result was returned");
  assert.equal(result.code, "RECORD_INTEGRITY");
});

test("an envelope moved to another capture fails, with the same data key and with the real provider", async () => {
  const sameKey = createRecordCrypto({ keyProvider: fakeProvider() });
  const a = await sealOne(sameKey);
  const contextB = { ...CONTEXT, captureId: CAPTURE_B };
  const b = await sealOne(sameKey, { captureId: CAPTURE_B }, contextB);
  await recordError(() => open(sameKey, b.sealed, b.record.binding, a.envelope, contextB), "RECORD_INTEGRITY");
  await recordError(() => open(sameKey, a.sealed, a.record.binding, b.envelope), "RECORD_INTEGRITY");

  const local = createRecordCrypto({
    keyProvider: createLocalKeyProvider({ keys: [{ id: "k1", material: new Uint8Array(32).fill(7), state: "active" }], scope: { namespaces: [NAMESPACE] } }),
  });
  const la = await sealOne(local);
  const lb = await sealOne(local, { captureId: CAPTURE_B }, contextB);
  await recordError(() => open(local, lb.sealed, lb.record.binding, la.envelope, contextB), "RECORD_INTEGRITY");
});

test("a wrapped key swapped between captures fails", async () => {
  const local = createRecordCrypto({
    keyProvider: createLocalKeyProvider({ keys: [{ id: "k1", material: new Uint8Array(32).fill(7), state: "active" }], scope: { namespaces: [NAMESPACE] } }),
  });
  const contextB = { ...CONTEXT, captureId: CAPTURE_B };
  const a = await sealOne(local);
  const b = await sealOne(local, { captureId: CAPTURE_B }, contextB);
  // The local provider binds the wrapped key to its capture: the swap is caught at unwrap.
  await rejectsWith(() => open(local, b.sealed, a.record.binding, a.envelope), KeyProviderError, "KEY_INTEGRITY");

  // A provider that binds nothing returns another capture's data key: the tag catches it.
  const first = createRecordCrypto({ keyProvider: fakeProvider({ dek: new Uint8Array(32).fill(1) }) });
  const second = createRecordCrypto({ keyProvider: fakeProvider({ dek: new Uint8Array(32).fill(2) }) });
  const sealedByFirst = await sealOne(first);
  await recordError(() => open(second, sealedByFirst.sealed, sealedByFirst.record.binding, sealedByFirst.envelope), "RECORD_INTEGRITY");
});

test("a flipped bit anywhere in the envelope gives the fixed error of its region and never a value", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const { record, sealed, envelope } = await sealOne(crypto);
  const regionOf = (index) => {
    if (index < 4) return ["magic", ["RECORD_MALFORMED"]];
    if (index === 4) return ["formatVersion", ["RECORD_UNSUPPORTED"]];
    if (index === 5) return ["algorithm", ["RECORD_UNSUPPORTED"]];
    if (index < 18) return ["nonce", ["RECORD_INTEGRITY"]];
    if (index < 22) return ["length", ["RECORD_MALFORMED", "RECORD_LIMIT"]];
    if (index < envelope.length - 16) return ["ciphertext", ["RECORD_INTEGRITY"]];
    return ["tag", ["RECORD_INTEGRITY"]];
  };
  const seen = new Set();
  for (let index = 0; index < envelope.length; index += 1) {
    for (let bit = 0; bit < 8; bit += 1) {
      const tampered = envelope.slice();
      tampered[index] ^= 1 << bit;
      const [region, codes] = regionOf(index);
      seen.add(region);
      await recordError(() => open(crypto, sealed, record.binding, tampered), codes, leak(envelope));
    }
  }
  assert.deepEqual([...seen], ["magic", "formatVersion", "algorithm", "nonce", "length", "ciphertext", "tag"]);
});

test("every truncation and any trailing byte is rejected", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const { record, sealed, envelope } = await sealOne(crypto);
  for (let length = 0; length < envelope.length; length += 1) {
    await recordError(() => open(crypto, sealed, record.binding, envelope.slice(0, length)), "RECORD_MALFORMED");
  }
  for (const extra of [1, 16, 1000]) {
    const longer = new Uint8Array(envelope.length + extra);
    longer.set(envelope);
    await recordError(() => open(crypto, sealed, record.binding, longer), "RECORD_MALFORMED");
  }
});

test("an unknown formatVersion or algorithm is RECORD_UNSUPPORTED with no unwrap and no decryption", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const good = [1, 2].map((i) => ({ binding: binding({ entryId: entryId(i) }), payload: payload() }));
  const sealed = await crypto.sealCapture({ context: CONTEXT, records: good });

  const subtle = globalThis.crypto.subtle;
  let decrypts = 0;
  const original = subtle.decrypt;
  subtle.decrypt = function decrypt(...args) {
    decrypts += 1;
    return original.apply(this, args);
  };
  try {
    for (const [offset, value] of [[4, 0], [4, 2], [4, 255], [5, 0], [5, 2], [5, 255]]) {
      const altered = sealed.envelopes[1].slice();
      altered[offset] = value;
      // The first envelope is valid: it must not be decrypted either.
      const records = [
        { binding: good[0].binding, envelope: sealed.envelopes[0] },
        { binding: good[1].binding, envelope: altered },
      ];
      await recordError(() => crypto.openCapture({ context: CONTEXT, ...sealed, records }), "RECORD_UNSUPPORTED");
    }
    assert.equal(provider.calls.unwrap, 0, "a key was unwrapped for an unsupported record");
    assert.equal(decrypts, 0, "a decryption was attempted for an unsupported record");

    // The spy does see a normal open, so the zero above is meaningful.
    await crypto.openCapture({ context: CONTEXT, ...sealed, records: good.map((r, i) => ({ binding: r.binding, envelope: sealed.envelopes[i] })) });
    assert.equal(provider.calls.unwrap, 1);
    assert.equal(decrypts, 2);
  } finally {
    delete subtle.decrypt;
  }
});

test("a malformed envelope is rejected before the provider is called", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const { record, sealed, envelope } = await sealOne(crypto);
  await recordError(() => open(crypto, sealed, record.binding, envelope.slice(0, 30)), "RECORD_MALFORMED");
  await recordError(() => open(crypto, sealed, record.binding, "not bytes"), "RECORD_INVALID_ARGUMENT");
  assert.equal(provider.calls.unwrap, 0);
});

test("an oversized length field is rejected from the header alone, without allocating for it", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const { record, sealed, envelope } = await sealOne(crypto);
  const before = process.memoryUsage().arrayBuffers;
  for (let i = 0; i < 2000; i += 1) {
    const huge = envelope.slice();
    huge.set([0xff, 0xff, 0xff, 0xff], 18);
    await recordError(() => open(crypto, sealed, record.binding, huge), "RECORD_LIMIT");
  }
  const grown = process.memoryUsage().arrayBuffers - before;
  assert.ok(grown < 64 * 1024 * 1024, `2000 rejected envelopes claiming 4 GiB each grew array buffers by ${grown} bytes`);
});

test("an envelope larger than the ceiling is RECORD_LIMIT whatever it contains", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const { record, sealed } = await sealOne(crypto);
  const oversized = new Uint8Array(1024 * 1024 + 64 * 1024 + 1);
  await recordError(() => open(crypto, sealed, record.binding, oversized), "RECORD_LIMIT");
  assert.equal(provider.calls.unwrap, 0);
});

test("an authentic ciphertext is not accepted under another tenant's context", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const { record, sealed, envelope } = await sealOne(crypto);
  const moved = { ...record.binding, tenant: OTHER_TENANT };
  await recordError(() => open(crypto, sealed, moved, envelope, { ...CONTEXT, tenant: OTHER_TENANT }), "RECORD_INTEGRITY");
  // A binding that disagrees with the context is refused before any key is used.
  await recordError(() => open(crypto, sealed, moved, envelope, CONTEXT), "RECORD_INVALID_ARGUMENT");
  assert.equal(TENANT, record.binding.tenant);
  assert.equal(CAPTURE_A, record.binding.captureId);
});
