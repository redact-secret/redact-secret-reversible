// Seal and open through the real local provider: counts, Unicode, sizes, nonces.
import assert from "node:assert/strict";
import test from "node:test";

import { LIMITS } from "@redact-secret/vault-contracts";

import { createRecordCrypto, decodeEnvelope, RECORD_CRYPTO_PROFILE } from "../dist/index.js";
import { createLocalKeyProvider } from "../dist/local-key-provider.js";
import {
  binding,
  CAPTURE_A,
  CONTEXT,
  entryId,
  fakeProvider,
  fromUtf8,
  hex,
  NAMESPACE,
  payload,
  recordError,
  SESSION,
  TENANT,
  utf8,
  VALUES,
} from "./helpers.mjs";

function localCrypto() {
  const keyProvider = createLocalKeyProvider({
    keys: [{ id: "2026-10", material: Uint8Array.from({ length: 32 }, (_unused, i) => 0x80 + i), state: "active" }],
    scope: { namespaces: [NAMESPACE] },
  });
  return createRecordCrypto({ keyProvider });
}

async function roundTrip(crypto, records) {
  const sealed = await crypto.sealCapture({ context: CONTEXT, records });
  assert.equal(sealed.envelopes.length, records.length);
  const opened = await crypto.openCapture({
    context: CONTEXT,
    keyRef: sealed.keyRef,
    wrappedKey: sealed.wrappedKey,
    records: records.map((record, i) => ({ binding: record.binding, envelope: sealed.envelopes[i] })),
  });
  assert.equal(opened.length, records.length);
  return { sealed, opened };
}

test("profile identifier", () => {
  assert.equal(localCrypto().profile, RECORD_CRYPTO_PROFILE);
  assert.equal(RECORD_CRYPTO_PROFILE, "aes-256-gcm-hkdf-v1");
});

test("one record round-trips, and the envelope holds no plaintext", async () => {
  const record = { binding: binding({ sessionId: SESSION }), payload: payload(VALUES[0], { policyRevision: "policy-rev-synthetic-7" }) };
  const { sealed, opened } = await roundTrip(localCrypto(), [record]);
  assert.equal(sealed.keyRef, "local:2026-10");
  assert.ok(opened[0].value instanceof Uint8Array);
  assert.equal(fromUtf8(opened[0].value), VALUES[0]);
  assert.equal(opened[0].type, "synthetic-finding-type");
  assert.deepEqual(opened[0].grants, [{ sink: "sink-a", paths: ["body"] }]);
  assert.equal(opened[0].policyRevision, "policy-rev-synthetic-7");
  const envelopeHex = hex(sealed.envelopes[0]);
  for (const visible of [VALUES[0], "synthetic-finding-type", "sink-a", "policy-rev-synthetic-7"]) {
    assert.ok(!envelopeHex.includes(hex(utf8(visible))), "an encrypted field is readable in the envelope");
  }
  const decoded = decodeEnvelope(sealed.envelopes[0]);
  assert.equal(decoded.formatVersion, 1);
  assert.equal(decoded.algorithm, 1);
  assert.equal(decoded.nonce.length, 12);
});

test("several records round-trip in order, each with its own grants", async () => {
  const records = VALUES.map((value, i) => ({
    binding: binding({ entryId: entryId(i + 1), maxUses: i + 1 }),
    payload: payload(value, { grants: [{ sink: `sink-${i}`, paths: [`path-${i}`, "body"] }] }),
  }));
  const { opened } = await roundTrip(localCrypto(), records);
  opened.forEach((item, i) => {
    assert.equal(fromUtf8(item.value), VALUES[i]);
    assert.deepEqual(item.grants, [{ sink: `sink-${i}`, paths: ["body", `path-${i}`] }]);
    assert.equal(item.policyRevision, null);
  });
});

test("the largest capture (1024 records) round-trips; one more is RECORD_LIMIT", async () => {
  const records = Array.from({ length: LIMITS.maxCreateEntries }, (_unused, i) => ({
    binding: binding({ entryId: entryId(i + 1) }),
    payload: payload(`SYNTHETIC-VALUE-${String(i).padStart(4, "0")}`),
  }));
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const { opened } = await roundTrip(crypto, records);
  assert.equal(fromUtf8(opened[1023].value), "SYNTHETIC-VALUE-1023");
  assert.deepEqual(provider.calls, { generate: 1, unwrap: 1, rewrap: 0 }, "one provider call per capture, not per entry");

  records.push({ binding: binding({ entryId: entryId(5000) }), payload: payload() });
  await recordError(() => crypto.sealCapture({ context: CONTEXT, records }), "RECORD_LIMIT");
  assert.equal(provider.calls.generate, 1, "an oversized capture never reaches the provider");
});

test("Unicode values, including supplementary characters, round-trip byte for byte", async () => {
  const values = ["SYNTHETIC-合成-값", "SYNTHETIC-\u{1F9EA}\u{10000}\u{10FFFF}", "﻿SYNTHETIC-leading-bom", "SYNTHETIC-é-not-normalized"];
  const records = values.map((value, i) => ({ binding: binding({ entryId: entryId(i + 1) }), payload: payload(value) }));
  const { opened } = await roundTrip(localCrypto(), records);
  opened.forEach((item, i) => {
    assert.deepEqual(item.value, utf8(values[i]));
    assert.equal(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(item.value), values[i]);
  });
});

test("non-ASCII type, sink, path, policy revision, tenant, and session round-trip", async () => {
  const tenant = "tenant-合成-\u{1F9EA}";
  const context = { namespace: NAMESPACE, tenant, captureId: CAPTURE_A };
  const record = {
    binding: binding({ tenant, sessionId: "session-\u{10000}" }),
    payload: payload(VALUES[0], {
      type: "유형-synthetic",
      grants: [{ sink: "싱크-\u{1F9EA}", paths: ["﻿bom-first", "경로"] }],
      policyRevision: "rev-\u{10000}",
    }),
  };
  const crypto = localCrypto();
  const sealed = await crypto.sealCapture({ context, records: [record] });
  const [opened] = await crypto.openCapture({ context, ...sealed, records: [{ binding: record.binding, envelope: sealed.envelopes[0] }] });
  assert.equal(opened.type, "유형-synthetic");
  assert.equal(opened.grants[0].sink, "싱크-\u{1F9EA}");
  assert.deepEqual(opened.grants[0].paths, ["경로", "﻿bom-first"]);
  assert.equal(opened.policyRevision, "rev-\u{10000}");
});

test("an empty value round-trips, and an empty policy revision stays distinct from none", async () => {
  const records = [
    { binding: binding({ entryId: entryId(1) }), payload: payload(new Uint8Array(0)) },
    { binding: binding({ entryId: entryId(2) }), payload: payload(new Uint8Array(0), { policyRevision: "" }) },
  ];
  const { opened } = await roundTrip(localCrypto(), records);
  assert.equal(opened[0].value.length, 0);
  assert.equal(opened[0].policyRevision, null);
  assert.equal(opened[1].policyRevision, "");
});

test("a value of exactly 1 MiB round-trips; one byte more is RECORD_LIMIT before the provider is called", async () => {
  const value = new Uint8Array(LIMITS.maxValueBytes).fill(0x53);
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const { sealed, opened } = await roundTrip(crypto, [{ binding: binding(), payload: payload(value) }]);
  assert.ok(sealed.envelopes[0].length <= LIMITS.maxEnvelopeBytes);
  assert.equal(opened[0].value.length, LIMITS.maxValueBytes);
  assert.ok(opened[0].value.every((byte) => byte === 0x53));

  const tooLarge = new Uint8Array(LIMITS.maxValueBytes + 1);
  await recordError(() => crypto.sealCapture({ context: CONTEXT, records: [{ binding: binding(), payload: payload(tooLarge) }] }), "RECORD_LIMIT");
  assert.equal(provider.calls.generate, 1);
});

test("a payload whose envelope would pass the envelope ceiling is RECORD_LIMIT", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const wide = "p".repeat(250);
  const grants = Array.from({ length: 2 }, (_unused, g) => ({
    sink: `sink-${g}`,
    paths: Array.from({ length: 256 }, (_unused2, p) => `${wide}${String(p).padStart(4, "0")}`),
  }));
  const value = new Uint8Array(LIMITS.maxValueBytes);
  await recordError(() => crypto.sealCapture({ context: CONTEXT, records: [{ binding: binding(), payload: payload(value, { grants }) }] }), "RECORD_LIMIT");
  assert.equal(provider.calls.generate, 0);
});

test("1000 seals of one input use 1000 distinct nonces and produce 1000 distinct ciphertexts", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const input = { context: CONTEXT, records: [{ binding: binding(), payload: payload() }] };
  const nonces = new Set();
  const ciphertexts = new Set();
  for (let i = 0; i < 1000; i += 1) {
    const sealed = await crypto.sealCapture(input);
    const decoded = decodeEnvelope(sealed.envelopes[0]);
    nonces.add(hex(decoded.nonce));
    ciphertexts.add(hex(decoded.ciphertext));
  }
  assert.equal(nonces.size, 1000);
  assert.equal(ciphertexts.size, 1000);
});

test("records of one capture do not share a nonce or an entry key", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const records = [1, 2].map((i) => ({ binding: binding({ entryId: entryId(i) }), payload: payload(VALUES[0]) }));
  const sealed = await crypto.sealCapture({ context: CONTEXT, records });
  const [a, b] = sealed.envelopes.map((envelope) => decodeEnvelope(envelope));
  assert.notEqual(hex(a.nonce), hex(b.nonce));
  assert.notEqual(hex(a.ciphertext), hex(b.ciphertext));
});

test("the data key handed over by the provider is overwritten after seal and after open", async () => {
  const provider = fakeProvider();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const record = { binding: binding(), payload: payload() };
  const sealed = await crypto.sealCapture({ context: CONTEXT, records: [record] });
  await crypto.openCapture({ context: CONTEXT, ...sealed, records: [{ binding: record.binding, envelope: sealed.envelopes[0] }] });
  assert.equal(provider.handedOut.length, 2);
  for (const key of provider.handedOut) assert.ok(key.every((byte) => byte === 0), "a data key was left in memory");
});

test("the caller's value array is not modified by seal, and the opened value is a separate copy", async () => {
  const crypto = createRecordCrypto({ keyProvider: fakeProvider() });
  const value = utf8(VALUES[0]);
  const record = { binding: binding(), payload: payload(value) };
  const sealed = await crypto.sealCapture({ context: CONTEXT, records: [record] });
  assert.equal(fromUtf8(value), VALUES[0]);
  const [opened] = await crypto.openCapture({ context: CONTEXT, ...sealed, records: [{ binding: record.binding, envelope: sealed.envelopes[0] }] });
  opened.value.fill(0);
  assert.equal(fromUtf8(value), VALUES[0]);
});

test("rewrapCaptureKey delegates to the provider and keeps the data key", async () => {
  const material = (start) => Uint8Array.from({ length: 32 }, (_unused, i) => start + i);
  const before = createRecordCrypto({
    keyProvider: createLocalKeyProvider({ keys: [{ id: "old", material: material(1), state: "active" }], scope: { namespaces: [NAMESPACE], tenants: [TENANT] } }),
  });
  const after = createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [
        { id: "new", material: material(101), state: "active" },
        { id: "old", material: material(1), state: "decrypt-only" },
      ],
      scope: { namespaces: [NAMESPACE], tenants: [TENANT] },
    }),
  });
  const record = { binding: binding(), payload: payload() };
  const sealed = await before.sealCapture({ context: CONTEXT, records: [record] });
  const rewrapped = await after.rewrapCaptureKey({ context: CONTEXT, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey });
  assert.equal(rewrapped.keyRef, "local:new");
  const [opened] = await after.openCapture({ context: CONTEXT, ...rewrapped, records: [{ binding: record.binding, envelope: sealed.envelopes[0] }] });
  assert.equal(fromUtf8(opened.value), VALUES[0]);
});
