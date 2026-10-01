// End-to-end cases through `createRecordCrypto` of @redact-secret/vault-crypto,
// shared by the mock suite and the real-KMS suite. Synthetic data only.
import assert from "node:assert/strict";

import { KeyProviderError, RecordCryptoError } from "@redact-secret/vault-contracts";
import { createRecordCrypto } from "@redact-secret/vault-crypto";

const CREATED_AT = 1_790_000_000_000;
const EXPIRES_AT = CREATED_AT + 3_600_000;
const VALUES = ["SYNTHETIC-VALUE-0001", "SYNTHETIC-VALUE-0002 é中🔑"];
const utf8 = (text) => new TextEncoder().encode(text);
const fromUtf8 = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
const entryId = (index) => index.toString(16).padStart(64, "0");

function records(context) {
  return VALUES.map((value, index) => ({
    binding: { ...context, entryId: entryId(index + 1), sessionId: index === 0 ? "session-synthetic-0001" : null, createdAt: CREATED_AT, expiresAt: EXPIRES_AT, maxUses: 1 },
    payload: { value: utf8(value), type: "synthetic-finding-type", grants: [{ sink: "sink-a", paths: ["body"] }], policyRevision: null },
  }));
}

async function rejects(promise, Class, code) {
  let error;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof Class, `expected ${Class.name} ${code}`);
  assert.equal(error.code, code);
  assert.equal(error.message, new Class(code).message);
  assert.equal("cause" in error, false);
  for (const value of VALUES) assert.equal(`${error.stack}`.includes(value), false);
}

/**
 * `setup()` resolves to `{ provider, context, otherContext, rotated? }`:
 * a provider, a context in its scope, another context in its scope, and
 * optionally a provider in which the first one's active key is decrypt-only
 * and another key is active.
 */
export function e2eCases(setup) {
  const open = (crypto, sealed, items, context) =>
    crypto.openCapture({
      context,
      keyRef: sealed.keyRef,
      wrappedKey: sealed.wrappedKey,
      records: items.map((record, i) => ({ binding: record.binding, envelope: sealed.envelopes[i] })),
    });

  return [
    {
      name: "seal and open round-trip through createRecordCrypto",
      async run() {
        const { provider, context } = await setup();
        const crypto = createRecordCrypto({ keyProvider: provider });
        const items = records(context);
        const sealed = await crypto.sealCapture({ context, records: items });
        assert.ok(sealed.keyRef.startsWith("aws-kms:arn:"));
        assert.equal(sealed.envelopes.length, 2);
        for (const envelope of sealed.envelopes) {
          for (const value of VALUES) assert.equal(Buffer.from(envelope).includes(Buffer.from(value)), false);
        }
        const opened = await open(crypto, sealed, items, context);
        assert.deepEqual(opened.map((payload) => fromUtf8(payload.value)), VALUES);
        assert.deepEqual(opened[0].grants, [{ sink: "sink-a", paths: ["body"] }]);
      },
    },
    {
      name: "a capture opened under another capture, tenant, or key context fails closed",
      async run() {
        const { provider, context, otherContext } = await setup();
        const crypto = createRecordCrypto({ keyProvider: provider });
        const items = records(context);
        const sealed = await crypto.sealCapture({ context, records: items });
        // The stored key presented for another context: KMS refuses the unwrap.
        const moved = items.map((record) => ({ ...record, binding: { ...record.binding, ...otherContext } }));
        await rejects(open(crypto, sealed, moved, otherContext), KeyProviderError, "KEY_INTEGRITY");
        // The right key context with a changed row: the record's own tag fails.
        const changed = items.map((record) => ({ ...record, binding: { ...record.binding, maxUses: 2 } }));
        await rejects(open(crypto, sealed, changed, context), RecordCryptoError, "RECORD_INTEGRITY");
      },
    },
    {
      name: "a tampered wrapped key, a swapped wrapped key, a tampered envelope, and an unknown key reference fail closed",
      async run() {
        const { provider, context, otherContext } = await setup();
        const crypto = createRecordCrypto({ keyProvider: provider });
        const items = records(context);
        const sealed = await crypto.sealCapture({ context, records: items });

        const tampered = sealed.wrappedKey.slice();
        tampered[tampered.length - 1] ^= 0x01;
        await rejects(open(crypto, { ...sealed, wrappedKey: tampered }, items, context), KeyProviderError, "KEY_INTEGRITY");

        // A wrapped key rolled over from another capture: it does not unwrap for this context.
        const other = await crypto.sealCapture({ context: otherContext, records: records(otherContext) });
        await rejects(open(crypto, { ...sealed, wrappedKey: other.wrappedKey }, items, context), KeyProviderError, "KEY_INTEGRITY");

        const envelope = sealed.envelopes[0].slice();
        envelope[envelope.length - 1] ^= 0x01;
        await rejects(open(crypto, { ...sealed, envelopes: [envelope, sealed.envelopes[1]] }, items, context), RecordCryptoError, "RECORD_INTEGRITY");

        await rejects(open(crypto, { ...sealed, keyRef: `${sealed.keyRef}0` }, items, context), KeyProviderError, "KEY_UNAVAILABLE");
        await rejects(open(crypto, { ...sealed, keyRef: "local:2026-10" }, items, context), KeyProviderError, "KEY_UNAVAILABLE");
      },
    },
    {
      name: "rewrapCaptureKey moves a capture to the active key without touching its envelopes",
      async run() {
        const { provider, context, rotated } = await setup();
        if (rotated === undefined) return;
        const items = records(context);
        const sealed = await createRecordCrypto({ keyProvider: provider }).sealCapture({ context, records: items });
        const crypto = createRecordCrypto({ keyProvider: rotated });
        // Before the rewrap the old key reference still opens, because the old key is decrypt-only.
        assert.deepEqual((await open(crypto, sealed, items, context)).map((payload) => fromUtf8(payload.value)), VALUES);
        const moved = await crypto.rewrapCaptureKey({ keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, context });
        assert.notEqual(moved.keyRef, sealed.keyRef);
        const opened = await open(crypto, { ...moved, envelopes: sealed.envelopes }, items, context);
        assert.deepEqual(opened.map((payload) => fromUtf8(payload.value)), VALUES);
        // The new wrapped key under the old reference is refused.
        await rejects(open(crypto, { keyRef: sealed.keyRef, wrappedKey: moved.wrappedKey, envelopes: sealed.envelopes }, items, context), KeyProviderError, "KEY_UNAVAILABLE");
      },
    },
  ];
}
