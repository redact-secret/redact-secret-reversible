// The provider under @redact-secret/vault-crypto's createRecordCrypto, over the fake KMS.
import assert from "node:assert/strict";
import test from "node:test";

import { KeyProviderError } from "@redact-secret/vault-contracts";
import { createRecordCrypto } from "@redact-secret/vault-crypto";

import { createAwsKmsKeyProvider } from "../dist/index.js";
import { e2eCases } from "./e2e-cases.mjs";
import { createFakeKms, EXPECTED, FakeSdkError } from "./fake-kms.mjs";
import { assertClean, assertCommands, CAPTURE_B, CONTEXT, NAMESPACE, OTHER_TENANT, SCOPE, TENANT } from "./helpers.mjs";

function setup() {
  const fake = createFakeKms();
  const first = fake.createKey();
  const second = fake.createKey();
  const make = (keys) => createAwsKmsKeyProvider({ client: fake.client, keys, expected: EXPECTED, scope: SCOPE });
  return {
    fake,
    provider: make([{ keyArn: first, state: "active" }]),
    rotated: make([
      { keyArn: second, state: "active" },
      { keyArn: first, state: "decrypt-only" },
    ]),
    context: CONTEXT,
    otherContext: { ...CONTEXT, tenant: OTHER_TENANT, captureId: CAPTURE_B },
  };
}

for (const item of e2eCases(async () => setup())) test(item.name, item.run);

test("through the crypto layer, KMS still sees only the digest context and explicit key ARNs", async () => {
  const { fake, provider, rotated, context } = setup();
  const record = {
    binding: { ...context, entryId: "1".padStart(64, "0"), sessionId: null, createdAt: 1_790_000_000_000, expiresAt: 1_790_000_600_000, maxUses: 1 },
    payload: { value: new TextEncoder().encode("SYNTHETIC-VALUE-0001"), type: "synthetic-finding-type", grants: [{ sink: "sink-a", paths: ["body"] }], policyRevision: null },
  };
  const sealed = await createRecordCrypto({ keyProvider: provider }).sealCapture({ context, records: [record] });
  const crypto = createRecordCrypto({ keyProvider: rotated });
  await crypto.openCapture({ context, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, records: [{ binding: record.binding, envelope: sealed.envelopes[0] }] });
  await crypto.rewrapCaptureKey({ keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, context });
  assert.deepEqual(fake.calls.map((call) => call.name), ["GenerateDataKeyCommand", "DecryptCommand", "ReEncryptCommand"]);
  assertCommands(fake.calls, [NAMESPACE, TENANT, "SYNTHETIC-VALUE", "sink-a", "synthetic-finding-type"]);
});

test("a KMS failure during seal or open surfaces as a clean KeyProviderError, and nothing is sealed", async () => {
  const { fake, provider, context } = setup();
  const crypto = createRecordCrypto({ keyProvider: provider });
  const record = {
    binding: { ...context, entryId: "1".padStart(64, "0"), sessionId: null, createdAt: 1_790_000_000_000, expiresAt: 1_790_000_600_000, maxUses: 1 },
    payload: { value: new TextEncoder().encode("SYNTHETIC-VALUE-0001"), type: "synthetic-finding-type", grants: [{ sink: "sink-a", paths: ["body"] }], policyRevision: null },
  };
  for (const [name, code] of [
    ["ThrottlingException", "KEY_THROTTLED"],
    ["DisabledException", "KEY_UNAVAILABLE"],
    ["AccessDeniedException", "KEY_UNAVAILABLE"],
  ]) {
    fake.failNext(new FakeSdkError(name, "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000000"));
    let error;
    let sealed;
    try {
      sealed = await crypto.sealCapture({ context, records: [record] });
    } catch (caught) {
      error = caught;
    }
    assert.equal(sealed, undefined);
    assert.ok(error instanceof KeyProviderError);
    assert.equal(error.code, code);
    assertClean(error, ["SYNTHETIC-VALUE"]);
  }
  const sealed = await crypto.sealCapture({ context, records: [record] });
  fake.failNext(new FakeSdkError("KMSInvalidStateException"));
  await assert.rejects(
    crypto.openCapture({ context, keyRef: sealed.keyRef, wrappedKey: sealed.wrappedKey, records: [{ binding: record.binding, envelope: sealed.envelopes[0] }] }),
    (error) => {
      assertClean(error, ["SYNTHETIC-VALUE"]);
      return error.code === "KEY_UNAVAILABLE";
    },
  );
});
