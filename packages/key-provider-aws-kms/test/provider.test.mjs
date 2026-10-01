// Construction, key selection, context binding, error mapping, timeouts, and
// cancellation of the provider, against the fake KMS. Synthetic data only.
import assert from "node:assert/strict";
import test from "node:test";

import { AWS_KMS_KEY_PROVIDER_PROFILE, createAwsKmsKeyProvider, DEFAULT_CALL_TIMEOUT_MS, KEY_REF_PREFIX } from "../dist/index.js";
import { ACCOUNT, arnFor, createFakeKms, EXPECTED, FakeSdkError, REGION } from "./fake-kms.mjs";
import { assertCommands, CAPTURE_B, CONTEXT, expectedDigest, hex, keyError, keyErrorSync, NAMESPACE, OTHER_TENANT, SCOPE, TENANT } from "./helpers.mjs";

const IDENTIFIERS = [NAMESPACE, TENANT, OTHER_TENANT, "support", "acme"];

function setup(extra = {}) {
  const fake = createFakeKms();
  const active = fake.createKey();
  const old = fake.createKey();
  const options = {
    client: fake.client,
    keys: [
      { keyArn: active, state: "active" },
      { keyArn: old, state: "decrypt-only" },
    ],
    expected: EXPECTED,
    scope: SCOPE,
    ...extra,
  };
  return { fake, active, old, options, provider: createAwsKmsKeyProvider(options) };
}

/** A provider whose active key is `old`, to produce keys wrapped under the decrypt-only key of `setup`. */
function under(fake, arn, extra = {}) {
  return createAwsKmsKeyProvider({ client: fake.client, keys: [{ keyArn: arn, state: "active" }], expected: EXPECTED, scope: SCOPE, ...extra });
}

test("profile, key reference, and defaults", async () => {
  const { provider, active, fake } = setup();
  assert.equal(provider.profile, "aws-kms-envelope-v1");
  assert.equal(AWS_KMS_KEY_PROVIDER_PROFILE, "aws-kms-envelope-v1");
  assert.equal(DEFAULT_CALL_TIMEOUT_MS, 5000);
  assert.ok(Object.isFrozen(provider));
  const key = await provider.generateDataKey(CONTEXT);
  assert.equal(key.keyRef, `${KEY_REF_PREFIX}${active}`);
  assert.equal(key.keyRef, `aws-kms:${active}`);
  assert.equal(key.plaintextKey.byteLength, 32);
  assert.equal(fake.calls.length, 1);
  assert.deepEqual(provider.stats(), {
    closed: false,
    cacheEnabled: false,
    cacheEntries: 0,
    cacheTenants: 0,
    cacheHits: 0,
    cacheMisses: 0,
    cacheEvictions: 0,
    generateDataKeyCalls: 1,
    decryptCalls: 0,
    reEncryptCalls: 0,
  });
});

test("construction makes no KMS call", () => {
  const { fake } = setup();
  assert.equal(fake.calls.length, 0);
});

test("an alias, an alias ARN, a bare key id, and malformed ARNs are rejected at construction", () => {
  const { options } = setup();
  const id = "00000000-0000-4000-8000-000000000000";
  const rejected = [
    "alias/synthetic",
    `arn:aws:kms:${REGION}:${ACCOUNT}:alias/synthetic`,
    id,
    `key/${id}`,
    `arn:aws:kms:${REGION}:${ACCOUNT}:key/`,
    `arn:aws:kms:${REGION}:${ACCOUNT}:key/${id}/extra`,
    `arn:aws:kms:${REGION}:${ACCOUNT}:key/${id.toUpperCase().replace(/0/g, "A")}`,
    `arn:aws:kms:${REGION}:${ACCOUNT}:key/*`,
    `arn:aws:kms:${REGION}::key/${id}`,
    `arn:aws:kms::${ACCOUNT}:key/${id}`,
    `arn:aws:s3:${REGION}:${ACCOUNT}:key/${id}`,
    ` ${arnFor(id)}`,
    `${arnFor(id)}\n`,
    "",
    42,
    null,
  ];
  for (const keyArn of rejected) {
    keyErrorSync(() => createAwsKmsKeyProvider({ ...options, keys: [{ keyArn, state: "active" }] }), "KEY_INVALID_ARGUMENT");
  }
  // The same shape with a well-formed ARN is accepted.
  createAwsKmsKeyProvider({ ...options, keys: [{ keyArn: arnFor(id), state: "active" }] });
});

test("an ARN in another region, account, or partition than expected is rejected at construction", () => {
  const { options, active } = setup();
  const id = "00000000-0000-4000-8000-000000000000";
  for (const keyArn of [
    arnFor(id, { region: "us-west-2" }),
    arnFor(id, { account: "444455556666" }),
    `arn:aws-us-gov:kms:${REGION}:${ACCOUNT}:key/${id}`,
  ]) {
    keyErrorSync(() => createAwsKmsKeyProvider({ ...options, keys: [{ keyArn, state: "active" }] }), "KEY_INVALID_ARGUMENT");
    // One stray key among good ones is enough to refuse the whole configuration.
    keyErrorSync(
      () => createAwsKmsKeyProvider({ ...options, keys: [{ keyArn: active, state: "active" }, { keyArn, state: "decrypt-only" }] }),
      "KEY_INVALID_ARGUMENT",
    );
  }
  for (const expected of [undefined, {}, { region: REGION }, { accountId: ACCOUNT }, { region: "US-EAST-1", accountId: ACCOUNT }, { region: REGION, accountId: "1234" }, { region: REGION, accountId: ACCOUNT, partition: "azure" }]) {
    keyErrorSync(() => createAwsKmsKeyProvider({ ...options, expected }), "KEY_INVALID_ARGUMENT");
  }
  // A stated partition is honored.
  createAwsKmsKeyProvider({
    ...options,
    expected: { region: "us-gov-west-1", accountId: ACCOUNT, partition: "aws-us-gov" },
    keys: [{ keyArn: `arn:aws-us-gov:kms:us-gov-west-1:${ACCOUNT}:key/${id}`, state: "active" }],
  });
});

test("the configuration needs a client, exactly one active key, unique keys, a scope, and sane options", () => {
  const { options, active, old } = setup();
  const bad = [
    { client: undefined },
    { client: {} },
    { client: { send: "not a function" } },
    { keys: [] },
    { keys: undefined },
    { keys: [{ keyArn: active, state: "decrypt-only" }] },
    { keys: [{ keyArn: active, state: "active" }, { keyArn: old, state: "active" }] },
    { keys: [{ keyArn: active, state: "active" }, { keyArn: active, state: "decrypt-only" }] },
    { keys: [{ keyArn: active, state: "enabled" }] },
    { scope: undefined },
    { scope: { namespaces: [] } },
    { scope: { namespaces: ["not a namespace!"] } },
    { scope: { namespaces: [NAMESPACE], tenants: [] } },
    { callTimeoutMs: 0 },
    { callTimeoutMs: 1.5 },
    { callTimeoutMs: Number.POSITIVE_INFINITY },
    { callTimeoutMs: "5000" },
    { cache: {} },
    { cache: { maxEntries: 0, maxAgeMs: 1000, perTenantMaxEntries: 1 } },
    { cache: { maxEntries: 10, maxAgeMs: 300_001, perTenantMaxEntries: 1 } },
    { cache: { maxEntries: 10, maxAgeMs: 0, perTenantMaxEntries: 1 } },
    { cache: { maxEntries: 10, maxAgeMs: 1000, perTenantMaxEntries: 11 } },
    { cache: { maxEntries: 10_001, maxAgeMs: 1000, perTenantMaxEntries: 1 } },
    { cache: { maxEntries: 10, maxAgeMs: 1000, perTenantMaxEntries: 1, now: 5 } },
  ];
  for (const override of bad) keyErrorSync(() => createAwsKmsKeyProvider({ ...options, ...override }), "KEY_INVALID_ARGUMENT");
  keyErrorSync(() => createAwsKmsKeyProvider(undefined), "KEY_INVALID_ARGUMENT");
});

test("the encryption context is the digest and the version, and nothing of the KeyContext, on every command", async () => {
  const { provider, fake, active, old } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...key, context: CONTEXT })).fill(0);
  await provider.rewrapDataKey({ ...key, context: CONTEXT });
  const oldKey = await under(fake, old).generateDataKey(CONTEXT);
  await provider.rewrapDataKey({ keyRef: oldKey.keyRef, wrappedKey: oldKey.wrappedKey, context: CONTEXT });
  await keyError(provider.unwrapDataKey({ ...key, context: { ...CONTEXT, captureId: CAPTURE_B } }), "KEY_INTEGRITY");

  assert.equal(fake.calls.length, 6);
  assertCommands(fake.calls, IDENTIFIERS);
  const digest = expectedDigest(CONTEXT);
  const want = { "rsv:ctx": digest, "rsv:v": "1" };
  assert.deepEqual(fake.calls[0].input.EncryptionContext, want);
  assert.deepEqual(fake.calls[1].input.EncryptionContext, want);
  assert.deepEqual(fake.calls[2].input.SourceEncryptionContext, want);
  assert.deepEqual(fake.calls[2].input.DestinationEncryptionContext, want);
  assert.deepEqual(fake.calls[5].input.EncryptionContext, { "rsv:ctx": expectedDigest({ ...CONTEXT, captureId: CAPTURE_B }), "rsv:v": "1" });
  // Key selection: generate on the active key, decrypt and re-encrypt from exactly the referenced key.
  assert.equal(fake.calls[0].input.KeyId, active);
  assert.equal(fake.calls[1].input.KeyId, active);
  assert.equal(fake.calls[4].input.SourceKeyId, old);
  assert.equal(fake.calls[4].input.DestinationKeyId, active);
});

test("the digest separates fields: moving a boundary between tenant and namespace changes it", () => {
  const one = expectedDigest({ namespace: "ab", tenant: "c", captureId: CONTEXT.captureId });
  const two = expectedDigest({ namespace: "a", tenant: "bc", captureId: CONTEXT.captureId });
  assert.notEqual(one, two);
});

test("contextLabels are validated, sent on every command, and part of the binding", async () => {
  const { options, fake } = setup();
  const labels = { environment: "staging-synthetic", app: "rsv" };
  const provider = createAwsKmsKeyProvider({ ...options, contextLabels: labels });
  const key = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...key, context: CONTEXT })).fill(0);
  await provider.rewrapDataKey({ ...key, context: CONTEXT });
  assertCommands(fake.calls, IDENTIFIERS, labels);
  assert.deepEqual(fake.calls[0].input.EncryptionContext, { "rsv:ctx": expectedDigest(CONTEXT), "rsv:v": "1", ...labels });

  // A provider without the labels, or with other labels, cannot unwrap it.
  await keyError(createAwsKmsKeyProvider(options).unwrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY");
  await keyError(createAwsKmsKeyProvider({ ...options, contextLabels: { environment: "production-synthetic", app: "rsv" } }).unwrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY");

  const bad = [
    { "rsv:ctx": "override" },
    { "rsv:v": "2" },
    { "aws:something": "x" },
    { "": "x" },
    { "1env": "x" },
    { env: "" },
    { env: "has space" },
    { env: "tenant/acme" },
    { env: 7 },
    { env: "x".repeat(129) },
    { ["k".repeat(64)]: "x" },
    Object.fromEntries(Array.from({ length: 9 }, (_unused, i) => [`label${i}`, "x"])),
    ["environment"],
    "environment=staging",
  ];
  for (const contextLabels of bad) keyErrorSync(() => createAwsKmsKeyProvider({ ...options, contextLabels }), "KEY_INVALID_ARGUMENT");
});

test("unwrap and rewrap accept only a key reference that names a configured, non-retired key, and make no call otherwise", async () => {
  const { provider, fake, active, old, options } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const unconfigured = fake.createKey();
  const foreign = await under(fake, unconfigured).generateDataKey(CONTEXT);
  const before = fake.calls.length;
  const refused = [
    foreign.keyRef,
    active,
    `local:${active}`,
    `aws-kms:${active.split("/")[1]}`,
    "aws-kms:alias/synthetic",
    `aws-kms:${active} `,
    `AWS-KMS:${active}`,
    `aws-kms:${active.replace(REGION, "us-west-2")}`,
    `aws-kms:${active.replace(ACCOUNT, "444455556666")}`,
  ];
  for (const keyRef of refused) {
    await keyError(provider.unwrapDataKey({ keyRef, wrappedKey: key.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
    await keyError(provider.rewrapDataKey({ keyRef, wrappedKey: key.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
    await keyError(provider.unwrapDataKey({ keyRef, wrappedKey: foreign.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  }
  assert.equal(fake.calls.length, before, "a refused key reference must not reach KMS");

  // Retired in the configuration: refused without a call, although KMS would still decrypt.
  const oldKey = await under(fake, old).generateDataKey(CONTEXT);
  const retired = createAwsKmsKeyProvider({ ...options, keys: [{ keyArn: active, state: "active" }, { keyArn: old, state: "retired" }] });
  const count = fake.calls.length;
  await keyError(retired.unwrapDataKey({ keyRef: oldKey.keyRef, wrappedKey: oldKey.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  await keyError(retired.rewrapDataKey({ keyRef: oldKey.keyRef, wrappedKey: oldKey.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  assert.equal(fake.calls.length, count);
});

test("Decrypt always carries the referenced key: a ciphertext of key A presented with key reference B is refused", async () => {
  const { provider, fake, active, old } = setup();
  const underActive = await provider.generateDataKey(CONTEXT);
  const underOld = await under(fake, old).generateDataKey(CONTEXT);
  const start = fake.calls.length;

  // A's ciphertext with B's reference, both configured and usable: KMS would decrypt it if it chose the key from the blob.
  await keyError(provider.unwrapDataKey({ keyRef: `aws-kms:${old}`, wrappedKey: underActive.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  await keyError(provider.unwrapDataKey({ keyRef: `aws-kms:${active}`, wrappedKey: underOld.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
  await keyError(provider.rewrapDataKey({ keyRef: `aws-kms:${active}`, wrappedKey: underOld.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");

  const sent = fake.calls.slice(start);
  assert.deepEqual(sent.map((call) => call.name), ["DecryptCommand", "DecryptCommand", "ReEncryptCommand"]);
  assert.equal(sent[0].input.KeyId, old);
  assert.equal(sent[1].input.KeyId, active);
  assert.equal(sent[2].input.SourceKeyId, active);
  for (const call of fake.calls) if (call.name === "DecryptCommand") assert.equal(typeof call.input.KeyId, "string");
});

test("a response naming another key than the one requested is KEY_INTEGRITY", async () => {
  const { provider, fake, active, old } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const dek = hex(key.plaintextKey);

  // Decrypt answered by another key, with a perfectly good plaintext.
  fake.setTransform((output) => ({ ...output, KeyId: old }));
  await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY", [dek]);
  assert.ok(fake.plaintexts.at(-1).every((byte) => byte === 0), "a refused plaintext must be overwritten");
  await keyError(provider.generateDataKey(CONTEXT), "KEY_INTEGRITY");
  assert.ok(fake.plaintexts.at(-1).every((byte) => byte === 0));
  await keyError(provider.rewrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY");

  // The key id without the ARN, an alias ARN, and a missing KeyId are not the requested ARN either.
  for (const KeyId of [active.split("/")[1], `arn:aws:kms:${REGION}:${ACCOUNT}:alias/synthetic`, undefined, 7]) {
    fake.setTransform((output) => ({ ...output, KeyId }));
    await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY", [dek]);
  }
  // ReEncrypt must confirm both the source and the destination key.
  fake.setTransform((output) => ({ ...output, SourceKeyId: old }));
  await keyError(provider.rewrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY");
  fake.setTransform(null);
  (await provider.unwrapDataKey({ ...key, context: CONTEXT })).fill(0);
});

test("a malformed response is KEY_INTEGRITY and its plaintext is overwritten", async () => {
  const { provider, fake } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const shapes = [
    (output) => ({ ...output, Plaintext: output.Plaintext.subarray(0, 31) }),
    (output) => ({ ...output, Plaintext: new Uint8Array(33) }),
    (output) => ({ ...output, Plaintext: new Uint8Array(0) }),
    (output) => ({ ...output, Plaintext: undefined }),
    (output) => ({ ...output, Plaintext: "c3ludGhldGlj" }),
    (output) => ({ ...output, Plaintext: Array.from(output.Plaintext) }),
  ];
  for (const shape of shapes) {
    fake.setTransform(shape);
    await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY");
    await keyError(provider.generateDataKey(CONTEXT), "KEY_INTEGRITY");
  }
  for (const CiphertextBlob of [undefined, new Uint8Array(0), new Uint8Array(4097), "blob"]) {
    fake.setTransform((output) => ({ ...output, CiphertextBlob }));
    await keyError(provider.generateDataKey(CONTEXT), "KEY_INTEGRITY");
    assert.ok(fake.plaintexts.at(-1).every((byte) => byte === 0));
    await keyError(provider.rewrapDataKey({ ...key, context: CONTEXT }), "KEY_INTEGRITY");
  }
  for (const output of [undefined, null, "ok", 7]) {
    fake.setTransform(() => output);
    await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }), "KEY_UNAVAILABLE");
  }
});

test("the returned data key is a copy, and the SDK's plaintext buffer is overwritten", async () => {
  const { provider, fake } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  assert.notEqual(key.plaintextKey, fake.plaintexts[0]);
  assert.ok(key.plaintextKey.some((byte) => byte !== 0));
  assert.ok(fake.plaintexts[0].every((byte) => byte === 0), "the GenerateDataKey response buffer was not overwritten");
  const dek = await provider.unwrapDataKey({ ...key, context: CONTEXT });
  assert.deepEqual(dek, key.plaintextKey);
  assert.ok(fake.plaintexts[1].every((byte) => byte === 0), "the Decrypt response buffer was not overwritten");
  // The caller's wrapped key is not retained or changed.
  const wrapped = key.wrappedKey.slice();
  (await provider.unwrapDataKey({ ...key, context: CONTEXT })).fill(0);
  assert.deepEqual(key.wrappedKey, wrapped);
});

test("rewrap uses ReEncrypt: no Decrypt is sent and no plaintext reaches the provider or its caller", async () => {
  const { provider, fake, active, old } = setup();
  const source = await under(fake, old).generateDataKey(CONTEXT);
  const dek = source.plaintextKey.slice();
  const start = fake.calls.length;
  const handedOut = fake.plaintexts.length;

  const moved = await provider.rewrapDataKey({ keyRef: source.keyRef, wrappedKey: source.wrappedKey, context: CONTEXT });

  assert.deepEqual(fake.calls.slice(start).map((call) => call.name), ["ReEncryptCommand"]);
  assert.equal(fake.plaintexts.length, handedOut, "the client returned a plaintext during a rewrap");
  assert.deepEqual(Object.keys(moved).sort(), ["keyRef", "wrappedKey"]);
  assert.equal(moved.keyRef, `aws-kms:${active}`);
  assert.equal("plaintextKey" in moved, false);
  for (const value of Object.values(moved)) {
    if (value instanceof Uint8Array) assert.equal(hex(value).includes(hex(dek)), false);
  }
  assert.equal(provider.stats().decryptCalls, 0);
  assert.equal(provider.stats().reEncryptCalls, 1);
  assert.deepEqual(await provider.unwrapDataKey({ ...moved, context: CONTEXT }), dek);
  // A rewrap under another context does not authenticate.
  await keyError(provider.rewrapDataKey({ keyRef: source.keyRef, wrappedKey: source.wrappedKey, context: { ...CONTEXT, tenant: OTHER_TENANT } }), "KEY_INTEGRITY");
});

const MAPPING = [
  ["ThrottlingException", "KEY_THROTTLED"],
  ["LimitExceededException", "KEY_THROTTLED"],
  ["TooManyRequestsException", "KEY_THROTTLED"],
  ["RequestLimitExceeded", "KEY_THROTTLED"],
  ["DisabledException", "KEY_UNAVAILABLE"],
  ["KMSInvalidStateException", "KEY_UNAVAILABLE"],
  ["NotFoundException", "KEY_UNAVAILABLE"],
  ["AccessDeniedException", "KEY_UNAVAILABLE"],
  ["KeyUnavailableException", "KEY_UNAVAILABLE"],
  ["IncorrectKeyException", "KEY_UNAVAILABLE"],
  ["InvalidKeyUsageException", "KEY_UNAVAILABLE"],
  ["InvalidGrantTokenException", "KEY_UNAVAILABLE"],
  ["KMSInternalException", "KEY_UNAVAILABLE"],
  ["DependencyTimeoutException", "KEY_UNAVAILABLE"],
  ["UnrecognizedClientException", "KEY_UNAVAILABLE"],
  ["ExpiredTokenException", "KEY_UNAVAILABLE"],
  ["CredentialsProviderError", "KEY_UNAVAILABLE"],
  ["SomethingNobodyHasSeenException", "KEY_UNAVAILABLE"],
  ["AbortError", "KEY_UNAVAILABLE"],
  ["InvalidCiphertextException", "KEY_INTEGRITY"],
  ["TimeoutError", "KEY_TIMEOUT"],
  ["RequestTimeout", "KEY_TIMEOUT"],
];

for (const [name, code] of MAPPING) {
  test(`${name} from the client is ${code} on every operation, with nothing of the SDK error`, async () => {
    const { provider, fake, active } = setup();
    const key = await provider.generateDataKey(CONTEXT);
    const operations = [
      () => provider.generateDataKey(CONTEXT),
      () => provider.unwrapDataKey({ ...key, context: CONTEXT }),
      () => provider.rewrapDataKey({ ...key, context: CONTEXT }),
    ];
    for (const operation of operations) {
      const before = fake.calls.length;
      fake.failNext(new FakeSdkError(name, active));
      const error = await keyError(operation(), code, [active.split("/")[1]]);
      assert.equal(Object.keys(error).includes("$metadata"), false);
      assert.equal(fake.calls.length, before + 1, "the provider must not retry");
    }
  });
}

test("a KMSInvalidStateException the SDK marks as throttling is KEY_THROTTLED", async () => {
  const { provider, fake, active } = setup();
  fake.failNext(new FakeSdkError("KMSInvalidStateException", active, { $retryable: { throttling: true } }));
  await keyError(provider.generateDataKey(CONTEXT), "KEY_THROTTLED");
  fake.failNext(new FakeSdkError("KMSInvalidStateException", active, { $retryable: { throttling: false } }));
  await keyError(provider.generateDataKey(CONTEXT), "KEY_UNAVAILABLE");
});

test("anything else a client throws is KEY_UNAVAILABLE, including a forged KeyProviderError and hostile objects", async () => {
  const { KeyProviderError } = await import("@redact-secret/vault-contracts");
  const { provider, fake } = setup();
  const hostile = {
    get name() {
      throw new Error("SYNTHETIC-SDK-ERROR-TEXT getter");
    },
  };
  const forged = new KeyProviderError("KEY_INTEGRITY");
  forged.cause = new Error("SYNTHETIC-SDK-ERROR-TEXT forged");
  for (const thrown of [undefined, null, "SYNTHETIC-SDK-ERROR-TEXT string", 7, {}, { name: 42 }, hostile, forged, new TypeError("SYNTHETIC-SDK-ERROR-TEXT fetch failed")]) {
    fake.failNext(thrown);
    await keyError(provider.generateDataKey(CONTEXT), "KEY_UNAVAILABLE");
  }
  // A client whose send throws synchronously is handled the same way.
  const sync = createAwsKmsKeyProvider({
    client: {
      send() {
        throw new FakeSdkError("ThrottlingException");
      },
    },
    keys: [{ keyArn: arnFor("00000000-0000-4000-8000-000000000000"), state: "active" }],
    expected: EXPECTED,
    scope: SCOPE,
  });
  await keyError(sync.generateDataKey(CONTEXT), "KEY_THROTTLED");
});

test("key states in KMS: a disabled or pending-deletion key is KEY_UNAVAILABLE, and no other key is tried", async () => {
  const { provider, fake, active, old } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const oldKey = await under(fake, old).generateDataKey(CONTEXT);
  for (const state of ["Disabled", "PendingDeletion", "PendingImport"]) {
    fake.setState(active, state);
    const before = fake.calls.length;
    await keyError(provider.generateDataKey(CONTEXT), "KEY_UNAVAILABLE");
    await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }), "KEY_UNAVAILABLE");
    // The old key is usable, but the destination of a rewrap is the active key.
    await keyError(provider.rewrapDataKey({ keyRef: oldKey.keyRef, wrappedKey: oldKey.wrappedKey, context: CONTEXT }), "KEY_UNAVAILABLE");
    const sent = fake.calls.slice(before);
    assert.equal(sent.length, 3, "one call per operation: no retry and no fallback");
    assert.equal(sent[0].input.KeyId, active);
    assert.equal(sent[1].input.KeyId, active);
    assert.equal(sent[2].input.DestinationKeyId, active);
    // A key under the still-enabled old key keeps unwrapping.
    (await provider.unwrapDataKey({ keyRef: oldKey.keyRef, wrappedKey: oldKey.wrappedKey, context: CONTEXT })).fill(0);
  }
  fake.setState(active, "Enabled");
  (await provider.unwrapDataKey({ ...key, context: CONTEXT })).fill(0);
});

test("a call that outlives callTimeoutMs is KEY_TIMEOUT, and the client's abort signal fires", async () => {
  const { options, fake } = setup();
  const provider = createAwsKmsKeyProvider({ ...options, callTimeoutMs: 30 });
  const key = await provider.generateDataKey(CONTEXT);
  fake.setHang(true);
  for (const operation of [
    () => provider.generateDataKey(CONTEXT),
    () => provider.unwrapDataKey({ ...key, context: CONTEXT }),
    () => provider.rewrapDataKey({ ...key, context: CONTEXT }),
  ]) {
    const started = Date.now();
    await keyError(operation(), "KEY_TIMEOUT");
    assert.ok(Date.now() - started < 2000);
    const { options: sendOptions } = fake.calls.at(-1);
    assert.ok(sendOptions.abortSignal instanceof AbortSignal, "send was not given an abort signal");
    assert.equal(sendOptions.abortSignal.aborted, true, "the client call was not aborted on timeout");
  }
});

test("a response that arrives after the timeout is discarded and its plaintext overwritten", async () => {
  const { options, fake } = setup();
  const provider = createAwsKmsKeyProvider({ ...options, callTimeoutMs: 20 });
  fake.setDelay(80);
  await keyError(provider.generateDataKey(CONTEXT), "KEY_TIMEOUT");
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.equal(fake.plaintexts.length, 1);
  assert.ok(fake.plaintexts[0].every((byte) => byte === 0), "a late plaintext was left in memory");
});

test("the caller's signal: aborted before the call makes no KMS call; aborted during the call is KEY_ABORTED", async () => {
  const { provider, fake } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const before = fake.calls.length;
  const aborted = AbortSignal.abort();
  await keyError(provider.generateDataKey(CONTEXT, { signal: aborted }), "KEY_ABORTED");
  await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }, { signal: aborted }), "KEY_ABORTED");
  await keyError(provider.rewrapDataKey({ ...key, context: CONTEXT }, { signal: aborted }), "KEY_ABORTED");
  assert.equal(fake.calls.length, before);

  fake.setHang(true);
  for (const operation of [
    (signal) => provider.generateDataKey(CONTEXT, { signal }),
    (signal) => provider.unwrapDataKey({ ...key, context: CONTEXT }, { signal }),
    (signal) => provider.rewrapDataKey({ ...key, context: CONTEXT }, { signal }),
  ]) {
    const controller = new AbortController();
    const pending = operation(controller.signal);
    setTimeout(() => controller.abort(), 15);
    await keyError(pending, "KEY_ABORTED");
    assert.equal(fake.calls.at(-1).options.abortSignal.aborted, true, "the client call was not aborted");
    assert.notEqual(fake.calls.at(-1).options.abortSignal, controller.signal, "the caller's signal is not handed to the client");
  }
  fake.setHang(false);

  // Aborted while the response was in flight: the result is discarded.
  fake.setDelay(40);
  const controller = new AbortController();
  const pending = provider.unwrapDataKey({ ...key, context: CONTEXT }, { signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await keyError(pending, "KEY_ABORTED");

  for (const options of [null, 7, { signal: {} }, { signal: { aborted: false } }, { signal: "abort" }]) {
    await keyError(provider.generateDataKey(CONTEXT, options), "KEY_INVALID_ARGUMENT");
  }
});

test("inputs outside the contract are KEY_INVALID_ARGUMENT and reach no KMS call", async () => {
  const { provider, fake } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const before = fake.calls.length;
  for (const context of [undefined, null, "context", {}, { ...CONTEXT, namespace: "" }, { ...CONTEXT, tenant: "" }, { ...CONTEXT, tenant: "\ud800" }, { ...CONTEXT, captureId: "capture" }]) {
    await keyError(provider.generateDataKey(context), "KEY_INVALID_ARGUMENT");
    await keyError(provider.unwrapDataKey({ ...key, context }), "KEY_INVALID_ARGUMENT");
    await keyError(provider.rewrapDataKey({ ...key, context }), "KEY_INVALID_ARGUMENT");
  }
  for (const stored of [undefined, null, {}, { keyRef: 7, wrappedKey: key.wrappedKey }, { keyRef: key.keyRef, wrappedKey: "bytes" }, { keyRef: key.keyRef, wrappedKey: Array.from(key.wrappedKey) }, { keyRef: "", wrappedKey: key.wrappedKey }, { keyRef: key.keyRef, wrappedKey: new Uint8Array(0) }, { keyRef: key.keyRef, wrappedKey: new Uint8Array(4097) }]) {
    await keyError(provider.unwrapDataKey({ ...stored, context: CONTEXT }), "KEY_INVALID_ARGUMENT");
    await keyError(provider.rewrapDataKey({ ...stored, context: CONTEXT }), "KEY_INVALID_ARGUMENT");
  }
  assert.equal(fake.calls.length, before);
});

test("scope: a namespace or tenant outside it is KEY_UNAVAILABLE without a KMS call; no tenant list serves any tenant", async () => {
  const { provider, fake, options } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  const before = fake.calls.length;
  for (const context of [{ ...CONTEXT, namespace: "other-synthetic" }, { ...CONTEXT, tenant: "tenant-initech-synthetic" }]) {
    await keyError(provider.generateDataKey(context), "KEY_UNAVAILABLE");
    await keyError(provider.unwrapDataKey({ ...key, context }), "KEY_UNAVAILABLE");
    await keyError(provider.rewrapDataKey({ ...key, context }), "KEY_UNAVAILABLE");
  }
  assert.equal(fake.calls.length, before);
  const anyTenant = createAwsKmsKeyProvider({ ...options, scope: { namespaces: [NAMESPACE] } });
  const other = { ...CONTEXT, tenant: "tenant-initech-synthetic" };
  const otherKey = await anyTenant.generateDataKey(other);
  (await anyTenant.unwrapDataKey({ ...otherKey, context: other })).fill(0);
  // Without a tenant scope, the binding is what separates tenants.
  await keyError(anyTenant.unwrapDataKey({ ...otherKey, context: CONTEXT }), "KEY_INTEGRITY");
});

test("close: every later call is KEY_UNAVAILABLE and reaches no KMS call; close is idempotent", async () => {
  const { provider, fake } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  provider.close();
  provider.close();
  const before = fake.calls.length;
  await keyError(provider.generateDataKey(CONTEXT), "KEY_UNAVAILABLE");
  await keyError(provider.unwrapDataKey({ ...key, context: CONTEXT }), "KEY_UNAVAILABLE");
  await keyError(provider.rewrapDataKey({ ...key, context: CONTEXT }), "KEY_UNAVAILABLE");
  assert.equal(fake.calls.length, before);
  assert.equal(provider.stats().closed, true);
});

test("a call in flight when the provider is closed fails KEY_UNAVAILABLE and its plaintext is overwritten", async () => {
  const { provider, fake } = setup();
  const key = await provider.generateDataKey(CONTEXT);
  fake.setDelay(30);
  const pending = provider.unwrapDataKey({ ...key, context: CONTEXT });
  setTimeout(() => provider.close(), 5);
  await keyError(pending, "KEY_UNAVAILABLE");
  assert.ok(fake.plaintexts.at(-1).every((byte) => byte === 0));
});

test("stats holds counts only", async () => {
  const { provider } = setup({ cache: { maxEntries: 4, maxAgeMs: 1000, perTenantMaxEntries: 2 } });
  const key = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...key, context: CONTEXT })).fill(0);
  const stats = provider.stats();
  for (const [name, value] of Object.entries(stats)) {
    assert.ok(typeof value === "number" || typeof value === "boolean", `${name} is not a count`);
  }
  assert.equal(JSON.stringify(stats).includes("arn:"), false);
});
