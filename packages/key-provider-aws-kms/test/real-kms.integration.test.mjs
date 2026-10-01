// Integration tests against real AWS KMS.
//
// They run only when both variables are set, and are reported as skipped with
// a reason otherwise:
//   RSV_KMS_TEST_KEY_ARN      a symmetric encryption key the caller may use
//   RSV_KMS_TEST_OLD_KEY_ARN  a second one, in the same account and region
//
// This file, not the library, constructs the client: `new KMSClient({ region })`
// with the default credential chain of the test process. The principal needs
// kms:GenerateDataKey, kms:Decrypt, kms:ReEncryptFrom, and kms:ReEncryptTo on
// both keys, and, for the disabled-key case only, kms:DisableKey and
// kms:EnableKey on the second key. Throttling is not provoked here; it is
// covered by the mock suite only.
//
// Only synthetic identifiers are sent. No ARN, account id, or key is printed.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { DecryptCommand, DisableKeyCommand, EnableKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { KeyProviderError } from "@redact-secret/vault-contracts";
import { keyProviderConformanceCases, runWithNodeTest } from "@redact-secret/vault-conformance";

import { createAwsKmsKeyProvider } from "../dist/index.js";
import { e2eCases } from "./e2e-cases.mjs";
import { assertCommands, expectedDigest } from "./helpers.mjs";

const KEY_A = process.env.RSV_KMS_TEST_KEY_ARN ?? "";
const KEY_OLD = process.env.RSV_KMS_TEST_OLD_KEY_ARN ?? "";
const ARN = /^arn:(aws[a-z-]*):kms:([a-z0-9-]+):(\d{12}):key\/[0-9a-f-]{36}$/;
const parsed = ARN.exec(KEY_A);
const parsedOld = ARN.exec(KEY_OLD);

let skip = false;
if (KEY_A === "" || KEY_OLD === "") {
  skip = "real AWS KMS is not configured: set RSV_KMS_TEST_KEY_ARN and RSV_KMS_TEST_OLD_KEY_ARN to two symmetric test keys";
} else if (parsed === null || parsedOld === null || KEY_A === KEY_OLD || parsed[2] !== parsedOld[2] || parsed[3] !== parsedOld[3]) {
  throw new Error("RSV_KMS_TEST_KEY_ARN and RSV_KMS_TEST_OLD_KEY_ARN must be two different full key ARNs of one account and region");
}

const region = parsed?.[2] ?? "us-east-1";
const accountId = parsed?.[3] ?? "000000000000";
const expected = { region, accountId, partition: parsed?.[1] ?? "aws" };

const NAMESPACE = "rsv-113-qualification-synthetic";
const TENANT = "tenant-acme-synthetic";
const OTHER_TENANT = "tenant-globex-synthetic";
const SCOPE = { namespaces: [NAMESPACE], tenants: [TENANT, OTHER_TENANT] };
const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const captureId = () => `cap_${Array.from(randomBytes(26), (byte) => ALPHABET[byte % 32]).join("")}`;
const context = (tenant = TENANT) => ({ namespace: NAMESPACE, tenant, captureId: captureId() });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const raw = skip ? null : new KMSClient({ region });
/** Per-operation latencies in milliseconds, and every request the provider sent. */
const latencies = new Map();
const sent = [];
const client = {
  async send(command, options) {
    const name = command.constructor.name;
    sent.push({ name, input: structuredClone(command.input) });
    const started = performance.now();
    try {
      return await raw.send(command, options);
    } finally {
      const list = latencies.get(name) ?? [];
      list.push(performance.now() - started);
      latencies.set(name, list);
    }
  },
};

const provider = (keys, extra = {}) => createAwsKmsKeyProvider({ client, keys, expected, scope: SCOPE, ...extra });
const activeA = (extra) => provider([{ keyArn: KEY_A, state: "active" }, { keyArn: KEY_OLD, state: "decrypt-only" }], extra);
const activeOld = (extra) => provider([{ keyArn: KEY_OLD, state: "active" }, { keyArn: KEY_A, state: "decrypt-only" }], extra);

async function code(promise) {
  try {
    const value = await promise;
    if (value instanceof Uint8Array) value.fill(0);
    return "resolved";
  } catch (error) {
    assert.ok(error instanceof KeyProviderError, "a foreign error escaped the provider");
    assert.equal(error.message, new KeyProviderError(error.code).message);
    assert.equal("cause" in error, false);
    assert.deepEqual(Object.getOwnPropertyNames(error).sort(), ["code", "message", "name", "stack"].sort());
    assert.equal(`${error.stack}${JSON.stringify(error)}`.includes(accountId), false, "an error carries the account id");
    assert.equal(`${error.stack}${JSON.stringify(error)}`.includes("arn:"), false, "an error carries an ARN");
    return error.code;
  }
}

/** The name of what the SDK throws for a raw call. Used to record what KMS itself answers. */
async function rawErrorName(command) {
  try {
    const output = await raw.send(command);
    if (output.Plaintext instanceof Uint8Array) output.Plaintext.fill(0);
    return "resolved";
  } catch (error) {
    return error.name;
  }
}

const it = (name, fn) => test(`real KMS: ${name}`, { skip, timeout: 180_000 }, fn);

// The shared conformance cases. With two keys, a rotation swaps which one is
// active and leaves the other decrypt-only; retirement is the provider's
// configuration, which refuses the reference without a call.
runWithNodeTest(
  keyProviderConformanceCases(async ({ scope }) => {
    let states = { [KEY_OLD]: "active", [KEY_A]: "decrypt-only" };
    const build = () => createAwsKmsKeyProvider({ client, keys: Object.entries(states).map(([keyArn, state]) => ({ keyArn, state })), expected, scope });
    let current = build();
    const from = sent.length;
    return {
      provider: {
        get profile() {
          return current.profile;
        },
        generateDataKey: (...args) => current.generateDataKey(...args),
        unwrapDataKey: (...args) => current.unwrapDataKey(...args),
        rewrapDataKey: (...args) => current.rewrapDataKey(...args),
      },
      async rotate() {
        const next = {};
        for (const [arn, state] of Object.entries(states)) next[arn] = state === "active" ? "decrypt-only" : state === "decrypt-only" ? "active" : state;
        states = next;
        current = build();
      },
      async retire(keyRef) {
        states = Object.fromEntries(Object.entries(states).map(([arn, state]) => [arn, `aws-kms:${arn}` === keyRef ? "retired" : state]));
        current = build();
      },
      async dispose() {
        current.close();
        assertCommands(sent.slice(from), [...scope.namespaces, ...scope.tenants, "tenant-initech-synthetic"]);
      },
    };
  }),
  (name, fn) => test(`real KMS: ${name}`, { skip, timeout: 180_000 }, fn),
);

for (const item of e2eCases(async () => ({
  provider: activeOld(),
  rotated: activeA(),
  context: context(),
  otherContext: context(OTHER_TENANT),
}))) {
  it(item.name, item.run);
}

it("KMS itself binds the wrapped key to the context digest: another context, no context, and an extra pair all fail", async () => {
  const one = context();
  const key = await activeA().generateDataKey(one);
  const good = { "rsv:ctx": expectedDigest(one), "rsv:v": "1" };
  const decrypt = (EncryptionContext) => rawErrorName(new DecryptCommand({ KeyId: KEY_A, CiphertextBlob: key.wrappedKey, ...(EncryptionContext ? { EncryptionContext } : {}) }));
  assert.equal(await decrypt(good), "resolved", "the digest context this test computed independently did not decrypt");
  assert.equal(await decrypt(undefined), "InvalidCiphertextException");
  assert.equal(await decrypt({ ...good, "rsv:ctx": expectedDigest({ ...one, tenant: OTHER_TENANT }) }), "InvalidCiphertextException");
  assert.equal(await decrypt({ "rsv:ctx": good["rsv:ctx"] }), "InvalidCiphertextException");
  assert.equal(await decrypt({ ...good, extra: "x" }), "InvalidCiphertextException");
  // The same through the provider, for each field of the KeyContext.
  for (const changed of [{ ...one, captureId: captureId() }, { ...one, tenant: OTHER_TENANT }]) {
    assert.equal(await code(activeA().unwrapDataKey({ ...key, context: changed })), "KEY_INTEGRITY");
    assert.equal(await code(activeA().rewrapDataKey({ ...key, context: changed })), "KEY_INTEGRITY");
  }
  // Labels are part of the binding.
  const labelled = activeA({ contextLabels: { environment: "qualification-synthetic" } });
  assert.equal(await code(labelled.unwrapDataKey({ ...key, context: one })), "KEY_INTEGRITY");
  const withLabels = await labelled.generateDataKey(one);
  assert.equal(await code(labelled.unwrapDataKey({ ...withLabels, context: one })), "resolved");
  assert.equal(await code(activeA().unwrapDataKey({ ...withLabels, context: one })), "KEY_INTEGRITY");
});

it("a ciphertext produced under key A presented with the reference of key B is refused, although KMS would decrypt it without a KeyId", async () => {
  const one = context();
  const key = await activeA().generateDataKey(one);
  const EncryptionContext = { "rsv:ctx": expectedDigest(one), "rsv:v": "1" };
  // What the explicit KeyId protects against: without it, KMS picks the key from the blob and succeeds.
  assert.equal(await rawErrorName(new DecryptCommand({ CiphertextBlob: key.wrappedKey, EncryptionContext })), "resolved");
  assert.equal(await rawErrorName(new DecryptCommand({ KeyId: KEY_OLD, CiphertextBlob: key.wrappedKey, EncryptionContext })), "IncorrectKeyException");
  const before = sent.length;
  assert.equal(await code(activeA().unwrapDataKey({ keyRef: `aws-kms:${KEY_OLD}`, wrappedKey: key.wrappedKey, context: one })), "KEY_UNAVAILABLE");
  assert.equal(await code(activeA().rewrapDataKey({ keyRef: `aws-kms:${KEY_OLD}`, wrappedKey: key.wrappedKey, context: one })), "KEY_UNAVAILABLE");
  assert.equal(sent[before].input.KeyId, KEY_OLD);
  assert.equal(sent[before + 1].input.SourceKeyId, KEY_OLD);
});

it("ReEncrypt moves a wrapped key from the old key to the active key without a Decrypt", async () => {
  const one = context();
  const old = await activeOld().generateDataKey(one);
  assert.equal(old.keyRef, `aws-kms:${KEY_OLD}`);
  const before = sent.length;
  const target = activeA();
  const moved = await target.rewrapDataKey({ keyRef: old.keyRef, wrappedKey: old.wrappedKey, context: one });
  assert.deepEqual(sent.slice(before).map((call) => call.name), ["ReEncryptCommand"]);
  assert.equal(moved.keyRef, `aws-kms:${KEY_A}`);
  assert.equal(target.stats().decryptCalls, 0);
  assert.deepEqual(await target.unwrapDataKey({ ...moved, context: one }), old.plaintextKey);
  // KMS agrees that the new blob belongs to key A and no longer to the old key.
  const EncryptionContext = { "rsv:ctx": expectedDigest(one), "rsv:v": "1" };
  assert.equal(await rawErrorName(new DecryptCommand({ KeyId: KEY_OLD, CiphertextBlob: moved.wrappedKey, EncryptionContext })), "IncorrectKeyException");
  old.plaintextKey.fill(0);
});

it("a wrong-account or wrong-region ARN is rejected at construction, and a key id that does not exist is KEY_UNAVAILABLE", async () => {
  const otherAccount = accountId === "111122223333" ? "444455556666" : "111122223333";
  for (const keyArn of [KEY_A.replace(accountId, otherAccount), KEY_A.replace(region, region === "us-west-2" ? "us-east-1" : "us-west-2"), KEY_A.split("/")[1], "alias/rsv-synthetic"]) {
    assert.throws(() => provider([{ keyArn, state: "active" }]), { code: "KEY_INVALID_ARGUMENT" });
  }
  // Syntactically valid, in the right account and region, and not a key.
  const missing = `arn:${expected.partition}:kms:${region}:${accountId}:key/00000000-0000-4000-8000-000000000000`;
  const one = context();
  const key = await activeA().generateDataKey(one);
  const absent = provider([{ keyArn: missing, state: "active" }, { keyArn: KEY_A, state: "decrypt-only" }]);
  assert.equal(await code(absent.generateDataKey(one)), "KEY_UNAVAILABLE");
  assert.equal(await code(absent.unwrapDataKey({ keyRef: `aws-kms:${missing}`, wrappedKey: key.wrappedKey, context: one })), "KEY_UNAVAILABLE");
  assert.equal(await code(absent.rewrapDataKey({ ...key, context: one })), "KEY_UNAVAILABLE");
});

it("callTimeoutMs and the caller's signal bound a real call", async () => {
  const one = context();
  const key = await activeA().generateDataKey(one);
  const hurried = activeA({ callTimeoutMs: 1 });
  assert.equal(await code(hurried.generateDataKey(one)), "KEY_TIMEOUT");
  assert.equal(await code(hurried.unwrapDataKey({ ...key, context: one })), "KEY_TIMEOUT");
  const controller = new AbortController();
  const pending = activeA().unwrapDataKey({ ...key, context: one }, { signal: controller.signal });
  controller.abort();
  assert.equal(await code(pending), "KEY_ABORTED");
  assert.equal(await code(activeA().unwrapDataKey({ ...key, context: one })), "resolved");
});

it("a key disabled in KMS is KEY_UNAVAILABLE; a cached data key outlives it until the cache entry ages out", async (t) => {
  const one = context();
  const two = context();
  const source = activeOld();
  const key = await source.generateDataKey(one);
  const uncached = await source.generateDataKey(two);
  let now = 1_790_000_000_000;
  const cached = activeOld({ cache: { maxEntries: 4, maxAgeMs: 60_000, perTenantMaxEntries: 4, now: () => now } });
  assert.equal(await code(cached.unwrapDataKey({ ...key, context: one })), "resolved");
  const EncryptionContext = { "rsv:ctx": expectedDigest(one), "rsv:v": "1" };

  let disabledAfterMs;
  try {
    const started = performance.now();
    await raw.send(new DisableKeyCommand({ KeyId: KEY_OLD }));
    // KMS is eventually consistent: wait until the change is visible, for at most a minute.
    let outcome = "resolved";
    for (let attempt = 0; attempt < 60 && outcome === "resolved"; attempt += 1) {
      outcome = await code(source.unwrapDataKey({ ...key, context: one }));
      if (outcome === "resolved") await sleep(1000);
    }
    disabledAfterMs = Math.round(performance.now() - started);
    assert.equal(outcome, "KEY_UNAVAILABLE");
    assert.equal(await rawErrorName(new DecryptCommand({ KeyId: KEY_OLD, CiphertextBlob: key.wrappedKey, EncryptionContext })), "DisabledException");
    assert.equal(await code(source.generateDataKey(one)), "KEY_UNAVAILABLE");
    assert.equal(await code(source.rewrapDataKey({ ...key, context: one })), "KEY_UNAVAILABLE");
    // Moving it to the enabled key is refused too: the source key is the disabled one.
    assert.equal(await code(activeA().rewrapDataKey({ ...key, context: one })), "KEY_UNAVAILABLE");
    // The enabled key is unaffected.
    assert.equal(await code(activeA().generateDataKey(one)), "resolved");

    // The documented revocation delay: the cached key is still served, an uncached one is not.
    assert.equal(await code(cached.unwrapDataKey({ ...key, context: one })), "resolved");
    assert.equal(await code(cached.unwrapDataKey({ ...uncached, context: two })), "KEY_UNAVAILABLE");
    now += 60_000;
    assert.equal(await code(cached.unwrapDataKey({ ...key, context: one })), "KEY_UNAVAILABLE");
  } finally {
    await raw.send(new EnableKeyCommand({ KeyId: KEY_OLD }));
    let outcome = "KEY_UNAVAILABLE";
    for (let attempt = 0; attempt < 60 && outcome !== "resolved"; attempt += 1) {
      outcome = await code(source.unwrapDataKey({ ...key, context: one }));
      if (outcome !== "resolved") await sleep(1000);
    }
    assert.equal(outcome, "resolved", "the test key did not become usable again after EnableKey");
  }
  t.diagnostic(`DisableKey was visible to Decrypt after ${disabledAfterMs} ms`);
});

it("latency of each KMS call, as seen by the provider's client", (t) => {
  for (const [name, list] of [...latencies].sort()) {
    const sorted = [...list].sort((a, b) => a - b);
    const at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))].toFixed(0);
    t.diagnostic(`${name}: n=${sorted.length} min=${sorted[0].toFixed(0)}ms p50=${at(0.5)}ms p95=${at(0.95)}ms max=${sorted.at(-1).toFixed(0)}ms`);
  }
  assert.ok(latencies.size > 0);
});
