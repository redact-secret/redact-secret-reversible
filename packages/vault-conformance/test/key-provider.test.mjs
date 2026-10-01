// The key-provider harness against the insecure deterministic test provider,
// the provider's own unit tests, and mutation controls for the harness.
// Every seed, identifier, and key here is synthetic test material.
import assert from "node:assert/strict";
import test from "node:test";

import { KeyProviderError } from "@redact-secret/vault-contracts";

import { createInsecureTestKeyProvider, keyProviderConformanceCases, runCases, runWithNodeTest } from "../dist/index.js";

const SEED = "synthetic-seed-for-tests-only";

/** The factory an adapter author would write, here for the insecure test provider. */
function factory(wrap = (provider) => provider, capabilities = { rotate: true, retire: true }) {
  return async ({ scope }) => {
    const provider = createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed: SEED, scope });
    return {
      provider: wrap(provider),
      ...(capabilities.rotate ? { rotate: async () => void provider.control.rotate() } : {}),
      ...(capabilities.retire ? { retire: async (keyRef) => provider.control.retire(keyRef) } : {}),
    };
  };
}

const cases = keyProviderConformanceCases(factory());
runWithNodeTest(cases, test);

test("the key-provider harness skips nothing for the insecure test provider", async () => {
  const results = await runCases(cases);
  assert.deepEqual(results.filter((result) => result.status !== "passed"), []);
  assert.ok(results.length >= 12);
});

test("without rotate and retire, the rotation and retirement cases are skipped with a reason", async () => {
  const results = await runCases(keyProviderConformanceCases(factory(undefined, { rotate: false, retire: false })));
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
  const skipped = results.filter((result) => result.status === "skipped");
  assert.equal(skipped.length, 2);
  for (const result of skipped) assert.match(result.detail, /rotate capability/);
  const onlyRotate = await runCases(keyProviderConformanceCases(factory(undefined, { rotate: true, retire: false })));
  assert.deepEqual(onlyRotate.filter((result) => result.status === "skipped").map((result) => result.detail), ["the factory supplies no retire capability"]);
});

test("createInsecureTestKeyProvider refuses to construct without the exact acknowledgement", () => {
  for (const options of [undefined, null, {}, { seed: SEED }, { acknowledgeInsecure: true, seed: SEED }, { acknowledgeInsecure: "test", seed: SEED }, { acknowledgeInsecure: "TEST-ONLY", seed: SEED }]) {
    assert.throws(() => createInsecureTestKeyProvider(options), TypeError);
  }
  for (const seed of [undefined, "", new Uint8Array(0), 7]) {
    assert.throws(() => createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed }), TypeError);
  }
  const provider = createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed: SEED });
  assert.equal(provider.profile, "insecure-test-only");
});

test("the insecure test provider is deterministic in its seed and call order", async () => {
  const context = { namespace: "support-synthetic", tenant: "tenant-acme-synthetic", captureId: "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa" };
  const open = (seed) => createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed });
  const [a, b, other] = [open(SEED), open(new TextEncoder().encode(SEED)), open("another-synthetic-seed")];
  const [ka, kb, ko] = [await a.generateDataKey(context), await b.generateDataKey(context), await other.generateDataKey(context)];
  assert.deepEqual(ka, kb);
  assert.equal(ka.keyRef, "insecure-test:v1");
  assert.notDeepEqual(ka.plaintextKey, ko.plaintextKey);
  assert.notDeepEqual(ka.wrappedKey, ko.wrappedKey);
  assert.deepEqual(await a.generateDataKey(context), await b.generateDataKey(context));
  assert.deepEqual(await a.rewrapDataKey({ ...ka, context }), await b.rewrapDataKey({ ...kb, context }));
  // A key wrapped under one seed does not authenticate under another.
  await assert.rejects(other.unwrapDataKey({ keyRef: ka.keyRef, wrappedKey: ka.wrappedKey, context }), (error) => error instanceof KeyProviderError && error.code === "KEY_INTEGRITY");
});

test("the insecure test provider's controls rotate and retire versions", async () => {
  const context = { namespace: "support-synthetic", tenant: "tenant-acme-synthetic", captureId: "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa" };
  const provider = createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed: SEED });
  assert.equal(provider.control.activeKeyRef(), "insecure-test:v1");
  assert.equal(provider.control.rotate(), "insecure-test:v2");
  assert.equal((await provider.generateDataKey(context)).keyRef, "insecure-test:v2");
  assert.throws(() => provider.control.retire("insecure-test:v9"), TypeError);
  provider.control.retire("insecure-test:v2");
  assert.equal(provider.control.activeKeyRef(), null);
  await assert.rejects(provider.generateDataKey(context), (error) => error instanceof KeyProviderError && error.code === "KEY_UNAVAILABLE");
  assert.equal(provider.control.rotate(), "insecure-test:v3");
  assert.equal((await provider.generateDataKey(context)).keyRef, "insecure-test:v3");
});

// ---- Mutation controls: the harness must fail a provider with one defect ----

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const MUTANTS = [
  [
    "unwrap ignores the context",
    (provider) => {
      const contexts = new Map();
      return {
        profile: provider.profile,
        async generateDataKey(context, options) {
          const key = await provider.generateDataKey(context, options);
          contexts.set(hex(key.wrappedKey), context);
          return key;
        },
        unwrapDataKey: (input, options) => provider.unwrapDataKey({ ...input, context: contexts.get(hex(input.wrappedKey)) ?? input.context }, options),
        rewrapDataKey: (input, options) => provider.rewrapDataKey(input, options),
      };
    },
    "key-provider: unwrapDataKey with any in-scope KeyContext field changed",
  ],
  [
    "an unknown key reference falls back to the active key",
    (provider) => ({
      profile: provider.profile,
      generateDataKey: (context, options) => provider.generateDataKey(context, options),
      unwrapDataKey: (input, options) => provider.unwrapDataKey(input, options).catch((error) => {
        if (error.code !== "KEY_UNAVAILABLE" || input.keyRef.startsWith("insecure-test:v")) throw error;
        return provider.unwrapDataKey({ ...input, keyRef: provider.control.activeKeyRef() }, options);
      }),
      rewrapDataKey: (input, options) => provider.rewrapDataKey(input, options),
    }),
    "key-provider: an unknown key reference is KEY_UNAVAILABLE",
  ],
  [
    "an error message contains the wrapped key",
    (provider) => ({
      profile: provider.profile,
      generateDataKey: (context, options) => provider.generateDataKey(context, options),
      unwrapDataKey: (input, options) => provider.unwrapDataKey(input, options).catch((error) => {
        error.message = `${error.message} ${hex(input.wrappedKey)}`;
        throw error;
      }),
      rewrapDataKey: (input, options) => provider.rewrapDataKey(input, options),
    }),
    "key-provider: a tampered wrapped key fails KEY_INTEGRITY",
  ],
  [
    "an error carries a cause",
    (provider) => ({
      profile: provider.profile,
      generateDataKey: (context, options) => provider.generateDataKey(context, options),
      unwrapDataKey: (input, options) => provider.unwrapDataKey(input, options).catch((error) => {
        error.cause = new Error("synthetic underlying failure");
        throw error;
      }),
      rewrapDataKey: (input, options) => provider.rewrapDataKey(input, options),
    }),
    "key-provider: a tampered wrapped key fails KEY_INTEGRITY",
  ],
  [
    "a foreign error instead of a KeyProviderError",
    (provider) => ({
      profile: provider.profile,
      generateDataKey: (context, options) => provider.generateDataKey(context, options),
      unwrapDataKey: (input, options) => provider.unwrapDataKey(input, options).catch(() => {
        throw new Error("synthetic foreign failure");
      }),
      rewrapDataKey: (input, options) => provider.rewrapDataKey(input, options),
    }),
    "key-provider: a tampered wrapped key fails KEY_INTEGRITY",
  ],
  [
    "the abort signal is ignored",
    (provider) => ({
      profile: provider.profile,
      generateDataKey: (context) => provider.generateDataKey(context),
      unwrapDataKey: (input) => provider.unwrapDataKey(input),
      rewrapDataKey: (input) => provider.rewrapDataKey(input),
    }),
    "key-provider: an already aborted signal is KEY_ABORTED",
  ],
  [
    "generateDataKey returns the same key every time",
    (provider) => {
      let first;
      return {
        profile: provider.profile,
        async generateDataKey(context, options) {
          const key = await provider.generateDataKey(context, options);
          first ??= { context, key: { ...key, plaintextKey: new Uint8Array(key.plaintextKey) } };
          return first.context === context ? { ...first.key, plaintextKey: new Uint8Array(first.key.plaintextKey) } : key;
        },
        unwrapDataKey: (input, options) => provider.unwrapDataKey(input, options),
        rewrapDataKey: (input, options) => provider.rewrapDataKey(input, options),
      };
    },
    "key-provider: two generated keys differ",
  ],
];

for (const [defect, wrap, mustFail] of MUTANTS) {
  test(`key-provider mutant: ${defect}`, async () => {
    const results = await runCases(keyProviderConformanceCases(factory(wrap)));
    const failed = results.filter((result) => result.status === "failed");
    assert.ok(failed.some((result) => result.name.startsWith(mustFail)), `expected "${mustFail}…" to fail; failing: ${failed.map((result) => result.name).join(" | ")}`);
    for (const result of failed) {
      assert.doesNotMatch(result.detail, /[0-9a-f]{32}/i, "a failure message never contains key bytes");
    }
  });
}

test("a retirement that does nothing is caught", async () => {
  const lazy = async ({ scope }) => {
    const provider = createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed: SEED, scope });
    return { provider, rotate: async () => void provider.control.rotate(), retire: async () => {} };
  };
  const failed = (await runCases(keyProviderConformanceCases(lazy))).filter((result) => result.status === "failed");
  assert.deepEqual(failed.map((result) => result.name), ["key-provider: a retired wrapping key version is KEY_UNAVAILABLE, and a key rewrapped before retirement survives"]);
});
