// The opt-in cache of unwrapped data keys: off by default, bounded by count,
// age, and tenant, overwritten on eviction and close. Synthetic data only.
import assert from "node:assert/strict";
import test from "node:test";

import { createDataKeyCache } from "../dist/cache.js";
import { CACHE_MAX_AGE_CEILING_MS, createAwsKmsKeyProvider } from "../dist/index.js";
import { createFakeKms, EXPECTED } from "./fake-kms.mjs";
import { CONTEXT, keyError, NAMESPACE, OTHER_TENANT, SCOPE, TENANT } from "./helpers.mjs";

const capture = (index) => `cap_${index.toString(26).replace(/[0-9]/g, (d) => "qrstuvwxyz"[d]).padStart(26, "a")}`;
const zeroed = (bytes) => bytes.every((byte) => byte === 0);
const key = (fill) => new Uint8Array(32).fill(fill);

function clock(start = 1_790_000_000_000) {
  let now = start;
  return { now: () => now, advance: (ms) => (now += ms), set: (value) => (now = value) };
}

function setup(cache) {
  const fake = createFakeKms();
  const active = fake.createKey();
  const provider = createAwsKmsKeyProvider({
    client: fake.client,
    keys: [{ keyArn: active, state: "active" }],
    expected: EXPECTED,
    scope: SCOPE,
    ...(cache === undefined ? {} : { cache }),
  });
  const decrypts = () => fake.calls.filter((call) => call.name === "DecryptCommand").length;
  return { fake, active, provider, decrypts };
}

test("the cache is off by default: a second unwrap calls KMS again", async () => {
  const { provider, decrypts } = setup(undefined);
  const dataKey = await provider.generateDataKey(CONTEXT);
  const one = await provider.unwrapDataKey({ ...dataKey, context: CONTEXT });
  const two = await provider.unwrapDataKey({ ...dataKey, context: CONTEXT });
  assert.deepEqual(one, two);
  assert.equal(decrypts(), 2);
  const stats = provider.stats();
  assert.equal(stats.cacheEnabled, false);
  assert.equal(stats.cacheEntries, 0);
  assert.equal(stats.cacheHits, 0);
});

test("with the cache on, a second unwrap of the same key and context is served without KMS, as a separate copy", async () => {
  const { provider, decrypts } = setup({ maxEntries: 4, maxAgeMs: 60_000, perTenantMaxEntries: 4 });
  const dataKey = await provider.generateDataKey(CONTEXT);
  assert.equal(provider.stats().cacheEntries, 0, "generateDataKey must not populate the cache");
  const one = await provider.unwrapDataKey({ ...dataKey, context: CONTEXT });
  const two = await provider.unwrapDataKey({ ...dataKey, context: CONTEXT });
  assert.equal(decrypts(), 1);
  assert.deepEqual(one, dataKey.plaintextKey);
  assert.deepEqual(two, dataKey.plaintextKey);
  assert.notEqual(one, two);
  // Overwriting what a caller was given does not reach the cached copy.
  one.fill(0);
  two.fill(0);
  assert.deepEqual(await provider.unwrapDataKey({ ...dataKey, context: CONTEXT }), dataKey.plaintextKey);
  assert.equal(decrypts(), 1);
  assert.deepEqual(
    { entries: provider.stats().cacheEntries, tenants: provider.stats().cacheTenants, hits: provider.stats().cacheHits, misses: provider.stats().cacheMisses },
    { entries: 1, tenants: 1, hits: 2, misses: 1 },
  );
});

test("the cache key is the key reference, the wrapped key, and the context: none of them is served from another's entry", async () => {
  const { provider, decrypts } = setup({ maxEntries: 8, maxAgeMs: 60_000, perTenantMaxEntries: 8 });
  const dataKey = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(decrypts(), 1);

  // Another context with the cached wrapped key: KMS is asked and refuses.
  await keyError(provider.unwrapDataKey({ ...dataKey, context: { ...CONTEXT, captureId: capture(1) } }), "KEY_INTEGRITY");
  await keyError(provider.unwrapDataKey({ ...dataKey, context: { ...CONTEXT, tenant: OTHER_TENANT } }), "KEY_INTEGRITY");
  assert.equal(decrypts(), 3);
  // A tampered wrapped key is a different entry.
  const tampered = dataKey.wrappedKey.slice();
  tampered[tampered.length - 1] ^= 1;
  await keyError(provider.unwrapDataKey({ keyRef: dataKey.keyRef, wrappedKey: tampered, context: CONTEXT }), "KEY_INTEGRITY");
  assert.equal(decrypts(), 4);
  // Failures are not cached.
  assert.equal(provider.stats().cacheEntries, 1);
  // Scope and key reference are checked before the cache is read.
  await keyError(provider.unwrapDataKey({ ...dataKey, context: { ...CONTEXT, namespace: "other-synthetic" } }), "KEY_UNAVAILABLE");
  await keyError(provider.unwrapDataKey({ ...dataKey, keyRef: `${dataKey.keyRef}x`, context: CONTEXT }), "KEY_UNAVAILABLE");
  await keyError(provider.unwrapDataKey({ ...dataKey, context: CONTEXT }, { signal: AbortSignal.abort() }), "KEY_ABORTED");
  assert.equal(decrypts(), 4);
});

test("rewrap is never cached and never reads the cache", async () => {
  const { provider, fake } = setup({ maxEntries: 4, maxAgeMs: 60_000, perTenantMaxEntries: 4 });
  const dataKey = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  await provider.rewrapDataKey({ ...dataKey, context: CONTEXT });
  await provider.rewrapDataKey({ ...dataKey, context: CONTEXT });
  assert.equal(fake.calls.filter((call) => call.name === "ReEncryptCommand").length, 2);
  assert.equal(provider.stats().cacheEntries, 1);
});

test("bounded by count: the oldest entry is evicted", async () => {
  const { provider, decrypts } = setup({ maxEntries: 2, maxAgeMs: 60_000, perTenantMaxEntries: 2 });
  const contexts = [0, 1, 2].map((i) => ({ ...CONTEXT, captureId: capture(i) }));
  const keys = [];
  for (const context of contexts) keys.push(await provider.generateDataKey(context));
  for (let i = 0; i < 3; i += 1) (await provider.unwrapDataKey({ ...keys[i], context: contexts[i] })).fill(0);
  assert.equal(decrypts(), 3);
  assert.equal(provider.stats().cacheEntries, 2);
  assert.equal(provider.stats().cacheEvictions, 1);
  (await provider.unwrapDataKey({ ...keys[2], context: contexts[2] })).fill(0);
  (await provider.unwrapDataKey({ ...keys[1], context: contexts[1] })).fill(0);
  assert.equal(decrypts(), 3, "the two newest entries are still cached");
  (await provider.unwrapDataKey({ ...keys[0], context: contexts[0] })).fill(0);
  assert.equal(decrypts(), 4, "the oldest entry was evicted");
  assert.equal(provider.stats().cacheEntries, 2);
});

test("bounded per tenant: one tenant cannot fill the cache, and its eviction leaves other tenants alone", async () => {
  const { provider, decrypts } = setup({ maxEntries: 10, maxAgeMs: 60_000, perTenantMaxEntries: 2 });
  const otherContext = { ...CONTEXT, tenant: OTHER_TENANT, captureId: capture(50) };
  const otherKey = await provider.generateDataKey(otherContext);
  (await provider.unwrapDataKey({ ...otherKey, context: otherContext })).fill(0);
  const contexts = [0, 1, 2, 3].map((i) => ({ ...CONTEXT, captureId: capture(i) }));
  const keys = [];
  for (const context of contexts) keys.push(await provider.generateDataKey(context));
  for (let i = 0; i < 4; i += 1) (await provider.unwrapDataKey({ ...keys[i], context: contexts[i] })).fill(0);
  assert.equal(provider.stats().cacheEntries, 3, "two of the busy tenant and one of the other");
  assert.equal(provider.stats().cacheTenants, 2);
  const before = decrypts();
  (await provider.unwrapDataKey({ ...otherKey, context: otherContext })).fill(0);
  (await provider.unwrapDataKey({ ...keys[3], context: contexts[3] })).fill(0);
  (await provider.unwrapDataKey({ ...keys[2], context: contexts[2] })).fill(0);
  assert.equal(decrypts(), before);
  (await provider.unwrapDataKey({ ...keys[0], context: contexts[0] })).fill(0);
  assert.equal(decrypts(), before + 1);
});

test("bounded by age, with an injected clock: an entry is served until maxAgeMs and not at or after it", async () => {
  const time = clock();
  const { provider, decrypts } = setup({ maxEntries: 4, maxAgeMs: 1000, perTenantMaxEntries: 4, now: time.now });
  const dataKey = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  time.advance(999);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(decrypts(), 1);
  time.advance(1);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(decrypts(), 2, "an entry at its maximum age must not be served");
  // A read does not extend the lifetime of an entry.
  time.advance(600);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  time.advance(600);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(decrypts(), 3);
  // A clock that goes backwards, or stops answering, expires entries instead of extending them.
  time.set(1_000);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(decrypts(), 4);
  time.set(Number.NaN);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(decrypts(), 6);
  assert.equal(provider.stats().cacheEntries, 0);
});

test("maxAgeMs has a hard ceiling of five minutes", () => {
  assert.equal(CACHE_MAX_AGE_CEILING_MS, 300_000);
  createDataKeyCache({ maxEntries: 1, maxAgeMs: 300_000, perTenantMaxEntries: 1 });
  assert.throws(() => createDataKeyCache({ maxEntries: 1, maxAgeMs: 300_001, perTenantMaxEntries: 1 }), { code: "KEY_INVALID_ARGUMENT" });
});

test("a key disabled in KMS keeps unwrapping from the cache until the entry ages out: the revocation delay is maxAgeMs", async () => {
  const time = clock();
  const { provider, fake, active, decrypts } = setup({ maxEntries: 4, maxAgeMs: 60_000, perTenantMaxEntries: 4, now: time.now });
  const cached = await provider.generateDataKey(CONTEXT);
  const neverUnwrapped = await provider.generateDataKey({ ...CONTEXT, captureId: capture(7) });
  (await provider.unwrapDataKey({ ...cached, context: CONTEXT })).fill(0);

  fake.setState(active, "Disabled");

  // This is the documented limit, not a defect the test hides: the cached key is still returned.
  time.advance(59_999);
  assert.deepEqual(await provider.unwrapDataKey({ ...cached, context: CONTEXT }), cached.plaintextKey);
  assert.equal(decrypts(), 1);
  // A key that was not cached is refused at once, and so are generate and rewrap, which are never cached.
  await keyError(provider.unwrapDataKey({ ...neverUnwrapped, context: { ...CONTEXT, captureId: capture(7) } }), "KEY_UNAVAILABLE");
  await keyError(provider.generateDataKey(CONTEXT), "KEY_UNAVAILABLE");
  await keyError(provider.rewrapDataKey({ ...cached, context: CONTEXT }), "KEY_UNAVAILABLE");
  // At maxAgeMs the entry is gone, KMS is asked, and the disabled key is refused.
  time.advance(1);
  await keyError(provider.unwrapDataKey({ ...cached, context: CONTEXT }), "KEY_UNAVAILABLE");
  assert.equal(provider.stats().cacheEntries, 0);
  // Closing the provider is the immediate way to drop cached keys.
});

test("close overwrites and drops every entry", async () => {
  const { provider } = setup({ maxEntries: 4, maxAgeMs: 60_000, perTenantMaxEntries: 4 });
  const dataKey = await provider.generateDataKey(CONTEXT);
  (await provider.unwrapDataKey({ ...dataKey, context: CONTEXT })).fill(0);
  assert.equal(provider.stats().cacheEntries, 1);
  provider.close();
  assert.equal(provider.stats().cacheEntries, 0);
  await keyError(provider.unwrapDataKey({ ...dataKey, context: CONTEXT }), "KEY_UNAVAILABLE");
});

// The cache module itself, where the arrays it owns can be observed.

test("cache unit: an entry is overwritten when evicted by count, by tenant bound, by age, by replacement, and by clear", () => {
  const time = clock();
  const cache = createDataKeyCache({ maxEntries: 3, maxAgeMs: 1000, perTenantMaxEntries: 2, now: time.now });

  // By tenant bound.
  const a1 = key(1);
  const a2 = key(2);
  const a3 = key(3);
  cache.put("a1", TENANT, a1);
  cache.put("a2", TENANT, a2);
  cache.put("a3", TENANT, a3);
  assert.ok(zeroed(a1), "an entry evicted by the tenant bound was not overwritten");
  assert.equal(cache.get("a1"), undefined);
  assert.deepEqual(cache.get("a2"), key(2));

  // By count: the oldest entry overall goes, whichever tenant it belongs to.
  const b1 = key(4);
  const c1 = key(5);
  cache.put("b1", OTHER_TENANT, b1);
  cache.put("c1", "tenant-third-synthetic", c1);
  assert.ok(zeroed(a2), "an entry evicted by the count bound was not overwritten");
  assert.equal(cache.counts().entries, 3);
  assert.equal(cache.counts().tenants, 3);

  // By replacement of the same id.
  const b1Again = key(6);
  cache.put("b1", OTHER_TENANT, b1Again);
  assert.ok(zeroed(b1), "a replaced entry was not overwritten");
  assert.deepEqual(cache.get("b1"), key(6));
  assert.equal(cache.counts().entries, 3);

  // By age, on a read and on a write.
  time.advance(1000);
  assert.equal(cache.get("a3"), undefined);
  assert.ok(zeroed(a3), "an entry that aged out was not overwritten");
  const d1 = key(7);
  cache.put("d1", TENANT, d1);
  assert.ok(zeroed(c1) && zeroed(b1Again), "a write must purge aged entries");
  assert.deepEqual(cache.counts(), { entries: 1, tenants: 1, hits: 2, misses: 2, evictions: 6 });

  // By clear.
  cache.clear();
  assert.ok(zeroed(d1), "clear did not overwrite an entry");
  assert.deepEqual({ entries: cache.counts().entries, tenants: cache.counts().tenants }, { entries: 0, tenants: 0 });
});

test("cache unit: get returns a copy, and the cache holds the array it was given", () => {
  const cache = createDataKeyCache({ maxEntries: 2, maxAgeMs: 1000, perTenantMaxEntries: 2 });
  const owned = key(9);
  cache.put("id", TENANT, owned);
  const copy = cache.get("id");
  assert.notEqual(copy, owned);
  copy.fill(0);
  assert.deepEqual(cache.get("id"), key(9));
  cache.clear();
  assert.ok(zeroed(owned));
});

test("the provider hands the cache its own copy: zeroing the returned key does not empty the cache, and close leaves the returned key alone", async () => {
  const { provider, decrypts } = setup({ maxEntries: 2, maxAgeMs: 60_000, perTenantMaxEntries: 2 });
  const dataKey = await provider.generateDataKey({ namespace: NAMESPACE, tenant: TENANT, captureId: capture(9) });
  const context = { namespace: NAMESPACE, tenant: TENANT, captureId: capture(9) };
  const first = await provider.unwrapDataKey({ ...dataKey, context });
  first.fill(0);
  const second = await provider.unwrapDataKey({ ...dataKey, context });
  assert.deepEqual(second, dataKey.plaintextKey);
  assert.equal(decrypts(), 1);
  provider.close();
  assert.deepEqual(second, dataKey.plaintextKey, "a key already returned belongs to the caller");
});
