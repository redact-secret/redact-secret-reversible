/**
 * `keyProviderConformanceCases`: the behavior docs/specs/persistent-vault.md
 * §6.1 and §6.2 require of any `KeyProvider`.
 */
import { isKeyRef, KeyProviderError, LIMITS } from "@redact-secret/vault-contracts";
import type { KeyContext, KeyProviderErrorCode } from "@redact-secret/vault-contracts";
import { check, describe, equal, fail, freshNamespace, hashSeed, Prng, sameBytes, toHex } from "./support.js";
import { ConformanceFailure, ConformanceSkip } from "./types.js";
import type { ConformanceCase, KeyProviderFactory, KeyProviderScope, KeyProviderUnderTest } from "./types.js";

interface KeyBench extends KeyProviderUnderTest {
  readonly scope: KeyProviderScope;
  readonly rng: Prng;
  /** A context inside the provider's scope. */
  context(): KeyContext;
  /** Key material seen so far, so that every error can be checked for leaks. */
  readonly sensitive: Uint8Array[];
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function checkErrorIsClean(error: KeyProviderError, sensitive: readonly Uint8Array[], what: string): void {
  equal(error.message, new KeyProviderError(error.code).message, `${what}: the message is the fixed message of its code`);
  check(!("cause" in error) || (error as { cause?: unknown }).cause === undefined, `${what}: a KeyProviderError must not carry a cause`);
  const text = [error.message, error.stack ?? "", String(error)];
  for (const key of Object.getOwnPropertyNames(error)) {
    const value = (error as unknown as Record<string, unknown>)[key];
    text.push(typeof value === "string" ? value : value instanceof Uint8Array ? toHex(value) : "");
  }
  const haystack = text.join("\n");
  for (const bytes of sensitive) {
    if (bytes.byteLength < 8) continue;
    const hex = toHex(bytes);
    const b64 = base64(bytes);
    const leaked = haystack.includes(hex) || haystack.includes(hex.toUpperCase()) || haystack.includes(b64) || haystack.includes(b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"));
    check(!leaked, `${what}: an error must not contain key bytes`);
  }
}

async function throwsKeyError(
  bench: KeyBench,
  call: () => Promise<unknown>,
  codes: KeyProviderErrorCode | readonly KeyProviderErrorCode[],
  what: string,
): Promise<KeyProviderError> {
  const allowed = typeof codes === "string" ? [codes] : codes;
  let result: unknown;
  try {
    result = await call();
  } catch (error) {
    if (!(error instanceof KeyProviderError)) fail(`${what}: expected a KeyProviderError, got ${describe(error)}`);
    if (!allowed.includes(error.code)) fail(`${what}: expected ${describe(allowed.join("|"))}, got ${describe(error.code)}`);
    checkErrorIsClean(error, bench.sensitive, what);
    return error;
  }
  if (result instanceof Uint8Array) result.fill(0);
  fail(`${what}: expected ${describe(allowed.join("|"))} to be thrown, but the call succeeded`);
}

type KeyBody = (bench: KeyBench) => Promise<void>;

/**
 * The key-provider conformance cases. `factory` is called once per case with
 * the scope the provider must serve.
 */
export function keyProviderConformanceCases(factory: KeyProviderFactory, options: { readonly seed?: number } = {}): ConformanceCase[] {
  const seed = options.seed ?? 20261001;
  const cases: ConformanceCase[] = [];
  const group = "key-provider";

  const add = (name: string, body: KeyBody): void => {
    const fullName = `${group}: ${name}`;
    cases.push({
      name: fullName,
      group,
      async run() {
        const scope: KeyProviderScope = {
          namespaces: [freshNamespace(), freshNamespace()],
          tenants: ["tenant-acme-synthetic", "tenant-globex-synthetic"],
        };
        const sut = await factory({ scope });
        const rng = new Prng(hashSeed(seed, fullName));
        const bench: KeyBench = {
          ...sut,
          scope,
          rng,
          sensitive: [],
          context: () => ({ namespace: scope.namespaces[0] as string, tenant: scope.tenants[0] as string, captureId: rng.captureId() }),
        };
        try {
          await body(bench);
        } catch (error) {
          if (error instanceof ConformanceSkip) throw error;
          if (error instanceof ConformanceFailure) throw new ConformanceFailure(`${fullName}: ${error.message} [seed ${seed}]`);
          throw new ConformanceFailure(`${fullName}: unexpected ${describe(error)} [seed ${seed}]`);
        } finally {
          for (const bytes of bench.sensitive) bytes.fill(0);
          if (sut.dispose !== undefined) await sut.dispose();
        }
      },
    });
  };

  async function generate(bench: KeyBench, context: KeyContext) {
    const key = await bench.provider.generateDataKey(context);
    check(key.plaintextKey instanceof Uint8Array && key.wrappedKey instanceof Uint8Array, "generateDataKey returns byte arrays");
    // Copies: the provider's buffers are wiped when the case ends.
    bench.sensitive.push(new Uint8Array(key.plaintextKey), new Uint8Array(key.wrappedKey));
    return key;
  }

  const rotation = (bench: KeyBench): (() => Promise<void>) => {
    if (bench.rotate === undefined) throw new ConformanceSkip("the factory supplies no rotate capability");
    return bench.rotate;
  };

  add("generateDataKey returns a 32-byte key, a wrapped key, and a key reference within the limits", async (bench) => {
    equal(typeof bench.provider.profile === "string" && bench.provider.profile.length > 0, true, "profile is a non-empty string");
    const key = await generate(bench, bench.context());
    equal(key.plaintextKey.byteLength, LIMITS.dataKeyBytes, "the data key length");
    check(key.wrappedKey.byteLength >= 1 && key.wrappedKey.byteLength <= LIMITS.wrappedKeyMaxBytes, "the wrapped key is 1 to 4096 bytes");
    check(isKeyRef(key.keyRef), "the key reference is 1 to 512 bytes of well-formed text");
    check(!toHex(key.wrappedKey).includes(toHex(key.plaintextKey)), "the wrapped key does not contain the data key in clear");
  });

  add("two generated keys differ, for different contexts and for the same context", async (bench) => {
    const context = bench.context();
    const one = await generate(bench, context);
    const two = await generate(bench, context);
    const three = await generate(bench, bench.context());
    check(!sameBytes(one.plaintextKey, two.plaintextKey), "two data keys for one context differ");
    check(!sameBytes(one.plaintextKey, three.plaintextKey), "two data keys for two contexts differ");
    check(!sameBytes(one.wrappedKey, two.wrappedKey), "two wrapped keys differ");
  });

  add("unwrapDataKey returns the generated key, in a buffer of its own", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    const expected = new Uint8Array(key.plaintextKey);
    const first = await bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context });
    check(sameBytes(first, expected), "unwrapDataKey returns the data key that was generated");
    first.fill(0);
    key.plaintextKey.fill(0);
    const second = await bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context });
    check(sameBytes(second, expected), "overwriting a returned key does not change a later unwrap");
    second.fill(0);
  });

  add("unwrapDataKey with any in-scope KeyContext field changed fails KEY_INTEGRITY", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    const stored = { keyRef: key.keyRef, wrappedKey: key.wrappedKey };
    const changes: [string, KeyContext][] = [
      ["another captureId", { ...context, captureId: bench.rng.captureId() }],
      ["another tenant of the scope", { ...context, tenant: bench.scope.tenants[1] as string }],
      ["another namespace of the scope", { ...context, namespace: bench.scope.namespaces[1] as string }],
    ];
    for (const [label, changed] of changes) {
      await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ ...stored, context: changed }), "KEY_INTEGRITY", `unwrapDataKey with ${label}`);
      await throwsKeyError(bench, () => bench.provider.rewrapDataKey({ ...stored, context: changed }), "KEY_INTEGRITY", `rewrapDataKey with ${label}`);
    }
  });

  add("a context outside the provider's scope is KEY_UNAVAILABLE", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    const stored = { keyRef: key.keyRef, wrappedKey: key.wrappedKey };
    const outside = { ...context, namespace: freshNamespace() };
    await throwsKeyError(bench, () => bench.provider.generateDataKey(outside), "KEY_UNAVAILABLE", "generateDataKey for a namespace outside the scope");
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ ...stored, context: outside }), "KEY_UNAVAILABLE", "unwrapDataKey for a namespace outside the scope");
    await throwsKeyError(bench, () => bench.provider.rewrapDataKey({ ...stored, context: outside }), "KEY_UNAVAILABLE", "rewrapDataKey for a namespace outside the scope");
    // A provider that scopes tenants answers KEY_UNAVAILABLE; one that does not fails the context binding instead.
    const otherTenant = { ...context, tenant: "tenant-initech-synthetic" };
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ ...stored, context: otherTenant }), ["KEY_UNAVAILABLE", "KEY_INTEGRITY"], "unwrapDataKey for a tenant outside the scope");
  });

  add("an unknown key reference is KEY_UNAVAILABLE and is never tried under another key", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    for (const keyRef of [`${key.keyRef}-unknown-synthetic`, "unknown-synthetic-key-reference"]) {
      await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef, wrappedKey: key.wrappedKey, context }), "KEY_UNAVAILABLE", "unwrapDataKey with an unknown key reference");
      await throwsKeyError(bench, () => bench.provider.rewrapDataKey({ keyRef, wrappedKey: key.wrappedKey, context }), "KEY_UNAVAILABLE", "rewrapDataKey with an unknown key reference");
    }
  });

  add("a tampered wrapped key fails KEY_INTEGRITY", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    const length = key.wrappedKey.byteLength;
    for (const position of new Set([0, 1, Math.floor(length / 2), length - 1])) {
      const tampered = new Uint8Array(key.wrappedKey);
      tampered[position] = (tampered[position] as number) ^ 0x01;
      await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: tampered, context }), "KEY_INTEGRITY", "unwrapDataKey with one bit of the wrapped key changed");
    }
    if (length > 1) {
      const truncated = key.wrappedKey.slice(0, length - 1);
      await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: truncated, context }), ["KEY_INTEGRITY", "KEY_INVALID_ARGUMENT"], "unwrapDataKey with a truncated wrapped key");
    }
    const other = await generate(bench, context);
    check(!sameBytes(await bench.provider.unwrapDataKey({ keyRef: other.keyRef, wrappedKey: other.wrappedKey, context }), new Uint8Array(key.plaintextKey)), "another wrapped key of the same context unwraps to its own data key");
  });

  add("an input that violates the contract is KEY_INVALID_ARGUMENT", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    await throwsKeyError(bench, () => bench.provider.generateDataKey({ ...context, captureId: "capture-synthetic" }), "KEY_INVALID_ARGUMENT", "generateDataKey with a capture identifier outside the grammar");
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: new Uint8Array(0), context }), "KEY_INVALID_ARGUMENT", "unwrapDataKey with an empty wrapped key");
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: "", wrappedKey: key.wrappedKey, context }), "KEY_INVALID_ARGUMENT", "unwrapDataKey with an empty key reference");
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: new Uint8Array(LIMITS.wrappedKeyMaxBytes + 1), context }), "KEY_INVALID_ARGUMENT", "unwrapDataKey with a wrapped key over its limit");
  });

  add("rewrapDataKey returns another wrapping of the same data key", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    const rewrapped = await bench.provider.rewrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context });
    check(isKeyRef(rewrapped.keyRef), "the rewrapped key reference is within its limit");
    check(rewrapped.wrappedKey.byteLength >= 1 && rewrapped.wrappedKey.byteLength <= LIMITS.wrappedKeyMaxBytes, "the rewrapped key is within its limit");
    const unwrapped = await bench.provider.unwrapDataKey({ ...rewrapped, context });
    check(sameBytes(unwrapped, key.plaintextKey), "the rewrapped key unwraps to the same data key");
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ ...rewrapped, context: { ...context, captureId: bench.rng.captureId() } }), "KEY_INTEGRITY", "unwrapDataKey of a rewrapped key under another context");
    check(sameBytes(await bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context }), key.plaintextKey), "the original wrapping still unwraps");
  });

  add("after rotation old wrapped keys still unwrap, new keys use the new reference, and a rewrap survives", async (bench) => {
    const rotate = rotation(bench);
    const context = bench.context();
    const old = await generate(bench, context);
    await rotate();
    check(sameBytes(await bench.provider.unwrapDataKey({ keyRef: old.keyRef, wrappedKey: old.wrappedKey, context }), old.plaintextKey), "a key wrapped before rotation still unwraps");
    const fresh = await generate(bench, bench.context());
    check(fresh.keyRef !== old.keyRef, "a key generated after rotation names the new wrapping key version");
    const moved = await bench.provider.rewrapDataKey({ keyRef: old.keyRef, wrappedKey: old.wrappedKey, context });
    equal(moved.keyRef, fresh.keyRef, "a rewrap after rotation uses the active wrapping key version");
    check(sameBytes(await bench.provider.unwrapDataKey({ ...moved, context }), old.plaintextKey), "the rewrapped key unwraps to the same data key");
    await rotate();
    check(sameBytes(await bench.provider.unwrapDataKey({ ...moved, context }), old.plaintextKey), "the rewrapped key survives another rotation");
  });

  add("a retired wrapping key version is KEY_UNAVAILABLE, and a key rewrapped before retirement survives", async (bench) => {
    const rotate = rotation(bench);
    if (bench.retire === undefined) throw new ConformanceSkip("the factory supplies no retire capability");
    const context = bench.context();
    const kept = await generate(bench, context);
    const lostContext = bench.context();
    const lost = await generate(bench, lostContext);
    await rotate();
    const moved = await bench.provider.rewrapDataKey({ keyRef: kept.keyRef, wrappedKey: kept.wrappedKey, context });
    await bench.retire(lost.keyRef);
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: lost.keyRef, wrappedKey: lost.wrappedKey, context: lostContext }), "KEY_UNAVAILABLE", "unwrapDataKey under a retired version");
    await throwsKeyError(bench, () => bench.provider.rewrapDataKey({ keyRef: lost.keyRef, wrappedKey: lost.wrappedKey, context: lostContext }), "KEY_UNAVAILABLE", "rewrapDataKey under a retired version");
    check(sameBytes(await bench.provider.unwrapDataKey({ ...moved, context }), kept.plaintextKey), "a key rewrapped before the retirement still unwraps");
  });

  add("an already aborted signal is KEY_ABORTED", async (bench) => {
    const context = bench.context();
    const key = await generate(bench, context);
    const controller = new AbortController();
    controller.abort();
    const aborted = { signal: controller.signal };
    await throwsKeyError(bench, () => bench.provider.generateDataKey(bench.context(), aborted), "KEY_ABORTED", "generateDataKey with an aborted signal");
    await throwsKeyError(bench, () => bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context }, aborted), "KEY_ABORTED", "unwrapDataKey with an aborted signal");
    await throwsKeyError(bench, () => bench.provider.rewrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context }, aborted), "KEY_ABORTED", "rewrapDataKey with an aborted signal");
    const live = new AbortController();
    check(sameBytes(await bench.provider.unwrapDataKey({ keyRef: key.keyRef, wrappedKey: key.wrappedKey, context }, { signal: live.signal }), key.plaintextKey), "a signal that is not aborted does not fail the call");
  });

  return cases;
}
