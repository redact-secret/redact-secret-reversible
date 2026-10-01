/**
 * `createInsecureTestKeyProvider`: the deterministic key provider of
 * docs/specs/persistent-vault.md §6.3, for vectors and tests only.
 *
 * Every data key and every wrapped key is a function of the seed and a call
 * counter. Anyone who knows the seed can derive every key. It must never
 * protect real data, and it refuses to construct without the exact
 * acknowledgement string.
 */
import { isCaptureId, isIdentifier, isKeyRef, isNamespace, KeyProviderError, LIMITS } from "@redact-secret/vault-contracts";
import type { DataKey, KeyCallOptions, KeyContext, KeyProvider, StoredKey } from "@redact-secret/vault-contracts";

export interface InsecureTestKeyProviderOptions {
  /** Must be exactly "test-only". */
  readonly acknowledgeInsecure: "test-only";
  /** Any non-empty string or byte array. The same seed and call order give the same keys. */
  readonly seed: string | Uint8Array;
  /** Namespaces and tenants the provider serves. An omitted list serves any. */
  readonly scope?: { readonly namespaces?: readonly string[]; readonly tenants?: readonly string[] };
}

export interface InsecureTestKeyProviderControl {
  /** Makes a new wrapping key version active and the previous one decrypt-only. Returns the new `keyRef`. */
  rotate(): string;
  /** Retires the version `keyRef` names. Retiring the active version leaves no active version until `rotate`. */
  retire(keyRef: string): void;
  /** The `keyRef` of the active version, or null when it was retired. */
  activeKeyRef(): string | null;
}

export type InsecureTestKeyProvider = KeyProvider & { readonly control: InsecureTestKeyProviderControl };

const KEY_REF_PREFIX = "insecure-test:v";
const WRAP_FORMAT = 0x7f;
const NONCE_BYTES = 16;
const MAC_BYTES = 32;
const WRAPPED_BYTES = 1 + NONCE_BYTES + LIMITS.dataKeyBytes + MAC_BYTES;

type Bytes = Uint8Array<ArrayBuffer>;

function utf8(text: string): Bytes {
  return new Uint8Array(new TextEncoder().encode(text));
}

function concat(...parts: readonly Uint8Array[]): Bytes {
  let length = 0;
  for (const part of parts) length += part.byteLength;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function u32(value: number): Bytes {
  return new Uint8Array([(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]);
}

function lp16(text: string): Bytes {
  const bytes = utf8(text);
  return concat(new Uint8Array([(bytes.byteLength >>> 8) & 255, bytes.byteLength & 255]), bytes);
}

async function hmac(key: Uint8Array, ...parts: readonly Uint8Array[]): Promise<Bytes> {
  const imported = await crypto.subtle.importKey("raw", new Uint8Array(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, concat(...parts)));
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i += 1) difference |= (a[i] as number) ^ (b[i] as number);
  return difference === 0;
}

function validContext(context: unknown): context is KeyContext {
  if (typeof context !== "object" || context === null) return false;
  const c = context as Partial<KeyContext>;
  return isNamespace(c.namespace) && isIdentifier(c.tenant) && isCaptureId(c.captureId);
}

/**
 * Creates the insecure deterministic test provider. It throws unless
 * `acknowledgeInsecure` is exactly `"test-only"`.
 */
export function createInsecureTestKeyProvider(options: InsecureTestKeyProviderOptions): InsecureTestKeyProvider {
  if (typeof options !== "object" || options === null || options.acknowledgeInsecure !== "test-only") {
    throw new TypeError('createInsecureTestKeyProvider: pass { acknowledgeInsecure: "test-only" }. This provider must never protect real data.');
  }
  const given = options.seed;
  const seedBytes = typeof given === "string" ? utf8(given) : given instanceof Uint8Array ? new Uint8Array(given) : null;
  if (seedBytes === null || seedBytes.byteLength === 0) {
    throw new TypeError("createInsecureTestKeyProvider: seed must be a non-empty string or byte array.");
  }
  const seed: Bytes = seedBytes;
  const namespaces = options.scope?.namespaces === undefined ? null : new Set(options.scope.namespaces);
  const tenants = options.scope?.tenants === undefined ? null : new Set(options.scope.tenants);

  const versions = new Map<number, "active" | "decrypt-only" | "retired">([[1, "active"]]);
  let latest = 1;
  let counter = 0;

  const keyRefOf = (version: number): string => `${KEY_REF_PREFIX}${version}`;
  const versionOf = (keyRef: string): number | null => {
    if (!keyRef.startsWith(KEY_REF_PREFIX)) return null;
    const digits = keyRef.slice(KEY_REF_PREFIX.length);
    if (!/^[1-9][0-9]{0,8}$/.test(digits)) return null;
    const version = Number(digits);
    return versions.has(version) ? version : null;
  };
  const activeVersion = (): number | null => {
    for (const [version, state] of versions) if (state === "active") return version;
    return null;
  };

  function guard(options: KeyCallOptions | undefined): void {
    if (options?.signal?.aborted === true) throw new KeyProviderError("KEY_ABORTED");
  }

  function inScope(context: KeyContext): boolean {
    return (namespaces === null || namespaces.has(context.namespace)) && (tenants === null || tenants.has(context.tenant));
  }

  function contextBytes(context: KeyContext): Bytes {
    return concat(lp16(context.namespace), lp16(context.tenant), lp16(context.captureId));
  }

  const wrapKey = (version: number): Promise<Bytes> => hmac(seed, utf8("rsv-insecure-test/wrap-key"), u32(version));

  async function wrap(version: number, context: KeyContext, key: Uint8Array, index: number): Promise<Bytes> {
    const wrapping = await wrapKey(version);
    const nonce = (await hmac(seed, utf8("rsv-insecure-test/nonce"), u32(index))).slice(0, NONCE_BYTES);
    const bound = contextBytes(context);
    const pad = await hmac(wrapping, new Uint8Array([1]), nonce, bound);
    const sealed = new Uint8Array(LIMITS.dataKeyBytes);
    for (let i = 0; i < sealed.byteLength; i += 1) sealed[i] = (key[i] as number) ^ (pad[i] as number);
    const tag = await hmac(wrapping, new Uint8Array([2]), nonce, bound, sealed);
    return concat(new Uint8Array([WRAP_FORMAT]), nonce, sealed, tag);
  }

  async function unwrap(input: StoredKey & { readonly context: KeyContext }, options: KeyCallOptions | undefined): Promise<Bytes> {
    guard(options);
    if (typeof input !== "object" || input === null || !validContext(input.context) || !isKeyRef(input.keyRef)) {
      throw new KeyProviderError("KEY_INVALID_ARGUMENT");
    }
    if (!(input.wrappedKey instanceof Uint8Array) || input.wrappedKey.byteLength < 1 || input.wrappedKey.byteLength > LIMITS.wrappedKeyMaxBytes) {
      throw new KeyProviderError("KEY_INVALID_ARGUMENT");
    }
    const context: KeyContext = { namespace: input.context.namespace, tenant: input.context.tenant, captureId: input.context.captureId };
    const wrapped = new Uint8Array(input.wrappedKey);
    if (!inScope(context)) throw new KeyProviderError("KEY_UNAVAILABLE");
    const version = versionOf(input.keyRef);
    // Exactly the version the reference names; never another one.
    if (version === null || versions.get(version) === "retired") throw new KeyProviderError("KEY_UNAVAILABLE");
    if (wrapped.byteLength !== WRAPPED_BYTES || wrapped[0] !== WRAP_FORMAT) throw new KeyProviderError("KEY_INTEGRITY");
    const nonce = wrapped.slice(1, 1 + NONCE_BYTES);
    const sealed = wrapped.slice(1 + NONCE_BYTES, 1 + NONCE_BYTES + LIMITS.dataKeyBytes);
    const tag = wrapped.slice(1 + NONCE_BYTES + LIMITS.dataKeyBytes);
    const wrapping = await wrapKey(version);
    const bound = contextBytes(context);
    const expected = await hmac(wrapping, new Uint8Array([2]), nonce, bound, sealed);
    guard(options);
    if (!constantTimeEqual(expected, tag)) throw new KeyProviderError("KEY_INTEGRITY");
    const pad = await hmac(wrapping, new Uint8Array([1]), nonce, bound);
    const key = new Uint8Array(LIMITS.dataKeyBytes);
    for (let i = 0; i < key.byteLength; i += 1) key[i] = (sealed[i] as number) ^ (pad[i] as number);
    guard(options);
    return key;
  }

  const control: InsecureTestKeyProviderControl = {
    rotate() {
      const current = activeVersion();
      if (current !== null) versions.set(current, "decrypt-only");
      latest += 1;
      versions.set(latest, "active");
      return keyRefOf(latest);
    },
    retire(keyRef) {
      const version = typeof keyRef === "string" ? versionOf(keyRef) : null;
      if (version === null) throw new TypeError("retire: unknown keyRef.");
      versions.set(version, "retired");
    },
    activeKeyRef() {
      const current = activeVersion();
      return current === null ? null : keyRefOf(current);
    },
  };

  return {
    profile: "insecure-test-only",
    control: Object.freeze(control),

    async generateDataKey(context: KeyContext, options?: KeyCallOptions): Promise<DataKey> {
      guard(options);
      if (!validContext(context)) throw new KeyProviderError("KEY_INVALID_ARGUMENT");
      const bound: KeyContext = { namespace: context.namespace, tenant: context.tenant, captureId: context.captureId };
      if (!inScope(bound)) throw new KeyProviderError("KEY_UNAVAILABLE");
      const version = activeVersion();
      if (version === null) throw new KeyProviderError("KEY_UNAVAILABLE");
      counter += 1;
      const index = counter;
      const plaintextKey = await hmac(seed, utf8("rsv-insecure-test/dek"), u32(index));
      const wrappedKey = await wrap(version, bound, plaintextKey, index);
      guard(options);
      return { plaintextKey, wrappedKey, keyRef: keyRefOf(version) };
    },

    unwrapDataKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<Uint8Array> {
      return unwrap(input, options);
    },

    async rewrapDataKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<StoredKey> {
      const key = await unwrap(input, options);
      const context: KeyContext = { namespace: input.context.namespace, tenant: input.context.tenant, captureId: input.context.captureId };
      try {
        const version = activeVersion();
        if (version === null) throw new KeyProviderError("KEY_UNAVAILABLE");
        counter += 1;
        const wrappedKey = await wrap(version, context, key, counter);
        guard(options);
        return { keyRef: keyRefOf(version), wrappedKey };
      } finally {
        key.fill(0);
      }
    },
  };
}
