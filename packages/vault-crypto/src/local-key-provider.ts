/**
 * The local key provider of docs/specs/persistent-vault.md §6.3: a
 * `KeyProvider` over key material the application injects.
 *
 * Limits, restated from the specification: the material is in process
 * memory; anyone who obtains it and a copy of the store can decrypt every
 * capture wrapped under it; every wrapping key derives from one material, so
 * retiring that material makes every capture under it unreadable; there is
 * no per-tenant or per-capture erasure. The provider does not load, store,
 * or rotate material, reads no environment variable, has no default key and
 * no passphrase path, and caches no unwrapped key.
 */
import {
  type DataKey,
  isCaptureId,
  isIdentifier,
  isNamespace,
  type KeyCallOptions,
  type KeyContext,
  type KeyProvider,
  KeyProviderError,
  type KeyProviderErrorCode,
  LIMITS,
  type StoredKey,
} from "@redact-secret/vault-contracts";

export const LOCAL_KEY_PROVIDER_PROFILE = "local-hkdf-aes-256-gcm-v1";
/** Leading byte of a wrapped key. */
export const LOCAL_WRAP_VERSION = 1;

const KEY_REF_PREFIX = "local:";
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const MATERIAL_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const WRAPPED_BYTES = 1 + NONCE_BYTES + LIMITS.dataKeyBytes + TAG_BYTES;
const ZERO_SALT = new Uint8Array(32);
const LABEL = "rsv-local-wrap-v1";

export type LocalKeyState = "active" | "decrypt-only" | "retired";

export interface LocalKey {
  /** 1 to 64 characters of `[A-Za-z0-9._-]`. The key reference is `local:<id>`. */
  readonly id: string;
  /** 32 bytes, or a non-extractable HKDF `CryptoKey` with the `deriveKey` usage. */
  readonly material: Uint8Array | CryptoKey;
  readonly state: LocalKeyState;
}

export interface LocalKeyProviderOptions {
  /** Exactly one key is `active`. */
  readonly keys: readonly LocalKey[];
  /** The namespaces, and optionally the tenants, this provider may serve. Required. */
  readonly scope: { readonly namespaces: readonly string[]; readonly tenants?: readonly string[] };
}

function fail(code: KeyProviderErrorCode): never {
  throw new KeyProviderError(code);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isCryptoKey(value: unknown): value is CryptoKey {
  const platformKey = (globalThis as { CryptoKey?: typeof CryptoKey }).CryptoKey;
  return typeof platformKey === "function" && value instanceof platformKey;
}

function isHkdfKey(key: CryptoKey): boolean {
  return (
    key.type === "secret" && key.extractable === false && key.algorithm.name === "HKDF" && key.usages.includes("deriveKey")
  );
}

function lp16(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(2 + bytes.byteLength);
  out[0] = (bytes.byteLength >>> 8) & 0xff;
  out[1] = bytes.byteLength & 0xff;
  out.set(bytes, 2);
  return out;
}

/** `"rsv-local-wrap-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(captureId)`. */
function wrapInfo(context: KeyContext): Uint8Array<ArrayBuffer> {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(LABEL),
    Uint8Array.of(0),
    lp16(encoder.encode(context.namespace)),
    lp16(encoder.encode(context.tenant)),
    lp16(encoder.encode(context.captureId)),
  ];
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function snapshotContext(context: unknown): KeyContext {
  if (!isObject(context)) fail("KEY_INVALID_ARGUMENT");
  const { namespace, tenant, captureId } = context;
  // isIdentifier tests well-formedness, so the encoder below never substitutes U+FFFD.
  if (!isNamespace(namespace) || !isIdentifier(tenant) || !isCaptureId(captureId)) fail("KEY_INVALID_ARGUMENT");
  return { namespace, tenant, captureId };
}

function readSignal(options: unknown): AbortSignal | undefined {
  if (options === undefined) return undefined;
  if (!isObject(options)) fail("KEY_INVALID_ARGUMENT");
  const signal = (options as KeyCallOptions).signal;
  if (signal === undefined) return undefined;
  if (!isObject(signal) || typeof signal.aborted !== "boolean") fail("KEY_INVALID_ARGUMENT");
  return signal;
}

function checkAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) fail("KEY_ABORTED");
}

interface HeldKey {
  readonly id: string;
  readonly state: "active" | "decrypt-only";
  readonly base: Promise<CryptoKey>;
}

/**
 * Builds the provider. Throws `KEY_INVALID_ARGUMENT` unless the options name
 * exactly one active key, unique identifiers, usable material, and an
 * explicit scope. Byte material is copied and imported as a non-extractable
 * HKDF key; the caller's array is not retained and may be overwritten.
 */
export function createLocalKeyProvider(options: LocalKeyProviderOptions): KeyProvider {
  const candidate = (globalThis as { crypto?: Crypto }).crypto;
  if (candidate === undefined || candidate.subtle === undefined || typeof candidate.getRandomValues !== "function") {
    fail("KEY_UNAVAILABLE");
  }
  const platform: Crypto = candidate;
  const subtle = platform.subtle;

  if (!isObject(options) || !isObject(options.scope)) fail("KEY_INVALID_ARGUMENT");
  const { namespaces, tenants } = options.scope;
  if (!Array.isArray(namespaces) || namespaces.length === 0 || !namespaces.every(isNamespace)) {
    fail("KEY_INVALID_ARGUMENT");
  }
  if (tenants !== undefined && (!Array.isArray(tenants) || tenants.length === 0 || !tenants.every(isIdentifier))) {
    fail("KEY_INVALID_ARGUMENT");
  }
  const allowedNamespaces: ReadonlySet<string> = new Set(namespaces as readonly string[]);
  const allowedTenants: ReadonlySet<string> | null = tenants === undefined ? null : new Set(tenants as string[]);

  if (!Array.isArray(options.keys) || options.keys.length === 0) fail("KEY_INVALID_ARGUMENT");
  // Validate every key before importing any, so a rejected configuration imports nothing.
  const declared = new Map<string, { state: LocalKeyState; material: Uint8Array | CryptoKey }>();
  let activeId: string | undefined;
  for (const key of options.keys as readonly unknown[]) {
    if (!isObject(key) || typeof key.id !== "string" || !KEY_ID.test(key.id) || declared.has(key.id)) {
      fail("KEY_INVALID_ARGUMENT");
    }
    const { state, material } = key;
    if (state !== "active" && state !== "decrypt-only" && state !== "retired") fail("KEY_INVALID_ARGUMENT");
    if (material instanceof Uint8Array) {
      if (material.byteLength !== MATERIAL_BYTES) fail("KEY_INVALID_ARGUMENT");
    } else if (!isCryptoKey(material) || !isHkdfKey(material)) {
      fail("KEY_INVALID_ARGUMENT");
    }
    if (state === "active") {
      if (activeId !== undefined) fail("KEY_INVALID_ARGUMENT");
      activeId = key.id;
    }
    declared.set(key.id, { state, material });
  }
  if (activeId === undefined) fail("KEY_INVALID_ARGUMENT");
  const active: string = activeId;

  const held = new Map<string, HeldKey>();
  for (const [id, { state, material }] of declared) {
    // A retired key neither wraps nor unwraps: its material is not imported or kept.
    if (state === "retired") continue;
    let base: Promise<CryptoKey>;
    if (material instanceof Uint8Array) {
      const copy = material.slice();
      base = subtle.importKey("raw", copy, "HKDF", false, ["deriveKey"]).finally(() => copy.fill(0));
      // An import failure surfaces as KEY_UNAVAILABLE on first use, not as an unhandled rejection.
      base.catch(() => undefined);
    } else {
      base = Promise.resolve(material);
    }
    held.set(id, { id, state, base });
  }

  function inScope(context: KeyContext): boolean {
    return allowedNamespaces.has(context.namespace) && (allowedTenants === null || allowedTenants.has(context.tenant));
  }

  async function wrappingKey(key: HeldKey, context: KeyContext, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info: wrapInfo(context) },
      await key.base,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  }

  async function wrap(dek: Uint8Array<ArrayBuffer>, context: KeyContext): Promise<StoredKey> {
    const key = held.get(active) as HeldKey;
    try {
      const nonce = platform.getRandomValues(new Uint8Array(NONCE_BYTES));
      const sealed = new Uint8Array(
        await subtle.encrypt(
          { name: "AES-GCM", iv: nonce, tagLength: TAG_BYTES * 8 },
          await wrappingKey(key, context, "encrypt"),
          dek,
        ),
      );
      const wrappedKey = new Uint8Array(WRAPPED_BYTES);
      wrappedKey[0] = LOCAL_WRAP_VERSION;
      wrappedKey.set(nonce, 1);
      wrappedKey.set(sealed, 1 + NONCE_BYTES);
      return { keyRef: KEY_REF_PREFIX + key.id, wrappedKey };
    } catch {
      return fail("KEY_UNAVAILABLE");
    }
  }

  function snapshotStored(input: unknown): { keyRef: string; wrappedKey: Uint8Array<ArrayBuffer>; context: KeyContext } {
    if (!isObject(input)) fail("KEY_INVALID_ARGUMENT");
    const { keyRef, wrappedKey } = input;
    if (typeof keyRef !== "string" || !(wrappedKey instanceof Uint8Array)) fail("KEY_INVALID_ARGUMENT");
    if (wrappedKey.byteLength > LIMITS.wrappedKeyMaxBytes) fail("KEY_INVALID_ARGUMENT");
    return { keyRef, wrappedKey: wrappedKey.slice(), context: snapshotContext(input.context) };
  }

  /** Unwraps with exactly the key `keyRef` names. Never tries another key. */
  async function unwrap(
    input: { keyRef: string; wrappedKey: Uint8Array<ArrayBuffer>; context: KeyContext },
    signal: AbortSignal | undefined,
  ): Promise<Uint8Array<ArrayBuffer>> {
    const { keyRef, wrappedKey, context } = input;
    if (!inScope(context)) fail("KEY_UNAVAILABLE");
    const key = keyRef.startsWith(KEY_REF_PREFIX) ? held.get(keyRef.slice(KEY_REF_PREFIX.length)) : undefined;
    if (key === undefined) fail("KEY_UNAVAILABLE");
    if (wrappedKey.byteLength !== WRAPPED_BYTES || wrappedKey[0] !== LOCAL_WRAP_VERSION) fail("KEY_INTEGRITY");
    let derived: CryptoKey;
    try {
      derived = await wrappingKey(key, context, "decrypt");
    } catch {
      return fail("KEY_UNAVAILABLE");
    }
    checkAborted(signal);
    let dek: Uint8Array<ArrayBuffer>;
    try {
      dek = new Uint8Array(
        await subtle.decrypt(
          { name: "AES-GCM", iv: wrappedKey.subarray(1, 1 + NONCE_BYTES), tagLength: TAG_BYTES * 8 },
          derived,
          wrappedKey.subarray(1 + NONCE_BYTES),
        ),
      );
    } catch {
      return fail("KEY_INTEGRITY");
    }
    if (signal?.aborted === true) {
      dek.fill(0);
      fail("KEY_ABORTED");
    }
    return dek;
  }

  const provider: KeyProvider = {
    profile: LOCAL_KEY_PROVIDER_PROFILE,

    async generateDataKey(context: KeyContext, callOptions?: KeyCallOptions): Promise<DataKey> {
      const signal = readSignal(callOptions);
      checkAborted(signal);
      const snapshot = snapshotContext(context);
      if (!inScope(snapshot)) fail("KEY_UNAVAILABLE");
      const plaintextKey = platform.getRandomValues(new Uint8Array(LIMITS.dataKeyBytes));
      try {
        const stored = await wrap(plaintextKey, snapshot);
        checkAborted(signal);
        return { ...stored, plaintextKey };
      } catch (error) {
        plaintextKey.fill(0);
        throw error;
      }
    },

    async unwrapDataKey(
      input: StoredKey & { readonly context: KeyContext },
      callOptions?: KeyCallOptions,
    ): Promise<Uint8Array> {
      const signal = readSignal(callOptions);
      checkAborted(signal);
      return unwrap(snapshotStored(input), signal);
    },

    async rewrapDataKey(
      input: StoredKey & { readonly context: KeyContext },
      callOptions?: KeyCallOptions,
    ): Promise<StoredKey> {
      const signal = readSignal(callOptions);
      checkAborted(signal);
      const stored = snapshotStored(input);
      const dek = await unwrap(stored, signal);
      try {
        const rewrapped = await wrap(dek, stored.context);
        checkAborted(signal);
        return rewrapped;
      } finally {
        dek.fill(0);
      }
    },
  };
  return Object.freeze(provider);
}
