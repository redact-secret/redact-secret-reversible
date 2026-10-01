/**
 * `RecordCrypto` over a `KeyProvider`: one data key per capture, one derived
 * AES-256-GCM key per entry, one random nonce per encryption (§3.3).
 */
import {
  isCaptureId,
  isIdentifier,
  isKeyRef,
  isNamespace,
  type KeyCallOptions,
  type KeyContext,
  type KeyProvider,
  KeyProviderError,
  LIMITS,
  type OpenCaptureInput,
  type RecordBinding,
  type RecordCrypto,
  RecordCryptoError,
  type RecordCryptoErrorCode,
  type RecordPayload,
  type SealCaptureInput,
  type SealedCapture,
  type StoredKey,
} from "@redact-secret/vault-contracts";
import { type Bytes, fail, isBytes, view, webcrypto, zero } from "./bytes.js";
import {
  type DecodedEnvelope,
  decodePayload,
  encodeAad,
  encodeEnvelope,
  NONCE_BYTES,
  type PayloadPlan,
  parseEnvelope,
  planPayload,
  snapshotBinding,
  TAG_BYTES,
  writePayload,
} from "./codec.js";
import { deriveEntryKeyFrom, importDataKey } from "./derive.js";
import {
  callProvider,
  checkDataKey,
  checkPlaintextKey,
  checkStoredKey,
  discardDataKey,
  discardPlaintextKey,
  readSignal,
} from "./provider-call.js";

export const RECORD_CRYPTO_PROFILE = "aes-256-gcm-hkdf-v1";
export const DEFAULT_KEY_TIMEOUT_MS = 5000;
const MAX_KEY_TIMEOUT_MS = 2_147_483_647;

export interface RecordCryptoOptions {
  readonly keyProvider: KeyProvider;
  /** Upper bound of one provider call, in milliseconds. Default 5000. */
  readonly keyTimeoutMs?: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** Our own errors are rebuilt from their code; anything else becomes `fallback`. Nothing foreign is rethrown. */
function sanitize(error: unknown, fallback: RecordCryptoErrorCode): Error {
  if (error instanceof RecordCryptoError) return new RecordCryptoError(error.code);
  if (error instanceof KeyProviderError) return new KeyProviderError(error.code);
  return new RecordCryptoError(fallback);
}

function snapshotContext(context: unknown): KeyContext {
  if (!isObject(context)) fail("RECORD_INVALID_ARGUMENT");
  const { namespace, tenant, captureId } = context;
  if (!isNamespace(namespace) || !isIdentifier(tenant) || !isCaptureId(captureId)) fail("RECORD_INVALID_ARGUMENT");
  return Object.freeze({ namespace, tenant, captureId });
}

function snapshotStoredKey(input: Record<string, unknown>): StoredKey {
  const { keyRef, wrappedKey } = input;
  if (!isKeyRef(keyRef) || !isBytes(wrappedKey)) fail("RECORD_INVALID_ARGUMENT");
  if (wrappedKey.byteLength === 0) fail("RECORD_INVALID_ARGUMENT");
  if (wrappedKey.byteLength > LIMITS.wrappedKeyMaxBytes) fail("RECORD_LIMIT");
  return { keyRef, wrappedKey: wrappedKey.slice() };
}

interface Bound {
  readonly binding: RecordBinding;
  readonly aad: Bytes;
}

/** Validates the bindings of one capture: each inside `context`, no entry twice. */
function bindRecords(context: KeyContext, records: unknown, ceiling: number): { bound: Bound[]; items: unknown[] } {
  if (!Array.isArray(records) || records.length === 0) fail("RECORD_INVALID_ARGUMENT");
  if (records.length > ceiling) fail("RECORD_LIMIT");
  const items = records.slice() as unknown[];
  const seen = new Set<string>();
  const bound = items.map((record) => {
    if (!isObject(record)) fail("RECORD_INVALID_ARGUMENT");
    const binding = snapshotBinding(record.binding);
    if (
      binding.namespace !== context.namespace ||
      binding.tenant !== context.tenant ||
      binding.captureId !== context.captureId ||
      seen.has(binding.entryId)
    ) {
      fail("RECORD_INVALID_ARGUMENT");
    }
    seen.add(binding.entryId);
    return { binding, aad: encodeAad(binding) };
  });
  return { bound, items };
}

function zeroPayloads(payloads: readonly RecordPayload[]): void {
  for (const payload of payloads) zero(payload.value);
}

/**
 * A `RecordCrypto` of profile `aes-256-gcm-hkdf-v1`. The provider is called
 * once per `sealCapture`, once per `openCapture`, and once per
 * `rewrapCaptureKey`; no key is cached between calls.
 */
export function createRecordCrypto(options: RecordCryptoOptions): RecordCrypto {
  if (!isObject(options)) fail("RECORD_INVALID_ARGUMENT");
  const provider = options.keyProvider;
  if (
    !isObject(provider) ||
    typeof provider.generateDataKey !== "function" ||
    typeof provider.unwrapDataKey !== "function" ||
    typeof provider.rewrapDataKey !== "function"
  ) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  const timeoutMs = options.keyTimeoutMs ?? DEFAULT_KEY_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_KEY_TIMEOUT_MS) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  const platform = webcrypto();
  const subtle = platform.subtle;

  async function sealCapture(input: SealCaptureInput, callOptions?: KeyCallOptions): Promise<SealedCapture> {
    const signal = readSignal(callOptions);
    if (!isObject(input)) fail("RECORD_INVALID_ARGUMENT");
    const context = snapshotContext(input.context);
    const { bound, items } = bindRecords(context, input.records, LIMITS.maxCreateEntries);
    const plans: PayloadPlan[] = items.map((record) => planPayload((record as { payload?: unknown }).payload));

    const dataKey = await callProvider(
      (keyOptions) => provider.generateDataKey(context, keyOptions),
      checkDataKey,
      discardDataKey,
      signal,
      timeoutMs,
    );
    try {
      const base = await importDataKey(dataKey.plaintextKey);
      const envelopes: Uint8Array[] = [];
      for (let i = 0; i < bound.length; i += 1) {
        const { binding, aad } = bound[i] as Bound;
        const key = await deriveEntryKeyFrom(base, binding.entryId);
        const nonce = platform.getRandomValues(new Uint8Array(NONCE_BYTES));
        const payload = writePayload(plans[i] as PayloadPlan);
        try {
          const sealed = await subtle.encrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: TAG_BYTES * 8 },
            key,
            payload,
          );
          envelopes.push(encodeEnvelope({ nonce, ciphertext: new Uint8Array(sealed) }));
        } finally {
          zero(payload);
        }
      }
      return Object.freeze({
        keyRef: dataKey.keyRef,
        wrappedKey: dataKey.wrappedKey,
        envelopes: Object.freeze(envelopes),
      });
    } catch (error) {
      throw sanitize(error, "RECORD_UNSUPPORTED");
    } finally {
      zero(dataKey.plaintextKey);
    }
  }

  async function openCapture(
    input: OpenCaptureInput,
    callOptions?: KeyCallOptions,
  ): Promise<readonly RecordPayload[]> {
    const signal = readSignal(callOptions);
    if (!isObject(input)) fail("RECORD_INVALID_ARGUMENT");
    const context = snapshotContext(input.context);
    const stored = snapshotStoredKey(input);
    const { bound, items } = bindRecords(context, input.records, LIMITS.maxRestoreEntries);
    // Every envelope is decoded, and its version and algorithm checked, before any key is unwrapped.
    const envelopes: DecodedEnvelope[] = items.map((record) =>
      parseEnvelope((record as { envelope?: unknown }).envelope),
    );

    const dek = await callProvider(
      (keyOptions) => provider.unwrapDataKey({ ...stored, context }, keyOptions),
      checkPlaintextKey,
      discardPlaintextKey,
      signal,
      timeoutMs,
    );
    const opened: RecordPayload[] = [];
    try {
      const base = await importDataKey(dek);
      for (let i = 0; i < bound.length; i += 1) {
        const { binding, aad } = bound[i] as Bound;
        const envelope = envelopes[i] as DecodedEnvelope;
        const key = await deriveEntryKeyFrom(base, binding.entryId);
        let plaintext: Bytes;
        try {
          plaintext = new Uint8Array(
            await subtle.decrypt(
              { name: "AES-GCM", iv: view(envelope.nonce), additionalData: aad, tagLength: TAG_BYTES * 8 },
              key,
              view(envelope.ciphertext),
            ),
          );
        } catch {
          return fail("RECORD_INTEGRITY");
        }
        try {
          opened.push(decodePayload(plaintext));
        } finally {
          zero(plaintext);
        }
      }
      return Object.freeze(opened);
    } catch (error) {
      zeroPayloads(opened);
      opened.length = 0;
      throw sanitize(error, "RECORD_INTEGRITY");
    } finally {
      zero(dek);
    }
  }

  async function rewrapCaptureKey(
    input: StoredKey & { readonly context: KeyContext },
    callOptions?: KeyCallOptions,
  ): Promise<StoredKey> {
    const signal = readSignal(callOptions);
    if (!isObject(input)) fail("RECORD_INVALID_ARGUMENT");
    const context = snapshotContext(input.context);
    const stored = snapshotStoredKey(input);
    return callProvider(
      (keyOptions) => provider.rewrapDataKey({ ...stored, context }, keyOptions),
      checkStoredKey,
      () => undefined,
      signal,
      timeoutMs,
    );
  }

  return Object.freeze({ profile: RECORD_CRYPTO_PROFILE, sealCapture, openCapture, rewrapCaptureKey });
}
