/**
 * The only way this package calls a `KeyProvider` (§6.1). A call is bounded
 * by a timeout, follows the caller's `AbortSignal`, and can only end in a
 * validated result or a freshly built `KeyProviderError`: a provider's own
 * exception, its message, and its stack never pass through.
 */
import {
  type DataKey,
  isKeyRef,
  type KeyCallOptions,
  KeyProviderError,
  type KeyProviderErrorCode,
  LIMITS,
  type StoredKey,
} from "@redact-secret/vault-contracts";
import { isBytes, zero } from "./bytes.js";

const KEY_CODES: ReadonlySet<string> = new Set<KeyProviderErrorCode>([
  "KEY_UNAVAILABLE",
  "KEY_INTEGRITY",
  "KEY_TIMEOUT",
  "KEY_THROTTLED",
  "KEY_ABORTED",
  "KEY_INVALID_ARGUMENT",
]);

/** A new error carrying only the code. Anything that is not a `KeyProviderError` is `KEY_UNAVAILABLE`. */
function sanitize(error: unknown): KeyProviderError {
  if (error instanceof KeyProviderError && KEY_CODES.has(error.code)) return new KeyProviderError(error.code);
  return new KeyProviderError("KEY_UNAVAILABLE");
}

/** The caller's signal, or `KEY_INVALID_ARGUMENT` when `options` is not a `KeyCallOptions`. */
export function readSignal(options: unknown): AbortSignal | undefined {
  if (options === undefined) return undefined;
  if (typeof options !== "object" || options === null) throw new KeyProviderError("KEY_INVALID_ARGUMENT");
  const signal = (options as KeyCallOptions).signal;
  if (signal === undefined) return undefined;
  if (
    typeof signal !== "object" ||
    signal === null ||
    typeof signal.aborted !== "boolean" ||
    typeof signal.addEventListener !== "function" ||
    typeof signal.removeEventListener !== "function"
  ) {
    throw new KeyProviderError("KEY_INVALID_ARGUMENT");
  }
  return signal;
}

/**
 * Runs one provider call. `check` validates and returns the result; `discard`
 * overwrites key bytes in a result that is rejected or arrives after the call
 * was already given up.
 */
export async function callProvider<T>(
  invoke: (options: KeyCallOptions) => Promise<T>,
  check: (result: unknown) => T | undefined,
  discard: (result: unknown) => void,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<T> {
  if (signal?.aborted === true) throw new KeyProviderError("KEY_ABORTED");
  const controller = new AbortController();
  let abandoned = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;

  const interrupted = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new KeyProviderError("KEY_TIMEOUT")), timeoutMs);
    onAbort = () => reject(new KeyProviderError("KEY_ABORTED"));
    signal?.addEventListener("abort", onAbort, { once: true });
  });
  const pending = (async () => invoke({ signal: controller.signal }))();
  pending.then(
    (late) => {
      if (abandoned) discard(late);
    },
    () => undefined,
  );

  let result: unknown;
  try {
    result = await Promise.race([pending, interrupted]);
  } catch (error) {
    abandoned = true;
    controller.abort();
    throw sanitize(error);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (onAbort !== undefined) signal?.removeEventListener("abort", onAbort);
  }

  let checked: T | undefined;
  try {
    checked = check(result);
  } catch {
    checked = undefined;
  }
  if (checked === undefined) {
    discard(result);
    throw new KeyProviderError("KEY_UNAVAILABLE");
  }
  return checked;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isWrappedKey(value: unknown): value is Uint8Array {
  return isBytes(value) && value.byteLength >= 1 && value.byteLength <= LIMITS.wrappedKeyMaxBytes;
}

export function isStoredKey(value: unknown): value is StoredKey {
  return isObject(value) && isKeyRef(value.keyRef) && isWrappedKey(value.wrappedKey);
}

export function checkDataKey(result: unknown): DataKey | undefined {
  if (!isStoredKey(result)) return undefined;
  const plaintextKey = (result as Partial<DataKey>).plaintextKey;
  if (!isBytes(plaintextKey) || plaintextKey.byteLength !== LIMITS.dataKeyBytes) return undefined;
  return { keyRef: result.keyRef, wrappedKey: result.wrappedKey.slice(), plaintextKey };
}

export function discardDataKey(result: unknown): void {
  if (isObject(result) && isBytes(result.plaintextKey)) zero(result.plaintextKey);
}

export function checkPlaintextKey(result: unknown): Uint8Array | undefined {
  return isBytes(result) && result.byteLength === LIMITS.dataKeyBytes ? result : undefined;
}

export function discardPlaintextKey(result: unknown): void {
  if (isBytes(result)) zero(result);
}

export function checkStoredKey(result: unknown): StoredKey | undefined {
  if (!isStoredKey(result)) return undefined;
  return Object.freeze({ keyRef: result.keyRef, wrappedKey: result.wrappedKey.slice() });
}
