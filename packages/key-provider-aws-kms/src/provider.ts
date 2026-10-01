/**
 * A `KeyProvider` (docs/specs/persistent-vault.md §6.1) over AWS KMS.
 *
 * The application supplies a configured KMS client, the exact key ARNs the
 * provider may use, and its scope. This module constructs no client, reads no
 * environment variable, resolves no region, and loads no credential. It never
 * retries, never falls back to another key or to a local key, logs nothing,
 * and never lets an SDK error, its message, or its metadata reach the caller.
 */
import { DecryptCommand, GenerateDataKeyCommand, ReEncryptCommand } from "@aws-sdk/client-kms";
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
import { createDataKeyCache, type DataKeyCache, type DataKeyCacheOptions } from "./cache.js";
import { base64url, contextDigest, encryptionContext, sha256, snapshotLabels } from "./context.js";

export const AWS_KMS_KEY_PROVIDER_PROFILE = "aws-kms-envelope-v1";
export const KEY_REF_PREFIX = "aws-kms:";
export const DEFAULT_CALL_TIMEOUT_MS = 5000;
const MAX_CALL_TIMEOUT_MS = 2_147_483_647;

/** A full key ARN. An alias, an alias ARN, and a bare key id are not accepted: an alias can be repointed. */
const KEY_ARN =
  /^arn:(aws(?:-[a-z]+)*):kms:([a-z]{2}(?:-[a-z]+)+-\d{1,2}):(\d{12}):key\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;
const REGION = /^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/;
const ACCOUNT = /^\d{12}$/;
const PARTITION = /^aws(?:-[a-z]+)*$/;

export type AwsKmsKeyState = "active" | "decrypt-only" | "retired";

export interface AwsKmsKey {
  /** A full key ARN, `arn:<partition>:kms:<region>:<account>:key/<key-id>`. The key reference is `aws-kms:<keyArn>`. */
  readonly keyArn: string;
  readonly state: AwsKmsKeyState;
}

export type KmsCommand = GenerateDataKeyCommand | DecryptCommand | ReEncryptCommand;

/** The part of a `KMSClient` this provider uses. A `KMSClient` of `@aws-sdk/client-kms` satisfies it. */
export interface KmsClientLike {
  send(command: KmsCommand, options?: { readonly abortSignal?: AbortSignal }): Promise<unknown>;
}

export interface AwsKmsKeyProviderOptions {
  /** A KMS client the application constructed, with its region, credentials, retry, and timeout settings. */
  readonly client: KmsClientLike;
  /** Exactly one key is `active`. */
  readonly keys: readonly AwsKmsKey[];
  /** The region and account every key ARN must be in, stated by the application. `partition` defaults to `aws`. */
  readonly expected: { readonly region: string; readonly accountId: string; readonly partition?: string };
  /** The namespaces, and optionally the tenants, this provider may serve. Required. */
  readonly scope: { readonly namespaces: readonly string[]; readonly tenants?: readonly string[] };
  /** Opt-in cache of unwrapped data keys. Off when absent. */
  readonly cache?: DataKeyCacheOptions;
  /** Upper bound of one KMS call in milliseconds. Default 5000. */
  readonly callTimeoutMs?: number;
  /**
   * Opt-in static, non-sensitive pairs added to the encryption context, for
   * IAM conditions. They appear in CloudTrail and become part of the binding:
   * a key wrapped with one set of labels does not unwrap with another.
   */
  readonly contextLabels?: Readonly<Record<string, string>>;
}

/** Counts only. No key, identifier, or ARN. */
export interface AwsKmsKeyProviderStats {
  readonly closed: boolean;
  readonly cacheEnabled: boolean;
  readonly cacheEntries: number;
  readonly cacheTenants: number;
  readonly cacheHits: number;
  readonly cacheMisses: number;
  readonly cacheEvictions: number;
  readonly generateDataKeyCalls: number;
  readonly decryptCalls: number;
  readonly reEncryptCalls: number;
}

export interface AwsKmsKeyProvider extends KeyProvider {
  /** Overwrites and drops every cached data key. Every later call fails `KEY_UNAVAILABLE`. It does not close the client. */
  close(): void;
  stats(): AwsKmsKeyProviderStats;
}

function fail(code: KeyProviderErrorCode): never {
  throw new KeyProviderError(code);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/** Overwrites the plaintext of a KMS response, where there is one. */
function discardPlaintext(output: unknown): void {
  if (isObject(output) && isBytes(output.Plaintext)) output.Plaintext.fill(0);
}

function discardNothing(): void {}

/** Read through a function so that a check after an await is not narrowed away by an earlier one. */
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal !== undefined && signal.aborted === true;
}

const THROTTLED: ReadonlySet<string> = new Set([
  "ThrottlingException",
  "LimitExceededException",
  "TooManyRequestsException",
  "RequestLimitExceeded",
  "Throttling",
  "ThrottledException",
  "RequestThrottledException",
  "RequestThrottled",
]);
const TIMED_OUT: ReadonlySet<string> = new Set(["TimeoutError", "RequestTimeout", "RequestTimeoutException"]);

/**
 * Maps what a client threw to a code. Only the error's `name` and the SDK's
 * `$retryable.throttling` flag are read; the message is not. Every name not
 * listed, including `DisabledException`, `KMSInvalidStateException`,
 * `NotFoundException`, `AccessDeniedException`, `KeyUnavailableException`,
 * and `IncorrectKeyException`, is `KEY_UNAVAILABLE`.
 */
function classify(error: unknown): KeyProviderErrorCode {
  let name = "";
  let throttling = false;
  try {
    if (isObject(error)) {
      if (typeof error.name === "string") name = error.name;
      const retryable = error.$retryable;
      throttling = isObject(retryable) && retryable.throttling === true;
    }
  } catch {
    return "KEY_UNAVAILABLE";
  }
  if (name === "InvalidCiphertextException") return "KEY_INTEGRITY";
  if (throttling || THROTTLED.has(name)) return "KEY_THROTTLED";
  if (TIMED_OUT.has(name)) return "KEY_TIMEOUT";
  return "KEY_UNAVAILABLE";
}

function snapshotContext(context: unknown): KeyContext {
  if (!isObject(context)) fail("KEY_INVALID_ARGUMENT");
  const { namespace, tenant, captureId } = context;
  if (!isNamespace(namespace) || !isIdentifier(tenant) || !isCaptureId(captureId)) fail("KEY_INVALID_ARGUMENT");
  return { namespace, tenant, captureId };
}

function readSignal(options: unknown): AbortSignal | undefined {
  if (options === undefined) return undefined;
  if (!isObject(options)) fail("KEY_INVALID_ARGUMENT");
  const signal = (options as KeyCallOptions).signal;
  if (signal === undefined) return undefined;
  if (
    !isObject(signal) ||
    typeof signal.aborted !== "boolean" ||
    typeof signal.addEventListener !== "function" ||
    typeof signal.removeEventListener !== "function"
  ) {
    fail("KEY_INVALID_ARGUMENT");
  }
  return signal;
}

interface Stored {
  readonly keyRef: string;
  readonly wrappedKey: Uint8Array<ArrayBuffer>;
  readonly context: KeyContext;
}

function snapshotStored(input: unknown): Stored {
  if (!isObject(input)) fail("KEY_INVALID_ARGUMENT");
  const { keyRef, wrappedKey } = input;
  if (typeof keyRef !== "string" || !isBytes(wrappedKey)) fail("KEY_INVALID_ARGUMENT");
  if (keyRef.length === 0 || wrappedKey.byteLength === 0 || wrappedKey.byteLength > LIMITS.wrappedKeyMaxBytes) {
    fail("KEY_INVALID_ARGUMENT");
  }
  return { keyRef, wrappedKey: wrappedKey.slice(), context: snapshotContext(input.context) };
}

/** A wrapped key as KMS returned it, or `undefined` when it is outside the contract's limits. */
function wrappedFrom(output: Record<string, unknown>): Uint8Array | undefined {
  const blob = output.CiphertextBlob;
  if (!isBytes(blob) || blob.byteLength === 0 || blob.byteLength > LIMITS.wrappedKeyMaxBytes) return undefined;
  return blob.slice();
}

/** The reason a call was given up, kept apart from anything a client can throw. */
class Interrupt {
  readonly code: "KEY_TIMEOUT" | "KEY_ABORTED";
  constructor(code: "KEY_TIMEOUT" | "KEY_ABORTED") {
    this.code = code;
  }
}

/**
 * Builds the provider. Throws `KEY_INVALID_ARGUMENT` unless the options hold
 * a client, full key ARNs that all lie in the expected partition, region, and
 * account, exactly one active key, and an explicit scope. Makes no KMS call.
 */
export function createAwsKmsKeyProvider(options: AwsKmsKeyProviderOptions): AwsKmsKeyProvider {
  const platform = (globalThis as { crypto?: Crypto }).crypto;
  if (platform === undefined || platform.subtle === undefined) fail("KEY_UNAVAILABLE");
  const subtle = platform.subtle;

  if (!isObject(options)) fail("KEY_INVALID_ARGUMENT");
  const client = options.client;
  if (!isObject(client) || typeof client.send !== "function") fail("KEY_INVALID_ARGUMENT");

  if (!isObject(options.scope)) fail("KEY_INVALID_ARGUMENT");
  const { namespaces, tenants } = options.scope;
  if (!Array.isArray(namespaces) || namespaces.length === 0 || !namespaces.every(isNamespace)) {
    fail("KEY_INVALID_ARGUMENT");
  }
  if (tenants !== undefined && (!Array.isArray(tenants) || tenants.length === 0 || !tenants.every(isIdentifier))) {
    fail("KEY_INVALID_ARGUMENT");
  }
  const allowedNamespaces: ReadonlySet<string> = new Set(namespaces as readonly string[]);
  const allowedTenants: ReadonlySet<string> | null = tenants === undefined ? null : new Set(tenants as string[]);

  if (!isObject(options.expected)) fail("KEY_INVALID_ARGUMENT");
  const { region, accountId } = options.expected;
  const partition = options.expected.partition ?? "aws";
  if (typeof region !== "string" || !REGION.test(region)) fail("KEY_INVALID_ARGUMENT");
  if (typeof accountId !== "string" || !ACCOUNT.test(accountId)) fail("KEY_INVALID_ARGUMENT");
  if (typeof partition !== "string" || !PARTITION.test(partition)) fail("KEY_INVALID_ARGUMENT");

  if (!Array.isArray(options.keys) || options.keys.length === 0) fail("KEY_INVALID_ARGUMENT");
  /** ARN to state, for the keys that may still be used. A retired key is not held. */
  const usable = new Map<string, "active" | "decrypt-only">();
  const seen = new Set<string>();
  let activeArn: string | undefined;
  for (const key of options.keys as readonly unknown[]) {
    if (!isObject(key) || typeof key.keyArn !== "string" || seen.has(key.keyArn)) fail("KEY_INVALID_ARGUMENT");
    const match = KEY_ARN.exec(key.keyArn);
    if (match === null || match[1] !== partition || match[2] !== region || match[3] !== accountId) {
      fail("KEY_INVALID_ARGUMENT");
    }
    const state = key.state;
    if (state !== "active" && state !== "decrypt-only" && state !== "retired") fail("KEY_INVALID_ARGUMENT");
    if (state === "active") {
      if (activeArn !== undefined) fail("KEY_INVALID_ARGUMENT");
      activeArn = key.keyArn;
    }
    seen.add(key.keyArn);
    if (state !== "retired") usable.set(key.keyArn, state);
  }
  if (activeArn === undefined) fail("KEY_INVALID_ARGUMENT");
  const active: string = activeArn;

  const timeout = options.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS;
  if (typeof timeout !== "number" || !Number.isInteger(timeout) || timeout < 1 || timeout > MAX_CALL_TIMEOUT_MS) {
    fail("KEY_INVALID_ARGUMENT");
  }
  const labels = snapshotLabels(options.contextLabels);
  const cache: DataKeyCache | null = options.cache === undefined ? null : createDataKeyCache(options.cache);

  let closed = false;
  const calls = { generate: 0, decrypt: 0, reEncrypt: 0 };

  function inScope(context: KeyContext): boolean {
    return allowedNamespaces.has(context.namespace) && (allowedTenants === null || allowedTenants.has(context.tenant));
  }

  /** The ARN `keyRef` names, when it is a configured key that is not retired. Never another key. */
  function arnOf(keyRef: string): string {
    if (!keyRef.startsWith(KEY_REF_PREFIX)) fail("KEY_UNAVAILABLE");
    const arn = keyRef.slice(KEY_REF_PREFIX.length);
    if (!usable.has(arn)) fail("KEY_UNAVAILABLE");
    return arn;
  }

  async function digestOf(context: KeyContext): Promise<string> {
    try {
      return await contextDigest(subtle, context);
    } catch {
      return fail("KEY_UNAVAILABLE");
    }
  }

  /**
   * One KMS call, bounded by the timeout and the caller's signal. It ends in
   * the response object or a new `KeyProviderError`; nothing the client threw
   * is rethrown or attached. `discard` overwrites a response that arrives
   * after the call was given up.
   */
  async function send(
    command: KmsCommand,
    signal: AbortSignal | undefined,
    discard: (output: unknown) => void,
  ): Promise<Record<string, unknown>> {
    if (isAborted(signal)) fail("KEY_ABORTED");
    const controller = new AbortController();
    let abandoned = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const interrupted = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Interrupt("KEY_TIMEOUT")), timeout);
      onAbort = () => reject(new Interrupt("KEY_ABORTED"));
      signal?.addEventListener("abort", onAbort, { once: true });
    });
    const pending = (async () => client.send(command, { abortSignal: controller.signal }))();
    pending.then(
      (late) => {
        if (abandoned) discard(late);
      },
      () => undefined,
    );

    let output: unknown;
    try {
      output = await Promise.race([pending, interrupted]);
    } catch (error) {
      abandoned = true;
      controller.abort();
      throw new KeyProviderError(error instanceof Interrupt ? error.code : classify(error));
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (onAbort !== undefined) signal?.removeEventListener("abort", onAbort);
    }
    if (!isObject(output)) fail("KEY_UNAVAILABLE");
    if (closed) {
      discard(output);
      fail("KEY_UNAVAILABLE");
    }
    if (isAborted(signal)) {
      discard(output);
      fail("KEY_ABORTED");
    }
    return output;
  }

  function enter(callOptions: unknown): AbortSignal | undefined {
    const signal = readSignal(callOptions);
    if (isAborted(signal)) fail("KEY_ABORTED");
    if (closed) fail("KEY_UNAVAILABLE");
    return signal;
  }

  const provider: AwsKmsKeyProvider = {
    profile: AWS_KMS_KEY_PROVIDER_PROFILE,

    async generateDataKey(context: KeyContext, callOptions?: KeyCallOptions): Promise<DataKey> {
      const signal = enter(callOptions);
      const snapshot = snapshotContext(context);
      if (!inScope(snapshot)) fail("KEY_UNAVAILABLE");
      const digest = await digestOf(snapshot);
      calls.generate += 1;
      const output = await send(
        new GenerateDataKeyCommand({
          KeyId: active,
          KeySpec: "AES_256",
          EncryptionContext: encryptionContext(digest, labels),
        }),
        signal,
        discardPlaintext,
      );
      const plaintext = output.Plaintext;
      const wrappedKey = wrappedFrom(output);
      if (
        output.KeyId !== active ||
        !isBytes(plaintext) ||
        plaintext.byteLength !== LIMITS.dataKeyBytes ||
        wrappedKey === undefined
      ) {
        discardPlaintext(output);
        fail("KEY_INTEGRITY");
      }
      const plaintextKey = plaintext.slice();
      plaintext.fill(0);
      return { keyRef: KEY_REF_PREFIX + active, wrappedKey, plaintextKey };
    },

    async unwrapDataKey(
      input: StoredKey & { readonly context: KeyContext },
      callOptions?: KeyCallOptions,
    ): Promise<Uint8Array> {
      const signal = enter(callOptions);
      const stored = snapshotStored(input);
      if (!inScope(stored.context)) fail("KEY_UNAVAILABLE");
      const arn = arnOf(stored.keyRef);
      const digest = await digestOf(stored.context);

      let cacheId: string | undefined;
      if (cache !== null) {
        try {
          cacheId = `${arn}\n${base64url(await sha256(subtle, stored.wrappedKey))}\n${digest}`;
        } catch {
          return fail("KEY_UNAVAILABLE");
        }
        if (isAborted(signal)) fail("KEY_ABORTED");
        if (closed) fail("KEY_UNAVAILABLE");
        const cached = cache.get(cacheId);
        if (cached !== undefined) return cached;
      }

      calls.decrypt += 1;
      // KeyId is always sent: KMS must use the key the reference names, not the one the blob names.
      const output = await send(
        new DecryptCommand({
          KeyId: arn,
          CiphertextBlob: stored.wrappedKey,
          EncryptionContext: encryptionContext(digest, labels),
        }),
        signal,
        discardPlaintext,
      );
      const plaintext = output.Plaintext;
      if (output.KeyId !== arn || !isBytes(plaintext) || plaintext.byteLength !== LIMITS.dataKeyBytes) {
        discardPlaintext(output);
        fail("KEY_INTEGRITY");
      }
      const dek = plaintext.slice();
      plaintext.fill(0);
      if (cache !== null && cacheId !== undefined) cache.put(cacheId, stored.context.tenant, dek.slice());
      return dek;
    },

    async rewrapDataKey(
      input: StoredKey & { readonly context: KeyContext },
      callOptions?: KeyCallOptions,
    ): Promise<StoredKey> {
      const signal = enter(callOptions);
      const stored = snapshotStored(input);
      if (!inScope(stored.context)) fail("KEY_UNAVAILABLE");
      const arn = arnOf(stored.keyRef);
      const digest = await digestOf(stored.context);
      calls.reEncrypt += 1;
      // ReEncrypt decrypts and encrypts inside KMS: the data key does not reach this process.
      const output = await send(
        new ReEncryptCommand({
          CiphertextBlob: stored.wrappedKey,
          SourceKeyId: arn,
          SourceEncryptionContext: encryptionContext(digest, labels),
          DestinationKeyId: active,
          DestinationEncryptionContext: encryptionContext(digest, labels),
        }),
        signal,
        discardNothing,
      );
      const wrappedKey = wrappedFrom(output);
      if (output.SourceKeyId !== arn || output.KeyId !== active || wrappedKey === undefined) fail("KEY_INTEGRITY");
      return { keyRef: KEY_REF_PREFIX + active, wrappedKey };
    },

    close(): void {
      closed = true;
      cache?.clear();
    },

    stats(): AwsKmsKeyProviderStats {
      const counts = cache?.counts() ?? { entries: 0, tenants: 0, hits: 0, misses: 0, evictions: 0 };
      return {
        closed,
        cacheEnabled: cache !== null,
        cacheEntries: counts.entries,
        cacheTenants: counts.tenants,
        cacheHits: counts.hits,
        cacheMisses: counts.misses,
        cacheEvictions: counts.evictions,
        generateDataKeyCalls: calls.generate,
        decryptCalls: calls.decrypt,
        reEncryptCalls: calls.reEncrypt,
      };
    },
  };
  return Object.freeze(provider);
}
