/**
 * The request digest (§7.3) and the session tag (§3.2). Both are
 * HMAC-SHA-256 under the application's digest key, or SHA-256 when the
 * application explicitly chose unkeyed digests.
 */
import {
  isCaptureId,
  isEntryId,
  isIdentifier,
  isNamespace,
  isWellFormed,
  LIMITS,
} from "@redact-secret/vault-contracts";
import {
  type Bytes,
  compareBytes,
  concat,
  fail,
  isBytes,
  label,
  lp16,
  toHex,
  u8,
  u16,
  u32,
  utf8,
  webcrypto,
} from "./bytes.js";

export const DIGEST_KEY_BYTES = 32;
const MAX_PATHS_PER_USE = 0xffff;
const MAX_OCCURRENCES = 0xffff_ffff;

export type DigesterOptions = { readonly key: Uint8Array } | { readonly unkeyed: true };

export interface RequestDigestInput {
  readonly namespace: string;
  readonly tenant: string;
  readonly principalId: string;
  /** The session resolved for this request, or null. */
  readonly sessionId: string | null;
  readonly sink: string;
  readonly purpose: string;
  /** Every capture the request names. Sorted here. */
  readonly captureIds: readonly string[];
  /** Each entry once. Entries and paths are sorted here. */
  readonly uses: readonly {
    readonly entryId: string;
    readonly paths: readonly { readonly path: string; readonly occurrences: number }[];
  }[];
}

export interface SessionTagInput {
  readonly namespace: string;
  readonly tenant: string;
  readonly captureId: string;
  readonly sessionId: string;
}

export interface Digester {
  /** 32 bytes. */
  requestDigest(input: RequestDigestInput): Promise<Uint8Array>;
  /** 64 lowercase hexadecimal characters. */
  sessionTag(input: SessionTagInput): Promise<string>;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function sortUnique<T>(items: T[], key: (item: T) => Bytes): T[] {
  items.sort((a, b) => compareBytes(key(a), key(b)));
  for (let i = 1; i < items.length; i += 1) {
    if (compareBytes(key(items[i - 1] as T), key(items[i] as T)) === 0) fail("RECORD_INVALID_ARGUMENT");
  }
  return items;
}

/** The bytes the request digest is computed over (§7.3). */
function encodeRequest(input: RequestDigestInput): Bytes {
  if (!isObject(input)) fail("RECORD_INVALID_ARGUMENT");
  const { namespace, tenant, principalId, sessionId, sink, purpose, captureIds, uses } = input;
  if (!isNamespace(namespace) || !isIdentifier(tenant) || !isIdentifier(principalId) || !isIdentifier(sink)) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  if (sessionId !== null && !isIdentifier(sessionId)) fail("RECORD_INVALID_ARGUMENT");
  if (typeof purpose !== "string" || purpose.length === 0 || !isWellFormed(purpose)) fail("RECORD_INVALID_ARGUMENT");
  if (purpose.length > LIMITS.purposeMaxBytes) fail("RECORD_LIMIT");
  const purposeBytes = utf8(purpose);
  if (purposeBytes.byteLength > LIMITS.purposeMaxBytes) fail("RECORD_LIMIT");

  if (!Array.isArray(captureIds) || captureIds.length === 0) fail("RECORD_INVALID_ARGUMENT");
  if (captureIds.length > LIMITS.maxRestoreCaptures) fail("RECORD_LIMIT");
  const captures = sortUnique(
    (captureIds as readonly unknown[]).map((captureId) => {
      if (!isCaptureId(captureId)) fail("RECORD_INVALID_ARGUMENT");
      return utf8(captureId);
    }),
    (bytes) => bytes,
  );

  if (!Array.isArray(uses) || uses.length === 0) fail("RECORD_INVALID_ARGUMENT");
  if (uses.length > LIMITS.maxRestoreEntries) fail("RECORD_LIMIT");
  const encodedUses = sortUnique(
    (uses as readonly unknown[]).map((use) => {
      if (!isObject(use) || !isEntryId(use.entryId)) fail("RECORD_INVALID_ARGUMENT");
      if (!Array.isArray(use.paths) || use.paths.length === 0) fail("RECORD_INVALID_ARGUMENT");
      if (use.paths.length > MAX_PATHS_PER_USE) fail("RECORD_LIMIT");
      const paths = sortUnique(
        (use.paths as readonly unknown[]).map((item) => {
          if (!isObject(item) || !isIdentifier(item.path)) fail("RECORD_INVALID_ARGUMENT");
          const occurrences = item.occurrences;
          if (typeof occurrences !== "number" || !Number.isSafeInteger(occurrences) || occurrences < 1) {
            fail("RECORD_INVALID_ARGUMENT");
          }
          if (occurrences > MAX_OCCURRENCES) fail("RECORD_LIMIT");
          return { path: utf8(item.path), occurrences };
        }),
        (item) => item.path,
      );
      return { entryId: utf8(use.entryId), paths };
    }),
    (use) => use.entryId,
  );

  const parts: Bytes[] = [
    label("rsv-request-v1"),
    lp16(utf8(namespace)),
    lp16(utf8(tenant)),
    lp16(utf8(principalId)),
    u8(sessionId === null ? 0 : 1),
    lp16(sessionId === null ? new Uint8Array(0) : utf8(sessionId)),
    lp16(utf8(sink)),
    lp16(purposeBytes),
    u16(captures.length),
  ];
  for (const capture of captures) parts.push(lp16(capture));
  parts.push(u16(encodedUses.length));
  for (const use of encodedUses) {
    parts.push(lp16(use.entryId), u16(use.paths.length));
    for (const item of use.paths) parts.push(lp16(item.path), u32(item.occurrences));
  }
  return concat(parts);
}

function encodeSessionTag(input: SessionTagInput): Bytes {
  if (!isObject(input)) fail("RECORD_INVALID_ARGUMENT");
  const { namespace, tenant, captureId, sessionId } = input;
  if (!isNamespace(namespace) || !isIdentifier(tenant) || !isCaptureId(captureId) || !isIdentifier(sessionId)) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  return concat([
    label("rsv-session-tag-v1"),
    lp16(utf8(namespace)),
    lp16(utf8(tenant)),
    lp16(utf8(captureId)),
    lp16(utf8(sessionId)),
  ]);
}

/**
 * `{ key }` selects HMAC-SHA-256 under a 32-byte key, imported as
 * non-extractable; the caller's array is not retained and may be overwritten
 * once this returns. `{ unkeyed: true }` selects SHA-256 and accepts that a
 * party reading the store can test guesses against what is stored (§7.3).
 */
export function createDigester(options: DigesterOptions): Digester {
  if (!isObject(options)) fail("RECORD_INVALID_ARGUMENT");
  const subtle = webcrypto().subtle;
  let mac: (message: Bytes) => Promise<ArrayBuffer>;
  const hasKey = "key" in options && options.key !== undefined;
  const unkeyed = "unkeyed" in options && options.unkeyed !== undefined;
  if (hasKey && !unkeyed) {
    const key = options.key;
    if (!isBytes(key) || key.byteLength !== DIGEST_KEY_BYTES) fail("RECORD_INVALID_ARGUMENT");
    const copy = key.slice();
    const imported = subtle
      .importKey("raw", copy, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
      .finally(() => copy.fill(0));
    // An import failure is reported by the first call, not as an unhandled rejection.
    imported.catch(() => undefined);
    mac = async (message) => subtle.sign("HMAC", await imported, message);
  } else if (unkeyed && !hasKey && options.unkeyed === true) {
    mac = (message) => subtle.digest("SHA-256", message);
  } else {
    fail("RECORD_INVALID_ARGUMENT");
  }

  const run = async (message: Bytes): Promise<Bytes> => {
    try {
      return new Uint8Array(await mac(message));
    } catch {
      return fail("RECORD_UNSUPPORTED");
    }
  };

  return Object.freeze({
    async requestDigest(input: RequestDigestInput): Promise<Uint8Array> {
      return run(encodeRequest(input));
    },
    async sessionTag(input: SessionTagInput): Promise<string> {
      return toHex(await run(encodeSessionTag(input)));
    },
  });
}
