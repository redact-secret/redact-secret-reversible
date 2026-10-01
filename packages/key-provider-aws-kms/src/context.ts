/**
 * What this provider sends to AWS KMS as the encryption context.
 *
 * The encryption context is authenticated but not secret, and AWS records it
 * in CloudTrail. So the namespace, tenant, and capture identifier of a
 * `KeyContext` are never sent: one SHA-256 digest of their canonical encoding
 * is (docs/specs/persistent-vault.md §3.7, §6.1). KMS binds the wrapped key
 * to that digest, so a different context does not unwrap.
 */
import { type KeyContext, KeyProviderError } from "@redact-secret/vault-contracts";

/** Encryption context key of the context digest. */
export const CONTEXT_DIGEST_KEY = "rsv:ctx";
/** Encryption context key of the constant binding version. */
export const CONTEXT_VERSION_KEY = "rsv:v";
export const CONTEXT_VERSION = "1";

const LABEL = "rsv-kms-context-v1";
const MAX_LABELS = 8;
const LABEL_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,62}$/;
const LABEL_VALUE = /^[A-Za-z0-9_.-]{1,128}$/;

function lp16(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + bytes.byteLength);
  out[0] = (bytes.byteLength >>> 8) & 0xff;
  out[1] = bytes.byteLength & 0xff;
  out.set(bytes, 2);
  return out;
}

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function sha256(subtle: SubtleCrypto, bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

/** `base64url(SHA-256("rsv-kms-context-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(captureId)))`. */
export async function contextDigest(subtle: SubtleCrypto, context: KeyContext): Promise<string> {
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
  const input = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    input.set(part, offset);
    offset += part.byteLength;
  }
  return base64url(await sha256(subtle, input));
}

/**
 * Validates the opt-in static labels. A label key is 1 to 63 characters of
 * `[A-Za-z0-9_.-]` starting with a letter, so it can never collide with
 * `rsv:` or `aws:` keys; a value is 1 to 128 characters of `[A-Za-z0-9_.-]`.
 * At most eight labels.
 */
export function snapshotLabels(labels: unknown): readonly (readonly [string, string])[] {
  if (labels === undefined) return [];
  if (typeof labels !== "object" || labels === null || Array.isArray(labels)) {
    throw new KeyProviderError("KEY_INVALID_ARGUMENT");
  }
  const entries = Object.entries(labels as Record<string, unknown>);
  if (entries.length > MAX_LABELS) throw new KeyProviderError("KEY_INVALID_ARGUMENT");
  const out: [string, string][] = [];
  for (const [key, value] of entries) {
    if (!LABEL_KEY.test(key) || typeof value !== "string" || !LABEL_VALUE.test(value)) {
      throw new KeyProviderError("KEY_INVALID_ARGUMENT");
    }
    out.push([key, value]);
  }
  return out;
}

/** A fresh encryption context object: the digest, the version, and the labels. Nothing else. */
export function encryptionContext(digest: string, labels: readonly (readonly [string, string])[]): Record<string, string> {
  const out: Record<string, string> = { [CONTEXT_DIGEST_KEY]: digest, [CONTEXT_VERSION_KEY]: CONTEXT_VERSION };
  for (const [key, value] of labels) out[key] = value;
  return out;
}
