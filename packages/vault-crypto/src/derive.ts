/**
 * Derivations of record format version 1: the entry identifier (§3.2) and
 * the entry key (§3.3).
 */
import { isEntryId, isIdentifier, isNamespace, LIMITS } from "@redact-secret/vault-contracts";
import { type Bytes, concat, fail, isBytes, label, lp16, toHex, u8, utf8, view, webcrypto } from "./bytes.js";
import { ALGORITHM_AES_256_GCM } from "./codec.js";

const ISSUED_TOKEN = /^<rsv_[a-z2-7]{26}>$/;
const ZERO_SALT = new Uint8Array(32);

/**
 * `hex(SHA-256("rsv-entry-id-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(token)))`.
 * `token` is the issued token as written, including `<` and `>`.
 */
export async function deriveEntryId(namespace: string, tenant: string, token: string): Promise<string> {
  if (!isNamespace(namespace) || !isIdentifier(tenant)) fail("RECORD_INVALID_ARGUMENT");
  if (typeof token !== "string" || !ISSUED_TOKEN.test(token)) fail("RECORD_INVALID_ARGUMENT");
  const input = concat([label("rsv-entry-id-v1"), lp16(utf8(namespace)), lp16(utf8(tenant)), lp16(utf8(token))]);
  return toHex(new Uint8Array(await webcrypto().subtle.digest("SHA-256", input)));
}

function entryKeyInfo(entryId: string): Bytes {
  if (!isEntryId(entryId)) fail("RECORD_INVALID_ARGUMENT");
  return concat([label("rsv-entry-key-v1"), u8(ALGORITHM_AES_256_GCM), lp16(utf8(entryId))]);
}

/** Imports a capture data key as a non-extractable HKDF base key. */
export async function importDataKey(dek: Uint8Array): Promise<CryptoKey> {
  if (!isBytes(dek) || dek.byteLength !== LIMITS.dataKeyBytes) fail("RECORD_INVALID_ARGUMENT");
  return webcrypto().subtle.importKey("raw", view(dek), "HKDF", false, ["deriveKey"]);
}

/** The entry key of §3.3 from an imported data key. The key bytes never leave WebCrypto. */
export async function deriveEntryKeyFrom(dataKey: CryptoKey, entryId: string): Promise<CryptoKey> {
  const info = entryKeyInfo(entryId);
  return webcrypto().subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info },
    dataKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * `HKDF-SHA-256(ikm = dek, salt = 32 zero bytes, info = "rsv-entry-key-v1" 0x00
 * || u8 algorithm || lp16(entryId), length = 32)` as a non-extractable
 * AES-256-GCM key. `dek` is not retained; the caller overwrites it.
 */
export async function deriveEntryKey(dek: Uint8Array, entryId: string): Promise<CryptoKey> {
  entryKeyInfo(entryId);
  return deriveEntryKeyFrom(await importDataKey(dek), entryId);
}
