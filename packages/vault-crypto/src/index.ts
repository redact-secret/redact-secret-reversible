/**
 * `@redact-secret/vault-crypto`: record format version 1 of
 * docs/specs/persistent-vault.md §3 over the platform's WebCrypto, and a
 * `RecordCrypto` built on an injected `KeyProvider`. It stores nothing and
 * authorizes nothing. The local key provider is a separate entry point,
 * `@redact-secret/vault-crypto/local-key-provider`.
 */
export type { DecodedEnvelope, EnvelopeParts } from "./codec.js";
export {
  ALGORITHM_AES_256_GCM,
  decodeEnvelope,
  decodePayload,
  encodeAad,
  encodeEnvelope,
  encodePayload,
  FORMAT_VERSION,
} from "./codec.js";
export { deriveEntryId, deriveEntryKey } from "./derive.js";
export type { Digester, DigesterOptions, RequestDigestInput, SessionTagInput } from "./digest.js";
export { createDigester } from "./digest.js";
export type { RecordCryptoOptions } from "./record-crypto.js";
export { createRecordCrypto, DEFAULT_KEY_TIMEOUT_MS, RECORD_CRYPTO_PROFILE } from "./record-crypto.js";
