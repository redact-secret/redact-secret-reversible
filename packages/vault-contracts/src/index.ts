/**
 * `@redact-secret/vault-contracts`: the types, limits, validators, and error
 * classes shared by a persistent vault server, its crypto layer, store
 * adapters, and key providers. It has no runtime dependency and performs no
 * I/O. Semantics are defined by docs/specs/persistent-vault.md.
 */
export type * from "./types.js";
export { KeyProviderError, RecordCryptoError, StoreError } from "./errors.js";
export type { KeyProviderErrorCode, RecordCryptoErrorCode, StoreErrorCode } from "./errors.js";
export { LIMITS } from "./limits.js";
export {
  isAttemptId,
  isCaptureId,
  isEntryId,
  isIdentifier,
  isKeyRef,
  isNamespace,
  isSessionTag,
  isTimestamp,
  isWellFormed,
  missingCapabilities,
  validateCommitRestore,
  validateCreateCapture,
  validateDeleteCiphertext,
  validateInitializeNamespace,
  validateInspectAttempt,
  validateInvalidateRecovered,
  validateNamespace,
  validateReadCaptures,
  validateReadEntries,
  validateReplaceCaptureKey,
  validateRevokeCapture,
  validateSweep,
} from "./validate.js";
