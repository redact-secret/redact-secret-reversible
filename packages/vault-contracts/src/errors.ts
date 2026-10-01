/**
 * Sanitized errors shared by stores, key providers, and crypto layers
 * (docs/specs/persistent-vault.md §4.1). Every message is a fixed string
 * chosen by `code`. No error carries a driver or SDK message, input, key,
 * ciphertext, or token, and `cause` is never set.
 */

export type StoreErrorCode =
  | "STORE_UNAVAILABLE"
  | "STORE_AMBIGUOUS"
  | "STORE_INVALID_ARGUMENT"
  | "STORE_CAPABILITY"
  | "STORE_CLOSED";

const STORE_MESSAGES: Readonly<Record<StoreErrorCode, string>> = Object.freeze({
  STORE_UNAVAILABLE: "The store was unavailable; the operation had no effect.",
  STORE_AMBIGUOUS: "The store could not confirm whether the operation took effect.",
  STORE_INVALID_ARGUMENT: "The store operation received an input that violates the contract.",
  STORE_CAPABILITY: "The store operation exceeds a declared store capability.",
  STORE_CLOSED: "The store adapter has been closed.",
});

export class StoreError extends Error {
  readonly code: StoreErrorCode;

  constructor(code: StoreErrorCode) {
    super(STORE_MESSAGES[code]);
    this.name = "StoreError";
    this.code = code;
  }
}

export type KeyProviderErrorCode =
  | "KEY_UNAVAILABLE"
  | "KEY_INTEGRITY"
  | "KEY_TIMEOUT"
  | "KEY_THROTTLED"
  | "KEY_ABORTED"
  | "KEY_INVALID_ARGUMENT";

const KEY_MESSAGES: Readonly<Record<KeyProviderErrorCode, string>> = Object.freeze({
  KEY_UNAVAILABLE: "The key is unknown, disabled, retired, or outside the provider's scope.",
  KEY_INTEGRITY: "The wrapped key did not authenticate for this context.",
  KEY_TIMEOUT: "The key provider did not answer in time.",
  KEY_THROTTLED: "The key provider refused the call for load.",
  KEY_ABORTED: "The key provider call was cancelled.",
  KEY_INVALID_ARGUMENT: "The key provider received an input that violates the contract.",
});

export class KeyProviderError extends Error {
  readonly code: KeyProviderErrorCode;

  constructor(code: KeyProviderErrorCode) {
    super(KEY_MESSAGES[code]);
    this.name = "KeyProviderError";
    this.code = code;
  }
}

export type RecordCryptoErrorCode =
  | "RECORD_MALFORMED"
  | "RECORD_UNSUPPORTED"
  | "RECORD_INTEGRITY"
  | "RECORD_LIMIT"
  | "RECORD_INVALID_ARGUMENT";

const RECORD_MESSAGES: Readonly<Record<RecordCryptoErrorCode, string>> = Object.freeze({
  RECORD_MALFORMED: "The encrypted record is not well-formed.",
  RECORD_UNSUPPORTED: "The encrypted record uses an unsupported version or algorithm.",
  RECORD_INTEGRITY: "The encrypted record did not authenticate.",
  RECORD_LIMIT: "The record exceeds a size limit.",
  RECORD_INVALID_ARGUMENT: "The crypto operation received an input that violates the contract.",
});

export class RecordCryptoError extends Error {
  readonly code: RecordCryptoErrorCode;

  constructor(code: RecordCryptoErrorCode) {
    super(RECORD_MESSAGES[code]);
    this.name = "RecordCryptoError";
    this.code = code;
  }
}
