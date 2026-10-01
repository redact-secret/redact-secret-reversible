import type { VaultErrorCode } from "@redact-secret/vault";

import type { ServerDenialReason } from "./types.js";

/**
 * The single sanitized error type this package throws. Same discipline as
 * `@redact-secret/vault`'s `VaultError`: every message is a fixed string
 * chosen by `code`, and no error carries input text, a matched value, an
 * issued token, a restored value, a field path, a principal's attributes,
 * or the message of an exception thrown by a consumer callback
 * (`PrincipalResolver`, `ServerReleasePolicy`, `ServerAuditHook`). `cause`
 * is never set.
 */
export type ServerVaultErrorCode =
  | "INVALID_ARGUMENT"
  | "RESTORE_DENIED"
  | "INVARIANT_VIOLATION"
  | "VAULT_FAILURE"
  | "DISPOSED"
  // The codes below are thrown only by the persistent profile
  // (`@redact-secret/vault-server/persistent`, docs/specs/persistent-vault.md §8.3).
  | "UNSUPPORTED_STORE"
  | "STORE_UNAVAILABLE"
  | "STORE_QUARANTINED"
  | "COMMIT_AMBIGUOUS"
  | "RESTORE_CONFLICT"
  | "CLOCK_SKEW"
  | "LIMIT_EXCEEDED"
  | "LIFECYCLE_DENIED"
  | "KEY_UNAVAILABLE"
  | "CLOSED";

const MESSAGES: Readonly<Record<ServerVaultErrorCode, string>> = Object.freeze({
  INVALID_ARGUMENT: "The server vault operation received an invalid argument.",
  RESTORE_DENIED: "The restore request was denied.",
  INVARIANT_VIOLATION: "The server vault rejected an inconsistent intermediate result.",
  VAULT_FAILURE: "The underlying vault rejected the operation.",
  DISPOSED: "The server vault has been disposed or has expired.",
  UNSUPPORTED_STORE: "The store does not declare the capabilities this server requires.",
  STORE_UNAVAILABLE: "The store was unavailable; nothing was released.",
  STORE_QUARANTINED: "The store namespace is not serving at the configured recovery epoch.",
  COMMIT_AMBIGUOUS: "The store could not confirm whether the restore committed; nothing was released.",
  RESTORE_CONFLICT: "The restore kept conflicting with concurrent changes; nothing was consumed.",
  CLOCK_SKEW: "The server clock and the store clock differ by more than the allowed bound.",
  LIMIT_EXCEEDED: "The operation exceeds a configured limit or a store capability.",
  LIFECYCLE_DENIED: "The lifecycle operation was denied.",
  KEY_UNAVAILABLE: "The key provider could not supply a key; nothing was stored.",
  CLOSED: "The persistent server vault has been closed.",
});

export class VaultServerError extends Error {
  readonly code: ServerVaultErrorCode;
  /** Set only for `RESTORE_DENIED`. */
  readonly reason: ServerDenialReason | undefined;
  /** Set only for `VAULT_FAILURE`: the wrapped `@redact-secret/vault` error's own fixed code. */
  readonly vaultCode: VaultErrorCode | undefined;
  /**
   * Set only for `VAULT_FAILURE` whose `vaultCode` is `CORE_FAILURE`: the
   * core's own fixed error code (for example `PII_ACTIVATION_CONFLICT` or
   * `NOT_INITIALIZED`), passed through from the wrapped `VaultError`.
   */
  readonly coreCode: string | undefined;
  /**
   * Set only for `COMMIT_AMBIGUOUS`: the opaque attempt identifier to pass to
   * `resolveAttempt`. Never a token or a value.
   */
  readonly attemptId: string | undefined;

  constructor(
    code: ServerVaultErrorCode,
    detail: {
      reason?: ServerDenialReason | undefined;
      vaultCode?: VaultErrorCode | undefined;
      coreCode?: string | undefined;
      attemptId?: string | undefined;
    } = {},
  ) {
    super(MESSAGES[code]);
    this.name = "VaultServerError";
    this.code = code;
    this.reason = detail.reason;
    this.vaultCode = detail.vaultCode;
    this.coreCode = code === "VAULT_FAILURE" && detail.vaultCode === "CORE_FAILURE" ? detail.coreCode : undefined;
    this.attemptId = code === "COMMIT_AMBIGUOUS" ? detail.attemptId : undefined;
  }
}
