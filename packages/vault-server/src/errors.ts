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
  | "DISPOSED";

const MESSAGES: Readonly<Record<ServerVaultErrorCode, string>> = Object.freeze({
  INVALID_ARGUMENT: "The server vault operation received an invalid argument.",
  RESTORE_DENIED: "The restore request was denied.",
  INVARIANT_VIOLATION: "The server vault rejected an inconsistent intermediate result.",
  VAULT_FAILURE: "The underlying vault rejected the operation.",
  DISPOSED: "The server vault has been disposed or has expired.",
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

  constructor(
    code: ServerVaultErrorCode,
    detail: {
      reason?: ServerDenialReason | undefined;
      vaultCode?: VaultErrorCode | undefined;
      coreCode?: string | undefined;
    } = {},
  ) {
    super(MESSAGES[code]);
    this.name = "VaultServerError";
    this.code = code;
    this.reason = detail.reason;
    this.vaultCode = detail.vaultCode;
    this.coreCode = code === "VAULT_FAILURE" && detail.vaultCode === "CORE_FAILURE" ? detail.coreCode : undefined;
  }
}
