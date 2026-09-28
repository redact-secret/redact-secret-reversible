/**
 * `@redact-secret/vault-server`: server authority for restoring values
 * captured by `@redact-secret/vault` across principals, tenants, sources,
 * destinations, and purposes.
 *
 * Implements the interface fixed by
 * docs/decisions/2026-09-27-define-server-authority-interface.md (S1, #15)
 * — `PrincipalResolver`, `ServerReleasePolicy`, `ServerDenialReason`, and
 * `ServerAuditEvent` — with an in-memory storage backend built on
 * `@redact-secret/vault`. See the package README for the evaluation order,
 * the concurrency contract, and what this package does not do (persistence,
 * Python, streaming — see the README's "Supported, and not" table).
 *
 * Importing this module retains nothing; only `createServerVault` does.
 */
export { createServerVault } from "./server-vault.js";
export { VaultServerError } from "./errors.js";
export type { ServerVaultErrorCode } from "./errors.js";
export type {
  Principal,
  PolicyDecision,
  PrincipalResolver,
  RestoreDecisionInput,
  ServerAuditEvent,
  ServerAuditHook,
  ServerAuditOperation,
  ServerCaptureOptions,
  ServerDenialReason,
  ServerReleasePolicy,
  ServerRestoreRequest,
  ServerRestoreResult,
  ServerVault,
  ServerVaultOptions,
  ServerVaultStats,
} from "./types.js";
