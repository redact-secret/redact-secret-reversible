/**
 * `@redact-secret/vault`: an opt-in, bounded, in-memory vault that retains
 * eligible original values from one whole input and restores them only into
 * application-designated structured fields.
 *
 * Importing this module retains nothing. See the package README for the
 * supported runtimes, the trust boundary, and what this package does not
 * protect against.
 */
export { createVault, DEFAULT_LIMITS, LIMIT_CEILINGS } from "./vault.js";
export { VaultError } from "./errors.js";
export type { DenialReason, VaultErrorCode } from "./errors.js";
export type {
  AuditEvent,
  AuditHook,
  CaptureOptions,
  CaptureResult,
  IssuedToken,
  PiiRetention,
  ReleaseGrant,
  ReleasePolicy,
  ReleaseRequest,
  RestoreRequest,
  RestoreResult,
  Vault,
  VaultLimits,
  VaultOptions,
  VaultStats,
} from "./types.js";
