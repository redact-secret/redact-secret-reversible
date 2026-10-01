/**
 * `@redact-secret/vault-server/persistent`: the opt-in persistent server
 * profile (docs/specs/persistent-vault.md §8). The application injects a
 * `Store`, a `RecordCrypto`, its identity resolvers, and its policies; this
 * module imports no database driver, key-service SDK, or cipher.
 *
 * Importing it retains nothing and does not change `createServerVault`.
 */
export { createPersistentServerVault } from "./server.js";
export { VaultServerError } from "../errors.js";
export type { ServerVaultErrorCode } from "../errors.js";
export type {
  DeleteCiphertextResult,
  LifecycleDecisionInput,
  LifecycleOperation,
  LifecyclePolicy,
  LifecycleRequest,
  PersistentCaptureOptions,
  PersistentCaptureResult,
  PersistentRestoreRequest,
  PersistentRestoreResult,
  PersistentServerVault,
  PersistentServerVaultOptions,
  ResolveAttemptRequest,
  ResolveAttemptResult,
  RevokeResult,
  SessionResolver,
} from "./types.js";
export type {
  PolicyDecision,
  Principal,
  PrincipalResolver,
  RestoreDecisionInput,
  ServerAuditEvent,
  ServerAuditHook,
  ServerAuditOperation,
  ServerDenialReason,
  ServerReleasePolicy,
} from "../types.js";
