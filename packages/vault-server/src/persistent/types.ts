import type { CaptureOptions, IssuedToken, VaultLimits, VaultOptions } from "@redact-secret/vault";
import type { RecordCrypto, Store, StoreCapabilities } from "@redact-secret/vault-contracts";

import type { Principal, PrincipalResolver, ServerAuditHook, ServerReleasePolicy } from "../types.js";

/**
 * Resolves the session a request belongs to from the same trusted context
 * the `PrincipalResolver` receives. `null` or `undefined` means "no session":
 * a capture made from such a context is not session-bound and can be restored
 * from any session of its tenant. A session identifier is an identifier, not
 * a credential, and must not be a bearer token. A throw or a timeout denies.
 */
export type SessionResolver<Context = unknown> = (
  context: Context,
) => string | null | undefined | Promise<string | null | undefined>;

export type LifecycleOperation = "capture" | "revoke" | "delete-ciphertext" | "resolve-attempt";

export interface LifecycleDecisionInput {
  readonly operation: LifecycleOperation;
  readonly principal: Principal;
  readonly tenant: string;
  readonly sessionId: string | null;
  /** Absent for `capture` and `resolve-attempt`. */
  readonly captureId?: string;
  /** Of the capture, for `revoke` and `delete-ciphertext`, when the capture exists. */
  readonly sessionBound?: boolean;
  /** For `capture`: values about to be retained. */
  readonly entries?: number;
  /** For `capture`: their total UTF-8 size. */
  readonly bytes?: number;
  readonly requestedAt: number;
}

/**
 * Asked once per `capture`, `revoke`, `deleteCaptureCiphertext`, and
 * `resolveAttempt`. Only `{ allow: true }` allows. A throw, a rejection, a
 * timeout, or any other return value fails the operation `LIFECYCLE_DENIED`
 * before any store mutation.
 */
export type LifecyclePolicy = (
  input: LifecycleDecisionInput,
) => { readonly allow: boolean } | Promise<{ readonly allow: boolean }>;

export interface PersistentServerVaultOptions<Context = unknown> {
  /** The application-controlled persistent vault namespace. */
  readonly namespace: string;
  /** The recovery epoch from deployment configuration (specification §9.3). */
  readonly recoveryEpoch: number;
  readonly store: Store;
  readonly crypto: RecordCrypto;
  /**
   * 32 bytes, the same in every process of the namespace. Keys the request
   * digest and the session tag. Required unless `allowUnkeyedDigests` is true.
   */
  readonly digestKey?: Uint8Array;
  /** Use plain SHA-256 for digests, accepting that a party reading the store can test guesses against them. */
  readonly allowUnkeyedDigests?: boolean;
  readonly resolvePrincipal: PrincipalResolver<Context>;
  readonly resolveSession?: SessionResolver<Context>;
  readonly policy: ServerReleasePolicy;
  readonly lifecyclePolicy: LifecyclePolicy;
  readonly onAudit?: ServerAuditHook;
  /** Capture and restore limits. `maxEntries`, `maxRetainedBytes`, and `vaultTtlMs` bound one capture here, not a process. */
  readonly limits?: Partial<VaultLimits>;
  /** Millisecond clock. Default `Date.now`. Floored and made non-decreasing. */
  readonly now?: () => number;
  readonly policyRevision?: string | (() => string);
  /** Deadline for one resolver call. Default 5000. */
  readonly resolverTimeoutMs?: number;
  /** Deadline for one policy or lifecycle-policy call. Default 5000. */
  readonly policyTimeoutMs?: number;
  /** Deadline for one store call. Default 10000. A mutating call that passes it has an unknown outcome. */
  readonly storeTimeoutMs?: number;
  /** Deadline for all crypto and key-provider work of one operation. Default 15000. */
  readonly cryptoTimeoutMs?: number;
  /** Re-reads after a `stale` commit before failing `RESTORE_CONFLICT`. Default 3, at most 10. */
  readonly maxCommitRetries?: number;
  /** Added to the latest capture expiry and the skew bound to set a receipt's lifetime. Default one hour. */
  readonly receiptGraceMs?: number;
  /** How long a revocation tombstone outlives its capture. Default 24 hours. */
  readonly tombstoneRetentionMs?: number;
  /** Accept a store that is volatile or single-process. For tests and development. */
  readonly allowNonDurableStore?: boolean;
  /** Accept a durable store that declares no restore detection; the recovery runbook is then the only control. */
  readonly allowNoRestoreDetection?: boolean;
  readonly pii?: VaultOptions["pii"];
  readonly expectPiiActivation?: VaultOptions["expectPiiActivation"];
}

export interface PersistentCaptureOptions<Context = unknown> extends CaptureOptions {
  /** Passed verbatim to the resolvers. The capture's tenant and session come only from them. */
  readonly context: Context;
  /** Caller/transport correlation id, mirrored onto audit events. */
  readonly requestId?: string;
}

export interface PersistentCaptureResult {
  readonly captureId: string;
  readonly text: string;
  readonly tokens: readonly IssuedToken[];
  readonly passedThrough: number;
  readonly passedThroughTypes: readonly string[];
  readonly unrestorable: number;
  readonly expiresAt: number;
  readonly tenant: string;
  readonly sessionBound: boolean;
}

export interface PersistentRestoreRequest<Context = unknown> {
  readonly context: Context;
  readonly sink: string;
  readonly purpose: string;
  readonly captures: readonly string[];
  readonly fields: Readonly<Record<string, string>>;
  /**
   * Identifies this attempt for deduplication and for `resolveAttempt`. The
   * server generates one when omitted; it is returned on success and carried
   * by a `COMMIT_AMBIGUOUS` error.
   */
  readonly attemptId?: string;
  readonly requestId?: string;
}

export interface PersistentRestoreResult {
  readonly fields: Readonly<Record<string, string>>;
  readonly restored: number;
  readonly principalId: string;
  readonly tenant: string;
  /** Absent when the request held no token: nothing was committed. */
  readonly attemptId?: string;
}

export interface LifecycleRequest<Context = unknown> {
  readonly context: Context;
  readonly captureId: string;
  readonly requestId?: string;
}

export interface RevokeResult {
  readonly outcome: "revoked" | "already-revoked" | "not-found";
  /** Entry rows the capture had when it was revoked. Informational. */
  readonly entries: number;
}

export interface DeleteCiphertextResult {
  readonly outcome: "deleted" | "not-found";
  readonly entries: number;
  /**
   * Always false. Deleting ciphertext from the live store retires no key and
   * removes no copy held in a backup, replica, or log archive.
   */
  readonly keyRetired: false;
}

export interface ResolveAttemptRequest<Context = unknown> extends PersistentRestoreRequest<Context> {
  readonly attemptId: string;
}

export type ResolveAttemptResult =
  | { readonly state: "committed"; readonly committedAt: number }
  | { readonly state: "absent" }
  | { readonly state: "attempt-mismatch" };

export interface PersistentServerVault<Context = unknown> {
  readonly namespace: string;
  readonly piiActivation: string | null;
  /** The capabilities the store declared when this instance was created. */
  readonly storeCapabilities: StoreCapabilities;
  capture(input: string, options: PersistentCaptureOptions<Context>): Promise<PersistentCaptureResult>;
  restore(request: PersistentRestoreRequest<Context>): Promise<PersistentRestoreResult>;
  /** Denies future restores of one capture. Does not delete ciphertext. */
  revoke(request: LifecycleRequest<Context>): Promise<RevokeResult>;
  /** Revokes, then deletes the capture's ciphertext from the live store. Not erasure. */
  deleteCaptureCiphertext(request: LifecycleRequest<Context>): Promise<DeleteCiphertextResult>;
  /** Reports whether an attempt committed. Never returns restored fields. */
  resolveAttempt(request: ResolveAttemptRequest<Context>): Promise<ResolveAttemptResult>;
  /** Releases this instance. Revokes nothing, deletes nothing, and closes no store or provider. */
  close(): Promise<void>;
}
