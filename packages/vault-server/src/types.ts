import type { AuditHook, CaptureOptions, CaptureResult, VaultLimits, VaultOptions } from "@redact-secret/vault";
import type { DenialReason, VaultErrorCode } from "@redact-secret/vault";

import type { ServerVaultErrorCode } from "./errors.js";

/**
 * Reference signatures from
 * docs/decisions/2026-09-27-define-server-authority-interface.md (S1,
 * accepted for the contract only). Reproduced field-for-field: this package
 * is the first concrete implementation of that contract (S2, #16).
 */

/** Opaque, application-issued identity. Carries no server authority by itself. */
export interface Principal {
  readonly id: string;
  readonly tenant: string;
  /**
   * Optional descriptive claims (roles, scopes). Advisory only — a
   * ServerReleasePolicy decides what they mean. Never derived from model or
   * tool output.
   */
  readonly attributes?: Readonly<Record<string, string>>;
}

/**
 * Resolves the trusted principal for one restore call from request-scoped,
 * server-trusted context that the *consuming application* already verified
 * (a validated session, an mTLS client identity, a service-to-service
 * credential, ...). `Context` is the consumer's own type: this interface
 * does not import, wrap, or assume OAuth, OIDC, SAML, or any specific
 * session or JWT library.
 *
 * Must throw or reject rather than return a partial or best-effort
 * Principal. A resolver that cannot establish trust MUST leave the restore
 * denied ("unauthenticated"); it must never default to an anonymous or
 * shared principal.
 */
export type PrincipalResolver<Context = unknown> = (
  context: Context,
) => Principal | Promise<Principal>;

/** Generalizes `ReleaseRequest` with principal, tenant, source, and purpose. */
export interface RestoreDecisionInput {
  readonly principal: Principal;
  /**
   * Resolved tenant of the requesting principal. Usually `principal.tenant`;
   * kept separate so a trusted admin/support-tooling flow can state it
   * explicitly without redefining Principal.
   */
  readonly tenant: string;
  readonly source: {
    /** Which capture issued the entry (mirrors the vault's `captures`). */
    readonly captureId: string;
    /** Tenant that owns the captured value. */
    readonly issuedTenant: string;
    /** Optional session/conversation binding beyond captureId. */
    readonly sessionId?: string;
  };
  readonly sink: string;
  readonly path: string;
  /**
   * Required. No default purpose; a resolver or policy that cannot
   * establish one must deny ("missing-purpose"), never substitute a
   * wildcard.
   */
  readonly purpose: string;
  /** Core finding type of the retained value. Descriptive only — mirrors `ReleaseRequest.type`. */
  readonly type: string;
  readonly occurrences: number;
  readonly totalOccurrences: number;
  readonly used: number;
  readonly maxUses: number;
  /** Opaque identifier of the policy in effect, for a policy that wants to pin itself to the revision active at issuance. */
  readonly policyRevision?: string;
  readonly requestedAt: number;
}

export type PolicyDecision =
  | { readonly allow: true }
  | { readonly allow: false; readonly reason: ServerDenialReason };

/**
 * Evaluated fresh for every occurrence of every path in a restore request —
 * never cached from an earlier grant or an earlier call. May be sync or
 * async. A rejection, a thrown exception, or a non-conforming return value
 * is denial ("policy-evaluation-error"); the interface has no allow-on-error
 * mode.
 */
export type ServerReleasePolicy = (
  input: RestoreDecisionInput,
) => PolicyDecision | Promise<PolicyDecision>;

export type ServerDenialReason =
  | DenialReason
  | "unauthenticated" // no trusted principal could be resolved
  | "tenant-mismatch" // principal's tenant does not match the source's issuing tenant
  | "missing-purpose" // purpose absent, or not permitted for this sink/path
  | "revoked" // explicit revocation, distinct from "unknown-token" (see below)
  | "stale-policy" // policy revision changed since issuance, for a policy that binds to one
  | "rate-limited" // consumer-defined quota or backpressure control
  | "policy-evaluation-error" // the policy threw, rejected, or timed out — always a denial, never allow
  // Persistent profile only (docs/specs/persistent-vault.md §8.3):
  | "integrity-failure" // a stored record did not authenticate for the trusted scope
  | "key-unavailable" // the key provider could not unwrap the capture's data key
  | "attempt-mismatch" // the attempt identifier was already used for a different request
  | "attempt-already-committed"; // the attempt already committed; its output is never sent again

export type ServerAuditOperation =
  | "resolve-principal"
  | "restore"
  | "revoke"
  | "policy-error"
  // Persistent profile only:
  | "capture"
  | "delete-ciphertext"
  | "resolve-attempt";

export interface ServerAuditEvent {
  readonly operation: ServerAuditOperation;
  readonly outcome: "committed" | "denied" | "failed";
  readonly at: number;
  /** Application-defined opaque identifier. MUST NOT be derived from, or contain, a restored value. */
  readonly principalId?: string;
  readonly tenant?: string;
  readonly sink?: string;
  readonly path?: string;
  readonly purpose?: string;
  readonly reason?: ServerDenialReason;
  readonly code?: VaultErrorCode | ServerVaultErrorCode;
  /** Entries created, consumed, or removed by this operation. */
  readonly entries?: number;
  readonly policyRevision?: string;
  /** Caller/transport correlation id. Opaque; never restored content. */
  readonly requestId?: string;
  /** Persistent profile only: the opaque capture identifier of a lifecycle operation. */
  readonly captureId?: string;
  /** Persistent profile only: the opaque attempt identifier of a restore. */
  readonly attemptId?: string;
}

export type ServerAuditHook = (event: Readonly<ServerAuditEvent>) => void;

// --- This package's own surface: how a consumer opens and drives a server
// vault. Not part of the S1 ADR (which stops at the injection points above);
// these shapes are #16's own implementation, reusing @redact-secret/vault's
// CaptureOptions/CaptureResult/VaultLimits unchanged wherever the meaning is
// identical.

export interface ServerCaptureOptions extends CaptureOptions {
  /**
   * Tenant that owns the value(s) retained by this capture. Recorded
   * against every token this capture issues and compared against the
   * resolved principal's tenant on every later restore ("tenant-mismatch").
   * The application supplies this from its own already-authenticated
   * capture-time context; capture itself is not gated by a
   * `PrincipalResolver` in this package (only restore is, per #16's
   * acceptance criteria) — an application that also wants capture-time
   * authentication composes its own check before calling `capture`.
   */
  readonly issuedTenant: string;
}

export interface ServerRestoreRequest<Context = unknown> {
  /** Passed verbatim to `PrincipalResolver`. */
  readonly context: Context;
  /**
   * Explicit tenant for a trusted admin/support-tooling flow. Defaults to
   * the resolved principal's own tenant.
   */
  readonly tenant?: string;
  readonly sink: string;
  readonly purpose: string;
  /** Optional session/conversation binding, mirrored onto every decision tuple's `source.sessionId`. */
  readonly sessionId?: string;
  /** The captures this output may draw from, by `captureId`. Required and non-empty. */
  readonly captures: readonly string[];
  /** Field path → text that may contain issued tokens. */
  readonly fields: Readonly<Record<string, string>>;
  /** Caller/transport correlation id, mirrored onto audit events. Never restored content. */
  readonly requestId?: string;
}

export interface ServerRestoreResult {
  /** The same paths as the request, with issued tokens replaced. */
  readonly fields: Readonly<Record<string, string>>;
  /** Token occurrences replaced. */
  readonly restored: number;
  readonly principalId: string;
  readonly tenant: string;
}

export interface ServerVaultStats {
  readonly entries: number;
  readonly captures: number;
  readonly revokedCaptures: number;
  readonly disposed: boolean;
}

export interface ServerVault<Context = unknown> {
  /**
   * The wrapped vault's `piiActivation`: the core's canonical PII activation
   * identity observed at creation, or `null` when the installed core has no
   * PII surface (beta.9).
   */
  readonly piiActivation: string | null;
  capture(input: string, options: ServerCaptureOptions): Promise<CaptureResult>;
  restore(request: ServerRestoreRequest<Context>): Promise<ServerRestoreResult>;
  /** Removes every entry of one capture and tombstones it so a later restore reports "revoked". */
  revoke(captureId: string): Promise<number>;
  dispose(): Promise<void>;
  stats(): Promise<ServerVaultStats>;
}

export interface ServerVaultOptions<Context = unknown> {
  readonly resolvePrincipal: PrincipalResolver<Context>;
  readonly policy: ServerReleasePolicy;
  readonly onAudit?: ServerAuditHook;
  /**
   * Forwarded unchanged to the wrapped `@redact-secret/vault` instance's own
   * `onAudit`: its bare capture/restore/revoke/dispose storage-layer events,
   * distinct from this package's own richer `onAudit` (principal/tenant/
   * purpose-aware, §5 of the ADR). Most consumers want both: this one for a
   * low-level storage audit trail, `onAudit` for the security/access one.
   */
  readonly onVaultAudit?: AuditHook;
  readonly limits?: Partial<VaultLimits>;
  readonly now?: () => number;
  /**
   * Opaque revision stamped onto every capture and echoed on its decision
   * tuples' `policyRevision`. A string is used unchanged; a function is
   * called at each capture to support rotation. This package never compares
   * revisions itself (`"stale-policy"` detection, if wanted, is the
   * `ServerReleasePolicy`'s own job — see the ADR's §4 note).
   */
  readonly policyRevision?: string | (() => string);
  /**
   * How long a revoked capture's tokens are remembered as `"revoked"`
   * (rather than reported as `"unknown-token"`) after `revoke()`. Default:
   * `limits.entryTtlMs`. Bounded and swept, like every other retained
   * quantity in this package.
   */
  readonly revocationMemoryMs?: number;
  /** Deadline for one `resolvePrincipal` call. Default 5000. Exceeding it denies "unauthenticated". */
  readonly resolverTimeoutMs?: number;
  /** Deadline for one `ServerReleasePolicy` call. Default 5000. Exceeding it denies "policy-evaluation-error". */
  readonly policyTimeoutMs?: number;
  /**
   * Forwarded verbatim to `@redact-secret/vault`'s `createVault({ pii })`:
   * core PII selectors, `[]` for explicit "PII off", omitted to adopt the
   * activation the application already established. This package adds no
   * activation behavior of its own. See
   * docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md §3.
   */
  readonly pii?: VaultOptions["pii"];
  /** Forwarded verbatim to `createVault({ expectPiiActivation })`. */
  readonly expectPiiActivation?: VaultOptions["expectPiiActivation"];
}

export type { DenialReason, VaultErrorCode } from "@redact-secret/vault";
