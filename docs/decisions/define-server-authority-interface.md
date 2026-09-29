---
decision_id: decision-define-server-authority-interface
status: accepted
scope: repository
title: Define the server authority interface and reference policy examples
decided_at: 2026-09-27
---
# Define the server authority interface and reference policy examples

> **Accepted 2026-09-27** for the interface contract only ([#15](https://github.com/redact-secret/redact-secret-vault/issues/15)). No implementation exists yet. `@redact-secret/vault-server` ([#16](https://github.com/redact-secret/redact-secret-vault/issues/16)), the Python server integration ([#17](https://github.com/redact-secret/redact-secret-vault/issues/17)), and the persistent-store contract ([#19](https://github.com/redact-secret/redact-secret-vault/issues/19)) build against this contract and must each pass their own conformance and qualification gates before claiming support.

## Context

`@redact-secret/vault` 0.1.0-alpha.1 already models authorization, revocation, and denial for a single-process, single-principal, in-memory scope: [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md) (#9/F4) fixes a synchronous, all-or-nothing preflight that validates every occurrence in a restore request — marker, known entry, source, expiry, sink/path grant, budget, then a page-local `releasePolicy` — before any plaintext or budget change is visible, and [decision-restore-authority-and-lifecycle](restore-authority-and-lifecycle.md) fixes that a token alone never grants authority. V3 (#13) implements this as `ReleaseGrant`, `ReleaseRequest`, `ReleasePolicy`, `DenialReason`, and `AuditEvent` in `packages/vault/src/types.ts` and `packages/vault/src/errors.ts`, enforced by `#restore` in `packages/vault/src/vault.ts:L529-L649` and audited by `#audit` at `packages/vault/src/vault.ts:L727-L734`. That model is explicitly browser/single-process scoped: ARCHITECTURE.md's "Storage and authorization" section and the [package and language decision](name-vault-packages-and-language-contract.md) already name `@redact-secret/vault-server` as the layer that adds principal, tenant, source, destination, and value-path authorization across multiple principals, without mandating one identity provider or vendor.

This ADR is S1 on the (archived) [issue roadmap](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/plans/issue-roadmap.md): it defines that server authority interface and reference policy examples so #16 (JS implementation), #17 (Python integration), and #19 (persistent-store contract) have one unambiguous starting contract instead of each inventing their own shape. F4 (#9) and F5 (#10) are closed dependencies; this ADR generalizes their accepted model rather than replacing it.

## Decision

Define, as reference TypeScript signatures (language-neutral in intent — a native Python distribution under #17 implements equivalent semantics, not this exact syntax):

1. Principal/tenant resolution as a consumer-supplied injection point.
2. A source→sink/path/purpose decision tuple that generalizes `ReleaseRequest`.
3. A policy evaluation contract: fresh per request, fail-closed, all-or-nothing.
4. An explicit denial vocabulary, extending `DenialReason` rather than replacing it.
5. An audit event shape with no field capable of carrying a restored value.
6. What is explicitly out of scope for this ADR.

None of this is exported by `@redact-secret/vault` or any published package. It is reference material for #16/#17/#19.

### 1. Principal and tenant resolution — consumer-injected, no mandated identity provider

```ts
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
```

The consuming application chooses `Context` — an HTTP request, an RPC call, a queue message — and wires its own authentication. This repository never bundles a login flow, token verifier, or user store, matching the [package and language decision](name-vault-packages-and-language-contract.md)'s "must not force one vendor's vault or the consumer's identity provider."

### 2. Decision tuple — source→sink/path/purpose

Generalizes `ReleaseRequest` (`packages/vault/src/types.ts:L43-L55`). `captureId`, `sink`, `path`, `type`, `occurrences`, `totalOccurrences`, and `used` carry the same meaning; `principal`, `tenant`, `source.issuedTenant`, `source.sessionId`, `purpose`, `maxUses`, and `policyRevision` are new.

```ts
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
```

### 3. Policy evaluation contract

```ts
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
```

Required evaluation order, mirroring `#restore` (`packages/vault/src/vault.ts:L529-L649`) with the new checks inserted:

1. Resolve principal → `unauthenticated` on failure.
2. Marker/grammar and known-entry checks → `malformed-token` / `unknown-token` (unchanged from the vault).
3. Source binding → `source`.
4. Tenant match → `tenant-mismatch`.
5. Expiry → `expired`.
6. Sink/path grant → `sink-or-path`.
7. Purpose presence → `missing-purpose`.
8. Budget → `budget`.
9. `ServerReleasePolicy` → `policy`, or a more specific `ServerDenialReason` the policy itself returns (for example `rate-limited`).

Every occurrence of every path in the whole request is checked before any plaintext is returned; one denial fails the complete request, per [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md)'s all-or-nothing preflight. No subset is ever returned.

### 4. Denial vocabulary

```ts
import type { DenialReason } from "@redact-secret/vault"; // reused verbatim, never redefined

export type ServerDenialReason =
  | DenialReason
  | "unauthenticated"       // no trusted principal could be resolved
  | "tenant-mismatch"       // principal's tenant does not match the source's issuing tenant
  | "missing-purpose"       // purpose absent, or not permitted for this sink/path
  | "revoked"                // explicit revocation, distinct from "unknown-token" (see below)
  | "stale-policy"          // policy revision changed since issuance, for a policy that binds to one
  | "rate-limited"          // consumer-defined quota or backpressure control
  | "policy-evaluation-error"; // the policy threw, rejected, or timed out — always a denial, never allow
```

`"revoked"` deliberately diverges from the in-memory vault, which collapses pre-restore revocation into `"unknown-token"` because the entry is deleted outright (see [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md), "Revocation"). A server audit trail benefits from distinguishing "never existed / forged" from "existed, was revoked" for incident response. A qualified server store that retains a short-lived revocation tombstone MAY report `"revoked"`; a store that does not keep one MAY report `"unknown-token"` instead. Both are conformant — this ADR does not mandate tombstone retention, only that the vocabulary exists for stores that choose to keep one.

### 5. Audit event shape — no plaintext-capable field, by construction

```ts
export type ServerAuditOperation = "resolve-principal" | "restore" | "revoke" | "policy-error";

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
  readonly code?: VaultErrorCode;
  /** Entries created, consumed, or removed by this operation. */
  readonly entries?: number;
  readonly policyRevision?: string;
  /** Caller/transport correlation id. Opaque; never restored content. */
  readonly requestId?: string;
}

export type ServerAuditHook = (event: Readonly<ServerAuditEvent>) => void;
```

Every field is a fixed enum, a count, a timestamp, or an *identifier* the application itself defined at the trust boundary (`principalId`, `tenant`, `sink`, `path`, `purpose`, `requestId`) — never a free-text `message`, `description`, or `value` field. There is nowhere in this type to put a restored value, on purpose, matching ARCHITECTURE.md's "Audit hooks expose only bounded safe metadata and outcome codes." A consumer who separately logs a raw string next to this event breaks the contract out of band; the type itself cannot stop that, but it gives the misuse nowhere to live inside the audited object. Exceptions thrown by a `ServerAuditHook` must never change an operation's outcome, mirroring `#audit` (`packages/vault/src/vault.ts:L727-L734`).

### 6. Consumer injection points, summarized

- `PrincipalResolver<Context>` — identity and session verification. No mandated provider.
- `ServerReleasePolicy` — the authorization decision. No mandated rule engine, RBAC/ABAC model, or policy language.
- `ServerAuditHook` — where audit events go. No mandated logging or SIEM sink.
- Storage — deferred entirely to [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md)'s "qualified store" contract and P1/#19, #20. This ADR assumes that split unchanged and adds no new persistence requirement.

## Reference policy examples

Illustrative only. Synthetic tenant/purpose/sink literals; no real deployment logic; not exported by any package.

```ts
/**
 * deny-by-default: nothing is allowed unless another rule explicitly says
 * so. The recommended base for every deployment.
 */
const denyByDefault: ServerReleasePolicy = () => ({ allow: false, reason: "policy" });

/** allow-same-tenant-only: never allow restoration across a tenant boundary. */
const allowSameTenantOnly: ServerReleasePolicy = (input) =>
  input.tenant === input.source.issuedTenant
    ? { allow: true }
    : { allow: false, reason: "tenant-mismatch" };

/**
 * purpose-limited: an allowlist of (sink, purpose) pairs — for example, a
 * support-reply sink may only be used for a declared support purpose, and
 * only within the same tenant.
 */
const SUPPORT_SINK_PURPOSES = new Set(["support-reply-purpose-synthetic"]);
const purposeLimited: ServerReleasePolicy = (input) => {
  if (input.sink !== "support-ticket-reply-sink-synthetic") {
    return { allow: false, reason: "sink-or-path" };
  }
  if (!SUPPORT_SINK_PURPOSES.has(input.purpose)) {
    return { allow: false, reason: "missing-purpose" };
  }
  return input.tenant === input.source.issuedTenant
    ? { allow: true }
    : { allow: false, reason: "tenant-mismatch" };
};

/** compose: a deployment typically chains rules; the first denial wins. */
const allOf =
  (...policies: readonly ServerReleasePolicy[]): ServerReleasePolicy =>
  async (input) => {
    for (const policy of policies) {
      const decision = await policy(input);
      if (!decision.allow) return decision;
    }
    return { allow: true };
  };
```

## Negative and adversarial examples

Synthetic-only decision-tuple inputs and the outcome a conformant server must produce. None resembles a real credential, tenant, or purpose.

```ts
// Cross-tenant read: the requesting principal's tenant differs from the
// tenant that captured the value.
const crossTenantRead: RestoreDecisionInput = {
  principal: { id: "user-synthetic-042", tenant: "tenant-northwind-synthetic" },
  tenant: "tenant-northwind-synthetic",
  source: { captureId: "cap_synthetic_1", issuedTenant: "tenant-acme-synthetic" },
  sink: "support-ticket-reply-sink-synthetic",
  path: "body",
  purpose: "support-reply-purpose-synthetic",
  type: "jwt",
  occurrences: 1,
  totalOccurrences: 1,
  used: 0,
  maxUses: 1,
  requestedAt: 1_700_000_000_000,
};
// allowSameTenantOnly(crossTenantRead) => { allow: false, reason: "tenant-mismatch" }

// Missing purpose: field empty, or not in the sink's allowed set.
const missingPurpose: RestoreDecisionInput = {
  ...crossTenantRead,
  tenant: "tenant-acme-synthetic",
  purpose: "",
};
// purposeLimited(missingPurpose) => { allow: false, reason: "missing-purpose" }

// Revoked token reuse: the entry existed and was later revoked. Preflight
// denies before any ServerReleasePolicy runs (§3, step 2/3), independent of
// which policy is configured.
const revokedReuse: RestoreDecisionInput = { ...crossTenantRead, tenant: "tenant-acme-synthetic" };
// A qualified server preflight denies: { allow: false, reason: "revoked" }
// (or "unknown-token" for a store without a revocation tombstone — see §4)
```

All fixture literals above use an unmistakably synthetic `*-synthetic*` shape, consistent with CONVENTIONS.md's security-sensitive-change rule and this repository's security boundary: no plaintext secret value, real credential, or real tenant/principal identifier appears anywhere in this ADR.

## Out of scope

Explicitly **not** covered by this ADR:

- A concrete `@redact-secret/vault-server` implementation, HTTP/RPC transport, or wire format (#16).
- Native Python, or any non-JavaScript, server integration; this ADR states language-neutral *intent*, not a Python API (#17).
- Persistent-store encryption, key ownership, backup, or the store's own linearization proof — unchanged from [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md)'s "qualified store" contract (#19, #20).
- A specific identity provider, session library, RBAC/ABAC model, policy language, or rate-limiter implementation. The interface only names the injection points.
- A concrete multi-process/distributed consistency proof for `ServerReleasePolicy` evaluation; that remains store-specific per the transaction-boundary ADR.
- Arbitrary-text restore, streaming, and Worker-mode server use — still open per the [threat model](../specs/threat-model.md).

## Threat boundary, failure behavior, and residual risk

- **Threat boundary added over the in-memory vault:** a different authenticated principal, a cross-tenant request, a stale grant surviving a policy or revocation change, and a resolver or policy that is unreachable, slow, or throws.
- **Failure behavior:** every injection point (`PrincipalResolver`, `ServerReleasePolicy`, `ServerAuditHook`) fails closed. An unresolved principal, a thrown, rejected, or timed-out policy, or any decision other than `{allow: true}` denies the entire restore request with no partial plaintext, mirroring the in-memory vault's all-or-nothing preflight ([decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md)). A `ServerAuditHook` exception never changes the outcome.
- **Residual risk:** this interface cannot verify that a consumer's `PrincipalResolver` actually authenticates the caller, that its `ServerReleasePolicy` is logically sound, or that its audit sink is durable — those remain the implementing package's (#16/#17) and the deploying application's responsibility, qualified independently. A policy bug that always returns `{allow: true}` is indistinguishable from `denyByDefault` at the type level; only #16's conformance corpus and adversarial tests can catch it. Multi-process policy-revision consistency is explicitly deferred to the store contract.

## Core compatibility

This ADR adds no dependency on `@redact-secret/core` and does not change the pinned `0.1.0-beta.9` compatibility declared in the [qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-0.1.0-alpha.1.md). It operates entirely downstream of vault-issued tokens and captures; the core's detection, policy, and placeholder-formatting surface is unaffected. The one-way dependency direction is preserved: this ADR is consumed by `redact-secret-reversible` packages only; the core, adapters, and detection benchmarks acquire no dependency on it.

## Consequences

- #16 (`vault-server`, JS, in-memory) implements `PrincipalResolver`, `ServerReleasePolicy` evaluation in the order given in §3, `ServerDenialReason`, and `ServerAuditEvent` against this contract and the shared conformance corpus, and coordinates concurrent restore/revoke per [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md).
- #17 (Python) implements the equivalent semantics natively; Python type names may differ, but the decision tuple, denial vocabulary, and fail-closed behavior must match.
- #19 (persistent store) inherits [decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md)'s store contract unchanged; this ADR adds no new persistence requirement.
- A future conformance corpus version adds the server-only case classes named in [conformance/README.md](../../conformance/README.md): principal-resolution failure, cross-tenant, missing/invalid purpose, revoked-vs-unknown-token, policy-evaluation-error/timeout, and policy-revision staleness.

## Alternatives considered

- Reusing the in-memory vault's `ReleasePolicy` (`(request: ReleaseRequest) => boolean`) unchanged on the server: rejected. It is synchronous, returns a bare boolean with no denial reason, and has no principal/tenant/purpose fields — it cannot express *why* a server-side request was denied, which audit and incident-response need.
- A single opaque `authorize(request): boolean` with no structured decision tuple: rejected for the same reason a universal `restore(text)` with no destination context was rejected in [decision-restore-authority-and-lifecycle](restore-authority-and-lifecycle.md) — a boolean with no context is an unsafe default.
- Mandating a specific identity provider (OAuth/OIDC) or policy engine (OPA, Cedar, ...) in the interface: rejected; this repository does not own identity or policy-engine choice for every consumer, per the [package and language decision](name-vault-packages-and-language-contract.md)'s "must not force one vendor's vault or the consumer's identity provider."
- Collapsing `"revoked"` into `"unknown-token"` to keep exact parity with the in-memory vault: considered, but rejected as the one server-specific addition worth diverging on — see §4.

## Open questions

- Whether `ServerReleasePolicy` needs a per-request timeout parameter in the type itself, or whether that is purely an implementation (#16) concern.
- The exact multi-process/distributed linearization mechanism for policy-revision consistency, left to #19's store contract.
- ~~Whether Python's equivalent (#17) should mirror these names one-to-one or adopt idiomatic Python naming while preserving the same fields — left for #17 to decide and document.~~ **Resolved by #17** (`packages/vault-server-py`, renamed `packages/vault-py` / `redact-secret-vault` by #56 before any PyPI publish): idiomatic Python (`dataclass`/`enum.Enum`/`typing.Protocol`, snake_case fields), not a one-to-one name mirror. Same decision-tuple fields, same nine-step preflight order, same `ServerDenialReason` string values, same audit event shape. Full inventory, boundary decision (no native Python core exists; capture uses a Node.js service boundary to `@redact-secret/core`), and candid JS/Python differences: [docs/research/python-server-integration-2026-09-27.md](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/python-server-integration-2026-09-27.md).
