---
decision_id: decision-implement-vault-server-in-memory
status: accepted
scope: package
title: Implement @redact-secret/vault-server's in-memory backend and linearization point
decided_at: 2026-09-27
---
# Implement `@redact-secret/vault-server`'s in-memory backend and linearization point

> **Accepted 2026-09-27** for `@redact-secret/vault-server` 0.1.0-alpha.1 ([#16](https://github.com/redact-secret/redact-secret-reversible/issues/16), S2). Records the concrete choices this package makes where [the server authority interface ADR](2026-09-27-define-server-authority-interface.md) (S1, #15) deliberately left implementation open. Python ([#17](https://github.com/redact-secret/redact-secret-reversible/issues/17)) and persistent stores ([#19](https://github.com/redact-secret/redact-secret-reversible/issues/19)) are not covered and must each make and document their own equivalent choices.

## Context

S1 fixes `PrincipalResolver`, `RestoreDecisionInput`, `ServerReleasePolicy`, `ServerDenialReason`, `ServerAuditEvent`, and the required nine-step evaluation order, but explicitly states no implementation and defers: a linearization point of the implementation's own, `"stale-policy"` detection, per-request timeouts, and the exact multi-process consistency mechanism (deferred further to #19). This package is the first concrete implementation and must resolve each of those.

## Decision

### Storage: a metadata shadow over the wrapped in-memory vault, not a reimplementation

`@redact-secret/vault-server` wraps one `@redact-secret/vault` instance rather than reimplementing token minting, value retention, or the atomic restore/budget mechanics F4 already qualified. But `#restore`'s single opaque call has no hook point between its own checks (source, expiry, sink/path, budget — unchanged from the vault, per S1 §3 step 2) to insert the ADR's new tenant-match (step 4) and purpose (step 7) checks in the required order. Resolving this required one of: (a) folding the new checks into the wrapped vault's own `releasePolicy` hook, which only runs *after* budget (violating the required order and leaking, via denial reason, whether an unauthorized caller's token was even over budget); or (b) tracking enough metadata in this package to preflight the full order itself, calling the wrapped vault only once every step has already passed, as the sole source of truth for the final substitution and budget consumption.

(b) is what this package does. At `capture()`, alongside delegating to the wrapped vault (which remains the only place a plaintext value is ever held), this package records — keyed by the same issued token the vault's own `CaptureResult` returns — the issuing `captureId`, the caller-supplied `issuedTenant`, the sink/path grants, the use budget, and the expiry the vault itself reports. **Never the plaintext value.** `restore()` preflights the full nine-step order against this shadow; only if every occurrence of every path clears it does it call the wrapped vault's own `restore()`, which independently re-validates and performs the actual substitution. A denial there despite the shadow preflight passing is treated as this package's own bug (`INVARIANT_VIOLATION`), not a legitimate authorization outcome — fail closed either way, no partial plaintext.

### Linearization: an async FIFO queue with per-callback timeouts, not a busy-reject

The in-memory vault's own contract (F4) achieves "one operation at a time" for free: each `capture`/`restore`/`revoke`/`dispose` is one synchronous JavaScript call, so true concurrency is impossible except via a callback re-entering the vault mid-call, which it rejects with `BUSY`. `PrincipalResolver` and `ServerReleasePolicy` are async and may do real I/O (an identity provider, a policy engine), so two `restore()`/`revoke()` calls on one `ServerVault` genuinely can overlap in time — the exact "coordinate concurrent restore/revoke" requirement S2's acceptance criteria names.

This package defines its own linearization point: every `capture`/`restore`/`revoke`/`dispose`/`stats` call is appended to a single FIFO promise chain, so at most one is ever executing and each fully commits or denies before the next begins. A call arriving after another is in flight *waits its turn* rather than being rejected — this is deliberately different from the wrapped vault's synchronous `BUSY`-on-reentrancy, because rejecting genuinely-concurrent external callers (not reentrant callback misuse) would make coordinating them the caller's problem instead of this package's. The risk this trades in — a slow or reentrant `PrincipalResolver`/`ServerReleasePolicy` holding the queue indefinitely — is bounded by `resolverTimeoutMs`/`policyTimeoutMs` (default 5000 each, per-call, S1's own open question "resolved" as an implementation concern): exceeding either fails the operation closed (`unauthenticated` / `policy-evaluation-error`) rather than hanging, and converts a reentrant deadlock into a bounded denial instead of a stuck process.

**Consequence:** calls are serialized, not parallelized, on one `ServerVault` instance. This is a throughput/availability trade-off, not a security gap — an application needing concurrent throughput retries on denial or shards by tenant across multiple instances.

### Revocation memory: a bounded tombstone, not indefinite retention

S1 §4 permits, but does not require, distinguishing `"revoked"` from `"unknown-token"` for a store that "retains a short-lived revocation tombstone." This package does: `revoke()` moves a capture's tokens into a bounded-lifetime tombstone (default `limits.entryTtlMs`, configurable via `revocationMemoryMs`) instead of deleting them outright, so a restore attempt against a recently-revoked token reports `"revoked"` for that window and `"unknown-token"` once it ages out and is swept. Both are conformant per S1.

### Audit: two hooks, not one broadened vocabulary

S1's `ServerAuditOperation` is exactly `"resolve-principal" | "restore" | "revoke" | "policy-error"` — it does not cover this package's own `capture`/`dispose` lifecycle, which is out of S1's scope (server-authority *restore*-time authorization only). Rather than widen the ADR's fixed vocabulary without necessity, this package exposes `onVaultAudit`, forwarded unchanged to the wrapped `@redact-secret/vault` instance's own `onAudit` (its existing `AuditEvent` shape already covers `capture`/`restore`/`revoke`/`dispose`), alongside `onAudit: ServerAuditHook` using S1's `ServerAuditEvent` verbatim for the four operations it names. Both are zero-plaintext by construction; most consumers wire both.

### `"stale-policy"` remains the policy's own responsibility

Per S1 §4's note, this package stamps a `policyRevision` (a string, or the result of a consumer-supplied function called at each capture) onto every capture and echoes it on that capture's decision tuples, but never compares revisions itself. Detecting staleness — and choosing to deny `"stale-policy"` — is left entirely to the injected `ServerReleasePolicy`, consistent with S1 leaving the exact mechanism open.

## Threat boundary, failure behavior, and residual risk

Unchanged from S1's own threat boundary and failure-behavior sections, with this package's additions:

- **Added threat surface:** a `PrincipalResolver`/`ServerReleasePolicy` that is slow enough to matter for availability (bounded by the timeouts above), and the shadow-registry/wrapped-vault drift case (`INVARIANT_VIOLATION`, always fails closed).
- **Residual risk:** single-process only (no distributed linearization — deferred to #19); `revoke()` is not itself principal-gated (mirrors the wrapped vault's own trusted-operator `revoke`); serialized throughput is a scaling trade-off an application must plan around; this package cannot verify a consumer's injected `PrincipalResolver`/`ServerReleasePolicy` is logically sound, only exercise it against adversarial tests.

## Core compatibility

Adds no direct dependency on `@redact-secret/core`. Depends on `@redact-secret/vault@0.1.0-alpha.1` unchanged, whose core peer range remains pinned exactly to `0.1.0-beta.9` (see the [qualification record](../research/qualification-0.1.0-alpha.1.md)). This ADR changes no core compatibility statement.

## Out of scope

Persistent storage and its own consistency proof (#19), Python or any non-JavaScript server integration (#17), principal-gating `revoke()` itself, multi-process/distributed deployments, streaming, and arbitrary-text restore — all unchanged from S1's own "out of scope" section.

## Alternatives considered

- Folding tenant/purpose checks into the wrapped vault's existing `releasePolicy` hook: rejected — it runs after the vault's own budget check, which would report `budget` before `tenant-mismatch`/`missing-purpose` for a request that fails both, violating S1 §3's required order and, for `budget` specifically, disclosing usage information to a caller who was never entitled to know the token existed.
- Rejecting concurrent calls immediately with `BUSY` (mirroring the wrapped vault's reentrancy behavior exactly): rejected as the primary mechanism — it would make ordinary concurrent load a caller-visible failure mode rather than something this package coordinates, which is what S2's acceptance criteria ask for. `BUSY`-style rejection was kept only implicitly, as the bounded timeout's failure outcome for a genuinely stuck callback.
- Unbounded revocation tombstone retention: rejected as inconsistent with every other retained quantity in this repository being explicitly bounded (`VaultLimits`); `revocationMemoryMs` is swept the same way expired entries are.

## Open questions

- Whether a future multi-process deployment of this same in-memory model (sharing one Node.js process across workers via a shared-memory or IPC mechanism) is worth qualifying before #19's persistent-store contract lands, or whether it should wait for that contract.
- Whether `revoke()` should eventually accept its own `context` for principal resolution, once a concrete consumer need for authorizing *who* may revoke is identified.
