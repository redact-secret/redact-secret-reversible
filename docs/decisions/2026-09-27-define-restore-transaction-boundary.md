---
decision_id: decision-define-restore-transaction-boundary
status: accepted
scope: repository
title: Define atomic restore checks within the vault boundary
proposed_at: 2026-09-27
decided_at: 2026-09-27
---
# Define the restore transaction boundary

> **Accepted 2026-09-27** for the single-process in-memory vault ([#9](https://github.com/redact-secret/redact-secret-reversible/issues/9)). External stores, multi-process deployments, and server authorization must each prove their own linearization point before claiming this contract ([#16](https://github.com/redact-secret/redact-secret-reversible/issues/16), [#19](https://github.com/redact-secret/redact-secret-reversible/issues/19)).

## Context

Restoration combines lookup, fresh authorization, expiry, revocation, usage budgets, and plaintext delivery. Concurrent restore/revoke requests can race, and a store may succeed while the response to the consumer is lost. A storage transaction cannot retract plaintext already handed to the application or a downstream sink. Redis serializes transaction commands but does not roll them back; other stores need their own concurrency proof. [Redis transactions](https://redis.io/docs/latest/develop/using-commands/transactions/), [PostgreSQL isolation](https://www.postgresql.org/docs/current/transaction-iso.html).

## Decision

- For one restore request, validate the entire set of requested issued entries and their authorization before returning any plaintext. Unknown, expired, revoked, wrong-session, wrong-tenant, wrong-sink/path, over-budget, or disallowed entries reject the full request; no subset is returned.
- A qualified store must define one linearization point at which restore eligibility and any usage-budget change take effect relative to concurrent restore/revoke. No other restore may consume the same one-time allowance after that point. A revoke committed before a restore's linearization point must deny it; a later revoke cannot undo an already released value.
- For capture, publish neither sanitized output nor a mapping until all staged entries are ready. Failure before the commit yields neither. For restore, all requested mappings are resolved and validated under the store's declared consistency mechanism before plaintext is returned from the vault.
- Authorization must be fresh at the release boundary. If policy/identity is served by a different system from the mapping store, the adapter must document and test its revocation window. It must not claim a single atomic authorization-and-store transaction unless one actually exists.
- TTL is a use-time validation condition. Background cleanup and backend expiration are supplementary. Persistent stores require encrypted/integrity-protected records and separately documented key ownership, backup retention, and deletion; encryption alone does not provide this transaction behavior.
- The library must document what happens when the store commits a use but the response fails or delivery status is unknown. A conservative at-most-once consumption policy is the candidate default for single-use tokens; optional retries require an explicit idempotency contract. Exact one-time versus multi-use defaults and delivery semantics remain to be selected before acceptance.

## Guarantee boundary

“All or nothing” refers to the library/store operation before it returns plaintext, including multi-token validation and any usage-budget change. It does **not** claim atomic delivery to an application callback, browser DOM, external tool, model, or network service. An already delivered value cannot be revoked retroactively. Errors and audit events disclose no plaintext or raw mapping.

## Consequences and alternatives

- The portable contract describes behavior, not Redis, PostgreSQL, a particular vault vendor, or one identity provider. An injected consumer store must pass the same conformance suite; a weaker backend cannot silently inherit the server-security claim.
- Server memory can implement the same atomic boundary with appropriate process coordination, but a multi-process deployment needs a shared mechanism or an explicitly limited single-process qualification.
- If a consumer requires guaranteed external delivery exactly once, that needs a separate application-level protocol and sink cooperation. The vault cannot provide it alone. A consumer that cannot tolerate response-loss ambiguity may keep the value redacted.
- Physical cleanup and backup erasure are separate lifecycle guarantees. Logical revocation must work even while old ciphertext exists.

## Verification before acceptance

Run concurrent restore/restore and restore/revoke, multi-token failures, policy changes, store exceptions, timeout, commit-success/response-loss, retry, process restart, replica lag, and background expiry delay. Verify no partial plaintext and correct budget state at the declared boundary for each backend. See [security research](../research/security-foundations-2026-09-27.md).

## Resolved choices (in-memory vault, alpha.1)

- **Linearization point.** Each `capture`, `restore`, `revoke`, and `dispose` is one synchronous call and linearizes at that call. JavaScript runs it to completion, so concurrent callers (promises, timers, events) observe calls in invocation order. A consumer callback invoked during an operation (core policy, `eligible`, `displayFormatter`, `releasePolicy`, `onAudit`) that re-enters the vault gets `BUSY`, so it cannot interleave a revoke or dispose with a half-validated restore.
- **Preflight.** A restore snapshots the request (own data properties only; accessors are rejected without being invoked). It then checks every occurrence in every field in this order: marker/grammar, known entry, listed source capture, expiry, sink and path grant, use budget, and last the page-local `releasePolicy` for each entry and path. Only a literal `true` allows; a throwing policy denies. Any failure throws `RESTORE_DENIED` with a coarse `reason`, consumes no budget, and returns no plaintext.
- **Budget.** Default one use per entry (at-most-once). An entry whose budget is exhausted is deleted immediately. Consumption happens in the same synchronous step that builds the returned object, so a use is consumed if and only if `restore` returns normally.
- **Response loss.** The in-process call cannot lose its response. If the application loses or fails to deliver the returned value afterward, the use is still consumed and cannot be replayed. The application may capture again from the original input if it still holds it.
- **Revocation.** A revoke before a restore denies it (`unknown-token`). A revoke after a restore removes only unconsumed entries and cannot retract released values.
- **Expiry.** Checked at use time. The default clock is `Date.now()` anchored at creation and advanced by the monotonic `performance.now()`. Observed time never decreases, even with an injected clock. Expired entries are swept at each capture, after every restore (allowed or denied), and on `stats()`; no timers run. The vault's own lifetime (`vaultTtlMs`) disposes it on the first call after expiry, including `stats()`.
- **Capture commit.** Staged entries become visible only after output validation. Every failure before that leaves `stats()` unchanged.

## Evidence

Corpus cases `preflight.all-or-nothing`, `budget.*`, `lifecycle.*`, `policy.*`, and `token.duplicate-beyond-budget`, plus runtime checks `revoke-and-restore-race-in-microtasks`, `reentrant-policy-cannot-mutate-mid-restore`, `reentrant-core-policy-fails-capture`, `audit-hook-failure-and-reentry-do-not-change-outcome`, and `restore-request-snapshot-resists-getters`, pass on Node.js and in three browser engines. Deliberately broken builds (budget check removed, expiry check removed, partial commit on formatter failure) are caught by the suite. See the [qualification record](../research/qualification-0.1.0-alpha.1.md).
