# `@redact-secret/vault-server` reference

Evaluation order, concurrency, audit, and the full API of the default, in-memory entry of [`@redact-secret/vault-server`](../../packages/vault-server/README.md). The persistent entry is in the [persistent server guide](../guides/persistent-server.md).

## Versions

`0.1.0-alpha.2` was this package's first published version. The npm `latest` and `beta` tags of both `@redact-secret/vault-server` and `@redact-secret/vault` point at `0.1.0-beta.3`. Exact versions are still recommended while the packages are beta, because each release pins exact `@redact-secret/vault` and `@redact-secret/core` versions.

On `main` this package is `0.1.0-beta.4`, **unpublished**. It adds the opt-in [persistent profile](../guides/persistent-server.md) at `@redact-secret/vault-server/persistent` (alpha) and a dependency on `@redact-secret/vault-contracts`; the default entry described below is unchanged. The sections up to "Persistent profile" describe the default, in-memory entry.

## Supported, and not

| | Status in 0.1.0-beta.3 |
| --- | --- |
| Server runtimes | Node.js 20, 22, 24 (same as `@redact-secret/vault`), by this package's own adversarial suite and the [beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-core-0.1.0-beta.10.md) |
| Storage backend, default entry (`createServerVault`) | In-memory only, single process |
| Persistent profile (`./persistent`, on `main`, unpublished, **alpha**) | Implemented. This package contains no store, driver, cipher, or key provider: the application injects them. Qualified with [`@redact-secret/store-postgres`](../../packages/store-postgres/README.md) on PostgreSQL 17.11 (single primary, or primary with one synchronous standby), Node.js 22, and the local key provider; tested over the non-durable `@redact-secret/store-memory` on Node.js 20, 22, 24. Nothing else: see the [qualification record](../research/qualification-persistence-0.1.0-alpha.1.md) |
| Python | **Not in this package**, and no Python persistence exists. A research-grade native Python implementation of the same contract is [`redact-secret-vault`](../../packages/vault-py/README.md) ([#17](https://github.com/redact-secret/redact-secret-vault/issues/17)) |
| Streaming, arbitrary-text `restore(text)` | **Not supported**, matching `@redact-secret/vault` |
| Browser | **Not a target**, for either entry. This package assumes a server trust boundary (`PrincipalResolver` reads request-scoped, already-authenticated context); it is Node.js-only and is never bundled for a browser |

## Evaluation order

Every occurrence of every path in a restore request is checked, in this exact order, before any plaintext or budget change is visible — one violation fails the whole request:

1. Resolve principal (`unauthenticated` on failure, malformed return, or timeout).
2. Marker/grammar and known-entry — `malformed-token`, `unknown-token`, or `revoked` for a token whose capture was recently revoked (a bounded memory window; see `revocationMemoryMs`).
3. Source binding (`source`).
4. Tenant match against the capture's `issuedTenant` (`tenant-mismatch`).
5. Expiry (`expired`).
6. Sink/path grant (`sink-or-path`).
7. Purpose presence — a non-empty `purpose` is required (`missing-purpose`).
8. Use budget (`budget`).
9. `ServerReleasePolicy`, evaluated fresh for this exact occurrence (`policy`, or a more specific reason the policy returns; a throw, rejection, timeout, or malformed return is `policy-evaluation-error`, never allow-on-error).

Only after every occurrence of every path clears all nine steps does this package call into the wrapped `@redact-secret/vault` instance, which is the source of truth for token → value substitution and atomically consumes budget at its own linearization point.

## Concurrency

Every `capture`/`restore`/`revoke`/`dispose`/`stats` call on one `ServerVault` is queued onto a single FIFO chain: at most one is ever executing, and each fully commits or denies before the next begins — including across the `await`s a `PrincipalResolver` or `ServerReleasePolicy` introduces (which the underlying, synchronous `@redact-secret/vault` never has to contend with). This is this package's own linearization point, generalizing [the transaction-boundary ADR](../decisions/define-restore-transaction-boundary.md)'s contract to genuinely concurrent async operations:

- A `revoke()` queued before a `restore()` call denies it (`revoked`), never the other way around.
- A slow or malicious `PrincipalResolver`/`ServerReleasePolicy` holds the queue for at most `resolverTimeoutMs`/`policyTimeoutMs` (default 5000 each); exceeding it fails closed (`unauthenticated` / `policy-evaluation-error`) rather than hanging or, worse, letting a reentrant call from inside that same callback deadlock the queue.
- **Throughput note:** calls are serialized, not parallelized. An application needing concurrent throughput should retry on transient denial or partition by tenant across multiple `ServerVault` instances; this is a scaling trade-off, not a security gap — the ordering guarantee above holds regardless of load.

## What this package tracks, and what it does not

To check tenant/purpose/source *before* any commit — in the order above — this package keeps a small metadata shadow per issued token: which capture issued it, its `issuedTenant`, its sink/path grants, its use budget, and its expiry. **Never the plaintext value**, which stays inside the wrapped `@redact-secret/vault` instance, the sole source of truth for capture, token minting, value retention, and the final atomic substitution + budget consumption this package delegates to on every successful preflight.

## Audit

Two audit hooks, both optional and both receiving only bounded, fixed-shape, non-plaintext-capable events (per the ADR's §5):

- `onAudit(event: ServerAuditEvent)` — this package's own security/access trail: `resolve-principal` (denied), `restore` (committed/denied/failed), `revoke` (committed), `policy-error` (failed). Field-for-field the ADR's `ServerAuditEvent`.
- `onVaultAudit(event)` — forwarded unchanged to the wrapped vault's own `onAudit`: its bare `capture`/`restore`/`revoke`/`dispose` storage-layer events. Most consumers want both.

Exceptions thrown by either hook never change an operation's outcome.

## API

`createServerVault(options) → Promise<ServerVault>`. Options: `resolvePrincipal` (required), `policy` (required), `onAudit`, `onVaultAudit`, `limits` (partial `VaultLimits`, same shape as `@redact-secret/vault`), `now()` (for tests), `policyRevision` (string or a function, stamped per capture), `revocationMemoryMs` (default `limits.entryTtlMs`), `resolverTimeoutMs`/`policyTimeoutMs` (default 5000 each), `pii` and `expectPiiActivation` (forwarded as given to `@redact-secret/vault`'s `createVault`. This package adds no PII activation behavior of its own. See the vault README's "PII findings" section).

`server.piiActivation → string | null`. The wrapped vault's observed core PII activation identity. It is `null` on a core without PII support.

`server.capture(input, options) → Promise<CaptureResult>`. Options extend `@redact-secret/vault`'s `CaptureOptions` with a required `issuedTenant`. The PII retention allowlist `pii: { retain }` is forwarded as given. Result is the vault's own unmodified `CaptureResult`. A vault capture failure rejects with `VAULT_FAILURE` carrying the vault's `vaultCode` and, for `CORE_FAILURE`, the core's `coreCode`: for example `INVALID_PLACEHOLDER` for a `displayFormatter` label that reproduces a finding's matched text, or `FINDING_LIMIT_EXCEEDED` when findings (PII included) exceed `limits.maxFindings`.

`server.restore({ context, tenant?, sink, purpose, sessionId?, captures, fields, requestId? }) → Promise<{ fields, restored, principalId, tenant }>`. Throws `VaultServerError` with code `RESTORE_DENIED` and one of the reasons above, or `INVALID_ARGUMENT` for a structurally malformed request (checked before principal resolution, and never audited as a security decision).

`server.revoke(captureId) → Promise<number>`, `server.dispose() → Promise<void>` (idempotent), `server.stats() → Promise<{ entries, captures, revokedCaptures, disposed }>`.

Error codes: `INVALID_ARGUMENT`, `RESTORE_DENIED`, `INVARIANT_VIOLATION` (the shadow registry and the wrapped vault disagreed — a bug in this package, always fails closed), `VAULT_FAILURE` (wraps a `@redact-secret/vault` `VaultError`, exposed as `.vaultCode`; when that is `CORE_FAILURE`, the core's fixed code, for example `PII_ACTIVATION_CONFLICT`, is exposed as `.coreCode`), `DISPOSED`.

From `0.1.0-beta.4` (on `main`, unpublished), the `ServerVaultErrorCode`, `ServerDenialReason`, and `ServerAuditOperation` types also contain the members the [persistent profile](../guides/persistent-server.md) uses: codes `UNSUPPORTED_STORE`, `STORE_UNAVAILABLE`, `STORE_QUARANTINED`, `COMMIT_AMBIGUOUS`, `RESTORE_CONFLICT`, `CLOCK_SKEW`, `LIMIT_EXCEEDED`, `LIFECYCLE_DENIED`, `KEY_UNAVAILABLE`, `CLOSED`; denial reasons `integrity-failure`, `key-unavailable`, `attempt-mismatch`, `attempt-already-committed`; audit operations `capture`, `delete-ciphertext`, `resolve-attempt`. `createServerVault` never produces them, but an exhaustive `switch` over these types needs the new cases.

## Threat boundary, failure behavior, and residual risk

- **Threat boundary added over the in-memory vault:** a different authenticated principal, a cross-tenant request, a stale grant surviving a policy or revocation change, and a resolver or policy that is unreachable, slow, or throws — the exact boundary the [server authority ADR](../decisions/define-server-authority-interface.md) names.
- **Failure behavior:** every injection point fails closed, as above. A revoked or drained token reads as `unknown-token` once its short-lived tombstone (`revocationMemoryMs`) ages out — both are conformant per the ADR's §4.
- **Residual risk (this package's own, beyond what the ADR already states):**
  - Single-process only. This is `@redact-secret/vault`'s in-memory backend wrapped with server authority, not a distributed store; a multi-process deployment uses the [persistent profile](../guides/persistent-server.md), where the store's transaction is the shared linearization point.
  - `revoke()` is not itself principal-gated in this release (it mirrors `@redact-secret/vault`'s own trusted-operator `revoke(captureId)`); an application that needs to authorize *who* may revoke composes its own check before calling it.
  - The FIFO queue trades throughput for correctness (see Concurrency, above): under sustained load, calls wait for their turn rather than running in parallel.
  - This package cannot verify that a consumer's `PrincipalResolver` actually authenticates the caller or that its `ServerReleasePolicy` is logically sound — a policy bug that always allows is indistinguishable from `denyByDefault` at the type level. Only this package's own adversarial tests, and the application's own review of its injected policy, catch that.

## Core compatibility

This package adds no direct dependency on `@redact-secret/core`; its `@redact-secret/core` peer is pinned exactly to `0.1.0-beta.12` (`0.1.0-beta.11` in `0.1.0-beta.2`, [#96](https://github.com/redact-secret/redact-secret-vault/issues/96)), the same core `@redact-secret/vault` requires. The published `0.1.0-alpha.2` through `0.1.0-beta.1` pin `0.1.0-beta.10` (see the [beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md)). Before `0.1.0-alpha.2`, the unpublished package on `main` pinned `0.1.0-beta.9`.
