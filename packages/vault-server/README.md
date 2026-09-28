# @redact-secret/vault-server

**Alpha.** Server authority for restoring values captured by [`@redact-secret/vault`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault/README.md) across principals, tenants, sources, destinations, and purposes, with an in-memory storage backend. Implements the interface fixed by [the server authority ADR](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/decisions/2026-09-27-define-server-authority-interface.md) (S1, #15): `PrincipalResolver`, `ServerReleasePolicy`, `ServerDenialReason`, and `ServerAuditEvent`.

```bash
npm install @redact-secret/vault-server@0.1.0-alpha.2 @redact-secret/vault@0.1.0-alpha.2 @redact-secret/core@0.1.0-beta.10
```

`0.1.0-alpha.2` is this package's first published version. Install exact versions: `@redact-secret/vault`'s npm `latest` tag still points at `0.1.0-alpha.1`, which conflicts with core beta.10, and this package's own `latest` tag is the prerelease `0.1.0-alpha.2` (npm assigned it on first publish).

## Supported, and not

| | Status in 0.1.0-alpha.2 |
| --- | --- |
| Server runtimes | Node.js 20, 22, 24 (same as `@redact-secret/vault`), by this package's own adversarial suite and the [beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-core-0.1.0-beta.10.md) |
| Storage backend | In-memory only. `@redact-secret/store-*` persistent backends are a separate, later track ([#19](https://github.com/redact-secret/redact-secret-vault/issues/19)) — this package does not implement or claim one |
| Python | **Not in this package.** A research-grade native Python implementation of the same contract is [`redact-secret-vault-server`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault-server-py/README.md) ([#17](https://github.com/redact-secret/redact-secret-vault/issues/17)) |
| Streaming, arbitrary-text `restore(text)` | **Not supported**, matching `@redact-secret/vault` |
| Browser | **Not a target.** This package assumes a server trust boundary (`PrincipalResolver` reads request-scoped, already-authenticated context); it is Node.js-only and is never bundled for a browser |

## Usage

```ts
import { createServerVault, VaultServerError } from "@redact-secret/vault-server";

const server = await createServerVault({
  // Reads YOUR application's already-authenticated request context. Throw
  // or reject if it cannot be established — never return a default principal.
  resolvePrincipal: async (ctx) => ({ id: ctx.userId, tenant: ctx.tenant }),
  // Deny-by-default is the recommended base; see the ADR's reference policies.
  policy: (input) =>
    input.tenant === input.source.issuedTenant && input.purpose === "support-reply-purpose-synthetic"
      ? { allow: true }
      : { allow: false, reason: "policy" },
  onAudit: (event) => auditSink.write(event), // no field can carry a restored value
  // Core PII activation is the application's: `pii: []` initializes the core with
  // PII off. Omit it only if your code already awaited the core's `initialize(...)`;
  // otherwise this fails VAULT_FAILURE / CORE_FAILURE / NOT_INITIALIZED.
  pii: [],
});

const captured = await server.capture(userText, {
  release: [{ sink: "support-ticket-reply-sink-synthetic", paths: ["body"] }],
  issuedTenant: request.tenant, // whose value this is
});

// ... send captured.text to a model; it sees only tokens ...

try {
  const { fields } = await server.restore({
    context: request, // passed to resolvePrincipal
    sink: "support-ticket-reply-sink-synthetic",
    purpose: "support-reply-purpose-synthetic",
    captures: [captured.captureId],
    fields: { body: modelReply },
  });
  render(fields.body);
} catch (error) {
  if (!(error instanceof VaultServerError) || error.code !== "RESTORE_DENIED") throw error;
  render(modelReply); // denied: keep the redacted text
}
```

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

Every `capture`/`restore`/`revoke`/`dispose`/`stats` call on one `ServerVault` is queued onto a single FIFO chain: at most one is ever executing, and each fully commits or denies before the next begins — including across the `await`s a `PrincipalResolver` or `ServerReleasePolicy` introduces (which the underlying, synchronous `@redact-secret/vault` never has to contend with). This is this package's own linearization point, generalizing [the transaction-boundary ADR](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/decisions/2026-09-27-define-restore-transaction-boundary.md)'s contract to genuinely concurrent async operations:

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

## Threat boundary, failure behavior, and residual risk

- **Threat boundary added over the in-memory vault:** a different authenticated principal, a cross-tenant request, a stale grant surviving a policy or revocation change, and a resolver or policy that is unreachable, slow, or throws — the exact boundary the [server authority ADR](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/decisions/2026-09-27-define-server-authority-interface.md) names.
- **Failure behavior:** every injection point fails closed, as above. A revoked or drained token reads as `unknown-token` once its short-lived tombstone (`revocationMemoryMs`) ages out — both are conformant per the ADR's §4.
- **Residual risk (this package's own, beyond what the ADR already states):**
  - Single-process only. This is `@redact-secret/vault`'s in-memory backend wrapped with server authority, not a distributed store; a multi-process deployment needs its own shared linearization mechanism, deferred to the persistent-store contract (#19).
  - `revoke()` is not itself principal-gated in this release (it mirrors `@redact-secret/vault`'s own trusted-operator `revoke(captureId)`); an application that needs to authorize *who* may revoke composes its own check before calling it.
  - The FIFO queue trades throughput for correctness (see Concurrency, above): under sustained load, calls wait for their turn rather than running in parallel.
  - This package cannot verify that a consumer's `PrincipalResolver` actually authenticates the caller or that its `ServerReleasePolicy` is logically sound — a policy bug that always allows is indistinguishable from `denyByDefault` at the type level. Only this package's own adversarial tests, and the application's own review of its injected policy, catch that.

## Core compatibility

This package adds no direct dependency on `@redact-secret/core`; its `@redact-secret/core` peer is pinned exactly to `0.1.0-beta.10`, the same core `@redact-secret/vault@0.1.0-alpha.2` requires (see the [beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-core-0.1.0-beta.10.md)). Before this release, the unpublished package on `main` pinned `0.1.0-beta.9`.

## Security reports

Report vulnerabilities privately through [GitHub security advisories](https://github.com/redact-secret/redact-secret-vault/security/advisories/new). Never include live credentials. See [SECURITY.md](https://github.com/redact-secret/redact-secret-vault/blob/main/SECURITY.md).

## License

MIT
