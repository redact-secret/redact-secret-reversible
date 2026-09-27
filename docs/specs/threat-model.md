# Threat model: reversible restoration modes

**Status:** current for `@redact-secret/vault@0.1.0-alpha.1` browser main-thread and Node.js in-memory use, and for its optional dedicated-Worker mode ([#14](https://github.com/redact-secret/redact-secret-reversible/issues/14), a later, separately qualified release; see the [Worker-mode ADR](../decisions/2026-09-27-qualify-dedicated-worker-mode.md)); **proposed** for server authority and persistent modes, which have no implementation or support claim.
**Issue:** [#6](https://github.com/redact-secret/redact-secret-reversible/issues/6). **Core compatibility:** `@redact-secret/core` `0.1.0-beta.9` exactly (see [qualification record](../research/qualification-0.1.0-alpha.1.md)).

This document names the assets, attackers, data flows, trust boundary, residual risk, and alternative for each mode. It complements the [browser in-memory specification](in-memory-security.md) and the [architecture](../../ARCHITECTURE.md). A mode is supported only when its row below says **qualified** and its runtime passes the [conformance corpus](../../conformance/README.md).

## Assets

| Asset | Where it exists | Why it matters |
| --- | --- | --- |
| Original input | Application memory before `capture`; the core's scan buffer | Contains every secret, including undetected ones. The vault cannot protect it from code that already holds it. |
| Retained values | The vault's private entry map, from capture commit until restore consumption, revocation, expiry, or disposal | The new asset reversibility creates. Bounded by entries, bytes, TTL, and use count. |
| Issued tokens | Redacted text sent outward; model output returned | Unpredictable lookup keys. Not authority: a token is released only into a granted sink and path within budget and policy. |
| Release grants and policy | Application code at capture and restore time | Decide where plaintext may reappear. Model output never supplies them. |
| Restored values | The object `restore` returns to the application | Plaintext again. Once returned, the application owns rendering and onward transmission. |
| Diagnostics | Errors, audit events, stats | Must carry fixed codes and counts only. |

## Attacker capabilities considered

1. **Untrusted model or tool output.** Can copy, duplicate, reorder, alter, invent, or relocate tokens; can place tokens in fields and sinks the application did not intend; can include token-like literals and `$` replacement patterns.
2. **Untrusted input author.** Can plant token-like literals in input, Unicode that stresses ranges, unpaired surrogates, oversized input, and many findings.
3. **Another vault session in the same process.** Holds its own tokens and may present them to a different vault.
4. **Careless integrator.** Logs errors or audit events, forwards `text` without checking `passedThrough`, grants broad paths, or retries after denial.
5. **Same-page hostile script, compromised dependency, or browser extension.** Out of scope for protection: it can read the original input, call `restore`, or read its result. Documented as a limit, never as a guarantee.
6. **Other principals and tenants on a server.** Out of scope for the vault. Requires the proposed server authority layer.

## Modes

### Browser main thread — qualified for alpha.1

- **Data flow:** page code → `capture` (core WASM scan in the same page) → redacted text to an external service → model output → `restore` into granted fields → page renders.
- **Trust boundary:** the page. Every same-origin script shares it.
- **Protects against:** accidental release of retained values into non-granted fields or sinks; forged, altered, cross-vault, expired, revoked, or over-budget tokens; partial restore; `block` findings reaching output; silent `warn`/`allow` plaintext pass-through; plaintext in vault errors, audit events, and stats; implicit persistence (no storage, network, messaging, or console use; checked on the packed artifact).
- **Does not protect against:** XSS or compromised page scripts; a model placing a valid token in a *granted* field of the right sink (release is by policy, not semantic provenance); undetected secrets (the core does not find everything); memory disclosure (JavaScript strings cannot be zeroized); the application mishandling restored plaintext.
- **Requirements on the deployment:** CSP must allow `'wasm-unsafe-eval'` for the core; without it the vault fails closed (`CORE_FAILURE` / `INITIALIZATION_FAILED`, verified in three engines).
- **Alternative if residual risk is unacceptable:** keep core-only redaction with no retention; move capture and restore to a trusted server (proposed `vault-server`); isolate the sensitive workflow on a separate origin.

### Node.js process memory — qualified for alpha.1 (single process, application-level policy)

- **Data flow:** request handler → `capture` → outbound model call → `restore` into granted fields → response or tool call.
- **Trust boundary:** the process. The vault is a per-session object; it does not know users or tenants.
- **Protects against:** the same misuse classes as the browser mode, plus cross-session lookup between vault instances in one process.
- **Does not protect against:** an application sharing one vault across users or tenants (the vault would then happily restore one user's value into another user's granted field); multi-process coordination; heap dumps or core files; application logging of restored values.
- **Alternative:** one vault per user session or task; the proposed `vault-server` layer for principal/tenant authorization ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15), [#16](https://github.com/redact-secret/redact-secret-reversible/issues/16)).

### Dedicated Worker — qualified, optional, separately from main-thread mode

- **Data flow:** page code → `createWorkerVault(worker)` → validated message → Worker-owned vault (`capture`/`restore`/`revoke`/`stats`/`dispose`, core WASM scan inside the Worker) → validated message back → page code.
- **Trust boundary:** unchanged from browser main thread — still the page. A dedicated Worker is not a privilege or authentication boundary; it narrows *accidental* main-thread reach to the mapping, nothing more.
- **Intended benefit:** the mapping (retained entries) lives in a closure private to the Worker's own module scope, never assigned to a global or to any value a posted message can carry. Ordinary main-thread application code has no way to enumerate, dump, or directly read it; the only interface is the validated protocol.
- **Protects against:** everything the browser main-thread row protects against, plus direct main-thread object access to the mapping, and adds its own gates: unrecognized message `kind`/version/operation, an unexpected key on any message (including `__proto__`/`constructor`/`prototype`), and a non-cloneable capture option (`policy`, `eligible`, `displayFormatter`) are all rejected explicitly — the pre-send builder throws before anything is sent, and the Worker-side parser rejects independently, so a hostile page that talks to the Worker directly (bypassing the client wrapper) gets the same rejection. There is no `dump`/`listSecrets`/export operation to find.
- **Does not protect against — same limit as before, now demonstrated directly:** a compromised page can still call `capture`/`restore` through the same protocol a legitimate caller uses, and can still observe whatever that protocol legitimately returns; messages are cloned, so the main thread retains its own copy of whatever it sent. A Worker narrows direct mapping access; it does not authenticate the caller. See `packages/vault/test/worker-suite.js`'s hostile-main-thread cases and the [Worker-mode ADR](../decisions/2026-09-27-qualify-dedicated-worker-mode.md)'s guarantee boundary.
- **API shape:** deliberately asynchronous (`WorkerVault`, every call returns a `Promise`), not the synchronous `Vault` interface main-thread mode exposes. This is a visible difference, never conflated with main-thread guarantees.
- **Requirements on the deployment:** same `'wasm-unsafe-eval'` CSP requirement as main-thread mode, applied to the Worker's own script response (not silently inherited from the page); an explicit `worker-src` directive (Worker creation fails closed, never falls back to main-thread capture, if CSP denies it); and, under `require-trusted-types-for 'script'`, a Trusted Types policy for the `new Worker(url)` sink, distinct from the `<script src>` sink main-thread mode uses.
- **Failure behavior:** never silent. Worker creation, initialization, and every call reject with a fixed `VaultError` (`WORKER_PROTOCOL_VIOLATION`, `WORKER_UNAVAILABLE`, or the Worker's own reported code such as `CORE_FAILURE`/`INITIALIZATION_FAILED`) rather than degrading to main-thread behavior.
- **Alternative if residual risk is unacceptable:** the same alternatives as browser main-thread mode. Worker mode does not change which alternative is appropriate; it only narrows one specific accidental-access path.
- **Out of scope for this qualification:** `SharedWorker`, a Service Worker, and Node.js `worker_threads` (a different message-port API). None of those are claimed supported.

### Server authority (JavaScript or Python) — proposed, not supported

- **Assets added:** principal, tenant, purpose, and policy revision.
- **Attackers added:** a different authenticated user, a cross-tenant request, a stale grant after revocation.
- **Required controls:** server-resolved identity, fresh authorization per restore, a decision tuple of principal, tenant, source/session, entry, policy revision, purpose, sink, and path, and multi-process consistency. The alpha vault provides none of these. The exact decision tuple, denial vocabulary, and audit event shape are now decided as a contract — not yet an implementation — in the [server authority interface](../decisions/2026-09-27-define-server-authority-interface.md) ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15)), which `vault-server` ([#16](https://github.com/redact-secret/redact-secret-reversible/issues/16)), the Python integration ([#17](https://github.com/redact-secret/redact-secret-reversible/issues/17)), and cross-language conformance documentation ([#18](https://github.com/redact-secret/redact-secret-reversible/issues/18)) build against.

### Persistent mappings — proposed, not supported

- **Assets added:** ciphertext at rest, keys, backups, replicas.
- **Attackers added:** database disclosure, record substitution, key compromise, stale backups, replica lag.
- **Required controls:** authenticated encryption bound to tenant, session, and entry metadata; consumer-owned keys; logical expiry and revocation at use time; a backend-specific linearization proof; deletion and backup policy. The exact store interface, AEAD/AAD binding, key-injection and rotation shape, deletion/backup guarantees, and fail-closed failure behavior are now decided as a contract — not yet an implementation — in the [persistent store contract](../decisions/2026-09-27-define-persistent-store-contract.md) ([#19](https://github.com/redact-secret/redact-secret-reversible/issues/19)), which a concrete qualified backend ([#20](https://github.com/redact-secret/redact-secret-reversible/issues/20)) builds against. The alpha vault never persists anything.

## Residual risks accepted for alpha.1

| Risk | Why accepted | Mitigation available to the application |
| --- | --- | --- |
| Valid token copied by a model into another *granted* path or reordered within one | Text tokens cannot prove semantic position | Grant the narrowest paths; `maxUses: 1` (default); page-local `releasePolicy`; keep a trusted out-of-band structure instead of free text |
| Plaintext remains in JavaScript memory after revoke or dispose | Managed runtimes copy and intern strings | Short TTLs; dispose on task end; do not claim zeroization |
| `warn`/`allow` plaintext when the application opts into `"pass-through"` | The core leaves them unchanged by contract | Default `"reject"`; `passedThrough` count on every result |
| Undetected secrets pass through as ordinary text | Detection is incomplete by design | Treat output as "known findings removed", never "safe to send" |
| Denial reasons tell the caller which check failed, and so whether a token is live | Useful for integrators; the caller is already inside the trust boundary | Do not forward `reason` to the model or end user |
| A value copied between conversations sharing one vault | The vault cannot know conversations; `captures` scopes each restore to listed captures | One vault per user task; list only the current conversation's captures |
| Token altered with a homoglyph so the marker disappears | Destroying the marker also destroys the token; nothing is restored | None needed: that text stays as ordinary text |
| Private fields visible to debuggers and DevTools | Runtime inspection is outside the page API | Do not inspect vaults in shared sessions |
| Same-page script compromise | Outside any in-page control | Strict CSP, Trusted Types, fewer third-party scripts, or a server/origin alternative |
