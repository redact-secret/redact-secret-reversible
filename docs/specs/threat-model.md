# Threat model: reversible restoration modes

**Status:** current for `@redact-secret/vault@0.1.0-alpha.1` browser main-thread and Node.js in-memory use, and for `@redact-secret/vault-server@0.1.0-alpha.1`'s single-process, in-memory server authority mode; **proposed** for Worker, multi-process/persistent server authority, and persistent-store modes, which have no implementation or support claim.
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
6. **Other principals and tenants on a server.** Out of scope for the plain in-memory vault. Addressed by `@redact-secret/vault-server`'s server authority layer.

## Modes

### Browser main thread — qualified for alpha.1

- **Data flow:** page code → `capture` (core WASM scan in the same page) → redacted text to an external service → model output → `restore` into granted fields → page renders.
- **Trust boundary:** the page. Every same-origin script shares it.
- **Protects against:** accidental release of retained values into non-granted fields or sinks; forged, altered, cross-vault, expired, revoked, or over-budget tokens; partial restore; `block` findings reaching output; silent `warn`/`allow` plaintext pass-through; plaintext in vault errors, audit events, and stats; implicit persistence (no storage, network, messaging, or console use; checked on the packed artifact).
- **Does not protect against:** XSS or compromised page scripts; a model placing a valid token in a *granted* field of the right sink (release is by policy, not semantic provenance); undetected secrets (the core does not find everything); memory disclosure (JavaScript strings cannot be zeroized); the application mishandling restored plaintext.
- **Requirements on the deployment:** CSP must allow `'wasm-unsafe-eval'` for the core; without it the vault fails closed (`CORE_FAILURE` / `INITIALIZATION_FAILED`, verified in three engines).
- **Alternative if residual risk is unacceptable:** keep core-only redaction with no retention; move capture and restore to a trusted server ([`@redact-secret/vault-server`](../../packages/vault-server/README.md)); isolate the sensitive workflow on a separate origin.

### Node.js process memory — qualified for alpha.1 (single process, application-level policy)

- **Data flow:** request handler → `capture` → outbound model call → `restore` into granted fields → response or tool call.
- **Trust boundary:** the process. The vault is a per-session object; it does not know users or tenants.
- **Protects against:** the same misuse classes as the browser mode, plus cross-session lookup between vault instances in one process.
- **Does not protect against:** an application sharing one vault across users or tenants (the vault would then happily restore one user's value into another user's granted field); multi-process coordination; heap dumps or core files; application logging of restored values.
- **Alternative:** one vault per user session or task; [`@redact-secret/vault-server`](../../packages/vault-server/README.md) for principal/tenant authorization ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15), [#16](https://github.com/redact-secret/redact-secret-reversible/issues/16)).

### Dedicated Worker — proposed, not supported

- **Intended benefit:** keeps the mapping out of direct main-thread object reach.
- **Why not a security boundary:** a compromised page can still message the Worker, supply input, and observe restored output. Messages are cloned, so the main thread retains its copy of the input.
- **Open work:** CSP (`worker-src` and the Worker's own policy), WASM loading inside the Worker, message validation, termination, and explicit failure without silent main-thread fallback ([#14](https://github.com/redact-secret/redact-secret-reversible/issues/14)).

### Server authority, JavaScript, single-process, in-memory — implemented and tested for `@redact-secret/vault-server` 0.1.0-alpha.1

This row is tested by this package's own adversarial suite (`packages/vault-server/test/`), not yet the shared [conformance corpus](../../conformance/README.md) (still coupled to `@redact-secret/vault`'s own API — see that document's "Covered classes"). Treat this row as implemented and adversarially tested, short of this document's top-line "qualified" bar until a shared, language-neutral corpus version covers these classes.

- **Data flow:** request handler → `PrincipalResolver` resolves the trusted principal from already-authenticated context → `capture` (tenant-attributed) → outbound model call → `restore` (principal, tenant, source, sink/path, purpose, budget, then `ServerReleasePolicy`, all fresh per occurrence) → response or tool call.
- **Trust boundary:** the process, generalized to a single `ServerVault` instance's own linearization queue rather than one JavaScript call. Own-instance concurrent `restore`/`revoke` calls are coordinated (queued, not raced); a revoke queued ahead of a restore denies it.
- **Assets added over the plain in-memory vault:** principal, tenant, purpose, and (optionally, policy-defined) policy revision.
- **Attackers added:** a different authenticated principal, a cross-tenant request, a stale grant surviving a policy or revocation change, a `PrincipalResolver`/`ServerReleasePolicy` that is unreachable, slow, or throws.
- **Protects against:** everything the Node.js in-memory mode protects against, plus: cross-tenant restoration (denied `tenant-mismatch` even under an allow-all policy); an unresolved, malformed, or timed-out principal (`unauthenticated`); a missing purpose (`missing-purpose`); a throwing, rejecting, timed-out, or malformed-return policy (`policy-evaluation-error`, never allow-on-error); a revoked token reused within its tombstone window (`revoked`, distinct from `unknown-token`).
- **Does not protect against:** multi-process deployments (single-process only; no distributed linearization — see [decision-implement-vault-server-in-memory](../decisions/2026-09-27-implement-vault-server-in-memory.md)); an application whose injected `PrincipalResolver` does not actually authenticate the caller, or whose `ServerReleasePolicy` is logically unsound (a policy that always allows is indistinguishable from `denyByDefault` at the type level); `revoke()` itself is not principal-gated in this release.
- **Contract and implementation:** the decision tuple, denial vocabulary, and audit event shape are fixed by the [server authority interface](../decisions/2026-09-27-define-server-authority-interface.md) ([#15](https://github.com/redact-secret/redact-secret-reversible/issues/15)). [`@redact-secret/vault-server`](../../packages/vault-server/README.md) ([#16](https://github.com/redact-secret/redact-secret-reversible/issues/16)) implements it, with the in-memory-specific choices recorded in [decision-implement-vault-server-in-memory](../decisions/2026-09-27-implement-vault-server-in-memory.md). A native Python integration ([#17](https://github.com/redact-secret/redact-secret-reversible/issues/17)) and cross-language conformance documentation ([#18](https://github.com/redact-secret/redact-secret-reversible/issues/18)) remain proposed.

### Persistent mappings — proposed, not supported

- **Assets added:** ciphertext at rest, keys, backups, replicas.
- **Attackers added:** database disclosure, record substitution, key compromise, stale backups, replica lag.
- **Required controls:** authenticated encryption bound to tenant, session, and entry metadata; consumer-owned keys; logical expiry and revocation at use time; a backend-specific linearization proof; deletion and backup policy ([#19](https://github.com/redact-secret/redact-secret-reversible/issues/19), [#20](https://github.com/redact-secret/redact-secret-reversible/issues/20)). The alpha vault never persists anything.

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
