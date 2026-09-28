# Threat model: reversible restoration modes

**Status:** current for `@redact-secret/vault` browser main-thread and Node.js in-memory use (published `0.1.0-alpha.1` and `0.1.0-alpha.2`), its optional dedicated-Worker mode ([#14](https://github.com/redact-secret/redact-secret-vault/issues/14), first published in `0.1.0-alpha.2`; see the [Worker-mode ADR](../decisions/2026-09-27-qualify-dedicated-worker-mode.md)), and for `@redact-secret/vault-server`'s single-process, in-memory server authority mode (published `0.1.0-alpha.2`, its first release); **proposed** for multi-process/persistent server authority and persistent-store modes, which have no implementation or support claim.
**Issue:** [#6](https://github.com/redact-secret/redact-secret-vault/issues/6). **Core compatibility:** `@redact-secret/vault@0.1.0-alpha.1` pins `@redact-secret/core` `0.1.0-beta.9` exactly (see [qualification record](../research/qualification-0.1.0-alpha.1.md)); the `0.1.0-alpha.2` candidates pin `0.1.0-beta.10` exactly ([#41](https://github.com/redact-secret/redact-secret-vault/issues/41), [#44](https://github.com/redact-secret/redact-secret-vault/issues/44)). Opt-in PII detection in `0.1.0-beta.10` is implemented and qualified with PII off and on, not yet published ([#42](https://github.com/redact-secret/redact-secret-vault/issues/42), [qualification record](../research/qualification-core-0.1.0-beta.10.md)); see [PII findings](#pii-findings-core-beta10--current-unreleased).

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
- **Alternative:** one vault per user session or task; [`@redact-secret/vault-server`](../../packages/vault-server/README.md) for principal/tenant authorization ([#15](https://github.com/redact-secret/redact-secret-vault/issues/15), [#16](https://github.com/redact-secret/redact-secret-vault/issues/16)).

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

### Server authority, JavaScript, single-process, in-memory — implemented and tested for `@redact-secret/vault-server` 0.1.0-alpha.2 (published)

This row is tested by this package's own adversarial suite (`packages/vault-server/test/`), not yet the shared [conformance corpus](../../conformance/README.md) (still coupled to `@redact-secret/vault`'s own API — see that document's "Covered classes"). Treat this row as implemented and adversarially tested, short of this document's top-line "qualified" bar until a shared, language-neutral corpus version covers these classes.

- **Data flow:** request handler → `PrincipalResolver` resolves the trusted principal from already-authenticated context → `capture` (tenant-attributed) → outbound model call → `restore` (principal, tenant, source, sink/path, purpose, budget, then `ServerReleasePolicy`, all fresh per occurrence) → response or tool call.
- **Trust boundary:** the process, generalized to a single `ServerVault` instance's own linearization queue rather than one JavaScript call. Own-instance concurrent `restore`/`revoke` calls are coordinated (queued, not raced); a revoke queued ahead of a restore denies it.
- **Assets added over the plain in-memory vault:** principal, tenant, purpose, and (optionally, policy-defined) policy revision.
- **Attackers added:** a different authenticated principal, a cross-tenant request, a stale grant surviving a policy or revocation change, a `PrincipalResolver`/`ServerReleasePolicy` that is unreachable, slow, or throws.
- **Protects against:** everything the Node.js in-memory mode protects against, plus: cross-tenant restoration (denied `tenant-mismatch` even under an allow-all policy); an unresolved, malformed, or timed-out principal (`unauthenticated`); a missing purpose (`missing-purpose`); a throwing, rejecting, timed-out, or malformed-return policy (`policy-evaluation-error`, never allow-on-error); a revoked token reused within its tombstone window (`revoked`, distinct from `unknown-token`).
- **Does not protect against:** multi-process deployments (single-process only; no distributed linearization — see [decision-implement-vault-server-in-memory](../decisions/2026-09-27-implement-vault-server-in-memory.md)); an application whose injected `PrincipalResolver` does not actually authenticate the caller, or whose `ServerReleasePolicy` is logically unsound (a policy that always allows is indistinguishable from `denyByDefault` at the type level); `revoke()` itself is not principal-gated in this release.
- **Contract and implementation:** the decision tuple, denial vocabulary, and audit event shape are fixed by the [server authority interface](../decisions/2026-09-27-define-server-authority-interface.md) ([#15](https://github.com/redact-secret/redact-secret-vault/issues/15)). [`@redact-secret/vault-server`](../../packages/vault-server/README.md) ([#16](https://github.com/redact-secret/redact-secret-vault/issues/16)) implements it, with the in-memory-specific choices recorded in [decision-implement-vault-server-in-memory](../decisions/2026-09-27-implement-vault-server-in-memory.md). A research-grade native Python implementation exists ([`redact-secret-vault-server`](../../packages/vault-server-py/README.md), [#17](https://github.com/redact-secret/redact-secret-vault/issues/17)); it is not qualified to this row's bar (see [its research record](../research/python-server-integration-2026-09-27.md)). Cross-language conformance documentation ([#18](https://github.com/redact-secret/redact-secret-vault/issues/18)) remains proposed.

### Persistent mappings — proposed, not supported

- **Assets added:** ciphertext at rest, keys, backups, replicas.
- **Attackers added:** database disclosure, record substitution, key compromise, stale backups, replica lag.
- **Required controls:** authenticated encryption bound to tenant, session, and entry metadata; consumer-owned keys; logical expiry and revocation at use time; a backend-specific linearization proof; deletion and backup policy. The exact store interface, AEAD/AAD binding, key-injection and rotation shape, deletion/backup guarantees, and fail-closed failure behavior are now decided as a contract — not yet an implementation — in the [persistent store contract](../decisions/2026-09-27-define-persistent-store-contract.md) ([#19](https://github.com/redact-secret/redact-secret-vault/issues/19)), which a concrete qualified backend ([#20](https://github.com/redact-secret/redact-secret-vault/issues/20)) builds against. The alpha vault never persists anything.

### PII findings (core beta.10) — current, published in 0.1.0-alpha.2

This section is **current** for the packages on `main` against `@redact-secret/core@0.1.0-beta.10` with the PII selection `["pii"]`. The `@redact-secret/vault` and `@redact-secret/vault-server` `0.1.0-alpha.2` releases carry it; both were published on 2026-09-28 ([#44](https://github.com/redact-secret/redact-secret-vault/issues/44), [#55](https://github.com/redact-secret/redact-secret-vault/issues/55)). They pin the published beta.10 ([#41](https://github.com/redact-secret/redact-secret-vault/issues/41)). The contract is [decision-pii-retention-and-activation-ownership](../decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md) ([#45](https://github.com/redact-secret/redact-secret-vault/issues/45)). The main-thread vault and `vault-server` ([#38](https://github.com/redact-secret/redact-secret-vault/issues/38)), Worker mode ([#39](https://github.com/redact-secret/redact-secret-vault/issues/39)), and the Python bridge ([#40](https://github.com/redact-secret/redact-secret-vault/issues/40)) implement it. The [beta.10 qualification record](../research/qualification-core-0.1.0-beta.10.md) ([#42](https://github.com/redact-secret/redact-secret-vault/issues/42)) verifies the controls below with PII off and on: Node.js (addon and WASM), Chromium, Firefox, and WebKit on the main thread and in a dedicated Worker, and the Python bridge. The `warn` gate is verified with a policy-assigned `warn` and, since corpus 1.3.0, a default-confidence `warn` PII finding (Medium `pii_global_phone`, [#43](https://github.com/redact-secret/redact-secret-vault/issues/43)).

- **Assets added:**
  - Personal data in retained entries, when the application opts in: payment card numbers, national identifiers, bank account numbers, contact data.
  - The realm's PII activation identity.
  - PII type labels (`pii_…`) in `tokens[].type`, `passedThroughTypes`, and core display placeholders.
- **Attackers added:**
  - A careless integrator whose generic `eligible` callback allows everything.
  - Any other component in the same realm that initializes the core first with a different PII selection.
  - A hostile page script trying to choose the Worker realm's selection.
  - A core swapped under the Python bridge.
- **Protects against:**
  - Implicit PII retention. `pii_` findings are retained only when their exact type is in `CaptureOptions.pii.retain`. A generic `eligible` can narrow that allowlist but never widen it.
  - The vault fixing the realm's PII selection. It forwards only an application-supplied `pii` and otherwise adopts the existing activation or fails `NOT_INITIALIZED`.
  - Scanning under a different selection than stated. Conflicts fail `CORE_FAILURE`/`PII_ACTIVATION_CONFLICT`, and `expectPiiActivation` mismatches fail `PII_ACTIVATION_MISMATCH`.
  - Silent warn-level PII plaintext. The default is `unredacted: "reject"`.
  - PII options silently ignored on a core without PII support, or with PII off. These fail `PII_UNAVAILABLE`.
  - Page-chosen Worker activation. No request message carries selectors.
  - A typed PII display label (for example the core's `<PII_JURISDICTION_US_SSN_1>`, or an application's `<SSN_1>`) presented as a restore capability. It is ordinary text: restoration needs an issued `<rsv_…>` token and a grant, and the value exists only if its type was allowlisted ([typed placeholder decision](../decisions/2026-09-27-decouple-typed-placeholders-from-restoration.md)).
- **Does not protect against:**
  - PII the core does not detect. PII is off by default, and detection is incomplete by design.
  - The consequences of an application deliberately allowlisting PAN- or SSN-class types.
  - Another in-realm component that needs a different PII selection. Only one selection can exist per realm.
  - The category disclosure carried by PII type labels.
  - Plaintext PII that an application passes through with `"pass-through"`.

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

### Residual risks for PII findings (current, published `0.1.0-alpha.2`, core beta.10; see [decision-pii-retention-and-activation-ownership](../decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md))

| Risk | Why accepted | Mitigation available to the application |
| --- | --- | --- |
| **Regulatory exposure from retained PAN, SSN, or IBAN-class values.** An application that puts payment-card or national-identifier types (e.g. `pii_jurisdiction_us_ssn`) in `pii.retain` makes the vault's process memory (and, later, any persistent store) hold cardholder data or national identifiers. That may bring the process into PCI DSS or national-ID/data-protection scope. | Retention is the application's explicit, per-type opt-in. The vault cannot know the application's legal basis. Nothing is retained by default. | Do not allowlist payment-card or national-ID types. Where unavoidable, restrict to server authority mode with the narrowest grants, `maxUses: 1`, and short TTLs. Revoke on task end. Assess compliance scope before enabling. Treat the vault as in scope wherever such a type is retained. |
| **Realm-global, one-shot activation.** One PII selection exists per process or JavaScript realm. The first initializer fixes it for every library in the realm. | This is the core's contract. The vault avoids *being* that first initializer unless asked. | Initialize the core once at application start with the selection the whole realm needs. Pass `expectPiiActivation` to detect drift. Use a separate realm (a dedicated Worker or a separate process) for a workflow that needs a different selection. |
| **Order-dependent startup failure.** On beta.10, `createVault()` with no `pii` fails `CORE_FAILURE`/`NOT_INITIALIZED` if the application has not initialized the core yet. | Silently locking PII off would be worse and order-dependent. | Await the core's `initialize(...)` first, or pass `pii: []` for credentials-only. |
| **Warn-level PII rejected or passed through.** Medium- and Low-confidence PII defaults to `warn`. Captures containing it reject under the default. Under `"pass-through"`, the plaintext PII is sent. | The vault does not reinterpret core actions. | Map chosen PII types to `redact` with a core `policy`. Inspect `passedThroughTypes`. Choose pass-through per named boundary only. In Worker mode, no in-protocol policy exists yet. |
| **PII type labels as metadata.** `pii_…` types appear in `tokens[].type`, in `passedThroughTypes`, and possibly in core display placeholders sent to the model. They reveal the *category* of data present, never the value. | Type labels are descriptive and grant nothing. They help the application make release decisions. | Do not log or forward type lists beyond need. Use a neutral `displayFormatter` where the category itself is sensitive. |
| **Allowlisted type renamed or split by a future core.** An exact-type allowlist stops matching after a core rename. | This fails closed: the finding is then not retained, only replaced. | Re-review `pii.retain` whenever the core's PII vocabulary version changes (visible in the activation identity). |
