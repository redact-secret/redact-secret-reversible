---
decision_id: decision-pii-retention-and-activation-ownership
status: accepted
scope: repository
title: Decide PII retention eligibility and core PII activation ownership
proposed_at: 2026-09-27
decided_at: 2026-09-27
---
# Decide PII retention eligibility and core PII activation ownership

> **Accepted 2026-09-27** as the contract for [#45](https://github.com/redact-secret/redact-secret-vault/issues/45). Implemented on every surface: main-thread `@redact-secret/vault` and `@redact-secret/vault-server` ([#38](https://github.com/redact-secret/redact-secret-vault/issues/38)), Worker mode with protocol version 2 ([#39](https://github.com/redact-secret/redact-secret-vault/issues/39)), and the Python bridge ([#40](https://github.com/redact-secret/redact-secret-vault/issues/40)). The packages pin the published `@redact-secret/core@0.1.0-beta.10` exactly ([#41](https://github.com/redact-secret/redact-secret-vault/issues/41)). **Qualified 2026-09-28** against that core with PII off and on ([#42](https://github.com/redact-secret/redact-secret-vault/issues/42), [qualification record](../research/qualification-core-0.1.0-beta.10.md)): Node.js 20/22/24 (addon and WASM), Chromium, Firefox, and WebKit on the main thread and in a dedicated Worker, and the Python bridge. Every rule in *Verification before implementation is accepted* below holds in a fresh realm per scenario. Conformance corpus 1.2.0 carries the retention, warn and block, and activation cases in language-neutral form. A default-confidence `warn` PII finding (Medium `pii_global_phone`) is covered by corpus 1.3.0 ([#43](https://github.com/redact-secret/redact-secret-vault/issues/43)). **Released 2026-09-28** in `@redact-secret/vault@0.1.0-alpha.2` and `@redact-secret/vault-server@0.1.0-alpha.2` ([#44](https://github.com/redact-secret/redact-secret-vault/issues/44), [#55](https://github.com/redact-secret/redact-secret-vault/issues/55)); the Python bridge `0.1.0a2` is not published to any index.

## Context

Core `0.1.0-beta.10` adds opt-in PII detection. The canonical contract is the core decision [Define the PII domain, scope, arbitration, and activation contract](https://github.com/redact-secret/redact-secret/blob/main/docs/decisions/2026-09-26-define-the-pii-domain-scope-arbitration-and-activation-contract.md). This record links to it rather than restating it. What matters here:

- **Surface.** `initialize({ pii: string[] })` selects PII families. `piiActivation()` returns the canonical activation identity (`credentials=<full|common>;selectors=<off|…>;families=<…>;vocabulary=<…>`). The new fixed error codes are `PII_SELECTOR_INVALID`, `PII_SELECTOR_UNSUPPORTED`, `PII_SELECTOR_UNAVAILABLE`, and `PII_ACTIVATION_CONFLICT`. `piiActivation()` throws `NOT_INITIALIZED` before initialization.
- **Finding types.** Public PII finding types start with `pii_`, for example `pii_global_email`, `pii_jurisdiction_us_ssn`, and `pii_ambiguous_national_id`. The core owns the inventory.
- **Default actions.** High confidence maps to `redact`. Medium and Low map to `warn`. No PII type is always-redact.
- **Activation is realm-global and one-shot.** The first initialization builds the registry and fixes the selection for the whole process or JavaScript realm. After that, any initialization with a different canonical selection rejects with `PII_ACTIVATION_CONFLICT`. A plain `initialize()` counts as a selection, namely PII off. Verified against the core source (`bindings/node/src/lib.rs` `initialize_profile`, `packages/javascript/src/runtime.ts` `initialize`):
  - The app calls `initialize({ pii: ["pii"] })` and then the vault calls plain `initialize()`: the vault's call rejects with the conflict.
  - The vault calls plain `initialize()` first: the realm is locked to PII off, and the app's later PII selection rejects.

Three facts about today's vault collide with that contract:

1. `createVault` calls `initialize()` with no options (`packages/vault/src/vault.ts:194`), and so do the Worker host (through `createVault`) and the Python bridge (`boundary/core_bridge.mjs`). If the application initializes first with PII, `createVault` fails. If the vault initializes first, the application can no longer enable PII.
2. `capture` retains every `redact` finding unless the generic `eligible` callback excludes it (`vault.ts:416-427`). With PII on, every High-confidence PII finding would be retained by default: payment card numbers, national IDs, IBANs.
3. `unredacted` defaults to `"reject"`, so any Medium or Low PII finding (default `warn`) fails the whole capture with `UNREDACTED_FINDINGS`.

## Decision

### 1. PII findings are never retained by default

A finding is a **PII finding** when its public `type` starts with the exact prefix `pii_`. The vault checks only this prefix. It does not copy or enumerate the core's PII inventory.

`CaptureOptions` gains one optional, PII-specific field. It is separate from `eligible`:

```ts
/** Exact public PII finding types whose `redact` findings may be retained. */
export interface PiiRetention {
  /**
   * Non-empty. Each entry is an exact public PII type (`pii_…`, at most 128
   * ASCII characters from [a-z0-9_-]). No wildcards, prefixes, or selectors.
   * Duplicates are ignored. Unknown but well-formed names are accepted and
   * simply never match: the vault does not know the core's inventory.
   */
  readonly retain: readonly string[];
}

export interface CaptureOptions {
  // …existing fields unchanged…
  /** PII retention opt-in. Omit to retain no PII finding. */
  readonly pii?: PiiRetention;
}
```

For each `redact` finding `f`, in order:

1. If `f.type` does **not** start with `pii_`: unchanged. Retain iff `eligible` is absent or `eligible(f) === true`.
2. If `f.type` starts with `pii_` and `options.pii` is absent, or `f.type` is not in `options.pii.retain`: **not retained**. `eligible` is **not called** for this finding.
3. Otherwise, retain iff `eligible` is absent or `eligible(f) === true`. `eligible` can narrow the PII allowlist. It can never widen it.

The rest is unchanged:

- A non-retained PII `redact` finding is still replaced in the output by a non-restorable display placeholder (`displayFormatter`, or the core default) and counted in `unrestorable`. The `displayFormatter` marker-spoofing check applies unchanged.
- `block` still rejects the whole capture with `BLOCKED_FINDING`, for PII and non-PII findings alike.
- Retained PII entries carry the same `release` grants, `maxUses`, TTLs, and byte/entry limits as any other entry. There is no PII-specific restore path, grant, or audit field. `IssuedToken.type` reports the core type, as it does today.

Validation (`INVALID_ARGUMENT`, fixed and value-free) fails when any of these hold:

- `pii` is not a plain object with exactly the key `retain`.
- `retain` is not an array of 1 to 64 strings.
- An entry fails the prefix or character rule above.

A capture that supplies `pii` fails with `PII_UNAVAILABLE` (below) when the vault's observed activation has no PII surface or has `selectors=off`. That combination means the application is configuring retention for findings the core cannot produce. Such an application would believe PII is handled while PII passes through as undetected plaintext.

### 2. `warn` and `allow` PII keep the existing `unredacted` semantics

This part is unchanged from [Gate capture on core actions](2026-09-27-gate-capture-on-core-actions.md). Any `warn` or `allow` finding, PII or not, fails the capture with `UNREDACTED_FINDINGS` under the default `unredacted: "reject"`. With `"pass-through"` it is left as plaintext and reported in `passedThrough` and `passedThroughTypes`. The vault never changes a PII `warn` into `redact` or `allow`, and never leaves it out of the gate.

Impact, stated plainly: once PII is active, **most real captures that contain Medium- or Low-confidence PII will fail by default**. The application has two ways out. Both are its own decision:

- Pass a core `policy` that maps the chosen PII types to `redact`, so they are replaced. Retention still requires §1's allowlist. Or map them to `allow` with `"pass-through"`.
- Choose `unredacted: "pass-through"` for a named outbound boundary and accept the plaintext PII that `passedThroughTypes` reports.

Worker mode has neither `policy` nor `eligible` in the protocol, because functions cannot be cloned, and a `ruleset` adds detectors without changing built-in actions. So a Worker-mode capture containing warn-level PII can only reject or pass through (see *Questions left open*).

### 3. The application owns core PII activation. The vault forwards and observes; it never chooses.

The vault must never fix a realm to a selection the application did not state. It must not be a second, competing initializer either. One rule covers every surface: **the vault forwards a selection only when the application passes one. Otherwise it adopts the realm's existing activation. In both cases it records the observed identity.**

#### Main thread, `@redact-secret/vault`

```ts
export interface VaultOptions {
  // …existing fields unchanged…
  /**
   * PII selectors, forwarded verbatim (as a copied array) to the core's
   * `initialize({ pii })`. `[]` is an explicit "PII off". Omit to adopt the
   * activation the application already established; the vault then calls no
   * initializer on a core that has a PII surface.
   */
  readonly pii?: readonly string[];
  /**
   * Optional exact canonical activation identity the application expects,
   * compared byte-for-byte with `piiActivation()` after initialization or
   * adoption.
   */
  readonly expectPiiActivation?: string;
}

export interface Vault {
  // …existing members unchanged…
  /**
   * The core's canonical activation identity observed at `createVault`, or
   * `null` when the installed core has no PII surface (beta.9). Fixed for the
   * vault's lifetime because activation is one-shot per realm.
   */
  readonly piiActivation: string | null;
}
```

`createVault` does exactly this, after its existing argument and CSPRNG checks:

1. **Shape check.** `pii`, if present, must be an array of 0 to 64 strings, each 1 to 128 characters. `expectPiiActivation`, if present, must be a 1 to 512 character string. Otherwise `INVALID_ARGUMENT`. The vault does **not** parse selector grammar. The core owns it and reports `PII_SELECTOR_*`.
2. **Feature detection.** The core has a PII surface iff its public module exports a `piiActivation` function. Detection happens at runtime so the package type-checks and runs against beta.9.
3. **Core without a PII surface (beta.9).**
   - A non-empty `pii` or any `expectPiiActivation` fails with `PII_UNAVAILABLE` before the vault calls the core.
   - Otherwise the vault calls `initialize()` exactly as today and records `piiActivation = null`. Omitted `pii` and `pii: []` both do this, because beta.9 is PII-off by construction and has no selection to lock.
4. **Core with a PII surface, `pii` present.** The vault calls `initialize({ pii })` with the application's array, verbatim.
   - An identical canonical selection already active (for example `["pii"]` against an existing `["pii:global"]`) resolves idempotently. The core runtime canonicalizes, not the vault.
   - A different one rejects, and the vault throws `CORE_FAILURE` with `coreCode: "PII_ACTIVATION_CONFLICT"`. The realm keeps the application's selection. The vault changed nothing.
   - Selector errors surface the same way with `coreCode` `PII_SELECTOR_INVALID`, `PII_SELECTOR_UNSUPPORTED`, or `PII_SELECTOR_UNAVAILABLE`.
5. **Core with a PII surface, `pii` omitted.** The vault calls `piiActivation()` and does **not** call `initialize`.
   - If it returns, the application already initialized the core. The vault adopts that activation.
   - If it throws `NOT_INITIALIZED`, the vault throws `CORE_FAILURE` with `coreCode: "NOT_INITIALIZED"` and still calls no initializer. The application fixes this by awaiting the core's own `initialize(...)` first, or by passing `pii` (`[]` for credentials-only).
6. **Record and compare.** The vault reads `piiActivation()` once. If `expectPiiActivation` is set and differs, the vault throws `PII_ACTIVATION_MISMATCH` and no vault is returned. Otherwise the identity becomes `vault.piiActivation`.

New fixed, value-free `VaultErrorCode`s:

| Code | Message | When |
| --- | --- | --- |
| `PII_UNAVAILABLE` | `PII options were supplied, but the redaction core has no PII support or PII detection is not active.` | A PII option on a core without a PII surface; a capture's `pii` option while the observed activation is `null` or `selectors=off`. |
| `PII_ACTIVATION_MISMATCH` | `The redaction core's PII activation differs from the expected activation.` | The observed identity differs from `expectPiiActivation`, or from a Python bridge's pinned identity. |

Neither error carries a selector, an identity string, or any input. Core rejections stay `CORE_FAILURE` plus the core's fixed `coreCode`, as before.

`@redact-secret/vault-server` creates its vault through `createVault` (`packages/vault-server/src/server-vault.ts`). Its options gain the same `pii` and `expectPiiActivation` fields, forwarded verbatim. Its capture options gain the same `pii: PiiRetention`, forwarded verbatim. It adds no activation behavior of its own.

#### Worker mode ([#39](https://github.com/redact-secret/redact-secret-vault/issues/39))

The Worker is its own realm with its own core instance, and the application writes the Worker script. So activation belongs to that script, not to the page:

- `startVaultWorkerHost({ pii?, expectPiiActivation?, … })` has exactly the main-thread `createVault` semantics inside the Worker realm, including adoption when the Worker script initialized the core itself.
- **The page cannot choose the Worker's selection.** No request message carries selectors. A hostile page talking to the Worker directly therefore cannot lock or change activation.
- The `vault-ready` message gains `piiActivation: string | null`. `vault-init-failed` still carries only `code` and `coreCode`.
- `PROTOCOL_VERSION` becomes `2`. A version-1 peer is rejected with `WORKER_PROTOCOL_VIOLATION`, and unknown keys are still rejected.
- `CreateWorkerVaultOptions` gains `expectPiiActivation?: string`. The client compares it with the ready message and rejects `createWorkerVault` with `PII_ACTIVATION_MISMATCH` on a difference. `WorkerVault` exposes `readonly piiActivation: string | null`.
- `WorkerCaptureOptions` gains `pii: PiiRetention`. It is a plain cloneable object, so it is allowed. The host parser accepts only the key `retain` with a string array and applies §1's validation independently.

#### Python bridge ([#40](https://github.com/redact-secret/redact-secret-vault/issues/40))

Each `NodeCoreBridge.scan` spawns a fresh Node.js process whose realm has no other initializer. So the Python application's bridge configuration is the only owner of the selection. Adoption is meaningless here, and omission means PII off.

- **Python interface.** `NodeCoreBridge(…, pii: Sequence[str] = (), expected_pii_activation: str | None = None)`.
- **Request.** The bridge request JSON gains `"pii": string[]`.
  - `core_bridge.mjs` calls `initialize({ pii })` when the core has `piiActivation`.
  - Otherwise it calls plain `initialize()` when `pii` is empty.
  - Otherwise, with a non-empty `pii` and no PII surface, it returns `{"error":{"code":"PII_UNAVAILABLE"}}`.
- **Response.** A successful response gains `"piiActivation": string | null`, where `null` means no PII surface. The bridge does not invent an identity string for beta.9.
- **Pinning.** `NodeCoreBridge` compares every response with `expected_pii_activation` when that is set. Otherwise it pins the identity from its first successful response and requires every later response to match. Each call is a new process, so this catches a core swapped underneath the server. A difference raises `VaultServerError(PII_ACTIVATION_MISMATCH)`. Bridge-reported core codes surface as `CORE_FAILURE` with `core_code`, as today.
- **Retention.** `VaultServerErrorCode` gains `PII_UNAVAILABLE` and `PII_ACTIVATION_MISMATCH`. `CaptureOptions` gains `pii: PiiRetention | None = None` with `retain: tuple[str, ...]`, under §1's exact rules and order relative to `eligible`.

### 4. Compatibility with core beta.9

- The package keeps compiling and passing CI against the pinned `0.1.0-beta.9`. PII support is detected at runtime by the presence of `piiActivation`, never by version string.
- On beta.9, callers that pass no PII option see no behavior change: `createVault()`, `startVaultWorkerHost()`, and `NodeCoreBridge()` call plain `initialize()` exactly as today. The only additions are the observable `piiActivation: null` and the `v: 2` Worker protocol.
- On beta.9, any PII option fails closed with `PII_UNAVAILABLE` before the core is called: a non-empty `pii` selection, `expectPiiActivation`, or a capture's `pii` retention. `pii: []` is accepted and equals omission.
- On beta.10, omitting `pii` with an uninitialized core is a deliberate behavior change: `CORE_FAILURE`/`NOT_INITIALIZED` instead of silently locking PII off. The release notes for the alpha that adopts beta.10 ([#41](https://github.com/redact-secret/redact-secret-vault/issues/41), [#44](https://github.com/redact-secret/redact-secret-vault/issues/44)) must call it out with the one-line migration: `createVault({ pii: [] })`, or await the core's `initialize` first.

## Rationale

- **Separate PII opt-in.** Many existing `eligible` callbacks are written as allow-all or as a deny-list of credential types (`(f) => f.type !== "x"`). Such a callback returns `true` for every PII type it has never heard of. If `eligible` alone gated PII, upgrading the core would silently begin retaining payment card numbers. An exact-type allowlist defaults closed as the core adds families, and it is auditable in configuration.
- **Data, not a callback.** A `string[]` crosses the Worker boundary and the Python bridge unchanged. A predicate cannot (Worker mode already rejects `eligible`). One shape keeps the three surfaces identical.
- **Adopt instead of initialize.** Activation is realm-global and one-shot, so any initializer call the vault makes is a realm-wide choice. Calling plain `initialize()` would lock PII off whenever the vault happens to run first, and would crash whenever the application ran first with PII. Adopting via `piiActivation()` has no side effect. Forwarding only an application-supplied selection means the vault's only effect is the one the application asked for.
- **Fail on uninitialized rather than default off.** Defaulting to off would reintroduce the order-dependence #38 describes. The failure is loud, fixed, and fixed by one explicit argument.
- **An identity check for the separate realms.** A Worker or bridge process activates in another realm, where the caller cannot call `piiActivation()` itself. The identity string is the core's own observable contract, so comparing it copies no core logic.

## Alternatives rejected

- **Let `eligible` decide PII.** Rejected: a generic allow-all or deny-list callback would retain PII by default, which is the failure #45 exists to prevent.
- **A PII predicate (`pii: { retain: (f) => boolean }`).** Rejected: it cannot be cloned into a Worker or serialized to the bridge, and it cannot be audited as configuration. `eligible` already provides narrowing on top of the allowlist.
- **Retain by family or prefix (`"pii_jurisdiction_us_*"`, selectors).** Rejected: the scope would silently widen as the core adds families.
- **The vault always calls `initialize({ pii })` with a default such as `[]`.** Rejected: the vault would choose a selection the application did not state.
- **The vault calls plain `initialize()` when `pii` is omitted, as today.** Rejected: it locks the realm to off or conflicts, depending on call order.
- **The vault retries or catches `PII_ACTIVATION_CONFLICT` and continues with the existing activation.** Rejected: a caller that stated a selection would get a vault scanning under a different one.
- **Treat Medium/Low PII as non-blocking, or promote `warn` to `redact` inside the vault.** Rejected: it reinterprets core actions, contrary to the gate ADR and CONVENTIONS rule 4. The application's `policy` is the supported lever.
- **Let the page send a PII selection to the Worker in a message.** Rejected: a hostile same-page script could lock the Worker realm's selection.

## Consequences

- #38, #39, and #40 implement exactly the shapes above. Changing a name or rule needs an amendment to this record.
- An application that enables PII and wants any PII restorable must name each type. Everything else is replaced and counted in `unrestorable`.
- With PII on and default options, captures containing Medium or Low PII reject. This is intended. Applications must choose a policy or pass-through per boundary.
- On beta.10, `createVault()` with no arguments requires the core to have been initialized first. This is a behavior change for the alpha that adopts beta.10.
- Worker mode cannot remap PII actions until a cloneable policy exists.
- The threat model records new residual risks: regulatory exposure from opting in to retain PAN/SSN-class values, realm-global activation, warn-level PII pass-through, and PII type labels as metadata. See [threat model](../specs/threat-model.md#pii-findings-core-beta10--current-unreleased).

## Verification before implementation is accepted

Covered by #38, #39, #40, and #43, against a local beta.10 build, with PII-on cases skipped and reported when the installed core has no PII surface. All data is synthetic, such as test-range card numbers and invalid SSN area numbers.

- **Initialization order.** Both orders, identical-selection idempotence, `PII_ACTIVATION_CONFLICT` as `CORE_FAILURE`, adoption, and `NOT_INITIALIZED` on omission.
- **Retention.** No retention without `pii.retain`. An allow-all `eligible` still does not retain PII. `eligible` narrows the allowlist. Non-retained PII counts in `unrestorable`. An allowlisted type retains and restores.
- **Failure codes.** `PII_UNAVAILABLE` on beta.9 and on off activation. `PII_ACTIVATION_MISMATCH`.
- **Worker protocol.** v2 key validation.
- **Python bridge.** Selector propagation and identity pinning.

## Questions left open

- A cloneable policy for Worker mode (for example a type-to-action map), so warn-level PII can be redacted without main-thread code. Tracked outside this record.
- Whether a future core adds PII types to always-redact, which would change §2's practical impact but not the rule.
- Per-type retention limits (for example a lower `maxUses` or TTL ceiling for PII). Not decided. The existing limits apply uniformly.
- Streaming capture remains excluded, as in the gate ADR.
