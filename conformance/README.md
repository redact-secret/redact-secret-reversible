# Adversarial conformance corpus

Language-neutral cases that any reversible-restoration implementation in this repository must pass for each runtime it claims ([#10](https://github.com/redact-secret/redact-secret-vault/issues/10)). The corpus is versioned separately from detection benchmarks: it measures vault behavior, not detection accuracy.

- `v1/corpus.json`: version 1.3.0, written against `@redact-secret/core@0.1.0-beta.10` (full profile). Version 1.2.0 added the PII cases (`pii.*`) and the `IBAN` fixture ([#42](https://github.com/redact-secret/redact-secret-vault/issues/42)). Version 1.3.0 adds the `PHONE` fixture and two default-confidence `warn` PII cases ([#43](https://github.com/redact-secret/redact-secret-vault/issues/43)). Earlier versions targeted `0.1.0-beta.9`. Every non-PII case gives the same finding types on beta.9 and on beta.10, with PII off or on; see the [beta.10 qualification record](../docs/research/qualification-core-0.1.0-beta.10.md).
- Runners:
  - [`packages/vault/test/suite.js`](../packages/vault/test/suite.js) interprets the corpus in Node.js and in browsers, and adds runtime checks that need code (callback re-entrancy, RNG failure, getters, microtask ordering). Its host runners (`qualification/*.mjs`) run it twice, once in a realm initialized with PII off and once with PII on (`["pii"]`).
  - [`packages/vault-py/tests/conformance_runtime.py`](../packages/vault-py/tests/conformance_runtime.py) interprets the same corpus in Python against `redact_secret_vault.InMemoryVaultServer`, adapting the vault-level `releasePolicy` spec to the S1 `ServerReleasePolicy` contract under one fixed synthetic principal/tenant/purpose. Three case IDs' expected denial reasons are deliberately overridden where the S1 contract diverges from the vault-level one by design (documented in that file); see [docs/research/python-server-integration-2026-09-27.md](../docs/research/python-server-integration-2026-09-27.md). It replays every case in a PII-off and a PII-on lane.

## Format

`fixtures` holds synthetic values. Each is unmistakably fake, and none is a credential. Each case is an ordered list of `steps`:

| op | Fields | Meaning |
| --- | --- | --- |
| `vault` | `id?`, `limits?`, `releasePolicy?`, `pii?`, `expectPiiActivation?`, `expect?` | Create a vault; the clock starts at 0. `releasePolicy` is `{denyTypes}`, `{throw: true}`, or `{returns: value}`. `pii` and `expectPiiActivation` are forwarded verbatim to the implementation's activation options. `expect.error`/`expect.coreCode` name the error that creation must raise. |
| `capture` | `vault?`, `as?`, `input`, `options`, `expect` | `options.policy` maps finding type → action (`default` for others; unmapped types become `redact`; omit to use the core's built-in policy). `options.eligibleTypes` restricts retention. `options.pii` is `{retain: [...]}`, the exact PII types that may be retained. |
| `restore` | `vault?`, `sink`, `fields`, `expect` | `expect` is either `fields`/`restored` or `error`/`reason`. |
| `revoke` | `capture`, `expect.removed` | |
| `advance` | `ms` | Advance the injected clock. |
| `dispose` | | |
| `stats` | `expect` | Compare named counters. |

Templates: `{NAME}` is a fixture; `{cN.i}` is token `i` of capture `cN`; `{cN.text}` is that capture's redacted text; `{cN.i:upper|truncate|space}` alters a token; `{repeat:x:N}` repeats a character.

Every run also asserts that no fixture value or issued token appears in any error (message, stack, JSON, own properties), audit event, or console output.

Case-level fields (since 1.2.0):

| Field | Meaning |
| --- | --- |
| `piiActivation` | `"on"` (`selectors=pii:global`, from the selection `["pii"]`) or `"off"` (`selectors=off`). The case runs only under that core PII activation. A runner under a different activation reports it as **skipped**, never as passed. Cases without the field run under any activation. |
| `requiresSharedRealm` | The case needs one realm-global, one-shot core activation shared by every vault in the process, as in JavaScript. A runner whose core boundary starts a fresh core per call (the Python bridge) reports it as skipped with that reason. |

A Python-specific adapter rule: the bridge observes activation on its first core call. So for a `vault` step that expects an error, the Python runner makes one `scan("")` call, which must raise that error.

## PII cases

All values are synthetic. `IBAN` is the widely published documentation-example IBAN. It is not an account. Beta.10 detects it as `pii_global_iban` (High, `redact`) only next to a field label, so inputs write `iban {IBAN}`. Documentation-range emails, test card numbers, and `555-01xx` phone numbers are treated as synthetic by the core and not detected, so they are not used. `PHONE` (`555-2345`) is the core's own conformance value for a Medium-confidence phone finding: a seven-digit local number with no area code. After a label (`telephone={PHONE}`) beta.10 detects it as `pii_global_phone` (Medium, default action `warn`) with no policy. The `pii.action.default-warn-*` cases use it. The other `warn` and `block` cases assign the action to the IBAN with `options.policy`.

- Retention: `pii.retention.default-not-retained`, `pii.retention.allowlist-restores`, `pii.retention.allowlist-is-exact-and-eligible-narrows`.
- Actions: `pii.action.warn-rejected-by-default`, `pii.action.warn-pass-through-is-visible`, `pii.action.block-rejects`, `pii.action.default-warn-rejected-by-default`, `pii.action.default-warn-pass-through-is-visible` (a warn-level type listed in `pii.retain` is still passed through, not retained).
- Activation: `pii.activation.retention-unavailable-when-off`, `pii.activation.conflict-when-off` and `pii.activation.conflict-when-on` (shared realm), `pii.activation.equivalent-selection-is-idempotent`, `pii.activation.expectation-mismatch`.

Initialization order, `NOT_INITIALIZED`, and any other case that needs an *uninitialized* realm cannot run in a corpus replayed in one pre-initialized realm. Those are the per-realm scenarios in [`packages/vault/test/pii-scenarios.js`](../packages/vault/test/pii-scenarios.js) and `qualification/worker.mjs`.

## Covered classes

Action gates (`block`, `redact`, `warn`, `allow`; default and custom policy; eligibility), PII retention allowlist, PII action gates, and PII activation conflict and mismatch, Unicode ranges (ZWJ emoji, RTL, combining marks, accented and astral characters), short matches, repeated values, literal collisions, forged, altered, cross-session, copied, duplicated, and reordered tokens, sink/path grants, budgets, page-local policy denial and failure, revoke/restore ordering, entry and vault expiry, disposal, every configured limit, argument validation, and diagnostic leakage.

Server-only classes (principal, tenant, policy revision) and persistent-store classes (crash, replica lag, record substitution) are left to their future corpus versions of `v1/corpus.json`, which is coupled to `packages/vault/test/suite.js`'s `Vault` API and not yet shared with the server-authority or persistent-store API surfaces. The [server authority interface](../docs/decisions/2026-09-27-define-server-authority-interface.md) (#15) names the exact server-only case classes a future corpus version must cover — principal-resolution failure, cross-tenant, missing/invalid purpose, revoked-vs-unknown-token, policy-evaluation-error/timeout, and policy-revision staleness. Both server implementations cover all six as executable adversarial tests against their own APIs in the meantime, pending a shared, language-neutral corpus version both can run unchanged: [`@redact-secret/vault-server`](../packages/vault-server/README.md) (#16, `packages/vault-server/test/`, including N-tenant cross-tenant isolation and concurrent restore/revoke races) and [`redact-secret-vault` (Python)](../packages/vault-py/README.md) (#17, [`packages/vault-py/tests/test_server_authority.py`](../packages/vault-py/tests/test_server_authority.py)). The [persistent store contract](../docs/decisions/2026-09-27-define-persistent-store-contract.md) (#19) likewise names the exact persistent-store-only case classes a future corpus version must cover — crash-mid-consume, replica-lag eligibility, cross-tenant record substitution, key-rotation race, backup replay, and ambiguous-consume resolution — for [#20](https://github.com/redact-secret/redact-secret-vault/issues/20) to implement as executable cases against its chosen backend.
