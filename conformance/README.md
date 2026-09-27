# Adversarial conformance corpus

Language-neutral cases that any reversible-restoration implementation in this repository must pass for each runtime it claims ([#10](https://github.com/redact-secret/redact-secret-reversible/issues/10)). The corpus is versioned separately from detection benchmarks: it measures vault behavior, not detection accuracy.

- `v1/corpus.json`: version 1.0.0, written against `@redact-secret/core@0.1.0-beta.9` (full profile).
- Runner: [`packages/vault/test/suite.js`](../packages/vault/test/suite.js) interprets the corpus in Node.js and in browsers, and adds runtime checks that need code (callback re-entrancy, RNG failure, getters, microtask ordering).

## Format

`fixtures` holds synthetic values. Each is unmistakably fake, and none is a credential. Each case is an ordered list of `steps`:

| op | Fields | Meaning |
| --- | --- | --- |
| `vault` | `id?`, `limits?`, `releasePolicy?` | Create a vault; the clock starts at 0. `releasePolicy` is `{denyTypes}`, `{throw: true}`, or `{returns: value}`. |
| `capture` | `vault?`, `as?`, `input`, `options`, `expect` | `options.policy` maps finding type → action (`default` for others; unmapped types become `redact`; omit to use the core's built-in policy). `options.eligibleTypes` restricts retention. |
| `restore` | `vault?`, `sink`, `fields`, `expect` | `expect` is either `fields`/`restored` or `error`/`reason`. |
| `revoke` | `capture`, `expect.removed` | |
| `advance` | `ms` | Advance the injected clock. |
| `dispose` | | |
| `stats` | `expect` | Compare named counters. |

Templates: `{NAME}` is a fixture; `{cN.i}` is token `i` of capture `cN`; `{cN.text}` is that capture's redacted text; `{cN.i:upper|truncate|space}` alters a token; `{repeat:x:N}` repeats a character.

Every run also asserts that no fixture value or issued token appears in any error (message, stack, JSON, own properties), audit event, or console output.

## Covered classes

Action gates (`block`, `redact`, `warn`, `allow`; default and custom policy; eligibility), Unicode ranges (ZWJ emoji, RTL, combining marks, accented and astral characters), short matches, repeated values, literal collisions, forged, altered, cross-session, copied, duplicated, and reordered tokens, sink/path grants, budgets, page-local policy denial and failure, revoke/restore ordering, entry and vault expiry, disposal, every configured limit, argument validation, and diagnostic leakage.

Server-only classes (principal, tenant, policy revision) and persistent-store classes (crash, replica lag, record substitution) are left to their future corpus versions of `v1/corpus.json`, which is coupled to `packages/vault/test/suite.js`'s `Vault` API and not yet shared with the server-authority or persistent-store API surfaces. The [server authority interface](../docs/decisions/2026-09-27-define-server-authority-interface.md) (#15) names the exact server-only case classes a future corpus version must cover — principal-resolution failure, cross-tenant, missing/invalid purpose, revoked-vs-unknown-token, policy-evaluation-error/timeout, and policy-revision staleness. [`@redact-secret/vault-server`](../packages/vault-server/README.md) (#16) implements every one of those classes as executable adversarial tests in its own suite (`packages/vault-server/test/`) against its own API — including N-tenant cross-tenant isolation and concurrent restore/revoke races — pending a shared, language-neutral corpus version that both this package and [#17](https://github.com/redact-secret/redact-secret-reversible/issues/17)'s Python integration can run unchanged. The [persistent store contract](../docs/decisions/2026-09-27-define-persistent-store-contract.md) (#19) likewise names the exact persistent-store-only case classes a future corpus version must cover — crash-mid-consume, replica-lag eligibility, cross-tenant record substitution, key-rotation race, backup replay, and ambiguous-consume resolution — for [#20](https://github.com/redact-secret/redact-secret-reversible/issues/20) to implement as executable cases against its chosen backend.
