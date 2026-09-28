# Qualification record: vault surfaces against @redact-secret/core 0.1.0-beta.10, PII off and on

**Status:** executed evidence, 2026-09-28, for the unreleased packages on `main` (`@redact-secret/vault` and `@redact-secret/vault-server` after [#38](https://github.com/redact-secret/redact-secret-reversible/issues/38)–[#41](https://github.com/redact-secret/redact-secret-reversible/issues/41), and `redact-secret-vault-server` for Python after [#40](https://github.com/redact-secret/redact-secret-reversible/issues/40)). It is additional to the [0.1.0-alpha.1 record](qualification-0.1.0-alpha.1.md) and the [Worker-mode record](qualification-worker-mode.md). Those records describe core `0.1.0-beta.9` and stay as recorded. `@redact-secret/vault@0.1.0-alpha.1` is still the release for beta.9. This record qualifies no published vault version.
**Issue:** [#42](https://github.com/redact-secret/redact-secret-reversible/issues/42). **Decision:** [PII retention and activation ownership](../decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md).

## Pinned core artifact

| Package | Version | npm integrity |
| --- | --- | --- |
| `@redact-secret/core` | `0.1.0-beta.10` | `sha512-EjsFPTdEhbxMkzsjYyRgmfXv1axKH2yA6VANrfl0l1ccSyLkmk++J1jGmSxJpta+Zua91VWW5YpC9aXPdLsNnQ==` |
| `@redact-secret/wasm` | `0.1.0-beta.10` (core dependency) | `sha512-NPzFJI5sCF9r4LGyWAKZOAdEa7ZqekmkQ8FSra0QbeFVEgD0ojU+q5jcu3luG5AsMgMJyu1rI0iOn0ymWlLSnQ==` |
| `@redact-secret/node-darwin-arm64` | `0.1.0-beta.10` (optional, local addon) | `sha512-htycClikxOGL2QhX7COrKCpwXL1vsyGBP+981+kNuBCJrwt24IqL/Q7gdcMxavnIzwdCrxFpmdbkKZlba7CT2A==` |
| `@redact-secret/node-linux-x64-gnu` | `0.1.0-beta.10` (optional, CI addon) | `sha512-tpbniunBS/v7DL+uB7pEsUpEdB3g7mVRlkfv/RMCG/KYBC5Q/XEPJCSpmBjPRJovHNzFqs6EC2dco3Zc8c6boA==` |

The vault peer-depends on `@redact-secret/core` `0.1.0-beta.10` exactly, and the Python bridge's `PINNED_CORE_VERSION` is `0.1.0-beta.10`. The vault imports only the core's public root export; the packed-artifact boundary check (`npm run check:boundaries`) enforces this.

**PII selection under test.** "PII on" means `initialize({ pii: ["pii"] })`. The core reports it as `credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v1`. "PII off" means `pii: []`, reported as `credentials=full;selectors=off;families=;vocabulary=pii-context/v1`. Other selections (for example `pii:us`, which adds `pii:us:ssn`) are not qualified.

## Method

The runners from the earlier records are unchanged in method: the packed vault tarball and the pinned core are installed into a throwaway consumer project outside the repository, browsers load a production Vite bundle under a strict CSP, and the Worker runner uses a real dedicated Worker. #42 adds two lanes to every JavaScript runtime and one to Python. Core PII activation is realm-global and one-shot, so each lane and each scenario gets its own realm.

1. **PII off.** The portable suite (`packages/vault/test/suite.js`) with the realm pre-initialized `pii: []`. This is the existing lane.
2. **PII on.** The same suite, unchanged, with the realm pre-initialized `pii: ["pii"]`. Every existing corpus case and runtime check must still pass.
3. **PII scenarios.** `packages/vault/test/pii-scenarios.js` (main thread) or the Worker runner's scenarios, one fresh, uninitialized realm each. Node.js starts a new process, the browser loads a new page, and Worker mode creates new Workers.
4. **Python.** `pytest` replays the whole corpus twice, with the bridge's selection `()` and `("pii",)` (`packages/vault-server-py/tests/test_conformance.py`). The real-core bridge tests in `test_pii_bridge.py` layer 4 also run against the pinned beta.10.

### Conformance corpus 1.2.0

`conformance/v1/corpus.json` moves from 1.1.0 to 1.2.0: `coreCompatibility` is beta.10, one fixture is added, and eleven synthetic PII cases are added. The format changes are backward compatible:

- A case's `piiActivation` (`"on"` or `"off"`) names the activation the case needs. A runner in a different activation reports it as skipped, never as passed.
- `requiresSharedRealm` marks a case that needs one realm-global activation shared by every vault. The Python bridge starts a fresh core per scan, so it skips those two cases with that reason.
- A `vault` step can carry `pii`, `expectPiiActivation`, and an `expect` error.

| Case | Activation | What it asserts |
| --- | --- | --- |
| `pii.retention.default-not-retained` | on | No `pii.retain`: the IBAN is replaced but not retained (`unrestorable: 1`). An `eligibleTypes` that lists `pii_global_iban` does not widen retention. |
| `pii.retention.allowlist-restores` | on | `pii.retain: ["pii_global_iban"]` retains it, and the restore returns the exact input. |
| `pii.retention.allowlist-is-exact-and-eligible-narrows` | on | A well-formed type that is absent from the input retains nothing. `eligible` narrows the allowlist. Duplicate entries are accepted. |
| `pii.action.warn-rejected-by-default` | on | A `warn` PII finding fails the capture with `UNREDACTED_FINDINGS` and commits nothing. |
| `pii.action.warn-pass-through-is-visible` | on | With `"pass-through"`, the PII plaintext stays and is reported in `passedThroughTypes`. |
| `pii.action.block-rejects` | on | A `block` PII finding fails with `BLOCKED_FINDING`, even when allowlisted. |
| `pii.activation.retention-unavailable-when-off` | off | `pii.retain` on a `selectors=off` activation fails with `PII_UNAVAILABLE`. |
| `pii.activation.conflict-when-off` | off, shared realm | `createVault({ pii: ["pii"] })` fails with `CORE_FAILURE` / `PII_ACTIVATION_CONFLICT`. |
| `pii.activation.conflict-when-on` | on, shared realm | `createVault({ pii: [] })` fails with `CORE_FAILURE` / `PII_ACTIVATION_CONFLICT`. |
| `pii.activation.equivalent-selection-is-idempotent` | on | `pii: ["pii:global"]` against an existing `["pii"]` activation succeeds. |
| `pii.activation.expectation-mismatch` | any | An `expectPiiActivation` the core does not report fails with `PII_ACTIVATION_MISMATCH`. |

The `warn` and `block` PII findings come from an explicit core `policy`. See [Warn-level PII](#warn-level-pii).

A sensitivity check ran the ten activation-gated cases in the wrong activation, with the gate removed. All ten failed there, so none of them passes vacuously.

### PII scenarios, one fresh realm each

| Scenario | Main thread (Node.js, browsers) | Worker mode |
| --- | --- | --- |
| Application initializes first; vault adopts | `order:application-first-vault-adopts` (also idempotent `pii:global` with a matching `expectPiiActivation`) | `order:worker-script-first-host-adopts` (a second Worker realm matches through `expectPiiActivation`) |
| Application first; vault passes a different selection | `order:application-first-vault-conflicts` (`CORE_FAILURE` / `PII_ACTIVATION_CONFLICT`, realm unchanged) | `order:worker-script-first-host-conflicts` |
| Vault first; application's identical call agrees, different call conflicts | `order:vault-first-application-conflicts` | `order:host-first-worker-script-conflicts` (the Worker script reports outcome codes on a message kind the client ignores) |
| `pii: []` locks off; `pii.retain` then fails `PII_UNAVAILABLE` | `order:vault-first-off-then-retention-unavailable` | `retention:selectors-off-capture-pii-unavailable` |
| `pii` omitted, core uninitialized | `activation:omitted-and-uninitialized-is-not-initialized` (`CORE_FAILURE` / `NOT_INITIALIZED`; the core stays uninitialized) | same id |
| `expectPiiActivation` mismatch | `activation:expectation-mismatch-rejects` | same id |
| Invalid selector | `activation:selector-error-surfaces-core-code` (`CORE_FAILURE` / `PII_SELECTOR_*`) | not run |
| Retention: default, allow-all `eligible`, narrowing, allowlist restore, warn gate | `retention:default-allowlist-narrowing-and-warn-gate` | Default and allowlist only: `parity:pii-retention-default-and-allowlist` in the PII-on Worker suite. `eligible` and `policy` cannot cross the protocol. |

## Results

Local run: macOS 26 (darwin-arm64), Node.js 22.16.0, Python 3.14.7, Playwright 1.63.0. The CI results are in [CI evidence](#ci-evidence).

| Runtime | Core artifact | PII off | PII on | PII scenarios |
| --- | --- | --- | --- | --- |
| Node.js 22.16.0, darwin-arm64 | addon | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Node.js 22.16.0, darwin-arm64 | wasm fallback | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Chromium 153.0.8010.12 (Playwright), main thread | wasm, strict CSP | 70/70 (8 skipped) | 74/74 (2 skipped) | 8/8 |
| Firefox 155.0 (Playwright), main thread | wasm, strict CSP | 70/70 (8 skipped) | 74/74 (2 skipped) | 8/8 |
| WebKit 26.6 (Playwright), main thread | wasm, strict CSP | 70/70 (8 skipped) | 74/74 (2 skipped) | 8/8 |
| Chromium 153.0.8010.12, dedicated Worker | wasm, Worker CSP | 23/23 (1 skipped) | 18/18 (1 skipped) | 6/6 |
| Firefox 155.0, dedicated Worker | wasm, Worker CSP | 23/23 (1 skipped) | 18/18 (1 skipped) | 6/6 |
| WebKit 26.6, dedicated Worker | wasm, Worker CSP | 23/23 (1 skipped) | 18/18 (1 skipped) | 6/6 |
| Python 3.14.7 bridge (`pytest`), Node.js 22.16.0 subprocess | addon | 50 corpus cases: 41 run, 9 skipped | 50 corpus cases: 47 run, 3 skipped | not applicable |

How to read the counts:

- The suite has 50 corpus cases, 21 runtime checks, and 1 leakage check. PII off skips the 8 `on` cases. PII on skips the 2 `off` cases.
- The browser main-thread runner adds 5 checks with PII off (the 4 from alpha.1 plus `browser:pii-activation-off`) and 3 with PII on.
- The Worker suite has 17 cases. Each lane skips the one PII case for the other activation. The runner adds 7 checks with PII off (the 6 from the Worker-mode record plus `worker:pii-activation-off`) and 2 with PII on.
- Python skips per lane: `off` skips the 8 `on` cases plus the shared-realm `conflict-when-off`, and `on` skips the 2 `off` cases plus `conflict-when-on`. The whole package run is `205 passed, 16 skipped` (`ruff check .` clean). The 4 other skips are the beta.9-only bridge tests.
- `npm run test:vault` (unit tests, fake and real core) reports `74 passed, 0 failed, 5 skipped`. The 5 skips are the beta.9-only cases.

In every configuration, the core action probes match the alpha.1 record: `redact` and `block` are replaced, `warn` and `allow` leave plaintext, and the GitHub-token fixture after a leading emoji has the UTF-16 range `[3, 43)`. The existing negative controls (no-`'wasm-unsafe-eval'`, `worker-src 'none'`, no WASM inside the Worker, page-selected mismatch) still fail closed. Every PII-on and scenario page recorded no CSP violation.

### CI evidence

CI run [36405277007](https://github.com/redact-secret/redact-secret-reversible/actions/runs/36405277007) on commit `7361b8ca54059cb6abc22b805c765c685f34917b` (an earlier push of pull request [#51](https://github.com/redact-secret/redact-secret-reversible/pull/51). Its code, tests, corpus, and workflows are identical to the final commit; only documentation changed after it). Reports are uploaded as run artifacts (`reports-node-*`, `reports-browser`, `reports-worker`). Each `node` job took under a minute; `browser` took 1m6s and `worker` 1m21s.

| Runtime | Platform | Core artifact | PII off | PII on | PII scenarios |
| --- | --- | --- | --- | --- | --- |
| Node.js 20.20.2 | linux-x64, darwin-arm64 | addon | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Node.js 20.20.2 | linux-x64, darwin-arm64 | wasm fallback | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Node.js 22.23.2 | linux-x64, darwin-arm64 | addon | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Node.js 22.23.2 | linux-x64, darwin-arm64 | wasm fallback | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Node.js 24.21.0 / 24.20.0 | linux-x64 / darwin-arm64 | addon | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Node.js 24.21.0 / 24.20.0 | linux-x64 / darwin-arm64 | wasm fallback | 65/65 (8 skipped) | 71/71 (2 skipped) | 8/8 |
| Chromium 153.0.8010.12, main thread | linux-x64 | wasm, strict CSP | 70/70 (8 skipped) | 74/74 (2 skipped) | 8/8 |
| Firefox 155.0, main thread | linux-x64 | wasm, strict CSP | 70/70 (8 skipped) | 74/74 (2 skipped) | 8/8 |
| WebKit 26.6, main thread | linux-x64 | wasm, strict CSP | 70/70 (8 skipped) | 74/74 (2 skipped) | 8/8 |
| Chromium 153.0.8010.12, dedicated Worker | linux-x64 | wasm, Worker CSP | 23/23 (1 skipped) | 18/18 (1 skipped) | 6/6 |
| Firefox 155.0, dedicated Worker | linux-x64 | wasm, Worker CSP | 23/23 (1 skipped) | 18/18 (1 skipped) | 6/6 |
| WebKit 26.6, dedicated Worker | linux-x64 | wasm, Worker CSP | 23/23 (1 skipped) | 18/18 (1 skipped) | 6/6 |
| Python 3.10, 3.12, 3.13 bridge (`pytest -q`), Node.js 22 subprocess | linux-x64 | addon | lane `off` | lane `on` | `205 passed, 16 skipped` on each Python version |

### Finding types: beta.9 compared with beta.10

Every corpus fixture and every capture input that uses only fixtures (8 fixtures and 56 inputs) was scanned with `0.1.0-beta.9`, with `0.1.0-beta.10` PII off, and with `0.1.0-beta.10` using `pii: ["pii", "pii:us"]`. The type, confidence, and action lists are identical in all three: `github_token`, `aws_access_key_id`, `jwt`, and `contextual_secret` (High `redact` and Medium `warn`). No corpus input produces a PII finding or an `anthropic_admin_api_key` finding. This matches [#41](https://github.com/redact-secret/redact-secret-reversible/issues/41): no finding-type change affects the corpus. The comparison covers the corpus only. It is not a detection benchmark.

## Known differences between runtimes

- **`findingReuseAfterRedact`.** Passing the same findings to a second `redact` call is `allowed` on the Node.js addon, and fails with `INVALID_FINDINGS` on the WASM artifact (Node.js fallback and all three browsers). This is unchanged from beta.9 and does not depend on PII activation. The vault never reuses findings.
- **Python bridge activation.** Every `NodeCoreBridge.scan` runs in a fresh Node.js process, so an activation conflict cannot happen there and the two `requiresSharedRealm` cases are skipped. The bridge observes activation on its first scan, not at construction. Its conformance adapter therefore makes one `scan("")` call for a `vault` step that expects an error. Its closest equivalent to the conflict checks is identity pinning (`PII_ACTIVATION_MISMATCH`), covered by `test_pii_bridge.py`.
- **Worker mode.** The protocol carries neither `eligible` nor `policy`, so Worker mode qualifies default retention and the allowlist, but not `eligible` narrowing or warn gating by policy. Invalid selectors are not run in a Worker.

## Warn-level PII

No synthetic input was found that makes beta.10 produce a Medium- or Low-confidence (default `warn`) PII finding. Inputs tried: documentation-range emails (`example.com`, `.test`, `.invalid`), `555` phone numbers, test card numbers, documentation-range and private IP addresses, the documentation IBAN with and without a field label, and invalid or advertising-sample SSNs, all with and without labels such as `contact`, `id`, and `national id`. Each was either not detected or detected at High (`redact`) next to a field label. Two examples: `ip 10.0.0.1` gives `pii_global_network_address`, and `card number 4242 4242 4242 4242` gives `pii_global_payment_card`. The corpus therefore gets `warn` from an explicit policy (`pii_global_iban: "warn"`). That exercises the vault's gate identically, because the gate reads the action, not the confidence. It does not show which real inputs the core rates Medium or Low. A default-action `warn` PII case is left to [#43](https://github.com/redact-secret/redact-secret-reversible/issues/43).

## Residual risks

- Detection is incomplete by design, and the IBAN fixture is detected only next to a field label. Qualification shows the vault's behavior for findings the core reports. It does not show that PII is found.
- Only the `["pii"]` selection is qualified end to end. `pii:us` was probed in the finding-type comparison only.
- The PII scenarios run once per realm and do not race concurrent initializers. Concurrent-initialization behavior is the core's contract and is not tested here.
- The PII residual risks in the [threat model](../specs/threat-model.md) apply unchanged: regulatory exposure from allowlisting PAN- or SSN-class types, one activation per realm, warn-level PII pass-through, and PII type labels as metadata.

## What this does and does not establish

- **Establishes**, for the exact versions above: the corpus and runtime suite pass with PII off and on in Node.js (addon and WASM), in three browser engines on the main thread, and in a dedicated Worker, all under a strict CSP. The PII activation contract holds in each realm type: adoption, both initialization orders, conflict, `NOT_INITIALIZED`, and mismatch. PII is not retained by default, an allowlisted type is retained and restores, and `eligible` narrows but never widens retention (main thread). The Python bridge replays the same corpus with PII off and on. No fixture value or issued token appears in any error, audit event, or console output in any lane.
- **Does not establish**: a published vault release on beta.10 ([#44](https://github.com/redact-secret/redact-secret-reversible/issues/44)); default-confidence `warn` PII ([#43](https://github.com/redact-secret/redact-secret-reversible/issues/43)); PII selections other than `["pii"]`; `maxFindings` with PII-dense input ([#43](https://github.com/redact-secret/redact-secret-reversible/issues/43)); PII detection quality; branded Chrome, Edge, or Safari on real devices; Windows or Linux arm64 Node.js; Python on Windows; `SharedWorker`, Service Worker, or `worker_threads`; persistence; streaming; memory erasure; resistance to same-page script compromise.

## Reproduce

```bash
npm ci
npm run check:boundaries
npm run test:vault
npm run qualify:node           # current Node.js; addon and WASM; PII off, on, scenarios
npx playwright install chromium firefox webkit
npm run qualify:browser        # BROWSERS=chromium,firefox,webkit
npm run qualify:worker         # BROWSERS=chromium,firefox,webkit
cd packages/vault-server-py && pip install -e ".[test,lint]" && ruff check . && pytest -q
```

Reports are written to `.qualification/reports/`. The PII lanes add `-pii-on` and `-pii-scenarios` report files next to each existing one.
