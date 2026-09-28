# Python server integration: inventory, boundary decision, and equivalence evidence

**Status:** executed evidence, 2026-09-27. Written for [#17](https://github.com/redact-secret/redact-secret-vault/issues/17) (roadmap S3), against [decision-define-server-authority-interface](../decisions/2026-09-27-define-server-authority-interface.md) (S1, #15). Leaves the breadcrumbs [#18](https://github.com/redact-secret/redact-secret-vault/issues/18) (S4, JS/Python documentation and conformance) needs.

## 1. Inventory: is there a native Python core?

**No.** Checked against the `redact-secret` GitHub organization on 2026-09-27:

```
$ gh api repos/redact-secret/redact-secret/contents/packages --jq '.[].name'
javascript
$ gh api "search/repositories?q=redact-secret+in:name" --jq '.items[].full_name'
redact-secret/redact-secret
redact-secret/redact-secret-reversible
redact-secret/redact-secret-benchmarks
redact-secret/redact-secret-adapters
```

`redact-secret/redact-secret` (the core repository) publishes exactly one package, `packages/javascript` (npm `@redact-secret/core`). There is no `packages/python`, and no `redact-secret-python`/similar repository exists in the organization. A broader PyPI search found no official Python port. Per the issue's scope note, this is therefore a **qualified service boundary** situation, not a "choose a native package" situation.

### What the core's public API exposes (for a future native binding to match)

Inspected directly against the installed `@redact-secret/core@0.1.0-beta.9` (same pin as [qualification-0.1.0-alpha.1.md](qualification-0.1.0-alpha.1.md)):

- **Findings** (`DetectedSecretFinding`/`SecretFinding`, `node_modules/@redact-secret/core/dist/types.d.ts`): `id` (`"finding-1"`, ...), `type` (for example `"github_token"`), `detector`, `confidence` (`"high"|"medium"|"low"`), `obfuscation` (`"none"|"invisible-characters"`), `start`/`end`, and — after policy evaluation — `action`. Never a matched value.
- **Actions** (`SecretAction`): `"redact" | "block" | "warn" | "allow"`.
- **Ranges** (`RangeUnit`): `"utf16-code-units"` — half-open `[start, end)` pairs; `input.slice(start, end)` (JS) selects exactly the matched span. Python has no native UTF-16 indexing (`str` indexes by Unicode code point), so this package converts offsets explicitly — see §3 and `src/redact_secret_vault_server/utf16.py`.
- **Public functions**: `initialize`, `scan`, `redact`, `scanAndRedact`, `createIncrementalSanitizer`, `defaultPlaceholderFormatter`, `typedPlaceholderFormatter`, `PROFILE`, `RANGE_UNIT`, `VERSION`, `artifact()`.

A native Python distribution, if one is built later, should expose the same finding fields, the same four actions, and the same UTF-16 range convention (or document its own convention explicitly) to stay a drop-in replacement for the boundary this package uses today.

## 2. Decision: qualified service boundary, not reimplementation

`packages/vault-server-py/src/redact_secret_vault_server/core_client.py` defines `CoreClient` as a `Protocol` with one method, `scan`. `NodeCoreBridge` implements it by shelling out to `boundary/core_bridge.mjs`, a ~50-line Node.js script that imports `@redact-secret/core` and calls only its public `scan` API, returning safe finding metadata as JSON. Detection and policy evaluation happen entirely in the pinned core (Rust, via its Node addon or WASM fallback); this package never parses a secret pattern, never ships a detector table, and never sees a matched value cross the process boundary except as the exact UTF-16 span Python then slices from its own copy of the input text — the same value the caller already gave it.

This satisfies AGENTS.md/CONVENTIONS.md's "do not reimplement detectors": the boundary is thin, auditable, and calls only the documented public API, matching the one-way dependency direction (`reversible` may consume `core`'s public API; `core` never depends on `reversible`).

**Threat boundary, failure behavior, residual risk** (`NodeCoreBridge`, `packages/vault-server-py/src/redact_secret_vault_server/core_client.py`):

- **Threat boundary:** same-host, server-side only (not qualified for browser/Worker/CSP contexts — that remains V1-V4's scope). Trusts the local `node` executable and the npm-installed `@redact-secret/core` resolved from this repository's workspace (or a caller-supplied script/executable). The bridge script is invoked with the caller's own text on stdin; it never receives untrusted network input directly, and it never echoes the request text back on any code path.
- **PII:** the bridge also forwards a PII selection to `initialize({ pii })` and reports the core's activation identity; see §8.
- **Failure behavior:** a missing `node` executable raises `UNSUPPORTED_RUNTIME` at construction. A subprocess timeout, non-zero exit, malformed stdout, or a `coreVersion` mismatch against the pinned `0.1.0-beta.9` each raise `VaultServerError(CORE_FAILURE)` — fail-closed, never a partial or best-effort finding list, matching `@redact-secret/vault`'s own `CORE_FAILURE` mapping (`packages/vault/src/vault.ts:L380-L388`).
- **Residual risk:** a compromised local `node` binary or a supply-chain compromise of the installed `@redact-secret/core` package affects this boundary exactly as it already affects the JS vault; this class adds no new trust beyond what the repository already accepts for capture. The boundary itself (the `.mjs` script and the subprocess invocation) has **not** gone through its own dedicated adversarial qualification (malformed-stdin fuzzing, resource-exhaustion, or process-isolation testing) the way V1-V4 qualified the browser/Node paths for the vault; that is a candid gap, tracked below.

## 3. What this package implements

`packages/vault-server-py` (`redact-secret-vault-server` on PyPI naming, module `redact_secret_vault_server`):

- **S1 authority contract** (`types.py`, `errors.py`, `policies.py`, `server.py`): `Principal`/`PrincipalResolver`, `RestoreDecisionInput` (the decision tuple), `PolicyDecision`/`ServerReleasePolicy`, `ServerDenialReason` (the vault's eight reasons plus the S1 additions, verbatim string values), `ServerAuditEvent`/`ServerAuditHook`, and the four reference policies (`deny_by_default`, `allow_same_tenant_only`, `purpose_limited`, `all_of`) from the ADR's "Reference policy examples", ported field-for-field to Python (`dataclass`/`enum.Enum`/`typing.Protocol` in place of `interface`/string-literal unions/bare function types).
- **`InMemoryVaultServer.restore`** implements the ADR's exact nine-step preflight order (principal → marker/grammar+known-entry → source → tenant → expiry → sink/path → purpose → budget → policy), all-or-nothing across every occurrence of every path, exactly as `packages/vault/src/vault.ts:L529-L649` structures the in-memory vault's preflight (see the extensive inline citations in `server.py`).
- **Capture** (`InMemoryVaultServer.capture`) is this package's own extension — the ADR is explicitly restore-only. It mirrors `@redact-secret/vault`'s whole-input capture (same limits, same eligibility/pass-through/unredacted semantics, same `<rsv_[a-z2-7]{26}>` token grammar) but adds `issued_tenant`, which the S1 tenant check needs and the single-tenant in-memory vault does not have.
- **Storage** is a plain in-process dict — the same threat boundary as `@redact-secret/vault`: no persistence, no encryption-at-rest, no cross-process coordination. A qualified persistent store remains #19's scope.

## 4. Conformance evidence

Ran with `pytest` (Python 3.14 locally; CI's `python` job additionally covers 3.10/3.12/3.13) against the real `@redact-secret/core@0.1.0-beta.9` through `NodeCoreBridge` — **68 tests, 68 passed**:

- **40/40** cases of the shared corpus (`conformance/v1/corpus.json`, the same corpus `@redact-secret/vault` qualifies against in `packages/vault/test/suite.js`), replayed through `tests/conformance_runtime.py` — a Python port of the JS reference runner's step interpreter (templates, transforms, multi-vault, controlled clock, `releasePolicy` specs) driving `InMemoryVaultServer` instead of `InMemoryVault`.
- **1** corpus leakage check (`test_leakage_across_corpus`), mirroring the JS suite's: no fixture value or issued token appears in any error or audit event collected across the whole corpus replay (16+ errors, 16+ audit events observed).
- **17** S1-only adversarial cases (`tests/test_server_authority.py`) covering every class the ADR's "Consequences" section names for #16/#17 to implement as executable cases, since the shared corpus does not cover them yet: principal-resolution failure (resolver throws; no resolver configured), cross-tenant read (and its positive same-tenant control), missing/invalid purpose (empty string; not in a policy's allowlist), revoked-vs-unknown-token (an explicitly revoked token vs. a forged one), policy-evaluation-error (a throwing policy, a non-conforming return value, and a policy timeout), fail-closed-with-no-policy-configured, policy-revision staleness, policy composition (`all_of`, first-denial-wins), reentrancy (`BUSY`), and the audit event's structural inability to carry a restored value.
- **11** unit tests for the UTF-16 offset conversion and token/marker-grammar helpers (astral characters, ZWJ emoji sequences, invisible-format-character marker spoofing).

Reproduce:

```bash
npm ci   # installs @redact-secret/core at the repo root, for the bridge
cd packages/vault-server-py
pip install -e ".[test,lint]"
ruff check .
pytest -q
```

### What "equivalent to `@redact-secret/vault-server` (JS, #16)" means here

At the time this package was built, #16 had not yet merged to `main` (built in parallel, per the issue's instructions not to block on it). "Equivalent" is therefore checked against the **shared, written contract** both packages must satisfy — the S1 ADR and the conformance corpus's documented expected outcomes — not against #16's source. The claim is:

- The same decision tuple fields (`RestoreDecisionInput`, snake_case in Python / camelCase in TS, same semantics).
- The same nine-step preflight order.
- The same denial vocabulary (`ServerDenialReason`'s string values are identical to the ADR's TypeScript union, verbatim).
- The same audit event shape, with no field capable of carrying a restored value.
- The same fail-closed behavior for every injection point (`PrincipalResolver`, `ServerReleasePolicy`, `ServerAuditHook`).
- Given the same synthetic tenant/purpose/principal on every call, the same capture/restore/revoke/lifecycle/limit outcomes as `@redact-secret/vault` on the shared corpus's 40 V2/V3 cases.

It does **not** mean byte-identical code, an identical wire format, or that this package has been checked against #16's actual TypeScript source (that comparison is #18/S4's job, once both exist on `main`).

## 5. Candid differences from the JS implementation

| Topic | JS (`@redact-secret/vault` / the S1 ADR) | This package | Why |
| --- | --- | --- | --- |
| Core integration | Direct in-process import of `@redact-secret/core` | Out-of-process call to the same core via a Node.js subprocess (`NodeCoreBridge`) | No native Python core distribution exists (§1); calling the real core over a boundary was chosen over reimplementing detection. |
| Redaction assembly | Core's `redact()` API with a custom `placeholderFormatter` callback | `scan()` only; this package slices UTF-16 ranges and assembles the output text itself | Bridging a per-finding callback across a process boundary is unnecessary complexity; the substitution step is vault-owned logic in both languages (the JS formatter is also vault code, not core code), so this is a mechanical, not a detection, difference. |
| Throwing `ServerReleasePolicy` | N/A yet in JS (#16 not merged); ADR mandates `"policy-evaluation-error"` | `"policy-evaluation-error"`, per the ADR | Both should match once #16 lands; documented here because the *vault-level* `ReleasePolicy` (a different, older contract) instead uses `"policy"` for a throwing callback — see the corpus-adapter note in `tests/conformance_runtime.py`. |
| Revoked-token reporting | Optional per ADR §4 | Implements a short-lived revocation tombstone and reports `"revoked"` | The ADR explicitly permits either `"revoked"` (with a tombstone) or `"unknown-token"` (without one); this package chose the richer signal for incident response. `@redact-secret/vault`'s corpus cases (written before tombstones existed) expect `"unknown-token"`, so `tests/conformance_runtime.py` documents and overrides those two specific expectations rather than silently diverging. |
| Token entropy source | Manual bit-packing of `crypto.getRandomValues()` output | `secrets.choice()` per base32 character | Both are CSPRNG-backed with ≥128 bits of entropy; Python's approach is simpler and still cryptographically sound. Token *values* are never compared across languages, only the grammar. |
| Marker-obfuscation detection | `/r\p{Cf}*s\p{Cf}*v\p{Cf}*_/giu` (interspersed Unicode-format characters) | Strips every Unicode category-Cf character from the whole text, then searches for a literal `rsv_` | Python's `re` has no `\p{Cf}` escape. The Python approach is slightly more permissive about *where* invisible characters may sit between marker characters — it never under-detects a spoofed marker, only occasionally over-detects (a false positive here means "refuse to restore," never "restore something it shouldn't"). |
| Capture audit vocabulary | `AuditEvent.operation` includes `"capture"`/`"dispose"` (vault-level, not part of the S1 ADR) | `capture()`/`dispose()` never call the S1 `ServerAuditHook` | The S1 ADR's `ServerAuditOperation` is a closed set — `"resolve-principal"\|"restore"\|"revoke"\|"policy-error"` — and does not include capture or dispose. This package keeps `on_audit` strictly within that vocabulary rather than inventing a fifth value; a consumer that wants capture-level auditing must add its own hook around `capture()`. |
| Async model | Single-threaded JS event loop; `ServerReleasePolicy`/`PrincipalResolver` may return a `Promise` | `restore()` is `async def`; both sync and `async def` policies/resolvers are awaited uniformly via `inspect.isawaitable` | Idiomatic per-language concurrency model; the *contract* (fresh evaluation per call, no caching) is unchanged. `capture()` stays synchronous, since it never calls an S1 injection point. |

## 6. Gaps and limitations (explicit, not papered over)

- **No native Python core.** Capture depends on a working `node` executable and an installed `@redact-secret/core`; a Python-only deployment with no Node.js available cannot capture (it can still authorize restores against entries created elsewhere, since `InMemoryVaultServer` accepts pre-existing entries only through `capture()` — there is currently no way to seed entries without going through the bridge). This is the primary limitation this issue was asked to surface rather than paper over.
- **The bridge boundary itself is unqualified.** `NodeCoreBridge`/`core_bridge.mjs` has not been through its own adversarial qualification pass (malformed-stdin fuzzing, subprocess resource exhaustion, concurrent-invocation stress). It is exercised indirectly by this package's test suite (68 tests, real subprocess calls) but that is not the same as a dedicated qualification record like [qualification-0.1.0-alpha.1.md](qualification-0.1.0-alpha.1.md).
- **No Worker/browser/CSP story.** This package is server-only Python; it says nothing about browser or Worker use, which remain V1/V4's scope in any language.
- **No persistent store.** In-memory only, matching `@redact-secret/vault`'s own threat boundary; #19 remains open.
- **Concurrency.** `InMemoryVaultServer` guards against re-entrant calls on the *same instance* (a `BUSY` error, mirroring the vault) but assumes single-threaded/single-event-loop use per instance; a multi-threaded Python server sharing one instance across threads needs its own synchronization, which this package does not add. Multi-process policy-revision consistency is explicitly out of scope per the ADR.
- **Not compared against #16's actual code**, only against the shared written contract — see §4.

## 7. Core compatibility statement

Pinned to `@redact-secret/core@0.1.0-beta.9`, identical to the pin in [qualification-0.1.0-alpha.1.md](qualification-0.1.0-alpha.1.md) and this repository's root `package.json`. `NodeCoreBridge` checks the resolved core's reported `VERSION` against this pin on every call and fails closed (`CORE_FAILURE`/`CORE_VERSION_MISMATCH`) if they differ, so a silent core upgrade cannot silently change this package's behavior. This package adds no new core dependency beyond the one `@redact-secret/vault` already declares; the one-way dependency direction is unchanged (this repository consumes the core's public API; the core never depends on this repository).

## 8. PII selection, activation identity, and retention (#40)

**Status:** implemented and tested, unreleased, 2026-09-28. Implements §1 and §3 "Python bridge" of the [PII retention and activation decision record](../decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md) for [#40](https://github.com/redact-secret/redact-secret-vault/issues/40), with the same rules `@redact-secret/vault` implements for #38 (`packages/vault/src/pii.ts`, ported as `src/redact_secret_vault_server/pii.py`). The pin stays `0.1.0-beta.9`. PII-on behavior was checked against a local build of the `0.1.0-beta.10` candidate, which is not on npm.

The issue text asked the bridge to report `"off"` on beta.9. The accepted decision record supersedes that: the bridge reports `piiActivation: null` and does not invent an identity string.

**Bridge protocol.** The request gains `"pii": string[]` (required, 0 to 64 strings of 1 to 128 characters; a malformed list is refused with a code-free error that does not echo the request). The success response gains `"piiActivation": string | null`. The script imports the core as a namespace and detects PII support by the presence of a `piiActivation` function, never by version:

| Core | `pii` | Bridge does | Response |
| --- | --- | --- | --- |
| Has `piiActivation` | any, including `[]` | `initialize({ pii })` | `piiActivation()` identity |
| No PII surface (beta.9) | `[]` | plain `initialize()`, as before | `null` |
| No PII surface (beta.9) | non-empty | nothing; no initialize, no scan | `{"error":{"code":"PII_UNAVAILABLE"}}` |

The script also projects each finding to exactly the eight safe fields before writing it, instead of serializing the core's objects as-is.

**`NodeCoreBridge`.** `pii: Sequence[str] = ()` and `expected_pii_activation: str | None = None` are shape-checked at construction (`INVALID_ARGUMENT`; a bare `str` is refused rather than iterated). Response parsing is now strict: the success object must have exactly `findings`, `coreVersion`, `artifact`, and `piiActivation`, each finding exactly the eight safe fields with `str`/`int` types, and an `error` object an optional string `code`. Anything else is `CORE_FAILURE`/`BRIDGE_BAD_OUTPUT`, so an older bridge script without `piiActivation` also fails closed. With `expected_pii_activation` set, every response must report exactly that identity (`PII_UNAVAILABLE` when the core reports `null`, `PII_ACTIVATION_MISMATCH` when it differs). Otherwise the identity of the first fully valid response is pinned, including `null`, and every later response must match. Core rejections (`PII_SELECTOR_*`, `NOT_INITIALIZED`) stay `CORE_FAILURE` with `core_code`, as the JS server's `coreCode` does.

**Retention.** `CaptureOptions.pii: PiiRetention | None` with `retain: tuple[str, ...]` follows §1 exactly: 1 to 64 exact `pii_` types (`pii_[a-z0-9_-]{1,124}`, full match), duplicates ignored, unknown well-formed types accepted; a PII `redact` finding outside the list is not retained and `eligible` is not called for it; `eligible` can only narrow the list. A malformed `pii` raises `INVALID_ARGUMENT` before the core runs, and therefore before any `PII_UNAVAILABLE`.

**One ordering difference from the JS vault.** The JS vault observes the activation once at `createVault` and refuses a capture's `pii` with `PII_UNAVAILABLE` before scanning. The Python server has no such moment: every scan is a new realm, and the identity arrives with that scan's result. So `InMemoryVaultServer` checks `CoreScanOutcome.pii_activation` immediately after the scan, before any finding is gated or staged. The consequence is that input-size and token-literal checks, and core failures, are reported before `PII_UNAVAILABLE`. Nothing is retained or returned either way. A custom `CoreClient` that never sets `pii_activation` can never have PII retained.

**Evidence** (Python 3.14 locally, `ruff check .` clean):

- Against the pinned beta.9: **155 passed, 4 skipped** (`pytest -q`). The 68 pre-existing tests, including 40/40 corpus cases, pass unchanged. `tests/test_pii_retention.py` covers retention with a fake core; `tests/test_pii_bridge.py` covers the bridge with a faked subprocess (propagation, pinning, expected identity, 20 malformed responses), the real `core_bridge.mjs` against fake core modules with and without `piiActivation`, and the real beta.9 core (`null` identity, `PII_UNAVAILABLE` for a selection, an expected identity, and capture retention). The 4 skips are the PII-capable-core cases, with the reason printed.
- Against the local beta.10 candidate (`VAULT_SERVER_PY_PII_CORE_NODE_MODULES` pointing at a scratch install of the packed build): `tests/test_pii_bridge.py` **64 passed, 0 skipped**. Selection `["pii"]` reports `selectors=pii:global` and is pinned, a wrong expected identity raises `PII_ACTIVATION_MISMATCH`, `[]` reports `selectors=off` and refuses capture retention, an invalid selector surfaces `PII_SELECTOR_INVALID`, an allow-all `eligible` still leaves the documentation-example IBAN unretained, and an allowlisted `pii_global_iban` is retained and restored.
