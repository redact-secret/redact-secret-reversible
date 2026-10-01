# Server epic reconciliation: #3 and issues #15 to #18

**Date:** 2026-10-01. **Scope:** a comparison of each acceptance item in epic [#3](https://github.com/redact-secret/redact-secret-vault/issues/3) and its children [#15](https://github.com/redact-secret/redact-secret-vault/issues/15), [#16](https://github.com/redact-secret/redact-secret-vault/issues/16), [#17](https://github.com/redact-secret/redact-secret-vault/issues/17), and [#18](https://github.com/redact-secret/redact-secret-vault/issues/18) with the code, tests, corpora, and documents on `main` (commit `007c50f`). Nothing here changes code, and no issue is closed by it.

**Method and limits.** Evidence was found by reading the issue text, the decision records, and the sources, and by listing test names with their line numbers. The test suites were **not executed** for this record (the worktree has no installed dependencies). A cited test shows that a check exists, not that it passed today. The latest `ci` run on `main` (run 36928007063, 2026-10-01) concluded `success`; that is the only pass evidence relied on. File and line numbers are as of `007c50f` and move as files change. Every value in the cited tests is synthetic.

## Verdicts

| Issue | State | Verdict |
| --- | --- | --- |
| [#15](https://github.com/redact-secret/redact-secret-vault/issues/15) S1 interface | Closed | Complete. Three stale statements in the record itself (below), none a missing deliverable |
| [#16](https://github.com/redact-secret/redact-secret-vault/issues/16) S2 in-memory server | Closed | Complete except one acceptance phrase: "passes the shared corpus". The server's own preflight layer is not run against `conformance/v1/corpus.json`; the corpus is run against the wrapped `Vault` and, separately, against the Python server |
| [#17](https://github.com/redact-secret/redact-secret-vault/issues/17) S3 Python | Closed | Complete for what it asked (inventory, boundary decision, corpus, failure tests), at research grade. Its evidence record is archived and stale in its numbers, and Python tests contain no preflight-order cases |
| [#18](https://github.com/redact-secret/redact-secret-vault/issues/18) S4 conformance and ranges | Open | **Not complete.** Examples and the "Rust/Go planned separately" statement exist. The exact runtime/version matrix, the cross-language equivalence evidence, and the candid differences are partial, scattered, or stale |
| [#3](https://github.com/redact-secret/redact-secret-vault/issues/3) epic | Open | Gate not yet met: its second clause, "cross-language outcomes are verified", is the open part of #18 |

## #15: Define the server authority interface and reference policy examples

Source of truth: [define-server-authority-interface.md](../decisions/define-server-authority-interface.md) (accepted 2026-09-27), implemented in `packages/vault-server/src/types.ts`.

| Acceptance item | Evidence | Gap |
| --- | --- | --- |
| Trusted principal/tenant resolution | ADR §1; `Principal` and `PrincipalResolver` at `packages/vault-server/src/types.ts:14-40`; resolver step at `packages/vault-server/src/server-vault.ts:461` (`unauthenticated`); `order-and-denials.test.mjs:20,33,42`; `policy.test.mjs:78` (resolver timeout); Python `tests/test_server_authority.py:83,111` | None |
| Source to sink/path/purpose checks | ADR §2; `RestoreDecisionInput` at `types.ts:43-76`; checks at `server-vault.ts:493-514`; `order-and-denials.test.mjs:93,142,155` | None |
| Current policy evaluation | ADR §3 (fresh per request, fail-closed, all-or-nothing); `server-vault.ts:543-546`; `policy.test.mjs:37,50,59,68,127` | None |
| Denial vocabulary | ADR §4; `ServerDenialReason` at `types.ts:93-106`; set at `server-vault.ts:30-44`; `order-and-denials.test.mjs:54-81` | None. `stale-policy` and `rate-limited` are accepted from a policy and never produced by the in-memory server itself (stated in `types.ts:229-233`); see #16 |
| Audit event shape | ADR §5; `ServerAuditEvent` at `types.ts:118-139`; `cross-tenant-and-leak.test.mjs:53` (no value, no token in errors, audit events, or console) | None for the in-memory server. The persistent profile adds operations and reasons beyond the ADR (`types.ts:108-116`); they are specified in [persistent-vault.md](../specs/persistent-vault.md) §8.3, not in the ADR |
| Consumer injection points, no mandated identity provider | ADR §6; `ServerVaultOptions` at `types.ts:214-257` (`resolvePrincipal`, `policy`, `onAudit` all injected); `basic-api.test.mjs:7` | None |
| Reference policy examples | ADR "Reference policy examples" and its 2026-10-01 addendum ([#134](https://github.com/redact-secret/redact-secret-vault/issues/134)); `packages/vault-server/src/policies.ts:21-77`; `policies.test.mjs:35-101`; Python `policies.py` | None |
| Checklist: synthetic data; threat boundary, failure behavior, residual risk | ADR "Threat boundary, failure behavior, and residual risk"; `*-synthetic*` literals in the ADR | None |
| Checklist: adversarial/negative evidence | The ADR's "Negative and adversarial examples" are executable in `packages/vault-server/test/order-and-denials.test.mjs` and `cross-tenant-and-leak.test.mjs:18` | None |
| Checklist: update specs/ADRs and exact core compatibility statement | ADR "Core compatibility"; [threat-model.md](../specs/threat-model.md) server section | **Stale text.** The ADR says it pins `0.1.0-beta.9` and its callout says "No implementation exists yet". The current pin is `0.1.0-beta.12` ([status.md](../status.md), [vault-server reference](../reference/vault-server.md)). The ADR is dated and the current statement is elsewhere, but the ADR is not annotated |
| Checklist: one-way dependency | `npm run check:boundaries` (`qualification/check-boundaries.mjs`) | None |

**Verdict: complete.** Optional follow-up: add a dated note to the ADR's callout and compatibility section, as other records do.

## #16: Implement `@redact-secret/vault-server` with in-memory storage

Source: `packages/vault-server/src/server-vault.ts`; record: [implement-vault-server-in-memory.md](../decisions/implement-vault-server-in-memory.md).

| Acceptance item | Evidence | Gap |
| --- | --- | --- |
| Enforces S1 on every restore | `#restore` at `server-vault.ts:374-600`: order is request shape (431-438), principal (461), marker (478), known entry, source (493), tenant (497), expiry (501), sink/path (507), purpose (511), budget (514), policy (543-546). `order-and-denials.test.mjs:199,214` pin the order; `:223` all-or-nothing | None |
| Coordinates concurrent restore and revoke | FIFO queue (`#run`, `server-vault.ts:317-327`; ADR "Linearization"); `concurrency.test.mjs:13,36,76,94,118` | Single process only, by design (ADR "Residual risk") |
| Passes the shared corpus | `conformance/v1/corpus.json` is run by `packages/vault/test/suite.js` through `qualification/node.mjs`, `browser.mjs`, `worker.mjs`, which exercise `@redact-secret/vault`, the layer `vault-server` wraps | **Gap.** No test under `packages/vault-server/test/` reads the corpus (`grep` finds it only in `qualification/` and the Python tests). The server's own preflight is covered by its own tests, not by the shared cases. [conformance/README.md](../../conformance/README.md) says server-only classes are "left to a future corpus version" |
| Cross-tenant tests | `cross-tenant-and-leak.test.mjs:18` (N tenants, every cross-tenant restore denied); `order-and-denials.test.mjs:103,115` | None |
| "Server memory is a valid backend" | Package is in-memory by design; [status.md](../status.md) lists Node.js 20/22/24 | None |
| Server-only classes named in S1 (principal failure, cross-tenant, purpose, revoked vs unknown, policy error/timeout, revision staleness) | First five: tests cited above and `policy.test.mjs`. Staleness: `policy.test.mjs:155` shows the revision is stamped per capture and echoed to the policy | **Partial.** The in-memory server never compares revisions; a `stale-policy` denial is exercised only for a policy that returns it (`policy.test.mjs:19`) and, in the persistent profile, by `test/persistent/restore-authorization.test.mjs:237,339`. This follows the ADR ("`stale-policy` remains the policy's own responsibility"), but the README's claim that both servers cover all six classes is true only in that sense |
| Checklist: failure behavior, residual risk | ADR "Threat boundary, failure behavior, and residual risk"; [threat-model.md](../specs/threat-model.md) lines 68-72 | None |
| Checklist: exact core compatibility statement | `packages/vault-server/package.json:33` peer `0.1.0-beta.12`; [vault-server reference](../reference/vault-server.md) line 100 | The ADR's own "Core compatibility" still reads `0.1.0-beta.9` / `alpha.1` (dated) |

**Verdict: complete, with one wording gap.** The acceptance sentence "passes the shared corpus" is satisfied transitively (the wrapped vault passes it; the Python server passes it) and not directly. Either run a server-API adapter over the corpus in `packages/vault-server/test/`, or reword the claim to what exists. That choice belongs to #18.

## #17: Qualify a native Python server integration against the same contract

Source: `packages/vault-py/src/redact_secret_vault/`; evidence record: the archived [Python server integration record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/python-server-integration-2026-09-27.md) (2026-09-27), with the PII addendum in its §8.

| Acceptance item | Evidence | Gap |
| --- | --- | --- |
| Inventory Python core public findings, actions, ranges | Archived record §1: no Python core exists; findings fields, four actions, UTF-16 half-open ranges, public functions, checked against core `0.1.0-beta.9` | The inventory was taken at beta.9. It was not repeated for beta.12 in this repository's documents. Bridge pin: `PINNED_CORE_VERSION = "0.1.0-beta.12"` (`core_client.py:42`) |
| Choose a native package or a qualified service boundary | Archived record §2: service boundary (`NodeCoreBridge`, `core_client.py:342`; `boundary/core_bridge.mjs`); [threat-model.md](../specs/threat-model.md) lines 73-88 (data flow, trust boundary, timeout, crash, fork) | The bridge is "research-grade, not qualified" by its own heading in the threat model |
| Equivalent conformance tests | `tests/test_conformance.py:45` replays the shared corpus; `tests/conformance_runtime.py` is the interpreter; `test_conformance.py:54-65` asserts at least 50 cases and names the only two skips; two PII lanes (`tests/test_conformance.py:67`) | Three expectations are overridden by design (`conformance_runtime.py:92-96`: `policy.throwing-callback-denies`, `lifecycle.revoke-before-restore`, `lifecycle.restore-before-revoke`); two shared-realm cases are skipped |
| Equivalent failure tests | `tests/test_server_authority.py:83-518` (resolver failure, cross-tenant, purpose, revoked vs unknown, throwing, malformed, and slow policy, no policy, staleness, `all_of`, audit shape, re-entrancy); `tests/test_bridge_process.py` (reuse, timeout, crash, malformed and oversized output, threads, fork); `test_pii_bridge.py`, `test_pii_retention.py`, `test_core_location.py`, `test_utf16.py`, `test_doctor.py` | **No preflight-order test.** The JS suite pins the order with `order-and-denials.test.mjs:199,214`; no Python test asserts, for example, that `tenant-mismatch` outranks `expired`. The archived record claims "the same nine-step preflight order" (steps are commented at `server.py:582-639`) without an order test |
| Do not reimplement detectors | The bridge calls only `initialize`, `scan`, and `piiActivation` (`boundary/core_bridge.mjs` header, lines 11-14); Python slices ranges itself | None |
| Checklist: threat boundary, failure behavior, residual risk | Archived record §2 and §6; threat-model lines 73-88 | The archived §6 says the bridge had no adversarial qualification; `test_bridge_process.py` now covers much of that list, but no document says the gap is closed |
| Checklist: exact core compatibility statement | `docs/reference/vault-py.md:129`; `packages/vault-py/README.md` ("Requirements") | The archived record's §7 and its counts (68 tests, 40 corpus cases, beta.9) are stale: the corpus has 52 cases at version 1.3.0 and the pin is beta.12 |
| Checklist: native Python is not claimed | [status.md](../status.md): "research-grade", "No persistence" | None |

**Verdict: complete as a research-grade integration.** Gaps to carry into #18: the missing order tests, a refreshed evidence record, and the stale numbers in the archived record.

## #18: Document and test JS/Python conformance and supported core ranges

Dependencies #16 and #17 are done, so this issue is unblocked.

| Acceptance item | Evidence on `main` | Gap |
| --- | --- | --- |
| **Exact runtime/version matrix** | CI matrices in `.github/workflows/ci.yml`: `vault-server` Node 20/22/24 on ubuntu and macOS (lines 36-50); `node` Node 20/22/24 on both (58-66); persistence Node 20/22/24 (89-97); Python 3.10, 3.12, 3.13 on ubuntu with Node 22 only (209-240). [status.md](../status.md) package table gives runtimes per package. [ARCHITECTURE.md](../../ARCHITECTURE.md) line 118: "Each language distribution declares and tests its supported core range and runtime matrix" | **Gap.** No single matrix. The Python row in status.md says "Python 3.10+ ... `node` executable available", not what CI ran. Untested: Python 3.11 and 3.14 (3.14 was a local run only), Python on macOS or Windows, the Python bridge with Node 20 or 24, and the bridge on any Node other than 22. Core range: both distributions pin `0.1.0-beta.12` exactly (`packages/vault-server/package.json:33`, `core_client.py:42`); there is no range, so "supported ranges" is one version per release, and the history (beta.9 to beta.12, with `conformance/README.md` noting corpus 1.3.0 passes on beta.11) is spread over README, status.md, and per-package references. The conventions require tests at both ends of any claimed range; none is claimed |
| **Equivalent outcomes for synthetic fixtures** | One corpus, `conformance/v1/corpus.json` 1.3.0, 52 cases, 10 fixtures. JS: `packages/vault/test/suite.js` through `qualification/node.mjs`, `browser.mjs`, `worker.mjs`. Python: `tests/test_conformance.py` against `InMemoryVaultServer`, PII off and on | **Partial.** (1) The JS server API is not run against the corpus (see #16), so there is no JS-server and Python-server pair on the same cases; the JS side is the wrapped `Vault`. (2) The server-only classes are not in the corpus; each language has its own tests, so equivalence on those is by parallel authoring, not by one shared case list ([conformance/README.md](../../conformance/README.md), last section). (3) Three expectations are overridden and two cases skipped in Python (see #17). (4) No artifact compares outcomes across languages; a pass in each is the only signal. (5) Persistence has shared bytes (`conformance/persistent/v1/vectors.json`, cross-checked by `verify_vectors.py`) but its schedules run only in JavaScript, and Python persistence is a plan ([python-persistence-parity.md](../plans/python-persistence-parity.md), [#115](https://github.com/redact-secret/redact-secret-vault/issues/115)) |
| **Package examples** | `examples/04-server-two-tenants.mjs` and `examples/05-python-server.py`; `npm run examples` and the CI step `python examples/05-python-server.py` (`ci.yml:240`); `packages/vault-server/README.md`, `packages/vault-py/README.md` | None for the in-memory servers. `examples/persistent/` is JavaScript only |
| **Candid differences** | [vault-py.md](../reference/vault-py.md) lines 208-216 summarize "token entropy source, marker-detection regex, capture's audit vocabulary, and the core-integration boundary" and link the archived record's §5 table | **Gap.** The full table lives only in the archived record, written before #16 merged and "not compared against #16's actual code" (its §4, §6). It lists eight differences and was never reconciled. Differences found now that no current document states: see the next table |
| **Rust/Go remain separately planned** | [ROADMAP.md](../../ROADMAP.md) "Not planned"; status.md "Proposed delivery"; [name-vault-packages-and-language-contract.md](../decisions/name-vault-packages-and-language-contract.md); ARCHITECTURE.md | None |
| Checklist: threat boundary, failure behavior, residual risk | threat-model sections for the server and the bridge (lines 68-88) | The cross-language statement itself (what equivalence does and does not mean) has no home |
| Checklist: exact core compatibility statement | status.md; vault-server and vault-py references | See the matrix gap |
| Checklist: one-way dependency | `npm run check:boundaries` | None |

### Differences between the JavaScript and Python servers not yet documented

These were found by comparing `packages/vault-server/src/server-vault.ts` with `packages/vault-py/src/redact_secret_vault/server.py` and their tests. Each needs a maintainer to confirm it is intended before it is documented as a difference, or fixed as a defect.

| # | Topic | JavaScript | Python | Where |
| --- | --- | --- | --- | --- |
| 1 | Source of `policyRevision` | Stamped at capture from the server option and echoed on every decision tuple; the caller cannot supply it | A field of `RestoreRequest`, supplied by the caller on each restore, and passed to the policy | JS `server-vault.ts:355`, `policy.test.mjs:155`; Python `types.py:232`, `server.py:661` |
| 2 | No policy configured | A construction error: `createServerVault` requires `policy` | Constructible; every restore then denies `policy` | `basic-api.test.mjs:7`; `server.py:664`, `test_server_authority.py:391` |
| 3 | Concurrent calls on one instance | Queued first in, first out, with per-callback timeouts | Re-entrancy is refused with `BUSY`; an instance is not thread-safe | ADR "Linearization"; `concurrency.test.mjs:36`; `test_server_authority.py:518` |
| 4 | Persistent profile | `@redact-secret/vault-server/persistent` (alpha, unpublished) | None | [status.md](../status.md); [#115](https://github.com/redact-secret/redact-secret-vault/issues/115) |
| 5 | Order of PII unavailability | Activation observed at `createVault`, before any scan | Checked after the first scan of each call; size and token-literal checks and core failures come first | Archived record §8 |
| 6 | Core realm | One process-wide realm | One realm per `NodeCoreBridge` process, so the shared-realm PII cases are skipped | `conformance/README.md` (`requiresSharedRealm`) |
| 7 | Revoked-token reporting in the shared corpus | Vault level: `unknown-token`; server: `revoked` | Server level only, so two corpus expectations are overridden | `conformance_runtime.py:92-96` |
| 8 | Preflight-order evidence | Two dedicated tests | None | see #17 |

Items 1 to 6 are not stated in a current document. Item 7 is explained in the archived record's §5 and in a comment in `conformance_runtime.py`; item 8 is new. The archived record's own table (core integration, redaction assembly, throwing policy, revoked reporting, token entropy, marker detection, capture audit vocabulary, async model) is still the only statement of those eight.

### What would make #18 complete

Listed as gaps, not as a plan: (a) one matrix document, with each tested cell tied to a CI job, and an explicit statement that the supported core range is the exact pin; (b) a server-API corpus runner for `@redact-secret/vault-server`, or a rewording of the #16 claim; (c) a Python preflight-order test, and either a shared server-case corpus version or an accepted statement that equivalence on the server-only classes is by parallel tests; (d) a differences table brought up to date against #16's code, including the rows above; (e) a note in the S1 and S2 records and the archived Python record that their pins and counts are historical.

Refs #18
