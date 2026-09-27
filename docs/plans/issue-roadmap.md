# Issue roadmap for reversible restoration

**Status:** proposed issue plan, 2026-09-27. This document does not claim packages or runtimes are implemented.
**Release cadence:** independent of the core's beta milestones. A core release is a tested compatibility input, not this repository's release clock.

The repository currently has no issues. The plan groups work by a security exit gate rather than by language alone. Epics can become GitHub parent issues, with the numbered tasks below as linked child issues. Titles are ready to use as English issue titles. Avoid assigning dates or versions until gates are met.

## Phase 0 — security contract and evidence

**Epic title:** Establish the reversible security contract before public APIs

| ID | Proposed child issue title | Reviewable result and acceptance | Depends on |
| --- | --- | --- | --- |
| F1 | Define threat models for browser memory, Worker, server memory, and persistent mappings | Assets, attacker capabilities, data flows, trust boundary, residual risk, and alternative per mode. Explicitly distinguish same-page code from server principal/tenant authority. | None |
| F2 | Resolve issued-token identity, literal collisions, and approved output provenance | Decide token grammar/entropy, repeated-value rule, exact source and path binding, literal collision handling, copied/reordered token behavior. Update the [proposed ADR](../decisions/2026-09-27-bind-issued-tokens-to-approved-output.md) and negative corpus. | F1 |
| F3 | Qualify core action and range integration in a real browser | Pin a core release; run its **public API** with browser WASM under strict CSP. Test `block`, `redact`, `warn`, `allow`, Unicode, formatter failure, finding reuse, and no partial mapping. Reconcile [Node/WASM proof](../research/verification-2026-09-27.md) and [action ADR](../decisions/2026-09-27-gate-capture-on-core-actions.md). | F1 |
| F4 | Specify restore authorization, revocation races, and transaction semantics | Define the server decision tuple, browser-local policy limits, multi-token all-or-nothing boundary, use-budget consumption, commit/revoke ordering, and lost-response behavior. Update the [transaction ADR](../decisions/2026-09-27-define-restore-transaction-boundary.md). | F1, F2 |
| F5 | Build a language-neutral adversarial conformance corpus | Synthetic cases and expected outcomes for forged/copied tokens, paths, tenants, action gates, races, TTL, failures, logging leakage, and payload size. Version the corpus separately from detection benchmarks. | F2–F4 |

**Gate F:** proposed ADRs become accepted only after their alternatives, tests, and limits are reviewable. No API can claim browser/server/persistent security based on a design document alone.

## Phase 1 — portable in-memory vault

**Epic title:** Deliver `@redact-secret/vault` for qualified in-memory runtimes

| ID | Proposed child issue title | Reviewable result and acceptance | Depends on |
| --- | --- | --- | --- |
| V1 | Scaffold the portable vault package and enforce repository boundaries | Public-core dependency only, browser-safe bundle, no server/store SDK pulled into browser, explicit compatibility matrix, import without capture side effects. | Gate F |
| V2 | Implement bounded whole-input capture and issued-token lifecycle | Explicit opt-in, action gate, UTF-16 span capture, cryptographic identity, collision handling, TTL/byte/entry limits, staged commit, dispose and sanitized errors. Conformance tests pass on Node and browser. | V1, F3, F5 |
| V3 | Implement structured-field restoration and browser-local release policy | Exact issued lookup, app-selected sink/path, all-token preflight, budgets, revocation, no bulk export, redacted/abort outcome on denial. Do not claim multi-principal auth. | V2, F4 |
| V4 | Qualify optional dedicated-Worker mode and its failure behavior | Worker-owned mapping, validated message protocol, browser/CSP/WASM test matrix, hostile-main-thread demonstration, explicit error rather than silent fallback. Main-thread and Worker guarantees documented separately. | V2, V3 |

**Gate V:** a browser or Node runtime is marked supported only when its own conformance runner and end-to-end packaging pass. Worker is an optional separately qualified mode, not an implicit upgrade.

## Phase 2 — server authority and language parity

**Epic title:** Deliver server restoration under a language-neutral authority contract

| ID | Proposed child issue title | Reviewable result and acceptance | Depends on |
| --- | --- | --- | --- |
| S1 | Define the server authority interface and reference policy examples | Trusted principal/tenant resolution, source→sink/path/purpose checks, current policy evaluation, denial vocabulary, audit event shape, and consumer injection points without a mandated identity provider. | F4, F5 |
| S2 | Implement `@redact-secret/vault-server` with in-memory storage | JS server authority enforces S1 on every restore, coordinates concurrent restore/revoke, and passes the shared corpus and cross-tenant tests. Server memory is a valid backend. | S1, V2 |
| S3 | Qualify a native Python server integration against the same contract | Inventory Python core public findings/actions/ranges; choose a native package or qualified service boundary; pass equivalent conformance and failure tests. Do not reimplement detectors. | S1, F5 |
| S4 | Document and test JS/Python conformance and supported core ranges | Exact runtime/version matrix, equivalent outcomes for synthetic fixtures, package examples, and candid differences. Rust/Go targets remain separately planned after their core integration exists. | S2, S3 |

**Gate S:** server authorization claims require a trusted application identity context and negative cross-tenant evidence. Browser policy callbacks cannot satisfy this gate.

## Phase 3 — optional persistence

**Epic title:** Qualify consumer stores and optional `@redact-secret/store-*` backends

| ID | Proposed child issue title | Reviewable result and acceptance | Depends on |
| --- | --- | --- | --- |
| P1 | Specify the persistent store, encryption, and key ownership contract | Atomic eligibility/consume/revoke behavior, logical TTL, tenant isolation, AEAD metadata binding, key injection/rotation, backup and deletion, error handling. Allow consumer-owned KMS/store; do not impose a vendor. | F4, S1 |
| P2 | Qualify one concrete persistent store through adversarial tests | Select backend after P1; test crashes, retries, replica lag, races, encrypted record substitution, tenant isolation, expiry and revocation. Publish the backend-specific guarantees and limitations. | P1, F5, S2 |

**Gate P:** `store-*` is optional. Persistence cannot weaken server authority and cannot claim that encryption provides same-page XSS resistance.

## Cross-cutting release work

**Epic title:** Verify consumer safety and publish precise support claims

| ID | Proposed child issue title | Reviewable result and acceptance | Depends on |
| --- | --- | --- | --- |
| R1 | Audit public APIs and examples for accidental plaintext disclosure | No plaintext/mappings in logs, traces, errors, audit events, snapshots, or docs; examples show explicit denial/cleanup and explain residual risks. Independent security review of misuse paths. | V3, S2 |
| R2 | Establish independent releases, provenance, and security reporting | Versioned compatibility matrix, pinned core test artifacts, package provenance, vulnerability reporting channel, and no claims for unqualified runtimes. | V3; S/P claims only after their gates |

## Critical path and scope discipline

`F1 → F2/F3/F4 → F5 → V1/V2/V3 → Gate V` is the shortest path to a useful first browser/Node in-memory release. S1/S2 can use the same in-memory vault; Python S3 follows its own qualification. Persistence P1/P2 is a separate opt-in track after server authority. Worker V4 may follow the basic vault release if its packaging/CSP evidence takes longer.

Start with whole-input text and structured-field restoration. Streaming, arbitrary-text global restore, Service Worker storage, CLI restoration, and Rust/Go server distributions need separate threat models and issues when evidence supports them. The core, adapters, and detection benchmarks must not acquire a dependency on this repository.

## Issue template for each child

Every implementation issue should contain: threat/asset addressed; exact public contract and failure behavior; dependencies; negative tests; supported runtime; doc changes; residual risk; and acceptance evidence. Research issues should deliver a decision or measured finding, not just “investigate.”
