# Redact Secret Vault

Optional, policy-gated restoration of values redacted by [Redact Secret](https://github.com/redact-secret/redact-secret). This repository was formerly `redact-secret/redact-secret-reversible`.

**Status: alpha.** [`@redact-secret/vault`](packages/vault/README.md) provides opt-in, bounded, in-memory whole-input capture and structured-field restoration for Node.js and browser main-thread runtimes, with an optional, separately qualified dedicated-Worker mode ([worker qualification record](docs/research/qualification-worker-mode.md), [#14](https://github.com/redact-secret/redact-secret-vault/issues/14)); Worker mode is not an implicit upgrade over main-thread use, and the two modes' guarantees are documented separately. [`@redact-secret/vault-server`](packages/vault-server/README.md) adds server authority — principal, tenant, source, sink/path, and purpose authorization on every restore, with an in-memory backend built on `@redact-secret/vault`. [`redact-secret-vault` (Python)](packages/vault-py/README.md) is a research-grade, in-memory implementation of the same [server authority interface](docs/decisions/2026-09-27-define-server-authority-interface.md) (S1) as `@redact-secret/vault-server` — not of the `@redact-secret/vault` API, passing the shared conformance corpus against the real core through a documented Node.js service boundary — see [its inventory and equivalence evidence](docs/research/python-server-integration-2026-09-27.md). Persistent stores and streaming remain design work; nothing here claims them.

| Release | Core | State |
| --- | --- | --- |
| `@redact-secret/vault@0.1.0-alpha.1` | `@redact-secret/core@0.1.0-beta.9` exactly | Published 2026-09-27, manually, without provenance. No PII support. [Qualification record](docs/research/qualification-0.1.0-alpha.1.md) |
| `@redact-secret/vault@0.1.0-alpha.2`, `@redact-secret/vault-server@0.1.0-alpha.2` | `@redact-secret/core@0.1.0-beta.10` exactly | Published 2026-09-28 (npm `alpha` tag; [GitHub pre-release](https://github.com/redact-secret/redact-secret-vault/releases/tag/v0.1.0-alpha.2)). `@redact-secret/vault` was published by the release workflow with npm provenance; `@redact-secret/vault-server` (its first publish) was published manually, without provenance. Adds opt-in PII activation and retention ([decision record](docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md)), Worker protocol v2, and a breaking initialization change; see the [changelog](CHANGELOG.md). Qualified with PII off and on in Node.js, three browser engines on the main thread and in a dedicated Worker, and the Python bridge ([beta.10 qualification record](docs/research/qualification-core-0.1.0-beta.10.md)) |
| `redact-secret-vault` (Python) `0.1.0a2` | `@redact-secret/core@0.1.0-beta.10` through the bridge | Not published to any index; install from this repository |

Install exact versions rather than a dist-tag. `@alpha` resolves to `0.1.0-alpha.2` for both packages, but npm's `latest` tag is a prerelease on both: `0.1.0-alpha.1` for `@redact-secret/vault` (which peers core beta.9 and conflicts with core beta.10) and `0.1.0-alpha.2` for `@redact-secret/vault-server` (see [RELEASING.md](RELEASING.md#the-latest-dist-tag)).

The core detects and redacts without storing matched plaintext. This repository will opt in to temporarily retaining an original-value mapping so an application can restore an approved value for an approved purpose. Installing or using the core alone must never create a recoverable mapping.

## Repository boundaries

| Repository | Owns | Must not own |
| --- | --- | --- |
| [redact-secret](https://github.com/redact-secret/redact-secret) | Detection, overlap resolution, policy, redaction, safe finding metadata, and placeholder formatting | Restoration storage, restore authorization, or a dependency on this repository |
| **redact-secret-vault** | Opt-in mapping lifecycle, opaque identifiers, restoration checks, and storage/authorization extension points | Detection rules, PII classification, or changes to core policy |
| [redact-secret-adapters](https://github.com/redact-secret/redact-secret-adapters) | Host integrations for logs, traces, AI context, and MCP | Restoration or emitting mapped plaintext to observability |
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Detection and support evidence | Treating restoration success as detection accuracy |

Dependency direction is one way: this repository may consume the core's documented public API; the core and adapters must not depend on this repository. A separate release cadence and an explicitly tested core compatibility range will apply when a package exists. See [Architecture](ARCHITECTURE.md) and [boundary decision](docs/decisions/2026-09-27-separate-reversible-boundary.md).

## Packages and distribution

The agreed JavaScript package names describe two different responsibilities:

| Package | Responsibility | Version on `main` | Runtimes |
| --- | --- | --- | --- |
| `@redact-secret/vault` | Portable, opt-in in-memory mapping and token lifecycle (**alpha**) | `0.1.0-alpha.2` (published) | Qualified: Node.js 20/22/24 and browser main thread; optional dedicated-Worker mode qualified separately (opt-in, not an implicit upgrade). Not yet: edge, SharedWorker, Service Worker, Node.js `worker_threads` |
| `@redact-secret/vault-server` | Server-side authorization of restoration across principals, tenants, sources, destinations, and value paths (**alpha**, in-memory backend) | `0.1.0-alpha.2` (published; first release) | Tested: Node.js 20/22/24. Not yet: persistent backends |
| `@redact-secret/store-*` | Optional persistent backend implementations (**proposed**; [contract](docs/decisions/2026-09-27-define-persistent-store-contract.md) only) | None | Backend-specific server environments |
| `redact-secret-vault` (Python, [packages/vault-py](packages/vault-py/README.md)) | Native Python implementation of the same server-authority contract, in-memory storage, capture via a qualified Node.js boundary to the core (**research-grade**) | `0.1.0a2` (unpublished) | Python 3.10+ server processes with a `node` executable available |

All packages on `main` pin `@redact-secret/core@0.1.0-beta.10` exactly:

```bash
# Once 0.1.0-alpha.2 is published (not yet):
npm install @redact-secret/vault@0.1.0-alpha.2 @redact-secret/core@0.1.0-beta.10
npm install @redact-secret/vault-server@0.1.0-alpha.2 @redact-secret/vault@0.1.0-alpha.2 @redact-secret/core@0.1.0-beta.10
```

A server may use the default in-memory vault; `vault-server` and in-memory storage are not alternatives. Persistence is a storage choice, not a third trust environment. The server security contract is language-neutral: Python, Rust, and Go should have native distributions or a separately qualified service boundary as the core support and evidence permit. The npm names do not imply that server use is JavaScript-only. See the [package and language decision](docs/decisions/2026-09-27-name-vault-packages-and-language-contract.md).

## Typed placeholders are independent

The core offers a typed formatter using safe finding metadata, such as `<JWT_1>`. Core `0.1.0-beta.10` adds real, opt-in PII finding types, all prefixed `pii_` (for example `pii_global_email`, `pii_global_iban`, `pii_jurisdiction_us_ssn`). A typed display label for one of them, whether the core's `typedPlaceholderFormatter` output (`<PII_JURISDICTION_US_SSN_1>`) or an application label such as `<SSN_1>`, is still a core formatting concern. It grants nothing and does **not** imply that the original value was retained or can be restored.

Restoration needs an issued vault token (`<rsv_…>`, 128 random bits, bound to one vault and capture) plus an application grant for the sink and exact path. A PII value is retained only when the application names its exact type in the capture's PII allowlist (`pii: { retain: [...] }`); every other PII finding is replaced by a display placeholder that cannot be restored. Restoration never infers authority from a visible type name or parses a core display placeholder as proof of ownership. See [typed placeholder decision](docs/decisions/2026-09-27-decouple-typed-placeholders-from-restoration.md) and the [PII retention decision](docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md).

## Security direction

- Retention is explicit opt-in and limited to a session or consumer-selected store.
- A token alone grants no restore authority. The application supplies identity, tenant, purpose, destination, and authorization policy at the restore boundary.
- Core `block` findings cannot become restorable entries. Other actions require an explicit eligibility decision.
- Expired, revoked, unknown, cross-session, or cross-tenant lookups fail without exposing plaintext in errors, logs, traces, or diagnostics.
- A short-lived in-memory vault is the proposed portable default in both browser and server environments. Browser memory belongs to the page's trust boundary; it does not enforce multi-user server authorization.
- External stores are opt-in. Persistent mappings require an independently qualified encryption, key management, isolation, expiry, and atomicity contract.
- No library can guarantee that a managed-runtime string has been wiped from every memory copy.
- Model output, tool arguments, and visible placeholder text cannot authorize their own restoration.

The in-memory vault implements these for its scope; server and persistence items remain design requirements. The [security decision](docs/decisions/2026-09-27-restore-authority-and-lifecycle.md) distinguishes invariants from consumer choices.

## Proposed delivery

Define shared security and conformance contracts first. Qualify `@redact-secret/vault` for browser and Node.js memory use, then qualify server authorization, including Python as an early target — `packages/vault-py` is that initial, research-grade Python implementation, still gated on its own conformance evidence and the boundary qualification gaps its research doc names. Rust and Go support follow available core integration and measured demand; do not reimplement detectors here. Each language/runtime is supported only after its own threat model and tests. The names above are selected, but exact API signatures, package versions, TTL defaults, token syntax, store implementations, and release dates remain open.

## Documents

- [Architecture](ARCHITECTURE.md): trust boundaries and proposed components.
- [Conventions](CONVENTIONS.md): documentation, implementation, and review rules.
- [Decisions](docs/decisions/README.md): accepted boundaries and open design questions, including the [server authority interface](docs/decisions/2026-09-27-define-server-authority-interface.md) and [its in-memory implementation](docs/decisions/2026-09-27-implement-vault-server-in-memory.md), and the [persistent store contract](docs/decisions/2026-09-27-define-persistent-store-contract.md) (contract only; no implementation yet).
- [Threat model](docs/specs/threat-model.md): assets, attackers, boundary, and residual risk per mode.
- [Browser in-memory security](docs/specs/in-memory-security.md): guarantees, limits, and deployment alternatives.
- [Qualification record](docs/research/qualification-0.1.0-alpha.1.md): tested runtime/core matrix and evidence for 0.1.0-alpha.1.
- [Core beta.10 qualification record](docs/research/qualification-core-0.1.0-beta.10.md): PII-off and PII-on matrix for 0.1.0-alpha.2, including the registry verification of the published package.
- [Changelog](CHANGELOG.md): release notes, including the 0.1.0-alpha.2 breaking changes and migration.
- [Worker-mode qualification record](docs/research/qualification-worker-mode.md): tested evidence for the optional dedicated-Worker mode, including its hostile-main-thread and CSP negative-control evidence.
- [Conformance corpus](conformance/README.md): language-neutral adversarial cases.
- [Security policy](SECURITY.md) and [releasing](RELEASING.md).
- [Core integration research](docs/research/core-integration.md): public API facts and proof-of-concept questions.
- [Python server integration research](docs/research/python-server-integration-2026-09-27.md): core inventory, the qualified service-boundary decision, conformance evidence, and candid differences from the JS server authority contract.
- [Executed verification](docs/research/verification-2026-09-27.md): Node addon and WASM findings, with browser qualification still open.
- [Security research](docs/research/security-foundations-2026-09-27.md): primary-source findings for browser, authorization, persistence, and release review.
- [Pre-implementation plan](docs/plans/pre-implementation.md): research sequence and release gates.
- [Issue roadmap](docs/plans/issue-roadmap.md): registered epics, child issues, dependencies, and acceptance gates.
- [Alpha.1 orchestrator prompt](docs/plans/alpha1-orchestrator-prompt.md): end-to-end implementation, PR, merge, and release instructions.

Report security concerns privately through this repository's [security advisories](https://github.com/redact-secret/redact-secret-vault/security/advisories/new) (see [SECURITY.md](SECURITY.md)). Never submit live credentials in a public issue or fixture.
