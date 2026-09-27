# Redact Secret Reversible

Optional, policy-gated restoration of values redacted by [Redact Secret](https://github.com/redact-secret/redact-secret).

**Status: design-only scaffold.** This repository has no published package, supported runtime, or implemented restore API yet. The documents describe the intended security boundary and decisions to validate before implementation.

The core detects and redacts without storing matched plaintext. This repository will opt in to temporarily retaining an original-value mapping so an application can restore an approved value for an approved purpose. Installing or using the core alone must never create a recoverable mapping.

## Repository boundaries

| Repository | Owns | Must not own |
| --- | --- | --- |
| [redact-secret](https://github.com/redact-secret/redact-secret) | Detection, overlap resolution, policy, redaction, safe finding metadata, and placeholder formatting | Restoration storage, restore authorization, or a dependency on this repository |
| **redact-secret-reversible** | Opt-in mapping lifecycle, opaque identifiers, restoration checks, and storage/authorization extension points | Detection rules, PII classification, or changes to core policy |
| [redact-secret-adapters](https://github.com/redact-secret/redact-secret-adapters) | Host integrations for logs, traces, AI context, and MCP | Restoration or emitting mapped plaintext to observability |
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Detection and support evidence | Treating restoration success as detection accuracy |

Dependency direction is one way: this repository may consume the core's documented public API; the core and adapters must not depend on this repository. A separate release cadence and an explicitly tested core compatibility range will apply when a package exists. See [Architecture](ARCHITECTURE.md) and [boundary decision](docs/decisions/2026-09-27-separate-reversible-boundary.md).

## Packages and distribution

The agreed JavaScript package names describe two different responsibilities:

| Package | Proposed responsibility | Intended runtimes |
| --- | --- | --- |
| `@redact-secret/vault` | Portable, opt-in in-memory mapping and token lifecycle | Browser, Node.js, and qualified edge runtimes |
| `@redact-secret/vault-server` | Server-side authorization of restoration across principals, tenants, sources, destinations, and value paths | Qualified server runtimes |
| `@redact-secret/store-*` | Optional persistent backend implementations | Backend-specific server environments |

A server may use the default in-memory vault; `vault-server` and in-memory storage are not alternatives. Persistence is a storage choice, not a third trust environment. The server security contract is language-neutral: Python, Rust, and Go should have native distributions or a separately qualified service boundary as the core support and evidence permit. The npm names do not imply that server use is JavaScript-only. See the [package and language decision](docs/decisions/2026-09-27-name-vault-packages-and-language-contract.md).

## Typed placeholders are independent

The core already offers a typed formatter using safe finding metadata, such as `<JWT_1>`. If a future PII detector reports type `ssn`, a typed display label such as `<SSN_1>` remains a core formatting concern. Such a label does **not** imply that the original value was retained or can be restored.

A reversible token will need a session-scoped, collision-resistant identity and an authorized mapping lookup. Its exact syntax is not yet selected. Restoration must not infer authority from the visible type name or parse a core display placeholder as proof of ownership. See [typed placeholder decision](docs/decisions/2026-09-27-decouple-typed-placeholders-from-restoration.md).

## Security direction

- Retention is explicit opt-in and limited to a session or consumer-selected store.
- A token alone grants no restore authority. The application supplies identity, tenant, purpose, destination, and authorization policy at the restore boundary.
- Core `block` findings cannot become restorable entries. Other actions require an explicit eligibility decision.
- Expired, revoked, unknown, cross-session, or cross-tenant lookups fail without exposing plaintext in errors, logs, traces, or diagnostics.
- A short-lived in-memory vault is the proposed portable default in both browser and server environments. Browser memory belongs to the page's trust boundary; it does not enforce multi-user server authorization.
- External stores are opt-in. Persistent mappings require an independently qualified encryption, key management, isolation, expiry, and atomicity contract.
- No library can guarantee that a managed-runtime string has been wiped from every memory copy.
- Model output, tool arguments, and visible placeholder text cannot authorize their own restoration.

These are design requirements, not claims of current implementation. The [security decision](docs/decisions/2026-09-27-restore-authority-and-lifecycle.md) distinguishes invariants from consumer choices.

## Proposed delivery

Define shared security and conformance contracts first. Qualify `@redact-secret/vault` for browser and Node.js memory use, then qualify server authorization, including Python as an early target. Rust and Go support follow available core integration and measured demand; do not reimplement detectors here. Each language/runtime is supported only after its own threat model and tests. The names above are selected, but exact API signatures, package versions, TTL defaults, token syntax, store implementations, and release dates remain open.

## Documents

- [Architecture](ARCHITECTURE.md): trust boundaries and proposed components.
- [Conventions](CONVENTIONS.md): documentation, implementation, and review rules.
- [Decisions](docs/decisions/README.md): accepted boundaries and open design questions.
- [Browser in-memory security](docs/specs/in-memory-security.md): proposed guarantees, limits, and deployment alternatives.
- [Core integration research](docs/research/core-integration.md): public API facts and proof-of-concept questions.
- [Executed verification](docs/research/verification-2026-09-27.md): Node addon and WASM findings, with browser qualification still open.
- [Security research](docs/research/security-foundations-2026-09-27.md): primary-source findings for browser, authorization, persistence, and release review.
- [Pre-implementation plan](docs/plans/pre-implementation.md): research sequence and release gates.
- [Issue roadmap](docs/plans/issue-roadmap.md): registered epics, child issues, dependencies, and acceptance gates.
- [Alpha.1 orchestrator prompt](docs/plans/alpha1-orchestrator-prompt.md): end-to-end implementation, PR, merge, and release instructions.

Report security concerns through the core project's [private advisory channel](https://github.com/redact-secret/redact-secret/security/advisories/new) until this repository defines its own reporting channel. Never submit live credentials in a public issue or fixture.
