# Redact Secret Vault

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15003/badge)](https://www.bestpractices.dev/projects/15003)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![SAST](https://github.com/redact-secret/redact-secret-vault/actions/workflows/sast.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/sast.yml)
[![npm: @redact-secret/vault](https://img.shields.io/npm/v/@redact-secret/vault?label=%40redact-secret%2Fvault)](https://www.npmjs.com/package/@redact-secret/vault)
[![npm: @redact-secret/vault-server](https://img.shields.io/npm/v/@redact-secret/vault-server?label=%40redact-secret%2Fvault-server)](https://www.npmjs.com/package/@redact-secret/vault-server)
[![PyPI: redact-secret-vault](https://img.shields.io/pypi/v/redact-secret-vault?label=redact-secret-vault)](https://pypi.org/project/redact-secret-vault/)
[![License: MIT](https://img.shields.io/github/license/redact-secret/redact-secret-vault)](./LICENSE)


Optional, policy-gated restoration of values redacted by [Redact Secret](https://github.com/redact-secret/redact-secret). This repository was formerly `redact-secret/redact-secret-reversible`.

**Status: beta.** [`@redact-secret/vault`](packages/vault/README.md) provides opt-in, bounded, in-memory whole-input capture and structured-field restoration for Node.js and browser main-thread runtimes, with an optional, separately qualified dedicated-Worker mode ([worker qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-worker-mode.md), [#14](https://github.com/redact-secret/redact-secret-vault/issues/14)); Worker mode is not an implicit upgrade over main-thread use, and the two modes' guarantees are documented separately. [`@redact-secret/vault-server`](packages/vault-server/README.md) adds server authority — principal, tenant, source, sink/path, and purpose authorization on every restore, with an in-memory backend built on `@redact-secret/vault`. [`redact-secret-vault` (Python)](packages/vault-py/README.md) is a research-grade, in-memory implementation of the same [server authority interface](docs/decisions/define-server-authority-interface.md) (S1) as `@redact-secret/vault-server` — not of the `@redact-secret/vault` API, passing the shared conformance corpus against the real core through a documented Node.js service boundary — see [its inventory and equivalence evidence](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/python-server-integration-2026-09-27.md). Persistent stores and streaming remain design work; nothing here claims them.

| Release | Core | State |
| --- | --- | --- |
| `@redact-secret/vault@0.1.0-alpha.1` | `@redact-secret/core@0.1.0-beta.9` exactly | Published 2026-09-27, manually, without provenance. No PII support. [Qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-0.1.0-alpha.1.md) |
| `@redact-secret/vault@0.1.0-alpha.2`, `@redact-secret/vault-server@0.1.0-alpha.2` | `@redact-secret/core@0.1.0-beta.10` exactly | Published 2026-09-28 (npm `alpha` tag; [GitHub pre-release](https://github.com/redact-secret/redact-secret-vault/releases/tag/v0.1.0-alpha.2)). `@redact-secret/vault` was published by the release workflow with npm provenance; `@redact-secret/vault-server` (its first publish) was published manually, without provenance. Adds opt-in PII activation and retention ([decision record](docs/decisions/decide-pii-retention-and-activation-ownership.md)), Worker protocol v2, and a breaking initialization change; see the [changelog](CHANGELOG.md). Qualified with PII off and on in Node.js, three browser engines on the main thread and in a dedicated Worker, and the Python bridge ([beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md)) |
| `@redact-secret/vault@0.1.0-alpha.3`, `@redact-secret/vault-server@0.1.0-alpha.3` | `@redact-secret/core@0.1.0-beta.10` exactly | Released 2026-09-28 from `release.yml` with npm provenance for both packages (npm `alpha` tag). Adds a Worker-script-owned core `policy` for Worker mode ([#59](https://github.com/redact-secret/redact-secret-vault/issues/59)); no breaking change from `0.1.0-alpha.2`. See the [changelog](CHANGELOG.md) |
| `@redact-secret/vault@0.1.0-beta.1`, `@redact-secret/vault-server@0.1.0-beta.1`, `redact-secret-vault` (Python) `0.1.0b1` | `@redact-secret/core@0.1.0-beta.10` exactly (Python: through the bridge) | Released 2026-09-29 from `release.yml` (npm `beta` tag, PyPI). First beta line; no breaking change from `0.1.0-alpha.3` / `0.1.0a3`. Adds constant-cost expiry sweeping, single-pass capture output validation, incremental revocation-tombstone sweeping, a long-lived Python Node.js bridge, and application-owned core location for the Python package. See the [changelog](CHANGELOG.md) |
| `redact-secret-vault` (Python) `0.1.0a3` | `@redact-secret/core@0.1.0-beta.10` through the bridge | On PyPI: `pip install redact-secret-vault==0.1.0a3`, the first version published there, from `release.yml` through PyPI trusted publishing ([RELEASING.md](RELEASING.md#python)). `0.1.0a2` was never published |

npm's `latest` and `beta` tags both point at `0.1.0-beta.1` for both packages, so a bare install gets the current release. Exact versions are still recommended while the packages are beta, because each release pins an exact core version (see [RELEASING.md](RELEASING.md#the-latest-dist-tag)).

The core detects and redacts without storing matched plaintext. This repository will opt in to temporarily retaining an original-value mapping so an application can restore an approved value for an approved purpose. Installing or using the core alone must never create a recoverable mapping.

## Quick start

```bash
npm install @redact-secret/vault@0.1.0-beta.1 @redact-secret/core@0.1.0-beta.10
```

```ts
import { createVault } from "@redact-secret/vault";

const vault = await createVault({ pii: [] }); // initializes the core with PII detection off
const captured = vault.capture("Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today", {
  release: [{ sink: "reply", paths: ["body"] }], // where values may come back
});
// captured.text === "Rotate <rsv_…> today" — send this to the model.
const { fields } = vault.restore({ sink: "reply", captures: [captured.captureId], fields: { body: captured.text } });
// fields.body is the original text again, restored only into the granted sink and path.
vault.dispose();
```

The [`@redact-secret/vault` README](packages/vault/README.md#usage) shows the full pattern, including how to handle a denied restore. Server use: [`@redact-secret/vault-server`](packages/vault-server/README.md#usage). Python: [`redact-secret-vault`](packages/vault-py/README.md).

## Repository boundaries

| Repository | Owns | Must not own |
| --- | --- | --- |
| [redact-secret](https://github.com/redact-secret/redact-secret) | Detection, overlap resolution, policy, redaction, safe finding metadata, and placeholder formatting | Restoration storage, restore authorization, or a dependency on this repository |
| **redact-secret-vault** | Opt-in mapping lifecycle, opaque identifiers, restoration checks, and storage/authorization extension points | Detection rules, PII classification, or changes to core policy |
| [redact-secret-adapters](https://github.com/redact-secret/redact-secret-adapters) | Host integrations for logs, traces, AI context, and MCP | Restoration or emitting mapped plaintext to observability |
| [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) | Detection and support evidence | Treating restoration success as detection accuracy |

Dependency direction is one way: this repository may consume the core's documented public API; the core and adapters must not depend on this repository. Each package releases on its own cadence, independent of the core, and pins one exactly tested core version ([RELEASING.md](RELEASING.md)). See [Architecture](ARCHITECTURE.md) and [boundary decision](docs/decisions/separate-reversible-boundary.md).

## Packages and distribution

The agreed JavaScript package names describe two different responsibilities:

| Package | Responsibility | Version on `main` | Runtimes |
| --- | --- | --- | --- |
| `@redact-secret/vault` | Portable, opt-in in-memory mapping and token lifecycle (**beta**) | `0.1.0-beta.1` | Qualified: Node.js 20/22/24 and browser main thread; optional dedicated-Worker mode qualified separately (opt-in, not an implicit upgrade). Not yet: edge, SharedWorker, Service Worker, Node.js `worker_threads` |
| `@redact-secret/vault-server` | Server-side authorization of restoration across principals, tenants, sources, destinations, and value paths (**beta**, in-memory backend) | `0.1.0-beta.1` | Tested: Node.js 20/22/24. Not yet: persistent backends |
| `@redact-secret/store-*` | Optional persistent backend implementations (**proposed**; [contract](docs/decisions/define-persistent-store-contract.md) only) | None | Backend-specific server environments |
| `redact-secret-vault` (Python, [packages/vault-py](packages/vault-py/README.md)) | Native Python implementation of the same server-authority contract, in-memory storage, capture via a qualified Node.js boundary to the core (**research-grade**) | `0.1.0b1` (on PyPI) | Python 3.10+ server processes with a `node` executable available |

All packages on `main` pin `@redact-secret/core@0.1.0-beta.10` exactly:

```bash
npm install @redact-secret/vault@0.1.0-beta.1 @redact-secret/core@0.1.0-beta.10
npm install @redact-secret/vault-server@0.1.0-beta.1 @redact-secret/vault@0.1.0-beta.1 @redact-secret/core@0.1.0-beta.10
```

A server may use the default in-memory vault; `vault-server` and in-memory storage are not alternatives. Persistence is a storage choice, not a third trust environment. The server security contract is language-neutral: Python, Rust, and Go should have native distributions or a separately qualified service boundary as the core support and evidence permit. The npm names do not imply that server use is JavaScript-only. See the [package and language decision](docs/decisions/name-vault-packages-and-language-contract.md).

## Typed placeholders are independent

The core offers a typed formatter using safe finding metadata, such as `<JWT_1>`. Core `0.1.0-beta.10` adds real, opt-in PII finding types, all prefixed `pii_` (for example `pii_global_email`, `pii_global_iban`, `pii_jurisdiction_us_ssn`). A typed display label for one of them, whether the core's `typedPlaceholderFormatter` output (`<PII_JURISDICTION_US_SSN_1>`) or an application label such as `<SSN_1>`, is still a core formatting concern. It grants nothing and does **not** imply that the original value was retained or can be restored.

Restoration needs an issued vault token (`<rsv_…>`, 128 random bits, bound to one vault and capture) plus an application grant for the sink and exact path. A PII value is retained only when the application names its exact type in the capture's PII allowlist (`pii: { retain: [...] }`); every other PII finding is replaced by a display placeholder that cannot be restored. Restoration never infers authority from a visible type name or parses a core display placeholder as proof of ownership. See [typed placeholder decision](docs/decisions/decouple-typed-placeholders-from-restoration.md) and the [PII retention decision](docs/decisions/decide-pii-retention-and-activation-ownership.md).

## Security direction

- Retention is explicit opt-in and limited to a session or consumer-selected store.
- A token alone grants no restore authority. The application supplies identity, tenant, purpose, destination, and authorization policy at the restore boundary.
- Core `block` findings cannot become restorable entries. Other actions require an explicit eligibility decision.
- Expired, revoked, unknown, cross-session, or cross-tenant lookups fail without exposing plaintext in errors, logs, traces, or diagnostics.
- A short-lived in-memory vault is the proposed portable default in both browser and server environments. Browser memory belongs to the page's trust boundary; it does not enforce multi-user server authorization.
- External stores are opt-in. Persistent mappings require an independently qualified encryption, key management, isolation, expiry, and atomicity contract.
- No library can guarantee that a managed-runtime string has been wiped from every memory copy.
- Model output, tool arguments, and visible placeholder text cannot authorize their own restoration.

The in-memory vault implements these for its scope; server and persistence items remain design requirements. The [security decision](docs/decisions/restore-authority-and-lifecycle.md) distinguishes invariants from consumer choices.

## Proposed delivery

Define shared security and conformance contracts first. Qualify `@redact-secret/vault` for browser and Node.js memory use, then qualify server authorization, including Python as an early target — `packages/vault-py` is that initial, research-grade Python implementation, still gated on its own conformance evidence and the boundary qualification gaps its research doc names. Rust and Go support follow available core integration and measured demand; do not reimplement detectors here. Each language/runtime is supported only after its own threat model and tests. The names above are selected, but exact API signatures, package versions, TTL defaults, token syntax, store implementations, and release dates remain open.

## Documents

- [Architecture](ARCHITECTURE.md): trust boundaries and proposed components.
- [Conventions](CONVENTIONS.md): documentation, implementation, and review rules.
- [Contributing](CONTRIBUTING.md): reporting bugs, submitting changes, and the test policy.
- [Security policy](SECURITY.md): private vulnerability reporting, response process, and release verification.
- [Code of conduct](CODE_OF_CONDUCT.md), [governance](GOVERNANCE.md), and [roadmap](ROADMAP.md).
- [Assurance case](docs/specs/assurance-case.md): why the security requirements are met.
- [Decisions](docs/decisions/README.md): accepted boundaries and open design questions, including the [server authority interface](docs/decisions/define-server-authority-interface.md) and [its in-memory implementation](docs/decisions/implement-vault-server-in-memory.md), and the [persistent store contract](docs/decisions/define-persistent-store-contract.md) (contract only; no implementation yet).
- [Threat model](docs/specs/threat-model.md): assets, attackers, boundary, and residual risk per mode.
- [Browser in-memory security](docs/specs/in-memory-security.md): guarantees, limits, and deployment alternatives.
- [Qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-0.1.0-alpha.1.md) (archived): tested runtime/core matrix and evidence for 0.1.0-alpha.1.
- [Core beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md) (archived): PII-off and PII-on matrix for 0.1.0-alpha.2, including the registry verification of the published package.
- [Changelog](CHANGELOG.md): release notes, including the 0.1.0-alpha.2 breaking changes and migration.
- [Worker-mode qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-worker-mode.md) (archived): tested evidence for the optional dedicated-Worker mode, including its hostile-main-thread and CSP negative-control evidence.
- [Conformance corpus](conformance/README.md): language-neutral adversarial cases.
- [Security policy](SECURITY.md) and [releasing](RELEASING.md).
- Earlier research records and plans (core integration, Python server integration, executed verification, security research, pre-implementation plan, issue roadmap, alpha.1 orchestrator prompt) were retired in `a47d6d9`; they remain readable in the [archived `docs/`](https://github.com/redact-secret/redact-secret-vault/tree/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs) tree.

Report security concerns privately through this repository's [security advisories](https://github.com/redact-secret/redact-secret-vault/security/advisories/new) (see [SECURITY.md](SECURITY.md)). Never submit live credentials in a public issue or fixture.
