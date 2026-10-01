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

**Status: beta.** [`@redact-secret/vault`](packages/vault/README.md) provides opt-in, bounded, in-memory whole-input capture and structured-field restoration for Node.js and browser main-thread runtimes, with an optional, separately qualified dedicated-Worker mode ([worker qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-worker-mode.md), [#14](https://github.com/redact-secret/redact-secret-vault/issues/14)); Worker mode is not an implicit upgrade over main-thread use, and the two modes' guarantees are documented separately. [`@redact-secret/vault-server`](packages/vault-server/README.md) adds server authority — principal, tenant, source, sink/path, and purpose authorization on every restore, with an in-memory backend built on `@redact-secret/vault`. [`redact-secret-vault` (Python)](packages/vault-py/README.md) is a research-grade, in-memory implementation of the same [server authority interface](docs/decisions/define-server-authority-interface.md) (S1) as `@redact-secret/vault-server` — not of the `@redact-secret/vault` API, passing the shared conformance corpus against the real core through a documented Node.js service boundary — see [its inventory and equivalence evidence](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/python-server-integration-2026-09-27.md). An opt-in persistent server profile is implemented on `main` and **unpublished**: `@redact-secret/vault-server/persistent` with ciphertext-only stores and injected key providers ([specification](docs/specs/persistent-vault.md)). It is alpha, and qualified only for the profiles its [qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md) names: Node.js 22 with PostgreSQL 17.11 as a single primary or a primary with one synchronous standby. Python, browser, and Worker persistence and streaming are not implemented; nothing here claims them.

| Release | Core | State |
| --- | --- | --- |
| `@redact-secret/vault@0.1.0-alpha.1` | `@redact-secret/core@0.1.0-beta.9` exactly | Published 2026-09-27, manually, without provenance. No PII support. [Qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-0.1.0-alpha.1.md) |
| `@redact-secret/vault@0.1.0-alpha.2`, `@redact-secret/vault-server@0.1.0-alpha.2` | `@redact-secret/core@0.1.0-beta.10` exactly | Published 2026-09-28 (npm `alpha` tag; [GitHub pre-release](https://github.com/redact-secret/redact-secret-vault/releases/tag/v0.1.0-alpha.2)). `@redact-secret/vault` was published by the release workflow with npm provenance; `@redact-secret/vault-server` (its first publish) was published manually, without provenance. Adds opt-in PII activation and retention ([decision record](docs/decisions/decide-pii-retention-and-activation-ownership.md)), Worker protocol v2, and a breaking initialization change; see the [changelog](CHANGELOG.md). Qualified with PII off and on in Node.js, three browser engines on the main thread and in a dedicated Worker, and the Python bridge ([beta.10 qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-core-0.1.0-beta.10.md)) |
| `@redact-secret/vault@0.1.0-alpha.3`, `@redact-secret/vault-server@0.1.0-alpha.3` | `@redact-secret/core@0.1.0-beta.10` exactly | Released 2026-09-28 from `release.yml` with npm provenance for both packages (npm `alpha` tag). Adds a Worker-script-owned core `policy` for Worker mode ([#59](https://github.com/redact-secret/redact-secret-vault/issues/59)); no breaking change from `0.1.0-alpha.2`. See the [changelog](CHANGELOG.md) |
| `@redact-secret/vault@0.1.0-beta.1`, `@redact-secret/vault-server@0.1.0-beta.1`, `redact-secret-vault` (Python) `0.1.0b1` | `@redact-secret/core@0.1.0-beta.10` exactly (Python: through the bridge) | Released 2026-09-29 from `release.yml` (npm `beta` tag, PyPI). First beta line; no breaking change from `0.1.0-alpha.3` / `0.1.0a3`. Adds constant-cost expiry sweeping, single-pass capture output validation, incremental revocation-tombstone sweeping, a long-lived Python Node.js bridge, and application-owned core location for the Python package. See the [changelog](CHANGELOG.md) |
| `@redact-secret/vault@0.1.0-beta.2`, `@redact-secret/vault-server@0.1.0-beta.2`, `redact-secret-vault` (Python) `0.1.0b2` | `@redact-secret/core@0.1.0-beta.11` exactly (Python: through the bridge) | Released 2026-09-29 from `release.yml` (npm `beta` tag, PyPI). Re-pins the core to `0.1.0-beta.11` ([#96](https://github.com/redact-secret/redact-secret-vault/issues/96)); no API change from `0.1.0-beta.1` / `0.1.0b1`. See the [changelog](CHANGELOG.md) |
| `@redact-secret/vault@0.1.0-beta.3`, `@redact-secret/vault-server@0.1.0-beta.3`, `redact-secret-vault` (Python) `0.1.0b3` | `@redact-secret/core@0.1.0-beta.12` exactly (Python: through the bridge) | Released 2026-10-01 from `release.yml` (npm `beta` tag, PyPI). Re-pins the core to `0.1.0-beta.12`; no API change from `0.1.0-beta.2` / `0.1.0b2`. See the [changelog](CHANGELOG.md) |
| `@redact-secret/vault@0.1.0-beta.4`, `@redact-secret/vault-server@0.1.0-beta.4`, and six new packages at `0.1.0-alpha.1` (`vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `key-provider-aws-kms`) | `@redact-secret/core@0.1.0-beta.12` exactly | **On `main`, unpublished.** Adds the opt-in persistent server profile (`@redact-secret/vault-server/persistent`) and the packages it is built from. `@redact-secret/vault` gains an internal capture-plan entry and no public API change; the default `@redact-secret/vault-server` entry is unchanged apart from new members of its error and denial types. The Python package is unchanged at `0.1.0b3`. See the [changelog](CHANGELOG.md) and the [qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md) |
| `redact-secret-vault` (Python) `0.1.0a3` | `@redact-secret/core@0.1.0-beta.10` through the bridge | On PyPI: `pip install redact-secret-vault==0.1.0a3`, the first version published there, from `release.yml` through PyPI trusted publishing ([RELEASING.md](RELEASING.md#python)). `0.1.0a2` was never published |

**Registry state (2026-10-01).** `0.1.0-beta.4` and the six new packages are not on npm; none of the new package names exists there yet. PyPI's newest `redact-secret-vault` is `0.1.0b3`. npm's `latest` and `beta` tags both point at `0.1.0-beta.3` for `@redact-secret/vault` and `@redact-secret/vault-server`, so a bare install gets the current release. `0.1.0-beta.2` peers `@redact-secret/core@0.1.0-beta.11` exactly and `0.1.0-beta.1` peers `0.1.0-beta.10`; core's own `latest` is `0.1.0-beta.12`, which `0.1.0-beta.3` pins, so installing it next to a bare `@redact-secret/core` resolves. Exact versions are still recommended while the packages are beta, because each release pins an exact core version (see [RELEASING.md](RELEASING.md#the-latest-dist-tag)).

The core detects and redacts without storing matched plaintext. This repository will opt in to temporarily retaining an original-value mapping so an application can restore an approved value for an approved purpose. Installing or using the core alone must never create a recoverable mapping.

## Quick start

```bash
npm install @redact-secret/vault@0.1.0-beta.3 @redact-secret/core@0.1.0-beta.12
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

## Persistent quick start

**On `main`, unpublished, alpha.** These packages cannot be installed from npm yet. The example is the shape of a server that captures in one process and restores in another, over PostgreSQL. Read the [qualified profiles](docs/research/qualification-persistence-0.1.0-alpha.1.md#2-tested-matrix) and the [operations specification](docs/specs/persistent-operations.md) before using it.

Once, from a maintenance process: `migrate(ownerPool, "rsv")`, the grants from `grantStatements("rsv", role)`, and `store.initializeNamespace({ namespace: "support-prod", epoch: 1 })`. A server never initializes a namespace. Then, in every server process:

```ts
import pg from "pg";
import { createPostgresStore } from "@redact-secret/store-postgres";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";

// The application creates the pool and closes it. Nothing below ends it.
const pool = new pg.Pool({ connectionString: databaseUrl, max: 20, connectionTimeoutMillis: 5000 });
pool.on("error", () => {});
const store = await createPostgresStore({ pool, schema: "rsv" });

// 32 bytes each, from the application's secret manager. Never a literal, never from this library.
const material = await loadWrappingKeyFromSecretManager();
const digestKey = await loadDigestKeyFromSecretManager(); // the same in every process of the namespace

const SINK = "support-ticket-reply-sink-synthetic";
const PURPOSE = "support-reply-purpose-synthetic";

const vault = await createPersistentServerVault({
  namespace: "support-prod",
  recoveryEpoch: 1, // from deployment configuration, kept outside the database
  store,
  crypto: createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "2026-10", material, state: "active" }],
      scope: { namespaces: ["support-prod"] },
    }),
  }),
  digestKey,
  resolvePrincipal: (ctx) => ({ id: ctx.userId, tenant: ctx.tenant }), // from already-authenticated context; throw if unknown
  resolveSession: (ctx) => ctx.conversationId, // binds each capture to its conversation
  // Deny by default: this server may capture and revoke, and nothing else.
  lifecyclePolicy: ({ operation }) => ({ allow: operation === "capture" || operation === "revoke" }),
  // Deny by default: one sink, one purpose.
  policy: (input) =>
    input.sink === SINK && input.purpose === PURPOSE ? { allow: true } : { allow: false, reason: "policy" },
  limits: { entryTtlMs: 5 * 60 * 1000 }, // every capture expires; the ceiling is 24 hours
  pii: [], // core PII detection off
});

const captured = await vault.capture(userText, {
  context: request,
  release: [{ sink: SINK, paths: ["body"] }], // the only sink and path a value may return to
});
// ... send captured.text to the model ...
const { fields } = await vault.restore({
  context: request,
  sink: SINK,
  purpose: PURPOSE,
  captures: [captured.captureId],
  fields: { body: modelReply },
});

await vault.close(); // releases this instance only
await pool.end(); // the application closes what it opened
```

A restore releases a value at most once. A denied, conflicting, or ambiguous restore returns no fields; keep the redacted text, and see the [`vault-server` README](packages/vault-server/README.md#persistent-profile) for each failure. After a database restore from backup or a failover that may have lost commits, recovered captures are not returned to service: the supported path is to invalidate them and capture again ([runbook](docs/specs/persistent-operations.md#5-backup-recovery-runbook)).

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
| `@redact-secret/vault` | Portable, opt-in in-memory mapping and token lifecycle (**beta**) | `0.1.0-beta.4` (npm: `0.1.0-beta.3`) | Qualified: Node.js 20/22/24 and browser main thread; optional dedicated-Worker mode qualified separately (opt-in, not an implicit upgrade). Not yet: edge, SharedWorker, Service Worker, Node.js `worker_threads` |
| `@redact-secret/vault-server` | Server-side authorization of restoration across principals, tenants, sources, destinations, and value paths (**beta**, in-memory backend). Its `./persistent` entry is the opt-in persistent profile (**alpha**, unpublished) | `0.1.0-beta.4` (npm: `0.1.0-beta.3`) | In-memory: tested on Node.js 20/22/24. Persistent profile: tested on Node.js 20/22/24 over `store-memory`; qualified with PostgreSQL on Node.js 22 only |
| [`@redact-secret/vault-contracts`](packages/vault-contracts/README.md) | Types, limits, validators, and error classes of the store, key-provider, and record-crypto contracts; no dependency (**alpha**, unpublished) | `0.1.0-alpha.1` | Tested: Node.js 20/22/24 |
| [`@redact-secret/vault-crypto`](packages/vault-crypto/README.md) | Canonical record encoding and AES-256-GCM envelope encryption over WebCrypto; the local key provider for injected key material (**alpha**, unpublished) | `0.1.0-alpha.1` | Tested: Node.js 20/22/24. Not run in a browser. The local provider is not qualified as a production key-management profile |
| [`@redact-secret/vault-conformance`](packages/vault-conformance/README.md) | Store and key-provider conformance harnesses, fault injection, and an insecure test-only key provider (**alpha**, unpublished) | `0.1.0-alpha.1` | Tested: Node.js 20/22/24 |
| [`@redact-secret/store-memory`](packages/store-memory/README.md) | Ciphertext-only reference store for tests and development. **Non-durable and single-process; not persistence** (**alpha**, unpublished) | `0.1.0-alpha.1` | Tested: Node.js 20/22/24 |
| [`@redact-secret/store-postgres`](packages/store-postgres/README.md) | Ciphertext-only PostgreSQL store over a consumer-owned `pg` pool (**alpha**, unpublished) | `0.1.0-alpha.1` | Qualified: Node.js 22, `pg` 8.23.1, PostgreSQL 17.11, as a single primary (`fsync` and `synchronous_commit` on) or a primary with one synchronous standby. Nothing else: no other version, pooler, managed service, asynchronous failover, or TLS run |
| [`@redact-secret/key-provider-aws-kms`](packages/key-provider-aws-kms/README.md) | Optional AWS KMS key provider over a consumer-supplied client (**alpha**, unpublished) | `0.1.0-alpha.1` | Fake-backed suite on Node.js 20/22/24; one real-service run in `us-east-1` on Node.js 22 with single-Region symmetric keys. Not run with `store-postgres` |
| `redact-secret-vault` (Python, [packages/vault-py](packages/vault-py/README.md)) | Native Python implementation of the same server-authority contract, in-memory storage, capture via a qualified Node.js boundary to the core (**research-grade**) | `0.1.0b3` (on PyPI) | Python 3.10+ server processes with a `node` executable available. No persistence |

The packages on `main` that depend on the core pin `@redact-secret/core@0.1.0-beta.12` exactly, as does the published `0.1.0-beta.3`, which these commands install; `0.1.0-beta.2` pinned `0.1.0-beta.11` ([#96](https://github.com/redact-secret/redact-secret-vault/issues/96)) and `0.1.0-beta.1` pinned `0.1.0-beta.10`:

```bash
npm install @redact-secret/vault@0.1.0-beta.3 @redact-secret/core@0.1.0-beta.12
npm install @redact-secret/vault-server@0.1.0-beta.3 @redact-secret/vault@0.1.0-beta.3 @redact-secret/core@0.1.0-beta.12
```

A server may use the default in-memory vault; `vault-server` and in-memory storage are not alternatives. Persistence is a storage choice, not a third trust environment: the server authorizes, `vault-crypto` encrypts, a key provider wraps data keys, and a store holds ciphertext. `@redact-secret/vault` and the default `@redact-secret/vault-server` entry load no store, driver, SDK, or crypto layer; two packed-artifact checks enforce that ([ARCHITECTURE.md](ARCHITECTURE.md#dependency-rules)). An application may inject its own `Store` or `KeyProvider`; doing so is not a supported profile until it has its own qualification. The server security contract is language-neutral: Python, Rust, and Go should have native distributions or a separately qualified service boundary as the core support and evidence permit. The npm names do not imply that server use is JavaScript-only. See the [package and language decision](docs/decisions/name-vault-packages-and-language-contract.md).

## Typed placeholders are independent

The core offers a typed formatter using safe finding metadata, such as `<JWT_1>`. Core `0.1.0-beta.10` adds real, opt-in PII finding types, all prefixed `pii_` (for example `pii_global_email`, `pii_global_iban`, `pii_jurisdiction_us_ssn`). A typed display label for one of them, whether the core's `typedPlaceholderFormatter` output (`<PII_JURISDICTION_US_SSN_1>`) or an application label such as `<SSN_1>`, is still a core formatting concern. It grants nothing and does **not** imply that the original value was retained or can be restored.

Restoration needs an issued vault token (`<rsv_…>`, 128 random bits, bound to one vault and capture) plus an application grant for the sink and exact path. A PII value is retained only when the application names its exact type in the capture's PII allowlist (`pii: { retain: [...] }`); every other PII finding is replaced by a display placeholder that cannot be restored. Restoration never infers authority from a visible type name or parses a core display placeholder as proof of ownership. See [typed placeholder decision](docs/decisions/decouple-typed-placeholders-from-restoration.md) and the [PII retention decision](docs/decisions/decide-pii-retention-and-activation-ownership.md).

## Security direction

- Retention is explicit opt-in and limited to a session or consumer-selected store.
- A token alone grants no restore authority. The application supplies identity, tenant, purpose, destination, and authorization policy at the restore boundary.
- Core `block` findings cannot become restorable entries. Other actions require an explicit eligibility decision.
- Expired, revoked, unknown, cross-session, or cross-tenant lookups fail without exposing plaintext in errors, logs, traces, or diagnostics.
- A short-lived in-memory vault is the proposed portable default in both browser and server environments. Browser memory belongs to the page's trust boundary; it does not enforce multi-user server authorization.
- External stores are opt-in and hold ciphertext only: no value, token, grant, or key reaches a store. Keys are injected by the application; the library has no default key and reads none from the environment.
- Every persistent capture expires (24 hours at most). A persistent restore releases a value at most once and never replays it; exactly-once delivery is not provided.
- Deleting ciphertext is not erasure, and a database restored from backup holds authentic but stale state. Encryption does not detect a rollback or a party that can write the database. See the [threat model](docs/specs/threat-model.md#persistent-mappings--implemented-on-main-qualified-for-two-postgresql-profiles).
- No library can guarantee that a managed-runtime string has been wiped from every memory copy.
- Model output, tool arguments, and visible placeholder text cannot authorize their own restoration.

The in-memory vault and the in-memory server implement these for their scope. The persistent items are implemented on `main` and qualified only as the [qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md) states. The [security decision](docs/decisions/restore-authority-and-lifecycle.md) distinguishes invariants from consumer choices.

## Proposed delivery

Define shared security and conformance contracts first. Qualify `@redact-secret/vault` for browser and Node.js memory use, then qualify server authorization, including Python as an early target — `packages/vault-py` is that initial, research-grade Python implementation, still gated on its own conformance evidence and the boundary qualification gaps its research doc names. Rust and Go support follow available core integration and measured demand; do not reimplement detectors here. Each language/runtime is supported only after its own threat model and tests. Persistence follows the same rule: one backend and two topologies are qualified, and each further backend, key provider, or language needs its own record. Release dates remain open.

## Documents

- [Architecture](ARCHITECTURE.md): trust boundaries and components.
- [Conventions](CONVENTIONS.md): documentation, implementation, and review rules.
- [Contributing](CONTRIBUTING.md): reporting bugs, submitting changes, and the test policy.
- [Security policy](SECURITY.md): private vulnerability reporting, response process, and release verification.
- [Code of conduct](CODE_OF_CONDUCT.md), [governance](GOVERNANCE.md), and [roadmap](ROADMAP.md).
- [Assurance case](docs/specs/assurance-case.md): why the security requirements are met.
- [Decisions](docs/decisions/README.md): accepted boundaries and open design questions, including the [server authority interface](docs/decisions/define-server-authority-interface.md) and [its in-memory implementation](docs/decisions/implement-vault-server-in-memory.md), the earlier [persistent store contract](docs/decisions/define-persistent-store-contract.md) (partly superseded), and the [ciphertext-only store decision](docs/decisions/supersede-persistent-store-contract.md) that replaces it (implemented on `main`, unpublished).
- [Persistent vault specification](docs/specs/persistent-vault.md): record format, store and key-provider contracts, restore and failure semantics, recovery and erasure limits.
- [Persistent vault operations](docs/specs/persistent-operations.md): expiry and cleanup, the four deletion-related operations, and the backup-recovery and failover runbooks.
- [Persistence qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md): tested matrix, evidence index, unqualified profiles, and remaining limitations, with the [PostgreSQL qualification report](packages/store-postgres/qualification/report/report.md) and the [design review](docs/research/persistent-vault-design-review.md).
- [Persistent record test vectors](conformance/persistent/v1/README.md): deterministic wire vectors every implementation must reproduce.
- [Persistent backend research](docs/research/persistent-backend-capabilities.md) (DynamoDB, Redis, SQLite; research only, no adapter) and the [Python persistence parity plan](docs/plans/python-persistence-parity.md) (plan only, not implemented).
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
