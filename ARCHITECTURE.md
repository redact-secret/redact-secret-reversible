# Architecture

## Status and intent

This is the design contract for an optional restoration product. It records where plaintext is permitted, which repository owns each behavior, and what must be verified before a behavior is called supported.

State on `main` (2026-10-01):

- **Current, published (beta).** The in-memory vault, `@redact-secret/vault`, and single-process, in-memory server authority, `@redact-secret/vault-server`, are on npm at `0.1.0-beta.3`. The research-grade Python package `redact-secret-vault` is on PyPI at `0.1.0b3`; it has in-memory storage only.
- **Implemented, unpublished (alpha).** An opt-in persistent server profile: `@redact-secret/vault-server/persistent` (in `0.1.0-beta.4`), with `@redact-secret/vault-contracts`, `@redact-secret/vault-crypto`, `@redact-secret/vault-conformance`, `@redact-secret/store-memory`, `@redact-secret/store-postgres`, `@redact-secret/store-sqlite`, and `@redact-secret/key-provider-aws-kms` at `0.1.0-alpha.1`. It is qualified only for the profiles the [qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md) names: Node.js 22 with PostgreSQL 17.11 as a single primary or a primary with one synchronous standby. `store-sqlite` has a [partial record](docs/research/qualification-store-sqlite-0.1.0-alpha.1.md) (one machine, Node.js 22.16.0; power loss not simulated) and is not a supported profile.
- **In the source tree, unpublished, not supported.** Python persistent modules in `redact-secret-vault` (`persistent`, `crypto`, `stores.postgres`, `keys.aws_kms`, behind the `crypto`, `postgres`, and `aws-kms` extras; Python 3.11 and later). They ran against the cells of the [Python qualification record](docs/research/qualification-python-persistence-0.1.0b3.md), which states that its gates are not all passed and that the Node.js core bridge is not qualified; no Python persistence support is claimed. The published `0.1.0b3` does not contain them.
- **Not implemented.** Browser or Worker persistence, streaming, arbitrary-text restore, and any store other than the three above, and any claim for `store-sqlite` beyond its record. DynamoDB and Redis exist as [research](docs/research/persistent-backend-capabilities.md) only.

## Package and language boundaries

`@redact-secret/vault` is the portable in-memory session primitive for browser and Node.js runtimes; edge runtimes are not qualified. `@redact-secret/vault-server` adds server authority for principals, tenants, sources, destinations, paths, and usage budgets; its default entry uses memory. Persistence is opt-in through `@redact-secret/vault-server/persistent` and is a storage choice, not a third execution profile.

The server security specification and adversarial conformance cases belong to this repository, independently of language. JavaScript uses the npm names above. Python has one distribution, `redact-secret-vault` ([packages/vault-py](packages/vault-py/README.md), on PyPI, research-grade, in-memory only), which implements the same server-authority contract as `@redact-secret/vault-server`, not the `@redact-secret/vault` API; Python has no separate authority-free portable vault, so its name carries no `-server` suffix. Python, Rust, and Go need their own native distribution or a separately qualified service boundary; no JavaScript dependency is imposed on them. See [package decision](docs/decisions/name-vault-packages-and-language-contract.md).

The persistent profile splits ownership four ways. The [persistent vault specification](docs/specs/persistent-vault.md) §2 is the authoritative table; in short:

| Component | Package | Owns | Never does |
| --- | --- | --- | --- |
| Server | `@redact-secret/vault-server/persistent` | Principal, tenant, session, sink, path, and purpose authorization; policy evaluation; lifecycle orchestration | Open a database or key-service client |
| Crypto layer | `@redact-secret/vault-crypto` | Canonical encoding and AES-256-GCM envelope encryption of each record | Store or authorize |
| Key provider | `@redact-secret/vault-crypto/local-key-provider`, `@redact-secret/key-provider-aws-kms`, or the application's own | Generate, wrap, and unwrap one data key per capture | See a payload, store, or authorize |
| Store | `@redact-secret/store-postgres`, `@redact-secret/store-sqlite` (one host), `@redact-secret/store-memory` (non-durable, tests only), or the application's own | Ciphertext I/O and conditional transactions | See a value, a token, a key, a principal, or a policy |

`@redact-secret/vault-contracts` holds the shared types, limits, validators, and error classes and has no dependency. `@redact-secret/vault-conformance` holds the store and key-provider harnesses. An application may inject its own `Store`, `KeyProvider`, or `RecordCrypto`. An injected implementation runs inside the trusted process: an interface does not isolate the vault from it, and passing the conformance harness shows a correct adapter behaves, not that a hostile one is safe.

### Dependency rules

These are checked on the packed artifacts, in CI, by two scripts:

- `qualification/check-boundaries.mjs` (`npm run check:boundaries`): `@redact-secret/vault` packs only its build output; its root and Worker entry points use no storage, network, or console API and do not re-export the internal capture plan.
- `qualification/check-persistence-boundaries.mjs` (`npm run check:persistence-boundaries`): for each of `vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, `key-provider-aws-kms`, and `vault-server`, the exact set of runtime dependencies, peers, and import specifiers its packed JavaScript may contain.

The rules they enforce:

- `@redact-secret/vault` has no runtime dependency and imports only its core peer.
- `@redact-secret/vault-contracts` has no dependency.
- `vault-crypto`, `vault-conformance`, and each store depend on `vault-contracts` only. Workspace dependencies are pinned to exact versions.
- `@redact-secret/vault-server` depends on `@redact-secret/vault` and `vault-contracts`. Its default entry reaches no file of the persistent profile and does not import `vault-contracts`.
- Only a `store-*` or `key-provider-*` package may name a database driver, a key-service SDK, or another adapter, and it declares the driver or SDK as a peer: `pg` for `store-postgres`, `@aws-sdk/client-kms` for `key-provider-aws-kms`. `store-postgres` imports no driver; the application passes a pool. `store-sqlite` imports none either and declares no peer: the application loads `better-sqlite3` or `node:sqlite` and passes it in. `store-sqlite` is the only package that may import `node:fs` and `node:path`, for its restore marker file and path canonicalization.
- A store calls no cipher and no key provider.
- No packed file uses `console`, the network, browser storage, `process.env`, or dynamic code, and no package has an install-time script.

`qualification/persistence-consumer.mjs` (`npm run qualify:persistence`) adds a behavioral check: it installs the packed tarballs into projects outside the repository and shows that installing and importing `@redact-secret/vault` and `@redact-secret/vault-server` installs no driver, SDK, store, provider, or crypto layer and loads neither `vault-contracts` nor the persistent profile.

## Trust boundaries

```text
Untrusted input
    |
    v
Redact Secret public scan/policy/range API
    |
    +--> ordinary core redaction --> safe text + safe metadata
    |
    +--> explicit reversible session (opt-in, trusted runtime)
              | original spans retained only for eligible findings
              v
        session-scoped mapping store
              |
              | authenticated and authorized restore request
              v
        designated application destination
```

The core remains side-effect-free and never receives a storage dependency. This product necessarily handles plaintext before and during restoration; it therefore has a different security model. The core, logs, traces, model context, conversation storage, and benchmark reports must not receive the mapping or restored values by accident.

### Dependency and ownership

- Depend only on the core's documented public operations and safe finding metadata. Verify the exact compatibility surface before implementation; do not import internal Rust, binding, or package modules.
- The core owns detector types, action decisions, offset semantics, and default/typed placeholder formatting. This product may not redefine detection or quietly change a `block` action.
- This product owns token identity, value capture from original input ranges, mapping lifecycle, restore authorization, and backend contracts.
- Host adapters continue to sanitize their outbound sinks; they neither depend on this product nor gain restore capability.
- Detection benchmarks remain independent. Restoration security needs its own adversarial and lifecycle tests.

## Proposed session lifecycle

1. A caller explicitly opens an in-memory vault with bounded scope and lifetime. Browser-only final-display use stays within the page's trust boundary; multi-principal server use additionally requires server-owned identity, tenant, source, and authorization policy.
2. The session asks the core to inspect input under the application's policy. Only eligible finalized ranges may be captured. A `block` outcome fails the relevant operation rather than entering the mapping.
3. For each retained occurrence, the session issues a collision-resistant, session-bound token and records a mapping with bounded lifetime and size. Visible type information is descriptive only.
4. The caller sends only sanitized text across the intended boundary. The store and session handle remain in the trusted environment.
5. At restore time, a server integration resolves the principal, purpose, destination, and structural value path from trusted runtime context, never a model assertion. It preflights the entire operation against current authorization, source, session/tenant binding, expiry/revocation, usage limits, and exact issued tokens; one violation rejects the complete operation without partial plaintext or budget consumption. A browser final-display integration has a different trust model and cannot claim server-grade caller authentication.
6. The caller sends the restored value only to its approved destination. Abort, expiry, revoke, and completion invalidate the mapping according to the documented store contract.

An LLM response or tool argument is untrusted input to step 5. It may carry a token but cannot supply an authoritative grant. The application must decide whether and where restoration is permitted. A constrained structured-field operation can be the safe default; an advanced arbitrary-text operation may be provided only with the same mandatory authorization checks.

Whole-input capture should be designed first. Streaming introduces unresolved ranges, partial output, cancellation, and late `block` findings; it must have a separate contract before support is claimed.

## Placeholder identity

`<SECRET_1>` and core typed labels such as `<JWT_1>` are deterministic display placeholders. They are not capabilities and cannot safely serve as the sole lookup key. A reversible token requires unpredictable, session-bound identity; token syntax, collision handling, escaping, and behavior when an identical literal already exists in input or output need a decision and tests. The token's type label, if any, must not be trusted to classify the underlying value.

## Storage and authorization

The proposed portable default is short-lived in-runtime memory with explicit limits. In a browser, the same-page scripts share that trust boundary; encryption with a key available to the page does not protect against compromised page code. In a server, memory belongs to the process and still requires application authorization before any external destination receives a value. Neither environment can promise that all managed-runtime copies have been erased. The library must not force one vendor's vault or the consumer's identity provider.

Persistent storage is implemented on `main` as the split above and specified in the [persistent vault specification](docs/specs/persistent-vault.md); the [operations specification](docs/specs/persistent-operations.md) covers expiry, deletion, recovery, and failover. What the split means at the trust boundary:

- The store holds ciphertext, wrapped keys, counters, and receipts. It never receives a value, an issued token, a grant, a finding type, or a data key. A party that reads it sees the metadata of specification §3.7: tenant and capture identifiers, times, counters, sizes.
- The server builds each record's associated data from trusted scope, so a stored record moved to another tenant, capture, entry, or session, or given another expiry or use budget, fails authentication.
- A restore is one conditional transaction in the store, which is its linearization point; a revocation that commits first denies it. Release is at most once: nothing is returned before a definite commit, and a receipt never authorizes sending a value again. Exactly-once delivery is not provided.
- Keys are injected by the application. There is no default key, no key read from the environment, and no fallback from a remote provider to a local one.
- Encryption shows a record is authentic, not that it is current. A party that can write the database can reset a use counter or a revocation, and a database restored from backup holds authentic stale rows. The control for a recovery is an epoch held in deployment configuration plus a runbook that invalidates recovered captures; a rollback the operator does not know about is not detected.
- Revocation, ciphertext deletion, key retirement, and verified erasure are four different things. The library performs the first two. Deleting a row is not erasure while a wrapped key survives in a backup and its wrapping key is usable.
- Each store declares the deployment profile its qualification covers. Transaction isolation is not evidence of crash or failover durability; those were tested separately, and an asynchronous replica was shown to be an unsafe failover target.

The [threat model](docs/specs/threat-model.md#persistent-mappings--implemented-on-main-qualified-for-two-postgresql-profiles) states the assets, attackers, residual risks, and alternatives.

The package enforces invariant checks but cannot authenticate a principal on behalf of an application. The consumer supplies authentication, authorization policy, destination identity, and permitted purpose. Authorization is re-evaluated at restore time; an earlier grant does not override later revocation. The [server authority interface](docs/decisions/define-server-authority-interface.md) fixes this paragraph's principal resolution, decision tuple, denial vocabulary, and audit shape as a reference contract. [`@redact-secret/vault-server`](packages/vault-server/README.md) implements it with an in-memory backend built on `@redact-secret/vault` ([implementation decision](docs/decisions/implement-vault-server-in-memory.md)). The [persistent store contract](docs/decisions/define-persistent-store-contract.md) likewise fixes this paragraph's atomic eligibility/consume/revoke behavior, logical TTL, tenant isolation, AEAD encryption bound to record metadata, consumer-owned key injection and rotation, and backup/deletion semantics as a reference contract; it defines no backend and mandates no vendor, and no package implements it as written (#19). Its store interface, key-provider shape, per-entry atomicity, plaintext replay, and deletion promise are superseded by the [ciphertext-only store decision](docs/decisions/supersede-persistent-store-contract.md) ([#104](https://github.com/redact-secret/redact-secret-vault/issues/104)), which is what the packages on `main` implement.

No raw mapping, value, restore result, or payload-bearing exception may be sent to logs, traces, analytics, serialized session state, model context, or public errors. Audit hooks expose only bounded safe metadata and outcome codes. Avoid claiming universal leak prevention: application code can deliberately forward a restored value, and the documented integration boundary must make that responsibility clear.

## Release and language strategy

This repository versions independently from the core and adapters. Each language distribution declares and tests its supported core range and runtime matrix. JavaScript browser and Node.js are the vault targets; JavaScript and Python are the server targets, and only JavaScript has a persistent profile that is qualified for named profiles; Python has persistent modules in the source tree that are unpublished and not supported ([Python parity plan](docs/plans/python-persistence-parity.md), [qualification record](docs/research/qualification-python-persistence-0.1.0b3.md)). Each persistence package versions and qualifies on its own. Rust and Go integrations are separately qualified as core support permits, without reimplementing detection. Shared conformance cases protect the language-neutral security contract without requiring lockstep releases. CLI restoration remains a separate threat-model decision.

## Required qualification before an API is declared supported

- Correct range extraction, Unicode behavior, repeated values, literal token collisions, and deterministic output under the chosen contract.
- Rejection of `block`, unknown, forged, expired, revoked, cross-session, and cross-tenant tokens.
- Authorization changes between redaction and restoration, destination changes, and replay attempts.
- Storage failure, partial write, concurrent restore/revoke, cancellation, and cleanup behavior.
- No plaintext in errors, diagnostic hooks, logging, OTel, snapshots, or published fixtures.
- Real-core integration at the declared dependency range endpoints.

See [Decisions](docs/decisions/README.md) for settled boundaries and open questions.
