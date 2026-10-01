# Architecture

## Status and intent

This is the design contract for an optional restoration product. Its in-memory vault is implemented as `@redact-secret/vault` (published `0.1.0-alpha.1` and `0.1.0-alpha.2`) and single-process, in-memory server authority as `@redact-secret/vault-server` (published `0.1.0-alpha.2`, its first release); persistence is not implemented. It records where plaintext is permitted, which repository owns each behavior, and what must be verified before publishing. Concrete interfaces and storage backends remain open.

## Package and language boundaries

`@redact-secret/vault` is the proposed portable in-memory session primitive for browser, Node.js, and separately qualified edge runtimes. `@redact-secret/vault-server` adds server authority for principals, tenants, sources, destinations, paths, and usage budgets; it can still use memory. `@redact-secret/store-*` packages are optional persistence implementations, not a third execution profile. An application may also provide its own store when it satisfies the same contract.

The server security specification and adversarial conformance cases belong to this repository, independently of language. JavaScript uses the npm names above. Python has one distribution, `redact-secret-vault` ([packages/vault-py](packages/vault-py/README.md), unpublished, research-grade), which implements the same server-authority contract as `@redact-secret/vault-server`, not the `@redact-secret/vault` API; Python has no separate authority-free portable vault, so its name carries no `-server` suffix. Python, Rust, and Go need their own native distribution or a separately qualified service boundary; no JavaScript dependency is imposed on them. See [package decision](docs/decisions/name-vault-packages-and-language-contract.md).

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

The proposed portable default is short-lived in-runtime memory with explicit limits. In a browser, the same-page scripts share that trust boundary; encryption with a key available to the page does not protect against compromised page code. In a server, memory belongs to the process and still requires application authorization before any external destination receives a value. Neither environment can promise that all managed-runtime copies have been erased. A consumer-provided store must preserve session and tenant binding, expiry, atomic revocation semantics, and non-leaking failure behavior. If persistent storage is supported, encryption, key ownership, rotation, backup retention, and access auditing need separate qualification. The library must not force one vendor's vault or the consumer's identity provider.

The package enforces invariant checks but cannot authenticate a principal on behalf of an application. The consumer supplies authentication, authorization policy, destination identity, and permitted purpose. Authorization is re-evaluated at restore time; an earlier grant does not override later revocation. The [server authority interface](docs/decisions/define-server-authority-interface.md) fixes this paragraph's principal resolution, decision tuple, denial vocabulary, and audit shape as a reference contract. [`@redact-secret/vault-server`](packages/vault-server/README.md) implements it with an in-memory backend built on `@redact-secret/vault` ([implementation decision](docs/decisions/implement-vault-server-in-memory.md)). The [persistent store contract](docs/decisions/define-persistent-store-contract.md) likewise fixes this paragraph's atomic eligibility/consume/revoke behavior, logical TTL, tenant isolation, AEAD encryption bound to record metadata, consumer-owned key injection and rotation, and backup/deletion semantics as a reference contract; it defines no backend and mandates no vendor, and no package implements it yet (#19). Its store interface, key-provider shape, per-entry atomicity, plaintext replay, and deletion promise are superseded by the [ciphertext-only store decision](docs/decisions/supersede-persistent-store-contract.md) and the [persistent vault specification](docs/specs/persistent-vault.md) (**proposed**, [#104](https://github.com/redact-secret/redact-secret-vault/issues/104)): the server authorizes, a crypto layer encrypts, a key provider wraps data keys, and a store holds ciphertext and performs conditional transactions.

No raw mapping, value, restore result, or payload-bearing exception may be sent to logs, traces, analytics, serialized session state, model context, or public errors. Audit hooks expose only bounded safe metadata and outcome codes. Avoid claiming universal leak prevention: application code can deliberately forward a restored value, and the documented integration boundary must make that responsibility clear.

## Release and language strategy

This repository versions independently from the core and adapters. Each language distribution declares and tests its supported core range and runtime matrix. JavaScript browser and Node.js are intended early vault targets; JavaScript and Python are intended early server targets. Rust and Go integrations are separately qualified as core support permits, without reimplementing detection. Shared conformance cases protect the language-neutral security contract without requiring lockstep releases. CLI restoration remains a separate threat-model decision.

## Required qualification before an API is declared supported

- Correct range extraction, Unicode behavior, repeated values, literal token collisions, and deterministic output under the chosen contract.
- Rejection of `block`, unknown, forged, expired, revoked, cross-session, and cross-tenant tokens.
- Authorization changes between redaction and restoration, destination changes, and replay attempts.
- Storage failure, partial write, concurrent restore/revoke, cancellation, and cleanup behavior.
- No plaintext in errors, diagnostic hooks, logging, OTel, snapshots, or published fixtures.
- Real-core integration at the declared dependency range endpoints.

See [Decisions](docs/decisions/README.md) for settled boundaries and open questions.
