# Architecture

## Status and intent

This is a design contract for an unimplemented, optional restoration product. It records where plaintext is permitted, which repository owns each behavior, and what must be verified before publishing. Concrete interfaces and storage backends remain open.

## Trust boundaries

```text
Untrusted input
    |
    v
Redact Secret public scan/policy/range API
    |
    +--> ordinary core redaction --> safe text + safe metadata
    |
    +--> explicit reversible session (opt-in, trusted process)
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

1. A trusted caller creates a session with explicit identity/tenant context, bounds, and an authorization policy.
2. The session asks the core to inspect input under the application's policy. Only eligible finalized ranges may be captured. A `block` outcome fails the relevant operation rather than entering the mapping.
3. For each retained occurrence, the session issues a collision-resistant, session-bound token and records a mapping with bounded lifetime and size. Visible type information is descriptive only.
4. The caller sends only sanitized text across the intended boundary. The store and session handle remain in the trusted environment.
5. At restore time, the trusted application names the principal, purpose, destination, and target operation. The product checks current authorization, session/tenant binding, expiry/revocation, and the exact issued token before retrieval.
6. The caller sends the restored value only to its approved destination. Abort, expiry, revoke, and completion invalidate the mapping according to the documented store contract.

An LLM response or tool argument is untrusted input to step 5. It may carry a token but cannot supply an authoritative grant. The application must decide whether and where restoration is permitted. A constrained structured-field operation can be the safe default; an advanced arbitrary-text operation may be provided only with the same mandatory authorization checks.

Whole-input capture should be designed first. Streaming introduces unresolved ranges, partial output, cancellation, and late `block` findings; it must have a separate contract before support is claimed.

## Placeholder identity

`<SECRET_1>` and core typed labels such as `<JWT_1>` are deterministic display placeholders. They are not capabilities and cannot safely serve as the sole lookup key. A reversible token requires unpredictable, session-bound identity; token syntax, collision handling, escaping, and behavior when an identical literal already exists in input or output need a decision and tests. The token's type label, if any, must not be trusted to classify the underlying value.

## Storage and authorization

The first proposed implementation is short-lived in-process memory with explicit limits. This is a proposal, not a guarantee that process memory can be securely erased. A consumer-provided store must preserve session and tenant binding, expiry, atomic revocation semantics, and non-leaking failure behavior. If persistent storage is supported, encryption, key ownership, rotation, backup retention, and access auditing need separate qualification. The library must not force one vendor's vault or the consumer's identity provider.

The package enforces invariant checks but cannot authenticate a principal on behalf of an application. The consumer supplies authentication, authorization policy, destination identity, and permitted purpose. Authorization is re-evaluated at restore time; an earlier grant does not override later revocation.

No raw mapping, value, restore result, or payload-bearing exception may be sent to logs, traces, analytics, serialized session state, model context, or public errors. Audit hooks expose only bounded safe metadata and outcome codes. Avoid claiming universal leak prevention: application code can deliberately forward a restored value, and the documented integration boundary must make that responsibility clear.

## Release and language strategy

This repository versions independently from the core and adapters. A future package declares and tests a supported range of core versions, including range endpoints. Node.js is the proposed first surface. A language-neutral security contract can later drive Python or Rust implementations with shared adversarial cases; it does not require lockstep artifacts. Browser and CLI restoration require their own threat models.

## Required qualification before an API is declared supported

- Correct range extraction, Unicode behavior, repeated values, literal token collisions, and deterministic output under the chosen contract.
- Rejection of `block`, unknown, forged, expired, revoked, cross-session, and cross-tenant tokens.
- Authorization changes between redaction and restoration, destination changes, and replay attempts.
- Storage failure, partial write, concurrent restore/revoke, cancellation, and cleanup behavior.
- No plaintext in errors, diagnostic hooks, logging, OTel, snapshots, or published fixtures.
- Real-core integration at the declared dependency range endpoints.

See [Decisions](docs/decisions/README.md) for settled boundaries and open questions.
