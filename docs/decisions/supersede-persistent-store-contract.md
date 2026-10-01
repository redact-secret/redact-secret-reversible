---
decision_id: decision-supersede-persistent-store-contract
status: accepted
scope: repository
title: Supersede the persistent store contract with ciphertext-only stores and independent key providers
decided_at: 2026-10-01
supersedes: decision-define-persistent-store-contract (sections listed below)
---
# Supersede the persistent store contract with ciphertext-only stores and independent key providers

> **Accepted 2026-10-01** as a design, after an [independent review](../research/persistent-vault-design-review.md), for [#104](https://github.com/redact-secret/redact-secret-vault/issues/104), [#105](https://github.com/redact-secret/redact-secret-vault/issues/105), and [#107](https://github.com/redact-secret/redact-secret-vault/issues/107), under epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4). The interfaces, bytes, and semantics are in the [persistent vault specification](../specs/persistent-vault.md). This record states what was decided, what it replaces, and why. It is a design decision; no package implements it yet, and the specification stays **proposed** until packages are qualified against it.

## Context

[decision-define-persistent-store-contract](define-persistent-store-contract.md) (#19) was accepted as a contract with no implementation. Reviewing it before implementation found five requirements that cannot hold together with a storage adapter that only stores:

1. `Store.consume` returns plaintext, so the adapter decrypts and the store boundary handles retained values.
2. The store calls `KeyProvider.seal` and `open`, so the adapter owns encryption and the key provider encrypts whole payloads.
3. Atomicity is defined per entry, while a restore must be all-or-nothing across every entry and field of a request.
4. A retry with the same idempotency key replays the plaintext.
5. `Store.purge` resolves "once no key this backend controls can ever decrypt" the entries, a promise about keys that a database adapter cannot keep.

The core repository's coordination issue ([redact-secret#1002](https://github.com/redact-secret/redact-secret/issues/1002)) assigns the detailed store, crypto, and key-provider contracts to this repository and requires that stores hold ciphertext only.

## Superseded sections

The earlier record stays in the repository as history. These parts of it are replaced and must not be implemented:

| Section of the earlier record | Replaced by |
| --- | --- |
| §1 `Store` interface (`checkEligibility`, `consume` returning plaintext, `revoke`, `purge`) | Specification §4 and §5: a ciphertext-only `Store` with atomic whole-capture creation and whole-request commit |
| §1.1 per-entry linearization | Specification §7.1: one transaction per restore request, one per revocation |
| §2 logical TTL checked by the store against `logicalExpiresAt` it carries | Specification §7.5: authenticated `expiresAt`, judged at commit on the store's clock, with a skew bound |
| §3 tenant isolation, "cryptographic binding" by the store | Specification §3.4: the server builds the AAD from trusted scope; the store only scopes rows |
| §4 AAD layout (`schemaVersion || entryId || captureId || issuedTenant || releaseDigest || type || keyVersion`) and "AAD is authenticated but not encrypted" metadata | Specification §3.3 to §3.5: AES-256-GCM is fixed; grants, type, and policy revision are encrypted; key identity is not in the AAD |
| §5 `KeyProvider.seal` / `open` and `SealedRecord` | Specification §6: data-key generation, unwrapping, and re-wrapping; payload encryption in the crypto layer |
| §6 `purge`, crypto-shredding as a store operation, "deletion completion means cryptographic unrecoverability" as a store guarantee | Specification §9: revoke, ciphertext deletion, key retirement, and verified erasure are separate, and a store promises only the first two |
| §6 backup replay "a compliant Store must not let a restored-from-backup entry be re-consumed" | Specification §9.3: recovery epoch held outside the database, quarantine, invalidation |
| §7 idempotent `consume` replaying `{consumed: true, plaintext}` and `"ambiguous-consume"` | Specification §7.3: receipts deduplicate the state change and never replay plaintext; an ambiguous commit is resolved by an authoritative receipt read |

Still in force from the earlier record: that persistence is optional and sits beneath server authority; that no vendor is mandated; that native backend TTL is cleanup and not authorization; that every failure is a denial; and its non-goals (no browser persistence, no streaming, no claim about same-page script resistance).

## Decision

### Ownership

The server authorizes and orchestrates. The crypto layer encodes and encrypts. The key provider supplies and wraps data keys. The store performs ciphertext I/O and conditional transactional state changes. The specification's §2 table is the boundary; each row also lists what that component never does.

A store interface never accepts or returns a retained value or a raw key. A key provider never sees a payload. A remote service that encrypts whole payloads is a `RecordCrypto` implementation with its own qualification, not a `KeyProvider`.

### Packages and exports

| Package | Entry points | Runtime dependencies |
| --- | --- | --- |
| `@redact-secret/vault` (existing) | `.`, `./worker`, `./worker/host`, and new `./internal/capture-plan` (`node` condition only) | Core peer only |
| `@redact-secret/vault-server` (existing) | `.` (unchanged) and new `./persistent` | `@redact-secret/vault`, `@redact-secret/vault-contracts` |
| `@redact-secret/vault-contracts` (new) | `.` | None |
| `@redact-secret/vault-crypto` (new) | `.` and `./local-key-provider` | `@redact-secret/vault-contracts` |
| `@redact-secret/vault-conformance` (new) | `.` (store and key-provider harnesses, fault injection, vectors) | `@redact-secret/vault-contracts` |
| `@redact-secret/store-memory` (new) | `.` | `@redact-secret/vault-contracts` |
| `@redact-secret/store-postgres` (new, #20) | `.` | `@redact-secret/vault-contracts`; peer `pg` |
| `@redact-secret/key-provider-aws-kms` (new, #113) | `.` | `@redact-secret/vault-contracts`; peer `@aws-sdk/client-kms` |

The local key provider is an entry point of `vault-crypto`, not a package of its own: it needs the same primitives and no dependency, and one fewer package is one fewer release to qualify. Packages are created when their issue is implemented, not in advance.

### Record and crypto profile

AES-256-GCM through platform WebCrypto, random 96-bit nonce, full tag. One data key per capture from the key provider; each entry is encrypted under its own key derived from it with HKDF-SHA-256, and an entry key encrypts one message. Canonical length-prefixed binary encoding with versions for the format, the AAD, the payload, and the identifier derivations. Shared deterministic vectors bind every implementation, in any language, to the same bytes.

### Lifecycle and failure semantics

Whole-capture creation is one create-if-absent transaction. Whole-request consumption is one conditional transaction that checks revisions, budgets, expiry, capture generation, the recovery epoch, and the attempt receipt, and is the linearization point. It must conflict with a concurrent revocation of any capture it names (specification §5.2); checking the capture without that conflict is not enough. Revocation is a durable fence in the same order. Release is at most once: no plaintext is returned before a definitive commit, a receipt never authorizes sending it again, and an unknown commit outcome denies. Exactly-once delivery is not claimed.

### Keys

The application constructs the provider with explicit material or an explicit client and an explicit scope. No default key, no environment discovery, no passphrase default, no fallback. Rotation, re-wrap, re-encryption, retirement, caching, and memory limits are in specification §6.

## Choices made here that the issues left open

- **`entryId` is an unkeyed SHA-256 of namespace, tenant, and token.** Issue #107 requires the lookup to be opaque and stable across restart, and to be separately versioned and rotated *if* keyed. A token has 128 random bits, so an unkeyed digest is not invertible or enumerable; a keyed derivation would add a third key lifecycle, and with a key service it would add a network call per token. The derivation is versioned so it can change.
- **The request digest is keyed, with an explicit opt-out.** Issue #105 asks for a keyed digest. The persistent factory requires a digest key that is the same in every process; an application may pass `allowUnkeyedDigests` and accept that a party reading the store can test guesses of principal, sink, purpose, and session against what is stored.
- **One data key per capture, not per entry.** Issue #106 prefers per-entry keys. A per-entry key means one key-service call per value at capture and again at restore. A per-capture key with HKDF-derived entry keys keeps one message per key and makes the cost one call per capture. The capture is the unit of revocation and deletion in either design.
- **The session is stored only as a keyed tag.** The session identifier is bound through the associated data; the capture row keeps an HMAC tag of it under the digest key, so a wrong session is denied `source` before any key is unwrapped and lifecycle operations can check it.
- **Rotation in version 1 is a decrypt-only window.** With a 24-hour ceiling on any capture, keeping the old wrapping key decrypt-only for that long replaces re-wrapping. The compare-and-swap operation for re-wrap is in the store contract and tested, but nothing enumerates captures by key reference yet. Re-encryption under a new data key is not in version 1.
- **A lifecycle policy is required.** Capture, revoke, ciphertext deletion, and attempt resolution are denied unless the application's policy allows them. Stored volume has no quota in this version; the lifecycle policy is where an application limits capture rate.
- **Tenant comes only from the resolved principal in the persistent profile.** The in-memory server accepts an explicit `tenant` on a restore for support tooling. The persistent profile does not; a support flow resolves a principal of the target tenant.
- **A token under the wrong tenant is `unknown-token`, not `tenant-mismatch`.** Telling them apart would mean reading another tenant's rows.
- **Policy is evaluated before the commit, not inside it.** The store's transaction does not span the application's identity system. The remaining window and its two mitigations are in specification §7.4.
- **The capture plan is an internal module of `@redact-secret/vault`.** The alternatives were to copy the capture gate into `vault-server` (two implementations of eligibility) or to add a method that reads values out of a vault (a mapping export). The plan is a function of one input that returns the redacted text, the issued tokens, and the ranges they replaced. It returns no value and reads no vault; the caller slices the input it already holds.
- **Recovery uses an epoch in deployment configuration, stamped on every capture.** Raising it and invalidating makes every recovered capture unusable; version 1 has no way to return recovered captures to service. It makes the safe path explicit and testable without requiring every application to run an external ledger. It does not detect a rollback the operator does not know about, and the specification says so.

## Consequences

- #106, #108, #109, #20, #110, #111, and #113 implement against the specification, not against the earlier record.
- `docs/specs/threat-model.md`, `ARCHITECTURE.md`, `README.md`, and the decisions index point here for persistence.
- The conformance corpus gains a persistent section with wire vectors and lifecycle schedules.
- Python parity (#115) is defined against the same bytes and the same store semantics, and is a separate qualification.

## Alternatives considered

- **Keep the earlier interface and add a batch method.** Rejected: the adapter would still decrypt and still own key calls.
- **Encrypt in the database (for example `pgcrypto`) or rely on storage-level encryption.** Rejected: the database would see plaintext and keys, and metadata binding would depend on the backend.
- **Replay plaintext for a repeated attempt.** Rejected: it stores or re-derives released values for the receipt lifetime and turns a deduplication record into a second disclosure.
- **Two-phase reserve and confirm.** Rejected for the first scope: it adds a reserved state, a timeout that must release or burn budget, and a second ambiguous step, without removing the first.
- **Bind the key reference into the AAD.** Rejected: re-wrapping would then require re-encrypting every payload. Substitution is covered by the provider's context binding.
- **A deterministic or counter nonce coordinated across processes.** Rejected: one encryption per data key removes the need.

## Review

The [independent design review](../research/persistent-vault-design-review.md) found no critical defect and one high one (a restore commit that did not conflict with a concurrent revocation), which the specification now rules out. Thirty findings are listed there with their dispositions; one is partly declined and two are accepted as stated limits. A second pass on the revised text confirmed the fixes and raised ten further low findings, all applied.
