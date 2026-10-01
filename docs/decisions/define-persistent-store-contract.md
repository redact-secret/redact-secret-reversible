---
decision_id: decision-define-persistent-store-contract
status: accepted
scope: repository
title: Define the persistent store, encryption, and key ownership contract
decided_at: 2026-09-27
---
# Define the persistent store, encryption, and key ownership contract

> **Partly superseded 2026-10-01** by [decision-supersede-persistent-store-contract](supersede-persistent-store-contract.md) ([#104](https://github.com/redact-secret/redact-secret-vault/issues/104)) and the [persistent vault specification](../specs/persistent-vault.md). Do not implement §1, §1.1, §4's AAD layout, §5's `KeyProvider`, §6's `purge` and backup-replay rule, or §7's plaintext replay: each of those sections carries a note naming its replacement. The record is kept as history.
>
> **Accepted 2026-09-27** for the interface contract only ([#19](https://github.com/redact-secret/redact-secret-vault/issues/19)). No `@redact-secret/store-*` package, backend, or vendor selection exists yet. [#20](https://github.com/redact-secret/redact-secret-vault/issues/20) selects and adversarially qualifies one concrete backend against this contract; it must pass its own conformance and qualification gates before claiming support, exactly as [#16](https://github.com/redact-secret/redact-secret-vault/issues/16) and [#17](https://github.com/redact-secret/redact-secret-vault/issues/17) must against the [server authority interface](define-server-authority-interface.md).

## Context

[decision-define-restore-transaction-boundary](define-restore-transaction-boundary.md) (#9/F4) fixes the in-memory vault's all-or-nothing preflight and linearization point, but explicitly defers "a qualified store must define one linearization point" and "persistent stores require encrypted/integrity-protected records and separately documented key ownership, backup retention, and deletion" to this issue. [decision-define-server-authority-interface](define-server-authority-interface.md) (#15/S1) defines the principal/tenant/purpose decision tuple, denial vocabulary, and audit shape that sits *above* storage, and states plainly that it "adds no new persistence requirement" and defers "storage" to this ADR unchanged.

This ADR is P1 on the (archived) [issue roadmap](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/plans/issue-roadmap.md). Gate P requires that persistence stay optional, never weaken server authority, and never claim that encryption-at-rest provides same-page XSS resistance. ARCHITECTURE.md's "Storage and authorization" section and the [threat model](../specs/threat-model.md)'s "Persistent mappings" row already name the required controls — authenticated encryption bound to tenant/session/entry metadata, consumer-owned keys, logical expiry and revocation at use time, a backend-specific linearization proof, and deletion/backup policy — without defining their shape. This ADR defines that shape as a reference contract, generalizing F4's linearization requirement and S1's decision tuple, so #20 (concrete backend selection and adversarial qualification) has one unambiguous starting contract instead of inventing its own.

None of this is exported by `@redact-secret/vault`, `@redact-secret/vault-server`, or any published package. It is reference material for #20 and any consumer-supplied store.

## Decision

### 1. Store interface — atomic eligibility check, consume, and revoke

> **Superseded.** A store never returns plaintext and never calls a key provider. See [specification §4 and §5](../specs/persistent-vault.md#4-contracts).

```ts
/**
 * The store's own opaque identifier for one retained value. Distinct from
 * the issued token text (`IssuedToken.token`) the vault hands to the
 * application — a store implementation must never require the plaintext
 * token as its lookup key, so a store dump cannot be used to enumerate or
 * guess live tokens.
 */
export type StoreEntryId = string;

/**
 * Metadata fixed at capture time, before any restore request exists.
 * Mirrors `ReleaseGrant` and `CaptureResult` (`packages/vault/src/types.ts`).
 * This is the tuple a compliant store binds into its AEAD associated data
 * (§2) — everything here is decided once, at write time, and never changes
 * for the life of the entry.
 */
export interface StoreEntryMetadata {
  readonly entryId: StoreEntryId;
  readonly captureId: string;
  /** Tenant that captured and owns this value. */
  readonly issuedTenant: string;
  /** The exact sink/path grants chosen at capture; never widened later. */
  readonly release: readonly { readonly sink: string; readonly paths: readonly string[] }[];
  /** Core finding type. Descriptive only, as elsewhere in this repository. */
  readonly type: string;
  readonly maxUses: number;
  /** Which key version encrypted this record (§3). Not secret. */
  readonly keyVersion: string;
  /** Record layout/AAD-construction version, for future migration. */
  readonly schemaVersion: string;
}

export interface StoreCheckInput {
  readonly entryId: StoreEntryId;
  readonly captureId: string;
  /** Resolved tenant of the requesting principal (`RestoreDecisionInput.tenant`, S1). */
  readonly tenant: string;
  readonly sink: string;
  readonly path: string;
  readonly requestedAt: number;
}

/**
 * `ServerDenialReason` is S1's reference type (never an importable module —
 * S1 itself is reference TypeScript only, like this ADR). Reused verbatim,
 * never redefined; a store adds only the store-specific reasons below.
 */
export type StoreDenialReason =
  | ServerDenialReason
  | "store-unavailable"       // transient infra failure; no state changed, safe to retry
  | "ambiguous-consume"       // could not confirm whether a prior consume committed (§5)
  | "key-unavailable"         // KMS/provider could not seal or open, including a retired version
  | "integrity-failure"       // AEAD authentication failed: tampered, substituted, or wrong-AAD ciphertext
  | "replica-read-rejected";  // the store refused to answer from a replica that cannot prove it observed the linearization point (§4, scenario 1)

export type StoreCheckResult =
  | { readonly eligible: true }
  | { readonly eligible: false; readonly reason: StoreDenialReason };

export interface StoreConsumeInput extends StoreCheckInput {
  /**
   * Caller-supplied idempotency key, unique per restore attempt (for
   * example one per `RestoreRequest`). Required. The store uses it to
   * answer "did my own earlier call already commit?" without re-running
   * the consume, which is what makes response-loss retries safe (§5).
   */
  readonly idempotencyKey: string;
}

export type StoreConsumeResult =
  | { readonly consumed: true; readonly plaintext: Uint8Array; readonly keyVersion: string }
  | { readonly consumed: false; readonly reason: StoreDenialReason };

export interface Store {
  /**
   * Read-only preflight check for one entry/path, with no side effect and
   * no budget change. A server authority layer calls this once per
   * occurrence per path during S1's preflight (before any
   * `ServerReleasePolicy` runs), exactly as the in-memory vault's own
   * preflight checks `source`/`expired`/`sink-or-path`/`budget` before any
   * plaintext is touched.
   */
  checkEligibility(input: StoreCheckInput): Promise<StoreCheckResult>;

  /**
   * The one storage operation that may return plaintext. Must be atomic
   * per §1.1 below. Idempotent for a repeated call with the same
   * `idempotencyKey` against the same `entryId`.
   */
  consume(input: StoreConsumeInput): Promise<StoreConsumeResult>;

  /** Revokes every unconsumed entry of one capture. Returns the count removed. */
  revoke(captureId: string): Promise<number>;

  /**
   * Consumer-driven purge (for example a deletion request). See §4
   * (backup and deletion). Resolves once no key this backend controls can
   * ever decrypt the named entries again — not necessarily once every
   * physical byte is gone.
   */
  purge(input: { readonly tenant: string; readonly entryId?: StoreEntryId; readonly captureId?: string }): Promise<void>;
}
```

#### 1.1 What "atomic" means here

> **Superseded.** Atomicity is per restore request and per capture, not per entry. See [specification §7.1](../specs/persistent-vault.md#71-linearization).

"Atomic" is the same guarantee F4 already defines for the in-memory vault, restated for a store that may be distributed, replicated, or crash independently of the calling process:

- **One linearization point per entry.** Each entry's lifecycle (`unconsumed → consumed`, `unconsumed → revoked`) transitions at exactly one storage-level operation — a conditional write (compare-and-swap on a state/version column, or an equivalent serializable transaction) keyed on `entryId`. No other operation may observe or act on a state between "check passed" and "state transitioned."
- **No partial application under concurrent access.** For an entry with `maxUses = N`, at most `N` `consume` calls may ever observe `{consumed: true}`; every call beyond that observes `{consumed: false, reason: "budget"}`. A `consume` and a `revoke` racing on the same entry: whichever's conditional write lands first at the store wins — a `revoke` that commits before a `consume`'s linearization point makes that `consume` fail (`"revoked"` or `"unknown-token"`, per S1 §4); a `revoke` that arrives after `consume` already committed removes nothing for that entry and cannot retract an already-returned value, matching F4's "a later revoke cannot undo an already released value."
- **No partial application under crash.** If the process, the store node, or the network fails *before* the conditional write commits, the entry's state is unchanged and a retry with the same `idempotencyKey` is safe. If a failure happens *after* the conditional write commits but before the caller observes the result, the entry is durably consumed regardless of what the caller believes happened — see §5's `"ambiguous-consume"` handling. There is no state in which the write "half happened": either the conditional write's precondition held and its effect is fully visible to every subsequent reader, or it did not hold and nothing changed.
- **This is a linearizability requirement on `entryId`-scoped state, not a claim about the whole store.** It says nothing about cross-entry transactions, backend throughput, or replication topology; those are backend-specific and remain #20's qualification burden, per F4's "a multi-process deployment needs a shared mechanism or an explicitly limited single-process qualification."

### 2. Logical TTL — distinct from any backend's native TTL

> **Refined.** Native TTL remains cleanup only. Expiry is an authenticated field judged at commit on the store's clock. See [specification §7.5](../specs/persistent-vault.md#75-time).

A store's `logicalExpiresAt` (carried in `StoreEntryMetadata` at write time, derived from the vault's `entryTtlMs`) is the *only* deadline `checkEligibility` and `consume` may honor. It is computed and checked against the store's own trusted clock at request time — never a client-supplied timestamp — exactly as the in-memory vault's expiry check works today (F4, "Resolved choices"). A backend's own native expiry mechanism (Redis `EXPIRE`, DynamoDB TTL, a Postgres row plus a reaper job, ...) is a **storage-reclamation optimization**, not a security boundary:

- A backend MAY set its native TTL later than `logicalExpiresAt` (recommended, with a documented margin) so ciphertext remains physically present for `purge`/crypto-shredding to act on deliberately rather than being silently reclaimed first.
- A backend MUST NOT rely on native TTL as the sole expiry enforcement: `checkEligibility`/`consume` must independently deny (`"expired"`, reusing `DenialReason`) once past `logicalExpiresAt`, even if the backend's own reclamation has not yet run.
- A backend whose native TTL fires *before* `logicalExpiresAt` fails closed (the entry becomes unavailable early) rather than unsafe — availability loss, never an authorization bypass — but must be documented as a limitation, since it silently shortens the vault's stated TTL.

### 3. Tenant isolation

> **Refined.** The store scopes rows; the server, not the store, builds the associated data from trusted scope. See [specification §3.4](../specs/persistent-vault.md#34-associated-data).

Every stored entry is partitioned by `issuedTenant`, and every `checkEligibility`/`consume`/`revoke`/`purge` call is scoped to a `tenant` argument. A compliant store enforces isolation at two independent layers, not one:

1. **Storage layout.** `issuedTenant` is part of the entry's physical key/partition, so a query scoped to one tenant cannot structurally return another tenant's rows.
2. **Cryptographic binding.** `issuedTenant` is part of the AEAD associated data (§4), so even a storage-layer bug, misconfiguration, or an attacker with read access to the raw table who manages to associate the wrong tenant's row with a ciphertext gets an authentication failure on decrypt, not another tenant's plaintext (§4, adversarial scenario 2).

`tenant-mismatch` at the store layer is deliberately redundant with S1's `ServerReleasePolicy` tenant check — a store must not assume the layer above it always gets this right.

### 4. Encryption contract — AEAD with metadata bound into AAD

> **Superseded** for the AAD layout, the cipher choice, and which metadata is left unencrypted. See [specification §3](../specs/persistent-vault.md#3-record-format-version-1).

Every retained value is sealed with authenticated encryption with associated data (AEAD: any cipher construction offering both confidentiality and integrity/authenticity over the ciphertext, with additional authenticated data that is verified but not encrypted — for example AES-256-GCM per [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), or XChaCha20-Poly1305). This ADR does not mandate a specific cipher or library, per Gate P and the [package/language decision](name-vault-packages-and-language-contract.md)'s "must not force one vendor's vault or the consumer's identity provider" — it requires the AEAD *property*, backed by [OWASP's cryptographic storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html):

- A unique nonce per encryption operation under a given key; nonce reuse under the same key is never acceptable and is a store implementation's own qualification burden (#20).
- The authentication tag is verified before any plaintext is returned from `consume`. A failed verification is `"integrity-failure"`, never a partial or "best-effort" plaintext.

**What is bound into AAD.** A canonical, deterministic encoding of the fields in `StoreEntryMetadata` that are fixed at capture/write time:

```text
AAD = schemaVersion || entryId || captureId || issuedTenant || releaseDigest || type || keyVersion
```

where `releaseDigest` is a stable digest of the sorted `(sink, path)` grant pairs. Binding this tuple means a ciphertext decrypted with metadata that does not match exactly what it was sealed under — a different `entryId`, a different `issuedTenant`, a widened or substituted `release` set, or a different `keyVersion` claim — fails authentication and is refused, closing the "record substitution/replay under different metadata" class the issue asks for (§ Adversarial scenarios, #2).

**`purpose` is deliberately excluded from AAD.** Unlike `tenant`, `sink`, and `path`, `purpose` (S1's `RestoreDecisionInput.purpose`) is not known at capture time — it is supplied per restore attempt and evaluated by `ServerReleasePolicy`. Binding a restore-time-only field into write-time ciphertext is not possible without re-encrypting per attempted purpose, which this contract does not require. Purpose enforcement remains entirely S1's job (`ServerReleasePolicy`, denial `"missing-purpose"`); the store's AEAD binding protects the capture-time facts, not the restore-time decision.

**What this does and does not protect against.**

- **Protects against:** a ciphertext (or its whole row) being moved, copied, or substituted to a different tenant's, entry's, or grant's context and successfully decrypting there; a backend or operator misconfiguration that associates the wrong metadata row with a ciphertext blob; tampering with ciphertext bytes in transit or at rest.
- **Does not protect against, and this ADR makes no claim otherwise:**
  - **Same-page XSS or compromised page scripts, per Gate P.** AEAD in a *server-side* store says nothing about browser-side trust boundaries. ARCHITECTURE.md's "encryption with a key available to the page does not protect against compromised page code" applies unchanged; this contract is for server-side persistence, not an in-page store.
  - **A currently-authorized, legitimately-decrypting process that misuses the plaintext it correctly obtained.** Encryption authenticates *data*, not caller *intent*; that remains S1's authorization boundary.
  - **Metadata confidentiality.** AAD is authenticated but not encrypted — `entryId`, `issuedTenant`, `sink`/`path`/`release` digest, `type`, and `keyVersion` are visible in plaintext to anyone with read access to the store, even without any key. A store must not claim these fields are protected at rest; only the retained *value* is encrypted.
  - **Traffic analysis, storage-size, or timing side channels.**
  - **Memory disclosure after decryption.** Once `consume` returns plaintext, the same caveats as the in-memory vault apply (no managed-runtime zeroization guarantee).

### 5. Key ownership — consumer-owned KMS, injection interface, and rotation

> **Superseded.** The key provider supplies and wraps data keys; it does not seal payloads. See [specification §6](../specs/persistent-vault.md#6-keys).

This repository does not implement, bundle, or depend on any KMS, HSM, or crypto library. A consumer supplies key material through one injection point:

```ts
export interface SealedRecord {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  /** The exact key version used. Stored alongside, not secret (§4). */
  readonly keyVersion: string;
}

/**
 * Consumer-owned key access. This repository never implements one; a
 * consumer wraps their own KMS/HSM/vault client (AWS KMS, GCP KMS,
 * HashiCorp Vault transit, an on-prem HSM, ...) behind this shape. No
 * vendor is mandated or assumed.
 */
export interface KeyProvider {
  /**
   * Encrypts under the provider's current preferred key version — never a
   * caller-chosen version, so nothing can force encryption under a
   * retired or weak key. Must throw/reject (fail closed) rather than
   * return a partial result if no current key is configured.
   */
  seal(plaintext: Uint8Array, aad: Uint8Array): Promise<SealedRecord>;

  /**
   * Decrypts under the *exact* `keyVersion` recorded with the ciphertext.
   * Must never guess, coerce, or silently fall back to a different
   * version. Rejects with `"key-unavailable"` if that version is unknown
   * or has been fully retired.
   */
  open(input: { readonly ciphertext: Uint8Array; readonly nonce: Uint8Array; readonly aad: Uint8Array; readonly keyVersion: string }): Promise<Uint8Array>;
}
```

**Rotation semantics — old-key-decrypt / new-key-encrypt overlap window.**

- `seal` always uses the provider's current version; `open` accepts any version the provider still keeps in its decrypt window. This is the standard asymmetric envelope-rotation shape: write-one-version, read-many-versions.
- Every record's `keyVersion` (§1) is how a record signals which key encrypted it — read at `consume` time and passed back into `KeyProvider.open` verbatim; the store never infers or defaults a version.
- Rotating to a new version does not require touching existing records. An operator marks the old version **decrypt-only** (no new `seal` calls may select it) for a grace period the operator sets to at least the maximum configured `entryTtlMs`/`logicalExpiresAt`, so every record still live when rotation began remains decryptable until it is naturally consumed, revoked, or expires.
- Only after every record encrypted under a version has passed its `logicalExpiresAt` (or been consumed/revoked/purged) may that version be destroyed. Destroying a version while live records still reference it makes those records permanently unrecoverable — a residual risk an operator accepts explicitly, not a state this contract can prevent by construction (see §7, adversarial scenario 4).
- A version's retirement is the KMS/`KeyProvider`'s decision, not the store's; the store only ever asks for "current" (`seal`) or "this exact recorded version" (`open`) and treats a rejection from either as `"key-unavailable"`.

### 6. Backup and deletion

> **Superseded.** A store cannot promise key destruction, and backup replay is handled by a recovery epoch and quarantine. See [specification §9](../specs/persistent-vault.md#9-revoke-deletion-key-retirement-erasure).

- **Logical deletion is immediate and independent of physical byte removal.** `revoke` and `purge` make an entry unreadable through the store's own API (`checkEligibility`/`consume` return denial) at their linearization point, regardless of when or whether the underlying ciphertext bytes are actually erased from disk, replicas, or backups.
- **Crypto-shredding is an acceptable deletion mechanism** for `purge`, provided the backend can destroy/retire the specific key version(s) that could ever decrypt the named entries *without* also destroying still-needed keys for unrelated live entries (granular enough key scoping — for example per-tenant or per-rotation-epoch keys, never one permanent key for an entire store), and the backend documents and tests that no other key it retains can decrypt that ciphertext afterward.
- **A backend that cannot do granular crypto-shredding must guarantee physical deletion instead** — including from backups, or backups must themselves expire no later than `logicalExpiresAt` plus a documented, bounded grace period — before it may claim compliant deletion.
- **Backups must never retain plaintext.** No backup format, snapshot, replication stream, or "for QA/debugging" export may contain a decrypted value; only ciphertext (and its AAD-visible metadata, per §4) may appear in a backup.
- **Backup replay is a named residual risk, not a claim this contract resolves.** Restoring an old backup can reintroduce a ciphertext row for an entry that was later consumed, revoked, or purged in the live store. A compliant `Store` must not let a restored-from-backup entry be re-`consume`d as if it were still live — for example by tracking a monotonic revocation/consumption record independent of the value row, or by treating backup restoration as an operational event that requires re-establishing eligibility before use is permitted again. #20 must test this explicitly for its chosen backend; this ADR only states the requirement.
- **Deletion completion means cryptographic unrecoverability, not necessarily byte-level absence.** A consumer-facing deletion/erasure guarantee is satisfied once no key under this backend's control can ever decrypt the entry again, even if ciphertext bytes persist in a backup until that backup's own natural expiry.

### 7. Error handling and failure behavior — fail closed on ambiguous state

> **Superseded** for idempotent plaintext replay and `"ambiguous-consume"`. Receipts never replay plaintext. See [specification §7.3](../specs/persistent-vault.md#73-attempts-and-failure-outcomes).

The controlling invariant, stated exactly as the issue requires: **a store must never both release a secret and leave it consumable again.** Concretely:

- Every operation that cannot definitively determine its outcome — timeout, partial write acknowledgment, network partition mid-call, a KMS that is unreachable, a replica that cannot prove it has observed the current linearization point — returns a denial (`StoreDenialReason`) or rejects. There is no "assume success" or "assume failure" default; ambiguity is always resolved toward denial, never toward release.
- **`consume` is idempotent on `idempotencyKey`, which is how ambiguity gets resolved safely instead of just conservatively.** If a caller's earlier `consume` call committed the conditional write but the caller never received the response (network failure, process crash, timeout), a retry with the *same* `idempotencyKey` against the *same* `entryId` must return the store's recorded result for that exact attempt (replaying `{consumed: true, plaintext, keyVersion}` if it already committed, since the vault's own model already accepts that a lost response still consumes the use — F4, "Response loss") — **not** re-run the consume as if it were new, and **not** report `{consumed: false, reason: "budget"}` as though nothing happened while secretly still holding the entry's one use.
- **If the store genuinely cannot tell** whether its own earlier attempt with that `idempotencyKey` committed (for example its own idempotency-record write is itself unconfirmed), it MUST treat the entry as consumed/unavailable going forward — `"ambiguous-consume"` — rather than as available for a fresh consume. An over-cautious denial (the secret becomes permanently unavailable; the application can ask its source to re-capture if it still holds the original input, per F4's alternative) is the only acceptable failure direction. A second, independent successful consume of the same one-time entry is not.
- No operation ever returns a partial result across multiple requested entries/paths, mirroring F4's whole-request preflight: a store-layer implementation backing a multi-entry restore must still let the layer above it (S1's server authority) enforce "one denial fails the complete request."
- Exceptions raised by a consumer-supplied `KeyProvider` are treated exactly like a denial from the store itself — never surfaced as plaintext, never treated as an implicit allow.

## Adversarial scenarios (synthetic, illustrative — not implemented here)

These are the scenario shapes #20 must build executable, backend-specific tests for; none of the following is executed by this ADR.

1. **Replica lag serving a stale eligibility check.** A `checkEligibility`/`consume` call is served by a read replica that has not yet applied a just-committed `revoke` (or a just-committed `consume` that exhausted budget). Required behavior: the store either routes `consume`'s linearization-point operation only to a node that can prove it holds the current, authoritative state (for example the write leader, or a quorum read), or, if it cannot prove that, refuses with `"replica-read-rejected"` rather than answering from a replica that might be behind. `checkEligibility` alone (no side effect) may be served by a lagging replica only if the backend documents the resulting staleness window as a limitation; `consume` may never rely on a replica it cannot prove is current, because a stale-eligible answer there would let a revoked or already-exhausted entry be consumed again.
2. **Encrypted-record substitution/swap across tenants.** An attacker with read/write access to the raw storage layer (but not the `KeyProvider`) swaps which ciphertext blob is associated with which tenant's row — for example copying `tenant-acme-synthetic`'s ciphertext under a row now labeled `tenant-northwind-synthetic`. Required behavior: `consume` for the swapped row calls `KeyProvider.open` with `tenant-northwind-synthetic` (and the rest of that row's metadata) in the AAD; because the ciphertext was sealed under `tenant-acme-synthetic`'s original AAD, authentication fails, and the store returns `"integrity-failure"` — never `tenant-acme-synthetic`'s plaintext under `tenant-northwind-synthetic`'s identity.
3. **Crash mid-consume.** The process executing `consume` crashes after the conditional write commits (entry now durably `consumed`) but before it returns `{consumed: true, plaintext, keyVersion}` to its caller. Required behavior: per §7, a retry with the same `idempotencyKey` must not re-consume a second use; if the store can still resolve that this exact `idempotencyKey` already committed, it replays the same result (the application may still receive the value exactly once, on retry); if it cannot resolve that, it returns `"ambiguous-consume"` and the entry stays permanently unavailable rather than being offered again as `budget`-available. Either outcome is acceptable; a fresh, unrelated `consume` succeeding on the same entry after this crash is not.
4. **Key rotation race.** A `consume` call is mid-flight — it has already read a record's `keyVersion` (say, `v3`) — at the moment an operator retires `v3` because rotation to `v4` was believed complete. Required behavior: per §5, retirement must only happen after every `v3`-encrypted record has passed `logicalExpiresAt` or been consumed/revoked/purged; a live, still-unconsumed record referencing `v3` at retirement time means the grace-period requirement was violated by the operator, not a store-contract failure — the record becomes permanently unrecoverable (`"key-unavailable"`), which is the documented residual risk of premature retirement, not a silent wrong-key decrypt. A store implementation itself must never attempt to decrypt under any version other than the one the record names.

## Non-goals

Explicitly **not** covered by this ADR, matching Gate P and mirroring S1's own "out of scope":

- **No vendor or backend choice.** This ADR names no database, KMS, or cloud provider. #20 selects one and documents its specific guarantees and limits against this contract.
- **No concrete `@redact-secret/store-*` implementation, wire format, or SDK.** #20's responsibility entirely.
- **No claim that encryption-at-rest provides same-page XSS resistance**, per Gate P and §4's explicit disclaimer. This contract is a server-side persistence contract; it says nothing about a page's DOM/script trust boundary, which ARCHITECTURE.md and the [threat model](../specs/threat-model.md) already cover separately.
- **No weakening of S1's server authority.** This ADR adds a storage layer *beneath* `ServerReleasePolicy`, never a bypass of it; `purpose`, principal resolution, and policy evaluation remain entirely S1's contract (§4). A store denial and a policy denial are both denials; neither can override the other into an allow.
- **No specific AEAD cipher, KMS API, or cryptographic library mandate.** §4 and §5 state required properties, not a specific primitive or vendor call.
- **No cross-process/distributed consensus algorithm.** §1.1's atomicity requirement is a specification a backend must prove, not a protocol this ADR designs.
- **No arbitrary-text restore, streaming, or Worker-mode persistence.** Unchanged from the existing [threat model](../specs/threat-model.md)'s open items.

## Threat boundary, failure behavior, and residual risk

- **Threat boundary added over F4's single-process in-memory vault and S1's authority interface:** storage-layer disclosure (an attacker who can read raw rows but not decrypt), ciphertext substitution/replay across tenants or records, key compromise or premature retirement, backup/replica staleness, and a store operation whose outcome the calling process cannot confirm.
- **Failure behavior:** every store operation (`checkEligibility`, `consume`, `revoke`, `purge`, `KeyProvider.seal`/`open`) fails closed. Ambiguity about whether a `consume` committed is resolved toward "treat as consumed," never toward "treat as still available" (§7). A `KeyProvider` exception is a denial, never an implicit allow or a fallback to a different key.
- **Residual risk:** this interface cannot verify that a consumer's `KeyProvider` is actually backed by a sound KMS, that key destruction is truly irreversible, that a backend's claimed linearizability holds under its real deployment topology, or that its backup pipeline actually excludes plaintext — those remain #20's (backend selection) and the deploying application's responsibility, qualified independently with adversarial tests, exactly as S1 states for `PrincipalResolver` and `ServerReleasePolicy`. A backend that always answers `{eligible: true}`/`{consumed: true}` is indistinguishable from a correct one at the type level; only #20's adversarial corpus can catch it. Backup replay (§6) and premature key retirement (§7, scenario 4) are named, accepted residual risks of operator error that this contract cannot prevent by construction, only make detectable and attributable.

## Core compatibility

This ADR adds no dependency on `@redact-secret/core` and does not change the pinned `0.1.0-beta.9` compatibility declared in the [qualification record](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/qualification-0.1.0-alpha.1.md). It operates entirely downstream of vault-issued entries and the S1 decision tuple; the core's detection, policy, and placeholder-formatting surface is unaffected. The one-way dependency direction is preserved: this ADR is consumed by `redact-secret-reversible` packages only; the core, adapters, and detection benchmarks acquire no dependency on it.

## Consequences

- #20 selects one concrete backend, implements `Store` and `KeyProvider` (or documents how its chosen KMS satisfies `KeyProvider`) against this contract, and adversarially tests the four scenario classes in this ADR plus F4's existing concurrency/crash/replica-lag list, publishing the backend's specific guarantees and limitations rather than inheriting this contract's claims by assertion.
- A future conformance corpus version adds the persistent-store-only case classes this ADR names — crash-mid-consume, replica-lag eligibility, cross-tenant record substitution, key-rotation race, backup replay, and ambiguous-consume resolution — for #20 to implement as executable cases, the same way S1 named server-only classes for #16/#17.
- `docs/specs/threat-model.md`'s "Persistent mappings" row and `conformance/README.md`'s persistent-store-classes note are updated alongside this ADR to point here instead of describing the requirement only in prose.

## Alternatives considered

- **Mandating a specific AEAD cipher or KMS vendor in the interface:** rejected, per Gate P ("do not impose a vendor") and the same reasoning S1 used to reject mandating an identity provider or policy engine — this repository does not own a consumer's cryptography or infrastructure stack.
- **Binding `purpose` into AAD alongside tenant/sink/path:** considered, since the issue names it explicitly as "whatever's relevant from the S1 decision tuple." Rejected because `purpose` is not fixed at write time (§4) — binding it would require sealing a value once per possible future purpose, which is not a write-time property a store can know. Purpose remains S1's restore-time check instead.
- **Treating native backend TTL as sufficient expiry enforcement:** rejected; F4 already establishes TTL as a use-time validation condition, and a backend's own reclamation timing is not trustworthy as a security boundary (§2).
- **Best-effort/at-least-once consume semantics with idempotency left to the application:** rejected. Pushing ambiguity resolution to the consumer would let two different application-level retries both believe they "won" a one-time secret; the store must own idempotency (§7) because it is the only party that can see the actual committed state.
- **Requiring physical deletion (never crypto-shredding) for `purge`:** rejected as the sole option; granular crypto-shredding is an accepted, common pattern (see [OWASP key management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)) that a backend may offer instead, provided it can prove it, per §6.

## Open questions

- The exact backend-specific mechanism that proves "this replica can answer for the current linearization point" (§7, scenario 1) — quorum reads, leader-only routing, bounded-staleness proofs — is left entirely to #20's backend choice.
- Whether a future corpus version needs a machine-checkable idempotency-key format/TTL of its own, or whether that stays an implementation detail of #20's chosen backend.
- Whether `purge`'s cross-tenant/cross-entry batching semantics (for example a tenant-wide erasure request spanning many captures) need their own atomicity contract beyond "each named entry individually satisfies §6," left for #20 to propose once a concrete backend and consumer erasure-request shape exist.
