# Persistent vault specification

**Status:** implemented on `main` by unpublished alpha packages (`@redact-secret/vault-server/persistent` in `0.1.0-beta.4`; `vault-contracts`, `vault-crypto`, `vault-conformance`, `store-memory`, `store-postgres`, `store-sqlite`, and `key-provider-aws-kms` at `0.1.0-alpha.1`; `store-sqlite` has only a [partial record](../research/qualification-store-sqlite-0.1.0-alpha.1.md)). It is **current** only for the profiles the [qualification record](../research/qualification-persistence-0.1.0-alpha.1.md) names; for every other backend, topology, runtime, key provider, and language it remains a design and is not a support claim. A profile is supported only when a qualification record says so. This is the design frozen by [decision-supersede-persistent-store-contract](../decisions/supersede-persistent-store-contract.md) for [#104](https://github.com/redact-secret/redact-secret-vault/issues/104), [#105](https://github.com/redact-secret/redact-secret-vault/issues/105), and [#107](https://github.com/redact-secret/redact-secret-vault/issues/107), after the [independent design review](../research/persistent-vault-design-review.md).

It is language-neutral where it defines bytes and semantics (§3, §5, §6, §7) and TypeScript where it names the JavaScript surface (§4, §8). All examples use synthetic identifiers.

## 1. Scope

Server-side persistence for values retained by a server vault, so a capture made by one server process can be restored by another, or after a restart, inside one application-controlled namespace.

Out of scope: browser storage, Worker persistence, streaming, a network gateway, arbitrary-text restore, and any backend other than the ones a qualification record names.

## 2. Ownership

| Component | Owns | Never does |
| --- | --- | --- |
| `@redact-secret/core` | Detection, actions, ranges, display formatting | Storage, crypto, restore |
| `@redact-secret/vault` | The portable in-memory vault; the capture plan (§8.1) | Persistence, drivers, key providers |
| `@redact-secret/vault-server` | Principal, tenant, session, sink, path, and purpose authorization; policy evaluation; lifecycle orchestration | Database or KMS clients |
| `@redact-secret/vault-contracts` | The types, limits, and error classes in §4 | Runtime dependencies, detector logic, I/O |
| `@redact-secret/vault-crypto` | Canonical encoding, AEAD, AAD, envelope encryption (§3); the local key provider (§6.3) | Storage, authorization |
| `KeyProvider` implementations | Scoped data-key generation, wrapping, unwrapping, retirement | Storage, authorization, payload encryption |
| `Store` implementations (`@redact-secret/store-*`) | Ciphertext I/O and conditional transactional state changes | Plaintext, keys, principals, policy |

Dependency rules, checked on packed artifacts:

- `vault` depends on nothing but its core peer. Its root and Worker entry points import no contract, store, or provider.
- `vault-contracts` has no dependency.
- `vault-crypto` depends on `vault-contracts` and on the platform's WebCrypto.
- `vault-server` depends on `vault` and `vault-contracts`. The crypto layer, the store, and the key provider are injected by the application.
- A store or provider package owns its driver or SDK as a peer dependency, or takes the driver from the application (`store-sqlite`). No other package names one.

An application may inject its own `Store`, `KeyProvider`, identity resolver, and policy. An injected implementation runs inside the trusted process; a TypeScript interface does not isolate the vault from it (§10).

## 3. Record format, version 1

### 3.1 Encoding rules

- Integers are unsigned and big-endian: `u8`, `u16`, `u32`, `u64`.
- `lp16(x)` is `u16` byte length followed by the bytes; `lp32(x)` uses a `u32` length.
- A string is the UTF-8 encoding of a well-formed Unicode string. An implementation tests well-formedness before encoding and rejects a lone surrogate; it must not rely on an encoder that silently substitutes U+FFFD. No normalization is applied: two strings are equal only when their bytes are.
- "Ascending byte order" compares the UTF-8 bytes as unsigned values. This differs from a UTF-16 code-unit sort for supplementary characters, and the vectors include that case.
- A timestamp is an integer number of milliseconds since the Unix epoch, `0 ≤ t ≤ 2^53 − 1`, encoded as `u64`. A non-integer is rejected at every contract boundary; the server floors its own clock reading.
- A decoder rejects trailing bytes, a length that exceeds the remaining input, an unknown version or algorithm, a non-empty field whose presence flag is 0, and any value over the limits in §3.6. It never guesses.

### 3.2 Identifiers

| Identifier | Form | Chosen by |
| --- | --- | --- |
| `namespace` | 1 to 128 characters of `[A-Za-z0-9._:-]` | The application, once per persistent vault |
| `tenant` | 1 to 256 UTF-16 code units, well-formed | The trusted principal resolver |
| `sessionId` | 1 to 256 UTF-16 code units, well-formed, optional | The trusted session resolver |
| `captureId` | `cap_` followed by 26 characters of `[a-z2-7]` (128 random bits) | The vault |
| issued token | `<rsv_` followed by 26 characters of `[a-z2-7]` and `>` (128 random bits) | The vault |
| `entryId` | 64 lowercase hexadecimal characters | Derived, below |
| `attemptId` | 1 to 128 characters of `[A-Za-z0-9._:-]` | The caller, or the server when omitted |

```text
entryId = hex(SHA-256(
  "rsv-entry-id-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(token) ))
```

The store never sees an issued token. The derivation is unkeyed: a token carries 128 bits from the platform CSPRNG, which the vault obtains itself and no caller supplies (§8.1), so a party that reads the store cannot recover or enumerate tokens from identifiers. A party that already holds a token and can read the store can find that token's row; it learns nothing it can decrypt. If a later version needs a keyed derivation, it gets a new label and a new `lookupVersion`, and is rotated separately from encryption keys.

A `sessionId` is an identifier, not a credential, and must not be a bearer token. It is bound into the associated data and is never stored. What is stored with a session-bound capture is a keyed tag, so a wrong session can be denied before any key is unwrapped and lifecycle operations can check it:

```text
sessionTag = hex(MAC( "rsv-session-tag-v1" 0x00
   || lp16(namespace) || lp16(tenant) || lp16(captureId) || lp16(sessionId) ))
```

`MAC` is the digest function of §7.3 under the same key.

### 3.3 Algorithm and keys

Algorithm `1` is AES-256-GCM as specified by [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final): 256-bit key, 96-bit nonce, 128-bit tag, no truncation. It is the only allowed algorithm. The algorithm is read from the envelope and checked against the allowlist; it is never inferred from the stored bytes or negotiated down.

- **Capture data key (DEK).** One 256-bit DEK per capture, produced by the `KeyProvider` (§6) in one call. It is never used as a cipher key directly.
- **Entry key.** For each entry, a 256-bit AES-GCM key derived with HKDF-SHA-256 from the capture DEK:

  ```text
  entryKey = HKDF-SHA-256(ikm = DEK, salt = 32 zero bytes,
                          info = "rsv-entry-key-v1" 0x00 || u8 algorithm || lp16(entryId), length = 32)
  ```

  An entry key encrypts one payload. Entry identifiers are unique within a capture and the crypto layer refuses a duplicate, so no entry key is derived twice for two messages. Version 1 has no re-encryption (§6.2).
- **Nonce.** 96 random bits from the platform CSPRNG, generated in the process that encrypts. Because an entry key encrypts one message, nonce uniqueness per key does not depend on coordination between processes.
- **Implementation.** Platform WebCrypto (`crypto.subtle`) in the Node.js profile. No handwritten cipher. That a browser also has WebCrypto does not qualify a browser persistent vault.

One DEK per capture, not per entry, is a deliberate choice: a key service is called once per capture and once per capture restored, instead of once per value. The unit of revocation and deletion is the capture either way.

### 3.4 Associated data

```text
AAD = "rsv-aad-v1" 0x00
   || u8  formatVersion        (1)
   || u8  algorithm            (1)
   || lp16(namespace)
   || lp16(tenant)
   || lp16(captureId)
   || lp16(entryId)
   || u8  sessionBound         (0 or 1)
   || lp16(sessionId)          (empty when sessionBound is 0)
   || u64 createdAt
   || u64 expiresAt
   || u32 maxUses
```

The server builds the AAD from trusted inputs, not from the row alone: `namespace` from its configuration, `tenant` and `sessionId` from the resolvers, `entryId` from the token in the request. `captureId`, `sessionBound`, `createdAt`, `expiresAt`, and `maxUses` come from the row and are therefore authenticated by the tag: a changed value fails decryption. `captureId` is additionally required to be one of the captures the request names.

Key identity is not in the AAD. A swapped or rolled-back wrapped key yields a different DEK, or none, so the tag fails; the provider's context binding (§6.1) is a second check. Leaving it out keeps re-wrapping possible without re-encrypting payloads.

### 3.5 Payload and envelope

Plaintext handed to the AEAD:

```text
payload = u8 payloadVersion (1)
       || lp32(value)
       || lp16(type)
       || u16 grantCount                                  (1 to 64)
       || grantCount × ( lp16(sink) || u16 pathCount || pathCount × lp16(path) )   (pathCount 1 to 256)
       || u8 hasPolicyRevision (0 or 1)
       || lp16(policyRevision)   (empty when hasPolicyRevision is 0)
```

Sinks are unique and in ascending byte order; within a grant, paths are unique and in ascending byte order. A decoder rejects any other order. `type` is 1 to 256 bytes. A `policyRevision` that is present may be empty, and stays distinct from an absent one. `value` is opaque bytes to the crypto layer, which neither decodes nor validates it; the server encodes it from a well-formed string and decodes it strictly. The value, the finding type, the grants, and the policy revision are encrypted because the store does not need them to index or to enforce lifecycle conditions.

Stored envelope, one per entry:

```text
envelope = "RSVE" || u8 formatVersion (1) || u8 algorithm (1)
        || nonce (12 bytes) || lp32(ciphertext || tag)
```

Stored on the capture and replaceable under a key revision (§5.6): `keyRef` (a non-secret provider string, 1 to 512 bytes) and `wrappedKey` (1 to 4096 bytes).

### 3.6 Limits

| Quantity | Ceiling |
| --- | --- |
| Value | 1 MiB (`LIMIT_CEILINGS.maxValueBytes` of the vault; default 8 KiB) |
| Envelope | The store's `maxEnvelopeBytes`, at most 1 MiB + 64 KiB. A maximum-size value with very large grants can exceed it; that is a `RECORD_LIMIT` at seal |
| Grants per record | 1 to 64 sinks, 1 to 256 paths each, each identifier at most 256 code units |
| `type`, `policyRevision` | 256 bytes each |
| `sink`, each `path`, `principalId` | 256 code units each |
| `purpose` | 1 to 1024 bytes |
| Capture lifetime (`expiresAt − createdAt`) | Greater than 0, at most 24 hours |
| `maxUses` | 1 to 1000 |
| Entries in one capture | The store's `maxCreateEntries`, at most 1024 |
| Bytes in one capture | The store's `maxCreateBytes` (sum of envelopes) |
| Entries in one restore | The store's `maxRestoreEntries`, at most 1024 |
| Captures named by one restore | The store's `maxRestoreCaptures`, at most 64 |

Every record expires. There is no "never" value. All entries of a capture share its `createdAt` and `expiresAt`.

There is no aggregate quota in this version. Stored volume is bounded by the capture rate times the 24-hour ceiling. Limiting the rate per principal or tenant is the application's control, exercised through the lifecycle policy (§8.2).

### 3.7 What stays visible

A party that reads the store sees, per capture: namespace, tenant, capture identifier, a session tag when session-bound, creation and expiry time, epoch, state, generation, key reference, and wrapped key. Per entry: entry identifier, `maxUses`, uses consumed, revisions, and ciphertext length. Per receipt: attempt identifier, request digest, and time. Sizes, counts, and timing are not hidden. Tenant identifiers are stored as given; an application that considers them sensitive supplies opaque ones.

A key provider is given the `KeyContext` (§4). A provider backed by a remote key service must not send those identifiers to the service in clear where they would be logged; it sends a digest of the context (§6.1).

### 3.8 Test vectors

`conformance/persistent/v1/vectors.json` holds deterministic vectors for `entryId`, the entry-key derivation, the AAD, the payload, the envelope (fixed DEK and nonce, used only by tests), the request digest (§7.3), the session tag, and the local provider's wrapped key. Every implementation in any language must reproduce them byte for byte and must reject each listed negative case.

## 4. Contracts

Exported by `@redact-secret/vault-contracts`. The signatures here are the frozen surface; the package's comments restate the semantics of this document.

```ts
export interface StoreScope {
  readonly namespace: string;
  readonly tenant: string;
}

export interface StoreCapabilities {
  readonly contractVersion: 1;
  /** Package or implementation name. Descriptive. */
  readonly adapter: string;
  /** The deployment profile the adapter verified or was told it runs under. */
  readonly profile: string;
  readonly atomicCreate: boolean;
  readonly maxCreateEntries: number;
  readonly maxCreateBytes: number;
  readonly atomicRestore: boolean;
  readonly maxRestoreEntries: number;
  readonly maxRestoreCaptures: number;
  /** Commit, revoke, and inspect are evaluated against authoritative state. */
  readonly authoritativeCommit: boolean;
  readonly revocationFences: boolean;
  readonly attemptReceipts: boolean;
  /** The store judges expiry and skew with its own clock. */
  readonly storeClock: boolean;
  /** Largest difference the store accepts between its clock and a caller's `now`. */
  readonly maxClockSkewMs: number;
  /** "volatile": state is lost when the process exits. */
  readonly durability: "volatile" | "durable";
  /** Independent processes share one authoritative state. */
  readonly crossProcess: boolean;
  /** What the adapter does to notice a restored or rolled-back database: a short identifier, or "none". */
  readonly restoreDetection: string;
  readonly maxEnvelopeBytes: number;
}

export interface StoredKey {
  readonly keyRef: string;
  readonly wrappedKey: Uint8Array;
}

export interface NewEntry {
  readonly entryId: string;
  readonly maxUses: number;
  readonly envelope: Uint8Array;
}

export interface CreateCaptureInput {
  readonly scope: StoreScope;
  readonly epoch: number;
  readonly now: number;
  readonly capture: StoredKey & {
    readonly captureId: string;
    /** 64 hexadecimal characters, or null for a capture that is not session-bound. */
    readonly sessionTag: string | null;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly lookupVersion: 1;
  };
  readonly entries: readonly NewEntry[];
}

export type CreateCaptureResult =
  | { readonly outcome: "created" }
  | { readonly outcome: "rejected"; readonly reason: "exists" | "fenced" | "clock-skew" | "quarantined" | "stale" };

export interface StoredEntry {
  readonly entryId: string;
  readonly captureId: string;
  readonly maxUses: number;
  readonly used: number;
  readonly lifecycleRevision: number;
  readonly ciphertextRevision: number;
  readonly envelope: Uint8Array;
}

export interface StoredCapture extends StoredKey {
  readonly captureId: string;
  readonly state: "live" | "revoked";
  readonly generation: number;
  readonly keyRevision: number;
  readonly epoch: number;
  readonly sessionTag: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ReadEntriesInput {
  readonly scope: StoreScope;
  readonly entryIds: readonly string[];
}

export interface ReadCapturesInput {
  readonly scope: StoreScope;
  readonly captureIds: readonly string[];
}

export interface ReadEntriesResult {
  readonly recovery: RecoveryState;
  /** Entries found, in no particular order. A missing identifier is simply absent. */
  readonly entries: readonly StoredEntry[];
  /** The capture of every returned entry. */
  readonly captures: readonly StoredCapture[];
}

export interface CommitRestoreInput {
  readonly scope: StoreScope;
  readonly epoch: number;
  readonly now: number;
  readonly attempt: { readonly attemptId: string; readonly requestDigest: Uint8Array };
  readonly receiptExpiresAt: number;
  /** Exactly the captures of the entries in `uses`, each once. */
  readonly captures: readonly { readonly captureId: string; readonly generation: number }[];
  /** Each entry once, with its total occurrence count across the request. */
  readonly uses: readonly {
    readonly entryId: string;
    readonly captureId: string;
    readonly count: number;
    readonly lifecycleRevision: number;
    readonly ciphertextRevision: number;
  }[];
}

export type CommitRejection =
  | "revoked" | "expired" | "budget" | "stale" | "unknown" | "clock-skew" | "quarantined";

export type CommitRestoreResult =
  | { readonly outcome: "committed" }
  | { readonly outcome: "already-committed" }
  | { readonly outcome: "attempt-mismatch" }
  | { readonly outcome: "rejected"; readonly reason: CommitRejection };

export interface StoreCallOptions {
  readonly signal?: AbortSignal;
}

export interface Store {
  capabilities(): StoreCapabilities;
  createCapture(input: CreateCaptureInput, options?: StoreCallOptions): Promise<CreateCaptureResult>;
  readEntries(input: ReadEntriesInput, options?: StoreCallOptions): Promise<ReadEntriesResult>;
  readCaptures(input: ReadCapturesInput, options?: StoreCallOptions): Promise<readonly StoredCapture[]>;
  commitRestore(input: CommitRestoreInput, options?: StoreCallOptions): Promise<CommitRestoreResult>;
  revokeCapture(input: RevokeCaptureInput, options?: StoreCallOptions): Promise<RevokeCaptureResult>;
  inspectAttempt(input: InspectAttemptInput, options?: StoreCallOptions): Promise<InspectAttemptResult>;
  replaceCaptureKey(input: ReplaceCaptureKeyInput, options?: StoreCallOptions): Promise<ReplaceCaptureKeyResult>;
  deleteCiphertext(input: DeleteCiphertextInput, options?: StoreCallOptions): Promise<DeleteCiphertextResult>;
  sweepExpired(input: SweepInput, options?: StoreCallOptions): Promise<SweepResult>;
  recoveryState(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState>;
  initializeNamespace(input: { readonly namespace: string; readonly epoch: number }, options?: StoreCallOptions): Promise<InitializeNamespaceResult>;
  quarantine(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState>;
  invalidateRecovered(input: InvalidateRecoveredInput, options?: StoreCallOptions): Promise<InvalidateRecoveredResult>;
}
```

The remaining input and result types are listed with their operation in §5.

```ts
export interface KeyContext {
  readonly namespace: string;
  readonly tenant: string;
  readonly captureId: string;
}

export interface KeyCallOptions {
  readonly signal?: AbortSignal;
}

export interface DataKey extends StoredKey {
  /** 32 bytes. The caller overwrites it after use. */
  readonly plaintextKey: Uint8Array;
}

export interface KeyProvider {
  /** Profile identifier, for diagnostics and qualification records. Not secret. */
  readonly profile: string;
  generateDataKey(context: KeyContext, options?: KeyCallOptions): Promise<DataKey>;
  unwrapDataKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<Uint8Array>;
  rewrapDataKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<StoredKey>;
}

/** Everything authenticated but not encrypted for one entry (§3.4), from trusted scope and the row. */
export interface RecordBinding {
  readonly namespace: string;
  readonly tenant: string;
  readonly captureId: string;
  readonly entryId: string;
  readonly sessionId: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly maxUses: number;
}

/** Everything encrypted for one entry (§3.5). */
export interface RecordPayload {
  /** UTF-8 bytes. The caller decodes them only when the value is about to be returned, and overwrites them otherwise. */
  readonly value: Uint8Array;
  readonly type: string;
  readonly grants: readonly { readonly sink: string; readonly paths: readonly string[] }[];
  readonly policyRevision: string | null;
}

export interface SealCaptureInput {
  readonly context: KeyContext;
  readonly records: readonly { readonly binding: RecordBinding; readonly payload: RecordPayload }[];
}
export interface SealedCapture extends StoredKey {
  /** In the order of `records`. */
  readonly envelopes: readonly Uint8Array[];
}

export interface OpenCaptureInput extends StoredKey {
  readonly context: KeyContext;
  readonly records: readonly { readonly binding: RecordBinding; readonly envelope: Uint8Array }[];
}

export interface RecordCrypto {
  /** Profile identifier. Not secret. */
  readonly profile: string;
  sealCapture(input: SealCaptureInput, options?: KeyCallOptions): Promise<SealedCapture>;
  /** Payloads in the order of `records`. All of them, or an error: never a partial result. */
  openCapture(input: OpenCaptureInput, options?: KeyCallOptions): Promise<readonly RecordPayload[]>;
  rewrapCaptureKey(input: StoredKey & { readonly context: KeyContext }, options?: KeyCallOptions): Promise<StoredKey>;
}
```

`sealCapture` and `openCapture` reject (`RECORD_INVALID_ARGUMENT`) a duplicate `entryId` among the records and any record whose namespace, tenant, or capture differs from `context`.

`RecordCrypto` is what the server calls. `@redact-secret/vault-crypto` implements it over a `KeyProvider`. A remote service that encrypts whole payloads is a different profile: it implements `RecordCrypto`, is qualified on its own, and is never passed off as a `KeyProvider`.

### 4.1 Errors

A store or provider reports an expected outcome in its result and throws only for the failures below. Every error has a fixed message per code, no `cause`, and no driver, SDK, input, key, or ciphertext text.

| Class | Code | Meaning |
| --- | --- | --- |
| `StoreError` | `STORE_UNAVAILABLE` | The operation definitely had no effect |
| | `STORE_AMBIGUOUS` | The operation may or may not have taken effect |
| | `STORE_INVALID_ARGUMENT` | The input violates the contract; nothing was attempted |
| | `STORE_CAPABILITY` | The input exceeds a declared capability; nothing was attempted |
| | `STORE_CLOSED` | The adapter was closed |
| `KeyProviderError` | `KEY_UNAVAILABLE` | Unknown, disabled, retired, or out-of-scope key |
| | `KEY_INTEGRITY` | The wrapped key did not authenticate for this context |
| | `KEY_TIMEOUT`, `KEY_THROTTLED`, `KEY_ABORTED` | The provider did not answer in time, refused for load, or the call was cancelled |
| | `KEY_INVALID_ARGUMENT` | The input violates the contract |
| `RecordCryptoError` | `RECORD_MALFORMED`, `RECORD_UNSUPPORTED`, `RECORD_INTEGRITY`, `RECORD_LIMIT`, `RECORD_INVALID_ARGUMENT` | Decoding, version or algorithm, authentication, size, and input failures |

Code assignment in the crypto layer:

- `RECORD_MALFORMED`: bad magic, a length that does not match, non-canonical order, a zero count, a bad presence flag, trailing bytes, invalid UTF-8 in an identifier.
- `RECORD_UNSUPPORTED`: an unknown format version, algorithm, or payload version, checked before any key is unwrapped.
- `RECORD_LIMIT`: anything over a ceiling of §3.6, including a length field that claims more than the envelope ceiling. Nothing that large is allocated.
- `RECORD_INTEGRITY`: the tag did not verify.
- `RECORD_INVALID_ARGUMENT`: the caller's input, including a binding outside §3.6 and an empty record list.
- A provider result of the wrong shape (a key that is not 32 bytes, a key reference or wrapped key outside its limits) is `KEY_UNAVAILABLE`. A provider's own `KeyProviderError` is rebuilt from its code, so nothing attached to it passes through.

An adapter that cannot tell whether a mutation took effect must throw `STORE_AMBIGUOUS`. The server treats any other exception from a mutating store call as ambiguous too.

### 4.2 Mechanical validation by the store

A store rejects with `STORE_INVALID_ARGUMENT`, before any write: an identifier or timestamp outside §3; a duplicate `entryId` in `entries` or `uses`; a duplicate capture; a `count` that is not an integer of at least 1; a `uses` entry whose capture is not in `captures`, or a capture in `captures` with no use; an empty `uses` or `entries`; an empty or duplicated identifier list in a read; a capture lifetime outside `0 < expiresAt − createdAt ≤ 24 h`; a `maxUses` outside 1 to 1000; an envelope over the contract ceiling of §3.6 (one between the store's own lower `maxEnvelopeBytes` and that ceiling is `STORE_CAPABILITY`); a `requestDigest` that is not 32 bytes; a `keyRef` or `wrappedKey` that is empty or over its limit; a `sessionTag` that is neither null nor 64 hexadecimal characters; an `epoch` or `newEpoch` that is not a positive safe integer; a `receiptExpiresAt` more than 48 hours past the store's clock (judged inside the transaction, since it needs the clock); a `retentionMs` outside 0 to 30 days; a sweep `limit` outside 1 to 10 000. `STORE_INVALID_ARGUMENT` is a definite failure: nothing was applied, and the server reports it as an invariant violation, not as an ambiguous commit. These checks protect the store's own invariants against a faulty caller. They are not authorization.

## 5. Store semantics

Every operation is scoped: it reads and writes only rows of the given `namespace` and `tenant`, mechanically, whatever the caller asks. A store never resolves a principal, evaluates a policy, decrypts, or holds a key.

A store declares its capabilities once. An input over a declared bound throws `STORE_CAPABILITY` before any write. A store never splits a batch into smaller transactions.

### 5.1 State

```text
capture:  (absent) --createCapture--> live --revokeCapture--> revoked --sweep--> (absent)
                  \--revokeCapture(fenceAbsent)--> revoked     (only for an identifier the server issued)

entry:    live(used < maxUses) --commitRestore--> live or exhausted(used = maxUses)
          any --deleteCiphertext / sweep--> (absent)

receipt:  (absent) --commitRestore--> committed --sweep after receiptExpiresAt--> (absent)

namespace recovery record:
          (absent) --initializeNamespace--> serving --quarantine--> quarantined
          serving or quarantined --invalidateRecovered--> serving, with a higher epoch
```

Mutable lifecycle state (`used`, `lifecycleRevision`, capture `state` and `generation`) is separate from the encrypted record. `ciphertextRevision` counts replacements of an entry's envelope; `keyRevision` counts replacements of a capture's stored key. No revision is reset by another's change.

A capture row records the namespace epoch it was created under. A capture whose epoch is lower than the namespace's current epoch is treated as revoked by every operation: reads return it with `state: "revoked"`, and `revokeCapture` answers `already-revoked`.

A fence row and a capture whose ciphertext was deleted hold no key. Neither is ever returned by `readEntries`; `readCaptures` returns them with `state: "revoked"`, an empty `keyRef`, and an empty `wrappedKey`.

### 5.2 Conflict rule

This rule is what makes §7.1 true, and an adapter must implement it, not merely the checks:

> `commitRestore` and `createCapture` must conflict with any concurrent `revokeCapture` of a capture they name and with any concurrent `quarantine` or `invalidateRecovered` of their namespace. "Conflict" means the store serializes the two: one observes the other's committed effect, or one is aborted. Reading a row under an isolation level that lets a concurrent writer commit unseen does not satisfy this.

In a locking store this means `commitRestore` and `createCapture` take a shared lock on the namespace recovery record and a lock on every named capture row that excludes a revocation until they commit; `quarantine` and `invalidateRecovered` take the recovery record exclusively. Commits in one namespace therefore do not serialize on that record against each other. In an optimistic store it means the transaction's conditions include those rows. An abort caused by this rule is reported as `rejected: "stale"`, never as success and never as an ambiguous outcome: an aborted transaction definitely applied nothing.

Rows are locked in one fixed order — recovery record, then captures by identifier, then entries by identifier — so two transactions cannot deadlock on each other. A store that detects a deadlock or serialization failure anyway rolls back and reports `stale`.

The conformance harness must include schedules that hold one transaction open on a second connection: a revocation committed between a restore's read of the capture and its commit, and a quarantine committed between a create's check and its commit. A store passes only if the restore or create does not succeed.

### 5.3 `createCapture`

One transaction that creates the capture and all its entries, or nothing.

- `rejected: "quarantined"` when the namespace has no recovery record, is quarantined, or `input.epoch` differs from the stored epoch.
- `rejected: "clock-skew"` when the store's clock and `input.now` differ by more than `maxClockSkewMs`, or `createdAt` is outside that bound of the store's clock.
- `rejected: "fenced"` when a capture with that identifier exists and is revoked, is a fence, or was created under an earlier epoch.
- `rejected: "exists"` when a live capture or any entry with one of the entry identifiers exists. Nothing is overwritten.
- `rejected: "stale"` when the conflict rule aborted the transaction. The server may try again with a new capture identifier.
- Otherwise every row is created with `used = 0`, `lifecycleRevision = 1`, `ciphertextRevision = 1`, capture `generation = 1`, `keyRevision = 1`, and the current epoch.

A capture that retains no entry is not created: there is nothing to store or revoke.

### 5.4 `readEntries`

A bounded read for preflight, taken as one consistent snapshot of the recovery record, the entries, and their captures. Its result authorizes nothing: every condition it suggests is checked again by `commitRestore`. An entry of a revoked capture is returned with its capture so the server can report `revoked`; an entry whose ciphertext was deleted is absent. At most `maxRestoreEntries` identifiers per call.

`readCaptures` returns the capture rows that exist among at most `maxRestoreCaptures` identifiers. The server uses it for lifecycle operations, which start from a capture identifier.

### 5.5 `commitRestore`

One transaction, evaluated against authoritative state under the conflict rule, that either applies every use and writes the receipt or changes nothing.

1. No recovery record, namespace quarantined, or `input.epoch` differs: `rejected: "quarantined"`.
2. A receipt for `attemptId` in this scope exists: `already-committed` when its digest equals `requestDigest`, otherwise `attempt-mismatch`.
3. Store clock and `input.now` differ by more than `maxClockSkewMs`: `rejected: "clock-skew"`.
4. For each capture: absent is `unknown`; revoked, or created under a lower epoch, is `revoked`; a different `generation` is `stale`; store clock at or past `expiresAt` is `expired`.
5. For each use: an absent entry, or one belonging to a different capture than stated, is `unknown`; a different `lifecycleRevision` or `ciphertextRevision` is `stale`; `used + count > maxUses` is `budget`.
6. `receiptExpiresAt` earlier than the latest `expiresAt` among the captures: `STORE_INVALID_ARGUMENT`.
7. Apply: `used += count` and `lifecycleRevision += 1` for each entry; insert the receipt.

Steps 1 and 2 are evaluated first, in that order. When several conditions of steps 3 to 5 fail at once, which reason is reported is not specified; that some rejection is reported and nothing is applied is.

The transaction's commit is the linearization point of the restore.

### 5.6 `revokeCapture`, `inspectAttempt`, `replaceCaptureKey`

```ts
export interface RevokeCaptureInput {
  readonly scope: StoreScope;
  readonly captureId: string;
  readonly now: number;
  /** How long past the capture's expiry (or past now, if later) the tombstone is kept. */
  readonly retentionMs: number;
  /** Write a fence when the capture does not exist. Only for an identifier the server itself issued. */
  readonly fenceAbsent: boolean;
}
export type RevokeCaptureResult =
  | { readonly outcome: "revoked" | "already-revoked"; readonly entries: number }
  | { readonly outcome: "not-found" }
  | { readonly outcome: "fenced" };

export interface InspectAttemptInput { readonly scope: StoreScope; readonly attemptId: string }
export type InspectAttemptResult =
  | { readonly state: "committed"; readonly requestDigest: Uint8Array; readonly committedAt: number }
  | { readonly state: "absent" };

export interface ReplaceCaptureKeyInput extends StoredKey {
  readonly scope: StoreScope;
  readonly captureId: string;
  readonly keyRevision: number;
}
export type ReplaceCaptureKeyResult =
  | { readonly outcome: "replaced"; readonly keyRevision: number }
  | { readonly outcome: "rejected"; readonly reason: "stale" | "unknown" | "revoked" | "expired" };
```

`revokeCapture` sets the capture to `revoked` and increments its `generation` in one transaction. `entries` is the number of entry rows the capture had at that moment; it is informational. For an absent capture it returns `not-found` and writes nothing, unless `fenceAbsent` is set, in which case it writes a revoked row whose `createdAt` and `expiresAt` are the store's clock, and returns `fenced`; the epoch recorded on a fence is not significant. A capture of an earlier epoch already reads as revoked: revoking it answers `already-revoked` and writes nothing. The caller's `now` is informational here: the result has no skew rejection, and retention is computed from the store's clock. Revocation works in a quarantined namespace. The tombstone is kept at least until the later of the capture's `expiresAt` and the store's clock at revocation, plus `retentionMs`.

`inspectAttempt` is an authoritative read. `absent` means no transaction for that attempt has committed as of the read. It never returns restored data.

`replaceCaptureKey` replaces a capture's wrapped key with another wrapping of the same DEK: a compare-and-swap on `keyRevision`. It refuses a capture that is revoked, expired on the store's clock, or has had its ciphertext deleted (`revoked`); when several refusals apply, which is reported is not specified. It works in a quarantined namespace. It never changes an envelope, `used`, `lifecycleRevision`, `ciphertextRevision`, `maxUses`, `state`, `generation`, the epoch, or any time. A restore running concurrently is unaffected, because the DEK is the same. Version 1 has no operation that replaces envelopes; `ciphertextRevision` is 1 for every entry and is checked at commit so a later version can add one.

### 5.7 `deleteCiphertext`, `sweepExpired`

```ts
export interface DeleteCiphertextInput { readonly scope: StoreScope; readonly captureId: string; readonly now: number }
export type DeleteCiphertextResult =
  | { readonly outcome: "deleted"; readonly entries: number }
  | { readonly outcome: "rejected"; readonly reason: "live" | "not-found" | "clock-skew" };

export interface SweepInput { readonly namespace: string; readonly now: number; readonly limit: number }
export type SweepResult =
  | { readonly outcome: "swept"; readonly entries: number; readonly captures: number; readonly receipts: number; readonly more: boolean }
  | { readonly outcome: "rejected"; readonly reason: "clock-skew" };
```

`deleteCiphertext` removes the entry rows of a capture that is revoked, or expired on the store's clock; overwrites the capture's stored key with an empty value; increments `keyRevision`; marks the capture revoked; and keeps the row as a tombstone. It does not change `generation`. Deleting again answers `deleted` with zero entries. It refuses a live, unexpired capture. The skew check applies only when the decision rests on expiry: a revoked capture's ciphertext can be deleted whatever the clocks say.

`sweepExpired` removes at most `limit` rows per kind: entries of captures expired on the store's clock, capture rows past their expiry or tombstone retention, and receipts past `receiptExpiresAt`. Entries and unrevoked capture rows go when the store's clock is at or past `expiresAt`; receipts and tombstones go only strictly past their bound; a capture row is never removed while it still has entries. It is cleanup. Skipping it changes storage use, never an authorization outcome. A backend's native TTL, where used, must not delete a row before the same bound, and is likewise never the reason a restore is denied or allowed.

Both take the caller's `now`, so a store clock that has jumped forward cannot delete live rows on its own authority.

Both delete ciphertext from the live store only. Neither is erasure (§9).

### 5.8 Recovery operations

```ts
export interface RecoveryState {
  /** 0 when the namespace has no recovery record. */
  readonly epoch: number;
  readonly state: "uninitialized" | "serving" | "quarantined";
}
export type InitializeNamespaceResult =
  | { readonly outcome: "initialized" }
  | { readonly outcome: "rejected"; readonly reason: "exists" | "not-empty" };
export interface InvalidateRecoveredInput { readonly namespace: string; readonly newEpoch: number }
export type InvalidateRecoveredResult =
  | { readonly outcome: "invalidated"; readonly recovery: RecoveryState }
  | { readonly outcome: "rejected"; readonly reason: "epoch-not-greater" | "uninitialized" };
```

- `initializeNamespace` creates the recovery record. It refuses when the record exists, or when any capture, entry, or receipt row of the namespace exists. No other operation creates the record: a server that finds none fails closed.
- `quarantine` sets the state to `quarantined`. Captures and commits are then rejected; revocation still works. For a namespace with no record it changes nothing and reports `uninitialized`.
- `invalidateRecovered` sets the epoch to `newEpoch`, which must be greater than the stored epoch, and the state to `serving`, in one transaction. Every capture created under an earlier epoch is thereafter treated as revoked. Invalidation is decided by the epoch stamped on each capture, not by comparing clocks.

There is no operation that adopts a new epoch while keeping earlier captures usable, and none that sets `used` from an external ledger. See §9.3.

## 6. Keys

### 6.1 `KeyProvider`

A provider is constructed by the application with explicit key material or an explicit client, and an explicit scope (which namespaces and tenants it may serve). There is no embedded or default key, no key read from the environment by this library, no passphrase-derived key, and no fallback to a local key when a remote provider fails.

- `generateDataKey` returns a fresh random 256-bit DEK, its wrapped form, and the `keyRef` naming the exact wrapping key and version. It always uses the provider's active wrapping key.
- `unwrapDataKey` unwraps with exactly the key `keyRef` names. A key reference the provider does not hold, or holds as retired, or a context outside the provider's scope, is `KEY_UNAVAILABLE`. It never tries another key.
- The provider binds the wrapped key to the `KeyContext`: unwrapping with a different context fails with `KEY_INTEGRITY`. A provider that sends context to a remote service sends a digest of the canonical context, not the identifiers.
- `rewrapDataKey` produces a new wrapped form of the same DEK under the active wrapping key, for the same context.
- Every call accepts an `AbortSignal`. The server bounds each call with a timeout (default 5 seconds) and each operation with a total deadline, and treats timeout, throttling, cancellation, and any thrown non-`KeyProviderError` as failure. It never tries a different provider.

Three kinds of key are kept apart: the wrapping key and its version (`keyRef`), the capture DEK with its derived entry keys, and the derivation of `entryId` (unkeyed in version 1, §3.2).

### 6.2 Lifecycle

A wrapping key version is `active` (wraps and unwraps), `decrypt-only` (unwraps), or `retired` (neither). Exactly one version is active per provider.

- **Rotation.** Make a new version active and the old one decrypt-only. Keep the old version decrypt-only for at least 24 hours plus the clock skew bound, the longest any capture can live. After that no live capture references it and it can be retired. This is the rotation procedure of version 1.
- **Re-wrap.** `rewrapDataKey` with `replaceCaptureKey` moves a capture to the active wrapping key without touching payloads. The store operation is part of the contract and is covered by conformance tests. Version 1 has no enumeration of captures by key reference, so this library does not drive it; with a 24-hour lifetime ceiling, waiting out the decrypt-only window achieves the same.
- **Re-encryption** under a new DEK is not in version 1. It would need a read of every entry of a capture and the session identifier of a session-bound capture, neither of which a maintenance tool has.
- **Exposure.** Neither would help after a wrapping key is exposed: a party holding the old key and an old copy of the store can still decrypt that copy. The response to exposure is revocation and capture from source again.
- **Retirement.** Retiring a version while live captures reference it makes them permanently unreadable (`key-unavailable`). A concurrent restore that already unwrapped a DEK may complete; one that had not fails closed.
- **Cache.** A provider does not cache unwrapped keys by default. An opt-in cache is bounded by entry count, age, and tenant, and is cleared on `close`. Disabling a key at the key service does not reach a cached DEK until the cache entry ages out; that delay is the configured maximum age.
- **Memory.** The crypto layer overwrites DEK, entry-key, and payload buffers it owns after use. A managed runtime may have copied them; restored values are JavaScript strings and cannot be overwritten. This is stated, not solved.

### 6.3 Local provider

`@redact-secret/vault-crypto/local-key-provider` accepts explicitly injected key material:

```ts
createLocalKeyProvider({
  keys: [{ id: "2026-10", material, state: "active" }, { id: "2026-07", material: old, state: "decrypt-only" }],
  scope: { namespaces: ["support-prod"] },
});
```

`material` is 32 bytes, or a non-extractable `CryptoKey` for HKDF with the `deriveKey` usage. `keyRef` is `local:<id>`. For each context the provider derives a wrapping key with HKDF-SHA-256 (`salt` = 32 zero bytes, `info = "rsv-local-wrap-v1" 0x00 || lp16(namespace) || lp16(tenant) || lp16(captureId)`) and wraps the DEK with AES-256-GCM under a random 96-bit nonce: `wrappedKey = 0x01 || nonce || ciphertext || tag`, where the leading byte is the wrap format version. No associated data is passed; the context is bound through the derivation. A stored key of the wrong length or version, or one that does not authenticate, is `KEY_INTEGRITY`; an empty or oversized one, or an empty key reference, is `KEY_INVALID_ARGUMENT`. `scope.tenants`, when given, is not empty. The provider does not load, store, or rotate the material; the application does, from its own secret manager.

It is a complete provider for a deployment whose secret manager delivers key material to the process. Its limits are stated in the package: the material is in process memory; anyone who obtains it and a copy of the store can decrypt every capture wrapped under it; and because every wrapping key derives from one material, retiring that material makes every capture under it unreadable. It offers no per-tenant or per-capture erasure.

A deterministic provider for vectors is exported only from the conformance package, is named `createInsecureTestKeyProvider`, and refuses to construct unless called with `{ acknowledgeInsecure: "test-only" }`.

## 7. Restore semantics

### 7.1 Linearization

A restore is linearized at the commit of the store's `commitRestore` transaction. A revocation is linearized at the commit of `revokeCapture`. The conflict rule (§5.2) makes the store order them: the restore's transaction excludes a concurrent revocation of any capture it names until it commits, or is aborted by it.

- A revocation that commits first makes the restore's commit `revoked` or `stale`; on `stale` the server reads again and then sees the revocation. Nothing is returned and no budget changes.
- A revocation that commits after the restore's commit cannot retract a value already staged for return.
- Two restores of the same entry are ordered by the store. With `maxUses = N`, at most N occurrences ever commit.
- A capture creation and a revocation of the same identifier are ordered by the store: creation first gives a live capture that is then revoked; a fence first makes the creation `fenced`.
- A quarantine or invalidation is ordered against captures and commits the same way.

### 7.2 Order of a restore

1. Validate the request shape and snapshot the fields.
2. Resolve the principal from trusted context, with a timeout. The tenant is the principal's. Resolve the session, when a session resolver is configured; a resolver that throws or times out denies `unauthenticated`. Then deny malformed token markers and an empty purpose. Both denials come after the principal is known, so the audit event can name it, and before any store read or key unwrap.
3. A request with no token is returned unchanged. No store call is made and no attempt is recorded.
4. Derive entry identifiers and call `readEntries`. Deny, in this order: a namespace that is not serving at the configured epoch; unknown entries; revoked captures; captures the request does not name; a session tag that does not match the resolved session, or a session-bound capture when no session resolved; expiry on the server's clock; `used + count > maxUses` from the row.
5. For each capture involved, unwrap its DEK once and decrypt its entries with the AAD built from trusted scope. Any failure is a denial; no partial result exists.
6. Check sink and path grants from the decrypted records.
7. Evaluate the application's policy for every entry and path, outside any database lock, with a timeout.
8. Decode the values and stage the output fields in memory.
9. Call `commitRestore` with the revisions and generations read in step 4.
10. Only on `committed`: return the fields. In every other case the staged output is discarded.

Steps 1 to 8 change no stored state. Nothing restored leaves the server before step 10.

Values are decrypted in step 5, before grants and policy are known to pass, because grants are encrypted with the value. A request denied in step 6 or 7 therefore had its values in process memory for the duration of the call. The crypto layer returns values as bytes, the server decodes them to strings only in step 8, and on a denial it overwrites them, so a denied request leaves no value in an immutable string.

On `rejected: "stale"` the server repeats from step 4 with the same attempt, re-evaluating policy, up to a configured number of times (default 3). If the commit is still `stale`, the restore fails `RESTORE_CONFLICT`: nothing was consumed, and the caller may retry. Parallel restores of one multi-use entry collide this way by design, because each commit changes the `used` value the policy was shown.

### 7.3 Attempts and failure outcomes

Every restore that reaches the store has an `attemptId`.

```text
requestDigest = MAC( "rsv-request-v1" 0x00
   || lp16(namespace) || lp16(tenant) || lp16(principalId)
   || u8 hasSession || lp16(sessionId)                               (the session resolved for this request)
   || lp16(sink) || lp16(purpose)
   || u16 captureCount || captureCount × lp16(captureId)             (ascending byte order)
   || u16 useCount || useCount × ( lp16(entryId) || u16 pathCount
        || pathCount × ( lp16(path) || u32 occurrences ) ) )         (entries, then paths, ascending)
```

`captureId` here is every capture the request names: 1 to 64. There are 1 to 1024 uses, each with 1 to 65 535 paths and 1 to 2^32 − 1 occurrences. `MAC` is HMAC-SHA-256 under the application's digest key, which also keys the session tag (§3.2). The key is required: without it, a party reading the store could test guesses of principal, sink, purpose, and session against what is stored. An application may pass `allowUnkeyedDigests: true`, which substitutes SHA-256 and accepts that. The key must be the same in every process of the namespace; an attempt made under one key and retried under another is `attempt-mismatch`, and a session-bound capture made under one key is denied `source` under another, so the key is changed only when it is acceptable to lose outstanding attempts and session-bound captures.

| Situation | Stored effect | Returned to caller |
| --- | --- | --- |
| Denied before commit (steps 1 to 8) | None | `RESTORE_DENIED` with the reason |
| `commitRestore` rejected | None | `RESTORE_DENIED` (`revoked`, `expired`, `budget`, `unknown-token`), or `STORE_QUARANTINED`, or `CLOCK_SKEW` |
| `stale` after every retry | None | `RESTORE_CONFLICT`. The caller may retry the same attempt |
| `STORE_UNAVAILABLE` | None | `STORE_UNAVAILABLE`. The caller may retry the same attempt |
| Committed, response delivered | Budget consumed, receipt written | The restored fields, once |
| Committed, then the server crashes or the response is lost | Budget consumed, receipt written | Nothing. The value is not delivered and that use is spent |
| Same `attemptId`, same request, after a commit | None | `RESTORE_DENIED`, no fields. The reason is `attempt-already-committed` when the request reaches the commit; when the attempt itself exhausted an entry, the preflight denies `budget` first. `resolveAttempt` reports `committed` in both cases |
| Same `attemptId`, different request | None | `RESTORE_DENIED`, reason `attempt-mismatch` |
| `STORE_AMBIGUOUS` or any unclassified failure at commit | Unknown | `COMMIT_AMBIGUOUS` carrying the `attemptId`, no fields |

The release rule is **at most once**. A receipt deduplicates the state change; it does not authorize sending the plaintext again. This design does not provide exactly-once delivery and does not claim to.

After `COMMIT_AMBIGUOUS`:

- The server discards the staged output and never retries on its own, with the same or a new attempt identifier.
- The application resolves the attempt with `resolveAttempt`, passing the attempt identifier and the original request. The server recomputes the digest, reads the receipt authoritatively, and returns `committed`, `absent`, or `attempt-mismatch`. It never returns fields.
- `absent` means the attempt had not committed at the read. The application may submit the same attempt again; the receipt's uniqueness makes the earlier transaction and the retry mutually exclusive, so at most one of them commits.
- A different attempt identifier is a new restore. It is fully re-authorized and consumes its own budget; if the ambiguous attempt did commit, a single-use entry is exhausted and the new attempt is denied. An application that wants a value back after that captures it again from its source.
- No path treats "unknown" as "not consumed". Budget is only ever spent inside a transaction that checks it.

Resumable delivery of an encrypted result is not part of this design. If it is added later it is repeated disclosure under fresh authorization, and it gets its own decision record.

### 7.4 Policy revisions and external authorization

Policy is evaluated in step 7 and the commit happens in step 9. The application's identity and policy systems are not part of the store's transaction, so a change to them between those steps is not seen. The window is bounded by the commit timeout. Two mitigations exist and neither closes the window:

- When `policyRevision` is a function, the server calls it again immediately before the commit and denies `stale-policy` if the value changed since step 7.
- An application that needs a hard cut-off revokes the capture: revocation is in the store's transaction order.

### 7.5 Time

- The server's clock is the application-supplied `now` (default `Date.now`), floored to an integer and made non-decreasing within a process. It sets `createdAt` and `expiresAt` and drives preflight.
- The persistent profile requires a store with `storeClock`. The store judges expiry at commit with its own clock, and rejects `clock-skew` when a caller's `now` and its clock differ by more than `maxClockSkewMs`. Processes with drifting clocks therefore fail closed instead of disagreeing about expiry.
- A capture is expired when the store's clock is at or past `expiresAt`. Expiry is a condition of the commit, independent of whether cleanup has removed the row.
- If only the store's clock is set back, commits fail `clock-skew` once the difference passes the bound, so the extension of any lifetime is at most the bound. If the store's and the servers' clocks are set back together, lifetimes extend by that amount; nothing inside the system can detect it. Trustworthy time on the database host and the servers is a deployment requirement.
- A restart does not reset any deadline: all are absolute timestamps.
- `used` is stored on the entry, not on the receipt, so removing a receipt never makes a consumed use available again. What a receipt provides is deduplication of its attempt. The server sets `receiptExpiresAt` to the latest `expiresAt` among the captures of the attempt, plus the skew bound, plus a grace period (default 1 hour), so every capture an attempt touched has expired before its receipt can be swept, and a replay of that attempt is denied `expired`, or `unknown-token` once the rows are swept.
- Tombstones are kept as §5.6 states, with a default retention of 24 hours. Capture identifiers are 128 random bits and are never reissued.

### 7.6 Cancellation, timeouts, partitions, failover

A cancelled or timed-out call before the store acknowledged a commit is ambiguous unless the adapter can prove the transaction was rolled back. An adapter never retries a commit whose outcome it does not know, and never replays a successful restore as part of a generic retry.

A failover is treated as a lost connection: the outcome is resolved through the receipt on the new primary. That is sound only when the new primary holds every acknowledged commit. `durability: "durable"` is the adapter's declaration about one named profile, backed by its qualification record, not a property this contract can verify. Promoting a replica that may lack acknowledged commits is a rollback, and §9.3 applies to it.

## 8. Server integration

### 8.1 Capture plan

`@redact-secret/vault` gains one module, `@redact-secret/vault/internal/capture-plan`, used by `vault-server`. It contains the capture logic the in-memory vault already runs — the core scan, the action gate, PII allowlisting, eligibility, token issuance, formatting, and output validation — as a function of one input:

```ts
planCapture(core, piiActive, input, options, limits): CapturePlan
// CapturePlan: { text, retained: [{ token, start, end, type }], passedThrough, passedThroughTypes, unrestorable }
```

It returns the redacted text and, for each retained finding, the issued token, the finding type, and the range of the finding in `input`. It returns no value: the caller slices the input it already holds. It reads no vault and retains nothing. Tokens are generated from the platform CSPRNG inside the module; no caller supplies randomness. The in-memory vault calls the same function, so there is one implementation of capture eligibility and no copy of detector logic.

The module is exported under the `node` condition only, is not re-exported from the package root or the Worker entry points, and is documented as internal: `vault-server` pins the exact vault version it was built with.

### 8.2 Persistent server factory

```ts
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";

const vault = await createPersistentServerVault({
  namespace: "support-prod",
  recoveryEpoch: 1,
  store,                 // a Store
  crypto,                // a RecordCrypto, for example createRecordCrypto({ keyProvider })
  digestKey,             // 32 bytes, the same in every process of the namespace
  resolvePrincipal,      // trusted context -> { id, tenant }
  resolveSession,        // optional: trusted context -> session identifier, or null
  policy,                // per entry and path, at restore
  lifecyclePolicy,       // capture, revoke, delete-ciphertext, resolve-attempt
  // limits, now, onAudit, timeouts, maxCommitRetries, policyRevision, pii ...
});
```

- The existing `createServerVault` is unchanged and remains the default. Persistence is opt-in by calling this factory.
- The factory reads `store.capabilities()` and fails `UNSUPPORTED_STORE` unless `contractVersion` is 1 and `atomicCreate`, `atomicRestore`, `authoritativeCommit`, `revocationFences`, `attemptReceipts`, and `storeClock` are all true. A store that is `volatile` or not `crossProcess` is refused unless the application passes `allowNonDurableStore: true`. A durable store whose `restoreDetection` is `"none"` is refused unless the application passes `allowNoRestoreDetection: true`; the runbook of §9.3 is then the only control against a recovered database. It then reads the recovery state and fails `STORE_QUARANTINED` unless the namespace is serving at `recoveryEpoch`. It never initializes a namespace.
- `capture(input, { context, release, ... })` resolves the principal and session from `context`, then asks `lifecyclePolicy`. The tenant and session binding of a capture come only from the resolvers. A context for which the session resolver returns `null` produces a capture that is not session-bound and can be restored from any session of the tenant.
- `restore({ context, sink, purpose, captures, fields, attemptId })` has no `tenant` and no `sessionId` field, and ignores one if passed. A restore cannot assert the session a capture came from; it can only present trusted context that resolves to the same one.
- `revoke({ context, captureId })` denies future restores. `deleteCaptureCiphertext({ context, captureId })` revokes, then deletes the capture's ciphertext from the live store, and its result states that no key was retired. Both read the capture first; for a session-bound capture the resolved session must match its tag. There is no tenant-wide delete.
- `lifecyclePolicy` is asked once per call of `capture`, `revoke`, `deleteCaptureCiphertext`, and `resolveAttempt`:

  ```ts
  type LifecyclePolicy = (input: {
    readonly operation: "capture" | "revoke" | "delete-ciphertext" | "resolve-attempt";
    readonly principal: Principal;
    readonly tenant: string;
    readonly sessionId: string | null;
    readonly captureId?: string;        // absent for "capture" and "resolve-attempt"
    readonly sessionBound?: boolean;    // of the capture, for "revoke" and "delete-ciphertext"
    readonly entries?: number;          // for "capture": values about to be retained
    readonly bytes?: number;            // for "capture": their total UTF-8 size
    readonly requestedAt: number;
  }) => { allow: boolean } | Promise<{ allow: boolean }>;
  ```

  It has the same deadline as the restore policy. A throw, a rejection, a timeout, or anything but `{ allow: true }` fails the operation `LIFECYCLE_DENIED` before any store mutation.
- `resolveAttempt({ context, attemptId, ...originalRequest })` is §7.3's resolution path.
- `close()` releases the instance and nothing else: it does not revoke, delete, or close a store or provider the application created.
- Staged plaintext exists only inside one call, bounded by the capture and restore limits, and is not cached across calls.
- Audit events carry operation, outcome, reason, counts, and opaque identifiers. They never carry a value, a token, a key, ciphertext, or a driver or provider message.

Capture failure: when encryption, a provider call, or `createCapture` fails, no capture result is returned, so no usable token exists outside the server. When `createCapture` is ambiguous, the server calls `revokeCapture` once with `fenceAbsent` for the identifier it issued and reports failure either way. A `stale` creation applied nothing and is reported as `STORE_UNAVAILABLE`; the caller captures again.

### 8.3 Differences from the in-memory server

| Situation | In-memory `createServerVault` | Persistent profile |
| --- | --- | --- |
| Token of another tenant | `tenant-mismatch` | `unknown-token`: another tenant's rows are not read |
| Token of an exhausted entry | `unknown-token` | `budget`, until the row is swept |
| Token of a revoked capture after its ciphertext was deleted | `revoked` while remembered | `unknown-token` |
| Wrong or missing session for a session-bound capture | Not enforced (`sessionId` is advisory) | `source`, from the session tag, before any key is unwrapped. The session is also part of the associated data |
| Captures named by one restore | Up to 1024 | Up to the store's `maxRestoreCaptures` (at most 64) |
| Explicit `tenant` or `sessionId` on a restore | Accepted | Ignored: it has no effect |
| Identifier with a lone surrogate | Accepted | `INVALID_ARGUMENT`; in a restore field path, the denial `invalid-request` |
| Capture requires a principal | No | Yes |
| New denial reasons | — | `integrity-failure`, `key-unavailable`, `attempt-mismatch`, `attempt-already-committed` |
| New error codes | — | `UNSUPPORTED_STORE`, `STORE_UNAVAILABLE`, `STORE_QUARANTINED`, `COMMIT_AMBIGUOUS`, `RESTORE_CONFLICT`, `CLOCK_SKEW`, `LIMIT_EXCEEDED`, `LIFECYCLE_DENIED`, `KEY_UNAVAILABLE` (capture only; at restore a key failure is a denial), `CLOSED` |

## 9. Revoke, deletion, key retirement, erasure

Four different things:

| Operation | Effect | What it does not do |
| --- | --- | --- |
| **Revoke** | Future restores of the capture are denied, durably, in the store's transaction order | Remove ciphertext; affect a value already returned |
| **Ciphertext deletion** | Entry rows and the stored key are removed from the live store | Remove copies in backups, replicas, snapshots, or log archives |
| **Key retirement** | The key owner makes a wrapping key version unusable | Anything, if a copy of that key survives elsewhere; it also makes every capture under that version unreadable, not one capture |
| **Verified erasure** | A statement by the key owner and the storage operator that no retained copy can be decrypted | It is not an operation of this library |

Consequences that must be stated wherever deletion is described:

- A store cannot destroy a key and does not promise to.
- A wrapped DEK in a backup stays decryptable for as long as its wrapping key is usable. Deleting the live row is not cryptographic erasure.
- Retiring a wrapping key shared by unrelated captures is not per-capture erasure.
- Routes to an erasure statement: a provider whose wrapping keys are scoped narrowly enough (for example per tenant and rotation period) that retiring one covers only the data to be erased, with an independent record of which key covered what; backups that expire within a stated bound; or a stated completion delay equal to backup retention. The local provider (§6.3) offers none of these by itself.

### 9.3 Backup recovery and rollback

Authenticated encryption shows a record was written by a key holder. It does not show the record is current. A database restored from a backup contains authentic rows whose budgets and revocations are those of the backup time.

- The application holds a `recoveryEpoch` outside the database, in its deployment configuration. The store holds the namespace's epoch and stamps it on every capture. Every capture and commit carries the configured epoch and is rejected `quarantined` when they differ.
- **Runbook, on any restore from backup, snapshot, point-in-time recovery, or promotion of a replica that may lack acknowledged commits:**
  1. Stop every server of the namespace, or cut its access to the database, before the recovered database accepts connections. A server still running with the old epoch would otherwise serve the recovered rows.
  2. Call `quarantine` on the recovered database.
  3. Raise the configured epoch.
  4. Call `invalidateRecovered` with the new epoch. Every capture in the recovered database is now treated as revoked.
  5. Start servers with the new epoch. Applications capture again from their sources.
The step-by-step procedures, with the exact calls and what a qualification run demonstrated for each, are in the [operations specification](persistent-operations.md).

- **Tripwire.** An adapter for a durable backend states in `restoreDetection` what it does to notice a recovered database by itself, and quarantines the namespace when it does. It is a guard against a skipped runbook, not a replacement for it, and a backup taken after an earlier recovery already carries the current epoch.
- **Not offered:** returning recovered captures to service. That would need a record of consumption and revocation kept outside the database, and operations to apply it; version 1 has neither.
- **Not covered:** a party that can write the database, or roll it back without the operator's knowledge, can also restore the epoch record and whatever the tripwire reads. Freshness against that party needs a monotonic lifecycle authority outside the database, which is the application's to provide. This design does not claim to detect a malicious rollback.

## 10. Trust boundaries

| Party | Can | Cannot, under this design |
| --- | --- | --- |
| Reads the store or a backup | See §3.7 metadata, sizes, timing | Read values, grants, types, or tokens without a wrapping key |
| Writes the store | Delete or corrupt rows; reset budgets and revocations; roll back; replay old authentic rows | Forge a record, move one to another tenant, capture, entry, or session, or change its expiry or `maxUses`, without failing authentication |
| Holds a wrapping key and a store copy | Decrypt every capture wrapped under that key | Be stopped by revocation or expiry, which are server checks |
| Reads a remote key service's audit log | See which context digests were used and when | See identifiers or values |
| Compromises the server process | Everything the server can do, including reading restored values | — |
| Supplies a malicious `Store` or `KeyProvider` | Run in the trusted process: lie about results, retain what it is given, observe memory | Be contained by an interface. Conformance tests show a correct adapter behaves; they do not make a hostile one safe |
| Compromises the key service | Unwrap DEKs; with a store copy, decrypt | — |
| Database or cloud operator | Whatever "reads" and "writes" allow | — |

Database access control supplements the server's authorization; it does not replace it. The store receives conditions that were already decided.

## 11. Compatibility and migration

- `createServerVault` and `@redact-secret/vault` keep their behavior. Nothing existing gains a dependency.
- Tokens and capture identifiers keep their grammar.
- There is no migration from in-memory to persistent state: an in-memory vault has no export.
- A future record format gets a new `formatVersion`; a reader refuses versions it does not know. Schema changes in an adapter are forward-only and never rewrite `used`, revisions, epochs, or capture state.

## 12. Open questions

- Whether `entryId` derivation should be keyed for deployments that treat issued tokens as low-sensitivity but long-lived log content.
- A `LifecycleAuthority` interface (an external monotonic ledger) and the operations to reconcile recovered captures against it.
- A store without a clock of its own (for example a conditional-write key-value service): how expiry is judged at commit. Version 1 refuses such a store.
- A bounded, ciphertext-only enumeration of captures by key reference, to drive re-wrap.
- An aggregate per-tenant quota enforced in `createCapture`.
- Padding of payloads to hide value length.
- Resumable encrypted result delivery.
