---
decision_id: decision-decide-stores-without-a-clock
status: proposed
scope: repository
title: Decide whether contract version 2 may judge expiry on a caller clock for stores without storeClock
proposed_at: 2026-10-01
amends: decision-supersede-persistent-store-contract (specification §7.5, §8.2, §12 only)
---
# Decide whether contract version 2 may judge expiry on a caller clock for stores without `storeClock`

> **Proposed.** Nothing here is implemented, and nothing here is accepted until the maintainer accepts it. It answers [#131](https://github.com/redact-secret/redact-secret-vault/issues/131), under epic [#4](https://github.com/redact-secret/redact-secret-vault/issues/4), raised by the [backend capability research](../research/persistent-backend-capabilities.md) ([#114](https://github.com/redact-secret/redact-secret-vault/issues/114)), sections 4 and 11. It is a specification and decision record, not an adapter. Contract version 1 is unchanged by it.

## Context

Contract version 1 requires `storeClock` ([specification](../specs/persistent-vault.md) §7.5, §8.2, §12). The store judges expiry at commit on its own clock and rejects `clock-skew` when a caller's `now` differs from that clock by more than `maxClockSkewMs`. The persistent factory fails `UNSUPPORTED_STORE` when `storeClock` is false, and §12 lists "a store without a clock of its own" as an open question that version 1 refuses.

The research found that DynamoDB condition expressions have no time function (research D15) and that AWS's own expiry examples take the time from the client (D16). No DynamoDB profile therefore satisfies version 1 as written. An adapter that declared `storeClock: true` while passing its host's time into a condition would declare something false. The issue states the consequence: if the revision is declined, DynamoDB is declined as a backend.

This record decides the revision, not the adapter. It stays inside the research's candidate profile (`dynamodb-single-region`, §4.1); it does not reopen the rejected profiles of §4.2.

### Inputs and their status

Statements about DynamoDB below came first from the research's reading of AWS documentation. The follow-up [DynamoDB profile inputs](../research/dynamodb-profile-inputs.md) re-fetched the primary pages on 2026-10-01, quotes each finding, and labels it documented, not documented, or needing a measurement on the real service. Nothing was measured on a service, and the one local run (DynamoDB Local) is labelled as not service behavior. Implementation is on hold by maintainer decision; this record is still `proposed`.

| Input | Status, with the finding that settles it |
| --- | --- |
| Conditions have no clock (D15); AWS examples use the client's time (D16) | Documented. [Finding d](../research/dynamodb-profile-inputs.md#6-finding-d-time-in-conditions-and-the-options): the grammar lists six functions, none returns time |
| Transactions are serializable against a standard `UpdateItem`; a colliding transaction is cancelled, not queued (D5, D19) | Documented. [Finding a](../research/dynamodb-profile-inputs.md#3-finding-a-check-only-transactions-on-the-same-item) quotes the conflict rule and the `TransactionConflict` reason |
| Item overhead, 4 MB aggregate ("aggregate size of the items", D1) | The wording is documented, and 4 MB is 4 194 304 bytes (the constraints page defines 1 MB = 1024 KB). Whether `Update` and `ConditionCheck` actions count the whole stored item is **not documented**; needs a service measurement ([finding b](../research/dynamodb-profile-inputs.md#4-finding-b-transaction-limits-and-size-accounting), experiment B) |
| Whether two transactions whose only shared item is under a `ConditionCheck` in both conflict | **Not documented.** The pages support two readings; needs a service measurement ([finding a](../research/dynamodb-profile-inputs.md#3-finding-a-check-only-transactions-on-the-same-item), experiment A). DynamoDB Local does not throw conflicts, so it cannot answer. If they do conflict, the recovery record serializes every commit and create in a namespace |
| Per-item overhead for the planned key and attribute names | The size formulas are documented ([finding g](../research/dynamodb-profile-inputs.md#7-finding-g-the-400-kb-item-limit-and-the-about-40-kib-envelope-figure)); the exact figure for the planned layout needs a measurement (experiment B) |
| Whether `CancellationReasons` flags every failing item | The list shape (one entry per item, `None` for no error) is documented. Whether every failing item is flagged when several fail needs a measurement (experiment D); the research's fallback does not depend on it |
| `ReturnValuesOnConditionCheckFailure` inside transactions | Documented shape: valid values `NONE` and `ALL_OLD`, returned in `CancellationReason.Item` ([finding a](../research/dynamodb-profile-inputs.md#3-finding-a-check-only-transactions-on-the-same-item)) |
| A stable, unique table identity usable for `restoreDetection` | `TableId` is documented as unique and generated at creation, and restore always creates a new table. That a restore yields a different `TableId` needs a measurement (experiment C); blind spots in [finding f](../research/dynamodb-profile-inputs.md#9-finding-f-restoredetection-and-its-blind-spots). `restoreDetection` stays `"none"` until then |
| TTL never deletes before its timestamp | Documented by definition ("the item expires after that time"), not as a guarantee sentence ([finding d](../research/dynamodb-profile-inputs.md#6-finding-d-time-in-conditions-and-the-options)). The guard (TTL on the retention bound) does not depend on it |
| The "about 40 KiB" envelope figure | Recomputed from the contract ceilings: 39 to 46 KiB under the whole-item assumption ([finding g](../research/dynamodb-profile-inputs.md#7-finding-g-the-400-kb-item-limit-and-the-about-40-kib-envelope-figure)). The figure holds; it is conditional on the unverified size basis |

Nothing in this record depends on the unverified rows being favourable except where marked. Two of them (check-only conflict, 4 MB accounting) decide whether a DynamoDB profile is usable at all, and neither can be settled by reading: the experiments, tables, and costs are specified in [section 10 of the findings](../research/dynamodb-profile-inputs.md#10-experiments-that-need-the-real-service-specified-not-run), with a work breakdown for the case the maintainer later schedules the profile. No finding contradicts a fact stated above, and none changes the recommendation.

## Decision (proposed)

### 1. Caller-clock expiry

**Recommendation: decline.** Contract version 2 should not add a mode in which expiry is judged on the caller's clock. Contract version 1 and its `storeClock` requirement stand, and a store without a clock stays refused.

Reasons:

1. **It removes the only check on the direction that matters.** Skew has two directions. A host whose clock runs ahead denies early: an availability failure that is safe. A host whose clock runs behind accepts a restore after the authenticated `expiresAt`: the security failure. In version 1 the store's clock plus `maxClockSkewMs` bounds that extension to the bound, and a drifting server fails closed. With a caller clock, one host with a stalled or set-back clock extends every lifetime it commits by the full error, nothing in the store sees it, and two servers disagree about expiry by exactly their difference ([research §4.1](../research/persistent-backend-capabilities.md)). The 24-hour ceiling on a capture limits the effect to a day plus the error, but the error itself has no ceiling.
2. **The weakened claim has no enforcement to point to.** [CONVENTIONS](../../CONVENTIONS.md) treats exact TTL values as claims that need an implementation and evidence. A stated assumption ("every host keeps its clock within *B* of true time") is a deployment requirement, not evidence, and the vault would stop being able to test it. The optional hardening that could partly replace the check, a non-decreasing high-water mark of accepted `now`, turns the recovery record from a check into an update in every commit, so it is the very contention the unverified input above asks about. The research does not recommend it without measurement.
3. **The rest of the revision is large and leaves the profile weak.** Caller-clock mode is one of four changes (below). The profile it would admit has `restoreDetection: "none"`, an envelope bound near 40 KiB unless a restore byte bound is also added, an unsolved namespace-empty proof, and a throughput question that may be fatal. Version 1's guarantees would be restated per backend.
4. **A supported alternative for AWS users exists.** `@redact-secret/store-postgres` runs on a managed PostgreSQL service, and `@redact-secret/key-provider-aws-kms` is independent of the store. The vault does not need DynamoDB to serve an AWS deployment.

Declining does not close the question for good. The record should be reopened, not re-argued, if all of these hold:

- both unverified conditions above are measured against a real table and are favourable (check-only overlap does not serialize a namespace; item accounting leaves a usable envelope bound);
- an adopter states a deployment that cannot use a store with its own clock; and
- the maintainer accepts that the skew assumption below becomes a documented deployment requirement of that profile.

### 2. Terms if the maintainer accepts anyway

These make the revision decidable. They are not a recommendation to adopt it.

**Capabilities and opt-in.** A new capability `clockSource: "store" | "caller"` replaces reading `storeClock` alone; `maxClockSkewMs` is then the *assumed* bound, not an enforced one. The persistent factory refuses `"caller"` unless the application passes an explicit option (working name `allowCallerClockExpiry: true`), in the way `allowNonDurableStore` and `allowNoRestoreDetection` exist. The option also takes the application's stated skew bound `B`; there is no default. The factory writes `B` into audit events at startup and into the capture's receipts bound. A `contractVersion` of 2 is required to declare `"caller"`, so a version 1 factory still refuses these stores.

**Skew assumption.** Every server host of the namespace keeps its clock within `B` of true time. The effective error of every lifetime is `B`. Two servers can disagree about expiry by up to `2B`. Nothing in the store detects a violation.

**`createdAt`, `expiresAt`, receipts.** Set from the caller's `now`, as now. `receiptExpiresAt` adds `B` as now (§7.5), and should add `2B` in this mode so a replay from a server whose clock is `B` behind is still denied.

**Fence and tombstone timestamps.** `revokeCapture` with `fenceAbsent` cannot take the store's clock. It records `createdAt = now` and `expiresAt = now + 24 h + 2B`: the latest moment any capture with that identifier could still have been valid on a clock in bound, which is the 24-hour lifetime ceiling plus the error. The tombstone is kept until `max(expiresAt, now) + retentionMs + 2B`, all on caller values. The caller's `now` that was "informational" in §5.6 becomes load-bearing for retention, and is only ever used to keep a row longer when it errs high.

**`deleteCiphertext` and `sweepExpired`.** With no store clock there is nothing to compare `now` against, so the version 1 `clock-skew` rejection cannot exist. A row is removed on expiry only when `now >= expiresAt + 2B`, and receipts and tombstones only strictly past their bounds as now. This is safe in one direction: a host whose clock is ahead can delete rows early, which only denies. A host whose clock is behind deletes late, which changes storage use, never authorization. A revoked capture's ciphertext can still be deleted regardless of time, as in §5.7.

**Commit.** Expiry is a condition on the caller's `now` inside the transaction (`expiresAt > :now`). The condition cannot compare against a store time, so version 2 must not label this expiry "judged by the store". Specification §7.5 would describe the two modes separately.

**Byte bound for restore.** Independent of the clock and not decided here beyond this: version 1 has `maxCreateBytes` but no byte bound on `commitRestore` or `readEntries`. A store with a per-transaction byte cap can stay honest only by declaring a small `maxEnvelopeBytes` (about 40 KiB under the research's whole-item assumption) or by the contract gaining `maxRestoreBytes`, a sum of envelopes in one restore, checked by the server before it asks the store. If a store of this kind is ever admitted, add `maxRestoreBytes`; shrinking `maxEnvelopeBytes` instead would silently lower the vault's value limit for that backend. This is also unverified: it depends on the 4 MB accounting row above. No other store needs it today.

**Namespace-empty proof for key-value stores.** §5.8 requires `initializeNamespace` to refuse when any capture, entry, or receipt row exists. The DynamoDB pages read offer `Query` and `Scan`, which are read-committed (D5), so a read followed by a write is not an atomic proof. The only design the research names is a per-namespace row counter maintained inside every create and sweep transaction. That puts a write on one shared item in every create, which is the same contention as above. The alternative that avoids it is to change the contract so emptiness is an operational precondition, not a store proof: the operator attests the namespace is fresh (a new table, or a prefix never used), and `initializeNamespace` records that attestation and refuses only on `exists`. That weakens §5.8 and would need the threat model updated. A third, counter-free design is possible if every row-writing transaction already checks the recovery item (an inference, [finding e](../research/dynamodb-profile-inputs.md#8-finding-e-proving-a-namespace-empty-in-a-key-value-store)). This record does not choose among them, because the choice depends on a measurement that has not been made.

### 3. What happens next

- If declined: no DynamoDB adapter issue is opened, DynamoDB is declined as a backend, and the research's DynamoDB section is marked declined with a link to this record. Specification §12 keeps its open question, reworded to point here.
- If accepted: a contract version 2 change to specification §3.6, §4, §5.6, §5.7, §5.8, §7.5, §8.2, and §12, and a threat-model update, comes first. A DynamoDB adapter issue is opened only after the two measurements, and the research's starting limits (restore: entries + captures + 2 ≤ 100; create: at most 98 entries; global tables, MRSC and MREC, rejected) carry over unchanged.

## Consequences

- No code, package, test, or published behavior changes. The status of version 1 and of the alpha packages is the same.
- Declining leaves the vault with one qualified store (PostgreSQL) and the in-memory test store. The research's Redis and SQLite proposals do not depend on this record.

## Alternatives considered

- **Accept caller-clock expiry with the high-water mark enabled by default.** Rejected: it reintroduces the contention the unverified input asks about, and a mark protects against a clock that moves back after a commit, not against one that was always behind.
- **Declare `storeClock: true` and pass the host clock into conditions.** Rejected: it is a false capability declaration (research D15).
- **Use the HTTP `Date` response header as the store clock.** Rejected: the pages read do not document it as a clock contract.
- **Use native TTL as expiry.** Rejected: TTL deletes late and items stay visible after expiry (D13, D14).
- **Put a time-service item in the table and compare against it.** Not evaluated; it would need a trusted writer and an update on a shared item, so it inherits the contention concern and adds a new authority. Listed so it is not rediscovered as free.

## Open questions

- The two unverified conditions above, measured on a real table.
- The namespace-empty design, if a key-value store is ever admitted.
- Whether a restore byte bound is wanted independent of any backend.

Refs #131
