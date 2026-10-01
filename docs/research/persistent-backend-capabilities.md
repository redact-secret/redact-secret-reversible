# Persistent backend capability research: DynamoDB, Redis, SQLite

**Status: research, not a support claim.** Nothing here says that an adapter exists, is planned for a release, or has been qualified. It records what the vendors' own documentation says each backend can and cannot provide for the proposed `Store` contract in [persistent-vault.md](../specs/persistent-vault.md) (§3.6, §4, §5, §7, §8.2, §9, as revised after its design review), which is itself proposed and not implemented. Tracking issue: [redact-secret-vault#114](https://github.com/redact-secret/redact-secret-vault/issues/114).

## 1. Method

- Sources are primary documentation only: `docs.aws.amazon.com` for DynamoDB, `redis.io` for Redis Open Source (single node, Sentinel, Cluster), `sqlite.org` for SQLite. No blog posts, no third-party analyses, no recollection.
- Every page was fetched on **2026-10-01**. For redis.io the Markdown rendition of each page (`…/index.html.md`) was read; the URLs below are the canonical HTML pages.
- A bare `§` reference (for example §5.2, §7.5, §9.3) always means a section of the specification as revised after its design review, never of this document. This document's own sections are called "section N".
- Each evidence item has an identifier (`D…`, `R…`, `S…`), a quotation or close paraphrase, and its URL. Quotations are verbatim apart from line wrapping. Matrix cells cite those identifiers.
- Statements marked **Inference** are conclusions drawn here from the cited evidence. They are not vendor statements.
- Nothing was executed against any backend. Every "yes" below means "the documentation says so", and still has to be shown by a qualification run (section 10 below).
- Where documentation is silent or ambiguous, that is said, and collected in section 11 below.

What the contract needs, in short (numbering used by the matrix):

| # | Requirement | Spec |
| --- | --- | --- |
| C1 | One atomic create-if-absent transaction for a capture row (which carries the capture's `keyRef` and `wrappedKey`) and all its entry rows, bounded by `maxCreateEntries` and `maxCreateBytes` | §5.3, §3.6 |
| C2 | One atomic conditional transaction per restore: every entry (revisions, budget), every named capture (state, generation, epoch, expiry), the namespace recovery record, and the insert of an attempt receipt | §5.5 |
| C3 | A durable revocation fence: an acknowledged revoke or consumed use is not lost | §5.6, §7.1, §7.6 |
| C4 | Conditions evaluated against authoritative, non-stale state | §5.5, §5.6 |
| C5 | A store clock that judges expiry and skew (`storeClock`, `maxClockSkewMs`). Required in contract version 1 | §7.5, §8.2, §12 |
| C6 | Bounded cleanup that is never the authorization mechanism; native TTL never deletes early | §5.7 |
| C7 | Receipt and tombstone retention until their stated bound | §5.6, §7.5 |
| C8 | Independent processes share one authoritative state | §4 `crossProcess`, §8.2 |
| C9 | Backup, rollback, or lossy failover can be met with the quarantine and epoch runbook; a stated `restoreDetection` | §5.8, §9.3 |
| C10 | Finite, declarable batch bounds; no splitting | §5, §3.6 |
| C11 | Conflict rule: a commit or create is serialized against a concurrent revoke of a capture it names and against a concurrent quarantine or invalidation of its namespace | §5.2 |
| C12 | `readEntries` returns one consistent snapshot of the recovery record, the entries, and their captures | §5.4 |

## 2. Capability matrix

`yes` = documented and sufficient under the stated configuration. `conditional` = holds only under a restriction named in the footnote. `no` = documented as not provided, or documented as unreliable.

| Requirement | DynamoDB single-Region | DynamoDB global tables | Redis single node, AOF `always` | Redis Sentinel / replicated | Redis Cluster | SQLite local disk, WAL | SQLite network filesystem |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1 atomic create | conditional [a] | no [b] | yes [g] | conditional [k] | conditional [m] | yes [p] | no [u] |
| C2 atomic restore | conditional [a] | no [b] | yes [g] | conditional [k] | conditional [m] | yes [p] | no [u] |
| C3 durable fence | yes [c] | no [b] | conditional [h] | no [l] | no [l] | conditional [q] | no [u] |
| C4 authoritative evaluation | yes [c] | no [b] | yes [g] | no [l] | no [l] | yes [p] | no [u] |
| C5 store clock | **no** [d] | **no** [d] | yes [i] | conditional [i] | conditional [i] | yes [r] | yes [r] |
| C6 cleanup not authorization | yes [e] | conditional [e] | conditional [j] | conditional [j] | conditional [j] | yes [s] | yes [s] |
| C7 receipt/tombstone retention | yes [e] | no [b] | conditional [j] | no [l] | no [l] | yes [s] | no [u] |
| C8 cross-process | yes [c] | no [b] | yes [g] | no [l] | no [l] | conditional [t] | no [u] |
| C9 rollback recovery | conditional [f] | conditional [f] | conditional [n] | conditional [n] | conditional [n] | conditional [n] | no [u] |
| C10 finite bounds | yes [a] | no [b] | conditional [o] | conditional [o] | conditional [m] | yes [p] | no [u] |
| C11 conflict rule | conditional [v] | no [b] | yes [g] | conditional [k] | conditional [m] | yes [x] | no [u] |
| C12 consistent read snapshot | conditional [w] | no [b] | yes [g] | conditional [k] | conditional [m] | yes [x] | no [u] |

Because contract version 1 requires `storeClock` (§7.5, §8.2), the two "no" cells in row C5 mean that **no DynamoDB profile satisfies contract version 1 as written**, whatever the other rows say.

Footnotes:

- **[a]** `TransactWriteItems` is all-or-nothing with per-item conditions, but capped at 100 actions, 4 MB aggregate, 400 KB per item, one action per item (D1, D2, D3, D4). The contract's ceilings (1024 entries, 1 MiB + 64 KiB envelope) cannot be met; an adapter would declare smaller bounds (section 4.1 below).
- **[b]** MREC global tables: transactions are atomic only in the invoking Region, are not replicated as a unit, conflicts resolve last-writer-wins, and conditions see only the local version (D9, D10, D11). MRSC global tables: transaction operations return an error (D12). Neither mode supports C1, C2, C11, or C12 across Regions.
- **[c]** A 200 response means the write is durably persisted (D7); transactional operations are serializable against each other and against single-item reads and writes (D5); `ConsistentRead` reflects all prior successful writes on the base table (D7). GSIs are always eventually consistent and must not be used for any authorization read (D8).
- **[d]** Condition expressions have no time function; every documented example computes "now" in the client (D15, D16). **Inference:** expiry can only be judged with a caller-supplied timestamp, so `storeClock` cannot honestly be `true`, and the persistent server factory refuses the store (§8.2).
- **[e]** TTL deletes after the timestamp, "typically within a few days", and expired items stay readable and writable until then (D13, D14). It therefore never deletes early and can never be the expiry check. MRSC does not support TTL (D12). MREC replicates TTL deletes (D13).
- **[f]** Backup and point-in-time restores always create a new table, do not carry TTL or Streams settings, and "do not guarantee causal consistency across items"; a restore can contain part of a recent transaction (D1, D17, D18). The §9.3 runbook applies. Version 1 offers no way to return recovered captures to service, which is the only sound choice for a restored table of this kind.
- **[g]** Scripts and functions execute atomically and block all other server activity (R1). One server, one keyspace: every read inside a script is authoritative, a read-only script is a consistent snapshot, and no revoke, quarantine, or invalidation can run between a commit script's checks and its writes.
- **[h]** Only with `appendonly yes` and `appendfsync always`, where the fsync precedes the reply (R6). With `everysec` one second of acknowledged writes can be lost; with RDB only, minutes (R5, R6). Also depends on the device honouring fsync, which Redis cannot verify.
- **[i]** `TIME` may be called inside a script before writes under effects replication, the only mode since 7.0 (R4). It is the host wall clock. On a replicated deployment the clock belongs to whichever node is master, so it changes on failover.
- **[j]** Only with `maxmemory-policy noeviction` (or no `maxmemory`). Any `allkeys-*` policy can evict a fence or receipt; any `volatile-*` policy can evict any key that carries a Redis TTL (R12). Native key expiry follows the server's wall clock (R13).
- **[k]** Atomic, serialized, and snapshot-consistent on the master that ran the script; the effects reach replicas as one MULTI/EXEC (R3). Atomicity is not the problem on this profile; durability is ([l]).
- **[l]** "Sentinel + Redis distributed system does not guarantee that acknowledged writes are retained during failures" (R8). Redis Cluster "will lose writes that were acknowledged by the system to the client" (R10). `WAIT` and `WAITAOF` do "not make Redis a strongly consistent store" (R7). A lost revoke or lost consumed use violates C3, C4, C7, and the one-use rule of §7.1. §7.6 names this case: promoting a replica that may lack acknowledged commits is a rollback.
- **[m]** All keys of one script must be in one hash slot (R11). **Inference:** because every commit and create touches the namespace recovery record, the whole namespace must share one hash tag, so Cluster provides no sharding for this workload, and still has [l].
- **[n]** Possible through the §9.3 runbook, since the recovery record and the epoch stamped on each capture are ordinary data that a restored copy carries at their old values. Not automatic: restoring an RDB/AOF file or an SQLite backup file is silent. What `restoreDetection` could honestly say is discussed per profile below.
- **[o]** No hard key-count limit for a script was found in the pages read. The bound is latency: a script blocks every other client for its whole run (R1, R2). The declared maxima must come from measurement.
- **[p]** SQLite transactions are atomic and serializable with a single writer (S1, S2). Limits are far above the contract's ceilings (S14).
- **[q]** Durable only with `synchronous=FULL` in WAL mode, or `synchronous=EXTRA` with a rollback journal (S3). `synchronous=NORMAL` in WAL "does lose durability" across power loss (S3). Depends on a device that honours sync (S10).
- **[r]** `'now'` is the host clock through the VFS (S13), read by the store inside its transaction, so `storeClock` is literally true. Every process is on one host by requirement, so the store and the servers normally share that clock: the skew check only bites when an application injects its own `now`, and of the two cases in §7.5 only "set back together" can occur.
- **[s]** No native TTL exists. Cleanup is bounded deletes inside ordinary transactions; nothing is removed unless the adapter removes it.
- **[t]** Multiple processes are supported only on the same host and, in WAL mode, with shared memory (S4, S5). Connections must not cross `fork()` (S9).
- **[u]** "WAL does not work over a network filesystem" (S4). Rollback-journal mode depends on file locks that "have been known to operate incorrectly for some network filesystems. This has led to database corruption" (S7, S8).
- **[v]** Met optimistically, as §5.2 allows, by putting a `ConditionCheck` on the recovery item and on every named capture item inside the same `TransactWriteItems`; a transaction is serializable against a concurrent single-item write and against another transaction (D5). The condition: transactions that share an item, even only for a check, are documented as conflicting with each other (D19), so the shared recovery item may make unrelated commits in one namespace cancel each other. See section 4.1.
- **[w]** `TransactGetItems` gives an atomic read of up to 100 items and 4 MB from base tables (D5, D6). `readEntries` receives entry identifiers only, so capture keys must be learned first; the snapshot is a second, transactional read. The 4 MB cap bounds the envelopes one read can return. See section 4.1.
- **[x]** `BEGIN IMMEDIATE` makes the transaction the only writer from its first statement (S2), so a revoke, quarantine, or invalidation on another connection commits either before it starts or after it commits. A read transaction sees one snapshot (S2).

## 3. DynamoDB evidence

**D1. `TransactWriteItems` is all-or-nothing, 100 actions, same account and Region, 4 MB.**
"`TransactWriteItems` is a synchronous and idempotent write operation that groups up to 100 write actions in a single all-or-nothing operation. These actions can target up to 100 distinct items in one or more DynamoDB tables within the same AWS account and in the same Region. The aggregate size of the items in the transaction cannot exceed 4 MB. The actions are completed atomically so that either all of them succeed or none of them succeeds." The same page: "Transactions cannot be performed using indexes", and "if a table is restored from backup (RestoreTableFromBackup) or exported to a point in time (ExportTableToPointInTime) mid-propagation, it can contain only some of the changes made during a recent transaction."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>

**D2. One action per item; `ConditionCheck` is an action.**
"You can't target the same item with multiple operations within the same transaction. For example, you can't perform a `ConditionCheck` and also an `Update` action on the same item in the same transaction." Action types are `Put`, `Update`, `Delete`, and `ConditionCheck` ("Checks that an item exists or checks the condition of specific attributes of the item"). The API reference states `TransactItems` is "An ordered array of up to 100 `TransactWriteItem` objects … Maximum number of 100 items."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html>

**D3. Constraints page restates the limits.**
"A transaction cannot contain more than 100 unique items. A transaction cannot contain more than 4 MB of data. No two actions in a transaction can work against the same item in the same table. … A transaction cannot operate on tables in more than one AWS account or Region." Also: "The maximum item size in DynamoDB is 400 KB, which includes both attribute name binary length (UTF-8 length) and attribute value lengths", "The maximum length of any expression string is 4 KB", and "The maximum number of operators or functions allowed in a single expression is 300."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Constraints.html>

**D4. `ClientRequestToken` idempotency lasts 10 minutes.**
"A client token is valid for 10 minutes after the request that uses it finishes. After 10 minutes, any request that uses the same client token is treated as a new request." A repeat within the window with different parameters returns `IdempotentParameterMismatch`. The API reference gives the token "Maximum length of 36". A successful repeat "return[s] successfully without making any changes".
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html>

*Why this is not an attempt receipt (**Inference**):* §7.5 keeps a receipt until the latest capture expiry plus skew plus a grace period, which can exceed 25 hours; the token is forgotten after 10 minutes, after which the same request would be applied again. A token cannot be read back (`inspectAttempt` has nothing to read), and it does not store the request digest that distinguishes `already-committed` from `attempt-mismatch` beyond its window. The receipt must be an item written by the same transaction with `attribute_not_exists`. The token is still useful for one narrower purpose: making an SDK-level retry of the *same* call return success instead of tripping over its own receipt.

**D5. Isolation levels.**
Serializable "Between any transactional operation and any standard write operation (`PutItem`, `UpdateItem`, or `DeleteItem`)", "Between any transactional operation and any standard read operation (`GetItem`)", and "Between a `TransactWriteItems` operation and a `TransactGetItems` operation." But: "The isolation level is read-committed between any transactional operation and any read operation that involves multiple standard reads (`BatchGetItem`, `Query`, or `Scan`)", and `BatchWriteItem` as a unit is "NOT Serializable". Several independent `GetItem` calls against a concurrent transaction "can be run in any order, and therefore the results are read-committed"; "You should use `TransactGetItems` if you prefer serializable isolation level for multiple `GetItem` requests."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>

**D6. `TransactGetItems`.**
"`TransactGetItems` is a synchronous operation that atomically retrieves multiple items from one or more tables (but not from indexes) in a single account and Region. A `TransactGetItems` call can contain up to 100 `TransactGetItem` objects … The aggregate size of the items in the transaction cannot exceed 4 MB." It is rejected when "A conflicting operation is in the process of updating an item to be read."
<https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactGetItems.html>

**D7. Durability of an acknowledged write; strongly consistent reads.**
"When your application writes data to a DynamoDB table and receives an HTTP 200 response (OK), that means the write completed successfully and has been durably persisted." "If you set `ConsistentRead` to true, DynamoDB returns a response with the most up-to-date data, reflecting the updates from all prior write operations that were successful." Eventually consistent is the default for every read. After a transaction, "subsequent eventually consistent read operations may still return the old state for a short period … you should use strongly consistent reads by setting `ConsistentRead` to true."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>

**D8. Global secondary indexes are never strongly consistent.**
"Strongly consistent reads are only supported on tables and local secondary indexes. Strongly consistent reads from a global secondary index or a DynamoDB stream are not supported." GSIs "are updated asynchronously, using an eventually consistent model."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html>

**D9. Global tables have two consistency modes.**
"Global tables support two consistency modes: multi-Region eventual consistency (MREC) and multi-Region strong consistency (MRSC). If you do not specify a consistency mode when creating a global table, the global table defaults to multi-Region eventual consistency (MREC). … You cannot change a global table's consistency mode after creation." "Any global table replica can serve reads and writes."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html>

**D10. MREC: asynchronous, last writer wins, conditions see the local version.**
"Item changes in an MREC global table replica are asynchronously replicated to all other replicas, typically within a second or less." "If the same item is modified in multiple Regions simultaneously, DynamoDB will resolve the conflict by using the modification with the latest internal timestamp on a per-item basis, referred to as a 'last writer wins' conflict resolution method." "Strongly consistent read operations return the latest version of an item if that item was last updated in the Region where the read occurred, but may return stale data if the item was last updated in a different Region. Conditional writes evaluate the condition expression against the version of the item in the Region." MREC has "a Recovery Point Objective (RPO) equal to the replication delay between replicas, usually a few seconds".
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html>

**D11. MREC: transactions are not replicated as a unit.**
"On a global table configured for MREC, DynamoDB transaction operations (`TransactWriteItems` and `TransactGetItems`) are only atomic within the Region where the operation was invoked. Transactional writes are not replicated as a unit across Regions, meaning only some of the writes in a transaction might be returned by read operations in other replicas at a given point in time." The transactions page adds: "Transactions aren't supported across Regions in global tables."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>

**D12. MRSC: synchronous and strongly consistent, but no transactions and no TTL.**
"Item changes in an MRSC global table replica are synchronously replicated to at least one other Region before the write operation returns a successful response. Strongly consistent read operations on any MRSC replica always return the latest version of an item. Conditional writes always evaluate the condition expression against the latest version of an item." It "must be deployed in exactly three Regions", supports "a Recovery Point Objective (RPO) of zero", and a write "fails with a `ReplicatedWriteConflictException` when it attempts to modify an item that is already being modified in another Region." However: "Global tables configured for multi-Region strong consistency (MRSC) do not support transaction operations, and will return an error if those operations are invoked on an MRSC replica", "Time to Live (TTL) is not supported for MRSC global tables", and "Local secondary indexes (LSIs) are not supported for MRSC global tables."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html>

**D13. TTL deletion is delayed and in seconds.**
"DynamoDB automatically deletes expired items within a few days of their expiration time, without consuming write throughput." "The timestamp must be stored as a Number data type in Unix epoch time format at the seconds granularity." "Items with valid, expired TTL attributes might be deleted by the system at any time, typically within a few days after their expiration. You can still update the expired items that are pending deletion, including changing or removing their TTL attributes." For global tables version 2019.11.21, "DynamoDB replicates TTL deletes to all replica tables."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html>

**D14. Expired items remain visible until deleted.**
"Expired items that are pending deletion can be filtered from read and write operations. … If they are not filtered, they'll continue to show in read and write operations until they are deleted by the background process." "A condition expression can be used to avoid writes against expired items."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html>

**D15. Condition expressions have no clock.**
The documented grammar allows operands that are "A top-level attribute name" or "A document path that references a nested attribute" (plus expression attribute values), the comparators `= <> < <= > >=`, `BETWEEN`, `IN`, and exactly these functions: `attribute_exists`, `attribute_not_exists`, `attribute_type`, `begins_with`, `contains`, `size`. No function returns the current time.
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html>

**D16. AWS's own expiry examples take the time from the client.**
"the filter expression can filter out items where the TTL time is equal to or less than the current time. For example, the Python SDK code includes an assignment statement that obtains the current time as a variable (`now`)". The conditional-write example likewise "checks whether the expiration time is greater than the current time" using a client-computed value.
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html>

**D17. Point-in-time recovery restores to a new table and drops settings.**
PITR provides "up to 35 days of recovery points at a per second granularity"; "`LatestRestorableDateTime` is typically five minutes before the current time"; "The point-in-time recovery process always restores to a new table." After a restore "you must set up the following on the new table yourself, because a restore does not carry them over: auto scaling policies, AWS Identity and Access Management policies, CloudWatch metrics and alarms, tags, DynamoDB Streams settings, Time to Live settings, and point-in-time recovery settings." For a global table replica, "the backup restores to an independent table that is not part of the global table."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Point-in-time-recovery.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.Tutorial.html>

**D18. Backups are not causally consistent across items.**
"DynamoDB backups do not guarantee causal consistency across items; however, the skew between updates in a backup is usually much less than a second."
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CreateBackup.html>

**D19. Failed transactions and SDK retries.**
"If any item-level request within `TransactWriteItems` or `TransactGetItems` is rejected, the request fails with a `TransactionCanceledException`. If that request fails, AWS SDKs do not retry the request. The exception contains the list of `CancellationReasons`, ordered according to the list of items in the `TransactItems` request parameter." Listed conflict scenarios include "An item within a `TransactWriteItems` request is part of another ongoing `TransactWriteItems` request"; such a transaction is cancelled, not queued. "default SDK behavior is to retry transactions in case of a `TransactionInProgressException`". Capacity "is consumed even when a transaction does not succeed", and every item costs two underlying writes.
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>

## 4. Candidate and rejected DynamoDB profiles

### 4.1 Candidate, not admissible under contract version 1: `dynamodb-single-region`

One table (or a fixed set of tables) in one Region and one account. Not a global table.

**Why it is not a version 1 profile.** §7.5 states "The persistent profile requires a store with `storeClock`", §8.2 has the factory fail `UNSUPPORTED_STORE` unless `storeClock` is true, and §12 lists "a store without a clock of its own" as an open question that "version 1 refuses". DynamoDB conditions have no clock (D15, D16). An adapter that set `storeClock: true` while passing its own host's time into conditions would be declaring something false. So this section describes what a DynamoDB profile would look like **after a contract revision**, and what that revision has to decide. Everything else about the backend is favourable, which is the reason to write it down.

**The contract change it needs**

- A second, explicitly weaker time mode, declared in capabilities, in which expiry at commit is judged with the caller's `now` and the store performs no skew check of its own.
- A stated deployment assumption in place of `maxClockSkewMs` enforcement: every server host keeps its clock within a stated bound of true time, and the effective error of every lifetime is that bound. Two servers whose clocks differ can disagree about whether a capture is expired by exactly their difference; nothing in the store detects it.
- A decision on what a fence written by `revokeCapture` with `fenceAbsent` records for `createdAt` and `expiresAt` (the spec says "the store's clock"), on how tombstone retention is anchored (§5.6 uses the store's clock at revocation), and on what `deleteCiphertext` and `sweepExpired` compare the caller's `now` against (§5.7 gives them a caller `now` precisely so that a store clock cannot act alone; without a store clock there is nothing to compare it with).
- An opt-in at the factory, in the way `allowNonDurableStore` and `allowNoRestoreDetection` exist, so that an application chooses caller-clock expiry knowingly.
- Optional hardening that the revision could consider and that this research does not recommend without measurement: a non-decreasing high-water mark of accepted `now` values. Keeping it on the recovery item turns that item from a check into an update in every commit, so every commit in the namespace would conflict with every other (D19).
- The HTTP `Date` response header is not documented as a clock contract in the pages read and must not be relied on.

**Configuration the profile would require**

- Every authoritative read uses `ConsistentRead: true` on the base table or `TransactGetItems`. No GSI and no DAX on any path the contract calls authoritative (D7, D8).
- All mutations that the contract calls a transaction go through `TransactWriteItems`. `BatchWriteItem` is never used (D5).
- Every row a commit touches is one item with a key derivable from the request or from a previous read: recovery record, capture, entry, receipt. No `Query` or `Scan` result may feed a condition (D5: both are read-committed).
- TTL, if enabled, is set on an attribute holding the retention bound (not the logical expiry) rounded **up** to whole seconds (D13). Expiry is always a condition on a separate millisecond attribute.

**Conflict rule, §5.2 (Inference from D2, D5, D19)**

DynamoDB has no locks to take, so this is the optimistic form the spec allows: "the transaction's conditions include those rows".

- `commitRestore` carries a `ConditionCheck` on the recovery item (`epoch = :epoch AND state = serving`) and a `ConditionCheck` on each named capture item (`state = live`, `generation = :g`, `epoch = :epoch`, `expiresAt > :now`). `createCapture` carries the same recovery `ConditionCheck`, and its capture `Put` is conditioned on `attribute_not_exists`.
- `revokeCapture` is a single conditional `UpdateItem` on the capture item. `quarantine` and `invalidateRecovered` are single conditional `UpdateItem` calls on the recovery item.
- A transaction is serializable against a standard `UpdateItem` (D5). So a revoke, quarantine, or invalidation takes effect entirely before the transaction, in which case the condition fails and nothing is applied, or entirely after it. That is the ordering §5.2 and §7.1 ask for.
- A transaction that collides with another in-flight transaction on an item is cancelled (`TransactionCanceledException`, reason `TransactionConflict`), and a cancelled transaction applies nothing (D1, D19). That maps to `rejected: "stale"`, as §5.2 requires for an abort.
- The capture's `epoch` is stamped at create and compared with the caller's epoch in the capture's own condition, so the "lower epoch means revoked" rule of §5.1 needs no cross-item comparison and no clock.
- **Liveness cost, unverified.** §5.2 notes that in a locking store "commits in one namespace … do not serialize on that record against each other". The DynamoDB documentation lists "An item within a `TransactWriteItems` request is part of another ongoing `TransactWriteItems` request" as a conflict without distinguishing a `ConditionCheck` from a write (D19). If check-only overlap does conflict, every commit and create in a namespace collides on the recovery item, and two restores naming the same capture collide on the capture item. That is safe (the loser is `stale` and retried, default 3 times, then `RESTORE_CONFLICT`) but could make a busy namespace unusable. This has to be measured before any profile is proposed.

**Transaction shape and the resulting maxima (Inference from D1–D3)**

One data key per capture means `keyRef` (at most 512 bytes) and `wrappedKey` (at most 4096 bytes) sit on the capture item; an entry item carries its envelope and a few small attributes.

`commitRestore`, one action per item (D2):

| Item | Action | Count |
| --- | --- | --- |
| Namespace recovery record | `ConditionCheck` | 1 |
| Attempt receipt | `Put` with `attribute_not_exists` | 1 |
| Each named capture | `ConditionCheck` | C |
| Each entry | `Update` conditioned on `captureId`, `lifecycleRevision`, `ciphertextRevision`, `used + count <= maxUses` | E |

So **E + C + 2 ≤ 100**, and since capabilities are static, `maxRestoreEntries + maxRestoreCaptures + 2 ≤ 100`:

| `maxRestoreCaptures` | Largest `maxRestoreEntries` |
| --- | --- |
| 1 | 97 |
| 8 | 90 |
| 16 | 82 |
| 34 | 64 |
| 64 (contract ceiling) | 34 |

The contract ceiling of 1024 entries per restore is out of reach by a factor of ten.

`createCapture`: one `Put` for the capture, one `ConditionCheck` on the recovery record, one `Put` per entry (each with `attribute_not_exists`): **E + 2 ≤ 100, so `maxCreateEntries ≤ 98`.**

Other operations: `replaceCaptureKey` is one conditional `UpdateItem` on the capture item (compare-and-swap on `keyRevision`; version 1 has no envelope replacement, so no entry item is touched). `deleteCiphertext` must remove every entry of a capture; with at most 98 entries, the capture item can hold the list of its entry identifiers (98 × 64 characters is about 6 KB), which makes the delete one transaction of at most 98 `Delete` actions plus one `Update` of the capture, with no index read. `initializeNamespace` must refuse when any row of the namespace exists; the pages read give no atomic way to test "no item with this prefix exists" together with a write, so this needs a design (for example a per-namespace row counter maintained in the create transaction, which would add a write on a shared item) and is listed in section 11.

**Size limits (Inference from D1, D3)**

- One item is at most 400 KB including attribute names. An entry item is its envelope plus identifiers and counters, so **`maxEnvelopeBytes` must be declared below 400 KB**, by a margin to be measured. The vault's default value limit of 8 KiB fits; its 1 MiB ceiling does not. A capture item is roughly 4.6 KB of key material plus identifiers, times, the session tag, and (if used) the entry list: about 12 KB at most, far below the item limit.
- **Create.** A transaction is at most 4 MB "aggregate size of the items". `maxCreateBytes` is defined as the sum of envelopes (§3.6), so the adapter must declare `maxCreateBytes ≤ 4 MB − capture item − maxCreateEntries × per-entry overhead − (possibly) the checked recovery item`. Before measurement, something near 3.5 MiB is plausible. `maxCreateBytes` answers the earlier question about a byte bound for create.
- **Restore and read.** Each entry `Update` targets an item that contains its envelope, and `readEntries` returns the envelopes. If the 4 MB aggregate counts whole items (not stated on the pages read), both `commitRestore` and the `TransactGetItems` snapshot are bounded by `maxRestoreEntries × (maxEnvelopeBytes + overhead) + maxRestoreCaptures × capture item ≤ 4 MB`. The contract has no `maxRestoreBytes`. An adapter can stay honest without one only by declaring `maxEnvelopeBytes` small enough that the product always fits: with 82 entries and 16 captures that is roughly 45 KiB per envelope; with 97 entries and 1 capture roughly 41 KiB. **So a DynamoDB profile either accepts an envelope bound near 40 KiB, or the contract gains a restore byte bound.** Splitting each entry into a small lifecycle item and an immutable envelope item would remove the envelope from the commit, but not from the read, and halves `maxCreateEntries` to 49; it is not recommended.
- Illustrative declaration, to be confirmed by measurement: `maxEnvelopeBytes` 32 KiB, `maxCreateEntries` 98, `maxCreateBytes` 3 MiB, `maxRestoreEntries` 82, `maxRestoreCaptures` 16.

**Consistent read snapshot, §5.4 (Inference from D5, D6)**

- `readEntries` is given entry identifiers, not capture identifiers. A first consistent read of the entry items yields each entry's `captureId`, which never changes. A second call, one `TransactGetItems` over the recovery item, the entry items, and those capture items, is the snapshot: **E + C + 1 ≤ 100** and at most 4 MB. The commit's `E + C + 2 ≤ 100` is the tighter count, so the declared restore bounds cover the read.
- `TransactGetItems` is rejected when it meets an in-flight write on one of its items (D6). That is a definite non-result and maps to `STORE_UNAVAILABLE` or an internal bounded retry of the read.
- Several `GetItem` calls, `BatchGetItem`, or `Query` are read-committed as a set (D5) and do not meet §5.4.
- `readCaptures` (at most 64 identifiers) fits one `TransactGetItems`.

**Rejection precedence, §5.5**

Only "quarantined, then receipt" are ordered; the rest is unspecified. On DynamoDB all conditions of a transaction are evaluated together and a failure returns `CancellationReasons` in request order (D19). **Inference:** if the recovery item is always the first action and the receipt the second, the adapter reports `quarantined` when the first reason is a condition failure, otherwise reads the receipt (consistent `GetItem`) when the second is, and compares digests. The pages read do not say whether every failing item is always flagged. If not, the adapter can classify after a cancellation with a `TransactGetItems` of the recovery item and the receipt; nothing was applied, so reporting what that read shows, in the required order, is truthful. Either way the two ordered reasons can be reported first. This closes the earlier open question, subject to the test in section 10.

**Receipts and tombstones**

- Receipt: an item keyed by scope and `attemptId`, holding the request digest and commit time, written by the commit transaction. `inspectAttempt` is a `GetItem` with `ConsistentRead: true`. The native `ClientRequestToken` is not a receipt (D4).
- Tombstone and fence: the capture item in state `revoked`, with empty key material where §5.1 says so.
- `revokeCapture` returns `entries`, which §5.6 calls informational; it can be read from the capture item's entry list in the same update.
- Removal by `sweepExpired` using conditional deletes, optionally backed by TTL on the retention-bound attribute. TTL only ever deletes late (D13), which §5.7 permits. A receipt may outlive `receiptExpiresAt` by days.

**Backup, rollback, and `restoreDetection`**

- Every restore path produces a new table (D17). Pointing servers at it is a deployment change, which fits step 1 of the §9.3 runbook (servers stopped or cut off before the recovered store accepts them).
- A restored table is not a transaction-consistent snapshot (D1, D18): it may hold a receipt without the matching budget decrement or the reverse. Version 1 only invalidates, which is the right treatment.
- TTL and Streams settings are not restored (D17); the runbook must re-enable TTL or accept sweep-only cleanup.
- `restoreDetection`: honestly `"none"` on the evidence gathered. A candidate is to record an identity of the table in the recovery item at `initializeNamespace` and compare it with what the control plane reports for the table in use, since a restore is always a different table. Which table attribute is stable and unique for that purpose was not established from the pages read, so it stays a candidate.

### 4.2 Rejected DynamoDB profiles

- **Global tables, MRSC.** Transaction operations return an error (D12). C1, C2, C11, and C12 cannot be implemented at all. Declined.
- **Global tables, MREC, written in more than one Region.** Conditions see only the local version, conflicts are last-writer-wins, and transactions arrive in pieces (D10, D11). Two Regions can each spend the same single-use entry, and a revoke in one Region can be overwritten by a later-stamped use in another. Declined.
- **Global tables, MREC, single write-and-read Region with passive replicas.** Technically the single-Region candidate plus a standby copy. Declined as a distinct profile: a Region failover has a non-zero RPO (D10), so by §7.6 the promoted replica is a rolled-back store and must go through the §9.3 runbook.
- **Any design that reads through a GSI or DAX, or with default (eventual) consistency, for commit, revoke, inspect, or the §5.4 snapshot.** D7, D8.
- **Using `ClientRequestToken` as the attempt receipt.** D4.
- **Using TTL as the expiry mechanism.** D13, D14.
- **Declaring `storeClock: true` for a DynamoDB adapter under contract version 1.** D15.

## 5. Redis evidence

**R1. Scripts and functions are atomic by blocking.**
"Redis guarantees the script's atomic execution. While executing the script, all server activities are blocked during its entire runtime." "The blocking semantics of an executed script apply to all connected clients at all times."
<https://redis.io/docs/latest/develop/programmability/eval-intro/>, <https://redis.io/docs/latest/develop/programmability/>

**R2. No rollback; what "atomic" means on error.**
For MULTI/EXEC: "A request sent by another client will never be served in the middle of the execution of a Redis Transaction." Errors after `EXEC` "are not handled in a special way: all the other commands will be executed even if some command fails during the transaction." "Redis does not support rollbacks of transactions". For scripts: errors from `redis.call()` "are returned directly to the client"; a script that exceeds `busy-reply-threshold` "isn't terminated by Redis automatically. Doing so would violate the contract between Redis and the scripting engine that ensures that scripts are atomic. Interrupting the execution of a script has the potential of leaving the dataset with half-written changes." Once such a script has written, "the only command allowed is `SHUTDOWN NOSAVE`". Under memory pressure, "the first write command encountered in the script that uses additional memory will cause the script to abort", and if the first write uses no additional memory "Redis will allow all commands in the script to run to ensure atomicity."
<https://redis.io/docs/latest/develop/using-commands/transactions/>, <https://redis.io/docs/latest/develop/programmability/eval-intro/>, <https://redis.io/docs/latest/develop/programmability/>

*Inference:* atomic means isolated and uninterrupted, not all-or-nothing. A script that raises after its first write leaves that write in place. An adapter script must finish every check before its first write, and its writes must be ones that cannot fail for type or argument reasons.

**R3. Script effects are propagated as one MULTI/EXEC.**
"When the script execution finishes, the sequence of commands that the script generated are wrapped into a `MULTI`/`EXEC` transaction and are sent to the replicas and AOF." "In Redis 5.0, effects replication became the default mode. As of Redis 7.0, verbatim replication is no longer supported." On the AOF side: "Redis makes sure to use a single write(2) syscall to write the transaction on disk. However if the Redis server crashes or is killed by the system administrator in some hard way it is possible that only a partial number of operations are registered. Redis will detect this condition at restart, and will exit with an error. Using the `redis-check-aof` tool it is possible to fix the append only file that will remove the partial transaction".
<https://redis.io/docs/latest/develop/programmability/eval-intro/>, <https://redis.io/docs/latest/develop/using-commands/transactions/>

**R4. `TIME` inside scripts.**
"When script effects replication is enabled, the restrictions on non-deterministic functions are removed. You can, for example, use the `TIME` or `SRANDMEMBER` commands inside your scripts freely at any place." `TIME` returns "the Unix timestamp in seconds and the microseconds' count." Also: "During Lua scripts executions no key expiries are performed. As a Lua script runs, conceptually the time in the master is frozen".
<https://redis.io/docs/latest/develop/programmability/eval-intro/>, <https://redis.io/docs/latest/commands/time/>, <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>

**R5. RDB alone loses minutes.**
"RDB is NOT good if you need to minimize the chance of data loss in case Redis stops working … you should be prepared to lose the latest minutes of data." "Snapshotting is not very durable. If your computer running Redis stops, your power line fails, or you accidentally `kill -9` your instance, the latest data written to Redis will be lost."
<https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/>

**R6. AOF fsync policies.**
"`appendfsync always`: `fsync` every time new commands are appended to the AOF. Very very slow, very safe. Note that the commands are appended to the AOF after a batch of commands from multiple clients or a pipeline are executed, so it means a single write and a single fsync (before sending the replies)." "`appendfsync everysec`: `fsync` every second. … you may lose 1 second of data if there is a disaster." "`appendfsync no`: Never `fsync` … Normally Linux will flush data every 30 seconds with this configuration". "The suggested (and default) policy is to `fsync` every second." After a crash "the last command in the AOF could be truncated", and Redis loads such a file when `aof-load-truncated` is enabled. AOF rewrite: "The rewrite is completely safe".
<https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/>

**R7. `WAIT` and `WAITAOF` are not strong consistency.**
"`WAIT` does not make Redis a strongly consistent store: while synchronous replication is part of a replicated state machine, it is not the only thing needed. … it is more likely (but not guaranteed) that if the master fails, we'll be able to promote, during a failover, a replica that received the write … this is just a best-effort attempt so it is possible to still lose a write synchronously replicated to multiple replicas." `WAIT` returns on timeout with a lower count, so "the client should check that the returned value is equal or greater to the replication level it demanded." Inside MULTI or a script "the command does not block but instead just return ASAP". `WAITAOF`: "similarly to `WAIT`, `WAITAOF` does not make Redis a strongly-consistent store. Unless waiting for all members of a cluster to fsync writes to disk, data can still be lost during a failover or a Redis restart." `WAITAOF` "cannot be used on replica instances", and is "incompatible" with scripts that use `redis.set_repl`.
<https://redis.io/docs/latest/commands/wait/>, <https://redis.io/docs/latest/commands/waitaof/>

*Inference:* both commands run after the script has already applied its writes on the master and other clients can already observe them. A `WAIT` that comes back short cannot undo the commit, so it cannot be a commit condition; it only tells the adapter the outcome is ambiguous.

**R8. Replication is asynchronous; Sentinel does not keep acknowledged writes.**
"Redis uses by default asynchronous replication". `WAIT` "is only able to ensure there are the specified number of acknowledged copies in the other Redis instances, it does not turn a set of Redis instances into a CP system with strong consistency: acknowledged writes can still be lost during a failover, depending on the exact configuration of the Redis persistence." Sentinel: "Sentinel + Redis distributed system does not guarantee that acknowledged writes are retained during failures, since Redis uses asynchronous replication." "In every Sentinel setup, as Redis uses asynchronous replication, there is always the risk of losing some writes because a given acknowledged write may not be able to reach the replica which is promoted to master." A partitioned old master keeps accepting writes and "This data will be lost forever since when the partition will heal, the master will be reconfigured as a replica of the new master, discarding its data set." `min-replicas-to-write` / `min-replicas-max-lag` bound that window (10 seconds in the documented example) but "because Redis uses asynchronous replication it is not possible to ensure the replica actually received a given write, so there is always a window for data loss."
<https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>, <https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/>

**R9. A master without persistence that restarts empties its replicas.**
"it is strongly advised to have persistence turned on in the master and in the replicas." With persistence off and auto-restart, "the node restarts with an empty data set" and the replicas "will replicate from node A, which is empty, so they'll effectively destroy their copy of the data."
<https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>

**R10. Redis Cluster loses acknowledged writes.**
"Redis Cluster does not guarantee strong consistency. In practical terms this means that under certain conditions it is possible that Redis Cluster will lose writes that were acknowledged by the system to the client." "Redis Cluster does not implement strong consistency even when synchronous replication is used: it is always possible, under more complex failure scenarios, that a replica that was not able to receive the write will be elected as master." The specification: "Redis Cluster uses asynchronous replication between nodes, and last failover wins implicit merge function. … There is always a window of time when it is possible to lose writes during partitions." On a minority partition "all the writes performed in the minority side up to that point may be lost" once the partition outlasts `NODE_TIMEOUT`.
<https://redis.io/docs/latest/operate/oss_and_stack/management/scaling/>, <https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/>

**R11. Cluster: one hash slot per script.**
"Redis Cluster supports multiple key operations as long as all of the keys involved in a single command execution (or whole transaction, or Lua script execution) belong to the same hash slot. The user can force multiple keys to be part of the same hash slot by using a feature called hash tags." "all names of keys that a script accesses must be explicitly provided as input key arguments." "Multi-key operations may become unavailable when a resharding of the hash slot the keys belong to is in progress."
<https://redis.io/docs/latest/operate/oss_and_stack/management/scaling/>, <https://redis.io/docs/latest/develop/programmability/eval-intro/>, <https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/>

**R12. Eviction policies.**
"`noeviction`: Keys are not evicted but the server will return an error when you try to execute commands that cache new data." `allkeys-lru`, `allkeys-lrm`, `allkeys-lfu`, `allkeys-random` evict from all keys. `volatile-lru`, `volatile-lrm`, `volatile-lfu`, `volatile-random`, `volatile-ttl` evict keys "that have an associated expiration (TTL)". "The `volatile-xxx` policies behave like `noeviction` if no keys have an associated expiration." Evictions are propagated: a master that evicts "synthesizes a `DEL` command which is transmitted to all the replicas."
<https://redis.io/docs/latest/develop/reference/eviction/>, <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>

**R13. Key expiry.**
"Redis keys are expired in two ways: a passive way and an active way. A key is passively expired when a client tries to access it and the key is timed out." Actively, "periodically, Redis tests a few keys at random amongst the set of keys with an expiration." "Since Redis 2.6 the expire error is from 0 to 1 milliseconds." "Keys expiring information is stored as absolute Unix timestamps … Even running instances will always check the computer clock, so for instance if you set a key with a time to live of 1000 seconds, and then set your computer time 2000 seconds in the future, the key will be expired immediately". On replicas: "Replicas don't expire keys, instead they wait for masters to expire the keys", and a replica may "still have in memory keys that are already logically expired", which it hides "only for read operations".
<https://redis.io/docs/latest/commands/expire/>, <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>

## 6. Proposed and rejected Redis profiles

### 6.1 Proposed: `redis-single-node-aof-always`

One Redis Open Source server that is the only authority. No replica is ever read or promoted automatically.

**Required configuration**

- `appendonly yes`, `appendfsync always` (R6). Any other fsync policy is a different, rejected profile.
- `maxmemory-policy noeviction`, or `maxmemory 0` (R12). At the memory limit writes then fail, which the adapter reports as `STORE_UNAVAILABLE`; nothing is silently dropped.
- Redis 7.0 or later, so effects replication is the only mode and `TIME` is usable in scripts (R3, R4).
- Every mutation is one script or function. Each script performs all reads and checks first and writes only afterwards, and declares every key it touches (R2, R11).
- A dedicated instance or logical database. A shared instance where another tenant can run `FLUSHALL`, `CONFIG SET`, or `DEBUG` is outside the profile.
- At start, and periodically, the adapter verifies `appendonly`, `appendfsync`, `maxmemory-policy`, and that the server's role is master with the expected replica count. If it cannot read them (restricted `CONFIG`), the profile is "as told", and `capabilities().profile` must say so.
- Storage that honours fsync. Redis documentation does not offer a way to verify this; it is an operator statement.

**Conflict rule (§5.2) and read snapshot (§5.4)**

- A script blocks every other client for its whole run (R1). `commitRestore`, `createCapture`, `revokeCapture`, `quarantine`, and `invalidateRecovered` are each one script, so any two of them are executed one after the other and the later one sees the earlier one's writes. There is no interleaving to exclude and no abort: the `stale` outcome arises only from a changed `generation` or revision found by the commit script's own checks.
- `readEntries` is one read-only script that returns the recovery record, the entries, and their captures; that is one snapshot by R1. `readCaptures` likewise.
- The two-connection schedules of §5.2 reduce, on this backend, to: revoke (or quarantine) issued between the read script and the commit script, and revoke issued while a commit script is running (it must be served only after the script ends).

**Limits**

- No documented action-count cap was found. The real bound is that the script blocks all clients (R1). `maxCreateEntries`, `maxCreateBytes`, `maxRestoreEntries`, `maxRestoreCaptures`, and `maxEnvelopeBytes` are to be set from measured script time against a stated latency budget; the contract ceilings (1024 entries, 64 captures) may be reachable.
- `busy-reply-threshold` must stay above the worst measured script time: a writing script that crosses it can only be stopped by `SHUTDOWN NOSAVE` (R2).
- Availability: one node. While it is down the vault denies everything. That is the price of this profile and must be stated to adopters.

**Clock**

- `storeClock: true`, using `TIME` inside the script before any write (R4). `maxClockSkewMs` is enforced by comparing the caller's `now` with it. It is the Redis host's wall clock and can step; §7.5 describes both cases (store clock alone set back: commits fail `clock-skew`; both set back: undetectable).
- `deleteCiphertext` and `sweepExpired` compare the caller's `now` with `TIME` as §5.7 requires.

**Receipts, tombstones, cleanup**

- Receipts and tombstones are ordinary keys. Prefer no Redis TTL on them, with removal by `sweepExpired` over a sorted index, so that no policy change can make them evictable (R12) and no clock step can remove them early (R13).
- If native expiry is used, it must be `PEXPIREAT` at the retention bound, never the logical expiry, and the `noeviction` requirement becomes load-bearing rather than defensive.

**Backup, rollback, and `restoreDetection`**

- Restoring an RDB or AOF copy, or starting from an older data directory, is a rollback. It is silent. The §9.3 runbook applies in full.
- A restart after a crash may refuse to start on a partially written transaction until `redis-check-aof` removes it (R3). **Inference:** with `appendfsync always` a transaction that was never fully written was never acknowledged, so removing it does not lose an acknowledged commit; this has to be shown by fault injection, not assumed.
- A warm standby replica is permitted only as a disaster-recovery copy with **manual** promotion, and by §7.6 promotion is a rollback event that goes through the runbook.
- `restoreDetection` (**Inference**; no vendor feature is claimed): nothing in the pages read gives Redis a marker that distinguishes a restored data set from the one that was running, because a restored file carries every key the original had. What an adapter could honestly declare is a process-local high-water mark: a counter key incremented in every mutating script, with each adapter process remembering the highest value it has seen and quarantining the namespace when the server reports a lower one. That detects a rollback only for processes that outlive it, and not at all after every server restarts. Unless that limited mechanism is implemented and named as such, the honest value is `"none"`, and the application must pass `allowNoRestoreDetection: true`.

### 6.2 Rejected Redis profiles

- **Sentinel or any automatically failing-over master/replica set.** The documentation states acknowledged writes are not guaranteed to be retained (R8) and that `WAIT`/`WAITAOF` do not change this (R7). A lost `revokeCapture` re-enables a revoked capture; a lost `commitRestore` returns a spent single-use entry to service after its value was already released. That breaks §7.1 without any operator action, and §7.6 says failover resolution through the receipt "is sound only when the new primary holds every acknowledged commit". Declined. `min-replicas-to-write` and `WAIT` narrow the window and do not close it.
- **Redis Cluster.** Same write-loss statements (R10), plus the one-slot rule (R11) forces a whole namespace into one slot because every commit includes the namespace recovery record. Declined.
- **Single node with `appendfsync everysec`, `no`, or RDB only.** Up to a second, an OS-dependent interval, or minutes of acknowledged commits can vanish on a crash (R5, R6). This could only ever be offered as `durability: "volatile"`, which the persistent factory refuses by default. Declined as a persistent profile.
- **Any eviction policy other than `noeviction`.** R12.
- **Reads from replicas for any contract operation.** Replicas lag and hold logically expired keys (R13).
- **Managed or proprietary Redis-compatible services, Redis Software Active-Active.** Not covered by the sources read. No claim either way; a consumer may bring a store it has qualified itself.

## 7. SQLite evidence

**S1. Atomic commit.**
"Atomic commit means that either all database changes within a single transaction occur or none of them occur." "SQLite still supports atomic commit when write-ahead logging is enabled".
<https://www.sqlite.org/atomiccommit.html>

**S2. One writer; serializable.**
"SQLite implements serializable transactions by actually serializing the writes. There can only be a single writer at a time to an SQLite database." In WAL mode, "since there is only one WAL file, there can only be one writer at a time", and readers see "snapshot isolation". "IMMEDIATE causes the database connection to start a new write immediately, without waiting for a write statement. The BEGIN IMMEDIATE might fail with SQLITE_BUSY if another write transaction is already active on another database connection." "EXCLUSIVE and IMMEDIATE are the same in WAL mode". With `BEGIN DEFERRED`, a later write "will upgrade the transaction to a write transaction if possible, or return SQLITE_BUSY."
<https://www.sqlite.org/isolation.html>, <https://www.sqlite.org/wal.html>, <https://www.sqlite.org/lang_transaction.html>

**S3. `synchronous` and durability.**
"FULL is atomic, consistent, isolated, and durable (ACID) in WAL mode and is atomic, consistent, and isolated with a rollback journal. FULL might also be durable using a rollback journal, depending on the underlying filesystem. FULL is not necessarily durable across a power loss in rollback mode, so if durability is desired, it is best to set the synchronous mode to EXTRA." "WAL mode is always consistent with synchronous=NORMAL, but WAL mode does lose durability. A transaction committed in WAL mode with synchronous=NORMAL might roll back following a power loss or system crash. Transactions are durable across application crashes regardless of the synchronous setting or journal mode." "EXTRA is no different from FULL in WAL mode." From the WAL page: "Writers sync the WAL on every transaction commit if PRAGMA synchronous is set to FULL but omit this sync if PRAGMA synchronous is set to NORMAL."
<https://www.sqlite.org/pragma.html#pragma_synchronous>, <https://www.sqlite.org/wal.html>

**S4. WAL needs one host and no network filesystem.**
"All processes using a database must be on the same host computer; WAL does not work over a network filesystem. This is because WAL requires all processes to share a small amount of memory and processes on separate host machines obviously cannot share memory with each other."
<https://www.sqlite.org/wal.html>

**S5. WAL persistence, files, and busy cases.**
"The WAL journaling mode is persistent; after being set it stays in effect across multiple database connections and after closing and reopening the database." "The WAL file is part of the persistent state of the database and should be kept with the database if the database is copied or moved. If a database file is separated from its WAL file, then transactions that were previously committed to the database might be lost". A WAL database can be used without shared memory only when "locking_mode is set to EXCLUSIVE before the first attempted access", that is, by a single process. Even reads can return `SQLITE_BUSY` in WAL mode, for example while another connection runs crash recovery.
<https://www.sqlite.org/pragma.html#pragma_journal_mode>, <https://www.sqlite.org/wal.html>

**S6. Checkpointing.**
"By default, SQLite does a checkpoint automatically when the WAL file reaches a threshold size of 1000 pages." "All automatic checkpoints are PASSIVE." "The WAL must be synced to persistent storage prior to moving content from the WAL into the database and the database file must be synced prior to resetting the WAL." "A checkpoint is only able to run to completion, and reset the WAL file, if there are no other database connections using the WAL file"; with a continuous overlap of readers "the WAL file will grow without bound" ("checkpoint starvation"). "With PRAGMA synchronous set to NORMAL, the checkpoint is the only operation to issue an I/O barrier or sync operation".
<https://www.sqlite.org/wal.html>, <https://www.sqlite.org/pragma.html#pragma_wal_autocheckpoint>

**S7. Network filesystems.**
"SQLite relies on exclusive locks for write operations, and those have been known to operate incorrectly for some network filesystems. This has led to database corruption." "The bottom line is that network filesystem sync and locking reliability vary among implementations and installations. … Rely upon it at your (and your customers') peril." "it behooves application developers to not rely on early testing success to decide that their remote database use will work as desired."
<https://www.sqlite.org/useovernet.html>

**S8. Locking depends on the filesystem.**
"SQLite depends on the underlying filesystem to do locking as the documentation says it will. But some filesystems contain bugs in their locking logic … This is especially true of network filesystems and NFS in particular." FAQ: "this locking mechanism might not work correctly if the database file is kept on an NFS filesystem. This is because fcntl() file locking is broken on many NFS implementations. You should avoid putting SQLite database files on NFS if multiple processes might try to access the file at the same time." Atomic-commit page: "You are advised to avoid using SQLite on a network filesystem in the first place".
<https://www.sqlite.org/howtocorrupt.html>, <https://www.sqlite.org/faq.html#q5>, <https://www.sqlite.org/atomiccommit.html>

**S9. Process hazards.**
"Do not open an SQLite database connection, then fork(), then try to use that database connection in the child process." "If two or more processes open the database using different names, then they will use different rollback journals and WAL files … opening and using a database file that has two or more names results in behavior that is undefined and probably undesirable."
<https://www.sqlite.org/howtocorrupt.html>

**S10. Sync depends on the OS and the device.**
"SQLite assumes that the flush or fsync will not return until all pending write operations for the file that is being flushed have completed. We are told that the flush and fsync primitives are broken on some versions of Windows and Linux. … there is nothing that SQLite can do to test for or remedy the situation." "most consumer-grade mass storage devices lie about syncing." `PRAGMA fullfsync` "determines whether or not the F_FULLFSYNC syncing method is used on systems that support it. The default value of the fullfsync flag is off. Only Mac OS X supports F_FULLFSYNC."
<https://www.sqlite.org/atomiccommit.html>, <https://www.sqlite.org/howtocorrupt.html>, <https://www.sqlite.org/pragma.html#pragma_fullfsync>

**S11. Backups of a live database.**
A plain file copy during a transaction "might contain some old and some new content, and thus be corrupt." Safe methods: `sqlite3_rsync`, `VACUUM INTO`, and the backup API; "It is also safe to make a copy of an SQLite database file as long as there are no transactions in progress while the copy is taking place", and the `-journal` or `-wal` file must be copied with it. The backup API yields "a consistent and up-to-date snapshot of the original", but writes from another process restart it, and "If the backup process is restarted frequently enough it may never run to completion". "The VACUUM INTO command is transactional in the sense that the generated output database is a consistent snapshot of the original database", and "all deleted content is purged from the backup".
<https://www.sqlite.org/howtocorrupt.html>, <https://www.sqlite.org/backup.html>, <https://www.sqlite.org/lang_vacuum.html>

**S12. A WAL-mode corruption bug fixed in 2026.**
"The bug is likely present in all version of SQLite from 3.7.0 (2010-07-21) through 3.51.2 (2026-01-09). It is fixed in version 3.51.3 (2026-03-13) and later. Backports of the fix are available for some earlier releases: 3.44.6 and 3.50.7. The bug only affects databases in WAL mode when there are two or more database connections open on the same file, in separate threads or processes, and when those two connections attempt to write or checkpoint at the same instant."
<https://www.sqlite.org/wal.html>

**S13. Clock and busy handling.**
"the string 'now', is converted into the current date and time as obtained from the xCurrentTime method of the sqlite3_vfs object in use." `sqlite3_busy_timeout` "sets a busy handler that sleeps for a specified amount of time when a table is locked … After at least 'ms' milliseconds of sleeping, the handler returns 0 which causes sqlite3_step() to return SQLITE_BUSY." "An attempt to execute COMMIT might also result in an SQLITE_BUSY return code".
<https://www.sqlite.org/lang_datefunc.html>, <https://www.sqlite.org/c3ref/busy_timeout.html>, <https://www.sqlite.org/lang_transaction.html>

**S14. Size limits.**
Default maximum string or BLOB length is 1,000,000,000 bytes (`SQLITE_MAX_LENGTH`); the maximum host parameter number is "32766 for SQLite versions after 3.32.0".
<https://www.sqlite.org/limits.html>

## 8. Proposed and rejected SQLite profiles

### 8.1 Proposed: `sqlite-local-wal`

One database file on a local filesystem of one host, opened by one or more processes on that host.

**Required configuration**

- `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=FULL` on every connection (S3). `synchronous` is per connection and must be set each time; the adapter reads both back after setting them and refuses to start on any other value.
- Alternative of equal standing: `journal_mode=DELETE` with `synchronous=EXTRA` (S3). It is slower and blocks readers during writes, but does not need shared memory.
- Every mutating operation runs in `BEGIN IMMEDIATE … COMMIT` (S2). `BEGIN DEFERRED` is not used for writes, because the read-to-write upgrade can fail with `SQLITE_BUSY` after reads the transaction already depended on.
- `busy_timeout` set to a bounded value below the server's commit timeout (S13).
- SQLite 3.51.3 or later, or a release carrying the backported fix (3.44.6, 3.50.7), whenever more than one connection can write (S12). The adapter checks `sqlite_version()`.
- The database, `-wal`, and `-shm` files on a local filesystem; all processes on the same host; the file opened under one canonical path; no connection inherited across `fork()` (S4, S5, S9).
- Storage that honours sync. On macOS, `PRAGMA fullfsync=ON` (S10; see section 11 for what the documentation does not say).

**Conflict rule (§5.2) and read snapshot (§5.4) (Inference from S2)**

- There is one writer at a time, and `BEGIN IMMEDIATE` acquires that role before the transaction reads anything. `commitRestore` and `createCapture` therefore read the recovery record and the capture rows, and write, with no other writer able to commit in between. A `revokeCapture`, `quarantine`, or `invalidateRecovered` on another connection waits in its own `BEGIN IMMEDIATE` (up to `busy_timeout`) or fails `SQLITE_BUSY` before doing anything.
- This is stricter than the spec's locking description: commits in one namespace do serialize against each other, because SQLite has no row locks. It is a throughput property of the profile, not a correctness gap.
- The fixed lock order and deadlock handling of §5.2 have nothing to act on with a single writer lock. A transaction that never reaches the writer role maps to `STORE_UNAVAILABLE` (nothing was attempted), not `stale`; `stale` arises only from a changed generation or revision.
- The mistake to exclude by test is doing the checks in a deferred or separate read transaction and the writes in another: under WAL a reader keeps seeing its snapshot while a writer commits (S2), which is exactly the "concurrent writer commit unseen" that §5.2 rules out.
- `readEntries` runs its selects inside one explicit read transaction, which under WAL is one snapshot (S2) and under a rollback journal holds a shared lock for its duration.

**Outcome mapping (Inference from S2, S13)**

- `SQLITE_BUSY` from `BEGIN IMMEDIATE`: nothing was attempted: `STORE_UNAVAILABLE`.
- `SQLITE_BUSY` or another error from `COMMIT`, followed by a successful `ROLLBACK`: definitely no effect: `STORE_UNAVAILABLE`.
- An I/O error at `COMMIT` where rollback cannot be confirmed, or a lost process: `STORE_AMBIGUOUS`, resolved through the receipt.

**Limits**

- No transaction action limit. The contract ceilings (1024 entries per create and per restore, 64 captures, 1 MiB + 64 KiB envelope) fit within S14, and the capture's `keyRef` and `wrappedKey` are two small columns. `maxCreateBytes` is a policy choice bounded by memory and by how long one writer may hold the database (1024 envelopes at the ceiling would be about 1 GiB in one transaction, which no deployment should declare); a figure in the tens of mebibytes, set from measurement, is the realistic declaration. Statements must stay under 32766 bound parameters each.
- One writer at a time (S2): throughput is one commit stream per database file, each paying a WAL sync. Large batches extend the time other writers wait.
- `crossProcess: true` only in the sense of "processes on this host". It must not be read as multi-host.

**Clock**

- The store reads the host clock inside its transaction (S13), so `storeClock: true` is accurate and `maxClockSkewMs` is enforced against the caller's `now`.
- Because every server process is on the same host, the store's clock and the default server clock are the same source. The skew check therefore only detects an injected `now` that disagrees with the host. Of the two cases in §7.5, "only the store's clock is set back" cannot happen; a host clock set back extends lifetimes by that amount and nothing in the system detects it. The profile documentation must say so and require trustworthy time on the host.

**Receipts, tombstones, cleanup**

- Rows in ordinary tables with unique keys; the receipt insert relies on a primary-key conflict inside the commit transaction. The receipt lookup is the second statement of the commit transaction, after the recovery record, which gives the ordered precedence of §5.5 directly.
- `sweepExpired` is a bounded delete in its own `BEGIN IMMEDIATE` transaction.
- Deleted rows remain in free pages, the WAL, and any earlier backup until overwritten or vacuumed. This matches §9 ("Neither is erasure") and should be restated in the adapter documentation.

**Checkpoint, backup, and `restoreDetection`**

- Keep the default auto-checkpoint. Read transactions must be short, or the WAL grows without bound (S6). An optional periodic `wal_checkpoint(TRUNCATE)` bounds file size; durability under `FULL` does not depend on it.
- Backups only through `VACUUM INTO`, the backup API, or `sqlite3_rsync`; never by copying the main file alone (S5, S11).
- Replacing the database file with a backup is a silent rollback. The §9.3 runbook applies.
- `restoreDetection` (**Inference**; no vendor feature is claimed): a backup made by any documented route is a faithful copy, so nothing stored in the file can distinguish it from the original. Two limited mechanisms are honest: a process-local high-water mark of a counter incremented in every mutating transaction (detects a rollback only for processes that outlive it), and a marker file kept beside the database, outside the backup set, holding the last counter value (detects a restored database file when the marker survives; defeated when both are restored together or the marker is lost). Either must be named for what it is. Without one, the value is `"none"` and the application must pass `allowNoRestoreDetection: true`.

### 8.2 Rejected SQLite profiles

- **Any network filesystem, in any journal mode.** WAL is documented as not working there (S4); rollback mode depends on locks and sync documented as unreliable there, with corruption as the stated consequence (S7, S8). The SQLite documentation explicitly warns that passing tests is not evidence. Declined, including shared volumes mounted by several hosts or containers on different hosts.
- **`synchronous=NORMAL` or `OFF`.** `NORMAL` in WAL "does lose durability": a committed revoke or use can roll back after power loss (S3). Declined as a durable profile.
- **`journal_mode=MEMORY` or `OFF`.** Crash during a transaction "will very likely" corrupt the file in `MEMORY` mode (pragma page). Declined.
- **Rollback journal with `synchronous=FULL` presented as durable.** "FULL is not necessarily durable across a power loss in rollback mode" (S3). Use `EXTRA`.
- **Multi-host SQLite by replication tools.** Not covered by sqlite.org sources; no claim by analogy.

## 9. Recommendation

Follow-up issues opened on 2026-10-01: [#130](https://github.com/redact-secret/redact-secret-vault/issues/130) for the SQLite profile and [#131](https://github.com/redact-secret/redact-secret-vault/issues/131) for the contract revision a DynamoDB profile would need. No issue is opened for Redis until there is demand.

| Profile | Recommendation | Main reason |
| --- | --- | --- |
| `sqlite-local-wal` (WAL + `FULL`, or DELETE + `EXTRA`) | Open an implementation issue | Meets every requirement of contract version 1 on documented behaviour, including the conflict rule and the store clock; meets the contract's ceilings; smallest qualification surface |
| `redis-single-node-aof-always` | Open an implementation issue only if there is adopter demand for a single-node, no-failover Redis | Meets contract version 1 on paper, but the configuration that makes it sound is not how Redis is normally run, and misconfiguration fails silently |
| `dynamodb-single-region` | Do **not** open an implementation issue. Open a contract-revision issue first | No DynamoDB profile satisfies contract version 1: the store has no clock and version 1 requires one. Atomicity, durability, consistency, and the conflict rule are otherwise well supported, with bounds roughly 10× below the contract ceilings |
| DynamoDB global tables (MRSC, MREC multi-writer) | Decline explicitly | D10, D11, D12 |
| Redis Sentinel / replicated with automatic failover | Decline explicitly | R7, R8 |
| Redis Cluster | Decline explicitly | R10, R11 |
| Redis with `everysec`, `no`, RDB only, or any eviction | Decline explicitly | R5, R6, R12 |
| SQLite on a network filesystem; SQLite with `synchronous=NORMAL` | Decline explicitly | S3, S4, S7, S8 |

Declining a profile is not a statement that nobody can build a compliant store on that technology. A consumer may bring its own store and qualify it; what is declined is this project claiming it.

Proposed scope of each issue:

**Issue A — "Implement and qualify `@redact-secret/store-sqlite` for the `sqlite-local-wal` profile."** Profile: one database file on a local filesystem of one host, one or more processes on that host. Required configuration: `journal_mode=WAL` with `synchronous=FULL` (or `DELETE` with `EXTRA`), `BEGIN IMMEDIATE` for every mutation, a bounded `busy_timeout`, SQLite 3.51.3 or a release with the backported WAL-reset fix, one canonical path, no forked connections, `fullfsync` on macOS; all verified at start. Declared limits: `maxCreateEntries` and `maxRestoreEntries` up to 1024, `maxRestoreCaptures` up to 64, `maxEnvelopeBytes` up to the contract ceiling, `maxCreateBytes` from measurement, `storeClock: true` with a stated `maxClockSkewMs`, `durability: "durable"`, `crossProcess: true` (same host), `restoreDetection` either `"none"` or a named limited mechanism. Qualification gates: the common list and the SQLite list of section 10, including the §5.2 two-connection schedules and block-device power-loss simulation. Prerequisite: the contracts package and the shared conformance harness of the persistent vault work; nothing in the contract needs to change.

**Issue B (only on demand) — "Implement and qualify `@redact-secret/store-redis` for the `redis-single-node-aof-always` profile."** Profile: one Redis Open Source 7.0+ server as sole authority, no automatic failover, no replica reads. Required configuration: `appendonly yes`, `appendfsync always`, `maxmemory-policy noeviction`, dedicated instance, check-then-write scripts or functions, `TIME` as the store clock; verified at start and periodically, with the profile reported as "as told" when `CONFIG` is unreadable. Declared limits: all batch and byte maxima from measured script time under a stated latency budget and below `busy-reply-threshold`; `storeClock: true`; `durability: "durable"`; `crossProcess: true`; `restoreDetection` `"none"` or a named process-local high-water mark. Qualification gates: the common list and the Redis list of section 10, including kill and power-loss after acknowledged commits and the negative failover test that documents the declined profile. Prerequisite: Issue A's harness, a named adopter, and the unverified Redis points of section 11 (fsync failure behaviour, script limits) answered from primary sources or by test.

**Issue C — "Contract revision: admit a store without its own clock (caller-clock expiry), as the precondition for any DynamoDB profile."** This is a specification and decision-record issue, not an adapter. Scope: decide whether a later contract version adds a declared caller-clock mode; define the skew assumption that replaces `maxClockSkewMs` enforcement and the factory opt-in; define fence and tombstone timestamps, and the `now` comparison of `deleteCiphertext` and `sweepExpired`, without a store clock; decide whether a restore byte bound is added or small envelopes are required; decide how `initializeNamespace` proves emptiness on a key-value store. Inputs it must gather first: whether check-only overlap between DynamoDB transactions conflicts (section 4.1), the 4 MB accounting rule, and per-item overhead. Declared limits that a later adapter issue would start from: `maxRestoreEntries + maxRestoreCaptures + 2 ≤ 100`, `maxCreateEntries ≤ 98`, `maxEnvelopeBytes` in the tens of kibibytes, `maxCreateBytes` below 4 MB. Qualification gates for that later adapter: the common list and the DynamoDB list of section 10. Prerequisite for the adapter issue: this revision accepted. If the revision is rejected, DynamoDB is declined outright.

## 10. Qualification requirements

Common to every profile, against the real backend and not a mock:

1. The shared `Store` conformance suite, including every rejection reason of §5.3 and §5.5, with `quarantined` and then the receipt outcomes taking precedence over all others, and the mechanical validation of §4.2.
2. **Conflict-rule schedules (§5.2), on two connections.** (a) A revocation committed between a restore's read of the capture and its commit: the commit must not return `committed`. (b) A quarantine committed between a create's recovery check and its commit: the create must not return `created`. (c) The same with `invalidateRecovered` in place of quarantine, for both commit and create. (d) Each of these with the second operation issued while the first transaction is in flight, not only between calls. An aborted transaction is reported `stale` (or a definite no-effect error), never success and never ambiguous.
3. **One-use race.** For an entry with `maxUses = N`, at least 10× N concurrent `commitRestore` calls from at least two independent processes; exactly N occurrences commit.
4. **Create/fence race.** Concurrent `createCapture` and `revokeCapture` with `fenceAbsent` of the same identifier; the outcome is either "live then revoked" or "fenced", never a live capture after an acknowledged fence. `revokeCapture` without `fenceAbsent` on an absent capture writes nothing.
5. **Epoch.** After `invalidateRecovered`, every capture stamped with a lower epoch reads as `revoked`, commits against it are `revoked`, and `revokeCapture` answers `already-revoked`, with no clock involved. `initializeNamespace` refuses a non-empty namespace.
6. **Receipt uniqueness.** The same `attemptId` submitted concurrently with equal and with different digests; at most one commit, then `already-committed` or `attempt-mismatch`.
7. **Read snapshot (§5.4).** `readEntries` under concurrent commits, revokes, and an invalidation never returns an entry with a capture or recovery state from a different moment.
8. **Ambiguity.** Kill the client between send and response; `inspectAttempt` on a fresh process returns a result consistent with the stored budget.
9. **Bounds.** Batches at the declared maxima (`maxCreateEntries`, `maxCreateBytes`, `maxRestoreEntries`, `maxRestoreCaptures`, `maxEnvelopeBytes`, maximum `keyRef` and `wrappedKey`) succeed atomically; one over throws `STORE_CAPABILITY` or `STORE_INVALID_ARGUMENT` with no write; no batch is ever split.
10. **Clock.** A caller `now` beyond `maxClockSkewMs` of the store clock is rejected `clock-skew` on create, commit, expiry-based delete, and sweep; a store clock stepped forward cannot delete live rows by itself.
11. **Cleanup independence.** With sweeping disabled and with native TTL (where used) enabled, expiry and retention outcomes are unchanged.
12. **Rollback drill.** Restore from each supported backup route and run the §9.3 runbook: quarantine, raise the epoch, `invalidateRecovered`; every earlier capture is `revoked`. The declared `restoreDetection` is exercised and its stated blind spots are demonstrated, not only its successes.
13. **Ciphertext-only I/O.** Capture of everything written to the backend shows no plaintext value, token, session identifier, or unwrapped key.
14. **Key replacement.** `replaceCaptureKey` is a compare-and-swap on `keyRevision`, refuses revoked, expired, and ciphertext-deleted captures, and leaves a concurrent restore unaffected.

SQLite-specific:

- Startup refuses when `journal_mode`, `synchronous`, or `sqlite_version()` are outside the profile, and when the file is on a filesystem the adapter can identify as networked (best effort; documented as best effort).
- Schedule 2 run with a second connection holding `BEGIN IMMEDIATE`: the other side waits or reports busy with no effect. A deliberately wrong variant that checks in a read transaction and writes in another is shown to fail the schedule, to prove the harness can see the defect.
- Multi-process contention: several processes on one host under sustained write load; `SQLITE_BUSY` surfaces as `STORE_UNAVAILABLE` and never as a partial commit.
- `kill -9` of a writer at each step (before `COMMIT`, during, after); after recovery by another process, state is all-or-nothing and every acknowledged commit is present.
- Power-loss simulation on the block device with `synchronous=FULL`; acknowledged commits survive. The same test with `NORMAL` is expected to lose commits and documents the decline.
- Long-running reader during load: WAL growth is bounded by the adapter's own read-transaction limits; checkpoints complete once the reader ends.
- Backup under write load through `VACUUM INTO` and the backup API; the copy passes `integrity_check`; restoring it triggers the rollback drill. A raw copy of the main file without the `-wal` file is shown to lose committed transactions, to justify the documentation warning.
- `fork()` misuse and double-path opening are documented as unsupported; where the runtime makes them possible they are tested for refusal.

Redis-specific:

- Startup refuses when `appendonly`, `appendfsync`, `maxmemory-policy`, or role differ from the profile; a runtime `CONFIG SET` to a weaker value is detected by the periodic check.
- Schedule 2 run with the second connection's command sent while a commit script is executing (a deliberately slowed script in the test build): it is served only after the script ends and the outcomes are ordered.
- `kill -9` of the server immediately after each acknowledged `commitRestore` and `revokeCapture`, at volume; after restart every acknowledged commit and revoke is present. Repeat with power-loss simulation on the block device (not only process kill).
- Kill during AOF rewrite, and during a script, then restart; if the server refuses to start, run the documented `redis-check-aof` repair and verify no acknowledged operation is missing.
- Memory limit reached: writes fail, no key disappears, fences and receipts remain.
- A script error injected after the checks phase proves there is no write-then-fail path (every write command used is shown not to fail for type or argument reasons).
- Worst-case script duration at the declared maxima stays under `busy-reply-threshold` with margin.
- Server clock stepped forward and backward: logical expiry follows `TIME`; no fence or receipt is removed before its bound.
- A negative test documenting, not fixing, the rejected profile: with a replica and forced failover, an acknowledged revoke can be lost. This is the evidence for the decline and guards against the profile being enabled later by assumption.

DynamoDB-specific (applies only after the contract revision of section 9, Issue C):

- Schedule 2 with the revoke, quarantine, or invalidation issued (i) between the `TransactGetItems` snapshot and the commit and (ii) concurrently with the commit. Result is `revoked`, `quarantined`, or `stale`; never `committed`.
- **Check-only contention.** Many concurrent commits in one namespace that share only the recovery item's `ConditionCheck`, and many that also share one capture's `ConditionCheck`: measure the `TransactionConflict` rate and the resulting `RESTORE_CONFLICT` rate. A profile is not proposable if ordinary load exhausts the retry budget.
- Transactions exactly at 100 actions and at the declared byte bounds; one action over and one byte-class over are refused before any request is sent.
- An entry item at the declared `maxEnvelopeBytes`, and a capture item with maximum `keyRef`, `wrappedKey`, and entry list, each stay under 400 KB; a restore and a snapshot read at the declared maxima stay under 4 MB.
- Expired-but-undeleted items: with TTL enabled, a capture past `expiresAt` that still exists is denied `expired`; a receipt past TTL that still exists still deduplicates.
- Every read on an authoritative path is asserted to carry `ConsistentRead: true` or to be a `TransactGetItems` (request capture), and no index or DAX endpoint is contacted.
- Throttling, `TransactionCanceledException` for conflict, `TransactionInProgressException`, and HTTP timeouts are each mapped to the right one of `stale`, `STORE_UNAVAILABLE`, and `STORE_AMBIGUOUS`; SDK automatic retries are either disabled or shown to be idempotent through the token within its 10-minute window and never relied on after it.
- Precedence: a commit that fails the recovery check and other conditions at once reports `quarantined`; one that meets an existing receipt and other failures reports `already-committed` or `attempt-mismatch`.
- Caller-clock mode: two adapter processes with clocks offset by more than the stated assumption; the observed disagreement about expiry is recorded and equals the offset, and the deployment's time control is shown to detect it.
- PITR restore into a new table: TTL is off on the restored table; the rollback drill passes; a restore taken during load is inspected for a receipt without its decrement, to confirm that invalidation is the only safe treatment.

## 11. Open questions and unverified points

Answered by the revised specification, recorded here so they are not raised again:

- A store without its own clock is refused in version 1 (§7.5, §8.2, §12). Consequence: section 9, Issue C.
- A byte bound for create exists: `maxCreateBytes` (§3.6, §4).
- The `entries` count returned by `revokeCapture` is informational (§5.6).
- Only "quarantined, then receipt" are ordered among rejections (§5.5); DynamoDB can report those two first (section 4.1).
- The SQLite store clock and the server clock are the same host clock; noted in section 8.1.

Still open on the contract side, all for the DynamoDB revision:

1. **Caller-clock mode.** Whether a later contract version admits it, and the rules listed in section 4.1 (skew assumption, fence and tombstone timestamps, `now` checks in delete and sweep).
2. **Restore byte bound.** `maxCreateBytes` bounds create. `commitRestore` and `readEntries` have no byte capability. A store with a per-transaction byte cap can only be honest by declaring a small `maxEnvelopeBytes`, or the contract gains a restore bound.
3. **`initializeNamespace` emptiness.** §5.8 requires refusing when any capture, entry, or receipt row of the namespace exists. On a key-value store that needs an atomic emptiness proof; the DynamoDB pages read offer `Query` and `Scan`, which are read-committed (D5).
4. **Commit-versus-commit conflicts on shared checked items.** §5.2 expects commits in one namespace not to serialize against each other on the recovery record. Whether DynamoDB can offer that depends on the unverified point below.

Points not verified from primary sources:

- **DynamoDB: do two transactions conflict when the only item they share is under a `ConditionCheck` in both?** The conflict list (D19) does not distinguish. Decisive for throughput.
- **DynamoDB 4 MB accounting.** The documentation says "aggregate size of the items in the transaction". Whether an `Update`, `ConditionCheck`, or `Get` counts the whole stored item was not stated on the pages read. Section 4.1 assumes the whole item.
- **DynamoDB per-item overhead** for the planned key and attribute names, and therefore the exact `maxEnvelopeBytes` and `maxCreateBytes`. Needs measurement.
- **DynamoDB `CancellationReasons` completeness**: whether every failing item is flagged. Section 4.1 gives a fallback that does not depend on it.
- **DynamoDB `ReturnValuesOnConditionCheckFailure`** inside transactions was not examined; it may let a failed create distinguish `exists` from `fenced` without a second read.
- **A stable table identity** usable for `restoreDetection` on DynamoDB was not established.
- **The dedicated MRSC/MREC page** (`V2globaltables.consistency-modes.html`) did not return content on the fetch date. All global-table statements come from `GlobalTables.html` and `V2globaltables_HowItWorks.html`.
- **DynamoDB durability mechanism** (replication across Availability Zones) was not fetched; only the "durably persisted" statement (D7) is relied on.
- **TTL lower bound.** The pages say deletion happens after expiry, "typically within a few days". No page read states an explicit guarantee that TTL never deletes before the timestamp; it is implied by the definition of an expired item. To be confirmed by test, and guarded by using the retention bound.
- **Redis behaviour when the AOF fsync itself fails** under `appendfsync always` (whether the client receives an error, whether the server stops) was not found in the pages read.
- **Redis limits** on script argument count, key count, and value size were not fetched.
- **Redis functions versus `EVAL`** for adapter delivery (persistence of the function library, cache volatility of `EVAL` scripts) was only skimmed; either satisfies R1.
- **The claim that removing a partial AOF transaction never removes an acknowledged commit** under `appendfsync always` is an inference from R3 and R6.
- **SQLite default `synchronous` in WAL mode** depends on compile-time options and was not established; the profile sets it explicitly for that reason.
- **macOS `fsync` versus `F_FULLFSYNC`.** sqlite.org states the pragma exists and is off by default; the pages read do not spell out what is lost without it.
- **Container and virtual-machine file sharing** (bind mounts across a VM boundary, overlay filesystems) is not addressed by the SQLite pages read. No claim is made; treat as outside the profile until tested.
- **The `restoreDetection` mechanisms** sketched for Redis and SQLite are designs proposed here, with stated blind spots; no vendor documentation describes them.
- **Managed Redis-compatible services and Redis Software** were out of scope.
