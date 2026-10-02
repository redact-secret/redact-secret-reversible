# DynamoDB profile inputs: what AWS documents, what it does not, what needs the service

**Status: research, not a support claim.** Implementation of a DynamoDB profile is **on hold** by maintainer decision; nothing here schedules it, and nothing here is accepted. This note settles, from primary sources, the inputs that [#131](https://github.com/redact-secret/redact-secret-vault/issues/131) and the proposed [decision](../decisions/decide-stores-without-a-clock.md) list as unverified. The decision's status (`proposed`) and its recommendation (decline) are unchanged by this note; the section "Effect on the decision" says why. It follows the [backend capability research](persistent-backend-capabilities.md) ([#114](https://github.com/redact-secret/redact-secret-vault/issues/114)); evidence identifiers `D1` to `D19` below refer to that document, new ones are `I1` onward.

## 1. Method

- Sources are primary documentation only: pages under `docs.aws.amazon.com`. No blog posts, no third-party analyses, no recollection.
- Every page was fetched on **2026-10-01** with the WebFetch tool. Quotations are verbatim from the fetched page text, apart from line wrapping. The URL under each item is the canonical page.
- No AWS account was used and no AWS service was called. One local check ran against DynamoDB Local (Docker image `amazon/dynamodb-local:latest`, version 3.3.1, in memory, fake credentials, synthetic item names). Its results are labelled **"DynamoDB Local, not service behavior"** and are used only for the shape of requests and responses.
- Each finding carries one label:
  - **DOCUMENTED**: a quoted sentence states it.
  - **NOT DOCUMENTED**: the pages read do not state it. Where an inference is drawn, it is marked **Inference**.
  - **NEEDS SERVICE MEASUREMENT**: only the real service can answer. The experiment, table setup, and expected cost are specified in section 10. None was run.
- A bare `§` means a section of the [specification](../specs/persistent-vault.md). Byte arithmetic uses the units AWS itself defines (finding g).

## 2. Summary

| # | Input (from the issue and the decision) | Verdict |
| --- | --- | --- |
| a | Do two transactions that only `ConditionCheck` the same item conflict? | **NOT DOCUMENTED.** The pages support two readings. **NEEDS SERVICE MEASUREMENT**; decisive for throughput |
| b | How the 4 MB limit counts `Update` and `ConditionCheck`; the 100-action limit | 100: **DOCUMENTED**. 4 MB size basis (whole item or not): **NOT DOCUMENTED**, **NEEDS SERVICE MEASUREMENT**. 1 MB = 1024 KB: **DOCUMENTED** |
| c | `ClientRequestToken` versus attempt receipts | **DOCUMENTED.** A token cannot be a receipt: 10 minutes against a receipt kept at least 25 hours |
| d | No time function in conditions; options | No function: **DOCUMENTED** by the exhaustive grammar. Client `now`: **DOCUMENTED** (AWS's own examples). TTL never deletes early: **DOCUMENTED by definition**, not stated as a guarantee |
| e | Proving a namespace empty | Strongly consistent `Query` and `Scan`: **DOCUMENTED**. An atomic proof from a read alone: **DOCUMENTED as impossible** (read-committed). A counter-free design exists (**Inference**, section 8) |
| f | `restoreDetection` | `TableId` is a documented unique identifier: **DOCUMENTED**. That a restore yields a different one: **NEEDS SERVICE MEASUREMENT**. Blind spots listed in section 9 |
| g | 400 KB item limit; the "about 40 KiB envelope" figure | 400 KB: **DOCUMENTED**. The 40 KiB figure **recomputes** to 39 to 46 KiB under the whole-item assumption, which is itself **NOT DOCUMENTED** |

Also settled, because the decision lists them: `CancellationReasons` shape and `ReturnValuesOnConditionCheckFailure` are **DOCUMENTED** (finding a), and whether every failing item is flagged when several fail stays **NEEDS SERVICE MEASUREMENT** (cheap).

## 3. Finding a: check-only transactions on the same item

**Question.** If `commitRestore` and `createCapture` each carry a `ConditionCheck` on the namespace recovery item and write nothing to it, do two such concurrent transactions conflict, so that the recovery item serializes every commit in a namespace?

**I1. What the documentation states about conflicts.** DOCUMENTED, but silent on the case.

> "Transaction conflicts can occur in the following scenarios: A `PutItem`, `UpdateItem`, or `DeleteItem` request for an item conflicts with an ongoing `TransactWriteItems` request that includes the same item. An item within a `TransactWriteItems` request is part of another ongoing `TransactWriteItems` request. An item within a `TransactGetItems` request is part of an ongoing `TransactWriteItems`, `BatchWriteItem`, `PutItem`, `UpdateItem`, or `DeleteItem` request."

<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>

**I2. The API reference words the same rule differently.**

> "DynamoDB rejects the entire `TransactWriteItems` request if any of the following is true: ... An ongoing operation is in the process of updating the same item."

and, in the errors section:

> "There is an ongoing `TransactWriteItems` operation that conflicts with a concurrent `TransactWriteItems` request."

<https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html>

**I3. What a `ConditionCheck` is.**

> "`ConditionCheck` — Applies a condition to an item that is not being modified by the transaction."

Same page. The developer guide says "`ConditionCheck` — Checks that an item exists or checks the condition of specific attributes of the item." and, on capacity, "DynamoDB performs two underlying reads or writes of every item in the transaction: one to prepare the transaction and one to commit the transaction." A `ConditionCheck` item is an item of the transaction, so it takes part in prepare and commit.

**Reading.** The first reading: "An item within a `TransactWriteItems` request is part of another ongoing `TransactWriteItems` request" covers every action type, so check-only overlap conflicts. The second reading: the API reference's "in the process of updating the same item" describes a conflict only when someone updates, so two checks do not. The pages do not choose. **Verdict: NOT DOCUMENTED. NEEDS SERVICE MEASUREMENT** (experiment A, section 10). The cost of being wrong is stated in the [decision](../decisions/decide-stores-without-a-clock.md): the recovery item would serialize every commit and create of a namespace.

**DynamoDB Local cannot answer it.** DOCUMENTED: "`TransactionConflictExceptions` aren't thrown by downloadable DynamoDB for transactional APIs." (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.UsageNotes.html>)

**What a conflict looks like (DOCUMENTED).** A conflicting `TransactWriteItems` fails with `TransactionCanceledException`; the item's cancellation reason is

> "Transaction Conflict: Code: `TransactionConflict`, Message: Transaction is ongoing for the item."

A standalone `PutItem`, `UpdateItem`, or `DeleteItem` that collides fails with `TransactionConflictException`. "If that request fails, AWS SDKs do not retry the request." The transaction is cancelled, not queued: the exception is returned on the call. A concurrent standalone `GetItem` does not conflict: "If an ongoing `TransactWriteItems` or `TransactGetItems` operation conflicts with a concurrent `GetItem` request, both operations can succeed." The `TransactionConflict` CloudWatch metric "is incremented for each failed item-level request", which gives experiment A a second signal.

**`CancellationReasons`.** DOCUMENTED shape: "Transaction cancellation reasons are ordered in the order of requested items, if an item has no error it will have `None` code and `Null` message." The reason codes are `None`, `ConditionalCheckFailed`, `ItemCollectionSizeLimitExceeded`, `TransactionConflict`, `ProvisionedThroughputExceeded`, `ThrottlingError`, `ValidationError`. The `CancellationReason` type has `Code`, `Message`, and `Item` ("Item in the request which caused the transaction to get cancelled."). So the position of the recovery item, receipt, and entries in the request is recoverable from the list, which the research's rejection-precedence inference (section 4.1) relies on. NOT DOCUMENTED: whether every failing item is flagged when several fail at once, and whether `TransactionConflict` on one item can mask `ConditionalCheckFailed` on another (**NEEDS SERVICE MEASUREMENT**, experiment D; the research's fallback read does not depend on it).

**`ReturnValuesOnConditionCheckFailure` (DOCUMENTED shape).** "Use `ReturnValuesOnConditionCheckFailure` to get the item attributes if the `ConditionCheck` condition fails. For `ReturnValuesOnConditionCheckFailure`, the valid values are: NONE and ALL_OLD." (<https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ConditionCheck.html>) The same field exists on `Put`, `Update`, and `Delete` ("a field indicating whether to retrieve the item's attributes if the condition is not met"). The returned attributes go to `CancellationReason.Item`. A failed create could therefore tell `exists` from `fenced` from the returned old item without a second read. Whether the failing item's attributes come back for the item that failed when other items also fail is part of experiment D.

*DynamoDB Local, not service behavior:* a three-action transaction (failing check with `ALL_OLD`, passing check, conditional put) returned `TransactionCanceledException` with the message `[ConditionalCheckFailed, None, None]`. That confirms the request shape and the per-position list, and nothing about the service's conflict rules.

## 4. Finding b: transaction limits and size accounting

**I4. 100 actions, 100 distinct items, 4 MB.** DOCUMENTED, in four places.

> "`TransactWriteItems` is a synchronous and idempotent write operation that groups up to 100 write actions in a single all-or-nothing operation. These actions can target up to 100 distinct items in one or more DynamoDB tables within the same AWS account and in the same Region. The aggregate size of the items in the transaction cannot exceed 4 MB."

<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>. The API reference: "`TransactItems` ... Array Members: Minimum number of 1 item. Maximum number of 100 items." The constraints page: "A transaction cannot contain more than 100 unique items. A transaction cannot contain more than 4 MB of data. No two actions in a transaction can work against the same item in the same table." `TransactGetItems` has the same two bounds: "groups up to 100 `Get` actions together ... The aggregate size of the items in the transaction can't exceed 4 MB." So the research's counts stand: restore `E + C + 2 ≤ 100`, create `E + 2 ≤ 100`, snapshot read `E + C + 1 ≤ 100`. Because "No two actions ... can work against the same item", a restore that names a capture twice, or an entry and its capture folded into one item, cannot be expressed; each item gets exactly one action.

**I5. The unit is binary.** DOCUMENTED: "All size measurements in DynamoDB use binary-based units. DynamoDB denotes 1 KB = 1024 bytes, 1 MB = 1024 KB, 1 GB = 1024 MB, 1 TB = 1024 GB." (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Constraints.html>) So **4 MB is 4 194 304 bytes** and 400 KB is 409 600 bytes. The research's arithmetic in section 4.1 does not say which it used; finding g recomputes with the documented unit.

**I6. What "the items in the transaction" means for size.** The phrase "aggregate size of the items in the transaction" is all the transaction pages say. The pages read do not state whether an `Update` counts the stored item, the item after the update, the request payload, or the larger of before and after; or whether a `ConditionCheck` counts the stored item; or whether a `Get` counts the stored item. **Verdict: NOT DOCUMENTED. NEEDS SERVICE MEASUREMENT** (experiment B).

Two documented facts that point toward whole-item counting without establishing it. First, for throughput (not for the 4 MB limit): "`UpdateItem` ... DynamoDB considers the size of the item as it appears before and after the update. The provisioned throughput consumed reflects the larger of these item sizes. Even if you update a subset of the item's attributes, `UpdateItem` will still consume the full amount of provisioned throughput." (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html>) Second, capacity is charged on a failed check too: "A `TransactWriteItems` or `TransactGetItems` call that is canceled ... still consumes the underlying read or write capacity for the items it attempted." These are about billing; the 4 MB rule may use another measure. **Inference only:** capacity is charged on the whole item, so the service reads the whole item for a check or update, which makes whole-item counting plausible. The adapter must not rely on a plausible reading for a bound.

**I7. Item size, and what the 400 KB covers.** DOCUMENTED:

> "The maximum item size in DynamoDB is 400 KB, which includes both attribute name binary length (UTF-8 length) and attribute value lengths (again binary length). The attribute name counts towards the size limit."

and the size formulas (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html>): "The total size of an item is the sum of the lengths of its attribute names and values, plus any applicable overhead as described below." A string is "(number of UTF-8-encoded bytes of attribute name) + (number of UTF-8-encoded bytes)"; a binary attribute is "(number of UTF-8-encoded bytes of attribute name) + (number of raw bytes)"; a number is "approximately (number of UTF-8-encoded bytes of attribute name) + (1 byte per two significant digits) + (1 byte)"; "An attribute of type `List` or `Map` requires 3 bytes of overhead" plus "1 byte of overhead" per element. Binary values count raw bytes, not the base64 length.

The same page: "All items in DynamoDB require 100 bytes of storage overhead per item" and "Some DynamoDB features (global tables, transactions, change data capture for Kinesis Data Streams with DynamoDB) require additional storage overhead to account for system-created attributes". That overhead is introduced "For storage billing purposes". Whether it counts toward the 400 KB limit or the 4 MB aggregate is **NOT DOCUMENTED**; experiment B bisects the exact accepted size, which settles it for the planned key and attribute names.

**I8. Where a size violation surfaces (DOCUMENTED).** An item over 400 KB, and an aggregate over 4 MB, are both listed as rejections of the whole request: "An item size becomes too large (bigger than 400 KB) ... The aggregate size of the items in the transaction exceeds 4 MB." The cancellation code for an oversize item is `ValidationError` ("Item size to update has exceeded the maximum allowed size."). Which error type the 4 MB overrun returns is NOT DOCUMENTED; experiment B records it. This matters for the adapter: a size violation must map to the definite `STORE_INVALID_ARGUMENT` or `STORE_CAPABILITY` of §5, not to an ambiguous failure.

## 5. Finding c: `ClientRequestToken` against attempt receipts

**I9. Window and semantics.** DOCUMENTED:

> "A client token is valid for 10 minutes after the request that uses it finishes. After 10 minutes, any request that uses the same client token is treated as a new request. You should not reuse the same client token for the same request after 10 minutes."

> "If you repeat a request with the same client token within the 10-minute idempotency window but change some other request parameter, DynamoDB returns an `IdempotentParameterMismatch` exception."

> "If the original `TransactWriteItems` call was successful, then subsequent `TransactWriteItems` calls with the same client token return successfully without making any changes."

<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html>. The API reference adds "Length Constraints: Minimum length of 1. Maximum length of 36", "A client request token is valid for 10 minutes after the first request that uses it is completed", and the `TransactionInProgressException` ("The transaction with the given request token is already in progress"). The SDK retries `TransactionInProgressException` by default; the page says "Plan for the additional read-capacity units (RCUs) that these retries consume. The same is true if you are retrying transactions in your own code using a `ClientRequestToken`."

**Comparison with the contract's receipts.** §7.5 sets `receiptExpiresAt` to the latest capture `expiresAt` plus the skew bound plus a grace period (default 1 hour), and the store rejects a `receiptExpiresAt` more than 48 hours past its clock. A capture lives at most 24 hours (§3.6). So a receipt lives at least until the capture expires, up to about 25 hours plus skew by default and 48 hours at the cap. The token window is 10 minutes after completion: **at least 150 times shorter** than the default receipt life, 288 times shorter than the cap. Differences that follow from the quotes:

| Property the contract needs | Receipt (§5.5, §7.5) | `ClientRequestToken` |
| --- | --- | --- |
| Lifetime | Until `receiptExpiresAt` (25 h or more) | 10 minutes after completion |
| Survives as readable state (`inspectAttempt`, `resolveAttempt`) | Yes, an item read with a strongly consistent `GetItem` | No: nothing documents a way to read a token back |
| Distinguishes `already-committed` from `attempt-mismatch` after the window | Yes, stores the 32-byte request digest | Not after 10 minutes; inside the window a changed request is `IdempotentParameterMismatch`, which does not say what was committed |
| Identifier size | `attemptId` up to 128 characters | Token at most 36 characters |
| Success return for a repeat | `already-committed` with the receipt | "return successfully without making any changes", with different `ConsumedCapacity` |

**Verdict: DOCUMENTED. The token cannot be the receipt** (confirms D4's inference). The receipt must be an item written by the same transaction with `attribute_not_exists`. **Inference** for the one narrow use: a token derived from `attemptId` (a hash cut to 36 characters; `attemptId` itself can be 128) makes an SDK retry of the same call inside the window return success, instead of tripping over its own receipt (`ConditionalCheckFailed` on the receipt, then a read and a digest comparison). That is an optimization, not a requirement; the receipt path is needed anyway for the case after the window. One interaction to test, not documented: after a successful call, a repeat inside the window returns success without applying anything, so the adapter must treat that as `already-committed` and read the receipt for the digest, or it risks reporting `committed` to a request whose digest differs. Because the token is bound to the request parameters, a different request under the same `attemptId` inside the window gets `IdempotentParameterMismatch` before any condition is evaluated; the adapter must map that to `attempt-mismatch`.

*DynamoDB Local, not service behavior:* a repeat with the same token and parameters returned success; a repeat with the same token and a different item returned `IdempotentParameterMismatchException` with an empty message. Local's 10-minute expiry was not tested.

## 6. Finding d: time in conditions, and the options

**I10. Conditions have no clock (DOCUMENTED by the grammar).** The page gives the complete condition grammar:

> "condition-expression ::= operand comparator operand | operand BETWEEN operand AND operand | operand IN ( operand (',' operand (, ...) )) | function | condition AND condition | condition OR condition | NOT condition | ( condition )"

> "function ::= attribute_exists (path) | attribute_not_exists (path) | attribute_type (path, type) | begins_with (path, substr) | contains (path, operand) | size (path)"

An operand is "A top-level attribute name" or "A document path that references a nested attribute"; the page's function table lists exactly those six. The grammar is the complete syntax summary, so **no function returns the current time**; the statement that none exists is an inference from a complete list, which the pages do not repeat in words. (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html>) The operator budget is 300 per expression, expression strings 4 KB, and "The maximum length of any single expression attribute name or expression attribute value is 255 bytes" (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Constraints.html>). The update-expression page was not read, so nothing is claimed about time in `UpdateExpression`; the contract needs time only in conditions.

*DynamoDB Local, not service behavior:* a condition `expiresAt > now()` returned `ValidationException: Invalid ConditionExpression: Syntax error; token: ")", near: "()"`. A parse error, as the grammar predicts.

**I11. The documented option: the client's time as an attribute value.** DOCUMENTED, in AWS's own examples:

> "the filter expression can filter out items where the TTL time is equal to or less than the current time. For example, the Python SDK code includes an assignment statement that obtains the current time as a variable (`now`), and converts it into `int` for epoch time format."

> "A condition expression can be used to avoid writes against expired items. The code snippet below is a conditional update that checks whether the expiration time is greater than the current time."

The example condition is `expireAt > :c` with `:c` computed by the client. (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html>) This is the "caller clock" of the decision's section 1: the comparison runs inside the service, but one operand is the caller's. Nothing on the pages gives the service's time to a condition.

**I12. TTL: what it can and cannot be.** DOCUMENTED:

> "DynamoDB automatically deletes expired items within a few days of their expiration time, without consuming write throughput. ... The timestamp must be stored as a Number data type in Unix epoch time format at the seconds granularity."

> "Items with valid, expired TTL attributes might be deleted by the system at any time, typically within a few days after their expiration."

> "If they are not filtered, they'll continue to show in read and write operations until they are deleted by the background process."

> "To be considered for expiry and deletion, the TTL can't be more than five years in the past. ... If you set the expiration time to sometime in the future when you want the item to expire, the item expires after that time. ... There is no minimum TTL duration."

Sources: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/time-to-live-ttl-before-you-start.html>. Consequences:

- **Delayed deletion:** documented as "within a few days"; no upper bound and no lower latency promise beyond "might be deleted ... at any time" after expiry. TTL is cleanup, which §5.7 allows. It cannot be the expiry check (D13, D14 stand).
- **Never early:** the pages say deletion applies to "expired" items and that an item "expires after" its timestamp, so by definition an item is not deleted before. The decision's row "TTL never deletes before its timestamp: implied, not stated" is thereby **DOCUMENTED by definition, but not as a guarantee sentence**. The only operational guard is the research's: put the retention bound, not the logical expiry, in the TTL attribute, rounded up to whole seconds. No experiment could prove the negative; observing none early over a long window is evidence only.
- **Seconds granularity:** the contract's timestamps are milliseconds (§3), so the TTL attribute is a separate Number attribute, and the logical `expiresAt` stays in milliseconds for conditions.
- **TTL is not a clock.** The TTL process's idea of "now" is not readable from a condition (I10).

Options for a clock, then: (1) the caller's `now` as an attribute value (documented, the decision's proposed mode, recommended against); (2) the HTTP `Date` response header (not documented as a clock contract; not evaluated further here); (3) a time item in the table, written by a trusted writer (not evaluated by the decision; inherits contention and adds an authority, as the decision says). The pages offer nothing else.

## 7. Finding g: the 400 KB item limit and the "about 40 KiB envelope" figure

The inputs are I5 and I7 for units and item size, and these ceilings of the specification:

| Ceiling | Value | Source |
| --- | --- | --- |
| Envelope, contract ceiling | 1 MiB + 64 KiB = 1 114 112 bytes | §3.6 |
| Value, ceiling and default | 1 MiB, 8 KiB | §3.6 |
| Envelope framing | `"RSVE"` 4 + version 1 + algorithm 1 + nonce 12 + length 4 + tag 16 = 38 bytes beyond the payload | §3.5 |
| Payload fixed part | 1 + 4 + 2 (type length) + type up to 256 + 2 (grant count) + 1 + 2 + policyRevision up to 256 = at most 524 bytes beyond value and grants | §3.5 |
| Grants | 1 to 64 sinks, 1 to 256 paths each, each identifier up to 256 code units | §3.6 |
| `maxCreateEntries`, `maxRestoreEntries` | at most 1024 | §3.6 |
| `maxRestoreCaptures` | at most 64 | §3.6 |
| `keyRef`, `wrappedKey` | 512, 4096 bytes | §3.5 |
| `namespace`, `tenant` | 128 characters, 256 UTF-16 code units | §3.2 |
| `captureId`, `entryId` | 30 characters, 64 hexadecimal characters | §3.2 |

**Per-item overhead, worst case (planned layout, assumption).** Short attribute names (`pk`, `sk`, `cid`, `mu`, `u`, `lr`, `cr`, `env`). Partition key `N#<namespace>#T#<tenant>` is at most 2 + 128 + 3 + 768 = 901 bytes (a tenant of 256 code units at 3 UTF-8 bytes each); sort key `E#<entryId>` is 66. One entry item then carries about **1 040 bytes** of non-envelope data (keys 971 with names, captureId 33, four small numbers about 19, the `env` name 3, rounded up). A typical tenant of 36 bytes brings that near 300. A capture item holds `keyRef` and `wrappedKey` (about 4.6 KB), identifiers, times, a session tag, and, if used, an entry-identifier list of up to 98 × 65 bytes: **about 12.5 KB** at most. The recovery item and the receipt item are about 1.1 KB and 1.2 KB. These byte counts are **Inference** from the I7 formulas for a layout that does not exist; experiment B replaces them with measured numbers.

**Single item.** 400 KB = 409 600 bytes. The largest envelope that fits in one entry item is about 409 600 − 1 040 = **408 560 bytes**. The contract ceiling of 1 114 112 bytes is 2.7 times larger, so a store on one item per entry must declare `maxEnvelopeBytes` below that; the research's statement stands (the 1 MiB ceiling does not fit; the default 8 KiB value does).

**Transaction, under the whole-item assumption (I6, not documented).** Budget `B = 4 194 304` bytes. Per entry `(B − fixed) / E − 1 040`, with `fixed = 12 500 × C + 2 300` (captures, recovery item, receipt):

| Restore shape (research's table) | Fixed bytes | Entry budget | Per-envelope bound, binary 4 MB | Same with a decimal 4 000 000 |
| --- | --- | --- | --- | --- |
| E = 97, C = 1 | 14 800 | 4 179 504 | 42 047 bytes = **41.1 KiB** | 40 045 bytes = 39.1 KiB |
| E = 82, C = 16 | 202 300 | 3 992 004 | 47 643 bytes = **46.5 KiB** | 45 273 bytes = 44.2 KiB |
| E = 34, C = 64 | 802 300 | 3 392 004 | 98 725 bytes = 96.4 KiB | 93 000 bytes = 90.8 KiB |

**The "about 40 KiB" figure reproduces.** The tightest shape (97 entries, one capture) gives 39 to 41 KiB, the 82-entry shape 44 to 47 KiB, matching the research's "roughly 45 KiB" and "roughly 41 KiB" within the unit difference. The figure holds as an order of magnitude and a worst-case-overhead number under the whole-item assumption; with the documented binary unit it is slightly conservative. Three qualifications:

1. It is conditional on I6, which is NOT DOCUMENTED. If `ConditionCheck` and `Update` count only keys and changed attributes, the bound is far larger and the entry item limit (about 408 KiB) is the only cap. If `Update` counts the larger of before and after, the number is unchanged.
2. The 1 MiB value ceiling is out of reach in either case. With the 8 KiB default value, about 32 KiB remains for grants and type under a 40 KiB bound, so ordinary records fit. A record with the worst grant set (64 sinks × 256 paths) can exceed it and would be a `RECORD_LIMIT` at seal, as §3.6 already says for an oversized envelope.
3. **Create** is looser: `maxCreateBytes ≤ 4 194 304 − 12 500 (capture) − 1 100 (recovery check) − 98 × 1 040 = 4 078 784` bytes, about **3.89 MiB**, against the research's "near 3.5 MiB plausible". Create counts `Put` items, which carry their payload, so its basis is less uncertain than the restore basis.

## 8. Finding e: proving a namespace empty in a key-value store

**I13. Consistency of `Query` and `Scan`.** DOCUMENTED:

> "Read operations such as `GetItem`, `Query`, and `Scan` provide an optional `ConsistentRead` parameter. If you set `ConsistentRead` to true, DynamoDB returns a response with the most up-to-date data, reflecting the updates from all prior write operations that were successful. Strongly consistent reads are only supported on tables and local secondary indexes."

> "If you require strongly consistent reads, as of the time that the `Scan` begins, set the `ConsistentRead` parameter to `true` in the `Scan` request. This ensures that all of the write operations that completed before the `Scan` began are included in the `Scan` response."

<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html>, <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html>. The default is eventually consistent, and a global secondary index never supports it ("If you query a global secondary index with `ConsistentRead` set to `true`, you will receive a `ValidationException`").

**I14. A read is not an atomic proof (DOCUMENTED).** "The isolation level is read-committed between any transactional operation and any read operation that involves multiple standard reads (`BatchGetItem`, `Query`, or `Scan`)." (transaction-apis page) and "Read-committed isolation does not prevent modifications of the item immediately after the read operation." So an empty result is true as of the moment read and says nothing about a transaction that commits a moment later. Paging adds a second gap: "A single `Query` operation will read up to the maximum number of items set (if using the `Limit` parameter) or a maximum of 1 MB of data", "The result set from a `Scan` is limited to 1 MB per call", and "If `LastEvaluatedKey` is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when `LastEvaluatedKey` is empty." A proof by `Query` must therefore loop until `LastEvaluatedKey` is absent, and a one-item `Query` (`Limit: 1`, no filter) is the cheapest, with `Select: COUNT` costing the same read units as returning items ("uses the same quantity of read capacity units as getting the items"). A filter is not usable here: "A `Query` operation can return an empty result set and a `LastEvaluatedKey` if all the items read for the page of results are filtered out."

**Verdict.** Strongly consistent `Query` and `Scan`: DOCUMENTED. An atomic emptiness proof from reads alone: not available (DOCUMENTED above). So the decision's statement stands as written. What the pages do not rule out, and the decision's text does not mention, is a design that gets atomicity from the write side:

**I15. Counter-free design (Inference from I4, I13, I14; not documented, not measured).**

1. Every row-writing transaction of the research's candidate already carries a `ConditionCheck` on the recovery item (`createCapture`, `commitRestore`; section 4.1 of the research). No capture, entry, or receipt row can therefore be created while the recovery item is absent.
2. `initializeNamespace` first runs a strongly consistent `Query` over the namespace's partition (`Limit: 1`, no filter, loop to the end), refuses with the §5.8 error when it finds any row, then writes the recovery item with `Put` and `attribute_not_exists`. Between the read and the write no row can appear, because step 1 forbids writers without the recovery item; two concurrent initializers are ordered by the conditional `Put`, which is a single-item write.
3. The invariant "recovery item absent implies no rows" can fail only if an operator deletes the recovery item by hand or imports rows outside the vault; the same read catches the stray rows that exist before the write.

Costs and conditions: the key design must put a namespace's rows under one partition key (`pk = namespace`, `sk` = row kind and identifier) so a `Query` can enumerate them. The tenant then sits in the sort key and the item's attributes; the 2048-byte partition key limit and 1024-byte sort key limit hold ("The maximum length is 2048 bytes", "The maximum length is 1024 bytes"). With rows spread over many partition keys, only a `Scan` ("reads every item in a table") could prove it, with a full-table cost. Whether one partition key for a busy namespace is acceptable for throughput is not documented here (the partition throughput page was not read) and belongs with experiment A. This finding **does not remove** the recovery-item contention of finding a; it removes the need for a second shared item (the row counter), so the decision's "the choice depends on a measurement" survives, with a third option on the table.

## 9. Finding f: `restoreDetection` and its blind spots

**I16. Restore always creates a new table (DOCUMENTED).** "The point-in-time recovery process always restores to a new table." (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html>) "The recovery process restores to a new DynamoDB table." (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html>) The on-demand-backup and PITR restores, and a restore from the system backup of a deleted table ("DynamoDB automatically creates a backup snapshot called a *system backup* and retains it for 35 days"), all produce a table. Import from S3 does too: "Your data will be imported into a new DynamoDB table ... Import into existing tables is not currently supported by this feature." (<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/S3DataImport.HowItWorks.html>) A cross-Region restore is documented as well, to a table in another Region.

**I17. A table has a unique, generated identifier (DOCUMENTED).**

> "TableId: A unique identifier for the table, in UUID format, generated by DynamoDB when the table is created."

> "TableArn: The Amazon Resource Name (ARN) that uniquely identifies the table."

<https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html>, returned by `DescribeTable`, which "uses an eventually consistent query" (<https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DescribeTable.html>). `TableDescription` also carries `CreationDateTime` and a `RestoreSummary`: "Contains details for the restore", with `SourceBackupArn`, `SourceTableArn`, `RestoreDateTime`, `RestoreInProgress` (<https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreSummary.html>).

**The mechanism this gives (Inference).** `initializeNamespace` records the table's `TableId` in the recovery item. The tripwire (§9.3) reads `DescribeTable` for the table in use and compares. A restore copies the recovery item with the old `TableId` into a table that has a new `TableId`, so a mismatch means "this database is a restored copy". `RestoreSummary` is a second signal: a restored table is described with it. This is the research's candidate ("record an identity of the table in the recovery item"), and the identity it was missing is `TableId`. **What the pages do not say:** that a restored table gets a `TableId` different from its source (implied by "a unique identifier ... generated by DynamoDB when the table is created" and by "a new table", but not stated for restore); that `RestoreSummary` is kept for the table's life; how long after a restore `DescribeTable` returns the new values. **NEEDS SERVICE MEASUREMENT** (experiment C). Until then `restoreDetection` stays `"none"` in the decision's row, now with a documented candidate.

**Blind spots, each documented or marked.**

| Blind spot | Basis |
| --- | --- |
| **A restored copy that was never compared.** The tripwire runs where the adapter chooses to run it (factory start, periodic). A restored table put into service between checks is accepted until the next check. A transaction cannot read table metadata, so no commit can carry the check | Inference from the transaction action types (I4); control-plane calls are separate requests |
| **Item-level rollback in the same table.** An operator who rewrites items from an export or an old copy, or who `BatchWriteItem`s a replay into the live table, changes no `TableId` and no `RestoreSummary`. Export itself does not touch the table ("Exports are asynchronous, they don't consume read capacity units ... and have no impact on table performance and availability") and import cannot target an existing table, so the supported paths all create a new table; the manual path is the blind spot | Inference; the pages document no per-table "last restored" marker beyond `RestoreSummary` |
| **Partial transactions in the restored data.** "if a table is restored from backup ... or exported to a point in time ... mid-propagation, it can contain only some of the changes made during a recent transaction." and "DynamoDB backups do not guarantee causal consistency across items; however, the skew between updates in a backup is usually much less than a second." Detection of the swap does not repair this; version 1's invalidation (every capture under a lower epoch is revoked) is what handles the state, and a restored receipt without the matching budget decrement, or the reverse, is possible | D1, D18 |
| **Settings do not carry over.** TTL, Streams, PITR, tags, IAM policies, deletion protection, CloudWatch alarms, auto scaling and Contributor Insights are not restored; "You must manually set the following on the restored table". The runbook must re-enable TTL or accept sweep-only cleanup, and re-apply the IAM that scopes the vault | D17, the restore page |
| **`DescribeTable` is eventually consistent and rate limited.** "DescribeTable uses an eventually consistent query"; the control plane allows "up to 2,500 requests per second" for `DescribeTable`, `ListTables`, and `GetResourcePolicy` combined. A tripwire that polls is cheap, but a read right after a restore can fail with `ResourceNotFoundException` or stale values | API reference, constraints page |
| **A restored table under a name servers already use.** There is no rename in the pages read; the old table must be deleted or the servers repointed. If the old table is deleted and the restored one takes its name, `DescribeTable` by name returns the new `TableId`, which the tripwire compares against the stored one: the case it is built for. If the deployment is repointed by ARN, the same holds | Inference from I16, I17; confirm with experiment C |
| **A cross-account or cross-Region copy** (restore to another Region, export and import elsewhere) produces a table with its own `TableId` and ARN; if servers there are given the copy, the stored identity mismatches. The tripwire catches it only if it runs there | I16 |
| **`restoreDetection` under DynamoDB Local.** DynamoDB Local "doesn't support Point-in-time recovery (PITR)" and, in the run here, returned no `TableId` in `DescribeTable` (*DynamoDB Local, not service behavior*). A contract test of the tripwire against Local would test nothing | Usage notes; local run |
| **Global tables** are outside the candidate profile ("the backup restores to an independent table that is not part of the global table") | D17 |

**Verdict: DOCUMENTED** for the identifier and for restore-to-new-table; **NEEDS SERVICE MEASUREMENT** for "a restore changes it" and for `RestoreSummary` persistence. The blind spots are why the decision keeps `restoreDetection` honest: even with `TableId`, the profile's control against a recovered database is the §9.3 runbook, and the tripwire is, as §9.3 already says, "a guard against a skipped runbook".

## 10. Experiments that need the real service (specified, not run)

None of these was run. Each needs an AWS account in a sandbox with a budget alarm, one Region, one table per experiment, on-demand capacity, no GSI, no DAX, no TTL, PITR off (except C), item and key names synthetic. Costs are in request units; price them from the DynamoDB pricing page on the day, which this research did not fetch.

**Experiment A: check-only conflict (decisive).** Table `rsv_probe_a`, key `pk` (S), `sk` (S). Items: `ns#probe | recovery` (state `serving`, `epoch` 1), then unique receipt and entry items created by the workload. Workers: K processes spread over two hosts in the table's Region, each with its own SDK client and SDK retries off for cancellations. Each worker loops `TransactWriteItems [ConditionCheck recovery (epoch = :e AND state = :s), Put receipt#<unique> (attribute_not_exists), Put entry#<unique> (attribute_not_exists)]`. Variants: V1 shared check (the real shape); V2 control, every transaction `Update`s the recovery item (expected to conflict); V3 control, each worker checks its own private item (expected not to); V4 one standard `UpdateItem` on the recovery item once a second while V1 runs (expected `TransactionConflictException` on the update and `TransactionConflict` on some transactions, which also confirms the documented serializability). Levels: 1, 2, 4, 8, 16, 32, 64 workers, closed loop, 60 s each, plus open-loop 10, 50, 100, 500 transactions per second. Record: success rate, every `CancellationReasons` array (expected `[TransactionConflict, None, None]` if check-only conflicts), latency p50 and p99, the CloudWatch `TransactionConflict` metric, `ConsumedCapacity`. **Read as:** V1 failure rate within noise of V3 at every level means check-only overlap does not conflict (favourable, condition 1 of the decision's reopening list). V1 close to V2 means it does; then report the highest sustained commits per second per namespace and the share of restores that would exhaust the default 3 retries (§5.2) at the adopter's stated rate. **Cost:** a transaction of three small items is 6 write request units; at a cap of 10^6 transactions the run is about 6 × 10^6 write request units plus cancelled attempts (which also consume capacity, per the capacity page quoted in I6); elapsed about two hours plus setup. Also record whether a single partition key for the namespace throttles at the higher levels (finding e).

**Experiment B: 4 MB accounting and per-item overhead.** Table `rsv_probe_b`. Items: 12 items of 399 KB (below the 409 600-byte limit, built as one binary attribute plus the planned names), 100 small items. Probes, each at n = 9, 10, 11, 12 items, bisecting at the boundary: (B1) `TransactWriteItems` of n `ConditionCheck`s on distinct 399 KB items; (B2) n `Update`s that increment a small counter (item size unchanged); (B3) n `Update`s that add 1 KB near the limit; (B4) `TransactGetItems` of n `Get`s; (B5) n `Put`s of new 399 KB items. **Prediction if whole items count:** 10 accepted, 11 rejected (10 × 399 KB = 3 990 KB under 4 096 KB; 11 × 399 KB = 4 389 KB over). **If only keys or payload count:** 11 and 12 accepted in B1 and B2. Also a shape probe with 100 `ConditionCheck`s on small items. For overhead: `Put` one item of exactly 409 600 bytes per the I7 formula, then 409 601 bytes, with the planned attribute names; the largest accepted size gives the true per-item overhead including any system attribute. Record the exact error type and text of each rejection (I8 leaves the 4 MB overrun's error type open) and whether a rejection happens before capacity is charged. **Cost:** a transactional write of a 399 KB item is 2 × 399 write request units; one n = 10 probe is about 8 000; about 40 probes is about 3.2 × 10^5; building the 12 large items is about 5 000; the `Get` probes are 2 read request units per 4 KB, about 2 000 per probe. Order of 4 × 10^5 request units; about one hour.

**Experiment C: restore identity.** Table `rsv_probe_c` with PITR on (PITR is billed by table size; the table is a few items). Record `TableId`, `TableArn`, `CreationDateTime`, `RestoreSummary` from `DescribeTable`. Write a sentinel item holding the recorded `TableId`. After the earliest restorable time, (C1) restore to a new name; (C2) delete the source and restore under the original name; (C3) `RestoreTableFromBackup` from an on-demand backup. Compare the stored sentinel with the restored table's `TableId`, and read `RestoreSummary` at +0, +1 h, +24 h; time how long `DescribeTable` returns `ResourceNotFoundException` or stale data after the restore completes. **Expected cost:** a few items, so storage and restore charges at the minimum; elapsed about a day (the +24 h read); restore completion time is documented as variable ("isn't always correlated with the size of the table").

**Experiment D: `CancellationReasons` completeness.** Table `rsv_probe_d`. One transaction with four actions where two fail their conditions and a fifth item is held by an ongoing slow transaction from another client; record whether every failing position is flagged, whether `TransactionConflict` masks `ConditionalCheckFailed`, and whether `Item` is returned for the failing positions when `ReturnValuesOnConditionCheckFailure` is `ALL_OLD`. **Cost:** under 10^3 request units; minutes. Can share the table with experiment A.

**Not worth running: TTL never early.** No experiment proves a negative. The guard in I12 (TTL on the retention bound) makes the question moot.

## 11. Effect on the decision

No finding contradicts a stated fact of the [decision](../decisions/decide-stores-without-a-clock.md), and none changes its recommendation (decline). Changes in standing of its "Inputs and their status" rows, which the decision now points here for:

- **Settled in the direction the decision already stated:** conditions have no clock and AWS's examples use the client's time (I10, I11); a colliding transaction is cancelled with `TransactionConflict` (I1); the 100-action limit (I4); the receipt cannot be a token (I9).
- **Narrowed, no longer open:** `CancellationReasons` list shape and per-position `None` (finding a); `ReturnValuesOnConditionCheckFailure` shape, valid values `NONE` and `ALL_OLD` (finding a); TTL "never early" is true by definition (I12); a stable table identity exists on paper, `TableId` (I17).
- **Still open, now with an experiment:** check-only conflict (A), the 4 MB size basis and per-item overhead (B), restore changing `TableId` (C), flagging of every failing item (D).
- **Recomputed:** the "about 40 KiB" figure reproduces at 39 to 46 KiB under the whole-item assumption, with the documented binary unit (finding g). It remains conditional on the unverified size basis.
- **A third option for the namespace-empty proof**, counter-free, on top of the decision's two (I15). It does not make the profile cheaper; the decision's reasons for declining (the caller-clock risk, the unenforceable skew assumption, the large revision for a weak profile, a supported AWS alternative) do not depend on the measurements, and the decision says so.

## 12. If scheduled for the next version

Not scheduled. If the maintainer later schedules DynamoDB for the next version, this is the order and the cost. Effort: S is under two days, M two to five, L more than five. The first gate is a decision, and everything after it is conditional on "accepted".

| Order | Issue (to open only when scheduled) | Effort | Needs | Gate |
| --- | --- | --- | --- | --- |
| 1 | **Service measurement spike**: run experiments A to D of section 10 against a real table and write the numbers into this note (no product code) | M | An AWS sandbox account with a budget alarm and a single Region; IAM role limited to the probe tables; two small hosts in the Region for experiment A; CloudWatch read access for the `TransactionConflict` metric; about 5 × 10^6 request units in all, plus PITR for one day. The adopter's required commits per second per namespace, stated in writing, to read experiment A against | None; first |
| 2 | **Reopen the decision with measurements**: a revision of the decision record giving the numbers and the adopter's deployment statement | S | The spike results; the maintainer | Reopening conditions of the decision: favourable A and B, an adopter, maintainer accepts the skew assumption as a deployment requirement. If any fails, stop: the decision stays declined and DynamoDB is declined |
| 3 | **Contract version 2 revision** (specification §3.6, §4, §5.6, §5.7, §5.8, §7.5, §8.2, §12) including `clockSource`, `allowCallerClockExpiry` with a required skew bound, fence and tombstone timestamps, delete and sweep comparisons, and `maxRestoreBytes`; threat-model update; ADR accepted | L | The maintainer's acceptance; a second review pass in the manner of the existing [design review](persistent-vault-design-review.md) | Step 2 accepted |
| 4 | **Namespace-empty rule**: choose between the recovery-item invariant (I15), a row counter, or an operator attestation; amend §5.8 accordingly with a conformance case | S to M | Spike data on single-partition-key throughput (experiment A); the maintainer's choice | Step 3 drafted |
| 5 | **`@redact-secret/store-dynamodb` adapter** over an injected client (as the AWS KMS provider is over an injected one): `TransactWriteItems` and `TransactGetItems` shapes of the research's section 4.1, `restoreDetection` by `TableId` if experiment C is favourable, declared limits from experiment B | L | Steps 3 and 4; AWS SDK for JavaScript v3 as a store-package dependency (§2); DynamoDB Local only for API-shape tests, never for conflict or size behavior | Step 3 accepted |
| 6 | **Conformance and qualification**: the common suite, the DynamoDB list of the research's section 10, a two-process concurrent schedule for the §5.2 conflict rule, a size-boundary test at the measured limits, a restore-then-detect test, and a qualification record | M to L | A real table in the sandbox; budget as step 1, larger; the measured per-item overhead | Step 5 |
| 7 | **Docs, status, and changelog**: store reference, `docs/status.md`, the research marked with the outcome, the Python parity question as a separate issue | S | Steps 5 and 6 | Step 6 |

Honest total if every gate passes: about two to three weeks of one engineer, most of it steps 3, 5, and 6, and about a day of calendar time added by experiment C. Steps 1 and 2 are the only ones worth starting before the maintainer commits to the profile, because they decide whether steps 3 to 7 exist; if step 1 shows check-only transactions conflict at the adopter's rate, the work stops at step 2 at the cost of one spike.

Refs #131
