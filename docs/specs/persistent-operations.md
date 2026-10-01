# Persistent vault operations

**Status:** proposed. This is the operational specification for [#111](https://github.com/redact-secret/redact-secret-vault/issues/111): expiry and cleanup, the four deletion-related operations, backup recovery, failover, and what an operator can and cannot promise. It complements the [persistent vault specification](persistent-vault.md), which defines the contracts, and does not restate them. Nothing here is a support claim. The packages it describes are unpublished.

It is written for the first backend, [`@redact-secret/store-postgres`](../../packages/store-postgres/README.md), with the persistent profile of [`@redact-secret/vault-server`](../../packages/vault-server/README.md). Statements about the contract apply to any store; statements about PostgreSQL say so.

Every claim below carries one of two marks:

- **Demonstrated** means current behavior of the code on this branch, shown by an executable scenario in the qualification run of the PostgreSQL store. The mark links to the scenario; the run's results are in the [qualification report](../../packages/store-postgres/qualification/report/report.md). It was shown on PostgreSQL 17.11, Node.js 22.16.0, and `pg` 8.23.1, and on nothing else.
- **Stated limit** means the claim was not demonstrated. It is either something the design does not do, or something it relies on the operator for.

## 1. Vocabulary

- A **server** is a process that called `createPersistentServerVault`. A **store** is what `createPostgresStore` returned.
- The **configured epoch** is the `recoveryEpoch` option of the server. It lives in deployment configuration, outside the database. The **stored epoch** is the namespace's epoch in the database.
- A **recovery** is any event after which the database may lack a commit it once acknowledged: a restore from a dump, a snapshot, or a base backup; point-in-time recovery; promotion of a replica that may be behind.

## 2. Expiry, revocation, and cleanup

### 2.1 Denial does not depend on cleanup

A capture is expired when the store's clock is at or past its `expiresAt`, and revoked when a revocation has committed. Both are conditions of the `commitRestore` transaction. Neither depends on any row having been removed.

- **Demonstrated:** a restore of an expired capture is denied `expired` before any sweep has run, and denied after its rows were swept ([sweep test](../../packages/store-postgres/test/sweep-concurrency.test.mjs)).
- **Demonstrated:** with a sweeper running continuously on a second connection, a fixed schedule of 110 commits produced the same successes and refusals as without one; no live capture, entry, or receipt was removed; no restore of an expired capture succeeded in either run. Cleanup changed one thing: an expired capture is refused `expired` while its rows exist and `unknown` afterwards (the server reports `unknown-token`) ([sweep test](../../packages/store-postgres/test/sweep-concurrency.test.mjs)).
- **Demonstrated:** a restore that began after a revocation was acknowledged never succeeded, across two server processes, and `used` equaled the number of successful restores in every trial ([two-process test](../../packages/store-postgres/test/two-process.test.mjs)).

### 2.2 Every record expires

There is no "never". A capture lives at most 24 hours (`LIMITS.maxCaptureLifetimeMs`); the server's default is 10 minutes (`limits.entryTtlMs`). The store rejects a longer lifetime with `STORE_INVALID_ARGUMENT`. The shared conformance suite checks this for the PostgreSQL store.

### 2.3 Retention of receipts and tombstones

These are the defaults in `packages/vault-server/src/persistent/server.ts`:

| What | Kept until | Default | Option, range |
| --- | --- | --- | --- |
| Receipt of a committed attempt | Latest `expiresAt` among its captures, plus the store's `maxClockSkewMs`, plus a grace | Grace 1 hour; skew bound 2000 ms in the PostgreSQL store | `receiptGraceMs`, 0 to 24 hours |
| Tombstone of a revoked capture | The later of the capture's `expiresAt` and the store clock at revocation, plus a retention | 24 hours | `tombstoneRetentionMs`, 0 to 30 days |
| Fence written for an absent capture | The store clock at the fence, plus the same retention | 24 hours | the same |

- **Demonstrated:** a receipt's stored expiry was exactly its capture's expiry + 2000 ms + 3 600 000 ms. It was still present after its capture and entry were swept, `resolveAttempt` still answered `committed`, a sweep at the millisecond of its expiry left it, and a sweep one millisecond later removed it. A tombstone was kept until exactly its capture's expiry + 24 hours, and its identifier stayed fenced against reuse ([sweep test](../../packages/store-postgres/test/sweep-concurrency.test.mjs)).
- `used` is stored on the entry, not on the receipt. Removing a receipt never makes a consumed use available again (specification §7.5).
- **Enforced:** the store refuses a receipt more than 48 hours past its clock, so the server refuses, at creation, a configuration whose capture lifetime, skew bound, and receipt grace together pass that horizon (`INVALID_ARGUMENT`). The qualification report's `outside` suite recorded the earlier behavior, before this check existed: the configuration was accepted and every restore failed closed with `INVARIANT_VIOLATION`.

### 2.4 Cleanup bounds

`store.sweepExpired({ namespace, now, limit })` removes at most `limit` rows per kind per call (`limit` 1 to 10 000) and reports `more`. It takes the caller's `now` and refuses `clock-skew`, so a store clock that jumped forward cannot delete live rows on its own authority.

- The server vault has no sweep method. The application schedules sweeps on the store, per namespace: for example once a minute, repeating while `more` is true. **Stated limit:** no schedule was measured for throughput or table growth.
- Skipping sweeps changes storage use only. Stored volume is bounded by the capture rate times the 24-hour ceiling plus retention.
- A swept row is gone from the table. Its bytes remain in the table's heap until vacuum reuses the space, and in WAL, replicas, snapshots, and backups for as long as those are kept. Section 3 applies.

## 3. The four operations

Specification §9 separates four things. This is how each is performed, and what it does not do.

| Operation | How | Effect | What it does not do |
| --- | --- | --- | --- |
| **Revoke** | `vault.revoke({ context, captureId })` | Future restores of the capture are denied, durably, in the store's transaction order | Remove ciphertext. Affect a value already returned |
| **Ciphertext deletion** | `vault.deleteCaptureCiphertext({ context, captureId })` | Revokes, then deletes the capture's entry rows and overwrites its stored wrapped key in the live database. The result carries `keyRetired: false` | Remove copies in backups, replicas, snapshots, WAL archives, server logs, or unvacuumed pages. Retire any key |
| **Key retirement** | The key owner, outside this library. With the local provider: construct it without the key version, or with it `retired` | Wrapped keys under that version can no longer be unwrapped by this provider | Anything, if a copy of the key material survives elsewhere. It also makes every capture under that version unreadable, not one capture |
| **Verified erasure** | Not an operation of this library | A statement by the key owner and the storage operator that no retained copy can be decrypted | It cannot be produced by any call in these packages |

Consequences that must accompany any description of deletion:

- A store cannot destroy a key and does not promise to. No single database delete is erasure.
- **A wrapped data key that survives in a backup stays usable for as long as its wrapping key is usable.** Deleting the row in the live database, or the capture's wrapped key there, is not cryptographic erasure: anyone with the backup and the wrapping key can decrypt the capture.
- Retiring a wrapping key shared by unrelated captures is not per-capture erasure. The local key provider derives every wrapping key from one material, so retiring that material makes every capture under it unreadable (specification §6.3).
- **Demonstrated, for the first clause only:** a database restored from a backup contained the captures, their wrapped keys, and their envelopes as of the backup, and a server holding the same key material decrypted and returned their values ([backup scenario](../../packages/store-postgres/qualification/scenarios/backup.scenario.mjs)). Revocation and consumption recorded after the backup were not in it.
- **Stated limit:** nothing in the qualification run exercised key retirement against a backup, or produced an erasure statement.

Routes to an erasure statement, none of which this library provides by itself:

1. **Scoped keys with an independent registry.** A key provider whose wrapping keys are scoped narrowly enough (for example per tenant and rotation period) that retiring one covers only the data to be erased, and a record, kept outside the vault's database, of which key covered which captures. Erasure is then the destruction of that key by its owner, evidenced by the key service.
2. **Bounded backup expiry.** Every backup, snapshot, WAL archive, and replica that could hold the wrapped key expires within a stated bound. Erasure completes when the last of them has.
3. **A stated completion delay.** The operator states that deletion completes after the backup retention period, and reports completion only then.

A capture lives at most 24 hours. That bounds how long a value is restorable through the server. It does not bound how long its ciphertext and wrapped key exist in backups.

## 4. What is exposed, and to whom

The metadata a reader of the store sees is listed in specification §3.7, and the trust boundaries are the table in specification §10. They are not repeated here. This section adds what the qualification run showed for each row of that table, for the PostgreSQL store.

| Party (specification §10) | Shown in the qualification run |
| --- | --- |
| Reads the store or a backup | **Stated limit:** not exercised as an attack. The schema holds no column for a value, token, type, grant, or key, and the server-log scenario found no value, token, or key in anything sent to the database |
| Writes the store | **Demonstrated:** swapping envelopes between entries and between tenants, moving a whole record to another tenant, extending `expires_at`, raising `max_uses`, removing or replacing a `session_tag`, and swapping `wrapped_key` between captures were each denied (`integrity-failure`, or `source` for a foreign session tag) with nothing consumed. **Demonstrated as a limit:** resetting `used` to 0 made a consumed single-use value restorable again. Authenticated encryption shows a record is authentic; it does not show its counter is current ([two-process test](../../packages/store-postgres/test/two-process.test.mjs)) |
| Rolls the store back | **Demonstrated as a limit:** a restored backup, and a promoted stale replica, held authentic old rows; a server on the old epoch released a consumed value a second time and restored a revoked capture. Sections 5 and 6 are the control |
| Holds a wrapping key and a store copy | **Stated limit:** can decrypt every capture under that key. Revocation and expiry are server checks and do not stop it |
| Compromises the server process, the key service, or supplies a hostile `Store` or `KeyProvider` | **Stated limit:** as specification §10. Nothing here contains such a party |

**Database logs.** Outside the application's processes, the database's own log can hold stored bytes. **Demonstrated** ([server-log scenario](../../packages/store-postgres/qualification/scenarios/server-log.scenario.mjs)): with PostgreSQL's defaults a successful call logs nothing, and a failing statement logs its text and a `DETAIL` that for a constraint violation prints the failing row, including identifiers and the first bytes of the envelope; with `log_statement = all` every bound parameter is logged, including whole envelopes and wrapped keys; with `log_parameter_max_length = 0` as well, statement text only. No plaintext value, issued token, or key appeared under any configuration, because none is sent to the database. Operators keep `log_statement` at `none` or `ddl`, set `log_parameter_max_length = 0` and `log_parameter_max_length_on_error = 0`, and give server logs and WAL archives the retention and access control of the database itself, since for erasure purposes they are copies of it.

**Application errors and audit events.** **Demonstrated:** no `StoreError`, server error, or audit event carried a driver message, SQLSTATE, connection string, or stored byte when PostgreSQL returned errors containing row data ([diagnostics test](../../packages/store-postgres/test/diagnostics.test.mjs)).

## 5. Backup recovery runbook

Use this after any recovery (section 1), including one you are not sure lost anything. It makes every capture in the recovered namespace unusable. That is the only safe outcome version 1 offers: there is no operation that returns recovered captures to service, because that would need a record of consumption and revocation kept outside the database (specification §9.3).

1. **Stop every server of the namespace, or cut its access to the database, before the recovered database accepts application connections.** Revoke the serving role's `CONNECT`, close the network path, or keep the recovered instance on an address no server uses.

   Why this is first. **Demonstrated:** for two restore methods the adapter's tripwire sees nothing (section 5.1), and a server still configured with the old epoch then served the recovered rows: it released a consumed single-use value again and restored a revoked capture ([backup scenario](../../packages/store-postgres/qualification/scenarios/backup.scenario.mjs)).

2. **Quarantine the namespace on the recovered database.** With a store opened on it by a maintenance process:

   ```js
   const store = await createPostgresStore({ pool, schema });
   await store.quarantine({ namespace });   // -> { epoch, state: "quarantined" }
   ```

   Do this for every namespace in the database. The library has no call that lists namespaces; read them with `SELECT namespace, epoch, state FROM "<schema>".rsv_namespace`. From here captures and commits are rejected, and revocation still works.

3. **Raise the configured epoch** in deployment configuration: the stored epoch plus one, or any larger number that no backup of this database can hold.

4. **Invalidate the recovered captures.**

   ```js
   await store.invalidateRecovered({ namespace, newEpoch });
   // -> { outcome: "invalidated", recovery: { epoch: newEpoch, state: "serving" } }
   ```

   `rejected: "epoch-not-greater"` means `newEpoch` is not above the stored epoch: choose a higher one and repeat step 3. Every capture stamped with an earlier epoch is revoked from this commit on, whatever its `used` or state said. The PostgreSQL store also records the database's present identity.

5. **Start the servers with the new epoch.** `createPersistentServerVault({ recoveryEpoch: newEpoch, ... })` fails `STORE_QUARANTINED` for any other value, and a server that kept running with the old one is refused on every capture and restore.

6. **Applications capture again from their sources.** Tokens issued before the recovery are denied `revoked`.

**Demonstrated** for all four restore methods of section 5.1: after steps 2 to 4, every recovered capture was denied `revoked`, including the one consumed after the backup, the one revoked after the backup, one never touched, and one consumed before the backup; a server on the old epoch was refused `STORE_QUARANTINED`; new captures worked ([backup scenario](../../packages/store-postgres/qualification/scenarios/backup.scenario.mjs)). The same held for a promoted stale replica ([failover scenario](../../packages/store-postgres/qualification/scenarios/failover.scenario.mjs)).

**Demonstrated:** the epoch record is in the database and is rolled back with it. Restoring the old dump again over an invalidated database brought back the old epoch in a serving state. Servers configured with the new epoch refused it. The configured epoch, outside the database, is what protects; keep it where a database restore cannot change it.

**Stated limits:**

- A backup taken after step 4 carries the current epoch. Restoring it later is again a recovery, and only this runbook, run again with a higher epoch, protects.
- A party that can write the database, or roll it back without the operator's knowledge, can also restore the epoch record and whatever the tripwire reads. This design does not detect a malicious rollback (specification §9.3).
- The store-level calls of this runbook emit no audit event. Record them in your own change log (section 10).

### 5.1 What the tripwire notices by itself

The PostgreSQL store compares the cluster's system identifier and the timeline it is writing WAL on with the values recorded in the namespace record, in every transaction, and reads the namespace as `quarantined` when they differ. **Demonstrated:**

| Restore method | System identifier | Timeline | Quarantined with no operator action |
| --- | --- | --- | --- |
| `pg_dump` restored into a new cluster | changed | same | yes |
| Base backup, WAL archive, recovery to a named restore point, promote | same | changed | yes |
| `pg_dump` restored into the same cluster | same | same | **no** |
| Base backup (or a file-system snapshot) started as a plain copy, without recovery configuration | same | same | **no** |
| Promotion of a streaming standby | same | changed | yes, on the first call after promotion |

The tripwire is a guard against a skipped runbook, not the runbook. For the two undetected methods, **demonstrated:** a server configured with a raised epoch refused the restored database, and steps 2 to 4 invalidated it. **Stated limits:** timeline numbers are not unique across divergent histories; rows restored selectively into a live database change neither value; neither case was tested.

## 6. Failover runbook

A failover is a recovery unless the promoted node is known to hold every commit the old primary acknowledged. That is knowable for one topology only: the qualified profile with one synchronous standby.

After any promotion the namespace reads `quarantined` on the promoted node. **Demonstrated:** it did so on the first call after promotion, while PostgreSQL's control file still reported the old timeline; servers were refused `STORE_QUARANTINED`, and the acknowledged consumption, revocation, and receipt were on the promoted node ([failover scenario](../../packages/store-postgres/qualification/scenarios/failover.scenario.mjs)).

### 6.1 Promotion of the synchronous standby

Call `acknowledgeIdentityChange` only when all of the following are established. If any is unknown, use section 5.

1. **The servers ran with `requireSynchronousStandby: true`.** The store then refused to start, and refused every transaction, whenever `synchronous_standby_names` was empty. **Demonstrated:** with the setting removed by a reload while a store was running, commits failed `STORE_UNAVAILABLE` and applied nothing.
2. **`synchronous_standby_names` named exactly the standby that was promoted, and nothing else changed it.** Check the configuration history and your failover tool's log. A tool that removes the synchronous standby to keep the primary available turns the topology into a single primary with an asynchronous replica; item 1 makes servers stop in that case, but only if they ran with the option.
3. **The promoted node is that standby**, not another replica.
4. **Nobody cancelled a backend that was waiting for the standby.** PostgreSQL completes such a `COMMIT` with a warning: the transaction is committed on the primary and may be missing on the standby. **Demonstrated:** a commit was not acknowledged for as long as the standby was down, even from a session whose default was `synchronous_commit = off` and past the adapter's statement timeout; when an operator cancelled the waiting backend, the store reported `STORE_AMBIGUOUS`, not success. **Stated limit:** that detection needs a `pg` client; and it does not cover a primary restarted while commits were waiting.
5. **The old primary is fenced.** It must not accept another write. The adapter cannot detect two primaries.

Then, for every namespace:

```js
await store.acknowledgeIdentityChange({ namespace });   // -> { epoch, state: "serving" }
```

A server process that kept running needs no restart: it reads the recovery state on every call. **Demonstrated**, with a server instance opened after the acknowledgement: the consumed entry stayed consumed, the revoked capture stayed revoked, `resolveAttempt` for the attempt committed before the failover answered `committed`, an untouched capture restored, and new captures worked ([failover scenario](../../packages/store-postgres/qualification/scenarios/failover.scenario.mjs)).

`acknowledgeIdentityChange` accepts a new timeline of the same cluster and nothing else. **Demonstrated:** it refuses a database with a different system identifier, leaves a namespace quarantined by `quarantine` quarantined, and never changes the epoch. It cannot tell a synchronous standby from a stale one.

After the failover the promoted node has no synchronous standby. A store created with `requireSynchronousStandby: true` refuses it until one is attached and named (**demonstrated**). Running on it meanwhile is the single-primary profile, and has to be an explicit decision.

Restores that were in flight during the failover end `COMMIT_AMBIGUOUS` or `STORE_UNAVAILABLE`. The application resolves each with `resolveAttempt` on the new primary (specification §7.3).

### 6.2 Promotion of anything else

An asynchronous replica, a replica whose lag is unknown, or a synchronous standby for which section 6.1 cannot be established: use section 5.

**Demonstrated** as a negative control ([failover scenario](../../packages/store-postgres/qualification/scenarios/failover.scenario.mjs)): a primary acknowledged a restore (and returned its value), a revocation, and their receipt, while its asynchronous standby was stopped. The primary was killed and the standby promoted. The promoted node held none of the three. After `acknowledgeIdentityChange` was wrongly called, the single-use value was released a second time, the revoked capture was restorable, and `resolveAttempt` for the delivered restore answered `absent`. In a second namespace on the same node, the runbook of section 5 made every recovered capture unusable.

The two halves of that scenario ran the same adapter, the same `READ COMMITTED` transactions, and the same row locks. What decided whether an acknowledged commit survived was whether its WAL had reached the promoted node before the acknowledgement. Transaction isolation orders concurrent transactions on one node. It is not evidence of crash or failover durability, and nothing in this design infers one from the other.

## 7. Time, clocks, and disaster recovery

- The store judges expiry at commit with the database clock and rejects a caller whose `now` differs from it by more than `maxClockSkewMs`. A server whose clock drifts fails closed, `CLOCK_SKEW`, instead of disagreeing about expiry. This is checked by the conformance suite against the PostgreSQL store with a controlled clock.
- If only the database clock is set back, the extension of any lifetime is at most the skew bound. **Stated limit:** if the database's and the servers' clocks are set back together, lifetimes extend by that amount and nothing inside the system can detect it. Trustworthy time on the database host and on every server is a deployment requirement (specification §7.5).
- A restart does not reset any deadline; all are absolute timestamps. **Demonstrated** for restart and crash recovery of the database ([restart scenario](../../packages/store-postgres/qualification/scenarios/restart.scenario.mjs)) and for a restart of both server processes ([two-process test](../../packages/store-postgres/test/two-process.test.mjs)).
- **Disaster recovery is a recovery.** Bringing the namespace up in another site from a backup or from an asynchronous replica follows section 5. Bringing it up on a synchronous standby in another site follows section 6.1. **Stated limit:** no cross-site topology was tested.
- The recovery site needs the wrapping key material and the digest key. Without the wrapping key every capture is unreadable; with a different digest key, session-bound captures are denied and outstanding attempts cannot be resolved (specification §7.3). After section 5 neither matters for old captures, which are revoked anyway.
- Since a capture lives at most 24 hours, a recovery older than that restores only expired captures. Section 5 is still required: the epoch, not the age of the backup, is the control.

## 8. Migrations and stored state

- Store schema migrations are forward-only and never rewrite `used`, a revision, an epoch, or a capture state (specification §11). **Demonstrated** for the PostgreSQL store: running the migration three more times over a schema holding consumed entries, a revoked capture, and a receipt changed no row and no object; two processes migrating one new schema at once both succeeded; a store refused a schema version above or below its own; the serving role could not run a migration ([privilege test](../../packages/store-postgres/test/least-privilege.test.mjs)).
- There is no down migration. Rolling back a release means running the previous adapter against a schema it accepts.
- Replacing a capture's wrapped key (`replaceCaptureKey`) is a compare-and-swap on `keyRevision` that changes no envelope, counter, state, generation, epoch, or time. The conformance suite's `rekey` group checks this against the PostgreSQL store. Version 1 has no operation that replaces envelopes; `ciphertextRevision` is 1 for every entry and is checked at commit.
- **Stated limit:** no migration between schema versions exists yet, so none was tested.

## 9. Maintenance interface

Lifecycle operations on captures go through the server and are authenticated the way restores are.

- `revoke` and `deleteCaptureCiphertext` take a `context`, not a tenant. The tenant and session come from the application's `resolvePrincipal` and `resolveSession`; a capture of another tenant is not found, and a session-bound capture is managed only from its own session.
- `lifecyclePolicy` is asked once per `capture`, `revoke`, `deleteCaptureCiphertext`, and `resolveAttempt`, with the operation, principal, tenant, session, and capture identifier. Anything but `{ allow: true }`, including a throw or a timeout, fails the operation `LIFECYCLE_DENIED` before any store mutation (specification §8.2).
- There is no tenant-wide delete and no operation keyed by a caller-supplied tenant string. Removing everything of a tenant is done capture by capture by a principal of that tenant, or by letting captures expire.
- **Demonstrated:** across two processes, a principal of another tenant could not restore, revoke, delete, or resolve an attempt of a capture: `unknown-token`, `not-found`, `not-found`, `absent` ([two-process test](../../packages/store-postgres/test/two-process.test.mjs)). **Stated limit:** the qualification run used an allow-all `lifecyclePolicy`; denial by that policy is covered by the server's own behavior, not by these scenarios.

Recovery and cleanup operations are on the store, not the server: `initializeNamespace`, `quarantine`, `invalidateRecovered`, `acknowledgeIdentityChange`, and `sweepExpired`. They take a namespace and no principal. Whoever holds the serving role's database credentials and can run code with the store can call them. Run them from a maintenance process under operator control, and do not expose them through an application endpoint.

## 10. Audit events

The server's `onAudit` hook receives one event per operation: `capture`, `restore`, `revoke`, `delete-ciphertext`, `resolve-attempt`, and `resolve-principal` and `policy-error` for those failures. Each has an outcome (`committed`, `denied`, `failed`), a time, and where known the principal identifier, tenant, sink, purpose, denial reason or error code, entry count, capture identifier, attempt identifier, and request identifier. Events never carry a value, a token, a key, ciphertext, or a driver or provider message; **demonstrated** for failures caused by database errors that contained row data ([diagnostics test](../../packages/store-postgres/test/diagnostics.test.mjs)).

**Stated limits:**

- The store-level operations of section 9 emit no audit event. An operator's quarantine, invalidation, identity acknowledgement, and sweeps are recorded only where the operator records them.
- An exception thrown by the hook is swallowed so that audit delivery cannot change an operation's outcome. A lost audit event is therefore not reported.
- A restore that committed and whose response was lost is audited by the process that committed it only if that process survived. **Demonstrated:** when the process was killed after the commit, the use was spent, another process's `resolveAttempt` answered `committed`, and no value was available again ([two-process test](../../packages/store-postgres/test/two-process.test.mjs)). The receipt in the database, not the audit trail, is the durable record of that attempt.

## 11. Evidence

| Claim | Scenario |
| --- | --- |
| Denial at expiry and revocation is independent of cleanup; receipt and tombstone retention | [sweep-concurrency.test.mjs](../../packages/store-postgres/test/sweep-concurrency.test.mjs) |
| Two processes, concurrency, response loss, tenant isolation, record substitution, the `used` reset limit | [two-process.test.mjs](../../packages/store-postgres/test/two-process.test.mjs) |
| Failure before, at, and after `COMMIT`; ambiguity and its resolution; no commit retry | [commit-failure.test.mjs](../../packages/store-postgres/test/commit-failure.test.mjs) |
| Restart and crash recovery | [restart.scenario.mjs](../../packages/store-postgres/qualification/scenarios/restart.scenario.mjs) |
| Failover to a synchronous standby; the asynchronous negative control | [failover.scenario.mjs](../../packages/store-postgres/qualification/scenarios/failover.scenario.mjs) |
| Backup restore, the detection matrix, the runbook | [backup.scenario.mjs](../../packages/store-postgres/qualification/scenarios/backup.scenario.mjs) |
| Serving-role privileges and migrations | [least-privilege.test.mjs](../../packages/store-postgres/test/least-privilege.test.mjs) |
| Sanitized errors and audit events; database logs | [diagnostics.test.mjs](../../packages/store-postgres/test/diagnostics.test.mjs), [server-log.scenario.mjs](../../packages/store-postgres/qualification/scenarios/server-log.scenario.mjs) |
| Results, versions, settings, counts, and times of the run | [report.md](../../packages/store-postgres/qualification/report/report.md), [summary.json](../../packages/store-postgres/qualification/report/summary.json) |

## 12. What this does not provide

- Returning recovered captures to service, or reconciling them against an external ledger.
- Detection of a malicious or unnoticed rollback.
- Erasure. The library revokes and deletes rows; an erasure statement is the key owner's and the storage operator's.
- Protection against a party holding a wrapping key and a copy of the store.
- A tenant-wide delete, a namespace listing, an audit trail for store-level operations, or a sweep scheduler.
- Any claim for a backend, PostgreSQL version, topology, or runtime other than those the qualification report names.
