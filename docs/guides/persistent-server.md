# Persistent server

**On `main`, unpublished, alpha.** An opt-in entry point for captures that one server process makes and another restores, or that survive a restart. It is specified in the [persistent vault specification](../specs/persistent-vault.md) (§7, §8) and qualified only as the [qualification record](../research/qualification-persistence-0.1.0-alpha.1.md) states. Importing `@redact-secret/vault-server` loads none of it.

## Quick start

These packages cannot be installed from npm yet. The example is the shape of a server that captures in one process and restores in another, over PostgreSQL. Read the [qualified profiles](../research/qualification-persistence-0.1.0-alpha.1.md#2-tested-matrix) and the [operations specification](../specs/persistent-operations.md) before using it.

Once, from a maintenance process: `migrate(ownerPool, "rsv")`, the grants from `grantStatements("rsv", role)`, and `store.initializeNamespace({ namespace: "support-prod", epoch: 1 })`. A server never initializes a namespace. Then, in every server process:

```ts
import pg from "pg";
import { createPostgresStore } from "@redact-secret/store-postgres";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";

// The application creates the pool and closes it. Nothing below ends it.
const pool = new pg.Pool({ connectionString: databaseUrl, max: 20, connectionTimeoutMillis: 5000 });
pool.on("error", () => {});
const store = await createPostgresStore({ pool, schema: "rsv" });

// 32 bytes each, from the application's secret manager. Never a literal, never from this library.
const material = await loadWrappingKeyFromSecretManager();
const digestKey = await loadDigestKeyFromSecretManager(); // the same in every process of the namespace

const SINK = "support-ticket-reply-sink-synthetic";
const PURPOSE = "support-reply-purpose-synthetic";

const vault = await createPersistentServerVault({
  namespace: "support-prod",
  recoveryEpoch: 1, // from deployment configuration, kept outside the database
  store,
  crypto: createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "2026-10", material, state: "active" }],
      scope: { namespaces: ["support-prod"] },
    }),
  }),
  digestKey,
  resolvePrincipal: (ctx) => ({ id: ctx.userId, tenant: ctx.tenant }), // from already-authenticated context; throw if unknown
  resolveSession: (ctx) => ctx.conversationId, // binds each capture to its conversation
  // Deny by default: this server may capture and revoke, and nothing else.
  lifecyclePolicy: ({ operation }) => ({ allow: operation === "capture" || operation === "revoke" }),
  // Deny by default: one sink, one purpose.
  policy: (input) =>
    input.sink === SINK && input.purpose === PURPOSE ? { allow: true } : { allow: false, reason: "policy" },
  limits: { entryTtlMs: 5 * 60 * 1000 }, // every capture expires; the ceiling is 24 hours
  pii: [], // core PII detection off
});

const captured = await vault.capture(userText, {
  context: request,
  release: [{ sink: SINK, paths: ["body"] }], // the only sink and path a value may return to
});
// ... send captured.text to the model ...
const { fields } = await vault.restore({
  context: request,
  sink: SINK,
  purpose: PURPOSE,
  captures: [captured.captureId],
  fields: { body: modelReply },
});

await vault.close(); // releases this instance only
await pool.end(); // the application closes what it opened
```

A restore releases a value at most once. A denied, conflicting, or ambiguous restore returns no fields; keep the redacted text, and see [Failures](#failures) for each one. After a database restore from backup or a failover that may have lost commits, recovered captures are not returned to service: the supported path is to invalidate them and capture again ([runbook](../specs/persistent-operations.md#5-backup-recovery-runbook)).

## Who owns what

The server authorizes and orchestrates. It never opens a database or key-service connection: `store` and `crypto` are objects the application constructs, and the application closes whatever they hold (a `pg` pool, a KMS client). The server decrypts in process, so values exist in its memory for the duration of a call; the store only ever receives ciphertext, wrapped keys, counters, and receipts. An injected `Store` or `RecordCrypto` runs inside the trusted process and is not contained by its interface.

## Options

Required: `namespace`, `recoveryEpoch`, `store`, `crypto`, `resolvePrincipal`, `policy`, `lifecyclePolicy`, and `digestKey` (or `allowUnkeyedDigests: true`, which accepts that a reader of the store can test guesses of principal, sink, purpose, and session against stored digests).

Optional: `resolveSession`; `onAudit`; `limits` (`entryTtlMs` is the capture lifetime: default 10 minutes, at most 24 hours; there is no "never"); `now`; `policyRevision`; `resolverTimeoutMs` and `policyTimeoutMs` (default 5000 each); `storeTimeoutMs` (10000); `cryptoTimeoutMs` (15000); `maxCommitRetries` (3, at most 10); `receiptGraceMs` (one hour); `tombstoneRetentionMs` (24 hours); `pii` and `expectPiiActivation`.

Waivers, each off by default: `allowNonDurableStore` (accept a volatile or single-process store such as `@redact-secret/store-memory`; for tests) and `allowNoRestoreDetection` (accept a durable store that declares no restore detection).

Creation fails closed: `UNSUPPORTED_STORE` when the store does not declare the required capabilities, `STORE_QUARANTINED` unless the namespace is serving at `recoveryEpoch`, and `INVALID_ARGUMENT` for a missing digest key or when `limits.entryTtlMs` plus twice the store's clock-skew bound plus `receiptGraceMs` exceeds the 48 hours a store accepts for a receipt. The server never initializes a namespace; a maintenance process calls `store.initializeNamespace` once.

## Operations

| Call | What it does | What it does not do |
| --- | --- | --- |
| `capture(input, { context, release, ... })` | Resolves principal and session from `context`, asks `lifecyclePolicy`, scans with the core, encrypts each retained value, and creates the capture and its entries in one store transaction. Tokens are returned only after that transaction succeeded | Accept a tenant or session from the caller: `issuedTenant`, `tenant`, and `sessionId` in the options have no effect |
| `restore({ context, sink, purpose, captures, fields, attemptId? })` | Authorizes every occurrence (session, expiry, budget, grants, policy), stages the output, commits one conditional transaction, and returns the fields only on a definite commit. Each restore that reaches the store has an `attemptId`, generated when omitted | Return anything on a denial, conflict, or unknown outcome. Release a value twice for one use |
| `revoke({ context, captureId })` | Durably denies future restores of one capture | Delete ciphertext. Retract a value already returned |
| `deleteCaptureCiphertext({ context, captureId })` | Revokes, then deletes the capture's entry rows and stored wrapped key from the live store. The result carries `keyRetired: false` | Erase. Copies in backups, replicas, and logs remain decryptable while the wrapping key is usable, and no key is retired |
| `resolveAttempt({ context, attemptId, ...originalRequest })` | Reports whether an attempt committed: `committed`, `absent`, or `attempt-mismatch` | Return restored fields, ever |
| `close()` | Releases this instance; later calls fail `CLOSED` | Revoke, delete, or close the store, the pool, or the key provider |

`revoke` and `deleteCaptureCiphertext` are found only within the caller's own tenant, and for a session-bound capture only from its own session. There is no tenant-wide delete. Cleanup of expired rows is `store.sweepExpired`, scheduled by the application; it is never what denies a restore.

## Failures

Summarized from [specification §7.3](../specs/persistent-vault.md#73-attempts-and-failure-outcomes), which is authoritative. No row returns fields except the first.

| Outcome | Stored effect | What the caller does |
| --- | --- | --- |
| Success | Budget consumed, receipt written | Use the fields, once |
| `RESTORE_DENIED` with a reason | None | Keep the redacted text |
| `RESTORE_CONFLICT` (still `stale` after the retries) | None | May retry the same attempt |
| `STORE_UNAVAILABLE` | None | May retry the same attempt |
| `STORE_QUARANTINED`, `CLOCK_SKEW` | None | Fix the deployment: the epoch or recovery state, or the clocks |
| `COMMIT_AMBIGUOUS` (carries `attemptId`) | Unknown | Call `resolveAttempt`. On `absent`, the same attempt may be submitted again. On `committed`, the use is spent and the value was not delivered: capture it again from its source |
| Same `attemptId` and request after it committed | None | `RESTORE_DENIED`: `attempt-already-committed`, or `budget` when that attempt exhausted the entry |
| Same `attemptId`, different request | None | `RESTORE_DENIED`, `attempt-mismatch` |
| `LIFECYCLE_DENIED` | None | The lifecycle policy, a resolver, or a timeout denied capture, revoke, deletion, or resolution |
| `KEY_UNAVAILABLE` (capture only), `LIMIT_EXCEEDED` | None | Nothing was stored. At restore, a key failure is the denial `key-unavailable` |

Release is **at most once**. The server never retries an ambiguous commit and never replays a committed result. Exactly-once delivery is not provided.

A failed capture returns no result, so no usable token leaves the server. When the store cannot say whether a capture was created, the server fences the identifier it issued so the capture cannot be restored.

## Differences from `createServerVault`

[Specification §8.3](../specs/persistent-vault.md#83-differences-from-the-in-memory-server) lists them. The ones most likely to matter: a token of another tenant is `unknown-token` (not `tenant-mismatch`), because another tenant's rows are never read; a session-bound capture is enforced (`source`), where the in-memory server's `sessionId` is advisory; an explicit `tenant` or `sessionId` on a restore is ignored; capture requires a principal; at most 64 captures per restore; and `revoke` takes `{ context, captureId }` and is gated by `lifecyclePolicy`.

## Limits to know before deploying

- A party that can write the database can reset a use counter or a revocation. Encryption shows a record is authentic, not current.
- After a database restore from backup, or a failover that may have lost commits, follow the [recovery runbook](../specs/persistent-operations.md#5-backup-recovery-runbook): recovered captures are invalidated, and applications capture again. Keep `recoveryEpoch` where a database restore cannot change it.
- The same `digestKey` must be configured in every process of the namespace; changing it loses outstanding attempts and session-bound captures.
- Audit events (`capture`, `restore`, `revoke`, `delete-ciphertext`, `resolve-attempt`, `resolve-principal`, `policy-error`) carry codes, counts, and opaque identifiers only. Store-level recovery and cleanup calls emit none.
- The threat model's [persistent section](../specs/threat-model.md#persistent-mappings--implemented-on-main-qualified-for-two-postgresql-profiles) lists what is and is not protected.

## Related

- [`@redact-secret/store-postgres`](../../packages/store-postgres/README.md) and its [reference](../reference/store-postgres.md): the qualified store.
- [`@redact-secret/vault-crypto`](../../packages/vault-crypto/README.md): record encryption and the local key provider.
- [`@redact-secret/key-provider-aws-kms`](../../packages/key-provider-aws-kms/README.md): the optional AWS KMS key provider.
- [`@redact-secret/store-memory`](../../packages/store-memory/README.md): a non-durable store for tests.
