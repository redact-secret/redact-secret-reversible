import {
  LIMITS,
  StoreError,
  validateCommitRestore,
  validateCreateCapture,
  validateDeleteCiphertext,
  validateInitializeNamespace,
  validateInspectAttempt,
  validateInvalidateRecovered,
  validateNamespace,
  validateReadCaptures,
  validateReadEntries,
  validateReplaceCaptureKey,
  validateRevokeCapture,
  validateSweep,
} from "@redact-secret/vault-contracts";
import type {
  CommitRestoreInput,
  CommitRestoreResult,
  CreateCaptureInput,
  CreateCaptureResult,
  DeleteCiphertextInput,
  DeleteCiphertextResult,
  InitializeNamespaceResult,
  InspectAttemptInput,
  InspectAttemptResult,
  InvalidateRecoveredInput,
  InvalidateRecoveredResult,
  ReadCapturesInput,
  ReadEntriesInput,
  ReadEntriesResult,
  RecoveryState,
  ReplaceCaptureKeyInput,
  ReplaceCaptureKeyResult,
  RevokeCaptureInput,
  RevokeCaptureResult,
  Store,
  StoreCallOptions,
  StoreCapabilities,
  StoredCapture,
  StoredEntry,
  SweepInput,
  SweepResult,
} from "@redact-secret/vault-contracts";

import { isSchemaName, migrationStatements, SCHEMA_VERSION } from "./schema.js";

/**
 * The part of a `pg` client this adapter uses. Declared structurally so the
 * adapter imports no driver: the application creates the pool, owns its
 * configuration and credentials, and closes it.
 */
export interface PgClientLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
  release(destroy?: boolean | Error): void;
  /**
   * Optional, as on a `pg` client. When both are present the adapter listens
   * for `error` on a client for as long as it holds it: `pg` emits that event
   * when a checked-out connection fails, and Node.js turns an `error` event
   * nobody listens for into an uncaught exception.
   */
  on?(event: string, listener: (...args: unknown[]) => void): unknown;
  removeListener?(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface PgPoolLike {
  connect(): Promise<PgClientLike>;
}

export interface PostgresStoreOptions {
  /** A `pg.Pool` connected to the primary. The application owns and closes it. */
  readonly pool: PgPoolLike;
  /** Schema holding the tables. Default `rsv`. Lowercase identifier. */
  readonly schema?: string;
  /** Largest accepted difference between the database clock and a caller's `now`. Default 2000. */
  readonly maxClockSkewMs?: number;
  /**
   * The commit durability this store insists on for every write transaction:
   * `on` (local flush; with a synchronous standby configured, also its
   * flush) or `remote_apply`. Default `on`. A weaker session or database
   * default is overridden per transaction.
   */
  readonly synchronousCommit?: "on" | "remote_apply";
  /** Refuse to start unless `synchronous_standby_names` is set. Default false. */
  readonly requireSynchronousStandby?: boolean;
  /** Per-statement deadline inside a transaction. Default 5000. */
  readonly statementTimeoutMs?: number;
  /** How long a transaction waits for a row lock before reporting `stale`. Default 2000. */
  readonly lockTimeoutMs?: number;
  readonly maxCreateEntries?: number;
  readonly maxCreateBytes?: number;
  readonly maxRestoreEntries?: number;
  readonly maxRestoreCaptures?: number;
  readonly maxEnvelopeBytes?: number;
}

export interface PostgresStore extends Store {
  /**
   * Records the database's current identity for a namespace without changing
   * its epoch, after the operator has established that the change of identity
   * lost no acknowledged commit (promotion of a synchronous standby). Any
   * other change of identity is a recovery: use `invalidateRecovered`.
   */
  acknowledgeIdentityChange(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState>;
  /** Marks this adapter closed. The pool stays open: the application owns it. */
  close(): void;
}

const NOW_MS = "(extract(epoch from clock_timestamp()) * 1000)::bigint";

/** Thrown inside a transaction body to roll back and return a result. */
class Rollback<T> {
  readonly value: T;
  constructor(value: T) {
    this.value = value;
  }
}

/** A lock wait, deadlock, or serialization failure: nothing was applied. */
class Contention {}

interface Head {
  readonly now: number;
  readonly systemIdentifier: string;
  readonly timelineId: number;
}

interface NamespaceRow {
  readonly epoch: number;
  readonly state: "serving" | "quarantined" | "uninitialized";
}

function sqlState(thrown: unknown): string | undefined {
  if (typeof thrown !== "object" || thrown === null) return undefined;
  const code = (thrown as { code?: unknown }).code;
  return typeof code === "string" && /^[0-9A-Z]{5}$/.test(code) ? code : undefined;
}

function toNumber(value: unknown): number {
  // `bigint` columns arrive as strings by default, and as BigInt or number when the application configured a type parser.
  const n = typeof value === "string" || typeof value === "bigint" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n)) throw new StoreError("STORE_UNAVAILABLE");
  return n;
}

function toBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new StoreError("STORE_UNAVAILABLE");
  return new Uint8Array(value);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function boundedOption(value: number | undefined, fallback: number, ceiling: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > ceiling) throw new StoreError("STORE_INVALID_ARGUMENT");
  return resolved;
}

/**
 * A client the adapter has taken from the pool, until `release`.
 *
 * While it is held, a connection failure is observed here and reaches the
 * caller only as the rejected statement that follows, never as an unhandled
 * `error` event. A client that is destroyed keeps the listener: late events
 * of a discarded connection must not escape either.
 */
function hold(client: PgClientLike): { release(destroy: boolean): void } {
  const listening = typeof client.on === "function" && typeof client.removeListener === "function";
  const ignore = (): void => {};
  if (listening) client.on?.("error", ignore);
  return {
    release(destroy: boolean): void {
      if (listening && !destroy) client.removeListener?.("error", ignore);
      client.release(destroy ? true : undefined);
    },
  };
}

/**
 * Creates the tables of schema version 1. Run once, by a role that owns the
 * schema, before any store is opened. See `grantStatements` for the serving
 * role's privileges.
 */
export async function migrate(pool: PgPoolLike, schema = "rsv"): Promise<void> {
  if (!isSchemaName(schema)) throw new StoreError("STORE_INVALID_ARGUMENT");
  let client: PgClientLike;
  try {
    client = await pool.connect();
  } catch {
    throw new StoreError("STORE_UNAVAILABLE");
  }
  const held = hold(client);
  try {
    await client.query("BEGIN");
    // One migration at a time across processes.
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`rsv-migrate:${schema}`]);
    for (const statement of migrationStatements(schema)) await client.query(statement);
    await client.query("COMMIT");
    held.release(false);
  } catch {
    let destroy = false;
    try {
      await client.query("ROLLBACK");
    } catch {
      destroy = true;
    }
    held.release(destroy);
    throw new StoreError("STORE_UNAVAILABLE");
  }
}

/**
 * Opens the store after verifying the deployment it is pointed at: the schema
 * version, that the server is a primary, that `fsync` is on, and that the
 * required commit durability can be set. It refuses to start otherwise.
 */
export async function createPostgresStore(options: PostgresStoreOptions): Promise<PostgresStore> {
  return openPostgresStore(options, NOW_MS);
}

/**
 * `createPostgresStore` with the SQL expression that yields the store clock.
 * Not exported from the package: the published entry point always uses the
 * database clock. This package's own tests import it from the build output
 * to run the time-dependent conformance cases against real transactions.
 */
export async function openPostgresStore(options: PostgresStoreOptions, nowSql: string): Promise<PostgresStore> {
  if (typeof options !== "object" || options === null) throw new StoreError("STORE_INVALID_ARGUMENT");
  const { pool } = options;
  if (typeof pool !== "object" || pool === null || typeof pool.connect !== "function") {
    throw new StoreError("STORE_INVALID_ARGUMENT");
  }
  const schema = options.schema ?? "rsv";
  if (!isSchemaName(schema)) throw new StoreError("STORE_INVALID_ARGUMENT");
  const synchronousCommit = options.synchronousCommit ?? "on";
  if (synchronousCommit !== "on" && synchronousCommit !== "remote_apply") throw new StoreError("STORE_INVALID_ARGUMENT");
  const maxClockSkewMs = options.maxClockSkewMs ?? 2000;
  if (!Number.isSafeInteger(maxClockSkewMs) || maxClockSkewMs < 0 || maxClockSkewMs > 60_000) {
    throw new StoreError("STORE_INVALID_ARGUMENT");
  }
  const statementTimeoutMs = boundedOption(options.statementTimeoutMs, 5000, 600_000);
  const lockTimeoutMs = boundedOption(options.lockTimeoutMs, 2000, 600_000);

  let client: PgClientLike;
  try {
    client = await pool.connect();
  } catch {
    throw new StoreError("STORE_UNAVAILABLE");
  }
  let standbyNames: string;
  const held = hold(client);
  try {
    const version = await client.query(`SELECT version FROM "${schema}".rsv_schema`);
    if (version.rows.length !== 1 || toNumber(version.rows[0]?.version) !== SCHEMA_VERSION) {
      throw new StoreError("STORE_CAPABILITY");
    }
    const facts = await client.query(
      "SELECT pg_is_in_recovery() AS standby, current_setting('fsync') AS fsync, current_setting('synchronous_standby_names') AS standbys",
    );
    const row = facts.rows[0] ?? {};
    // Writes are routed to the primary only, and durability is not inferred from isolation.
    if (row.standby !== false || row.fsync !== "on") throw new StoreError("STORE_CAPABILITY");
    standbyNames = typeof row.standbys === "string" ? row.standbys : "";
    if ((options.requireSynchronousStandby === true || synchronousCommit === "remote_apply") && standbyNames.trim() === "") {
      throw new StoreError("STORE_CAPABILITY");
    }
    held.release(false);
  } catch (thrown) {
    held.release(true);
    if (thrown instanceof StoreError) throw thrown;
    throw new StoreError("STORE_UNAVAILABLE");
  }

  const capabilities: StoreCapabilities = Object.freeze({
    contractVersion: 1,
    adapter: "store-postgres",
    profile:
      standbyNames.trim() === ""
        ? `postgres-single-primary/synchronous_commit=${synchronousCommit}`
        : `postgres-primary-with-synchronous-standby/synchronous_commit=${synchronousCommit}`,
    atomicCreate: true,
    maxCreateEntries: boundedOption(options.maxCreateEntries, LIMITS.maxCreateEntries, LIMITS.maxCreateEntries),
    maxCreateBytes: boundedOption(options.maxCreateBytes, 64 * 1024 * 1024, 256 * 1024 * 1024),
    atomicRestore: true,
    maxRestoreEntries: boundedOption(options.maxRestoreEntries, LIMITS.maxRestoreEntries, LIMITS.maxRestoreEntries),
    maxRestoreCaptures: boundedOption(options.maxRestoreCaptures, LIMITS.maxRestoreCaptures, LIMITS.maxRestoreCaptures),
    authoritativeCommit: true,
    revocationFences: true,
    attemptReceipts: true,
    storeClock: true,
    maxClockSkewMs,
    durability: "durable",
    crossProcess: true,
    restoreDetection: "postgres-system-identifier-and-timeline",
    maxEnvelopeBytes: boundedOption(options.maxEnvelopeBytes, LIMITS.maxEnvelopeBytes, LIMITS.maxEnvelopeBytes),
  });

  return new PostgresStoreImpl(pool, schema, capabilities, synchronousCommit, statementTimeoutMs, lockTimeoutMs, nowSql);
}

class PostgresStoreImpl implements PostgresStore {
  readonly #pool: PgPoolLike;
  readonly #t: { readonly ns: string; readonly capture: string; readonly entry: string; readonly receipt: string };
  readonly #capabilities: StoreCapabilities;
  readonly #synchronousCommit: string;
  readonly #statementTimeoutMs: number;
  readonly #lockTimeoutMs: number;
  readonly #nowSql: string;
  #closed = false;

  constructor(
    pool: PgPoolLike,
    schema: string,
    capabilities: StoreCapabilities,
    synchronousCommit: string,
    statementTimeoutMs: number,
    lockTimeoutMs: number,
    nowSql: string,
  ) {
    this.#pool = pool;
    this.#t = {
      ns: `"${schema}".rsv_namespace`,
      capture: `"${schema}".rsv_capture`,
      entry: `"${schema}".rsv_entry`,
      receipt: `"${schema}".rsv_receipt`,
    };
    this.#capabilities = capabilities;
    this.#synchronousCommit = synchronousCommit;
    this.#statementTimeoutMs = statementTimeoutMs;
    this.#lockTimeoutMs = lockTimeoutMs;
    this.#nowSql = nowSql;
  }

  capabilities(): StoreCapabilities {
    return this.#capabilities;
  }

  close(): void {
    this.#closed = true;
  }

  // ------------------------------------------------------------ transactions

  /**
   * One transaction on one connection.
   *
   * - A failure before `COMMIT` is sent leaves nothing applied: PostgreSQL
   *   discards an uncommitted transaction when it is rolled back or its
   *   connection ends. That is `STORE_UNAVAILABLE`, or `Contention` for a
   *   lock wait, deadlock, or serialization failure.
   * - A failure of `COMMIT` itself has an unknown outcome when the
   *   transaction wrote: `STORE_AMBIGUOUS`. This adapter never retries it.
   * - No driver error, message, or detail leaves this function.
   */
  async #transaction<T>(
    mode: "write" | "read",
    options: StoreCallOptions | undefined,
    body: (client: PgClientLike, head: Head) => Promise<T>,
  ): Promise<T> {
    if (this.#closed) throw new StoreError("STORE_CLOSED");
    const aborted = (): boolean => options?.signal?.aborted === true;
    if (aborted()) throw new StoreError("STORE_UNAVAILABLE");
    let client: PgClientLike;
    try {
      client = await this.#pool.connect();
    } catch {
      throw new StoreError("STORE_UNAVAILABLE");
    }
    const held = hold(client);
    let value: T;
    try {
      await client.query(mode === "write" ? "BEGIN ISOLATION LEVEL READ COMMITTED" : "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query(
        `SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true), set_config('synchronous_commit', $3, true)`,
        [String(this.#statementTimeoutMs), String(this.#lockTimeoutMs), this.#synchronousCommit],
      );
      const facts = await client.query(
        `SELECT ${this.#nowSql} AS now, pg_is_in_recovery() AS standby,
                (SELECT system_identifier::text FROM pg_control_system()) AS sysid,
                (SELECT timeline_id FROM pg_control_checkpoint()) AS timeline`,
      );
      const row = facts.rows[0] ?? {};
      // A connection that has landed on a standby is not the authority.
      if (row.standby !== false || typeof row.sysid !== "string") throw new StoreError("STORE_UNAVAILABLE");
      const head: Head = { now: toNumber(row.now), systemIdentifier: row.sysid, timelineId: toNumber(row.timeline) };
      value = await body(client, head);
      // Cancelled before COMMIT was sent: roll back, so the outcome is known.
      if (aborted()) throw new StoreError("STORE_UNAVAILABLE");
    } catch (thrown) {
      let destroy = false;
      try {
        await client.query("ROLLBACK");
      } catch {
        destroy = true;
      }
      held.release(destroy);
      if (thrown instanceof Rollback) return thrown.value as T;
      if (thrown instanceof StoreError || thrown instanceof Contention) throw thrown;
      const state = sqlState(thrown);
      // serialization_failure, deadlock_detected, lock_not_available
      if (state === "40001" || state === "40P01" || state === "55P03") throw new Contention();
      throw new StoreError("STORE_UNAVAILABLE");
    }
    try {
      await client.query("COMMIT");
    } catch {
      held.release(true);
      throw new StoreError(mode === "write" ? "STORE_AMBIGUOUS" : "STORE_UNAVAILABLE");
    }
    held.release(false);
    return value;
  }

  /**
   * The namespace recovery record under a lock: shared for operations that
   * must conflict with quarantine and invalidation (§5.2), exclusive for those
   * two. A database whose identity differs from the recorded one reads as
   * quarantined whatever the stored state says.
   */
  async #namespace(client: PgClientLike, head: Head, namespace: string, lock: "share" | "update" | "none"): Promise<NamespaceRow> {
    const suffix = lock === "share" ? " FOR SHARE" : lock === "update" ? " FOR UPDATE" : "";
    const result = await client.query(
      `SELECT epoch, state, system_identifier, timeline_id FROM ${this.#t.ns} WHERE namespace = $1${suffix}`,
      [namespace],
    );
    const row = result.rows[0];
    if (row === undefined) return { epoch: 0, state: "uninitialized" };
    const sameDatabase = row.system_identifier === head.systemIdentifier && toNumber(row.timeline_id) === head.timelineId;
    return {
      epoch: toNumber(row.epoch),
      state: sameDatabase && row.state === "serving" ? "serving" : "quarantined",
    };
  }

  #skewed(head: Head, now: number): boolean {
    return Math.abs(head.now - now) > this.#capabilities.maxClockSkewMs;
  }

  // -------------------------------------------------------------- operations

  async createCapture(input: CreateCaptureInput, options?: StoreCallOptions): Promise<CreateCaptureResult> {
    validateCreateCapture(input, this.#capabilities);
    const { scope, capture, entries } = input;
    const reject = (reason: "exists" | "fenced" | "clock-skew" | "quarantined" | "stale"): CreateCaptureResult => ({ outcome: "rejected", reason });
    try {
      return await this.#transaction<CreateCaptureResult>("write", options, async (client, head) => {
        const ns = await this.#namespace(client, head, scope.namespace, "share");
        if (ns.state !== "serving" || ns.epoch !== input.epoch) throw new Rollback(reject("quarantined"));
        if (this.#skewed(head, input.now) || this.#skewed(head, capture.createdAt)) throw new Rollback(reject("clock-skew"));
        const inserted = await client.query(
          `INSERT INTO ${this.#t.capture}
             (namespace, tenant, capture_id, state, generation, key_revision, epoch, session_tag,
              created_at, expires_at, key_ref, wrapped_key, has_ciphertext, retain_until)
           VALUES ($1, $2, $3, 'live', 1, 1, $4, $5, $6, $7, $8, $9, true, $7)
           ON CONFLICT (namespace, tenant, capture_id) DO NOTHING`,
          [scope.namespace, scope.tenant, capture.captureId, input.epoch, capture.sessionTag, capture.createdAt, capture.expiresAt, capture.keyRef, capture.wrappedKey],
        );
        if (inserted.rowCount !== 1) {
          const [existing] = await this.#captures(client, scope.namespace, scope.tenant, [capture.captureId], ns.epoch, "");
          // Revoked, fenced, or created under an earlier epoch: the identifier is fenced.
          throw new Rollback(reject(existing !== undefined && existing.state !== "live" ? "fenced" : "exists"));
        }
        const rows = await client.query(
          `INSERT INTO ${this.#t.entry}
             (namespace, tenant, entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision, envelope, expires_at)
           SELECT $1, $2, e.entry_id, $3, e.max_uses, 0, 1, 1, decode(e.envelope, 'hex'), $4
             FROM unnest($5::text[], $6::int[], $7::text[]) AS e(entry_id, max_uses, envelope)
           ON CONFLICT (namespace, tenant, entry_id) DO NOTHING`,
          [
            scope.namespace,
            scope.tenant,
            capture.captureId,
            capture.expiresAt,
            entries.map((entry) => entry.entryId),
            entries.map((entry) => entry.maxUses),
            entries.map((entry) => toHex(entry.envelope)),
          ],
        );
        // Any entry identifier already present: nothing is created, nothing overwritten.
        if (rows.rowCount !== entries.length) throw new Rollback(reject("exists"));
        return { outcome: "created" };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) return reject("stale");
      throw thrown;
    }
  }

  async readEntries(input: ReadEntriesInput, options?: StoreCallOptions): Promise<ReadEntriesResult> {
    validateReadEntries(input, this.#capabilities);
    const { scope } = input;
    try {
      // REPEATABLE READ gives the three reads one snapshot (§5.4).
      return await this.#transaction("read", options, async (client, head) => {
        const ns = await this.#namespace(client, head, scope.namespace, "none");
        const rows = await client.query(
          `SELECT e.entry_id, e.capture_id, e.max_uses, e.used, e.lifecycle_revision, e.ciphertext_revision, e.envelope
             FROM ${this.#t.entry} e
            WHERE e.namespace = $1 AND e.tenant = $2 AND e.entry_id = ANY($3::text[])`,
          [scope.namespace, scope.tenant, input.entryIds],
        );
        const entries: StoredEntry[] = rows.rows.map((row) => ({
          entryId: String(row.entry_id),
          captureId: String(row.capture_id),
          maxUses: toNumber(row.max_uses),
          used: toNumber(row.used),
          lifecycleRevision: toNumber(row.lifecycle_revision),
          ciphertextRevision: toNumber(row.ciphertext_revision),
          envelope: toBytes(row.envelope),
        }));
        const captureIds = [...new Set(entries.map((entry) => entry.captureId))];
        const captures = captureIds.length === 0 ? [] : await this.#captures(client, scope.namespace, scope.tenant, captureIds, ns.epoch, "");
        return { recovery: { epoch: ns.epoch, state: ns.state }, entries, captures };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async readCaptures(input: ReadCapturesInput, options?: StoreCallOptions): Promise<readonly StoredCapture[]> {
    validateReadCaptures(input, this.#capabilities);
    const { scope } = input;
    try {
      return await this.#transaction("read", options, async (client, head) => {
        const ns = await this.#namespace(client, head, scope.namespace, "none");
        return this.#captures(client, scope.namespace, scope.tenant, input.captureIds, ns.epoch, "");
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  /** Capture rows in identifier order. A capture created under a lower epoch reads as revoked (§5.1). */
  async #captures(
    client: PgClientLike,
    namespace: string,
    tenant: string,
    captureIds: readonly string[],
    epoch: number,
    lock: "" | " FOR SHARE" | " FOR UPDATE",
  ): Promise<StoredCapture[]> {
    const result = await client.query(
      `SELECT capture_id, state, generation, key_revision, epoch, session_tag, created_at, expires_at, key_ref, wrapped_key
         FROM ${this.#t.capture}
        WHERE namespace = $1 AND tenant = $2 AND capture_id = ANY($3::text[])
        ORDER BY capture_id${lock}`,
      [namespace, tenant, captureIds],
    );
    return result.rows.map((row) => {
      const captureEpoch = toNumber(row.epoch);
      return {
        captureId: String(row.capture_id),
        state: row.state === "live" && captureEpoch === epoch ? "live" : "revoked",
        generation: toNumber(row.generation),
        keyRevision: toNumber(row.key_revision),
        epoch: captureEpoch,
        sessionTag: row.session_tag === null ? null : String(row.session_tag),
        createdAt: toNumber(row.created_at),
        expiresAt: toNumber(row.expires_at),
        keyRef: String(row.key_ref),
        wrappedKey: toBytes(row.wrapped_key),
      };
    });
  }

  async commitRestore(input: CommitRestoreInput, options?: StoreCallOptions): Promise<CommitRestoreResult> {
    validateCommitRestore(input, this.#capabilities);
    const { scope, attempt } = input;
    const reject = (reason: "revoked" | "expired" | "budget" | "stale" | "unknown" | "clock-skew" | "quarantined"): CommitRestoreResult => ({
      outcome: "rejected",
      reason,
    });
    try {
      return await this.#transaction<CommitRestoreResult>("write", options, async (client, head) => {
        // Lock order: recovery record, receipt, captures by identifier, entries by identifier.
        // 1. Shared lock on the recovery record: conflicts with quarantine and invalidation.
        const ns = await this.#namespace(client, head, scope.namespace, "share");
        if (ns.state !== "serving" || ns.epoch !== input.epoch) throw new Rollback(reject("quarantined"));

        // 2. The receipt is claimed first. A concurrent transaction for the
        // same attempt waits here until this one ends, then sees the conflict.
        const claimed = await client.query(
          `INSERT INTO ${this.#t.receipt} (namespace, tenant, attempt_id, request_digest, committed_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (namespace, tenant, attempt_id) DO NOTHING`,
          [scope.namespace, scope.tenant, attempt.attemptId, attempt.requestDigest, head.now, input.receiptExpiresAt],
        );
        if (claimed.rowCount !== 1) {
          const existing = await client.query(
            `SELECT request_digest FROM ${this.#t.receipt} WHERE namespace = $1 AND tenant = $2 AND attempt_id = $3`,
            [scope.namespace, scope.tenant, attempt.attemptId],
          );
          const row = existing.rows[0];
          // Swept between the conflict and the read: nothing known, nothing applied.
          if (row === undefined) throw new Rollback(reject("stale"));
          const same = toHex(toBytes(row.request_digest)) === toHex(attempt.requestDigest);
          throw new Rollback<CommitRestoreResult>({ outcome: same ? "already-committed" : "attempt-mismatch" });
        }

        // 3. Skew.
        if (this.#skewed(head, input.now)) throw new Rollback(reject("clock-skew"));
        if (input.receiptExpiresAt > head.now + LIMITS.maxReceiptHorizonMs) throw new StoreError("STORE_INVALID_ARGUMENT");

        // 4. Captures, share-locked: a revocation of any of them now waits for
        // this transaction, and one that already committed is visible here.
        const captures = await this.#captures(
          client,
          scope.namespace,
          scope.tenant,
          input.captures.map((capture) => capture.captureId),
          ns.epoch,
          " FOR SHARE",
        );
        const byId = new Map(captures.map((capture) => [capture.captureId, capture]));
        let latestExpiry = 0;
        for (const expected of input.captures) {
          const capture = byId.get(expected.captureId);
          if (capture === undefined) throw new Rollback(reject("unknown"));
          if (capture.state !== "live") throw new Rollback(reject("revoked"));
          if (capture.generation !== expected.generation) throw new Rollback(reject("stale"));
          if (head.now >= capture.expiresAt) throw new Rollback(reject("expired"));
          latestExpiry = Math.max(latestExpiry, capture.expiresAt);
        }

        // 5. Entries, locked for update in identifier order.
        const locked = await client.query(
          `SELECT entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision
             FROM ${this.#t.entry}
            WHERE namespace = $1 AND tenant = $2 AND entry_id = ANY($3::text[])
            ORDER BY entry_id FOR UPDATE`,
          [scope.namespace, scope.tenant, input.uses.map((use) => use.entryId)],
        );
        const entries = new Map(locked.rows.map((row) => [String(row.entry_id), row]));
        for (const use of input.uses) {
          const row = entries.get(use.entryId);
          if (row === undefined || row.capture_id !== use.captureId) throw new Rollback(reject("unknown"));
          if (toNumber(row.lifecycle_revision) !== use.lifecycleRevision || toNumber(row.ciphertext_revision) !== use.ciphertextRevision) {
            throw new Rollback(reject("stale"));
          }
          if (toNumber(row.used) + use.count > toNumber(row.max_uses)) throw new Rollback(reject("budget"));
        }

        // 6. A receipt must outlive every capture it covers.
        if (input.receiptExpiresAt < latestExpiry) throw new StoreError("STORE_INVALID_ARGUMENT");

        // 7. Apply every use in one statement.
        const applied = await client.query(
          `UPDATE ${this.#t.entry} e
              SET used = e.used + u.count, lifecycle_revision = e.lifecycle_revision + 1
             FROM unnest($3::text[], $4::int[]) AS u(entry_id, count)
            WHERE e.namespace = $1 AND e.tenant = $2 AND e.entry_id = u.entry_id`,
          [scope.namespace, scope.tenant, input.uses.map((use) => use.entryId), input.uses.map((use) => use.count)],
        );
        if (applied.rowCount !== input.uses.length) throw new StoreError("STORE_UNAVAILABLE");
        return { outcome: "committed" };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) return reject("stale");
      throw thrown;
    }
  }

  async revokeCapture(input: RevokeCaptureInput, options?: StoreCallOptions): Promise<RevokeCaptureResult> {
    validateRevokeCapture(input);
    const { scope, captureId } = input;
    const attempt = (): Promise<RevokeCaptureResult> =>
      this.#transaction<RevokeCaptureResult>("write", options, async (client, head) => {
        // Revocation works in a quarantined namespace; the record is read for its epoch only.
        const ns = await this.#namespace(client, head, scope.namespace, "share");
        const [capture] = await this.#captures(client, scope.namespace, scope.tenant, [captureId], ns.epoch, " FOR UPDATE");
        if (capture === undefined) {
          if (!input.fenceAbsent) return { outcome: "not-found" };
          const fenced = await client.query(
            `INSERT INTO ${this.#t.capture}
               (namespace, tenant, capture_id, state, generation, key_revision, epoch, session_tag,
                created_at, expires_at, key_ref, wrapped_key, has_ciphertext, retain_until)
             VALUES ($1, $2, $3, 'revoked', 1, 1, $4, NULL, $5, $5, '', ''::bytea, false, $6)
             ON CONFLICT (namespace, tenant, capture_id) DO NOTHING`,
            [scope.namespace, scope.tenant, captureId, Math.max(ns.epoch, 1), head.now, head.now + input.retentionMs],
          );
          // A creation won the race: run again and revoke what now exists.
          if (fenced.rowCount !== 1) throw new Contention();
          return { outcome: "fenced" };
        }
        const count = await client.query(
          `SELECT count(*)::int AS entries FROM ${this.#t.entry} WHERE namespace = $1 AND tenant = $2 AND capture_id = $3`,
          [scope.namespace, scope.tenant, captureId],
        );
        const entries = toNumber(count.rows[0]?.entries);
        if (capture.state !== "live") return { outcome: "already-revoked", entries };
        await client.query(
          `UPDATE ${this.#t.capture}
              SET state = 'revoked', generation = generation + 1, retain_until = GREATEST(expires_at, $4::bigint) + $5::bigint
            WHERE namespace = $1 AND tenant = $2 AND capture_id = $3`,
          [scope.namespace, scope.tenant, captureId, head.now, input.retentionMs],
        );
        return { outcome: "revoked", entries };
      });
    try {
      return await attempt();
    } catch (thrown) {
      if (!(thrown instanceof Contention)) throw thrown;
    }
    // One more try after a lock wait or a lost create/fence race. Nothing was applied by the first.
    try {
      return await attempt();
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async inspectAttempt(input: InspectAttemptInput, options?: StoreCallOptions): Promise<InspectAttemptResult> {
    validateInspectAttempt(input);
    const { scope } = input;
    try {
      // Read on the primary (the transaction head refuses a standby): authoritative.
      return await this.#transaction<InspectAttemptResult>("read", options, async (client) => {
        const result = await client.query(
          `SELECT request_digest, committed_at FROM ${this.#t.receipt} WHERE namespace = $1 AND tenant = $2 AND attempt_id = $3`,
          [scope.namespace, scope.tenant, input.attemptId],
        );
        const row = result.rows[0];
        if (row === undefined) return { state: "absent" };
        return { state: "committed", requestDigest: toBytes(row.request_digest), committedAt: toNumber(row.committed_at) };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async replaceCaptureKey(input: ReplaceCaptureKeyInput, options?: StoreCallOptions): Promise<ReplaceCaptureKeyResult> {
    validateReplaceCaptureKey(input);
    const { scope, captureId } = input;
    const reject = (reason: "stale" | "unknown" | "revoked" | "expired"): ReplaceCaptureKeyResult => ({ outcome: "rejected", reason });
    try {
      return await this.#transaction<ReplaceCaptureKeyResult>("write", options, async (client, head) => {
        const ns = await this.#namespace(client, head, scope.namespace, "share");
        const [capture] = await this.#captures(client, scope.namespace, scope.tenant, [captureId], ns.epoch, " FOR UPDATE");
        if (capture === undefined) return reject("unknown");
        if (capture.state !== "live") return reject("revoked");
        if (head.now >= capture.expiresAt) return reject("expired");
        if (capture.keyRevision !== input.keyRevision) return reject("stale");
        // Only the stored key changes: no envelope, counter, state, epoch, or time.
        await client.query(
          `UPDATE ${this.#t.capture} SET key_ref = $4, wrapped_key = $5, key_revision = key_revision + 1
            WHERE namespace = $1 AND tenant = $2 AND capture_id = $3`,
          [scope.namespace, scope.tenant, captureId, input.keyRef, input.wrappedKey],
        );
        return { outcome: "replaced", keyRevision: input.keyRevision + 1 };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) return reject("stale");
      throw thrown;
    }
  }

  async deleteCiphertext(input: DeleteCiphertextInput, options?: StoreCallOptions): Promise<DeleteCiphertextResult> {
    validateDeleteCiphertext(input);
    const { scope, captureId } = input;
    try {
      return await this.#transaction<DeleteCiphertextResult>("write", options, async (client, head) => {
        const ns = await this.#namespace(client, head, scope.namespace, "share");
        const [capture] = await this.#captures(client, scope.namespace, scope.tenant, [captureId], ns.epoch, " FOR UPDATE");
        if (capture === undefined) return { outcome: "rejected", reason: "not-found" };
        if (capture.state === "live") {
          // The decision rests on expiry, so the clocks must agree.
          if (this.#skewed(head, input.now)) return { outcome: "rejected", reason: "clock-skew" };
          if (head.now < capture.expiresAt) return { outcome: "rejected", reason: "live" };
        }
        const removed = await client.query(
          `DELETE FROM ${this.#t.entry} WHERE namespace = $1 AND tenant = $2 AND capture_id = $3`,
          [scope.namespace, scope.tenant, captureId],
        );
        await client.query(
          `UPDATE ${this.#t.capture}
              SET state = 'revoked', key_ref = '', wrapped_key = ''::bytea, has_ciphertext = false,
                  key_revision = key_revision + 1
            WHERE namespace = $1 AND tenant = $2 AND capture_id = $3`,
          [scope.namespace, scope.tenant, captureId],
        );
        return { outcome: "deleted", entries: removed.rowCount ?? 0 };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async sweepExpired(input: SweepInput, options?: StoreCallOptions): Promise<SweepResult> {
    validateSweep(input);
    const { namespace, limit } = input;
    try {
      return await this.#transaction<SweepResult>("write", options, async (client, head) => {
        if (this.#skewed(head, input.now)) return { outcome: "rejected", reason: "clock-skew" };
        // Rows another transaction holds are skipped, never waited for: cleanup yields to restores.
        const entries = await client.query(
          `DELETE FROM ${this.#t.entry} WHERE ctid IN (
             SELECT ctid FROM ${this.#t.entry} WHERE namespace = $1 AND expires_at <= $2 LIMIT $3 FOR UPDATE SKIP LOCKED)`,
          [namespace, head.now, limit],
        );
        const captures = await client.query(
          `DELETE FROM ${this.#t.capture} c WHERE ctid IN (
             SELECT ctid FROM ${this.#t.capture} x
              WHERE x.namespace = $1 AND x.expires_at <= $2
                AND (x.state = 'live' OR x.retain_until < $2)
                AND NOT EXISTS (SELECT 1 FROM ${this.#t.entry} e
                                 WHERE e.namespace = x.namespace AND e.tenant = x.tenant AND e.capture_id = x.capture_id)
              LIMIT $3 FOR UPDATE SKIP LOCKED)`,
          [namespace, head.now, limit],
        );
        const receipts = await client.query(
          `DELETE FROM ${this.#t.receipt} WHERE ctid IN (
             SELECT ctid FROM ${this.#t.receipt} WHERE namespace = $1 AND expires_at < $2 LIMIT $3 FOR UPDATE SKIP LOCKED)`,
          [namespace, head.now, limit],
        );
        const counts = [entries.rowCount ?? 0, captures.rowCount ?? 0, receipts.rowCount ?? 0];
        return {
          outcome: "swept",
          entries: counts[0] as number,
          captures: counts[1] as number,
          receipts: counts[2] as number,
          more: counts.some((count) => count >= limit),
        };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async recoveryState(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> {
    validateNamespace(input);
    try {
      return await this.#transaction("read", options, async (client, head) => {
        const ns = await this.#namespace(client, head, input.namespace, "none");
        return { epoch: ns.epoch, state: ns.state };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async initializeNamespace(
    input: { readonly namespace: string; readonly epoch: number },
    options?: StoreCallOptions,
  ): Promise<InitializeNamespaceResult> {
    validateInitializeNamespace(input);
    try {
      return await this.#transaction<InitializeNamespaceResult>("write", options, async (client, head) => {
        // Serializes initializations of one namespace, so the emptiness check and the insert are one step.
        await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`rsv-namespace:${input.namespace}`]);
        const existing = await client.query(`SELECT 1 FROM ${this.#t.ns} WHERE namespace = $1`, [input.namespace]);
        if (existing.rows.length > 0) return { outcome: "rejected", reason: "exists" };
        const rows = await client.query(
          `SELECT EXISTS (SELECT 1 FROM ${this.#t.capture} WHERE namespace = $1)
               OR EXISTS (SELECT 1 FROM ${this.#t.entry} WHERE namespace = $1)
               OR EXISTS (SELECT 1 FROM ${this.#t.receipt} WHERE namespace = $1) AS occupied`,
          [input.namespace],
        );
        if (rows.rows[0]?.occupied !== false) return { outcome: "rejected", reason: "not-empty" };
        await client.query(
          `INSERT INTO ${this.#t.ns} (namespace, epoch, state, system_identifier, timeline_id) VALUES ($1, $2, 'serving', $3, $4)`,
          [input.namespace, input.epoch, head.systemIdentifier, head.timelineId],
        );
        return { outcome: "initialized" };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async quarantine(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> {
    validateNamespace(input);
    try {
      return await this.#transaction<RecoveryState>("write", options, async (client, head) => {
        // Exclusive: waits for in-flight commits and creates, and blocks new ones until it commits.
        const ns = await this.#namespace(client, head, input.namespace, "update");
        if (ns.state === "uninitialized") return { epoch: 0, state: "uninitialized" };
        await client.query(`UPDATE ${this.#t.ns} SET state = 'quarantined' WHERE namespace = $1`, [input.namespace]);
        return { epoch: ns.epoch, state: "quarantined" };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async invalidateRecovered(input: InvalidateRecoveredInput, options?: StoreCallOptions): Promise<InvalidateRecoveredResult> {
    validateInvalidateRecovered(input);
    try {
      return await this.#transaction<InvalidateRecoveredResult>("write", options, async (client, head) => {
        const ns = await this.#namespace(client, head, input.namespace, "update");
        if (ns.state === "uninitialized") return { outcome: "rejected", reason: "uninitialized" };
        if (input.newEpoch <= ns.epoch) return { outcome: "rejected", reason: "epoch-not-greater" };
        // Every capture stamped with an earlier epoch is revoked from here on; the
        // database's present identity becomes the recorded one.
        await client.query(
          `UPDATE ${this.#t.ns} SET epoch = $2, state = 'serving', system_identifier = $3, timeline_id = $4 WHERE namespace = $1`,
          [input.namespace, input.newEpoch, head.systemIdentifier, head.timelineId],
        );
        return { outcome: "invalidated", recovery: { epoch: input.newEpoch, state: "serving" } };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }

  async acknowledgeIdentityChange(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> {
    validateNamespace(input);
    try {
      return await this.#transaction<RecoveryState>("write", options, async (client, head) => {
        const ns = await this.#namespace(client, head, input.namespace, "update");
        if (ns.state === "uninitialized") return { epoch: 0, state: "uninitialized" };
        await client.query(`UPDATE ${this.#t.ns} SET system_identifier = $2, timeline_id = $3 WHERE namespace = $1`, [
          input.namespace,
          head.systemIdentifier,
          head.timelineId,
        ]);
        const after = await this.#namespace(client, head, input.namespace, "none");
        return { epoch: after.epoch, state: after.state };
      });
    } catch (thrown) {
      if (thrown instanceof Contention) throw new StoreError("STORE_UNAVAILABLE");
      throw thrown;
    }
  }
}
