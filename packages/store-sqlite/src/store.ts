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

import {
  currentConfiguration,
  expectedSynchronous,
  openConnection,
  probeMarkerDirectory,
  readMarker,
  sqliteVersionAcceptable,
  writeMarker,
} from "./deployment.js";
import type { Database, JournalMode, Marker, Statement } from "./deployment.js";
import { migrationStatements, SCHEMA_VERSION } from "./schema.js";

export interface SqliteStoreOptions {
  /**
   * The database file, on a local file system of this host. It must exist and
   * have been migrated (`migrate`). In-memory, temporary, and URI names are
   * refused. Every process of the namespace must name the same file.
   */
  readonly filename: string;
  /**
   * `wal` (default): `journal_mode=WAL` with `synchronous=FULL`. `delete`:
   * `journal_mode=DELETE` with `synchronous=EXTRA`. Both are verified by
   * reading the values back; the store refuses to start on any other.
   */
  readonly journalMode?: JournalMode;
  /**
   * How long one statement waits for another connection's write lock before
   * it fails with `SQLITE_BUSY`, which this store reports as
   * `STORE_UNAVAILABLE`. Finite, 1 to 60000. Default 5000. The driver is
   * synchronous: while it waits, this process's event loop waits too. Keep it
   * below the server's `storeTimeoutMs` (default 10000).
   */
  readonly busyTimeoutMs?: number;
  /** Largest accepted difference between the host clock and a caller's `now`. Default 2000. */
  readonly maxClockSkewMs?: number;
  /**
   * The restore tripwire's marker file. A path, or `false` to keep only the
   * process-local high-water mark. Default: the database path plus
   * `.rsv-marker`, which sits beside the database and so inside most backup
   * sets; place it elsewhere (on another volume, outside what is backed up)
   * to give it value. See docs/reference/store-sqlite.md.
   */
  readonly restoreMarker?: string | false;
  readonly maxCreateEntries?: number;
  readonly maxCreateBytes?: number;
  readonly maxRestoreEntries?: number;
  readonly maxRestoreCaptures?: number;
  readonly maxEnvelopeBytes?: number;
}

export interface SqliteStore extends Store {
  /** Closes this adapter's connection. A closed store throws `STORE_CLOSED`. */
  close(): void;
}

export interface MigrateOptions {
  readonly filename: string;
  readonly journalMode?: JournalMode;
  readonly busyTimeoutMs?: number;
  readonly restoreMarker?: string | false;
}

export interface DeploymentReport {
  readonly ok: boolean;
  readonly sqliteVersion: string;
  /** Fixed names of the checks that failed: `sqlite-version`, `journal-mode`, `synchronous`, `busy-timeout`, `foreign-keys`, `locking-mode`, `fullfsync`, `schema`, `pragma`. */
  readonly failures: readonly string[];
}

/**
 * Seams for this package's own tests. Not exported from the package: the
 * published entry point reads the host clock through SQLite and has no hooks.
 */
export interface SqliteInternals {
  /** A SQL expression yielding the store clock in milliseconds. */
  readonly nowSql?: string;
  /** Called inside every write transaction after its last statement, before `COMMIT`. */
  readonly beforeCommit?: () => void;
  /** Called after `COMMIT` returned, before the result is handed back. */
  readonly afterCommit?: () => void;
  readonly wrapConnection?: (db: Database) => Database;
  /** Replaces the version the connection reports, to exercise the refusal of an old SQLite. */
  readonly sqliteVersion?: string;
}

const DEFAULT_NOW = "CAST(ROUND(unixepoch('subsec') * 1000) AS INTEGER)";
const DEFAULT_BUSY_TIMEOUT_MS = 5000;
const DEFAULT_MAX_CREATE_BYTES = 16 * 1024 * 1024;
const MAX_CREATE_BYTES_CEILING = 256 * 1024 * 1024;

/** Thrown inside a transaction body to roll back and return a result. */
class Rollback<T> {
  readonly value: T;
  constructor(value: T) {
    this.value = value;
  }
}

interface Head {
  readonly now: number;
  readonly counter: number;
  readonly databaseId: string;
  /** The database is older than something this process or the marker file has seen. */
  readonly rolledBack: boolean;
}

interface NamespaceRow {
  readonly epoch: number;
  readonly state: "serving" | "quarantined" | "uninitialized";
}

/**
 * The highest `counter` of each database file this process has seen, keyed by
 * canonical path. It lives as long as the process, so a store opened again on
 * a file that was replaced by an older copy still notices.
 */
const HIGH_WATER = new Map<string, Marker>();

function toNumber(value: unknown): number {
  const n = typeof value === "bigint" ? Number(value) : value;
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
  const resolved = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > ceiling) throw new StoreError("STORE_INVALID_ARGUMENT");
  return resolved;
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => "?").join(", ");
}

function resolveMarker(path: string, option: string | false | undefined): string | null {
  if (option === false) return null;
  if (option === undefined) return `${path}.rsv-marker`;
  if (typeof option !== "string" || option === "" || option.includes("\0")) throw new StoreError("STORE_INVALID_ARGUMENT");
  return option;
}

function journalOption(value: JournalMode | undefined): JournalMode {
  const mode = value === undefined ? "wal" : value;
  if (mode !== "wal" && mode !== "delete") throw new StoreError("STORE_INVALID_ARGUMENT");
  return mode;
}

function busyOption(value: number | undefined): number {
  return boundedOption(value, DEFAULT_BUSY_TIMEOUT_MS, 60_000);
}

/**
 * Creates the tables of schema version 1 in a database file, creating the
 * file if it does not exist, and sets its journal mode. Idempotent. Run once
 * before any store is opened. A newly created database also resets the
 * restore tripwire for its path.
 */
export async function migrate(options: MigrateOptions): Promise<void> {
  if (typeof options !== "object" || options === null) throw new StoreError("STORE_INVALID_ARGUMENT");
  const journalMode = journalOption(options.journalMode);
  const busyTimeoutMs = busyOption(options.busyTimeoutMs);
  const opened = await openConnection({ filename: options.filename, journalMode, busyTimeoutMs }, false);
  const { db, path } = opened;
  const markerPath = resolveMarker(path, options.restoreMarker);
  try {
    if (opened.failures.length > 0) throw new StoreError("STORE_CAPABILITY");
    const databaseId = globalThis.crypto.randomUUID();
    db.exec("BEGIN IMMEDIATE");
    let created = false;
    try {
      for (const statement of migrationStatements(databaseId)) {
        const result = db.prepare(statement).run();
        if (statement.startsWith("INSERT OR IGNORE INTO rsv_meta") && Number(result.changes) === 1) created = true;
      }
      const meta = db.prepare("SELECT version, database_id FROM rsv_meta WHERE singleton = 1").get();
      if (meta === undefined || toNumber(meta.version) !== SCHEMA_VERSION) throw new StoreError("STORE_CAPABILITY");
      db.exec("COMMIT");
      if (created) {
        // A new database starts a new history: forget what an earlier file at this path had reached.
        HIGH_WATER.set(path, { databaseId: String(meta.database_id), counter: 0 });
        if (markerPath !== null) writeMarker(markerPath, { databaseId: String(meta.database_id), counter: 0 });
      }
    } catch (thrown) {
      try {
        if (db.inTransaction) db.exec("ROLLBACK");
      } catch {
        // The connection is closed below.
      }
      throw thrown;
    }
  } catch (thrown) {
    if (thrown instanceof StoreError) throw thrown;
    throw new StoreError("STORE_UNAVAILABLE");
  } finally {
    try {
      db.close();
    } catch {
      // Nothing to add to the error already chosen.
    }
  }
}

/**
 * Opens a connection, applies the profile's pragmas, and reports which checks
 * failed, without keeping the connection. For a startup probe or a health
 * check; `createSqliteStore` runs the same checks and refuses on any failure.
 */
export async function checkDeployment(options: SqliteStoreOptions): Promise<DeploymentReport> {
  const opened = await openConnection(
    { filename: options.filename, journalMode: journalOption(options.journalMode), busyTimeoutMs: busyOption(options.busyTimeoutMs) },
    true,
  );
  try {
    const failures = [...opened.failures];
    if (failures.length === 0 && !schemaMatches(opened.db)) failures.push("schema");
    return { ok: failures.length === 0, sqliteVersion: opened.sqliteVersion, failures };
  } finally {
    try {
      opened.db.close();
    } catch {
      // Nothing to report.
    }
  }
}

function schemaMatches(db: Database): boolean {
  try {
    const row = db.prepare("SELECT version FROM rsv_meta WHERE singleton = 1").get();
    return row !== undefined && toNumber(row.version) === SCHEMA_VERSION;
  } catch {
    return false;
  }
}

/**
 * Opens the store after verifying the deployment it is pointed at: SQLite
 * 3.51.3 or later (or a release carrying the backported fix), `journal_mode`
 * and `synchronous` of the profile, a finite `busy_timeout`, the schema
 * version, and, when a marker file is in use, that it can be written. It
 * refuses to start otherwise.
 */
export async function createSqliteStore(options: SqliteStoreOptions): Promise<SqliteStore> {
  return openSqliteStore(options, {});
}

/**
 * `createSqliteStore` with test seams. Not exported from the package: this
 * package's own tests import it from the build output.
 */
export async function openSqliteStore(options: SqliteStoreOptions, internals: SqliteInternals): Promise<SqliteStore> {
  if (typeof options !== "object" || options === null) throw new StoreError("STORE_INVALID_ARGUMENT");
  const journalMode = journalOption(options.journalMode);
  const busyTimeoutMs = busyOption(options.busyTimeoutMs);
  const maxClockSkewMs = options.maxClockSkewMs ?? 2000;
  if (!Number.isSafeInteger(maxClockSkewMs) || maxClockSkewMs < 0 || maxClockSkewMs > 60_000) throw new StoreError("STORE_INVALID_ARGUMENT");
  const capabilities: StoreCapabilities = Object.freeze({
    contractVersion: 1,
    adapter: "store-sqlite",
    profile: journalMode === "wal" ? "sqlite-local-wal/synchronous=FULL" : "sqlite-local-delete/synchronous=EXTRA",
    atomicCreate: true,
    maxCreateEntries: boundedOption(options.maxCreateEntries, LIMITS.maxCreateEntries, LIMITS.maxCreateEntries),
    maxCreateBytes: boundedOption(options.maxCreateBytes, DEFAULT_MAX_CREATE_BYTES, MAX_CREATE_BYTES_CEILING),
    atomicRestore: true,
    maxRestoreEntries: boundedOption(options.maxRestoreEntries, LIMITS.maxRestoreEntries, LIMITS.maxRestoreEntries),
    maxRestoreCaptures: boundedOption(options.maxRestoreCaptures, LIMITS.maxRestoreCaptures, LIMITS.maxRestoreCaptures),
    authoritativeCommit: true,
    revocationFences: true,
    attemptReceipts: true,
    storeClock: true,
    maxClockSkewMs,
    durability: "durable",
    // Processes of this host, and no other.
    crossProcess: true,
    restoreDetection: options.restoreMarker === false ? "sqlite-process-high-water-mark" : "sqlite-counter-high-water-mark-and-marker-file",
    maxEnvelopeBytes: boundedOption(options.maxEnvelopeBytes, LIMITS.maxEnvelopeBytes, LIMITS.maxEnvelopeBytes),
  });

  const opened = await openConnection({ filename: options.filename, journalMode, busyTimeoutMs }, true);
  const markerPath = resolveMarker(opened.path, options.restoreMarker);
  try {
    if (opened.failures.length > 0 || !schemaMatches(opened.db)) throw new StoreError("STORE_CAPABILITY");
    if (internals.sqliteVersion !== undefined && !sqliteVersionAcceptable(internals.sqliteVersion)) throw new StoreError("STORE_CAPABILITY");
    if (markerPath !== null) {
      // A marker that cannot be written is a tripwire that is not there: refuse instead of declaring it.
      const existing = readMarker(markerPath);
      const meta = opened.db.prepare("SELECT database_id, counter FROM rsv_meta WHERE singleton = 1").get();
      if (meta === undefined) throw new StoreError("STORE_CAPABILITY");
      probeMarkerDirectory(markerPath);
      if (existing === null) writeMarker(markerPath, { databaseId: String(meta.database_id), counter: toNumber(meta.counter) });
    }
  } catch (thrown) {
    try {
      opened.db.close();
    } catch {
      // Nothing to add.
    }
    if (thrown instanceof StoreError) throw thrown;
    throw new StoreError("STORE_CAPABILITY");
  }
  const db = internals.wrapConnection === undefined ? opened.db : internals.wrapConnection(opened.db);
  return new SqliteStoreImpl(db, opened.path, markerPath, journalMode, capabilities, internals);
}

class SqliteStoreImpl implements SqliteStore {
  readonly #db: Database;
  readonly #path: string;
  readonly #markerPath: string | null;
  readonly #journalMode: JournalMode;
  readonly #capabilities: StoreCapabilities;
  readonly #nowSql: string;
  readonly #internals: SqliteInternals;
  readonly #pid: number;
  readonly #statements = new Map<string, Statement>();
  #closed = false;

  constructor(db: Database, path: string, markerPath: string | null, journalMode: JournalMode, capabilities: StoreCapabilities, internals: SqliteInternals) {
    this.#db = db;
    this.#path = path;
    this.#markerPath = markerPath;
    this.#journalMode = journalMode;
    this.#capabilities = capabilities;
    this.#internals = internals;
    this.#nowSql = internals.nowSql ?? DEFAULT_NOW;
    // A connection must not be used by a process other than the one that opened it (fork).
    this.#pid = process.pid;
  }

  capabilities(): StoreCapabilities {
    return this.#capabilities;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#statements.clear();
    try {
      this.#db.close();
    } catch {
      // Closing is best effort; the adapter is closed either way.
    }
  }

  // ------------------------------------------------------------ transactions

  #q(sql: string): Statement {
    let statement = this.#statements.get(sql);
    if (statement === undefined) {
      statement = this.#db.prepare(sql);
      this.#statements.set(sql, statement);
    }
    return statement;
  }

  #clock(): number {
    return toNumber(this.#q(`SELECT ${this.#nowSql} AS now`).get()?.now);
  }

  #skewed(head: Head, now: number): boolean {
    return Math.abs(head.now - now) > this.#capabilities.maxClockSkewMs;
  }

  /**
   * One transaction, synchronously, on this adapter's one connection.
   *
   * - Every write is `BEGIN IMMEDIATE`: the writer role is taken before
   *   anything is read, so the checks and the writes see one state and no
   *   other connection can commit between them (specification §5.2). It is
   *   never `BEGIN DEFERRED`: the read-to-write upgrade can fail after reads
   *   the transaction already depended on.
   * - A failure before `COMMIT` is sent leaves nothing applied: the
   *   transaction is rolled back, and the outcome is `STORE_UNAVAILABLE`.
   *   That includes `SQLITE_BUSY` from `BEGIN IMMEDIATE` after the busy
   *   timeout.
   * - A failure of `COMMIT`: when the transaction is still open and a
   *   `ROLLBACK` succeeds, nothing was applied (`STORE_UNAVAILABLE`);
   *   otherwise the outcome is unknown and, for a write, is
   *   `STORE_AMBIGUOUS`. This adapter never retries it.
   * - No driver error, message, or path leaves this function.
   */
  #transaction<T>(mode: "write" | "read", options: StoreCallOptions | undefined, body: (head: Head) => T): T {
    if (this.#closed) throw new StoreError("STORE_CLOSED");
    if (process.pid !== this.#pid) throw new StoreError("STORE_UNAVAILABLE");
    if (options?.signal?.aborted === true) throw new StoreError("STORE_UNAVAILABLE");
    const db = this.#db;
    let value: T;
    let head: Head;
    try {
      db.exec(mode === "write" ? "BEGIN IMMEDIATE" : "BEGIN");
    } catch {
      this.#abandon();
      throw new StoreError("STORE_UNAVAILABLE");
    }
    try {
      const configuration = currentConfiguration(db);
      // Another process can change the journal mode of the file; a connection that no longer runs the profile stops.
      if (configuration.journalMode !== this.#journalMode || configuration.synchronous !== expectedSynchronous(this.#journalMode)) {
        throw new StoreError("STORE_UNAVAILABLE");
      }
      const meta = this.#q("SELECT database_id, counter FROM rsv_meta WHERE singleton = 1").get();
      if (meta === undefined) throw new StoreError("STORE_UNAVAILABLE");
      head = this.#head(String(meta.database_id), toNumber(meta.counter));
      if (mode === "write") this.#q("UPDATE rsv_meta SET counter = counter + 1 WHERE singleton = 1").run();
      value = body(head);
      this.#internals.beforeCommit?.();
    } catch (thrown) {
      this.#abandon();
      if (thrown instanceof Rollback) return thrown.value as T;
      if (thrown instanceof StoreError) throw thrown;
      throw new StoreError("STORE_UNAVAILABLE");
    }
    try {
      db.exec("COMMIT");
    } catch {
      // Still open: a successful rollback proves nothing was applied.
      let rolledBack = false;
      try {
        if (db.inTransaction) {
          db.exec("ROLLBACK");
          rolledBack = true;
        }
      } catch {
        rolledBack = false;
      }
      // A transaction that could be neither committed nor rolled back would hold the write lock against every
      // other process: closing the connection ends it. The adapter is then closed; the application opens another.
      if (this.#db.inTransaction) this.close();
      throw new StoreError(mode === "write" && !rolledBack ? "STORE_AMBIGUOUS" : "STORE_UNAVAILABLE");
    }
    if (mode === "write") this.#committed(head);
    this.#internals.afterCommit?.();
    return value;
  }

  /** Rolls back whatever is open. A connection that cannot be rolled back is closed: nothing was committed. */
  #abandon(): void {
    try {
      if (this.#db.inTransaction) this.#db.exec("ROLLBACK");
    } catch {
      this.close();
    }
  }

  /**
   * The restore tripwire (docs/reference/store-sqlite.md). `counter` grows by
   * one in every write transaction, so a database file that holds a lower
   * value than this process or the marker file has already seen is an older
   * copy. A different `database_id` is a different file at the same path.
   */
  #head(databaseId: string, counter: number): Head {
    let rolledBack = false;
    const seen = HIGH_WATER.get(this.#path);
    if (seen !== undefined && (seen.databaseId !== databaseId || counter < seen.counter)) rolledBack = true;
    if (this.#markerPath !== null) {
      const marker = readMarker(this.#markerPath);
      if (marker === "invalid") rolledBack = true;
      else if (marker !== null && (marker.databaseId !== databaseId || counter < marker.counter)) rolledBack = true;
    }
    if (!rolledBack && (seen === undefined || counter > seen.counter)) HIGH_WATER.set(this.#path, { databaseId, counter });
    return { now: this.#clock(), counter, databaseId, rolledBack };
  }

  /** After a write transaction committed: advance the high-water mark and the marker file, never lower either. */
  #committed(head: Head): void {
    const next = head.counter + 1;
    const seen = HIGH_WATER.get(this.#path);
    if (!head.rolledBack && (seen === undefined || seen.databaseId !== head.databaseId || next > seen.counter)) {
      HIGH_WATER.set(this.#path, { databaseId: head.databaseId, counter: next });
    }
    if (this.#markerPath !== null && !head.rolledBack) this.#advanceMarker({ databaseId: head.databaseId, counter: next }, false);
  }

  /**
   * The marker is advisory and written after the commit, so a crash between
   * the two leaves it behind the database, which is safe. A write failure
   * cannot be reported as a failure of the commit it follows.
   */
  #advanceMarker(next: Marker, force: boolean): void {
    if (this.#markerPath === null) return;
    try {
      const current = readMarker(this.#markerPath);
      if (force || current === null || (current !== "invalid" && current.databaseId === next.databaseId && next.counter > current.counter)) {
        writeMarker(this.#markerPath, next);
      }
    } catch {
      // The next commit tries again.
    }
  }

  /**
   * The namespace recovery record. A database that the tripwire reads as
   * older than something already seen is quarantined whatever the stored
   * state says.
   */
  #namespace(head: Head, namespace: string): NamespaceRow {
    const row = this.#q("SELECT epoch, state FROM rsv_namespace WHERE namespace = ?").get(namespace);
    if (row === undefined) return { epoch: 0, state: "uninitialized" };
    return { epoch: toNumber(row.epoch), state: !head.rolledBack && row.state === "serving" ? "serving" : "quarantined" };
  }

  /** Capture rows in identifier order. A capture created under a lower epoch reads as revoked (§5.1). */
  #captures(namespace: string, tenant: string, captureIds: readonly string[], epoch: number): StoredCapture[] {
    const rows = this.#q(
      `SELECT capture_id, state, generation, key_revision, epoch, session_tag, created_at, expires_at, key_ref, wrapped_key
         FROM rsv_capture
        WHERE namespace = ? AND tenant = ? AND capture_id IN (${placeholders(captureIds.length)})
        ORDER BY capture_id`,
    ).all(namespace, tenant, ...captureIds);
    return rows.map((row) => {
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

  // -------------------------------------------------------------- operations

  async createCapture(input: CreateCaptureInput, options?: StoreCallOptions): Promise<CreateCaptureResult> {
    validateCreateCapture(input, this.#capabilities);
    const { scope, capture, entries } = input;
    const reject = (reason: "exists" | "fenced" | "clock-skew" | "quarantined" | "stale"): CreateCaptureResult => ({ outcome: "rejected", reason });
    return this.#transaction<CreateCaptureResult>("write", options, (head) => {
      const ns = this.#namespace(head, scope.namespace);
      if (ns.state !== "serving" || ns.epoch !== input.epoch) throw new Rollback(reject("quarantined"));
      if (this.#skewed(head, input.now) || this.#skewed(head, capture.createdAt)) throw new Rollback(reject("clock-skew"));
      const [existing] = this.#captures(scope.namespace, scope.tenant, [capture.captureId], ns.epoch);
      // Revoked, fenced, or created under an earlier epoch: the identifier is fenced.
      if (existing !== undefined) throw new Rollback(reject(existing.state !== "live" ? "fenced" : "exists"));
      this.#q(
        `INSERT INTO rsv_capture
           (namespace, tenant, capture_id, state, generation, key_revision, epoch, session_tag,
            created_at, expires_at, key_ref, wrapped_key, has_ciphertext, retain_until)
         VALUES (?, ?, ?, 'live', 1, 1, ?, ?, ?, ?, ?, ?, 1, ?)`,
      ).run(scope.namespace, scope.tenant, capture.captureId, input.epoch, capture.sessionTag, capture.createdAt, capture.expiresAt, capture.keyRef, capture.wrappedKey, capture.expiresAt);
      const insert = this.#q(
        `INSERT INTO rsv_entry
           (namespace, tenant, entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision, envelope, expires_at)
         VALUES (?, ?, ?, ?, ?, 0, 1, 1, ?, ?)
         ON CONFLICT (namespace, tenant, entry_id) DO NOTHING`,
      );
      for (const entry of entries) {
        // Any entry identifier already present: nothing is created, nothing overwritten.
        if (Number(insert.run(scope.namespace, scope.tenant, entry.entryId, capture.captureId, entry.maxUses, entry.envelope, capture.expiresAt).changes) !== 1) {
          throw new Rollback(reject("exists"));
        }
      }
      return { outcome: "created" };
    });
  }

  async readEntries(input: ReadEntriesInput, options?: StoreCallOptions): Promise<ReadEntriesResult> {
    validateReadEntries(input, this.#capabilities);
    const { scope } = input;
    // One explicit read transaction: under WAL one snapshot, under a rollback journal a shared lock held throughout (§5.4).
    return this.#transaction("read", options, (head) => {
      const ns = this.#namespace(head, scope.namespace);
      const rows = this.#q(
        `SELECT entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision, envelope
           FROM rsv_entry
          WHERE namespace = ? AND tenant = ? AND entry_id IN (${placeholders(input.entryIds.length)})`,
      ).all(scope.namespace, scope.tenant, ...input.entryIds);
      const entries: StoredEntry[] = rows.map((row) => ({
        entryId: String(row.entry_id),
        captureId: String(row.capture_id),
        maxUses: toNumber(row.max_uses),
        used: toNumber(row.used),
        lifecycleRevision: toNumber(row.lifecycle_revision),
        ciphertextRevision: toNumber(row.ciphertext_revision),
        envelope: toBytes(row.envelope),
      }));
      const captureIds = [...new Set(entries.map((entry) => entry.captureId))];
      const captures = captureIds.length === 0 ? [] : this.#captures(scope.namespace, scope.tenant, captureIds, ns.epoch);
      return { recovery: { epoch: ns.epoch, state: ns.state }, entries, captures };
    });
  }

  async readCaptures(input: ReadCapturesInput, options?: StoreCallOptions): Promise<readonly StoredCapture[]> {
    validateReadCaptures(input, this.#capabilities);
    const { scope } = input;
    return this.#transaction("read", options, (head) => {
      const ns = this.#namespace(head, scope.namespace);
      return this.#captures(scope.namespace, scope.tenant, input.captureIds, ns.epoch);
    });
  }

  async commitRestore(input: CommitRestoreInput, options?: StoreCallOptions): Promise<CommitRestoreResult> {
    validateCommitRestore(input, this.#capabilities);
    const { scope, attempt } = input;
    const reject = (reason: "revoked" | "expired" | "budget" | "stale" | "unknown" | "clock-skew" | "quarantined"): CommitRestoreResult => ({
      outcome: "rejected",
      reason,
    });
    // BEGIN IMMEDIATE has made this the only writer: the recovery record, the receipt, the captures, and the entries
    // are read and written with no other connection able to commit in between.
    return this.#transaction<CommitRestoreResult>("write", options, (head) => {
      // 1. The recovery record.
      const ns = this.#namespace(head, scope.namespace);
      if (ns.state !== "serving" || ns.epoch !== input.epoch) throw new Rollback(reject("quarantined"));

      // 2. The receipt of this attempt.
      const receipt = this.#q("SELECT request_digest FROM rsv_receipt WHERE namespace = ? AND tenant = ? AND attempt_id = ?").get(
        scope.namespace,
        scope.tenant,
        attempt.attemptId,
      );
      if (receipt !== undefined) {
        const same = toHex(toBytes(receipt.request_digest)) === toHex(attempt.requestDigest);
        throw new Rollback<CommitRestoreResult>({ outcome: same ? "already-committed" : "attempt-mismatch" });
      }

      // 3. Skew.
      if (this.#skewed(head, input.now)) throw new Rollback(reject("clock-skew"));
      if (input.receiptExpiresAt > head.now + LIMITS.maxReceiptHorizonMs) throw new StoreError("STORE_INVALID_ARGUMENT");

      // 4. Captures.
      const captures = this.#captures(
        scope.namespace,
        scope.tenant,
        input.captures.map((capture) => capture.captureId),
        ns.epoch,
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

      // 5. Entries.
      const rows = this.#q(
        `SELECT entry_id, capture_id, max_uses, used, lifecycle_revision, ciphertext_revision
           FROM rsv_entry
          WHERE namespace = ? AND tenant = ? AND entry_id IN (${placeholders(input.uses.length)})`,
      ).all(scope.namespace, scope.tenant, ...input.uses.map((use) => use.entryId));
      const entries = new Map(rows.map((row) => [String(row.entry_id), row]));
      for (const use of input.uses) {
        const row = entries.get(use.entryId);
        if (row === undefined || row.capture_id !== use.captureId) throw new Rollback(reject("unknown"));
        if (toNumber(row.lifecycle_revision) !== use.lifecycleRevision || toNumber(row.ciphertext_revision) !== use.ciphertextRevision) {
          throw new Rollback(reject("stale"));
        }
        if (toNumber(row.used) + use.count > toNumber(row.max_uses)) throw new Rollback(reject("budget"));
      }

      // Expiry is judged again at the last moment before the writes.
      const lockedAt = this.#clock();
      for (const capture of captures) {
        if (lockedAt >= capture.expiresAt) throw new Rollback(reject("expired"));
      }

      // 6. A receipt must outlive every capture it covers.
      if (input.receiptExpiresAt < latestExpiry) throw new StoreError("STORE_INVALID_ARGUMENT");

      // 7. Apply every use, then the receipt.
      const apply = this.#q(
        `UPDATE rsv_entry SET used = used + ?, lifecycle_revision = lifecycle_revision + 1
          WHERE namespace = ? AND tenant = ? AND entry_id = ?`,
      );
      for (const use of input.uses) {
        if (Number(apply.run(use.count, scope.namespace, scope.tenant, use.entryId).changes) !== 1) throw new StoreError("STORE_UNAVAILABLE");
      }
      this.#q("INSERT INTO rsv_receipt (namespace, tenant, attempt_id, request_digest, committed_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)").run(
        scope.namespace,
        scope.tenant,
        attempt.attemptId,
        attempt.requestDigest,
        head.now,
        input.receiptExpiresAt,
      );
      return { outcome: "committed" };
    });
  }

  async revokeCapture(input: RevokeCaptureInput, options?: StoreCallOptions): Promise<RevokeCaptureResult> {
    validateRevokeCapture(input);
    const { scope, captureId } = input;
    return this.#transaction<RevokeCaptureResult>("write", options, (head) => {
      // Revocation works in a quarantined namespace; the record is read for its epoch only.
      const ns = this.#namespace(head, scope.namespace);
      const [capture] = this.#captures(scope.namespace, scope.tenant, [captureId], ns.epoch);
      if (capture === undefined) {
        if (!input.fenceAbsent) return { outcome: "not-found" };
        this.#q(
          `INSERT INTO rsv_capture
             (namespace, tenant, capture_id, state, generation, key_revision, epoch, session_tag,
              created_at, expires_at, key_ref, wrapped_key, has_ciphertext, retain_until)
           VALUES (?, ?, ?, 'revoked', 1, 1, ?, NULL, ?, ?, '', x'', 0, ?)`,
        ).run(scope.namespace, scope.tenant, captureId, Math.max(ns.epoch, 1), head.now, head.now, head.now + input.retentionMs);
        return { outcome: "fenced" };
      }
      const entries = toNumber(
        this.#q("SELECT count(*) AS entries FROM rsv_entry WHERE namespace = ? AND tenant = ? AND capture_id = ?").get(scope.namespace, scope.tenant, captureId)?.entries,
      );
      if (capture.state !== "live") return { outcome: "already-revoked", entries };
      this.#q(
        `UPDATE rsv_capture SET state = 'revoked', generation = generation + 1, retain_until = ?
          WHERE namespace = ? AND tenant = ? AND capture_id = ?`,
      ).run(Math.max(capture.expiresAt, head.now) + input.retentionMs, scope.namespace, scope.tenant, captureId);
      return { outcome: "revoked", entries };
    });
  }

  async inspectAttempt(input: InspectAttemptInput, options?: StoreCallOptions): Promise<InspectAttemptResult> {
    validateInspectAttempt(input);
    const { scope } = input;
    // The one writer's commits are visible to a read that begins after them: authoritative on this host.
    return this.#transaction<InspectAttemptResult>("read", options, () => {
      const row = this.#q("SELECT request_digest, committed_at FROM rsv_receipt WHERE namespace = ? AND tenant = ? AND attempt_id = ?").get(
        scope.namespace,
        scope.tenant,
        input.attemptId,
      );
      if (row === undefined) return { state: "absent" };
      return { state: "committed", requestDigest: toBytes(row.request_digest), committedAt: toNumber(row.committed_at) };
    });
  }

  async replaceCaptureKey(input: ReplaceCaptureKeyInput, options?: StoreCallOptions): Promise<ReplaceCaptureKeyResult> {
    validateReplaceCaptureKey(input);
    const { scope, captureId } = input;
    const reject = (reason: "stale" | "unknown" | "revoked" | "expired"): ReplaceCaptureKeyResult => ({ outcome: "rejected", reason });
    return this.#transaction<ReplaceCaptureKeyResult>("write", options, (head) => {
      const ns = this.#namespace(head, scope.namespace);
      const [capture] = this.#captures(scope.namespace, scope.tenant, [captureId], ns.epoch);
      if (capture === undefined) return reject("unknown");
      if (capture.state !== "live") return reject("revoked");
      if (this.#clock() >= capture.expiresAt) return reject("expired");
      if (capture.keyRevision !== input.keyRevision) return reject("stale");
      // Only the stored key changes: no envelope, counter, state, epoch, or time.
      this.#q(
        `UPDATE rsv_capture SET key_ref = ?, wrapped_key = ?, key_revision = key_revision + 1
          WHERE namespace = ? AND tenant = ? AND capture_id = ?`,
      ).run(input.keyRef, input.wrappedKey, scope.namespace, scope.tenant, captureId);
      return { outcome: "replaced", keyRevision: input.keyRevision + 1 };
    });
  }

  async deleteCiphertext(input: DeleteCiphertextInput, options?: StoreCallOptions): Promise<DeleteCiphertextResult> {
    validateDeleteCiphertext(input);
    const { scope, captureId } = input;
    return this.#transaction<DeleteCiphertextResult>("write", options, (head) => {
      const ns = this.#namespace(head, scope.namespace);
      const [capture] = this.#captures(scope.namespace, scope.tenant, [captureId], ns.epoch);
      if (capture === undefined) return { outcome: "rejected", reason: "not-found" };
      if (capture.state === "live") {
        // The decision rests on expiry, so the clocks must agree.
        if (this.#skewed(head, input.now)) return { outcome: "rejected", reason: "clock-skew" };
        if (head.now < capture.expiresAt) return { outcome: "rejected", reason: "live" };
      }
      const removed = this.#q("DELETE FROM rsv_entry WHERE namespace = ? AND tenant = ? AND capture_id = ?").run(scope.namespace, scope.tenant, captureId);
      this.#q(
        `UPDATE rsv_capture
            SET state = 'revoked', key_ref = '', wrapped_key = x'', has_ciphertext = 0, key_revision = key_revision + 1
          WHERE namespace = ? AND tenant = ? AND capture_id = ?`,
      ).run(scope.namespace, scope.tenant, captureId);
      return { outcome: "deleted", entries: Number(removed.changes) };
    });
  }

  async sweepExpired(input: SweepInput, options?: StoreCallOptions): Promise<SweepResult> {
    validateSweep(input);
    const { namespace, limit } = input;
    return this.#transaction<SweepResult>("write", options, (head) => {
      if (this.#skewed(head, input.now)) return { outcome: "rejected", reason: "clock-skew" };
      const entries = Number(
        this.#q(
          `DELETE FROM rsv_entry WHERE rowid IN (SELECT rowid FROM rsv_entry WHERE namespace = ? AND expires_at <= ? LIMIT ?)`,
        ).run(namespace, head.now, limit).changes,
      );
      const captures = Number(
        this.#q(
          `DELETE FROM rsv_capture WHERE rowid IN (
             SELECT x.rowid FROM rsv_capture x
              WHERE x.namespace = ? AND x.expires_at <= ?
                AND (x.state = 'live' OR x.retain_until < ?)
                AND NOT EXISTS (SELECT 1 FROM rsv_entry e
                                 WHERE e.namespace = x.namespace AND e.tenant = x.tenant AND e.capture_id = x.capture_id)
              LIMIT ?)`,
        ).run(namespace, head.now, head.now, limit).changes,
      );
      const receipts = Number(
        this.#q(`DELETE FROM rsv_receipt WHERE rowid IN (SELECT rowid FROM rsv_receipt WHERE namespace = ? AND expires_at < ? LIMIT ?)`).run(
          namespace,
          head.now,
          limit,
        ).changes,
      );
      return { outcome: "swept", entries, captures, receipts, more: [entries, captures, receipts].some((count) => count >= limit) };
    });
  }

  async recoveryState(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> {
    validateNamespace(input);
    return this.#transaction("read", options, (head) => {
      const ns = this.#namespace(head, input.namespace);
      return { epoch: ns.epoch, state: ns.state };
    });
  }

  async initializeNamespace(
    input: { readonly namespace: string; readonly epoch: number },
    options?: StoreCallOptions,
  ): Promise<InitializeNamespaceResult> {
    validateInitializeNamespace(input);
    return this.#transaction<InitializeNamespaceResult>("write", options, () => {
      if (this.#q("SELECT 1 AS one FROM rsv_namespace WHERE namespace = ?").get(input.namespace) !== undefined) {
        return { outcome: "rejected", reason: "exists" };
      }
      const occupied = this.#q(
        `SELECT EXISTS (SELECT 1 FROM rsv_capture WHERE namespace = ?)
             OR EXISTS (SELECT 1 FROM rsv_entry WHERE namespace = ?)
             OR EXISTS (SELECT 1 FROM rsv_receipt WHERE namespace = ?) AS occupied`,
      ).get(input.namespace, input.namespace, input.namespace);
      if (occupied?.occupied !== 0) return { outcome: "rejected", reason: "not-empty" };
      this.#q("INSERT INTO rsv_namespace (namespace, epoch, state) VALUES (?, ?, 'serving')").run(input.namespace, input.epoch);
      return { outcome: "initialized" };
    });
  }

  async quarantine(input: { readonly namespace: string }, options?: StoreCallOptions): Promise<RecoveryState> {
    validateNamespace(input);
    return this.#transaction<RecoveryState>("write", options, (head) => {
      const ns = this.#namespace(head, input.namespace);
      if (ns.state === "uninitialized") return { epoch: 0, state: "uninitialized" };
      this.#q("UPDATE rsv_namespace SET state = 'quarantined' WHERE namespace = ?").run(input.namespace);
      return { epoch: ns.epoch, state: "quarantined" };
    });
  }

  async invalidateRecovered(input: InvalidateRecoveredInput, options?: StoreCallOptions): Promise<InvalidateRecoveredResult> {
    validateInvalidateRecovered(input);
    const result = this.#transaction<InvalidateRecoveredResult>("write", options, (head) => {
      const ns = this.#namespace(head, input.namespace);
      if (ns.state === "uninitialized") return { outcome: "rejected", reason: "uninitialized" };
      if (input.newEpoch <= ns.epoch) return { outcome: "rejected", reason: "epoch-not-greater" };
      // Every capture stamped with an earlier epoch is revoked from here on.
      this.#q("UPDATE rsv_namespace SET epoch = ?, state = 'serving' WHERE namespace = ?").run(input.newEpoch, input.namespace);
      this.#recovered = { databaseId: head.databaseId, counter: head.counter + 1 };
      return { outcome: "invalidated", recovery: { epoch: input.newEpoch, state: "serving" } };
    });
    // The operator has recovered this database on purpose: its present state becomes the baseline of the tripwire.
    const accepted = this.#recovered;
    this.#recovered = undefined;
    if (result.outcome === "invalidated" && accepted !== undefined) {
      HIGH_WATER.set(this.#path, accepted);
      this.#advanceMarker(accepted, true);
    }
    return result;
  }

  #recovered: Marker | undefined;
}
