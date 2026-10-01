/**
 * Schema of `@redact-secret/store-sqlite`, version 1.
 *
 * Every column is ciphertext, an opaque identifier, a counter, or a time.
 * There is no plaintext value, issued token, data key, grant, or finding type
 * here (docs/specs/persistent-vault.md §3.7 lists what stays visible).
 *
 * Migrations are forward-only and never rewrite `used`, a revision, an epoch,
 * or a capture state.
 */
export const SCHEMA_VERSION = 1;

/**
 * The statements that create schema version 1. Idempotent. `rsv_meta` holds
 * the schema version, a random database identifier, and `counter`, which every
 * write transaction increments: the restore tripwire reads it
 * (docs/reference/store-sqlite.md).
 */
export function migrationStatements(databaseId: string): readonly string[] {
  if (!/^[0-9a-f-]{36}$/.test(databaseId)) throw new RangeError("invalid database identifier");
  return [
    `CREATE TABLE IF NOT EXISTS rsv_meta (
       singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
       version INTEGER NOT NULL,
       database_id TEXT NOT NULL,
       counter INTEGER NOT NULL CHECK (counter >= 0)
     ) STRICT`,
    `INSERT OR IGNORE INTO rsv_meta (singleton, version, database_id, counter) VALUES (1, ${SCHEMA_VERSION}, '${databaseId}', 0)`,
    `CREATE TABLE IF NOT EXISTS rsv_namespace (
       namespace TEXT PRIMARY KEY,
       epoch INTEGER NOT NULL CHECK (epoch >= 1),
       state TEXT NOT NULL CHECK (state IN ('serving', 'quarantined'))
     ) STRICT`,
    `CREATE TABLE IF NOT EXISTS rsv_capture (
       namespace TEXT NOT NULL,
       tenant TEXT NOT NULL,
       capture_id TEXT NOT NULL,
       state TEXT NOT NULL CHECK (state IN ('live', 'revoked')),
       generation INTEGER NOT NULL CHECK (generation >= 1),
       key_revision INTEGER NOT NULL CHECK (key_revision >= 1),
       epoch INTEGER NOT NULL CHECK (epoch >= 1),
       session_tag TEXT,
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       key_ref TEXT NOT NULL,
       wrapped_key BLOB NOT NULL,
       has_ciphertext INTEGER NOT NULL CHECK (has_ciphertext IN (0, 1)),
       retain_until INTEGER NOT NULL,
       PRIMARY KEY (namespace, tenant, capture_id)
     ) STRICT`,
    `CREATE INDEX IF NOT EXISTS rsv_capture_sweep ON rsv_capture (namespace, retain_until)`,
    `CREATE TABLE IF NOT EXISTS rsv_entry (
       namespace TEXT NOT NULL,
       tenant TEXT NOT NULL,
       entry_id TEXT NOT NULL,
       capture_id TEXT NOT NULL,
       max_uses INTEGER NOT NULL CHECK (max_uses >= 1),
       used INTEGER NOT NULL CHECK (used >= 0),
       lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision >= 1),
       ciphertext_revision INTEGER NOT NULL CHECK (ciphertext_revision >= 1),
       envelope BLOB NOT NULL,
       expires_at INTEGER NOT NULL,
       PRIMARY KEY (namespace, tenant, entry_id),
       CHECK (used <= max_uses),
       FOREIGN KEY (namespace, tenant, capture_id) REFERENCES rsv_capture (namespace, tenant, capture_id)
     ) STRICT`,
    `CREATE INDEX IF NOT EXISTS rsv_entry_capture ON rsv_entry (namespace, tenant, capture_id)`,
    `CREATE INDEX IF NOT EXISTS rsv_entry_sweep ON rsv_entry (namespace, expires_at)`,
    `CREATE TABLE IF NOT EXISTS rsv_receipt (
       namespace TEXT NOT NULL,
       tenant TEXT NOT NULL,
       attempt_id TEXT NOT NULL,
       request_digest BLOB NOT NULL,
       committed_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       PRIMARY KEY (namespace, tenant, attempt_id)
     ) STRICT`,
    `CREATE INDEX IF NOT EXISTS rsv_receipt_sweep ON rsv_receipt (namespace, expires_at)`,
  ];
}
