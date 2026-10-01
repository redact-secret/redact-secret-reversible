/**
 * Schema of `@redact-secret/store-postgres`, version 1.
 *
 * Every column is ciphertext, an opaque identifier, a counter, or a time.
 * There is no plaintext value, issued token, data key, grant, or finding type
 * here (docs/specs/persistent-vault.md §3.7 lists what stays visible).
 *
 * Migrations are forward-only and never rewrite `used`, a revision, an epoch,
 * or a capture state.
 */
export const SCHEMA_VERSION = 1;

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

/** A schema name is interpolated into SQL, so it is restricted to a plain lowercase identifier. */
export function isSchemaName(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

/** The statements that create schema version 1. Idempotent. Run by a role that owns the schema. */
export function migrationStatements(schema: string): readonly string[] {
  if (!isSchemaName(schema)) throw new RangeError("invalid schema name");
  const s = `"${schema}"`;
  return [
    `CREATE SCHEMA IF NOT EXISTS ${s}`,
    `CREATE TABLE IF NOT EXISTS ${s}.rsv_schema (
       singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
       version integer NOT NULL
     )`,
    `INSERT INTO ${s}.rsv_schema (singleton, version) VALUES (true, ${SCHEMA_VERSION})
       ON CONFLICT (singleton) DO NOTHING`,
    `CREATE TABLE IF NOT EXISTS ${s}.rsv_namespace (
       namespace text PRIMARY KEY,
       epoch bigint NOT NULL CHECK (epoch >= 1),
       state text NOT NULL CHECK (state IN ('serving', 'quarantined')),
       system_identifier text NOT NULL,
       timeline_id bigint NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS ${s}.rsv_capture (
       namespace text NOT NULL,
       tenant text NOT NULL,
       capture_id text NOT NULL,
       state text NOT NULL CHECK (state IN ('live', 'revoked')),
       generation integer NOT NULL CHECK (generation >= 1),
       key_revision integer NOT NULL CHECK (key_revision >= 1),
       epoch bigint NOT NULL CHECK (epoch >= 1),
       session_tag text,
       created_at bigint NOT NULL,
       expires_at bigint NOT NULL,
       key_ref text NOT NULL,
       wrapped_key bytea NOT NULL,
       has_ciphertext boolean NOT NULL,
       retain_until bigint NOT NULL,
       PRIMARY KEY (namespace, tenant, capture_id)
     )`,
    `CREATE INDEX IF NOT EXISTS rsv_capture_sweep ON ${s}.rsv_capture (namespace, retain_until)`,
    `CREATE TABLE IF NOT EXISTS ${s}.rsv_entry (
       namespace text NOT NULL,
       tenant text NOT NULL,
       entry_id text NOT NULL,
       capture_id text NOT NULL,
       max_uses integer NOT NULL CHECK (max_uses >= 1),
       used integer NOT NULL CHECK (used >= 0),
       lifecycle_revision integer NOT NULL CHECK (lifecycle_revision >= 1),
       ciphertext_revision integer NOT NULL CHECK (ciphertext_revision >= 1),
       envelope bytea NOT NULL,
       expires_at bigint NOT NULL,
       PRIMARY KEY (namespace, tenant, entry_id),
       CHECK (used <= max_uses),
       FOREIGN KEY (namespace, tenant, capture_id)
         REFERENCES ${s}.rsv_capture (namespace, tenant, capture_id)
     )`,
    `CREATE INDEX IF NOT EXISTS rsv_entry_capture ON ${s}.rsv_entry (namespace, tenant, capture_id)`,
    `CREATE INDEX IF NOT EXISTS rsv_entry_sweep ON ${s}.rsv_entry (namespace, expires_at)`,
    `CREATE TABLE IF NOT EXISTS ${s}.rsv_receipt (
       namespace text NOT NULL,
       tenant text NOT NULL,
       attempt_id text NOT NULL,
       request_digest bytea NOT NULL,
       committed_at bigint NOT NULL,
       expires_at bigint NOT NULL,
       PRIMARY KEY (namespace, tenant, attempt_id)
     )`,
    `CREATE INDEX IF NOT EXISTS rsv_receipt_sweep ON ${s}.rsv_receipt (namespace, expires_at)`,
  ];
}

/**
 * The privileges the serving role needs, for a schema owned by a separate
 * migration role: row access to the four tables and nothing else. It needs no
 * DDL, no TRUNCATE, and no access to any other schema.
 */
export function grantStatements(schema: string, role: string): readonly string[] {
  if (!isSchemaName(schema) || !isSchemaName(role)) throw new RangeError("invalid identifier");
  const s = `"${schema}"`;
  const r = `"${role}"`;
  return [
    `GRANT USAGE ON SCHEMA ${s} TO ${r}`,
    `GRANT SELECT ON ${s}.rsv_schema TO ${r}`,
    `GRANT SELECT, INSERT, UPDATE ON ${s}.rsv_namespace TO ${r}`,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ${s}.rsv_capture, ${s}.rsv_entry, ${s}.rsv_receipt TO ${r}`,
  ];
}
