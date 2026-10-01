/**
 * `@redact-secret/store-postgres`: a ciphertext-only `Store` on PostgreSQL
 * for the persistent vault server (docs/specs/persistent-vault.md §5).
 *
 * It holds no plaintext, key, grant, principal, or policy, and imports no
 * driver: the application passes its own `pg` pool and closes it.
 */
export { createPostgresStore, migrate } from "./store.js";
export type { PgClientLike, PgPoolLike, PostgresStore, PostgresStoreOptions } from "./store.js";
export { grantStatements, migrationStatements, SCHEMA_VERSION } from "./schema.js";
