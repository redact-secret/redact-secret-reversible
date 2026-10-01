/**
 * `@redact-secret/store-sqlite`: a ciphertext-only `Store` on one SQLite
 * database file for the persistent vault server, under the `sqlite-local-wal`
 * profile (docs/research/persistent-backend-capabilities.md §8.1).
 *
 * It holds no plaintext, key, grant, principal, or policy. `better-sqlite3` is
 * an optional peer dependency that only this package names; the base vault,
 * server, and contracts packages stay free of any driver.
 */
export { checkDeployment, createSqliteStore, migrate } from "./store.js";
export type { DeploymentReport, MigrateOptions, SqliteStore, SqliteStoreOptions } from "./store.js";
export { SCHEMA_VERSION } from "./schema.js";
export { sqliteVersionAcceptable } from "./deployment.js";
export type { JournalMode } from "./deployment.js";
