/**
 * `@redact-secret/store-sqlite`: a ciphertext-only `Store` on one SQLite
 * database file for the persistent vault server, under the `sqlite-local-wal`
 * profile (docs/research/persistent-backend-capabilities.md §8.1).
 *
 * It holds no plaintext, key, grant, principal, or policy. It imports no
 * driver: the application loads `better-sqlite3` or `node:sqlite` itself and
 * passes it through `betterSqlite3Driver` or `nodeSqliteDriver`. The base
 * vault, server, and contracts packages stay free of any driver.
 */
export { checkDeployment, createSqliteStore, migrate } from "./store.js";
export type { DeploymentReport, MigrateOptions, SqliteStore, SqliteStoreOptions } from "./store.js";
export { SCHEMA_VERSION } from "./schema.js";
export { betterSqlite3Driver, nodeSqliteDriver } from "./drivers.js";
export { sqliteVersionAcceptable } from "./deployment.js";
export type { JournalMode, SqliteDriver } from "./deployment.js";
