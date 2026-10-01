/**
 * The two drivers this package supports, as thin wrappers around a module the
 * application loads itself. Nothing here imports a driver: the application
 * does, and passes the module in. The startup version check of the store
 * applies to both.
 */
import { existsSync } from "node:fs";

import { StoreError } from "@redact-secret/vault-contracts";

import type { Database, SqliteDriver } from "./deployment.js";

/**
 * `better-sqlite3` (`^12.11.1`). Pass the default export of the package the
 * application installed and loaded.
 */
export function betterSqlite3Driver(DatabaseConstructor: unknown): SqliteDriver {
  if (typeof DatabaseConstructor !== "function") throw new StoreError("STORE_INVALID_ARGUMENT");
  const Constructor = DatabaseConstructor as new (path: string, options: { fileMustExist: boolean; timeout: number }) => Database;
  return Object.freeze({
    name: "better-sqlite3",
    open: (path: string, options: { readonly fileMustExist: boolean; readonly busyTimeoutMs: number }): Database =>
      new Constructor(path, { fileMustExist: options.fileMustExist, timeout: options.busyTimeoutMs }),
  });
}

interface NodeSqliteConnection {
  readonly isTransaction?: unknown;
  prepare(source: string): ReturnType<Database["prepare"]>;
  exec(source: string): unknown;
  close(): unknown;
}

/**
 * Node.js's built-in SQLite module (experimental in the Node.js releases that
 * have it). Pass the module the application loaded.
 * The SQLite it bundles is the Node.js build's own, so the store's version
 * check decides whether a given Node.js release may be used. A Node.js without
 * `DatabaseSync.prototype.isTransaction` is refused: the store needs it to know
 * whether a transaction is still open after a failed `COMMIT`.
 */
export function nodeSqliteDriver(sqliteModule: unknown): SqliteDriver {
  const DatabaseSync = (sqliteModule as { DatabaseSync?: unknown } | null)?.DatabaseSync;
  if (typeof DatabaseSync !== "function") throw new StoreError("STORE_INVALID_ARGUMENT");
  const Constructor = DatabaseSync as new (path: string) => NodeSqliteConnection;
  return Object.freeze({
    name: "node:sqlite",
    open(path: string, options: { readonly fileMustExist: boolean; readonly busyTimeoutMs: number }): Database {
      if (options.fileMustExist && !existsSync(path)) throw new StoreError("STORE_CAPABILITY");
      const raw = new Constructor(path);
      if (typeof raw.isTransaction !== "boolean") {
        raw.close();
        throw new StoreError("STORE_CAPABILITY");
      }
      return {
        get inTransaction(): boolean {
          return raw.isTransaction === true;
        },
        prepare: (source: string) => raw.prepare(source),
        exec: (source: string) => raw.exec(source),
        close: () => raw.close(),
      };
    },
  });
}
