// The SQLite drivers the tests run against, and a raw connection for the tests'
// own SQL (what an operator would run beside the store).
//
// better-sqlite3 is not part of the root install. It is installed by
// `npm run install:sqlite-driver` into qualification/sqlite-driver, the only
// place the repository runs its install script. RSV_BETTER_SQLITE3_DIR names
// another directory that holds it.
//
// RSV_SQLITE_DRIVERS lists the drivers this run must exercise (default
// "better-sqlite3,node:sqlite"). A listed driver that is not installed fails
// loudly, except node:sqlite, which is skipped with the reason when this
// Node.js has none or bundles a SQLite below the store's minimum.
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { betterSqlite3Driver, nodeSqliteDriver, sqliteVersionAcceptable } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
export const BETTER_SQLITE3_DIR = process.env.RSV_BETTER_SQLITE3_DIR ?? join(here, "../../../qualification/sqlite-driver");

/** @returns {{ name: string, driver?: object, raw?: Function, skip?: string, missing?: string }} */
export async function loadDriver(name) {
  if (name === "better-sqlite3") {
    let Database;
    try {
      Database = createRequire(join(BETTER_SQLITE3_DIR, "package.json"))("better-sqlite3");
    } catch {
      return { name, missing: "better-sqlite3 is not installed: run `npm run install:sqlite-driver` (or set RSV_SQLITE_DRIVERS=node:sqlite)" };
    }
    return {
      name,
      driver: betterSqlite3Driver(Database),
      open: (filename, { readonly = false } = {}) => {
        const db = new Database(filename, readonly ? { readonly: true } : {});
        return rawConnection(db, "better-sqlite3", Database);
      },
    };
  }
  if (name === "node:sqlite") {
    let sqlite;
    try {
      sqlite = await import("node:sqlite");
    } catch {
      return { name, skip: `node:sqlite is not available on Node.js ${process.version}` };
    }
    if (!sqliteVersionAcceptable(process.versions.sqlite)) {
      return { name, skip: `node:sqlite on Node.js ${process.version} bundles SQLite ${process.versions.sqlite}, below the store's minimum (3.51.3 or a backport)` };
    }
    return {
      name,
      driver: nodeSqliteDriver(sqlite),
      open: (filename, { readonly = false } = {}) => rawConnection(new sqlite.DatabaseSync(filename, readonly ? { readOnly: true } : {}), "node:sqlite", sqlite),
    };
  }
  throw new Error(`unknown driver ${name}`);
}

/** A uniform raw connection: exec, prepare, pragma, backup, close. */
function rawConnection(db, name, module) {
  return {
    exec: (text) => db.exec(text),
    prepare: (text) => db.prepare(text),
    /** `pragma("busy_timeout = 1000")` sets; `pragma("wal_checkpoint(TRUNCATE)")` returns its rows. */
    pragma(text) {
      if (text.includes("=")) {
        db.exec(`PRAGMA ${text}`);
        return [];
      }
      return db.prepare(`PRAGMA ${text}`).all();
    },
    get inTransaction() {
      return name === "better-sqlite3" ? db.inTransaction : db.isTransaction;
    },
    /** The SQLite backup API. node:sqlite has it from the Node.js releases that export `backup`. */
    backup: async (destination) => {
      if (name === "better-sqlite3") return db.backup(destination);
      if (typeof module.backup !== "function") throw new Error("this node:sqlite has no backup()");
      return module.backup(db, destination);
    },
    hasBackup: name === "better-sqlite3" || typeof module.backup === "function",
    close: () => db.close(),
  };
}

/** The drivers a run must exercise, loaded. Throws when a required one other than node:sqlite is missing. */
export async function requestedDrivers() {
  const names = (process.env.RSV_SQLITE_DRIVERS ?? "better-sqlite3,node:sqlite").split(",").map((name) => name.trim()).filter(Boolean);
  const loaded = [];
  for (const name of names) loaded.push(await loadDriver(name));
  return loaded;
}

/** The driver the non-conformance tests use: RSV_SQLITE_DRIVER, else the first usable requested one. */
export async function selectedDriver() {
  const wanted = process.env.RSV_SQLITE_DRIVER;
  const candidates = wanted === undefined ? await requestedDrivers() : [await loadDriver(wanted)];
  const missing = candidates.find((candidate) => candidate.missing !== undefined);
  if (wanted !== undefined && missing !== undefined) throw new Error(missing.missing);
  const usable = candidates.find((candidate) => candidate.driver !== undefined);
  if (usable === undefined) {
    throw new Error(candidates.map((candidate) => candidate.missing ?? candidate.skip).join("; "));
  }
  // A listed better-sqlite3 that is absent is an error even when node:sqlite could stand in: the run would not be the one asked for.
  if (wanted === undefined && missing !== undefined) throw new Error(missing.missing);
  return usable;
}
