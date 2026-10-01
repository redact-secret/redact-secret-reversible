// Startup verification: the store refuses to start unless the deployment is
// the profile (docs/research/persistent-backend-capabilities.md §8.1).
import assert from "node:assert/strict";
import { existsSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import { checkDeployment, createSqliteStore, migrate, sqliteVersionAcceptable } from "../dist/index.js";
import { openSqliteStore } from "../dist/store.js";
import { initialized, openStore, randomNamespace, rawCapture } from "../support/fixtures.mjs";
import { Database, freshDatabase, sql, tempDir } from "./helpers.mjs";

/** Captures the store's own connection so a test can read its pragmas back. */
function capture() {
  const held = {};
  return {
    held,
    wrapConnection: (db) => {
      held.db = db;
      return db;
    },
  };
}
const pragma = (db, name) => Object.values(db.prepare(`PRAGMA ${name}`).get())[0];

describe("startup verification", () => {
  const databases = [];
  after(() => {
    for (const database of databases) database.cleanup();
  });
  const fresh = async (options) => {
    const database = await freshDatabase(options);
    databases.push(database);
    return database;
  };

  test("the version rule: 3.51.3 or later, or the backports 3.44.6 and 3.50.7 in their own lines", () => {
    const table = [
      ["3.51.3", true],
      ["3.51.2", false],
      ["3.51.0", false],
      ["3.52.0", true],
      ["3.53.2", true],
      ["4.0.0", true],
      ["3.44.6", true],
      ["3.44.9", true],
      ["3.44.5", false],
      ["3.45.0", false],
      ["3.49.1", false],
      ["3.50.7", true],
      ["3.50.12", true],
      ["3.50.6", false],
      ["3.50.0", false],
      ["3.7.17", false],
      ["2.99.99", false],
      ["3.51.3.1", true],
      ["", false],
      ["3.51", false],
      ["not a version", false],
      [undefined, false],
      [3.51, false],
    ];
    for (const [version, expected] of table) assert.equal(sqliteVersionAcceptable(version), expected, String(version));
  });

  test("the SQLite the driver ships is acceptable, and the report says so", async () => {
    const database = await fresh();
    const report = await checkDeployment({ filename: database.filename });
    assert.equal(report.ok, true, report.failures.join(","));
    assert.equal(sqliteVersionAcceptable(report.sqliteVersion), true);
    assert.deepEqual(report.failures, []);
  });

  test("refuses a SQLite older than the fixed release", async () => {
    const database = await fresh();
    for (const version of ["3.51.2", "3.49.1", "3.50.6", "3.45.0"]) {
      await assert.rejects(openSqliteStore({ filename: database.filename }, { sqliteVersion: version }), { code: "STORE_CAPABILITY" }, version);
    }
    const store = await openSqliteStore({ filename: database.filename }, { sqliteVersion: "3.50.7" });
    store.close();
  });

  test("WAL with synchronous=FULL, a finite busy_timeout, foreign keys, and normal locking are set and read back", async () => {
    const database = await fresh();
    const seen = capture();
    const store = await openSqliteStore({ filename: database.filename, busyTimeoutMs: 1234 }, { wrapConnection: seen.wrapConnection });
    try {
      assert.equal(pragma(seen.held.db, "journal_mode"), "wal");
      assert.equal(pragma(seen.held.db, "synchronous"), 2, "FULL");
      assert.equal(pragma(seen.held.db, "busy_timeout"), 1234);
      assert.equal(pragma(seen.held.db, "foreign_keys"), 1);
      assert.equal(pragma(seen.held.db, "locking_mode"), "normal");
      if (process.platform === "darwin") {
        assert.equal(pragma(seen.held.db, "fullfsync"), 1);
        assert.equal(pragma(seen.held.db, "checkpoint_fullfsync"), 1);
      }
      const capabilities = store.capabilities();
      assert.equal(capabilities.profile, "sqlite-local-wal/synchronous=FULL");
      assert.equal(capabilities.adapter, "store-sqlite");
      assert.equal(capabilities.storeClock, true);
      assert.equal(capabilities.crossProcess, true);
      assert.equal(capabilities.durability, "durable");
      assert.equal(capabilities.restoreDetection, "sqlite-counter-high-water-mark-and-marker-file");
    } finally {
      store.close();
    }
  });

  test("the alternative profile: journal_mode=DELETE with synchronous=EXTRA", async () => {
    const database = await fresh();
    const seen = capture();
    const store = await openSqliteStore({ filename: database.filename, journalMode: "delete" }, { wrapConnection: seen.wrapConnection });
    try {
      assert.equal(pragma(seen.held.db, "journal_mode"), "delete");
      assert.equal(pragma(seen.held.db, "synchronous"), 3, "EXTRA");
      assert.equal(store.capabilities().profile, "sqlite-local-delete/synchronous=EXTRA");
      const namespace = randomNamespace("delete");
      await initialized(store, namespace, 1);
      assert.equal((await store.createCapture(rawCapture({ namespace }))).outcome, "created");
      assert.equal(existsSync(`${database.filename}-wal`), false, "no WAL file in this mode");
    } finally {
      store.close();
    }
  });

  test("rejects a journal mode or synchronous level the profile does not name", async () => {
    const database = await fresh();
    for (const journalMode of ["memory", "off", "truncate", "WAL", 1, null]) {
      await assert.rejects(createSqliteStore({ filename: database.filename, journalMode }), { code: "STORE_INVALID_ARGUMENT" }, String(journalMode));
    }
  });

  test("an unbounded or absurd busy_timeout is refused", async () => {
    const database = await fresh();
    for (const busyTimeoutMs of [0, -1, 1.5, 60_001, Number.POSITIVE_INFINITY, Number.NaN, "1000"]) {
      await assert.rejects(createSqliteStore({ filename: database.filename, busyTimeoutMs }), { code: "STORE_INVALID_ARGUMENT" }, String(busyTimeoutMs));
      await assert.rejects(migrate({ filename: database.filename, busyTimeoutMs }), { code: "STORE_INVALID_ARGUMENT" }, String(busyTimeoutMs));
    }
  });

  test("an in-memory, temporary, URI, or empty name is refused: one canonical path", async () => {
    for (const filename of [":memory:", "", "file:vault.sqlite?mode=memory", undefined, null, 7, "a\0b"]) {
      await assert.rejects(createSqliteStore({ filename }), { code: "STORE_INVALID_ARGUMENT" }, String(filename));
    }
  });

  test("a missing file and a database without the schema are refused, and nothing is created", async () => {
    const temp = tempDir();
    try {
      const missing = join(temp.dir, "missing.sqlite");
      await assert.rejects(createSqliteStore({ filename: missing }), { code: "STORE_CAPABILITY" });
      assert.equal(existsSync(missing), false, "a store never creates the file: migrate does");
      const blank = join(temp.dir, "blank.sqlite");
      new Database(blank).close();
      await assert.rejects(createSqliteStore({ filename: blank }), { code: "STORE_CAPABILITY" });
      assert.deepEqual((await checkDeployment({ filename: blank })).failures, ["schema"]);
    } finally {
      temp.cleanup();
    }
  });

  test("a schema version this adapter does not know is refused", async () => {
    const database = await fresh();
    const db = new Database(database.filename);
    db.exec("UPDATE rsv_meta SET version = 2");
    db.close();
    await assert.rejects(createSqliteStore({ filename: database.filename }), { code: "STORE_CAPABILITY" });
  });

  test("a marker file that cannot be written means the tripwire is not there: refused instead of declared", async () => {
    const database = await fresh();
    // The marker's directory is a regular file.
    await assert.rejects(createSqliteStore({ filename: database.filename, restoreMarker: join(database.filename, "marker") }), { code: "STORE_CAPABILITY" });
    // Without a marker the store says what it has left.
    const store = await createSqliteStore({ filename: database.filename, restoreMarker: false });
    try {
      assert.equal(store.capabilities().restoreDetection, "sqlite-process-high-water-mark");
    } finally {
      store.close();
    }
  });

  test("migrate is idempotent and keeps the database identity, counter, and data", async () => {
    const database = await fresh();
    const before = sql(database.filename, "SELECT database_id, version, counter FROM rsv_meta")[0];
    const store = await openStore(database.filename);
    const namespace = randomNamespace("migrate");
    await initialized(store, namespace, 1);
    store.close();
    await migrate({ filename: database.filename });
    await migrate({ filename: database.filename });
    const after_ = sql(database.filename, "SELECT database_id, version, counter FROM rsv_meta")[0];
    assert.equal(after_.database_id, before.database_id);
    assert.equal(after_.version, 1);
    assert.ok(after_.counter >= 1, "the counter is not reset");
    assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_namespace WHERE namespace = ?", namespace)[0].n, 1);
  });

  test("tables hold no plaintext column: ciphertext, identifiers, counters, and times only", async () => {
    const database = await fresh();
    const columns = sql(
      database.filename,
      "SELECT m.name AS tbl, p.name AS col, p.type AS type FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type = 'table' AND m.name LIKE 'rsv_%' ORDER BY 1, 2",
    );
    const names = columns.map((column) => `${column.tbl}.${column.col}`);
    for (const forbidden of ["value", "token", "plaintext", "secret", "grant", "policy", "principal", "session_id", "data_key"]) {
      assert.ok(!names.some((name) => name.endsWith(`.${forbidden}`)), forbidden);
    }
    assert.ok(columns.every((column) => ["TEXT", "INTEGER", "BLOB"].includes(column.type)), "STRICT tables with three storage types");
    assert.ok(names.includes("rsv_entry.envelope") && names.includes("rsv_capture.wrapped_key"));
  });

  test("one canonical path: a symlink and the real name share one marker and one high-water mark", async () => {
    const database = await fresh();
    const link = join(database.dir, "link.sqlite");
    symlinkSync(database.filename, link);
    const viaLink = await openStore(link);
    const direct = await openStore(database.filename);
    try {
      assert.equal(existsSync(`${database.filename}.rsv-marker`), true);
      assert.equal(existsSync(`${link}.rsv-marker`), false, "no second marker under the alias");
      const namespace = randomNamespace("alias");
      await initialized(viaLink, namespace, 1);
      assert.deepEqual(await direct.recoveryState({ namespace }), { epoch: 1, state: "serving" });
    } finally {
      viaLink.close();
      direct.close();
    }
  });
});
