// Backup and restore of the database file, and what the restore tripwire does
// and does not notice. The recovery runbook is
// docs/specs/persistent-operations.md §5 and docs/reference/store-sqlite.md.
//
// A restored backup is a faithful older copy: nothing inside the file can tell
// it from the original. The adapter's tripwire (a counter every write
// transaction increments, a process-local high-water mark, and a marker file)
// is evidence of a rollback only where one of the two witnesses outlived it.
// The last test here shows the case it does not cover.
import assert from "node:assert/strict";
import { copyFileSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import {
  captureText,
  initialized,
  openStore,
  randomAttemptId,
  randomNamespace,
  RELEASE,
  rawCapture,
  rawCommit,
  restoreRequest,
  spawnWorker,
  syntheticKeys,
  wire,
} from "../support/fixtures.mjs";
import { driver, Database, freshDatabase, sql } from "./helpers.mjs";

const TENANT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };

/** Removes the live file and its side files, so a copied-in backup is all that remains. */
function removeLive(filename) {
  for (const suffix of ["", "-wal", "-shm"]) rmSync(`${filename}${suffix}`, { force: true });
}

describe("backup and restore", () => {
  const databases = [];
  const workers = new Set();
  after(async () => {
    for (const started of workers) await started.kill("SIGKILL");
    for (const database of databases) database.cleanup();
  });

  const fresh = async () => {
    const database = await freshDatabase();
    databases.push(database);
    return database;
  };
  const spawn = async (config) => {
    const started = await spawnWorker(config);
    workers.add(started);
    return started;
  };

  /**
   * A namespace with one live capture of two entries, `maxUses` 2, one of them
   * restored once, then `after` more mutations, so a backup taken between has a
   * lower counter than the file at the end.
   */
  async function history(database, { backup }) {
    const namespace = randomNamespace("backup");
    const store = await openStore(database.filename);
    await initialized(store, namespace, 1);
    const input = rawCapture({ namespace, entries: 2, maxUses: 2 });
    assert.equal((await store.createCapture(input)).outcome, "created");
    assert.equal((await store.commitRestore(await rawCommit(store, input))).outcome, "committed");
    const backupPath = join(database.dir, "backup.sqlite");
    await backup(database.filename, backupPath, store);
    // After the backup: a second use is spent, and then the capture is revoked.
    assert.equal((await store.commitRestore(await rawCommit(store, input))).outcome, "committed");
    assert.equal((await store.revokeCapture({ scope: input.scope, captureId: input.capture.captureId, now: Date.now(), retentionMs: 60_000, fenceAbsent: false })).outcome, "revoked");
    store.close();
    return { namespace, input, backupPath };
  }

  const viaBackupApi = async (filename, destination) => {
    const db = new Database(filename);
    try {
      db.pragma("busy_timeout = 30000");
      await db.backup(destination);
    } finally {
      db.close();
    }
  };
  const viaVacuumInto = async (filename, destination) => {
    const db = new Database(filename);
    try {
      db.pragma("busy_timeout = 30000");
      db.exec(`VACUUM INTO '${destination.replaceAll("'", "''")}'`);
    } finally {
      db.close();
    }
  };
  const viaFileCopy = async (filename, destination, store) => {
    // A copy of the main file alone is safe only when no transaction is in progress and the WAL has been
    // folded into it: checkpoint first, then copy.
    const db = new Database(filename);
    try {
      db.pragma("busy_timeout = 30000");
      const [result] = db.pragma("wal_checkpoint(TRUNCATE)");
      assert.equal(result.busy, 0, "the checkpoint ran to completion");
    } finally {
      db.close();
    }
    copyFileSync(filename, destination);
    void store;
  };

  for (const [name, backup] of [
    ["the SQLite backup API", viaBackupApi],
    ["VACUUM INTO", viaVacuumInto],
    ["a file copy after a TRUNCATE checkpoint", viaFileCopy],
  ]) {
    describe(`backup by ${name}`, () => {
      test("restored into a new process: the tripwire (marker file) quarantines, and recovered captures do not serve", async () => {
        const database = await fresh();
        const { namespace, input, backupPath } = await history(database, { backup });
        // The disaster: the live file is replaced by the backup. The marker file survives it, beside the database.
        removeLive(database.filename);
        copyFileSync(backupPath, database.filename);

        const recovered = await spawn({ filename: database.filename });
        const state = await recovered.call("store", { method: "recoveryState", input: { namespace } });
        assert.deepEqual(state.value, { epoch: 1, state: "quarantined" }, "a restored database reads as quarantined by itself");

        const read = await recovered.call("store", { method: "readEntries", input: wire({ scope: input.scope, entryIds: input.entries.map((entry) => entry.entryId) }) });
        assert.equal(read.value.recovery.state, "quarantined");
        // Not served: no commit, no creation, whatever the backup's rows say (the backup holds the capture live with one use left).
        const store = await openStore(database.filename, { restoreMarker: false });
        const commit = await rawCommit(store, input, { attemptId: randomAttemptId() });
        store.close();
        const denied = await recovered.call("store", { method: "commitRestore", input: wire(commit) });
        assert.deepEqual([denied.value.outcome, denied.value.reason], ["rejected", "quarantined"]);
        const created = await recovered.call("store", { method: "createCapture", input: wire(rawCapture({ namespace })) });
        assert.deepEqual([created.value.outcome, created.value.reason], ["rejected", "quarantined"]);
        // Revocation still works in a quarantined namespace.
        const revoked = await recovered.call("store", {
          method: "revokeCapture",
          input: wire({ scope: input.scope, captureId: input.capture.captureId, now: Date.now(), retentionMs: 60_000, fenceAbsent: false }),
        });
        assert.equal(revoked.value.outcome, "revoked");
      });

      test("the runbook: quarantine, then invalidateRecovered under a new epoch; every recovered capture is revoked, new ones serve", async () => {
        const database = await fresh();
        const { namespace, input, backupPath } = await history(database, { backup });
        removeLive(database.filename);
        copyFileSync(backupPath, database.filename);

        // 1. No server runs against it (none is started here). 2. quarantine. 3-4. a higher epoch.
        const store = await openStore(database.filename);
        try {
          assert.equal((await store.recoveryState({ namespace })).state, "quarantined");
          assert.equal((await store.quarantine({ namespace })).state, "quarantined");
          assert.deepEqual((await store.invalidateRecovered({ namespace, newEpoch: 2 })).outcome, "invalidated");
          assert.deepEqual(await store.recoveryState({ namespace }), { epoch: 2, state: "serving" });
          // 5. servers start with the new epoch. The recovered capture reads as revoked and cannot be committed.
          const [capture] = await store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] });
          assert.equal(capture.state, "revoked");
          const stale = await rawCommit(store, { ...input, epoch: 2 }, { attemptId: randomAttemptId() });
          assert.deepEqual(await store.commitRestore(stale).then((result) => [result.outcome, result.reason]), ["rejected", "revoked"]);
          // The old epoch is refused outright.
          assert.deepEqual(await store.commitRestore({ ...stale, epoch: 1 }).then((result) => [result.outcome, result.reason]), ["rejected", "quarantined"]);
          const next = rawCapture({ namespace, epoch: 2 });
          assert.equal((await store.createCapture(next)).outcome, "created");
        } finally {
          store.close();
        }
        // The recovery is the baseline now: a new process finds a serving namespace, not a perpetual quarantine.
        const later = await spawn({ filename: database.filename });
        assert.deepEqual((await later.call("store", { method: "recoveryState", input: { namespace } })).value, { epoch: 2, state: "serving" });
      });
    });
  }

  test("a process that outlives the replacement notices it too, with no marker file at all", async () => {
    const database = await fresh();
    const namespace = randomNamespace("outlive");
    const options = { restoreMarker: false };
    const store = await openStore(database.filename, options);
    await initialized(store, namespace, 1);
    const input = rawCapture({ namespace });
    assert.equal((await store.createCapture(input)).outcome, "created");
    store.close();
    const backupPath = join(database.dir, "backup.sqlite");
    await viaBackupApi(database.filename, backupPath);
    const again = await openStore(database.filename, options);
    assert.equal((await again.commitRestore(await rawCommit(again, input))).outcome, "committed");
    again.close();
    removeLive(database.filename);
    copyFileSync(backupPath, database.filename);
    // The same process opens the replaced file: its high-water mark is higher than the file's counter.
    const reopened = await openStore(database.filename, options);
    try {
      assert.equal(reopened.capabilities().restoreDetection, "sqlite-process-high-water-mark");
      assert.deepEqual(await reopened.recoveryState({ namespace }), { epoch: 1, state: "quarantined" });
    } finally {
      reopened.close();
    }
  });

  test("a file copy of the main file alone, while the database is live, is an older database: it misses what is still in the WAL", async () => {
    const database = await fresh();
    const namespace = randomNamespace("mainonly");
    const store = await openStore(database.filename);
    try {
      await initialized(store, namespace, 1);
      const before = sql(database.filename, "SELECT counter FROM rsv_meta")[0].counter;
      const input = rawCapture({ namespace, entries: 1 });
      assert.equal((await store.createCapture(input)).outcome, "created");
      const copy = join(database.dir, "main-only.sqlite");
      copyFileSync(database.filename, copy);
      assert.ok(existsSync(`${database.filename}-wal`), "committed transactions are in the -wal file");
      const [row] = sql(copy, "SELECT counter FROM rsv_meta");
      assert.ok(row.counter < before + 1, "the copy is behind the live database: committed transactions are missing");
    } finally {
      store.close();
    }
  });

  test("NOT detected: a backup restored together with its marker file reads as a healthy database", async () => {
    // The limit, stated as a test. When the marker is restored from the same backup set, and no process outlived the
    // replacement, nothing distinguishes the old file from the current one. The runbook is then the only control.
    const database = await fresh();
    const namespace = randomNamespace("both");
    const store = await openStore(database.filename);
    await initialized(store, namespace, 1);
    const input = rawCapture({ namespace, entries: 1, maxUses: 1 });
    assert.equal((await store.createCapture(input)).outcome, "created");
    store.close();
    const marker = `${database.filename}.rsv-marker`;
    const backupPath = join(database.dir, "backup.sqlite");
    await viaBackupApi(database.filename, backupPath);
    const markerBackup = readFileSync(marker, "utf8");
    const later = await openStore(database.filename);
    assert.equal((await later.commitRestore(await rawCommit(later, input))).outcome, "committed", "the single use is spent");
    later.close();

    removeLive(database.filename);
    copyFileSync(backupPath, database.filename);
    writeFileSync(marker, markerBackup);
    const recovered = await spawn({ filename: database.filename });
    assert.deepEqual((await recovered.call("store", { method: "recoveryState", input: { namespace } })).value, { epoch: 1, state: "serving" });
    // The spent use is available again: a silent rollback of a budget.
    const store2 = await openStore(database.filename, { restoreMarker: false });
    const commit = await rawCommit(store2, input, { attemptId: randomAttemptId() });
    store2.close();
    const replayed = await recovered.call("store", { method: "commitRestore", input: wire(commit) });
    assert.equal(replayed.value.outcome, "committed", "the tripwire does not cover this case; the runbook must be followed");
  });

  test("a marker file that does not parse is read as a rollback signal, and invalidateRecovered rewrites it", async () => {
    const database = await fresh();
    const namespace = randomNamespace("badmarker");
    const store = await openStore(database.filename);
    await initialized(store, namespace, 1);
    store.close();
    writeFileSync(`${database.filename}.rsv-marker`, "not a marker");
    const process_ = await spawn({ filename: database.filename });
    assert.deepEqual((await process_.call("store", { method: "recoveryState", input: { namespace } })).value, { epoch: 1, state: "quarantined" });
    const operator = await openStore(database.filename);
    assert.equal((await operator.invalidateRecovered({ namespace, newEpoch: 2 })).outcome, "invalidated");
    operator.close();
    const later = await spawn({ filename: database.filename });
    assert.deepEqual((await later.call("store", { method: "recoveryState", input: { namespace } })).value, { epoch: 2, state: "serving" });
  });

  test("a replaced database of another history (different database_id) is quarantined by the marker", async () => {
    const one = await fresh();
    const two = await fresh();
    const namespace = randomNamespace("other");
    const store = await openStore(one.filename);
    await initialized(store, namespace, 1);
    store.close();
    const other = await openStore(two.filename);
    await initialized(other, namespace, 1);
    other.close();
    removeLive(one.filename);
    copyFileSync(two.filename, one.filename);
    const process_ = await spawn({ filename: one.filename });
    assert.deepEqual((await process_.call("store", { method: "recoveryState", input: { namespace } })).value, { epoch: 1, state: "quarantined" });
  });

  test("through the server: recovered tokens are denied, before and after the runbook", async () => {
    const database = await fresh();
    const namespace = randomNamespace("server");
    const keys = syntheticKeys();
    const store = await openStore(database.filename);
    await initialized(store, namespace, 1);
    store.close();
    const before = await spawn({ filename: database.filename, namespace, epoch: 1, ...keys });
    const { text } = captureText(1, 900);
    const captured = await before.call("capture", { text, context: TENANT, maxUses: 3, release: RELEASE });
    assert.equal(captured.ok, true, captured.code);
    const tokens = captured.value.tokens.map((token) => token.token);
    const request = () => restoreRequest({ context: TENANT, captures: [captured.value.captureId], tokens, attemptId: randomAttemptId() });
    await before.stop();
    const backupPath = join(database.dir, "backup.sqlite");
    await viaBackupApi(database.filename, backupPath);
    // Work after the backup moves the counter on.
    const working = await spawn({ filename: database.filename, namespace, epoch: 1, ...keys });
    assert.equal((await working.call("restore", { request: request() })).ok, true);
    await working.stop();

    removeLive(database.filename);
    copyFileSync(backupPath, database.filename);
    // A server started against the recovered file at the old epoch refuses to start: the namespace reads as quarantined.
    await assert.rejects(spawn({ filename: database.filename, namespace, epoch: 1, ...keys }), /STORE_QUARANTINED/);
    // The runbook, then servers at the new epoch.
    const operator = await openStore(database.filename);
    assert.equal((await operator.invalidateRecovered({ namespace, newEpoch: 2 })).outcome, "invalidated");
    operator.close();
    const after_ = await spawn({ filename: database.filename, namespace, epoch: 2, ...keys });
    const denied = await after_.call("restore", { request: request() });
    assert.equal(denied.ok, false);
    assert.equal(denied.code, "RESTORE_DENIED");
    assert.equal(denied.reason, "revoked");
    assert.equal(denied.hasFields, false);
    // Capturing again from the source works under the new epoch.
    const again = await after_.call("capture", { text, context: TENANT, maxUses: 1, release: RELEASE });
    assert.equal(again.ok, true, again.code);
  });
});
