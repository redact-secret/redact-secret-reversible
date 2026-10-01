// Transaction discipline and outcome mapping (research §8.1): every mutation
// in BEGIN IMMEDIATE, a finite busy wait, and the three kinds of failure at or
// before COMMIT.
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import { openSqliteStore } from "../dist/store.js";
import { initialized, randomAttemptId, randomNamespace, rawCapture, rawCommit } from "../support/fixtures.mjs";
import { BUSY_MS, Database, freshDatabase, sql } from "./helpers.mjs";

/** A connection that records every `exec` and lets a test replace one. */
function spy(log, hooks = {}) {
  return (db) => ({
    get inTransaction() {
      return db.inTransaction;
    },
    prepare: (text) => db.prepare(text),
    exec(text) {
      log.push(text);
      return hooks.exec === undefined ? db.exec(text) : hooks.exec(text, db);
    },
    close: () => db.close(),
  });
}

describe("transactions", () => {
  const databases = [];
  after(() => {
    for (const database of databases) database.cleanup();
  });
  const fresh = async () => {
    const database = await freshDatabase();
    databases.push(database);
    return database;
  };

  test("every mutation runs in BEGIN IMMEDIATE and every read in a plain read transaction; none is deferred or exclusive", async () => {
    const database = await fresh();
    const log = [];
    const store = await openSqliteStore({ filename: database.filename, busyTimeoutMs: BUSY_MS }, { wrapConnection: spy(log) });
    try {
      const namespace = randomNamespace("immediate");
      const writes = [];
      const reads = [];
      const mark = async (kind, work) => {
        log.length = 0;
        await work();
        (kind === "write" ? writes : reads).push([...log]);
      };
      await mark("write", () => store.initializeNamespace({ namespace, epoch: 1 }));
      const input = rawCapture({ namespace, entries: 2, maxUses: 3 });
      await mark("write", () => store.createCapture(input));
      const commit = await rawCommit(store, input);
      await mark("write", () => store.commitRestore(commit));
      await mark("write", () => store.revokeCapture({ scope: input.scope, captureId: input.capture.captureId, now: Date.now(), retentionMs: 1000, fenceAbsent: false }));
      const second = rawCapture({ namespace, entries: 1 });
      await mark("write", () => store.createCapture(second));
      await mark("write", () =>
        store.replaceCaptureKey({ scope: second.scope, captureId: second.capture.captureId, keyRevision: 1, keyRef: "local:synthetic-2", wrappedKey: new Uint8Array(40).fill(7) }),
      );
      await mark("write", () => store.deleteCiphertext({ scope: input.scope, captureId: input.capture.captureId, now: Date.now() }));
      await mark("write", () => store.sweepExpired({ namespace, now: Date.now(), limit: 10 }));
      await mark("write", () => store.quarantine({ namespace }));
      await mark("write", () => store.invalidateRecovered({ namespace, newEpoch: 2 }));
      await mark("read", () => store.readEntries({ scope: input.scope, entryIds: input.entries.map((entry) => entry.entryId) }));
      await mark("read", () => store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] }));
      await mark("read", () => store.inspectAttempt({ scope: input.scope, attemptId: commit.attempt.attemptId }));
      await mark("read", () => store.recoveryState({ namespace }));

      assert.equal(writes.length, 10);
      for (const statements of writes) assert.equal(statements[0], "BEGIN IMMEDIATE", statements.join(" | "));
      for (const statements of reads) assert.equal(statements[0], "BEGIN", statements.join(" | "));
      for (const statements of [...writes, ...reads]) {
        assert.equal(statements.at(-1), "COMMIT");
        assert.ok(!statements.some((text) => /DEFERRED|EXCLUSIVE|SAVEPOINT/i.test(text)), statements.join(" | "));
      }
    } finally {
      store.close();
    }
  });

  test("a rejected outcome rolls back: the counter, like every row, is unchanged", async () => {
    const database = await fresh();
    const store = await openSqliteStore({ filename: database.filename, busyTimeoutMs: BUSY_MS }, {});
    try {
      const namespace = randomNamespace("rollback");
      await initialized(store, namespace, 1);
      const before = sql(database.filename, "SELECT counter FROM rsv_meta")[0].counter;
      const input = rawCapture({ namespace });
      assert.equal((await store.createCapture({ ...input, epoch: 9 })).reason, "quarantined");
      assert.equal(sql(database.filename, "SELECT counter FROM rsv_meta")[0].counter, before);
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
    } finally {
      store.close();
    }
  });

  test("a failure before COMMIT leaves nothing applied: STORE_UNAVAILABLE, and the rows are untouched", async () => {
    const database = await fresh();
    let armed = false;
    const store = await openSqliteStore(
      { filename: database.filename, busyTimeoutMs: BUSY_MS },
      {
        beforeCommit: () => {
          if (armed) throw new Error("synthetic failure before COMMIT");
        },
      },
    );
    try {
      const namespace = randomNamespace("before");
      await initialized(store, namespace, 1);
      const input = rawCapture({ namespace, entries: 2 });
      armed = true;
      await assert.rejects(store.createCapture(input), (thrown) => thrown instanceof StoreError && thrown.code === "STORE_UNAVAILABLE");
      armed = false;
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
      assert.equal((await store.createCapture(input)).outcome, "created", "the connection is usable after the rollback");
    } finally {
      store.close();
    }
  });

  test("COMMIT fails with the transaction still open and ROLLBACK succeeds: definitely no effect, STORE_UNAVAILABLE", async () => {
    const database = await fresh();
    const log = [];
    let fail = false;
    const store = await openSqliteStore(
      { filename: database.filename, busyTimeoutMs: BUSY_MS },
      {
        wrapConnection: spy(log, {
          exec(text, db) {
            if (fail && text === "COMMIT") throw Object.assign(new Error("synthetic SQLITE_BUSY at COMMIT"), { code: "SQLITE_BUSY" });
            return db.exec(text);
          },
        }),
      },
    );
    try {
      const namespace = randomNamespace("commitbusy");
      await initialized(store, namespace, 1);
      const input = rawCapture({ namespace });
      fail = true;
      await assert.rejects(store.createCapture(input), (thrown) => thrown.code === "STORE_UNAVAILABLE");
      fail = false;
      assert.ok(log.includes("ROLLBACK"), "the rollback that proves the outcome");
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
      assert.equal((await store.createCapture(input)).outcome, "created");
    } finally {
      store.close();
    }
  });

  test("COMMIT fails and the outcome cannot be established: STORE_AMBIGUOUS, resolved through the receipt, never retried by the adapter", async () => {
    const database = await fresh();
    let mode = "none";
    let commits = 0;
    const store = await openSqliteStore(
      { filename: database.filename, busyTimeoutMs: BUSY_MS },
      {
        wrapConnection: spy([], {
          exec(text, db) {
            if (mode !== "none" && text === "COMMIT") {
              commits += 1;
              // The transaction really commits, and the caller is told it failed: an I/O error after the sync.
              if (mode === "applied") db.exec("COMMIT");
              throw Object.assign(new Error("synthetic SQLITE_IOERR at COMMIT"), { code: "SQLITE_IOERR" });
            }
            if (mode === "no-rollback" && text === "ROLLBACK") throw new Error("synthetic failure of ROLLBACK");
            return db.exec(text);
          },
        }),
      },
    );
    try {
      const namespace = randomNamespace("ambiguous");
      await initialized(store, namespace, 1);
      const input = rawCapture({ namespace, maxUses: 2 });
      assert.equal((await store.createCapture(input)).outcome, "created");

      // (a) The commit was applied, the connection no longer in a transaction: ambiguous, and the receipt shows it applied.
      const applied = await rawCommit(store, input);
      mode = "applied";
      await assert.rejects(store.commitRestore(applied), (thrown) => thrown.code === "STORE_AMBIGUOUS");
      mode = "none";
      assert.equal(commits, 1, "one COMMIT was sent, none retried");
      assert.equal((await store.inspectAttempt({ scope: applied.scope, attemptId: applied.attempt.attemptId })).state, "committed");
      assert.equal((await store.commitRestore(applied)).outcome, "already-committed");

      // (b) COMMIT failed and so did ROLLBACK: ambiguous too.
      const second = await rawCommit(store, input, { attemptId: randomAttemptId() });
      mode = "no-rollback";
      await assert.rejects(store.commitRestore(second), (thrown) => thrown.code === "STORE_AMBIGUOUS");
      mode = "none";
      // The adapter closed its connection: the open transaction would otherwise hold the write lock against every other process.
      await assert.rejects(store.inspectAttempt({ scope: second.scope, attemptId: second.attempt.attemptId }), (thrown) => thrown.code === "STORE_CLOSED");
      const other = new Database(database.filename);
      other.pragma("busy_timeout = 1000");
      other.exec("BEGIN IMMEDIATE");
      other.exec("ROLLBACK");
      other.close();
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_receipt WHERE attempt_id = ?", second.attempt.attemptId)[0].n, 0);
    } finally {
      store.close();
    }
  });

  test("a writer that cannot get the write lock within the busy timeout fails STORE_UNAVAILABLE, applies nothing, and a WAL reader is not blocked", async () => {
    const database = await fresh();
    const store = await openSqliteStore({ filename: database.filename, busyTimeoutMs: 150 }, {});
    const holder = new Database(database.filename);
    holder.pragma("busy_timeout = 30000");
    try {
      const namespace = randomNamespace("busy");
      await initialized(store, namespace, 1);
      const input = rawCapture({ namespace });
      assert.equal((await store.createCapture(input)).outcome, "created");
      holder.exec("BEGIN IMMEDIATE");
      const startedAt = Date.now();
      const blocked = rawCapture({ namespace });
      await assert.rejects(store.createCapture(blocked), (thrown) => thrown.code === "STORE_UNAVAILABLE");
      const waited = Date.now() - startedAt;
      assert.ok(waited >= 100 && waited < 5000, `waited ${waited} ms: finite`);
      // Under WAL a reader sees the last committed snapshot while another connection holds the writer role.
      assert.equal((await store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] })).length, 1);
      holder.exec("ROLLBACK");
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", blocked.capture.captureId)[0].n, 0);
      assert.equal((await store.createCapture(blocked)).outcome, "created", "the writer role is available again");
    } finally {
      holder.close();
      store.close();
    }
  });

  test("a call cancelled before it starts has no effect; a closed store throws STORE_CLOSED", async () => {
    const database = await fresh();
    const store = await openSqliteStore({ filename: database.filename, busyTimeoutMs: BUSY_MS }, {});
    const namespace = randomNamespace("abort");
    await initialized(store, namespace, 1);
    const input = rawCapture({ namespace });
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(store.createCapture(input, { signal: controller.signal }), (thrown) => thrown.code === "STORE_UNAVAILABLE");
    assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
    store.close();
    store.close();
    await assert.rejects(store.createCapture(input), (thrown) => thrown.code === "STORE_CLOSED");
    await assert.rejects(store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] }), (thrown) => thrown.code === "STORE_CLOSED");
  });

  test("a read transaction is one snapshot: entries and their captures come from the same moment", async () => {
    const database = await fresh();
    const store = await openSqliteStore({ filename: database.filename, busyTimeoutMs: BUSY_MS }, {});
    const writer = await openSqliteStore({ filename: database.filename, busyTimeoutMs: BUSY_MS }, {});
    try {
      const namespace = randomNamespace("snapshot");
      await initialized(store, namespace, 1);
      const input = rawCapture({ namespace, entries: 2, maxUses: 3 });
      assert.equal((await store.createCapture(input)).outcome, "created");
      const read = await store.readEntries({ scope: input.scope, entryIds: input.entries.map((entry) => entry.entryId) });
      assert.equal(read.entries.length, 2);
      assert.equal(read.captures.length, 1);
      assert.equal(read.captures[0].state, "live");
      // A revocation by another connection afterwards is a later snapshot, never a mixture.
      await writer.revokeCapture({ scope: input.scope, captureId: input.capture.captureId, now: Date.now(), retentionMs: 1000, fenceAbsent: false });
      const later = await store.readEntries({ scope: input.scope, entryIds: input.entries.map((entry) => entry.entryId) });
      assert.equal(later.captures[0].state, "revoked");
      assert.equal(later.entries.length, 2);
    } finally {
      writer.close();
      store.close();
    }
  });
});
