// Fixtures for the store-sqlite tests. Every identifier, byte, and path here is
// synthetic. Each test works in a fresh temporary directory.
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";

import { StoreError } from "@redact-secret/vault-contracts";

import { migrate } from "../dist/index.js";
// Not a package export: the store with test seams.
import { openSqliteStore } from "../dist/store.js";

const require = createRequire(import.meta.url);
export const Database = require("better-sqlite3");

export const WORKER_URL = new URL("../support/store-worker.mjs", import.meta.url);

/** A fresh directory, removed by `cleanup`. */
export function tempDir(prefix = "rsv-sqlite-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export function randomNamespace(prefix = "t") {
  return `${prefix}-${Date.now().toString(36)}-${randomBytes(5).toString("hex")}`;
}

export const BUSY_MS = 30_000;

/** A migrated database in a temporary directory. */
export async function freshDatabase(options = {}) {
  const temp = tempDir();
  const filename = join(temp.dir, "vault.sqlite");
  await migrate({ filename, busyTimeoutMs: BUSY_MS, ...options });
  return { ...temp, filename };
}

/** A store in another thread, behind the `Store` interface. */
async function remoteStore(options, nowSql) {
  const done = new Int32Array(new SharedArrayBuffer(4));
  const worker = new Worker(WORKER_URL, { workerData: { options, nowSql, done: done.buffer } });
  const pending = new Map();
  let next = 1;
  const ready = new Promise((resolve, reject) => {
    worker.once("error", reject);
    worker.on("message", (message) => {
      if (message.ready) resolve(message.capabilities);
      else if (message.id !== undefined) {
        const waiter = pending.get(message.id);
        pending.delete(message.id);
        if (message.ok) waiter.resolve(message.value);
        else waiter.reject(new StoreError(message.code));
      }
    });
  });
  const capabilities = await ready;
  const call = (method, args) =>
    new Promise((resolve, reject) => {
      const id = next++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, method, args });
    });
  const handler = {
    get(_target, property) {
      if (property === "capabilities") return () => capabilities;
      return (...args) => call(String(property), args);
    },
  };
  return {
    store: new Proxy({}, handler),
    /** Blocks this thread until the worker finishes a call, or `ms` pass: lets a held transaction give a competing one time. */
    waitForCall(ms, before) {
      Atomics.wait(done, 0, before, ms);
    },
    callsDone: () => Atomics.load(done, 0),
    async close() {
      await new Promise((resolve) => {
        worker.once("message", (message) => message.closed && resolve());
        worker.postMessage({ close: true });
      });
      await worker.terminate();
    },
  };
}

/**
 * The factory the conformance harness calls once per case. The primary store is
 * in this thread, the second connection in a worker thread, so the competing
 * call of an interleaved schedule really waits for the primary's write lock.
 */
export function makeFactory({ controlledClock }) {
  return async function factory() {
    const database = await freshDatabase();
    const options = { filename: database.filename, busyTimeoutMs: BUSY_MS, maxClockSkewMs: controlledClock ? 2000 : 30_000 };
    let clock = null;
    let nowSql;
    let control;
    let now = 1_800_000_000_000;
    if (controlledClock) {
      // A test-owned clock row, in the same database file, read by both stores inside their transactions.
      control = new Database(database.filename);
      control.pragma("busy_timeout = 30000");
      control.exec("CREATE TABLE rsv_test_clock (id INTEGER PRIMARY KEY, now_ms INTEGER NOT NULL)");
      control.prepare("INSERT INTO rsv_test_clock (id, now_ms) VALUES (1, ?)").run(now);
      const write = () => control.prepare("UPDATE rsv_test_clock SET now_ms = ? WHERE id = 1").run(now);
      clock = {
        now: () => now,
        advance(ms) {
          now += ms;
          write();
        },
        set(ms) {
          now = ms;
          write();
        },
      };
      nowSql = "(SELECT now_ms FROM rsv_test_clock WHERE id = 1)";
    }
    let beforeCommit;
    const store = await openSqliteStore(options, {
      ...(nowSql === undefined ? {} : { nowSql }),
      beforeCommit: () => beforeCommit?.(),
    });
    const second = await remoteStore(options, nowSql);
    return {
      store,
      clock,
      secondStore: second.store,
      async interleave({ primary, concurrent }) {
        let competing;
        beforeCommit = () => {
          beforeCommit = undefined;
          const before = second.callsDone();
          competing = concurrent(second.store);
          // The primary transaction holds the write lock. Give the competing call time to either finish
          // or to block on that lock, then let the primary commit.
          second.waitForCall(400, before);
        };
        try {
          return await primary();
        } finally {
          beforeCommit = undefined;
          if (competing !== undefined) await competing;
        }
      },
      async dispose() {
        await second.close();
        store.close();
        control?.close();
        database.cleanup();
      },
    };
  };
}

/** Reads the database with SQL on a connection of its own, as an operator would. */
export function sql(filename, text, ...params) {
  const db = new Database(filename, { readonly: true });
  try {
    db.pragma("busy_timeout = 30000");
    return db.prepare(text).all(...params);
  } finally {
    db.close();
  }
}
