// Process kill around commit. A process is killed with SIGKILL at a chosen
// point of a transaction, and a new process opens the same file.
//
// This is application-crash evidence only. It is NOT a power-loss simulation:
// a killed process leaves the operating system's page cache intact, so the file
// contents the next process sees say nothing about what survives when the
// device loses power. Power-loss behavior was not run (see
// docs/research/qualification-store-sqlite-0.1.0-alpha.1.md).
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import {
  initialized,
  openStore,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  rawCommit,
  spawnWorker,
  wire,
} from "../support/fixtures.mjs";
import { freshDatabase, sql } from "./helpers.mjs";

describe("process kill around commit", () => {
  let database;
  let namespace;
  const workers = new Set();

  before(async () => {
    database = await freshDatabase();
    namespace = randomNamespace("kill");
    const store = await openStore(database.filename);
    await initialized(store, namespace, 1);
    store.close();
  });

  after(async () => {
    for (const started of workers) await started.kill("SIGKILL");
    database?.cleanup();
  });

  const doomed = async (hook) => {
    const started = await spawnWorker({ filename: database.filename, hook });
    workers.add(started);
    return started;
  };

  /** Sends one armed store call to a worker that kills itself inside it, and waits for the death. */
  const dieDuring = async (started, method, input) => {
    started.send("store", { method, input: wire(input), arm: true });
    const exit = await started.exit;
    assert.equal(exit.signal, "SIGKILL");
  };

  const integrity = () => sql(database.filename, "PRAGMA integrity_check")[0].integrity_check;

  test("killed before COMMIT of a creation: nothing was created, and the identifiers can be used again", async () => {
    const input = rawCapture({ namespace, entries: 3 });
    await dieDuring(await doomed("before-commit"), "createCapture", input);
    assert.equal(integrity(), "ok");
    assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
    assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_entry WHERE capture_id = ?", input.capture.captureId)[0].n, 0);
    const store = await openStore(database.filename);
    try {
      assert.equal((await store.createCapture(input)).outcome, "created");
    } finally {
      store.close();
    }
  });

  test("killed after COMMIT of a creation, before the reply: the capture exists whole", async () => {
    const input = rawCapture({ namespace, entries: 3 });
    await dieDuring(await doomed("after-commit"), "createCapture", input);
    assert.equal(integrity(), "ok");
    assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_capture WHERE capture_id = ?", input.capture.captureId)[0].n, 1);
    assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_entry WHERE capture_id = ?", input.capture.captureId)[0].n, 3);
    const store = await openStore(database.filename);
    try {
      assert.deepEqual(await store.createCapture(input).then((result) => [result.outcome, result.reason]), ["rejected", "exists"]);
    } finally {
      store.close();
    }
  });

  test("killed before COMMIT of a restore: no use was spent, no receipt exists, the attempt is absent and can run again", async () => {
    const store = await openStore(database.filename);
    try {
      const input = rawCapture({ namespace, entries: 2, maxUses: 1 });
      assert.equal((await store.createCapture(input)).outcome, "created");
      const commit = await rawCommit(store, input);
      await dieDuring(await doomed("before-commit"), "commitRestore", commit);
      assert.equal(integrity(), "ok");
      assert.deepEqual(sql(database.filename, "SELECT used FROM rsv_entry WHERE capture_id = ?", input.capture.captureId).map((row) => row.used), [0, 0]);
      assert.equal(sql(database.filename, "SELECT count(*) AS n FROM rsv_receipt WHERE attempt_id = ?", commit.attempt.attemptId)[0].n, 0);
      assert.equal((await store.inspectAttempt({ scope: commit.scope, attemptId: commit.attempt.attemptId })).state, "absent");
      assert.equal((await store.commitRestore(commit)).outcome, "committed", "the same attempt commits once the first one is known not to have");
    } finally {
      store.close();
    }
  });

  test("killed after COMMIT of a restore, before the reply: the use is spent and the receipt resolves the attempt", async () => {
    const store = await openStore(database.filename);
    try {
      const input = rawCapture({ namespace, entries: 2, maxUses: 1 });
      assert.equal((await store.createCapture(input)).outcome, "created");
      const commit = await rawCommit(store, input);
      await dieDuring(await doomed("after-commit"), "commitRestore", commit);
      assert.equal(integrity(), "ok");
      assert.deepEqual(sql(database.filename, "SELECT used FROM rsv_entry WHERE capture_id = ?", input.capture.captureId).map((row) => row.used), [1, 1]);
      const inspected = await store.inspectAttempt({ scope: commit.scope, attemptId: commit.attempt.attemptId });
      assert.equal(inspected.state, "committed");
      assert.deepEqual([...inspected.requestDigest], [...commit.attempt.requestDigest]);
      assert.equal((await store.commitRestore(commit)).outcome, "already-committed");
      // A new attempt cannot spend the use again.
      const fresh = await rawCommit(store, input, { attemptId: randomAttemptId() });
      assert.deepEqual(await store.commitRestore(fresh).then((result) => [result.outcome, result.reason]), ["rejected", "budget"]);
    } finally {
      store.close();
    }
  });

  test("a revoke killed before COMMIT is not applied; killed after COMMIT it is", async () => {
    const store = await openStore(database.filename);
    try {
      const input = rawCapture({ namespace, entries: 1, maxUses: 3 });
      assert.equal((await store.createCapture(input)).outcome, "created");
      const revoke = { scope: input.scope, captureId: input.capture.captureId, now: Date.now(), retentionMs: 60_000, fenceAbsent: false };
      await dieDuring(await doomed("before-commit"), "revokeCapture", revoke);
      assert.equal((await store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] }))[0].state, "live");
      await dieDuring(await doomed("after-commit"), "revokeCapture", revoke);
      assert.equal((await store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] }))[0].state, "revoked");
      assert.equal(integrity(), "ok");
    } finally {
      store.close();
    }
  });

  test("a process killed at random moments while committing in a loop leaves every restore whole: used and receipt agree, and the file is intact", async () => {
    const store = await openStore(database.filename);
    const input = rawCapture({ namespace, entries: 40, maxUses: 1 });
    assert.equal((await store.createCapture(input)).outcome, "created");
    const attempts = [];
    for (const [index, entry] of input.entries.entries()) attempts.push({ entry, attemptId: `loop-${index}-${randomAttemptId()}` });
    const commits = [];
    for (const { entry, attemptId } of attempts) commits.push(await rawCommit(store, input, { attemptId, entries: [entry] }));
    store.close();
    for (let round = 0; round < 5; round += 1) {
      const started = await spawnWorker({ filename: database.filename });
      workers.add(started);
      for (const commit of commits) started.send("store", { method: "commitRestore", input: wire(commit) });
      // Kill at a different moment each round, while commits are in flight.
      await new Promise((resolve) => setTimeout(resolve, 5 + round * 11));
      await started.kill("SIGKILL");
      assert.equal(integrity(), "ok");
      if (process.env.RSVQ_VERBOSE) console.log("round", round, "receipts", sql(database.filename, "SELECT count(*) AS n FROM rsv_receipt WHERE attempt_id LIKE 'loop-%'")[0].n);
    }
    const spent = new Map(sql(database.filename, "SELECT entry_id, used FROM rsv_entry WHERE capture_id = ?", input.capture.captureId).map((row) => [row.entry_id, row.used]));
    const receipts = new Set(sql(database.filename, "SELECT attempt_id FROM rsv_receipt WHERE attempt_id LIKE 'loop-%'").map((row) => row.attempt_id));
    for (const { entry, attemptId } of attempts) {
      // The two are one transaction: a spent use without its receipt, or a receipt without its use, would be a torn commit.
      assert.equal(spent.get(entry.entryId) === 1, receipts.has(attemptId), `entry ${entry.entryId.slice(0, 8)}`);
    }
    // And a new process finishes the job: every attempt ends committed exactly once.
    const finisher = await openStore(database.filename);
    try {
      for (const commit of commits) {
        const result = await finisher.commitRestore(commit);
        assert.ok(["committed", "already-committed"].includes(result.outcome), result.outcome);
      }
      assert.ok(sql(database.filename, "SELECT used FROM rsv_entry WHERE capture_id = ?", input.capture.captureId).every((row) => row.used === 1));
    } finally {
      finisher.close();
    }
  });
});
