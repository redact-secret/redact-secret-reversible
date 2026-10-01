// Scenario D: failover.
//
// Supported profile: a primary and ONE synchronous streaming standby
// (`synchronous_standby_names = 'FIRST 1 (sync)'`, `synchronous_commit = on`),
// two `postgres:17` containers on a Docker network, the standby built with
// `pg_basebackup`. The primary is hard-killed and the standby promoted.
//
// Negative control: the same with an ASYNCHRONOUS standby that was stopped
// before commits the primary acknowledged, then promoted.
//
// Why `on` and not `remote_apply`: `on` makes COMMIT wait until the standby
// has flushed the commit record to its disk, which is what failover needs. A
// promoted standby replays everything it has flushed before it accepts
// writes. `remote_apply` additionally waits for replay, which only matters to
// readers of the standby, and this adapter never reads one.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import { createPostgresStore } from "../../dist/index.js";
import { createTopology, docker, dockerUnavailable, psql, sleep, until } from "../lib/docker.mjs";
import { hookPool } from "../lib/fault.mjs";
import {
  captureState,
  captureText,
  evidence,
  initializeNamespace,
  openPool,
  openVault,
  port,
  prepareDatabase,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  rawCommit,
  receiptCount,
  RELEASE,
  restoreRequest,
  rows,
  SCHEMA,
  settle,
  syntheticKeys,
} from "../lib/harness.mjs";

const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };
const LAG_WAIT_MS = Number(process.env.RSVQ_TIMELINE_LAG_WAIT_MS ?? 330_000);
const IDENTITY = `SELECT pg_is_in_recovery() AS standby,
  (SELECT system_identifier::text FROM pg_control_system()) AS sysid,
  (SELECT timeline_id FROM pg_control_checkpoint()) AS control_timeline,
  CASE WHEN pg_is_in_recovery() THEN NULL ELSE ('x' || substr(pg_walfile_name(pg_current_wal_insert_lsn()), 1, 8))::bit(32)::int END AS insert_timeline`;

let offset = 30_000;
const capturing = (vault) => async (maxUses = 1) => {
  const { text, values } = captureText(1, offset++);
  const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses });
  return { captureId: captured.captureId, tokens: captured.tokens.map((token) => token.token), values };
};
const request = (captured) => restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: captured.tokens, attemptId: randomAttemptId() });
const isStoreError = (code) => (thrown) => thrown instanceof StoreError && thrown.code === code;

/** Many dirty buffers, so the checkpoint PostgreSQL starts at promotion is spread over minutes, as on a busy server. */
async function dirtyBuffers(node) {
  await psql(node.name, "CREATE TABLE IF NOT EXISTS rsvq_filler AS SELECT g, repeat('x', 500) AS pad FROM generate_series(1, 200000) g");
  await psql(node.name, "UPDATE rsvq_filler SET pad = repeat('y', 500)");
}

describe("D. failover", { skip: dockerUnavailable() }, () => {
  // Both topologies stay up until the end: the promoted synchronous standby is
  // watched while the negative control runs.
  const topologies = [];
  let lag;

  after(async () => {
    for (const topology of topologies) await topology.cleanup();
  });

  describe("supported profile: primary with one synchronous standby", () => {
    let topology;
    let primary;
    let standby;
    let admin;
    let pool;
    let standbyPool;
    let namespace;
    let keys;
    const captures = {};

    before(async () => {
      topology = createTopology("d");
      topologies.push(topology);
      primary = await topology.primary("primary", port(20), { networked: true });
      await prepareDatabase(primary);
      standby = await topology.standby("sync", port(21), primary);
      admin = openPool(primary.adminUrl, 4);
      pool = openPool(primary.appUrl, 10);
      standbyPool = openPool(standby.appUrl, 10);
      namespace = randomNamespace("failover");
      keys = syntheticKeys();
    });

    after(async () => {
      await pool?.end().catch(() => undefined);
      await standbyPool?.end().catch(() => undefined);
      await admin?.end().catch(() => undefined);
    });

    test("requireSynchronousStandby refuses a primary without a synchronous standby, and starts once one is configured", async () => {
      await assert.rejects(createPostgresStore({ pool, schema: SCHEMA, requireSynchronousStandby: true }), isStoreError("STORE_CAPABILITY"));
      await assert.rejects(createPostgresStore({ pool, schema: SCHEMA, synchronousCommit: "remote_apply" }), isStoreError("STORE_CAPABILITY"));
      await psql(primary.name, `ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (${standby.applicationName})'`);
      await psql(primary.name, "SELECT pg_reload_conf()");
      await until(async () => (await psql(primary.name, "SELECT sync_state FROM pg_stat_replication")) === "sync", { what: "the standby to become synchronous" });
      const store = await createPostgresStore({ pool, schema: SCHEMA, requireSynchronousStandby: true });
      assert.equal(store.capabilities().profile, "postgres-primary-with-synchronous-standby/synchronous_commit=on");
      const applying = await createPostgresStore({ pool, schema: SCHEMA, synchronousCommit: "remote_apply" });
      assert.equal(applying.capabilities().profile, "postgres-primary-with-synchronous-standby/synchronous_commit=remote_apply");
      await initializeNamespace(pool, namespace, 1);
      const settings = Object.fromEntries(
        (await rows(admin, "SELECT name, setting FROM pg_settings WHERE name = ANY($1::text[]) ORDER BY name", [["fsync", "synchronous_commit", "synchronous_standby_names", "wal_level", "full_page_writes"]])).map((row) => [row.name, row.setting]),
      );
      const [replication] = await rows(admin, "SELECT application_name, state, sync_state FROM pg_stat_replication");
      assert.equal(settings.fsync, "on");
      assert.equal(settings.synchronous_commit, "on");
      assert.deepEqual(replication, { application_name: standby.applicationName, state: "streaming", sync_state: "sync" });
      evidence("D", "sync/settings", { settings, replication, profile: store.capabilities().profile, standbys: 1, synchronousCommitChosen: "on" });
    });

    test("a store pointed at the standby refuses to serve: STORE_CAPABILITY at creation, STORE_UNAVAILABLE per transaction", async () => {
      await assert.rejects(createPostgresStore({ pool: standbyPool, schema: SCHEMA }), isStoreError("STORE_CAPABILITY"));
      // A store opened on the primary whose pool later hands out connections to the standby.
      let target = pool;
      const routed = { connect: () => target.connect() };
      const store = await createPostgresStore({ pool: routed, schema: SCHEMA });
      const created = rawCapture({ namespace });
      assert.equal((await store.createCapture(created)).outcome, "created");
      const commit = await rawCommit(store, created);
      await until(async () => (await rows(standbyPool, `SELECT 1 FROM "${SCHEMA}".rsv_capture WHERE capture_id = $1`, [created.capture.captureId])).length === 1, { what: "the standby to replay the capture" });
      target = standbyPool;
      const calls = {
        recoveryState: () => store.recoveryState({ namespace }),
        readEntries: () => store.readEntries({ scope: created.scope, entryIds: [created.entries[0].entryId] }),
        inspectAttempt: () => store.inspectAttempt({ scope: created.scope, attemptId: commit.attempt.attemptId }),
        commitRestore: () => store.commitRestore(commit),
        createCapture: () => store.createCapture(rawCapture({ namespace })),
        revokeCapture: () => store.revokeCapture({ scope: created.scope, captureId: created.capture.captureId, now: Date.now(), retentionMs: 0, fenceAbsent: false }),
      };
      for (const [name, call] of Object.entries(calls)) await assert.rejects(call(), isStoreError("STORE_UNAVAILABLE"), name);
      target = pool;
      assert.equal((await store.commitRestore(commit)).outcome, "committed", "back on the primary the same call commits");
      evidence("D", "sync/standby-refuses-to-serve", { atCreation: "STORE_CAPABILITY", perTransaction: "STORE_UNAVAILABLE", operations: Object.keys(calls) });
    });

    test("a commit is not acknowledged while the synchronous standby is down, even from a session whose default is synchronous_commit=off", async () => {
      const weak = openPool(primary.appUrl, 2);
      weak.on("connect", (client) => {
        client.query("SET synchronous_commit = off").catch(() => undefined);
      });
      const hooked = hookPool(weak);
      let pid;
      hooked.set({
        before: ({ text, client, state }) => {
          if (text === "COMMIT" && state.writing) pid = client.processID;
        },
      });
      try {
        const store = await createPostgresStore({ pool: hooked, schema: SCHEMA, statementTimeoutMs: 1000 });
        const created = rawCapture({ namespace });
        assert.equal((await store.createCapture(created)).outcome, "created");
        await docker(["stop", standby.name]);
        const commit = await rawCommit(store, created);
        pid = undefined;
        const committing = store.commitRestore(commit).then(
          (value) => ({ value }),
          (thrown) => ({ thrown }),
        );
        // Longer than the adapter's statement timeout: that timeout does not end the wait.
        assert.equal(await Promise.race([committing, sleep(4000).then(() => "waiting")]), "waiting", "the commit was acknowledged without the synchronous standby");
        const [activity] = await rows(admin, "SELECT wait_event FROM pg_stat_activity WHERE pid = $1", [pid]);
        assert.equal(activity.wait_event, "SyncRep");
        // An operator cancels the waiting backend. PostgreSQL then completes the COMMIT with a
        // warning: the transaction is committed locally and may not be on the standby.
        await admin.query("SELECT pg_cancel_backend($1)", [pid]);
        const outcome = await committing;
        assert.ok(outcome.thrown instanceof StoreError, `the adapter reported ${JSON.stringify(outcome.value)} for a commit the standby never confirmed`);
        assert.equal(outcome.thrown.code, "STORE_AMBIGUOUS");
        assert.deepEqual((await captureState(admin, namespace, created.capture.captureId)).used, [1], "it is committed on the primary");
        evidence("D", "sync/commit-waits-for-standby", { waitedMs: 4000, waitEvent: activity.wait_event, sessionDefault: "synchronous_commit=off", statementTimeoutMs: 1000, afterOperatorCancel: "STORE_AMBIGUOUS" });
      } finally {
        await docker(["start", standby.name]);
        await topology.waitReady(standby);
        await until(async () => (await psql(primary.name, "SELECT sync_state FROM pg_stat_replication")) === "sync", { what: "the standby to be synchronous again" });
        await weak.end().catch(() => undefined);
      }
    });

    test("a commit acknowledged on the primary is on the standby after the primary is hard-killed and the standby promoted; the namespace reads quarantined at once", async () => {
      const { vault } = await openVault({ pool, namespace, keys, storeOptions: { requireSynchronousStandby: true } });
      const capture = capturing(vault);
      captures.consumed = await capture();
      captures.revoked = await capture();
      captures.untouched = await capture();
      await dirtyBuffers(primary);
      const [recorded] = await rows(admin, `SELECT system_identifier, timeline_id::int AS timeline_id FROM "${SCHEMA}".rsv_namespace WHERE namespace = $1`, [namespace]);
      captures.attempt = request(captures.consumed);
      assert.equal((await settle(vault.restore(captures.attempt))).ok, true);
      assert.equal((await vault.revoke({ context: CONTEXT, captureId: captures.revoked.captureId })).outcome, "revoked");
      const acknowledgedAt = Date.now();
      await docker(["kill", primary.name]);
      const killedAfterMs = Date.now() - acknowledgedAt;
      await psql(standby.name, "SELECT pg_promote(true, 60)");
      const promotedAt = Date.now();

      // The first thing a reconnecting server does: ask for the recovery state.
      const promoted = await createPostgresStore({ pool: standbyPool, schema: SCHEMA });
      const first = await promoted.recoveryState({ namespace });
      const [identity] = await rows(standbyPool, IDENTITY);
      const watch = openPool(standby.appUrl, 1);
      // Keep watching the control file: how long does its checkpoint timeline stay behind?
      lag = (async () => {
        const deadline = promotedAt + LAG_WAIT_MS;
        for (;;) {
          const [now] = await rows(watch, IDENTITY).catch(() => [undefined]);
          const caughtUp = now !== undefined && now.control_timeline === now.insert_timeline;
          if (caughtUp || Date.now() > deadline) {
            await watch.end().catch(() => undefined);
            return { caughtUp, ms: Date.now() - promotedAt };
          }
          await sleep(500);
        }
      })();

      assert.equal(identity.standby, false);
      assert.equal(identity.sysid, recorded.system_identifier, "a promoted standby keeps the system identifier");
      assert.equal(recorded.timeline_id, 1);
      assert.equal(identity.insert_timeline, 2, "promotion starts a new timeline");
      assert.deepEqual(first, { epoch: 1, state: "quarantined" }, "the adapter must notice the promotion on the first call after it");
      await assert.rejects(openVault({ pool: standbyPool, namespace, keys }), (thrown) => thrown.code === "STORE_QUARANTINED");
      const probe = rawCapture({ namespace });
      assert.deepEqual(await promoted.createCapture(probe), { outcome: "rejected", reason: "quarantined" });
      await assert.rejects(createPostgresStore({ pool: standbyPool, schema: SCHEMA, requireSynchronousStandby: true }), isStoreError("STORE_CAPABILITY"), "the promoted node has no synchronous standby of its own yet");

      // The acknowledged commits are on the promoted node, read with SQL before anything is acknowledged.
      const promotedAdmin = openPool(standby.adminUrl, 2);
      try {
        assert.deepEqual((await captureState(promotedAdmin, namespace, captures.consumed.captureId)).used, [1]);
        assert.equal((await captureState(promotedAdmin, namespace, captures.revoked.captureId)).capture.state, "revoked");
        assert.equal(await receiptCount(promotedAdmin, namespace, captures.attempt.attemptId), 1);
      } finally {
        await promotedAdmin.end();
      }
      evidence("D", "sync/promotion", {
        killedWithinMsOfAcknowledgement: killedAfterMs,
        systemIdentifierChanged: false,
        timeline: { recorded: recorded.timeline_id, insertAfterPromotion: identity.insert_timeline, controlFileCheckpointAtFirstCall: identity.control_timeline },
        controlFileLaggedAtFirstCall: identity.control_timeline !== identity.insert_timeline,
        recoveryStateOnFirstCall: first.state,
        acknowledgedCommitsOnPromotedNode: true,
      });
    });

    test("after acknowledgeIdentityChange on the promoted synchronous standby, consumed stays consumed, revoked stays revoked, and untouched captures restore", async () => {
      const promoted = await createPostgresStore({ pool: standbyPool, schema: SCHEMA });
      assert.deepEqual(await promoted.acknowledgeIdentityChange({ namespace }), { epoch: 1, state: "serving" });
      const { vault } = await openVault({ pool: standbyPool, namespace, keys });
      const consumed = await settle(vault.restore(request(captures.consumed)));
      assert.deepEqual([consumed.code, consumed.reason], ["RESTORE_DENIED", "budget"]);
      assert.equal((await vault.resolveAttempt(captures.attempt)).state, "committed");
      const revoked = await settle(vault.restore(request(captures.revoked)));
      assert.deepEqual([revoked.code, revoked.reason], ["RESTORE_DENIED", "revoked"]);
      const untouched = await settle(vault.restore(request(captures.untouched)));
      assert.equal(untouched.ok, true);
      assert.ok(untouched.value.fields.body.includes(captures.untouched.values[0]));
      const fresh = await capturing(vault)();
      assert.equal((await settle(vault.restore(request(fresh)))).ok, true);
      evidence("D", "sync/after-acknowledge", { consumed: consumed.reason, revoked: revoked.reason, untouchedRestored: true, epoch: 1 });
    });
  });

  describe("negative control: an asynchronous standby that missed acknowledged commits is promoted", () => {
    let topology;
    let primary;
    let standby;
    let pool;
    let standbyPool;
    let standbyAdmin;
    let keys;
    const wrong = { namespace: randomNamespace("async-wrong") };
    const runbook = { namespace: randomNamespace("async-runbook") };

    before(async () => {
      topology = createTopology("n");
      topologies.push(topology);
      primary = await topology.primary("primary", port(22), { networked: true });
      await prepareDatabase(primary);
      standby = await topology.standby("async", port(23), primary);
      pool = openPool(primary.appUrl, 10);
      standbyPool = openPool(standby.appUrl, 10);
      standbyAdmin = openPool(standby.adminUrl, 2);
      keys = syntheticKeys();
    });

    after(async () => {
      await pool?.end().catch(() => undefined);
      await standbyPool?.end().catch(() => undefined);
      await standbyAdmin?.end().catch(() => undefined);
    });

    test("the primary acknowledges commits the stopped standby never received; the standby is then promoted", async () => {
      assert.equal(await psql(primary.name, "SELECT sync_state FROM pg_stat_replication"), "async");
      const store = await createPostgresStore({ pool, schema: SCHEMA });
      assert.equal(store.capabilities().profile, "postgres-single-primary/synchronous_commit=on", "an asynchronous standby is invisible to the profile: it is a single primary");
      await assert.rejects(createPostgresStore({ pool, schema: SCHEMA, requireSynchronousStandby: true }), isStoreError("STORE_CAPABILITY"));

      for (const side of [wrong, runbook]) {
        await initializeNamespace(pool, side.namespace, 1);
        ({ vault: side.vault } = await openVault({ pool, namespace: side.namespace, keys }));
        const capture = capturing(side.vault);
        side.consumed = await capture();
        side.revoked = await capture();
        side.untouched = await capture();
      }
      // The standby has everything so far.
      const lsn = await psql(primary.name, "SELECT pg_current_wal_lsn()");
      await until(async () => (await psql(primary.name, `SELECT replay_lsn >= '${lsn}'::pg_lsn FROM pg_stat_replication`)) === "t", { what: "the standby to replay the captures" });
      await docker(["stop", standby.name]);

      for (const side of [wrong, runbook]) {
        side.attempt = request(side.consumed);
        const restored = await settle(side.vault.restore(side.attempt));
        assert.equal(restored.ok, true, "the primary acknowledged the restore and returned the value");
        assert.equal((await side.vault.revoke({ context: CONTEXT, captureId: side.revoked.captureId })).outcome, "revoked");
        assert.equal((await side.vault.resolveAttempt(side.attempt)).state, "committed");
      }
      await docker(["kill", primary.name]);
      await docker(["start", standby.name]);
      await topology.waitReady(standby);
      await psql(standby.name, "SELECT pg_promote(true, 60)");

      // What the promoted node holds: the state from before the acknowledged commits.
      for (const side of [wrong, runbook]) {
        assert.deepEqual((await captureState(standbyAdmin, side.namespace, side.consumed.captureId)).used, [0], "the acknowledged consumption is not on the promoted node");
        assert.equal((await captureState(standbyAdmin, side.namespace, side.revoked.captureId)).capture.state, "live", "the acknowledged revocation is not on the promoted node");
        assert.equal(await receiptCount(standbyAdmin, side.namespace, side.attempt.attemptId), 0);
      }
      const promoted = await createPostgresStore({ pool: standbyPool, schema: SCHEMA });
      assert.deepEqual(await promoted.recoveryState({ namespace: wrong.namespace }), { epoch: 1, state: "quarantined" }, "the tripwire sees the new timeline; it cannot see what was lost");
      await assert.rejects(openVault({ pool: standbyPool, namespace: wrong.namespace, keys }), (thrown) => thrown.code === "STORE_QUARANTINED");
      evidence("D", "async/promotion", { acknowledgedOnPrimary: ["consumption", "revocation", "receipt"], presentOnPromotedStandby: [], recoveryState: "quarantined" });
    });

    test("WRONG: acknowledgeIdentityChange on the stale node makes a consumed token consumable again and a revoked capture usable", async () => {
      const promoted = await createPostgresStore({ pool: standbyPool, schema: SCHEMA });
      assert.deepEqual(await promoted.acknowledgeIdentityChange({ namespace: wrong.namespace }), { epoch: 1, state: "serving" });
      const { vault } = await openVault({ pool: standbyPool, namespace: wrong.namespace, keys });
      assert.equal((await vault.resolveAttempt(wrong.attempt)).state, "absent", "the receipt of a restore that returned its value is gone");
      const again = await settle(vault.restore(request(wrong.consumed)));
      assert.equal(again.ok, true, "this is the failure the runbook exists to prevent");
      assert.ok(again.value.fields.body.includes(wrong.consumed.values[0]), "the single-use value was released a second time");
      const revoked = await settle(vault.restore(request(wrong.revoked)));
      assert.equal(revoked.ok, true, `a capture whose revocation was acknowledged is restorable (${revoked.code}:${revoked.reason})`);
      evidence("D", "async/wrong-acknowledge", { singleUseValueReleasedTwice: true, revokedCaptureRestored: true, receiptOfDeliveredRestore: "absent" });
    });

    test("RUNBOOK: quarantine, raise the epoch, invalidateRecovered: every recovered capture is unusable", async () => {
      const promoted = await createPostgresStore({ pool: standbyPool, schema: SCHEMA });
      assert.deepEqual(await promoted.quarantine({ namespace: runbook.namespace }), { epoch: 1, state: "quarantined" });
      await assert.rejects(openVault({ pool: standbyPool, namespace: runbook.namespace, keys, epoch: 1 }), (thrown) => thrown.code === "STORE_QUARANTINED");
      await assert.rejects(openVault({ pool: standbyPool, namespace: runbook.namespace, keys, epoch: 2 }), (thrown) => thrown.code === "STORE_QUARANTINED");
      assert.deepEqual(await promoted.invalidateRecovered({ namespace: runbook.namespace, newEpoch: 2 }), { outcome: "invalidated", recovery: { epoch: 2, state: "serving" } });
      await assert.rejects(openVault({ pool: standbyPool, namespace: runbook.namespace, keys, epoch: 1 }), (thrown) => thrown.code === "STORE_QUARANTINED", "a server still configured with the old epoch is refused");
      const { vault } = await openVault({ pool: standbyPool, namespace: runbook.namespace, keys, epoch: 2 });
      const reasons = {};
      for (const name of ["consumed", "revoked", "untouched"]) {
        const outcome = await settle(vault.restore(request(runbook[name])));
        assert.deepEqual([outcome.ok, outcome.code, outcome.reason], [false, "RESTORE_DENIED", "revoked"], name);
        reasons[name] = outcome.reason;
      }
      assert.deepEqual((await captureState(standbyAdmin, runbook.namespace, runbook.consumed.captureId)).used, [0], "nothing was consumed on the way");
      const fresh = await capturing(vault)();
      assert.equal((await settle(vault.restore(request(fresh)))).ok, true, "new captures work under the new epoch");
      evidence("D", "async/runbook", { recoveredCaptures: reasons, newEpoch: 2, oldEpochServer: "STORE_QUARANTINED", newCaptures: "ok" });
      evidence("D", "conclusion", {
        text: "Both runs used the same adapter, the same READ COMMITTED transactions with the same row locks, and commits the primary acknowledged. What decided whether an acknowledged consumption survived failover was whether its WAL had reached the promoted node before the acknowledgement: with a synchronous standby it had, with an asynchronous one it had not. Transaction isolation orders concurrent transactions on one node; it says nothing about which commits another node holds.",
      });
    });
  });

  test("measurement: how long pg_control_checkpoint() kept reporting the old timeline after promotion", async () => {
    assert.ok(lag !== undefined, "the promotion test did not run");
    const measured = await lag;
    // Not an assertion about PostgreSQL: a record of why the adapter does not read the timeline from there.
    evidence("D", "sync/control-file-timeline-lag", { ...measured, waitedAtMostMs: LAG_WAIT_MS, source: "pg_control_checkpoint().timeline_id versus the WAL insert timeline" });
    assert.ok(measured.ms >= 0);
  });
});
