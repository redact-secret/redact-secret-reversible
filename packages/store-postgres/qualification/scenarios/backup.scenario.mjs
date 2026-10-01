// Scenario E: restore from backup, as a negative control (#20, #111).
//
// A source cluster with WAL archiving. Before a consumption and a revocation:
// a logical dump (`pg_dump -Fc`), a physical base backup (`pg_basebackup`),
// and a named restore point. Afterwards the backups are restored four ways,
// and for each one this file records whether the adapter's tripwire (system
// identifier and timeline) notices, and shows that the runbook
// (docs/specs/persistent-operations.md) protects whether or not it does.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { createPostgresStore } from "../../dist/index.js";
import { createTopology, DATA_DIRECTORY, docker, dockerUnavailable, psql, until } from "../lib/docker.mjs";
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
  RELEASE,
  restoreRequest,
  rows,
  SCHEMA,
  settle,
  syntheticKeys,
} from "../lib/harness.mjs";

const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };
const RESTORE_POINT = "rsvq_before_consumption";
const IDENTITY = `SELECT (SELECT system_identifier::text FROM pg_control_system()) AS sysid,
  ('x' || substr(pg_walfile_name(pg_current_wal_insert_lsn()), 1, 8))::bit(32)::int AS timeline`;

let offset = 40_000;
const capturing = (vault) => async () => {
  const { text, values } = captureText(1, offset++);
  const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE });
  return { captureId: captured.captureId, tokens: captured.tokens.map((token) => token.token), values };
};
const request = (captured) => restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: captured.tokens, attemptId: randomAttemptId() });
const quarantined = (thrown) => thrown.code === "STORE_QUARANTINED";

describe("E. restore from backup", { skip: dockerUnavailable() }, () => {
  let topology;
  let volume;
  let source;
  let namespace;
  let keys;
  let recorded;
  const captures = {};
  const pools = [];
  const matrix = [];
  const pool = (url, max = 6) => {
    const opened = openPool(url, max);
    pools.push(opened);
    return opened;
  };

  /** Identity of a restored database compared with what the namespace record holds, and what the adapter then reports. */
  const observe = async (method, appUrl) => {
    const app = pool(appUrl);
    const [identity] = await rows(app, IDENTITY);
    const store = await createPostgresStore({ pool: app, schema: SCHEMA });
    const state = await store.recoveryState({ namespace });
    const row = {
      method,
      systemIdentifierChanged: identity.sysid !== recorded.system_identifier,
      timelineChanged: identity.timeline !== recorded.timeline_id,
      detected: state.state === "quarantined",
    };
    matrix.push(row);
    return { app, store, state, row };
  };

  /** The runbook after step 1 (servers stopped): quarantine, raise the epoch, invalidate, restart with the new epoch. */
  const runbook = async ({ app, store }, names) => {
    assert.deepEqual(await store.quarantine({ namespace }), { epoch: 1, state: "quarantined" });
    await assert.rejects(openVault({ pool: app, namespace, keys, epoch: 1 }), quarantined);
    assert.deepEqual(await store.invalidateRecovered({ namespace, newEpoch: 2 }), { outcome: "invalidated", recovery: { epoch: 2, state: "serving" } });
    await assert.rejects(openVault({ pool: app, namespace, keys, epoch: 1 }), quarantined, "a server left on the old epoch is refused");
    const { vault } = await openVault({ pool: app, namespace, keys, epoch: 2 });
    const reasons = {};
    for (const name of names) {
      const outcome = await settle(vault.restore(request(captures[name])));
      assert.deepEqual([outcome.ok, outcome.code, outcome.reason], [false, "RESTORE_DENIED", "revoked"], name);
      reasons[name] = outcome.reason;
    }
    const fresh = await capturing(vault)();
    assert.equal((await settle(vault.restore(request(fresh)))).ok, true, "new captures work under the new epoch");
    return { vault, reasons };
  };

  before(async () => {
    topology = createTopology("e");
    volume = await topology.sharedVolume("share");
    source = await topology.primary("source", port(30), {
      mounts: [`${volume}:/share`],
      settings: { archive_mode: "on", archive_command: "test ! -f /share/archive/%f && cp %p /share/archive/%f" },
    });
    await prepareDatabase(source);
    namespace = randomNamespace("backup");
    keys = syntheticKeys();
  });

  after(async () => {
    for (const opened of pools) await opened.end().catch(() => undefined);
    await topology?.cleanup();
  });

  test("backups are taken before a consumption and a revocation", async () => {
    const admin = pool(source.adminUrl, 2);
    const app = pool(source.appUrl);
    await initializeNamespace(app, namespace, 1);
    const { vault } = await openVault({ pool: app, namespace, keys });
    const capture = capturing(vault);
    captures.consumedAfter = await capture();
    captures.revokedAfter = await capture();
    captures.untouched = await capture();
    captures.consumedBefore = await capture();
    assert.equal((await settle(vault.restore(request(captures.consumedBefore)))).ok, true);
    [recorded] = await rows(admin, `SELECT system_identifier, timeline_id::int AS timeline_id FROM "${SCHEMA}".rsv_namespace WHERE namespace = $1`, [namespace]);

    // Physical base backup, then one more capture, then the point to recover to.
    await docker(["exec", "-u", "postgres", source.name, "pg_basebackup", "-D", "/share/base", "-X", "stream", "-c", "fast"]);
    captures.afterBaseBackup = await capture();
    await admin.query("SELECT pg_create_restore_point($1)", [RESTORE_POINT]);
    // Logical dump at the same point.
    await docker(["exec", "-u", "postgres", source.name, "pg_dump", "-Fc", "-d", "rsv", "-f", "/share/rsv.dump"]);

    // After every backup: a consumption and a revocation the source acknowledges.
    captures.attempt = request(captures.consumedAfter);
    assert.equal((await settle(vault.restore(captures.attempt))).ok, true);
    assert.equal((await vault.revoke({ context: CONTEXT, captureId: captures.revokedAfter.captureId })).outcome, "revoked");
    captures.afterBackups = await capture();
    const [{ segment }] = await rows(admin, "SELECT pg_walfile_name(pg_current_wal_lsn()) AS segment");
    await admin.query("SELECT pg_switch_wal()");
    await until(async () => (await rows(admin, "SELECT last_archived_wal >= $1 AS done FROM pg_stat_archiver", [segment]))[0].done === true, { what: "the WAL up to the restore point to be archived" });

    // The source itself is correct: this is the state a restore must not undo.
    const consumed = await settle(vault.restore(request(captures.consumedAfter)));
    assert.deepEqual([consumed.code, consumed.reason], ["RESTORE_DENIED", "budget"]);
    const revoked = await settle(vault.restore(request(captures.revokedAfter)));
    assert.deepEqual([revoked.code, revoked.reason], ["RESTORE_DENIED", "revoked"]);
    const settings = Object.fromEntries((await rows(admin, "SELECT name, setting FROM pg_settings WHERE name = ANY($1::text[])", [["archive_mode", "wal_level", "fsync", "synchronous_commit"]])).map((row) => [row.name, row.setting]));
    evidence("E", "backups-taken", { logical: "pg_dump -Fc", physical: "pg_basebackup -X stream", restorePoint: RESTORE_POINT, settings, afterBackups: ["consumption", "revocation"] });
  });

  test("pg_dump restored into a fresh cluster: detected (system identifier), and the runbook invalidates every recovered capture", async () => {
    const fresh = await topology.primary("fresh", port(31), { mounts: [`${volume}:/share`] });
    await docker(["exec", "-u", "postgres", fresh.name, "pg_restore", "-d", "rsv", "/share/rsv.dump"]);
    const observed = await observe("pg_dump restored into a fresh cluster (initdb)", fresh.appUrl);
    assert.deepEqual(observed.row, { method: observed.row.method, systemIdentifierChanged: true, timelineChanged: false, detected: true });
    // Without any operator action: quarantined, whatever epoch a server is configured with.
    assert.deepEqual(observed.state, { epoch: 1, state: "quarantined" });
    await assert.rejects(openVault({ pool: observed.app, namespace, keys, epoch: 1 }), quarantined);
    await assert.rejects(openVault({ pool: observed.app, namespace, keys, epoch: 2 }), quarantined);
    const admin = pool(fresh.adminUrl, 2);
    assert.deepEqual((await captureState(admin, namespace, captures.consumedAfter.captureId)).used, [0], "the restored rows are those of the backup: authentic and stale");
    assert.equal((await captureState(admin, namespace, captures.revokedAfter.captureId)).capture.state, "live");
    const { vault, reasons } = await runbook(observed, ["consumedAfter", "revokedAfter", "untouched", "consumedBefore", "afterBaseBackup"]);
    const absent = await settle(vault.restore(request(captures.afterBackups)));
    assert.deepEqual([absent.code, absent.reason], ["RESTORE_DENIED", "unknown-token"], "a capture made after the backup is not in it");
    evidence("E", "logical-into-fresh-cluster", { ...observed.row, withoutOperatorAction: "quarantined", afterInvalidateRecovered: reasons });
  });

  test("pg_dump restored into the SAME cluster: NOT detected; an old-epoch server serves stale state, and only the raised epoch and the runbook protect", async () => {
    await docker(["exec", "-u", "postgres", source.name, "createdb", "rsv_restored"]);
    await docker(["exec", "-u", "postgres", source.name, "pg_restore", "-d", "rsv_restored", "/share/rsv.dump"]);
    const restoredUrl = source.appUrl.replace(/\/rsv$/, "/rsv_restored");
    const observed = await observe("pg_dump restored into the same cluster (another database, or the same one)", restoredUrl);
    assert.deepEqual(observed.row, { method: observed.row.method, systemIdentifierChanged: false, timelineChanged: false, detected: false });
    assert.deepEqual(observed.state, { epoch: 1, state: "serving" }, "the tripwire has nothing to see: same cluster, same timeline");

    // A server configured with the raised epoch refuses the restored database.
    await assert.rejects(openVault({ pool: observed.app, namespace, keys, epoch: 2 }), quarantined);
    // A server still running with the OLD epoch serves the stale rows. This is why the runbook starts by stopping servers.
    const { vault: stale } = await openVault({ pool: observed.app, namespace, keys, epoch: 1 });
    const again = await settle(stale.restore(request(captures.consumedAfter)));
    assert.equal(again.ok, true, "the consumed single-use value is released a second time");
    assert.ok(again.value.fields.body.includes(captures.consumedAfter.values[0]));
    const unrevoked = await settle(stale.restore(request(captures.revokedAfter)));
    assert.equal(unrevoked.ok, true, "the revoked capture is restorable");
    assert.equal((await stale.resolveAttempt(captures.attempt)).state, "absent", "the receipt of the original restore is not in the backup");
    const stillSpent = await settle(stale.restore(request(captures.consumedBefore)));
    assert.deepEqual([stillSpent.code, stillSpent.reason], ["RESTORE_DENIED", "budget"], "what was consumed before the backup stays consumed");

    const { reasons, vault } = await runbook(observed, ["consumedAfter", "revokedAfter", "untouched", "consumedBefore", "afterBaseBackup"]);
    // The stale server instance, still on epoch 1, is now refused on every operation.
    const refused = await settle(stale.restore(request(captures.untouched)));
    assert.equal(refused.code, "STORE_QUARANTINED");
    const refusedCapture = await settle(stale.capture(captureText(1, offset++).text, { context: CONTEXT, release: RELEASE }));
    assert.equal(refusedCapture.code, "STORE_QUARANTINED");

    // The same dump restored again over the invalidated database brings back epoch 1.
    // The configured epoch lives outside the database, so servers on epoch 2 refuse it.
    await docker(["exec", "-u", "postgres", source.name, "pg_restore", "--clean", "--if-exists", "-d", "rsv_restored", "/share/rsv.dump"]);
    assert.deepEqual(await observed.store.recoveryState({ namespace }), { epoch: 1, state: "serving" });
    await assert.rejects(openVault({ pool: observed.app, namespace, keys, epoch: 2 }), quarantined);
    const rolledBack = await settle(vault.restore(request(captures.untouched)));
    assert.equal(rolledBack.code, "STORE_QUARANTINED", "a running epoch-2 server refuses the rolled-back epoch record");
    evidence("E", "logical-into-same-cluster", {
      ...observed.row,
      withoutOperatorAction: "serving",
      raisedEpochServer: "STORE_QUARANTINED",
      oldEpochServerServedStale: { consumedTokenReleasedAgain: true, revokedCaptureRestored: true },
      afterInvalidateRecovered: reasons,
      dumpRestoredAgainOverInvalidatedDatabase: { databaseEpoch: 1, epoch2Server: "STORE_QUARANTINED" },
    });
  });

  test("base backup with point-in-time recovery to before the consumption: detected (timeline), and the runbook invalidates every recovered capture", async () => {
    const prepare = [
      `cp -a /share/base ${DATA_DIRECTORY}`,
      `chmod 700 ${DATA_DIRECTORY}`,
      `touch ${DATA_DIRECTORY}/recovery.signal`,
      `printf "restore_command = 'cp /share/archive/%%f %%p'\\nrecovery_target_name = '${RESTORE_POINT}'\\nrecovery_target_action = 'promote'\\n" >> ${DATA_DIRECTORY}/postgresql.auto.conf`,
    ].join(" && ");
    const pitr = await topology.fromFiles("pitr", port(32), volume, prepare);
    await until(async () => (await psql(pitr.name, "SELECT pg_is_in_recovery()")) === "f", { what: "point-in-time recovery to finish" });
    const observed = await observe("pg_basebackup + WAL archive, recovery_target_name, promote (PITR)", pitr.appUrl);
    assert.deepEqual(observed.row, { method: observed.row.method, systemIdentifierChanged: false, timelineChanged: true, detected: true });
    assert.deepEqual(observed.state, { epoch: 1, state: "quarantined" });
    await assert.rejects(openVault({ pool: observed.app, namespace, keys, epoch: 1 }), quarantined);
    const admin = pool(pitr.adminUrl, 2);
    assert.deepEqual((await captureState(admin, namespace, captures.consumedAfter.captureId)).used, [0], "recovered to before the consumption");
    assert.equal((await captureState(admin, namespace, captures.afterBaseBackup.captureId)).capture.state, "live", "WAL after the base backup was replayed up to the restore point");
    assert.equal((await captureState(admin, namespace, captures.afterBackups.captureId)).capture, undefined);
    const { reasons } = await runbook(observed, ["consumedAfter", "revokedAfter", "untouched", "consumedBefore", "afterBaseBackup"]);
    evidence("E", "physical-pitr", { ...observed.row, withoutOperatorAction: "quarantined", afterInvalidateRecovered: reasons });
  });

  test("base backup started as a plain copy, without recovery configuration: NOT detected; the raised epoch and the runbook protect", async () => {
    const plain = await topology.fromFiles("plain", port(33), volume, `cp -a /share/base ${DATA_DIRECTORY} && chmod 700 ${DATA_DIRECTORY}`);
    await until(async () => (await psql(plain.name, "SELECT pg_is_in_recovery()")) === "f", { what: "the copied cluster to start" });
    const observed = await observe("pg_basebackup copy (or a file-system snapshot) started without recovery.signal", plain.appUrl);
    assert.deepEqual(observed.row, { method: observed.row.method, systemIdentifierChanged: false, timelineChanged: false, detected: false });
    assert.deepEqual(observed.state, { epoch: 1, state: "serving" });
    await assert.rejects(openVault({ pool: observed.app, namespace, keys, epoch: 2 }), quarantined);
    const { vault: stale } = await openVault({ pool: observed.app, namespace, keys, epoch: 1 });
    const again = await settle(stale.restore(request(captures.consumedAfter)));
    assert.equal(again.ok, true, "an old-epoch server serves the stale copy");
    const { reasons } = await runbook(observed, ["consumedAfter", "revokedAfter", "untouched", "consumedBefore"]);
    evidence("E", "physical-plain-copy", { ...observed.row, withoutOperatorAction: "serving", raisedEpochServer: "STORE_QUARANTINED", oldEpochServerServedStale: true, afterInvalidateRecovered: reasons });
  });

  test("the restore-detection matrix", () => {
    assert.equal(matrix.length, 4);
    assert.deepEqual(matrix.map((row) => row.detected), [true, false, true, false]);
    evidence("E", "restore-detection-matrix", { rows: matrix });
  });
});
