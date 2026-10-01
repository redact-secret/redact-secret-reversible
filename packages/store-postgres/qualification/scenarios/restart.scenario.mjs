// Scenario C: database restart and crash recovery on a single primary.
//
// One `postgres:17` container with the image's default durability settings,
// which are queried and recorded. The server is restarted cleanly
// (`docker restart`) and killed (`docker kill`, SIGKILL, then `docker start`:
// crash recovery) between capture and restore and immediately after
// acknowledged commits.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { createPostgresStore } from "../../dist/index.js";
import { createTopology, docker, dockerUnavailable } from "../lib/docker.mjs";
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
  randomCaptureId,
  randomNamespace,
  rawCapture,
  receiptCount,
  RELEASE,
  restoreRequest,
  rows,
  SCHEMA,
  settle,
  syntheticKeys,
} from "../lib/harness.mjs";

const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };

describe("C. database restart and crash recovery", { skip: dockerUnavailable() }, () => {
  let topology;
  let node;
  let admin;
  let pool;
  let vault;
  let store;
  let namespace;
  let offset = 20_000;

  const capture = async (maxUses = 1) => {
    const { text, values } = captureText(1, offset++);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses });
    return { captureId: captured.captureId, tokens: captured.tokens.map((token) => token.token), values };
  };
  const request = (captured) => restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: captured.tokens, attemptId: randomAttemptId() });

  /** The same pool across a restart: a call that meets a dead connection is STORE_UNAVAILABLE, had no effect, and is repeated. */
  const eventually = async (call) => {
    let unavailable = 0;
    for (;;) {
      const outcome = await settle(call());
      if (outcome.ok || outcome.code !== "STORE_UNAVAILABLE") return { outcome, unavailable };
      unavailable += 1;
      assert.ok(unavailable < 50, "the store never came back");
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  };

  before(async () => {
    topology = createTopology("c");
    node = await topology.primary("pg", port(10));
    await prepareDatabase(node);
    admin = openPool(node.adminUrl, 4);
    pool = openPool(node.appUrl, 10);
    namespace = randomNamespace("restart");
    await initializeNamespace(pool, namespace, 1);
    ({ vault, store } = await openVault({ pool, namespace, keys: syntheticKeys() }));
  });

  after(async () => {
    await pool?.end().catch(() => undefined);
    await admin?.end().catch(() => undefined);
    await topology?.cleanup();
  });

  test("the durability settings in effect are the qualified ones", async () => {
    const settings = Object.fromEntries(
      (await rows(admin, "SELECT name, setting FROM pg_settings WHERE name = ANY($1::text[]) ORDER BY name", [["fsync", "synchronous_commit", "full_page_writes", "wal_sync_method", "wal_level", "synchronous_standby_names"]])).map((row) => [row.name, row.setting]),
    );
    assert.equal(settings.fsync, "on");
    assert.equal(settings.synchronous_commit, "on");
    assert.equal(settings.full_page_writes, "on");
    assert.equal(settings.synchronous_standby_names, "");
    assert.equal(store.capabilities().profile, "postgres-single-primary/synchronous_commit=on");
    const [{ version }] = await rows(admin, "SELECT version()");
    evidence("C", "settings", { settings, profile: store.capabilities().profile, server: version });
  });

  test("docker restart between capture and restore: the capture is still restorable, once", async () => {
    const captured = await capture();
    await docker(["restart", node.name]);
    await topology.waitReady(node);
    const { outcome, unavailable } = await eventually(() => vault.restore(request(captured)));
    assert.equal(outcome.ok, true, `${outcome.code}:${outcome.reason}`);
    assert.ok(outcome.value.fields.body.includes(captured.values[0]));
    const again = await settle(vault.restore(request(captured)));
    assert.deepEqual([again.code, again.reason], ["RESTORE_DENIED", "budget"]);
    assert.deepEqual(await store.recoveryState({ namespace }), { epoch: 1, state: "serving" }, "a restart is not a restore: the namespace keeps serving");
    evidence("C", "restart-between-capture-and-restore", { method: "docker restart", restored: true, unavailableCallsBeforeReconnect: unavailable });
  });

  for (const [method, stop] of [
    ["docker kill (SIGKILL), then start: crash recovery", (name) => docker(["kill", name])],
    ["docker restart", (name) => docker(["restart", name])],
    ["docker kill (SIGKILL), then start: crash recovery, second round", (name) => docker(["kill", name])],
  ]) {
    test(`${method}, immediately after acknowledged commits: consumption, revocation, receipt, and fence all survive`, async () => {
      const consumed = await capture();
      const revoked = await capture();
      const untouched = await capture();
      const fencedId = randomCaptureId();
      const consuming = request(consumed);
      // Each of these is acknowledged before the server is stopped.
      assert.equal((await settle(vault.restore(consuming))).ok, true);
      assert.equal((await vault.revoke({ context: CONTEXT, captureId: revoked.captureId })).outcome, "revoked");
      const fence = await store.revokeCapture({ scope: { namespace, tenant: CONTEXT.tenant }, captureId: fencedId, now: Date.now(), retentionMs: 60_000, fenceAbsent: true });
      assert.equal(fence.outcome, "fenced");
      const acknowledgedAt = Date.now();
      await stop(node.name);
      const stoppedAfterMs = Date.now() - acknowledgedAt;
      if (method.startsWith("docker kill")) await docker(["start", node.name]);
      await topology.waitReady(node);

      const replay = await eventually(() => vault.restore(request(consumed)));
      assert.deepEqual([replay.outcome.code, replay.outcome.reason], ["RESTORE_DENIED", "budget"], "the consumed use stays consumed");
      assert.equal((await vault.resolveAttempt(consuming)).state, "committed", "the receipt survived");
      const denied = await settle(vault.restore(request(revoked)));
      assert.deepEqual([denied.code, denied.reason], ["RESTORE_DENIED", "revoked"], "the revocation survived");
      const reuse = rawCapture({ namespace, tenant: CONTEXT.tenant });
      reuse.capture.captureId = fencedId;
      assert.deepEqual(await store.createCapture(reuse), { outcome: "rejected", reason: "fenced" }, "the fence survived");
      const intact = await settle(vault.restore(request(untouched)));
      assert.equal(intact.ok, true, "an unconsumed capture survived");

      assert.deepEqual((await captureState(admin, namespace, consumed.captureId)).used, [1]);
      assert.equal((await captureState(admin, namespace, revoked.captureId)).capture.state, "revoked");
      assert.equal((await captureState(admin, namespace, fencedId)).capture.state, "revoked");
      assert.equal(await receiptCount(admin, namespace, consuming.attemptId), 1);
      assert.deepEqual(await store.recoveryState({ namespace }), { epoch: 1, state: "serving" });
      evidence("C", "restart-after-acknowledged-commit", { method, stoppedWithinMsOfAcknowledgement: stoppedAfterMs, consumedStaysConsumed: true, revocationSurvived: true, receiptSurvived: true, fenceSurvived: true });
    });
  }

  test("a store opened while the server is down fails closed, and works once it is back", async () => {
    await docker(["stop", node.name]);
    const down = openPool(node.appUrl, 2, { connectionTimeoutMillis: 2000 });
    try {
      await assert.rejects(createPostgresStore({ pool: down, schema: SCHEMA }), (thrown) => thrown.code === "STORE_UNAVAILABLE");
      await docker(["start", node.name]);
      await topology.waitReady(node);
      const back = await createPostgresStore({ pool: down, schema: SCHEMA });
      assert.deepEqual(await back.recoveryState({ namespace }), { epoch: 1, state: "serving" });
    } finally {
      await down.end().catch(() => undefined);
    }
  });
});
