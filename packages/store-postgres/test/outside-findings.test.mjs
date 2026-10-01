// Findings outside this package, demonstrated against the real store.
//
// These are not defects of @redact-secret/store-postgres and are not fixed
// here. Each has one test that pins down what happens today, and one skipped
// test that states what should happen, with the reason it is skipped.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import {
  captureState,
  captureText,
  evidence,
  initializeNamespace,
  openPool,
  openVault,
  randomAttemptId,
  randomNamespace,
  RELEASE,
  restoreRequest,
  settle,
  syntheticKeys,
} from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, prepare, SKIP } from "./helpers.mjs";

const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };
const HOUR = 60 * 60 * 1000;

describe("findings outside this package", { skip: SKIP }, () => {
  let admin;
  let pool;
  let namespace;

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 2);
    pool = openPool(APP_URL, 6);
    namespace = randomNamespace("outside");
    await initializeNamespace(pool, namespace, 1);
  });

  after(async () => {
    await pool?.end();
    await admin?.end();
  });

  // vault-server accepts `receiptGraceMs` up to 24 hours and `limits.entryTtlMs` up to
  // 24 hours. It sets receiptExpiresAt = capture expiry + skew bound + grace, and the
  // store contract (§4.2) refuses a receipt more than 48 hours past the store clock.
  // A 24-hour capture with a 24-hour grace is therefore past the limit by the skew bound.
  const longLived = () => openVault({ pool, namespace, keys: syntheticKeys(), vaultOptions: { limits: { entryTtlMs: 24 * HOUR, vaultTtlMs: 24 * HOUR }, receiptGraceMs: 24 * HOUR } });

  test("vault-server: a configuration it accepts (24 h captures, 24 h receipt grace) makes every restore fail INVARIANT_VIOLATION; nothing is consumed", async () => {
    const { vault } = await longLived();
    const { text } = captureText(1, 60_000);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE });
    const outcome = await settle(vault.restore(restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [captured.tokens[0].token], attemptId: randomAttemptId() })));
    assert.deepEqual([outcome.ok, outcome.code], [false, "INVARIANT_VIOLATION"]);
    assert.deepEqual((await captureState(admin, namespace, captured.captureId)).used, [0], "it fails closed");
    evidence("outside", "vault-server/receipt-horizon", { configuration: "entryTtlMs=24h, receiptGraceMs=24h", restore: outcome.code, consumed: 0, specification: "§4.2, §7.5" });
  });

  test("vault-server: should refuse that configuration at creation, or cap the receipt lifetime at the store's 48-hour horizon", { skip: "defect in @redact-secret/vault-server (packages/vault-server/src/persistent/server.ts, receiptGraceMs bound); this package may not change it" }, async () => {
    const { vault } = await longLived();
    const { text } = captureText(1, 60_001);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE });
    const outcome = await settle(vault.restore(restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [captured.tokens[0].token], attemptId: randomAttemptId() })));
    assert.equal(outcome.ok, true);
  });

  // Specification §7.3 says the same attempt, submitted again after it committed, is denied
  // `attempt-already-committed`. For a single-use entry the server's preflight (§7.2 step 4)
  // sees the exhausted budget first and denies `budget` before the store is asked about the receipt.
  test("vault-server: replaying a committed attempt on a single-use entry is denied `budget`, not `attempt-already-committed`", async () => {
    const { vault } = await openVault({ pool, namespace, keys: syntheticKeys() });
    const { text } = captureText(1, 60_002);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses: 1 });
    const request = restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [captured.tokens[0].token], attemptId: randomAttemptId() });
    assert.equal((await settle(vault.restore(request))).ok, true);
    const replay = await settle(vault.restore(request));
    assert.deepEqual([replay.ok, replay.code, replay.reason], [false, "RESTORE_DENIED", "budget"]);
    assert.equal((await vault.resolveAttempt(request)).state, "committed", "the attempt can still be resolved");
    evidence("outside", "vault-server/replay-reason-single-use", { replay: replay.reason, specificationSays: "attempt-already-committed", resolveAttempt: "committed", specification: "§7.2 step 4, §7.3" });
  });

  test("vault-server: a replay of a committed attempt should be denied `attempt-already-committed` whatever the budget", { skip: "specification §7.2 and §7.3 disagree for an exhausted entry, and the server follows §7.2; this package may not change either" }, async () => {
    const { vault } = await openVault({ pool, namespace, keys: syntheticKeys() });
    const { text } = captureText(1, 60_003);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses: 1 });
    const request = restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [captured.tokens[0].token], attemptId: randomAttemptId() });
    await vault.restore(request);
    const replay = await settle(vault.restore(request));
    assert.equal(replay.reason, "attempt-already-committed");
  });
});
