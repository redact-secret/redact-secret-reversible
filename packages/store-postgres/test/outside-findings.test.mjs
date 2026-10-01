// Findings outside this package, demonstrated against the real store.
//
// Server behaviour first observed while qualifying this adapter, pinned here
// against the real store.
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

  // The server refuses, at creation, a capture lifetime and receipt grace that
  // together pass the store's 48-hour receipt horizon (§4.2).
  test("vault-server: a 24 h capture lifetime with a 24 h receipt grace is refused at creation", async () => {
    const outcome = await settle(openVault({ pool, namespace, keys: syntheticKeys(), vaultOptions: { limits: { entryTtlMs: 24 * HOUR, vaultTtlMs: 24 * HOUR }, receiptGraceMs: 24 * HOUR } }));
    assert.deepEqual([outcome.ok, outcome.code], [false, "INVALID_ARGUMENT"]);
  });

  // Specification §7.3: a replayed attempt is denied with no fields. For an entry the
  // attempt itself exhausted, the preflight denies `budget` before the commit is reached.
  test("vault-server: replaying a committed attempt on a single-use entry is denied `budget`, not `attempt-already-committed`", async () => {
    const { vault } = await openVault({ pool, namespace, keys: syntheticKeys() });
    const { text } = captureText(1, 60_002);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses: 1 });
    const request = restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [captured.tokens[0].token], attemptId: randomAttemptId() });
    assert.equal((await settle(vault.restore(request))).ok, true);
    const replay = await settle(vault.restore(request));
    assert.deepEqual([replay.ok, replay.code, replay.reason], [false, "RESTORE_DENIED", "budget"]);
    assert.equal((await vault.resolveAttempt(request)).state, "committed", "the attempt can still be resolved");
    evidence("outside", "vault-server/replay-reason-single-use", { replay: replay.reason, resolveAttempt: "committed", specification: "§7.2 step 4, §7.3" });
  });

});
