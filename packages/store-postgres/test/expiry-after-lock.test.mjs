// Expiry is judged after the row locks are held, not at transaction start
// (docs/specs/persistent-vault.md §5.5, §7.5; implementation review A4).
import assert from "node:assert/strict";
import { test } from "node:test";

import { createPostgresStore } from "../dist/index.js";
import { appPool, prepare, randomNamespace, SCHEMA, SKIP } from "./helpers.mjs";

test("a commit that waits for a row lock past the capture's expiry is rejected expired and consumes nothing", { skip: SKIP }, async () => {
  await prepare();
  const pool = appPool(4);
  try {
    const store = await createPostgresStore({ pool, schema: SCHEMA, lockTimeoutMs: 10_000 });
    const namespace = randomNamespace("expiry");
    assert.equal((await store.initializeNamespace({ namespace, epoch: 1 })).outcome, "initialized");
    const scope = { namespace, tenant: "tenant-acme-synthetic" };
    const captureId = "cap_cccccccccccccccccccccccccc";
    const entryId = "e".repeat(64);
    const now = Date.now();
    const expiresAt = now + 1500;
    const created = await store.createCapture({
      scope,
      epoch: 1,
      now,
      capture: { captureId, sessionTag: null, createdAt: now, expiresAt, lookupVersion: 1, keyRef: "local:synthetic", wrappedKey: new Uint8Array([1]) },
      entries: [{ entryId, maxUses: 1, envelope: new Uint8Array([7]) }],
    });
    assert.equal(created.outcome, "created");

    // Another session holds the entry row until after the capture has expired.
    const blocker = await pool.connect();
    await blocker.query("BEGIN");
    await blocker.query(`SELECT 1 FROM "${SCHEMA}".rsv_entry WHERE namespace = $1 AND entry_id = $2 FOR UPDATE`, [namespace, entryId]);
    const release = new Promise((resolve) => setTimeout(resolve, 2500)).then(() => blocker.query("COMMIT")).finally(() => blocker.release());

    const result = await store.commitRestore({
      scope,
      epoch: 1,
      now: Date.now(),
      attempt: { attemptId: "attempt-synthetic-expiry", requestDigest: new Uint8Array(32) },
      receiptExpiresAt: expiresAt + 60_000,
      captures: [{ captureId, generation: 1 }],
      uses: [{ entryId, captureId, count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }],
    });
    await release;
    assert.ok(Date.now() >= expiresAt, "the commit returned after the capture's expiry");
    assert.deepEqual(result, { outcome: "rejected", reason: "expired" });
    const row = await pool.query(`SELECT used FROM "${SCHEMA}".rsv_entry WHERE namespace = $1 AND entry_id = $2`, [namespace, entryId]);
    assert.equal(row.rows[0].used, 0);
    assert.equal((await store.inspectAttempt({ scope, attemptId: "attempt-synthetic-expiry" })).state, "absent");
  } finally {
    await pool.end();
  }
});
