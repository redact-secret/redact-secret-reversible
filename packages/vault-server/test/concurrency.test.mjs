// Coordinating concurrent restore/revoke, generalizing F4's linearization
// contract (docs/decisions/2026-09-27-define-restore-transaction-boundary.md)
// to this package's necessarily-async operations: every capture/restore/
// revoke/dispose on one ServerVault is queued onto a single FIFO chain, so
// exactly one is ever in flight and each fully commits or denies before the
// next begins.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultServerError } from "../dist/index.js";
import { captureOne, deferred, openServer } from "./helpers.mjs";

test("a revoke queued before a restore call denies it (\"revoked\"), matching the vault's own pre-restore-revoke contract", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server);

  // Deliberately not awaited between these two calls: revoke() is enqueued
  // first purely because it is *called* first, and the queue is FIFO.
  const revokePromise = server.revoke(captured.captureId);
  const restorePromise = server.restore({
    context: {},
    sink: "sink-a",
    purpose: "p",
    captures: [captured.captureId],
    fields: { body: captured.text },
  });

  assert.equal(await revokePromise, 1);
  await assert.rejects(restorePromise, (error) => {
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.reason, "revoked");
    return true;
  });
});

test("a restore holding the queue on a slow policy delays a concurrently-issued revoke until it settles", async () => {
  const gate = deferred();
  const events = [];
  const { server } = await openServer({
    policy: async (input) => {
      events.push(`policy:${input.path}`);
      await gate.promise;
      return { allow: true };
    },
  });
  const captured = await captureOne(server, { maxUses: 1 });

  const restorePromise = server
    .restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } })
    .then((r) => {
      events.push("restore:committed");
      return r;
    });
  const revokePromise = server.revoke(captured.captureId).then((n) => {
    events.push(`revoke:${n}`);
    return n;
  });

  // Give both calls a full macrotask turn (several microtask hops deep,
  // through the queue's own .then() chain and withTimeout's Promise.race);
  // only the policy call (inside restore, which got the queue first) should
  // have run so far — revoke is still queued behind it.
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(events, ["policy:body"]);

  gate.resolve();
  await restorePromise;
  await revokePromise;

  // The restore consumed the single-use token before revoke got its turn,
  // so revoke correctly finds nothing left to remove — no interleaving, no
  // partial state, no double-release.
  assert.deepEqual(events, ["policy:body", "restore:committed", "revoke:0"]);
});

test("two concurrent restores racing the same single-use token: the first-enqueued call wins deterministically, the second is denied", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server, { maxUses: 1 });
  const request = () =>
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } });

  const first = request();
  const second = request();

  const firstResult = await first;
  assert.match(firstResult.fields.body, /ghp_SYNTHETIC/);
  await assert.rejects(second, (error) => {
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.reason, "unknown-token");
    return true;
  });
});

test("capture, restore, and revoke calls fired concurrently on one instance all complete without corrupting stats()", async () => {
  const { server } = await openServer();
  const captures = await Promise.all(
    Array.from({ length: 5 }, (_, i) =>
      captureOne(server, { text: `secret number ${i} is ghp_SYNTHETICxREVOKEDxTESTx555555555555${i}`, maxUses: 1 }),
    ),
  );

  const results = await Promise.allSettled([
    ...captures.map((c) =>
      server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [c.captureId], fields: { body: c.text } }),
    ),
    server.revoke(captures[0].captureId), // races the first restore
  ]);

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  assert.ok(fulfilled.length >= 4, "every non-conflicting operation must still complete");

  const stats = await server.stats();
  assert.equal(stats.disposed, false);
  assert.ok(Number.isInteger(stats.entries));
  assert.ok(Number.isInteger(stats.captures));
});

test("a call that arrives after dispose() is queued but fails DISPOSED, never silently ignored", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server);
  const disposePromise = server.dispose();
  const restorePromise = server.restore({
    context: {},
    sink: "sink-a",
    purpose: "p",
    captures: [captured.captureId],
    fields: { body: captured.text },
  });
  await disposePromise;
  await assert.rejects(restorePromise, (error) => {
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.code, "DISPOSED");
    return true;
  });
});
