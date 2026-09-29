// Revocation memory (#87): which revoked captures are still remembered at a
// given time — reported as "revoked" rather than "unknown-token" and counted
// in stats().revokedCaptures — must not depend on how the tombstone sweep is
// implemented. These pin the window boundary, ordering across many and
// interleaved revocations, and a capture revoked more than once.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultServerError } from "../dist/index.js";
import { captureOne, manualClock, openServer } from "./helpers.mjs";

const MEMORY_MS = 1000;

/** Unmistakably synthetic, one per index; never a real credential. */
function syntheticSecret(i) {
  return `ghp_SYNTHETICxREVOKEDxTESTx${String(i).padStart(13, "0")}`;
}

function capture(server, i) {
  return captureOne(server, { text: `secret ${syntheticSecret(i)} here` });
}

/** The restore outcome for one capture: "restored" or the denial reason. */
async function outcome(server, captured) {
  try {
    await server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } });
    return "restored";
  } catch (error) {
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.code, "RESTORE_DENIED");
    return error.reason;
  }
}

async function remembered(server) {
  return (await server.stats()).revokedCaptures;
}

test("the window is half-open: remembered until revocationMemoryMs has elapsed, forgotten exactly at it", async () => {
  const clock = manualClock();
  const auditEvents = [];
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS, onAudit: (event) => auditEvents.push(event) });
  const captured = await captureOne(server);
  await server.revoke(captured.captureId);

  clock.advance(MEMORY_MS - 1);
  assert.equal(await remembered(server), 1);
  assert.equal(await outcome(server, captured), "revoked");

  clock.advance(1);
  assert.equal(await outcome(server, captured), "unknown-token");
  assert.equal(await remembered(server), 0);

  const denials = auditEvents.filter((event) => event.outcome === "denied").map((event) => event.reason);
  assert.deepEqual(denials, ["revoked", "unknown-token"]);
});

test("a zero revocation memory forgets a revocation immediately", async () => {
  const { server } = await openServer({ revocationMemoryMs: 0 });
  const captured = await captureOne(server);
  assert.equal(await server.revoke(captured.captureId), 1);
  assert.equal(await remembered(server), 0);
  assert.equal(await outcome(server, captured), "unknown-token");
});

test("many staggered revocations age out oldest first, one step at a time", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS });
  const count = 250;
  const step = 10; // MEMORY_MS / step = 100 revocations remembered at steady state
  const revoked = [];
  for (let i = 0; i < count; i += 1) {
    if (i > 0) clock.advance(step);
    const captured = await capture(server, i);
    await server.revoke(captured.captureId);
    revoked.push(captured);
    assert.equal(await remembered(server), Math.min(i + 1, MEMORY_MS / step));
  }
  // The newest remembered revocation is the last one; the oldest is 99 steps back.
  const oldest = count - MEMORY_MS / step;
  assert.equal(await outcome(server, revoked[oldest]), "revoked");
  assert.equal(await outcome(server, revoked[oldest - 1]), "unknown-token");
  assert.equal(await outcome(server, revoked[0]), "unknown-token");

  // Advancing one step at a time forgets exactly one more each time.
  for (let k = 1; k <= 5; k += 1) {
    clock.advance(step);
    assert.equal(await remembered(server), MEMORY_MS / step - k);
    assert.equal(await outcome(server, revoked[oldest + k - 1]), "unknown-token");
    assert.equal(await outcome(server, revoked[oldest + k]), "revoked");
  }

  clock.advance(MEMORY_MS);
  assert.equal(await remembered(server), 0);
  assert.equal(await outcome(server, revoked[count - 1]), "unknown-token");
});

test("revocations with the same timestamp age out together", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS });
  const batch = [];
  for (let i = 0; i < 5; i += 1) {
    const captured = await capture(server, i);
    await server.revoke(captured.captureId);
    batch.push(captured);
  }
  clock.advance(MEMORY_MS - 1);
  assert.equal(await remembered(server), 5);
  clock.advance(1);
  assert.equal(await remembered(server), 0);
  for (const captured of batch) assert.equal(await outcome(server, captured), "unknown-token");
});

test("interleaved captures, restores, and revocations keep each capture's own window", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS });
  const a = await capture(server, 1);
  const b = await capture(server, 2);
  await server.revoke(a.captureId); // t = 0
  clock.advance(400);
  const c = await capture(server, 3);
  await server.revoke(b.captureId); // t = 400
  clock.advance(400);
  const d = await capture(server, 4); // t = 800, still live

  assert.equal(await outcome(server, a), "revoked");
  assert.equal(await outcome(server, b), "revoked");
  assert.equal(await outcome(server, c), "restored");

  clock.advance(200); // t = 1000: a is forgotten, b is not
  assert.equal(await remembered(server), 1);
  assert.equal(await outcome(server, a), "unknown-token");
  assert.equal(await outcome(server, b), "revoked");

  await server.revoke(d.captureId); // t = 1000
  clock.advance(400); // t = 1400: b is forgotten, d is not
  assert.equal(await remembered(server), 1);
  assert.equal(await outcome(server, b), "unknown-token");
  assert.equal(await outcome(server, d), "revoked");

  clock.advance(600); // t = 2000
  assert.equal(await remembered(server), 0);
  assert.equal(await outcome(server, d), "unknown-token");
});

test("revoking a capture again restarts its window without holding back older revocations", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS });
  const a = await capture(server, 1);
  const b = await capture(server, 2);
  await server.revoke(a.captureId); // t = 0
  clock.advance(100);
  await server.revoke(b.captureId); // t = 100
  clock.advance(100);
  assert.equal(await server.revoke(a.captureId), 0); // t = 200: nothing left to remove, window restarts

  clock.advance(950); // t = 1150: b (revoked at 100) is forgotten; a (re-revoked at 200) is not
  assert.equal(await remembered(server), 1);
  assert.equal(await outcome(server, b), "unknown-token");
  assert.equal(await outcome(server, a), "revoked");

  clock.advance(50); // t = 1200
  assert.equal(await remembered(server), 0);
  assert.equal(await outcome(server, a), "unknown-token");
});

test("a repeat revoke before any sweep carries the earlier revocation's tokens into the new window", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS });
  const a = await capture(server, 1);
  await server.revoke(a.captureId); // t = 0
  clock.advance(MEMORY_MS + 500); // aged out, but no call has swept it yet
  await server.revoke(a.captureId); // t = 1500
  assert.equal(await remembered(server), 1);
  assert.equal(await outcome(server, a), "revoked");
  clock.advance(MEMORY_MS);
  assert.equal(await outcome(server, a), "unknown-token");
});

test("revoking a never-issued capture id is remembered and aged out like any other", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: MEMORY_MS });
  const live = await capture(server, 1);
  assert.equal(await server.revoke("cap_synthetic_never_issued"), 0);
  assert.equal(await remembered(server), 1);
  assert.equal(await outcome(server, live), "restored");
  clock.advance(MEMORY_MS);
  assert.equal(await remembered(server), 0);
});
