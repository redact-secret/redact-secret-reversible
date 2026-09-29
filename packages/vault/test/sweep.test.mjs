// Expiry sweep regression tests (#86). The sweep visits only due captures
// through an expiry-ordered queue instead of copying and walking the whole
// entry map. These tests pin the observable semantics of
// docs/decisions/define-restore-transaction-boundary.md ("Expiry"): expired
// entries are swept at each capture, after every restore (allowed or denied),
// and on stats(); an entry is expired when `at >= expiresAt`.
//
// Runs against the built package (dist/) with the fake core. All values are
// synthetic, revoked-looking GitHub token shapes.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultError } from "../dist/errors.js";
import { ExpiryQueue } from "../dist/expiry-queue.js";
import { openVault } from "../dist/vault.js";
import { createFakeCore } from "./fake-core.mjs";

const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
const TTL = 1000;

/** A distinct synthetic token-shaped value: `ghp_` + 36 alphanumerics. */
function synthetic(i) {
  return `ghp_SYNTHETICxREVOKEDxTESTx${String(i).padStart(13, "0")}`;
}

function inputOf(from, count) {
  const lines = [];
  for (let i = from; i < from + count; i += 1) lines.push(`key ${synthetic(i)} retired`);
  return lines.join("\n");
}

/** A vault on a controllable clock. `clock.fail = true` makes the clock throw. */
async function clockedVault(limits = {}) {
  const fake = createFakeCore({ pii: false });
  await fake.module.initialize();
  const clock = { t: 0, fail: false };
  const audits = [];
  const vault = await openVault(fake.module, {
    limits: { entryTtlMs: TTL, vaultTtlMs: 24 * 60 * 60 * 1000, ...limits },
    now: () => {
      if (clock.fail) throw new Error("clock unavailable");
      return clock.t;
    },
    onAudit: (event) => audits.push(event),
  });
  return { vault, clock, audits };
}

/** stats() without its own sweep: a failing clock leaves the counters as they are. */
function rawStats(vault, clock) {
  clock.fail = true;
  try {
    return vault.stats();
  } finally {
    clock.fail = false;
  }
}

function denied(reason) {
  return (error) => {
    assert.ok(error instanceof VaultError);
    assert.equal(error.code, "RESTORE_DENIED");
    assert.equal(error.reason, reason);
    return true;
  };
}

// --- the queue itself ------------------------------------------------------

test("ExpiryQueue pops in expiry order for out-of-order keys (mixed TTLs)", () => {
  let seed = 7;
  const random = () => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;
    return seed / 2 ** 31;
  };
  const queue = new ExpiryQueue();
  const keys = [];
  for (let i = 0; i < 2000; i += 1) {
    // Mostly increasing (a shared TTL) with arbitrary per-item TTLs mixed in.
    const expiresAt = i % 3 === 0 ? Math.floor(random() * 5000) : i * 2;
    keys.push(expiresAt);
    queue.push({ expiresAt, id: i });
  }
  assert.equal(queue.size, keys.length);
  const popped = [];
  while (queue.size > 0) popped.push(queue.pop().expiresAt);
  assert.deepEqual(popped, [...keys].sort((a, b) => a - b));
  assert.equal(queue.pop(), undefined);
  assert.equal(queue.peek(), undefined);
});

test("ExpiryQueue.retain keeps heap order and clear empties it", () => {
  const queue = new ExpiryQueue();
  for (const expiresAt of [9, 3, 7, 1, 8, 2, 6, 4, 5, 0]) queue.push({ expiresAt });
  queue.retain((item) => item.expiresAt % 2 === 1);
  const popped = [];
  while (queue.size > 0) popped.push(queue.pop().expiresAt);
  assert.deepEqual(popped, [1, 3, 5, 7, 9]);
  queue.push({ expiresAt: 1 });
  queue.clear();
  assert.equal(queue.size, 0);
});

// --- vault semantics -------------------------------------------------------

test("sweep removes exactly the entries with at >= expiresAt, capture by capture", async () => {
  const { vault, clock } = await clockedVault();
  const captures = [];
  for (const [i, t] of [0, 100, 250].entries()) {
    clock.t = t;
    captures.push(vault.capture(inputOf(i * 10, i + 1), { release: RELEASE }));
  }
  assert.deepEqual(captures.map((c) => c.expiresAt), [1000, 1100, 1250]);
  assert.equal(vault.stats().entries, 6);

  clock.t = 999;
  assert.equal(vault.stats().entries, 6, "one millisecond before expiry is still live");
  clock.t = 1000;
  let stats = vault.stats();
  assert.equal(stats.entries, 5, "at == expiresAt is expired");
  assert.equal(stats.captures, 2);
  clock.t = 1249;
  stats = vault.stats();
  assert.equal(stats.entries, 3);
  assert.equal(stats.captures, 1);

  // The survivor is still restorable; the swept ones are unknown.
  const live = vault.restore({ sink: "sink-a", captures: [captures[2].captureId], fields: { body: captures[2].text } });
  assert.equal(live.restored, 3);
  assert.throws(
    () => vault.restore({ sink: "sink-a", captures: [captures[1].captureId], fields: { body: captures[1].text } }),
    denied("unknown-token"),
  );
  stats = vault.stats();
  assert.deepEqual([stats.entries, stats.retainedBytes, stats.captures], [0, 0, 0]);
});

test("expiry is exact for captures revoked, consumed, or partly consumed before they expire", async () => {
  const { vault, clock } = await clockedVault();
  clock.t = 0;
  const revoked = vault.capture(inputOf(0, 2), { release: RELEASE });
  clock.t = 10;
  const consumed = vault.capture(inputOf(10, 2), { release: RELEASE });
  clock.t = 20;
  const partial = vault.capture(inputOf(20, 2), { release: RELEASE, maxUses: 2 });
  clock.t = 30;
  const later = vault.capture(inputOf(30, 1), { release: RELEASE });

  assert.equal(vault.revoke(revoked.captureId), 2);
  vault.restore({ sink: "sink-a", captures: [consumed.captureId], fields: { body: consumed.text } });
  const firstToken = partial.tokens[0].token;
  vault.restore({ sink: "sink-a", captures: [partial.captureId], fields: { body: firstToken } });
  vault.restore({ sink: "sink-a", captures: [partial.captureId], fields: { body: firstToken } });
  let stats = vault.stats();
  assert.deepEqual([stats.entries, stats.captures], [2, 2], "one partial entry and the later capture remain");

  clock.t = 1020;
  stats = vault.stats();
  assert.deepEqual([stats.entries, stats.captures], [1, 1]);
  assert.throws(
    () => vault.restore({ sink: "sink-a", captures: [partial.captureId], fields: { body: partial.tokens[1].token } }),
    denied("unknown-token"),
  );
  clock.t = 1030;
  stats = vault.stats();
  assert.deepEqual([stats.entries, stats.retainedBytes, stats.captures], [0, 0, 0]);
  assert.equal(later.expiresAt, 1030);
});

test("a denied restore sweeps expired entries before returning", async () => {
  const { vault, clock, audits } = await clockedVault();
  clock.t = 0;
  const old = vault.capture(inputOf(0, 3), { release: RELEASE });
  clock.t = 500;
  const fresh = vault.capture(inputOf(10, 1), { release: RELEASE });

  clock.t = 1000;
  // Denied for an unrelated reason (wrong sink) against the fresh capture.
  assert.throws(
    () => vault.restore({ sink: "sink-b", captures: [fresh.captureId], fields: { body: fresh.text } }),
    denied("sink-or-path"),
  );
  let stats = rawStats(vault, clock);
  assert.deepEqual([stats.entries, stats.captures], [1, 1], "the deny swept the expired capture itself");
  assert.equal(audits.at(-1).outcome, "denied");

  // An expired token is denied as expired, and the deny removes it.
  const { vault: v2, clock: c2 } = await clockedVault();
  c2.t = 0;
  const cap = v2.capture(inputOf(0, 2), { release: RELEASE });
  c2.t = TTL;
  assert.throws(
    () => v2.restore({ sink: "sink-a", captures: [cap.captureId], fields: { body: cap.text } }),
    denied("expired"),
  );
  stats = rawStats(v2, c2);
  assert.deepEqual([stats.entries, stats.retainedBytes, stats.captures], [0, 0, 0]);
  assert.equal(old.expiresAt, TTL);
});

test("capture and allowed restore sweep; maxEntries and maxRetainedBytes count only live entries", async () => {
  const { vault, clock } = await clockedVault({ maxEntries: 4 });
  clock.t = 0;
  vault.capture(inputOf(0, 3), { release: RELEASE });
  clock.t = 400;
  const keep = vault.capture(inputOf(10, 1), { release: RELEASE });
  assert.throws(() => vault.capture(inputOf(20, 1), { release: RELEASE }), (e) => e.code === "LIMIT_EXCEEDED");

  // At expiry of the first capture, a capture frees its room first.
  clock.t = 1000;
  const next = vault.capture(inputOf(30, 3), { release: RELEASE });
  let stats = rawStats(vault, clock);
  assert.equal(stats.entries, 4);

  // An allowed restore sweeps what expired in the meantime.
  clock.t = 1400;
  vault.restore({ sink: "sink-a", captures: [next.captureId], fields: { body: next.tokens[0].token } });
  stats = rawStats(vault, clock);
  assert.deepEqual([stats.entries, stats.captures], [2, 1], "keep expired at 1400 and one of next was consumed");
  assert.equal(keep.expiresAt, 1400);
});

test("vault expiry disposes on the first call after it, including stats()", async () => {
  const { vault, clock, audits } = await clockedVault({ vaultTtlMs: 5000 });
  clock.t = 0;
  vault.capture(inputOf(0, 2), { release: RELEASE });
  clock.t = 5000;
  const stats = vault.stats();
  assert.equal(stats.disposed, true);
  assert.equal(stats.entries, 0);
  assert.equal(audits.at(-1).operation, "dispose");
  assert.equal(audits.at(-1).entries, 2);
});

test("large N: many staggered captures expire in order with exact counts", async () => {
  const perCapture = 250;
  const captureCount = 80; // 20 000 entries
  const { vault, clock } = await clockedVault({
    maxEntries: perCapture * captureCount,
    maxRetainedBytes: 64 * 1024 * 1024,
  });
  const captures = [];
  for (let i = 0; i < captureCount; i += 1) {
    clock.t = i * 10;
    captures.push(vault.capture(inputOf(i * perCapture, perCapture), { release: RELEASE }));
  }
  assert.equal(vault.stats().entries, perCapture * captureCount);

  // Revoke every fifth capture so the queue carries stale items.
  let revoked = 0;
  for (let i = 0; i < captureCount; i += 5) {
    vault.revoke(captures[i].captureId);
    revoked += 1;
  }

  const started = performance.now();
  for (let i = 0; i < captureCount; i += 1) {
    clock.t = TTL + i * 10;
    const stats = vault.stats();
    const liveCaptures = captures.filter((_, k) => k > i && k % 5 !== 0).length;
    assert.equal(stats.captures, liveCaptures);
    assert.equal(stats.entries, liveCaptures * perCapture);
  }
  assert.equal(vault.stats().retainedBytes, 0);
  assert.ok(revoked > 0);
  // Generous bound: the old full-map sweep also passes; this guards against
  // a pathological (for example quadratic) regression, not a slope.
  assert.ok(performance.now() - started < 5000, "sweeping 20 000 entries took too long");
});

test("capture-and-revoke churn does not grow the vault's retained state", async () => {
  const { vault, clock } = await clockedVault({ maxEntries: 8 });
  clock.t = 0;
  const hold = vault.capture(inputOf(0, 1), { release: RELEASE });
  for (let i = 0; i < 2000; i += 1) {
    const c = vault.capture(inputOf(10 + i, 1), { release: RELEASE });
    vault.revoke(c.captureId);
  }
  let stats = vault.stats();
  assert.deepEqual([stats.entries, stats.captures], [1, 1]);
  clock.t = TTL;
  stats = vault.stats();
  assert.deepEqual([stats.entries, stats.captures], [0, 0]);
  assert.equal(hold.expiresAt, TTL);
});
