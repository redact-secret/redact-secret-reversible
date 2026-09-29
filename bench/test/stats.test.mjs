import assert from "node:assert/strict";
import { test } from "node:test";

import { mulberry32 } from "../lib/rng.mjs";
import { bootstrapRatio, median, medianInPlace, quantile, summarize } from "../lib/stats.mjs";
import { sample, samplePaired } from "../lib/timing.mjs";

test("quantile interpolates linearly (type 7)", () => {
  assert.equal(quantile([1, 2, 3, 4], 0.5), 2.5);
  assert.equal(quantile([4, 1, 3, 2], 0), 1);
  assert.equal(quantile([4, 1, 3, 2], 1), 4);
  assert.equal(quantile([10], 0.99), 10);
  assert.ok(Math.abs(quantile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95) - 9.55) < 1e-12);
  assert.throws(() => quantile([], 0.5), RangeError);
});

test("summarize reports n, ordered percentiles, and extremes", () => {
  const values = Array.from({ length: 100 }, (_, i) => 100 - i);
  const s = summarize(values);
  assert.equal(s.n, 100);
  assert.equal(s.min, 1);
  assert.equal(s.max, 100);
  assert.equal(s.p50, 50.5);
  assert.ok(s.p50 <= s.p95 && s.p95 <= s.p99);
  assert.equal(s.mean, 50.5);
  assert.throws(() => summarize([]), RangeError);
  assert.throws(() => summarize([1, Number.NaN]), TypeError);
});

test("medianInPlace matches median for odd, even, and tied samples", () => {
  const random = mulberry32(7);
  for (const n of [1, 2, 3, 10, 11, 101, 1000]) {
    const values = Array.from({ length: n }, () => Math.round(random() * 20) / 4);
    assert.equal(medianInPlace(Float64Array.from(values)), median(values), `n=${n}`);
  }
  assert.throws(() => medianInPlace(new Float64Array(0)), RangeError);
});

test("mulberry32 is deterministic per seed", () => {
  const a = mulberry32(42);
  const b = mulberry32(42);
  const c = mulberry32(43);
  const xs = [a(), a(), a()];
  assert.deepEqual(xs, [b(), b(), b()]);
  assert.notDeepEqual(xs, [c(), c(), c()]);
  assert.ok(xs.every((x) => x >= 0 && x < 1));
});

function noisy(seed, center, n) {
  const random = mulberry32(seed);
  return Array.from({ length: n }, () => center * (0.9 + 0.2 * random()));
}

test("bootstrapRatio: equal distributions give a CI containing 1", () => {
  const rounds = 8;
  const cand = Array.from({ length: rounds }, (_, r) => noisy(100 + r, 10, 40));
  const base = Array.from({ length: rounds }, (_, r) => noisy(200 + r, 10, 40));
  const r = bootstrapRatio(cand, base, { resamples: 500 });
  assert.ok(r.lo <= 1 && r.hi >= 1, `CI [${r.lo}, ${r.hi}] should contain 1`);
  assert.equal(r.level, 0.95);
});

test("bootstrapRatio: a 25% slowdown gives a CI above 1.10", () => {
  const rounds = 8;
  const cand = Array.from({ length: rounds }, (_, r) => noisy(300 + r, 12.5, 40));
  const base = Array.from({ length: rounds }, (_, r) => noisy(400 + r, 10, 40));
  const r = bootstrapRatio(cand, base, { resamples: 500 });
  assert.ok(Math.abs(r.ratio - 1.25) < 0.05, `ratio ${r.ratio}`);
  assert.ok(r.lo > 1.1, `lo ${r.lo}`);
  assert.ok(r.lo <= r.ratio && r.ratio <= r.hi);
});

test("bootstrapRatio is reproducible for a seed, accepts one flat round, and rejects mismatched rounds", () => {
  const cand = noisy(1, 5, 30);
  const base = noisy(2, 5, 30);
  assert.deepEqual(bootstrapRatio(cand, base, { resamples: 200 }), bootstrapRatio(cand, base, { resamples: 200 }));
  assert.throws(() => bootstrapRatio([[1], [2]], [[1]]), RangeError);
  const zero = bootstrapRatio([1, 2], [0, 0], { resamples: 50 });
  assert.equal(zero.ratio, null);
  assert.equal(zero.lo, null);
  assert.equal(median([3, 1, 2]), 2);
});

test("sample runs warmup untimed, then a fixed number of timed iterations", async () => {
  let calls = 0;
  let setups = 0;
  let teardowns = 0;
  const samples = await sample({
    warmup: 3,
    iterations: 7,
    setup: () => {
      setups += 1;
      return { n: setups };
    },
    op: (state) => {
      assert.equal(typeof state.n, "number");
      calls += 1;
    },
    teardown: () => {
      teardowns += 1;
    },
  });
  assert.equal(samples.length, 7);
  assert.equal(calls, 10);
  assert.equal(setups, 10);
  assert.equal(teardowns, 10);
  assert.ok(samples.every((ms) => ms >= 0));
  await assert.rejects(sample({ op: () => {}, iterations: 0 }), TypeError);
});

test("sample awaits async operations inside the timed region", async () => {
  const [ms] = await sample({ iterations: 1, op: () => new Promise((resolve) => setTimeout(resolve, 20)) });
  assert.ok(ms >= 15, `expected >= 15ms, got ${ms}`);
});

test("samplePaired alternates order and reports b - a", async () => {
  const order = [];
  const out = await samplePaired({
    iterations: 4,
    a: () => order.push("a"),
    b: () => order.push("b"),
  });
  assert.deepEqual(order, ["a", "b", "b", "a", "a", "b", "b", "a"]);
  assert.equal(out.diff.length, 4);
  out.diff.forEach((d, i) => {
    assert.equal(d, out.b[i] - out.a[i]);
  });
});
