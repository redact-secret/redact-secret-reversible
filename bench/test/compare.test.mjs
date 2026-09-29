import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { compareMetric } from "../compare.mjs";
import { loadCorpus } from "../corpus/v1/index.mjs";
import { aggregateRounds, compareMeasurement, deterministicVerdict, latencyVerdict, WARN_RATIO } from "../lib/compare.mjs";
import { discoverMetrics } from "../lib/harness.mjs";
import { assertExactVersion } from "../lib/published.mjs";
import { mulberry32 } from "../lib/rng.mjs";
import { activateSide, loadWorkspaceSide } from "../lib/sides.mjs";

const FIXTURES = fileURLToPath(new URL("./fixtures/metrics/", import.meta.url));

test("regression rule: warn only when ratio > 1.10 and the CI excludes 1.0", () => {
  assert.equal(WARN_RATIO, 1.1);
  assert.equal(latencyVerdict({ ratio: 1.2, lo: 1.05, hi: 1.3 }), "warn");
  assert.equal(latencyVerdict({ ratio: 1.2, lo: 0.99, hi: 1.4 }), "ok");
  assert.equal(latencyVerdict({ ratio: 1.08, lo: 1.02, hi: 1.12 }), "ok");
  assert.equal(latencyVerdict({ ratio: 0.8, lo: 0.7, hi: 0.9 }), "improved");
  assert.equal(latencyVerdict({ ratio: null, lo: null, hi: null }), "inconclusive");
});

test("deterministic measurements fail on their threshold (the B8 hook)", () => {
  assert.deepEqual(deterministicVerdict(105, 100, { maxRatio: 1.05 }).verdict, "ok");
  assert.deepEqual(deterministicVerdict(106, 100, { maxRatio: 1.05 }).verdict, "fail");
  assert.deepEqual(deterministicVerdict(90, 100, { max: 80 }).verdict, "fail");
  assert.deepEqual(deterministicVerdict(90, 100, undefined).verdict, "ok");
  assert.match(deterministicVerdict(90, 100, undefined).rule, /informational/);
});

function rounds(center, seed) {
  const random = mulberry32(seed);
  return Array.from({ length: 6 }, () => ({
    name: "op",
    kind: "latency",
    unit: "ms",
    samples: Array.from({ length: 30 }, () => center * (0.95 + 0.1 * random())),
  }));
}

test("compareMeasurement flags a 30% latency regression and passes gating through", () => {
  const warn = compareMeasurement({
    metric: "m",
    name: "op",
    rounds: { candidate: rounds(1.3, 1), baseline: rounds(1, 2) },
    labels: { candidate: "candidate", baseline: "baseline" },
    seed: 1,
  });
  assert.equal(warn.verdict, "warn");
  assert.equal(warn.gating, true);
  assert.ok(warn.ci.lo > 1);

  const informational = rounds(1.3, 3).map((m) => ({ ...m, gating: false }));
  const c = compareMeasurement({
    metric: "m",
    name: "op",
    rounds: { candidate: informational, baseline: rounds(1, 4) },
    labels: { candidate: "candidate", baseline: "baseline" },
    seed: 1,
  });
  assert.equal(c.gating, false);
});

test("deterministic values are the median of every round, not round 0", () => {
  const det = (value) => ({ name: "size", kind: "deterministic", unit: "bytes", value, threshold: { maxRatio: 1.1 } });
  // Round 0 alone would read 5.0 and fail; the median of the rounds is 1.01.
  const c = compareMeasurement({
    metric: "m",
    name: "size",
    rounds: { candidate: [500, 101, 99, 101].map(det), baseline: [100, 100, 100, 100].map(det) },
    labels: { candidate: "candidate", baseline: "baseline" },
    seed: 1,
  });
  assert.equal(c.ratio, 1.01);
  assert.equal(c.verdict, "ok");
  assert.deepEqual([c.ci.lo, c.ci.hi], [1.01, 1.01]);
  assert.equal(aggregateRounds([det(3), det(1), det(2)]).value, 2);
  assert.deepEqual(aggregateRounds([det(3), det(1)]).threshold, { maxRatio: 1.1 });
  const lat = (samples) => ({ name: "op", kind: "latency", unit: "ms", samples });
  assert.deepEqual(aggregateRounds([lat([1, 2]), lat([3])]).samples, [1, 2, 3]);
});

test("baseline versions must be exact", () => {
  assert.equal(assertExactVersion("0.1.0-alpha.3", "v"), "0.1.0-alpha.3");
  for (const bad of ["^0.1.0", "latest", "0.1", "0.1.0 || 0.2.0", "alpha", "", undefined]) {
    assert.throws(() => assertExactVersion(bad, "v"), /exact version/);
  }
});

test("compareMetric interleaves rounds and reports both sides and a ratio per measurement", async () => {
  const candidate = await activateSide(await loadWorkspaceSide({ label: "candidate" }), "off");
  // The same packages under the baseline label: an A/A run, no network.
  const baseline = { ...candidate, label: "baseline" };
  const [metric] = await discoverMetrics({ dir: FIXTURES, only: ["fixture-roundtrip"] });
  const { entry, comparisons } = await compareMetric(metric, {
    sides: [candidate, baseline],
    corpus: loadCorpus(),
    piiMode: "off",
    settings: { iterations: 5, warmup: 1 },
    quick: true,
    rounds: 3,
  });
  assert.equal(entry.status, "ok");
  assert.deepEqual(
    entry.measurements.map((m) => [m.side, m.n]),
    [
      ["candidate", 15],
      ["baseline", 15],
    ],
  );
  assert.equal(comparisons.length, 1);
  assert.equal(comparisons[0].measurement, "roundtrip");
  assert.ok(comparisons[0].ratio > 0);
});

test("compareMetric runs a metric no more rounds than its compareRounds", async () => {
  const candidate = await activateSide(await loadWorkspaceSide({ label: "candidate" }), "off");
  const baseline = { ...candidate, label: "baseline" };
  const [fixture] = await discoverMetrics({ dir: FIXTURES, only: ["fixture-roundtrip"] });
  const tiers = [];
  const metric = {
    ...fixture,
    compareRounds: 2,
    run: (ctx) => {
      tiers.push(ctx.tier);
      return fixture.run(ctx);
    },
  };
  const { entry } = await compareMetric(metric, {
    sides: [candidate, baseline],
    corpus: loadCorpus(),
    piiMode: "off",
    settings: { iterations: 5, warmup: 1 },
    quick: true,
    rounds: 5,
  });
  assert.equal(entry.status, "ok");
  assert.equal(entry.rounds, 2);
  assert.deepEqual(
    entry.measurements.map((m) => m.n),
    [10, 10],
  );
  assert.deepEqual(tiers, ["standard", "standard", "standard", "standard"]);
});
