import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";
import { DISPOSE_UNRECLAIMED_MAX, medianOf, SIZES, summarizeCycles } from "../metrics/entry-memory.mjs";

test("medianOf handles odd and even counts", () => {
  assert.equal(medianOf([3, 1, 2]), 2);
  assert.equal(medianOf([4, 1, 3, 2]), 2.5);
});

test("summarizeCycles reports medians and the unreclaimed share", () => {
  const cycles = [
    { growth: 1000, retainedBytes: 50, remaining: 10 },
    { growth: 1200, retainedBytes: 50, remaining: 900 },
    { growth: 1100, retainedBytes: 50, remaining: 11 },
  ];
  const s = summarizeCycles(cycles, 10);
  assert.equal(s.bytesPerEntry, 110);
  assert.equal(s.perRetainedByte, 22);
  assert.equal(s.unreclaimed, 0.01);
  // A vault that keeps its fill after dispose reads close to 1.
  const leaking = summarizeCycles([{ growth: 1000, retainedBytes: 50, remaining: 990 }], 10);
  assert.ok(leaking.unreclaimed > DISPOSE_UNRECLAIMED_MAX);
  assert.throws(() => summarizeCycles([{ growth: 0, retainedBytes: 50, remaining: 0 }], 10));
  assert.throws(() => summarizeCycles([{ growth: 10, retainedBytes: 0, remaining: 0 }], 10));
});

test("entry-memory reports heap per entry and reclaim without leaking values", async () => {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const corpus = loadCorpus();
  const settings = { iterations: 1, warmup: 0 };
  const [metric] = await discoverMetrics({ only: ["entry-memory"] });
  assert.equal(metric.issue, 80);
  assert.deepEqual(metric.piiModes, ["off"]);

  const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings, quick: true }));
  assert.equal(outcome.status, "ok", outcome.reason);
  const byName = Object.fromEntries(outcome.raw.map((m) => [m.name, m]));
  for (const size of SIZES) {
    const perEntry = byName[`heap.bytes_per_entry.at-${size}`];
    assert.equal(perEntry.kind, "deterministic");
    assert.equal(perEntry.params.entries, size);
    // Each entry holds at least its 20-byte value, and far less than 64 KiB.
    assert.ok(perEntry.value > 20 && perEntry.value < 65_536, String(perEntry.value));
    for (const path of ["revoke", "dispose"]) {
      const m = byName[`heap.unreclaimed_ratio.${path}.at-${size}`];
      assert.ok(Number.isFinite(m.value));
    }
  }
  const gated = byName["heap.unreclaimed_ratio.dispose.at-10000"];
  assert.deepEqual(gated.threshold, { max: DISPOSE_UNRECLAIMED_MAX });
  assert.equal(gated.gating, undefined);
  assert.ok(gated.value <= DISPOSE_UNRECLAIMED_MAX, String(gated.value));
  assert.equal(byName["heap.unreclaimed_ratio.dispose.at-256"].gating, false);

  const result = newResult({
    kind: "run",
    piiMode: "off",
    quick: true,
    settings,
    corpus,
    environment: captureEnvironment(),
    sides: [describeSide(side)],
  });
  result.metrics.push({
    id: metric.id,
    issue: metric.issue,
    title: metric.title,
    status: "ok",
    measurements: outcome.raw.map((raw) => toResultMeasurement(raw, side.label)),
  });
  const out = join(mkdtempSync(join(tmpdir(), "bench-entry-memory-")), "result.json");
  await writeResult(result, out);
  const text = readFileSync(out, "utf8");
  for (const value of SENSITIVE_VALUES) assert.ok(!text.includes(value));
  assert.ok(!/SYNTHETIC|rsv_/.test(text));
});
