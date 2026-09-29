import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";
import { FILL_CHUNK, fillInput, linearSlope, logLogExponent } from "../metrics/entry-scaling.mjs";

test("linearSlope is the least-squares slope", () => {
  assert.equal(linearSlope([0, 1, 2], [1, 3, 5]), 2);
  assert.ok(Math.abs(linearSlope([256, 10_000, 100_000], [0.05, 0.5, 5]) - 5e-5) < 1e-6);
  assert.throws(() => linearSlope([1], [1]), RangeError);
  assert.throws(() => linearSlope([2, 2], [1, 3]), RangeError);
});

test("logLogExponent uses the two largest sizes", () => {
  // Linear growth plus a fixed cost: the smallest point would pull a full
  // fit below 1; the two largest recover the per-entry exponent.
  const xs = [256, 10_000, 100_000];
  const ys = xs.map((n) => 0.1 + 1e-4 * n);
  const e = logLogExponent(xs, ys);
  assert.ok(e > 0.9 && e < 1, String(e));
  assert.equal(logLogExponent([10, 100], [1, 1]), 0);
  assert.ok(Math.abs(logLogExponent([100, 10], [100, 1]) - 2) < 1e-12);
  assert.equal(logLogExponent([1, 2], [0, 1]), null);
});

test("fill inputs are distinct values the pinned core retains, one finding each", async () => {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const text = fillInput(0, FILL_CHUNK);
  assert.ok(!/rsv_/i.test(text));
  const findings = side.core.scan(text, { limits: { maxInputBytes: 1 << 20, maxFindings: 1024 } });
  assert.equal(findings.length, FILL_CHUNK);
  for (const f of findings) {
    assert.equal(f.type, "aws_access_key_id");
    assert.equal(f.action, "redact");
  }
  const values = new Set(findings.map((f) => text.slice(f.start, f.end)));
  assert.equal(values.size, FILL_CHUNK);
  // Chunks do not repeat values across a 100 000-entry fill.
  assert.notEqual(fillInput(99_999, 1), fillInput(0, 1));
});

test("entry-scaling reports per-size latency and slopes without leaking values", async () => {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const corpus = loadCorpus();
  const settings = { iterations: 12, warmup: 1 };
  const [metric] = await discoverMetrics({ only: ["entry-scaling"] });
  assert.equal(metric.issue, 78);
  assert.deepEqual(metric.piiModes, ["off"]);

  const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings, quick: true }));
  assert.equal(outcome.status, "ok", outcome.reason);
  const byName = Object.fromEntries(outcome.raw.map((m) => [m.name, m]));
  for (const size of [256, 2048]) {
    for (const op of ["capture", "capture.core_ms", "capture.vault_overhead_ms", "restore"]) {
      const m = byName[`${op}.at-${size}`];
      assert.ok(m, `${op}.at-${size}`);
      assert.equal(m.kind, "latency");
      assert.equal(m.params.entries, size);
    }
  }
  assert.equal(byName["capture.vault_overhead_ms.at-256"].gating, undefined);
  assert.equal(byName["capture.at-256"].gating, false);
  for (const prefix of ["capture.vault_overhead_ms", "restore"]) {
    const slope = byName[`${prefix}.ms_per_1k_entries`];
    assert.equal(slope.kind, "deterministic");
    assert.equal(slope.gating, false);
    assert.ok(Number.isFinite(slope.value));
  }

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
  const out = join(mkdtempSync(join(tmpdir(), "bench-entry-scaling-")), "result.json");
  await writeResult(result, out);
  const text = readFileSync(out, "utf8");
  for (const value of SENSITIVE_VALUES) assert.ok(!text.includes(value));
  assert.ok(!/SYNTHETIC|rsv_/.test(text));
});
