import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";

test("op-latency measures capture (with core/overhead split), restore, and revoke without leaking values", async () => {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const corpus = loadCorpus();
  const settings = { iterations: 5, warmup: 1 };
  const [metric] = await discoverMetrics({ only: ["op-latency"] });
  assert.equal(metric.issue, 77);

  const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings, quick: true }));
  assert.equal(outcome.status, "ok", outcome.reason);
  const byName = Object.fromEntries(outcome.raw.map((m) => [m.name, m]));
  assert.deepEqual(Object.keys(byName).sort(), ["capture", "capture.core_ms", "capture.vault_overhead_ms", "restore", "revoke"]);
  for (const m of outcome.raw) assert.equal(m.samples.length, settings.iterations);
  byName.capture.samples.forEach((total, i) => {
    const split = byName["capture.core_ms"].samples[i] + byName["capture.vault_overhead_ms"].samples[i];
    assert.ok(Math.abs(total - split) < 1e-9);
  });
  assert.equal(byName.capture.params.findings, 4);
  assert.equal(byName.restore.params.fields, 64);

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
    status: outcome.status,
    measurements: outcome.raw.map((raw) => toResultMeasurement(raw, side.label)),
  });
  const out = join(mkdtempSync(join(tmpdir(), "bench-op-")), "r.json");
  await writeResult(result, out);
  const text = readFileSync(out, "utf8");
  for (const value of SENSITIVE_VALUES) assert.ok(!text.includes(value));
  assert.ok(!/rsv_/i.test(text));
});
