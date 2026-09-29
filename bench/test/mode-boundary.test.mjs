import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";

const settings = { iterations: 3, warmup: 1 };

async function runOne(id) {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const corpus = loadCorpus();
  const [metric] = await discoverMetrics({ only: [id] });
  assert.equal(metric.issue, 79);
  const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings, quick: true }));
  return { side, corpus, metric, outcome };
}

async function assertWritable({ side, corpus, metric, outcome }) {
  const result = newResult({ kind: "run", piiMode: "off", quick: true, settings, corpus, environment: captureEnvironment(), sides: [describeSide(side)] });
  result.metrics.push({
    id: metric.id,
    issue: metric.issue,
    title: metric.title,
    status: outcome.status,
    ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
    measurements: outcome.raw.map((raw) => toResultMeasurement(raw, side.label)),
  });
  const out = join(mkdtempSync(join(tmpdir(), "bench-mode-")), "r.json");
  await writeResult(result, out);
  const text = readFileSync(out, "utf8");
  for (const value of SENSITIVE_VALUES) assert.ok(!text.includes(value));
  assert.ok(!/rsv_/i.test(text));
}

test("mode-server pairs vault and vault-server per op with a boundary split and a ratio", async () => {
  const run = await runOne("mode-server");
  assert.equal(run.outcome.status, "ok", run.outcome.reason);
  const byName = Object.fromEntries(run.outcome.raw.map((m) => [m.name, m]));
  for (const op of ["capture", "restore", "revoke"]) {
    for (const suffix of ["vault", "server", "boundary_ms"]) assert.equal(byName[`${op}.${suffix}`].samples.length, settings.iterations);
    byName[`${op}.server`].samples.forEach((s, i) => {
      assert.ok(Math.abs(s - byName[`${op}.vault`].samples[i] - byName[`${op}.boundary_ms`].samples[i]) < 1e-9);
    });
    assert.ok(byName[`${op}.ratio`].value > 0);
  }
  await assertWritable(run);
});

test("mode-server skips a side without vault-server", async () => {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const [metric] = await discoverMetrics({ only: ["mode-server"] });
  const outcome = await runMetric(metric, makeContext({ side: { ...side, vaultServer: null }, corpus: loadCorpus(), piiMode: "off", settings, quick: true }));
  assert.equal(outcome.status, "skipped");
});

test("mode-python separates spawn from scan, or skips cleanly without Python", async () => {
  const run = await runOne("mode-python");
  assert.notEqual(run.outcome.status, "failed", run.outcome.reason);
  if (run.outcome.status === "ok") {
    const names = new Set(run.outcome.raw.map((m) => m.name));
    for (const name of ["python.node_spawn", "python.bridge.startup_ms", "python.bridge.scan_work_ms", "python.capture", "capture.ratio"]) {
      assert.ok(names.has(name), name);
    }
    assert.ok(run.outcome.raw.every((m) => m.gating === false));
  }
  await assertWritable(run);
});

test("mode-python skips a published side", async () => {
  const side = await activateSide(await loadWorkspaceSide(), "off");
  const [metric] = await discoverMetrics({ only: ["mode-python"] });
  const outcome = await runMetric(metric, makeContext({ side: { ...side, source: "npm" }, corpus: loadCorpus(), piiMode: "off", settings, quick: true }));
  assert.equal(outcome.status, "skipped");
});
