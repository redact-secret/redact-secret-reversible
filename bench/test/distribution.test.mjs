// B8 (#82): dist-size, cold-init, and cold-init-browser against the workspace
// side. The browser metric is only checked on its skip path here, so the
// suite needs no installed browser.

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";

import { loadCorpus } from "../corpus/v1/index.mjs";
import { deterministicVerdict } from "../lib/compare.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";
import { SPAWNS } from "../metrics/cold-init.mjs";
import { MAX_RATIO } from "../metrics/dist-size.mjs";

const SETTINGS = { iterations: 1, warmup: 0 };
let side;
let corpus;
let metrics;

before(async () => {
  side = await activateSide(await loadWorkspaceSide(), "off");
  corpus = loadCorpus();
  metrics = Object.fromEntries((await discoverMetrics({ only: ["dist-size", "cold-init", "cold-init-browser"] })).map((m) => [m.id, m]));
});

const ctx = () => makeContext({ side, corpus, piiMode: "off", settings: SETTINGS, quick: true });

function assertWritable(metric, raw) {
  const result = newResult({ kind: "run", piiMode: "off", quick: true, settings: SETTINGS, corpus, environment: captureEnvironment(), sides: [describeSide(side)] });
  result.metrics.push({
    id: metric.id,
    issue: metric.issue,
    title: metric.title,
    status: "ok",
    measurements: raw.map((m) => toResultMeasurement(m, side.label)),
  });
  return writeResult(result, join(mkdtempSync(join(tmpdir(), "bench-b8-")), "r.json"));
}

test("dist-size reports exact package and bundle sizes, gates the vault's, and not the core's", async () => {
  const metric = metrics["dist-size"];
  assert.equal(metric.issue, 82);
  const first = await runMetric(metric, ctx());
  assert.equal(first.status, "ok", first.reason);
  const byName = Object.fromEntries(first.raw.map((m) => [m.name, m]));
  for (const pkg of ["vault", "vault-server"]) {
    for (const what of ["tarball_bytes", "unpacked_bytes"]) {
      const m = byName[`pack.${pkg}.${what}`];
      assert.ok(Number.isInteger(m.value) && m.value > 0);
      assert.deepEqual(m.threshold, { maxRatio: MAX_RATIO });
    }
    assert.equal(byName[`pack.${pkg}.files`].gating, false);
  }
  assert.ok(byName["pack.vault.tarball_bytes"].value < byName["pack.vault.unpacked_bytes"].value);
  assert.deepEqual(byName["bundle.vault.gzip_bytes"].threshold, { maxRatio: MAX_RATIO });
  assert.ok(byName["bundle.vault.gzip_bytes"].value < byName["bundle.vault.min_bytes"].value);
  const core = first.raw.filter((m) => m.name.startsWith("core."));
  assert.ok(core.length >= 2);
  for (const m of core) {
    assert.equal(m.gating, false);
    assert.equal(m.threshold, undefined);
  }

  // Deterministic and cached: a second round returns the same figures.
  const second = await runMetric(metric, ctx());
  assert.deepEqual(second.raw, first.raw);

  // The compare hook: a size just over the ratio fails, one at it passes.
  const base = byName["pack.vault.tarball_bytes"].value;
  assert.equal(deterministicVerdict(Math.ceil(base * MAX_RATIO) + 1, base, byName["pack.vault.tarball_bytes"].threshold).verdict, "fail");
  assert.equal(deterministicVerdict(base, base, byName["pack.vault.tarball_bytes"].threshold).verdict, "ok");
  await assertWritable(metric, first.raw);
});

test("cold-init times createVault in fresh processes, split into core and vault", async () => {
  const metric = metrics["cold-init"];
  const outcome = await runMetric(metric, ctx());
  assert.equal(outcome.status, "ok", outcome.reason);
  const byName = Object.fromEntries(outcome.raw.map((m) => [m.name, m]));
  assert.deepEqual(Object.keys(byName).sort(), ["cold_init.core_ms", "cold_init.process_ms", "cold_init.total_ms", "cold_init.vault_ms"]);
  for (const m of outcome.raw) {
    assert.equal(m.samples.length, SPAWNS.quick);
    assert.ok(m.samples.every((s) => Number.isFinite(s) && s > 0));
  }
  byName["cold_init.total_ms"].samples.forEach((total, i) => {
    assert.ok(Math.abs(total - byName["cold_init.core_ms"].samples[i] - byName["cold_init.vault_ms"].samples[i]) < 1e-9);
    assert.ok(byName["cold_init.process_ms"].samples[i] > total);
  });
  assert.notEqual(byName["cold_init.vault_ms"].gating, false);
  assert.equal(byName["cold_init.core_ms"].gating, false);
  await assertWritable(metric, outcome.raw);
});

test("cold-init-browser skips, not fails, when browsers are opted out", async () => {
  const previous = process.env.BENCH_SKIP_BROWSER;
  process.env.BENCH_SKIP_BROWSER = "1";
  try {
    const outcome = await runMetric(metrics["cold-init-browser"], ctx());
    assert.equal(outcome.status, "skipped");
  } finally {
    if (previous === undefined) delete process.env.BENCH_SKIP_BROWSER;
    else process.env.BENCH_SKIP_BROWSER = previous;
  }
});
