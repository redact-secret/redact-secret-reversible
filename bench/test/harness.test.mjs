import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import {
  discoverMetrics,
  formatLine,
  makeContext,
  METRICS_DIR,
  newResult,
  runMetric,
  toResultMeasurement,
  writeResult,
} from "../lib/harness.mjs";
import { validateResult } from "../lib/schema.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";

const FIXTURES = fileURLToPath(new URL("./fixtures/metrics/", import.meta.url));
const SETTINGS = { iterations: 3, warmup: 1 };

let side;
before(async () => {
  side = await activateSide(await loadWorkspaceSide(), "off");
});

test("discovery imports every metric file in name order and validates its exports", async () => {
  const metrics = await discoverMetrics({ dir: FIXTURES });
  assert.deepEqual(
    metrics.map((m) => m.id),
    ["fixture-roundtrip", "fixture-skip"],
  );
  assert.deepEqual(metrics[0].piiModes, ["off", "on"]);
  assert.deepEqual(metrics[1].piiModes, ["off"]);
  assert.deepEqual(
    (await discoverMetrics({ dir: FIXTURES, only: ["fixture-skip"] })).map((m) => m.id),
    ["fixture-skip"],
  );
  await assert.rejects(discoverMetrics({ dir: FIXTURES, only: ["nope"] }), /unknown metric/);
  assert.deepEqual(await discoverMetrics({ dir: join(tmpdir(), "bench-no-such-dir") }), []);
});

test("discovery rejects a metric whose id does not match its file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bench-metrics-"));
  writeFileSync(join(dir, "right-name.mjs"), 'export const id = "wrong"; export const issue = 1; export const title = "t"; export function run() { return []; }');
  await assert.rejects(discoverMetrics({ dir }), /id must equal "right-name"/);
});

test("every metric in bench/metrics satisfies the module contract", async () => {
  for (const metric of await discoverMetrics({ dir: METRICS_DIR })) {
    assert.equal(typeof metric.run, "function", metric.id);
  }
});

test("the workspace side resolves the core the vault uses", () => {
  assert.equal(side.source, "workspace");
  assert.equal(typeof side.vault.createVault, "function");
  assert.equal(typeof side.vaultServer.createServerVault, "function");
  assert.match(side.piiActivation ?? "selectors=off", /selectors=off/);
});

test("a sample result from a real capture/restore metric is schema-valid and carries no values", async () => {
  const corpus = loadCorpus();
  const result = newResult({
    kind: "run",
    piiMode: "off",
    quick: true,
    settings: SETTINGS,
    corpus,
    environment: captureEnvironment(),
    sides: [describeSide(side)],
  });
  for (const metric of await discoverMetrics({ dir: FIXTURES })) {
    const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings: SETTINGS, quick: true }));
    const entry = { id: metric.id, issue: metric.issue, title: metric.title, status: outcome.status, measurements: [] };
    if (outcome.reason !== undefined) entry.reason = outcome.reason;
    entry.measurements = outcome.raw.map((raw) => toResultMeasurement(raw, side.label));
    result.metrics.push(entry);
  }
  assert.equal(result.metrics[0].status, "ok");
  assert.equal(result.metrics[0].measurements[0].n, SETTINGS.iterations);
  assert.equal(result.metrics[1].status, "skipped");

  const out = join(mkdtempSync(join(tmpdir(), "bench-result-")), "r.json");
  await writeResult(result, out);
  const text = readFileSync(out, "utf8");
  assert.deepEqual(validateResult(JSON.parse(text)), []);
  for (const value of SENSITIVE_VALUES) assert.ok(!text.includes(value), "a corpus value reached the result");
  assert.ok(!/rsv_/i.test(text), "an issued token reached the result");
  assert.ok(!text.includes(corpus.items.capture1k.input.slice(0, 40)), "input text reached the result");

  const line = formatLine(result, "fixture-roundtrip", result.metrics[0].measurements[0]);
  assert.match(line, /pii=off corpus-v1 candidate/);
  for (const value of SENSITIVE_VALUES) assert.ok(!line.includes(value));
});

test("writeResult refuses a result carrying a captured value", async () => {
  const corpus = loadCorpus();
  const result = newResult({
    kind: "run",
    piiMode: "off",
    quick: true,
    settings: SETTINGS,
    corpus,
    environment: captureEnvironment(),
    sides: [describeSide(side)],
  });
  result.metrics.push({
    id: "leaky",
    issue: 75,
    title: "Leaky",
    status: "ok",
    measurements: [
      { name: "x", side: side.label, kind: "deterministic", unit: "count", value: 1, params: { oops: SENSITIVE_VALUES[0] } },
    ],
  });
  const out = join(mkdtempSync(join(tmpdir(), "bench-result-")), "r.json");
  await assert.rejects(writeResult(result, out), (error) => {
    assert.match(error.message, /refusing to emit/);
    assert.ok(!error.message.includes(SENSITIVE_VALUES[0]));
    return true;
  });
});

test("a metric that throws is recorded as failed with a value-free reason", async () => {
  const corpus = loadCorpus();
  const metric = {
    id: "boom",
    issue: 75,
    title: "Boom",
    piiModes: ["off"],
    run: () => {
      throw new Error(`leaked ${SENSITIVE_VALUES[0]}`);
    },
  };
  const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings: SETTINGS, quick: true }));
  assert.equal(outcome.status, "failed");
  assert.equal(outcome.reason, "Error");
  const onOnly = { ...metric, piiModes: ["on"] };
  assert.equal((await runMetric(onOnly, makeContext({ side, corpus, piiMode: "off", settings: SETTINGS, quick: true }))).status, "skipped");
});
