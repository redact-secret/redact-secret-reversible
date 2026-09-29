#!/usr/bin/env node
// Runs the discovered metrics against the workspace packages (one side) and
// writes a schema-valid result (#75).
//
//   node bench/run.mjs [--metrics a,b] [--quick] [--pii off|on] [--out file]
//                      [--iterations N] [--warmup N] [--tier standard|extended]
//
// The default tier here is extended (every shape); see bench/lib/harness.mjs.
//
// One process measures one PII mode: core activation is one-shot per process.

import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { loadCorpus } from "./corpus/v1/index.mjs";
import { captureEnvironment } from "./lib/env.mjs";
import {
  discoverMetrics,
  formatLine,
  makeContext,
  newResult,
  runMetric,
  toResultMeasurement,
  writeResult,
} from "./lib/harness.mjs";
import { parseCommonArgs } from "./lib/cli.mjs";
import { activateSide, describeSide, loadWorkspaceSide, REPO_ROOT } from "./lib/sides.mjs";

const USAGE =
  "usage: node bench/run.mjs [--metrics a,b] [--quick] [--pii off|on] [--out file] [--iterations N] [--warmup N] [--tier standard|extended]";

async function main() {
  const { values, settings, only } = parseCommonArgs(process.argv.slice(2));
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  const piiMode = values.pii;
  const corpus = loadCorpus();
  const metrics = await discoverMetrics({ only });
  const side = await activateSide(await loadWorkspaceSide(), piiMode);

  const result = newResult({
    kind: "run",
    piiMode,
    quick: values.quick,
    settings,
    tier: values.tier,
    corpus,
    environment: captureEnvironment(),
    sides: [describeSide(side)],
  });

  let failed = 0;
  for (const metric of metrics) {
    const ctx = makeContext({ side, corpus, piiMode, settings, quick: values.quick, tier: values.tier });
    const outcome = await runMetric(metric, ctx);
    const entry = { id: metric.id, issue: metric.issue, title: metric.title, status: outcome.status, measurements: [] };
    if (outcome.reason !== undefined) entry.reason = outcome.reason;
    entry.measurements = outcome.raw.map((raw) => toResultMeasurement(raw, side.label));
    const over = outcome.raw.find((raw) => raw.kind === "deterministic" && raw.threshold?.max !== undefined && raw.value > raw.threshold.max);
    if (over !== undefined) {
      entry.status = "failed";
      entry.reason = `${over.name} exceeds threshold.max`.slice(0, 80);
    }
    if (entry.status === "failed") failed += 1;
    result.metrics.push(entry);
  }

  const stamp = result.createdAt.replace(/[:.]/g, "-");
  const out = values.out ?? join(REPO_ROOT, ".bench-results", `run-pii-${piiMode}-${stamp}.json`);
  await writeResult(result, out);

  for (const metric of result.metrics) {
    if (metric.status !== "ok") console.log(`${metric.id} ${metric.status}: ${metric.reason}`);
    for (const m of metric.measurements) console.log(formatLine(result, metric.id, m));
  }
  console.log(`wrote ${out} (${result.metrics.length} metric(s), ${failed} failed)`);
  return failed > 0 ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 2;
    },
  );
}
