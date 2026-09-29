#!/usr/bin/env node
// Interleaved A/B: the workspace candidate against an exact published
// version, in one process, reported as candidate÷baseline ratios with a
// bootstrap CI (#76).
//
//   node bench/compare.mjs [--baseline 0.1.0-alpha.3] [--metrics a,b] [--quick]
//                          [--pii off|on] [--rounds N] [--iterations N]
//                          [--warmup N] [--out file] [--fail-on-warn]
//
// Each round runs every metric once per side, alternating which side goes
// first (ABBA...), so drift over the job (thermal, background load) lands on
// both sides. `--iterations` is per round per side. Without `--baseline`, the
// version in bench/baseline.json is used.
//
// Exit status: 0 ok (warnings are printed), 1 a gating fail verdict, a failed
// metric, or (with --fail-on-warn) a gating warning, 2 a usage or setup error.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { loadCorpus } from "./corpus/v1/index.mjs";
import { parseCommonArgs } from "./lib/cli.mjs";
import { compareMeasurement } from "./lib/compare.mjs";
import { captureEnvironment } from "./lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "./lib/harness.mjs";
import { assertExactVersion, loadPublishedSide } from "./lib/published.mjs";
import { activateSide, describeSide, loadWorkspaceSide, REPO_ROOT } from "./lib/sides.mjs";

const USAGE =
  "usage: node bench/compare.mjs [--baseline <exact version>] [--metrics a,b] [--quick] [--pii off|on] [--rounds N] [--iterations N] [--warmup N] [--out file] [--fail-on-warn]";

/** bench/baseline.json names the previous published version; bump it after a release. */
function defaultBaseline() {
  return JSON.parse(readFileSync(new URL("./baseline.json", import.meta.url), "utf8")).version;
}

function pooled(rawRounds) {
  const first = rawRounds[0];
  if (first.kind === "latency") return { ...first, samples: rawRounds.flatMap((m) => m.samples) };
  return first;
}

function sideTag(side) {
  const where = side.source === "workspace" ? `workspace${side.gitSha === undefined ? "" : `@${side.gitSha}`}` : "npm";
  return `${side.label}=vault@${side.vault.version}(${where}) core@${side.core.version}/${side.core.artifact}`;
}

function fmtRatio(value) {
  return value === null ? "n/a" : value.toFixed(3);
}

export async function compareMetric(metric, { sides, corpus, piiMode, settings, quick, rounds }) {
  const entry = { id: metric.id, issue: metric.issue, title: metric.title, status: "ok", measurements: [] };
  const byName = new Map();
  for (let round = 0; round < rounds; round += 1) {
    const order = round % 2 === 0 ? sides : [...sides].reverse();
    for (const side of order) {
      const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode, settings, quick, round }));
      if (outcome.status !== "ok") {
        entry.status = outcome.status;
        entry.reason = `${side.label}: ${outcome.reason}`.slice(0, 80);
        return { entry, comparisons: [] };
      }
      for (const raw of outcome.raw) {
        if (!byName.has(raw.name)) byName.set(raw.name, { candidate: [], baseline: [] });
        byName.get(raw.name)[side.label].push(raw);
      }
    }
  }
  const comparisons = [];
  let seed = 0x5eed;
  for (const [name, perSide] of byName) {
    if (perSide.candidate.length !== rounds || perSide.baseline.length !== rounds) {
      entry.status = "failed";
      entry.reason = `measurement ${name} missing on one side`.slice(0, 80);
      return { entry, comparisons: [] };
    }
    entry.measurements.push(toResultMeasurement(pooled(perSide.candidate), "candidate"));
    entry.measurements.push(toResultMeasurement(pooled(perSide.baseline), "baseline"));
    seed += 1;
    comparisons.push(
      compareMeasurement({ metric: metric.id, name, rounds: perSide, labels: { candidate: "candidate", baseline: "baseline" }, seed }),
    );
  }
  return { entry, comparisons };
}

async function main() {
  const { values, settings, only } = parseCommonArgs(process.argv.slice(2), {
    baseline: { type: "string" },
    rounds: { type: "string" },
    "fail-on-warn": { type: "boolean", default: false },
  });
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  const baselineVersion = assertExactVersion(values.baseline ?? defaultBaseline(), "--baseline");
  const piiMode = values.pii;
  const rounds = settings.rounds;
  const corpus = loadCorpus();
  const metrics = await discoverMetrics({ only });

  const candidate = await activateSide(await loadWorkspaceSide({ label: "candidate" }), piiMode);
  const baseline = await activateSide(
    await loadPublishedSide(baselineVersion, { label: "baseline", log: (line) => console.log(line) }),
    piiMode,
  );
  const sides = [candidate, baseline];

  const result = newResult({
    kind: "compare",
    piiMode,
    quick: values.quick,
    settings,
    rounds,
    corpus,
    environment: captureEnvironment(),
    sides: sides.map(describeSide),
  });
  result.comparisons = [];
  const [candDesc, baseDesc] = result.sides;
  if (candDesc.core.version !== baseDesc.core.version || candDesc.core.artifact !== baseDesc.core.artifact) {
    console.log(
      `note: the sides use different cores (${candDesc.core.version}/${candDesc.core.artifact} vs ${baseDesc.core.version}/${baseDesc.core.artifact}); compare vault overhead, not totals`,
    );
  }

  let failedMetrics = 0;
  for (const metric of metrics) {
    const { entry, comparisons } = await compareMetric(metric, {
      sides,
      corpus,
      piiMode,
      settings,
      quick: values.quick,
      rounds,
    });
    if (entry.status === "failed") failedMetrics += 1;
    result.metrics.push(entry);
    result.comparisons.push(...comparisons);
  }

  const stamp = result.createdAt.replace(/[:.]/g, "-");
  const out = values.out ?? join(REPO_ROOT, ".bench-results", `compare-${baselineVersion}-pii-${piiMode}-${stamp}.json`);
  await writeResult(result, out);

  const env = result.environment;
  console.log(
    `[pii=${piiMode} ${corpus.version} rounds=${rounds}x${settings.iterations} node@${env.node} ${env.platform}-${env.arch} ${env.runner}${values.quick ? " quick" : ""}] ${sideTag(candDesc)} vs ${sideTag(baseDesc)}`,
  );
  for (const metric of result.metrics) {
    if (metric.status !== "ok") console.log(`${metric.id} ${metric.status}: ${metric.reason}`);
  }
  for (const c of result.comparisons) {
    const ci = `CI${Math.round(c.ci.level * 100)}=[${fmtRatio(c.ci.lo)}, ${fmtRatio(c.ci.hi)}]`;
    console.log(`  ${c.metric} ${c.measurement} ratio=${fmtRatio(c.ratio)} ${ci} ${c.verdict}${c.gating ? "" : " (informational)"}`);
  }
  const gating = result.comparisons.filter((c) => c.gating);
  const fails = gating.filter((c) => c.verdict === "fail").length;
  const warns = gating.filter((c) => c.verdict === "warn").length;
  console.log(`wrote ${out} (${result.comparisons.length} comparison(s): ${warns} warn, ${fails} fail; ${failedMetrics} failed metric(s))`);
  if (values.quick && warns > 0) console.log("note: quick runs are smoke tests; do not act on their ratios");
  if (fails > 0 || failedMetrics > 0) return 1;
  if (values["fail-on-warn"] && warns > 0) return 1;
  return 0;
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
