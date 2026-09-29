// Metric discovery, the per-side metric context, and result assembly shared
// by run.mjs (one side) and compare.mjs (interleaved A/B).
//
// Metric module contract (bench/metrics/<id>.mjs, auto-discovered):
//
//   export const id = "<id>";          // must equal the file name without .mjs
//   export const issue = 77;           // tracking issue number
//   export const title = "...";
//   export const piiModes = ["off"];   // optional; default ["off", "on"]
//   export async function run(ctx) { return [RawMeasurement, ...]; }
//
//   RawMeasurement =
//     | { name, kind: "latency", unit: "ms", samples: number[], params?, gating? }
//     | { name, kind: "deterministic", unit, value: number, threshold?: { max?, maxRatio? }, params?, gating? }
//
//   `gating: false` marks a measurement compare.mjs reports but does not
//   count toward warn/fail (default true). `threshold` makes a deterministic
//   measurement fail: `max` on the value (run and compare), `maxRatio` on
//   candidate÷baseline (compare).
//
// run(ctx) must be repeatable: compare.mjs calls it once per round per side.
// It creates and disposes its own vaults, never passes `pii` to createVault
// (the harness owns activation), and returns numbers only: raw samples are
// summarized by the harness and never written to results.

import { readdirSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { assertNoLeaks } from "./leak-guard.mjs";
import { RESULT_SCHEMA, validateResult } from "./schema.mjs";
import { summarize } from "./stats.mjs";
import { sample, samplePaired } from "./timing.mjs";

export const METRICS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "metrics");

/** Iteration settings: full runs and `--quick` (smoke) runs. */
export const DEFAULT_SETTINGS = Object.freeze({
  full: Object.freeze({ iterations: 1000, warmup: 200, rounds: 10 }),
  quick: Object.freeze({ iterations: 50, warmup: 10, rounds: 4 }),
});

/** Thrown by `ctx.skip(reason)`: the metric does not apply to this side or mode. */
export class SkipMetric extends Error {
  constructor(reason) {
    super(reason);
    this.name = "SkipMetric";
    this.reason = reason;
  }
}

function checkMetricModule(module, file) {
  const expectedId = basename(file, ".mjs");
  const problems = [];
  if (module.id !== expectedId) problems.push(`id must equal "${expectedId}"`);
  if (!(Number.isInteger(module.issue) && module.issue > 0)) problems.push("issue must be a positive integer");
  if (!(typeof module.title === "string" && module.title.length > 0)) problems.push("title must be a string");
  if (typeof module.run !== "function") problems.push("run must be a function");
  if (module.piiModes !== undefined && !(Array.isArray(module.piiModes) && module.piiModes.every((m) => m === "off" || m === "on"))) {
    problems.push('piiModes must be an array of "off" | "on"');
  }
  if (problems.length > 0) throw new Error(`invalid metric ${file}: ${problems.join("; ")}`);
  return {
    id: module.id,
    issue: module.issue,
    title: module.title,
    piiModes: module.piiModes ?? ["off", "on"],
    run: module.run,
  };
}

/**
 * Imports every `*.mjs` in `dir`, sorted by file name. `only` (ids) filters
 * and must name existing metrics.
 */
export async function discoverMetrics({ dir = METRICS_DIR, only } = {}) {
  let files = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort();
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const metrics = [];
  for (const file of files) {
    const module = await import(pathToFileURL(join(dir, file)).href);
    metrics.push(checkMetricModule(module, file));
  }
  if (only === undefined) return metrics;
  const known = new Set(metrics.map((m) => m.id));
  const unknown = only.filter((id) => !known.has(id));
  if (unknown.length > 0) throw new Error(`unknown metric(s): ${unknown.join(", ")}; known: ${[...known].join(", ")}`);
  return metrics.filter((m) => only.includes(m.id));
}

/** The context a metric's run() receives for one side. */
export function makeContext({ side, corpus, piiMode, settings, quick, round = 0 }) {
  return Object.freeze({
    side: Object.freeze({ label: side.label, source: side.source, packages: side.packages, piiActivation: side.piiActivation }),
    vault: side.vault,
    vaultServer: side.vaultServer,
    core: side.core,
    corpus,
    pii: Object.freeze({ mode: piiMode }),
    quick,
    iterations: settings.iterations,
    warmup: settings.warmup,
    round,
    sample,
    samplePaired,
    skip(reason) {
      throw new SkipMetric(reason);
    },
  });
}

function checkRaw(raw, metricId) {
  if (!Array.isArray(raw)) throw new Error(`metric ${metricId} must return an array of measurements`);
  for (const m of raw) {
    if (m === null || typeof m !== "object" || typeof m.name !== "string") {
      throw new Error(`metric ${metricId} returned a measurement without a name`);
    }
    if (m.kind === "latency" && !(Array.isArray(m.samples) && m.samples.length > 0)) {
      throw new Error(`metric ${metricId} ${m.name}: latency needs samples`);
    }
  }
  return raw;
}

/**
 * Runs one metric on one side. Returns `{ status, reason?, raw }`; a thrown
 * error becomes `failed` with only its code or name as the reason, since an
 * arbitrary message is not guaranteed value-free.
 */
export async function runMetric(metric, ctx) {
  if (!metric.piiModes.includes(ctx.pii.mode)) {
    return { status: "skipped", reason: `not measured with PII ${ctx.pii.mode}`, raw: [] };
  }
  try {
    return { status: "ok", raw: checkRaw(await metric.run(ctx), metric.id) };
  } catch (error) {
    if (error instanceof SkipMetric) return { status: "skipped", reason: String(error.reason).slice(0, 80), raw: [] };
    const reason = typeof error?.code === "string" ? error.code : (error?.name ?? "Error");
    return { status: "failed", reason: String(reason).slice(0, 80), raw: [], error };
  }
}

/** Converts a raw measurement to its result form for one side. */
export function toResultMeasurement(raw, sideLabel) {
  const base = { name: raw.name, side: sideLabel, kind: raw.kind, unit: raw.unit };
  const out = raw.kind === "latency" ? { ...base, ...summarize(raw.samples) } : { ...base, value: raw.value };
  if (raw.kind === "deterministic" && raw.threshold !== undefined) out.threshold = { ...raw.threshold };
  if (raw.params !== undefined) out.params = { ...raw.params };
  return out;
}

export function newResult({ kind, piiMode, quick, settings, rounds = null, corpus, environment, sides }) {
  return {
    schema: RESULT_SCHEMA,
    kind,
    createdAt: new Date().toISOString(),
    mode: { pii: piiMode, quick, iterations: settings.iterations, warmup: settings.warmup, rounds },
    corpus: { version: corpus.version, sha256: corpus.sha256 },
    environment,
    sides,
    metrics: [],
  };
}

/** Validates, leak-checks, and writes a result. Throws without writing on any problem. */
export async function writeResult(result, outPath) {
  const errors = validateResult(result);
  if (errors.length > 0) throw new Error(`result does not match ${RESULT_SCHEMA}:\n  ${errors.join("\n  ")}`);
  const text = `${JSON.stringify(result, null, 2)}\n`;
  assertNoLeaks(text, SENSITIVE_VALUES);
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, text);
  return text;
}

const fmt = (ms) => (ms >= 1 ? ms.toFixed(3) : ms.toFixed(4));

/** One console line per measurement; always carries the mode and environment. */
export function formatLine(result, metricId, m) {
  const side = result.sides.find((s) => s.label === m.side);
  const env = result.environment;
  const tag = `[pii=${result.mode.pii} ${result.corpus.version} ${side.label} vault@${side.vault.version} core@${side.core.version}/${side.core.artifact} node@${env.node} ${env.platform}-${env.arch}${result.mode.quick ? " quick" : ""}]`;
  const figure =
    m.kind === "latency"
      ? `p50=${fmt(m.p50)}ms p95=${fmt(m.p95)}ms p99=${fmt(m.p99)}ms n=${m.n}`
      : `value=${m.value}${m.unit}`;
  return `${tag} ${metricId} ${m.name} ${figure}`;
}
