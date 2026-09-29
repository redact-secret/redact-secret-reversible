// The benchmark result schema, `redact-secret-vault/bench-result@1`, and its
// validator. Hand-written so the harness needs no runtime dependency. Every
// measurement object is closed (unknown keys are errors), so a metric cannot
// smuggle raw samples, inputs, or outputs into a result.
//
// {
//   schema: "redact-secret-vault/bench-result@1",
//   kind: "run" | "compare",
//   createdAt: ISO-8601 string,
//   mode: { pii: "off" | "on", quick, iterations, warmup, rounds: int | null },
//   corpus: { version: "corpus-vN", sha256 },
//   environment: { node, v8, platform, arch, osRelease, cpuModel, cpuCount, totalMemoryBytes, runner },
//   sides: [{ label, source: "workspace" | "npm", gitSha?, piiActivation: string | null,
//             vault: Pkg, vaultServer: Pkg | null, core: Pkg & { artifact: string | null } }],
//   metrics: [{ id, issue, title, status: "ok" | "skipped" | "failed", reason?,
//               measurements: [Latency | Deterministic] }],
//   comparisons?: [Comparison]            // kind "compare" only
// }
// Pkg         = { version, resolved?, integrity? }
// Latency     = { name, side, kind: "latency", unit: "ms", n, p50, p95, p99, mean, min, max, params? }
// Deterministic = { name, side, kind: "deterministic", unit, value, threshold?, params? }
// Comparison  = { metric, measurement, kind, unit, candidate, baseline, ratio: number | null,
//                 ci: { lo, hi, level } (numbers or null), verdict, gating: boolean, rule }
//
// `params` values are numbers, booleans, or strings of at most 80 characters
// (input sizes, counts, labels) — never inputs or outputs.

export const RESULT_SCHEMA = "redact-secret-vault/bench-result@1";

export const PII_MODES = Object.freeze(["off", "on"]);
export const METRIC_STATUSES = Object.freeze(["ok", "skipped", "failed"]);
export const VERDICTS = Object.freeze(["ok", "warn", "improved", "fail", "inconclusive"]);

const LATENCY_KEYS = new Set(["name", "side", "kind", "unit", "n", "p50", "p95", "p99", "mean", "min", "max", "params"]);
const DETERMINISTIC_KEYS = new Set(["name", "side", "kind", "unit", "value", "threshold", "params"]);
const COMPARISON_KEYS = new Set([
  "metric",
  "measurement",
  "kind",
  "unit",
  "candidate",
  "baseline",
  "ratio",
  "ci",
  "verdict",
  "gating",
  "rule",
]);
const MAX_PARAM_STRING = 80;

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isString = (value) => typeof value === "string" && value.length > 0;
const isFiniteNumber = (value) => typeof value === "number" && Number.isFinite(value);
const isCount = (value) => Number.isInteger(value) && value >= 0;

function checkClosed(errors, where, value, allowed) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${where}: unexpected key "${key}"`);
}

function checkParams(errors, where, params) {
  if (params === undefined) return;
  if (!isObject(params)) {
    errors.push(`${where}.params must be an object`);
    return;
  }
  for (const [key, value] of Object.entries(params)) {
    const ok =
      isFiniteNumber(value) || typeof value === "boolean" || (typeof value === "string" && value.length <= MAX_PARAM_STRING);
    if (!ok) errors.push(`${where}.params.${key} must be a number, boolean, or short string`);
  }
}

function checkPkg(errors, where, pkg) {
  if (!isObject(pkg)) {
    errors.push(`${where} must be an object`);
    return;
  }
  if (!isString(pkg.version)) errors.push(`${where}.version must be a string`);
  for (const key of ["resolved", "integrity"]) {
    if (pkg[key] !== undefined && !isString(pkg[key])) errors.push(`${where}.${key} must be a string when present`);
  }
}

function checkMeasurement(errors, where, m, sideLabels) {
  if (!isObject(m)) {
    errors.push(`${where} must be an object`);
    return;
  }
  if (!isString(m.name)) errors.push(`${where}.name must be a string`);
  if (!sideLabels.has(m.side)) errors.push(`${where}.side must name one of the result's sides`);
  if (!isString(m.unit)) errors.push(`${where}.unit must be a string`);
  checkParams(errors, where, m.params);
  if (m.kind === "latency") {
    checkClosed(errors, where, m, LATENCY_KEYS);
    if (m.unit !== "ms") errors.push(`${where}.unit must be "ms" for latency`);
    if (!(Number.isInteger(m.n) && m.n > 0)) errors.push(`${where}.n must be a positive integer`);
    for (const key of ["p50", "p95", "p99", "mean", "min", "max"]) {
      if (!isFiniteNumber(m[key])) errors.push(`${where}.${key} must be a finite number`);
    }
    if (isFiniteNumber(m.p50) && isFiniteNumber(m.p95) && isFiniteNumber(m.p99) && !(m.p50 <= m.p95 && m.p95 <= m.p99)) {
      errors.push(`${where}: percentiles must satisfy p50 <= p95 <= p99`);
    }
  } else if (m.kind === "deterministic") {
    checkClosed(errors, where, m, DETERMINISTIC_KEYS);
    if (!isFiniteNumber(m.value)) errors.push(`${where}.value must be a finite number`);
    if (m.threshold !== undefined) {
      if (!isObject(m.threshold)) errors.push(`${where}.threshold must be an object`);
      else {
        checkClosed(errors, `${where}.threshold`, m.threshold, new Set(["max", "maxRatio"]));
        for (const key of ["max", "maxRatio"]) {
          if (m.threshold[key] !== undefined && !isFiniteNumber(m.threshold[key])) {
            errors.push(`${where}.threshold.${key} must be a finite number`);
          }
        }
      }
    }
  } else {
    errors.push(`${where}.kind must be "latency" or "deterministic"`);
  }
}

function checkComparison(errors, where, c) {
  if (!isObject(c)) {
    errors.push(`${where} must be an object`);
    return;
  }
  checkClosed(errors, where, c, COMPARISON_KEYS);
  for (const key of ["metric", "measurement", "kind", "unit", "candidate", "baseline", "rule"]) {
    if (!isString(c[key])) errors.push(`${where}.${key} must be a string`);
  }
  if (!(c.ratio === null || isFiniteNumber(c.ratio))) errors.push(`${where}.ratio must be a number or null`);
  if (!isObject(c.ci)) errors.push(`${where}.ci must be an object`);
  else {
    for (const key of ["lo", "hi"]) {
      if (!(c.ci[key] === null || isFiniteNumber(c.ci[key]))) errors.push(`${where}.ci.${key} must be a number or null`);
    }
    if (!(isFiniteNumber(c.ci.level) && c.ci.level > 0 && c.ci.level < 1)) errors.push(`${where}.ci.level must be in (0, 1)`);
  }
  if (!VERDICTS.includes(c.verdict)) errors.push(`${where}.verdict must be one of ${VERDICTS.join(", ")}`);
  if (typeof c.gating !== "boolean") errors.push(`${where}.gating must be a boolean`);
}

/** Returns a list of schema errors; empty means valid. */
export function validateResult(result) {
  const errors = [];
  if (!isObject(result)) return ["result must be an object"];
  if (result.schema !== RESULT_SCHEMA) errors.push(`schema must be "${RESULT_SCHEMA}"`);
  if (result.kind !== "run" && result.kind !== "compare") errors.push('kind must be "run" or "compare"');
  if (!(isString(result.createdAt) && !Number.isNaN(Date.parse(result.createdAt)))) errors.push("createdAt must be an ISO date");

  const mode = result.mode;
  if (!isObject(mode)) errors.push("mode must be an object");
  else {
    if (!PII_MODES.includes(mode.pii)) errors.push(`mode.pii must be one of ${PII_MODES.join(", ")}`);
    if (typeof mode.quick !== "boolean") errors.push("mode.quick must be a boolean");
    if (!(Number.isInteger(mode.iterations) && mode.iterations > 0)) errors.push("mode.iterations must be a positive integer");
    if (!isCount(mode.warmup)) errors.push("mode.warmup must be a non-negative integer");
    if (!(mode.rounds === null || (Number.isInteger(mode.rounds) && mode.rounds > 0))) {
      errors.push("mode.rounds must be a positive integer or null");
    }
  }

  if (!isObject(result.corpus)) errors.push("corpus must be an object");
  else {
    if (!/^corpus-v\d+$/.test(result.corpus.version ?? "")) errors.push("corpus.version must look like corpus-vN");
    if (!/^[0-9a-f]{64}$/.test(result.corpus.sha256 ?? "")) errors.push("corpus.sha256 must be a hex SHA-256");
  }

  const env = result.environment;
  if (!isObject(env)) errors.push("environment must be an object");
  else {
    for (const key of ["node", "v8", "platform", "arch", "osRelease", "cpuModel", "runner"]) {
      if (!isString(env[key])) errors.push(`environment.${key} must be a string`);
    }
    if (!(Number.isInteger(env.cpuCount) && env.cpuCount > 0)) errors.push("environment.cpuCount must be a positive integer");
    if (!isCount(env.totalMemoryBytes)) errors.push("environment.totalMemoryBytes must be a non-negative integer");
  }

  const sideLabels = new Set();
  if (!(Array.isArray(result.sides) && result.sides.length > 0)) errors.push("sides must be a non-empty array");
  else {
    result.sides.forEach((side, i) => {
      const where = `sides[${i}]`;
      if (!isObject(side)) {
        errors.push(`${where} must be an object`);
        return;
      }
      if (!isString(side.label)) errors.push(`${where}.label must be a string`);
      else if (sideLabels.has(side.label)) errors.push(`${where}.label is duplicated`);
      else sideLabels.add(side.label);
      if (side.source !== "workspace" && side.source !== "npm") errors.push(`${where}.source must be "workspace" or "npm"`);
      if (side.gitSha !== undefined && !isString(side.gitSha)) errors.push(`${where}.gitSha must be a string when present`);
      if (!(side.piiActivation === null || isString(side.piiActivation))) {
        errors.push(`${where}.piiActivation must be a string or null`);
      }
      checkPkg(errors, `${where}.vault`, side.vault);
      if (side.vaultServer !== null) checkPkg(errors, `${where}.vaultServer`, side.vaultServer);
      checkPkg(errors, `${where}.core`, side.core);
      if (isObject(side.core) && !(side.core.artifact === null || isString(side.core.artifact))) {
        errors.push(`${where}.core.artifact must be a string or null`);
      }
    });
  }

  if (!Array.isArray(result.metrics)) errors.push("metrics must be an array");
  else {
    result.metrics.forEach((metric, i) => {
      const where = `metrics[${i}]`;
      if (!isObject(metric)) {
        errors.push(`${where} must be an object`);
        return;
      }
      if (!isString(metric.id)) errors.push(`${where}.id must be a string`);
      if (!(Number.isInteger(metric.issue) && metric.issue > 0)) errors.push(`${where}.issue must be a positive integer`);
      if (!isString(metric.title)) errors.push(`${where}.title must be a string`);
      if (!METRIC_STATUSES.includes(metric.status)) errors.push(`${where}.status must be one of ${METRIC_STATUSES.join(", ")}`);
      if (metric.reason !== undefined && !(typeof metric.reason === "string" && metric.reason.length <= MAX_PARAM_STRING)) {
        errors.push(`${where}.reason must be a short string`);
      }
      if (!Array.isArray(metric.measurements)) errors.push(`${where}.measurements must be an array`);
      else {
        metric.measurements.forEach((m, j) => {
          checkMeasurement(errors, `${where}.measurements[${j}]`, m, sideLabels);
        });
      }
    });
  }

  if (result.kind === "compare") {
    if (!Array.isArray(result.comparisons)) errors.push("comparisons must be an array for kind compare");
    else {
      result.comparisons.forEach((c, i) => {
        checkComparison(errors, `comparisons[${i}]`, c);
      });
    }
  } else if (result.comparisons !== undefined) {
    errors.push("comparisons is only allowed for kind compare");
  }
  return errors;
}
