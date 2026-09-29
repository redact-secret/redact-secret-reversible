// Interleaved A/B comparison (#76): verdicts and comparison records.
//
// Regression rule (#74): a latency ratio candidate÷baseline above 1.10 whose
// bootstrap CI lies entirely above 1.0 is a warning. A deterministic
// measurement fails when it exceeds its own threshold (`max` on the
// candidate's value, or `maxRatio` on candidate÷baseline) — the hook B8's
// package-size metric uses.
//
// A raw measurement with `gating: false` (for example `capture.core_ms`,
// which moves with the pinned core, not the vault) is still compared and
// reported, but its verdict does not count toward the job's outcome.

import { bootstrapRatio } from "./stats.mjs";

export const WARN_RATIO = 1.1;
export const CI_LEVEL = 0.95;
export const LATENCY_RULE = `ratio of medians > ${WARN_RATIO} and ${CI_LEVEL * 100}% bootstrap CI excludes 1.0 -> warn`;

/** Verdict for a latency ratio and its CI. */
export function latencyVerdict({ ratio, lo, hi }) {
  if (ratio === null || lo === null || hi === null) return "inconclusive";
  if (ratio > WARN_RATIO && lo > 1) return "warn";
  if (hi < 1) return "improved";
  return "ok";
}

/** Verdict and rule text for a deterministic measurement. */
export function deterministicVerdict(candidate, baseline, threshold) {
  const ratio = baseline > 0 ? candidate / baseline : null;
  const rules = [];
  let verdict = "ok";
  if (threshold?.max !== undefined) {
    rules.push(`value > ${threshold.max} -> fail`);
    if (candidate > threshold.max) verdict = "fail";
  }
  if (threshold?.maxRatio !== undefined) {
    rules.push(`ratio > ${threshold.maxRatio} -> fail`);
    if (ratio === null || ratio > threshold.maxRatio) verdict = "fail";
  }
  if (rules.length === 0) rules.push("no threshold (informational)");
  return { ratio, verdict, rule: rules.join("; ") };
}

/**
 * Builds one comparison from the per-round raw measurements of both sides.
 * `rounds.candidate[r]` / `rounds.baseline[r]` are that round's raw
 * measurement objects for this name.
 */
export function compareMeasurement({ metric, name, rounds, labels, seed }) {
  const first = rounds.candidate[0];
  const common = { metric, measurement: name, kind: first.kind, unit: first.unit, candidate: labels.candidate, baseline: labels.baseline };
  const gating = first.gating !== false;
  if (first.kind === "latency") {
    const ci = bootstrapRatio(
      rounds.candidate.map((m) => m.samples),
      rounds.baseline.map((m) => m.samples),
      { level: CI_LEVEL, seed },
    );
    return {
      ...common,
      ratio: ci.ratio,
      ci: { lo: ci.lo, hi: ci.hi, level: CI_LEVEL },
      verdict: latencyVerdict(ci),
      gating,
      rule: LATENCY_RULE,
    };
  }
  const candidate = rounds.candidate[0].value;
  const baseline = rounds.baseline[0].value;
  const { ratio, verdict, rule } = deterministicVerdict(candidate, baseline, first.threshold);
  return { ...common, ratio, ci: { lo: ratio, hi: ratio, level: CI_LEVEL }, verdict, gating, rule };
}
