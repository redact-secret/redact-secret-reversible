// Descriptive statistics and the bootstrap confidence interval used for
// candidate÷baseline ratios.

import { mulberry32, randomInt } from "./rng.mjs";

/** Linear-interpolation quantile (R type 7) of an ascending-sorted array. */
export function quantileSorted(sorted, q) {
  if (sorted.length === 0) throw new RangeError("quantile of an empty sample");
  if (!(q >= 0 && q <= 1)) throw new RangeError("q must be in [0, 1]");
  const position = (sorted.length - 1) * q;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
}

export function quantile(values, q) {
  return quantileSorted([...values].sort((x, y) => x - y), q);
}

export function median(values) {
  return quantile(values, 0.5);
}

/** Summary carried by every latency measurement in a result. */
export function summarize(samples) {
  if (!Array.isArray(samples) || samples.length === 0) throw new RangeError("summarize needs at least one sample");
  for (const value of samples) {
    if (typeof value !== "number" || !Number.isFinite(value)) throw new TypeError("samples must be finite numbers");
  }
  const sorted = [...samples].sort((x, y) => x - y);
  const sum = sorted.reduce((total, value) => total + value, 0);
  return {
    n: sorted.length,
    p50: quantileSorted(sorted, 0.5),
    p95: quantileSorted(sorted, 0.95),
    p99: quantileSorted(sorted, 0.99),
    mean: sum / sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
  };
}

function resampleRounds(rounds, indices, random) {
  const pooled = [];
  for (const index of indices) {
    const round = rounds[index];
    for (let i = 0; i < round.length; i += 1) pooled.push(round[randomInt(random, round.length)]);
  }
  return pooled;
}

/**
 * Ratio of medians candidate÷baseline with a percentile bootstrap CI.
 *
 * Inputs are *rounds*: `candidate[r]` and `baseline[r]` are the samples of the
 * two sides taken in interleaved round `r`, so rounds are paired in time. Each
 * resample draws the same round indices for both sides (keeping the pairing,
 * and so the between-round drift), then resamples samples within each drawn
 * round. A plain `number[]` is treated as a single round.
 *
 * Returns `{ ratio, lo, hi, level, resamples }`. A non-positive baseline
 * median makes the ratio undefined, reported as `null` bounds.
 */
export function bootstrapRatio(candidate, baseline, { resamples = 2000, level = 0.95, seed = 0x5eed, statistic = median } = {}) {
  const cand = Array.isArray(candidate[0]) ? candidate : [candidate];
  const base = Array.isArray(baseline[0]) ? baseline : [baseline];
  if (cand.length !== base.length) throw new RangeError("candidate and baseline must have the same number of rounds");
  if (cand.some((round) => round.length === 0) || base.some((round) => round.length === 0)) {
    throw new RangeError("every round needs at least one sample");
  }
  const baselineStat = statistic(base.flat());
  const ratio = baselineStat > 0 ? statistic(cand.flat()) / baselineStat : null;
  const random = mulberry32(seed);
  const ratios = [];
  const roundCount = cand.length;
  for (let b = 0; b < resamples; b += 1) {
    const indices = Array.from({ length: roundCount }, () => randomInt(random, roundCount));
    const denominator = statistic(resampleRounds(base, indices, random));
    if (!(denominator > 0)) continue;
    ratios.push(statistic(resampleRounds(cand, indices, random)) / denominator);
  }
  if (ratio === null || ratios.length < resamples / 2) return { ratio, lo: null, hi: null, level, resamples };
  ratios.sort((x, y) => x - y);
  const alpha = (1 - level) / 2;
  return { ratio, lo: quantileSorted(ratios, alpha), hi: quantileSorted(ratios, 1 - alpha), level, resamples };
}
