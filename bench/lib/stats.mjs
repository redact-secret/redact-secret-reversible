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

/** k-th smallest element (0-based), partially reordering `a` in place (Hoare quickselect). */
function selectInPlace(a, k) {
  let left = 0;
  let right = a.length - 1;
  while (left < right) {
    const pivot = a[(left + right) >> 1];
    let i = left;
    let j = right;
    while (i <= j) {
      while (a[i] < pivot) i += 1;
      while (a[j] > pivot) j -= 1;
      if (i <= j) {
        const t = a[i];
        a[i] = a[j];
        a[j] = t;
        i += 1;
        j -= 1;
      }
    }
    if (k <= j) right = j;
    else if (k >= i) left = i;
    else return a[k];
  }
  return a[k];
}

/**
 * Median in O(n) expected time; same value as `median` (the mean of the two
 * middle elements for an even count). Reorders `a`.
 */
export function medianInPlace(a) {
  const n = a.length;
  if (n === 0) throw new RangeError("median of an empty sample");
  const upper = selectInPlace(a, n >> 1);
  if (n % 2 === 1) return upper;
  // After selecting index n/2, every element left of it is <= upper.
  let lower = Number.NEGATIVE_INFINITY;
  for (let i = 0; i < n >> 1; i += 1) if (a[i] > lower) lower = a[i];
  return (lower + upper) / 2;
}

function resampleRounds(rounds, indices, random, total) {
  const pooled = new Float64Array(total);
  let at = 0;
  for (const index of indices) {
    const round = rounds[index];
    for (let i = 0; i < round.length; i += 1) pooled[at++] = round[randomInt(random, round.length)];
  }
  return pooled.subarray(0, at);
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
export function bootstrapRatio(candidate, baseline, { resamples = 2000, level = 0.95, seed = 0x5eed } = {}) {
  const cand = Array.isArray(candidate[0]) ? candidate : [candidate];
  const base = Array.isArray(baseline[0]) ? baseline : [baseline];
  if (cand.length !== base.length) throw new RangeError("candidate and baseline must have the same number of rounds");
  if (cand.some((round) => round.length === 0) || base.some((round) => round.length === 0)) {
    throw new RangeError("every round needs at least one sample");
  }
  const baselineStat = median(base.flat());
  const ratio = baselineStat > 0 ? median(cand.flat()) / baselineStat : null;
  const random = mulberry32(seed);
  const ratios = [];
  const roundCount = cand.length;
  const maxRound = Math.max(...cand.map((r) => r.length), ...base.map((r) => r.length));
  for (let b = 0; b < resamples; b += 1) {
    const indices = Array.from({ length: roundCount }, () => randomInt(random, roundCount));
    const denominator = medianInPlace(resampleRounds(base, indices, random, roundCount * maxRound));
    if (!(denominator > 0)) continue;
    ratios.push(medianInPlace(resampleRounds(cand, indices, random, roundCount * maxRound)) / denominator);
  }
  if (ratio === null || ratios.length < resamples / 2) return { ratio, lo: null, hi: null, level, resamples };
  ratios.sort((x, y) => x - y);
  const alpha = (1 - level) / 2;
  return { ratio, lo: quantileSorted(ratios, alpha), hi: quantileSorted(ratios, 1 - alpha), level, resamples };
}
