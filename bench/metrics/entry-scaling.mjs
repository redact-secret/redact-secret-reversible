// B4 (#78): capture and restore latency as the number of retained entries
// grows, and the slope of that curve.
//
// The vault's `#sweep` copies and walks the whole entry map on every capture
// and restore, so per-operation cost is expected to grow linearly with the
// entries already held. This metric makes that visible and gives an
// optimization baseline: a later change is judged by the reported slope.
//
// Sizes (retained entries at the time of the operation): 256 (the default
// `maxEntries`), 10 000, and 100 000 (`LIMIT_CEILINGS.maxEntries`); quick
// mode uses 256 and 2048. For each size, one vault with `maxEntries` = size
// is filled once, untimed, to size − 4 entries, and then every timed
// operation runs against that fill:
//
// - `capture.at-<n>` / `capture.core_ms.at-<n>` / `capture.vault_overhead_ms.at-<n>`:
//   one `vault.capture` of `capture1k` (4 findings, all retained, so the
//   vault reaches exactly <n> entries), paired with the core's own scan and
//   redact of the same input as in B3. The capture is revoked (untimed)
//   before the next iteration, so the fill level stays fixed.
// - `restore.at-<n>`: one `vault.restore` of `restore64` over a fresh
//   `capture1k` capture (setup, untimed). The restore consumes the four
//   entries' whole budget, so the vault is back to the fill level afterwards.
// - `capture.vault_overhead_ms.ms_per_1k_entries`, `restore.ms_per_1k_entries`:
//   least-squares slope of the per-size medians against entry count, in ms
//   per 1000 entries. Deterministic-kind and non-gating: informational.
// - `capture.vault_overhead_ms.loglog_exponent`, `restore.loglog_exponent`:
//   log-log slope of the medians between the two largest sizes, where the
//   per-entry term dominates the fixed cost. ≈1 means O(n), ≈0 means flat.
//
// Filling. Filling to N with one-finding captures is itself O(N²) because
// every capture sweeps. The fill is built once per size per `run()` from
// multi-finding captures of FILL_CHUNK synthetic AWS-key-shaped values each
// (the core's scan cost grows faster than linearly with findings per input,
// so chunks stay moderate). Fill values are generated deterministically here:
// `AKIASYNTHETIC` plus a 7-character base-36 counter, one per line, so every
// value is distinct and is detected as `aws_access_key_id` / `redact` by the
// pinned core. Each fill capture checks that it retained exactly its chunk,
// and the whole fill checks `stats().entries`. No fill value, token, or
// restored value is ever returned.
//
// Iterations scale down with size (ITERATION_SHARE) so the whole metric
// stays within about two minutes in full mode. PII off only, like B3.

import { median } from "../lib/stats.mjs";

export const id = "entry-scaling";
export const issue = 78;
export const title = "Scaling of capture and restore by retained entry count";
export const piiModes = ["off"];

const SINK = "bench-sink";
const FULL_SIZES = Object.freeze([256, 10_000, 100_000]);
const QUICK_SIZES = Object.freeze([256, 2048]);
/** Fraction of ctx.iterations / ctx.warmup run at a size. */
const ITERATION_SHARE = Object.freeze({ 256: 1, 2048: 0.5, 10000: 0.3, 100000: 0.1 });
const MIN_ITERATIONS = 10;
export const FILL_CHUNK = 250;
const FILL_ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function expectCount(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${expected}, got ${actual}`);
}

/** The fill value suffix for index i: 7 base-36 characters. */
function fillId(i) {
  let s = "";
  let n = i;
  for (let k = 0; k < 7; k += 1) {
    s = FILL_ID_ALPHABET[n % 36] + s;
    n = Math.floor(n / 36);
  }
  return s;
}

/** One fill input holding `count` distinct synthetic AWS key ids, starting at `start`. */
export function fillInput(start, count) {
  let text = "";
  for (let i = start; i < start + count; i += 1) text += `key AKIASYNTHETIC${fillId(i)} retired\n`;
  return text;
}

/** Least-squares slope of y against x. */
export function linearSlope(xs, ys) {
  if (xs.length !== ys.length || xs.length < 2) throw new RangeError("need at least two points");
  const n = xs.length;
  const mx = xs.reduce((a, b) => a + b, 0) / n;
  const my = ys.reduce((a, b) => a + b, 0) / n;
  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i += 1) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  if (den === 0) throw new RangeError("x values must differ");
  return num / den;
}

/**
 * Log-log slope between the two largest x: the growth exponent where the
 * per-entry term dominates. null when either y is not positive.
 */
export function logLogExponent(xs, ys) {
  const order = xs.map((_, i) => i).sort((a, b) => xs[a] - xs[b]);
  const [i, j] = order.slice(-2);
  if (!(ys[i] > 0 && ys[j] > 0) || xs[i] === xs[j]) return null;
  return Math.log(ys[j] / ys[i]) / Math.log(xs[j] / xs[i]);
}

function iterationsFor(ctx, size) {
  const share = ITERATION_SHARE[size] ?? 1;
  return {
    iterations: Math.max(MIN_ITERATIONS, Math.round(ctx.iterations * share)),
    warmup: Math.round(ctx.warmup * share),
  };
}

async function filledVault(ctx, size, opEntries) {
  const { LIMIT_CEILINGS } = ctx.vault;
  const vault = await ctx.vault.createVault({
    limits: { maxEntries: size, maxRetainedBytes: LIMIT_CEILINGS.maxRetainedBytes },
  });
  try {
    const target = size - opEntries;
    const options = { release: [{ sink: SINK, paths: ["body"] }] };
    for (let start = 0; start < target; start += FILL_CHUNK) {
      const count = Math.min(FILL_CHUNK, target - start);
      const captured = vault.capture(fillInput(start, count), options);
      expectCount(captured.tokens.length, count, "fill entries");
    }
    expectCount(vault.stats().entries, target, "filled entries");
    return vault;
  } catch (error) {
    vault.dispose();
    throw error;
  }
}

async function measureCapture(ctx, vault, size, counts) {
  const item = ctx.corpus.items.capture1k;
  const input = item.input;
  const expected = item.findings.piiOff;
  const { core } = ctx;
  const limits = { maxInputBytes: ctx.vault.DEFAULT_LIMITS.maxInputBytes, maxFindings: ctx.vault.DEFAULT_LIMITS.maxFindings };
  const options = { release: [{ sink: SINK, paths: ["body"] }] };
  const paired = await ctx.samplePaired({
    ...counts,
    setup: () => ({}),
    a: (state) => {
      const findings = core.scan(input, { limits });
      state.coreText = core.redact(input, findings, { placeholderFormatter: core.defaultPlaceholderFormatter, limits });
      state.coreFindings = findings.length;
    },
    b: (state) => {
      state.captured = vault.capture(input, options);
    },
    teardown: (state) => {
      expectCount(state.coreFindings, expected, "core findings");
      expectCount(state.captured.tokens.length, expected, "capture entries");
      expectCount(vault.stats().entries, size, "entries at capture");
      vault.revoke(state.captured.captureId);
    },
  });
  const params = { entries: size, item: "capture1k", findings: expected };
  return {
    overhead: paired.diff,
    raw: [
      // The total and the core share move with the pinned core; the overhead
      // is the release signal, as in B3.
      { name: `capture.at-${size}`, kind: "latency", unit: "ms", samples: paired.b, params, gating: false },
      { name: `capture.core_ms.at-${size}`, kind: "latency", unit: "ms", samples: paired.a, params, gating: false },
      { name: `capture.vault_overhead_ms.at-${size}`, kind: "latency", unit: "ms", samples: paired.diff, params },
    ],
  };
}

async function measureRestore(ctx, vault, size, counts) {
  const source = ctx.corpus.items.capture1k;
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;
  const paths = templates.map((f) => f.path);
  const options = { release: [{ sink: SINK, paths }], maxUses: usesPerToken };
  const samples = await ctx.sample({
    ...counts,
    setup: () => {
      const captured = vault.capture(source.input, options);
      const fields = {};
      for (const f of templates) fields[f.path] = f.before + captured.tokens[f.slot].token + f.after;
      return { captureId: captured.captureId, request: { sink: SINK, captures: [captured.captureId], fields } };
    },
    op: (state) => {
      state.restored = vault.restore(state.request).restored;
    },
    teardown: (state) => {
      expectCount(state.restored, templates.length, "restored occurrences");
      vault.revoke(state.captureId);
      expectCount(vault.stats().entries, size - source.findings.piiOff, "entries after restore");
    },
  });
  return {
    samples,
    raw: [
      {
        name: `restore.at-${size}`,
        kind: "latency",
        unit: "ms",
        samples,
        params: { entries: size, fields: templates.length, tokenOccurrences: templates.length },
      },
    ],
  };
}

function slopeMeasurements(prefix, sizes, medians) {
  const params = { sizes: sizes.join("/"), statistic: "p50" };
  const out = [
    {
      name: `${prefix}.ms_per_1k_entries`,
      kind: "deterministic",
      unit: "ms",
      value: linearSlope(sizes, medians) * 1000,
      params,
      gating: false,
    },
  ];
  const exponent = logLogExponent(sizes, medians);
  if (exponent !== null) {
    out.push({ name: `${prefix}.loglog_exponent`, kind: "deterministic", unit: "exponent", value: exponent, params, gating: false });
  }
  return out;
}

export async function run(ctx) {
  const sizes = ctx.quick ? QUICK_SIZES : FULL_SIZES;
  const opEntries = ctx.corpus.items.capture1k.findings.piiOff;
  const raw = [];
  const overheadMedians = [];
  const restoreMedians = [];
  for (const size of sizes) {
    const counts = iterationsFor(ctx, size);
    const vault = await filledVault(ctx, size, opEntries);
    try {
      const capture = await measureCapture(ctx, vault, size, counts);
      const restore = await measureRestore(ctx, vault, size, counts);
      raw.push(...capture.raw, ...restore.raw);
      overheadMedians.push(median(capture.overhead));
      restoreMedians.push(median(restore.samples));
    } finally {
      vault.dispose();
    }
  }
  raw.push(...slopeMeasurements("capture.vault_overhead_ms", sizes, overheadMedians));
  raw.push(...slopeMeasurements("restore", sizes, restoreMedians));
  return raw;
}
