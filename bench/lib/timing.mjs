// Timing primitives: process.hrtime.bigint(), an untimed warmup, then a fixed
// number of timed iterations. No adaptive iteration counts, so two runs with
// the same settings always take the same number of samples.

const NS_PER_MS = 1_000_000;

function isThenable(value) {
  return value !== null && (typeof value === "object" || typeof value === "function") && typeof value.then === "function";
}

/**
 * Times one call of `op(state)` in milliseconds. Awaits the result only when
 * `op` returns a promise, so a synchronous operation is timed without an
 * extra microtask turn.
 */
export async function timeOnce(op, state) {
  const start = process.hrtime.bigint();
  const result = op(state);
  if (isThenable(result)) await result;
  const end = process.hrtime.bigint();
  return Number(end - start) / NS_PER_MS;
}

/**
 * Runs `warmup` untimed and then `iterations` timed calls of `op`, each
 * wrapped by optional untimed `setup()` (whose return value is passed to `op`
 * and `teardown`) and `teardown(state)`.
 *
 * Returns the timed samples in milliseconds, in call order.
 */
export async function sample({ op, setup, teardown, warmup = 0, iterations }) {
  if (!Number.isInteger(iterations) || iterations < 1) throw new TypeError("iterations must be a positive integer");
  if (!Number.isInteger(warmup) || warmup < 0) throw new TypeError("warmup must be a non-negative integer");
  const samples = [];
  for (let i = 0; i < warmup + iterations; i += 1) {
    const state = setup === undefined ? undefined : await setup(i);
    const ms = await timeOnce(op, state);
    if (teardown !== undefined) await teardown(state);
    if (i >= warmup) samples.push(ms);
  }
  return samples;
}

/**
 * Paired sampling of two operations on the same state per iteration, for
 * splits such as `core_ms` vs the whole capture. The order of `a` and `b`
 * alternates every iteration so neither systematically runs on a warmer
 * cache. Returns `{ a, b, diff }` where `diff[i] = b[i] - a[i]`.
 */
export async function samplePaired({ a, b, setup, teardown, warmup = 0, iterations }) {
  if (!Number.isInteger(iterations) || iterations < 1) throw new TypeError("iterations must be a positive integer");
  const out = { a: [], b: [], diff: [] };
  for (let i = 0; i < warmup + iterations; i += 1) {
    const state = setup === undefined ? undefined : await setup(i);
    let ta;
    let tb;
    if (i % 2 === 0) {
      ta = await timeOnce(a, state);
      tb = await timeOnce(b, state);
    } else {
      tb = await timeOnce(b, state);
      ta = await timeOnce(a, state);
    }
    if (teardown !== undefined) await teardown(state);
    if (i >= warmup) {
      out.a.push(ta);
      out.b.push(tb);
      out.diff.push(tb - ta);
    }
  }
  return out;
}
