// B6 (#80): heap retained per vault entry, and how much of it comes back
// after `revoke()` and after `dispose()`.
//
// Every figure is taken in a fresh child process started with
// `node --expose-gc`, one child per size, so the harness process's flags,
// JIT state, and heap history do not matter and `gc()` is available. The
// child loads the same side's core and vault from their package directories
// (bench/metrics/support/distribution.mjs, as B8's cold-init does), activates
// the core for the run's PII mode, and checks that the core artifact and the
// vault's PII activation match the harness's.
//
// One cycle, at N retained entries (heapUsed after two forced full GCs is
// "the heap"):
//
//   create vault (maxEntries = N)             -> heap h0
//   fill to N entries, drop every result
//     except the capture ids                  -> heap h1
//   revoke every capture  | or  dispose()     -> heap h2   (vault still referenced)
//
//   growth                  = h1 − h0
//   bytes_per_entry         = growth ÷ N
//   heap_per_retained_byte  = growth ÷ stats().retainedBytes   (value bytes the vault accounts)
//   unreclaimed_ratio       = (h2 − h0) ÷ growth               (0 = all returned, 1 = none)
//
// The revoke and dispose paths each use their own vault (a revoke-then-
// dispose sequence would leave dispose nothing to return). The vault object
// stays referenced after dispose on purpose: the claim under test is that a
// disposed vault a caller still holds does not keep the values or the
// entry maps alive. Capture ids are held by the child (about 40 short strings
// at 10 000 entries), and the fill inputs and capture results are dropped.
//
// Filling reuses B4's deterministic fill (`fillInput`, chunks of FILL_CHUNK =
// 250 findings per capture; many findings per capture is super-linear in the
// core), so values are distinct synthetic AWS-key-shaped strings. Nothing but
// numbers crosses the process boundary.
//
// Noise and the compare rule. heapUsed after forced GC still moves by a few
// KiB between identical cycles (allocation-site feedback, inline caches,
// map/hash-table capacity). Each child runs one untimed warm-up cycle and
// then REPEATS cycles per path, and reports medians. The harness schema allows
// "ms" only for latency samples, so these are deterministic-kind values, and
// bench:compare compares deterministic values from round 0 only: the median
// inside that one child is what makes a single round usable.
//
// Threshold. `heap.unreclaimed_ratio.dispose.at-10000` carries
// `threshold: { max: 0.1 }`: more than 10% of the fill's heap growth still
// live after dispose() and two full GCs is a non-reclaiming vault and fails
// the metric (bench:run exits non-zero, bench:compare marks it fail). At 10 000
// entries the growth is megabytes, so 10% is far above the KiB-level noise;
// at 256 entries the growth is about 90 KiB and the same noise is 5–10% of
// it, so the 256 figures are reported without a threshold. The revoke path
// is informational too: revoke-all leaves an empty but live vault, and the
// bounded-memory claim this backs is about dispose().
//
// Every run() spawns two children (one per size), about 2 s each in full
// mode. bench:compare calls run() every round although it only compares
// round 0's deterministic values.
//
// Sizes: 256 (default maxEntries) and 10 000 in both modes; quick mode runs
// fewer repeats. PII off only, like B3/B4.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { PII_SELECTORS, publicEntry } from "../lib/sides.mjs";
import { sideDirs } from "./support/distribution.mjs";

export const id = "entry-memory";
export const issue = 80;
export const title = "Heap per retained entry and reclaim after revoke and dispose";
export const piiModes = ["off"];

/**
 * Each call already reports a median over REPEATS cycles in its own child, so
 * bench:compare runs three rounds (the median of three medians) instead of
 * every round at about 4 s per call.
 */
export const compareRounds = 3;

export const SIZES = Object.freeze([256, 10_000]);
export const REPEATS = Object.freeze({ full: 7, quick: 3 });
/** Largest unreclaimed share of the fill's heap growth after dispose() (10 000 entries). */
export const DISPOSE_UNRECLAIMED_MAX = 0.1;
const GATED_SIZE = 10_000;

const FILL_MODULE = pathToFileURL(fileURLToPath(new URL("./entry-scaling.mjs", import.meta.url))).href;

// Runs in the child. Reads its inputs from the environment and prints one
// JSON object of numbers (and the core artifact label) on stdout.
const CHILD = `
if (typeof globalThis.gc !== "function") throw new Error("gc unavailable");
const core = await import(process.env.BENCH_B6_CORE);
const selectors = JSON.parse(process.env.BENCH_B6_PII);
if (typeof core.piiActivation === "function") await core.initialize({ pii: selectors });
else if (selectors.length > 0) throw new Error("core has no PII surface");
else await core.initialize();
const vaultModule = await import(process.env.BENCH_B6_VAULT);
const { fillInput, FILL_CHUNK } = await import(process.env.BENCH_B6_FILL);
const size = Number(process.env.BENCH_B6_SIZE);
const repeats = Number(process.env.BENCH_B6_REPEATS);
const options = { release: [{ sink: "bench-sink", paths: ["body"] }] };
const { LIMIT_CEILINGS } = vaultModule;

async function settledHeap() {
  for (let i = 0; i < 2; i += 1) {
    globalThis.gc();
    await new Promise((r) => setImmediate(r));
  }
  return process.memoryUsage().heapUsed;
}

function fill(vault) {
  const ids = [];
  for (let start = 0; start < size; start += FILL_CHUNK) {
    const count = Math.min(FILL_CHUNK, size - start);
    const captured = vault.capture(fillInput(start, count), options);
    if (captured.tokens.length !== count) throw new Error("fill retained a different count");
    ids.push(captured.captureId);
  }
  return ids;
}

let piiActivation = null;
async function cycle(path) {
  let vault = await vaultModule.createVault({ limits: { maxEntries: size, maxRetainedBytes: LIMIT_CEILINGS.maxRetainedBytes } });
  piiActivation = vault.piiActivation ?? null;
  const h0 = await settledHeap();
  const ids = fill(vault);
  const stats = vault.stats();
  if (stats.entries !== size) throw new Error("fill entry count mismatch");
  const retainedBytes = stats.retainedBytes;
  const h1 = await settledHeap();
  if (path === "revoke") {
    let removed = 0;
    for (const id of ids) removed += vault.revoke(id);
    if (removed !== size || vault.stats().entries !== 0) throw new Error("revoke removed a different count");
  } else {
    vault.dispose();
    if (vault.stats().disposed !== true) throw new Error("vault not disposed");
  }
  const h2 = await settledHeap();
  const growth = h1 - h0;
  const result = { growth, retainedBytes, remaining: h2 - h0 };
  if (path === "revoke") vault.dispose();
  vault = null;
  return result;
}

await cycle("dispose"); // untimed warm-up: compiles and shapes every path once
const out = { revoke: [], dispose: [] };
for (let r = 0; r < repeats; r += 1) {
  out.revoke.push(await cycle("revoke"));
  out.dispose.push(await cycle("dispose"));
}
process.stdout.write(JSON.stringify({ artifact: typeof core.artifact === "function" ? core.artifact() : null, piiActivation, ...out }));
`;

/** Median of a non-empty number array. */
export function medianOf(values) {
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 === 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * Per-path figures from one child's cycles: medians over repeats of bytes per
 * entry, heap per retained value byte, and the unreclaimed share.
 */
export function summarizeCycles(cycles, size) {
  for (const c of cycles) {
    if (!(Number.isFinite(c.growth) && Number.isFinite(c.remaining) && c.retainedBytes > 0)) {
      throw new Error("entry-memory child returned no figures");
    }
    // A fill that did not grow the heap cannot give a reclaim ratio.
    if (!(c.growth > 0)) throw new Error("entry-memory fill did not grow the heap");
  }
  return {
    bytesPerEntry: medianOf(cycles.map((c) => c.growth / size)),
    perRetainedByte: medianOf(cycles.map((c) => c.growth / c.retainedBytes)),
    unreclaimed: medianOf(cycles.map((c) => c.remaining / c.growth)),
  };
}

function spawnChild(env) {
  const child = spawnSync(process.execPath, ["--expose-gc", "--input-type=module", "-e", CHILD], {
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
    maxBuffer: 1 << 20,
  });
  // The child's stderr is not surfaced: only its exit status is.
  if (child.error !== undefined || child.status !== 0) {
    const error = new Error("entry-memory child failed");
    error.code = child.error?.code ?? "CHILD_EXIT";
    throw error;
  }
  return JSON.parse(child.stdout);
}

export async function run(ctx) {
  const dirs = sideDirs(ctx.side);
  const repeats = ctx.quick ? REPEATS.quick : REPEATS.full;
  const expectedArtifact = typeof ctx.core.artifact === "function" ? ctx.core.artifact() : null;
  const raw = [];
  for (const size of SIZES) {
    const env = {
      ...process.env,
      BENCH_B6_CORE: pathToFileURL(publicEntry(dirs.core)).href,
      BENCH_B6_VAULT: pathToFileURL(publicEntry(dirs.vault)).href,
      BENCH_B6_FILL: FILL_MODULE,
      BENCH_B6_PII: JSON.stringify(PII_SELECTORS[ctx.pii.mode]),
      BENCH_B6_SIZE: String(size),
      BENCH_B6_REPEATS: String(repeats),
    };
    const out = spawnChild(env);
    if (out.artifact !== expectedArtifact) throw new Error(`child loaded core artifact ${out.artifact}, harness has ${expectedArtifact}`);
    if (out.piiActivation !== ctx.side.piiActivation) throw new Error("child vault adopted a different PII activation than the harness");

    const revoke = summarizeCycles(out.revoke, size);
    const dispose = summarizeCycles(out.dispose, size);
    const params = { entries: size, repeats, statistic: "median", runtime: "node", artifact: String(expectedArtifact) };
    const gated = size === GATED_SIZE;
    raw.push(
      // Growth figures come from both paths' fills; the dispose path's are
      // reported (the revoke path's fills are the same operation).
      { name: `heap.bytes_per_entry.at-${size}`, kind: "deterministic", unit: "bytes", value: dispose.bytesPerEntry, params, gating: false },
      {
        name: `heap.per_retained_byte.at-${size}`,
        kind: "deterministic",
        unit: "ratio",
        value: dispose.perRetainedByte,
        params,
        gating: false,
      },
      { name: `heap.unreclaimed_ratio.revoke.at-${size}`, kind: "deterministic", unit: "ratio", value: revoke.unreclaimed, params, gating: false },
      gated
        ? {
            name: `heap.unreclaimed_ratio.dispose.at-${size}`,
            kind: "deterministic",
            unit: "ratio",
            value: dispose.unreclaimed,
            threshold: { max: DISPOSE_UNRECLAIMED_MAX },
            params,
          }
        : { name: `heap.unreclaimed_ratio.dispose.at-${size}`, kind: "deterministic", unit: "ratio", value: dispose.unreclaimed, params, gating: false },
    );
  }
  return raw;
}
