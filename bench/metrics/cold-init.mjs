// B8 (#82): cold `createVault()` in Node.js, one fresh child process per
// sample, including the core's native addon (or WebAssembly) load.
//
// Each child imports the side's core, initializes it for the run's PII mode,
// then imports the side's vault and awaits `createVault()`:
//
//   cold_init.core_ms     import core + core.initialize()   (moves with the pinned core; informational)
//   cold_init.vault_ms    import vault + createVault()      (the vault's own cold start; the release signal)
//   cold_init.total_ms    the two together                  (informational)
//   cold_init.process_ms  parent-side spawn to exit, including Node.js startup (informational)
//
// Times inside the child use performance.now() from before the first import,
// so Node.js startup is excluded from all but process_ms. The vault resolves
// the same core module the child imported (the vault fails NOT_INITIALIZED
// otherwise). The child reports the core artifact and the vault's PII activation,
// which must match the harness's own, so the child loads the same core build
// (addon or wasm) in the same PII mode.
//
// "Cold" means a fresh process and module graph; the OS file cache is warm:
// one untimed spawn per run() call absorbs first-touch disk and code-signing
// cost, which otherwise dominates a single sample. Spawns run sequentially.
// Samples per run() call: 20 (quick: 3); the A/B runner pools them over rounds.
// No input, output, or captured value crosses the process boundary: the child
// creates an empty vault and prints three numbers and an artifact label.

import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { PII_SELECTORS, publicEntry } from "../lib/sides.mjs";
import { sideDirs } from "./support/distribution.mjs";

export const id = "cold-init";
export const issue = 82;
export const title = "Cold createVault() in a fresh Node.js process";

export const SPAWNS = Object.freeze({ full: 20, quick: 3 });

const CHILD = `
const t0 = performance.now();
const core = await import(process.env.BENCH_B8_CORE);
const selectors = JSON.parse(process.env.BENCH_B8_PII);
if (typeof core.piiActivation === "function") await core.initialize({ pii: selectors });
else if (selectors.length > 0) throw new Error("core has no PII surface");
else await core.initialize();
const t1 = performance.now();
const vault = await import(process.env.BENCH_B8_VAULT);
const created = await vault.createVault();
const t2 = performance.now();
const piiActivation = created.piiActivation ?? null;
created.dispose();
process.stdout.write(JSON.stringify({ core: t1 - t0, vault: t2 - t1, artifact: typeof core.artifact === "function" ? core.artifact() : null, piiActivation }));
`;

function spawnOnce(env) {
  const start = process.hrtime.bigint();
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", CHILD], {
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
  });
  const processMs = Number(process.hrtime.bigint() - start) / 1e6;
  // The child's stderr is not surfaced: only its exit status is.
  if (child.error !== undefined || child.status !== 0) {
    const error = new Error("cold-init child failed");
    error.code = child.error?.code ?? "CHILD_EXIT";
    throw error;
  }
  const parsed = JSON.parse(child.stdout);
  if (!(Number.isFinite(parsed.core) && Number.isFinite(parsed.vault))) throw new Error("cold-init child returned no timing");
  return { ...parsed, processMs };
}

export async function run(ctx) {
  const dirs = sideDirs(ctx.side);
  const env = {
    ...process.env,
    BENCH_B8_CORE: pathToFileURL(publicEntry(dirs.core)).href,
    BENCH_B8_VAULT: pathToFileURL(publicEntry(dirs.vault)).href,
    BENCH_B8_PII: JSON.stringify(PII_SELECTORS[ctx.pii.mode]),
  };
  const expectedArtifact = typeof ctx.core.artifact === "function" ? ctx.core.artifact() : null;
  const spawns = ctx.quick ? SPAWNS.quick : SPAWNS.full;

  spawnOnce(env); // untimed: warms the OS file cache
  const core = [];
  const vault = [];
  const total = [];
  const processMs = [];
  for (let i = 0; i < spawns; i += 1) {
    const s = spawnOnce(env);
    if (s.artifact !== expectedArtifact) throw new Error(`child loaded core artifact ${s.artifact}, harness has ${expectedArtifact}`);
    if (s.piiActivation !== ctx.side.piiActivation) throw new Error("child vault adopted a different PII activation than the harness");
    core.push(s.core);
    vault.push(s.vault);
    total.push(s.core + s.vault);
    processMs.push(s.processMs);
  }
  const params = { spawns, runtime: "node", artifact: String(expectedArtifact) };
  return [
    { name: "cold_init.total_ms", kind: "latency", unit: "ms", samples: total, params, gating: false },
    { name: "cold_init.core_ms", kind: "latency", unit: "ms", samples: core, params, gating: false },
    { name: "cold_init.vault_ms", kind: "latency", unit: "ms", samples: vault, params },
    { name: "cold_init.process_ms", kind: "latency", unit: "ms", samples: processMs, params, gating: false },
  ];
}
