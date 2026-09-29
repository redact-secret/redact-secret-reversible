// B8 (#82): distribution size, as deterministic byte counts per side.
//
//   pack.<pkg>.tarball_bytes   `npm pack --dry-run` tarball size (what npm downloads)
//   pack.<pkg>.unpacked_bytes  sum of the packed files' sizes (what lands on disk)
//   pack.<pkg>.files           packed file count (informational)
//   bundle.vault.min_bytes     minified browser bundle of `export { createVault }`
//                              from "@redact-secret/vault", core external (informational)
//   bundle.vault.gzip_bytes    the same, gzip level 9 (what a browser downloads)
//   core.<pkg>.*               the pinned core and its WebAssembly package (informational)
//
// <pkg> is `vault` or `vault-server`. Both sides are packed by the same local
// npm, so the published baseline is re-packed from its install in
// .bench-cache/ instead of using the registry tarball.
//
// The bundle is a production Vite build (the repository's vite devDependency)
// with `@redact-secret/core` external, so it counts only vault code. The core
// is a peer dependency pinned per release; its size is reported under `core.`
// with `gating: false` and never fails the vault.
//
// Thresholds (`maxRatio`, candidate÷baseline, checked by compare.mjs): 1.10
// on the tarball, unpacked, and gzip bundle sizes of both packages. It is the
// epic's latency regression ratio (#74), and byte counts have no noise, so any
// crossing is a real change: a release that grows the vault by more than 10%
// on purpose fails the check and has to say so, instead of drifting upward a
// few percent per release unnoticed. Minified bytes and file counts track the
// same growth as the gated figures and are informational.
//
// Everything is measured once per side per process and cached, so the A/B
// runner's rounds reuse it. PII mode does not change sizes; the metric runs in
// both so either mode's job carries the gate.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import { B8_WORK_DIR, ensureDir, packInfo, sideDirs, sideKey } from "./support/distribution.mjs";

export const id = "dist-size";
export const issue = 82;
export const title = "Distribution size: npm tarball, unpacked, and browser bundle";

export const MAX_RATIO = 1.1;
const GATE = Object.freeze({ maxRatio: MAX_RATIO });

const cache = new Map();

function bytes(name, value, { gated, params } = {}) {
  const m = { name, kind: "deterministic", unit: "bytes", value };
  if (gated) m.threshold = { ...GATE };
  else m.gating = false;
  if (params !== undefined) m.params = params;
  return m;
}

function packMeasurements(prefix, dir, gated) {
  const info = packInfo(dir);
  return [
    bytes(`${prefix}.tarball_bytes`, info.tarball, { gated }),
    bytes(`${prefix}.unpacked_bytes`, info.unpacked, { gated }),
    { name: `${prefix}.files`, kind: "deterministic", unit: "files", value: info.files, gating: false },
  ];
}

/**
 * Minified bundle of the vault's main entry for browsers, core external.
 * Returns summed bytes over every emitted JS chunk (one, today).
 */
export async function bundleVault(vaultDir, workDir) {
  const { build } = await import("vite");
  ensureDir(workDir);
  const entry = join(workDir, "entry.js");
  writeFileSync(entry, 'export { createVault } from "@redact-secret/vault";\n');
  const output = await build({
    configFile: false,
    root: workDir,
    logLevel: "silent",
    resolve: { alias: [{ find: /^@redact-secret\/vault$/, replacement: vaultDir }] },
    build: {
      write: false,
      outDir: join(workDir, "dist"),
      emptyOutDir: false,
      minify: true,
      target: "es2022",
      modulePreload: false,
      rollupOptions: {
        input: entry,
        // Keep the entry's export, or the app build tree-shakes everything.
        preserveEntrySignatures: "strict",
        external: [/^@redact-secret\/core(\/|$)/],
      },
    },
  });
  const chunks = (Array.isArray(output) ? output : [output]).flatMap((o) => o.output).filter((c) => c.type === "chunk");
  if (chunks.length === 0) throw new Error("vite emitted no chunk");
  let min = 0;
  let gzip = 0;
  for (const chunk of chunks) {
    // The core must stay external: a bundled core would count its size as the vault's.
    if (chunk.moduleIds.some((m) => /[\\/]@redact-secret[\\/](core|wasm)[\\/]/.test(m))) throw new Error("core was bundled");
    min += Buffer.byteLength(chunk.code);
    gzip += gzipSync(chunk.code, { level: 9 }).length;
  }
  return { min, gzip, chunks: chunks.length };
}

async function measure(side) {
  const dirs = sideDirs(side);
  const out = [...packMeasurements("pack.vault", dirs.vault, true)];
  if (dirs.vaultServer !== null) out.push(...packMeasurements("pack.vault-server", dirs.vaultServer, true));

  const bundle = await bundleVault(dirs.vault, join(B8_WORK_DIR, `bundle-${sideKey(side)}`));
  const params = { entry: "createVault", core: "external", chunks: bundle.chunks };
  out.push(bytes("bundle.vault.min_bytes", bundle.min, { params }));
  out.push(bytes("bundle.vault.gzip_bytes", bundle.gzip, { gated: true, params: { ...params, gzipLevel: 9 } }));

  for (const [prefix, dir] of [
    ["core.core", dirs.core],
    ["core.wasm", dirs.wasm],
  ]) {
    if (dir === undefined) continue;
    const info = packInfo(dir);
    out.push(bytes(`${prefix}.tarball_bytes`, info.tarball), bytes(`${prefix}.unpacked_bytes`, info.unpacked));
  }
  return out;
}

export async function run(ctx) {
  if (ctx.vaultServer === null) ctx.skip("side has no vault-server");
  const key = sideKey(ctx.side);
  if (!cache.has(key)) cache.set(key, measure(ctx.side));
  const measured = await cache.get(key);
  return measured.map((m) => ({ ...m, ...(m.params === undefined ? {} : { params: { ...m.params } }) }));
}
