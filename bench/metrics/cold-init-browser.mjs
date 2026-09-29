// B8 (#82): cold `createVault()` in one browser engine (Chromium, through the
// repository's playwright devDependency), including the core's WebAssembly
// fetch and compile.
//
// Per side, a production Vite build of a page that dynamically imports the
// side's core, initializes it for the run's PII mode, then dynamically imports
// the side's vault and awaits `createVault()`. It is built once per side per
// process under .bench-cache/b8/ and served from 127.0.0.1 with
// `cache-control: no-store`. Every sample is a new browser context (empty HTTP
// and compiled-code cache) and a fresh page, so each one loads the chunks and
// the .wasm asset from scratch.
//
//   cold_init.browser.total_ms  import core + initialize + import vault + createVault (informational)
//   cold_init.browser.core_ms   import core + core.initialize()   (moves with the pinned core; informational)
//   cold_init.browser.vault_ms  import vault + createVault()      (the release signal)
//
// Timing uses the page's performance.now(), which browsers coarsen (Chromium:
// 0.1 ms without cross-origin isolation); vault_ms is several ms, so that is
// well under the 10% warn ratio. Page and navigation setup are not timed.
// One untimed page per run() call warms the browser process. Each page must
// report the wasm artifact and the harness's PII activation.
// Samples per run() call: 15 (quick: 3), plus one Chromium launch.
//
// Skipped (not failed) when playwright's Chromium is not installed
// (`npx playwright install chromium`) or BENCH_SKIP_BROWSER=1 is set, so
// machines without browsers still run every other metric.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, sep } from "node:path";

import { B8_WORK_DIR, ensureDir, sideDirs, sideKey } from "./support/distribution.mjs";

export const id = "cold-init-browser";
export const issue = 82;
export const title = "Cold createVault() in a fresh Chromium page";

export const PAGES = Object.freeze({ full: 15, quick: 3 });

const MAIN = `
const selectors = new URLSearchParams(location.search).get("pii") === "on" ? ["pii"] : [];
const t0 = performance.now();
const core = await import("@redact-secret/core");
if (typeof core.piiActivation === "function") await core.initialize({ pii: selectors });
else if (selectors.length > 0) throw new Error("core has no PII surface");
else await core.initialize();
const t1 = performance.now();
const vault = await import("@redact-secret/vault");
const created = await vault.createVault();
const t2 = performance.now();
const piiActivation = created.piiActivation ?? null;
created.dispose();
window.__b8 = { core: t1 - t0, vault: t2 - t1, artifact: typeof core.artifact === "function" ? core.artifact() : null, piiActivation };
`;

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm" };
const builds = new Map();

async function loadChromium() {
  if (process.env.BENCH_SKIP_BROWSER === "1") return { reason: "BENCH_SKIP_BROWSER=1" };
  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    return { reason: "playwright is not installed" };
  }
  if (!existsSync(chromium.executablePath())) return { reason: "playwright chromium is not installed" };
  return { chromium };
}

async function buildPage(dirs, workDir) {
  const { build } = await import("vite");
  ensureDir(workDir);
  writeFileSync(
    join(workDir, "index.html"),
    '<!doctype html><html><head><meta charset="utf-8"><title>cold init</title></head><body><script type="module" src="./main.js"></script></body></html>\n',
  );
  writeFileSync(join(workDir, "main.js"), MAIN);
  const outDir = join(workDir, "dist");
  await build({
    configFile: false,
    root: workDir,
    logLevel: "silent",
    resolve: {
      alias: [
        { find: /^@redact-secret\/vault$/, replacement: dirs.vault },
        { find: /^@redact-secret\/core$/, replacement: dirs.core },
      ],
    },
    build: { outDir, emptyOutDir: true, assetsInlineLimit: 0, modulePreload: { polyfill: false }, target: "es2022" },
  });
  return outDir;
}

function serve(root) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const file = join(root, normalize(url.pathname === "/" ? "/index.html" : url.pathname));
    if (!file.startsWith(root + sep) || !existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function samplePage(browser, url) {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(url);
    await page.waitForFunction(() => window.__b8 !== undefined, null, { timeout: 30_000 });
    return await page.evaluate(() => window.__b8);
  } finally {
    await context.close();
  }
}

export async function run(ctx) {
  const { chromium, reason } = await loadChromium();
  if (chromium === undefined) ctx.skip(reason);

  const key = sideKey(ctx.side);
  if (!builds.has(key)) builds.set(key, buildPage(sideDirs(ctx.side), join(B8_WORK_DIR, `browser-${key}`)));
  const root = await builds.get(key);

  const pages = ctx.quick ? PAGES.quick : PAGES.full;
  const server = await serve(root);
  const url = `http://127.0.0.1:${server.address().port}/?pii=${ctx.pii.mode}`;
  const browser = await chromium.launch();
  try {
    const version = browser.version();
    await samplePage(browser, url); // untimed warmup
    const core = [];
    const vault = [];
    const total = [];
    for (let i = 0; i < pages; i += 1) {
      const s = await samplePage(browser, url);
      if (s.artifact !== "wasm") throw new Error(`page loaded core artifact ${s.artifact}, expected wasm`);
      if (s.piiActivation !== ctx.side.piiActivation) throw new Error("page vault adopted a different PII activation than the harness");
      core.push(s.core);
      vault.push(s.vault);
      total.push(s.core + s.vault);
    }
    const params = { pages, runtime: "chromium", browser: version, artifact: "wasm" };
    return [
      { name: "cold_init.browser.total_ms", kind: "latency", unit: "ms", samples: total, params, gating: false },
      { name: "cold_init.browser.core_ms", kind: "latency", unit: "ms", samples: core, params, gating: false },
      { name: "cold_init.browser.vault_ms", kind: "latency", unit: "ms", samples: vault, params },
    ];
  } finally {
    await browser.close();
    server.close();
  }
}
