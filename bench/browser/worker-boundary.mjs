#!/usr/bin/env node
// B5 (#79), mode pair 3: dedicated-Worker ÷ main-thread vault, in Chromium.
//
//   npm run build && node bench/browser/worker-boundary.mjs [--quick] [--out file]
//                                                           [--iterations N] [--warmup N]
//
// Worker mode is browser-only (`@redact-secret/vault/worker` + `/worker/host`
// over a real `new Worker()`; Node's worker_threads is not a supported
// port), so this is a separate script rather than a `bench/metrics/` file:
// the harness runs metrics in-process in Node.js. It writes the same
// `redact-secret-vault/bench-result@1` result (kind `run`, metric id
// `mode-worker`), validated and leak-checked by the harness's own
// `writeResult`, to `.bench-results/worker-boundary-<time>.json` by default.
//
// How: a tiny page is bundled with Vite from the workspace build (the app
// lives in the gitignored `.bench-cache/worker-boundary/`, so bare imports
// resolve to the workspace packages and the repository's pinned core), served
// from localhost with COOP/COEP so the page is cross-origin isolated (Chromium
// then gives `performance.now()` 5 µs resolution instead of 100 µs), and run
// in headless Chromium through Playwright. The page initializes the core with
// PII off and creates a main-thread vault; the Worker script starts
// `startVaultWorkerHost({ pii: [] })`. Per iteration, in alternating order,
// the same operation runs on both vaults on its own fresh captures:
//
//   rtt.*      stats(): the smallest request, i.e. the message round-trip floor
//   capture.*  capture of corpus-v1 `capture1k`
//   restore.*  restore of `restore64` (64 fields) over a fresh capture
//   revoke.*   revoke of a 4-entry capture
//
// For each: `<op>.main`, `<op>.worker`, `<op>.boundary_ms` (worker − main,
// paired per iteration), and `<op>.ratio` (p50 worker ÷ p50 main). The page
// returns timing numbers only.
//
// Ratios are omitted where the main-thread p50 is under 0.05 ms (10 timer
// ticks): rtt and revoke. Set BENCH_DEBUG=1 to print the page's console.
//
// Chromium only. When Playwright's Chromium is not installed the script
// writes a result with the metric `skipped` and exits 0.

import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { pathToFileURL } from "node:url";

import { loadCorpus } from "../corpus/v1/index.mjs";
import { parseCommonArgs } from "../lib/cli.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { formatLine, newResult, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { describeSide, loadWorkspaceSide, REPO_ROOT } from "../lib/sides.mjs";

const METRIC = { id: "mode-worker", issue: 79, title: "Mode boundary cost: dedicated Worker vs main thread" };
const APP = join(REPO_ROOT, ".bench-cache", "worker-boundary");
const USAGE = "usage: node bench/browser/worker-boundary.mjs [--quick] [--out file] [--iterations N] [--warmup N]";

const PAGE = `import { createVault } from "@redact-secret/vault";
import { createWorkerVault } from "@redact-secret/vault/worker";
import * as core from "@redact-secret/core";
import input from "./input.json";

const SINK = "bench-sink";

function paired(iterations, warmup, setup, a, b, teardown) {
  return (async () => {
    const out = { a: [], b: [] };
    for (let i = 0; i < warmup + iterations; i += 1) {
      const state = await setup();
      let ta;
      let tb;
      const runA = async () => { const t = performance.now(); await a(state); ta = performance.now() - t; };
      const runB = async () => { const t = performance.now(); await b(state); tb = performance.now() - t; };
      if (i % 2 === 0) { await runA(); await runB(); } else { await runB(); await runA(); }
      await teardown(state);
      if (i >= warmup) { out.a.push(ta); out.b.push(tb); }
    }
    return out;
  })();
}

function expect(actual, expected) {
  if (actual !== expected) throw Object.assign(new Error("unexpected count"), { code: "UNEXPECTED_COUNT" });
}

async function main() {
  const { iterations, warmup, item, restore64 } = input;
  await core.initialize({ pii: [] });
  const main = await createVault();
  const worker = await createWorkerVault(new Worker(new URL("./worker-entry.js", import.meta.url), { type: "module" }), { timeoutMs: 30000 });
  const release = [{ sink: SINK, paths: ["body"] }];
  const rOptions = { release: [{ sink: SINK, paths: restore64.fields.map((f) => f.path) }], maxUses: restore64.usesPerToken };
  const fieldsFor = (tokens) => Object.fromEntries(restore64.fields.map((f) => [f.path, f.before + tokens[f.slot].token + f.after]));
  const samples = {};
  try {
    samples.rtt = await paired(iterations, warmup, () => ({}),
      (s) => { s.m = main.stats(); }, async (s) => { s.w = await worker.stats(); },
      (s) => { expect(s.m.entries, 0); expect(s.w.entries, 0); });
    samples.capture = await paired(iterations, warmup, () => ({}),
      (s) => { s.m = main.capture(item.input, { release }); },
      async (s) => { s.w = await worker.capture(item.input, { release }); },
      async (s) => {
        expect(s.m.tokens.length + s.m.unrestorable, item.findings);
        expect(s.w.tokens.length + s.w.unrestorable, item.findings);
        main.revoke(s.m.captureId);
        await worker.revoke(s.w.captureId);
      });
    samples.restore = await paired(iterations, warmup,
      async () => {
        const m = main.capture(item.input, rOptions);
        const w = await worker.capture(item.input, rOptions);
        return {
          mId: m.captureId, wId: w.captureId,
          mReq: { sink: SINK, captures: [m.captureId], fields: fieldsFor(m.tokens) },
          wReq: { sink: SINK, captures: [w.captureId], fields: fieldsFor(w.tokens) },
        };
      },
      (s) => { s.m = main.restore(s.mReq).restored; },
      async (s) => { s.w = (await worker.restore(s.wReq)).restored; },
      async (s) => {
        expect(s.m, restore64.fields.length);
        expect(s.w, restore64.fields.length);
        main.revoke(s.mId);
        await worker.revoke(s.wId);
      });
    samples.revoke = await paired(iterations, warmup,
      async () => ({ mId: main.capture(item.input, { release }).captureId, wId: (await worker.capture(item.input, { release })).captureId }),
      (s) => { s.m = main.revoke(s.mId); }, async (s) => { s.w = await worker.revoke(s.wId); },
      (s) => { expect(s.m, item.findings); expect(s.w, item.findings); });
    const artifact = core.artifact();
    return {
      samples,
      coreVersion: core.VERSION,
      artifact: typeof artifact === "string" ? artifact : (artifact?.kind ?? null),
      piiActivation: main.piiActivation ?? null,
      crossOriginIsolated: self.crossOriginIsolated === true,
    };
  } finally {
    main.dispose();
    await worker.dispose();
    worker.terminate();
  }
}

main().then(
  (r) => { window.__result = r; },
  (e) => { console.error(e && e.stack); window.__result = { error: typeof e?.code === "string" ? e.code : (e?.name ?? "Error") }; },
);
`;

const WORKER = `import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
startVaultWorkerHost({ pii: [] });
`;

// 10 ticks of Chromium's cross-origin-isolated performance.now() (5 µs).
const MIN_RATIO_DENOMINATOR_MS = 0.05;

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".json": "application/json" };

function median(samples) {
  const sorted = [...samples].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function bundle(corpus, settings) {
  rmSync(APP, { recursive: true, force: true });
  mkdirSync(APP, { recursive: true });
  const { capture1k, restore64 } = corpus.items;
  writeFileSync(
    join(APP, "input.json"),
    JSON.stringify({
      iterations: settings.iterations,
      warmup: settings.warmup,
      item: { input: capture1k.input, findings: capture1k.findings.piiOff },
      restore64: { fields: restore64.fields, usesPerToken: restore64.usesPerToken },
    }),
  );
  writeFileSync(join(APP, "index.html"), '<!doctype html><html><head><meta charset="utf-8"><title>worker boundary</title></head><body><script type="module" src="./main.js"></script></body></html>');
  writeFileSync(join(APP, "main.js"), PAGE);
  writeFileSync(join(APP, "worker-entry.js"), WORKER);
  const { build } = await import("vite");
  await build({
    root: APP,
    logLevel: "warn",
    build: { outDir: join(APP, "dist"), emptyOutDir: true, assetsInlineLimit: 0, modulePreload: { polyfill: false }, target: "es2022" },
    worker: { format: "es" },
  });
}

function serve() {
  const dist = join(APP, "dist");
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const path = normalize(url.pathname === "/" ? "/index.html" : url.pathname);
    const file = join(dist, path);
    if (!file.startsWith(dist) || !existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp",
      "cross-origin-resource-policy": "same-origin",
    });
    res.end(readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function measurementsFrom(samples, params) {
  const out = [];
  const opParams = {
    rtt: {},
    capture: { item: "capture1k", findings: 4 },
    restore: { fields: 64, tokenOccurrences: 64 },
    revoke: { entries: 4 },
  };
  for (const op of ["rtt", "capture", "restore", "revoke"]) {
    const { a: main, b: worker } = samples[op];
    if (!(Array.isArray(main) && Array.isArray(worker) && main.length > 0 && main.length === worker.length)) {
      throw new Error(`page returned no ${op} samples`);
    }
    const p = { ...params, ...opParams[op] };
    const mainP50 = median(main);
    out.push(
      { name: `${op}.main`, kind: "latency", unit: "ms", samples: main, params: p },
      { name: `${op}.worker`, kind: "latency", unit: "ms", samples: worker, params: p },
      { name: `${op}.boundary_ms`, kind: "latency", unit: "ms", samples: worker.map((w, i) => w - main[i]), params: p },
    );
    // A main-thread p50 within a few timer ticks has no meaningful ratio
    // (stats and revoke take well under a microsecond); boundary_ms is the
    // figure for those.
    if (mainP50 >= MIN_RATIO_DENOMINATOR_MS) {
      out.push({
        name: `${op}.ratio`,
        kind: "deterministic",
        unit: "ratio",
        value: Math.round((median(worker) / mainP50) * 10_000) / 10_000,
        params: { ...p, of: "p50 worker / p50 main" },
      });
    }
  }
  return out;
}

async function main() {
  const { values, settings } = parseCommonArgs(process.argv.slice(2));
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (values.pii !== "off") throw new Error("worker-boundary measures PII off only");
  const corpus = loadCorpus();
  const side = await loadWorkspaceSide();
  const entry = { ...METRIC, status: "ok", measurements: [] };
  let pageInfo = null;

  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    entry.status = "skipped";
    entry.reason = "playwright is not installed";
  }
  if (entry.status === "ok") {
    await bundle(corpus, settings);
    const server = await serve();
    let browser;
    try {
      try {
        browser = await chromium.launch();
      } catch {
        entry.status = "skipped";
        entry.reason = "playwright chromium is not installed";
      }
      if (browser !== undefined) {
        const page = await browser.newPage();
        if (process.env.BENCH_DEBUG) {
          // Error stacks only; the page never logs an input or a token.
          page.on("console", (m) => console.log("page:", m.text()));
          page.on("pageerror", (e) => console.log("pageerror:", e.message));
        }
        await page.goto(`http://127.0.0.1:${server.address().port}/`);
        await page.waitForFunction(() => window.__result !== undefined, null, { timeout: 600_000 });
        const r = await page.evaluate(() => window.__result);
        if (typeof r.error === "string") {
          entry.status = "failed";
          entry.reason = r.error.slice(0, 80);
        } else {
          pageInfo = r;
          const params = { browser: `chromium ${browser.version()}`.slice(0, 80), crossOriginIsolated: r.crossOriginIsolated };
          entry.raw = measurementsFrom(r.samples, params);
        }
      }
    } finally {
      await browser?.close();
      server.close();
      rmSync(APP, { recursive: true, force: true });
    }
  }

  // The side is the workspace build as the browser ran it: the page's core
  // artifact (wasm in a browser) and PII activation, not Node's.
  side.piiActivation = pageInfo?.piiActivation ?? null;
  side.artifact = pageInfo?.artifact ?? null;
  if (pageInfo !== null && pageInfo.coreVersion !== side.packages.core.version) throw new Error("page core version differs from the workspace core");
  const result = newResult({
    kind: "run",
    piiMode: "off",
    quick: values.quick,
    settings,
    corpus,
    environment: captureEnvironment(),
    sides: [describeSide(side)],
  });
  const { raw = [], ...rest } = entry;
  result.metrics.push({ ...rest, measurements: raw.map((m) => toResultMeasurement(m, side.label)) });
  const stamp = result.createdAt.replace(/[:.]/g, "-");
  const out = values.out ?? join(REPO_ROOT, ".bench-results", `worker-boundary-${stamp}.json`);
  await writeResult(result, out);

  const [metric] = result.metrics;
  if (metric.status !== "ok") console.log(`${metric.id} ${metric.status}: ${metric.reason}`);
  for (const m of metric.measurements) console.log(formatLine(result, metric.id, m));
  console.log(`wrote ${out}`);
  return metric.status === "failed" ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error?.stack ?? String(error));
      process.exitCode = 1;
    },
  );
}
