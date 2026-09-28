// Real-browser qualification for optional Worker mode (#14). Builds a
// production Vite bundle of a consumer app that creates a real dedicated
// Worker importing the packed vault's `./worker/host` entry, drives it
// through the packed `./worker` client, and runs the portable Worker suite
// through Playwright in Chromium, Firefox, and WebKit. This is a separate,
// additional qualification from `qualify:browser`: passing it does not
// change what `qualify:browser` established about main-thread-only use, and
// failing it does not remove main-thread qualification.
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { extname, join, normalize } from "node:path";

import { chromium, firefox, webkit } from "playwright";
import { build } from "vite";

import { makeConsumer, packVault, STRICT_CSP, summarize, writeReport } from "./lib.mjs";

// Adds worker-src explicitly rather than relying on the script-src fallback,
// so the qualification evidence states the exact directive Worker mode
// needs, and so the negative control below (worker-src 'none') can prove
// the failure mode is explicit rather than a silent same-origin allowance.
//
// `new Worker(url)` is itself a Trusted Types sink (it requires a
// TrustedScriptURL, distinct from the `<script src>` sink the main-thread
// suite exercises), so the blanket `trusted-types 'none'` STRICT_CSP uses
// would make Worker creation impossible in an engine that enforces Trusted
// Types. Name one narrow policy instead of disabling the platform's
// strongest DOM-XSS defense for the whole page.
const WORKER_CSP = `${STRICT_CSP.replace("trusted-types 'none'", "trusted-types default")}; worker-src 'self'`;
const NO_WASM_WORKER_CSP = WORKER_CSP.replace(" 'wasm-unsafe-eval'", "");
const NO_WORKER_SRC_CSP = WORKER_CSP.replace("worker-src 'self'", "worker-src 'none'");

const requested = (process.env.BROWSERS ?? "chromium,firefox,webkit").split(",");
const engines = { chromium, firefox, webkit };

const tarball = packVault();
const dir = makeConsumer("worker", tarball);

writeFileSync(
  join(dir, "index.html"),
  `<!doctype html><html><head><meta charset="utf-8"><title>vault worker qualification</title></head>
<body><script type="module" src="./main.js"></script></body></html>`,
);
writeFileSync(
  join(dir, "worker-entry.js"),
  `import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
startVaultWorkerHost();
`,
);
// PII activation control (#39): the Worker script, not the page, states a
// PII selection for its own realm. On a core without a PII surface (the
// pinned beta.9) this must fail closed with PII_UNAVAILABLE; on a PII-capable
// core it must report the activation it observed in the Worker realm.
writeFileSync(
  join(dir, "worker-pii-entry.js"),
  `import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
startVaultWorkerHost({ pii: ["pii"] });
`,
);
writeFileSync(
  join(dir, "main.js"),
  `import { createWorkerVault } from "@redact-secret/vault/worker";
import * as core from "@redact-secret/core";
import corpus from "./corpus.json";
import { runWorkerSuite } from "./worker-suite.js";

const violations = [];
document.addEventListener("securitypolicyviolation", (e) => violations.push(e.effectiveDirective));

const mode = new URLSearchParams(location.search).get("mode");
// Runtime feature detection, as the vault does: the page's core module has a
// PII surface iff it exports a piiActivation function (beta.10+). Read
// dynamically so the bundler does not flag the export beta.9 lacks.
const corePii = typeof Reflect.get(core, "piiActivation") === "function";

// Trusted Types, where the engine supports it (the CSP directive is simply
// unsupported elsewhere): \`new Worker(url)\` is itself a Trusted Types sink,
// distinct from the <script src> sink the main-thread suite exercises. A
// "default" policy is what the platform consults automatically for a sink
// given a plain string/URL, so the literal \`new Worker(new URL(...))\` call
// Vite's build needs to see in order to bundle the worker stays intact; this
// policy performs no rewriting, it only satisfies the sink's type check.
if (window.trustedTypes && typeof window.trustedTypes.createPolicy === "function" && !window.trustedTypes.defaultPolicy) {
  window.trustedTypes.createPolicy("default", { createScriptURL: (url) => url });
}

function makeWorker() {
  return new Worker(new URL("./worker-entry.js", import.meta.url), { type: "module" });
}

async function main() {
  if (mode === "no-worker-src") {
    // The page's own CSP forbids creating the Worker at all. No fallback to
    // main-thread capture may occur; the client must reject explicitly.
    let worker;
    try {
      worker = makeWorker();
    } catch (e) {
      window.__result = { rejected: true, code: "WORKER_UNAVAILABLE", violations, constructorThrew: String(e) };
      return;
    }
    try {
      await createWorkerVault(worker, { timeoutMs: 4000 });
      window.__result = { rejected: false };
    } catch (e) {
      window.__result = { rejected: true, code: e && e.code, violations };
    }
    return;
  }

  if (mode === "pii-select") {
    const worker = new Worker(new URL("./worker-pii-entry.js", import.meta.url), { type: "module" });
    try {
      const vault = await createWorkerVault(worker, { timeoutMs: 10000 });
      window.__result = { corePii, created: true, piiActive: /(^|;)selectors=(?!off(;|$))[^;]+/.test(vault.piiActivation ?? "") };
    } catch (e) {
      window.__result = { corePii, created: false, code: e && e.code, coreCode: e && e.coreCode };
    }
    worker.terminate();
    return;
  }

  if (mode === "expect-mismatch") {
    // The page states an activation the Worker realm cannot have. The client
    // must reject with PII_ACTIVATION_MISMATCH and return no vault.
    const worker = makeWorker();
    try {
      await createWorkerVault(worker, { timeoutMs: 10000, expectPiiActivation: "credentials=full;selectors=qualification-mismatch" });
      window.__result = { created: true };
    } catch (e) {
      window.__result = { created: false, code: e && e.code };
    }
    worker.terminate();
    return;
  }

  if (mode === "no-wasm") {
    // The Worker itself is created, but its CSP forbids WebAssembly
    // compilation, so the core cannot initialize inside it.
    const worker = makeWorker();
    try {
      await createWorkerVault(worker, { timeoutMs: 10000 });
      window.__result = { created: true };
    } catch (e) {
      window.__result = { created: false, code: e && e.code, coreCode: e && e.coreCode, violations };
    }
    return;
  }

  const worker = makeWorker();
  const workerVault = await createWorkerVault(worker);
  const report = await runWorkerSuite({
    workerVault,
    worker,
    fixtures: corpus.fixtures,
    corePii,
  });
  report.cspViolations = violations;
  // core.VERSION is a static export; core.artifact() is deliberately not
  // called here. It would throw NOT_INITIALIZED: this main thread never
  // calls initialize() in Worker mode, only the Worker's own realm does. The
  // artifact the Worker loaded is exercised by the ".wasm asset served"
  // check below, from the network requests this page actually made.
  report.coreVersion = core.VERSION;
  report.artifact = "wasm";
  report.probes = null;
  await workerVault.dispose();
  worker.terminate();
  window.__result = report;
}

main().catch((e) => {
  window.__result = { fatal: String((e && e.code) || (e && e.message) || e) };
});
`,
);

await build({
  root: dir,
  logLevel: "warn",
  build: { outDir: join(dir, "dist"), emptyOutDir: true, assetsInlineLimit: 0, modulePreload: { polyfill: false }, target: "es2022" },
});

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".json": "application/json" };
const served = new Set();
// A dedicated Worker's own CSP comes from its OWN script response's
// Content-Security-Policy header, not from the query string on the page
// that created it: `new Worker(new URL(...))` carries no query string of its
// own. So every response in one navigation (the document, its worker
// script, and the worker's own .wasm fetch) must agree on which CSP mode is
// under test. Tests run sequentially, one `page.goto()` at a time, so the
// mode named on the last top-level navigation governs every response until
// the next one.
let currentMode = null;
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  const path = normalize(url.pathname === "/" ? "/index.html" : url.pathname);
  if (path === "/index.html") currentMode = url.searchParams.get("mode");
  const csp = currentMode === "no-wasm" ? NO_WASM_WORKER_CSP : currentMode === "no-worker-src" ? NO_WORKER_SRC_CSP : WORKER_CSP;
  const file = join(dir, "dist", path);
  if (!file.startsWith(join(dir, "dist")) || !existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  served.add(path);
  res.writeHead(200, {
    "content-type": TYPES[extname(file)] ?? "application/octet-stream",
    "content-security-policy": csp,
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
  });
  res.end(readFileSync(file));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

let ok = true;
try {
  for (const name of requested) {
    const browser = await engines[name].launch();
    try {
      const version = browser.version();

      const page = await browser.newPage();
      await page.goto(`${origin}/`);
      await page.waitForFunction(() => window.__result !== undefined, null, { timeout: 120_000 });
      const report = await page.evaluate(() => window.__result);
      if (report.fatal) throw new Error(`${name}: worker suite failed to run (${report.fatal})`);
      report.runtime = { name, version, csp: WORKER_CSP, userAgent: await page.evaluate(() => navigator.userAgent) };
      const extra = [];
      extra.push({ id: "worker:no-csp-violations", ok: report.cspViolations.length === 0, message: `violations ${report.cspViolations}` });
      extra.push({ id: "worker:asset-served", ok: [...served].some((p) => p.endsWith(".wasm")), message: "no .wasm asset requested" });

      // Negative control 1: CSP denies worker-src, so the Worker cannot be
      // created at all. createWorkerVault must reject explicitly and never
      // silently substitute a main-thread vault.
      const noSrc = await browser.newPage();
      await noSrc.goto(`${origin}/?mode=no-worker-src`);
      await noSrc.waitForFunction(() => window.__result !== undefined, null, { timeout: 60_000 });
      const noSrcResult = await noSrc.evaluate(() => window.__result);
      report.noWorkerSrcCsp = noSrcResult;
      extra.push({
        id: "worker:rejects-explicitly-when-worker-src-denied",
        ok: noSrcResult.rejected === true && typeof noSrcResult.code === "string",
        message: `outcome ${JSON.stringify(noSrcResult)}`,
      });

      // Negative control 2: the Worker is created, but WebAssembly cannot
      // compile inside it. The host must fail closed and say so.
      const noWasm = await browser.newPage();
      await noWasm.goto(`${origin}/?mode=no-wasm`);
      await noWasm.waitForFunction(() => window.__result !== undefined, null, { timeout: 60_000 });
      const noWasmResult = await noWasm.evaluate(() => window.__result);
      report.noWasmCsp = noWasmResult;
      extra.push({
        id: "worker:fails-closed-without-wasm-csp-inside-worker",
        ok: noWasmResult.created === false && noWasmResult.code === "CORE_FAILURE" && noWasmResult.coreCode === "INITIALIZATION_FAILED",
        message: `outcome ${JSON.stringify(noWasmResult)}`,
      });

      // PII controls (#39), same strict CSP as the main run.
      const piiPage = await browser.newPage();
      await piiPage.goto(`${origin}/?mode=pii-select`);
      await piiPage.waitForFunction(() => window.__result !== undefined, null, { timeout: 60_000 });
      const piiResult = await piiPage.evaluate(() => window.__result);
      report.piiSelect = piiResult;
      extra.push({
        id: "worker:pii-selection-owned-by-worker-script",
        ok: piiResult.corePii
          ? piiResult.created === true && piiResult.piiActive === true
          : piiResult.created === false && piiResult.code === "PII_UNAVAILABLE",
        message: `outcome ${JSON.stringify(piiResult)}`,
      });

      const mismatchPage = await browser.newPage();
      await mismatchPage.goto(`${origin}/?mode=expect-mismatch`);
      await mismatchPage.waitForFunction(() => window.__result !== undefined, null, { timeout: 60_000 });
      const mismatchResult = await mismatchPage.evaluate(() => window.__result);
      report.expectMismatch = mismatchResult;
      extra.push({
        id: "worker:expect-pii-activation-mismatch-rejects",
        ok: mismatchResult.created === false && mismatchResult.code === "PII_ACTIVATION_MISMATCH",
        message: `outcome ${JSON.stringify(mismatchResult)}`,
      });

      for (const r of extra) {
        if (r.ok) delete r.message;
        report.results.push(r);
      }
      report.passed = report.results.filter((r) => r.ok).length;
      report.failed = report.results.filter((r) => !r.ok).length;
      writeReport(`worker-${name}-${version}`, report);
      ok = summarize(`worker ${name} ${version}`, report) && ok;
    } finally {
      await browser.close();
    }
  }
} finally {
  server.close();
}
process.exit(ok ? 0 : 1);
