// Real-browser qualification. Builds a production Vite bundle of a consumer
// app that imports the *packed* vault and the pinned core (whose browser
// export loads the distributed WebAssembly asset), serves it under a strict
// Content Security Policy, and runs the portable suite in Chromium, Firefox,
// and WebKit through Playwright. WASM executed in Node is not counted here.
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { extname, join, normalize } from "node:path";

import { chromium, firefox, webkit } from "playwright";
import { build } from "vite";

import { makeConsumer, packVault, STRICT_CSP, summarize, writeReport } from "./lib.mjs";

// Identical except WebAssembly compilation is not permitted.
const NO_WASM_CSP = STRICT_CSP.replace(" 'wasm-unsafe-eval'", "");

const requested = (process.env.BROWSERS ?? "chromium,firefox,webkit").split(",");
const engines = { chromium, firefox, webkit };

const tarball = packVault();
const dir = makeConsumer("browser", tarball);

writeFileSync(
  join(dir, "index.html"),
  `<!doctype html><html><head><meta charset="utf-8"><title>vault qualification</title></head>
<body><script type="module" src="./main.js"></script></body></html>`,
);
writeFileSync(
  join(dir, "main.js"),
  `import * as vault from "@redact-secret/vault";
import * as core from "@redact-secret/core";
import corpus from "./corpus.json";
import { runSuite } from "./suite.js";

const violations = [];
document.addEventListener("securitypolicyviolation", (e) => violations.push(e.effectiveDirective));

const mode = new URLSearchParams(location.search).get("mode");
if (mode === "no-wasm") {
  vault.createVault().then(
    () => { window.__result = { created: true }; },
    (e) => { window.__result = { created: false, code: e.code, coreCode: e.coreCode, violations }; },
  );
} else {
  runSuite({ vault, core, corpus }).then(
    (report) => { report.cspViolations = violations; window.__result = report; },
    (e) => { window.__result = { fatal: String(e && e.code || "non-vault failure") }; },
  );
}
`,
);

await build({
  root: dir,
  logLevel: "warn",
  build: { outDir: join(dir, "dist"), emptyOutDir: true, assetsInlineLimit: 0, modulePreload: { polyfill: false }, target: "es2022" },
});

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".json": "application/json" };
const served = new Set();
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  const csp = url.searchParams.get("mode") === "no-wasm" ? NO_WASM_CSP : STRICT_CSP;
  const path = normalize(url.pathname === "/" ? "/index.html" : url.pathname);
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
      if (report.fatal) throw new Error(`${name}: suite failed to run (${report.fatal})`);
      report.runtime = { name, version, csp: STRICT_CSP, userAgent: await page.evaluate(() => navigator.userAgent) };
      const extra = [];
      extra.push({ id: "browser:artifact-is-wasm", ok: report.artifact === "wasm", message: `artifact ${report.artifact}` });
      extra.push({ id: "browser:no-csp-violations", ok: report.cspViolations.length === 0, message: `violations ${report.cspViolations}` });
      extra.push({ id: "browser:wasm-asset-served", ok: [...served].some((p) => p.endsWith(".wasm")), message: "no .wasm asset requested" });

      // Negative control: without 'wasm-unsafe-eval' the core cannot compile
      // its WebAssembly, and the vault must fail closed rather than degrade.
      const denied = await browser.newPage();
      await denied.goto(`${origin}/?mode=no-wasm`);
      await denied.waitForFunction(() => window.__result !== undefined, null, { timeout: 60_000 });
      const negative = await denied.evaluate(() => window.__result);
      report.noWasmCsp = negative;
      extra.push({
        id: "browser:fails-closed-without-wasm-csp",
        ok: negative.created === false && negative.code === "CORE_FAILURE" && negative.coreCode === "INITIALIZATION_FAILED",
        message: `outcome ${JSON.stringify(negative)}`,
      });
      for (const r of extra) {
        if (r.ok) delete r.message;
        report.results.push(r);
      }
      report.passed = report.results.filter((r) => r.ok).length;
      report.failed = report.results.filter((r) => !r.ok).length;
      writeReport(`browser-${name}-${version}`, report);
      ok = summarize(`${name} ${version}`, report) && ok;
    } finally {
      await browser.close();
    }
  }
} finally {
  server.close();
}
process.exit(ok ? 0 : 1);
