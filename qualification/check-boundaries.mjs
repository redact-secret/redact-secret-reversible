// Repository and package boundary checks for @redact-secret/vault (#11, #21).
// Inspects the packed artifact, not the source tree.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { packVault } from "./lib.mjs";

const failures = [];
const check = (ok, message) => ok || failures.push(message);

const tarball = packVault();
const out = mkdtempSync(join(tmpdir(), "vault-pack-"));
execFileSync("tar", ["-xzf", tarball, "-C", out]);
const pkgDir = join(out, "package");
const files = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" }).trim().split("\n").map((f) => f.replace(/^package\//, "")).sort();

const allowed = /^(LICENSE|README\.md|package\.json|dist\/[a-z-]+\.(js|d\.ts))$/;
for (const f of files) check(allowed.test(f), `unexpected packed file ${f}`);
const REQUIRED_FILES = [
  "LICENSE",
  "README.md",
  "package.json",
  "dist/index.js",
  "dist/index.d.ts",
  // Worker mode (#14): a separate, optional entry point. Importing the
  // package's main "." export must never pull this in (checked below).
  "dist/worker-client.js",
  "dist/worker-client.d.ts",
  "dist/worker-host.js",
  "dist/worker-host.d.ts",
];
for (const required of REQUIRED_FILES) check(files.includes(required), `missing packed file ${required}`);

const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
check(pkg.dependencies === undefined || Object.keys(pkg.dependencies).length === 0, "vault must have no runtime dependencies");
check(JSON.stringify(pkg.peerDependencies) === JSON.stringify({ "@redact-secret/core": "0.1.0-beta.10" }), "core peer must be pinned exactly");
check(pkg.sideEffects === false, "package must declare sideEffects: false");
check(pkg.publishConfig?.tag === "alpha", "publishConfig.tag must be alpha");
check(!("scripts" in pkg) || !Object.keys(pkg.scripts).some((s) => /install|prepare|prepack|postpack/.test(s)), "no install-time scripts");

const js = readdirSync(join(pkgDir, "dist")).filter((f) => f.endsWith(".js"));
// Only these two files may talk across a thread boundary at all (#14): the
// Worker-mode client and host. Every other packed file, including the main
// "." entry (index.js) and the shared worker-protocol.js validator, must
// stay free of cross-context messaging, so importing the package plainly
// cannot gain that capability, and the protocol's own validation logic
// cannot bypass it by talking to postMessage directly.
const WORKER_TRANSPORT_FILES = new Set(["worker-client.js", "worker-host.js"]);
for (const f of js) {
  const src = readFileSync(join(pkgDir, "dist", f), "utf8");
  for (const [, spec] of src.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
    check(spec.startsWith("./") || spec === "@redact-secret/core", `${f} imports ${spec} (only relative files and the core's public root are allowed)`);
  }
  const forbidden = [
    [/\bconsole\./, "console"], [/\bfetch\s*\(/, "fetch"], [/XMLHttpRequest|sendBeacon|WebSocket|EventSource/, "network"],
    [/localStorage|sessionStorage|indexedDB|caches\.|document\.cookie/, "browser storage"], [/\bprocess\./, "process global"],
    [/\beval\s*\(|new Function/, "dynamic code"],
  ];
  if (!WORKER_TRANSPORT_FILES.has(f)) forbidden.push([/postMessage|BroadcastChannel|SharedWorker/, "cross-context messaging"]);
  for (const [pattern, label] of forbidden) check(!pattern.test(src), `${f} uses ${label}`);
}

// The main-thread-only entry never imports Worker-mode code: plain `import
// "@redact-secret/vault"` must not gain postMessage-based capability.
if (js.includes("index.js")) {
  const indexSrc = readFileSync(join(pkgDir, "dist", "index.js"), "utf8");
  check(!/worker-(client|host|protocol)\.js/.test(indexSrc), "dist/index.js imports Worker-mode code");
}
// The client and host stay physically independent: a main-thread bundle
// that imports only "./worker" must not also pull in vault creation (host).
if (js.includes("worker-client.js")) {
  const clientSrc = readFileSync(join(pkgDir, "dist", "worker-client.js"), "utf8");
  check(!/worker-host\.js/.test(clientSrc), "dist/worker-client.js imports the Worker host");
}
if (js.includes("worker-host.js")) {
  const hostSrc = readFileSync(join(pkgDir, "dist", "worker-host.js"), "utf8");
  check(!/worker-client\.js/.test(hostSrc), "dist/worker-host.js imports the Worker client");
}

// No server or store SDK leaks into the browser bundle: the packed tree has
// exactly one external import, and nothing in this repo depends back on it.
const rootPkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
check(!Object.keys(rootPkg.devDependencies ?? {}).some((d) => /vault-server|store-/.test(d)), "unexpected server/store dependency");

if (failures.length) {
  console.error(`boundary check failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`boundary check passed: ${files.length} packed files, 0 runtime dependencies, core peer 0.1.0-beta.10`);
console.log(files.map((f) => `  ${f}`).join("\n"));
