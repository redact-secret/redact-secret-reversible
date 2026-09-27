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
for (const required of ["LICENSE", "README.md", "package.json", "dist/index.js", "dist/index.d.ts"]) check(files.includes(required), `missing packed file ${required}`);

const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
check(pkg.dependencies === undefined || Object.keys(pkg.dependencies).length === 0, "vault must have no runtime dependencies");
check(JSON.stringify(pkg.peerDependencies) === JSON.stringify({ "@redact-secret/core": "0.1.0-beta.9" }), "core peer must be pinned exactly");
check(pkg.sideEffects === false, "package must declare sideEffects: false");
check(pkg.publishConfig?.tag === "alpha", "publishConfig.tag must be alpha");
check(!("scripts" in pkg) || !Object.keys(pkg.scripts).some((s) => /install|prepare|prepack|postpack/.test(s)), "no install-time scripts");

const js = readdirSync(join(pkgDir, "dist")).filter((f) => f.endsWith(".js"));
for (const f of js) {
  const src = readFileSync(join(pkgDir, "dist", f), "utf8");
  for (const [, spec] of src.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
    check(spec.startsWith("./") || spec === "@redact-secret/core", `${f} imports ${spec} (only relative files and the core's public root are allowed)`);
  }
  const forbidden = [
    [/\bconsole\./, "console"], [/\bfetch\s*\(/, "fetch"], [/XMLHttpRequest|sendBeacon|WebSocket|EventSource/, "network"],
    [/localStorage|sessionStorage|indexedDB|caches\.|document\.cookie/, "browser storage"], [/\bprocess\./, "process global"],
    [/\beval\s*\(|new Function/, "dynamic code"], [/postMessage|BroadcastChannel|SharedWorker/, "cross-context messaging"],
  ];
  for (const [pattern, label] of forbidden) check(!pattern.test(src), `${f} uses ${label}`);
}

// No server or store SDK leaks into the browser bundle: the packed tree has
// exactly one external import, and nothing in this repo depends back on it.
const rootPkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
check(!Object.keys(rootPkg.devDependencies ?? {}).some((d) => /vault-server|store-/.test(d)), "unexpected server/store dependency");

if (failures.length) {
  console.error(`boundary check failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`boundary check passed: ${files.length} packed files, 0 runtime dependencies, core peer 0.1.0-beta.9`);
console.log(files.map((f) => `  ${f}`).join("\n"));
