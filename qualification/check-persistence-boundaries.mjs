// Package boundary checks for the persistence packages (#112). Inspects the
// packed artifacts, not the source tree: what a consumer installs is what is
// checked. Complements check-boundaries.mjs, which covers @redact-secret/vault.
//
// The rules are the dependency rules of docs/specs/persistent-vault.md §2:
// only an adapter package may name a database driver or a key-service SDK,
// and the base packages resolve neither.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ROOT, run } from "./lib.mjs";

const failures = [];
const check = (ok, message) => ok || failures.push(message);

const CONTRACTS = "@redact-secret/vault-contracts";
const CORE = "@redact-secret/core";
const VAULT = "@redact-secret/vault";

/**
 * name → the exact runtime dependencies, peers, and import specifiers its
 * packed JavaScript may contain. Anything else fails.
 */
const PACKAGES = {
  "vault-contracts": { deps: [], peers: [], imports: [], nodeBuiltins: false },
  "vault-crypto": { deps: [CONTRACTS], peers: [], imports: [CONTRACTS], nodeBuiltins: false },
  "vault-conformance": { deps: [CONTRACTS], peers: [], imports: [CONTRACTS], nodeBuiltins: false },
  "store-memory": { deps: [CONTRACTS], peers: [], imports: [CONTRACTS], nodeBuiltins: false },
  // The adapter declares the driver as a peer and types it structurally: its
  // own code imports no driver, the application passes a pool.
  "store-postgres": { deps: [CONTRACTS], peers: ["pg"], imports: [CONTRACTS], nodeBuiltins: false },
  // The one package that names the SQLite driver, as an optional peer: it is loaded by a dynamic import inside
  // the store and never reaches the base packages. The store reads and writes its marker file and canonicalizes
  // the database path, so it alone may import Node built-ins.
  "store-sqlite": { deps: [CONTRACTS], peers: ["better-sqlite3"], imports: [CONTRACTS, "better-sqlite3"], nodeBuiltins: ["node:fs", "node:path"], optionalPeers: ["better-sqlite3"] },
  "key-provider-aws-kms": { deps: [CONTRACTS], peers: ["@aws-sdk/client-kms"], imports: [CONTRACTS, "@aws-sdk/client-kms"], nodeBuiltins: false },
  "vault-server": {
    deps: [VAULT, CONTRACTS],
    peers: [CORE],
    imports: [VAULT, `${VAULT}/internal/capture-plan`, CONTRACTS],
    nodeBuiltins: false,
  },
};

/** Driver, SDK, and adapter names that must not appear outside the package that owns them. */
const ADAPTER_ONLY = [/@aws-sdk\//, /\bfrom\s+["']pg["']/, /require\(["']pg["']\)/, /\bioredis\b/, /\bbetter-sqlite3\b/, /@redact-secret\/store-/, /@redact-secret\/key-provider-/];

const FORBIDDEN = [
  [/\bconsole\./, "console"],
  [/\bfetch\s*\(/, "fetch"],
  [/XMLHttpRequest|sendBeacon|WebSocket|EventSource/, "network"],
  [/localStorage|sessionStorage|indexedDB|document\.cookie/, "browser storage"],
  [/\bprocess\.(env|argv|exit|stdout|stderr)/, "process global"],
  [/\beval\s*\(|new Function/, "dynamic code"],
];

function listFiles(dir, prefix = "") {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listFiles(full, `${prefix}${entry}/`));
    else out.push(`${prefix}${entry}`);
  }
  return out;
}

const packDir = mkdtempSync(join(tmpdir(), "rsv-persistence-pack-"));
const summary = [];

for (const [dirName, rule] of Object.entries(PACKAGES)) {
  const pkgRoot = join(ROOT, "packages", dirName);
  if (!existsSync(join(pkgRoot, "package.json"))) continue;
  const name = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")).name;
  const dest = join(packDir, dirName);
  mkdirSync(dest, { recursive: true });
  run("npm", ["pack", "-w", name, "--pack-destination", dest], ROOT);
  const tarball = readdirSync(dest).find((f) => f.endsWith(".tgz"));
  check(tarball !== undefined, `${name}: npm pack produced no tarball`);
  if (tarball === undefined) continue;
  execFileSync("tar", ["-xzf", join(dest, tarball), "-C", dest]);
  const out = join(dest, "package");
  const files = listFiles(out).sort();

  // Packed file list: built output, README, LICENSE, manifest. No sources, tests, or fixtures.
  const allowed = /^(LICENSE|README\.md|package\.json|dist\/([a-z-]+\/)*[a-z-]+\.(js|d\.ts))$/;
  for (const file of files) check(allowed.test(file), `${name}: unexpected packed file ${file}`);
  for (const required of ["LICENSE", "README.md", "package.json", "dist/index.js", "dist/index.d.ts"]) {
    check(files.includes(required), `${name}: missing packed file ${required}`);
  }

  const pkg = JSON.parse(readFileSync(join(out, "package.json"), "utf8"));
  check(JSON.stringify(Object.keys(pkg.dependencies ?? {}).sort()) === JSON.stringify([...rule.deps].sort()), `${name}: runtime dependencies are ${Object.keys(pkg.dependencies ?? {}).join(", ") || "none"}`);
  check(JSON.stringify(Object.keys(pkg.peerDependencies ?? {}).sort()) === JSON.stringify([...rule.peers].sort()), `${name}: peer dependencies are ${Object.keys(pkg.peerDependencies ?? {}).join(", ") || "none"}`);
  check(pkg.optionalDependencies === undefined, `${name}: optional dependencies are not allowed`);
  // A peer is optional only where the rule says so: the driver of an adapter is the application's choice to install.
  const optionalPeers = Object.entries(pkg.peerDependenciesMeta ?? {}).filter(([, meta]) => meta?.optional === true).map(([peer]) => peer);
  check(JSON.stringify(optionalPeers.sort()) === JSON.stringify([...(rule.optionalPeers ?? [])].sort()), `${name}: optional peers are ${optionalPeers.join(", ") || "none"}`);
  // Workspace packages are pinned exactly: a range would let an unqualified combination install.
  for (const [dep, range] of Object.entries(pkg.dependencies ?? {})) {
    if (dep.startsWith("@redact-secret/")) check(/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(range), `${name}: ${dep} must be pinned exactly, found ${range}`);
  }
  check(pkg.sideEffects === false, `${name}: must declare sideEffects: false`);
  check(typeof pkg.publishConfig?.tag === "string" && pkg.publishConfig.tag !== "latest", `${name}: publishConfig.tag must be an explicit prerelease tag`);
  check(!Object.keys(pkg.scripts ?? {}).some((s) => /install|prepare|prepack|postpack/.test(s)), `${name}: no install-time scripts`);
  check(pkg.type === "module", `${name}: must be an ES module package`);

  for (const file of files.filter((f) => f.endsWith(".js"))) {
    const src = readFileSync(join(out, file), "utf8");
    for (const [, spec] of src.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
      if (spec.startsWith("./") || spec.startsWith("../")) continue;
      if (spec.startsWith("node:")) {
        check(Array.isArray(rule.nodeBuiltins) && rule.nodeBuiltins.includes(spec), `${name}: ${file} imports ${spec}`);
        continue;
      }
      check(rule.imports.includes(spec), `${name}: ${file} imports ${spec}`);
    }
    for (const [pattern, label] of FORBIDDEN) check(!pattern.test(src), `${name}: ${file} uses ${label}`);
    // Only the package that owns an adapter may name one.
    const ownsAdapter = dirName.startsWith("store-") || dirName.startsWith("key-provider-");
    if (!ownsAdapter) {
      for (const pattern of ADAPTER_ONLY) check(!pattern.test(src), `${name}: ${file} names an adapter, driver, or SDK (${pattern})`);
    }
    if (dirName === "store-postgres" || dirName === "store-memory" || dirName === "store-sqlite") {
      // A store holds ciphertext: it imports no crypto layer and calls no cipher or key provider.
      check(!/crypto\.subtle|createRecordCrypto|unwrapDataKey|generateDataKey|decrypt\(/.test(src), `${name}: ${file} touches a cipher or a key provider`);
    }
  }

  if (dirName === "vault-server") {
    // The default entry stays what it was: it resolves no persistence code.
    const index = readFileSync(join(out, "dist/index.js"), "utf8");
    check(!/persistent/.test(index), "vault-server: dist/index.js references the persistent profile");
    check(!/vault-contracts/.test(index), "vault-server: dist/index.js imports the contracts package");
    const reachable = new Set(["index.js"]);
    const queue = ["index.js"];
    while (queue.length > 0) {
      const current = queue.pop();
      const src = readFileSync(join(out, "dist", current), "utf8");
      for (const [, spec] of src.matchAll(/(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g)) {
        const target = join(current, "..", spec).replace(/^\.\//, "");
        if (!reachable.has(target)) {
          reachable.add(target);
          queue.push(target);
        }
      }
    }
    for (const file of reachable) check(!file.startsWith("persistent/"), `vault-server: the default entry reaches ${file}`);
    check(JSON.stringify(Object.keys(pkg.exports).sort()) === JSON.stringify([".", "./package.json", "./persistent", "./policies"]), "vault-server: exports must be '.', './persistent', './policies', './package.json'");
    // The reference policies are plain functions: no import beyond their own types.
    check(!/\bimport\b|\brequire\(/.test(readFileSync(join(out, "dist/policies.js"), "utf8")), "vault-server: dist/policies.js imports something");
  }

  summary.push(`${name}@${pkg.version}: ${files.length} files, deps [${Object.keys(pkg.dependencies ?? {}).join(", ")}], peers [${Object.keys(pkg.peerDependencies ?? {}).join(", ")}]`);
}

// The portable vault names nothing from the persistence packages.
const vaultPkg = JSON.parse(readFileSync(join(ROOT, "packages/vault/package.json"), "utf8"));
check(Object.keys(vaultPkg.dependencies ?? {}).length === 0, "vault: must have no runtime dependencies");
for (const file of readdirSync(join(ROOT, "packages/vault/dist")).filter((f) => f.endsWith(".js"))) {
  const src = readFileSync(join(ROOT, "packages/vault/dist", file), "utf8");
  for (const [, spec] of src.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
    check(spec.startsWith("./") || spec === CORE, `vault: dist/${file} imports ${spec}`);
  }
}

rmSync(packDir, { recursive: true, force: true });

if (failures.length) {
  console.error(`persistence boundary check failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`persistence boundary check passed:\n${summary.map((line) => `  ${line}`).join("\n")}`);
