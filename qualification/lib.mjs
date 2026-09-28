// Shared helpers for qualification runners. They install the *packed*
// @redact-secret/vault tarball into a throwaway consumer project, so every
// runtime result describes the distributed artifact, not the source tree.
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Consumers live outside the repository so Node module resolution cannot
// walk up into the workspace's own node_modules (which would, for example,
// satisfy the core's native addon from the repo and mask the WASM fallback).
export const WORK = process.env.QUALIFICATION_DIR ?? join(tmpdir(), "redact-secret-vault-qualification");
export const REPORTS = join(ROOT, ".qualification", "reports");
export const CORE_VERSION = "0.1.0-beta.9";

// Shared by browser.mjs and worker.mjs (not re-exported from browser.mjs: that
// module's top level has side effects and launches real browsers on import).
export const STRICT_CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join("; ");

export function run(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "inherit"], encoding: "utf8" });
}

/**
 * Builds and packs the vault once; returns the tarball path.
 *
 * Set `VAULT_SPEC` (e.g. `@redact-secret/vault@0.1.0-alpha.1`) to skip the
 * local build/pack and return that npm install spec instead, so the
 * qualification runners install the *published registry package* rather than
 * the working tree. This is the post-publish registry verification in
 * RELEASING.md step 5 (run ad hoc for alpha.1; now scriptable from the repo).
 */
export function packVault() {
  if (process.env.VAULT_SPEC) return process.env.VAULT_SPEC;
  const packDir = join(WORK, "pack");
  rmSync(packDir, { recursive: true, force: true });
  mkdirSync(packDir, { recursive: true });
  run("npm", ["run", "build", "-w", "@redact-secret/vault"], ROOT);
  run("npm", ["pack", "-w", "@redact-secret/vault", "--pack-destination", packDir], ROOT);
  const tarball = readdirSync(packDir).find((f) => f.endsWith(".tgz"));
  if (!tarball) throw new Error("npm pack produced no tarball");
  return join(packDir, tarball);
}

/** Creates a consumer project with the packed vault and the pinned core. */
export function makeConsumer(name, tarball, { omitOptional = false, extraDeps = [] } = {}) {
  const dir = join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `qualify-${name}`, private: true, type: "module" }, null, 2));
  const args = ["install", "--no-audit", "--no-fund", "--save-exact", tarball, `@redact-secret/core@${CORE_VERSION}`, ...extraDeps];
  run("npm", args, dir);
  if (omitOptional) {
    // Simulate a failed optional-dependency install: the core documents that
    // initialize() then falls back to its WebAssembly artifact.
    const scope = join(dir, "node_modules/@redact-secret");
    for (const entry of readdirSync(scope)) {
      if (entry.startsWith("node-")) rmSync(join(scope, entry), { recursive: true, force: true });
    }
  }
  cpSync(join(ROOT, "packages/vault/test/suite.js"), join(dir, "suite.js"));
  cpSync(join(ROOT, "packages/vault/test/worker-suite.js"), join(dir, "worker-suite.js"));
  cpSync(join(ROOT, "conformance/v1/corpus.json"), join(dir, "corpus.json"));
  return dir;
}

export function writeReport(name, report) {
  mkdirSync(REPORTS, { recursive: true });
  writeFileSync(join(REPORTS, `${name}.json`), JSON.stringify(report, null, 2) + "\n");
}

export function summarize(name, report) {
  const failed = report.results.filter((r) => !r.ok);
  console.log(`${name}: ${report.passed} passed, ${report.failed} failed (core ${report.coreVersion}, artifact ${report.artifact})`);
  for (const f of failed) console.log(`  FAIL ${f.id}: ${f.message}`);
  console.log(`  probes: ${JSON.stringify(report.probes)}`);
  return failed.length === 0;
}
