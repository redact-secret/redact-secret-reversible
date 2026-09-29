// A "side" is one set of packages under test: the vault, vault-server, and
// the exact core that vault resolves. Metrics receive a side's modules through
// `ctx`, never by importing packages themselves, so the A/B runner can run the
// same metric file against the workspace candidate and a published version.
//
// Benchmarks consume the packages' public entry points only (#75): each module
// is loaded from its package.json `exports["."]` import target.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Core `initialize({ pii })` selectors per PII mode. */
export const PII_SELECTORS = Object.freeze({ off: Object.freeze([]), on: Object.freeze(["pii"]) });

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** Absolute path of a package's public "." ESM entry. */
export function publicEntry(packageDir) {
  const pkg = readJson(join(packageDir, "package.json"));
  const root = typeof pkg.exports === "string" ? pkg.exports : pkg.exports?.["."];
  const target = typeof root === "string" ? root : (root?.import ?? root?.default);
  if (typeof target !== "string") throw new Error(`${pkg.name} has no public "." import entry`);
  return join(packageDir, target);
}

export async function importPackage(packageDir) {
  const entry = publicEntry(packageDir);
  if (!existsSync(entry)) throw new Error(`${entry} is missing; run \`npm run build\` first`);
  return import(pathToFileURL(entry).href);
}

function gitSha(root) {
  try {
    const sha = execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const dirty = execFileSync("git", ["status", "--porcelain", "--", "packages"], { cwd: root, encoding: "utf8" }).trim();
    return dirty.length > 0 ? `${sha}-dirty` : sha;
  } catch {
    return undefined;
  }
}

/**
 * The candidate: the workspace's built packages and the core installed at the
 * repository root (the one `packages/vault/dist` resolves).
 */
export async function loadWorkspaceSide({ root = REPO_ROOT, label = "candidate" } = {}) {
  const vaultDir = join(root, "packages", "vault");
  const serverDir = join(root, "packages", "vault-server");
  const coreDir = join(root, "node_modules", "@redact-secret", "core");
  const side = {
    label,
    source: "workspace",
    gitSha: gitSha(root),
    vault: await importPackage(vaultDir),
    vaultServer: await importPackage(serverDir),
    core: await importPackage(coreDir),
    packages: {
      vault: { version: readJson(join(vaultDir, "package.json")).version },
      vaultServer: { version: readJson(join(serverDir, "package.json")).version },
      core: { version: readJson(join(coreDir, "package.json")).version },
    },
    piiActivation: null,
    artifact: null,
  };
  return side;
}

/**
 * Initializes the side's core for a PII mode (activation is one-shot per
 * process, so one process runs one mode), then proves the vault resolves this
 * very core instance: a `createVault()` with `pii` omitted adopts the
 * activation and fails `NOT_INITIALIZED` on any other instance.
 */
export async function activateSide(side, piiMode) {
  const selectors = PII_SELECTORS[piiMode];
  if (selectors === undefined) throw new Error(`unknown PII mode ${piiMode}`);
  const hasPiiSurface = typeof side.core.piiActivation === "function";
  if (hasPiiSurface) await side.core.initialize({ pii: [...selectors] });
  else if (selectors.length > 0) throw new Error(`${side.label}: core ${side.packages.core.version} has no PII surface`);
  else await side.core.initialize();

  const probe = await side.vault.createVault();
  try {
    side.piiActivation = probe.piiActivation ?? null;
  } finally {
    probe.dispose();
  }
  side.artifact = typeof side.core.artifact === "function" ? side.core.artifact() : null;
  return side;
}

/** The value-free description of a side recorded in results. */
export function describeSide(side) {
  const out = {
    label: side.label,
    source: side.source,
    piiActivation: side.piiActivation,
    vault: { ...side.packages.vault },
    vaultServer: side.packages.vaultServer === null ? null : { ...side.packages.vaultServer },
    core: { ...side.packages.core, artifact: side.artifact },
  };
  if (side.gitSha !== undefined) out.gitSha = side.gitSha;
  return out;
}
