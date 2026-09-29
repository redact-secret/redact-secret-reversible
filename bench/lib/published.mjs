// The baseline side for A/B runs (#76): an exact published version of
// @redact-secret/vault (and @redact-secret/vault-server when that version
// exists), with the exact core that version pins, installed into a gitignored
// cache directory. Nothing is added to the root package.json or lockfile.
//
// Install scripts are not run (`--ignore-scripts`); the core ships prebuilt
// native addons as optional dependencies and a WebAssembly fallback.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { importPackage, REPO_ROOT } from "./sides.mjs";

export const DEFAULT_CACHE_DIR = join(REPO_ROOT, ".bench-cache");

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const VAULT = "@redact-secret/vault";
const SERVER = "@redact-secret/vault-server";
const CORE = "@redact-secret/core";

export function assertExactVersion(version, what) {
  if (typeof version !== "string" || !EXACT_VERSION.test(version)) {
    throw new Error(`${what} must be an exact version like 0.1.0-alpha.3, got ${JSON.stringify(version)}`);
  }
  return version;
}

function npm(args, cwd) {
  return execFileSync("npm", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/** `npm view <spec> <fields> --json`, or undefined when the version does not exist. */
function npmView(spec, fields) {
  try {
    const out = npm(["view", spec, ...fields, "--json"], REPO_ROOT).trim();
    return out.length === 0 ? undefined : JSON.parse(out);
  } catch (error) {
    const text = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    if (/E404/.test(text)) return undefined;
    throw new Error(`npm view ${spec} failed; is the registry reachable?`);
  }
}

/** Exact dependency set for a published vault version, from the registry. */
export function resolvePublishedSet(version) {
  assertExactVersion(version, "baseline version");
  const vault = npmView(`${VAULT}@${version}`, ["version", "peerDependencies"]);
  if (vault === undefined || vault.version !== version) throw new Error(`${VAULT}@${version} is not published`);
  const core = assertExactVersion(vault.peerDependencies?.[CORE], `${VAULT}@${version}'s ${CORE} peer`);
  const server = npmView(`${SERVER}@${version}`, ["version"]);
  const deps = { [VAULT]: version, [CORE]: core };
  if (server !== undefined) deps[SERVER] = version;
  return deps;
}

function installedVersion(dir, name) {
  const path = join(dir, "node_modules", ...name.split("/"), "package.json");
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")).version : undefined;
}

function lockEntry(dir, name) {
  const lockPath = join(dir, "package-lock.json");
  if (!existsSync(lockPath)) return {};
  const entry = JSON.parse(readFileSync(lockPath, "utf8")).packages?.[`node_modules/${name}`] ?? {};
  const out = {};
  if (typeof entry.resolved === "string") out.resolved = entry.resolved;
  if (typeof entry.integrity === "string") out.integrity = entry.integrity;
  return out;
}

function matches(dir, deps) {
  return Object.entries(deps).every(([name, version]) => installedVersion(dir, name) === version);
}

/**
 * Ensures `<cacheDir>/vault-<version>` holds exactly the published set, and
 * returns `{ dir, deps }`. A cache that already matches (by manifest and the
 * installed package versions) is reused without touching the network.
 */
export function ensurePublishedInstall(version, { cacheDir = DEFAULT_CACHE_DIR, log = () => {} } = {}) {
  assertExactVersion(version, "baseline version");
  const dir = join(cacheDir, `vault-${version}`);
  const manifestPath = join(dir, "package.json");
  if (existsSync(manifestPath)) {
    const deps = JSON.parse(readFileSync(manifestPath, "utf8")).dependencies ?? {};
    if (deps[VAULT] === version && matches(dir, deps)) return { dir, deps };
  }
  const deps = resolvePublishedSet(version);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    manifestPath,
    `${JSON.stringify({ name: `bench-baseline-vault-${version}`, private: true, type: "module", dependencies: deps }, null, 2)}\n`,
  );
  log(`installing ${Object.entries(deps).map(([n, v]) => `${n}@${v}`).join(" ")} into ${dir}`);
  npm(["install", "--prefix", dir, "--no-audit", "--no-fund", "--ignore-scripts", "--save-exact", "--workspaces=false"], dir);
  if (!matches(dir, deps)) throw new Error(`installed packages in ${dir} do not match ${JSON.stringify(deps)}`);
  return { dir, deps };
}

/** Loads a published version as a side (activate it with activateSide). */
export async function loadPublishedSide(version, { cacheDir, label = "baseline", log } = {}) {
  const { dir, deps } = ensurePublishedInstall(version, { cacheDir, log });
  const pkgDir = (name) => join(dir, "node_modules", ...name.split("/"));
  const hasServer = deps[SERVER] !== undefined;
  return {
    label,
    source: "npm",
    vault: await importPackage(pkgDir(VAULT)),
    vaultServer: hasServer ? await importPackage(pkgDir(SERVER)) : null,
    core: await importPackage(pkgDir(CORE)),
    packages: {
      vault: { version: deps[VAULT], ...lockEntry(dir, VAULT) },
      vaultServer: hasServer ? { version: deps[SERVER], ...lockEntry(dir, SERVER) } : null,
      core: { version: deps[CORE], ...lockEntry(dir, CORE) },
    },
    piiActivation: null,
    artifact: null,
  };
}
