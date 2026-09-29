// Shared by the B8 (#82) distribution metrics: dist-size, cold-init, and
// cold-init-browser. Not a metric itself (discovery only imports
// bench/metrics/*.mjs, not subdirectories).
//
// Size and cold-start metrics need each side's package *directories*, not just
// its imported modules. `ctx.side.source` says where they are:
//   - "workspace": packages/vault, packages/vault-server, and the core at the
//     repository root's node_modules (what packages/vault/dist resolves).
//   - "npm": the baseline install bench/lib/published.mjs made under
//     .bench-cache/vault-<version>/node_modules.
// Each directory's package.json version is checked against ctx.side.packages,
// so a stale or foreign directory fails the metric instead of being measured.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { DEFAULT_CACHE_DIR } from "../../lib/published.mjs";
import { REPO_ROOT } from "../../lib/sides.mjs";

/** Scratch space for B8 build outputs (gitignored via /.bench-cache/). */
export const B8_WORK_DIR = join(DEFAULT_CACHE_DIR, "b8");

function readVersion(dir) {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version;
}

function checked(dir, expected, what) {
  if (!existsSync(join(dir, "package.json"))) throw new Error(`${what} package directory is missing`);
  const version = readVersion(dir);
  if (expected !== undefined && version !== expected) throw new Error(`${what} directory holds ${version}, expected ${expected}`);
  return dir;
}

/** Walks up from `fromDir` the way Node resolves a bare package name. */
export function findPackageDir(fromDir, name) {
  let dir = fromDir;
  for (;;) {
    const candidate = join(dir, "node_modules", ...name.split("/"));
    if (existsSync(join(candidate, "package.json"))) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/**
 * `{ vault, vaultServer, core, wasm }` package directories for a ctx side.
 * `vaultServer` is null when the side has none; `wasm` (the core's
 * WebAssembly dependency) is undefined when it is not installed.
 */
export function sideDirs(side) {
  const { packages } = side;
  let vault;
  let vaultServer;
  let core;
  if (side.source === "workspace") {
    vault = join(REPO_ROOT, "packages", "vault");
    vaultServer = join(REPO_ROOT, "packages", "vault-server");
    core = join(REPO_ROOT, "node_modules", "@redact-secret", "core");
  } else if (side.source === "npm") {
    const modules = join(DEFAULT_CACHE_DIR, `vault-${packages.vault.version}`, "node_modules", "@redact-secret");
    vault = join(modules, "vault");
    vaultServer = join(modules, "vault-server");
    core = join(modules, "core");
  } else {
    throw new Error(`unknown side source ${side.source}`);
  }
  return {
    vault: checked(vault, packages.vault.version, "vault"),
    vaultServer: packages.vaultServer === null ? null : checked(vaultServer, packages.vaultServer.version, "vault-server"),
    core: checked(core, packages.core.version, "core"),
    wasm: findPackageDir(core, "@redact-secret/wasm"),
  };
}

/** A key that identifies one side within one process. */
export function sideKey(side) {
  return `${side.label}-${side.source}-${side.packages.vault.version}`;
}

/**
 * `npm pack --dry-run --json` of a package directory: the tarball npm would
 * publish, gzipped by the local npm, without writing it. Both sides are packed
 * by the same npm, so the published baseline is re-packed rather than using
 * the registry's tarball (whose gzip output depends on the publisher's npm).
 */
export function packInfo(dir) {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts", "--workspaces=false"], {
    cwd: dir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const [info] = JSON.parse(out);
  if (!(Number.isInteger(info?.size) && Number.isInteger(info?.unpackedSize) && Array.isArray(info?.files))) {
    throw new Error("npm pack returned no size");
  }
  return { tarball: info.size, unpacked: info.unpackedSize, files: info.files.length };
}

export function ensureDir(dir) {
  mkdirSync(dir, { recursive: true });
  return dir;
}
