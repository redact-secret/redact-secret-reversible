#!/usr/bin/env node
// Pins the links of a package README to the release tag while the package is
// packed, so the README on the registry points at the documentation of the
// version it ships with, not at `main` (#138).
//
//   node scripts/pin-readme-links.mjs pin [package directory ...]
//   node scripts/pin-readme-links.mjs restore [package directory ...]
//
// With no directory, every package under packages/ that has a package.json.
// release.yml runs `pin` once, after the build and before the first publish.
// It is a step of the release, not a `prepack` script: package manifests carry
// no lifecycle script (qualification/check-boundaries.mjs).
//
// `pin` rewrites README.md in place and keeps the original under the
// repository's node_modules/.cache; `restore` puts it back. The original
// cannot sit next to the README: npm packs every file named README.*,
// whatever `files` says.
//
// What is rewritten:
//   - https://github.com/<repo>/blob/main/... and /tree/main/...  -> the tag
//   - relative links (../../docs/x.md, test/y.mjs)                -> absolute, at the tag
// The tag is `v<version of @redact-secret/vault>`, the tag release.yml runs
// from. RSV_README_REF overrides it.
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_URL = "https://github.com/redact-secret/redact-secret-vault";
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Pure rewrite. `packageDir` is the package's path from the repository root
 * with forward slashes; `isDirectory(repoPath)` says whether a repository path
 * is a directory (it then links to /tree/ instead of /blob/).
 */
export function pinLinks(text, { packageDir, ref, isDirectory = () => false }) {
  const absolute = new RegExp(`${REPO_URL.replace(/[.]/g, "\\.")}/(blob|tree)/main/`, "g");
  let fence = null;
  return text
    .split("\n")
    .map((line) => {
      const mark = line.match(/^\s*(`{3,}|~{3,})/);
      if (fence) {
        if (mark && mark[1][0] === fence[0] && mark[1].length >= fence.length) fence = null;
        return line;
      }
      if (mark) {
        fence = mark[1];
        return line;
      }
      return line.replace(absolute, `${REPO_URL}/$1/${ref}/`).replace(/\]\(([^)\s]+)\)/g, (all, target) => {
        if (/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(target)) return all;
        const hash = target.indexOf("#");
        const path = hash < 0 ? target : target.slice(0, hash);
        const fragment = hash < 0 ? "" : target.slice(hash);
        const repoPath = posix.normalize(posix.join(packageDir, path)).replace(/\/$/, "");
        if (repoPath === ".." || repoPath.startsWith("../")) return all;
        const kind = isDirectory(repoPath) ? "tree" : "blob";
        return `](${REPO_URL}/${kind}/${ref}/${repoPath}${fragment})`;
      });
    })
    .join("\n");
}

export function releaseRef() {
  if (process.env.RSV_README_REF) return process.env.RSV_README_REF;
  const { version } = JSON.parse(readFileSync(join(REPO_ROOT, "packages/vault/package.json"), "utf8"));
  return `v${version}`;
}

/** Where the original README of a package is kept while it is packed. */
export function savedOriginal(packagePath) {
  const packageDir = relative(REPO_ROOT, resolve(packagePath)).split(sep).join("/");
  return join(REPO_ROOT, "node_modules/.cache/pin-readme-links", packageDir.replace(/[^A-Za-z0-9._-]/g, "_"), "README.md");
}

export function pin(packagePath) {
  const readme = join(packagePath, "README.md");
  const original = savedOriginal(packagePath);
  // A leftover from a pack that never reached postpack: start from the real file.
  if (existsSync(original)) restore(packagePath);
  const text = readFileSync(readme, "utf8");
  const packageDir = relative(REPO_ROOT, resolve(packagePath)).split(sep).join("/");
  const pinned = pinLinks(text, {
    packageDir,
    ref: releaseRef(),
    isDirectory: (repoPath) => {
      try {
        return statSync(join(REPO_ROOT, repoPath)).isDirectory();
      } catch {
        return false;
      }
    },
  });
  mkdirSync(dirname(original), { recursive: true });
  writeFileSync(original, text);
  writeFileSync(readme, pinned);
}

export function restore(packagePath) {
  const readme = join(packagePath, "README.md");
  const original = savedOriginal(packagePath);
  if (!existsSync(original)) return;
  copyFileSync(original, readme);
  rmSync(original);
}

/** Every package directory under packages/ that npm publishes. */
export function npmPackages() {
  return readdirSync(join(REPO_ROOT, "packages"))
    .map((name) => join(REPO_ROOT, "packages", name))
    .filter((path) => existsSync(join(path, "package.json")) && existsSync(join(path, "README.md")))
    .sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...given] = process.argv.slice(2);
  const targets = given.length > 0 ? given : npmPackages();
  if (command !== "pin" && command !== "restore") {
    console.error("usage: pin-readme-links.mjs pin|restore [package directory ...]");
    process.exit(2);
  }
  for (const target of targets) {
    if (command === "pin") pin(target);
    else restore(target);
    console.error(`${command}: ${relative(REPO_ROOT, resolve(target))}/README.md${command === "pin" ? ` -> ${releaseRef()}` : ""}`);
  }
}
