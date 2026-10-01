#!/usr/bin/env node
// Publishes the named workspace packages (directory names under packages/),
// in the order given, with npm provenance. Used by .github/workflows/release.yml.
//
// For each package: refuses the `latest` dist-tag; skips a version that is
// already on the registry (so a re-run or a re-pushed tag is a no-op); waits
// for every exact @redact-secret/* dependency to be visible on the registry;
// then runs `npm publish --provenance --tag <publishConfig.tag>`.
//
// It never falls back to a token, never moves `latest`, and stops at the
// first failure so nothing is published on top of a missing dependency.
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DRY_RUN = process.env.PUBLISH_DRY_RUN === "1";
const ATTEMPTS = 20;
const WAIT_MS = 15_000;

const onRegistry = (spec) => spawnSync("npm", ["view", spec, "version", "--prefer-online"], { cwd: ROOT, stdio: "ignore" }).status === 0;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

const names = process.argv.slice(2);
if (names.length === 0 || names.some((name) => !/^[a-z][a-z0-9-]*$/.test(name))) {
  console.error("usage: publish-workspace.mjs <package-directory> [...]");
  process.exit(2);
}

for (const directory of names) {
  const pkg = JSON.parse(readFileSync(join(ROOT, "packages", directory, "package.json"), "utf8"));
  const spec = `${pkg.name}@${pkg.version}`;
  const tag = pkg.publishConfig?.tag;
  if (typeof tag !== "string" || tag.length === 0 || tag === "latest") {
    console.error(`::error::${pkg.name}: publishConfig.tag must be an explicit dist-tag other than 'latest'.`);
    process.exit(1);
  }
  if (onRegistry(spec)) {
    console.error(`${spec} is already on the registry; skipping publish.`);
    continue;
  }
  for (const [dependency, version] of Object.entries(pkg.dependencies ?? {})) {
    if (!dependency.startsWith("@redact-secret/")) continue;
    let attempt = 1;
    while (!onRegistry(`${dependency}@${version}`)) {
      if (attempt >= ATTEMPTS) {
        console.error(`::error::${spec} depends on ${dependency}@${version}, which is not on the registry after ${attempt} attempts.`);
        process.exit(1);
      }
      console.error(`${dependency}@${version} not visible on the registry yet (attempt ${attempt}/${ATTEMPTS}); retrying in 15s.`);
      attempt += 1;
      await sleep(WAIT_MS);
    }
  }
  const args = ["publish", "-w", pkg.name, "--provenance", "--tag", tag];
  if (DRY_RUN) args.push("--dry-run");
  console.error(`npm ${args.join(" ")}`);
  execFileSync("npm", args, { cwd: ROOT, stdio: "inherit" });
}
