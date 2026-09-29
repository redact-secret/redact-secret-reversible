#!/usr/bin/env node
// Turns a release's `bench:compare` results into the committed per-release
// archive `docs/research/perf/<version>.json` (#83).
//
//   node bench/archive.mjs <compare-result.json>... [--version <v>]
//                          [--out file | --out-dir dir] [--force] [--allow-local]
//
// Default output: docs/research/perf/<version>.json (`--out-dir` keeps the
// `<version>.json` name in another directory).
//
// Inputs are the result files the `bench` workflow uploads (one per PII
// mode). Each must be a full compare of a clean workspace commit against a
// published baseline, run on GitHub Actions (`--allow-local` overrides that
// last rule), and all must name the same commit, versions, and corpus. The
// archive is validated and leak-checked before it is written; an existing
// archive is not overwritten without `--force`.

import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { SENSITIVE_VALUES } from "./corpus/v1/index.mjs";
import { buildArchive, validateArchive } from "./lib/archive.mjs";
import { assertNoLeaks } from "./lib/leak-guard.mjs";
import { assertExactVersion } from "./lib/published.mjs";
import { REPO_ROOT } from "./lib/sides.mjs";

const USAGE =
  "usage: node bench/archive.mjs <compare-result.json>... [--version <v>] [--out file | --out-dir dir] [--force] [--allow-local]";
export const ARCHIVE_DIR = join(REPO_ROOT, "docs", "research", "perf");

async function main() {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      version: { type: "string" },
      out: { type: "string" },
      "out-dir": { type: "string" },
      force: { type: "boolean", default: false },
      "allow-local": { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    allowPositionals: true,
    strict: true,
  });
  if (values.help || positionals.length === 0) {
    console.log(USAGE);
    return values.help ? 0 : 2;
  }
  if (values.version !== undefined) assertExactVersion(values.version, "--version");
  if (values.out !== undefined && values["out-dir"] !== undefined) throw new Error("pass --out or --out-dir, not both");
  const results = positionals.map((file) => JSON.parse(readFileSync(file, "utf8")));
  const archive = buildArchive(results, { version: values.version, allowLocal: values["allow-local"] });
  const errors = validateArchive(archive);
  if (errors.length > 0) throw new Error(`archive is invalid:\n  ${errors.join("\n  ")}`);

  const text = `${JSON.stringify(archive, null, 2)}\n`;
  assertNoLeaks(text, SENSITIVE_VALUES);
  const out = values.out ?? join(values["out-dir"] ?? ARCHIVE_DIR, `${archive.version}.json`);
  if (existsSync(out) && !values.force) throw new Error(`${out} exists; pass --force to replace it`);
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, text);

  for (const s of archive.summary) {
    console.log(
      `[pii=${s.pii} ${s.corpus} tier=${s.tier} rounds=${s.rounds} node@${s.node} ${s.runner}] vault@${archive.version} vs ${archive.baseline}: ${s.comparisons} comparison(s), ${s.warn} warn, ${s.fail} fail, ${s.failedMetrics} failed metric(s)`,
    );
  }
  console.log(`wrote ${out}`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 2;
    },
  );
}
