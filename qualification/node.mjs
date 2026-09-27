// Node.js qualification: runs the portable suite against the packed vault
// with the core's native addon, and again with optional dependencies omitted
// so the core's documented WebAssembly fallback loads instead.
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { makeConsumer, packVault, run, summarize, writeReport } from "./lib.mjs";

const tarball = packVault();
const major = process.versions.node.split(".")[0];
let ok = true;

for (const [mode, omitOptional] of [["addon", false], ["wasm", true]]) {
  const dir = makeConsumer(`node${major}-${mode}`, tarball, { omitOptional });
  writeFileSync(
    join(dir, "run.mjs"),
    `import * as vault from "@redact-secret/vault";
import * as core from "@redact-secret/core";
import { readFileSync } from "node:fs";
import { runSuite } from "./suite.js";
const corpus = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));
const report = await runSuite({ vault, core, corpus });
process.stdout.write(JSON.stringify(report));
`,
  );
  const report = JSON.parse(run(process.execPath, ["run.mjs"], dir));
  report.runtime = { name: "node", version: process.versions.node, platform: `${process.platform}-${process.arch}`, expectedArtifact: mode };
  if (report.artifact !== mode) {
    report.failed += 1;
    report.results.push({ id: "runtime:expected-artifact", ok: false, message: `expected ${mode}, loaded ${report.artifact}` });
  }
  writeReport(`node${major}-${process.platform}-${process.arch}-${mode}`, report);
  ok = summarize(`node ${process.versions.node} ${mode}`, report) && ok;
}
process.exit(ok ? 0 : 1);
