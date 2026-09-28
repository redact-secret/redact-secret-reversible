// Node.js qualification: runs the portable suite against the packed vault
// with the core's native addon, and again with optional dependencies omitted
// so the core's documented WebAssembly fallback loads instead.
//
// Each artifact runs three PII lanes (#42), each in its own Node.js process
// because core PII activation is process-global and one-shot:
// - pii-off: the suite with the core pre-initialized `pii: []`;
// - pii-on: the same suite with the core pre-initialized `pii: ["pii"]`;
// - pii-scenarios: every scenario in packages/vault/test/pii-scenarios.js,
//   one fresh, uninitialized process each (initialization orders,
//   NOT_INITIALIZED, conflicts, retention).
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { makeConsumer, packVault, run, scenarioReport, summarize, writeReport } from "./lib.mjs";

const tarball = packVault();
const major = process.versions.node.split(".")[0];
let ok = true;

const SUITE_RUNNER = `import * as vault from "@redact-secret/vault";
import * as core from "@redact-secret/core";
import { readFileSync } from "node:fs";
import { runSuite } from "./suite.js";
const corpus = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));
// The application owns PII activation (core beta.10+ requires it before createVault()).
await core.initialize({ pii: JSON.parse(process.argv[2]) });
const report = await runSuite({ vault, core, corpus });
process.stdout.write(JSON.stringify(report));
`;

const SCENARIO_RUNNER = `import * as vault from "@redact-secret/vault";
import * as core from "@redact-secret/core";
import { readFileSync } from "node:fs";
import { runPiiScenario } from "./pii-scenarios.js";
const { fixtures } = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));
const name = process.argv[2];
if (name === "--list") {
  const { piiScenarios } = await import("./pii-scenarios.js");
  process.stdout.write(JSON.stringify(Object.keys(piiScenarios)));
} else {
  const result = await runPiiScenario(name, { vault, core, fixtures });
  // Read after the scenario; one whose core never initialized has none.
  try { result.artifact = core.artifact(); } catch {}
  process.stdout.write(JSON.stringify(result));
}
`;

function checkArtifact(report, mode) {
  if (report.artifact !== mode) {
    report.failed += 1;
    report.results.push({ id: "runtime:expected-artifact", ok: false, message: `expected ${mode}, loaded ${report.artifact}` });
  }
}

for (const [mode, omitOptional] of [["addon", false], ["wasm", true]]) {
  const dir = makeConsumer(`node${major}-${mode}`, tarball, { omitOptional });
  writeFileSync(join(dir, "run.mjs"), SUITE_RUNNER);
  writeFileSync(join(dir, "run-scenario.mjs"), SCENARIO_RUNNER);
  const runtime = { name: "node", version: process.versions.node, platform: `${process.platform}-${process.arch}`, expectedArtifact: mode };

  for (const [lane, selection, suffix] of [["off", [], ""], ["on", ["pii"], "-pii-on"]]) {
    const report = JSON.parse(run(process.execPath, ["run.mjs", JSON.stringify(selection)], dir));
    report.runtime = { ...runtime, piiSelection: selection };
    checkArtifact(report, mode);
    if (report.piiActivation !== lane) {
      report.failed += 1;
      report.results.push({ id: "runtime:expected-pii-activation", ok: false, message: `expected ${lane}, realm is ${report.piiActivation}` });
    }
    writeReport(`node${major}-${process.platform}-${process.arch}-${mode}${suffix}`, report);
    ok = summarize(`node ${process.versions.node} ${mode} pii-${lane}`, report) && ok;
  }

  const names = JSON.parse(run(process.execPath, ["run-scenario.mjs", "--list"], dir));
  const results = names.map((name) => JSON.parse(run(process.execPath, ["run-scenario.mjs", name], dir)));
  const artifacts = new Set(results.map((r) => r.artifact).filter((a) => a !== undefined));
  for (const r of results) delete r.artifact;
  const report = scenarioReport(results, { coreVersion: null, artifact: [...artifacts].join(",") });
  report.coreVersion = JSON.parse(run(process.execPath, ["-e", 'import("@redact-secret/core").then((c) => process.stdout.write(JSON.stringify(c.VERSION)))'], dir));
  report.runtime = runtime;
  // A scenario that fails before initializing reports no artifact; every one
  // that initialized must have loaded the expected artifact.
  if ([...artifacts].some((a) => a !== mode)) {
    report.failed += 1;
    report.results.push({ id: "runtime:expected-artifact", ok: false, message: `expected ${mode}, loaded ${[...artifacts]}` });
  }
  writeReport(`node${major}-${process.platform}-${process.arch}-${mode}-pii-scenarios`, report);
  ok = summarize(`node ${process.versions.node} ${mode} pii-scenarios`, report) && ok;
}
process.exit(ok ? 0 : 1);
