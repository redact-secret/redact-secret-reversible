// Qualification run for @redact-secret/store-postgres.
//
//   npm run qualify -w @redact-secret/store-postgres
//
// Starts the PostgreSQL topologies the scenarios need, runs every test file
// with the right environment, removes everything it started, and writes
// `qualification/report/summary.json` and `qualification/report/report.md`.
//
// Single-node suites run against RSV_PG_ADMIN_URL / RSV_PG_APP_URL when both
// are set (a CI service container), otherwise against a container this
// script starts. Suites that need their own containers are reported as
// skipped, with the reason, when Docker is not available. A skipped suite is
// never counted as a pass, and the run is then reported as incomplete.
//
// Options: --only=A,D   run only the named suites
//          --require-all   exit 1 when any suite was skipped
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import { dirname, join, relative } from "node:path";
import { run } from "node:test";
import { fileURLToPath } from "node:url";

import pg from "pg";

import { createTopology, dockerUnavailable, IMAGE, remaining, removeRun, RUN_ID } from "./lib/docker.mjs";
import { port } from "./lib/harness.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const reportDirectory = join(here, "report");
const require = createRequire(import.meta.url);

const SUITES = [
  { id: "conformance", title: "Store conformance suite (shared harness), as the serving role", file: "test/conformance.test.mjs", needs: "database" },
  { id: "A", title: "Two independent server processes", file: "test/two-process.test.mjs", needs: "database" },
  { id: "B", title: "Failure around commit", file: "test/commit-failure.test.mjs", needs: "database" },
  { id: "probes", title: "Adapter probes", file: "test/adapter-probes.test.mjs", needs: "database" },
  { id: "F", title: "Least privilege and migrations", file: "test/least-privilege.test.mjs", needs: "database" },
  { id: "G", title: "Cleanup under concurrency", file: "test/sweep-concurrency.test.mjs", needs: "database" },
  { id: "H", title: "Diagnostics hygiene (adapter and server)", file: "test/diagnostics.test.mjs", needs: "database" },
  { id: "outside", title: "Findings outside this package, pinned down", file: "test/outside-findings.test.mjs", needs: "database" },
  { id: "packed", title: "Packed artifact in a clean consumer project", file: "qualification/scenarios/packed.scenario.mjs", needs: "database" },
  { id: "C", title: "Database restart and crash recovery", file: "qualification/scenarios/restart.scenario.mjs", needs: "docker" },
  { id: "D", title: "Failover: synchronous standby, and the asynchronous negative control", file: "qualification/scenarios/failover.scenario.mjs", needs: "docker" },
  { id: "E", title: "Restore from backup (negative control)", file: "qualification/scenarios/backup.scenario.mjs", needs: "docker" },
  { id: "H-log", title: "What the PostgreSQL server log contains", file: "qualification/scenarios/server-log.scenario.mjs", needs: "docker" },
];

const args = process.argv.slice(2);
const only = args.find((arg) => arg.startsWith("--only="))?.slice(7).split(",");
const requireAll = args.includes("--require-all");

function tryExec(command, commandArgs) {
  try {
    return execFileSync(command, commandArgs, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

/** Runs one test file in its own process through `node:test` and collects every result. */
async function runSuite(suite) {
  const started = Date.now();
  const tests = [];
  const stream = run({ files: [join(packageRoot, suite.file)], concurrency: 1 });
  const record = (status) => (event) => {
    const type = event.details?.type;
    const skipped = event.skip !== undefined && event.skip !== false;
    // A suite is recorded only when it was skipped as a whole: its tests then never report.
    if (type === "suite" && !skipped) return;
    tests.push({
      name: event.name,
      status: skipped ? "skipped" : status,
      ...(skipped ? { reason: typeof event.skip === "string" ? event.skip : "skipped" } : {}),
      ...(status === "failed" && !skipped ? { error: String(event.details?.error?.cause?.message ?? event.details?.error?.message ?? "failed").split("\n")[0] } : {}),
      durationMs: Math.round(event.details?.duration_ms ?? 0),
      suite: type === "suite",
    });
  };
  stream.on("test:pass", record("passed"));
  stream.on("test:fail", record("failed"));
  stream.on("test:stderr", (event) => process.stderr.write(event.message));
  await new Promise((resolve) => {
    stream.on("end", resolve);
    stream.on("close", resolve);
    stream.resume();
  });
  const count = (status) => tests.filter((test) => test.status === status).length;
  const result = { ...suite, passed: count("passed"), failed: count("failed"), skipped: count("skipped"), wallClockMs: Date.now() - started, tests };
  result.status = result.failed > 0 ? "failed" : result.passed === 0 ? "skipped" : "passed";
  return result;
}

async function databaseFacts(adminUrl) {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    const version = (await client.query("SELECT version() AS version, current_setting('server_version') AS number")).rows[0];
    const names = ["fsync", "synchronous_commit", "full_page_writes", "wal_sync_method", "wal_level", "synchronous_standby_names", "default_transaction_isolation", "max_connections", "log_statement", "log_parameter_max_length", "log_parameter_max_length_on_error"];
    const settings = Object.fromEntries((await client.query("SELECT name, setting FROM pg_settings WHERE name = ANY($1::text[]) ORDER BY name", [names])).rows.map((row) => [row.name, row.setting]));
    return { version: version.number, versionString: version.version, settings };
  } finally {
    await client.end();
  }
}

const flatten = (value, prefix = "") => {
  if (value === null || typeof value !== "object") return [`${prefix}=${value}`];
  if (Array.isArray(value)) return value.every((item) => item === null || typeof item !== "object") ? [`${prefix}=[${value.join(", ")}]`] : value.flatMap((item, index) => flatten(item, `${prefix}[${index}]`));
  return Object.entries(value).flatMap(([key, inner]) => flatten(inner, prefix === "" ? key : `${prefix}.${key}`));
};
const cell = (text) => String(text).replaceAll("|", "\\|").replaceAll("\n", " ");
const seconds = (ms) => `${(ms / 1000).toFixed(1)} s`;

function markdown(summary) {
  const lines = [];
  const add = (...text) => lines.push(...text);
  const env = summary.environment;
  add("# Qualification report: @redact-secret/store-postgres", "");
  add(`**Result: ${summary.status}.** Generated by \`npm run qualify -w @redact-secret/store-postgres\` (\`qualification/run.mjs\`). Machine-readable copy: [summary.json](summary.json).`, "");
  add("This report records one run. It is evidence for the profiles named in the [package README](../../README.md) on the versions below, and for nothing else. Every identifier, key, and password in the run was synthetic.", "");
  add("## Run", "");
  add("| | |", "| --- | --- |");
  add(`| Started | ${summary.startedAt} |`, `| Wall clock | ${seconds(summary.wallClockMs)} |`, `| Source commit | \`${env.commit ?? "unknown"}\`${env.dirty ? " with uncommitted changes" : ""} |`);
  add(`| Node.js | ${env.node} |`, `| \`pg\` driver | ${env.pg} |`, `| OS / architecture | ${env.os} / ${env.arch} |`);
  add(`| PostgreSQL | ${env.postgres?.version ?? "not reached"} |`, `| PostgreSQL build | ${cell(env.postgres?.versionString ?? "not reached")} |`);
  add(`| Image | \`${env.image.name}\`, id \`${env.image.id ?? "unavailable"}\`, digest \`${env.image.digests ?? "unavailable"}\` |`, `| Docker | ${env.docker ?? "unavailable"} |`);
  add(`| Single-node database | ${env.database} |`, `| Docker resources left after the run | ${summary.cleanup} |`, "");
  if (env.postgres?.settings) {
    add("Settings of the single-node database, queried at the start of the run:", "", "| Setting | Value |", "| --- | --- |");
    for (const [name, value] of Object.entries(env.postgres.settings)) add(`| \`${name}\` | \`${value === "" ? "(empty)" : value}\` |`);
    add("");
  }

  add("## Suites", "", "| Suite | What | Result | Passed | Failed | Skipped | Wall clock |", "| --- | --- | --- | --- | --- | --- | --- |");
  for (const suite of summary.suites) add(`| ${suite.id} | ${cell(suite.title)} | ${suite.status} | ${suite.passed} | ${suite.failed} | ${suite.skipped} | ${seconds(suite.wallClockMs)} |`);
  const totals = summary.totals;
  add(`| **Total** | | **${summary.status}** | ${totals.passed} | ${totals.failed} | ${totals.skipped} | ${seconds(summary.wallClockMs)} |`, "");

  const failures = summary.suites.flatMap((suite) => suite.tests.filter((test) => test.status === "failed").map((test) => ({ suite: suite.id, ...test })));
  if (failures.length > 0) {
    add("## Failures", "");
    for (const failure of failures) add(`- **${failure.suite}** ${cell(failure.name)}: ${cell(failure.error ?? "")}`);
    add("");
  }

  add("## Qualified topologies in this run", "", "| Profile | Topology | Settings observed | Evidence |", "| --- | --- | --- | --- |");
  const find = (scenario, name) => summary.evidence.find((item) => item.scenario === scenario && item.name === name);
  const single = find("C", "settings");
  const sync = find("D", "sync/settings");
  add(`| Single primary | One \`${IMAGE}\` container | ${single ? cell(flatten(single.settings).join("; ")) : "not run"} | Suites conformance, A, B, C, F, G, H |`);
  add(`| Primary with one synchronous standby | Two \`${IMAGE}\` containers on a Docker network; standby from \`pg_basebackup\` | ${sync ? cell(flatten(sync.settings).join("; ")) : "not run"} | Suite D, first half |`);
  add("| NOT qualified: asynchronous standby as a failover target | Two containers; the standby stopped before acknowledged commits, then promoted | as the single primary | Suite D, negative control: a consumed token was released a second time |", "");

  const matrix = find("E", "restore-detection-matrix");
  const promotion = find("D", "sync/promotion");
  add("## Restore-detection matrix", "", "The adapter compares the cluster's system identifier and the timeline it is writing WAL on with the values recorded in the namespace record. \"Detected\" means the namespace read `quarantined` with no operator action.", "");
  add("| Event | System identifier changed | Timeline changed | Detected |", "| --- | --- | --- | --- |");
  if (promotion) add(`| Promotion of a streaming standby (suite D) | ${promotion.systemIdentifierChanged ? "yes" : "no"} | ${promotion.timeline.recorded !== promotion.timeline.insertAfterPromotion ? `yes (${promotion.timeline.recorded} to ${promotion.timeline.insertAfterPromotion})` : "no"} | ${promotion.recoveryStateOnFirstCall === "quarantined" ? "yes, on the first call" : "NO"} |`);
  for (const row of matrix?.rows ?? []) add(`| ${cell(row.method)} | ${row.systemIdentifierChanged ? "yes" : "no"} | ${row.timelineChanged ? "yes" : "no"} | ${row.detected ? "yes" : "**no**"} |`);
  add("| Restart or crash recovery of the same cluster (suite C) | no | no | not a restore: the namespace keeps serving |", "");
  const lag = find("D", "sync/control-file-timeline-lag");
  if (lag) add(`After the promotion in suite D, \`pg_control_checkpoint().timeline_id\` ${lag.caughtUp ? `kept the old timeline for ${seconds(lag.ms)}` : `still showed the old timeline when observation stopped after ${seconds(lag.ms)}`}. The adapter reads the WAL insert timeline instead, which had changed on the first call.`, "");

  add("## Evidence by scenario", "", "Each row is a finding a test recorded after its assertions passed. Counts and trial numbers are from this run.", "");
  const groups = new Map();
  for (const item of summary.evidence) {
    if (!groups.has(item.scenario)) groups.set(item.scenario, []);
    groups.get(item.scenario).push(item);
  }
  for (const [scenario, items] of groups) {
    add(`### ${scenario}`, "", "| Finding | Recorded |", "| --- | --- |");
    for (const { scenario: _scenario, name, ...data } of items) add(`| ${cell(name)} | ${cell(flatten(data).join("; "))} |`);
    add("");
  }

  add("## Skipped", "");
  const skipped = summary.suites.flatMap((suite) => suite.tests.filter((test) => test.status === "skipped").map((test) => ({ suite: suite.id, ...test })));
  if (skipped.length === 0) add("Nothing was skipped.", "");
  else {
    const reasons = new Map();
    for (const test of skipped) {
      const key = `${test.suite}: ${test.reason}`;
      reasons.set(key, (reasons.get(key) ?? 0) + 1);
    }
    add("A skipped case is not a pass.", "", "| Suite and reason | Cases |", "| --- | --- |");
    for (const [reason, count] of reasons) add(`| ${cell(reason)} | ${count} |`);
    add("");
  }

  add("## All cases", "");
  for (const suite of summary.suites) {
    add(`<details><summary>${suite.id}: ${suite.passed} passed, ${suite.failed} failed, ${suite.skipped} skipped</summary>`, "");
    for (const test of suite.tests) add(`- ${test.status}: ${cell(test.name)}${test.reason ? ` (${cell(test.reason)})` : ""}${test.status === "failed" ? `: ${cell(test.error ?? "")}` : ""}`);
    add("", "</details>", "");
  }
  return `${lines.join("\n")}\n`;
}

async function main() {
  const startedAt = new Date();
  const scratch = mkdtempSync(join(os.tmpdir(), "rsvq-"));
  const evidenceFile = join(scratch, "evidence.jsonl");
  writeFileSync(evidenceFile, "");
  process.env.RSVQ_EVIDENCE_FILE = evidenceFile;
  process.env.RSVQ_RUN_ID = RUN_ID;

  const noDocker = dockerUnavailable();
  const environment = {
    node: process.version,
    pg: require("pg/package.json").version,
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    commit: tryExec("git", ["-C", packageRoot, "rev-parse", "HEAD"]),
    dirty: (tryExec("git", ["-C", packageRoot, "status", "--porcelain", "--", ".", ":(exclude)qualification/report"]) ?? "") !== "",
    docker: noDocker ? null : tryExec("docker", ["version", "--format", "{{.Server.Version}}"]),
    image: {
      name: IMAGE,
      id: noDocker ? null : tryExec("docker", ["image", "inspect", IMAGE, "--format", "{{.Id}}"]),
      digests: noDocker ? null : tryExec("docker", ["image", "inspect", IMAGE, "--format", "{{join .RepoDigests \", \"}}"]),
    },
    database: "none",
    postgres: null,
  };

  const suites = [];
  let topology;
  let cleanup = "nothing was created";
  try {
    const external = typeof process.env.RSV_PG_ADMIN_URL === "string" && typeof process.env.RSV_PG_APP_URL === "string";
    if (external) environment.database = "provided through RSV_PG_ADMIN_URL and RSV_PG_APP_URL";
    else if (!noDocker) {
      topology = createTopology("s");
      const node = await topology.primary("pg", port(1));
      process.env.RSV_PG_ADMIN_URL = node.adminUrl;
      process.env.RSV_PG_APP_URL = node.appUrl;
      environment.database = `a ${IMAGE} container started by this run, default configuration except max_connections=300`;
    }
    if (process.env.RSV_PG_ADMIN_URL !== undefined) environment.postgres = await databaseFacts(process.env.RSV_PG_ADMIN_URL);

    for (const suite of SUITES) {
      if (only !== undefined && !only.includes(suite.id)) continue;
      process.stdout.write(`${suite.id}: ${suite.title} ... `);
      const result = await runSuite(suite);
      suites.push(result);
      process.stdout.write(`${result.status} (${result.passed} passed, ${result.failed} failed, ${result.skipped} skipped, ${seconds(result.wallClockMs)})\n`);
    }
  } finally {
    await topology?.cleanup().catch(() => undefined);
    if (!noDocker) {
      await removeRun().catch(() => undefined);
      const left = await remaining().catch(() => ({ containers: "unknown", volumes: "unknown", networks: "unknown" }));
      cleanup = left.containers === "" && left.volumes === "" && left.networks === "" ? "none" : `LEFT BEHIND: ${JSON.stringify(left)}`;
    }
  }

  const evidence = readFileSync(evidenceFile, "utf8").split("\n").filter((line) => line !== "").map((line) => JSON.parse(line));
  rmSync(scratch, { recursive: true, force: true });
  const totals = { passed: 0, failed: 0, skipped: 0 };
  for (const suite of suites) for (const key of Object.keys(totals)) totals[key] += suite[key];
  const wholeSuitesSkipped = suites.filter((suite) => suite.status === "skipped").map((suite) => suite.id);
  const status = totals.failed > 0 ? "failed" : wholeSuitesSkipped.length > 0 || only !== undefined ? "incomplete" : "passed";
  const summary = {
    package: "@redact-secret/store-postgres",
    status,
    startedAt: startedAt.toISOString(),
    wallClockMs: Date.now() - startedAt.getTime(),
    environment,
    cleanup,
    totals,
    wholeSuitesSkipped,
    suites: suites.map(({ needs: _needs, ...suite }) => ({ ...suite, file: relative(packageRoot, join(packageRoot, suite.file)) })),
    evidence,
  };
  mkdirSync(reportDirectory, { recursive: true });
  writeFileSync(join(reportDirectory, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(join(reportDirectory, "report.md"), markdown(summary));
  process.stdout.write(`\n${status.toUpperCase()}: ${totals.passed} passed, ${totals.failed} failed, ${totals.skipped} skipped in ${seconds(summary.wallClockMs)}. Docker resources left: ${cleanup}.\nReport: ${relative(process.cwd(), join(reportDirectory, "report.md"))}\n`);
  if (status === "failed" || cleanup.startsWith("LEFT") || (requireAll && status !== "passed")) process.exitCode = 1;
}

// An interrupted run still removes what it started: everything carries the run label.
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    removeRun()
      .catch(() => undefined)
      .finally(() => process.exit(130));
  });
}

await main();
