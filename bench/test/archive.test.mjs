import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { ARCHIVE_DIR } from "../archive.mjs";
import { ARCHIVE_SCHEMA, buildArchive, validateArchive } from "../lib/archive.mjs";
import { RESULT_SCHEMA } from "../lib/schema.mjs";

function side(label, source, version, extra = {}) {
  return {
    label,
    source,
    piiActivation: null,
    vault: { version },
    vaultServer: { version },
    core: { version: "0.1.0-beta.10", artifact: "addon" },
    ...extra,
  };
}

function compareResult({ pii = "off", candidate = "0.1.0-alpha.4", baseline = "0.1.0-alpha.3", gitSha = "0123456789ab", quick = false, runner } = {}) {
  return {
    schema: RESULT_SCHEMA,
    kind: "compare",
    createdAt: "2026-09-29T00:00:00.000Z",
    mode: { pii, quick, tier: "standard", iterations: 1000, warmup: 200, rounds: 10 },
    corpus: { version: "corpus-v1", sha256: "a".repeat(64) },
    environment: {
      node: "22.16.0",
      v8: "12.4",
      platform: "linux",
      arch: "x64",
      osRelease: "6.8",
      cpuModel: "Example CPU",
      cpuCount: 4,
      totalMemoryBytes: 1024,
      runner: runner ?? "github-actions/Linux/X64/ubuntu24/20260928.1",
    },
    sides: [side("candidate", "workspace", candidate, { gitSha }), side("baseline", "npm", baseline)],
    metrics: [{ id: "m", issue: 77, title: "t", status: "ok", rounds: 10, measurements: [] }],
    comparisons: [
      {
        metric: "m",
        measurement: "op",
        kind: "latency",
        unit: "ms",
        candidate: "candidate",
        baseline: "baseline",
        ratio: 1.2,
        ci: { lo: 1.1, hi: 1.3, level: 0.95 },
        verdict: "warn",
        gating: true,
        rule: "r",
      },
    ],
  };
}

test("an archive holds one compare result per PII mode with a value-free summary", () => {
  const archive = buildArchive([compareResult({ pii: "on" }), compareResult({ pii: "off" })], { version: "0.1.0-alpha.4" });
  assert.equal(archive.schema, ARCHIVE_SCHEMA);
  assert.equal(archive.version, "0.1.0-alpha.4");
  assert.equal(archive.baseline, "0.1.0-alpha.3");
  assert.deepEqual(
    archive.summary.map((s) => [s.pii, s.tier, s.corpus, s.warn, s.fail]),
    [
      ["off", "standard", "corpus-v1", 1, 0],
      ["on", "standard", "corpus-v1", 1, 0],
    ],
  );
  assert.deepEqual(validateArchive(archive), []);
  assert.deepEqual(validateArchive(JSON.parse(JSON.stringify(archive))), []);

  const tampered = { ...archive, summary: archive.summary.map((s) => ({ ...s, warn: 0 })) };
  assert.match(validateArchive(tampered).join(), /summary/);
  assert.match(validateArchive({ ...archive, extra: 1 }).join(), /unexpected key/);
});

test("only full, clean, CI-run release comparisons are archived", () => {
  const cases = [
    [[compareResult({ quick: true })], /quick/],
    [[compareResult({ gitSha: "0123456789ab-dirty" })], /clean commit/],
    [[compareResult({ runner: "local" })], /GitHub Actions/],
    [[compareResult({ candidate: "0.1.0-alpha.3" })], /A\/A/],
    [[compareResult(), compareResult()], /appears twice/],
    [[compareResult(), compareResult({ pii: "on", gitSha: "ba9876543210" })], /commit differs/],
    [[compareResult(), compareResult({ pii: "on", baseline: "0.1.0-alpha.2" })], /baseline version differs/],
  ];
  for (const [results, pattern] of cases) assert.throws(() => buildArchive(results), pattern);
  assert.throws(() => buildArchive([compareResult()], { version: "0.1.0-alpha.5" }), /does not match/);
  assert.equal(buildArchive([compareResult({ runner: "local" })], { allowLocal: true }).version, "0.1.0-alpha.4");

  const run = compareResult();
  run.kind = "run";
  delete run.comparisons;
  assert.throws(() => buildArchive([run]), /kind must be "compare"/);
});

test("every committed per-release archive is valid", () => {
  const files = readdirSync(ARCHIVE_DIR).filter((f) => f.endsWith(".json"));
  for (const file of files) {
    const archive = JSON.parse(readFileSync(join(ARCHIVE_DIR, file), "utf8"));
    assert.deepEqual(validateArchive(archive), [], file);
    assert.equal(file, `${archive.version}.json`);
  }
});
