import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCorpus, SENSITIVE_VALUES } from "../corpus/v1/index.mjs";
import { captureEnvironment } from "../lib/env.mjs";
import { discoverMetrics, makeContext, newResult, runMetric, toResultMeasurement, writeResult } from "../lib/harness.mjs";
import { activateSide, describeSide, loadWorkspaceSide } from "../lib/sides.mjs";
import { packedInput, spreadInput } from "../metrics/worst-case.mjs";

const side = await activateSide(await loadWorkspaceSide(), "off");
const LIMITS = { maxInputBytes: 1 << 22, maxFindings: 4096 };

function detected(text) {
  const findings = side.core.scan(text, { limits: LIMITS });
  for (const f of findings) {
    assert.equal(f.type, "aws_access_key_id");
    assert.equal(f.action, "redact");
  }
  return new Set(findings.map((f) => text.slice(f.start, f.end))).size;
}

test("generated worst-case inputs have exact sizes and exactly the planted findings", () => {
  const spread = spreadInput(64, 64 * 1024);
  assert.equal(spread.length, 64 * 1024);
  assert.equal(detected(spread), 64);
  const packed = packedInput(100, 8192);
  assert.equal(packed.length, 8192);
  assert.equal(detected(packed), 100);
  // Filler alone finds nothing.
  assert.equal(detected(packedInput(0, 16 * 1024)), 0);
  assert.ok(!/rsv_/i.test(spread + packed));
  assert.throws(() => spreadInput(1024, 1024), RangeError);
});

test("worst-case reports limit, ceiling, denial, and revocation figures without leaking values", async () => {
  const corpus = loadCorpus();
  const settings = { iterations: 3, warmup: 0 };
  const [metric] = await discoverMetrics({ only: ["worst-case"] });
  assert.equal(metric.issue, 81);
  assert.deepEqual(metric.piiModes, ["off"]);

  const outcome = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings, quick: true }));
  assert.equal(outcome.status, "ok", outcome.reason);
  const byName = Object.fromEntries(outcome.raw.map((m) => [m.name, m]));
  const expected = [
    "capture.default.input-1MiB.vault_overhead_ms",
    "capture.default.findings-1024.vault_overhead_ms",
    "capture.default.worst-1024f-128KiB.core_ms",
    "capture.reject.input-over",
    "capture.reject.findings-over",
    "capture.reject.entries-over",
    "capture.ceiling.input-4MiB.ms",
    "capture.ceiling.findings-2048.vault_overhead_ms",
    "capture.model.check_ratio",
    "capture.extrapolated.core_ms.50000f-64MiB",
    "restore.committed",
    "restore.committed.policy",
    "restore.max-size.denied.malformed-token",
    "server.restore.committed",
    "server.restore.max-size.committed",
    "server.capture.revoked-250",
    "server.revoke.ms_per_1k_revoked",
  ];
  for (const reason of ["invalid-request", "malformed-token", "unknown-token", "source", "expired", "sink-or-path", "budget", "policy"]) {
    expected.push(`restore.denied.${reason}`, `server.restore.denied.${reason}`);
  }
  for (const reason of ["unauthenticated", "revoked", "tenant-mismatch", "missing-purpose", "policy-evaluation-error"]) {
    expected.push(`server.restore.denied.${reason}`);
  }
  for (const name of expected) assert.ok(byName[name] !== undefined, name);
  for (const m of outcome.raw) {
    if (m.kind === "latency") assert.ok(m.samples.every((s) => s >= 0 || m.name.endsWith("vault_overhead_ms")), m.name);
    else assert.ok(Number.isFinite(m.value), m.name);
  }
  assert.ok(byName["capture.model.check_ratio"].value > 0);

  // Later rounds of the same side reuse the round-0 ceiling sample.
  const again = await runMetric(metric, makeContext({ side, corpus, piiMode: "off", settings, quick: true, round: 1 }));
  assert.equal(again.status, "ok", again.reason);
  const ceiling = again.raw.find((m) => m.name === "capture.ceiling.input-4MiB.ms");
  assert.equal(ceiling.value, byName["capture.ceiling.input-4MiB.ms"].value);
  assert.deepEqual(
    again.raw.map((m) => m.name),
    outcome.raw.map((m) => m.name),
  );

  const result = newResult({ kind: "run", piiMode: "off", quick: true, settings, corpus, environment: captureEnvironment(), sides: [describeSide(side)] });
  result.metrics.push({
    id: metric.id,
    issue: metric.issue,
    title: metric.title,
    status: outcome.status,
    measurements: outcome.raw.map((raw) => toResultMeasurement(raw, side.label)),
  });
  const out = join(mkdtempSync(join(tmpdir(), "bench-worst-")), "r.json");
  await writeResult(result, out);
  const text = readFileSync(out, "utf8");
  for (const value of SENSITIVE_VALUES) assert.ok(!text.includes(value));
  assert.ok(!/rsv_|SYNTHETIC/i.test(text));
});
