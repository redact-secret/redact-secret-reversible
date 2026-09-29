import assert from "node:assert/strict";
import { test } from "node:test";

import { findLeaks } from "../lib/leak-guard.mjs";
import { RESULT_SCHEMA, validateResult } from "../lib/schema.mjs";

function sampleResult() {
  return {
    schema: RESULT_SCHEMA,
    kind: "run",
    createdAt: "2026-09-29T00:00:00.000Z",
    mode: { pii: "off", quick: true, iterations: 20, warmup: 5, rounds: null },
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
      runner: "local",
    },
    sides: [
      {
        label: "candidate",
        source: "workspace",
        piiActivation: null,
        vault: { version: "0.1.0-alpha.3" },
        vaultServer: null,
        core: { version: "0.1.0-beta.10", artifact: "addon" },
      },
    ],
    metrics: [
      {
        id: "m",
        issue: 77,
        title: "M",
        status: "ok",
        measurements: [
          { name: "capture.total", side: "candidate", kind: "latency", unit: "ms", n: 3, p50: 1, p95: 2, p99: 3, mean: 2, min: 1, max: 3, params: { inputBytes: 1024 } },
          { name: "size", side: "candidate", kind: "deterministic", unit: "bytes", value: 10, threshold: { maxRatio: 1.05 } },
        ],
      },
    ],
  };
}

test("a well-formed run result is valid", () => {
  assert.deepEqual(validateResult(sampleResult()), []);
});

test("environment, mode, and corpus fields are required", () => {
  for (const mutate of [
    (r) => delete r.environment.node,
    (r) => delete r.environment.runner,
    (r) => (r.mode.pii = "maybe"),
    (r) => delete r.mode.pii,
    (r) => (r.corpus.version = "v1"),
    (r) => delete r.sides[0].core.version,
    (r) => (r.sides = []),
  ]) {
    const r = sampleResult();
    mutate(r);
    assert.notDeepEqual(validateResult(r), [], mutate.toString());
  }
});

test("latency measurements must carry p50/p95/p99 and a sample count", () => {
  for (const key of ["n", "p50", "p95", "p99"]) {
    const r = sampleResult();
    delete r.metrics[0].measurements[0][key];
    assert.notDeepEqual(validateResult(r), [], key);
  }
  const r = sampleResult();
  r.metrics[0].measurements[0].p95 = 0.5;
  assert.match(validateResult(r).join(), /p50 <= p95 <= p99/);
});

test("measurements are closed: raw samples or values cannot be smuggled in", () => {
  const r = sampleResult();
  r.metrics[0].measurements[0].samples = [1, 2, 3];
  r.metrics[0].measurements[0].output = "text";
  const errors = validateResult(r).join("\n");
  assert.match(errors, /unexpected key "samples"/);
  assert.match(errors, /unexpected key "output"/);

  const long = sampleResult();
  long.metrics[0].measurements[0].params.text = "x".repeat(200);
  assert.match(validateResult(long).join(), /params.text/);
});

test("a measurement must name a known side", () => {
  const r = sampleResult();
  r.metrics[0].measurements[0].side = "baseline";
  assert.match(validateResult(r).join(), /side must name/);
});

test("comparisons only appear in compare results and are shape-checked", () => {
  const run = sampleResult();
  run.comparisons = [];
  assert.match(validateResult(run).join(), /only allowed for kind compare/);

  const cmp = sampleResult();
  cmp.kind = "compare";
  cmp.mode.rounds = 4;
  cmp.comparisons = [
    {
      metric: "m",
      measurement: "capture.total",
      kind: "latency",
      unit: "ms",
      candidate: "candidate",
      baseline: "baseline",
      ratio: 1.02,
      ci: { lo: 0.98, hi: 1.06, level: 0.95 },
      verdict: "ok",
      gating: true,
      rule: "ratio > 1.10 and CI excludes 1.0 -> warn",
    },
  ];
  assert.deepEqual(validateResult(cmp), []);
  cmp.comparisons[0].verdict = "great";
  assert.match(validateResult(cmp).join(), /verdict/);
});

test("mode.tier and a metric's compare rounds are optional but checked", () => {
  const r = sampleResult();
  assert.deepEqual(validateResult(r), []);
  r.mode.tier = "standard";
  r.metrics[0].rounds = 3;
  assert.deepEqual(validateResult(r), []);
  r.mode.tier = "huge";
  r.metrics[0].rounds = 0;
  const errors = validateResult(r).join();
  assert.match(errors, /mode\.tier/);
  assert.match(errors, /rounds must be a positive integer/);
});

test("the leak guard flags corpus values and token markers without echoing them", () => {
  const secret = "SYNTHETICxREVOKED-example";
  const reasons = findLeaks(`{"x":"<rsv_abc>","y":"${secret}"}`, [secret]);
  assert.equal(reasons.length, 3);
  for (const reason of reasons) assert.ok(!reason.includes(secret) && !reason.includes("rsv_abc"));
  assert.deepEqual(findLeaks(JSON.stringify(sampleResult()), [secret]), []);
});
