// The full store conformance suite against store-memory. The factory supplies
// a controllable clock and `interleave`, so no case may be skipped: the last
// test here fails if one is.
//
// Passing this suite shows that this in-memory adapter follows the contract.
// It says nothing about a database adapter.
import assert from "node:assert/strict";
import test from "node:test";

import { runCases, runWithNodeTest, STORE_CASE_GROUPS, storeConformanceCases } from "@redact-secret/vault-conformance";

import { conformanceFactory } from "./helpers.mjs";

const cases = storeConformanceCases(conformanceFactory);

runWithNodeTest(cases, test);

test("the conformance suite covers every case group and skips nothing for store-memory", async () => {
  assert.deepEqual([...new Set(cases.map((item) => item.group))], [...STORE_CASE_GROUPS]);
  const skipped = (await runCases(cases)).filter((result) => result.status === "skipped");
  assert.deepEqual(skipped.map((result) => result.name), []);
});

test("the conformance suite passes with every bound lowered", async () => {
  const { createMemoryStore } = await import("../dist/index.js");
  const lowered = storeConformanceCases(
    async () => {
      let now = 1_800_000_000_000;
      const clock = { now: () => now, advance: (ms) => { now += ms; }, set: (ms) => { now = ms; } };
      const { store } = createMemoryStore({
        now: () => now,
        maxClockSkewMs: 500,
        maxCreateEntries: 8,
        maxCreateBytes: 4096,
        maxRestoreEntries: 4,
        maxRestoreCaptures: 2,
        maxEnvelopeBytes: 1024,
      });
      return { store, clock };
    },
    { parallelism: 16, modelSequences: 1, modelSteps: 200 },
  );
  const results = await runCases(lowered);
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
  // Without `interleave` the two-connection schedules are skipped with a reason, never passed.
  const skipped = results.filter((result) => result.status === "skipped");
  assert.ok(skipped.length > 0);
  for (const result of skipped) {
    assert.equal(result.group, "interleave");
    assert.match(result.detail, /interleave/);
  }
});
