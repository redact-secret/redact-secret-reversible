// Mutation controls: the harness must fail a store that has exactly one
// defect. Each mutant is the reference model with one decision broken (a
// subclass defined here, never shipped), or the model store deciding on a
// stale read. The unbroken model store is the control and must pass.
//
// The "model" group compares a store with the reference model, so it would
// catch a mutant of that model trivially. Each mutant therefore also names a
// deterministic case that must fail on its own.
import assert from "node:assert/strict";
import test from "node:test";

import { runCases, storeConformanceCases } from "../dist/index.js";
import { modelFactory } from "./model-store.mjs";
import { MUTANTS } from "./mutants.mjs";

const OPTIONS = { parallelism: 16, modelSequences: 2, modelSteps: 250 };

test("control: the unbroken reference model passes every case and skips none", async () => {
  const results = await runCases(storeConformanceCases(modelFactory(), OPTIONS));
  assert.deepEqual(results.filter((result) => result.status !== "passed"), []);
});

for (const [number, defect, options, mustFail] of MUTANTS) {
  test(`mutant ${number}: ${defect}`, async (t) => {
    const results = await runCases(storeConformanceCases(modelFactory(options), OPTIONS));
    const failed = results.filter((result) => result.status === "failed");
    assert.ok(failed.length > 0, "the harness must report at least one failing case");
    const deterministic = failed.filter((result) => result.group !== "model");
    assert.ok(
      deterministic.some((result) => result.name.startsWith(mustFail)),
      `expected the case "${mustFail}…" to fail; failing cases: ${failed.map((result) => result.name).join(" | ")}`,
    );
    t.diagnostic(`mutant ${number} failed ${failed.length} case(s): ${failed.map((result) => result.name).join(" | ")}`);
  });
}

test("mutant 12 is invisible without interleave: the write skew is only detectable through it", async () => {
  const factory = async () => {
    const { store, clock } = await modelFactory({ staleCommitRead: true })();
    return { store, clock };
  };
  const results = await runCases(storeConformanceCases(factory, OPTIONS));
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
  const skipped = results.filter((result) => result.status === "skipped");
  assert.ok(skipped.length > 0);
  assert.ok(skipped.every((result) => result.group === "interleave" && /interleave/.test(result.detail)));
});
