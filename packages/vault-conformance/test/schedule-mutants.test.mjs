// The mutation controls of the native harness, run against the schedule corpus
// (conformance/persistent/v1/schedules.json) through the JavaScript driver. A
// store with exactly one defect must fail the schedule that converts the case
// the native harness names for it. The unbroken model store is the control.
//
// Mutant 19 (reads return the store's own buffers) is a property of in-process
// buffer ownership, which the line protocol cannot express; it stays native.
import assert from "node:assert/strict";
import test from "node:test";

import { createModelStore } from "./model-store.mjs";
import { MUTANTS } from "./mutants.mjs";

const V1 = new URL("../../../conformance/persistent/v1/", import.meta.url);
const { runSchedules, loadSchedules } = await import(new URL("orchestrator.mjs", V1).href);
const { inProcessDriver } = await import(new URL("driver-js.mjs", V1).href);

const doc = await loadSchedules();

async function run(options, { holds = true } = {}) {
  const driver = inProcessDriver({
    open: () => {
      const { store, clock, interleave } = createModelStore(options);
      return { store, clock, interleave: holds ? interleave : null };
    },
  });
  return runSchedules({ doc, drivers: new Map([["*", driver]]), options: { level: "store", parallelism: 16 } });
}

test("control: the unbroken reference model passes every schedule and skips none", async () => {
  const results = await run({});
  assert.deepEqual(results.filter((result) => result.status !== "passed").map((result) => `${result.id}: ${result.detail}`), []);
});

for (const [number, defect, options, mustFail] of MUTANTS) {
  if (number === 19) continue;
  test(`mutant ${number}: ${defect}`, async (t) => {
    const results = await run(options);
    const failed = results.filter((result) => result.status === "failed");
    assert.ok(failed.length > 0, "the schedules must report at least one failing case");
    const expected = doc.cases.filter((item) => item.native !== undefined && item.native.startsWith(mustFail)).map((item) => item.id);
    assert.ok(expected.length > 0, `no schedule converts the native case "${mustFail}"`);
    assert.ok(
      failed.some((result) => expected.includes(result.id)),
      `expected one of ${expected.join(", ")} to fail; failing: ${failed.map((result) => result.id).join(" | ")}`,
    );
    t.diagnostic(`mutant ${number} failed ${failed.length} schedule(s)`);
  });
}

test("mutant 12 is invisible without holds: the write skew is only detectable through them", async () => {
  const results = await run({ staleCommitRead: true }, { holds: false });
  assert.deepEqual(results.filter((result) => result.status === "failed"), []);
  const skipped = results.filter((result) => result.status === "skipped");
  assert.ok(skipped.length > 0);
  assert.ok(skipped.every((result) => /hold/.test(result.detail)));
});
