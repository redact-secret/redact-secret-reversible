// The shared Store conformance suite against real SQLite files, including the
// two-connection schedules of specification §5.2 (the second connection is in
// its own thread; see helpers.mjs).
//
// Zero unexplained skips: the run on the host clock cannot move time, so the
// cases that need an exact clock value report themselves skipped there, and the
// same cases run and pass in the controlled-clock run. The last test checks both
// statements mechanically.
import assert from "node:assert/strict";
import { test } from "node:test";

import { runWithNodeTest, storeConformanceCases } from "@redact-secret/vault-conformance";

import { makeFactory } from "./helpers.mjs";

const skips = [];
const passes = new Set();

/** A `test` function that records each case's outcome without changing how the runner reports it. */
function recording(prefix) {
  return (name, fn) =>
    test(name, async (context) => {
      await fn({
        skip(reason) {
          skips.push({ name: name.slice(prefix.length), prefix, reason });
          context.skip(reason);
        },
      });
      if (!skips.some((entry) => entry.prefix === prefix && `${prefix}${entry.name}` === name)) passes.add(name);
    });
}

const HOST = "[host clock] ";
const CONTROLLED = "[controlled clock] ";

// 1. The host clock read through SQLite: what a deployment runs.
runWithNodeTest(
  storeConformanceCases(makeFactory({ controlledClock: false }), { parallelism: 100, modelSteps: 150 }).map((c) => ({ ...c, name: `${HOST}${c.name}` })),
  recording(HOST),
);
// 2. A test-owned clock row in the same file: the same transactions, and the cases that need an exact clock value.
runWithNodeTest(
  storeConformanceCases(makeFactory({ controlledClock: true }), { parallelism: 100, modelSteps: 150 }).map((c) => ({ ...c, name: `${CONTROLLED}${c.name}` })),
  recording(CONTROLLED),
);

test("every skip is the documented clock skip, and the same case passed in the controlled-clock run", () => {
  assert.ok(skips.length > 0, "the host-clock run is expected to skip the time-travel cases");
  for (const skip of skips) {
    assert.equal(skip.prefix, HOST, `a skip outside the host-clock run: ${skip.name}`);
    assert.equal(skip.reason, "the factory supplies no controllable store clock (clock: null)", skip.name);
    assert.ok(passes.has(`${CONTROLLED}${skip.name}`), `not run to a pass with a controlled clock: ${skip.name}`);
  }
  assert.ok([...passes].filter((name) => name.includes("interleave:")).length >= 10, "the §5.2 schedules ran in both runs");
});
