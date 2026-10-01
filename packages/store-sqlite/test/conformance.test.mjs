// The shared Store conformance suite against real SQLite files, once per
// driver (better-sqlite3 and node:sqlite), including the two-connection
// schedules of specification §5.2 (the second connection is in its own thread;
// see helpers.mjs).
//
// Zero unexplained skips: the run on the host clock cannot move time, so the
// cases that need an exact clock value report themselves skipped there, and the
// same cases run and pass in the controlled-clock run. A driver that cannot be
// used here (not installed, or a node:sqlite whose SQLite is below the store's
// minimum) is one explicit skipped test that names the reason, or a failure
// when it is better-sqlite3. The last test per driver checks all of this
// mechanically.
import assert from "node:assert/strict";
import { test } from "node:test";

import { runWithNodeTest, storeConformanceCases } from "@redact-secret/vault-conformance";

import { requestedDrivers } from "../support/drivers.mjs";
import { makeFactory } from "./helpers.mjs";

const HOST = "[host clock] ";
const CONTROLLED = "[controlled clock] ";

for (const loaded of await requestedDrivers()) {
  const label = `[${loaded.name}] `;
  if (loaded.missing !== undefined) {
    test(`${label}driver is available`, () => assert.fail(loaded.missing));
    continue;
  }
  if (loaded.skip !== undefined) {
    test(`${label}conformance suite`, { skip: loaded.skip }, () => {});
    continue;
  }

  const skips = [];
  const passes = new Set();

  /** A `test` function that records each case's outcome without changing how the runner reports it. */
  const recording = (prefix) => (name, fn) =>
    test(name, async (context) => {
      await fn({
        skip(reason) {
          skips.push({ name: name.slice(label.length + prefix.length), prefix, reason });
          context.skip(reason);
        },
      });
      if (!skips.some((entry) => entry.prefix === prefix && `${label}${prefix}${entry.name}` === name)) passes.add(name);
    });

  // 1. The host clock read through SQLite: what a deployment runs.
  runWithNodeTest(
    storeConformanceCases(makeFactory({ controlledClock: false, loaded }), { parallelism: 100, modelSteps: 150 }).map((c) => ({ ...c, name: `${label}${HOST}${c.name}` })),
    recording(HOST),
  );
  // 2. A test-owned clock row in the same file: the same transactions, and the cases that need an exact clock value.
  runWithNodeTest(
    storeConformanceCases(makeFactory({ controlledClock: true, loaded }), { parallelism: 100, modelSteps: 150 }).map((c) => ({ ...c, name: `${label}${CONTROLLED}${c.name}` })),
    recording(CONTROLLED),
  );

  test(`${label}every skip is the documented clock skip, and the same case passed in the controlled-clock run`, () => {
    assert.ok(skips.length > 0, "the host-clock run is expected to skip the time-travel cases");
    for (const skip of skips) {
      assert.equal(skip.prefix, HOST, `a skip outside the host-clock run: ${skip.name}`);
      assert.equal(skip.reason, "the factory supplies no controllable store clock (clock: null)", skip.name);
      assert.ok(passes.has(`${label}${CONTROLLED}${skip.name}`), `not run to a pass with a controlled clock: ${skip.name}`);
    }
    assert.ok([...passes].filter((name) => name.includes("interleave:")).length >= 10, "the §5.2 schedules ran in both runs");
  });
}
