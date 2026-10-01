// The shared Store conformance suite against a real PostgreSQL server.
import { test } from "node:test";

import { runWithNodeTest, storeConformanceCases } from "@redact-secret/vault-conformance";

import { conformanceFactory, controlledClockFactory, SKIP } from "./helpers.mjs";

if (SKIP) {
  test("store conformance against PostgreSQL", { skip: SKIP }, () => {});
} else {
  // 1. The database's own clock: what a deployment runs. Cases that need an
  //    exact clock value report themselves skipped.
  runWithNodeTest(
    storeConformanceCases(conformanceFactory, { parallelism: 100, modelSteps: 150 }).map((c) => ({ ...c, name: `[database clock] ${c.name}` })),
    test,
  );
  // 2. A test-owned clock row: the same transactions, and no case skipped.
  runWithNodeTest(
    storeConformanceCases(controlledClockFactory, { parallelism: 100, modelSteps: 150 }).map((c) => ({ ...c, name: `[controlled clock] ${c.name}` })),
    test,
  );
}
