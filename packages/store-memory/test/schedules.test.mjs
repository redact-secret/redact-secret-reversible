// The language-neutral schedule corpus (conformance/persistent/v1/schedules.json)
// run through the JavaScript driver, compared with this package's native
// harness (@redact-secret/vault-conformance). The corpus is the oracle for
// every language; this file shows that for store-memory it says what the
// native harness says, case by case, in four configurations.
//
// Passing shows that this in-memory adapter follows the contract. It says
// nothing about a database adapter, or about any other language.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createMemoryStore } from "@redact-secret/store-memory";
import { runCases, storeConformanceCases } from "@redact-secret/vault-conformance";

import { conformanceFactory } from "./helpers.mjs";

const V1 = new URL("../../../conformance/persistent/v1/", import.meta.url);
const { runSchedules, loadSchedules, stdioDriver } = await import(new URL("orchestrator.mjs", V1).href);
const { inProcessDriver } = await import(new URL("driver-js.mjs", V1).href);

const doc = await loadSchedules();

// Native cases that have no schedule, and why. Everything else maps to exactly one schedule.
const NATIVE_ONLY = [
  ["aliasing: a caller that changes its buffers after createCapture does not change the store", "in-process buffer ownership"],
  ["aliasing: a caller that changes returned buffers does not change the store", "in-process buffer ownership"],
  ["aliasing: a caller that changes its digest or key buffers after the call does not change the store", "in-process buffer ownership"],
];

function statusOf(results) {
  return new Map(results.map((result) => [result.name ?? result.native, result.status]));
}

async function scheduleStatuses({ parallelism = 100, storeOptions = {} } = {}) {
  const driver = inProcessDriver();
  const results = await runSchedules({ doc, drivers: new Map([["*", driver]]), options: { parallelism, storeOptions } });
  return results;
}

test("schedules.json is up to date with its generator", () => {
  execFileSync(process.execPath, [fileURLToPath(new URL("generate-schedules.mjs", V1)), "--check"], { stdio: "pipe" });
});

test("every schedule case is well-formed: unique ids, a known level, steps", () => {
  assert.equal(new Set(doc.cases.map((item) => item.id)).size, doc.cases.length);
  for (const item of doc.cases) {
    assert.ok(["store", "server"].includes(item.level), item.id);
    assert.ok(Array.isArray(item.steps) && item.steps.length > 0, item.id);
  }
  const natives = doc.cases.filter((item) => item.native !== undefined).map((item) => item.native);
  assert.equal(new Set(natives).size, natives.length, "a native case is converted once");
});

test("through the stdio driver, the store-memory schedules pass and none is skipped", async () => {
  const driver = stdioDriver(process.execPath, [fileURLToPath(new URL("driver-js.mjs", V1))]);
  try {
    const results = await runSchedules({ doc, drivers: new Map([["*", driver]]), options: { level: "store" } });
    assert.deepEqual(results.filter((result) => result.status !== "passed").map((result) => `${result.id}: ${result.detail}`), []);
    assert.ok(results.length >= 100, "the corpus has at least 100 store cases");
  } finally {
    await driver.close();
  }
});

async function compareWithNative(label, { nativeFactory, storeOptions, nativeOptions = {} }) {
  const native = await runCases(storeConformanceCases(nativeFactory, { parallelism: 100, ...nativeOptions }));
  const nativeStatus = new Map(native.map((result) => [result.name, result.status]));
  const scheduled = await scheduleStatuses({ storeOptions });
  const mapped = new Set();
  const differences = [];
  for (const result of scheduled.filter((item) => item.native !== null)) {
    mapped.add(result.native);
    assert.ok(nativeStatus.has(result.native), `${result.id} names a native case that does not exist: ${result.native}`);
    if (nativeStatus.get(result.native) !== result.status) {
      differences.push(`${label}: ${result.id}: schedule ${result.status}${result.detail === undefined ? "" : ` (${result.detail})`}, native ${nativeStatus.get(result.native)}`);
    }
  }
  assert.deepEqual(differences, []);
  assert.deepEqual(
    native.filter((result) => !mapped.has(result.name) && result.group !== "model").map((result) => result.name).sort(),
    NATIVE_ONLY.map(([name]) => name).sort(),
    "every native case except the listed ones has a schedule",
  );
  // The schedules that have no native counterpart pass too.
  assert.deepEqual(scheduled.filter((item) => item.native === null && item.status === "failed"), []);
  return { native, scheduled };
}

test("identical to the native harness: controllable clock and holds", async () => {
  const { scheduled } = await compareWithNative("default", { nativeFactory: conformanceFactory });
  assert.deepEqual(scheduled.filter((item) => item.status !== "passed"), []);
});

test("identical to the native harness: a clock the harness cannot move, and no holds", async () => {
  const nativeFactory = async () => {
    const { store } = createMemoryStore({ now: Date.now });
    return { store, clock: null };
  };
  const { scheduled } = await compareWithNative("no clock", { nativeFactory, storeOptions: { realClock: true, noHolds: true } });
  const skipped = scheduled.filter((item) => item.status === "skipped");
  assert.ok(skipped.length >= 10, "time-travel and two-connection cases are skipped, never passed");
  for (const item of skipped) assert.match(item.detail, /testClock|hold|controllable store clock|maxClockSkewMs/);
});

test("identical to the native harness: every bound lowered", async () => {
  const bounds = { maxClockSkewMs: 500, maxCreateEntries: 8, maxCreateBytes: 4096, maxRestoreEntries: 4, maxRestoreCaptures: 2, maxEnvelopeBytes: 1024 };
  const nativeFactory = async () => {
    let now = 1_800_000_000_000;
    const clock = { now: () => now, advance: (ms) => { now += ms; }, set: (ms) => { now = ms; } };
    const { store } = createMemoryStore({ now: () => now, ...bounds });
    return { store, clock };
  };
  await compareWithNative("lowered", { nativeFactory, storeOptions: { ...bounds, noHolds: true } });
});

test("identical to the native harness: a smaller parallelism", async () => {
  const nativeResults = await runCases(storeConformanceCases(conformanceFactory, { parallelism: 8 }));
  const scheduled = await scheduleStatuses({ parallelism: 8 });
  const byName = new Map(nativeResults.map((result) => [result.name, result.status]));
  for (const result of scheduled.filter((item) => item.native !== null)) {
    assert.equal(result.status, byName.get(result.native), result.id);
  }
});
