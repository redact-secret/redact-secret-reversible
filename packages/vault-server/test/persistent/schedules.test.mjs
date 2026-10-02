// The server-level cases of the language-neutral schedule corpus
// (conformance/persistent/v1/schedules.json), run through the JavaScript driver
// over `@redact-secret/store-memory` and the local key provider. The JavaScript
// persistent profile is the reference these cases were taken from; this file
// shows the driver and the corpus agree with it. Everything is synthetic.
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const V1 = new URL("../../../../conformance/persistent/v1/", import.meta.url);
const { runSchedules, loadSchedules, stdioDriver } = await import(new URL("orchestrator.mjs", V1).href);

test("the server-level schedules pass through the stdio JavaScript driver, and none is skipped", async () => {
  const doc = await loadSchedules();
  const driver = stdioDriver(process.execPath, [fileURLToPath(new URL("driver-js.mjs", V1))]);
  try {
    const results = await runSchedules({ doc, drivers: new Map([["*", driver]]), options: { level: "server" } });
    assert.ok(results.length >= 10, "the corpus has at least ten server cases");
    assert.deepEqual(results.filter((result) => result.status !== "passed").map((result) => `${result.id}: ${result.detail}`), []);
  } finally {
    await driver.close();
  }
});
