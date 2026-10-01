// A second connection for the two-connection conformance schedules, in its own
// thread: the driver is synchronous, so a competing call that must wait for
// the primary transaction's write lock can only wait in another thread. It
// opens its own store on the same file and answers RPC calls from the parent.
import { parentPort, workerData } from "node:worker_threads";

import { openSqliteStore } from "../dist/store.js";
import { loadDriver } from "./drivers.mjs";

const done = new Int32Array(workerData.done);
const loaded = await loadDriver(workerData.driverName);
const store = await openSqliteStore({ ...workerData.options, driver: loaded.driver }, { nowSql: workerData.nowSql });

parentPort.postMessage({ ready: true, capabilities: store.capabilities() });
parentPort.on("message", async (message) => {
  if (message.close) {
    store.close();
    parentPort.postMessage({ closed: true });
    return;
  }
  let reply;
  try {
    reply = { id: message.id, ok: true, value: await store[message.method](...message.args) };
  } catch (thrown) {
    reply = { id: message.id, ok: false, code: thrown?.code ?? "UNKNOWN" };
  }
  parentPort.postMessage(reply);
  // Wakes a parent thread that is blocked in Atomics.wait while this call ran.
  Atomics.add(done, 0, 1);
  Atomics.notify(done, 0);
});
