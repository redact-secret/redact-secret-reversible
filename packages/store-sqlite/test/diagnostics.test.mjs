// Errors and diagnostics expose no path, driver text, input, or ciphertext.
import assert from "node:assert/strict";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import { checkDeployment, createSqliteStore } from "../dist/index.js";
import { openSqliteStore } from "../dist/store.js";
import { initialized, randomNamespace, rawCapture } from "../support/fixtures.mjs";
import { driver, BUSY_MS, freshDatabase, tempDir } from "./helpers.mjs";

const DISTINCTIVE = "synthetic-distinctive-directory-name";

function describeError(thrown) {
  return JSON.stringify({ name: thrown.name, message: thrown.message, code: thrown.code, own: Object.getOwnPropertyNames(thrown), string: String(thrown), stack: undefined });
}

describe("diagnostics", () => {
  const cleanups = [];
  after(() => {
    for (const cleanup of cleanups) cleanup();
  });

  test("a refusal at startup is a StoreError with a fixed message: no path, no driver text, no cause", async () => {
    const temp = tempDir(`${DISTINCTIVE}-`);
    cleanups.push(temp.cleanup);
    const missing = join(temp.dir, "missing.sqlite");
    for (const open of [() => createSqliteStore({ driver, filename: missing }), () => createSqliteStore({ driver, filename: join(temp.dir, "no", "such", "dir", "x.sqlite") }), () => createSqliteStore({ driver, filename: ":memory:" })]) {
      await assert.rejects(open(), (thrown) => {
        assert.ok(thrown instanceof StoreError);
        const text = describeError(thrown);
        assert.ok(!text.includes(DISTINCTIVE), text);
        assert.ok(!/sqlite|ENOENT|SQLITE_|unable to open/i.test(thrown.message), thrown.message);
        assert.equal(thrown.cause, undefined);
        return true;
      });
    }
  });

  test("a failed operation reports a fixed message and nothing of the input or the file", async () => {
    const database = await freshDatabase();
    cleanups.push(database.cleanup);
    let armed = false;
    const store = await openSqliteStore(
      { driver, filename: database.filename, busyTimeoutMs: BUSY_MS },
      {
        beforeCommit: () => {
          if (armed) throw new Error(`synthetic failure mentioning ${database.filename}`);
        },
      },
    );
    try {
      const namespace = randomNamespace("diag");
      await initialized(store, namespace, 1);
      const input = rawCapture({ namespace });
      armed = true;
      await assert.rejects(store.createCapture(input), (thrown) => {
        assert.ok(thrown instanceof StoreError);
        const text = describeError(thrown);
        assert.ok(!text.includes(database.dir), "no path");
        assert.ok(!text.includes(input.capture.captureId), "no identifier of the input");
        assert.ok(!text.includes("synthetic failure"), "the underlying error text is dropped");
        assert.equal(thrown.cause, undefined);
        return true;
      });
    } finally {
      store.close();
    }
  });

  test("checkDeployment names failed checks by fixed identifiers only", async () => {
    const temp = tempDir(`${DISTINCTIVE}-`);
    cleanups.push(temp.cleanup);
    const database = await freshDatabase();
    cleanups.push(database.cleanup);
    const report = await checkDeployment({ driver, filename: database.filename });
    assert.deepEqual(Object.keys(report).sort(), ["driver", "failures", "ok", "sqliteVersion"]);
    assert.ok(!JSON.stringify(report).includes(database.dir));
  });
});
