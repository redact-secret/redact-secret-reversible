// Scenario H, second part: what the DATABASE's own log contains.
//
// The adapter's errors are sanitized (test/diagnostics.test.mjs). The server
// log is outside the adapter's control. This file reads it with `docker logs`
// under three logging configurations and records what is there, so the
// operational guidance rests on an observation, not an assumption.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

import { createTopology, dockerUnavailable, logs, psql, sleep } from "../lib/docker.mjs";
import {
  captureText,
  evidence,
  initializeNamespace,
  openPool,
  openVault,
  port,
  prepareDatabase,
  randomAttemptId,
  randomNamespace,
  RELEASE,
  restoreRequest,
  rows,
  SCHEMA,
  settle,
  syntheticKeys,
} from "../lib/harness.mjs";

const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };

describe("H. what the PostgreSQL server log contains", { skip: dockerUnavailable() }, () => {
  let topology;
  let node;
  let admin;
  let pool;
  let vault;
  let keys;
  let namespace;
  let offset = 50_000;

  /** One capture and one restore, and the stored bytes and identifiers that belong to them. */
  const exercise = async () => {
    const { text, values } = captureText(1, offset++);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses: 3 });
    const token = captured.tokens[0].token;
    const attempt = restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [token], attemptId: randomAttemptId() });
    const restored = await settle(vault.restore(attempt));
    const [stored] = await rows(
      admin,
      `SELECT encode(e.envelope, 'hex') AS envelope, encode(c.wrapped_key, 'hex') AS wrapped, e.entry_id
         FROM "${SCHEMA}".rsv_entry e JOIN "${SCHEMA}".rsv_capture c USING (namespace, tenant, capture_id) WHERE c.capture_id = $1`,
      [captured.captureId],
    );
    return { captured, token, value: values[0], attempt, restored, ...stored };
  };

  const neverInLog = (log, run) => {
    assert.ok(!log.includes(run.value), "the plaintext value is never sent to the database");
    assert.ok(!log.includes(run.token), "the issued token is never sent to the database");
    assert.ok(!log.includes(keys.keyHex) && !log.includes(keys.digestHex), "no key is sent to the database");
  };

  const configure = async (settings) => {
    for (const [name, value] of Object.entries(settings)) await psql(node.name, value === null ? `ALTER SYSTEM RESET ${name}` : `ALTER SYSTEM SET ${name} = '${value}'`);
    await psql(node.name, "SELECT pg_reload_conf()");
    await sleep(500);
  };

  before(async () => {
    topology = createTopology("h");
    node = await topology.primary("pg", port(40));
    await prepareDatabase(node);
    admin = openPool(node.adminUrl, 2);
    pool = openPool(node.appUrl, 4);
    namespace = randomNamespace("server-log");
    keys = syntheticKeys();
    await initializeNamespace(pool, namespace, 1);
    ({ vault } = await openVault({ pool, namespace, keys }));
  });

  after(async () => {
    await pool?.end().catch(() => undefined);
    await admin?.end().catch(() => undefined);
    await topology?.cleanup();
  });

  test("default logging: no statement or parameter is logged for successful calls; a failing statement is logged with its row DETAIL", async () => {
    const defaults = Object.fromEntries(
      (await rows(admin, "SELECT name, setting FROM pg_settings WHERE name = ANY($1::text[]) ORDER BY name", [["log_statement", "log_min_duration_statement", "log_parameter_max_length", "log_parameter_max_length_on_error", "log_min_error_statement", "log_error_verbosity"]])).map((row) => [row.name, row.setting]),
    );
    assert.equal(defaults.log_statement, "none");
    const run = await exercise();
    assert.equal(run.restored.ok, true);
    let log = await logs(node.name);
    neverInLog(log, run);
    assert.ok(!log.includes(run.envelope) && !log.includes(run.wrapped) && !log.includes(run.captured.captureId), "nothing of a successful call is logged by default");

    // A statement that fails: PostgreSQL logs the error, its DETAIL, and the statement text.
    await admin.query(`ALTER TABLE "${SCHEMA}".rsv_entry ADD CONSTRAINT rsvq_synthetic_check CHECK (used < 2) NOT VALID`);
    let failed;
    try {
      failed = await settle(vault.restore(restoreRequest({ context: CONTEXT, captures: [run.captured.captureId], tokens: [run.token], attemptId: randomAttemptId() })));
    } finally {
      await admin.query(`ALTER TABLE "${SCHEMA}".rsv_entry DROP CONSTRAINT rsvq_synthetic_check`);
    }
    assert.equal(failed.code, "STORE_UNAVAILABLE");
    await sleep(300);
    log = await logs(node.name);
    neverInLog(log, run);
    assert.ok(log.includes("rsvq_synthetic_check"), "the constraint violation is in the server log");
    const failingRow = log.includes("Failing row contains");
    const rowHasIdentifiers = log.includes(run.entry_id) && log.includes(run.captured.captureId);
    const rowHasEnvelopeBytes = log.includes(run.envelope.slice(0, 24));
    assert.ok(failingRow && rowHasIdentifiers, "the DETAIL prints the failing row: tenant, entry and capture identifiers, counters");
    assert.ok(!log.includes("Parameters: $1"), "bound parameters are not logged on error by default");
    evidence("H", "server-log/default", { settings: defaults, successfulCallsLogged: false, failingStatementLogged: true, failingRowDetail: { identifiers: rowHasIdentifiers, envelopeBytes: rowHasEnvelopeBytes }, boundParameters: false, plaintextValueOrToken: false });
  });

  test("log_statement=all: every bound parameter is in the server log, including envelopes and wrapped keys, never a plaintext value", async () => {
    await configure({ log_statement: "all" });
    try {
      const run = await exercise();
      assert.equal(run.restored.ok, true);
      await sleep(300);
      const log = await logs(node.name);
      neverInLog(log, run);
      const found = {
        envelope: log.includes(run.envelope),
        wrappedKey: log.includes(run.wrapped),
        captureId: log.includes(run.captured.captureId),
        entryId: log.includes(run.entry_id),
        tenant: log.includes(CONTEXT.tenant),
        attemptId: log.includes(run.attempt.attemptId),
      };
      assert.deepEqual(found, { envelope: true, wrappedKey: true, captureId: true, entryId: true, tenant: true, attemptId: true }, "statement logging copies ciphertext, wrapped keys, and identifiers into the server log");
      evidence("H", "server-log/log_statement=all", { found, plaintextValueOrToken: false });
    } finally {
      await configure({ log_statement: null });
    }
  });

  test("log_statement=all with log_parameter_max_length=0: statements are logged without their parameters", async () => {
    await configure({ log_statement: "all", log_parameter_max_length: "0" });
    try {
      const run = await exercise();
      assert.equal(run.restored.ok, true);
      await sleep(300);
      const log = await logs(node.name);
      neverInLog(log, run);
      assert.ok(log.includes("rsv_entry"), "the statement text is logged");
      assert.ok(!log.includes(run.envelope) && !log.includes(run.wrapped) && !log.includes(run.captured.captureId) && !log.includes(run.attempt.attemptId), "no bound parameter value is logged");
      evidence("H", "server-log/log_parameter_max_length=0", { statementTextLogged: true, boundParameters: false });
    } finally {
      await configure({ log_statement: null, log_parameter_max_length: null });
    }
  });
});
