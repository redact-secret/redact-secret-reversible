// Scenario H: diagnostics hygiene.
//
// PostgreSQL is made to return errors that carry row data: a unique
// violation whose DETAIL names the key value, a check violation whose DETAIL
// prints the failing row (envelope bytes included), and trigger exceptions
// that quote an envelope and a wrapped key. The test first shows that the
// driver's error really contains those bytes, then that nothing the adapter
// or the server throws, audits, or prints does.
//
// The constraint and triggers live in a scratch schema created for this file.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { inspect } from "node:util";

import { createPostgresStore, grantStatements, migrate } from "../dist/index.js";
import { hookPool } from "../qualification/lib/fault.mjs";
import {
  assertSanitized,
  captureText,
  evidence,
  openPool,
  openVault,
  randomAttemptId,
  randomNamespace,
  rawCapture,
  rawCommit,
  RELEASE,
  restoreRequest,
  rows,
  settle,
  syntheticKeys,
} from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, prepare, SKIP } from "./helpers.mjs";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const CONTEXT = { tenant: "tenant-synthetic-a", principal: "user-synthetic-1" };

describe("H. diagnostics hygiene", { skip: SKIP }, () => {
  let admin;
  let pool;
  let hooked;
  let store;
  let namespace;
  const schema = `rsvq_diag_${Math.random().toString(36).slice(2, 10)}`;
  const driverErrors = [];
  const printed = [];
  const originals = {};

  /** Runs a call, returns what it threw, and the driver error the pool saw underneath. */
  const provoke = async (call) => {
    driverErrors.length = 0;
    let thrown;
    try {
      await call();
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown !== undefined, "the call was expected to throw");
    const driver = driverErrors.find((error) => typeof error.code === "string" && error.code !== "25P02");
    return { thrown, driver, driverText: driver === undefined ? "" : inspect(driver, { depth: 6, breakLength: Infinity }) };
  };

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 4);
    pool = openPool(APP_URL, 10);
    await migrate(admin, schema);
    const role = new URL(APP_URL).username;
    for (const statement of grantStatements(schema, role)) await admin.query(statement);
    namespace = randomNamespace("diag");
    // Records every error the driver hands the adapter, as the positive control.
    hooked = hookPool(pool);
    const inner = hooked.connect.bind(hooked);
    hooked.connect = async () => {
      const client = await inner();
      return {
        ...client,
        async query(text, values) {
          try {
            return await client.query(text, values);
          } catch (error) {
            driverErrors.push(error);
            throw error;
          }
        },
      };
    };
    store = await createPostgresStore({ pool: hooked, schema, maxClockSkewMs: 30_000 });
    await store.initializeNamespace({ namespace, epoch: 1 });
    for (const method of ["log", "info", "warn", "error", "debug", "trace"]) {
      originals[method] = console[method];
      console[method] = (...args) => printed.push(inspect(args, { depth: 6 }));
    }
  });

  after(async () => {
    for (const [method, original] of Object.entries(originals)) console[method] = original;
    await admin?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await pool?.end();
    await admin?.end();
  });

  test("a unique violation whose DETAIL carries the key value", async () => {
    await admin.query(`CREATE UNIQUE INDEX rsvq_digest_once ON "${schema}".rsv_receipt (request_digest)`);
    try {
      const created = rawCapture({ namespace, maxUses: 5 });
      await store.createCapture(created);
      const first = await rawCommit(store, created);
      assert.equal((await store.commitRestore(first)).outcome, "committed");
      const second = await rawCommit(store, created, { digest: first.attempt.requestDigest });
      const { thrown, driver, driverText } = await provoke(() => store.commitRestore(second));
      const digest = hex(first.attempt.requestDigest);
      assert.equal(driver.code, "23505");
      assert.ok(driverText.includes(digest), "control: the driver's error does carry the stored bytes");
      assertSanitized(thrown, "STORE_UNAVAILABLE", [digest, "23505", "Key (", "already exists", "rsvq_digest_once", schema, namespace, created.capture.captureId, second.attempt.attemptId]);
      evidence("H", "unique-violation", { sqlstate: driver.code, driverErrorCarriedBytes: true, storeError: "STORE_UNAVAILABLE" });
    } finally {
      await admin.query(`DROP INDEX "${schema}".rsvq_digest_once`);
    }
  });

  test("a check violation whose DETAIL prints the failing row, envelope included", async () => {
    const created = rawCapture({ namespace, maxUses: 5 });
    await store.createCapture(created);
    await admin.query(`ALTER TABLE "${schema}".rsv_entry ADD CONSTRAINT rsvq_synthetic_check CHECK (used < 1) NOT VALID`);
    try {
      const commit = await rawCommit(store, created);
      const { thrown, driver, driverText } = await provoke(() => store.commitRestore(commit));
      const envelope = hex(created.entries[0].envelope);
      assert.equal(driver.code, "23514");
      assert.ok(driverText.includes(envelope.slice(0, 40)), "control: the driver's error does carry envelope bytes");
      assertSanitized(thrown, "STORE_UNAVAILABLE", [envelope.slice(0, 40), envelope.slice(0, 16), "23514", "Failing row", "rsvq_synthetic_check", created.entries[0].entryId, created.capture.captureId, schema]);
      evidence("H", "check-violation", { sqlstate: driver.code, driverErrorCarriedEnvelopeBytes: true, storeError: "STORE_UNAVAILABLE" });
    } finally {
      await admin.query(`ALTER TABLE "${schema}".rsv_entry DROP CONSTRAINT rsvq_synthetic_check`);
    }
  });

  test("exceptions that quote an envelope and a wrapped key in their message, detail, and hint", async () => {
    await admin.query(`
      CREATE FUNCTION "${schema}".rsvq_leak_entry() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'synthetic server message %', encode(NEW.envelope, 'hex')
          USING DETAIL = 'entry ' || NEW.entry_id || ' ' || encode(NEW.envelope, 'hex'), HINT = 'tenant ' || NEW.tenant, ERRCODE = 'P0001';
      END $$`);
    await admin.query(`
      CREATE FUNCTION "${schema}".rsvq_leak_capture() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'synthetic server message %', encode(OLD.wrapped_key, 'hex') USING DETAIL = 'capture ' || OLD.capture_id, ERRCODE = 'P0001';
      END $$`);
    const outcomes = {};
    try {
      // createCapture: the entry insert fails, quoting the envelope.
      await admin.query(`CREATE TRIGGER rsvq_leak BEFORE INSERT ON "${schema}".rsv_entry FOR EACH ROW EXECUTE FUNCTION "${schema}".rsvq_leak_entry()`);
      const blocked = rawCapture({ namespace });
      const create = await provoke(() => store.createCapture(blocked));
      const envelope = hex(blocked.entries[0].envelope);
      assert.ok(create.driverText.includes(envelope), "control: the driver's error carries the envelope");
      assertSanitized(create.thrown, "STORE_UNAVAILABLE", [envelope, hex(blocked.capture.wrappedKey), "synthetic server message", "P0001", blocked.entries[0].entryId, blocked.capture.captureId, blocked.scope.tenant]);
      outcomes.createCapture = create.thrown.code;
      await admin.query(`DROP TRIGGER rsvq_leak ON "${schema}".rsv_entry`);
      assert.equal((await rows(admin, `SELECT count(*)::int AS n FROM "${schema}".rsv_capture WHERE capture_id = $1`, [blocked.capture.captureId]))[0].n, 0, "nothing was created");

      // Every operation that updates a capture row fails, quoting the wrapped key.
      const created = rawCapture({ namespace });
      await store.createCapture(created);
      await admin.query(`CREATE TRIGGER rsvq_leak BEFORE UPDATE OR DELETE ON "${schema}".rsv_capture FOR EACH ROW EXECUTE FUNCTION "${schema}".rsvq_leak_capture()`);
      const wrapped = hex(created.capture.wrappedKey);
      const forbidden = [wrapped, "synthetic server message", "P0001", created.capture.captureId, created.scope.tenant, namespace];
      for (const [name, call] of [
        ["revokeCapture", () => store.revokeCapture({ scope: created.scope, captureId: created.capture.captureId, now: Date.now(), retentionMs: 0, fenceAbsent: false })],
        ["replaceCaptureKey", () => store.replaceCaptureKey({ scope: created.scope, captureId: created.capture.captureId, keyRevision: 1, keyRef: "local:synthetic-2", wrappedKey: created.capture.wrappedKey })],
      ]) {
        const result = await provoke(call);
        assert.ok(result.driverText.includes(wrapped), "control: the driver's error carries the wrapped key");
        assertSanitized(result.thrown, "STORE_UNAVAILABLE", forbidden);
        outcomes[name] = result.thrown.code;
      }
    } finally {
      await admin.query(`DROP TRIGGER IF EXISTS rsvq_leak ON "${schema}".rsv_entry`);
      await admin.query(`DROP TRIGGER IF EXISTS rsvq_leak ON "${schema}".rsv_capture`);
      await admin.query(`DROP FUNCTION "${schema}".rsvq_leak_entry(), "${schema}".rsvq_leak_capture()`);
    }
    evidence("H", "server-exceptions-with-row-data", { operations: outcomes, driverErrorsCarriedBytes: true });
  });

  test("connection failures: no host, port, user, password, or connection string", async () => {
    const reachable = new URL(APP_URL);
    const wrongPassword = new URL(APP_URL);
    wrongPassword.password = "synthetic-wrong-password";
    const closedPort = new URL(APP_URL);
    closedPort.hostname = "127.0.0.1";
    closedPort.port = "1";
    const results = {};
    for (const [label, target] of [
      ["wrong password", wrongPassword],
      ["closed port", closedPort],
    ]) {
      const broken = openPool(target.toString(), 1, { connectionTimeoutMillis: 3000 });
      try {
        let control;
        await broken.connect().catch((error) => {
          control = inspect(error, { depth: 4 });
        });
        assert.ok(control !== undefined && control.length > 0, "control: the driver does fail to connect");
        const forbidden = ["synthetic-wrong-password", "synthetic-local-only", reachable.username, target.host, "ECONNREFUSED", "28P01", "password authentication", "postgres://"];
        const created = await provokeOpen(() => createPostgresStore({ pool: broken, schema }));
        assertSanitized(created, "STORE_UNAVAILABLE", forbidden);
        const migrated = await provokeOpen(() => migrate(broken, schema));
        assertSanitized(migrated, "STORE_UNAVAILABLE", forbidden);
        results[label] = created.code;
      } finally {
        await broken.end().catch(() => undefined);
      }
    }
    evidence("H", "connection-failures", results);
  });

  test("through the server: errors and audit events carry no driver text, stored bytes, or value", async () => {
    const keys = syntheticKeys();
    const audit = [];
    const { vault } = await openVault({ namespace, keys, store, vaultOptions: { onAudit: (event) => audit.push(event) } });
    const { text, values } = captureText(1, 7000);
    const captured = await vault.capture(text, { context: CONTEXT, release: RELEASE, maxUses: 3 });
    const token = captured.tokens[0].token;
    const [row] = await rows(admin, `SELECT encode(e.envelope, 'hex') AS envelope, encode(c.wrapped_key, 'hex') AS wrapped FROM "${schema}".rsv_entry e JOIN "${schema}".rsv_capture c USING (namespace, tenant, capture_id) WHERE c.capture_id = $1`, [captured.captureId]);
    await admin.query(`ALTER TABLE "${schema}".rsv_entry ADD CONSTRAINT rsvq_synthetic_check CHECK (used < 1) NOT VALID`);
    let failed;
    try {
      failed = await settle(vault.restore(restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [token], attemptId: randomAttemptId() })));
    } finally {
      await admin.query(`ALTER TABLE "${schema}".rsv_entry DROP CONSTRAINT rsvq_synthetic_check`);
    }
    assert.deepEqual([failed.ok, failed.name, failed.code, failed.hasFields], [false, "VaultServerError", "STORE_UNAVAILABLE", false]);
    let thrown;
    await admin.query(`ALTER TABLE "${schema}".rsv_entry ADD CONSTRAINT rsvq_synthetic_check CHECK (used < 1) NOT VALID`);
    try {
      await vault.restore(restoreRequest({ context: CONTEXT, captures: [captured.captureId], tokens: [token], attemptId: randomAttemptId() }));
    } catch (error) {
      thrown = error;
    } finally {
      await admin.query(`ALTER TABLE "${schema}".rsv_entry DROP CONSTRAINT rsvq_synthetic_check`);
    }
    const visible = `${inspect(thrown, { showHidden: true, depth: 8 })}\n${thrown.stack}\n${JSON.stringify(audit)}`;
    for (const forbidden of [row.envelope.slice(0, 32), row.wrapped, values[0], token, "23514", "Failing row", "rsvq_synthetic_check", keys.keyHex, keys.digestHex]) {
      assert.ok(!visible.includes(forbidden), "the server error or an audit event exposed text it must not carry");
    }
    assert.equal(thrown.cause, undefined);
    assert.ok(audit.some((event) => event.operation === "restore" && event.outcome === "failed" && event.code === "STORE_UNAVAILABLE"));
    evidence("H", "server-error-and-audit", { error: failed.code, auditEvents: audit.length });
  });

  test("pg_stat_activity shows the statement text with placeholders, not the bound envelope bytes", async () => {
    const created = rawCapture({ namespace });
    const lock = await admin.connect();
    let observed;
    try {
      await lock.query("BEGIN");
      await lock.query(`LOCK TABLE "${schema}".rsv_entry IN ACCESS EXCLUSIVE MODE`);
      const creating = store.createCapture(created);
      for (let i = 0; i < 200 && observed === undefined; i += 1) {
        const found = await rows(admin, "SELECT query FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%rsv_entry%' AND pid <> pg_backend_pid()");
        if (found.length > 0) observed = found[0].query;
        else await new Promise((resolve) => setTimeout(resolve, 25));
      }
      await lock.query("ROLLBACK");
      assert.equal((await creating).outcome, "created");
    } finally {
      await lock.query("ROLLBACK").catch(() => undefined);
      lock.release();
    }
    assert.ok(observed !== undefined, "the blocked statement was visible in pg_stat_activity");
    assert.ok(observed.includes("$5") && observed.includes("unnest"), "the statement text with its placeholders");
    assert.ok(!observed.includes(hex(created.entries[0].envelope)), "bound parameter values are not part of pg_stat_activity.query");
    assert.ok(!observed.includes(created.entries[0].entryId));
    evidence("H", "pg-stat-activity", { showsStatementText: true, showsBoundParameters: false });
  });

  test("nothing was written to the console", () => {
    assert.deepEqual(printed, []);
    evidence("H", "console", { lines: printed.length });
  });
});

async function provokeOpen(call) {
  try {
    await call();
  } catch (thrown) {
    return thrown;
  }
  assert.fail("expected the call to throw");
}
