// Scenario F: the serving role, and migrations.
//
// Every other test file of this package (the conformance suite and scenarios
// A, B, G, and H) connects as the serving role of RSV_PG_APP_URL, which holds
// only what `grantStatements` grants. This file shows what that role is, what
// it cannot do, and how migrations behave.
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { after, before, describe, test } from "node:test";

import { StoreError } from "@redact-secret/vault-contracts";

import * as api from "../dist/index.js";
import { createPostgresStore, grantStatements, migrate, migrationStatements, SCHEMA_VERSION } from "../dist/index.js";
import { evidence, MIGRATE_WORKER_PATH, openPool, randomNamespace, rawCapture, rawCommit, rows } from "../qualification/lib/harness.mjs";
import { ADMIN_URL, APP_URL, prepare, SCHEMA, SKIP } from "./helpers.mjs";

const TABLES = ["rsv_schema", "rsv_namespace", "rsv_capture", "rsv_entry", "rsv_receipt"];
const PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"];
const EXPECTED = {
  rsv_schema: ["SELECT"],
  rsv_namespace: ["SELECT", "INSERT", "UPDATE"],
  rsv_capture: ["SELECT", "INSERT", "UPDATE", "DELETE"],
  rsv_entry: ["SELECT", "INSERT", "UPDATE", "DELETE"],
  rsv_receipt: ["SELECT", "INSERT", "UPDATE", "DELETE"],
};

describe("F. least privilege and migrations", { skip: SKIP }, () => {
  let admin;
  let app;
  const scratch = `rsvq_mig_${Math.random().toString(36).slice(2, 10)}`;
  const role = SKIP ? "" : new URL(APP_URL).username;

  before(async () => {
    await prepare();
    admin = openPool(ADMIN_URL, 4);
    app = openPool(APP_URL, 4);
  });

  after(async () => {
    await admin?.query(`DROP SCHEMA IF EXISTS "${scratch}" CASCADE`).catch(() => undefined);
    await app?.end();
    await admin?.end();
  });

  test("the serving role is not a superuser and holds exactly the privileges of grantStatements", async () => {
    const [attributes] = await rows(app, "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user");
    assert.deepEqual(attributes, { rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false });
    const [schema] = await rows(app, "SELECT has_schema_privilege(current_user, $1, 'USAGE') AS usage, has_schema_privilege(current_user, $1, 'CREATE') AS can_create", [SCHEMA]);
    assert.deepEqual(schema, { usage: true, can_create: false });
    const held = {};
    for (const table of TABLES) {
      held[table] = [];
      for (const privilege of PRIVILEGES) {
        const [{ ok }] = await rows(app, "SELECT has_table_privilege(current_user, $1, $2) AS ok", [`"${SCHEMA}".${table}`, privilege]);
        if (ok) held[table].push(privilege);
      }
    }
    assert.deepEqual(held, EXPECTED);
    const [{ owner }] = await rows(app, "SELECT bool_or(tableowner = current_user) AS owner FROM pg_tables WHERE schemaname = $1", [SCHEMA]);
    assert.equal(owner, false, "the serving role owns no table");
    assert.equal(grantStatements(SCHEMA, role).length, 4);
    evidence("F", "role-privileges", { role: "serving role of RSV_PG_APP_URL", attributes, schema, tables: held });
  });

  test("the serving role cannot TRUNCATE, DROP, or ALTER the tables, create objects, read pg_authid, or weaken its session", async () => {
    const denied = {};
    for (const [label, statement] of [
      ...TABLES.map((table) => [`TRUNCATE ${table}`, `TRUNCATE "${SCHEMA}".${table}`]),
      ...TABLES.map((table) => [`DROP TABLE ${table}`, `DROP TABLE "${SCHEMA}".${table}`]),
      ...TABLES.map((table) => [`ALTER TABLE ${table}`, `ALTER TABLE "${SCHEMA}".${table} ADD COLUMN synthetic integer`]),
      ["ALTER TABLE DISABLE TRIGGER", `ALTER TABLE "${SCHEMA}".rsv_entry DISABLE TRIGGER ALL`],
      ["CREATE TABLE", `CREATE TABLE "${SCHEMA}".synthetic (id integer)`],
      ["CREATE INDEX", `CREATE INDEX synthetic ON "${SCHEMA}".rsv_entry (used)`],
      ["DROP SCHEMA", `DROP SCHEMA "${SCHEMA}" CASCADE`],
      ["UPDATE rsv_schema", `UPDATE "${SCHEMA}".rsv_schema SET version = 99`],
      ["DELETE rsv_namespace", `DELETE FROM "${SCHEMA}".rsv_namespace`],
      ["SELECT pg_authid", "SELECT rolname, rolpassword FROM pg_authid"],
      ["SET session_replication_role", "SET session_replication_role = replica"],
      ["ALTER SYSTEM", "ALTER SYSTEM SET fsync = off"],
    ]) {
      let code = "allowed";
      try {
        await app.query(statement);
      } catch (thrown) {
        code = thrown.code;
      }
      denied[label] = code;
      assert.equal(code, "42501", `${label} was not refused with insufficient_privilege (${code})`);
    }
    const [{ n }] = await rows(admin, `SELECT count(*)::int AS n FROM information_schema.columns WHERE table_schema = $1 AND column_name = 'synthetic'`, [SCHEMA]);
    assert.equal(n, 0);
    const [{ version }] = await rows(admin, `SELECT version FROM "${SCHEMA}".rsv_schema`);
    assert.equal(version, SCHEMA_VERSION);
    evidence("F", "denied-statements", { statements: Object.keys(denied).length, sqlstate: "42501" });
  });

  test("the serving role cannot run migrations", async () => {
    const fresh = `rsvq_app_${Math.random().toString(36).slice(2, 10)}`;
    await assert.rejects(migrate(app, fresh), (thrown) => thrown instanceof StoreError && thrown.code === "STORE_UNAVAILABLE");
    const [{ n }] = await rows(admin, "SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = $1", [fresh]);
    assert.equal(n, 0);
    // On the existing schema it cannot either: it may not create objects there.
    await assert.rejects(migrate(app, SCHEMA), (thrown) => thrown instanceof StoreError && thrown.code === "STORE_UNAVAILABLE");
  });

  test("migrations are idempotent and never rewrite stored state", async () => {
    await migrate(admin, scratch);
    for (const statement of grantStatements(scratch, role)) await admin.query(statement);
    const store = await createPostgresStore({ pool: app, schema: scratch });
    const namespace = randomNamespace("migrate");
    await store.initializeNamespace({ namespace, epoch: 4 });
    const created = rawCapture({ namespace, entries: 2, maxUses: 3, epoch: 4 });
    await store.createCapture(created);
    assert.equal((await store.commitRestore(await rawCommit(store, created, { counts: [2, 1] }))).outcome, "committed");
    const revoked = rawCapture({ namespace, epoch: 4 });
    await store.createCapture(revoked);
    await store.revokeCapture({ scope: revoked.scope, captureId: revoked.capture.captureId, now: Date.now(), retentionMs: 60_000, fenceAbsent: false });
    const snapshot = async () => ({
      namespace: await rows(admin, `SELECT * FROM "${scratch}".rsv_namespace ORDER BY namespace`),
      captures: await rows(admin, `SELECT capture_id, state, generation, key_revision, epoch FROM "${scratch}".rsv_capture ORDER BY capture_id`),
      entries: await rows(admin, `SELECT entry_id, used, max_uses, lifecycle_revision, ciphertext_revision FROM "${scratch}".rsv_entry ORDER BY entry_id`),
      receipts: await rows(admin, `SELECT attempt_id, committed_at FROM "${scratch}".rsv_receipt ORDER BY attempt_id`),
      schema: await rows(admin, `SELECT * FROM "${scratch}".rsv_schema`),
      objects: await rows(admin, "SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 ORDER BY c.relname", [scratch]),
    });
    const before_ = await snapshot();
    assert.deepEqual(before_.entries.map((entry) => entry.used).sort(), [0, 1, 2]);
    for (let round = 0; round < 3; round += 1) await migrate(admin, scratch);
    assert.deepEqual(await snapshot(), before_, "three more migrations changed nothing");
    assert.equal((await store.recoveryState({ namespace })).epoch, 4);
    evidence("F", "migrate-idempotent", { reruns: 3, rowsPreserved: true, objects: before_.objects.length });
  });

  test("two processes migrating the same new schema at once both succeed", async () => {
    const schema = `${scratch}_c`;
    const start = () =>
      new Promise((resolve, reject) => {
        const child = fork(MIGRATE_WORKER_PATH, [], {
          env: { ...process.env, RSVQ_MIGRATE_CONFIG: JSON.stringify({ url: ADMIN_URL, schema, rounds: 5 }) },
          stdio: ["ignore", "inherit", "inherit", "ipc"],
        });
        let report;
        const done = new Promise((finish) => child.once("exit", (code) => finish({ code, report })));
        child.on("message", (message) => {
          if (message.event === "ready") resolve({ child, done });
          else report = message;
        });
        child.once("error", reject);
      });
    try {
      const processes = await Promise.all([start(), start()]);
      assert.notEqual(processes[0].child.pid, processes[1].child.pid);
      for (const { child } of processes) child.send("go");
      const results = await Promise.all(processes.map(({ done }) => done));
      for (const result of results) assert.deepEqual([result.code, result.report?.failures], [0, 0]);
      const tables = await rows(admin, "SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY tablename", [schema]);
      assert.deepEqual(tables.map((row) => row.tablename), [...TABLES].sort());
      assert.deepEqual(await rows(admin, `SELECT singleton, version FROM "${schema}".rsv_schema`), [{ singleton: true, version: SCHEMA_VERSION }]);
      evidence("F", "migrate-concurrently", { processes: 2, migrationsEach: 5, failures: 0 });
    } finally {
      await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    }
  });

  test("migrations are forward-only: there is no down migration, and a store refuses a schema version it was not built for", async () => {
    assert.deepEqual(Object.keys(api).sort(), ["SCHEMA_VERSION", "createPostgresStore", "grantStatements", "migrate", "migrationStatements"]);
    assert.ok(migrationStatements(scratch).every((statement) => !/\b(DROP|TRUNCATE|DELETE|UPDATE)\b/.test(statement)), "no migration statement removes or rewrites anything");
    await migrate(admin, scratch);
    for (const version of [SCHEMA_VERSION + 1, 0]) {
      await admin.query(`UPDATE "${scratch}".rsv_schema SET version = $1`, [version]);
      await assert.rejects(createPostgresStore({ pool: app, schema: scratch }), (thrown) => thrown instanceof StoreError && thrown.code === "STORE_CAPABILITY");
      // Running this version's migration again does not move the recorded version in either direction.
      await migrate(admin, scratch);
      assert.deepEqual(await rows(admin, `SELECT version FROM "${scratch}".rsv_schema`), [{ version }]);
    }
    await admin.query(`UPDATE "${scratch}".rsv_schema SET version = $1`, [SCHEMA_VERSION]);
    await createPostgresStore({ pool: app, schema: scratch });
    await assert.rejects(createPostgresStore({ pool: app, schema: `${scratch}_absent` }), (thrown) => thrown instanceof StoreError && thrown.code === "STORE_UNAVAILABLE");
    evidence("F", "forward-only", { refusedVersions: [SCHEMA_VERSION + 1, 0], error: "STORE_CAPABILITY" });
  });
});
