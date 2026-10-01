// Shared fixtures for the qualification scenarios. Every identifier, key,
// byte, and password here is synthetic and generated per run.
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";

import { StoreError } from "@redact-secret/vault-contracts";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";
import pg from "pg";

import { createPostgresStore, grantStatements, migrate } from "../../dist/index.js";

export const SCHEMA = process.env.RSV_PG_SCHEMA ?? "rsv";
export const WORKER_PATH = fileURLToPath(new URL("./vault-worker.mjs", import.meta.url));
export const MIGRATE_WORKER_PATH = fileURLToPath(new URL("./migrate-worker.mjs", import.meta.url));

/** Unmistakably synthetic values the core detects (AGENTS.md security boundary). Never a real credential. */
export function syntheticSecret(index = 0) {
  return `ghp_SYNTHETICxREVOKEDxTESTx${String(index).padStart(13, "0")}`;
}

/** Fresh random key material for one run: the wrapping key and the digest key, as hex. */
export function syntheticKeys() {
  return { keyHex: randomBytes(32).toString("hex"), digestHex: randomBytes(32).toString("hex") };
}

export function randomNamespace(prefix = "q") {
  return `${prefix}-${Date.now().toString(36)}-${randomBytes(5).toString("hex")}`;
}

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
export function randomCaptureId() {
  let out = "cap_";
  for (const byte of randomBytes(26)) out += BASE32[byte % 32];
  return out;
}

export function randomEntryId() {
  return randomBytes(32).toString("hex");
}

export function randomAttemptId(prefix = "att") {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}

/** A pool whose idle-connection errors (a killed or restarted server) do not crash the test process. */
export function openPool(connectionString, max = 20, extra = {}) {
  const pool = new pg.Pool({ connectionString, max, ...extra });
  pool.on("error", () => {});
  return pool;
}

export async function rows(pool, text, values) {
  return (await pool.query(text, values)).rows;
}

/** Migrates as the admin role and grants the serving role exactly `grantStatements`. Also creates the test-only clock table. */
export async function prepareDatabase({ adminUrl, appUrl, schema = SCHEMA }) {
  const admin = openPool(adminUrl, 1);
  try {
    await migrate(admin, schema);
    const role = new URL(appUrl).username;
    for (const statement of grantStatements(schema, role)) await admin.query(statement);
    await admin.query(`CREATE TABLE IF NOT EXISTS "${schema}".rsv_test_clock (id text PRIMARY KEY, now_ms bigint NOT NULL)`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON "${schema}".rsv_test_clock TO "${role}"`);
  } finally {
    await admin.end();
  }
}

/** Creates the namespace recovery record once, as the parent of the server processes does. */
export async function initializeNamespace(pool, namespace, epoch = 1, schema = SCHEMA) {
  const store = await createPostgresStore({ pool, schema });
  const result = await store.initializeNamespace({ namespace, epoch });
  if (result.outcome !== "initialized") throw new Error(`namespace not initialized: ${JSON.stringify(result)}`);
  store.close();
}

function fromHex(hex) {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/** The trusted context of these tests: the transport has already authenticated it. */
export const resolvePrincipal = (context) => ({ id: context.principal ?? "user-synthetic-1", tenant: context.tenant });
export const resolveSession = (context) => context.session ?? null;

/**
 * A persistent server vault over a PostgreSQL store, built the way an
 * application would: its own pool, the local key provider with injected
 * material, and the keyed digester.
 */
export async function openVault({ pool, namespace, epoch = 1, keys, schema = SCHEMA, store, storeOptions = {}, vaultOptions = {} }) {
  const resolvedStore = store ?? (await createPostgresStore({ pool, schema, ...storeOptions }));
  const keyProvider = createLocalKeyProvider({
    keys: [{ id: "synthetic-1", material: fromHex(keys.keyHex), state: "active" }],
    scope: { namespaces: [namespace] },
  });
  const audit = [];
  const vault = await createPersistentServerVault({
    namespace,
    recoveryEpoch: epoch,
    store: resolvedStore,
    crypto: createRecordCrypto({ keyProvider }),
    digestKey: fromHex(keys.digestHex),
    resolvePrincipal,
    resolveSession,
    policy: () => ({ allow: true }),
    lifecyclePolicy: () => ({ allow: true }),
    onAudit: (event) => audit.push(event),
    pii: [],
    ...vaultOptions,
  });
  return { vault, store: resolvedStore, audit };
}

/** A promise's outcome as plain data: a value, or the code and reason of a sanitized error. */
export async function settle(promise) {
  try {
    return { ok: true, value: await promise };
  } catch (thrown) {
    return {
      ok: false,
      name: thrown?.name,
      code: thrown?.code,
      reason: thrown?.reason,
      attemptId: thrown?.attemptId,
      hasFields: thrown !== null && typeof thrown === "object" && "fields" in thrown,
    };
  }
}

/** One capture of `count` synthetic values, with the restore request that names all of them once. */
export function captureText(count = 1, offset = 0) {
  const values = Array.from({ length: count }, (_unused, index) => syntheticSecret(offset + index));
  return { text: values.map((value, index) => `field ${index}: ${value}`).join("\n"), values };
}

export const RELEASE = [{ sink: "sink-a", paths: ["body", "subject"] }];

export function restoreRequest({ context, captures, tokens, attemptId, purpose = "qualification", path = "body", repeat = 1 }) {
  return {
    context,
    sink: "sink-a",
    purpose,
    captures,
    fields: { [path]: tokens.map((token) => `${token} `.repeat(repeat)).join("| ") },
    ...(attemptId === undefined ? {} : { attemptId }),
  };
}

// ----------------------------------------------------------- worker processes

/**
 * Starts one independent server process (`vault-worker.mjs`). It builds its
 * own pool, store, key provider, and vault from the configuration, and is
 * driven by IPC messages.
 */
export async function spawnWorker(config) {
  const child = fork(WORKER_PATH, [], {
    env: { ...process.env, RSVQ_WORKER_CONFIG: JSON.stringify(config) },
    stdio: ["ignore", "inherit", "inherit", "ipc"],
  });
  let next = 1;
  const pending = new Map();
  const listeners = new Set();
  let exited = false;
  const exit = new Promise((resolve) => {
    child.once("exit", (code, signal) => {
      exited = true;
      for (const { reject } of pending.values()) reject(Object.assign(new Error("worker exited before replying"), { workerExited: true, signal }));
      pending.clear();
      resolve({ code, signal });
    });
  });
  const started = new Promise((resolve, reject) => {
    child.on("message", (message) => {
      if (message.event === "ready") resolve();
      else if (message.event === "failed") reject(new Error(`worker failed to start: ${message.code}`));
      else if (message.event !== undefined) for (const listener of listeners) listener(message);
      else if (message.id !== undefined) {
        const waiter = pending.get(message.id);
        pending.delete(message.id);
        waiter?.resolve(message.reply);
      }
    });
    child.once("exit", () => reject(new Error("worker exited during startup")));
  });
  await started;
  return {
    pid: child.pid,
    exit,
    get exited() {
      return exited;
    },
    onEvent(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    call(op, args = {}) {
      return new Promise((resolve, reject) => {
        if (exited) return reject(Object.assign(new Error("worker has exited"), { workerExited: true }));
        const id = next++;
        pending.set(id, { resolve, reject });
        child.send({ id, op, args });
      });
    },
    kill(signal = "SIGKILL") {
      child.kill(signal);
      return exit;
    },
    async stop() {
      if (!exited) child.send({ op: "exit" });
      return exit;
    },
  };
}

// -------------------------------------------------------- store-level fixtures

/** A `createCapture` input of opaque random bytes: the store never decrypts, so it does not need real envelopes. */
export function rawCapture({ namespace, tenant = "tenant-synthetic-a", entries = 1, maxUses = 1, epoch = 1, now = Date.now(), ttlMs = 60 * 60 * 1000, sessionTag = null }) {
  return {
    scope: { namespace, tenant },
    epoch,
    now,
    capture: {
      captureId: randomCaptureId(),
      sessionTag,
      createdAt: now,
      expiresAt: now + ttlMs,
      lookupVersion: 1,
      keyRef: "local:synthetic-1",
      wrappedKey: new Uint8Array(randomBytes(61)),
    },
    entries: Array.from({ length: entries }, () => ({ entryId: randomEntryId(), maxUses, envelope: new Uint8Array(randomBytes(96)) })).sort((a, b) =>
      a.entryId < b.entryId ? -1 : 1,
    ),
  };
}

/** A `commitRestore` input for entries of one raw capture, as read back from the store. */
export async function rawCommit(store, created, { attemptId = randomAttemptId(), counts, digest, now = Date.now(), entries = created.entries } = {}) {
  const read = await store.readEntries({ scope: created.scope, entryIds: entries.map((entry) => entry.entryId) });
  const capture = read.captures.find((candidate) => candidate.captureId === created.capture.captureId);
  return {
    scope: created.scope,
    epoch: created.epoch,
    now,
    attempt: { attemptId, requestDigest: digest ?? new Uint8Array(randomBytes(32)) },
    receiptExpiresAt: created.capture.expiresAt + 2000 + 60 * 60 * 1000,
    captures: [{ captureId: created.capture.captureId, generation: capture?.generation ?? 1 }],
    uses: entries.map((entry, index) => {
      const row = read.entries.find((candidate) => candidate.entryId === entry.entryId);
      return {
        entryId: entry.entryId,
        captureId: created.capture.captureId,
        count: counts?.[index] ?? 1,
        lifecycleRevision: row?.lifecycleRevision ?? 1,
        ciphertextRevision: row?.ciphertextRevision ?? 1,
      };
    }),
  };
}

/** What the database holds for a capture, read with SQL by the admin role. */
export async function captureState(admin, namespace, captureId, schema = SCHEMA) {
  const [capture] = await rows(admin, `SELECT state, generation, epoch, key_revision, has_ciphertext, expires_at, retain_until FROM "${schema}".rsv_capture WHERE namespace = $1 AND capture_id = $2`, [namespace, captureId]);
  const entries = await rows(admin, `SELECT entry_id, used, max_uses, lifecycle_revision FROM "${schema}".rsv_entry WHERE namespace = $1 AND capture_id = $2 ORDER BY entry_id`, [namespace, captureId]);
  return { capture, entries, used: entries.map((entry) => entry.used) };
}

export async function receiptCount(admin, namespace, attemptId, schema = SCHEMA) {
  const [row] = await rows(admin, `SELECT count(*)::int AS n FROM "${schema}".rsv_receipt WHERE namespace = $1 AND attempt_id = $2`, [namespace, attemptId]);
  return row.n;
}

/** Encodes byte arrays for the worker's `store` operation. */
export function wire(value) {
  if (value instanceof Uint8Array) return { $hex: Buffer.from(value).toString("hex") };
  if (Array.isArray(value)) return value.map(wire);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, wire(inner)]));
  return value;
}

// ------------------------------------------------------------------- sanitized errors

const ALLOWED_ERROR_PROPERTIES = new Set(["code", "message", "name", "stack"]);

/**
 * Asserts that a thrown value is a `StoreError` with the fixed message of its
 * code and nothing else: no cause, no extra property, and none of the
 * `forbidden` strings anywhere `util.inspect` can reach.
 */
export function assertSanitized(thrown, code, forbidden = []) {
  assert.ok(thrown instanceof StoreError, `expected a StoreError, got ${thrown?.constructor?.name}`);
  assert.equal(thrown.code, code);
  assert.equal(thrown.message, new StoreError(code).message, "the message is the fixed one for the code");
  assert.equal(thrown.cause, undefined, "no cause");
  for (const property of Reflect.ownKeys(thrown)) assert.ok(ALLOWED_ERROR_PROPERTIES.has(property), `unexpected property ${String(property)}`);
  const visible = `${inspect(thrown, { showHidden: true, depth: 8, breakLength: Infinity })}\n${thrown.stack}\n${JSON.stringify(thrown)}`;
  for (const text of forbidden) {
    if (text === "" || text === undefined) continue;
    assert.ok(!visible.includes(text), "a sanitized error exposed text it must not carry");
  }
}

// -------------------------------------------------------------------- evidence

/** Appends one machine-readable finding to the run's evidence file, when `run.mjs` set one. */
export function evidence(scenario, name, data = {}) {
  const file = process.env.RSVQ_EVIDENCE_FILE;
  if (typeof file !== "string" || file === "") return;
  appendFileSync(file, `${JSON.stringify({ scenario, name, ...data })}\n`);
}

export function tally(outcomes, key = (outcome) => (outcome.ok ? "ok" : `${outcome.code}${outcome.reason === undefined ? "" : `:${outcome.reason}`}`)) {
  const counts = {};
  for (const outcome of outcomes) {
    const label = key(outcome);
    counts[label] = (counts[label] ?? 0) + 1;
  }
  return counts;
}
