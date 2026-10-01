// Shared helpers for the persistent server profile tests
// (docs/specs/persistent-vault.md §7, §8). Tests run against the *built*
// package: `npm run test:vault-server` builds first.
//
// Everything here is synthetic. No value in this directory is, or resembles
// closely enough to be mistaken for, a real credential or key.
//
// This module does three things besides building a test rig:
//
//  1. It records every error a test expects and every audit event a vault
//     emits, and scans them for anything that must never leave the server:
//     captured values, issued tokens, capture identifiers (in errors), key
//     material, data keys, envelopes, wrapped keys, and the text of a foreign
//     driver error. `registerLeakHygiene()` adds a last test to a file that
//     scans everything again against the complete set.
//  2. It replaces `console.*` for the life of the process and counts calls.
//  3. It watches `crypto.subtle.digest` for `entryId` preimages, which is the
//     only way a test can learn a token the server issued but never returned.
import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { inspect } from "node:util";

import { createMemoryStore } from "@redact-secret/store-memory";
import { createFaultyStore, SYNTHETIC_SECRET_MARKER } from "@redact-secret/vault-conformance";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";

// `mutation-controls.mjs` points this at a mutated copy of the build output.
const DIST =
  process.env.RSV_PERSISTENT_DIST === undefined
    ? new URL("../../dist/", import.meta.url)
    : pathToFileURL(`${resolve(process.env.RSV_PERSISTENT_DIST)}/`);

export const { createPersistentServerVault, VaultServerError } = await import(new URL("persistent/index.js", DIST).href);
export const digests = await import(new URL("persistent/digests.js", DIST).href);

export { createFaultyStore, createMemoryStore, SYNTHETIC_SECRET_MARKER };

// ------------------------------------------------------------- synthetic data

export const NAMESPACE = "support-synthetic";
export const TENANT = "tenant-acme-synthetic";
export const OTHER_TENANT = "tenant-globex-synthetic";
export const SECRET_A = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
export const SECRET_B = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111";
export const SECRET_C = "ghp_SYNTHETICxREVOKEDxTESTx2222222222222";
export const PURPOSE = "purpose-synthetic-support-reply";
export const SINK = "sink-a";
export const RELEASE = Object.freeze([Object.freeze({ sink: SINK, paths: Object.freeze(["body", "subject"]) })]);
export const FORGED_TOKEN = "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>";
export const ABSENT_CAPTURE = "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa";

/** Public test constants, as in conformance/persistent/v1/vectors.json. Never a real key. */
export const KEY_MATERIAL = Uint8Array.from({ length: 32 }, (_unused, index) => 0x80 + index);
export const DIGEST_KEY = Uint8Array.from({ length: 32 }, (_unused, index) => 0x40 + index);

export function ctx({ id = "principal-synthetic-0001", tenant = TENANT, session } = {}) {
  return { principal: { id, tenant }, ...(session === undefined ? {} : { session }) };
}
export const CTX_A = Object.freeze(ctx());
export const CTX_B = Object.freeze(ctx({ id: "principal-synthetic-0002", tenant: OTHER_TENANT }));

export function manualClock(startMs = 1_790_000_000_000) {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
      return t;
    },
    set: (ms) => {
      t = ms;
    },
  };
}

export function sleep(ms) {
  return new Promise((done) => {
    setTimeout(done, ms);
  });
}

export function deferred() {
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((res, rej) => {
    resolvePromise = res;
    rejectPromise = rej;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

// ------------------------------------------------------------ leak registry

/** string -> label. Anything here must never appear in an error or an audit event. */
const sensitive = new Map();
/** Capture identifiers: never in an error; in an audit event only as `captureId`. */
const captureIds = new Set();
const recordedErrors = [];
const recordedAudits = [];

export function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

export function noteSecret(label, value) {
  if (typeof value === "string" && value.length >= 8 && !sensitive.has(value)) sensitive.set(value, label);
}

export function noteBytes(label, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 12) return;
  // A buffer of one repeated byte (a zeroed key, a placeholder) identifies nothing.
  if (bytes.every((byte) => byte === bytes[0])) return;
  const buffer = Buffer.from(bytes);
  noteSecret(`${label} (hex)`, buffer.toString("hex"));
  noteSecret(`${label} (base64)`, buffer.toString("base64"));
  noteSecret(`${label} (base64url)`, buffer.toString("base64url"));
}

export function noteCaptureId(captureId) {
  if (typeof captureId === "string" && captureId.startsWith("cap_")) captureIds.add(captureId);
}

for (const value of [SECRET_A, SECRET_B, SECRET_C]) noteSecret("captured value", value);
noteSecret("foreign error text", SYNTHETIC_SECRET_MARKER);
noteSecret("foreign error text", "synthetic driver failure");
noteBytes("key material", KEY_MATERIAL);
noteBytes("digest key", DIGEST_KEY);

function findLeak(text, { allowCaptureIds = false } = {}) {
  for (const [value, label] of sensitive) {
    if (text.includes(value)) return label;
  }
  if (!allowCaptureIds) {
    for (const captureId of captureIds) {
      if (text.includes(captureId)) return "capture identifier";
    }
  }
  return undefined;
}

/** Every surface an error can carry text on, as [where, text] pairs. */
function errorSurfaces(error) {
  const surfaces = [
    ["String(error)", String(error)],
    ["message", String(error.message)],
    ["stack", String(error.stack)],
    ["JSON.stringify", JSON.stringify(error) ?? ""],
    ["JSON.stringify(entries)", JSON.stringify(Object.entries(error)) ?? ""],
    ["inspect", inspect(error, { showHidden: true, depth: 8, maxStringLength: null, maxArrayLength: null })],
  ];
  for (const key of Reflect.ownKeys(error)) {
    const value = error[key];
    surfaces.push([
      `own property ${String(key)}`,
      typeof value === "string" ? value : inspect(value, { showHidden: true, depth: 8, maxStringLength: null, maxArrayLength: null }),
    ]);
  }
  return surfaces;
}

const ERROR_FIELDS = new Set(["stack", "message", "name", "code", "reason", "vaultCode", "coreCode", "attemptId"]);

/** Fails, naming the kind of thing that leaked and where, never the leaked text itself. */
export function assertErrorClean(error) {
  assert.ok(error instanceof VaultServerError, `expected a VaultServerError, got ${Object.prototype.toString.call(error)}`);
  assert.equal(error.name, "VaultServerError");
  assert.equal(Object.hasOwn(error, "cause"), false, "an error must not carry a cause");
  assert.equal(error.cause, undefined, "an error must not carry a cause");
  // A fixed message per code, and no property beyond the documented ones.
  assert.equal(error.message, new VaultServerError(error.code).message, `error ${error.code} must carry its fixed message`);
  for (const key of Reflect.ownKeys(error)) {
    assert.ok(ERROR_FIELDS.has(key), `error ${error.code} carries an undocumented property: ${String(key)}`);
  }
  for (const [where, text] of errorSurfaces(error)) {
    const leaked = findLeak(text);
    assert.equal(leaked, undefined, `error ${error.code} leaks a ${leaked} through ${where}`);
  }
}

const AUDIT_FIELDS = new Set([
  "operation",
  "outcome",
  "at",
  "principalId",
  "tenant",
  "sink",
  "path",
  "purpose",
  "reason",
  "code",
  "entries",
  "policyRevision",
  "requestId",
  "captureId",
  "attemptId",
]);

export function assertAuditClean(event) {
  assert.equal(typeof event, "object");
  assert.ok(Object.isFrozen(event), "audit events are frozen");
  for (const key of Reflect.ownKeys(event)) {
    assert.ok(typeof key === "string" && AUDIT_FIELDS.has(key), `audit event carries an undocumented field: ${String(key)}`);
    const value = event[key];
    assert.ok(
      typeof value === "string" || typeof value === "number",
      `audit field ${key} must be a string or a number, got ${typeof value}`,
    );
    if (key === "captureId") continue;
    const leaked = findLeak(String(value));
    assert.equal(leaked, undefined, `audit event (${event.operation}/${event.outcome}) leaks a ${leaked} through ${key}`);
  }
  const whole = JSON.stringify({ ...event, captureId: undefined });
  const leaked = findLeak(whole);
  assert.equal(leaked, undefined, `audit event (${event.operation}/${event.outcome}) leaks a ${leaked}`);
}

// ------------------------------------------------------------- console guard

const consoleCalls = [];
for (const method of ["log", "info", "warn", "error", "debug", "trace", "dir", "table", "group", "groupCollapsed"]) {
  console[method] = (...args) => {
    // Only the method and the argument count are kept: a leak must not be repeated by the guard.
    consoleCalls.push(`${method}/${args.length}`);
  };
}

// ---------------------------------------------- tokens the server never returned

/** Every `{ namespace, tenant, token }` an `entryId` was derived for in this process. */
export const observedTokens = [];
{
  const subtle = globalThis.crypto.subtle;
  const original = subtle.digest;
  const label = Buffer.from("rsv-entry-id-v1\0", "utf8");
  subtle.digest = function digest(algorithm, data) {
    try {
      const bytes = Buffer.from(data.buffer ?? data, data.byteOffset ?? 0, data.byteLength);
      if (bytes.subarray(0, label.length).equals(label)) {
        let offset = label.length;
        const fields = [];
        for (let i = 0; i < 3; i += 1) {
          const length = bytes.readUInt16BE(offset);
          fields.push(bytes.subarray(offset + 2, offset + 2 + length).toString("utf8"));
          offset += 2 + length;
        }
        const [namespace, tenant, token] = fields;
        observedTokens.push({ namespace, tenant, token });
        noteSecret("issued token", token);
      }
    } catch {
      // A preimage this spy cannot parse is not an entry identifier.
    }
    return original.call(this, algorithm, data);
  };
}

// ---------------------------------------------------------------- assertions

/**
 * Awaits a rejection and checks it is a clean `VaultServerError` with the
 * expected code (and denial reason). The resolved value of an unexpected
 * success is never printed.
 */
export async function rejects(promise, code, reason) {
  let error;
  let settled = false;
  try {
    await promise;
    settled = true;
  } catch (thrown) {
    error = thrown;
  }
  assert.equal(settled, false, `expected ${code}${reason === undefined ? "" : `/${reason}`}, but the call succeeded`);
  recordedErrors.push(error);
  assertErrorClean(error);
  assert.equal(error.code, code, `expected ${code}, got ${error.code}${error.reason === undefined ? "" : `/${error.reason}`}`);
  if (reason !== undefined) assert.equal(error.reason, reason);
  if (code !== "RESTORE_DENIED") assert.equal(error.reason, undefined);
  if (code !== "COMMIT_AMBIGUOUS") assert.equal(error.attemptId, undefined);
  return error;
}

/**
 * Awaits a call that may succeed or fail. A failure must be a clean
 * `VaultServerError`; it is recorded and returned. A success returns
 * `undefined`: its value is deliberately dropped.
 */
export async function failureOf(promise) {
  try {
    await promise;
    return undefined;
  } catch (thrown) {
    recordedErrors.push(thrown);
    assertErrorClean(thrown);
    return thrown;
  }
}

export function denied(promise, reason) {
  return rejects(promise, "RESTORE_DENIED", reason);
}

/** For a synchronous or already-caught error from somewhere `rejects` cannot wrap. */
export function recordError(error) {
  recordedErrors.push(error);
  assertErrorClean(error);
  return error;
}

/**
 * Adds the file's last test: everything recorded is scanned again, now that
 * every token, key, and envelope of the whole file is known.
 */
export function registerLeakHygiene({ minErrors = 1 } = {}) {
  test("leak hygiene: no error, audit event, or console call of this file carries a value, token, key, envelope, or foreign text", () => {
    assert.ok(recordedErrors.length >= minErrors, `expected at least ${minErrors} recorded error(s), got ${recordedErrors.length}`);
    for (const error of recordedErrors) assertErrorClean(error);
    for (const event of recordedAudits) assertAuditClean(event);
    assert.deepEqual(consoleCalls, [], "console.* must never be called");
  });
}

export function leakStats() {
  return { errors: recordedErrors.length, audits: recordedAudits.length, sensitive: sensitive.size, console: consoleCalls.length };
}

// ------------------------------------------------------------------- spies

export const STORE_OPERATIONS = Object.freeze([
  "createCapture",
  "readEntries",
  "readCaptures",
  "commitRestore",
  "revokeCapture",
  "inspectAttempt",
  "replaceCaptureKey",
  "deleteCiphertext",
  "sweepExpired",
  "recoveryState",
  "initializeNamespace",
  "quarantine",
  "invalidateRecovered",
]);
export const MUTATING_OPERATIONS = Object.freeze([
  "createCapture",
  "commitRestore",
  "revokeCapture",
  "replaceCaptureKey",
  "deleteCiphertext",
  "sweepExpired",
  "initializeNamespace",
  "quarantine",
  "invalidateRecovered",
]);

function noteStoreTraffic(value) {
  if (typeof value !== "object" || value === null) return;
  if (value instanceof Uint8Array) return;
  if (Array.isArray(value)) {
    for (const item of value) noteStoreTraffic(item);
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === "captureId") noteCaptureId(item);
    else if (key === "envelope") noteBytes("envelope", item);
    else if (key === "wrappedKey") noteBytes("wrapped key", item);
    else noteStoreTraffic(item);
  }
}

/**
 * The server-facing store: records every call, and lets a test rewrite a
 * result (`tamper[operation]`) or run something first (`before[operation]`).
 */
export function spyStore(inner) {
  const calls = [];
  const tamper = {};
  const before = {};
  const store = { capabilities: () => inner.capabilities() };
  for (const operation of STORE_OPERATIONS) {
    store[operation] = async (input, options) => {
      const record = { operation, input, signal: options?.signal, result: undefined, error: undefined, settled: false };
      calls.push(record);
      noteStoreTraffic(input);
      if (before[operation] !== undefined) await before[operation](input);
      try {
        let result = await inner[operation](input, options);
        noteStoreTraffic(result);
        if (tamper[operation] !== undefined) result = await tamper[operation](result, input);
        record.result = result;
        return result;
      } catch (thrown) {
        record.error = thrown;
        throw thrown;
      } finally {
        record.settled = true;
      }
    };
  }
  const of = (operation) => calls.filter((call) => call.operation === operation);
  return {
    store,
    calls,
    tamper,
    before,
    of,
    count: (operation) => of(operation).length,
    last: (operation) => of(operation).at(-1),
    mutations: () => calls.filter((call) => MUTATING_OPERATIONS.includes(call.operation)).length,
    reset: () => {
      calls.length = 0;
    },
  };
}

/** Counts provider calls, records every data key it sees as sensitive, and can be made to fail. */
export function spyKeyProvider(inner) {
  const stats = { generate: 0, unwrap: 0, rewrap: 0 };
  const fail = { generate: undefined, unwrap: undefined };
  const provider = {
    profile: inner.profile,
    async generateDataKey(context, options) {
      stats.generate += 1;
      if (fail.generate !== undefined) return fail.generate(context, options);
      const key = await inner.generateDataKey(context, options);
      noteBytes("data key", key.plaintextKey);
      noteBytes("wrapped key", key.wrappedKey);
      return key;
    },
    async unwrapDataKey(input, options) {
      stats.unwrap += 1;
      if (fail.unwrap !== undefined) return fail.unwrap(input, options);
      const key = await inner.unwrapDataKey(input, options);
      noteBytes("data key", key);
      return key;
    },
    async rewrapDataKey(input, options) {
      stats.rewrap += 1;
      return inner.rewrapDataKey(input, options);
    },
  };
  return { provider, stats, fail };
}

/** An error no sanitizing layer may let through: it carries the synthetic marker everywhere. */
export function foreignError() {
  const error = new Error(`synthetic driver failure at kms.invalid: credential=${SYNTHETIC_SECRET_MARKER}`, {
    cause: new Error(`synthetic driver failure: ${SYNTHETIC_SECRET_MARKER}`),
  });
  error.name = "SyntheticForeignError";
  error.detail = SYNTHETIC_SECRET_MARKER;
  return error;
}

// --------------------------------------------------------------------- rig

export const allow = () => ({ allow: true });

/**
 * One memory store with a fault layer and a spy on top, a spied local key
 * provider, and helpers to open any number of vault instances over them.
 * Layers, from the server down: spy -> faulty -> memory.
 */
export async function createRig(options = {}) {
  const clock = options.clock ?? manualClock();
  const storeClock = options.storeClock ?? clock;
  const memory = options.memory ?? createMemoryStore({ now: storeClock.now, ...(options.memoryOptions ?? {}) });
  if (options.initialize !== false) {
    const initialized = await memory.store.initializeNamespace({ namespace: NAMESPACE, epoch: options.epoch ?? 1 });
    assert.equal(initialized.outcome, "initialized");
  }
  const faulty = createFaultyStore(memory.store, options.capabilities === undefined ? {} : { capabilities: options.capabilities });
  const spy = spyStore(faulty);
  const keys = spyKeyProvider(
    createLocalKeyProvider({
      keys: [{ id: "synthetic-2026-10", material: KEY_MATERIAL, state: "active" }],
      scope: { namespaces: [NAMESPACE] },
    }),
  );
  const recordCrypto = createRecordCrypto({ keyProvider: keys.provider });
  const rig = {
    clock,
    storeClock,
    memory,
    faulty,
    faults: faulty.faults,
    spy,
    keys,
    crypto: recordCrypto,
    audits: [],
    policyCalls: [],
    lifecycleCalls: [],
    policy: allow,
    lifecycle: allow,
    /** Makes the next call of `operation` on the fault layer fail with `fault`. */
    failNext(operation, fault) {
      faulty.faults.add({ operation, call: faulty.faults.calls(operation), fault });
    },
    options(extra = {}) {
      return {
        namespace: NAMESPACE,
        recoveryEpoch: options.epoch ?? 1,
        store: spy.store,
        crypto: recordCrypto,
        digestKey: DIGEST_KEY,
        resolvePrincipal: (context) => context.principal,
        resolveSession: (context) => context.session ?? null,
        policy: (input) => {
          rig.policyCalls.push(input);
          return rig.policy(input);
        },
        lifecyclePolicy: (input) => {
          rig.lifecycleCalls.push(input);
          return rig.lifecycle(input);
        },
        onAudit: (event) => {
          // Recorded here, checked by the file's last test: the server swallows whatever an audit hook throws.
          rig.audits.push(event);
          recordedAudits.push(event);
        },
        now: clock.now,
        allowNonDurableStore: true,
        // Core beta.10+ needs an established activation: PII off, as these tests assume.
        pii: [],
        ...extra,
      };
    },
    open(extra = {}) {
      return createPersistentServerVault(rig.options(extra));
    },
    /** The authoritative rows of `tokens`, read from the memory store beneath every wrapper. */
    async rows(tokens, tenant = TENANT) {
      const entryIds = await Promise.all(tokens.map((token) => digests.deriveEntryId(NAMESPACE, tenant, token)));
      const read = await memory.store.readEntries({ scope: { namespace: NAMESPACE, tenant }, entryIds });
      return { entryIds, ...read, byId: new Map(read.entries.map((entry) => [entry.entryId, entry])) };
    },
    /** `used` of each token, in order; `undefined` for a token with no row. */
    async used(tokens, tenant = TENANT) {
      const { entryIds, byId } = await rig.rows(tokens, tenant);
      return entryIds.map((entryId) => byId.get(entryId)?.used);
    },
    async captureRow(captureId, tenant = TENANT) {
      const found = await memory.store.readCaptures({ scope: { namespace: NAMESPACE, tenant }, captureIds: [captureId] });
      return found[0];
    },
  };
  if (options.open !== false) rig.vault = await rig.open(options.vault ?? {});
  return rig;
}

export async function captureOne(rig, { vault = rig.vault, text = `secret ${SECRET_A} here`, context = CTX_A, release = RELEASE, ...rest } = {}) {
  const captured = await vault.capture(text, { context, release, ...rest });
  noteCaptureId(captured.captureId);
  for (const { token } of captured.tokens) noteSecret("issued token", token);
  return captured;
}

export function restoreRequest(captured, extra = {}) {
  return {
    context: CTX_A,
    sink: SINK,
    purpose: PURPOSE,
    captures: [captured.captureId],
    fields: { body: captured.text },
    ...extra,
  };
}
