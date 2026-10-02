#!/usr/bin/env node
// JavaScript driver for the schedule orchestrator (plan §6.3): serves
// `@redact-secret/store-memory` over the line protocol described in README.md.
//
// A test tool. It is not published, accepts only synthetic fixtures, and its
// responses carry result structures and error codes only. The hold and fault
// hooks live here, outside every package's production API.
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { createMemoryStore } from "@redact-secret/store-memory";
import { StoreError } from "@redact-secret/vault-contracts";
import { createFaultyStore } from "@redact-secret/vault-conformance";

const CLOCK_START_MS = 1_800_000_000_000;
const BYTES_FIELDS = new Set(["envelope", "wrappedKey", "requestDigest"]);
const HEX = "0123456789abcdef";
const STORE_OPERATIONS = new Set([
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

/** The default store: `@redact-secret/store-memory` with a clock the orchestrator can move. */
export function openMemory(options = {}) {
  let now = CLOCK_START_MS;
  const controllable = options.realClock !== true;
  const clock = controllable
    ? {
        now: () => now,
        advance(ms) {
          now += ms;
        },
        set(ms) {
          now = ms;
        },
      }
    : null;
  const bounds = {};
  for (const key of ["maxClockSkewMs", "maxCreateEntries", "maxCreateBytes", "maxRestoreEntries", "maxRestoreCaptures", "maxEnvelopeBytes"]) {
    if (options[key] !== undefined) bounds[key] = options[key];
  }
  const { store, control } = createMemoryStore({ now: clock === null ? Date.now : clock.now, ...bounds });
  return { store, control, clock };
}

export const HOLD_POINTS = Object.freeze(["before-commit"]);
export const FAULTS = Object.freeze(["unavailable", "before-first-write", "drop-connection", "after-commit-before-ack"]);

function toBytes(value) {
  if (typeof value === "string" && value.length % 2 === 0 && /^[0-9a-f]*$/.test(value)) {
    const out = new Uint8Array(value.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value) && Number.isInteger(value.$fill) && Number.isInteger(value.length)) {
    return new Uint8Array(value.length).fill(value.$fill);
  }
  return value;
}

function toHex(bytes) {
  let out = "";
  for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 15];
  return out;
}

/** Wire form to API form: the three byte fields become `Uint8Array`. */
function decode(value, key) {
  if (Array.isArray(value)) return value.map((item) => decode(item));
  if (value !== null && typeof value === "object" && !(key !== undefined && BYTES_FIELDS.has(key))) {
    const out = {};
    for (const [name, item] of Object.entries(value)) out[name] = decode(item, name);
    return out;
  }
  return key !== undefined && BYTES_FIELDS.has(key) ? toBytes(value) : value;
}

/** API form to wire form: bytes become lowercase hexadecimal. */
function encode(value) {
  if (value instanceof Uint8Array) return toHex(value);
  if (Array.isArray(value)) return value.map((item) => encode(item));
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const [name, item] of Object.entries(value)) out[name] = encode(item);
    return out;
  }
  return value;
}

// ---------------------------------------------------------------- server level

/** Public test constants, as in conformance/persistent/v1/vectors.json. Never a real key. */
const KEY_MATERIAL = Uint8Array.from({ length: 32 }, (_unused, index) => 0x80 + index);
const DIGEST_KEY = Uint8Array.from({ length: 32 }, (_unused, index) => 0x40 + index);

/** The fixed synthetic identities of the server-level cases. Anything else is not authenticated. */
const PRINCIPALS = Object.freeze({
  "principal-a1": { id: "principal-a1", tenant: "tenant-acme-synthetic" },
  "principal-a2": { id: "principal-a2", tenant: "tenant-acme-synthetic" },
  "principal-b1": { id: "principal-b1", tenant: "tenant-globex-synthetic" },
});

const SERVER_FAULT_KINDS = Object.freeze({
  unavailable: { kind: "unavailable" },
  "before-first-write": { kind: "unavailable" },
  "drop-connection": { kind: "ambiguous", applied: false },
  "after-commit-before-ack": { kind: "ambiguous", applied: true },
});

const SERVER_OPERATIONS = new Set(["capture", "restore", "revoke", "deleteCaptureCiphertext", "resolveAttempt"]);

/** Opens a persistent server over store-memory, the local key provider, and fixed synthetic resolvers and policies. */
async function openServer(message) {
  const [{ createPersistentServerVault, VaultServerError }, { createRecordCrypto }, { createLocalKeyProvider }] = await Promise.all([
    import("@redact-secret/vault-server/persistent"),
    import("@redact-secret/vault-crypto"),
    import("@redact-secret/vault-crypto/local-key-provider"),
  ]);
  const namespace = message.namespace;
  let now = CLOCK_START_MS;
  const clock = {
    now: () => now,
    advance(ms) {
      now += ms;
    },
    set(ms) {
      now = ms;
    },
  };
  const memory = createMemoryStore({ now: clock.now });
  await memory.store.initializeNamespace({ namespace, epoch: 1 });
  const faulty = createFaultyStore(memory.store);
  const crypto = createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "synthetic-2026-10", material: KEY_MATERIAL, state: "active" }],
      scope: { namespaces: [namespace] },
    }),
  });
  const allow = () => ({ allow: true });
  const vault = await createPersistentServerVault({
    namespace,
    recoveryEpoch: 1,
    store: faulty,
    crypto,
    digestKey: DIGEST_KEY,
    resolvePrincipal: (context) => {
      const principal = PRINCIPALS[context?.principal];
      if (principal === undefined) throw new Error("unauthenticated");
      return principal;
    },
    resolveSession: (context) => context?.session ?? null,
    policy: allow,
    lifecyclePolicy: allow,
    now: clock.now,
    allowNonDurableStore: true,
    // The core needs an established activation: PII off.
    pii: [],
  });
  return { vault, faulty, clock, VaultServerError, namespace, store: faulty };
}

async function serverCall(state, message) {
  const { vault, faulty, VaultServerError } = state;
  const input = message.input ?? {};
  if (message.fault !== undefined && message.fault !== null) {
    const fault = SERVER_FAULT_KINDS[message.fault.kind];
    if (fault === undefined) return { error: "UNSUPPORTED_FAULT" };
    faulty.faults.add({ operation: message.fault.operation, call: faulty.faults.calls(message.fault.operation), fault });
  }
  try {
    switch (message.op) {
      case "capture": {
        const { context, text, ...options } = input;
        const result = await vault.capture(text, { context, ...options });
        return { result: JSON.parse(JSON.stringify(result)) };
      }
      case "restore":
        return { result: JSON.parse(JSON.stringify(await vault.restore(input))) };
      case "revoke":
        return { result: JSON.parse(JSON.stringify(await vault.revoke(input))) };
      case "deleteCaptureCiphertext":
        return { result: JSON.parse(JSON.stringify(await vault.deleteCaptureCiphertext(input))) };
      case "resolveAttempt":
        return { result: JSON.parse(JSON.stringify(await vault.resolveAttempt(input))) };
      default:
        return { error: "UNSUPPORTED_OPERATION" };
    }
  } catch (error) {
    if (error instanceof VaultServerError) {
      const detail = {};
      if (error.reason !== undefined) detail.reason = error.reason;
      if (error.attemptId !== undefined) detail.attemptId = error.attemptId;
      return { error: error.code, detail };
    }
    return { error: "INTERNAL" };
  }
}

/**
 * The driver as a function of requests. `emit(event)` carries unsolicited
 * events (`{event: "held", holdId}`); the return value of `handle` is the
 * response. Requests may overlap: a held call does not block any other.
 */
export function createDriver({ open = openMemory } = {}) {
  let state = null;

  function reset() {
    if (state !== null) for (const waiter of state.holds.values()) waiter.release();
    if (state?.server !== undefined) state.server.vault.close().catch(() => {});
    state = null;
  }

  async function configureServer(message) {
    reset();
    const opened = await openServer(message);
    state = { server: opened, clock: opened.clock, controllable: true, holds: new Map(), holdsEnabled: false };
    return {
      ok: true,
      capabilities: encode(opened.store.capabilities()),
      features: { testClock: true, holds: [], faults: Object.keys(SERVER_FAULT_KINDS), levels: ["server"] },
    };
  }

  function configure(message) {
    reset();
    const options = message.store ?? {};
    const opened = open(options);
    state = {
      store: opened.store,
      control: opened.control ?? null,
      interleave: opened.interleave ?? null,
      clock: opened.clock,
      controllable: opened.clock !== null,
      holds: new Map(),
      holdsEnabled: options.noHolds !== true && (opened.control != null || opened.interleave != null),
    };
    return {
      ok: true,
      capabilities: encode(state.store.capabilities()),
      features: {
        testClock: state.controllable,
        holds: state.holdsEnabled ? [...HOLD_POINTS] : [],
        faults: [...FAULTS],
        levels: ["store"],
      },
    };
  }

  async function storeCall(message, emit) {
    const { store, control, interleave } = state;
    const input = message.input === undefined ? undefined : decode(message.input);
    const operation = message.op;
    const invoke = () => store[operation](input);
    const fault = message.fault ?? null;
    if (fault !== null && !FAULTS.includes(fault)) return { error: "UNSUPPORTED_FAULT" };
    let run = invoke;
    let removeHook = null;
    if (message.hold !== undefined && message.hold !== null) {
      if (!state.holdsEnabled || !HOLD_POINTS.includes(message.hold)) return { error: "UNSUPPORTED_HOLD" };
      let release;
      const released = new Promise((done) => {
        release = done;
      });
      state.holds.set(message.holdId, { release, released });
      const wait = async () => {
        emit({ event: "held", holdId: message.holdId });
        await released;
      };
      if (control !== null) {
        removeHook = control.onPhase(operation, "before-apply", async () => {
          removeHook();
          await wait();
        });
      } else {
        run = () => interleave({ operation, primary: invoke, concurrent: wait });
      }
    }
    try {
      if (fault === "unavailable" || fault === "before-first-write") throw new StoreError("STORE_UNAVAILABLE");
      if (fault === "drop-connection") throw new StoreError("STORE_AMBIGUOUS");
      const result = await run();
      if (fault === "after-commit-before-ack") throw new StoreError("STORE_AMBIGUOUS");
      return { result: encode(result) };
    } catch (error) {
      if (error instanceof StoreError) return { error: error.code };
      return { error: "INTERNAL" };
    } finally {
      if (removeHook !== null) removeHook();
    }
  }

  return {
    async handle(message, emit = () => {}) {
      const respond = (body) => ({ id: message.id, ...body });
      try {
        switch (message.op) {
          case "configure":
            if (message.level === "server") return respond(await configureServer(message));
            if (message.level !== "store") {
              reset();
              return respond({ ok: false, error: "UNSUPPORTED_LEVEL" });
            }
            return respond(configure(message));
          case "reset":
            reset();
            return respond({ ok: true });
          default:
        }
        if (state === null) return respond({ error: "NOT_CONFIGURED" });
        if (state.server !== undefined) {
          if (message.op === "capabilities") return respond({ result: encode(state.server.store.capabilities()) });
          if (SERVER_OPERATIONS.has(message.op)) return respond(await serverCall(state.server, message));
        } else if (message.op === "capabilities") {
          return respond({ result: encode(state.store.capabilities()) });
        }
        if (message.op === "clock") {
          if (!state.controllable) return respond({ error: "UNSUPPORTED_CLOCK" });
          if (message.action === "now") return respond({ result: { now: state.clock.now() } });
          if (message.action === "advance") state.clock.advance(message.ms);
          else if (message.action === "set") state.clock.set(message.ms);
          else return respond({ error: "UNSUPPORTED_CLOCK" });
          return respond({ result: { now: state.clock.now() } });
        }
        if (message.op === "release") {
          const waiter = state.holds.get(message.holdId);
          if (waiter !== undefined) {
            state.holds.delete(message.holdId);
            waiter.release();
          }
          return respond({ ok: true });
        }
        if (STORE_OPERATIONS.has(message.op)) return respond(await storeCall(message, emit));
        return respond({ error: "UNSUPPORTED_OPERATION" });
      } catch {
        return respond({ error: "INTERNAL" });
      }
    },
  };
}

/**
 * A driver served in this process, with the interface the orchestrator's
 * `stdioDriver` has. For tests that need to supply their own store.
 */
export function inProcessDriver(options) {
  const driver = createDriver(options);
  const listeners = new Set();
  let nextId = 1;
  return {
    request(message) {
      const id = nextId;
      nextId += 1;
      // Round-trip through JSON, as the line protocol does, so no object identity crosses.
      const wire = JSON.parse(JSON.stringify({ id, ...message }));
      return driver
        .handle(wire, (event) => {
          for (const listener of listeners) listener(JSON.parse(JSON.stringify(event)));
        })
        .then((response) => JSON.parse(JSON.stringify(response)));
    },
    onEvent(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    async close() {},
  };
}

/** Wires a driver to a pair of streams as the line protocol. */
export function serveLines(driver, input, write) {
  const reader = createInterface({ input });
  const open = new Set();
  reader.on("line", (line) => {
    if (line.trim() === "") return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      write({ id: null, error: "BAD_REQUEST" });
      return;
    }
    const work = driver.handle(message, write).then((response) => {
      write(response);
      open.delete(work);
    });
    open.add(work);
  });
  return new Promise((done) => {
    reader.on("close", () => {
      Promise.all(open).then(done);
    });
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await serveLines(createDriver(), process.stdin, (body) => process.stdout.write(`${JSON.stringify(body)}\n`));
}
