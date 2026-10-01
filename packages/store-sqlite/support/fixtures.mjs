// Shared fixtures for the store-sqlite tests and qualification scripts. Every
// identifier, key, byte, and value here is synthetic and generated per run.
import { fork } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";

import { createSqliteStore } from "../dist/index.js";
import { selectedDriver } from "./drivers.mjs";

export const PROCESS_WORKER = fileURLToPath(new URL("./process-worker.mjs", import.meta.url));

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

const fromHex = (hex) => new Uint8Array(Buffer.from(hex, "hex"));

export const resolvePrincipal = (context) => ({ id: context.principal ?? "user-synthetic-1", tenant: context.tenant });
export const resolveSession = (context) => context.session ?? null;

/** A persistent server vault over a SQLite store, built the way an application would. */
export async function openVault({ store, namespace, epoch = 1, keys, vaultOptions = {} }) {
  const keyProvider = createLocalKeyProvider({
    keys: [{ id: "synthetic-1", material: fromHex(keys.keyHex), state: "active" }],
    scope: { namespaces: [namespace] },
  });
  const audit = [];
  const vault = await createPersistentServerVault({
    namespace,
    recoveryEpoch: epoch,
    store,
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
  return { vault, store, audit };
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

/** Encodes byte arrays for IPC. */
export function wire(value) {
  if (value instanceof Uint8Array) return { $hex: Buffer.from(value).toString("hex") };
  if (Array.isArray(value)) return value.map(wire);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, wire(inner)]));
  return value;
}

export function unwire(value) {
  if (Array.isArray(value)) return value.map(unwire);
  if (value !== null && typeof value === "object") {
    if (typeof value.$hex === "string") return new Uint8Array(Buffer.from(value.$hex, "hex"));
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, unwire(inner)]));
  }
  return value;
}

/**
 * Starts one independent server process (`process-worker.mjs`): its own
 * connection, store, key provider, and vault on the shared file, driven by IPC.
 */
export async function spawnWorker(config) {
  const child = fork(PROCESS_WORKER, [], {
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
    /** Fire and forget: for an operation the worker is expected to die in. */
    send(op, args = {}) {
      child.send({ id: next++, op, args });
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

/** A serving namespace in a store, at `epoch`. */
export async function initialized(store, namespace, epoch = 1) {
  const result = await store.initializeNamespace({ namespace, epoch });
  if (result.outcome !== "initialized") throw new Error(`namespace not initialized: ${result.reason}`);
}

export async function openStore(filename, extra = {}) {
  return createSqliteStore({ driver: (await selectedDriver()).driver, filename, busyTimeoutMs: 30_000, maxClockSkewMs: 30_000, ...extra });
}
