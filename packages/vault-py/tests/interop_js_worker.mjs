// Test tooling for the cross-language runs (docs/plans/python-persistence-parity.md sections 5.4 and 6.1): one
// JavaScript persistent server process over PostgreSQL, driven by one JSON object per line on standard input, answering
// one per line on standard output. It builds what an application process would build for itself: its own pool, the
// PostgreSQL store, the local key provider, record crypto, and a persistent server vault. It shares nothing with the
// Python process except the database and the key material, which the test generates per run and passes as hex.
//
// Configuration: RSV_INTEROP_CONFIG = { url, schema, namespace, epoch, keyHex, digestHex, poolMax, storeOptions, vaultOptions }.
// Requests: { id, op, args }. Answers: { id, reply }. Events: { event: "ready" | "held", ... }.
//
// A hold point: `{ op: "arm-hold", args: { holdId } }` makes the next write transaction of this process pause before
// COMMIT (it has executed its statements and holds its locks), announce `{ event: "held", holdId }`, and wait for
// `{ op: "release", args: { holdId } }`. Synthetic values only; no restored value is logged.
import { createInterface } from "node:readline";

import { openPool, openVault, settle } from "../../store-postgres/qualification/lib/harness.mjs";

const config = JSON.parse(process.env.RSV_INTEROP_CONFIG ?? "null");
const BYTES_FIELDS = new Set(["envelope", "wrappedKey", "requestDigest"]);
const HEX = "0123456789abcdef";

function write(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function toBytes(text) {
  if (typeof text !== "string" || text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) return text;
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes) {
  let out = "";
  for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 15];
  return out;
}

function decode(value, key) {
  if (Array.isArray(value)) return value.map((item) => decode(item));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, decode(item, name)]));
  return key !== undefined && BYTES_FIELDS.has(key) ? toBytes(value) : value;
}

function encode(value) {
  if (value instanceof Uint8Array) return toHex(value);
  if (Array.isArray(value)) return value.map((item) => encode(item));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, encode(item)]));
  return value;
}

/** A pool whose write transactions pause before COMMIT when a hold is armed. */
function holdingPool(pool) {
  const waiting = new Map();
  let armed = null;
  return {
    arm(holdId) {
      armed = holdId;
    },
    release(holdId) {
      waiting.get(holdId)?.();
      waiting.delete(holdId);
    },
    async connect() {
      const client = await pool.connect();
      let writing = false;
      return {
        async query(text, values) {
          if (text.startsWith("BEGIN")) writing = text.includes("READ COMMITTED");
          if (text === "COMMIT" && writing && armed !== null) {
            const holdId = armed;
            armed = null;
            const released = new Promise((resolve) => waiting.set(holdId, resolve));
            write({ event: "held", holdId });
            await released;
          }
          return client.query(text, values);
        },
        release: (destroy) => client.release(destroy),
        on: (event, listener) => client.on(event, listener),
        removeListener: (event, listener) => client.removeListener(event, listener),
      };
    },
  };
}

async function main() {
  if (config === null) return;
  const pool = openPool(config.url, config.poolMax ?? 20);
  const holding = holdingPool(pool);
  let vault;
  let store;
  try {
    ({ vault, store } = await openVault({
      pool: holding,
      namespace: config.namespace,
      epoch: config.epoch ?? 1,
      keys: { keyHex: config.keyHex, digestHex: config.digestHex },
      schema: config.schema,
      storeOptions: config.storeOptions ?? {},
      vaultOptions: config.vaultOptions ?? {},
    }));
  } catch (thrown) {
    write({ event: "failed", code: thrown?.code ?? "unknown" });
    await pool.end().catch(() => undefined);
    return;
  }
  const operations = {
    capture: ({ text, context, maxUses, release }) =>
      settle(vault.capture(text, { context, release, ...(maxUses === undefined ? {} : { maxUses }) })),
    restore: ({ request }) => settle(vault.restore(request)),
    burst: async ({ requests }) => Promise.all(requests.map((request) => settle(vault.restore(request)))),
    revoke: ({ context, captureId }) => settle(vault.revoke({ context, captureId })),
    resolveAttempt: ({ request }) => settle(vault.resolveAttempt(request)),
    "arm-hold": ({ holdId }) => {
      holding.arm(holdId);
      return { ok: true };
    },
    release: ({ holdId }) => {
      holding.release(holdId);
      return { ok: true };
    },
    store: async ({ method, input }) => {
      try {
        return { result: encode(await store[method](decode(input))) };
      } catch (thrown) {
        return { error: thrown?.code ?? "FOREIGN" };
      }
    },
  };
  const lines = createInterface({ input: process.stdin });
  lines.on("line", async (line) => {
    if (line.trim() === "") return;
    const message = JSON.parse(line);
    if (message.op === "exit") {
      await vault.close();
      await pool.end().catch(() => undefined);
      process.exit(0);
    }
    const run = operations[message.op];
    const reply = run === undefined ? { ok: false, code: "UNKNOWN_OPERATION" } : await run(message.args ?? {});
    write({ id: message.id, reply });
  });
  write({ event: "ready" });
}

await main();
