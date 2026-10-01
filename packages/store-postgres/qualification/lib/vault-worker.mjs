// One independent server process for the two-process scenarios.
//
// It is started with `child_process.fork` and builds everything an
// application process would build for itself: a `pg.Pool`, the PostgreSQL
// store, the local key provider and record crypto, and a persistent server
// vault. It shares nothing with the other process except the database and
// the key material, which the parent generates per run and passes as hex.
// It is driven by IPC messages and replies with plain data: results, or the
// code and reason of a sanitized error. No restored value is logged.
import { openPool, openVault, settle } from "./harness.mjs";

const config = JSON.parse(process.env.RSVQ_WORKER_CONFIG ?? "null");

function revive(value) {
  if (Array.isArray(value)) return value.map(revive);
  if (value !== null && typeof value === "object") {
    if (typeof value.$hex === "string") return new Uint8Array(Buffer.from(value.$hex, "hex"));
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, revive(inner)]));
  }
  return value;
}

function plain(value) {
  if (value instanceof Uint8Array) return { $hex: Buffer.from(value).toString("hex") };
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, plain(inner)]));
  return value;
}

/**
 * The response-loss hook: after the `COMMIT` of a transaction that consumed a
 * use has been acknowledged by PostgreSQL, tell the parent and then never
 * return, so the parent can `kill -9` this process before it replies.
 */
function killAfterRestoreCommit(pool) {
  return {
    async connect() {
      const client = await pool.connect();
      let consumed = false;
      return {
        async query(text, values) {
          if (text.startsWith("BEGIN")) consumed = false;
          if (text.includes("SET used = e.used + u.count")) consumed = true;
          const result = await client.query(text, values);
          if (text === "COMMIT" && consumed) {
            process.send({ event: "commit-acknowledged" });
            await new Promise(() => {});
          }
          return result;
        },
        release: (destroy) => client.release(destroy),
        on: (event, listener) => client.on(event, listener),
        removeListener: (event, listener) => client.removeListener(event, listener),
      };
    },
  };
}

async function main() {
  if (config === null || typeof process.send !== "function") return;
  const pool = openPool(config.url, config.poolMax ?? 20);
  const storePool = config.hook === "kill-after-restore-commit" ? killAfterRestoreCommit(pool) : pool;
  let vault;
  let store;
  try {
    ({ vault, store } = await openVault({
      pool: storePool,
      namespace: config.namespace,
      epoch: config.epoch ?? 1,
      keys: { keyHex: config.keyHex, digestHex: config.digestHex },
      schema: config.schema,
      storeOptions: config.storeOptions ?? {},
      vaultOptions: config.vaultOptions ?? {},
    }));
  } catch (thrown) {
    process.send({ event: "failed", code: thrown?.code ?? "unknown" });
    await pool.end().catch(() => undefined);
    return;
  }

  const timed = async (work) => {
    const startedAt = process.hrtime.bigint();
    const outcome = await settle(work());
    return { ...outcome, startedAt: String(startedAt), endedAt: String(process.hrtime.bigint()) };
  };

  const operations = {
    capture: ({ text, context, maxUses, release }) =>
      settle(vault.capture(text, { context, release, ...(maxUses === undefined ? {} : { maxUses }) })),
    restore: ({ request }) => timed(() => vault.restore(request)),
    burst: ({ requests }) => Promise.all(requests.map((request) => timed(() => vault.restore(request)))),
    revoke: ({ context, captureId }) => timed(() => vault.revoke({ context, captureId })),
    deleteCiphertext: ({ context, captureId }) => settle(vault.deleteCaptureCiphertext({ context, captureId })),
    resolveAttempt: ({ request }) => settle(vault.resolveAttempt(request)),
    store: async ({ method, input }) => {
      const outcome = await timed(() => store[method](revive(input)));
      return plain(outcome);
    },
  };

  process.on("message", async (message) => {
    if (message.op === "exit") {
      await vault.close();
      await pool.end().catch(() => undefined);
      process.exit(0);
    }
    const run = operations[message.op];
    const reply = run === undefined ? { ok: false, code: "UNKNOWN_OPERATION" } : await run(message.args);
    process.send({ id: message.id, reply });
  });
  process.send({ event: "ready" });
}

await main();
