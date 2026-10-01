// One independent server process on the shared database file, for the
// two-process and process-kill tests.
//
// Started with `child_process.fork`; builds everything an application process
// would: its own connection, the SQLite store, the local key provider and record
// crypto, and a persistent server vault. It shares nothing with the other
// process but the file and the key material the parent generates per run.
// Replies are plain data: results, or the code and reason of a sanitized error.
// No restored value is logged.
import { openSqliteStore } from "../dist/store.js";
import { selectedDriver } from "./drivers.mjs";
import { openVault, settle, unwire, wire } from "./fixtures.mjs";

const config = JSON.parse(process.env.RSVQ_WORKER_CONFIG ?? "null");

/** Kill hooks: the process dies by SIGKILL at a chosen point around the commit of a transaction. */
function killHooks(kind) {
  let armed = false;
  const kill = () => process.kill(process.pid, "SIGKILL");
  return {
    arm: () => {
      armed = true;
    },
    internals:
      kind === "before-commit"
        ? { beforeCommit: () => armed && kill() }
        : kind === "after-commit"
          ? { afterCommit: () => armed && kill() }
          : {},
  };
}

async function main() {
  if (config === null || typeof process.send !== "function") return;
  const hooks = killHooks(config.hook);
  let store;
  let vault;
  try {
    store = await openSqliteStore(
      { driver: (await selectedDriver()).driver, filename: config.filename, busyTimeoutMs: config.busyTimeoutMs ?? 30_000, maxClockSkewMs: 30_000, ...(config.storeOptions ?? {}) },
      hooks.internals,
    );
    if (config.keyHex !== undefined) {
      ({ vault } = await openVault({
        store,
        namespace: config.namespace,
        epoch: config.epoch ?? 1,
        keys: { keyHex: config.keyHex, digestHex: config.digestHex },
        vaultOptions: config.vaultOptions ?? {},
      }));
    }
  } catch (thrown) {
    // A process that failed to start must not linger holding a connection to the shared file.
    try {
      store?.close();
    } catch {
      // Nothing to add.
    }
    process.send({ event: "failed", code: thrown?.code ?? "unknown" }, () => process.exit(0));
    return;
  }

  const timed = async (work) => {
    const startedAt = process.hrtime.bigint();
    const outcome = await settle(work());
    return { ...outcome, startedAt: String(startedAt), endedAt: String(process.hrtime.bigint()) };
  };

  const operations = {
    capture: ({ text, context, maxUses, release }) => settle(vault.capture(text, { context, release, ...(maxUses === undefined ? {} : { maxUses }) })),
    restore: ({ request }) => timed(() => vault.restore(request)),
    burst: ({ requests }) => Promise.all(requests.map((request) => timed(() => vault.restore(request)))),
    revoke: ({ context, captureId }) => timed(() => vault.revoke({ context, captureId })),
    deleteCiphertext: ({ context, captureId }) => settle(vault.deleteCaptureCiphertext({ context, captureId })),
    resolveAttempt: ({ request }) => settle(vault.resolveAttempt(request)),
    store: async ({ method, input, arm }) => {
      if (arm) hooks.arm();
      return wire(await timed(() => store[method](unwire(input))));
    },
  };

  process.on("message", async (message) => {
    if (message.op === "exit") {
      await vault?.close();
      store.close();
      process.exit(0);
    }
    const run = operations[message.op];
    const reply = run === undefined ? { ok: false, code: "UNKNOWN_OPERATION" } : await run(message.args);
    process.send({ id: message.id, reply });
  });
  process.send({ event: "ready" });
}

await main();
