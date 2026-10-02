// Test tooling for the capture-parity run (docs/plans/python-persistence-parity.md section 6.2, gate G5): one
// JavaScript persistent server over `store-memory`, with a clock the test moves, driven by one JSON object per line
// on standard input and answering one per line on standard output. A new process is started for each case and PII
// lane, because the core's PII activation is realm-global.
//
// Requests: { id, op, args } with op one of
//   configure { pii: string[], limits?: {...}, namespace }   builds the server
//   capture   { text, options }                              captures; answers the result or the error code, and,
//                                                            on success, each issued token's stored record opened
//                                                            with the run's test key: [value, type]
//   advance   { ms }                                         moves the clock
// Synthetic values only. The opened values are compared by the test and never logged.
import { createInterface } from "node:readline";

import { createRecordCrypto, deriveEntryId } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { createMemoryStore } from "@redact-secret/store-memory";
import { createPersistentServerVault, VaultServerError } from "@redact-secret/vault-server/persistent";

const TENANT = "tenant-conformance-synthetic";
/** Public test constants, as in conformance/persistent/v1/vectors.json. Never a real key. */
const KEY_MATERIAL = Uint8Array.from({ length: 32 }, (_unused, index) => 0x80 + index);
const DIGEST_KEY = Uint8Array.from({ length: 32 }, (_unused, index) => 0x40 + index);

function write(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

let state = null;
let clock = 0;

async function configure({ pii, limits, namespace }) {
  clock = 0;
  const memory = createMemoryStore({ now: () => clock });
  await memory.store.initializeNamespace({ namespace, epoch: 1 });
  const crypto = createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "synthetic-2026-10", material: KEY_MATERIAL, state: "active" }],
      scope: { namespaces: [namespace] },
    }),
  });
  const vault = await createPersistentServerVault({
    namespace,
    recoveryEpoch: 1,
    store: memory.store,
    crypto,
    digestKey: DIGEST_KEY,
    resolvePrincipal: () => ({ id: "user-conformance-synthetic", tenant: TENANT }),
    policy: () => ({ allow: true }),
    lifecyclePolicy: () => ({ allow: true }),
    now: () => clock,
    allowNonDurableStore: true,
    pii,
    ...(limits === undefined || limits === null ? {} : { limits }),
  });
  state = { vault, store: memory.store, crypto, namespace };
}

function failure(thrown) {
  if (thrown instanceof VaultServerError) {
    return { ok: false, code: thrown.code, vaultCode: thrown.vaultCode ?? null, reason: thrown.reason ?? null, coreCode: thrown.coreCode ?? null };
  }
  if (process.env.RSV_DEBUG === "1") process.stderr.write(`${thrown?.stack}\n`);
  return { ok: false, code: "FOREIGN", reason: null, coreCode: null };
}

async function stored(tokens) {
  const { store, crypto, namespace } = state;
  const found = [];
  for (const token of tokens) {
    const entryId = await deriveEntryId(namespace, TENANT, token);
    const read = await store.readEntries({ scope: { namespace, tenant: TENANT }, entryIds: [entryId] });
    const entry = read.entries[0];
    const capture = read.captures.find((candidate) => candidate.captureId === entry.captureId);
    const [payload] = await crypto.openCapture({
      keyRef: capture.keyRef,
      wrappedKey: capture.wrappedKey,
      context: { namespace, tenant: TENANT, captureId: capture.captureId },
      records: [
        {
          binding: {
            namespace,
            tenant: TENANT,
            captureId: capture.captureId,
            entryId,
            sessionId: null,
            createdAt: capture.createdAt,
            expiresAt: capture.expiresAt,
            maxUses: entry.maxUses,
          },
          envelope: entry.envelope,
        },
      ],
    });
    found.push([Buffer.from(payload.value).toString("utf8"), payload.type]);
    payload.value.fill(0);
  }
  return found;
}

async function capture({ text, options }) {
  const { eligibleTypes, policy, ...rest } = options;
  try {
    const result = await state.vault.capture(text, {
      context: {},
      ...rest,
      // The corpus writes a policy as a map from finding type to action; the API takes an object with `evaluate`.
      ...(policy === undefined || policy === null ? {} : { policy: { evaluate: (finding) => policy[finding.type] ?? policy.default ?? "redact" } }),
      ...(eligibleTypes === undefined || eligibleTypes === null ? {} : { eligible: (finding) => eligibleTypes.includes(finding.type) }),
    });
    return {
      ok: true,
      value: JSON.parse(JSON.stringify(result)),
      stored: await stored(result.tokens.map((item) => item.token)),
    };
  } catch (thrown) {
    return failure(thrown);
  }
}

const lines = createInterface({ input: process.stdin });
lines.on("line", async (line) => {
  if (line.trim() === "") return;
  const message = JSON.parse(line);
  if (message.op === "exit") process.exit(0);
  let reply;
  try {
    if (message.op === "configure") {
      await configure(message.args);
      reply = { ok: true };
    } else if (message.op === "capture") {
      reply = await capture(message.args);
    } else if (message.op === "advance") {
      clock += message.args.ms;
      reply = { ok: true };
    } else {
      reply = { ok: false, code: "UNKNOWN_OPERATION" };
    }
  } catch (thrown) {
    reply = failure(thrown);
  }
  write({ id: message.id, reply });
});
write({ event: "ready" });
