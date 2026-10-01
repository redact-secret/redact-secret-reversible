#!/usr/bin/env node
// Capture in one process, restore in another, over PostgreSQL.
//   node examples/persistent/demo.mjs            runs both steps, each in its own process
//   node examples/persistent/demo.mjs capture    prints { captureId, text }
//   node examples/persistent/demo.mjs restore <captureId> <text>
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import pg from "pg";
import { createPostgresStore } from "@redact-secret/store-postgres";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";
import { VaultServerError } from "@redact-secret/vault-server";
import { createPersistentServerVault } from "@redact-secret/vault-server/persistent";
import { allOf, allowSameTenantOnly, allowSinkPurposes } from "@redact-secret/vault-server/policies";

import { APP_URL, NAMESPACE, RECOVERY_EPOCH, SCHEMA, loadDevKeys } from "./config.mjs";

const SINK = "support-ticket-reply-sink-synthetic";
const PURPOSE = "support-reply-purpose-synthetic";
// Stands in for your already-authenticated request.
const request = { userId: "user-synthetic-1", tenant: "tenant-acme-synthetic" };

/** What every server process does at start. */
async function openVault() {
  // The application creates the pool and closes it.
  const pool = new pg.Pool({ connectionString: APP_URL, max: 4, connectionTimeoutMillis: 5000 });
  pool.on("error", () => {});
  const store = await createPostgresStore({ pool, schema: SCHEMA });
  const { wrappingKey, digestKey } = loadDevKeys(); // a real server: from its secret manager
  const vault = await createPersistentServerVault({
    namespace: NAMESPACE,
    recoveryEpoch: RECOVERY_EPOCH,
    store,
    crypto: createRecordCrypto({
      keyProvider: createLocalKeyProvider({
        keys: [{ id: "dev-1", material: wrappingKey, state: "active" }],
        scope: { namespaces: [NAMESPACE] },
      }),
    }),
    digestKey,
    resolvePrincipal: (context) => ({ id: context.userId, tenant: context.tenant }),
    // Deny by default: this server may capture and revoke, and nothing else.
    lifecyclePolicy: ({ operation }) => ({ allow: operation === "capture" || operation === "revoke" }),
    policy: allOf(allowSameTenantOnly, allowSinkPurposes({ [SINK]: [PURPOSE] })),
    limits: { entryTtlMs: 5 * 60 * 1000 },
    pii: [],
  });
  return { vault, close: async () => (await vault.close(), await pool.end()) };
}

async function capture() {
  const { vault, close } = await openVault();
  try {
    // Unmistakably synthetic; never a real credential.
    const captured = await vault.capture("Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today", {
      context: request,
      release: [{ sink: SINK, paths: ["body"] }],
    });
    return { captureId: captured.captureId, text: captured.text };
  } finally {
    await close();
  }
}

async function restore(captureId, text) {
  const { vault, close } = await openVault();
  const attempt = () =>
    vault.restore({ context: request, sink: SINK, purpose: PURPOSE, captures: [captureId], fields: { body: text } });
  try {
    const { fields } = await attempt();
    // A value is released at most once: the same restore again is denied.
    const second = await attempt().then(
      () => "released",
      (error) => {
        if (!(error instanceof VaultServerError)) throw error;
        return error.reason ?? error.code;
      },
    );
    return { body: fields.body, second };
  } finally {
    await close();
  }
}

const [command, ...args] = process.argv.slice(2);
if (command === "capture") {
  console.log(JSON.stringify(await capture()));
} else if (command === "restore") {
  console.log(JSON.stringify(await restore(args[0], args[1])));
} else {
  const self = fileURLToPath(import.meta.url);
  const run = (...argv) => JSON.parse(execFileSync(process.execPath, [self, ...argv], { encoding: "utf8" }));

  const captured = run("capture");
  console.log("process 1 captured:  ", captured.text);
  assert.ok(!captured.text.includes("ghp_"));

  const restored = run("restore", captured.captureId, captured.text);
  console.log("process 2 restored:  ", restored.body);
  console.log("process 2, again:    ", restored.second);
  assert.equal(restored.body, "Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today");
  assert.notEqual(restored.second, "released");
}
