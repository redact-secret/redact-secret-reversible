// PII-on behavior through @redact-secret/vault-server against the *real*
// installed core. Requires a core with a PII surface (beta.10 or later);
// skipped with a stated reason on the pinned beta.9.
//
// Node's test runner gives this file its own process, so the application's
// activation below is the realm's first. Imports are by package name so the
// file also runs in a scratch consumer next to a candidate core.
//
// Synthetic data: the documentation-example IBAN and a revoked-looking token.
import assert from "node:assert/strict";
import test from "node:test";

import * as core from "@redact-secret/core";
import { createServerVault, VaultServerError } from "@redact-secret/vault-server";

const SKIP = typeof core.piiActivation === "function"
  ? false
  : `installed @redact-secret/core ${core.VERSION} has no PII surface (no piiActivation export); PII-on tests need a beta.10+ core`;

const GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const IBAN = "DE89 3704 0044 0532 0130 00";
const TENANT = "tenant-acme-synthetic";

function open(extra = {}) {
  return createServerVault({
    resolvePrincipal: () => ({ id: "user-synthetic-1", tenant: TENANT }),
    policy: () => ({ allow: true }),
    ...extra,
  });
}

test("real core: server adopts the application's activation, forwards retention, and restores allowlisted PII", { skip: SKIP }, async () => {
  await core.initialize({ pii: ["pii"] });
  const identity = core.piiActivation();

  const server = await open({ expectPiiActivation: identity });
  assert.equal(server.piiActivation, identity);

  const input = `token ${GH} iban ${IBAN} end`;
  const release = [{ sink: "sink-a", paths: ["body"] }];

  const plain = await server.capture(input, { release, issuedTenant: TENANT });
  assert.deepEqual(plain.tokens.map((t) => t.type), ["github_token"]);
  assert.equal(plain.unrestorable, 1);

  const kept = await server.capture(input, { release, issuedTenant: TENANT, pii: { retain: ["pii_global_iban"] } });
  assert.deepEqual(kept.tokens.map((t) => t.type).sort(), ["github_token", "pii_global_iban"]);
  const restored = await server.restore({ context: {}, sink: "sink-a", purpose: "synthetic-test", captures: [kept.captureId], fields: { body: kept.text } });
  assert.ok(restored.fields.body === input, "restored text equals the original input");

  // A different selection conflicts, surfaced value-free with the core's code.
  await assert.rejects(
    open({ pii: [] }),
    (e) => e instanceof VaultServerError && e.code === "VAULT_FAILURE" && e.vaultCode === "CORE_FAILURE" && e.coreCode === "PII_ACTIVATION_CONFLICT",
  );
  await assert.rejects(
    open({ expectPiiActivation: "credentials=full;selectors=off;families=;vocabulary=pii-context/v1" }),
    (e) => e instanceof VaultServerError && e.vaultCode === "PII_ACTIVATION_MISMATCH",
  );
});
