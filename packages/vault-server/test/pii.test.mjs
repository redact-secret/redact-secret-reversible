// PII options are forwarded verbatim to @redact-secret/vault
// (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md §3).
// These run against the installed core; with a beta.9 core they assert
// the fail-closed compatibility rules (§4) and skip if the core has a PII
// surface. PII-on behavior through this package is in pii-core.test.mjs.
import assert from "node:assert/strict";
import test from "node:test";

import * as core from "@redact-secret/core";

import { createServerVault, VaultServerError } from "../dist/index.js";
import { allowAll, SECRET_A, staticResolver } from "./helpers.mjs";

const SKIP = typeof core.piiActivation === "function"
  ? "installed @redact-secret/core has a PII surface (piiActivation); beta.9 compatibility checks do not apply"
  : false;

function open(extra = {}) {
  return createServerVault({
    resolvePrincipal: staticResolver({ id: "user-synthetic-1", tenant: "tenant-acme-synthetic" }),
    policy: allowAll,
    ...extra,
  });
}

function vaultFailure(vaultCode) {
  return (e) => e instanceof VaultServerError && e.code === "VAULT_FAILURE" && e.vaultCode === vaultCode;
}

test("beta.9: piiActivation is null with pii omitted or []", { skip: SKIP }, async () => {
  assert.equal((await open()).piiActivation, null);
  const server = await open({ pii: [] });
  assert.equal(server.piiActivation, null);
  const captured = await server.capture(`secret ${SECRET_A}`, { release: [{ sink: "s", paths: ["p"] }], issuedTenant: "tenant-acme-synthetic" });
  assert.equal(captured.tokens.length, 1, "pii: [] equals omission");
});

test("beta.9: pii and expectPiiActivation are forwarded and fail PII_UNAVAILABLE", { skip: SKIP }, async () => {
  await assert.rejects(open({ pii: ["pii"] }), vaultFailure("PII_UNAVAILABLE"));
  await assert.rejects(open({ expectPiiActivation: "credentials=full;selectors=off" }), vaultFailure("PII_UNAVAILABLE"));
  await assert.rejects(open({ pii: "pii" }), vaultFailure("INVALID_ARGUMENT"));
});

test("beta.9: capture pii retention is forwarded and fails PII_UNAVAILABLE", { skip: SKIP }, async () => {
  const server = await open();
  await assert.rejects(
    server.capture(`secret ${SECRET_A}`, {
      release: [{ sink: "s", paths: ["p"] }],
      issuedTenant: "tenant-acme-synthetic",
      pii: { retain: ["pii_global_iban"] },
    }),
    vaultFailure("PII_UNAVAILABLE"),
  );
  await assert.rejects(
    server.capture("x", { release: [{ sink: "s", paths: ["p"] }], issuedTenant: "tenant-acme-synthetic", pii: { retain: [] } }),
    vaultFailure("INVALID_ARGUMENT"),
  );
  assert.equal((await server.stats()).entries, 0);
});

// On a PII-capable core (beta.10+) the same forwarding is checked against a
// realm the vault locks off with `pii: []` (this file has its own process).
const SKIP_UNLESS_PII = typeof core.piiActivation === "function"
  ? false
  : "installed @redact-secret/core has no PII surface; PII-off activation checks need beta.10+";

test("PII-capable core: pii: [] locks the realm off; malformed options and capture retention are forwarded", { skip: SKIP_UNLESS_PII }, async () => {
  await assert.rejects(open({ pii: "pii" }), vaultFailure("INVALID_ARGUMENT"));
  const server = await open({ pii: [] });
  assert.equal(server.piiActivation, core.piiActivation());
  const captured = await server.capture(`secret ${SECRET_A}`, { release: [{ sink: "s", paths: ["p"] }], issuedTenant: "tenant-acme-synthetic" });
  assert.equal(captured.tokens.length, 1);
  await assert.rejects(
    server.capture(`secret ${SECRET_A}`, {
      release: [{ sink: "s", paths: ["p"] }],
      issuedTenant: "tenant-acme-synthetic",
      pii: { retain: ["pii_global_iban"] },
    }),
    vaultFailure("PII_UNAVAILABLE"),
  );
  await assert.rejects(
    server.capture("x", { release: [{ sink: "s", paths: ["p"] }], issuedTenant: "tenant-acme-synthetic", pii: { retain: [] } }),
    vaultFailure("INVALID_ARGUMENT"),
  );
});

test("coreCode is carried only for VAULT_FAILURE / CORE_FAILURE", () => {
  const withCore = new VaultServerError("VAULT_FAILURE", { vaultCode: "CORE_FAILURE", coreCode: "PII_ACTIVATION_CONFLICT" });
  assert.equal(withCore.coreCode, "PII_ACTIVATION_CONFLICT");
  assert.equal(new VaultServerError("VAULT_FAILURE", { vaultCode: "PII_UNAVAILABLE", coreCode: "X" }).coreCode, undefined);
  assert.equal(new VaultServerError("INVALID_ARGUMENT", { coreCode: "X" }).coreCode, undefined);
  assert.ok(!withCore.message.includes("PII_ACTIVATION_CONFLICT"), "message stays fixed");
});
