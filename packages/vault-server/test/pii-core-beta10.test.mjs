// Core beta.10 regressions through @redact-secret/vault-server against the
// *real* installed core (#43): the core #887 placeholder rule, a
// default-confidence warn PII finding, and PII findings under maxFindings.
// Requires a core with a PII surface (beta.10 or later); skipped with a
// stated reason on a beta.9 core.
//
// Node's test runner gives this file its own process, so the application's
// activation below is the realm's first.
//
// Synthetic data: the documentation-example IBAN, a revoked-looking token, and
// the core's own Medium-confidence phone conformance value (a seven-digit
// local number with no area code; conformance/fixtures/pii-phone-v1.json in
// the core repository).
import assert from "node:assert/strict";
import test from "node:test";

import * as core from "@redact-secret/core";
import { createServerVault, VaultServerError } from "@redact-secret/vault-server";

const SKIP = typeof core.piiActivation === "function"
  ? false
  : `installed @redact-secret/core ${core.VERSION} has no PII surface (no piiActivation export); PII-on tests need a beta.10+ core`;

const GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const GH2 = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111";
const IBAN = "DE89 3704 0044 0532 0130 00";
const PHONE = "555-2345";
const TENANT = "tenant-acme-synthetic";
const RELEASE = [{ sink: "sink-a", paths: ["body"] }];

function open(extra = {}) {
  return createServerVault({
    resolvePrincipal: () => ({ id: "user-synthetic-1", tenant: TENANT }),
    policy: () => ({ allow: true }),
    ...extra,
  });
}

function valueFree(e, ...values) {
  const surfaces = [String(e), String(e.message), String(e.stack), JSON.stringify(e), JSON.stringify(Object.entries(e))];
  for (const v of values) assert.ok(surfaces.every((s) => !s.includes(v)), "an error surface carries a fixture value");
}

async function failure(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return assert.fail("expected a rejection");
}

test("real core (server): #887 placeholder rule, default warn PII, and PII under maxFindings", { skip: SKIP }, async (t) => {
  await core.initialize({ pii: ["pii"] });

  await t.test("a displayFormatter label reproducing a sibling warn/allow finding -> VAULT_FAILURE / CORE_FAILURE / INVALID_PLACEHOLDER", async () => {
    const events = [];
    const server = await open({ onVaultAudit: (e) => events.push(e) });
    const input = `token ${GH} iban ${IBAN} token ${GH2} end`;
    for (const action of ["warn", "allow"]) {
      const policy = { evaluate: (f) => (f.type === "pii_global_iban" ? action : "redact") };
      let calls = 0;
      const before = await server.stats();
      events.length = 0;
      const error = await failure(server.capture(input, {
        release: RELEASE, issuedTenant: TENANT, policy, unredacted: "pass-through",
        eligible: () => ++calls === 1, displayFormatter: () => IBAN,
      }));
      assert.ok(error instanceof VaultServerError);
      assert.equal(error.code, "VAULT_FAILURE");
      assert.equal(error.vaultCode, "CORE_FAILURE");
      assert.equal(error.coreCode, "INVALID_PLACEHOLDER");
      valueFree(error, IBAN, GH, GH2);
      assert.deepEqual(await server.stats(), before, `${action}: the failed capture committed something`);
      assert.equal(events.length, 1);
      assert.equal(events[0].code, "CORE_FAILURE");
      assert.ok(!JSON.stringify(events).includes(IBAN));
    }
  });

  await t.test("default-confidence warn PII (Medium pii_global_phone) x unredacted reject / pass-through", async () => {
    const server = await open();
    const input = `telephone=${PHONE} token ${GH}`;
    const error = await failure(server.capture(input, { release: RELEASE, issuedTenant: TENANT }));
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.vaultCode, "UNREDACTED_FINDINGS");
    valueFree(error, PHONE, GH);
    const passed = await server.capture(input, { release: RELEASE, issuedTenant: TENANT, unredacted: "pass-through" });
    assert.equal(passed.passedThrough, 1);
    assert.deepEqual(passed.passedThroughTypes, ["pii_global_phone"]);
    assert.deepEqual(passed.tokens.map((t) => t.type), ["github_token"]);
    assert.ok(passed.text.includes(`telephone=${PHONE}`) && !passed.text.includes(GH));
  });

  await t.test("PII findings count toward maxFindings -> VAULT_FAILURE / CORE_FAILURE / FINDING_LIMIT_EXCEEDED", async () => {
    const server = await open({ limits: { maxFindings: 2 } });
    const two = `iban ${IBAN}; iban ${IBAN}`;
    const kept = await server.capture(two, { release: RELEASE, issuedTenant: TENANT, pii: { retain: ["pii_global_iban"] } });
    assert.equal(kept.tokens.length, 2);
    const before = await server.stats();
    const error = await failure(server.capture(`${two}; iban ${IBAN}`, { release: RELEASE, issuedTenant: TENANT, pii: { retain: ["pii_global_iban"] } }));
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.code, "VAULT_FAILURE");
    assert.equal(error.vaultCode, "CORE_FAILURE");
    assert.equal(error.coreCode, "FINDING_LIMIT_EXCEEDED");
    valueFree(error, IBAN);
    assert.deepEqual(await server.stats(), before);
  });
});
