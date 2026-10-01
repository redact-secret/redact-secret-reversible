// PII through the persistent profile, against the real installed core
// (docs/specs/persistent-vault.md §8.1; issue #109 "PII activation and exact
// retention allowlist remain opt-in").
//
// The core's PII activation is realm-global. Node's test runner gives this
// file its own process, so the activation below is the realm's first and the
// other files of this directory (which lock PII off with `pii: []`) are not
// affected. Requires a core with a PII surface (beta.10 or later).
//
// Synthetic data: the documentation-example IBAN and a revoked-looking token.
import assert from "node:assert/strict";
import test from "node:test";

import * as core from "@redact-secret/core";

import {
  captureOne,
  createRig,
  CTX_A,
  denied,
  noteSecret,
  registerLeakHygiene,
  rejects,
  RELEASE,
  restoreRequest,
  SECRET_A,
} from "./helpers.mjs";

const SKIP =
  typeof core.piiActivation === "function"
    ? false
    : `installed @redact-secret/core ${core.VERSION} has no PII surface (no piiActivation export); these tests need a beta.10+ core`;

const IBAN = "DE89 3704 0044 0532 0130 00";
const INPUT = `token ${SECRET_A} iban ${IBAN} end`;
noteSecret("captured value", IBAN);

test("PII: the persistent profile adopts the application's activation and retains PII only on the exact-type allowlist", { skip: SKIP }, async () => {
  await core.initialize({ pii: ["pii"] });
  const identity = core.piiActivation();
  const rig = await createRig({ vault: { pii: undefined, expectPiiActivation: identity } });
  assert.equal(rig.vault.piiActivation, identity);

  // Without an allowlist: the PII finding is redacted and not retained. Nothing of it is stored.
  const plain = await captureOne(rig, { text: INPUT });
  assert.deepEqual(plain.tokens.map(({ type }) => type), ["github_token"]);
  assert.equal(plain.unrestorable, 1);
  assert.equal(plain.text.includes(IBAN), false);
  assert.equal(rig.spy.last("createCapture").input.entries.length, 1);
  assert.equal(rig.lifecycleCalls.at(-1).entries, 1);
  assert.equal(rig.lifecycleCalls.at(-1).bytes, Buffer.byteLength(SECRET_A));
  const restoredPlain = await rig.vault.restore(restoreRequest(plain));
  assert.equal(restoredPlain.fields.body.includes(SECRET_A), true);
  assert.equal(restoredPlain.fields.body.includes(IBAN), false, "an unretained PII value cannot come back");

  // An allowlist naming another PII type does not retain this one.
  const otherType = await captureOne(rig, { text: INPUT, pii: { retain: ["pii_global_phone"] } });
  assert.deepEqual(otherType.tokens.map(({ type }) => type), ["github_token"]);
  assert.equal(otherType.unrestorable, 1);
  // `eligible` may narrow the allowlist, never widen it.
  const widened = await captureOne(rig, { text: INPUT, eligible: () => true });
  assert.deepEqual(widened.tokens.map(({ type }) => type), ["github_token"]);

  // With the exact type on the allowlist it is retained, stored encrypted, and restored.
  const kept = await captureOne(rig, { text: INPUT, pii: { retain: ["pii_global_iban"] } });
  assert.deepEqual(kept.tokens.map(({ type }) => type).sort(), ["github_token", "pii_global_iban"]);
  assert.equal(kept.unrestorable, 0);
  const { input } = rig.spy.last("createCapture");
  assert.equal(input.entries.length, 2);
  for (const entry of input.entries) {
    assert.equal(Buffer.from(entry.envelope).includes(Buffer.from(IBAN)), false);
    assert.equal(Buffer.from(entry.envelope).includes(Buffer.from("pii_global_iban")), false, "the finding type is encrypted too");
  }
  const restored = await rig.vault.restore(restoreRequest(kept));
  assert.equal(restored.fields.body, INPUT);
  assert.deepEqual(rig.policyCalls.slice(-2).map((call) => call.type).sort(), ["github_token", "pii_global_iban"]);

  // A malformed or empty allowlist is rejected before anything is stored.
  const before = rig.spy.mutations();
  for (const pii of [{ retain: [] }, { retain: "pii_global_iban" }, "pii", { retain: [7] }]) {
    const error = await rejects(rig.vault.capture(INPUT, { context: CTX_A, release: RELEASE, pii }), "VAULT_FAILURE");
    assert.equal(error.vaultCode, "INVALID_ARGUMENT");
  }
  assert.equal(rig.spy.mutations(), before);

  // A different selection than the realm's is refused at creation, with the core's own code.
  const conflict = await rejects(rig.open({ pii: [] }), "VAULT_FAILURE");
  assert.equal(conflict.vaultCode, "CORE_FAILURE");
  assert.equal(conflict.coreCode, "PII_ACTIVATION_CONFLICT");
  const mismatch = await rejects(
    rig.open({ pii: undefined, expectPiiActivation: "credentials=full;selectors=off;families=;vocabulary=pii-context/v1" }),
    "VAULT_FAILURE",
  );
  assert.equal(mismatch.vaultCode, "PII_ACTIVATION_MISMATCH");

  // A PII value follows the same authorization as any other.
  await denied(rig.vault.restore(restoreRequest(kept)), "budget");
});

registerLeakHygiene({ minErrors: 5 });
