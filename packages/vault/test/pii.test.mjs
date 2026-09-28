// Unit tests for the PII retention allowlist and application-owned core PII
// activation (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md).
//
// Runs against the built package (dist/). Two kinds of core:
// - a fake core (./fake-core.mjs) injected through the internal `openVault`,
//   which models both a PII-capable core and a beta.9-shaped one; and
// - the installed @redact-secret/core through the public `createVault`. With
//   the pinned beta.9 those tests assert the fail-closed compatibility rules
//   (ADR §4); they skip, with a reason, if the installed core has a PII surface.
//
// All data is synthetic: FAKEPII-… markers and a revoked-looking token shape.
import assert from "node:assert/strict";
import test from "node:test";

import * as core from "@redact-secret/core";

import { VaultError, VAULT_ERROR_CODES } from "../dist/errors.js";
import { isPiiActive, isPiiFindingType, resolvePiiRetention, resolvePiiSelection } from "../dist/pii.js";
import { createVault, openVault } from "../dist/vault.js";
import { createFakeCore } from "./fake-core.mjs";

const GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const IBAN = "FAKEPII-IBAN-0001";
const SSN = "FAKEPII-SSN-0002";
const PHONE = "FAKEPII-PHONE-0003";
const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
const INSTALLED_HAS_PII = typeof core.piiActivation === "function";
const BETA9_ONLY = INSTALLED_HAS_PII
  ? "installed @redact-secret/core has a PII surface (piiActivation); beta.9 compatibility checks do not apply"
  : false;

function isVaultError(code, coreCode) {
  return (error) => {
    assert.ok(error instanceof VaultError, `expected VaultError, got ${error?.name}`);
    assert.equal(error.code, code);
    if (coreCode !== undefined) assert.equal(error.coreCode, coreCode);
    return true;
  };
}

async function piiRealm(selection = ["pii"]) {
  const fake = createFakeCore();
  await fake.module.initialize({ pii: selection });
  fake.calls.initialize.length = 0;
  return fake;
}

async function piiVault(options = {}) {
  const fake = await piiRealm();
  const vault = await openVault(fake.module, options);
  return { vault, fake };
}

// --- error codes -----------------------------------------------------------

test("PII error codes are fixed, value-free, and listed", () => {
  assert.ok(VAULT_ERROR_CODES.includes("PII_UNAVAILABLE"));
  assert.ok(VAULT_ERROR_CODES.includes("PII_ACTIVATION_MISMATCH"));
  assert.equal(
    new VaultError("PII_UNAVAILABLE").message,
    "PII options were supplied, but the redaction core has no PII support or PII detection is not active.",
  );
  assert.equal(
    new VaultError("PII_ACTIVATION_MISMATCH").message,
    "The redaction core's PII activation differs from the expected activation.",
  );
});

// --- helpers #39 reuses -----------------------------------------------------

test("isPiiFindingType checks only the exact pii_ prefix", () => {
  assert.equal(isPiiFindingType("pii_global_email"), true);
  assert.equal(isPiiFindingType("pii_"), true);
  assert.equal(isPiiFindingType("PII_global_email"), false);
  assert.equal(isPiiFindingType("github_token"), false);
  assert.equal(isPiiFindingType("xpii_global_email"), false);
});

test("isPiiActive: null, selectors=off, and an unreadable identity are inactive", () => {
  assert.equal(isPiiActive(null), false);
  assert.equal(isPiiActive("credentials=full;selectors=off;families=;vocabulary=pii-context/v1"), false);
  assert.equal(isPiiActive("credentials=full;families=;vocabulary=v1"), false);
  assert.equal(isPiiActive("credentials=full;selectors=;families=;vocabulary=v1"), false);
  assert.equal(isPiiActive("credentials=full;selectors=pii:global;families=pii:global:iban;vocabulary=v1"), true);
});

test("resolvePiiRetention accepts exact types, de-duplicates, and rejects everything else", () => {
  assert.equal(resolvePiiRetention(undefined), undefined);
  assert.deepEqual([...resolvePiiRetention({ retain: ["pii_global_iban", "pii_global_iban"] })], ["pii_global_iban"]);
  assert.deepEqual([...resolvePiiRetention(Object.assign(Object.create(null), { retain: ["pii_x-y_1"] }))], ["pii_x-y_1"]);
  // Unknown but well-formed: accepted (it simply never matches).
  assert.equal(resolvePiiRetention({ retain: ["pii_not_a_real_family"] }).size, 1);
  const bad = [
    null,
    "pii_global_iban",
    ["pii_global_iban"],
    {},
    { retain: [] },
    { retain: "pii_global_iban" },
    { retain: ["pii_global_iban"], extra: true },
    { retain: [42] },
    { retain: ["global_iban"] },
    { retain: ["pii_"] },
    { retain: ["PII_GLOBAL_IBAN"] },
    { retain: ["pii_global_*"] },
    { retain: ["pii:global:iban"] },
    { retain: ["pii_global iban"] },
    { retain: [`pii_${"a".repeat(125)}`] },
    { retain: Array.from({ length: 65 }, (_, i) => `pii_t${i}`) },
    { retain: [, "pii_global_iban"] }, // eslint-disable-line no-sparse-arrays
    new (class Retention { retain = ["pii_global_iban"]; })(),
    { [Symbol("x")]: 1, retain: ["pii_global_iban"] },
  ];
  for (const value of bad) assert.throws(() => resolvePiiRetention(value), isVaultError("INVALID_ARGUMENT"));
  assert.equal(resolvePiiRetention({ retain: [`pii_${"a".repeat(124)}`] }).size, 1, "128 characters is the maximum");

  let invoked = false;
  const getter = {};
  Object.defineProperty(getter, "retain", { enumerable: true, get() { invoked = true; return ["pii_global_iban"]; } });
  assert.throws(() => resolvePiiRetention(getter), isVaultError("INVALID_ARGUMENT"));
  assert.equal(invoked, false, "a getter must never be invoked");
});

test("resolvePiiSelection checks shape only and returns a frozen copy", () => {
  assert.equal(resolvePiiSelection(undefined), undefined);
  const input = ["pii", "not-a-real-selector"];
  const copy = resolvePiiSelection(input);
  assert.deepEqual(copy, input);
  assert.notEqual(copy, input);
  assert.ok(Object.isFrozen(copy));
  assert.deepEqual(resolvePiiSelection([]), []);
  for (const value of ["pii", [""], [7], ["x".repeat(129)], Array.from({ length: 65 }, () => "pii"), {}, null]) {
    assert.throws(() => resolvePiiSelection(value), isVaultError("INVALID_ARGUMENT"));
  }
});

// --- createVault: option shape (step 1) -------------------------------------

test("createVault rejects malformed pii / expectPiiActivation with INVALID_ARGUMENT before touching the core", async () => {
  for (const options of [
    { pii: "pii" },
    { pii: [""] },
    { pii: [1] },
    { pii: ["x".repeat(129)] },
    { pii: Array.from({ length: 65 }, () => "pii") },
    { expectPiiActivation: "" },
    { expectPiiActivation: 5 },
    { expectPiiActivation: "x".repeat(513) },
  ]) {
    const fake = createFakeCore();
    await assert.rejects(openVault(fake.module, options), isVaultError("INVALID_ARGUMENT"));
    assert.equal(fake.calls.initialize.length, 0);
    assert.equal(fake.calls.piiActivation, 0);
  }
});

// --- createVault on a beta.9-shaped core (steps 2-3) -------------------------

test("no PII surface: a non-empty pii or any expectPiiActivation fails PII_UNAVAILABLE before the core is called", async () => {
  for (const options of [{ pii: ["pii"] }, { expectPiiActivation: "credentials=full;selectors=off" }, { pii: [], expectPiiActivation: "x" }]) {
    const fake = createFakeCore({ pii: false });
    await assert.rejects(openVault(fake.module, options), isVaultError("PII_UNAVAILABLE"));
    assert.equal(fake.calls.initialize.length, 0);
  }
});

test("no PII surface: omitted pii and pii: [] both call plain initialize() and observe null", async () => {
  for (const options of [{}, { pii: [] }]) {
    const fake = createFakeCore({ pii: false });
    const vault = await openVault(fake.module, options);
    assert.deepEqual(fake.calls.initialize, [undefined], "plain initialize(), no options");
    assert.equal(vault.piiActivation, null);
    const result = vault.capture(`token ${GH}`, { release: RELEASE });
    assert.equal(result.tokens.length, 1);
    assert.throws(() => vault.capture("x", { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), isVaultError("PII_UNAVAILABLE"));
  }
});

// --- createVault on a PII-capable core (steps 4-6) ---------------------------

test("application initializes first, vault omits pii: adopts without calling any initializer", async () => {
  const fake = await piiRealm(["pii"]);
  const expected = fake.module.piiActivation();
  const vault = await openVault(fake.module);
  assert.equal(fake.calls.initialize.length, 0, "the vault must not call initialize when adopting");
  assert.equal(vault.piiActivation, expected);
  assert.match(vault.piiActivation, /selectors=pii:global;/);
});

test("application initializes first, vault passes an identical canonical selection: idempotent", async () => {
  const fake = await piiRealm(["pii"]);
  const expected = fake.module.piiActivation();
  const vault = await openVault(fake.module, { pii: ["pii:global"] });
  assert.deepEqual(fake.calls.initialize, [{ pii: ["pii:global"] }], "forwarded verbatim");
  assert.equal(vault.piiActivation, expected);
});

test("application initializes first, vault passes a different selection: CORE_FAILURE / PII_ACTIVATION_CONFLICT, realm unchanged", async () => {
  const fake = await piiRealm(["pii"]);
  const before = fake.module.piiActivation();
  await assert.rejects(openVault(fake.module, { pii: [] }), isVaultError("CORE_FAILURE", "PII_ACTIVATION_CONFLICT"));
  assert.equal(fake.module.piiActivation(), before, "the realm keeps the application's selection");
});

test("vault initializes first with the application's selection; the application's matching call then succeeds", async () => {
  const fake = createFakeCore();
  const vault = await openVault(fake.module, { pii: ["pii"] });
  assert.match(vault.piiActivation, /selectors=pii:global;/);
  await fake.module.initialize({ pii: ["pii"] });
  await assert.rejects(fake.module.initialize(), (e) => e.code === "PII_ACTIVATION_CONFLICT");
});

test("vault initializes first with pii: [] (explicit off): the realm is off and a later PII selection conflicts", async () => {
  const fake = createFakeCore();
  const vault = await openVault(fake.module, { pii: [] });
  assert.deepEqual(fake.calls.initialize, [{ pii: [] }]);
  assert.match(vault.piiActivation, /selectors=off;/);
  await assert.rejects(fake.module.initialize({ pii: ["pii"] }), (e) => e.code === "PII_ACTIVATION_CONFLICT");
});

test("pii omitted on an uninitialized PII-capable core: CORE_FAILURE / NOT_INITIALIZED and still no initializer call", async () => {
  const fake = createFakeCore();
  await assert.rejects(openVault(fake.module), isVaultError("CORE_FAILURE", "NOT_INITIALIZED"));
  assert.equal(fake.calls.initialize.length, 0);
  assert.throws(() => fake.module.piiActivation(), (e) => e.code === "NOT_INITIALIZED", "the core stays uninitialized");
});

test("selector errors surface as CORE_FAILURE with the core's code", async () => {
  await assert.rejects(openVault(createFakeCore().module, { pii: ["PII!"] }), isVaultError("CORE_FAILURE", "PII_SELECTOR_INVALID"));
  await assert.rejects(openVault(createFakeCore().module, { pii: ["pii:zz"] }), isVaultError("CORE_FAILURE", "PII_SELECTOR_UNSUPPORTED"));
});

test("expectPiiActivation: exact match succeeds, any difference fails PII_ACTIVATION_MISMATCH without echoing either identity", async () => {
  const fake = await piiRealm(["pii"]);
  const identity = fake.module.piiActivation();
  const vault = await openVault(fake.module, { expectPiiActivation: identity });
  assert.equal(vault.piiActivation, identity);
  let caught;
  await assert.rejects(
    openVault(fake.module, { expectPiiActivation: `${identity} ` }).catch((e) => {
      caught = e;
      throw e;
    }),
    isVaultError("PII_ACTIVATION_MISMATCH"),
  );
  assert.ok(!caught.message.includes("selectors"), "the error carries no identity");
  assert.deepEqual(Object.keys(caught).sort(), ["code", "coreCode", "name", "reason"]);
  assert.equal(caught.coreCode, undefined);
});

test("vault.piiActivation is read-only", async () => {
  const { vault } = await piiVault();
  const before = vault.piiActivation;
  assert.throws(() => {
    "use strict";
    vault.piiActivation = "credentials=full;selectors=off";
  }, TypeError);
  assert.equal(vault.piiActivation, before);
});

// --- capture: retention (§1) ------------------------------------------------

test("PII redact findings are not retained without an allowlist; non-PII findings are unchanged", async () => {
  const { vault } = await piiVault();
  const result = vault.capture(`token ${GH} iban ${IBAN} ssn ${SSN}`, { release: RELEASE });
  assert.deepEqual(result.tokens.map((t) => t.type), ["github_token"]);
  assert.equal(result.unrestorable, 2);
  assert.ok(!result.text.includes(IBAN) && !result.text.includes(SSN) && !result.text.includes(GH));
  assert.match(result.text, /<SECRET_\d+>/);
});

test("an allow-all eligible never retains PII, and eligible is not called for PII outside the allowlist", async () => {
  const { vault } = await piiVault();
  const seen = [];
  const result = vault.capture(`${GH} ${IBAN} ${SSN}`, {
    release: RELEASE,
    eligible: (finding) => {
      seen.push(finding.type);
      return true;
    },
    pii: { retain: ["pii_global_iban"] },
  });
  assert.deepEqual(seen, ["github_token", "pii_global_iban"], "not called for the non-allowlisted SSN");
  assert.deepEqual(result.tokens.map((t) => t.type).sort(), ["github_token", "pii_global_iban"]);
  assert.equal(result.unrestorable, 1);
});

test("eligible narrows the PII allowlist", async () => {
  const { vault } = await piiVault();
  const result = vault.capture(`${IBAN} ${SSN}`, {
    release: RELEASE,
    eligible: (finding) => finding.type !== "pii_global_iban",
    pii: { retain: ["pii_global_iban", "pii_jurisdiction_us_ssn"] },
  });
  assert.deepEqual(result.tokens.map((t) => t.type), ["pii_jurisdiction_us_ssn"]);
  assert.equal(result.unrestorable, 1);
});

test("an allowlisted PII type is retained and restorable under the usual grants and budget", async () => {
  const { vault } = await piiVault();
  const captured = vault.capture(`iban ${IBAN} end`, { release: RELEASE, pii: { retain: ["pii_global_iban"] } });
  assert.equal(captured.tokens.length, 1);
  assert.equal(captured.tokens[0].type, "pii_global_iban");
  assert.ok(!captured.text.includes(IBAN));
  const restored = vault.restore({ sink: "sink-a", captures: [captured.captureId], fields: { body: captured.text } });
  assert.equal(restored.fields.body, `iban ${IBAN} end`);
  // maxUses defaults to 1, exactly as for any other entry.
  assert.throws(
    () => vault.restore({ sink: "sink-a", captures: [captured.captureId], fields: { body: captured.text } }),
    isVaultError("RESTORE_DENIED"),
  );
});

test("an allowlist naming a different PII type does not retain this one", async () => {
  const { vault } = await piiVault();
  const result = vault.capture(IBAN, { release: RELEASE, pii: { retain: ["pii_jurisdiction_us_ssn"] } });
  assert.equal(result.tokens.length, 0);
  assert.equal(result.unrestorable, 1);
});

test("the displayFormatter marker-spoofing check still applies to non-retained PII", async () => {
  const { vault } = await piiVault();
  assert.throws(
    () => vault.capture(IBAN, { release: RELEASE, displayFormatter: () => "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" }),
    (e) => e instanceof VaultError && (e.code === "CORE_FAILURE" || e.code === "INVARIANT_VIOLATION"),
  );
  assert.equal(vault.stats().entries, 0);
});

test("malformed capture pii fails INVALID_ARGUMENT and retains nothing", async () => {
  const { vault } = await piiVault();
  for (const pii of [{ retain: [] }, { retain: ["pii_*"] }, { retain: ["pii_global_iban"], also: 1 }, ["pii_global_iban"], null]) {
    assert.throws(() => vault.capture(IBAN, { release: RELEASE, pii }), isVaultError("INVALID_ARGUMENT"));
  }
  assert.equal(vault.stats().entries, 0);
});

test("capture pii on a PII-off activation fails PII_UNAVAILABLE", async () => {
  const fake = createFakeCore();
  const vault = await openVault(fake.module, { pii: [] });
  assert.throws(() => vault.capture(GH, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), isVaultError("PII_UNAVAILABLE"));
  // Without the option, capture works as before.
  assert.equal(vault.capture(GH, { release: RELEASE }).tokens.length, 1);
});

// --- capture: unredacted semantics unchanged (§2) ---------------------------

test("warn-level PII rejects by default and passes through only when asked", async () => {
  const { vault } = await piiVault();
  assert.throws(() => vault.capture(`call ${PHONE}`, { release: RELEASE }), isVaultError("UNREDACTED_FINDINGS"));
  assert.throws(
    () => vault.capture(`call ${PHONE}`, { release: RELEASE, pii: { retain: ["pii_global_phone"] } }),
    isVaultError("UNREDACTED_FINDINGS"),
    "the allowlist never promotes warn to redact",
  );
  const passed = vault.capture(`call ${PHONE}`, { release: RELEASE, unredacted: "pass-through" });
  assert.equal(passed.passedThrough, 1);
  assert.deepEqual(passed.passedThroughTypes, ["pii_global_phone"]);
  assert.equal(passed.tokens.length, 0);
});

test("a policy mapping PII to redact replaces it; retention still needs the allowlist", async () => {
  const { vault } = await piiVault();
  const policy = { evaluate: () => "redact" };
  const replaced = vault.capture(`call ${PHONE}`, { release: RELEASE, policy });
  assert.equal(replaced.tokens.length, 0);
  assert.equal(replaced.unrestorable, 1);
  const retained = vault.capture(`call ${PHONE}`, { release: RELEASE, policy, pii: { retain: ["pii_global_phone"] } });
  assert.equal(retained.tokens.length, 1);
});

test("block still rejects the whole capture for PII", async () => {
  const { vault } = await piiVault();
  assert.throws(
    () => vault.capture(`${GH} ${IBAN}`, { release: RELEASE, policy: { evaluate: (f) => (f.type.startsWith("pii_") ? "block" : "redact") } }),
    isVaultError("BLOCKED_FINDING"),
  );
  assert.equal(vault.stats().entries, 0);
});

// --- the installed core (beta.9 in CI) -------------------------------------

test("installed core without a PII surface: createVault() and pii: [] observe piiActivation === null", { skip: BETA9_ONLY }, async () => {
  const a = await createVault();
  const b = await createVault({ pii: [] });
  assert.equal(a.piiActivation, null);
  assert.equal(b.piiActivation, null);
  const ra = a.capture(`token ${GH}`, { release: RELEASE });
  const rb = b.capture(`token ${GH}`, { release: RELEASE });
  assert.equal(ra.tokens.length, rb.tokens.length, "pii: [] equals omission");
  assert.equal(ra.unrestorable, rb.unrestorable);
});

test("installed core without a PII surface: every PII option fails PII_UNAVAILABLE", { skip: BETA9_ONLY }, async () => {
  await assert.rejects(createVault({ pii: ["pii"] }), isVaultError("PII_UNAVAILABLE"));
  await assert.rejects(createVault({ expectPiiActivation: "credentials=full;selectors=off" }), isVaultError("PII_UNAVAILABLE"));
  const vault = await createVault();
  assert.throws(() => vault.capture(`token ${GH}`, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), isVaultError("PII_UNAVAILABLE"));
  assert.equal(vault.stats().entries, 0);
});

test("installed core without a PII surface: malformed PII options still fail INVALID_ARGUMENT", { skip: BETA9_ONLY }, async () => {
  await assert.rejects(createVault({ pii: "pii" }), isVaultError("INVALID_ARGUMENT"));
  await assert.rejects(createVault({ expectPiiActivation: "" }), isVaultError("INVALID_ARGUMENT"));
  const vault = await createVault();
  assert.throws(() => vault.capture(GH, { release: RELEASE, pii: { retain: [] } }), isVaultError("INVALID_ARGUMENT"));
});
