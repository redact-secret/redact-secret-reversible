// The capture plan (docs/specs/persistent-vault.md §8.1): the part of a
// capture that runs before anything is retained, shared by the in-memory
// vault and a persistent server. A plan holds the redacted text and, for each
// retained finding, the token, the type, and the range in the input. It never
// holds a value.
//
// Runs against the built package (dist/). Most tests use the fake core
// (./fake-core.mjs), which models both a PII-capable core and a beta.9-shaped
// one; the last ones use the installed @redact-secret/core through
// `openCapturePlanner` and `createVault`.
//
// All data is synthetic: FAKEPII-… markers, revoked-looking GitHub token
// shapes, and forged `<rsv_…>` strings that nothing issued.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import * as plan from "../dist/capture-plan.js";
import { VaultError } from "../dist/errors.js";
import * as root from "../dist/index.js";
import { createVault, openVault } from "../dist/vault.js";
import { createFakeCore } from "./fake-core.mjs";

const {
  newPlannedCaptureId,
  openCapturePlanner,
  openCapturePlannerFor,
  planCapture,
  resolveCaptureLimits,
} = plan;

const GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const IBAN = "FAKEPII-IBAN-0001";
const SSN = "FAKEPII-SSN-0002";
const PHONE = "FAKEPII-PHONE-0003";
const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
const TOKEN = /<rsv_[a-z2-7]{26}>/g;
const CAPTURE_ID = /^cap_[a-z2-7]{26}$/;
const FORGED = `<rsv_${"a".repeat(26)}>`;
const NOTHING_HELD = { liveEntries: 0, retainedBytes: 0 };

/** A distinct synthetic, revoked-looking GitHub token the fake core detects. */
function gh(i) {
  return `ghp_SYNTHETICxREVOKEDxTESTx${String(i).padStart(13, "0")}`;
}

function isVaultError(code, coreCode) {
  return (error) => {
    assert.ok(error instanceof VaultError, `expected VaultError, got ${error?.name}`);
    assert.equal(error.code, code);
    if (coreCode !== undefined) assert.equal(error.coreCode, coreCode);
    return true;
  };
}

/** A policy that gives every finding of `type` the fixed `action`. */
function policy(actions) {
  return { evaluate: (finding) => actions[finding.type] ?? "redact" };
}

async function plainCore() {
  const fake = createFakeCore({ pii: false });
  await fake.module.initialize();
  return fake.module;
}

async function piiCore() {
  const fake = createFakeCore();
  await fake.module.initialize({ pii: ["pii"] });
  return fake.module;
}

/** `planCapture` with default limits unless overridden, nothing held unless given. */
function planWith(core, input, options = {}, { piiActive = false, limits = {}, budget = NOTHING_HELD } = {}) {
  return planCapture(core, piiActive, input, { release: RELEASE, ...options }, resolveCaptureLimits(limits), budget);
}

// --- shape -----------------------------------------------------------------

test("ranges slice to the original values and the text holds each token exactly once", async () => {
  const core = await plainCore();
  const values = [gh(1), gh(2), gh(3)];
  const input = `first ${values[0]}\nsecond ${values[1]} third ${values[2]} end`;
  const made = planWith(core, input);

  assert.equal(made.retained.length, 3);
  assert.deepEqual(made.retained.map((entry) => input.slice(entry.start, entry.end)), values);
  assert.deepEqual(made.retained.map((entry) => entry.type), ["github_token", "github_token", "github_token"]);
  assert.equal(new Set(made.retained.map((entry) => entry.token)).size, 3);
  for (const entry of made.retained) {
    assert.match(entry.token, /^<rsv_[a-z2-7]{26}>$/);
    assert.equal(made.text.split(entry.token).length - 1, 1, "token appears exactly once");
  }
  assert.deepEqual(made.text.match(TOKEN), made.retained.map((entry) => entry.token), "tokens are in input order");
  for (const value of values) assert.ok(!made.text.includes(value));
  assert.equal(made.passedThrough, 0);
  assert.deepEqual(made.passedThroughTypes, []);
  assert.equal(made.unrestorable, 0);
});

test("a plan holds no value, and is frozen throughout", async () => {
  const core = await plainCore();
  const input = `alpha ${gh(7)} beta ${gh(8)}`;
  const made = planWith(core, input, { maxUses: 3 });

  const serialized = JSON.stringify(made);
  assert.ok(!serialized.includes(gh(7)) && !serialized.includes(gh(8)));
  assert.ok(!serialized.includes("SYNTHETICxREVOKED"), "no fragment of a value either");
  assert.deepEqual(Object.keys(made).sort(), ["grants", "maxUses", "passedThrough", "passedThroughTypes", "retained", "text", "unrestorable"]);
  for (const entry of made.retained) {
    assert.deepEqual(Object.keys(entry).sort(), ["end", "start", "token", "type"]);
    assert.ok(Object.isFrozen(entry));
  }
  assert.ok(Object.isFrozen(made) && Object.isFrozen(made.retained) && Object.isFrozen(made.passedThroughTypes));
  assert.ok(Object.isFrozen(made.grants) && made.grants.every((g) => Object.isFrozen(g) && Object.isFrozen(g.paths)));
});

test("grants are deduplicated per sink and maxUses is the effective value", async () => {
  const core = await plainCore();
  const release = [
    { sink: "sink-a", paths: ["body", "body", "subject"] },
    { sink: "sink-b", paths: ["note"] },
    { sink: "sink-a", paths: ["subject", "footer"] },
  ];
  const made = planWith(core, `x ${GH}`, { release });
  assert.deepEqual(made.grants, [
    { sink: "sink-a", paths: ["body", "subject", "footer"] },
    { sink: "sink-b", paths: ["note"] },
  ]);
  assert.equal(made.maxUses, 1, "default");
  assert.equal(planWith(core, `x ${GH}`, { maxUses: 5 }).maxUses, 5);
});

test("capture identifiers come from the module, with the documented grammar", () => {
  const ids = new Set();
  for (let i = 0; i < 64; i += 1) {
    const id = newPlannedCaptureId();
    assert.match(id, CAPTURE_ID);
    ids.add(id);
  }
  assert.equal(ids.size, 64);
  assert.equal(planCapture.length, 6, "no parameter for a random source");
  assert.equal(newPlannedCaptureId.length, 0);
});

// --- argument validation ---------------------------------------------------

test("invalid arguments fail INVALID_ARGUMENT before the core runs", async () => {
  const core = await plainCore();
  let scans = 0;
  const counting = { ...core, scan: (...args) => { scans += 1; return core.scan(...args); } };
  const bad = [
    { release: [] },
    { release: [{ sink: "", paths: ["body"] }] },
    { release: [{ sink: "sink-a", paths: [] }] },
    { maxUses: 0 },
    { maxUses: 17 },
    { unredacted: "ignore" },
    { eligible: "yes" },
    { displayFormatter: "label" },
    { pii: { retain: [] } },
    { pii: { retain: ["github_token"] } },
  ];
  for (const options of bad) {
    assert.throws(() => planWith(counting, `x ${GH}`, options), isVaultError("INVALID_ARGUMENT"), JSON.stringify(options));
  }
  assert.throws(() => planCapture(counting, false, 42, { release: RELEASE }, resolveCaptureLimits(), NOTHING_HELD), isVaultError("INVALID_ARGUMENT"));
  assert.throws(() => planCapture(counting, false, GH, null, resolveCaptureLimits(), NOTHING_HELD), isVaultError("INVALID_ARGUMENT"));
  for (const budget of [null, {}, { liveEntries: -1, retainedBytes: 0 }, { liveEntries: 0, retainedBytes: 1.5 }]) {
    assert.throws(() => planWith(counting, `x ${GH}`, {}, { budget }), isVaultError("INVALID_ARGUMENT"));
  }
  assert.equal(scans, 0);
});

test("a PII allowlist on a core without active PII fails PII_UNAVAILABLE", async () => {
  const core = await plainCore();
  assert.throws(
    () => planWith(core, `x ${GH}`, { pii: { retain: ["pii_global_iban"] } }, { piiActive: false }),
    isVaultError("PII_UNAVAILABLE"),
  );
});

// --- the action gate -------------------------------------------------------

test("a block finding rejects the whole capture", async () => {
  const core = await plainCore();
  assert.throws(
    () => planWith(core, `x ${GH}`, { policy: policy({ github_token: "block" }), unredacted: "pass-through" }),
    isVaultError("BLOCKED_FINDING"),
  );
});

test("warn and allow findings reject by default and pass through on request", async () => {
  const core = await piiCore();
  const input = `call ${PHONE} about ${gh(1)} and ${gh(2)}`;
  for (const action of ["warn", "allow"]) {
    const options = { policy: policy({ pii_global_phone: action }) };
    assert.throws(() => planWith(core, input, options, { piiActive: true }), isVaultError("UNREDACTED_FINDINGS"));
    assert.throws(
      () => planWith(core, input, { ...options, unredacted: "reject" }, { piiActive: true }),
      isVaultError("UNREDACTED_FINDINGS"),
    );
    const made = planWith(core, input, { ...options, unredacted: "pass-through" }, { piiActive: true });
    assert.equal(made.passedThrough, 1);
    assert.deepEqual(made.passedThroughTypes, ["pii_global_phone"]);
    assert.equal(made.retained.length, 2);
    assert.ok(made.text.includes(PHONE), "a passed-through finding stays in the text");
  }
});

test("passedThroughTypes is sorted and deduplicated", async () => {
  const core = await piiCore();
  const input = `${PHONE} ${gh(1)} ${IBAN} ${gh(2)}`;
  const made = planWith(
    core,
    input,
    { policy: policy({ pii_global_phone: "warn", pii_global_iban: "allow", github_token: "warn" }), unredacted: "pass-through" },
    { piiActive: true },
  );
  assert.equal(made.passedThrough, 4);
  assert.deepEqual(made.passedThroughTypes, ["github_token", "pii_global_iban", "pii_global_phone"]);
  assert.equal(made.retained.length, 0);
  assert.equal(made.text, input);
});

// --- PII allowlist and `eligible` ------------------------------------------

test("PII findings are retained only for exact allowlisted types", async () => {
  const core = await piiCore();
  const input = `iban ${IBAN} ssn ${SSN} key ${GH}`;

  const off = planWith(core, input, {}, { piiActive: true });
  assert.deepEqual(off.retained.map((entry) => entry.type), ["github_token"]);
  assert.equal(off.unrestorable, 2);
  assert.ok(!off.text.includes(IBAN) && !off.text.includes(SSN), "an unretained PII finding is still redacted");

  const on = planWith(core, input, { pii: { retain: ["pii_global_iban"] } }, { piiActive: true });
  assert.deepEqual(on.retained.map((entry) => entry.type), ["pii_global_iban", "github_token"]);
  assert.deepEqual(on.retained.map((entry) => input.slice(entry.start, entry.end)), [IBAN, GH]);
  assert.equal(on.unrestorable, 1);
  assert.ok(!JSON.stringify(on).includes(IBAN) && !JSON.stringify(on).includes(SSN));
});

test("eligible narrows what is retained and cannot widen the PII allowlist", async () => {
  const core = await piiCore();
  const input = `iban ${IBAN} key ${gh(1)} key ${gh(2)}`;
  const seen = [];
  const made = planWith(
    core,
    input,
    { eligible: (finding) => { seen.push(finding.type); return finding.start > input.indexOf(gh(1)); } },
    { piiActive: true },
  );
  assert.deepEqual(seen, ["github_token", "github_token"], "eligible is not consulted for an unlisted PII finding");
  assert.deepEqual(made.retained.map((entry) => input.slice(entry.start, entry.end)), [gh(2)]);
  assert.equal(made.unrestorable, 2);
  assert.ok(!made.text.includes(gh(1)), "an ineligible finding is still redacted");
  assert.equal(made.text.match(TOKEN).length, 1);

  assert.equal(planWith(core, input, { eligible: () => "true" }, { piiActive: true }).retained.length, 0, "only a literal true keeps");
  assert.throws(
    () => planWith(core, input, { eligible: () => { throw new Error("synthetic failure"); } }, { piiActive: true }),
    isVaultError("INVALID_ARGUMENT"),
  );
});

// --- limits ----------------------------------------------------------------

test("maxEntries counts what the caller already holds", async () => {
  const core = await plainCore();
  const input = `${gh(1)} ${gh(2)}`;
  const limits = { maxEntries: 4 };
  assert.equal(planWith(core, input, {}, { limits, budget: { liveEntries: 2, retainedBytes: 0 } }).retained.length, 2);
  assert.throws(
    () => planWith(core, input, {}, { limits, budget: { liveEntries: 3, retainedBytes: 0 } }),
    isVaultError("LIMIT_EXCEEDED"),
  );
  assert.throws(() => planWith(core, `${input} ${gh(3)}`, {}, { limits: { maxEntries: 2 } }), isVaultError("LIMIT_EXCEEDED"));
});

test("maxValueBytes bounds each retained value", async () => {
  const core = await plainCore();
  assert.equal(planWith(core, `x ${GH}`, {}, { limits: { maxValueBytes: GH.length } }).retained.length, 1);
  assert.throws(
    () => planWith(core, `x ${GH}`, {}, { limits: { maxValueBytes: GH.length - 1 } }),
    isVaultError("LIMIT_EXCEEDED"),
  );
});

test("maxRetainedBytes counts what the caller already holds", async () => {
  const core = await plainCore();
  const input = `${gh(1)} ${gh(2)}`;
  const limits = { maxRetainedBytes: 2 * GH.length + 10 };
  assert.equal(planWith(core, input, {}, { limits, budget: { liveEntries: 0, retainedBytes: 10 } }).retained.length, 2);
  assert.throws(
    () => planWith(core, input, {}, { limits, budget: { liveEntries: 0, retainedBytes: 11 } }),
    isVaultError("LIMIT_EXCEEDED"),
  );
});

test("maxInputBytes is measured in UTF-8 bytes, before the core runs", async () => {
  const core = await plainCore();
  let scans = 0;
  const counting = { ...core, scan: (...args) => { scans += 1; return core.scan(...args); } };
  // Four UTF-16 units, eight UTF-8 bytes.
  const wide = "\u{1F512}\u{1F512}";
  assert.throws(() => planWith(counting, wide, {}, { limits: { maxInputBytes: 7 } }), isVaultError("LIMIT_EXCEEDED"));
  assert.equal(scans, 0);
  assert.equal(planWith(counting, wide, {}, { limits: { maxInputBytes: 8 } }).text, wide);
});

test("resolveCaptureLimits applies defaults, and rejects unknown keys and values over a ceiling", () => {
  const defaults = resolveCaptureLimits();
  assert.deepEqual(defaults, plan.DEFAULT_LIMITS);
  assert.ok(Object.isFrozen(defaults));
  assert.equal(resolveCaptureLimits({ maxEntries: 8 }).maxEntries, 8);
  assert.equal(resolveCaptureLimits({ maxEntries: undefined }).maxEntries, plan.DEFAULT_LIMITS.maxEntries);
  for (const partial of [null, 5, { maxEntries: 0 }, { maxEntries: 1.5 }, { unknownLimit: 1 }, { maxEntries: plan.LIMIT_CEILINGS.maxEntries + 1 }]) {
    assert.throws(() => resolveCaptureLimits(partial), isVaultError("INVALID_ARGUMENT"));
  }
  assert.equal(root.DEFAULT_LIMITS, plan.DEFAULT_LIMITS, "one limits table, not a copy");
  assert.equal(root.LIMIT_CEILINGS, plan.LIMIT_CEILINGS);
});

// --- token provenance ------------------------------------------------------

test("a token-like literal in the input is refused", async () => {
  const core = await plainCore();
  for (const literal of [FORGED, "rsv_", "RSV_", "r​sv_"]) {
    assert.throws(() => planWith(core, `x ${GH} ${literal}`), isVaultError("TOKEN_LITERAL_IN_INPUT"));
  }
});

test("a displayFormatter that returns a token-like label fails the capture", async () => {
  const core = await plainCore();
  const input = `${gh(1)} ${gh(2)}`;
  const first = (finding) => finding.start === 0;
  for (const label of [FORGED, "rsv_x", 7]) {
    assert.throws(
      () => planWith(core, input, { eligible: first, displayFormatter: () => label }),
      isVaultError("CORE_FAILURE", "PLACEHOLDER_FAILURE"),
    );
  }
  const made = planWith(core, input, { eligible: first, displayFormatter: () => "[hidden]" });
  assert.equal(made.retained.length, 1);
  assert.equal(made.text, `${made.retained[0].token} [hidden]`);
});

test("an output that does not hold exactly the issued tokens fails INVARIANT_VIOLATION", async () => {
  const core = await plainCore();
  const tampered = (tamper) => ({ ...core, redact: (...args) => tamper(core.redact(...args)) });
  assert.throws(() => planWith(tampered((text) => `${text} ${FORGED}`), `x ${GH}`), isVaultError("INVARIANT_VIOLATION"));
  assert.throws(() => planWith(tampered((text) => `${text} ${text}`), `x ${GH}`), isVaultError("INVARIANT_VIOLATION"));
  assert.throws(() => planWith(tampered((text) => text.replace(TOKEN, "")), `x ${GH}`), isVaultError("INVARIANT_VIOLATION"));
});

// --- the planner factory ---------------------------------------------------

test("a planner on a beta.9-shaped core has PII off and plans with nothing held", async () => {
  const fake = createFakeCore({ pii: false });
  const planner = await openCapturePlannerFor(fake.module);
  assert.equal(planner.piiActivation, null);
  assert.ok(Object.isFrozen(planner));
  assert.deepEqual(Object.keys(planner).sort(), ["newCaptureId", "piiActivation", "plan"]);
  assert.deepEqual(fake.calls.initialize, [undefined], "initialized the core once, as openVault does");

  const input = `x ${gh(1)} y ${gh(2)}`;
  const limits = resolveCaptureLimits({ maxEntries: 2 });
  const made = planner.plan(input, { release: RELEASE }, limits);
  assert.deepEqual(made.retained.map((entry) => input.slice(entry.start, entry.end)), [gh(1), gh(2)]);
  assert.ok(Object.isFrozen(made));
  // Nothing is held between plans: the same limit admits the same input again.
  assert.equal(planner.plan(input, { release: RELEASE }, limits).retained.length, 2);
  assert.throws(
    () => planner.plan(input, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }, limits),
    isVaultError("PII_UNAVAILABLE"),
  );
  assert.match(planner.newCaptureId(), CAPTURE_ID);
  assert.notEqual(planner.newCaptureId(), planner.newCaptureId());

  await assert.rejects(openCapturePlannerFor(createFakeCore({ pii: false }).module, { pii: ["pii"] }), isVaultError("PII_UNAVAILABLE"));
  await assert.rejects(openCapturePlannerFor(fake.module, null), isVaultError("INVALID_ARGUMENT"));
});

test("a planner with PII on retains allowlisted PII types and reports the vault's activation", async () => {
  const fake = createFakeCore();
  const planner = await openCapturePlannerFor(fake.module, { pii: ["pii"] });
  const vault = await openVault(fake.module);
  assert.equal(planner.piiActivation, vault.piiActivation);
  assert.match(planner.piiActivation, /selectors=pii:global/);

  const input = `iban ${IBAN} ssn ${SSN} key ${GH}`;
  const limits = resolveCaptureLimits();
  assert.deepEqual(planner.plan(input, { release: RELEASE }, limits).retained.map((entry) => entry.type), ["github_token"]);
  const made = planner.plan(input, { release: RELEASE, pii: { retain: ["pii_global_iban", "pii_jurisdiction_us_ssn"] } }, limits);
  assert.deepEqual(made.retained.map((entry) => input.slice(entry.start, entry.end)), [IBAN, SSN, GH]);
  assert.equal(made.unrestorable, 0);
  vault.dispose();
});

test("a planner checks the expected activation and surfaces core activation failures", async () => {
  const fake = createFakeCore();
  await fake.module.initialize({ pii: ["pii"] });
  const identity = fake.module.piiActivation();
  assert.equal((await openCapturePlannerFor(fake.module, { expectPiiActivation: identity })).piiActivation, identity);
  await assert.rejects(
    openCapturePlannerFor(fake.module, { expectPiiActivation: `${identity} ` }),
    isVaultError("PII_ACTIVATION_MISMATCH"),
  );
  await assert.rejects(openCapturePlannerFor(fake.module, { pii: [] }), isVaultError("CORE_FAILURE", "PII_ACTIVATION_CONFLICT"));
  await assert.rejects(openCapturePlannerFor(createFakeCore().module), isVaultError("CORE_FAILURE", "NOT_INITIALIZED"));
  await assert.rejects(openCapturePlannerFor(fake.module, { pii: "pii" }), isVaultError("INVALID_ARGUMENT"));
});

test("a planner cannot be opened without a CSPRNG", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  if (!descriptor?.configurable) return;
  const fake = createFakeCore({ pii: false });
  Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
  try {
    await assert.rejects(openCapturePlannerFor(fake.module), isVaultError("UNSUPPORTED_RUNTIME"));
    assert.deepEqual(fake.calls.initialize, [], "checked before the core is touched");
  } finally {
    Object.defineProperty(globalThis, "crypto", descriptor);
  }
});

// --- equivalence with the vault --------------------------------------------

/** What a capture and a plan of the same input must agree on. */
function shapeOf(text, retainedTypes, counts) {
  return {
    tokens: (text.match(TOKEN) ?? []).length,
    skeleton: text.replace(TOKEN, "<rsv>"),
    retainedTypes,
    passedThrough: counts.passedThrough,
    passedThroughTypes: [...counts.passedThroughTypes],
    unrestorable: counts.unrestorable,
  };
}

const EQUIVALENCE_CASES = [
  { name: "no finding", input: "nothing to see here", options: {} },
  { name: "one credential", input: `key ${GH}`, options: {} },
  { name: "several credentials", input: `${gh(1)}\n${gh(2)} mid ${gh(3)}`, options: { maxUses: 2 } },
  { name: "unlisted PII", input: `iban ${IBAN} key ${GH}`, options: {} },
  { name: "allowlisted PII", input: `iban ${IBAN} ssn ${SSN} key ${GH}`, options: { pii: { retain: ["pii_global_iban"] } } },
  { name: "pass-through", input: `call ${PHONE} key ${GH}`, options: { unredacted: "pass-through" } },
  { name: "eligible", input: `${gh(1)} ${gh(2)}`, options: { eligible: (finding) => finding.start === 0, displayFormatter: () => "[hidden]" } },
];

test("the vault and a plan of the same input agree on the output shape", async () => {
  const fake = createFakeCore();
  const planner = await openCapturePlannerFor(fake.module, { pii: ["pii"] });
  const vault = await openVault(fake.module);
  const limits = resolveCaptureLimits();
  for (const { name, input, options } of EQUIVALENCE_CASES) {
    const full = { release: RELEASE, ...options };
    const captured = vault.capture(input, full);
    const made = planner.plan(input, full, limits);
    assert.deepEqual(
      shapeOf(made.text, made.retained.map((entry) => entry.type), made),
      shapeOf(captured.text, captured.tokens.map((entry) => entry.type), captured),
      name,
    );
    assert.equal(made.retained.length, captured.tokens.length, name);
    // The vault restores exactly what the plan's ranges name.
    if (captured.tokens.length > 0) {
      const restored = vault.restore({
        sink: "sink-a",
        captures: [captured.captureId],
        fields: { body: captured.tokens.map((entry) => entry.token).join("\n") },
      });
      assert.equal(restored.fields.body, made.retained.map((entry) => input.slice(entry.start, entry.end)).join("\n"), name);
    }
  }
  vault.dispose();
});

test("the vault and a plan fail the same way", async () => {
  const fake = createFakeCore();
  const planner = await openCapturePlannerFor(fake.module, { pii: ["pii"] });
  const limits = resolveCaptureLimits({ maxEntries: 2, maxValueBytes: 64 });
  const vault = await openVault(fake.module, { limits: { maxEntries: 2, maxValueBytes: 64 } });
  const cases = [
    [`x ${GH}`, { release: [] }, "INVALID_ARGUMENT"],
    [`x ${GH} ${FORGED}`, { release: RELEASE }, "TOKEN_LITERAL_IN_INPUT"],
    [`x ${GH}`, { release: RELEASE, policy: policy({ github_token: "block" }) }, "BLOCKED_FINDING"],
    [`call ${PHONE}`, { release: RELEASE }, "UNREDACTED_FINDINGS"],
    [`${gh(1)} ${gh(2)} ${gh(3)}`, { release: RELEASE }, "LIMIT_EXCEEDED"],
    // Order of checks: argument validation precedes the token-literal check,
    // which precedes the action gate, which precedes the limits.
    [`x ${GH} ${FORGED}`, { release: [] }, "INVALID_ARGUMENT"],
    [`${gh(1)} ${gh(2)} ${gh(3)} ${PHONE}`, { release: RELEASE }, "UNREDACTED_FINDINGS"],
  ];
  for (const [input, options, code] of cases) {
    assert.throws(() => vault.capture(input, options), isVaultError(code), `vault: ${code}`);
    assert.throws(() => planner.plan(input, options, limits), isVaultError(code), `plan: ${code}`);
  }
  assert.equal(vault.stats().entries, 0);
  vault.dispose();
});

test("the installed core: openCapturePlanner and createVault agree", async () => {
  const hasPii = typeof (await import("@redact-secret/core")).piiActivation === "function";
  // On a core with a PII surface, `pii: []` is the explicit "PII off"
  // selection, which createVault() then adopts. On beta.9 it equals omission.
  const planner = await openCapturePlanner({ pii: [] });
  const vault = await createVault();
  assert.equal(planner.piiActivation, vault.piiActivation);
  if (hasPii) {
    await assert.rejects(
      openCapturePlanner({ expectPiiActivation: `${planner.piiActivation};synthetic-mismatch` }),
      isVaultError("PII_ACTIVATION_MISMATCH"),
    );
    assert.equal((await openCapturePlanner({ expectPiiActivation: planner.piiActivation })).piiActivation, planner.piiActivation);
  } else {
    assert.equal(planner.piiActivation, null);
    await assert.rejects(openCapturePlanner({ expectPiiActivation: "synthetic-identity" }), isVaultError("PII_UNAVAILABLE"));
  }

  const limits = resolveCaptureLimits();
  const options = { release: RELEASE, unredacted: "pass-through" };
  for (const input of ["nothing to see here", `token ${GH} in a sentence`, `${gh(11)}\n${gh(12)}`]) {
    const captured = vault.capture(input, options);
    const made = planner.plan(input, options, limits);
    assert.deepEqual(
      shapeOf(made.text, made.retained.map((entry) => entry.type), made),
      shapeOf(captured.text, captured.tokens.map((entry) => entry.type), captured),
    );
    assert.ok(!JSON.stringify(made).includes("SYNTHETICxREVOKED"));
    for (const entry of made.retained) assert.ok(input.slice(entry.start, entry.end).length > 0);
  }
  vault.dispose();
});

// --- export surface --------------------------------------------------------

test("the package root does not export the plan, and the subpath is node-only", () => {
  assert.deepEqual(Object.keys(root).sort(), ["DEFAULT_LIMITS", "LIMIT_CEILINGS", "VaultError", "createVault"]);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.deepEqual(pkg.exports["./internal/capture-plan"], {
    node: { types: "./dist/capture-plan.d.ts", import: "./dist/capture-plan.js" },
  });
});
