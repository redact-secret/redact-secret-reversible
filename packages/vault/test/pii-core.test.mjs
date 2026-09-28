// PII-on behavior against the *real* installed @redact-secret/core
// (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md,
// "Verification before implementation is accepted").
//
// Requires a core with a PII surface (beta.10 or later). With a beta.9
// core every test here is skipped with a stated reason; the same contract
// is covered against a fake core in pii.test.mjs.
//
// PII activation is realm-global and one-shot, so each scenario runs in its
// own Node.js process. Scenarios import the packages by name, so this file
// runs unchanged in the repository and in a scratch consumer project that
// installs the packed vault next to a candidate core.
//
// Data is synthetic: the widely published documentation-example IBAN (the
// core detects it as `pii_global_iban`, High, `redact`) and the repository's
// revoked-looking GitHub token shape. Documentation-range emails
// (example.com), test card numbers, and 555-01xx phone numbers are treated
// as synthetic by the core and not detected, so they are not used here.
// PHONE is the core's own conformance value for a Medium-confidence
// (default `warn`) PII finding (conformance/fixtures/pii-phone-v1.json,
// `phone-sensitive-local-separated-medium-confidence`): a seven-digit local
// number with no area code, detected only after a label such as `telephone=`.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as core from "@redact-secret/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const SKIP = typeof core.piiActivation === "function"
  ? false
  : `installed @redact-secret/core ${core.VERSION} has no PII surface (no piiActivation export); PII-on tests need a beta.10+ core`;

const PRELUDE = `
import assert from "node:assert/strict";
import * as core from "@redact-secret/core";
import { createVault, VaultError } from "@redact-secret/vault";
const GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const IBAN = "DE89 3704 0044 0532 0130 00";
const GH2 = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111";
const PHONE = "555-2345";
const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
// A value-free error carries no fixture value anywhere it can be read.
function valueFree(e, ...values) {
  const surfaces = [String(e), String(e.message), String(e.stack), JSON.stringify(e), JSON.stringify(Object.entries(e))];
  for (const v of values) assert.ok(surfaces.every((s) => !s.includes(v)), "an error surface carries a fixture value");
}
async function rejectsWith(promise, code, coreCode) {
  try { await promise; } catch (e) {
    assert.ok(e instanceof VaultError, "expected a VaultError");
    assert.equal(e.code, code);
    if (coreCode !== undefined) assert.equal(e.coreCode, coreCode);
    return;
  }
  assert.fail("expected a rejection with " + code);
}
`;

/** Runs one scenario in a fresh process; the child asserts and exits non-zero on failure. */
function scenario(body) {
  try {
    execFileSync(process.execPath, ["--input-type=module", "-e", `${PRELUDE}\n${body}`], {
      cwd: HERE,
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8",
    });
  } catch (error) {
    // The child prints only assertion text (codes and booleans), never values.
    assert.fail(`scenario failed:\n${String(error.stderr).split("\n").slice(0, 12).join("\n")}`);
  }
}

test("real core: application initializes first; createVault() adopts without initializing", { skip: SKIP }, () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const identity = core.piiActivation();
    const vault = await createVault();
    assert.equal(vault.piiActivation, identity);
    assert.match(vault.piiActivation, /selectors=pii:global;/);
    // An identical canonical selection is idempotent; expectPiiActivation matches.
    const again = await createVault({ pii: ["pii:global"], expectPiiActivation: identity });
    assert.equal(again.piiActivation, identity);
  `);
});

test("real core: application first, vault passes a different selection -> CORE_FAILURE / PII_ACTIVATION_CONFLICT", { skip: SKIP }, () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const before = core.piiActivation();
    await rejectsWith(createVault({ pii: [] }), "CORE_FAILURE", "PII_ACTIVATION_CONFLICT");
    assert.equal(core.piiActivation(), before, "realm keeps the application's selection");
  `);
});

test("real core: vault initializes first with the application's selection; app's own calls agree or conflict", { skip: SKIP }, () => {
  scenario(`
    const vault = await createVault({ pii: ["pii"] });
    assert.equal(vault.piiActivation, core.piiActivation());
    await core.initialize({ pii: ["pii"] });
    let code;
    await core.initialize().catch((e) => { code = e.code; });
    assert.equal(code, "PII_ACTIVATION_CONFLICT");
  `);
});

test("real core: vault first with pii: [] locks PII off; a later PII selection conflicts", { skip: SKIP }, () => {
  scenario(`
    const vault = await createVault({ pii: [] });
    assert.match(vault.piiActivation, /selectors=off;/);
    let code;
    await core.initialize({ pii: ["pii"] }).catch((e) => { code = e.code; });
    assert.equal(code, "PII_ACTIVATION_CONFLICT");
    // Capture-time retention on an off activation fails closed.
    assert.throws(() => vault.capture(GH, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), (e) => e.code === "PII_UNAVAILABLE");
  `);
});

test("real core: pii omitted on an uninitialized core -> CORE_FAILURE / NOT_INITIALIZED, core left uninitialized", { skip: SKIP }, () => {
  scenario(`
    await rejectsWith(createVault(), "CORE_FAILURE", "NOT_INITIALIZED");
    let code;
    try { core.piiActivation(); } catch (e) { code = e.code; }
    assert.equal(code, "NOT_INITIALIZED", "the vault called no initializer");
    // The documented one-line migration works.
    const vault = await createVault({ pii: [] });
    assert.match(vault.piiActivation, /selectors=off;/);
  `);
});

test("real core: expectPiiActivation mismatch -> PII_ACTIVATION_MISMATCH", { skip: SKIP }, () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    await rejectsWith(createVault({ expectPiiActivation: "credentials=full;selectors=off;families=;vocabulary=pii-context/v1" }), "PII_ACTIVATION_MISMATCH");
  `);
});

test("real core: selector errors surface as CORE_FAILURE with the core's PII_SELECTOR_* code", { skip: SKIP }, () => {
  scenario(`
    let error;
    try { await createVault({ pii: ["pii:not a selector"] }); } catch (e) { error = e; }
    assert.ok(error instanceof VaultError);
    assert.equal(error.code, "CORE_FAILURE");
    assert.match(String(error.coreCode), /^PII_SELECTOR_/);
  `);
});

test("real core: PII not retained without the allowlist, allow-all eligible cannot widen, allowlisted PII restores", { skip: SKIP }, () => {
  scenario(`
    const vault = await createVault({ pii: ["pii"] });
    const input = "token " + GH + " iban " + IBAN + " end";

    const plain = vault.capture(input, { release: RELEASE });
    assert.deepEqual(plain.tokens.map((t) => t.type), ["github_token"]);
    assert.equal(plain.unrestorable, 1);
    assert.ok(!plain.text.includes(IBAN));

    const seen = [];
    const allowAll = vault.capture(input, { release: RELEASE, eligible: (f) => { seen.push(f.type); return true; } });
    assert.deepEqual(allowAll.tokens.map((t) => t.type), ["github_token"]);
    assert.ok(!seen.includes("pii_global_iban"), "eligible not called for non-allowlisted PII");

    const narrowed = vault.capture(input, { release: RELEASE, pii: { retain: ["pii_global_iban"] }, eligible: (f) => f.type !== "pii_global_iban" });
    assert.deepEqual(narrowed.tokens.map((t) => t.type), ["github_token"]);
    assert.equal(narrowed.unrestorable, 1);

    const kept = vault.capture(input, { release: RELEASE, pii: { retain: ["pii_global_iban"] } });
    assert.deepEqual(kept.tokens.map((t) => t.type).sort(), ["github_token", "pii_global_iban"]);
    assert.equal(kept.unrestorable, 0);
    assert.ok(!kept.text.includes(IBAN));
    const restored = vault.restore({ sink: "sink-a", captures: [kept.captureId], fields: { body: kept.text } });
    assert.ok(restored.fields.body === input, "restored text equals the original input");
  `);
});

// Core #887 (beta.10): redact() rejects a placeholder that reproduces the
// matched text of ANY finding in the input, including a sibling warn or allow
// finding the vault leaves as plaintext. A displayFormatter label that does
// so fails the whole capture as CORE_FAILURE / INVALID_PLACEHOLDER, value-free,
// with nothing committed (#43).
test("real core: a displayFormatter label reproducing a sibling warn/allow finding -> CORE_FAILURE / INVALID_PLACEHOLDER, nothing committed", { skip: SKIP }, () => {
  scenario(`
    const events = [];
    const vault = await createVault({ pii: ["pii"], onAudit: (e) => events.push(e) });
    const input = "token " + GH + " iban " + IBAN + " token " + GH2 + " end";
    for (const action of ["warn", "allow"]) {
      const policy = { evaluate: (f) => (f.type === "pii_global_iban" ? action : "redact") };
      // Retain the first github_token only; the second gets a display label.
      const options = (label) => {
        let calls = 0;
        return { release: RELEASE, policy, unredacted: "pass-through", eligible: () => ++calls === 1, displayFormatter: () => label };
      };
      const before = vault.stats();
      events.length = 0;
      let error;
      try { vault.capture(input, options(IBAN)); } catch (e) { error = e; }
      assert.ok(error instanceof VaultError, action + ": expected a VaultError");
      assert.equal(error.code, "CORE_FAILURE");
      assert.equal(error.coreCode, "INVALID_PLACEHOLDER");
      assert.equal(error.message, "The redaction core rejected the operation.");
      valueFree(error, IBAN, GH, GH2);
      assert.deepEqual(vault.stats(), before, action + ": the failed capture committed something");
      assert.equal(events.length, 1);
      assert.deepEqual({ ...events[0], at: 0 }, { operation: "capture", outcome: "failed", at: 0, code: "CORE_FAILURE" });

      // Control: the same capture with a label that reproduces no finding commits.
      const ok = vault.capture(input, options("[hidden]"));
      assert.deepEqual(ok.tokens.map((t) => t.type), ["github_token"]);
      assert.equal(ok.unrestorable, 1);
      assert.deepEqual(ok.passedThroughTypes, ["pii_global_iban"]);
      assert.ok(ok.text.includes("iban " + IBAN) && ok.text.includes("[hidden]"));
      assert.equal(vault.stats().entries, before.entries + 1);
    }
  `);
});

// A Medium-confidence PII finding gets the core's default action warn (no
// policy): the vault's unredacted gate applies to it like any warn finding,
// and pii.retain (which governs redact findings only) does not retain it.
test("real core: default-confidence warn PII (Medium pii_global_phone) x unredacted reject / pass-through", { skip: SKIP }, () => {
  scenario(`
    const vault = await createVault({ pii: ["pii"] });
    const input = "telephone=" + PHONE + " token " + GH;
    // Guard: the core still rates this input Medium / warn by default.
    assert.deepEqual(core.scan(input).map((f) => [f.type, f.confidence, f.action]), [["pii_global_phone", "medium", "warn"], ["github_token", "high", "redact"]]);

    let error;
    try { vault.capture(input, { release: RELEASE }); } catch (e) { error = e; }
    assert.ok(error instanceof VaultError);
    assert.equal(error.code, "UNREDACTED_FINDINGS");
    valueFree(error, PHONE, GH);
    assert.equal(vault.stats().entries, 0);
    assert.equal(vault.stats().captures, 0);

    for (const extra of [{}, { pii: { retain: ["pii_global_phone"] } }]) {
      const passed = vault.capture(input, { release: RELEASE, unredacted: "pass-through", ...extra });
      assert.equal(passed.passedThrough, 1);
      assert.deepEqual(passed.passedThroughTypes, ["pii_global_phone"]);
      assert.deepEqual(passed.tokens.map((t) => t.type), ["github_token"]);
      assert.equal(passed.unrestorable, 0);
      assert.ok(passed.text.includes("telephone=" + PHONE) && !passed.text.includes(GH));
    }
  `);
});

// The main-thread contract Worker mode's Worker-script policy reuses (#59): a
// policy escalating default-warn PII to redact replaces it (non-restorable
// unless allowlisted); a policy that throws or returns an unknown action fails
// the capture as CORE_FAILURE with the core's fixed code, value-free, with
// nothing committed.
test("real core: policy escalation of warn PII, and a throwing / invalid-action policy -> CORE_FAILURE, nothing committed", { skip: SKIP }, () => {
  scenario(`
    const events = [];
    const vault = await createVault({ pii: ["pii"], onAudit: (e) => events.push(e) });
    const input = "telephone=" + PHONE + " token " + GH;
    const escalate = { evaluate: (f) => (f.type === "pii_global_phone" ? "redact" : f.confidence === "high" ? "redact" : "warn") };
    const escalated = vault.capture(input, { release: RELEASE, policy: escalate });
    assert.equal(escalated.passedThrough, 0);
    assert.equal(escalated.unrestorable, 1);
    assert.deepEqual(escalated.tokens.map((t) => t.type), ["github_token"]);
    assert.ok(!escalated.text.includes(PHONE));
    const kept = vault.capture(input, { release: RELEASE, policy: escalate, pii: { retain: ["pii_global_phone"] } });
    assert.deepEqual(kept.tokens.map((t) => t.type).sort(), ["github_token", "pii_global_phone"]);

    for (const [policy, coreCode] of [
      [{ evaluate() { throw new Error("policy failure " + PHONE); } }, "POLICY_FAILURE"],
      [{ evaluate: () => undefined }, "POLICY_FAILURE"],
      [{ evaluate: () => "escalate" }, "INVALID_POLICY_ACTION"],
    ]) {
      const before = vault.stats();
      events.length = 0;
      let error;
      try { vault.capture(input, { release: RELEASE, policy }); } catch (e) { error = e; }
      assert.ok(error instanceof VaultError, coreCode);
      assert.equal(error.code, "CORE_FAILURE");
      assert.equal(error.coreCode, coreCode);
      assert.equal(error.message, "The redaction core rejected the operation.");
      valueFree(error, PHONE, GH);
      assert.deepEqual(vault.stats(), before, coreCode + ": the failed capture committed something");
      assert.deepEqual(events.map((e) => ({ ...e, at: 0 })), [{ operation: "capture", outcome: "failed", at: 0, code: "CORE_FAILURE" }]);
    }
  `);
});

// PII findings count toward maxFindings (passed to the core as its limit);
// exceeding it is the core's FINDING_LIMIT_EXCEEDED, surfaced as CORE_FAILURE,
// whether the PII finding would be retained, replaced, or passed through.
test("real core: PII findings count toward maxFindings -> CORE_FAILURE / FINDING_LIMIT_EXCEEDED, nothing committed", { skip: SKIP }, () => {
  scenario(`
    const vault = await createVault({ pii: ["pii"], limits: { maxFindings: 2 } });
    const two = "iban " + IBAN + "; iban " + IBAN;
    const kept = vault.capture(two, { release: RELEASE, pii: { retain: ["pii_global_iban"] } });
    assert.equal(kept.tokens.length, 2, "exactly maxFindings PII findings are accepted");
    const before = vault.stats();
    for (const [input, options] of [
      [two + "; iban " + IBAN, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }],
      [two + "; iban " + IBAN, { release: RELEASE }],
      ["telephone=" + PHONE + "; iban " + IBAN + "; token " + GH, { release: RELEASE, unredacted: "pass-through" }],
    ]) {
      let error;
      try { vault.capture(input, options); } catch (e) { error = e; }
      assert.ok(error instanceof VaultError);
      assert.equal(error.code, "CORE_FAILURE");
      assert.equal(error.coreCode, "FINDING_LIMIT_EXCEEDED");
      valueFree(error, IBAN, PHONE, GH);
      assert.deepEqual(vault.stats(), before);
    }
  `);
});
