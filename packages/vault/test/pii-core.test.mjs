// PII-on behavior against the *real* installed @redact-secret/core
// (docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md,
// "Verification before implementation is accepted").
//
// Requires a core with a PII surface (beta.10 or later). With the pinned
// beta.9 every test here is skipped with a stated reason; the same contract
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
// (example.com), test card numbers, and 555 phone numbers are treated as
// synthetic by the core and not detected, so they are not used here.
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
const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
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
