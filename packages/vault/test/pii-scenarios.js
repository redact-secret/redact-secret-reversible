/**
 * Portable PII activation and retention scenarios for @redact-secret/vault
 * against a PII-capable core (beta.10+).
 *
 * Contract: docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md.
 * Core PII activation is realm-global and one-shot, so every scenario needs
 * its own fresh realm whose core nobody has initialized yet: a fresh Node.js
 * process (qualification/node.mjs) or a fresh page (qualification/browser.mjs).
 * The host runner calls `runPiiScenario(name, ...)` exactly once per realm.
 *
 * Like suite.js, this never prints a fixture value: failures name the check
 * and a fixed error code only. Data is synthetic: the corpus's revoked-looking
 * GitHub token shape and the widely published documentation-example IBAN,
 * which beta.10 detects as `pii_global_iban` (High, `redact`) only next to a
 * field label.
 */

/** The PII selection every PII-on qualification lane uses. */
export const PII_SELECTION = Object.freeze(["pii"]);

const RELEASE = [{ sink: "reply", paths: ["body"] }];
const MISMATCH = "credentials=full;selectors=qualification-mismatch;families=;vocabulary=pii-context/v1";

class AssertionFailure extends Error {}

function assert(condition, message) {
  if (!condition) throw new AssertionFailure(message);
}

function selectorsOf(identity) {
  return String(identity).split(";").find((part) => part.startsWith("selectors=")) ?? "";
}

async function rejection(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return undefined;
}

function throwing(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

function expectVaultError(V, error, code, coreCode, what) {
  assert(error !== undefined, `${what}: expected ${code}, operation succeeded`);
  assert(error instanceof V.VaultError, `${what}: expected a VaultError`);
  assert(error.code === code, `${what}: expected ${code}, got ${error.code}`);
  if (coreCode !== undefined) assert(error.coreCode === coreCode, `${what}: expected core ${coreCode}, got ${error.coreCode}`);
}

function input(F) {
  return `iban ${F.IBAN} token ${F.GH}`;
}

export const piiScenarios = {
  // ADR §3 step 5: the application initializes first; createVault() without
  // `pii` adopts, calls no initializer, and reports the realm's identity.
  async "order:application-first-vault-adopts"(V, C) {
    await C.initialize({ pii: [...PII_SELECTION] });
    const identity = C.piiActivation();
    assert(selectorsOf(identity) === "selectors=pii:global", "activation identity is not pii:global");
    const vault = await V.createVault();
    assert(vault.piiActivation === identity, "vault.piiActivation differs from the realm's identity");
    const same = await V.createVault({ pii: ["pii:global"], expectPiiActivation: identity });
    assert(same.piiActivation === identity, "an equivalent canonical selection was not idempotent");
    vault.dispose();
    same.dispose();
  },

  // ADR §3 step 4: application first, the vault passes a different selection.
  async "order:application-first-vault-conflicts"(V, C) {
    await C.initialize({ pii: [...PII_SELECTION] });
    const before = C.piiActivation();
    expectVaultError(V, await rejection(V.createVault({ pii: [] })), "CORE_FAILURE", "PII_ACTIVATION_CONFLICT", "createVault({ pii: [] })");
    assert(C.piiActivation() === before, "the vault changed the realm's activation");
  },

  // ADR §3 step 4: the vault initializes first with the application's
  // selection; the application's identical call agrees, a different one conflicts.
  async "order:vault-first-application-conflicts"(V, C) {
    const vault = await V.createVault({ pii: [...PII_SELECTION] });
    assert(vault.piiActivation === C.piiActivation(), "vault.piiActivation differs from the realm's identity");
    assert(selectorsOf(vault.piiActivation) === "selectors=pii:global", "activation identity is not pii:global");
    await C.initialize({ pii: [...PII_SELECTION] });
    const error = await rejection(C.initialize());
    assert(error?.code === "PII_ACTIVATION_CONFLICT", `plain initialize() after a PII selection: ${error?.code ?? "succeeded"}`);
    vault.dispose();
  },

  // `pii: []` locks the realm off; a later PII selection conflicts, and a
  // capture that asks for PII retention fails closed with PII_UNAVAILABLE.
  async "order:vault-first-off-then-retention-unavailable"(V, C, F) {
    const vault = await V.createVault({ pii: [] });
    assert(selectorsOf(vault.piiActivation) === "selectors=off", "pii: [] did not report selectors=off");
    const error = await rejection(C.initialize({ pii: [...PII_SELECTION] }));
    assert(error?.code === "PII_ACTIVATION_CONFLICT", `PII selection after pii: []: ${error?.code ?? "succeeded"}`);
    expectVaultError(V, throwing(() => vault.capture(input(F), { release: RELEASE, pii: { retain: ["pii_global_iban"] } })), "PII_UNAVAILABLE", undefined, "capture pii.retain with selectors=off");
    assert(vault.stats().entries === 0, "a refused capture left a mapping");
    vault.dispose();
  },

  // ADR §3 step 5: `pii` omitted on an uninitialized core -> NOT_INITIALIZED,
  // and the vault still calls no initializer.
  async "activation:omitted-and-uninitialized-is-not-initialized"(V, C) {
    expectVaultError(V, await rejection(V.createVault()), "CORE_FAILURE", "NOT_INITIALIZED", "createVault() on an uninitialized core");
    const error = throwing(() => C.piiActivation());
    assert(error?.code === "NOT_INITIALIZED", "the vault initialized the core although pii was omitted");
    const vault = await V.createVault({ pii: [] });
    assert(selectorsOf(vault.piiActivation) === "selectors=off", "the documented pii: [] migration did not work");
    vault.dispose();
  },

  // ADR §3 step 6.
  async "activation:expectation-mismatch-rejects"(V, C) {
    await C.initialize({ pii: [...PII_SELECTION] });
    expectVaultError(V, await rejection(V.createVault({ expectPiiActivation: MISMATCH })), "PII_ACTIVATION_MISMATCH", undefined, "createVault({ expectPiiActivation })");
  },

  // Selector grammar is the core's; the vault surfaces it as CORE_FAILURE.
  async "activation:selector-error-surfaces-core-code"(V) {
    const error = await rejection(V.createVault({ pii: ["pii:not a selector"] }));
    expectVaultError(V, error, "CORE_FAILURE", undefined, "createVault with an invalid selector");
    assert(/^PII_SELECTOR_/.test(String(error.coreCode)), `selector error core code ${error.coreCode}`);
  },

  // ADR §1 and §2 on a PII-on realm: not retained by default, allow-all
  // `eligible` cannot widen, the allowlist retains and restores, `eligible`
  // narrows it, and a warn PII finding is gated by `unredacted`.
  async "retention:default-allowlist-narrowing-and-warn-gate"(V, C, F) {
    const vault = await V.createVault({ pii: [...PII_SELECTION] });
    const text = input(F);

    const plain = vault.capture(text, { release: RELEASE });
    assert(JSON.stringify(plain.tokens.map((t) => t.type)) === '["github_token"]', "PII retained by default");
    assert(plain.unrestorable === 1, `default unrestorable ${plain.unrestorable}`);
    assert(!plain.text.includes(F.IBAN), "PII left in the output by default");

    const seen = [];
    const allowAll = vault.capture(text, { release: RELEASE, eligible: (f) => { seen.push(f.type); return true; } });
    assert(allowAll.tokens.length === 1 && allowAll.unrestorable === 1, "allow-all eligible widened PII retention");
    assert(!seen.includes("pii_global_iban"), "eligible was called for a non-allowlisted PII finding");

    const narrowed = vault.capture(text, { release: RELEASE, pii: { retain: ["pii_global_iban"] }, eligible: (f) => f.type !== "pii_global_iban" });
    assert(narrowed.tokens.length === 1 && narrowed.unrestorable === 1, "eligible did not narrow the PII allowlist");

    const kept = vault.capture(text, { release: RELEASE, pii: { retain: ["pii_global_iban"] } });
    assert(JSON.stringify(kept.tokens.map((t) => t.type)) === '["pii_global_iban","github_token"]', "allowlisted PII not retained");
    assert(kept.unrestorable === 0 && !kept.text.includes(F.IBAN), "allowlisted capture output");
    const restored = vault.restore({ sink: "reply", captures: [kept.captureId], fields: { body: kept.text } });
    assert(restored.fields.body === text && restored.restored === 2, "allowlisted PII did not restore");

    const warnPolicy = { evaluate: (f) => (f.type === "pii_global_iban" ? "warn" : "redact") };
    expectVaultError(V, throwing(() => vault.capture(text, { release: RELEASE, policy: warnPolicy })), "UNREDACTED_FINDINGS", undefined, "warn PII under unredacted: reject");
    const passed = vault.capture(text, { release: RELEASE, policy: warnPolicy, unredacted: "pass-through" });
    assert(passed.passedThrough === 1 && JSON.stringify(passed.passedThroughTypes) === '["pii_global_iban"]', "warn PII pass-through not reported");
    vault.dispose();
  },
};

/** Runs one scenario and returns `{ id, ok, message? }`; never throws. */
export async function runPiiScenario(name, { vault: V, core: C, fixtures }) {
  const id = `pii-scenario:${name}`;
  const scenario = piiScenarios[name];
  if (scenario === undefined) return { id, ok: false, message: "unknown scenario" };
  try {
    await scenario(V, C, fixtures);
    return { id, ok: true };
  } catch (error) {
    if (error instanceof AssertionFailure) return { id, ok: false, message: error.message };
    const code = error && typeof error === "object" && typeof error.code === "string" ? error.code : "non-vault exception";
    return { id, ok: false, message: `unexpected error ${code}` };
  }
}
