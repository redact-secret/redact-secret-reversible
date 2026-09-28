/**
 * Portable qualification suite for @redact-secret/vault.
 *
 * Runs unchanged in Node.js and in a real browser. It receives the installed
 * package modules and the conformance corpus from its host runner, executes
 * every corpus case plus runtime-level adversarial checks, and returns a
 * plain JSON report. It never prints a fixture value: failures describe the
 * mismatch by field name and sanitized code only.
 */

export async function runSuite({ vault: V, core: C, corpus }) {
  const results = [];
  const fixtures = corpus.fixtures;
  const secrets = Object.values(fixtures);
  const observed = { errors: [], audit: [], console: [] };

  // The realm's core PII activation, fixed by the host runner before this
  // suite starts: "on" (selectors active), "off" (selectors=off), or "none"
  // (a core without a PII surface). Corpus cases that name a `piiActivation`
  // run only under that activation and are reported as skipped otherwise.
  const piiActivation = observedPiiActivation(C);

  const restoreConsole = trapConsole(observed.console);
  try {
    for (const testCase of corpus.cases) {
      if (testCase.piiActivation !== undefined && testCase.piiActivation !== piiActivation) {
        results.push({ id: `corpus:${testCase.id}`, ok: true, skipped: `needs PII activation ${testCase.piiActivation}, realm is ${piiActivation}` });
        continue;
      }
      results.push(await record(`corpus:${testCase.id}`, () => runCase(V, C, testCase, fixtures, observed)));
    }
    for (const [name, check] of Object.entries(runtimeChecks)) {
      results.push(await record(`runtime:${name}`, () => check(V, C, fixtures, observed)));
    }
  } finally {
    restoreConsole();
  }

  // Leakage: no fixture value in any error, audit event, or console output.
  results.push(
    await record("leakage:no-plaintext-in-errors-audit-console", () => {
      const haystacks = [
        ...observed.errors.map(serializeError),
        ...observed.audit.map((event) => JSON.stringify(event)),
        ...observed.console,
      ];
      const tokenLike = /rsv_[a-z2-7]{26}/;
      for (const text of haystacks) {
        for (const secret of secrets) assert(!text.includes(secret), "fixture value leaked into diagnostics");
        assert(!tokenLike.test(text), "issued token leaked into diagnostics");
      }
      assert(observed.errors.length > 20, "too few errors observed for a meaningful leakage check");
      assert(observed.audit.length > 20, "too few audit events observed for a meaningful leakage check");
      assert(observed.console.length === 0, "the vault wrote to the console");
    }),
  );

  return {
    corpus: `${corpus.corpus}@${corpus.version}`,
    coreVersion: C.VERSION,
    artifact: C.artifact(),
    piiActivation,
    passed: results.filter((r) => r.ok && !r.skipped).length,
    failed: results.filter((r) => !r.ok).length,
    skipped: results.filter((r) => r.skipped).length,
    results,
    probes: await coreProbes(C, fixtures),
  };
}

function observedPiiActivation(C) {
  if (typeof C.piiActivation !== "function") return "none";
  const identity = C.piiActivation();
  const field = identity.split(";").find((part) => part.startsWith("selectors="));
  return field === undefined || field === "selectors=off" || field === "selectors=" ? "off" : "on";
}

async function record(id, body) {
  try {
    await body();
    return { id, ok: true };
  } catch (error) {
    return { id, ok: false, message: error instanceof AssertionFailure ? error.message : safeDescribe(error) };
  }
}

class AssertionFailure extends Error {}

function assert(condition, message) {
  if (!condition) throw new AssertionFailure(message);
}

function safeDescribe(error) {
  if (error && typeof error === "object" && typeof error.code === "string") return `unexpected error code ${error.code}`;
  return "unexpected non-vault exception";
}

function serializeError(error) {
  return [String(error), error?.stack ?? "", JSON.stringify(error), JSON.stringify(Object.getOwnPropertyNames(error ?? {}).map((k) => [k, String(error[k])]))].join("\n");
}

function trapConsole(sink) {
  const methods = ["log", "info", "warn", "error", "debug", "trace"];
  const original = methods.map((m) => console[m]);
  for (const m of methods) console[m] = (...args) => sink.push(args.map(String).join(" "));
  return () => methods.forEach((m, i) => (console[m] = original[i]));
}

function makePolicy(spec) {
  if (spec === undefined) return undefined;
  return { evaluate: (finding) => spec[finding.type] ?? spec.default ?? "redact" };
}

function makeReleasePolicy(spec) {
  if (spec === undefined) return undefined;
  if (spec.throw) return () => { throw new Error(`policy failure ${JSON.stringify(spec)}`); };
  if ("returns" in spec) return () => spec.returns;
  return (request) => !(spec.denyTypes ?? []).includes(request.type);
}

function expand(template, fixtures, captures) {
  return template.replace(/\{([A-Za-z0-9_]+)(?:\.([a-z0-9]+))?(?::([a-z]+))?\}|\{repeat:(.):(\d+)\}/g, (whole, name, index, transform, ch, n) => {
    if (ch !== undefined) return ch.repeat(Number(n));
    if (index === undefined) {
      if (!(name in fixtures)) throw new AssertionFailure(`unknown fixture ${name}`);
      return fixtures[name];
    }
    const capture = captures.get(name);
    if (capture === undefined) throw new AssertionFailure(`unknown capture ${name}`);
    let value = index === "text" ? capture.text : capture.tokens[Number(index)]?.token;
    if (value === undefined) throw new AssertionFailure(`capture ${name} has no ${index}`);
    if (transform === "upper") value = value.toUpperCase();
    if (transform === "truncate") value = value.slice(0, -3) + ">";
    if (transform === "space") value = "< " + value.slice(1);
    if (transform === "zwsp") value = value.slice(0, 2) + "\u200b" + value.slice(2);
    return value;
  });
}

async function runCase(V, C, testCase, fixtures, observed) {
  let clock = 0;
  const vaults = new Map();
  const captures = new Map();
  const where = (i) => `${testCase.id} step ${i}`;
  const onAudit = (event) => observed.audit.push(event);

  for (const [i, step] of testCase.steps.entries()) {
    const vault = vaults.get(step.vault ?? "A");
    const expect = step.expect ?? {};
    const attempt = (fn) => {
      try {
        return { value: fn() };
      } catch (error) {
        observed.errors.push(error);
        assert(error instanceof V.VaultError, `${where(i)}: non-VaultError thrown`);
        return { error };
      }
    };
    const expectError = (outcome) => {
      if (expect.error === undefined) {
        assert(outcome.error === undefined, `${where(i)}: unexpected ${outcome.error?.code}/${outcome.error?.reason}`);
        return false;
      }
      assert(outcome.error !== undefined, `${where(i)}: expected ${expect.error}, operation succeeded`);
      assert(outcome.error.code === expect.error, `${where(i)}: expected ${expect.error}, got ${outcome.error.code}`);
      if (expect.reason) assert(outcome.error.reason === expect.reason, `${where(i)}: expected reason ${expect.reason}, got ${outcome.error.reason}`);
      if (expect.coreCode) assert(outcome.error.coreCode === expect.coreCode, `${where(i)}: expected core ${expect.coreCode}, got ${outcome.error.coreCode}`);
      return true;
    };

    switch (step.op) {
      case "vault": {
        let outcome;
        try {
          outcome = {
            value: await V.createVault({
              ...(step.limits ? { limits: step.limits } : {}),
              ...(step.releasePolicy ? { releasePolicy: makeReleasePolicy(step.releasePolicy) } : {}),
              ...(step.pii !== undefined ? { pii: step.pii } : {}),
              ...(step.expectPiiActivation !== undefined ? { expectPiiActivation: step.expectPiiActivation } : {}),
              onAudit,
              now: () => clock,
            }),
          };
        } catch (error) {
          observed.errors.push(error);
          assert(error instanceof V.VaultError, `${where(i)}: non-VaultError thrown`);
          outcome = { error };
        }
        if (expectError(outcome)) break;
        vaults.set(step.id ?? "A", outcome.value);
        break;
      }
      case "capture": {
        const { policy, eligibleTypes, ...rest } = step.options;
        const options = {
          ...rest,
          ...(policy ? { policy: makePolicy(policy) } : {}),
          ...(eligibleTypes ? { eligible: (f) => eligibleTypes.includes(f.type) } : {}),
        };
        const outcome = attempt(() => vault.capture(expand(step.input, fixtures, captures), options));
        if (expectError(outcome)) break;
        const result = outcome.value;
        if (step.as) captures.set(step.as, { ...result, vault: step.vault ?? "A" });
        if (expect.tokens !== undefined) assert(result.tokens.length === expect.tokens, `${where(i)}: expected ${expect.tokens} tokens, got ${result.tokens.length}`);
        if (expect.types) assert(JSON.stringify(result.tokens.map((t) => t.type)) === JSON.stringify(expect.types), `${where(i)}: token types differ`);
        if (expect.passedThrough !== undefined) assert(result.passedThrough === expect.passedThrough, `${where(i)}: passedThrough ${result.passedThrough}`);
        if (expect.passedThroughTypes) assert(JSON.stringify(result.passedThroughTypes) === JSON.stringify(expect.passedThroughTypes), `${where(i)}: passedThroughTypes differ`);
        if (expect.unrestorable !== undefined) assert(result.unrestorable === expect.unrestorable, `${where(i)}: unrestorable ${result.unrestorable}`);
        if (expect.expiresAt !== undefined) assert(result.expiresAt === expect.expiresAt, `${where(i)}: expiresAt ${result.expiresAt}`);
        if (expect.text !== undefined) assert(result.text === expand(expect.text, fixtures, captures), `${where(i)}: text differs`);
        for (const t of expect.textIncludes ?? []) assert(result.text.includes(expand(t, fixtures, captures)), `${where(i)}: text lacks an expected span`);
        for (const t of expect.textExcludes ?? []) assert(!result.text.includes(expand(t, fixtures, captures)), `${where(i)}: text still contains a redacted value`);
        if (expect.distinctTokens) assert(new Set(result.tokens.map((t) => t.token)).size === result.tokens.length, `${where(i)}: tokens not distinct`);
        for (const t of result.tokens) assert(/^<rsv_[a-z2-7]{26}>$/.test(t.token), `${where(i)}: token grammar`);
        assert(Object.isFrozen(result) && Object.isFrozen(result.tokens), `${where(i)}: result not frozen`);
        break;
      }
      case "restore": {
        const fields = Object.fromEntries(Object.entries(step.fields).map(([k, v]) => [k, expand(v, fixtures, captures)]));
        const vaultName = step.vault ?? "A";
        const ids = step.captures
          ? step.captures.map((n) => captures.get(n)?.captureId ?? "cap_unknown")
          : [...captures.values()].filter((c) => c.vault === vaultName).map((c) => c.captureId);
        const outcome = attempt(() => vault.restore({ sink: step.sink, captures: ids, fields }));
        if (expectError(outcome)) break;
        const result = outcome.value;
        for (const [path, text] of Object.entries(expect.fields ?? {})) {
          assert(result.fields[path] === expand(text, fixtures, captures), `${where(i)}: field ${path} differs`);
        }
        assert(JSON.stringify(Object.keys(result.fields)) === JSON.stringify(Object.keys(fields)), `${where(i)}: field set differs`);
        if (expect.restored !== undefined) assert(result.restored === expect.restored, `${where(i)}: restored ${result.restored}`);
        break;
      }
      case "revoke": {
        const id = captures.get(step.capture)?.captureId ?? "cap_unknown";
        const outcome = attempt(() => vault.revoke(id));
        if (expectError(outcome)) break;
        if (expect.removed !== undefined) assert(outcome.value === expect.removed, `${where(i)}: removed ${outcome.value}`);
        break;
      }
      case "advance":
        clock += step.ms;
        break;
      case "dispose":
        vault.dispose();
        break;
      case "stats": {
        const stats = vault.stats();
        for (const [key, value] of Object.entries(expect)) assert(stats[key] === value, `${where(i)}: stats.${key} = ${stats[key]}, expected ${value}`);
        break;
      }
      default:
        throw new AssertionFailure(`${where(i)}: unknown op ${step.op}`);
    }
  }
  for (const vault of vaults.values()) vault.dispose();
}

const RELEASE = [{ sink: "reply", paths: ["body"] }];

function expectVaultError(V, observed, fn, code, extra = {}) {
  try {
    fn();
  } catch (error) {
    observed.errors.push(error);
    assert(error instanceof V.VaultError, `expected VaultError ${code}`);
    assert(error.code === code, `expected ${code}, got ${error.code}`);
    for (const [k, v] of Object.entries(extra)) assert(error[k] === v, `expected ${k}=${v}, got ${error[k]}`);
    return error;
  }
  throw new AssertionFailure(`expected ${code}, operation succeeded`);
}

async function withPatchedRandom(replacement, body) {
  const target = globalThis.crypto;
  const own = Object.getOwnPropertyDescriptor(target, "getRandomValues");
  Object.defineProperty(target, "getRandomValues", { value: replacement, configurable: true, writable: true });
  try {
    return await body();
  } finally {
    if (own) Object.defineProperty(target, "getRandomValues", own);
    else delete target.getRandomValues;
  }
}

const runtimeChecks = {
  async "module-surface-has-no-capture-side-effects"(V) {
    const names = Object.keys(V).sort();
    assert(JSON.stringify(names) === JSON.stringify(["DEFAULT_LIMITS", "LIMIT_CEILINGS", "VaultError", "createVault"]), `unexpected exports ${names}`);
    assert(Object.isFrozen(V.DEFAULT_LIMITS) && Object.isFrozen(V.LIMIT_CEILINGS), "limits not frozen");
    assert(!("restore" in V) && !("restoreText" in V), "a module-level restore shortcut exists");
  },

  // ADR 2026-09-27 PII retention and activation ownership, §4: on a core
  // without a PII surface (a beta.9 core) every PII option fails closed
  // before the core is called, `pii: []` equals omission, and the observed
  // activation is null. On a PII-capable core the host runner owns
  // activation, so only the identity type is checked here.
  async "pii-options-fail-closed-without-pii-surface"(V, C, F, observed) {
    if (typeof C.piiActivation === "function") {
      const vault = await V.createVault();
      assert(typeof vault.piiActivation === "string", "a PII-capable core must report an identity");
      vault.dispose();
      return;
    }
    const plain = await V.createVault();
    const empty = await V.createVault({ pii: [] });
    assert(plain.piiActivation === null && empty.piiActivation === null, "piiActivation must be null without a PII surface");
    assert(plain.capture(F.GH, { release: RELEASE }).tokens.length === empty.capture(F.GH, { release: RELEASE }).tokens.length, "pii: [] must equal omission");
    for (const options of [{ pii: ["pii"] }, { expectPiiActivation: "credentials=full;selectors=off" }]) {
      let error;
      try {
        await V.createVault(options);
      } catch (thrown) {
        error = thrown;
        observed.errors.push(thrown);
      }
      assert(error instanceof V.VaultError && error.code === "PII_UNAVAILABLE", `expected PII_UNAVAILABLE, got ${error?.code}`);
    }
    expectVaultError(V, observed, () => plain.capture(F.GH, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), "PII_UNAVAILABLE");
    expectVaultError(V, observed, () => plain.capture(F.GH, { release: RELEASE, pii: { retain: [] } }), "INVALID_ARGUMENT");
    plain.dispose();
    empty.dispose();
  },

  async "vault-exposes-no-bulk-export"(V, C, F) {
    const vault = await V.createVault();
    vault.capture(`${F.GH}`, { release: RELEASE });
    const surface = new Set();
    for (let o = vault; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) Object.getOwnPropertyNames(o).forEach((n) => surface.add(n));
    surface.delete("constructor");
    assert(JSON.stringify([...surface].sort()) === JSON.stringify(["capture", "dispose", "piiActivation", "restore", "revoke", "stats"]), `unexpected vault surface ${[...surface]}`);
    const serialized = JSON.stringify(vault) + String(vault) + JSON.stringify(vault.stats());
    assert(!serialized.includes(F.GH), "serializing the vault exposed a value");
    vault.dispose();
  },

  async "invalid-configuration-rejected"(V, C, F, observed) {
    for (const limits of [{ maxEntries: 0 }, { maxEntries: 1.5 }, { entryTtlMs: 25 * 3600 * 1000 }, { unknownLimit: 1 }, { maxRetainedBytes: -1 }]) {
      try {
        await V.createVault({ limits });
        throw new AssertionFailure("invalid limits accepted");
      } catch (error) {
        if (error instanceof AssertionFailure) throw error;
        observed.errors.push(error);
        assert(error.code === "INVALID_ARGUMENT", `limits rejected with ${error.code}`);
      }
    }
  },

  async "revoke-and-restore-race-in-microtasks"(V, C, F) {
    const vault = await V.createVault();
    const a = vault.capture(`${F.GH}`, { release: RELEASE });
    const b = vault.capture(`${F.AWS}`, { release: RELEASE });
    const order = [];
    await Promise.all([
      Promise.resolve().then(() => order.push(["revoke-a", vault.revoke(a.captureId)])),
      Promise.resolve().then(() => {
        try { vault.restore({ sink: "reply", captures: [a.captureId], fields: { body: a.tokens[0].token } }); order.push(["restore-a", "ok"]); } catch (e) { order.push(["restore-a", e.reason]); }
      }),
      Promise.resolve().then(() => {
        try { vault.restore({ sink: "reply", captures: [b.captureId], fields: { body: b.tokens[0].token } }); order.push(["restore-b", "ok"]); } catch (e) { order.push(["restore-b", e.reason]); }
      }),
      Promise.resolve().then(() => order.push(["revoke-b", vault.revoke(b.captureId)])),
    ]);
    assert(JSON.stringify(order) === JSON.stringify([["revoke-a", 1], ["restore-a", "unknown-token"], ["restore-b", "ok"], ["revoke-b", 0]]), `race order ${JSON.stringify(order)}`);
    vault.dispose();
  },

  async "reentrant-policy-cannot-mutate-mid-restore"(V, C, F, observed) {
    let vault;
    let reentry;
    vault = await V.createVault({
      releasePolicy: () => {
        try { vault.revoke(capture.captureId); } catch (e) { reentry = e.code; }
        try { vault.dispose(); } catch (e) { reentry += "," + e.code; }
        return true;
      },
    });
    const capture = vault.capture(`${F.GH}`, { release: RELEASE });
    const result = vault.restore({ sink: "reply", captures: [capture.captureId], fields: { body: capture.tokens[0].token } });
    assert(result.fields.body === F.GH, "restore failed");
    assert(reentry === "BUSY,BUSY", `re-entry outcome ${reentry}`);
    assert(!vault.stats().disposed, "reentrant dispose took effect");
    vault.dispose();
  },

  async "reentrant-core-policy-fails-capture"(V, C, F, observed) {
    let vault;
    vault = await V.createVault();
    expectVaultError(V, observed, () => vault.capture(F.GH, { release: RELEASE, policy: { evaluate: () => { vault.dispose(); return "redact"; } } }), "CORE_FAILURE", { coreCode: "POLICY_FAILURE" });
    assert(!vault.stats().disposed && vault.stats().entries === 0, "reentrant policy mutated state");
    vault.dispose();
  },

  async "audit-hook-failure-and-reentry-do-not-change-outcome"(V, C, F) {
    let vault;
    vault = await V.createVault({ onAudit: () => { vault.dispose(); throw new Error(`hook ${F.GH}`); } });
    const capture = vault.capture(F.GH, { release: RELEASE });
    assert(vault.stats().entries === 1 && !vault.stats().disposed, "audit hook changed the outcome");
    const restored = vault.restore({ sink: "reply", captures: [capture.captureId], fields: { body: capture.tokens[0].token } });
    assert(restored.fields.body === F.GH, "restore failed");
    vault.dispose();
  },

  async "display-formatter-failure-commits-nothing"(V, C, F, observed) {
    const vault = await V.createVault();
    let calls = 0;
    const eligible = (f) => f.type === "github_token";
    expectVaultError(V, observed, () => vault.capture(`${F.GH} ${F.AWS} ${F.GH2} ${F.JWT}`, {
      release: RELEASE, eligible, displayFormatter: () => { calls += 1; if (calls === 2) throw new Error(`boom ${F.AWS}`); return "<HIDDEN>"; },
    }), "CORE_FAILURE", { coreCode: "PLACEHOLDER_FAILURE" });
    assert(calls === 2, `formatter calls ${calls}`);
    expectVaultError(V, observed, () => vault.capture(`${F.GH} ${F.AWS}`, { release: RELEASE, eligible, displayFormatter: () => "" }), "CORE_FAILURE", { coreCode: "INVALID_PLACEHOLDER" });
    expectVaultError(V, observed, () => vault.capture(`${F.GH} ${F.AWS}`, { release: RELEASE, eligible, displayFormatter: () => "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" }), "CORE_FAILURE", { coreCode: "PLACEHOLDER_FAILURE" });
    expectVaultError(V, observed, () => vault.capture(`${F.GH} ${F.AWS}`, { release: RELEASE, eligible: () => { throw new Error(F.GH); } }), "INVALID_ARGUMENT");
    const stats = vault.stats();
    assert(stats.entries === 0 && stats.captures === 0 && stats.retainedBytes === 0, "a failed capture left a mapping");
    vault.dispose();
  },

  async "random-source-failure-and-collision"(V, C, F, observed) {
    await withPatchedRandom(() => { throw new Error("rng unavailable"); }, async () => {
      const vault = await V.createVault();
      expectVaultError(V, observed, () => vault.capture(F.GH, { release: RELEASE }), "TOKEN_GENERATION_FAILED");
      assert(vault.stats().entries === 0, "mapping after RNG failure");
      vault.dispose();
    });
    await withPatchedRandom((bytes) => bytes.fill(7), async () => {
      const vault = await V.createVault();
      expectVaultError(V, observed, () => vault.capture(`${F.GH} ${F.AWS}`, { release: RELEASE }), "TOKEN_GENERATION_FAILED");
      assert(vault.stats().entries === 0, "mapping after token collision");
      vault.dispose();
    });
    const saved = globalThis.crypto;
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    if (descriptor?.configurable) {
      Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
      try {
        await V.createVault().then(() => { throw new AssertionFailure("vault created without CSPRNG"); }, (e) => {
          observed.errors.push(e);
          assert(e.code === "UNSUPPORTED_RUNTIME", `no-crypto outcome ${e.code}`);
        });
      } finally {
        Object.defineProperty(globalThis, "crypto", descriptor);
      }
      assert(globalThis.crypto === saved, "crypto not restored");
    }
  },

  async "tokens-unpredictable-and-unique-at-volume"(V, C, F) {
    const vault = await V.createVault({ limits: { maxEntries: 2000, maxRetainedBytes: 200_000, maxFindings: 2000, maxInputBytes: 200_000 } });
    const input = Array.from({ length: 1000 }, () => F.AWS).join(" ");
    const { tokens } = vault.capture(input, { release: RELEASE });
    const bodies = tokens.map((t) => t.token.slice(5, -1));
    assert(new Set(bodies).size === 1000, "duplicate token issued");
    const counts = new Map();
    for (const b of bodies) for (const ch of b.slice(0, 25)) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    assert(counts.size === 32, "token alphabet not fully used");
    const expected = 25_000 / 32;
    for (const n of counts.values()) assert(Math.abs(n - expected) < expected * 0.25, "token characters visibly biased");
    vault.dispose();
  },

  async "restore-request-snapshot-resists-getters"(V, C, F, observed) {
    const vault = await V.createVault();
    const capture = vault.capture(F.GH, { release: RELEASE });
    let touched = false;
    const fields = {};
    Object.defineProperty(fields, "body", { enumerable: true, get() { touched = true; return capture.tokens[0].token; } });
    expectVaultError(V, observed, () => vault.restore({ sink: "reply", captures: [capture.captureId], fields }), "RESTORE_DENIED", { reason: "invalid-request" });
    assert(!touched, "getter executed");
    expectVaultError(V, observed, () => vault.restore({ sink: "reply", captures: [capture.captureId], fields: [capture.tokens[0].token] }), "INVALID_ARGUMENT");
    expectVaultError(V, observed, () => vault.restore({ sink: "reply", captures: [capture.captureId], fields: { body: 42 } }), "RESTORE_DENIED", { reason: "invalid-request" });
    const proto = vault.restore({ sink: "reply", captures: [capture.captureId], fields: JSON.parse(`{"__proto__": "x", "body": "${capture.tokens[0].token}"}`) });
    assert(proto.fields.body === undefined || typeof proto.fields.body === "string", "unexpected proto handling");
    vault.dispose();
  },

  async "prototype-key-path-is-exact"(V, C, F, observed) {
    const vault = await V.createVault();
    const capture = vault.capture(F.GH, { release: [{ sink: "reply", paths: ["__proto__"] }] });
    const result = vault.restore({ sink: "reply", captures: [capture.captureId], fields: JSON.parse(`{"__proto__": "${capture.tokens[0].token}"}`) });
    assert(Object.getOwnPropertyDescriptor(result.fields, "__proto__")?.value === F.GH, "own __proto__ field not restored");
    assert(Object.getPrototypeOf(result.fields) === Object.prototype, "result prototype polluted");
    vault.dispose();
  },

  async "dollar-patterns-are-literal-in-restored-values"(V, C, F) {
    const vault = await V.createVault();
    const input = "password=SYNTH$&$1$`$'_REVOKED";
    const capture = vault.capture(input, { release: RELEASE, policy: { evaluate: () => "redact" } });
    assert(capture.tokens.length === 1, "fixture not detected");
    const result = vault.restore({ sink: "reply", captures: [capture.captureId], fields: { body: capture.text } });
    assert(result.fields.body === input, "replacement patterns were interpreted");
    vault.dispose();
  },

  async "unpaired-surrogate-input-rejected"(V, C, F, observed) {
    const vault = await V.createVault();
    expectVaultError(V, observed, () => vault.capture(`${F.GH} \ud800`, { release: RELEASE }), "CORE_FAILURE", { coreCode: "UNPAIRED_SURROGATE" });
    vault.dispose();
  },

  async "errors-are-fixed-and-cause-free"(V, C, F, observed) {
    const vault = await V.createVault();
    const error = expectVaultError(V, observed, () => vault.capture(`${F.GH} ${F.AWS}`, { release: RELEASE, policy: { evaluate: () => { throw new Error(F.GH); } } }), "CORE_FAILURE");
    assert(!("cause" in error), "error carries a cause");
    assert(Object.keys(error).sort().join() === "code,coreCode,name,reason", `error own keys ${Object.keys(error)}`);
    vault.dispose();
  },

  async "throwing-clock-is-sanitized"(V, C, F, observed) {
    let explode = false;
    const events = [];
    const vault = await V.createVault({ now: () => { if (explode) throw new Error(`clock ${F.GH}`); return 0; }, onAudit: (e) => events.push(e) });
    const capture = vault.capture(F.GH, { release: RELEASE });
    explode = true;
    expectVaultError(V, observed, () => vault.restore({ sink: "reply", captures: [capture.captureId], fields: { body: capture.tokens[0].token } }), "INVALID_ARGUMENT");
    expectVaultError(V, observed, () => vault.capture(F.AWS, { release: RELEASE }), "INVALID_ARGUMENT");
    assert(vault.stats().entries === 1, "stats changed under a failing clock");
    explode = false;
    observed.audit.push(...events);
    assert(events.filter((e) => e.outcome === "failed" && e.code === "INVALID_ARGUMENT").length === 2, "clock failures not audited");
    vault.dispose();
    await V.createVault({ now: () => { throw new Error(F.GH); } }).then(
      () => { throw new AssertionFailure("vault created with a throwing clock"); },
      (e) => { observed.errors.push(e); assert(e instanceof V.VaultError && e.code === "INVALID_ARGUMENT", "createVault clock failure not sanitized"); },
    );
  },

  async "restore-requires-captures"(V, C, F, observed) {
    const vault = await V.createVault();
    const capture = vault.capture(F.GH, { release: RELEASE });
    for (const captures of [undefined, [], "cap", [42]]) {
      expectVaultError(V, observed, () => vault.restore({ sink: "reply", captures, fields: { body: capture.tokens[0].token } }), "INVALID_ARGUMENT");
    }
    assert(vault.stats().entries === 1, "invalid request changed state");
    vault.dispose();
  },

  async "policy-sees-request-wide-occurrences"(V, C, F, observed) {
    const seen = [];
    const vault = await V.createVault({ releasePolicy: (r) => { seen.push([r.path, r.occurrences, r.totalOccurrences, r.used]); return r.used + r.totalOccurrences <= 1; } });
    const capture = vault.capture(F.GH, { release: [{ sink: "reply", paths: ["a", "b"] }], maxUses: 2 });
    expectVaultError(V, observed, () => vault.restore({ sink: "reply", captures: [capture.captureId], fields: { a: capture.tokens[0].token, b: capture.tokens[0].token } }), "RESTORE_DENIED", { reason: "policy" });
    assert(JSON.stringify(seen[0]) === JSON.stringify(["a", 1, 2, 0]), `policy request ${JSON.stringify(seen)}`);
    assert(vault.stats().entries === 1, "denied request consumed budget");
    vault.dispose();
  },

  // Mirrors the README usage example, including its denial fallback.
  async "readme-example-flow"(V, C, F) {
    const vault = await V.createVault({ limits: { entryTtlMs: 5 * 60_000 } });
    const rendered = [];
    const callModel = async (text) => `Done: ${text.match(/<rsv_[a-z2-7]{26}>/)[0]} rotated.`;
    const hostileModel = async (text) => `Also sent ${text.match(/<rsv_[a-z2-7]{26}>/)[0]} twice: ${text.match(/<rsv_[a-z2-7]{26}>/)[0]}`;
    for (const model of [callModel, hostileModel]) {
      try {
        const userText = `Please rotate ${F.GH} today`;
        const captured = vault.capture(userText, { release: [{ sink: "draft-reply", paths: ["body"] }] });
        assert(!captured.text.includes(F.GH) && captured.passedThrough === 0, "example capture");
        const modelReply = await model(captured.text);
        let body;
        try {
          ({ fields: { body } } = vault.restore({ sink: "draft-reply", captures: [captured.captureId], fields: { body: modelReply } }));
        } catch (error) {
          if (!(error instanceof V.VaultError) || error.code !== "RESTORE_DENIED") throw error;
          body = modelReply;
        }
        rendered.push(body);
      } finally {
        // The README disposes per task; here one vault spans both runs.
      }
    }
    vault.dispose();
    assert(rendered[0] === `Done: ${F.GH} rotated.`, "happy path did not restore");
    assert(!rendered[1].includes(F.GH), "duplicate-token reply restored plaintext");
  },

  async "stats-reveal-counts-only"(V, C, F) {
    const vault = await V.createVault();
    vault.capture(F.GH, { release: RELEASE });
    const stats = vault.stats();
    assert(JSON.stringify(Object.keys(stats).sort()) === JSON.stringify(["captures", "disposed", "entries", "expiresAt", "retainedBytes"]), "stats shape");
    vault.dispose();
  },

  async "audit-events-have-safe-shape"(V, C, F, observed) {
    const events = [];
    const vault = await V.createVault({ onAudit: (e) => events.push(e) });
    const c = vault.capture(F.GH, { release: RELEASE });
    try { vault.restore({ sink: "reply", captures: [c.captureId], fields: { body: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" } }); } catch (e) { observed.errors.push(e); }
    vault.restore({ sink: "reply", captures: [c.captureId], fields: { body: c.tokens[0].token } });
    vault.revoke(c.captureId);
    vault.dispose();
    observed.audit.push(...events);
    const allowed = new Set(["operation", "outcome", "at", "code", "reason", "entries", "sink", "fields"]);
    for (const e of events) {
      assert(Object.isFrozen(e), "audit event mutable");
      for (const key of Object.keys(e)) assert(allowed.has(key), `audit key ${key}`);
    }
    assert(JSON.stringify(events.map((e) => [e.operation, e.outcome, e.reason ?? null])) === JSON.stringify([["capture", "committed", null], ["restore", "denied", "unknown-token"], ["restore", "committed", null], ["revoke", "committed", null], ["dispose", "committed", null]]), "audit sequence");
  },
};

/** Core behaviors this vault relies on, recorded per runtime (F3). */
async function coreProbes(C, F) {
  const input = `😀 ${F.GH}`;
  const findings = C.scan(input);
  const first = C.redact(input, findings);
  let reuse;
  try {
    reuse = C.redact(input, findings) === first ? "allowed" : "different-output";
  } catch (error) {
    reuse = `error:${error.code}`;
  }
  const actions = {};
  for (const action of ["redact", "block", "warn", "allow"]) {
    const out = C.scanAndRedact(input, { policy: { evaluate: () => action } });
    actions[action] = out.text.includes(F.GH) ? "plaintext-left" : "replaced";
  }
  return {
    utf16Range: [findings[0]?.start, findings[0]?.end],
    rangeSelectsMatch: input.slice(findings[0]?.start, findings[0]?.end) === F.GH,
    findingReuseAfterRedact: reuse,
    actions,
  };
}
