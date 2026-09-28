// Worker protocol v2 against the *real* installed @redact-secret/core (#39).
//
// Each scenario is one fresh Node.js process standing in for one Worker
// realm: the public `@redact-secret/vault/worker/host` entry runs there with
// an in-memory channel as its target, and the public `@redact-secret/vault/worker`
// client talks to it. (Real browser Workers are covered by `qualify:worker`.)
//
// - Beta.9 compatibility (ADR §4): run with the pinned core, skipped with a
//   reason when the installed core has a PII surface.
// - PII-on: need a core with `piiActivation` (beta.10 or later); skipped with
//   a reason on beta.9. The same contract runs against a fake core in
//   worker-pii.test.mjs.
//
// Scenarios import the packages by name, so this file runs unchanged in the
// repository and in a scratch consumer project with a candidate core.
// Data is synthetic: the widely published documentation-example IBAN and the
// repository's revoked-looking GitHub token shape (see pii-core.test.mjs).
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import * as core from "@redact-secret/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const HAS_PII = typeof core.piiActivation === "function";
const NEEDS_PII = HAS_PII
  ? false
  : `installed @redact-secret/core ${core.VERSION} has no PII surface (no piiActivation export); PII-on Worker tests need a beta.10+ core`;
const BETA9_ONLY = HAS_PII
  ? `installed @redact-secret/core ${core.VERSION} has a PII surface (piiActivation); beta.9 compatibility checks do not apply`
  : false;

const PRELUDE = `
import assert from "node:assert/strict";
import * as core from "@redact-secret/core";
import { createWorkerVault, VaultError } from "@redact-secret/vault/worker";
import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
import { channel, nextHandshake, rawRequest } from ${JSON.stringify(pathToFileURL(join(HERE, "worker-channel.mjs")).href)};
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
async function connect(hostOptions = {}, clientOptions = {}) {
  const { port, scope } = channel();
  const vault = createWorkerVault(port, { timeoutMs: 10000, ...clientOptions });
  await startVaultWorkerHost({ ...hostOptions, target: scope });
  return { vault, port, scope };
}
`;

function scenario(body) {
  try {
    execFileSync(process.execPath, ["--input-type=module", "-e", `${PRELUDE}\n${body}`], {
      cwd: HERE,
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8",
    });
  } catch (error) {
    // The child prints only assertion text (codes and booleans), never values.
    assert.fail(`scenario failed:\n${String(error.stderr).split("\n").slice(0, 16).join("\n")}`);
  }
}

// --- beta.9 compatibility -------------------------------------------------------

test("real core (beta.9): startVaultWorkerHost() is ready with piiActivation null", { skip: BETA9_ONLY }, () => {
  scenario(`
    const { port, scope } = channel();
    const handshake = nextHandshake(port);
    const vault = createWorkerVault(port, { timeoutMs: 10000 });
    await startVaultWorkerHost({ target: scope });
    assert.deepEqual(await handshake, { kind: "vault-ready", v: 2, piiActivation: null });
    const v = await vault;
    assert.equal(v.piiActivation, null);
    assert.equal((await v.capture("rotate " + GH, { release: RELEASE })).tokens.length, 1);
    const empty = await (await connect({ pii: [] })).vault;
    assert.equal(empty.piiActivation, null);
  `);
});

test("real core (beta.9): PII options fail closed with PII_UNAVAILABLE; client expectation mismatches", { skip: BETA9_ONLY }, () => {
  scenario(`
    await rejectsWith((await connect({ pii: ["pii"] })).vault, "PII_UNAVAILABLE");
    await rejectsWith((await connect({ expectPiiActivation: "credentials=full;selectors=off" })).vault, "PII_UNAVAILABLE");
    const v = await (await connect()).vault;
    await rejectsWith(v.capture(GH, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), "PII_UNAVAILABLE");
    await rejectsWith((await connect({}, { expectPiiActivation: "credentials=full;selectors=off" })).vault, "PII_ACTIVATION_MISMATCH");
  `);
});

// --- PII-on (beta.10+) -------------------------------------------------------------

test("real core: Worker script selection is forwarded; ready identity equals the realm's piiActivation()", { skip: NEEDS_PII }, () => {
  scenario(`
    const { port, scope } = channel();
    const handshake = nextHandshake(port);
    await startVaultWorkerHost({ pii: ["pii"], target: scope });
    const message = await handshake;
    assert.equal(message.v, 2);
    assert.equal(message.piiActivation, core.piiActivation());
    assert.match(message.piiActivation, /selectors=pii:global;/);
  `);
});

test("real core: Worker script initializes first; host adopts; client expectPiiActivation matches", { skip: NEEDS_PII }, () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const identity = core.piiActivation();
    const v = await (await connect({}, { expectPiiActivation: identity })).vault;
    assert.equal(v.piiActivation, identity);
    await rejectsWith((await connect({}, { expectPiiActivation: identity + "x" })).vault, "PII_ACTIVATION_MISMATCH");
  `);
});

test("real core: activation conflict inside the Worker realm -> CORE_FAILURE / PII_ACTIVATION_CONFLICT", { skip: NEEDS_PII }, () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const before = core.piiActivation();
    await rejectsWith((await connect({ pii: [] })).vault, "CORE_FAILURE", "PII_ACTIVATION_CONFLICT");
    assert.equal(core.piiActivation(), before, "realm keeps the Worker script's selection");
  `);
});

test("real core: pii omitted on an uninitialized Worker realm -> CORE_FAILURE / NOT_INITIALIZED", { skip: NEEDS_PII }, () => {
  scenario(`
    await rejectsWith((await connect()).vault, "CORE_FAILURE", "NOT_INITIALIZED");
    let code;
    try { core.piiActivation(); } catch (e) { code = e.code; }
    assert.equal(code, "NOT_INITIALIZED", "the host called no initializer");
  `);
});

test("real core: Worker-mode PII retention default and allowlist", { skip: NEEDS_PII }, () => {
  scenario(`
    const v = await (await connect({ pii: ["pii"] })).vault;
    const input = "token " + GH + " iban " + IBAN + " end";
    const plain = await v.capture(input, { release: RELEASE });
    assert.deepEqual(plain.tokens.map((t) => t.type), ["github_token"]);
    assert.equal(plain.unrestorable, 1);
    assert.ok(!plain.text.includes(IBAN));
    const kept = await v.capture(input, { release: RELEASE, pii: { retain: ["pii_global_iban"] } });
    assert.deepEqual(kept.tokens.map((t) => t.type).sort(), ["github_token", "pii_global_iban"]);
    const restored = await v.restore({ sink: "sink-a", captures: [kept.captureId], fields: { body: kept.text } });
    assert.equal(restored.fields.body, input);
  `);
});

// Default-confidence warn PII needs no policy, so Worker mode can gate it (#43).
// PHONE is the core's own Medium-confidence conformance value (see pii-core.test.mjs).
test("real core: Worker-mode default-confidence warn PII x unredacted reject / pass-through; PII counts toward maxFindings", { skip: NEEDS_PII }, () => {
  scenario(`
    const PHONE = "555-2345";
    const v = await (await connect({ pii: ["pii"], limits: { maxFindings: 2 } })).vault;
    const input = "telephone=" + PHONE + " token " + GH;
    await rejectsWith(v.capture(input, { release: RELEASE }), "UNREDACTED_FINDINGS");
    assert.equal((await v.stats()).entries, 0);
    const passed = await v.capture(input, { release: RELEASE, unredacted: "pass-through" });
    assert.equal(passed.passedThrough, 1);
    assert.deepEqual(passed.passedThroughTypes, ["pii_global_phone"]);
    assert.deepEqual(passed.tokens.map((t) => t.type), ["github_token"]);
    assert.ok(passed.text.includes("telephone=" + PHONE) && !passed.text.includes(GH));
    const before = await v.stats();
    await rejectsWith(v.capture(input + " iban " + IBAN, { release: RELEASE, unredacted: "pass-through" }), "CORE_FAILURE", "FINDING_LIMIT_EXCEEDED");
    assert.deepEqual(await v.stats(), before);
  `);
});

test("real core: a hostile page cannot change the Worker realm's activation", { skip: NEEDS_PII }, () => {
  scenario(`
    const { vault, port } = await connect({ pii: ["pii"] });
    await vault;
    const before = core.piiActivation();
    for (const [id, message] of [
      ["h1", { kind: "vault-request", v: 2, id: "h1", op: "stats", pii: [] }],
      ["h2", { kind: "vault-request", v: 2, id: "h2", op: "capture", input: "x", options: { release: RELEASE, pii: [] } }],
      ["h3", { kind: "vault-request", v: 1, id: "h3", op: "stats" }],
    ]) {
      const reply = await rawRequest(port, message);
      assert.equal(reply.ok, false, id);
      assert.equal(reply.error.code, "WORKER_PROTOCOL_VIOLATION", id);
    }
    assert.equal(core.piiActivation(), before);
  `);
});
