// Worker protocol v2: PII activation and PII retention in Worker mode
// (#39, docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
// §3 "Worker mode").
//
// Runs against the built package (dist/). Two layers:
// - Pure protocol and client-handshake tests, in this process, with no core.
// - Host scenarios. PII activation is realm-global and one-shot, and a
//   Worker is its own realm, so each scenario runs in a fresh Node.js
//   process that stands in for one Worker realm. `--import
//   ./fake-core-register.mjs` resolves `@redact-secret/core` to a fake core
//   (PII-capable, or beta.9-shaped with FAKE_CORE_PII=0), so the public
//   `@redact-secret/vault/worker` and `/worker/host` entries run unchanged
//   while a beta.9 core is installed. The same scenarios against a real
//   core live in worker-pii-core.test.mjs.
//
// All data is synthetic: FAKEPII-… markers and a revoked-looking token shape.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { VaultError } from "../dist/errors.js";
import { createWorkerVault } from "../dist/worker-client.js";
import {
  buildCaptureRequest,
  parseRequest,
  parseResponse,
  PROTOCOL_VERSION,
} from "../dist/worker-protocol.js";
import { channel } from "./worker-channel.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const RELEASE = [{ sink: "sink-a", paths: ["body"] }];
const IDENTITY = "credentials=full;selectors=pii:global;families=pii:global:iban;vocabulary=pii-context/v1";

function isVaultError(code, coreCode) {
  return (error) => {
    assert.ok(error instanceof VaultError, `expected VaultError, got ${error?.name}`);
    assert.equal(error.code, code);
    if (coreCode !== undefined) assert.equal(error.coreCode, coreCode);
    return true;
  };
}

function request(extra) {
  return { kind: "vault-request", v: 2, id: "r1", ...extra };
}

function rejectedWithId(result, id = "r1") {
  assert.equal(result.ok, false);
  assert.equal(result.id, id);
}

// --- protocol version --------------------------------------------------------

test("protocol version is 2", () => {
  assert.equal(PROTOCOL_VERSION, 2);
});

test("parseRequest rejects a version-1 (and any other version) request with its id", () => {
  for (const v of [1, 3, 0, "2", undefined, null]) {
    rejectedWithId(parseRequest({ kind: "vault-request", v, id: "r1", op: "stats" }));
  }
  assert.equal(parseRequest(request({ op: "stats" })).ok, true);
});

test("parseResponse rejects version-1 messages of every kind", () => {
  assert.equal(parseResponse({ kind: "vault-ready", v: 1 }).ok, false);
  assert.equal(parseResponse({ kind: "vault-ready", v: 1, piiActivation: null }).ok, false);
  assert.equal(parseResponse({ kind: "vault-init-failed", v: 1, code: "CORE_FAILURE" }).ok, false);
  const v1Response = parseResponse({ kind: "vault-response", v: 1, id: "r1", op: "stats", ok: true, result: null });
  rejectedWithId(v1Response);
});

// --- vault-ready carries the observed identity ---------------------------------

test("vault-ready requires piiActivation: a bounded string or null, and nothing else", () => {
  const ok = parseResponse({ kind: "vault-ready", v: 2, piiActivation: IDENTITY });
  assert.deepEqual(ok, { ok: true, value: { kind: "vault-ready", v: 2, piiActivation: IDENTITY } });
  assert.deepEqual(parseResponse({ kind: "vault-ready", v: 2, piiActivation: null }).value.piiActivation, null);
  for (const bad of [
    { kind: "vault-ready", v: 2 },
    { kind: "vault-ready", v: 2, piiActivation: undefined },
    { kind: "vault-ready", v: 2, piiActivation: "" },
    { kind: "vault-ready", v: 2, piiActivation: "x".repeat(513) },
    { kind: "vault-ready", v: 2, piiActivation: 1 },
    { kind: "vault-ready", v: 2, piiActivation: ["pii"] },
    { kind: "vault-ready", v: 2, piiActivation: null, selectors: ["pii"] },
    { kind: "vault-ready", v: 2, piiActivation: null, pii: ["pii"] },
  ]) {
    assert.equal(parseResponse(bad).ok, false, JSON.stringify(Object.keys(bad)));
  }
  assert.equal(parseResponse({ kind: "vault-ready", v: 2, piiActivation: "x".repeat(512) }).ok, true);
});

test("vault-init-failed still carries only code and coreCode", () => {
  assert.equal(parseResponse({ kind: "vault-init-failed", v: 2, code: "PII_ACTIVATION_MISMATCH" }).ok, true);
  const conflict = parseResponse({ kind: "vault-init-failed", v: 2, code: "CORE_FAILURE", coreCode: "PII_ACTIVATION_CONFLICT" });
  assert.equal(conflict.value.coreCode, "PII_ACTIVATION_CONFLICT");
  assert.equal(parseResponse({ kind: "vault-init-failed", v: 2, code: "CORE_FAILURE", piiActivation: IDENTITY }).ok, false);
});

// --- capture options: pii retention only, validated independently -------------

test("parseRequest accepts pii.retain and rebuilds it as a fresh, de-duplicated { retain }", () => {
  const retain = ["pii_global_iban", "pii_global_iban", "pii_jurisdiction_us_ssn"];
  const parsed = parseRequest(request({ op: "capture", input: "x", options: { release: RELEASE, pii: { retain } } }));
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.value.options.pii, { retain: ["pii_global_iban", "pii_jurisdiction_us_ssn"] });
  assert.notEqual(parsed.value.options.pii.retain, retain);
  const absent = parseRequest(request({ op: "capture", input: "x", options: { release: RELEASE, pii: undefined } }));
  assert.equal(absent.ok, true, "pii: undefined means absent");
});

test("parseRequest applies ADR §1 validation to pii itself (malformed retention is a protocol violation)", () => {
  for (const pii of [
    null,
    ["pii"], // a selector list, not a retention object
    "pii_global_iban",
    {},
    { retain: [] },
    { retain: "pii_global_iban" },
    { retain: [42] },
    { retain: ["global_iban"] },
    { retain: ["pii:global:iban"] },
    { retain: ["pii_global_*"] },
    { retain: ["PII_GLOBAL_IBAN"] },
    { retain: [`pii_${"a".repeat(125)}`] },
    { retain: Array.from({ length: 65 }, (_, i) => `pii_t${i}`) },
    { retain: ["pii_global_iban"], selectors: ["pii"] },
    { retain: ["pii_global_iban"], pii: ["pii"] },
    { retain: ["pii_global_iban"], expectPiiActivation: IDENTITY },
    JSON.parse('{"retain":["pii_global_iban"],"__proto__":{"polluted":true}}'),
  ]) {
    rejectedWithId(parseRequest(request({ op: "capture", input: "x", options: { release: RELEASE, pii } })));
  }
  assert.equal({}.polluted, undefined);
});

test("no request can carry a PII selection or an expected activation (selector smuggling)", () => {
  const smuggled = { pii: ["pii"], selectors: ["pii:global"], expectPiiActivation: IDENTITY, piiActivation: IDENTITY };
  const shapes = [
    { op: "capture", input: "x", options: { release: RELEASE } },
    { op: "restore", request: { sink: "sink-a", captures: ["c"], fields: { body: "x" } } },
    { op: "revoke", captureId: "c" },
    { op: "stats" },
    { op: "dispose" },
  ];
  for (const shape of shapes) {
    assert.equal(parseRequest(request(shape)).ok, true, `baseline ${shape.op}`);
    for (const [key, value] of Object.entries(smuggled)) {
      rejectedWithId(parseRequest(request({ ...shape, [key]: value })));
    }
  }
  for (const [key, value] of Object.entries(smuggled)) {
    if (key === "pii") continue; // covered above: `options.pii` must be a { retain } object
    rejectedWithId(parseRequest(request({ op: "capture", input: "x", options: { release: RELEASE, [key]: value } })));
  }
  // There is no request kind or op that initializes, configures, or re-activates.
  for (const op of ["initialize", "init", "configure", "activate", "setPii", "piiActivation"]) {
    rejectedWithId(parseRequest(request({ op, pii: ["pii"] })));
  }
  for (const kind of ["vault-init", "vault-configure", "vault-ready"]) {
    assert.equal(parseRequest({ kind, v: 2, id: "r1", pii: ["pii"] }).ok, false);
  }
});

test("buildCaptureRequest applies ADR §1 synchronously: invalid pii is INVALID_ARGUMENT before anything is sent", () => {
  const built = buildCaptureRequest("w1", "x", { release: RELEASE, pii: { retain: ["pii_global_iban"] } });
  assert.equal(built.v, 2);
  assert.deepEqual(built.options.pii, { retain: ["pii_global_iban"] });
  for (const pii of [["pii"], { retain: [] }, { retain: ["email"] }, { retain: ["pii_x"], extra: 1 }, null]) {
    assert.throws(() => buildCaptureRequest("w1", "x", { release: RELEASE, pii }), isVaultError("INVALID_ARGUMENT"));
  }
  assert.throws(() => buildCaptureRequest("w1", "x", { release: RELEASE, selectors: ["pii"] }), isVaultError("INVALID_ARGUMENT"));
});

// --- client handshake ----------------------------------------------------------

async function handshake(readyMessage, options) {
  const { port, scope } = channel();
  const pending = createWorkerVault(port, { timeoutMs: 2000, ...options });
  scope.postMessage(readyMessage);
  return pending;
}

test("createWorkerVault exposes the ready message's piiActivation, read-only", async () => {
  const vault = await handshake({ kind: "vault-ready", v: 2, piiActivation: IDENTITY });
  assert.equal(vault.piiActivation, IDENTITY);
  assert.throws(() => {
    "use strict";
    vault.piiActivation = "credentials=full;selectors=off;families=;vocabulary=x";
  }, TypeError);
  assert.equal(vault.piiActivation, IDENTITY);
  const beta9 = await handshake({ kind: "vault-ready", v: 2, piiActivation: null });
  assert.equal(beta9.piiActivation, null);
});

test("createWorkerVault: expectPiiActivation must equal the Worker's identity byte-for-byte", async () => {
  const same = await handshake({ kind: "vault-ready", v: 2, piiActivation: IDENTITY }, { expectPiiActivation: IDENTITY });
  assert.equal(same.piiActivation, IDENTITY);
  await assert.rejects(
    handshake({ kind: "vault-ready", v: 2, piiActivation: IDENTITY }, { expectPiiActivation: `${IDENTITY} ` }),
    isVaultError("PII_ACTIVATION_MISMATCH"),
  );
  await assert.rejects(
    handshake({ kind: "vault-ready", v: 2, piiActivation: null }, { expectPiiActivation: IDENTITY }),
    isVaultError("PII_ACTIVATION_MISMATCH"),
  );
});

test("PII_ACTIVATION_MISMATCH from the client is value-free", async () => {
  try {
    await handshake({ kind: "vault-ready", v: 2, piiActivation: IDENTITY }, { expectPiiActivation: "credentials=full;selectors=off" });
    assert.fail("expected a rejection");
  } catch (error) {
    assert.equal(error.code, "PII_ACTIVATION_MISMATCH");
    const text = `${error.message} ${JSON.stringify(error)} ${String(error.coreCode)}`;
    assert.ok(!text.includes("selectors="), "an identity leaked into the error");
  }
});

test("createWorkerVault validates expectPiiActivation's shape", async () => {
  const { port } = channel();
  for (const bad of ["", "x".repeat(513), 1, null, ["pii"]]) {
    await assert.rejects(createWorkerVault(port, { expectPiiActivation: bad }), isVaultError("INVALID_ARGUMENT"));
  }
});

test("a version-1 or incomplete ready message rejects the handshake with WORKER_PROTOCOL_VIOLATION", async () => {
  for (const ready of [
    { kind: "vault-ready", v: 1 },
    { kind: "vault-ready", v: 2 },
    { kind: "vault-ready", v: 2, piiActivation: null, extra: true },
    { kind: "vault-init-failed", v: 1, code: "CORE_FAILURE" },
  ]) {
    await assert.rejects(handshake(ready), isVaultError("WORKER_PROTOCOL_VIOLATION"), JSON.stringify(ready));
  }
});

test("the client sends v2 requests and rejects a v1 reply to them", async () => {
  const { port, scope } = channel();
  const pending = createWorkerVault(port, { timeoutMs: 2000 });
  scope.postMessage({ kind: "vault-ready", v: 2, piiActivation: null });
  const vault = await pending;
  scope.addEventListener("message", (event) => {
    assert.equal(event.data.v, 2);
    scope.postMessage({ kind: "vault-response", v: 1, id: event.data.id, op: "stats", ok: true, result: null });
  });
  await assert.rejects(vault.stats(), isVaultError("WORKER_PROTOCOL_VIOLATION"));
});

test("an invalid pii retention throws synchronously and sends nothing", async () => {
  const { port, scope } = channel();
  const pending = createWorkerVault(port, { timeoutMs: 2000 });
  scope.postMessage({ kind: "vault-ready", v: 2, piiActivation: IDENTITY });
  const vault = await pending;
  assert.throws(() => vault.capture("x", { release: RELEASE, pii: { retain: ["email"] } }), isVaultError("INVALID_ARGUMENT"));
  assert.throws(() => vault.capture("x", { release: RELEASE, pii: ["pii"] }), isVaultError("INVALID_ARGUMENT"));
  assert.equal(port.posted.length, 0);
});

// --- host scenarios, one Worker realm per process --------------------------------

const PRELUDE = `
import assert from "node:assert/strict";
import * as core from "@redact-secret/core";
import { createWorkerVault, VaultError } from "@redact-secret/vault/worker";
import { startVaultWorkerHost } from "@redact-secret/vault/worker/host";
import { channel, nextHandshake, rawRequest } from ${JSON.stringify(pathToFileURL(join(HERE, "worker-channel.mjs")).href)};
const GH = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const IBAN = "FAKEPII-IBAN-0001";
const SSN = "FAKEPII-SSN-0002";
const PHONE = "FAKEPII-PHONE-0003";
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
/** Starts the host in this realm (the "Worker") and connects a client from the "page". */
async function connect(hostOptions = {}, clientOptions = {}) {
  const { port, scope } = channel();
  const vault = createWorkerVault(port, { timeoutMs: 2000, ...clientOptions });
  await startVaultWorkerHost({ ...hostOptions, target: scope });
  return { vault, port, scope };
}
`;

function scenario(body, { pii = true } = {}) {
  try {
    execFileSync(
      process.execPath,
      ["--import", pathToFileURL(join(HERE, "fake-core-register.mjs")).href, "--input-type=module", "-e", `${PRELUDE}\n${body}`],
      { cwd: HERE, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", env: { ...process.env, FAKE_CORE_PII: pii ? "1" : "0" } },
    );
  } catch (error) {
    // The child prints only assertion text (codes and booleans), never values.
    assert.fail(`scenario failed:\n${String(error.stderr).split("\n").slice(0, 16).join("\n")}`);
  }
}

test("Worker realm: host forwards the Worker script's selection and reports the identity", () => {
  scenario(`
    const { vault } = await connect({ pii: ["pii"] });
    const v = await vault;
    assert.equal(v.piiActivation, core.piiActivation());
    assert.match(v.piiActivation, /^credentials=full;selectors=pii:global;/);
    assert.deepEqual(core.calls.initialize, [{ pii: ["pii"] }]);
  `);
});

test("Worker realm: host adopts the activation the Worker script established itself", () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const { vault } = await connect();
    const v = await vault;
    assert.match(v.piiActivation, /selectors=pii:global;/);
    assert.equal(core.calls.initialize.length, 1, "the host called an initializer during adoption");
  `);
});

test("Worker realm: an identical selection resolves idempotently", () => {
  scenario(`
    await core.initialize({ pii: ["pii:global"] });
    const v = await (await connect({ pii: ["pii"] })).vault;
    assert.match(v.piiActivation, /selectors=pii:global;/);
  `);
});

test("Worker realm: a different selection is PII_ACTIVATION_CONFLICT and the realm keeps its selection", () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const { vault, port } = await connect({ pii: [] });
    await rejectsWith(vault, "CORE_FAILURE", "PII_ACTIVATION_CONFLICT");
    assert.match(core.piiActivation(), /selectors=pii:global;/);
  `);
  scenario(`
    const { vault } = await connect({ pii: [] });
    const v = await vault;
    assert.match(v.piiActivation, /selectors=off;/);
    // The Worker realm is now locked off, because the Worker script said so.
    await assert.rejects(core.initialize({ pii: ["pii"] }), (e) => e.code === "PII_ACTIVATION_CONFLICT");
  `);
});

test("Worker realm: omitted pii on an uninitialized PII core is NOT_INITIALIZED and calls no initializer", () => {
  scenario(`
    const { vault } = await connect();
    await rejectsWith(vault, "CORE_FAILURE", "NOT_INITIALIZED");
    assert.equal(core.calls.initialize.length, 0);
  `);
});

test("Worker realm: selector errors surface as CORE_FAILURE with the core's code", () => {
  scenario(`
    await rejectsWith((await connect({ pii: ["not a selector"] })).vault, "CORE_FAILURE", "PII_SELECTOR_INVALID");
  `);
});

test("Worker realm: host expectPiiActivation mismatch is vault-init-failed PII_ACTIVATION_MISMATCH", () => {
  scenario(`
    const { port, scope } = channel();
    const handshake = nextHandshake(port);
    await startVaultWorkerHost({ pii: ["pii"], expectPiiActivation: "credentials=full;selectors=off", target: scope });
    const message = await handshake;
    assert.deepEqual(message, { kind: "vault-init-failed", v: 2, code: "PII_ACTIVATION_MISMATCH" });
  `);
});

test("Worker realm: ready message identity equals the realm's piiActivation()", () => {
  scenario(`
    const { port, scope } = channel();
    const handshake = nextHandshake(port);
    await startVaultWorkerHost({ pii: ["pii"], target: scope });
    const message = await handshake;
    assert.deepEqual(Object.keys(message).sort(), ["kind", "piiActivation", "v"]);
    assert.equal(message.v, 2);
    assert.equal(message.piiActivation, core.piiActivation());
  `);
});

test("Worker realm: client expectPiiActivation match and mismatch", () => {
  scenario(`
    await core.initialize({ pii: ["pii"] });
    const expected = core.piiActivation();
    const ok = await (await connect({}, { expectPiiActivation: expected })).vault;
    assert.equal(ok.piiActivation, expected);
    await rejectsWith((await connect({}, { expectPiiActivation: expected + "x" })).vault, "PII_ACTIVATION_MISMATCH");
  `);
});

test("Worker realm: PII is never retained by default", () => {
  scenario(`
    const v = await (await connect({ pii: ["pii"] })).vault;
    const input = "rotate " + GH + " iban " + IBAN + " ssn " + SSN;
    const result = await v.capture(input, { release: RELEASE });
    assert.deepEqual(result.tokens.map((t) => t.type), ["github_token"]);
    assert.equal(result.unrestorable, 2);
    assert.ok(!result.text.includes(IBAN) && !result.text.includes(SSN), "PII left in the text");
    const restored = await v.restore({ sink: "sink-a", captures: [result.captureId], fields: { body: result.text } });
    assert.ok(!restored.fields.body.includes(IBAN) && !restored.fields.body.includes(SSN), "unretained PII restored");
  `);
});

test("Worker realm: pii.retain allowlists exact types, and only those", () => {
  scenario(`
    const v = await (await connect({ pii: ["pii"] })).vault;
    const input = "iban " + IBAN + " ssn " + SSN;
    const result = await v.capture(input, { release: RELEASE, pii: { retain: ["pii_global_iban", "pii_not_a_real_type"] } });
    assert.deepEqual(result.tokens.map((t) => t.type), ["pii_global_iban"]);
    assert.equal(result.unrestorable, 1);
    const restored = await v.restore({ sink: "sink-a", captures: [result.captureId], fields: { body: result.text } });
    assert.ok(restored.fields.body.includes(IBAN), "allowlisted type did not restore");
    assert.ok(!restored.fields.body.includes(SSN), "non-allowlisted type restored");
  `);
});

test("Worker realm: warn-level PII keeps the unredacted gate", () => {
  scenario(`
    const v = await (await connect({ pii: ["pii"] })).vault;
    await rejectsWith(v.capture("call " + PHONE, { release: RELEASE }), "UNREDACTED_FINDINGS");
    const passed = await v.capture("call " + PHONE, { release: RELEASE, unredacted: "pass-through" });
    assert.deepEqual(passed.passedThroughTypes, ["pii_global_phone"]);
  `);
});

test("Worker realm: pii retention while the realm's PII is off is PII_UNAVAILABLE", () => {
  scenario(`
    const v = await (await connect({ pii: [] })).vault;
    await rejectsWith(v.capture(GH, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), "PII_UNAVAILABLE");
    assert.equal((await v.capture(GH, { release: RELEASE })).tokens.length, 1);
  `);
});

test("Worker realm: a hostile page cannot send selectors, and activation never changes", () => {
  scenario(`
    const { vault, port } = await connect({ pii: ["pii"] });
    const v = await vault;
    const before = core.piiActivation();
    const initCalls = core.calls.initialize.length;
    const hostile = [
      { kind: "vault-request", v: 2, id: "h1", op: "capture", input: IBAN, options: { release: RELEASE, pii: ["pii:us"] } },
      { kind: "vault-request", v: 2, id: "h2", op: "capture", input: IBAN, options: { release: RELEASE, pii: { retain: ["pii_global_iban"], selectors: ["pii"] } } },
      { kind: "vault-request", v: 2, id: "h3", op: "capture", input: IBAN, options: { release: RELEASE }, pii: [] },
      { kind: "vault-request", v: 2, id: "h4", op: "capture", input: IBAN, options: { release: RELEASE, selectors: [] } },
      { kind: "vault-request", v: 2, id: "h5", op: "stats", pii: [] },
      { kind: "vault-request", v: 2, id: "h6", op: "stats", expectPiiActivation: "credentials=full;selectors=off" },
      { kind: "vault-request", v: 2, id: "h7", op: "initialize", pii: [] },
      { kind: "vault-request", v: 2, id: "h8", op: "dispose", selectors: ["pii"] },
      { kind: "vault-request", v: 1, id: "h9", op: "stats" },
      { kind: "vault-request", v: 2, id: "h10", op: "capture", input: IBAN, options: { release: RELEASE, pii: { retain: [] } } },
    ];
    for (const message of hostile) {
      const reply = await rawRequest(port, message);
      assert.equal(reply.ok, false, message.id + " was accepted");
      assert.equal(reply.error.code, "WORKER_PROTOCOL_VIOLATION", message.id);
      assert.equal(reply.v, 2);
      assert.ok(!JSON.stringify(reply).includes(IBAN), "a value leaked into a violation reply");
    }
    assert.equal(core.piiActivation(), before);
    assert.equal(core.calls.initialize.length, initCalls, "a page message reached the core's initializer");
    assert.equal((await v.stats()).disposed, false, "the Worker stopped serving");
    // A well-formed raw v2 retention request is accepted: retention is not activation.
    const ok = await rawRequest(port, { kind: "vault-request", v: 2, id: "ok1", op: "capture", input: IBAN, options: { release: RELEASE, pii: { retain: ["pii_global_iban"] } } });
    assert.equal(ok.ok, true);
    assert.deepEqual(ok.result.tokens.map((t) => t.type), ["pii_global_iban"]);
  `);
});

test("beta.9-shaped Worker realm: no PII option means ready with piiActivation null", () => {
  scenario(
    `
    const v = await (await connect()).vault;
    assert.equal(v.piiActivation, null);
    assert.deepEqual(core.calls.initialize, [undefined], "expected exactly one plain initialize()");
    const empty = await (await connect({ pii: [] })).vault;
    assert.equal(empty.piiActivation, null);
    assert.equal((await v.capture(GH, { release: RELEASE })).tokens.length, 1);
  `,
    { pii: false },
  );
});

test("beta.9-shaped Worker realm: every PII option fails closed with PII_UNAVAILABLE", () => {
  scenario(
    `
    await rejectsWith((await connect({ pii: ["pii"] })).vault, "PII_UNAVAILABLE");
    await rejectsWith((await connect({ expectPiiActivation: "credentials=full;selectors=off" })).vault, "PII_UNAVAILABLE");
    assert.equal(core.calls.initialize.length, 0, "the core was called despite a PII option");
    const v = await (await connect()).vault;
    await rejectsWith(v.capture(GH, { release: RELEASE, pii: { retain: ["pii_global_iban"] } }), "PII_UNAVAILABLE");
    await rejectsWith((await connect({}, { expectPiiActivation: "credentials=full;selectors=off" })).vault, "PII_ACTIVATION_MISMATCH");
  `,
    { pii: false },
  );
});
