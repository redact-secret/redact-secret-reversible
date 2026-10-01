// capture(): the capture gate, tenant and session binding from the resolvers
// only, the lifecycle policy, store and key failures, and the rule that a
// failed capture leaves nothing a caller could restore
// (docs/specs/persistent-vault.md §5.3, §8.1, §8.2).
import assert from "node:assert/strict";
import test from "node:test";

import { KeyProviderError, RecordCryptoError, StoreError } from "@redact-secret/vault-contracts";

import {
  captureOne,
  createRig,
  CTX_A,
  CTX_B,
  ctx,
  denied,
  DIGEST_KEY,
  digests,
  foreignError,
  NAMESPACE,
  noteCaptureId,
  observedTokens,
  OTHER_TENANT,
  PURPOSE,
  registerLeakHygiene,
  rejects,
  RELEASE,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  SINK,
  sleep,
  TENANT,
} from "./helpers.mjs";

const TWO = `first ${SECRET_A} second ${SECRET_B} end`;
const EMPTY = { namespaces: 1, captures: 0, entries: 0, receipts: 0 };

async function vaultFailure(promise, vaultCode) {
  const error = await rejects(promise, "VAULT_FAILURE");
  assert.equal(error.vaultCode, vaultCode);
  return error;
}

/** Nothing reached the store or the key provider, and nothing is stored. */
function assertUntouched(rig) {
  assert.equal(rig.spy.mutations(), 0, "no mutating store call");
  assert.equal(rig.keys.stats.generate, 0, "no data key was generated");
  assert.deepEqual(rig.memory.control.counts(), EMPTY);
}

/** The capture the server tried to create, and the token it issued but never returned. */
function attempted(rig) {
  const created = rig.spy.last("createCapture");
  const captureId = created.input.capture.captureId;
  noteCaptureId(captureId);
  return { created, captureId, token: observedTokens.at(-1).token };
}

function restoreOf(captureId, token) {
  return { context: CTX_A, sink: SINK, purpose: PURPOSE, captures: [captureId], fields: { body: `value ${token}` } };
}

test("capture: round trip; the store receives ciphertext and identifiers, never a value or a token", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: TWO, maxUses: 2 });
  assert.equal(captured.tokens.length, 2);
  assert.equal(captured.tenant, TENANT);
  assert.equal(captured.sessionBound, false);
  assert.equal(captured.expiresAt, rig.clock.now() + 10 * 60 * 1000);
  assert.ok(Object.isFrozen(captured) && Object.isFrozen(captured.tokens));
  assert.ok(!captured.text.includes(SECRET_A) && !captured.text.includes(SECRET_B));
  for (const { token } of captured.tokens) assert.equal(captured.text.split(token).length, 2, "each token appears once");

  // Exactly one create, and what it carried.
  assert.equal(rig.spy.count("createCapture"), 1);
  const { input } = rig.spy.last("createCapture");
  assert.deepEqual(input.scope, { namespace: NAMESPACE, tenant: TENANT });
  assert.equal(input.epoch, 1);
  assert.equal(input.capture.captureId, captured.captureId);
  assert.equal(input.capture.sessionTag, null);
  assert.equal(input.capture.createdAt, rig.clock.now());
  assert.equal(input.capture.expiresAt, captured.expiresAt);
  assert.equal(input.capture.lookupVersion, 1);
  const expectedIds = await Promise.all(captured.tokens.map(({ token }) => digests.deriveEntryId(NAMESPACE, TENANT, token)));
  assert.deepEqual(input.entries.map((entry) => entry.entryId), expectedIds);
  assert.deepEqual(input.entries.map((entry) => entry.maxUses), [2, 2]);
  const wire = Buffer.concat([
    Buffer.from(JSON.stringify(input, (_key, value) => (value instanceof Uint8Array ? undefined : value))),
    ...input.entries.map((entry) => Buffer.from(entry.envelope)),
    Buffer.from(input.capture.wrappedKey),
  ]);
  for (const forbidden of [SECRET_A, SECRET_B, ...captured.tokens.map(({ token }) => token), "github", SINK, "body"]) {
    assert.equal(wire.includes(Buffer.from(forbidden)), false, "the store input carries no value, token, type, or grant in clear");
  }
  assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 1, entries: 2, receipts: 0 });

  const restored = await rig.vault.restore(restoreRequest(captured));
  assert.equal(restored.fields.body, TWO);
  assert.equal(restored.restored, 2);
  assert.equal(restored.tenant, TENANT);
  assert.equal(restored.principalId, CTX_A.principal.id);

  const audit = rig.audits.find((event) => event.operation === "capture");
  assert.deepEqual(audit, {
    operation: "capture",
    outcome: "committed",
    at: rig.clock.now(),
    principalId: CTX_A.principal.id,
    tenant: TENANT,
    entries: 2,
    captureId: captured.captureId,
  });
});

test("capture: argument errors are INVALID_ARGUMENT or a wrapped vault code, and store nothing", async () => {
  const rig = await createRig();
  await rejects(rig.vault.capture(7, { context: CTX_A, release: RELEASE }), "INVALID_ARGUMENT");
  await rejects(rig.vault.capture("text", null), "INVALID_ARGUMENT");
  await rejects(rig.vault.capture("text", "options"), "INVALID_ARGUMENT");
  await rejects(rig.vault.capture("text", { context: CTX_A, release: RELEASE, requestId: 7 }), "INVALID_ARGUMENT");
  await vaultFailure(rig.vault.capture(`secret ${SECRET_A}`, { context: CTX_A }), "INVALID_ARGUMENT");
  await vaultFailure(rig.vault.capture(`secret ${SECRET_A}`, { context: CTX_A, release: [] }), "INVALID_ARGUMENT");
  await vaultFailure(rig.vault.capture(`secret ${SECRET_A}`, { context: CTX_A, release: RELEASE, maxUses: 0 }), "INVALID_ARGUMENT");
  await vaultFailure(rig.vault.capture(`secret ${SECRET_A}`, { context: CTX_A, release: RELEASE, maxUses: 17 }), "INVALID_ARGUMENT");
  await vaultFailure(
    rig.vault.capture(`secret ${SECRET_A} <rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>`, { context: CTX_A, release: RELEASE }),
    "TOKEN_LITERAL_IN_INPUT",
  );
  assertUntouched(rig);
});

test("capture: a sink or path with a lone surrogate is INVALID_ARGUMENT, not an internal failure (§8.3)", async () => {
  const rig = await createRig();
  for (const release of [
    [{ sink: "sink-\ud800-lone", paths: ["body"] }],
    [{ sink: "sink-a", paths: ["body", "path-\udc00-lone"] }],
    [...RELEASE, { sink: "sink-b", paths: ["\ud83d"] }],
  ]) {
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release }), "INVALID_ARGUMENT");
  }
  assert.equal(rig.lifecycleCalls.length, 0);
  assertUntouched(rig);
  // A well-formed supplementary character is an ordinary identifier.
  const captured = await captureOne(rig, { release: [{ sink: "sink-\u{1f512}", paths: ["body-\u{1f512}"] }] });
  const restored = await rig.vault.restore(restoreRequest(captured, { sink: "sink-\u{1f512}", fields: { "body-\u{1f512}": captured.text } }));
  assert.equal(restored.fields["body-\u{1f512}"], `secret ${SECRET_A} here`);
});

test("capture: PII off: a retention allowlist is refused, and nothing is stored", async () => {
  // PII-on behaviour is in pii.test.mjs, which has its own process and activation.
  const rig = await createRig();
  await vaultFailure(
    rig.vault.capture(`${TWO} iban DE89 3704 0044 0532 0130 00`, { context: CTX_A, release: RELEASE, pii: { retain: ["pii_global_iban"] } }),
    "PII_UNAVAILABLE",
  );
  assertUntouched(rig);
});

test("capture: a policyRevision source that throws or returns an oversized value fails the capture with nothing stored", async () => {
  const rig = await createRig();
  for (const policyRevision of [
    () => {
      throw foreignError();
    },
    () => "r".repeat(257),
    () => 7,
    () => "revision-\ud800-lone",
  ]) {
    const vault = await rig.open({ policyRevision });
    await rejects(vault.capture(TWO, { context: CTX_A, release: RELEASE }), "INVALID_ARGUMENT");
  }
  assertUntouched(rig);
});

test("capture: a block finding rejects VAULT_FAILURE / BLOCKED_FINDING and nothing is stored", async () => {
  const rig = await createRig();
  const error = await vaultFailure(
    rig.vault.capture(TWO, { context: CTX_A, release: RELEASE, policy: { evaluate: () => "block" } }),
    "BLOCKED_FINDING",
  );
  assert.equal(error.coreCode, undefined);
  assertUntouched(rig);
  // Block wins even when the caller asked for pass-through.
  await vaultFailure(
    rig.vault.capture(TWO, { context: CTX_A, release: RELEASE, unredacted: "pass-through", policy: { evaluate: () => "block" } }),
    "BLOCKED_FINDING",
  );
  // One blocked finding among redacted ones aborts the whole capture.
  let seen = 0;
  await vaultFailure(
    rig.vault.capture(TWO, { context: CTX_A, release: RELEASE, policy: { evaluate: () => ((seen += 1) === 1 ? "redact" : "block") } }),
    "BLOCKED_FINDING",
  );
  assertUntouched(rig);
  assert.equal(rig.audits.at(-1).outcome, "failed");
  assert.equal(rig.audits.at(-1).code, "VAULT_FAILURE");
});

test("capture: warn and allow findings reject unless the caller passes them through explicitly", async () => {
  for (const action of ["warn", "allow"]) {
    const rig = await createRig();
    await vaultFailure(
      rig.vault.capture(TWO, { context: CTX_A, release: RELEASE, policy: { evaluate: () => action } }),
      "UNREDACTED_FINDINGS",
    );
    await rejects(
      rig.vault.capture(TWO, { context: CTX_A, release: RELEASE, unredacted: "yes", policy: { evaluate: () => action } }),
      "VAULT_FAILURE",
    );
    assertUntouched(rig);

    // Explicit pass-through: the finding stays in the text and is not retained.
    const passed = await captureOne(rig, { text: TWO, unredacted: "pass-through", policy: { evaluate: () => action } });
    assert.equal(passed.passedThrough, 2);
    assert.equal(passed.tokens.length, 0);
    assert.equal(passed.text, TWO);
    assert.equal(passed.sessionBound, false);
    assertUntouched(rig);

    // Mixed: one retained, one passed through. Only the retained one is stored.
    let seen = 0;
    const mixed = await captureOne(rig, {
      text: TWO,
      unredacted: "pass-through",
      policy: { evaluate: () => ((seen += 1) === 1 ? "redact" : action) },
    });
    assert.equal(mixed.tokens.length, 1);
    assert.equal(mixed.passedThrough, 1);
    assert.ok(!mixed.text.includes(SECRET_A) && mixed.text.includes(SECRET_B));
    assert.equal(rig.spy.last("createCapture").input.entries.length, 1);
    assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 1, entries: 1, receipts: 0 });
  }
});

test("capture: a finding the caller's eligible() declines is redacted but not retained", async () => {
  const rig = await createRig();
  let seen = 0;
  const captured = await captureOne(rig, { text: TWO, eligible: () => (seen += 1) === 1 });
  assert.equal(captured.tokens.length, 1);
  assert.equal(captured.unrestorable, 1);
  assert.ok(!captured.text.includes(SECRET_A) && !captured.text.includes(SECRET_B));
  assert.equal(rig.spy.last("createCapture").input.entries.length, 1);
});

test("capture: the tenant comes from the resolver; issuedTenant, tenant, and sessionId in options have no effect", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, {
    context: CTX_A,
    issuedTenant: OTHER_TENANT,
    tenant: OTHER_TENANT,
    sessionId: "session-synthetic-smuggled",
    sessionBound: true,
    captureId: "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb",
  });
  assert.equal(captured.tenant, TENANT);
  assert.equal(captured.sessionBound, false);
  assert.notEqual(captured.captureId, "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb");
  const { input } = rig.spy.last("createCapture");
  assert.deepEqual(input.scope, { namespace: NAMESPACE, tenant: TENANT });
  assert.equal(input.capture.sessionTag, null);
  // Nothing was written under the smuggled tenant.
  assert.equal((await rig.rows([captured.tokens[0].token], OTHER_TENANT)).entries.length, 0);
  assert.equal((await rig.rows([captured.tokens[0].token], TENANT)).entries.length, 1);
  // The smuggled tenant cannot restore it; the resolved one can, from any session.
  await denied(rig.vault.restore(restoreRequest(captured, { context: CTX_B })), "unknown-token");
  const restored = await rig.vault.restore(restoreRequest(captured, { context: ctx({ session: "session-synthetic-any" }) }));
  assert.equal(restored.fields.body, `secret ${SECRET_A} here`);
});

test("capture: the session binding comes from the session resolver and is stored only as a keyed tag", async () => {
  const rig = await createRig();
  const session = "session-synthetic-0001";
  const captured = await captureOne(rig, { context: ctx({ session }) });
  assert.equal(captured.sessionBound, true);
  const { input } = rig.spy.last("createCapture");
  const digester = await digests.createDigester(DIGEST_KEY);
  assert.equal(
    input.capture.sessionTag,
    await digester.sessionTag({ namespace: NAMESPACE, tenant: TENANT, captureId: captured.captureId, sessionId: session }),
  );
  assert.equal(JSON.stringify(input, (_key, value) => (value instanceof Uint8Array ? undefined : value)).includes(session), false);
  // An unkeyed tag would be guessable from the store: the configured key is what was used.
  const unkeyed = await digests.createDigester(null);
  assert.notEqual(
    input.capture.sessionTag,
    await unkeyed.sessionTag({ namespace: NAMESPACE, tenant: TENANT, captureId: captured.captureId, sessionId: session }),
  );
});

test("capture: lifecyclePolicy is asked once, with the entry count and UTF-8 byte size, before any store or key call", async () => {
  const rig = await createRig();
  let atDecision;
  rig.lifecycle = () => {
    atDecision = { mutations: rig.spy.mutations(), generated: rig.keys.stats.generate };
    return { allow: true };
  };
  const captured = await captureOne(rig, { text: `é ${SECRET_A} ü ${SECRET_B}`, context: ctx({ session: "session-synthetic-0001" }) });
  assert.equal(rig.lifecycleCalls.length, 1);
  const [input] = rig.lifecycleCalls;
  assert.deepEqual(input, {
    operation: "capture",
    principal: { id: "principal-synthetic-0001", tenant: TENANT },
    tenant: TENANT,
    sessionId: "session-synthetic-0001",
    entries: 2,
    bytes: Buffer.byteLength(SECRET_A) + Buffer.byteLength(SECRET_B),
    requestedAt: rig.clock.now(),
  });
  assert.ok(Object.isFrozen(input));
  assert.equal("captureId" in input, false);
  assert.deepEqual(atDecision, { mutations: 0, generated: 0 });
  assert.equal(captured.tokens.length, 2);
});

test("capture: a lifecyclePolicy deny, throw, rejection, timeout, or malformed return is LIFECYCLE_DENIED with nothing stored", async () => {
  const rig = await createRig({ vault: { policyTimeoutMs: 25 } });
  const behaviours = [
    () => ({ allow: false }),
    () => {
      throw foreignError();
    },
    () => Promise.reject(foreignError()),
    () => new Promise(() => {}),
    () => true,
    () => "allow",
    () => null,
    () => undefined,
    () => ({}),
    () => ({ allow: 1 }),
    () => ({ allow: "true" }),
    () => [true],
  ];
  for (const behaviour of behaviours) {
    rig.lifecycle = behaviour;
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "LIFECYCLE_DENIED");
    assert.equal(rig.audits.at(-1).outcome, "denied");
    assert.equal(rig.audits.at(-1).code, "LIFECYCLE_DENIED");
  }
  assert.equal(rig.lifecycleCalls.length, behaviours.length);
  assert.equal(rig.spy.calls.filter((call) => call.operation !== "recoveryState").length, 0, "no store call at all");
  assertUntouched(rig);
});

test("capture: a resolver that throws, times out, or returns a malformed principal or session is LIFECYCLE_DENIED", async () => {
  const rig = await createRig({ vault: { resolverTimeoutMs: 25 } });
  const contexts = [
    undefined,
    null,
    {},
    { principal: null },
    { principal: "principal-synthetic" },
    { principal: { id: "principal-synthetic-0001" } },
    { principal: { tenant: TENANT } },
    { principal: { id: "", tenant: TENANT } },
    { principal: { id: "principal-synthetic-0001", tenant: "" } },
    { principal: { id: "principal-synthetic-0001", tenant: "x".repeat(257) } },
    { principal: { id: "principal-synthetic-0001", tenant: "tenant-\ud800-lone" } },
    { principal: { id: 7, tenant: TENANT } },
    { principal: new Promise(() => {}) },
    { ...CTX_A, session: 7 },
    { ...CTX_A, session: "" },
    { ...CTX_A, session: "s".repeat(257) },
    { ...CTX_A, session: "session-\udc00-lone" },
    { ...CTX_A, session: new Promise(() => {}) },
  ];
  for (const context of contexts) {
    await rejects(rig.vault.capture(TWO, { context, release: RELEASE }), "LIFECYCLE_DENIED");
  }
  const throwing = await rig.open({
    resolvePrincipal: () => {
      throw foreignError();
    },
  });
  await rejects(throwing.capture(TWO, { context: CTX_A, release: RELEASE }), "LIFECYCLE_DENIED");
  const throwingSession = await rig.open({
    resolveSession: () => {
      throw foreignError();
    },
  });
  await rejects(throwingSession.capture(TWO, { context: CTX_A, release: RELEASE }), "LIFECYCLE_DENIED");
  assert.equal(rig.lifecycleCalls.length, 0, "the lifecycle policy is not asked about an unresolved principal");
  assertUntouched(rig);
});

test("capture: a capture that retains nothing makes no store call and no key call", async () => {
  const rig = await createRig();
  const captured = await rig.vault.capture("nothing sensitive in this synthetic sentence", {
    context: ctx({ session: "session-synthetic-0001" }),
    release: RELEASE,
  });
  assert.equal(captured.tokens.length, 0);
  assert.equal(captured.text, "nothing sensitive in this synthetic sentence");
  assert.equal(captured.sessionBound, false);
  assert.match(captured.captureId, /^cap_[a-z2-7]{26}$/);
  assert.equal(rig.lifecycleCalls.length, 1);
  assert.equal(rig.lifecycleCalls[0].entries, 0);
  assert.equal(rig.lifecycleCalls[0].bytes, 0);
  assert.equal(rig.spy.calls.filter((call) => call.operation !== "recoveryState").length, 0);
  assertUntouched(rig);
  assert.equal(rig.audits.at(-1).entries, 0);
  assert.equal("captureId" in rig.audits.at(-1), false);
});

test("capture: more entries than the store's maxCreateEntries is LIMIT_EXCEEDED before any store write or key call", async () => {
  const rig = await createRig({ memoryOptions: { maxCreateEntries: 1 } });
  await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "LIMIT_EXCEEDED");
  assert.equal(rig.lifecycleCalls.length, 0);
  assertUntouched(rig);
  // At the bound it works.
  assert.equal((await captureOne(rig)).tokens.length, 1);
});

test("capture: an envelope over maxEnvelopeBytes, or a capture over maxCreateBytes, is LIMIT_EXCEEDED before any store write", async () => {
  const small = await createRig({ memoryOptions: { maxEnvelopeBytes: 48 } });
  await rejects(small.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "LIMIT_EXCEEDED");
  assert.equal(small.spy.mutations(), 0);
  assert.deepEqual(small.memory.control.counts(), EMPTY);

  // Find one envelope's size, then allow one envelope but not two.
  const probe = await createRig();
  await captureOne(probe);
  const size = probe.spy.last("createCapture").input.entries[0].envelope.byteLength;
  const tight = await createRig({ memoryOptions: { maxCreateBytes: size + 8 } });
  await rejects(tight.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "LIMIT_EXCEEDED");
  assert.equal(tight.spy.mutations(), 0);
  assert.deepEqual(tight.memory.control.counts(), EMPTY);
  assert.equal((await captureOne(tight)).tokens.length, 1);
});

test("capture: the vault's own limits are enforced before anything is stored", async () => {
  const rig = await createRig({ vault: { limits: { maxValueBytes: 8 } } });
  await vaultFailure(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "LIMIT_EXCEEDED");
  const few = await rig.open({ limits: { maxEntries: 1 } });
  await vaultFailure(few.capture(TWO, { context: CTX_A, release: RELEASE }), "LIMIT_EXCEEDED");
  assertUntouched(rig);
});

test("capture: a key provider failure is KEY_UNAVAILABLE and nothing is stored", async () => {
  const rig = await createRig({ vault: { cryptoTimeoutMs: 40 } });
  const failures = [
    () => {
      throw foreignError();
    },
    () => Promise.reject(foreignError()),
    () => {
      throw new KeyProviderError("KEY_UNAVAILABLE");
    },
    () => {
      throw new KeyProviderError("KEY_THROTTLED");
    },
    () => {
      throw new KeyProviderError("KEY_TIMEOUT");
    },
    () => new Promise(() => {}),
    () => null,
    () => ({ keyRef: "local:synthetic", wrappedKey: new Uint8Array(60), plaintextKey: new Uint8Array(16) }),
    () => ({ keyRef: "", wrappedKey: new Uint8Array(60), plaintextKey: new Uint8Array(32) }),
    () => ({ keyRef: "local:synthetic", wrappedKey: "not-bytes", plaintextKey: new Uint8Array(32) }),
  ];
  for (const failure of failures) {
    rig.keys.fail.generate = failure;
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "KEY_UNAVAILABLE");
    assert.equal(rig.audits.at(-1).code, "KEY_UNAVAILABLE");
  }
  assert.equal(rig.keys.stats.generate, failures.length, "one provider call per capture, no retry and no other provider");
  assert.equal(rig.spy.mutations(), 0);
  assert.deepEqual(rig.memory.control.counts(), EMPTY);
});

test("capture: a crypto layer that throws or returns a malformed result stores nothing", async () => {
  const rig = await createRig();
  const real = rig.crypto;
  const open = (sealCapture) => rig.open({ crypto: { ...real, sealCapture } });
  const cases = [
    [
      () => {
        throw new RecordCryptoError("RECORD_INVALID_ARGUMENT");
      },
      "INVARIANT_VIOLATION",
    ],
    [
      () => {
        throw new RecordCryptoError("RECORD_LIMIT");
      },
      "LIMIT_EXCEEDED",
    ],
    [
      () => {
        throw foreignError();
      },
      "KEY_UNAVAILABLE",
    ],
    [() => null, "INVARIANT_VIOLATION"],
    [() => "sealed", "INVARIANT_VIOLATION"],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), envelopes: [] }), "INVARIANT_VIOLATION"],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), envelopes: "ee" }), "INVARIANT_VIOLATION"],
    [
      async (input, options) => {
        const sealed = await real.sealCapture(input, options);
        return { ...sealed, envelopes: [sealed.envelopes[0]] };
      },
      "INVARIANT_VIOLATION",
    ],
    [
      async (input, options) => {
        const sealed = await real.sealCapture(input, options);
        return { ...sealed, envelopes: [...sealed.envelopes, sealed.envelopes[0]] };
      },
      "INVARIANT_VIOLATION",
    ],
    [
      async (input, options) => {
        const sealed = await real.sealCapture(input, options);
        return { ...sealed, envelopes: sealed.envelopes.map(() => "not-bytes") };
      },
      "INVARIANT_VIOLATION",
    ],
    [
      async (input, options) => {
        const sealed = await real.sealCapture(input, options);
        return { ...sealed, envelopes: sealed.envelopes.map(() => new Uint8Array(0)) };
      },
      "INVARIANT_VIOLATION",
    ],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), wrappedKey: new Uint8Array(0) }), "INVARIANT_VIOLATION"],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), wrappedKey: new Uint8Array(4097) }), "INVARIANT_VIOLATION"],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), wrappedKey: "wrapped" }), "INVARIANT_VIOLATION"],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), keyRef: "" }), "INVARIANT_VIOLATION"],
    [async (input, options) => ({ ...(await real.sealCapture(input, options)), keyRef: 7 }), "INVARIANT_VIOLATION"],
  ];
  for (const [sealCapture, code] of cases) {
    const vault = await open(sealCapture);
    await rejects(vault.capture(TWO, { context: CTX_A, release: RELEASE }), code);
  }
  assert.equal(rig.spy.mutations(), 0);
  assert.deepEqual(rig.memory.control.counts(), EMPTY);
});

test("capture: a display formatter that throws or forges a token leaves no partial mapping", async () => {
  const rig = await createRig();
  let seen = 0;
  const onlyFirst = () => (seen += 1) % 2 === 1;
  await rejects(
    rig.vault.capture(TWO, {
      context: CTX_A,
      release: RELEASE,
      eligible: onlyFirst,
      displayFormatter: () => {
        throw foreignError();
      },
    }),
    "VAULT_FAILURE",
  );
  await rejects(
    rig.vault.capture(TWO, {
      context: CTX_A,
      release: RELEASE,
      eligible: onlyFirst,
      displayFormatter: () => "<rsv_bbbbbbbbbbbbbbbbbbbbbbbbbb>",
    }),
    "VAULT_FAILURE",
  );
  await vaultFailure(
    rig.vault.capture(TWO, {
      context: CTX_A,
      release: RELEASE,
      eligible: () => {
        throw foreignError();
      },
    }),
    "INVALID_ARGUMENT",
  );
  assertUntouched(rig);
});

test("capture: createCapture STORE_UNAVAILABLE returns no capture result, stores nothing, and needs no fence", async () => {
  const rig = await createRig();
  rig.failNext("createCapture", { kind: "unavailable" });
  await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "STORE_UNAVAILABLE");
  assert.equal(rig.spy.count("createCapture"), 1, "the server does not retry a create");
  assert.equal(rig.spy.count("revokeCapture"), 0, "a definite failure needs no fence");
  assert.deepEqual(rig.memory.control.counts(), EMPTY);
  const { captureId, token } = attempted(rig);
  await denied(rig.vault.restore(restoreOf(captureId, token)), "unknown-token");
});

const AMBIGUOUS_APPLIED = [
  ["STORE_AMBIGUOUS after the create was applied", { kind: "ambiguous", applied: true }, {}],
  ["a foreign Error after the create was applied", { kind: "foreign-error", when: "after" }, {}],
  ["a response that arrives after storeTimeoutMs", { kind: "delay", afterMs: 150 }, { storeTimeoutMs: 30 }],
];
for (const [name, fault, vaultOptions] of AMBIGUOUS_APPLIED) {
  test(`capture: ${name} fails the capture, and the capture that was created is fenced and not restorable`, async () => {
    const rig = await createRig({ vault: vaultOptions });
    rig.failNext("createCapture", fault);
    const error = await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "STORE_UNAVAILABLE");
    assert.deepEqual(Object.keys(error).sort(), ["attemptId", "code", "coreCode", "name", "reason", "vaultCode"].sort());
    const { created, captureId, token } = attempted(rig);
    while (!created.settled) await sleep(10);

    assert.equal(rig.spy.count("createCapture"), 1, "no retry");
    const fences = rig.spy.of("revokeCapture");
    assert.equal(fences.length, 1, "exactly one fence attempt");
    assert.equal(fences[0].input.captureId, captureId);
    assert.equal(fences[0].input.fenceAbsent, true);
    assert.deepEqual(fences[0].input.scope, { namespace: NAMESPACE, tenant: TENANT });

    // The capture exists in the store, with its entries, and is revoked.
    assert.equal((await rig.captureRow(captureId)).state, "revoked");
    assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 1, entries: 2, receipts: 0 });
    // Even with the token and the capture identifier, which the caller never got, nothing is restorable.
    await denied(rig.vault.restore(restoreOf(captureId, token)), "revoked");
    const second = await rig.open();
    await denied(second.restore(restoreOf(captureId, token)), "revoked");
    assert.equal(rig.keys.stats.unwrap, 0);
    assert.equal(rig.spy.count("commitRestore"), 0);
  });
}

const AMBIGUOUS_NOT_APPLIED = [
  ["STORE_AMBIGUOUS with the create not applied", { kind: "ambiguous", applied: false }, {}],
  ["a foreign Error before the create was applied", { kind: "foreign-error", when: "before" }, {}],
  ["a create still pending after storeTimeoutMs", { kind: "delay", beforeMs: 150 }, { storeTimeoutMs: 30 }],
];
for (const [name, fault, vaultOptions] of AMBIGUOUS_NOT_APPLIED) {
  test(`capture: ${name} fails the capture and writes a fence, so a late create cannot make it live`, async () => {
    const rig = await createRig({ vault: vaultOptions });
    rig.failNext("createCapture", fault);
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "STORE_UNAVAILABLE");
    const { created, captureId, token } = attempted(rig);
    while (!created.settled) await sleep(10);
    // The late create, if it ran at all, was refused by the fence.
    if (created.error === undefined) assert.deepEqual(created.result, { outcome: "rejected", reason: "fenced" });

    const fences = rig.spy.of("revokeCapture");
    assert.equal(fences.length, 1);
    assert.equal(fences[0].input.fenceAbsent, true);
    assert.deepEqual(fences[0].result, { outcome: "fenced" });
    assert.equal((await rig.captureRow(captureId)).state, "revoked");
    assert.deepEqual(rig.memory.control.counts(), { namespaces: 1, captures: 1, entries: 0, receipts: 0 });
    await denied(rig.vault.restore(restoreOf(captureId, token)), "unknown-token");
    // The identifier is burnt: the store refuses a create under it.
    const retry = await rig.memory.store.createCapture({ ...created.input, now: rig.clock.now() });
    assert.deepEqual(retry, { outcome: "rejected", reason: "fenced" });
  });
}

test("capture: when the fence attempt itself fails, the capture still fails and is attempted once", async () => {
  const rig = await createRig();
  rig.failNext("createCapture", { kind: "ambiguous", applied: false });
  rig.failNext("revokeCapture", { kind: "foreign-error", when: "before" });
  await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "STORE_UNAVAILABLE");
  assert.equal(rig.spy.count("revokeCapture"), 1);
  assert.equal(rig.spy.count("createCapture"), 1);
});

const UNINTERPRETABLE_CREATE = [
  ["null", { kind: "malformed", shape: "null" }],
  ["a result of the wrong types", { kind: "malformed", shape: "wrong-types" }],
  ["an unknown outcome", { kind: "result", result: { outcome: "maybe" }, delegate: true }],
  ["an unknown rejection reason", { kind: "result", result: { outcome: "rejected", reason: "busy" }, delegate: true }],
];
for (const [name, fault] of UNINTERPRETABLE_CREATE) {
  test(`capture: a create that was applied but answered with ${name} fails, and the capture is fenced and not restorable`, async () => {
    const rig = await createRig();
    rig.failNext("createCapture", fault);
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "INVARIANT_VIOLATION");
    const { captureId, token } = attempted(rig);
    const fences = rig.spy.of("revokeCapture");
    assert.equal(fences.length, 1, "an outcome the server cannot interpret is unknown: one fence attempt");
    assert.equal(fences[0].input.captureId, captureId);
    assert.equal(fences[0].input.fenceAbsent, true);
    assert.equal((await rig.captureRow(captureId)).state, "revoked");
    await denied(rig.vault.restore(restoreOf(captureId, token)), "revoked");
    assert.equal(rig.keys.stats.unwrap, 0);
  });
}

test("capture: a definite store rejection maps to its code, stores nothing, and writes no fence", async () => {
  const cases = [
    [{ outcome: "rejected", reason: "quarantined" }, "STORE_QUARANTINED"],
    [{ outcome: "rejected", reason: "clock-skew" }, "CLOCK_SKEW"],
    [{ outcome: "rejected", reason: "stale" }, "STORE_UNAVAILABLE"],
    [{ outcome: "rejected", reason: "exists" }, "INVARIANT_VIOLATION"],
    [{ outcome: "rejected", reason: "fenced" }, "INVARIANT_VIOLATION"],
  ];
  for (const [result, code] of cases) {
    const rig = await createRig();
    rig.failNext("createCapture", { kind: "result", result, delegate: false });
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), code);
    assert.equal(rig.spy.count("createCapture"), 1);
    assert.equal(rig.spy.count("revokeCapture"), 0);
    assert.deepEqual(rig.memory.control.counts(), EMPTY);
  }
});

test("capture: STORE_INVALID_ARGUMENT and STORE_CAPABILITY from the store are definite: INVARIANT_VIOLATION, no fence", async () => {
  // §4.2: both codes mean nothing was attempted, so the outcome is not unknown.
  const rig = await createRig();
  for (const code of ["STORE_INVALID_ARGUMENT", "STORE_CAPABILITY"]) {
    rig.spy.before.createCapture = () => {
      throw new StoreError(code);
    };
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "INVARIANT_VIOLATION");
  }
  assert.equal(rig.spy.count("createCapture"), 2);
  assert.equal(rig.spy.count("revokeCapture"), 0);
  assert.deepEqual(rig.memory.control.counts(), EMPTY);
});

test("capture: a quarantined namespace, or a store clock out of bound, rejects the capture with nothing stored", async () => {
  const rig = await createRig();
  await rig.memory.store.quarantine({ namespace: NAMESPACE });
  await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "STORE_QUARANTINED");
  assert.deepEqual(rig.memory.control.counts(), EMPTY);

  const clock = { server: 1_790_000_000_000, store: 1_790_000_000_000 };
  const skewed = await createRig({ clock: { now: () => clock.server }, storeClock: { now: () => clock.store } });
  clock.store += 2001;
  await rejects(skewed.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "CLOCK_SKEW");
  clock.store -= 4002;
  await rejects(skewed.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "CLOCK_SKEW");
  assert.deepEqual(skewed.memory.control.counts(), EMPTY);
  clock.store = clock.server + 2000;
  assert.equal((await captureOne(skewed)).tokens.length, 1);
});

test("clock: the server floors its clock, never lets it go back, and refuses a reading that is not a timestamp (§7.5)", async () => {
  let reading = 1_790_000_000_000.9;
  const rig = await createRig({ clock: { now: () => reading }, storeClock: { now: () => 1_790_000_000_000 } });
  const first = await captureOne(rig);
  assert.equal(rig.spy.last("createCapture").input.capture.createdAt, 1_790_000_000_000, "floored");
  assert.equal(first.expiresAt, 1_790_000_000_000 + 10 * 60 * 1000);
  assert.equal(rig.spy.last("createCapture").input.now, 1_790_000_000_000);

  // The clock source steps back: this instance keeps its latest reading.
  reading = 1_789_999_990_000;
  const second = await captureOne(rig);
  assert.equal(rig.spy.last("createCapture").input.capture.createdAt, 1_790_000_000_000);
  assert.equal(second.expiresAt, first.expiresAt);
  assert.equal(rig.lifecycleCalls.at(-1).requestedAt, 1_790_000_000_000);

  const before = rig.spy.mutations();
  for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY, "1790000000000", null, undefined, Number.MAX_SAFE_INTEGER + 2]) {
    reading = bad;
    await rejects(rig.vault.capture(TWO, { context: CTX_A, release: RELEASE }), "INVALID_ARGUMENT");
    await rejects(rig.vault.restore(restoreRequest(first)), "INVALID_ARGUMENT");
    await rejects(rig.vault.revoke({ context: CTX_A, captureId: first.captureId }), "INVALID_ARGUMENT");
  }
  assert.equal(rig.spy.mutations(), before);
  reading = 1_790_000_000_500;
  assert.equal((await rig.vault.restore(restoreRequest(first))).fields.body, `secret ${SECRET_A} here`);
});

test("capture: two captures of the same value get different tokens, identifiers, keys, and ciphertext", async () => {
  const rig = await createRig();
  const first = await captureOne(rig);
  const second = await captureOne(rig);
  assert.notEqual(first.captureId, second.captureId);
  assert.notEqual(first.tokens[0].token, second.tokens[0].token);
  const [a, b] = rig.spy.of("createCapture").map((call) => call.input);
  assert.notDeepEqual(a.entries[0].envelope, b.entries[0].envelope);
  assert.notDeepEqual(a.capture.wrappedKey, b.capture.wrappedKey);
  assert.equal(rig.keys.stats.generate, 2, "one data key per capture");
});

registerLeakHygiene({ minErrors: 100 });
