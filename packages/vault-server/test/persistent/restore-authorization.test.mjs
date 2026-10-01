// restore(): who may restore what, in the order of
// docs/specs/persistent-vault.md §7.2, and that every denial consumes nothing.
import assert from "node:assert/strict";
import test from "node:test";

import { KeyProviderError } from "@redact-secret/vault-contracts";
import { createRecordCrypto } from "@redact-secret/vault-crypto";
import { createLocalKeyProvider } from "@redact-secret/vault-crypto/local-key-provider";

import {
  ABSENT_CAPTURE,
  captureOne,
  createRig,
  CTX_A,
  CTX_B,
  ctx,
  denied,
  FORGED_TOKEN,
  foreignError,
  NAMESPACE,
  OTHER_TENANT,
  PURPOSE,
  registerLeakHygiene,
  rejects,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  SINK,
  TENANT,
} from "./helpers.mjs";

const ORIGINAL = `secret ${SECRET_A} here`;
const S1 = "session-synthetic-0001";
const S2 = "session-synthetic-0002";

/** Nothing was consumed, no commit was attempted, and no receipt exists. */
async function assertNothingConsumed(rig, captured, tenant = TENANT) {
  assert.equal(rig.spy.count("commitRestore"), 0, "no commit was attempted");
  const used = await rig.used(captured.tokens.map(({ token }) => token), tenant);
  assert.deepEqual(used, captured.tokens.map(() => 0));
  assert.equal(rig.memory.control.counts().receipts, 0);
}

test("restore: a token of another tenant is unknown-token; the other tenant's rows are never read", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await denied(rig.vault.restore(restoreRequest(captured, { context: CTX_B })), "unknown-token");
  const reads = rig.spy.of("readEntries");
  assert.equal(reads.length, 1);
  assert.deepEqual(reads[0].input.scope, { namespace: NAMESPACE, tenant: OTHER_TENANT });
  assert.equal(reads[0].result.entries.length, 0);
  assert.equal(rig.keys.stats.unwrap, 0);
  await assertNothingConsumed(rig, captured);
  assert.deepEqual(rig.audits.at(-1), {
    operation: "restore",
    outcome: "denied",
    at: rig.clock.now(),
    principalId: CTX_B.principal.id,
    tenant: OTHER_TENANT,
    sink: SINK,
    purpose: PURPOSE,
    reason: "unknown-token",
    attemptId: rig.audits.at(-1).attemptId,
  });
});

test("restore: a token of a capture the request does not name is denied source, before any key is unwrapped", async () => {
  const rig = await createRig();
  const first = await captureOne(rig);
  const second = await captureOne(rig, { text: `other ${SECRET_B}` });
  await denied(rig.vault.restore(restoreRequest(first, { fields: { body: second.text } })), "source");
  await denied(rig.vault.restore(restoreRequest(second, { captures: [ABSENT_CAPTURE] })), "source");
  // Naming one of two captures used is not enough.
  await denied(rig.vault.restore(restoreRequest(first, { fields: { body: `${first.text} ${second.text}` } })), "source");
  assert.equal(rig.keys.stats.unwrap, 0);
  await assertNothingConsumed(rig, first);
  await assertNothingConsumed(rig, second);
  // Named together, both restore, with one unwrap per capture.
  const both = await rig.vault.restore(
    restoreRequest(first, { captures: [first.captureId, second.captureId], fields: { body: `${first.text} ${second.text}` } }),
  );
  assert.equal(both.fields.body, `${ORIGINAL} other ${SECRET_B}`);
  assert.equal(rig.keys.stats.unwrap, 2);
});

test("restore: a session-bound capture is denied source from another session, with no key unwrap", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { context: ctx({ session: S1 }) });
  assert.equal(captured.sessionBound, true);
  await denied(rig.vault.restore(restoreRequest(captured, { context: ctx({ session: S2 }) })), "source");
  // Same session identifier, another tenant: its rows are simply not there.
  await denied(rig.vault.restore(restoreRequest(captured, { context: ctx({ tenant: OTHER_TENANT, session: S1 }) })), "unknown-token");
  assert.equal(rig.keys.stats.unwrap, 0, "the session tag is checked before any key is unwrapped");
  await assertNothingConsumed(rig, captured);
});

test("restore: a session-bound capture is denied source when no session resolves", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { context: ctx({ session: S1 }) });
  await denied(rig.vault.restore(restoreRequest(captured, { context: CTX_A })), "source");
  // An instance configured without a session resolver can never present a session.
  const noResolver = await rig.open({ resolveSession: undefined });
  await denied(noResolver.restore(restoreRequest(captured, { context: ctx({ session: S1 }) })), "source");
  assert.equal(rig.keys.stats.unwrap, 0);
  await assertNothingConsumed(rig, captured);
  // The same session restores it.
  const restored = await rig.vault.restore(restoreRequest(captured, { context: ctx({ session: S1 }) }));
  assert.equal(restored.fields.body, ORIGINAL);
});

test("restore: a capture that is not session-bound restores from any session of its tenant, and from none", async () => {
  const rig = await createRig();
  for (const context of [CTX_A, ctx({ session: S1 }), ctx({ session: S2 }), ctx({ id: "principal-synthetic-0009", session: S2 })]) {
    const captured = await captureOne(rig);
    assert.equal(captured.sessionBound, false);
    assert.equal((await rig.vault.restore(restoreRequest(captured, { context }))).fields.body, ORIGINAL);
  }
  const captured = await captureOne(rig);
  const noResolver = await rig.open({ resolveSession: undefined });
  assert.equal((await noResolver.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("restore: tenant and sessionId on the request cannot manufacture provenance", async () => {
  const rig = await createRig();
  const bound = await captureOne(rig, { context: ctx({ session: S1 }) });
  // The request claims the capture's session; the trusted context resolves another, or none.
  for (const context of [ctx({ session: S2 }), CTX_A]) {
    await denied(
      rig.vault.restore(restoreRequest(bound, { context, sessionId: S1, session: S1, source: { sessionId: S1 } })),
      "source",
    );
  }
  // The request claims the capture's tenant; the trusted context resolves another.
  await denied(
    rig.vault.restore(restoreRequest(bound, { context: ctx({ tenant: OTHER_TENANT, session: S1 }), tenant: TENANT, issuedTenant: TENANT })),
    "unknown-token",
  );
  for (const read of rig.spy.of("readEntries").slice(-1)) assert.equal(read.input.scope.tenant, OTHER_TENANT);
  assert.equal(rig.keys.stats.unwrap, 0);
  await assertNothingConsumed(rig, bound);

  // And the other way round: a claimed foreign tenant does not redirect a legitimate restore.
  const restored = await rig.vault.restore(restoreRequest(bound, { context: ctx({ session: S1 }), tenant: OTHER_TENANT, sessionId: S2 }));
  assert.equal(restored.tenant, TENANT);
  assert.equal(rig.spy.last("commitRestore").input.scope.tenant, TENANT);
  assert.equal(rig.policyCalls.at(-1).source.sessionId, S1);
  assert.equal(rig.policyCalls.at(-1).source.issuedTenant, TENANT);
});

test("restore: a capture past its expiry on the server's clock is denied expired, before any unwrap or commit", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  rig.clock.set(captured.expiresAt - 1);
  // One millisecond before expiry it still restores (maxUses 1, so use a second capture for the rest).
  const late = await captureOne(rig, { vault: await rig.open({ limits: { entryTtlMs: 1 } }) });
  assert.equal(late.expiresAt, captured.expiresAt);
  rig.clock.set(captured.expiresAt);
  const before = rig.keys.stats.unwrap;
  await denied(rig.vault.restore(restoreRequest(captured)), "expired");
  await denied(rig.vault.restore(restoreRequest(late)), "expired");
  rig.clock.advance(60 * 60 * 1000);
  await denied(rig.vault.restore(restoreRequest(captured)), "expired");
  assert.equal(rig.keys.stats.unwrap, before, "expiry is checked before any key is unwrapped");
  await assertNothingConsumed(rig, captured);
  await assertNothingConsumed(rig, late);
});

test("restore: one millisecond before expiry a capture still restores", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  rig.clock.set(captured.expiresAt - 1);
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("restore: expiry is judged by the server's clock in preflight and by the store's clock at commit", async () => {
  const time = { server: 1_790_000_000_000, store: 1_790_000_000_000 };
  const rig = await createRig({ clock: { now: () => time.server }, storeClock: { now: () => time.store } });
  const captured = await captureOne(rig);

  // Server clock past expiry, store clock not (inside the skew bound): the server denies by itself.
  time.server = captured.expiresAt;
  time.store = captured.expiresAt - 1500;
  await denied(rig.vault.restore(restoreRequest(captured)), "expired");
  assert.equal(rig.spy.count("commitRestore"), 0);
  assert.equal(rig.keys.stats.unwrap, 0);

  // Store clock past expiry, server clock not: preflight passes and the commit denies.
  time.server = captured.expiresAt - 1500;
  time.store = captured.expiresAt;
  // (A fresh instance: a server's clock never goes back within one instance.)
  const behind = await rig.open();
  await denied(behind.restore(restoreRequest(captured)), "expired");
  assert.equal(rig.spy.count("commitRestore"), 1);
  assert.deepEqual(rig.spy.last("commitRestore").result, { outcome: "rejected", reason: "expired" });
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [0]);
  assert.equal(rig.memory.control.counts().receipts, 0);
});

test("restore: a sink or a path the capture did not grant is denied sink-or-path", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 2, release: [{ sink: SINK, paths: ["body"] }, { sink: "sink-b", paths: ["note"] }] });
  await denied(rig.vault.restore(restoreRequest(captured, { sink: "sink-c" })), "sink-or-path");
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { subject: captured.text } })), "sink-or-path");
  // A path granted to another sink does not count.
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { note: captured.text } })), "sink-or-path");
  await denied(rig.vault.restore(restoreRequest(captured, { sink: "sink-b", fields: { body: captured.text } })), "sink-or-path");
  // One granted path and one that is not: the whole request is denied.
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: captured.text, subject: captured.text } })), "sink-or-path");
  assert.equal(rig.policyCalls.length, 0, "grants are checked before the policy is asked");
  await assertNothingConsumed(rig, captured);
  const restored = await rig.vault.restore(restoreRequest(captured, { sink: "sink-b", fields: { note: captured.text } }));
  assert.equal(restored.fields.note, ORIGINAL);
});

test("restore: an empty purpose is denied missing-purpose before any store read or unwrap", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await denied(rig.vault.restore(restoreRequest(captured, { purpose: "" })), "missing-purpose");
  assert.equal(rig.spy.count("readEntries"), 0);
  assert.equal(rig.keys.stats.unwrap, 0);
  assert.equal(rig.policyCalls.length, 0);
  await assertNothingConsumed(rig, captured);
  // No token in the fields does not excuse a missing purpose.
  await denied(rig.vault.restore(restoreRequest(captured, { purpose: "", fields: { body: "no token here" } })), "missing-purpose");
  for (const purpose of [undefined, null, 7, "p".repeat(1025), "purpose-\ud800-lone"]) {
    await rejects(rig.vault.restore(restoreRequest(captured, { purpose })), "INVALID_ARGUMENT");
  }
});

test("restore: a policy deny, throw, rejection, timeout, malformed return, or unknown reason is a denial with nothing consumed", async () => {
  const rig = await createRig({ vault: { policyTimeoutMs: 25 } });
  const captured = await captureOne(rig);
  const cases = [
    [() => ({ allow: false, reason: "policy" }), "policy"],
    [() => ({ allow: false, reason: "rate-limited" }), "rate-limited"],
    [() => ({ allow: false, reason: "tenant-mismatch" }), "tenant-mismatch"],
    [async () => ({ allow: false, reason: "stale-policy" }), "stale-policy"],
    [() => ({ allow: false, reason: "synthetic-unknown-reason" }), "policy-evaluation-error"],
    [() => ({ allow: false, reason: SECRET_A }), "policy-evaluation-error"],
    [() => ({ allow: false }), "policy-evaluation-error"],
    [() => ({ allow: false, reason: 7 }), "policy-evaluation-error"],
    // Reasons only the server itself may report.
    [() => ({ allow: false, reason: "attempt-already-committed" }), "policy-evaluation-error"],
    [() => ({ allow: false, reason: "integrity-failure" }), "policy-evaluation-error"],
    [
      () => {
        throw foreignError();
      },
      "policy-evaluation-error",
    ],
    [() => Promise.reject(foreignError()), "policy-evaluation-error"],
    [() => new Promise(() => {}), "policy-evaluation-error"],
    [() => true, "policy-evaluation-error"],
    [() => null, "policy-evaluation-error"],
    [() => undefined, "policy-evaluation-error"],
    [() => ({}), "policy-evaluation-error"],
    [() => ({ allow: "true" }), "policy-evaluation-error"],
    [() => ({ allow: 1 }), "policy-evaluation-error"],
    [() => "allow", "policy-evaluation-error"],
  ];
  for (const [policy, reason] of cases) {
    rig.policy = policy;
    await denied(rig.vault.restore(restoreRequest(captured)), reason);
    const audit = rig.audits.at(-1);
    assert.equal(audit.reason, reason);
    assert.equal(audit.operation, reason === "policy-evaluation-error" ? "policy-error" : "restore");
    assert.equal(audit.outcome, reason === "policy-evaluation-error" ? "failed" : "denied");
  }
  assert.equal(rig.policyCalls.length, cases.length);
  await assertNothingConsumed(rig, captured);
});

test("restore: the policy is asked once per entry and path, with the decision input the specification names", async () => {
  let revision = "policy-rev-synthetic-1";
  const rig = await createRig({ vault: { policyRevision: () => revision } });
  const session = S1;
  const captured = await captureOne(rig, {
    text: `first ${SECRET_A} second ${SECRET_B}`,
    maxUses: 3,
    context: ctx({ session }),
  });
  const [a, b] = captured.tokens;
  // The revision in effect now differs from the one stamped at capture.
  revision = "policy-rev-synthetic-2";
  rig.clock.advance(1234);
  // Prime `used` of the first entry to 1 so the input is not all zeros.
  await rig.vault.restore(restoreRequest(captured, { context: ctx({ session }), fields: { body: a.token } }));
  rig.policyCalls.length = 0;
  rig.clock.advance(1000);

  const restored = await rig.vault.restore(
    restoreRequest(captured, { context: ctx({ session }), fields: { body: `${a.token} ${b.token} ${a.token}`, subject: b.token } }),
  );
  assert.equal(restored.fields.body, `${SECRET_A} ${SECRET_B} ${SECRET_A}`);
  assert.equal(restored.fields.subject, SECRET_B);
  assert.equal(restored.restored, 4);

  const principal = { id: "principal-synthetic-0001", tenant: TENANT };
  const common = {
    principal,
    tenant: TENANT,
    source: { captureId: captured.captureId, issuedTenant: TENANT, sessionId: session },
    sink: SINK,
    purpose: PURPOSE,
    maxUses: 3,
    policyRevision: "policy-rev-synthetic-1",
    requestedAt: rig.clock.now(),
  };
  const byKey = (input) => `${input.type}/${input.path}/${input.totalOccurrences}/${input.used}`;
  assert.deepEqual(
    [...rig.policyCalls].sort((x, y) => byKey(x).localeCompare(byKey(y))),
    [
      { ...common, path: "body", type: a.type, occurrences: 2, totalOccurrences: 2, used: 1 },
      { ...common, path: "body", type: b.type, occurrences: 1, totalOccurrences: 2, used: 0 },
      { ...common, path: "subject", type: b.type, occurrences: 1, totalOccurrences: 2, used: 0 },
    ].sort((x, y) => byKey(x).localeCompare(byKey(y))),
  );
  for (const input of rig.policyCalls) {
    assert.ok(Object.isFrozen(input) && Object.isFrozen(input.source));
    assert.equal(JSON.stringify(input).includes(SECRET_A) || JSON.stringify(input).includes(a.token), false);
  }
  assert.deepEqual(await rig.used([a.token, b.token]), [3, 2]);
});

test("restore: a capture that is not session-bound, or has no stamped revision, shows neither to the policy", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await rig.vault.restore(restoreRequest(captured, { context: ctx({ session: S1 }) }));
  const [input] = rig.policyCalls;
  assert.deepEqual(input.source, { captureId: captured.captureId, issuedTenant: TENANT });
  assert.equal("policyRevision" in input, false);
  // A fixed string revision is stamped unchanged.
  const fixed = await rig.open({ policyRevision: "policy-rev-synthetic-fixed" });
  const stamped = await captureOne(rig, { vault: fixed });
  await fixed.restore(restoreRequest(stamped));
  assert.equal(rig.policyCalls.at(-1).policyRevision, "policy-rev-synthetic-fixed");
});

test("restore: a policy revision that changes between the policy call and the commit is denied stale-policy", async () => {
  let revision = "policy-rev-synthetic-1";
  const rig = await createRig({ vault: { policyRevision: () => revision } });
  const captured = await captureOne(rig);
  rig.policy = () => {
    revision = "policy-rev-synthetic-2";
    return { allow: true };
  };
  await denied(rig.vault.restore(restoreRequest(captured)), "stale-policy");
  await assertNothingConsumed(rig, captured);
  // A revision that is stable across the call restores, whatever it was at capture.
  rig.policy = () => ({ allow: true });
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("restore: malformed token markers are denied malformed-token with no store call", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const token = captured.tokens[0].token;
  const malformed = [
    "<rsv_short>",
    "rsv_",
    token.toUpperCase(),
    token.slice(0, -1),
    token.slice(1),
    `${token.slice(0, 3)}​${token.slice(3)}`,
    `${token} and <rsv_${"a".repeat(25)}>`,
    `<rsv_${"A".repeat(26)}>`,
    `<rsv_${"1".repeat(26)}>`,
    `<RsV_${"a".repeat(26)}>`,
  ];
  for (const text of malformed) {
    await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: text } })), "malformed-token");
  }
  // One well-formed field does not excuse a malformed one.
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: captured.text, subject: "rsv_" } })), "malformed-token");
  assert.equal(rig.spy.count("readEntries"), 0);
  await assertNothingConsumed(rig, captured);
});

test("restore: a forged token of valid grammar is unknown-token, and denies the whole request", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: FORGED_TOKEN } })), "unknown-token");
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: `${captured.text} ${FORGED_TOKEN}` } })), "unknown-token");
  await denied(rig.vault.restore(restoreRequest(captured, { fields: { body: captured.text, subject: FORGED_TOKEN } })), "unknown-token");
  assert.equal(rig.keys.stats.unwrap, 0);
  await assertNothingConsumed(rig, captured);
});

test("restore: a request with no token returns its fields unchanged, with no store call and no attempt", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  rig.spy.reset();
  const fields = { body: "plain synthetic text", subject: "", note: "<not a token>" };
  const restored = await rig.vault.restore(restoreRequest(captured, { fields, attemptId: "attempt-synthetic-0001" }));
  assert.deepEqual(restored.fields, fields);
  assert.notEqual(restored.fields, fields);
  assert.ok(Object.isFrozen(restored.fields));
  assert.equal(restored.restored, 0);
  assert.equal("attemptId" in restored, false);
  assert.equal(rig.spy.calls.length, 0, "no store call");
  assert.equal(rig.policyCalls.length, 0);
  assert.equal(rig.memory.control.counts().receipts, 0);
  // The attempt identifier was not recorded: it is still free.
  assert.deepEqual(await rig.vault.resolveAttempt(restoreRequest(captured, { fields, attemptId: "attempt-synthetic-0001" })), { state: "absent" });
  // It still needs an authenticated principal.
  await denied(rig.vault.restore(restoreRequest(captured, { fields, context: {} })), "unauthenticated");
});

test("restore: an unresolved principal or session is denied unauthenticated, before any store call", async () => {
  const rig = await createRig({ vault: { resolverTimeoutMs: 25 } });
  const captured = await captureOne(rig);
  rig.spy.reset();
  const contexts = [
    undefined,
    null,
    {},
    { principal: { id: "principal-synthetic-0001" } },
    { principal: { id: "principal-synthetic-0001", tenant: "" } },
    { principal: { id: "principal-synthetic-0001", tenant: "tenant-\ud800-lone" } },
    { principal: new Promise(() => {}) },
    { ...CTX_A, session: 7 },
    { ...CTX_A, session: "" },
    { ...CTX_A, session: new Promise(() => {}) },
  ];
  for (const context of contexts) {
    await denied(rig.vault.restore(restoreRequest(captured, { context })), "unauthenticated");
    assert.equal(rig.audits.at(-1).operation, "resolve-principal");
    assert.equal("principalId" in rig.audits.at(-1), false);
  }
  const throwing = await rig.open({
    resolvePrincipal: () => {
      throw foreignError();
    },
  });
  await denied(throwing.restore(restoreRequest(captured)), "unauthenticated");
  const throwingSession = await rig.open({
    resolveSession: async () => {
      throw foreignError();
    },
  });
  await denied(throwingSession.restore(restoreRequest(captured)), "unauthenticated");
  assert.equal(rig.spy.calls.filter((call) => call.operation !== "recoveryState").length, 0);
});

test("restore: a malformed request is INVALID_ARGUMENT; a malformed field set is denied invalid-request", async () => {
  const rig = await createRig({ vault: { limits: { maxRestoreFields: 2, maxRestoreFieldBytes: 64 } } });
  const captured = await captureOne(rig);
  rig.spy.reset();
  await rejects(rig.vault.restore(null), "INVALID_ARGUMENT");
  await rejects(rig.vault.restore("request"), "INVALID_ARGUMENT");
  const invalid = [
    { sink: "" },
    { sink: 7 },
    { sink: "s".repeat(257) },
    { sink: "sink-\ud800-lone" },
    { captures: [] },
    { captures: "cap" },
    { captures: [captured.captureId, "cap_short"] },
    { captures: [7] },
    { captures: Array.from({ length: 65 }, () => captured.captureId) },
    { fields: null },
    { fields: "fields" },
    { fields: [captured.text] },
    { attemptId: "" },
    { attemptId: "has space" },
    { attemptId: "a".repeat(129) },
    { attemptId: 7 },
    { requestId: 7 },
  ];
  for (const extra of invalid) await rejects(rig.vault.restore(restoreRequest(captured, extra)), "INVALID_ARGUMENT");

  const getter = {};
  Object.defineProperty(getter, "body", { enumerable: true, get: () => captured.text });
  const deniedShapes = [
    { body: 7 },
    { body: null },
    { body: captured.text, subject: ["x"] },
    getter,
    { "": captured.text },
    { ["p".repeat(257)]: captured.text },
    { body: "a", subject: "b", note: "c" },
    { body: "x".repeat(65) },
  ];
  for (const fields of deniedShapes) await denied(rig.vault.restore(restoreRequest(captured, { fields })), "invalid-request");
  assert.equal(rig.spy.calls.length, 0);
  await assertNothingConsumed(rig, captured);
});

test("restore: more tokens or captures than the store's bounds is refused before any store call", async () => {
  const rig = await createRig({ memoryOptions: { maxRestoreEntries: 1, maxRestoreCaptures: 2 } });
  const captured = await captureOne(rig, { text: `first ${SECRET_A} second ${SECRET_B}` });
  rig.spy.reset();
  await denied(rig.vault.restore(restoreRequest(captured)), "invalid-request");
  await rejects(
    rig.vault.restore(restoreRequest(captured, { captures: [captured.captureId, ABSENT_CAPTURE, "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb"] })),
    "INVALID_ARGUMENT",
  );
  assert.equal(rig.spy.calls.length, 0);
  // One token is within the bound.
  const one = await rig.vault.restore(restoreRequest(captured, { fields: { body: captured.tokens[0].token } }));
  assert.equal(one.fields.body, SECRET_A);
});

test("restore: a revoked capture is denied revoked and an exhausted entry is denied budget, both before any unwrap", async () => {
  const rig = await createRig();
  const revoked = await captureOne(rig);
  assert.equal((await rig.vault.revoke({ context: CTX_A, captureId: revoked.captureId })).outcome, "revoked");
  await denied(rig.vault.restore(restoreRequest(revoked)), "revoked");
  assert.equal(rig.keys.stats.unwrap, 0);
  assert.equal(rig.spy.count("commitRestore"), 0);

  const single = await captureOne(rig);
  await rig.vault.restore(restoreRequest(single));
  const unwraps = rig.keys.stats.unwrap;
  const commits = rig.spy.count("commitRestore");
  await denied(rig.vault.restore(restoreRequest(single)), "budget");
  assert.equal(rig.keys.stats.unwrap, unwraps, "the row budget is checked before any key is unwrapped");
  assert.equal(rig.spy.count("commitRestore"), commits, "and before any commit");
  assert.deepEqual(await rig.used([single.tokens[0].token]), [1]);
});

test("restore: the preflight denials are reported in the specification's order", async () => {
  const rig = await createRig();
  // Revoked comes before source.
  const revoked = await captureOne(rig);
  await rig.vault.revoke({ context: CTX_A, captureId: revoked.captureId });
  await denied(rig.vault.restore(restoreRequest(revoked, { captures: [ABSENT_CAPTURE] })), "revoked");
  // Unknown comes before revoked.
  await denied(rig.vault.restore(restoreRequest(revoked, { fields: { body: `${revoked.text} ${FORGED_TOKEN}` } })), "unknown-token");
  // Source comes before the session, the session before expiry, expiry before budget.
  const bound = await captureOne(rig, { context: ctx({ session: S1 }) });
  await rig.vault.restore(restoreRequest(bound, { context: ctx({ session: S1 }) }));
  rig.clock.set(bound.expiresAt + 1);
  await denied(rig.vault.restore(restoreRequest(bound, { context: ctx({ session: S2 }), captures: [ABSENT_CAPTURE] })), "source");
  await denied(rig.vault.restore(restoreRequest(bound, { context: ctx({ session: S2 }) })), "source");
  await denied(rig.vault.restore(restoreRequest(bound, { context: ctx({ session: S1 }) })), "expired");
});

test("restore: a key provider failure is a denial with nothing consumed and no second provider call", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  // Only the provider that never answers needs a short deadline; real WebCrypto work gets the default one.
  const impatient = await rig.open({ cryptoTimeoutMs: 40 });
  const cases = [
    [
      () => {
        throw foreignError();
      },
      "key-unavailable",
    ],
    [
      () => {
        throw new KeyProviderError("KEY_UNAVAILABLE");
      },
      "key-unavailable",
    ],
    [
      () => {
        throw new KeyProviderError("KEY_THROTTLED");
      },
      "key-unavailable",
    ],
    [
      () => {
        throw new KeyProviderError("KEY_INTEGRITY");
      },
      "integrity-failure",
    ],
    [() => new Promise(() => {}), "key-unavailable", impatient],
    [() => new Uint8Array(16), "key-unavailable"],
    [() => "not-bytes", "key-unavailable"],
    // A data key that is not this capture's: authentication fails.
    [() => new Uint8Array(32).fill(7), "integrity-failure"],
  ];
  for (const [failure, reason, vault = rig.vault] of cases) {
    rig.keys.fail.unwrap = failure;
    await denied(vault.restore(restoreRequest(captured)), reason);
  }
  assert.equal(rig.keys.stats.unwrap, cases.length, "one unwrap per restore: no retry, no fallback");
  assert.equal(rig.policyCalls.length, 0);
  await assertNothingConsumed(rig, captured);
  rig.keys.fail.unwrap = undefined;
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("restore: an instance holding other key material, another key reference, or another digest key cannot restore", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const bound = await captureOne(rig, { context: ctx({ session: S1 }) });

  const otherMaterial = createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "synthetic-2026-10", material: new Uint8Array(32).fill(0x11), state: "active" }],
      scope: { namespaces: [NAMESPACE] },
    }),
  });
  await denied((await rig.open({ crypto: otherMaterial })).restore(restoreRequest(captured)), "integrity-failure");

  const otherReference = createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "synthetic-2027-01", material: new Uint8Array(32).fill(0x11), state: "active" }],
      scope: { namespaces: [NAMESPACE] },
    }),
  });
  await denied((await rig.open({ crypto: otherReference })).restore(restoreRequest(captured)), "key-unavailable");

  const outOfScope = createRecordCrypto({
    keyProvider: createLocalKeyProvider({
      keys: [{ id: "synthetic-2026-10", material: new Uint8Array(32).fill(0x11), state: "active" }],
      scope: { namespaces: ["another-namespace-synthetic"] },
    }),
  });
  await denied((await rig.open({ crypto: outOfScope })).restore(restoreRequest(captured)), "key-unavailable");

  // §7.3: a session-bound capture made under one digest key is denied source under another.
  const otherDigestKey = await rig.open({ digestKey: new Uint8Array(32).fill(0x22) });
  await denied(otherDigestKey.restore(restoreRequest(bound, { context: ctx({ session: S1 }) })), "source");
  const unkeyed = await rig.open({ digestKey: undefined, allowUnkeyedDigests: true });
  await denied(unkeyed.restore(restoreRequest(bound, { context: ctx({ session: S1 }) })), "source");

  await assertNothingConsumed(rig, captured);
  await assertNothingConsumed(rig, bound);
});

test("restore: the result carries the request's paths, frozen, and one unwrap serves every entry of a capture", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { text: `first ${SECRET_A} second ${SECRET_B}` });
  const restored = await rig.vault.restore(
    restoreRequest(captured, { fields: { body: captured.text, subject: "no token" }, requestId: "request-synthetic-0001" }),
  );
  assert.deepEqual(Object.keys(restored.fields), ["body", "subject"]);
  assert.equal(restored.fields.body, `first ${SECRET_A} second ${SECRET_B}`);
  assert.equal(restored.fields.subject, "no token");
  assert.ok(Object.isFrozen(restored) && Object.isFrozen(restored.fields));
  assert.equal(restored.restored, 2);
  assert.match(restored.attemptId, /^[A-Za-z0-9._:-]{1,128}$/);
  assert.equal(rig.keys.stats.unwrap, 1);
  assert.deepEqual(rig.audits.at(-1), {
    operation: "restore",
    outcome: "committed",
    at: rig.clock.now(),
    principalId: CTX_A.principal.id,
    tenant: TENANT,
    sink: SINK,
    purpose: PURPOSE,
    entries: 2,
    attemptId: restored.attemptId,
    requestId: "request-synthetic-0001",
  });
});

test("restore: a path named like an Object.prototype member is an ordinary own property of the result", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig, { maxUses: 3, release: [{ sink: SINK, paths: ["__proto__", "constructor", "toString"] }] });
  const fields = JSON.parse(
    `{"__proto__": ${JSON.stringify(captured.text)}, "constructor": ${JSON.stringify(captured.text)}, "toString": ${JSON.stringify(captured.text)}}`,
  );
  const restored = await rig.vault.restore(restoreRequest(captured, { fields }));
  assert.deepEqual(Object.keys(restored.fields), ["__proto__", "constructor", "toString"]);
  for (const path of Object.keys(restored.fields)) {
    assert.equal(Object.getOwnPropertyDescriptor(restored.fields, path).value, ORIGINAL);
  }
  assert.equal(Object.getPrototypeOf(restored.fields), Object.prototype);
  assert.equal(typeof {}.toString, "function", "Object.prototype is untouched");
  assert.deepEqual(rig.policyCalls.map((input) => input.path).sort(), ["__proto__", "constructor", "toString"]);
});

test("restore: a token of another namespace over the same store is unknown-token", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  const otherNamespace = "billing-synthetic";
  assert.equal((await rig.memory.store.initializeNamespace({ namespace: otherNamespace, epoch: 1 })).outcome, "initialized");
  const other = await rig.open({
    namespace: otherNamespace,
    crypto: createRecordCrypto({
      keyProvider: createLocalKeyProvider({
        keys: [{ id: "synthetic-2026-10", material: new Uint8Array(32).fill(0x33), state: "active" }],
        scope: { namespaces: [otherNamespace] },
      }),
    }),
  });
  await denied(other.restore(restoreRequest(captured)), "unknown-token");
  assert.deepEqual(rig.spy.last("readEntries").input.scope, { namespace: otherNamespace, tenant: TENANT });
  // Even a store that hands the other namespace's rows over cannot make them restorable: they are not the entries asked for.
  const rows = await rig.rows([captured.tokens[0].token]);
  rig.spy.tamper.readEntries = (result, input) =>
    input.scope.namespace === otherNamespace ? { ...result, entries: rows.entries, captures: rows.captures } : result;
  await rejects(other.restore(restoreRequest(captured)), "INVARIANT_VIOLATION");
  // Relabelled with the entry identifier the other namespace derived, they do not authenticate.
  rig.spy.tamper.readEntries = (result, input) =>
    input.scope.namespace === otherNamespace
      ? { ...result, entries: rows.entries.map((entry) => ({ ...entry, entryId: input.entryIds[0] })), captures: rows.captures }
      : result;
  const error = await rejects(other.restore(restoreRequest(captured)), "RESTORE_DENIED");
  assert.ok(["key-unavailable", "integrity-failure"].includes(error.reason));
  rig.spy.tamper.readEntries = undefined;
  await assertNothingConsumed(rig, captured);
  // The other namespace quarantined does not stop this one.
  await rig.memory.store.quarantine({ namespace: otherNamespace });
  assert.equal((await rig.vault.restore(restoreRequest(captured))).fields.body, ORIGINAL);
});

test("restore: an instance with unkeyed digests round-trips its own session-bound captures", async () => {
  const rig = await createRig({ vault: { digestKey: undefined, allowUnkeyedDigests: true } });
  const captured = await captureOne(rig, { context: ctx({ session: S1 }) });
  await denied(rig.vault.restore(restoreRequest(captured, { context: ctx({ session: S2 }) })), "source");
  assert.equal((await rig.vault.restore(restoreRequest(captured, { context: ctx({ session: S1 }) }))).fields.body, ORIGINAL);
});

test("restore: the commit carries the read's revisions, the configured epoch, and a receipt expiry of latest expiry + skew + grace", async () => {
  const rig = await createRig();
  const early = await captureOne(rig);
  rig.clock.advance(5000);
  const late = await captureOne(rig, { text: `other ${SECRET_B}` });
  rig.clock.advance(1000);
  await rig.vault.restore(
    restoreRequest(early, { captures: [early.captureId, late.captureId], fields: { body: early.text, subject: late.text } }),
  );
  const { input } = rig.spy.last("commitRestore");
  assert.deepEqual(input.scope, { namespace: NAMESPACE, tenant: TENANT });
  assert.equal(input.epoch, 1);
  assert.equal(input.now, rig.clock.now());
  assert.equal(input.receiptExpiresAt, late.expiresAt + 2000 + 60 * 60 * 1000);
  assert.deepEqual(
    [...input.captures].sort((x, y) => x.captureId.localeCompare(y.captureId)),
    [
      { captureId: early.captureId, generation: 1 },
      { captureId: late.captureId, generation: 1 },
    ].sort((x, y) => x.captureId.localeCompare(y.captureId)),
  );
  assert.deepEqual(
    input.uses.map((use) => [use.captureId, use.count, use.lifecycleRevision, use.ciphertextRevision]).sort(),
    [
      [early.captureId, 1, 1, 1],
      [late.captureId, 1, 1, 1],
    ].sort(),
  );
  assert.ok(input.attempt.requestDigest instanceof Uint8Array && input.attempt.requestDigest.byteLength === 32);
  // A configured grace is used as given.
  const graced = await rig.open({ receiptGraceMs: 0 });
  const third = await captureOne(rig, { vault: graced });
  await graced.restore(restoreRequest(third));
  assert.equal(rig.spy.last("commitRestore").input.receiptExpiresAt, third.expiresAt + 2000);
});

registerLeakHygiene({ minErrors: 100 });
