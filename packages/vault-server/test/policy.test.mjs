// ServerReleasePolicy: fresh evaluation per occurrence, fail-closed on
// throw/reject/timeout/malformed return, and the exact RestoreDecisionInput
// shape (docs/decisions/2026-09-27-define-server-authority-interface.md §3).
import assert from "node:assert/strict";
import test from "node:test";

import { VaultServerError } from "../dist/index.js";
import { captureOne, deferred, openServer, staticResolver } from "./helpers.mjs";

async function expectDenied(promise, reason) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.code, "RESTORE_DENIED");
    assert.equal(error.reason, reason);
    return true;
  });
}

test("a policy denial with an explicit reason is reported verbatim", async () => {
  const { server } = await openServer({ policy: () => ({ allow: false, reason: "rate-limited" }) });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "rate-limited",
  );
});

test("a policy denial with a bogus reason string is coerced to policy-evaluation-error, not forwarded verbatim", async () => {
  const { server } = await openServer({ policy: () => ({ allow: false, reason: "not-a-real-reason" }) });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "policy-evaluation-error",
  );
});

test("a throwing policy denies policy-evaluation-error, never allow-on-error", async () => {
  const { server } = await openServer({
    policy: () => {
      throw new Error("boom");
    },
  });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "policy-evaluation-error",
  );
});

test("a rejecting async policy denies policy-evaluation-error", async () => {
  const { server } = await openServer({ policy: async () => Promise.reject(new Error("nope")) });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "policy-evaluation-error",
  );
});

test("a malformed policy return value (no boolean allow) denies policy-evaluation-error", async () => {
  const { server } = await openServer({ policy: () => ({ ok: true }) });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "policy-evaluation-error",
  );
});

test("a policy that hangs past policyTimeoutMs denies policy-evaluation-error instead of hanging the queue forever", async () => {
  const never = deferred(); // intentionally never resolved
  const { server } = await openServer({ policy: () => never.promise, policyTimeoutMs: 30 });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "policy-evaluation-error",
  );
});

test("a resolver that hangs past resolverTimeoutMs denies unauthenticated", async () => {
  const never = deferred();
  const { server } = await openServer({ resolvePrincipal: () => never.promise, resolverTimeoutMs: 30 });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "unauthenticated",
  );
});

test("the decision tuple carries the fields the ADR fixes, including source and purpose", async () => {
  const seen = [];
  const { server } = await openServer({
    resolvePrincipal: staticResolver({ id: "user-synthetic-9", tenant: "tenant-acme-synthetic", attributes: { role: "support" } }),
    policy: (input) => {
      seen.push(input);
      return { allow: true };
    },
    policyRevision: "policy-rev-2026-09-27",
  });
  const captured = await captureOne(server, { issuedTenant: "tenant-acme-synthetic", maxUses: 3 });
  await server.restore({
    context: {},
    sink: "sink-a",
    purpose: "support-reply-purpose-synthetic",
    sessionId: "session-synthetic-1",
    captures: [captured.captureId],
    fields: { body: captured.text },
  });

  assert.equal(seen.length, 1);
  const input = seen[0];
  assert.equal(input.principal.id, "user-synthetic-9");
  assert.equal(input.principal.attributes.role, "support");
  assert.equal(input.tenant, "tenant-acme-synthetic");
  assert.equal(input.source.captureId, captured.captureId);
  assert.equal(input.source.issuedTenant, "tenant-acme-synthetic");
  assert.equal(input.source.sessionId, "session-synthetic-1");
  assert.equal(input.sink, "sink-a");
  assert.equal(input.path, "body");
  assert.equal(input.purpose, "support-reply-purpose-synthetic");
  assert.equal(input.occurrences, 1);
  assert.equal(input.totalOccurrences, 1);
  assert.equal(input.used, 0);
  assert.equal(input.maxUses, 3);
  assert.equal(input.policyRevision, "policy-rev-2026-09-27");
  assert.equal(typeof input.requestedAt, "number");
});

test("the policy is evaluated once per distinct path, with correct per-path and total occurrence counts", async () => {
  const seen = [];
  const { server } = await openServer({
    policy: (input) => {
      seen.push({ path: input.path, occurrences: input.occurrences, totalOccurrences: input.totalOccurrences });
      return { allow: true };
    },
  });
  const captured = await captureOne(server, {
    release: [{ sink: "sink-a", paths: ["body", "subject"] }],
    maxUses: 5,
  });
  const twiceInBody = `${captured.text} ${captured.text}`;
  await server.restore({
    context: {},
    sink: "sink-a",
    purpose: "p",
    captures: [captured.captureId],
    fields: { body: twiceInBody, subject: captured.text },
  });

  seen.sort((a, b) => a.path.localeCompare(b.path));
  assert.deepEqual(seen, [
    { path: "body", occurrences: 2, totalOccurrences: 3 },
    { path: "subject", occurrences: 1, totalOccurrences: 3 },
  ]);
});

test("policyRevision may be a rotating function, stamped per-capture at issuance and unaffected by later rotation", async () => {
  let revision = "rev-1";
  const seen = [];
  const { server } = await openServer({
    policyRevision: () => revision,
    policy: (input) => {
      seen.push(input.policyRevision);
      return { allow: true };
    },
  });
  const first = await captureOne(server, { maxUses: 2 });
  revision = "rev-2"; // rotate after the first capture, before the second
  const second = await captureOne(server, { text: "second secret ghp_SYNTHETICxREVOKEDxTESTx4444444444444", maxUses: 2 });

  await server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [first.captureId], fields: { body: first.text } });
  await server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [second.captureId], fields: { body: second.text } });

  assert.deepEqual(seen, ["rev-1", "rev-2"]);
});
