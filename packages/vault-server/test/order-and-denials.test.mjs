// Every denial class and the exact evaluation order fixed by
// docs/decisions/2026-09-27-define-server-authority-interface.md §3:
// 1 principal, 2 marker/known-entry (+ revoked), 3 source, 4 tenant, 5
// expiry, 6 sink/path, 7 purpose, 8 budget, 9 ServerReleasePolicy.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultServerError } from "../dist/index.js";
import { allowAll, captureOne, manualClock, openServer, staticResolver } from "./helpers.mjs";

async function expectDenied(promise, reason) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof VaultServerError);
    assert.equal(error.code, "RESTORE_DENIED");
    assert.equal(error.reason, reason);
    return true;
  });
}

test("unauthenticated: a resolver that throws denies the whole request, never touching the vault", async () => {
  const { server } = await openServer({
    resolvePrincipal: () => {
      throw new Error("no session");
    },
  });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "unauthenticated",
  );
});

test("unauthenticated: a resolver returning a partial/malformed principal also denies", async () => {
  const { server } = await openServer({ resolvePrincipal: () => ({ id: "only-id" }) }); // no tenant
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "unauthenticated",
  );
});

test("unauthenticated is checked before known-entry: a forged token with a failing resolver still denies unauthenticated", async () => {
  const { server } = await openServer({
    resolvePrincipal: () => {
      throw new Error("nope");
    },
  });
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: ["cap_forged"], fields: { body: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" } }),
    "unauthenticated",
  );
});

test("malformed-token: a marker present without an exact token wrapping it", async () => {
  const { server } = await openServer();
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: ["cap_x"], fields: { body: "look: rsv_notatoken" } }),
    "malformed-token",
  );
});

test("unknown-token: a well-formed but never-issued token", async () => {
  const { server } = await openServer();
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: ["cap_x"], fields: { body: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" } }),
    "unknown-token",
  );
});

test("revoked: distinct from unknown-token, reported for a short-lived window after revoke()", async () => {
  const { server } = await openServer({ revocationMemoryMs: 60_000 });
  const captured = await captureOne(server);
  const removed = await server.revoke(captured.captureId);
  assert.equal(removed, 1);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "revoked",
  );
});

test("revoked ages out to unknown-token once the revocation memory window passes", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, revocationMemoryMs: 1000 });
  const captured = await captureOne(server);
  await server.revoke(captured.captureId);
  clock.advance(2000);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "unknown-token",
  );
});

test("source: a live token whose capture is not listed in `captures`", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server);
  const other = await captureOne(server, { text: "other secret ghp_SYNTHETICxREVOKEDxTESTx2222222222222" });
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [other.captureId], fields: { body: captured.text } }),
    "source",
  );
});

test("tenant-mismatch: principal tenant differs from the capture's issuedTenant, even with an allow-all policy", async () => {
  const { server } = await openServer({
    resolvePrincipal: staticResolver({ id: "user-synthetic-2", tenant: "tenant-northwind-synthetic" }),
    policy: allowAll,
  });
  const captured = await captureOne(server, { issuedTenant: "tenant-acme-synthetic" });
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "tenant-mismatch",
  );
});

test("an explicit `tenant` override on the request is compared, not the principal's own tenant", async () => {
  const { server } = await openServer({
    resolvePrincipal: staticResolver({ id: "support-agent-synthetic", tenant: "tenant-support-tooling-synthetic" }),
  });
  const captured = await captureOne(server, { issuedTenant: "tenant-acme-synthetic" });
  const { fields } = await server.restore({
    context: {},
    tenant: "tenant-acme-synthetic",
    sink: "sink-a",
    purpose: "support-reply",
    captures: [captured.captureId],
    fields: { body: captured.text },
  });
  assert.match(fields.body, /ghp_SYNTHETIC/);
});

test("expired: checked at use time against the capture's TTL", async () => {
  const clock = manualClock();
  const { server } = await openServer({ clock, limits: { entryTtlMs: 1000 } });
  const captured = await captureOne(server);
  clock.advance(2000);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "expired",
  );
});

test("sink-or-path: a sink or path outside the capture's grant", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server, { release: [{ sink: "sink-a", paths: ["body"] }] });
  await expectDenied(
    server.restore({ context: {}, sink: "sink-b", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "sink-or-path",
  );
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { subject: captured.text } }),
    "sink-or-path",
  );
});

test("missing-purpose: an empty purpose denies before the policy ever runs", async () => {
  let policyCalled = false;
  const { server } = await openServer({
    policy: () => {
      policyCalled = true;
      return { allow: true };
    },
  });
  const captured = await captureOne(server);
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "", captures: [captured.captureId], fields: { body: captured.text } }),
    "missing-purpose",
  );
  assert.equal(policyCalled, false, "policy must not run once an earlier check has already denied");
});

test("budget: a token's maxUses is enforced across occurrences in one request", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server, { maxUses: 1 });
  const twice = `${captured.text} ${captured.text}`;
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: twice } }),
    "budget",
  );
});

test("budget is checked, and denies, before the policy runs for an over-budget request", async () => {
  let policyCalled = false;
  const { server } = await openServer({
    policy: () => {
      policyCalled = true;
      return { allow: true };
    },
  });
  const captured = await captureOne(server, { maxUses: 1 });
  await server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } });
  policyCalled = false;
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "unknown-token", // consumed on first use (maxUses: 1) and removed from the shadow registry
  );
  assert.equal(policyCalled, false);
});

test("ordering: tenant-mismatch is reported over a simultaneously-true expired condition", async () => {
  const clock = manualClock();
  const { server } = await openServer({
    clock,
    limits: { entryTtlMs: 1000 },
    resolvePrincipal: staticResolver({ id: "user-synthetic-3", tenant: "tenant-northwind-synthetic" }),
  });
  const captured = await captureOne(server, { issuedTenant: "tenant-acme-synthetic" });
  clock.advance(2000); // now also expired
  await expectDenied(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    "tenant-mismatch",
  );
});

test("ordering: sink-or-path is reported over a simultaneously-true missing-purpose condition", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server, { release: [{ sink: "sink-a", paths: ["body"] }] });
  await expectDenied(
    server.restore({ context: {}, sink: "sink-wrong", purpose: "", captures: [captured.captureId], fields: { body: captured.text } }),
    "sink-or-path",
  );
});

test("all-or-nothing: one bad field denies every field in the request, with no partial plaintext", async () => {
  const { server } = await openServer();
  const good = await captureOne(server, { text: "good secret ghp_SYNTHETICxREVOKEDxTESTx3333333333333" });
  await expectDenied(
    server.restore({
      context: {},
      sink: "sink-a",
      purpose: "p",
      captures: [good.captureId],
      fields: { body: good.text, other: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" },
    }),
    "unknown-token",
  );
  // The good token must still be live and usable afterward — the denied
  // request must not have consumed its budget.
  const { fields } = await server.restore({
    context: {},
    sink: "sink-a",
    purpose: "p",
    captures: [good.captureId],
    fields: { body: good.text },
  });
  assert.match(fields.body, /ghp_SYNTHETIC/);
});
