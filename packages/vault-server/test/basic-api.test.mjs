import assert from "node:assert/strict";
import test from "node:test";

import { createServerVault, VaultServerError } from "../dist/index.js";
import { allowAll, captureOne, openServer, staticResolver } from "./helpers.mjs";

test("createServerVault requires resolvePrincipal and policy", async () => {
  await assert.rejects(createServerVault({ policy: allowAll }), (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT");
  await assert.rejects(
    createServerVault({ resolvePrincipal: staticResolver({ id: "u", tenant: "t" }) }),
    (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT",
  );
});

test("capture requires issuedTenant and rejects a malformed one", async () => {
  const { server } = await openServer();
  await assert.rejects(
    server.capture("hello", { release: [{ sink: "s", paths: ["p"] }] }),
    (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT",
  );
  await assert.rejects(
    server.capture("hello", { release: [{ sink: "s", paths: ["p"] }], issuedTenant: "" }),
    (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT",
  );
});

test("a structurally invalid restore request throws INVALID_ARGUMENT, not RESTORE_DENIED", async () => {
  const { server } = await openServer();
  await assert.rejects(server.restore(null), (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT");
  await assert.rejects(
    server.restore({ context: {}, sink: "", purpose: "p", captures: ["c"], fields: {} }),
    (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT",
  );
  await assert.rejects(
    server.restore({ context: {}, sink: "s", purpose: "p", captures: [], fields: {} }),
    (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT",
  );
  await assert.rejects(
    server.restore({ context: {}, sink: "s", purpose: 42, captures: ["c"], fields: {} }),
    (e) => e instanceof VaultServerError && e.code === "INVALID_ARGUMENT",
  );
});

test("a getter on the fields object is rejected without being invoked (own-data-properties snapshot only)", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server);
  let invoked = false;
  const fields = {};
  Object.defineProperty(fields, "body", {
    enumerable: true,
    get() {
      invoked = true;
      return captured.text;
    },
  });
  await assert.rejects(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields }),
    (e) => e instanceof VaultServerError && e.code === "RESTORE_DENIED" && e.reason === "invalid-request",
  );
  assert.equal(invoked, false, "a getter must never be invoked during the snapshot");
});

test("revoke on an unknown captureId is a harmless no-op, returning 0", async () => {
  const { server } = await openServer();
  assert.equal(await server.revoke("cap_never_issued"), 0);
});

test("dispose is idempotent and every later call fails DISPOSED", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server);
  await server.dispose();
  await server.dispose(); // idempotent
  await assert.rejects(server.stats.bind(server)(), (e) => e instanceof VaultServerError && e.code === "DISPOSED");
  await assert.rejects(
    server.capture("x", { release: [{ sink: "s", paths: ["p"] }], issuedTenant: "t" }),
    (e) => e instanceof VaultServerError && e.code === "DISPOSED",
  );
  await assert.rejects(
    server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
    (e) => e instanceof VaultServerError && e.code === "DISPOSED",
  );
  await assert.rejects(server.revoke(captured.captureId), (e) => e instanceof VaultServerError && e.code === "DISPOSED");
});

test("stats() reflects captures/entries and revoked-capture memory", async () => {
  const { server } = await openServer();
  assert.deepEqual(await server.stats(), { entries: 0, captures: 0, revokedCaptures: 0, disposed: false });

  const captured = await captureOne(server);
  let stats = await server.stats();
  assert.equal(stats.entries, 1);
  assert.equal(stats.captures, 1);

  await server.revoke(captured.captureId);
  stats = await server.stats();
  assert.equal(stats.entries, 0);
  assert.equal(stats.captures, 0);
  assert.equal(stats.revokedCaptures, 1);
});

test("a successful restore returns only the granted fields, unchanged apart from token substitution", async () => {
  const { server } = await openServer();
  const captured = await captureOne(server, { text: "before ghp_SYNTHETICxREVOKEDxTESTx0000000000000 after" });
  const { fields, restored } = await server.restore({
    context: {},
    sink: "sink-a",
    purpose: "p",
    captures: [captured.captureId],
    fields: { body: captured.text },
  });
  assert.equal(fields.body, "before ghp_SYNTHETICxREVOKEDxTESTx0000000000000 after");
  assert.equal(restored, 1);
});
