// Cross-tenant isolation and the no-plaintext-in-diagnostics invariant,
// mirroring @redact-secret/vault's own qualification suite
// (packages/vault/test/suite.js's "leakage:no-plaintext-in-errors-audit-console")
// but for this package's own error/audit surface.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultServerError } from "../dist/index.js";
import { captureOne, openServer, staticResolver } from "./helpers.mjs";

const TENANTS = ["tenant-acme-synthetic", "tenant-northwind-synthetic", "tenant-globex-synthetic"];
const SECRETS = [
  "ghp_SYNTHETICxREVOKEDxTESTx0000000000000",
  "ghp_SYNTHETICxREVOKEDxTESTx1111111111111",
  "ghp_SYNTHETICxREVOKEDxTESTx2222222222222",
];

test("N tenants, one capture each: every same-tenant restore succeeds and every cross-tenant restore is denied", async () => {
  for (let owner = 0; owner < TENANTS.length; owner += 1) {
    for (let requester = 0; requester < TENANTS.length; requester += 1) {
      const principal = { id: `user-synthetic-${requester}`, tenant: TENANTS[requester] };
      // Fresh server per attempt so a denied same-token restore never
      // shadows a later legitimate one in this matrix (budget is 1 by
      // default) — this test is about tenant isolation, not budgets.
      const { server } = await openServer({ resolvePrincipal: staticResolver(principal) });
      const captured = await captureOne(server, { text: `secret ${SECRETS[owner]} here`, issuedTenant: TENANTS[owner] });
      const result = server.restore({
        context: {},
        sink: "sink-a",
        purpose: "support-reply-purpose-synthetic",
        captures: [captured.captureId],
        fields: { body: captured.text },
      });

      if (requester === owner) {
        const { fields } = await result;
        assert.match(fields.body, /ghp_SYNTHETIC/, `same-tenant restore (${TENANTS[owner]}) must succeed`);
      } else {
        await assert.rejects(
          result,
          (error) => {
            assert.ok(error instanceof VaultServerError);
            assert.equal(error.reason, "tenant-mismatch", `${TENANTS[requester]} must not read ${TENANTS[owner]}'s value`);
            return true;
          },
          `cross-tenant restore (${TENANTS[requester]} reading ${TENANTS[owner]}) must be denied`,
        );
      }
    }
  }
});

test("no fixture value, and no issued token, ever appears in a thrown error, an audit event, or console output", async () => {
  const errors = [];
  const auditEvents = [];
  const vaultAuditEvents = [];
  const consoleOutput = [];

  const originalConsole = { log: console.log, warn: console.warn, error: console.error, info: console.info };
  for (const method of Object.keys(originalConsole)) {
    console[method] = (...args) => consoleOutput.push(args.map(String).join(" "));
  }

  try {
    const { server } = await openServer({
      onAudit: (event) => auditEvents.push(event),
      onVaultAudit: (event) => vaultAuditEvents.push(event),
      policy: () => ({ allow: false, reason: "rate-limited" }), // deny path exercised heavily below
    });

    const captured = await captureOne(server, { text: `leak-check secret ${SECRETS[0]} inline`, maxUses: 2 });

    const attempts = [
      () => server.restore({ context: {}, sink: "wrong-sink", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }),
      () => server.restore({ context: {}, sink: "sink-a", purpose: "", captures: [captured.captureId], fields: { body: captured.text } }),
      () => server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: ["cap_wrong"], fields: { body: captured.text } }),
      () => server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" } }),
      () => server.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [captured.captureId], fields: { body: captured.text } }), // denied by policy
    ];
    for (const attempt of attempts) {
      try {
        await attempt();
      } catch (error) {
        errors.push(error);
      }
    }

    // An allow-all restore too, so a *successful* audit event is also checked.
    const { server: allowServer } = await openServer({ onAudit: (event) => auditEvents.push(event) });
    const good = await captureOne(allowServer, { text: `also leak-check ${SECRETS[1]} inline` });
    await allowServer.restore({ context: {}, sink: "sink-a", purpose: "p", captures: [good.captureId], fields: { body: good.text } });

    assert.ok(errors.length >= 4, "too few errors observed for a meaningful leakage check");
    assert.ok(auditEvents.length >= 4, "too few audit events observed for a meaningful leakage check");

    const haystacks = [
      ...errors.map((e) => JSON.stringify({ message: e.message, name: e.name, code: e.code, reason: e.reason, stack: e.stack, ...e })),
      ...auditEvents.map((e) => JSON.stringify(e)),
      ...vaultAuditEvents.map((e) => JSON.stringify(e)),
      ...consoleOutput,
    ];
    const tokenLike = /rsv_[a-z2-7]{26}/;
    for (const text of haystacks) {
      for (const secret of SECRETS) assert.ok(!text.includes(secret), `fixture value leaked: ${text}`);
      assert.ok(!tokenLike.test(text), `issued token leaked: ${text}`);
    }
    assert.equal(consoleOutput.length, 0, "this package must never write to the console itself");
  } finally {
    for (const method of Object.keys(originalConsole)) console[method] = originalConsole[method];
  }
});
