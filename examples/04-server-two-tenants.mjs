// A server with two tenants: your resolver says who is asking, your policy
// says whether they may. Another tenant's request is denied.
// Run: node examples/04-server-two-tenants.mjs
import assert from "node:assert/strict";

import { createServerVault, VaultServerError } from "@redact-secret/vault-server";
import { allOf, allowSameTenantOnly, allowSinkPurposes } from "@redact-secret/vault-server/policies";

const SINK = "support-ticket-reply-sink-synthetic";
const PURPOSE = "support-reply-purpose-synthetic";

const audit = [];
const server = await createServerVault({
  // In a real server, `context` is your already-authenticated request.
  resolvePrincipal: (context) => {
    if (!context.userId || !context.tenant) throw new Error("unauthenticated");
    return { id: context.userId, tenant: context.tenant };
  },
  policy: allOf(allowSameTenantOnly, allowSinkPurposes({ [SINK]: [PURPOSE] })),
  onAudit: (event) => audit.push(event),
  pii: [],
});

const acme = { userId: "user-synthetic-1", tenant: "tenant-acme-synthetic" };
const other = { userId: "user-synthetic-2", tenant: "tenant-other-synthetic" };

const captured = await server.capture("Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today", {
  release: [{ sink: SINK, paths: ["body"] }],
  issuedTenant: acme.tenant,
});
const request = { sink: SINK, purpose: PURPOSE, captures: [captured.captureId], fields: { body: captured.text } };

async function reasonOf(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    if (!(error instanceof VaultServerError) || error.code !== "RESTORE_DENIED") throw error;
    return error.reason;
  }
}

console.log("another tenant:    ", await reasonOf(server.restore({ ...request, context: other })));
console.log("no identity:       ", await reasonOf(server.restore({ ...request, context: {} })));
console.log("another purpose:   ", await reasonOf(server.restore({ ...request, context: acme, purpose: "export-purpose-synthetic" })));

const { fields, principalId } = await server.restore({ ...request, context: acme });
console.log("the owner:         ", fields.body, `(restored for ${principalId})`);

assert.deepEqual(
  audit.filter((event) => event.operation === "restore").map((event) => event.reason ?? event.outcome),
  ["tenant-mismatch", "missing-purpose", "committed"],
);
assert.ok(fields.body.includes("ghp_SYNTHETIC"));
assert.ok(!JSON.stringify(audit).includes("ghp_SYNTHETIC"), "audit events never carry a value");

await server.dispose();
