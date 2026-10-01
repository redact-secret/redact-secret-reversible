// The reference policies of `@redact-secret/vault-server/policies` (#134):
// each one alone, their composition, and that composing them cannot turn a
// malformed or failing policy into an allow.
import assert from "node:assert/strict";
import test from "node:test";

import { VaultServerError } from "../dist/index.js";
import { allOf, allowSameTenantOnly, allowSinkPurposes, denyByDefault } from "../dist/policies.js";
import { captureOne, openServer, staticResolver } from "./helpers.mjs";

const SINK = "sink-a";
const PURPOSE = "support-reply-purpose-synthetic";
const input = (over = {}) => ({
  principalId: "user-synthetic-1",
  tenant: "tenant-acme-synthetic",
  sink: SINK,
  path: "body",
  purpose: PURPOSE,
  source: { captureId: "c", issuedTenant: "tenant-acme-synthetic" },
  ...over,
});

async function restoreWith(policy, { purpose = PURPOSE, principal } = {}) {
  const { server } = await openServer({ policy, ...(principal ? { resolvePrincipal: staticResolver(principal) } : {}) });
  const captured = await captureOne(server);
  return server.restore({ context: {}, sink: SINK, purpose, captures: [captured.captureId], fields: { body: captured.text } });
}
const denied = (reason) => (error) => {
  assert.ok(error instanceof VaultServerError);
  assert.equal(error.code, "RESTORE_DENIED");
  assert.equal(error.reason, reason);
  return true;
};

test("denyByDefault denies with `policy`", async () => {
  assert.deepEqual(denyByDefault(input()), { allow: false, reason: "policy" });
  await assert.rejects(restoreWith(denyByDefault), denied("policy"));
});

test("allowSameTenantOnly allows the issuing tenant and denies another", () => {
  assert.deepEqual(allowSameTenantOnly(input()), { allow: true });
  assert.deepEqual(allowSameTenantOnly(input({ tenant: "tenant-other-synthetic" })), { allow: false, reason: "tenant-mismatch" });
});

test("allowSinkPurposes allows listed pairs only", () => {
  const policy = allowSinkPurposes({ [SINK]: [PURPOSE] });
  assert.deepEqual(policy(input()), { allow: true });
  assert.deepEqual(policy(input({ sink: "sink-b" })), { allow: false, reason: "sink-or-path" });
  assert.deepEqual(policy(input({ purpose: "another-purpose-synthetic" })), { allow: false, reason: "missing-purpose" });
  assert.deepEqual(allowSinkPurposes({})(input()), { allow: false, reason: "sink-or-path" });
  assert.deepEqual(allowSinkPurposes({ [SINK]: [] })(input()), { allow: false, reason: "missing-purpose" });
});

test("allowSinkPurposes matches own entries only and copies its table", () => {
  for (const sink of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    assert.deepEqual(allowSinkPurposes({ [SINK]: [PURPOSE] })(input({ sink })), { allow: false, reason: "sink-or-path" });
  }
  const purposes = [PURPOSE];
  const table = { [SINK]: purposes };
  const policy = allowSinkPurposes(table);
  purposes.push("added-later-synthetic");
  table["sink-b"] = [PURPOSE];
  assert.deepEqual(policy(input({ purpose: "added-later-synthetic" })), { allow: false, reason: "missing-purpose" });
  assert.deepEqual(policy(input({ sink: "sink-b" })), { allow: false, reason: "sink-or-path" });
});

test("allowSinkPurposes rejects a malformed table when it is created", () => {
  for (const bad of [null, undefined, "x", [], { [SINK]: PURPOSE }, { [SINK]: [""] }, { [SINK]: [1] }, { "": [PURPOSE] }]) {
    assert.throws(() => allowSinkPurposes(bad), TypeError);
  }
});

test("allOf: every policy must allow, and the first denial decides", async () => {
  const calls = [];
  const spy = (name, decision) => (i) => (calls.push(name), decision);
  const policy = allOf(spy("a", { allow: true }), spy("b", { allow: false, reason: "rate-limited" }), spy("c", { allow: true }));
  assert.deepEqual(await policy(input()), { allow: false, reason: "rate-limited" });
  assert.deepEqual(calls, ["a", "b"]);
  assert.deepEqual(await allOf(allowSameTenantOnly, async () => ({ allow: true }))(input()), { allow: true });
});

test("allOf with no policy denies", async () => {
  assert.deepEqual(await allOf()(input()), { allow: false, reason: "policy" });
  await assert.rejects(restoreWith(allOf()), denied("policy"));
  assert.throws(() => allOf(allowSameTenantOnly, undefined), TypeError);
});

test("allOf never turns a malformed decision into an allow", async () => {
  for (const malformed of [undefined, null, true, "allow", {}, { allow: "yes" }, { allow: 1 }]) {
    const policy = allOf(() => malformed, () => ({ allow: true }));
    assert.equal(await policy(input()), malformed, "the malformed decision is handed back, not skipped");
    await assert.rejects(restoreWith(policy), denied("policy-evaluation-error"));
  }
});

test("allOf: a policy that throws or rejects is policy-evaluation-error at the server", async () => {
  await assert.rejects(restoreWith(allOf(() => { throw new Error("synthetic"); })), denied("policy-evaluation-error"));
  await assert.rejects(restoreWith(allOf(allowSameTenantOnly, async () => { throw new Error("synthetic"); })), denied("policy-evaluation-error"));
});

test("a composed deny-by-default policy restores for the right sink and purpose, and nothing else", async () => {
  const policy = allOf(allowSameTenantOnly, allowSinkPurposes({ [SINK]: [PURPOSE] }));
  const { fields } = await restoreWith(policy);
  assert.match(fields.body, /ghp_SYNTHETIC/);
  await assert.rejects(restoreWith(policy, { purpose: "another-purpose-synthetic" }), denied("missing-purpose"));
  await assert.rejects(restoreWith(policy, { principal: { id: "user-synthetic-2", tenant: "tenant-other-synthetic" } }), denied("tenant-mismatch"));
});
