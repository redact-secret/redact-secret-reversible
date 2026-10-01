// The server's own copy of the identifier and digest derivations
// (dist/persistent/digests.js) against the shared vectors of
// conformance/persistent/v1/vectors.json (docs/specs/persistent-vault.md
// §3.2, §3.8, §7.3). vault-server does not depend on vault-crypto, so the two
// copies are held together only by these vectors: every byte must match.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { createDigester as createCryptoDigester, deriveEntryId as cryptoDeriveEntryId } from "@redact-secret/vault-crypto";

import { digests, hex } from "./helpers.mjs";

const vectors = JSON.parse(readFileSync(new URL("../../../../conformance/persistent/v1/vectors.json", import.meta.url), "utf8"));
const bytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));

async function digesterFor(vector) {
  assert.ok(vector.mode === "keyed" || vector.mode === "unkeyed", `unknown vector mode ${vector.mode}`);
  return digests.createDigester(vector.mode === "keyed" ? bytes(vector.key) : null);
}

test("vectors: the file holds the groups this suite replays, in both digest modes", () => {
  assert.equal(vectors.formatVersion, 1);
  assert.ok(vectors.entryId.length >= 3);
  for (const group of ["sessionTag", "requestDigest"]) {
    const modes = new Set(vectors[group].map((vector) => vector.mode));
    assert.deepEqual([...modes].sort(), ["keyed", "unkeyed"], `${group} has keyed and unkeyed vectors`);
  }
});

test("vectors: entryId", async () => {
  for (const vector of vectors.entryId) {
    assert.equal(await digests.deriveEntryId(vector.namespace, vector.tenant, vector.token), vector.entryId);
    // The preimage in the file is what is hashed.
    const fromPreimage = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(vector.preimage))));
    assert.equal(fromPreimage, vector.entryId);
  }
});

test("vectors: sessionTag, keyed and unkeyed", async () => {
  for (const vector of vectors.sessionTag) {
    const digester = await digesterFor(vector);
    assert.equal(await digester.sessionTag(vector.input), vector.sessionTag);
  }
});

test("vectors: requestDigest, keyed and unkeyed", async () => {
  for (const vector of vectors.requestDigest) {
    const digester = await digesterFor(vector);
    const digest = await digester.requestDigest(vector.input);
    assert.ok(digest instanceof Uint8Array && digest.byteLength === 32);
    assert.equal(hex(digest), vector.requestDigest, vector.name);
  }
});

test("requestDigest: the order of captures, uses, and paths in the input does not change the digest", async () => {
  for (const vector of vectors.requestDigest) {
    const digester = await digesterFor(vector);
    const reversed = {
      ...vector.input,
      captureIds: [...vector.input.captureIds].reverse(),
      uses: [...vector.input.uses].reverse().map((use) => ({ ...use, paths: [...use.paths].reverse() })),
    };
    assert.equal(hex(await digester.requestDigest(reversed)), vector.requestDigest, vector.name);
  }
});

test("requestDigest: every field of the request changes the digest", async () => {
  const vector = vectors.requestDigest.find((candidate) => candidate.mode === "keyed");
  const digester = await digesterFor(vector);
  const base = vector.input;
  const variants = [
    { ...base, namespace: `${base.namespace}x` },
    { ...base, tenant: `${base.tenant}x` },
    { ...base, principalId: `${base.principalId}x` },
    { ...base, sessionId: base.sessionId === null ? "session-synthetic-0001" : null },
    { ...base, sessionId: "" },
    { ...base, sink: `${base.sink}x` },
    { ...base, purpose: `${base.purpose}x` },
    { ...base, captureIds: [...base.captureIds, "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb"] },
    { ...base, uses: base.uses.map((use) => ({ ...use, entryId: "0".repeat(64) })) },
    { ...base, uses: base.uses.map((use) => ({ ...use, paths: use.paths.map((path) => ({ ...path, path: `${path.path}x` })) })) },
    { ...base, uses: base.uses.map((use) => ({ ...use, paths: use.paths.map((path) => ({ ...path, occurrences: path.occurrences + 1 })) })) },
    { ...base, uses: [] },
  ];
  const seen = new Set([vector.requestDigest]);
  for (const variant of variants) {
    const digest = hex(await digester.requestDigest(variant));
    assert.equal(seen.has(digest), false, "a changed request must not collide");
    seen.add(digest);
  }
  // And the key matters.
  const otherKey = await digests.createDigester(new Uint8Array(32).fill(0x22));
  assert.notEqual(hex(await otherKey.requestDigest(base)), vector.requestDigest);
  const unkeyed = await digests.createDigester(null);
  assert.notEqual(hex(await unkeyed.requestDigest(base)), vector.requestDigest);
});

test("derivations: the server's copy and vault-crypto's agree on inputs outside the vectors", async () => {
  const key = Uint8Array.from({ length: 32 }, (_unused, index) => 0x40 + index);
  const mine = await digests.createDigester(key);
  const theirs = await createCryptoDigester({ key });
  const mineUnkeyed = await digests.createDigester(null);
  const theirsUnkeyed = await createCryptoDigester({ unkeyed: true });
  const tenants = ["tenant-acme-synthetic", "租户-synthetic", "tenant-\u{1f512}-synthetic", "tenant-￿-synthetic", "t"];
  for (const tenant of tenants) {
    const token = "<rsv_abcdefghijklmnopqrstuvwxyz>";
    assert.equal(await digests.deriveEntryId("support-synthetic", tenant, token), await cryptoDeriveEntryId("support-synthetic", tenant, token));
    const tagInput = { namespace: "support-synthetic", tenant, captureId: "cap_abcdefghijklmnopqrstuvwxyz", sessionId: `session-${tenant}` };
    assert.equal(await mine.sessionTag(tagInput), await theirs.sessionTag(tagInput));
    assert.equal(await mineUnkeyed.sessionTag(tagInput), await theirsUnkeyed.sessionTag(tagInput));
    const request = {
      namespace: "support-synthetic",
      tenant,
      principalId: `principal-${tenant}`,
      sessionId: tenant.length > 5 ? `session-${tenant}` : null,
      sink: "sink-\u{1f512}",
      purpose: "purpose-synthetic-é",
      captureIds: ["cap_bbbbbbbbbbbbbbbbbbbbbbbbbb", "cap_abcdefghijklmnopqrstuvwxyz"],
      uses: [
        {
          entryId: "f".repeat(64),
          // Byte order, not UTF-16 order: U+FFFF sorts before a supplementary character in UTF-8.
          paths: [
            { path: "\u{1f512}", occurrences: 2 },
            { path: "￿", occurrences: 1 },
            { path: "body", occurrences: 4294967295 },
          ],
        },
        { entryId: "0".repeat(64), paths: [{ path: "subject", occurrences: 1 }] },
      ],
    };
    assert.equal(hex(await mine.requestDigest(request)), hex(await theirs.requestDigest(request)));
    assert.equal(hex(await mineUnkeyed.requestDigest(request)), hex(await theirsUnkeyed.requestDigest(request)));
  }
});

test("derivations: an ill-formed string is rejected, never encoded with a replacement character", async () => {
  const digester = await digests.createDigester(null);
  await assert.rejects(digests.deriveEntryId("support-synthetic", "tenant-\ud800", "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>"), RangeError);
  await assert.rejects(
    digester.sessionTag({ namespace: "support-synthetic", tenant: "tenant-acme-synthetic", captureId: "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa", sessionId: "s-\udc00" }),
    RangeError,
  );
});

test("equalTags and equalBytes: equal only when every position is", () => {
  assert.equal(digests.equalTags("ab".repeat(32), "ab".repeat(32)), true);
  assert.equal(digests.equalTags("ab".repeat(32), `${"ab".repeat(31)}ac`), false);
  assert.equal(digests.equalTags("ab".repeat(32), "ab".repeat(31)), false);
  assert.equal(digests.equalTags("", ""), true);
  assert.equal(digests.equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  assert.equal(digests.equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  assert.equal(digests.equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])), false);
});
