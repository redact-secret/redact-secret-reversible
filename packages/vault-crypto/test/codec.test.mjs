// The pure functions: payload, envelope, associated data, identifiers, digests.
import assert from "node:assert/strict";
import test from "node:test";

import { LIMITS } from "@redact-secret/vault-contracts";

import {
  createDigester,
  createRecordCrypto,
  decodeEnvelope,
  decodePayload,
  deriveEntryId,
  deriveEntryKey,
  encodeAad,
  encodeEnvelope,
  encodePayload,
} from "../dist/index.js";
import {
  binding,
  CAPTURE_A,
  CAPTURE_B,
  CONTEXT,
  entryId,
  fakeProvider,
  FIXED_DEK,
  hex,
  NAMESPACE,
  payload,
  recordError,
  SESSION,
  TENANT,
  TOKENS,
  utf8,
} from "./helpers.mjs";

const LONE_HIGH = "synthetic-\ud800-lone";
const LONE_LOW = "\udc00synthetic";
const BMP_HIGH = "～"; // U+FF5E, UTF-8 EF BD 9E
const SUPPLEMENTARY = "\u{10000}"; // UTF-8 F0 90 80 80, UTF-16 D800 DC00

const u16 = (n) => [n >>> 8, n & 0xff];
const u32 = (n) => [n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const lp16 = (value) => [...u16(utf8(value).length), ...utf8(value)];
/** A payload written exactly as given, with no sorting. */
const raw = ({ version = 1, value = "v", type = "t", grants = [["s", ["p"]]], flag = 0, revision = "", trailing = [] } = {}) =>
  Uint8Array.from([
    version,
    ...u32(utf8(value).length),
    ...utf8(value),
    ...lp16(type),
    ...u16(grants.length),
    ...grants.flatMap(([sink, paths]) => [...lp16(sink), ...u16(paths.length), ...paths.flatMap((p) => lp16(p))]),
    flag,
    ...lp16(revision),
    ...trailing,
  ]);

test("encodePayload sorts sinks and paths by UTF-8 bytes, not by UTF-16 code units", () => {
  assert.ok(BMP_HIGH > SUPPLEMENTARY, "precondition: the JavaScript string order puts U+FF5E after U+10000");
  const encoded = encodePayload(
    payload("v", {
      type: "t",
      grants: [
        { sink: SUPPLEMENTARY, paths: [SUPPLEMENTARY, BMP_HIGH, "z"] },
        { sink: BMP_HIGH, paths: ["b", "a"] },
      ],
    }),
  );
  assert.equal(
    hex(encoded),
    hex(
      raw({
        grants: [
          [BMP_HIGH, ["a", "b"]],
          [SUPPLEMENTARY, ["z", BMP_HIGH, SUPPLEMENTARY]],
        ],
      }),
    ),
  );
  const decoded = decodePayload(encoded);
  assert.deepEqual(
    decoded.grants.map((grant) => grant.sink),
    [BMP_HIGH, SUPPLEMENTARY],
  );
  assert.deepEqual(decoded.grants[1].paths, ["z", BMP_HIGH, SUPPLEMENTARY]);
});

test("encodePayload rejects duplicates, empty sets, and wrong shapes", async () => {
  const cases = [
    [{ grants: [] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "s", paths: [] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "s", paths: ["p", "p"] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "s", paths: ["p"] }, { sink: "s", paths: ["q"] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "", paths: ["p"] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "s", paths: [""] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "s", paths: [7] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: [{ sink: "s".repeat(257), paths: ["p"] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: "sink-a" }, "RECORD_INVALID_ARGUMENT"],
    [{ grants: Array.from({ length: 65 }, (_unused, i) => ({ sink: `s${i}`, paths: ["p"] })) }, "RECORD_LIMIT"],
    [{ grants: [{ sink: "s", paths: Array.from({ length: 257 }, (_unused, i) => `p${i}`) }] }, "RECORD_LIMIT"],
    [{ type: "" }, "RECORD_INVALID_ARGUMENT"],
    [{ type: 7 }, "RECORD_INVALID_ARGUMENT"],
    [{ type: "t".repeat(257) }, "RECORD_LIMIT"],
    [{ type: "é".repeat(129) }, "RECORD_LIMIT"],
    [{ policyRevision: "r".repeat(257) }, "RECORD_LIMIT"],
    [{ policyRevision: undefined }, "RECORD_INVALID_ARGUMENT"],
    [{ policyRevision: 7 }, "RECORD_INVALID_ARGUMENT"],
    [{ value: "a string, not bytes" }, "RECORD_INVALID_ARGUMENT"],
    [{ value: new Uint8Array(LIMITS.maxValueBytes + 1) }, "RECORD_LIMIT"],
  ];
  for (const [overrides, code] of cases) {
    await recordError(() => encodePayload({ ...payload(), ...overrides }), code);
  }
  await recordError(() => encodePayload(null), "RECORD_INVALID_ARGUMENT");
  // Exactly at the limits is accepted.
  encodePayload(payload("v", { type: "é".repeat(128), policyRevision: "r".repeat(256) }));
  encodePayload(
    payload("v", {
      grants: Array.from({ length: 64 }, (_unused, i) => ({ sink: `s${i}`, paths: ["p"] })),
    }),
  );
});

test("decodePayload rejects every non-canonical or malformed payload", async () => {
  assert.equal(decodePayload(raw()).type, "t");
  const cases = [
    ["unsorted sinks", raw({ grants: [["b", ["p"]], ["a", ["p"]]] }), "RECORD_MALFORMED"],
    ["duplicate sinks", raw({ grants: [["a", ["p"]], ["a", ["q"]]] }), "RECORD_MALFORMED"],
    ["unsorted paths", raw({ grants: [["s", ["q", "p"]]] }), "RECORD_MALFORMED"],
    ["duplicate paths", raw({ grants: [["s", ["p", "p"]]] }), "RECORD_MALFORMED"],
    ["paths in UTF-16 order", raw({ grants: [["s", [SUPPLEMENTARY, BMP_HIGH]]] }), "RECORD_MALFORMED"],
    ["sinks in UTF-16 order", raw({ grants: [[SUPPLEMENTARY, ["p"]], [BMP_HIGH, ["p"]]] }), "RECORD_MALFORMED"],
    ["zero grants", raw({ grants: [] }), "RECORD_MALFORMED"],
    ["zero paths", raw({ grants: [["s", []]] }), "RECORD_MALFORMED"],
    ["empty sink", raw({ grants: [["", ["p"]]] }), "RECORD_MALFORMED"],
    ["empty path", raw({ grants: [["s", [""]]] }), "RECORD_MALFORMED"],
    ["empty type", raw({ type: "" }), "RECORD_MALFORMED"],
    ["flag 0 with a revision", raw({ flag: 0, revision: "r" }), "RECORD_MALFORMED"],
    ["flag 2", raw({ flag: 2 }), "RECORD_MALFORMED"],
    ["flag 255", raw({ flag: 255, revision: "r" }), "RECORD_MALFORMED"],
    ["trailing byte", raw({ trailing: [0] }), "RECORD_MALFORMED"],
    ["trailing bytes after a revision", raw({ flag: 1, revision: "r", trailing: [1, 2, 3] }), "RECORD_MALFORMED"],
    ["version 0", raw({ version: 0 }), "RECORD_UNSUPPORTED"],
    ["version 2", raw({ version: 2 }), "RECORD_UNSUPPORTED"],
    ["empty input", new Uint8Array(0), "RECORD_MALFORMED"],
    ["65 grants", raw({ grants: Array.from({ length: 65 }, (_unused, i) => [`s${String(i).padStart(2, "0")}`, ["p"]]) }), "RECORD_LIMIT"],
    ["257 paths", raw({ grants: [["s", Array.from({ length: 257 }, (_unused, i) => `p${String(i).padStart(3, "0")}`)]] }), "RECORD_LIMIT"],
    ["type of 257 bytes", raw({ type: "t".repeat(257) }), "RECORD_LIMIT"],
    ["revision of 257 bytes", raw({ flag: 1, revision: "r".repeat(257) }), "RECORD_LIMIT"],
    ["sink of 257 code units", raw({ grants: [["s".repeat(257), ["p"]]] }), "RECORD_LIMIT"],
    ["value length past the input", Uint8Array.from([1, ...u32(50), 1, 2, 3]), "RECORD_MALFORMED"],
    ["value length over the limit", Uint8Array.from([1, ...u32(LIMITS.maxValueBytes + 1), 1, 2, 3]), "RECORD_LIMIT"],
    ["value length 0xffffffff", Uint8Array.from([1, 0xff, 0xff, 0xff, 0xff]), "RECORD_LIMIT"],
    ["not bytes", "payload", "RECORD_INVALID_ARGUMENT"],
  ];
  for (const [name, bytes, code] of cases) {
    await recordError(() => decodePayload(bytes), code).catch((error) => {
      throw new Error(`${name}: ${error.message}`);
    });
  }
  const good = raw({ flag: 1, revision: "rev" });
  for (let length = 0; length < good.length; length += 1) {
    await recordError(() => decodePayload(good.slice(0, length)), "RECORD_MALFORMED");
  }
});

test("decodePayload rejects invalid UTF-8 in every string field", async () => {
  const invalid = [
    [0xff],
    [0x80],
    [0xc0, 0xaf], // overlong
    [0xe2, 0x82], // truncated
    [0xed, 0xa0, 0x80], // encoded surrogate
    [0xf4, 0x90, 0x80, 0x80], // past U+10FFFF
  ];
  const withField = (prefix, bad, suffix) => Uint8Array.from([...prefix, ...u16(bad.length), ...bad, ...suffix]);
  const head = [1, ...u32(1), 0x76];
  const tail = [0, 0, 0];
  for (const bad of invalid) {
    const type = withField(head, bad, [...u16(1), ...lp16("s"), ...u16(1), ...lp16("p"), ...tail]);
    const sink = withField([...head, ...lp16("t"), ...u16(1)], bad, [...u16(1), ...lp16("p"), ...tail]);
    const path = withField([...head, ...lp16("t"), ...u16(1), ...lp16("s"), ...u16(1)], bad, tail);
    const revision = withField([...head, ...lp16("t"), ...u16(1), ...lp16("s"), ...u16(1), ...lp16("p"), 1], bad, []);
    for (const bytes of [type, sink, path, revision]) await recordError(() => decodePayload(bytes), "RECORD_MALFORMED");
  }
});

test("decodePayload keeps a leading U+FEFF and returns a value that is a copy", () => {
  const decoded = decodePayload(raw({ type: "﻿t", grants: [["﻿s", ["﻿p"]]], flag: 1, revision: "﻿" }));
  assert.equal(decoded.type, "﻿t");
  assert.equal(decoded.grants[0].sink, "﻿s");
  assert.equal(decoded.grants[0].paths[0], "﻿p");
  assert.equal(decoded.policyRevision, "﻿");
  const bytes = raw({ value: "abc" });
  const value = decodePayload(bytes).value;
  bytes.fill(0);
  assert.deepEqual(value, utf8("abc"));
});

test("a lone surrogate is rejected in every string input, before anything is encoded", async () => {
  for (const bad of [LONE_HIGH, LONE_LOW]) {
    for (const overrides of [
      { type: bad },
      { policyRevision: bad },
      { grants: [{ sink: bad, paths: ["p"] }] },
      { grants: [{ sink: "s", paths: [bad] }] },
    ]) {
      await recordError(() => encodePayload({ ...payload(), ...overrides }), "RECORD_INVALID_ARGUMENT");
    }
    for (const field of ["tenant", "sessionId", "namespace", "captureId", "entryId"]) {
      await recordError(() => encodeAad(binding({ [field]: bad })), "RECORD_INVALID_ARGUMENT");
    }
    await recordError(() => deriveEntryId(NAMESPACE, bad, TOKENS[0]), "RECORD_INVALID_ARGUMENT");
    await recordError(() => deriveEntryId(NAMESPACE, TENANT, `<rsv_${bad}>`), "RECORD_INVALID_ARGUMENT");

    const digester = createDigester({ unkeyed: true });
    const request = {
      namespace: NAMESPACE,
      tenant: TENANT,
      principalId: "principal-synthetic-0001",
      sessionId: null,
      sink: "sink-a",
      purpose: "purpose-synthetic",
      captureIds: [CAPTURE_A],
      uses: [{ entryId: entryId(1), paths: [{ path: "body", occurrences: 1 }] }],
    };
    for (const overrides of [
      { tenant: bad },
      { principalId: bad },
      { sessionId: bad },
      { sink: bad },
      { purpose: bad },
      { uses: [{ entryId: entryId(1), paths: [{ path: bad, occurrences: 1 }] }] },
    ]) {
      await recordError(() => digester.requestDigest({ ...request, ...overrides }), "RECORD_INVALID_ARGUMENT");
    }
    for (const field of ["tenant", "sessionId"]) {
      await recordError(
        () => digester.sessionTag({ namespace: NAMESPACE, tenant: TENANT, captureId: CAPTURE_A, sessionId: SESSION, [field]: bad }),
        "RECORD_INVALID_ARGUMENT",
      );
    }

    const provider = fakeProvider();
    const crypto = createRecordCrypto({ keyProvider: provider });
    await recordError(
      () => crypto.sealCapture({ context: { ...CONTEXT, tenant: bad }, records: [{ binding: binding({ tenant: bad }), payload: payload() }] }),
      "RECORD_INVALID_ARGUMENT",
    );
    await recordError(
      () => crypto.sealCapture({ context: CONTEXT, records: [{ binding: binding({ sessionId: bad }), payload: payload() }] }),
      "RECORD_INVALID_ARGUMENT",
    );
    await recordError(
      () => crypto.sealCapture({ context: CONTEXT, records: [{ binding: binding(), payload: payload("v", { type: bad }) }] }),
      "RECORD_INVALID_ARGUMENT",
    );
    assert.equal(provider.calls.generate, 0);
  }
});

test("encodeAad validates every field of the binding", async () => {
  const cases = [
    { namespace: "has space" },
    { namespace: "" },
    { tenant: "" },
    { tenant: "t".repeat(257) },
    { captureId: "cap_short" },
    { entryId: "ABCDEF".padEnd(64, "0") },
    { entryId: "0".repeat(63) },
    { sessionId: "" },
    { sessionId: undefined },
    { createdAt: 1.5 },
    { createdAt: -1 },
    { expiresAt: Number.MAX_SAFE_INTEGER + 1 },
    { expiresAt: binding().createdAt },
    { expiresAt: binding().createdAt + LIMITS.maxCaptureLifetimeMs + 1 },
    { maxUses: 0 },
    { maxUses: 1001 },
    { maxUses: 1.5 },
    { maxUses: "1" },
  ];
  for (const overrides of cases) await recordError(() => encodeAad(binding(overrides)), "RECORD_INVALID_ARGUMENT");
  await recordError(() => encodeAad(null), "RECORD_INVALID_ARGUMENT");
  encodeAad(binding({ expiresAt: binding().createdAt + LIMITS.maxCaptureLifetimeMs, maxUses: 1000 }));
});

test("encodeAad separates every field: no two distinct bindings encode alike", () => {
  const variants = [
    binding(),
    binding({ sessionId: SESSION }),
    binding({ tenant: `${TENANT}x` }),
    binding({ captureId: CAPTURE_B }),
    binding({ entryId: entryId(2) }),
    binding({ createdAt: binding().createdAt + 1 }),
    binding({ expiresAt: binding().expiresAt + 1 }),
    binding({ maxUses: 2 }),
    binding({ namespace: `${NAMESPACE}x` }),
  ];
  assert.equal(new Set(variants.map((b) => hex(encodeAad(b)))).size, variants.length);
});

test("envelope encode and decode are strict inverses", async () => {
  const nonce = Uint8Array.from({ length: 12 }, (_unused, i) => i);
  const ciphertext = Uint8Array.from({ length: 40 }, (_unused, i) => 200 - i);
  const envelope = encodeEnvelope({ nonce, ciphertext });
  assert.equal(hex(envelope.subarray(0, 6)), "525356450101");
  assert.equal(envelope.length, 22 + 40);
  const decoded = decodeEnvelope(envelope);
  assert.deepEqual(decoded.nonce, nonce);
  assert.deepEqual(decoded.ciphertext, ciphertext);
  envelope.fill(0);
  assert.deepEqual(decoded.ciphertext, ciphertext, "decodeEnvelope returns copies");

  await recordError(() => encodeEnvelope({ nonce: nonce.slice(0, 11), ciphertext }), "RECORD_INVALID_ARGUMENT");
  await recordError(() => encodeEnvelope({ nonce, ciphertext: ciphertext.slice(0, 16) }), "RECORD_INVALID_ARGUMENT");
  await recordError(() => encodeEnvelope({ nonce, ciphertext: new Uint8Array(LIMITS.maxEnvelopeBytes) }), "RECORD_LIMIT");
  await recordError(() => decodeEnvelope("RSVE"), "RECORD_INVALID_ARGUMENT");
  // The largest envelope is accepted by both directions.
  const largest = encodeEnvelope({ nonce, ciphertext: new Uint8Array(LIMITS.maxEnvelopeBytes - 22) });
  assert.equal(largest.length, LIMITS.maxEnvelopeBytes);
  assert.equal(decodeEnvelope(largest).ciphertext.length, LIMITS.maxEnvelopeBytes - 22);
});

test("deriveEntryId is deterministic, scoped, and accepts only an exact issued token", async () => {
  const id = await deriveEntryId(NAMESPACE, TENANT, TOKENS[0]);
  assert.match(id, /^[0-9a-f]{64}$/);
  assert.equal(await deriveEntryId(NAMESPACE, TENANT, TOKENS[0]), id);
  assert.notEqual(await deriveEntryId(NAMESPACE, TENANT, TOKENS[1]), id);
  assert.notEqual(await deriveEntryId(NAMESPACE, "tenant-northwind-synthetic", TOKENS[0]), id);
  assert.notEqual(await deriveEntryId("support-synthetic-2", TENANT, TOKENS[0]), id);
  for (const token of ["rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa", "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaa>", "<rsv_AAAAAAAAAAAAAAAAAAAAAAAAAA>", "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaa1>", `${TOKENS[0]} `, "", 7]) {
    await recordError(() => deriveEntryId(NAMESPACE, TENANT, token), "RECORD_INVALID_ARGUMENT");
  }
  await recordError(() => deriveEntryId("bad namespace", TENANT, TOKENS[0]), "RECORD_INVALID_ARGUMENT");
  await recordError(() => deriveEntryId(NAMESPACE, "", TOKENS[0]), "RECORD_INVALID_ARGUMENT");
});

test("deriveEntryKey returns a non-extractable AES-256-GCM key", async () => {
  const key = await deriveEntryKey(FIXED_DEK, entryId(1));
  assert.equal(key.extractable, false);
  assert.equal(key.algorithm.name, "AES-GCM");
  assert.equal(key.algorithm.length, 256);
  await assert.rejects(globalThis.crypto.subtle.exportKey("raw", key));
  await recordError(() => deriveEntryKey(FIXED_DEK.slice(0, 31), entryId(1)), "RECORD_INVALID_ARGUMENT");
  await recordError(() => deriveEntryKey(FIXED_DEK, "not-an-entry-id"), "RECORD_INVALID_ARGUMENT");
  await recordError(() => deriveEntryKey("0".repeat(32), entryId(1)), "RECORD_INVALID_ARGUMENT");
});

test("the digester sorts by UTF-8 bytes, rejects duplicates and out-of-range values", async () => {
  const digester = createDigester({ key: new Uint8Array(32).fill(9) });
  const request = {
    namespace: NAMESPACE,
    tenant: TENANT,
    principalId: "principal-synthetic-0001",
    sessionId: SESSION,
    sink: "sink-a",
    purpose: "purpose-synthetic",
    captureIds: [CAPTURE_B, CAPTURE_A],
    uses: [
      { entryId: entryId(2), paths: [{ path: SUPPLEMENTARY, occurrences: 1 }, { path: BMP_HIGH, occurrences: 2 }] },
      { entryId: entryId(1), paths: [{ path: "body", occurrences: 3 }] },
    ],
  };
  const digest = await digester.requestDigest(request);
  assert.equal(digest.length, 32);
  const reordered = {
    ...request,
    captureIds: [CAPTURE_A, CAPTURE_B],
    uses: [
      { entryId: entryId(1), paths: [{ path: "body", occurrences: 3 }] },
      { entryId: entryId(2), paths: [{ path: BMP_HIGH, occurrences: 2 }, { path: SUPPLEMENTARY, occurrences: 1 }] },
    ],
  };
  assert.equal(hex(await digester.requestDigest(reordered)), hex(digest), "the order given by the caller does not matter");

  const different = [
    { sessionId: null },
    { sessionId: "session-synthetic-0002" },
    { sink: "sink-b" },
    { purpose: "purpose-synthetic-2" },
    { principalId: "principal-synthetic-0002" },
    { tenant: "tenant-northwind-synthetic" },
    { captureIds: [CAPTURE_A] },
    { uses: [request.uses[1]] },
    { uses: [request.uses[0], { entryId: entryId(1), paths: [{ path: "body", occurrences: 4 }] }] },
    // Occurrences moved between two paths: the pairing is part of the digest.
    { uses: [{ entryId: entryId(2), paths: [{ path: SUPPLEMENTARY, occurrences: 2 }, { path: BMP_HIGH, occurrences: 1 }] }, request.uses[1]] },
  ];
  const digests = new Set([hex(digest)]);
  for (const overrides of different) digests.add(hex(await digester.requestDigest({ ...request, ...overrides })));
  assert.equal(digests.size, different.length + 1);

  const invalid = [
    [{ captureIds: [CAPTURE_A, CAPTURE_A] }, "RECORD_INVALID_ARGUMENT"],
    [{ captureIds: [] }, "RECORD_INVALID_ARGUMENT"],
    [{ captureIds: ["cap_x"] }, "RECORD_INVALID_ARGUMENT"],
    [{ captureIds: Array.from({ length: 65 }, (_unused, i) => `cap_${"a".repeat(24)}${"abcdefghijklmnopqrstuvwxyz234567"[i >> 5]}${"abcdefghijklmnopqrstuvwxyz234567"[i & 31]}`) }, "RECORD_LIMIT"],
    [{ uses: [] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [request.uses[1], request.uses[1]] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [{ entryId: "nope", paths: [{ path: "body", occurrences: 1 }] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [{ entryId: entryId(1), paths: [] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [{ entryId: entryId(1), paths: [{ path: "body", occurrences: 1 }, { path: "body", occurrences: 2 }] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [{ entryId: entryId(1), paths: [{ path: "body", occurrences: 0 }] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [{ entryId: entryId(1), paths: [{ path: "body", occurrences: 1.5 }] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: [{ entryId: entryId(1), paths: [{ path: "body", occurrences: 2 ** 32 }] }] }, "RECORD_LIMIT"],
    [{ uses: [{ entryId: entryId(1), paths: [{ path: "", occurrences: 1 }] }] }, "RECORD_INVALID_ARGUMENT"],
    [{ uses: Array.from({ length: 1025 }, (_unused, i) => ({ entryId: entryId(i + 1), paths: [{ path: "body", occurrences: 1 }] })) }, "RECORD_LIMIT"],
    [{ purpose: "" }, "RECORD_INVALID_ARGUMENT"],
    [{ purpose: "p".repeat(1025) }, "RECORD_LIMIT"],
    [{ purpose: "é".repeat(513) }, "RECORD_LIMIT"],
    [{ sink: "" }, "RECORD_INVALID_ARGUMENT"],
    [{ namespace: "bad namespace" }, "RECORD_INVALID_ARGUMENT"],
    [{ sessionId: "" }, "RECORD_INVALID_ARGUMENT"],
    [{ sessionId: undefined }, "RECORD_INVALID_ARGUMENT"],
  ];
  for (const [overrides, code] of invalid) await recordError(() => digester.requestDigest({ ...request, ...overrides }), code);
  await digester.requestDigest({ ...request, purpose: "é".repeat(512) });
});

test("keyed and unkeyed digests differ, and the key is required explicitly", async () => {
  const key = new Uint8Array(32).fill(9);
  const keyed = createDigester({ key });
  key.fill(0); // the caller's array is not retained
  const sameKey = createDigester({ key: new Uint8Array(32).fill(9) });
  const otherKey = createDigester({ key: new Uint8Array(32).fill(10) });
  const unkeyed = createDigester({ unkeyed: true });
  const input = { namespace: NAMESPACE, tenant: TENANT, captureId: CAPTURE_A, sessionId: SESSION };
  const tag = await keyed.sessionTag(input);
  assert.match(tag, /^[0-9a-f]{64}$/);
  assert.equal(await sameKey.sessionTag(input), tag);
  assert.notEqual(await otherKey.sessionTag(input), tag);
  assert.notEqual(await unkeyed.sessionTag(input), tag);
  assert.notEqual(await keyed.sessionTag({ ...input, sessionId: "session-synthetic-0002" }), tag);
  assert.notEqual(await keyed.sessionTag({ ...input, captureId: CAPTURE_B }), tag);

  for (const options of [undefined, null, {}, { key: new Uint8Array(31) }, { key: new Uint8Array(33) }, { key: "k".repeat(32) }, { unkeyed: false }, { unkeyed: "true" }, { key: new Uint8Array(32), unkeyed: true }]) {
    await recordError(() => createDigester(options), "RECORD_INVALID_ARGUMENT");
  }
  await recordError(() => keyed.sessionTag({ ...input, sessionId: null }), "RECORD_INVALID_ARGUMENT");
  await recordError(() => keyed.sessionTag({ ...input, captureId: "cap_x" }), "RECORD_INVALID_ARGUMENT");
});
