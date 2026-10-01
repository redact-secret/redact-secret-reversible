// Deterministic test vectors for record format version 1
// (docs/specs/persistent-vault.md §3.8). Test-only: the data key, the
// nonces, the digest key, and the wrapping material below are fixed public
// constants and must never be used to protect anything.
//
//   npm run build -w @redact-secret/vault-contracts
//   npm run build -w @redact-secret/vault-crypto
//   node conformance/persistent/v1/generate-vectors.mjs          # writes vectors.json
//   node conformance/persistent/v1/generate-vectors.mjs --check  # compares, writes nothing
//
// Every positive vector is produced twice: by the byte layout written out in
// this file with WebCrypto called directly, and by the exported functions of
// @redact-secret/vault-crypto. The generator fails if the two disagree.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  createDigester,
  decodeEnvelope,
  decodePayload,
  deriveEntryId,
  encodeAad,
  encodeEnvelope,
  encodePayload,
} from "../../../packages/vault-crypto/dist/index.js";

const subtle = globalThis.crypto.subtle;
const text = new TextEncoder();

// --- byte layout, written independently of the package --------------------

const enc = (value) => (typeof value === "string" ? text.encode(value) : value);
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const u8 = (n) => Uint8Array.of(n);
const u16 = (n) => Uint8Array.of(n >>> 8, n & 0xff);
const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
const u64 = (n) => cat(u32(Math.floor(n / 2 ** 32)), u32(n % 2 ** 32));
const lp16 = (value) => cat(u16(enc(value).length), enc(value));
const lp32 = (value) => cat(u32(enc(value).length), enc(value));
const label = (name) => cat(enc(name), u8(0));
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const range = (start, length) => Uint8Array.from({ length }, (_unused, i) => start + i);
const compare = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
const byBytes = (a, b) => compare(enc(a), enc(b));

const sha256 = async (message) => new Uint8Array(await subtle.digest("SHA-256", message));
const hmac = async (key, message) => {
  const imported = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", imported, message));
};
const hkdf = async (ikm, info) => {
  const imported = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, imported, 256);
  return new Uint8Array(bits);
};
const gcmSeal = async (key, nonce, aad, plaintext) => {
  const imported = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const params = { name: "AES-GCM", iv: nonce, tagLength: 128 };
  if (aad !== null) params.additionalData = aad;
  return new Uint8Array(await subtle.encrypt(params, imported, plaintext));
};

const aadBytes = (b) =>
  cat(
    label("rsv-aad-v1"),
    u8(1),
    u8(1),
    lp16(b.namespace),
    lp16(b.tenant),
    lp16(b.captureId),
    lp16(b.entryId),
    u8(b.sessionId === null ? 0 : 1),
    lp16(b.sessionId ?? ""),
    u64(b.createdAt),
    u64(b.expiresAt),
    u32(b.maxUses),
  );

/** Writes a payload exactly as given: no sorting, no validation. Used for canonical and negative cases alike. */
const rawPayload = ({ version = 1, value, type, grants, flag, revision, trailing = new Uint8Array(0) }) =>
  cat(
    u8(version),
    lp32(value),
    lp16(type),
    u16(grants.length),
    ...grants.map((grant) => cat(lp16(grant.sink), u16(grant.paths.length), ...grant.paths.map((path) => lp16(path)))),
    u8(flag),
    lp16(revision),
    trailing,
  );

const canonicalPayload = (payload) =>
  rawPayload({
    value: payload.value,
    type: payload.type,
    grants: payload.grants
      .map((grant) => ({ sink: grant.sink, paths: [...grant.paths].sort(byBytes) }))
      .sort((a, b) => byBytes(a.sink, b.sink)),
    flag: payload.policyRevision === null ? 0 : 1,
    revision: payload.policyRevision ?? "",
  });

const rawEnvelope = ({ magic = "RSVE", version = 1, algorithm = 1, nonce, sealed, length = sealed.length }) =>
  cat(enc(magic), u8(version), u8(algorithm), nonce, u32(length), sealed);

const requestBytes = (r) => {
  const captures = [...r.captureIds].sort(byBytes);
  const uses = r.uses
    .map((use) => ({ entryId: use.entryId, paths: [...use.paths].sort((a, b) => byBytes(a.path, b.path)) }))
    .sort((a, b) => byBytes(a.entryId, b.entryId));
  return cat(
    label("rsv-request-v1"),
    lp16(r.namespace),
    lp16(r.tenant),
    lp16(r.principalId),
    u8(r.sessionId === null ? 0 : 1),
    lp16(r.sessionId ?? ""),
    lp16(r.sink),
    lp16(r.purpose),
    u16(captures.length),
    ...captures.map((captureId) => lp16(captureId)),
    u16(uses.length),
    ...uses.map((use) =>
      cat(lp16(use.entryId), u16(use.paths.length), ...use.paths.map((p) => cat(lp16(p.path), u32(p.occurrences)))),
    ),
  );
};

const sessionTagBytes = (s) =>
  cat(label("rsv-session-tag-v1"), lp16(s.namespace), lp16(s.tenant), lp16(s.captureId), lp16(s.sessionId));

// --- fixed synthetic inputs -------------------------------------------------

const NAMESPACE = "support-synthetic";
const TENANT = "tenant-acme-synthetic";
const TENANT_UNICODE = "tenant-合成-\u{1F9EA}";
const CAPTURE_A = "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa";
const CAPTURE_B = "cap_bbbbbbbbbbbbbbbbbbbbbbbbbb";
const TOKEN_1 = "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>";
const TOKEN_2 = "<rsv_abcdefghijklmnopqrstuvwxyz>";
const TOKEN_3 = "<rsv_234567abcdefghijklmnopqrst>";
const SESSION = "session-synthetic-0001";
const CREATED_AT = 1_790_000_000_000;
const EXPIRES_AT = CREATED_AT + 3_600_000;

const DEK = range(0x00, 32);
const DIGEST_KEY = range(0x40, 32);
const LOCAL_MATERIAL = range(0x80, 32);
const NONCE_1 = range(0xa0, 12);
const NONCE_2 = range(0xb0, 12);
const WRAP_NONCE = range(0xc0, 12);

// U+FF5E sorts after U+10000 by UTF-16 code unit (0xFF5E > 0xD800) and before it by UTF-8 byte (0xEF < 0xF0).
const BMP_HIGH = "～";
const SUPPLEMENTARY = "\u{10000}";

export async function generateVectors() {
  // entryId
  const entryIdInputs = [
    { namespace: NAMESPACE, tenant: TENANT, token: TOKEN_1 },
    { namespace: NAMESPACE, tenant: TENANT, token: TOKEN_2 },
    { namespace: "ns.other:synthetic-2", tenant: TENANT_UNICODE, token: TOKEN_3 },
  ];
  const entryId = [];
  for (const input of entryIdInputs) {
    const preimage = cat(label("rsv-entry-id-v1"), lp16(input.namespace), lp16(input.tenant), lp16(input.token));
    const id = hex(await sha256(preimage));
    assert.equal(await deriveEntryId(input.namespace, input.tenant, input.token), id);
    entryId.push({ ...input, preimage: hex(preimage), entryId: id });
  }
  const ENTRY_1 = entryId[0].entryId;
  const ENTRY_2 = entryId[1].entryId;

  // sessionTag
  const keyed = createDigester({ key: DIGEST_KEY });
  const unkeyed = createDigester({ unkeyed: true });
  const sessionInputs = [
    { namespace: NAMESPACE, tenant: TENANT, captureId: CAPTURE_A, sessionId: SESSION },
    { namespace: NAMESPACE, tenant: TENANT_UNICODE, captureId: CAPTURE_B, sessionId: `session-${SUPPLEMENTARY}` },
  ];
  const sessionTag = [];
  for (const input of sessionInputs) {
    const preimage = sessionTagBytes(input);
    for (const mode of ["keyed", "unkeyed"]) {
      const tag = hex(mode === "keyed" ? await hmac(DIGEST_KEY, preimage) : await sha256(preimage));
      assert.equal(await (mode === "keyed" ? keyed : unkeyed).sessionTag(input), tag);
      sessionTag.push({
        mode,
        key: mode === "keyed" ? hex(DIGEST_KEY) : null,
        input,
        preimage: hex(preimage),
        sessionTag: tag,
      });
    }
  }

  // requestDigest
  const requestInputs = [
    {
      name: "one capture, one use, no session",
      input: {
        namespace: NAMESPACE,
        tenant: TENANT,
        principalId: "principal-synthetic-0001",
        sessionId: null,
        sink: "sink-a",
        purpose: "support-reply-purpose-synthetic",
        captureIds: [CAPTURE_A],
        uses: [{ entryId: ENTRY_1, paths: [{ path: "body", occurrences: 1 }] }],
      },
    },
    {
      name: "session, two captures and two uses given out of order, paths given in UTF-16 order",
      input: {
        namespace: NAMESPACE,
        tenant: TENANT_UNICODE,
        principalId: "principal-synthetic-0002",
        sessionId: SESSION,
        sink: "sink-b",
        purpose: "목적-synthetic-purpose",
        captureIds: [CAPTURE_B, CAPTURE_A],
        uses: [
          {
            entryId: ENTRY_1 < ENTRY_2 ? ENTRY_2 : ENTRY_1,
            paths: [
              { path: SUPPLEMENTARY, occurrences: 2 },
              { path: BMP_HIGH, occurrences: 3 },
              { path: "body", occurrences: 1 },
            ],
          },
          { entryId: ENTRY_1 < ENTRY_2 ? ENTRY_1 : ENTRY_2, paths: [{ path: "subject", occurrences: 4294967295 }] },
        ],
      },
    },
  ];
  const requestDigest = [];
  for (const { name, input } of requestInputs) {
    const preimage = requestBytes(input);
    for (const mode of ["keyed", "unkeyed"]) {
      const digest = mode === "keyed" ? await hmac(DIGEST_KEY, preimage) : await sha256(preimage);
      assert.equal(hex(await (mode === "keyed" ? keyed : unkeyed).requestDigest(input)), hex(digest));
      requestDigest.push({
        name,
        mode,
        key: mode === "keyed" ? hex(DIGEST_KEY) : null,
        input,
        preimage: hex(preimage),
        requestDigest: hex(digest),
      });
    }
  }

  // entryKey
  const entryKey = [];
  for (const id of [ENTRY_1, ENTRY_2]) {
    const info = cat(label("rsv-entry-key-v1"), u8(1), lp16(id));
    entryKey.push({ dek: hex(DEK), entryId: id, salt: hex(new Uint8Array(32)), info: hex(info), entryKey: hex(await hkdf(DEK, info)) });
  }

  // aad
  const bindingBound = {
    namespace: NAMESPACE,
    tenant: TENANT,
    captureId: CAPTURE_A,
    entryId: ENTRY_1,
    sessionId: SESSION,
    createdAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    maxUses: 1,
  };
  const bindingUnbound = {
    namespace: NAMESPACE,
    tenant: TENANT_UNICODE,
    captureId: CAPTURE_A,
    entryId: ENTRY_2,
    sessionId: null,
    createdAt: 0,
    expiresAt: 86_400_000,
    maxUses: 1000,
  };
  const bindingLargeTime = { ...bindingBound, createdAt: 2 ** 53 - 1 - 1000, expiresAt: 2 ** 53 - 1, maxUses: 258 };
  const aad = [];
  for (const [name, binding] of [
    ["session-bound", bindingBound],
    ["not session-bound, non-ASCII tenant, 24-hour lifetime, maxUses 1000", bindingUnbound],
    ["timestamps at the 2^53 - 1 ceiling", bindingLargeTime],
  ]) {
    const bytes = aadBytes(binding);
    assert.equal(hex(encodeAad(binding)), hex(bytes));
    aad.push({ name, binding, aad: hex(bytes) });
  }

  // payload
  const payloadCases = [
    {
      name: "one grant, one path, no policy revision",
      payload: {
        value: "SYNTHETIC-VALUE-0001",
        type: "synthetic-finding-type",
        grants: [{ sink: "sink-a", paths: ["body"] }],
        policyRevision: null,
      },
    },
    {
      name: "policy revision present",
      payload: {
        value: "SYNTHETIC-VALUE-0002 \u{1F9EA} 合成",
        type: "synthetic-finding-type",
        grants: [{ sink: "sink-a", paths: ["body"] }],
        policyRevision: "policy-rev-synthetic-7",
      },
    },
    {
      name: "policy revision present and empty",
      payload: { value: "SYNTHETIC-VALUE-0003", type: "t", grants: [{ sink: "s", paths: ["p"] }], policyRevision: "" },
    },
    {
      name: "empty value",
      payload: { value: "", type: "synthetic-finding-type", grants: [{ sink: "sink-a", paths: ["body"] }], policyRevision: null },
    },
    {
      name: "several grants and paths given out of order",
      payload: {
        value: "SYNTHETIC-VALUE-0004",
        type: "synthetic-finding-type",
        grants: [
          { sink: "sink-b", paths: ["subject", "body", "attachments.0.name"] },
          { sink: "sink-a", paths: ["body"] },
          { sink: "Sink-C", paths: ["b", "a"] },
        ],
        policyRevision: null,
      },
    },
    {
      name: "supplementary character sorts after U+FF5E by UTF-8 bytes, before it by UTF-16 code units",
      payload: {
        value: "SYNTHETIC-VALUE-0005",
        type: "synthetic-finding-type",
        grants: [
          { sink: SUPPLEMENTARY, paths: [SUPPLEMENTARY, BMP_HIGH] },
          { sink: BMP_HIGH, paths: [BMP_HIGH, SUPPLEMENTARY] },
        ],
        policyRevision: null,
      },
    },
  ];
  const payload = [];
  for (const { name, payload: p } of payloadCases) {
    const bytes = canonicalPayload(p);
    assert.equal(hex(encodePayload({ ...p, value: enc(p.value) })), hex(bytes));
    const decoded = decodePayload(bytes);
    payload.push({
      name,
      payload: { ...p, value: hex(enc(p.value)) },
      canonicalGrants: decoded.grants,
      bytes: hex(bytes),
    });
  }

  // envelope: binding + payload -> envelope, under the fixed data key and a fixed nonce
  const envelope = [];
  const sealRecord = async (name, binding, p, nonce) => {
    const info = cat(label("rsv-entry-key-v1"), u8(1), lp16(binding.entryId));
    const key = await hkdf(DEK, info);
    const associated = aadBytes(binding);
    const plaintext = canonicalPayload(p);
    const sealed = await gcmSeal(key, nonce, associated, plaintext);
    const bytes = rawEnvelope({ nonce, sealed });
    assert.equal(hex(encodeEnvelope({ nonce, ciphertext: sealed })), hex(bytes));
    assert.equal(hex(decodeEnvelope(bytes).ciphertext), hex(sealed));
    return {
      name,
      dek: hex(DEK),
      nonce: hex(nonce),
      binding,
      payload: { ...p, value: hex(enc(p.value)) },
      entryKey: hex(key),
      aad: hex(associated),
      plaintext: hex(plaintext),
      envelope: hex(bytes),
    };
  };
  envelope.push(await sealRecord("session-bound entry", bindingBound, payloadCases[0].payload, NONCE_1));
  envelope.push(await sealRecord("second entry of the same capture, not session-bound", bindingUnbound, payloadCases[4].payload, NONCE_2));

  // localWrap
  const context = { namespace: NAMESPACE, tenant: TENANT, captureId: CAPTURE_A };
  const wrapInfo = (c) => cat(label("rsv-local-wrap-v1"), lp16(c.namespace), lp16(c.tenant), lp16(c.captureId));
  const wrappingKey = await hkdf(LOCAL_MATERIAL, wrapInfo(context));
  const wrapped = cat(u8(1), WRAP_NONCE, await gcmSeal(wrappingKey, WRAP_NONCE, null, DEK));
  const localWrap = [
    {
      keyId: "2026-10",
      material: hex(LOCAL_MATERIAL),
      context,
      salt: hex(new Uint8Array(32)),
      info: hex(wrapInfo(context)),
      wrappingKey: hex(wrappingKey),
      dek: hex(DEK),
      nonce: hex(WRAP_NONCE),
      keyRef: "local:2026-10",
      wrappedKey: hex(wrapped),
    },
  ];

  // negative cases
  const good = envelope[0];
  const goodBytes = rawEnvelope({ nonce: NONCE_1, sealed: Uint8Array.from(good.envelope.slice(44).match(/../g), (h) => Number.parseInt(h, 16)) });
  assert.equal(hex(goodBytes), good.envelope);
  const sealed = goodBytes.slice(22);
  const flip = (bytes, index) => {
    const out = bytes.slice();
    out[index] ^= 0x01;
    return out;
  };
  const negativeEnvelope = [
    { name: "empty", bytes: new Uint8Array(0), error: "RECORD_MALFORMED" },
    { name: "magic changed", bytes: rawEnvelope({ magic: "RSVF", nonce: NONCE_1, sealed }), error: "RECORD_MALFORMED" },
    { name: "magic truncated", bytes: enc("RSV"), error: "RECORD_MALFORMED" },
    { name: "formatVersion 0", bytes: rawEnvelope({ version: 0, nonce: NONCE_1, sealed }), error: "RECORD_UNSUPPORTED" },
    { name: "formatVersion 2", bytes: rawEnvelope({ version: 2, nonce: NONCE_1, sealed }), error: "RECORD_UNSUPPORTED" },
    { name: "algorithm 0", bytes: rawEnvelope({ algorithm: 0, nonce: NONCE_1, sealed }), error: "RECORD_UNSUPPORTED" },
    { name: "algorithm 2", bytes: rawEnvelope({ algorithm: 2, nonce: NONCE_1, sealed }), error: "RECORD_UNSUPPORTED" },
    { name: "ends after the algorithm", bytes: goodBytes.slice(0, 6), error: "RECORD_MALFORMED" },
    { name: "ends inside the nonce", bytes: goodBytes.slice(0, 12), error: "RECORD_MALFORMED" },
    { name: "ends inside the length", bytes: goodBytes.slice(0, 20), error: "RECORD_MALFORMED" },
    { name: "last byte removed", bytes: goodBytes.slice(0, -1), error: "RECORD_MALFORMED" },
    { name: "one trailing byte", bytes: cat(goodBytes, u8(0)), error: "RECORD_MALFORMED" },
    { name: "length one less than the bytes present", bytes: rawEnvelope({ nonce: NONCE_1, sealed, length: sealed.length - 1 }), error: "RECORD_MALFORMED" },
    { name: "length one more than the bytes present", bytes: rawEnvelope({ nonce: NONCE_1, sealed, length: sealed.length + 1 }), error: "RECORD_MALFORMED" },
    { name: "length 0xffffffff", bytes: rawEnvelope({ nonce: NONCE_1, sealed, length: 0xffffffff }), error: "RECORD_LIMIT" },
    { name: "length over the envelope ceiling", bytes: rawEnvelope({ nonce: NONCE_1, sealed, length: 1024 * 1024 + 64 * 1024 }), error: "RECORD_LIMIT" },
    { name: "tag only, no ciphertext", bytes: rawEnvelope({ nonce: NONCE_1, sealed: sealed.slice(-16) }), error: "RECORD_MALFORMED" },
    { name: "shorter than a tag", bytes: rawEnvelope({ nonce: NONCE_1, sealed: sealed.slice(-8) }), error: "RECORD_MALFORMED" },
  ].map((item) => ({ name: item.name, envelope: hex(item.bytes), error: item.error }));

  const base = { value: "SYNTHETIC-VALUE-0001", type: "synthetic-finding-type", flag: 0, revision: "" };
  const oneGrant = [{ sink: "sink-a", paths: ["body"] }];
  const goodPayload = rawPayload({ ...base, grants: oneGrant });
  assert.equal(hex(goodPayload), payload[0].bytes);
  const many = (count, prefix) => Array.from({ length: count }, (_unused, i) => `${prefix}${String(i).padStart(4, "0")}`);
  const negativePayloadCases = [
    { name: "empty", bytes: new Uint8Array(0), error: "RECORD_MALFORMED" },
    { name: "payloadVersion 0", bytes: rawPayload({ ...base, version: 0, grants: oneGrant }), error: "RECORD_UNSUPPORTED" },
    { name: "payloadVersion 2", bytes: rawPayload({ ...base, version: 2, grants: oneGrant }), error: "RECORD_UNSUPPORTED" },
    { name: "one trailing byte", bytes: rawPayload({ ...base, grants: oneGrant, trailing: u8(0) }), error: "RECORD_MALFORMED" },
    { name: "last byte removed", bytes: goodPayload.slice(0, -1), error: "RECORD_MALFORMED" },
    { name: "value length past the input", bytes: cat(u8(1), u32(1000), enc("short")), error: "RECORD_MALFORMED" },
    { name: "value length 0xffffffff", bytes: cat(u8(1), u32(0xffffffff), enc("short")), error: "RECORD_LIMIT" },
    { name: "value length one over the limit", bytes: cat(u8(1), u32(1024 * 1024 + 1), enc("short")), error: "RECORD_LIMIT" },
    { name: "type empty", bytes: rawPayload({ ...base, type: "", grants: oneGrant }), error: "RECORD_MALFORMED" },
    { name: "type of 257 bytes", bytes: rawPayload({ ...base, type: "t".repeat(257), grants: oneGrant }), error: "RECORD_LIMIT" },
    { name: "type is invalid UTF-8", bytes: rawPayload({ ...base, type: Uint8Array.of(0x74, 0xff), grants: oneGrant }), error: "RECORD_MALFORMED" },
    { name: "zero grants", bytes: rawPayload({ ...base, grants: [] }), error: "RECORD_MALFORMED" },
    { name: "65 grants", bytes: rawPayload({ ...base, grants: many(65, "sink-").map((sink) => ({ sink, paths: ["body"] })) }), error: "RECORD_LIMIT" },
    { name: "zero paths", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: [] }] }), error: "RECORD_MALFORMED" },
    { name: "257 paths", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: many(257, "path-") }] }), error: "RECORD_LIMIT" },
    { name: "sinks not ascending", bytes: rawPayload({ ...base, grants: [{ sink: "sink-b", paths: ["body"] }, { sink: "sink-a", paths: ["body"] }] }), error: "RECORD_MALFORMED" },
    { name: "duplicate sink", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: ["body"] }, { sink: "sink-a", paths: ["subject"] }] }), error: "RECORD_MALFORMED" },
    { name: "paths not ascending", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: ["subject", "body"] }] }), error: "RECORD_MALFORMED" },
    { name: "duplicate path", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: ["body", "body"] }] }), error: "RECORD_MALFORMED" },
    { name: "paths in UTF-16 code-unit order (supplementary before U+FF5E)", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: [SUPPLEMENTARY, BMP_HIGH] }] }), error: "RECORD_MALFORMED" },
    { name: "sinks in UTF-16 code-unit order (supplementary before U+FF5E)", bytes: rawPayload({ ...base, grants: [{ sink: SUPPLEMENTARY, paths: ["body"] }, { sink: BMP_HIGH, paths: ["body"] }] }), error: "RECORD_MALFORMED" },
    { name: "empty sink", bytes: rawPayload({ ...base, grants: [{ sink: "", paths: ["body"] }] }), error: "RECORD_MALFORMED" },
    { name: "empty path", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: [""] }] }), error: "RECORD_MALFORMED" },
    { name: "sink of 257 code units", bytes: rawPayload({ ...base, grants: [{ sink: "s".repeat(257), paths: ["body"] }] }), error: "RECORD_LIMIT" },
    { name: "sink is invalid UTF-8 (0xff)", bytes: rawPayload({ ...base, grants: [{ sink: Uint8Array.of(0x73, 0xff), paths: ["body"] }] }), error: "RECORD_MALFORMED" },
    { name: "path is an encoded surrogate (ED A0 80)", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: [Uint8Array.of(0xed, 0xa0, 0x80)] }] }), error: "RECORD_MALFORMED" },
    { name: "path is an overlong encoding (C0 AF)", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: [Uint8Array.of(0xc0, 0xaf)] }] }), error: "RECORD_MALFORMED" },
    { name: "path is a truncated sequence (E2 82)", bytes: rawPayload({ ...base, grants: [{ sink: "sink-a", paths: [Uint8Array.of(0xe2, 0x82)] }] }), error: "RECORD_MALFORMED" },
    { name: "presence flag 0 with a non-empty policy revision", bytes: rawPayload({ ...base, grants: oneGrant, flag: 0, revision: "policy-rev-synthetic-7" }), error: "RECORD_MALFORMED" },
    { name: "presence flag 2", bytes: rawPayload({ ...base, grants: oneGrant, flag: 2, revision: "" }), error: "RECORD_MALFORMED" },
    { name: "policy revision of 257 bytes", bytes: rawPayload({ ...base, grants: oneGrant, flag: 1, revision: "r".repeat(257) }), error: "RECORD_LIMIT" },
    { name: "policy revision is invalid UTF-8", bytes: rawPayload({ ...base, grants: oneGrant, flag: 1, revision: Uint8Array.of(0x80) }), error: "RECORD_MALFORMED" },
    { name: "policy revision length past the input", bytes: cat(goodPayload.slice(0, -2), u16(5)), error: "RECORD_MALFORMED" },
  ];
  const negativePayload = negativePayloadCases.map((item) => ({ name: item.name, payload: hex(item.bytes), error: item.error }));

  // open: a binding, an envelope, and the data key, with the error openCapture must report
  const goodKey = await hkdf(DEK, cat(label("rsv-entry-key-v1"), u8(1), lp16(bindingBound.entryId)));
  const authenticNonCanonical = rawPayload({ ...base, grants: [{ sink: "sink-a", paths: ["subject", "body"] }] });
  const authenticUnknownVersion = rawPayload({ ...base, version: 2, grants: oneGrant });
  const sealAuthentic = async (plaintext) =>
    rawEnvelope({ nonce: NONCE_1, sealed: await gcmSeal(goodKey, NONCE_1, aadBytes(bindingBound), plaintext) });
  const openCases = [
    ["namespace changed", { ...bindingBound, namespace: "support-synthetic-2" }, goodBytes, "RECORD_INTEGRITY"],
    ["tenant changed", { ...bindingBound, tenant: "tenant-northwind-synthetic" }, goodBytes, "RECORD_INTEGRITY"],
    ["captureId changed", { ...bindingBound, captureId: CAPTURE_B }, goodBytes, "RECORD_INTEGRITY"],
    ["entryId changed", { ...bindingBound, entryId: ENTRY_2 }, goodBytes, "RECORD_INTEGRITY"],
    ["session changed", { ...bindingBound, sessionId: "session-synthetic-0002" }, goodBytes, "RECORD_INTEGRITY"],
    ["session removed", { ...bindingBound, sessionId: null }, goodBytes, "RECORD_INTEGRITY"],
    ["createdAt changed", { ...bindingBound, createdAt: CREATED_AT + 1 }, goodBytes, "RECORD_INTEGRITY"],
    ["expiresAt changed", { ...bindingBound, expiresAt: EXPIRES_AT + 1 }, goodBytes, "RECORD_INTEGRITY"],
    ["maxUses changed", { ...bindingBound, maxUses: 2 }, goodBytes, "RECORD_INTEGRITY"],
    ["nonce bit flipped", bindingBound, flip(goodBytes, 6), "RECORD_INTEGRITY"],
    ["ciphertext bit flipped", bindingBound, flip(goodBytes, 22), "RECORD_INTEGRITY"],
    ["tag bit flipped", bindingBound, flip(goodBytes, goodBytes.length - 1), "RECORD_INTEGRITY"],
    ["algorithm 2", bindingBound, rawEnvelope({ algorithm: 2, nonce: NONCE_1, sealed }), "RECORD_UNSUPPORTED"],
    ["authentic ciphertext of a payload with unsorted paths", bindingBound, await sealAuthentic(authenticNonCanonical), "RECORD_MALFORMED"],
    ["authentic ciphertext of a payload with payloadVersion 2", bindingBound, await sealAuthentic(authenticUnknownVersion), "RECORD_UNSUPPORTED"],
  ];
  const negativeOpen = openCases.map(([name, binding, bytes, error]) => ({
    name,
    dek: hex(DEK),
    binding,
    envelope: hex(bytes),
    error,
  }));
  // The data key itself is wrong: every other input is the valid vector.
  negativeOpen.push({ name: "different data key", dek: hex(range(0x01, 32)), binding: bindingBound, envelope: good.envelope, error: "RECORD_INTEGRITY" });

  const localCase = (name, changes, error) => ({
    name,
    material: hex(LOCAL_MATERIAL),
    keyId: "2026-10",
    keyRef: "local:2026-10",
    context,
    wrappedKey: hex(wrapped),
    ...changes,
    error,
  });
  const negativeLocalUnwrap = [
    localCase("wrap format version 2", { wrappedKey: hex(cat(u8(2), wrapped.slice(1))) }, "KEY_INTEGRITY"),
    localCase("wrap format version 0", { wrappedKey: hex(cat(u8(0), wrapped.slice(1))) }, "KEY_INTEGRITY"),
    localCase("last byte removed", { wrappedKey: hex(wrapped.slice(0, -1)) }, "KEY_INTEGRITY"),
    localCase("one trailing byte", { wrappedKey: hex(cat(wrapped, u8(0))) }, "KEY_INTEGRITY"),
    localCase("version byte only", { wrappedKey: "01" }, "KEY_INTEGRITY"),
    localCase("nonce bit flipped", { wrappedKey: hex(flip(wrapped, 1)) }, "KEY_INTEGRITY"),
    localCase("ciphertext bit flipped", { wrappedKey: hex(flip(wrapped, 13)) }, "KEY_INTEGRITY"),
    localCase("tag bit flipped", { wrappedKey: hex(flip(wrapped, wrapped.length - 1)) }, "KEY_INTEGRITY"),
    localCase("namespace of the context changed", { context: { ...context, namespace: "support-synthetic-2" } }, "KEY_INTEGRITY"),
    localCase("tenant of the context changed", { context: { ...context, tenant: "tenant-northwind-synthetic" } }, "KEY_INTEGRITY"),
    localCase("captureId of the context changed", { context: { ...context, captureId: CAPTURE_B } }, "KEY_INTEGRITY"),
    localCase("different material", { material: hex(range(0x81, 32)) }, "KEY_INTEGRITY"),
    localCase("key reference names a key the provider does not hold", { keyRef: "local:2026-07" }, "KEY_UNAVAILABLE"),
    localCase("key reference without the local: prefix", { keyRef: "2026-10" }, "KEY_UNAVAILABLE"),
  ];

  return {
    description:
      "Deterministic vectors for record format version 1 (docs/specs/persistent-vault.md). Test-only: every key and nonce here is a public constant. All byte strings are lowercase hexadecimal. See README.md.",
    formatVersion: 1,
    entryId,
    sessionTag,
    requestDigest,
    entryKey,
    aad,
    payload,
    envelope,
    localWrap,
    negative: {
      envelope: negativeEnvelope,
      payload: negativePayload,
      open: negativeOpen,
      localUnwrap: negativeLocalUnwrap,
    },
  };
}

export const VECTORS_PATH = fileURLToPath(new URL("./vectors.json", import.meta.url));

export function serializeVectors(vectors) {
  return `${JSON.stringify(vectors, null, 2)}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const serialized = serializeVectors(await generateVectors());
  if (process.argv.includes("--check")) {
    assert.equal(await readFile(VECTORS_PATH, "utf8"), serialized, "vectors.json is out of date");
    console.log("vectors.json matches");
  } else {
    await writeFile(VECTORS_PATH, serialized);
    console.log(`wrote ${VECTORS_PATH}`);
  }
}
