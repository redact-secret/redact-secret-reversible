/**
 * Canonical encodings of record format version 1: associated data (§3.4),
 * payload and envelope (§3.5), under the limits of §3.6. Pure functions: no
 * key, no randomness, no I/O. Every failure is a `RecordCryptoError` with a
 * fixed message.
 */
import {
  isCaptureId,
  isEntryId,
  isIdentifier,
  isNamespace,
  isTimestamp,
  LIMITS,
  type RecordBinding,
  type RecordPayload,
} from "@redact-secret/vault-contracts";
import {
  type Bytes,
  compareBytes,
  concat,
  fail,
  fromUtf8,
  isBytes,
  label,
  lp16,
  Reader,
  u8,
  u16,
  u32,
  u64,
  utf8,
} from "./bytes.js";

export const FORMAT_VERSION = 1;
export const PAYLOAD_VERSION = 1;
/** AES-256-GCM, 96-bit nonce, 128-bit tag (§3.3). The only allowed algorithm. */
export const ALGORITHM_AES_256_GCM = 1;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;

const MAGIC = Uint8Array.of(0x52, 0x53, 0x56, 0x45); // "RSVE"
/** magic, formatVersion, algorithm, nonce, u32 length. */
const ENVELOPE_HEADER_BYTES = MAGIC.byteLength + 1 + 1 + NONCE_BYTES + 4;
const MAX_SEALED_BYTES = LIMITS.maxEnvelopeBytes - ENVELOPE_HEADER_BYTES;
/** The largest payload whose envelope still fits `LIMITS.maxEnvelopeBytes`. */
export const MAX_PAYLOAD_BYTES = MAX_SEALED_BYTES - TAG_BYTES;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** A validated copy of a binding, so later mutation by the caller changes nothing. */
export function snapshotBinding(binding: unknown): RecordBinding {
  if (!isObject(binding)) fail("RECORD_INVALID_ARGUMENT");
  const { namespace, tenant, captureId, entryId, sessionId, createdAt, expiresAt, maxUses } = binding;
  if (!isNamespace(namespace) || !isIdentifier(tenant) || !isCaptureId(captureId) || !isEntryId(entryId)) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  if (sessionId !== null && !isIdentifier(sessionId)) fail("RECORD_INVALID_ARGUMENT");
  if (!isTimestamp(createdAt) || !isTimestamp(expiresAt)) fail("RECORD_INVALID_ARGUMENT");
  const lifetime = expiresAt - createdAt;
  if (lifetime <= 0 || lifetime > LIMITS.maxCaptureLifetimeMs) fail("RECORD_INVALID_ARGUMENT");
  if (typeof maxUses !== "number" || !Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > LIMITS.maxUses) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  return { namespace, tenant, captureId, entryId, sessionId, createdAt, expiresAt, maxUses };
}

/** The associated data of §3.4 for one entry. */
export function encodeAad(binding: RecordBinding): Bytes {
  const b = snapshotBinding(binding);
  return concat([
    label("rsv-aad-v1"),
    u8(FORMAT_VERSION),
    u8(ALGORITHM_AES_256_GCM),
    lp16(utf8(b.namespace)),
    lp16(utf8(b.tenant)),
    lp16(utf8(b.captureId)),
    lp16(utf8(b.entryId)),
    u8(b.sessionId === null ? 0 : 1),
    lp16(b.sessionId === null ? new Uint8Array(0) : utf8(b.sessionId)),
    u64(b.createdAt),
    u64(b.expiresAt),
    u32(b.maxUses),
  ]);
}

/** Encodes identifiers, sorts them by UTF-8 bytes, and rejects a duplicate. */
function canonicalSet(values: readonly unknown[]): Bytes[] {
  const encoded = values.map((value) => {
    if (!isIdentifier(value)) fail("RECORD_INVALID_ARGUMENT");
    return utf8(value);
  });
  encoded.sort(compareBytes);
  for (let i = 1; i < encoded.length; i += 1) {
    if (compareBytes(encoded[i - 1] as Bytes, encoded[i] as Bytes) === 0) fail("RECORD_INVALID_ARGUMENT");
  }
  return encoded;
}

/**
 * A validated payload ready to be written. It holds the encoded metadata and
 * a reference to the caller's value, not a copy: the plaintext is copied only
 * by `writePayload`, into a buffer the caller of that function overwrites.
 */
export interface PayloadPlan {
  readonly value: Uint8Array;
  readonly valueBytes: number;
  readonly type: Bytes;
  readonly grants: readonly { readonly sink: Bytes; readonly paths: readonly Bytes[] }[];
  readonly policyRevision: Bytes | null;
  readonly size: number;
}

export function planPayload(payload: unknown): PayloadPlan {
  if (!isObject(payload)) fail("RECORD_INVALID_ARGUMENT");
  const { value, type, grants, policyRevision } = payload;
  if (!isBytes(value)) fail("RECORD_INVALID_ARGUMENT");
  if (value.byteLength > LIMITS.maxValueBytes) fail("RECORD_LIMIT");
  if (typeof type !== "string" || type.length === 0) fail("RECORD_INVALID_ARGUMENT");
  if (type.length > LIMITS.typeMaxBytes) fail("RECORD_LIMIT");
  const typeBytes = utf8(type);
  if (typeBytes.byteLength > LIMITS.typeMaxBytes) fail("RECORD_LIMIT");

  let revisionBytes: Bytes | null = null;
  if (policyRevision !== null) {
    if (typeof policyRevision !== "string") fail("RECORD_INVALID_ARGUMENT");
    if (policyRevision.length > LIMITS.policyRevisionMaxBytes) fail("RECORD_LIMIT");
    revisionBytes = utf8(policyRevision);
    if (revisionBytes.byteLength > LIMITS.policyRevisionMaxBytes) fail("RECORD_LIMIT");
  }

  if (!Array.isArray(grants) || grants.length === 0) fail("RECORD_INVALID_ARGUMENT");
  if (grants.length > LIMITS.maxGrants) fail("RECORD_LIMIT");
  let size = 1 + 4 + value.byteLength + 2 + typeBytes.byteLength + 2 + 1 + 2 + (revisionBytes?.byteLength ?? 0);
  const encodedGrants: { sink: Bytes; paths: readonly Bytes[] }[] = [];
  for (const grant of grants as readonly unknown[]) {
    if (!isObject(grant) || !Array.isArray(grant.paths) || grant.paths.length === 0) fail("RECORD_INVALID_ARGUMENT");
    if (grant.paths.length > LIMITS.maxPathsPerGrant) fail("RECORD_LIMIT");
    if (!isIdentifier(grant.sink)) fail("RECORD_INVALID_ARGUMENT");
    const sink = utf8(grant.sink);
    const paths = canonicalSet(grant.paths as readonly unknown[]);
    size += 2 + sink.byteLength + 2;
    for (const path of paths) size += 2 + path.byteLength;
    if (size > MAX_PAYLOAD_BYTES) fail("RECORD_LIMIT");
    encodedGrants.push({ sink, paths });
  }
  if (size > MAX_PAYLOAD_BYTES) fail("RECORD_LIMIT");
  encodedGrants.sort((a, b) => compareBytes(a.sink, b.sink));
  for (let i = 1; i < encodedGrants.length; i += 1) {
    const previous = encodedGrants[i - 1] as { sink: Bytes };
    if (compareBytes(previous.sink, (encodedGrants[i] as { sink: Bytes }).sink) === 0) fail("RECORD_INVALID_ARGUMENT");
  }
  return {
    value,
    valueBytes: value.byteLength,
    type: typeBytes,
    grants: encodedGrants,
    policyRevision: revisionBytes,
    size,
  };
}

/** Writes a planned payload. The result holds plaintext; the caller overwrites it. */
export function writePayload(plan: PayloadPlan): Bytes {
  // The value is referenced, not copied, by the plan: refuse one that changed size since.
  if (plan.value.byteLength !== plan.valueBytes) fail("RECORD_INVALID_ARGUMENT");
  const out = new Uint8Array(plan.size);
  let offset = 0;
  const put = (bytes: Uint8Array): void => {
    out.set(bytes, offset);
    offset += bytes.byteLength;
  };
  put(u8(PAYLOAD_VERSION));
  put(u32(plan.valueBytes));
  put(plan.value);
  put(lp16(plan.type));
  put(u16(plan.grants.length));
  for (const grant of plan.grants) {
    put(lp16(grant.sink));
    put(u16(grant.paths.length));
    for (const path of grant.paths) put(lp16(path));
  }
  put(u8(plan.policyRevision === null ? 0 : 1));
  put(lp16(plan.policyRevision ?? new Uint8Array(0)));
  return out;
}

/**
 * The plaintext of §3.5. Grants are sorted by the UTF-8 bytes of their sink
 * and paths by their UTF-8 bytes; a duplicate sink, or a duplicate path
 * within a grant, is rejected. The result holds the value: overwrite it.
 */
export function encodePayload(payload: RecordPayload): Bytes {
  return writePayload(planPayload(payload));
}

function readIdentifier(reader: Reader, previous: Uint8Array | null): { bytes: Uint8Array; text: string } {
  const bytes = reader.take(reader.u16());
  if (bytes.byteLength === 0) fail("RECORD_MALFORMED");
  if (previous !== null && compareBytes(previous, bytes) >= 0) fail("RECORD_MALFORMED");
  const text = fromUtf8(bytes);
  if (text.length > LIMITS.identifierMaxLength) fail("RECORD_LIMIT");
  return { bytes, text };
}

/**
 * Strict inverse of `encodePayload`. Rejects an unknown version, a length
 * past the input, a value over a limit, a zero count, a non-canonical order,
 * a duplicate, a presence flag other than 0 or 1, a non-empty field whose
 * flag is 0, invalid UTF-8, and trailing bytes. `value` is a fresh copy.
 */
export function decodePayload(bytes: Uint8Array): RecordPayload {
  if (!isBytes(bytes)) fail("RECORD_INVALID_ARGUMENT");
  if (bytes.byteLength > MAX_PAYLOAD_BYTES) fail("RECORD_LIMIT");
  const reader = new Reader(bytes);
  if (reader.u8() !== PAYLOAD_VERSION) fail("RECORD_UNSUPPORTED");

  const valueBytes = reader.u32();
  if (valueBytes > LIMITS.maxValueBytes) fail("RECORD_LIMIT");
  const valueView = reader.take(valueBytes);

  const typeLength = reader.u16();
  if (typeLength > LIMITS.typeMaxBytes) fail("RECORD_LIMIT");
  if (typeLength === 0) fail("RECORD_MALFORMED");
  const type = fromUtf8(reader.take(typeLength));

  const grantCount = reader.u16();
  if (grantCount === 0) fail("RECORD_MALFORMED");
  if (grantCount > LIMITS.maxGrants) fail("RECORD_LIMIT");
  const grants: { sink: string; paths: readonly string[] }[] = [];
  let previousSink: Uint8Array | null = null;
  for (let g = 0; g < grantCount; g += 1) {
    const sink = readIdentifier(reader, previousSink);
    previousSink = sink.bytes;
    const pathCount = reader.u16();
    if (pathCount === 0) fail("RECORD_MALFORMED");
    if (pathCount > LIMITS.maxPathsPerGrant) fail("RECORD_LIMIT");
    const paths: string[] = [];
    let previousPath: Uint8Array | null = null;
    for (let p = 0; p < pathCount; p += 1) {
      const path = readIdentifier(reader, previousPath);
      previousPath = path.bytes;
      paths.push(path.text);
    }
    grants.push(Object.freeze({ sink: sink.text, paths: Object.freeze(paths) }));
  }

  const hasPolicyRevision = reader.u8();
  if (hasPolicyRevision !== 0 && hasPolicyRevision !== 1) fail("RECORD_MALFORMED");
  const revisionLength = reader.u16();
  if (revisionLength > LIMITS.policyRevisionMaxBytes) fail("RECORD_LIMIT");
  if (hasPolicyRevision === 0 && revisionLength !== 0) fail("RECORD_MALFORMED");
  const revision = fromUtf8(reader.take(revisionLength));
  reader.end();

  return Object.freeze({
    value: valueView.slice(),
    type,
    grants: Object.freeze(grants),
    policyRevision: hasPolicyRevision === 1 ? revision : null,
  });
}

export interface EnvelopeParts {
  /** 12 bytes. */
  readonly nonce: Uint8Array;
  /** AES-GCM output: ciphertext followed by the 16-byte tag. */
  readonly ciphertext: Uint8Array;
}

export interface DecodedEnvelope extends EnvelopeParts {
  readonly formatVersion: 1;
  readonly algorithm: 1;
}

/** The stored envelope of §3.5. */
export function encodeEnvelope(parts: EnvelopeParts): Bytes {
  if (!isObject(parts) || !isBytes(parts.nonce) || !isBytes(parts.ciphertext)) fail("RECORD_INVALID_ARGUMENT");
  if (parts.nonce.byteLength !== NONCE_BYTES || parts.ciphertext.byteLength <= TAG_BYTES) {
    fail("RECORD_INVALID_ARGUMENT");
  }
  if (parts.ciphertext.byteLength > MAX_SEALED_BYTES) fail("RECORD_LIMIT");
  return concat([
    MAGIC,
    u8(FORMAT_VERSION),
    u8(ALGORITHM_AES_256_GCM),
    parts.nonce,
    u32(parts.ciphertext.byteLength),
    parts.ciphertext,
  ]);
}

/**
 * Parses an envelope into views over `bytes`, allocating nothing. The magic,
 * the version, and the algorithm allowlist are checked before any length.
 */
export function parseEnvelope(bytes: unknown): DecodedEnvelope {
  if (!isBytes(bytes)) fail("RECORD_INVALID_ARGUMENT");
  if (bytes.byteLength > LIMITS.maxEnvelopeBytes) fail("RECORD_LIMIT");
  const reader = new Reader(bytes);
  const magic = reader.take(MAGIC.byteLength);
  if (compareBytes(magic, MAGIC) !== 0) fail("RECORD_MALFORMED");
  if (reader.u8() !== FORMAT_VERSION) fail("RECORD_UNSUPPORTED");
  if (reader.u8() !== ALGORITHM_AES_256_GCM) fail("RECORD_UNSUPPORTED");
  const nonce = reader.take(NONCE_BYTES);
  const sealedBytes = reader.u32();
  if (sealedBytes > MAX_SEALED_BYTES) fail("RECORD_LIMIT");
  if (sealedBytes !== reader.remaining || sealedBytes <= TAG_BYTES) fail("RECORD_MALFORMED");
  const ciphertext = reader.take(sealedBytes);
  return { formatVersion: 1, algorithm: 1, nonce, ciphertext };
}

/** Strict inverse of `encodeEnvelope`. The returned arrays are copies. */
export function decodeEnvelope(bytes: Uint8Array): DecodedEnvelope {
  const parsed = parseEnvelope(bytes);
  return { formatVersion: 1, algorithm: 1, nonce: parsed.nonce.slice(), ciphertext: parsed.ciphertext.slice() };
}
