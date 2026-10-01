/**
 * Byte helpers for record format version 1 (docs/specs/persistent-vault.md
 * §3.1). Integers are unsigned and big-endian. A string is encoded only after
 * it has been tested for well-formedness, and decoded only by a decoder that
 * rejects invalid input and keeps a leading U+FEFF.
 */
import { isWellFormed, RecordCryptoError, type RecordCryptoErrorCode } from "@redact-secret/vault-contracts";

/** A byte array this package allocated itself, over a plain `ArrayBuffer`. */
export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function fail(code: RecordCryptoErrorCode): never {
  throw new RecordCryptoError(code);
}

/** The platform WebCrypto, or `RECORD_UNSUPPORTED` when the runtime has none. */
export function webcrypto(): Crypto {
  const candidate = (globalThis as { crypto?: Crypto }).crypto;
  if (
    candidate === undefined ||
    candidate.subtle === undefined ||
    typeof candidate.getRandomValues !== "function"
  ) {
    fail("RECORD_UNSUPPORTED");
  }
  return candidate;
}

export function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/** A view WebCrypto accepts, over the same memory. */
export function view(bytes: Uint8Array): Bytes {
  return bytes as Bytes;
}

export function zero(bytes: Uint8Array | undefined | null): void {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

/** UTF-8 bytes of a well-formed string. A lone surrogate is `RECORD_INVALID_ARGUMENT`. */
export function utf8(text: unknown): Bytes {
  if (typeof text !== "string" || !isWellFormed(text)) fail("RECORD_INVALID_ARGUMENT");
  return encoder.encode(text);
}

/** Strict UTF-8 decoding. Invalid input is `RECORD_MALFORMED`. */
export function fromUtf8(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    return fail("RECORD_MALFORMED");
  }
}

/** Unsigned lexicographic comparison: negative, zero, or positive. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.byteLength, b.byteLength);
  for (let i = 0; i < shared; i += 1) {
    const difference = (a[i] as number) - (b[i] as number);
    if (difference !== 0) return difference;
  }
  return a.byteLength - b.byteLength;
}

const HEX = "0123456789abcdef";

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += (HEX[byte >>> 4] as string) + (HEX[byte & 15] as string);
  return out;
}

export function concat(parts: readonly Uint8Array[]): Bytes {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

export function u8(value: number): Bytes {
  return Uint8Array.of(value & 0xff);
}

export function u16(value: number): Bytes {
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

export function u32(value: number): Bytes {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

/** `value` is a non-negative safe integer. */
export function u64(value: number): Bytes {
  const high = Math.floor(value / 0x1_0000_0000);
  const low = value % 0x1_0000_0000;
  return concat([u32(high), u32(low)]);
}

/** `u16` length, then the bytes. The caller has checked the length fits. */
export function lp16(bytes: Uint8Array): Bytes {
  if (bytes.byteLength > 0xffff) fail("RECORD_LIMIT");
  return concat([u16(bytes.byteLength), bytes]);
}

/** A label followed by one zero byte, as every domain separator in §3 and §7.3 is written. */
export function label(text: string): Bytes {
  return concat([encoder.encode(text), u8(0)]);
}

/** A bounds-checked cursor. It returns views and never allocates from a length field. */
export class Reader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  get remaining(): number {
    return this.#bytes.byteLength - this.#offset;
  }

  take(length: number): Uint8Array {
    if (length > this.remaining) fail("RECORD_MALFORMED");
    const out = this.#bytes.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return out;
  }

  u8(): number {
    return this.take(1)[0] as number;
  }

  u16(): number {
    const b = this.take(2);
    return ((b[0] as number) << 8) | (b[1] as number);
  }

  u32(): number {
    const b = this.take(4);
    return (((b[0] as number) << 24) | ((b[1] as number) << 16) | ((b[2] as number) << 8) | (b[3] as number)) >>> 0;
  }

  end(): void {
    if (this.remaining !== 0) fail("RECORD_MALFORMED");
  }
}
