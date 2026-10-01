/**
 * Identifier and digest derivations of docs/specs/persistent-vault.md §3.2
 * and §7.3, on platform WebCrypto. `@redact-secret/vault-crypto` exports the
 * same derivations; this package does not depend on it (the crypto layer is
 * injected), so the bytes are fixed by the shared vectors in
 * conformance/persistent/v1/vectors.json, which this package's tests replay.
 */
import { isWellFormed } from "@redact-secret/vault-contracts";

const encoder = new TextEncoder();

function utf8(text: string): Uint8Array {
  if (!isWellFormed(text)) throw new RangeError("ill-formed string");
  return encoder.encode(text);
}

class Writer {
  readonly #chunks: Uint8Array[] = [];
  #length = 0;

  bytes(value: Uint8Array): this {
    this.#chunks.push(value);
    this.#length += value.byteLength;
    return this;
  }

  label(text: string): this {
    return this.bytes(utf8(text)).u8(0);
  }

  u8(value: number): this {
    return this.bytes(Uint8Array.of(value & 0xff));
  }

  u16(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError("u16 out of range");
    return this.bytes(Uint8Array.of(value >>> 8, value & 0xff));
  }

  u32(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError("u32 out of range");
    return this.bytes(Uint8Array.of(value >>> 24, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff));
  }

  lp16(text: string): this {
    const encoded = utf8(text);
    return this.u16(encoded.byteLength).bytes(encoded);
  }

  finish(): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(this.#length);
    let offset = 0;
    for (const chunk of this.#chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out;
  }
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Unsigned byte-wise comparison of the UTF-8 encodings (§3.1). */
function compareUtf8(a: string, b: string): number {
  const x = utf8(a);
  const y = utf8(b);
  const length = Math.min(x.byteLength, y.byteLength);
  for (let i = 0; i < length; i += 1) {
    const difference = (x[i] as number) - (y[i] as number);
    if (difference !== 0) return difference;
  }
  return x.byteLength - y.byteLength;
}

export async function deriveEntryId(namespace: string, tenant: string, token: string): Promise<string> {
  const input = new Writer().label("rsv-entry-id-v1").lp16(namespace).lp16(tenant).lp16(token).finish();
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}

export interface RequestDigestInput {
  readonly namespace: string;
  readonly tenant: string;
  readonly principalId: string;
  readonly sessionId: string | null;
  readonly sink: string;
  readonly purpose: string;
  readonly captureIds: readonly string[];
  readonly uses: readonly {
    readonly entryId: string;
    readonly paths: readonly { readonly path: string; readonly occurrences: number }[];
  }[];
}

export interface Digester {
  requestDigest(input: RequestDigestInput): Promise<Uint8Array>;
  sessionTag(input: {
    readonly namespace: string;
    readonly tenant: string;
    readonly captureId: string;
    readonly sessionId: string;
  }): Promise<string>;
}

/** HMAC-SHA-256 under `key`, or plain SHA-256 when `key` is `null` (the explicit unkeyed opt-out). */
export async function createDigester(key: Uint8Array | null): Promise<Digester> {
  let mac: (data: Uint8Array<ArrayBuffer>) => Promise<Uint8Array>;
  if (key === null) {
    mac = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  } else {
    const imported = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    mac = async (data) => new Uint8Array(await crypto.subtle.sign("HMAC", imported, data));
  }

  return {
    async requestDigest(input) {
      const writer = new Writer()
        .label("rsv-request-v1")
        .lp16(input.namespace)
        .lp16(input.tenant)
        .lp16(input.principalId)
        .u8(input.sessionId === null ? 0 : 1)
        .lp16(input.sessionId ?? "")
        .lp16(input.sink)
        .lp16(input.purpose);
      const captures = [...input.captureIds].sort(compareUtf8);
      writer.u16(captures.length);
      for (const captureId of captures) writer.lp16(captureId);
      const uses = [...input.uses].sort((a, b) => compareUtf8(a.entryId, b.entryId));
      writer.u16(uses.length);
      for (const use of uses) {
        writer.lp16(use.entryId);
        const paths = [...use.paths].sort((a, b) => compareUtf8(a.path, b.path));
        writer.u16(paths.length);
        for (const { path, occurrences } of paths) writer.lp16(path).u32(occurrences);
      }
      return mac(writer.finish());
    },
    async sessionTag(input) {
      const data = new Writer()
        .label("rsv-session-tag-v1")
        .lp16(input.namespace)
        .lp16(input.tenant)
        .lp16(input.captureId)
        .lp16(input.sessionId)
        .finish();
      return hex(await mac(data));
    },
  };
}

/** Comparison whose duration does not depend on where two equal-length strings differ. */
export function equalTags(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i += 1) difference |= (a[i] as number) ^ (b[i] as number);
  return difference === 0;
}
