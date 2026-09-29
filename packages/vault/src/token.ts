/**
 * Issued-token grammar (see docs/decisions/2026-09-27-bind-issued-tokens-to-approved-output.md).
 *
 * A token is `<rsv_` + 26 lowercase RFC 4648 base32 characters + `>`: 130
 * bits of which the leading 128 come from the platform CSPRNG. The token
 * names no finding type; type is descriptive metadata returned beside it, and
 * never an input to lookup or authorization.
 */
const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
export const TOKEN_BODY_LENGTH = 26;
export const TOKEN_LENGTH = TOKEN_BODY_LENGTH + 6;

/** Exact issued-token grammar. Global: callers must reset `lastIndex`. */
export const TOKEN_PATTERN = /<rsv_[a-z2-7]{26}>/g;

/**
 * Any case-insensitive occurrence of the token marker, including one split by
 * invisible format characters (Unicode category Cf). Text containing a
 * marker that is not part of an exact token is treated as an altered or
 * spoofed token and rejected, never passed through as if ordinary text.
 */
export const MARKER_PATTERN = /r\p{Cf}*s\p{Cf}*v\p{Cf}*_/giu;

export type RandomFill = (bytes: Uint8Array<ArrayBuffer>) => void;

export function resolveRandomFill(): RandomFill | undefined {
  const cryptoObject = (globalThis as { crypto?: Crypto }).crypto;
  if (cryptoObject === undefined || typeof cryptoObject.getRandomValues !== "function") {
    return undefined;
  }
  const getRandomValues = cryptoObject.getRandomValues;
  return (bytes) => {
    getRandomValues.call(cryptoObject, bytes);
  };
}

export function newToken(fill: RandomFill): string {
  const bytes = new Uint8Array(17);
  fill(bytes.subarray(0, 16));
  bytes[16] = 0;
  let out = "<rsv_";
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < bytes.length && out.length < TOKEN_BODY_LENGTH + 5; i += 1) {
    buffer = (buffer << 8) | (bytes[i] as number);
    bits += 8;
    while (bits >= 5 && out.length < TOKEN_BODY_LENGTH + 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  bytes.fill(0);
  return `${out}>`;
}

/** Opaque identifier for a capture; same entropy, distinct grammar. */
export function newCaptureId(fill: RandomFill): string {
  return `cap_${newToken(fill).slice(5, -1)}`;
}

export function countMatches(pattern: RegExp, text: string): number {
  pattern.lastIndex = 0;
  let count = 0;
  while (pattern.exec(text) !== null) count += 1;
  pattern.lastIndex = 0;
  return count;
}

/**
 * Whether `text` holds each of `expected` exactly once and no other token
 * marker, checked in one pass over `text`.
 *
 * Every marker match must be the `rsv_` of an exact token in `expected` that
 * has not been seen yet, and the number of matches must equal
 * `expected.size`. Together these say each expected token occurs exactly
 * once: an occurrence of a token always yields a marker match at its own
 * `r` (the body alphabet has no `_`, so matches cannot overlap a token), a
 * repeat is caught as already seen, and a missing token leaves the count
 * short. A marker that is altered, forged, differs in case, or is split by
 * format characters does not slice to an expected token and fails.
 */
export function holdsExactlyOnce(text: string, expected: ReadonlySet<string>): boolean {
  const seen = new Set<string>();
  MARKER_PATTERN.lastIndex = 0;
  try {
    for (let match = MARKER_PATTERN.exec(text); match !== null; match = MARKER_PATTERN.exec(text)) {
      const start = match.index - 1;
      if (start < 0) return false;
      const token = text.slice(start, start + TOKEN_LENGTH);
      if (!expected.has(token) || seen.has(token)) return false;
      seen.add(token);
    }
  } finally {
    MARKER_PATTERN.lastIndex = 0;
  }
  return seen.size === expected.size;
}
