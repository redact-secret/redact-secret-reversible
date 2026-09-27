/**
 * The issued-token grammar, exactly as fixed by
 * docs/decisions/2026-09-27-bind-issued-tokens-to-approved-output.md and
 * implemented in `packages/vault/src/token.ts`. `@redact-secret/vault` does
 * not export its token module (`token.ts` is not part of its public
 * `exports` map), so this package — which must classify tokens embedded in
 * restore-field text *before* it is safe to call the underlying vault (see
 * server-vault.ts's preflight) — keeps its own copy of the same public,
 * documented grammar rather than reaching into the other package's
 * internals.
 *
 * `test/token-pattern.test.mjs` guards against drift: it captures a real
 * token from a live `@redact-secret/vault` instance and asserts it matches
 * this pattern exactly.
 */
export const TOKEN_PATTERN = /<rsv_[a-z2-7]{26}>/g;

/**
 * Any case-insensitive occurrence of the token marker, including one split
 * by invisible format characters (Unicode category Cf). Text containing a
 * marker that is not part of an exact token is treated as an altered or
 * spoofed token and rejected, never passed through as if ordinary text.
 */
export const MARKER_PATTERN = /r\p{Cf}*s\p{Cf}*v\p{Cf}*_/giu;

export function countMatches(pattern: RegExp, text: string): number {
  pattern.lastIndex = 0;
  let count = 0;
  while (pattern.exec(text) !== null) count += 1;
  pattern.lastIndex = 0;
  return count;
}
