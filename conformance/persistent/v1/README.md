# Persistent record format, version 1: test vectors

`vectors.json` holds the deterministic vectors that [the persistent vault specification](../../../docs/specs/persistent-vault.md) §3.8 requires. An implementation in any language must reproduce every positive vector byte for byte and must reject every negative case with the listed error.

**Test-only.** The data key (`00 01 … 1f`), the nonces, the digest key, and the wrapping material in this directory are public constants. They exist so that outputs are reproducible. Never use them, or a fixed nonce, to protect anything: the implementation draws every nonce and data key from the platform CSPRNG.

## Files

| File | Purpose |
| --- | --- |
| `vectors.json` | The vectors. Generated; do not edit by hand. |
| `generate-vectors.mjs` | Writes `vectors.json`. Each positive vector is computed twice, once from the byte layout written out in the script with WebCrypto called directly, and once by `@redact-secret/vault-crypto`; the script fails if they differ. `--check` compares without writing. |
| `verify_vectors.py` | A cross-check that shares no code with the JavaScript package: Python's standard library for SHA-256, HMAC, and HKDF, and the `cryptography` package for AES-256-GCM. |
| `schedules.json`, `orchestrator.mjs`, `driver-js.mjs` | The schedule corpus for the Store contract and the server profile, its orchestrator, and the JavaScript driver. Not vectors: see [SCHEDULES.md](SCHEDULES.md). |

```sh
npm run build -w @redact-secret/vault-contracts
npm run build -w @redact-secret/vault-crypto
node conformance/persistent/v1/generate-vectors.mjs --check
uv run --with cryptography python conformance/persistent/v1/verify_vectors.py
```

`verify_vectors.py` exits 3, not 0, when `cryptography` is not importable: the hash and HKDF checks still run, but a run without the AES-GCM checks is not a pass.

## Conventions

- The file is UTF-8. Every byte string is lowercase hexadecimal. Every other string is the exact Unicode string to encode as UTF-8, with no normalization.
- Integers are big-endian. `lp16(x)` is a 16-bit length followed by the bytes, `lp32(x)` a 32-bit length.
- "Sorted" means ascending order of UTF-8 bytes compared as unsigned values. Several vectors use U+FF5E and U+10000 together: UTF-8 order puts U+FF5E (`ef bd 9e`) first, and a UTF-16 code-unit sort puts U+10000 (`d800 dc00`) first. An implementation that sorts native strings in a UTF-16 language fails those vectors.
- `preimage` fields are the exact bytes that were hashed or MACed. They are there to locate a mismatch; a conforming implementation only has to match the result.

## Positive groups

| Group | Inputs | Expected |
| --- | --- | --- |
| `entryId` | `namespace`, `tenant`, `token` (as issued, with `<` and `>`) | `entryId`: hexadecimal SHA-256 of `preimage` (§3.2) |
| `sessionTag` | `mode`, `key` (null when unkeyed), `input` | `sessionTag`: HMAC-SHA-256 under `key` when `mode` is `keyed`, SHA-256 when `unkeyed` (§3.2) |
| `requestDigest` | `mode`, `key`, `input` | `requestDigest` (§7.3). `input.captureIds`, `input.uses`, and each `paths` list are deliberately given out of order in one case; the implementation sorts them |
| `entryKey` | `dek`, `entryId` | `entryKey`: HKDF-SHA-256 with `salt` and `info` as shown, 32 bytes (§3.3) |
| `aad` | `binding` | `aad` (§3.4). A null `sessionId` means not session-bound |
| `payload` | `payload` (`value` in hexadecimal; grants as the caller gave them) | `bytes` (§3.5), and `canonicalGrants`, what a decoder returns |
| `envelope` | `dek`, `nonce`, `binding`, `payload` | `entryKey`, `aad`, `plaintext`, and `envelope`: the full stored envelope (§3.5) |
| `localWrap` | `material`, `context`, `dek`, `nonce` | `info`, `wrappingKey`, `keyRef`, and `wrappedKey` of the local provider (§6.3) |

To use `envelope` in an implementation whose public API draws its own nonce and data key: build the envelope from the lower-level pieces (entry key derivation, associated data, payload encoding, AES-256-GCM with the given nonce) and compare; then open the vector's envelope through the public API, with a test key provider that returns `dek`, and compare the payload. The JavaScript package exports no function that accepts a caller-chosen nonce.

To use `localWrap`: unwrap `wrappedKey` with a provider constructed from `material` and compare with `dek`. Wrapping with the fixed `nonce` needs the lower-level primitive. The local provider passes no additional data to AES-GCM; the context is bound through the HKDF `info` alone.

## Negative groups

Each case names the error code an implementation must report. In another language, map the code to that language's equivalent error; what matters is that the input is rejected, and for which class of reason.

| Group | How to run it | Codes |
| --- | --- | --- |
| `negative.envelope` | Decode `envelope` | `RECORD_MALFORMED`, `RECORD_UNSUPPORTED`, `RECORD_LIMIT` |
| `negative.payload` | Decode `payload` as the plaintext of §3.5 | `RECORD_MALFORMED`, `RECORD_UNSUPPORTED`, `RECORD_LIMIT` |
| `negative.open` | Open `envelope` under `binding`, with a test provider that returns `dek` | `RECORD_INTEGRITY` for a changed binding, flipped bit, or wrong key; `RECORD_UNSUPPORTED` or `RECORD_MALFORMED` where stated |
| `negative.localUnwrap` | Unwrap `wrappedKey` with a local provider holding `material` as key `keyId`, scoped to allow the `context` | `KEY_INTEGRITY`, `KEY_UNAVAILABLE` |

Two cases in `negative.open` are authentic ciphertexts of a payload that is not canonical or has an unknown payload version. They show that the payload decoder is applied after authentication and is as strict there as on its own.

A case with an oversized length field (`0xffffffff`) must be rejected from the header. An implementation must not allocate what a length field claims.

Not in the file, because JSON cannot carry it portably: a string with a lone surrogate. Every implementation must reject one in any identifier, type, sink, path, purpose, or policy revision before encoding, and must not substitute U+FFFD.

## Choices these vectors fix

The specification leaves a few points open. The vectors record the reading the JavaScript implementation took, so another implementation matches it; each is reported for the specification to settle.

- A `type` of zero length is rejected (`RECORD_MALFORMED` on decode). A policy revision that is present and empty is accepted and stays distinct from an absent one.
- `value` is carried as opaque bytes. The decoder does not check that it is UTF-8.
- An envelope whose length field is over the envelope ceiling is `RECORD_LIMIT`; a length that disagrees with the bytes present is `RECORD_MALFORMED`. A magic mismatch is `RECORD_MALFORMED`; a known magic with an unknown version or algorithm is `RECORD_UNSUPPORTED`.
- A wrapped key of the wrong length or with an unknown leading version byte is `KEY_INTEGRITY`.
- An unknown `payloadVersion` is `RECORD_UNSUPPORTED`.

## Verified with

Generated and checked on Node.js 22.16.0. `verify_vectors.py` passed all 58 checks on Python 3.13.15 with `cryptography` 50.0.2.
