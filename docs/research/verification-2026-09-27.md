# Verification of core behavior for reversible design

**Status:** executed proof of concept, 2026-09-27. This is not a security qualification of a reversible implementation.
**Artifacts:** npm `@redact-secret/core@0.1.0-beta.8` and `@redact-secret/wasm@0.1.0-beta.8`.
**Integrity:** core `sha512-vM1f1U6/mvMiqLoG1j6vaSE3dvr2neWI32+nCWDsOnLvyrssHEEfkEarp5htTZ+SgMoUicuo3cMMBM8ed+lRuA==`; wasm `sha512-h4a3UV0upmJuTqP6Ungu6p89hfmEh31qa+6wKKcYKIA0PFWAaety7IX0yg4TgAMaBrYFz8CDggAUb3OR2O47cw==`.

## Method

Executed a small Node.js program against the installed public `@redact-secret/core` API. Independently loaded the same release's WASM bytes in Node.js and drove the core's WASM binding. The latter uses internal loader modules in the **verification harness only** to force WASM selection; product code must use the public package API. Test input was a synthetic revoked-looking GitHub token prefixed by a non-BMP emoji, never a live credential. Tested `scan`, `scanAndRedact`, `redact`, a custom formatter, output collisions, and errors. Both programs exited successfully after assertions; an initial WASM assertion failure led to a fresh finding for the subsequent invalid-placeholder case, as described below.

A real Chromium page or dedicated Worker was **not executed**: the available browser automation installation had no Chromium executable. Therefore this verifies the published WASM artifact in Node, not browser loading, CSP, Worker messages, or browser lifecycle.

## Results

| Probe | Node addon | WASM binding in Node | Design consequence |
| --- | --- | --- | --- |
| UTF-16 range with leading emoji | `[3, 43)` selects the exact synthetic matched value | Same | Slice the original input using public ranges; qualify again in real browser. |
| `redact` action | Value replaced by `<SECRET_1>` | Same | Eligible only under explicit reversible policy. |
| `block` action | Value replaced by `<SECRET_1>` | Same | Placeholder in output does **not** mean the request can proceed. Abort before mapping/output publication. |
| `warn` or `allow` action | Original value remains in text | Same | Outbound policy must explicitly reject or accept this exposure. |
| Custom formatter | Accepted `<RANDOM_abcdefghijklmnop>` | Same | Session tokens can plausibly be emitted without changing core; randomness/provenance still need design. |
| Literal collision | Input already containing `<RANDOM_abcdefghijklmnop>` produced two indistinguishable occurrences after redaction | Same | Plain string replacement cannot identify which occurrence was issued. Token grammar, escaping, and provenance remain a blocking design decision. |
| Formatter returns matched value | `INVALID_PLACEHOLDER` | Same with a fresh finding | Core rejects this example; do not assume arbitrary formatter output is allowed. |
| Reuse a finding for a second `redact` call | Not exercised | `INVALID_FINDINGS` after the first call | Treat scanned WASM findings as potentially single-use; design for one redact per scan and test failure/retry behavior before relying on reuse. |

The reuse result is an observed behavior of this published artifact, **not** a claim that every future version's public contract promises one-time use. The first WASM run reused a prior finding for the matched-value formatter probe and received `INVALID_FINDINGS`, rather than reaching the formatter. A fresh `scan` made the probe reach `INVALID_PLACEHOLDER`. That distinction matters for rollback and retry design.

## Decision impact

1. The candidate `scan → preflight → stage → redact once → validate → commit` sequence remains plausible. A `block` finding aborts before any publish; a formatter must not persist state during callback execution. On formatter/output failure discard the staged mapping and, if retry is permitted, rescan the same input rather than reusing WASM finding handles.
2. The literal collision result prevents adopting a naive global `restore(text)` contract. Even an unpredictable token can appear twice after a valid input literal, and a model can copy an issued token. Select explicit structural provenance and failure behavior before API design.
3. `warn` and `allow` demonstrate that core redaction does not automatically make every outbound text safe. The caller's policy and the vault's external-send gate must be specified together.
4. This exercise does not prove atomic mapping publication, cross-session isolation, TTL, authorization, Worker isolation, or resistance to malicious same-page scripts. They remain separate conformance work.
5. Re-run against the exact release candidate and browser runtime before claiming support. The source files on `main` can differ from the tested npm beta artifact.

## Next verification gates

- Run the **public API** in a real browser with the distributed WASM asset and a strict CSP; separately test main-thread and dedicated-Worker modes.
- Inject formatter failure after multiple findings and verify no mapping or partial output escapes; test collision regeneration and retries with fresh findings.
- Create an adversarial output matrix: literal tokens, copied valid tokens, reordered/duplicated tokens, cross-session tokens, non-approved paths, and all-or-nothing rejection.
- Specify and test `warn`/`allow` outbound handling; establish a default that does not silently send retained plaintext.
- Pin supported core versions and run the same matrix for the Node addon and browser WASM; do not infer runtime qualification from this report.

The companion [integration research](core-integration.md) records the proposed sequence and remaining decisions. Browser-mode security requirements live in the [in-memory security specification](../specs/in-memory-security.md).
