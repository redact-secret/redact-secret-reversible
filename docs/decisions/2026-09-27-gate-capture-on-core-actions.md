---
decision_id: decision-gate-capture-on-core-actions
status: accepted
scope: repository
title: Gate reversible capture and outbound text on finalized core actions
proposed_at: 2026-09-27
decided_at: 2026-09-27
---
# Gate capture and outbound text on core actions

> **Accepted 2026-09-27** for whole-input capture in `@redact-secret/vault` ([#8](https://github.com/redact-secret/redact-secret-reversible/issues/8)), against `@redact-secret/core@0.1.0-beta.9` in real browsers and Node.js. Streaming remains excluded.

## Context

The public core's `redact` and `scanAndRedact` replace both `redact` and `block` findings; `warn` and `allow` leave the matched text unchanged. This was reproduced against npm `@redact-secret/core@0.1.0-beta.8` on a Node addon and the WASM artifact in Node. A placeholder in output therefore does not mean a `block` finding may be sent, and a returned `text` field does not imply all known sensitive spans were removed. The core cannot guarantee detection of every secret. [Verification](../research/verification-2026-09-27.md), [core public guide](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/README.md).

## Decision

- Whole-input reversible capture uses the core's public finalized findings from the *same* input. Any `block` finding rejects the complete capture/send operation before a mapping or outbound text is published. It is never restorable. Do not reinterpret or override the core action.
- Only `redact` findings are candidates for capture, subject to a separate explicit consumer eligibility policy. Capturing original spans is an opt-in to retention; an ordinary redaction remains independent.
- `warn` and `allow` findings are not captured by default and remain plaintext under current core semantics. When the application declares an external boundary that should receive no *known* matched originals, the reversible integration defaults to rejecting that send if such findings remain. Consumers may explicitly choose to pass them through for a named boundary and policy; the API must make that exposure visible rather than silently treating the payload as fully redacted.
- A scan with no findings is not evidence that input is universally secret-free. Product documentation must avoid the phrase “guaranteed safe to send.”
- Stage captured spans and token identities before formatting, but commit none of them until the core successfully returns complete redacted output and collision/output checks pass. On scan, policy, formatter, validation, or commit failure, return no partial result. Do not publish tokens or invoke payload-bearing consumer hooks from formatter callbacks.
- The core owns detection, action decisions, and range semantics. This repository does not copy detectors, change a `block` to `redact`, or import private core internals.

## Rationale

The gate prevents a masked `block` output from being mistaken for approval and makes the `warn`/`allow` leakage explicit. The consumer can retain a legitimate `allow` workflow by choosing an outbound policy for its application. The gate only covers findings the core reported under the chosen detector profile/policy.

## Consequences and alternatives

- An application that merely wants display warnings can keep using core directly. A reversible integration with an external-send guarantee needs an explicit send decision.
- If the consumer opts into passing `warn`/`allow` plaintext, document which sink receives it. Reversible storage cannot make that outbound payload private.
- Streaming capture has unresolved finalization/cancellation behavior and needs a separate ADR. The initial contract is whole-input only.
- Token formatting may need a single `scan → redact` attempt per session: WASM finding reuse after a prior `redact` returned `INVALID_FINDINGS` in the tested artifact. Retry must rescan and be verified at the supported release.

## Verification before acceptance

Test action matrices under default and custom policies, multiple findings with a later `block`, `warn`/`allow` before and after eligible findings, partial formatter failure, Unicode ranges, and no published mapping/output on failure. Include consumer opt-in to passthrough and a runtime-specific browser WASM run. See [core integration research](../research/core-integration.md).

## Resolved choices (alpha.1)

- **Sequence.** `scan` once with the application's policy and the vault's input/finding limits. Gate on every finalized action. Stage values by exact UTF-16 slicing and pre-issue tokens. Call `redact` once with a formatter that only looks up staged tokens. Validate the output, then commit. There is no retry: a failure after `scan` fails the capture, and the caller may call `capture` again, which rescans.
- **`block`.** Any `block` finding fails with `BLOCKED_FINDING` before staging, formatting, or output.
- **`warn`/`allow`.** The default `unredacted: "reject"` fails with `UNREDACTED_FINDINGS`. `"pass-through"` must be passed explicitly, and every result reports `passedThrough`.
- **Eligibility.** All `redact` findings are retained by default. An `eligible` callback can exclude some. Excluded ones get a non-restorable display placeholder (default `<SECRET_n>`, or a custom `displayFormatter` whose output may not contain the token marker). They are counted in `unrestorable`.
- **Failures.** A formatter, policy, or eligibility callback failure, a core error, or an output/staging mismatch returns no text and commits no mapping. Core errors surface as `CORE_FAILURE` carrying only the core's fixed code.

## Evidence (core 0.1.0-beta.9)

| Probe | Node addon | Node WASM fallback | Chromium / Firefox / WebKit (WASM, strict CSP) |
| --- | --- | --- | --- |
| `redact`, `block` | replaced | replaced | replaced |
| `warn`, `allow` | plaintext left | plaintext left | plaintext left |
| UTF-16 range, leading emoji | `[3, 43)` exact | same | same |
| Reuse findings for a second `redact` | allowed | `INVALID_FINDINGS` | `INVALID_FINDINGS` |

The reuse difference is why the vault never calls `redact` twice per `scan`. Corpus cases `action.*`, `capture.unicode.ranges`, and `capture.short-match`, plus runtime checks `display-formatter-failure-commits-nothing` and `unpaired-surrogate-input-rejected`, pass in all five runtime configurations. See the [qualification record](../research/qualification-0.1.0-alpha.1.md).
