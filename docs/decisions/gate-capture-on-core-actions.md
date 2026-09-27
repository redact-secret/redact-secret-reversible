---
decision_id: decision-gate-capture-on-core-actions
status: proposed
scope: repository
title: Gate reversible capture and outbound text on finalized core actions
proposed_at: 2026-09-27
---
# Gate capture and outbound text on core actions

## Context

The public core's `redact` and `scanAndRedact` replace both `redact` and `block` findings; `warn` and `allow` leave the matched text unchanged. This was reproduced against npm `@redact-secret/core@0.1.0-beta.8` on a Node addon and the WASM artifact in Node. A placeholder in output therefore does not mean a `block` finding may be sent, and a returned `text` field does not imply all known sensitive spans were removed. The core cannot guarantee detection of every secret. [Verification](../research/verification-2026-09-27.md), [core public guide](https://github.com/redact-secret/redact-secret/blob/main/packages/javascript/README.md).

## Proposed decision

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
