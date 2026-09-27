---
decision_id: decision-bind-issued-tokens-to-approved-output
status: accepted
scope: repository
title: Bind issued tokens to application-approved output locations
proposed_at: 2026-09-27
decided_at: 2026-09-27
---
# Bind issued tokens to approved output locations

> **Accepted 2026-09-27** for the in-memory `@redact-secret/vault` ([#7](https://github.com/redact-secret/redact-secret-reversible/issues/7)). Server principal/tenant binding remains with [#15](https://github.com/redact-secret/redact-secret-reversible/issues/15). The concrete choices and evidence are under *Resolved choices* below.

## Context

A core typed placeholder such as `<SSN_1>` is display-only. The reversible product issues its own unpredictable mapping identity, but a model can copy a valid issued token into a different sentence or field. A literal token-like string can also occur in source text. The [beta.8 verification](../research/verification-2026-09-27.md) produced two indistinguishable occurrences when a literal already matched the formatter's output. A random token prevents guessing; it does not prove the provenance of a particular occurrence.

## Decision

- Issue tokens only inside an explicit session. Bind every entry to its issuing session and source, original range, safe finding metadata, and the application's eligible action. Visible type is descriptive, not authority. Use cryptographic randomness and collision checks; exact token grammar and entropy are to be fixed by a measured implementation decision.
- The default restore surface accepts an application-designated structured output location, a declared sink, and an application-owned release policy. The library verifies exact issued identity, current validity, the expected source/session, destination/path, and use budget before returning any plaintext. On a server, the application also supplies server-verified principal/tenant and a current authorization decision. Browser-local policy is not server authentication.
- A restore request cannot use a model-supplied destination, purpose, tenant, or permission as authority. Type labels or a parsed `<TYPE_N>` pattern cannot serve as a mapping lookup.
- If a proposed token string already occurs literally in original input, issue a different token or fail capture before publishing output. Reject unknown or duplicate token occurrences beyond the session's explicitly authorized replacement count. This avoids the demonstrated literal collision, but cannot establish that an LLM kept a valid token at its original semantic location.
- An advanced free-text restore surface, if added, needs its own specification and adversarial qualification. It must not be a global replacement shortcut that bypasses field/path policy. A consumer requiring a guarantee that model text cannot relocate an issued token should use out-of-band structured handles or decline restoration; a string token alone cannot provide that guarantee.

## Rationale

OWASP recommends denying access by default and checking permissions at every access. Its LLM guidance treats model-influenced tool arguments as untrusted. The exact source-to-sink binding above is this repository's design inference, not a prescribed OWASP API. [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [LLM prompt injection](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

## Consequences and alternatives

- The ordinary integration operates on specified fields and application-approved destinations. The consumer chooses its own identity provider and policy implementation; the library does not choose its sinks.
- A copied valid token in an allowed output location may still be released under the application's chosen policy. Applications needing stricter semantic provenance must keep a trusted out-of-band handle rather than infer it from model output.
- Strict no-restoration and core-only redaction remain valid choices when no permitted sink can be established.
- Exact token syntax, duplicate reuse across repeated values, slot binding, and maximum replacement count remain design/test questions; no API is shipped by this ADR.

## Verification before acceptance

Test literal collisions, copied/reordered/duplicated valid tokens, forged and cross-session tokens, wrong source/sink/path, policy changes, and all-or-nothing rejection without plaintext in errors. Run the corpus in each supported runtime. See [security research](../research/security-foundations-2026-09-27.md).

## Resolved choices (alpha.1)

- **Grammar and entropy.** `<rsv_` + 26 lowercase RFC 4648 base32 characters + `>` (32 characters). 128 bits come from `crypto.getRandomValues`; the final character carries padding bits. The token names no type. Type is returned beside it as descriptive metadata and is never consulted for lookup or authorization. A collision with a live or staged token is regenerated up to four times, then the capture fails with `TOKEN_GENERATION_FAILED`. A random-source failure fails the same way. Neither commits anything.
- **Repeated values.** Every occurrence gets its own token, including identical values in one input. There is no deduplication within or across captures.
- **Literal collisions.** Capture fails with `TOKEN_LITERAL_IN_INPUT` when the input contains the case-insensitive marker `rsv_` anywhere. This covers a verbatim earlier token, a forged one, and a near miss, so a token in redacted output is always one this capture issued. After redaction the vault verifies that each staged token occurs exactly once and that the output holds no other marker.
- **Altered tokens.** At restore, a field in which the count of `rsv_` markers differs from the count of exact-grammar tokens is denied with `malformed-token`. A marker split by invisible format characters (Unicode Cf) still counts. Case changes, truncation, inserted whitespace, and zero-width insertions therefore fail closed. An alteration that destroys the marker, such as a homoglyph, leaves ordinary text that is not restored.
- **Source binding.** A restore request must list the `captures` its output may draw from. It is required and non-empty. A token from any other capture in the same vault is denied (`source`), even if that capture granted the same sink and path. This stops a model from moving one conversation's value into another conversation's reply within a shared vault.
- **Path binding.** Each capture carries application grants: `{ sink, paths[] }` pairs, which are required and non-empty. A restore names one sink and a map of path → text. Every token occurrence must belong to this vault, be unexpired, and be granted for that sink and that exact path. A token in a field without a grant is denied (`sink-or-path`). Fields without tokens pass through unchanged.
- **Copies, duplicates, reordering.** Every occurrence consumes one use from the entry's budget (`maxUses`, default 1, capped by `maxUsesPerEntry`). A duplicate beyond budget, whether in one field or across fields, is denied (`budget`). Reordering within a granted field is allowed; that is the documented residual risk.
- **Cross-session.** Lookup is confined to the vault instance's private map. Another vault's token is `unknown-token`.

## Evidence

The [conformance corpus](../../conformance/v1/corpus.json) cases `literal.*`, `token.*`, `source.*`, `capture.repeated-values.*`, and `preflight.all-or-nothing`, plus runtime checks `random-source-failure-and-collision` and `tokens-unpredictable-and-unique-at-volume`, pass on Node.js (addon and WASM fallback) and in Chromium, Firefox, and WebKit. See the [qualification record](../research/qualification-0.1.0-alpha.1.md).
