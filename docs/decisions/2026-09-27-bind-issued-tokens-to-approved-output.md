---
decision_id: decision-bind-issued-tokens-to-approved-output
status: proposed
scope: repository
title: Bind issued tokens to application-approved output locations
proposed_at: 2026-09-27
---
# Bind issued tokens to approved output locations

## Context

A core typed placeholder such as `<SSN_1>` is display-only. The reversible product issues its own unpredictable mapping identity, but a model can copy a valid issued token into a different sentence or field. A literal token-like string can also occur in source text. The [beta.8 verification](../research/verification-2026-09-27.md) produced two indistinguishable occurrences when a literal already matched the formatter's output. A random token prevents guessing; it does not prove the provenance of a particular occurrence.

## Proposed decision

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
