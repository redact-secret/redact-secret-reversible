---
name: owasp-review
description: Review the current code against OWASP guidance (ASVS 5.0, Top 10, relevant Cheat Sheets) and report which requirements it meets, misses, or cannot be judged. Use when asked for an OWASP review or compliance check ("owasp-review", "/owasp-review packages/vault", "does this meet OWASP?"). Read-only; changes nothing.
---

# owasp-review

Review code against OWASP guidance. Report findings only; do not edit files.

## Scope

- Target: the path given as an argument, or else the current diff (`git diff main...HEAD`), or else `packages/`.
- Read `docs/specs/threat-model.md` first. Judge each control only within the trust boundary it describes; a documented residual risk is not a finding.

## Checklist

Map the code to the OWASP areas that apply. Skip areas that do not.

| Area | Source | Check |
| --- | --- | --- |
| Access control | ASVS V8, Authorization Cheat Sheet | Deny by default; checked on every use; model or user input never supplies authority |
| Sensitive data | ASVS V14, Cryptographic Storage | No plaintext in errors, logs, audit events, snapshots; bounded retention; no implicit persistence |
| Cryptography and randomness | ASVS V11 | CSPRNG for identifiers; no custom crypto; failure fails closed |
| Input validation | ASVS V1/V2 | Types, sizes, and counts bounded; accessors and prototype keys handled; regex safe from ReDoS |
| Errors and logging | ASVS V16, Logging Cheat Sheet | Fixed error messages; no `cause` chains carrying payloads; security events recorded without secrets |
| Business logic and concurrency | ASVS V2 | All-or-nothing operations; no race or re-entrancy window; limits cannot be bypassed |
| LLM output handling | LLM Prompt Injection Cheat Sheet, OWASP Top 10 for LLM | Model output treated as untrusted; no model-selected sink, path, or permission |
| Supply chain | NPM Security Cheat Sheet, ASVS V15 | Pinned dependencies, no install scripts, minimal packed files, provenance status stated |

## Output

One table, most severe first:

| Status | Severity | OWASP ref | file:line | Evidence | Fix |
| --- | --- | --- | --- | --- | --- |

- Status: `pass`, `fail`, or `n/a` (with the reason).
- Every `fail` needs a concrete scenario: input → wrong outcome.
- End with a one-line verdict and the requirements that could not be judged without runtime testing. Hand those to `vulnerability-test`.

## Rules

- Use synthetic values only. Never paste real secrets or findings' plaintext.
- Cite the specific requirement (for example `ASVS 5.0 V8.2.1`) when you can. Otherwise name the Cheat Sheet.
- Do not claim compliance or certification. Say "meets the reviewed requirements".
