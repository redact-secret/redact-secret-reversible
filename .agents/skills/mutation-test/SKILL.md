---
name: mutation-test
description: Measure whether the vault's tests catch security regressions by mutating the security-critical source with Stryker and reporting surviving mutants. Use when asked to check test strength, after changing vault checks, or for "mutation-test", "/mutation-test vault.ts". Report-only; proposes tests for survivors.
---

# mutation-test

A check that can be deleted without a test failing is not protected. Find those.

## Setup

- Use `@stryker-mutator/core` with the `command` test runner and the TypeScript checker, as exact-pinned devDependencies. Put config in `stryker.config.json`. Ask before committing new files.
- Test command: build, then run the portable suite against the built package without packing, for speed. For example, `npm run build -w @redact-secret/vault && node packages/vault/test/run-local.mjs`, where `run-local.mjs` imports `packages/vault/dist` and exits non-zero on any failed check. Create it if it is missing.
- Mutate only security-relevant code: `packages/vault/src/vault.ts`, `token.ts`, and `errors.ts`, or the file given as an argument.

## Run

`npx stryker run --concurrency 4`. Record Stryker's version and the mutation score.

## Triage survivors

For each surviving mutant, decide one of the following:
- **Gap.** It weakens a security check (deny path, grant or source or budget or expiry test, marker count, staging validation, error sanitization, limit). Propose the exact conformance case or runtime check that kills it.
- **Equivalent.** The behavior is unchanged. Say why in one line.
- **Non-security.** A message string, a comment, or dead code. List it without action.

## Output

| Verdict | file:line | Mutator | Mutation | Why it survived | Proposed test |
| --- | --- | --- | --- | --- | --- |

End with the mutation score overall and for security-relevant lines, and the number of gaps.

## Rules

- Never commit mutated source. Confirm `git diff packages/vault/src` is empty when done.
- Synthetic values only in any proposed test.
