---
name: invariant-fuzz
description: Property-based fuzzing of @redact-secret/vault security invariants with fast-check against the built package. Generates random inputs, grants, and model outputs and reports any counterexample with its seed. Use when asked to fuzz the vault or check its invariants ("invariant-fuzz", "/invariant-fuzz 20000", "fuzz restore").
---

# invariant-fuzz

Break the vault's invariants with generated inputs. Report counterexamples, not opinions.

## Setup

- Build first: `npm run build -w @redact-secret/vault`. Test `packages/vault/dist/index.js` through the public API only.
- Properties live in `packages/vault/test/fuzz.mjs`. If it is missing, create it. Add `fast-check` as an exact-pinned devDependency and ask before committing either.
- Run: `node packages/vault/test/fuzz.mjs [numRuns] [seed]`. Default is 2000 runs. The argument sets the count.

## Invariants

Generators: text mixing fixtures (`ghp_SYNTHETIC…`, `AKIASYNTHETIC0TEST00`, `password=SYNTH_REVOKED_42`), Unicode (ZWJ emoji, RTL, combining, Cf characters), `$` patterns, and token-like strings. Grants use 1–3 sinks and paths. Model output is issued tokens copied, duplicated, reordered, altered, or forged, placed into random sinks, paths, and captures.

1. **No release without authority.** Plaintext appears in a restored field only if its token came from a listed capture, that capture granted the sink and path, and budget remained.
2. **All or nothing.** A throwing `restore` or `capture` leaves `stats()` unchanged, apart from expiry sweeps.
3. **Budget conservation.** Total occurrences restored per entry is at most `maxUses`, across any sequence of calls.
4. **Round trip.** Restoring a capture's own `text` into its granted path with budget returns the original input exactly.
5. **No diagnostic leakage.** No fixture value or issued token appears in any error (message, stack, JSON), audit event, or `stats()`.
6. **Action gate.** A `block` finding never yields output or entries. `warn`/`allow` under `"reject"` never yield output.

## Output

For each violated invariant: the invariant, the fast-check seed and path, the shrunk counterexample with values replaced by fixture names, and the observed vs expected result. End with `N runs, seed S: all invariants held` or the violation count.

## Rules

- Synthetic values only. Never print plaintext from a failing case; name the fixture instead.
- Do not change product code. Propose a conformance case for each confirmed violation.
