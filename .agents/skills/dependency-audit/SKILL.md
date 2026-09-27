---
name: dependency-audit
description: Scan this repository's dependencies for known vulnerabilities and registry-signature problems with OSV-Scanner and npm audit signatures, separating what ships to consumers from dev-only tooling. Use when asked to audit dependencies, before a release, or for "dependency-audit", "/dependency-audit". Report-only.
---

# dependency-audit

Answer one question: does any dependency we ship or build with have a known vulnerability or a bad signature?

## Run

1. `npm ci` from a clean tree.
2. `osv-scanner scan source -L package-lock.json --format json`. Record the OSV-Scanner version and scan time.
3. `npm audit signatures`. This verifies registry signatures and provenance attestations for installed packages.
4. `npm view @redact-secret/core@<pinned> dist.integrity dist.signatures` and compare with `docs/research/qualification-*.md`.

## Classify every hit

- **Shipped**: `@redact-secret/vault` has zero runtime dependencies, so only the core peer and its transitive packages (`@redact-secret/wasm`, `@redact-secret/node-*`) reach consumers.
- **Build/test only**: typescript, vite, playwright, and their trees.
- **Reachable?** State whether the vulnerable function is used by our code or tests. Say "not assessed" when unsure; never guess "not reachable".

## Output

| Class | Package@version | Advisory (OSV/GHSA/CVE) | Severity | Fixed in | Reachable | Action |
| --- | --- | --- | --- | --- | --- | --- |

Then the `npm audit signatures` summary (verified, missing, invalid) and whether the pinned core integrity matches the qualification record. Verdict: `no known vulnerabilities in shipped dependencies` or the counts.

## Rules

- Do not upgrade anything. A core version change needs a new qualification run, so propose it instead.
- Never paste tokens. If a registry call needs auth, stop and say so.
