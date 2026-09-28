---
name: ci-hardening
description: Audit this repository's GitHub Actions workflows and repo settings for supply-chain weaknesses with zizmor and OpenSSF Scorecard, then propose exact patches. Use when asked to harden or review CI/CD, before adding a release or publish workflow, or for "ci-hardening", "/ci-hardening". Report-only unless asked to apply.
---

# ci-hardening

Find ways CI or release automation could be abused. Propose patches; apply only when asked.

## Run

- `uvx zizmor --format plain .github/workflows/` (or `pipx run zizmor`). Record the zizmor version.
- `scorecard --repo=github.com/redact-secret/redact-secret-vault --format json`. This needs `GITHUB_AUTH_TOKEN`; skip it and say so if the token is unavailable.
- Read every workflow yourself as well. The tools miss repo-specific intent.

## Checks

| Check | Pass when |
| --- | --- |
| Action pinning | Every `uses:` is pinned to a full commit SHA with a version comment |
| Token permissions | Top-level `permissions: contents: read`; broader scopes only on the job that needs them |
| Publish job | `id-token: write` only on the publish job; npm trusted publishing or `--provenance`; never publishes a version that already exists; dist-tag is explicit and never `latest` for prereleases |
| Injection | No `${{ github.event.* }}` or other untrusted context inside `run:`; no `pull_request_target` that checks out PR code |
| Credentials | `persist-credentials: false` on checkout unless a later step pushes; no long-lived npm token secret once OIDC works (#24) |
| Branch protection | `main` requires the `ci` checks; force-push disabled. Read via `gh api repos/{owner}/{repo}/branches/main/protection` |
| Artifacts | Qualification reports uploaded; nothing secret-bearing uploaded |

## Output

| Severity | Workflow:line or setting | Finding | Exploit path | Patch |
| --- | --- | --- | --- | --- |

Give each patch as a minimal diff. End with the Scorecard score, if run, and a one-line verdict.

## Rules

- Never print, create, or move secrets. Do not change repo settings or push unless asked.
