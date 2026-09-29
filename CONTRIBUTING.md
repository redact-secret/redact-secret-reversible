# Contributing

Thank you for helping improve Redact Secret Vault. Read [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [CONVENTIONS.md](CONVENTIONS.md) before starting; the conventions are the binding rules for changes here.

## Reporting bugs and requesting features

- Bugs and enhancement requests: open a [GitHub issue](https://github.com/redact-secret/redact-secret-vault/issues). Include the package and version, runtime (Node.js version, browser, or Python version), the core version, and a minimal reproduction.
- Vulnerabilities: **do not open a public issue.** Follow [SECURITY.md](SECURITY.md).
- Detection problems (a secret the core misses or misclassifies) belong to the [core repository](https://github.com/redact-secret/redact-secret).

Never paste a real credential into an issue, pull request, test, or log. Use unmistakably synthetic values such as `ghp_SYNTHETICxREVOKEDxTESTx0000000000000`.

## Submitting changes

1. Fork the repository and create a branch from `main`.
2. Make the change, with tests and documentation (see below).
3. Run the local checks below.
4. Open a pull request against `main` describing what changed and why, linking any related issue.

A pull request is merged only when the `ci` and `sast` workflows are green and a maintainer has reviewed it.

## Requirements for acceptable contributions

- **Tests.** New functionality must come with automated tests in the relevant suite (`packages/vault/test`, `packages/vault-server/test`, `packages/vault-py/tests`), and a bug fix should come with a test that fails without it. Security-sensitive changes need the negative tests listed in [CONVENTIONS.md](CONVENTIONS.md#security-sensitive-changes) (forged, expired, revoked, cross-session, cross-tenant, and policy-changed requests, including failure and cancellation).
- **No warnings.** TypeScript compiles under `strict` with no errors; Python passes `ruff check`. The OpenGrep SAST gate (`scripts/run-sast.py`) must not report new findings.
- **Boundaries.** Use only the core's documented public API; do not copy detector rules or policy logic (`npm run check:boundaries`).
- **Documentation and decisions.** Update the README, threat model, or a decision record in `docs/decisions/` when behavior, token identity, capture, storage, authorization, or restore semantics change. Add a `CHANGELOG.md` entry under `Unreleased` for user-visible changes.
- **No plaintext in diagnostics.** Errors, audit events, logs, and CI output must never contain original or restored values.

## Local checks

```bash
npm ci
npm run typecheck
npm run check:boundaries
npm test                      # vault and vault-server unit tests
npm run qualify:node          # optional: packed-package qualification
```

Python (`packages/vault-py`, needs `npm ci` at the repository root first):

```bash
cd packages/vault-py
pip install -e ".[test,lint]"
ruff check .
pytest -q
```

## License

By contributing, you agree that your contributions are licensed under the repository's [MIT License](LICENSE).
