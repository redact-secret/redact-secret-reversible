# OpenGrep SAST

One pinned tool, one pinned rule set, one command, the same as [redact-secret](https://github.com/redact-secret/redact-secret/tree/main/sast):

```bash
python3 scripts/run-sast.py          # needs python3 and cosign
```

1. It downloads OpenGrep 1.30.0 for the host and checks its SHA-256 against `opengrep.lock.json`. It then verifies its Sigstore signature with `cosign` against OpenGrep's release workflow identity. A mismatch fails closed.
2. It recomputes the digest of `sast/rules/` and fails closed if the digest differs from the lock.
3. It scans the repository, minus the paths in `EXCLUSIONS` in `scripts/run-sast.py`, each listed with its reason. Reports carry rule, path, line, and message only, never the matched code.
4. It fails unless every finding in `baseline.json` is classified `false_positive` or `hardening` with a rationale. A `blocking` finding never passes.

## Rules

- `rules/javascript`, `rules/typescript`, `rules/yaml/github-actions` are vendored from [opengrep-rules](https://github.com/opengrep/opengrep-rules) at the revision in the lock (Commons Clause + LGPL-2.1, dev tooling only; never published).
- `rules/local/vault-contract.yaml` holds this repository's own rules. They encode the vault contract: no dynamic code, no DOM HTML sinks, no logging, network, storage, or messaging in vault source, no `Math.random`, no error `cause`, and no string-pattern replacement of restored values.

Editing any rule file changes the digest. To accept a change, update `rules.digest` in `opengrep.lock.json` in the same reviewed commit. `scripts/run-sast.py` and `scripts/install-opengrep.py` are copied from redact-secret at `941053b`; only `EXCLUSIONS` differs.

CI: `.github/workflows/sast.yml` runs on every pull request and every push to `main`. The scan's exit code is the gate. The SARIF upload to code scanning is best effort.
