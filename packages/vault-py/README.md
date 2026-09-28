# redact-secret-vault (Python)

**Status: alpha / research-grade.** Native Python implementation of the same
S1 server-authority contract as the JavaScript
[`@redact-secret/vault-server`](../vault-server/README.md)
([decision record](../../docs/decisions/2026-09-27-define-server-authority-interface.md)).
It does **not** implement the JavaScript `@redact-secret/vault` API: Python has
no authority-free portable vault, so this single distribution is named
`redact-secret-vault` without a `-server` suffix (see the
[naming decision's 2026-09-28 note](../../docs/decisions/2026-09-27-name-vault-packages-and-language-contract.md)).
The distribution was called `redact-secret-vault-server` (module
`redact_secret_vault_server`) before its first publish; that name was never on
PyPI. It provides trusted principal/tenant resolution, a source→sink/path/purpose decision
tuple, fail-closed policy evaluation, an extended denial vocabulary, and
audit events with no field capable of carrying a restored value. Storage is
in-memory only, matching `@redact-secret/vault`'s threat boundary — nothing
here is persistent. Version `0.1.0a2` (PEP 440; the counterpart of the npm
`0.1.0-alpha.2` release) is installable only from this repository.

This package does not implement secret detection. `@redact-secret/core` has
no published Python distribution (verified against the
`redact-secret/redact-secret` GitHub organization on 2026-09-27: only
`packages/javascript` exists there). Capture therefore uses a **qualified
service boundary**: [`NodeCoreBridge`](src/redact_secret_vault/core_client.py)
shells out to a small Node.js script
([`boundary/core_bridge.mjs`](src/redact_secret_vault/boundary/core_bridge.mjs))
that calls only the core's public `scan` API and returns its safe finding
metadata (never a matched value). See
[docs/research/python-server-integration-2026-09-27.md](../../docs/research/python-server-integration-2026-09-27.md)
for the full inventory, the gap this leaves, and what "equivalent to the JS
implementation" means here.

## Requirements

- Python 3.10+
- A `node` executable on `PATH` and `@redact-secret/core` resolvable from
  `node_modules` (installed at this repository's root via `npm ci`), for
  `NodeCoreBridge`. A consumer that supplies its own `CoreClient` does not
  need Node at all — the boundary is a `Protocol`, not a hard dependency.

## Install (from this repository)

```bash
cd packages/vault-py
pip install -e ".[test]"
```

## Usage sketch

```python
import asyncio

from redact_secret_vault import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    NodeCoreBridge,
    PolicyDecision,
    Principal,
    RestoreRequest,
)


def resolve_principal(context):
    # The consuming application's own authentication — never a mandated
    # identity provider. Must raise, not return a partial Principal, when
    # trust cannot be established.
    return Principal(id=context["user_id"], tenant=context["tenant"])


def same_tenant_only(decision_input):
    if decision_input.tenant == decision_input.source.issued_tenant:
        return PolicyDecision(allow=True)
    from redact_secret_vault import ServerDenialReason

    return PolicyDecision(allow=False, reason=ServerDenialReason.TENANT_MISMATCH)


async def main() -> None:
    server = InMemoryVaultServer(
        core_client=NodeCoreBridge(),
        principal_resolver=resolve_principal,
        release_policy=same_tenant_only,
    )
    captured = server.capture(
        "deploy with ghp_EXAMPLE_SYNTHETIC_TOKEN_0000000000 now",
        CaptureOptions(
            issued_tenant="tenant-acme-synthetic",
            release=(CaptureGrant(sink="reply", paths=("body",)),),
        ),
    )
    result = await server.restore(
        RestoreRequest(
            sink="reply",
            captures=(captured.capture_id,),
            fields={"body": f"Use {captured.tokens[0].token} please"},
            purpose="support-reply-purpose-synthetic",
            tenant="tenant-acme-synthetic",
            context={"user_id": "user-synthetic-1", "tenant": "tenant-acme-synthetic"},
        )
    )
    print(result.fields["body"])


asyncio.run(main())
```

## PII selection and retention

**Status: implemented in `0.1.0a2`, which is not published to any index.** PII detection needs
`@redact-secret/core@0.1.0-beta.10`, which this repository pins
(`PINNED_CORE_VERSION`). A core without PII support (`0.1.0-beta.9`) gets the
fail-closed rules below. The rules are
the [PII retention and activation decision record](../../docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md)
(§1 and §3 "Python bridge"), the same ones `@redact-secret/vault` follows.

- **Selection.** `NodeCoreBridge(pii=[...])` forwards the selectors verbatim
  to the core's `initialize({ pii })` in each bridge process. Each scan runs in
  a fresh Node.js process, so this list is the only selection. Omitting it
  (the default `()`) means PII off. The core judges selector grammar; its
  rejections surface as `CORE_FAILURE` with `core_code` (for example
  `PII_SELECTOR_INVALID`).
- **Identity.** Each scan reports the core's `piiActivation()` identity as
  `CoreScanOutcome.pii_activation`, or `None` when the core has no PII support.
  The bridge pins the identity from its first successful scan and raises
  `PII_ACTIVATION_MISMATCH` if a later scan differs. Pass
  `expected_pii_activation=` to compare against a fixed identity instead.
- **Retention.** A `redact` finding whose type starts with `pii_` is never
  retained unless its exact type is listed in
  `CaptureOptions(pii=PiiRetention(retain=("pii_global_iban", ...)))`. An
  `eligible` callback is not called for unlisted PII types and can only narrow
  the list. Unretained PII is replaced by a non-restorable placeholder and
  counted in `unrestorable`.
- **Fail closed.** A non-empty `pii` selection or an `expected_pii_activation`
  on a core without PII support, and a capture's `pii` retention when the scan
  reported no active PII detection, each raise `PII_UNAVAILABLE`.

```python
bridge = NodeCoreBridge(pii=["pii"])  # the pinned beta.10
options = CaptureOptions(
    issued_tenant="tenant-acme-synthetic",
    release=(CaptureGrant(sink="reply", paths=("body",)),),
    pii=PiiRetention(retain=("pii_global_iban",)),
)
```

With PII on, Medium- and Low-confidence PII findings default to `warn`, so a
capture containing them fails with `UNREDACTED_FINDINGS` unless the caller
passes a `policy` that maps them or `unredacted="pass-through"`. For example,
beta.10 rates a labeled seven-digit local phone number (`telephone=…`) as
Medium `pii_global_phone`. `pii.retain` applies only to `redact` findings, so
listing a warn-level type there does not retain it.

Every finding the core returns, PII included, counts toward `max_findings`,
which the bridge passes to the core. Exceeding it raises `CORE_FAILURE` with
`core_code="FINDING_LIMIT_EXCEEDED"` and commits nothing.

This package has no `displayFormatter`: it builds its own output with
`<SECRET_n>` placeholders and never calls the core's `redact()`. The core
beta.10 rule that rejects a placeholder reproducing any finding's matched text
(`INVALID_PLACEHOLDER`, which the JavaScript vault surfaces from a custom
`displayFormatter`) therefore does not apply here.

## Tests

```bash
pip install -e ".[test]"
pytest
```

`tests/test_pii_bridge.py` includes four cases that need a PII-capable core;
they run against the pinned beta.10. `VAULT_SERVER_PY_PII_CORE_NODE_MODULES`
points them at another `node_modules` (for example a local core build). Four
further cases need a core without PII support (beta.9) and skip with a reason;
the fake-core cases in the same file cover those rules.

`tests/test_conformance.py` runs the shared language-neutral corpus
(`conformance/v1/corpus.json`) against this package; `tests/test_server_authority.py`
covers the S1-specific adversarial cases (cross-tenant, missing purpose,
revoked-token reuse, policy-evaluation-error, principal-resolution failure)
that the corpus does not yet include (see `conformance/README.md`). Both
require a `node` executable and `@redact-secret/core` installed at the
repository root (`npm ci` from the repo root first).

## What "equivalent to `@redact-secret/vault-server` (JS)" means

See [docs/research/python-server-integration-2026-09-27.md](../../docs/research/python-server-integration-2026-09-27.md)
for the full statement and the candid differences (token entropy source,
marker-detection regex, capture's audit vocabulary, and the core-integration
boundary itself). In short: the same decision tuple, the same nine-step
preflight order, the same denial vocabulary, and audit events that
structurally cannot carry a restored value — not byte-identical code or
wire format.
