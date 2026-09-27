# redact-secret-vault-server (Python)

**Status: alpha / research-grade.** Native Python implementation of the S1
server authority contract
([decision record](../../docs/decisions/2026-09-27-define-server-authority-interface.md)):
trusted principal/tenant resolution, a source→sink/path/purpose decision
tuple, fail-closed policy evaluation, an extended denial vocabulary, and
audit events with no field capable of carrying a restored value. Storage is
in-memory only, matching `@redact-secret/vault`'s threat boundary — nothing
here is persistent.

This package does not implement secret detection. `@redact-secret/core` has
no published Python distribution (verified against the
`redact-secret/redact-secret` GitHub organization on 2026-09-27: only
`packages/javascript` exists there). Capture therefore uses a **qualified
service boundary**: [`NodeCoreBridge`](src/redact_secret_vault_server/core_client.py)
shells out to a small Node.js script
([`boundary/core_bridge.mjs`](src/redact_secret_vault_server/boundary/core_bridge.mjs))
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
cd packages/vault-server-py
pip install -e ".[test]"
```

## Usage sketch

```python
import asyncio

from redact_secret_vault_server import (
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
    from redact_secret_vault_server import ServerDenialReason

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

## Tests

```bash
pip install -e ".[test]"
pytest
```

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
