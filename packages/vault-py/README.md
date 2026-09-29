# redact-secret-vault (Python)

**Status: alpha / research-grade.** Native Python implementation of the same
S1 server-authority contract as the JavaScript
[`@redact-secret/vault-server`](../vault-server/README.md)
([decision record](../../docs/decisions/define-server-authority-interface.md)).
It does **not** implement the JavaScript `@redact-secret/vault` API: Python has
no authority-free portable vault, so this single distribution is named
`redact-secret-vault` without a `-server` suffix (see the
[naming decision's 2026-09-28 note](../../docs/decisions/name-vault-packages-and-language-contract.md)).
The distribution was called `redact-secret-vault-server` (module
`redact_secret_vault_server`) before its first publish; that name was never on
PyPI. It provides trusted principal/tenant resolution, a source→sink/path/purpose decision
tuple, fail-closed policy evaluation, an extended denial vocabulary, and
audit events with no field capable of carrying a restored value. Storage is
in-memory only, matching `@redact-secret/vault`'s threat boundary — nothing
here is persistent. Version `0.1.0a3` (PEP 440; the counterpart of the npm
`0.1.0-alpha.3` release) is the first version to be published to PyPI, from
`release.yml` through trusted publishing (see
[RELEASING.md](../../RELEASING.md#python)). Until that publish has run, it is
installable only from this repository.

This package does not implement secret detection. `@redact-secret/core` has
no published Python distribution (verified against the
`redact-secret/redact-secret` GitHub organization on 2026-09-27: only
`packages/javascript` exists there). Capture therefore uses a **qualified
service boundary**: [`NodeCoreBridge`](src/redact_secret_vault/core_client.py)
runs a small Node.js script
([`boundary/core_bridge.mjs`](src/redact_secret_vault/boundary/core_bridge.mjs))
in a long-lived child process that calls only the core's public `scan` API
and returns its safe finding metadata (never a matched value). See
[Bridge process](#bridge-process) below and the threat model's
[Python core bridge](../../docs/specs/threat-model.md#python-core-bridge-redact-secret-vault--research-grade-not-qualified)
section for the boundary, what it protects against, and what it does not.
The original service-boundary inventory is
[archived](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/python-server-integration-2026-09-27.md).

## Requirements

- Python 3.10+
- For `NodeCoreBridge`: a `node` executable (Node.js 20, 22, or 24) on
  `PATH`, and `@redact-secret/core` at exactly the pinned version
  (`PINNED_CORE_VERSION`, `0.1.0-beta.10`) installed with npm in a directory
  your application owns. A consumer that supplies its own `CoreClient` does
  not need Node at all — the boundary is a `Protocol`, not a hard dependency.

## Install

```bash
pip install redact-secret-vault==0.1.0a3
# In a directory of your choice, for example /srv/myapp/core:
npm install @redact-secret/core@0.1.0-beta.10
```

Then tell the bridge where that `node_modules` is, either in code or through
the environment:

```python
bridge = NodeCoreBridge(node_modules="/srv/myapp/core/node_modules")
```

```bash
export REDACT_SECRET_VAULT_NODE_MODULES=/srv/myapp/core/node_modules
```

The explicit `node_modules=` argument wins over the environment variable. The
bridge then loads `<node_modules>/@redact-secret/core` from exactly that
directory. It never searches parent directories or the working directory, so
whoever controls the process's working directory cannot substitute the core.
A relative path is made absolute when the bridge is constructed. The reported
core version must still equal `PINNED_CORE_VERSION`
(`CORE_VERSION_MISMATCH` otherwise). A directory without the core raises
`CORE_FAILURE` with `core_code="BRIDGE_CORE_NOT_FOUND"`, or
`BRIDGE_CORE_LOAD_FAILED` if the core is there but fails to load. Neither
error includes the path.

With neither setting, the bridge script resolves the core relative to its own
location in site-packages. That works when the virtualenv lives inside the
project that ran `npm install` (for example `/srv/myapp/.venv` with
`/srv/myapp/node_modules`), and in this repository. For a virtualenv anywhere
else it fails with `BRIDGE_CORE_NOT_FOUND`, so pass `node_modules=`.

From this repository (development; `npm ci` at the root installs the core):

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

## Bridge process

**Since [#89](https://github.com/redact-secret/redact-secret-vault/issues/89).**
Earlier versions spawned a new Node.js process for every scan, which made
almost all of a capture's cost process start-up. Now each `NodeCoreBridge`
owns one long-lived process:

- **Start.** The process starts on the first `scan`, not at construction, and
  loads and initializes the core once. That start (about 30 ms on an Apple M4)
  is paid once per process. Later scans cost a pipe round trip plus the scan
  itself (about 0.3 ms for a 1 KiB input).
- **Protocol.** One request and one response per line (newline-delimited
  JSON). Each request carries a sequential `id` that the response must echo.
  Parsing is as strict as before: exact keys and types, only the eight safe
  finding fields. A request larger than `MAX_REQUEST_FRAME_BYTES` (448 MiB)
  raises `LIMIT_EXCEEDED` before it is sent; a response line longer than
  `MAX_RESPONSE_FRAME_BYTES` (32 MiB) is `BRIDGE_BAD_OUTPUT`.
- **Threads.** A lock admits one request at a time, so threads that share a
  bridge are serialized and never see each other's findings. Each waits for
  the requests ahead of it. For parallel scans, use one bridge per worker;
  separate bridges own separate processes.
- **Failure.** A request that runs past `timeout_s` (default 10 s) is killed
  (`CORE_FAILURE` with `BRIDGE_TIMEOUT`). A process that exits mid-request is
  `BRIDGE_PROCESS_FAILED`; malformed, oversized, or out-of-sequence output is
  `BRIDGE_BAD_OUTPUT`. After any failure, including a core error and an
  interrupted call, the process is killed and never used again, and the
  next `scan` starts a new one. A process that died while idle is replaced
  silently, because no request was lost. Errors carry fixed codes only,
  never input or process output, and the process's stderr is discarded.
- **Lifetime.** `max_scans_per_process` (default 10,000; the process is
  killed right after its last scan), `max_process_age_s` (default 600), and
  `idle_timeout_s` (default 60; the process exits by itself when idle that
  long) bound how long one process lives and how many inputs pass through
  its heap. `max_scans_per_process=1` gives back one process per scan.
- **Shutdown.** Call `close()` or use the bridge as a context manager. It
  kills and reaps the process, and a later `scan` raises `CORE_FAILURE`
  with `BRIDGE_CLOSED`. Garbage collection of the bridge and interpreter
  exit do the same. The process also exits when its stdin closes, so it
  cannot outlive your Python process. After `os.fork()`, the child starts
  its own process and never touches the parent's.
- **PII.** Every new process is initialized with the bridge's `pii` and
  its activation is checked again (see below).

```python
with NodeCoreBridge(node_modules="/srv/myapp/core/node_modules") as bridge:
    server = InMemoryVaultServer(core_client=bridge, principal_resolver=resolve_principal)
    ...
```

Residual risk: earlier inputs can stay in the bridge process's heap until
it is garbage-collected or the process exits, now for up to the lifetime
bounds instead of one scan. Lower the bounds, or use one bridge per tenant,
if that matters for your deployment.

## PII selection and retention

**Status: implemented since `0.1.0a2` (never published); `0.1.0a3` is the first PyPI release.** PII detection needs
`@redact-secret/core@0.1.0-beta.10`, which this repository pins
(`PINNED_CORE_VERSION`). A core without PII support (`0.1.0-beta.9`) gets the
fail-closed rules below. The rules are
the [PII retention and activation decision record](../../docs/decisions/decide-pii-retention-and-activation-ownership.md)
(§1 and §3 "Python bridge"), the same ones `@redact-secret/vault` follows.

- **Selection.** `NodeCoreBridge(pii=[...])` forwards the selectors verbatim
  to the core's `initialize({ pii })` in each bridge process. Nothing else
  initializes that process's core, so this list is the only selection. Omitting it
  (the default `()`) means PII off. The core judges selector grammar; its
  rejections surface as `CORE_FAILURE` with `core_code` (for example
  `PII_SELECTOR_INVALID`).
- **Identity.** Each scan reports the core's `piiActivation()` identity as
  `CoreScanOutcome.pii_activation`, or `None` when the core has no PII support.
  The bridge pins the identity from its first successful scan and raises
  `PII_ACTIVATION_MISMATCH` if a later scan differs, including the first scan
  of a replacement process. Pass
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

`tests/test_bridge_process.py` covers the bridge process: reuse, lifetime
bounds, timeout, crash, malformed and oversized output, threads sharing a
bridge, separate bridges, `close()`, garbage collection, and `fork()`.

`tests/test_conformance.py` runs the shared language-neutral corpus
(`conformance/v1/corpus.json`) against this package; `tests/test_server_authority.py`
covers the S1-specific adversarial cases (cross-tenant, missing purpose,
revoked-token reuse, policy-evaluation-error, principal-resolution failure)
that the corpus does not yet include (see `conformance/README.md`). Both
require a `node` executable and `@redact-secret/core` installed at the
repository root (`npm ci` from the repo root first).

## What "equivalent to `@redact-secret/vault-server` (JS)" means

See [docs/research/python-server-integration-2026-09-27.md](https://github.com/redact-secret/redact-secret-vault/blob/0db9a33a654704f1afad9388f5fdf0cf403a6b01/docs/research/python-server-integration-2026-09-27.md)
for the full statement and the candid differences (token entropy source,
marker-detection regex, capture's audit vocabulary, and the core-integration
boundary itself). In short: the same decision tuple, the same nine-step
preflight order, the same denial vocabulary, and audit events that
structurally cannot carry a restored value — not byte-identical code or
wire format.
