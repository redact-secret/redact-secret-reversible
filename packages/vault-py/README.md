# redact-secret-vault (Python)

Swap secrets for random tokens before text leaves your server (for example, to an LLM), then put the original values back, but only for the user, tenant, purpose, and field your policy allows. It is the Python counterpart of [`@redact-secret/vault-server`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault-server/README.md).

**Research-grade.** In-memory only; nothing is persistent. Detection runs in [`@redact-secret/core`](https://www.npmjs.com/package/@redact-secret/core), which has no Python build, so this package talks to it through a small Node.js child process.

## Requirements

- Python 3.10+
- Node.js 20, 22, or 24 on `PATH`
- `@redact-secret/core` at exactly `0.1.0-beta.12`, installed with npm in a directory your application owns

## Install

```bash
pip install redact-secret-vault==0.1.0b3
# In a directory of your choice, for example /srv/myapp/core:
npm install @redact-secret/core@0.1.0-beta.12
```

Tell the bridge where that `node_modules` is, in code or through the environment:

```python
bridge = NodeCoreBridge(node_modules="/srv/myapp/core/node_modules")
```

```bash
export REDACT_SECRET_VAULT_NODE_MODULES=/srv/myapp/core/node_modules
```

Then check the setup. `doctor` is on `main` and not in `0.1.0b3`:

```bash
python -m redact_secret_vault doctor --node-modules /srv/myapp/core/node_modules
```

```text
ok    node: v22.16.0
ok    core location: /srv/myapp/core/node_modules (from --node-modules)
ok    core: @redact-secret/core 0.1.0-beta.12 loaded (addon)
ok    scan: 1 finding(s) in the synthetic input
```

A failing check prints `FAIL`, the reason, and a `fix:` line, and the command exits 1.

## Use

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

A complete version that also shows a denied restore: [examples/05-python-server.py](https://github.com/redact-secret/redact-secret-vault/blob/main/examples/05-python-server.py).

## The rules

- **You supply two functions.** `principal_resolver` turns your already-authenticated request context into a `Principal`; raise when it cannot. `release_policy` decides each restore. A failure in either one denies.
- **`capture` grants, `restore` checks.** A value returns only into the `sink` and `paths` the capture granted, for the capture's `issued_tenant`, with a non-empty `purpose`.
- **A restore is all or nothing.** One failing token denies the whole request and returns no values.
- **Close the bridge.** Use `NodeCoreBridge` as a context manager, or call `close()`. Threads sharing one bridge are served one at a time; use one bridge per worker for parallel scans.
- **PII is off by default** and never retained unless a capture names the exact type.

## Common problems

Run `python -m redact_secret_vault doctor` first: it names the failing part and the fix.

| Error | Cause |
| --- | --- |
| `CORE_FAILURE` / `BRIDGE_CORE_NOT_FOUND` | The bridge cannot find the core. Pass `node_modules=` or set `REDACT_SECRET_VAULT_NODE_MODULES` |
| `CORE_VERSION_MISMATCH` | The installed core is not the pinned version |
| `CORE_FAILURE` / `BRIDGE_TIMEOUT` | A scan ran past `timeout_s` (default 10 s) |
| `UNREDACTED_FINDINGS` | The input has findings the core left visible. Pass a `policy` that redacts them, or `unredacted="pass-through"` |

## More

- [Troubleshooting](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/guides/troubleshooting.md#python): every error code with its fix.
- [Reference](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/reference/vault-py.md): how the core is located, the bridge process and its limits, PII, tests, and how this package compares with the JavaScript one.
- [Threat model](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/specs/threat-model.md#python-core-bridge-redact-secret-vault--research-grade-not-qualified) for the bridge.
- [Release status](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/status.md) and [RELEASING.md](https://github.com/redact-secret/redact-secret-vault/blob/main/RELEASING.md#python).

## Development

From this repository (`npm ci` at the root installs the core):

```bash
cd packages/vault-py
pip install -e ".[test]"
pytest
```
