# redact-secret-vault (Python)

[![PyPI](https://img.shields.io/pypi/v/redact-secret-vault)](https://pypi.org/project/redact-secret-vault/)
[![Python versions](https://img.shields.io/pypi/pyversions/redact-secret-vault)](https://pypi.org/project/redact-secret-vault/)
[![License: MIT](https://img.shields.io/pypi/l/redact-secret-vault)](https://pypi.org/project/redact-secret-vault/)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)

Swap secrets for random tokens before text leaves your server (for example, to an LLM), then put the original values back, but only for the user, tenant, purpose, and field your policy allows. It is the Python counterpart of [`@redact-secret/vault-server`](https://github.com/redact-secret/redact-secret-vault/blob/main/packages/vault-server/README.md).

**Research-grade.** The base install is the in-memory server; nothing in it is persistent. Persistent modules ship in the same wheel behind extras (below) and are not supported. Detection runs in [`@redact-secret/core`](https://www.npmjs.com/package/@redact-secret/core), which has no Python build, so this package talks to it through a small Node.js child process.

**Python persistence is not supported.** The wheel also ships persistent modules (below), behind the `crypto`, `postgres`, and `aws-kms` extras, since `0.1.0b4`. They are verified only for the cells of the [qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-python-persistence-0.1.0b3.md) states that its gates are not all passed: the Node.js bridge (G5: the bridge is not named qualified for any cell) and the support matrix (G9) are not passed in full. Nothing on this page claims support for them.

## Requirements

- Python 3.10 to 3.13 for the in-memory server (the classifiers list these; CI runs 3.10, 3.12, and 3.13). The persistent modules need Python 3.11+ and refuse to import on 3.10 (CI runs them on 3.11 and 3.12)
- Node.js 20, 22, or 24 on `PATH`
- `@redact-secret/core` at exactly `0.1.0-beta.12`, installed with npm in a directory your application owns

## Install

```bash
pip install redact-secret-vault==0.1.0b4
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

Then check the setup. `doctor` is new in `0.1.0b4`; `0.1.0b3` does not have it:

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

## Persistent modules (shipped in 0.1.0b4 behind extras, not supported)

`pip install redact-secret-vault==0.1.0b4` puts these modules in the environment; `0.1.0b3` does not contain them. Each is behind an extra that brings its dependency (for example `pip install "redact-secret-vault[postgres]==0.1.0b4"`), and the base install keeps no runtime dependency. They need Python 3.11 or later. The API is `async` only (`Store`, `KeyProvider`, and `RecordCrypto` are protocols with `async def` methods); there is no synchronous twin. Status words follow [CONVENTIONS.md](https://github.com/redact-secret/redact-secret-vault/blob/main/CONVENTIONS.md#status-language): **implemented** here means the code exists and passed the runs named in the record, **not supported** means no support claim is made.

| Import path | Extra | What it is | Status |
| --- | --- | --- | --- |
| `redact_secret_vault.persistent` | none | Contracts, errors, validators, canonical encoding, digests, the volatile reference `store_memory`, and `create_persistent_server_vault` (the persistent server profile) | Implemented; not supported. The persistent profile, the vectors, and the schedule corpus passed on the cells of the record |
| `redact_secret_vault.crypto` | `crypto` | Record crypto and a local key provider over `cryptography`. Key material is bytes in process memory, so the profile is `local-bytes-hkdf-aes-256-gcm-v1`, not the JavaScript profile | Implemented; not supported. Vectors and interoperation with the JavaScript crypto passed on the cells of the record |
| `redact_secret_vault.stores.postgres` | `postgres` | A PostgreSQL store over `psycopg` 3, against the schema `@redact-secret/store-postgres` owns (Python creates no table) | Implemented; not supported. Run against PostgreSQL 17.11, a single primary, with `psycopg` 3.3.6 (`binary` build) only |
| `redact_secret_vault.keys.aws_kms` | `aws-kms` | An AWS KMS key provider over an injected `boto3` client | Implemented; not supported. One real-service run in `us-east-1` with two symmetric keys; throttling not provoked |

- **Install variant.** The `postgres` extra names plain `psycopg`, which cannot be imported at all without a system `libpq`. Install `libpq` or add `psycopg[binary]` (the variant tested). The adapter takes a pool the application owns (`psycopg_pool.AsyncConnectionPool` works; it is not a dependency) and never opens a connection from a URL.
- **WSGI and other synchronous hosts.** Call the async API through one long-lived event-loop thread per process. Do not use `asyncio.run` per request: a connection pool is bound to its loop.
- **Fork.** A store created before `os.fork()` raises `STORE_CLOSED` in the child. Construct it after the fork.
- **No default key.** The key material, the digest key, the pool, and the KMS client are all supplied by the application. A bytes key in Python memory cannot be cleared; the package overwrites the buffers it owns and says so, and does not claim more.
- **At rest is not everywhere.** Encryption at rest covers what the store holds. The whole capture input, every secret in it and not only the retained values, still goes to the Node.js bridge and stays in its heap until it is collected or the process exits. **The bridge is research-grade and not qualified**, and the Python qualification does not include it: any deployment claim is for an application-supplied, separately qualified `CoreClient` ([decision](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/decisions/limit-python-persistence-claim-to-a-supplied-core-client.md)). Use `max_scans_per_process=1`, one bridge per tenant or trust domain, or your own `CoreClient` if that residual risk is not acceptable.
- **Bridge limits, measured** (the [record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-python-persistence-0.1.0b3.md), section 4.10). The child's memory still held a copy of an input's secret after the scan, and one copy stayed through thousands of later scans, until the process exited; only `max_scans_per_process=1` leaves no live process holding it. One bridge serves a few hundred to a few thousand small scans per second (the measured range depends on the host's load) however many threads wait. The first scan after a start pays for the Node.js start-up, the core load, and hashing the core (the integrity pin). `timeout_s` is end to end: a caller that waits for the bridge longer than `timeout_s` gets `BRIDGE_TIMEOUT` and nothing is sent, so a queue longer than `timeout_s` fails closed. The bridge refuses a core that is not the pinned release byte for byte (`CORE_INTEGRITY_MISMATCH`), and refuses an error code or field from the child that does not have its fixed shape (`BRIDGE_BAD_OUTPUT`); after repeated start failures it backs off (0.1 s to 5 s) and fails at once with the same code. The persistent server's scans run on two threads the bridge owns, not on the loop's default executor. Inputs near the 64 MiB ceiling can exceed the default `timeout_s` of 10 s.
- **Not tested, so not stated:** Windows, macOS in CI, free-threaded or PyPy builds, Python 3.14 and 3.10 for the persistent modules, a synchronous standby or failover, a connection pooler, managed PostgreSQL, two hosts, TLS, and power loss. Linux x86-64 ran only as a labeled subset under emulation, and in the GitHub-hosted jobs the record cites. The details are in the [qualification record](https://github.com/redact-secret/redact-secret-vault/blob/main/docs/research/qualification-python-persistence-0.1.0b3.md), which is the only document that may state support for a cell.
- **Logging.** With a real key, `botocore` at `DEBUG` was observed writing the plaintext data key and the key ARN (`botocore.parsers`, the response body) and the wrapped key (`botocore.endpoint`, the request parameters). The KMS provider therefore fails closed without touching your logging configuration: at construction and before every KMS call it checks whether `DEBUG` is enabled (`Logger.isEnabledFor`, so inherited levels, the root logger, and `logging.disable` count) for `botocore`, `botocore.parsers`, `botocore.hooks`, `botocore.endpoint`, `boto3`, and `urllib3.connectionpool`. If it is, construction raises `KEY_INVALID_ARGUMENT` and a call raises `KEY_UNAVAILABLE` before any request is made. Pass `allow_sdk_debug_logging=True` only if you accept that the SDK **writes key material to your logs**; the provider then works as before. A cache hit makes no SDK call and is not refused. Not covered: a level raised while a call is in flight, a call abandoned by its timeout that is still running, a logger the SDK adds later, and a client you configured to log by another route. `psycopg` at `DEBUG` writes the host, port, user, and database of each connection, never a statement or a value.

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

The persistent tests need the extras (`pip install -e ".[test,lint,crypto,postgres,aws-kms]"` and `psycopg[binary]`) and Python 3.11+; those that need a database or AWS skip with their reason when it is not configured (`RSV_PG_APP_URL` and `RSV_PG_ADMIN_URL` for PostgreSQL, applied with `node packages/vault-py/tests/pg_prepare.mjs`; `RSV_KMS_TEST_KEY_ARN` and `RSV_KMS_TEST_OLD_KEY_ARN` for KMS). `RSV_REQUIRE_POSTGRES=1` makes a missing database a failure.

Qualification tools, none of them in the wheel: `python tests/bridge_qualification.py --help` runs the bridge qualification harness (adversarial and fuzzed frames, lifetime bounds, plaintext left in the child, timeouts, concurrency, limits); `tests/test_persistent_server_postgres_leaks.py` is the server-level leak test over PostgreSQL (set `RSV_PG_CONTAINER` to a Docker container name to search the server's own log too); `scripts/qualify-python-matrix.sh` runs one Linux cell of the matrix in Docker.
