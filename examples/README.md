# Examples

Small programs that run as they are. Every value in them is synthetic.

| File | Shows |
| --- | --- |
| [01-single-user.mjs](01-single-user.mjs) | The whole flow: capture, send, restore, dispose |
| [02-multi-turn.mjs](02-multi-turn.mjs) | A conversation: capture each new turn, restore across all of them |
| [03-denied-restore.mjs](03-denied-restore.mjs) | What a denied restore looks like, and keeping the redacted text |
| [04-server-two-tenants.mjs](04-server-two-tenants.mjs) | A server: resolver, ready-made policies, another tenant denied, audit events |
| [05-python-server.py](05-python-server.py) | The same server flow in Python |
| [persistent/](persistent/README.md) | Capture in one process and restore in another, over a local PostgreSQL (needs Docker) |

## Run them

From a checkout of this repository:

```bash
npm ci
npm run examples                      # builds the packages, then runs every .mjs example
node examples/01-single-user.mjs      # or one at a time, after a build
```

The Python example needs the Python package:

```bash
pip install -e packages/vault-py
python examples/05-python-server.py
```

In your own project, install the packages instead (`npm install @redact-secret/vault`, and `@redact-secret/vault-server` for example 04) and copy a file. Example 04 imports `@redact-secret/vault-server/policies`, which is on `main` and not in `0.1.0-beta.3`; with the published version, write the policy as a function, as the [package README](../packages/vault-server/README.md#use) does.

CI runs all of these, so an example that stops working fails the build.
