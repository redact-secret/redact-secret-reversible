# Persistent example

Capture in one process and restore in another, over a local PostgreSQL. Three commands from a clean checkout.

**Development only.** This is not a qualified deployment profile: the database is a disposable container with a synthetic password, and the keys are generated into a local file. For a real deployment, read the [persistent server guide](../../docs/guides/persistent-server.md) and the [`store-postgres` reference](../../docs/reference/store-postgres.md).

## Run it

You need Docker and Node.js 22. From the repository root:

```bash
npm ci && npm run build

docker compose -f examples/persistent/compose.yaml up -d   # PostgreSQL 17 on 127.0.0.1:55432
node examples/persistent/setup.mjs                         # role, schema, grants, namespace, dev keys
node examples/persistent/demo.mjs                          # capture in one process, restore in another
```

```text
process 1 captured:   Rotate <rsv_…> today
process 2 restored:   Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today
process 2, again:     budget
```

The last line is the point of the persistent profile: a value is released at most once, even across processes.

Stop and delete the database with `docker compose -f examples/persistent/compose.yaml down -v`.

## What each file does

| File | Does |
| --- | --- |
| [compose.yaml](compose.yaml) | Starts PostgreSQL 17 with `fsync`, `synchronous_commit`, and `full_page_writes` on |
| [setup.mjs](setup.mjs) | The one-time maintenance steps: creates the unprivileged serving role, runs `migrate` as the owner, applies `grantStatements`, initializes the namespace, and generates development keys. Safe to run again |
| [demo.mjs](demo.mjs) | What a server does: opens a pool, a store, and a vault, then captures or restores. With no argument it runs both, each in its own process |
| [config.mjs](config.mjs) | Connection URLs, schema, namespace, and the development key loader |

To use another database, set `RSV_PG_ADMIN_URL` (a role that may create the schema and the serving role) and `RSV_PG_APP_URL` (the serving role) before running `setup.mjs` and `demo.mjs`.

## What to change for a real server

- **Keys.** `setup.mjs` writes two random 32-byte keys to `.dev-keys.json` (git-ignored). A real server loads them from its secret manager, or uses [`@redact-secret/key-provider-aws-kms`](../../packages/key-provider-aws-kms/README.md). Every process of a namespace needs the same digest key.
- **Identity.** `demo.mjs` uses a fixed synthetic user. Your `resolvePrincipal` reads your already-authenticated request and throws when there is none.
- **Database.** Use one of the two [qualified profiles](../../docs/reference/store-postgres.md#qualified-deployment-profiles), run the migration as the owner role in your deploy step, and keep `recoveryEpoch` in deployment configuration outside the database.
- **Cleanup.** Schedule `store.sweepExpired` ([Cleanup](../../docs/reference/store-postgres.md#cleanup)).
