# Roadmap

This is the intended direction for the next twelve months (October 2026 – September 2027). Items linked to an issue are tracked work; the rest are **proposed** and depend on core support and measured demand ([CONVENTIONS.md](CONVENTIONS.md#status-language)). Dates are not commitments.

## Near term

- The persistent profile's first prerelease is out (2026-10-02): `0.1.0-beta.4` of both npm packages and `0.1.0-alpha.1` of the seven persistence packages. Still open: the independent implementation review's remaining findings and the qualification gaps its record lists ([#112](https://github.com/redact-secret/redact-secret-vault/issues/112), [qualification record](docs/research/qualification-persistence-0.1.0-alpha.1.md)).
- Document and test JavaScript/Python conformance and the supported core version ranges ([#18](https://github.com/redact-secret/redact-secret-vault/issues/18)).
- Continue qualifying `@redact-secret/vault` on the in-memory runtimes it supports ([#2](https://github.com/redact-secret/redact-secret-vault/issues/2)).

## Later in the year

- Server restoration under the language-neutral authority contract, including qualifying the Python package beyond research grade ([#3](https://github.com/redact-secret/redact-secret-vault/issues/3)).
- Persistence beyond the first qualified profile ([#4](https://github.com/redact-secret/redact-secret-vault/issues/4)). `@redact-secret/store-postgres` is implemented and qualified on PostgreSQL 17.11 for two topologies ([#20](https://github.com/redact-secret/redact-secret-vault/issues/20)). `@redact-secret/store-sqlite` is implemented with a partial [record](docs/research/qualification-store-sqlite-0.1.0-alpha.1.md) and no support claim ([#130](https://github.com/redact-secret/redact-secret-vault/issues/130); the power-loss simulation is not run). Further backends (**proposed**; DynamoDB and Redis are [research](docs/research/persistent-backend-capabilities.md) only, [#114](https://github.com/redact-secret/redact-secret-vault/issues/114)) and Python persistence (**proposed**; [plan](docs/plans/python-persistence-parity.md), [#115](https://github.com/redact-secret/redact-secret-vault/issues/115)) each need their own qualification, against the [persistent vault specification](docs/specs/persistent-vault.md).

## Not planned

- Detection rules or policy logic: they belong to the [core](https://github.com/redact-secret/redact-secret).
- Streaming restoration, browser or Worker persistence, Rust or Go distributions, and edge, SharedWorker, Service Worker, or Node.js `worker_threads` runtimes are not scheduled. Each needs its own threat model and qualification first.
