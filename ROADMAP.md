# Roadmap

This is the intended direction for the next twelve months (October 2026 – September 2027). Items linked to an issue are tracked work; the rest are **proposed** and depend on core support and measured demand ([CONVENTIONS.md](CONVENTIONS.md#status-language)). Dates are not commitments.

## Near term

- Re-pin `@redact-secret/core` to `0.1.0-beta.11` and release `0.1.0-alpha.4` of both npm packages ([#64](https://github.com/redact-secret/redact-secret-vault/issues/64)).
- Document and test JavaScript/Python conformance and the supported core version ranges ([#18](https://github.com/redact-secret/redact-secret-vault/issues/18)).
- Continue qualifying `@redact-secret/vault` on the in-memory runtimes it supports ([#2](https://github.com/redact-secret/redact-secret-vault/issues/2)).

## Later in the year

- Server restoration under the language-neutral authority contract, including qualifying the Python package beyond research grade ([#3](https://github.com/redact-secret/redact-secret-vault/issues/3)).
- Qualify one concrete persistent store through adversarial tests ([#20](https://github.com/redact-secret/redact-secret-vault/issues/20)), then optional `@redact-secret/store-*` backends ([#4](https://github.com/redact-secret/redact-secret-vault/issues/4)), built against the [persistent store contract](docs/decisions/2026-09-27-define-persistent-store-contract.md).

## Not planned

- Detection rules or policy logic: they belong to the [core](https://github.com/redact-secret/redact-secret).
- Streaming restoration, Rust or Go distributions, and edge, SharedWorker, Service Worker, or Node.js `worker_threads` runtimes are not scheduled. Each needs its own threat model and qualification first.
