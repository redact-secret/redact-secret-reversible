# @redact-secret/store-memory

[![npm (alpha)](https://img.shields.io/npm/v/@redact-secret/store-memory/alpha?label=npm%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/store-memory)
[![License: MIT](https://img.shields.io/npm/l/@redact-secret/store-memory)](https://www.npmjs.com/package/@redact-secret/store-memory)
[![Node.js](https://img.shields.io/node/v/@redact-secret/store-memory/alpha?label=node%20%28alpha%29)](https://www.npmjs.com/package/@redact-secret/store-memory)
[![CI](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret-vault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret-vault/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret-vault)

**Status: alpha.** A ciphertext-only reference `Store` that keeps everything in process memory. It exists for tests and development of a persistent Redact Secret vault. It is not persistence.

It implements the store contract of the [persistent vault specification](../../docs/specs/persistent-vault.md) (§5) with the types and validators of [`@redact-secret/vault-contracts`](../vault-contracts/README.md). It stores envelopes, wrapped keys, counters, and receipts exactly as it is given them. It never decrypts, never holds a data key, never resolves a principal, and never evaluates a policy.

## Use

```js
import { createMemoryStore } from "@redact-secret/store-memory";

const { store, control } = createMemoryStore();

// A persistent server refuses a non-durable store unless you accept the loss:
// createPersistentServerVault({ store, allowNonDurableStore: true, ... })
```

`store` is the `Store` to hand to a server. It has the contract's methods and nothing else. `control` holds test-only controls and is returned next to the store, never on it, so passing `store` along cannot expose them.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `now` | `Date.now` | The store's own clock, in milliseconds. The reading is floored. The store judges expiry and clock skew with it. |
| `maxClockSkewMs` | `2000` | Largest accepted difference between the store's clock and a caller's `now`. 0 to 60 000. |
| `maxCreateEntries` | `1024` | May only be lowered. |
| `maxCreateBytes` | 16 MiB | May only be lowered. |
| `maxRestoreEntries` | `1024` | May only be lowered. |
| `maxRestoreCaptures` | `64` | May only be lowered. |
| `maxEnvelopeBytes` | 1 MiB + 64 KiB | May only be lowered. |

A value above a default, or one that is not a positive integer, throws a `TypeError` when the store is created.

## What it is not

- **Not durable.** All state is lost when the process exits. A new instance knows nothing of an earlier one: captures, consumed uses, revocations, and receipts are all gone. Its capabilities say `durability: "volatile"`.
- **Not cross-process.** Two processes, or two instances in one process, share nothing. Its capabilities say `crossProcess: false`.
- **Not accepted by a persistent server by default.** A server refuses a volatile or single-process store unless the application passes `allowNonDurableStore: true` (specification §8.2). Passing that flag does not make the store durable; it accepts the loss.
- **Not evidence about a database.** This package passes the store conformance suite of [`@redact-secret/vault-conformance`](../vault-conformance/README.md). That shows this in-memory adapter follows the contract. It says nothing about any database adapter, whose transactions, isolation, and durability have to be shown against the real backend.
- **Not required by, and not a replacement for, `@redact-secret/vault`.** The [portable in-memory vault](../vault/README.md) does not depend on this package and does not use a `Store`. This package holds ciphertext for a persistent server; the portable vault holds values for one application instance. Neither stands in for the other.

## Behavior worth knowing

- Every operation validates its input with the contract's validators and takes its own copy of it before anything else. Byte arrays are copied on the way in and on the way out, so a caller that changes a buffer after a call does not change stored state, and changing a returned buffer does not either.
- Each operation's read, checks, and writes run as one synchronous section. Operations are asynchronous, but no other operation can run inside that section, so a commit and a revocation of the same capture are always ordered.
- An operation whose `signal` is already aborted throws `STORE_UNAVAILABLE` and has no effect.
- Rows are scoped by namespace and tenant mechanically. The same identifier under another tenant or namespace is another row.

## Test controls

```js
const remove = control.onPhase("commitRestore", "before-apply", async ({ operation, phase, call }) => {
  await store.revokeCapture(/* ... */);
});
```

`control.onPhase(operation, phase, hook)` runs `hook`, awaited, on every later call of that operation, and returns a function that removes it. `control.clearHooks()` removes all hooks. `control.counts()` returns row counts and nothing else.

There are two phases:

- `"before-validate"` runs before the input is validated and copied.
- `"before-apply"` runs after validation and the copy, before the operation's atomic section starts.

What the hooks can simulate: a second caller whose operation commits while the hooked call is suspended. That is how the conformance harness places a revocation between a restore's preflight read and its commit, or a quarantine between a creation's check and its commit. They can also delay a call, fail it before it has any effect by throwing, or move the store's clock while a call is open.

What they cannot simulate: anything inside the atomic section. The section reads the clock and all state after the last hook returns, and nothing can be interleaved with its read, checks, and writes. A hook therefore cannot produce a torn write, a lost update, a transaction that commits on a stale read, a crash between two rows of one batch, or an ambiguous outcome. Those failures belong to real backends and are exercised there, or injected in front of this store with `createFaultyStore` from the conformance package.

## Deletion

`deleteCiphertext` and `sweepExpired` remove rows from this process's memory. That is not erasure: the specification's §9 on backups and key retirement applies to any real deployment, and this store has neither.
