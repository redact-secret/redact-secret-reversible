# @redact-secret/vault-conformance

**Status: alpha, unpublished.** Conformance harnesses for the `Store` and `KeyProvider` contracts of the [persistent vault specification](../../docs/specs/persistent-vault.md), a store wrapper that injects faults, and an insecure deterministic key provider for tests.

It is for authors of a store adapter or a key provider, and for the tests of a persistent vault server. Its only dependency is [`@redact-secret/vault-contracts`](../vault-contracts/README.md). It imports no test runner, no `node:` module, and no driver.

## What a pass shows, and what it does not

A store that passes behaves as specification §4.2 and §5 require for the inputs and schedules this harness runs, in the configuration the factory supplied.

- **Store compliance does not prove a malicious in-process adapter safe.** An adapter runs inside the trusted process. One that lies only on inputs the harness does not send, keeps what it is given, or reads memory is not caught by any test here (specification §10).
- **A pass against one store says nothing about another.** [`@redact-secret/store-memory`](../store-memory/README.md) passing shows that the in-memory adapter follows the contract. It says nothing about a database adapter: isolation levels, locking, durability, failover, and clock behavior belong to the backend and have to be shown against it, with the options and versions recorded.
- A pass is not durability. Nothing here kills a process, cuts a connection, or restores a backup.
- A skipped case is not a pass. Cases the factory cannot support are reported as skipped with a reason.
- The key-provider harness shows the contract's observable behavior. It cannot show that key material is protected at rest or that a remote service retires a key.

## Store harness

```js
import test from "node:test";
import { runWithNodeTest, storeConformanceCases } from "@redact-secret/vault-conformance";

runWithNodeTest(storeConformanceCases(factory), test);
```

`storeConformanceCases(factory, options?)` returns an array of `{ name, group, run }`. `run()` resolves on a pass, rejects with `ConformanceSkip` (it has a `reason`) when the factory lacks what the case needs, and rejects with `ConformanceFailure` otherwise. `runWithNodeTest(cases, test)` registers each case with the `test` function you pass and reports a skip through the runner. `runCases(cases)` runs them in order and returns `{ name, group, status, detail }` for each, for any other runner.

### The factory

The factory is called once per case:

```ts
type StoreFactory = () => Promise<StoreUnderTest>;

interface StoreUnderTest {
  store: Store;
  clock: ConformanceClock | null;
  secondStore?: Store;
  interleave?: Interleave;
  dispose?: () => Promise<void>;
}

interface ConformanceClock {
  now(): number;
  advance(ms: number): void;
  set(ms: number): void;
}

type Interleave = <T>(request: {
  operation: "commitRestore" | "createCapture";
  primary: () => Promise<T>;
  concurrent: (second: Store) => Promise<void>;
}) => Promise<T>;
```

- `store` is the store under test. The factory may return a new store each time or handles on one shared database. Every case draws its namespaces at random and never touches another, so cases can share a database and run against one that already holds data.
- `clock` controls the clock the store judges expiry and skew with. Pass `null` when the harness cannot move it, as with a real database. The harness then uses `Date.now()` as its estimate of the store's clock, which must agree with it to well within `maxClockSkewMs`, and reports every time-travel case as skipped. A controllable clock should start at a realistic time, at least a few days past the Unix epoch.
- `secondStore` is a handle on the same state over a second connection. When present, the concurrency cases spread their calls over both.
- `interleave` holds one transaction open while another runs. It starts `primary()`, suspends that call after its reads and checks and before its commit, calls `concurrent(second)` with a handle on a second connection, lets the primary call continue once `concurrent` has settled or is known to be blocked by the primary's locks, and resolves with the primary call's result after both have settled. A locking store will block the competing call until the primary commits. An optimistic store will let it commit and abort the primary. The harness observes which was acknowledged first and accepts either order. It fails a primary call that succeeds after the competing call was acknowledged.
- `dispose` is called when the case ends, whatever its outcome.

The harness needs `maxCreateEntries` and `maxRestoreEntries` of at least 4, `maxRestoreCaptures` of at least 2, `maxEnvelopeBytes` of at least 64, and `maxCreateBytes` of at least 256.

Options: `seed` (default 20261001, printed by every failing case), `parallelism` (calls issued together by a concurrency case, default 100), `modelSequences` (default 4) and `modelSteps` (default 400).

### Case groups

| Group | What it checks |
| --- | --- |
| `capabilities` | The declared capabilities satisfy `missingCapabilities` and do not change |
| `validation` | Each invalid input of §4.2 throws `STORE_INVALID_ARGUMENT`, each input over a declared bound throws `STORE_CAPABILITY`, and neither changes anything |
| `create` | Initial counters; `exists`, `fenced`, `clock-skew`, `quarantined`; nothing created on a rejection; scope independence |
| `read` | Absent identifiers; revoked captures; deleted ciphertext; tenant and namespace isolation; the recovery state of the snapshot |
| `commit` | Every step of §5.5: precedence, each rejection, budget and expiry boundaries, all-or-nothing batches, receipts |
| `revoke` | Revocation, generations, `not-found`, fences, quarantine, tenant isolation |
| `inspect` | Receipts as an authoritative read |
| `rekey` | `replaceCaptureKey` as a compare-and-swap that changes nothing else |
| `delete` | `deleteCiphertext`: refusals, the expiry branch and its skew check, tombstones |
| `sweep` | `sweepExpired`: limits, `more`, what must never be removed early |
| `recovery` | `initializeNamespace`, `quarantine`, `invalidateRecovered`, and captures of an earlier epoch |
| `aliasing` | Buffers are copied in and out |
| `concurrency` | Parallel restores of one entry, restores racing a revocation, identical attempts, a creation racing a fence, multi-entry batches under contention |
| `interleave` | The two-connection schedules of §5.2 |
| `model` | Seeded random operation sequences compared, result by result and by a final read-back, with the reference model |

### What is skipped, and when

| Factory | Skipped |
| --- | --- |
| `clock: null` | Cases that need the store's clock at an exact value: the skew and expiry boundaries, receipt and tombstone retention in `sweep`, and the `model` sequences with time travel. The other `model` sequences still run. Cases that only need an expired capture create one that is already expired instead |
| No `interleave` | Every case of the `interleave` group |
| `maxCreateBytes` that cannot be exceeded within `maxCreateEntries` envelopes of `maxEnvelopeBytes`, or only with more than 256 MiB | The one case that exceeds `maxCreateBytes` |

A store whose clock cannot be moved and whose `maxClockSkewMs` is below 100 also skips the cases that need an expired capture.

### The reference model

`ReferenceModel` is the harness's transaction oracle: a pure, synchronous model of the §5 state machine. The `model` group gives the store and the model the same operations and compares every result. Each decision is a method of its own, so a test can subclass the model and break one decision. The mutation controls of this package do exactly that, in its test directory: each mutant has one defect, and the harness must report a failing case for it. No defect switch is part of this package's exports.

The model and a store written by the same author can share a misreading of the specification. The deterministic groups are written from the specification's sentences, not from the model, for that reason.

## Fault injection

```js
import { createFaultyStore } from "@redact-secret/vault-conformance";

const store = createFaultyStore(inner, {
  rules: [
    { operation: "commitRestore", call: 0, fault: { kind: "ambiguous", applied: true } },
    { operation: "inspectAttempt", fault: { kind: "unavailable" } },
  ],
});
```

`createFaultyStore(inner, plan)` returns a `Store` with one extra member, `faults`. A rule names an operation, an optional zero-based call index (omitted: every call), and a fault:

| Fault | Effect |
| --- | --- |
| `{ kind: "unavailable" }` | Throws `STORE_UNAVAILABLE` without calling the inner store |
| `{ kind: "ambiguous", applied }` | Throws `STORE_AMBIGUOUS`; with `applied: true` after the inner store applied the call, so the response is lost |
| `{ kind: "delay", beforeMs?, afterMs? }` | Waits before or after the inner call |
| `{ kind: "foreign-error", when }` | Throws an `Error` that is not a `StoreError` and carries `SYNTHETIC_SECRET_MARKER` in its message, a property, and its `cause`; a caller must never let that text out |
| `{ kind: "malformed", shape }` | Returns a corrupted result: wrong types, `null`, a row of a capture nobody asked for, an entry under another capture, entries without captures, a duplicate entry, revisions or `used` that are not the stored ones |
| `{ kind: "clock-skew", shiftMs }` | Shifts the input's `now` |
| `{ kind: "result", result, delegate }` | Returns a fixed answer, with or without applying the call |

`faults.calls(operation)`, `faults.log()`, `faults.add(rule)`, and `faults.clear()` inspect and change the plan. `plan.capabilities` replaces declared capabilities, to model an adapter that misdeclares itself. `plan.sleep` replaces the timer a delay uses.

The wrapper injects faults. It does not check the caller.

## Key-provider harness

```js
import { keyProviderConformanceCases, runWithNodeTest } from "@redact-secret/vault-conformance";

runWithNodeTest(keyProviderConformanceCases(factory), test);
```

```ts
type KeyProviderFactory = (request: {
  scope: { namespaces: readonly string[]; tenants: readonly string[] };
}) => Promise<{
  provider: KeyProvider;
  rotate?: () => Promise<void>;
  retire?: (keyRef: string) => Promise<void>;
  dispose?: () => Promise<void>;
}>;
```

The provider must serve exactly `scope.namespaces`. A provider that can restrict tenants restricts them to `scope.tenants`; one that cannot ignores that list. `rotate` makes a new wrapping key version active and the previous one decrypt-only. `retire` retires the version a `keyRef` names. Without `rotate` the rotation and retirement cases are skipped; without `retire` the retirement case is.

The cases check specification §6.1 and §6.2: a 32-byte data key with a wrapped key and reference within the limits; distinct keys; unwrap round trips; `KEY_INTEGRITY` when the capture, the tenant, or the namespace of the context changes within the scope; `KEY_UNAVAILABLE` for a namespace outside the scope, for an unknown key reference, and for a retired version; `KEY_INTEGRITY` for a tampered wrapped key; `KEY_INVALID_ARGUMENT` for an input outside the contract; rewrap keeping the data key, across rotation; `KEY_ABORTED` for an aborted signal. Every error must be a `KeyProviderError` with the fixed message of its code, no `cause`, and no key bytes in its message, stack, or properties.

In two places the harness accepts either of two codes, because the specification does not single one out: a tenant outside the scope may be `KEY_UNAVAILABLE` (the provider scopes tenants) or `KEY_INTEGRITY` (it does not, and the context binding fails), and a truncated wrapped key may be `KEY_INTEGRITY` or `KEY_INVALID_ARGUMENT`.

## Insecure test key provider

```js
import { createInsecureTestKeyProvider } from "@redact-secret/vault-conformance";

const provider = createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed: "any synthetic seed" });
```

**This provider must never protect real data.** Every data key and every wrapped key is derived from the seed and a call counter with HMAC-SHA-256, so anyone who knows the seed can derive all of them, and two providers with the same seed and call order produce the same bytes. That is what makes it useful for vectors and tests, and what makes it unusable for anything else.

It throws unless `acknowledgeInsecure` is exactly `"test-only"`. Its `profile` is `"insecure-test-only"`. `provider.control.rotate()`, `retire(keyRef)`, and `activeKeyRef()` drive its wrapping key versions so the key-provider harness can be run against it. An optional `scope` restricts namespaces and tenants.
