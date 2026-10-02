# @redact-secret/vault-conformance

Test harnesses for authors of a `Store` or a `KeyProvider` for the [persistent vault server](../../docs/guides/persistent-server.md), plus a fault-injecting store wrapper and an insecure key provider for tests. Applications that only use a vault do not need it.

**Alpha.** Its only dependency is [`@redact-secret/vault-contracts`](../vault-contracts/README.md). It imports no test runner, no `node:` module, and no driver.

## Use

Check a store:

```js
import test from "node:test";
import { runWithNodeTest, storeConformanceCases } from "@redact-secret/vault-conformance";

// factory: () => Promise<{ store, clock, secondStore?, interleave?, dispose? }>, called once per case
runWithNodeTest(storeConformanceCases(factory), test);
```

Check a key provider:

```js
import { keyProviderConformanceCases, runWithNodeTest } from "@redact-secret/vault-conformance";

runWithNodeTest(keyProviderConformanceCases(factory), test);
```

Make a store fail on purpose:

```js
import { createFaultyStore } from "@redact-secret/vault-conformance";

const store = createFaultyStore(inner, {
  rules: [{ operation: "commitRestore", call: 0, fault: { kind: "ambiguous", applied: true } }],
});
```

Get a deterministic key provider for tests. **It must never protect real data.**

```js
import { createInsecureTestKeyProvider } from "@redact-secret/vault-conformance";

const provider = createInsecureTestKeyProvider({ acknowledgeInsecure: "test-only", seed: "any synthetic seed" });
```

With another test runner, `runCases(cases)` runs the cases in order and returns `{ name, group, status, detail }` for each.

The deterministic store cases are also published as data, for implementations in other languages: [`conformance/persistent/v1/schedules.json`](../../conformance/persistent/v1/SCHEDULES.md), run by an orchestrator through a driver. The seeded random sequences and the three buffer-aliasing cases exist only here.

## What a pass shows, and what it does not

A store that passes behaves as specification §4.2 and §5 require for the inputs and schedules this harness runs, in the configuration the factory supplied.

- **Store compliance does not prove a malicious in-process adapter safe.** An adapter runs inside the trusted process. One that lies only on inputs the harness does not send, keeps what it is given, or reads memory is not caught by any test here (specification §10).
- **A pass against one store says nothing about another.** [`@redact-secret/store-memory`](../store-memory/README.md) passing shows that the in-memory adapter follows the contract. It says nothing about a database adapter: isolation levels, locking, durability, failover, and clock behavior belong to the backend and have to be shown against it, with the options and versions recorded.
- A pass is not durability. Nothing here kills a process, cuts a connection, or restores a backup.
- A skipped case is not a pass. Cases the factory cannot support are reported as skipped with a reason.
- The key-provider harness shows the contract's observable behavior. It cannot show that key material is protected at rest or that a remote service retires a key.

## More

The [reference](../../docs/reference/vault-conformance.md) has the factory contracts, every case group, what is skipped and when, the reference model, every fault kind, and the test key provider.
