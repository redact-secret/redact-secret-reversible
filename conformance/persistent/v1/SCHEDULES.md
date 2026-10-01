# Schedule corpus and driver protocol, version 1

`schedules.json` holds the cases that decide whether a `Store` (and, at the server level, a persistent server profile) behaves as [the persistent vault specification](../../../docs/specs/persistent-vault.md) §4.2, §5, §7, and §8 require. The cases are **data**. An *orchestrator* interprets them and talks to one or more *drivers* over standard input and output; a driver is a small program in the language of the implementation under test. The orchestrator does not know the language, the store, or the crypto: the same file gives the JavaScript run, a Python run, and mixed runs where actors are in different languages ([plan §6.3](../../../docs/plans/python-persistence-parity.md#63-making-the-store-conformance-oracle-language-neutral)).

**This is test tooling.** The orchestrator, the drivers, and the hold and fault hooks are not shipped in any package or wheel, accept only synthetic fixtures, and carry result structures and error codes only. A pass shows that one implementation, in one configuration, followed the contract on the schedules run. It is not durability, and it says nothing about another store, another language, or a hostile in-process adapter.

## Files

| File | Purpose |
| --- | --- |
| `schedules.json` | The cases. Generated; do not edit by hand. |
| `generate-schedules.mjs` | Writes `schedules.json` from `schedules/*.mjs`, which author the cases with loops for variant lists. `--check` compares without writing. |
| `orchestrator.mjs` | Interprets the file. Node.js standard library only. Exports `runSchedules`; `node orchestrator.mjs --driver "<command>"` is the command line. |
| `driver-js.mjs` | The JavaScript driver: `@redact-secret/store-memory` at the store level, a persistent server over it at the server level. |
| [`packages/vault-py/tests/schedule_driver.py`](../../../packages/vault-py/tests/schedule_driver.py) | The Python driver: the Python reference store at the store level. It lives in the test tree and is not in the wheel. A level it does not serve answers `UNSUPPORTED_LEVEL` and those cases are skipped with that reason. |

```sh
npm run build
node conformance/persistent/v1/generate-schedules.mjs --check
node conformance/persistent/v1/orchestrator.mjs --driver "node conformance/persistent/v1/driver-js.mjs"
# options: --level store|server  --filter <text in the case id>  --ids <id,id,…>  --seed <n>  --parallelism <n>
#          --store-options '<json passed to the driver>'  --actor-driver B="<command>"  --json  --debug
```

The exit status is 0 when no case failed, 1 when one did, 2 on a usage error. A case that needs something the driver cannot supply is reported **skipped, with the reason**. A skipped case is never a pass.

## The file

`version`, `fixtures` (synthetic values: two tenants, a key reference, the server-level identities and values), `holdPoints`, `faultPoints`, and `cases`. A case has:

| Field | Meaning |
| --- | --- |
| `id` | Unique, `<group>.<slug>`. |
| `group`, `title` | The area, and a sentence. |
| `level` | `store` (operations of spec §5 on a `Store`) or `server` (`capture`, `restore`, `revoke`, `deleteCaptureCiphertext`, `resolveAttempt` on a persistent server). |
| `native` | The name of the case of `@redact-secret/vault-conformance` this one converts. Absent for cases that exist only here. |
| `requires` | What the driver must supply, or the case is skipped: `testClock` (the clock can be moved), `holds` (hold points), `faults` (fault points), `crossProcess` (actors in separate processes against a store that declares `crossProcess`), `durability`. |
| `actors` | Names of the actors, default `["A"]`. Actors that share a store run in one driver process; with `crossProcess` stores each actor may have its own driver (`--actor-driver`). |
| `steps` | The ordered steps. |

Every case works in namespaces it draws at random (`{NS}`, `{NS2}`) and never touches another, so cases may share a database.

## Values

Inputs and results use the specification's field names. Bytes are lowercase hexadecimal. In a request a byte field may instead be `{"$fill": <byte>, "length": <n>}`, a run of one byte, so a case can send a maximum-size envelope without a megabyte of hexadecimal. Integers are JSON integers; `1.5` and `9007199254740992` (2^53) are used on purpose and must be rejected by the contract's validators.

Strings in a step may contain `{name}` and `{name.path[0]}`, which are replaced by a variable. A string that is exactly one such reference keeps the variable's type. Variables are the fixed ones (`NS`, `NS2`, `SCOPE_A`, `SCOPE_B`, `SCOPE_A2`, `TENANT_A`, `TENANT_B`, `CAPS` the declared capabilities, `SKEW` the declared `maxClockSkewMs`, `FAR`, `HOUR`, `DAY`, `PARALLELISM`, `CTX`, and the fixture `values`) and those a step saves. An object with a single key that starts with `$` is an operator:

| Operator | Result |
| --- | --- |
| `$now: n` | The store clock plus `n`. Without `testClock` the orchestrator's own clock. |
| `$cap`, `$param` | A declared capability; the parallelism. |
| `$add`, `$sub`, `$mul`, `$div` (floor), `$mod`, `$neg`, `$min`, `$max`, `$pow` | Integer arithmetic. |
| `$repeat: [text, n]`, `$concat: [...]`, `$len: x` | String and list helpers. |
| `$bytes: {length, fill?}` | A byte run (with `fill`) or `length` pseudo-random bytes as hexadecimal. |
| `$gen: kind`, `$list: {gen, count}` | A fresh synthetic `captureId`, `entryId`, `attemptId`, or `digest`; a list of them. |
| `$hex: {byte, times}` | A hexadecimal string. |
| `{$from: x, set: {path: expr}, unset: [path]}` | A deep copy of `x` with fields replaced. `path` may end in `[]` to append. Inside `set`, `$src: "path"` reads the source before any change. |
| `$if`, `$eq`, `$ne`, `$lt`, `$lte`, `$gt`, `$gte`, `$and`, `$or`, `$not`, `$contains` | Conditions. |
| `$match: [value, pattern]` | Whether `value` matches `pattern` (below). |
| `$count`, `$sum`, `$find`, `$map`, `$range`, `$slice`, `$flatten`, `$concatList` | Over lists, with `item` and `i` in scope (`$find` and `$count` take `where`, a pattern). |

A **pattern** is an object that matches by subset (every key listed must match), a list that matches by index prefix (use `$length` for an exact length), or a value. Pattern operators: `$in: [values]`, `$length: n`, `$absent: true`, `$atLeast`, `$atMost`, `$notMatch: pattern`, `$all: [patterns]`, `$any: [patterns]`.

## Steps

| Step | Meaning |
| --- | --- |
| `{op, actor?, input, expect?, expectOneOf?, expectError?, expectReason?, save?, what}` | One operation on one actor. `expect` is a pattern the result must match, `expectOneOf` a list of patterns where the specification leaves the reason open (an alternative may carry `$when: {variable: value}` to apply only then), `expectError` a code or a list (a `StoreError` code at the store level, a `VaultServerError` code at the server level, with `expectReason` for its denial reason). A call with none of these may return anything but an error. `save` names a variable for the result, or for an error `{error, reason?, attemptId?}`. |
| `{create: name, options}`, `{createExpired: name, options}` | Build a capture as the JavaScript harness's bench does (options `entries`, `maxUses`, `lifetimeMs`, `epoch`, `captureId`, `entryIds`, `sessionTag`, `envelopeBytes`, `envelopeFill`, `scope`), create it, and save a handle `{scope, captureId, entryIds, createdAt, expiresAt, input}`. An expired capture is created and the clock moved to its expiry, or, without `testClock`, created already expired by the store's skew allowance. |
| `{build: "capture"\|"commit", as, ...}` | Build an input without sending it. A commit input is built as a server would, from a fresh `readEntries` of `uses: [{capture, entry?, count?}]` (or from a saved read, `fromRead`). |
| `{entry: name, of, index}`, `{captureRow: name, of}` | Read one entry, or one capture row, and save it. |
| `{snapshot: name, captures}`, `{expectSnapshot: name, captures, what}` | Save, and later compare, everything the store returns for those captures. |
| `{setClock: ms}`, `{advance: ms}` | Move the store's clock (needs `testClock`). |
| `{capabilities: "complete"\|"read", save?}` | Read the declared capabilities, and check them against the requirements of spec §4.1. |
| `{check: expr, what}` | A condition that must be true. |
| `{let: {name: expr}}`, `{skipIf: expr, reason}`, `when: {variable: value}` | Variables; a skip with a reason; run a step only if a variable (or `testClock`) has that value. |
| `{forEach: {over, as?, collect?, itemAs?, steps}}`, `{loop: {max, until, steps}}` | Sequential repetition. |
| `{parallel: {over, as, actors?, steps}, async?}` | Run `steps` for each item at once, on actors in turn (`ACTOR`); the saved variables of each become one item of `as`. |
| `{restoreRetry: name, uses, actor, maxTries}` | Read, commit, and read again on `stale`, as a server does; saves `committed` or the rejection reason. |
| `async: name`, `{await: name, within?, settledAs?, as?}` | Start an operation without waiting; later wait for it. With `within` (ms) the wait ends early when the call is still pending, and `settledAs` records whether it had settled. |
| `hold: "before-commit"`, `holdId`, `{release: holdId}` | See below. |
| `fault` | See below. |

## Hold and fault points

The vocabulary is fixed. Each driver implements it in its test build; no production API exposes it.

**Hold points.** `before-commit`: the call has done its reads and checks and has not committed, and waits for `{release}`. The driver announces it with the event `{"event":"held","holdId":…}`, and the orchestrator does not go on until it has arrived. A competing call is then issued, with `async`, and the schedule states the **required outcome, not the mechanism**: a locking store makes the competing call wait for the held transaction and an optimistic store lets it commit and aborts the held one, so a schedule uses `expectOneOf` with `$when` on whether the competing call settled first (`await … within`). What a schedule never accepts is a held call that succeeds after a conflicting call was acknowledged. For PostgreSQL, the transaction has executed its statements and waits before `COMMIT`. For `store-memory`, the call waits after validation and before its atomic section.

**Fault points.** A fault applies to one call.

| Fault | Effect |
| --- | --- |
| `unavailable` | The call fails `STORE_UNAVAILABLE` without reaching the store. Nothing is applied. |
| `before-first-write` | The call begins, and fails `STORE_UNAVAILABLE` before its first write. Nothing is applied. |
| `drop-connection` | The connection is lost at an unspecified point: `STORE_AMBIGUOUS`. The effect is unknown; a schedule reads the state afterwards and checks it is self-consistent. |
| `after-commit-before-ack` | The commit is durable and the caller sees a lost connection: `STORE_AMBIGUOUS`. |

At the server level a fault names the store operation it hits: `fault: {operation: "commitRestore", kind: "after-commit-before-ack"}`.

## Driver protocol

One JSON object per line on standard input; one per line on standard output. Requests carry an integer `id`. A driver **must process requests concurrently**: a held call must not block any other, and responses may arrive in any order. Standard error is not read.

```text
-> {"id":1,"op":"configure","level":"store","caseId":"…","actors":["A","B"],"store":{…},"namespace":"conf-…","otherNamespace":"conf-…","fixtures":{…}}
<- {"id":1,"ok":true,"capabilities":{…},"features":{"testClock":true,"holds":["before-commit"],"faults":[…],"levels":["store"]}}
-> {"id":2,"op":"commitRestore","actor":"A","input":{…},"hold":"before-commit","holdId":"h1"}
<- {"event":"held","holdId":"h1"}
-> {"id":3,"op":"release","holdId":"h1"}
<- {"id":3,"ok":true}
<- {"id":2,"result":{"outcome":"rejected","reason":"stale"}}
<- {"id":4,"error":"STORE_AMBIGUOUS"}
<- {"id":5,"error":"RESTORE_DENIED","detail":{"reason":"budget"}}
```

| Request | Meaning |
| --- | --- |
| `configure` | Start a fresh store (or, at `level: "server"`, a server over a store, a record-crypto layer, fixed synthetic resolvers, and allow-all policies) for one case, forgetting the previous one. `store` is opaque options from the command line (the JavaScript driver reads the declared bounds, `realClock`, and `noHolds`). Answers `ok: false` for a level the driver does not serve; the case is then skipped. |
| `reset` | Forget the case: release every hold and drop the store. |
| `capabilities` | The store's declared capabilities. |
| `clock` with `action` `now`, `advance`, or `set` | The store's clock, when the driver reports `testClock`. At the server level it moves the server's clock too. |
| a store operation (`createCapture`, `readEntries`, `readCaptures`, `commitRestore`, `revokeCapture`, `inspectAttempt`, `replaceCaptureKey`, `deleteCiphertext`, `sweepExpired`, `recoveryState`, `initializeNamespace`, `quarantine`, `invalidateRecovered`) | `input` is the operation's input. The answer is `result` or `error`, the `StoreError` code. Any other failure is `INTERNAL`, with no text. |
| a server operation (`capture`, `restore`, `revoke`, `deleteCaptureCiphertext`, `resolveAttempt`) | `input` carries a `context` (an identity from the fixture table, and optionally a session) and the operation's arguments. The answer is `result`, or `error` with `detail: {reason?, attemptId?}`. |
| `release` | Let a held call continue. |

The database connection string, when a driver needs one, is passed by environment variable name, never in the schedule file. A driver's answers carry result structures and error codes only, never a driver's error text.

## What is converted, and what is not

The cases of the JavaScript store harness (`@redact-secret/vault-conformance`) are converted by `native`: the capability, validation, create, read, commit, revoke, inspect, rekey, delete, sweep, recovery, concurrency, and interleave groups, 97 cases. **Not converted:**

- the three `aliasing` cases: they change a buffer in the caller's process after a call, which a line protocol cannot express. They stay native.
- the five `model` cases: seeded random sequences compared with a reference model. They are a generator of schedules, a JavaScript tool that can emit more cases in this format (plan §6.3 and issue #110); no random schedule is in the file.
- the key-provider harness: a different contract, not part of this file.

The `fault` group (store level) and the `server` group have no native counterpart. The server cases take the JavaScript profile as the reference; they cover the round trip, budgets, grants, tenants, sessions, revocation, ciphertext deletion, expiry, attempts, a lost acknowledgement, and an unavailable store. They are not a replacement for the server tests of `@redact-secret/vault-server`, which are code.

## How the JavaScript reference store is checked

`packages/store-memory/test/schedules.test.mjs` runs every store case through the JavaScript driver and compares its result, case by case, with the native harness, with a controllable clock and holds, with a clock the harness cannot move and no holds, with every bound lowered, and with a smaller parallelism. The two must agree on passed and skipped for every converted case. `packages/vault-conformance/test/schedule-mutants.test.mjs` runs the harness's own mutants (a store with one broken decision) through the schedules and requires each to fail the schedule that converts the case the native harness names for it.
