// Store-level cases converted from packages/vault-conformance/src/lifecycle-cases.ts
// (sweep, recovery). The three aliasing cases of that file test in-process buffer
// ownership, which the line protocol cannot express; they stay native (README.md).
import {
  DAY,
  FARSKEW,
  HOUR,
  add,
  adder,
  buildCapture,
  buildCommit,
  bytes,
  captureRow,
  check,
  commitOk,
  create,
  createExpired,
  deleteIn,
  entry,
  eq,
  expectAbsent,
  expectOutcome,
  expectRejected,
  from,
  inspect,
  readCaptures,
  readEntries,
  revokeIn,
  revokeOk,
  same,
  serving,
  snapshot,
} from "./helpers.mjs";

export const cases = [];

const sweepStep = (as, { limit = 10000, namespace = "{NS}" } = {}) => ({
  op: "sweepExpired",
  input: { namespace, now: { $now: 0 }, limit },
  expect: { outcome: "swept" },
  what: "sweepExpired with an agreeing clock must sweep",
  save: as,
});

const swept = (name, entries, captures, receipts, what) => [
  eq(`{${name}.entries}`, entries, `${what}: entries removed`),
  eq(`{${name}.captures}`, captures, `${what}: capture rows removed`),
  eq(`{${name}.receipts}`, receipts, `${what}: receipts removed`),
];

{
  const addCase = adder("sweep", cases);

  addCase("rejects clock-skew when the caller's now is outside the bound, and removes nothing", [
    serving(),
    createExpired("h", { entries: 2 }),
    ...[1, -1].map((sign) =>
      expectRejected(
        "sweepExpired",
        { namespace: "{NS}", now: add({ $now: 0 }, { $mul: [sign, FARSKEW] }), limit: 100 },
        "clock-skew",
        "sweepExpired with a skewed now",
      ),
    ),
    readEntries("{h.scope}", "{h.entryIds}", { expect: { entries: { $length: 2 } }, what: "the expired entries are still there" }),
  ]);

  addCase("never removes an unexpired capture, its entries, a revoked capture's unexpired entries, or an unexpired receipt", [
    serving(),
    create("live", { entries: 2, maxUses: 3 }),
    create("revoked", { entries: 2 }),
    buildCommit("k", ["live"]),
    commitOk("k"),
    revokeOk("revoked"),
    snapshot("before", ["live", "revoked"]),
    sweepStep("result"),
    ...swept("result", 0, 0, 0, "a sweep with nothing expired"),
    eq("{result.more}", false, "a sweep with nothing expired reports no more work"),
    same("before", ["live", "revoked"], "every row is unchanged"),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "committed" }, "the receipt is kept before receiptExpiresAt"),
  ]);

  addCase("removes the entries and the row of an expired capture, and nothing of a live one", [
    serving(),
    createExpired("expired", { entries: 2 }),
    create("live", { entries: 1 }),
    sweepStep("result"),
    ...swept("result", 2, 1, 0, "a sweep over one expired capture"),
    eq("{result.more}", false, "nothing is left to sweep"),
    readEntries("{expired.scope}", "{expired.entryIds}", { expect: { entries: { $length: 0 } }, what: "the expired entries are gone" }),
    readCaptures("{expired.scope}", ["{expired.captureId}"], { expect: { $length: 0 }, what: "the expired capture row is gone" }),
    captureRow("cr", "live"),
    eq("{cr.state}", "live", "the live capture is untouched"),
    readEntries("{live.scope}", "{live.entryIds}", { expect: { entries: { $length: 1 } }, what: "the live entry is untouched" }),
  ]);

  addCase("removes at most limit rows per kind and reports more until nothing is left", [
    serving(),
    createExpired("x0", { entries: 2 }),
    createExpired("x1", { entries: 2 }),
    createExpired("x2", { entries: 2 }),
    { let: { entries: 0, captures: 0, rounds: 0 } },
    sweepStep("result", { limit: 1 }),
    eq("{result.more}", true, "the first limited sweep leaves work and reports more"),
    {
      loop: {
        max: 50,
        until: { $not: "{more}" },
        steps: [
          check(
            { $and: [{ $lte: ["{result.entries}", 1] }, { $lte: ["{result.captures}", 1] }, { $lte: ["{result.receipts}", 1] }] },
            "a sweep removes at most limit rows per kind",
          ),
          { let: { entries: add("{entries}", "{result.entries}"), captures: add("{captures}", "{result.captures}"), more: "{result.more}" } },
          { when: { more: true }, ...sweepStep("result", { limit: 1 }) },
        ],
      },
      what: "limited sweeps must finish",
    },
    eq("{entries}", 6, "every expired entry was eventually removed"),
    eq("{captures}", 3, "every expired capture row was eventually removed"),
    sweepStep("after", { limit: 1 }),
    ...swept("after", 0, 0, 0, "a sweep after more was false"),
  ]);

  addCase("is scoped to its namespace", [
    serving(),
    serving(1, "{NS2}"),
    createExpired("other", { scope: "{SCOPE_A2}", entries: 2 }),
    sweepStep("result"),
    ...swept("result", 0, 0, 0, "a sweep of a namespace with nothing expired"),
    readEntries("{other.scope}", "{other.entryIds}", { expect: { entries: { $length: 2 } }, what: "another namespace's expired entries are untouched" }),
  ]);

  addCase(
    "keeps a receipt until receiptExpiresAt, and a replay of the swept attempt is denied",
    [
      serving(),
      create("h", { maxUses: 5, lifetimeMs: HOUR }),
      buildCommit("k", ["h"]),
      commitOk("k"),
      { setClock: { $sub: ["{k.receiptExpiresAt}", 1] } },
      sweepStep("early"),
      eq("{early.receipts}", 0, "no receipt is removed before receiptExpiresAt"),
      inspect("{k.scope}", "{k.attempt.attemptId}", { state: "committed" }, "the receipt still deduplicates its attempt"),
      expectOutcome("commitRestore", from("{k}", { now: { $now: 0 } }), "already-committed", "a replay before the receipt is swept"),
      { setClock: add("{k.receiptExpiresAt}", 1) },
      sweepStep("late"),
      eq("{late.receipts}", 1, "the receipt is removed after receiptExpiresAt"),
      inspect("{k.scope}", "{k.attempt.attemptId}", { state: "absent" }, "the swept receipt is gone"),
      expectRejected(
        "commitRestore",
        from("{k}", { now: { $now: 0 } }),
        ["expired", "unknown"],
        "a replay of a swept attempt: every capture it touched has expired",
      ),
      inspect("{k.scope}", "{k.attempt.attemptId}", { state: "absent" }, "the denied replay writes no receipt"),
    ],
    { requires: { testClock: true } },
  );

  addCase(
    "an expired capture is denied at commit whether or not it was swept",
    [
      serving(),
      create("h", { maxUses: 5, lifetimeMs: HOUR }),
      buildCommit("prepared", ["h"]),
      { setClock: add("{h.expiresAt}", 5) },
      expectRejected("commitRestore", from("{prepared}", { now: { $now: 0 } }), "expired", "commitRestore of an expired, unswept capture"),
      sweepStep("result"),
      expectRejected(
        "commitRestore",
        from("{prepared}", { now: { $now: 0 }, "attempt.attemptId": { $gen: "attemptId" } }),
        ["expired", "unknown"],
        "commitRestore of an expired, swept capture",
      ),
    ],
    { requires: { testClock: true } },
  );

  addCase(
    "keeps a revocation tombstone until the capture's expiry plus retention, and it fences creation meanwhile",
    [
      serving(),
      create("h", { entries: 2, lifetimeMs: HOUR }),
      { let: { keepUntil: add("{h.expiresAt}", 3 * HOUR) } },
      expectOutcome("revokeCapture", revokeIn("h", { retention: 3 * HOUR }), "revoked", "revokeCapture with a retention"),
      { setClock: { $sub: ["{keepUntil}", 1] } },
      sweepStep("early"),
      ...swept("early", 2, 0, 0, "a sweep past expiry and before the retention bound"),
      readCaptures("{h.scope}", ["{h.captureId}"], { expect: { $length: 1 }, what: "the tombstone is kept" }),
      buildCapture("again", { captureId: "{h.captureId}" }),
      expectRejected("createCapture", "{again.input}", "fenced", "createCapture of a tombstoned identifier"),
      { setClock: add("{keepUntil}", 1) },
      sweepStep("late"),
      ...swept("late", 0, 1, 0, "a sweep past the retention bound"),
      readCaptures("{h.scope}", ["{h.captureId}"], { expect: { $length: 0 }, what: "the tombstone is gone" }),
    ],
    { requires: { testClock: true } },
  );

  addCase(
    "keeps the tombstone of a capture revoked after its expiry for retention past the revocation",
    [
      serving(),
      create("h", { lifetimeMs: HOUR }),
      { setClock: add("{h.expiresAt}", 2 * HOUR) },
      { let: { revokedAt: { $now: 0 } } },
      expectOutcome("revokeCapture", revokeIn("h", { retention: HOUR }), "revoked", "revokeCapture of an expired capture"),
      { setClock: { $sub: [add("{revokedAt}", HOUR), 1] } },
      sweepStep("early"),
      eq("{early.captures}", 0, "the tombstone is kept until the store clock at revocation plus retention"),
      { setClock: add("{revokedAt}", HOUR, 1) },
      sweepStep("late"),
      eq("{late.captures}", 1, "the tombstone is removed after that"),
    ],
    { requires: { testClock: true } },
  );

  addCase(
    "keeps a fence for its retention",
    [
      serving(),
      buildCapture("c"),
      { let: { fencedAt: { $now: 0 } } },
      expectOutcome("revokeCapture", revokeIn("c", { fence: true, retention: DAY }), "fenced", "fencing an absent identifier"),
      { setClock: { $sub: [add("{fencedAt}", DAY), 1] } },
      sweepStep("early"),
      ...swept("early", 0, 0, 0, "a sweep before the fence's retention bound"),
      buildCapture("again", { captureId: "{c.captureId}" }),
      expectRejected("createCapture", "{again.input}", "fenced", "createCapture of a fenced identifier"),
      { setClock: add("{fencedAt}", DAY, 1) },
      sweepStep("late"),
      ...swept("late", 0, 1, 0, "a sweep past the fence's retention bound"),
    ],
    { requires: { testClock: true } },
  );
}

{
  const addCase = adder("recovery", cases);
  const quarantine = { op: "quarantine", input: { namespace: "{NS}" } };

  addCase("a namespace is uninitialized until initializeNamespace, which refuses a second call", [
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { state: "uninitialized", epoch: 0 }, what: "recoveryState of a namespace with no record" },
    serving(5),
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { state: "serving", epoch: 5 }, what: "recoveryState after initializeNamespace" },
    expectRejected("initializeNamespace", { namespace: "{NS}", epoch: 6 }, "exists", "initializeNamespace of an initialized namespace"),
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { epoch: 5 }, what: "the refused call left the epoch" },
    { op: "recoveryState", input: { namespace: "{NS2}" }, expect: { state: "uninitialized" }, what: "another namespace is unaffected" },
  ]);

  addCase("initializeNamespace refuses a namespace that already holds a row", [
    {
      op: "revokeCapture",
      input: { scope: "{SCOPE_A}", captureId: { $gen: "captureId" }, now: { $now: 0 }, retentionMs: DAY, fenceAbsent: true },
      expect: { outcome: "fenced" },
      what: "fencing an identifier in a namespace with no record",
    },
    expectRejected("initializeNamespace", { namespace: "{NS}", epoch: 1 }, "not-empty", "initializeNamespace of a namespace that holds a capture row"),
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { state: "uninitialized" }, what: "the refused call created no record" },
  ]);

  addCase("quarantine does not create a record", [
    { ...quarantine, expect: { state: "uninitialized", epoch: 0 }, what: "quarantine of a namespace with no record" },
    serving(),
  ]);

  addCase("quarantine blocks create and commit, and revocation still works", [
    serving(2),
    create("h", { epoch: 2, maxUses: 5 }),
    buildCommit("prepared", ["h"]),
    { ...quarantine, expect: { state: "quarantined", epoch: 2 }, what: "quarantine returns the new state and keeps the epoch" },
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { state: "quarantined" }, what: "recoveryState after quarantine" },
    buildCapture("blocked", { epoch: 2 }),
    expectRejected("createCapture", "{blocked.input}", "quarantined", "createCapture in a quarantined namespace"),
    ...expectAbsent("blocked", "createCapture in a quarantined namespace"),
    expectRejected("commitRestore", "{prepared}", "quarantined", "commitRestore in a quarantined namespace"),
    entry("e", "h"),
    eq("{e.used}", 0, "the blocked commit consumed nothing"),
    { ...quarantine, expect: { state: "quarantined" }, what: "quarantine is idempotent" },
    revokeOk("h"),
  ]);

  addCase("invalidateRecovered refuses an epoch that is not greater and an uninitialized namespace", [
    expectRejected("invalidateRecovered", { namespace: "{NS}", newEpoch: 2 }, "uninitialized", "invalidateRecovered of a namespace with no record"),
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { state: "uninitialized" }, what: "the refused call created no record" },
    serving(4),
    ...[4, 3, 1].map((newEpoch) =>
      expectRejected("invalidateRecovered", { namespace: "{NS}", newEpoch }, "epoch-not-greater", "invalidateRecovered with an epoch that is not greater"),
    ),
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { epoch: 4, state: "serving" }, what: "the refused calls left the epoch and the state" },
  ]);

  addCase("invalidateRecovered raises the epoch and returns a quarantined namespace to serving", [
    serving(1),
    quarantine,
    {
      op: "invalidateRecovered",
      input: { namespace: "{NS}", newEpoch: 9 },
      expect: { outcome: "invalidated", recovery: { epoch: 9, state: "serving" } },
      what: "invalidateRecovered with a greater epoch must succeed",
    },
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { epoch: 9, state: "serving" }, what: "the stored epoch and state" },
  ]);

  addCase("every capture of an earlier epoch is treated as revoked by every operation", [
    serving(1),
    create("h", { entries: 2, maxUses: 5 }),
    create("extra", { maxUses: 5 }),
    buildCommit("prepared", ["h"]),
    expectOutcome("invalidateRecovered", { namespace: "{NS}", newEpoch: 2 }, "invalidated", "invalidateRecovered"),
    readEntries("{h.scope}", "{h.entryIds}", {
      expect: { entries: { $length: 2 }, captures: [{ state: "revoked", epoch: 1 }] },
      what: "entries of an earlier epoch are still returned, with their capture revoked and keeping its epoch",
    }),
    captureRow("cr", "h"),
    eq("{cr.state}", "revoked", "readCaptures reports a capture of an earlier epoch revoked"),
    expectRejected("commitRestore", "{prepared}", "quarantined", "commitRestore carrying the old epoch"),
    expectRejected(
      "commitRestore",
      from("{prepared}", { epoch: 2, "attempt.attemptId": { $gen: "attemptId" } }),
      "revoked",
      "commitRestore of an earlier epoch's capture under the new epoch",
    ),
    entry("e", "h"),
    eq("{e.used}", 0, "nothing was consumed"),
    expectOutcome("revokeCapture", revokeIn("h"), "already-revoked", "revokeCapture of an earlier epoch's capture"),
    expectRejected(
      "replaceCaptureKey",
      { scope: "{h.scope}", captureId: "{h.captureId}", keyRevision: 1, keyRef: "synthetic-key:v2", wrappedKey: bytes(40) },
      "revoked",
      "replaceCaptureKey of an earlier epoch's capture",
    ),
    buildCapture("again", { epoch: 2, captureId: "{h.captureId}" }),
    expectRejected("createCapture", "{again.input}", "fenced", "createCapture reusing an earlier epoch's capture identifier"),
    expectOutcome(
      "deleteCiphertext",
      deleteIn("extra", add({ $now: 0 }, FARSKEW)),
      "deleted",
      "deleteCiphertext of an earlier epoch's capture, whatever the clocks say",
    ),
  ]);

  addCase("captures under the new epoch work, and the old epoch no longer does", [
    serving(1),
    create("old"),
    expectOutcome("invalidateRecovered", { namespace: "{NS}", newEpoch: 2 }, "invalidated", "invalidateRecovered"),
    buildCapture("stale", { epoch: 1 }),
    expectRejected("createCapture", "{stale.input}", "quarantined", "createCapture carrying the old epoch"),
    ...expectAbsent("stale", "createCapture carrying the old epoch"),
    create("h", { epoch: 2, maxUses: 2 }),
    captureRow("cr", "h"),
    eq("{cr.epoch}", 2, "a new capture carries the new epoch"),
    eq("{cr.state}", "live", "a new capture is live"),
    buildCommit("k", ["h"]),
    commitOk("k"),
    entry("e", "h"),
    eq("{e.used}", 1, "a commit under the new epoch applies"),
  ]);
}
