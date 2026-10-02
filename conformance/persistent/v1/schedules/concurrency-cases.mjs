// Concurrency cases (§7.1) and the two-connection schedules of §5.2, converted from
// packages/vault-conformance/src/concurrency-cases.ts.
import {
  DAY,
  add,
  adder,
  buildCapture,
  buildCommit,
  check,
  commitOk,
  create,
  entry,
  eq,
  expectOutcome,
  expectRejected,
  expectAbsent,
  from,
  inspect,
  readCaptures,
  readEntries,
  revokeIn,
  serving,
} from "./helpers.mjs";

export const cases = [];

const N = "{PARALLELISM}";
const TWO_ACTORS = ["A", "B"];

/** The case's calls run on two actors in turn, as the native harness spreads them over two handles. */
const spread = TWO_ACTORS;

const countWhere = (over, where) => ({ $count: { over, where } });

{
  const addCase = adder("concurrency", cases);

  addCase(
    "parallel restores of one single-use entry: exactly one commits",
    [
      serving(),
      create("h", { maxUses: 1 }),
      readEntries("{h.scope}", "{h.entryIds}", { save: "r" }),
      {
        forEach: {
          over: { $range: [0, N] },
          collect: "k",
          as: "inputs",
          steps: [buildCommit("k", ["h"], { fromRead: "{r}" })],
        },
      },
      {
        parallel: {
          over: "{inputs}",
          as: "p",
          actors: spread,
          steps: [{ op: "commitRestore", actor: "{ACTOR}", input: "{item}", save: "res", what: "a parallel restore" }],
        },
      },
      eq(countWhere("{p}", { res: { outcome: "committed" } }), 1, "exactly one of the parallel restores commits"),
      eq(
        countWhere("{p}", {
          res: { $notMatch: { $any: [{ outcome: "committed" }, { outcome: "rejected", reason: { $in: ["budget", "stale"] } }] } },
        }),
        0,
        "a parallel restore that lost is rejected for budget or stale",
      ),
      entry("e", "h"),
      eq("{e.used}", 1, "used after the parallel restores"),
      eq("{e.lifecycleRevision}", 2, "lifecycleRevision after the parallel restores"),
      {
        forEach: {
          over: "{p}",
          collect: "flag",
          as: "receipts",
          steps: [
            inspect("{item.item.scope}", "{item.item.attempt.attemptId}", undefined, "inspectAttempt of a parallel attempt", { save: "rc" }),
            { let: { flag: { $eq: ["{rc.state}", "committed"] } } },
            check({ $eq: ["{flag}", { $eq: ["{item.res.outcome}", "committed"] }] }, "an attempt has a receipt exactly when it committed"),
          ],
        },
      },
      eq(countWhere("{receipts}", true), 1, "exactly one receipt was written"),
    ],
  );

  addCase("parallel restores of one entry with maxUses 7, retried on stale: exactly seven commit", [
    serving(),
    create("h", { maxUses: 7 }),
    {
      parallel: {
        over: { $range: [0, N] },
        as: "p",
        actors: spread,
        steps: [{ restoreRetry: "o", uses: [{ capture: "h" }], actor: "{ACTOR}", maxTries: { $mul: [20, N] } }],
      },
    },
    eq(countWhere("{p}", { o: "committed" }), { $min: [7, N] }, "exactly maxUses restores commit"),
    eq(countWhere("{p}", { o: { $notMatch: { $in: ["committed", "budget"] } } }), 0, "a restore either commits or is denied for budget"),
    entry("e", "h"),
    eq("{e.used}", { $min: [7, N] }, "used never exceeds maxUses"),
  ]);

  const readAll = (handle, as) => [
    { let: { size: "{CAPS.maxRestoreEntries}" } },
    {
      forEach: {
        over: { $range: [0, { $div: [add({ $len: `{${handle}.entryIds}` }, "{size}", -1), "{size}"] }] },
        collect: "chunk",
        as: `${as}_chunks`,
        steps: [
          readEntries(`{${handle}.scope}`, { $slice: [`{${handle}.entryIds}`, { $mul: ["{item}", "{size}"] }, { $mul: [add("{item}", 1), "{size}"] }] }, {
            save: "rd",
            what: "readEntries of a chunk",
          }),
          { let: { chunk: "{rd.entries}" } },
        ],
      },
    },
    { let: { [as]: { $flatten: `{${as}_chunks}` } } },
  ];

  addCase("parallel restores racing one revocation are consistent with a single order", [
    serving(),
    { let: { count: { $min: [N, "{CAPS.maxCreateEntries}"] } } },
    create("h", { entries: "{count}", maxUses: 1000, envelopeBytes: 8 }),
    {
      forEach: {
        over: { $range: [0, N] },
        collect: "k",
        as: "inputs",
        steps: [buildCommit("k", [{ capture: "h", entry: { $mod: ["{item}", "{count}"] } }])],
      },
    },
    { let: { half: { $div: [N, 2] }, late: { $div: [{ $mul: [N, 3] }, 4] } } },
    {
      parallel: {
        over: { $slice: ["{inputs}", 0, "{half}"] },
        as: "g1",
        actors: spread,
        steps: [{ op: "commitRestore", actor: "{ACTOR}", input: "{item}", save: "res" }],
      },
      async: "first",
    },
    {
      actor: "B",
      op: "revokeCapture",
      input: revokeIn("h"),
      expect: { outcome: "revoked" },
      what: "the revocation",
      async: "revocation",
    },
    {
      parallel: {
        over: { $slice: ["{inputs}", "{half}", "{late}"] },
        as: "g2",
        actors: spread,
        steps: [{ op: "commitRestore", actor: "{ACTOR}", input: "{item}", save: "res" }],
      },
      async: "second",
    },
    { await: "revocation" },
    {
      parallel: {
        over: { $slice: ["{inputs}", "{late}", N] },
        as: "g3",
        actors: spread,
        steps: [{ op: "commitRestore", actor: "{ACTOR}", input: "{item}", save: "res" }],
      },
      async: "third",
    },
    { await: "first", as: "g1" },
    { await: "second", as: "g2" },
    { await: "third", as: "g3" },
    check(
      { $eq: [countWhere("{g3}", { res: { outcome: "committed" } }), 0] },
      "a restore started after the revocation was acknowledged must not commit",
    ),
    { let: { all: { $concatList: ["{g1}", "{g2}", "{g3}"] } } },
    eq(
      countWhere("{all}", { res: { $notMatch: { $any: [{ outcome: "committed" }, { outcome: "rejected", reason: { $in: ["revoked", "stale"] } }] } } }),
      0,
      "a restore that lost to the revocation or to another restore is rejected for revoked or stale",
    ),
    ...readAll("h", "used"),
    {
      check: {
        $eq: [
          { $sum: { over: "{used}", of: "{item.used}" } },
          countWhere("{all}", { res: { outcome: "committed" } }),
        ],
      },
      what: "total used equals the number of committed restores",
    },
    {
      forEach: {
        over: "{used}",
        itemAs: "ent",
        steps: [
          check(
            {
              $eq: [
                "{ent.used}",
                countWhere("{all}", { res: { outcome: "committed" }, item: { uses: [{ entryId: "{ent.entryId}" }] } }),
              ],
            },
            "each entry's used equals the restores that committed on it",
          ),
        ],
      },
    },
    { op: "readCaptures", input: { scope: "{h.scope}", captureIds: ["{h.captureId}"] }, expect: [{ state: "revoked" }], what: "the capture ends revoked" },
    {
      forEach: {
        over: "{all}",
        steps: [
          inspect("{item.item.scope}", "{item.item.attempt.attemptId}", undefined, "inspectAttempt of an attempt", { save: "rc" }),
          check(
            { $eq: [{ $eq: ["{rc.state}", "committed"] }, { $eq: ["{item.res.outcome}", "committed"] }] },
            "an attempt has a receipt exactly when it committed",
          ),
        ],
      },
    },
  ]);

  addCase("parallel identical attempts: one commits, the others are already-committed, used moves once", [
    serving(),
    create("h", { maxUses: 1000 }),
    buildCommit("k", [{ capture: "h", count: 2 }]),
    {
      parallel: {
        over: { $range: [0, N] },
        as: "p",
        actors: spread,
        steps: [
          {
            op: "commitRestore",
            actor: "{ACTOR}",
            input: "{k}",
            // A store may abort a transaction that conflicts with its twin; the same attempt is then retried.
            retryOn: { outcome: "rejected", reason: "stale" },
            maxTries: { $mul: [20, N] },
            save: "res",
          },
        ],
      },
    },
    eq(countWhere("{p}", { res: { outcome: "committed" } }), 1, "exactly one of the identical attempts commits"),
    eq(countWhere("{p}", { res: { outcome: "already-committed" } }), { $sub: [N, 1] }, "every other identical attempt is already-committed"),
    entry("e", "h"),
    eq("{e.used}", 2, "used was incremented once"),
    eq("{e.lifecycleRevision}", 2, "lifecycleRevision was incremented once"),
  ]);

  addCase("a creation racing a fence of the same identifier: created then revoked, or fenced", [
    serving(),
    {
      forEach: {
        over: { $range: [0, { $max: [8, { $div: [N, 4] }] }] },
        steps: [
          buildCapture("c", { entries: 2 }),
          { let: { parity: { $mod: ["{item}", 2] }, fence: revokeIn("c", { fence: true }) } },
          { when: { parity: 0 }, op: "createCapture", input: "{c.input}", actor: "A", async: "creating", what: "the creation" },
          { when: { parity: 0 }, op: "revokeCapture", input: "{fence}", actor: "B", async: "fencing", what: "the fence" },
          { when: { parity: 1 }, op: "revokeCapture", input: "{fence}", actor: "B", async: "fencing", what: "the fence" },
          { when: { parity: 1 }, op: "createCapture", input: "{c.input}", actor: "A", async: "creating", what: "the creation" },
          { await: "creating", as: "created" },
          { await: "fencing", as: "revoked" },
          readEntries("{c.scope}", "{c.entryIds}", { save: "rd", what: "readEntries after the race" }),
          check(
            {
              $or: [
                {
                  $and: [
                    { $eq: ["{created.outcome}", "created"] },
                    { $eq: ["{revoked.outcome}", "revoked"] },
                    { $eq: [{ $len: "{rd.entries}" }, 2] },
                  ],
                },
                {
                  $and: [
                    { $match: ["{created}", { outcome: "rejected", reason: { $in: ["fenced", "stale"] } }] },
                    { $eq: ["{revoked.outcome}", "fenced"] },
                    { $eq: [{ $len: "{rd.entries}" }, 0] },
                  ],
                },
              ],
            },
            "a creation racing a fence ends created then revoked, or fenced with no entry",
          ),
          readCaptures("{c.scope}", ["{c.captureId}"], { save: "rows", expect: { $length: 1 }, what: "the identifier has one row" }),
          check({ $eq: ["{rows[0].state}", "revoked"] }, "the identifier ends revoked either way"),
          buildCapture("later", { captureId: "{c.captureId}" }),
          expectRejected("createCapture", "{later.input}", "fenced", "a later creation of the same identifier"),
        ],
      },
    },
  ]);

  addCase("multi-entry restores under contention never apply part of a batch", [
    serving(),
    create("h", { entries: 2, maxUses: [1000, 3] }),
    { let: { pairs: { $div: [N, 2] } } },
    { let: { singles: { $sub: [N, "{pairs}"] } } },
    {
      parallel: {
        over: { $range: [0, N] },
        as: "p",
        actors: spread,
        steps: [
          { let: { isPair: { $lt: ["{item}", "{pairs}"] } } },
          {
            when: { isPair: true },
            restoreRetry: "o",
            uses: [
              { capture: "h", entry: 0 },
              { capture: "h", entry: 1 },
            ],
            actor: "{ACTOR}",
            maxTries: { $mul: [40, N] },
          },
          { when: { isPair: false }, restoreRetry: "o", uses: [{ capture: "h", entry: 0 }], actor: "{ACTOR}", maxTries: { $mul: [40, N] } },
        ],
      },
    },
    { let: { pairRuns: { $slice: ["{p}", 0, "{pairs}"] }, singleRuns: { $slice: ["{p}", "{pairs}", N] } } },
    { let: { pairCommitted: countWhere("{pairRuns}", { o: "committed" }), singleCommitted: countWhere("{singleRuns}", { o: "committed" }) } },
    eq("{pairCommitted}", { $min: [3, "{pairs}"] }, "exactly as many two-entry restores commit as the scarcer entry allows"),
    eq("{singleCommitted}", "{singles}", "every single-entry restore commits"),
    eq(countWhere("{pairRuns}", { o: { $notMatch: { $in: ["committed", "budget"] } } }), 0, "a two-entry restore commits or is denied for budget"),
    entry("scarce", "h", 1),
    eq("{scarce.used}", "{pairCommitted}", "the scarce entry's used equals the two-entry restores that committed"),
    entry("plenty", "h", 0),
    eq("{plenty.used}", add("{pairCommitted}", "{singleCommitted}"), "the other entry's used counts no rolled-back batch"),
  ]);
}

// -------------------------------------------------------------- interleaving
{
  const addCase = adder("interleave", cases);
  const hold = { hold: "before-commit", holdId: "h1", async: "primary" };
  const requires = { holds: ["before-commit"] };
  const concurrent = (op, input, expect, what) => ({ actor: "B", op, input, expect, what, async: "competing" });
  const afterHold = [
    { await: "competing", within: 500, settledAs: "concurrentFirst" },
    { release: "h1" },
    { await: "competing" },
  ];

  addCase(
    "a revocation committed between a restore's read and its commit: the restore does not commit",
    [
      serving(),
      create("h", { maxUses: 5 }),
      buildCommit("prepared", ["h"]),
      { op: "commitRestore", input: "{prepared}", ...hold, what: "the primary restore" },
      concurrent("revokeCapture", revokeIn("h"), { outcome: "revoked" }, "the competing revocation"),
      ...afterHold,
      {
        await: "primary",
        as: "res",
        expectOneOf: [{ outcome: "rejected", reason: { $in: ["revoked", "stale"] } }, { $when: { concurrentFirst: false }, outcome: "committed" }],
      },
      { let: { committed: { $eq: ["{res.outcome}", "committed"] } } },
      entry("e", "h"),
      eq("{e.used}", { $if: ["{committed}", 1, 0] }, "used matches the restore's outcome"),
      inspect(
        "{prepared.scope}",
        "{prepared.attempt.attemptId}",
        undefined,
        "inspectAttempt after the race",
        { save: "rc" },
      ),
      eq("{rc.state}", { $if: ["{committed}", "committed", "absent"] }, "the receipt matches the restore's outcome"),
      { op: "readCaptures", input: { scope: "{h.scope}", captureIds: ["{h.captureId}"] }, expect: [{ state: "revoked" }], what: "the capture ends revoked" },
    ],
    { actors: TWO_ACTORS, requires },
  );

  addCase(
    "a quarantine committed between a creation's check and its commit: the creation does not succeed",
    [
      serving(),
      buildCapture("c", { entries: 2 }),
      { op: "createCapture", input: "{c.input}", ...hold, what: "the primary creation" },
      concurrent("quarantine", { namespace: "{NS}" }, { state: "quarantined" }, "the competing quarantine"),
      ...afterHold,
      {
        await: "primary",
        as: "res",
        expectOneOf: [{ outcome: "rejected", reason: { $in: ["quarantined", "stale"] } }, { $when: { concurrentFirst: false }, outcome: "created" }],
      },
      readEntries("{c.scope}", "{c.entryIds}", { save: "rd", what: "readEntries after the race" }),
      readCaptures("{c.scope}", ["{c.captureId}"], { save: "rows", what: "readCaptures after the race" }),
      eq({ $len: "{rd.entries}" }, { $if: [{ $eq: ["{res.outcome}", "created"] }, 2, 0] }, "a creation ordered before the quarantine is complete, and a lost one leaves no entry"),
      eq({ $len: "{rows}" }, { $if: [{ $eq: ["{res.outcome}", "created"] }, 1, 0] }, "a lost creation leaves no capture row"),
      { op: "recoveryState", input: { namespace: "{NS}" }, expect: { state: "quarantined" }, what: "the namespace ends quarantined" },
    ],
    { actors: TWO_ACTORS, requires },
  );

  addCase(
    "a quarantine committed between a restore's read and its commit: the restore does not commit",
    [
      serving(),
      create("h", { maxUses: 5 }),
      buildCommit("prepared", ["h"]),
      { op: "commitRestore", input: "{prepared}", ...hold, what: "the primary restore" },
      concurrent("quarantine", { namespace: "{NS}" }, { state: "quarantined" }, "the competing quarantine"),
      ...afterHold,
      {
        await: "primary",
        as: "res",
        expectOneOf: [{ outcome: "rejected", reason: { $in: ["quarantined", "stale"] } }, { $when: { concurrentFirst: false }, outcome: "committed" }],
      },
      entry("e", "h"),
      eq("{e.used}", { $if: [{ $eq: ["{res.outcome}", "committed"] }, 1, 0] }, "used matches the restore's outcome"),
    ],
    { actors: TWO_ACTORS, requires },
  );

  addCase(
    "an invalidation committed between a restore's read and its commit: the restore does not commit",
    [
      serving(),
      create("h", { maxUses: 5 }),
      buildCommit("prepared", ["h"]),
      { op: "commitRestore", input: "{prepared}", ...hold, what: "the primary restore" },
      concurrent("invalidateRecovered", { namespace: "{NS}", newEpoch: 2 }, { outcome: "invalidated" }, "the competing invalidation"),
      ...afterHold,
      {
        await: "primary",
        as: "res",
        expectOneOf: [
          { outcome: "rejected", reason: { $in: ["quarantined", "revoked", "stale"] } },
          { $when: { concurrentFirst: false }, outcome: "committed" },
        ],
      },
      entry("e", "h"),
      eq("{e.used}", { $if: [{ $eq: ["{res.outcome}", "committed"] }, 1, 0] }, "used matches the restore's outcome"),
    ],
    { actors: TWO_ACTORS, requires },
  );

  addCase(
    "a fence committed between a creation's check and its commit: the creation does not succeed",
    [
      serving(),
      buildCapture("c", { entries: 2 }),
      { op: "createCapture", input: "{c.input}", ...hold, what: "the primary creation" },
      concurrent("revokeCapture", revokeIn("c", { fence: true }), { outcome: { $in: ["fenced", "revoked"] } }, "the competing fence"),
      { await: "competing", within: 500, settledAs: "concurrentFirst", as: "fo" },
      { release: "h1" },
      { await: "competing", as: "fo" },
      {
        await: "primary",
        as: "res",
        expectOneOf: [
          { $when: { "fo.outcome": "fenced" }, outcome: "rejected", reason: { $in: ["fenced", "stale"] } },
          { $when: { "fo.outcome": "revoked", concurrentFirst: false }, outcome: "created" },
        ],
      },
      readEntries("{c.scope}", "{c.entryIds}", { save: "rd", what: "readEntries after the race" }),
      eq({ $len: "{rd.entries}" }, { $if: [{ $eq: ["{fo.outcome}", "fenced"] }, 0, 2] }, "a fenced creation leaves no entry"),
      readCaptures("{c.scope}", ["{c.captureId}"], { save: "rows", expect: [{ state: "revoked" }], what: "the identifier ends revoked either way" }),
    ],
    { actors: TWO_ACTORS, requires },
  );
}
