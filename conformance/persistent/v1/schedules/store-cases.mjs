// Store-level cases converted from packages/vault-conformance/src/store-cases.ts.
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
  expectThrows,
  findEntry,
  from,
  gte,
  hexOf,
  inspect,
  readCaptures,
  readEntries,
  revokeIn,
  revokeOk,
  same,
  serving,
  snapshot,
  src,
} from "./helpers.mjs";

export const cases = [];

// ---------------------------------------------------------------- capabilities
{
  const addCase = adder("capabilities", cases);

  addCase("declares every capability a persistent server requires, within the contract's limits", [
    { capabilities: "complete" },
  ]);

  addCase("declares bounds large enough for this harness to exercise it", [
    { capabilities: "read", save: "caps" },
    gte("{caps.maxCreateEntries}", 4, "the harness needs maxCreateEntries of at least 4"),
    gte("{caps.maxRestoreEntries}", 4, "the harness needs maxRestoreEntries of at least 4"),
    gte("{caps.maxRestoreCaptures}", 2, "the harness needs maxRestoreCaptures of at least 2"),
    gte("{caps.maxEnvelopeBytes}", 64, "the harness needs maxEnvelopeBytes of at least 64"),
    gte("{caps.maxCreateBytes}", 256, "the harness needs maxCreateBytes of at least 256"),
  ]);
}

// ---------------------------------------------------------------------- create
{
  const addCase = adder("create", cases);

  addCase("creates the capture and every entry with initial counters", [
    serving(),
    create("h", { entries: 3, maxUses: [1, 5, 1000], sessionTag: hexOf("ab", 32) }),
    captureRow("cr", "h"),
    eq("{cr.state}", "live", "a new capture is live"),
    eq("{cr.generation}", 1, "a new capture has generation 1"),
    eq("{cr.keyRevision}", 1, "a new capture has keyRevision 1"),
    eq("{cr.epoch}", 1, "a new capture carries the namespace epoch"),
    eq("{cr.sessionTag}", "{h.input.capture.sessionTag}", "the session tag is stored as given"),
    eq("{cr.createdAt}", "{h.createdAt}", "createdAt is stored as given"),
    eq("{cr.expiresAt}", "{h.expiresAt}", "expiresAt is stored as given"),
    eq("{cr.keyRef}", "{h.input.capture.keyRef}", "keyRef is stored as given"),
    eq("{cr.wrappedKey}", "{h.input.capture.wrappedKey}", "the wrapped key is stored byte for byte"),
    readEntries("{h.scope}", "{h.entryIds}", {
      save: "r",
      expect: { entries: { $length: 3 }, captures: { $length: 1 } },
      what: "every created entry is readable, with its capture once",
    }),
    ...[0, 1, 2].flatMap((index) => [
      { let: { [`e${index}`]: findEntry("r", `{h.entryIds[${index}]}`) } },
      check({ $ne: [`{e${index}}`, null] }, "a created entry is missing from readEntries"),
      eq(`{e${index}.captureId}`, "{h.captureId}", "an entry names its capture"),
      eq(`{e${index}.maxUses}`, `{h.input.entries[${index}].maxUses}`, `entry ${index}: maxUses is stored as given`),
      eq(`{e${index}.used}`, 0, "a new entry has used 0"),
      eq(`{e${index}.lifecycleRevision}`, 1, "a new entry has lifecycleRevision 1"),
      eq(`{e${index}.ciphertextRevision}`, 1, "a new entry has ciphertextRevision 1"),
      eq(`{e${index}.envelope}`, `{h.input.entries[${index}].envelope}`, "the envelope is stored byte for byte"),
    ]),
  ]);

  addCase("a capture that is not session-bound has a null session tag", [
    serving(),
    create("h"),
    captureRow("cr", "h"),
    eq("{cr.sessionTag}", null, "sessionTag of an unbound capture"),
  ]);

  addCase("rejects exists for a live capture identifier and overwrites nothing", [
    serving(),
    create("h", { entries: 2, maxUses: 3 }),
    snapshot("before", ["h"]),
    buildCapture("second", { captureId: "{h.captureId}", entries: 2 }),
    expectRejected("createCapture", "{second.input}", "exists", "createCapture with a live capture's identifier"),
    same("before", ["h"], "the existing capture and its entries are unchanged"),
    readEntries("{second.scope}", "{second.entryIds}", { expect: { entries: { $length: 0 } }, what: "no entry of the rejected capture was created" }),
  ]);

  addCase("rejects exists when any entry identifier exists under another capture, creating nothing", [
    serving(),
    create("h", { entries: 2 }),
    snapshot("before", ["h"]),
    { let: { fresh0: { $gen: "entryId" }, fresh2: { $gen: "entryId" } } },
    buildCapture("second", { entryIds: ["{fresh0}", "{h.entryIds[1]}", "{fresh2}"] }),
    expectRejected("createCapture", "{second.input}", "exists", "createCapture with a colliding entry identifier"),
    same("before", ["h"], "the existing capture and its entries are unchanged"),
    readCaptures("{second.scope}", ["{second.captureId}"], { expect: { $length: 0 }, what: "the rejected capture row was not created" }),
    readEntries("{second.scope}", ["{fresh0}", "{fresh2}"], {
      expect: { entries: { $length: 0 } },
      what: "the non-colliding entries of the rejected capture were not created",
    }),
  ]);

  addCase("rejects fenced for a revoked capture identifier", [
    serving(),
    create("h"),
    revokeOk("h"),
    buildCapture("second", { captureId: "{h.captureId}" }),
    expectRejected("createCapture", "{second.input}", "fenced", "createCapture with a revoked capture's identifier"),
    readEntries("{second.scope}", "{second.entryIds}", { expect: { entries: { $length: 0 } }, what: "no entry of the fenced capture was created" }),
    captureRow("cr", "h"),
    eq("{cr.state}", "revoked", "the revoked capture stays revoked"),
  ]);

  {
    const variants = [
      ["now ahead of the store clock", { now: add(src("now"), FARSKEW) }],
      ["now behind the store clock", { now: { $sub: [src("now"), FARSKEW] } }],
      [
        "createdAt ahead of the store clock",
        { "capture.createdAt": add(src("capture.createdAt"), FARSKEW), "capture.expiresAt": add(src("capture.expiresAt"), FARSKEW) },
      ],
      [
        "createdAt behind the store clock",
        { "capture.createdAt": { $sub: [src("capture.createdAt"), FARSKEW] }, "capture.expiresAt": { $sub: [src("capture.expiresAt"), FARSKEW] } },
      ],
    ];
    addCase("rejects clock-skew when the caller's now or createdAt is outside the bound, in both directions", [
      serving(),
      ...variants.flatMap(([label, set], index) => [
        buildCapture(`c${index}`, { entries: 2 }),
        expectRejected("createCapture", from(`{c${index}.input}`, set), "clock-skew", `createCapture with ${label}`),
        ...expectAbsent(`c${index}`, `createCapture with ${label}`),
      ]),
    ]);
  }

  addCase(
    "accepts a now and a createdAt exactly at the skew bound",
    [
      serving(),
      ...[1, -1].flatMap((sign, index) => [
        buildCapture(`c${index}`),
        expectOutcome(
          "createCapture",
          from(`{c${index}.input}`, {
            now: add({ $now: 0 }, { $mul: [sign, "{SKEW}"] }),
            "capture.createdAt": add({ $now: 0 }, { $mul: [-sign, "{SKEW}"] }),
            "capture.expiresAt": add({ $now: 0 }, { $mul: [-sign, "{SKEW}"] }, HOUR),
          }),
          "created",
          "createCapture exactly at the skew bound",
        ),
      ]),
    ],
    { requires: { testClock: true } },
  );

  addCase("rejects quarantined for an uninitialized namespace, a quarantined one, and an epoch mismatch", [
    buildCapture("first"),
    expectRejected("createCapture", "{first.input}", "quarantined", "createCapture in a namespace with no recovery record"),
    ...expectAbsent("first", "createCapture in an uninitialized namespace"),
    serving(3),
    ...[2, 4].flatMap((epoch) => [
      buildCapture(`e${epoch}`, { epoch }),
      expectRejected("createCapture", `{e${epoch}.input}`, "quarantined", "createCapture with an epoch that differs from the stored one"),
      ...expectAbsent(`e${epoch}`, "createCapture with a wrong epoch"),
    ]),
    { op: "quarantine", input: { namespace: "{NS}" } },
    buildCapture("blocked", { epoch: 3 }),
    expectRejected("createCapture", "{blocked.input}", "quarantined", "createCapture in a quarantined namespace"),
    ...expectAbsent("blocked", "createCapture in a quarantined namespace"),
  ]);

  addCase("the same identifiers in another tenant and another namespace are independent rows", [
    serving(),
    serving(1, "{NS2}"),
    create("h", { entries: 2 }),
    buildCapture("other_tenant", { scope: "{SCOPE_B}", captureId: "{h.captureId}", entryIds: "{h.entryIds}" }),
    expectOutcome("createCapture", "{other_tenant.input}", "created", "createCapture of the same identifiers in another scope"),
    buildCapture("other_ns", { scope: "{SCOPE_A2}", captureId: "{h.captureId}", entryIds: "{h.entryIds}" }),
    expectOutcome("createCapture", "{other_ns.input}", "created", "createCapture of the same identifiers in another scope"),
    readEntries("{h.scope}", "{h.entryIds}", { save: "mine" }),
    ...[0, 1].flatMap((index) => [
      { let: { [`m${index}`]: findEntry("mine", `{h.entryIds[${index}]}`) } },
      eq(`{m${index}.envelope}`, `{h.input.entries[${index}].envelope}`, "a scope reads its own envelope, not another scope's"),
    ]),
  ]);

  addCase("throws STORE_CAPABILITY for more entries than maxCreateEntries, before any write", [
    serving(),
    buildCapture("c", { entries: add("{CAPS.maxCreateEntries}", 1), envelopeBytes: 1 }),
    expectThrows("createCapture", "{c.input}", "STORE_CAPABILITY", "createCapture over maxCreateEntries"),
    ...expectAbsent("c", "createCapture over maxCreateEntries"),
  ]);

  addCase("throws STORE_CAPABILITY for more bytes than maxCreateBytes, before any write", [
    serving(),
    {
      let: {
        per: "{CAPS.maxEnvelopeBytes}",
        count: add({ $div: ["{CAPS.maxCreateBytes}", "{CAPS.maxEnvelopeBytes}"] }, 1),
      },
    },
    {
      skipIf: { $gt: ["{count}", "{CAPS.maxCreateEntries}"] },
      reason: "maxCreateBytes cannot be exceeded within maxCreateEntries envelopes of maxEnvelopeBytes",
    },
    {
      skipIf: { $gt: [{ $mul: ["{count}", "{per}"] }, 256 * 1024 * 1024] },
      reason: "exceeding maxCreateBytes would need more than 256 MiB of synthetic envelopes",
    },
    buildCapture("c", { entries: "{count}", envelopeBytes: "{per}", envelopeFill: 7 }),
    expectThrows("createCapture", "{c.input}", "STORE_CAPABILITY", "createCapture over maxCreateBytes"),
    ...expectAbsent("c", "createCapture over maxCreateBytes"),
  ]);

  addCase("throws for an envelope over maxEnvelopeBytes, before any write", [
    serving(),
    buildCapture("c", { entries: 2 }),
    // Specification §4.2 lists this as STORE_INVALID_ARGUMENT and §5 as STORE_CAPABILITY.
    // Below the format's ceiling only the declared bound is exceeded, so it is a capability error.
    expectThrows(
      "createCapture",
      from("{c.input}", { "entries[1].envelope": bytes(add("{CAPS.maxEnvelopeBytes}", 1), 7) }),
      { $if: [{ $lt: ["{CAPS.maxEnvelopeBytes}", 1114112] }, ["STORE_CAPABILITY"], ["STORE_CAPABILITY", "STORE_INVALID_ARGUMENT"]] },
      "createCapture with an oversized envelope",
    ),
    ...expectAbsent("c", "createCapture with an oversized envelope"),
  ]);
}

// ------------------------------------------------------------------ validation
{
  const addCase = adder("validation", cases);
  const INVALID = "STORE_INVALID_ARGUMENT";

  const createVariants = [
    ["a namespace with a character outside the grammar", { "scope.namespace": "bad namespace" }],
    ["an empty namespace", { "scope.namespace": "" }],
    ["a namespace of 129 characters", { "scope.namespace": { $repeat: ["n", 129] } }],
    ["an empty tenant", { "scope.tenant": "" }],
    ["a tenant of 257 code units", { "scope.tenant": { $repeat: ["t", 257] } }],
    ["a tenant with a lone surrogate", { "scope.tenant": "tenant-\ud800-synthetic" }],
    ["a capture identifier outside the grammar", { "capture.captureId": "cap_UPPERCASEUPPERCASEUPPERCASE" }],
    ["a capture identifier of the wrong length", { "capture.captureId": "cap_abc" }],
    ["an entry identifier with uppercase hexadecimal", { "entries[0].entryId": { $repeat: ["A", 64] } }],
    ["an entry identifier of 63 characters", { "entries[0].entryId": { $repeat: ["a", 63] } }],
    ["a duplicate entry identifier", { "entries[1].entryId": src("entries[0].entryId") }],
    ["no entries", { entries: [] }],
    ["a lifetime of zero", { "capture.expiresAt": src("capture.createdAt") }],
    ["a negative lifetime", { "capture.expiresAt": { $sub: [src("capture.createdAt"), 1] } }],
    ["a lifetime over 24 hours", { "capture.expiresAt": add(src("capture.createdAt"), DAY, 1) }],
    ["a non-integer createdAt", { "capture.createdAt": add(src("capture.createdAt"), 0.5) }],
    ["a non-integer now", { now: add(src("now"), 0.5) }],
    ["a negative now", { now: -1 }],
    ["a now beyond the safe integer range", { now: 9007199254740992 }],
    ["maxUses of 0", { "entries[0].maxUses": 0 }],
    ["maxUses of 1001", { "entries[0].maxUses": 1001 }],
    ["a non-integer maxUses", { "entries[0].maxUses": 1.5 }],
    ["an empty envelope", { "entries[0].envelope": "" }],
    ["an envelope that is not bytes", { "entries[0].envelope": "synthetic" }],
    ["an empty keyRef", { "capture.keyRef": "" }],
    ["a keyRef of 513 bytes", { "capture.keyRef": { $repeat: ["k", 513] } }],
    ["an empty wrappedKey", { "capture.wrappedKey": "" }],
    ["a wrappedKey of 4097 bytes", { "capture.wrappedKey": bytes(4097, 0) }],
    ["a session tag of 63 characters", { "capture.sessionTag": { $repeat: ["a", 63] } }],
    ["a session tag with uppercase hexadecimal", { "capture.sessionTag": { $repeat: ["A", 64] } }],
    ["an epoch of 0", { epoch: 0 }],
    ["a non-integer epoch", { epoch: 1.5 }],
    ["an unknown lookupVersion", { "capture.lookupVersion": 2 }],
  ];

  addCase("createCapture rejects each invalid input with STORE_INVALID_ARGUMENT and creates nothing", [
    serving(),
    buildCapture("valid", { entries: 2 }),
    ...createVariants.flatMap(([label, set]) => [
      expectThrows("createCapture", from("{valid.input}", set), INVALID, `createCapture with ${label}`),
      ...expectAbsent("valid", `createCapture with ${label}`),
    ]),
  ]);

  const commitVariants = [
    ["a duplicate entry in uses", { "uses[]": src("uses[0]") }],
    ["a duplicate capture", { "captures[]": src("captures[0]") }],
    ["a count of 0", { "uses[0].count": 0 }],
    ["a non-integer count", { "uses[0].count": 1.5 }],
    ["a negative count", { "uses[0].count": -1 }],
    ["a use whose capture is not in captures", { captures: [{ captureId: { $gen: "captureId" }, generation: 1 }] }],
    ["a capture with no use", { "captures[]": { captureId: { $gen: "captureId" }, generation: 1 } }],
    ["empty uses", { uses: [] }],
    ["empty captures", { captures: [] }],
    ["a request digest of 31 bytes", { "attempt.requestDigest": bytes(31) }],
    ["a request digest of 33 bytes", { "attempt.requestDigest": bytes(33) }],
    ["an attempt identifier outside the grammar", { "attempt.attemptId": "attempt synthetic" }],
    ["an attempt identifier of 129 characters", { "attempt.attemptId": { $repeat: ["a", 129] } }],
    ["an epoch of 0", { epoch: 0 }],
    ["a non-integer now", { now: add(src("now"), 0.5) }],
    ["an entry identifier outside the grammar", { "uses[0].entryId": "not-an-entry" }],
    ["a tenant with a lone surrogate", { "scope.tenant": "\udc00" }],
    ["a receiptExpiresAt more than 48 hours past the store clock", { receiptExpiresAt: add({ $now: 0 }, 48 * HOUR, FARSKEW) }],
    ["a non-integer receiptExpiresAt", { receiptExpiresAt: add(src("receiptExpiresAt"), 0.5) }],
  ];

  addCase("commitRestore rejects each invalid input with STORE_INVALID_ARGUMENT and changes nothing", [
    serving(),
    create("one", { entries: 2, maxUses: 5 }),
    create("two", { entries: 1, maxUses: 5 }),
    snapshot("before", ["one", "two"]),
    ...commitVariants.flatMap(([label, set], index) => [
      buildCommit(`valid${index}`, [{ capture: "one", entry: 0 }, { capture: "one", entry: 1 }]),
      expectThrows("commitRestore", from(`{valid${index}}`, set), INVALID, `commitRestore with ${label}`),
      same("before", ["one", "two"], `commitRestore with ${label}: no entry changed`),
      inspect(`{valid${index}.scope}`, `{valid${index}.attempt.attemptId}`, { state: "absent" }, `commitRestore with ${label}: no receipt was written`),
    ]),
  ]);

  const revokeVariants = [
    ["a negative retentionMs", { retentionMs: -1 }],
    ["a retentionMs over 30 days", { retentionMs: 30 * DAY + 1 }],
    ["a non-integer retentionMs", { retentionMs: 0.5 }],
    ["a capture identifier outside the grammar", { captureId: "capture-synthetic" }],
    ["a non-integer now", { now: add(src("now"), 0.5) }],
    ["a fenceAbsent that is not a boolean", { fenceAbsent: "yes" }],
    ["an invalid scope", { scope: { namespace: "{NS}", tenant: "" } }],
  ];
  const deleteVariants = [
    ["a capture identifier outside the grammar", { captureId: "cap_" }],
    ["a negative now", { now: -5 }],
    ["an invalid namespace", { scope: { namespace: "bad/namespace", tenant: "{h.scope.tenant}" } }],
  ];

  addCase("revokeCapture and deleteCiphertext reject invalid inputs and change nothing", [
    serving(),
    create("h"),
    snapshot("before", ["h"]),
    { let: { rb: revokeIn("h"), db: deleteIn("h") } },
    ...revokeVariants.map(([label, set]) => expectThrows("revokeCapture", from("{rb}", set), INVALID, `revokeCapture with ${label}`)),
    ...deleteVariants.map(([label, set]) => expectThrows("deleteCiphertext", from("{db}", set), INVALID, `deleteCiphertext with ${label}`)),
    same("before", ["h"], "the capture is unchanged after every rejected call"),
  ]);

  const rekeyVariants = [
    ["an empty keyRef", { keyRef: "" }],
    ["a keyRef over its limit", { keyRef: { $repeat: ["k", 513] } }],
    ["an empty wrappedKey", { wrappedKey: "" }],
    ["a wrappedKey over its limit", { wrappedKey: bytes(4097, 0) }],
    ["a keyRevision of 0", { keyRevision: 0 }],
    ["a capture identifier outside the grammar", { captureId: "x" }],
  ];

  addCase("replaceCaptureKey rejects invalid inputs and changes nothing", [
    serving(),
    create("h"),
    snapshot("before", ["h"]),
    {
      let: {
        base: { scope: "{h.scope}", captureId: "{h.captureId}", keyRevision: 1, keyRef: "synthetic-key:v2", wrappedKey: bytes(40, 0) },
      },
    },
    ...rekeyVariants.map(([label, set]) => expectThrows("replaceCaptureKey", from("{base}", set), INVALID, `replaceCaptureKey with ${label}`)),
    same("before", ["h"], "the capture is unchanged after every rejected call"),
  ]);

  addCase("reads and inspectAttempt reject invalid inputs", [
    serving(),
    expectThrows("readEntries", { scope: "{SCOPE_A}", entryIds: ["not-hex"] }, INVALID, "readEntries with an entry identifier outside the grammar"),
    expectThrows(
      "readEntries",
      { scope: { namespace: "", tenant: "{TENANT_A}" }, entryIds: [{ $gen: "entryId" }] },
      INVALID,
      "readEntries with an empty namespace",
    ),
    expectThrows("readCaptures", { scope: "{SCOPE_A}", captureIds: ["cap_short"] }, INVALID, "readCaptures with a capture identifier outside the grammar"),
    expectThrows("inspectAttempt", { scope: "{SCOPE_A}", attemptId: "" }, INVALID, "inspectAttempt with an empty attempt identifier"),
    expectThrows("inspectAttempt", { scope: "{SCOPE_A}", attemptId: "attempt/synthetic" }, INVALID, "inspectAttempt with an attempt identifier outside the grammar"),
  ]);

  addCase("reads over a declared bound throw STORE_CAPABILITY", [
    serving(),
    expectThrows(
      "readEntries",
      { scope: "{SCOPE_A}", entryIds: { $list: { gen: "entryId", count: add("{CAPS.maxRestoreEntries}", 1) } } },
      "STORE_CAPABILITY",
      "readEntries over maxRestoreEntries",
    ),
    expectThrows(
      "readCaptures",
      { scope: "{SCOPE_A}", captureIds: { $list: { gen: "captureId", count: add("{CAPS.maxRestoreCaptures}", 1) } } },
      "STORE_CAPABILITY",
      "readCaptures over maxRestoreCaptures",
    ),
  ]);

  addCase("commitRestore over a declared bound throws STORE_CAPABILITY and changes nothing", [
    serving(),
    create("h", { maxUses: 5 }),
    snapshot("before", ["h"]),
    buildCommit("valid", ["h"]),
    expectThrows(
      "commitRestore",
      from("{valid}", {
        uses: {
          $concatList: [
            src("uses"),
            { $map: { over: { $range: [0, "{CAPS.maxRestoreEntries}"] }, do: from(src("uses[0]"), { entryId: { $gen: "entryId" } }) } },
          ],
        },
      }),
      "STORE_CAPABILITY",
      "commitRestore over maxRestoreEntries",
    ),
    { let: { ghosts: { $list: { gen: "captureId", count: "{CAPS.maxRestoreCaptures}" } } } },
    expectThrows(
      "commitRestore",
      from("{valid}", {
        captures: { $concatList: [src("captures"), { $map: { over: "{ghosts}", do: { captureId: "{item}", generation: 1 } } }] },
        uses: {
          $concatList: [
            src("uses"),
            { $map: { over: "{ghosts}", do: from(src("uses[0]"), { entryId: { $gen: "entryId" }, captureId: "{item}" }) } },
          ],
        },
      }),
      "STORE_CAPABILITY",
      "commitRestore over maxRestoreCaptures",
    ),
    same("before", ["h"], "no entry changed"),
    inspect("{valid.scope}", "{valid.attempt.attemptId}", { state: "absent" }, "no receipt was written"),
  ]);

  addCase("sweepExpired and the recovery operations reject invalid inputs", [
    serving(),
    { let: { now: { $now: 0 } } },
    ...[
      ["a limit of 0", 0],
      ["a limit of 10001", 10001],
      ["a non-integer limit", 1.5],
    ].map(([label, limit]) =>
      expectThrows("sweepExpired", { namespace: "{NS}", now: "{now}", limit }, INVALID, `sweepExpired with ${label}`),
    ),
    expectThrows("sweepExpired", { namespace: "bad namespace", now: "{now}", limit: 1 }, INVALID, "sweepExpired with an invalid namespace"),
    expectThrows("sweepExpired", { namespace: "{NS}", now: -1, limit: 1 }, INVALID, "sweepExpired with a negative now"),
    ...[
      ["0", 0],
      ["a negative number", -1],
      ["a non-integer", 1.5],
      ["an unsafe integer", 9007199254740992],
    ].flatMap(([label, epoch]) => [
      expectThrows("initializeNamespace", { namespace: "{NS2}", epoch }, INVALID, `initializeNamespace with an epoch of ${label}`),
      expectThrows("invalidateRecovered", { namespace: "{NS}", newEpoch: epoch }, INVALID, `invalidateRecovered with a newEpoch of ${label}`),
    ]),
    {
      op: "recoveryState",
      input: { namespace: "{NS2}" },
      expect: { state: "uninitialized" },
      what: "a rejected initializeNamespace creates no record",
    },
    { op: "recoveryState", input: { namespace: "{NS}" }, expect: { epoch: 1 }, what: "a rejected invalidateRecovered leaves the epoch" },
    expectThrows("recoveryState", { namespace: "bad namespace" }, INVALID, "recoveryState with an invalid namespace"),
    expectThrows("quarantine", { namespace: "" }, INVALID, "quarantine with an empty namespace"),
  ]);
}

// ------------------------------------------------------------------------ read
{
  const addCase = adder("read", cases);

  addCase("unknown identifiers are simply absent", [
    serving(),
    readEntries("{SCOPE_A}", [{ $gen: "entryId" }, { $gen: "entryId" }], {
      expect: { entries: { $length: 0 }, captures: { $length: 0 }, recovery: { state: "serving" } },
      what: "readEntries of unknown identifiers returns nothing, and carries the recovery state",
    }),
    readCaptures("{SCOPE_A}", [{ $gen: "captureId" }], { expect: { $length: 0 }, what: "readCaptures of an unknown identifier returns nothing" }),
  ]);

  addCase("returns the known entries of several captures, each capture once", [
    serving(),
    create("one", { entries: 2 }),
    create("two", { entries: 1 }),
    readEntries("{SCOPE_A}", ["{one.entryIds[0]}", { $gen: "entryId" }, "{two.entryIds[0]}", "{one.entryIds[1]}"], {
      save: "r",
      expect: { entries: { $length: 3 }, captures: { $length: 2 } },
      what: "three of four identifiers exist; the capture of every returned entry is returned once",
    }),
    check(
      { $eq: [{ $count: { over: "{r.entries}", where: { captureId: { $in: ["{one.captureId}", "{two.captureId}"] } } } }, 3] },
      "every returned entry's capture is returned",
    ),
    readCaptures("{SCOPE_A}", ["{one.captureId}", "{two.captureId}"], { expect: { $length: 2 }, what: "readCaptures returns every row that exists" }),
    readCaptures("{SCOPE_A}", [{ $gen: "captureId" }, "{two.captureId}"], {
      expect: { $length: 1 },
      save: "mixed",
      what: "readCaptures returns only the rows that exist",
    }),
    eq("{mixed[0].captureId}", "{two.captureId}", "readCaptures returns the row that was asked for"),
  ]);

  addCase("returns an entry of a revoked capture, with the capture's state revoked", [
    serving(),
    create("h", { entries: 2 }),
    revokeOk("h"),
    readEntries("{h.scope}", "{h.entryIds}", {
      save: "r",
      expect: { entries: { $length: 2 }, captures: [{ state: "revoked" }] },
      what: "the entries of a revoked capture are still returned, and their capture is reported revoked",
    }),
    check({ $gt: [{ $len: "{r.captures[0].keyRef}" }, 0] }, "a revoked capture whose ciphertext was not deleted still holds its key"),
  ]);

  addCase("an entry whose ciphertext was deleted is absent, and its capture row holds no key", [
    serving(),
    create("h", { entries: 2 }),
    revokeOk("h"),
    expectOutcome("deleteCiphertext", deleteIn("h"), "deleted", "deleteCiphertext of a revoked capture"),
    readEntries("{h.scope}", "{h.entryIds}", {
      expect: { entries: { $length: 0 }, captures: { $length: 0 } },
      what: "deleted entries are absent, and a capture with no key is never returned by readEntries",
    }),
    captureRow("cr", "h"),
    eq("{cr.state}", "revoked", "readCaptures reports the tombstone revoked"),
    eq("{cr.keyRef}", "", "the tombstone has an empty keyRef"),
    eq("{cr.wrappedKey}", "", "the tombstone has an empty wrappedKey"),
  ]);

  addCase("another tenant's identifiers return nothing", [
    serving(),
    create("h", { entries: 2 }),
    readEntries("{SCOPE_B}", "{h.entryIds}", {
      expect: { entries: { $length: 0 }, captures: { $length: 0 } },
      what: "readEntries from another tenant returns nothing",
    }),
    readCaptures("{SCOPE_B}", ["{h.captureId}"], { expect: { $length: 0 }, what: "readCaptures from another tenant returns nothing" }),
  ]);

  addCase("another namespace's identifiers return nothing", [
    serving(),
    serving(1, "{NS2}"),
    create("h", { entries: 2 }),
    readEntries("{SCOPE_A2}", "{h.entryIds}", { expect: { entries: { $length: 0 } }, what: "readEntries from another namespace returns no entry" }),
    readCaptures("{SCOPE_A2}", ["{h.captureId}"], { expect: { $length: 0 }, what: "readCaptures from another namespace returns nothing" }),
  ]);

  addCase("readEntries carries the recovery state of its snapshot", [
    readEntries("{SCOPE_A}", [{ $gen: "entryId" }], {
      expect: { recovery: { state: "uninitialized", epoch: 0 } },
      what: "a namespace with no record reads as uninitialized with epoch 0",
    }),
    serving(7),
    create("h", { epoch: 7 }),
    readEntries("{SCOPE_A}", "{h.entryIds}", {
      expect: { recovery: { state: "serving", epoch: 7 } },
      what: "an initialized namespace reads as serving with the stored epoch",
    }),
    { op: "quarantine", input: { namespace: "{NS}" } },
    readEntries("{SCOPE_A}", "{h.entryIds}", {
      expect: { recovery: { state: "quarantined" }, entries: { $length: 1 } },
      what: "a quarantined namespace reads as quarantined, and reads still work",
    }),
  ]);
}

// ---------------------------------------------------------------------- commit
{
  const addCase = adder("commit", cases);
  const ok = (name) => commitOk(name);

  addCase("applies a use, bumps the lifecycle revision, and writes the receipt", [
    serving(),
    create("h", { maxUses: 3 }),
    buildCommit("k", ["h"]),
    ok("k"),
    entry("e", "h"),
    eq("{e.used}", 1, "used after one committed use"),
    eq("{e.lifecycleRevision}", 2, "lifecycleRevision after one commit"),
    eq("{e.ciphertextRevision}", 1, "ciphertextRevision is not changed by a commit"),
    captureRow("cr", "h"),
    eq("{cr.generation}", 1, "a commit does not change the capture's generation"),
    eq("{cr.keyRevision}", 1, "a commit does not change the capture's keyRevision"),
    eq("{cr.state}", "live", "a commit does not change the capture's state"),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "committed" }, "the receipt of a committed attempt"),
  ]);

  addCase("consumes the aggregate occurrence count of an entry in one step", [
    serving(),
    create("h", { maxUses: 5 }),
    buildCommit("k", [{ capture: "h", count: 3 }]),
    ok("k"),
    entry("e", "h"),
    eq("{e.used}", 3, "used after a use of count 3"),
    eq("{e.lifecycleRevision}", 2, "one commit bumps lifecycleRevision once, whatever the count"),
  ]);

  addCase("applies every use of a batch across entries and captures", [
    serving(),
    create("one", { entries: 2, maxUses: 4 }),
    create("two", { entries: 1, maxUses: 4 }),
    buildCommit("k", [
      { capture: "one", entry: 0, count: 2 },
      { capture: "one", entry: 1 },
      { capture: "two", count: 4 },
    ]),
    ok("k"),
    entry("a", "one", 0),
    entry("b", "one", 1),
    entry("c", "two", 0),
    eq("{a.used}", 2, "first entry of the first capture"),
    eq("{b.used}", 1, "second entry of the first capture"),
    eq("{c.used}", 4, "entry of the second capture"),
  ]);

  addCase("rejects unknown for an absent capture, an absent entry, and an entry stated under another capture", [
    serving(),
    create("one", { maxUses: 5 }),
    create("two", { maxUses: 5 }),
    snapshot("before", ["one", "two"]),
    buildCommit("valid", ["one"]),
    { let: { ghost: { $gen: "captureId" } } },
    expectRejected(
      "commitRestore",
      from("{valid}", {
        captures: [{ captureId: "{ghost}", generation: 1 }],
        "uses[0].captureId": "{ghost}",
        "uses[0].entryId": { $gen: "entryId" },
      }),
      "unknown",
      "commitRestore naming an absent capture",
    ),
    expectRejected("commitRestore", from("{valid}", { "uses[0].entryId": { $gen: "entryId" } }), "unknown", "commitRestore naming an absent entry"),
    expectRejected(
      "commitRestore",
      from("{valid}", { captures: [{ captureId: "{two.captureId}", generation: 1 }], "uses[0].captureId": "{two.captureId}" }),
      "unknown",
      "commitRestore stating an entry under a capture it does not belong to",
    ),
    same("before", ["one", "two"], "no rejected commit changed anything"),
  ]);

  addCase("rejects stale for a different lifecycleRevision, ciphertextRevision, or generation", [
    serving(),
    create("h", { maxUses: 5 }),
    snapshot("before", ["h"]),
    buildCommit("valid", ["h"]),
    expectRejected(
      "commitRestore",
      from("{valid}", { "uses[0].lifecycleRevision": add(src("uses[0].lifecycleRevision"), 1) }),
      "stale",
      "commitRestore with a higher lifecycleRevision",
    ),
    expectRejected(
      "commitRestore",
      from("{valid}", { "uses[0].ciphertextRevision": add(src("uses[0].ciphertextRevision"), 1) }),
      "stale",
      "commitRestore with a higher ciphertextRevision",
    ),
    expectRejected(
      "commitRestore",
      from("{valid}", { "captures[0].generation": add(src("captures[0].generation"), 1) }),
      "stale",
      "commitRestore with a higher generation",
    ),
    same("before", ["h"], "no stale commit changed anything"),
    ok("valid"),
    expectRejected(
      "commitRestore",
      from("{valid}", { "attempt.attemptId": { $gen: "attemptId" } }),
      "stale",
      "commitRestore with the lifecycleRevision of an earlier read",
    ),
    entry("e", "h"),
    eq("{e.used}", 1, "the stale commit consumed nothing"),
  ]);

  addCase("accepts a budget exactly at maxUses and rejects one over", [
    serving(),
    create("h", { entries: 2, maxUses: 3 }),
    buildCommit("k1", [{ capture: "h", entry: 0, count: 4 }]),
    expectRejected("commitRestore", "{k1}", "budget", "a use of maxUses + 1 on an unused entry"),
    entry("e0", "h", 0),
    eq("{e0.used}", 0, "a budget rejection consumes nothing"),
    buildCommit("k2", [{ capture: "h", entry: 0, count: 3 }]),
    ok("k2"),
    entry("e0b", "h", 0),
    eq("{e0b.used}", 3, "a use of exactly maxUses commits"),
    buildCommit("k3", [{ capture: "h", entry: 0 }]),
    expectRejected("commitRestore", "{k3}", "budget", "one more use of an exhausted entry"),
    buildCommit("k4", [{ capture: "h", entry: 1, count: 2 }]),
    ok("k4"),
    buildCommit("k5", [{ capture: "h", entry: 1, count: 2 }]),
    expectRejected("commitRestore", "{k5}", "budget", "a use that would take used one over maxUses"),
    buildCommit("k6", [{ capture: "h", entry: 1, count: 1 }]),
    ok("k6"),
    entry("e1", "h", 1),
    eq("{e1.used}", 3, "used never exceeds maxUses"),
    eq("{e1.lifecycleRevision}", 3, "only committed uses bump lifecycleRevision"),
  ]);

  addCase("rejects expired for a capture already expired on the store's clock", [
    serving(),
    createExpired("h", { maxUses: 2 }),
    buildCommit("k", ["h"]),
    expectRejected("commitRestore", "{k}", "expired", "commitRestore of an expired capture"),
    entry("e", "h"),
    eq("{e.used}", 0, "an expired commit consumes nothing"),
  ]);

  addCase(
    "judges expiry on the store's clock: live one millisecond before expiresAt, expired exactly at it",
    [
      serving(),
      create("h", { maxUses: 3, lifetimeMs: HOUR }),
      { let: { expiresAt: "{h.expiresAt}" } },
      { setClock: { $sub: ["{expiresAt}", 1] } },
      buildCommit("k1", ["h"]),
      ok("k1"),
      { setClock: "{expiresAt}" },
      buildCommit("k2", ["h"]),
      expectRejected(
        "commitRestore",
        from("{k2}", { now: { $sub: ["{expiresAt}", 1] } }),
        "expired",
        "commitRestore with the store clock at expiresAt and the caller's now before it",
      ),
      entry("e", "h"),
      eq("{e.used}", 1, "the expired commit consumed nothing"),
      { setClock: { $sub: ["{expiresAt}", 1] } },
      buildCommit("k3", ["h"]),
      expectOutcome(
        "commitRestore",
        from("{k3}", { now: add("{expiresAt}", 1) }),
        "committed",
        "commitRestore with the store clock before expiresAt and the caller's now past it",
      ),
    ],
    { requires: { testClock: true } },
  );

  addCase("rejects clock-skew when the caller's now is outside the bound, and applies nothing", [
    serving(),
    create("h", { maxUses: 5 }),
    ...[1, -1].flatMap((sign, index) => [
      buildCommit(`k${index}`, ["h"]),
      expectRejected(
        "commitRestore",
        from(`{k${index}}`, { now: add(src("now"), { $mul: [sign, FARSKEW] }) }),
        "clock-skew",
        "commitRestore with a now outside the skew bound",
      ),
      inspect(`{k${index}.scope}`, `{k${index}.attempt.attemptId}`, { state: "absent" }, "a skewed commit writes no receipt"),
    ]),
    entry("e", "h"),
    eq("{e.used}", 0, "a skewed commit consumes nothing"),
  ]);

  addCase("is all-or-nothing: a batch whose last use fails leaves the earlier entries untouched", [
    serving(),
    create("one", { entries: 2, maxUses: 5 }),
    create("two", { entries: 1, maxUses: 1 }),
    snapshot("before", ["one", "two"]),
    buildCommit("over", [{ capture: "one", entry: 0 }, { capture: "one", entry: 1, count: 2 }, { capture: "two", count: 2 }]),
    expectRejected("commitRestore", "{over}", "budget", "a batch whose last use is over budget"),
    same("before", ["one", "two"], "used and revisions of the earlier entries are unchanged"),
    inspect("{over.scope}", "{over.attempt.attemptId}", { state: "absent" }, "a rejected batch writes no receipt"),
    buildCommit("stale", [{ capture: "one", entry: 0 }, { capture: "one", entry: 1 }, "two"]),
    expectRejected(
      "commitRestore",
      from("{stale}", { "uses[2].lifecycleRevision": add(src("uses[2].lifecycleRevision"), 1) }),
      "stale",
      "a batch whose last use is stale",
    ),
    same("before", ["one", "two"], "used and revisions are unchanged after the stale batch"),
    buildCommit("unknown", [{ capture: "one", entry: 0 }, "two"]),
    expectRejected("commitRestore", from("{unknown}", { "uses[1].entryId": { $gen: "entryId" } }), "unknown", "a batch whose last use names an absent entry"),
    same("before", ["one", "two"], "used and revisions are unchanged after the unknown batch"),
  ]);

  addCase("is all-or-nothing across captures: a revoked last capture leaves the first capture's entries untouched", [
    serving(),
    create("one", { maxUses: 5 }),
    create("two", { maxUses: 5 }),
    buildCommit("k", ["one", "two"]),
    revokeOk("two"),
    snapshot("before", ["one", "two"]),
    expectRejected("commitRestore", "{k}", ["revoked", "stale"], "a batch naming a capture revoked after the read"),
    same("before", ["one", "two"], "nothing was applied"),
  ]);

  addCase("answers already-committed for the same attempt and digest, and changes nothing", [
    serving(),
    create("h", { maxUses: 5 }),
    buildCommit("k", ["h"]),
    ok("k"),
    snapshot("before", ["h"]),
    expectOutcome("commitRestore", "{k}", "already-committed", "the same attempt and digest, replayed"),
    buildCommit("fresh", ["h"]),
    expectOutcome(
      "commitRestore",
      from("{fresh}", { "attempt.attemptId": "{k.attempt.attemptId}", "attempt.requestDigest": "{k.attempt.requestDigest}" }),
      "already-committed",
      "the same attempt and digest with fresh revisions",
    ),
    same("before", ["h"], "a replayed attempt consumes nothing"),
    entry("e", "h"),
    eq("{e.used}", 1, "used was incremented once"),
  ]);

  addCase("answers attempt-mismatch for the same attempt with another digest, and changes nothing", [
    serving(),
    create("h", { maxUses: 5 }),
    buildCommit("k", ["h"]),
    ok("k"),
    snapshot("before", ["h"]),
    buildCommit("other", ["h"]),
    expectOutcome(
      "commitRestore",
      from("{other}", { "attempt.attemptId": "{k.attempt.attemptId}" }),
      "attempt-mismatch",
      "the same attempt identifier with a different digest",
    ),
    same("before", ["h"], "a mismatched attempt consumes nothing"),
    inspect(
      "{k.scope}",
      "{k.attempt.attemptId}",
      { state: "committed", requestDigest: "{k.attempt.requestDigest}" },
      "the receipt keeps the digest of the attempt that committed",
    ),
  ]);

  addCase("evaluates quarantine first, then the receipt, then everything else", [
    serving(),
    create("h", { maxUses: 5 }),
    buildCommit("k", ["h"]),
    ok("k"),
    expectOutcome(
      "commitRestore",
      from("{k}", { now: add(src("now"), FARSKEW) }),
      "already-committed",
      "a replay with a skewed now: the receipt is checked before the clock",
    ),
    revokeOk("h"),
    expectOutcome("commitRestore", "{k}", "already-committed", "a replay after revocation: the receipt is checked before the capture"),
    { let: { mismatch: from("{k}", { "attempt.requestDigest": { $gen: "digest" } }) } },
    expectOutcome("commitRestore", "{mismatch}", "attempt-mismatch", "a mismatched replay after revocation"),
    { op: "quarantine", input: { namespace: "{NS}" } },
    expectRejected("commitRestore", "{k}", "quarantined", "a replay in a quarantined namespace: quarantine is checked before the receipt"),
    expectRejected("commitRestore", "{mismatch}", "quarantined", "a mismatched replay in a quarantined namespace"),
  ]);

  addCase("throws STORE_INVALID_ARGUMENT for a receipt that would expire before the latest capture, and applies nothing", [
    serving(),
    create("one", { maxUses: 5, lifetimeMs: HOUR }),
    create("two", { maxUses: 5, lifetimeMs: 2 * HOUR }),
    snapshot("before", ["one", "two"]),
    buildCommit("k", ["one", "two"]),
    expectThrows(
      "commitRestore",
      from("{k}", { receiptExpiresAt: { $sub: ["{two.expiresAt}", 1] } }),
      "STORE_INVALID_ARGUMENT",
      "commitRestore with receiptExpiresAt before the latest expiresAt",
    ),
    same("before", ["one", "two"], "nothing was applied"),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "absent" }, "no receipt was written"),
    expectOutcome(
      "commitRestore",
      from("{k}", { receiptExpiresAt: "{two.expiresAt}" }),
      "committed",
      "commitRestore with receiptExpiresAt equal to the latest expiresAt",
    ),
  ]);

  addCase("an attempt identifier is unique per tenant, not across tenants", [
    serving(),
    create("mine", { maxUses: 2 }),
    create("theirs", { scope: "{SCOPE_B}", maxUses: 2 }),
    buildCommit("first", ["mine"]),
    ok("first"),
    buildCommit("second", ["theirs"], { scope: "{SCOPE_B}" }),
    expectOutcome(
      "commitRestore",
      from("{second}", { "attempt.attemptId": "{first.attempt.attemptId}" }),
      "committed",
      "the same attempt identifier in another tenant",
    ),
    inspect(
      "{SCOPE_A}",
      "{first.attempt.attemptId}",
      { state: "committed", requestDigest: "{first.attempt.requestDigest}" },
      "the first tenant's receipt keeps its digest",
    ),
    inspect(
      "{SCOPE_B}",
      "{first.attempt.attemptId}",
      { state: "committed", requestDigest: "{second.attempt.requestDigest}" },
      "the second tenant's receipt keeps its digest",
    ),
  ]);

  addCase("rejects revoked after a revocation, with the generation read before or after it", [
    serving(),
    create("h", { maxUses: 5 }),
    buildCommit("early", ["h"]),
    revokeOk("h"),
    expectRejected("commitRestore", "{early}", ["revoked", "stale"], "commitRestore with the generation read before the revocation"),
    buildCommit("late", ["h"]),
    eq("{late.captures[0].generation}", 2, "the read after revocation shows the new generation"),
    expectRejected("commitRestore", "{late}", "revoked", "commitRestore with the generation read after the revocation"),
    entry("e", "h"),
    eq("{e.used}", 0, "a revoked capture's budget is never consumed"),
  ]);

  addCase("cannot reach another tenant's or another namespace's rows", [
    serving(),
    serving(1, "{NS2}"),
    create("h", { maxUses: 5 }),
    buildCommit("valid", ["h"]),
    expectRejected(
      "commitRestore",
      from("{valid}", { scope: "{SCOPE_B}", "attempt.attemptId": { $gen: "attemptId" } }),
      "unknown",
      "commitRestore naming another scope's identifiers",
    ),
    expectRejected(
      "commitRestore",
      from("{valid}", { scope: "{SCOPE_A2}", "attempt.attemptId": { $gen: "attemptId" } }),
      "unknown",
      "commitRestore naming another scope's identifiers",
    ),
    entry("e", "h"),
    eq("{e.used}", 0, "the owner's entry is untouched"),
  ]);

  addCase("rejects quarantined for an uninitialized namespace and for an epoch that differs", [
    { let: { ghost: { $gen: "captureId" } } },
    expectRejected(
      "commitRestore",
      {
        scope: "{SCOPE_A}",
        epoch: 1,
        now: { $now: 0 },
        attempt: { attemptId: { $gen: "attemptId" }, requestDigest: { $gen: "digest" } },
        receiptExpiresAt: add({ $now: 0 }, HOUR),
        captures: [{ captureId: "{ghost}", generation: 1 }],
        uses: [{ entryId: { $gen: "entryId" }, captureId: "{ghost}", count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }],
      },
      "quarantined",
      "commitRestore in a namespace with no recovery record",
    ),
    serving(2),
    create("h", { epoch: 2, maxUses: 5 }),
    ...[1, 3].flatMap((epoch) => [
      buildCommit(`k${epoch}`, ["h"]),
      expectRejected("commitRestore", from(`{k${epoch}}`, { epoch }), "quarantined", "commitRestore with an epoch that differs from the stored one"),
    ]),
    entry("e", "h"),
    eq("{e.used}", 0, "nothing was consumed"),
  ]);
}

// ---------------------------------------------------------------------- revoke
{
  const addCase = adder("revoke", cases);

  addCase("revokes a live capture, increments its generation, and reports its entry count", [
    serving(),
    create("h", { entries: 3 }),
    expectOutcome("revokeCapture", revokeIn("h"), "revoked", "revokeCapture of a live capture", { save: "r" }),
    eq("{r.entries}", 3, "entries is the number of entry rows"),
    captureRow("cr", "h"),
    eq("{cr.state}", "revoked", "state after revocation"),
    eq("{cr.generation}", 2, "generation after revocation"),
    eq("{cr.keyRevision}", 1, "revocation does not change keyRevision"),
  ]);

  addCase("answers already-revoked the second time and does not increment the generation again", [
    serving(),
    create("h", { entries: 2 }),
    revokeOk("h"),
    expectOutcome("revokeCapture", revokeIn("h", { fence: true }), "already-revoked", "revokeCapture of a revoked capture", { save: "again" }),
    eq("{again.entries}", 2, "entries of an already revoked capture"),
    captureRow("cr", "h"),
    eq("{cr.generation}", 2, "generation is incremented once"),
  ]);

  addCase("answers not-found for an absent capture and writes nothing", [
    serving(),
    buildCapture("c"),
    expectOutcome(
      "revokeCapture",
      revokeIn("c"),
      "not-found",
      "revokeCapture of an absent capture without fenceAbsent",
    ),
    ...expectAbsent("c", "revokeCapture without fenceAbsent"),
    expectOutcome("createCapture", "{c.input}", "created", "createCapture after a not-found revocation"),
  ]);

  addCase("writes a fence for an absent capture when fenceAbsent is set, and the fence blocks creation", [
    serving(),
    buildCapture("c"),
    expectOutcome("revokeCapture", revokeIn("c", { fence: true }), "fenced", "revokeCapture of an absent capture with fenceAbsent"),
    expectRejected("createCapture", "{c.input}", "fenced", "createCapture of a fenced identifier"),
    readCaptures("{c.scope}", ["{c.captureId}"], { save: "rows", expect: { $length: 1 }, what: "readCaptures returns the fence row" }),
    eq("{rows[0].state}", "revoked", "a fence is revoked"),
    eq("{rows[0].keyRef}", "", "a fence has an empty keyRef"),
    eq("{rows[0].wrappedKey}", "", "a fence has an empty wrappedKey"),
    eq("{rows[0].createdAt}", "{rows[0].expiresAt}", "a fence's createdAt and expiresAt are the same store clock reading"),
    { ...eq("{rows[0].createdAt}", { $now: 0 }, "a fence's times are the store's clock"), when: { testClock: true } },
    readEntries("{c.scope}", "{c.entryIds}", { expect: { entries: { $length: 0 } }, what: "no entry of the fenced capture exists" }),
    expectOutcome("revokeCapture", revokeIn("c", { fence: true }), "already-revoked", "revokeCapture of a fence", { save: "again" }),
    eq("{again.entries}", 0, "a fence has no entries"),
  ]);

  addCase("a fence is scoped to its tenant", [
    serving(),
    buildCapture("c"),
    expectOutcome(
      "revokeCapture",
      { scope: "{SCOPE_B}", captureId: "{c.captureId}", now: { $now: 0 }, retentionMs: DAY, fenceAbsent: true },
      "fenced",
      "fencing an identifier in another tenant",
    ),
    expectOutcome("createCapture", "{c.input}", "created", "createCapture of the same identifier in this tenant"),
  ]);

  addCase("works in a quarantined namespace", [
    serving(),
    create("h"),
    { op: "quarantine", input: { namespace: "{NS}" } },
    expectOutcome("revokeCapture", revokeIn("h"), "revoked", "revokeCapture in a quarantined namespace"),
    captureRow("cr", "h"),
    eq("{cr.state}", "revoked", "state after revocation under quarantine"),
    expectOutcome(
      "revokeCapture",
      { scope: "{SCOPE_A}", captureId: { $gen: "captureId" }, now: { $now: 0 }, retentionMs: DAY, fenceAbsent: true },
      "fenced",
      "fencing in a quarantined namespace",
    ),
  ]);

  addCase("cannot revoke another tenant's capture", [
    serving(),
    create("h"),
    expectOutcome(
      "revokeCapture",
      { scope: "{SCOPE_B}", captureId: "{h.captureId}", now: { $now: 0 }, retentionMs: DAY, fenceAbsent: false },
      "not-found",
      "revokeCapture from another tenant",
    ),
    captureRow("cr", "h"),
    eq("{cr.state}", "live", "the owner's capture stays live"),
    eq("{cr.generation}", 1, "the owner's capture keeps its generation"),
  ]);

  addCase("does not depend on the caller's clock", [
    serving(),
    create("h"),
    expectOutcome("revokeCapture", from(revokeIn("h"), { now: add({ $now: 0 }, FARSKEW) }), "revoked", "revokeCapture with a now outside the skew bound"),
  ]);
}

// --------------------------------------------------------------------- inspect
{
  const addCase = adder("inspect", cases);

  addCase("reports absent before a commit and committed with the digest after it", [
    serving(),
    create("h", { maxUses: 2 }),
    buildCommit("k", ["h"]),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "absent" }, "inspectAttempt before the commit"),
    { let: { before: { $now: 0 } } },
    commitOk("k"),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "committed", requestDigest: "{k.attempt.requestDigest}" }, "inspectAttempt after the commit", {
      save: "receipt",
    }),
    { ...eq("{receipt.committedAt}", "{before}", "committedAt is the store's clock at the commit"), when: { testClock: true } },
    {
      ...check(
        { $lte: [{ $max: [{ $sub: ["{receipt.committedAt}", "{before}"] }, { $sub: ["{before}", "{receipt.committedAt}"] }] }, add("{SKEW}", "{FAR}")] },
        "committedAt is a store clock reading near the commit",
      ),
      when: { testClock: false },
    },
    inspect("{SCOPE_B}", "{k.attempt.attemptId}", { state: "absent" }, "another tenant does not see the receipt"),
  ]);

  addCase("reports absent for an attempt whose commit was rejected", [
    serving(),
    create("h", { maxUses: 1 }),
    buildCommit("k", [{ capture: "h", count: 2 }]),
    expectRejected("commitRestore", "{k}", "budget", "a use over budget"),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "absent" }, "a rejected attempt has no receipt"),
    buildCommit("retry", ["h"]),
    expectOutcome(
      "commitRestore",
      from("{retry}", { "attempt.attemptId": "{k.attempt.attemptId}", "attempt.requestDigest": "{k.attempt.requestDigest}" }),
      "committed",
      "the same attempt identifier can commit after its rejection",
    ),
  ]);
}

// product of rekey and delete are in the same file to keep the helper imports short
{
  const addCase = adder("rekey", cases);
  const newKey = (handle, keyRevision = 1) => ({
    scope: `{${handle}.scope}`,
    captureId: `{${handle}.captureId}`,
    keyRevision,
    keyRef: "synthetic-key:v2",
    wrappedKey: bytes(48),
  });

  addCase("replaces the stored key under the expected keyRevision and changes nothing else", [
    serving(),
    create("h", { entries: 2, maxUses: 4, sessionTag: hexOf("cd", 32) }),
    buildCommit("k", [{ capture: "h", count: 2 }]),
    commitOk("k"),
    captureRow("before", "h"),
    readEntries("{h.scope}", "{h.entryIds}", { save: "entriesBefore" }),
    { let: { key: newKey("h") } },
    expectOutcome("replaceCaptureKey", "{key}", "replaced", "replaceCaptureKey with the current keyRevision", { save: "res" }),
    eq("{res.keyRevision}", 2, "the new keyRevision is returned"),
    captureRow("after", "h"),
    eq("{after.keyRevision}", 2, "keyRevision after the replacement"),
    eq("{after.keyRef}", "{key.keyRef}", "keyRef after the replacement"),
    eq("{after.wrappedKey}", "{key.wrappedKey}", "wrappedKey after the replacement"),
    ...["state", "generation", "epoch", "sessionTag", "createdAt", "expiresAt"].map((field) =>
      eq(`{after.${field}}`, `{before.${field}}`, `replaceCaptureKey must not change the capture's ${field}`),
    ),
    readEntries("{h.scope}", "{h.entryIds}", { save: "entriesAfter", expect: { entries: { $length: 2 } }, what: "replaceCaptureKey must not remove an entry" }),
    ...[0, 1].flatMap((index) => [
      { let: { [`was${index}`]: findEntry("entriesBefore", `{h.entryIds[${index}]}`), [`now${index}`]: findEntry("entriesAfter", `{h.entryIds[${index}]}`) } },
      ...["used", "maxUses", "lifecycleRevision", "ciphertextRevision", "envelope"].map((field) =>
        eq(`{now${index}.${field}}`, `{was${index}.${field}}`, `replaceCaptureKey must not change an entry's ${field}`),
      ),
    ]),
  ]);

  addCase("rejects stale for another keyRevision", [
    serving(),
    create("h"),
    snapshot("before", ["h"]),
    expectRejected("replaceCaptureKey", newKey("h", 2), "stale", "replaceCaptureKey with a keyRevision that is not current"),
    same("before", ["h"], "nothing changed"),
    expectOutcome("replaceCaptureKey", newKey("h", 1), "replaced", "the first replacement"),
    expectRejected("replaceCaptureKey", newKey("h", 1), "stale", "a second replacement with the old keyRevision"),
  ]);

  addCase("rejects unknown for an absent capture and for another tenant's capture", [
    serving(),
    create("h"),
    expectRejected("replaceCaptureKey", from(newKey("h"), { captureId: { $gen: "captureId" } }), "unknown", "replaceCaptureKey of an absent capture"),
    expectRejected("replaceCaptureKey", from(newKey("h"), { scope: "{SCOPE_B}" }), "unknown", "replaceCaptureKey from another tenant"),
    captureRow("cr", "h"),
    eq("{cr.keyRevision}", 1, "the owner's key is unchanged"),
  ]);

  addCase("refuses a revoked capture, an expired one, and one whose ciphertext was deleted", [
    serving(),
    create("revoked"),
    revokeOk("revoked"),
    snapshot("before", ["revoked"]),
    expectRejected("replaceCaptureKey", newKey("revoked"), "revoked", "replaceCaptureKey of a revoked capture"),
    same("before", ["revoked"], "the revoked capture is unchanged"),
    expectOutcome("deleteCiphertext", deleteIn("revoked"), "deleted", "deleteCiphertext of the revoked capture"),
    captureRow("deleted", "revoked"),
    expectRejected("replaceCaptureKey", newKey("revoked", "{deleted.keyRevision}"), "revoked", "replaceCaptureKey of a capture whose ciphertext was deleted"),
    captureRow("deleted2", "revoked"),
    eq("{deleted2.keyRef}", "", "the deleted capture still holds no key"),
    createExpired("expired"),
    expectRejected("replaceCaptureKey", newKey("expired"), "expired", "replaceCaptureKey of an expired capture"),
    captureRow("expiredRow", "expired"),
    eq("{expiredRow.keyRevision}", 1, "the expired capture's key is unchanged"),
  ]);

  addCase("a restore prepared before the re-wrap still commits, and its use is kept", [
    serving(),
    create("h", { maxUses: 3 }),
    buildCommit("first", ["h"]),
    commitOk("first"),
    buildCommit("prepared", ["h"]),
    expectOutcome("replaceCaptureKey", newKey("h"), "replaced", "replaceCaptureKey between a restore's read and its commit"),
    entry("e1", "h"),
    eq("{e1.used}", 1, "replaceCaptureKey must not reset used"),
    commitOk("prepared"),
    entry("e2", "h"),
    eq("{e2.used}", 2, "the restore prepared before the re-wrap committed"),
  ]);
}

{
  const addCase = adder("delete", cases);

  addCase("refuses a live, unexpired capture and an absent one", [
    serving(),
    create("h", { entries: 2 }),
    snapshot("before", ["h"]),
    expectRejected("deleteCiphertext", deleteIn("h"), "live", "deleteCiphertext of a live, unexpired capture"),
    same("before", ["h"], "the live capture is unchanged"),
    expectRejected(
      "deleteCiphertext",
      { scope: "{h.scope}", captureId: { $gen: "captureId" }, now: { $now: 0 } },
      "not-found",
      "deleteCiphertext of an absent capture",
    ),
    expectRejected(
      "deleteCiphertext",
      { scope: "{SCOPE_B}", captureId: "{h.captureId}", now: { $now: 0 } },
      "not-found",
      "deleteCiphertext from another tenant",
    ),
    same("before", ["h"], "the live capture is still unchanged"),
  ]);

  addCase("deletes a revoked capture's ciphertext whatever the clocks say", [
    serving(),
    create("h", { entries: 3 }),
    revokeOk("h"),
    expectOutcome("deleteCiphertext", deleteIn("h", add({ $now: 0 }, FARSKEW)), "deleted", "deleteCiphertext of a revoked capture with a skewed now", {
      save: "res",
    }),
    eq("{res.entries}", 3, "entries is the number of rows removed"),
    readEntries("{h.scope}", "{h.entryIds}", { expect: { entries: { $length: 0 } }, what: "the entry rows are gone" }),
    captureRow("t", "h"),
    eq("{t.state}", "revoked", "the row stays as a revoked tombstone"),
    eq("{t.keyRef}", "", "the stored keyRef is emptied"),
    eq("{t.wrappedKey}", "", "the stored wrappedKey is emptied"),
    eq("{t.keyRevision}", 2, "keyRevision is incremented"),
  ]);

  addCase("deletes an expired capture's ciphertext and marks the capture revoked", [
    serving(),
    createExpired("h", { entries: 2 }),
    expectOutcome("deleteCiphertext", deleteIn("h"), "deleted", "deleteCiphertext of an expired capture", { save: "res" }),
    eq("{res.entries}", 2, "entries is the number of rows removed"),
    captureRow("t", "h"),
    eq("{t.state}", "revoked", "an expired capture is marked revoked by the deletion"),
    eq("{t.keyRevision}", 2, "keyRevision is incremented"),
    eq("{t.keyRef}", "", "the stored key is emptied"),
  ]);

  addCase("rejects clock-skew when the decision rests on expiry and the clocks disagree", [
    serving(),
    createExpired("h", { entries: 2 }),
    snapshot("before", ["h"]),
    ...[1, -1].map((sign) =>
      expectRejected(
        "deleteCiphertext",
        deleteIn("h", add({ $now: 0 }, { $mul: [sign, FARSKEW] })),
        "clock-skew",
        "deleteCiphertext of an expired capture with a skewed now",
      ),
    ),
    same("before", ["h"], "nothing was deleted"),
  ]);

  addCase("the tombstone remains, still fences creation, and its entries can no longer be committed", [
    serving(),
    create("h", { maxUses: 5 }),
    buildCommit("prepared", ["h"]),
    revokeOk("h"),
    expectOutcome("deleteCiphertext", deleteIn("h"), "deleted", "deleteCiphertext of a revoked capture"),
    buildCapture("again", { captureId: "{h.captureId}" }),
    expectRejected("createCapture", "{again.input}", "fenced", "createCapture of a deleted capture's identifier"),
    expectRejected("commitRestore", "{prepared}", ["revoked", "stale", "unknown"], "commitRestore after the ciphertext was deleted"),
    expectOutcome("deleteCiphertext", deleteIn("h"), "deleted", "deleteCiphertext a second time", { save: "second" }),
    eq("{second.entries}", 0, "the second deletion removes nothing"),
  ]);
}
