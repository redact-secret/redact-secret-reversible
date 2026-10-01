// Fault cases for the store level. They have no counterpart in the native harness
// (`native` is absent): they exercise the fault vocabulary of README.md, which
// every driver implements in its test build and no production API exposes.
import {
  adder,
  buildCapture,
  buildCommit,
  captureRow,
  commitOk,
  create,
  entry,
  eq,
  expectAbsent,
  expectOutcome,
  expectRejected,
  expectThrows,
  inspect,
  revokeIn,
  serving,
  snapshot,
  same,
} from "./helpers.mjs";

export const cases = [];

const addCase = adder("fault", cases);
const options = (...faults) => ({ native: null, requires: { faults } });

addCase(
  "an unavailable store applies nothing, and the same restore then commits",
  [
    serving(),
    create("h", { maxUses: 2 }),
    buildCommit("k", ["h"]),
    snapshot("before", ["h"]),
    expectThrows("commitRestore", "{k}", "STORE_UNAVAILABLE", "commitRestore against an unavailable store", { fault: "unavailable" }),
    same("before", ["h"], "an unavailable store changed nothing"),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "absent" }, "no receipt was written"),
    commitOk("k"),
    entry("e", "h"),
    eq("{e.used}", 1, "the retried restore consumed one use"),
  ],
  options("unavailable"),
);

addCase(
  "a failure before the first write applies nothing",
  [
    serving(),
    buildCapture("c", { entries: 2 }),
    expectThrows("createCapture", "{c.input}", "STORE_UNAVAILABLE", "createCapture that fails before its first write", { fault: "before-first-write" }),
    ...expectAbsent("c", "createCapture that fails before its first write"),
    expectOutcome("createCapture", "{c.input}", "created", "the same creation, retried"),
  ],
  options("before-first-write"),
);

addCase(
  "a commit whose acknowledgement is lost is ambiguous, and inspectAttempt resolves it as committed",
  [
    serving(),
    create("h", { maxUses: 1 }),
    buildCommit("k", ["h"]),
    expectThrows("commitRestore", "{k}", "STORE_AMBIGUOUS", "commitRestore whose acknowledgement is lost", { fault: "after-commit-before-ack" }),
    inspect("{k.scope}", "{k.attempt.attemptId}", { state: "committed", requestDigest: "{k.attempt.requestDigest}" }, "the commit is durable and its receipt resolves the attempt"),
    expectOutcome("commitRestore", "{k}", "already-committed", "the same attempt, replayed"),
    entry("e", "h"),
    eq("{e.used}", 1, "the lost-acknowledgement commit consumed exactly one use"),
    buildCommit("again", ["h"]),
    expectRejected("commitRestore", "{again}", "budget", "a new attempt for a single-use entry that already committed"),
  ],
  options("after-commit-before-ack"),
);

addCase(
  "a creation whose acknowledgement is lost leaves a capture that a fence revokes",
  [
    serving(),
    buildCapture("c", { entries: 2 }),
    expectThrows("createCapture", "{c.input}", "STORE_AMBIGUOUS", "createCapture whose acknowledgement is lost", { fault: "after-commit-before-ack" }),
    expectOutcome("revokeCapture", revokeIn("c", { fence: true }), "revoked", "the compensating revoke of an ambiguous creation"),
    buildCapture("again", { captureId: "{c.captureId}" }),
    expectRejected("createCapture", "{again.input}", "fenced", "createCapture of the revoked identifier"),
  ],
  options("after-commit-before-ack"),
);

addCase(
  "a dropped connection is ambiguous, and the receipt and the counters agree afterwards",
  [
    serving(),
    create("h", { maxUses: 2 }),
    buildCommit("k", ["h"]),
    expectThrows("commitRestore", "{k}", "STORE_AMBIGUOUS", "commitRestore on a dropped connection", { fault: "drop-connection" }),
    { op: "inspectAttempt", input: { scope: "{k.scope}", attemptId: "{k.attempt.attemptId}" }, save: "rc", what: "inspectAttempt after a dropped connection" },
    entry("e", "h"),
    eq("{e.used}", { $if: [{ $eq: ["{rc.state}", "committed"] }, 1, 0] }, "the receipt and the counter agree"),
  ],
  options("drop-connection"),
);

addCase(
  "an unavailable store does not revoke, and the revoke then succeeds",
  [
    serving(),
    create("h"),
    expectThrows("revokeCapture", revokeIn("h"), "STORE_UNAVAILABLE", "revokeCapture against an unavailable store", { fault: "unavailable" }),
    captureRow("cr", "h"),
    eq("{cr.state}", "live", "the capture is still live"),
    expectOutcome("revokeCapture", revokeIn("h"), "revoked", "revokeCapture, retried"),
  ],
  options("unavailable"),
);

addCase(
  "a revoke whose acknowledgement is lost has revoked, and a second revoke reports it",
  [
    serving(),
    create("h"),
    expectThrows("revokeCapture", revokeIn("h"), "STORE_AMBIGUOUS", "revokeCapture whose acknowledgement is lost", { fault: "after-commit-before-ack" }),
    captureRow("cr", "h"),
    eq("{cr.state}", "revoked", "the revocation is durable"),
    expectOutcome("revokeCapture", revokeIn("h"), "already-revoked", "revokeCapture, repeated"),
  ],
  options("after-commit-before-ack"),
);
