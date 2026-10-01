// Server-level cases (`level: "server"`): the persistent server profile
// (docs/specs/persistent-vault.md §7 and §8) driven through a driver that holds
// a server over a store, a record-crypto layer, fixed synthetic resolvers, and
// allow-all policies. Every value is synthetic. The expectations are those of the
// JavaScript profile (packages/vault-server/src/persistent), the semantic
// reference; no native harness case corresponds, so `native` is absent.
import { adder, check, eq } from "./helpers.mjs";

export const cases = [];

const addCase = adder("server", cases);
const OPTIONS = { native: null, level: "server" };

const TEXT = "secret {SECRET_A} here";

const capture = (as, { ctx = "a1", ...options } = {}) => ({
  op: "capture",
  input: { context: `{CTX.${ctx}}`, text: TEXT, release: [{ sink: "{SINK}", paths: ["body"] }], ...options },
  expect: { tokens: { $length: 1 } },
  save: as,
  what: "capture",
});

const restoreIn = (as, { ctx = "a1", fields, ...extra } = {}) => ({
  context: `{CTX.${ctx}}`,
  sink: "{SINK}",
  purpose: "{PURPOSE}",
  captures: [`{${as}.captureId}`],
  fields: fields ?? { body: `{${as}.text}` },
  ...extra,
});

const restore = (as, { ctx = "a1", fields, ...extra } = {}, step = {}) => ({
  op: "restore",
  input: restoreIn(as, { ctx, fields, ...extra }),
  ...step,
});

const restored = (principal = "principal-a1") => ({
  fields: { body: TEXT },
  restored: 1,
  principalId: principal,
  tenant: "{TENANT_A}",
});

const denied = (reason, what) => ({ expectError: "RESTORE_DENIED", expectReason: reason, what });

addCase(
  "capture hides the value, and restore puts it back into the granted field",
  [
    capture("c"),
    check({ $not: { $contains: ["{c.text}", "{SECRET_A}"] } }, "the captured text must not contain the value"),
    eq("{c.tenant}", "{TENANT_A}", "the capture belongs to the principal's tenant"),
    eq("{c.sessionBound}", false, "a context with no session is not session-bound"),
    restore("c", {}, { expect: restored(), what: "restore into the granted field" }),
  ],
  OPTIONS,
);

addCase(
  "a capture that finds nothing retains nothing",
  [
    {
      op: "capture",
      input: { context: "{CTX.a1}", text: "nothing to hide here", release: [{ sink: "{SINK}", paths: ["body"] }] },
      expect: { tokens: { $length: 0 }, text: "nothing to hide here", passedThrough: 0, unrestorable: 0 },
      what: "capture of a text with no finding",
    },
  ],
  OPTIONS,
);

addCase(
  "a token budget of one allows one restore, and a second is denied for budget",
  [
    capture("c"),
    restore("c", {}, { expect: restored(), what: "the first restore" }),
    restore("c", {}, denied("budget", "the second restore of a single-use token")),
  ],
  OPTIONS,
);

addCase(
  "maxUses counts occurrences across restores",
  [
    capture("c", { maxUses: 2 }),
    restore("c", {}, { expect: restored(), what: "the first restore" }),
    restore("c", {}, { expect: restored(), what: "the second restore" }),
    restore("c", {}, denied("budget", "the third restore")),
  ],
  OPTIONS,
);

addCase(
  "a sink or path that was not granted is denied",
  [
    capture("c", { maxUses: 3 }),
    restore("c", {}, { ...denied("sink-or-path", "a restore into another sink"), input: { ...restoreIn("c"), sink: "sink-not-granted" } }),
    restore("c", { fields: { subject: "{c.text}" } }, denied("sink-or-path", "a restore into a path that was not granted")),
    restore("c", {}, { expect: restored(), what: "the granted sink and path still restore" }),
  ],
  OPTIONS,
);

addCase(
  "a forged or unknown token is denied, and so is a principal that cannot be resolved",
  [
    capture("c"),
    restore("c", { fields: { body: "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>" } }, denied("unknown-token", "a forged token")),
    restore("c", { ctx: "nobody" }, denied("unauthenticated", "a principal the resolver cannot resolve")),
    restore("c", {}, { expect: restored(), what: "the real token still restores: nothing was consumed" }),
  ],
  OPTIONS,
);

addCase(
  "another tenant cannot restore, and another principal of the same tenant can",
  [
    capture("c"),
    restore("c", { ctx: "b1" }, denied("unknown-token", "a principal of another tenant")),
    restore("c", { ctx: "a2" }, { expect: restored("principal-a2"), what: "another principal of the capture's tenant" }),
  ],
  OPTIONS,
);

addCase(
  "a session-bound capture restores only under its own session",
  [
    capture("c", { ctx: "a1s1" }),
    eq("{c.sessionBound}", true, "a capture made under a session is session-bound"),
    restore("c", { ctx: "a1s2" }, denied("source", "another session")),
    restore("c", { ctx: "a1" }, denied("source", "no session")),
    restore("c", { ctx: "a1s1" }, { expect: restored(), what: "the capture's own session" }),
  ],
  OPTIONS,
);

addCase(
  "revoke denies later restores, repeats as already-revoked, and is scoped to the tenant",
  [
    capture("c"),
    { op: "revoke", input: { context: "{CTX.b1}", captureId: "{c.captureId}" }, expect: { outcome: "not-found" }, what: "revoke from another tenant" },
    { op: "revoke", input: { context: "{CTX.a1}", captureId: "{c.captureId}" }, expect: { outcome: "revoked", entries: 1 }, what: "revoke" },
    restore("c", {}, denied("revoked", "a restore after revocation")),
    { op: "revoke", input: { context: "{CTX.a1}", captureId: "{c.captureId}" }, expect: { outcome: "already-revoked" }, what: "revoke, repeated" },
  ],
  OPTIONS,
);

addCase(
  "deleting the ciphertext keeps restores denied and reports no key retirement",
  [
    capture("c"),
    {
      op: "deleteCaptureCiphertext",
      input: { context: "{CTX.a1}", captureId: "{c.captureId}" },
      expect: { outcome: "deleted", entries: 1, keyRetired: false },
      what: "deleteCaptureCiphertext",
    },
    restore("c", {}, { expectError: "RESTORE_DENIED", what: "a restore after the ciphertext was deleted" }),
    {
      op: "deleteCaptureCiphertext",
      input: { context: "{CTX.a1}", captureId: "{c.captureId}" },
      expect: { outcome: "deleted", entries: 0 },
      what: "deleteCaptureCiphertext, repeated",
    },
  ],
  OPTIONS,
);

addCase(
  "an expired capture is denied",
  [capture("c"), { setClock: "{c.expiresAt}" }, restore("c", {}, denied("expired", "a restore at the capture's expiry"))],
  OPTIONS,
);

addCase(
  "an attempt that committed is never answered twice, and resolveAttempt reports it without fields",
  [
    capture("c", { maxUses: 3 }),
    restore("c", { attemptId: "attempt-synthetic-one" }, { expect: { ...restored(), attemptId: "attempt-synthetic-one" }, what: "the first attempt" }),
    restore("c", { attemptId: "attempt-synthetic-one" }, denied("attempt-already-committed", "the same attempt and request, again")),
    restore("c", { attemptId: "attempt-synthetic-one", purpose: "purpose-synthetic-other" }, denied("attempt-mismatch", "the same attempt for a different request")),
    {
      op: "resolveAttempt",
      input: restoreIn("c", { attemptId: "attempt-synthetic-one" }),
      expect: { state: "committed" },
      what: "resolveAttempt of the committed attempt",
    },
    {
      op: "resolveAttempt",
      input: restoreIn("c", { attemptId: "attempt-synthetic-one", purpose: "purpose-synthetic-other" }),
      expect: { state: "attempt-mismatch" },
      what: "resolveAttempt with a different request",
    },
    {
      op: "resolveAttempt",
      input: restoreIn("c", { attemptId: "attempt-synthetic-two" }),
      expect: { state: "absent" },
      what: "resolveAttempt of an attempt that never committed",
    },
  ],
  OPTIONS,
);

addCase(
  "a commit whose acknowledgement is lost releases nothing, and resolveAttempt finds it committed",
  [
    capture("c"),
    {
      ...restore("c", { attemptId: "attempt-synthetic-lost" }, { expectError: "COMMIT_AMBIGUOUS", what: "a restore whose acknowledgement is lost" }),
      fault: { operation: "commitRestore", kind: "after-commit-before-ack" },
      save: "failure",
    },
    eq("{failure.attemptId}", "attempt-synthetic-lost", "the error carries the attempt identifier, and no field"),
    {
      op: "resolveAttempt",
      input: restoreIn("c", { attemptId: "attempt-synthetic-lost" }),
      expect: { state: "committed" },
      what: "resolveAttempt after the lost acknowledgement",
    },
    restore("c", {}, denied("budget", "a new attempt for the single-use token that committed")),
  ],
  { ...OPTIONS, requires: { faults: ["after-commit-before-ack"] } },
);

addCase(
  "an unavailable store releases nothing and consumes nothing, and the restore then succeeds",
  [
    capture("c"),
    { ...restore("c", {}, { expectError: "STORE_UNAVAILABLE", what: "a restore against an unavailable store" }), fault: { operation: "commitRestore", kind: "unavailable" } },
    restore("c", {}, { expect: restored(), what: "the retried restore" }),
  ],
  { ...OPTIONS, requires: { faults: ["unavailable"] } },
);

addCase(
  "a capture the store cannot create fails and stores nothing",
  [
    {
      op: "capture",
      input: { context: "{CTX.a1}", text: TEXT, release: [{ sink: "{SINK}", paths: ["body"] }] },
      fault: { operation: "createCapture", kind: "unavailable" },
      expectError: "STORE_UNAVAILABLE",
      what: "capture against an unavailable store",
    },
    capture("c"),
    restore("c", {}, { expect: restored(), what: "a later capture works" }),
  ],
  { ...OPTIONS, requires: { faults: ["unavailable"] } },
);
