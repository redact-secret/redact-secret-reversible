/**
 * Deterministic store cases: one per behavior stated in
 * docs/specs/persistent-vault.md §4.2 and §5. Each works in its own random
 * namespace and uses only the public `Store` interface.
 */
import { LIMITS, missingCapabilities } from "@redact-secret/vault-contracts";
import type { CommitRestoreInput, CreateCaptureInput, StoreScope } from "@redact-secret/vault-contracts";
import {
  altered,
  at,
  check,
  DAY_MS,
  equal,
  fail,
  HOUR_MS,
  outcome,
  rejected,
  sameBytes,
  throwsStoreError,
} from "./support.js";
import type { Bench, CaptureHandle, CaseBody, Draft } from "./support.js";
import { ConformanceSkip } from "./types.js";

export type Add = (group: string, name: string, body: CaseBody) => void;

export const FAR_MS = 60_000;

export async function expectAbsent(b: Bench, input: CreateCaptureInput, what: string): Promise<void> {
  const captures = await b.store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] });
  equal(captures.length, 0, `${what}: no capture row may exist`);
  const entries = await b.read(
    input.scope,
    input.entries.slice(0, b.caps.maxRestoreEntries).map((entry) => entry.entryId),
  );
  equal(entries.entries.length, 0, `${what}: no entry row may exist`);
}

export function revokeInput(b: Bench, handle: { scope: StoreScope; captureId: string }, fenceAbsent = false, retentionMs = DAY_MS) {
  return { scope: handle.scope, captureId: handle.captureId, now: b.now(), retentionMs, fenceAbsent };
}

export async function revoke(b: Bench, handle: CaptureHandle): Promise<void> {
  outcome(await b.store.revokeCapture(revokeInput(b, handle)), "revoked", "revokeCapture of a live capture");
}

export async function commit(b: Bench, input: CommitRestoreInput): Promise<void> {
  outcome(await b.store.commitRestore(input), "committed", "commitRestore of a valid restore");
}

export function addCapabilityCases(add: Add): void {
  add("capabilities", "declares every capability a persistent server requires, within the contract's limits", async (b) => {
    const missing = missingCapabilities(b.caps);
    equal(missing.length, 0, `missingCapabilities must be empty (first: ${missing[0] ?? "none"})`);
    const again = b.store.capabilities();
    for (const key of Object.keys(b.caps) as (keyof typeof b.caps)[]) {
      equal(again[key], b.caps[key], "capabilities are declared once and do not change");
    }
  });

  add("capabilities", "declares bounds large enough for this harness to exercise it", async (b) => {
    check(b.caps.maxCreateEntries >= 4, "the harness needs maxCreateEntries of at least 4");
    check(b.caps.maxRestoreEntries >= 4, "the harness needs maxRestoreEntries of at least 4");
    check(b.caps.maxRestoreCaptures >= 2, "the harness needs maxRestoreCaptures of at least 2");
    check(b.caps.maxEnvelopeBytes >= 64, "the harness needs maxEnvelopeBytes of at least 64");
    check(b.caps.maxCreateBytes >= 256, "the harness needs maxCreateBytes of at least 256");
  });
}

export function addCreateCases(add: Add): void {
  add("create", "creates the capture and every entry with initial counters", async (b) => {
    await b.serving();
    const tag = "ab".repeat(32);
    const h = await b.create({ entries: 3, maxUses: [1, 5, 1000], sessionTag: tag });
    const capture = await b.capture(h);
    equal(capture.state, "live", "a new capture is live");
    equal(capture.generation, 1, "a new capture has generation 1");
    equal(capture.keyRevision, 1, "a new capture has keyRevision 1");
    equal(capture.epoch, 1, "a new capture carries the namespace epoch");
    equal(capture.sessionTag, tag, "the session tag is stored as given");
    equal(capture.createdAt, h.input.capture.createdAt, "createdAt is stored as given");
    equal(capture.expiresAt, h.input.capture.expiresAt, "expiresAt is stored as given");
    equal(capture.keyRef, h.input.capture.keyRef, "keyRef is stored as given");
    check(sameBytes(capture.wrappedKey, h.input.capture.wrappedKey), "the wrapped key is stored byte for byte");
    const read = await b.read(h.scope, h.entryIds);
    equal(read.entries.length, 3, "every created entry is readable");
    equal(read.captures.length, 1, "the capture of the returned entries is returned once");
    for (const [index, source] of h.input.entries.entries()) {
      const entry = read.entries.find((candidate) => candidate.entryId === source.entryId);
      if (entry === undefined) fail("a created entry is missing from readEntries");
      equal(entry.captureId, h.captureId, "an entry names its capture");
      equal(entry.maxUses, source.maxUses, `entry ${index}: maxUses is stored as given`);
      equal(entry.used, 0, "a new entry has used 0");
      equal(entry.lifecycleRevision, 1, "a new entry has lifecycleRevision 1");
      equal(entry.ciphertextRevision, 1, "a new entry has ciphertextRevision 1");
      check(sameBytes(entry.envelope, source.envelope), "the envelope is stored byte for byte");
    }
  });

  add("create", "a capture that is not session-bound has a null session tag", async (b) => {
    await b.serving();
    const h = await b.create();
    equal((await b.capture(h)).sessionTag, null, "sessionTag of an unbound capture");
  });

  add("create", "rejects exists for a live capture identifier and overwrites nothing", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2, maxUses: 3 });
    const before = await b.fingerprint([h]);
    const second = b.captureInput({ captureId: h.captureId, entries: 2 });
    rejected(await b.store.createCapture(second), "exists", "createCapture with a live capture's identifier");
    equal(await b.fingerprint([h]), before, "the existing capture and its entries are unchanged");
    const stray = await b.read(second.scope, second.entries.map((entry) => entry.entryId));
    equal(stray.entries.length, 0, "no entry of the rejected capture was created");
  });

  add("create", "rejects exists when any entry identifier exists under another capture, creating nothing", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2 });
    const before = await b.fingerprint([h]);
    const fresh = [b.rng.entryId(), at(h.entryIds, 1), b.rng.entryId()];
    const second = b.captureInput({ entryIds: fresh });
    rejected(await b.store.createCapture(second), "exists", "createCapture with a colliding entry identifier");
    equal(await b.fingerprint([h]), before, "the existing capture and its entries are unchanged");
    const captures = await b.store.readCaptures({ scope: second.scope, captureIds: [second.capture.captureId] });
    equal(captures.length, 0, "the rejected capture row was not created");
    const stray = await b.read(second.scope, [at(fresh, 0), at(fresh, 2)]);
    equal(stray.entries.length, 0, "the non-colliding entries of the rejected capture were not created");
  });

  add("create", "rejects fenced for a revoked capture identifier", async (b) => {
    await b.serving();
    const h = await b.create();
    await revoke(b, h);
    const second = b.captureInput({ captureId: h.captureId });
    rejected(await b.store.createCapture(second), "fenced", "createCapture with a revoked capture's identifier");
    const stray = await b.read(second.scope, second.entries.map((entry) => entry.entryId));
    equal(stray.entries.length, 0, "no entry of the fenced capture was created");
    equal((await b.capture(h)).state, "revoked", "the revoked capture stays revoked");
  });

  add("create", "rejects clock-skew when the caller's now or createdAt is outside the bound, in both directions", async (b) => {
    await b.serving();
    const far = b.skew + FAR_MS;
    const variants: [string, (copy: { now: number; capture: { createdAt: number; expiresAt: number } }) => void][] = [
      ["now ahead of the store clock", (copy) => { copy.now += far; }],
      ["now behind the store clock", (copy) => { copy.now -= far; }],
      ["createdAt ahead of the store clock", (copy) => { copy.capture.createdAt += far; copy.capture.expiresAt += far; }],
      ["createdAt behind the store clock", (copy) => { copy.capture.createdAt -= far; copy.capture.expiresAt -= far; }],
    ];
    for (const [label, change] of variants) {
      const input = altered(b.captureInput({ entries: 2 }), change);
      rejected(await b.store.createCapture(input), "clock-skew", `createCapture with ${label}`);
      await expectAbsent(b, input, `createCapture with ${label}`);
    }
  });

  add("create", "accepts a now and a createdAt exactly at the skew bound", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    for (const sign of [1, -1]) {
      const input = altered(b.captureInput(), (copy) => {
        copy.now = clock.now() + sign * b.skew;
        copy.capture.createdAt = clock.now() - sign * b.skew;
        copy.capture.expiresAt = copy.capture.createdAt + HOUR_MS;
      });
      outcome(await b.store.createCapture(input), "created", "createCapture exactly at the skew bound");
    }
  });

  add("create", "rejects quarantined for an uninitialized namespace, a quarantined one, and an epoch mismatch", async (b) => {
    const first = b.captureInput();
    rejected(await b.store.createCapture(first), "quarantined", "createCapture in a namespace with no recovery record");
    await expectAbsent(b, first, "createCapture in an uninitialized namespace");
    await b.serving(3);
    for (const epoch of [2, 4]) {
      const input = b.captureInput({ epoch });
      rejected(await b.store.createCapture(input), "quarantined", "createCapture with an epoch that differs from the stored one");
      await expectAbsent(b, input, "createCapture with a wrong epoch");
    }
    await b.store.quarantine({ namespace: b.namespace });
    const blocked = b.captureInput({ epoch: 3 });
    rejected(await b.store.createCapture(blocked), "quarantined", "createCapture in a quarantined namespace");
    await expectAbsent(b, blocked, "createCapture in a quarantined namespace");
  });

  add("create", "the same identifiers in another tenant and another namespace are independent rows", async (b) => {
    await b.serving();
    await b.serving(1, b.otherNamespace);
    const h = await b.create({ entries: 2 });
    for (const scope of [b.tenantB, { namespace: b.otherNamespace, tenant: b.tenantA.tenant }]) {
      const input = b.captureInput({ scope, captureId: h.captureId, entryIds: h.entryIds });
      outcome(await b.store.createCapture(input), "created", "createCapture of the same identifiers in another scope");
    }
    const mine = await b.read(h.scope, h.entryIds);
    for (const entry of mine.entries) {
      const source = h.input.entries.find((candidate) => candidate.entryId === entry.entryId);
      check(source !== undefined && sameBytes(entry.envelope, source.envelope), "a scope reads its own envelope, not another scope's");
    }
  });

  add("create", "throws STORE_CAPABILITY for more entries than maxCreateEntries, before any write", async (b) => {
    await b.serving();
    const input = b.captureInput({ entries: b.caps.maxCreateEntries + 1, envelopeBytes: 1 });
    await throwsStoreError(() => b.store.createCapture(input), "STORE_CAPABILITY", "createCapture over maxCreateEntries");
    await expectAbsent(b, input, "createCapture over maxCreateEntries");
  });

  add("create", "throws STORE_CAPABILITY for more bytes than maxCreateBytes, before any write", async (b) => {
    await b.serving();
    const per = b.caps.maxEnvelopeBytes;
    const count = Math.floor(b.caps.maxCreateBytes / per) + 1;
    if (count > b.caps.maxCreateEntries) {
      throw new ConformanceSkip("maxCreateBytes cannot be exceeded within maxCreateEntries envelopes of maxEnvelopeBytes");
    }
    if (count * per > 256 * 1024 * 1024) {
      throw new ConformanceSkip("exceeding maxCreateBytes would need more than 256 MiB of synthetic envelopes");
    }
    const input = altered(b.captureInput({ entries: count, envelopeBytes: 1 }), (copy) => {
      for (const entry of copy.entries) entry.envelope = new Uint8Array(per).fill(7);
    });
    await throwsStoreError(() => b.store.createCapture(input), "STORE_CAPABILITY", "createCapture over maxCreateBytes");
    await expectAbsent(b, input, "createCapture over maxCreateBytes");
  });

  add("create", "throws for an envelope over maxEnvelopeBytes, before any write", async (b) => {
    await b.serving();
    const input = altered(b.captureInput({ entries: 2 }), (copy) => {
      at(copy.entries, 1).envelope = new Uint8Array(b.caps.maxEnvelopeBytes + 1).fill(7);
    });
    // §4.2 lists this as STORE_INVALID_ARGUMENT and §5 as STORE_CAPABILITY. Below the
    // format's ceiling only the declared bound is exceeded, so it is a capability error.
    const codes =
      b.caps.maxEnvelopeBytes < LIMITS.maxEnvelopeBytes
        ? (["STORE_CAPABILITY"] as const)
        : (["STORE_CAPABILITY", "STORE_INVALID_ARGUMENT"] as const);
    await throwsStoreError(() => b.store.createCapture(input), codes, "createCapture with an oversized envelope");
    await expectAbsent(b, input, "createCapture with an oversized envelope");
  });
}

export function addValidationCases(add: Add): void {
  type Change<T> = [string, (copy: Draft<T>) => void];

  add("validation", "createCapture rejects each invalid input with STORE_INVALID_ARGUMENT and creates nothing", async (b) => {
    await b.serving();
    const changes: Change<CreateCaptureInput>[] = [
      ["a namespace with a character outside the grammar", (c) => { c.scope.namespace = "bad namespace"; }],
      ["an empty namespace", (c) => { c.scope.namespace = ""; }],
      ["a namespace of 129 characters", (c) => { c.scope.namespace = "n".repeat(129); }],
      ["an empty tenant", (c) => { c.scope.tenant = ""; }],
      ["a tenant of 257 code units", (c) => { c.scope.tenant = "t".repeat(257); }],
      ["a tenant with a lone surrogate", (c) => { c.scope.tenant = "tenant-\ud800-synthetic"; }],
      ["a capture identifier outside the grammar", (c) => { c.capture.captureId = "cap_UPPERCASEUPPERCASEUPPERCASE"; }],
      ["a capture identifier of the wrong length", (c) => { c.capture.captureId = "cap_abc"; }],
      ["an entry identifier with uppercase hexadecimal", (c) => { at(c.entries, 0).entryId = "A".repeat(64); }],
      ["an entry identifier of 63 characters", (c) => { at(c.entries, 0).entryId = "a".repeat(63); }],
      ["a duplicate entry identifier", (c) => { at(c.entries, 1).entryId = at(c.entries, 0).entryId; }],
      ["no entries", (c) => { c.entries = []; }],
      ["a lifetime of zero", (c) => { c.capture.expiresAt = c.capture.createdAt; }],
      ["a negative lifetime", (c) => { c.capture.expiresAt = c.capture.createdAt - 1; }],
      ["a lifetime over 24 hours", (c) => { c.capture.expiresAt = c.capture.createdAt + DAY_MS + 1; }],
      ["a non-integer createdAt", (c) => { c.capture.createdAt += 0.5; }],
      ["a non-integer now", (c) => { c.now += 0.5; }],
      ["a negative now", (c) => { c.now = -1; }],
      ["a now beyond the safe integer range", (c) => { c.now = 2 ** 53; }],
      ["maxUses of 0", (c) => { at(c.entries, 0).maxUses = 0; }],
      ["maxUses of 1001", (c) => { at(c.entries, 0).maxUses = 1001; }],
      ["a non-integer maxUses", (c) => { at(c.entries, 0).maxUses = 1.5; }],
      ["an empty envelope", (c) => { at(c.entries, 0).envelope = new Uint8Array(0); }],
      ["an envelope that is not bytes", (c) => { at(c.entries, 0).envelope = "synthetic" as never; }],
      ["an empty keyRef", (c) => { c.capture.keyRef = ""; }],
      ["a keyRef of 513 bytes", (c) => { c.capture.keyRef = "k".repeat(513); }],
      ["an empty wrappedKey", (c) => { c.capture.wrappedKey = new Uint8Array(0); }],
      ["a wrappedKey of 4097 bytes", (c) => { c.capture.wrappedKey = new Uint8Array(4097); }],
      ["a session tag of 63 characters", (c) => { c.capture.sessionTag = "a".repeat(63); }],
      ["a session tag with uppercase hexadecimal", (c) => { c.capture.sessionTag = "A".repeat(64); }],
      ["an epoch of 0", (c) => { c.epoch = 0; }],
      ["a non-integer epoch", (c) => { c.epoch = 1.5; }],
      ["an unknown lookupVersion", (c) => { c.capture.lookupVersion = 2 as never; }],
    ];
    for (const [label, change] of changes) {
      const valid = b.captureInput({ entries: 2 });
      const input = altered(valid, change);
      await throwsStoreError(() => b.store.createCapture(input), "STORE_INVALID_ARGUMENT", `createCapture with ${label}`);
      await expectAbsent(b, valid, `createCapture with ${label}`);
    }
  });

  add("validation", "commitRestore rejects each invalid input with STORE_INVALID_ARGUMENT and changes nothing", async (b) => {
    await b.serving();
    const one = await b.create({ entries: 2, maxUses: 5 });
    const two = await b.create({ entries: 1, maxUses: 5 });
    const before = await b.fingerprint([one, two]);
    const changes: Change<CommitRestoreInput>[] = [
      ["a duplicate entry in uses", (c) => { c.uses.push({ ...at(c.uses, 0) }); }],
      ["a duplicate capture", (c) => { c.captures.push({ ...at(c.captures, 0) }); }],
      ["a count of 0", (c) => { at(c.uses, 0).count = 0; }],
      ["a non-integer count", (c) => { at(c.uses, 0).count = 1.5; }],
      ["a negative count", (c) => { at(c.uses, 0).count = -1; }],
      ["a use whose capture is not in captures", (c) => { c.captures = [{ captureId: b.rng.captureId(), generation: 1 }]; }],
      ["a capture with no use", (c) => { c.captures.push({ captureId: b.rng.captureId(), generation: 1 }); }],
      ["empty uses", (c) => { c.uses = []; }],
      ["empty captures", (c) => { c.captures = []; }],
      ["a request digest of 31 bytes", (c) => { c.attempt.requestDigest = new Uint8Array(31); }],
      ["a request digest of 33 bytes", (c) => { c.attempt.requestDigest = new Uint8Array(33); }],
      ["an attempt identifier outside the grammar", (c) => { c.attempt.attemptId = "attempt synthetic"; }],
      ["an attempt identifier of 129 characters", (c) => { c.attempt.attemptId = "a".repeat(129); }],
      ["an epoch of 0", (c) => { c.epoch = 0; }],
      ["a non-integer now", (c) => { c.now += 0.5; }],
      ["an entry identifier outside the grammar", (c) => { at(c.uses, 0).entryId = "not-an-entry"; }],
      ["a tenant with a lone surrogate", (c) => { c.scope.tenant = "\udc00"; }],
      ["a receiptExpiresAt more than 48 hours past the store clock", (c) => { c.receiptExpiresAt = b.now() + 48 * HOUR_MS + b.skew + FAR_MS; }],
      ["a non-integer receiptExpiresAt", (c) => { c.receiptExpiresAt += 0.5; }],
    ];
    for (const [label, change] of changes) {
      const valid = await b.commitInput([{ capture: one, entry: 0 }, { capture: one, entry: 1 }]);
      const input = altered(valid, change);
      await throwsStoreError(() => b.store.commitRestore(input), "STORE_INVALID_ARGUMENT", `commitRestore with ${label}`);
      equal(await b.fingerprint([one, two]), before, `commitRestore with ${label}: no entry changed`);
      const receipt = await b.store.inspectAttempt({ scope: valid.scope, attemptId: valid.attempt.attemptId });
      equal(receipt.state, "absent", `commitRestore with ${label}: no receipt was written`);
    }
  });

  add("validation", "revokeCapture and deleteCiphertext reject invalid inputs and change nothing", async (b) => {
    await b.serving();
    const h = await b.create();
    const before = await b.fingerprint([h]);
    const base = revokeInput(b, h);
    const revokes: [string, object][] = [
      ["a negative retentionMs", { ...base, retentionMs: -1 }],
      ["a retentionMs over 30 days", { ...base, retentionMs: 30 * DAY_MS + 1 }],
      ["a non-integer retentionMs", { ...base, retentionMs: 0.5 }],
      ["a capture identifier outside the grammar", { ...base, captureId: "capture-synthetic" }],
      ["a non-integer now", { ...base, now: base.now + 0.5 }],
      ["a fenceAbsent that is not a boolean", { ...base, fenceAbsent: "yes" }],
      ["an invalid scope", { ...base, scope: { namespace: b.namespace, tenant: "" } }],
    ];
    for (const [label, input] of revokes) {
      await throwsStoreError(() => b.store.revokeCapture(input as never), "STORE_INVALID_ARGUMENT", `revokeCapture with ${label}`);
    }
    const deletes: [string, object][] = [
      ["a capture identifier outside the grammar", { scope: h.scope, captureId: "cap_", now: b.now() }],
      ["a negative now", { scope: h.scope, captureId: h.captureId, now: -5 }],
      ["an invalid namespace", { scope: { namespace: "bad/namespace", tenant: h.scope.tenant }, captureId: h.captureId, now: b.now() }],
    ];
    for (const [label, input] of deletes) {
      await throwsStoreError(() => b.store.deleteCiphertext(input as never), "STORE_INVALID_ARGUMENT", `deleteCiphertext with ${label}`);
    }
    equal(await b.fingerprint([h]), before, "the capture is unchanged after every rejected call");
  });

  add("validation", "replaceCaptureKey rejects invalid inputs and changes nothing", async (b) => {
    await b.serving();
    const h = await b.create();
    const before = await b.fingerprint([h]);
    const base = { scope: h.scope, captureId: h.captureId, keyRevision: 1, keyRef: "synthetic-key:v2", wrappedKey: new Uint8Array(40) };
    const inputs: [string, object][] = [
      ["an empty keyRef", { ...base, keyRef: "" }],
      ["a keyRef over its limit", { ...base, keyRef: "k".repeat(LIMITS.keyRefMaxBytes + 1) }],
      ["an empty wrappedKey", { ...base, wrappedKey: new Uint8Array(0) }],
      ["a wrappedKey over its limit", { ...base, wrappedKey: new Uint8Array(LIMITS.wrappedKeyMaxBytes + 1) }],
      ["a keyRevision of 0", { ...base, keyRevision: 0 }],
      ["a capture identifier outside the grammar", { ...base, captureId: "x" }],
    ];
    for (const [label, input] of inputs) {
      await throwsStoreError(() => b.store.replaceCaptureKey(input as never), "STORE_INVALID_ARGUMENT", `replaceCaptureKey with ${label}`);
    }
    equal(await b.fingerprint([h]), before, "the capture is unchanged after every rejected call");
  });

  add("validation", "reads and inspectAttempt reject invalid inputs", async (b) => {
    await b.serving();
    const scope = b.tenantA;
    await throwsStoreError(() => b.store.readEntries({ scope, entryIds: ["not-hex"] }), "STORE_INVALID_ARGUMENT", "readEntries with an entry identifier outside the grammar");
    await throwsStoreError(() => b.store.readEntries({ scope: { namespace: "", tenant: scope.tenant }, entryIds: [b.rng.entryId()] }), "STORE_INVALID_ARGUMENT", "readEntries with an empty namespace");
    await throwsStoreError(() => b.store.readCaptures({ scope, captureIds: ["cap_short"] }), "STORE_INVALID_ARGUMENT", "readCaptures with a capture identifier outside the grammar");
    await throwsStoreError(() => b.store.inspectAttempt({ scope, attemptId: "" }), "STORE_INVALID_ARGUMENT", "inspectAttempt with an empty attempt identifier");
    await throwsStoreError(() => b.store.inspectAttempt({ scope, attemptId: "attempt/synthetic" }), "STORE_INVALID_ARGUMENT", "inspectAttempt with an attempt identifier outside the grammar");
  });

  add("validation", "reads over a declared bound throw STORE_CAPABILITY", async (b) => {
    await b.serving();
    const entryIds = Array.from({ length: b.caps.maxRestoreEntries + 1 }, () => b.rng.entryId());
    await throwsStoreError(() => b.store.readEntries({ scope: b.tenantA, entryIds }), "STORE_CAPABILITY", "readEntries over maxRestoreEntries");
    const captureIds = Array.from({ length: b.caps.maxRestoreCaptures + 1 }, () => b.rng.captureId());
    await throwsStoreError(() => b.store.readCaptures({ scope: b.tenantA, captureIds }), "STORE_CAPABILITY", "readCaptures over maxRestoreCaptures");
  });

  add("validation", "commitRestore over a declared bound throws STORE_CAPABILITY and changes nothing", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const before = await b.fingerprint([h]);
    const valid = await b.commitInput([{ capture: h }]);
    const tooManyUses = altered(valid, (copy) => {
      for (let i = 0; i < b.caps.maxRestoreEntries; i += 1) {
        copy.uses.push({ ...at(copy.uses, 0), entryId: b.rng.entryId() });
      }
    });
    await throwsStoreError(() => b.store.commitRestore(tooManyUses), "STORE_CAPABILITY", "commitRestore over maxRestoreEntries");
    const tooManyCaptures = altered(valid, (copy) => {
      for (let i = 0; i < b.caps.maxRestoreCaptures; i += 1) {
        const captureId = b.rng.captureId();
        copy.captures.push({ captureId, generation: 1 });
        copy.uses.push({ ...at(copy.uses, 0), entryId: b.rng.entryId(), captureId });
      }
    });
    await throwsStoreError(() => b.store.commitRestore(tooManyCaptures), "STORE_CAPABILITY", "commitRestore over maxRestoreCaptures");
    equal(await b.fingerprint([h]), before, "no entry changed");
    equal((await b.store.inspectAttempt({ scope: valid.scope, attemptId: valid.attempt.attemptId })).state, "absent", "no receipt was written");
  });

  add("validation", "sweepExpired and the recovery operations reject invalid inputs", async (b) => {
    await b.serving();
    const now = b.now();
    for (const [label, limit] of [["a limit of 0", 0], ["a limit of 10001", 10_001], ["a non-integer limit", 1.5]] as const) {
      await throwsStoreError(() => b.store.sweepExpired({ namespace: b.namespace, now, limit }), "STORE_INVALID_ARGUMENT", `sweepExpired with ${label}`);
    }
    await throwsStoreError(() => b.store.sweepExpired({ namespace: "bad namespace", now, limit: 1 }), "STORE_INVALID_ARGUMENT", "sweepExpired with an invalid namespace");
    await throwsStoreError(() => b.store.sweepExpired({ namespace: b.namespace, now: -1, limit: 1 }), "STORE_INVALID_ARGUMENT", "sweepExpired with a negative now");
    for (const [label, epoch] of [["0", 0], ["a negative number", -1], ["a non-integer", 1.5], ["an unsafe integer", 2 ** 53]] as const) {
      await throwsStoreError(() => b.store.initializeNamespace({ namespace: b.otherNamespace, epoch }), "STORE_INVALID_ARGUMENT", `initializeNamespace with an epoch of ${label}`);
      await throwsStoreError(() => b.store.invalidateRecovered({ namespace: b.namespace, newEpoch: epoch }), "STORE_INVALID_ARGUMENT", `invalidateRecovered with a newEpoch of ${label}`);
    }
    equal((await b.store.recoveryState({ namespace: b.otherNamespace })).state, "uninitialized", "a rejected initializeNamespace creates no record");
    equal((await b.store.recoveryState({ namespace: b.namespace })).epoch, 1, "a rejected invalidateRecovered leaves the epoch");
    await throwsStoreError(() => b.store.recoveryState({ namespace: "bad namespace" }), "STORE_INVALID_ARGUMENT", "recoveryState with an invalid namespace");
    await throwsStoreError(() => b.store.quarantine({ namespace: "" }), "STORE_INVALID_ARGUMENT", "quarantine with an empty namespace");
  });
}

export function addReadCases(add: Add): void {
  add("read", "unknown identifiers are simply absent", async (b) => {
    await b.serving();
    const read = await b.read(b.tenantA, [b.rng.entryId(), b.rng.entryId()]);
    equal(read.entries.length, 0, "readEntries of unknown identifiers returns no entry");
    equal(read.captures.length, 0, "readEntries of unknown identifiers returns no capture");
    equal(read.recovery.state, "serving", "the recovery state is part of the read");
    const captures = await b.store.readCaptures({ scope: b.tenantA, captureIds: [b.rng.captureId()] });
    equal(captures.length, 0, "readCaptures of an unknown identifier returns nothing");
  });

  add("read", "returns the known entries of several captures, each capture once", async (b) => {
    await b.serving();
    const one = await b.create({ entries: 2 });
    const two = await b.create({ entries: 1 });
    const ids = [at(one.entryIds, 0), b.rng.entryId(), at(two.entryIds, 0), at(one.entryIds, 1)];
    const read = await b.read(b.tenantA, ids);
    equal(read.entries.length, 3, "three of the four identifiers exist");
    equal(read.captures.length, 2, "the capture of every returned entry is returned, once");
    for (const entry of read.entries) {
      check(read.captures.some((capture) => capture.captureId === entry.captureId), "every returned entry's capture is returned");
    }
    const both = await b.store.readCaptures({ scope: b.tenantA, captureIds: [one.captureId, two.captureId] });
    equal(both.length, 2, "readCaptures returns every row that exists");
    const mixed = await b.store.readCaptures({ scope: b.tenantA, captureIds: [b.rng.captureId(), two.captureId] });
    equal(mixed.length, 1, "readCaptures returns only the rows that exist");
    equal(at(mixed, 0).captureId, two.captureId, "readCaptures returns the row that was asked for");
  });

  add("read", "returns an entry of a revoked capture, with the capture's state revoked", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2 });
    await revoke(b, h);
    const read = await b.read(h.scope, h.entryIds);
    equal(read.entries.length, 2, "the entries of a revoked capture are still returned");
    equal(at(read.captures, 0).state, "revoked", "their capture is reported revoked");
    check(at(read.captures, 0).keyRef.length > 0, "a revoked capture whose ciphertext was not deleted still holds its key");
  });

  add("read", "an entry whose ciphertext was deleted is absent, and its capture row holds no key", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2 });
    await revoke(b, h);
    outcome(await b.store.deleteCiphertext({ scope: h.scope, captureId: h.captureId, now: b.now() }), "deleted", "deleteCiphertext of a revoked capture");
    const read = await b.read(h.scope, h.entryIds);
    equal(read.entries.length, 0, "deleted entries are absent from readEntries");
    equal(read.captures.length, 0, "a capture with no key is never returned by readEntries");
    const capture = await b.capture(h);
    equal(capture.state, "revoked", "readCaptures reports the tombstone revoked");
    equal(capture.keyRef, "", "the tombstone has an empty keyRef");
    equal(capture.wrappedKey.byteLength, 0, "the tombstone has an empty wrappedKey");
  });

  add("read", "another tenant's identifiers return nothing", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2 });
    const read = await b.read(b.tenantB, h.entryIds);
    equal(read.entries.length, 0, "readEntries from another tenant returns no entry");
    equal(read.captures.length, 0, "readEntries from another tenant returns no capture");
    equal((await b.store.readCaptures({ scope: b.tenantB, captureIds: [h.captureId] })).length, 0, "readCaptures from another tenant returns nothing");
  });

  add("read", "another namespace's identifiers return nothing", async (b) => {
    await b.serving();
    await b.serving(1, b.otherNamespace);
    const h = await b.create({ entries: 2 });
    const scope = { namespace: b.otherNamespace, tenant: h.scope.tenant };
    const read = await b.read(scope, h.entryIds);
    equal(read.entries.length, 0, "readEntries from another namespace returns no entry");
    equal((await b.store.readCaptures({ scope, captureIds: [h.captureId] })).length, 0, "readCaptures from another namespace returns nothing");
  });

  add("read", "readEntries carries the recovery state of its snapshot", async (b) => {
    const ids = [b.rng.entryId()];
    const fresh = await b.read(b.tenantA, ids);
    equal(fresh.recovery.state, "uninitialized", "a namespace with no record reads as uninitialized");
    equal(fresh.recovery.epoch, 0, "a namespace with no record has epoch 0");
    await b.serving(7);
    const h = await b.create({ epoch: 7 });
    const serving = await b.read(b.tenantA, h.entryIds);
    equal(serving.recovery.state, "serving", "an initialized namespace reads as serving");
    equal(serving.recovery.epoch, 7, "the stored epoch is returned");
    await b.store.quarantine({ namespace: b.namespace });
    const quarantined = await b.read(b.tenantA, h.entryIds);
    equal(quarantined.recovery.state, "quarantined", "a quarantined namespace reads as quarantined");
    equal(quarantined.entries.length, 1, "reads still work in a quarantined namespace");
  });
}

export function addCommitCases(add: Add): void {
  add("commit", "applies a use, bumps the lifecycle revision, and writes the receipt", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 3 });
    const input = await b.commitInput([{ capture: h }]);
    await commit(b, input);
    const entry = await b.entry(h);
    equal(entry.used, 1, "used after one committed use");
    equal(entry.lifecycleRevision, 2, "lifecycleRevision after one commit");
    equal(entry.ciphertextRevision, 1, "ciphertextRevision is not changed by a commit");
    const capture = await b.capture(h);
    equal(capture.generation, 1, "a commit does not change the capture's generation");
    equal(capture.keyRevision, 1, "a commit does not change the capture's keyRevision");
    equal(capture.state, "live", "a commit does not change the capture's state");
    const receipt = await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId });
    equal(receipt.state, "committed", "the receipt of a committed attempt");
  });

  add("commit", "consumes the aggregate occurrence count of an entry in one step", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    await commit(b, await b.commitInput([{ capture: h, count: 3 }]));
    const entry = await b.entry(h);
    equal(entry.used, 3, "used after a use of count 3");
    equal(entry.lifecycleRevision, 2, "one commit bumps lifecycleRevision once, whatever the count");
  });

  add("commit", "applies every use of a batch across entries and captures", async (b) => {
    await b.serving();
    const one = await b.create({ entries: 2, maxUses: 4 });
    const two = await b.create({ entries: 1, maxUses: 4 });
    await commit(b, await b.commitInput([{ capture: one, entry: 0, count: 2 }, { capture: one, entry: 1 }, { capture: two, count: 4 }]));
    equal((await b.entry(one, 0)).used, 2, "first entry of the first capture");
    equal((await b.entry(one, 1)).used, 1, "second entry of the first capture");
    equal((await b.entry(two, 0)).used, 4, "entry of the second capture");
  });

  add("commit", "rejects unknown for an absent capture, an absent entry, and an entry stated under another capture", async (b) => {
    await b.serving();
    const one = await b.create({ maxUses: 5 });
    const two = await b.create({ maxUses: 5 });
    const before = await b.fingerprint([one, two]);
    const valid = await b.commitInput([{ capture: one }]);
    const ghost = b.rng.captureId();
    const absentCapture = altered(valid, (copy) => {
      copy.captures = [{ captureId: ghost, generation: 1 }];
      at(copy.uses, 0).captureId = ghost;
      at(copy.uses, 0).entryId = b.rng.entryId();
    });
    rejected(await b.store.commitRestore(absentCapture), "unknown", "commitRestore naming an absent capture");
    const absentEntry = altered(valid, (copy) => { at(copy.uses, 0).entryId = b.rng.entryId(); });
    rejected(await b.store.commitRestore(absentEntry), "unknown", "commitRestore naming an absent entry");
    const wrongCapture = altered(valid, (copy) => {
      copy.captures = [{ captureId: two.captureId, generation: 1 }];
      at(copy.uses, 0).captureId = two.captureId;
    });
    rejected(await b.store.commitRestore(wrongCapture), "unknown", "commitRestore stating an entry under a capture it does not belong to");
    equal(await b.fingerprint([one, two]), before, "no rejected commit changed anything");
  });

  add("commit", "rejects stale for a different lifecycleRevision, ciphertextRevision, or generation", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const before = await b.fingerprint([h]);
    const valid = await b.commitInput([{ capture: h }]);
    const variants: [string, CommitRestoreInput][] = [
      ["a higher lifecycleRevision", altered(valid, (copy) => { at(copy.uses, 0).lifecycleRevision += 1; })],
      ["a higher ciphertextRevision", altered(valid, (copy) => { at(copy.uses, 0).ciphertextRevision += 1; })],
      ["a higher generation", altered(valid, (copy) => { at(copy.captures, 0).generation += 1; })],
    ];
    for (const [label, input] of variants) {
      rejected(await b.store.commitRestore(input), "stale", `commitRestore with ${label}`);
    }
    equal(await b.fingerprint([h]), before, "no stale commit changed anything");
    await commit(b, valid);
    const replay = altered(valid, (copy) => { copy.attempt.attemptId = b.attemptId(); });
    rejected(await b.store.commitRestore(replay), "stale", "commitRestore with the lifecycleRevision of an earlier read");
    equal((await b.entry(h)).used, 1, "the stale commit consumed nothing");
  });

  add("commit", "accepts a budget exactly at maxUses and rejects one over", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2, maxUses: 3 });
    rejected(await b.store.commitRestore(await b.commitInput([{ capture: h, entry: 0, count: 4 }])), "budget", "a use of maxUses + 1 on an unused entry");
    equal((await b.entry(h, 0)).used, 0, "a budget rejection consumes nothing");
    await commit(b, await b.commitInput([{ capture: h, entry: 0, count: 3 }]));
    equal((await b.entry(h, 0)).used, 3, "a use of exactly maxUses commits");
    rejected(await b.store.commitRestore(await b.commitInput([{ capture: h, entry: 0 }])), "budget", "one more use of an exhausted entry");
    await commit(b, await b.commitInput([{ capture: h, entry: 1, count: 2 }]));
    rejected(await b.store.commitRestore(await b.commitInput([{ capture: h, entry: 1, count: 2 }])), "budget", "a use that would take used one over maxUses");
    await commit(b, await b.commitInput([{ capture: h, entry: 1, count: 1 }]));
    const entry = await b.entry(h, 1);
    equal(entry.used, 3, "used never exceeds maxUses");
    equal(entry.lifecycleRevision, 3, "only committed uses bump lifecycleRevision");
  });

  add("commit", "rejects expired for a capture already expired on the store's clock", async (b) => {
    await b.serving();
    const h = await b.createExpired({ maxUses: 2 });
    rejected(await b.store.commitRestore(await b.commitInput([{ capture: h }])), "expired", "commitRestore of an expired capture");
    equal((await b.entry(h)).used, 0, "an expired commit consumes nothing");
  });

  add("commit", "judges expiry on the store's clock: live one millisecond before expiresAt, expired exactly at it", async (b) => {
    const clock = b.timeTravel();
    await b.serving();
    const h = await b.create({ maxUses: 3, lifetimeMs: HOUR_MS });
    const expiresAt = h.input.capture.expiresAt;
    clock.set(expiresAt - 1);
    await commit(b, await b.commitInput([{ capture: h }]));
    clock.set(expiresAt);
    const input = altered(await b.commitInput([{ capture: h }]), (copy) => { copy.now = expiresAt - 1; });
    rejected(await b.store.commitRestore(input), "expired", "commitRestore with the store clock at expiresAt and the caller's now before it");
    equal((await b.entry(h)).used, 1, "the expired commit consumed nothing");
    clock.set(expiresAt - 1);
    const early = altered(await b.commitInput([{ capture: h }]), (copy) => { copy.now = expiresAt + 1; });
    outcome(await b.store.commitRestore(early), "committed", "commitRestore with the store clock before expiresAt and the caller's now past it");
  });

  add("commit", "rejects clock-skew when the caller's now is outside the bound, and applies nothing", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    for (const delta of [b.skew + FAR_MS, -(b.skew + FAR_MS)]) {
      const input = altered(await b.commitInput([{ capture: h }]), (copy) => { copy.now += delta; });
      rejected(await b.store.commitRestore(input), "clock-skew", "commitRestore with a now outside the skew bound");
      equal((await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId })).state, "absent", "a skewed commit writes no receipt");
    }
    equal((await b.entry(h)).used, 0, "a skewed commit consumes nothing");
  });

  add("commit", "is all-or-nothing: a batch whose last use fails leaves the earlier entries untouched", async (b) => {
    await b.serving();
    const one = await b.create({ entries: 2, maxUses: 5 });
    const two = await b.create({ entries: 1, maxUses: 1 });
    const before = await b.fingerprint([one, two]);
    const overBudget = await b.commitInput([{ capture: one, entry: 0 }, { capture: one, entry: 1, count: 2 }, { capture: two, count: 2 }]);
    rejected(await b.store.commitRestore(overBudget), "budget", "a batch whose last use is over budget");
    equal(await b.fingerprint([one, two]), before, "used and revisions of the earlier entries are unchanged");
    equal((await b.store.inspectAttempt({ scope: overBudget.scope, attemptId: overBudget.attempt.attemptId })).state, "absent", "a rejected batch writes no receipt");
    const staleLast = altered(await b.commitInput([{ capture: one, entry: 0 }, { capture: one, entry: 1 }, { capture: two }]), (copy) => {
      at(copy.uses, 2).lifecycleRevision += 1;
    });
    rejected(await b.store.commitRestore(staleLast), "stale", "a batch whose last use is stale");
    equal(await b.fingerprint([one, two]), before, "used and revisions are unchanged after the stale batch");
    const unknownLast = altered(await b.commitInput([{ capture: one, entry: 0 }, { capture: two }]), (copy) => {
      at(copy.uses, 1).entryId = b.rng.entryId();
    });
    rejected(await b.store.commitRestore(unknownLast), "unknown", "a batch whose last use names an absent entry");
    equal(await b.fingerprint([one, two]), before, "used and revisions are unchanged after the unknown batch");
  });

  add("commit", "is all-or-nothing across captures: a revoked last capture leaves the first capture's entries untouched", async (b) => {
    await b.serving();
    const one = await b.create({ maxUses: 5 });
    const two = await b.create({ maxUses: 5 });
    const input = await b.commitInput([{ capture: one }, { capture: two }]);
    await revoke(b, two);
    const before = await b.fingerprint([one, two]);
    rejected(await b.store.commitRestore(input), ["revoked", "stale"], "a batch naming a capture revoked after the read");
    equal(await b.fingerprint([one, two]), before, "nothing was applied");
  });

  add("commit", "answers already-committed for the same attempt and digest, and changes nothing", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const input = await b.commitInput([{ capture: h }]);
    await commit(b, input);
    const before = await b.fingerprint([h]);
    outcome(await b.store.commitRestore(input), "already-committed", "the same attempt and digest, replayed");
    const refreshed = altered(await b.commitInput([{ capture: h }]), (copy) => {
      copy.attempt.attemptId = input.attempt.attemptId;
      copy.attempt.requestDigest = new Uint8Array(input.attempt.requestDigest);
    });
    outcome(await b.store.commitRestore(refreshed), "already-committed", "the same attempt and digest with fresh revisions");
    equal(await b.fingerprint([h]), before, "a replayed attempt consumes nothing");
    equal((await b.entry(h)).used, 1, "used was incremented once");
  });

  add("commit", "answers attempt-mismatch for the same attempt with another digest, and changes nothing", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const input = await b.commitInput([{ capture: h }]);
    await commit(b, input);
    const before = await b.fingerprint([h]);
    const other = altered(await b.commitInput([{ capture: h }]), (copy) => { copy.attempt.attemptId = input.attempt.attemptId; });
    outcome(await b.store.commitRestore(other), "attempt-mismatch", "the same attempt identifier with a different digest");
    equal(await b.fingerprint([h]), before, "a mismatched attempt consumes nothing");
    const receipt = await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId });
    check(receipt.state === "committed" && sameBytes(receipt.requestDigest, input.attempt.requestDigest), "the receipt keeps the digest of the attempt that committed");
  });

  add("commit", "evaluates quarantine first, then the receipt, then everything else", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const input = await b.commitInput([{ capture: h }]);
    await commit(b, input);
    const skewed = altered(input, (copy) => { copy.now += b.skew + FAR_MS; });
    outcome(await b.store.commitRestore(skewed), "already-committed", "a replay with a skewed now: the receipt is checked before the clock");
    await revoke(b, h);
    outcome(await b.store.commitRestore(input), "already-committed", "a replay after revocation: the receipt is checked before the capture");
    const mismatch = altered(input, (copy) => { copy.attempt.requestDigest = b.digest(); });
    outcome(await b.store.commitRestore(mismatch), "attempt-mismatch", "a mismatched replay after revocation");
    await b.store.quarantine({ namespace: b.namespace });
    rejected(await b.store.commitRestore(input), "quarantined", "a replay in a quarantined namespace: quarantine is checked before the receipt");
    rejected(await b.store.commitRestore(mismatch), "quarantined", "a mismatched replay in a quarantined namespace");
  });

  add("commit", "throws STORE_INVALID_ARGUMENT for a receipt that would expire before the latest capture, and applies nothing", async (b) => {
    await b.serving();
    const one = await b.create({ maxUses: 5, lifetimeMs: HOUR_MS });
    const two = await b.create({ maxUses: 5, lifetimeMs: 2 * HOUR_MS });
    const before = await b.fingerprint([one, two]);
    const input = altered(await b.commitInput([{ capture: one }, { capture: two }]), (copy) => {
      copy.receiptExpiresAt = two.input.capture.expiresAt - 1;
    });
    await throwsStoreError(() => b.store.commitRestore(input), "STORE_INVALID_ARGUMENT", "commitRestore with receiptExpiresAt before the latest expiresAt");
    equal(await b.fingerprint([one, two]), before, "nothing was applied");
    equal((await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId })).state, "absent", "no receipt was written");
    const exact = altered(input, (copy) => { copy.receiptExpiresAt = two.input.capture.expiresAt; });
    outcome(await b.store.commitRestore(exact), "committed", "commitRestore with receiptExpiresAt equal to the latest expiresAt");
  });

  add("commit", "an attempt identifier is unique per tenant, not across tenants", async (b) => {
    await b.serving();
    const mine = await b.create({ maxUses: 2 });
    const theirs = await b.create({ scope: b.tenantB, maxUses: 2 });
    const first = await b.commitInput([{ capture: mine }]);
    await commit(b, first);
    const second = altered(await b.commitInput([{ capture: theirs }], b.tenantB), (copy) => {
      copy.attempt.attemptId = first.attempt.attemptId;
    });
    outcome(await b.store.commitRestore(second), "committed", "the same attempt identifier in another tenant");
    const a = await b.store.inspectAttempt({ scope: b.tenantA, attemptId: first.attempt.attemptId });
    const other = await b.store.inspectAttempt({ scope: b.tenantB, attemptId: first.attempt.attemptId });
    check(a.state === "committed" && sameBytes(a.requestDigest, first.attempt.requestDigest), "the first tenant's receipt keeps its digest");
    check(other.state === "committed" && sameBytes(other.requestDigest, second.attempt.requestDigest), "the second tenant's receipt keeps its digest");
  });

  add("commit", "rejects revoked after a revocation, with the generation read before or after it", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const early = await b.commitInput([{ capture: h }]);
    await revoke(b, h);
    rejected(await b.store.commitRestore(early), ["revoked", "stale"], "commitRestore with the generation read before the revocation");
    const late = await b.commitInput([{ capture: h }]);
    equal(at(late.captures, 0).generation, 2, "the read after revocation shows the new generation");
    rejected(await b.store.commitRestore(late), "revoked", "commitRestore with the generation read after the revocation");
    equal((await b.entry(h)).used, 0, "a revoked capture's budget is never consumed");
  });

  add("commit", "cannot reach another tenant's or another namespace's rows", async (b) => {
    await b.serving();
    await b.serving(1, b.otherNamespace);
    const h = await b.create({ maxUses: 5 });
    const valid = await b.commitInput([{ capture: h }]);
    for (const scope of [b.tenantB, { namespace: b.otherNamespace, tenant: h.scope.tenant }]) {
      const input = altered(valid, (copy) => { copy.scope = { ...scope }; copy.attempt.attemptId = b.attemptId(); });
      rejected(await b.store.commitRestore(input), "unknown", "commitRestore naming another scope's identifiers");
    }
    equal((await b.entry(h)).used, 0, "the owner's entry is untouched");
  });

  add("commit", "rejects quarantined for an uninitialized namespace and for an epoch that differs", async (b) => {
    const ghost = b.rng.captureId();
    const input: CommitRestoreInput = {
      scope: b.tenantA,
      epoch: 1,
      now: b.now(),
      attempt: { attemptId: b.attemptId(), requestDigest: b.digest() },
      receiptExpiresAt: b.now() + HOUR_MS,
      captures: [{ captureId: ghost, generation: 1 }],
      uses: [{ entryId: b.rng.entryId(), captureId: ghost, count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }],
    };
    rejected(await b.store.commitRestore(input), "quarantined", "commitRestore in a namespace with no recovery record");
    await b.serving(2);
    const h = await b.create({ epoch: 2, maxUses: 5 });
    for (const epoch of [1, 3]) {
      const wrong = altered(await b.commitInput([{ capture: h }]), (copy) => { copy.epoch = epoch; });
      rejected(await b.store.commitRestore(wrong), "quarantined", "commitRestore with an epoch that differs from the stored one");
    }
    equal((await b.entry(h)).used, 0, "nothing was consumed");
  });
}

export function addRevokeCases(add: Add): void {
  add("revoke", "revokes a live capture, increments its generation, and reports its entry count", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 3 });
    const result = await b.store.revokeCapture(revokeInput(b, h));
    outcome(result, "revoked", "revokeCapture of a live capture");
    equal((result as { entries?: number }).entries, 3, "entries is the number of entry rows");
    const capture = await b.capture(h);
    equal(capture.state, "revoked", "state after revocation");
    equal(capture.generation, 2, "generation after revocation");
    equal(capture.keyRevision, 1, "revocation does not change keyRevision");
  });

  add("revoke", "answers already-revoked the second time and does not increment the generation again", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2 });
    await revoke(b, h);
    const again = await b.store.revokeCapture(revokeInput(b, h, true));
    outcome(again, "already-revoked", "revokeCapture of a revoked capture");
    equal((again as { entries?: number }).entries, 2, "entries of an already revoked capture");
    equal((await b.capture(h)).generation, 2, "generation is incremented once");
  });

  add("revoke", "answers not-found for an absent capture and writes nothing", async (b) => {
    await b.serving();
    const input = b.captureInput();
    outcome(await b.store.revokeCapture(revokeInput(b, { scope: input.scope, captureId: input.capture.captureId })), "not-found", "revokeCapture of an absent capture without fenceAbsent");
    await expectAbsent(b, input, "revokeCapture without fenceAbsent");
    outcome(await b.store.createCapture(input), "created", "createCapture after a not-found revocation");
  });

  add("revoke", "writes a fence for an absent capture when fenceAbsent is set, and the fence blocks creation", async (b) => {
    await b.serving();
    const input = b.captureInput();
    const target = { scope: input.scope, captureId: input.capture.captureId };
    outcome(await b.store.revokeCapture(revokeInput(b, target, true)), "fenced", "revokeCapture of an absent capture with fenceAbsent");
    rejected(await b.store.createCapture(input), "fenced", "createCapture of a fenced identifier");
    const rows = await b.store.readCaptures({ scope: input.scope, captureIds: [input.capture.captureId] });
    equal(rows.length, 1, "readCaptures returns the fence row");
    const fence = at(rows, 0);
    equal(fence.state, "revoked", "a fence is revoked");
    equal(fence.keyRef, "", "a fence has an empty keyRef");
    equal(fence.wrappedKey.byteLength, 0, "a fence has an empty wrappedKey");
    equal(fence.createdAt, fence.expiresAt, "a fence's createdAt and expiresAt are the same store clock reading");
    if (b.clock !== null) equal(fence.createdAt, b.clock.now(), "a fence's times are the store's clock");
    equal((await b.read(input.scope, input.entries.map((entry) => entry.entryId))).entries.length, 0, "no entry of the fenced capture exists");
    const again = await b.store.revokeCapture(revokeInput(b, target, true));
    outcome(again, "already-revoked", "revokeCapture of a fence");
    equal((again as { entries?: number }).entries, 0, "a fence has no entries");
  });

  add("revoke", "a fence is scoped to its tenant", async (b) => {
    await b.serving();
    const input = b.captureInput();
    outcome(await b.store.revokeCapture(revokeInput(b, { scope: b.tenantB, captureId: input.capture.captureId }, true)), "fenced", "fencing an identifier in another tenant");
    outcome(await b.store.createCapture(input), "created", "createCapture of the same identifier in this tenant");
  });

  add("revoke", "works in a quarantined namespace", async (b) => {
    await b.serving();
    const h = await b.create();
    await b.store.quarantine({ namespace: b.namespace });
    outcome(await b.store.revokeCapture(revokeInput(b, h)), "revoked", "revokeCapture in a quarantined namespace");
    equal((await b.capture(h)).state, "revoked", "state after revocation under quarantine");
    const ghost = { scope: b.tenantA, captureId: b.rng.captureId() };
    outcome(await b.store.revokeCapture(revokeInput(b, ghost, true)), "fenced", "fencing in a quarantined namespace");
  });

  add("revoke", "cannot revoke another tenant's capture", async (b) => {
    await b.serving();
    const h = await b.create();
    outcome(await b.store.revokeCapture(revokeInput(b, { scope: b.tenantB, captureId: h.captureId })), "not-found", "revokeCapture from another tenant");
    equal((await b.capture(h)).state, "live", "the owner's capture stays live");
    equal((await b.capture(h)).generation, 1, "the owner's capture keeps its generation");
  });

  add("revoke", "does not depend on the caller's clock", async (b) => {
    await b.serving();
    const h = await b.create();
    const input = { ...revokeInput(b, h), now: b.now() + b.skew + FAR_MS };
    outcome(await b.store.revokeCapture(input), "revoked", "revokeCapture with a now outside the skew bound");
  });
}

export function addInspectCases(add: Add): void {
  add("inspect", "reports absent before a commit and committed with the digest after it", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 2 });
    const input = await b.commitInput([{ capture: h }]);
    const target = { scope: input.scope, attemptId: input.attempt.attemptId };
    equal((await b.store.inspectAttempt(target)).state, "absent", "inspectAttempt before the commit");
    const before = b.now();
    await commit(b, input);
    const receipt = await b.store.inspectAttempt(target);
    if (receipt.state !== "committed") fail("inspectAttempt after the commit must report committed");
    check(sameBytes(receipt.requestDigest, input.attempt.requestDigest), "the receipt carries the request digest");
    if (b.clock !== null) equal(receipt.committedAt, before, "committedAt is the store's clock at the commit");
    else check(Math.abs(receipt.committedAt - before) <= b.skew + FAR_MS, "committedAt is a store clock reading near the commit");
    equal((await b.store.inspectAttempt({ scope: b.tenantB, attemptId: input.attempt.attemptId })).state, "absent", "another tenant does not see the receipt");
  });

  add("inspect", "reports absent for an attempt whose commit was rejected", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 1 });
    const input = await b.commitInput([{ capture: h, count: 2 }]);
    rejected(await b.store.commitRestore(input), "budget", "a use over budget");
    equal((await b.store.inspectAttempt({ scope: input.scope, attemptId: input.attempt.attemptId })).state, "absent", "a rejected attempt has no receipt");
    const retry = altered(await b.commitInput([{ capture: h }]), (copy) => {
      copy.attempt = { attemptId: input.attempt.attemptId, requestDigest: new Uint8Array(input.attempt.requestDigest) };
    });
    outcome(await b.store.commitRestore(retry), "committed", "the same attempt identifier can commit after its rejection");
  });
}

export function addRekeyCases(add: Add): void {
  const newKey = (b: Bench, h: CaptureHandle, keyRevision = 1) => ({
    scope: h.scope,
    captureId: h.captureId,
    keyRevision,
    keyRef: "synthetic-key:v2",
    wrappedKey: b.rng.bytes(48),
  });

  add("rekey", "replaces the stored key under the expected keyRevision and changes nothing else", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2, maxUses: 4, sessionTag: "cd".repeat(32) });
    await commit(b, await b.commitInput([{ capture: h, count: 2 }]));
    const before = await b.capture(h);
    const entriesBefore = await b.read(h.scope, h.entryIds);
    const input = newKey(b, h);
    const result = await b.store.replaceCaptureKey(input);
    outcome(result, "replaced", "replaceCaptureKey with the current keyRevision");
    equal((result as { keyRevision?: number }).keyRevision, 2, "the new keyRevision is returned");
    const after = await b.capture(h);
    equal(after.keyRevision, 2, "keyRevision after the replacement");
    equal(after.keyRef, input.keyRef, "keyRef after the replacement");
    check(sameBytes(after.wrappedKey, input.wrappedKey), "wrappedKey after the replacement");
    for (const key of ["state", "generation", "epoch", "sessionTag", "createdAt", "expiresAt"] as const) {
      equal(after[key], before[key], `replaceCaptureKey must not change the capture's ${key}`);
    }
    const entriesAfter = await b.read(h.scope, h.entryIds);
    for (const entry of entriesBefore.entries) {
      const now = entriesAfter.entries.find((candidate) => candidate.entryId === entry.entryId);
      if (now === undefined) fail("replaceCaptureKey must not remove an entry");
      for (const key of ["used", "maxUses", "lifecycleRevision", "ciphertextRevision"] as const) {
        equal(now[key], entry[key], `replaceCaptureKey must not change an entry's ${key}`);
      }
      check(sameBytes(now.envelope, entry.envelope), "replaceCaptureKey must not change an envelope");
    }
  });

  add("rekey", "rejects stale for another keyRevision", async (b) => {
    await b.serving();
    const h = await b.create();
    const before = await b.fingerprint([h]);
    rejected(await b.store.replaceCaptureKey(newKey(b, h, 2)), "stale", "replaceCaptureKey with a keyRevision that is not current");
    equal(await b.fingerprint([h]), before, "nothing changed");
    outcome(await b.store.replaceCaptureKey(newKey(b, h, 1)), "replaced", "the first replacement");
    rejected(await b.store.replaceCaptureKey(newKey(b, h, 1)), "stale", "a second replacement with the old keyRevision");
  });

  add("rekey", "rejects unknown for an absent capture and for another tenant's capture", async (b) => {
    await b.serving();
    const h = await b.create();
    rejected(await b.store.replaceCaptureKey({ ...newKey(b, h), captureId: b.rng.captureId() }), "unknown", "replaceCaptureKey of an absent capture");
    rejected(await b.store.replaceCaptureKey({ ...newKey(b, h), scope: b.tenantB }), "unknown", "replaceCaptureKey from another tenant");
    equal((await b.capture(h)).keyRevision, 1, "the owner's key is unchanged");
  });

  add("rekey", "refuses a revoked capture, an expired one, and one whose ciphertext was deleted", async (b) => {
    await b.serving();
    const revoked = await b.create();
    await revoke(b, revoked);
    const before = await b.fingerprint([revoked]);
    rejected(await b.store.replaceCaptureKey(newKey(b, revoked)), "revoked", "replaceCaptureKey of a revoked capture");
    equal(await b.fingerprint([revoked]), before, "the revoked capture is unchanged");
    outcome(await b.store.deleteCiphertext({ scope: revoked.scope, captureId: revoked.captureId, now: b.now() }), "deleted", "deleteCiphertext of the revoked capture");
    const deleted = await b.capture(revoked);
    rejected(await b.store.replaceCaptureKey(newKey(b, revoked, deleted.keyRevision)), "revoked", "replaceCaptureKey of a capture whose ciphertext was deleted");
    equal((await b.capture(revoked)).keyRef, "", "the deleted capture still holds no key");
    const expired = await b.createExpired();
    rejected(await b.store.replaceCaptureKey(newKey(b, expired)), "expired", "replaceCaptureKey of an expired capture");
    equal((await b.capture(expired)).keyRevision, 1, "the expired capture's key is unchanged");
  });

  add("rekey", "a restore prepared before the re-wrap still commits, and its use is kept", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 3 });
    await commit(b, await b.commitInput([{ capture: h }]));
    const prepared = await b.commitInput([{ capture: h }]);
    outcome(await b.store.replaceCaptureKey(newKey(b, h)), "replaced", "replaceCaptureKey between a restore's read and its commit");
    equal((await b.entry(h)).used, 1, "replaceCaptureKey must not reset used");
    await commit(b, prepared);
    equal((await b.entry(h)).used, 2, "the restore prepared before the re-wrap committed");
  });
}

export function addDeleteCases(add: Add): void {
  const del = (b: Bench, h: { scope: StoreScope; captureId: string }, now = b.now()) => ({ scope: h.scope, captureId: h.captureId, now });

  add("delete", "refuses a live, unexpired capture and an absent one", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 2 });
    const before = await b.fingerprint([h]);
    rejected(await b.store.deleteCiphertext(del(b, h)), "live", "deleteCiphertext of a live, unexpired capture");
    equal(await b.fingerprint([h]), before, "the live capture is unchanged");
    rejected(await b.store.deleteCiphertext(del(b, { scope: h.scope, captureId: b.rng.captureId() })), "not-found", "deleteCiphertext of an absent capture");
    rejected(await b.store.deleteCiphertext(del(b, { scope: b.tenantB, captureId: h.captureId })), "not-found", "deleteCiphertext from another tenant");
    equal(await b.fingerprint([h]), before, "the live capture is still unchanged");
  });

  add("delete", "deletes a revoked capture's ciphertext whatever the clocks say", async (b) => {
    await b.serving();
    const h = await b.create({ entries: 3 });
    await revoke(b, h);
    const result = await b.store.deleteCiphertext(del(b, h, b.now() + b.skew + FAR_MS));
    outcome(result, "deleted", "deleteCiphertext of a revoked capture with a skewed now");
    equal((result as { entries?: number }).entries, 3, "entries is the number of rows removed");
    equal((await b.read(h.scope, h.entryIds)).entries.length, 0, "the entry rows are gone");
    const tombstone = await b.capture(h);
    equal(tombstone.state, "revoked", "the row stays as a revoked tombstone");
    equal(tombstone.keyRef, "", "the stored keyRef is emptied");
    equal(tombstone.wrappedKey.byteLength, 0, "the stored wrappedKey is emptied");
    equal(tombstone.keyRevision, 2, "keyRevision is incremented");
  });

  add("delete", "deletes an expired capture's ciphertext and marks the capture revoked", async (b) => {
    await b.serving();
    const h = await b.createExpired({ entries: 2 });
    const result = await b.store.deleteCiphertext(del(b, h));
    outcome(result, "deleted", "deleteCiphertext of an expired capture");
    equal((result as { entries?: number }).entries, 2, "entries is the number of rows removed");
    const tombstone = await b.capture(h);
    equal(tombstone.state, "revoked", "an expired capture is marked revoked by the deletion");
    equal(tombstone.keyRevision, 2, "keyRevision is incremented");
    equal(tombstone.keyRef, "", "the stored key is emptied");
  });

  add("delete", "rejects clock-skew when the decision rests on expiry and the clocks disagree", async (b) => {
    await b.serving();
    const h = await b.createExpired({ entries: 2 });
    const before = await b.fingerprint([h]);
    for (const delta of [b.skew + FAR_MS, -(b.skew + FAR_MS)]) {
      rejected(await b.store.deleteCiphertext(del(b, h, b.now() + delta)), "clock-skew", "deleteCiphertext of an expired capture with a skewed now");
    }
    equal(await b.fingerprint([h]), before, "nothing was deleted");
  });

  add("delete", "the tombstone remains, still fences creation, and its entries can no longer be committed", async (b) => {
    await b.serving();
    const h = await b.create({ maxUses: 5 });
    const prepared = await b.commitInput([{ capture: h }]);
    await revoke(b, h);
    outcome(await b.store.deleteCiphertext(del(b, h)), "deleted", "deleteCiphertext of a revoked capture");
    rejected(await b.store.createCapture(b.captureInput({ captureId: h.captureId })), "fenced", "createCapture of a deleted capture's identifier");
    rejected(await b.store.commitRestore(prepared), ["revoked", "stale", "unknown"], "commitRestore after the ciphertext was deleted");
    const again = await b.store.deleteCiphertext(del(b, h));
    outcome(again, "deleted", "deleteCiphertext a second time");
    equal((again as { entries?: number }).entries, 0, "the second deletion removes nothing");
  });
}
