/**
 * Model cases: the store and the reference model receive the same seeded,
 * sequential operation sequence, and every result is compared, followed by a
 * read-back of everything the sequence touched.
 */
import { StoreError } from "@redact-secret/vault-contracts";
import type { CommitRestoreInput, CreateCaptureInput, Store, StoreScope } from "@redact-secret/vault-contracts";
import { ReferenceModel } from "./model.js";
import type { Add } from "./store-cases.js";
import { altered, DAY_MS, describe, fail, HOUR_MS, sameBytes } from "./support.js";
import type { Bench } from "./support.js";

type Operation = Exclude<keyof Store, "capabilities">;

type Settled = { readonly value: unknown } | { readonly threw: string };

function thrown(error: unknown): Settled {
  return { threw: error instanceof StoreError ? error.code : "an error that is not a StoreError" };
}

function isFenceView(value: Record<string, unknown>): boolean {
  return value.keyRef === "" && value.state === "revoked" && value.createdAt === value.expiresAt && "generation" in value;
}

/** The path of the first difference between two results, or null. Paths name fields, never values. */
function difference(a: unknown, b: unknown, exact: boolean, path: string): string | null {
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    return a instanceof Uint8Array && b instanceof Uint8Array && sameBytes(a, b) ? null : path;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return `${path}.length`;
    const order = (items: unknown[]) =>
      [...items].sort((x, y) => {
        const left = sortKey(x);
        const right = sortKey(y);
        return left < right ? -1 : left > right ? 1 : 0;
      });
    const left = order(a);
    const right = order(b);
    for (let i = 0; i < left.length; i += 1) {
      const found = difference(left[i], right[i], exact, `${path}[${i}]`);
      if (found !== null) return found;
    }
    return null;
  }
  if (typeof a === "object" && a !== null && typeof b === "object" && b !== null) {
    const left = a as Record<string, unknown>;
    const right = b as Record<string, unknown>;
    const skip = new Set<string>();
    if (!exact) {
      // Without a controllable clock the model's clock is an estimate of the store's.
      skip.add("committedAt");
      if (isFenceView(left) && isFenceView(right)) {
        skip.add("createdAt");
        skip.add("expiresAt");
      }
    }
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    for (const key of keys) {
      if (skip.has(key)) continue;
      const found = difference(left[key], right[key], exact, `${path}.${key}`);
      if (found !== null) return found;
    }
    return null;
  }
  return a === b ? null : path;
}

function sortKey(value: unknown): string {
  if (typeof value !== "object" || value === null) return String(value);
  const record = value as Record<string, unknown>;
  return String(record.entryId ?? record.captureId ?? "");
}

function sameScope(a: StoreScope, b: StoreScope): boolean {
  return a.namespace === b.namespace && a.tenant === b.tenant;
}

interface KnownCapture {
  readonly scope: StoreScope;
  readonly captureId: string;
  readonly entryIds: readonly string[];
}

async function drive(b: Bench, steps: number, timeTravel: boolean): Promise<void> {
  const clock = timeTravel ? b.timeTravel() : null;
  const exact = b.clock !== null;
  const rng = b.rng;
  const model = new ReferenceModel({ maxClockSkewMs: b.skew });
  const namespaces = [b.namespace, b.otherNamespace];
  const scopes: StoreScope[] = [b.tenantA, b.tenantA, b.tenantB, { namespace: b.otherNamespace, tenant: b.tenantA.tenant }];
  const known: KnownCapture[] = [];
  const attempts: CommitRestoreInput[] = [];
  const far = b.skew + 60_000;
  let step = 0;

  async function apply(operation: Operation, input: unknown): Promise<Settled> {
    const storeNow = b.now();
    let expected: Settled;
    try {
      expected = { value: (model[operation] as (input: unknown, now: number) => unknown)(input, storeNow) };
    } catch (error) {
      expected = thrown(error);
    }
    let actual: Settled;
    try {
      actual = { value: await (b.store[operation] as (input: unknown) => Promise<unknown>)(input) };
    } catch (error) {
      actual = thrown(error);
    }
    const where = `step ${step} (${operation})`;
    if ("threw" in expected || "threw" in actual) {
      const want = "threw" in expected ? expected.threw : describe(expected.value);
      const got = "threw" in actual ? actual.threw : describe(actual.value);
      if (want !== got || !("threw" in expected) || !("threw" in actual)) {
        fail(`${where}: the reference model gives ${want}, the store gave ${got}`);
      }
      return actual;
    }
    const found = difference(expected.value, actual.value, exact, "result");
    if (found !== null) {
      fail(`${where}: the reference model gives ${describe(expected.value)}, the store gave ${describe(actual.value)}; first difference at ${found}`);
    }
    return actual;
  }

  const maybeSkewed = (now: number, probability: number): number =>
    rng.chance(probability) ? now + (rng.chance(0.5) || now < far ? far : -far) : now;

  function createInput(): CreateCaptureInput {
    const scope = rng.pick(scopes);
    const epoch = model.recoveryOf(scope.namespace).epoch;
    const mine = known.filter((capture) => sameScope(capture.scope, scope));
    const reuseCapture = mine.length > 0 && rng.chance(0.1);
    const reuseEntry = mine.length > 0 && rng.chance(0.06);
    const count = 1 + rng.int(Math.min(3, b.caps.maxCreateEntries));
    const entryIds = Array.from({ length: count }, () => rng.entryId());
    if (reuseEntry) entryIds[rng.int(count)] = rng.pick(rng.pick(mine).entryIds);
    const base = b.captureInput({
      scope,
      epoch: Math.max(1, rng.chance(0.08) ? epoch + rng.pick([-1, 1]) : epoch),
      ...(reuseCapture ? { captureId: rng.pick(mine).captureId } : {}),
      entryIds,
      maxUses: entryIds.map(() => rng.pick([1, 2, 3, 1000])),
      lifetimeMs: timeTravel ? rng.pick([5 * 60_000, HOUR_MS, 6 * HOUR_MS, DAY_MS]) : rng.pick([HOUR_MS, DAY_MS]),
      sessionTag: rng.chance(0.3) ? rng.entryId() : null,
    });
    return altered(base, (copy) => {
      copy.now = maybeSkewed(copy.now, 0.04);
      if (rng.chance(0.03)) {
        copy.capture.createdAt += far;
        copy.capture.expiresAt += far;
      }
    });
  }

  function commitInput(): CommitRestoreInput | null {
    if (attempts.length > 0 && rng.chance(0.12)) {
      const earlier = rng.pick(attempts);
      return altered(earlier, (copy) => {
        copy.now = b.now();
        if (rng.chance(0.4)) copy.attempt.requestDigest = b.digest();
      });
    }
    if (known.length === 0) return null;
    // Mostly recent captures: older ones are likelier to be revoked, expired, or of an earlier epoch.
    const first = rng.chance(0.8) ? rng.pick(known.slice(-8)) : rng.pick(known);
    const scope = first.scope;
    const candidates = known.filter((capture) => sameScope(capture.scope, scope)).slice(-6);
    const chosen = new Map<string, string>();
    const wanted = 1 + rng.int(Math.min(3, b.caps.maxRestoreEntries, b.caps.maxRestoreCaptures));
    for (let i = 0; i < wanted; i += 1) {
      const capture = i === 0 ? first : rng.pick(candidates);
      chosen.set(rng.pick(capture.entryIds), capture.captureId);
    }
    const view = model.readEntries({ scope, entryIds: [...chosen.keys()] }, b.now());
    const captures = new Map<string, number>();
    let latest = 0;
    const uses = [...chosen].map(([entryId, captureId]) => {
      const entry = view.entries.find((candidate) => candidate.entryId === entryId);
      const capture = view.captures.find((candidate) => candidate.captureId === captureId);
      captures.set(captureId, capture?.generation ?? 1);
      latest = Math.max(latest, capture?.expiresAt ?? 0);
      const remaining = entry === undefined ? 1 : entry.maxUses - entry.used;
      return {
        entryId,
        captureId,
        count: rng.chance(0.12) ? Math.min(1000, Math.max(1, remaining + 1)) : 1 + rng.int(Math.max(1, Math.min(2, remaining))),
        lifecycleRevision: Math.max(1, (entry?.lifecycleRevision ?? 1) + (rng.chance(0.08) ? rng.pick([-1, 1]) : 0)),
        ciphertextRevision: (entry?.ciphertextRevision ?? 1) + (rng.chance(0.03) ? 1 : 0),
      };
    });
    if (candidates.length > 1 && rng.chance(0.05)) {
      // State one entry under another capture of the same scope.
      const other = rng.pick(candidates).captureId;
      const use = uses[0];
      if (use !== undefined && other !== use.captureId) {
        use.captureId = other;
        if (!captures.has(other)) captures.set(other, model.findCapture(scope, other)?.generation ?? 1);
      }
    }
    const epoch = model.recoveryOf(scope.namespace).epoch;
    const now = b.now();
    return {
      scope,
      epoch: Math.max(1, rng.chance(0.05) ? epoch + 1 : epoch),
      now: maybeSkewed(now, 0.04),
      attempt: { attemptId: b.attemptId(), requestDigest: b.digest() },
      receiptExpiresAt: rng.chance(0.03) ? Math.max(0, latest - 1) : Math.max(latest, now) + b.skew + HOUR_MS,
      // Exactly the captures the uses state, each once: the model assumes validated input.
      captures: [...new Set(uses.map((use) => use.captureId))].map((captureId) => ({
        captureId,
        generation: (captures.get(captureId) ?? 1) + (rng.chance(0.04) ? 1 : 0),
      })),
      uses,
    };
  }

  function anyCapture(): { scope: StoreScope; captureId: string } {
    if (known.length === 0 || rng.chance(0.1)) return { scope: rng.pick(scopes), captureId: rng.captureId() };
    const capture = rng.pick(known);
    return { scope: rng.chance(0.1) ? rng.pick(scopes) : capture.scope, captureId: capture.captureId };
  }

  for (const namespace of namespaces) {
    await apply("initializeNamespace", { namespace, epoch: 1 });
    step += 1;
  }

  for (; step < steps; step += 1) {
    const roll = rng.next();
    const namespace = rng.chance(0.75) ? b.namespace : b.otherNamespace;
    if (model.recoveryOf(namespace).state === "quarantined" && rng.chance(0.3)) {
      const epoch = model.recoveryOf(namespace).epoch;
      await apply("invalidateRecovered", { namespace, newEpoch: epoch + 1 });
    } else if (roll < 0.2) {
      const input = createInput();
      const result = await apply("createCapture", input);
      if ("value" in result && (result.value as { outcome?: string }).outcome === "created") {
        known.push({ scope: input.scope, captureId: input.capture.captureId, entryIds: input.entries.map((entry) => entry.entryId) });
      }
    } else if (roll < 0.47) {
      const input = commitInput();
      if (input === null) continue;
      const result = await apply("commitRestore", input);
      if ("value" in result && (result.value as { outcome?: string }).outcome === "committed") attempts.push(input);
    } else if (roll < 0.56) {
      const scope = rng.pick(scopes);
      const entryIds = new Set<string>([rng.entryId()]);
      for (let i = 0; i < 3 && known.length > 0; i += 1) entryIds.add(rng.pick(rng.pick(known).entryIds));
      await apply("readEntries", { scope, entryIds: [...entryIds].slice(0, b.caps.maxRestoreEntries) });
    } else if (roll < 0.6) {
      const target = anyCapture();
      await apply("readCaptures", { scope: target.scope, captureIds: [target.captureId] });
    } else if (roll < 0.69) {
      const target = anyCapture();
      const input = {
        ...target,
        now: b.now(),
        retentionMs: timeTravel ? rng.pick([0, HOUR_MS, DAY_MS]) : rng.pick([HOUR_MS, DAY_MS]),
        fenceAbsent: rng.chance(0.3),
      };
      const result = await apply("revokeCapture", input);
      if ("value" in result && (result.value as { outcome?: string }).outcome === "fenced") {
        known.push({ scope: target.scope, captureId: target.captureId, entryIds: [rng.entryId()] });
      }
    } else if (roll < 0.73) {
      const scope = rng.pick(scopes);
      const attemptId = attempts.length > 0 && rng.chance(0.8) ? rng.pick(attempts).attempt.attemptId : b.attemptId();
      await apply("inspectAttempt", { scope, attemptId });
    } else if (roll < 0.79) {
      const target = anyCapture();
      const current = model.findCapture(target.scope, target.captureId)?.keyRevision ?? 1;
      await apply("replaceCaptureKey", {
        ...target,
        keyRevision: rng.chance(0.2) ? current + 1 : current,
        keyRef: `synthetic-key:v${2 + rng.int(3)}`,
        wrappedKey: rng.bytes(40),
      });
    } else if (roll < 0.84) {
      await apply("deleteCiphertext", { ...anyCapture(), now: maybeSkewed(b.now(), 0.1) });
    } else if (roll < 0.89) {
      await apply("sweepExpired", { namespace, now: maybeSkewed(b.now(), 0.1), limit: 10_000 });
    } else if (roll < 0.91) {
      await apply("recoveryState", { namespace });
    } else if (roll < 0.916) {
      await apply("quarantine", { namespace });
    } else if (roll < 0.922) {
      const epoch = model.recoveryOf(namespace).epoch;
      await apply("invalidateRecovered", { namespace, newEpoch: rng.chance(0.3) ? epoch : epoch + 1 });
    } else if (roll < 0.926) {
      await apply("initializeNamespace", { namespace, epoch: 1 });
    } else if (clock !== null) {
      clock.advance(rng.pick([1, 1000, 5 * 60_000, HOUR_MS, 3 * HOUR_MS]));
    }
  }

  // Read back everything the sequence touched, from every scope.
  step = steps;
  for (const namespace of namespaces) await apply("recoveryState", { namespace });
  const distinct = new Set(scopes);
  for (const capture of known) {
    for (const scope of distinct) {
      await apply("readCaptures", { scope, captureIds: [capture.captureId] });
      await apply("readEntries", { scope, entryIds: capture.entryIds.slice(0, b.caps.maxRestoreEntries) });
    }
  }
  for (const attempt of attempts) {
    for (const scope of distinct) await apply("inspectAttempt", { scope, attemptId: attempt.attempt.attemptId });
  }
}

export function addModelCases(add: Add, sequences: number, steps: number): void {
  for (let index = 1; index <= sequences; index += 1) {
    add("model", `random operation sequence ${index} matches the reference model`, (b) => drive(b, steps, false));
  }
  for (let index = 1; index <= sequences; index += 1) {
    add("model", `random operation sequence ${index} with time travel matches the reference model`, (b) => drive(b, steps, true));
  }
}
