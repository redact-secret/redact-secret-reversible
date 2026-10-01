// Shared fixtures. Every identifier and byte here is synthetic.
import { createMemoryStore } from "../dist/index.js";

export const START = 1_800_000_000_000;

/** A store with a clock the test moves. */
export function openStore(options = {}) {
  let now = START;
  const clock = {
    now: () => now,
    advance: (ms) => {
      now += ms;
    },
    set: (ms) => {
      now = ms;
    },
  };
  const { store, control } = createMemoryStore({ now: () => now, ...options });
  return { store, control, clock };
}

/**
 * The factory the conformance harness calls once per case. `interleave`
 * suspends the primary call at its "before-apply" hook, runs the competing
 * call to completion, and lets the primary call continue.
 */
export async function conformanceFactory() {
  const { store, control, clock } = openStore();
  return {
    store,
    clock,
    secondStore: store,
    async interleave({ operation, primary, concurrent }) {
      const remove = control.onPhase(operation, "before-apply", async () => {
        remove();
        await concurrent(store);
      });
      try {
        return await primary();
      } finally {
        remove();
      }
    },
  };
}

export const scope = { namespace: "support-synthetic", tenant: "tenant-acme-synthetic" };
export const captureId = "cap_aaaaaaaaaaaaaaaaaaaaaaaaaa";
export const entryId = `${"0".repeat(63)}1`;

export function synthetic(length, fill) {
  return new Uint8Array(length).fill(fill);
}

export function captureInput(now, overrides = {}) {
  return {
    scope,
    epoch: 1,
    now,
    capture: {
      captureId,
      sessionTag: null,
      createdAt: now,
      expiresAt: now + 3_600_000,
      lookupVersion: 1,
      keyRef: "synthetic-key:v1",
      wrappedKey: synthetic(40, 0x11),
    },
    entries: [{ entryId, maxUses: 2, envelope: synthetic(24, 0x22) }],
    ...overrides,
  };
}

export function commitInput(now, overrides = {}) {
  return {
    scope,
    epoch: 1,
    now,
    attempt: { attemptId: "attempt-synthetic-1", requestDigest: synthetic(32, 0x33) },
    receiptExpiresAt: now + 2 * 3_600_000,
    captures: [{ captureId, generation: 1 }],
    uses: [{ entryId, captureId, count: 1, lifecycleRevision: 1, ciphertextRevision: 1 }],
    ...overrides,
  };
}
