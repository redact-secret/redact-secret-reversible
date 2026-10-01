// A `Store` over the harness's own reference model, for the harness's
// self-tests. It lives in the test directory on purpose: the published
// package ships the model, not a store, and no defect switch.
//
// `Model` may be a subclass of ReferenceModel with one decision broken.
// `staleCommitRead` and `staleCreateRead` make the store itself defective in
// the way §5.2 forbids: the operation decides on what it read before a
// concurrent writer committed.
import {
  validateCommitRestore,
  validateCreateCapture,
  validateDeleteCiphertext,
  validateInitializeNamespace,
  validateInspectAttempt,
  validateInvalidateRecovered,
  validateNamespace,
  validateReadCaptures,
  validateReadEntries,
  validateReplaceCaptureKey,
  validateRevokeCapture,
  validateSweep,
} from "@redact-secret/vault-contracts";

import { ReferenceModel } from "../dist/index.js";

export const START = 1_800_000_000_000;

const CAPABILITIES = Object.freeze({
  contractVersion: 1,
  adapter: "conformance-self-test",
  profile: "reference-model",
  atomicCreate: true,
  maxCreateEntries: 128,
  maxCreateBytes: 64 * 1024,
  atomicRestore: true,
  maxRestoreEntries: 64,
  maxRestoreCaptures: 8,
  authoritativeCommit: true,
  revocationFences: true,
  attemptReceipts: true,
  storeClock: true,
  maxClockSkewMs: 2000,
  durability: "volatile",
  crossProcess: false,
  restoreDetection: "none",
  maxEnvelopeBytes: 4096,
});

export function createModelStore({ Model = ReferenceModel, staleCommitRead = false, staleCreateRead = false, realClock = false } = {}) {
  let fixed = START;
  // `realClock` models a database: the store reads a clock the harness cannot move.
  const read = () => (realClock ? Date.now() : fixed);
  const clock = realClock
    ? null
    : {
        now: () => fixed,
        advance: (ms) => {
          fixed += ms;
        },
        set: (ms) => {
          fixed = ms;
        },
      };
  const model = new Model({ maxClockSkewMs: CAPABILITIES.maxClockSkewMs });
  const pauses = new Map();

  const validators = {
    createCapture: (input) => validateCreateCapture(input, CAPABILITIES),
    readEntries: (input) => validateReadEntries(input, CAPABILITIES),
    readCaptures: (input) => validateReadCaptures(input, CAPABILITIES),
    commitRestore: (input) => validateCommitRestore(input, CAPABILITIES),
    revokeCapture: validateRevokeCapture,
    inspectAttempt: validateInspectAttempt,
    replaceCaptureKey: validateReplaceCaptureKey,
    deleteCiphertext: validateDeleteCiphertext,
    sweepExpired: validateSweep,
    recoveryState: validateNamespace,
    initializeNamespace: validateInitializeNamespace,
    quarantine: validateNamespace,
    invalidateRecovered: validateInvalidateRecovered,
  };

  /** Applies `fn` with one model method temporarily replaced. */
  function withOverride(name, replacement, fn) {
    const original = model[name];
    model[name] = replacement;
    try {
      return fn();
    } finally {
      model[name] = original;
    }
  }

  const operation = (name) => async (input) => {
    validators[name](input);
    const snapshot = structuredClone(input);

    // What a defective store "read" before the concurrent writer ran.
    let apply = () => model[name](snapshot, read());
    if (name === "commitRestore" && staleCommitRead) {
      const seen = new Map(
        snapshot.captures.map(({ captureId }) => {
          const row = model.findCapture(snapshot.scope, captureId);
          return [captureId, row === undefined ? undefined : { ...row }];
        }),
      );
      const find = model.findCapture.bind(model);
      apply = () =>
        withOverride(
          "findCapture",
          (scope, captureId) => (seen.has(captureId) ? seen.get(captureId) : find(scope, captureId)),
          () => model.commitRestore(snapshot, read()),
        );
    }
    if (name === "createCapture" && staleCreateRead) {
      const blocked = model.notServing(snapshot.scope.namespace, snapshot.epoch);
      apply = () => withOverride("notServing", () => blocked, () => model.createCapture(snapshot, read()));
    }

    const pause = pauses.get(name);
    if (pause !== undefined) {
      pauses.delete(name);
      await pause();
    } else {
      await null;
    }
    return apply();
  };

  const store = { capabilities: () => CAPABILITIES };
  for (const name of Object.keys(validators)) store[name] = operation(name);

  async function interleave({ operation: name, primary, concurrent }) {
    pauses.set(name, () => concurrent(store));
    try {
      return await primary();
    } finally {
      pauses.delete(name);
    }
  }

  return { store, clock, model, interleave };
}

/** A conformance factory over a model class and store-level defects. */
export function modelFactory(options = {}) {
  return async () => {
    const { store, clock, interleave } = createModelStore(options);
    return { store, clock, secondStore: store, interleave };
  };
}
