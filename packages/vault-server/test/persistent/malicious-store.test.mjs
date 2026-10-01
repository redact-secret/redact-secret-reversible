// A store, or a crypto layer, that returns something false
// (docs/specs/persistent-vault.md §3.4, §10; issue #110 "malicious adapter
// return values"). The store beneath is honest at commit; what lies is the
// read. The outcome must always be a denial or INVARIANT_VIOLATION, never
// fields, and never a consumed use.
import assert from "node:assert/strict";
import test from "node:test";

import { RecordCryptoError } from "@redact-secret/vault-contracts";

import {
  captureOne,
  createRig,
  CTX_A,
  CTX_B,
  ctx,
  denied,
  DIGEST_KEY,
  digests,
  foreignError,
  NAMESPACE,
  OTHER_TENANT,
  registerLeakHygiene,
  rejects,
  restoreRequest,
  SECRET_A,
  SECRET_B,
  SECRET_C,
  TENANT,
} from "./helpers.mjs";

const S1 = "session-synthetic-0001";
const S2 = "session-synthetic-0002";

/** A shallow, independent copy of a readEntries result that a test may rewrite. */
function copyRead(read) {
  return {
    recovery: { ...read.recovery },
    entries: read.entries.map((entry) => ({ ...entry, envelope: new Uint8Array(entry.envelope) })),
    captures: read.captures.map((capture) => ({ ...capture, wrappedKey: new Uint8Array(capture.wrappedKey) })),
  };
}

/** Rewrites every later readEntries result with `rewrite(copy, input)`. */
function lie(rig, rewrite) {
  rig.spy.tamper.readEntries = async (result, input) => {
    const copy = copyRead(result);
    return (await rewrite(copy, input)) ?? copy;
  };
}

/**
 * One capture of two entries (a, b), a second capture of the same tenant (c),
 * and one capture of another tenant (x), all with budget to spare.
 */
async function scene(options = {}) {
  const rig = await createRig(options.rig ?? {});
  const context = options.session === undefined ? CTX_A : ctx({ session: options.session });
  const first = await captureOne(rig, { text: `a ${SECRET_A} b ${SECRET_B}`, maxUses: 4, context });
  const second = await captureOne(rig, { text: `c ${SECRET_C}`, maxUses: 4, context });
  const foreign = await captureOne(rig, { text: `x ${SECRET_C}`, maxUses: 4, context: CTX_B });
  const [a, b] = first.tokens.map(({ token }) => token);
  const c = second.tokens[0].token;
  const x = foreign.tokens[0].token;
  const request = (extra = {}) => restoreRequest(first, { context, fields: { body: a }, ...extra });
  const unused = async () => {
    assert.deepEqual(await rig.used([a, b, c]), [0, 0, 0], "nothing was consumed");
    assert.deepEqual(await rig.used([x], OTHER_TENANT), [0]);
    assert.equal(rig.memory.control.counts().receipts, 0);
  };
  return { rig, context, first, second, foreign, a, b, c, x, request, unused };
}

test("malicious read: the fault layer's malformed shapes never release anything", async () => {
  const expectations = {
    "wrong-types": ["INVARIANT_VIOLATION"],
    null: ["INVARIANT_VIOLATION"],
    "foreign-entry": ["INVARIANT_VIOLATION"],
    "mismatched-capture": ["INVARIANT_VIOLATION"],
    "missing-capture": ["INVARIANT_VIOLATION"],
    "duplicate-entry": ["INVARIANT_VIOLATION"],
    // The preflight is fooled; the store's own revision check at commit is not.
    "revision-lie": ["RESTORE_CONFLICT"],
  };
  for (const [shape, [code, reason]] of Object.entries(expectations)) {
    const s = await scene();
    s.rig.faults.add({ operation: "readEntries", fault: { kind: "malformed", shape } });
    await rejects(s.rig.vault.restore(s.request()), code, reason);
    await s.unused();
    if (code === "INVARIANT_VIOLATION") {
      assert.equal(s.rig.keys.stats.unwrap, 0, `${shape}: rejected before any key is unwrapped`);
      assert.equal(s.rig.spy.count("commitRestore"), 0);
    }
  }
});

test("malicious read: an exhausted entry presented as unused is still denied budget, by the commit", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await rig.vault.restore(restoreRequest(captured));
  rig.faults.add({ operation: "readEntries", fault: { kind: "malformed", shape: "budget-lie" } });
  // `used` alone: the revision still tells the truth, so the commit sees the budget.
  await denied(rig.vault.restore(restoreRequest(captured)), "budget");
  assert.deepEqual(rig.spy.last("commitRestore").result, { outcome: "rejected", reason: "budget" });
  // `used` and the revision both rolled back to the capture's first state: the commit is stale, forever.
  rig.faults.clear();
  lie(rig, (read) => {
    for (const entry of read.entries) {
      entry.used = 0;
      entry.lifecycleRevision = 1;
    }
  });
  await rejects(rig.vault.restore(restoreRequest(captured)), "RESTORE_CONFLICT");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
  assert.equal(rig.memory.control.counts().receipts, 1);
});

test("malicious read: an entry that was not asked for is INVARIANT_VIOLATION, even a real one of the same capture", async () => {
  const s = await scene();
  const real = (await s.rig.rows([s.b])).entries[0];
  lie(s.rig, (read) => {
    read.entries.push(real);
  });
  await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  assert.equal(s.rig.keys.stats.unwrap, 0);
  await s.unused();
});

test("malicious read: an entry attributed to another capture never authenticates", async () => {
  // Attributed to a capture the request also names, with that capture's row and key.
  const s = await scene();
  const other = (await s.rig.rows([s.c])).captures[0];
  lie(s.rig, (read) => {
    read.entries[0].captureId = s.second.captureId;
    read.captures = [other];
  });
  await denied(s.rig.vault.restore(s.request({ captures: [s.first.captureId, s.second.captureId] })), "integrity-failure");
  // Attributed to a capture the request does not name.
  await denied(s.rig.vault.restore(s.request()), "source");
  await s.unused();
  assert.equal(s.rig.spy.count("commitRestore"), 0);
});

test("malicious read: duplicate captures, and a live capture of another epoch, are INVARIANT_VIOLATION", async () => {
  const s = await scene();
  lie(s.rig, (read) => {
    read.captures.push({ ...read.captures[0] });
  });
  await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  for (const epoch of [2, 0, "1", undefined]) {
    lie(s.rig, (read) => {
      read.captures[0].epoch = epoch;
    });
    await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  }
  assert.equal(s.rig.keys.stats.unwrap, 0);
  await s.unused();
});

test("malicious read: a recovery state that does not match the configured epoch fails closed", async () => {
  const s = await scene();
  for (const recovery of [
    { epoch: 2, state: "serving" },
    { epoch: 1, state: "quarantined" },
    { epoch: 0, state: "uninitialized" },
  ]) {
    lie(s.rig, (read) => {
      read.recovery = recovery;
      // A store consistent with its own lie reports the captures under the same epoch.
      for (const capture of read.captures) capture.epoch = recovery.epoch;
    });
    await rejects(s.rig.vault.restore(s.request()), "STORE_QUARANTINED");
  }
  for (const recovery of [null, "serving", { state: "serving" }, { epoch: 1.5, state: "serving" }, { epoch: 1, state: 7 }]) {
    lie(s.rig, (read) => {
      read.recovery = recovery;
    });
    await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  }
  assert.equal(s.rig.keys.stats.unwrap, 0);
  await s.unused();
});

test("malicious read: every wrongly typed or out-of-range field is INVARIANT_VIOLATION before any unwrap", async () => {
  const s = await scene();
  const entryLies = [
    ["entryId", "f".repeat(63)],
    ["entryId", 7],
    ["captureId", "cap_short"],
    ["captureId", null],
    ["maxUses", 0],
    ["maxUses", 1001],
    ["maxUses", 1.5],
    ["maxUses", "4"],
    ["used", -1],
    ["used", "0"],
    ["used", 0.5],
    ["used", undefined],
    ["lifecycleRevision", 0],
    ["lifecycleRevision", "1"],
    ["ciphertextRevision", 0],
    ["ciphertextRevision", null],
    ["envelope", "envelope"],
    ["envelope", new Uint8Array(0)],
    ["envelope", new Uint8Array(1024 * 1024 + 64 * 1024 + 1)],
    ["envelope", [1, 2, 3]],
  ];
  for (const [field, value] of entryLies) {
    lie(s.rig, (read) => {
      read.entries[0][field] = value;
    });
    await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  }
  const captureLies = [
    ["captureId", "cap_short"],
    ["state", "LIVE"],
    ["state", undefined],
    ["generation", 0],
    ["generation", "1"],
    ["createdAt", -1],
    ["createdAt", 1.5],
    ["expiresAt", "later"],
    ["expiresAt", Number.POSITIVE_INFINITY],
    ["sessionTag", "zz"],
    ["sessionTag", undefined],
    ["sessionTag", 7],
    ["keyRef", ""],
    ["keyRef", 7],
    ["wrappedKey", new Uint8Array(0)],
    ["wrappedKey", "wrapped"],
  ];
  for (const [field, value] of captureLies) {
    lie(s.rig, (read) => {
      read.captures[0][field] = value;
    });
    await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  }
  for (const rewrite of [
    (read) => {
      read.entries = null;
    },
    (read) => {
      read.captures = "captures";
    },
    (read) => {
      read.entries = [null];
    },
    (read) => {
      read.captures = [null];
    },
    () => "read",
    () => 7,
  ]) {
    lie(s.rig, rewrite);
    await rejects(s.rig.vault.restore(s.request()), "INVARIANT_VIOLATION");
  }
  assert.equal(s.rig.keys.stats.unwrap, 0);
  assert.equal(s.rig.spy.count("commitRestore"), 0);
  await s.unused();
});

test("malicious read: an entry the store hides is unknown-token; an extra capture nobody uses changes nothing", async () => {
  const s = await scene();
  lie(s.rig, (read) => {
    read.entries = [];
    read.captures = [];
  });
  await denied(s.rig.vault.restore(s.request()), "unknown-token");
  await s.unused();

  const extra = (await s.rig.rows([s.c])).captures[0];
  lie(s.rig, (read) => {
    read.captures.push(extra);
  });
  const restored = await s.rig.vault.restore(s.request());
  assert.equal(restored.fields.body, SECRET_A);
  assert.deepEqual(s.rig.spy.last("commitRestore").input.captures.map((capture) => capture.captureId), [s.first.captureId]);
});

test("malicious read: envelopes swapped between two entries of one capture fail authentication", async () => {
  const s = await scene();
  lie(s.rig, (read) => {
    const [x, y] = read.entries;
    [x.envelope, y.envelope] = [y.envelope, x.envelope];
  });
  await denied(s.rig.vault.restore(s.request({ fields: { body: `${s.a} ${s.b}` } })), "integrity-failure");
  await s.unused();
  assert.equal(s.rig.spy.count("commitRestore"), 0);
  assert.equal(s.rig.policyCalls.length, 0, "the policy is never shown a record that did not authenticate");
});

test("malicious read: an envelope, or a wrapped key, moved in from another capture or tenant fails authentication", async () => {
  const s = await scene();
  const sameTenant = await s.rig.rows([s.c]);
  const otherTenant = await s.rig.rows([s.x], OTHER_TENANT);

  const substitutions = [
    // The other capture's envelope under this capture's key.
    (read) => {
      read.entries[0].envelope = sameTenant.entries[0].envelope;
    },
    (read) => {
      read.entries[0].envelope = otherTenant.entries[0].envelope;
    },
    // This capture's envelope under another capture's key.
    (read) => {
      read.captures[0].wrappedKey = sameTenant.captures[0].wrappedKey;
      read.captures[0].keyRef = sameTenant.captures[0].keyRef;
    },
    (read) => {
      read.captures[0].wrappedKey = otherTenant.captures[0].wrappedKey;
    },
    // Both moved together: a whole foreign record presented under this entry's identifier.
    (read) => {
      read.entries[0].envelope = otherTenant.entries[0].envelope;
      read.captures[0].wrappedKey = otherTenant.captures[0].wrappedKey;
    },
    (read) => {
      read.entries[0].envelope = sameTenant.entries[0].envelope;
      read.captures[0].wrappedKey = sameTenant.captures[0].wrappedKey;
    },
  ];
  for (const substitute of substitutions) {
    lie(s.rig, substitute);
    await denied(s.rig.vault.restore(s.request()), "integrity-failure");
  }
  // A whole foreign capture row and entry, relabelled with this capture's and entry's identifiers.
  lie(s.rig, (read) => {
    read.entries[0] = { ...otherTenant.entries[0], entryId: read.entries[0].entryId, captureId: s.first.captureId };
    read.captures[0] = { ...otherTenant.captures[0], captureId: s.first.captureId };
  });
  await denied(s.rig.vault.restore(s.request()), "integrity-failure");

  await s.unused();
  assert.equal(s.rig.spy.count("commitRestore"), 0);
  assert.equal(s.rig.policyCalls.length, 0);
});

test("malicious read: a key reference the provider does not hold is key-unavailable; the provider never tries another key", async () => {
  const s = await scene();
  for (const keyRef of ["local:synthetic-unknown", "kms:synthetic", "local:"]) {
    lie(s.rig, (read) => {
      read.captures[0].keyRef = keyRef;
    });
    await denied(s.rig.vault.restore(s.request()), "key-unavailable");
  }
  await s.unused();
});

test("malicious read: a corrupted, truncated, or re-versioned envelope is integrity-failure", async () => {
  const s = await scene();
  const corruptions = [
    (envelope) => {
      envelope[envelope.length - 1] ^= 0x01;
      return envelope;
    },
    (envelope) => {
      envelope[20] ^= 0x80;
      return envelope;
    },
    (envelope) => envelope.subarray(0, envelope.length - 1),
    (envelope) => envelope.subarray(0, 8),
    (envelope) => {
      envelope[4] = 2;
      return envelope;
    },
    (envelope) => {
      envelope[5] = 0;
      return envelope;
    },
    (envelope) => {
      envelope[0] ^= 0xff;
      return envelope;
    },
    (envelope) => new Uint8Array([...envelope, 0]),
    () => new Uint8Array(64),
  ];
  for (const corrupt of corruptions) {
    lie(s.rig, (read) => {
      read.entries[0].envelope = new Uint8Array(corrupt(read.entries[0].envelope));
    });
    await denied(s.rig.vault.restore(s.request()), "integrity-failure");
  }
  // A corrupted wrapped key.
  lie(s.rig, (read) => {
    read.captures[0].wrappedKey[10] ^= 0x01;
  });
  await denied(s.rig.vault.restore(s.request()), "integrity-failure");
  await s.unused();
  assert.equal(s.rig.spy.count("commitRestore"), 0);
});

test("malicious read: a changed expiresAt, createdAt, or maxUses fails authentication", async () => {
  const s = await scene();
  const realExpiry = s.first.expiresAt;
  // Past its real expiry, with the store claiming a later one.
  s.rig.clock.set(realExpiry + 1000);
  lie(s.rig, (read) => {
    read.captures[0].expiresAt = realExpiry + 60 * 60 * 1000;
  });
  await denied(s.rig.vault.restore(s.request()), "integrity-failure");

  const fresh = await scene();
  for (const change of [
    (read) => {
      read.captures[0].expiresAt += 1;
    },
    (read) => {
      read.captures[0].createdAt -= 1;
    },
    (read) => {
      read.captures[0].createdAt += 1;
    },
    (read) => {
      read.entries[0].maxUses = 1000;
    },
    (read) => {
      read.entries[0].maxUses = 1;
    },
  ]) {
    lie(fresh.rig, change);
    await denied(fresh.rig.vault.restore(fresh.request()), "integrity-failure");
  }
  await fresh.unused();
  await s.unused();
  assert.equal(fresh.rig.spy.count("commitRestore") + s.rig.spy.count("commitRestore"), 0);
});

test("malicious read: an exhausted entry presented with a raised maxUses and a reset counter is not released", async () => {
  const rig = await createRig();
  const captured = await captureOne(rig);
  await rig.vault.restore(restoreRequest(captured));
  lie(rig, (read) => {
    read.entries[0].maxUses = 1000;
    read.entries[0].used = 0;
  });
  await denied(rig.vault.restore(restoreRequest(captured)), "integrity-failure");
  assert.deepEqual(await rig.used([captured.tokens[0].token]), [1]);
});

test("malicious read: a session-bound capture presented as unbound fails authentication, from any session and from none", async () => {
  const s = await scene({ session: S1 });
  lie(s.rig, (read) => {
    for (const capture of read.captures) capture.sessionTag = null;
  });
  for (const context of [ctx({ session: S2 }), CTX_A, ctx({ session: S1 })]) {
    await denied(s.rig.vault.restore(s.request({ context })), "integrity-failure");
  }
  await s.unused();
  assert.equal(s.rig.spy.count("commitRestore"), 0);
  assert.equal(s.rig.policyCalls.length, 0);
});

test("malicious read: a session tag rewritten for the attacker's session passes the tag check and still fails authentication", async () => {
  const s = await scene({ session: S1 });
  const digester = await digests.createDigester(DIGEST_KEY);
  const forged = await digester.sessionTag({ namespace: NAMESPACE, tenant: TENANT, captureId: s.first.captureId, sessionId: S2 });
  lie(s.rig, (read) => {
    read.captures[0].sessionTag = forged;
  });
  await denied(s.rig.vault.restore(s.request({ context: ctx({ session: S2 }) })), "integrity-failure");
  // And an unbound capture given a tag is simply denied to everyone it does not match.
  const unbound = await scene();
  lie(unbound.rig, (read) => {
    read.captures[0].sessionTag = forged;
  });
  await denied(unbound.rig.vault.restore(unbound.request()), "source");
  await denied(unbound.rig.vault.restore(unbound.request({ context: ctx({ session: S2 }) })), "source");
  await s.unused();
  await unbound.unused();
});

test("malicious read: a revoked capture presented as live is denied by the commit", async () => {
  const s = await scene();
  await s.rig.vault.revoke({ context: CTX_A, captureId: s.first.captureId });
  const live = (await s.rig.rows([s.a])).captures[0];
  assert.equal(live.state, "revoked");
  lie(s.rig, (read) => {
    read.captures[0].state = "live";
  });
  await denied(s.rig.vault.restore(s.request()), "revoked");
  assert.deepEqual(s.rig.spy.last("commitRestore").result, { outcome: "rejected", reason: "revoked" });
  // With the generation rolled back as well, the commit still refuses.
  lie(s.rig, (read) => {
    read.captures[0].state = "live";
    read.captures[0].generation = 1;
  });
  await denied(s.rig.vault.restore(s.request()), "revoked");
  await s.unused();
});

test("malicious crypto layer: a result of the wrong length or shape, or a throw, releases nothing", async () => {
  const s = await scene();
  const real = s.rig.crypto;
  const payload = { value: new TextEncoder().encode("synthetic"), type: "synthetic-type", grants: [{ sink: "sink-a", paths: ["body"] }], policyRevision: null };
  const cases = [
    [() => [], "integrity-failure"],
    [() => [payload, payload], "integrity-failure"],
    [() => null, "integrity-failure"],
    [() => "payloads", "integrity-failure"],
    [() => ({ length: 1, 0: payload }), "integrity-failure"],
    [() => [null], "integrity-failure"],
    [() => ["payload"], "integrity-failure"],
    [() => [{ ...payload, value: "synthetic" }], "integrity-failure"],
    [() => [{ ...payload, value: [1, 2, 3] }], "integrity-failure"],
    [() => [{ ...payload, value: undefined }], "integrity-failure"],
    [() => [{ ...payload, type: 7 }], "integrity-failure"],
    [() => [{ ...payload, grants: "grants" }], "integrity-failure"],
    [() => [{ ...payload, grants: [null] }], "integrity-failure"],
    [() => [{ ...payload, grants: [{ sink: 7, paths: ["body"] }] }], "integrity-failure"],
    [() => [{ ...payload, grants: [{ sink: "sink-a", paths: "body" }] }], "integrity-failure"],
    [() => [{ ...payload, grants: [{ sink: "sink-a", paths: [7] }] }], "integrity-failure"],
    [() => [{ ...payload, policyRevision: 7 }], "integrity-failure"],
    [() => [{ ...payload, policyRevision: undefined }], "integrity-failure"],
    // Bytes that are not UTF-8 are never turned into a string with replacement characters.
    [() => [{ ...payload, value: new Uint8Array([0xff, 0xfe, 0xfd]) }], "integrity-failure"],
    [
      () => {
        throw new RecordCryptoError("RECORD_INTEGRITY");
      },
      "integrity-failure",
    ],
    [
      () => {
        throw new RecordCryptoError("RECORD_MALFORMED");
      },
      "integrity-failure",
    ],
    [
      () => {
        throw foreignError();
      },
      "key-unavailable",
    ],
    [() => new Promise(() => {}), "key-unavailable"],
  ];
  for (const [openCapture, reason] of cases) {
    const vault = await s.rig.open({ crypto: { ...real, openCapture }, cryptoTimeoutMs: 40 });
    await denied(vault.restore(s.request()), reason);
  }
  await s.unused();
  assert.equal(s.rig.spy.count("commitRestore"), 0);
});

test("malicious crypto layer: grants it invents are still only grants; the request's sink and path must be among them", async () => {
  const s = await scene();
  const real = s.rig.crypto;
  const vault = await s.rig.open({
    crypto: {
      ...real,
      openCapture: async (input, options) =>
        (await real.openCapture(input, options)).map((payload) => ({ ...payload, grants: [{ sink: "sink-z", paths: ["body"] }] })),
    },
  });
  await denied(vault.restore(s.request()), "sink-or-path");
  await s.unused();
});

registerLeakHygiene({ minErrors: 100 });
