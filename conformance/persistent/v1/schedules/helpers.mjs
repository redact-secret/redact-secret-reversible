// Authoring helpers for generate-schedules.mjs. They only build plain JSON.

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
/** The skew bound plus a margin: a `now` this far from the store clock is always rejected. */
export const FARSKEW = { $add: ["{SKEW}", "{FAR}"] };

export function slug(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 90);
}

/** `adder(group, list)(name, steps, options)` appends one case that mirrors the native case `group: name`. */
export function adder(group, list) {
  return (name, steps, options = {}) => {
    const { requires, actors, native = `${group}: ${name}`, level = "store", server } = options;
    const item = { id: `${group}.${slug(name)}`, group, level, title: name };
    if (native !== null) item.native = native;
    if (requires !== undefined) item.requires = requires;
    if (actors !== undefined) item.actors = actors;
    if (server !== undefined) item.server = server;
    item.steps = steps;
    list.push(item);
  };
}

// ---- steps ---------------------------------------------------------------

export const serving = (epoch = 1, ns = "{NS}") => ({
  op: "initializeNamespace",
  input: { namespace: ns, epoch },
  expect: { outcome: "initialized" },
  what: "initializeNamespace of a fresh namespace",
});

export const create = (name, options = {}) => ({ create: name, options });
export const createExpired = (name, options = {}) => ({ createExpired: name, options });
export const buildCapture = (as, options = {}) => ({ build: "capture", as, options });

/** `uses` entries: a capture variable name, or `{capture, entry, count}`. */
export const buildCommit = (as, uses, extra = {}) => ({
  build: "commit",
  as,
  uses: uses.map((use) => (typeof use === "string" ? { capture: use } : use)),
  ...extra,
});

export const commitOk = (input, what = "commitRestore of a valid restore") => ({
  op: "commitRestore",
  input: `{${input}}`,
  expect: { outcome: "committed" },
  what,
});

export const rejectedWith = (reasons) => ({
  outcome: "rejected",
  reason: typeof reasons === "string" ? reasons : { $in: reasons },
});

export const expectRejected = (op, input, reasons, what, extra = {}) => ({
  op,
  input,
  expect: rejectedWith(reasons),
  what,
  ...extra,
});

export const expectOutcome = (op, input, outcome, what, extra = {}) => ({
  op,
  input,
  expect: { outcome },
  what,
  ...extra,
});

export const expectThrows = (op, input, codes, what, extra = {}) => ({ op, input, expectError: codes, what, ...extra });

export const revokeIn = (handle, { fence = false, retention = DAY, scope, now } = {}) => ({
  scope: scope ?? `{${handle}.scope}`,
  captureId: `{${handle}.captureId}`,
  now: now ?? { $now: 0 },
  retentionMs: retention,
  fenceAbsent: fence,
});

export const revokeOk = (handle, what = "revokeCapture of a live capture") =>
  expectOutcome("revokeCapture", revokeIn(handle), "revoked", what);

export const deleteIn = (handle, now = { $now: 0 }) => ({ scope: `{${handle}.scope}`, captureId: `{${handle}.captureId}`, now });

export const entry = (name, handle, index = 0) => ({ entry: name, of: handle, index });
export const captureRow = (name, handle) => ({ captureRow: name, of: handle });
export const snapshot = (name, handles) => ({ snapshot: name, captures: handles });
export const same = (name, handles, what) => ({ expectSnapshot: name, captures: handles, what });

export const eq = (a, b, what) => ({ check: { $eq: [a, b] }, what });
export const lte = (a, b, what) => ({ check: { $lte: [a, b] }, what });
export const gte = (a, b, what) => ({ check: { $gte: [a, b] }, what });
export const check = (expression, what) => ({ check: expression, what });
export const matchValue = (value, pattern, what) => ({ check: { $match: [value, pattern] }, what });

export const readEntries = (scope, entryIds, extra = {}) => ({ op: "readEntries", input: { scope, entryIds }, ...extra });
export const readCaptures = (scope, captureIds, extra = {}) => ({ op: "readCaptures", input: { scope, captureIds }, ...extra });

export const inspect = (scope, attemptId, expect, what, extra = {}) => ({
  op: "inspectAttempt",
  input: { scope, attemptId },
  expect,
  what,
  ...extra,
});

/** The create inputs of an attempt that must leave no row: no capture row, no entry row. */
export const expectAbsent = (handle, what) => [
  readCaptures(`{${handle}.scope}`, [`{${handle}.captureId}`], { expect: { $length: 0 }, what: `${what}: no capture row may exist` }),
  readEntries(
    `{${handle}.scope}`,
    { $slice: [`{${handle}.entryIds}`, 0, "{CAPS.maxRestoreEntries}"] },
    { expect: { entries: { $length: 0 } }, what: `${what}: no entry row may exist` },
  ),
];

export const findEntry = (readVar, idExpression) => ({
  $find: { over: `{${readVar}.entries}`, where: { entryId: idExpression } },
});

/** A `$from` copy of a saved value with fields replaced. */
export const from = (source, set = {}, unset) => ({ $from: source, set, ...(unset === undefined ? {} : { unset }) });
export const src = (path) => ({ $src: path });
export const add = (...parts) => ({ $add: parts });
export const hexOf = (byte, times) => ({ $hex: { byte, times } });
export const bytes = (length, fill) => ({ $bytes: fill === undefined ? { length } : { length, fill } });
