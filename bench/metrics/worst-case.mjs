// B7 (#81): worst-case cost at the configured limits and on denial. The
// limits are the vault's DoS defense, so the time an input at (or just past)
// a limit costs is the real guarantee, not the 1 KiB median of B3.
//
// 1. Capture at the default limits (`createVault()` defaults), paired with
//    the core's own scan + redact of the same input as in B3, so each case
//    reports `<name>`, `<name>.core_ms`, and `<name>.vault_overhead_ms`:
//    - `capture.default.input-1MiB`: exactly `maxInputBytes` (1 MiB), four
//      findings, all retained.
//    - `capture.default.findings-1024`: exactly `maxFindings` (1024) findings
//      packed into 33 KiB; `eligible` retains the first 256 (`maxEntries`),
//      the rest become display placeholders.
//    - `capture.default.worst-1024f-1MiB`: both edges at once, 1024 findings
//      spread through 1 MiB, 256 retained. The core's scan and redact each
//      cost about (findings × input bytes), so this shape, not either edge
//      alone, is the slowest capture the defaults accept.
//    Rejected captures, one `vault.capture` that must fail:
//    - `capture.reject.input-over`: 1 MiB + 1 byte, LIMIT_EXCEEDED before the
//      core runs.
//    - `capture.reject.findings-over`: 1 MiB packed with ~31 775 findings,
//      CORE_FAILURE / FINDING_LIMIT_EXCEEDED from the core.
//    - `capture.reject.entries-over`: 1024 findings all retained,
//      LIMIT_EXCEEDED on `maxEntries` after the full scan.
//
// 2. Capture at the configured ceilings (`LIMIT_CEILINGS` for input bytes,
//    findings, entries, and retained bytes). These are too slow to sample:
//    one paired sample per side per process, reported as deterministic ms
//    values (`capture.ceiling.<shape>.ms`, `.core_ms`, `.vault_overhead_ms`).
//    `bench:compare` reads deterministic values from round 0 only, so later
//    rounds of the same side reuse the round-0 sample instead of paying for
//    it again (the value is identical by construction).
//    - `input-64MiB`: exactly 64 MiB, four findings.
//    - `findings-4096`: 4096 findings packed into 132 KiB, all retained.
//    The findings ceiling itself (50 000) is not run: at ~1.2 ms per
//    finding·MiB for the core it would take minutes to hours. Instead the
//    run fits core_ms ≈ a·MiB + b·findings·MiB from the default-limit cases
//    (`capture.model.*`), checks it against the measured `findings-4096`
//    ceiling case (`capture.model.check_ratio`, measured ÷ predicted), and
//    reports `capture.extrapolated.core_ms.<shape>` for 50 000 findings in
//    1 MiB (the default input limit) and in 64 MiB (all ceilings). These are
//    labeled extrapolations, not measurements.
//
// 3. Restore denials, one per reason, against a committed restore of the same
//    shape (`restore64` over a fresh `capture1k` capture: 64 fields, 16
//    occurrences per token). Each denial is placed as late as the reason
//    allows (the offending token or value is in `field_63`), so the figure is
//    the most preflight work a denied request can cause:
//    - vault: `restore.committed`, `restore.denied.<reason>` for
//      invalid-request, malformed-token, unknown-token, source, expired,
//      sink-or-path, budget; and `restore.committed.policy` /
//      `restore.denied.policy` on a vault with a release policy.
//    - vault-server: `server.restore.committed`, `server.restore.denied.<reason>`
//      for the vault's reasons plus unauthenticated, revoked,
//      tenant-mismatch, missing-purpose, and policy-evaluation-error.
//    - Largest request at the defaults: 64 fields of 1 MiB
//      (`maxRestoreFieldBytes`), one token at the end of each:
//      `[server.]restore.max-size.committed` and
//      `[server.]restore.max-size.denied.malformed-token` (a broken marker
//      at the end of the last field).
//
// 4. vault-server revocation memory (non-gating). With the default
//    `revocationMemoryMs` (the entry TTL) every revoked capture leaves a
//    tombstone that each capture/restore/revoke sweeps. For n recently
//    revoked captures (0, 1000, 10 000; quick 0, 250), filled untimed with
//    one-finding captures: `server.<op>.revoked-<n>` and the slope
//    `server.<op>.ms_per_1k_revoked`. The sweep cost depends on how many
//    tombstones are alive, not on the memory length, so the level is held at
//    exactly n with a rolling window on a fake clock: one revoke per 1 ms and
//    `revocationMemoryMs` = n ms. With the default memory (10 minutes), n is
//    the number of captures revoked in the last 10 minutes. Timed captures
//    are consumed by a restore (no tombstone) instead of revoked; each timed
//    revoke first advances the clock one step, so the oldest tombstone ages
//    out and the level is n - 1 before and n after it. The server's clock is
//    monotonic, so the level cannot be held by moving time backwards.
//
// Inputs. `corpus-v1` is unchanged; the large inputs are generated here,
// deterministically: lines `key AKIASYNTHETIC<7 base-36 chars> retired`
// (the B4 fill value, detected as `aws_access_key_id` / `redact`) and a
// fixed English filler sentence with no digits or key-like words. Every
// iteration checks the finding, entry, or error outcome, so a changed
// detection fails the metric instead of timing another path. No input,
// token, or restored value is returned.
//
// PII off only. Iteration counts per case are capped by ctx.iterations and
// ctx.warmup, so `--iterations` lowers them; quick mode uses fewer and a
// smaller worst-case shape and ceiling input.

import { fillInput, linearSlope } from "./entry-scaling.mjs";
import { median } from "../lib/stats.mjs";

export const id = "worst-case";
export const issue = 81;
export const title = "Worst-case cost at configured limits and on denial";
export const piiModes = ["off"];

const SINK = "bench-sink";
const PURPOSE = "bench-purpose";
const TENANT = "bench-tenant";
const MIB = 1024 * 1024;
const FILL_LINE_BYTES = 33;
const FILLER_SENTENCE = "the team will review the weekly notes and share the draft summary after the meeting.\n";
const DENIED_FIELD = "field_63";

/** Per-case sample counts: [iterations, warmup] in full and quick mode. */
const COUNTS = Object.freeze({
  input: { full: [10, 1], quick: [3, 1] },
  findings: { full: [30, 3], quick: [5, 1] },
  worst: { full: [3, 1], quick: [2, 1] },
  rejectInput: { full: [200, 20], quick: [20, 2] },
  rejectFindings: { full: [10, 1], quick: [3, 1] },
  rejectEntries: { full: [30, 3], quick: [5, 1] },
  maxSize: { full: [6, 1], quick: [3, 1] },
  denial: { full: [500, 100], quick: [50, 10] },
});

/** Shapes that differ between full and quick mode. */
const SHAPES = Object.freeze({
  full: { worst: { findings: 1024, bytes: MIB }, ceilingInput: 64 * MIB, ceilingFindings: 4096, revoked: [0, 1000, 10_000] },
  quick: { worst: { findings: 1024, bytes: 128 * 1024 }, ceilingInput: 4 * MIB, ceilingFindings: 2048, revoked: [0, 250] },
});
/** Iteration share per revoked-capture fill level. */
const REVOKED_SHARE = Object.freeze({ 0: 0.5, 250: 1, 1000: 0.25, 10000: 0.1 });

/** Fake-clock time between revokes in the revocation-memory window. */
const REVOKE_STEP_MS = 1;

/** Round-0 ceiling samples per side (see header, section 2). */
const ceilingCache = new Map();

function expectCount(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${expected}, got ${actual}`);
}

function countsFor(ctx, key, share = 1) {
  const [iterations, warmup] = COUNTS[key][ctx.quick ? "quick" : "full"];
  return {
    iterations: Math.max(1, Math.min(ctx.iterations, Math.round(iterations * share))),
    warmup: Math.min(ctx.warmup, Math.round(warmup * share)),
  };
}

function sizeLabel(bytes) {
  return bytes % MIB === 0 ? `${bytes / MIB}MiB` : `${bytes / 1024}KiB`;
}

/** Exactly `bytes` of filler text. */
function filler(bytes) {
  if (bytes <= 0) return "";
  const text = FILLER_SENTENCE.repeat(Math.ceil(bytes / FILLER_SENTENCE.length)).slice(0, bytes - 1);
  return `${text}\n`;
}

/** Forces a flat string so flattening a rope is not timed inside an operation. */
function flat(text) {
  /^/.test(text);
  return text;
}

/**
 * Exactly `bytes` of text holding `findings` distinct synthetic AWS key ids,
 * spread evenly (each followed by filler to its share of the bytes).
 */
export function spreadInput(findings, bytes) {
  const lines = fillInput(0, findings);
  const per = Math.floor(bytes / findings);
  if (per < FILL_LINE_BYTES) throw new RangeError("too many findings for the input size");
  let text = "";
  for (let i = 0; i < findings; i += 1) {
    const line = lines.slice(i * FILL_LINE_BYTES, (i + 1) * FILL_LINE_BYTES);
    const size = i === findings - 1 ? bytes - text.length - line.length : per - line.length;
    text += line + filler(size);
  }
  return flat(text);
}

/** Exactly `bytes` of text: `count` packed key lines, then filler. */
export function packedInput(count, bytes = count * FILL_LINE_BYTES) {
  return flat(fillInput(0, count) + filler(bytes - count * FILL_LINE_BYTES));
}

/** Capture options that retain at most `limit` findings (the first ones). */
function retainFirst(limit) {
  let kept = 0;
  return {
    release: [{ sink: SINK, paths: ["body"] }],
    eligible: () => {
      kept += 1;
      return kept <= limit;
    },
  };
}

function captureLimits(limits) {
  return { maxInputBytes: limits.maxInputBytes, maxFindings: limits.maxFindings };
}

function coreScanRedact(core, input, limits) {
  const findings = core.scan(input, { limits });
  core.redact(input, findings, { placeholderFormatter: core.defaultPlaceholderFormatter, limits });
  return findings.length;
}

/** Paired core vs capture on one vault, as in B3. */
async function pairedCapture(ctx, vault, { input, findings, retained, limits, options, counts }) {
  const coreLimits = captureLimits(limits);
  return ctx.samplePaired({
    ...counts,
    setup: () => ({ options: options() }),
    a: (state) => {
      state.coreFindings = coreScanRedact(ctx.core, input, coreLimits);
    },
    b: (state) => {
      state.captured = vault.capture(input, state.options);
    },
    teardown: (state) => {
      expectCount(state.coreFindings, findings, "core findings");
      expectCount(state.captured.tokens.length, retained, "retained entries");
      expectCount(state.captured.tokens.length + state.captured.unrestorable, findings, "capture findings");
      vault.revoke(state.captured.captureId);
    },
  });
}

function splitMeasurements(name, paired, params, { gateOverhead }) {
  return [
    { name, kind: "latency", unit: "ms", samples: paired.b, params, gating: false },
    { name: `${name}.core_ms`, kind: "latency", unit: "ms", samples: paired.a, params, gating: false },
    { name: `${name}.vault_overhead_ms`, kind: "latency", unit: "ms", samples: paired.diff, params, gating: gateOverhead },
  ];
}

function expectVaultError(fn, code, detail) {
  try {
    fn();
  } catch (error) {
    if (error?.code !== code) throw new Error(`expected ${code}, got ${error?.code ?? error?.name}`);
    if (detail !== undefined && error.coreCode !== detail) throw new Error(`expected ${detail}, got ${error.coreCode}`);
    return;
  }
  throw new Error(`expected ${code}, got success`);
}

async function rejectedCapture(ctx, vault, name, { input, code, coreCode, counts, params, gating }) {
  const options = { release: [{ sink: SINK, paths: ["body"] }] };
  const samples = await ctx.sample({
    ...counts,
    op: () => {
      try {
        vault.capture(input, options);
      } catch (error) {
        return error;
      }
      return null;
    },
    teardown: () => expectCount(vault.stats().entries, 0, "entries after rejected capture"),
  });
  // One untimed check of the outcome (the timed op returns it, but sample()
  // does not surface return values).
  expectVaultError(() => vault.capture(input, options), code, coreCode);
  return { name, kind: "latency", unit: "ms", samples, params, gating };
}

async function measureDefaultCaptures(ctx, shapes) {
  const limits = ctx.vault.DEFAULT_LIMITS;
  const vault = await ctx.vault.createVault();
  const raw = [];
  const model = {};
  try {
    const all = () => ({ release: [{ sink: SINK, paths: ["body"] }] });

    const inputBytes = limits.maxInputBytes;
    const input1 = spreadInput(4, inputBytes);
    const p1 = await pairedCapture(ctx, vault, {
      input: input1,
      findings: 4,
      retained: 4,
      limits,
      options: all,
      counts: countsFor(ctx, "input"),
    });
    raw.push(...splitMeasurements(`capture.default.input-${sizeLabel(inputBytes)}`, p1, { inputBytes, findings: 4, retained: 4 }, { gateOverhead: true }));
    model.inputCore = { mib: inputBytes / MIB, findings: 4, ms: median(p1.a) };

    const maxF = limits.maxFindings;
    const input2 = packedInput(maxF);
    const p2 = await pairedCapture(ctx, vault, {
      input: input2,
      findings: maxF,
      retained: limits.maxEntries,
      limits,
      options: () => retainFirst(limits.maxEntries),
      counts: countsFor(ctx, "findings"),
    });
    raw.push(
      ...splitMeasurements(`capture.default.findings-${maxF}`, p2, { inputBytes: input2.length, findings: maxF, retained: limits.maxEntries }, { gateOverhead: true }),
    );

    const { findings: wf, bytes: wb } = shapes.worst;
    const input3 = spreadInput(wf, wb);
    const p3 = await pairedCapture(ctx, vault, {
      input: input3,
      findings: wf,
      retained: limits.maxEntries,
      limits,
      options: () => retainFirst(limits.maxEntries),
      counts: countsFor(ctx, "worst"),
    });
    raw.push(
      ...splitMeasurements(`capture.default.worst-${wf}f-${sizeLabel(wb)}`, p3, { inputBytes: wb, findings: wf, retained: limits.maxEntries }, { gateOverhead: false }),
    );
    model.worstCore = { mib: wb / MIB, findings: wf, ms: median(p3.a) };

    raw.push(
      await rejectedCapture(ctx, vault, "capture.reject.input-over", {
        input: flat(`${input1}x`),
        code: "LIMIT_EXCEEDED",
        counts: countsFor(ctx, "rejectInput"),
        params: { inputBytes: inputBytes + 1 },
        gating: true,
      }),
    );
    const packedCount = Math.floor(inputBytes / FILL_LINE_BYTES);
    raw.push(
      await rejectedCapture(ctx, vault, "capture.reject.findings-over", {
        input: packedInput(packedCount, inputBytes),
        code: "CORE_FAILURE",
        coreCode: "FINDING_LIMIT_EXCEEDED",
        counts: countsFor(ctx, "rejectFindings"),
        params: { inputBytes, findings: packedCount },
        gating: false,
      }),
    );
    raw.push(
      await rejectedCapture(ctx, vault, "capture.reject.entries-over", {
        input: input2,
        code: "LIMIT_EXCEEDED",
        counts: countsFor(ctx, "rejectEntries"),
        params: { inputBytes: input2.length, findings: maxF, maxEntries: limits.maxEntries },
        gating: false,
      }),
    );
  } finally {
    vault.dispose();
  }
  return { raw, model };
}

async function sampleCeilings(ctx, shapes) {
  const C = ctx.vault.LIMIT_CEILINGS;
  const limits = {
    maxInputBytes: C.maxInputBytes,
    maxFindings: C.maxFindings,
    maxEntries: C.maxEntries,
    maxRetainedBytes: C.maxRetainedBytes,
  };
  const vault = await ctx.vault.createVault({ limits });
  const once = { iterations: 1, warmup: 0 };
  const all = () => ({ release: [{ sink: SINK, paths: ["body"] }] });
  try {
    const bytes = shapes.ceilingInput;
    const pInput = await pairedCapture(ctx, vault, { input: spreadInput(4, bytes), findings: 4, retained: 4, limits, options: all, counts: once });
    const nf = shapes.ceilingFindings;
    const inputF = packedInput(nf);
    const pFindings = await pairedCapture(ctx, vault, { input: inputF, findings: nf, retained: nf, limits, options: all, counts: once });
    return [
      { shape: `input-${sizeLabel(bytes)}`, paired: pInput, params: { inputBytes: bytes, findings: 4, retained: 4 } },
      { shape: `findings-${nf}`, paired: pFindings, params: { inputBytes: inputF.length, findings: nf, retained: nf }, mib: inputF.length / MIB, findings: nf },
    ];
  } finally {
    vault.dispose();
  }
}

async function measureCeilings(ctx, shapes, model) {
  const key = `${ctx.side.label}/${ctx.pii.mode}/${ctx.quick}`;
  if (ctx.round === 0 || !ceilingCache.has(key)) ceilingCache.set(key, await sampleCeilings(ctx, shapes));
  const cases = ceilingCache.get(key);
  const raw = [];
  for (const c of cases) {
    const params = { ...c.params, samples: 1 };
    const [a] = c.paired.a;
    const [b] = c.paired.b;
    raw.push(
      { name: `capture.ceiling.${c.shape}.ms`, kind: "deterministic", unit: "ms", value: b, params, gating: false },
      { name: `capture.ceiling.${c.shape}.core_ms`, kind: "deterministic", unit: "ms", value: a, params, gating: false },
      { name: `capture.ceiling.${c.shape}.vault_overhead_ms`, kind: "deterministic", unit: "ms", value: b - a, params, gating: false },
    );
  }

  // core_ms ≈ a·MiB + b·findings·MiB, from the two default-limit shapes.
  const perMib = model.inputCore.ms / model.inputCore.mib;
  const w = model.worstCore;
  const perFindingMib = Math.max(0, (w.ms - perMib * w.mib) / (w.findings * w.mib));
  const predict = (mib, findings) => perMib * mib + perFindingMib * findings * mib;
  const check = cases.find((c) => c.findings !== undefined);
  const modelParams = { fit: "default input + worst shapes, p50 core_ms" };
  raw.push(
    { name: "capture.model.core_ms_per_mib", kind: "deterministic", unit: "ms", value: perMib, params: modelParams, gating: false },
    { name: "capture.model.core_ms_per_finding_mib", kind: "deterministic", unit: "ms", value: perFindingMib, params: modelParams, gating: false },
    {
      name: "capture.model.check_ratio",
      kind: "deterministic",
      unit: "ratio",
      value: check.paired.a[0] / predict(check.mib, check.findings),
      params: { of: `measured / predicted core_ms, ${check.shape}` },
      gating: false,
    },
  );
  const C = ctx.vault.LIMIT_CEILINGS;
  const D = ctx.vault.DEFAULT_LIMITS;
  for (const [label, bytes] of [
    [sizeLabel(D.maxInputBytes), D.maxInputBytes],
    [sizeLabel(C.maxInputBytes), C.maxInputBytes],
  ]) {
    raw.push({
      name: `capture.extrapolated.core_ms.${C.maxFindings}f-${label}`,
      kind: "deterministic",
      unit: "ms",
      value: predict(bytes / MIB, C.maxFindings),
      params: { inputBytes: bytes, findings: C.maxFindings, extrapolated: true },
      gating: false,
    });
  }
  return raw;
}

// ---- restore denials -------------------------------------------------------

function buildFields(templates, tokens) {
  const fields = {};
  for (const f of templates) fields[f.path] = f.before + tokens[f.slot].token + f.after;
  return fields;
}

/** A well-formed token that is not issued: the last body character changed. */
function unknownToken(token) {
  const body = token.slice(0, -2);
  const last = token.at(-2);
  return `${body}${last === "a" ? "b" : "a"}>`;
}

/** The token with its marker upper-cased: a marker without a valid token. */
function malformedToken(token) {
  return token.toUpperCase();
}

function replaceInField(fields, path, from, to) {
  return { ...fields, [path]: fields[path].replace(from, to) };
}

function slotOf(templates, path) {
  return templates.find((f) => f.path === path).slot;
}

/**
 * Denial cases for the plain vault. Each returns `{ options, request(captured) }`:
 * capture options for the setup capture and the request to time.
 */
function vaultDenialCases(templates, usesPerToken) {
  const paths = templates.map((f) => f.path);
  const slot = slotOf(templates, DENIED_FIELD);
  const base = { release: [{ sink: SINK, paths }], maxUses: usesPerToken };
  const committed = (captured) => ({ sink: SINK, captures: [captured.captureId], fields: buildFields(templates, captured.tokens) });
  const token = (captured) => captured.tokens[slot].token;
  return {
    committed: { options: base, request: committed },
    "invalid-request": {
      options: base,
      request: (c) => ({ ...committed(c), fields: { ...committed(c).fields, [DENIED_FIELD]: 63 } }),
    },
    "malformed-token": {
      options: base,
      request: (c) => ({ ...committed(c), fields: replaceInField(committed(c).fields, DENIED_FIELD, token(c), malformedToken(token(c))) }),
    },
    "unknown-token": {
      options: base,
      request: (c) => ({ ...committed(c), fields: replaceInField(committed(c).fields, DENIED_FIELD, token(c), unknownToken(token(c))) }),
    },
    source: { options: base, request: (c) => ({ ...committed(c), captures: ["bench-other-capture"] }) },
    expired: { options: base, request: committed, expire: true },
    "sink-or-path": {
      options: { ...base, release: [{ sink: SINK, paths: paths.filter((p) => p !== DENIED_FIELD) }] },
      request: committed,
    },
    budget: { options: { ...base, maxUses: usesPerToken - 1 }, request: committed },
  };
}

function expectDenied(result, reason) {
  if (result.error === undefined) throw new Error(`expected denial ${reason}, got success`);
  const got = result.error.reason ?? result.error.code ?? result.error.name;
  if (got !== reason) throw new Error(`expected denial ${reason}, got ${got}`);
}

async function timeRestoreCase(ctx, vault, clock, name, c, { expected, params, counts, gating = true }) {
  const samples = await ctx.sample({
    ...counts,
    setup: () => {
      const captured = vault.capture(ctx.corpus.items.capture1k.input, c.options);
      const request = c.request(captured);
      if (c.expire) clock.t += clock.entryTtlMs;
      return { captureId: captured.captureId, request, result: {} };
    },
    op: (state) => {
      try {
        state.result.restored = vault.restore(state.request).restored;
      } catch (error) {
        state.result.error = error;
      }
    },
    teardown: (state) => {
      if (expected === "committed") {
        if (state.result.error !== undefined) throw state.result.error;
        expectCount(state.result.restored, 64, "restored occurrences");
      } else {
        expectDenied(state.result, expected);
      }
      vault.revoke(state.captureId);
      clock.t += 1;
    },
  });
  return { name, kind: "latency", unit: "ms", samples, params, gating };
}

function fakeClock(entryTtlMs) {
  const clock = { t: 1_000_000, entryTtlMs };
  clock.now = () => clock.t;
  return clock;
}

async function measureVaultDenials(ctx) {
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;
  const C = ctx.vault.LIMIT_CEILINGS;
  const entryTtlMs = 1000;
  const limits = { entryTtlMs, vaultTtlMs: C.vaultTtlMs };
  const counts = countsFor(ctx, "denial");
  const params = { fields: templates.length, tokenOccurrences: templates.length, deniedField: DENIED_FIELD };
  const raw = [];

  const clock = fakeClock(entryTtlMs);
  const vault = await ctx.vault.createVault({ limits, now: clock.now });
  try {
    for (const [reason, c] of Object.entries(vaultDenialCases(templates, usesPerToken))) {
      const name = reason === "committed" ? "restore.committed" : `restore.denied.${reason}`;
      raw.push(await timeRestoreCase(ctx, vault, clock, name, c, { expected: reason, params, counts }));
    }
  } finally {
    vault.dispose();
  }

  // Release policy: allow everything except DENIED_FIELD in the denied case.
  const policyClock = fakeClock(entryTtlMs);
  const policy = { deny: false };
  const policyVault = await ctx.vault.createVault({
    limits,
    now: policyClock.now,
    releasePolicy: (req) => !(policy.deny && req.path === DENIED_FIELD),
  });
  try {
    const { committed } = vaultDenialCases(templates, usesPerToken);
    policy.deny = false;
    raw.push(await timeRestoreCase(ctx, policyVault, policyClock, "restore.committed.policy", committed, { expected: "committed", params, counts }));
    policy.deny = true;
    raw.push(await timeRestoreCase(ctx, policyVault, policyClock, "restore.denied.policy", committed, { expected: "policy", params, counts }));
  } finally {
    policyVault.dispose();
  }
  return raw;
}

// ---- vault-server denials --------------------------------------------------

const REQUEST_CONTEXT = Object.freeze({ tenant: TENANT });
const FAILING_CONTEXT = Object.freeze({ tenant: TENANT, fail: true });

function resolvePrincipal(context) {
  if (context.fail === true) throw new Error("bench: principal not resolved");
  return { id: "bench-principal", tenant: context.tenant };
}

async function createBenchServer(ctx, { clock, policyMode, entryTtlMs, revocationMemoryMs }) {
  const C = ctx.vault.LIMIT_CEILINGS;
  return ctx.vaultServer.createServerVault({
    resolvePrincipal,
    policy: (input) => {
      if (input.path === DENIED_FIELD && policyMode.value === "policy") return { allow: false, reason: "policy" };
      if (input.path === DENIED_FIELD && policyMode.value === "throw") throw new Error("bench: policy failure");
      return { allow: true };
    },
    now: clock.now,
    limits: { ...(entryTtlMs === undefined ? {} : { entryTtlMs }), vaultTtlMs: C.vaultTtlMs },
    ...(revocationMemoryMs === undefined ? {} : { revocationMemoryMs }),
  });
}

function serverDenialCases(templates, usesPerToken) {
  const paths = templates.map((f) => f.path);
  const slot = slotOf(templates, DENIED_FIELD);
  const base = { release: [{ sink: SINK, paths }], maxUses: usesPerToken, issuedTenant: TENANT };
  const committed = (c) => ({
    context: REQUEST_CONTEXT,
    sink: SINK,
    purpose: PURPOSE,
    captures: [c.captureId],
    fields: buildFields(templates, c.tokens),
  });
  const token = (c) => c.tokens[slot].token;
  const withField = (c, to) => ({ ...committed(c), fields: replaceInField(committed(c).fields, DENIED_FIELD, token(c), to) });
  return {
    committed: { options: base, request: committed },
    "invalid-request": { options: base, request: (c) => ({ ...committed(c), fields: { ...committed(c).fields, [DENIED_FIELD]: 63 } }) },
    unauthenticated: { options: base, request: (c) => ({ ...committed(c), context: FAILING_CONTEXT }) },
    "malformed-token": { options: base, request: (c) => withField(c, malformedToken(token(c))) },
    "unknown-token": { options: base, request: (c) => withField(c, unknownToken(token(c))) },
    // A second, revoked capture's token in the last field.
    revoked: { options: base, request: (c, revokedToken) => ({ ...withField(c, revokedToken), captures: [c.captureId, c.revokedId] }), revokedSecond: true },
    source: { options: base, request: (c) => ({ ...committed(c), captures: ["bench-other-capture"] }) },
    "tenant-mismatch": { options: base, request: (c) => ({ ...committed(c), tenant: "bench-other-tenant" }) },
    expired: { options: base, request: committed, expire: true },
    "sink-or-path": { options: { ...base, release: [{ sink: SINK, paths: paths.filter((p) => p !== DENIED_FIELD) }] }, request: committed },
    "missing-purpose": { options: base, request: (c) => ({ ...committed(c), purpose: "" }) },
    budget: { options: { ...base, maxUses: usesPerToken - 1 }, request: committed },
    policy: { options: base, request: committed, policyMode: "policy" },
    "policy-evaluation-error": { options: base, request: committed, policyMode: "throw" },
  };
}

async function measureServerDenials(ctx) {
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;
  const item = ctx.corpus.items.capture1k;
  const entryTtlMs = 1000;
  const counts = countsFor(ctx, "denial");
  const params = { fields: templates.length, tokenOccurrences: templates.length, deniedField: DENIED_FIELD };
  const clock = fakeClock(entryTtlMs);
  const policyMode = { value: "allow" };
  // Revocation memory of 1 ms on the fake clock: a tombstone lives for the
  // iteration that made it and is swept at the next one.
  const server = await createBenchServer(ctx, { clock, policyMode, entryTtlMs, revocationMemoryMs: 1 });
  const raw = [];
  try {
    for (const [reason, c] of Object.entries(serverDenialCases(templates, usesPerToken))) {
      const name = reason === "committed" ? "server.restore.committed" : `server.restore.denied.${reason}`;
      policyMode.value = c.policyMode ?? "allow";
      const samples = await ctx.sample({
        ...counts,
        setup: async () => {
          const captured = await server.capture(item.input, c.options);
          let request;
          if (c.revokedSecond) {
            const second = await server.capture(item.input, c.options);
            await server.revoke(second.captureId);
            request = c.request({ ...captured, revokedId: second.captureId }, second.tokens[0].token);
          } else {
            request = c.request(captured);
          }
          if (c.expire) clock.t += entryTtlMs;
          return { captureId: captured.captureId, request, result: {} };
        },
        op: async (state) => {
          try {
            state.result.restored = (await server.restore(state.request)).restored;
          } catch (error) {
            state.result.error = error;
          }
        },
        teardown: async (state) => {
          if (reason === "committed") {
            if (state.result.error !== undefined) throw state.result.error;
            expectCount(state.result.restored, 64, "restored occurrences");
          } else {
            expectDenied(state.result, reason);
          }
          await server.revoke(state.captureId);
          clock.t += 2;
        },
      });
      raw.push({ name, kind: "latency", unit: "ms", samples, params, gating: true });
    }
  } finally {
    await server.dispose();
  }
  return raw;
}

// ---- largest restore request at the defaults -------------------------------

async function measureMaxSizeRestore(ctx) {
  const D = ctx.vault.DEFAULT_LIMITS;
  const item = ctx.corpus.items.capture1k;
  const fieldsCount = D.maxRestoreFields;
  const tokenCount = item.findings.piiOff;
  const usesPerToken = fieldsCount / tokenCount;
  const paths = Array.from({ length: fieldsCount }, (_, i) => `field_${String(i).padStart(2, "0")}`);
  // Filler sized so that filler + token is exactly maxRestoreFieldBytes.
  const tokenLength = 32;
  const pad = filler(D.maxRestoreFieldBytes - tokenLength);
  const fieldsFor = (tokens, broken) => {
    const fields = {};
    paths.forEach((path, i) => {
      const token = tokens[i % tokenCount].token;
      fields[path] = flat(pad + (broken && i === fieldsCount - 1 ? malformedToken(token) : token));
    });
    return fields;
  };
  const counts = countsFor(ctx, "maxSize");
  const params = { fields: fieldsCount, fieldBytes: D.maxRestoreFieldBytes, tokenOccurrences: fieldsCount };
  const release = [{ sink: SINK, paths }];
  const raw = [];

  const vault = await ctx.vault.createVault();
  try {
    for (const broken of [false, true]) {
      const samples = await ctx.sample({
        ...counts,
        setup: () => {
          const captured = vault.capture(item.input, { release, maxUses: usesPerToken });
          expectCount(captured.tokens[0].token.length, tokenLength, "token length");
          return { captureId: captured.captureId, request: { sink: SINK, captures: [captured.captureId], fields: fieldsFor(captured.tokens, broken) }, result: {} };
        },
        op: (state) => {
          try {
            state.result.restored = vault.restore(state.request).restored;
          } catch (error) {
            state.result.error = error;
          }
        },
        teardown: (state) => {
          if (broken) expectDenied(state.result, "malformed-token");
          else expectCount(state.result.restored, fieldsCount, "restored occurrences");
          vault.revoke(state.captureId);
        },
      });
      raw.push({ name: broken ? "restore.max-size.denied.malformed-token" : "restore.max-size.committed", kind: "latency", unit: "ms", samples, params, gating: false });
    }
  } finally {
    vault.dispose();
  }

  if (ctx.vaultServer === null) return raw;
  const clock = fakeClock(D.entryTtlMs);
  const server = await createBenchServer(ctx, { clock, policyMode: { value: "allow" }, revocationMemoryMs: 0 });
  try {
    for (const broken of [false, true]) {
      const samples = await ctx.sample({
        ...counts,
        setup: async () => {
          const captured = await server.capture(item.input, { release, maxUses: usesPerToken, issuedTenant: TENANT });
          return {
            captureId: captured.captureId,
            request: { context: REQUEST_CONTEXT, sink: SINK, purpose: PURPOSE, captures: [captured.captureId], fields: fieldsFor(captured.tokens, broken) },
            result: {},
          };
        },
        op: async (state) => {
          try {
            state.result.restored = (await server.restore(state.request)).restored;
          } catch (error) {
            state.result.error = error;
          }
        },
        teardown: async (state) => {
          if (broken) expectDenied(state.result, "malformed-token");
          else expectCount(state.result.restored, fieldsCount, "restored occurrences");
          await server.revoke(state.captureId);
        },
      });
      raw.push({
        name: broken ? "server.restore.max-size.denied.malformed-token" : "server.restore.max-size.committed",
        kind: "latency",
        unit: "ms",
        samples,
        params,
        gating: false,
      });
    }
  } finally {
    await server.dispose();
  }
  return raw;
}

// ---- vault-server revocation memory ----------------------------------------

async function measureRevocationMemory(ctx, sizes) {
  const item = ctx.corpus.items.capture1k;
  const tokenCount = item.findings.piiOff;
  const raw = [];
  const medians = { capture: [], restore: [], revoke: [] };
  const consume = (server, captured) =>
    server.restore({
      context: REQUEST_CONTEXT,
      sink: SINK,
      purpose: PURPOSE,
      captures: [captured.captureId],
      fields: { body: captured.tokens.map((t) => t.token).join(" ") },
    });
  const options = { release: [{ sink: SINK, paths: ["body"] }], issuedTenant: TENANT };

  for (const n of sizes) {
    // A rolling window on the fake clock (see header, section 4): one
    // revoke per REVOKE_STEP_MS and a memory of n steps keep exactly n
    // tombstones alive.
    const clock = { t: 1_000_000 };
    clock.now = () => clock.t;
    const server = await createBenchServer(ctx, { clock, policyMode: { value: "allow" }, revocationMemoryMs: n * REVOKE_STEP_MS });
    try {
      for (let i = 0; i < n; i += 1) {
        if (i > 0) clock.t += REVOKE_STEP_MS;
        const captured = await server.capture(fillInput(i, 1), options);
        expectCount(captured.tokens.length, 1, "fill entries");
        await server.revoke(captured.captureId);
      }
      const level = async () => expectCount((await server.stats()).revokedCaptures, n, "revoked captures");
      await level();
      const share = REVOKED_SHARE[n] ?? 1;
      const counts = { iterations: Math.max(10, Math.round(ctx.iterations * share)), warmup: Math.round(ctx.warmup * share) };
      const params = { revoked: n, revokedTokens: n, item: "capture1k", entries: tokenCount };

      const capture = await ctx.sample({
        ...counts,
        setup: () => ({}),
        op: async (state) => {
          state.captured = await server.capture(item.input, options);
        },
        teardown: async (state) => {
          expectCount((await consume(server, state.captured)).restored, tokenCount, "consumed entries");
          await level();
        },
      });
      const restore = await ctx.sample({
        ...counts,
        setup: async () => ({ captured: await server.capture(item.input, options) }),
        op: async (state) => {
          state.restored = (await consume(server, state.captured)).restored;
        },
        teardown: async (state) => {
          expectCount(state.restored, tokenCount, "restored occurrences");
          await level();
        },
      });
      const revoke = await ctx.sample({
        ...counts,
        setup: async () => {
          // One step later the oldest tombstone ages out: n - 1 alive
          // before the timed revoke, n after it.
          clock.t += REVOKE_STEP_MS;
          return { captured: await server.capture(item.input, options) };
        },
        op: async (state) => {
          state.removed = await server.revoke(state.captured.captureId);
        },
        teardown: async (state) => {
          expectCount(state.removed, tokenCount, "revoked entries");
          await level();
        },
      });
      for (const [op, samples] of Object.entries({ capture, restore, revoke })) {
        raw.push({ name: `server.${op}.revoked-${n}`, kind: "latency", unit: "ms", samples, params, gating: false });
        medians[op].push(median(samples));
      }
    } finally {
      await server.dispose();
    }
  }
  for (const [op, ys] of Object.entries(medians)) {
    raw.push({
      name: `server.${op}.ms_per_1k_revoked`,
      kind: "deterministic",
      unit: "ms",
      value: linearSlope(sizes, ys) * 1000,
      params: { sizes: sizes.join("/"), statistic: "p50" },
      gating: false,
    });
  }
  return raw;
}

export async function run(ctx) {
  const shapes = SHAPES[ctx.quick ? "quick" : "full"];
  const defaults = await measureDefaultCaptures(ctx, shapes);
  const raw = [...defaults.raw];
  raw.push(...(await measureCeilings(ctx, shapes, defaults.model)));
  raw.push(...(await measureVaultDenials(ctx)));
  raw.push(...(await measureMaxSizeRestore(ctx)));
  if (ctx.vaultServer !== null) {
    raw.push(...(await measureServerDenials(ctx)));
    raw.push(...(await measureRevocationMemory(ctx, shapes.revoked)));
  }
  return raw;
}
