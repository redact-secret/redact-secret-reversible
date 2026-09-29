// B3 (#77): p50/p95/p99 of capture, restore, and revoke on the main-thread
// vault, with capture split into the core's own work and the vault's overhead.
//
// `capture.core_ms` times what the vault asks of the core for the same input
// (scan, then redact with the same limits), and `capture.vault_overhead_ms`
// is the per-iteration difference from the whole capture. The two run
// back-to-back in alternating order on the same input, so a core re-pin shows
// up in core_ms and not as a vault regression.
//
// Every operation runs on a vault holding no other entries: each iteration's
// capture is revoked (untimed) before the next.

export const id = "op-latency";
export const issue = 77;
export const title = "Operation latency with core/vault overhead split";

const SINK = "bench-sink";

// Per PII mode: which corpus item capture uses and the capture options that
// go with it. Adding a mode here is the whole change to measure it; restore
// and revoke use `capture1k` in every mode.
const CAPTURE_INPUTS = {
  off: { item: "capture1k", options: {} },
};

export const piiModes = Object.keys(CAPTURE_INPUTS);

function expectCount(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${expected}, got ${actual}`);
}

async function measureCapture(ctx, vault) {
  const { item: itemName, options: extra } = CAPTURE_INPUTS[ctx.pii.mode];
  const item = ctx.corpus.items[itemName];
  const input = item.input;
  const expected = item.findings[ctx.pii.mode === "on" ? "piiOn" : "piiOff"];
  const { core } = ctx;
  const limits = { maxInputBytes: ctx.vault.DEFAULT_LIMITS.maxInputBytes, maxFindings: ctx.vault.DEFAULT_LIMITS.maxFindings };
  const options = { release: [{ sink: SINK, paths: ["body"] }], ...extra };

  const paired = await ctx.samplePaired({
    iterations: ctx.iterations,
    warmup: ctx.warmup,
    setup: () => ({}),
    a: (state) => {
      const findings = core.scan(input, { limits });
      state.coreText = core.redact(input, findings, { placeholderFormatter: core.defaultPlaceholderFormatter, limits });
      state.coreFindings = findings.length;
    },
    b: (state) => {
      state.captured = vault.capture(input, options);
    },
    teardown: (state) => {
      expectCount(state.coreFindings, expected, "core findings");
      expectCount(state.captured.tokens.length + state.captured.unrestorable, expected, "capture findings");
      vault.revoke(state.captured.captureId);
    },
  });
  const params = { item: itemName, inputBytes: item.bytes, findings: expected };
  return [
    // The total and the core share move with the pinned core, so A/B reports
    // them without gating on them; the overhead is the release signal.
    { name: "capture", kind: "latency", unit: "ms", samples: paired.b, params, gating: false },
    { name: "capture.core_ms", kind: "latency", unit: "ms", samples: paired.a, params, gating: false },
    { name: "capture.vault_overhead_ms", kind: "latency", unit: "ms", samples: paired.diff, params },
  ];
}

async function measureRestore(ctx, vault) {
  const source = ctx.corpus.items.capture1k;
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;
  const paths = templates.map((f) => f.path);
  const options = { release: [{ sink: SINK, paths }], maxUses: usesPerToken };

  const samples = await ctx.sample({
    iterations: ctx.iterations,
    warmup: ctx.warmup,
    setup: () => {
      const captured = vault.capture(source.input, options);
      const fields = {};
      for (const f of templates) fields[f.path] = f.before + captured.tokens[f.slot].token + f.after;
      return { captureId: captured.captureId, request: { sink: SINK, captures: [captured.captureId], fields } };
    },
    op: (state) => {
      state.restored = vault.restore(state.request).restored;
    },
    teardown: (state) => {
      expectCount(state.restored, templates.length, "restored occurrences");
      vault.revoke(state.captureId);
    },
  });
  return [
    {
      name: "restore",
      kind: "latency",
      unit: "ms",
      samples,
      params: { fields: templates.length, tokenOccurrences: templates.length, entries: source.findings.piiOff },
    },
  ];
}

async function measureRevoke(ctx, vault) {
  const source = ctx.corpus.items.capture1k;
  const options = { release: [{ sink: SINK, paths: ["body"] }] };
  const samples = await ctx.sample({
    iterations: ctx.iterations,
    warmup: ctx.warmup,
    setup: () => ({ captureId: vault.capture(source.input, options).captureId }),
    op: (state) => {
      state.removed = vault.revoke(state.captureId);
    },
    teardown: (state) => expectCount(state.removed, source.findings.piiOff, "revoked entries"),
  });
  return [{ name: "revoke", kind: "latency", unit: "ms", samples, params: { entries: source.findings.piiOff } }];
}

export async function run(ctx) {
  const vault = await ctx.vault.createVault();
  try {
    return [
      ...(await measureCapture(ctx, vault)),
      ...(await measureRestore(ctx, vault)),
      ...(await measureRevoke(ctx, vault)),
    ];
  } finally {
    vault.dispose();
  }
}
