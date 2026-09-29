// B5 (#79), mode pair 1: `vault-server` ÷ `vault` in Node.js on the same
// workload. What the server adds per call is its FIFO queue (every call is
// chained, so even an uncontended call pays a promise hop), principal
// resolution and a release-policy call per token occurrence (each raced
// against its timeout), and the metadata shadow it checks before delegating
// to the wrapped vault.
//
// Each iteration runs the same operation on a plain vault (`a`) and a server
// vault (`b`) back to back, in alternating order, on its own fresh captures,
// so `<op>.boundary_ms = server − vault` is paired per iteration. The
// resolver and policy are the cheapest conformant ones (a constant principal,
// always allow), so the boundary figure is the server's own floor, not an
// application's policy cost.
//
// `<op>.ratio` is p50(server) ÷ p50(vault) of this side and round, as a
// deterministic value. A/B compares it (informational); the gating signals
// are `restore.boundary_ms` and `revoke.boundary_ms`, which move with the
// server package, not the core. `capture.boundary_ms` is informational: its
// median is within timer noise of zero (a queue hop and shadow bookkeeping on
// a ~0.2 ms core-bound call), so its A/B ratio is unstable.
//
// The server is created with `revocationMemoryMs: 0`. With the default
// (the entry TTL), every revoked capture leaves a tombstone that each later
// capture/restore/revoke sweeps in O(tombstones), so the per-call cost grows
// with how many captures were revoked recently. In a full run (about 3,600
// revokes) that took the p50 boundary from ~0.002 to ~0.08 ms for capture and
// from ~0.001 to ~0.24 ms for revoke, and the figure depended on the
// iteration count. That growth is a scaling property (B4/B7 territory), not
// the per-call boundary floor this metric reports.
//
// Skipped on a side without `@redact-secret/vault-server` (published before
// 0.1.0-alpha.2).

export const id = "mode-server";
export const issue = 79;
export const title = "Mode boundary cost: vault-server vs vault";
export const piiModes = ["off"];

const SINK = "bench-sink";
const PURPOSE = "bench-purpose";
const TENANT = "bench-tenant";
const REQUEST_CONTEXT = Object.freeze({ tenant: TENANT });

function expectCount(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${expected}, got ${actual}`);
}

function median(samples) {
  const sorted = [...samples].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/** The three measurements of one op, plus its p50 ratio. */
function pairMeasurements(op, paired, params, { gateBoundary = true } = {}) {
  const vaultP50 = median(paired.a);
  return [
    { name: `${op}.vault`, kind: "latency", unit: "ms", samples: paired.a, params, gating: false },
    { name: `${op}.server`, kind: "latency", unit: "ms", samples: paired.b, params, gating: false },
    { name: `${op}.boundary_ms`, kind: "latency", unit: "ms", samples: paired.diff, params, gating: gateBoundary },
    {
      name: `${op}.ratio`,
      kind: "deterministic",
      unit: "ratio",
      value: vaultP50 > 0 ? Math.round((median(paired.b) / vaultP50) * 10_000) / 10_000 : 0,
      params: { ...params, of: "p50 server / p50 vault" },
      gating: false,
    },
  ];
}

async function measureCapture(ctx, vault, server) {
  const item = ctx.corpus.items.capture1k;
  const expected = item.findings.piiOff;
  const release = [{ sink: SINK, paths: ["body"] }];
  const paired = await ctx.samplePaired({
    iterations: ctx.iterations,
    warmup: ctx.warmup,
    setup: () => ({}),
    a: (state) => {
      state.v = vault.capture(item.input, { release });
    },
    b: async (state) => {
      state.s = await server.capture(item.input, { release, issuedTenant: TENANT });
    },
    teardown: async (state) => {
      expectCount(state.v.tokens.length + state.v.unrestorable, expected, "vault capture findings");
      expectCount(state.s.tokens.length + state.s.unrestorable, expected, "server capture findings");
      vault.revoke(state.v.captureId);
      await server.revoke(state.s.captureId);
    },
  });
  return pairMeasurements("capture", paired, { item: "capture1k", inputBytes: item.bytes, findings: expected }, { gateBoundary: false });
}

function fieldsFor(templates, tokens) {
  const fields = {};
  for (const f of templates) fields[f.path] = f.before + tokens[f.slot].token + f.after;
  return fields;
}

async function measureRestore(ctx, vault, server) {
  const source = ctx.corpus.items.capture1k;
  const { fields: templates, usesPerToken } = ctx.corpus.items.restore64;
  const options = { release: [{ sink: SINK, paths: templates.map((f) => f.path) }], maxUses: usesPerToken };
  const paired = await ctx.samplePaired({
    iterations: ctx.iterations,
    warmup: ctx.warmup,
    setup: async () => {
      const v = vault.capture(source.input, options);
      const s = await server.capture(source.input, { ...options, issuedTenant: TENANT });
      return {
        vId: v.captureId,
        sId: s.captureId,
        vRequest: { sink: SINK, captures: [v.captureId], fields: fieldsFor(templates, v.tokens) },
        sRequest: {
          context: REQUEST_CONTEXT,
          sink: SINK,
          purpose: PURPOSE,
          captures: [s.captureId],
          fields: fieldsFor(templates, s.tokens),
        },
      };
    },
    a: (state) => {
      state.vRestored = vault.restore(state.vRequest).restored;
    },
    b: async (state) => {
      state.sRestored = (await server.restore(state.sRequest)).restored;
    },
    teardown: async (state) => {
      expectCount(state.vRestored, templates.length, "vault restored occurrences");
      expectCount(state.sRestored, templates.length, "server restored occurrences");
      vault.revoke(state.vId);
      await server.revoke(state.sId);
    },
  });
  return pairMeasurements("restore", paired, { fields: templates.length, tokenOccurrences: templates.length });
}

async function measureRevoke(ctx, vault, server) {
  const source = ctx.corpus.items.capture1k;
  const release = [{ sink: SINK, paths: ["body"] }];
  const expected = source.findings.piiOff;
  const paired = await ctx.samplePaired({
    iterations: ctx.iterations,
    warmup: ctx.warmup,
    setup: async () => ({
      vId: vault.capture(source.input, { release }).captureId,
      sId: (await server.capture(source.input, { release, issuedTenant: TENANT })).captureId,
    }),
    a: (state) => {
      state.vRemoved = vault.revoke(state.vId);
    },
    b: async (state) => {
      state.sRemoved = await server.revoke(state.sId);
    },
    teardown: (state) => {
      expectCount(state.vRemoved, expected, "vault revoked entries");
      expectCount(state.sRemoved, expected, "server revoked entries");
    },
  });
  return pairMeasurements("revoke", paired, { entries: expected });
}

export async function run(ctx) {
  if (ctx.vaultServer === null) ctx.skip("no @redact-secret/vault-server on this side");
  const vault = await ctx.vault.createVault();
  let server;
  try {
    server = await ctx.vaultServer.createServerVault({
      resolvePrincipal: (context) => ({ id: "bench-principal", tenant: context.tenant }),
      policy: () => ({ allow: true }),
      // Forget revoked captures at once: every call sweeps the tombstone map
      // in O(recently revoked captures), so with the default memory (the
      // entry TTL) each iteration's revoke would make every later call
      // slower and the figure would depend on the iteration count.
      revocationMemoryMs: 0,
    });
    return [
      ...(await measureCapture(ctx, vault, server)),
      ...(await measureRestore(ctx, vault, server)),
      ...(await measureRevoke(ctx, vault, server)),
    ];
  } finally {
    vault.dispose();
    if (server !== undefined) await server.dispose();
  }
}
