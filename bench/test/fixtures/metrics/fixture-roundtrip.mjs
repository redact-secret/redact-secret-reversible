// Test fixture: a metric that really captures and restores corpus values
// through ctx, so tests can check that none of them reach the result.
export const id = "fixture-roundtrip";
export const issue = 75;
export const title = "Fixture: capture and restore round trip";

export async function run(ctx) {
  const { input } = ctx.corpus.items.capture1k;
  const vault = await ctx.vault.createVault();
  try {
    const release = [{ sink: "fixture", paths: ["body"] }];
    const samples = await ctx.sample({
      iterations: ctx.iterations,
      warmup: ctx.warmup,
      op: () => {
        const captured = vault.capture(input, { release });
        const restored = vault.restore({ sink: "fixture", captures: [captured.captureId], fields: { body: captured.text } });
        if (restored.fields.body !== input) throw new Error("round trip mismatch");
      },
    });
    return [{ name: "roundtrip", kind: "latency", unit: "ms", samples, params: { inputBytes: input.length } }];
  } finally {
    vault.dispose();
  }
}
