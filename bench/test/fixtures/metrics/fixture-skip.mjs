// Test fixture: a metric that declines to run.
export const id = "fixture-skip";
export const issue = 75;
export const title = "Fixture: skipped metric";
export const piiModes = ["off"];

export async function run(ctx) {
  ctx.skip("fixture always skips");
}
