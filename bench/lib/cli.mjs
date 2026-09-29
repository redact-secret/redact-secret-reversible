// Command-line options shared by run.mjs and compare.mjs.

import { parseArgs } from "node:util";

import { DEFAULT_SETTINGS } from "./harness.mjs";
import { PII_SELECTORS } from "./sides.mjs";

export function parseCommonArgs(argv, extra = {}) {
  const { values } = parseArgs({
    args: argv,
    options: {
      metrics: { type: "string" },
      quick: { type: "boolean", default: false },
      pii: { type: "string", default: "off" },
      out: { type: "string" },
      iterations: { type: "string" },
      warmup: { type: "string" },
      help: { type: "boolean", default: false },
      ...extra,
    },
    strict: true,
  });
  if (!(values.pii in PII_SELECTORS)) throw new Error(`--pii must be one of ${Object.keys(PII_SELECTORS).join(", ")}`);
  const settings = { ...(values.quick ? DEFAULT_SETTINGS.quick : DEFAULT_SETTINGS.full) };
  for (const key of ["iterations", "warmup", "rounds"]) {
    if (values[key] === undefined) continue;
    const n = Number(values[key]);
    if (!Number.isInteger(n) || n < (key === "warmup" ? 0 : 1)) throw new Error(`--${key} must be an integer`);
    settings[key] = n;
  }
  const only = values.metrics?.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  return { values, settings, only };
}
