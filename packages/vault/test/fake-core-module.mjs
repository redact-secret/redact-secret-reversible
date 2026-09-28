// One realm-global fake core instance, shaped like the `@redact-secret/core`
// module namespace. `fake-core-register.mjs` redirects `@redact-secret/core`
// here, so in that process the vault, its Worker host, and the scenario code
// all share this instance, exactly as they would share the real core inside
// one Worker realm. `FAKE_CORE_PII=0` gives a beta.9-shaped core (no
// `piiActivation` export value). Synthetic data only; see fake-core.mjs.
import { createFakeCore } from "./fake-core.mjs";

const fake = createFakeCore({ pii: process.env.FAKE_CORE_PII !== "0" });

export const VERSION = "0.0.0-fake";
export const initialize = fake.module.initialize;
export const scan = fake.module.scan;
export const redact = fake.module.redact;
export const defaultPlaceholderFormatter = fake.module.defaultPlaceholderFormatter;
/** `undefined` on a beta.9-shaped fake, so runtime feature detection sees no PII surface. */
export const piiActivation = fake.module.piiActivation;
/** Test-only: every `initialize` call the realm saw, and how often `piiActivation` was read. */
export const calls = fake.calls;
