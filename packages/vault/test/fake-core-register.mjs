// Loaded with `node --import` by worker-pii.test.mjs scenarios only: resolves
// `@redact-secret/core` to the fake core in fake-core-module.mjs for the whole
// process, so the public Worker-mode entries (`@redact-secret/vault/worker`,
// `@redact-secret/vault/worker/host`) run unchanged against a PII-capable
// fake core while the pinned beta.9 is installed.
import { register } from "node:module";

const target = new URL("./fake-core-module.mjs", import.meta.url).href;
const hooks = `
export async function resolve(specifier, context, next) {
  if (specifier === "@redact-secret/core") return { url: ${JSON.stringify(target)}, shortCircuit: true };
  return next(specifier, context);
}
`;
register(`data:text/javascript,${encodeURIComponent(hooks)}`);
