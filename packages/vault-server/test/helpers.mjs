// Shared test helpers. Tests run against the *built* package (dist/), the
// same convention @redact-secret/vault's own qualification suite uses:
// `npm run test -w @redact-secret/vault-server` builds first.
import { createServerVault } from "../dist/index.js";

/** Unmistakably synthetic; never a real credential (AGENTS.md security boundary). */
export const SECRET_A = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
export const SECRET_B = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111";

export function manualClock(startMs = 1_700_000_000_000) {
  let t = startMs;
  return { now: () => t, advance: (ms) => (t += ms) };
}

/** A resolver that always succeeds with the given principal. */
export function staticResolver(principal) {
  return () => principal;
}

/** An allow-all policy, for tests that only care about the pre-policy checks. */
export function allowAll() {
  return { allow: true };
}

/** allow only when tenant matches the source's issuedTenant, else tenant-mismatch. */
export function sameTenantPolicy(input) {
  return input.tenant === input.source.issuedTenant
    ? { allow: true }
    : { allow: false, reason: "tenant-mismatch" };
}

/** A controllable promise for concurrency tests: resolve()/reject() from outside. */
export function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export async function openServer(overrides = {}) {
  const clock = overrides.clock ?? manualClock();
  const server = await createServerVault({
    resolvePrincipal: overrides.resolvePrincipal ?? staticResolver({ id: "user-synthetic-1", tenant: "tenant-acme-synthetic" }),
    policy: overrides.policy ?? allowAll,
    onAudit: overrides.onAudit,
    onVaultAudit: overrides.onVaultAudit,
    limits: overrides.limits,
    now: clock.now,
    policyRevision: overrides.policyRevision,
    revocationMemoryMs: overrides.revocationMemoryMs,
    resolverTimeoutMs: overrides.resolverTimeoutMs,
    policyTimeoutMs: overrides.policyTimeoutMs,
    // Core beta.10+ requires an initialized core: PII off, as these tests assume.
    pii: overrides.pii ?? [],
  });
  return { server, clock };
}

export async function captureOne(server, { text = `secret ${SECRET_A} here`, release, issuedTenant = "tenant-acme-synthetic", maxUses } = {}) {
  return server.capture(text, {
    release: release ?? [{ sink: "sink-a", paths: ["body"] }],
    issuedTenant,
    ...(maxUses === undefined ? {} : { maxUses }),
  });
}
