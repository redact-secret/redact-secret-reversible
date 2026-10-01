/**
 * `@redact-secret/vault-server/policies`: reference `ServerReleasePolicy`
 * values, for composing a deny-by-default restore policy without writing the
 * same three rules by hand.
 *
 * They are ordinary policies. A server evaluates them exactly as it evaluates
 * an application's own function, after its own checks (tenant, expiry, grant,
 * purpose presence, budget), so none of them can widen what the server allows.
 * See docs/decisions/define-server-authority-interface.md, "Reference policy
 * examples".
 */
import type { PolicyDecision, ServerReleasePolicy } from "./types.js";

const ALLOW: PolicyDecision = Object.freeze({ allow: true });
const DENY: PolicyDecision = Object.freeze({ allow: false, reason: "policy" });
const DENY_TENANT: PolicyDecision = Object.freeze({ allow: false, reason: "tenant-mismatch" });
const DENY_SINK: PolicyDecision = Object.freeze({ allow: false, reason: "sink-or-path" });
const DENY_PURPOSE: PolicyDecision = Object.freeze({ allow: false, reason: "missing-purpose" });

/** Denies every restore. The base to start from; allows nothing on its own. */
export const denyByDefault: ServerReleasePolicy = () => DENY;

/** Allows only when the caller's tenant is the tenant the value was captured for. */
export const allowSameTenantOnly: ServerReleasePolicy = (input) =>
  input.tenant === input.source.issuedTenant ? ALLOW : DENY_TENANT;

/**
 * Allows only the listed purposes for each listed sink. A sink that is not
 * listed is denied `sink-or-path`; a purpose that is not listed for its sink is
 * denied `missing-purpose`.
 *
 * The table is copied when the policy is created, so changing the object
 * afterwards has no effect. An empty table, or a sink with no purposes, allows
 * nothing.
 */
export function allowSinkPurposes(allowed: Readonly<Record<string, readonly string[]>>): ServerReleasePolicy {
  if (typeof allowed !== "object" || allowed === null || Array.isArray(allowed)) {
    throw new TypeError("allowSinkPurposes expects an object of sink -> purposes.");
  }
  const table = new Map<string, ReadonlySet<string>>();
  for (const sink of Object.keys(allowed)) {
    const purposes = allowed[sink];
    if (sink.length === 0 || !Array.isArray(purposes) || purposes.some((p) => typeof p !== "string" || p.length === 0)) {
      throw new TypeError("allowSinkPurposes expects non-empty sink names, each with an array of non-empty purposes.");
    }
    table.set(sink, new Set(purposes as readonly string[]));
  }
  return (input) => {
    const purposes = table.get(input.sink);
    if (purposes === undefined) return DENY_SINK;
    return purposes.has(input.purpose) ? ALLOW : DENY_PURPOSE;
  };
}

/**
 * Chains policies: every one must allow, and the first that does not decides.
 * With no policy it denies.
 *
 * Only a decision whose `allow` is exactly `true` continues the chain. Anything
 * else, including a malformed return, is handed back unchanged, so the server
 * applies its own fail-closed check to it. A policy that throws or rejects
 * propagates, which the server reports as `policy-evaluation-error`.
 */
export function allOf(...policies: readonly ServerReleasePolicy[]): ServerReleasePolicy {
  for (const policy of policies) {
    if (typeof policy !== "function") throw new TypeError("allOf expects policy functions.");
  }
  const chain = [...policies];
  if (chain.length === 0) return denyByDefault;
  return async (input) => {
    for (const policy of chain) {
      const decision = await policy(input);
      if (typeof decision !== "object" || decision === null || decision.allow !== true) return decision;
    }
    return ALLOW;
  };
}
