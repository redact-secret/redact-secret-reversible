/**
 * The `@redact-secret/vault/internal/capture-plan` entry point: the part of
 * the capture plan `@redact-secret/vault-server` uses. Internal, not a
 * supported public API, and resolvable under the `node` condition only.
 *
 * Nothing here reads a vault or returns a retained value: a plan holds the
 * redacted text, the issued tokens, and the ranges they replaced in the
 * caller's own input. No function takes a random source.
 */
export { openCapturePlanner, resolveCaptureLimits } from "./capture-plan.js";
export type {
  CapturePlan,
  CapturePlanner,
  CapturePlannerOptions,
  PlannedEntry,
  PlannedGrant,
} from "./capture-plan.js";
