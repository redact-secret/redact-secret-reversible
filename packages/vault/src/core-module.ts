/**
 * How the vault reaches `@redact-secret/core`, and the application-owned PII
 * activation routine of
 * docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md §3.
 *
 * The core is imported as a namespace so the optional PII surface
 * (`piiActivation`, `initialize({ pii })`, core beta.10 and later) can be
 * detected at runtime while this package still type-checks against beta.9.
 */
import * as core from "@redact-secret/core";

import { coreCodeOf, VaultError } from "./errors.js";

/** The part of the core's public module the vault uses. Satisfied by beta.9 and beta.10. */
export interface CoreModule {
  readonly initialize: () => Promise<void>;
  readonly scan: typeof core.scan;
  readonly redact: typeof core.redact;
  readonly defaultPlaceholderFormatter: typeof core.defaultPlaceholderFormatter;
}

/**
 * The PII surface of a core that has one. Typed locally, not imported, so
 * this package type-checks against beta.9, whose `initialize` takes no
 * options and which exports no `piiActivation`.
 */
export interface PiiCoreSurface {
  initialize(options: { readonly pii: readonly string[] }): Promise<void>;
  piiActivation(): string;
}

/** The installed `@redact-secret/core`, as the vault uses it. */
export const installedCore: CoreModule = core;

/**
 * Runtime feature detection (ADR §3 step 2): a core has a PII surface iff its
 * public module exports a `piiActivation` function. Never a version check.
 */
export function piiSurfaceOf(module: object): PiiCoreSurface | undefined {
  const candidate = module as { readonly piiActivation?: unknown; readonly initialize?: unknown };
  if (typeof candidate.piiActivation !== "function" || typeof candidate.initialize !== "function") {
    return undefined;
  }
  const initialize = candidate.initialize as (options: { readonly pii: readonly string[] }) => Promise<void>;
  const piiActivation = candidate.piiActivation as () => string;
  return {
    initialize: (options) => initialize(options),
    piiActivation: () => piiActivation(),
  };
}

/**
 * ADR §3 steps 2 to 6, given already shape-checked options (step 1). Returns
 * the observed canonical activation identity, or `null` for a core without a
 * PII surface. The vault forwards a selection only when the application
 * passed one; otherwise it adopts the realm's existing activation and calls
 * no initializer. It never retries, catches a conflict, or picks a default.
 *
 * Throws `PII_UNAVAILABLE` (a PII option on a core without a PII surface),
 * `CORE_FAILURE` with the core's fixed `coreCode` (`PII_ACTIVATION_CONFLICT`,
 * `PII_SELECTOR_*`, `NOT_INITIALIZED`, ...), `INVARIANT_VIOLATION` (the core
 * returned a non-string identity), or `PII_ACTIVATION_MISMATCH`.
 */
export async function activateCore(
  module: CoreModule,
  selection: readonly string[] | undefined,
  expected: string | undefined,
): Promise<string | null> {
  const surface = piiSurfaceOf(module);

  if (surface === undefined) {
    // Step 3: beta.9 is PII-off by construction; omission and `[]` are equal.
    if ((selection !== undefined && selection.length > 0) || expected !== undefined) {
      throw new VaultError("PII_UNAVAILABLE");
    }
    try {
      await module.initialize();
    } catch (thrown) {
      throw new VaultError("CORE_FAILURE", { coreCode: coreCodeOf(thrown) });
    }
    return null;
  }

  // Step 4: forward the application's selection verbatim (as a fresh copy).
  if (selection !== undefined) {
    try {
      await surface.initialize({ pii: [...selection] });
    } catch (thrown) {
      throw new VaultError("CORE_FAILURE", { coreCode: coreCodeOf(thrown) });
    }
  }

  // Steps 5 and 6: observe once. With `pii` omitted this is adoption: a core
  // nobody initialized reports NOT_INITIALIZED and stays uninitialized.
  let activation: unknown;
  try {
    activation = surface.piiActivation();
  } catch (thrown) {
    throw new VaultError("CORE_FAILURE", { coreCode: coreCodeOf(thrown) });
  }
  if (typeof activation !== "string") throw new VaultError("INVARIANT_VIOLATION");
  if (expected !== undefined && activation !== expected) {
    throw new VaultError("PII_ACTIVATION_MISMATCH");
  }
  return activation;
}
