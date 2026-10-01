/**
 * The opt-in cache of unwrapped data keys (docs/specs/persistent-vault.md
 * §6.2). It is bounded by entry count, by age, and per tenant; every entry
 * is overwritten when it is evicted, when it ages out, and on `clear`.
 *
 * Disabling a key in AWS KMS does not reach an entry held here until the
 * entry ages out: the revocation delay is `maxAgeMs`.
 */
import { KeyProviderError } from "@redact-secret/vault-contracts";

/** Hard ceiling of `maxAgeMs`: five minutes. */
export const CACHE_MAX_AGE_CEILING_MS = 5 * 60 * 1000;
/** Hard ceiling of `maxEntries`. */
export const CACHE_MAX_ENTRIES_CEILING = 10_000;

export interface DataKeyCacheOptions {
  /** Entries held at once, 1 to 10000. */
  readonly maxEntries: number;
  /** Lifetime of an entry in milliseconds, 1 to 300000. This is the revocation delay. */
  readonly maxAgeMs: number;
  /** Entries held at once for one tenant, 1 to `maxEntries`. */
  readonly perTenantMaxEntries: number;
  /** Clock in milliseconds, for tests. Default `Date.now`. */
  readonly now?: () => number;
}

interface Entry {
  readonly tenant: string;
  readonly key: Uint8Array;
  readonly storedAt: number;
}

export interface DataKeyCache {
  /** A copy of the cached key, or `undefined`. An entry at or past its age is removed and overwritten. */
  get(id: string): Uint8Array | undefined;
  /** Stores `key`. The cache owns the array from here on and overwrites it on eviction. */
  put(id: string, tenant: string, key: Uint8Array): void;
  /** Overwrites and removes every entry. */
  clear(): void;
  counts(): { entries: number; tenants: number; hits: number; misses: number; evictions: number };
}

function isCount(value: unknown, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= max;
}

export function createDataKeyCache(options: DataKeyCacheOptions): DataKeyCache {
  if (typeof options !== "object" || options === null) throw new KeyProviderError("KEY_INVALID_ARGUMENT");
  const { maxEntries, maxAgeMs, perTenantMaxEntries } = options;
  if (
    !isCount(maxEntries, CACHE_MAX_ENTRIES_CEILING) ||
    !isCount(maxAgeMs, CACHE_MAX_AGE_CEILING_MS) ||
    !isCount(perTenantMaxEntries, maxEntries) ||
    (options.now !== undefined && typeof options.now !== "function")
  ) {
    throw new KeyProviderError("KEY_INVALID_ARGUMENT");
  }
  const clock = options.now ?? Date.now;
  // Insertion order is age order: an entry is never refreshed by a read.
  const entries = new Map<string, Entry>();
  const perTenant = new Map<string, number>();
  let hits = 0;
  let misses = 0;
  let evictions = 0;

  function remove(id: string, entry: Entry): void {
    entry.key.fill(0);
    entries.delete(id);
    const left = (perTenant.get(entry.tenant) ?? 1) - 1;
    if (left <= 0) perTenant.delete(entry.tenant);
    else perTenant.set(entry.tenant, left);
    evictions += 1;
  }

  /** An unreadable clock, or one that went backwards, expires the entry. */
  function expired(entry: Entry, now: number): boolean {
    return !Number.isFinite(now) || now < entry.storedAt || now - entry.storedAt >= maxAgeMs;
  }

  function purge(now: number): void {
    for (const [id, entry] of entries) if (expired(entry, now)) remove(id, entry);
  }

  return {
    get(id) {
      const entry = entries.get(id);
      if (entry === undefined) {
        misses += 1;
        return undefined;
      }
      if (expired(entry, clock())) {
        remove(id, entry);
        misses += 1;
        return undefined;
      }
      hits += 1;
      return entry.key.slice();
    },

    put(id, tenant, key) {
      const now = clock();
      if (!Number.isFinite(now)) {
        key.fill(0);
        return;
      }
      purge(now);
      const previous = entries.get(id);
      if (previous !== undefined) remove(id, previous);
      if ((perTenant.get(tenant) ?? 0) >= perTenantMaxEntries) {
        for (const [oldId, old] of entries) {
          if (old.tenant === tenant) {
            remove(oldId, old);
            break;
          }
        }
      }
      if (entries.size >= maxEntries) {
        const oldest = entries.entries().next().value;
        if (oldest !== undefined) remove(oldest[0], oldest[1]);
      }
      entries.set(id, { tenant, key, storedAt: now });
      perTenant.set(tenant, (perTenant.get(tenant) ?? 0) + 1);
    },

    clear() {
      for (const [id, entry] of entries) remove(id, entry);
    },

    counts() {
      return { entries: entries.size, tenants: perTenant.size, hits, misses, evictions };
    },
  };
}
