# Security review: @redact-secret/vault 0.1.0-alpha.1

**Issue:** [#21](https://github.com/redact-secret/redact-secret-reversible/issues/21). **Date:** 2026-09-27.
**Reviewer:** a separate review agent (Claude) with no part in writing the implementation. It worked read-only on the source, tests, corpus, specification, and ADRs, and confirmed findings by running throwaway scripts with synthetic values against the built package. This is an AI review, independent of the implementing agent; it is **not** a human or third-party audit.
**Scope:** every public export, defaults, README examples, error/audit/stats paths, and misuse paths of the in-memory vault. Worker, server, and persistence modes were out of scope (unimplemented).

## Result

No critical or high findings. Three confirmed low-severity defects and one medium design concern were fixed before release. The remaining items are documented residual risks.

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | Low–medium (confirmed) | Captures that retained nothing stayed in the capture index forever (5,000 empty captures → `captures: 5000`) | Such captures are no longer tracked. Corpus `no-findings.no-mapping` now asserts `captures: 0` |
| 2 | Low (confirmed) | A throwing injected clock escaped as a raw, payload-bearing exception | Clock failures become `INVALID_ARGUMENT` (audited as `failed`), in `createVault` and every operation. Runtime check `throwing-clock-is-sanitized` |
| 3 | Low (confirmed) | Expired values stayed in memory after a denied restore, and `stats()` ignored expiry | A denied restore sweeps expired entries; `stats()` applies entry and vault expiry. Corpus `lifecycle.expired-entries-dropped-without-further-operations`, `lifecycle.vault-expiry-visible-in-stats` |
| 4 | Medium (design, confirmed) | Tokens from different captures in one vault were interchangeable under the same grant, contradicting the ADR's "expected source" | `restore` now **requires** `captures`; tokens from other captures are denied with `source`. Corpus `source.token-from-other-capture`; ADR and README updated |
| 5 | Low (design) | `releasePolicy` saw per-path occurrences only, so a budget-style policy could approve more than intended | Added `totalOccurrences`. Runtime check `policy-sees-request-wide-occurrences` |
| 6 | Low (design) | Denial reasons reveal whether a token is live | Kept for integrators; README and threat model tell integrators not to forward `reason` |
| 7 | Low (design, confirmed) | Zero-width characters inside the marker bypassed malformed-token detection | The marker pattern ignores Unicode Cf characters, for capture and restore. Corpus cases use `{c1.0:zwsp}` and a hidden-marker input. The README claim is narrowed: homoglyphs that destroy the marker leave text unrestored |
| 8 | Info | Multi-turn re-capture fails, which may push integrators toward restoring history | README section on the multi-turn pattern |
| 9 | Info | `pass-through` is global, and the result did not name the passed types | Added `passedThroughTypes`; README steers to adjusting core policy first |
| 10 | Info (confirmed) | Wall-clock and injected clocks can move backwards and extend TTLs | Default clock is now monotonic (`performance.now()` anchored to `Date.now()`); observed time never decreases. Corpus `lifecycle.observed-time-never-decreases` |
| 11 | Info | Inherited-key check in limits; DevTools can show private fields; stale spec header; core limit codes surface as `CORE_FAILURE` | `Object.hasOwn`; DevTools line in README and threat model; header updated; `coreCode` behavior documented |

## Held up under review

Fixed-message errors without `cause`; safe-metadata audit events; the action gate matching the core contract; output/marker validation before commit; request snapshotting that rejects accessors; preflight ordering with no throwing code after budget commit; function-based replacement (no `$` patterns); `__proto__` paths as own properties; `lastIndex` resets; `BUSY` on re-entry; per-token budget accounting across fields; cross-vault and forged tokens rejected; collision checks against live and staged tokens.

## Verification after fixes

The same reviewer re-verified the fixes: all eleven findings were fixed or documented, and no new critical, high, or medium defect was found. Two low leftovers were then addressed. The default clock now takes the later of wall-clock and monotonic time, so system sleep cannot pause TTLs. The README names non-format invisible marks explicitly. The full suite was rerun on Node.js (addon and WASM fallback) and in Chromium, Firefox, and WebKit. See the [qualification record](../research/qualification-0.1.0-alpha.1.md).
