# Persistent vault design review, 2026-10-01

Independent security review of the [persistent vault specification](../specs/persistent-vault.md) and [its decision record](../decisions/supersede-persistent-store-contract.md), done before any implementation ([#104](https://github.com/redact-secret/redact-secret-vault/issues/104), [#105](https://github.com/redact-secret/redact-secret-vault/issues/105), [#107](https://github.com/redact-secret/redact-secret-vault/issues/107)).

**Method.** A reviewer that did not write the design read the first draft of both documents, the earlier contract, the in-memory server and vault source, the threat model, and issues #4, #20, #104 to #109, and #111, with the instruction to break the design. It was a reading review: nothing was executed, because nothing was implemented. Each finding below was then checked against the draft and either fixed in the specification, declined with a reason, or left as a stated limit. Findings are hypotheses until checked; one was partly declined.

**Result.** No critical finding. One high finding, fixed. The reviewer's list of areas it found sound and areas it could not assess is at the end.

## Findings and dispositions

Severity is the reviewer's. Section numbers are those of the current specification.

| # | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| 1 | High | The draft said a restore and a revocation "both write the capture row, so the store orders them", but its commit only read the capture. Under snapshot or read-committed isolation a revocation could commit unseen and the restore still release (write skew). The same held against quarantine and invalidation | **Fixed.** §5.2 adds a normative conflict rule: commit and create must conflict with a concurrent revoke of a named capture and with quarantine or invalidation, by lock or by condition, and an abort is `stale`. §7.1 is rewritten on that rule. A two-connection schedule for this interleaving is a required conformance case |
| 2 | Medium | Invalidation compared a store clock (`invalidBefore`) with server-set `createdAt`, so a recovered capture could survive when clocks disagreed | **Fixed.** Each capture is stamped with the namespace epoch; a capture under a lower epoch is treated as revoked. The timestamp comparison is gone (§5.1, §5.8) |
| 3 | Medium | The epoch only protects if no server with the old configuration reaches the recovered database; nothing could set `quarantined`; the tripwire was optional | **Fixed.** The runbook starts with stopping or fencing servers; `quarantine` is an operation; adapters declare `restoreDetection` (§5.8, §9.3). A backup taken after an earlier recovery is named as a case only the runbook covers |
| 4 | Medium | A public revoke of an unknown identifier wrote a durable tombstone: unbounded storage for any authenticated caller. Revoke and erase had no authorization hook | **Fixed.** Revoke of an absent capture is `not-found` and writes nothing; `fenceAbsent` is used only by the server for an identifier it issued (§5.6). A required `lifecyclePolicy` gates capture, revoke, ciphertext deletion, and attempt resolution (§8.2) |
| 5 | Medium | Values are decrypted before sink, path, purpose, and policy are checked | **Partly fixed.** Purpose is checked in step 1 and the row budget in step 4, before any unwrap. Splitting the payload so grants decrypt separately from the value is **declined**: it adds a second authenticated message and a second key derivation per entry to the wire format, and the plaintext it would avoid exists only inside one bounded call in the trusted process. §7.2 states the exposure |
| 6 | Medium | The capture plan returned plaintext beside tokens and took a caller-supplied random source, on which the unkeyed `entryId` depends | **Fixed.** The plan returns ranges, not values; the caller slices its own input. Randomness comes from the platform inside the module. The module is under `internal/`, exported for `node` only (§8.1). The over-stated sentence is removed |
| 7 | Low | Unkeyed digests over low-entropy inputs (`sessionDigest`, request digest) | **Fixed.** The stored session value is an HMAC tag and the request digest is HMAC, both under a required digest key with an explicit opt-out (§3.2, §7.3). `sessionId` is stated not to be a credential |
| 8 | Low | Key context identifiers would reach a remote key service's audit log in clear | **Fixed.** A remote provider sends a digest of the context (§3.7, §6.1) |
| 9 | Medium | `tombstoneExpiresAt` could not be computed by the caller | **Fixed.** The caller passes a retention; the store computes the bound from the capture's expiry (§5.6) |
| 10 | Medium | Re-wrap and re-encryption could not be driven: no enumeration by key reference | **Accepted as a limit.** Version 1 rotates by keeping the old version decrypt-only for 24 hours plus skew. The store operation stays in the contract and in the conformance tests. §6.2 also states that re-wrap does not help after a key is exposed. Enumeration is an open question |
| 11 | Medium | The reconciliation path had no operations | **Fixed by removal.** Version 1 offers invalidation only (§9.3) |
| 12 | Medium | The outcome after `stale` retries were exhausted was undefined | **Fixed.** `RESTORE_CONFLICT`, nothing consumed, retryable; the collision on multi-use entries is stated as intended (§7.2) |
| 13 | Medium | Undefined types; the skew bound was not a capability; required capabilities were not listed | **Fixed.** §4 defines every type; `maxClockSkewMs` is a capability; §8.2 lists the required ones; a store without a clock is refused |
| 14 | Medium | No aggregate retention bound | **Stated as a limit.** Volume is bounded by capture rate times 24 hours; rate limiting is the application's, through `lifecyclePolicy` (§3.6). A store-enforced quota is an open question |
| 15 | Low | The store did not have to reject duplicates, non-positive counts, or bad lifetimes | **Fixed.** §4.2 |
| 16 | Low | `captures` in a commit could name unused captures | **Fixed.** Exactly the captures of the entries used (§4, §4.2) |
| 17 | Low | Zero-token restore and zero-entry capture undefined | **Fixed.** §7.2 step 3, §5.3 |
| 18 | Low | Namespace bootstrap undefined | **Fixed.** `initializeNamespace` refuses a non-empty namespace; nothing else creates the record (§5.8) |
| 19 | Low | Request digest had no bytes | **Fixed.** §7.3, with vectors |
| 20 | Low | `resolveAttempt` took only an identifier | **Fixed.** It takes the original request and compares digests (§7.3) |
| 21 | Low | Encoding details: surrogates, sort order, fractional timestamps, presence flags, empty grants | **Fixed.** §3.1, §3.5 |
| 22 | Low | Local provider: salt, key usage, no version byte | **Fixed.** §6.3 |
| 23 | Low | Behaviour differences from the in-memory server were not listed | **Fixed.** §8.3 |
| 24 | Low | One key-service call per entry | **Fixed.** One data key per capture, entry keys derived with HKDF; a total deadline per operation (§3.3, §6.1) |
| 25 | Low | Cleanup trusted the store clock alone | **Fixed.** Cleanup takes the caller's `now` and rejects on skew (§5.7) |
| 26 | Over-stated | "Bounded by the 24-hour ceiling" for clock rollback | **Corrected.** §7.5 |
| 27 | Over-stated | The reason given for receipt removal being safe | **Corrected.** §7.5 |
| 28 | Over-stated | `eraseCapture` named an operation the design says it does not have | **Renamed** `deleteCaptureCiphertext` (§8.2) |
| 29 | Over-stated | Per-tenant erasure route with a provider that has one material | **Corrected.** §6.3, §9 |
| 30 | Over-stated | Failover resolved "under the qualified profile" while durability is self-declared | **Corrected.** §7.6: an asynchronous promotion is a rollback |

Three questions from the reviewer, answered in the specification: the revision check is kept in addition to the budget check, and its cost is the stated conflict (§7.2); a session resolver may return no session, which yields a capture restorable from any session of the tenant (§8.2); capture identifiers are held by the application that made the capture, and their use for revoke and deletion is gated by the lifecycle policy (§8.2).

## Second pass

The same reviewer re-read the revised specification. It judged 24 of the 27 fixes closed and three partly closed (3, 13, 15), found none of the declined or accepted dispositions unsafe, and raised ten new findings against material added after the first pass. All ten were low and all were applied:

| # | Finding | Change |
| --- | --- | --- |
| 3 (rest) | A durable store could declare no restore detection and still be accepted | The factory refuses it without `allowNoRestoreDetection` (§8.2) |
| 31 | `createCapture` could not report an abort under the conflict rule; lock modes on the recovery record were unstated; the two-connection schedule was only promised here | `stale` added; shared and exclusive modes stated; the schedules are required in §5.2 |
| 32 | With only a session-bound flag, a wrong session cost an unwrap, read as tampering, and could not be checked by revoke | A keyed session tag is stored; mismatch is `source` before unwrap; lifecycle operations check it (§3.2, §7.2, §8.2) |
| 33 | Re-encryption could not be built from the contract | Removed from version 1; only re-wrap remains (§5.6, §6.2) |
| 34 | Decrypted values were immutable strings even for denied requests | The crypto layer returns bytes; the server decodes only when returning (§4, §7.2) |
| 35 | A re-wrap could write a key back after ciphertext deletion; skew blocked deletion for revoked captures; emptied rows were not valid results | Deletion bumps `keyRevision` and revokes; re-wrap refuses such captures; skew applies only to the expiry branch; such rows are never returned by `readEntries` (§5.1, §5.6, §5.7) |
| 36, 13 (rest) | `lifecyclePolicy` had no signature or failure behaviour | Defined, with a deadline and deny on any failure (§8.2) |
| 37 | Request digest: unbounded purpose, unbounded named captures, ambiguous flag name | Bounds in §3.6; flag renamed `hasSession` (§7.3) |
| 38, 15 (rest) | Validation gaps for key fields, receipt and retention bounds, epochs, sweep limit; invalid-argument at commit unmapped | §4.2 |
| 39 | A duplicate entry identifier reached encryption before the store rejected it; no algorithm in the key derivation | The crypto layer rejects duplicates and mismatched bindings; the algorithm is in the HKDF `info` (§3.3, §4) |
| 40 | `readEntries` consistency; how a lower-epoch capture is reported | One snapshot; reported as `revoked` (§5.1, §5.4) |
| 14 (rest) | The lifecycle policy could limit capture rate but not volume | It receives the entry count and byte size of a capture (§8.2) |

It also examined and found sound: the key hierarchy, the wrapped key on the capture row, re-wrap concurrent with a restore, the request digest, the commit step ordering, and namespace initialization.

## Found sound

The reviewer tried and could not break:

- Substitution by a store writer across tenant, namespace, capture, entry, and session, and changes to expiry and `maxUses`: each fails the tag because the server rebuilds the associated data from trusted scope.
- Leaving the key reference out of the associated data: a swapped wrapped key yields a different data key and the tag fails.
- AES-GCM usage, and the unambiguity of the encodings.
- Same-attempt retry after `absent`, and a fresh attempt after an ambiguous commit: no double release could be constructed.
- Two restores of one entry, partial batch consumption, and repeated tokens across fields.
- Create against revoke ordering, including a delayed ambiguous create.
- That replacing ciphertext cannot reset a budget or a revocation.
- That no plaintext, token, or key reaches the store interface or an error.

## Not assessed

- Any real backend's isolation, durability, or failover behaviour (#20).
- Whether a key service's context binding holds (#113).
- The conformance vectors, which did not exist.
- Whether the capture plan preserves PII activation state exactly.

These are implementation-stage questions and are carried into the final review (#110, #112).
