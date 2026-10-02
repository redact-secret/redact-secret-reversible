---
decision_id: decision-limit-python-persistence-claim-to-a-supplied-core-client
status: accepted
scope: packages/vault-py
title: Limit any Python persistence claim to an application-supplied, separately qualified CoreClient
decided_at: 2026-10-01
---
# Limit any Python persistence claim to an application-supplied, separately qualified `CoreClient`

> **Accepted 2026-10-01** as the scope of the Python qualification record ([#128](https://github.com/redact-secret/redact-secret-vault/issues/128)), the choice the [plan](../plans/python-persistence-parity.md) (section 6.2 and open question 9) left to that issue. It claims nothing about persistence by itself; the cells that were run and their results are in the [qualification record](../research/qualification-python-persistence-0.1.0b3.md). It does not qualify the bridge.

## Context

The Python persistent server profile captures through a `CoreClient`. The default one is `NodeCoreBridge`, which runs `@redact-secret/core` in a Node.js child process. The [threat model](../specs/threat-model.md) marks that bridge "research-grade, not qualified" and lists what is missing: no dedicated adversarial qualification record, no fuzzing of the frame parser, no Windows run, plaintext that lingers in the child's heap for up to the process lifetime bounds, a core replaced on disk being picked up at the next process start, unbounded queuing delay behind its lock, and a discarded standard error. Persistence changes none of that and makes some of it matter more: the bridge receives the whole capture input, every secret in it and not only the retained ones, and an at-rest statement about a ciphertext-only store says nothing about the host's other copies of that plaintext (plan section 2.3).

Plan section 6.2 gives two ways out: close the gaps with their own record, or word the claim as "with an application-supplied, separately qualified `CoreClient`" and leave the bridge research-grade.

## Decision

1. **No Python persistence statement includes `NodeCoreBridge` as a qualified component.** Wherever a document says a cell of the persistent profile was run, it says capture went through the bridge as a test fixture, and that the claim is for a deployment whose `CoreClient` the application supplies and qualifies.
2. **The bridge's gaps stay open.** An adversarial protocol run, fuzzing of the frame parser, and a statement of supported operating systems are not done by the Python qualification record. Closing them is a separate record about the bridge, not about persistence.
3. **What the Python qualification does cover for capture** is the persistent server's use of a `CoreClient`: the capture plan shared with the in-memory server, the retained set, the UTF-16 range conversion, the required `expected_pii_activation`, and parity of what is stored with the JavaScript persistent server on the shared corpus. That evidence is about what the server does with findings, not about how the findings were obtained.
4. **A deployment that wants to rely on the bridge** states the residual risks in the threat model next to its at-rest statement, can use `max_scans_per_process=1`, one bridge per tenant or trust domain, or its own `CoreClient` (a separately qualified service), and runs its own bridge qualification.

## What would change this

A record that closes the three gaps above for named Node.js versions and operating systems would let the persistence documents name the bridge as qualified for those cells. Until it exists, decision 1 applies to every Python persistence statement.
