# Candidate private-proof transport budget v0.1

## Purpose and status

This document fixes a **candidate receiver-side resource budget** for the
currently executable, three-proof private-transfer research bundle. It is not
a wire format, proof-verifier selection, consensus rule, wallet benchmark or
production denial-of-service policy. The active service remains fail-closed.

It intentionally does not modify `NXPT v1`. `NXPT` has one opaque proof field
limited to 2 MiB, while the current research bundle already exceeds that
limit. Reusing or silently widening that legacy field would blur unrelated
packet and proof-bundle designs.

## Measured input

The complete optimized release path measured **4,968,511 raw bytes** on
2026-09-02:

| Relation | Raw pinned-research bytes |
| --- | ---: |
| intent/value conservation | 2,836,034 |
| ownership input 0 | 1,066,377 |
| ownership input 1 | 1,066,100 |
| **Total** | **4,968,511** |

This is one reproducible research-case measurement, not a maximum proof size.
The command and its limitations are recorded in
[the proof-bundle evidence](PRIVATE_TRANSFER_PROOF_BUNDLE_RESEARCH_V0_1.md).

## Candidate bound

`noxis-private-proof-contract::CandidatePrivateProofTransportBudgetV1`
enforces the following independent, inclusive limits before a future envelope
decoder can reserve variable-length storage:

| Component | Limit | Rationale |
| --- | ---: | --- |
| Raw aggregate of the three proof chunks | 8,388,608 bytes (8 MiB) | Leaves 3,420,097 bytes above the measured bundle without treating that margin as a security guarantee. |
| Canonical framing and public metadata | 65,536 bytes (64 KiB) | Makes non-proof bytes visible and bounded rather than silently borrowing proof capacity. |
| Total envelope bytes | 8,454,144 bytes | Sum of the two explicit limits. |

The checks are fail-closed: a proof aggregate or metadata region one byte above
its own cap is rejected. The aggregate total is checked with overflow-safe
addition as well.

## What this does not solve

An allocation cap does not bound the CPU, stack, peak memory or algorithmic
cost of decoding and verifying attacker-supplied Plonky3 proof bytes. Before a
new `NX..` envelope can be proposed, the project still needs all of the
following:

1. Strict canonical framing with a per-chunk limit checked before allocation.
2. Candidate deployment and statement bindings, including exact relation
   ordering and no caller-selected receipt identities.
3. Adversarial-size decode and verification benchmarks at the caps, with
   timeout, memory and concurrency policy.
4. Fuzzing of every length, truncation, trailing-byte and malformed-field path.
5. A separate review before any network, ABCI, wallet or consensus admission.

The next implementation step may therefore use this budget only to build a
separate **candidate local proof-bundle envelope**. It must serialize, decode,
reconstruct and independently verify all three relations before a ledger can
consume it; it cannot activate private settlement merely by existing.
