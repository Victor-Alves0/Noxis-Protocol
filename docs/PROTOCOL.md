# Protocol Overview

## Status

Noxis is a research-stage Rust protocol for privacy-preserving, multi-asset
settlement. It has deterministic ledger rules, durable local replay, a
CometBFT ABCI integration boundary, and an active research path for private
notes and STARK proofs. It is **not** a production network, wallet, custody
system, or private-payment system.

## What the protocol is trying to provide

At the ledger layer, an accepted transition must use known assets, preserve
canonical encoding, add new commitments, and never spend a nullifier twice.
The eventual private-transfer path is intended to prove ownership, note
membership, nullifier derivation, value conservation and valid output notes
without disclosing the witness.

## What works today

- Deterministic transition validation, canonical transaction codecs, commitment
  uniqueness and nullifier single-use rules.
- Genesis/state identities, durable replay and guarded local-node lifecycle.
- A research-only local operational demo.
- A Plonky3 STARK experiment that proves the frozen Poseidon2-P24 candidate
  permutation, `Hash16(Leaf, commitment)` and ordered
  `Hash16(Node, left || right)` against external vectors, plus one private
  ordered Merkle step; it is not a membership or private-transfer proof.

## What does not exist yet

There is no deployed validator network, production proof verifier, audited
wallet, anonymous transaction path, active post-quantum protection, asset
custody, or authorization to handle value.

## Canonical specifications

Read [PROTOCOL_SPEC_V0_1.md](PROTOCOL_SPEC_V0_1.md) for the current state
machine, [ARCHITECTURE.md](ARCHITECTURE.md) for module boundaries, and
[PROJECT_PLAN.md](PROJECT_PLAN.md) for the implementation sequence.
