# STARK verifier-profile research boundary v0.1

## Status

**Evidence, not a protocol format.** This document records one deliberately
small backend experiment. It does not select a proof system, define Noxis
proof bytes, or enable private-transfer settlement.

## What the executable test establishes

`noxis-stark-experiment` constructs a P24 permutation proof, serializes that
opaque Plonky3 proof with `postcard`, deserializes it, and verifies it again
with a **freshly constructed local STARK configuration** using the same pinned
code profile:

```powershell
cargo test --release -p noxis-stark-experiment p24_research_proof_round_trips_to_a_fresh_local_verifier_config
```

This is useful evidence that the experimental proof object has a serializable
representation in the pinned dependency set. It is intentionally a test-only
round trip: no bytes are emitted by a Noxis public API, persisted, accepted by
the ledger, or sent over the network.

## What this clarifies

The current hiding-FRI configuration is created with fresh operating-system
randomness for proof generation. The test proves that this process-local
randomness is not needed by a newly constructed verifier configuration with
the same code-level parameters.

## Crucial limitation: this is still not portable verification

The configuration is implicit in Rust code and pinned library versions; it is
not a public, versioned Noxis verifier descriptor. The test also executes in
one process and does not establish a cross-process, cross-version or
independent-implementation compatibility guarantee.

Consequently, these claims remain false:

- a proof can be verified by an independently started Noxis process;
- a serialized proof is a stable, canonical Noxis wire or storage format;
- the configuration, field encoding, trace-hiding behavior and FRI parameters
  are selected protocol parameters;
- a verifier can safely accept attacker-supplied proof bytes.

The experiment is evidence about a library capability, not evidence of a
portable proof system.

## Conditions before a verifier profile may be proposed

1. Select and independently review the complete private-transfer relation and
   proof backend.
2. Define a public, versioned verifier descriptor that fixes field, AIR,
   Poseidon parameters, FRI/PCS parameters, verifier material and dependency
   compatibility rules.
3. Publish a descriptor that reconstructs the verification configuration (or
   prescribes immutable verifier material) without relying on implicit Rust
   code or process-local state.
4. Specify a bounded canonical proof envelope in the wire/storage registry,
   including parser behavior, upgrade policy and negative test vectors.
5. Add cross-process and independent-implementation verification evidence,
   then perform adversarial testing and an external review.

Until every condition is met, the crypto service gate remains fail-closed.
