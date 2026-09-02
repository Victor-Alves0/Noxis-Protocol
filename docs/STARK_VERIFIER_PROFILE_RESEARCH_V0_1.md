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
representation in the pinned dependency set. The two retained proof wrappers
used by the private-transfer research path now expose the same capability as
explicit `encode_pinned_research_bytes` and `decode_pinned_research_bytes`
helpers. They serialize only the opaque Plonky3 object; callers still need to
retain and verify its public-result metadata and exact relation context.

This is not a Noxis proof artifact: those helpers emit no Noxis magic, do not
commit to a selected verifier/profile identifier, do not persist bytes, and
are not accepted by the ledger or network.

A second test writes those raw test bytes to a temporary file and starts a
fresh child test process to deserialize and verify them. It establishes a
same-host, same-build process boundary only; the temporary bytes are removed
after the test and are not a Noxis artifact.

## What this clarifies

The current hiding-FRI configuration is created with fresh operating-system
randomness for proof generation. The test proves that this process-local
randomness is not needed by a newly constructed verifier configuration with
the same code-level parameters.

## Explicit code-level descriptor

`ResearchStarkVerifierProfileV1` now centralizes the two experimental P24
profiles: `STANDARD_P24` uses FRI blowup `3`; `HIGH_DEGREE_P24` uses `4` for
the full-depth membership and NXSM AIRs. Both fix 32 FRI queries, no proof of
work, final polynomial log length `0`, maximum folding-arity log `1` and four
random codewords. The constructor consumes this descriptor instead of carrying
those values as scattered literals.

This is deliberately a Rust-level research descriptor, not a protocol
selection. Its source and locked dependencies still determine field, extension
degree, hash/PCS types and serialization behavior.

## Crucial limitation: this is still not portable verification

The configuration is now explicit in a versioned Rust descriptor, but it is
not a selected Noxis protocol verifier descriptor. The process-boundary test
uses the same test executable and pinned dependency set, so it does not
establish cross-version, cross-machine or independent-implementation
compatibility.

Consequently, these claims remain false:

- a proof can be verified by an independently started Noxis node build;
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
3. Extend the research descriptor into a canonical protocol descriptor that
   also fixes field, AIR, hash/PCS types, dependency compatibility and any
   immutable verifier material.
4. Specify a bounded canonical proof envelope in the wire/storage registry,
   including parser behavior, upgrade policy and negative test vectors.
5. Add cross-process and independent-implementation verification evidence,
   then perform adversarial testing and an external review.

Until every condition is met, the crypto service gate remains fail-closed.

## Reproduction

The following release test constructs a real depth-32 ownership proof, encodes
the opaque proof bytes, reconstructs it under a fresh high-degree research
configuration, verifies it, and then confirms that altered public metadata is
rejected:

```powershell
cargo test --release -p noxis-stark-experiment ownership::tests::ownership_stark_binds_one_private_key_note_position_leaf_and_path_to_the_public_root --lib -- --exact --nocapture
```

On 2026-09-02 this test emitted **1,066,268 bytes** for one serialized
depth-32 ownership proof. The fixed two-input relation therefore needs more
than 2 MiB for ownership proofs alone, before the intent/value proof or public
metadata. The current `NXPT v1` 2 MiB opaque-proof cap is consequently known
to be insufficient for this research bundle and must not be used as its future
transport budget. A bounded envelope needs full-bundle measurements and an
explicit denial-of-service review before selecting a replacement limit.
