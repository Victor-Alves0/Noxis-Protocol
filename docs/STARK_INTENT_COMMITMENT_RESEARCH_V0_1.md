# Public `H_INTENT` STARK research relation v0.1

## Status

This is the first executable slice of the candidate `NXAR v1`
private-transfer AIR profile. It proves the exact candidate Poseidon2-P24
`H_INTENT` sponge evaluation over the 214 public `BytePack3LE` elements of a
canonical 640-byte `PrivateTransferIntentV2` encoding.

The implementation is
[`intent.rs`](../crates/noxis-stark-experiment/src/intent.rs). It is a Plonky3
research component with a hiding-FRI configuration, but its 214 input elements
and resulting 16-element commitment are public by design. It has no proof
serialization, selected verifier profile or production activation.

## Exact relation

`NXIC v1` fixes 214 three-byte little-endian field elements. The AIR starts a
P24 sponge with the frozen `H_INTENT` IV, absorbs those elements in fifteen
rate-15 blocks (the final block has four elements), applies the prescribed
fifteen permutations, then applies the squeezing permutation. Its 230 public
values are exactly:

```text
BytePack3LE(intent.encode())[0..214] || H_INTENT(intent.encode())[0..16]
```

No caller-chosen packing is accepted by the public API: it receives a typed
`PrivateTransferIntentV2`, uses its canonical encoder, and derives the digest
again through the independent candidate reference before proving. The AIR does
not yet decompose the public elements into bytes itself; that range and
recomposition constraint remains part of the complete transfer AIR.

## Evidence

The relation is checked against both frozen external `NXIV v1` records:

```powershell
cargo test --release -p noxis-stark-experiment intent_stark_matches_every_frozen_external_nxiv_vector
cargo run --release -p noxis-stark-experiment --bin noxis-stark-smoke
```

On the development machine, the two-vector release test completed in 15.83
seconds. A direct constraint test also rejects a changed public packed element
or a changed public commitment.

## What this does not prove

- It does **not** hide the transfer intent; this candidate statement makes the
  intent public.
- It does **not** prove note ownership, value conservation, output-note
  opening, nullifier absence or an `NXSM` transition.
- It does **not** compose with the existing ownership or `NXSM` research
  proofs, and is not a private transfer proof.
- It is not a proof format, a wallet operation, a validator operation or a
  ledger authorization.

The next AIR work joins this public frame to one witness family at a time,
starting with the existing private ownership-and-note-membership relation. A
backend must remain unselected and the service fail-closed until the complete
relation, proof profile and independent review exist.
