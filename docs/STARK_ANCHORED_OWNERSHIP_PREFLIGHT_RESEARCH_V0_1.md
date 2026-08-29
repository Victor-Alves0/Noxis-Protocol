# Anchored ownership preflight research relation v0.1

## Status

This is an executable local composition of already-existing candidate
components. It binds one opaque P24 ownership proof to one input of a canonical
`NXPU v1` public statement, then revalidates the typed `NXPS v2` anchor and the
local `NXSM` nullifier-transition witness.

The implementation is
[`anchored_ownership.rs`](../crates/noxis-private-proof-contract/src/anchored_ownership.rs).
It is not a transfer proof, ledger verifier, wire packet or privacy activation.

## Relation

For a chosen input index `i` in the fixed two-input candidate statement, the
preflight checks all of the following:

```text
P24 ownership proof verifies
P24_proof.root      == NXPS-v2.note_root
P24_proof.nullifier == NXPU.intent.nullifiers[i]
NXPU / NXPS-v2 / pre-tree revalidate together
NXSM local witness proves the ordered two-nullifier absence/update relation
```

The P24 key, note opening, leaf position and 32 note-tree siblings remain
inside the opaque ownership proof. The state anchor binds the note root,
candidate `NXSM` root, spent count, genesis and validation context. The `NXSM`
path witness is supplied locally and transparently, so it is not protected by
the P24 proof.

## What this establishes

It eliminates a previously implicit gap in the executable research path: a
locally verified note-ownership proof can no longer be paired with an unrelated
candidate note root or with a different input nullifier from an otherwise valid
intent. The exact `NXPU` statement identity is retained with the proof wrapper,
and verification rejects a different statement before accepting the proof.

## What this does not establish

This is **not** a single zero-knowledge proof of nullifier absence. The 512
`NXSM` siblings are still visible to the local preflight, and the P24 proof does
not constrain them. It also does not prove the second input's ownership,
outputs, value conservation, state transition authorization or ledger
acceptance.

The next cryptographic composition must place the `NXSM` paths and their
pre/intermediate/post roots inside a reviewed proof relation. Given the current
research P24 prover cost, that must be preceded by an explicit backend and
performance design rather than a mechanically expanded 512-level experiment.

## Executable evidence

The focused release test creates a real candidate note commitment, places it at
position zero of a candidate depth-32 snapshot, constructs its `NXPS v2`
anchor, derives a two-nullifier `NXSM` witness, proves ownership, and verifies
the full local composition:

```powershell
cargo test --release -p noxis-private-proof-contract locally_composes_ownership_proof_note_anchor_and_nxsm_absence
```
