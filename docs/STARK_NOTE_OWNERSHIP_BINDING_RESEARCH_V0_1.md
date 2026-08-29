# Private note-ownership binding STARK research relation v0.1

## Status

This document specifies one executable Plonky3 research relation. It composes
the frozen, unselected `NXPH v1` candidate functions `H_ADDR`, `H_NOTE` and
`H_NULLIFIER`, plus the frozen tree candidate `H_LEAF`, in one hiding-FRI
STARK. It is not a selected cryptographic primitive, wallet API,
Merkle-membership proof, transaction proof or settlement authorization.

The implementation is
[`ownership.rs`](../crates/noxis-stark-experiment/src/ownership.rs). Its
zero-knowledge properties, proof parameters and the underlying candidate have
not received independent cryptographic review. It must not protect funds or
personal data.

## Statement

The sole public input is a 16-element BabyBear nullifier digest. The private
witness contains a 32-byte nullifier key, a 178-byte note preimage and a
four-byte big-endian leaf position. The AIR proves together:

```text
recipient_commitment = H_ADDR(nullifier_key)
note_commitment      = H_NOTE(note_preimage)
nullifier            = H_NULLIFIER(
    nullifier_key || rho || note_commitment-u32le || leaf_position-u32be
)
tree_leaf            = H_LEAF(note_commitment)
```

It additionally enforces that:

1. every private byte is range-checked by eight Boolean witness bits;
2. every private sponge input follows exact fixed-length `BytePack3LE`;
3. the note version bytes are exactly `u16be(1)`;
4. the 64 note recipient bytes encode exactly the private `H_ADDR` digest;
5. the 64 bytes inside `H_NULLIFIER` encode exactly the private `H_NOTE`
   digest in canonical `u32le` lane order; and
6. `rho` and the position used by `H_NULLIFIER` are taken from the same note
   witness and position witness, respectively; and
7. the private tree leaf is exactly the candidate tree-domain hash of the same
   private note commitment.

The recipient and note commitments are retained only as private AIR witness
values; they are not independent public inputs. That prevents a verifier from
linking this narrow proof to a recipient or note commitment merely by observing
it. The only public value is the deterministic nullifier.

## What this proves — and what it does not

This is the first executable binding that establishes knowledge of a key
committed inside a note, uses that same key to derive its nullifier, and derives
the exact leaf which must enter the candidate note tree. It is a necessary
ownership subrelation for a private spend.

It does **not** prove that this leaf is in the note tree, that the supplied
position has a valid path, that the nullifier is absent from state, that the
asset/value fields satisfy transfer rules, that the note is unspent, that an
envelope can be decrypted by a hybrid recipient key, or that a ledger accepts
anything. It also does not yet enforce every semantic `NoteOpeningV2` rule
such as value/padding policy. None of those properties may be inferred from
this proof.

## Executable evidence

Run the full research smoke program with:

```powershell
cargo run --release -p noxis-stark-experiment --bin noxis-stark-smoke
```

Focused tests prove a synthetic internally consistent note end-to-end against
the frozen reference and directly reject a changed public nullifier, a
recipient byte that no longer corresponds to the private key, an altered note
commitment byte, or an altered private tree leaf.

## Next required composition

The next ownership extension must use this private `tree_leaf` in its complete
private depth-32 Merkle path to a public state root, then establish nullifier
absence against a public nullifier-state anchor. Only after that can the
relation be combined with asset/value conservation, outputs, encrypted
envelopes and a state transition.
