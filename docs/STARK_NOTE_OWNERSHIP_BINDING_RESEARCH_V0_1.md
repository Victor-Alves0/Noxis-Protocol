# Private note-ownership binding STARK research relation v0.1

## Status

This document specifies one executable Plonky3 research relation. It composes
the frozen, unselected `NXPH v1` candidate functions `H_ADDR`, `H_NOTE` and
`H_NULLIFIER`, plus the frozen tree candidates `H_LEAF` and `H_NODE`, in one
hiding-FRI STARK. It proves a complete private depth-32 candidate-Merkle path
to one public root. It is not a selected cryptographic primitive, wallet API,
transaction proof or settlement authorization.

The implementation is
[`ownership.rs`](../crates/noxis-stark-experiment/src/ownership.rs). Its
zero-knowledge properties, proof parameters and the underlying candidate have
not received independent cryptographic review. It must not protect funds or
personal data.

## Local prover/verifier boundary

`prove_p24_note_ownership_path32` returns an opaque in-memory proof object and
its public result. `verify_p24_note_ownership_proof` reconstructs the frozen
AIR and independently verifies that object using only its public nullifier and
root. The compatibility helper still performs both steps in one call.

There is deliberately no proof encoder, decoder, wire frame or ledger adapter.
Plonky3 serialization details, the candidate parameters and a verifier profile
must be selected and reviewed together before a proof can cross a process or
network boundary.

## Statement

The public inputs are a 16-element BabyBear nullifier digest and a 16-element
candidate-tree root. The private witness contains a 32-byte nullifier key, a
178-byte note preimage, a four-byte big-endian leaf position, 32 siblings and
31 intermediate path values. The AIR proves together:

```text
recipient_commitment = H_ADDR(nullifier_key)
note_commitment      = H_NOTE(note_preimage)
nullifier            = H_NULLIFIER(
    nullifier_key || rho || note_commitment-u32le || leaf_position-u32be
)
tree_leaf            = H_LEAF(note_commitment)
path[0]              = H_NODE(tree_leaf, sibling[0], position.bit(0))
path[i + 1]          = H_NODE(path[i], sibling[i + 1], position.bit(i + 1))
root                 = path[31]
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
   private note commitment; and
8. every one of the 32 private sibling values is ordered with the corresponding
   bit of the same private position used by `H_NULLIFIER`, producing the public
   root.

The recipient and note commitments, leaf, siblings, directions and intermediate
nodes are retained only as private AIR witness values; they are not independent
public inputs. The public values are the deterministic nullifier and the
depth-32 root.

## What this proves — and what it does not

This executable binding establishes knowledge of a key committed inside a
note, uses that same key to derive its nullifier, derives the exact candidate
tree leaf and proves a complete private depth-32 path to a public root. It is a
necessary ownership-and-membership subrelation for a private spend.

It does **not** establish that the public root is a current or accepted
state-anchor, that the nullifier is absent from state, that the asset/value
fields satisfy transfer rules, that the note is unspent, that an envelope can
be decrypted by a hybrid recipient key, or that a ledger accepts anything. It
also does not yet enforce every semantic `NoteOpeningV2` rule such as
value/padding policy. None of those properties may be inferred from this proof.

## Executable evidence

Run the full research smoke program with:

```powershell
cargo run --release -p noxis-stark-experiment --bin noxis-stark-smoke
```

Focused tests prove a synthetic internally consistent note end-to-end against
the frozen reference and directly reject a changed public nullifier or root, a
recipient byte that no longer corresponds to the private key, an altered note
commitment byte, an altered private tree leaf or an altered private sibling.
The mutation suite covers both the first and terminal private path levels, as
well as the final private intermediate node.
The proof is intentionally expensive research code: its 8,192-row trace and
wide private witness are not a wallet or validator performance target.

## Next required composition

The next required extension is nullifier absence against a public
nullifier-state anchor and an explicit policy binding the public root to a
state snapshot. Only after that can the relation be combined with asset/value
conservation, outputs, encrypted envelopes and a state transition.
