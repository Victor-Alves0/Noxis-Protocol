# Private `H_NOTE` STARK research relation v0.1

## Status

This document specifies one executable Plonky3 research relation. It proves a
private preimage of the frozen, unselected `NXPH v1` `H_NOTE` candidate. It is
not a selected cryptographic primitive, wallet API, note-ownership proof,
transaction proof or settlement authorization.

The implementation is [`note.rs`](../crates/noxis-stark-experiment/src/note.rs).
It uses a hiding FRI PCS, but its zero-knowledge properties and parameters have
not received an independent audit. Therefore it must not be used to protect
funds or personal data.

## Statement

The sole public input is a 16-element BabyBear digest:

```text
note_commitment[0..16) = H_NOTE(note_preimage[178])
```

All 178 preimage bytes are private trace witness data. The AIR enforces:

1. each private byte is the sum of eight private Boolean bits;
2. the sixty absorbed elements are exactly `BytePack3LE(note_preimage)`;
3. the final two-byte group has no implicit third byte;
4. the four 15-element input blocks are absorbed in order under the frozen
   `NXPH/NOTE` capacity IV;
5. each inter-block state receives precisely the next block before the required
   external linear layer and P24 permutation; and
6. the first fifteen digest elements and the sixteenth squeezed element are
   the prescribed P24 sponge output.

This is the same fixed input length, packing rule, IV, block order and squeeze
construction used by `Poseidon2P24PrivacyReference::hash_note`.

## What the verifier learns

The verifier learns only `note_commitment`. It does not receive the preimage,
bits, packed elements, intermediate sponge states, asset, value, recipient,
or note randomness.

This relation deliberately proves only a byte-exact hash. In particular, it
does **not** yet establish that the bytes are a semantically valid
`NoteOpeningV2`, that a regular note has a non-zero value, that its recipient
field equals `H_ADDR(nullifier_key)`, that its `rho` is used by
`H_NULLIFIER`, that it belongs to a Merkle tree, or that it is authorized by
ledger state. Those conditions must be joined in one later private-transfer
AIR; unrelated proofs must not be composed off-chain to infer those bindings.

## Executable evidence

Run the full research smoke program with:

```powershell
cargo run --release -p noxis-stark-experiment --bin noxis-stark-smoke
```

Focused tests compare the public commitment with the frozen reference and use
direct AIR constraint checks to reject a changed commitment, a non-Boolean bit,
an inconsistent byte, and an inconsistent packed element. They also prove both
of the frozen external `NXNV` `H_NOTE` vectors end-to-end.

## Next required composition

The next relation must use one shared private note-opening witness: it must
derive `recipient_commitment = H_ADDR(nullifier_key)`, constrain the recipient
bytes inside `H_NOTE` to that commitment, and derive `H_NULLIFIER` from the
same key, `rho`, note commitment and leaf position. This is the first point at
which note ownership becomes a cryptographically meaningful statement.
