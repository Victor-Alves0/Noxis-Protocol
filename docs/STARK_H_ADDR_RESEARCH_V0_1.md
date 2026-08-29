# Private `H_ADDR` STARK research relation v0.1

## Status

This document specifies one executable Plonky3 research relation. It proves a
private preimage of the frozen, unselected `NXPH v1` `H_ADDR` candidate. It is
not a selected cryptographic primitive, wallet API, recipient-address scheme,
note-ownership proof, transaction proof or settlement authorization.

The implementation is [`addr.rs`](../crates/noxis-stark-experiment/src/addr.rs).
It uses a hiding FRI PCS, but its zero-knowledge properties and parameters have
not received an independent audit. Therefore it must not be used to protect
funds or personal data.

## Statement

The sole public input is a 16-element BabyBear digest:

```text
recipient_commitment[0..16) = H_ADDR(nullifier_key[32])
```

The 32-byte `nullifier_key` is private trace witness data. The AIR enforces:

1. each private byte is the sum of eight private Boolean bits;
2. the eleven absorbed elements are exactly `BytePack3LE(key)`;
3. the final two-byte group has no implicit third byte;
4. the first P24 permutation starts from those eleven elements, four zero rate
   lanes, and the frozen `NXPH/ADDR` capacity IV;
5. the first fifteen output elements come from that first permutation; and
6. the sixteenth output element comes from a second P24 permutation after its
   required external linear layer.

This is the same fixed 32-byte input, packing rule, IV and squeeze construction
used by `Poseidon2P24PrivacyReference::hash_addr`.

## What the verifier learns

The verifier learns only `recipient_commitment`. It does not receive the key,
bits, packed elements or intermediate sponge states.

This is deliberately a narrow primitive. It does **not** establish that the
same key is in a note opening, derives a public nullifier, controls an X25519
or ML-KEM key, owns a Merkle leaf, or is authorized by ledger state. Those
bindings must be imposed together in a later private-transfer AIR; they must
not be inferred by composing unrelated proofs off-chain.

## Executable evidence

Run the full research smoke program with:

```powershell
cargo run --release -p noxis-stark-experiment --bin noxis-stark-smoke
```

Focused tests compare the public commitment with the frozen reference and use
direct AIR constraint checks to reject a changed commitment, a non-Boolean bit,
an inconsistent byte, and an inconsistent packed element. They also prove both
of the frozen external `NXNV` `H_ADDR` vectors end-to-end.

## Next required composition

The next proof relation must preserve the exact byte witness and bind its
`recipient_commitment` into `H_NOTE`, then bind that note commitment and the
same key into `H_NULLIFIER`. Only after that, Merkle membership, state-anchor,
nullifier-absence, conservation and transaction-level bindings can form a
single private-transfer statement.
