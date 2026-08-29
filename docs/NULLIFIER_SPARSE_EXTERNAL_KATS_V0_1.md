# External `NXSM` sparse-tree KATs — v0.1

`NXSV v1` is a closed, externally calculated known-answer-test corpus for the
unselected `NXSM v1` sparse-nullifier-tree candidate. It is evidence for one
specific candidate only; it neither selects parameters nor enables private
transfers, settlement, or consensus use.

## What the corpus proves

The committed artifact is decoded by
`P24NullifierSparseVectorCorpusV1::frozen_external_kat_corpus`. Its exact
decoded bytes have SHA-256:

```text
e0309dd9cb2415ccf4ea3a0a97fc4f002fec6024f439821f030a7efa790c9b0d
```

The parser binds the corpus to the current `NXSM` candidate ID, rejects altered
framing and non-canonical BabyBear values, canonicalizes record ordering, and
requires this complete focused profile:

| Evidence | Coverage |
| --- | --- |
| Spent leaves | Two canonical 64-byte nullifiers: an all-one baseline and a boundary-heavy value |
| Ordered nodes | Both `left || right` and `right || left` for those leaves |
| Empty subtree values | Levels `0`, `1`, `2`, `32`, `255`, `511`, and `512` |
| Sparse roots | Empty, each individual spend, and the two-spend set |

The integration test in `noxis-nullifier-tree-state` checks every record using
both the immutable reference evaluator and the mutable state. In plain terms,
this confirms that the public rules for hashing, ordering, empty branches and
spending a nullifier all lead to the same results as a separately executed
implementation.

## Independent generation method

The generator at
[`scripts/audit/nxsm_nullifier_sparse_kat.rs`](../scripts/audit/nxsm_nullifier_sparse_kat.rs)
was executed as an example inside the Horizen `plain_implementations` source
snapshot at commit `055bde3f4782731ba5f5ce5888a440a94327eaf3`. It uses that
snapshot's `Poseidon2-BabyBear-P24` permutation; it does not call the Noxis
reference evaluator.

The script re-derives the three `NXSM` capacity IVs by rejection sampling
SHA-256 with the published `NXPH` parent ID and domain labels, applies
`BytePack3LE`, builds a depth-512 sparse tree, and writes canonical `NXSV v1`
bytes. Re-deriving the IVs is intentional: it removes manual transcription as
a source of false interoperability results.

For a fresh audit clone, copy the script to that clone's `examples/` directory
and run:

```text
cargo run --example nxsm_nullifier_sparse_kat
```

The command writes `nxsm_nullifier_sparse_kat_v1.bin`. Its SHA-256 must match
the value above before comparing its Base64 encoding with the committed fixture
at `crates/noxis-tree-params/fixtures/`.

## Boundaries

This is focused KAT coverage, not a proof-system implementation, fuzz campaign,
parameter-security review, storage format, selected tree parameter, or protocol
activation. The next design step is a separately versioned state-anchor
candidate that can bind an `NXSM` root and spent-count to a private transition;
that work still requires an AIR/proof backend and independent review.
