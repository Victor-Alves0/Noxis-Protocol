# Private `NXSM` prefix STARK research relation v0.1

## Status

This is an executable, bounded Plonky3 experiment for the real candidate
`NXSM v1` sparse-nullifier construction. It proves the first eight levels of
one absence path, starting from the frozen `E0` empty leaf and using the real
`NXSM` `Node` domain, IV and `BytePack3LE` encoding for the ordered 128-byte
child input.

The implementation is
[`nxsm.rs`](../crates/noxis-stark-experiment/src/nxsm.rs). It is research code,
has no proof serialization or selected verifier profile, and must not protect
funds or personal data.

## Exact bounded relation

For one public nullifier `nf`, the prover derives its first canonical byte and
the eight least-significant bits. The private witness has eight 64-byte sibling
digests and seven 64-byte intermediate digests. Every private byte is range
checked with eight Boolean bits. The AIR starts from the frozen candidate empty
leaf `E0` and proves:

```text
current[0]   = E0
current[i+1] = H_NXSM_NODE(
  current[i], sibling[i], bit(nf, i)
) for i = 0..7
boundary = current[8]
```

`H_NXSM_NODE` is not treated as a 32-element field hash. Its two 16-lane
digests are serialized as canonical little-endian `u32` bytes, concatenated in
the direction selected by the nullifier bit, then packed as 43 exact
`BytePack3LE` elements before the four prescribed P24 permutations. The public
boundary is constrained to the final output; all siblings and intermediate
bytes remain in the hidden trace.

The verifier API derives the eight bits from the stored typed nullifier. The
STARK public values contain the boundary, the first nullifier byte and its
eight recomposed Boolean bits. This is sufficient for levels 0–7; later
segments will bind their corresponding canonical nullifier byte.

## What this proves

It proves that a private eight-sibling prefix from the exact candidate `E0`
reaches one public boundary under the exact `NXSM` node construction and the
first eight canonical nullifier directions. Tests reject a changed nullifier
prefix byte or a changed boundary.

This is the first private `NXSM` component, not a substitute for the existing
transparent 512-level witness.

## What it does not prove

- It does **not** prove absence at a 512-level `NXSM` root.
- It does **not** expose, update or validate the public `NXNT` pre/intermediate/post roots.
- It does **not** aggregate segments, recurse proofs, prove note ownership,
  enforce value conservation or authorize a ledger transition.
- It is not portable across a process or network boundary.

A full direct adaptation of the current wide-trace experiment to 512 levels
would multiply the expensive witness representation far beyond a credible
wallet or validator workload. The next design and implementation step is a
reviewable composition strategy — preferably recursive/aggregated — that keeps
the full-depth statement private without presenting a sequence of local checks
as a transferable proof.

## Executable evidence

```powershell
cargo test --release -p noxis-stark-experiment private_nxsm_prefix_binds_real_empty_leaf_node_domain_and_nullifier_bits
```

The test derives an actual path from candidate sparse-tree state containing
spent nullifiers, proves and verifies its first eight absence levels, compares
the public boundary to the independent `noxis-nullifier-tree-reference`, then
rejects changed public bindings.
