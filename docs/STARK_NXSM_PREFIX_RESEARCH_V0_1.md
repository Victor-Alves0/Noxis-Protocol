# Private `NXSM` prefix STARK research relation v0.1

## Status

This is an executable Plonky3 experiment for the real candidate `NXSM v1`
sparse-nullifier construction. Its basic relation proves one exact eight-level
segment. A local sequential preflight executes all 64 segments from the frozen
`E0` empty leaf to a candidate 512-level root, verifying and dropping each
opaque proof before beginning the next.

The implementation is
[`nxsm.rs`](../crates/noxis-stark-experiment/src/nxsm.rs). It is research code,
has no proof serialization or selected verifier profile, and must not protect
funds or personal data.

## Exact bounded relation

For one public nullifier `nf` and a byte index `j` in its 64-byte canonical
encoding, the prover derives the eight bits of `nf[j]`. The private witness has
eight 64-byte sibling
digests and seven 64-byte intermediate digests. Every private byte is range
checked with eight Boolean bits. Given a local start boundary held alongside
the opaque in-memory proof, the AIR proves:

```text
current[0]   = start
current[i+1] = H_NXSM_NODE(
  current[i], sibling[i], bit(nf, (8 * j) + i)
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
STARK public values contain the boundary, the selected nullifier byte and its
eight recomposed Boolean bits. The local start boundary is part of the
reconstructed in-memory AIR statement, not a portable public input. The public
API derives the bits from the typed nullifier; a caller cannot give it a
separate direction bitmap.

`prove_p24_nxsm_absence_prefix8` is the fixed convenience entry point for
`j = 0` and `start = E0`. `prove_p24_nxsm_absence_segment8` is the reusable
segment primitive. `run_p24_nxsm_absence_path512_sequential_preflight` joins
all 64 byte-indexed segments in process and accepts only the expected final
root. It retains no proof object or intermediate boundary when it returns.

## What this proves

It proves that a private eight-sibling segment reaches one public boundary
under the exact `NXSM` node construction and the corresponding canonical
nullifier directions. The sequential preflight has been executed end-to-end
against an actual candidate sparse-tree root: all 64 segments were verified
and the final root matched after 1,926.27 seconds in a release test on the
development machine. Tests reject a changed nullifier byte or a changed
boundary.

This is the first private `NXSM` component, not a substitute for the existing
transparent 512-level witness.

## What it does not prove

- It does **not** produce one transferable proof of absence at a 512-level
  `NXSM` root. The complete preflight is a local sequence of 64 proofs.
- It does **not** expose, update or validate the public `NXNT` pre/intermediate/post roots.
- It does **not** aggregate segments, recurse proofs, prove note ownership,
  enforce value conservation or authorize a ledger transition.
- It is not portable across a process or network boundary.

A full direct adaptation of the current wide-trace experiment to 512 levels
would multiply the expensive witness representation far beyond a credible
wallet or validator workload. Even the bounded sequential composition is about
32 minutes in the measured test. The next design and implementation step is a
reviewable recursive/aggregated composition strategy with a fixed portable
verifier profile; a sequence of local checks must never be presented as a
transferable proof.

## Executable evidence

```powershell
cargo test --release -p noxis-stark-experiment private_nxsm_prefix_binds_real_empty_leaf_node_domain_and_nullifier_bits
cargo test --release -p noxis-stark-experiment private_nxsm_terminal_segment_reaches_an_actual_sparse_tree_root
cargo test --release -p noxis-stark-experiment sequential_private_segments_reach_a_complete_candidate_nxsm_root -- --ignored
```

The first two tests derive an actual path from candidate sparse-tree state
containing spent nullifiers, prove both the first and final eight levels, and
compare their boundaries to the independent
`noxis-nullifier-tree-reference`. The ignored operational test derives all 512
siblings, runs the 64-proof local sequence and confirms the final candidate
root. It is ignored because the measured cost is unsuitable for normal CI.
