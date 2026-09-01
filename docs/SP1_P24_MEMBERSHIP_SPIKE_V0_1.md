# SP1 P24 membership spike — v0.1

## Purpose

This bounded research spike asks one narrow question: can an isolated SP1 guest
evaluate the exact frozen Noxis candidate Poseidon2-BabyBear-P24 construction
for one private depth-32 membership path, while publishing only its root?

It is **not** a production recursive-backend selection, a Noxis wire proof,
or a private-transfer implementation.

## Relation

The guest receives privately:

- one 16-element note commitment;
- one 32-bit leaf position;
- 32 ordered, 16-element sibling values.

It computes the candidate leaf, orders each pair from the corresponding index
bit, performs all 32 candidate node transformations, and publishes exactly one
64-byte root: sixteen canonical BabyBear elements in little-endian order.

The host obtains the fixture from `noxis-poseidon2-reference`, then asserts
that `noxis-poseidon2-core` reconstructs the same root before it asks SP1 to
execute or prove the relation. This gives two independently structured paths:
the pre-existing auditable reference and a small, `no_std`, allocation-free
kernel that the guest can use.

## Canonical parameter boundary

`noxis-poseidon2-core` does not carry another copy of the P24 parameters. Its
build step reads the frozen fixture already owned by `noxis-tree-params` and
rejects a different length, SHA-256 checksum, or non-canonical field element
before generating the fixed parameter array. It has no manifest parser, file
reader, consensus rule, or tree format.

This is intentionally a code-portability boundary, not a new wire or storage
format.

## Reproduction

SP1 is exercised only in the supported local WSL environment:

```bash
cd spikes/sp1-p24-membership
bash scripts/check-wsl.sh
bash scripts/run-wsl.sh --execute
bash scripts/run-wsl.sh --prove
```

The script must report the root equality after execution, and the proof path
must complete local verification before either result is counted as evidence.

## Measured status

The isolated guest has executed locally and its 64-byte public root matched the
independent Noxis P24 reference path. The first direct evaluator required
50,546,572 cycles. Two semantics-preserving optimizations (the canonical
`J + diagonal` internal layer and single-subtraction BabyBear addition)
reduced this to **15,680,422 cycles** while retaining the same root and all
reference-vector checks.

The local SP1 core-proof attempt is **not yet accepted evidence**: it was
terminated by the WSL out-of-memory killer at roughly 21 GiB resident memory.
This happened both before and after the cycle reductions. The command remains
in the spike to make the constraint reproducible, but this document does not
claim a locally verified P24 membership proof.

The next technical direction is a genuinely bound segmented/recursive design:
it must keep each path segment private and cryptographically bind adjacent
segment roots. Merely proving two halves and having a host compare them would
not prove one private membership relation and is therefore not acceptable.

## Explicit non-claims

This spike does not yet bind:

- an address or a wallet key;
- a note opening or encrypted recipient payload;
- a nullifier or a spent-nullifier state check;
- the `NXPU` packet, relation kind, input index, proof-envelope ID, or a
  selected tree-parameter identity;
- any outer proof, recursion, consensus admission, or network message.

Those are separate obligations. In particular, a root-membership proof alone
does not demonstrate ownership, anonymity, double-spend prevention, or a
safe production recursive verifier.

## Promotion gates

The spike can only inform the backend decision after all of these are met:

1. execution and a locally verified proof are reproducible;
2. canonical output and witness bindings are specified, including the P24
   candidate identity and Noxis statement context;
3. the full key/address, note and nullifier relations are added without
   weakening their existing native checks;
4. an independent review plan covers guest code, serialization and proof
   verification; and
5. no hosted prover is required for correctness.

The governing decision remains
[Recursive backend decision](RECURSIVE_BACKEND_DECISION_V0_1.md).
