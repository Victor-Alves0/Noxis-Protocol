# Private-transaction reference architectures — v0.1

## Status and scope

This is a non-normative source study for the next Noxis implementation gate.
It does not import upstream code, select a production proof backend, create a
wire format, or approve private settlement. The repositories were cloned into
a temporary directory and inspected read-only at these snapshots:

| System | Snapshot | Primary implementation boundary |
|---|---|---|
| Zcash Orchard | `38bd227439117e5bcd031026218299c9ae310095` | [`src/circuit.rs`](https://github.com/zcash/orchard/blob/38bd227439117e5bcd031026218299c9ae310095/src/circuit.rs) and [`src/bundle.rs`](https://github.com/zcash/orchard/blob/38bd227439117e5bcd031026218299c9ae310095/src/bundle.rs) |
| Penumbra | `36a31c17974c23a7e84cc02c64f0062ae57e79b1` | [`spend/proof.rs`](https://github.com/penumbra-zone/penumbra/blob/36a31c17974c23a7e84cc02c64f0062ae57e79b1/crates/core/component/shielded-pool/src/spend/proof.rs), [`action_handler/spend.rs`](https://github.com/penumbra-zone/penumbra/blob/36a31c17974c23a7e84cc02c64f0062ae57e79b1/crates/core/component/shielded-pool/src/component/action_handler/spend.rs), and [`transaction/plan/build.rs`](https://github.com/penumbra-zone/penumbra/blob/36a31c17974c23a7e84cc02c64f0062ae57e79b1/crates/core/transaction/src/plan/build.rs) |
| Aztec | `f6bf8487959ae7ea35bbe9f2e4021bd35d8ea162` | [`private_kernel_init.nr`](https://github.com/AztecProtocol/aztec-packages/blob/f6bf8487959ae7ea35bbe9f2e4021bd35d8ea162/noir-projects/fnd/noir-protocol-circuits/crates/private-kernel-lib/src/private_kernel_init.nr) and [`private_kernel_inner.nr`](https://github.com/AztecProtocol/aztec-packages/blob/f6bf8487959ae7ea35bbe9f2e4021bd35d8ea162/noir-projects/fnd/noir-protocol-circuits/crates/private-kernel-lib/src/private_kernel_inner.nr) |
| SP1 | `4f56564727906846f80b30532dde26eacfc7e44c` plus pinned SDK `6.5.0` | [`crates/prover/src/recursion.rs`](https://github.com/succinctlabs/sp1/blob/4f56564727906846f80b30532dde26eacfc7e44c/crates/prover/src/recursion.rs) and the `ProveRequest` mode boundary |

## What the systems actually do

### Orchard: one auditable Action relation, repeated in a bundle

The Orchard Action circuit privately witnesses the old note material, Merkle
path, position, keys, values and randomness. It constrains commitment-tree
membership, value-commitment integrity, nullifier derivation, spend authority,
recipient integrity and the new note commitment. Its public `Instance` carries
the anchor, net value commitment, nullifier, randomized authorization key, new
commitment and flags.

A bundle maps every action to the same public-instance shape. Proof creation
accepts arrays of circuits and instances, and bundle verification reconstructs
those instances from the transaction. The useful lesson is not Orchard's
specific curve or circuit: it is the stable, repeated action statement and the
strict reconstruction of public inputs from transaction effects.

### Penumbra: prove each action, bind the whole transaction separately

Penumbra is the closest match to the bounded Noxis transfer. A spend proof has
four public values: anchor, balance commitment, nullifier and randomized spend
authorization key. Stateless admission verifies the authorization signature
and proof. Stateful execution separately checks that the public nullifier is
unspent and then records it.

The transaction planner obtains commitment witnesses under one anchor, builds
actions (optionally in parallel), inserts authorization data and creates a
binding signature from the accumulated value blinding factors. Proof
aggregation is not required before a complete shielded transaction exists.

### Aztec: recursive kernels for arbitrary private call composition

Aztec's private kernel Init validates the first private call and initializes
accumulated note hashes, nullifiers, validation requests and other side
effects. Each Inner kernel verifies the previous kernel proof, validates one
more private call and propagates a new public accumulator. Reset and Tail
circuits normalize and finalize that accumulated state.

This is the relevant long-term pattern if Noxis adopts private smart contracts.
It is intentionally more complex than needed for the first fixed two-input,
two-output transfer.

### SP1: core sharding and recursive compression are different products

In SP1 6.5.0 the proof request defaults to `Core`. The SDK documents that a
core proof grows with the execution length. `Compressed` recursively aggregates
the core shard proofs into one constant-size proof. The prover controller sends
the stream of core proofs into a reduction tree when the selected mode is not
`Core`.

Consequently, reducing trace thresholds while continuing to request a core
proof is a resource diagnostic, not a recursion benchmark. Noxis must request
and verify `Compressed` explicitly when evaluating SP1 as a composition
backend.

## Noxis decision for the next executable milestone

The first private-transfer integration will not wait for recursive aggregation.
It will follow an action-oriented boundary close to Penumbra and Orchard:

1. reconstruct one canonical `NXPU v1` public statement from the candidate
   `NXPT` transaction and validated recipient envelopes;
2. verify the existing intent/value relation against that exact statement;
3. verify one ownership-and-membership proof for each of the two input slots,
   with relation kind and input index domain-separated;
4. verify both output-note relations against the same statement;
5. require all receipts to carry the same statement identity and verifier
   profile;
6. let the ledger atomically reject duplicate or already-spent public
   nullifiers and only then mutate commitments and nullifier state.

This may initially be a research-only in-memory bundle behind an explicit
feature gate. It is not assigned a wire magic, `ProofVerifierId`, or consensus
approval until serialization, verifier identity and failure behavior are
fixed. Recursive compression remains the next optimization and portability
gate, not the prerequisite for demonstrating one real local private transfer.

## Why this is safer than host-side stitching

The host is not allowed to compare unrelated proof outputs and call the result
a transfer. Every accepted inner proof must be independently verified and bind
the same canonical statement ID, relation kind, input slot, tree anchor and
verifier profile. Atomic ledger admission then enforces the stateful invariants
that proofs alone cannot establish against concurrent transactions.

## Explicit non-claims

This study does not establish that:

- Orchard, Penumbra, Aztec or SP1 primitives are suitable for direct reuse;
- multiple Noxis research proofs are already accepted by the ledger;
- public nullifiers solve network-level transaction linkability;
- SP1 compressed proving fits the local resource budget;
- the Noxis hybrid post-quantum profile is compatible with any cited circuit;
- the candidate bundle is ready for a public testnet.

The next implementation artifact is a typed, in-memory research bundle and
fail-closed verifier adapter. A new portable proof format comes only after that
path executes end to end and its bindings are reviewed.
