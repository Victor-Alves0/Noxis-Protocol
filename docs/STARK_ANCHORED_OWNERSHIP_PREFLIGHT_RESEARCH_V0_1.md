# Anchored ownership preflight research relation v0.1

## Status

This is an executable local composition of already-existing candidate
components. It supports a one-input wrapper and, for the fixed two-input
candidate statement, a sequential `H_INTENT` plus two-input preflight. Each
opaque P24 ownership proof is verified before it is dropped; the preflight
then retains only the public intent/ownership results, the typed `NXPS v2`
anchor and the local `NXSM` nullifier-transition bindings.

The implementation is
[`anchored_ownership.rs`](../crates/noxis-private-proof-contract/src/anchored_ownership.rs).
It is not a transfer proof, ledger verifier, wire packet or privacy activation.

## Relation

For a chosen input index `i` in the fixed two-input candidate statement, the
one-input wrapper checks all of the following:

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

`run_candidate_anchored_ownership_pair_preflight` applies that relation first
to canonical input zero, then to canonical input one. It requires both public
roots to equal the same `NXPS v2` note root, both public nullifiers to equal
the ordered `NXPU` inputs, and the two results to have distinct nullifiers.
The first proof object is dropped before the second proof begins. This is a
memory-conscious sequential check, **not** proof aggregation.

`run_candidate_intent_anchored_ownership_preflight` adds one narrower
operational sequence for a selected input: it first proves and verifies the
canonical `H_INTENT` relation, compares its public digest to that exact
statement, then proves and verifies the anchored ownership relation. The
returned receipt retains the intent digest, ownership result, input index and
statement ID only after both opaque proof objects are dropped. Its revalidation
checks those retained public and local-state bindings, but cannot reverify the
dropped proofs.

`run_candidate_intent_anchored_ownership_pair_preflight` is the corresponding
fixed-arity path: it proves and verifies `H_INTENT` once, then proves and
verifies canonical ownership input zero and input one in sequence. Both public
results must bind the same note root, their ordered intent nullifiers and the
same ordered two-nullifier `NXSM` witness. It returns only the intent result,
two ownership results and statement ID. Revalidation rejects a changed retained
intent commitment or any public/root/nullifier mismatch, but cannot reverify
the three dropped opaque proof objects.

## What this establishes

It eliminates a previously implicit gap in the executable research path: a
locally verified note-ownership proof can no longer be paired with an unrelated
candidate note root or with a different input nullifier from an otherwise valid
intent. For the two-input preflight, both owned notes are bound to the same
statement and ordered `NXSM` transition. The exact `NXPU` statement identity is
retained with the one-input proof wrapper or the two-input public receipt, and
revalidation rejects a different statement.

The intent preflights demonstrate that the executable canonical-byte `H_INTENT`
proof and one or both ownership proofs were checked against one statement
before every opaque proof is discarded. A changed retained intent commitment is
rejected during receipt revalidation.

## What this does not establish

This is **not** a single zero-knowledge proof of nullifier absence. The 512
`NXSM` siblings are still visible to the local preflight, and the P24 proof does
not constrain them. The two-input receipt cannot be independently used to
reverify either discarded opaque proof, and it is not a transferable proof.
It also does not prove outputs, value conservation, state transition
authorization or ledger acceptance.

It is also **not** cryptographic composition of `H_INTENT` and ownership: the
current backend has verified two separate local proofs in sequence. Recursion
or another reviewed composition scheme is required before a verifier can
accept one proof in place of this local run.

The next cryptographic composition must place the `NXSM` paths and their
pre/intermediate/post roots inside a reviewed proof relation. Given the current
research P24 prover cost, that must be preceded by an explicit backend and
performance design rather than a mechanically expanded 512-level experiment.

## Executable evidence

The focused release tests create real candidate note commitments and a
depth-32 snapshot, construct an `NXPS v2` anchor, derive an ordered
two-nullifier `NXSM` witness, prove ownership and verify the full local
composition. The second command runs the two proofs sequentially and is
substantially more expensive:

```powershell
cargo test --release -p noxis-private-proof-contract locally_composes_ownership_proof_note_anchor_and_nxsm_absence
cargo test --release -p noxis-private-proof-contract locally_composes_two_owned_notes_with_one_anchor_and_ordered_nxsm_transition
```

The first command executes the single-input `H_INTENT` plus anchored ownership
sequence. The second executes `H_INTENT` plus both ownership proofs for the
fixed 2×2 candidate fixture. Both mutate the retained commitment and confirm
that receipt revalidation rejects it.
