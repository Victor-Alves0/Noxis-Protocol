# Noxis Protocol — State Chain Specification v0.1

## Status and scope

This document specifies the legacy local-record state-chain contract for the
`NXRF` persistent Noxis ledger mode. It defines how an ordered transaction record identifies its predecessor
and resulting ledger state, how checkpoints bind to that history, and when
recovery must fail closed.

The present v0.1 implementation derives a deterministic local `StateId` from
the ledger's canonical public components, derives a transaction intent identity
that avoids self-reference, and persistently frames strict `NXRC` records in
an `NXRF` log. On opening, it replays every complete record from its configured
initial state, checks the sequence/state links, re-runs ledger validation, and
recomputes each resulting state ID before enabling writes. It handles only a
structurally incomplete final frame, and only after the full complete prefix
has passed replay. `StateId` is now bound to `GenesisId`; `NXCP` checkpoints
are published and compared to this strict replay, but cannot skip an
unauthenticated history prefix. Transfer-proof and mint-authorization
statements now carry `GenesisId`, `ValidationContextId`, the transaction intent
and pre-transition `StateId`; the intent ID itself remains deliberately free of
those fields to avoid a binding cycle and is not a network identifier.

The `NXRF` state chain is local storage history. It is not the authority in
`CometBlockJournalV1`, where `NXCB` recovery is specified separately in
[DURABILITY_SPEC_V0_1.md](DURABILITY_SPEC_V0_1.md). Neither format alone
provides distributed finality, Byzantine fault tolerance, proof soundness, or
a defense against a malicious host or storage administrator.

## Definitions

| Term | Meaning |
| --- | --- |
| **State** | The complete logical ledger state: registered assets, issued supply, accepted commitments, spent nullifiers, and accepted transaction identifiers. |
| **State identifier** | A versioned, canonical, domain-separated commitment to exactly one logical state. It is not a hash of language-runtime memory layout. |
| **Genesis state** | The initial state defined by a verified genesis artifact. It has sequence number zero. |
| **Record** | One complete durable representation of one validated transaction transition. |
| **Sequence number** | The non-negative integer position of a state in the chain. Genesis is `0`; a record transitioning from `n` to `n + 1` has sequence `n + 1`. |
| **Predecessor identifier** | The state identifier that a record requires before it can apply. |
| **Result identifier** | The state identifier that must result after applying a record. |
| **Checkpoint** | A durable, canonical materialization of state at one sequence number, verified against strict replay; it is not yet authorized to shorten recovery. |

## Canonical state identity

Before network-final persistent operation is enabled, the protocol must extend
the current canonical state-identifier algorithm to commit, with explicit domain
separation and versioning, to:

- the genesis/deployment identity and protocol rule version;
- the complete asset registry and each asset definition;
- issued supply for every registered asset;
- the complete set (or canonical accumulator) of accepted commitments;
- the complete set (or canonical accumulator) of spent nullifiers; and
- the complete set (or canonical accumulator) of accepted transaction IDs.

The algorithm must define ordering, byte encoding, handling of empty sets,
integer widths, and all hash/accumulator parameters. If it uses accumulators or
Merkle trees, the construction, leaf encoding, ordering, root semantics, and
update rules must be specified. Two correct implementations given the same
logical state must produce byte-for-byte identical identifiers.

The current local implementation uses SHA-256 with the domain
`NOXIS/STATE/V2\0`, begins with `GenesisId`, and commits to Merkle-root/depth, assets, issued supply,
spent nullifiers and accepted legacy transaction identifiers. It uses sorted
raw identifier bytes and length-prefixed ticker bytes rather than runtime
`HashMap`/`HashSet` iteration. This is a deterministic bridge toward the full
proof- and consensus-bound construction; it must not be used as network finality.

The state identifier does not itself establish confidentiality, collision
resistance, proof membership, or cryptographic soundness. Those claims depend
on the chosen concrete construction and its documented assumptions.

## Record structure and sequencing

Every durable transaction record must logically contain:

| Field | Required rule |
| --- | --- |
| Record format version | Must be recognized by the reader; unknown versions are rejected. |
| Sequence number | Must equal the preceding sequence number plus one. |
| Predecessor state identifier | Must equal the identifier of the recovered current state before this record. |
| Canonical transaction bytes | Must encode exactly one versioned transaction within explicit resource limits. |
| Transaction intent identifier | Must match the non-self-referential identity recalculated from canonical transaction bytes. |
| Result state identifier | Must equal the identifier computed after applying the transaction. |
| Framing/integrity data | Must make incomplete or accidentally corrupted records detectable. |

The record has exactly one direction: `state[n] -- transaction[n+1] -->
state[n+1]`. It may be appended only when all of the following hold:

1. its sequence is `current_sequence + 1`;
2. its predecessor ID equals the current state ID;
3. its transaction is valid against the current state under the configured
   verifier and mint policy;
4. applying it produces the state whose canonical ID equals its result ID; and
5. the record is completely durable according to the durability contract
   before the resulting state is acknowledged.

No record may be accepted by sequence number alone, by transaction ID alone,
or because its result identifier looks plausible. A transaction valid against
one predecessor may be invalid against another because a nullifier, commitment,
or asset state has changed.

## Genesis binding

The chain begins at the genesis state identifier in the verified data-directory
manifest. Recovery always starts at `(sequence = 0, state_id = genesis_state_id)`
in this version. The first record must have sequence `1` and name that exact
genesis identifier as its predecessor.

Changing genesis, its asset registry, its crypto-suite configuration, or its
rule version changes the compatible chain. An implementation must reject,
rather than splice together, records that are bound to another genesis or
deployment identity.

## Checkpoints

Checkpoints are optional checked state materializations. They do not supersede
the append-only state chain and must never be accepted as an opaque snapshot.
They become recovery accelerators only after an authenticated provenance rule
is specified.

A checkpoint must contain a canonical complete state (or a separately specified
equivalent representation), plus:

- checkpoint format version;
- genesis/deployment identifier and applicable protocol version;
- checkpoint sequence number;
- checkpoint state identifier;
- integrity information and resource bounds; and
- enough information to recompute or independently verify the stated state ID.

To use a checkpoint, recovery must verify every field, reconstruct or verify
its state, and confirm that its computed state ID equals the checkpoint state
ID. The next log record must then have sequence `checkpoint_sequence + 1` and
the same predecessor identifier. A checkpoint cannot skip unknown history by
claiming a later sequence without a valid, specified provenance rule.

Checkpoint creation must capture one coherent state under the same write
serialization that orders record commits. A checkpoint written during a crash
is eligible only if its own completion/integrity rule proves it complete; an
incomplete checkpoint may be ignored and recovery continues from genesis.

## Recovery algorithm

For writable service startup, recovery must proceed before accepting new
transactions:

1. Load the manifest and verify the expected genesis and supported formats.
2. Read each record in physical append order from genesis, within fixed resource
   limits.
3. Verify framing, supported version, contiguous sequence, transaction intent ID, and
   equality of `predecessor_state_id` to the current state ID.
4. Re-run ledger validation, apply the one transition to a candidate state,
   recompute its canonical state ID, and require equality with the record's
   result state ID.
5. At a matching sequence, restore a checkpoint only after its complete
   canonical snapshot equals the already replayed state and its terminal record
   hash matches. Otherwise ignore that checkpoint.
6. Publish the candidate as current state only after every check succeeds.

After recovery, the recovered sequence and state ID become the only permitted
predecessor for the next append. In particular, every nullifier in the
recovered state remains spent, so a transition that reuses it must be rejected.

## Fail-closed conditions

The service must enter an unavailable, non-writing state if it observes any of
the following before the special final-partial-record case described below:

- unsupported or ambiguous manifest, checkpoint, or record version;
- mismatched genesis/deployment/rule identity;
- duplicate, missing, decreasing, or non-contiguous sequence numbers;
- mismatched predecessor or result state identifiers;
- malformed, oversized, or unverifiable transaction encoding;
- a record whose transaction fails current transition validation;
- a checkpoint marked verified without matching the replayed state; or
- an integrity failure inside the committed portion of log history.

The service must not skip a record, reorder records, recompute an alternative
state ID, truncate mid-history, or continue from the last apparently good state
without an explicit operator recovery procedure and an independently verified
history source.

The only recoverable physical-tail case is a final record whose framing proves
it was never completed. Recovery may ignore that incomplete tail and retain the
preceding valid chain. It must not classify a complete-but-invalid final record
as an incomplete tail merely to start successfully.

## Required test evidence

Before a persistent state chain is relied on for double-spend resistance, tests
must demonstrate at least:

1. **Deterministic identity:** independently constructed equivalent logical
   states have identical IDs; a change to every committed state component
   changes the ID according to the defined construction.
2. **Valid replay:** genesis plus a sequence of valid records recovers the same
   sequence, state ID, supply, commitments, transaction IDs, and spent
   nullifiers as live execution.
3. **Sequence enforcement:** duplicate, skipped, reversed, and reordered
   records are rejected before the service accepts new writes.
4. **Link enforcement:** mutate each predecessor/result identifier and show
   recovery fails closed without applying later records.
5. **State-transition enforcement:** a well-framed record with a valid-looking
   ID but invalid transaction is rejected by re-validation.
6. **Restart double spend:** after recovery, submit a transaction reusing a
   previously committed nullifier and verify rejection.
7. **Partial tail:** truncate the final record at every byte boundary and show
   recovery retains exactly the prior complete chain; mutate a complete final
   record and show that it fails closed instead.
8. **Checkpoint equivalence:** strict recovery compares every generated
   checkpoint to the same replayed state and produces identical state IDs and
   complete state.
9. **Checkpoint rejection:** corrupt checkpoint state, sequence, genesis ID,
   or state ID; recovery ignores it and still validates all log records from
   genesis, never trusting the corrupt checkpoint.
10. **Resource bounds:** adversarial record lengths, state structures, and
    malformed encodings are rejected without crashes, integer overflow, or
    unbounded memory/CPU use.

## Acceptance criteria

An implementation conforms only when it has a published canonical state-ID and
record encoding, enforces one contiguous genesis-bound chain, verifies each
record by replay before use, validates checkpoints independently, and fails
closed on historical inconsistency. The required tests must run in continuous
integration alongside fault-injection and durability tests.

Conformance does not replace independent review of the selected hash,
accumulator, proof verifier, mint policy, storage platform, or future consensus
system.
