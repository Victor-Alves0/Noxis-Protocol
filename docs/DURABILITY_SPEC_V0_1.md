# Noxis Protocol — Durability Specification v0.1

## Status and scope

This document specifies the durability contract for the Noxis persistent
ledger. The current v0.1 implementation has a legacy single-process `NXRF`
record log containing strict `NXRC` state-transition records, plus an
authoritative consensus-oriented `NXCB` block journal. `NXCB` is the only
format suitable for a decided block: one frame holds its canonical `NXBH`
header, the exact CometBFT decision context, `AppHash` and every `NXRC` record, including the valid zero-record
case. Recovery streams one frame at a time from genesis, re-executes its
transactions and compares header, CometBFT context, records and `AppHash` before it advances the
tip. A structurally incomplete final `NXCB` frame is removed only after the
complete prefix has re-executed successfully.

The cross-format registry for magic/version identity, bounds, canonical parser
behavior and upgrade rules is [WIRE_STORAGE_FORMATS_V0_1.md](WIRE_STORAGE_FORMATS_V0_1.md).
This document owns the durability and authority semantics of its storage rows.

The older `NXLG` transaction-only log remains a legacy format. It is never
automatically upgraded or silently replayed by `PersistentLedger`, because it
lacks state links. `NXCP` publication and strict replay comparison are
implemented, but authenticated checkpoint acceleration, failure injection at
every OS write phase, explicit transaction-intent/proof genesis binding, and a
full storage-platform crash guarantee are not implemented yet.

The purpose of this specification is to make a later storage implementation
reviewable. Its critical outcome is simple: after a restart, a transaction
previously acknowledged inside a decided block must not become spendable again
through a lost nullifier record, a partial block or a partially restored tip.

## Terminology

| Term | Meaning |
| --- | --- |
| **Committed transaction** | A transaction whose complete state transition has been durably recorded according to this specification. |
| **Acknowledged transaction** | A committed transaction for which the node has returned successful acceptance to its caller. |
| **Append-only log** | An ordered sequence of immutable records. Existing bytes are never edited in place. |
| **Ledger transition** | One validated transaction applied to one preceding state, producing one successor state. |
| **Recovery** | Rebuilding a valid state from genesis and replaying valid log records; any checkpoint is compared only after that strict replay. |
| **Tail** | The final, possibly incomplete bytes of a log after interruption during a write. |
| **Committed block** | One complete, synchronized `NXCB` frame whose deterministic replay agrees with its header, records and `AppHash`. |

## Durability invariants

A compliant implementation must preserve all of these invariants:

1. Each committed log record represents exactly one complete ledger transition.
2. Records have one total order. Recovery applies them only in that order.
3. A transaction is acknowledged only after its complete record is durable on
   the storage device according to the configured durability mode.
4. Recovery either applies a record completely or does not apply it at all.
   It never derives a state from a partial record.
5. The recovered state must retain every nullifier consumed by every recovered
   committed transition. A nullifier accepted before a successful
   acknowledgment must therefore remain rejected after restart.
6. Every recovered transition must satisfy the same validation rules as a
   live transition, including asset existence, fresh nullifiers, fresh
   commitments, and mint authorization.
7. Corruption within the committed portion of history is a fail-closed event:
   the node must not silently omit or reinterpret the affected history.
8. A decided block is atomic: recovery accepts every one of its records and
   its resulting tip, or accepts none of them. A valid prefix of its records
   is never a committed consensus result.
9. A durable tip identifies execution height, `BlockId` and `AppHash`, so
   consecutive empty blocks remain distinguishable after restart.

The legacy `NXRF` path implements only single-transition durability and must
not be used as the authoritative `Commit` path of a consensus engine. `NXCB`
implements the single-file block/replay portion and holds an exclusive
cooperative OS file lock. Every writer of that journal must use this component;
the lock cannot constrain unrelated software that deliberately bypasses it.
The remaining limitations are listed in the status paragraph above and must be
closed before any value-bearing use.

## Consensus block journal (`NXCB`)

One physical frame has this canonical shape:

```text
"NXCB" | frame version | payload length | payload | CRC-32

payload = "NXBP" | payload version | NXBH length | canonical NXBH
        | AppHash | Comet network ID | Comet height | Comet block hash
        | next validators hash | record count | (NXRC length | canonical NXRC)*
```

The checksum detects accidental frame corruption; security comes from strict
decoding plus deterministic replay, not CRC-32. The duplicated count must
match the header commitment. Before writing, and again during recovery, the
implementation verifies canonical encoding, record sequence/state links,
header record commitment, parent/height continuity and re-execution equality.
The recovery scanner holds only the current frame in memory; log length does
not require retaining all past blocks in RAM.

`sync_data` is required before commit success. On Unix, every acknowledged
append also synchronizes the journal's parent directory so a newly created
filename is not acknowledged before that entry is durable. The current
implementation fails closed when an append runs on a platform where it cannot
provide an equivalent parent-directory durability operation; a documented
platform-specific backend is required before enabling consensus commits there.
At present this means `NXCB` consensus commits are supported only on Unix.
Windows may inspect or recover an existing journal but must not be configured
as a block-committing validator until an equivalent durability backend exists.

## Log format

The canonical binary encoding is intentionally deferred to the transaction
codec specification. Regardless of the eventual codec, every record must have
the following logical fields and be unambiguously length-delimited:

| Field | Purpose |
| --- | --- |
| Magic and log-format version | Rejects unrelated files and unsupported record formats. |
| Record sequence number | Enforces a contiguous total order. |
| Previous state identifier | Binds the record to the state it expects to extend. |
| Transaction bytes | Canonical, versioned bytes of exactly one transaction. |
| Transaction intent identifier | Non-self-referential identity recalculated from canonical transaction bytes. |
| Resulting state identifier | Commits to the state after a successful transition. |
| Integrity check | Detects accidental corruption; it is not a substitute for signatures, consensus, or an authenticated storage system. |
| Record length/trailer | Allows detection of incomplete tails and exact record framing. |

`Previous state identifier` and `resulting state identifier` must refer to a
canonical state commitment. The current implementation uses the documented
deterministic local `StateId` encoding, not a runtime-memory hash. It is bound
to a `GenesisId`, so histories from deployments with different genesis
configuration cannot be mixed. It remains insufficient for network finality
because transaction intent/proof binding, consensus and the other stated
requirements are absent.

Records must have explicit maximum sizes. Recovery must reject oversized,
malformed, unsupported-version, non-contiguous, or identifier-mismatched
records without allocating unbounded memory.

## Write and acknowledgment procedure

For one incoming transaction, a compliant single-writer implementation follows
this order:

1. Serialize access to the ledger state; no two transitions may decide
   validity against the same predecessor state and both commit independently.
2. Validate the transaction against the current state and concrete configured
   verifier and mint policy.
3. Build the complete next state in memory, including all newly spent
   nullifiers, commitments, supply changes, and accepted transaction ID.
4. Construct one complete record that binds the previous state, transaction,
   and resulting state.
5. Append the record and force it to durable media using the configured
   storage primitive. A successful buffered write alone is insufficient for
   the strongest durability mode.
6. Publish the next state to readers and then acknowledge success.

If any step through durable append fails, the transaction must not be
acknowledged as accepted. The process may retain the old in-memory state or
stop serving writes; it must not publish a state that it cannot recover under
the selected durability mode.

The exact operating-system calls and storage assumptions must be documented by
the implementation. Filesystem and hardware behavior can affect real-world
durability; this specification does not assert that a particular API makes a
write physically indestructible.

## Restart and recovery behavior

On startup, the node must:

1. Scan checkpoint candidates, if present, but start replay from the genesis
   state until a checkpoint has an authenticated provenance mechanism.
2. For each record, verify framing, format version, sequence number, integrity
   check, previous-state identifier, transaction intent identifier, and resulting
   state identifier.
3. Re-run the ledger transition validation before accepting the record's state
   effects. A record that cannot be validated must not be treated as a valid
   transition merely because it exists on disk.
4. At matching sequences, compare a checkpoint's identities, terminal record
   hash and complete canonical snapshot to that already replayed state. An
   invalid checkpoint is ignored; an invalid record remains fail-closed.
5. Make the reconstructed state available for writes only after recovery has
   completed successfully.

When a record is confirmed valid, recovery applies all of its effects as one
unit. In particular, the corresponding nullifiers, commitments, supply
accounting, and transaction ID are restored together.

## Interruption, truncation, and corruption

### Incomplete tail

An interrupted append can leave a partial final record. If the record is at
the physical end of the log and fails only because its framing proves it is
incomplete, recovery must ignore that partial tail and recover the preceding
complete history. The transaction represented by the tail is not committed and
must not be acknowledged retrospectively.

After successful recovery, an implementation may retain the incomplete bytes
for forensics or truncate only that known incomplete tail before accepting new
writes. Any truncation procedure must be atomic or safely repeatable and must
never remove a verified complete record.

### Corruption or discontinuity within history

An integrity failure, invalid length, unsupported version, unexpected sequence
number, state-identifier mismatch, or invalid transaction before the final
incomplete tail is a history-corruption event. The node must fail closed:

- it must stop accepting writes;
- it must not advance by skipping, repairing, or guessing at the record; and
- it must expose a clear operator-facing recovery status.

Repair requires an explicit operator procedure using an independently verified
backup, replica, or future consensus source. Automatic repair may be added only
after its trust assumptions and safety behavior are separately specified.

### Acknowledgment uncertainty

A caller can lose its response after a durable commit (for example, due to a
network disconnect). Retrying the same transaction must be safe: the node
should return its already-known outcome when the canonical transaction ID is
present, rather than attempting to apply the transition again. Until canonical
transaction IDs and request semantics are implemented, callers must treat this
case as unresolved and query a durable transaction-status API before retrying.

## Checkpoints

Checkpoints currently validate a durable state copy; they do not reduce replay
time until their provenance is authenticated. They do not replace the
append-only history or validation rules. A checkpoint must contain a canonical full state (or a
precisely specified equivalent representation), the sequence number and state
identifier it represents, format/version metadata, and an integrity check.

Checkpoint creation must not allow a log prefix and the checkpoint to describe
different states. The initial safe design is:

1. create and durably write a complete checkpoint for a known log sequence;
2. verify it before marking it eligible for recovery;
3. retain all log records until the checkpoint's validity and backup policy are
   satisfied; and
4. replay the complete history from genesis and compare the checkpoint at its
   matching sequence exactly as normal.

Log compaction, deletion, remote backup, encryption at rest, replica repair,
and key management are intentionally outside v0.1. They require their own
threat models because they can change the failure and trust assumptions.

## Required test evidence

Before declaring a persistence implementation usable for any environment where
double-spend resistance matters, automated tests must demonstrate at least:

1. **Round trip:** append several valid transitions, restart, and obtain an
   equivalent state including all spent nullifiers and commitments.
2. **Post-restart double spend:** accept a transition, restart, then reject a
   second transition that reuses one of its nullifiers.
3. **Failure at every write phase:** inject failure before append, during
   append, after append but before force-to-media, and after force-to-media but
   before response. The observed state and acknowledgment outcome must match
   the documented durability mode.
4. **Partial tail:** simulate truncation at every byte position of a final
   record; recovery must keep only the prior complete history and remain able
   to accept later valid writes safely.
5. **Mid-history corruption:** alter bytes in every logical field of a
   committed record; recovery must fail closed and must not silently continue.
6. **Ordering and concurrency:** submit conflicting transactions concurrently;
   at most one may commit when they share a nullifier, and restart must retain
   that result.
7. **Checkpoint equivalence:** recover from genesis and compare every generated
   checkpoint to its matching replayed state; both representations must yield
   the same canonical state identifier.
8. **Malformed-input limits:** test invalid lengths, huge lengths, unknown
   versions, duplicate sequence numbers, gaps, and mismatched identifiers
   without crashes or unbounded resource use.

## Acceptance criteria

A future persistent ledger component conforms to this document only when:

- its concrete record codec and state-identifier algorithm are specified and
  independently testable;
- the write procedure prevents an acknowledged transition from disappearing on
  supported failure scenarios;
- recovery restores all effects of each committed transition atomically;
- partial tails are distinguished from corruption within committed history;
- corruption causes a clear fail-closed condition; and
- the required fault-injection and restart tests run in continuous integration
  on the supported storage environments.

Conformance to this specification alone does not provide consensus, protection
against a malicious storage administrator, availability, cryptographic proof
soundness, or external-asset backing.
