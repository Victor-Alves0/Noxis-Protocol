# Private submission-history atomicity decision — candidate v0.1

## Decision and status

**Decision:** do not add a second private-submission journal beside `NXPL v1`.
The candidate implementation direction is instead a future **`NXPL v2` frame**
that carries one canonical local submission receipt and the corresponding
canonical `NXPR` post-state inside the same synchronized append.

`NXPL v2` is now implemented as a local candidate codec/store:
`PrivateSubmissionStoreV2` appends a single synchronized composite frame after
verified `NXPP` admission, returns the local receipt, and reopens the receipt
and successor state together. The implementation remains **local candidate
storage**. It does not establish durable proof availability, historic proof
re-verification, offline v1-to-v2 migration, ABCI admission, consensus history
or network transaction replay.

## Problem

The current candidate path has two true but intentionally separate facts:

1. `PrivateStateStoreV1` durably appends one verified `NXPR` post-state to
   `NXPL v1`, then publishes a replaceable cache; and
2. successful byte admission returns an in-memory
   `CandidatePrivateProofBundleAdmissionReceiptV1` containing a local hash of
   exact `NXPP` bytes and public transition facts.

Persisting the receipt in another file would create an unreviewed distributed
commit problem. A crash could produce either of these unsafe observations:

```text
history receipt present, but its post-state was never journaled
post-state journaled, but its history receipt is absent
```

Neither file could then safely be called authoritative without a recovery rule
that reconciles both files. Atomic rename does not solve synchronized appends
to two independent files, and a receipt file cannot be repaired by guessing
which proof or envelope produced a state transition.

## Selected direction: one composite journal frame

`NXPL v2` will preserve the current physical outer frame:

```text
"NXPL" | version u16be | payload length u32be | payload | CRC-32
```

but its payload is proposed to contain exactly one complete transition record:

```text
sequence u64be
previous StateId                  32 bytes
resulting StateId                 32 bytes
local NXPP envelope ID            32 bytes
asset ID                          32 bytes
input nullifier[0]                64 bytes canonical BabyBear
input nullifier[1]                64 bytes canonical BabyBear
output commitment[0]              64 bytes canonical BabyBear
output commitment[1]              64 bytes canonical BabyBear
NXPR length u32be
complete canonical NXPR bytes
```

The fixed v2 payload prefix would be **396 bytes**. Its maximum payload is
therefore `396 + PRIVATE_STATE_RECORD_MAX_BYTES`; every declared length must
be checked before allocation. The `NXPP` envelope itself, its proofs and every
private witness remain absent. The envelope ID is the existing
domain-separated local correlation handle, not an authorization proof.

This design does not create another magic or another append authority. One
complete frame is the unit of durability, recovery and history observation.

## Required validation on append and recovery

Before appending, a v2 writer must already have:

1. validated the exact `NXPP` bytes against the current state;
2. produced the typed candidate ledger receipt; and
3. reconstructed and validated the complete successor `NXPR`.

The v2 codec/store must then verify, both before append and again on recovery:

1. magic, version, payload bound, checksum and EOF framing;
2. strictly one-based contiguous sequence and predecessor link;
3. nested `NXPR` canonical decode and equality of its recomputed state ID with
   `resulting StateId`;
4. a nonzero envelope ID and canonical 64-byte BabyBear values;
5. the candidate asset exists in the predecessor state;
6. exactly two newly appended output commitments, in fixed slot order;
7. exactly two newly spent input nullifiers, in fixed slot order; and
8. that the receipt's pre/post state IDs agree with the predecessor and nested
   post-state.

Checks 5–7 validate that the persisted receipt describes the state delta. They
do **not** re-verify the historic proof: `NXPP` bytes are not retained and the
current research verifier is not a selected persistent proof profile.

## Commit, crash and recovery rule

The store must construct and validate the entire v2 frame in memory, append it
to the existing locked journal, flush and synchronize it, and only then publish
the cache. The frame contains both history receipt and post-state, so recovery
uses one authority:

| Failure point | Reopen behavior |
| --- | --- |
| Before the journal append | No complete transition exists; retain prior state/history. |
| Incomplete final frame | Re-scan; truncate only the verified incomplete suffix, as `NXPL v1` does. |
| Complete sync before cache publish | Recover both receipt and post-state from the journal; repair cache. |
| Corrupt complete frame or mid-history link | Fail closed; never infer a missing receipt or post-state. |

The on-disk receipt is local operator metadata. It must not be automatically
logged to peers, exposed through a public API, or treated as wallet payment
tracking because its envelope ID and state-delta facts are correlatable.

## Rejected alternatives

| Alternative | Rejection reason |
| --- | --- |
| Sibling `NX..` history journal | Requires two-file atomicity/recovery and creates a new format surface. |
| Append receipt after `NXPL v1` state append | Leaves a durable state without history after a crash. |
| Append receipt before `NXPL v1` state append | Leaves a history claim without its state after a crash. |
| Store full `NXPP`/proofs in history | Multiplies storage and adversarial parsing surface; leaks correlatable material and does not select a verifier profile. |
| Derive history retrospectively from snapshots | Cannot identify the original exact envelope or asset transition without an explicit receipt. |

## Version and migration rule

`NXPL v1` remains immutable and recoverable as v1. A v2 reader must reject a
mixed v1/v2 journal; a v1 writer must never append v2 bytes. Migration is a
separate offline operation, not an open-time guess:

1. validate and recover the complete v1 base plus journal;
2. create a new v2 journal with that recovered state as its separately retained
   base and **no fabricated historic receipts**;
3. switch only after the new base/cache/journal files are synchronized and
   independently reopened; and
4. retain the original v1 directory as migration evidence until an explicit
   retention policy authorizes removal.

The exact directory swap, failure injection matrix and operator tool are
implementation gates; no migration code is authorized by this decision alone.

## Implementation gates and current boundary

The implemented v2 boundary provides the source magic/version, strict bounded
codec, canonical field decoding, one store mutation path, release tests for
reopen, a partial final frame, a crash after journal sync/before cache publish,
and a complete checksum-recomputed frame with an invalid receipt field, plus a
registry row. The following work remains required before it can move beyond
local candidate storage:

1. a narrowly owned v2 codec and strict parser tests for every header, length,
   receipt field, nested `NXPR`, trailing byte and CRC path;
2. property/fuzz tests for framing, noncanonical BabyBear values and all
   predecessor/receipt-delta mismatches;
3. one store mutation path that produces the composite frame after verified
   `NXPP` admission, with no alternative receipt append API;
4. broader filesystem fault injection at every write/sync/publish boundary
   and across supported storage platforms; and
5. an explicit offline migration design and test corpus before a v1 store can
   be upgraded.

The implemented format remains `candidate private-submission journal / NXPL /
v2` in the registry. It is not consensus durability or a private network
transaction log.
