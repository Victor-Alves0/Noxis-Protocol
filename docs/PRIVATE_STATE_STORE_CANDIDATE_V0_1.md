# Candidate private-state store — research v0.1

## Implemented behavior

`PrivateStateStoreV1` owns a replaceable local `NXPR v1` cache, an adjacent
`NXPL v1` journal, an immutable `NXPR v1` base snapshot and one cooperative
writer-lock file. It initializes or opens the group only under that lock. For
a transfer it validates a clone, creates or validates the immutable base,
appends and syncs the canonical post-state to the journal, then atomically
publishes and re-decodes the cache before replacing the in-memory state and
reporting acceptance.

Any failure during proof authorization, transition validation, encoding, write,
synchronization, rename or post-publication decoding retains the old in-memory
state and returns an error.

## Recovery boundary

Opening first validates the journal framing and state links. Once the journal
has an entry, its final post-state is authoritative and its first predecessor
must match the immutable base snapshot. A stale or corrupt replaceable cache
is then rebuilt from that final journal state. With an empty journal, the cache
remains the recovery target and any immutable base must match it exactly.

Every `NXPR` read is bounded, checks its checksum and canonical encoding,
rebuilds the note snapshot and `NXSM`, derives `NXPS v2`, and compares encoded
and derived state IDs. A corrupt cache without a valid journal, a missing base
for a nonempty journal, or a base/link mismatch fails closed.

Tests prove that an accepted two-input/two-output transition survives reopen
with all four commitments and both newly spent 64-byte nullifiers. They also
prove a corrupted record cannot be opened.

## Deliberate limits

This is a candidate local cache-plus-journal store. It has no directory-metadata
durability proof on every platform, authenticated checkpoint, packet retention,
wallet database, portable proof bytes, ABCI admission or consensus authority.

An interrupted publication can leave a temporary sibling file; the store never
opens it. An interrupted final journal frame is truncated only after its valid
prefix and immutable base link are rechecked. Rename and directory metadata
crash guarantees remain platform-dependent and are not claimed as consensus
durability.

## Next gate

The proof-backed local demo now accepts `--data-dir PATH` and persists its
accepted candidate transition through this store before reopening it:

```powershell
cargo run --release -p noxis-private-proof-contract --bin noxis-private-ledger-demo -- --data-dir .\target\noxis-private-demo
```

The [private-state journal design](PRIVATE_STATE_JOURNAL_DESIGN_V0_1.md)
describes the remaining journal limits. A real wallet command still waits for
portable proofs, packet binding and recipient-envelope persistence.
