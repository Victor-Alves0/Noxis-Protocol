# Candidate private-state store — research v0.1

## Implemented behavior

`PrivateStateStoreV1` owns one local `NXPR v1` file and an adjacent
cooperative writer-lock file. It initializes or opens a state only under that
lock. For a transfer it validates a clone, writes and `sync_all`s the complete
successor snapshot under a same-directory temporary name, renames it into the
configured path, decodes that published file again, and only then replaces the
in-memory state and reports acceptance.

Any failure during proof authorization, transition validation, encoding, write,
synchronization, rename or post-publication decoding retains the old in-memory
state and returns an error.

## Recovery boundary

Opening reads at most the declared `NXPR` maximum, verifies its checksum and
canonical encoding, rebuilds the note snapshot, reconstructs `NXSM`, derives
`NXPS v2`, and compares the encoded and derived state IDs. Corrupt state files
fail closed.

Tests prove that an accepted two-input/two-output transition survives reopen
with all four commitments and both newly spent 64-byte nullifiers. They also
prove a corrupted record cannot be opened.

## Deliberate limits

This is a candidate **single-snapshot** local store. It has no append-only
private transition log, partial-tail recovery, directory-metadata durability
proof on every platform, authenticated checkpoint, packet retention, wallet
database, portable proof bytes, ABCI admission or consensus authority.

An interrupted publication can leave a temporary sibling file; the store never
opens it. The previous complete state remains the recovery target. Rename and
directory metadata crash guarantees remain platform-dependent and are not
claimed as consensus durability.

## Next gate

The proof-backed local demo now accepts `--data-dir PATH` and persists its
accepted candidate transition through this store before reopening it:

```powershell
cargo run --release -p noxis-private-proof-contract --bin noxis-private-ledger-demo -- --data-dir .\target\noxis-private-demo
```

The [private-state journal design](PRIVATE_STATE_JOURNAL_DESIGN_V0_1.md)
defines the next storage layer. A real wallet command still waits for portable
proofs, packet binding and recipient-envelope persistence.
