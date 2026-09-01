# Candidate private-state record (`NXPR v1`) — research v0.1

## Purpose

`NXPR v1` is the canonical bounded snapshot of the candidate private ledger.
It is an in-memory record codec, not yet a durable file, a checkpoint, a
wallet database or a consensus artifact.

The record contains only public candidate state:

- genesis and validation-context identities;
- note-tree parameter identity;
- the derived typed private state ID;
- ordered note commitments;
- sorted spent 64-byte nullifiers; and
- public asset definitions in ascending asset-ID order.

It contains no private keys, note openings, recipient envelopes, proofs or
ciphertexts.

## Canonical layout

```text
"NXPR" | version u16be | reserved[2] | GenesisId | ValidationContextId
| TreeParametersId | derived StateId | commitment_count u32be
| nullifier_count u32be | asset_count u16be
| commitments (64 bytes each, original append order)
| nullifiers (64 bytes each, ascending canonical order)
| assets (AssetId | kind tag | ticker length | uppercase ASCII ticker)
| SHA-256("NOXIS/PRIVATE-STATE-RECORD/V1\\0" || every preceding byte)
```

The current limits are 1,024 commitments, 2,048 nullifiers, 4,096 assets and
1–16 ASCII-uppercase ticker bytes. Unknown versions, nonzero reserved bytes,
invalid field elements, duplicate collections, noncanonical asset order,
invalid tickers, checksum mismatches, truncation and trailing bytes are
rejected.

## Reconstruction rule

Decoding never trusts the derived data in the record. It rebuilds the candidate
note snapshot, recreates `NXSM` by inserting every recorded nullifier, derives
a fresh `NXPS v2` anchor, and requires the resulting state ID to equal the
encoded ID. It also requires byte-for-byte re-encoding equality.

This ensures one decoded record cannot combine a valid note snapshot with a
nullifier root or state identity belonging to a different set.

## Current boundary and next gate

The codec makes private state portable *inside one process* and gives a future
storage writer one complete atomic value to publish. It does not itself call
the filesystem, acquire a writer lock, recover partial writes or acknowledge a
transaction.

The next implementation gate is a single-writer storage component that writes
an `NXPR` candidate to a temporary sibling file, synchronizes it, atomically
publishes it and reopens it fail-closed. Its recovery semantics must be
specified separately before any wallet, packet or ABCI caller can rely on it.
