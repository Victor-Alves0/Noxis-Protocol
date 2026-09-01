# Local private-ledger demo — research v0.1

## Purpose

This command exposes the executable boundary implemented by the candidate
private ledger. It is deliberately separate from `noxis-node demo-local`,
which demonstrates the durable **public** research ledger with a fixture
verifier.

Run the private path with an optimized build:

```powershell
cargo run --release -p noxis-private-proof-contract --bin noxis-private-ledger-demo
```

The command constructs deterministic candidate notes in memory, creates the
currently retained local proof bundle, verifies it at the typed private-ledger
boundary, commits one fixed 2x2 transfer, and submits the same request again.
The second submission must be rejected before another mutation.

Expected shape of the final output:

```text
Noxis private-ledger demo — RESEARCH ONLY
constructing candidate notes and proving three local STARK relations ...
private transfer proof bundle ... accepted
pre-state ID: ...
post-state ID: ...
commitments: 2 -> 4
spent 64-byte nullifiers: 2 -> 4
submitted same private transfer ... rejected: StateTransition
```

## What this demonstrates

- the proof bundle contains one intent/value proof and two ownership proofs;
- all proof checks are bound to the current typed private state and the exact
  `NXPU v1` intent;
- the accepted mutation appends both output commitments and spends both native
  64-byte nullifiers atomically; and
- the original request is stale after commit and cannot be applied twice.

The operation is intentionally slow. The currently selected research route
uses independent STARK relations rather than an aggregated transfer proof, so
an optimized run takes many minutes on ordinary development hardware.

## Deliberate limits

This is not a user transaction command. In particular, it does not produce an
`NXPT` packet, encrypt a real recipient envelope, persist private state, use a
wallet key, encode a portable proof, enter a mempool, start CometBFT or claim
finality. Its two ciphertext-digest fields are fixed non-secret fixture values;
they exist only to form the canonical private intent.

The packet-bound preflight remains independently tested. Connecting validated
recipient envelopes to this command is a later integration task, after a
portable proof and private-state persistence design exist.

## Next implementation gate

Specify a durable private-state record and recovery model for the typed
snapshot, `NXSM` tree and anchor. Only after recovery is crash-consistent
should a private transaction command or ABCI admission path retain user-facing
state.
