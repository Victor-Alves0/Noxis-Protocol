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
currently retained local proof bundle, serializes it as `NXPP v1`, verifies its
bytes at the typed private-ledger boundary, commits one fixed 2x2 transfer,
and submits the same intent and bytes again. The second submission must be
rejected before another mutation.

Expected shape of the final output:

```text
Noxis private-ledger demo — RESEARCH ONLY
constructing candidate notes and proving three local STARK relations ...
private transfer proof bundle ... accepted
candidate proof bundle envelope bytes: ...
candidate proof bundle envelope ID: ...
pre-state ID: ...
post-state ID: ...
commitments: 2 -> 4
spent 64-byte nullifiers: 2 -> 4
submitted same private transfer bytes ... rejected: stale state
```

## What this demonstrates

- the proof bundle contains one intent/value proof and two ownership proofs;
- the exact three-proof bundle is framed as bounded canonical `NXPP v1` bytes;
- all proof checks are bound to the current typed private state and the exact
  `NXPU v1` intent;
- the accepted mutation appends both output commitments and spends both native
  64-byte nullifiers atomically; and
- the original request is stale after commit and cannot be applied twice.

To exercise the same byte-entry path through the durable candidate store and
its `NXPL` journal, supply a new data directory:

```powershell
cargo run --release -p noxis-private-proof-contract --bin noxis-private-ledger-demo -- --data-dir .\\noxis-private-demo
```

On success, the command reopens `private-state.nxpr` in that directory and
prints both the recovered post-state ID and recovered composite-frame count.
It persists the verified post-state plus a local envelope-ID/transition receipt
in one `NXPL v2` frame. It does **not** persist `NXPP` bytes, private
witnesses or a proof archive.

On 2026-09-02, the persistent release demo accepted a 4,968,208-byte `NXPP`
envelope, advanced commitments from 2 to 4 and spent nullifiers from 2 to 4.
After reopening, it recovered the exact committed post-state ID
`7b0ac8e34bef48b0ebc56b02443c4c1bbc3e6776282b69fe6a65c17705a15365`.
The measured envelope size is supporting research evidence, not a maximum.

The operation is intentionally slow. The currently selected research route
uses independent STARK relations rather than an aggregated transfer proof, so
an optimized run takes many minutes on ordinary development hardware.

## Deliberate limits

This is not a user transaction command. In particular, it does not produce an
`NXPT` packet, encrypt a real recipient envelope, use a wallet key, select a
production proof profile, enter a mempool, start CometBFT or claim finality.
With `--data-dir`, it persists only candidate local receipt/state frames; it
does not persist `NXPP` bytes, proofs or private witnesses, and does not make
the local receipt a public transaction history.
Its two ciphertext-digest fields are fixed non-secret fixture values; they
exist only to form the canonical private intent.

The packet-bound preflight remains independently tested. Connecting validated
recipient envelopes to this command is a later integration task, after a
portable proof and private transaction-log design exist.

## Next implementation gate

The candidate snapshot/store/reopen path now accepts verified `NXPP` bytes
through one local composite receipt/state mutation boundary. Next, add the
fault-injection and migration corpus before considering any ABCI-facing
private-admission design.
