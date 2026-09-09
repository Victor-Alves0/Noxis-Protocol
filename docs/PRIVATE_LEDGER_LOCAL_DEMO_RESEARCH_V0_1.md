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

The command constructs candidate notes in memory, creates two fresh local
hybrid recipient descriptors and `NXRE v1` envelopes, commits their exact
digests into the two intent output slots, creates the retained proof bundle and
frames it as `NXPP v1` inside one `NXPT v1` packet. The typed private-ledger
boundary validates the delivery envelopes, verifies the proof bytes, commits
one fixed 2x2 transfer, then receives the same packet again. The second
submission must be rejected before another mutation.

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
- both fresh `NXRE v1` envelopes are structurally validated and their digests
  are bound to the canonical output slots before proof parsing;
- the complete `NXPT v1` packet carries that same intent, both recipient
  envelopes and the `NXPP` bytes, so delivery metadata cannot be mixed with an
  unrelated proof;
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

On 2026-09-09, a fresh persistent release run of the complete packet path
accepted a 4,968,697-byte `NXPP` envelope, rejected the repeated packet as
stale, and recovered one `NXPL v2` receipt/state frame after reopen. Its
recovered post-state ID was
`83765b477484bf93a9925ae330c7cb9f64359b59999d35895ac41de82a55fd05`.
This is again local research evidence, not a performance or privacy claim.

The operation is intentionally slow. The currently selected research route
uses independent STARK relations rather than an aggregated transfer proof, so
an optimized run takes many minutes on ordinary development hardware.

## Deliberate limits

This is not a user transaction command. It creates ephemeral local recipient
keysets and an `NXPT` packet solely to exercise the binding; it does not expose
or persist a wallet key, select a production proof profile, enter a mempool,
start CometBFT or claim finality.
With `--data-dir`, it persists only candidate local receipt/state frames; it
does not persist `NXPP` bytes, proofs or private witnesses, and does not make
the local receipt a public transaction history.
Its ciphertext digests are recomputed from the exact local recipient envelopes
and output commitments. The resulting proof remains a pinned research profile,
and `NXPL v2` deliberately stores neither packet bytes, recipient envelopes,
proofs nor witnesses.

## Next implementation gate

The candidate snapshot/store/reopen path now accepts a fully bound `NXPT`
packet through one local composite receipt/state mutation boundary. The storage
suite now scans every prefix of one real `NXPL v2` composite frame and accepts
only the complete frame as an entry; the existing store-reopen cases prove that
a verified incomplete tail is removed and returns the authenticated base. A
test-only failpoint also proves that a cache-publication error after journal
sync is recovered from the journal on reopen. Next, extend migration coverage
and filesystem-operation fault injection before considering any ABCI-facing
private-admission design.
