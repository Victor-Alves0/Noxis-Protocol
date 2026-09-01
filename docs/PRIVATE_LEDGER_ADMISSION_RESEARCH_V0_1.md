# Typed private-ledger admission — research v0.1

## Implemented boundary

`CandidatePrivateLedgerStateV1` is the first local ledger state that consumes
the native candidate privacy types without narrowing them through the legacy
public transfer model. It owns:

- a public registry of supported assets;
- the ordered candidate note-commitment snapshot;
- the candidate `NXSM` sparse tree with 64-byte nullifiers; and
- the `NXPS v2` anchor derived from both state domains.

One `CandidatePrivateTransferRequestV1<A>` carries the canonical fixed 2×2
private intent and authorization material interpreted only by an injected
`CandidatePrivateTransferAuthorizer<A>`.

The proof-contract adapter implements that authorization interface for
`CandidatePrivateTransferProofBundleV1`. It reconstructs the exact `NXPU v1`
statement from current ledger state and the request intent, then independently
verifies the retained intent/value proof and both ownership proofs.

## Atomic admission sequence

The implementation is separated internally into `ledger/model.rs`,
`ledger/invariants.rs` and `ledger/mutation.rs`:

1. reject an unregistered public asset;
2. derive the entire post-snapshot, post-`NXSM` tree and post-anchor on clones;
3. reject stale anchors, spent nullifiers, duplicate commitments and capacity
   failures before invoking the expensive authorizer;
4. verify the proof authorization against the exact current anchor, tree and
   intent;
5. revalidate the prepared transition; and
6. replace snapshot, nullifier tree and anchor only after every fallible step
   has succeeded.

No error path mutates one of those components independently. A replay is
rejected against the new state before proof verification runs again.

## Operational evidence

Fast tests use explicit accept/reject authorizers to prove the ledger boundary
independently of STARK runtime:

```powershell
cargo test -p noxis-private-state ledger:: --lib
```

They cover:

- atomic insertion of two outputs and two 64-byte nullifiers;
- complete rollback when authorization is rejected;
- rejection of an unknown asset before authorization; and
- replay rejection without a second mutation.

The full optimized integration creates the real proof bundle, uses its
fail-closed authorizer adapter, commits the private transition and rejects the
same request after commit:

```powershell
cargo test --release -p noxis-private-proof-contract transfer_preflight::tests::executes_every_available_private_relation_for_one_statement --lib -- --exact --ignored --nocapture
```

On 2026-09-01 that end-to-end local path passed in **1088.32 seconds** (about
18 minutes 8 seconds), excluding an 18.57-second incremental release build.
This is correctness evidence for the current research backend, not a wallet
performance target.

## What is now functional

Inside one process, Noxis can now construct a canonical private transfer,
produce the currently implemented proofs, verify them against current state,
atomically spend both public nullifiers, append both output commitments, derive
a new state anchor and reject a replay.

This is materially beyond a proof preflight, but it is still a local research
transaction path.

## Deliberate non-claims

This boundary does not yet provide:

- portable proof bytes or a selected `ProofVerifierId`;
- an `NXPT` submission command or wallet transaction builder;
- recipient-envelope persistence or availability guarantees;
- durable private snapshots, crash recovery or checkpoint integration;
- ABCI/mempool/consensus admission;
- concurrent writer control for private state; or
- production-approved privacy, post-quantum security or performance.

It also does not alter `noxis-ledger`'s legacy 32-byte public transfer. The two
models remain explicit rather than silently converting security-critical
values between incompatible widths.

## Executable local demo

An optimized command now drives the proof-to-commit boundary directly:

```powershell
cargo run --release -p noxis-private-proof-contract --bin noxis-private-ledger-demo
```

It produces the retained proof bundle, admits its fixed research transfer and
then proves that the same request is rejected. See
[the local private-ledger demo](PRIVATE_LEDGER_LOCAL_DEMO_RESEARCH_V0_1.md) for
the command, expected output and limits. It intentionally does not yet build a
packet or retain private state after the process exits.

## Next implementation gate

Design durable private-state records and crash recovery before connecting a
private transaction path to ABCI or consensus. A future packet/wallet command
must also bind actual recipient envelopes and portable proof bytes rather than
reuse this in-memory fixture.
