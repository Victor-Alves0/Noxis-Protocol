# Candidate private-proof submission receipt v0.1

## Purpose

`CandidatePrivateProofBundleAdmissionReceiptV1` is the public, in-memory
result returned after an `NXPP v1` envelope has both passed verification and
committed one local private-ledger transition. It is deliberately a receipt
boundary, not a new wire or storage format.

It contains only:

- a SHA-256 identity of the exact admitted `NXPP` bytes, under
  `NOXIS/CANDIDATE-PRIVATE-PROOF-BUNDLE-ENVELOPE-ID/V1\0`; and
- the existing public pre/post-state, asset, input-nullifier and output-note
  commitment facts from the candidate ledger admission receipt.

It contains no proof object, `NXPP` bytes, note preimage, recipient material,
nullifier key, ciphertext or Merkle witness.

## Why this exists before durable history

The private state store already has one correct mutation path:

```text
verify candidate transition → append verified post-state to NXPL → publish cache
```

Adding a second journal for submission history now would require a reviewed
cross-file atomicity and recovery protocol. Without that protocol, a crash
could leave a history entry without its post-state, or vice versa.

The receipt therefore establishes the minimum auditable identity and facts
that a future history design must bind, while keeping the current `NXPL`
post-state journal authoritative. The receipt is returned only after the
ledger/store mutation succeeds; a rejected or malformed envelope produces no
receipt.

## Privacy and scope limits

The envelope ID is stable for byte-for-byte identical `NXPP` submissions, so
it is a correlation handle. It must stay local to the candidate operator and
must not be published, used as a wallet payment ID, treated as a nullifier, or
presented as consensus finality. Different randomized proof bytes for an
otherwise equivalent statement can have different envelope IDs.

Neither the receipt nor `NXPL` establishes durable transaction history,
submission ordering, proof availability, a replay protocol across replicas or
interrupted-submission recovery. Those are the next separate design and
implementation gate.

## Verification

The envelope-identity test checks deterministic, exact-byte and
domain-separated derivation. The expensive release integration continues to
exercise the receipt through real `NXPP` admission, state mutation and replay
rejection:

```powershell
cargo test --release -p noxis-private-proof-contract transfer_preflight::tests::executes_every_available_private_relation_for_one_statement --lib -- --exact --ignored --nocapture
```

On 2026-09-02, that complete receipt path passed in **992.62 seconds** with
4,968,410 raw proof bytes and a 4,968,654-byte `NXPP` envelope. These are
research measurements, not protocol limits.
