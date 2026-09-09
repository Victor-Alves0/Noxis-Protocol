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

## Durable local v2 boundary

The private state store already has one correct mutation path:

```text
verify candidate transition → append verified post-state to NXPL → publish cache
```

`PrivateSubmissionStoreV2` now implements the reviewed composite alternative:
after verified admission it appends one `NXPL v2` frame with this receipt's
non-secret facts and the canonical successor `NXPR`, synchronizes the frame,
then publishes its replaceable cache. A reopen validates the receipt/state
delta together. This avoids a second journal and the resulting cross-file
atomicity problem.

The receipt is returned only after the ledger/store mutation succeeds; a
rejected or malformed envelope produces no receipt. `NXPL v1` remains the
separate compatible post-state-only store; it never interprets v2 frames.

## Privacy and scope limits

The envelope ID is stable for byte-for-byte identical `NXPP` submissions, so
it is a correlation handle. It must stay local to the candidate operator and
must not be published, used as a wallet payment ID, treated as a nullifier, or
presented as consensus finality. Different randomized proof bytes for an
otherwise equivalent statement can have different envelope IDs.

`NXPL v2` establishes local durable receipt/state ordering and can recover a
structurally verified interrupted final frame. It does not establish proof
availability, historic proof re-verification, a replica replay protocol,
wallet payment tracking or consensus finality.

The [submission-history atomicity decision](PRIVATE_SUBMISSION_HISTORY_ATOMICITY_DECISION_V0_1.md)
defines the implemented shape: the receipt shares one `NXPL v2` composite
frame with its canonical `NXPR` post-state, rather than becoming a second
independent journal. Offline v1-to-v2 migration and network admission remain
separate gates.

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
