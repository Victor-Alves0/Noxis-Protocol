# Candidate private-proof bundle envelope v0.1

## Status

`NXPP v1` is a canonical **local research envelope** for the three retained
Plonky3 proof objects currently used by the candidate private-transfer path.
It makes this limited sequence executable:

```text
typed local bundle
  → canonical NXPP bytes
  → strict bounded framing
  → rebuild pinned-research proof objects
  → independently verify all three relations against NXPU + current NXSM tree
  → typed local ledger admission
```

It is not a selected verifier profile, a wallet transaction, ABCI input,
network message, consensus rule or production privacy claim. The crypto
service remains fail-closed. In particular, the current proof composition
still has independently verified relations rather than one reviewed
transfer-proof system with nullifier absence inside its AIR.

`NXPP` now fits in `NXPT v1`'s opaque proof field: that packet's explicit
local-candidate limit is 8,454,144 bytes, matching the bounded `NXPP` envelope
rather than the former insufficient 2 MiB provisional limit. This does not
turn either format into a selected transaction or consensus format.

## Exact layout

All structural integers are big-endian. BabyBear field vectors are the
existing canonical 16 × `u32le` `NoteCommitmentV2` representation.

| Bytes | Field | Rule |
| ---: | --- | --- |
| 4 | `"NXPP"` | Exact magic. |
| 2 | version | Exactly `1`. |
| 2 | flags | Exactly zero. |
| 32 | candidate deployment ID | Must equal the locally reconstructed `NXPD v1` candidate ID. |
| 32 | statement ID | Must equal the supplied canonical `NXPU v1` statement ID. |
| 128 | two input-note commitments | Two canonical `NoteCommitmentV2` values, in input-slot order. They are the public inputs needed to reconstruct the intent/value and ownership proof metadata. |
| 12 | three `u32` proof lengths | Intent/value, ownership slot 0, ownership slot 1; every chunk is nonempty. |
| variable | three raw P3 proof chunks | In exactly that relation order. |
| 32 | checksum | SHA-256 over all preceding bytes under `NOXIS/CANDIDATE-PRIVATE-PROOF-BUNDLE-ENVELOPE-CHECKSUM/V1\0`. |

There are no caller-provided relation receipts, output commitments, nullifiers,
roots, trace heights or verifier IDs. The decoder reconstructs those values
from its supplied `NXPU` statement and candidate profile. This prevents an
envelope author from silently selecting a different statement or swapping
ownership slots through metadata.

## Resource and parser behavior

`NXPP v1` uses the separate
[candidate proof transport budget](PRIVATE_PROOF_TRANSPORT_BUDGET_CANDIDATE_V0_1.md):

- raw aggregate proof chunks: at most 8 MiB;
- framing plus public metadata: 244 bytes for this v1 layout, within the
  explicit 64 KiB allowance;
- total envelope: at most 8,454,144 bytes.

The decoder checks total size, magic, version, zero flags, exact deployment
binding, exact supplied-statement binding, canonical commitments, all declared
lengths, nonempty chunks, aggregate budget and checksum **before** invoking a
P3 decoder. It accepts neither trailing bytes nor framing ambiguity.

Successful structural parsing alone is not acceptance. `decode_and_verify`
rebuilds fresh pinned-research proof objects, derives the expected public
results from `NXPU`, then invokes the existing three-proof bundle verifier
against the supplied current `NXSM` state. Only then can it return the typed
bundle used by the local private ledger. A stale anchor or spent nullifier is
therefore rejected by the same existing state-bound verifier.

For callers that should not manipulate proof types at all,
`admit_candidate_private_proof_bundle_envelope` is the only local byte-to-ledger
orchestration API. It takes `(mutable ledger, typed intent, NXPP bytes)`,
reconstructs `NXPU` from the current ledger state, decodes and verifies the
envelope, then calls the ledger's atomic transition boundary. The intent is
deliberately typed and supplied separately: `NXPP` carries only the statement
ID, not a duplicate public transaction frame.

The corresponding `admit_candidate_private_proof_bundle_envelope_to_store`
function uses `PrivateStateStoreV1`'s existing single-writer `NXPL` journal
path. It persists a verified post-state and supports reopen/recovery; it does
not turn `NXPP` into durable transaction or proof history.

`admit_candidate_private_proof_bundle_envelope_to_submission_store` uses the
separate `PrivateSubmissionStoreV2` path. It verifies the same bytes first,
then persists the local envelope ID and typed transition facts with the
successor state in one `NXPL v2` frame. It still never persists `NXPP` bytes,
proofs or witnesses, and is not a network transaction history.

After a successful local admission, the API returns a separate
[submission receipt](PRIVATE_PROOF_SUBMISSION_RECEIPT_CANDIDATE_V0_1.md) whose
envelope ID is a domain-separated SHA-256 hash of the exact bytes. That ID is
local and correlatable; it is deliberately outside the `NXPP` layout and is
not a public transaction identifier.

`admit_candidate_private_transfer_packet_to_submission_store` is the complete
local packet path. It strictly decodes `NXPT`, validates both `NXRE` values and
their output-slot ciphertext digests, then treats the packet's bounded proof
field as `NXPP`. The packet intent is the sole source used to derive `NXPU`, so
recipient delivery metadata, public intent and proof statement cannot be mixed
across packets. Successful admission persists only the existing local `NXPP`
receipt ID and successor state facts in `NXPL v2`; it does not retain the
packet, envelopes, proofs or witnesses. This remains local candidate storage,
not a wallet submission, ABCI or consensus path.

## Required evidence and remaining gates

The focused unit test covers malformed framing before P3 deserialization. The
ignored optimized integration test additionally exercises the full real path,
including `bundle → NXPP inside validated NXPT → decoded bundle → verify →
ledger mutation → replay rejection`:

```powershell
cargo test --release -p noxis-private-proof-contract local_ledger_demo::tests::proves_commits_and_rejects_replay_through_the_local_demo --lib -- --exact --ignored --nocapture
```

Its cost remains substantial: it executes the current research prover and
verifier rather than a wallet-ready prover. The previous full path took about
16–18 minutes and peaked near 4.45 GB resident memory. `NXPP` does not reduce
that cost and must not be advertised as a network admission budget.

On 2026-09-09, this exact complete release test passed in **526.09 seconds**
after adding the local `NXPT`/`NXRE` packet path. A separate fresh persistent
release command also accepted the packet, rejected replay and recovered one
`NXPL v2` receipt/state frame after reopen. These are supporting local research
evidence, not wallet or consensus performance claims.

On 2026-09-02, the earlier complete release command passed in **991.30 seconds**. Its
freshly generated raw proof chunks totaled **4,967,527 bytes** and the exact
`NXPP v1` envelope was **4,967,771 bytes** (the fixed framing/checksum cost is
244 bytes). P3 proof serialization varies slightly across generated proofs,
so this is supporting evidence rather than a new maximum; both observed runs
remain inside the 8 MiB candidate raw-proof cap.

The same command subsequently exercised the public byte-to-ledger admission
API in **1014.98 seconds**, with 4,967,982 raw proof bytes and a 4,968,226-byte
envelope. It accepted the first admission and rejected replay after commit.

Before promotion beyond this local research boundary, the project still needs
adversarial maximum-size deserialization and verification benchmarks, fuzzing,
CPU/memory/concurrency policy, a selected/reviewed proof profile, privacy
analysis of the public input commitments, a complete nullifier-absence proof,
wallet transaction construction, consensus admission and independent review.
