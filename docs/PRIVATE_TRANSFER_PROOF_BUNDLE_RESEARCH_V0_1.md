# In-memory private-transfer proof bundle — research v0.1

## Implemented boundary

`CandidatePrivateTransferProofBundleV1` retains three opaque Plonky3 proof
objects inside one process:

1. one composed `H_INTENT` plus four-note value-conservation proof;
2. one ownership and depth-32 membership proof for input slot zero;
3. one ownership and depth-32 membership proof for input slot one.

Every relation is bound to the same canonical `NXPU v1` statement ID. The two
ownership relations also retain crate-local bindings to the exact input-note
commitments proved by the value relation. Domain-separated receipt identities
include the relation kind and input slot, so a caller cannot silently swap the
two ownership proofs or mix a proof from another statement.

`CandidatePrivateTransferProofBundleVerifierV1` fails closed. It reconstructs
the expected receipt identities, revalidates the statement against the current
nullifier tree, derives a fresh `NXSM` witness from that current state, verifies
all three opaque proofs independently, and rechecks the asset, output
commitments, nullifiers, note root and input-note cross-bindings.

## Why this matters

The earlier complete preflight proved and verified each relation, then dropped
the proof object and retained only public results. That demonstrated that the
relations could execute, but another component could not independently verify
what had been produced.

The bundle changes that boundary: proof material now survives long enough for
a separate verifier adapter to check it again. In plain terms, Noxis no longer
has to trust a local receipt saying “the proofs passed”; the adapter receives
the actual in-memory proofs and verifies them.

## Fail-closed state behavior

The bundle is not sufficient on its own. Verification requires the exact
current candidate nullifier state. A bundle valid for an earlier state is
rejected if its anchor no longer matches or if either nullifier has become
spent. Atomic mutation remains a ledger responsibility.

## Deliberate non-claims

The bundle is now carried only by the separate, local
[`NXPP v1` candidate envelope](PRIVATE_PROOF_BUNDLE_ENVELOPE_CANDIDATE_V0_1.md).
That envelope strictly frames bytes, reconstructs the three research objects
and independently verifies them before returning a usable bundle; it is still
not a transaction, verifier profile or selected Noxis artifact. The bundle is
not:

- a `noxis_crypto::ProofVerifier` implementation;
- a byte proof accepted by `noxis-ledger`;
- aggregation or recursion;
- a selected verifier profile or production proof suite;
- consensus admission or a private transaction submitted over ABCI;
- a claim that the current performance is suitable for a wallet.

The separation is necessary because the active ledger proof API still accepts
portable bytes and legacy 32-byte nullifiers, while the candidate private
statement uses local opaque proofs and 64-byte nullifiers. Bridging those types
implicitly would create an unsafe production bypass.

## Reproduction and measured cost

The full test is ignored by default because it runs both the compatibility
preflight and the retained bundle, then independently verifies the bundle and
checks rejection after the state changes. Run it explicitly in optimized mode:

```powershell
cargo test --release -p noxis-private-proof-contract transfer_preflight::tests::executes_every_available_private_relation_for_one_statement --lib -- --exact --ignored --nocapture
```

On 2026-09-01 the bundle-only version of this command passed locally in
**936.43 seconds** (about 15 minutes 36 seconds), excluding the 33.53-second
release compilation. Peak resident memory observed during the depth-32
ownership phases was about **4.45 GB**. After typed ledger admission was added,
the expanded proof-to-commit-and-replay test passed in **1088.32 seconds**; see
[`PRIVATE_LEDGER_ADMISSION_RESEARCH_V0_1.md`](PRIVATE_LEDGER_ADMISSION_RESEARCH_V0_1.md).

On 2026-09-02, the same full release test measured **4,968,511 bytes** of raw
pinned-research proof objects: 2,836,034 for intent/value, 1,066,377 for the
first ownership proof and 1,066,100 for the second. This is one research-case
measurement, not a maximum, protocol size limit or network-ready envelope.
The deliberately separate [candidate transport budget](PRIVATE_PROOF_TRANSPORT_BUDGET_CANDIDATE_V0_1.md)
uses that evidence for a bounded future envelope without changing `NXPT v1`.
The subsequent `NXPP` release round trip completed in 991.30 seconds with a
fresh 4,967,527-byte raw bundle and a 4,967,771-byte complete envelope; see
[the envelope evidence](PRIVATE_PROOF_BUNDLE_ENVELOPE_CANDIDATE_V0_1.md).

An unoptimized debug run was intentionally stopped after approximately 181
minutes while it was still making CPU progress. This is why the integration
test is ignored by default and why debug timings must not be presented as a
wallet benchmark.

## Implemented next gate

The typed private-ledger admission boundary now reconstructs `NXPU v1`, invokes
this verifier and atomically applies both nullifiers and commitments without
using the legacy 32-byte transfer model. The bundle itself remains local and
in memory; portable proof encoding, durable private transition history,
verifier identity and consensus activation remain separate later gates.
