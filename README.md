# Noxis Protocol

Noxis is a security-first implementation of a privacy-preserving, multi-asset settlement protocol. Development starts with the part that must be correct before networking, wallets, liquidity or chain adapters: **the state-transition rules**.

It is not a bank, exchange, wallet, custodian, stablecoin issuer, or production cryptographic implementation. It does not connect to real assets, fiat systems, blockchains, or payment rails.

## What exists now

- A modular Rust workspace with explicit ownership boundaries.
- A UTXO-like private-ledger state model: commitments are created; nullifiers are spent exactly once.
- Explicit asset registry and supply accounting.
- Pluggable proof verification and mint-authority contracts.
- Canonical, versioned binary transaction codec with strict parser limits.
- Fixed-depth Merkle state roots and inclusion proofs for commitments.
- Durable consensus-block replay: an `NXCB` frame stores a whole executed
  block, then recovery re-executes it before restoring its tip; the older
  per-record replay remains only for non-consensus migration/local use.
- A CometBFT v0.38 ABCI lifecycle and TCP socket adapter: local admission
  detects pending double spends, proposal execution is side-effect free, and
  only a finalized candidate can reach the durable `Commit` boundary. Its
  composed service accepts only loopback ABCI listeners, uses a dedicated
  consensus block journal and rejects a genesis or cryptographic components
  that do not match. It still needs end-to-end verification against a real
  CometBFT process; it is not yet a running multi-node network.
- For a Comet-enabled genesis, the engine identity, parameter commitment and
  exact v0.38 Ed25519 validator mapping are bound to `GenesisId` and `NXMF`
  v7; each `NXCB` v2 block binds the exact Comet decision context into both
  durable replay and `AppHash`.
- A typed embedded local-node API for admission, status and membership proofs.
- A genesis-bound data-directory runtime with a cooperative exclusive writer lock.
- Canonical genesis IDs; state IDs and durable histories are bound to that genesis.
- Validation context IDs bind the declared proof verifier and mint policy before recovery.
- Non-self-referential transaction intent IDs, bound with genesis, validation-context and pre-transition state IDs in every transfer proof and mint-authorization statement.
- Canonical `NXCP` checkpoints, atomically published under the protected data directory and verified against strict replay.
- Versioned cryptographic-suite metadata to prevent permanent coupling to one primitive.
- Canonical consensus data: weighted validator sets, block headers, record commitments and finality-certificate verification boundaries. This is not yet a running validator network or a finality claim.
- Genesis and the protected local manifest commit to the validator set, public verification keys, declared fault budget and consensus limits. A node cannot reopen the same data directory with a different consensus configuration.
- Tests for unauthorized issuance, duplicate nullifiers, duplicate commitments, and unknown assets.

`NXCB` consensus-block commits currently require Unix filesystem durability
semantics. On Windows the block writer fails closed instead of acknowledging a
commit without a proven directory-durability barrier.

## Architecture

```text
crates/
  noxis-types    Identifiers, amounts and asset definitions.
  noxis-privacy-types  Canonical public v2 private-transfer values and intent framing.
  noxis-tree-params  Frozen unselected tree-parameter candidates and vector framing.
  noxis-poseidon2-reference  Isolated dense reference evaluator for the unselected P24 candidate.
  noxis-nullifier-tree-state  Isolated mutable state and proof paths for the unselected NXSM candidate.
  noxis-crypto   CryptoSuite metadata and proof-verifier boundary.
  noxis-ledger   Transactions, validation and deterministic state transitions.
  noxis-codec    Canonical binary transaction encoding and decoding.
  noxis-merkle   Fixed-depth commitment tree and inclusion proofs.
  noxis-record-chain Strict state-transition record codec and link validator.
  noxis-checkpoint Canonical checkpoint codec and snapshot integrity validation.
  noxis-consensus  Engine-neutral BFT block, quorum and finality-certificate primitives.
  noxis-execution Deterministic execution of ordered blocks and AppHash calculation.
  noxis-storage  Atomic block journal plus legacy framed-record persistence.
  noxis-comet-abci  ABCI lifecycle, strict v0.38 socket protocol and NXCB.
  noxis-config   Validated genesis and local-node configuration.
  noxis-runtime  Genesis-bound data directory and writer-lock lifecycle.
  noxis-node     Typed local-node API and guarded loopback CometBFT service.
docs/
  README.md                     Documentation map and reader routes.
  PROTOCOL_SPEC_V0_1.md         Scope, invariants and state machine.
  THREAT_MODEL_V0_1.md          Explicit security assumptions and acceptance criteria.
  CONSENSUS_DECISION_V0_1.md    Consensus decision and required security choices.
  CRYPTOGRAPHY_DECISION_V0_1.md Chosen cryptographic direction and safeguards.
  ECONOMIC_SECURITY_MODEL_V0_1.md  Boundaries for validator rewards, liquidity and future contracts.
  TREE_PARAMETER_FRAMING_V0_1.md   Canonical draft manifest and field-vector boundary for v2 trees.
  TREE_VECTOR_CORPUS_FRAMING_V0_1.md  NXTV framing for external tree-vector evidence.
  TREE_VECTOR_CORPUS_P24_V2.md  NXTV v2 framing bound to the frozen P24 candidate.
  NOTE_OPENING_BOUNDARY_V0_1.md  Canonical private-note opening boundary before hash selection.
  POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md  Unselected candidate for private note hash domains.
  POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md  External KATs for private P24 domains.
  NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md  Canonical NXNV framing for private-domain KATs.
  TREE_VECTOR_GENERATION_BLOCKER_V0_1.md  Evidence and prerequisites for complete tree vectors.
  POSEIDON2_TREE_CONSTRUCTION_CANDIDATE_V0_1.md  Unselected P24 tree-construction candidate.
  POSEIDON2_P24_CANDIDATE_MANIFEST_V0_1.md  Frozen but unselected P24 parameter artifact.
  POSEIDON2_P24_REFERENCE_EVALUATION_V0_1.md  Cross-validated P24 permutation and candidate-tree vectors.
  POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md  Cross-validated permutation reference vectors.
  NULLIFIER_SPARSE_MUTABLE_REFERENCE_CANDIDATE_V0_1.md  Isolated mutable NXSM candidate state and limits.
  NULLIFIER_SPARSE_EXTERNAL_KATS_V0_1.md  Independently generated NXSV v1 evidence for the NXSM candidate.
  PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md  Candidate typed binding between a private snapshot and NXSM root.
  PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md  Candidate transparent before/after NXSM nullifier relation.
  ARCHITECTURE.md                Module boundaries and implementation roadmap.
```

For a guided route through protocol, security, architecture, consensus,
durability and privacy research, start with
[`docs/README.md`](docs/README.md).

Run the checks with:

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The CI workflow runs the same quality gate on Ubuntu with Rust 1.85, the
minimum supported compiler. It uses the committed lockfile and has read-only
repository permissions.

On Windows, run the checks from a Visual Studio Build Tools C++ developer
shell (or initialize `VsDevCmd.bat`) so Rust's MSVC target can find the Windows
SDK linker and libraries.

## Local operational demo

Run a complete, durable research-only sequence with:

```powershell
cargo run -p noxis-node --features research-testing -- demo-local
# or, if `just` is installed:
just demo
# Windows convenience script:
.\scripts\demo-local.ps1
```

On POSIX systems, use `./scripts/demo-local.sh`. The demo prints the initialized
genesis and state identities, accepts a fixture-authorized mint and one research
transfer, rejects the same nullifier on a second submission, then reopens the
node to prove durable recovery. Pass `--data-dir PATH` to keep a chosen demo
directory for inspection.

This deliberately does **not** start CometBFT or claim consensus, custody or
privacy: the displayed `AppHash` is explicitly unavailable in local-admission
mode, and the transfer uses a research fixture rather than a private proof.
See [`docs/LOCAL_OPERATIONAL_DEMO_V0_1.md`](docs/LOCAL_OPERATIONAL_DEMO_V0_1.md).

## Security boundary

The `ProofVerifier` and `MintPolicy` interfaces are deliberately unimplemented for production. A transaction is never private merely because it contains a `Proof` byte array: privacy and conservation are established only when an audited proof system verifies the statement against a canonical state root. Post-quantum and hybrid cryptography are design reservations, not active protection in this codebase. The consensus service is fail-closed: no cryptographic context is approved to run settlement yet; the only research exception is an explicitly compiled E2E fixture. See [`docs/CRYPTO_SERVICE_GATE_V0_1.md`](docs/CRYPTO_SERVICE_GATE_V0_1.md).

The ABCI socket is deliberately loopback-only and has bounded local
connections, but it is still unauthenticated IPC. It must run in an
operator-controlled same-user or isolated service boundary with CometBFT; a
host where arbitrary local processes are untrusted needs an authenticated IPC
boundary (for example a permissioned Unix socket) before use.

Do not use this code to custody value or operate on public networks without an independent security review, a complete threat model, formal protocol work, legal analysis, and operational controls.
