# Noxis Protocol

Noxis is a security-first implementation of a privacy-preserving, multi-asset settlement protocol. Development starts with the part that must be correct before networking, wallets, liquidity or chain adapters: **the state-transition rules**.

It is not a bank, exchange, wallet, custodian, stablecoin issuer, or production cryptographic implementation. It does not connect to real assets, fiat systems, blockchains, or payment rails.

## Research and community

Noxis is being built in public for careful technical discussion. Researchers,
Rust engineers, protocol designers and reviewers can start with the
[documentation map](docs/README.md), propose an answer to an
[open research question](docs/OPEN_QUESTIONS.md), or browse issues labeled
`help wanted`.

For design discussion, use GitHub Discussions or a scoped issue. For a
suspected vulnerability, follow [SECURITY.md](SECURITY.md) and do not disclose
details in a public issue. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
review and testing expectations.

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
  that do not match. CI runs a pinned real CometBFT process through handshake,
  empty-block `Commit` and restart; this is not yet a running multi-node
  network.
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
- A research-only Plonky3 STARK experiment that proves the frozen
  Poseidon2-P24 candidate permutation, private `H_ADDR(key)` and
  `H_NOTE(preimage)` relations, plus the public `H_INTENT` sponge over the
  canonical candidate intent frame. It also proves a composed private
  key-to-note-to-nullifier ownership-and-full-depth-private-membership binding,
  all with byte-exact `BytePack3LE`,
  `Hash16(Leaf, commitment)` and ordered
  `Hash16(Node, left || right)` constructions against external vectors, plus
  one private ordered Merkle step, a two-level private path and a complete
  depth-32 private path bound to note ownership. A local preflight can run the
  two candidate ownership checks sequentially against one typed `NXPS v2`
  anchor and ordered transparent `NXSM` witness. It is not proof aggregation,
  a nullifier-absence, value-conservation or private-transfer proof. The
  `H_INTENT` component arithmetizes the canonical byte packing, but does not
  yet bind any private witness.
- A second research-only STARK component proves exact private eight-level
  `NXSM` segments, including the sparse tree's byte packing and canonical
  nullifier-bit ordering. It can locally sequence all 64 segments to a real
  512-level candidate root, verifying and dropping every proof in turn. This
  is not a portable nullifier-absence proof or production privacy.
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
  noxis-private-proof-contract  Candidate public proof framing and local NXSM transition witness; no proof backend.
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
  PRIVATE_TRANSFER_WITNESS_CONSTRAINT_INTERFACE_CANDIDATE_V0_1.md  Candidate local witness contract for sequential NXSM constraints.
  PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md  Candidate unified public statement joining note and NXSM relations.
  PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md  Candidate machine-readable AIR constraint profile.
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

The CI workflow runs the same quality gate on Ubuntu with Rust 1.93, the
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

Run the separate full-depth P24 STARK research demo with an optimized build:

```powershell
cargo run --release -p noxis-stark-experiment --bin noxis-stark-smoke
```

It proves private candidate `H_ADDR` and `H_NOTE` preimages, plus one composed
private ownership-and-depth-32-membership binding with a public nullifier and
root. This is an expensive research workload, not a wallet or validator
operation; it does not yet prove state-anchor acceptance, nullifier absence or
a private transfer. The research API now keeps local proving and independent
verification as separate calls, but intentionally has no proof wire format.
An executable local preflight additionally binds one such proof to the typed
candidate state anchor and its `NXSM` nullifier transition; the `NXSM` witness
is still transparent and therefore is not a privacy proof.

The research proof contract now also has a typed in-memory bundle that retains
the composed intent/value proof and both ownership proofs, then lets a separate
fail-closed adapter verify them again against the same `NXPU v1` statement and
current nullifier state. It deliberately has no byte encoding, ledger adapter
or consensus activation; see
[`docs/PRIVATE_TRANSFER_PROOF_BUNDLE_RESEARCH_V0_1.md`](docs/PRIVATE_TRANSFER_PROOF_BUNDLE_RESEARCH_V0_1.md).

To reproduce the separate complete `NXSM` local preflight, explicitly opt in:

```powershell
cargo run --release -p noxis-stark-experiment --features local-nxsm-preflight --bin noxis-stark-smoke -- nxsm-preflight
```

It derives one non-secret candidate path, locally verifies and discards 64
private eight-level STARK proofs, and checks the final candidate root. On the
development machine this took about 32 minutes. It produces only a local
research receipt — never a portable proof, transaction, wallet or validator
operation.

On POSIX systems, use `./scripts/demo-local.sh`. The demo prints the initialized
genesis and state identities, accepts a fixture-authorized mint and one research
transfer, rejects the same nullifier on a second submission, then reopens the
node to prove durable recovery. Pass `--data-dir PATH` to keep a chosen demo
directory for inspection.

For an explicit persistent research-node lifecycle, use
`research init --data-dir PATH` and `research status --data-dir PATH`; see
[`docs/LOCAL_OPERATIONAL_DEMO_V0_1.md`](docs/LOCAL_OPERATIONAL_DEMO_V0_1.md).

Run the separate local hybrid recipient demonstration with:

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo
```

It creates fresh non-persistent keys, round-trips a public diversified address
and recipient envelope through their strict codecs, decrypts only as the
address owner, rejects an unrelated recipient and verifies a hybrid identity
signature. It is not a wallet, private transfer or production cryptography;
see [`docs/WALLET_CRYPTO_LOCAL_DEMO_V0_1.md`](docs/WALLET_CRYPTO_LOCAL_DEMO_V0_1.md).

To demonstrate the separate incoming view key scanning a bounded local batch
of encrypted candidate notes, run:

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note-scan
```

It accepts only notes authenticated for that recipient and ignores unrelated
or unauthenticated envelopes. It has no block source, persistence, balance,
nullifier or spend authority; see
[`docs/INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md`](docs/INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md).

To exercise the stricter packet-bound path, in which a candidate `NXPT` first
binds each `NXRE` envelope to its public output commitment before the incoming
view key scans it, run:

```powershell
cargo run -p noxis-private-packet-validation --bin noxis-private-packet-validation-demo
```

It rejects swapped output envelopes before decryption and then finds one local
recipient note out of two. This still does not verify a proof, admit the packet
to the ledger, establish finality, persist a note or create spend authority;
see
[`docs/PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md`](docs/PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md).

To persist and reopen only public address material, use:

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- address-book --data-dir .\target\noxis-public-addresses
# List and strictly revalidate stored public addresses:
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- address-book list --data-dir .\target\noxis-public-addresses
```

The address book stores canonical `NXPA` files with a single-writer lock. It
cannot store a private key, decrypt a payload, restore a wallet or spend funds.

To reproduce a **synthetic-only** keystore backup and restoration in two local
processes, run:

```powershell
New-Item -ItemType Directory -Force .\target\noxis-keystore-synthetic-demo | Out-Null

cargo run -p noxis-wallet-keystore --features research-testing --bin noxis-keystore-synthetic-demo -- create --wallet-dir .\target\noxis-keystore-synthetic-demo\source-wallet --bundle .\target\noxis-keystore-synthetic-demo\backup.nxkb --anchor .\target\noxis-keystore-synthetic-demo\anchor.nxka

cargo run -p noxis-wallet-keystore --features research-testing --bin noxis-keystore-synthetic-demo -- restore --wallet-dir .\target\noxis-keystore-synthetic-demo\restored-wallet --bundle .\target\noxis-keystore-synthetic-demo\backup.nxkb --anchor .\target\noxis-keystore-synthetic-demo\anchor.nxka
```

The commands prove canonical `NXKB` transport with a separately retained
`NXKA` receipt, not a user wallet backup. They generate no user seed, spend key
or view key; see [`docs/WALLET_SYNTHETIC_RECOVERY_BUNDLE_CANDIDATE_V0_1.md`](docs/WALLET_SYNTHETIC_RECOVERY_BUNDLE_CANDIDATE_V0_1.md).

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
