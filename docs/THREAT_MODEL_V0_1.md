# Noxis Protocol — Threat Model v0.1

## Status and decision boundary

This document describes the security assumptions and known limits of the Noxis
v0.1 ledger transition function, local-node runtime, durable replay, and
CometBFT ABCI integration boundary. The repository now contains canonical BFT
data types, deterministic block execution, a loopback TCP ABCI adapter, an
authoritative `NXCB` consensus-block journal, canonical `NXCP` checkpoints,
and cooperative writer exclusion. CI also starts a pinned real CometBFT
process against the adapter for one local handshake/empty-block/restart path.

`NXCP` is currently a canonical artifact and strict-replay check for the
legacy `NXRF` local-record mode; it is not an `NXCB` recovery accelerator or
an authenticated consensus checkpoint.

Those facts establish implementation and test boundaries; they do **not**
establish a deployed multi-validator network, a production finality claim,
peer security, fault tolerance under adversarial operations, or authorization
to settle external assets.

The v0.1 implementation is not authorized to custody value or make claims of
privacy, backing, finality, post-quantum resistance, or production readiness.
Those properties require separate protocol specifications, concrete reviewed
implementations, and operational controls.

## Protected assets and security properties

The protocol must protect the following properties within its stated boundary:

| Asset or property | Required protection in v0.1 |
| --- | --- |
| Asset definitions | An asset identifier is registered before it can be referenced by a transaction. |
| Issued supply | Supply can increase only through an accepted `Mint` transition, with a positive amount and a successful `MintPolicy` decision. |
| Commitments | An accepted commitment cannot be accepted again or mutated in the in-memory ledger state. |
| Nullifiers | A nullifier can be accepted at most once in a ledger state's lifetime. |
| Transition determinism | Given equivalent state, transaction, proof-verifier result, and mint-policy result, ledger validation must reach the same accept/reject decision. |
| State anchor | A transfer verifier receives the root and fixed depth of the current commitment tree, rather than a count-derived placeholder. |
| Protocol evolution | Cryptographic-suite metadata is versioned, so future choices are explicit rather than silently changing assumptions. |
| Consensus decision context | In Comet mode, genesis, `NXCB`, deterministic execution and `AppHash` bind the configured Comet identity, validator mapping and decision context. |
| Durable authority | In Comet block-journal mode, recovery re-executes complete `NXCB` frames rather than treating a legacy transaction log or `NXCP` artifact as a decided block. |

`issued_supply` is an accounting value for authorized protocol issuance. It is
not evidence that an asset is collateralized, redeemable, or backed by an
external reserve.

## Actors

| Actor | Capabilities | Security relevance |
| --- | --- | --- |
| Honest client | Submits a syntactically valid transfer or mint request. | Needs rejection of invalid state transitions. |
| Malicious client | Chooses arbitrary transaction fields, proofs, commitments, nullifiers, and request timing. | Primary source of double-spend, replay, malformed-input, and unauthorized-issuance attempts. |
| Mint authority | Supplies evidence interpreted by `MintPolicy`. | Can authorize issuance within the policy it controls; this is a privileged role, not a trustless mechanism. |
| Proof-verifier provider | Implements `ProofVerifier`. | Determines whether a claimed proof is accepted. A defective or malicious implementation can defeat properties delegated to proof verification. |
| Node operator | Configures the local runtime, validator mapping, storage location and attached CometBFT process. | The runtime rejects mismatched deployment configuration and holds cooperative writer ownership, but the operator still controls host availability, executable provenance and local IPC exposure. |
| CometBFT engine / validator operator | Orders proposals and calls the ABCI lifecycle. | Noxis checks the received application-facing context and persists only at `Commit`; it does not itself authenticate P2P peers, manage validator private keys or prove remote votes to clients. |
| Future dependency or maintainer | Changes code, dependencies, configurations, or suite selection. | Can introduce behavior changes, supply bugs, or weakened validation without disciplined review and release controls. |

## Trust boundaries

1. **Transaction input → ledger validation.** Transaction fields are untrusted
   until the ledger checks structure, asset existence, commitment uniqueness,
   nullifier freshness, and mint amount.
2. **Ledger → `ProofVerifier`.** Ownership, membership, value conservation,
   witness validity, and any privacy claim are outside the ledger's direct
   validation. They are trusted only to the extent that the selected verifier
   correctly verifies a specified statement against canonical public inputs.
3. **Ledger → `MintPolicy`.** Authority to issue is delegated to policy. The
   ledger passes a complete `MintStatement` bound to the genesis, validation
   context, intent, pre-transition state, state root, prior supply and exact
   issuance fields. It verifies that a policy approves; it does not
   independently prove reserves, collateral, legal authorization, or off-chain
   settlement.
4. **Node composition → protocol behavior.** The node selects concrete
   dependencies. Their public `ProofVerifierId` and `MintPolicyId` are bound
   into the immutable genesis validation context and are checked before log
   recovery and every submission. This detects a declared component swap, but
   it does not attest the executable or provide network governance.
5. **In-memory state → durable/system state.** The legacy `NXRF` path remains
   a local record-log mode. In Comet block-journal mode, only a complete,
   synchronized `NXCB` frame written at ABCI `Commit` is authoritative;
   recovery streams from genesis, re-executes every block and compares its
   header, Comet decision context, records and `AppHash`. Canonical `NXCP`
   artifacts are atomically published and strictly compared during legacy
   `NXRF` replay; they are not authenticated finality certificates, `NXCB`
   recovery accelerators or sources of block authority.
6. **Writer / storage boundary.** `LocalNodeRuntime` owns a cooperative
   create-new sentinel in its data directory, and `BlockJournal` holds an
   exclusive OS journal lock during recovery/writes. This constrains
   cooperating processes; it does not defend against a malicious host, an
   application that bypasses the component, unknown network-filesystem
   semantics, or all crash modes.
7. **CometBFT → loopback ABCI.** The TCP adapter accepts only loopback
   listeners, bounds protobuf framing and serializes concurrent engine
   connections. It is still unauthenticated same-host IPC and is not a public
   peer transport or a substitute for OS isolation.

## Threats and v0.1 treatment

| Threat | Attack outcome | Current treatment | Remaining risk / required future control |
| --- | --- | --- | --- |
| Reuse a nullifier | Double spend within one ledger state. | Ledger rejects spent nullifiers; Comet proposal handling uses discardable candidates and persists only the finalized `Commit` block as one `NXCB` frame. | Multi-validator adversarial, partition, crash and operator tests remain required before a network security claim. |
| Reuse a commitment | Duplicate note representation or ambiguous state. | Ledger rejects commitments already present and duplicate outputs in the same transition. | Requires canonical encoding and durable uniqueness checks. |
| Mint without authority | Unauthorized supply increase. | Mint requires known asset, positive amount, unique outputs, and policy approval over a deployment- and state-bound statement. | A permissive, compromised, or incorrectly configured policy can still authorize issuance. |
| Transfer unknown asset | State pollution or undefined asset rules. | Ledger rejects transfers/mints for unregistered assets. | Asset registration governance is not yet specified. |
| Forge proof or exploit weak proof integration | Spend without valid ownership, membership, or conservation. | These checks are delegated through `ProofVerifier`; v0.1 makes no assertion that a real proof system is used. | Define the statement and public inputs, construct canonical state roots, use an independently reviewed backend, and test adversarially. |
| Replay a transaction | Repeat an accepted state transition. | State-level duplicate nullifier/commitment checks stop many replay forms; transaction IDs are recorded. | Canonical transaction IDs, signatures, nonces, and network replay rules are not specified. |
| Overflow or invalid amounts | Incorrect supply accounting. | Amount uses a domain type and mint requires positive values. | Audit all arithmetic and define bounded serialization/decoding rules before persisted or networked use. |
| Malformed or ambiguous serialization | Different components interpret one transaction differently. | `NOXT`, `NXRC`, `NXCB/NXBP` and the loopback ABCI transport use versioned, bounded decoding with canonical/trailing-byte checks at their respective boundaries. | Add fuzz/property testing, signed/proven intent bindings and network-version negotiation. |
| State rollback, crash, or concurrent update | Previously spent nullifier becomes spendable again, or state becomes inconsistent. | `NXCB` recovery re-executes a complete synchronized block frame before advancing the tip; an incomplete final frame is removed only after its complete prefix validates. `NXCP` is canonical and checked against legacy `NXRF` replay. Runtime and journal locks serialize cooperating writers; consensus commits fail closed on platforms without the documented directory-durability barrier. | Add comprehensive fault injection, storage-platform validation, authenticated checkpoint acceleration, replication, backup/restore and hostile multi-process tests. |
| Equivocation by node operator | Different clients observe different ledgers or verifier/policy choices. | The Comet integration binds configured identity and decision context into genesis, journal recovery and `AppHash`; CI runs a pinned real CometBFT process through local handshake, empty-block commit and restart. | No multi-validator/P2P deployment, remote finality-verification API, vote-WAL operational evidence, peer authentication, key lifecycle or governance policy is complete. Do not claim BFT finality. |
| Denial of service | Exhaust CPU/memory with large or costly inputs. | Transaction, journal and ABCI parsers apply explicit bounds; the TCP adapter has bounded frames and proposal limits. | Add systematic cost accounting for proofs, rate limits, queues, peer-facing admission controls and production monitoring. |
| Dependency or build compromise | Malicious code changes validation behavior. | CI uses a locked Rust workspace and pins the CometBFT process artifact by SHA-256 for the integration job. | Add reproducible releases, dependency review policy, provenance/signature verification, SBOMs and security scanning. |
| Privacy metadata leakage | Link users or notes through transport, timing, wallet behavior, or public inputs. | The only implemented transport is unauthenticated loopback ABCI; there is no public peer network, production wallet or private-transfer verifier. | Develop a separate privacy threat model covering statement design, wallets, network metadata, logging, mempool behavior and operational practices. |

## Explicit non-goals

The following are not provided by v0.1 and must not be inferred from its APIs
or data structures:

- Custody, key management, account recovery, transaction signing, or wallet
  safety.
- A concrete zero-knowledge proof system, proof soundness, zero knowledge,
  trusted-setup management, post-quantum resistance, or any cryptographic
  security level.
- ZK-compatible Merkle hashing or proof membership validation by an audited
  circuit. The current SHA-256 commitment tree establishes state semantics but
  is not the planned proof-compatible tree.
- Public P2P transport, peer authentication, a multi-validator deployment,
  client-verifiable finality, data availability, censorship resistance, or
  protection against a malicious node operator. The loopback ABCI integration
  and its local CometBFT CI scenario are not these properties.
- Authenticated checkpoint acceleration, replication, backup/restore,
  malicious-storage resistance, or a complete cross-platform crash-consistency
  guarantee. Canonical checkpoints and cooperative writer exclusion exist but
  do not supply those stronger properties.
- Fiat redemption, external-asset custody, collateral verification, oracle
  correctness, bridges, or proof of reserves.
- Regulatory compliance, identity checks, KYC/AML controls, sanctions
  screening, legal opinions, or jurisdiction-specific operation.

## Security acceptance criteria for a production-oriented next stage

The ledger core may advance beyond the v0.1 boundary only when the following
are satisfied and evidenced in reviewable artifacts:

1. The proof statement, public inputs, state-root algorithm, and verifier
   failure behavior are specified precisely; a transaction cannot be accepted
   solely because an opaque proof byte array is present.
2. A concrete cryptographic backend is selected with documented assumptions,
   version pinning, test vectors, independent review, and a migration policy.
3. Transaction encoding and IDs are canonical, domain-separated, bounded, and
   covered by malformed-input, property, and fuzz tests.
4. The `NXCB` commit/recovery path, writer ownership and the separate legacy
   `NXRF` checkpoint lifecycle have fault-injection and cross-platform evidence
   demonstrating that accepted nullifiers and commitments are not lost or
   duplicated under supported failure scenarios.
5. Each mint policy has an explicit authority model, key lifecycle, revocation
   and rotation procedure, audit trail, and clearly stated external-asset
   semantics. No backing claim is made until that policy is independently
   verified for the relevant asset.
6. The existing ABCI/CometBFT integration has multi-validator adversarial
   tests, remote finality-verification evidence, configuration provenance,
   upgrade governance and operational monitoring before any network claim.
7. Security review covers the implementation, dependencies, operational
   deployment, and the relevant privacy model before any transferable value or
   public test network is introduced.

## Review triggers

This threat model must be updated before merging changes that add a concrete
proof system, change the mint-authority model, introduce serialization or
persistence, expose network APIs, add a wallet or chain adapter, or make a
claim about an external asset. A security-relevant change is incomplete until
its affected assumptions, threats, tests, and acceptance criteria are updated.
