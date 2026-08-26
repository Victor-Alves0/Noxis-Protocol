# Noxis Protocol — Threat Model v0.1

## Status and decision boundary

This document describes the security assumptions and known limits of the Noxis
v0.1 ledger transition function, its fixed-depth commitment tree, and its
single-process append-only replay coordinator. It applies to the Rust modules
currently in this repository, not to a deployed network, a wallet, a
custodian, or a system that settles external assets.

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
| Node operator | Composes the modules and invokes ledger transitions. | Atualmente controla disponibilidade e a escolha de verificador/política; consenso foi escolhido como arquitetura futura, mas ainda não existe uma implementação que o restrinja. |
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
5. **In-memory state → durable/system state.** `PersistentLedger` validates a
   candidate, writes canonical transaction bytes to a synced append-only
   state-record chain, then publishes it in memory; restart replays those
   transitions. It remains a single-process component without checkpoints,
   inter-process writer exclusion, replication, or audit authentication.

## Threats and v0.1 treatment

| Threat | Attack outcome | Current treatment | Remaining risk / required future control |
| --- | --- | --- | --- |
| Reuse a nullifier | Double spend within one ledger state. | Ledger rejects a nullifier already in `spent_nullifiers`. | Requires atomic persistence and consensus ordering before multi-node operation. |
| Reuse a commitment | Duplicate note representation or ambiguous state. | Ledger rejects commitments already present and duplicate outputs in the same transition. | Requires canonical encoding and durable uniqueness checks. |
| Mint without authority | Unauthorized supply increase. | Mint requires known asset, positive amount, unique outputs, and policy approval over a deployment- and state-bound statement. | A permissive, compromised, or incorrectly configured policy can still authorize issuance. |
| Transfer unknown asset | State pollution or undefined asset rules. | Ledger rejects transfers/mints for unregistered assets. | Asset registration governance is not yet specified. |
| Forge proof or exploit weak proof integration | Spend without valid ownership, membership, or conservation. | These checks are delegated through `ProofVerifier`; v0.1 makes no assertion that a real proof system is used. | Define the statement and public inputs, construct canonical state roots, use an independently reviewed backend, and test adversarially. |
| Replay a transaction | Repeat an accepted state transition. | State-level duplicate nullifier/commitment checks stop many replay forms; transaction IDs are recorded. | Canonical transaction IDs, signatures, nonces, and network replay rules are not specified. |
| Overflow or invalid amounts | Incorrect supply accounting. | Amount uses a domain type and mint requires positive values. | Audit all arithmetic and define bounded serialization/decoding rules before persisted or networked use. |
| Malformed or ambiguous serialization | Different components interpret one transaction differently. | `NOXT` is canonical, versioned, bounded and rejects malformed/trailing input; durable records use canonical `NXRC` inside framed `NXRF` storage. | Add fuzz/property testing, signed/proven intent bindings and network-version negotiation. |
| State rollback, crash, or concurrent update | Previously spent nullifier becomes spendable again, or state becomes inconsistent. | `PersistentLedger` replays a genesis-bound, sequential chain of canonical records and keeps nullifiers, while a candidate state is published only after `sync_data` succeeds. A clearly incomplete final frame is removed explicitly before replay. | Add verified checkpoints, inter-process writer exclusion, fault injection and replication. |
| Equivocation by node operator | Different clients observe different ledgers or verifier/policy choices. | Não há rede nem consenso implementado; o modelo de consenso foi escolhido e está documentado. | Escolher engine/modelo de falhas, implementar pares autenticados, finalidade, WAL de voto e governança de configuração. |
| Denial of service | Exhaust CPU/memory with large or costly inputs. | Basic non-empty validation exists only. | Add explicit size, depth, and verification-cost limits; rate limits; queues; and resource monitoring. |
| Dependency or build compromise | Malicious code changes validation behavior. | No release or supply-chain controls are defined here. | Pin and audit dependencies, generate reproducible builds, sign releases, review changes, and use CI security scanning. |
| Privacy metadata leakage | Link users or notes through transport, timing, wallet behavior, or public inputs. | No networking, wallet, or concrete proof system exists. | Develop a separate privacy threat model covering statement design, wallets, network metadata, logging, and operational practices. |

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
- Network transport, peer authentication, consensus, finality, data
  availability, censorship resistance, or protection against node equivocation.
- Multi-process durable storage, checkpoints, backup/restore, authenticated
  history or crash-consistency guarantees beyond the documented single-process
  append-and-replay behavior.
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
4. State commits are atomic and durable; restart, rollback, corruption, and
   concurrent-submission tests demonstrate that accepted nullifiers and
   commitments are not lost or duplicated.
5. Each mint policy has an explicit authority model, key lifecycle, revocation
   and rotation procedure, audit trail, and clearly stated external-asset
   semantics. No backing claim is made until that policy is independently
   verified for the relevant asset.
6. Consensus, networking, configuration provenance, upgrade governance, and
   operational monitoring have separate specifications and adversarial tests.
7. Security review covers the implementation, dependencies, operational
   deployment, and the relevant privacy model before any transferable value or
   public test network is introduced.

## Review triggers

This threat model must be updated before merging changes that add a concrete
proof system, change the mint-authority model, introduce serialization or
persistence, expose network APIs, add a wallet or chain adapter, or make a
claim about an external asset. A security-relevant change is incomplete until
its affected assumptions, threats, tests, and acceptance criteria are updated.
