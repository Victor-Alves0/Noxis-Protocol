# Noxis Protocol — Documentation Map

This directory contains specifications, architecture decisions, operational
guidance and research artifacts. It is intentionally split by responsibility:
reading one document should answer one question without hiding assumptions in a
large catch-all file.

Start with the [repository README](../README.md) for the current scope and the
commands that verify the workspace. Then use the routes below instead of
reading the directory alphabetically.

## Research front doors

These short guides are intended for new contributors and external reviewers;
they point to the versioned specifications rather than replacing them.

| If you are looking for | Start here |
| --- | --- |
| Current capabilities and non-claims | [Protocol overview](PROTOCOL.md) |
| Security assumptions and reporting | [Threat-model guide](THREAT_MODEL.md) and [SECURITY.md](../SECURITY.md) |
| Cryptographic direction | [Cryptography guide](CRYPTOGRAPHY.md) |
| Private-note roadmap | [Private-notes guide](PRIVATE_NOTES.md) |
| Hybrid post-quantum direction | [PQ hybrid design](PQ_HYBRID_DESIGN.md) |
| Research questions worth answering | [Open questions](OPEN_QUESTIONS.md) |

## Status legend

| Mark | Meaning |
| --- | --- |
| **Current** | Describes an implemented boundary or the current v0.1 protocol surface. It is still research software, not production approval. |
| **Decision** | Records a choice, its alternatives and the conditions needed before relying on it. |
| **Candidate / draft** | A bounded research artifact. It is deliberately not selected, connected to settlement, or a claim of active security. |
| **Evidence** | Test vectors, reference evaluations or reproducibility material for checking a candidate. |

## If you want to understand…

| Question | Read this first | Then follow with |
| --- | --- | --- |
| **What does the protocol mean?** | [Protocol semantics — `PROTOCOL_SPEC_V0_1.md`](PROTOCOL_SPEC_V0_1.md) | [Identity binding](IDENTITY_SPEC_V0_1.md), [validation context](VALIDATION_CONTEXT_SPEC_V0_1.md) and [state history](STATE_CHAIN_SPEC_V0_1.md). |
| **What can go wrong, and what is explicitly not promised?** | [Threat model — `THREAT_MODEL_V0_1.md`](THREAT_MODEL_V0_1.md) | [Cryptography decision](CRYPTOGRAPHY_DECISION_V0_1.md), [crypto service gate](CRYPTO_SERVICE_GATE_V0_1.md) and [economic-security boundaries](ECONOMIC_SECURITY_MODEL_V0_1.md). |
| **How is the code organized?** | [Module architecture — `ARCHITECTURE.md`](ARCHITECTURE.md) | [Ledger internal boundaries](LEDGER_INTERNAL_MODULE_BOUNDARY_V0_1.md) for representation, invariants and mutation. |
| **How does consensus / CometBFT fit in?** | [Consensus decision](CONSENSUS_DECISION_V0_1.md) | [Consensus data specification](CONSENSUS_DATA_SPEC_V0_1.md) and [CometBFT CI / end-to-end boundary](COMETBFT_CI_V0_1.md). |
| **How is data persisted and recovered?** | [Durability specification](DURABILITY_SPEC_V0_1.md) | [State-chain rules](STATE_CHAIN_SPEC_V0_1.md), [checkpoint format](CHECKPOINT_SPEC_V0_1.md), [checkpoint attestation decision](CHECKPOINT_ATTESTATION_DECISION_V0_1.md) and [data-directory lifecycle](DATA_DIRECTORY_SPEC_V0_1.md). |
| **Which bytes may be parsed or persisted?** | [Wire and storage format registry](WIRE_STORAGE_FORMATS_V0_1.md) | The owner specification and codec named in the registry row. CI also checks that every Rust `NX..`/`NOXT` magic has a registry entry. |
| **Can I run something now?** | [Local operational demo](LOCAL_OPERATIONAL_DEMO_V0_1.md) | [Node service boundary](NODE_SERVICE_SPEC_V0_1.md). The demo is local and research-only; it does not start a validator network or provide private transfers. |
| **Can I run the hybrid recipient components?** | [Local hybrid wallet-crypto demo](WALLET_CRYPTO_LOCAL_DEMO_V0_1.md), [local candidate-note receipt](WALLET_PRIVATE_NOTE_RECEIPT_LOCAL_V0_1.md) and [candidate envelope digest](RECIPIENT_ENVELOPE_DIGEST_CANDIDATE_V0_1.md) | The commands demonstrate experimental key generation, strict `NXPA`/`NXRE` decoding, authenticated recipient encryption, hybrid identity signatures, a public-address catalog, a recipient-side `H_NOTE` commitment recheck through an isolated local incoming view key and a candidate digest bound to output slot/commitment/envelope; they are not a wallet or private transfer. |
| **How is a receiving address paired with a note recipient commitment?** | [Local recipient descriptor candidate](RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md) | A locally signed descriptor pairs `NXPA` and `H_ADDR`; the local keyset derives its receiving/nullifier material from one erased root, but no public proof or descriptor protocol exists. |
| **How are recipient keys derived, and where is the view key?** | [Recipient-root derivation candidate](RECIPIENT_ROOT_DERIVATION_CANDIDATE_V0_1.md) | The local HKDF derivation creates an incoming view key that has no nullifier. Its [separate capability document](INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md) records why it cannot yet be exported or persisted. |
| **Can I reject a private packet with swapped envelopes?** | [Candidate packet envelope validation](PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md) | It strictly decodes a local `NXPT` plus its two `NXRE` values and checks their candidate P24 digests against the intent before proof processing; it is not proof, ledger or network validation. |
| **What must happen before a wallet stores secrets?** | [Wallet keystore security gate](WALLET_KEYSTORE_SECURITY_GATE_V0_1.md) | It records the secret-persistence threat model, candidate direction and mandatory design/review gates; no secret keystore exists today. |
| **Can I reproduce the full local NXSM preflight?** | [Private `NXSM` STARK research relation](STARK_NXSM_PREFIX_RESEARCH_V0_1.md) | It explicitly runs 64 local proofs and takes about 32 minutes; its receipt is not a portable absence or transfer proof. |
| **Where is the privacy and post-quantum roadmap?** | [Crypto service gate](CRYPTO_SERVICE_GATE_V0_1.md) — the current fail-closed boundary | Then read the [private-transfer architecture draft](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md), [hybrid cryptography profile draft](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md), [private-transfer AIR candidate](PRIVATE_TRANSFER_AIR_CANDIDATE_V0_1.md), [AIR profile](PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md) and [proof deployment candidate](PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md). |
| **What is already checked for the private-transfer research path?** | [Complete sequential preflight](STARK_PRIVATE_TRANSFER_PREFLIGHT_RESEARCH_V0_1.md) and [local state transition](PRIVATE_STATE_TRANSITION_CANDIDATE_V0_1.md) | One executable local proof run checks `H_INTENT` once, both input ownership relations and both private output-note relations against one candidate statement. A separate transparent local transition derives the post-note root and `NXSM` root from that kind of intent. Neither path is aggregation, a private-transfer proof or privacy activation. Then follow the [local semantic preflight](PRIVATE_TRANSFER_LOCAL_PREFLIGHT_V0_1.md), [intent commitment candidate](PRIVATE_TRANSFER_INTENT_COMMITMENT_CANDIDATE_V0_1.md), [private state snapshot](PRIVATE_STATE_SNAPSHOT_CANDIDATE_V0_1.md), [typed NXSM anchor v2](PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md), [NXSM transition](PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md), its [witness interface](PRIVATE_TRANSFER_WITNESS_CONSTRAINT_INTERFACE_CANDIDATE_V0_1.md) and the [unified public statement](PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md). |
| **Can the STARK preflight use validated packet envelopes?** | [Packet-bound STARK preflight](PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md) | One release test first validates both `NXRE` values against `NXPT` digests, then runs the sequential `H_INTENT`/ownership/output relations using that exact intent. It is still local research, not one transfer proof. |
| **What is the executable proof work?** | [public `H_INTENT` STARK relation](STARK_INTENT_COMMITMENT_RESEARCH_V0_1.md), [private `H_ADDR` STARK relation](STARK_H_ADDR_RESEARCH_V0_1.md), [private `H_NOTE` STARK relation](STARK_H_NOTE_RESEARCH_V0_1.md), [`H_NOTE` asset binding](STARK_H_NOTE_ASSET_BINDING_RESEARCH_V0_1.md), [private ownership-and-depth-32-membership binding](STARK_NOTE_OWNERSHIP_BINDING_RESEARCH_V0_1.md), [private `NXSM` segments and local full-path preflight](STARK_NXSM_PREFIX_RESEARCH_V0_1.md), [anchored ownership preflight](STARK_ANCHORED_OWNERSHIP_PREFLIGHT_RESEARCH_V0_1.md), and the [verifier-profile boundary](STARK_VERIFIER_PROFILE_RESEARCH_V0_1.md) | `H_INTENT` proves only the public candidate statement frame. The new output relation also binds the public asset bytes to each private note preimage. Full-depth ownership and membership are one separate P24 research relation. The `NXSM` experiment can locally sequence 64 private segments to a full candidate root. A test-only proof serialization round trip verifies with a fresh configuration using the same pinned code profile; none of these components is aggregation, portable verification, or a transferable nullifier-absence or transfer proof. |

## Suggested reading paths

### New contributor

1. [Repository README](../README.md)
2. [Protocol semantics](PROTOCOL_SPEC_V0_1.md)
3. [Module architecture](ARCHITECTURE.md)
4. [Threat model](THREAT_MODEL_V0_1.md)
5. [Project plan](PROJECT_PLAN.md)

This establishes the vocabulary, module ownership, security boundaries and
next milestones before diving into implementation details.

### Auditor or technical reviewer

1. [Threat model](THREAT_MODEL_V0_1.md)
2. [Protocol semantics](PROTOCOL_SPEC_V0_1.md)
3. [Validation context](VALIDATION_CONTEXT_SPEC_V0_1.md) and [identity binding](IDENTITY_SPEC_V0_1.md)
4. [State chain](STATE_CHAIN_SPEC_V0_1.md), [durability](DURABILITY_SPEC_V0_1.md) and [checkpoints](CHECKPOINT_SPEC_V0_1.md)
5. [Wire and storage format registry](WIRE_STORAGE_FORMATS_V0_1.md)
6. [Consensus data](CONSENSUS_DATA_SPEC_V0_1.md) and [crypto service gate](CRYPTO_SERVICE_GATE_V0_1.md)
7. [Ledger internal boundaries](LEDGER_INTERNAL_MODULE_BOUNDARY_V0_1.md)

This path moves from assumptions to invariants, then to the code boundaries
where those invariants are enforced and recovered.

### Operator evaluating the current local runtime

1. [Local operational demo](LOCAL_OPERATIONAL_DEMO_V0_1.md)
2. [Node service boundary](NODE_SERVICE_SPEC_V0_1.md)
3. [Data-directory lifecycle](DATA_DIRECTORY_SPEC_V0_1.md)
4. [Durability specification](DURABILITY_SPEC_V0_1.md)
5. [CometBFT CI / end-to-end boundary](COMETBFT_CI_V0_1.md)

Keep the limitations in view: the local demo proves a deterministic,
durable research sequence. It is not a public network deployment guide.

## Private-transfer research trail

The documents below are deliberately kept together because they can otherwise
look like active cryptography when they are not. The current service remains
fail-closed until a selected, implemented and independently reviewed proof
stack exists.

1. [Current fail-closed boundary](CRYPTO_SERVICE_GATE_V0_1.md)
2. [Architecture and scope](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md)
3. [AIR candidate](PRIVATE_TRANSFER_AIR_CANDIDATE_V0_1.md)
4. [Intent commitment candidate](PRIVATE_TRANSFER_INTENT_COMMITMENT_CANDIDATE_V0_1.md)
5. [Local semantic preflight](PRIVATE_TRANSFER_LOCAL_PREFLIGHT_V0_1.md)
6. [State snapshot and anchor](PRIVATE_STATE_SNAPSHOT_CANDIDATE_V0_1.md) / [local state transition](PRIVATE_STATE_TRANSITION_CANDIDATE_V0_1.md) / [v1 anchor details](PRIVATE_STATE_ANCHOR_CANDIDATE_V0_1.md) / [typed NXSM v2 candidate](PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md) / [NXSM transition](PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md) / [witness and constraint interface](PRIVATE_TRANSFER_WITNESS_CONSTRAINT_INTERFACE_CANDIDATE_V0_1.md) / [unified public statement](PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md)
7. [Complete sequential STARK preflight](STARK_PRIVATE_TRANSFER_PREFLIGHT_RESEARCH_V0_1.md), [executable output-note preflight](STARK_OUTPUT_NOTES_PREFLIGHT_RESEARCH_V0_1.md) and [anchored ownership preflight](STARK_ANCHORED_OWNERSHIP_PREFLIGHT_RESEARCH_V0_1.md)
8. [Hybrid identity and transport profile](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md)
9. [AIR constraint profile](PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md)
10. [Deployment prerequisites](PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md)

## Parameter candidates and reproducibility evidence

These documents support review of the unselected tree/hash candidates. They do
not make a candidate a protocol parameter.

| Subject | Candidate or framing | Evidence / reference |
| --- | --- | --- |
| Tree parameter framing | [Tree parameter framing](TREE_PARAMETER_FRAMING_V0_1.md), [P24 manifest](POSEIDON2_P24_CANDIDATE_MANIFEST_V0_1.md), [tree construction](POSEIDON2_TREE_CONSTRUCTION_CANDIDATE_V0_1.md) | [P24 reference evaluation](POSEIDON2_P24_REFERENCE_EVALUATION_V0_1.md), [BabyBear16 reference evaluation](POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md) |
| Tree vectors | [Corpus framing](TREE_VECTOR_CORPUS_FRAMING_V0_1.md), [P24 v2 corpus](TREE_VECTOR_CORPUS_P24_V2.md) | [Generation blocker](TREE_VECTOR_GENERATION_BLOCKER_V0_1.md) |
| Private-note domains | [Note-opening boundary](NOTE_OPENING_BOUNDARY_V0_1.md), [P24 note-domain candidate](POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md) | [Note-domain corpus](NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md), [reference evaluation](POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md) |
| Nullifier sparse tree | [Manifest candidate](NULLIFIER_SPARSE_MANIFEST_CANDIDATE_V0_1.md), [mutable state candidate](NULLIFIER_SPARSE_MUTABLE_REFERENCE_CANDIDATE_V0_1.md) | [Reference candidate](NULLIFIER_SPARSE_REFERENCE_CANDIDATE_V0_1.md), [external NXSV KATs](NULLIFIER_SPARSE_EXTERNAL_KATS_V0_1.md) |
| Intent commitment | [Manifest candidate](INTENT_COMMITMENT_MANIFEST_CANDIDATE_V0_1.md), [vector corpus candidate](INTENT_VECTOR_CORPUS_CANDIDATE_V0_1.md) | [External KATs](EXTERNAL_INTENT_COMMITMENT_KATS_V0_1.md) |

## Keeping this map useful

When adding a document, give it a narrowly stated question and link it from
the relevant route above. If it changes a security guarantee or readiness
claim, also update the repository README and [project plan](PROJECT_PLAN.md).
That keeps the entry point accurate without turning this map into a duplicate
of every specification.
