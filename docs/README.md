# Noxis Protocol — Documentation Map

This directory contains specifications, architecture decisions, operational
guidance and research artifacts. It is intentionally split by responsibility:
reading one document should answer one question without hiding assumptions in a
large catch-all file.

Start with the [repository README](../README.md) for the current scope and the
commands that verify the workspace. Then use the routes below instead of
reading the directory alphabetically.

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
| **Can I run something now?** | [Local operational demo](LOCAL_OPERATIONAL_DEMO_V0_1.md) | [Node service boundary](NODE_SERVICE_SPEC_V0_1.md). The demo is local and research-only; it does not start a validator network or provide private transfers. |
| **Where is the privacy and post-quantum roadmap?** | [Crypto service gate](CRYPTO_SERVICE_GATE_V0_1.md) — the current fail-closed boundary | Then read the [private-transfer architecture draft](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md), [hybrid cryptography profile draft](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md), [private-transfer AIR candidate](PRIVATE_TRANSFER_AIR_CANDIDATE_V0_1.md) and [proof deployment candidate](PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md). |
| **What is already checked for the private-transfer research path?** | [Local preflight](PRIVATE_TRANSFER_LOCAL_PREFLIGHT_V0_1.md) | [Intent commitment candidate](PRIVATE_TRANSFER_INTENT_COMMITMENT_CANDIDATE_V0_1.md), [private state snapshot](PRIVATE_STATE_SNAPSHOT_CANDIDATE_V0_1.md) and [private state anchor](PRIVATE_STATE_ANCHOR_CANDIDATE_V0_1.md). These are candidates, not privacy activation. |

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
5. [Consensus data](CONSENSUS_DATA_SPEC_V0_1.md) and [crypto service gate](CRYPTO_SERVICE_GATE_V0_1.md)
6. [Ledger internal boundaries](LEDGER_INTERNAL_MODULE_BOUNDARY_V0_1.md)

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
6. [State snapshot and anchor](PRIVATE_STATE_SNAPSHOT_CANDIDATE_V0_1.md) / [anchor details](PRIVATE_STATE_ANCHOR_CANDIDATE_V0_1.md)
7. [Hybrid identity and transport profile](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md)
8. [Deployment prerequisites](PRIVATE_TRANSFER_PROOF_DEPLOYMENT_CANDIDATE_V0_1.md)

## Parameter candidates and reproducibility evidence

These documents support review of the unselected tree/hash candidates. They do
not make a candidate a protocol parameter.

| Subject | Candidate or framing | Evidence / reference |
| --- | --- | --- |
| Tree parameter framing | [Tree parameter framing](TREE_PARAMETER_FRAMING_V0_1.md), [P24 manifest](POSEIDON2_P24_CANDIDATE_MANIFEST_V0_1.md), [tree construction](POSEIDON2_TREE_CONSTRUCTION_CANDIDATE_V0_1.md) | [P24 reference evaluation](POSEIDON2_P24_REFERENCE_EVALUATION_V0_1.md), [BabyBear16 reference evaluation](POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md) |
| Tree vectors | [Corpus framing](TREE_VECTOR_CORPUS_FRAMING_V0_1.md), [P24 v2 corpus](TREE_VECTOR_CORPUS_P24_V2.md) | [Generation blocker](TREE_VECTOR_GENERATION_BLOCKER_V0_1.md) |
| Private-note domains | [Note-opening boundary](NOTE_OPENING_BOUNDARY_V0_1.md), [P24 note-domain candidate](POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md) | [Note-domain corpus](NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md), [reference evaluation](POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md) |
| Nullifier sparse tree | [Manifest candidate](NULLIFIER_SPARSE_MANIFEST_CANDIDATE_V0_1.md), [mutable state candidate](NULLIFIER_SPARSE_MUTABLE_REFERENCE_CANDIDATE_V0_1.md) | [Reference candidate](NULLIFIER_SPARSE_REFERENCE_CANDIDATE_V0_1.md) |
| Intent commitment | [Manifest candidate](INTENT_COMMITMENT_MANIFEST_CANDIDATE_V0_1.md), [vector corpus candidate](INTENT_VECTOR_CORPUS_CANDIDATE_V0_1.md) | [External KATs](EXTERNAL_INTENT_COMMITMENT_KATS_V0_1.md) |

## Keeping this map useful

When adding a document, give it a narrowly stated question and link it from
the relevant route above. If it changes a security guarantee or readiness
claim, also update the repository README and [project plan](PROJECT_PLAN.md).
That keeps the entry point accurate without turning this map into a duplicate
of every specification.
