//! Local application API for one Noxis ledger process.
//!
//! This crate deliberately has no TCP, HTTP, P2P, wallet, custody, or consensus
//! adapter. It provides typed operations that a future authenticated local
//! transport can call without reimplementing protocol rules.

use std::path::{Path, PathBuf};

use noxis_codec::{CodecError, decode_transaction};
use noxis_config::{ConfigError, GenesisConfig, NodeConfig};
use noxis_crypto::{CryptoSuite, ProofVerifier};
use noxis_ledger::{LedgerError, MintPolicy};
use noxis_merkle::{InclusionProof, MerkleRoot};
use noxis_record_chain::RecordHash;
use noxis_runtime::{DataDirectory, NodeRuntime, RuntimeError};
use noxis_storage::{PersistentLedger, PersistentLedgerError, checkpoint_store::CheckpointReceipt};
use noxis_types::{Commitment, StateId, TransactionId, TransactionIntentId};

pub struct LocalNode<V, P> {
    ledger: PersistentLedger,
    verifier: V,
    mint_policy: P,
}

/// Couples a local node to the data-directory lock that protects its lifetime.
pub struct LocalNodeRuntime<V, P> {
    runtime: NodeRuntime,
    node: LocalNode<V, P>,
}

impl<V: ProofVerifier, P: MintPolicy> LocalNode<V, P> {
    /// Opens one local, durable ledger using an explicit validated configuration.
    pub fn open(config: &NodeConfig, verifier: V, mint_policy: P) -> Result<Self, NodeOpenError> {
        Self::open_at(
            config.transaction_log_path(),
            config.genesis(),
            verifier,
            mint_policy,
        )
    }

    /// Opens an embedded node at an explicit path.
    ///
    /// The caller is responsible for writer exclusion. Applications should use
    /// [`LocalNodeRuntime::open`] when they need the data-directory lock and
    /// its runtime-owned record-log path.
    pub fn open_at(
        record_log_path: impl AsRef<Path>,
        genesis: &GenesisConfig,
        verifier: V,
        mint_policy: P,
    ) -> Result<Self, NodeOpenError> {
        let initial_state = genesis
            .build_ledger_state()
            .map_err(NodeOpenError::Config)?;
        let anchor = genesis.chain_anchor().map_err(NodeOpenError::Config)?;
        let ledger = PersistentLedger::open(
            record_log_path,
            initial_state,
            anchor,
            genesis.validation_context(),
            &verifier,
            &mint_policy,
        )
        .map_err(NodeOpenError::Persistence)?;
        Ok(Self {
            ledger,
            verifier,
            mint_policy,
        })
    }

    /// Opens an embedded node and verifies checkpoints from an explicit
    /// operator-controlled directory. It still replays the complete record log.
    pub fn open_at_with_checkpoints(
        record_log_path: impl AsRef<Path>,
        checkpoint_directory: impl Into<PathBuf>,
        genesis: &GenesisConfig,
        verifier: V,
        mint_policy: P,
    ) -> Result<Self, NodeOpenError> {
        let initial_state = genesis
            .build_ledger_state()
            .map_err(NodeOpenError::Config)?;
        let anchor = genesis.chain_anchor().map_err(NodeOpenError::Config)?;
        let ledger = PersistentLedger::open_with_checkpoints(
            record_log_path,
            checkpoint_directory,
            initial_state,
            anchor,
            genesis.validation_context(),
            &verifier,
            &mint_policy,
        )
        .map_err(NodeOpenError::Persistence)?;
        Ok(Self {
            ledger,
            verifier,
            mint_policy,
        })
    }

    /// Publishes a verified snapshot of the current durable state.
    pub fn publish_checkpoint(
        &mut self,
        checkpoint_directory: impl Into<PathBuf>,
    ) -> Result<CheckpointReceipt, PersistentLedgerError> {
        self.ledger.publish_checkpoint(checkpoint_directory)
    }

    /// Submits one canonical transaction for local validation and durable storage.
    ///
    /// A successful result means only that this local node made the transition
    /// durable. It is not network confirmation or consensus finality.
    pub fn submit_canonical(&mut self, bytes: &[u8]) -> SubmissionOutcome {
        let transaction = match decode_transaction(bytes) {
            Ok(transaction) => transaction,
            Err(error) => return SubmissionOutcome::Rejected(SubmissionRejection::Codec(error)),
        };
        match self
            .ledger
            .apply(&transaction, &self.verifier, &self.mint_policy)
        {
            Ok(commit) => SubmissionOutcome::LocallyDurable(SubmissionReceipt {
                genesis_id: self.ledger.status().genesis_id,
                validation_context_id: self.ledger.status().validation_context_id,
                legacy_transaction_id: transaction.id,
                transaction_intent_id: commit.transaction_intent_id,
                record_hash: commit.record_hash,
                sequence: commit.sequence,
                log_offset: commit.log_offset,
                state_root: self.ledger.state().merkle_root(),
                state_id: commit.state_id,
            }),
            Err(PersistentLedgerError::Ledger(error)) => {
                SubmissionOutcome::Rejected(SubmissionRejection::Ledger(error))
            }
            Err(PersistentLedgerError::Codec(error)) => {
                SubmissionOutcome::Rejected(SubmissionRejection::Codec(error))
            }
            Err(PersistentLedgerError::Storage(error)) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(error.to_string()))
            }
            Err(PersistentLedgerError::RecordLog(error)) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(error.to_string()))
            }
            Err(PersistentLedgerError::RecordChain(error)) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(error.to_string()))
            }
            Err(PersistentLedgerError::Checkpoint(error)) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(error.to_string()))
            }
            Err(PersistentLedgerError::CheckpointStore(error)) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(error.to_string()))
            }
            Err(PersistentLedgerError::TransactionCryptoSuiteMismatch { expected, actual }) => {
                SubmissionOutcome::Rejected(SubmissionRejection::CryptoSuiteMismatch {
                    expected,
                    actual,
                })
            }
            Err(PersistentLedgerError::CheckpointAtGenesis) => SubmissionOutcome::Unavailable(
                NodeUnavailable::Storage("cannot checkpoint the genesis state".to_owned()),
            ),
            Err(PersistentLedgerError::AmbiguousCheckpoints { .. }) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(
                    "ambiguous local checkpoint artifacts".to_owned(),
                ))
            }
            Err(PersistentLedgerError::ResultingStateIdMismatch { .. }) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::Storage(
                    "local persistence state identity mismatch".to_owned(),
                ))
            }
            Err(
                PersistentLedgerError::InvalidChainAnchor { .. }
                | PersistentLedgerError::InvalidChainAnchorContext { .. }
                | PersistentLedgerError::ValidationContextMismatch { .. }
                | PersistentLedgerError::InvalidValidationContext(_),
            ) => SubmissionOutcome::Unavailable(NodeUnavailable::Storage(
                "local persistence validation context mismatch".to_owned(),
            )),
            Err(PersistentLedgerError::WriteUnavailable) => {
                SubmissionOutcome::Unavailable(NodeUnavailable::RecoveryRequired)
            }
        }
    }

    /// Returns public local-state information without mutating the ledger.
    pub fn status(&self) -> LocalNodeStatus {
        LocalNodeStatus {
            genesis_id: self.ledger.status().genesis_id,
            validation_context_id: self.ledger.status().validation_context_id,
            state_root: self.ledger.state().merkle_root(),
            state_id: self.ledger.status().state_id,
            sequence: self.ledger.status().sequence,
            recovered_checkpoint_sequence: self.ledger.status().recovered_checkpoint_sequence,
            commitment_count: self.ledger.state().commitment_count(),
        }
    }

    /// Generates a public inclusion proof from the node's current local state.
    pub fn inclusion_proof(&self, leaf_index: u32) -> Result<InclusionProofResponse, LedgerError> {
        let proof = self.ledger.state().prove_commitment(leaf_index)?;
        Ok(InclusionProofResponse {
            genesis_id: self.ledger.status().genesis_id,
            validation_context_id: self.ledger.status().validation_context_id,
            state_root: self.ledger.state().merkle_root(),
            state_id: self.ledger.status().state_id,
            sequence: self.ledger.status().sequence,
            leaf_index: proof.leaf_index(),
            proof,
        })
    }
}

impl<V: ProofVerifier, P: MintPolicy> LocalNodeRuntime<V, P> {
    /// Initializes or validates the immutable directory identity before opening the ledger.
    pub fn open(
        directory: DataDirectory,
        config: &NodeConfig,
        verifier: V,
        mint_policy: P,
    ) -> Result<Self, LocalNodeRuntimeError> {
        let runtime = NodeRuntime::open_or_initialize(directory, config.genesis().clone())
            .map_err(LocalNodeRuntimeError::Runtime)?;
        let node = LocalNode::open_at_with_checkpoints(
            runtime.ledger_path(),
            runtime.checkpoints_path(),
            runtime.manifest().genesis(),
            verifier,
            mint_policy,
        )
        .map_err(LocalNodeRuntimeError::Node)?;
        Ok(Self { runtime, node })
    }

    pub fn node(&self) -> &LocalNode<V, P> {
        &self.node
    }
    pub fn node_mut(&mut self) -> &mut LocalNode<V, P> {
        &mut self.node
    }
    pub fn runtime(&self) -> &NodeRuntime {
        &self.runtime
    }

    /// Publishes a checkpoint only in the runtime-owned protected directory.
    pub fn publish_checkpoint(&mut self) -> Result<CheckpointReceipt, PersistentLedgerError> {
        self.node
            .publish_checkpoint(self.runtime.checkpoints_path())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalNodeStatus {
    /// Genesis/deployment identity that bounds this local history.
    pub genesis_id: noxis_types::GenesisId,
    /// Public identity of the verifier and mint policy required for this state.
    pub validation_context_id: noxis_types::ValidationContextId,
    pub state_root: MerkleRoot,
    /// Local deterministic state identity; not distributed consensus finality.
    pub state_id: StateId,
    /// Position of this state in the local durable history; genesis is zero.
    pub sequence: u64,
    /// Most recent checkpoint independently compared during strict replay.
    pub recovered_checkpoint_sequence: Option<u64>,
    pub commitment_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionReceipt {
    /// Genesis/deployment identity that bounds the resulting state.
    pub genesis_id: noxis_types::GenesisId,
    /// Public identity of the verifier and mint policy required for this state.
    pub validation_context_id: noxis_types::ValidationContextId,
    /// Legacy envelope identifier, retained for compatibility only.
    pub legacy_transaction_id: TransactionId,
    /// Stable identity of the accepted transaction intent.
    pub transaction_intent_id: TransactionIntentId,
    /// Hash committing to the persisted state-transition record.
    pub record_hash: RecordHash,
    /// Position of this transition in the local state chain.
    pub sequence: u64,
    pub log_offset: u64,
    pub state_root: MerkleRoot,
    pub state_id: StateId,
}

#[derive(Debug)]
pub enum SubmissionOutcome {
    LocallyDurable(SubmissionReceipt),
    Rejected(SubmissionRejection),
    Unavailable(NodeUnavailable),
}

#[derive(Debug)]
pub enum SubmissionRejection {
    Codec(CodecError),
    Ledger(LedgerError),
    CryptoSuiteMismatch {
        expected: CryptoSuite,
        actual: CryptoSuite,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeUnavailable {
    Storage(String),
    RecoveryRequired,
}

#[derive(Debug)]
pub enum NodeOpenError {
    Config(ConfigError),
    Persistence(PersistentLedgerError),
}

#[derive(Debug)]
pub enum LocalNodeRuntimeError {
    Runtime(RuntimeError),
    Node(NodeOpenError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InclusionProofResponse {
    /// Genesis/deployment identity that bounds this snapshot.
    pub genesis_id: noxis_types::GenesisId,
    /// Public identity of the verifier and mint policy required for this snapshot.
    pub validation_context_id: noxis_types::ValidationContextId,
    pub state_root: MerkleRoot,
    /// Local state identity of the snapshot that generated this proof.
    pub state_id: StateId,
    /// Local chain sequence of the snapshot that generated this proof.
    pub sequence: u64,
    pub leaf_index: u32,
    pub proof: InclusionProof,
}

/// Verifies a response created by [`LocalNode::inclusion_proof`].
pub fn verify_inclusion(
    response: &InclusionProofResponse,
    commitment: Commitment,
) -> Result<bool, LedgerError> {
    noxis_merkle::MerkleTree::verify(response.state_root, commitment, &response.proof)
        .map_err(LedgerError::Merkle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_codec::encode_transaction;
    use noxis_config::GenesisConfig;
    use noxis_consensus::{
        CometBftNetworkIdentity, ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
    };
    use noxis_crypto::{
        CryptoSuite, Proof, TransferStatement, ValidationContext, VerificationError,
    };
    use noxis_ledger::{DenyAllMints, Operation, Transaction, Transfer};
    use noxis_types::{
        AssetDefinition, AssetId, AssetKind, Commitment, MintPolicyId, Nullifier, ProofVerifierId,
        TransactionId, ValidatorId,
    };
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct TemporaryDirectory(PathBuf);
    impl TemporaryDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "noxis-node-test-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct TestVerifier;
    impl ProofVerifier for TestVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            _: &TransferStatement,
            _: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }
    fn config(path: PathBuf) -> NodeConfig {
        let asset =
            AssetDefinition::new(AssetId::new([2; 32]), "USDX", AssetKind::Synthetic).unwrap();
        NodeConfig::new(
            GenesisConfig::new_with_comet_bft_identity(
                4,
                vec![asset],
                ValidationContext::new(
                    CryptoSuite::RESEARCH_V1,
                    ProofVerifierId::new([1; 32]),
                    MintPolicyId::new([0; 32]),
                ),
                ConsensusConfig::new(
                    1,
                    100,
                    1024,
                    0,
                    ValidatorSet::new(vec![
                        Validator::new(
                            ValidatorId::new([1; 32]),
                            1,
                            ValidatorVerificationKey::new(1, vec![1; 32]).unwrap(),
                        )
                        .unwrap(),
                    ])
                    .unwrap(),
                )
                .unwrap(),
                CometBftNetworkIdentity::new("noxis-node-test", 1, "cometbft-0.38", [7; 32])
                    .unwrap(),
            )
            .unwrap(),
            path,
        )
        .unwrap()
    }
    fn transaction() -> Transaction {
        Transaction {
            id: TransactionId::new([1; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: AssetId::new([2; 32]),
                input_nullifiers: vec![Nullifier::new([3; 32])],
                output_commitments: vec![Commitment::new([4; 32])],
                proof: Proof {
                    suite_version: 1,
                    bytes: vec![5],
                },
            }),
        }
    }
    #[test]
    fn node_recovers_a_locally_durable_transition() {
        let directory = TemporaryDirectory::new();
        let config = config(directory.0.join("ledger.nxlg"));
        let bytes = encode_transaction(&transaction()).unwrap();
        let root;
        {
            let mut node = LocalNode::open(&config, TestVerifier, DenyAllMints).unwrap();
            let SubmissionOutcome::LocallyDurable(receipt) = node.submit_canonical(&bytes) else {
                panic!("expected local durability");
            };
            root = receipt.state_root;
            assert_eq!(node.status().commitment_count, 1);
            assert!(
                verify_inclusion(&node.inclusion_proof(0).unwrap(), Commitment::new([4; 32]))
                    .unwrap()
            );
        }
        let mut recovered = LocalNode::open(&config, TestVerifier, DenyAllMints).unwrap();
        assert_eq!(recovered.status().state_root, root);
        assert!(matches!(
            recovered.submit_canonical(&bytes),
            SubmissionOutcome::Rejected(_)
        ));
    }

    #[test]
    fn runtime_owns_the_record_log_path_instead_of_the_embedded_path() {
        let workspace = TemporaryDirectory::new();
        let data_directory = DataDirectory::new(workspace.0.join("node-data")).unwrap();
        let external_path = workspace.0.join("must-not-be-used.nxrf");
        let config = config(external_path.clone());
        let bytes = encode_transaction(&transaction()).unwrap();
        let expected_genesis_id = config.genesis().genesis_id();

        {
            let mut runtime =
                LocalNodeRuntime::open(data_directory.clone(), &config, TestVerifier, DenyAllMints)
                    .unwrap();
            assert!(data_directory.ledger_path().is_file());
            assert!(!external_path.exists());
            let SubmissionOutcome::LocallyDurable(receipt) =
                runtime.node_mut().submit_canonical(&bytes)
            else {
                panic!("expected local durability");
            };
            assert_eq!(receipt.genesis_id, expected_genesis_id);
            assert_eq!(receipt.sequence, 1);
            assert_eq!(runtime.node().status().genesis_id, expected_genesis_id);
            let published = runtime.publish_checkpoint().unwrap();
            assert_eq!(published.checkpoint.sequence(), 1);
            assert!(
                published
                    .path
                    .starts_with(data_directory.checkpoints_path())
            );
        }

        let runtime =
            LocalNodeRuntime::open(data_directory, &config, TestVerifier, DenyAllMints).unwrap();
        assert_eq!(runtime.node().status().sequence, 1);
        assert_eq!(
            runtime.node().status().recovered_checkpoint_sequence,
            Some(1)
        );
        assert!(!external_path.exists());
    }
}
