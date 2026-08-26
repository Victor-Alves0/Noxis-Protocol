//! Authoritative, crash-detecting persistence for complete executed blocks.
//!
//! `PersistentExecution` deliberately does not use [`crate::PersistentLedger`]
//! as its source of truth: that legacy coordinator makes one NXRC transition
//! durable at a time. Consensus requires all records in a decided block to be
//! accepted together, including the zero-record case. The `NXCB` journal makes
//! one whole block the only durable unit and recovery re-executes every frame.

use std::{fmt, path::Path};

use noxis_consensus::{CometBftGenesis, CometBftNetworkIdentity};
use noxis_execution::{
    BlockProposal, CandidateExecutionState, CommittedExecutionState, ExecutedBlock,
    ExecutionContext, ExecutionError, ExecutionReceipt, execute_block, simulate_transaction,
};
use noxis_ledger::LedgerState;
use noxis_types::{AppHash, BlockId, StateId};

use crate::block_journal::{BlockJournal, BlockJournalError, BlockJournalReplayError, StoredBlock};

/// A durable fact established by one complete `NXCB` append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableBlockReceipt {
    /// Noxis execution height made durable.
    pub height: u64,
    /// Canonical identifier of the complete stored block.
    pub block_id: BlockId,
    /// Application commitment after this complete block.
    pub app_hash: AppHash,
    /// Resulting public ledger state identity.
    pub state_id: StateId,
    /// Physical journal position, for diagnostics only.
    pub log_offset: u64,
}

/// A single-writer coordinator for complete, replay-verified execution blocks.
///
/// A successful [`Self::commit`] has appended and synchronized exactly one
/// `NXCB` frame. After an I/O error the coordinator refuses every further
/// write until it is reopened and replayed; this avoids continuing from an
/// ambiguous physical-write result.
pub struct PersistentExecution {
    context: ExecutionContext,
    journal: BlockJournal,
    committed: CommittedExecutionState,
    app_hash: Option<AppHash>,
    tip_offset: Option<u64>,
    writes_available: bool,
}

impl PersistentExecution {
    /// Opens an authoritative block journal and reconstructs its exact tip.
    ///
    /// A final incomplete frame is removed only after every preceding complete
    /// frame has been decoded and re-executed successfully. Any corruption or
    /// semantic mismatch in a complete frame fails closed.
    pub fn open(
        path: impl AsRef<Path>,
        genesis_state: LedgerState,
        context: ExecutionContext,
    ) -> Result<Self, PersistentExecutionError> {
        let mut committed = CommittedExecutionState::genesis(genesis_state, context.chain_anchor())
            .map_err(PersistentExecutionError::Execution)?;
        let mut journal =
            BlockJournal::open_for_recovery(path).map_err(PersistentExecutionError::Journal)?;
        let mut app_hash = None;
        let mut tip_offset = None;
        let tail = match journal.replay_recoverable_tail(|stored| {
            let executed = reexecute_stored(&context, &committed, &stored)?;
            app_hash = Some(stored.app_hash);
            tip_offset = Some(stored.offset);
            committed = executed.into_committed_state();
            Ok::<(), PersistentExecutionError>(())
        }) {
            Ok(tail) => tail,
            Err(BlockJournalReplayError::Journal(error)) => {
                return Err(PersistentExecutionError::Journal(error));
            }
            Err(BlockJournalReplayError::Visitor(error)) => return Err(error),
        };
        if let Some(tail) = tail {
            journal
                .truncate_verified_incomplete_tail(tail)
                .map_err(PersistentExecutionError::Journal)?;
        }
        Ok(Self {
            context,
            journal,
            committed,
            app_hash,
            tip_offset,
            writes_available: true,
        })
    }

    /// Returns the fully re-executed durable tip.
    pub fn committed_state(&self) -> &CommittedExecutionState {
        &self.committed
    }

    /// Application commitment at the durable tip, if any block exists.
    pub const fn app_hash(&self) -> Option<AppHash> {
        self.app_hash
    }

    /// Returns the authoritative journal path.
    pub fn journal_path(&self) -> &Path {
        self.journal.path()
    }

    /// Genesis-bound engine identity used to validate every stored decision.
    pub fn comet_bft_identity(&self) -> &CometBftNetworkIdentity {
        self.context.comet_bft_identity()
    }

    /// Complete CometBFT genesis mapping used to validate durable decisions.
    pub fn comet_bft_genesis(&self) -> &CometBftGenesis {
        self.context.comet_bft_genesis()
    }

    /// Maximum records accepted in a single deterministic execution block.
    pub fn maximum_block_records(&self) -> u32 {
        self.context.consensus_config().maximum_block_records()
    }

    /// Maximum canonical transaction bytes accepted in one execution block.
    pub fn maximum_block_transaction_bytes(&self) -> u32 {
        self.context
            .consensus_config()
            .maximum_block_transaction_bytes()
    }

    /// Executes a proposal against the current durable tip without writing it.
    ///
    /// Call [`Self::commit`] only after the consensus engine has decided this
    /// exact output. Keeping execution and durability separate mirrors the
    /// proposal/finalize/commit boundary required by BFT engines.
    pub fn execute(
        &self,
        proposal: BlockProposal<'_>,
    ) -> Result<ExecutedBlock, PersistentExecutionError> {
        execute_block(&self.context, &self.committed, proposal)
            .map_err(PersistentExecutionError::Execution)
    }

    /// Starts a discardable transaction-validation overlay at the durable tip.
    ///
    /// The returned value is suitable only for mempool admission or proposal
    /// selection. It has no authority to alter the durable chain.
    pub fn candidate_execution_state(&self) -> CandidateExecutionState {
        CandidateExecutionState::from_committed(&self.committed)
    }

    /// Validates one transaction against a discardable candidate overlay.
    ///
    /// This is intentionally side-effect free with respect to the durable
    /// journal and committed execution state.
    pub fn simulate_transaction(
        &self,
        candidate: &mut CandidateExecutionState,
        transaction: &[u8],
    ) -> Result<ExecutionReceipt, PersistentExecutionError> {
        simulate_transaction(&self.context, candidate, transaction)
            .map_err(PersistentExecutionError::Execution)
    }

    /// Durably commits one complete candidate block or detects an idempotent retry.
    ///
    /// The candidate is re-executed against the current durable tip before any
    /// I/O. Therefore an output built for another parent, height, configuration
    /// or transaction order cannot be appended merely because it has valid
    /// individual records.
    pub fn commit(
        &mut self,
        block: &ExecutedBlock,
    ) -> Result<DurableBlockReceipt, PersistentExecutionError> {
        if !self.writes_available {
            return Err(PersistentExecutionError::WriteUnavailable);
        }
        if block.header().height() == self.committed.height() {
            return self.idempotent_receipt(block);
        }
        let expected_height = self
            .committed
            .height()
            .checked_add(1)
            .ok_or(PersistentExecutionError::HeightOverflow)?;
        if block.header().height() != expected_height {
            return Err(PersistentExecutionError::UnexpectedCommitHeight {
                expected: expected_height,
                actual: block.header().height(),
            });
        }
        let stored = StoredBlock::new(
            block.header().clone(),
            block.app_hash(),
            block.comet_decision(),
            block.records().to_vec(),
        )
        .map_err(PersistentExecutionError::Journal)?;
        let executed = reexecute_stored(&self.context, &self.committed, &stored)?;
        let offset = match self.journal.append_block(&stored) {
            Ok(offset) => offset,
            Err(error) => {
                self.writes_available = false;
                return Err(PersistentExecutionError::Journal(error));
            }
        };
        let receipt = DurableBlockReceipt {
            height: executed.header().height(),
            block_id: executed.header().id(),
            app_hash: executed.app_hash(),
            state_id: executed.header().resulting_state_id(),
            log_offset: offset,
        };
        self.app_hash = Some(receipt.app_hash);
        self.tip_offset = Some(offset);
        self.committed = executed.into_committed_state();
        Ok(receipt)
    }

    fn idempotent_receipt(
        &self,
        block: &ExecutedBlock,
    ) -> Result<DurableBlockReceipt, PersistentExecutionError> {
        if self.committed.height() > 0
            && self.committed.block_id() == Some(block.header().id())
            && self.app_hash == Some(block.app_hash())
        {
            return Ok(DurableBlockReceipt {
                height: self.committed.height(),
                block_id: block.header().id(),
                app_hash: block.app_hash(),
                state_id: self.committed.record_chain().current_state_id(),
                log_offset: self
                    .tip_offset
                    .expect("non-genesis durable tip has an offset"),
            });
        }
        Err(PersistentExecutionError::ConflictingCommitAtHeight {
            height: self.committed.height(),
        })
    }
}

fn reexecute_stored(
    context: &ExecutionContext,
    committed: &CommittedExecutionState,
    stored: &StoredBlock,
) -> Result<ExecutedBlock, PersistentExecutionError> {
    let transactions: Vec<Vec<u8>> = stored
        .records
        .iter()
        .map(|record| record.transaction_bytes().to_vec())
        .collect();
    let executed = execute_block(
        context,
        committed,
        BlockProposal {
            height: stored.header.height(),
            comet_decision: stored.comet_decision,
            transactions: &transactions,
        },
    )
    .map_err(PersistentExecutionError::Execution)?;
    if executed.header() != &stored.header
        || executed.comet_decision() != stored.comet_decision
        || executed.records() != stored.records.as_slice()
        || executed.app_hash() != stored.app_hash
    {
        return Err(PersistentExecutionError::ReplayMismatch {
            height: stored.header.height(),
        });
    }
    Ok(executed)
}

/// Reasons a consensus block journal cannot be opened or committed safely.
#[derive(Debug)]
pub enum PersistentExecutionError {
    Journal(BlockJournalError),
    Execution(ExecutionError),
    HeightOverflow,
    UnexpectedCommitHeight { expected: u64, actual: u64 },
    ConflictingCommitAtHeight { height: u64 },
    ReplayMismatch { height: u64 },
    WriteUnavailable,
}

impl fmt::Display for PersistentExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "durable block journal error: {error}"),
            Self::Execution(error) => write!(formatter, "block execution error: {error}"),
            Self::HeightOverflow => formatter.write_str("execution height overflows u64"),
            Self::UnexpectedCommitHeight { expected, actual } => write!(
                formatter,
                "expected durable block height {expected}, received {actual}"
            ),
            Self::ConflictingCommitAtHeight { height } => {
                write!(
                    formatter,
                    "a different block is already durable at height {height}"
                )
            }
            Self::ReplayMismatch { height } => {
                write!(
                    formatter,
                    "stored block at height {height} does not match deterministic replay"
                )
            }
            Self::WriteUnavailable => formatter.write_str(
                "writes are unavailable after an uncertain block append; reopen and replay first",
            ),
        }
    }
}

impl std::error::Error for PersistentExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::HeightOverflow
            | Self::UnexpectedCommitHeight { .. }
            | Self::ConflictingCommitAtHeight { .. }
            | Self::ReplayMismatch { .. }
            | Self::WriteUnavailable => None,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use noxis_codec::encode_transaction;
    use noxis_consensus::{
        CometBftDecision, CometBftGenesis, CometBftNetworkIdentity, ConsensusAnchor,
        ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
    };
    use noxis_crypto::{
        CryptoSuite, Proof, ProofVerifier, TransferStatement, ValidationContext, VerificationError,
    };
    use noxis_ledger::{DenyAllMints, LedgerState, MintPolicy, Operation, Transaction, Transfer};
    use noxis_types::{
        AssetDefinition, AssetId, AssetKind, ChainAnchor, Commitment, GenesisId, Nullifier,
        ProofVerifierId, TransactionId, ValidatorId,
    };

    use super::*;

    const ASSET: AssetId = AssetId::new([1; 32]);
    const GENESIS_ID: GenesisId = GenesisId::new([2; 32]);

    static TEMP_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    static ACCEPTING_VERIFIER: AcceptingVerifier = AcceptingVerifier;
    static DENY_ALL_MINTS: DenyAllMints = DenyAllMints;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "noxis-persistent-execution-test-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal_path(&self) -> PathBuf {
            self.0.join("blocks.nxcb")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct AcceptingVerifier;

    impl ProofVerifier for AcceptingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([3; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    fn fixture() -> (
        ChainAnchor,
        ValidationContext,
        ConsensusAnchor,
        ConsensusConfig,
        LedgerState,
    ) {
        let mut ledger = LedgerState::new(4).unwrap();
        ledger
            .register_asset(AssetDefinition::new(ASSET, "USDX", AssetKind::Synthetic).unwrap())
            .unwrap();
        let validation_context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ACCEPTING_VERIFIER.proof_verifier_id(),
            DENY_ALL_MINTS.mint_policy_id(),
        );
        let chain_anchor = ChainAnchor::new(
            GENESIS_ID,
            validation_context.id(),
            validation_context.proof_verifier_id(),
            validation_context.mint_policy_id(),
            ledger.state_id(GENESIS_ID),
        );
        let validator_set = ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([4; 32]),
                1,
                ValidatorVerificationKey::new(1, vec![5; 32]).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        let consensus_config = ConsensusConfig::new(1, 10, 4_096, 0, validator_set).unwrap();
        let consensus_anchor = ConsensusAnchor::new(
            chain_anchor.genesis_id,
            chain_anchor.validation_context_id,
            consensus_config.id(),
            chain_anchor.genesis_state_id,
            comet_genesis().id(),
        );
        (
            chain_anchor,
            validation_context,
            consensus_anchor,
            consensus_config,
            ledger,
        )
    }

    fn context(
        chain_anchor: ChainAnchor,
        validation_context: ValidationContext,
        consensus_anchor: ConsensusAnchor,
        consensus_config: &ConsensusConfig,
    ) -> ExecutionContext {
        ExecutionContext::new(
            chain_anchor,
            validation_context,
            consensus_anchor,
            Arc::new(consensus_config.clone()),
            comet_genesis(),
            Arc::new(AcceptingVerifier),
            Arc::new(DenyAllMints),
        )
        .unwrap()
    }

    fn comet_identity() -> CometBftNetworkIdentity {
        CometBftNetworkIdentity::new("noxis-storage-test", 1, "cometbft-0.38", [8; 32]).unwrap()
    }

    fn comet_genesis() -> CometBftGenesis {
        let validators = ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([4; 32]),
                1,
                ValidatorVerificationKey::new(1, vec![5; 32]).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        CometBftGenesis::from_consensus_config(comet_identity(), &validators).unwrap()
    }

    fn decision(height: u64) -> CometBftDecision {
        CometBftDecision::new(
            &comet_genesis(),
            i64::try_from(height).unwrap(),
            [height as u8; 32],
            comet_genesis().validators().hash(),
        )
        .unwrap()
    }

    fn transfer(id: u8, nullifier: u8, commitment: u8) -> Vec<u8> {
        encode_transaction(&Transaction {
            id: TransactionId::new([id; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: ASSET,
                input_nullifiers: vec![Nullifier::new([nullifier; 32])],
                output_commitments: vec![Commitment::new([commitment; 32])],
                proof: Proof {
                    suite_version: CryptoSuite::RESEARCH_V1.version,
                    bytes: vec![1],
                },
            }),
        })
        .unwrap()
    }

    #[test]
    fn commits_a_normal_block_and_reopens_its_exact_tip() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let transactions = vec![transfer(10, 11, 12)];

        let receipt;
        {
            let mut persistent = PersistentExecution::open(
                &path,
                genesis,
                context(anchor, validation_context, consensus_anchor, &config),
            )
            .unwrap();
            let block = persistent
                .execute(BlockProposal {
                    height: 1,
                    comet_decision: decision(1),
                    transactions: &transactions,
                })
                .unwrap();
            receipt = persistent.commit(&block).unwrap();
            assert_eq!(receipt.height, 1);
            assert_eq!(receipt.log_offset, 0);
            assert_eq!(persistent.committed_state().height(), 1);
            assert_eq!(persistent.app_hash(), Some(receipt.app_hash));
        }

        let (_, _, _, _, genesis) = fixture();
        let reopened = PersistentExecution::open(
            &path,
            genesis,
            context(anchor, validation_context, consensus_anchor, &config),
        )
        .unwrap();
        assert_eq!(reopened.committed_state().height(), receipt.height);
        assert_eq!(
            reopened.committed_state().block_id(),
            Some(receipt.block_id)
        );
        assert_eq!(
            reopened.committed_state().record_chain().current_state_id(),
            receipt.state_id
        );
        assert_eq!(reopened.app_hash(), Some(receipt.app_hash));
    }

    #[test]
    fn commits_and_recovers_an_empty_block_as_a_complete_state_transition() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let empty: Vec<Vec<u8>> = Vec::new();

        let receipt;
        {
            let mut persistent = PersistentExecution::open(
                &path,
                genesis,
                context(anchor, validation_context, consensus_anchor, &config),
            )
            .unwrap();
            let block = persistent
                .execute(BlockProposal {
                    height: 1,
                    comet_decision: decision(1),
                    transactions: &empty,
                })
                .unwrap();
            assert!(block.records().is_empty());
            receipt = persistent.commit(&block).unwrap();
            assert_eq!(
                persistent
                    .committed_state()
                    .record_chain()
                    .current_sequence(),
                0
            );
        }

        let (_, _, _, _, genesis) = fixture();
        let reopened = PersistentExecution::open(
            &path,
            genesis,
            context(anchor, validation_context, consensus_anchor, &config),
        )
        .unwrap();
        assert_eq!(reopened.committed_state().height(), 1);
        assert_eq!(
            reopened.committed_state().record_chain().current_sequence(),
            0
        );
        assert_eq!(
            reopened.committed_state().block_id(),
            Some(receipt.block_id)
        );
        assert_eq!(reopened.app_hash(), Some(receipt.app_hash));
    }

    #[test]
    fn retries_the_same_durable_block_without_appending_a_second_frame() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let transactions = vec![transfer(10, 11, 12)];
        let mut persistent = PersistentExecution::open(
            &path,
            genesis,
            context(anchor, validation_context, consensus_anchor, &config),
        )
        .unwrap();
        let block = persistent
            .execute(BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &transactions,
            })
            .unwrap();

        let first = persistent.commit(&block).unwrap();
        let length_after_first = fs::metadata(&path).unwrap().len();
        let retry = persistent.commit(&block).unwrap();

        assert_eq!(retry, first);
        assert_eq!(fs::metadata(&path).unwrap().len(), length_after_first);
    }

    #[test]
    fn rejects_a_different_block_at_an_already_durable_height() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let first_transactions = vec![transfer(10, 11, 12)];
        let conflicting_transactions = vec![transfer(13, 14, 15)];
        let mut persistent = PersistentExecution::open(
            &path,
            genesis,
            context(anchor, validation_context, consensus_anchor, &config),
        )
        .unwrap();
        let first = persistent
            .execute(BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &first_transactions,
            })
            .unwrap();
        let conflicting = persistent
            .execute(BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &conflicting_transactions,
            })
            .unwrap();

        persistent.commit(&first).unwrap();
        let durable_length = fs::metadata(&path).unwrap().len();
        assert!(matches!(
            persistent.commit(&conflicting),
            Err(PersistentExecutionError::ConflictingCommitAtHeight { height: 1 })
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), durable_length);
        assert_eq!(
            persistent.committed_state().block_id(),
            Some(first.header().id())
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_concurrent_second_writer_for_the_same_block_journal() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let first = PersistentExecution::open(
            &path,
            genesis,
            context(anchor, validation_context, consensus_anchor, &config),
        )
        .unwrap();

        let (_, _, _, _, genesis) = fixture();
        assert!(matches!(
            PersistentExecution::open(
                &path,
                genesis,
                context(anchor, validation_context, consensus_anchor, &config),
            ),
            Err(PersistentExecutionError::Journal(BlockJournalError::Io {
                operation: "acquire exclusive block-journal lock",
                ..
            }))
        ));
        drop(first);
    }

    #[test]
    fn refuses_a_corrupt_complete_frame_without_truncating_it() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let transactions = vec![transfer(10, 11, 12)];
        {
            let mut persistent = PersistentExecution::open(
                &path,
                genesis,
                context(anchor, validation_context, consensus_anchor, &config),
            )
            .unwrap();
            let block = persistent
                .execute(BlockProposal {
                    height: 1,
                    comet_decision: decision(1),
                    transactions: &transactions,
                })
                .unwrap();
            persistent.commit(&block).unwrap();
        }

        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        let original_length = fs::metadata(&path).unwrap().len();

        let (_, _, _, _, genesis) = fixture();
        assert!(matches!(
            PersistentExecution::open(
                &path,
                genesis,
                context(anchor, validation_context, consensus_anchor, &config),
            ),
            Err(PersistentExecutionError::Journal(
                BlockJournalError::ChecksumMismatch { offset: 0, .. }
            ))
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), original_length);
    }

    #[test]
    fn recovery_truncates_a_plausible_incomplete_final_block_frame() {
        let directory = TestDirectory::new();
        let path = directory.journal_path();
        let (anchor, validation_context, consensus_anchor, config, genesis) = fixture();
        let first_transactions = vec![transfer(10, 11, 12)];
        let second_transactions = vec![transfer(13, 14, 15)];

        let first_receipt;
        let second_offset;
        {
            let mut persistent = PersistentExecution::open(
                &path,
                genesis,
                context(anchor, validation_context, consensus_anchor, &config),
            )
            .unwrap();
            let first = persistent
                .execute(BlockProposal {
                    height: 1,
                    comet_decision: decision(1),
                    transactions: &first_transactions,
                })
                .unwrap();
            first_receipt = persistent.commit(&first).unwrap();
            let second = persistent
                .execute(BlockProposal {
                    height: 2,
                    comet_decision: decision(2),
                    transactions: &second_transactions,
                })
                .unwrap();
            second_offset = persistent.commit(&second).unwrap().log_offset;
        }

        let complete_journal = fs::read(&path).unwrap();
        let partial_length = usize::try_from(second_offset).unwrap() + 2;
        assert!(partial_length < complete_journal.len());
        fs::write(&path, &complete_journal[..partial_length]).unwrap();

        let (_, _, _, _, genesis) = fixture();
        let recovered = PersistentExecution::open(
            &path,
            genesis,
            context(anchor, validation_context, consensus_anchor, &config),
        )
        .unwrap();
        assert_eq!(recovered.committed_state().height(), 1);
        assert_eq!(
            recovered.committed_state().block_id(),
            Some(first_receipt.block_id)
        );
        assert_eq!(recovered.app_hash(), Some(first_receipt.app_hash));
        drop(recovered);
        assert_eq!(fs::metadata(&path).unwrap().len(), second_offset);
    }
}
