use noxis_codec::{decode_transaction, encode_transaction, transaction_intent_id};
use noxis_consensus::{BlockHeader, BlockHeaderInput, CometBftDecision, RecordCommitment};
use noxis_ledger::TransactionValidationContext;
use noxis_record_chain::{MAX_RECORD_TRANSACTION_BYTES, RecordHash, TransactionRecord};
use noxis_types::{AppHash, StateId, TransactionIntentId};
use sha2::{Digest, Sha256};

use crate::{CandidateExecutionState, CommittedExecutionState, ExecutionContext, ExecutionError};

/// An ordered proposal supplied by a consensus engine after its own framing.
///
/// The proposal carries no authority: execution checks its height and parent
/// against the committed state before interpreting any transaction bytes.
#[derive(Debug)]
pub struct BlockProposal<'a> {
    pub height: u64,
    /// Exact CometBFT decision context associated with this application block.
    pub comet_decision: CometBftDecision,
    pub transactions: &'a [Vec<u8>],
}

/// Per-transaction facts from deterministic block execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionReceipt {
    pub transaction_intent_id: TransactionIntentId,
    pub record_hash: RecordHash,
    pub resulting_state_id: StateId,
}

/// Complete candidate output of a side-effect-free block execution.
#[derive(Clone, Debug)]
pub struct ExecutedBlock {
    header: BlockHeader,
    comet_decision: CometBftDecision,
    records: Vec<TransactionRecord>,
    receipts: Vec<ExecutionReceipt>,
    resulting_state: noxis_ledger::LedgerState,
    resulting_record_chain: noxis_record_chain::RecordChain,
    terminal_record_hash: Option<RecordHash>,
    app_hash: AppHash,
}

impl ExecutedBlock {
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Exact engine decision context committed by this application block.
    pub const fn comet_decision(&self) -> CometBftDecision {
        self.comet_decision
    }

    pub fn records(&self) -> &[TransactionRecord] {
        &self.records
    }

    pub fn receipts(&self) -> &[ExecutionReceipt] {
        &self.receipts
    }

    pub fn resulting_state(&self) -> &noxis_ledger::LedgerState {
        &self.resulting_state
    }

    pub const fn resulting_record_chain(&self) -> noxis_record_chain::RecordChain {
        self.resulting_record_chain
    }

    pub const fn terminal_record_hash(&self) -> Option<RecordHash> {
        self.terminal_record_hash
    }

    /// Canonical commitment to the complete post-block application position.
    ///
    /// A future ABCI adapter may return these bytes as its application hash,
    /// observing the consensus engine's own height-mapping rules.
    pub const fn app_hash(&self) -> AppHash {
        self.app_hash
    }

    /// Turns this execution result into the next in-memory committed state.
    /// It intentionally does not imply storage durability or consensus finality.
    pub fn into_committed_state(self) -> CommittedExecutionState {
        CommittedExecutionState::from_executed_parts(
            self.resulting_state,
            self.resulting_record_chain,
            self.header.height(),
            self.header.id(),
            self.terminal_record_hash,
        )
    }
}

/// Executes every proposed transaction in its supplied order without I/O.
pub fn execute_block(
    context: &ExecutionContext,
    committed: &CommittedExecutionState,
    proposal: BlockProposal<'_>,
) -> Result<ExecutedBlock, ExecutionError> {
    let expected_height = committed
        .height()
        .checked_add(1)
        .ok_or(ExecutionError::HeightOverflow)?;
    if proposal.height != expected_height {
        return Err(ExecutionError::UnexpectedHeight {
            expected: expected_height,
            actual: proposal.height,
        });
    }
    proposal
        .comet_decision
        .validate_for(context.comet_bft_genesis(), proposal.height)
        .map_err(ExecutionError::EngineIdentity)?;
    let computed_committed_state_id = committed
        .ledger_state()
        .state_id(context.chain_anchor().genesis_id);
    if computed_committed_state_id != committed.record_chain().current_state_id() {
        return Err(ExecutionError::CommittedStateIdMismatch {
            expected: computed_committed_state_id,
            actual: committed.record_chain().current_state_id(),
        });
    }
    if proposal.transactions.len() > context.consensus_config().maximum_block_records() as usize {
        return Err(ExecutionError::TooManyTransactions {
            actual: proposal.transactions.len(),
            maximum: context.consensus_config().maximum_block_records(),
        });
    }
    let proposal_bytes = proposal
        .transactions
        .iter()
        .try_fold(0_usize, |total, bytes| {
            total
                .checked_add(bytes.len())
                .ok_or(ExecutionError::ProposalBytesExceeded {
                    actual: usize::MAX,
                    maximum: context.consensus_config().maximum_block_transaction_bytes(),
                })
        })?;
    if proposal_bytes > context.consensus_config().maximum_block_transaction_bytes() as usize {
        return Err(ExecutionError::ProposalBytesExceeded {
            actual: proposal_bytes,
            maximum: context.consensus_config().maximum_block_transaction_bytes(),
        });
    }
    let record_count = u32::try_from(proposal.transactions.len())
        .map_err(|_| ExecutionError::TransactionCountOverflow)?;

    let chain_anchor = context.chain_anchor();
    let mut state = committed.ledger_state().clone();
    let mut record_chain = committed.record_chain();
    let previous_state_id = record_chain.current_state_id();
    let first_record_sequence = record_chain.next_sequence();
    let mut records = Vec::with_capacity(proposal.transactions.len());
    let mut receipts = Vec::with_capacity(proposal.transactions.len());

    for (index, bytes) in proposal.transactions.iter().enumerate() {
        let (record, receipt) =
            apply_transaction(context, &mut state, &mut record_chain, bytes, index)?;
        receipts.push(receipt);
        records.push(record);
    }

    let record_hashes: Vec<_> = records.iter().map(TransactionRecord::record_hash).collect();
    let records_commitment =
        RecordCommitment::from_record_hashes(&record_hashes).map_err(ExecutionError::Consensus)?;
    let header = BlockHeader::new(BlockHeaderInput {
        protocol_version: context.consensus_config().protocol_version(),
        genesis_id: chain_anchor.genesis_id,
        validation_context_id: chain_anchor.validation_context_id,
        consensus_config_id: context.consensus_config().id(),
        validator_set_id: context.consensus_config().validator_set().id(),
        height: proposal.height,
        // V1 execution has no canonical engine-round source. Keeping these
        // fields fixed avoids an adapter creating different BlockIds for the
        // same committed transition. A future format can bind engine-proven
        // metadata explicitly.
        epoch: 0,
        round: 0,
        parent_block_id: committed.block_id(),
        previous_state_id,
        resulting_state_id: record_chain.current_state_id(),
        first_record_sequence,
        record_count,
        records_commitment,
    })
    .map_err(ExecutionError::Consensus)?;
    context
        .consensus_anchor()
        .validate_header(&header, context.consensus_config())
        .map_err(ExecutionError::Consensus)?;
    header
        .validate_record_hashes(&record_hashes)
        .map_err(ExecutionError::Consensus)?;

    let terminal_record_hash = records
        .last()
        .map(TransactionRecord::record_hash)
        .or(committed.terminal_record_hash());
    let app_hash = application_hash(
        context,
        &header,
        proposal.comet_decision,
        record_chain.current_sequence(),
        terminal_record_hash,
    );
    Ok(ExecutedBlock {
        header,
        comet_decision: proposal.comet_decision,
        terminal_record_hash,
        records,
        receipts,
        resulting_state: state,
        resulting_record_chain: record_chain,
        app_hash,
    })
}

/// Applies one canonical transaction to a discardable candidate overlay.
///
/// This is intended for local mempool admission and proposal selection. It
/// never constructs a block, changes a committed state or writes to storage.
pub fn simulate_transaction(
    context: &ExecutionContext,
    candidate: &mut CandidateExecutionState,
    transaction_bytes: &[u8],
) -> Result<ExecutionReceipt, ExecutionError> {
    let (state, record_chain) = candidate.mutable_parts();
    let (_record, receipt) = apply_transaction(context, state, record_chain, transaction_bytes, 0)?;
    Ok(receipt)
}

fn apply_transaction(
    context: &ExecutionContext,
    state: &mut noxis_ledger::LedgerState,
    record_chain: &mut noxis_record_chain::RecordChain,
    bytes: &[u8],
    index: usize,
) -> Result<(TransactionRecord, ExecutionReceipt), ExecutionError> {
    if bytes.len() > MAX_RECORD_TRANSACTION_BYTES as usize {
        return Err(ExecutionError::TransactionBytesExceeded {
            index,
            actual: bytes.len(),
            maximum: MAX_RECORD_TRANSACTION_BYTES,
        });
    }
    let transaction = decode_transaction(bytes)
        .map_err(|source| ExecutionError::TransactionCodec { index, source })?;
    let canonical = encode_transaction(&transaction)
        .map_err(|source| ExecutionError::TransactionCodec { index, source })?;
    if canonical != bytes {
        return Err(ExecutionError::NonCanonicalTransaction { index });
    }
    if transaction.suite != context.validation_context().crypto_suite() {
        return Err(ExecutionError::TransactionCryptoSuiteMismatch {
            index,
            expected: context.validation_context().crypto_suite(),
            actual: transaction.suite,
        });
    }
    let intent_id = transaction_intent_id(&transaction)
        .map_err(|source| ExecutionError::TransactionCodec { index, source })?;
    let chain_anchor = context.chain_anchor();
    let transition_context = TransactionValidationContext::new(
        chain_anchor.genesis_id,
        chain_anchor.validation_context_id,
        intent_id,
        record_chain.current_state_id(),
    );
    state
        .apply(
            &transaction,
            context.verifier(),
            context.mint_policy(),
            transition_context,
        )
        .map_err(|source| ExecutionError::Ledger { index, source })?;
    let record = TransactionRecord::new(
        record_chain.next_sequence(),
        record_chain.current_state_id(),
        canonical,
        state.state_id(chain_anchor.genesis_id),
    )
    .map_err(|source| ExecutionError::Record { index, source })?;
    record_chain
        .apply(&record)
        .map_err(|source| ExecutionError::RecordChain { index, source })?;
    let receipt = ExecutionReceipt {
        transaction_intent_id: record.transaction_intent_id(),
        record_hash: record.record_hash(),
        resulting_state_id: record.resulting_state_id(),
    };
    Ok((record, receipt))
}

fn application_hash(
    context: &ExecutionContext,
    header: &BlockHeader,
    comet_decision: CometBftDecision,
    record_sequence: u64,
    terminal_record_hash: Option<RecordHash>,
) -> AppHash {
    let mut hash = Sha256::new();
    hash.update(b"NOXIS/APP-HASH/V1\0");
    hash.update(context.chain_anchor().genesis_id.0);
    hash.update(context.chain_anchor().validation_context_id.0);
    hash.update(context.consensus_config().id().0);
    hash.update(comet_decision.network_id());
    hash.update(comet_decision.height().to_be_bytes());
    hash.update(comet_decision.block_hash());
    hash.update(comet_decision.next_validators_hash());
    hash.update(header.height().to_be_bytes());
    hash.update(header.id().0);
    hash.update(record_sequence.to_be_bytes());
    match terminal_record_hash {
        Some(record_hash) => {
            hash.update([1]);
            hash.update(record_hash.as_bytes());
        }
        None => hash.update([0]),
    }
    hash.update(header.resulting_state_id().0);
    AppHash::new(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use noxis_consensus::{
        CometBftDecision, CometBftGenesis, CometBftNetworkIdentity, ConsensusAnchor,
        ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
    };
    use noxis_crypto::{
        CryptoSuite, Proof, ProofVerifier, TransferStatement, ValidationContext, VerificationError,
    };
    use noxis_ledger::{DenyAllMints, LedgerError, Operation, Transaction, Transfer};
    use noxis_types::{
        AssetDefinition, AssetId, AssetKind, ChainAnchor, Commitment, GenesisId, MintPolicyId,
        Nullifier, ProofVerifierId, TransactionId, ValidatorId,
    };

    use super::*;

    const ASSET: AssetId = AssetId::new([1; 32]);
    const GENESIS_ID: GenesisId = GenesisId::new([2; 32]);

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

    fn fixture(
        maximum_block_transaction_bytes: u32,
    ) -> (
        ChainAnchor,
        ValidationContext,
        ConsensusAnchor,
        ConsensusConfig,
        noxis_ledger::LedgerState,
    ) {
        let mut ledger = noxis_ledger::LedgerState::new(4).unwrap();
        ledger
            .register_asset(AssetDefinition::new(ASSET, "USDX", AssetKind::Synthetic).unwrap())
            .unwrap();
        let validation_context = ValidationContext::new(
            CryptoSuite::RESEARCH_V1,
            ProofVerifierId::new([3; 32]),
            MintPolicyId::new([0; 32]),
        );
        let anchor = ChainAnchor::new(
            GENESIS_ID,
            validation_context.id(),
            validation_context.proof_verifier_id(),
            validation_context.mint_policy_id(),
            ledger.state_id(GENESIS_ID),
        );
        let validators = ValidatorSet::new(vec![
            Validator::new(
                ValidatorId::new([4; 32]),
                1,
                ValidatorVerificationKey::new(1, vec![5; 32]).unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        let config =
            ConsensusConfig::new(1, 10, maximum_block_transaction_bytes, 0, validators).unwrap();
        let consensus_anchor = ConsensusAnchor::new(
            anchor.genesis_id,
            anchor.validation_context_id,
            config.id(),
            anchor.genesis_state_id,
            comet_genesis().id(),
        );
        (anchor, validation_context, consensus_anchor, config, ledger)
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
                    suite_version: 1,
                    bytes: vec![1],
                },
            }),
        })
        .unwrap()
    }

    fn context(
        anchor: ChainAnchor,
        validation_context: ValidationContext,
        consensus_anchor: ConsensusAnchor,
        config: &ConsensusConfig,
    ) -> ExecutionContext {
        ExecutionContext::new(
            anchor,
            validation_context,
            consensus_anchor,
            Arc::new(config.clone()),
            comet_genesis(),
            Arc::new(AcceptingVerifier),
            Arc::new(DenyAllMints),
        )
        .unwrap()
    }

    fn comet_identity() -> CometBftNetworkIdentity {
        CometBftNetworkIdentity::new("noxis-execution-test", 1, "cometbft-0.38", [8; 32]).unwrap()
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

    #[test]
    fn executes_a_valid_batch_without_mutating_the_committed_tip() {
        let (anchor, validation_context, consensus_anchor, config, ledger) = fixture(4_096);
        let committed = CommittedExecutionState::genesis(ledger, anchor).unwrap();
        let prior_snapshot = committed.ledger_state().snapshot();
        let execution_context = context(anchor, validation_context, consensus_anchor, &config);
        let transactions = vec![transfer(10, 11, 12)];

        let first = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &transactions,
            },
        )
        .unwrap();
        let second = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &transactions,
            },
        )
        .unwrap();

        assert_eq!(first.header(), second.header());
        assert_eq!(first.app_hash(), second.app_hash());
        assert_eq!(first.records(), second.records());
        assert_eq!(committed.ledger_state().snapshot(), prior_snapshot);
        assert_eq!(committed.record_chain().current_sequence(), 0);
        assert_eq!(first.records().len(), 1);
        assert_eq!(first.receipts().len(), 1);
    }

    #[test]
    fn application_hash_commits_to_the_exact_comet_decision_context() {
        let (anchor, validation_context, consensus_anchor, config, ledger) = fixture(4_096);
        let committed = CommittedExecutionState::genesis(ledger, anchor).unwrap();
        let execution_context = context(anchor, validation_context, consensus_anchor, &config);
        let transactions = vec![transfer(10, 11, 12)];
        let first = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &transactions,
            },
        )
        .unwrap();
        let changed_decision = CometBftDecision::new(
            &comet_genesis(),
            1,
            [33; 32],
            comet_genesis().validators().hash(),
        )
        .unwrap();
        let second = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 1,
                comet_decision: changed_decision,
                transactions: &transactions,
            },
        )
        .unwrap();
        assert_eq!(first.header(), second.header());
        assert_ne!(first.app_hash(), second.app_hash());
    }

    #[test]
    fn execution_context_rejects_an_identity_not_committed_by_the_consensus_anchor() {
        let (anchor, validation_context, consensus_anchor, config, _ledger) = fixture(4_096);
        let other_identity =
            CometBftNetworkIdentity::new("other-comet-network", 1, "cometbft-0.38", [8; 32])
                .unwrap();
        let other_genesis =
            CometBftGenesis::from_consensus_config(other_identity, config.validator_set()).unwrap();

        assert!(matches!(
            ExecutionContext::new(
                anchor,
                validation_context,
                consensus_anchor,
                Arc::new(config),
                other_genesis,
                Arc::new(AcceptingVerifier),
                Arc::new(DenyAllMints),
            ),
            Err(ExecutionError::ConsensusAnchorMismatch)
        ));
    }

    #[test]
    fn executes_empty_blocks_and_derives_the_parent_from_committed_state() {
        let (anchor, validation_context, consensus_anchor, config, ledger) = fixture(4_096);
        let committed = CommittedExecutionState::genesis(ledger, anchor).unwrap();
        let execution_context = context(anchor, validation_context, consensus_anchor, &config);
        let empty: Vec<Vec<u8>> = Vec::new();

        let first = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &empty,
            },
        )
        .unwrap();
        assert_eq!(first.header().record_count(), 0);
        assert_eq!(first.header().last_record_sequence().unwrap(), None);
        assert_eq!(first.resulting_record_chain().current_sequence(), 0);
        let first_app_hash = first.app_hash();
        let committed = first.into_committed_state();

        let second = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 2,
                comet_decision: decision(2),
                transactions: &empty,
            },
        )
        .unwrap();
        assert_eq!(second.header().parent_block_id(), committed.block_id());
        assert_ne!(second.app_hash(), first_app_hash);
    }

    #[test]
    fn rejects_a_double_spend_without_leaking_a_partial_transition() {
        let (anchor, validation_context, consensus_anchor, config, ledger) = fixture(4_096);
        let committed = CommittedExecutionState::genesis(ledger, anchor).unwrap();
        let prior_snapshot = committed.ledger_state().snapshot();
        let execution_context = context(anchor, validation_context, consensus_anchor, &config);
        let transactions = vec![transfer(10, 11, 12), transfer(13, 11, 14)];

        let error = execute_block(
            &execution_context,
            &committed,
            BlockProposal {
                height: 1,
                comet_decision: decision(1),
                transactions: &transactions,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ExecutionError::Ledger {
                index: 1,
                source: LedgerError::NullifierAlreadySpent(_),
            }
        ));
        assert_eq!(committed.ledger_state().snapshot(), prior_snapshot);
        assert_eq!(committed.record_chain().current_sequence(), 0);
    }

    #[test]
    fn rejects_a_proposal_above_its_canonical_byte_limit() {
        let (anchor, validation_context, consensus_anchor, config, ledger) = fixture(1);
        let committed = CommittedExecutionState::genesis(ledger, anchor).unwrap();
        let execution_context = context(anchor, validation_context, consensus_anchor, &config);
        let transactions = vec![transfer(10, 11, 12)];

        assert!(matches!(
            execute_block(
                &execution_context,
                &committed,
                BlockProposal {
                    height: 1,
                    comet_decision: decision(1),
                    transactions: &transactions,
                },
            ),
            Err(ExecutionError::ProposalBytesExceeded { maximum: 1, .. })
        ));
    }

    #[test]
    fn rejects_an_unexpected_execution_height() {
        let (anchor, validation_context, consensus_anchor, config, ledger) = fixture(4_096);
        let committed = CommittedExecutionState::genesis(ledger, anchor).unwrap();
        let execution_context = context(anchor, validation_context, consensus_anchor, &config);
        let empty: Vec<Vec<u8>> = Vec::new();

        assert_eq!(
            execute_block(
                &execution_context,
                &committed,
                BlockProposal {
                    height: 2,
                    comet_decision: decision(2),
                    transactions: &empty,
                },
            )
            .unwrap_err()
            .to_string(),
            "expected execution block height 1, received 2"
        );
    }
}
