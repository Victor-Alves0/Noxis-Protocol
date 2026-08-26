#![cfg(unix)]

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use noxis_codec::encode_transaction;
use noxis_comet_abci::{
    CometAbciError, CometBftDecision, CometBftGenesis, CometBftNetworkIdentity, InitChainRequest,
    NoxisCometCore, ProposalStatus,
};
use noxis_consensus::{
    ConsensusAnchor, ConsensusConfig, Validator, ValidatorSet, ValidatorVerificationKey,
};
use noxis_crypto::{
    CryptoSuite, Proof, ProofVerifier, TransferStatement, ValidationContext, VerificationError,
};
use noxis_execution::ExecutionContext;
use noxis_ledger::{DenyAllMints, LedgerState, MintPolicy, Operation, Transaction, Transfer};
use noxis_storage::PersistentExecution;
use noxis_types::{
    AssetDefinition, AssetId, AssetKind, ChainAnchor, Commitment, GenesisId, Nullifier,
    ProofVerifierId, TransactionId, ValidatorId,
};

const ASSET: AssetId = AssetId::new([1; 32]);
const GENESIS_ID: GenesisId = GenesisId::new([2; 32]);
const CHAIN_ID: &str = "noxis-abci-test";
const INITIAL_HEIGHT: i64 = 41;

static TEMP_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEMP_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock must be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "noxis-comet-abci-test-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory must be created");
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

fn fixture(
    maximum_block_records: u32,
    maximum_block_transaction_bytes: u32,
) -> (TestDirectory, NoxisCometCore) {
    let directory = TestDirectory::new();
    let mut ledger = LedgerState::new(4).expect("test ledger depth is valid");
    ledger
        .register_asset(
            AssetDefinition::new(ASSET, "USDX", AssetKind::Synthetic)
                .expect("test asset definition is valid"),
        )
        .expect("test asset is new");
    let verifier = AcceptingVerifier;
    let mint_policy = DenyAllMints;
    let validation_context = ValidationContext::new(
        CryptoSuite::RESEARCH_V1,
        verifier.proof_verifier_id(),
        mint_policy.mint_policy_id(),
    );
    let chain_anchor = ChainAnchor::new(
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
            ValidatorVerificationKey::new(1, vec![5; 32]).expect("test verification key is valid"),
        )
        .expect("test validator is valid"),
    ])
    .expect("test validator set is valid");
    let consensus_config = ConsensusConfig::new(
        1,
        maximum_block_records,
        maximum_block_transaction_bytes,
        0,
        validators,
    )
    .expect("test consensus configuration is valid");
    let engine_genesis =
        CometBftGenesis::from_consensus_config(engine_identity(), consensus_config.validator_set())
            .expect("test Comet genesis mapping is valid");
    let consensus_anchor = ConsensusAnchor::new(
        chain_anchor.genesis_id,
        chain_anchor.validation_context_id,
        consensus_config.id(),
        chain_anchor.genesis_state_id,
        engine_genesis.id(),
    );
    let context = ExecutionContext::new(
        chain_anchor,
        validation_context,
        consensus_anchor,
        Arc::new(consensus_config),
        engine_genesis,
        Arc::new(verifier),
        Arc::new(mint_policy),
    )
    .expect("test execution context is valid");
    let execution = PersistentExecution::open(directory.journal_path(), ledger, context)
        .expect("test journal opens on Unix");
    let core = NoxisCometCore::new(execution);
    (directory, core)
}

fn initialize(core: &mut NoxisCometCore) {
    let parameters_sha256 = core.identity().parameters_sha256();
    let validators = core
        .identity()
        .engine_genesis()
        .validators()
        .validators()
        .to_vec();
    core.init_chain(InitChainRequest::new(
        CHAIN_ID,
        INITIAL_HEIGHT,
        parameters_sha256,
        &validators,
    ))
    .expect("matching InitChain must initialize the application");
}

fn transaction(id: u8, nullifier: u8, commitment: u8) -> Vec<u8> {
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
    .expect("test transaction encodes canonically")
}

fn engine_identity() -> CometBftNetworkIdentity {
    CometBftNetworkIdentity::new(CHAIN_ID, INITIAL_HEIGHT, "cometbft-0.38", [7; 32])
        .expect("test identity is valid")
}

fn engine_genesis() -> CometBftGenesis {
    let validators = ValidatorSet::new(vec![
        Validator::new(
            ValidatorId::new([4; 32]),
            1,
            ValidatorVerificationKey::new(1, vec![5; 32]).expect("test verification key is valid"),
        )
        .expect("test validator is valid"),
    ])
    .expect("test validator set is valid");
    CometBftGenesis::from_consensus_config(engine_identity(), &validators)
        .expect("test Comet genesis mapping is valid")
}

fn decision(value: u8) -> CometBftDecision {
    CometBftDecision::new(
        &engine_genesis(),
        INITIAL_HEIGHT,
        [value; 32],
        engine_genesis().validators().hash(),
    )
    .expect("test decision is valid")
}

#[test]
fn consensus_methods_require_matching_init_chain() {
    let (_directory, mut core) = fixture(10, 4_096);
    let tx = transaction(10, 11, 12);

    assert!(!core.check_tx(&tx).accepted);
    assert!(
        core.prepare_proposal(
            INITIAL_HEIGHT,
            4_096,
            engine_genesis().validators().hash(),
            std::slice::from_ref(&tx),
        )
        .is_err()
    );
    assert!(
        core.process_proposal(decision(1), std::slice::from_ref(&tx))
            .is_err()
    );
    assert!(
        core.finalize_block(decision(1), std::slice::from_ref(&tx))
            .is_err()
    );
    let parameters_sha256 = core.identity().parameters_sha256();
    let validators = core
        .identity()
        .engine_genesis()
        .validators()
        .validators()
        .to_vec();
    assert!(
        core.init_chain(InitChainRequest::new(
            "other-network",
            INITIAL_HEIGHT,
            parameters_sha256,
            &validators,
        ))
        .is_err()
    );
    assert_eq!(
        core.info()
            .expect("Info is always available")
            .last_block_height,
        0
    );

    initialize(&mut core);
    assert_eq!(
        core.process_proposal(decision(1), std::slice::from_ref(&tx))
            .expect("initialized valid proposal is processed"),
        ProposalStatus::Accept
    );
}

#[test]
fn init_chain_rejects_changed_parameters_or_validator_mapping() {
    let (_directory, mut core) = fixture(10, 4_096);
    let validators = core
        .identity()
        .engine_genesis()
        .validators()
        .validators()
        .to_vec();

    assert!(matches!(
        core.init_chain(InitChainRequest::new(
            CHAIN_ID,
            INITIAL_HEIGHT,
            [0; 32],
            &validators,
        )),
        Err(CometAbciError::InitChainMismatch)
    ));

    let original = validators[0];
    let changed = noxis_comet_abci::CometBftValidator::from_comet_ed25519(
        original.noxis_validator_id(),
        [99; 32],
        original.voting_power(),
    )
    .expect("structurally valid changed validator");
    let parameters_sha256 = core.identity().parameters_sha256();
    assert!(matches!(
        core.init_chain(InitChainRequest::new(
            CHAIN_ID,
            INITIAL_HEIGHT,
            parameters_sha256,
            &[changed],
        )),
        Err(CometAbciError::InitChainMismatch)
    ));
}

#[test]
fn finalize_is_volatile_until_commit_then_advances_tip_and_resets_mempool() {
    let (directory, mut core) = fixture(10, 4_096);
    initialize(&mut core);
    let pending_tx = transaction(10, 11, 12);
    let finalized_tx = transaction(13, 14, 15);

    assert!(core.check_tx(&pending_tx).accepted);
    assert_eq!(core.admitted_transaction_count(), 1);
    let journal_size_before = fs::metadata(directory.journal_path())
        .expect("journal exists")
        .len();
    let finalized = core
        .finalize_block(decision(1), std::slice::from_ref(&finalized_tx))
        .expect("valid block finalizes in memory");

    assert_eq!(core.info().expect("Info is available").last_block_height, 0);
    assert_eq!(core.info().expect("Info is available").app_hash, None);
    assert_eq!(
        fs::metadata(directory.journal_path())
            .expect("journal remains available")
            .len(),
        journal_size_before
    );

    let receipt = core.commit().expect("finalized block commits once");
    assert_eq!(receipt.height, 1);
    assert_eq!(receipt.app_hash, finalized.app_hash);
    assert_eq!(
        core.info().expect("Info is available").last_block_height,
        INITIAL_HEIGHT
    );
    assert_eq!(
        core.info().expect("Info is available").app_hash,
        Some(finalized.app_hash)
    );
    assert_eq!(core.admitted_transaction_count(), 0);
    assert!(
        fs::metadata(directory.journal_path())
            .expect("journal remains available")
            .len()
            > journal_size_before
    );
}

#[test]
fn check_tx_rejects_a_pending_double_spend_without_losing_the_first_transaction() {
    let (_directory, mut core) = fixture(10, 4_096);
    initialize(&mut core);
    let first = transaction(10, 11, 12);
    let conflicting = transaction(13, 11, 14);

    assert!(core.check_tx(&first).accepted);
    assert!(!core.check_tx(&conflicting).accepted);
    assert_eq!(core.admitted_transaction_count(), 1);
}

#[test]
fn prepare_proposal_preserves_input_order_and_enforces_engine_and_noxis_limits() {
    let (_directory, mut core) = fixture(2, 4_096);
    initialize(&mut core);
    let first = transaction(10, 11, 12);
    let duplicate_spend = transaction(13, 11, 14);
    let second = transaction(15, 16, 17);
    let third = transaction(18, 19, 20);
    let transactions = vec![first.clone(), duplicate_spend, second.clone(), third];
    let engine_limit = i64::try_from(first.len() + second.len()).expect("test limit fits i64");

    let selected = core
        .prepare_proposal(
            INITIAL_HEIGHT,
            engine_limit,
            engine_genesis().validators().hash(),
            &transactions,
        )
        .expect("proposal selection is local and deterministic");

    assert_eq!(selected, vec![first, second]);
    assert_eq!(
        core.info()
            .expect("selection never persists")
            .last_block_height,
        0
    );
    assert_eq!(core.admitted_transaction_count(), 0);
}

#[test]
fn prepare_proposal_rejects_a_next_validator_hash_not_bound_to_genesis() {
    let (_directory, mut core) = fixture(2, 4_096);
    initialize(&mut core);
    let transaction = transaction(10, 11, 12);

    assert!(matches!(
        core.prepare_proposal(
            INITIAL_HEIGHT,
            4_096,
            [99; 32],
            std::slice::from_ref(&transaction),
        ),
        Err(CometAbciError::UnexpectedNextValidatorsHash)
    ));
}

#[test]
fn rejects_wrong_height_and_conflicting_finalize_block_identity() {
    let (_directory, mut core) = fixture(10, 4_096);
    initialize(&mut core);
    let tx = transaction(10, 11, 12);

    assert!(
        core.process_proposal(
            CometBftDecision::new(
                &engine_genesis(),
                INITIAL_HEIGHT + 1,
                [1; 32],
                engine_genesis().validators().hash(),
            )
            .expect("wrong-height decision is structurally valid"),
            std::slice::from_ref(&tx),
        )
        .is_err()
    );
    let first = core
        .finalize_block(decision(1), std::slice::from_ref(&tx))
        .expect("first finalization is valid");
    assert_eq!(
        core.finalize_block(decision(1), std::slice::from_ref(&tx))
            .expect("same finalization is idempotent"),
        first
    );
    assert!(matches!(
        core.finalize_block(decision(2), std::slice::from_ref(&tx)),
        Err(CometAbciError::FinalizeConflict { .. })
    ));
}
