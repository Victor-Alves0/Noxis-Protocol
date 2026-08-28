//! Reproducible, local-only operational demonstration.
//!
//! The verifier and mint policy in this module are deterministic research
//! fixtures. They prove node wiring, durability and duplicate-nullifier
//! rejection only; they are not privacy proofs, custody controls or consensus.

use std::fmt;

use noxis_codec::encode_transaction;
use noxis_config::{ConfigError, GenesisConfig, NodeConfig};
use noxis_consensus::{
    ConsensusConfig, ConsensusError, Validator, ValidatorSet, ValidatorVerificationKey,
};
use noxis_crypto::{
    CryptoSuite, Proof, ProofVerifier, TransferStatement, ValidationContext, VerificationError,
};
use noxis_ledger::{
    LedgerError, Mint, MintAuthorizationError, MintPolicy, MintStatement, Operation, Transaction,
    Transfer,
};
use noxis_runtime::DataDirectory;
use noxis_types::{
    Amount, AssetDefinition, AssetId, AssetKind, Commitment, MintPolicyId, Nullifier,
    ProofVerifierId, TransactionId, ValidatorId,
};

use crate::{
    LocalNodeRuntime, LocalNodeRuntimeError, LocalNodeStatus, SubmissionOutcome, SubmissionReceipt,
    SubmissionRejection,
};

const DEMO_ASSET: AssetId = AssetId::new([0x44; 32]);
const DEMO_NULLIFIER: Nullifier = Nullifier::new([0x55; 32]);
const DEMO_MINT_COMMITMENT: Commitment = Commitment::new([0x66; 32]);
const DEMO_TRANSFER_COMMITMENT: Commitment = Commitment::new([0x77; 32]);
const DEMO_DUPLICATE_COMMITMENT: Commitment = Commitment::new([0x88; 32]);
const DEMO_MINT_AUTHORIZATION: &[u8] = b"NOXIS-RESEARCH-DEMO-MINT/V1";

/// Public facts emitted after a successful local research demonstration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResearchDemoReport {
    pub initial: LocalNodeStatus,
    pub mint: SubmissionReceipt,
    pub transfer: SubmissionReceipt,
    pub after_transfer: LocalNodeStatus,
    pub duplicate_rejection: LedgerError,
    pub recovered: LocalNodeStatus,
}

/// Runs the complete durable sequence in `directory` and then reopens it.
pub fn run_local(directory: DataDirectory) -> Result<ResearchDemoReport, ResearchDemoError> {
    let genesis = demo_genesis()?;
    let config =
        NodeConfig::new(genesis, directory.ledger_path()).map_err(ResearchDemoError::Config)?;
    let mut runtime =
        LocalNodeRuntime::open(directory.clone(), &config, DemoVerifier, DemoMintPolicy)
            .map_err(ResearchDemoError::Runtime)?;
    let initial = runtime.node().status();
    if initial.sequence != 0 {
        return Err(ResearchDemoError::DirectoryNotEmpty {
            sequence: initial.sequence,
        });
    }

    let mint = accepted(
        runtime
            .node_mut()
            .submit_canonical(&encode_transaction(&mint_transaction())?),
        "mint",
    )?;
    let transfer = accepted(
        runtime
            .node_mut()
            .submit_canonical(&encode_transaction(&transfer_transaction(
                2,
                DEMO_TRANSFER_COMMITMENT,
            ))?),
        "research transfer",
    )?;
    let after_transfer = runtime.node().status();
    let duplicate_rejection = duplicate_rejection(runtime.node_mut().submit_canonical(
        &encode_transaction(&transfer_transaction(3, DEMO_DUPLICATE_COMMITMENT))?,
    ))?;

    drop(runtime);
    let recovered_runtime =
        LocalNodeRuntime::open(directory, &config, DemoVerifier, DemoMintPolicy)
            .map_err(ResearchDemoError::Runtime)?;
    let recovered = recovered_runtime.node().status();
    if recovered != after_transfer {
        return Err(ResearchDemoError::RecoveryMismatch);
    }
    Ok(ResearchDemoReport {
        initial,
        mint,
        transfer,
        after_transfer,
        duplicate_rejection,
        recovered,
    })
}

fn demo_genesis() -> Result<GenesisConfig, ResearchDemoError> {
    let asset = AssetDefinition::new(DEMO_ASSET, "NUSD", AssetKind::Synthetic)
        .map_err(ResearchDemoError::Asset)?;
    let context = ValidationContext::new(
        CryptoSuite::RESEARCH_V1,
        DemoVerifier.proof_verifier_id(),
        DemoMintPolicy.mint_policy_id(),
    );
    let validator = Validator::new(
        ValidatorId::new([0x11; 32]),
        1,
        ValidatorVerificationKey::new(1, vec![0x22; 32]).map_err(ResearchDemoError::Consensus)?,
    )
    .map_err(ResearchDemoError::Consensus)?;
    let validators = ValidatorSet::new(vec![validator]).map_err(ResearchDemoError::Consensus)?;
    let consensus =
        ConsensusConfig::new(1, 100, 1024, 0, validators).map_err(ResearchDemoError::Consensus)?;
    GenesisConfig::new(8, vec![asset], context, consensus).map_err(ResearchDemoError::Config)
}

fn mint_transaction() -> Transaction {
    Transaction {
        id: TransactionId::new([1; 32]),
        suite: CryptoSuite::RESEARCH_V1,
        operation: Operation::Mint(Mint {
            asset_id: DEMO_ASSET,
            amount: Amount::new(1_000).expect("positive demo amount"),
            output_commitments: vec![DEMO_MINT_COMMITMENT],
            authorization: DEMO_MINT_AUTHORIZATION.to_vec(),
        }),
    }
}

fn transfer_transaction(id: u8, output: Commitment) -> Transaction {
    Transaction {
        id: TransactionId::new([id; 32]),
        suite: CryptoSuite::RESEARCH_V1,
        operation: Operation::Transfer(Transfer {
            asset_id: DEMO_ASSET,
            input_nullifiers: vec![DEMO_NULLIFIER],
            output_commitments: vec![output],
            proof: Proof {
                suite_version: 1,
                bytes: b"research-demo-proof".to_vec(),
            },
        }),
    }
}

fn accepted(
    outcome: SubmissionOutcome,
    action: &'static str,
) -> Result<SubmissionReceipt, ResearchDemoError> {
    match outcome {
        SubmissionOutcome::LocallyDurable(receipt) => Ok(receipt),
        SubmissionOutcome::Rejected(rejection) => {
            Err(ResearchDemoError::UnexpectedRejection { action, rejection })
        }
        SubmissionOutcome::Unavailable(unavailable) => Err(ResearchDemoError::Unavailable {
            action,
            detail: format!("{unavailable:?}"),
        }),
    }
}

fn duplicate_rejection(outcome: SubmissionOutcome) -> Result<LedgerError, ResearchDemoError> {
    match outcome {
        SubmissionOutcome::Rejected(SubmissionRejection::Ledger(
            error @ LedgerError::NullifierAlreadySpent(_),
        )) => Ok(error),
        SubmissionOutcome::Rejected(rejection) => Err(ResearchDemoError::UnexpectedRejection {
            action: "duplicate nullifier",
            rejection,
        }),
        SubmissionOutcome::LocallyDurable(_) => Err(ResearchDemoError::DuplicateAccepted),
        SubmissionOutcome::Unavailable(unavailable) => Err(ResearchDemoError::Unavailable {
            action: "duplicate nullifier",
            detail: format!("{unavailable:?}"),
        }),
    }
}

struct DemoVerifier;

impl ProofVerifier for DemoVerifier {
    fn proof_verifier_id(&self) -> ProofVerifierId {
        ProofVerifierId::new([0x33; 32])
    }

    fn verify_transfer(
        &self,
        statement: &TransferStatement,
        proof: &Proof,
    ) -> Result<(), VerificationError> {
        if statement.asset_id == DEMO_ASSET
            && statement.input_nullifiers == [DEMO_NULLIFIER]
            && proof.bytes == b"research-demo-proof"
        {
            Ok(())
        } else {
            Err(VerificationError::InvalidProof)
        }
    }
}

struct DemoMintPolicy;

impl MintPolicy for DemoMintPolicy {
    fn mint_policy_id(&self) -> MintPolicyId {
        MintPolicyId::new([0x34; 32])
    }

    fn authorize(
        &self,
        statement: &MintStatement,
        authorization: &[u8],
    ) -> Result<(), MintAuthorizationError> {
        if authorization == DEMO_MINT_AUTHORIZATION
            && statement.asset_id == DEMO_ASSET
            && statement.amount == Amount::new(1_000).expect("positive demo amount")
            && statement.output_commitments == [DEMO_MINT_COMMITMENT]
            && statement.issued_supply_before.is_none()
        {
            Ok(())
        } else {
            Err(MintAuthorizationError::Denied)
        }
    }
}

/// Errors from the deterministic research demo, not protocol validation errors.
#[derive(Debug)]
pub enum ResearchDemoError {
    Asset(noxis_types::AssetError),
    Consensus(ConsensusError),
    Config(ConfigError),
    Runtime(LocalNodeRuntimeError),
    Codec(noxis_codec::CodecError),
    DirectoryNotEmpty {
        sequence: u64,
    },
    UnexpectedRejection {
        action: &'static str,
        rejection: SubmissionRejection,
    },
    Unavailable {
        action: &'static str,
        detail: String,
    },
    DuplicateAccepted,
    RecoveryMismatch,
}

impl From<noxis_codec::CodecError> for ResearchDemoError {
    fn from(value: noxis_codec::CodecError) -> Self {
        Self::Codec(value)
    }
}

impl fmt::Display for ResearchDemoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asset(error) => write!(formatter, "invalid demo asset: {error}"),
            Self::Consensus(error) => {
                write!(formatter, "invalid demo consensus configuration: {error}")
            }
            Self::Config(error) => write!(formatter, "invalid demo node configuration: {error}"),
            Self::Runtime(error) => write!(formatter, "could not open demo runtime: {error:?}"),
            Self::Codec(error) => write!(formatter, "could not encode demo transaction: {error}"),
            Self::DirectoryNotEmpty { sequence } => write!(
                formatter,
                "demo directory already contains history through sequence {sequence}"
            ),
            Self::UnexpectedRejection { action, rejection } => write!(
                formatter,
                "{action} was unexpectedly rejected: {rejection:?}"
            ),
            Self::Unavailable { action, detail } => {
                write!(formatter, "{action} is unavailable: {detail}")
            }
            Self::DuplicateAccepted => {
                formatter.write_str("duplicate nullifier was incorrectly accepted")
            }
            Self::RecoveryMismatch => {
                formatter.write_str("reopened demo state differs from the durable state")
            }
        }
    }
}

impl std::error::Error for ResearchDemoError {}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn local_demo_is_durable_and_rejects_the_duplicate_nullifier() {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("noxis-research-demo-{suffix}-{sequence}"));
        let report = run_local(DataDirectory::new(&path).unwrap()).unwrap();
        assert_eq!(report.initial.sequence, 0);
        assert_eq!(report.mint.sequence, 1);
        assert_eq!(report.transfer.sequence, 2);
        assert!(matches!(
            report.duplicate_rejection,
            LedgerError::NullifierAlreadySpent(_)
        ));
        assert_eq!(report.after_transfer, report.recovered);
        fs::remove_dir_all(path).unwrap();
    }
}
