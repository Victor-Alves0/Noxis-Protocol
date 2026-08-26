use std::fmt;

use noxis_codec::CodecError;
use noxis_consensus::{ConsensusError, EngineIdentityError};
use noxis_crypto::{CryptoSuite, ValidationContextError};
use noxis_ledger::LedgerError;
use noxis_record_chain::RecordError;
use noxis_types::{MintPolicyId, ProofVerifierId, StateId};

/// A deterministic reason a proposed block cannot be executed.
#[derive(Debug)]
pub enum ExecutionError {
    InvalidValidationContext(ValidationContextError),
    ValidationContextAnchorMismatch,
    ConsensusAnchorMismatch,
    ProofVerifierMismatch {
        expected: ProofVerifierId,
        actual: ProofVerifierId,
    },
    MintPolicyMismatch {
        expected: MintPolicyId,
        actual: MintPolicyId,
    },
    CommittedStateIdMismatch {
        expected: StateId,
        actual: StateId,
    },
    InvalidGenesisExecutionState,
    MissingCommittedBlockId,
    HeightOverflow,
    UnexpectedHeight {
        expected: u64,
        actual: u64,
    },
    TooManyTransactions {
        actual: usize,
        maximum: u32,
    },
    ProposalBytesExceeded {
        actual: usize,
        maximum: u32,
    },
    TransactionBytesExceeded {
        index: usize,
        actual: usize,
        maximum: u32,
    },
    TransactionCountOverflow,
    TransactionCodec {
        index: usize,
        source: CodecError,
    },
    NonCanonicalTransaction {
        index: usize,
    },
    TransactionCryptoSuiteMismatch {
        index: usize,
        expected: CryptoSuite,
        actual: CryptoSuite,
    },
    Ledger {
        index: usize,
        source: LedgerError,
    },
    Record {
        index: usize,
        source: RecordError,
    },
    RecordChain {
        index: usize,
        source: RecordError,
    },
    Consensus(ConsensusError),
    EngineIdentity(EngineIdentityError),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValidationContext(error) => {
                write!(formatter, "invalid execution validation context: {error}")
            }
            Self::ValidationContextAnchorMismatch => {
                formatter.write_str("validation context does not match the chain anchor")
            }
            Self::ConsensusAnchorMismatch => formatter
                .write_str("consensus anchor does not match the chain anchor or configuration"),
            Self::ProofVerifierMismatch { .. } => {
                formatter.write_str("proof verifier does not match the chain anchor")
            }
            Self::MintPolicyMismatch { .. } => {
                formatter.write_str("mint policy does not match the chain anchor")
            }
            Self::CommittedStateIdMismatch { .. } => {
                formatter.write_str("committed record chain does not match committed ledger state")
            }
            Self::InvalidGenesisExecutionState => {
                formatter.write_str("genesis execution state cannot contain a block or record hash")
            }
            Self::MissingCommittedBlockId => {
                formatter.write_str("non-genesis execution state must identify its latest block")
            }
            Self::HeightOverflow => formatter.write_str("execution block height overflows u64"),
            Self::UnexpectedHeight { expected, actual } => write!(
                formatter,
                "expected execution block height {expected}, received {actual}"
            ),
            Self::TooManyTransactions { actual, maximum } => write!(
                formatter,
                "proposal has {actual} transactions, exceeding maximum {maximum}"
            ),
            Self::ProposalBytesExceeded { actual, maximum } => write!(
                formatter,
                "proposal has {actual} transaction bytes, exceeding maximum {maximum}"
            ),
            Self::TransactionBytesExceeded {
                index,
                actual,
                maximum,
            } => write!(
                formatter,
                "transaction {index} has {actual} bytes, exceeding maximum {maximum}"
            ),
            Self::TransactionCountOverflow => {
                formatter.write_str("proposal transaction count overflows u32")
            }
            Self::TransactionCodec { index, source } => {
                write!(formatter, "transaction {index} is invalid: {source}")
            }
            Self::NonCanonicalTransaction { index } => {
                write!(formatter, "transaction {index} is not canonically encoded")
            }
            Self::TransactionCryptoSuiteMismatch { index, .. } => {
                write!(
                    formatter,
                    "transaction {index} has a different cryptographic suite"
                )
            }
            Self::Ledger { index, source } => {
                write!(
                    formatter,
                    "transaction {index} is invalid for the candidate state: {source}"
                )
            }
            Self::Record { index, source } => {
                write!(
                    formatter,
                    "transaction {index} cannot produce a state record: {source}"
                )
            }
            Self::RecordChain { index, source } => {
                write!(
                    formatter,
                    "transaction {index} cannot extend the record chain: {source}"
                )
            }
            Self::Consensus(error) => write!(formatter, "invalid executed block: {error}"),
            Self::EngineIdentity(error) => {
                write!(formatter, "invalid CometBFT decision binding: {error}")
            }
        }
    }
}

impl std::error::Error for ExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidValidationContext(error) => Some(error),
            Self::TransactionCodec { source, .. } => Some(source),
            Self::Ledger { source, .. } => Some(source),
            Self::Record { source, .. } | Self::RecordChain { source, .. } => Some(source),
            Self::Consensus(error) => Some(error),
            Self::EngineIdentity(error) => Some(error),
            _ => None,
        }
    }
}
