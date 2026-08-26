use std::fmt;

use noxis_consensus::EngineIdentityError;
use noxis_crypto::ServiceCryptoEligibilityError;
use noxis_execution::ExecutionError;
use noxis_storage::PersistentExecutionError;

use crate::HeightMappingError;

/// A lifecycle violation or deterministic execution failure in the ABCI core.
#[derive(Debug)]
pub enum CometAbciError {
    CryptoEligibility(ServiceCryptoEligibilityError),
    Height(HeightMappingError),
    EngineIdentity(Box<EngineIdentityError>),
    Execution(ExecutionError),
    Storage(PersistentExecutionError),
    InitChainMismatch,
    InitChainAfterCommit,
    ConsensusBeforeInitChain,
    MempoolLimitExceeded,
    NegativeMaximumTransactionBytes(i64),
    UnexpectedEngineHeight { expected: i64, actual: i64 },
    UnexpectedNextValidatorsHash,
    FinalizeConflict { engine_height: i64 },
    MissingFinalizedBlock,
}

impl fmt::Display for CometAbciError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CryptoEligibility(error) => {
                write!(
                    formatter,
                    "cryptographic settlement eligibility failed: {error}"
                )
            }
            Self::Height(error) => write!(formatter, "invalid Comet/Noxis height: {error}"),
            Self::EngineIdentity(error) => {
                write!(formatter, "invalid CometBFT decision context: {error}")
            }
            Self::Execution(error) => write!(formatter, "deterministic execution failed: {error}"),
            Self::Storage(error) => write!(formatter, "durable block commit failed: {error}"),
            Self::InitChainMismatch => {
                formatter.write_str("InitChain does not match configured Comet identity")
            }
            Self::InitChainAfterCommit => {
                formatter.write_str("InitChain cannot run after a durable block exists")
            }
            Self::ConsensusBeforeInitChain => formatter.write_str(
                "consensus methods cannot run before a matching InitChain has completed",
            ),
            Self::MempoolLimitExceeded => {
                formatter.write_str("local mempool overlay limit exceeded")
            }
            Self::NegativeMaximumTransactionBytes(value) => {
                write!(
                    formatter,
                    "Comet proposal byte limit cannot be negative: {value}"
                )
            }
            Self::UnexpectedEngineHeight { expected, actual } => write!(
                formatter,
                "expected the next Comet height {expected}, received {actual}"
            ),
            Self::UnexpectedNextValidatorsHash => formatter.write_str(
                "Comet request next validators hash differs from the genesis-bound validator set",
            ),
            Self::FinalizeConflict { engine_height } => write!(
                formatter,
                "FinalizeBlock supplied different data for already pending engine height {engine_height}"
            ),
            Self::MissingFinalizedBlock => {
                formatter.write_str("Commit has no pending finalized block")
            }
        }
    }
}

impl std::error::Error for CometAbciError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CryptoEligibility(error) => Some(error),
            Self::Height(error) => Some(error),
            Self::EngineIdentity(error) => Some(error.as_ref()),
            Self::Execution(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::InitChainMismatch
            | Self::InitChainAfterCommit
            | Self::ConsensusBeforeInitChain
            | Self::MempoolLimitExceeded
            | Self::NegativeMaximumTransactionBytes(_)
            | Self::UnexpectedEngineHeight { .. }
            | Self::UnexpectedNextValidatorsHash
            | Self::FinalizeConflict { .. }
            | Self::MissingFinalizedBlock => None,
        }
    }
}
