//! Typed errors for rejected ledger boundaries and transitions.

use std::fmt;

use noxis_crypto::VerificationError;
use noxis_merkle::MerkleError;
use noxis_types::{AssetId, Commitment, Nullifier, StateId, TransactionId};

use crate::MintAuthorizationError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerError {
    AssetAlreadyRegistered(AssetId),
    UnknownAsset(AssetId),
    DuplicateTransaction(TransactionId),
    NullifierAlreadySpent(Nullifier),
    CommitmentAlreadyExists(Commitment),
    EmptyField(&'static str),
    SupplyOverflow(AssetId),
    ValidationStateIdMismatch {
        expected: StateId,
        supplied: StateId,
    },
    Merkle(MerkleError),
    MintAuthorization(MintAuthorizationError),
    Proof(VerificationError),
}

/// A reason a purported complete ledger snapshot is not canonical or safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerSnapshotError {
    Merkle(MerkleError),
    Ledger(LedgerError),
    AssetsNotStrictlySorted {
        index: usize,
    },
    InvalidAsset {
        index: usize,
        source: noxis_types::AssetError,
    },
    DuplicateCommitment(Commitment),
    NullifiersNotStrictlySorted,
    SupplyNotStrictlySorted {
        index: usize,
    },
    SupplyForUnknownAsset(AssetId),
    TransactionsNotStrictlySorted,
}

impl fmt::Display for LedgerSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Merkle(error) => write!(formatter, "invalid snapshot Merkle tree: {error}"),
            Self::Ledger(error) => write!(formatter, "invalid snapshot ledger state: {error}"),
            Self::AssetsNotStrictlySorted { index } => {
                write!(
                    formatter,
                    "snapshot assets are not strictly sorted at index {index}"
                )
            }
            Self::InvalidAsset { index, source } => {
                write!(formatter, "snapshot asset {index} is invalid: {source}")
            }
            Self::DuplicateCommitment(commitment) => {
                write!(formatter, "snapshot repeats commitment {commitment}")
            }
            Self::NullifiersNotStrictlySorted => {
                formatter.write_str("snapshot nullifiers are not strictly sorted")
            }
            Self::SupplyNotStrictlySorted { index } => {
                write!(
                    formatter,
                    "snapshot supply is not strictly sorted at index {index}"
                )
            }
            Self::SupplyForUnknownAsset(asset_id) => {
                write!(formatter, "snapshot supply names unknown asset {asset_id}")
            }
            Self::TransactionsNotStrictlySorted => {
                formatter.write_str("snapshot transaction IDs are not strictly sorted")
            }
        }
    }
}

impl std::error::Error for LedgerSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Merkle(error) => Some(error),
            Self::Ledger(error) => Some(error),
            Self::InvalidAsset { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssetAlreadyRegistered(asset) => {
                write!(formatter, "asset {asset} is already registered")
            }
            Self::UnknownAsset(asset) => write!(formatter, "asset {asset} is not registered"),
            Self::DuplicateTransaction(transaction) => {
                write!(formatter, "transaction {transaction} was already accepted")
            }
            Self::NullifierAlreadySpent(nullifier) => {
                write!(formatter, "nullifier {nullifier} was already spent")
            }
            Self::CommitmentAlreadyExists(commitment) => {
                write!(formatter, "commitment {commitment} already exists")
            }
            Self::EmptyField(label) => write!(formatter, "{label} cannot be empty"),
            Self::SupplyOverflow(asset) => {
                write!(formatter, "issued supply overflow for asset {asset}")
            }
            Self::ValidationStateIdMismatch { .. } => formatter.write_str(
                "transaction validation context does not identify the current ledger state",
            ),
            Self::Merkle(error) => error.fmt(formatter),
            Self::MintAuthorization(error) => error.fmt(formatter),
            Self::Proof(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LedgerError {}
