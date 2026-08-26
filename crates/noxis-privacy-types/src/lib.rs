//! Versioned public types for the future Noxis private-transfer protocol.
//!
//! These types deliberately contain no proving, hashing, KEM, key material or
//! wallet secrets. They are an isolated v2 boundary and do not alter `NOXT` v1
//! transactions or the active ledger.

mod error;
mod identifiers;
mod transfer;

pub use error::PrivacyTypesError;
pub use identifiers::{
    CiphertextDigestV2, CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2, TreeParametersId,
};
pub use transfer::{
    PRIVATE_TRANSFER_V2_INTENT_DOMAIN, PRIVATE_TRANSFER_V2_TREE_DEPTH, PrivateTransferIntentV2,
    TreeParametersV2,
};
