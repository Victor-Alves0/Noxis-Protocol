//! Public transaction representation and policy boundary for the ledger.
//!
//! These values describe a requested transition but never mutate state by
//! themselves. Validation and state changes are deliberately elsewhere.

use std::fmt;

use noxis_crypto::{CryptoSuite, Proof, StateAnchor};
use noxis_types::{
    Amount, AssetId, Commitment, GenesisId, MintPolicyId, Nullifier, StateId, TransactionId,
    TransactionIntentId, ValidationContextId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub id: TransactionId,
    pub suite: CryptoSuite,
    pub operation: Operation,
}

/// Immutable deployment and intent bindings supplied when a transition is
/// evaluated. These fields are carried into every transfer-proof and
/// mint-authorization statement so an otherwise valid proof cannot be
/// interpreted under another ledger's genesis, rule set, intent, or state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionValidationContext {
    pub genesis_id: GenesisId,
    pub validation_context_id: ValidationContextId,
    pub transaction_intent_id: TransactionIntentId,
    pub state_id: StateId,
}

impl TransactionValidationContext {
    pub const fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        transaction_intent_id: TransactionIntentId,
        state_id: StateId,
    ) -> Self {
        Self {
            genesis_id,
            validation_context_id,
            transaction_intent_id,
            state_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    Transfer(Transfer),
    Mint(Mint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transfer {
    pub asset_id: AssetId,
    pub input_nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<Commitment>,
    pub proof: Proof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mint {
    pub asset_id: AssetId,
    pub amount: Amount,
    pub output_commitments: Vec<Commitment>,
    /// Opaque policy-specific authorization payload; it is never interpreted by the ledger.
    pub authorization: Vec<u8>,
}

/// The complete public issuance request a [`MintPolicy`] must authorize.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintStatement {
    pub genesis_id: GenesisId,
    pub validation_context_id: ValidationContextId,
    pub transaction_intent_id: TransactionIntentId,
    pub state_id: StateId,
    pub asset_id: AssetId,
    pub amount: Amount,
    pub output_commitments: Vec<Commitment>,
    pub state_anchor: StateAnchor,
    pub issued_supply_before: Option<Amount>,
}

pub trait MintPolicy: Send + Sync {
    /// Stable public identity of this policy's non-secret configuration and rules.
    fn mint_policy_id(&self) -> MintPolicyId;

    /// Determines whether this complete issuance statement is authorized.
    fn authorize(
        &self,
        statement: &MintStatement,
        authorization: &[u8],
    ) -> Result<(), MintAuthorizationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenyAllMints;

impl MintPolicy for DenyAllMints {
    fn mint_policy_id(&self) -> MintPolicyId {
        MintPolicyId::new([0; 32])
    }

    fn authorize(
        &self,
        _statement: &MintStatement,
        _authorization: &[u8],
    ) -> Result<(), MintAuthorizationError> {
        Err(MintAuthorizationError::Denied)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MintAuthorizationError {
    Denied,
}

impl fmt::Display for MintAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mint authorization was denied")
    }
}

impl std::error::Error for MintAuthorizationError {}
