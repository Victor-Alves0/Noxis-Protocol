//! Stable, dependency-free domain primitives for Noxis.

use std::fmt;

macro_rules! fixed_identifier {
    ($name:ident) => {
        /// Fixed-width protocol identifier.
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

fixed_identifier!(AssetId);
fixed_identifier!(Commitment);
fixed_identifier!(Nullifier);
fixed_identifier!(TransactionId);
fixed_identifier!(TransactionIntentId);
fixed_identifier!(StateId);
fixed_identifier!(GenesisId);
fixed_identifier!(ProofVerifierId);
fixed_identifier!(MintPolicyId);
fixed_identifier!(ValidationContextId);
fixed_identifier!(ConsensusConfigId);
fixed_identifier!(ValidatorSetId);
fixed_identifier!(ValidatorId);
fixed_identifier!(BlockId);
fixed_identifier!(FinalityCertificateId);

/// Commitment to the complete application state after one executed block.
///
/// This is distinct from [`StateId`]: it also binds execution position and
/// consensus-domain data, allowing empty blocks to advance an application
/// commitment without inventing a ledger transition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AppHash(pub [u8; 32]);

impl AppHash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for AppHash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Display for AppHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable identity binding a local state-record chain to one genesis.
///
/// The pair is supplied by configuration/runtime wiring and verified by the
/// storage layer before any history is replayed. It contains no filesystem
/// path, secret, process-local setting, or mutable ledger data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainAnchor {
    pub genesis_id: GenesisId,
    pub validation_context_id: ValidationContextId,
    pub proof_verifier_id: ProofVerifierId,
    pub mint_policy_id: MintPolicyId,
    pub genesis_state_id: StateId,
}

impl ChainAnchor {
    pub const fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        proof_verifier_id: ProofVerifierId,
        mint_policy_id: MintPolicyId,
        genesis_state_id: StateId,
    ) -> Self {
        Self {
            genesis_id,
            validation_context_id,
            proof_verifier_id,
            mint_policy_id,
            genesis_state_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Amount(u128);

impl Amount {
    pub const fn new(units: u128) -> Option<Self> {
        if units == 0 { None } else { Some(Self(units)) }
    }

    pub const fn units(self) -> u128 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    /// A future adapter and custody policy may attest backing; this type alone proves none.
    NativeBacked,
    /// An asset governed by an explicit collateral and issuance policy.
    Synthetic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetDefinition {
    pub id: AssetId,
    pub ticker: String,
    pub kind: AssetKind,
}

impl AssetDefinition {
    pub fn new(
        id: AssetId,
        ticker: impl Into<String>,
        kind: AssetKind,
    ) -> Result<Self, AssetError> {
        let ticker = ticker.into();
        if ticker.is_empty()
            || ticker.len() > 16
            || !ticker.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(AssetError::InvalidTicker);
        }
        Ok(Self { id, ticker, kind })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetError {
    InvalidTicker,
}

impl fmt::Display for AssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTicker => {
                formatter.write_str("asset ticker must contain 1–16 uppercase ASCII characters")
            }
        }
    }
}

impl std::error::Error for AssetError {}
