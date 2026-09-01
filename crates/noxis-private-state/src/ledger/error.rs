//! Fail-closed errors for candidate private-ledger admission.

use std::fmt;

use noxis_types::AssetId;

use crate::{CandidatePrivateStateTransitionV2Error, PrivateStateAnchorV2Error};

/// Deliberately narrow error returned by an authorization adapter.
///
/// Detailed prover/verifier diagnostics stay at the research adapter boundary;
/// the ledger only needs to know that authorization was not established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePrivateTransferAuthorizationError {
    Rejected,
}

impl fmt::Display for CandidatePrivateTransferAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("candidate private-transfer authorization was rejected")
    }
}

impl std::error::Error for CandidatePrivateTransferAuthorizationError {}

/// Errors that leave the candidate private ledger completely unchanged.
#[derive(Debug)]
pub enum CandidatePrivateLedgerError {
    StateConstruction(PrivateStateAnchorV2Error),
    AssetAlreadyRegistered(AssetId),
    UnknownAsset(AssetId),
    StateTransition(CandidatePrivateStateTransitionV2Error),
    Authorization(CandidatePrivateTransferAuthorizationError),
}

impl From<PrivateStateAnchorV2Error> for CandidatePrivateLedgerError {
    fn from(value: PrivateStateAnchorV2Error) -> Self {
        Self::StateConstruction(value)
    }
}

impl From<CandidatePrivateStateTransitionV2Error> for CandidatePrivateLedgerError {
    fn from(value: CandidatePrivateStateTransitionV2Error) -> Self {
        Self::StateTransition(value)
    }
}

impl From<CandidatePrivateTransferAuthorizationError> for CandidatePrivateLedgerError {
    fn from(value: CandidatePrivateTransferAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

impl fmt::Display for CandidatePrivateLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate private-ledger error: {self:?}")
    }
}

impl std::error::Error for CandidatePrivateLedgerError {}
