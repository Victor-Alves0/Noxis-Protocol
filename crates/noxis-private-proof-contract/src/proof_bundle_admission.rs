//! One local byte-to-ledger admission boundary for `NXPP v1`.
//!
//! This module owns the orchestration that a caller would otherwise need to
//! reproduce by hand: rebuild the exact current `NXPU` statement, parse and
//! verify `NXPP`, then enter the only mutable candidate-ledger boundary. It
//! remains local research software and is not ABCI, consensus, wallet or
//! network admission.

use std::fmt;

use noxis_privacy_types::PrivateTransferIntentV2;
use noxis_private_state::{
    CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1,
    CandidatePrivateTransferAdmissionReceiptV1, CandidatePrivateTransferRequestV1,
};

use crate::{
    CandidatePrivateProofBundleEnvelopeError, CandidatePrivateProofBundleEnvelopeV1,
    CandidatePrivateTransferProofBundleVerifierV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementV1,
};

/// Parses, independently verifies and atomically admits one local `NXPP v1`
/// envelope against the exact present candidate ledger state.
///
/// The supplied intent is required because `NXPP` commits to a statement ID,
/// rather than duplicating a second mutable source of public transaction
/// fields. The function derives `NXPU` from that intent plus the ledger's
/// current anchor/tree, so an envelope for another state or intent fails
/// before ledger mutation. The final ledger authorizer deliberately performs
/// its own verification again at the mutation boundary.
pub fn admit_candidate_private_proof_bundle_envelope(
    ledger: &mut CandidatePrivateLedgerStateV1,
    intent: PrivateTransferIntentV2,
    envelope_bytes: &[u8],
) -> Result<CandidatePrivateTransferAdmissionReceiptV1, CandidatePrivateProofBundleAdmissionError> {
    let statement = CandidatePrivateTransferProofPublicStatementV1::new(
        ledger.anchor().clone(),
        ledger.nullifier_tree(),
        intent.clone(),
    )?;
    let bundle = CandidatePrivateProofBundleEnvelopeV1::decode_and_verify(
        envelope_bytes,
        &statement,
        ledger.nullifier_tree(),
    )?;
    let request = CandidatePrivateTransferRequestV1::new(intent, bundle);
    Ok(ledger.apply_transfer(
        &request,
        &CandidatePrivateTransferProofBundleVerifierV1::new(),
    )?)
}

/// Errors from the local `NXPP` byte-to-ledger admission boundary.
///
/// Each variant leaves the supplied ledger unchanged: parsing and proof
/// verification happen before `apply_transfer`, whose own transition logic is
/// all-or-nothing.
#[derive(Debug)]
pub enum CandidatePrivateProofBundleAdmissionError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    Envelope(CandidatePrivateProofBundleEnvelopeError),
    Ledger(CandidatePrivateLedgerError),
}

impl From<CandidatePrivateTransferProofPublicStatementError>
    for CandidatePrivateProofBundleAdmissionError
{
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}
impl From<CandidatePrivateProofBundleEnvelopeError> for CandidatePrivateProofBundleAdmissionError {
    fn from(value: CandidatePrivateProofBundleEnvelopeError) -> Self {
        Self::Envelope(value)
    }
}
impl From<CandidatePrivateLedgerError> for CandidatePrivateProofBundleAdmissionError {
    fn from(value: CandidatePrivateLedgerError) -> Self {
        Self::Ledger(value)
    }
}
impl fmt::Display for CandidatePrivateProofBundleAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-proof bundle admission error: {self:?}"
        )
    }
}
impl std::error::Error for CandidatePrivateProofBundleAdmissionError {}
