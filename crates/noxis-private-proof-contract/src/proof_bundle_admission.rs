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
use noxis_storage::{PrivateStateStoreError, PrivateStateStoreV1};

use crate::proof_bundle_envelope::candidate_private_proof_bundle_envelope_id;
use crate::{
    CandidatePrivateProofBundleEnvelopeError, CandidatePrivateProofBundleEnvelopeIdV1,
    CandidatePrivateProofBundleEnvelopeV1, CandidatePrivateTransferProofBundleVerifierV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementV1,
};

/// Public local receipt returned only after one `NXPP` envelope has passed
/// verification and the corresponding private-ledger state transition has
/// committed. It retains no proof, note, nullifier key, ciphertext or witness.
///
/// This receipt is in-memory evidence for a future history design. It is not a
/// transaction format, persistent log entry, network identity or finality
/// proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateProofBundleAdmissionReceiptV1 {
    envelope_id: CandidatePrivateProofBundleEnvelopeIdV1,
    ledger_receipt: CandidatePrivateTransferAdmissionReceiptV1,
}

impl CandidatePrivateProofBundleAdmissionReceiptV1 {
    pub const fn envelope_id(&self) -> CandidatePrivateProofBundleEnvelopeIdV1 {
        self.envelope_id
    }
    pub const fn ledger_receipt(&self) -> &CandidatePrivateTransferAdmissionReceiptV1 {
        &self.ledger_receipt
    }
    pub const fn pre_state_id(&self) -> noxis_types::StateId {
        self.ledger_receipt.pre_state_id()
    }
    pub const fn post_state_id(&self) -> noxis_types::StateId {
        self.ledger_receipt.post_state_id()
    }
    pub const fn asset_id(&self) -> noxis_types::AssetId {
        self.ledger_receipt.asset_id()
    }
    pub const fn input_nullifiers(&self) -> &[noxis_privacy_types::NullifierV2; 2] {
        self.ledger_receipt.input_nullifiers()
    }
    pub const fn output_commitments(&self) -> &[noxis_privacy_types::NoteCommitmentV2; 2] {
        self.ledger_receipt.output_commitments()
    }
}

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
) -> Result<CandidatePrivateProofBundleAdmissionReceiptV1, CandidatePrivateProofBundleAdmissionError>
{
    let envelope_id = candidate_private_proof_bundle_envelope_id(envelope_bytes);
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
    let ledger_receipt = ledger.apply_transfer(
        &request,
        &CandidatePrivateTransferProofBundleVerifierV1::new(),
    )?;
    Ok(CandidatePrivateProofBundleAdmissionReceiptV1 {
        envelope_id,
        ledger_receipt,
    })
}

/// Parses, verifies and durably admits one local `NXPP v1` envelope through
/// the existing single-writer `NXPL` private-state store.
///
/// The function does not write envelope bytes or proof material to disk. It
/// reuses the store's only mutation path, which journals the complete verified
/// post-state before publishing its cache. On success, reopening the store
/// recovers the resulting anchor; on every parse, verification or storage
/// error, the original in-memory and durable state remain the authority.
pub fn admit_candidate_private_proof_bundle_envelope_to_store(
    store: &mut PrivateStateStoreV1,
    intent: PrivateTransferIntentV2,
    envelope_bytes: &[u8],
) -> Result<CandidatePrivateProofBundleAdmissionReceiptV1, CandidatePrivateProofBundleAdmissionError>
{
    let envelope_id = candidate_private_proof_bundle_envelope_id(envelope_bytes);
    let state = store.state();
    let statement = CandidatePrivateTransferProofPublicStatementV1::new(
        state.anchor().clone(),
        state.nullifier_tree(),
        intent.clone(),
    )?;
    let bundle = CandidatePrivateProofBundleEnvelopeV1::decode_and_verify(
        envelope_bytes,
        &statement,
        state.nullifier_tree(),
    )?;
    let request = CandidatePrivateTransferRequestV1::new(intent, bundle);
    let ledger_receipt = store.apply_transfer(
        &request,
        &CandidatePrivateTransferProofBundleVerifierV1::new(),
    )?;
    Ok(CandidatePrivateProofBundleAdmissionReceiptV1 {
        envelope_id,
        ledger_receipt,
    })
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
    Store(PrivateStateStoreError),
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
impl From<PrivateStateStoreError> for CandidatePrivateProofBundleAdmissionError {
    fn from(value: PrivateStateStoreError) -> Self {
        Self::Store(value)
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
