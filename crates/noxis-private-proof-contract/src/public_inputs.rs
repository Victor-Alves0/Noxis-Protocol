//! Canonical public inputs for the unselected private-transfer AIR candidate.
//!
//! This representation contains no note opening or sparse-tree path. Keeping
//! it in the proof-contract crate prevents a future verifier from depending on
//! the crate that retains local wallet witness material.

use std::fmt;

use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_privacy_types::{
    PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2, TreeParametersId,
};
use noxis_tree_params::{
    CandidatePoseidon2P24ManifestV2, P24_BYTE_PACK_WIDTH, P24_INTENT_COMMITMENT_INPUT_ELEMENTS,
    Poseidon2P24CandidateError,
};

/// Candidate public frame for the future private-transfer AIR.
///
/// The complete canonical intent remains public. Its 214 `BytePack3LE`
/// elements and the sixteen-element `H_INTENT` digest are rederived here so a
/// prover cannot pair a witness with a different 640-byte intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferAirPublicInputsV1 {
    intent: PrivateTransferIntentV2,
    intent_elements: [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS],
    intent_commitment: PrivateTransferIntentCommitmentV2,
}

impl CandidatePrivateTransferAirPublicInputsV1 {
    /// Binds a canonical intent to the frozen candidate `H_INTENT` reference.
    pub fn from_intent(
        intent: PrivateTransferIntentV2,
    ) -> Result<Self, CandidatePrivateTransferAirPublicInputsError> {
        if intent.tree_parameters().id() != candidate_tree_parameters_id()? {
            return Err(
                CandidatePrivateTransferAirPublicInputsError::CandidateTreeParametersMismatch,
            );
        }
        let intent_commitment = Poseidon2P24PrivacyReference::load_candidate()?
            .hash_private_transfer_intent(&intent)?;
        Ok(Self {
            intent_elements: byte_pack3le_intent(&intent),
            intent,
            intent_commitment,
        })
    }

    /// The full canonical public statement whose bytes are committed below.
    pub const fn intent(&self) -> &PrivateTransferIntentV2 {
        &self.intent
    }

    /// Candidate `H_INTENT(intent.encode())` in canonical BabyBear encoding.
    pub const fn intent_commitment(&self) -> PrivateTransferIntentCommitmentV2 {
        self.intent_commitment
    }

    /// The 214 canonical `BytePack3LE` public elements consumed by the AIR.
    pub const fn intent_elements(&self) -> &[u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
        &self.intent_elements
    }

    /// Recomputes every public binding before a future prover or verifier uses
    /// this candidate frame.
    pub fn revalidate(&self) -> Result<(), CandidatePrivateTransferAirPublicInputsError> {
        let expected = Self::from_intent(self.intent.clone())?;
        if expected.intent_commitment != self.intent_commitment {
            return Err(CandidatePrivateTransferAirPublicInputsError::IntentCommitmentMismatch);
        }
        if expected.intent_elements != self.intent_elements {
            return Err(CandidatePrivateTransferAirPublicInputsError::IntentPackingMismatch);
        }
        Ok(())
    }
}

pub(crate) fn byte_pack3le_intent(
    intent: &PrivateTransferIntentV2,
) -> [u32; P24_INTENT_COMMITMENT_INPUT_ELEMENTS] {
    let encoded = intent.encode();
    core::array::from_fn(|index| {
        encoded[index * P24_BYTE_PACK_WIDTH
            ..core::cmp::min((index + 1) * P24_BYTE_PACK_WIDTH, encoded.len())]
            .iter()
            .enumerate()
            .fold(0_u32, |value, (offset, byte)| {
                value | (u32::from(*byte) << (offset * 8))
            })
    })
}

fn candidate_tree_parameters_id()
-> Result<TreeParametersId, CandidatePrivateTransferAirPublicInputsError> {
    let candidate_id = CandidatePoseidon2P24ManifestV2::new().candidate_id()?;
    Ok(TreeParametersId::new(candidate_id.as_bytes()))
}

/// Fail-closed errors while deriving the public AIR candidate frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidatePrivateTransferAirPublicInputsError {
    PrivacyReference(Poseidon2P24PrivacyReferenceError),
    Candidate(Poseidon2P24CandidateError),
    CandidateTreeParametersMismatch,
    IntentCommitmentMismatch,
    IntentPackingMismatch,
}

impl From<Poseidon2P24PrivacyReferenceError> for CandidatePrivateTransferAirPublicInputsError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::PrivacyReference(value)
    }
}

impl From<Poseidon2P24CandidateError> for CandidatePrivateTransferAirPublicInputsError {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for CandidatePrivateTransferAirPublicInputsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-transfer AIR public-input error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateTransferAirPublicInputsError {}
