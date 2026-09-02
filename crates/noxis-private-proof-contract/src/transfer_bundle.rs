//! Typed, in-memory composition of the currently executable private-transfer
//! proof relations.
//!
//! This module deliberately stops before proof serialization and network
//! admission. It retains three independently verifiable opaque proofs: one composed
//! intent/value proof and one ownership proof for each input. All three are
//! bound to the exact same canonical `NXPU v1` statement. Nullifier freshness
//! is re-derived from supplied current state and remains an atomic invariant
//! of the typed in-memory private ledger rather than a claim trusted from the
//! bundle.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_privacy_types::NoteCommitmentV2;
use noxis_private_state::{
    CandidatePrivateTransferAuthorizationError, CandidatePrivateTransferAuthorizer,
};
use noxis_stark_experiment::{
    Poseidon2P24IntentValueConservationExperimentResult, Poseidon2P24IntentValueConservationProof,
    Poseidon2P24OwnershipExperimentResult, StarkExperimentError,
    prove_p24_intent_value_conservation, verify_p24_intent_value_conservation_proof,
};

use crate::anchored_ownership::prove_candidate_anchored_ownership_bound_note_commitment;
use crate::{
    CandidateAnchoredOwnershipError, CandidateAnchoredOwnershipProofV1,
    CandidateAnchoredOwnershipWitnessV1, CandidateInnerRelationKindV1,
    CandidateInnerRelationReceiptIdV1, CandidateNxsmNullifierTransitionWitnessError,
    CandidateNxsmNullifierTransitionWitnessV1, CandidateOutputNoteWitnessV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1, candidate_inner_relation_receipt_id,
    verify_candidate_anchored_ownership,
};

/// Identities of the three independently verified relations retained by one
/// bundle. They prevent proofs from different statements or input slots from
/// being silently mixed by orchestration code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferProofBundleReceiptsV1 {
    intent_value: CandidateInnerRelationReceiptIdV1,
    input_ownership: [CandidateInnerRelationReceiptIdV1; 2],
}

impl CandidatePrivateTransferProofBundleReceiptsV1 {
    pub const fn intent_value(&self) -> CandidateInnerRelationReceiptIdV1 {
        self.intent_value
    }

    pub const fn input_ownership(&self) -> [CandidateInnerRelationReceiptIdV1; 2] {
        self.input_ownership
    }
}

/// Three opaque local proofs bound to one exact private-transfer statement.
///
/// There is intentionally no `Clone`, encoder or decoder. Moving this value
/// transfers ownership inside one process; it does not create a wire proof.
pub struct CandidatePrivateTransferProofBundleV1 {
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
    receipts: CandidatePrivateTransferProofBundleReceiptsV1,
    intent_value: Poseidon2P24IntentValueConservationProof,
    input_ownership: [CandidateAnchoredOwnershipProofV1; 2],
}

impl CandidatePrivateTransferProofBundleV1 {
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }

    pub const fn receipts(&self) -> &CandidatePrivateTransferProofBundleReceiptsV1 {
        &self.receipts
    }

    /// Returns raw pinned-research byte lengths for the intent/value proof and
    /// both ownership proofs. It deliberately does not create a bundle format;
    /// the measurements establish a defensible future transport budget.
    pub fn pinned_research_proof_lengths(
        &self,
    ) -> Result<[usize; 3], CandidatePrivateTransferProofBundleError> {
        Ok([
            self.intent_value.encode_pinned_research_bytes()?.len(),
            self.input_ownership[0].pinned_research_proof_length()?,
            self.input_ownership[1].pinned_research_proof_length()?,
        ])
    }
}

/// Public results reconstructed only after every retained proof and
/// cross-binding has been independently checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferProofBundleResultsV1 {
    pub intent_value: Poseidon2P24IntentValueConservationExperimentResult,
    pub input_ownership: [Poseidon2P24OwnershipExperimentResult; 2],
}

/// Fail-closed adapter for the typed local bundle.
///
/// This is not yet `noxis_crypto::ProofVerifier`: the active public ledger uses
/// a portable byte proof and legacy 32-byte nullifiers, while the candidate
/// private ledger accepts this adapter over opaque local proofs and 64-byte
/// private nullifiers. Keeping the interfaces separate prevents an accidental
/// production bypass while proof serialization and consensus admission remain
/// unresolved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidatePrivateTransferProofBundleVerifierV1;

impl CandidatePrivateTransferProofBundleVerifierV1 {
    pub const fn new() -> Self {
        Self
    }

    /// Verifies the exact statement, current state, receipt identities, all
    /// three opaque proofs and both private input-note cross-bindings.
    pub fn verify(
        self,
        bundle: &CandidatePrivateTransferProofBundleV1,
        statement: &CandidatePrivateTransferProofPublicStatementV1,
        current_tree: &NullifierSparseTreeStateV1,
    ) -> Result<
        CandidatePrivateTransferProofBundleResultsV1,
        CandidatePrivateTransferProofBundleError,
    > {
        verify_candidate_private_transfer_proof_bundle(bundle, statement, current_tree)
    }
}

impl CandidatePrivateTransferAuthorizer<CandidatePrivateTransferProofBundleV1>
    for CandidatePrivateTransferProofBundleVerifierV1
{
    fn verify(
        &self,
        authorization: &CandidatePrivateTransferProofBundleV1,
        current_anchor: &noxis_private_state::PrivateStateAnchorV2,
        current_tree: &NullifierSparseTreeStateV1,
        intent: &noxis_privacy_types::PrivateTransferIntentV2,
    ) -> Result<(), CandidatePrivateTransferAuthorizationError> {
        let statement = CandidatePrivateTransferProofPublicStatementV1::new(
            current_anchor.clone(),
            current_tree,
            intent.clone(),
        )
        .map_err(|_| CandidatePrivateTransferAuthorizationError::Rejected)?;
        CandidatePrivateTransferProofBundleVerifierV1::verify(
            *self,
            authorization,
            &statement,
            current_tree,
        )
        .map(|_| ())
        .map_err(|_| CandidatePrivateTransferAuthorizationError::Rejected)
    }
}

/// Produces and immediately verifies a typed local bundle. The constructor
/// returns only after all proofs agree with the same `NXPU v1` statement and
/// the same current nullifier state.
pub fn prove_candidate_private_transfer_proof_bundle(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    current_tree: &NullifierSparseTreeStateV1,
    input_witnesses: &[CandidateAnchoredOwnershipWitnessV1; 2],
    output_witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<CandidatePrivateTransferProofBundleV1, CandidatePrivateTransferProofBundleError> {
    statement.revalidate(current_tree)?;
    let nxsm_witness = CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(
        current_tree,
        statement.air_public_inputs().intent(),
    )?;
    let intent_value = prove_p24_intent_value_conservation(
        statement.air_public_inputs().intent(),
        [
            *input_witnesses[0].note_preimage(),
            *input_witnesses[1].note_preimage(),
            *output_witnesses[0].note_preimage(),
            *output_witnesses[1].note_preimage(),
        ],
    )?;
    let value_result = verify_p24_intent_value_conservation_proof(
        &intent_value,
        statement.air_public_inputs().intent(),
    )?;
    validate_intent_value_result(statement, &value_result)?;

    let input_ownership = [
        prove_candidate_anchored_ownership_bound_note_commitment(
            statement,
            current_tree,
            &nxsm_witness,
            0,
            &input_witnesses[0],
            value_result.values.note_commitments[0],
        )?,
        prove_candidate_anchored_ownership_bound_note_commitment(
            statement,
            current_tree,
            &nxsm_witness,
            1,
            &input_witnesses[1],
            value_result.values.note_commitments[1],
        )?,
    ];
    let bundle = CandidatePrivateTransferProofBundleV1 {
        statement_id: statement.statement_id(),
        receipts: expected_receipts(statement),
        intent_value,
        input_ownership,
    };
    CandidatePrivateTransferProofBundleVerifierV1::new().verify(
        &bundle,
        statement,
        current_tree,
    )?;
    Ok(bundle)
}

/// Independently verifies an already-produced in-memory bundle.
pub fn verify_candidate_private_transfer_proof_bundle(
    bundle: &CandidatePrivateTransferProofBundleV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    current_tree: &NullifierSparseTreeStateV1,
) -> Result<CandidatePrivateTransferProofBundleResultsV1, CandidatePrivateTransferProofBundleError>
{
    if bundle.statement_id != statement.statement_id() {
        return Err(CandidatePrivateTransferProofBundleError::StatementIdMismatch);
    }
    statement.revalidate(current_tree)?;
    validate_receipts(&bundle.receipts, statement)?;
    let nxsm_witness = CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(
        current_tree,
        statement.air_public_inputs().intent(),
    )?;
    let intent_value = verify_p24_intent_value_conservation_proof(
        &bundle.intent_value,
        statement.air_public_inputs().intent(),
    )?;
    validate_intent_value_result(statement, &intent_value)?;

    let first = verify_candidate_anchored_ownership(
        &bundle.input_ownership[0],
        statement,
        current_tree,
        &nxsm_witness,
    )?;
    let second = verify_candidate_anchored_ownership(
        &bundle.input_ownership[1],
        statement,
        current_tree,
        &nxsm_witness,
    )?;
    for (index, proof) in bundle.input_ownership.iter().enumerate() {
        let expected = intent_value.values.note_commitments[index];
        if proof.note_commitment_binding() != Some(expected) {
            return Err(
                CandidatePrivateTransferProofBundleError::InputNoteCommitmentBindingMismatch {
                    input_index: index,
                },
            );
        }
    }
    Ok(CandidatePrivateTransferProofBundleResultsV1 {
        intent_value,
        input_ownership: [first, second],
    })
}

fn expected_receipts(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
) -> CandidatePrivateTransferProofBundleReceiptsV1 {
    CandidatePrivateTransferProofBundleReceiptsV1 {
        intent_value: candidate_inner_relation_receipt_id(
            statement,
            CandidateInnerRelationKindV1::IntentValue,
            None,
        ),
        input_ownership: [
            candidate_inner_relation_receipt_id(
                statement,
                CandidateInnerRelationKindV1::InputOwnership,
                Some(0),
            ),
            candidate_inner_relation_receipt_id(
                statement,
                CandidateInnerRelationKindV1::InputOwnership,
                Some(1),
            ),
        ],
    }
}

fn validate_receipts(
    actual: &CandidatePrivateTransferProofBundleReceiptsV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
) -> Result<(), CandidatePrivateTransferProofBundleError> {
    let expected = expected_receipts(statement);
    if actual.intent_value != expected.intent_value {
        return Err(CandidatePrivateTransferProofBundleError::ReceiptMismatch {
            relation: CandidateInnerRelationKindV1::IntentValue,
            input_index: None,
        });
    }
    for input_index in 0..2 {
        if actual.input_ownership[input_index] != expected.input_ownership[input_index] {
            return Err(CandidatePrivateTransferProofBundleError::ReceiptMismatch {
                relation: CandidateInnerRelationKindV1::InputOwnership,
                input_index: Some(input_index as u8),
            });
        }
    }
    Ok(())
}

fn validate_intent_value_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    result: &Poseidon2P24IntentValueConservationExperimentResult,
) -> Result<(), CandidatePrivateTransferProofBundleError> {
    let intent = statement.air_public_inputs().intent();
    if result.intent.intent_commitment != statement.air_public_inputs().intent_commitment() {
        return Err(CandidatePrivateTransferProofBundleError::IntentCommitmentMismatch);
    }
    if result.values.asset_id != intent.asset_id().0 {
        return Err(CandidatePrivateTransferProofBundleError::AssetIdMismatch);
    }
    for output_index in 0..2 {
        let actual =
            NoteCommitmentV2::from_elements(result.values.note_commitments[output_index + 2])?;
        if actual != intent.outputs()[output_index].commitment() {
            return Err(
                CandidatePrivateTransferProofBundleError::OutputCommitmentMismatch { output_index },
            );
        }
    }
    Ok(())
}

/// Fail-closed errors from typed local proof composition. No variant carries a
/// private note, key, value, Merkle path or other secret witness material.
#[derive(Debug)]
pub enum CandidatePrivateTransferProofBundleError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    NxsmWitness(CandidateNxsmNullifierTransitionWitnessError),
    Ownership(CandidateAnchoredOwnershipError),
    Stark(StarkExperimentError),
    PrivacyTypes(noxis_privacy_types::PrivacyTypesError),
    StatementIdMismatch,
    ReceiptMismatch {
        relation: CandidateInnerRelationKindV1,
        input_index: Option<u8>,
    },
    IntentCommitmentMismatch,
    AssetIdMismatch,
    OutputCommitmentMismatch {
        output_index: usize,
    },
    InputNoteCommitmentBindingMismatch {
        input_index: usize,
    },
}

impl From<CandidatePrivateTransferProofPublicStatementError>
    for CandidatePrivateTransferProofBundleError
{
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}

impl From<CandidateNxsmNullifierTransitionWitnessError>
    for CandidatePrivateTransferProofBundleError
{
    fn from(value: CandidateNxsmNullifierTransitionWitnessError) -> Self {
        Self::NxsmWitness(value)
    }
}

impl From<CandidateAnchoredOwnershipError> for CandidatePrivateTransferProofBundleError {
    fn from(value: CandidateAnchoredOwnershipError) -> Self {
        Self::Ownership(value)
    }
}

impl From<StarkExperimentError> for CandidatePrivateTransferProofBundleError {
    fn from(value: StarkExperimentError) -> Self {
        Self::Stark(value)
    }
}

impl From<noxis_privacy_types::PrivacyTypesError> for CandidatePrivateTransferProofBundleError {
    fn from(value: noxis_privacy_types::PrivacyTypesError) -> Self {
        Self::PrivacyTypes(value)
    }
}

impl fmt::Display for CandidatePrivateTransferProofBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-transfer proof bundle error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateTransferProofBundleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_identity_rejects_a_relation_from_another_statement() {
        let statement_id = [7; 32];
        let other_statement_id = [8; 32];
        let expected = crate::candidate_inner_relation_receipt_id_from_statement_id(
            statement_id,
            CandidateInnerRelationKindV1::IntentValue,
            None,
        );
        let from_other = crate::candidate_inner_relation_receipt_id_from_statement_id(
            other_statement_id,
            CandidateInnerRelationKindV1::IntentValue,
            None,
        );
        assert_ne!(expected, from_other);
    }

    #[test]
    fn receipt_identity_rejects_swapped_input_slots() {
        let statement_id = [9; 32];
        let first = crate::candidate_inner_relation_receipt_id_from_statement_id(
            statement_id,
            CandidateInnerRelationKindV1::InputOwnership,
            Some(0),
        );
        let second = crate::candidate_inner_relation_receipt_id_from_statement_id(
            statement_id,
            CandidateInnerRelationKindV1::InputOwnership,
            Some(1),
        );
        assert_ne!(first, second);
    }
}
