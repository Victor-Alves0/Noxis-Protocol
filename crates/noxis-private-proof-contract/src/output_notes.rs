//! Local composition of private `H_NOTE` proofs with the two public output
//! commitments of `NXPU v1`.
//!
//! This is a deliberately narrow executable preflight. It proves that each
//! private 178-byte output preimage hashes to the output commitment already
//! declared by the canonical intent. It does not prove semantic note fields,
//! ciphertext construction, value conservation, output-tree insertion or an
//! atomic ledger transition.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_privacy_types::{NoteCommitmentV2, PrivacyTypesError};
use noxis_stark_experiment::{
    Poseidon2P24IntentExperimentResult, Poseidon2P24NoteExperimentResult, StarkExperimentError,
    prove_and_verify_p24_intent, prove_and_verify_p24_note,
};

use crate::{
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1,
};

/// In-memory private witness for one output `H_NOTE` relation.
///
/// It intentionally has no encoder: a note preimage may contain recipient
/// material, value and randomness and must remain local to the prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateOutputNoteWitnessV1 {
    note_preimage: [u8; 178],
}

impl CandidateOutputNoteWitnessV1 {
    /// Retains one exact private P24 note preimage in memory only.
    pub const fn new(note_preimage: [u8; 178]) -> Self {
        Self { note_preimage }
    }
}

/// Public receipt from one `H_INTENT` proof and two sequential output-note
/// proofs for a fixed two-output candidate statement.
///
/// The opaque proof objects are independently verified and discarded before
/// this receipt is returned. It is neither aggregation nor a portable proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateIntentOutputNotesPreflightV1 {
    intent_result: Poseidon2P24IntentExperimentResult,
    first_result: Poseidon2P24NoteExperimentResult,
    second_result: Poseidon2P24NoteExperimentResult,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

/// Public receipt of two sequential output `H_NOTE` checks without a separate
/// `H_INTENT` proof.
///
/// This is useful when a larger local preflight has already checked `H_INTENT`
/// once for the same statement. It still is not aggregation or a portable
/// verification artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateOutputNotesPreflightV1 {
    first_result: Poseidon2P24NoteExperimentResult,
    second_result: Poseidon2P24NoteExperimentResult,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

impl CandidateIntentOutputNotesPreflightV1 {
    /// Public `H_INTENT` commitment checked before the output proofs begin.
    pub const fn intent_result(&self) -> &Poseidon2P24IntentExperimentResult {
        &self.intent_result
    }

    /// Public `H_NOTE` result for canonical output index zero.
    pub const fn first_result(&self) -> &Poseidon2P24NoteExperimentResult {
        &self.first_result
    }

    /// Public `H_NOTE` result for canonical output index one.
    pub const fn second_result(&self) -> &Poseidon2P24NoteExperimentResult {
        &self.second_result
    }

    /// Identity of the exact `NXPU v1` statement used by all three checks.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }
}

impl CandidateOutputNotesPreflightV1 {
    /// Public `H_NOTE` result for canonical output index zero.
    pub const fn first_result(&self) -> &Poseidon2P24NoteExperimentResult {
        &self.first_result
    }

    /// Public `H_NOTE` result for canonical output index one.
    pub const fn second_result(&self) -> &Poseidon2P24NoteExperimentResult {
        &self.second_result
    }

    /// Identity of the exact `NXPU v1` statement used by both checks.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }
}

/// Runs and independently verifies `H_INTENT` once and one private `H_NOTE`
/// proof for each canonical output commitment in the supplied `NXPU v1`.
///
/// The output proofs run sequentially so the preflight does not imply that the
/// current research backend supports aggregation or recursion.
pub fn run_candidate_intent_output_notes_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<CandidateIntentOutputNotesPreflightV1, CandidateOutputNotesError> {
    statement.revalidate(pre_tree)?;

    let intent_result = prove_and_verify_p24_intent(statement.air_public_inputs().intent())?;
    validate_intent_result(statement, &intent_result)?;

    let outputs = run_candidate_output_notes_preflight(statement, pre_tree, witnesses)?;

    Ok(CandidateIntentOutputNotesPreflightV1 {
        intent_result,
        first_result: outputs.first_result,
        second_result: outputs.second_result,
        statement_id: outputs.statement_id,
    })
}

/// Runs one private `H_NOTE` proof for each canonical output commitment in a
/// supplied `NXPU v1`, without repeating the independent `H_INTENT` proof.
pub fn run_candidate_output_notes_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<CandidateOutputNotesPreflightV1, CandidateOutputNotesError> {
    statement.revalidate(pre_tree)?;
    let first_result = prove_and_verify_p24_note(witnesses[0].note_preimage)?;
    validate_output_result(statement, 0, &first_result)?;
    let second_result = prove_and_verify_p24_note(witnesses[1].note_preimage)?;
    validate_output_result(statement, 1, &second_result)?;
    Ok(CandidateOutputNotesPreflightV1 {
        first_result,
        second_result,
        statement_id: statement.statement_id(),
    })
}

/// Rechecks all retained public and candidate-state bindings of a completed
/// output-notes receipt. It cannot reverify the opaque proofs already dropped.
pub fn revalidate_candidate_intent_output_notes_preflight(
    preflight: &CandidateIntentOutputNotesPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
) -> Result<[Poseidon2P24NoteExperimentResult; 2], CandidateOutputNotesError> {
    if preflight.statement_id != statement.statement_id() {
        return Err(CandidateOutputNotesError::StatementIdMismatch);
    }
    let outputs = CandidateOutputNotesPreflightV1 {
        first_result: preflight.first_result.clone(),
        second_result: preflight.second_result.clone(),
        statement_id: preflight.statement_id,
    };
    validate_intent_result(statement, &preflight.intent_result)?;
    revalidate_candidate_output_notes_preflight(&outputs, statement, pre_tree)
}

/// Rechecks the public and candidate-state bindings retained by a completed
/// two-output receipt. It cannot reverify the discarded opaque proofs.
pub fn revalidate_candidate_output_notes_preflight(
    preflight: &CandidateOutputNotesPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
) -> Result<[Poseidon2P24NoteExperimentResult; 2], CandidateOutputNotesError> {
    if preflight.statement_id != statement.statement_id() {
        return Err(CandidateOutputNotesError::StatementIdMismatch);
    }
    statement.revalidate(pre_tree)?;
    validate_output_result(statement, 0, &preflight.first_result)?;
    validate_output_result(statement, 1, &preflight.second_result)?;
    Ok([
        preflight.first_result.clone(),
        preflight.second_result.clone(),
    ])
}

fn validate_intent_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    result: &Poseidon2P24IntentExperimentResult,
) -> Result<(), CandidateOutputNotesError> {
    if result.intent_commitment != statement.air_public_inputs().intent_commitment() {
        return Err(CandidateOutputNotesError::IntentCommitmentMismatch);
    }
    Ok(())
}

fn validate_output_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    output_index: usize,
    result: &Poseidon2P24NoteExperimentResult,
) -> Result<(), CandidateOutputNotesError> {
    let actual = NoteCommitmentV2::from_elements(result.note_commitment)?;
    let expected = statement.air_public_inputs().intent().outputs()[output_index].commitment();
    if actual != expected {
        return Err(CandidateOutputNotesError::OutputCommitmentMismatch { output_index });
    }
    Ok(())
}

/// Fail-closed errors while binding the separate public intent and output-note
/// relations. They never contain a note preimage or other secret witness data.
#[derive(Debug)]
pub enum CandidateOutputNotesError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    Stark(StarkExperimentError),
    PublicValue(PrivacyTypesError),
    StatementIdMismatch,
    IntentCommitmentMismatch,
    OutputCommitmentMismatch { output_index: usize },
}

impl From<CandidatePrivateTransferProofPublicStatementError> for CandidateOutputNotesError {
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}

impl From<StarkExperimentError> for CandidateOutputNotesError {
    fn from(value: StarkExperimentError) -> Self {
        Self::Stark(value)
    }
}

impl From<PrivacyTypesError> for CandidateOutputNotesError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PublicValue(value)
    }
}

impl fmt::Display for CandidateOutputNotesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate output-notes error: {self:?}")
    }
}

impl std::error::Error for CandidateOutputNotesError {}

#[cfg(test)]
mod tests {
    use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NullifierV2, PrivateTransferIntentCommitmentV2,
        PrivateTransferIntentV2, PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };

    fn vector(value: u32) -> [u32; 16] {
        [value; 16]
    }

    fn note(seed: u8) -> [u8; 178] {
        core::array::from_fn(|index| (index as u8).wrapping_mul(23).wrapping_add(seed))
    }

    fn statement_for_outputs(
        output_notes: [[u8; 178]; 2],
    ) -> (
        CandidatePrivateTransferProofPublicStatementV1,
        NullifierSparseTreeStateV1,
        [CandidateOutputNoteWitnessV1; 2],
    ) {
        let privacy = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let tree_reference = Poseidon2P24Reference::load_candidate().unwrap();
        let mut outputs = output_notes.map(|note_preimage| {
            let commitment =
                NoteCommitmentV2::from_elements(privacy.hash_note(&note_preimage).unwrap())
                    .unwrap();
            (commitment, note_preimage)
        });
        outputs.sort_by_key(|(commitment, _)| commitment.as_bytes());
        assert_ne!(outputs[0].0, outputs[1].0);

        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![
                NoteCommitmentV2::from_elements(vector(3)).unwrap(),
                NoteCommitmentV2::from_elements(vector(7)).unwrap(),
            ],
            vec![
                NullifierV2::from_elements(vector(3)).unwrap(),
                NullifierV2::from_elements(vector(7)).unwrap(),
            ],
            &tree_reference,
        )
        .unwrap();
        let mut pre_tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for spent in snapshot.spent_nullifiers() {
            pre_tree.mark_spent(*spent).unwrap();
        }
        let tree_parameters = TreeParametersV2::new(TreeParametersId::new(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()
                .unwrap()
                .as_bytes(),
        ));
        let anchor = PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            tree_parameters,
            &snapshot,
            &pre_tree,
        )
        .unwrap();
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([5; 32]),
            [
                NullifierV2::from_elements(vector(11)).unwrap(),
                NullifierV2::from_elements(vector(13)).unwrap(),
            ],
            [
                PrivateTransferOutputV2::new(
                    outputs[0].0,
                    CiphertextDigestV2::from_elements(vector(17)).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    outputs[1].0,
                    CiphertextDigestV2::from_elements(vector(19)).unwrap(),
                ),
            ],
        )
        .unwrap();
        let statement =
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &pre_tree, intent).unwrap();
        (
            statement,
            pre_tree,
            [
                CandidateOutputNoteWitnessV1::new(outputs[0].1),
                CandidateOutputNoteWitnessV1::new(outputs[1].1),
            ],
        )
    }

    #[test]
    fn locally_binds_two_private_output_notes_to_one_canonical_intent() {
        let (statement, pre_tree, witnesses) = statement_for_outputs([note(9), note(21)]);
        let preflight =
            run_candidate_intent_output_notes_preflight(&statement, &pre_tree, &witnesses).unwrap();
        let results =
            revalidate_candidate_intent_output_notes_preflight(&preflight, &statement, &pre_tree)
                .unwrap();
        assert_eq!(
            results[0].note_commitment,
            statement.air_public_inputs().intent().outputs()[0]
                .commitment()
                .elements()
        );
        assert_eq!(
            results[1].note_commitment,
            statement.air_public_inputs().intent().outputs()[1]
                .commitment()
                .elements()
        );
        assert_eq!(
            preflight.intent_result().intent_commitment,
            statement.air_public_inputs().intent_commitment()
        );
        assert_eq!(preflight.first_result(), &results[0]);
        assert_eq!(preflight.second_result(), &results[1]);
        assert_eq!(preflight.statement_id(), statement.statement_id());
    }

    #[test]
    fn rejects_a_retained_result_for_the_wrong_output_slot() {
        let (statement, pre_tree, _) = statement_for_outputs([note(9), note(21)]);
        let incorrect = Poseidon2P24NoteExperimentResult {
            note_commitment: statement.air_public_inputs().intent().outputs()[1]
                .commitment()
                .elements(),
            trace_rows: 256,
        };
        assert!(matches!(
            validate_output_result(&statement, 0, &incorrect),
            Err(CandidateOutputNotesError::OutputCommitmentMismatch { output_index: 0 })
        ));

        let intent_result = Poseidon2P24IntentExperimentResult {
            intent_commitment: statement.air_public_inputs().intent_commitment(),
            trace_rows: 1024,
        };
        let mut receipt = CandidateIntentOutputNotesPreflightV1 {
            intent_result,
            first_result: incorrect.clone(),
            second_result: incorrect,
            statement_id: statement.statement_id(),
        };
        let mut changed = receipt.intent_result.intent_commitment.elements();
        changed[0] = changed[0].wrapping_add(1);
        receipt.intent_result.intent_commitment =
            PrivateTransferIntentCommitmentV2::from_elements(changed).unwrap();
        assert!(matches!(
            revalidate_candidate_intent_output_notes_preflight(&receipt, &statement, &pre_tree),
            Err(CandidateOutputNotesError::IntentCommitmentMismatch)
        ));
    }
}
