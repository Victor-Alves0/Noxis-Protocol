//! One executable local preflight over every currently implemented candidate
//! private-transfer proof relation.
//!
//! The relations are still proved independently and sequentially. This module
//! makes their shared statement boundary executable without representing that
//! sequence as an aggregate proof, a selected verifier or a ledger transition.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_stark_experiment::{
    Poseidon2P24IntentExperimentResult, Poseidon2P24NoteWithAssetExperimentResult,
    Poseidon2P24OwnershipExperimentResult, StarkExperimentError, prove_and_verify_p24_intent,
};

use crate::{
    CandidateAnchoredOwnershipError, CandidateAnchoredOwnershipPairPreflightV1,
    CandidateAnchoredOwnershipWitnessV1, CandidateNxsmNullifierTransitionWitnessError,
    CandidateNxsmNullifierTransitionWitnessV1, CandidateOutputNoteWitnessV1,
    CandidateOutputNotesError, CandidateOutputNotesPreflightV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1,
    revalidate_candidate_anchored_ownership_pair_preflight,
    revalidate_candidate_output_notes_preflight, run_candidate_anchored_ownership_pair_preflight,
    run_candidate_output_notes_preflight,
};

/// Public results retained after the complete sequential candidate preflight.
///
/// The opaque STARK proof objects have already been verified and dropped. These
/// results cannot be submitted or independently verified by another process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferStarkPreflightResultsV1 {
    /// Public `H_INTENT` result for the canonical 640-byte intent.
    pub intent: Poseidon2P24IntentExperimentResult,
    /// Public ownership results for canonical input slots zero and one.
    pub inputs: [Poseidon2P24OwnershipExperimentResult; 2],
    /// Public `H_NOTE` results for canonical output slots zero and one.
    pub outputs: [Poseidon2P24NoteWithAssetExperimentResult; 2],
}

/// Receipt from one complete run of the currently available proof relations.
///
/// It proves `H_INTENT` exactly once, then sequentially checks two input
/// ownership relations and two output-note relations against one `NXPU v1`
/// statement. The `NXSM` witness remains transparent local material. This is
/// operational composition only: it is not an AIR composition or proof
/// recursion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferStarkPreflightV1 {
    intent_result: Poseidon2P24IntentExperimentResult,
    ownership: CandidateAnchoredOwnershipPairPreflightV1,
    outputs: CandidateOutputNotesPreflightV1,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

impl CandidatePrivateTransferStarkPreflightV1 {
    /// Public `H_INTENT` result shared by the complete run.
    pub const fn intent_result(&self) -> &Poseidon2P24IntentExperimentResult {
        &self.intent_result
    }

    /// Ownership-only receipt for the two canonical input slots.
    pub const fn ownership(&self) -> &CandidateAnchoredOwnershipPairPreflightV1 {
        &self.ownership
    }

    /// Output-note-only receipt for the two canonical output slots.
    pub const fn outputs(&self) -> &CandidateOutputNotesPreflightV1 {
        &self.outputs
    }

    /// Identity of the exact `NXPU v1` statement used by every relation.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }
}

/// Executes every currently available candidate proof relation for a fixed 2×2
/// private-transfer statement.
///
/// First `H_INTENT` is proved and verified once. Then both input ownership
/// proofs and both output `H_NOTE` proofs run sequentially. Every result is
/// bound to the same statement identity before it is retained.
pub fn run_candidate_private_transfer_stark_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    input_witnesses: &[CandidateAnchoredOwnershipWitnessV1; 2],
    output_witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<CandidatePrivateTransferStarkPreflightV1, CandidatePrivateTransferStarkPreflightError> {
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;

    let intent_result = prove_and_verify_p24_intent(statement.air_public_inputs().intent())?;
    validate_intent_result(statement, &intent_result)?;
    let ownership = run_candidate_anchored_ownership_pair_preflight(
        statement,
        pre_tree,
        nxsm_witness,
        &input_witnesses[0],
        &input_witnesses[1],
    )?;
    let outputs = run_candidate_output_notes_preflight(statement, pre_tree, output_witnesses)?;

    Ok(CandidatePrivateTransferStarkPreflightV1 {
        intent_result,
        ownership,
        outputs,
        statement_id: statement.statement_id(),
    })
}

/// Rechecks every retained public and transparent-state binding from a
/// completed complete preflight. It cannot reverify the discarded proofs.
pub fn revalidate_candidate_private_transfer_stark_preflight(
    preflight: &CandidatePrivateTransferStarkPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
) -> Result<
    CandidatePrivateTransferStarkPreflightResultsV1,
    CandidatePrivateTransferStarkPreflightError,
> {
    if preflight.statement_id != statement.statement_id() {
        return Err(CandidatePrivateTransferStarkPreflightError::StatementIdMismatch);
    }
    validate_intent_result(statement, &preflight.intent_result)?;
    let inputs = revalidate_candidate_anchored_ownership_pair_preflight(
        &preflight.ownership,
        statement,
        pre_tree,
        nxsm_witness,
    )?;
    let outputs =
        revalidate_candidate_output_notes_preflight(&preflight.outputs, statement, pre_tree)?;
    Ok(CandidatePrivateTransferStarkPreflightResultsV1 {
        intent: preflight.intent_result.clone(),
        inputs,
        outputs,
    })
}

fn validate_intent_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    result: &Poseidon2P24IntentExperimentResult,
) -> Result<(), CandidatePrivateTransferStarkPreflightError> {
    if result.intent_commitment != statement.air_public_inputs().intent_commitment() {
        return Err(CandidatePrivateTransferStarkPreflightError::IntentCommitmentMismatch);
    }
    Ok(())
}

/// Fail-closed errors from the complete sequential candidate preflight.
#[derive(Debug)]
pub enum CandidatePrivateTransferStarkPreflightError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    NxsmWitness(CandidateNxsmNullifierTransitionWitnessError),
    Ownership(CandidateAnchoredOwnershipError),
    OutputNotes(CandidateOutputNotesError),
    Stark(StarkExperimentError),
    StatementIdMismatch,
    IntentCommitmentMismatch,
}

impl From<CandidatePrivateTransferProofPublicStatementError>
    for CandidatePrivateTransferStarkPreflightError
{
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}

impl From<CandidateNxsmNullifierTransitionWitnessError>
    for CandidatePrivateTransferStarkPreflightError
{
    fn from(value: CandidateNxsmNullifierTransitionWitnessError) -> Self {
        Self::NxsmWitness(value)
    }
}

impl From<CandidateAnchoredOwnershipError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: CandidateAnchoredOwnershipError) -> Self {
        Self::Ownership(value)
    }
}

impl From<CandidateOutputNotesError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: CandidateOutputNotesError) -> Self {
        Self::OutputNotes(value)
    }
}

impl From<StarkExperimentError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: StarkExperimentError) -> Self {
        Self::Stark(value)
    }
}

impl fmt::Display for CandidatePrivateTransferStarkPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-transfer STARK preflight error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateTransferStarkPreflightError {}

#[cfg(test)]
mod tests {
    use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2,
        PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2, PrivateTransferOutputV2,
        TreeParametersId, TreeParametersV2,
    };
    use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;

    fn vector(value: u32) -> [u32; 16] {
        [value; 16]
    }

    fn note_with_recipient(recipient: [u32; 16], seed: u8) -> [u8; 178] {
        let mut note =
            core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(seed));
        note[..2].copy_from_slice(&1_u16.to_be_bytes());
        for (lane, value) in recipient.into_iter().enumerate() {
            note[50 + (lane * 4)..54 + (lane * 4)].copy_from_slice(&value.to_le_bytes());
        }
        note
    }

    fn nullifier_preimage(
        key: [u8; 32],
        note: [u8; 178],
        commitment: [u32; 16],
        position: u32,
    ) -> [u8; 132] {
        let mut bytes = [0_u8; 132];
        bytes[..32].copy_from_slice(&key);
        bytes[32..64].copy_from_slice(&note[114..146]);
        for (lane, value) in commitment.into_iter().enumerate() {
            bytes[64 + (lane * 4)..68 + (lane * 4)].copy_from_slice(&value.to_le_bytes());
        }
        bytes[128..].copy_from_slice(&position.to_be_bytes());
        bytes
    }

    #[test]
    fn executes_every_available_private_relation_for_one_statement() {
        let privacy = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let tree_reference = Poseidon2P24Reference::load_candidate().unwrap();
        let first_key =
            core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(3));
        let second_key =
            core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(5));
        let first_note = note_with_recipient(privacy.hash_addr(&first_key).unwrap(), 7);
        let second_note = note_with_recipient(privacy.hash_addr(&second_key).unwrap(), 11);
        let first_commitment = privacy.hash_note(&first_note).unwrap();
        let second_commitment = privacy.hash_note(&second_note).unwrap();
        let (_, first_siblings, root) = tree_reference
            .small_tree_path(&[first_commitment, second_commitment], 0)
            .unwrap();
        let (_, second_siblings, second_root) = tree_reference
            .small_tree_path(&[first_commitment, second_commitment], 1)
            .unwrap();
        assert_eq!(root, second_root);

        let first_nullifier = NullifierV2::from_elements(
            privacy
                .hash_nullifier_preimage(&nullifier_preimage(
                    first_key,
                    first_note,
                    first_commitment,
                    0,
                ))
                .unwrap(),
        )
        .unwrap();
        let second_nullifier = NullifierV2::from_elements(
            privacy
                .hash_nullifier_preimage(&nullifier_preimage(
                    second_key,
                    second_note,
                    second_commitment,
                    1,
                ))
                .unwrap(),
        )
        .unwrap();
        let first_witness =
            CandidateAnchoredOwnershipWitnessV1::new(first_key, first_note, 0, first_siblings);
        let second_witness =
            CandidateAnchoredOwnershipWitnessV1::new(second_key, second_note, 1, second_siblings);
        let (nullifiers, input_witnesses) =
            if first_nullifier.as_bytes() < second_nullifier.as_bytes() {
                (
                    [first_nullifier, second_nullifier],
                    [first_witness, second_witness],
                )
            } else {
                (
                    [second_nullifier, first_nullifier],
                    [second_witness, first_witness],
                )
            };

        let mut output_one = note_with_recipient(privacy.hash_addr(&[21; 32]).unwrap(), 13);
        let mut output_two = note_with_recipient(privacy.hash_addr(&[37; 32]).unwrap(), 17);
        output_one[2..34].copy_from_slice(&[5; 32]);
        output_two[2..34].copy_from_slice(&[5; 32]);
        let mut outputs = [output_one, output_two].map(|note| {
            (
                NoteCommitmentV2::from_elements(privacy.hash_note(&note).unwrap()).unwrap(),
                note,
            )
        });
        outputs.sort_by_key(|(commitment, _)| commitment.as_bytes());
        assert_ne!(outputs[0].0, outputs[1].0);

        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![
                NoteCommitmentV2::from_elements(first_commitment).unwrap(),
                NoteCommitmentV2::from_elements(second_commitment).unwrap(),
            ],
            vec![
                NullifierV2::from_elements(vector(3)).unwrap(),
                NullifierV2::from_elements(vector(9)).unwrap(),
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
            nullifiers,
            [
                PrivateTransferOutputV2::new(
                    outputs[0].0,
                    CiphertextDigestV2::from_elements(vector(12)).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    outputs[1].0,
                    CiphertextDigestV2::from_elements(vector(13)).unwrap(),
                ),
            ],
        )
        .unwrap();
        let statement =
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &pre_tree, intent).unwrap();
        let nxsm_witness = CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(
            &pre_tree,
            statement.air_public_inputs().intent(),
        )
        .unwrap();
        let output_witnesses = [
            CandidateOutputNoteWitnessV1::new(outputs[0].1),
            CandidateOutputNoteWitnessV1::new(outputs[1].1),
        ];

        let preflight = run_candidate_private_transfer_stark_preflight(
            &statement,
            &pre_tree,
            &nxsm_witness,
            &input_witnesses,
            &output_witnesses,
        )
        .unwrap();
        let results = revalidate_candidate_private_transfer_stark_preflight(
            &preflight,
            &statement,
            &pre_tree,
            &nxsm_witness,
        )
        .unwrap();
        assert_eq!(
            results.intent.intent_commitment,
            statement.air_public_inputs().intent_commitment()
        );
        assert_eq!(
            results.inputs[0].nullifier,
            statement.air_public_inputs().intent().nullifiers()[0].elements()
        );
        assert_eq!(
            results.inputs[1].nullifier,
            statement.air_public_inputs().intent().nullifiers()[1].elements()
        );
        assert_eq!(results.inputs[0].root, root);
        assert_eq!(results.inputs[1].root, root);
        assert_eq!(results.outputs[0].note_commitment, outputs[0].0.elements());
        assert_eq!(results.outputs[1].note_commitment, outputs[1].0.elements());
        assert_eq!(preflight.statement_id(), statement.statement_id());

        let mut corrupted = preflight.clone();
        let mut changed = corrupted.intent_result.intent_commitment.elements();
        changed[0] = changed[0].wrapping_add(1);
        corrupted.intent_result.intent_commitment =
            PrivateTransferIntentCommitmentV2::from_elements(changed).unwrap();
        assert!(matches!(
            revalidate_candidate_private_transfer_stark_preflight(
                &corrupted,
                &statement,
                &pre_tree,
                &nxsm_witness,
            ),
            Err(CandidatePrivateTransferStarkPreflightError::IntentCommitmentMismatch)
        ));
    }
}
