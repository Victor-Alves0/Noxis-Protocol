//! Transparent local checks for the private-transfer value relation.
//!
//! The selected AIR does not exist yet, so this module deliberately does not
//! claim zero knowledge or return a transferable proof. It makes the same
//! fixed-width asset and value invariants executable at preflight time and
//! fails before any expensive candidate STARK relation starts.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;

use crate::{
    CandidateAnchoredOwnershipWitnessV1, CandidateOutputNoteWitnessV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1,
};

const NOTE_VERSION_OFFSET: usize = 0;
const NOTE_VERSION_LENGTH: usize = 2;
const ASSET_OFFSET: usize = NOTE_VERSION_OFFSET + NOTE_VERSION_LENGTH;
const ASSET_LENGTH: usize = 32;
const VALUE_OFFSET: usize = ASSET_OFFSET + ASSET_LENGTH;
const VALUE_LENGTH: usize = 16;
const CANDIDATE_NOTE_VERSION: u16 = 1;

/// Evidence that one process checked the fixed 2x2 value relation against the
/// exact candidate statement. It deliberately retains no private values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateValueConservationPreflightV1 {
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

impl CandidateValueConservationPreflightV1 {
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }
}

/// Validates the transparent private-witness value relation for one exact
/// 2x2 candidate statement.
///
/// Both input openings and both output openings must use the one public asset,
/// input values must be nonzero, each sum must fit `u128`, and the sums must
/// match. This must be reproduced inside a selected AIR before settlement; it
/// is only an early local preflight gate today.
pub fn run_candidate_value_conservation_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    input_witnesses: &[CandidateAnchoredOwnershipWitnessV1; 2],
    output_witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<CandidateValueConservationPreflightV1, CandidateValueConservationError> {
    statement.revalidate(pre_tree)?;
    let expected_asset = statement.air_public_inputs().intent().asset_id().0;
    let inputs = [
        parse_note(input_witnesses[0].note_preimage()),
        parse_note(input_witnesses[1].note_preimage()),
    ];
    let outputs = [
        parse_note(output_witnesses[0].note_preimage()),
        parse_note(output_witnesses[1].note_preimage()),
    ];

    for (index, note) in inputs.iter().enumerate() {
        validate_note(note, expected_asset, CandidateValueNoteRoleV1::Input, index)?;
        if note.value == 0 {
            return Err(CandidateValueConservationError::ZeroInputValue { index });
        }
    }
    for (index, note) in outputs.iter().enumerate() {
        validate_note(
            note,
            expected_asset,
            CandidateValueNoteRoleV1::Output,
            index,
        )?;
    }

    let input_sum = inputs[0]
        .value
        .checked_add(inputs[1].value)
        .ok_or(CandidateValueConservationError::InputSumOverflow)?;
    let output_sum = outputs[0]
        .value
        .checked_add(outputs[1].value)
        .ok_or(CandidateValueConservationError::OutputSumOverflow)?;
    if input_sum != output_sum {
        return Err(CandidateValueConservationError::ValueNotConserved);
    }

    Ok(CandidateValueConservationPreflightV1 {
        statement_id: statement.statement_id(),
    })
}

#[derive(Clone, Copy)]
struct ParsedCandidateNote {
    version: u16,
    asset: [u8; ASSET_LENGTH],
    value: u128,
}

fn parse_note(note: &[u8; 178]) -> ParsedCandidateNote {
    ParsedCandidateNote {
        version: u16::from_be_bytes(
            note[NOTE_VERSION_OFFSET..NOTE_VERSION_OFFSET + NOTE_VERSION_LENGTH]
                .try_into()
                .expect("fixed candidate note version slice"),
        ),
        asset: note[ASSET_OFFSET..ASSET_OFFSET + ASSET_LENGTH]
            .try_into()
            .expect("fixed candidate note asset slice"),
        value: u128::from_be_bytes(
            note[VALUE_OFFSET..VALUE_OFFSET + VALUE_LENGTH]
                .try_into()
                .expect("fixed candidate note value slice"),
        ),
    }
}

/// Whether a failed candidate opening belongs to an input or output slot.
/// This is public error metadata only; it never carries a note or value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateValueNoteRoleV1 {
    Input,
    Output,
}

fn validate_note(
    note: &ParsedCandidateNote,
    expected_asset: [u8; ASSET_LENGTH],
    role: CandidateValueNoteRoleV1,
    index: usize,
) -> Result<(), CandidateValueConservationError> {
    if note.version != CANDIDATE_NOTE_VERSION {
        return Err(CandidateValueConservationError::UnsupportedNoteVersion { role, index });
    }
    if note.asset != expected_asset {
        return Err(CandidateValueConservationError::AssetMismatch { role, index });
    }
    Ok(())
}

/// Fail-closed errors for the local value relation. None includes a private
/// value, asset identifier, note opening or key.
#[derive(Debug)]
pub enum CandidateValueConservationError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    UnsupportedNoteVersion {
        role: CandidateValueNoteRoleV1,
        index: usize,
    },
    AssetMismatch {
        role: CandidateValueNoteRoleV1,
        index: usize,
    },
    ZeroInputValue {
        index: usize,
    },
    InputSumOverflow,
    OutputSumOverflow,
    ValueNotConserved,
}

impl From<CandidatePrivateTransferProofPublicStatementError> for CandidateValueConservationError {
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}

impl fmt::Display for CandidateValueConservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicStatement(error) => write!(
                formatter,
                "candidate value relation rejected public statement: {error}"
            ),
            Self::UnsupportedNoteVersion { role, index } => {
                write!(
                    formatter,
                    "candidate value relation rejected {} note {index}: unsupported version",
                    role.label()
                )
            }
            Self::AssetMismatch { role, index } => {
                write!(
                    formatter,
                    "candidate value relation rejected {} note {index}: asset mismatches intent",
                    role.label()
                )
            }
            Self::ZeroInputValue { index } => {
                write!(
                    formatter,
                    "candidate value relation rejected input note {index}: zero value"
                )
            }
            Self::InputSumOverflow => {
                formatter.write_str("candidate value relation input sum overflows u128")
            }
            Self::OutputSumOverflow => {
                formatter.write_str("candidate value relation output sum overflows u128")
            }
            Self::ValueNotConserved => {
                formatter.write_str("candidate value relation does not conserve value")
            }
        }
    }
}

impl std::error::Error for CandidateValueConservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PublicStatement(error) => Some(error),
            _ => None,
        }
    }
}

impl CandidateValueNoteRoleV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }
}

#[cfg(test)]
mod tests {
    use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };
    use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;

    fn note(asset: [u8; 32], value: u128) -> [u8; 178] {
        let mut note = [0_u8; 178];
        note[..2].copy_from_slice(&CANDIDATE_NOTE_VERSION.to_be_bytes());
        note[ASSET_OFFSET..ASSET_OFFSET + ASSET_LENGTH].copy_from_slice(&asset);
        note[VALUE_OFFSET..VALUE_OFFSET + VALUE_LENGTH].copy_from_slice(&value.to_be_bytes());
        note
    }

    fn fixture() -> (
        CandidatePrivateTransferProofPublicStatementV1,
        NullifierSparseTreeStateV1,
    ) {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let snapshot = CandidatePrivateStateSnapshotV1::new(vec![], vec![], &reference).unwrap();
        let tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
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
            &tree,
        )
        .unwrap();
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([3; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([4; 32]),
            [
                NullifierV2::from_elements([5; 16]).unwrap(),
                NullifierV2::from_elements([6; 16]).unwrap(),
            ],
            [
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::from_elements([7; 16]).unwrap(),
                    CiphertextDigestV2::from_elements([8; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::from_elements([9; 16]).unwrap(),
                    CiphertextDigestV2::from_elements([10; 16]).unwrap(),
                ),
            ],
        )
        .unwrap();
        (
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &tree, intent).unwrap(),
            tree,
        )
    }

    fn inputs(
        asset: [u8; 32],
        first: u128,
        second: u128,
    ) -> [CandidateAnchoredOwnershipWitnessV1; 2] {
        [
            CandidateAnchoredOwnershipWitnessV1::new([1; 32], note(asset, first), 0, [[0; 16]; 32]),
            CandidateAnchoredOwnershipWitnessV1::new(
                [2; 32],
                note(asset, second),
                1,
                [[0; 16]; 32],
            ),
        ]
    }

    fn outputs(asset: [u8; 32], first: u128, second: u128) -> [CandidateOutputNoteWitnessV1; 2] {
        [
            CandidateOutputNoteWitnessV1::new(note(asset, first)),
            CandidateOutputNoteWitnessV1::new(note(asset, second)),
        ]
    }

    #[test]
    fn accepts_fixed_width_conserved_values_without_retaining_them() {
        let (statement, tree) = fixture();
        let asset = statement.air_public_inputs().intent().asset_id().0;
        let receipt = run_candidate_value_conservation_preflight(
            &statement,
            &tree,
            &inputs(asset, 17, 23),
            &outputs(asset, 20, 20),
        )
        .unwrap();
        assert_eq!(receipt.statement_id(), statement.statement_id());
    }

    #[test]
    fn rejects_zero_mismatched_or_overflowing_value_relations() {
        let (statement, tree) = fixture();
        let asset = statement.air_public_inputs().intent().asset_id().0;
        assert!(matches!(
            run_candidate_value_conservation_preflight(
                &statement,
                &tree,
                &inputs(asset, 0, 40),
                &outputs(asset, 20, 20),
            ),
            Err(CandidateValueConservationError::ZeroInputValue { index: 0 })
        ));
        assert!(matches!(
            run_candidate_value_conservation_preflight(
                &statement,
                &tree,
                &inputs(asset, 30, 10),
                &outputs(asset, 20, 19),
            ),
            Err(CandidateValueConservationError::ValueNotConserved)
        ));
        assert!(matches!(
            run_candidate_value_conservation_preflight(
                &statement,
                &tree,
                &inputs(asset, u128::MAX, 1),
                &outputs(asset, 20, 20),
            ),
            Err(CandidateValueConservationError::InputSumOverflow)
        ));
        assert!(matches!(
            run_candidate_value_conservation_preflight(
                &statement,
                &tree,
                &inputs(asset, 20, 20),
                &outputs(asset, u128::MAX, 1),
            ),
            Err(CandidateValueConservationError::OutputSumOverflow)
        ));
    }

    #[test]
    fn rejects_an_asset_mismatch_without_revealing_the_asset() {
        let (statement, tree) = fixture();
        let asset = statement.air_public_inputs().intent().asset_id().0;
        assert!(matches!(
            run_candidate_value_conservation_preflight(
                &statement,
                &tree,
                &inputs([99; 32], 20, 20),
                &outputs(asset, 20, 20),
            ),
            Err(CandidateValueConservationError::AssetMismatch {
                role: CandidateValueNoteRoleV1::Input,
                index: 0,
            })
        ));
    }
}
