//! Local witness for the sequential `NXSM` nullifier transition.
//!
//! The two sparse-tree paths remain local so a future prover can turn this
//! relation into constraints. This module deliberately has no wire encoding,
//! proof backend, ledger transition, or consensus dependency.

use std::fmt;

use noxis_nullifier_tree_reference::{NullifierSparseTreeReferenceV1, NullifierTreeReferenceError};
use noxis_nullifier_tree_state::{
    NullifierSparseProofV1, NullifierSparseTreeStateError, NullifierSparseTreeStateV1,
};
use noxis_privacy_types::PrivateTransferIntentV2;
use noxis_tree_params::{
    CandidatePoseidon2P24NullifierSparseManifestV1, Poseidon2P24NullifierSparseCandidateError,
};

use crate::CandidateNxsmNullifierTransitionV1;

/// Private path material for the ordered two-nullifier `NXSM` update.
///
/// The first path proves absence at the pre-root. The second proves absence
/// after the first insertion, because the two paths can overlap. Keeping that
/// ordering explicit prevents a future prover from incorrectly treating two
/// independently pre-state paths as one atomic update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateNxsmNullifierTransitionWitnessV1 {
    first_absence_path: NullifierSparseProofV1,
    second_absence_path: NullifierSparseProofV1,
}

impl CandidateNxsmNullifierTransitionWitnessV1 {
    /// Derives the local paths from candidate state in the same canonical
    /// nullifier order frozen by `PrivateTransferIntentV2`.
    pub fn from_pre_tree(
        pre_tree: &NullifierSparseTreeStateV1,
        intent: &PrivateTransferIntentV2,
    ) -> Result<Self, CandidateNxsmNullifierTransitionWitnessError> {
        let [first, second] = *intent.nullifiers();
        if pre_tree.is_spent(first) {
            return Err(
                CandidateNxsmNullifierTransitionWitnessError::InputAlreadySpent { index: 0 },
            );
        }
        let first_absence_path = pre_tree.prove(first);

        let mut after_first = pre_tree.clone();
        after_first.mark_spent(first)?;
        if after_first.is_spent(second) {
            return Err(
                CandidateNxsmNullifierTransitionWitnessError::InputAlreadySpent { index: 1 },
            );
        }
        let second_absence_path = after_first.prove(second);

        Ok(Self {
            first_absence_path,
            second_absence_path,
        })
    }

    /// Replays the two private paths against an already-built public `NXNT`
    /// statement. It checks both absence relations and the exact intermediate
    /// root between the ordered insertions.
    pub fn revalidate(
        &self,
        transition: &CandidateNxsmNullifierTransitionV1,
    ) -> Result<(), CandidateNxsmNullifierTransitionWitnessError> {
        let expected_candidate =
            CandidatePoseidon2P24NullifierSparseManifestV1::new().candidate_id()?;
        if transition.nullifier_tree_candidate() != expected_candidate {
            return Err(CandidateNxsmNullifierTransitionWitnessError::CandidateMismatch);
        }
        let expected_post_count = transition
            .pre_spent_count()
            .checked_add(2)
            .ok_or(CandidateNxsmNullifierTransitionWitnessError::SpentCountMismatch)?;
        if transition.post_spent_count() != expected_post_count {
            return Err(CandidateNxsmNullifierTransitionWitnessError::SpentCountMismatch);
        }

        let reference = NullifierSparseTreeReferenceV1::load_candidate()?;
        let [first, second] = *transition.nullifiers();
        reference.verify_absence(
            transition.pre_root(),
            first,
            self.first_absence_path.siblings(),
        )?;
        let intermediate_root = reference.root_from_path(
            first,
            reference.spent_leaf(first)?,
            self.first_absence_path.siblings(),
        )?;
        reference.verify_absence(
            intermediate_root,
            second,
            self.second_absence_path.siblings(),
        )?;
        let post_root = reference.root_from_path(
            second,
            reference.spent_leaf(second)?,
            self.second_absence_path.siblings(),
        )?;
        if post_root != transition.post_root() {
            return Err(CandidateNxsmNullifierTransitionWitnessError::PostRootMismatch);
        }
        Ok(())
    }
}

/// Fail-closed errors for the local ordered-nullifier witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateNxsmNullifierTransitionWitnessError {
    SparseTree(NullifierSparseTreeStateError),
    Reference(NullifierTreeReferenceError),
    Candidate(Poseidon2P24NullifierSparseCandidateError),
    InputAlreadySpent { index: usize },
    CandidateMismatch,
    SpentCountMismatch,
    PostRootMismatch,
}

impl From<NullifierSparseTreeStateError> for CandidateNxsmNullifierTransitionWitnessError {
    fn from(value: NullifierSparseTreeStateError) -> Self {
        Self::SparseTree(value)
    }
}

impl From<NullifierTreeReferenceError> for CandidateNxsmNullifierTransitionWitnessError {
    fn from(value: NullifierTreeReferenceError) -> Self {
        Self::Reference(value)
    }
}

impl From<Poseidon2P24NullifierSparseCandidateError>
    for CandidateNxsmNullifierTransitionWitnessError
{
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for CandidateNxsmNullifierTransitionWitnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate NXSM nullifier-transition witness error: {self:?}"
        )
    }
}

impl std::error::Error for CandidateNxsmNullifierTransitionWitnessError {}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferOutputV2,
        TreeParametersId,
    };
    use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;

    fn commitment(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }

    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }

    fn pre_tree() -> NullifierSparseTreeStateV1 {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        tree.mark_spent(nullifier(3)).unwrap();
        tree.mark_spent(nullifier(9)).unwrap();
        tree
    }

    fn anchor(tree: &NullifierSparseTreeStateV1) -> PrivateStateAnchorV2 {
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![nullifier(3), nullifier(9)],
            &noxis_poseidon2_reference::Poseidon2P24Reference::load_candidate().unwrap(),
        )
        .unwrap();
        PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            noxis_privacy_types::TreeParametersV2::new(TreeParametersId::new([3; 32])),
            &snapshot,
            tree,
        )
        .unwrap()
    }

    fn intent(anchor: &PrivateStateAnchorV2) -> PrivateTransferIntentV2 {
        PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([5; 32]),
            [nullifier(10), nullifier(11)],
            [
                PrivateTransferOutputV2::new(
                    commitment(12),
                    CiphertextDigestV2::from_elements([12; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    commitment(13),
                    CiphertextDigestV2::from_elements([13; 16]).unwrap(),
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn ordered_paths_bind_the_pre_intermediate_and_post_roots() {
        let tree = pre_tree();
        let anchor = anchor(&tree);
        let intent = intent(&anchor);
        let transition = CandidateNxsmNullifierTransitionV1::new(&anchor, &tree, &intent).unwrap();
        let witness =
            CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(&tree, &intent).unwrap();

        assert_eq!(witness.revalidate(&transition), Ok(()));
    }

    #[test]
    fn refuses_to_derive_a_path_for_an_already_spent_input() {
        let tree = pre_tree();
        let anchor = anchor(&tree);
        let spent_intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([5; 32]),
            [nullifier(3), nullifier(10)],
            [
                PrivateTransferOutputV2::new(
                    commitment(12),
                    CiphertextDigestV2::from_elements([12; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    commitment(13),
                    CiphertextDigestV2::from_elements([13; 16]).unwrap(),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(&tree, &spent_intent),
            Err(CandidateNxsmNullifierTransitionWitnessError::InputAlreadySpent { index: 0 })
        );
    }
}
