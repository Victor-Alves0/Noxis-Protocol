//! Transparent, in-memory candidate application of one fixed 2×2 private
//! transfer to the note and nullifier state domains.
//!
//! This module deliberately owns state mutation only. It does not consume a
//! proof, ciphertext, network packet, ledger or consensus decision. A future
//! selected verifier must authorize this exact kind of transition before any
//! persistent or shared state uses it.

use std::fmt;

use noxis_nullifier_tree_state::{NullifierSparseTreeStateError, NullifierSparseTreeStateV1};
use noxis_poseidon2_reference::Poseidon2P24Reference;
use noxis_privacy_types::PrivateTransferIntentV2;

use crate::{
    CandidatePrivateStateError, CandidatePrivateStateSnapshotV1, PrivateStateAnchorError,
    PrivateStateAnchorV2, PrivateStateAnchorV2Error,
};

/// Result of applying the transparent candidate note-append and nullifier-spend
/// relation for one canonical 2×2 intent.
///
/// The post-state is intentionally returned only in memory. This is not a
/// proof receipt, an authorization or a persistent state transition.
#[derive(Clone, Debug)]
pub struct CandidatePrivateStateTransitionV2 {
    pre_anchor: PrivateStateAnchorV2,
    post_anchor: PrivateStateAnchorV2,
    post_snapshot: CandidatePrivateStateSnapshotV1,
    post_tree: NullifierSparseTreeStateV1,
}

impl CandidatePrivateStateTransitionV2 {
    /// Applies the two canonical output commitments and two canonical input
    /// nullifiers to one exact `NXPS v2` pre-state.
    ///
    /// The function first rebuilds the supplied pre-anchor from the snapshot
    /// and tree, rejects already-spent inputs, appends outputs in intent order,
    /// then builds a fresh typed post-anchor. No caller-provided post-root or
    /// leaf index is accepted.
    pub fn apply(
        pre_anchor: &PrivateStateAnchorV2,
        pre_snapshot: &CandidatePrivateStateSnapshotV1,
        pre_tree: &NullifierSparseTreeStateV1,
        intent: &PrivateTransferIntentV2,
        reference: &Poseidon2P24Reference,
    ) -> Result<Self, CandidatePrivateStateTransitionV2Error> {
        let rebuilt_pre_anchor = PrivateStateAnchorV2::new(
            pre_anchor.genesis_id(),
            pre_anchor.validation_context_id(),
            pre_anchor.note_tree_parameters(),
            pre_snapshot,
            pre_tree,
        )?;
        if rebuilt_pre_anchor != *pre_anchor {
            return Err(CandidatePrivateStateTransitionV2Error::PreAnchorMismatch);
        }
        pre_anchor.assert_matches_intent(intent)?;

        let nullifiers = *intent.nullifiers();
        for (index, nullifier) in nullifiers.into_iter().enumerate() {
            if pre_tree.is_spent(nullifier) {
                return Err(CandidatePrivateStateTransitionV2Error::InputAlreadySpent { index });
            }
        }

        let mut post_tree = pre_tree.clone();
        for nullifier in nullifiers {
            post_tree.mark_spent(nullifier)?;
        }

        let mut commitments = pre_snapshot.commitments().to_vec();
        commitments.extend(intent.output_commitments());
        let mut spent_nullifiers = pre_snapshot.spent_nullifiers().to_vec();
        spent_nullifiers.extend(nullifiers);
        let post_snapshot =
            CandidatePrivateStateSnapshotV1::new(commitments, spent_nullifiers, reference)?;
        let post_anchor = PrivateStateAnchorV2::new(
            pre_anchor.genesis_id(),
            pre_anchor.validation_context_id(),
            pre_anchor.note_tree_parameters(),
            &post_snapshot,
            &post_tree,
        )?;

        Ok(Self {
            pre_anchor: pre_anchor.clone(),
            post_anchor,
            post_snapshot,
            post_tree,
        })
    }

    /// Exact validated pre-anchor consumed by this in-memory transition.
    pub const fn pre_anchor(&self) -> &PrivateStateAnchorV2 {
        &self.pre_anchor
    }

    /// Fresh post-anchor derived from outputs and spent input nullifiers.
    pub const fn post_anchor(&self) -> &PrivateStateAnchorV2 {
        &self.post_anchor
    }

    /// Canonical post-snapshot with outputs appended in intent order.
    pub const fn post_snapshot(&self) -> &CandidatePrivateStateSnapshotV1 {
        &self.post_snapshot
    }

    /// Mutable candidate `NXSM` tree after both nullifiers are marked spent.
    pub const fn post_tree(&self) -> &NullifierSparseTreeStateV1 {
        &self.post_tree
    }

    /// Rebuilds the complete transparent transition and rejects changed post
    /// state. It cannot stand in for proof verification.
    pub fn revalidate(
        &self,
        pre_anchor: &PrivateStateAnchorV2,
        pre_snapshot: &CandidatePrivateStateSnapshotV1,
        pre_tree: &NullifierSparseTreeStateV1,
        intent: &PrivateTransferIntentV2,
        reference: &Poseidon2P24Reference,
    ) -> Result<(), CandidatePrivateStateTransitionV2Error> {
        let expected = Self::apply(pre_anchor, pre_snapshot, pre_tree, intent, reference)?;
        if expected.pre_anchor != self.pre_anchor
            || expected.post_anchor != self.post_anchor
            || expected.post_snapshot != self.post_snapshot
            || expected.post_tree.root()? != self.post_tree.root()?
            || expected.post_tree.spent_count() != self.post_tree.spent_count()
        {
            return Err(CandidatePrivateStateTransitionV2Error::PostStateMismatch);
        }
        Ok(())
    }
}

/// Fail-closed errors while applying the transparent candidate relation.
#[derive(Debug)]
pub enum CandidatePrivateStateTransitionV2Error {
    Snapshot(CandidatePrivateStateError),
    PreAnchor(PrivateStateAnchorV2Error),
    Intent(PrivateStateAnchorError),
    SparseTree(NullifierSparseTreeStateError),
    PreAnchorMismatch,
    InputAlreadySpent { index: usize },
    PostStateMismatch,
}

impl From<CandidatePrivateStateError> for CandidatePrivateStateTransitionV2Error {
    fn from(value: CandidatePrivateStateError) -> Self {
        Self::Snapshot(value)
    }
}

impl From<PrivateStateAnchorV2Error> for CandidatePrivateStateTransitionV2Error {
    fn from(value: PrivateStateAnchorV2Error) -> Self {
        Self::PreAnchor(value)
    }
}

impl From<PrivateStateAnchorError> for CandidatePrivateStateTransitionV2Error {
    fn from(value: PrivateStateAnchorError) -> Self {
        Self::Intent(value)
    }
}

impl From<NullifierSparseTreeStateError> for CandidatePrivateStateTransitionV2Error {
    fn from(value: NullifierSparseTreeStateError) -> Self {
        Self::SparseTree(value)
    }
}

impl fmt::Display for CandidatePrivateStateTransitionV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-state transition error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateStateTransitionV2Error {}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferOutputV2,
        TreeParametersId, TreeParametersV2,
    };
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;

    fn commitment(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }

    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }

    fn pre_state(
        reference: &Poseidon2P24Reference,
    ) -> (
        CandidatePrivateStateSnapshotV1,
        NullifierSparseTreeStateV1,
        PrivateStateAnchorV2,
    ) {
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![nullifier(3), nullifier(9)],
            reference,
        )
        .unwrap();
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for spent in snapshot.spent_nullifiers() {
            tree.mark_spent(*spent).unwrap();
        }
        let anchor = PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            TreeParametersV2::new(TreeParametersId::new([4; 32])),
            &snapshot,
            &tree,
        )
        .unwrap();
        (snapshot, tree, anchor)
    }

    fn intent(
        anchor: &PrivateStateAnchorV2,
        nullifiers: [NullifierV2; 2],
    ) -> PrivateTransferIntentV2 {
        PrivateTransferIntentV2::new(
            CircuitId::new([5; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([6; 32]),
            nullifiers,
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
    fn atomically_derives_the_post_note_and_nullifier_state_from_one_intent() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let (snapshot, tree, anchor) = pre_state(&reference);
        let intent = intent(&anchor, [nullifier(10), nullifier(11)]);
        let transition = CandidatePrivateStateTransitionV2::apply(
            &anchor, &snapshot, &tree, &intent, &reference,
        )
        .unwrap();

        assert_eq!(transition.pre_anchor(), &anchor);
        assert_eq!(
            transition.post_snapshot().commitments(),
            &[commitment(1), commitment(2), commitment(12), commitment(13)]
        );
        assert_eq!(
            transition.post_snapshot().spent_nullifiers(),
            &[nullifier(3), nullifier(9), nullifier(10), nullifier(11)]
        );
        assert_ne!(transition.post_anchor().state_id(), anchor.state_id());
        assert_eq!(transition.post_anchor().next_leaf_index(), 4);
        assert_eq!(
            transition.post_anchor().note_root(),
            transition.post_snapshot().root()
        );
        assert_eq!(
            transition.post_anchor().nullifier_root(),
            transition.post_tree().root().unwrap()
        );
        assert!(transition.post_tree().is_spent(nullifier(10)));
        assert!(transition.post_tree().is_spent(nullifier(11)));
        transition
            .revalidate(&anchor, &snapshot, &tree, &intent, &reference)
            .unwrap();
    }

    #[test]
    fn rejects_an_already_spent_intent_nullifier_before_appending_outputs() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let (snapshot, tree, anchor) = pre_state(&reference);
        let intent = intent(&anchor, [nullifier(9), nullifier(11)]);
        assert!(matches!(
            CandidatePrivateStateTransitionV2::apply(
                &anchor, &snapshot, &tree, &intent, &reference
            ),
            Err(CandidatePrivateStateTransitionV2Error::InputAlreadySpent { index: 0 })
        ));
    }

    #[test]
    fn rejects_an_output_commitment_that_already_exists_in_the_pre_state() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let (snapshot, tree, anchor) = pre_state(&reference);
        let mut intent = intent(&anchor, [nullifier(10), nullifier(11)]);
        intent = PrivateTransferIntentV2::new(
            intent.circuit_id(),
            intent.genesis_id(),
            intent.validation_context_id(),
            intent.pre_state_id(),
            intent.tree_parameters(),
            intent.pre_state_root(),
            intent.asset_id(),
            *intent.nullifiers(),
            [
                PrivateTransferOutputV2::new(
                    commitment(1),
                    CiphertextDigestV2::from_elements([12; 16]).unwrap(),
                ),
                *intent.outputs().get(1).unwrap(),
            ],
        )
        .unwrap();
        assert!(matches!(
            CandidatePrivateStateTransitionV2::apply(
                &anchor, &snapshot, &tree, &intent, &reference
            ),
            Err(CandidatePrivateStateTransitionV2Error::Snapshot(
                CandidatePrivateStateError::DuplicateCommitment
            ))
        ));
    }
}
