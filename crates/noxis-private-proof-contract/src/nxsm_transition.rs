//! Executable public candidate relation for one `NXSM` nullifier transition.
//!
//! It is intentionally transparent and in-memory: the type states what a
//! future AIR must prove, but it neither contains a proof nor authorizes a
//! ledger, consensus, persistence, or network mutation.

use std::fmt;

use noxis_nullifier_tree_reference::NullifierSparseRootV1;
use noxis_nullifier_tree_state::{NullifierSparseTreeStateError, NullifierSparseTreeStateV1};
use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_privacy_types::{
    NullifierV2, PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2,
};
use noxis_private_state::{PrivateStateAnchorError, PrivateStateAnchorV2};
use noxis_tree_params::{
    CandidatePoseidon2P24NullifierSparseIdV1, CandidatePoseidon2P24NullifierSparseManifestV1,
    Poseidon2P24NullifierSparseCandidateError,
};
use noxis_types::StateId;
use sha2::{Digest, Sha256};

/// Domain for an `NXNT v1` public-transition identity.
pub const CANDIDATE_NXSM_NULLIFIER_TRANSITION_ID_DOMAIN: &[u8] =
    b"NOXIS/NXSM-NULLIFIER-TRANSITION-ID/V1\0";
/// Exact byte length of the canonical `NXNT v1` public transition frame.
pub const CANDIDATE_NXSM_NULLIFIER_TRANSITION_ENCODED_LENGTH: usize = 408;

const MAGIC: [u8; 4] = *b"NXNT";
const VERSION: u16 = 1;

/// Public before/after statement for marking the two canonical intent
/// nullifiers as spent in `NXSM`.
///
/// The statement intentionally has no post-note root or post-state anchor.
/// Those require the still-unimplemented proof-backed note append transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateNxsmNullifierTransitionV1 {
    nullifier_tree_candidate: CandidatePoseidon2P24NullifierSparseIdV1,
    pre_state_id: StateId,
    pre_root: NullifierSparseRootV1,
    pre_spent_count: u64,
    post_root: NullifierSparseRootV1,
    post_spent_count: u64,
    nullifiers: [NullifierV2; 2],
    intent_commitment: PrivateTransferIntentCommitmentV2,
    transition_id: CandidateNxsmNullifierTransitionIdV1,
}

impl CandidateNxsmNullifierTransitionV1 {
    /// Builds the candidate relation by checking absence and applying both
    /// nullifier insertions to an in-memory clone of `pre_tree`.
    pub fn new(
        anchor: &PrivateStateAnchorV2,
        pre_tree: &NullifierSparseTreeStateV1,
        intent: &PrivateTransferIntentV2,
    ) -> Result<Self, CandidateNxsmNullifierTransitionError> {
        anchor.assert_matches_intent(intent)?;
        let pre_root = pre_tree.root()?;
        if pre_root != anchor.nullifier_root() {
            return Err(CandidateNxsmNullifierTransitionError::AnchorRootMismatch);
        }
        if pre_tree.spent_count() != anchor.spent_nullifier_count() {
            return Err(CandidateNxsmNullifierTransitionError::AnchorCountMismatch {
                anchor: anchor.spent_nullifier_count(),
                tree: pre_tree.spent_count(),
            });
        }
        let nullifiers = *intent.nullifiers();
        for (index, nullifier) in nullifiers.iter().copied().enumerate() {
            if pre_tree.is_spent(nullifier) {
                return Err(CandidateNxsmNullifierTransitionError::InputAlreadySpent { index });
            }
            let proof = pre_tree.prove(nullifier);
            pre_tree.verify_absence(pre_root, nullifier, &proof)?;
        }

        let mut post_tree = pre_tree.clone();
        for nullifier in nullifiers {
            post_tree.mark_spent(nullifier)?;
        }
        let post_root = post_tree.root()?;
        let post_spent_count = post_tree.spent_count();
        let expected_post_count = pre_tree
            .spent_count()
            .checked_add(2)
            .expect("bounded candidate counter cannot overflow");
        debug_assert_eq!(post_spent_count, expected_post_count);
        let reference = Poseidon2P24PrivacyReference::load_candidate()?;
        let intent_commitment = reference.hash_private_transfer_intent(intent)?;
        let mut transition = Self {
            nullifier_tree_candidate: CandidatePoseidon2P24NullifierSparseManifestV1::new()
                .candidate_id()?,
            pre_state_id: anchor.state_id(),
            pre_root,
            pre_spent_count: pre_tree.spent_count(),
            post_root,
            post_spent_count,
            nullifiers,
            intent_commitment,
            transition_id: CandidateNxsmNullifierTransitionIdV1([0; 32]),
        };
        let mut hasher = Sha256::new();
        hasher.update(CANDIDATE_NXSM_NULLIFIER_TRANSITION_ID_DOMAIN);
        hasher.update(transition.encode());
        transition.transition_id = CandidateNxsmNullifierTransitionIdV1(hasher.finalize().into());
        Ok(transition)
    }

    pub const fn nullifier_tree_candidate(&self) -> CandidatePoseidon2P24NullifierSparseIdV1 {
        self.nullifier_tree_candidate
    }

    pub const fn pre_state_id(&self) -> StateId {
        self.pre_state_id
    }

    pub const fn pre_root(&self) -> NullifierSparseRootV1 {
        self.pre_root
    }

    pub const fn pre_spent_count(&self) -> u64 {
        self.pre_spent_count
    }

    pub const fn post_root(&self) -> NullifierSparseRootV1 {
        self.post_root
    }

    pub const fn post_spent_count(&self) -> u64 {
        self.post_spent_count
    }

    pub const fn nullifiers(&self) -> &[NullifierV2; 2] {
        &self.nullifiers
    }

    pub const fn intent_commitment(&self) -> PrivateTransferIntentCommitmentV2 {
        self.intent_commitment
    }

    pub const fn transition_id(&self) -> CandidateNxsmNullifierTransitionIdV1 {
        self.transition_id
    }

    /// Fixed public encoding consumed by an eventual proof relation.
    pub fn encode(&self) -> [u8; CANDIDATE_NXSM_NULLIFIER_TRANSITION_ENCODED_LENGTH] {
        let mut output = [0_u8; CANDIDATE_NXSM_NULLIFIER_TRANSITION_ENCODED_LENGTH];
        let mut offset = 0;
        put(&mut output, &mut offset, &MAGIC);
        put(&mut output, &mut offset, &VERSION.to_be_bytes());
        put(&mut output, &mut offset, &[0; 2]);
        put(
            &mut output,
            &mut offset,
            &self.nullifier_tree_candidate.as_bytes(),
        );
        put(&mut output, &mut offset, &self.pre_state_id.0);
        put(&mut output, &mut offset, &self.pre_root.as_bytes());
        put(
            &mut output,
            &mut offset,
            &self.pre_spent_count.to_be_bytes(),
        );
        put(&mut output, &mut offset, &self.post_root.as_bytes());
        put(
            &mut output,
            &mut offset,
            &self.post_spent_count.to_be_bytes(),
        );
        for nullifier in self.nullifiers {
            put(&mut output, &mut offset, &nullifier.as_bytes());
        }
        put(&mut output, &mut offset, &self.intent_commitment.as_bytes());
        debug_assert_eq!(offset, CANDIDATE_NXSM_NULLIFIER_TRANSITION_ENCODED_LENGTH);
        output
    }

    /// Re-executes the candidate nullifier relation and rejects any changed
    /// public field before a future prover consumes it.
    pub fn revalidate(
        &self,
        anchor: &PrivateStateAnchorV2,
        pre_tree: &NullifierSparseTreeStateV1,
        intent: &PrivateTransferIntentV2,
    ) -> Result<(), CandidateNxsmNullifierTransitionError> {
        let expected = Self::new(anchor, pre_tree, intent)?;
        if expected != *self {
            return Err(CandidateNxsmNullifierTransitionError::PublicStatementMismatch);
        }
        Ok(())
    }
}

fn put(destination: &mut [u8], offset: &mut usize, source: &[u8]) {
    destination[*offset..*offset + source.len()].copy_from_slice(source);
    *offset += source.len();
}

/// Candidate identity for the exact public `NXNT v1` frame.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateNxsmNullifierTransitionIdV1([u8; 32]);

impl CandidateNxsmNullifierTransitionIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidateNxsmNullifierTransitionIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fail-closed errors while constructing the transparent candidate relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateNxsmNullifierTransitionError {
    Anchor(PrivateStateAnchorError),
    SparseTree(NullifierSparseTreeStateError),
    PrivacyReference(Poseidon2P24PrivacyReferenceError),
    Candidate(Poseidon2P24NullifierSparseCandidateError),
    AnchorRootMismatch,
    AnchorCountMismatch { anchor: u64, tree: u64 },
    InputAlreadySpent { index: usize },
    PublicStatementMismatch,
}

impl From<PrivateStateAnchorError> for CandidateNxsmNullifierTransitionError {
    fn from(value: PrivateStateAnchorError) -> Self {
        Self::Anchor(value)
    }
}

impl From<NullifierSparseTreeStateError> for CandidateNxsmNullifierTransitionError {
    fn from(value: NullifierSparseTreeStateError) -> Self {
        Self::SparseTree(value)
    }
}

impl From<Poseidon2P24PrivacyReferenceError> for CandidateNxsmNullifierTransitionError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::PrivacyReference(value)
    }
}

impl From<Poseidon2P24NullifierSparseCandidateError> for CandidateNxsmNullifierTransitionError {
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl fmt::Display for CandidateNxsmNullifierTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate NXSM nullifier transition error: {self:?}"
        )
    }
}

impl std::error::Error for CandidateNxsmNullifierTransitionError {}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, PrivateTransferOutputV2, TreeParametersId,
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

    fn snapshot() -> CandidatePrivateStateSnapshotV1 {
        CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![nullifier(3), nullifier(9)],
            &noxis_poseidon2_reference::Poseidon2P24Reference::load_candidate().unwrap(),
        )
        .unwrap()
    }

    fn pre_tree(snapshot: &CandidatePrivateStateSnapshotV1) -> NullifierSparseTreeStateV1 {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for nullifier in snapshot.spent_nullifiers() {
            tree.mark_spent(*nullifier).unwrap();
        }
        tree
    }

    fn anchor(
        snapshot: &CandidatePrivateStateSnapshotV1,
        tree: &NullifierSparseTreeStateV1,
    ) -> PrivateStateAnchorV2 {
        PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            noxis_privacy_types::TreeParametersV2::new(TreeParametersId::new([3; 32])),
            snapshot,
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
    fn binds_intent_anchor_absence_and_post_root_in_one_frozen_frame() {
        let snapshot = snapshot();
        let tree = pre_tree(&snapshot);
        let anchor = anchor(&snapshot, &tree);
        let intent = intent(&anchor);
        let transition = CandidateNxsmNullifierTransitionV1::new(&anchor, &tree, &intent).unwrap();

        assert_eq!(
            transition.encode().len(),
            CANDIDATE_NXSM_NULLIFIER_TRANSITION_ENCODED_LENGTH
        );
        assert_eq!(&transition.encode()[..8], b"NXNT\0\x01\0\0");
        assert_eq!(transition.pre_root(), tree.root().unwrap());
        assert_eq!(transition.pre_spent_count(), 2);
        assert_eq!(transition.post_spent_count(), 4);
        assert_ne!(transition.pre_root(), transition.post_root());
        assert_ne!(transition.intent_commitment().as_bytes(), [0; 64]);
        assert_eq!(
            transition.transition_id().as_bytes(),
            [
                131, 92, 223, 175, 198, 240, 64, 155, 247, 55, 239, 55, 137, 211, 113, 199, 68,
                106, 161, 248, 67, 165, 24, 34, 68, 213, 21, 154, 14, 224, 247, 129,
            ]
        );
        assert_eq!(transition.revalidate(&anchor, &tree, &intent), Ok(()));
    }

    #[test]
    fn rejects_a_spent_input_and_an_anchor_tree_mismatch() {
        let snapshot = snapshot();
        let tree = pre_tree(&snapshot);
        let anchor = anchor(&snapshot, &tree);
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
            CandidateNxsmNullifierTransitionV1::new(&anchor, &tree, &spent_intent),
            Err(CandidateNxsmNullifierTransitionError::InputAlreadySpent { index: 0 })
        );

        let mut different = NullifierSparseTreeStateV1::new_candidate().unwrap();
        different.mark_spent(nullifier(7)).unwrap();
        different.mark_spent(nullifier(8)).unwrap();
        assert_eq!(
            CandidateNxsmNullifierTransitionV1::new(&anchor, &different, &intent(&anchor)),
            Err(CandidateNxsmNullifierTransitionError::AnchorRootMismatch)
        );
    }
}
