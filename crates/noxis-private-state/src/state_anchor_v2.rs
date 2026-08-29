//! Candidate `NXPS v2` anchor that binds the typed `NXSM` sparse-tree root.
//!
//! This module deliberately sits beside, rather than replacing, the `NXPS v1`
//! SHA-256 nullifier-set commitment. It is an isolated research boundary: no
//! ledger, proof verifier, persistence layer or consensus component accepts it.

use std::fmt;

use noxis_nullifier_tree_reference::NullifierSparseRootV1;
use noxis_nullifier_tree_state::{NullifierSparseTreeStateError, NullifierSparseTreeStateV1};
use noxis_privacy_types::{MerkleRootV2, PrivateTransferIntentV2, TreeParametersV2};
use noxis_tree_params::{
    CandidatePoseidon2P24NullifierSparseIdV1, CandidatePoseidon2P24NullifierSparseManifestV1,
    Poseidon2P24NullifierSparseCandidateError,
};
use noxis_types::{GenesisId, StateId, ValidationContextId};
use sha2::{Digest, Sha256};

use crate::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorError};

/// Domain for the candidate `NXPS v2` state identity.
pub const PRIVATE_STATE_NXSM_ANCHOR_ID_DOMAIN: &[u8] = b"NOXIS/PRIVATE-STATE-ID/V2\0";
/// Exact byte length of the framed `NXPS v2` anchor preimage.
pub const PRIVATE_STATE_NXSM_ANCHOR_ENCODED_LENGTH: usize = 288;

const MAGIC: [u8; 4] = *b"NXPS";
const VERSION: u16 = 2;
const TREE_ARITY: u8 = 2;
const BABYBEAR_LE32X16_ENCODING: u8 = 1;
const SPARSE_DEPTH: u16 = 512;

/// Immutable candidate state statement with a typed `NXSM` nullifier root.
///
/// Construction rebuilds the sparse tree from the snapshot's canonical spent
/// nullifiers and requires it to equal the supplied state. This prevents a
/// caller from combining a note snapshot with a nullifier root for another
/// same-sized set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateStateAnchorV2 {
    genesis_id: GenesisId,
    validation_context_id: ValidationContextId,
    note_tree_parameters: TreeParametersV2,
    nullifier_tree_candidate: CandidatePoseidon2P24NullifierSparseIdV1,
    next_leaf_index: u64,
    note_root: MerkleRootV2,
    spent_nullifier_count: u64,
    nullifier_root: NullifierSparseRootV1,
    state_id: StateId,
}

impl PrivateStateAnchorV2 {
    /// Creates the candidate anchor only when `tree` represents this snapshot.
    ///
    /// Both structures remain candidate-only. `note_tree_parameters` records a
    /// future note-tree identity but does not select or authorize one.
    pub fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        note_tree_parameters: TreeParametersV2,
        snapshot: &CandidatePrivateStateSnapshotV1,
        tree: &NullifierSparseTreeStateV1,
    ) -> Result<Self, PrivateStateAnchorV2Error> {
        let nullifier_root = verify_snapshot_tree(snapshot, tree)?;
        let nullifier_tree_candidate =
            CandidatePoseidon2P24NullifierSparseManifestV1::new().candidate_id()?;
        let mut anchor = Self {
            genesis_id,
            validation_context_id,
            note_tree_parameters,
            nullifier_tree_candidate,
            next_leaf_index: snapshot.commitments().len() as u64,
            note_root: snapshot.root(),
            spent_nullifier_count: tree.spent_count(),
            nullifier_root,
            state_id: StateId::new([0; 32]),
        };
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_STATE_NXSM_ANCHOR_ID_DOMAIN);
        hasher.update(anchor.encode());
        anchor.state_id = StateId::new(hasher.finalize().into());
        Ok(anchor)
    }

    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }

    pub const fn validation_context_id(&self) -> ValidationContextId {
        self.validation_context_id
    }

    pub const fn note_tree_parameters(&self) -> TreeParametersV2 {
        self.note_tree_parameters
    }

    pub const fn nullifier_tree_candidate(&self) -> CandidatePoseidon2P24NullifierSparseIdV1 {
        self.nullifier_tree_candidate
    }

    pub const fn next_leaf_index(&self) -> u64 {
        self.next_leaf_index
    }

    pub const fn note_root(&self) -> MerkleRootV2 {
        self.note_root
    }

    pub const fn spent_nullifier_count(&self) -> u64 {
        self.spent_nullifier_count
    }

    pub const fn nullifier_root(&self) -> NullifierSparseRootV1 {
        self.nullifier_root
    }

    /// Candidate `H_STATE`; it is not a ledger-v1 or consensus state ID.
    pub const fn state_id(&self) -> StateId {
        self.state_id
    }

    /// Produces the only canonical 288-byte `NXPS v2` anchor frame.
    pub fn encode(&self) -> [u8; PRIVATE_STATE_NXSM_ANCHOR_ENCODED_LENGTH] {
        let mut output = [0_u8; PRIVATE_STATE_NXSM_ANCHOR_ENCODED_LENGTH];
        let mut offset = 0;
        put(&mut output, &mut offset, &MAGIC);
        put(&mut output, &mut offset, &VERSION.to_be_bytes());
        put(&mut output, &mut offset, &[0; 2]);
        put(&mut output, &mut offset, &self.genesis_id.0);
        put(&mut output, &mut offset, &self.validation_context_id.0);
        put(
            &mut output,
            &mut offset,
            &self.note_tree_parameters.id().as_bytes(),
        );
        put(
            &mut output,
            &mut offset,
            &[self.note_tree_parameters.depth()],
        );
        put(&mut output, &mut offset, &[TREE_ARITY]);
        put(&mut output, &mut offset, &[BABYBEAR_LE32X16_ENCODING]);
        put(
            &mut output,
            &mut offset,
            &self.nullifier_tree_candidate.as_bytes(),
        );
        put(&mut output, &mut offset, &SPARSE_DEPTH.to_be_bytes());
        put(&mut output, &mut offset, &[BABYBEAR_LE32X16_ENCODING]);
        put(&mut output, &mut offset, &[BABYBEAR_LE32X16_ENCODING]);
        put(&mut output, &mut offset, &[0]);
        put(
            &mut output,
            &mut offset,
            &self.next_leaf_index.to_be_bytes(),
        );
        put(&mut output, &mut offset, &self.note_root.as_bytes());
        put(
            &mut output,
            &mut offset,
            &self.spent_nullifier_count.to_be_bytes(),
        );
        put(&mut output, &mut offset, &self.nullifier_root.as_bytes());
        debug_assert_eq!(offset, PRIVATE_STATE_NXSM_ANCHOR_ENCODED_LENGTH);
        output
    }

    /// Rejects an intent not bound to this exact candidate anchor.
    pub fn assert_matches_intent(
        &self,
        intent: &PrivateTransferIntentV2,
    ) -> Result<(), PrivateStateAnchorError> {
        if intent.genesis_id() != self.genesis_id {
            return Err(PrivateStateAnchorError::GenesisMismatch);
        }
        if intent.validation_context_id() != self.validation_context_id {
            return Err(PrivateStateAnchorError::ValidationContextMismatch);
        }
        if intent.tree_parameters() != self.note_tree_parameters {
            return Err(PrivateStateAnchorError::TreeParametersMismatch);
        }
        if intent.pre_state_root() != self.note_root {
            return Err(PrivateStateAnchorError::NoteRootMismatch);
        }
        if intent.pre_state_id() != self.state_id {
            return Err(PrivateStateAnchorError::StateIdMismatch);
        }
        Ok(())
    }
}

fn verify_snapshot_tree(
    snapshot: &CandidatePrivateStateSnapshotV1,
    tree: &NullifierSparseTreeStateV1,
) -> Result<NullifierSparseRootV1, PrivateStateAnchorV2Error> {
    let snapshot_count = snapshot.spent_nullifiers().len() as u64;
    if tree.spent_count() != snapshot_count {
        return Err(PrivateStateAnchorV2Error::SpentCountMismatch {
            snapshot: snapshot_count,
            tree: tree.spent_count(),
        });
    }
    let mut rebuilt = NullifierSparseTreeStateV1::new_candidate()?;
    for nullifier in snapshot.spent_nullifiers() {
        rebuilt.mark_spent(*nullifier)?;
    }
    let expected_root = rebuilt.root()?;
    let supplied_root = tree.root()?;
    if supplied_root != expected_root {
        return Err(PrivateStateAnchorV2Error::NullifierRootMismatch);
    }
    Ok(supplied_root)
}

fn put(destination: &mut [u8], offset: &mut usize, source: &[u8]) {
    destination[*offset..*offset + source.len()].copy_from_slice(source);
    *offset += source.len();
}

/// Fail-closed construction errors for a candidate `NXPS v2` anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateStateAnchorV2Error {
    Candidate(Poseidon2P24NullifierSparseCandidateError),
    SparseTree(NullifierSparseTreeStateError),
    SpentCountMismatch { snapshot: u64, tree: u64 },
    NullifierRootMismatch,
}

impl From<Poseidon2P24NullifierSparseCandidateError> for PrivateStateAnchorV2Error {
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl From<NullifierSparseTreeStateError> for PrivateStateAnchorV2Error {
    fn from(value: NullifierSparseTreeStateError) -> Self {
        Self::SparseTree(value)
    }
}

impl fmt::Display for PrivateStateAnchorV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "private NXSM state anchor error: {self:?}")
    }
}

impl std::error::Error for PrivateStateAnchorV2Error {}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferOutputV2,
        TreeParametersId,
    };

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
            vec![nullifier(9), nullifier(3)],
            &noxis_poseidon2_reference::Poseidon2P24Reference::load_candidate().unwrap(),
        )
        .unwrap()
    }

    fn tree_for(snapshot: &CandidatePrivateStateSnapshotV1) -> NullifierSparseTreeStateV1 {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for nullifier in snapshot.spent_nullifiers() {
            tree.mark_spent(*nullifier).unwrap();
        }
        tree
    }

    fn anchor_for(
        snapshot: &CandidatePrivateStateSnapshotV1,
        tree: &NullifierSparseTreeStateV1,
    ) -> PrivateStateAnchorV2 {
        PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            TreeParametersV2::new(TreeParametersId::new([3; 32])),
            snapshot,
            tree,
        )
        .unwrap()
    }

    #[test]
    fn nxps_v2_binds_the_snapshot_and_typed_sparse_root() {
        let snapshot = snapshot();
        let tree = tree_for(&snapshot);
        let anchor = anchor_for(&snapshot, &tree);

        assert_eq!(
            anchor.encode().len(),
            PRIVATE_STATE_NXSM_ANCHOR_ENCODED_LENGTH
        );
        assert_eq!(&anchor.encode()[..8], b"NXPS\0\x02\0\0");
        assert_eq!(
            anchor.state_id(),
            StateId::new([
                188, 32, 148, 101, 131, 216, 54, 46, 56, 89, 21, 49, 178, 203, 41, 0, 86, 13, 38,
                79, 191, 62, 246, 203, 141, 122, 33, 208, 133, 31, 101, 224,
            ])
        );
        assert_eq!(anchor.spent_nullifier_count(), 2);
        assert_eq!(anchor.nullifier_root(), tree.root().unwrap());
        assert_eq!(
            anchor.nullifier_tree_candidate(),
            CandidatePoseidon2P24NullifierSparseManifestV1::new()
                .candidate_id()
                .unwrap()
        );
        assert_ne!(anchor.state_id(), StateId::new([0; 32]));
        assert_ne!(
            anchor.state_id(),
            PrivateStateAnchorV2::new(
                GenesisId::new([1; 32]),
                ValidationContextId::new([2; 32]),
                TreeParametersV2::new(TreeParametersId::new([4; 32])),
                &snapshot,
                &tree,
            )
            .unwrap()
            .state_id()
        );
    }

    #[test]
    fn nxps_v2_rejects_a_count_or_root_from_another_nullifier_set() {
        let snapshot = snapshot();
        let empty = NullifierSparseTreeStateV1::new_candidate().unwrap();
        assert_eq!(
            PrivateStateAnchorV2::new(
                GenesisId::new([1; 32]),
                ValidationContextId::new([2; 32]),
                TreeParametersV2::new(TreeParametersId::new([3; 32])),
                &snapshot,
                &empty,
            ),
            Err(PrivateStateAnchorV2Error::SpentCountMismatch {
                snapshot: 2,
                tree: 0,
            })
        );

        let mut different = NullifierSparseTreeStateV1::new_candidate().unwrap();
        different.mark_spent(nullifier(7)).unwrap();
        different.mark_spent(nullifier(8)).unwrap();
        assert_eq!(
            PrivateStateAnchorV2::new(
                GenesisId::new([1; 32]),
                ValidationContextId::new([2; 32]),
                TreeParametersV2::new(TreeParametersId::new([3; 32])),
                &snapshot,
                &different,
            ),
            Err(PrivateStateAnchorV2Error::NullifierRootMismatch)
        );
    }

    #[test]
    fn nxps_v2_requires_an_intent_to_bind_the_new_state_identifier() {
        let snapshot = snapshot();
        let tree = tree_for(&snapshot);
        let anchor = anchor_for(&snapshot, &tree);
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            noxis_types::AssetId::new([5; 32]),
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
        .unwrap();
        assert_eq!(anchor.assert_matches_intent(&intent), Ok(()));
    }
}
