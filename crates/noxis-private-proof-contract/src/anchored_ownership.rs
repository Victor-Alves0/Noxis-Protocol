//! Local composition of a P24 ownership proof with `NXPS v2` and `NXSM`.
//!
//! This is intentionally an executable *preflight*, not a private-transfer
//! proof. The P24 ownership proof is hidden; the supplied `NXSM` paths are
//! still local transparent witness material. Keeping this boundary explicit
//! prevents the existing candidate state relation from being described as
//! anonymity before a single reviewed AIR proves both sides together.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_privacy_types::{MerkleRootV2, NullifierV2, PrivacyTypesError};
use noxis_stark_experiment::{
    Poseidon2P24OwnershipExperimentResult, Poseidon2P24OwnershipProof, StarkExperimentError,
    prove_p24_note_ownership_path32, verify_p24_note_ownership_proof,
};

use crate::{
    CandidateNxsmNullifierTransitionWitnessError, CandidateNxsmNullifierTransitionWitnessV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1,
};

/// Local secret material for one ownership path bound to candidate state.
///
/// This witness has no encoder and must remain with the prover. It is kept
/// separate from the public `NXPU` statement and `NXSM` local paths so a
/// future AIR can audit each witness domain independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateAnchoredOwnershipWitnessV1 {
    nullifier_key: [u8; 32],
    note_preimage: [u8; 178],
    leaf_position: u32,
    siblings: [[u32; 16]; 32],
}

impl CandidateAnchoredOwnershipWitnessV1 {
    /// Creates one in-memory P24 key, note and depth-32 path witness.
    pub const fn new(
        nullifier_key: [u8; 32],
        note_preimage: [u8; 178],
        leaf_position: u32,
        siblings: [[u32; 16]; 32],
    ) -> Self {
        Self {
            nullifier_key,
            note_preimage,
            leaf_position,
            siblings,
        }
    }
}

/// One opaque P24 ownership proof bound to one input of a canonical `NXPU v1`
/// public statement.
///
/// It has no encoding and cannot be submitted to the ledger. The separate
/// verifier requires the exact public statement, pre-tree and local `NXSM`
/// witness again, so every cross-binding is rechecked.
pub struct CandidateAnchoredOwnershipProofV1 {
    ownership_proof: Poseidon2P24OwnershipProof,
    input_index: u8,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

impl CandidateAnchoredOwnershipProofV1 {
    /// The input index in the fixed two-input candidate relation.
    pub const fn input_index(&self) -> u8 {
        self.input_index
    }

    /// Identity of the exact candidate public statement this proof was checked
    /// against when it was produced.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }

    /// Public nullifier and note-root result bound by the opaque P24 proof.
    pub const fn public_result(&self) -> &Poseidon2P24OwnershipExperimentResult {
        self.ownership_proof.public_result()
    }
}

/// Produces and revalidates a P24 ownership proof against one exact `NXPS v2`
/// anchor and the existing local `NXSM` absence witness.
///
/// The 32 P24 Merkle siblings remain private to the ownership proof. The
/// `NXSM` witness is still transparent local material and is *not* absorbed
/// into that proof yet.
pub fn prove_candidate_anchored_ownership(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    input_index: u8,
    ownership_witness: &CandidateAnchoredOwnershipWitnessV1,
) -> Result<CandidateAnchoredOwnershipProofV1, CandidateAnchoredOwnershipError> {
    validate_input_index(input_index)?;
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;

    let ownership_proof = prove_p24_note_ownership_path32(
        ownership_witness.nullifier_key,
        ownership_witness.note_preimage,
        ownership_witness.leaf_position,
        ownership_witness.siblings,
    )?;
    let anchored = CandidateAnchoredOwnershipProofV1 {
        ownership_proof,
        input_index,
        statement_id: statement.statement_id(),
    };
    verify_candidate_anchored_ownership(&anchored, statement, pre_tree, nxsm_witness)?;
    Ok(anchored)
}

/// Verifies an opaque P24 ownership proof and every public/local cross-binding
/// to the supplied `NXPU v1`, `NXPS v2` and `NXSM` candidate state.
pub fn verify_candidate_anchored_ownership(
    anchored: &CandidateAnchoredOwnershipProofV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
) -> Result<Poseidon2P24OwnershipExperimentResult, CandidateAnchoredOwnershipError> {
    if anchored.statement_id != statement.statement_id() {
        return Err(CandidateAnchoredOwnershipError::StatementIdMismatch);
    }
    validate_input_index(anchored.input_index)?;
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;

    let result = verify_p24_note_ownership_proof(&anchored.ownership_proof)?;
    let note_root = MerkleRootV2::from_elements(result.root)?;
    if note_root != statement.anchor().note_root() {
        return Err(CandidateAnchoredOwnershipError::NoteRootMismatch);
    }
    let nullifier = NullifierV2::from_elements(result.nullifier)?;
    let expected =
        statement.air_public_inputs().intent().nullifiers()[usize::from(anchored.input_index)];
    if nullifier != expected {
        return Err(CandidateAnchoredOwnershipError::NullifierMismatch);
    }
    Ok(result)
}

fn validate_input_index(input_index: u8) -> Result<(), CandidateAnchoredOwnershipError> {
    if input_index >= 2 {
        return Err(CandidateAnchoredOwnershipError::InputIndexOutOfRange { input_index });
    }
    Ok(())
}

/// Fail-closed errors while composing the still-separate candidate relations.
#[derive(Debug)]
pub enum CandidateAnchoredOwnershipError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    NxsmWitness(CandidateNxsmNullifierTransitionWitnessError),
    Stark(StarkExperimentError),
    PublicValue(PrivacyTypesError),
    InputIndexOutOfRange { input_index: u8 },
    StatementIdMismatch,
    NoteRootMismatch,
    NullifierMismatch,
}

impl From<CandidatePrivateTransferProofPublicStatementError> for CandidateAnchoredOwnershipError {
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}

impl From<CandidateNxsmNullifierTransitionWitnessError> for CandidateAnchoredOwnershipError {
    fn from(value: CandidateNxsmNullifierTransitionWitnessError) -> Self {
        Self::NxsmWitness(value)
    }
}

impl From<StarkExperimentError> for CandidateAnchoredOwnershipError {
    fn from(value: StarkExperimentError) -> Self {
        Self::Stark(value)
    }
}

impl From<PrivacyTypesError> for CandidateAnchoredOwnershipError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PublicValue(value)
    }
}

impl fmt::Display for CandidateAnchoredOwnershipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate anchored-ownership error: {self:?}")
    }
}

impl std::error::Error for CandidateAnchoredOwnershipError {}

#[cfg(test)]
mod tests {
    use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;
    use crate::{
        CandidateNxsmNullifierTransitionWitnessV1, CandidatePrivateTransferProofPublicStatementV1,
    };
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, PrivateTransferIntentV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };

    fn vector(value: u32) -> [u32; 16] {
        [value; 16]
    }

    fn note_with_recipient(recipient: [u32; 16]) -> [u8; 178] {
        let mut note = core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(7));
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
    fn locally_composes_ownership_proof_note_anchor_and_nxsm_absence() {
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let tree_reference = Poseidon2P24Reference::load_candidate().unwrap();
        let key = core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(3));
        let note = note_with_recipient(private_reference.hash_addr(&key).unwrap());
        let commitment = private_reference.hash_note(&note).unwrap();
        let note_commitment = NoteCommitmentV2::from_elements(commitment).unwrap();
        let commitments = vec![
            note_commitment,
            NoteCommitmentV2::from_elements(vector(7)).unwrap(),
        ];
        let position = 0;
        let (_, siblings, expected_root) = tree_reference
            .small_tree_path(&[commitment, vector(7)], position as usize)
            .unwrap();

        let nullifier = NullifierV2::from_elements(
            private_reference
                .hash_nullifier_preimage(&nullifier_preimage(key, note, commitment, position))
                .unwrap(),
        )
        .unwrap();
        let other_nullifier = NullifierV2::from_elements(vector(17)).unwrap();
        assert_ne!(nullifier, other_nullifier);
        let (intent_nullifiers, input_index) = if nullifier.as_bytes() < other_nullifier.as_bytes()
        {
            ([nullifier, other_nullifier], 0)
        } else {
            ([other_nullifier, nullifier], 1)
        };

        let snapshot = CandidatePrivateStateSnapshotV1::new(
            commitments,
            vec![
                NullifierV2::from_elements(vector(3)).unwrap(),
                NullifierV2::from_elements(vector(9)).unwrap(),
            ],
            &tree_reference,
        )
        .unwrap();
        assert_eq!(snapshot.root().elements(), expected_root);
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
            intent_nullifiers,
            [
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::from_elements(vector(12)).unwrap(),
                    CiphertextDigestV2::from_elements(vector(12)).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    NoteCommitmentV2::from_elements(vector(13)).unwrap(),
                    CiphertextDigestV2::from_elements(vector(13)).unwrap(),
                ),
            ],
        )
        .unwrap();
        let statement =
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &pre_tree, intent.clone())
                .unwrap();
        let nxsm_witness =
            CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(&pre_tree, &intent).unwrap();
        let ownership_witness =
            CandidateAnchoredOwnershipWitnessV1::new(key, note, position, siblings);

        let anchored = prove_candidate_anchored_ownership(
            &statement,
            &pre_tree,
            &nxsm_witness,
            input_index,
            &ownership_witness,
        )
        .unwrap();
        let result =
            verify_candidate_anchored_ownership(&anchored, &statement, &pre_tree, &nxsm_witness)
                .unwrap();
        assert_eq!(result.nullifier, nullifier.elements());
        assert_eq!(result.root, expected_root);
        assert_eq!(anchored.input_index(), input_index);
        assert_eq!(anchored.statement_id(), statement.statement_id());

        assert!(matches!(
            prove_candidate_anchored_ownership(
                &statement,
                &pre_tree,
                &nxsm_witness,
                2,
                &ownership_witness,
            ),
            Err(CandidateAnchoredOwnershipError::InputIndexOutOfRange { input_index: 2 })
        ));
    }

    #[test]
    fn rejects_an_input_outside_the_fixed_two_input_relation_before_proving() {
        assert!(matches!(
            validate_input_index(2),
            Err(CandidateAnchoredOwnershipError::InputIndexOutOfRange { input_index: 2 })
        ));
    }
}
