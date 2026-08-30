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
    Poseidon2P24IntentExperimentResult, Poseidon2P24OwnershipExperimentResult,
    Poseidon2P24OwnershipProof, StarkExperimentError, prove_and_verify_p24_intent,
    prove_and_verify_p24_note_ownership_path32, prove_p24_note_ownership_path32,
    verify_p24_note_ownership_proof,
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

/// Public receipt of a sequential two-input ownership preflight.
///
/// Each P24 proof is generated and independently verified before it is
/// discarded, so this type retains only public results. It is explicitly not
/// an aggregate proof or a transferable verification artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateAnchoredOwnershipPairPreflightV1 {
    first_result: Poseidon2P24OwnershipExperimentResult,
    second_result: Poseidon2P24OwnershipExperimentResult,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

/// Public receipt of one sequential `H_INTENT` plus anchored-ownership run.
///
/// The two independently verified opaque proofs are discarded before this
/// receipt is returned. It records their public results and the exact `NXPU`
/// statement identity, but is not an aggregate or transferable proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateIntentAnchoredOwnershipPreflightV1 {
    intent_result: Poseidon2P24IntentExperimentResult,
    ownership_result: Poseidon2P24OwnershipExperimentResult,
    input_index: u8,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

impl CandidateIntentAnchoredOwnershipPreflightV1 {
    /// Public `H_INTENT` result checked before the ownership proof begins.
    pub const fn intent_result(&self) -> &Poseidon2P24IntentExperimentResult {
        &self.intent_result
    }

    /// Public ownership nullifier and note-root result for the selected input.
    pub const fn ownership_result(&self) -> &Poseidon2P24OwnershipExperimentResult {
        &self.ownership_result
    }

    /// The selected input in the fixed two-input candidate statement.
    pub const fn input_index(&self) -> u8 {
        self.input_index
    }

    /// Identity of the statement both sequential checks used.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }
}

impl CandidateAnchoredOwnershipPairPreflightV1 {
    /// Public result bound to canonical input index zero.
    pub const fn first_result(&self) -> &Poseidon2P24OwnershipExperimentResult {
        &self.first_result
    }

    /// Public result bound to canonical input index one.
    pub const fn second_result(&self) -> &Poseidon2P24OwnershipExperimentResult {
        &self.second_result
    }

    /// Identity of the public statement checked during the sequential run.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
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
    validate_public_result(
        statement,
        pre_tree,
        nxsm_witness,
        anchored.input_index,
        &result,
    )?;
    Ok(result)
}

/// Runs and verifies the canonical public `H_INTENT` relation, then runs and
/// verifies one private ownership proof against that same `NXPU v1` statement.
///
/// It is deliberately sequential: both opaque proof objects are discarded
/// before the returned receipt escapes. This is operational evidence that the
/// statement frame and one selected ownership result agree, not cryptographic
/// proof composition or a private-transfer proof.
pub fn run_candidate_intent_anchored_ownership_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    input_index: u8,
    ownership_witness: &CandidateAnchoredOwnershipWitnessV1,
) -> Result<CandidateIntentAnchoredOwnershipPreflightV1, CandidateAnchoredOwnershipError> {
    validate_input_index(input_index)?;
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;

    let intent_result = prove_and_verify_p24_intent(statement.air_public_inputs().intent())?;
    validate_intent_result(statement, &intent_result)?;

    let ownership = prove_candidate_anchored_ownership(
        statement,
        pre_tree,
        nxsm_witness,
        input_index,
        ownership_witness,
    )?;
    let ownership_result = ownership.public_result().clone();
    Ok(CandidateIntentAnchoredOwnershipPreflightV1 {
        intent_result,
        ownership_result,
        input_index,
        statement_id: statement.statement_id(),
    })
}

/// Rechecks the retained public and transparent-state bindings of a completed
/// sequential receipt. It cannot reverify the opaque proofs already dropped.
pub fn revalidate_candidate_intent_anchored_ownership_preflight(
    preflight: &CandidateIntentAnchoredOwnershipPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
) -> Result<Poseidon2P24OwnershipExperimentResult, CandidateAnchoredOwnershipError> {
    if preflight.statement_id != statement.statement_id() {
        return Err(CandidateAnchoredOwnershipError::StatementIdMismatch);
    }
    validate_intent_result(statement, &preflight.intent_result)?;
    validate_public_result(
        statement,
        pre_tree,
        nxsm_witness,
        preflight.input_index,
        &preflight.ownership_result,
    )?;
    Ok(preflight.ownership_result.clone())
}

fn validate_intent_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    result: &Poseidon2P24IntentExperimentResult,
) -> Result<(), CandidateAnchoredOwnershipError> {
    if result.intent_commitment != statement.air_public_inputs().intent_commitment() {
        return Err(CandidateAnchoredOwnershipError::IntentCommitmentMismatch);
    }
    Ok(())
}

fn validate_public_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    input_index: u8,
    result: &Poseidon2P24OwnershipExperimentResult,
) -> Result<(), CandidateAnchoredOwnershipError> {
    validate_input_index(input_index)?;
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;
    let note_root = MerkleRootV2::from_elements(result.root)?;
    if note_root != statement.anchor().note_root() {
        return Err(CandidateAnchoredOwnershipError::NoteRootMismatch);
    }
    let nullifier = NullifierV2::from_elements(result.nullifier)?;
    let expected = statement.air_public_inputs().intent().nullifiers()[usize::from(input_index)];
    if nullifier != expected {
        return Err(CandidateAnchoredOwnershipError::NullifierMismatch);
    }
    Ok(())
}

/// Runs both ownership proofs sequentially against one candidate statement.
///
/// This deliberately drops the first opaque proof before beginning the second
/// one. The current P24 research proof uses substantial memory; retaining both
/// objects would create a false impression that the backend supports proof
/// aggregation. The returned receipt can revalidate public and `NXSM`
/// cross-bindings, but cannot replace either discarded proof.
pub fn run_candidate_anchored_ownership_pair_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    first_witness: &CandidateAnchoredOwnershipWitnessV1,
    second_witness: &CandidateAnchoredOwnershipWitnessV1,
) -> Result<CandidateAnchoredOwnershipPairPreflightV1, CandidateAnchoredOwnershipError> {
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;
    let first_result = prove_and_verify_p24_note_ownership_path32(
        first_witness.nullifier_key,
        first_witness.note_preimage,
        first_witness.leaf_position,
        first_witness.siblings,
    )?;
    validate_public_result(statement, pre_tree, nxsm_witness, 0, &first_result)?;
    let second_result = prove_and_verify_p24_note_ownership_path32(
        second_witness.nullifier_key,
        second_witness.note_preimage,
        second_witness.leaf_position,
        second_witness.siblings,
    )?;
    validate_public_result(statement, pre_tree, nxsm_witness, 1, &second_result)?;
    if first_result.nullifier == second_result.nullifier {
        return Err(CandidateAnchoredOwnershipError::DuplicateNullifier);
    }
    Ok(CandidateAnchoredOwnershipPairPreflightV1 {
        first_result,
        second_result,
        statement_id: statement.statement_id(),
    })
}

/// Revalidates the public and `NXSM` bindings retained by a sequential
/// preflight receipt. It cannot reverify the discarded opaque P24 proofs.
pub fn revalidate_candidate_anchored_ownership_pair_preflight(
    preflight: &CandidateAnchoredOwnershipPairPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
) -> Result<[Poseidon2P24OwnershipExperimentResult; 2], CandidateAnchoredOwnershipError> {
    if preflight.statement_id != statement.statement_id() {
        return Err(CandidateAnchoredOwnershipError::StatementIdMismatch);
    }
    validate_public_result(
        statement,
        pre_tree,
        nxsm_witness,
        0,
        &preflight.first_result,
    )?;
    validate_public_result(
        statement,
        pre_tree,
        nxsm_witness,
        1,
        &preflight.second_result,
    )?;
    if preflight.first_result.nullifier == preflight.second_result.nullifier {
        return Err(CandidateAnchoredOwnershipError::DuplicateNullifier);
    }
    Ok([
        preflight.first_result.clone(),
        preflight.second_result.clone(),
    ])
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
    IntentCommitmentMismatch,
    DuplicateNullifier,
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
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, PrivateTransferIntentCommitmentV2,
        PrivateTransferIntentV2, PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
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

        let preflight = run_candidate_intent_anchored_ownership_preflight(
            &statement,
            &pre_tree,
            &nxsm_witness,
            input_index,
            &ownership_witness,
        )
        .unwrap();
        let result = revalidate_candidate_intent_anchored_ownership_preflight(
            &preflight,
            &statement,
            &pre_tree,
            &nxsm_witness,
        )
        .unwrap();
        assert_eq!(result.nullifier, nullifier.elements());
        assert_eq!(result.root, expected_root);
        assert_eq!(
            preflight.intent_result().intent_commitment,
            statement.air_public_inputs().intent_commitment()
        );
        assert_eq!(preflight.ownership_result(), &result);
        assert_eq!(preflight.input_index(), input_index);
        assert_eq!(preflight.statement_id(), statement.statement_id());

        let mut mismatched_intent_receipt = preflight.clone();
        let mut changed_commitment = mismatched_intent_receipt
            .intent_result
            .intent_commitment
            .elements();
        changed_commitment[0] = changed_commitment[0].wrapping_add(1);
        mismatched_intent_receipt.intent_result.intent_commitment =
            PrivateTransferIntentCommitmentV2::from_elements(changed_commitment).unwrap();
        assert!(matches!(
            revalidate_candidate_intent_anchored_ownership_preflight(
                &mismatched_intent_receipt,
                &statement,
                &pre_tree,
                &nxsm_witness,
            ),
            Err(CandidateAnchoredOwnershipError::IntentCommitmentMismatch)
        ));

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
    fn locally_composes_two_owned_notes_with_one_anchor_and_ordered_nxsm_transition() {
        let private_reference = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let tree_reference = Poseidon2P24Reference::load_candidate().unwrap();
        let first_key =
            core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(3));
        let second_key =
            core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(5));
        let first_note = note_with_recipient(private_reference.hash_addr(&first_key).unwrap());
        let second_note = note_with_recipient(private_reference.hash_addr(&second_key).unwrap());
        let first_commitment = private_reference.hash_note(&first_note).unwrap();
        let second_commitment = private_reference.hash_note(&second_note).unwrap();
        let commitments = [first_commitment, second_commitment];
        let (_, first_siblings, root) = tree_reference.small_tree_path(&commitments, 0).unwrap();
        let (_, second_siblings, second_root) =
            tree_reference.small_tree_path(&commitments, 1).unwrap();
        assert_eq!(root, second_root);

        let first_nullifier = NullifierV2::from_elements(
            private_reference
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
            private_reference
                .hash_nullifier_preimage(&nullifier_preimage(
                    second_key,
                    second_note,
                    second_commitment,
                    1,
                ))
                .unwrap(),
        )
        .unwrap();
        assert_ne!(first_nullifier, second_nullifier);
        let first_note_witness =
            CandidateAnchoredOwnershipWitnessV1::new(first_key, first_note, 0, first_siblings);
        let second_note_witness =
            CandidateAnchoredOwnershipWitnessV1::new(second_key, second_note, 1, second_siblings);
        let (intent_nullifiers, first_witness, second_witness) =
            if first_nullifier.as_bytes() < second_nullifier.as_bytes() {
                (
                    [first_nullifier, second_nullifier],
                    first_note_witness,
                    second_note_witness,
                )
            } else {
                (
                    [second_nullifier, first_nullifier],
                    second_note_witness,
                    first_note_witness,
                )
            };

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
        assert_eq!(snapshot.root().elements(), root);
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

        let preflight = run_candidate_anchored_ownership_pair_preflight(
            &statement,
            &pre_tree,
            &nxsm_witness,
            &first_witness,
            &second_witness,
        )
        .unwrap();
        let results = revalidate_candidate_anchored_ownership_pair_preflight(
            &preflight,
            &statement,
            &pre_tree,
            &nxsm_witness,
        )
        .unwrap();
        assert_eq!(results[0].nullifier, intent.nullifiers()[0].elements());
        assert_eq!(results[1].nullifier, intent.nullifiers()[1].elements());
        assert_eq!(results[0].root, root);
        assert_eq!(results[1].root, root);
        assert_eq!(preflight.first_result(), &results[0]);
        assert_eq!(preflight.second_result(), &results[1]);
        assert_eq!(preflight.statement_id(), statement.statement_id());
    }

    #[test]
    fn rejects_an_input_outside_the_fixed_two_input_relation_before_proving() {
        assert!(matches!(
            validate_input_index(2),
            Err(CandidateAnchoredOwnershipError::InputIndexOutOfRange { input_index: 2 })
        ));
    }
}
