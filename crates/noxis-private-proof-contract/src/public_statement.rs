//! One canonical public instance joining the note and nullifier relations.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_privacy_types::PrivateTransferIntentV2;
use noxis_private_state::PrivateStateAnchorV2;
use sha2::{Digest, Sha256};

use crate::{
    CandidateNxsmNullifierTransitionError, CandidateNxsmNullifierTransitionV1,
    CandidatePrivateTransferAirPublicInputsError, CandidatePrivateTransferAirPublicInputsV1,
};

/// SHA-256 domain for one combined public candidate-statement identity.
pub const CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ID_DOMAIN: &[u8] =
    b"NOXIS/PRIVATE-TRANSFER-PROOF-PUBLIC-STATEMENT-ID/V1\0";
/// Exact byte length of the local-only public-statement frame.
pub const CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH: usize = 1_440;

const MAGIC: [u8; 4] = *b"NXPU";
const VERSION: u16 = 1;

/// Public statement consumed as one unit by a future private-transfer prover.
///
/// It joins the fixed note-relation inputs with the typed `NXPS v2` anchor and
/// `NXNT v1` nullifier transition. It remains local-only until a separately
/// reviewed proof backend, packet format, state transition and genesis are
/// selected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferProofPublicStatementV1 {
    anchor: PrivateStateAnchorV2,
    air_public_inputs: CandidatePrivateTransferAirPublicInputsV1,
    nullifier_transition: CandidateNxsmNullifierTransitionV1,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

impl CandidatePrivateTransferProofPublicStatementV1 {
    /// Builds the single public statement only after anchor, intent and NXSM
    /// state agree on the same pre-state and `H_INTENT`.
    pub fn new(
        anchor: PrivateStateAnchorV2,
        pre_tree: &NullifierSparseTreeStateV1,
        intent: PrivateTransferIntentV2,
    ) -> Result<Self, CandidatePrivateTransferProofPublicStatementError> {
        anchor.assert_matches_intent(&intent)?;
        let air_public_inputs =
            CandidatePrivateTransferAirPublicInputsV1::from_intent(intent.clone())?;
        let nullifier_transition =
            CandidateNxsmNullifierTransitionV1::new(&anchor, pre_tree, &intent)?;
        validate_cross_bindings(&anchor, &air_public_inputs, &nullifier_transition)?;
        let mut statement = Self {
            anchor,
            air_public_inputs,
            nullifier_transition,
            statement_id: CandidatePrivateTransferProofPublicStatementIdV1([0; 32]),
        };
        statement.statement_id = statement.compute_id();
        Ok(statement)
    }

    /// The exact typed pre-state anchor bound to this relation.
    pub const fn anchor(&self) -> &PrivateStateAnchorV2 {
        &self.anchor
    }

    /// The note and canonical-intent public frame.
    pub const fn air_public_inputs(&self) -> &CandidatePrivateTransferAirPublicInputsV1 {
        &self.air_public_inputs
    }

    /// The before/after `NXSM` nullifier declaration.
    pub const fn nullifier_transition(&self) -> &CandidateNxsmNullifierTransitionV1 {
        &self.nullifier_transition
    }

    /// A domain-separated identity for the exact combined candidate frame.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }

    /// Frames the anchor, canonical intent, `H_INTENT` and `NXNT` in one order.
    pub fn encode(&self) -> [u8; CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH] {
        let mut output = [0_u8; CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH];
        output[..4].copy_from_slice(&MAGIC);
        output[4..6].copy_from_slice(&VERSION.to_be_bytes());
        output[6..8].fill(0);
        output[8..40].copy_from_slice(&self.anchor.state_id().0);
        output[40..328].copy_from_slice(&self.anchor.encode());
        output[328..968].copy_from_slice(&self.air_public_inputs.intent().encode());
        output[968..1032].copy_from_slice(&self.air_public_inputs.intent_commitment().as_bytes());
        output[1032..].copy_from_slice(&self.nullifier_transition.encode());
        output
    }

    /// Rechecks every public component and identity against the supplied
    /// candidate pre-state before an eventual prover uses it.
    pub fn revalidate(
        &self,
        pre_tree: &NullifierSparseTreeStateV1,
    ) -> Result<(), CandidatePrivateTransferProofPublicStatementError> {
        self.anchor
            .assert_matches_intent(self.air_public_inputs.intent())?;
        self.air_public_inputs.revalidate()?;
        self.nullifier_transition.revalidate(
            &self.anchor,
            pre_tree,
            self.air_public_inputs.intent(),
        )?;
        validate_cross_bindings(
            &self.anchor,
            &self.air_public_inputs,
            &self.nullifier_transition,
        )?;
        if self.compute_id() != self.statement_id {
            return Err(CandidatePrivateTransferProofPublicStatementError::StatementIdMismatch);
        }
        Ok(())
    }

    fn compute_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        let mut hasher = Sha256::new();
        hasher.update(CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ID_DOMAIN);
        hasher.update(self.encode());
        CandidatePrivateTransferProofPublicStatementIdV1(hasher.finalize().into())
    }
}

fn validate_cross_bindings(
    anchor: &PrivateStateAnchorV2,
    air: &CandidatePrivateTransferAirPublicInputsV1,
    transition: &CandidateNxsmNullifierTransitionV1,
) -> Result<(), CandidatePrivateTransferProofPublicStatementError> {
    if air.intent_commitment() != transition.intent_commitment() {
        return Err(CandidatePrivateTransferProofPublicStatementError::IntentCommitmentMismatch);
    }
    if air.intent().pre_state_id() != anchor.state_id()
        || air.intent().pre_state_id() != transition.pre_state_id()
    {
        return Err(CandidatePrivateTransferProofPublicStatementError::PreStateIdMismatch);
    }
    if air.intent().nullifiers() != transition.nullifiers() {
        return Err(CandidatePrivateTransferProofPublicStatementError::NullifierMismatch);
    }
    if anchor.nullifier_tree_candidate() != transition.nullifier_tree_candidate() {
        return Err(
            CandidatePrivateTransferProofPublicStatementError::NullifierTreeCandidateMismatch,
        );
    }
    if anchor.nullifier_root() != transition.pre_root()
        || anchor.spent_nullifier_count() != transition.pre_spent_count()
    {
        return Err(CandidatePrivateTransferProofPublicStatementError::PreNullifierStateMismatch);
    }
    Ok(())
}

/// Identity for an exact local public statement, never a `ProofVerifierId`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePrivateTransferProofPublicStatementIdV1([u8; 32]);

impl CandidatePrivateTransferProofPublicStatementIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for CandidatePrivateTransferProofPublicStatementIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fail-closed errors while joining the candidate public relations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidatePrivateTransferProofPublicStatementError {
    Anchor(noxis_private_state::PrivateStateAnchorError),
    AirPublicInputs(CandidatePrivateTransferAirPublicInputsError),
    NullifierTransition(CandidateNxsmNullifierTransitionError),
    IntentCommitmentMismatch,
    PreStateIdMismatch,
    NullifierMismatch,
    NullifierTreeCandidateMismatch,
    PreNullifierStateMismatch,
    StatementIdMismatch,
}

impl From<noxis_private_state::PrivateStateAnchorError>
    for CandidatePrivateTransferProofPublicStatementError
{
    fn from(value: noxis_private_state::PrivateStateAnchorError) -> Self {
        Self::Anchor(value)
    }
}

impl From<CandidatePrivateTransferAirPublicInputsError>
    for CandidatePrivateTransferProofPublicStatementError
{
    fn from(value: CandidatePrivateTransferAirPublicInputsError) -> Self {
        Self::AirPublicInputs(value)
    }
}

impl From<CandidateNxsmNullifierTransitionError>
    for CandidatePrivateTransferProofPublicStatementError
{
    fn from(value: CandidateNxsmNullifierTransitionError) -> Self {
        Self::NullifierTransition(value)
    }
}

impl fmt::Display for CandidatePrivateTransferProofPublicStatementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-transfer public-statement error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateTransferProofPublicStatementError {}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferOutputV2,
        TreeParametersId,
    };
    use noxis_private_state::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetId, GenesisId, ValidationContextId};

    use super::*;

    fn commitment(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }
    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }
    fn note_tree_parameters() -> noxis_privacy_types::TreeParametersV2 {
        noxis_privacy_types::TreeParametersV2::new(TreeParametersId::new(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()
                .unwrap()
                .as_bytes(),
        ))
    }
    fn parts() -> (
        PrivateStateAnchorV2,
        NullifierSparseTreeStateV1,
        PrivateTransferIntentV2,
    ) {
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![nullifier(3), nullifier(9)],
            &noxis_poseidon2_reference::Poseidon2P24Reference::load_candidate().unwrap(),
        )
        .unwrap();
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        tree.mark_spent(nullifier(3)).unwrap();
        tree.mark_spent(nullifier(9)).unwrap();
        let anchor = PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            note_tree_parameters(),
            &snapshot,
            &tree,
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
        (anchor, tree, intent)
    }

    #[test]
    fn joins_note_anchor_and_nxsm_transition_in_one_canonical_frame() {
        let (anchor, tree, intent) = parts();
        let statement =
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &tree, intent).unwrap();
        assert_eq!(
            statement.encode().len(),
            CANDIDATE_PRIVATE_TRANSFER_PROOF_PUBLIC_STATEMENT_ENCODED_LENGTH
        );
        assert_eq!(&statement.encode()[..8], b"NXPU\0\x01\0\0");
        assert_eq!(
            statement.air_public_inputs().intent_commitment(),
            statement.nullifier_transition().intent_commitment()
        );
        assert_ne!(statement.statement_id().as_bytes(), [0; 32]);
        assert_eq!(statement.revalidate(&tree), Ok(()));
    }

    #[test]
    fn public_statement_fails_closed_against_a_different_pre_state() {
        let (anchor, tree, intent) = parts();
        let statement =
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &tree, intent).unwrap();
        let mut different = NullifierSparseTreeStateV1::new_candidate().unwrap();
        different.mark_spent(nullifier(7)).unwrap();
        different.mark_spent(nullifier(8)).unwrap();
        assert!(statement.revalidate(&different).is_err());
    }
}
