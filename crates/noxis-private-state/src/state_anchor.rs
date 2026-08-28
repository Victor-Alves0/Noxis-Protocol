//! Canonical candidate binding between a private snapshot and an intent state ID.
//!
//! The resulting `StateId` is valid only in the isolated private-v2 candidate
//! domain. It is never a ledger-v1 state ID and this module exposes no state
//! transition or proof-verification operation.

use std::fmt;

use noxis_privacy_types::{PrivateTransferIntentV2, TreeParametersV2};
use noxis_types::{GenesisId, StateId, ValidationContextId};
use sha2::{Digest, Sha256};

use crate::{CandidatePrivateStateSnapshotV1, NullifierV2};

/// Domain for the SHA-256 commitment to the canonical spent-nullifier set.
pub const PRIVATE_NULLIFIER_SET_COMMITMENT_DOMAIN: &[u8] = b"NOXIS/PRIVATE-NULLIFIER-SET/V1\0";
/// Domain for the candidate private-state anchor identity (`H_STATE`).
pub const PRIVATE_STATE_ANCHOR_ID_DOMAIN: &[u8] = b"NOXIS/PRIVATE-STATE-ID/V1\0";
/// Exact byte length of the framed `NXPS v1` state-anchor preimage.
pub const PRIVATE_STATE_ANCHOR_ENCODED_LENGTH: usize = 220;

const MAGIC: [u8; 4] = *b"NXPS";
const VERSION: u16 = 1;
const TREE_ARITY: u8 = 2;
const BABYBEAR_LE32X16_ENCODING: u8 = 1;

/// SHA-256 commitment to the sorted, duplicate-free spent-nullifier set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrivateNullifierSetCommitmentV1([u8; 32]);

impl PrivateNullifierSetCommitmentV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for PrivateNullifierSetCommitmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Immutable `H_STATE` statement for one in-memory private snapshot.
///
/// The explicit fields make accidental mixing with a ledger-v1 `StateId`
/// visible to callers. The enclosed `state_id` is the only value that belongs
/// in `PrivateTransferIntentV2::pre_state_id` for this candidate domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateStateAnchorV1 {
    genesis_id: GenesisId,
    validation_context_id: ValidationContextId,
    tree_parameters: TreeParametersV2,
    next_leaf_index: u64,
    note_root: noxis_privacy_types::MerkleRootV2,
    spent_nullifier_count: u64,
    nullifier_set_commitment: PrivateNullifierSetCommitmentV1,
    state_id: StateId,
}

impl PrivateStateAnchorV1 {
    /// Derives `H_STATE` from the exact snapshot and deployment context.
    ///
    /// `tree_parameters` is recorded, not approved: this candidate layer has
    /// no allowlist and therefore cannot authorize a network selection.
    pub fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        tree_parameters: TreeParametersV2,
        snapshot: &CandidatePrivateStateSnapshotV1,
    ) -> Self {
        let next_leaf_index = snapshot.commitments().len() as u64;
        let spent_nullifier_count = snapshot.spent_nullifiers().len() as u64;
        let nullifier_set_commitment = nullifier_set_commitment(snapshot.spent_nullifiers());
        let note_root = snapshot.root();
        let mut anchor = Self {
            genesis_id,
            validation_context_id,
            tree_parameters,
            next_leaf_index,
            note_root,
            spent_nullifier_count,
            nullifier_set_commitment,
            state_id: StateId::new([0; 32]),
        };
        let frame = anchor.encode();
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_STATE_ANCHOR_ID_DOMAIN);
        hasher.update(frame);
        anchor.state_id = StateId::new(hasher.finalize().into());
        anchor
    }

    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis_id
    }
    pub const fn validation_context_id(&self) -> ValidationContextId {
        self.validation_context_id
    }
    pub const fn tree_parameters(&self) -> TreeParametersV2 {
        self.tree_parameters
    }
    pub const fn next_leaf_index(&self) -> u64 {
        self.next_leaf_index
    }
    pub const fn note_root(&self) -> noxis_privacy_types::MerkleRootV2 {
        self.note_root
    }
    pub const fn spent_nullifier_count(&self) -> u64 {
        self.spent_nullifier_count
    }
    pub const fn nullifier_set_commitment(&self) -> PrivateNullifierSetCommitmentV1 {
        self.nullifier_set_commitment
    }
    /// Candidate `H_STATE`, structurally carried by the intent's existing field.
    pub const fn state_id(&self) -> StateId {
        self.state_id
    }

    /// Produces the only accepted 220-byte `NXPS v1` state-anchor frame.
    pub fn encode(&self) -> [u8; PRIVATE_STATE_ANCHOR_ENCODED_LENGTH] {
        let mut output = [0_u8; PRIVATE_STATE_ANCHOR_ENCODED_LENGTH];
        let mut offset = 0;
        put(&mut output, &mut offset, &MAGIC);
        put(&mut output, &mut offset, &VERSION.to_be_bytes());
        put(&mut output, &mut offset, &[0; 2]);
        put(&mut output, &mut offset, &self.genesis_id.0);
        put(&mut output, &mut offset, &self.validation_context_id.0);
        put(
            &mut output,
            &mut offset,
            &self.tree_parameters.id().as_bytes(),
        );
        put(&mut output, &mut offset, &[self.tree_parameters.depth()]);
        put(&mut output, &mut offset, &[TREE_ARITY]);
        put(&mut output, &mut offset, &[BABYBEAR_LE32X16_ENCODING]);
        put(&mut output, &mut offset, &[BABYBEAR_LE32X16_ENCODING]);
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
        put(
            &mut output,
            &mut offset,
            &self.nullifier_set_commitment.as_bytes(),
        );
        debug_assert_eq!(offset, PRIVATE_STATE_ANCHOR_ENCODED_LENGTH);
        output
    }

    /// Fails closed when an intent does not bind exactly this private state.
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
        if intent.tree_parameters() != self.tree_parameters {
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

fn nullifier_set_commitment(nullifiers: &[NullifierV2]) -> PrivateNullifierSetCommitmentV1 {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_NULLIFIER_SET_COMMITMENT_DOMAIN);
    hasher.update((nullifiers.len() as u64).to_be_bytes());
    for nullifier in nullifiers {
        hasher.update(nullifier.as_bytes());
    }
    PrivateNullifierSetCommitmentV1(hasher.finalize().into())
}

fn put(destination: &mut [u8], offset: &mut usize, source: &[u8]) {
    destination[*offset..*offset + source.len()].copy_from_slice(source);
    *offset += source.len();
}

/// Exact mismatches between a private state anchor and a transfer intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateStateAnchorError {
    GenesisMismatch,
    ValidationContextMismatch,
    TreeParametersMismatch,
    NoteRootMismatch,
    StateIdMismatch,
}

impl fmt::Display for PrivateStateAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "private state anchor error: {self:?}")
    }
}

impl std::error::Error for PrivateStateAnchorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferOutputV2,
        TreeParametersId,
    };

    use crate::CandidatePrivateStateSnapshotV1;

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
    fn build_anchor(
        genesis: GenesisId,
        context: ValidationContextId,
        snapshot: &CandidatePrivateStateSnapshotV1,
    ) -> PrivateStateAnchorV1 {
        PrivateStateAnchorV1::new(
            genesis,
            context,
            TreeParametersV2::new(TreeParametersId::new([3; 32])),
            snapshot,
        )
    }

    #[test]
    fn h_state_has_a_frozen_frame_and_binds_the_private_snapshot() {
        let state = snapshot();
        let anchor = build_anchor(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            &state,
        );
        let encoded = anchor.encode();
        assert_eq!(encoded.len(), PRIVATE_STATE_ANCHOR_ENCODED_LENGTH);
        assert_eq!(&encoded[..8], b"NXPS\0\x01\0\0");
        assert_eq!(
            anchor.state_id(),
            StateId::new([
                88, 205, 62, 107, 174, 231, 56, 33, 42, 185, 41, 33, 96, 122, 203, 28, 159, 173,
                153, 117, 145, 218, 143, 204, 111, 178, 22, 100, 12, 38, 58, 133,
            ])
        );
        assert_ne!(
            anchor.state_id(),
            build_anchor(
                GenesisId::new([4; 32]),
                ValidationContextId::new([2; 32]),
                &state
            )
            .state_id()
        );
        assert_ne!(
            anchor.state_id(),
            build_anchor(
                GenesisId::new([1; 32]),
                ValidationContextId::new([5; 32]),
                &state
            )
            .state_id()
        );
        let different_snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(2), commitment(1)],
            vec![nullifier(3), nullifier(9)],
            &noxis_poseidon2_reference::Poseidon2P24Reference::load_candidate().unwrap(),
        )
        .unwrap();
        assert_ne!(
            anchor.state_id(),
            build_anchor(
                GenesisId::new([1; 32]),
                ValidationContextId::new([2; 32]),
                &different_snapshot
            )
            .state_id()
        );
    }

    #[test]
    fn intent_must_match_every_anchor_field() {
        let state = snapshot();
        let anchor = build_anchor(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            &state,
        );
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.tree_parameters(),
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
        let wrong_state = PrivateTransferIntentV2::new(
            intent.circuit_id(),
            intent.genesis_id(),
            intent.validation_context_id(),
            StateId::new([99; 32]),
            intent.tree_parameters(),
            intent.pre_state_root(),
            intent.asset_id(),
            *intent.nullifiers(),
            *intent.outputs(),
        )
        .unwrap();
        assert_eq!(
            anchor.assert_matches_intent(&wrong_state),
            Err(PrivateStateAnchorError::StateIdMismatch)
        );
    }
}
