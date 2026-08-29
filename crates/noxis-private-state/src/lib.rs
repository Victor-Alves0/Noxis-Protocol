//! In-memory candidate snapshot for the private Poseidon2 state domain.
//!
//! It is isolated from the SHA-256 ledger, persistence, networking and proof
//! verification. No method applies a transfer: an audited proof-backed v2
//! transition is still required before this state can carry value.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use noxis_poseidon2_reference::{
    BabyBearDigestV2, Poseidon2P24Reference, Poseidon2P24ReferenceError,
};
use noxis_privacy_types::{MerkleRootV2, NoteCommitmentV2, NullifierV2, PrivacyTypesError};
use noxis_tree_params::{CandidatePoseidon2P24ManifestV2, Poseidon2P24CandidateError};
use sha2::{Digest, Sha256};

mod state_anchor;
mod state_anchor_v2;

pub use state_anchor::{
    PRIVATE_NULLIFIER_SET_COMMITMENT_DOMAIN, PRIVATE_STATE_ANCHOR_ENCODED_LENGTH,
    PRIVATE_STATE_ANCHOR_ID_DOMAIN, PrivateNullifierSetCommitmentV1, PrivateStateAnchorError,
    PrivateStateAnchorV1,
};
pub use state_anchor_v2::{
    PRIVATE_STATE_NXSM_ANCHOR_ENCODED_LENGTH, PRIVATE_STATE_NXSM_ANCHOR_ID_DOMAIN,
    PrivateStateAnchorV2, PrivateStateAnchorV2Error,
};

/// Deliberate local-only bound; a persistent v2 accumulator will replace it.
pub const CANDIDATE_PRIVATE_STATE_MAX_NOTES: usize = 1_024;
/// Domain for the canonical candidate-state identity.
pub const CANDIDATE_PRIVATE_STATE_ID_DOMAIN: &[u8] = b"NOXIS/PRIVATE-STATE-CANDIDATE-ID/V1\0";

/// Immutable, canonical snapshot of candidate private commitments and nullifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateStateSnapshotV1 {
    commitments: Vec<NoteCommitmentV2>,
    spent_nullifiers: Vec<NullifierV2>,
    root: MerkleRootV2,
}

impl CandidatePrivateStateSnapshotV1 {
    /// Rebuilds the candidate depth-32 root and canonical state collections.
    pub fn new(
        commitments: Vec<NoteCommitmentV2>,
        mut spent_nullifiers: Vec<NullifierV2>,
        reference: &Poseidon2P24Reference,
    ) -> Result<Self, CandidatePrivateStateError> {
        if commitments.len() > CANDIDATE_PRIVATE_STATE_MAX_NOTES {
            return Err(CandidatePrivateStateError::TooManyCommitments(
                commitments.len(),
            ));
        }
        if commitments.iter().collect::<BTreeSet<_>>().len() != commitments.len() {
            return Err(CandidatePrivateStateError::DuplicateCommitment);
        }
        spent_nullifiers.sort_unstable();
        if spent_nullifiers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CandidatePrivateStateError::DuplicateNullifier);
        }
        // Append position is semantic, therefore commitments must retain caller order.
        let root = MerkleRootV2::from_elements(root_for_commitments(reference, &commitments)?)?;
        Ok(Self {
            commitments,
            spent_nullifiers,
            root,
        })
    }

    pub fn commitments(&self) -> &[NoteCommitmentV2] {
        &self.commitments
    }
    pub fn spent_nullifiers(&self) -> &[NullifierV2] {
        &self.spent_nullifiers
    }
    pub const fn root(&self) -> MerkleRootV2 {
        self.root
    }
    pub fn is_spent(&self, nullifier: NullifierV2) -> bool {
        self.spent_nullifiers.binary_search(&nullifier).is_ok()
    }

    /// Hash-addressed identity of the entire candidate snapshot.
    pub fn id(&self) -> Result<CandidatePrivateStateIdV1, CandidatePrivateStateError> {
        let mut hasher = Sha256::new();
        hasher.update(CANDIDATE_PRIVATE_STATE_ID_DOMAIN);
        hasher.update(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()?
                .as_bytes(),
        );
        hasher.update(self.root.as_bytes());
        hasher.update(
            u32::try_from(self.commitments.len())
                .expect("bounded count")
                .to_be_bytes(),
        );
        for commitment in &self.commitments {
            hasher.update(commitment.as_bytes());
        }
        hasher.update(
            u32::try_from(self.spent_nullifiers.len())
                .expect("bounded count")
                .to_be_bytes(),
        );
        for nullifier in &self.spent_nullifiers {
            hasher.update(nullifier.as_bytes());
        }
        Ok(CandidatePrivateStateIdV1(hasher.finalize().into()))
    }
}

fn root_for_commitments(
    reference: &Poseidon2P24Reference,
    commitments: &[NoteCommitmentV2],
) -> Result<BabyBearDigestV2, CandidatePrivateStateError> {
    let empty = reference.empty_values()?;
    if commitments.is_empty() {
        return Ok(empty[32]);
    }
    let mut nodes: BTreeMap<u32, BabyBearDigestV2> = commitments
        .iter()
        .enumerate()
        .map(|(index, commitment)| {
            Ok((
                u32::try_from(index).expect("local bound"),
                reference.leaf(commitment.elements())?,
            ))
        })
        .collect::<Result<_, CandidatePrivateStateError>>()?;
    for empty_value in empty.iter().take(32).copied() {
        let parents: BTreeSet<u32> = nodes.keys().map(|index| index >> 1).collect();
        let mut next = BTreeMap::new();
        for parent in parents {
            let left = nodes.get(&(parent << 1)).copied().unwrap_or(empty_value);
            let right = nodes
                .get(&((parent << 1) | 1))
                .copied()
                .unwrap_or(empty_value);
            next.insert(parent, reference.node(left, right)?);
        }
        nodes = next;
    }
    Ok(nodes.get(&0).copied().expect("nonempty tree retains root"))
}

/// Identity distinct from both ledger `StateId` and any consensus state commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidatePrivateStateIdV1([u8; 32]);
impl CandidatePrivateStateIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}
impl fmt::Display for CandidatePrivateStateIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fail-closed construction errors for candidate private snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidatePrivateStateError {
    Tree(Poseidon2P24ReferenceError),
    Candidate(Poseidon2P24CandidateError),
    PublicValue(PrivacyTypesError),
    TooManyCommitments(usize),
    DuplicateCommitment,
    DuplicateNullifier,
}
impl From<Poseidon2P24ReferenceError> for CandidatePrivateStateError {
    fn from(value: Poseidon2P24ReferenceError) -> Self {
        Self::Tree(value)
    }
}
impl From<Poseidon2P24CandidateError> for CandidatePrivateStateError {
    fn from(value: Poseidon2P24CandidateError) -> Self {
        Self::Candidate(value)
    }
}
impl From<PrivacyTypesError> for CandidatePrivateStateError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PublicValue(value)
    }
}
impl fmt::Display for CandidatePrivateStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "candidate private state error: {self:?}")
    }
}
impl std::error::Error for CandidatePrivateStateError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn commitment(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }
    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }
    #[test]
    fn snapshot_binds_append_order_root_and_spent_nullifiers() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let first = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![nullifier(9), nullifier(3)],
            &reference,
        )
        .unwrap();
        let second = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(2), commitment(1)],
            vec![nullifier(3), nullifier(9)],
            &reference,
        )
        .unwrap();
        assert_ne!(first.root(), second.root());
        assert_ne!(first.id().unwrap(), second.id().unwrap());
        assert!(first.is_spent(nullifier(3)));
        assert!(!first.is_spent(nullifier(4)));
    }
    #[test]
    fn snapshot_rejects_duplicate_commitments_and_nullifiers() {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        assert_eq!(
            CandidatePrivateStateSnapshotV1::new(
                vec![commitment(1), commitment(1)],
                vec![],
                &reference
            ),
            Err(CandidatePrivateStateError::DuplicateCommitment)
        );
        assert_eq!(
            CandidatePrivateStateSnapshotV1::new(
                vec![],
                vec![nullifier(1), nullifier(1)],
                &reference
            ),
            Err(CandidatePrivateStateError::DuplicateNullifier)
        );
    }
}
