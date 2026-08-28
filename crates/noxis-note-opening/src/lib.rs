//! Local-only construction and evaluation for the unselected P24 note candidate.
//!
//! This crate owns private note material only while a prover is preparing a
//! future witness. It does not encode, persist, log, transmit, prove, or
//! authorize anything. The candidate P24 references it uses are not active
//! protocol cryptography.

use std::fmt;

use noxis_poseidon2_privacy_reference::{
    Poseidon2P24PrivacyReference, Poseidon2P24PrivacyReferenceError,
};
use noxis_poseidon2_reference::{Poseidon2P24Reference, Poseidon2P24ReferenceError};
use noxis_privacy_types::{
    MerkleRootV2, MerkleSiblingV2, NoteCommitmentV2, NullifierV2, PrivacyTypesError,
    RecipientCommitmentV2,
};
use noxis_types::AssetId;
use zeroize::Zeroize;

const NOTE_VERSION: u16 = 1;
const NOTE_PREIMAGE_LENGTH: usize = 178;
const NULLIFIER_PREIMAGE_LENGTH: usize = 132;
const TREE_DEPTH: usize = 32;

/// Secret 32-byte key used only to derive the recipient commitment and nullifier.
///
/// It intentionally has no formatting, cloning, serialization, comparison, or
/// byte-extraction API. The caller transfers ownership into a local witness.
pub struct NullifierKeyV2([u8; 32]);

impl NullifierKeyV2 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for NullifierKeyV2 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret per-note nullifier randomness supplied by wallet policy.
pub struct NoteRandomnessV2([u8; 32]);

impl NoteRandomnessV2 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for NoteRandomnessV2 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret per-commitment randomness supplied by wallet policy.
pub struct CommitmentRandomnessV2([u8; 32]);

impl CommitmentRandomnessV2 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for CommitmentRandomnessV2 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Inputs transferred into a local note opening.
///
/// `rho` and `rcm` freshness is a wallet-generation responsibility: this type
/// never claims to test global uniqueness.
pub struct NoteOpeningInputV2 {
    asset_id: AssetId,
    value: u128,
    recipient_commitment: RecipientCommitmentV2,
    rho: NoteRandomnessV2,
    rcm: CommitmentRandomnessV2,
}

impl NoteOpeningInputV2 {
    pub fn new(
        asset_id: AssetId,
        value: u128,
        recipient_commitment: RecipientCommitmentV2,
        rho: NoteRandomnessV2,
        rcm: CommitmentRandomnessV2,
    ) -> Self {
        Self {
            asset_id,
            value,
            recipient_commitment,
            rho,
            rcm,
        }
    }
}

/// A local note opening. It is deliberately opaque and non-serializable.
pub struct NoteOpeningV2 {
    asset_id: AssetId,
    value: u128,
    recipient_commitment: RecipientCommitmentV2,
    rho: NoteRandomnessV2,
    rcm: CommitmentRandomnessV2,
}

impl NoteOpeningV2 {
    /// Creates a value-bearing note; zero is reserved for circuit padding.
    pub fn new_regular(input: NoteOpeningInputV2) -> Result<Self, NoteOpeningError> {
        if input.value == 0 {
            return Err(NoteOpeningError::RegularNoteHasZeroValue);
        }
        Ok(Self::from_input(input))
    }

    /// Creates an explicit zero-value padding note for the future 2x2 circuit.
    pub fn new_padding(input: NoteOpeningInputV2) -> Result<Self, NoteOpeningError> {
        if input.value != 0 {
            return Err(NoteOpeningError::PaddingNoteHasNonZeroValue);
        }
        Ok(Self::from_input(input))
    }

    /// Derives the public note commitment without exposing the note preimage.
    pub fn note_commitment(
        &self,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<NoteCommitmentV2, NoteOpeningError> {
        let mut preimage = self.note_preimage();
        let digest = evaluator.private_reference.hash_note(&preimage);
        preimage.zeroize();
        let digest = digest?;
        Ok(NoteCommitmentV2::from_elements(digest)?)
    }

    fn from_input(input: NoteOpeningInputV2) -> Self {
        Self {
            asset_id: input.asset_id,
            value: input.value,
            recipient_commitment: input.recipient_commitment,
            rho: input.rho,
            rcm: input.rcm,
        }
    }

    fn note_preimage(&self) -> [u8; NOTE_PREIMAGE_LENGTH] {
        let mut bytes = [0_u8; NOTE_PREIMAGE_LENGTH];
        bytes[..2].copy_from_slice(&NOTE_VERSION.to_be_bytes());
        bytes[2..34].copy_from_slice(&self.asset_id.0);
        bytes[34..50].copy_from_slice(&self.value.to_be_bytes());
        bytes[50..114].copy_from_slice(&self.recipient_commitment.as_bytes());
        bytes[114..146].copy_from_slice(self.rho.bytes());
        bytes[146..178].copy_from_slice(self.rcm.bytes());
        bytes
    }
}

impl Drop for NoteOpeningV2 {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// A future prover's complete local witness. It contains no network codec.
pub struct SpendingWitnessV2 {
    opening: NoteOpeningV2,
    nullifier_key: NullifierKeyV2,
    leaf_position: u32,
    siblings: [MerkleSiblingV2; TREE_DEPTH],
    public: DerivedNotePublicV2,
}

impl SpendingWitnessV2 {
    /// Validates all local candidate relations before retaining the witness.
    pub fn new(
        opening: NoteOpeningV2,
        nullifier_key: NullifierKeyV2,
        leaf_position: u32,
        siblings: [MerkleSiblingV2; TREE_DEPTH],
        expected_root: MerkleRootV2,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<Self, NoteOpeningError> {
        let public = evaluate_witness(
            &opening,
            &nullifier_key,
            leaf_position,
            &siblings,
            expected_root,
            evaluator,
        )?;
        Ok(Self {
            opening,
            nullifier_key,
            leaf_position,
            siblings,
            public,
        })
    }

    /// Returns exactly the values a future statement may make public.
    pub const fn public_values(&self) -> DerivedNotePublicV2 {
        self.public
    }

    /// Recomputes every retained local relation without revealing witness data.
    pub fn revalidate(
        &self,
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> Result<DerivedNotePublicV2, NoteOpeningError> {
        let derived = evaluate_witness(
            &self.opening,
            &self.nullifier_key,
            self.leaf_position,
            &self.siblings,
            self.public.merkle_root,
            evaluator,
        )?;
        if derived != self.public {
            return Err(NoteOpeningError::RetainedWitnessMismatch);
        }
        Ok(derived)
    }
}

fn evaluate_witness(
    opening: &NoteOpeningV2,
    nullifier_key: &NullifierKeyV2,
    leaf_position: u32,
    siblings: &[MerkleSiblingV2; TREE_DEPTH],
    expected_root: MerkleRootV2,
    evaluator: &CandidateP24NoteOpeningEvaluatorV2,
) -> Result<DerivedNotePublicV2, NoteOpeningError> {
    let derived_recipient = evaluator.recipient_commitment(nullifier_key)?;
    if derived_recipient != opening.recipient_commitment {
        return Err(NoteOpeningError::RecipientCommitmentMismatch);
    }
    let note_commitment = opening.note_commitment(evaluator)?;
    let nullifier =
        evaluator.nullifier(nullifier_key, &opening.rho, note_commitment, leaf_position)?;
    let leaf = evaluator.tree_reference.leaf(note_commitment.elements())?;
    let root = evaluator.tree_reference.root_from_path(
        leaf,
        leaf_position,
        (*siblings).map(MerkleSiblingV2::elements),
    )?;
    let actual_root = MerkleRootV2::from_elements(root)?;
    if actual_root != expected_root {
        return Err(NoteOpeningError::MerkleRootMismatch);
    }
    Ok(DerivedNotePublicV2 {
        note_commitment,
        nullifier,
        merkle_root: actual_root,
    })
}

/// Public values derived from one locally checked spending witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedNotePublicV2 {
    note_commitment: NoteCommitmentV2,
    nullifier: NullifierV2,
    merkle_root: MerkleRootV2,
}

impl DerivedNotePublicV2 {
    pub const fn note_commitment(self) -> NoteCommitmentV2 {
        self.note_commitment
    }

    pub const fn nullifier(self) -> NullifierV2 {
        self.nullifier
    }

    pub const fn merkle_root(self) -> MerkleRootV2 {
        self.merkle_root
    }
}

/// Isolated evaluator joining the two frozen, unselected P24 candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateP24NoteOpeningEvaluatorV2 {
    private_reference: Poseidon2P24PrivacyReference,
    tree_reference: Poseidon2P24Reference,
}

impl CandidateP24NoteOpeningEvaluatorV2 {
    /// Loads the candidate artifacts before evaluating any local relation.
    pub fn load_candidate() -> Result<Self, NoteOpeningError> {
        Ok(Self {
            private_reference: Poseidon2P24PrivacyReference::load_candidate()?,
            tree_reference: Poseidon2P24Reference::load_candidate()?,
        })
    }

    /// Derives the public recipient commitment for a locally held secret key.
    pub fn recipient_commitment(
        &self,
        nullifier_key: &NullifierKeyV2,
    ) -> Result<RecipientCommitmentV2, NoteOpeningError> {
        Ok(RecipientCommitmentV2::from_elements(
            self.private_reference.hash_addr(nullifier_key.bytes())?,
        )?)
    }

    fn nullifier(
        &self,
        nullifier_key: &NullifierKeyV2,
        rho: &NoteRandomnessV2,
        note_commitment: NoteCommitmentV2,
        leaf_position: u32,
    ) -> Result<NullifierV2, NoteOpeningError> {
        let mut preimage = [0_u8; NULLIFIER_PREIMAGE_LENGTH];
        preimage[..32].copy_from_slice(nullifier_key.bytes());
        preimage[32..64].copy_from_slice(rho.bytes());
        preimage[64..128].copy_from_slice(&note_commitment.as_bytes());
        preimage[128..].copy_from_slice(&leaf_position.to_be_bytes());
        let digest = self.private_reference.hash_nullifier_preimage(&preimage);
        preimage.zeroize();
        Ok(NullifierV2::from_elements(digest?)?)
    }
}

/// Errors intentionally describe only failed invariants, never secret values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoteOpeningError {
    RegularNoteHasZeroValue,
    PaddingNoteHasNonZeroValue,
    RecipientCommitmentMismatch,
    MerkleRootMismatch,
    RetainedWitnessMismatch,
    PrivateReference(Poseidon2P24PrivacyReferenceError),
    TreeReference(Poseidon2P24ReferenceError),
    PublicValue(PrivacyTypesError),
}

impl From<Poseidon2P24PrivacyReferenceError> for NoteOpeningError {
    fn from(value: Poseidon2P24PrivacyReferenceError) -> Self {
        Self::PrivateReference(value)
    }
}

impl From<Poseidon2P24ReferenceError> for NoteOpeningError {
    fn from(value: Poseidon2P24ReferenceError) -> Self {
        Self::TreeReference(value)
    }
}

impl From<PrivacyTypesError> for NoteOpeningError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PublicValue(value)
    }
}

impl fmt::Display for NoteOpeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegularNoteHasZeroValue => {
                formatter.write_str("regular note value must be non-zero")
            }
            Self::PaddingNoteHasNonZeroValue => {
                formatter.write_str("padding note value must be zero")
            }
            Self::RecipientCommitmentMismatch => {
                formatter.write_str("nullifier key does not match recipient commitment")
            }
            Self::MerkleRootMismatch => {
                formatter.write_str("candidate Merkle path does not match root")
            }
            Self::RetainedWitnessMismatch => {
                formatter.write_str("retained witness no longer matches its public values")
            }
            Self::PrivateReference(error) => {
                write!(formatter, "invalid private P24 reference: {error}")
            }
            Self::TreeReference(error) => write!(formatter, "invalid tree P24 reference: {error}"),
            Self::PublicValue(error) => write!(formatter, "invalid public v2 value: {error}"),
        }
    }
}

impl std::error::Error for NoteOpeningError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> NullifierKeyV2 {
        NullifierKeyV2::new([7; 32])
    }

    fn opening_input(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
        value: u128,
    ) -> NoteOpeningInputV2 {
        let recipient = evaluator.recipient_commitment(&key()).unwrap();
        NoteOpeningInputV2::new(
            AssetId::new([9; 32]),
            value,
            recipient,
            NoteRandomnessV2::new([11; 32]),
            CommitmentRandomnessV2::new([13; 32]),
        )
    }

    fn witness_parts(
        evaluator: &CandidateP24NoteOpeningEvaluatorV2,
    ) -> (NoteOpeningV2, [MerkleSiblingV2; TREE_DEPTH], MerkleRootV2) {
        let opening = NoteOpeningV2::new_regular(opening_input(evaluator, 42)).unwrap();
        let commitment = opening.note_commitment(evaluator).unwrap();
        let (_, siblings, root) = evaluator
            .tree_reference
            .small_tree_path(&[commitment.elements()], 0)
            .unwrap();
        (
            opening,
            siblings.map(|value| MerkleSiblingV2::from_elements(value).unwrap()),
            MerkleRootV2::from_elements(root).unwrap(),
        )
    }

    #[test]
    fn regular_and_padding_value_rules_are_explicit() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        assert!(matches!(
            NoteOpeningV2::new_regular(opening_input(&evaluator, 0)),
            Err(NoteOpeningError::RegularNoteHasZeroValue)
        ));
        assert!(matches!(
            NoteOpeningV2::new_padding(opening_input(&evaluator, 1)),
            Err(NoteOpeningError::PaddingNoteHasNonZeroValue)
        ));
        assert!(NoteOpeningV2::new_padding(opening_input(&evaluator, 0)).is_ok());
    }

    #[test]
    fn witness_checks_key_note_nullifier_and_depth_32_path() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        let (opening, siblings, root) = witness_parts(&evaluator);
        let witness =
            SpendingWitnessV2::new(opening, key(), 0, siblings, root, &evaluator).unwrap();
        let public = witness.public_values();
        assert_ne!(
            public.note_commitment(),
            NoteCommitmentV2::from_elements([0; 16]).unwrap()
        );
        assert_ne!(
            public.nullifier(),
            NullifierV2::from_elements([0; 16]).unwrap()
        );
        assert_eq!(public.merkle_root(), root);
        assert_eq!(witness.revalidate(&evaluator).unwrap(), public);
    }

    #[test]
    fn witness_rejects_another_key_a_changed_path_and_a_changed_root() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        let (opening, siblings, root) = witness_parts(&evaluator);
        assert!(matches!(
            SpendingWitnessV2::new(
                opening,
                NullifierKeyV2::new([8; 32]),
                0,
                siblings,
                root,
                &evaluator
            ),
            Err(NoteOpeningError::RecipientCommitmentMismatch)
        ));

        let (opening, mut siblings, root) = witness_parts(&evaluator);
        siblings[0] = MerkleSiblingV2::from_elements([1; 16]).unwrap();
        assert!(matches!(
            SpendingWitnessV2::new(opening, key(), 0, siblings, root, &evaluator),
            Err(NoteOpeningError::MerkleRootMismatch)
        ));
    }

    #[test]
    fn note_commitment_binds_each_private_preimage_region() {
        let evaluator = CandidateP24NoteOpeningEvaluatorV2::load_candidate().unwrap();
        let commitment = |asset, value, recipient_key, rho, rcm| {
            let recipient = evaluator
                .recipient_commitment(&NullifierKeyV2::new(recipient_key))
                .unwrap();
            NoteOpeningV2::new_regular(NoteOpeningInputV2::new(
                AssetId::new(asset),
                value,
                recipient,
                NoteRandomnessV2::new(rho),
                CommitmentRandomnessV2::new(rcm),
            ))
            .unwrap()
            .note_commitment(&evaluator)
            .unwrap()
        };
        let baseline = commitment([9; 32], 42, [7; 32], [11; 32], [13; 32]);
        assert_ne!(
            baseline,
            commitment([10; 32], 42, [7; 32], [11; 32], [13; 32])
        );
        assert_ne!(
            baseline,
            commitment([9; 32], 43, [7; 32], [11; 32], [13; 32])
        );
        assert_ne!(
            baseline,
            commitment([9; 32], 42, [8; 32], [11; 32], [13; 32])
        );
        assert_ne!(
            baseline,
            commitment([9; 32], 42, [7; 32], [12; 32], [13; 32])
        );
        assert_ne!(
            baseline,
            commitment([9; 32], 42, [7; 32], [11; 32], [14; 32])
        );
    }
}
