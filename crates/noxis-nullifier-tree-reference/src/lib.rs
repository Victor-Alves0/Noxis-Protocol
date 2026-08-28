//! Dense correctness reference for the candidate `NXSM` sparse nullifier tree.
//!
//! This crate provides no database, consensus hook, proof packet or state
//! transition. It is intentionally slow and isolated so future AIR and storage
//! implementations can compare their leaf, path and root calculations against
//! one fixed reading of the `NXSM v1` artifact.

use std::fmt;

use noxis_poseidon2_reference::{
    BABYBEAR_MODULUS, BabyBearDigestV2, Poseidon2P24Reference, Poseidon2P24ReferenceError,
};
use noxis_privacy_types::{MerkleRootV2, NullifierV2, PrivacyTypesError};
use noxis_tree_params::{
    CandidatePoseidon2P24NullifierSparseManifestV1, P24_BYTE_PACK_WIDTH,
    Poseidon2P24NullifierSparseCandidateError, Poseidon2P24NullifierSparseDomainV1,
};

/// Exact `NXSM v1` depth: one level for every bit of `NullifierV2` encoding.
pub const NULLIFIER_SPARSE_TREE_DEPTH_V1: usize = 512;
const RATE: usize = 15;
const WIDTH: usize = 24;
const DIGEST_ELEMENTS: usize = 16;

/// Candidate sparse-nullifier root, distinct from a note-membership root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NullifierSparseRootV1(MerkleRootV2);

impl NullifierSparseRootV1 {
    pub fn from_elements(elements: BabyBearDigestV2) -> Result<Self, NullifierTreeReferenceError> {
        Ok(Self(MerkleRootV2::from_elements(elements)?))
    }

    pub const fn as_bytes(self) -> [u8; 64] {
        self.0.as_bytes()
    }

    pub fn elements(self) -> BabyBearDigestV2 {
        self.0.elements()
    }
}

/// Candidate evaluator for the three fixed `NXSM` Poseidon2 domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifierSparseTreeReferenceV1 {
    permutation: Poseidon2P24Reference,
    leaf_iv: [u32; 9],
    node_iv: [u32; 9],
    empty_iv: [u32; 9],
    empty_values: Vec<BabyBearDigestV2>,
}

impl NullifierSparseTreeReferenceV1 {
    /// Loads the complete parent chain and candidate permutation before use.
    pub fn load_candidate() -> Result<Self, NullifierTreeReferenceError> {
        let manifest = CandidatePoseidon2P24NullifierSparseManifestV1::new();
        manifest.encode()?;
        let mut reference = Self {
            permutation: Poseidon2P24Reference::load_candidate()?,
            leaf_iv: manifest.iv(Poseidon2P24NullifierSparseDomainV1::Leaf)?,
            node_iv: manifest.iv(Poseidon2P24NullifierSparseDomainV1::Node)?,
            empty_iv: manifest.iv(Poseidon2P24NullifierSparseDomainV1::Empty)?,
            empty_values: Vec::new(),
        };
        reference.empty_values = reference.derive_empty_values()?;
        Ok(reference)
    }

    /// Canonical spent-leaf hash for exactly one 64-byte nullifier.
    pub fn spent_leaf(
        &self,
        nullifier: NullifierV2,
    ) -> Result<BabyBearDigestV2, NullifierTreeReferenceError> {
        self.hash_bytes(
            Poseidon2P24NullifierSparseDomainV1::Leaf,
            &nullifier.as_bytes(),
        )
    }

    /// Ordered parent hash for two child digests.
    pub fn node(
        &self,
        left: BabyBearDigestV2,
        right: BabyBearDigestV2,
    ) -> Result<BabyBearDigestV2, NullifierTreeReferenceError> {
        validate_digest(&left)?;
        validate_digest(&right)?;
        let mut bytes = [0_u8; 128];
        write_digest(&mut bytes[..64], left);
        write_digest(&mut bytes[64..], right);
        self.hash_bytes(Poseidon2P24NullifierSparseDomainV1::Node, &bytes)
    }

    /// Derives `E0..E512`, where the last value is the empty tree root.
    pub fn empty_values(&self) -> &[BabyBearDigestV2] {
        &self.empty_values
    }

    fn derive_empty_values(&self) -> Result<Vec<BabyBearDigestV2>, NullifierTreeReferenceError> {
        let mut values = Vec::with_capacity(NULLIFIER_SPARSE_TREE_DEPTH_V1 + 1);
        let mut current = self.hash_bytes(Poseidon2P24NullifierSparseDomainV1::Empty, &[])?;
        values.push(current);
        for _ in 0..NULLIFIER_SPARSE_TREE_DEPTH_V1 {
            current = self.node(current, current)?;
            values.push(current);
        }
        Ok(values)
    }

    /// Returns the candidate empty root.
    pub fn empty_root(&self) -> Result<NullifierSparseRootV1, NullifierTreeReferenceError> {
        NullifierSparseRootV1::from_elements(self.empty_values[NULLIFIER_SPARSE_TREE_DEPTH_V1])
    }

    /// Reconstructs a root from a leaf-to-root sibling path.
    ///
    /// The direction is derived only from the full canonical nullifier bytes:
    /// at level `n`, bit `n % 8` of byte `n / 8` is read least-significant bit
    /// first. The caller never supplies a free index or direction bitmap.
    pub fn root_from_path(
        &self,
        nullifier: NullifierV2,
        leaf: BabyBearDigestV2,
        siblings: &[BabyBearDigestV2],
    ) -> Result<NullifierSparseRootV1, NullifierTreeReferenceError> {
        if siblings.len() != NULLIFIER_SPARSE_TREE_DEPTH_V1 {
            return Err(NullifierTreeReferenceError::InvalidPathLength {
                actual: siblings.len(),
                expected: NULLIFIER_SPARSE_TREE_DEPTH_V1,
            });
        }
        validate_digest(&leaf)?;
        let mut current = leaf;
        for (level, sibling) in siblings.iter().copied().enumerate() {
            validate_digest(&sibling)?;
            current = if path_bit(nullifier, level) {
                self.node(sibling, current)?
            } else {
                self.node(current, sibling)?
            };
        }
        NullifierSparseRootV1::from_elements(current)
    }

    /// Validates a path proving that this nullifier is already spent.
    pub fn verify_inclusion(
        &self,
        root: NullifierSparseRootV1,
        nullifier: NullifierV2,
        siblings: &[BabyBearDigestV2],
    ) -> Result<(), NullifierTreeReferenceError> {
        let computed = self.root_from_path(nullifier, self.spent_leaf(nullifier)?, siblings)?;
        if computed != root {
            return Err(NullifierTreeReferenceError::RootMismatch);
        }
        Ok(())
    }

    /// Validates a path proving that this nullifier is not spent.
    pub fn verify_absence(
        &self,
        root: NullifierSparseRootV1,
        nullifier: NullifierV2,
        siblings: &[BabyBearDigestV2],
    ) -> Result<(), NullifierTreeReferenceError> {
        let computed = self.root_from_path(nullifier, self.empty_values[0], siblings)?;
        if computed != root {
            return Err(NullifierTreeReferenceError::RootMismatch);
        }
        Ok(())
    }

    fn hash_bytes(
        &self,
        domain: Poseidon2P24NullifierSparseDomainV1,
        input: &[u8],
    ) -> Result<BabyBearDigestV2, NullifierTreeReferenceError> {
        if input.len() != domain.input_bytes() {
            return Err(NullifierTreeReferenceError::InvalidInputLength {
                domain,
                actual: input.len(),
                expected: domain.input_bytes(),
            });
        }
        let packed: Vec<u32> = input
            .chunks(P24_BYTE_PACK_WIDTH)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0_u32, |value, (offset, byte)| {
                        value | (u32::from(*byte) << (offset * 8))
                    })
            })
            .collect();
        debug_assert_eq!(packed.len(), domain.input_elements());
        let iv = match domain {
            Poseidon2P24NullifierSparseDomainV1::Leaf => self.leaf_iv,
            Poseidon2P24NullifierSparseDomainV1::Node => self.node_iv,
            Poseidon2P24NullifierSparseDomainV1::Empty => self.empty_iv,
        };
        let mut state = [0_u32; WIDTH];
        state[RATE..].copy_from_slice(&iv);
        if packed.is_empty() {
            state = self.permutation.permutation(state)?;
        } else {
            for block in packed.chunks(RATE) {
                for (lane, value) in state[..RATE].iter_mut().zip(block) {
                    *lane = add(*lane, *value);
                }
                state = self.permutation.permutation(state)?;
            }
        }
        let mut output = [0_u32; DIGEST_ELEMENTS];
        output[..RATE].copy_from_slice(&state[..RATE]);
        state = self.permutation.permutation(state)?;
        output[RATE] = state[0];
        Ok(output)
    }
}

fn path_bit(nullifier: NullifierV2, level: usize) -> bool {
    let bytes = nullifier.as_bytes();
    (bytes[level / 8] >> (level % 8)) & 1 == 1
}

fn write_digest(destination: &mut [u8], digest: BabyBearDigestV2) {
    for (index, value) in digest.into_iter().enumerate() {
        destination[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn validate_digest(digest: &BabyBearDigestV2) -> Result<(), NullifierTreeReferenceError> {
    for (index, value) in digest.iter().copied().enumerate() {
        if value >= BABYBEAR_MODULUS {
            return Err(NullifierTreeReferenceError::NonCanonicalDigest { index, value });
        }
    }
    Ok(())
}

fn add(left: u32, right: u32) -> u32 {
    ((u64::from(left) + u64::from(right)) % u64::from(BABYBEAR_MODULUS)) as u32
}

/// Fail-closed errors from the candidate nullifier-tree reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NullifierTreeReferenceError {
    TreeReference(Poseidon2P24ReferenceError),
    Candidate(Poseidon2P24NullifierSparseCandidateError),
    PublicValue(PrivacyTypesError),
    InvalidInputLength {
        domain: Poseidon2P24NullifierSparseDomainV1,
        actual: usize,
        expected: usize,
    },
    InvalidPathLength {
        actual: usize,
        expected: usize,
    },
    NonCanonicalDigest {
        index: usize,
        value: u32,
    },
    RootMismatch,
}

impl From<Poseidon2P24ReferenceError> for NullifierTreeReferenceError {
    fn from(value: Poseidon2P24ReferenceError) -> Self {
        Self::TreeReference(value)
    }
}
impl From<Poseidon2P24NullifierSparseCandidateError> for NullifierTreeReferenceError {
    fn from(value: Poseidon2P24NullifierSparseCandidateError) -> Self {
        Self::Candidate(value)
    }
}
impl From<PrivacyTypesError> for NullifierTreeReferenceError {
    fn from(value: PrivacyTypesError) -> Self {
        Self::PublicValue(value)
    }
}
impl fmt::Display for NullifierTreeReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "nullifier tree reference error: {self:?}")
    }
}
impl std::error::Error for NullifierTreeReferenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }

    #[test]
    fn empty_root_has_a_valid_absence_path_and_frozen_kat() {
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();
        let empty = reference.empty_values();
        let root = reference.empty_root().unwrap();
        assert_eq!(empty.len(), NULLIFIER_SPARSE_TREE_DEPTH_V1 + 1);
        assert_eq!(
            root.as_bytes(),
            [
                10, 250, 239, 104, 183, 229, 65, 39, 20, 161, 94, 10, 231, 21, 2, 30, 250, 120,
                162, 109, 191, 193, 8, 39, 235, 227, 185, 43, 8, 221, 119, 12, 168, 98, 55, 29,
                118, 120, 72, 79, 53, 183, 241, 0, 128, 95, 189, 53, 182, 42, 248, 7, 62, 37, 137,
                18, 47, 190, 23, 97, 110, 191, 70, 67,
            ]
        );
        assert_eq!(
            reference.verify_absence(root, nullifier(7), &empty[..NULLIFIER_SPARSE_TREE_DEPTH_V1]),
            Ok(())
        );
    }

    #[test]
    fn one_spent_leaf_has_inclusion_but_not_absence() {
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();
        let empty = reference.empty_values();
        let spent = nullifier(9);
        let siblings = &empty[..NULLIFIER_SPARSE_TREE_DEPTH_V1];
        let root = reference
            .root_from_path(spent, reference.spent_leaf(spent).unwrap(), siblings)
            .unwrap();
        assert_eq!(reference.verify_inclusion(root, spent, siblings), Ok(()));
        assert_eq!(
            reference.verify_absence(root, spent, siblings),
            Err(NullifierTreeReferenceError::RootMismatch)
        );
        assert_eq!(
            reference.verify_inclusion(root, nullifier(10), siblings),
            Err(NullifierTreeReferenceError::RootMismatch)
        );
    }

    #[test]
    fn path_length_and_sibling_mutation_fail_closed() {
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();
        let empty = reference.empty_values();
        let root = reference.empty_root().unwrap();
        assert_eq!(
            reference.verify_absence(root, nullifier(1), &empty[..511]),
            Err(NullifierTreeReferenceError::InvalidPathLength {
                actual: 511,
                expected: 512,
            })
        );
        let mut mutated = empty[..NULLIFIER_SPARSE_TREE_DEPTH_V1].to_vec();
        mutated[19][0] = 1;
        assert_eq!(
            reference.verify_absence(root, nullifier(1), &mutated),
            Err(NullifierTreeReferenceError::RootMismatch)
        );
    }

    #[test]
    fn path_directions_cover_byte_boundaries_and_the_highest_reachable_bit() {
        let mut low_elements = [0_u32; 16];
        low_elements[0] = 0b1_0000_0001;
        let low = NullifierV2::from_elements(low_elements).unwrap();
        assert!(path_bit(low, 0));
        assert!(path_bit(low, 8));
        assert!(!path_bit(low, 7));

        let mut high_elements = [0_u32; 16];
        high_elements[15] = 1 << 30;
        let high = NullifierV2::from_elements(high_elements).unwrap();
        assert!(path_bit(high, 510));
        assert!(!path_bit(high, 511));
    }
}
