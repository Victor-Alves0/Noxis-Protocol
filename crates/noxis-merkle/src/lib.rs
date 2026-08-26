//! A deterministic, fixed-depth Merkle tree for Noxis commitments.
//!
//! The tree uses SHA-256 through the maintained `sha2` crate. Hash inputs have
//! explicit, distinct domains for occupied leaves, empty leaves, and internal
//! nodes. This is a commitment-tree data structure only; it is not a ZK circuit
//! and makes no claim of ZK compatibility.

use std::cmp;
use std::fmt;

use noxis_types::Commitment;
use sha2::{Digest, Sha256};

/// Minimum permitted fixed tree depth.
pub const MIN_DEPTH: u8 = 1;
/// Maximum permitted fixed tree depth.
pub const MAX_DEPTH: u8 = 32;
/// Memory and denial-of-service limit for stored commitments.
pub const MAX_COMMITMENTS: usize = 1_048_576;

const LEAF_DOMAIN: &[u8] = b"NOXIS/MERKLE/V1/LEAF";
const EMPTY_LEAF_DOMAIN: &[u8] = b"NOXIS/MERKLE/V1/EMPTY_LEAF";
const NODE_DOMAIN: &[u8] = b"NOXIS/MERKLE/V1/NODE";

type Hash = [u8; 32];

/// A SHA-256 Merkle root produced by this tree format.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MerkleRoot {
    digest: Hash,
    depth: u8,
}

impl MerkleRoot {
    /// Returns the canonical 32-byte root digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.digest
    }

    /// Returns the fixed tree depth committed to by this typed root.
    pub const fn depth(self) -> u8 {
        self.depth
    }
}

/// A proof that a commitment occurred at a particular leaf position.
///
/// Its internal data is deliberately not mutable by external callers. This
/// prevents accidentally constructing a proof with a mismatched depth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InclusionProof {
    leaf_index: u32,
    siblings: Vec<Hash>,
}

impl InclusionProof {
    /// Zero-based position of the proved commitment.
    pub const fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    /// Fixed tree depth represented by this proof.
    pub fn depth(&self) -> u8 {
        // Construction always bounds depth to 32.
        self.siblings.len() as u8
    }
}

/// An append-only fixed-depth Merkle commitment tree.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    depth: u8,
    commitments: Vec<Commitment>,
}

impl MerkleTree {
    /// Creates an empty tree with deterministic empty leaves.
    pub fn new(depth: u8) -> Result<Self, MerkleError> {
        validate_depth(depth)?;
        Ok(Self {
            depth,
            commitments: Vec::new(),
        })
    }

    /// Fixed depth of the tree.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Number of occupied commitment leaves.
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Whether the tree has no occupied leaves.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }

    /// Returns occupied commitments in their immutable append order.
    ///
    /// This is read-only because that order is part of the Merkle root and
    /// inclusion-proof semantics. It is used to create canonical snapshots.
    pub fn commitments(&self) -> &[Commitment] {
        &self.commitments
    }

    /// Maximum number of leaves accepted by this implementation at this depth.
    pub fn capacity(&self) -> usize {
        maximum_leaf_count(self.depth)
    }

    /// Appends a commitment and returns its zero-based leaf index.
    pub fn append(&mut self, commitment: Commitment) -> Result<u32, MerkleError> {
        if self.commitments.len() >= self.capacity() {
            return Err(MerkleError::TreeFull {
                capacity: self.capacity(),
            });
        }
        let index =
            u32::try_from(self.commitments.len()).map_err(|_| MerkleError::IndexOverflow)?;
        self.commitments.push(commitment);
        Ok(index)
    }

    /// Computes the current root, padding all unused leaves deterministically.
    pub fn root(&self) -> MerkleRoot {
        MerkleRoot {
            digest: root_from_commitments(self.depth, &self.commitments),
            depth: self.depth,
        }
    }

    /// Builds a membership proof for one appended commitment.
    pub fn prove(&self, leaf_index: u32) -> Result<InclusionProof, MerkleError> {
        let index = leaf_index as usize;
        if index >= self.commitments.len() {
            return Err(MerkleError::LeafIndexOutOfRange {
                index: leaf_index,
                occupied_leaves: self.commitments.len(),
            });
        }

        let empty_hashes = empty_hashes(self.depth);
        let mut level: Vec<Hash> = self.commitments.iter().copied().map(hash_leaf).collect();
        let mut current_index = index;
        let mut siblings = Vec::with_capacity(self.depth as usize);

        for height in 0..self.depth {
            if level.len() % 2 == 1 {
                level.push(empty_hashes[height as usize]);
            }
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            siblings.push(level[sibling_index]);
            level = parent_level(&level);
            current_index /= 2;
        }

        Ok(InclusionProof {
            leaf_index,
            siblings,
        })
    }

    /// Verifies that `commitment` is included in `root` according to `proof`.
    ///
    /// A false result means the proof does not establish membership. A malformed
    /// proof is reported distinctly so callers can reject it at trust boundaries.
    pub fn verify(
        root: MerkleRoot,
        commitment: Commitment,
        proof: &InclusionProof,
    ) -> Result<bool, MerkleError> {
        validate_depth(proof.depth())?;
        if proof.depth() != root.depth {
            return Err(MerkleError::ProofDepthMismatch {
                root_depth: root.depth,
                proof_depth: proof.depth(),
            });
        }
        let mut current = hash_leaf(commitment);
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            current = if index & 1 == 0 {
                hash_node(&current, sibling)
            } else {
                hash_node(sibling, &current)
            };
            index >>= 1;
        }
        Ok(current == root.digest)
    }
}

fn validate_depth(depth: u8) -> Result<(), MerkleError> {
    if !(MIN_DEPTH..=MAX_DEPTH).contains(&depth) {
        return Err(MerkleError::InvalidDepth {
            depth,
            minimum: MIN_DEPTH,
            maximum: MAX_DEPTH,
        });
    }
    Ok(())
}

fn maximum_leaf_count(depth: u8) -> usize {
    let structural_capacity = 1_u64 << depth;
    cmp::min(structural_capacity, MAX_COMMITMENTS as u64) as usize
}

fn root_from_commitments(depth: u8, commitments: &[Commitment]) -> Hash {
    let empty_hashes = empty_hashes(depth);
    if commitments.is_empty() {
        return empty_hashes[depth as usize];
    }

    let mut level: Vec<Hash> = commitments.iter().copied().map(hash_leaf).collect();
    for height in 0..depth {
        if level.len() % 2 == 1 {
            level.push(empty_hashes[height as usize]);
        }
        level = parent_level(&level);
    }
    debug_assert_eq!(level.len(), 1);
    level[0]
}

fn empty_hashes(depth: u8) -> Vec<Hash> {
    let mut hashes = Vec::with_capacity(depth as usize + 1);
    hashes.push(hash_empty_leaf());
    for height in 1..=depth as usize {
        hashes.push(hash_node(&hashes[height - 1], &hashes[height - 1]));
    }
    hashes
}

fn parent_level(children: &[Hash]) -> Vec<Hash> {
    debug_assert!(!children.is_empty() && children.len() % 2 == 0);
    children
        .chunks_exact(2)
        .map(|pair| hash_node(&pair[0], &pair[1]))
        .collect()
}

fn hash_leaf(commitment: Commitment) -> Hash {
    hash_parts(&[LEAF_DOMAIN, &commitment.0])
}

fn hash_empty_leaf() -> Hash {
    hash_parts(&[EMPTY_LEAF_DOMAIN])
}

fn hash_node(left: &Hash, right: &Hash) -> Hash {
    hash_parts(&[NODE_DOMAIN, left, right])
}

fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Errors returned by Merkle tree construction, insertion, proofs, and verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleError {
    InvalidDepth { depth: u8, minimum: u8, maximum: u8 },
    TreeFull { capacity: usize },
    LeafIndexOutOfRange { index: u32, occupied_leaves: usize },
    ProofDepthMismatch { root_depth: u8, proof_depth: u8 },
    IndexOverflow,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDepth {
                depth,
                minimum,
                maximum,
            } => write!(
                formatter,
                "Merkle depth {depth} is outside the supported range {minimum}..={maximum}"
            ),
            Self::TreeFull { capacity } => {
                write!(formatter, "Merkle tree reached its {capacity}-leaf limit")
            }
            Self::LeafIndexOutOfRange {
                index,
                occupied_leaves,
            } => write!(
                formatter,
                "leaf index {index} is outside {occupied_leaves} occupied leaves"
            ),
            Self::ProofDepthMismatch {
                root_depth,
                proof_depth,
            } => write!(
                formatter,
                "proof depth {proof_depth} does not match root depth {root_depth}"
            ),
            Self::IndexOverflow => formatter.write_str("Merkle leaf index exceeds u32 range"),
        }
    }
}

impl std::error::Error for MerkleError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(value: u8) -> Commitment {
        Commitment::new([value; 32])
    }

    #[test]
    fn proof_for_an_appended_commitment_verifies() {
        let mut tree = MerkleTree::new(4).unwrap();
        tree.append(commitment(1)).unwrap();
        let second_index = tree.append(commitment(2)).unwrap();
        tree.append(commitment(3)).unwrap();

        let proof = tree.prove(second_index).unwrap();
        assert_eq!(proof.leaf_index(), second_index);
        assert_eq!(proof.depth(), 4);
        assert!(MerkleTree::verify(tree.root(), commitment(2), &proof).unwrap());
    }

    #[test]
    fn wrong_commitment_or_changed_sibling_fails_verification() {
        let mut tree = MerkleTree::new(3).unwrap();
        tree.append(commitment(4)).unwrap();
        let index = tree.append(commitment(5)).unwrap();
        let root = tree.root();
        let proof = tree.prove(index).unwrap();

        assert!(!MerkleTree::verify(root, commitment(99), &proof).unwrap());
        let mut altered = proof;
        altered.siblings[0][0] ^= 1;
        assert!(!MerkleTree::verify(root, commitment(5), &altered).unwrap());
    }

    #[test]
    fn roots_are_deterministic_and_include_empty_padding() {
        let empty_a = MerkleTree::new(5).unwrap();
        let empty_b = MerkleTree::new(5).unwrap();
        assert_eq!(empty_a.root(), empty_b.root());

        let mut one_leaf = MerkleTree::new(5).unwrap();
        one_leaf.append(commitment(6)).unwrap();
        assert_ne!(empty_a.root(), one_leaf.root());

        let different_depth = MerkleTree::new(4).unwrap();
        assert_ne!(empty_a.root(), different_depth.root());
    }

    #[test]
    fn enforces_depth_and_capacity_limits() {
        assert!(matches!(
            MerkleTree::new(0),
            Err(MerkleError::InvalidDepth {
                depth: 0,
                minimum: MIN_DEPTH,
                maximum: MAX_DEPTH,
            })
        ));

        let mut tree = MerkleTree::new(1).unwrap();
        tree.append(commitment(1)).unwrap();
        tree.append(commitment(2)).unwrap();
        assert_eq!(
            tree.append(commitment(3)),
            Err(MerkleError::TreeFull { capacity: 2 })
        );
    }

    #[test]
    fn absent_leaf_cannot_be_proved() {
        let tree = MerkleTree::new(2).unwrap();
        assert_eq!(
            tree.prove(0),
            Err(MerkleError::LeafIndexOutOfRange {
                index: 0,
                occupied_leaves: 0,
            })
        );
    }

    #[test]
    fn proof_cannot_be_used_with_a_root_from_another_depth() {
        let mut shallower_tree = MerkleTree::new(2).unwrap();
        shallower_tree.append(commitment(7)).unwrap();
        let proof = shallower_tree.prove(0).unwrap();
        let deeper_root = MerkleTree::new(3).unwrap().root();

        assert_eq!(
            MerkleTree::verify(deeper_root, commitment(7), &proof),
            Err(MerkleError::ProofDepthMismatch {
                root_depth: 3,
                proof_depth: 2,
            })
        );
    }

    #[test]
    fn every_occupied_position_verifies_across_partial_tree_shapes() {
        for depth in 1..=5 {
            let capacity = MerkleTree::new(depth).unwrap().capacity();
            for count in 1..=capacity {
                let mut tree = MerkleTree::new(depth).unwrap();
                for value in 0..count {
                    tree.append(commitment(value as u8)).unwrap();
                }
                let root = tree.root();
                for index in 0..count {
                    let proof = tree.prove(index as u32).unwrap();
                    assert!(MerkleTree::verify(root, commitment(index as u8), &proof).unwrap());
                }
            }
        }
    }
}
