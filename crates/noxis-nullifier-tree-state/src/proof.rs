use noxis_nullifier_tree_reference::NULLIFIER_SPARSE_TREE_DEPTH_V1;
use noxis_poseidon2_reference::BabyBearDigestV2;

/// An immutable 512-sibling path generated from candidate sparse-tree state.
///
/// Direction is deliberately absent: verifiers derive it from the nullifier's
/// canonical bytes, exactly as the reference evaluator does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifierSparseProofV1 {
    siblings: Vec<BabyBearDigestV2>,
}

impl NullifierSparseProofV1 {
    pub(crate) fn new(siblings: Vec<BabyBearDigestV2>) -> Self {
        debug_assert_eq!(siblings.len(), NULLIFIER_SPARSE_TREE_DEPTH_V1);
        Self { siblings }
    }

    /// Exactly one sibling for each fixed tree level.
    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    /// A valid v1 proof is never empty, but this mirrors `len` for callers.
    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// The canonical leaf-to-root sibling list.
    pub fn siblings(&self) -> &[BabyBearDigestV2] {
        &self.siblings
    }
}
