use std::collections::BTreeMap;

use noxis_nullifier_tree_reference::{
    NULLIFIER_SPARSE_TREE_DEPTH_V1, NullifierSparseRootV1, NullifierSparseTreeReferenceV1,
};
use noxis_poseidon2_reference::BabyBearDigestV2;
use noxis_privacy_types::NullifierV2;

use crate::position::NodePositionV1;
use crate::{NullifierSparseProofV1, NullifierSparseTreeStateError, NullifierTreeUpdateV1};

/// Sparse, in-memory state for one fixed `NXSM v1` candidate evaluator.
///
/// Only non-empty nodes are stored. Every omitted node is exactly the
/// pre-derived empty value at the same height. There is no public node-write
/// operation, which keeps the stored map and root tied to `mark_spent`.
#[derive(Clone, Debug)]
pub struct NullifierSparseTreeStateV1 {
    pub(crate) reference: NullifierSparseTreeReferenceV1,
    pub(crate) non_empty_nodes: BTreeMap<NodePositionV1, BabyBearDigestV2>,
    pub(crate) spent_count: u64,
}

impl NullifierSparseTreeStateV1 {
    /// Loads and validates the complete candidate chain before creating state.
    pub fn new_candidate() -> Result<Self, NullifierSparseTreeStateError> {
        Ok(Self {
            reference: NullifierSparseTreeReferenceV1::load_candidate()?,
            non_empty_nodes: BTreeMap::new(),
            spent_count: 0,
        })
    }

    /// Current candidate root. An empty map returns the frozen empty root.
    pub fn root(&self) -> Result<NullifierSparseRootV1, NullifierSparseTreeStateError> {
        Ok(NullifierSparseRootV1::from_elements(
            self.value_at(NodePositionV1::root()),
        )?)
    }

    /// Number of accepted spent leaves; it cannot decrease in this v1 state.
    pub const fn spent_count(&self) -> u64 {
        self.spent_count
    }

    /// Count of explicit non-empty nodes, useful for bounded research audits.
    pub fn stored_node_count(&self) -> usize {
        self.non_empty_nodes.len()
    }

    /// Whether the canonical nullifier leaf is already occupied.
    pub fn is_spent(&self, nullifier: NullifierV2) -> bool {
        self.non_empty_nodes
            .contains_key(&NodePositionV1::leaf(nullifier))
    }

    /// Generates a deterministic inclusion or absence path from current state.
    pub fn prove(&self, nullifier: NullifierV2) -> NullifierSparseProofV1 {
        let mut position = NodePositionV1::leaf(nullifier);
        let mut siblings = Vec::with_capacity(NULLIFIER_SPARSE_TREE_DEPTH_V1);
        for _ in 0..NULLIFIER_SPARSE_TREE_DEPTH_V1 {
            siblings.push(self.value_at(position.sibling()));
            position = position.parent();
        }
        NullifierSparseProofV1::new(siblings)
    }

    /// Checks an immutable path as evidence that a nullifier is spent at `root`.
    pub fn verify_inclusion(
        &self,
        root: NullifierSparseRootV1,
        nullifier: NullifierV2,
        proof: &NullifierSparseProofV1,
    ) -> Result<(), NullifierSparseTreeStateError> {
        Ok(self
            .reference
            .verify_inclusion(root, nullifier, proof.siblings())?)
    }

    /// Checks an immutable path as evidence that a nullifier is unspent at `root`.
    pub fn verify_absence(
        &self,
        root: NullifierSparseRootV1,
        nullifier: NullifierV2,
        proof: &NullifierSparseProofV1,
    ) -> Result<(), NullifierSparseTreeStateError> {
        Ok(self
            .reference
            .verify_absence(root, nullifier, proof.siblings())?)
    }

    /// Atomically turns one empty leaf into its canonical spent leaf.
    pub fn mark_spent(
        &mut self,
        nullifier: NullifierV2,
    ) -> Result<NullifierTreeUpdateV1, NullifierSparseTreeStateError> {
        crate::transition::mark_spent(self, nullifier)
    }

    pub(crate) fn value_at(&self, position: NodePositionV1) -> BabyBearDigestV2 {
        self.non_empty_nodes
            .get(&position)
            .copied()
            .unwrap_or(self.reference.empty_values()[position.height()])
    }
}
