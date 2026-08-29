//! Prepare-then-commit mutation for the candidate sparse-nullifier state.

use noxis_nullifier_tree_reference::NullifierSparseRootV1;
use noxis_privacy_types::NullifierV2;

use crate::position::NodePositionV1;
use crate::{NullifierSparseTreeStateError, NullifierSparseTreeStateV1};

/// Observable result of one accepted, irreversible candidate spent-leaf update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NullifierTreeUpdateV1 {
    nullifier: NullifierV2,
    previous_root: NullifierSparseRootV1,
    root: NullifierSparseRootV1,
}

impl NullifierTreeUpdateV1 {
    pub const fn nullifier(&self) -> NullifierV2 {
        self.nullifier
    }

    pub const fn previous_root(&self) -> NullifierSparseRootV1 {
        self.previous_root
    }

    pub const fn root(&self) -> NullifierSparseRootV1 {
        self.root
    }
}

pub(crate) fn mark_spent(
    state: &mut NullifierSparseTreeStateV1,
    nullifier: NullifierV2,
) -> Result<NullifierTreeUpdateV1, NullifierSparseTreeStateError> {
    let previous_root = state.root()?;
    if state.is_spent(nullifier) {
        return Err(NullifierSparseTreeStateError::AlreadySpent { nullifier });
    }

    // Every fallible hash is evaluated before the first map mutation. The
    // commit below only installs the fully prepared leaf-to-root path.
    let updates = prepare_spend(state, nullifier)?;
    let root = NullifierSparseRootV1::from_elements(
        updates
            .last()
            .expect("a 512-level tree has a prepared root")
            .1,
    )?;

    state.non_empty_nodes.extend(updates);
    state.spent_count = state
        .spent_count
        .checked_add(1)
        .expect("candidate state count cannot overflow before memory exhaustion");
    Ok(NullifierTreeUpdateV1 {
        nullifier,
        previous_root,
        root,
    })
}

fn prepare_spend(
    state: &NullifierSparseTreeStateV1,
    nullifier: NullifierV2,
) -> Result<Vec<(NodePositionV1, [u32; 16])>, NullifierSparseTreeStateError> {
    let mut position = NodePositionV1::leaf(nullifier);
    let mut current = state.reference.spent_leaf(nullifier)?;
    let mut updates = Vec::with_capacity(513);
    updates.push((position, current));

    for _ in 0..noxis_nullifier_tree_reference::NULLIFIER_SPARSE_TREE_DEPTH_V1 {
        let sibling = state.value_at(position.sibling());
        current = if position.path_bit() {
            state.reference.node(sibling, current)?
        } else {
            state.reference.node(current, sibling)?
        };
        position = position.parent();
        updates.push((position, current));
    }
    Ok(updates)
}
