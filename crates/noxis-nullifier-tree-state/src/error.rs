use std::fmt;

use noxis_nullifier_tree_reference::NullifierTreeReferenceError;
use noxis_privacy_types::NullifierV2;

/// Fail-closed errors from candidate sparse-nullifier state operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NullifierSparseTreeStateError {
    /// The isolated candidate evaluator rejected a hash, path or root.
    Reference(NullifierTreeReferenceError),
    /// A leaf can only move from empty to spent once.
    AlreadySpent { nullifier: NullifierV2 },
}

impl From<NullifierTreeReferenceError> for NullifierSparseTreeStateError {
    fn from(value: NullifierTreeReferenceError) -> Self {
        Self::Reference(value)
    }
}

impl fmt::Display for NullifierSparseTreeStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "nullifier sparse tree state error: {self:?}")
    }
}

impl std::error::Error for NullifierSparseTreeStateError {}
