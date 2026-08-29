//! Canonical, private node addressing for the fixed 512-bit sparse tree.

use noxis_privacy_types::NullifierV2;

use noxis_nullifier_tree_reference::NULLIFIER_SPARSE_TREE_DEPTH_V1;

/// A tree node at `height`, addressed by a nullifier prefix with lower path
/// bits cleared. It is never constructed from a caller-selected index.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NodePositionV1 {
    height: usize,
    key: [u8; NullifierV2::LENGTH],
}

impl NodePositionV1 {
    pub(crate) fn leaf(nullifier: NullifierV2) -> Self {
        Self {
            height: 0,
            key: nullifier.as_bytes(),
        }
    }

    pub(crate) fn root() -> Self {
        Self {
            height: NULLIFIER_SPARSE_TREE_DEPTH_V1,
            key: [0; NullifierV2::LENGTH],
        }
    }

    pub(crate) const fn height(self) -> usize {
        self.height
    }

    pub(crate) fn sibling(self) -> Self {
        debug_assert!(self.height < NULLIFIER_SPARSE_TREE_DEPTH_V1);
        let mut key = self.key;
        key[self.height / 8] ^= 1 << (self.height % 8);
        Self {
            height: self.height,
            key,
        }
    }

    pub(crate) fn parent(self) -> Self {
        debug_assert!(self.height < NULLIFIER_SPARSE_TREE_DEPTH_V1);
        let mut key = self.key;
        key[self.height / 8] &= !(1 << (self.height % 8));
        Self {
            height: self.height + 1,
            key,
        }
    }

    pub(crate) fn path_bit(self) -> bool {
        debug_assert!(self.height < NULLIFIER_SPARSE_TREE_DEPTH_V1);
        (self.key[self.height / 8] >> (self.height % 8)) & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use noxis_privacy_types::NullifierV2;

    use super::*;

    #[test]
    fn parent_clears_only_the_consumed_path_bit() {
        let mut elements = [0_u32; 16];
        elements[0] = 0b11;
        let leaf = NodePositionV1::leaf(NullifierV2::from_elements(elements).unwrap());
        assert!(leaf.path_bit());
        assert!(leaf.parent().path_bit());
        assert!(!leaf.parent().parent().path_bit());
    }
}
