//! Shared private input for the isolated P24 depth-32 membership spike.
//!
//! The guest computes the candidate leaf from the private note commitment,
//! reconstructs its 32-level path and commits only the resulting root.

use noxis_poseidon2_core::{root_from_note_path, BabyBearDigestV2, P24CoreError, P24_TREE_DEPTH};
use serde::{Deserialize, Serialize};

/// Private witness for one Noxis candidate P24 membership relation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct P24MembershipWitnessV1 {
    /// Private preimage transformed into the candidate tree leaf.
    pub note_commitment: BabyBearDigestV2,
    /// Position whose low 32 bits order every sibling pair.
    pub leaf_index: u32,
    /// Private ordered sibling path, from leaf level through root level.
    pub siblings: [BabyBearDigestV2; P24_TREE_DEPTH],
}

/// Reconstructs the sole public output: the candidate tree root.
pub fn derive_root(witness: P24MembershipWitnessV1) -> Result<BabyBearDigestV2, P24CoreError> {
    root_from_note_path(
        witness.note_commitment,
        witness.leaf_index,
        witness.siblings,
    )
}

/// Serializes a public root as sixteen canonical little-endian field elements.
pub fn root_public_bytes(root: BabyBearDigestV2) -> [u8; 64] {
    let mut output = [0_u8; 64];
    for (index, value) in root.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    output
}
