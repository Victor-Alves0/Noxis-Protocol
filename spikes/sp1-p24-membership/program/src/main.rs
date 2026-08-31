//! Isolated proof guest for candidate Poseidon2 P24 depth-32 membership.
#![no_main]
sp1_zkvm::entrypoint!(main);

use noxis_sp1_p24_membership_lib::{derive_root, root_public_bytes, P24MembershipWitnessV1};

pub fn main() {
    let witness = sp1_zkvm::io::read::<P24MembershipWitnessV1>();
    let root = derive_root(witness).expect("membership witness must be canonical");
    sp1_zkvm::io::commit_slice(&root_public_bytes(root));
}
