//! Minimal Noxis-compatible inner-receipt binding program.
#![no_main]
sp1_zkvm::entrypoint!(main);

use noxis_sp1_inner_receipt_lib::{derive_inner_receipt_id, InnerReceiptWitnessV1};

pub fn main() {
    let witness = sp1_zkvm::io::read::<InnerReceiptWitnessV1>();
    let receipt_id = derive_inner_receipt_id(witness);
    sp1_zkvm::io::commit_slice(&receipt_id);
}
