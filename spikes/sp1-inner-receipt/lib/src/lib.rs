//! Shared, no-std-compatible witness framing for the SP1 integration spike.
//!
//! This intentionally mirrors only the public inner-receipt identifier domain
//! from Noxis. It is not a transfer circuit, receipt format, or backend choice.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INNER_RECEIPT_ID_DOMAIN: &[u8] = b"NOXIS/CANDIDATE-INNER-RELATION-RECEIPT-ID/V1\0";

/// Private zkVM input. The proof publishes only the derived 32-byte ID.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct InnerReceiptWitnessV1 {
    pub statement_id: [u8; 32],
    pub relation_kind: u8,
    pub input_index_tag: u8,
}

/// Computes the same domain-separated value as Noxis's local receipt helper.
pub fn derive_inner_receipt_id(witness: InnerReceiptWitnessV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INNER_RECEIPT_ID_DOMAIN);
    hasher.update(witness.statement_id);
    hasher.update([witness.relation_kind]);
    hasher.update([witness.input_index_tag]);
    hasher.finalize().into()
}
