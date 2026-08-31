//! Domain-separated identities for future multi-table inner proof receipts.
//!
//! This is deliberately not a proof format, verifier key or network frame.

use sha2::{Digest, Sha256};

use crate::CandidatePrivateTransferProofPublicStatementV1;

pub const CANDIDATE_INNER_RELATION_RECEIPT_ID_DOMAIN: &[u8] =
    b"NOXIS/CANDIDATE-INNER-RELATION-RECEIPT-ID/V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateInnerRelationKindV1 {
    IntentValue = 1,
    InputOwnership = 2,
    NullifierTransition = 3,
}

/// Stable local identity of one relation that an outer composition must bind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateInnerRelationReceiptIdV1([u8; 32]);

impl CandidateInnerRelationReceiptIdV1 {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

pub fn candidate_inner_relation_receipt_id(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    kind: CandidateInnerRelationKindV1,
    input_index: Option<u8>,
) -> CandidateInnerRelationReceiptIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_INNER_RELATION_RECEIPT_ID_DOMAIN);
    hasher.update(statement.statement_id().as_bytes());
    hasher.update([kind as u8]);
    hasher.update([input_index.unwrap_or(0xff)]);
    CandidateInnerRelationReceiptIdV1(hasher.finalize().into())
}
