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
    candidate_inner_relation_receipt_id_from_statement_id(
        statement.statement_id().as_bytes(),
        kind,
        input_index,
    )
}

/// Derives the local receipt identity from an already-canonical statement ID.
///
/// This is intentionally only an identity derivation. It does not validate a
/// proof, serialize a receipt, or make the supplied statement ID public.
pub fn candidate_inner_relation_receipt_id_from_statement_id(
    statement_id: [u8; 32],
    kind: CandidateInnerRelationKindV1,
    input_index: Option<u8>,
) -> CandidateInnerRelationReceiptIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(CANDIDATE_INNER_RELATION_RECEIPT_ID_DOMAIN);
    hasher.update(statement_id);
    hasher.update([kind as u8]);
    hasher.update([input_index.unwrap_or(0xff)]);
    CandidateInnerRelationReceiptIdV1(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_kind_and_input_index_are_domain_separated() {
        // This checks the tags independently of a concrete NXPU fixture; the
        // outer constructor supplies the statement identity at runtime.
        let mut ids = std::collections::BTreeSet::new();
        for (kind, index) in [
            (CandidateInnerRelationKindV1::IntentValue, None),
            (CandidateInnerRelationKindV1::InputOwnership, Some(0)),
            (CandidateInnerRelationKindV1::InputOwnership, Some(1)),
            (CandidateInnerRelationKindV1::NullifierTransition, None),
        ] {
            let mut hasher = Sha256::new();
            hasher.update(CANDIDATE_INNER_RELATION_RECEIPT_ID_DOMAIN);
            hasher.update([42; 32]);
            hasher.update([kind as u8]);
            hasher.update([index.unwrap_or(0xff)]);
            assert!(ids.insert(<[u8; 32]>::from(hasher.finalize())));
        }
    }

    #[test]
    fn statement_id_helper_matches_the_typed_statement_path() {
        // The full typed construction is covered by `public_statement`; this
        // fixed ID checks that the reusable derivation keeps its exact frame.
        let statement_id = [42; 32];
        let from_helper = candidate_inner_relation_receipt_id_from_statement_id(
            statement_id,
            CandidateInnerRelationKindV1::InputOwnership,
            Some(0),
        );
        let mut hasher = Sha256::new();
        hasher.update(CANDIDATE_INNER_RELATION_RECEIPT_ID_DOMAIN);
        hasher.update(statement_id);
        hasher.update([CandidateInnerRelationKindV1::InputOwnership as u8]);
        hasher.update([0]);
        assert_eq!(from_helper.as_bytes(), <[u8; 32]>::from(hasher.finalize()));
    }
}
