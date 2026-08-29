//! Mutable, in-memory state for the candidate `NXSM` sparse nullifier tree.
//!
//! This crate intentionally owns only the sparse-tree representation, its
//! invariants and its atomic in-memory update. It has no ledger, persistence,
//! network, proof packet or settlement dependency. The cryptographic
//! calculation remains delegated to `noxis-nullifier-tree-reference` so an
//! auditor can inspect state mutation separately from the candidate evaluator.

mod error;
mod position;
mod proof;
mod state;
mod transition;

pub use error::NullifierSparseTreeStateError;
pub use proof::NullifierSparseProofV1;
pub use state::NullifierSparseTreeStateV1;
pub use transition::NullifierTreeUpdateV1;

#[cfg(test)]
mod tests {
    use noxis_nullifier_tree_reference::NullifierSparseTreeReferenceV1;
    use noxis_privacy_types::NullifierV2;
    use noxis_tree_params::{P24NullifierSparseVectorCorpusV1, P24NullifierSparseVectorRecordV1};

    use super::*;

    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).expect("small canonical fixture")
    }

    fn nullifier_with_path_bit(bit: usize) -> NullifierV2 {
        let mut elements = [0_u32; 16];
        elements[bit / 32] = 1 << (bit % 32);
        NullifierV2::from_elements(elements).expect("reachable canonical path bit")
    }

    #[test]
    fn empty_tree_generates_a_valid_absence_proof() {
        let tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let unspent = nullifier(7);
        let root = tree.root().unwrap();
        let proof = tree.prove(unspent);

        assert_eq!(tree.spent_count(), 0);
        assert_eq!(proof.len(), 512);
        assert_eq!(tree.verify_absence(root, unspent, &proof), Ok(()));
        assert!(tree.verify_inclusion(root, unspent, &proof).is_err());
    }

    #[test]
    fn first_spend_matches_the_reference_path_reconstruction() {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let nullifier = nullifier(9);
        let update = tree.mark_spent(nullifier).unwrap();
        let proof = tree.prove(nullifier);
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();

        assert_ne!(update.previous_root(), update.root());
        assert_eq!(update.root(), tree.root().unwrap());
        assert_eq!(
            tree.verify_inclusion(update.root(), nullifier, &proof),
            Ok(())
        );
        assert_eq!(
            reference.root_from_path(
                nullifier,
                reference.spent_leaf(nullifier).unwrap(),
                proof.siblings(),
            ),
            Ok(update.root())
        );
    }

    #[test]
    fn insertion_order_does_not_change_a_sparse_set_root() {
        let first = [nullifier(1), nullifier(7), nullifier(33)];
        let second = [nullifier(33), nullifier(1), nullifier(7)];
        let mut left = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let mut right = NullifierSparseTreeStateV1::new_candidate().unwrap();

        for nullifier in first {
            left.mark_spent(nullifier).unwrap();
        }
        for nullifier in second {
            right.mark_spent(nullifier).unwrap();
        }

        assert_eq!(left.root(), right.root());
        for nullifier in first {
            assert_eq!(
                left.verify_inclusion(left.root().unwrap(), nullifier, &left.prove(nullifier)),
                Ok(())
            );
        }
    }

    #[test]
    fn duplicate_spend_is_rejected_without_mutating_state() {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let nullifier = nullifier(11);
        tree.mark_spent(nullifier).unwrap();
        let root = tree.root().unwrap();
        let stored_nodes = tree.stored_node_count();
        let count = tree.spent_count();
        let proof = tree.prove(nullifier);

        assert_eq!(
            tree.mark_spent(nullifier),
            Err(NullifierSparseTreeStateError::AlreadySpent { nullifier })
        );
        assert_eq!(tree.root(), Ok(root));
        assert_eq!(tree.stored_node_count(), stored_nodes);
        assert_eq!(tree.spent_count(), count);
        assert_eq!(tree.verify_inclusion(root, nullifier, &proof), Ok(()));
    }

    #[test]
    fn paths_cover_low_byte_boundary_and_highest_reachable_bit() {
        let nullifiers = [
            nullifier_with_path_bit(0),
            nullifier_with_path_bit(8),
            nullifier_with_path_bit(510),
        ];
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for nullifier in nullifiers {
            tree.mark_spent(nullifier).unwrap();
        }
        let root = tree.root().unwrap();
        for nullifier in nullifiers {
            assert_eq!(
                tree.verify_inclusion(root, nullifier, &tree.prove(nullifier)),
                Ok(())
            );
        }
        assert_eq!(
            tree.verify_absence(root, nullifier(0), &tree.prove(nullifier(0))),
            Ok(())
        );
    }

    #[test]
    fn another_nullifier_cannot_reuse_an_existing_path() {
        let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let spent = nullifier(4);
        let other = nullifier(5);
        tree.mark_spent(spent).unwrap();
        let root = tree.root().unwrap();
        let proof = tree.prove(spent);

        assert!(tree.verify_inclusion(root, other, &proof).is_err());
        assert!(tree.verify_absence(root, spent, &proof).is_err());
    }

    #[test]
    fn externally_generated_nxsm_corpus_matches_reference_and_mutable_state() {
        let corpus = P24NullifierSparseVectorCorpusV1::frozen_external_kat_corpus().unwrap();
        let reference = NullifierSparseTreeReferenceV1::load_candidate().unwrap();
        let empty = reference.empty_values();

        for record in corpus.records() {
            match record {
                P24NullifierSparseVectorRecordV1::Leaf { nullifier, leaf } => {
                    assert_eq!(reference.spent_leaf(*nullifier).unwrap(), leaf.elements());
                }
                P24NullifierSparseVectorRecordV1::Node {
                    left,
                    right,
                    parent,
                } => {
                    let computed = reference.node(left.elements(), right.elements()).unwrap();
                    assert_eq!(
                        computed,
                        parent.elements(),
                        "external node inputs: left={:?}, right={:?}",
                        left.elements(),
                        right.elements(),
                    );
                }
                P24NullifierSparseVectorRecordV1::Empty { level, value } => {
                    assert_eq!(empty[*level as usize], value.elements());
                }
                P24NullifierSparseVectorRecordV1::Root { nullifiers, root } => {
                    let mut tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
                    for nullifier in nullifiers {
                        tree.mark_spent(*nullifier).unwrap();
                    }
                    assert_eq!(tree.root().unwrap().elements(), root.elements());
                }
            }
        }
    }
}
