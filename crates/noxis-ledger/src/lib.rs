//! Deterministic state-transition engine for the Noxis research ledger.
//!
//! The engine validates public invariants and delegates privacy/conservation proofs
//! to an injected verifier. It contains no network, database or custody code.

mod error;
mod invariants;
mod model;
mod mutation;
mod state;

pub use error::{LedgerError, LedgerSnapshotError};
pub use model::{
    DenyAllMints, Mint, MintAuthorizationError, MintPolicy, MintStatement, Operation, Transaction,
    TransactionValidationContext, Transfer,
};
pub use state::{LedgerSnapshot, LedgerState};

#[cfg(test)]
mod tests {
    use noxis_crypto::{CryptoSuite, Proof, ProofVerifier, TransferStatement, VerificationError};
    use noxis_merkle::MerkleTree;
    use noxis_types::{
        Amount, AssetDefinition, AssetId, AssetKind, Commitment, GenesisId, MintPolicyId,
        Nullifier, ProofVerifierId, StateId, TransactionId, TransactionIntentId,
        ValidationContextId,
    };

    use super::*;

    const ASSET: AssetId = AssetId::new([1; 32]);

    struct TestVerifier;
    impl ProofVerifier for TestVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    struct RejectingVerifier;
    impl ProofVerifier for RejectingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([2; 32])
        }

        fn verify_transfer(
            &self,
            _statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            Err(VerificationError::InvalidProof)
        }
    }

    struct ContextCheckingVerifier;

    impl ProofVerifier for ContextCheckingVerifier {
        fn proof_verifier_id(&self) -> ProofVerifierId {
            ProofVerifierId::new([1; 32])
        }

        fn verify_transfer(
            &self,
            statement: &TransferStatement,
            _proof: &Proof,
        ) -> Result<(), VerificationError> {
            assert_eq!(statement.genesis_id, GenesisId::new([40; 32]));
            assert_eq!(
                statement.validation_context_id,
                ValidationContextId::new([41; 32])
            );
            assert_eq!(
                statement.transaction_intent_id,
                TransactionIntentId::new([42; 32])
            );
            assert_eq!(
                statement.state_id,
                state().state_id(GenesisId::new([40; 32]))
            );
            Ok(())
        }
    }

    struct TestMintPolicy;
    impl MintPolicy for TestMintPolicy {
        fn mint_policy_id(&self) -> MintPolicyId {
            MintPolicyId::new([3; 32])
        }

        fn authorize(
            &self,
            _statement: &MintStatement,
            authorization: &[u8],
        ) -> Result<(), MintAuthorizationError> {
            if authorization == b"test-authorized" {
                Ok(())
            } else {
                Err(MintAuthorizationError::Denied)
            }
        }
    }

    struct ContextCheckingMintPolicy;

    impl MintPolicy for ContextCheckingMintPolicy {
        fn mint_policy_id(&self) -> MintPolicyId {
            MintPolicyId::new([3; 32])
        }

        fn authorize(
            &self,
            statement: &MintStatement,
            authorization: &[u8],
        ) -> Result<(), MintAuthorizationError> {
            assert_eq!(statement.genesis_id, GenesisId::new([40; 32]));
            assert_eq!(
                statement.validation_context_id,
                ValidationContextId::new([41; 32])
            );
            assert_eq!(
                statement.transaction_intent_id,
                TransactionIntentId::new([42; 32])
            );
            assert_eq!(
                statement.state_id,
                state().state_id(GenesisId::new([40; 32]))
            );
            assert_eq!(statement.asset_id, ASSET);
            assert_eq!(statement.amount, Amount::new(100).unwrap());
            assert_eq!(statement.output_commitments, vec![Commitment::new([4; 32])]);
            assert_eq!(statement.issued_supply_before, None);
            assert_eq!(statement.state_anchor.tree_depth, 32);
            assert_eq!(authorization, b"test-authorized");
            Ok(())
        }
    }

    fn state() -> LedgerState {
        let mut state = LedgerState::default();
        state
            .register_asset(
                AssetDefinition::new(ASSET, "USDX", noxis_types::AssetKind::Synthetic).unwrap(),
            )
            .unwrap();
        state
    }

    fn transfer(id: u8, nullifier: u8, commitment: u8) -> Transaction {
        Transaction {
            id: TransactionId::new([id; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Transfer(Transfer {
                asset_id: ASSET,
                input_nullifiers: vec![Nullifier::new([nullifier; 32])],
                output_commitments: vec![Commitment::new([commitment; 32])],
                proof: Proof {
                    suite_version: 1,
                    bytes: vec![1],
                },
            }),
        }
    }

    fn test_context(state: &LedgerState) -> TransactionValidationContext {
        let genesis_id = GenesisId::new([40; 32]);
        TransactionValidationContext::new(
            genesis_id,
            ValidationContextId::new([41; 32]),
            TransactionIntentId::new([42; 32]),
            state.state_id(genesis_id),
        )
    }

    fn apply_with_test_context<V: ProofVerifier, P: MintPolicy>(
        state: &mut LedgerState,
        transaction: &Transaction,
        verifier: &V,
        mint_policy: &P,
    ) -> Result<(), LedgerError> {
        let context = test_context(state);
        state.apply(transaction, verifier, mint_policy, context)
    }

    #[test]
    fn a_nullifier_can_only_be_spent_once() {
        let mut state = state();
        apply_with_test_context(&mut state, &transfer(1, 9, 5), &TestVerifier, &DenyAllMints)
            .unwrap();
        let error =
            apply_with_test_context(&mut state, &transfer(2, 9, 6), &TestVerifier, &DenyAllMints)
                .unwrap_err();
        assert_eq!(
            error,
            LedgerError::NullifierAlreadySpent(Nullifier::new([9; 32]))
        );
    }

    #[test]
    fn a_commitment_cannot_be_reintroduced() {
        let mut state = state();
        apply_with_test_context(&mut state, &transfer(1, 8, 5), &TestVerifier, &DenyAllMints)
            .unwrap();
        let error =
            apply_with_test_context(&mut state, &transfer(2, 7, 5), &TestVerifier, &DenyAllMints)
                .unwrap_err();
        assert_eq!(
            error,
            LedgerError::CommitmentAlreadyExists(Commitment::new([5; 32]))
        );
    }

    #[test]
    fn rejected_proof_leaves_the_complete_state_unchanged() {
        let mut state = state();
        let before = state.snapshot();
        assert_eq!(
            apply_with_test_context(
                &mut state,
                &transfer(8, 11, 12),
                &RejectingVerifier,
                &DenyAllMints,
            ),
            Err(LedgerError::Proof(VerificationError::InvalidProof))
        );
        assert_eq!(state.snapshot(), before);
        assert!(!state.is_spent(Nullifier::new([11; 32])));
        assert!(!state.contains_commitment(Commitment::new([12; 32])));
    }

    #[test]
    fn transfer_proof_statement_carries_deployment_and_intent_bindings() {
        let mut state = state();
        apply_with_test_context(
            &mut state,
            &transfer(1, 8, 5),
            &ContextCheckingVerifier,
            &DenyAllMints,
        )
        .unwrap();
    }

    #[test]
    fn rejects_a_validation_context_for_a_different_pre_transition_state() {
        let mut state = state();
        let wrong_context = TransactionValidationContext::new(
            GenesisId::new([40; 32]),
            ValidationContextId::new([41; 32]),
            TransactionIntentId::new([42; 32]),
            StateId::new([99; 32]),
        );
        assert!(matches!(
            state.apply(
                &transfer(1, 8, 5),
                &TestVerifier,
                &DenyAllMints,
                wrong_context,
            ),
            Err(LedgerError::ValidationStateIdMismatch { .. })
        ));
    }

    #[test]
    fn minting_is_rejected_without_explicit_authorization() {
        let mut state = state();
        let mint = Transaction {
            id: TransactionId::new([3; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: ASSET,
                amount: Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([3; 32])],
                authorization: vec![],
            }),
        };
        assert_eq!(
            apply_with_test_context(&mut state, &mint, &TestVerifier, &DenyAllMints),
            Err(LedgerError::MintAuthorization(
                MintAuthorizationError::Denied
            ))
        );
        assert_eq!(state.issued_supply(ASSET), None);
    }

    #[test]
    fn authorized_mint_updates_supply_once() {
        let mut state = state();
        let mint = Transaction {
            id: TransactionId::new([4; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: ASSET,
                amount: Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([4; 32])],
                authorization: b"test-authorized".to_vec(),
            }),
        };
        apply_with_test_context(&mut state, &mint, &TestVerifier, &TestMintPolicy).unwrap();
        assert_eq!(state.issued_supply(ASSET).unwrap().units(), 100);
        assert!(state.contains_commitment(Commitment::new([4; 32])));
    }

    #[test]
    fn mint_policy_receives_a_complete_deployment_bound_issuance_statement() {
        let mut state = state();
        let mint = Transaction {
            id: TransactionId::new([4; 32]),
            suite: CryptoSuite::RESEARCH_V1,
            operation: Operation::Mint(Mint {
                asset_id: ASSET,
                amount: Amount::new(100).unwrap(),
                output_commitments: vec![Commitment::new([4; 32])],
                authorization: b"test-authorized".to_vec(),
            }),
        };
        apply_with_test_context(&mut state, &mint, &TestVerifier, &ContextCheckingMintPolicy)
            .unwrap();
    }

    #[test]
    fn equivalent_state_has_same_identity_and_transition_changes_it() {
        let genesis_id = GenesisId::new([42; 32]);
        let initial = state();
        let initial_id = initial.state_id(genesis_id);
        assert_eq!(initial_id, state().state_id(genesis_id));
        assert_ne!(initial_id, state().state_id(GenesisId::new([43; 32])));

        let mut changed = state();
        apply_with_test_context(
            &mut changed,
            &transfer(5, 6, 7),
            &TestVerifier,
            &DenyAllMints,
        )
        .unwrap();
        assert_ne!(initial_id, changed.state_id(genesis_id));
        assert_eq!(changed.state_id(genesis_id), changed.state_id(genesis_id));
    }

    #[test]
    fn canonical_snapshot_restores_every_observable_state_component() {
        let genesis_id = GenesisId::new([55; 32]);
        let mut original = state();
        apply_with_test_context(
            &mut original,
            &transfer(1, 9, 5),
            &TestVerifier,
            &DenyAllMints,
        )
        .unwrap();
        let snapshot = original.snapshot();
        let restored = LedgerState::from_snapshot(snapshot).unwrap();

        assert_eq!(restored.merkle_root(), original.merkle_root());
        assert_eq!(restored.state_id(genesis_id), original.state_id(genesis_id));
        assert!(restored.is_spent(Nullifier::new([9; 32])));
        assert!(restored.contains_commitment(Commitment::new([5; 32])));
        let proof = restored.prove_commitment(0).unwrap();
        assert!(
            MerkleTree::verify(restored.merkle_root(), Commitment::new([5; 32]), &proof).unwrap()
        );
    }

    #[test]
    fn snapshot_parts_reject_noncanonical_collections_before_restoring() {
        let first =
            AssetDefinition::new(AssetId::new([2; 32]), "USDX", AssetKind::Synthetic).unwrap();
        let second =
            AssetDefinition::new(AssetId::new([1; 32]), "EURX", AssetKind::Synthetic).unwrap();
        assert!(matches!(
            LedgerSnapshot::from_canonical_parts(
                4,
                vec![first, second],
                vec![],
                vec![],
                vec![],
                vec![]
            ),
            Err(LedgerSnapshotError::AssetsNotStrictlySorted { index: 1 })
        ));

        let asset = AssetDefinition::new(ASSET, "USDX", AssetKind::Synthetic).unwrap();
        assert!(matches!(
            LedgerSnapshot::from_canonical_parts(
                4,
                vec![asset],
                vec![Commitment::new([4; 32]), Commitment::new([4; 32])],
                vec![],
                vec![],
                vec![],
            ),
            Err(LedgerSnapshotError::DuplicateCommitment(_))
        ));
    }
}
