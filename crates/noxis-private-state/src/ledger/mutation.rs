//! The only candidate private-ledger operations that mutate state.

use noxis_types::AssetDefinition;

use super::{
    CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1,
    CandidatePrivateTransferAdmissionReceiptV1, CandidatePrivateTransferAuthorizer,
    CandidatePrivateTransferRequestV1,
};

impl CandidatePrivateLedgerStateV1 {
    pub fn register_asset(
        &mut self,
        asset: AssetDefinition,
    ) -> Result<(), CandidatePrivateLedgerError> {
        if self.assets.contains_key(&asset.id) {
            return Err(CandidatePrivateLedgerError::AssetAlreadyRegistered(
                asset.id,
            ));
        }
        self.assets.insert(asset.id, asset);
        Ok(())
    }

    /// Validates authorization and the complete post-state before atomically
    /// replacing the three cryptographic state components.
    pub fn apply_transfer<A>(
        &mut self,
        request: &CandidatePrivateTransferRequestV1<A>,
        authorizer: &impl CandidatePrivateTransferAuthorizer<A>,
    ) -> Result<CandidatePrivateTransferAdmissionReceiptV1, CandidatePrivateLedgerError> {
        let transition = self.prepare_transfer(request, authorizer)?;
        let intent = request.intent();
        let receipt = CandidatePrivateTransferAdmissionReceiptV1::new(
            transition.pre_anchor().state_id(),
            transition.post_anchor().state_id(),
            intent.asset_id(),
            *intent.nullifiers(),
            intent.output_commitments(),
        );

        // Every fallible operation completed above. These replacements form
        // the sole mutation boundary and cannot leave a partial transition.
        self.snapshot = transition.post_snapshot().clone();
        self.nullifier_tree = transition.post_tree().clone();
        self.anchor = transition.post_anchor().clone();
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetDefinition, AssetId, AssetKind, GenesisId, ValidationContextId};

    use super::*;
    use crate::{CandidatePrivateStateSnapshotV1, CandidatePrivateTransferAuthorizationError};

    const ASSET_ID: AssetId = AssetId::new([5; 32]);

    struct AcceptAll;

    impl CandidatePrivateTransferAuthorizer<()> for AcceptAll {
        fn verify(
            &self,
            _authorization: &(),
            _current_anchor: &crate::PrivateStateAnchorV2,
            _current_tree: &NullifierSparseTreeStateV1,
            _intent: &PrivateTransferIntentV2,
        ) -> Result<(), CandidatePrivateTransferAuthorizationError> {
            Ok(())
        }
    }

    struct RejectAll;

    impl CandidatePrivateTransferAuthorizer<()> for RejectAll {
        fn verify(
            &self,
            _authorization: &(),
            _current_anchor: &crate::PrivateStateAnchorV2,
            _current_tree: &NullifierSparseTreeStateV1,
            _intent: &PrivateTransferIntentV2,
        ) -> Result<(), CandidatePrivateTransferAuthorizationError> {
            Err(CandidatePrivateTransferAuthorizationError::Rejected)
        }
    }

    struct MustNotRun;

    impl CandidatePrivateTransferAuthorizer<()> for MustNotRun {
        fn verify(
            &self,
            _authorization: &(),
            _current_anchor: &crate::PrivateStateAnchorV2,
            _current_tree: &NullifierSparseTreeStateV1,
            _intent: &PrivateTransferIntentV2,
        ) -> Result<(), CandidatePrivateTransferAuthorizationError> {
            panic!("authorizer must not run for a transparently invalid request")
        }
    }

    fn commitment(value: u32) -> NoteCommitmentV2 {
        NoteCommitmentV2::from_elements([value; 16]).unwrap()
    }

    fn nullifier(value: u32) -> NullifierV2 {
        NullifierV2::from_elements([value; 16]).unwrap()
    }

    fn candidate_parameters() -> TreeParametersV2 {
        TreeParametersV2::new(TreeParametersId::new(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()
                .unwrap()
                .as_bytes(),
        ))
    }

    fn state() -> CandidatePrivateLedgerStateV1 {
        let reference = Poseidon2P24Reference::load_candidate().unwrap();
        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![commitment(1), commitment(2)],
            vec![],
            &reference,
        )
        .unwrap();
        let tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        let mut state = CandidatePrivateLedgerStateV1::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            candidate_parameters(),
            snapshot,
            tree,
        )
        .unwrap();
        state
            .register_asset(AssetDefinition::new(ASSET_ID, "NOX", AssetKind::Synthetic).unwrap())
            .unwrap();
        state
    }

    fn intent(state: &CandidatePrivateLedgerStateV1) -> PrivateTransferIntentV2 {
        PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            state.anchor().genesis_id(),
            state.anchor().validation_context_id(),
            state.anchor().state_id(),
            state.anchor().note_tree_parameters(),
            state.anchor().note_root(),
            ASSET_ID,
            [nullifier(10), nullifier(11)],
            [
                PrivateTransferOutputV2::new(
                    commitment(12),
                    CiphertextDigestV2::from_elements([20; 16]).unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    commitment(13),
                    CiphertextDigestV2::from_elements([21; 16]).unwrap(),
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn atomically_applies_two_64_byte_nullifiers_and_two_outputs() {
        let mut state = state();
        let pre_state_id = state.anchor().state_id();
        let request = CandidatePrivateTransferRequestV1::new(intent(&state), ());
        assert_eq!(request.intent().nullifiers()[0].as_bytes().len(), 64);

        let receipt = state.apply_transfer(&request, &AcceptAll).unwrap();

        assert_eq!(receipt.pre_state_id(), pre_state_id);
        assert_eq!(receipt.post_state_id(), state.anchor().state_id());
        assert_ne!(receipt.pre_state_id(), receipt.post_state_id());
        assert_eq!(receipt.asset_id(), ASSET_ID);
        assert_eq!(state.snapshot().commitments().len(), 4);
        assert_eq!(
            &state.snapshot().commitments()[2..],
            receipt.output_commitments()
        );
        assert!(
            state
                .nullifier_tree()
                .is_spent(receipt.input_nullifiers()[0])
        );
        assert!(
            state
                .nullifier_tree()
                .is_spent(receipt.input_nullifiers()[1])
        );
        assert_eq!(state.nullifier_tree().spent_count(), 2);
    }

    #[test]
    fn rejected_authorization_leaves_every_state_component_unchanged() {
        let mut state = state();
        let request = CandidatePrivateTransferRequestV1::new(intent(&state), ());
        let before_snapshot = state.snapshot().clone();
        let before_anchor = state.anchor().clone();
        let before_root = state.nullifier_tree().root().unwrap();

        assert!(matches!(
            state.apply_transfer(&request, &RejectAll),
            Err(CandidatePrivateLedgerError::Authorization(
                CandidatePrivateTransferAuthorizationError::Rejected
            ))
        ));
        assert_eq!(state.snapshot(), &before_snapshot);
        assert_eq!(state.anchor(), &before_anchor);
        assert_eq!(state.nullifier_tree().root().unwrap(), before_root);
        assert_eq!(state.nullifier_tree().spent_count(), 0);
    }

    #[test]
    fn unknown_asset_and_replay_fail_before_authorization_or_mutation() {
        let mut state = state();
        let mut unknown_intent = intent(&state);
        let source = unknown_intent.clone();
        unknown_intent = PrivateTransferIntentV2::new(
            source.circuit_id(),
            source.genesis_id(),
            source.validation_context_id(),
            source.pre_state_id(),
            source.tree_parameters(),
            source.pre_state_root(),
            AssetId::new([99; 32]),
            *source.nullifiers(),
            *source.outputs(),
        )
        .unwrap();
        let unknown = CandidatePrivateTransferRequestV1::new(unknown_intent, ());
        let original_anchor = state.anchor().clone();
        assert!(matches!(
            state.apply_transfer(&unknown, &MustNotRun),
            Err(CandidatePrivateLedgerError::UnknownAsset(_))
        ));
        assert_eq!(state.anchor(), &original_anchor);

        let request = CandidatePrivateTransferRequestV1::new(intent(&state), ());
        state.apply_transfer(&request, &AcceptAll).unwrap();
        let committed_anchor = state.anchor().clone();
        assert!(matches!(
            state.apply_transfer(&request, &MustNotRun),
            Err(CandidatePrivateLedgerError::StateTransition(_))
        ));
        assert_eq!(state.anchor(), &committed_anchor);
        assert_eq!(state.snapshot().commitments().len(), 4);
        assert_eq!(state.nullifier_tree().spent_count(), 2);
    }
}
