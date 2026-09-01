//! Preconditions and immutable preparation for private-ledger admission.

use noxis_poseidon2_reference::Poseidon2P24Reference;

use super::{
    CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1, CandidatePrivateTransferAuthorizer,
    CandidatePrivateTransferRequestV1,
};
use crate::CandidatePrivateStateTransitionV2;

impl CandidatePrivateLedgerStateV1 {
    pub(crate) fn prepare_transfer<A>(
        &self,
        request: &CandidatePrivateTransferRequestV1<A>,
        authorizer: &impl CandidatePrivateTransferAuthorizer<A>,
    ) -> Result<CandidatePrivateStateTransitionV2, CandidatePrivateLedgerError> {
        let intent = request.intent();
        if !self.assets.contains_key(&intent.asset_id()) {
            return Err(CandidatePrivateLedgerError::UnknownAsset(intent.asset_id()));
        }

        // Build the entire post-state on clones first. This catches stale
        // anchors, spent inputs, duplicate outputs and capacity errors without
        // changing any ledger field or invoking an expensive verifier.
        let reference = Poseidon2P24Reference::load_candidate()
            .map_err(crate::CandidatePrivateStateError::from)
            .map_err(crate::CandidatePrivateStateTransitionV2Error::from)?;
        let transition = CandidatePrivateStateTransitionV2::apply(
            &self.anchor,
            &self.snapshot,
            &self.nullifier_tree,
            intent,
            &reference,
        )?;

        authorizer.verify(
            request.authorization(),
            &self.anchor,
            &self.nullifier_tree,
            intent,
        )?;

        // Re-execute the prepared transition after authorization. No mutable
        // state can change while `&mut self` is held by the caller, but this
        // check makes the exact all-or-nothing handoff explicit for reviewers.
        transition.revalidate(
            &self.anchor,
            &self.snapshot,
            &self.nullifier_tree,
            intent,
            &reference,
        )?;
        Ok(transition)
    }
}
