//! Representation owned by the candidate private ledger.

use std::collections::BTreeMap;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_privacy_types::{
    NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2, TreeParametersV2,
};
use noxis_types::{AssetDefinition, AssetId, GenesisId, StateId, ValidationContextId};

use super::CandidatePrivateTransferAuthorizationError;
use crate::{CandidatePrivateStateSnapshotV1, PrivateStateAnchorV2};

/// One fixed-width private transfer plus authorization material understood only
/// by the injected authorizer. The ledger never serializes or interprets that
/// material itself.
pub struct CandidatePrivateTransferRequestV1<A> {
    intent: PrivateTransferIntentV2,
    authorization: A,
}

impl<A> CandidatePrivateTransferRequestV1<A> {
    pub const fn new(intent: PrivateTransferIntentV2, authorization: A) -> Self {
        Self {
            intent,
            authorization,
        }
    }

    pub const fn intent(&self) -> &PrivateTransferIntentV2 {
        &self.intent
    }

    pub const fn authorization(&self) -> &A {
        &self.authorization
    }
}

/// Authorization seam between deterministic state admission and a concrete
/// proof implementation. It intentionally returns only accepted/rejected.
pub trait CandidatePrivateTransferAuthorizer<A> {
    fn verify(
        &self,
        authorization: &A,
        current_anchor: &PrivateStateAnchorV2,
        current_tree: &NullifierSparseTreeStateV1,
        intent: &PrivateTransferIntentV2,
    ) -> Result<(), CandidatePrivateTransferAuthorizationError>;
}

/// Public in-memory evidence of one committed candidate transition.
///
/// This is not a transaction receipt format and has no encoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferAdmissionReceiptV1 {
    pre_state_id: StateId,
    post_state_id: StateId,
    asset_id: AssetId,
    input_nullifiers: [NullifierV2; 2],
    output_commitments: [NoteCommitmentV2; 2],
}

impl CandidatePrivateTransferAdmissionReceiptV1 {
    pub(crate) const fn new(
        pre_state_id: StateId,
        post_state_id: StateId,
        asset_id: AssetId,
        input_nullifiers: [NullifierV2; 2],
        output_commitments: [NoteCommitmentV2; 2],
    ) -> Self {
        Self {
            pre_state_id,
            post_state_id,
            asset_id,
            input_nullifiers,
            output_commitments,
        }
    }

    pub const fn pre_state_id(&self) -> StateId {
        self.pre_state_id
    }

    pub const fn post_state_id(&self) -> StateId {
        self.post_state_id
    }

    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }

    pub const fn input_nullifiers(&self) -> &[NullifierV2; 2] {
        &self.input_nullifiers
    }

    pub const fn output_commitments(&self) -> &[NoteCommitmentV2; 2] {
        &self.output_commitments
    }
}

/// Complete mutable state for the local candidate private ledger.
///
/// Assets are public policy metadata. The cryptographic state consists of the
/// ordered note snapshot, 64-byte nullifier sparse tree and their typed anchor.
#[derive(Clone, Debug)]
pub struct CandidatePrivateLedgerStateV1 {
    pub(crate) assets: BTreeMap<AssetId, AssetDefinition>,
    pub(crate) snapshot: CandidatePrivateStateSnapshotV1,
    pub(crate) nullifier_tree: NullifierSparseTreeStateV1,
    pub(crate) anchor: PrivateStateAnchorV2,
}

impl CandidatePrivateLedgerStateV1 {
    /// Rebuilds the anchor from all supplied state instead of trusting a
    /// caller-provided state ID or root.
    pub fn new(
        genesis_id: GenesisId,
        validation_context_id: ValidationContextId,
        note_tree_parameters: TreeParametersV2,
        snapshot: CandidatePrivateStateSnapshotV1,
        nullifier_tree: NullifierSparseTreeStateV1,
    ) -> Result<Self, super::CandidatePrivateLedgerError> {
        let anchor = PrivateStateAnchorV2::new(
            genesis_id,
            validation_context_id,
            note_tree_parameters,
            &snapshot,
            &nullifier_tree,
        )?;
        Ok(Self {
            assets: BTreeMap::new(),
            snapshot,
            nullifier_tree,
            anchor,
        })
    }

    pub const fn snapshot(&self) -> &CandidatePrivateStateSnapshotV1 {
        &self.snapshot
    }

    pub const fn nullifier_tree(&self) -> &NullifierSparseTreeStateV1 {
        &self.nullifier_tree
    }

    pub const fn anchor(&self) -> &PrivateStateAnchorV2 {
        &self.anchor
    }

    pub fn asset(&self, asset_id: AssetId) -> Option<&AssetDefinition> {
        self.assets.get(&asset_id)
    }

    /// Public asset-policy entries in their canonical ascending asset-ID order.
    pub fn assets(&self) -> impl ExactSizeIterator<Item = &AssetDefinition> {
        self.assets.values()
    }
}
