//! Explicit, local-only demonstration of typed private-ledger admission.
//!
//! The construction uses deterministic research witnesses. It generates the
//! currently retained local proofs, verifies them through the ledger's
//! authorizer seam, commits one candidate private transfer and proves that a
//! replay cannot mutate the resulting state. No packet bytes, wallet secret,
//! persistence, network or consensus claim is made here.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
use noxis_poseidon2_reference::Poseidon2P24Reference;
use noxis_privacy_types::{
    CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
    PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
};
use noxis_private_state::{
    CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1, CandidatePrivateStateSnapshotV1,
    CandidatePrivateTransferAdmissionReceiptV1, CandidatePrivateTransferRequestV1,
    PrivateStateAnchorV2,
};
use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
use noxis_types::{AssetDefinition, AssetId, AssetKind, GenesisId, StateId, ValidationContextId};

use crate::{
    CandidateAnchoredOwnershipWitnessV1, CandidateOutputNoteWitnessV1,
    CandidatePrivateTransferProofBundleVerifierV1, CandidatePrivateTransferProofPublicStatementV1,
    prove_candidate_private_transfer_proof_bundle,
};

const DEMO_ASSET: AssetId = AssetId::new([5; 32]);

/// Public, non-secret facts produced by the local private-ledger demonstration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateLedgerDemoReportV1 {
    initial_state_id: StateId,
    accepted: CandidatePrivateTransferAdmissionReceiptV1,
    initial_commitment_count: usize,
    final_commitment_count: usize,
    initial_spent_nullifier_count: u64,
    final_spent_nullifier_count: u64,
}

impl CandidatePrivateLedgerDemoReportV1 {
    pub const fn initial_state_id(&self) -> StateId {
        self.initial_state_id
    }

    pub const fn accepted(&self) -> &CandidatePrivateTransferAdmissionReceiptV1 {
        &self.accepted
    }

    pub const fn initial_commitment_count(&self) -> usize {
        self.initial_commitment_count
    }

    pub const fn final_commitment_count(&self) -> usize {
        self.final_commitment_count
    }

    pub const fn initial_spent_nullifier_count(&self) -> u64 {
        self.initial_spent_nullifier_count
    }

    pub const fn final_spent_nullifier_count(&self) -> u64 {
        self.final_spent_nullifier_count
    }
}

/// Runs the full proof-to-commit-and-replay sequence with deterministic
/// research fixtures.
///
/// This takes several minutes in an optimized build because the current
/// backend creates and verifies three independent local STARK proofs.
pub fn run_candidate_private_ledger_demo()
-> Result<CandidatePrivateLedgerDemoReportV1, CandidatePrivateLedgerDemoError> {
    let privacy = attempt(Poseidon2P24PrivacyReference::load_candidate())?;
    let tree_reference = attempt(Poseidon2P24Reference::load_candidate())?;
    let first_key = core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(3));
    let second_key = core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(5));

    let mut first_note = note_with_recipient(attempt(privacy.hash_addr(&first_key))?, 7);
    let mut second_note = note_with_recipient(attempt(privacy.hash_addr(&second_key))?, 11);
    set_asset_and_value(&mut first_note, 40);
    set_asset_and_value(&mut second_note, 60);
    let first_commitment = attempt(privacy.hash_note(&first_note))?;
    let second_commitment = attempt(privacy.hash_note(&second_note))?;
    let (_, first_siblings, _) =
        attempt(tree_reference.small_tree_path(&[first_commitment, second_commitment], 0))?;
    let (_, second_siblings, _) =
        attempt(tree_reference.small_tree_path(&[first_commitment, second_commitment], 1))?;

    let first_nullifier = attempt(NullifierV2::from_elements(attempt(
        privacy.hash_nullifier_preimage(&nullifier_preimage(
            first_key,
            first_note,
            first_commitment,
            0,
        )),
    )?))?;
    let second_nullifier = attempt(NullifierV2::from_elements(attempt(
        privacy.hash_nullifier_preimage(&nullifier_preimage(
            second_key,
            second_note,
            second_commitment,
            1,
        )),
    )?))?;
    let first_witness =
        CandidateAnchoredOwnershipWitnessV1::new(first_key, first_note, 0, first_siblings);
    let second_witness =
        CandidateAnchoredOwnershipWitnessV1::new(second_key, second_note, 1, second_siblings);
    let (nullifiers, input_witnesses) = if first_nullifier.as_bytes() < second_nullifier.as_bytes()
    {
        (
            [first_nullifier, second_nullifier],
            [first_witness, second_witness],
        )
    } else {
        (
            [second_nullifier, first_nullifier],
            [second_witness, first_witness],
        )
    };

    let mut output_one = note_with_recipient(attempt(privacy.hash_addr(&[21; 32]))?, 13);
    let mut output_two = note_with_recipient(attempt(privacy.hash_addr(&[37; 32]))?, 17);
    set_asset_and_value(&mut output_one, 45);
    set_asset_and_value(&mut output_two, 55);
    let mut outputs = [
        (
            attempt(NoteCommitmentV2::from_elements(attempt(
                privacy.hash_note(&output_one),
            )?))?,
            output_one,
        ),
        (
            attempt(NoteCommitmentV2::from_elements(attempt(
                privacy.hash_note(&output_two),
            )?))?,
            output_two,
        ),
    ];
    outputs.sort_by_key(|(commitment, _)| commitment.as_bytes());

    let snapshot = attempt(CandidatePrivateStateSnapshotV1::new(
        vec![
            attempt(NoteCommitmentV2::from_elements(first_commitment))?,
            attempt(NoteCommitmentV2::from_elements(second_commitment))?,
        ],
        vec![
            attempt(NullifierV2::from_elements([3; 16]))?,
            attempt(NullifierV2::from_elements([9; 16]))?,
        ],
        &tree_reference,
    ))?;
    let mut pre_tree = attempt(NullifierSparseTreeStateV1::new_candidate())?;
    for spent in snapshot.spent_nullifiers() {
        attempt(pre_tree.mark_spent(*spent))?;
    }
    let tree_parameters = TreeParametersV2::new(TreeParametersId::new(
        attempt(CandidatePoseidon2P24ManifestV2::new().candidate_id())?.as_bytes(),
    ));
    let anchor = attempt(PrivateStateAnchorV2::new(
        GenesisId::new([1; 32]),
        ValidationContextId::new([2; 32]),
        tree_parameters,
        &snapshot,
        &pre_tree,
    ))?;
    let intent = attempt(PrivateTransferIntentV2::new(
        CircuitId::new([4; 32]),
        anchor.genesis_id(),
        anchor.validation_context_id(),
        anchor.state_id(),
        anchor.note_tree_parameters(),
        anchor.note_root(),
        DEMO_ASSET,
        nullifiers,
        [
            PrivateTransferOutputV2::new(
                outputs[0].0,
                attempt(CiphertextDigestV2::from_elements([41; 16]))?,
            ),
            PrivateTransferOutputV2::new(
                outputs[1].0,
                attempt(CiphertextDigestV2::from_elements([43; 16]))?,
            ),
        ],
    ))?;
    let statement = attempt(CandidatePrivateTransferProofPublicStatementV1::new(
        anchor, &pre_tree, intent,
    ))?;
    let output_witnesses = [
        CandidateOutputNoteWitnessV1::new(outputs[0].1),
        CandidateOutputNoteWitnessV1::new(outputs[1].1),
    ];
    let bundle = attempt(prove_candidate_private_transfer_proof_bundle(
        &statement,
        &pre_tree,
        &input_witnesses,
        &output_witnesses,
    ))?;

    let mut ledger = attempt(CandidatePrivateLedgerStateV1::new(
        statement.anchor().genesis_id(),
        statement.anchor().validation_context_id(),
        statement.anchor().note_tree_parameters(),
        snapshot,
        pre_tree,
    ))?;
    attempt(ledger.register_asset(attempt(AssetDefinition::new(
        DEMO_ASSET,
        "NOX",
        AssetKind::Synthetic,
    ))?))?;
    let initial_state_id = ledger.anchor().state_id();
    let initial_commitment_count = ledger.snapshot().commitments().len();
    let initial_spent_nullifier_count = ledger.nullifier_tree().spent_count();
    let request = CandidatePrivateTransferRequestV1::new(
        statement.air_public_inputs().intent().clone(),
        bundle,
    );
    let accepted = attempt(ledger.apply_transfer(
        &request,
        &CandidatePrivateTransferProofBundleVerifierV1::new(),
    ))?;
    let final_commitment_count = ledger.snapshot().commitments().len();
    let final_spent_nullifier_count = ledger.nullifier_tree().spent_count();
    match ledger.apply_transfer(
        &request,
        &CandidatePrivateTransferProofBundleVerifierV1::new(),
    ) {
        Err(CandidatePrivateLedgerError::StateTransition(_)) => {}
        Err(error) => {
            return Err(CandidatePrivateLedgerDemoError::new(format!(
                "replay was rejected for an unexpected reason: {error}"
            )));
        }
        Ok(_) => {
            return Err(CandidatePrivateLedgerDemoError::new(
                "replay was incorrectly accepted".to_owned(),
            ));
        }
    }
    Ok(CandidatePrivateLedgerDemoReportV1 {
        initial_state_id,
        accepted,
        initial_commitment_count,
        final_commitment_count,
        initial_spent_nullifier_count,
        final_spent_nullifier_count,
    })
}

fn note_with_recipient(recipient: [u32; 16], seed: u8) -> [u8; 178] {
    let mut note = core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(seed));
    note[..2].copy_from_slice(&1_u16.to_be_bytes());
    for (lane, value) in recipient.into_iter().enumerate() {
        note[50 + (lane * 4)..54 + (lane * 4)].copy_from_slice(&value.to_le_bytes());
    }
    note
}

fn set_asset_and_value(note: &mut [u8; 178], value: u128) {
    note[2..34].copy_from_slice(&DEMO_ASSET.0);
    note[34..50].copy_from_slice(&value.to_be_bytes());
}

fn nullifier_preimage(
    key: [u8; 32],
    note: [u8; 178],
    commitment: [u32; 16],
    position: u32,
) -> [u8; 132] {
    let mut bytes = [0_u8; 132];
    bytes[..32].copy_from_slice(&key);
    bytes[32..64].copy_from_slice(&note[114..146]);
    for (lane, value) in commitment.into_iter().enumerate() {
        bytes[64 + (lane * 4)..68 + (lane * 4)].copy_from_slice(&value.to_le_bytes());
    }
    bytes[128..].copy_from_slice(&position.to_be_bytes());
    bytes
}

fn attempt<T, E: fmt::Display>(result: Result<T, E>) -> Result<T, CandidatePrivateLedgerDemoError> {
    result.map_err(|error| CandidatePrivateLedgerDemoError::new(error.to_string()))
}

/// Error from the deterministic local demo harness, never a protocol verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateLedgerDemoError {
    detail: String,
}

impl CandidatePrivateLedgerDemoError {
    const fn new(detail: String) -> Self {
        Self { detail }
    }
}

impl fmt::Display for CandidatePrivateLedgerDemoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-ledger demo failed: {}",
            self.detail
        )
    }
}

impl std::error::Error for CandidatePrivateLedgerDemoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "expensive cryptographic integration; run explicitly with --release"]
    fn proves_commits_and_rejects_replay_through_the_local_demo() {
        let report = run_candidate_private_ledger_demo().unwrap();
        assert_ne!(report.initial_state_id(), report.accepted().post_state_id());
        assert_eq!(report.initial_commitment_count(), 2);
        assert_eq!(report.final_commitment_count(), 4);
        assert_eq!(report.initial_spent_nullifier_count(), 2);
        assert_eq!(report.final_spent_nullifier_count(), 4);
    }
}
