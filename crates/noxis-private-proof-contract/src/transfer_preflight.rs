//! One executable local preflight over every currently implemented candidate
//! private-transfer proof relation.
//!
//! The relations are still proved independently and sequentially. This module
//! makes their shared statement boundary executable without representing that
//! sequence as an aggregate proof, a selected verifier or a ledger transition.

use std::fmt;

use noxis_nullifier_tree_state::NullifierSparseTreeStateV1;
use noxis_private_packet_validation::{
    CandidatePrivatePacketEnvelopeValidationError,
    CandidatePrivateTransferPacketEnvelopeValidationV1,
    validate_candidate_private_transfer_packet_envelopes,
};
use noxis_stark_experiment::{
    Poseidon2P24IntentExperimentResult, Poseidon2P24NoteWithAssetExperimentResult,
    Poseidon2P24OwnershipExperimentResult, StarkExperimentError,
};

use crate::{
    CandidateAnchoredOwnershipError, CandidateAnchoredOwnershipPairPreflightV1,
    CandidateAnchoredOwnershipWitnessV1, CandidateNxsmNullifierTransitionWitnessError,
    CandidateNxsmNullifierTransitionWitnessV1, CandidateOutputNoteWitnessV1,
    CandidateOutputNotesError, CandidateOutputNotesPreflightV1,
    CandidatePrivateTransferProofPublicStatementError,
    CandidatePrivateTransferProofPublicStatementIdV1,
    CandidatePrivateTransferProofPublicStatementV1, CandidateValueConservationError,
    revalidate_candidate_anchored_ownership_pair_preflight,
    revalidate_candidate_output_notes_preflight,
    run_candidate_anchored_ownership_pair_preflight_bound_note_commitments,
    run_candidate_output_notes_preflight, run_candidate_value_conservation_preflight,
};

/// Public results retained after the complete sequential candidate preflight.
///
/// The opaque STARK proof objects have already been verified and dropped. These
/// results cannot be submitted or independently verified by another process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferStarkPreflightResultsV1 {
    /// Public `H_INTENT` result for the canonical 640-byte intent.
    pub intent: Poseidon2P24IntentExperimentResult,
    /// Public ownership results for canonical input slots zero and one.
    pub inputs: [Poseidon2P24OwnershipExperimentResult; 2],
    /// Public `H_NOTE` results for canonical output slots zero and one.
    pub outputs: [Poseidon2P24NoteWithAssetExperimentResult; 2],
}

/// Receipt from one complete run of the currently available proof relations.
///
/// Its value relation contains a composed `H_INTENT` + four `H_NOTE` AIR, then
/// two input-ownership relations and two output-note relations run locally
/// against the same `NXPU v1` statement. The `NXSM` witness remains transparent
/// local material; this is not aggregation, recursion or settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferStarkPreflightV1 {
    intent_result: Poseidon2P24IntentExperimentResult,
    ownership: CandidateAnchoredOwnershipPairPreflightV1,
    outputs: CandidateOutputNotesPreflightV1,
    statement_id: CandidatePrivateTransferProofPublicStatementIdV1,
}

/// Complete local preflight retaining the validated `NXPT` envelope receipt
/// beside the sequential STARK-relation receipt.
///
/// This proves only that one local process first checked the candidate packet
/// envelope bindings and then used its same intent for the existing relations.
/// It is not a portable proof, packet authorization or ledger transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePacketBoundPrivateTransferStarkPreflightV1 {
    packet_envelopes: CandidatePrivateTransferPacketEnvelopeValidationV1,
    stark: CandidatePrivateTransferStarkPreflightV1,
}

impl CandidatePacketBoundPrivateTransferStarkPreflightV1 {
    /// The receipt proving the two packet envelopes matched the packet intent.
    pub const fn packet_envelopes(&self) -> &CandidatePrivateTransferPacketEnvelopeValidationV1 {
        &self.packet_envelopes
    }

    /// The receipt from the sequential private-transfer relation preflight.
    pub const fn stark(&self) -> &CandidatePrivateTransferStarkPreflightV1 {
        &self.stark
    }
}

impl CandidatePrivateTransferStarkPreflightV1 {
    /// Public `H_INTENT` result shared by the complete run.
    pub const fn intent_result(&self) -> &Poseidon2P24IntentExperimentResult {
        &self.intent_result
    }

    /// Ownership-only receipt for the two canonical input slots.
    pub const fn ownership(&self) -> &CandidateAnchoredOwnershipPairPreflightV1 {
        &self.ownership
    }

    /// Output-note-only receipt for the two canonical output slots.
    pub const fn outputs(&self) -> &CandidateOutputNotesPreflightV1 {
        &self.outputs
    }

    /// Identity of the exact `NXPU v1` statement used by every relation.
    pub const fn statement_id(&self) -> CandidatePrivateTransferProofPublicStatementIdV1 {
        self.statement_id
    }
}

/// Executes every currently available candidate proof relation for a fixed 2×2
/// private-transfer statement.
///
/// First a single composed AIR binds `H_INTENT`, all four `H_NOTE` openings,
/// the intent output slots and value conservation. Then both input ownership
/// proofs and both output `H_NOTE` proofs run sequentially. Every result is
/// bound to the same statement identity before it is retained.
pub fn run_candidate_private_transfer_stark_preflight(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    input_witnesses: &[CandidateAnchoredOwnershipWitnessV1; 2],
    output_witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<CandidatePrivateTransferStarkPreflightV1, CandidatePrivateTransferStarkPreflightError> {
    statement.revalidate(pre_tree)?;
    nxsm_witness.revalidate(statement.nullifier_transition())?;
    // This is a local transparent gate, not a substitute for the future AIR.
    // Run it before expensive STARK work so a malformed value/asset witness
    // cannot consume proving resources or be mistaken for a transfer preflight.
    let value_conservation = run_candidate_value_conservation_preflight(
        statement,
        pre_tree,
        input_witnesses,
        output_witnesses,
    )?;

    let intent_result = value_conservation.intent_result().clone();
    validate_intent_result(statement, &intent_result)?;
    let ownership = run_candidate_anchored_ownership_pair_preflight_bound_note_commitments(
        statement,
        pre_tree,
        nxsm_witness,
        &input_witnesses[0],
        &input_witnesses[1],
        value_conservation.input_note_commitments(),
    )?;
    let outputs = run_candidate_output_notes_preflight(statement, pre_tree, output_witnesses)?;

    Ok(CandidatePrivateTransferStarkPreflightV1 {
        intent_result,
        ownership,
        outputs,
        statement_id: statement.statement_id(),
    })
}

/// Runs the candidate preflight only after a separate `NXPT` envelope receipt
/// has accepted both `NXRE` values, and only if that receipt's intent equals
/// the statement's intent byte-for-byte.
pub fn run_candidate_packet_bound_private_transfer_stark_preflight(
    packet_envelopes: CandidatePrivateTransferPacketEnvelopeValidationV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
    input_witnesses: &[CandidateAnchoredOwnershipWitnessV1; 2],
    output_witnesses: &[CandidateOutputNoteWitnessV1; 2],
) -> Result<
    CandidatePacketBoundPrivateTransferStarkPreflightV1,
    CandidatePrivateTransferStarkPreflightError,
> {
    validate_packet_intent(&packet_envelopes, statement)?;
    let stark = run_candidate_private_transfer_stark_preflight(
        statement,
        pre_tree,
        nxsm_witness,
        input_witnesses,
        output_witnesses,
    )?;
    Ok(CandidatePacketBoundPrivateTransferStarkPreflightV1 {
        packet_envelopes,
        stark,
    })
}

/// Rechecks every retained public and transparent-state binding from a
/// completed complete preflight. It cannot reverify the discarded proofs.
pub fn revalidate_candidate_private_transfer_stark_preflight(
    preflight: &CandidatePrivateTransferStarkPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
) -> Result<
    CandidatePrivateTransferStarkPreflightResultsV1,
    CandidatePrivateTransferStarkPreflightError,
> {
    if preflight.statement_id != statement.statement_id() {
        return Err(CandidatePrivateTransferStarkPreflightError::StatementIdMismatch);
    }
    validate_intent_result(statement, &preflight.intent_result)?;
    let inputs = revalidate_candidate_anchored_ownership_pair_preflight(
        &preflight.ownership,
        statement,
        pre_tree,
        nxsm_witness,
    )?;
    let outputs =
        revalidate_candidate_output_notes_preflight(&preflight.outputs, statement, pre_tree)?;
    Ok(CandidatePrivateTransferStarkPreflightResultsV1 {
        intent: preflight.intent_result.clone(),
        inputs,
        outputs,
    })
}

/// Revalidates the packet receipt from its retained packet bytes, checks it
/// against the same statement intent, then revalidates the retained public
/// STARK-relation bindings. Opaque proofs remain unavailable by design.
pub fn revalidate_candidate_packet_bound_private_transfer_stark_preflight(
    preflight: &CandidatePacketBoundPrivateTransferStarkPreflightV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    pre_tree: &NullifierSparseTreeStateV1,
    nxsm_witness: &CandidateNxsmNullifierTransitionWitnessV1,
) -> Result<
    CandidatePrivateTransferStarkPreflightResultsV1,
    CandidatePrivateTransferStarkPreflightError,
> {
    let recomputed_packet = validate_candidate_private_transfer_packet_envelopes(
        preflight.packet_envelopes.packet().clone(),
    )?;
    if recomputed_packet != preflight.packet_envelopes {
        return Err(CandidatePrivateTransferStarkPreflightError::PacketReceiptMismatch);
    }
    validate_packet_intent(&recomputed_packet, statement)?;
    revalidate_candidate_private_transfer_stark_preflight(
        &preflight.stark,
        statement,
        pre_tree,
        nxsm_witness,
    )
}

fn validate_packet_intent(
    packet_envelopes: &CandidatePrivateTransferPacketEnvelopeValidationV1,
    statement: &CandidatePrivateTransferProofPublicStatementV1,
) -> Result<(), CandidatePrivateTransferStarkPreflightError> {
    if packet_envelopes.packet().intent() != statement.air_public_inputs().intent() {
        return Err(CandidatePrivateTransferStarkPreflightError::PacketIntentMismatch);
    }
    Ok(())
}

fn validate_intent_result(
    statement: &CandidatePrivateTransferProofPublicStatementV1,
    result: &Poseidon2P24IntentExperimentResult,
) -> Result<(), CandidatePrivateTransferStarkPreflightError> {
    if result.intent_commitment != statement.air_public_inputs().intent_commitment() {
        return Err(CandidatePrivateTransferStarkPreflightError::IntentCommitmentMismatch);
    }
    Ok(())
}

/// Fail-closed errors from the complete sequential candidate preflight.
#[derive(Debug)]
pub enum CandidatePrivateTransferStarkPreflightError {
    PublicStatement(CandidatePrivateTransferProofPublicStatementError),
    NxsmWitness(CandidateNxsmNullifierTransitionWitnessError),
    Ownership(CandidateAnchoredOwnershipError),
    OutputNotes(CandidateOutputNotesError),
    ValueConservation(CandidateValueConservationError),
    PacketEnvelope(CandidatePrivatePacketEnvelopeValidationError),
    Stark(StarkExperimentError),
    StatementIdMismatch,
    IntentCommitmentMismatch,
    PacketIntentMismatch,
    PacketReceiptMismatch,
}

impl From<CandidatePrivateTransferProofPublicStatementError>
    for CandidatePrivateTransferStarkPreflightError
{
    fn from(value: CandidatePrivateTransferProofPublicStatementError) -> Self {
        Self::PublicStatement(value)
    }
}

impl From<CandidateNxsmNullifierTransitionWitnessError>
    for CandidatePrivateTransferStarkPreflightError
{
    fn from(value: CandidateNxsmNullifierTransitionWitnessError) -> Self {
        Self::NxsmWitness(value)
    }
}

impl From<CandidateAnchoredOwnershipError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: CandidateAnchoredOwnershipError) -> Self {
        Self::Ownership(value)
    }
}

impl From<CandidateOutputNotesError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: CandidateOutputNotesError) -> Self {
        Self::OutputNotes(value)
    }
}

impl From<CandidateValueConservationError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: CandidateValueConservationError) -> Self {
        Self::ValueConservation(value)
    }
}

impl From<CandidatePrivatePacketEnvelopeValidationError>
    for CandidatePrivateTransferStarkPreflightError
{
    fn from(value: CandidatePrivatePacketEnvelopeValidationError) -> Self {
        Self::PacketEnvelope(value)
    }
}

impl From<StarkExperimentError> for CandidatePrivateTransferStarkPreflightError {
    fn from(value: StarkExperimentError) -> Self {
        Self::Stark(value)
    }
}

impl fmt::Display for CandidatePrivateTransferStarkPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate private-transfer STARK preflight error: {self:?}"
        )
    }
}

impl std::error::Error for CandidatePrivateTransferStarkPreflightError {}

#[cfg(test)]
mod tests {
    use crate::{
        CandidatePrivateProofBundleEnvelopeV1, CandidatePrivateTransferProofBundleVerifierV1,
        prove_candidate_private_transfer_proof_bundle,
    };
    use noxis_codec::PrivateTransferPacketV2;
    use noxis_poseidon2_privacy_reference::Poseidon2P24PrivacyReference;
    use noxis_poseidon2_reference::Poseidon2P24Reference;
    use noxis_privacy_types::{
        CiphertextDigestV2, CircuitId, NoteCommitmentV2, NullifierV2,
        PrivateTransferIntentCommitmentV2, PrivateTransferIntentV2, PrivateTransferOutputV2,
        TreeParametersId, TreeParametersV2,
    };
    use noxis_private_packet_validation::validate_candidate_private_transfer_packet_envelopes;
    use noxis_private_state::{
        CandidatePrivateLedgerError, CandidatePrivateLedgerStateV1,
        CandidatePrivateStateSnapshotV1, CandidatePrivateTransferRequestV1, PrivateStateAnchorV2,
    };
    use noxis_tree_params::CandidatePoseidon2P24ManifestV2;
    use noxis_types::{AssetDefinition, AssetId, AssetKind, GenesisId, ValidationContextId};
    use noxis_wallet_crypto::{
        CandidatePrivateOutputSlotV1, HybridPaymentAddressEntry, RecipientEnvelopeContext,
        candidate_ciphertext_digest_v1, encode_hybrid_recipient_envelope,
    };

    use super::*;

    fn vector(value: u32) -> [u32; 16] {
        [value; 16]
    }

    fn note_with_recipient(recipient: [u32; 16], seed: u8) -> [u8; 178] {
        let mut note =
            core::array::from_fn(|index| (index as u8).wrapping_mul(19).wrapping_add(seed));
        note[..2].copy_from_slice(&1_u16.to_be_bytes());
        for (lane, value) in recipient.into_iter().enumerate() {
            note[50 + (lane * 4)..54 + (lane * 4)].copy_from_slice(&value.to_le_bytes());
        }
        note
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

    #[test]
    #[ignore = "expensive cryptographic integration; run explicitly with --release"]
    fn executes_every_available_private_relation_for_one_statement() {
        let privacy = Poseidon2P24PrivacyReference::load_candidate().unwrap();
        let tree_reference = Poseidon2P24Reference::load_candidate().unwrap();
        let first_key =
            core::array::from_fn(|index| (index as u8).wrapping_mul(13).wrapping_add(3));
        let second_key =
            core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(5));
        let mut first_note = note_with_recipient(privacy.hash_addr(&first_key).unwrap(), 7);
        let mut second_note = note_with_recipient(privacy.hash_addr(&second_key).unwrap(), 11);
        first_note[2..34].copy_from_slice(&[5; 32]);
        second_note[2..34].copy_from_slice(&[5; 32]);
        first_note[34..50].copy_from_slice(&40_u128.to_be_bytes());
        second_note[34..50].copy_from_slice(&60_u128.to_be_bytes());
        let first_commitment = privacy.hash_note(&first_note).unwrap();
        let second_commitment = privacy.hash_note(&second_note).unwrap();
        let (_, first_siblings, root) = tree_reference
            .small_tree_path(&[first_commitment, second_commitment], 0)
            .unwrap();
        let (_, second_siblings, second_root) = tree_reference
            .small_tree_path(&[first_commitment, second_commitment], 1)
            .unwrap();
        assert_eq!(root, second_root);

        let first_nullifier = NullifierV2::from_elements(
            privacy
                .hash_nullifier_preimage(&nullifier_preimage(
                    first_key,
                    first_note,
                    first_commitment,
                    0,
                ))
                .unwrap(),
        )
        .unwrap();
        let second_nullifier = NullifierV2::from_elements(
            privacy
                .hash_nullifier_preimage(&nullifier_preimage(
                    second_key,
                    second_note,
                    second_commitment,
                    1,
                ))
                .unwrap(),
        )
        .unwrap();
        let first_witness =
            CandidateAnchoredOwnershipWitnessV1::new(first_key, first_note, 0, first_siblings);
        let second_witness =
            CandidateAnchoredOwnershipWitnessV1::new(second_key, second_note, 1, second_siblings);
        let (nullifiers, input_witnesses) =
            if first_nullifier.as_bytes() < second_nullifier.as_bytes() {
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

        let mut output_one = note_with_recipient(privacy.hash_addr(&[21; 32]).unwrap(), 13);
        let mut output_two = note_with_recipient(privacy.hash_addr(&[37; 32]).unwrap(), 17);
        output_one[2..34].copy_from_slice(&[5; 32]);
        output_two[2..34].copy_from_slice(&[5; 32]);
        output_one[34..50].copy_from_slice(&45_u128.to_be_bytes());
        output_two[34..50].copy_from_slice(&55_u128.to_be_bytes());
        let mut outputs = [output_one, output_two].map(|note| {
            (
                NoteCommitmentV2::from_elements(privacy.hash_note(&note).unwrap()).unwrap(),
                note,
            )
        });
        outputs.sort_by_key(|(commitment, _)| commitment.as_bytes());
        assert_ne!(outputs[0].0, outputs[1].0);

        let snapshot = CandidatePrivateStateSnapshotV1::new(
            vec![
                NoteCommitmentV2::from_elements(first_commitment).unwrap(),
                NoteCommitmentV2::from_elements(second_commitment).unwrap(),
            ],
            vec![
                NullifierV2::from_elements(vector(3)).unwrap(),
                NullifierV2::from_elements(vector(9)).unwrap(),
            ],
            &tree_reference,
        )
        .unwrap();
        let mut pre_tree = NullifierSparseTreeStateV1::new_candidate().unwrap();
        for spent in snapshot.spent_nullifiers() {
            pre_tree.mark_spent(*spent).unwrap();
        }
        let tree_parameters = TreeParametersV2::new(TreeParametersId::new(
            CandidatePoseidon2P24ManifestV2::new()
                .candidate_id()
                .unwrap()
                .as_bytes(),
        ));
        let anchor = PrivateStateAnchorV2::new(
            GenesisId::new([1; 32]),
            ValidationContextId::new([2; 32]),
            tree_parameters,
            &snapshot,
            &pre_tree,
        )
        .unwrap();
        let envelope_context =
            RecipientEnvelopeContext::new(b"noxis-private-preflight-research", 1).unwrap();
        let first_recipient = HybridPaymentAddressEntry::generate(1);
        let second_recipient = HybridPaymentAddressEntry::generate(1);
        let first_envelope = first_recipient
            .address()
            .encrypt_incoming(&envelope_context, &outputs[0].1)
            .unwrap();
        let second_envelope = second_recipient
            .address()
            .encrypt_incoming(&envelope_context, &outputs[1].1)
            .unwrap();
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            anchor.genesis_id(),
            anchor.validation_context_id(),
            anchor.state_id(),
            anchor.note_tree_parameters(),
            anchor.note_root(),
            AssetId::new([5; 32]),
            nullifiers,
            [
                PrivateTransferOutputV2::new(
                    outputs[0].0,
                    candidate_ciphertext_digest_v1(
                        CandidatePrivateOutputSlotV1::First,
                        outputs[0].0,
                        &first_envelope,
                    )
                    .unwrap(),
                ),
                PrivateTransferOutputV2::new(
                    outputs[1].0,
                    candidate_ciphertext_digest_v1(
                        CandidatePrivateOutputSlotV1::Second,
                        outputs[1].0,
                        &second_envelope,
                    )
                    .unwrap(),
                ),
            ],
        )
        .unwrap();
        let packet_envelopes = validate_candidate_private_transfer_packet_envelopes(
            PrivateTransferPacketV2::new(
                intent.clone(),
                [
                    encode_hybrid_recipient_envelope(&first_envelope).unwrap(),
                    encode_hybrid_recipient_envelope(&second_envelope).unwrap(),
                ],
                vec![1],
            )
            .unwrap(),
        )
        .unwrap();
        let statement =
            CandidatePrivateTransferProofPublicStatementV1::new(anchor, &pre_tree, intent).unwrap();
        let nxsm_witness = CandidateNxsmNullifierTransitionWitnessV1::from_pre_tree(
            &pre_tree,
            statement.air_public_inputs().intent(),
        )
        .unwrap();
        let output_witnesses = [
            CandidateOutputNoteWitnessV1::new(outputs[0].1),
            CandidateOutputNoteWitnessV1::new(outputs[1].1),
        ];

        let source_intent = statement.air_public_inputs().intent();
        let mut mismatched_outputs = *source_intent.outputs();
        mismatched_outputs[0] = PrivateTransferOutputV2::new(
            mismatched_outputs[0].commitment(),
            CiphertextDigestV2::from_elements(vector(15)).unwrap(),
        );
        let mismatched_intent = PrivateTransferIntentV2::new(
            source_intent.circuit_id(),
            source_intent.genesis_id(),
            source_intent.validation_context_id(),
            source_intent.pre_state_id(),
            source_intent.tree_parameters(),
            source_intent.pre_state_root(),
            source_intent.asset_id(),
            *source_intent.nullifiers(),
            mismatched_outputs,
        )
        .unwrap();
        let mismatched_statement = CandidatePrivateTransferProofPublicStatementV1::new(
            statement.anchor().clone(),
            &pre_tree,
            mismatched_intent,
        )
        .unwrap();
        assert!(matches!(
            run_candidate_packet_bound_private_transfer_stark_preflight(
                packet_envelopes.clone(),
                &mismatched_statement,
                &pre_tree,
                &nxsm_witness,
                &input_witnesses,
                &output_witnesses,
            ),
            Err(CandidatePrivateTransferStarkPreflightError::PacketIntentMismatch)
        ));

        let preflight = run_candidate_packet_bound_private_transfer_stark_preflight(
            packet_envelopes,
            &statement,
            &pre_tree,
            &nxsm_witness,
            &input_witnesses,
            &output_witnesses,
        )
        .unwrap();
        let results = revalidate_candidate_packet_bound_private_transfer_stark_preflight(
            &preflight,
            &statement,
            &pre_tree,
            &nxsm_witness,
        )
        .unwrap();
        assert_eq!(
            results.intent.intent_commitment,
            statement.air_public_inputs().intent_commitment()
        );
        assert_eq!(
            results.inputs[0].nullifier,
            statement.air_public_inputs().intent().nullifiers()[0].elements()
        );
        assert_eq!(
            results.inputs[1].nullifier,
            statement.air_public_inputs().intent().nullifiers()[1].elements()
        );
        assert_eq!(results.inputs[0].root, root);
        assert_eq!(results.inputs[1].root, root);
        assert_eq!(results.outputs[0].note_commitment, outputs[0].0.elements());
        assert_eq!(results.outputs[1].note_commitment, outputs[1].0.elements());
        assert_eq!(preflight.stark().statement_id(), statement.statement_id());

        // Unlike the compatibility preflight above, this path retains the
        // three opaque proof objects and independently verifies them again.
        let bundle = prove_candidate_private_transfer_proof_bundle(
            &statement,
            &pre_tree,
            &input_witnesses,
            &output_witnesses,
        )
        .unwrap();
        assert_eq!(bundle.statement_id(), statement.statement_id());
        let proof_lengths = bundle.pinned_research_proof_lengths().unwrap();
        println!(
            "pinned bundle proof bytes: intent-value={}, ownership-0={}, ownership-1={}, total={}",
            proof_lengths[0],
            proof_lengths[1],
            proof_lengths[2],
            proof_lengths.into_iter().sum::<usize>(),
        );
        let envelope_bytes =
            CandidatePrivateProofBundleEnvelopeV1::encode(&bundle, &statement).unwrap();
        println!(
            "candidate proof bundle envelope bytes: {}",
            envelope_bytes.len()
        );
        let decoded_bundle = CandidatePrivateProofBundleEnvelopeV1::decode_and_verify(
            &envelope_bytes,
            &statement,
            &pre_tree,
        )
        .unwrap();
        assert_eq!(decoded_bundle.statement_id(), statement.statement_id());
        let mut private_ledger = CandidatePrivateLedgerStateV1::new(
            statement.anchor().genesis_id(),
            statement.anchor().validation_context_id(),
            statement.anchor().note_tree_parameters(),
            snapshot.clone(),
            pre_tree.clone(),
        )
        .unwrap();
        private_ledger
            .register_asset(
                AssetDefinition::new(AssetId::new([5; 32]), "NOX", AssetKind::Synthetic).unwrap(),
            )
            .unwrap();
        let request = CandidatePrivateTransferRequestV1::new(
            statement.air_public_inputs().intent().clone(),
            decoded_bundle,
        );
        let receipt = private_ledger
            .apply_transfer(
                &request,
                &CandidatePrivateTransferProofBundleVerifierV1::new(),
            )
            .unwrap();
        assert_eq!(receipt.pre_state_id(), statement.anchor().state_id());
        assert_eq!(receipt.post_state_id(), private_ledger.anchor().state_id());
        assert_eq!(private_ledger.snapshot().commitments().len(), 4);
        assert_eq!(private_ledger.nullifier_tree().spent_count(), 4);
        assert!(
            private_ledger
                .nullifier_tree()
                .is_spent(receipt.input_nullifiers()[0])
        );
        assert!(
            private_ledger
                .nullifier_tree()
                .is_spent(receipt.input_nullifiers()[1])
        );

        // The same authorized request is stale after commit and must not
        // mutate the already-committed state a second time.
        let committed_anchor = private_ledger.anchor().clone();
        assert!(matches!(
            private_ledger.apply_transfer(
                &request,
                &CandidatePrivateTransferProofBundleVerifierV1::new(),
            ),
            Err(CandidatePrivateLedgerError::StateTransition(_))
        ));
        assert_eq!(private_ledger.anchor(), &committed_anchor);
        assert_eq!(private_ledger.snapshot().commitments().len(), 4);
        assert_eq!(private_ledger.nullifier_tree().spent_count(), 4);

        let mut corrupted = preflight.stark().clone();
        let mut changed = corrupted.intent_result.intent_commitment.elements();
        changed[0] = changed[0].wrapping_add(1);
        corrupted.intent_result.intent_commitment =
            PrivateTransferIntentCommitmentV2::from_elements(changed).unwrap();
        assert!(matches!(
            revalidate_candidate_private_transfer_stark_preflight(
                &corrupted,
                &statement,
                &pre_tree,
                &nxsm_witness,
            ),
            Err(CandidatePrivateTransferStarkPreflightError::IntentCommitmentMismatch)
        ));
    }
}
