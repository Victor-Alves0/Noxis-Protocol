//! Local demonstration of the candidate `NXPT` envelope-validation boundary.

use noxis_codec::{PrivateTransferPacketV2, encode_private_transfer};
use noxis_privacy_types::{
    CircuitId, MerkleRootV2, NullifierV2, PrivateTransferIntentV2, PrivateTransferOutputV2,
    TreeParametersId, TreeParametersV2,
};
use noxis_private_packet_validation::{
    CandidatePrivatePacketEnvelopeValidationError,
    decode_and_validate_candidate_private_transfer_packet_envelopes,
    decode_validate_and_scan_candidate_private_transfer_packet_for_incoming_view_key,
};
use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};
use noxis_wallet_crypto::{
    CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH, CandidateIncomingViewKeyV1,
    CandidatePrivateOutputSlotV1, CandidatePrivateRecipientKeysetV1, RecipientEnvelopeContext,
    candidate_ciphertext_digest_v1, decode_hybrid_recipient_envelope,
    encode_hybrid_recipient_envelope, encrypt_candidate_private_note_to_descriptor,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (packet, context, view_key) = sample_packet()?;
    let encoded = encode_private_transfer(&packet)?;
    let validated = decode_and_validate_candidate_private_transfer_packet_envelopes(&encoded)?;
    let scanned = decode_validate_and_scan_candidate_private_transfer_packet_for_incoming_view_key(
        &encoded, &context, &view_key,
    )?;
    let mut swapped_envelopes = packet.recipient_envelopes().clone();
    swapped_envelopes.swap(0, 1);
    let swapped = PrivateTransferPacketV2::new(
        packet.intent().clone(),
        swapped_envelopes,
        packet.proof().to_vec(),
    )?;
    let swapped_result =
        noxis_private_packet_validation::validate_candidate_private_transfer_packet_envelopes(
            swapped,
        );
    if !matches!(
        swapped_result,
        Err(CandidatePrivatePacketEnvelopeValidationError::DigestMismatch { slot: 0 })
    ) {
        return Err("swapped candidate envelopes were not rejected at slot zero".into());
    }

    println!("Noxis private packet envelope-validation demo — EXPERIMENTAL / LOCAL ONLY");
    println!(
        "NXPT decoded structurally ... accepted ({} bytes)",
        encoded.len()
    );
    println!("two NXRE envelopes strictly decoded ... accepted");
    println!("both output digests recomputed and matched the intent ... accepted");
    println!("swapped output envelopes ... rejected: DigestMismatch(slot 0)");
    println!(
        "incoming view key scanned packet-bound outputs ... accepted ({} own, {} ignored)",
        scanned.received().len(),
        scanned.ignored()
    );
    println!(
        "This does not verify the opaque proof, admit a packet, update state, expose a balance or authorize a ledger transaction."
    );
    println!(
        "Recomputed public digests: {}, {}",
        validated.ciphertext_digests()[0],
        validated.ciphertext_digests()[1]
    );
    Ok(())
}

fn sample_packet() -> Result<
    (
        PrivateTransferPacketV2,
        RecipientEnvelopeContext,
        CandidateIncomingViewKeyV1,
    ),
    Box<dyn std::error::Error>,
> {
    let context = RecipientEnvelopeContext::new(b"noxis-private-packet-demo", 1)?;
    let owner = CandidatePrivateRecipientKeysetV1::generate(1)?;
    let owner_descriptor = owner.public_descriptor();
    let unrelated = CandidatePrivateRecipientKeysetV1::generate(1)?;
    let unrelated_descriptor = unrelated.public_descriptor();
    let owned = encrypt_candidate_private_note_to_descriptor(
        &owner_descriptor,
        &context,
        note(
            owner_descriptor.recipient_commitment().as_bytes(),
            [11; 32],
            40,
            1,
        ),
    )?;
    let other = encrypt_candidate_private_note_to_descriptor(
        &unrelated_descriptor,
        &context,
        note(
            unrelated_descriptor.recipient_commitment().as_bytes(),
            [12; 32],
            41,
            2,
        ),
    )?;
    let mut output_data = [
        (
            owned.commitment(),
            encode_hybrid_recipient_envelope(owned.envelope())?,
        ),
        (
            other.commitment(),
            encode_hybrid_recipient_envelope(other.envelope())?,
        ),
    ];
    output_data.sort_unstable_by_key(|(commitment, _)| commitment.as_bytes());
    let first = decode_hybrid_recipient_envelope(&output_data[0].1)?;
    let second = decode_hybrid_recipient_envelope(&output_data[1].1)?;
    let outputs = [
        PrivateTransferOutputV2::new(
            output_data[0].0,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::First,
                output_data[0].0,
                &first,
            )?,
        ),
        PrivateTransferOutputV2::new(
            output_data[1].0,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::Second,
                output_data[1].0,
                &second,
            )?,
        ),
    ];
    let intent = PrivateTransferIntentV2::new(
        CircuitId::new([4; 32]),
        GenesisId::new([5; 32]),
        ValidationContextId::new([6; 32]),
        StateId::new([7; 32]),
        TreeParametersV2::new(TreeParametersId::new([8; 32])),
        MerkleRootV2::from_elements([9; 16])?,
        AssetId::new([10; 32]),
        [
            NullifierV2::from_elements([11; 16])?,
            NullifierV2::from_elements([12; 16])?,
        ],
        outputs,
    )?;
    Ok((
        PrivateTransferPacketV2::new(
            intent,
            [output_data[0].1.clone(), output_data[1].1.clone()],
            vec![13],
        )?,
        context,
        owner.into_incoming_view_key(),
    ))
}

fn note(
    recipient_commitment: [u8; 64],
    asset: [u8; 32],
    value: u128,
    witness_seed: u8,
) -> [u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH] {
    let mut note = [0_u8; CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH];
    note[..2].copy_from_slice(&1_u16.to_be_bytes());
    note[2..34].copy_from_slice(&asset);
    note[34..50].copy_from_slice(&value.to_be_bytes());
    note[50..114].copy_from_slice(&recipient_commitment);
    for (index, byte) in note[114..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(23).wrapping_add(witness_seed);
    }
    note
}
