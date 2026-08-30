//! Local demonstration of the candidate `NXPT` envelope-validation boundary.

use noxis_codec::{PrivateTransferPacketV2, encode_private_transfer};
use noxis_privacy_types::{
    CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
    PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
};
use noxis_private_packet_validation::{
    CandidatePrivatePacketEnvelopeValidationError,
    decode_and_validate_candidate_private_transfer_packet_envelopes,
};
use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};
use noxis_wallet_crypto::{
    CandidatePrivateOutputSlotV1, HybridPaymentAddressEntry, RecipientEnvelopeContext,
    candidate_ciphertext_digest_v1, encode_hybrid_recipient_envelope,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet = sample_packet()?;
    let encoded = encode_private_transfer(&packet)?;
    let validated = decode_and_validate_candidate_private_transfer_packet_envelopes(&encoded)?;
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
        "This does not verify the opaque proof, decrypt notes, update state or authorize a ledger transaction."
    );
    println!(
        "Recomputed public digests: {}, {}",
        validated.ciphertext_digests()[0],
        validated.ciphertext_digests()[1]
    );
    Ok(())
}

fn sample_packet() -> Result<PrivateTransferPacketV2, Box<dyn std::error::Error>> {
    let context = RecipientEnvelopeContext::new(b"noxis-private-packet-demo", 1)?;
    let first_owner = HybridPaymentAddressEntry::generate(1);
    let second_owner = HybridPaymentAddressEntry::generate(1);
    let first = first_owner
        .address()
        .encrypt_incoming(&context, &[11; 178])?;
    let second = second_owner
        .address()
        .encrypt_incoming(&context, &[12; 178])?;
    let first_commitment = NoteCommitmentV2::from_elements([2; 16])?;
    let second_commitment = NoteCommitmentV2::from_elements([3; 16])?;
    let outputs = [
        PrivateTransferOutputV2::new(
            first_commitment,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::First,
                first_commitment,
                &first,
            )?,
        ),
        PrivateTransferOutputV2::new(
            second_commitment,
            candidate_ciphertext_digest_v1(
                CandidatePrivateOutputSlotV1::Second,
                second_commitment,
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
    Ok(PrivateTransferPacketV2::new(
        intent,
        [
            encode_hybrid_recipient_envelope(&first)?,
            encode_hybrid_recipient_envelope(&second)?,
        ],
        vec![13],
    )?)
}
