//! Candidate boundary that validates `NXPT` recipient-envelope digests.
//!
//! `noxis-codec` owns structural `NXPT` decoding and `noxis-wallet-crypto`
//! owns strict `NXRE` parsing plus the candidate P24 digest. This crate joins
//! those two already-canonical boundaries without turning either into a
//! ledger rule, proof verifier, wallet, or network service.

use std::fmt;

use noxis_codec::{CodecError, PrivateTransferPacketV2, decode_private_transfer};
use noxis_privacy_types::CiphertextDigestV2;
use noxis_wallet_crypto::{
    CandidateCiphertextDigestError, CandidateIncomingViewKeyV1, CandidatePrivateNoteEnvelopeV1,
    CandidatePrivateNoteError, CandidatePrivateOutputSlotV1, PaymentAddressCodecError,
    ReceivedCandidatePrivateNoteV1, RecipientEnvelopeContext, candidate_ciphertext_digest_v1,
    decode_hybrid_recipient_envelope, decrypt_candidate_private_note_for_incoming_view_key,
    encode_hybrid_recipient_envelope,
};

/// A packet whose two envelope bytes were parsed as exact `NXRE v1` values and
/// whose candidate digests matched both intent output slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePrivateTransferPacketEnvelopeValidationV1 {
    packet: PrivateTransferPacketV2,
    ciphertext_digests: [CiphertextDigestV2; 2],
}

impl CandidatePrivateTransferPacketEnvelopeValidationV1 {
    /// The structurally decoded packet that passed the candidate envelope check.
    pub const fn packet(&self) -> &PrivateTransferPacketV2 {
        &self.packet
    }

    /// The recomputed public digest for the requested canonical output slot.
    pub const fn ciphertext_digests(&self) -> &[CiphertextDigestV2; 2] {
        &self.ciphertext_digests
    }
}

/// Structurally decodes exactly one `NXPT` packet and then validates its two
/// candidate recipient-envelope digest bindings.
pub fn decode_and_validate_candidate_private_transfer_packet_envelopes(
    bytes: &[u8],
) -> Result<
    CandidatePrivateTransferPacketEnvelopeValidationV1,
    CandidatePrivatePacketEnvelopeValidationError,
> {
    validate_candidate_private_transfer_packet_envelopes(decode_private_transfer(bytes)?)
}

/// One candidate output discovered with incoming-view authority after its
/// surrounding `NXPT` packet passed strict envelope/digest validation.
///
/// `output_slot` is the canonical v2 intent position, not a transaction,
/// block or consensus position. The result says nothing about proof validity,
/// packet admission, finality or spendability.
pub struct CandidatePacketScannedIncomingNoteV1 {
    output_slot: u8,
    note: ReceivedCandidatePrivateNoteV1,
}

impl CandidatePacketScannedIncomingNoteV1 {
    pub const fn output_slot(&self) -> u8 {
        self.output_slot
    }

    pub const fn note(&self) -> &ReceivedCandidatePrivateNoteV1 {
        &self.note
    }

    pub fn into_note(self) -> ReceivedCandidatePrivateNoteV1 {
        self.note
    }
}

/// The bounded result of scanning the two public output positions in one
/// canonical candidate `NXPT` packet.
pub struct CandidatePacketIncomingNoteScanResultV1 {
    received: Vec<CandidatePacketScannedIncomingNoteV1>,
    ignored: u8,
}

impl CandidatePacketIncomingNoteScanResultV1 {
    pub fn received(&self) -> &[CandidatePacketScannedIncomingNoteV1] {
        &self.received
    }

    pub fn into_received(self) -> Vec<CandidatePacketScannedIncomingNoteV1> {
        self.received
    }

    /// Number of output envelopes that were unrelated or unauthenticated for
    /// the supplied view key. They stay deliberately indistinguishable.
    pub const fn ignored(&self) -> u8 {
        self.ignored
    }
}

/// Strictly decodes and validates a candidate `NXPT`, then scans its two
/// output envelopes using only local incoming-view authority.
///
/// The scanner validates the exact `NXRE` bytes and their public digests
/// before attempting decryption. This prevents a caller from presenting an
/// envelope under a commitment/slot different from the one signed into the
/// candidate intent. It remains a packet-local read path: no proof is
/// verified, no state is mutated, and no accepted/final chain placement is
/// established.
pub fn decode_validate_and_scan_candidate_private_transfer_packet_for_incoming_view_key(
    bytes: &[u8],
    context: &RecipientEnvelopeContext,
    view_key: &CandidateIncomingViewKeyV1,
) -> Result<CandidatePacketIncomingNoteScanResultV1, CandidatePacketIncomingNoteScanError> {
    let validated = decode_and_validate_candidate_private_transfer_packet_envelopes(bytes)?;
    let outputs = validated.packet().intent().outputs();
    let envelope_bytes = validated.packet().recipient_envelopes();
    let mut received = Vec::new();
    let mut ignored = 0_u8;

    for (slot, (output, bytes)) in outputs.iter().zip(envelope_bytes).enumerate() {
        let envelope = decode_canonical_envelope(slot as u8, bytes)?;
        let candidate = CandidatePrivateNoteEnvelopeV1::from_parts(output.commitment(), envelope);
        match decrypt_candidate_private_note_for_incoming_view_key(view_key, context, &candidate) {
            Ok(note) => received.push(CandidatePacketScannedIncomingNoteV1 {
                output_slot: slot as u8,
                note,
            }),
            Err(CandidatePrivateNoteError::PaymentAddress(_)) => ignored += 1,
            Err(source) => {
                return Err(CandidatePacketIncomingNoteScanError::InvalidOwnedOutput {
                    slot: slot as u8,
                    source,
                });
            }
        }
    }

    Ok(CandidatePacketIncomingNoteScanResultV1 { received, ignored })
}

/// Validates the two exact `NXRE` envelope bytes already framed in an `NXPT` packet.
///
/// This verifies neither the opaque proof nor note ownership, nullifier
/// absence, value conservation, AEAD decryption, state transition or ledger
/// authorization. It is intentionally prior to all of those checks.
pub fn validate_candidate_private_transfer_packet_envelopes(
    packet: PrivateTransferPacketV2,
) -> Result<
    CandidatePrivateTransferPacketEnvelopeValidationV1,
    CandidatePrivatePacketEnvelopeValidationError,
> {
    let outputs = packet.intent().outputs();
    let envelope_bytes = packet.recipient_envelopes();
    let first_envelope = decode_canonical_envelope(0, &envelope_bytes[0])?;
    let second_envelope = decode_canonical_envelope(1, &envelope_bytes[1])?;
    let ciphertext_digests = [
        candidate_ciphertext_digest_v1(
            CandidatePrivateOutputSlotV1::First,
            outputs[0].commitment(),
            &first_envelope,
        )
        .map_err(
            |error| CandidatePrivatePacketEnvelopeValidationError::Digest { slot: 0, error },
        )?,
        candidate_ciphertext_digest_v1(
            CandidatePrivateOutputSlotV1::Second,
            outputs[1].commitment(),
            &second_envelope,
        )
        .map_err(
            |error| CandidatePrivatePacketEnvelopeValidationError::Digest { slot: 1, error },
        )?,
    ];
    for (slot, (actual, output)) in ciphertext_digests.iter().zip(outputs).enumerate() {
        if *actual != output.ciphertext_digest() {
            return Err(
                CandidatePrivatePacketEnvelopeValidationError::DigestMismatch { slot: slot as u8 },
            );
        }
    }
    Ok(CandidatePrivateTransferPacketEnvelopeValidationV1 {
        packet,
        ciphertext_digests,
    })
}

fn decode_canonical_envelope(
    slot: u8,
    bytes: &[u8],
) -> Result<
    noxis_wallet_crypto::HybridRecipientEnvelope,
    CandidatePrivatePacketEnvelopeValidationError,
> {
    let envelope = decode_hybrid_recipient_envelope(bytes).map_err(|error| {
        CandidatePrivatePacketEnvelopeValidationError::EnvelopeCodec { slot, error }
    })?;
    let reencoded = encode_hybrid_recipient_envelope(&envelope).map_err(|error| {
        CandidatePrivatePacketEnvelopeValidationError::EnvelopeCodec { slot, error }
    })?;
    if reencoded != bytes {
        return Err(CandidatePrivatePacketEnvelopeValidationError::NonCanonicalEnvelope { slot });
    }
    Ok(envelope)
}

/// Fail-closed errors from the candidate `NXPT` envelope-validation boundary.
#[derive(Debug)]
pub enum CandidatePrivatePacketEnvelopeValidationError {
    Codec(CodecError),
    EnvelopeCodec {
        slot: u8,
        error: PaymentAddressCodecError,
    },
    NonCanonicalEnvelope {
        slot: u8,
    },
    Digest {
        slot: u8,
        error: CandidateCiphertextDigestError,
    },
    DigestMismatch {
        slot: u8,
    },
}

/// Fail-closed errors from packet-bound incoming-view scanning.
#[derive(Debug)]
pub enum CandidatePacketIncomingNoteScanError {
    Packet(CandidatePrivatePacketEnvelopeValidationError),
    InvalidOwnedOutput {
        slot: u8,
        source: CandidatePrivateNoteError,
    },
}

impl From<CandidatePrivatePacketEnvelopeValidationError> for CandidatePacketIncomingNoteScanError {
    fn from(value: CandidatePrivatePacketEnvelopeValidationError) -> Self {
        Self::Packet(value)
    }
}

impl fmt::Display for CandidatePacketIncomingNoteScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(error) => write!(
                formatter,
                "candidate private packet scan rejected packet: {error}"
            ),
            Self::InvalidOwnedOutput { slot, source } => write!(
                formatter,
                "candidate private packet output slot {slot} violated a note invariant: {source}"
            ),
        }
    }
}

impl std::error::Error for CandidatePacketIncomingNoteScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(error) => Some(error),
            Self::InvalidOwnedOutput { source, .. } => Some(source),
        }
    }
}

impl From<CodecError> for CandidatePrivatePacketEnvelopeValidationError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl fmt::Display for CandidatePrivatePacketEnvelopeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => {
                write!(formatter, "candidate private packet codec error: {error}")
            }
            Self::EnvelopeCodec { slot, error } => {
                write!(
                    formatter,
                    "candidate private packet envelope {slot} is invalid: {error}"
                )
            }
            Self::NonCanonicalEnvelope { slot } => {
                write!(
                    formatter,
                    "candidate private packet envelope {slot} is not canonical"
                )
            }
            Self::Digest { slot, error } => {
                write!(
                    formatter,
                    "candidate private packet digest {slot} failed: {error}"
                )
            }
            Self::DigestMismatch { slot } => {
                write!(
                    formatter,
                    "candidate private packet envelope digest mismatches output slot {slot}"
                )
            }
        }
    }
}

impl std::error::Error for CandidatePrivatePacketEnvelopeValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::EnvelopeCodec { error, .. } => Some(error),
            Self::NonCanonicalEnvelope { .. } => None,
            Self::Digest { error, .. } => Some(error),
            Self::DigestMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxis_codec::{PrivateTransferPacketV2, encode_private_transfer};
    use noxis_privacy_types::{
        CircuitId, MerkleRootV2, NoteCommitmentV2, NullifierV2, PrivateTransferIntentV2,
        PrivateTransferOutputV2, TreeParametersId, TreeParametersV2,
    };
    use noxis_types::{AssetId, GenesisId, StateId, ValidationContextId};
    use noxis_wallet_crypto::{
        CANDIDATE_PRIVATE_NOTE_PREIMAGE_LENGTH, CandidateIncomingViewKeyV1,
        CandidatePrivateRecipientKeysetV1, HybridPaymentAddressEntry, RecipientEnvelopeContext,
        decode_hybrid_recipient_envelope, encode_hybrid_recipient_envelope,
        encrypt_candidate_private_note_to_descriptor,
    };

    fn packet() -> PrivateTransferPacketV2 {
        let context = RecipientEnvelopeContext::new(b"noxis-private-packet-research", 1).unwrap();
        let first_owner = HybridPaymentAddressEntry::generate(1);
        let second_owner = HybridPaymentAddressEntry::generate(1);
        let first = first_owner
            .address()
            .encrypt_incoming(&context, &[11; 178])
            .unwrap();
        let second = second_owner
            .address()
            .encrypt_incoming(&context, &[12; 178])
            .unwrap();
        let first_bytes = encode_hybrid_recipient_envelope(&first).unwrap();
        let second_bytes = encode_hybrid_recipient_envelope(&second).unwrap();
        let first_commitment = NoteCommitmentV2::from_elements([2; 16]).unwrap();
        let second_commitment = NoteCommitmentV2::from_elements([3; 16]).unwrap();
        let outputs = [
            PrivateTransferOutputV2::new(
                first_commitment,
                candidate_ciphertext_digest_v1(
                    CandidatePrivateOutputSlotV1::First,
                    first_commitment,
                    &first,
                )
                .unwrap(),
            ),
            PrivateTransferOutputV2::new(
                second_commitment,
                candidate_ciphertext_digest_v1(
                    CandidatePrivateOutputSlotV1::Second,
                    second_commitment,
                    &second,
                )
                .unwrap(),
            ),
        ];
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            GenesisId::new([5; 32]),
            ValidationContextId::new([6; 32]),
            StateId::new([7; 32]),
            TreeParametersV2::new(TreeParametersId::new([8; 32])),
            MerkleRootV2::from_elements([9; 16]).unwrap(),
            AssetId::new([10; 32]),
            [
                NullifierV2::from_elements([11; 16]).unwrap(),
                NullifierV2::from_elements([12; 16]).unwrap(),
            ],
            outputs,
        )
        .unwrap();
        PrivateTransferPacketV2::new(intent, [first_bytes, second_bytes], vec![13]).unwrap()
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

    fn scannable_packet() -> (
        Vec<u8>,
        RecipientEnvelopeContext,
        CandidateIncomingViewKeyV1,
        NoteCommitmentV2,
    ) {
        let context = RecipientEnvelopeContext::new(b"noxis-packet-scan-research", 1).unwrap();
        let owner = CandidatePrivateRecipientKeysetV1::generate(1).unwrap();
        let owner_descriptor = owner.public_descriptor();
        let unrelated = CandidatePrivateRecipientKeysetV1::generate(1).unwrap();
        let unrelated_descriptor = unrelated.public_descriptor();
        let owned = encrypt_candidate_private_note_to_descriptor(
            &owner_descriptor,
            &context,
            note(
                owner_descriptor.recipient_commitment().as_bytes(),
                [21; 32],
                50,
                1,
            ),
        )
        .unwrap();
        let other = encrypt_candidate_private_note_to_descriptor(
            &unrelated_descriptor,
            &context,
            note(
                unrelated_descriptor.recipient_commitment().as_bytes(),
                [22; 32],
                51,
                2,
            ),
        )
        .unwrap();
        let owned_commitment = owned.commitment();
        let mut output_data = [
            (
                owned.commitment(),
                encode_hybrid_recipient_envelope(owned.envelope()).unwrap(),
            ),
            (
                other.commitment(),
                encode_hybrid_recipient_envelope(other.envelope()).unwrap(),
            ),
        ];
        output_data.sort_unstable_by_key(|(commitment, _)| commitment.as_bytes());
        let first_envelope = decode_hybrid_recipient_envelope(&output_data[0].1).unwrap();
        let second_envelope = decode_hybrid_recipient_envelope(&output_data[1].1).unwrap();
        let outputs = [
            PrivateTransferOutputV2::new(
                output_data[0].0,
                candidate_ciphertext_digest_v1(
                    CandidatePrivateOutputSlotV1::First,
                    output_data[0].0,
                    &first_envelope,
                )
                .unwrap(),
            ),
            PrivateTransferOutputV2::new(
                output_data[1].0,
                candidate_ciphertext_digest_v1(
                    CandidatePrivateOutputSlotV1::Second,
                    output_data[1].0,
                    &second_envelope,
                )
                .unwrap(),
            ),
        ];
        let intent = PrivateTransferIntentV2::new(
            CircuitId::new([4; 32]),
            GenesisId::new([5; 32]),
            ValidationContextId::new([6; 32]),
            StateId::new([7; 32]),
            TreeParametersV2::new(TreeParametersId::new([8; 32])),
            MerkleRootV2::from_elements([9; 16]).unwrap(),
            AssetId::new([10; 32]),
            [
                NullifierV2::from_elements([11; 16]).unwrap(),
                NullifierV2::from_elements([12; 16]).unwrap(),
            ],
            outputs,
        )
        .unwrap();
        let packet = PrivateTransferPacketV2::new(
            intent,
            [output_data[0].1.clone(), output_data[1].1.clone()],
            vec![13],
        )
        .unwrap();
        (
            encode_private_transfer(&packet).unwrap(),
            context,
            owner.into_incoming_view_key(),
            owned_commitment,
        )
    }

    #[test]
    fn accepts_two_exact_nxre_envelopes_bound_to_the_intent() {
        let packet = packet();
        let validated =
            validate_candidate_private_transfer_packet_envelopes(packet.clone()).unwrap();
        assert_eq!(validated.packet(), &packet);
        assert_eq!(
            decode_and_validate_candidate_private_transfer_packet_envelopes(
                &encode_private_transfer(&packet).unwrap()
            )
            .unwrap()
            .packet(),
            &packet
        );
    }

    #[test]
    fn rejects_an_envelope_swapped_between_output_slots() {
        let packet = packet();
        let mut envelopes = packet.recipient_envelopes().clone();
        envelopes.swap(0, 1);
        let swapped = PrivateTransferPacketV2::new(
            packet.intent().clone(),
            envelopes,
            packet.proof().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            validate_candidate_private_transfer_packet_envelopes(swapped),
            Err(CandidatePrivatePacketEnvelopeValidationError::DigestMismatch { slot: 0 })
        ));
    }

    #[test]
    fn rejects_opaque_packet_bytes_that_are_not_strict_nxre() {
        let packet = packet();
        let invalid = PrivateTransferPacketV2::new(
            packet.intent().clone(),
            [vec![0; 1_024], packet.recipient_envelopes()[1].clone()],
            packet.proof().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            validate_candidate_private_transfer_packet_envelopes(invalid),
            Err(CandidatePrivatePacketEnvelopeValidationError::EnvelopeCodec { slot: 0, .. })
        ));
    }

    #[test]
    fn incoming_view_key_scans_only_its_packet_bound_output() {
        let (bytes, context, view_key, owned_commitment) = scannable_packet();
        let scanned =
            decode_validate_and_scan_candidate_private_transfer_packet_for_incoming_view_key(
                &bytes, &context, &view_key,
            )
            .unwrap();

        assert_eq!(scanned.ignored(), 1);
        assert_eq!(scanned.received().len(), 1);
        assert!(scanned.received()[0].output_slot() < 2);
        assert_eq!(scanned.received()[0].note().commitment(), owned_commitment);
        assert_eq!(
            scanned.received()[0].note().asset_id(),
            AssetId::new([21; 32])
        );
        assert_eq!(scanned.received()[0].note().value(), 50);
    }

    #[test]
    fn packet_bound_scanner_rejects_swapped_envelopes_before_decryption() {
        let (bytes, context, view_key, _) = scannable_packet();
        let packet = decode_private_transfer(&bytes).unwrap();
        let mut swapped_envelopes = packet.recipient_envelopes().clone();
        swapped_envelopes.swap(0, 1);
        let swapped = PrivateTransferPacketV2::new(
            packet.intent().clone(),
            swapped_envelopes,
            packet.proof().to_vec(),
        )
        .unwrap();

        assert!(matches!(
            decode_validate_and_scan_candidate_private_transfer_packet_for_incoming_view_key(
                &encode_private_transfer(&swapped).unwrap(),
                &context,
                &view_key,
            ),
            Err(CandidatePacketIncomingNoteScanError::Packet(
                CandidatePrivatePacketEnvelopeValidationError::DigestMismatch { slot: 0 }
            ))
        ));
    }
}
